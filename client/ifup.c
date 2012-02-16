/*
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <mcheck.h>
#include <stdlib.h>
#include <getopt.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/backend.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>
#include <wicked/dbus.h>
#include <wicked/objectmodel.h>

#include "wicked-client.h"

extern ni_dbus_object_t *	wicked_dbus_client_create(void);
extern ni_dbus_object_t *	wicked_get_interface(ni_dbus_object_t *, const char *);

/*
 * Interface state information
 */
enum {
	STATE_NONE = 0,
	STATE_DEVICE_DOWN,
	STATE_DEVICE_UP,
	STATE_LINK_UP,
	STATE_LINK_AUTHENTICATED,
	STATE_NETWORK_UP,

	__STATE_MAX
};

typedef struct ni_ifworker	ni_ifworker_t;
typedef struct ni_ifworker_array {
	unsigned int		count;
	ni_ifworker_t **	data;
} ni_ifworker_array_t;

typedef struct ni_interface_op {
	const char *		name;
	int			(*call)(ni_ifworker_t *, ni_netconfig_t *);
	int			(*check)(ni_ifworker_t *, ni_netconfig_t *, unsigned int);
	int			(*timeout)(ni_ifworker_t *);
} ni_interface_op_t;

struct ni_ifworker {
	unsigned int		refcount;

	char *			name;
	char *			object_path;
	unsigned int		ifindex;
	ni_iftype_t		iftype;

	int			target_state;
	int			state;
	unsigned int		failed		: 1,
				wait_for_event	: 1,
				is_slave	: 1,
				done		: 1;

	xml_node_t *		config;
	ni_interface_t *	device;

	unsigned int		shared_users;
	ni_ifworker_t *		exclusive_owner;

#if 0
	unsigned int		refcount;

	char *			ifname;
	ni_interface_t *	config;
	unsigned int		done      : 1,
				is_slave  : 1,
				is_policy : 1,
				waiting   : 1,
				called    : 1;
	int			result;

	int			have_state;
	unsigned int		timeout;
	ni_ifaction_t		behavior;
#endif

	const ni_interface_op_t	*fsm;

	ni_ifworker_t *		parent;
	ni_ifworker_array_t	children;
};


static ni_ifworker_array_t	interface_workers;
static int			work_to_be_done;

static ni_dbus_object_t *	__root_object;

static const char *		ni_ifworker_name(int);
static void			ni_ifworker_array_append(ni_ifworker_array_t *, ni_ifworker_t *);
static void			ni_ifworker_array_destroy(ni_ifworker_array_t *);

static inline ni_ifworker_t *
ni_ifworker_new(const char *name, xml_node_t *config)
{
	ni_ifworker_t *w;

	w = calloc(1, sizeof(*w));
	ni_string_dup(&w->name, name);
	w->config = config;
	w->refcount = 1;

	return w;
}

static void
ni_ifworker_free(ni_ifworker_t *state)
{
	ni_string_free(&state->name);
	ni_ifworker_array_destroy(&state->children);
}

static inline void
ni_ifworker_release(ni_ifworker_t *state)
{
	if (--(state->refcount) == 0)
		ni_ifworker_free(state);
}

static void
ni_ifworker_fail(ni_ifworker_t *w, const char *fmt, ...)
{
	char errmsg[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(errmsg, sizeof(errmsg), fmt, ap);
	va_end(ap);

	ni_error("device %s failed: %s", w->name, errmsg);
	w->state = w->target_state = STATE_NONE;
	w->failed = 1;
}

static void
ni_ifworker_success(ni_ifworker_t *w)
{
	printf("%s: %s\n", w->name, ni_ifworker_name(w->state));
	w->done = 1;
}

static const char *
ni_ifworker_name(int state)
{
	static ni_intmap_t __state_names[] = {
		{ "none",		STATE_NONE		},
		{ "device-down",	STATE_DEVICE_DOWN	},
		{ "device-up",		STATE_DEVICE_UP		},
		{ "link-up",		STATE_LINK_UP		},
		{ "network-up",		STATE_NETWORK_UP	},

		{ NULL }
	};

	return ni_format_int_mapped(state, __state_names);
}

static void
ni_ifworker_array_append(ni_ifworker_array_t *array, ni_ifworker_t *w)
{
	array->data = realloc(array->data, (array->count + 1) * sizeof(array->data[0]));
	array->data[array->count++] = w;
	w->refcount++;
}

static void
ni_ifworker_array_destroy(ni_ifworker_array_t *array)
{
	while (array->count)
		ni_ifworker_release(array->data[--(array->count)]);
	free(array->data);
	array->data = NULL;
}

static ni_ifworker_t *
ni_ifworker_array_find(ni_ifworker_array_t *array, const char *ifname)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		ni_ifworker_t *worker = array->data[i];

		if (!strcmp(worker->name, ifname))
			return worker;
	}
	return NULL;
}

static ni_ifworker_t *
ni_ifworker_add_child(ni_ifworker_t *parent, ni_ifworker_t *worker)
{
	unsigned int i;

	for (i = 0; i < parent->children.count; ++i) {
		if (parent->children.data[i] == worker)
			return worker;
	}

	ni_ifworker_array_append(&parent->children, worker);

#if 0
	if (parent->behavior.mandatory)
		worker->behavior.mandatory = 1;
#endif
	worker->is_slave = 1;

	return worker;
}

static ni_ifworker_t *
add_interface_worker(const char *name, xml_node_t *config)
{
	ni_ifworker_t *worker;

	worker = ni_ifworker_new(name, config);
	ni_ifworker_array_append(&interface_workers, worker);
	ni_ifworker_release(worker);

	return worker;
}

static unsigned int
add_all_interfaces(xml_document_t *doc)
{
	xml_node_t *root, *ifnode;
	unsigned int count = 0;

	root = xml_document_root(doc);
	for (ifnode = root->children; ifnode; ifnode = ifnode->next) {
		const char *ifname = NULL;
		xml_node_t *node;

		if ((node = xml_node_get_child(ifnode, "name")) != NULL)
			ifname = node->cdata;

		add_interface_worker(ifname, ifnode);
		count++;
	}

	return count;
}

static void
ni_ifworker_set_target(ni_ifworker_t *w, unsigned int min_state, unsigned int max_state)
{
	/* By default, assume we're not chaging the interface state */
	if (w->target_state == STATE_NONE)
		w->target_state = w->state;

	if (w->target_state < min_state)
		w->target_state = min_state;
	else
	if (w->target_state > max_state)
		w->target_state = max_state;

	if (min_state >= STATE_LINK_UP) {
		/* If we're bringing up the device, assume the device does not
		 * exist */
		w->state = STATE_DEVICE_DOWN;
	} else if (max_state <= STATE_LINK_UP) {
		/* Assume we have to bring it down */
		w->state = STATE_NETWORK_UP;
	}

	if (w->children.count != 0 && min_state >= STATE_LINK_UP) {
		unsigned int i;

		switch (w->iftype) {
		case NI_IFTYPE_VLAN:
			/* VLAN devices: the underlying eth device must be up */
			min_state = STATE_LINK_UP;
			max_state = __STATE_MAX;
			break;

		case NI_IFTYPE_BRIDGE:
			/* bridge device: the bridge ports should at least exist.
			 * However, in order to do anything useful, they should at
			 * least have link.
			 * We may later want to allow the config file to override
			 * the initial state for specific bridge ports.
			 */
			min_state = STATE_LINK_UP;
			max_state = __STATE_MAX;
			break;

		case NI_IFTYPE_BOND:
			/* bond device: all slaves devices must exist and be down */
			min_state = STATE_LINK_UP - 1;
			max_state = STATE_LINK_UP - 1;
			break;

		default:
			return;
		}

		ni_debug_dbus("%s: marking all children min=%s max=%s", w->name,
				ni_ifworker_name(min_state),
				ni_ifworker_name(max_state));
		for (i = 0; i < w->children.count; ++i) {
			ni_ifworker_t *child = w->children.data[i];

			ni_ifworker_set_target(child, min_state, max_state);
		}
	}
}

static unsigned int
mark_matching_interfaces(const char *match_name, unsigned int target_state)
{
	unsigned int i, count = 0;

	ni_debug_dbus("%s(name=%s, target_state=%s)", __func__, match_name, ni_ifworker_name(target_state));

	if (!strcmp(match_name, "all"))
		match_name = NULL;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (w->config == NULL)
			continue;
		if (w->exclusive_owner)
			continue;

		if (match_name) {
			if (w->name == NULL || strcmp(match_name, w->name))
				continue;
		}

		/* FIXME: check for matching behavior definition */

		ni_ifworker_set_target(w, target_state, target_state);
		count++;
	}

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (w->target_state != STATE_NONE)
			ni_debug_dbus("%s: target state %s",
					w->name, ni_ifworker_name(w->target_state));
	}

	return count;
}

/*
 * Build the hierarchy of devices.
 *
 * We need to ensure that we bring up devices in the proper order; e.g. an
 * eth interface needs to come up before any of the VLANs that reference
 * it.
 */
static void	__ni_ifworker_print_tree(const char *arrow, const ni_ifworker_t *, const char *);

static int
build_hierarchy(void)
{
	unsigned int i;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];
		xml_node_t *ifnode, *linknode, *devnode;
		ni_ifworker_t *child;

		/* A worker without an ifnode is one that we discovered in the
		 * system, but which we've not been asked to configure. */
		if (!(ifnode = w->config))
			continue;

		if (!(linknode = wicked_find_link_properties(ifnode)))
			continue;

		/* This cannot fail, as this is how wicked_find_link_properties tells
		 * link nodes from others. */
		w->iftype = ni_linktype_name_to_type(linknode->name);

		devnode = NULL;
		while ((devnode = xml_node_get_next_named(linknode, "device", devnode)) != NULL) {
			const char *slave_name;

			slave_name = devnode->cdata;
			if (slave_name == NULL) {
				ni_error("%s: empty <device> element in <%s> declaration",
						xml_node_location(ifnode),
						linknode->name);
				return -1;
			}

			child = ni_ifworker_array_find(&interface_workers, slave_name);
			if (child == NULL) {
				/* We may not have the config for this device, but it may exist
				 * in the system. */
			}

			if (child == NULL) {
				ni_error("%s: <%s> element references unknown slave device %s",
						xml_node_location(ifnode),
						linknode->name,
						slave_name);
				return -1;
			}

			if (child->exclusive_owner != NULL) {
				char *other_owner;

				other_owner = strdup(xml_node_location(child->exclusive_owner->config));
				ni_error("%s: slave interface already owned by %s",
						xml_node_location(devnode), other_owner);
				free(other_owner);
				return -1;
			}

			ni_debug_dbus("making %s a child of %s device %s", child->name, linknode->name, w->name);

			switch (w->iftype) {
			case NI_IFTYPE_VLAN:
				child->shared_users++;
				break;

			default:
				if (child->shared_users) {
					ni_error("%s: slave interface already used by other interfaces",
							xml_node_location(devnode));
					return -1;
				}
				child->exclusive_owner = w;
				break;
			}

			ni_ifworker_add_child(w, child);
		}
	}

	if (ni_debug & NI_TRACE_DBUS) {
		for (i = 0; i < interface_workers.count; ++i) {
			ni_ifworker_t *w = interface_workers.data[i];

			if (!w->shared_users && !w->exclusive_owner)
				__ni_ifworker_print_tree("   +-> ", w, "   |   ");
		}
	}
	return 0;
}

static void
__ni_ifworker_print_tree(const char *arrow, const ni_ifworker_t *w, const char *branches)
{
	if (w->children.count == 0) {
		fprintf(stderr, "%s%s\n", arrow, w->name);
	} else {
		char buffer[128];
		unsigned int i;

		fprintf(stderr, "%s%-10s", arrow, w->name);

		snprintf(buffer, sizeof(buffer), "%s%10s  |   ", branches, "");

		arrow = " +--> ";
		for (i = 0; i < w->children.count; ++i) {
			ni_ifworker_t *child = w->children.data[i];

			if (i != 0) {
				fprintf(stderr, "%s%10s", branches, "");
				if (i == w->children.count - 1)
					arrow = " \\--> ";
			}
			__ni_ifworker_print_tree(arrow, child, buffer);
		}
	}
}

void
interface_workers_refresh_state(void)
{
	static ni_dbus_object_t *iflist = NULL;
	ni_dbus_object_t *object;
	ni_ifworker_t *w;
	unsigned int i;

	if (!iflist && !(iflist = wicked_get_interface_object(NULL)))
		ni_fatal("unable to get server's interface list");

	/* Call ObjectManager.GetManagedObjects to get list of objects and their properties */
	if (!ni_dbus_object_refresh_children(iflist))
		ni_fatal("Couldn't refresh list of active network interfaces");

	for (i = 0; i < interface_workers.count; ++i) {
		ni_interface_t *dev;

		w = interface_workers.data[i];

		/* Don't touch devices we're done with */
		if (w->done)
			continue;

		if ((dev = w->device) != NULL) {
			w->device = NULL;
			ni_interface_put(dev);
		}

		w->state = STATE_DEVICE_DOWN;
	}

	for (object = iflist->children; object; object = object->next) {
		ni_interface_t *dev = ni_objectmodel_unwrap_interface(object);
		ni_ifworker_t *found = NULL;

		if (dev == NULL || dev->name == NULL)
			continue;

		for (i = 0; i < interface_workers.count; ++i) {
			w = interface_workers.data[i];

			if (w->ifindex) {
				if (w->ifindex != dev->link.ifindex)
					continue;
			} else
			if (w->name == NULL || strcmp(dev->name, w->name))
				continue;

			found = w;
			break;
		}

		if (!found)
			found = add_interface_worker(dev->name, NULL);

		/* Don't touch devices we're done with */
		if (found->done)
			continue;

		if (!found->object_path)
			ni_string_dup(&found->object_path, object->path);
		found->device = ni_interface_get(dev);
		found->ifindex = dev->link.ifindex;

		if (ni_interface_network_is_up(dev))
			found->state = STATE_NETWORK_UP;
		else
		if (ni_interface_link_is_up(dev))
			found->state = STATE_LINK_UP;
		else
			found->state = STATE_DEVICE_UP;
	}
}

static inline int
ni_ifworker_ready(const ni_ifworker_t *w)
{
	return w->done || w->target_state == STATE_NONE || w->target_state == w->state;
}

static int
ni_interface_children_ready(ni_ifworker_t *w)
{
	unsigned int i;

	for (i = 0; i < w->children.count; ++i) {
		ni_ifworker_t *child = w->children.data[i];

		if (!ni_ifworker_ready(child))
			return 0;
	}

	return 1;
}

static int
ni_ifworker_create_device(ni_ifworker_t *w)
{
	const ni_dbus_service_t *service;
	xml_node_t *linknode;
	const char *link_type;
	const char *object_path;

	ni_trace("%s(%s)", __func__, w->name);

	if (!(linknode = wicked_find_link_properties(w->config))) {
		ni_error("unable to create interface %s: cannot determine link type of interface", w->name);
		return -1;
	}
	link_type = linknode->name;

	if (!(service = wicked_link_layer_factory_service(link_type))) {
		ni_error("%s: unknown/unsupported link type %s", w->name, link_type);
		return -1;
	}

	object_path = wicked_create_interface_xml(service, w->name, linknode);
	if (object_path == NULL) {
		ni_error("%s: failed to create interface", w->name);
		return -1;
	}

	ni_debug_dbus("created device %s (path=%s)", w->name, object_path);
	ni_string_dup(&w->object_path, object_path);

	return 0;
}

/*
 * Finite state machine - create the device if it does not exist
 * Note this is called for all virtual devices, because the newLink
 * call also takes care of setting up things like the ports assigned
 * to a bridge.
 */
static int
ni_ifworker_do_device_up(ni_ifworker_t *w)
{
	ni_debug_dbus("%s: about to create %s", __func__, w->name);
	if (ni_ifworker_create_device(w) < 0) {
		ni_ifworker_fail(w, "unable to create device");
		return -1;
	}

	return 0;
}

/*
 * Finite state machine
 */
typedef int			ni_ifworker_fsm_action(ni_ifworker_t *);

static ni_ifworker_fsm_action *	ni_ifworker_fsm_up[__STATE_MAX] = {
[STATE_DEVICE_DOWN]	= ni_ifworker_do_device_up,
};

static ni_ifworker_fsm_action *	ni_ifworker_fsm_down[__STATE_MAX] = {
};

static unsigned int
ni_ifworker_fsm(void)
{
	unsigned int i, waiting;

	ni_debug_dbus("%s()", __func__);
	while (1) {
		int made_progress = 0;

		for (i = 0; i < interface_workers.count; ++i) {
			ni_ifworker_t *w = interface_workers.data[i];
			ni_ifworker_fsm_action *action;
			int next_state = STATE_NONE;

			if (w->target_state != STATE_NONE)
				ni_debug_dbus("%-12s: state=%s want=%s%s", w->name,
					ni_ifworker_name(w->state),
					ni_ifworker_name(w->target_state),
					w->wait_for_event? ", wait-for-event" : "");

			if (ni_ifworker_ready(w))
				continue;

			/* If we're still waiting for children to become ready,
			 * there's nothing we can do but wait. */
			if (!ni_interface_children_ready(w))
				continue;

			/* We requested a change that takes time (such as acquiring
			 * a DHCP lease). Wait for a notification from wickedd */
			if (w->wait_for_event)
				continue;

			if (w->state < w->target_state) {
				do {
					action = ni_ifworker_fsm_up[w->state];
				} while (action == NULL && ++(w->state) < w->target_state);
				next_state = w->state + 1;
			} else {
				do {
					action = ni_ifworker_fsm_down[w->state];
				} while (action == NULL && --(w->state) > w->target_state);
				next_state = w->state - 1;
			}

			if (action == NULL) {
				ni_assert(ni_ifworker_ready(w));
				ni_ifworker_success(w);
				made_progress = 1;
				continue;
			}

			if (action(w) >= 0) {
				made_progress = 1;
				if (w->state == next_state) {
					ni_debug_dbus("%s: successfully transitioned from %s to %s",
						w->name,
						ni_ifworker_name(w->state),
						ni_ifworker_name(next_state));
				}
			} else
			if (!w->failed) {
				/* The fsm action should really have marked this
				 * as a failure. shame on the lazy programmer. */
				ni_ifworker_fail(w, "%s: failed to transition from %s to %s",
						w->name,
						ni_ifworker_name(w->state),
						ni_ifworker_name(next_state));
			}
		}

		if (!made_progress)
			break;

		interface_workers_refresh_state();
	}

	for (i = waiting = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (!ni_ifworker_ready(w))
			waiting++;
	}

	ni_debug_dbus("waiting for %u devices to become ready", waiting);
	return waiting;
}

static void
interface_state_change_signal(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	unsigned int min_state = STATE_NONE, max_state = __STATE_MAX;
	unsigned int i;

	ni_debug_dbus("%s: got signal %s from %s", __func__, signal_name, object_path);

	if (!strcmp(signal_name, "linkUp"))
		min_state = STATE_LINK_UP;
	if (!strcmp(signal_name, "networkUp"))
		min_state = STATE_NETWORK_UP;
	if (!strcmp(signal_name, "linkDown"))
		max_state = STATE_DEVICE_UP;
	if (!strcmp(signal_name, "networkDown"))
		max_state = STATE_LINK_UP;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (w->target_state == STATE_NONE)
			continue;

		if (w->object_path && !strcmp(w->object_path, object_path)) {
			unsigned int prev_state = w->state;

			if (w->state < min_state)
				w->state = min_state;
			if (max_state < min_state)
				w->state = max_state;

			if (w->state != prev_state)
				ni_debug_dbus("device %s changed state %s -> %s",
						w->name,
						ni_ifworker_name(prev_state),
						ni_ifworker_name(w->state));
		}
	}

	if (ni_ifworker_fsm() == 0) {
		ni_debug_dbus("all devices have reached the intended state");
		work_to_be_done = 0;
	}
}

int
interface_workers_kickstart(void)
{
	unsigned int i;

	interface_workers_refresh_state();

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (w->target_state == STATE_NONE)
			continue;

		/* Instead of a plain device name, an interface configuration can
		 * contain a different sort of interface identification - such as
		 * its MAC address, or a platform specific name (such as the Dell
		 * biosdevname, or a System z specific interface name).
		 * Here, we should try to resolve these names.
		 */
		if (w->device == NULL) {
			/* check if the device has an <identify> element instead
			 * of (or in addition to) its name, and if so, call
			 * InterfaceList.identify() with this information.
			 */
		}

		if (w->device == NULL)
			w->state = STATE_DEVICE_DOWN;
	}

	return 0;
}

#include <wicked/socket.h>

/* static */ void
interface_worker_mainloop(void)
{
	work_to_be_done = 1;
	while (work_to_be_done) {
		long timeout;

		timeout = ni_timer_next_timeout();
		if (ni_socket_wait(timeout) < 0)
			ni_fatal("ni_socket_wait failed");
	}
}

int
do_ifup(int argc, char **argv)
{
	enum  { OPT_SYSCONFIG, OPT_NETCF, OPT_FILE, OPT_BOOT };
	static struct option ifup_options[] = {
		{ "file", required_argument, NULL, OPT_FILE },
		{ "boot", no_argument, NULL, OPT_BOOT },
		{ NULL }
	};
	ni_dbus_variant_t argument = NI_DBUS_VARIANT_INIT;
	const char *ifname = NULL;
	const char *opt_file = NULL;
	unsigned int ifevent = NI_IFACTION_MANUAL_UP;
	ni_interface_t *config_dev = NULL;
	xml_document_t *config_doc;
	int c, rv = 1;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case OPT_FILE:
			opt_file = optarg;
			break;

		case OPT_BOOT:
			ifevent = NI_IFACTION_BOOT;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifup [ifup-options] all\n"
				"wicked [options] ifup [ifup-options] <ifname> [options ...]\n"
				"\nSupported ifup-options:\n"
				"  --file <filename>\n"
				"      Read interface configuration(s) from file rather than using system config\n"
				"  --boot\n"
				"      Ignore interfaces with startmode != boot\n"
				);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}
	ifname = argv[optind++];

	if (!strcmp(ifname, "boot")) {
		ifevent = NI_IFACTION_BOOT;
		ifname = "all";
	}

	ni_dbus_variant_init_dict(&argument);
	if (opt_file) {
		if (!(config_doc = xml_document_read(opt_file))) {
			ni_error("unable to load interface definition from %s", opt_file);
			goto failed;
		}

		add_all_interfaces(config_doc);
	} else {
		ni_fatal("ifup: non-file case not implemented yet");
	}

	if (!(__root_object = wicked_dbus_client_create()))
		return 1;

	interface_workers_refresh_state();

	if (build_hierarchy() < 0)
		ni_fatal("ifup: unable to build device hierarchy");

	if (!mark_matching_interfaces(ifname, STATE_NETWORK_UP))
		return 0;

	ni_dbus_client_add_signal_handler(ni_dbus_object_get_client(__root_object), NULL, NULL,
			                        WICKED_DBUS_NETIF_INTERFACE,
						interface_state_change_signal,
						NULL);

	interface_workers_kickstart();

	if (ni_ifworker_fsm() != 0)
		interface_worker_mainloop();

#if 0
		/* Request that the server take the interface up */
		config_dev->link.ifflags = NI_IFF_NETWORK_UP | NI_IFF_LINK_UP | NI_IFF_DEVICE_UP;

		req = __interface_request_build(config_dev);

		request_object = ni_objectmodel_wrap_interface_request(req);
		if (!ni_dbus_object_get_properties_as_dict(request_object, &wicked_dbus_interface_request_service, &argument)) {
			ni_interface_request_free(req);
			ni_dbus_object_free(request_object);
			ni_netconfig_free(nc);
			goto failed;
		}

		ni_interface_request_free(req);
		ni_dbus_object_free(request_object);
		ni_netconfig_free(nc);

		if (config_dev->startmode.ifaction[ifevent].action == NI_INTERFACE_IGNORE) {
			ni_error("not permitted to bring up interface");
			goto failed;
		}
	} else {
		/* No options, just bring up with default options
		 * (which may include dhcp) */
	}

	if (!(root_object = wicked_dbus_client_create()))
		goto failed;

	if (!(dev_object = wicked_get_interface(root_object, ifname)))
		goto failed;

	/* now do the real dbus call to bring it up */
	if (!ni_dbus_object_call_variant(dev_object,
				WICKED_DBUS_NETIF_INTERFACE, "up",
				1, &argument, 0, NULL, &error)) {
		ni_error("Unable to configure interface. Server responds:");
		fprintf(stderr, /* ni_error_extra */
			"%s: %s\n", error.name, error.message);
		dbus_error_free(&error);
		goto failed;
	}

	rv = 0;

	// then wait for a signal from the server to tell us it's actually up

	ni_debug_wicked("successfully configured %s", ifname);
	rv = 0; /* success */
#endif

failed:
	if (config_dev)
		ni_interface_put(config_dev);
	ni_dbus_variant_destroy(&argument);
	return rv;
}
