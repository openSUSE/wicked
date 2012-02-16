/*
 * Copyright (C) 2010-2011 Olaf Kirch <okir@suse.de>
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

typedef struct ni_interface_state ni_interface_state_t;
typedef struct ni_interface_state_array {
	unsigned int		count;
	ni_interface_state_t **	data;
} ni_interface_state_array_t;

typedef struct ni_interface_op {
	const char *		name;
	int			(*call)(ni_interface_state_t *, ni_netconfig_t *);
	int			(*check)(ni_interface_state_t *, ni_netconfig_t *, unsigned int);
	int			(*timeout)(ni_interface_state_t *);
} ni_interface_op_t;

struct ni_interface_state {
	unsigned int		refcount;

	char *			name;
	char *			object_path;
	unsigned int		ifindex;
	ni_iftype_t		iftype;

	int			target_state;
	int			state;
	unsigned int		is_slave  : 1;

	xml_node_t *		config;
	ni_interface_t *	device;

	unsigned int		shared_users;
	ni_interface_state_t *	exclusive_owner;

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

	ni_interface_state_t *	parent;
	ni_interface_state_array_t children;
};


static ni_interface_state_array_t interface_workers;
static int		work_to_be_done;

static void		ni_interface_state_array_append(ni_interface_state_array_t *, ni_interface_state_t *);
static void		ni_interface_state_array_destroy(ni_interface_state_array_t *);

static inline ni_interface_state_t *
ni_interface_state_new(const char *name, xml_node_t *config)
{
	ni_interface_state_t *w;

	w = calloc(1, sizeof(*w));
	ni_string_dup(&w->name, name);
	w->config = config;
	w->refcount = 1;

	return w;
}

static void
ni_interface_state_free(ni_interface_state_t *state)
{
	ni_string_free(&state->name);
	ni_interface_state_array_destroy(&state->children);
}

static inline void
ni_interface_state_release(ni_interface_state_t *state)
{
	if (--(state->refcount) == 0)
		ni_interface_state_free(state);
}

static const char *
ni_interface_state_name(int state)
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
ni_interface_state_array_append(ni_interface_state_array_t *array, ni_interface_state_t *w)
{
	array->data = realloc(array->data, (array->count + 1) * sizeof(array->data[0]));
	array->data[array->count++] = w;
	w->refcount++;
}

static void
ni_interface_state_array_destroy(ni_interface_state_array_t *array)
{
	while (array->count)
		ni_interface_state_release(array->data[--(array->count)]);
	free(array->data);
	array->data = NULL;
}

static ni_interface_state_t *
ni_interface_state_array_find(ni_interface_state_array_t *array, const char *ifname)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		ni_interface_state_t *worker = array->data[i];

		if (!strcmp(worker->name, ifname))
			return worker;
	}
	return NULL;
}

static ni_interface_state_t *
ni_interface_state_add_child(ni_interface_state_t *parent, ni_interface_state_t *worker)
{
	unsigned int i;

	for (i = 0; i < parent->children.count; ++i) {
		if (parent->children.data[i] == worker)
			return worker;
	}

	ni_interface_state_array_append(&parent->children, worker);

#if 0
	if (parent->behavior.mandatory)
		worker->behavior.mandatory = 1;
#endif
	worker->is_slave = 1;

	return worker;
}

static void
add_interface_worker(const char *name, xml_node_t *config)
{
	ni_interface_state_t *worker;

	worker = ni_interface_state_new(name, config);
	ni_interface_state_array_append(&interface_workers, worker);
	ni_interface_state_release(worker);
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

static unsigned int
mark_matching_interfaces(const char *match_name, unsigned int target_state)
{
	unsigned int i, count = 0;

	ni_debug_dbus("%s(name=%s, target_state=%s)", __func__, match_name, ni_interface_state_name(target_state));

	if (!strcmp(match_name, "all"))
		match_name = NULL;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_interface_state_t *w = interface_workers.data[i];

		if (match_name) {
			if (w->name == NULL || strcmp(match_name, w->name))
				continue;
		}

		/* FIXME: check for matching behavior definition */

		ni_debug_dbus("%s: target state %s", w->name, ni_interface_state_name(target_state));
		w->target_state = target_state;

		if (target_state >= STATE_LINK_UP) {
			unsigned int j;

			/* VLAN devices cannot be taken up unless the underlying eth
			 * device is up. */
			for (j = 0; j < w->children.count; ++j) {
				ni_interface_state_t *child = w->children.data[j];

				if (child->target_state < STATE_LINK_UP)
					child->target_state = STATE_LINK_UP;
			}
		}
		count++;
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
static int
build_hierarchy(void)
{
	unsigned int i;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_interface_state_t *w = interface_workers.data[i];
		xml_node_t *ifnode, *linknode, *devnode;
		ni_interface_state_t *child;

		ifnode = w->config;

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
				continue;
			}

			child = ni_interface_state_array_find(&interface_workers, slave_name);
			if (child == NULL) {
				/* We may not have the config for this device, but it may exist
				 * in the system. */
			}

			if (child == NULL) {
				ni_error("%s: <%s> element references unknown slave device %s",
						xml_node_location(ifnode),
						linknode->name,
						slave_name);
				continue;
			}

			if (child->exclusive_owner != NULL) {
				char *other_owner;

				other_owner = strdup(xml_node_location(child->exclusive_owner->config));
				ni_error("%s: slave interface already owned by %s",
						xml_node_location(devnode), other_owner);
				free(other_owner);
				return -1;
			}

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

			ni_interface_state_add_child(w, child);
		}
	}

	return 0;
}

static void
interface_state_change_signal(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	unsigned int min_state = STATE_NONE, max_state = __STATE_MAX;
	unsigned int i, all_ready = 1;

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
		ni_interface_state_t *w = interface_workers.data[i];

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
						ni_interface_state_name(prev_state),
						ni_interface_state_name(w->state));
		}

		if (w->state != w->target_state)
			all_ready = 0;
	}

	if (all_ready) {
		ni_debug_dbus("all devices have reached the intended state");
		work_to_be_done = 0;
	}
}

void
interface_workers_refresh_state(ni_dbus_object_t *root_object)
{
	static ni_dbus_object_t *iflist = NULL;
	ni_dbus_object_t *object;
	ni_interface_state_t *w;
	unsigned int i;

	if (!iflist && !(iflist = wicked_get_interface_object(NULL)))
		ni_fatal("unable to get server's interface list");

	/* Call ObjectManager.GetManagedObjects to get list of objects and their properties */
	if (!ni_dbus_object_refresh_children(iflist))
		ni_fatal("Couldn't refresh list of active network interfaces");

	for (i = 0; i < interface_workers.count; ++i) {
		ni_interface_t *dev;

		w = interface_workers.data[i];
		if ((dev = w->device) != NULL) {
			w->device = NULL;
			ni_interface_put(dev);
		}
	}

	for (object = iflist->children; object; object = object->next) {
		ni_interface_t *dev = ni_objectmodel_unwrap_interface(object);

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

			if (!w->object_path)
				ni_string_dup(&w->object_path, object->path);
			w->device = ni_interface_get(dev);
			w->ifindex = dev->link.ifindex;
			break;
		}
	}
}

int
interface_workers_kickstart(ni_dbus_object_t *root_object)
{
	ni_interface_state_t *w;
	unsigned int i;

	interface_workers_refresh_state(root_object);

	for (i = 0; i < interface_workers.count; ++i) {
		w = interface_workers.data[i];

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

		if (w->device == NULL) {
			const ni_dbus_service_t *service;
			xml_node_t *linknode;
			const char *link_type;
			const char *object_path;

			/* Device doesn't exist yet, try to create it */
			ni_trace("interface_workers_kickstart: should create %s", w->name);
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
		}

		if (w->state < STATE_DEVICE_UP)
			w->state = STATE_DEVICE_UP;

		/* Have the FSM work on this */
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
	ni_dbus_object_t *root_object;
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

	if (build_hierarchy() < 0)
		ni_fatal("ifup: unable to build device hierarchy");

	if (!mark_matching_interfaces(ifname, STATE_NETWORK_UP))
		return 0;

	if (!(root_object = wicked_dbus_client_create()))
		return 1;

	ni_dbus_client_add_signal_handler(ni_dbus_object_get_client(root_object), NULL, NULL,
			                        WICKED_DBUS_NETIF_INTERFACE,
						interface_state_change_signal,
						NULL);

	interface_workers_kickstart(root_object);
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
