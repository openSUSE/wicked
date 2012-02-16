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
#include <wicked/xml.h>
#include <wicked/socket.h>
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

#define NI_IFWORKER_DEFAULT_TIMEOUT	20000

typedef struct ni_ifworker	ni_ifworker_t;

typedef struct ni_ifworker_array {
	unsigned int		count;
	ni_ifworker_t **	data;
} ni_ifworker_array_t;

typedef int			ni_netif_action_fn_t(ni_ifworker_t *);
typedef struct ni_netif_action {
	int			next_state;
	ni_netif_action_fn_t *	func;
} ni_netif_action_t;

struct ni_ifworker {
	unsigned int		refcount;

	char *			name;

	ni_dbus_object_t *	object;
	char *			object_path;

	unsigned int		ifindex;
	ni_iftype_t		iftype;

	int			target_state;
	int			state;
	int			wait_for_state;
	const ni_timer_t *	timer;

	ni_objectmodel_callback_info_t *callbacks;
	unsigned int		failed		: 1,
				done		: 1;

	xml_node_t *		config;
	ni_interface_t *	device;

	unsigned int		shared_users;
	ni_ifworker_t *		exclusive_owner;

	ni_netif_action_t *	actions;

	ni_ifworker_t *		parent;
	ni_ifworker_array_t	children;
};


static ni_ifworker_array_t	interface_workers;
static unsigned int		ni_ifworker_timeout_count;

static ni_dbus_object_t *	__root_object;

static const char *		ni_ifworker_state_name(int);
static void			ni_ifworker_array_append(ni_ifworker_array_t *, ni_ifworker_t *);
static void			ni_ifworker_array_destroy(ni_ifworker_array_t *);
static void			ni_ifworker_fsm_init(ni_ifworker_t *);
static const ni_dbus_service_t *__ni_ifworker_check_addrconf(const char *);

static inline ni_ifworker_t *
__ni_ifworker_new(const char *name, xml_node_t *config)
{
	ni_ifworker_t *w;

	w = calloc(1, sizeof(*w));
	ni_string_dup(&w->name, name);
	w->config = config;
	w->refcount = 1;

	return w;
}

static ni_ifworker_t *
ni_ifworker_new(const char *name, xml_node_t *config)
{
	ni_ifworker_t *worker;

	worker = __ni_ifworker_new(name, config);
	ni_ifworker_array_append(&interface_workers, worker);
	worker->refcount--;

	return worker;
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
	printf("%s: %s\n", w->name, ni_ifworker_state_name(w->state));
	w->done = 1;
}

/*
 * Handle timeouts of device config.
 */
static void
__ni_ifworker_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_ifworker_t *w = user_data;

	if (w->timer != timer) {
		ni_error("%s(%s) called with unexpected timer", __func__, w->name);
	} else {
		ni_ifworker_fail(w, "operation timed out");
	}
	ni_ifworker_timeout_count++;
}

static void
ni_ifworker_set_timeout(ni_ifworker_t *w, unsigned long timeout_ms)
{
	if (w->timer)
		ni_timer_cancel(w->timer);
	w->timer = ni_timer_register(timeout_ms, __ni_ifworker_timeout, w);
}

static const char *
ni_ifworker_state_name(int state)
{
	static ni_intmap_t __state_names[] = {
		{ "none",		STATE_NONE		},
		{ "device-down",	STATE_DEVICE_DOWN	},
		{ "device-up",		STATE_DEVICE_UP		},
		{ "link-up",		STATE_LINK_UP		},
		{ "link-authenticated",	STATE_LINK_AUTHENTICATED},
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
ni_ifworker_by_object_path(const char *object_path)
{
	unsigned int i;

	if (!object_path)
		return NULL;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (w->object_path && !strcmp(w->object_path, object_path))
			return w;
	}

	return NULL;
}

static ni_ifworker_t *
ni_ifworker_add_child(ni_ifworker_t *parent, ni_ifworker_t *child, xml_node_t *devnode)
{
	unsigned int i;

	/* Check if this child is already owned by the given parent. */
	for (i = 0; i < parent->children.count; ++i) {
		if (parent->children.data[i] == child)
			return child;
	}

	if (child->exclusive_owner != NULL) {
		char *other_owner;

		other_owner = strdup(xml_node_location(child->exclusive_owner->config));
		ni_error("%s: slave interface already owned by %s",
				xml_node_location(devnode), other_owner);
		free(other_owner);
		return NULL;
	}

	switch (parent->iftype) {
	case NI_IFTYPE_VLAN:
		child->shared_users++;
		break;

	default:
		if (child->shared_users) {
			ni_error("%s: interface already in shared use by other interfaces",
					xml_node_location(devnode));
			return NULL;
		}
		child->exclusive_owner = parent;
		break;
	}


	ni_ifworker_array_append(&parent->children, child);

#if 0
	if (parent->behavior.mandatory)
		child->behavior.mandatory = 1;
#endif

	return child;
}

/* Create an event wait object */
static void
ni_ifworker_add_callbacks(ni_ifworker_t *w, ni_objectmodel_callback_info_t *callback_list)
{
	ni_objectmodel_callback_info_t **pos, *cb;

	if (ni_debug & NI_TRACE_DBUS) {
		ni_trace("%s waiting for callbacks:", w->name);
		for (cb = callback_list; cb; cb = cb->next) {
			ni_trace(" %s event=%s",
				ni_print_hex(cb->uuid.octets, 16),
				cb->event);
		}
	}

	for (pos = &w->callbacks; (cb = *pos) != NULL; pos = &cb->next)
		;
	*pos = callback_list;
}

static ni_objectmodel_callback_info_t *
ni_ifworker_get_callback(ni_ifworker_t *w, const ni_uuid_t *uuid)
{
	ni_objectmodel_callback_info_t **pos, *cb;

	for (pos = &w->callbacks; (cb = *pos) != NULL; pos = &cb->next) {
		if (ni_uuid_equal(&cb->uuid, uuid)) {
			*pos = cb->next;
			return cb;
		}
	}
	return NULL;
}

static unsigned int
ni_ifworkers_from_xml(xml_document_t *doc)
{
	xml_node_t *root, *ifnode;
	unsigned int count = 0;

	root = xml_document_root(doc);
	for (ifnode = root->children; ifnode; ifnode = ifnode->next) {
		const char *ifname = NULL;
		xml_node_t *node;

		if (!ifnode->name || strcmp(ifnode->name, "interface")) {
			ni_warn("%s: ignoring non-interface element <%s>",
					xml_node_location(ifnode),
					ifnode->name);
			continue;
		}

		if ((node = xml_node_get_child(ifnode, "name")) != NULL)
			ifname = node->cdata;

		ni_ifworker_new(ifname, ifnode);
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

	if (w->children.count != 0) {
		unsigned int i;

		switch (w->iftype) {
		case NI_IFTYPE_VLAN:
			/* To brin a VLAN device up, the underlying eth device must be up.
			 * When bringing the VLAN down, don't touch the ethernet device,
			 * as it's shared. */
			if (min_state >= STATE_LINK_UP) {
				min_state = STATE_LINK_UP;
				max_state = __STATE_MAX;
			} else {
				return;
			}
			break;

		case NI_IFTYPE_BRIDGE:
			/* bridge device: the bridge ports should at least exist.
			 * However, in order to do anything useful, they should at
			 * least have link.
			 * We may later want to allow the config file to override
			 * the initial state for specific bridge ports.
			 */
			if (min_state >= STATE_LINK_UP) {
				min_state = STATE_LINK_UP;
				max_state = __STATE_MAX;
			}
			break;

		case NI_IFTYPE_BOND:
			/* bond device: all slaves devices must exist and be down */
			if (min_state >= STATE_LINK_UP) {
				min_state = STATE_LINK_UP - 1;
				max_state = STATE_LINK_UP - 1;
			}
			break;

		default:
			return;
		}

		ni_debug_dbus("%s: marking all children min=%s max=%s", w->name,
				ni_ifworker_state_name(min_state),
				ni_ifworker_state_name(max_state));
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

	ni_debug_dbus("%s(name=%s, target_state=%s)", __func__, match_name, ni_ifworker_state_name(target_state));

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

		if (w->target_state != STATE_NONE) {
			ni_debug_dbus("%s: target state %s",
					w->name, ni_ifworker_state_name(w->target_state));
			ni_ifworker_set_timeout(w, NI_IFWORKER_DEFAULT_TIMEOUT);
			ni_ifworker_fsm_init(w);
		}
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

			if (!ni_ifworker_add_child(w, child, devnode))
				return -1;
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
ni_ifworkers_refresh_state(void)
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

		/* Always clear the object - we don't know if it's still there
		 * after we've called ni_dbus_object_refresh_children() */
		w->object = NULL;

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
		ni_interface_t *dev = ni_objectmodel_unwrap_interface(object, NULL);
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
			found = ni_ifworker_new(dev->name, NULL);

		/* Don't touch devices we're done with */
		if (found->done)
			continue;

		if (!found->object_path)
			ni_string_dup(&found->object_path, object->path);
		found->device = ni_interface_get(dev);
		found->ifindex = dev->link.ifindex;
		found->object = object;

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

/*
 * Finite state machine - create the device if it does not exist
 * Note this is called for all virtual devices, because the newLink
 * call also takes care of setting up things like the ports assigned
 * to a bridge.
 */
static int
ni_ifworker_do_device_up(ni_ifworker_t *w)
{
	const ni_dbus_service_t *service;
	xml_node_t *linknode;
	const char *link_type;
	const char *object_path;

	ni_debug_dbus("%s(%s)", __func__, w->name);
	if (!(linknode = wicked_find_link_properties(w->config))) {
		/* If the device exists, this is not an error */
		if (w->device != NULL)
			goto device_is_up;

		ni_ifworker_fail(w, "cannot create interface: no link layer config");
		return -1;
	}
	link_type = linknode->name;

	if (!(service = wicked_link_layer_factory_service(link_type))) {
		ni_ifworker_fail(w, "unknown/unsupported link type %s", link_type);
		return -1;
	}

	object_path = wicked_create_interface_xml(service, w->name, linknode);
	if (object_path == NULL) {
		ni_error("%s: failed to create interface", w->name);
		return -1;
	}

	ni_debug_dbus("created device %s (path=%s)", w->name, object_path);
	ni_string_dup(&w->object_path, object_path);

	{
		unsigned int len = strlen("/com/suse/Wicked/");

		ni_assert(!strncmp(object_path, "/com/suse/Wicked/", len));
		object_path += len;
	}

	/* Lookup the object corresponding to this path. If it doesn't
	 * exist, create it on the fly (with a generic class of "netif" -
	 * the next refresh call with take care of this and correct the
	 * class */
	w->object = ni_dbus_object_create(__root_object, object_path,
				NULL,
				NULL);

device_is_up:
	w->state = STATE_DEVICE_UP;
	return 0;
}

/*
 * Finite state machine - bring up the device link layer.
 */
static int
ni_ifworker_do_link_up(ni_ifworker_t *w)
{
	ni_objectmodel_callback_info_t *callback_list = NULL;
	xml_node_t *devnode;

	ni_debug_dbus("%s(name=%s, object=%p, path=%s)", __func__, w->name, w->object, w->object_path);

	devnode = xml_node_get_child(w->config, "device");
	if (!wicked_link_up_xml(w->object, devnode, &callback_list)) {
		ni_ifworker_fail(w, "failed to configure and bring up link");
		return -1;
	}

	if (callback_list == NULL) {
		w->state = STATE_LINK_UP;
	} else {
		ni_ifworker_add_callbacks(w, callback_list);
		w->wait_for_state = STATE_LINK_UP;
	}

	return 0;
}

/*
 * Finite state machine - do link authentication
 */
static int
ni_ifworker_do_linkauth(ni_ifworker_t *w)
{
	/* For now, nothing to be done - this needs to be implemented */
	ni_debug_dbus("%s(%s)", __func__, w->name);
	w->state = STATE_LINK_AUTHENTICATED;
	return 0;
}

/*
 * Finite state machine - configure network addresses and routes
 */
static int
ni_ifworker_do_network_up(ni_ifworker_t *w)
{
	xml_node_t *child;

	ni_debug_dbus("%s(%s)", __func__, w->name);
	for (child = w->config->children; child; child = child->next) {
		ni_objectmodel_callback_info_t *callback_list = NULL;
		const ni_dbus_service_t *service;

		/* Addrconf elements are of the form <family:mode>, e.g.
		 * ipv6:static or ipv4:dhcp */
		if (!(service = __ni_ifworker_check_addrconf(child->name)))
			continue;

		/* Okay, this is an addrconf node */
		ni_debug_dbus("%s: found element <%s>, using interface %s",
				w->name, child->name, service->name);

		/* Call the service's configure() method.
		 * If the addresses could be configured instantly,
		 * it will just return a success status.
		 * If the address configuration is in progress (e.g. dhcp),
		 * we will receive a token indicating that the address
		 * acquisition is in process. When that completes, the server
		 * will emit a signal (addressConfigured) with the same token.
		 */
		if (!ni_call_request_lease_xml(w->object, service, child, &callback_list)) {
			ni_ifworker_fail(w, "address configuration failed (%s)", child->name);
			return -1;
		}

		if (callback_list) {
			ni_ifworker_add_callbacks(w, callback_list);
			w->wait_for_state = STATE_NETWORK_UP;
		}
	}
	if (w->callbacks == NULL) {
		ni_debug_dbus("%s: no address configuration; we're done", w->name);
		w->state = STATE_NETWORK_UP;
	}

	return 0;
}

static int
ni_ifworker_do_network_down(ni_ifworker_t *w)
{
	ni_debug_dbus("%s(%s)", __func__, w->name);
	ni_ifworker_fail(w, "%s not implemented yet", __func__);

#if 0
	if (w->callbacks == NULL) {
		ni_debug_dbus("%s: no address configuration; we're done", w->name);
		w->state = STATE_NETWORK_DOWN;
	}
#endif

	return 0;
}

static const ni_dbus_service_t *
__ni_ifworker_check_addrconf(const char *name)
{
	const ni_dbus_service_t *service = NULL;
	char *copy, *afname, *modename;

	copy = afname = strdup(name);
	if ((modename = strchr(copy, ':')) != NULL) {

		*modename++ = '\0';
		if (ni_addrfamily_name_to_type(afname) >= 0
		 &&  ni_addrconf_name_to_type(modename) >= 0) {
			char interface[128];

			snprintf(interface, sizeof(interface), "%s.Addrconf.%s.%s",
					WICKED_DBUS_INTERFACE,
					afname, modename);
			service = ni_objectmodel_service_by_name(interface);
			if (!service)
				ni_warn("No addrconf service for %s:%s; ignored", afname, modename);
		}
	}

	free(copy);
	return service;
}

/*
 * Finite state machine
 */
static ni_netif_action_t	ni_ifworker_fsm_up[] = {
	/* This creates the device (if it's virtual) and sets any device attributes,
	 * such as a MAC address */
	{ .next_state = STATE_DEVICE_UP,	.func = ni_ifworker_do_device_up },

	/* This step adds device-specific filtering, if available. Typical
	 * example would be bridge filtering with ebtables. */
//	{ .next_state = STATE_DEVICE_FILTER_UP,	.func = ni_ifworker_do_device_filter_up },

	/* This brings up the link layer, and sets general device attributes such
	 * as the MTU, the transfer queue length etc. */
	{ .next_state = STATE_LINK_UP,		.func = ni_ifworker_do_link_up },

	/* If the link requires authentication, this information can be provided
	 * here; for instance ethernet 802.1x, wireless WPA, or PPP chap/pap.
	 * NOTE: This may not be the right place; we may have to fold this into
	 * the link_up step, or even do it prior to that. */
	{ .next_state = STATE_LINK_AUTHENTICATED,.func = ni_ifworker_do_linkauth },

	/* Configure all assigned addresses and bring up the network */
	{ .next_state = STATE_NETWORK_UP,	.func = ni_ifworker_do_network_up },

	{ .next_state = STATE_NONE, .func = NULL }
};

static ni_netif_action_t	ni_ifworker_fsm_down[] = {
	/* Remove all assigned addresses and bring down the network */
	{ .next_state = STATE_NETWORK_UP,	.func = ni_ifworker_do_network_down },

	{ .next_state = STATE_NONE, .func = NULL }
};

static void
ni_ifworker_fsm_init(ni_ifworker_t *w)
{
	if (w->state < w->target_state) {
		w->actions = ni_ifworker_fsm_up;
	} else
	if (w->state > w->target_state) {
		w->actions = ni_ifworker_fsm_down;
	}
}

static unsigned int
ni_ifworker_fsm(void)
{
	unsigned int i, waiting;

	ni_debug_dbus("%s()", __func__);
	while (1) {
		int made_progress = 0;

		for (i = 0; i < interface_workers.count; ++i) {
			ni_ifworker_t *w = interface_workers.data[i];
			ni_netif_action_t *action;
			int prev_state;

			if (w->target_state != STATE_NONE)
				ni_debug_dbus("%-12s: state=%s want=%s%s%s", w->name,
					ni_ifworker_state_name(w->state),
					ni_ifworker_state_name(w->target_state),
					w->wait_for_state? ", wait-for=" : "",
					w->wait_for_state?  ni_ifworker_state_name(w->wait_for_state) : "");

			if (w->failed || ni_ifworker_ready(w))
				continue;

			/* If we're still waiting for children to become ready,
			 * there's nothing we can do but wait. */
			if (!ni_interface_children_ready(w))
				continue;

			/* We requested a change that takes time (such as acquiring
			 * a DHCP lease). Wait for a notification from wickedd */
			if (w->wait_for_state)
				continue;

			action = w->actions++;
			if (action->next_state == STATE_NONE) {
				w->state = w->target_state;
				ni_ifworker_success(w);
				made_progress = 1;
				continue;
			}

			prev_state = w->state;
			if (action->func(w) >= 0) {
				made_progress = 1;
				if (w->state == action->next_state) {
					/* We should not have transitioned to the next state while
					 * we were still waiting for some event. */
					ni_assert(w->callbacks == NULL);
					ni_debug_dbus("%s: successfully transitioned from %s to %s",
						w->name,
						ni_ifworker_state_name(prev_state),
						ni_ifworker_state_name(w->state));
				} else {
					ni_debug_dbus("%s: waiting for event in state %s",
						w->name,
						ni_ifworker_state_name(w->state));
					w->wait_for_state = action->next_state;
				}
			} else
			if (!w->failed) {
				/* The fsm action should really have marked this
				 * as a failure. shame on the lazy programmer. */
				ni_ifworker_fail(w, "%s: failed to transition from %s to %s",
						w->name,
						ni_ifworker_state_name(prev_state),
						ni_ifworker_state_name(w->state));
			}
		}

		if (!made_progress)
			break;

		ni_ifworkers_refresh_state();
	}

	for (i = waiting = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (!w->failed && !ni_ifworker_ready(w))
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
	ni_uuid_t event_uuid = NI_UUID_INIT;
	ni_ifworker_t *w;

	ni_debug_dbus("%s: got signal %s from %s", __func__, signal_name, object_path);

	if (!strcmp(signal_name, "linkUp"))
		min_state = STATE_LINK_UP;
	if (!strcmp(signal_name, "networkUp"))
		min_state = STATE_NETWORK_UP;
	if (!strcmp(signal_name, "linkDown"))
		max_state = STATE_DEVICE_UP;
	if (!strcmp(signal_name, "networkDown"))
		max_state = STATE_LINK_UP;

	/* See if this event comes with a uuid */
	{
		ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
		int argc;

		argc = ni_dbus_message_get_args_variants(msg, &result, 1);
		if (argc < 0) {
			ni_error("%s: cannot extract parameters of signal %s",
					__func__, signal_name);
			return;
		}
		if (ni_dbus_variant_get_uuid(&result, &event_uuid))
			ni_debug_dbus("event uuid=%s", ni_print_hex(event_uuid.octets, 16));
		else
			ni_debug_dbus("event does not have a uuid");
		ni_dbus_variant_destroy(&result);
	}

	if ((w = ni_ifworker_by_object_path(object_path)) != NULL && w->target_state != STATE_NONE) {
		ni_objectmodel_callback_info_t *cb = NULL;

		if (!ni_uuid_is_null(&event_uuid)) {
			cb = ni_ifworker_get_callback(w, &event_uuid);
			if (cb) {
				if (ni_string_eq(cb->event, signal_name)) {
					ni_debug_dbus("... great, we were expecting this event");
				} else {
					ni_debug_dbus("%s: was waiting for %s event, but got %s",
							w->name, cb->event, signal_name);
					ni_ifworker_fail(w, "got signal %s", signal_name);
				}
				ni_objectmodel_callback_info_free(cb);
			}
		}

		if (!w->failed) {
			unsigned int prev_state = w->state;

			if (w->state < min_state)
				w->state = min_state;
			if (max_state < min_state)
				w->state = max_state;

			if (w->state != prev_state)
				ni_debug_dbus("device %s changed state %s -> %s",
						w->name,
						ni_ifworker_state_name(prev_state),
						ni_ifworker_state_name(w->state));
		}
	}
}

static dbus_bool_t
ni_ifworkers_create_client(void)
{
	if (!(__root_object = wicked_dbus_client_create()))
		return FALSE;

	ni_dbus_client_add_signal_handler(ni_dbus_object_get_client(__root_object), NULL, NULL,
			                        WICKED_DBUS_NETIF_INTERFACE,
						interface_state_change_signal,
						NULL);

	return TRUE;
}

static int
ni_ifworkers_kickstart(void)
{
	unsigned int i;

	ni_ifworkers_refresh_state();

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

static void
ni_ifworker_mainloop(void)
{
	while (1) {
		long timeout;

		while (1) {
			timeout = ni_timer_next_timeout();
			if (!ni_ifworker_timeout_count)
				break;

			/* A timeout has fired. Check whether we've failed the
			 * last device that we were waiting for. If that's
			 * the case, we're done.
			 */
			if (ni_ifworker_fsm() == 0)
				goto done;

			ni_ifworker_timeout_count = 0;
		}

		if (ni_socket_wait(timeout) < 0)
			ni_fatal("ni_socket_wait failed");

		if (ni_ifworker_fsm() == 0)
			break;
	}

done:
	ni_debug_dbus("finished with all devices.");
}

int
do_ifup(int argc, char **argv)
{
	enum  { OPT_FILE, OPT_BOOT };
	static struct option ifup_options[] = {
		{ "file", required_argument, NULL, OPT_FILE },
		{ "boot", no_argument, NULL, OPT_BOOT },
		{ NULL }
	};
	const char *ifname = NULL;
	const char *opt_file = NULL;
	unsigned int ifevent = NI_IFACTION_MANUAL_UP;
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

	if (opt_file) {
		xml_document_t *config_doc;

		if (!(config_doc = xml_document_read(opt_file))) {
			ni_error("unable to load interface definition from %s", opt_file);
			return 1;
		}

		ni_ifworkers_from_xml(config_doc);
	} else {
		ni_fatal("ifup: non-file case not implemented yet");
	}

	if (!ni_ifworkers_create_client())
		return 1;

	ni_ifworkers_refresh_state();

	if (build_hierarchy() < 0)
		ni_fatal("ifup: unable to build device hierarchy");

	if (!mark_matching_interfaces(ifname, STATE_NETWORK_UP))
		return 0;

	ni_ifworkers_kickstart();
	if (ni_ifworker_fsm() != 0)
		ni_ifworker_mainloop();

	return rv;
}

int
do_ifdown(int argc, char **argv)
{
	enum  { OPT_FILE, OPT_DELETE };
	static struct option ifdown_options[] = {
		{ "file", required_argument, NULL, OPT_FILE },
		{ "delete", required_argument, NULL, OPT_DELETE },
		{ NULL }
	};
	const char *ifname;
	const char *opt_file = NULL;
	int c, rv = 1;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifdown_options, NULL)) != EOF) {
		switch (c) {
		case OPT_FILE:
			opt_file = optarg;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifdown [ifdown-options] all\n"
				"wicked [options] ifdown [ifdown-options] <ifname> [options ...]\n"
				"\nSupported ifup-options:\n"
				"  --file <filename>\n"
				"      Read interface configuration(s) from file rather than using system config\n"
				"  --delete\n"
				"      Delete virtual interfaces\n"
				);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}
	ifname = argv[optind++];

	if (opt_file) {
		xml_document_t *config_doc;

		if (!(config_doc = xml_document_read(opt_file))) {
			ni_error("unable to load interface definition from %s", opt_file);
			return 1;
		}

		ni_ifworkers_from_xml(config_doc);
	} else {
		ni_fatal("ifup: non-file case not implemented yet");
	}

	if (!ni_ifworkers_create_client())
		return 1;

	ni_ifworkers_refresh_state();

	if (build_hierarchy() < 0)
		ni_fatal("ifup: unable to build device hierarchy");

	if (!mark_matching_interfaces(ifname, STATE_DEVICE_UP))
		return 0;

	ni_ifworkers_kickstart();
	if (ni_ifworker_fsm() != 0)
		ni_ifworker_mainloop();

	return rv;
}

