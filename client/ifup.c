/*
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/xml.h>
#include <wicked/socket.h>
#include <wicked/dbus.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/socket.h>
#include <wicked/xpath.h>

#include "wicked-client.h"


#define WICKED_IFCONFIG_DIR_PATH	"/etc/sysconfig/network"

extern ni_dbus_object_t *	wicked_get_interface(ni_dbus_object_t *, const char *);

/*
 * Interface state information
 */
enum {
	STATE_NONE = 0,
	STATE_DEVICE_DOWN,
	STATE_DEVICE_EXISTS,
	STATE_DEVICE_UP,
	STATE_FIREWALL_UP,
	STATE_LINK_UP,
	STATE_LINK_AUTHENTICATED,
	STATE_ADDRCONF_UP,

	__STATE_MAX
};

#define NI_IFWORKER_DEFAULT_TIMEOUT	20000

typedef struct ni_ifworker	ni_ifworker_t;
typedef struct ni_ifworker_req	ni_ifworker_req_t;

typedef struct ni_ifworker_array {
	unsigned int		count;
	ni_ifworker_t **	data;
} ni_ifworker_array_t;

#define NI_IFWORKER_EDGE_MAX_CALLS	8
typedef struct ni_ifworker_edge {
	ni_ifworker_t *		child;
	xml_node_t *		node;

	struct ni_ifworker_edge_precondition {
		char *		call_name;
		unsigned int	min_child_state;
		unsigned int	max_child_state;
	} call_pre[NI_IFWORKER_EDGE_MAX_CALLS];
} ni_ifworker_edge_t;

typedef struct ni_ifworker_children {
	unsigned int		count;
	ni_ifworker_edge_t *	data;
} ni_ifworker_children_t;

typedef struct ni_netif_action	ni_iftransition_t;

typedef int			ni_netif_action_fn_t(ni_ifworker_t *, ni_iftransition_t *);
struct ni_netif_action {
	int			from_state;
	int			next_state;
	ni_netif_action_fn_t *	bind_func;
	ni_netif_action_fn_t *	func;

	struct {
		const char *		service_name;
		const ni_dbus_service_t *service;

		const char *		method_name;
		const ni_dbus_method_t *method;

		xml_node_t *		config;

		ni_bool_t		call_overloading;
	} common;

#define NI_NETIF_ACTION_BINDINGS_MAX	32
	ni_bool_t			bound;
	unsigned int			num_bindings;
	struct ni_netif_action_binding {
		const ni_dbus_service_t *service;
		const ni_dbus_method_t *method;
		xml_node_t *		config;
		ni_bool_t		skip_call;
	} binding[NI_NETIF_ACTION_BINDINGS_MAX];

	ni_objectmodel_callback_info_t *callbacks;

	struct {
		ni_bool_t		parsed;
		ni_ifworker_req_t *	list;
	} require;
};

struct ni_ifworker {
	unsigned int		refcount;

	char *			name;

	ni_dbus_object_t *	object;
	char *			object_path;

	unsigned int		ifindex;

	ni_uint_range_t		target_range;
	int			target_state;
	int			state;
	ni_iftransition_t *	wait_for;
	const ni_timer_t *	timer;

	unsigned int		failed		: 1,
				done		: 1;

	xml_node_t *		config;
	ni_netdev_t *		device;

	struct {
		const ni_dbus_service_t *service;
		const ni_dbus_method_t *method;
		const ni_dbus_service_t *factory_service;
		const ni_dbus_method_t *factory_method;
		xml_node_t *	config;
	} device_api;

	unsigned int		shared_users;
	ni_ifworker_t *		exclusive_owner;

	ni_iftransition_t *	actions;

	ni_ifworker_t *		parent;
	unsigned int		depth;		/* depth in device graph */
	ni_ifworker_children_t	children;
};

typedef ni_bool_t		ni_ifworker_req_fn_t(ni_ifworker_t *, ni_ifworker_req_t *);
struct ni_ifworker_req {
	ni_ifworker_req_t *	next;

	unsigned int		event_seq;
	ni_ifworker_req_fn_t *	test_fn;
	xml_node_t *		data;
};

static ni_ifworker_array_t	interface_workers;
static unsigned int		ni_ifworker_timeout = NI_IFWORKER_DEFAULT_TIMEOUT;
static unsigned int		ni_ifworker_timeout_count;

static unsigned int		ni_ifworker_lease_acquired_seq = 1;

static ni_dbus_object_t *	__root_object;

static const char *		ni_ifworker_state_name(int);
static void			ni_ifworker_array_append(ni_ifworker_array_t *, ni_ifworker_t *);
static int			ni_ifworker_array_index(const ni_ifworker_array_t *, const ni_ifworker_t *);
static ni_ifworker_edge_t *	ni_ifworker_children_append(ni_ifworker_children_t *, ni_ifworker_t *, xml_node_t *);
static void			ni_ifworker_children_destroy(ni_ifworker_children_t *);
static ni_ifworker_t *		ni_ifworker_identify_device(const xml_node_t *);
static void			ni_ifworker_set_dependencies_xml(ni_ifworker_t *, xml_node_t *);
static void			ni_ifworker_fsm_init(ni_ifworker_t *, unsigned int, unsigned int);
static int			ni_ifworker_fsm_bind_methods(ni_ifworker_t *);
static ni_bool_t		ni_ifworker_req_check_reachable(ni_ifworker_t *, ni_ifworker_req_t *);
static ni_bool_t		ni_ifworker_req_netif_resolve(ni_ifworker_t *, ni_ifworker_req_t *);
//static void			ni_ifworker_req_free(ni_ifworker_req_t *);

static inline ni_ifworker_t *
__ni_ifworker_new(const char *name, xml_node_t *config)
{
	ni_ifworker_t *w;

	w = calloc(1, sizeof(*w));
	ni_string_dup(&w->name, name);
	w->config = config;
	w->refcount = 1;

	w->target_range.min = STATE_NONE;
	w->target_range.max = __STATE_MAX;

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
ni_ifworker_free(ni_ifworker_t *w)
{
	ni_string_free(&w->name);
	ni_ifworker_children_destroy(&w->children);

#if 0
	/* FIXME: this doesn't work, as we increment w->actions
	 * in ni_ifworker_fsm() */
	if (w->actions)
		free(w->actions);
#endif
}

static inline void
ni_ifworker_release(ni_ifworker_t *state)
{
	if (--(state->refcount) == 0)
		ni_ifworker_free(state);
}

/*
 * constructor/destructor for dependency objects
 */
ni_ifworker_req_t *
ni_ifworker_req_new(const char *check, xml_node_t *node, ni_ifworker_req_t **list)
{
	ni_ifworker_req_fn_t *fn = NULL;
	ni_ifworker_req_t *req, **pos;

	if (ni_string_eq(check, "reachable")) {
		fn = ni_ifworker_req_check_reachable;
	} else
	if (ni_string_eq(check, "netif-resolve")) {
		fn = ni_ifworker_req_netif_resolve;
	}

	if (fn == NULL) {
		ni_error("unknown function in <require check=\"%s\"> at %s", check, xml_node_location(node));
		return NULL;
	}

	/* Find tail of list */
	for (pos = list; (req = *pos) != NULL; pos = &req->next)
		;

	req = calloc(1, sizeof(*req));
	req->test_fn = fn;
	req->event_seq = ~0U;
	req->data = node;

	*pos = req;
	return req;
}

void
ni_ifworker_req_free(ni_ifworker_req_t *req)
{
	free(req);
}

static ni_bool_t
ni_ifworker_req_check_reachable(ni_ifworker_t *w, ni_ifworker_req_t *req)
{
	const char *hostname, *attr;
	int afhint = AF_UNSPEC;
	ni_sockaddr_t address;

	if (!req->data)
		return FALSE;
	if (!(hostname = req->data->cdata))
		return FALSE;

	/* Do not check too often. If the dhcp or routing info didn't change,
	 * there is no point wasting time on another lookup. */
	if (req->event_seq == ni_ifworker_lease_acquired_seq) {
		ni_debug_application("check reachability: %s SKIP", hostname);
		return FALSE;
	}
	req->event_seq = ni_ifworker_lease_acquired_seq;

	if ((attr = xml_node_get_attr(req->data, "address-family")) != NULL) {
		if ((afhint = ni_addrfamily_name_to_type(attr)) < 0) {
			ni_error("%s: bad address-family attribute \"%s\"",
					xml_node_location(req->data), attr);
			return FALSE;
		}
	}

	if (ni_resolve_hostname_timed(hostname, afhint, &address, 1) <= 0) {
		ni_debug_application("check reachability: %s not resolvable", hostname);
		return FALSE;
	}

	if (ni_host_is_reachable(hostname, &address) <= 0) {
		ni_debug_application("check reachability: %s not reachable at %s",
				hostname, ni_address_print(&address));
		return FALSE;
	}

	ni_debug_application("check reachability: %s OK", hostname);
	return TRUE;
}

/*
 * Handle success/failure of an ifworker.
 */
static void
ni_ifworker_fail(ni_ifworker_t *w, const char *fmt, ...)
{
	char errmsg[256];
	va_list ap;

	if (w->failed)
		return;

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
	if (!w->done)
		printf("%s: %s\n", w->name, ni_ifworker_state_name(w->state));
	w->done = 1;
}

static unsigned int
ni_ifworkers_fail_count(void)
{
	unsigned int i, nfailed = 0;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (w->failed)
			nfailed++;
	}

	return nfailed;
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

static ni_intmap_t __state_names[] = {
	{ "none",		STATE_NONE		},
	{ "device-down",	STATE_DEVICE_DOWN	},
	{ "device-exists",	STATE_DEVICE_EXISTS	},
	{ "device-up",		STATE_DEVICE_UP		},
	{ "firewall-up",	STATE_FIREWALL_UP	},
	{ "link-up",		STATE_LINK_UP		},
	{ "link-authenticated",	STATE_LINK_AUTHENTICATED},
	{ "network-up",		STATE_ADDRCONF_UP	},
	{ "max",		__STATE_MAX		},

	{ NULL }
};

static const char *
ni_ifworker_state_name(int state)
{
	return ni_format_int_mapped(state, __state_names);
}

static int
ni_ifworker_state_from_name(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __state_names, &value) < 0)
		return -1;
	return value;
}

static void
ni_ifworker_array_append(ni_ifworker_array_t *array, ni_ifworker_t *w)
{
	array->data = realloc(array->data, (array->count + 1) * sizeof(array->data[0]));
	array->data[array->count++] = w;
	w->refcount++;
}

int
ni_ifworker_array_index(const ni_ifworker_array_t *array, const ni_ifworker_t *w)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		if (array->data[i] == w)
			return i;
	}
	return -1;
}

void
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

	if (!ifname)
		return NULL;

	for (i = 0; i < array->count; ++i) {
		ni_ifworker_t *worker = array->data[i];

		if (!strcmp(worker->name, ifname))
			return worker;
	}
	return NULL;
}

static ni_ifworker_t *
ni_ifworker_by_ifname(const char *ifname)
{
	return ni_ifworker_array_find(&interface_workers, ifname);
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
ni_ifworker_by_netdev(const ni_netdev_t *dev)
{
	unsigned int i;

	if (dev == NULL)
		return NULL;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (w->device == dev)
			return w;
		if (w->ifindex && w->ifindex == dev->link.ifindex)
			return w;
		if (w->name && ni_string_eq(dev->name, w->name))
			return w;
	}

	return NULL;
}

static ni_ifworker_t *
ni_ifworker_by_alias(const char *alias)
{
	unsigned int i;

	if (!alias)
		return NULL;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];
		xml_node_t *node;

		if (w->device && ni_string_eq(w->device->link.alias, alias))
			return w;

		if (w->config && (node = xml_node_get_child(w->config, "alias")) != NULL) {
			if (ni_string_eq(node->cdata, alias))
				return w;
		}
	}

	return NULL;
}

static ni_ifworker_t *
ni_ifworker_resolve_reference(xml_node_t *devnode)
{
	ni_ifworker_t *child;
	const char *slave_name;

	slave_name = devnode->cdata;
	if (slave_name != NULL) {
		child = ni_ifworker_array_find(&interface_workers, slave_name);

		if (child == NULL) {
			ni_error("%s: <%s> element references unknown slave device %s",
					xml_node_location(devnode),
					devnode->name,
					slave_name);
			return NULL;
		}
	} else
	if (devnode->children) {
		/* Try to identify device based on attributes given in the
		 * <device> node. */
		child = ni_ifworker_identify_device(devnode);
		if (child == NULL) {
			ni_error("%s: <%s> element references unknown slave device",
					xml_node_location(devnode),
					devnode->name);
			return NULL;
		}

		if (child->name == NULL) {
			ni_warn("%s: <%s> element references slave device with no name",
					xml_node_location(devnode),
					devnode->name);
		}

		ni_debug_application("%s: identified device as \"%s\"",
				xml_node_location(devnode),
				child->name);
		xml_node_set_cdata(devnode, child->name);
	} else {
		ni_error("%s: empty device reference in <%s> element",
				xml_node_location(devnode),
				devnode->name);
		return NULL;
	}

	return child;
}

static ni_ifworker_edge_t *
ni_ifworker_children_append(ni_ifworker_children_t *array, ni_ifworker_t *child, xml_node_t *node)
{
	struct ni_ifworker_edge *edge;

	array->data = realloc(array->data, (array->count + 1) * sizeof(array->data[0]));
	edge = &array->data[array->count++];

	memset(edge, 0, sizeof(*edge));
	edge->child = child;
	edge->node = node;
	child->refcount++;

	return edge;
}

static void
ni_ifworker_children_destroy(ni_ifworker_children_t *array)
{
	struct ni_ifworker_edge *edge;
	unsigned int i, j;

	for (edge = array->data, i = 0; i < array->count; ++i, ++edge) {
		ni_ifworker_release(edge->child);
		for (j = 0; j < NI_IFWORKER_EDGE_MAX_CALLS; ++j)
			ni_string_free(&edge->call_pre[i].call_name);
	}
	free(array->data);
	memset(array, 0, sizeof(*array));
}


static ni_ifworker_edge_t *
ni_ifworker_add_child(ni_ifworker_t *parent, ni_ifworker_t *child, xml_node_t *devnode, ni_bool_t shared)
{
	ni_ifworker_edge_t *edge;
	unsigned int i;

	/* Check if this child is already owned by the given parent. */
	for (i = 0, edge = parent->children.data; i < parent->children.count; ++i, ++edge) {
		if (parent->children.data[i].child == child)
			return edge;
	}

	if (child->exclusive_owner != NULL) {
		char *other_owner;

		other_owner = strdup(xml_node_location(child->exclusive_owner->config));
		ni_error("%s: subordinate interface already owned by %s",
				xml_node_location(devnode), other_owner);
		free(other_owner);
		return NULL;
	}

	if (shared) {
		/* The reference allows sharing with other uses, e.g. VLANs. */
		child->shared_users++;
	} else {
		if (child->shared_users) {
			ni_error("%s: interface already in shared use by other interfaces",
					xml_node_location(devnode));
			return NULL;
		}
		child->exclusive_owner = parent;
	}

	/* We record the devnode along with the child, so that we can update
	 * devnode->cdata with the object path before we call any device change
	 * functions. */
	edge = ni_ifworker_children_append(&parent->children, child, devnode);

	return edge;
}

void
ni_ifworker_edge_set_states(ni_ifworker_edge_t *edge, const char *call, unsigned int min_state, unsigned int max_state)
{
	struct ni_ifworker_edge_precondition *pre;
	unsigned int i;

	ni_debug_application("%s(%s, %s, %s, %s)", __func__, edge->child->name, call,
			ni_ifworker_state_name(min_state),
			ni_ifworker_state_name(max_state));
	for (i = 0, pre = edge->call_pre; i < NI_IFWORKER_EDGE_MAX_CALLS; ++i, ++pre) {
		if (pre->call_name == NULL) {
			ni_string_dup(&pre->call_name, call);
			pre->min_child_state = min_state;
			pre->max_child_state = max_state;
			return;
		}

		if (ni_string_eq(pre->call_name, call)) {
			if (min_state < pre->min_child_state)
				pre->min_child_state = min_state;
			if (max_state > pre->max_child_state)
				pre->max_child_state = max_state;
			return;
		}
	}
}

/* Create an event wait object */
static void
ni_ifworker_add_callbacks(ni_iftransition_t *action, ni_objectmodel_callback_info_t *callback_list, const char *ifname)
{
	ni_objectmodel_callback_info_t **pos, *cb;

	if (ni_debug & NI_TRACE_DBUS) {
		ni_trace("%s waiting for callbacks:", ifname);
		for (cb = callback_list; cb; cb = cb->next) {
			ni_trace(" %s event=%s",
				ni_print_hex(cb->uuid.octets, 16),
				cb->event);
		}
	}

	for (pos = &action->callbacks; (cb = *pos) != NULL; pos = &cb->next)
		;
	*pos = callback_list;
}

static ni_objectmodel_callback_info_t *
ni_ifworker_get_callback(ni_ifworker_t *w, const ni_uuid_t *uuid)
{
	ni_objectmodel_callback_info_t **pos, *cb;
	ni_iftransition_t *action;

	if ((action = w->wait_for) == NULL)
		return NULL;
	for (pos = &action->callbacks; (cb = *pos) != NULL; pos = &cb->next) {
		if (ni_uuid_equal(&cb->uuid, uuid)) {
			*pos = cb->next;
			return cb;
		}
	}
	return NULL;
}

static dbus_bool_t
ni_ifworker_waiting_for_event(ni_ifworker_t *w, const char *event_name)
{
	ni_objectmodel_callback_info_t *cb;
	ni_iftransition_t *action;

	if ((action = w->wait_for) == NULL)
		return FALSE;
	for (cb = action->callbacks; cb != NULL; cb = cb->next) {
		if (ni_string_eq(cb->event, event_name))
			return TRUE;
	}
	return FALSE;
}

static void
ni_ifworker_update_state(ni_ifworker_t *w, unsigned int min_state, unsigned int max_state)
{
	unsigned int prev_state = w->state;

	if (w->state < min_state)
		w->state = min_state;
	if (max_state < min_state)
		w->state = max_state;

	if (w->state != prev_state) {
		ni_debug_application("device %s changed state %s -> %s%s",
				w->name,
				ni_ifworker_state_name(prev_state),
				ni_ifworker_state_name(w->state),
				(w->wait_for && w->wait_for->next_state == w->state)?
					", resuming activity" : ", still waiting for event");
		if (w->state == w->target_state)
			ni_ifworker_success(w);
	}

	if (w->wait_for && w->wait_for->next_state == w->state)
		w->wait_for = NULL;
}

static unsigned int
ni_ifworkers_from_xml(xml_document_t *doc)
{
	xml_node_t *root, *ifnode;
	unsigned int count = 0;

	root = xml_document_root(doc);
	for (ifnode = root->children; ifnode; ifnode = ifnode->next) {
		const char *ifname = NULL;
		xml_node_t *node, *depnode;
		ni_ifworker_t *w;

		if (!ifnode->name || strcmp(ifnode->name, "interface")) {
			ni_warn("%s: ignoring non-interface element <%s>",
					xml_node_location(ifnode),
					ifnode->name);
			continue;
		}

		if ((node = xml_node_get_child(ifnode, "name")) != NULL) {
			ifname = node->cdata;
		} else
		if ((node = xml_node_get_child(ifnode, "identify")) != NULL) {
			w = ni_ifworker_identify_device(node);
			if (w != NULL) {
				ni_debug_application("%s: identified interface %s",
						xml_node_location(node),
						w->name);
				w->config = ifnode;
				continue;
			}
		}

		if (ifname == NULL) {
			ni_error("%s: ignoring unknown interface", xml_node_location(ifnode));
			continue;
		}

		if ((w = ni_ifworker_by_ifname(ifname)) != NULL)
			w->config = ifnode;
		else
			w = ni_ifworker_new(ifname, ifnode);

		if ((depnode = xml_node_get_child(ifnode, "dependencies")) != NULL)
			ni_ifworker_set_dependencies_xml(w, depnode);
		count++;
	}

	return count;
}

/*
 * Handle <require> metadata elements that mark netif references.
 * We need to resolve these to a real device (and dbus object path).
 * Optionally, the node may specify a minimum and/or maximum device state
 */
static ni_bool_t
ni_ifworker_req_netif_resolve(ni_ifworker_t *w, ni_ifworker_req_t *req)
{
	ni_ifworker_t *child_worker;
	xml_node_t *devnode;

	if (!(devnode = req->data))
		return FALSE;

	if (!(child_worker = ni_ifworker_resolve_reference(devnode)))
		return FALSE;

	ni_debug_application("%s: resolved reference to subordinate device %s", w->name, child_worker->name);
	if (!ni_ifworker_add_child(w, child_worker, devnode, FALSE))
		return FALSE;

	return TRUE;
}

/*
 * Dependency handling for interface bring-up.
 */
void
ni_ifworker_set_dependencies_xml(ni_ifworker_t *w, xml_node_t *depnode)
{
	ni_warn("%s: dependencies not supported right now", xml_node_location(depnode));
}

static ni_bool_t
ni_ifworker_check_dependencies(ni_ifworker_t *w, ni_iftransition_t *action)
{
	ni_ifworker_req_t *req, *next;

	if (!action->require.list)
		return TRUE;

	ni_debug_application("%s: checking requirements for %s -> %s transition",
			w->name,
			ni_ifworker_state_name(action->from_state),
			ni_ifworker_state_name(action->next_state));

	for (req = action->require.list; req; req = next) {
		next = req->next;
		if (!req->test_fn(w, req))
			return FALSE;
	}

	return TRUE;
}

/*
 * Identify a device based on a set of attributes.
 * The idea here is to get rid of all the constraints we currently have with
 * naming devices - udev kludges, Dell's biosdevname, device enumeration on
 * System z etc.
 */
static ni_ifworker_t *
ni_ifworker_identify_device(const xml_node_t *devnode)
{
	ni_ifworker_t *best = NULL;
	xml_node_t *attr;

	for (attr = devnode->children; attr; attr = attr->next) {
		ni_ifworker_t *found = NULL;

		if (!strcmp(attr->name, "alias")) {
			found = ni_ifworker_by_alias(attr->cdata);
		} else {
			char *object_path;

			object_path = ni_call_identify_device(attr);
			if (object_path)
				found = ni_ifworker_by_object_path(object_path);
			ni_string_free(&object_path);
		}

		if (found != NULL) {
			if (best && best != found) {
				ni_error("%s: ambiguous device reference",
						xml_node_location(devnode));
				return NULL;
			}
			best = found;
		}
	}

	if (best)
		ni_debug_application("%s: identified device as %s (%s)",
				xml_node_location(devnode), best->name, best->object_path);
	return best;
}

/*
 * Get all interfaces matching some user-specified criteria
 */
typedef struct ni_ifmatcher {
	const char *		name;
	const char *		boot_label;
	unsigned int		require_config : 1,
				skip_active    : 1;
} ni_ifmatcher_t;

static unsigned int
ni_ifworker_get_matching(ni_ifmatcher_t *match, ni_ifworker_array_t *result)
{
	unsigned int i;

	if (ni_string_eq(match->name, "all")) {
		/* safeguard: "ifdown all" should mean "all interfaces with a config file */
		match->require_config = 1;
		match->name = NULL;
	}

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (w->config == NULL && match->require_config)
			continue;
		if (w->exclusive_owner)
			continue;

		if (match->name && !ni_string_eq(match->name, w->name))
			continue;

		if (match->boot_label) {
			xml_node_t *boot_node;

			if (w->config == NULL
			 || !(boot_node = xml_node_get_child(w->config, "boot-label"))
			 || !ni_string_eq(match->boot_label, boot_node->cdata))
				continue;
		}

		if (match->skip_active && w->device && ni_netdev_device_is_up(w->device))
			continue;

		ni_ifworker_array_append(result, w);
	}

	return result->count;
}

/*
 * Check for loops in the device tree
 * We do this by counting edges - a graph has cycles iff there is a traversal
 * with more edges than the overall number of edges in the graph.
 */
static ni_bool_t
ni_ifworker_check_loops(const ni_ifworker_t *w, unsigned int *counter)
{
	unsigned int i, nchildren = w->children.count;
	ni_bool_t ret = TRUE;

	/* ni_trace("%s(%s, %u)", __func__, w->name, *counter); */
	if (nchildren > *counter)
		return FALSE;
	*counter -= nchildren;

	for (i = 0; i < w->children.count && ret; ++i) {
		ni_ifworker_t *child = w->children.data[i].child;

		ret = ni_ifworker_check_loops(child, counter);
	}

	return ret;
}

static ni_bool_t
ni_ifworkers_check_loops(ni_ifworker_array_t *array)
{
	unsigned int i, num_edges;

	for (i = num_edges = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		num_edges += w->children.count;
	}

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];
		unsigned int counter = num_edges;

		if (!ni_ifworker_check_loops(w, &counter)) {
			ni_ifworker_fail(w, "detected loop in device hierarchy");
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * Flatten the device graph by sorting the nodes by depth
 */
static void
__ni_ifworker_flatten(ni_ifworker_t *w, ni_ifworker_array_t *array, unsigned int depth)
{
	unsigned int i;

	if (depth > w->depth)
		w->depth = depth;

	for (i = 0; i < w->children.count; ++i) {
		ni_ifworker_t *child = w->children.data[i].child;

		if (ni_ifworker_array_index(array, child) < 0)
			ni_ifworker_array_append(array, child);
		__ni_ifworker_flatten(child, array, depth + 1);
	}
}

static int
__ni_ifworker_depth_compare(const void *a, const void *b)
{
	const ni_ifworker_t *wa = *(const ni_ifworker_t **) a;
	const ni_ifworker_t *wb = *(const ni_ifworker_t **) b;

	return (int) (wa->depth - wb->depth);
}

static void
ni_ifworkers_flatten(ni_ifworker_array_t *array)
{
	unsigned int i, count;

	/* Note, we take the array->count outside the loop.
	 * Inside the loop, we're adding new ifworkers to the array,
	 * and do that recursively. Avoid processing these newly
	 * added devices twice.
	 * NB a simple tail recursion won't work here.
	 */
	count = array->count;
	for (i = 0; i < count; ++i)
		__ni_ifworker_flatten(array->data[i], array, 0);

	qsort(array->data, array->count, sizeof(array->data[0]), __ni_ifworker_depth_compare);
}

static int
ni_ifworker_mark_up(ni_ifworker_t *w, const char *method)
{
	ni_ifworker_edge_t *edge;
	unsigned int i;

	for (i = 0, edge = w->children.data; i < w->children.count; ++i, ++edge) {
		ni_ifworker_t *child = edge->child;
		unsigned int j;

		for (j = 0; j < NI_IFWORKER_EDGE_MAX_CALLS; ++j) {
			if (ni_string_eq(edge->call_pre[j].call_name, method)) {
				unsigned int min_state = edge->call_pre[j].min_child_state;
				unsigned int max_state = edge->call_pre[j].max_child_state;

				ni_debug_application("%s: %s transition requires state of child %s to be in range [%s, %s]",
						w->name, method, child->name,
						ni_ifworker_state_name(min_state),
						ni_ifworker_state_name(max_state));
				if (min_state > child->target_range.min)
					child->target_range.min = min_state;
				if (max_state < child->target_range.max)
					child->target_range.max = max_state;
			}
		}
	}

	return 0;
}

static unsigned int
ni_ifworker_mark_matching(ni_ifmatcher_t *match, unsigned int target_min_state, unsigned int target_max_state)
{
	ni_ifworker_array_t marked = { 0, NULL };
	unsigned int i, j, count = 0;

	if (!ni_ifworker_get_matching(match, &marked))
		return 0;

	ni_ifworkers_check_loops(&marked);

	/* Mark all our primary devices with the requested target state */
	for (i = 0; i < marked.count; ++i) {
		ni_ifworker_t *w = marked.data[i];

		w->target_range.min = target_min_state;
		w->target_range.max = target_max_state;
	}

	/* Collect all workers in the device graph, and sort them by increasing
	 * depth. */
	ni_ifworkers_flatten(&marked);

	for (i = 0; i < marked.count; ++i) {
		ni_ifworker_t *w = marked.data[i];
		unsigned int min_state = w->target_range.min;
		unsigned int max_state = w->target_range.max;

#if 0
		ni_trace("%s checking, min=%s, max=%s%s", w->name,
					ni_ifworker_state_name(min_state),
					ni_ifworker_state_name(max_state),
					w->failed? " - failed" : "");
#endif
		if (w->failed)
			continue;

		if (min_state > max_state) {
			ni_error("%s: conflicting target states: min=%s max=%s",
					w->name,
					ni_ifworker_state_name(min_state),
					ni_ifworker_state_name(max_state));
			return -1;
		}

		if (max_state == __STATE_MAX) {
			if (min_state == STATE_NONE)
				continue;

			/* No upper bound; bring it up to min level */
			ni_ifworker_fsm_init(w, STATE_DEVICE_DOWN, min_state);
		} else if (min_state == STATE_NONE) {
			/* No lower bound; bring it down to max level */
			ni_ifworker_fsm_init(w, STATE_ADDRCONF_UP, max_state);
		} else {
			ni_warn("%s: not handled yet: bringing device into state range [%s, %s]",
					w->name,
					ni_ifworker_state_name(min_state),
					ni_ifworker_state_name(max_state));
		}

		ni_debug_application("%s: current state=%s target state=%s",
					w->name,
					ni_ifworker_state_name(w->state),
					ni_ifworker_state_name(w->target_state));

		if (w->target_state != STATE_NONE) {
			ni_ifworker_set_timeout(w, ni_ifworker_timeout);
			count++;
		}

		for (j = 0; j < w->actions[j].next_state; ++j) {
			const char *method = w->actions[j].common.method_name;

			if (method)
				ni_ifworker_mark_up(w, method);
		}
	}

	ni_debug_application("marked %u interfaces", count);
	return count;
}

/*
 * Bind a device API for an interface that doesn't exist yet.
 * We do this by looking at all factory services and finding one for
 * which our interface document provides a configuration.
 *
 * By convention, factory services have a newDevice method, which
 * takes a string (the requested device name, if any), and a configuration
 * dict. The xml schema specifies which element if an <interface>
 * description should be used for this argument.
 *
 * For instance, the newDevice method of the VLAN.Factory service
 * specifies that its configuration be taken from the <vlan> element.
 */
static int
ni_ifworker_bind_device_factory_api(ni_ifworker_t *w)
{
	const ni_dbus_method_t *method;
	const ni_dbus_class_t *netif_list_class;
	const ni_dbus_service_t *list_services[128];
	unsigned int i, count;
	int rv;

	if (w->config == NULL || w->device_api.factory_service)
		return 0;

	netif_list_class = ni_objectmodel_get_class(NI_OBJECTMODEL_NETIF_LIST_CLASS);
	count = ni_objectmodel_compatible_services_for_class(netif_list_class, list_services, 128);
	for (i = 0; i < count; ++i) {
		const ni_dbus_service_t *service = list_services[i];
		xml_node_t *config = NULL;

		method = ni_dbus_service_get_method(service, "newDevice");
		if (method == NULL)
			continue;

		rv = ni_dbus_xml_map_method_argument(method, 1, w->config, &config, NULL);
		if ((rv = ni_dbus_xml_map_method_argument(method, 1, w->config, &config, NULL)) < 0) {
			ni_ifworker_fail(w, "cannot create interface: xml document error");
			return -1;
		}

		if (config != NULL) {
			if (w->device_api.factory_service != NULL) {
				ni_ifworker_fail(w, "ambiguous device configuration - found services %s and %s",
						service->name, w->device_api.factory_service->name);
				return -1;
			}
			w->device_api.factory_service = service;
			w->device_api.factory_method = method;
			w->device_api.config = config;
		}
	}

	return 0;
}

/*
 * Given an XML interface description, find the device layer information.
 * By convention, a DBus device service must provide a changeDevice function.
 * The metadata of this function specifies which element of an <interface>
 * declaration it pertains to.
 */
static int
ni_ifworker_bind_device_apis(ni_ifworker_t *w)
{
	const ni_dbus_service_t *service;
	const ni_dbus_method_t *method;
	xml_node_t *config;

	if (w->device_api.config)
		return 1;

	if (w->config == NULL)
		return 0;

	if (w->object == NULL)
		return 0;

	service = ni_dbus_object_get_service_for_method(w->object, "changeDevice");
	if (service == NULL)
		return 0;

	method = ni_dbus_service_get_method(service, "changeDevice");
	ni_assert(method);

	if (ni_dbus_xml_map_method_argument(method, 0, w->config, &config, NULL) < 0)
		return -NI_ERROR_DOCUMENT_ERROR;

	w->device_api.service = service;
	w->device_api.method = method;
	w->device_api.config = config;
	return 1;
}

/*
 * Build the hierarchy of devices.
 *
 * We need to ensure that we bring up devices in the proper order; e.g. an
 * eth interface needs to come up before any of the VLANs that reference
 * it.
 */
static void		__ni_ifworker_print_tree(const char *arrow, const ni_ifworker_t *, const char *);
static dbus_bool_t	ni_ifworker_netif_resolve_cb(xml_node_t *, const ni_xs_type_t *, const xml_node_t *, void *);
static int		ni_ifworker_prompt_later_cb(xml_node_t *, const ni_xs_type_t *, const xml_node_t *, void *);

static int
ni_ifworkers_build_hierarchy(void)
{
	unsigned int i;

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];
		int rv;

		/* A worker without an ifnode is one that we discovered in the
		 * system, but which we've not been asked to configure. */
		if (!w->config)
			continue;

		/* First, check for factory interface */
		if ((rv = ni_ifworker_bind_device_factory_api(w)) < 0)
			return rv;
		if (w->device_api.config != NULL) {
			ni_dbus_xml_validate_context_t context = {
				.metadata_callback = ni_ifworker_netif_resolve_cb,
				.prompt_callback = ni_ifworker_prompt_later_cb,
				.user_data = w,
			};

			/* The XML validation code will do a pass over the part of our XML
			 * document that's used for the deviceNew() call, and call us for
			 * every bit of metadata it finds.
			 * This includes elements marked by <meta:netif-reference/>
			 * in the schema.
			 */
			if (!ni_dbus_xml_validate_argument(w->device_api.factory_method, 1, w->device_api.config, &context))
				return -NI_ERROR_DOCUMENT_ERROR;
			continue;
		}

		if ((rv = ni_ifworker_bind_device_apis(w)) < 0)
			return rv;
		if (w->device_api.config != NULL) {
			ni_dbus_xml_validate_context_t context = {
				.metadata_callback = ni_ifworker_netif_resolve_cb,
				.prompt_callback = ni_ifworker_prompt_later_cb,
				.user_data = w,
			};

			if (!ni_dbus_xml_validate_argument(w->device_api.method, 0, w->device_api.config, &context))
				return -NI_ERROR_DOCUMENT_ERROR;
			continue;
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

dbus_bool_t
ni_ifworker_netif_resolve_cb(xml_node_t *node, const ni_xs_type_t *type, const xml_node_t *metadata, void *user_data)
{
	ni_ifworker_t *w = user_data;
	ni_ifworker_t *child_worker = NULL;
	ni_ifworker_edge_t *edge = NULL;
	xml_node_t *mchild;

	for (mchild = metadata->children; mchild; mchild = mchild->next) {
		const char *attr;

		if (ni_string_eq(mchild->name, "netif-reference")) {
			ni_bool_t shared = FALSE;

			if (!(child_worker = ni_ifworker_resolve_reference(node)))
				return FALSE;

			if ((attr = xml_node_get_attr(mchild, "shared")) != NULL)
				shared = ni_string_eq(attr, "true");

			ni_debug_application("%s: resolved reference to subordinate device %s", w->name, child_worker->name);
			if (!(edge = ni_ifworker_add_child(w, child_worker, node, shared)))
				return FALSE;
		} else
		if (ni_string_eq(mchild->name, "require")) {
			int min_state = STATE_NONE, max_state = __STATE_MAX;

			if ((attr = xml_node_get_attr(mchild, "check")) == NULL
			 || !ni_string_eq(attr, "netif-child-state"))
				continue;

			if ((attr = xml_node_get_attr(mchild, "min-state")) != NULL) {
				min_state = ni_ifworker_state_from_name(attr);
				if (min_state < 0) {
					ni_error("%s: invalid state name min-state=\"%s\"",
							xml_node_location(mchild), attr);
					return FALSE;
				}
			}

			if ((attr = xml_node_get_attr(mchild, "max-state")) != NULL) {
				max_state = ni_ifworker_state_from_name(attr);
				if (max_state < 0) {
					ni_error("%s: invalid state name max-state=\"%s\"",
							xml_node_location(mchild), attr);
					return FALSE;
				}
			}

			if ((attr = xml_node_get_attr(mchild, "op")) == NULL) {
				ni_error("%s: missing op attribute", xml_node_location(mchild));
				return FALSE;
			}

			if (edge == NULL) {
				ni_error("%s: <meta:require check=netif-child-state> without netif-reference",
						xml_node_location(mchild));
				return FALSE;
			}

			ni_ifworker_edge_set_states(edge, attr, min_state, max_state);
		}
	}

	return TRUE;
}

int
ni_ifworker_prompt_later_cb(xml_node_t *node, const ni_xs_type_t *xs_type, const xml_node_t *metadata, void *user_data)
{
	return -NI_ERROR_RETRY_OPERATION;
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
			ni_ifworker_t *child = w->children.data[i].child;

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
		ni_netdev_t *dev;

		w = interface_workers.data[i];

		/* Always clear the object - we don't know if it's still there
		 * after we've called ni_dbus_object_refresh_children() */
		w->object = NULL;

		/* Don't touch devices we're done with */
		if (w->done)
			continue;

		if ((dev = w->device) != NULL) {
			w->device = NULL;
			ni_netdev_put(dev);
		}
	}

	for (object = iflist->children; object; object = object->next) {
		ni_netdev_t *dev = ni_objectmodel_unwrap_interface(object, NULL);
		ni_ifworker_t *found = NULL;

		if (dev == NULL || dev->name == NULL)
			continue;

		found = ni_ifworker_by_netdev(dev);
		if (!found)
			found = ni_ifworker_by_object_path(object->path);
		if (!found) {
			ni_debug_application("received new device %s (%s)", dev->name, object->path);
			found = ni_ifworker_new(dev->name, NULL);
		}

		/* Don't touch devices we're done with */
		if (found->done)
			continue;

		if (!found->object_path)
			ni_string_dup(&found->object_path, object->path);
		if (!found->device)
			found->device = ni_netdev_get(dev);
		found->ifindex = dev->link.ifindex;
		found->object = object;

		if (ni_netdev_link_is_up(dev))
			ni_ifworker_update_state(found, STATE_LINK_UP, __STATE_MAX);
		else
			ni_ifworker_update_state(found, 0, STATE_DEVICE_UP);
	}

	for (i = 0; i < interface_workers.count; ++i) {
		w = interface_workers.data[i];

		if (w->object == NULL)
			ni_ifworker_update_state(w, STATE_NONE, STATE_DEVICE_DOWN);
	}
}

static inline int
ni_ifworker_ready(const ni_ifworker_t *w)
{
	return w->done || w->target_state == STATE_NONE || w->target_state == w->state;
}

/*
 * The parent would like to move to the next state. See if all children are
 * ready.
 */
static ni_bool_t
ni_ifworker_children_ready_for(ni_ifworker_t *w, const ni_iftransition_t *action)
{
	unsigned int i, j;

	if (!action->common.method_name)
		return TRUE;

	for (i = 0; i < w->children.count; ++i) {
		ni_ifworker_edge_t *edge = &w->children.data[i];
		ni_ifworker_t *child = edge->child;

		for (j = 0; j < NI_IFWORKER_EDGE_MAX_CALLS; ++j) {
			struct ni_ifworker_edge_precondition *pre = &edge->call_pre[j];
			unsigned int wait_for_state;

			if (!ni_string_eq(pre->call_name, action->common.method_name))
				continue;

			if (child->state < pre->min_child_state) {
				wait_for_state = pre->min_child_state;
			} else
			if (child->state > pre->max_child_state) {
				wait_for_state = pre->max_child_state;
			} else {
				/* Okay, child interface is ready */
				continue;
			}

			if (child->failed) {
				/* Child is not in the expected state, but as it failed, it'll
				 * never get there. Fail the parent as well. */
				ni_ifworker_fail(w, "subordinate network interface %s failed", child->name);
				return FALSE;
			}

			ni_debug_application("%s: waiting for %s to reach state %s",
						w->name, child->name,
						ni_ifworker_state_name(wait_for_state));
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * This error handler can be used by link management functions to request
 * input from the user, such as wireless passphrases, or user/password for
 * a VPN tunnel.
 */
static int
ni_ifworker_error_handler(ni_call_error_context_t *ctx, const DBusError *error)
{
	char *detail = NULL;
	int errcode;

	ni_debug_dbus("%s(%s, %s)", __func__, error->name, error->message);
	errcode = ni_dbus_get_error(error, &detail);
	if (errcode == -NI_ERROR_AUTH_INFO_MISSING) {
		xml_node_t *authnode;
		char *node_spec, *prompt_type = NULL, *ident = NULL;
		const char *value = NULL;
		char buffer[256];
		int nretries;

		nretries = ni_call_error_context_get_retries(ctx, error);
		if (nretries < 0 || nretries > 2)
			goto out;

		/* The error detail is supposed to be formatted as
		 * "xml-node-spec|prompt-type|ident"
		 * where xml-node-spec specifies an xml node below the
		 * config node, prompt-type should be either PASSWORD
		 * or USER, and ident is an optional identifier of what
		 * is being asked for.
		 */
		if (!(node_spec = strtok(detail, "|")))
			goto out;
		if ((prompt_type = strtok(NULL, "|")) != NULL)
			ident = strtok(NULL, "|");

		if (prompt_type && !strcmp(prompt_type, "PASSWORD")) {
			char *prompt;

			prompt = "Please enter password: ";
			if (ident) {
				snprintf(buffer, sizeof(buffer), "Please enter password for %s: ", ident);
				prompt = buffer;
			}

			value = getpass(prompt);
		} else {
			if (ident)
				printf("Please enter user name for %s: ", ident);
			else
				printf("Please enter user name: ");
			fflush(stdout);

			value = fgets(buffer, sizeof(buffer), stdin);
			/* EOF? User pressed Ctrl-D */
			if (value == NULL)
				printf("\n");
		}

		if (value) {
			authnode = ni_call_error_context_get_node(ctx, node_spec);
			xml_node_set_cdata(authnode, value);
			errcode = -NI_ERROR_RETRY_OPERATION;
		}
	}

out:
	ni_string_free(&detail);
	return errcode;
}

/*
 * Process a <meta:require> element
 */
static int
ni_ifworker_require_xml(ni_iftransition_t *action, const xml_node_t *req_node, xml_node_t *element, xml_node_t *config)
{
	const char *attr, *check;
	ni_ifworker_req_t *require, **pos;
	int rv;

	pos = &action->require.list;
	if (element == NULL && config == NULL) {
		ni_error("%s: caller did not provide xml base nodes", __func__);
		return -1;
	}

	if ((check = xml_node_get_attr(req_node, "check")) == NULL) {
		ni_error("%s: missing check attribute", xml_node_location(req_node));
		return -NI_ERROR_DOCUMENT_ERROR;
	}

	if (element != NULL) {
		if (!ni_ifworker_req_new(check, element, pos)) {
			ni_error("%s: cannot build requirement", xml_node_location(req_node));
			return -NI_ERROR_DOCUMENT_ERROR;
		}
	} else {
		xml_node_t *expanded[64];
		unsigned int j, num_expanded;

		if ((attr = xml_node_get_attr(req_node, "document-node")) == NULL) {
			ni_error("%s: missing document-node attribute", xml_node_location(req_node));
			return -NI_ERROR_DOCUMENT_ERROR;
		}

		rv = ni_dbus_xml_expand_element_reference(config, attr, expanded, 64);
		if (rv < 0)
			return rv;

		num_expanded = rv;
		for (j = 0; j < num_expanded; ++j) {
			require = ni_ifworker_req_new(check, expanded[j], pos);
			if (require == NULL) {
				ni_error("%s: cannot build requirement", xml_node_location(req_node));
				return -NI_ERROR_DOCUMENT_ERROR;
			}

			pos = &require->next;
		}
	}

	return 0;
}

/*
 * XML validation callback
 * This is invoked when we're validating the schema. It can be used for doing all sorts
 * funny things, but right now, we use it only for expressing dependencies.
 */
dbus_bool_t
ni_ifworker_xml_metadata_callback(xml_node_t *node, const ni_xs_type_t *type, const xml_node_t *metadata, void *user_data)
{
	ni_iftransition_t *action = user_data;

	if (ni_string_eq(metadata->name, "require")) {
		if (ni_ifworker_require_xml(action, metadata, node, NULL) < 0)
			return FALSE;
	} else {
		/* Ignore unknown meta node */
	}

	return TRUE;
}

/*
 * User input callback. A mandatory element is missing from the document, but the schema
 * provides prompting information for it.
 *
 * In order to prompt for e.g. a password, your schema should look like this:
 *
 *	  <auth class="dict">
 *	    <user type="string" constraint="required">
 *	      <meta:user-input type="user" prompt="Please enter openvpn user name"/>
 *	    </user>
 *	    <password type="string" constraint="required">
 *	      <meta:user-input type="password" prompt="Please enter openvpn password"/>
 *	    </password>
 *	  </auth>
 *
 * If your interface document contains an empty <auth> element, wicked will prompt for
 * user and password. If the <auth> element exists and contains a <user> element, you
 * will not be prompted for the use name. Same for the <password> element.
 * If the document doesn't contain an <auth> element at all, no prompting will happen.
 * (If authentication is not optional, you should also mark the <auth> node as a
 * required element).
 */
int
ni_ifworker_prompt_cb(xml_node_t *node, const ni_xs_type_t *xs_type, const xml_node_t *metadata, void *user_data)
{
	const char *prompt, *type, *value;
	char buffer[256];

	prompt = xml_node_get_attr(metadata, "prompt");
	if ((type = xml_node_get_attr(metadata, "type")) == NULL) {
		ni_error("%s: missing type attribute in %s element", xml_node_location(metadata), metadata->name);
		return -1;
	}

	if (!strcasecmp(type, "password")) {
		if (prompt == NULL)
			prompt = "Please enter password";

		snprintf(buffer, sizeof(buffer), "%s: ", prompt);
		value = getpass(prompt);
	} else {
		if (prompt == NULL)
			prompt = "Please enter user name";

		printf("%s: ", prompt);
		fflush(stdout);

		value = fgets(buffer, sizeof(buffer), stdin);
		/* EOF? User pressed Ctrl-D */
		if (value == NULL)
			printf("\n");
	}

	if (value == NULL)
		return -1;
	xml_node_set_cdata(node, value);
	return 0;
}

/*
 * Parse any <require> tags contained in the per-method metadata
 */
static int
ni_ifworker_map_method_requires(ni_ifworker_t *w, ni_iftransition_t *action,
		const ni_dbus_service_t *service, const ni_dbus_method_t *method)
{
	xml_node_t *req_nodes[32];
	unsigned int i, count;

	action->require.parsed = TRUE;

	count = ni_dbus_xml_get_method_metadata(method, "require", req_nodes, 32);
	if (count == 0)
		return 0;

	for (i = 0; i < count; ++i) {
		int rv;

		if ((rv = ni_ifworker_require_xml(action, req_nodes[i], NULL, w->config)) < 0)
			return rv;
	}

	return 0;
}

/*
 * Debugging: print the binding info
 */
static void
ni_ifworker_print_binding(ni_ifworker_t *w, ni_iftransition_t *action)
{
	struct ni_netif_action_binding *bind;
	unsigned int i;

	for (i = 0, bind = action->binding; i < action->num_bindings; ++i, ++bind) {
		if (bind->method == NULL) {
			ni_trace("  %-40s %-12s   not supported by service",
					bind->service->name,
					action->common.method_name);
		} else
		if (bind->config == NULL) {
			ni_trace("  %-40s %-12s   no config in interface document%s",
					bind->service->name,
					bind->method->name,
					bind->skip_call? "; skipping call" : "");
		} else {
			ni_trace("  %-40s %-12s   mapped to <%s> @%s",
					bind->service->name,
					bind->method->name,
					bind->config->name,
					xml_node_location(bind->config));
		}
	}
}

/*
 * Most steps of the finite state machine follow the same pattern.
 *
 * First part: bind the service, method and argument that should be passed.
 */
int
ni_ifworker_do_common_bind(ni_ifworker_t *w, ni_iftransition_t *action)
{
	const ni_dbus_service_t *service;
	unsigned int i;
	int rv;

	/* If we haven't created the netdev yet, skip this binding
	 * quietly. We will retry later (or fail). */
	if (w->object == NULL)
		return 0;

	if (action->bound)
		return 0;
	action->bound = TRUE;

	service = action->common.service;
	if (service != NULL) {
		action->binding[0].service = service;
		action->num_bindings++;
	} else {
		if (action->common.service_name != NULL) {
			/* This transition explicitly specifies a dbus service.
			 * Fail if it is not supported. */
			service = ni_dbus_object_get_service(w->object, action->common.service_name);
			if (service == NULL) {
				ni_ifworker_fail(w, "object does not support interface %s",
						action->common.service_name);
				return -NI_ERROR_METHOD_NOT_SUPPORTED;
			}
			action->binding[0].service = service;
			action->num_bindings++;
		} else if (action->common.call_overloading) {
			/* Implicit: look up the service(s) based on the method name.
			 * We may have multiple services providing a given method,
			 * but we should pick the most specific one. */
			service = ni_dbus_object_get_service_for_method(w->object, action->common.method_name);
			if (service == NULL)
				return 0;

			action->binding[0].service = service;
			action->num_bindings++;
		} else {
			/* Implicit: look up the service(s) based on the method name.
			 * We may be dealing with several services, and we want to call all of them.
			 * This happens when it comes to addrconf services, for instance,
			 * but also for link authentication and firewalling.
			 */
			const ni_dbus_service_t *services[NI_NETIF_ACTION_BINDINGS_MAX];
			unsigned int count;

			count = ni_dbus_object_get_all_services_for_method(w->object,
						action->common.method_name,
						services, NI_NETIF_ACTION_BINDINGS_MAX);

			/* If there is no interface supporting this method, we trivially succeed. */
			if (count == 0)
				return 0;

			for (i = 0; i < count; ++i)
				action->binding[i].service = services[i];
			action->num_bindings = count;
		}
	}

	/* Now bind method and config. */
	for (i = 0; i < action->num_bindings; ++i) {
		struct ni_netif_action_binding *bind = &action->binding[i];

		bind->method = ni_dbus_service_get_method(bind->service, action->common.method_name);

		/* If the interface doesn't support this method, we trivially succeed. */
		if (bind->method == NULL)
			continue;

		/* Bind <require> tags attached to the method (in the schema) */
		rv = ni_ifworker_map_method_requires(w, action, bind->service, bind->method);
		if (rv < 0)
			return rv;

		/* Consult the method's metadata information to see how to
		 * locate the configuration node. Any argument to a method may have
		 * a <mapping> metadata element:
		 *
		 * <method ...>
		 *   <arguments>
		 *     <foobar type="...">
		 *       <meta:mapping
		 *	   	document-node="/some/xpath/expression" 
		 *		skip-unless-present="true"
		 *		/>
		 *     </foobar>
		 *   </arguments>
		 * </method>
		 *
		 * The document node is an xpath relative to the enclosing
		 * <interface> element. If the document does not contain the
		 * referenced node, and skip-unless-present is true, then we
		 * do not perform this call.
		 */
		if (ni_dbus_xml_map_method_argument(bind->method, 0, w->config, &bind->config, &bind->skip_call) < 0)
			goto document_error;

		/* Validate the document. This will record possible requirements, and will
		 * try to prompt for missing information.
		 */
		if (bind->config != NULL) {
			ni_dbus_xml_validate_context_t context = {
				.metadata_callback = ni_ifworker_xml_metadata_callback,
				.prompt_callback = ni_ifworker_prompt_cb,
				.user_data = action,
			};

			if (!ni_dbus_xml_validate_argument(bind->method, 0, bind->config, &context))
				goto document_error;
		}
	}

	return 0;

document_error:
	ni_ifworker_fail(w, "interface document error");
	return -1;
}

static int
ni_ifworker_do_common(ni_ifworker_t *w, ni_iftransition_t *action)
{
	unsigned int i;
	int rv;

	for (i = 0; i < action->num_bindings; ++i) {
		struct ni_netif_action_binding *bind = &action->binding[i];
		ni_objectmodel_callback_info_t *callback_list = NULL;

		if (bind->method == NULL || bind->skip_call)
			continue;

		rv = ni_call_common_xml(w->object, bind->service, bind->method, bind->config,
				&callback_list, ni_ifworker_error_handler);
		if (rv < 0) {
			ni_ifworker_fail(w, "call to %s.%s() failed: %s", bind->service->name, bind->method->name, ni_strerror(rv));
			return rv;
		}

		if (callback_list) {
			ni_ifworker_add_callbacks(action, callback_list, w->name);
			w->wait_for = action;
		}
	}

	if (w->wait_for != NULL)
		return 0;

	w->state = action->next_state;
	return 0;
}

/*
 * Finite state machine - create the device if it does not exist
 * Typically, this will create just the bare interface, like a bridge
 * or bond device, without actually configuring it (such as adding
 * bridge ports).
 */
static int
ni_ifworker_bind_device_factory(ni_ifworker_t *w, ni_iftransition_t *action)
{
	struct ni_netif_action_binding *bind;
	int rv;

	if (action->bound)
		return 0;
	action->bound = TRUE;

	if ((rv = ni_ifworker_bind_device_factory_api(w)) < 0)
		return rv;

	/* We error out later. */
	if (w->device_api.factory_service == NULL)
		return 0;

	bind = &action->binding[0];
	bind->service = w->device_api.factory_service;
	bind->method = w->device_api.factory_method;
	bind->config = w->device_api.config;
	action->num_bindings++;

	rv = ni_ifworker_map_method_requires(w, action, bind->service, bind->method);
	if (rv < 0)
		return rv;

	return 0;
}

static int
ni_ifworker_call_device_factory(ni_ifworker_t *w, ni_iftransition_t *action)
{
	if (w->device == NULL) {
		struct ni_netif_action_binding *bind;
		const char *relative_path;
		char *object_path;

		if (action->num_bindings == 0) {
			ni_ifworker_fail(w, "device does not exist");
			return -1;
		}
		bind = &action->binding[0];

		ni_debug_application("%s: calling device factory", w->name);
		object_path = ni_call_device_new_xml(bind->service, w->name, bind->config);
		if (object_path == NULL) {
			ni_ifworker_fail(w, "failed to create interface");
			return -1;
		}

		ni_debug_application("created device %s (path=%s)", w->name, object_path);
		ni_string_dup(&w->object_path, object_path);

		relative_path = ni_string_strip_prefix(NI_OBJECTMODEL_OBJECT_PATH "/", object_path);
		if (relative_path == NULL) {
			ni_ifworker_fail(w, "invalid device path %s", object_path);
			ni_string_free(&object_path);
			return -1;
		}

		/* Lookup the object corresponding to this path. If it doesn't
		 * exist, create it on the fly (with a generic class of "netif" -
		 * the next refresh call with take care of this and correct the
		 * class */
		w->object = ni_dbus_object_create(__root_object, relative_path,
					NULL,
					NULL);

		ni_string_free(&object_path);

		if (!ni_dbus_object_refresh_children(w->object)) {
			ni_ifworker_fail(w, "unable to refresh new device");
			return -1;
		}

		ni_ifworker_fsm_bind_methods(w);
	}

	w->state = action->next_state;
	return 0;
}

static int
ni_ifworker_can_delete(const ni_ifworker_t *w)
{
	return !!ni_dbus_object_get_service_for_method(w->object, "deleteDevice");
}

/*
 * Finite state machine
 */
#define __TRANSITION_UP_TO(__state)		.from_state = __state - 1, .next_state = __state
#define __TRANSITION_DOWN_FROM(__state)		.from_state = __state, .next_state = __state - 1
#define TRANSITION_UP_TO(__state, __bind_func, __func) { \
	__TRANSITION_UP_TO(__state), \
	.bind_func = __bind_func, \
	.func = __func \
}
#define TRANSITION_DOWN_FROM(__state, __bind_func, __func) { \
	__TRANSITION_DOWN_FROM(__state), \
	.bind_func = __bind_func, \
	.func = __func \
}

#define COMMON_TRANSITION_UP_TO(__state, __meth, __more...) { \
	__TRANSITION_UP_TO(__state), \
	.bind_func = ni_ifworker_do_common_bind, \
	.func = ni_ifworker_do_common, \
	.common = { .method_name = __meth, ##__more } \
}

#define COMMON_TRANSITION_DOWN_FROM(__state, __meth, __more...) { \
	__TRANSITION_DOWN_FROM(__state), \
	.bind_func = ni_ifworker_do_common_bind, \
	.func = ni_ifworker_do_common, \
	.common = { .method_name = __meth, ##__more } \
}

static ni_iftransition_t	ni_iftransitions[] = {
	/* -------------------------------------- *
	 * Transitions for bringing up a device
	 * -------------------------------------- */

	/* Create the device (if it's virtual). This is the only transition
	 * that takes a different approach, because it has to use a factory
	 * service, rather than the device services. */
	{
		__TRANSITION_UP_TO(STATE_DEVICE_EXISTS),
		.bind_func = ni_ifworker_bind_device_factory,
		.func = ni_ifworker_call_device_factory,
		.common = { .method_name = "newDevice" },
	},

	/* This sets any device attributes, such as a MAC address */
	COMMON_TRANSITION_UP_TO(STATE_DEVICE_UP, "changeDevice", .call_overloading = TRUE),

	/* This step adds device-specific filtering, if available. Typical
	 * example would be bridge filtering with ebtables. */
	COMMON_TRANSITION_UP_TO(STATE_FIREWALL_UP, "firewallUp"),

	/* This brings up the link layer, and sets general device attributes such
	 * as the MTU, the transfer queue length etc. */
	COMMON_TRANSITION_UP_TO(STATE_LINK_UP, "linkUp", .call_overloading = TRUE),

	/* If the link requires authentication, this information can be provided
	 * here; for instance ethernet 802.1x, wireless WPA, or PPP chap/pap.
	 * NOTE: This may not be the right place; we may have to fold this into
	 * the link_up step, or even do it prior to that. */
	COMMON_TRANSITION_UP_TO(STATE_LINK_AUTHENTICATED, "login", .call_overloading = TRUE),

	/* Configure all assigned addresses and bring up the network */
	COMMON_TRANSITION_UP_TO(STATE_ADDRCONF_UP, "requestLease"),

	/* -------------------------------------- *
	 * Transitions for bringing down a device
	 * -------------------------------------- */
	/* Remove all assigned addresses and bring down the network */
	COMMON_TRANSITION_DOWN_FROM(STATE_ADDRCONF_UP, "dropLease"),

	/* Shut down the link */
	COMMON_TRANSITION_DOWN_FROM(STATE_LINK_UP, "linkDown", .call_overloading = TRUE),

	/* Shut down the firewall */
	COMMON_TRANSITION_DOWN_FROM(STATE_FIREWALL_UP, "firewallDown"),

	/* Delete the device */
	COMMON_TRANSITION_DOWN_FROM(STATE_DEVICE_UP, "deleteDevice", .call_overloading = TRUE),

	{ .from_state = STATE_NONE, .next_state = STATE_NONE, .func = NULL }
};

static void
ni_ifworker_fsm_init(ni_ifworker_t *w, unsigned int from_state, unsigned int target_state)
{
	unsigned int index, num_actions;
	unsigned int cur_state;
	int increment;

	if (w->actions != NULL)
		return;

	/* If the --delete option was given, but the specific device cannot
	 * be deleted, then we don't try. */
	if (target_state == STATE_DEVICE_DOWN && !ni_ifworker_can_delete(w)) {
		ni_debug_application("%s: cannot delete device, ignoring --delete option", w->name);
		target_state = STATE_DEVICE_UP;
	}

	if (from_state <= target_state)
		increment = 1;
	else
		increment = -1;

	ni_debug_application("%s: set up FSM from %s -> %s", w->name,
			ni_ifworker_state_name(from_state),
			ni_ifworker_state_name(target_state));
	num_actions = 0;

do_it_again:
	index = 0;
	for (cur_state = from_state; cur_state != target_state; ) {
		unsigned int next_state = cur_state + increment;
		const ni_iftransition_t *a;

		for (a = ni_iftransitions; a->func; ++a) {
			if (a->from_state == cur_state && a->next_state == next_state) {
				if (w->actions != NULL) {

					ni_debug_application("  %s -> %s: %s()",
						ni_ifworker_state_name(cur_state),
						ni_ifworker_state_name(next_state),
						a->common.method_name);
					w->actions[index++] = *a;
					break;
				}
				num_actions++;
			}
		}

		cur_state = next_state;
	}

	if (w->actions == NULL) {
		w->actions = calloc(num_actions + 1, sizeof(ni_iftransition_t));
		goto do_it_again;
	}
	w->state = from_state;
	w->target_state = target_state;

	ni_ifworker_fsm_bind_methods(w);

	/* FIXME: Add <require> targets from the interface document */
}

/*
 * After we have mapped out the transitions the ifworker needs to go through, we
 * need to bind each of them to a dbus call.
 * We try to do this in one go as early as possible, so that we can flag errors
 * in the document early on.
 */
static int
ni_ifworker_fsm_bind_methods(ni_ifworker_t *w)
{
	ni_iftransition_t *action;
	unsigned int unbound = 0;
	int rv;

	ni_debug_application("%s: binding dbus calls to FSM transitions", w->name);
	for (action = w->actions; action->func; ++action) {
		if (action->bound)
			continue;
		rv = action->bind_func(w, action);
		if (rv < 0) {
			ni_ifworker_fail(w, "unable to bind %s() call", action->common.method_name);
			return rv;
		}

		if (!action->bound)
			unbound++;
		else if (ni_debug & NI_TRACE_APPLICATION)
			ni_ifworker_print_binding(w, action);
	}

	if (unbound)
		ni_debug_application("  %u transitions not bound yet", unbound);

	return 0;
}

static unsigned int
ni_ifworker_fsm(void)
{
	unsigned int i, waiting;

	while (1) {
		int made_progress = 0;

		for (i = 0; i < interface_workers.count; ++i) {
			ni_ifworker_t *w = interface_workers.data[i];
			ni_iftransition_t *action;
			int rv, prev_state;

			if (w->target_state != STATE_NONE)
				ni_debug_application("%s: state=%s want=%s%s%s", w->name,
					ni_ifworker_state_name(w->state),
					ni_ifworker_state_name(w->target_state),
					w->wait_for? ", wait-for=" : "",
					w->wait_for?  ni_ifworker_state_name(w->wait_for->next_state) : "");

			if (w->failed || ni_ifworker_ready(w))
				continue;

			/* If we're still waiting for children to become ready,
			 * there's nothing we can do but wait. */
			if (!ni_ifworker_children_ready_for(w, w->actions)) {
				if (w->failed)
					made_progress = 1;
				continue;
			}

			/* We requested a change that takes time (such as acquiring
			 * a DHCP lease). Wait for a notification from wickedd */
			if (w->wait_for)
				continue;

			action = w->actions;
			if (action->next_state == STATE_NONE)
				w->state = w->target_state;

			if (w->state == w->target_state) {
				ni_ifworker_success(w);
				made_progress = 1;
				continue;
			}

			if (!action->bound) {
				ni_ifworker_fail(w, "failed to bind services and methods for %s()",
						action->common.method_name);
				continue;
			}

			if (!ni_ifworker_check_dependencies(w, action)) {
				ni_debug_application("%s: defer action (pending dependencies)", w->name);
				continue;
			}

			prev_state = w->state;
			rv = action->func(w, action);
			w->actions++;

			if (rv >= 0) {
				made_progress = 1;
				if (w->state == action->next_state) {
					/* We should not have transitioned to the next state while
					 * we were still waiting for some event. */
					ni_assert(w->wait_for == NULL);
					ni_debug_application("%s: successfully transitioned from %s to %s",
						w->name,
						ni_ifworker_state_name(prev_state),
						ni_ifworker_state_name(w->state));
				} else {
					ni_debug_application("%s: waiting for event in state %s",
						w->name,
						ni_ifworker_state_name(w->state));
					w->wait_for = action;
				}
			} else
			if (!w->failed) {
				/* The fsm action should really have marked this
				 * as a failure. shame on the lazy programmer. */
				ni_ifworker_fail(w, "%s: failed to transition from %s to %s",
						w->name,
						ni_ifworker_state_name(prev_state),
						ni_ifworker_state_name(action->next_state));
			}
		}

		if (!made_progress)
			break;

		ni_debug_application("-- refreshing interface state --");
		ni_ifworkers_refresh_state();
	}

	for (i = waiting = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (!w->failed && !ni_ifworker_ready(w))
			waiting++;
	}

	ni_debug_application("waiting for %u devices to become ready", waiting);
	return waiting;
}

static void
interface_state_change_signal(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_uuid_t event_uuid = NI_UUID_INIT;
	ni_ifworker_t *w;

	ni_debug_dbus("%s: got signal %s from %s", __func__, signal_name, object_path);

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

	if (!strcmp(signal_name, "addressAcquired"))
		ni_ifworker_lease_acquired_seq += 1;

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

			/* We do not update the ifworker state if we're waiting for more events
			 * of the same name. For instance, during address configuration, we might
			 * start several addrconf mechanisms in parallel; for each of them, we'll
			 * receive an addressAcquired event. However, address configuration isn't
			 * complete until we've received *all* outstanding addressAcquired events.
			 */
			if (ni_ifworker_waiting_for_event(w, signal_name)) {
				ni_debug_application("%s: waiting for more %s events...", w->name, signal_name);
				goto done;
			}
		}

		if (!w->failed) {
			unsigned int min_state = STATE_NONE, max_state = __STATE_MAX;

			if (!strcmp(signal_name, "linkUp"))
				min_state = STATE_LINK_UP;
			if (!strcmp(signal_name, "linkDown"))
				max_state = STATE_LINK_UP - 1;
			if (!strcmp(signal_name, "addressAcquired"))
				min_state = STATE_ADDRCONF_UP;
			if (!strcmp(signal_name, "addressReleased"))
				max_state = STATE_ADDRCONF_UP - 1;

			ni_ifworker_update_state(w, min_state, max_state);
		}
	}

done: ;
}

static dbus_bool_t
ni_ifworkers_create_client(void)
{
	if (!(__root_object = ni_call_create_client()))
		return FALSE;

	ni_dbus_client_add_signal_handler(ni_dbus_object_get_client(__root_object), NULL, NULL,
			                        NI_OBJECTMODEL_NETIF_INTERFACE,
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
	ni_debug_application("finished with all devices.");
}

/*
 * Read ifconfig file(s)
 */
static dbus_bool_t
ni_ifconfig_file_load(const char *filename)
{
	xml_document_t *config_doc;

	ni_debug_readwrite("%s(%s)", __func__, filename);
	if (!(config_doc = xml_document_read(filename))) {
		ni_error("unable to load interface definition from %s", filename);
		return FALSE;
	}

	ni_ifworkers_from_xml(config_doc);

	/* Do *not* delete config_doc; we are keeping references to its
	 * descendant nodes in the ifworkers */
	return TRUE;
}

static dbus_bool_t
ni_ifconfig_load(const char *pathname)
{
	struct stat stb;

	ni_debug_readwrite("%s(%s)", __func__, pathname);
	if (stat(pathname, &stb) < 0) {
		ni_error("%s: %m", pathname);
		return FALSE;
	}

	if (S_ISREG(stb.st_mode))
		return ni_ifconfig_file_load(pathname);
	if (S_ISDIR(stb.st_mode)) {
		ni_string_array_t files = NI_STRING_ARRAY_INIT;
		char namebuf[PATH_MAX];
		unsigned int i;

		if (ni_scandir(pathname, "*.xml", &files) == 0) {
			ni_string_array_destroy(&files);
			return TRUE;
		}
		for (i = 0; i < files.count; ++i) {
			const char *name = files.data[i];

			snprintf(namebuf, sizeof(namebuf), "%s/%s", pathname, name);
			if (!ni_ifconfig_file_load(namebuf))
				return FALSE;
		}
		ni_string_array_destroy(&files);
		return TRUE;
	}

	ni_error("%s: neither a directory nor a regular file", pathname);
	return FALSE;
}

int
do_ifup(int argc, char **argv)
{
	enum  { OPT_IFCONFIG, OPT_BOOT, OPT_TIMEOUT, OPT_SKIP_ACTIVE };
	static struct option ifup_options[] = {
		{ "ifconfig",	required_argument, NULL,	OPT_IFCONFIG },
		{ "boot-label",	required_argument, NULL,	OPT_BOOT },
		{ "skip-active",required_argument, NULL,	OPT_SKIP_ACTIVE },
		{ "timeout",	required_argument, NULL,	OPT_TIMEOUT },
		{ NULL }
	};
	static ni_ifmatcher_t ifmatch;
	const char *opt_ifconfig = WICKED_IFCONFIG_DIR_PATH;
	unsigned int nmarked;
	int c;

	memset(&ifmatch, 0, sizeof(ifmatch));
	ifmatch.require_config = 1;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			opt_ifconfig = optarg;
			break;

		case OPT_BOOT:
			ifmatch.boot_label = optarg;
			break;

		case OPT_TIMEOUT:
			if (!strcmp(optarg, "infinite")) {
				ni_ifworker_timeout = 0;
			} else if (ni_parse_int(optarg, &ni_ifworker_timeout) >= 0) {
				ni_ifworker_timeout *= 1000; /* sec -> msec */
			} else {
				ni_error("ifup: cannot parse timeout option \"%s\"", optarg);
				goto usage;
			}
			break;

		case OPT_SKIP_ACTIVE:
			ifmatch.skip_active = 1;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifup [ifup-options] all\n"
				"wicked [options] ifup [ifup-options] <ifname> [options ...]\n"
				"\nSupported ifup-options:\n"
				"  --ifconfig <filename>\n"
				"      Read interface configuration(s) from file rather than using system config\n"
				"  --boot-label <label>\n"
				"      Only touch interfaces with matching <boot-label>\n"
				"  --timeout <nsec>\n"
				"      Timeout after <nsec> seconds\n"
				);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}

	if (!ni_ifworkers_create_client())
		return 1;

	ni_ifworkers_refresh_state();

	if (opt_global_rootdir) {
		static char namebuf[PATH_MAX];

		snprintf(namebuf, sizeof(namebuf), "%s/%s", opt_global_rootdir, opt_ifconfig);
		opt_ifconfig = namebuf;
	}

	if (!ni_ifconfig_load(opt_ifconfig))
		return 1;

	if (ni_ifworkers_build_hierarchy() < 0)
		ni_fatal("ifup: unable to build device hierarchy");

	nmarked = 0;
	while (optind < argc) {
		ifmatch.name = argv[optind++];

		if (!strcmp(ifmatch.name, "boot")) {
			ifmatch.name = "all";
			ifmatch.boot_label = "boot";
		}

		nmarked += ni_ifworker_mark_matching(&ifmatch, STATE_ADDRCONF_UP, __STATE_MAX);
	}
	if (nmarked == 0) {
		printf("No matching interfaces\n");
		return 0;
	}

	ni_ifworkers_kickstart();
	if (ni_ifworker_fsm() != 0)
		ni_ifworker_mainloop();

	/* return an error code if at least one of the devices failed */
	return ni_ifworkers_fail_count() != 0;
}

int
do_ifdown(int argc, char **argv)
{
	enum  { OPT_IFCONFIG, OPT_DELETE, OPT_TIMEOUT };
	static struct option ifdown_options[] = {
		{ "ifconfig",	required_argument, NULL,	OPT_IFCONFIG },
		{ "delete",	no_argument, NULL,		OPT_DELETE },
		{ "timeout",	required_argument, NULL,	OPT_TIMEOUT },
		{ NULL }
	};
	static ni_ifmatcher_t ifmatch;
	const char *opt_ifconfig = WICKED_IFCONFIG_DIR_PATH;
	unsigned int nmarked;
	int opt_delete = 0;
	int c;

	memset(&ifmatch, 0, sizeof(ifmatch));

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifdown_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			opt_ifconfig = optarg;
			break;

		case OPT_DELETE:
			opt_delete = 1;
			break;

		case OPT_TIMEOUT:
			if (!strcmp(optarg, "infinite")) {
				ni_ifworker_timeout = 0;
			} else if (ni_parse_int(optarg, &ni_ifworker_timeout) >= 0) {
				ni_ifworker_timeout *= 1000; /* sec -> msec */
			} else {
				ni_error("ifdown: cannot parse timeout option \"%s\"", optarg);
				goto usage;
			}
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
				"  --timeout <nsec>\n"
				"      Timeout after <nsec> seconds\n"
				);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}

	if (opt_global_rootdir) {
		static char namebuf[PATH_MAX];

		snprintf(namebuf, sizeof(namebuf), "%s/%s", opt_global_rootdir, opt_ifconfig);
		opt_ifconfig = namebuf;
	}

	if (!ni_ifconfig_load(opt_ifconfig))
		return 1;

	if (!ni_ifworkers_create_client())
		return 1;

	ni_ifworkers_refresh_state();

	nmarked = 0;
	while (optind < argc) {
		ifmatch.name = argv[optind++];
		nmarked += ni_ifworker_mark_matching(&ifmatch, STATE_NONE, opt_delete? STATE_DEVICE_DOWN : STATE_DEVICE_UP);
	}
	if (nmarked == 0) {
		printf("No matching interfaces\n");
		return 0;
	}

	ni_ifworkers_kickstart();
	if (ni_ifworker_fsm() != 0)
		ni_ifworker_mainloop();

	/* return an error code if at least one of the devices failed */
	return ni_ifworkers_fail_count() != 0;
}

