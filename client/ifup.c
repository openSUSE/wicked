/*
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
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

typedef struct ni_netif_action	ni_iftransition_t;

typedef int			ni_netif_action_fn_t(ni_ifworker_t *, ni_iftransition_t *);
struct ni_netif_action {
	int			from_state;
	int			next_state;
	ni_netif_action_fn_t *	func;

	struct {
		const char *		service_name;
		const ni_dbus_service_t *service;

		const char *		method_name;
		const ni_dbus_method_t *method;

		const char *		config_name;
		xml_node_t *		config;

		ni_bool_t		call_overloading;
	} common;

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
	ni_iftype_t		iftype;

	int			target_state;
	int			state;
	ni_iftransition_t *	wait_for;
	const ni_timer_t *	timer;

	unsigned int		failed		: 1,
				done		: 1;

	xml_node_t *		config;
	ni_netdev_t *		device;

	const ni_dbus_service_t *device_service;
	const ni_dbus_service_t *device_factory_service;
	xml_node_t *		device_config;

	unsigned int		shared_users;
	ni_ifworker_t *		exclusive_owner;

	ni_iftransition_t *	actions;
	ni_uint_range_t		child_states[__STATE_MAX];

	ni_ifworker_t *		parent;
	ni_ifworker_array_t	children;

	ni_ifworker_req_t *	dependencies;
};

typedef ni_bool_t		ni_ifworker_req_fn_t(ni_ifworker_t *, ni_ifworker_req_t *);
struct ni_ifworker_req {
	ni_ifworker_req_t *	next;

	unsigned int		event_seq;
	int			from_state;
	int			to_state;
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
static void			ni_ifworker_array_destroy(ni_ifworker_array_t *);
static ni_ifworker_t *		ni_ifworker_identify_device(const xml_node_t *);
static void			ni_ifworker_set_dependencies_xml(ni_ifworker_t *, xml_node_t *);
static void			ni_ifworker_fsm_init(ni_ifworker_t *);
static ni_bool_t		ni_ifworker_req_check_reachable(ni_ifworker_t *, ni_ifworker_req_t *);
static ni_bool_t		ni_ifworker_req_netif_resolve(ni_ifworker_t *, ni_ifworker_req_t *);
static void			ni_ifworker_req_free(ni_ifworker_req_t *);

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
ni_ifworker_free(ni_ifworker_t *w)
{
	ni_ifworker_req_t *req;

	ni_string_free(&w->name);
	ni_ifworker_array_destroy(&w->children);
	if (w->actions)
		free(w->actions);

	while ((req = w->dependencies) != NULL) {
		w->dependencies = req->next;
		ni_ifworker_req_free(req);
	}
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
ni_ifworker_req_new(const char *check, int from_state, int to_state, xml_node_t *node)
{
	ni_ifworker_req_fn_t *fn = NULL;
	ni_ifworker_req_t *req;

	if (ni_string_eq(check, "reachable")) {
		fn = ni_ifworker_req_check_reachable;
	} else
	if (ni_string_eq(check, "netif-resolve")) {
		fn = ni_ifworker_req_netif_resolve;
	}

	if (fn == NULL) {
		ni_error("%s: unknown dependency test \"%s\"", xml_node_location(node), check);
		return NULL;
	}

	req = calloc(1, sizeof(*req));
	req->from_state = from_state;
	req->to_state = to_state;
	req->test_fn = fn;
	req->event_seq = ~0U;
	req->data = node;

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
	const char *hostname;
	ni_sockaddr_t address;

	if (!req->data)
		return FALSE;
	if (!(hostname = req->data->cdata))
		return FALSE;

	/* Do not check too often. If the dhcp or routing info didn't change,
	 * there is no point wasting time on another lookup. */
	if (req->event_seq == ni_ifworker_lease_acquired_seq) {
		ni_debug_objectmodel("check reachability: %s SKIP", hostname);
		return FALSE;
	}
	req->event_seq = ni_ifworker_lease_acquired_seq;

	if (ni_resolve_hostname_timed(hostname, &address, 1) <= 0) {
		ni_debug_objectmodel("check reachability: %s not resolvable", hostname);
		return FALSE;
	}

	/* FIXME: actually check routability. */
	ni_debug_objectmodel("check reachability: %s OK", hostname);
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

		ni_debug_dbus("%s: identified device as \"%s\"",
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

	/* FIXME: we should record the devnode along with the child, and update
	 * devnode->cdata with the object path before we call any device change
	 * functions. */
	ni_ifworker_array_append(&parent->children, child);

#if 0
	if (parent->behavior.mandatory)
		child->behavior.mandatory = 1;
#endif

	return child;
}

static void
ni_ifworker_set_min_child_state_for(ni_ifworker_t *w, unsigned int dev_state, unsigned int child_state)
{
	ni_assert(dev_state < __STATE_MAX);
	ni_uint_range_update_min(&w->child_states[dev_state], child_state);
}

static void
ni_ifworker_set_max_child_state_for(ni_ifworker_t *w, unsigned int dev_state, unsigned int child_state)
{
	ni_assert(dev_state < __STATE_MAX);
	ni_uint_range_update_max(&w->child_states[dev_state], child_state);
}

static void
ni_ifworker_get_minmax_child_states(ni_ifworker_t *w, unsigned int *min_state, unsigned int *max_state)
{
	unsigned int st;

	*min_state = STATE_NONE;
	*max_state = __STATE_MAX;
	for (st = 0; st < __STATE_MAX; ++st) {
		const ni_uint_range_t *r = &w->child_states[st];

		if (*min_state < r->min)
			*min_state = r->min;
		if (*max_state > r->max)
			*max_state = r->max;
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
		ni_debug_dbus("device %s changed state %s -> %s%s",
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
				ni_debug_dbus("%s: identified interface %s",
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

	ni_trace("%s: resolved reference to subordinate device %s", w->name, child_worker->name);
	if (!ni_ifworker_add_child(w, child_worker, devnode))
		return FALSE;

	return TRUE;
}

/*
 * Dependency handling for interface bring-up.
 *
 * You can specify explicit dependencies for an interface using
 *   <dependencies>
 *     <require check="name-of-check" action="ifup|ifdown" state="link-up">parameter(s)</require>
 *   </dependencies>
 *
 * The "action" attribute specifies whether this rule applies to ifup or ifdown.
 *
 * The "state" attribute marks this as a requirement for entering the indicated
 * state (device-up, firewall-up, network-up, ...). If omitted, it defaults to
 * link-up.
 *
 * The "check" attribute specifies the name of the built-in test to use.
 * Currently implemented checks:
 *   reachable: the parameter is taken as a hostname, which must be resolvable
 *		and for which we have a route.
 */
void
ni_ifworker_set_dependencies_xml(ni_ifworker_t *w, xml_node_t *depnode)
{
	ni_ifworker_req_t **pos, *req;
	xml_node_t *reqnode;

	pos = &w->dependencies;
	for (reqnode = depnode->children; reqnode; reqnode = reqnode->next) {
		const char *check, *action, *state_name;
		int from_state, to_state = STATE_LINK_UP;

		if (!ni_string_eq(reqnode->name, "require"))
			continue;

		if (!(check = xml_node_get_attr(reqnode, "check"))) {
			ni_error("%s: <require> element lacks check attribute", xml_node_location(reqnode));
			continue;
		}
		if (!(action = xml_node_get_attr(reqnode, "action"))) {
			ni_error("%s: <require> element lacks action attribute", xml_node_location(reqnode));
			continue;
		}

		if ((state_name = xml_node_get_attr(reqnode, "state")) != NULL) {
			to_state = ni_ifworker_state_from_name(state_name);
			if (to_state < 0) {
				ni_error("%s: <require> element specifies bad state=\"%s\" attribute", xml_node_location(reqnode), state_name);
				continue;
			}
		}

		if (ni_string_eq(action, "ifup"))
			from_state = to_state - 1;
		else if (ni_string_eq(action, "ifdown"))
			from_state = to_state + 1;
		else {
			ni_error("%s: <require> element specifies bad action=\"%s\" attribute", xml_node_location(reqnode), action);
			continue;
		}

		req = ni_ifworker_req_new(check, from_state, to_state, reqnode);

		*pos = req;
		pos = &req->next;
	}
}

static ni_bool_t
ni_ifworker_check_dependencies(ni_ifworker_t *w, ni_iftransition_t *action)
{
	ni_ifworker_req_t *req, *next;

	if (!action->require.list)
		return TRUE;

	ni_debug_dbus("%s: checking requirements for %s -> %s transition",
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

static ni_bool_t
ni_ifworker_check_dependencies2(ni_ifworker_t *w, int next_state)
{
	ni_ifworker_req_t *req;
	int printed = 0;

	for (req = w->dependencies; req; req = req->next) {
		if (req->from_state == w->state
		 && req->to_state == next_state) {
			if (!printed++)
				ni_debug_dbus("%s: checking requirements for %s -> %s transition",
						w->name,
						ni_ifworker_state_name(req->from_state),
						ni_ifworker_state_name(req->to_state));
			if (!req->test_fn(w, req))
				return FALSE;
		}
	}

	return TRUE;
}

/*
 * Make sure the device's target state is in the [min, max] range.
 */
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
		w->state = STATE_ADDRCONF_UP;
	}
	ni_debug_dbus("%s: assuming current state=%s", w->name, ni_ifworker_state_name(w->state));

	if (w->children.count != 0) {
		unsigned int i;

		switch (w->iftype) {
		case NI_IFTYPE_VLAN:
			/* To bring a VLAN device up, the underlying eth device must be up.
			 * When bringing the VLAN down, don't touch the ethernet device,
			 * as it's shared. */
			if (min_state >= STATE_LINK_UP) {
				ni_ifworker_set_min_child_state_for(w, STATE_DEVICE_UP, STATE_DEVICE_UP);
				ni_ifworker_set_min_child_state_for(w, STATE_LINK_UP, STATE_LINK_UP);
			} else {
				return;
			}
			break;

		case NI_IFTYPE_BRIDGE:
			/* Bridge device: the bridge ports should at least exist.
			 * However, in order to do anything useful, they should at
			 * least have link.
			 * We may later want to allow the config file to override
			 * the initial state for specific bridge ports.
			 */
			if (min_state >= STATE_LINK_UP) {
				ni_ifworker_set_min_child_state_for(w, STATE_DEVICE_UP, STATE_DEVICE_UP);
				ni_ifworker_set_min_child_state_for(w, STATE_LINK_UP, STATE_LINK_UP);
			}
			break;

		case NI_IFTYPE_BOND:
			/* bond device: all slaves devices must exist and be down */
			if (min_state >= STATE_LINK_UP) {
				ni_ifworker_set_max_child_state_for(w, STATE_DEVICE_UP, STATE_LINK_UP - 1);
			}
			break;

		default:
			return;
		}

		ni_ifworker_get_minmax_child_states(w, &min_state, &max_state);

		ni_debug_dbus("%s: marking all children min=%s max=%s", w->name,
				ni_ifworker_state_name(min_state),
				ni_ifworker_state_name(max_state));
		for (i = 0; i < w->children.count; ++i) {
			ni_ifworker_t *child = w->children.data[i];

			ni_ifworker_set_target(child, min_state, max_state);
		}
	}
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
		ni_debug_dbus("%s: identified device as %s (%s)",
				xml_node_location(devnode), best->name, best->object_path);
	return best;
}

typedef struct ni_ifmatcher {
	const char *		name;
	const char *		boot_label;
	unsigned int		require_config : 1,
				skip_active    : 1;
} ni_ifmatcher_t;

static unsigned int
ni_ifworker_mark_matching(ni_ifmatcher_t *match, unsigned int target_state)
{
	unsigned int i, count = 0;

	ni_debug_dbus("%s(name=%s, target_state=%s)", __func__, match->name, ni_ifworker_state_name(target_state));

	if (!strcmp(match->name, "all")) {
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

		if (w->config == NULL) {
			fprintf(stderr,
				"%s: no configuration for interface, but bringing %s anyway\n",
				w->name, (target_state < STATE_LINK_UP)? "down" : "up");
		}

		ni_ifworker_set_target(w, target_state, target_state);
		count++;
	}

	for (i = 0; i < interface_workers.count; ++i) {
		ni_ifworker_t *w = interface_workers.data[i];

		if (w->target_state != STATE_NONE) {
			ni_debug_dbus("%s: target state %s",
					w->name, ni_ifworker_state_name(w->target_state));
			ni_ifworker_set_timeout(w, ni_ifworker_timeout);
			ni_ifworker_fsm_init(w);
		}
	}

	ni_debug_objectmodel("marked %u interfaces", count);
	return count;
}

/*
 * Given an XML interface description, find the device layer information.
 * By convention, the link layer information must be an XML element with
 * the name of the device type, such as <ethernet>, <vlan> or <bond>.
 * We do however also support "virtual" types such as openvpn, which is
 * really a tun device.
 */
static xml_node_t *
ni_ifworker_bind_device_apis(ni_ifworker_t *w)
{
	xml_node_t *ifnode, *child, *best_config;
	const ni_dbus_class_t *device_class = NULL, *best_class, *netif_class;
	const ni_dbus_service_t *best_service;

	if (w->device_config)
		return w->device_config;

	if ((ifnode = w->config) == NULL)
		return NULL;

	/* Check what type of interface we're dealing with. If the device exists,
	 * the class is based on the link layer.
	 */
	if (w->object)
		device_class = w->object->class;
	if (device_class == NULL && w->device != NULL) {
		const char *classname;

		w->iftype = w->device->link.type;
		if ((classname = ni_objectmodel_link_classname(w->device->link.type)) != NULL)
			 device_class = ni_objectmodel_get_class(classname);
	}

	netif_class = best_class = ni_objectmodel_get_class(NI_OBJECTMODEL_NETIF_CLASS);
	ni_assert(netif_class);

	for (child = ifnode->children; child; child = child->next) {
		const ni_dbus_service_t *device_service;

		device_service = ni_objectmodel_service_by_tag(child->name);
		if (device_service == NULL)
			device_service = ni_call_link_layer_service(child->name);

		if (device_service == NULL || device_service->compatible == NULL)
			continue;

		/* Silently ignore elements that are compatible with the "netif" class. We
		 * are only interested in device-specific subclasses.
		 */
		if (device_service->compatible == netif_class)
			continue;

		/* Silently ignore services that are compatible with the current "best" class
		 * or one of its super classes.
		 */
		if (ni_dbus_class_is_subclass(best_class, device_service->compatible))
			continue;

		ni_trace("<%s> - found %s, which is %s subclass of %s",
				child->name,
				device_service->compatible->name,
				ni_dbus_class_is_subclass(device_service->compatible, best_class)? "a": "no",
				best_class->name);

		/* Ignore services that are not compatible with our device class */
		if (device_class && !ni_dbus_class_is_subclass(device_class, device_service->compatible)) {
			ni_debug_objectmodel("%s: ignoring <%s> element (class %s), which is incompatible with %s",
					__func__, child->name, device_service->compatible->name,
					device_class->name);
			continue;
		}

		if (ni_dbus_class_is_subclass(device_service->compatible, best_class)) {
			best_service = device_service;
			best_config = child;
			best_class = device_service->compatible;
		} else {
			ni_error("%s: ambiguous link layer, found both <%s> and <%s> element",
					xml_node_location(ifnode),
					best_config->name, child->name);
			return NULL;
		}

	}

	/* It's perfectly fine not to find any link layer config;
	 * probably most people won't bother with adding any <ethernet>
	 * configuration for their eth devices. */
	if (best_service) {
		ni_debug_objectmodel("%s: using %s to configure device (using <%s> element)",
				w->name, best_service->name, best_config->name);

		/* Remember the device service and config node */
		w->device_service = best_service;
		w->device_config = best_config;

		/* Now find the factory and auth services for this device class, if there are any. */
		w->device_factory_service = ni_objectmodel_factory_service(best_service);

		/* The device service specifies a class it is compatible with, ie netif-foobar,
		 * where "foobar" must be a valid iftype name */
		if (w->iftype == NI_IFTYPE_UNKNOWN) {
			const char *classname = best_class->name;

			if (!strncmp(classname, "netif-", 6))
				w->iftype = ni_linktype_name_to_type(classname + 6);
		}
	}

	return w->device_config;
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

		if (!(linknode = ni_ifworker_bind_device_apis(w)))
			continue;

		if (w->iftype == NI_IFTYPE_UNKNOWN) {
			ni_error("%s: bug - unable to identify link type of %s", __func__, w->name);
			ni_fatal("Abort");
		}

		devnode = NULL;
		while ((devnode = xml_node_get_next_named(linknode, "device", devnode)) != NULL) {
			if (!(child = ni_ifworker_resolve_reference(devnode)))
				return -1;

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
static int
ni_ifworker_children_ready_for(ni_ifworker_t *w, unsigned int next_parent_state)
{
	const ni_uint_range_t *r;
	unsigned int i;

	ni_assert(next_parent_state < __STATE_MAX);
	r = &w->child_states[next_parent_state];

	for (i = 0; i < w->children.count; ++i) {
		ni_ifworker_t *child = w->children.data[i];

		if (r->min != __STATE_MAX && child->state < r->min) {
			ni_debug_dbus("%s: waiting for %s to reach state %s",
					w->name, child->name,
					ni_ifworker_state_name(r->min));
			return 0;
		}
		if (r->max != STATE_NONE && child->state > r->max) {
			ni_debug_dbus("%s: waiting for %s to reach state %s",
					w->name, child->name,
					ni_ifworker_state_name(r->max));
			return 0;
		}
	}

	return 1;
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
 * Parse any <require> tags contained in the per-method metadata
 */
static int
ni_ifworker_map_requires(ni_ifworker_t *w, ni_iftransition_t *action,
		const ni_dbus_service_t *service, const ni_dbus_method_t *method)
{
	xml_node_t *req_nodes[32];
	ni_ifworker_req_t **pos, *require;
	unsigned int i, count;

	action->require.parsed = TRUE;

	count = ni_dbus_xml_get_method_metadata(method, "require", req_nodes, 32);
	if (count == 0)
		return 0;

	for (pos = &action->require.list; (require = *pos) != NULL; pos = &require->next)
		;

	for (i = 0; i < count; ++i) {
		xml_node_t *rnode, *expanded[64];
		const char *attr, *check;
		unsigned int j, num_expanded;
		int rv;

		rnode = req_nodes[i];
		if ((check = xml_node_get_attr(rnode, "check")) == NULL) {
			ni_error("%s: missing check attribute", xml_node_location(rnode));
			return -NI_ERROR_DOCUMENT_ERROR;
		}

		if ((attr = xml_node_get_attr(rnode, "document-node")) == NULL) {
			ni_error("%s: missing document-node attribute", xml_node_location(rnode));
			return -NI_ERROR_DOCUMENT_ERROR;
		}

		rv = ni_dbus_xml_expand_element_reference(w->config, attr, expanded, 64);
		if (rv < 0)
			return rv;

		num_expanded = rv;
		for (j = 0; j < num_expanded; ++j) {
			require = ni_ifworker_req_new(check, 0, 0, expanded[j]);
			if (require == NULL) {
				ni_error("%s: cannot build requirement", xml_node_location(rnode));
				return -NI_ERROR_DOCUMENT_ERROR;
			}

			ni_trace("%s: add require check=%s node=%s", w->name, check, xml_node_location(expanded[j]));

			*pos = require;
			pos = &require->next;
		}
	}

	return 0;
}

/*
 * Most steps of the finite state machine follow the same pattern.
 */
static int
__ni_ifworker_do_common_service(ni_ifworker_t *w, ni_iftransition_t *action,
		const ni_dbus_service_t *service)
{
	ni_objectmodel_callback_info_t *callback_list = NULL;
	const ni_dbus_method_t *method;
	xml_node_t *config;
	int rv;

	method = action->common.method;
	if (method == NULL) {
		method = ni_dbus_service_get_method(service, action->common.method_name);

		/* If the interface doesn't support this interface, we trivially succeed. */
		if (method == NULL)
			return 0;
	}

	if (!action->require.parsed) {
		rv = ni_ifworker_map_requires(w, action, service, method);
		if (rv < 0)
			return rv;
	}
	if (!ni_ifworker_check_dependencies(w, action)) {
		ni_debug_objectmodel("%s: defer action (pending dependencies)", w->name);
		w->wait_for = action;
		return 0;
	}

	config = action->common.config;
	if (config == NULL && action->common.config_name) {
		config = xml_node_get_child(w->config, action->common.config_name);
	}

	if (config == NULL) {
		/* Consult the method's metadata information to see how to
		 * locate the configuration node. Any argument to a method may have
		 * a <mapping> metadata element:
		 *
		 * <method ...>
		 *   <arguments>
		 *     <foobar type="...">
		 *       <meta>
		 *	   <mapping
		 *	   	document-node="/some/xpath/expression" 
		 *		skip-unless-present="true"
		 *		/>
		 *       </meta>
		 *     </foobar>
		 *   </arguments>
		 * </method>
		 *
		 * The document node is an xpath relative to the enclosing
		 * <interface> element. If the document does not contain the
		 * referenced node, and skip-unless-present is true, then we
		 * do not perform this call.
		 */
		ni_bool_t skip_call = FALSE;

		if (ni_dbus_xml_map_method_argument(method, 0, w->config, &config, &skip_call) < 0)
			goto document_error;

		if (config == NULL && skip_call)
			return 0;
	}

	if (config != NULL) {
		/* FIXME: validate XML */
	}

	rv = ni_call_common_xml(w->object, service, method, config, &callback_list, ni_ifworker_error_handler);
	if (rv < 0) {
		ni_ifworker_fail(w, "call to %s.%s() failed: %s", service->name, method->name, ni_strerror(rv));
		return rv;
	}

	if (callback_list) {
		ni_ifworker_add_callbacks(action, callback_list, w->name);
		w->wait_for = action;
		return 0;
	}

	return 0;

document_error:
	ni_ifworker_fail(w, "interface document error");
	return -1;
}

int
ni_ifworker_do_common(ni_ifworker_t *w, ni_iftransition_t *action)
{
	const ni_dbus_service_t *service;
	int rv;

	ni_debug_objectmodel("%s(name=%s, object=%p, path=%s)",
			action->common.method_name, w->name, w->object, w->object_path);

	service = action->common.service;
	if (service == NULL) {
		if (action->common.service_name != NULL) {
			/* This transition explicitly specifies a dbus service.
			 * Fail if it is not supported. */
			service = ni_dbus_object_get_service(w->object, action->common.service_name);
			if (service == NULL) {
				ni_ifworker_fail(w, "object does not support interface %s",
						action->common.service_name);
				return -NI_ERROR_METHOD_NOT_SUPPORTED;
			}
		} else if (action->common.call_overloading) {
			/* Implicit: look up the service(s) based on the method name.
			 * We may have multiple services providing a given method,
			 * but we should pick the most specific one. */
			service = ni_dbus_object_get_service_for_method(w->object, action->common.method_name);
			if (service == NULL)
				goto success;
		} else {
			/* Implicit: look up the service(s) based on the method name.
			 * We may be dealing with several services, and we want to call all of them.
			 * This happens when it comes to addrconf services, for instance.
			 */
			const ni_dbus_service_t *services[32];
			unsigned int i, count;

			count = ni_dbus_object_get_all_services_for_method(w->object,
						action->common.method_name, services, 32);

			/* If the interface doesn't support this method, we trivially succeed. */
			if (count == 0)
				goto success;

			ni_trace("%s: found %u services providing %s()",
					w->name, count, action->common.method_name);
			for (i = 0; i < count; ++i) {
				rv = __ni_ifworker_do_common_service(w, action, services[i]);
				if (rv < 0)
					return rv;
			}
			goto success;
		}

		action->common.service = service;
	}

	if ((rv = __ni_ifworker_do_common_service(w, action, service)) < 0)
		return -1;

success:
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
ni_ifworker_do_device_new(ni_ifworker_t *w, ni_iftransition_t *action)
{
	const ni_dbus_service_t *device_service = NULL;
	xml_node_t *device_config = NULL;
	const ni_dbus_method_t *device_method = NULL;

	ni_debug_dbus("%s(%s)", __func__, w->name);

	if (w->device == NULL) {
		const ni_dbus_method_t *method;
		const ni_dbus_class_t *netif_list_class;
		const ni_dbus_service_t *list_services[128];
		unsigned int i, count;
		const char *relative_path;
		char *object_path;
		int rv;

		if (w->config == NULL) {
			ni_ifworker_fail(w, "cannot create device - no configuration");
			return -1;
		}

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
				if (device_config != NULL) {
					ni_ifworker_fail(w, "ambiguous device configuration - found services %s and %s",
							service->name, device_service->name);
					return -1;
				}
				device_service = service;
				device_config = config;
				device_method = method;
			}
		}

		if (device_service == NULL) {
			ni_ifworker_fail(w, "device does not exist");
			return -1;
		}

		rv = ni_ifworker_map_requires(w, action, device_service, device_method);
		if (rv < 0)
			return rv;

		if (!ni_ifworker_check_dependencies(w, action)) {
			ni_debug_objectmodel("%s: defer device creation (pending dependencies)", w->name);
			w->wait_for = action;
			return 0;
		}

		object_path = ni_call_device_new_xml(device_service, w->name, device_config);
		if (object_path == NULL) {
			ni_ifworker_fail(w, "failed to create interface");
			return -1;
		}

		ni_debug_dbus("created device %s (path=%s)", w->name, object_path);
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
#define TRANSITION_UP_TO(__state, __func) { \
	.from_state = __state - 1, .next_state = __state, .func = __func \
}
#define TRANSITION_DOWN_FROM(__state, __func) { \
	.from_state = __state, .next_state = __state - 1, .func = __func \
}

#define COMMON_TRANSITION_UP_TO(__state, __svc, __meth, __node, __more...) { \
	.from_state = __state - 1, \
	.next_state = __state, \
	.func = ni_ifworker_do_common, \
	.common = { .service_name = __svc, .method_name = __meth, .config_name = __node, ##__more } \
}

#define COMMON_TRANSITION_DOWN_FROM(__state, __svc, __meth, __node, __more...) { \
	.from_state = __state, \
	.next_state = __state - 1, \
	.func = ni_ifworker_do_common, \
	.common = { .service_name = __svc, .method_name = __meth, .config_name = __node, ##__more } \
}

static ni_iftransition_t	ni_iftransitions[] = {
	/* -------------------------------------- *
	 * Transitions for bringing up a device
	 * -------------------------------------- */
	/* This creates the device (if it's virtual) */
	TRANSITION_UP_TO(STATE_DEVICE_EXISTS, ni_ifworker_do_device_new),

	/* This sets any device attributes, such as a MAC address */
	COMMON_TRANSITION_UP_TO(STATE_DEVICE_UP, NULL, "changeDevice", NULL, .call_overloading = TRUE),

	/* This step adds device-specific filtering, if available. Typical
	 * example would be bridge filtering with ebtables. */
	COMMON_TRANSITION_UP_TO(STATE_FIREWALL_UP, NULL, "firewallUp", "firewall"),

	/* This brings up the link layer, and sets general device attributes such
	 * as the MTU, the transfer queue length etc. */
	/* FIXME: change the xml node name from <device> to something else.
	 * See also linkDown() below. */
	COMMON_TRANSITION_UP_TO(STATE_LINK_UP, NULL, "linkUp", "device"),

	/* If the link requires authentication, this information can be provided
	 * here; for instance ethernet 802.1x, wireless WPA, or PPP chap/pap.
	 * NOTE: This may not be the right place; we may have to fold this into
	 * the link_up step, or even do it prior to that. */
	COMMON_TRANSITION_UP_TO(STATE_LINK_AUTHENTICATED, NULL, "login", NULL),

	/* Configure all assigned addresses and bring up the network */
	COMMON_TRANSITION_UP_TO(STATE_ADDRCONF_UP, NULL, "requestLease", NULL),

	/* -------------------------------------- *
	 * Transitions for bringing down a device
	 * -------------------------------------- */
	/* Remove all assigned addresses and bring down the network */
	COMMON_TRANSITION_DOWN_FROM(STATE_ADDRCONF_UP, NULL, "dropLease", NULL),

	/* Shut down the link */
	COMMON_TRANSITION_DOWN_FROM(STATE_LINK_UP, NULL, "linkDown", "device"),

	/* Shut down the firewall */
	COMMON_TRANSITION_DOWN_FROM(STATE_FIREWALL_UP, NULL, "firewallDown", "firewall"),

	/* Delete the device */
	COMMON_TRANSITION_DOWN_FROM(STATE_DEVICE_UP, NULL, "deleteDevice", NULL),

	{ .from_state = STATE_NONE, .next_state = STATE_NONE, .func = NULL }
};

static void
ni_ifworker_fsm_init(ni_ifworker_t *w)
{
	unsigned int index, num_actions;
	unsigned int target_state, from_state, cur_state;
	int increment;

	if (w->actions != NULL)
		return;

	/* If the --delete option was given, but the specific device cannot
	 * be deleted, then we don't try. */
	target_state = w->target_state;
	if (target_state == STATE_DEVICE_DOWN && !ni_ifworker_can_delete(w)) {
		ni_debug_objectmodel("%s: cannot delete device, ignoring --delete option", w->name);
		target_state = STATE_DEVICE_UP;
	}

	switch (target_state) {
	case STATE_ADDRCONF_UP:
	case STATE_LINK_UP:
		from_state = STATE_DEVICE_DOWN;
		increment = 1;
		break;

	case STATE_DEVICE_UP:
	case STATE_DEVICE_DOWN:
		from_state = STATE_ADDRCONF_UP;
		increment = -1;
		break;

	default:
		ni_fatal("%s: cannot assign fsm for target state %s",
				w->name, ni_ifworker_state_name(w->target_state));
	}

	ni_debug_objectmodel("%s: set up FSM from %s -> %s", w->name,
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

					if (a->common.method_name) {
						ni_debug_objectmodel("  %s -> %s: %s()",
							ni_ifworker_state_name(cur_state),
							ni_ifworker_state_name(next_state),
							a->common.method_name);
					} else {
						ni_debug_objectmodel("  %s -> %s: func=%p",
							ni_ifworker_state_name(cur_state),
							ni_ifworker_state_name(target_state),
							a->func);
					}
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
			int prev_state;

			if (w->target_state != STATE_NONE)
				ni_debug_dbus("%-12s: state=%s want=%s%s%s", w->name,
					ni_ifworker_state_name(w->state),
					ni_ifworker_state_name(w->target_state),
					w->wait_for? ", wait-for=" : "",
					w->wait_for?  ni_ifworker_state_name(w->wait_for->next_state) : "");

			if (w->failed || ni_ifworker_ready(w))
				continue;

			/* If we're still waiting for children to become ready,
			 * there's nothing we can do but wait. */
			if (!ni_ifworker_children_ready_for(w, w->actions->next_state))
				continue;

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

			/* See if we've fulfilled all dependencies for entering this state. */
			if (!ni_ifworker_check_dependencies2(w, action->next_state)) {
				ni_debug_dbus("%s: not all dependencies fulfilled", w->name);
				continue;
			}

			prev_state = w->state;
			w->actions++;
			if (action->func(w, action) >= 0) {
				made_progress = 1;
				if (w->state == action->next_state) {
					/* We should not have transitioned to the next state while
					 * we were still waiting for some event. */
					ni_assert(w->wait_for == NULL);
					ni_debug_dbus("%s: successfully transitioned from %s to %s",
						w->name,
						ni_ifworker_state_name(prev_state),
						ni_ifworker_state_name(w->state));
				} else {
					ni_debug_dbus("%s: waiting for event in state %s",
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
				ni_debug_dbus("%s: waiting for more %s events...", w->name, signal_name);
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
	ni_debug_dbus("finished with all devices.");
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

	if (optind + 1 != argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}
	ifmatch.name = argv[optind++];

	if (!strcmp(ifmatch.name, "boot")) {
		ifmatch.name = "all";
		ifmatch.boot_label = "boot";
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

	if (build_hierarchy() < 0)
		ni_fatal("ifup: unable to build device hierarchy");

	if (!ni_ifworker_mark_matching(&ifmatch, STATE_ADDRCONF_UP))
		return 0;

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

	if (optind + 1 != argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}
	ifmatch.name = argv[optind++];

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

	if (!ni_ifworker_mark_matching(&ifmatch, opt_delete? STATE_DEVICE_DOWN : STATE_DEVICE_UP))
		return 0;

	ni_ifworkers_kickstart();
	if (ni_ifworker_fsm() != 0)
		ni_ifworker_mainloop();

	/* return an error code if at least one of the devices failed */
	return ni_ifworkers_fail_count() != 0;
}

