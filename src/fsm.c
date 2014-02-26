/*
 * Finite state machine and associated functionality for interface
 * bring-up and take-down.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <unistd.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/xml.h>
#include <wicked/socket.h>
#include <wicked/dbus.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/modem.h>
#include <wicked/xpath.h>
#include <wicked/fsm.h>
#include <wicked/client.h>
#include "util_priv.h"

static unsigned int		ni_ifworker_timeout_count;
static ni_fsm_user_prompt_fn_t *ni_fsm_user_prompt_fn;
static void *			ni_fsm_user_prompt_data;

static ni_ifworker_t *		ni_ifworker_identify_device(ni_fsm_t *, const xml_node_t *, ni_ifworker_type_t);
static ni_ifworker_t *		__ni_ifworker_identify_device(ni_fsm_t *, const char *, const xml_node_t *, ni_ifworker_type_t);
static void			ni_ifworker_set_dependencies_xml(ni_ifworker_t *, xml_node_t *);
static int			ni_fsm_schedule_init(ni_fsm_t *fsm, ni_ifworker_t *, unsigned int, unsigned int);
static int			ni_fsm_schedule_bind_methods(ni_fsm_t *, ni_ifworker_t *);
static ni_fsm_require_t *	ni_ifworker_netif_resolver_new(xml_node_t *);
static ni_fsm_require_t *	ni_ifworker_modem_resolver_new(xml_node_t *);
static void			ni_fsm_require_list_destroy(ni_fsm_require_t **);
static void			ni_fsm_require_free(ni_fsm_require_t *);
static int			ni_ifworker_bind_device_apis(ni_ifworker_t *, const ni_dbus_service_t *);
static void			ni_ifworker_control_set_defaults(ni_ifworker_t *);
static void			__ni_ifworker_refresh_netdevs(ni_fsm_t *);
#ifdef MODEM
static void			__ni_ifworker_refresh_modems(ni_fsm_t *);
#endif
static int			ni_fsm_user_prompt_default(const ni_fsm_prompt_t *, xml_node_t *, void *);
static void			ni_ifworker_refresh_client_info(ni_ifworker_t *, ni_device_clientinfo_t *);
static void			ni_ifworker_refresh_client_state(ni_ifworker_t *, ni_client_state_t *);
static void			ni_ifworker_set_config_origin(ni_ifworker_t *, const char *);
static void			ni_ifworker_cancel_timeout(ni_ifworker_t *);

ni_fsm_t *
ni_fsm_new(void)
{
	ni_fsm_t *fsm;

	fsm = calloc(1, sizeof(*fsm));
	fsm->worker_timeout = NI_IFWORKER_DEFAULT_TIMEOUT;
	fsm->readonly = FALSE;

	ni_fsm_user_prompt_fn = ni_fsm_user_prompt_default;
	return fsm;
}

void
ni_fsm_free(ni_fsm_t *fsm)
{
	ni_ifworker_array_destroy(&fsm->workers);
	free(fsm);
}

/*
 * Return number of failed interfaces
 */
unsigned int
ni_fsm_fail_count(ni_fsm_t *fsm)
{
	unsigned int i, nfailed = 0;

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (w->failed)
			nfailed++;
	}

	return nfailed;
}

static inline ni_ifworker_t *
__ni_ifworker_new(ni_ifworker_type_t type, const char *name)
{
	ni_ifworker_t *w;

	w = xcalloc(1, sizeof(*w));
	ni_string_dup(&w->name, name);
	w->type = type;
	w->refcount = 1;

	w->target_range.min = NI_FSM_STATE_NONE;
	w->target_range.max = __NI_FSM_STATE_MAX;
	w->readonly = FALSE;

	ni_ifworker_control_set_defaults(w);

	return w;
}

static ni_ifworker_t *
ni_ifworker_new(ni_fsm_t *fsm, ni_ifworker_type_t type, const char *name)
{
	ni_ifworker_t *worker;

	worker = __ni_ifworker_new(type, name);
	ni_ifworker_array_append(&fsm->workers, worker);
	worker->refcount--;

	return worker;
}

void
ni_ifworker_reset(ni_ifworker_t *w)
{
	ni_string_free(&w->object_path);
	ni_string_free(&w->config.origin);
	ni_string_free(&w->control.mode);
	ni_string_free(&w->control.boot_stage);
	ni_security_id_destroy(&w->security_id);

	/* When detaching children, clear their shared/exclusive ownership info */
	if (w->children.count != 0) {
		unsigned int i;

		for (i = 0; i < w->children.count; ++i) {
			ni_ifworker_t *child_worker = w->children.data[i];

			if (child_worker->exclusive_owner == w) {
				child_worker->exclusive_owner = NULL;
			} else {
				ni_assert(child_worker->exclusive_owner == NULL);
				ni_assert(child_worker->shared_users);
				child_worker->shared_users -= 1;
			}
		}
	}
	ni_ifworker_array_destroy(&w->children);

	if (w->fsm.action_table) {
		ni_fsm_transition_t *action;

		for (action = w->fsm.action_table; action->next_state; action++)
			ni_fsm_require_list_destroy(&action->require.list);
		free(w->fsm.action_table);
	}
	w->fsm.action_table = NULL;

	w->target_state = NI_FSM_STATE_NONE;
	w->target_range.min = NI_FSM_STATE_NONE;
	w->target_range.max = __NI_FSM_STATE_MAX;

	ni_ifworker_cancel_timeout(w);

	ni_fsm_require_list_destroy(&w->fsm.child_state_req_list);
	memset(&w->fsm, 0, sizeof(w->fsm));
	memset(&w->device_api, 0, sizeof(w->device_api));

	w->failed = FALSE;
	w->done = FALSE;
	w->kickstarted = FALSE;
	w->readonly = FALSE;
}

void
ni_ifworker_free(ni_ifworker_t *w)
{
	ni_string_free(&w->name);
	ni_ifworker_reset(w);
	free(w);
}

static inline ni_bool_t
ni_ifworker_device_bound(const ni_ifworker_t *w)
{
	switch (w->type) {
	case NI_IFWORKER_TYPE_NETDEV:
		return w->device != NULL;

	case NI_IFWORKER_TYPE_MODEM:
		return w->modem != NULL;

	default:
		return FALSE;
	}
}

/*
 * Register dependency types
 */
typedef struct ni_fsm_require_type ni_fsm_require_type_t;
struct ni_fsm_require_type {
	ni_fsm_require_type_t *	next;
	char *			name;
	ni_fsm_require_ctor_t *	func;
};

static struct ni_fsm_require_type *ni_fsm_require_type_registry;

void
ni_fsm_require_register_type(const char *name, ni_fsm_require_ctor_t *ctor)
{
	ni_fsm_require_type_t *type;

	type = xcalloc(1, sizeof(*type));
	ni_string_dup(&type->name, name);
	type->func = ctor;

	type->next = ni_fsm_require_type_registry;
	ni_fsm_require_type_registry = type;
}

static ni_fsm_require_ctor_t *
ni_fsm_require_find_type(const char *name)
{
	ni_fsm_require_type_t *type;

	for (type = ni_fsm_require_type_registry; type; type = type->next) {
		if (ni_string_eq(type->name, name))
			return type->func;
	}

	return NULL;
}

/*
 * constructor/destructor for dependency objects
 */
ni_fsm_require_t *
ni_ifworker_requirement_build(const char *check_name, xml_node_t *node, ni_fsm_require_t **list)
{
	ni_fsm_require_t *req, **pos;
	ni_fsm_require_ctor_t *ctor;

	/* Find tail of list */
	for (pos = list; (req = *pos) != NULL; pos = &req->next)
		;

	if ((ctor = ni_fsm_require_find_type(check_name)) != NULL) {
		req = ctor(node);
	} else
	if (ni_string_eq(check_name, "netif-resolve")) {
		req = ni_ifworker_netif_resolver_new(node);
	} else
	if (ni_string_eq(check_name, "modem-resolve")) {
		req = ni_ifworker_modem_resolver_new(node);
	} else {
		ni_error("unknown function in <require check=\"%s\"> at %s", check_name, xml_node_location(node));
		return NULL;
	}

	if (req == NULL) {
		ni_error("%s: invalid <require check=\"%s\"> element, cannot parse", xml_node_location(node), check_name);
		return NULL;
	}

	*pos = req;
	return req;
}

ni_fsm_require_t *
ni_fsm_require_new(ni_fsm_require_fn_t *test_fn, ni_fsm_require_dtor_t *destroy_fn)
{
	ni_fsm_require_t *req;

	req = calloc(1, sizeof(*req));
	req->test_fn = test_fn;
	req->destroy_fn = destroy_fn;
	req->event_seq = ~0U;
	return req;
}

void
ni_fsm_require_free(ni_fsm_require_t *req)
{
	if (req->destroy_fn)
		req->destroy_fn(req);
	free(req);
}

void
ni_fsm_require_list_destroy(ni_fsm_require_t **list)
{
	ni_fsm_require_t *req;

	while ((req = *list) != NULL) {
		*list = req->next;
		ni_fsm_require_free(req);
	}
}

void
ni_fsm_require_list_insert(ni_fsm_require_t **list, ni_fsm_require_t *req)
{
	req->next = *list;
	*list = req;
}

/*
 * Handle success/failure of an ifworker.
 */
static void
__ni_ifworker_done(ni_ifworker_t *w)
{
	w->fsm.action_table = NULL;
	if (w->completion.callback)
		w->completion.callback(w);
	w->done = 1;
}

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
	w->fsm.state = w->target_state = NI_FSM_STATE_NONE;
	w->failed = TRUE;

	__ni_ifworker_done(w);
}

static void
ni_ifworker_success(ni_ifworker_t *w)
{
	if (!w->done)
		printf("%s: %s\n", w->name, ni_ifworker_state_name(w->fsm.state));

	__ni_ifworker_done(w);

	ni_ifworker_cancel_timeout(w);
}

/*
 * Set the completion callback
 */
void
ni_ifworker_set_completion_callback(ni_ifworker_t *w, void (*cb)(ni_ifworker_t *), void *user_data)
{
	w->completion.callback = cb;
	w->completion.user_data = user_data;
}

/*
 * Handle timeouts of device config.
 */
static void
__ni_ifworker_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_ifworker_t *w = user_data;

	if (w->fsm.timer != timer) {
		ni_error("%s(%s) called with unexpected timer", __func__, w->name);
	} else {
		ni_ifworker_fail(w, "operation timed out");
	}
	ni_ifworker_timeout_count++;
}

static void
ni_ifworker_cancel_timeout(ni_ifworker_t *w)
{
	if (w->fsm.timer) {
		ni_timer_cancel(w->fsm.timer);
		w->fsm.timer = NULL;
		ni_debug_application("%s: cancel timeout", w->name);
	}
}

static void
ni_ifworker_set_timeout(ni_ifworker_t *w, unsigned long timeout_ms)
{
	ni_ifworker_cancel_timeout(w);
	if (timeout_ms && timeout_ms != NI_IFWORKER_INFINITE_TIMEOUT)
		w->fsm.timer = ni_timer_register(timeout_ms, __ni_ifworker_timeout, w);
}

static void
ni_ifworker_set_secondary_timeout(ni_ifworker_t *w, unsigned long timeout_ms, void (*handler)(void *, const ni_timer_t *))
{
	if (w->fsm.secondary_timer)
		ni_timer_cancel(w->fsm.secondary_timer);
	if (handler && timeout_ms && timeout_ms != NI_IFWORKER_INFINITE_TIMEOUT)
		w->fsm.secondary_timer = ni_timer_register(timeout_ms, handler, w);
}

static ni_intmap_t __state_names[] = {
	{ "none",		NI_FSM_STATE_NONE		},
	{ "device-down",	NI_FSM_STATE_DEVICE_DOWN	},
	{ "device-exists",	NI_FSM_STATE_DEVICE_EXISTS	},
	{ "device-up",		NI_FSM_STATE_DEVICE_UP		},
	{ "protocols-up",	NI_FSM_STATE_PROTOCOLS_UP	},
	{ "firewall-up",	NI_FSM_STATE_FIREWALL_UP	},
	{ "link-up",		NI_FSM_STATE_LINK_UP		},
	{ "link-authenticated",	NI_FSM_STATE_LINK_AUTHENTICATED	},
	{ "lldp-up",		NI_FSM_STATE_LLDP_UP		},
	{ "network-up",		NI_FSM_STATE_ADDRCONF_UP	},
	{ "max",		__NI_FSM_STATE_MAX		},

	{ NULL }
};

inline ni_bool_t
ni_ifworker_state_in_range(const ni_uint_range_t *range, const unsigned int state)
{
	return state >= range->min && state <= range->max;
}

const char *
ni_ifworker_state_name(unsigned int state)
{
	return ni_format_uint_mapped(state, __state_names);
}

ni_bool_t
ni_ifworker_state_from_name(const char *name, unsigned int *state)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __state_names, &value) < 0)
		return FALSE;
	if (state)
		*state = value;
	return TRUE;
}

void
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
ni_ifworker_array_find(ni_ifworker_array_t *array, ni_ifworker_type_t type, const char *ifname)
{
	unsigned int i;

	if (!ifname)
		return NULL;

	for (i = 0; i < array->count; ++i) {
		ni_ifworker_t *worker = array->data[i];

		if (worker->type == type && !strcmp(worker->name, ifname))
			return worker;
	}
	return NULL;
}

static ni_bool_t
ni_ifworker_array_remove(ni_ifworker_array_t *array, ni_ifworker_t *w)
{
	unsigned int i, j;
	ni_bool_t found = FALSE;

	for (i = 0; i < array->count; ) {
		if (w == array->data[i]) {
			ni_ifworker_release(w);

			/* Shift remainder of array down one position */
			array->count -= 1;
			for (j = i; j < array->count; ++j)
				array->data[j] = array->data[j + 1];

			found = TRUE;
		} else {
			++i;
		}
	}

	return found;
}

ni_ifworker_t *
ni_fsm_ifworker_by_name(ni_fsm_t *fsm, ni_ifworker_type_t type, const char *ifname)
{
	return ni_ifworker_array_find(&fsm->workers, type, ifname);
}

ni_ifworker_t *
ni_fsm_ifworker_by_object_path(ni_fsm_t *fsm, const char *object_path)
{
	unsigned int i;

	if (!object_path)
		return NULL;

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (w->object_path && !strcmp(w->object_path, object_path))
			return w;
	}

	return NULL;
}

static ni_ifworker_t *
ni_ifworker_by_ifindex(ni_fsm_t *fsm, unsigned int ifindex)
{
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (w->ifindex && w->ifindex == ifindex)
			return w;
	}

	return NULL;
}

ni_ifworker_t *
ni_fsm_ifworker_by_netdev(ni_fsm_t *fsm, const ni_netdev_t *dev)
{
	unsigned int i;

	if (dev == NULL)
		return NULL;

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

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
ni_ifworker_by_modem(ni_fsm_t *fsm, const ni_modem_t *dev)
{
	unsigned int i;

	if (dev == NULL)
		return NULL;

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (w->modem == dev)
			return w;
		if (w->name && ni_string_eq(dev->device, w->name))
			return w;
	}

	return NULL;
}

ni_bool_t
ni_ifworker_match_alias(const ni_ifworker_t *w, const char *alias)
{
	xml_node_t *node;

	if (!alias)
		return FALSE;

	if (w->device && ni_string_eq(w->device->link.alias, alias))
		return TRUE;

	if (w->config.node && (node = xml_node_get_child(w->config.node, "alias")) != NULL) {
		if (ni_string_eq(node->cdata, alias))
			return TRUE;
	}

	return FALSE;
}

static ni_ifworker_t *
ni_ifworker_by_alias(ni_fsm_t *fsm, const char *alias)
{
	unsigned int i;

	if (!alias)
		return NULL;

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (ni_ifworker_match_alias(w, alias))
			return w;
	}

	return NULL;
}

/*
 * Determine what class of devices a worker belongs to
 */
ni_rfkill_type_t
ni_ifworker_get_rfkill_type(const ni_ifworker_t *w)
{
	if (w->object == NULL)
		return FALSE;

	switch (w->type) {
	case NI_IFWORKER_TYPE_MODEM:
		/* FIXME */
		return -1;

	case NI_IFWORKER_TYPE_NETDEV:
		if (w->device == NULL)
			return -1;
		switch (w->device->link.type) {
		case NI_IFTYPE_WIRELESS:
			return NI_RFKILL_TYPE_WIRELESS;
		default: ;
		}
		break;

	default: ;
	}

	return -1;
}

/*
 * When processing an <interface> or <modem> document, resolve any references to
 * other devices.
 */
static ni_ifworker_t *
ni_ifworker_resolve_reference(ni_fsm_t *fsm, xml_node_t *devnode, ni_ifworker_type_t type)
{
	ni_ifworker_t *child;

	if (devnode->children || devnode->cdata) {
		/* Try to identify device based on attributes given in the
		 * <device> node. */
		const char *namespace;

		namespace = xml_node_get_attr(devnode, "namespace");
		if (namespace != NULL) {
			child = __ni_ifworker_identify_device(fsm, namespace, devnode, type);
		} else if (devnode->cdata) {
			const char *slave_name = devnode->cdata;
			child = ni_ifworker_array_find(&fsm->workers, type, slave_name);

			if (child == NULL) {
				ni_error("%s: <%s> element references unknown device %s",
						xml_node_location(devnode),
						devnode->name,
						slave_name);
				return NULL;
			}
		} else {
			ni_warn("%s: obsolete: using <device> node without namespace attribute "
				"- please use <device namespace=\"...\"> instead",
					xml_node_location(devnode));
			child = ni_ifworker_identify_device(fsm, devnode, type);
		}
		if (child == NULL) {
			ni_error("%s: <%s> element references unknown device",
					xml_node_location(devnode),
					devnode->name);
			return NULL;
		}

		if (child->name == NULL) {
			ni_warn("%s: <%s> element references device with no name",
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

static ni_bool_t
ni_ifworker_add_child(ni_ifworker_t *parent, ni_ifworker_t *child, xml_node_t *devnode, ni_bool_t shared)
{
	unsigned int i;

	/* Check if this child is already owned by the given parent. */
	for (i = 0; i < parent->children.count; ++i) {
		if (parent->children.data[i] == child)
			return TRUE;
	}

	if (child->exclusive_owner != NULL) {
		char *other_owner;

		other_owner = strdup(xml_node_location(child->exclusive_owner->config.node));
		ni_error("%s: subordinate interface already owned by %s",
				xml_node_location(devnode), other_owner);
		free(other_owner);
		return FALSE;
	}

	if (shared) {
		/* The reference allows sharing with other uses, e.g. VLANs. */
		child->shared_users++;
	} else {
		if (child->shared_users) {
			ni_error("%s: interface already in shared use by other interfaces",
					xml_node_location(devnode));
			return FALSE;
		}
		child->exclusive_owner = parent;
	}

	ni_ifworker_array_append(&parent->children, child);
	return TRUE;
}

/* Create an event wait object */
static void
ni_ifworker_add_callbacks(ni_fsm_transition_t *action, ni_objectmodel_callback_info_t *callback_list, const char *ifname)
{
	ni_objectmodel_callback_info_t **pos, *cb;

	if (ni_debug & NI_TRACE_DBUS) {
		ni_trace("%s: waiting for callbacks:", ifname);
		for (cb = callback_list; cb; cb = cb->next) {
			ni_trace("        %s event=%s",
				ni_uuid_print(&cb->uuid),
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
	ni_fsm_transition_t *action;

	if ((action = w->fsm.wait_for) == NULL)
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
	ni_fsm_transition_t *action;

	if ((action = w->fsm.wait_for) == NULL)
		return FALSE;
	for (cb = action->callbacks; cb != NULL; cb = cb->next) {
		if (ni_string_eq(cb->event, event_name))
			return TRUE;
	}
	return FALSE;
}

static void
ni_ifworker_update_client_info(ni_ifworker_t *w)
{
	ni_device_clientinfo_t client_info;

	ni_assert(w->object);
	memset(&client_info, 0, sizeof(client_info));
	client_info.state = (char *) ni_ifworker_state_name(w->fsm.state);
	client_info.config_origin = w->config.origin;
	client_info.config_uuid = w->config.uuid;
	ni_call_set_client_info(w->object, &client_info);

	ni_debug_application("%s: updating client-info structure: "
		"config_origin (%s) and uuid (%s)",
		w->name, w->config.origin, ni_uuid_print(&w->config.uuid));
}

static void
ni_ifworker_update_client_state(ni_ifworker_t *w)
{
	char *debug_str = NULL;
	ni_client_state_t client_state;

	ni_assert(w->object);
	client_state = w->client_state;
	ni_client_state_set_state(&client_state, w->fsm.state);
	ni_call_set_client_state(w->object, &client_state);

	ni_debug_application("%s: updating %s", w->name,
		ni_client_state_print(&client_state, &debug_str));

	if (debug_str)
		ni_string_free(&debug_str);
}

static inline ni_bool_t
ni_ifworker_empty_config(ni_ifworker_t *w)
{
	ni_assert(w);
	return ni_string_empty(w->config.origin);
}

static void
ni_ifworker_set_state(ni_ifworker_t *w, unsigned int new_state)
{
	unsigned int prev_state = w->fsm.state;

	if (prev_state != new_state) {
		w->fsm.state = new_state;

		ni_debug_application("%s: changed state %s -> %s%s",
				w->name,
				ni_ifworker_state_name(prev_state),
				ni_ifworker_state_name(new_state),
				w->fsm.wait_for == NULL? "" :
				(w->fsm.wait_for->next_state == w->fsm.state?
					", resuming activity" : ", still waiting for event"));

		if (w->fsm.wait_for && w->fsm.wait_for->next_state == new_state)
			w->fsm.wait_for = NULL;

		if (w->object && new_state != NI_FSM_STATE_DEVICE_DOWN && !w->readonly)
			ni_ifworker_update_client_info(w);

		if (w->target_state == new_state) {
			if (w->object && prev_state < new_state && !w->readonly)
				ni_ifworker_update_client_state(w);
			ni_ifworker_success(w);
		}
	}
}

static void
ni_ifworker_update_state(ni_ifworker_t *w, unsigned int min_state, unsigned int max_state)
{
	unsigned int new_state = w->fsm.state;

	if (new_state < min_state)
		new_state = min_state;
	if (max_state < new_state)
		new_state = max_state;

	if (w->fsm.state != new_state)
		ni_ifworker_set_state(w, new_state);

}

static void
ni_ifworker_refresh_client_info(ni_ifworker_t *w, ni_device_clientinfo_t *client_info)
{
	unsigned int state;

	ni_assert(w && client_info);
	if (ni_ifworker_state_from_name(client_info->state, &state))
		ni_ifworker_set_state(w, state);
	ni_ifworker_set_config_origin(w, client_info->config_origin);
	w->config.uuid = client_info->config_uuid;

	ni_debug_application("%s: refreshing client-info structure: "
		"config_origin (%s) and uuid (%s)",
		w->name, w->config.origin, ni_uuid_print(&w->config.uuid));
}

static void
ni_ifworker_refresh_client_state(ni_ifworker_t *w, ni_client_state_t *client_state)
{
	char *debug_str = NULL;

	ni_assert(w && client_state);
	w->client_state = *client_state;

	ni_debug_application("%s: refreshing %s", w->name,
		ni_client_state_print(client_state, &debug_str));
	if (debug_str)
		ni_string_free(&debug_str);
}

/*
 * Given the configuration for a device, generate a UUID that uniquely
 * identifies this configuration. We want to use this later to check
 * whether the configuration changed.
 *
 * We do this by hashing the XML configuration using a reasonably collision
 * free hash algorithm, and storing that in the UUID. If the algorithm's output
 * is less than the size of a UUID, the result is zero-padded; if it's bigger,
 * the digest is simply truncated.
 */
static inline int
__ni_ifworker_generate_config_uuid(const xml_node_t *config, ni_uuid_t *uuid)
{
	memset(uuid, 0, sizeof(*uuid));
	return xml_node_hash(config, uuid->octets, sizeof(uuid->octets));
}

static void
ni_ifworker_generate_uuid(ni_ifworker_t *w)
{
	if (w->config.node) {
		if (__ni_ifworker_generate_config_uuid(w->config.node, &w->config.uuid) < 0)
			ni_fatal("cannot generate uuid for %s config - hashing failed?!", w->name);
	} else {
		/* Generate a temporary uuid only */
		ni_uuid_generate(&w->config.uuid);
	}
	return;
}

/*
 * Reset an ifworker's control information to its defaults
 */
static void
ni_ifworker_control_set_defaults(ni_ifworker_t *w)
{
	ni_string_dup(&w->control.mode, "boot");
	ni_string_dup(&w->control.boot_stage, "default");
	w->control.link_timeout = NI_IFWORKER_INFINITE_TIMEOUT;
	w->control.link_required = FALSE;
}

/*
 * Update an ifworker's control information from XML
 */
static void
ni_ifworker_control_from_xml(ni_ifworker_t *w, xml_node_t *ctrlnode)
{
	xml_node_t *linknode, *np;

	if (ctrlnode == NULL)
		return;

	if ((np = xml_node_get_child(ctrlnode, "mode")) != NULL)
		ni_string_dup(&w->control.mode, np->cdata);
	if ((np = xml_node_get_child(ctrlnode, "boot-stage")) != NULL)
		ni_string_dup(&w->control.boot_stage, np->cdata);
	if ((linknode = xml_node_get_child(ctrlnode, "link-detection")) != NULL) {
		if ((np = xml_node_get_child(linknode, "timeout")) != NULL) {
			if (ni_string_eq(np->cdata, "infinite"))
				w->control.link_timeout = NI_IFWORKER_INFINITE_TIMEOUT;
			else
				ni_parse_uint(np->cdata, &w->control.link_timeout, 10);
		}
		if (xml_node_get_child(linknode, "require-link"))
			w->control.link_required = TRUE;
	}
}

/*
 * Set the configuration of an ifworker
 */
static void
ni_ifworker_set_config_origin(ni_ifworker_t *w, const char *config_origin)
{
	if (ni_string_eq(w->config.origin, config_origin))
		return;
	if (w->config.origin)
		ni_string_free(&w->config.origin);

	if (config_origin)
		ni_string_dup(&w->config.origin, config_origin);
	else
		w->config.origin = (char *) config_origin;
}

static ni_bool_t
ni_ifworker_set_config_client_state(ni_ifworker_t *w, xml_node_t *client_state_node)
{
	ni_client_state_t client_state;

	ni_assert(w && client_state_node);
	if (!ni_client_state_parse_xml(client_state_node, &client_state)) {
		ni_error("%s: unable to parse <client-state> node from %s file",
			w->name, w->config.origin);
		return FALSE;
	}

	if (ni_client_state_is_valid(&client_state)) {
		ni_warn("%s: full <client-state> node in %s file; "
		 "ignored all but <persistent>", w->name, w->config.origin);
	}

	/* only persistent value is taken into account - the rest is ignored */
	NI_CLIENT_STATE_SET_CONTROL_FLAG(w->client_state.persistent,
		TRUE, client_state.persistent);

	return TRUE;
}

void
ni_ifworker_set_config(ni_ifworker_t *w, xml_node_t *ifnode, const char *config_origin)
{
	xml_node_t *child;

	w->config.node = ifnode;

	if ((child = xml_node_get_child(ifnode, "control")))
		ni_ifworker_control_from_xml(w, child);

	ni_ifworker_generate_uuid(w);
	ni_ifworker_set_config_origin(w, config_origin);

	if ((child = xml_node_get_child(ifnode, "dependencies")))
		ni_ifworker_set_dependencies_xml(w, child);

	if ((child = xml_node_get_child(ifnode, NI_CLIENT_STATE_XML_STATE_NODE)))
		ni_ifworker_set_config_client_state(w, child);
}

/*
 * Check if the ifworker is still using the same config
 */
ni_bool_t
ni_ifworker_check_config(const ni_ifworker_t *w, const xml_node_t *config_node, const char *config_origin)
{
	ni_uuid_t uuid;

	if (__ni_ifworker_generate_config_uuid(config_node, &uuid) < 0)
		return FALSE;

	if (!ni_string_eq(w->config.origin, config_origin))
		return FALSE;

	if (memcmp(&w->config.uuid, &uuid, sizeof(uuid)) != 0)
		return FALSE;

	return TRUE;
}

/*
 * Given an XML document, build interface and modem objects, and policies from it.
 */
unsigned int
ni_fsm_workers_from_xml(ni_fsm_t *fsm, xml_document_t *doc)
{
	xml_node_t *root, *ifnode;
	unsigned int count = 0;

	root = xml_document_root(doc);
	for (ifnode = root->children; ifnode; ifnode = ifnode->next) {
		ni_ifworker_type_t type;
		const char *ifname = NULL;
		xml_node_t *node;
		ni_ifworker_t *w = NULL;

		if (ni_string_eq(ifnode->name, "policy")) {
			const char *name;

			name = xml_node_get_attr(ifnode, "name");
			ni_fsm_policy_new(fsm, name, ifnode);
			continue;
		}

		type = ni_ifworker_type_from_string(ifnode->name);
		if (type == NI_IFWORKER_TYPE_NONE) {
			ni_warn("%s: ignoring non-interface element <%s>",
					xml_node_location(ifnode),
					ifnode->name);
			continue;
		}

		if ((node = xml_node_get_child(ifnode, "identify")) != NULL) {
			ni_warn("%s: using obsolete <identify> element - please use <name namespace=\"...\"> instead", xml_node_location(ifnode));
			w = ni_ifworker_identify_device(fsm, node, type);
		} else 
		if ((node = xml_node_get_child(ifnode, "name")) != NULL) {
			const char *namespace;

			namespace = xml_node_get_attr(node, "namespace");
			if (namespace != NULL) {
				w = __ni_ifworker_identify_device(fsm, namespace, node, type);
			} else {
				ifname = node->cdata;
				if (ifname && (w = ni_fsm_ifworker_by_name(fsm, type, ifname)) == NULL)
					w = ni_ifworker_new(fsm, type, ifname);
			}
		}

		if (w == NULL) {
			ni_error("%s: ignoring unknown interface", xml_node_location(ifnode));
			continue;
		}

		ni_ifworker_set_config(w, ifnode, xml_node_get_location_filename(root));
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
ni_fsm_require_netif_resolve(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_require_t *req)
{
	xml_node_t *devnode = req->user_data;
	ni_ifworker_t *child_worker;

	if (req->user_data == NULL)
		return TRUE;

	if (!(child_worker = ni_ifworker_resolve_reference(fsm, devnode, NI_IFWORKER_TYPE_NETDEV)))
		return FALSE;

	ni_debug_application("%s: resolved reference to subordinate device %s", w->name, child_worker->name);
	if (!ni_ifworker_add_child(w, child_worker, devnode, FALSE))
		return FALSE;

	req->user_data = NULL;
	return TRUE;
}

ni_fsm_require_t *
ni_ifworker_netif_resolver_new(xml_node_t *node)
{
	ni_fsm_require_t *req;

	if (node == NULL)
		return NULL;

	req = ni_fsm_require_new(ni_fsm_require_netif_resolve, NULL);
	req->user_data = node;

	return req;
}

static ni_bool_t
ni_fsm_require_modem_resolve(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_require_t *req)
{
	xml_node_t *devnode = req->user_data;
	ni_ifworker_t *child_worker;

	if (req->user_data == NULL)
		return TRUE;

	if (!(child_worker = ni_ifworker_resolve_reference(fsm, devnode, NI_IFWORKER_TYPE_MODEM)))
		return FALSE;

	ni_debug_application("%s: resolved reference to subordinate device %s", w->name, child_worker->name);
	if (!ni_ifworker_add_child(w, child_worker, devnode, FALSE))
		return FALSE;

	req->user_data = NULL;
	return TRUE;
}

ni_fsm_require_t *
ni_ifworker_modem_resolver_new(xml_node_t *node)
{
	ni_fsm_require_t *req;

	if (node == NULL)
		return NULL;

	req = ni_fsm_require_new(ni_fsm_require_modem_resolve, NULL);
	req->user_data = node;

	return req;
}

/*
 * Handle link-detection check
 */
static void
__ni_ifworker_link_detection_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_ifworker_t *w = user_data;

	if (w->fsm.secondary_timer != timer) {
		ni_error("%s(%s) called with unexpected timer", __func__, w->name);
	} else {
		w->fsm.secondary_timer = NULL;
		if (w->control.link_required)
			ni_ifworker_fail(w, "link did not come up");
		else {
			ni_warn("%s: link did not come up, proceeding anyway", w->name);
			w->fsm.state = NI_FSM_STATE_LINK_UP;
		}
	}
}

static ni_bool_t
ni_fsm_require_detect_link(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_require_t *req)
{
	if (w->fsm.state == NI_FSM_STATE_LINK_UP)
		return TRUE;

	if (req->user_data != NULL) {
		req->user_data = NULL;
		if (w->control.link_timeout == 0) {
			if (w->control.link_required)
				return FALSE;

			/* timeout==0 and link not required means ignore link detection */
			w->fsm.state = NI_FSM_STATE_LINK_UP;
			return TRUE;
		}
		ni_ifworker_set_secondary_timeout(w, w->control.link_timeout, __ni_ifworker_link_detection_timeout);
	}

	return FALSE;
}

ni_fsm_require_t *
ni_ifworker_link_detection_new(void)
{
	ni_fsm_require_t *req;

	req = ni_fsm_require_new(ni_fsm_require_detect_link, NULL);
	req->user_data = (void *) 1;

	return req;
}

/*
 * Handle dependencies that check for a specific child state.
 */
struct ni_child_state_req_data {
	ni_ifworker_t *		child;
	char *			method;
	ni_uint_range_t		child_state;
};

static ni_bool_t
ni_ifworker_child_state_req_test(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_require_t *req)
{
	struct ni_child_state_req_data *data = (struct ni_child_state_req_data *) req->user_data;
	ni_ifworker_t *child = data->child;
	unsigned int wait_for_state;

	if (child->fsm.state < data->child_state.min) {
		wait_for_state = data->child_state.min;
	} else
	if (child->fsm.state > data->child_state.max) {
		wait_for_state = data->child_state.max;
	} else {
		/* Okay, child interface is ready */
		return TRUE;
	}

	if (child->failed) {
		/* Child is not in the expected state, but as it failed, it'll
		 * never get there. Fail the parent as well. */
		ni_ifworker_fail(w, "subordinate device %s failed", child->name);
		return FALSE;
	}

	ni_debug_application("%s: waiting for %s to reach state %s",
				w->name, child->name,
				ni_ifworker_state_name(wait_for_state));
	return FALSE;
}

static void
ni_ifworker_child_state_req_free(ni_fsm_require_t *req)
{
	struct ni_child_state_req_data *data = (struct ni_child_state_req_data *) req->user_data;

	if (data) {
		ni_string_free(&data->method);
		free(data);
	}
	req->user_data = NULL;
}

static void
ni_ifworker_add_child_state_req(ni_ifworker_t *w, const char *method, ni_ifworker_t *child_worker,
			unsigned int min_state, unsigned int max_state)
{
	struct ni_child_state_req_data *data;
	ni_fsm_require_t *req;

	data = calloc(1, sizeof(*data));
	data->child = child_worker;
	ni_string_dup(&data->method, method);
	data->child_state.min = min_state;
	data->child_state.max = max_state;

	req = ni_fsm_require_new(ni_ifworker_child_state_req_test, ni_ifworker_child_state_req_free);
	req->user_data = data;

	req->next = w->fsm.child_state_req_list;
	w->fsm.child_state_req_list = req;
}

static void
ni_ifworker_get_child_state_reqs_for_method(ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	ni_fsm_require_t **list, *req;

	for (list = &w->fsm.child_state_req_list; (req = *list) != NULL; ) {
		struct ni_child_state_req_data *data = req->user_data;
		unsigned int min_state = data->child_state.min;
		unsigned int max_state = data->child_state.max;
		ni_ifworker_t *child = data->child;

		if (!ni_string_eq(data->method, action->common.method_name)) {
			list = &req->next;
			continue;
		}

		ni_debug_application("%s: %s transition requires state of child %s to be in range [%s, %s]",
				w->name, data->method, child->name,
				ni_ifworker_state_name(min_state),
				ni_ifworker_state_name(max_state));
		if (min_state > child->target_range.min)
			child->target_range.min = min_state;
		if (max_state < child->target_range.max)
			child->target_range.max = max_state;

		/* Move this requirement to the action's req list */
		*list = req->next;
		ni_fsm_require_list_insert(&action->require.list, req);
	}
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
ni_ifworker_check_dependencies(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	ni_fsm_require_t *req, *next;

	if (!action->require.list)
		return TRUE;

	ni_debug_application("%s: checking requirements for %s -> %s transition",
			w->name,
			ni_ifworker_state_name(action->from_state),
			ni_ifworker_state_name(action->next_state));

	for (req = action->require.list; req; req = next) {
		next = req->next;
		if (!req->test_fn(fsm, w, req))
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
__ni_ifworker_identify_device(ni_fsm_t *fsm, const char *namespace, const xml_node_t *devnode, ni_ifworker_type_t type)
{
	ni_ifworker_t *found = NULL;
	char *object_path = NULL;

	/* Handle simple namespace first */
	if (namespace == NULL)
		return ni_fsm_ifworker_by_name(fsm, type, devnode->cdata);

	if (!strcmp(namespace, "alias"))
		return ni_ifworker_by_alias(fsm, devnode->cdata);

	if (type == NI_IFWORKER_TYPE_NETDEV && !strcmp(namespace, "ifindex")) {
		unsigned int ifindex;

		if (ni_parse_uint(devnode->cdata, &ifindex, 10) < 0) {
			ni_error("%s: cannot parse ifindex attribute", xml_node_location(devnode));
			return NULL;
		}
		return ni_ifworker_by_ifindex(fsm, ifindex);
	}

	switch (type) {
	case NI_IFWORKER_TYPE_NETDEV:
		object_path = ni_call_identify_device(namespace, devnode);
		break;

	case NI_IFWORKER_TYPE_MODEM:
#ifdef MODEM
		object_path = ni_call_identify_modem(namespace, devnode);
#endif
		break;

	default: ;
	}

	if (object_path)
		found = ni_fsm_ifworker_by_object_path(fsm, object_path);
	ni_string_free(&object_path);

	if (found)
		ni_debug_application("%s: identified device as %s (%s)",
				xml_node_location(devnode), found->name, found->object_path);
	return found;
}

static ni_ifworker_t *
ni_ifworker_identify_device(ni_fsm_t *fsm, const xml_node_t *devnode, ni_ifworker_type_t type)
{
	ni_ifworker_t *best = NULL;
	xml_node_t *attr;

	for (attr = devnode->children; attr; attr = attr->next) {
		ni_ifworker_t *found;
		xml_node_t *query = attr;

		/* If the attribute is of the form <foo:bar>, construct
		 *  <foo>
		 *    <bar>... original value ...</bar>
		 *  </foo>
		 */
		if (strchr(attr->name, ':') != NULL) {
			char *namespace = xstrdup(attr->name);
			char *key;

			key = strchr(namespace, ':');
			*key++ = '\0';

			query = xml_node_new(namespace, NULL);
			xml_node_new_element(key, query, attr->cdata);
			free(namespace);
		}

		found = __ni_ifworker_identify_device(fsm, query->name, query, type);
		if (query != attr)
			xml_node_free(query);
		if (found != NULL) {
			if (best && best != found) {
				ni_error("%s: ambiguous device reference", xml_node_location(devnode));
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

static ni_bool_t
ni_ifworker_merge_policy(ni_ifworker_t *w, ni_fsm_policy_t *policy)
{
	ni_warn("%s(%s, %s) TBD", __func__, w->name, ni_fsm_policy_name(policy));
	return TRUE;
}

static ni_bool_t
ni_ifworker_apply_policies(ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_bool_t use_default_policies = TRUE;
	ni_fsm_policy_t *policy;
	xml_node_t *config;

	if (w->config.node && (config = xml_node_get_child(w->config.node, "policies"))) {
		xml_node_t *child;

		for (child = config->children; child; child = child->next) {
			if (ni_string_eq(child->name, "default"))
				use_default_policies = TRUE;
			else
			if (ni_string_eq(child->name, "nodefault"))
				use_default_policies = FALSE;
			else
			if (ni_string_eq(child->name, "policy")) {
				if (!(policy = ni_fsm_policy_by_name(fsm, child->cdata))) {
					ni_error("%s: unknown policy \"%s\"", w->name, child->cdata);
					return FALSE;
				}
				ni_ifworker_merge_policy(w, policy);
			} else {
				ni_error("%s: ignoring unknown policy element <%s>",
						xml_node_location(child), child->name);
				continue;
			}
		}
	}

	w->use_default_policies = use_default_policies;
	return TRUE;
}

ni_ifworker_type_t
ni_ifworker_type_from_string(const char *s)
{
	if (ni_string_eq(s, "interface"))
		return NI_IFWORKER_TYPE_NETDEV;
	if (ni_string_eq(s, "modem"))
		return NI_IFWORKER_TYPE_MODEM;

	return NI_IFWORKER_TYPE_NONE;
}

const char *
ni_ifworker_type_to_string(ni_ifworker_type_t type)
{
	switch (type) {
	case NI_IFWORKER_TYPE_NETDEV:
		return "interface";
	case NI_IFWORKER_TYPE_MODEM:
		return "modem";
	default: ;
	}

	return NULL;
}

/*
 * Get all interfaces matching some user-specified criteria
 */
unsigned int
ni_fsm_get_matching_workers(ni_fsm_t *fsm, ni_ifmatcher_t *match, ni_ifworker_array_t *result)
{
	unsigned int i;

	if (ni_string_eq(match->name, "all")) {
		match->name = NULL;
	}

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (w->type != NI_IFWORKER_TYPE_NETDEV)
			continue;

		if (match->name && !ni_string_eq(match->name, w->name))
			continue;

		/* skipping ifworkers without xml configuration */
		if (!w->config.node && match->require_config) {
			ni_debug_application("skipping %s interface: "
				"no configuration provided", w->name);
			continue;
		}
		/* skipping ifworkers of interfaces not configured in the past */
		if (ni_string_empty(w->config.origin) && match->require_configured) {
			ni_debug_application("skipping %s interface: "
				"not configured yet", w->name);
			continue;
		}
		/* skipping ifworkers of interfaces in the persistent mode */
		if (w->client_state.persistent && !match->allow_persistent) {
			ni_debug_application("skipping %s interface: "
				"persistent mode is on", w->name);
			continue;
		}

		if (w->exclusive_owner)
			continue;

		if (match->mode && !ni_string_eq(match->mode, w->control.mode))
			continue;

		if (match->boot_stage && !ni_string_eq(match->boot_stage, w->control.boot_stage))
			continue;

		if (match->skip_origin) {
			ni_netdev_t *dev;

			if ((dev = w->device) == 0
			 || dev->client_info == NULL
			 || !ni_string_startswith(dev->client_info->config_origin, match->skip_origin))
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
		ni_ifworker_t *child = w->children.data[i];

		ret = ni_ifworker_check_loops(child, counter);
	}

	return ret;
}

static ni_bool_t
ni_ifworkers_check_loops(ni_fsm_t *fsm, ni_ifworker_array_t *array)
{
	unsigned int i, num_edges;

	for (i = num_edges = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		num_edges += w->children.count;
	}

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];
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
		ni_ifworker_t *child = w->children.data[i];

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

/*
 * After we've picked the list of matching interfaces, set their target state.
 * We need to do this recursively - for instance, bringing up a VLAN interface
 * requires that the underlying ethernet device at least has brought up the link.
 */
unsigned int
ni_fsm_mark_matching_workers(ni_fsm_t *fsm, ni_ifworker_array_t *marked, const ni_ifmarker_t *marker)
{
	unsigned int i, count = 0;

	ni_ifworkers_check_loops(fsm, marked);

	/* Mark all our primary devices with the requested marker values */
	for (i = 0; i < marked->count; ++i) {
		ni_ifworker_t *w = marked->data[i];
		ni_client_state_t *cs = &w->client_state;

		w->target_range = marker->target_range;
		NI_CLIENT_STATE_SET_CONTROL_FLAG(cs->persistent,
			marker->persistent == TRUE, TRUE);
	}

	count = ni_fsm_start_matching_workers(fsm, marked);
	ni_debug_application("marked %u interfaces", count);
	return count;
}

unsigned int
ni_fsm_start_matching_workers(ni_fsm_t *fsm, ni_ifworker_array_t *marked)
{
	unsigned int i, count = 0;

	/* Collect all workers in the device graph, and sort them
	 * by increasing depth.
	 */
	ni_ifworkers_flatten(marked);

	for (i = 0; i < marked->count; ++i) {
		ni_ifworker_t *w = marked->data[i];
		int rv;

		if (w->failed)
			continue;

		if ((rv = ni_ifworker_start(fsm, w, fsm->worker_timeout)) < 0)
			return rv;

		if (w->target_state != NI_FSM_STATE_NONE)
			count++;
	}
	return count;
}

void
ni_fsm_reset_matching_workers(ni_fsm_t *fsm, ni_ifworker_array_t *marked,
			const ni_uint_range_t *target_range, ni_bool_t hard)
{
	unsigned int i;

	for (i = 0; i < marked->count; ++i) {
		ni_ifworker_t *w = marked->data[i];

		if ((w->done || w->failed) &&
		    (w->target_range.max == NI_FSM_STATE_DEVICE_DOWN)) {
			ni_fsm_destroy_worker(fsm, w);
			if (ni_ifworker_array_remove(marked, w))
				--i;
			continue;
		}

		if (hard) {
			ni_ifworker_reset(w);
			if (target_range) {
				w->target_range = *target_range;
			}
			continue;
		}

		w->done = FALSE;
		w->failed = FALSE;
		w->kickstarted = FALSE;

		w->target_state = NI_FSM_STATE_NONE;
		if (target_range) {
			w->target_range = *target_range;
		} else {
			w->target_range.min = NI_FSM_STATE_NONE;
			w->target_range.max = __NI_FSM_STATE_MAX;
		}

		/* When detaching children, clear their shared/exclusive ownership info */
		if (w->children.count != 0) {
			unsigned int i;

			for (i = 0; i < w->children.count; ++i) {
				ni_ifworker_t *child_worker = w->children.data[i];

				if (child_worker->exclusive_owner == w) {
					child_worker->exclusive_owner = NULL;
				} else {
					ni_assert(child_worker->exclusive_owner == NULL);
					ni_assert(child_worker->shared_users);
					child_worker->shared_users -= 1;
				}
			}
		}
		ni_ifworker_array_destroy(&w->children);

		if (w->fsm.action_table) {
			ni_fsm_transition_t *action;

			for (action = w->fsm.action_table; action->next_state; action++)
				ni_fsm_require_list_destroy(&action->require.list);
			free(w->fsm.action_table);
			w->fsm.action_table = NULL;
		}

		ni_ifworker_cancel_timeout(w);

		ni_fsm_require_list_destroy(&w->fsm.child_state_req_list);

		memset(&w->fsm, 0, sizeof(w->fsm));
		memset(&w->device_api, 0, sizeof(w->device_api));
	}
}

ni_bool_t
ni_fsm_destroy_worker(ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_ifworker_get(w);

	ni_debug_application("%s(%s)", __func__, w->name);
	if (!ni_ifworker_array_remove(&fsm->workers, w)) {
		ni_ifworker_release(w);
		return FALSE;
	}

	if (w->object) {
		ni_dbus_object_free(w->object);
		w->object = NULL;
	}

	if (ni_ifworker_active(w))
		ni_ifworker_fail(w, "device was deleted");
	w->dead = TRUE;

	ni_ifworker_release(w);
	return TRUE;
}

int
ni_ifworker_start(ni_fsm_t *fsm, ni_ifworker_t *w, unsigned long timeout)
{
	unsigned int min_state = w->target_range.min;
	unsigned int max_state = w->target_range.max;
	unsigned int cur_state = w->fsm.state;
	unsigned int j;
	int rv;

	if (min_state > max_state) {
		ni_error("%s: conflicting target states: min=%s max=%s",
				w->name,
				ni_ifworker_state_name(min_state),
				ni_ifworker_state_name(max_state));
		return -1;
	}
	ni_debug_application("%s: target state min=%s max=%s",
				w->name,
				ni_ifworker_state_name(min_state),
				ni_ifworker_state_name(max_state));

	if (max_state == __NI_FSM_STATE_MAX) {
		if (min_state == NI_FSM_STATE_NONE)
			return 0;

		/* No upper bound; bring it up to min level */
		rv = ni_fsm_schedule_init(fsm, w, NI_FSM_STATE_DEVICE_DOWN, min_state);
		if (rv < 0)
			return rv;
	} else if (min_state == NI_FSM_STATE_NONE) {
		/* No lower bound; bring it down to max level */
		rv = ni_fsm_schedule_init(fsm, w, NI_FSM_STATE_ADDRCONF_UP, max_state);
		if (rv < 0)
			return rv;
	} else {
		ni_warn("%s: not handled yet: bringing device into state range [%s, %s]",
				w->name,
				ni_ifworker_state_name(min_state),
				ni_ifworker_state_name(max_state));
		return -NI_ERROR_GENERAL_FAILURE;
	}

	for (j = 0; j < w->children.count; ++j) {
		ni_ifworker_t *child = w->children.data[j];

		if (w->control.link_required)
			child->control.link_required = TRUE;
		if (w->control.link_timeout < child->control.link_timeout)
			child->control.link_timeout = w->control.link_timeout;
	}

	ni_debug_application("%s: current state=%s target state=%s",
				w->name,
				ni_ifworker_state_name(w->fsm.state),
				ni_ifworker_state_name(w->target_state));

	if (w->target_state != NI_FSM_STATE_NONE) {
		ni_client_state_t *cs = &w->client_state;

		if (!ni_client_state_is_valid(cs)) {
			ni_client_state_set_state(cs, cur_state);
			NI_CLIENT_STATE_SET_CONTROL_FLAG(cs->persistent,
				cur_state >= NI_FSM_STATE_LINK_UP, TRUE);
		}
		ni_ifworker_set_timeout(w, timeout);
	}

	/* For each of the DBus calls we will execute on this device,
	 * check whether there are constraints on child devices that
	 * require the subordinate device to have a certain
	 * minimum/maximum state.
	 */
	for (j = 0; j < w->fsm.action_table[j].next_state; ++j) {
		ni_ifworker_get_child_state_reqs_for_method(w, &w->fsm.action_table[j]);
	}

	return 0;
}

/*
 * Bind a device API for an interface that doesn't exist yet.
 * We do this by looking at all factory services and finding one for
 * which our interface document provides a configuration.
 *
 * By convention, factory services have a newDevice method, which
 * takes a string (the requested device name, if any), and a configuration
 * dict. The xml schema specifies which element of an <interface>
 * description should be used for this argument.
 *
 * For instance, the newDevice method of the VLAN.Factory service
 * specifies that its configuration be taken from the <vlan> element.
 */
static int
ni_ifworker_bind_device_factory_api(ni_ifworker_t *w)
{
	const ni_dbus_method_t *method;
	const ni_dbus_service_t *list_services[128];
	const char *link_type;
	unsigned int i, count;
	int rv;

	if (w->config.node == NULL || w->device_api.factory_service)
		return 0;

	/* Allow the configuration to explicitly specify a link-type. */
	link_type = xml_node_get_attr(w->config.node, "link-type");
	if (link_type != NULL) {
		const ni_dbus_service_t *service, *factory_service;
		const ni_dbus_class_t *class;
		char classname[128];

		snprintf(classname, sizeof(classname), "netif-%s", link_type);
		if (!(class = ni_objectmodel_get_class(classname))) {
			ni_error("%s: unknown device class \"%s\" in link-type attribute",
					xml_node_location(w->config.node), link_type);
			ni_ifworker_fail(w, "cannot create interface: xml document error");
			return -NI_ERROR_DOCUMENT_ERROR;
		}

		/* Look up the DBus service for this class, and then the factory
		 * service for that */
		if (!(service = ni_objectmodel_service_by_class(class))
		 || !(factory_service = ni_objectmodel_factory_service(service))) {
			ni_error("%s: unsupported device class \"%s\" in link-type attribute",
					xml_node_location(w->config.node), link_type);
			ni_ifworker_fail(w, "cannot create interface: device class not supported");
			return -NI_ERROR_DEVICE_NOT_COMPATIBLE;
		}

		if ((rv = ni_ifworker_bind_device_apis(w, service)) < 0)
			return rv;

		list_services[0] = factory_service;
		count = 1;
	} else {
		const ni_dbus_class_t *netif_list_class;

		/* We try to locate the factory service by looping over all services compatible
		 * with netif-list */
		netif_list_class = ni_objectmodel_get_class(NI_OBJECTMODEL_NETIF_LIST_CLASS);
		count = ni_objectmodel_compatible_services_for_class(netif_list_class, list_services, 128);
	}

	for (i = 0; i < count; ++i) {
		const ni_dbus_service_t *service = list_services[i];
		xml_node_t *config = NULL;

		method = ni_dbus_service_get_method(service, "newDevice");
		if (method == NULL)
			continue;

		if ((rv = ni_dbus_xml_map_method_argument(method, 1, w->config.node, &config, NULL)) < 0) {
			ni_ifworker_fail(w, "cannot create interface: xml document error");
			return -NI_ERROR_DOCUMENT_ERROR;
		}

		if (config != NULL) {
			if (w->device_api.factory_service != NULL) {
				ni_ifworker_fail(w, "ambiguous device configuration - found services %s and %s. "
						    "Please use link-type attribute to disambiguate.",
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
ni_ifworker_bind_device_apis(ni_ifworker_t *w, const ni_dbus_service_t *service)
{
	const ni_dbus_method_t *method;
	xml_node_t *config;

	if (w->device_api.service)
		return 1;

	if (w->config.node == NULL)
		return 0;

	if (w->object == NULL)
		return 0;

	/* FIXME: look up the device service based on the object class */

	if (service == NULL)
		service = ni_dbus_object_get_service_for_method(w->object, "changeDevice");
	if (service == NULL)
		return 0;

	method = ni_dbus_service_get_method(service, "changeDevice");
	if (method && ni_dbus_xml_map_method_argument(method, 0, w->config.node, &config, NULL) < 0)
		return -NI_ERROR_DOCUMENT_ERROR;

	w->device_api.service = service;
	w->device_api.method = method;
	w->device_api.config = config;
	return 1;
}

/*
 * Callback data used for callbacks from XML validation
 */
struct ni_ifworker_xml_validation_user_data {
	ni_fsm_t *	fsm;
	ni_ifworker_t *	worker;
};
static dbus_bool_t	ni_ifworker_netif_resolve_cb(xml_node_t *, const ni_xs_type_t *, const xml_node_t *, void *);
static int		ni_ifworker_prompt_cb(xml_node_t *, const ni_xs_type_t *, const xml_node_t *, void *);
static int		ni_ifworker_prompt_later_cb(xml_node_t *, const ni_xs_type_t *, const xml_node_t *, void *);

int
ni_ifworker_bind_early(ni_ifworker_t *w, ni_fsm_t *fsm, ni_bool_t prompt_now)
{
	struct ni_ifworker_xml_validation_user_data user_data = {
		.fsm = fsm, .worker = w,
	};
	ni_dbus_xml_validate_context_t context = {
		.metadata_callback = ni_ifworker_netif_resolve_cb,
		.prompt_callback = ni_ifworker_prompt_later_cb,
		.user_data = &user_data,
	};
	int rv;

	if (prompt_now)
		context.prompt_callback = ni_ifworker_prompt_cb;

	/* First, check for factory interface */
	if ((rv = ni_ifworker_bind_device_factory_api(w)) < 0)
		return rv;

	if (w->device_api.factory_method && w->device_api.config) {
		/* The XML validation code will do a pass over the part of our XML
		 * document that's used for the deviceNew() call, and call us for
		 * every bit of metadata it finds.
		 * This includes elements marked by <meta:netif-reference/>
		 * in the schema.
		 */
		if (!ni_dbus_xml_validate_argument(w->device_api.factory_method, 1, w->device_api.config, &context))
			return -NI_ERROR_DOCUMENT_ERROR;
		return 0;
	}

	if ((rv = ni_ifworker_bind_device_apis(w, NULL)) < 0)
		return rv;

	if (w->device_api.method && w->device_api.config) {
		if (!ni_dbus_xml_validate_argument(w->device_api.method, 0, w->device_api.config, &context))
			return -NI_ERROR_DOCUMENT_ERROR;
		return 0;
	}

	/* For now, just apply policies here */
	ni_ifworker_apply_policies(fsm, w);
	return 0;
}

/*
 * Build the hierarchy of devices.
 *
 * We need to ensure that we bring up devices in the proper order; e.g. an
 * eth interface needs to come up before any of the VLANs that reference
 * it.
 */
static void		__ni_ifworker_print_tree(const char *arrow, const ni_ifworker_t *, const char *);

int
ni_fsm_build_hierarchy(ni_fsm_t *fsm)
{
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];
		int rv;

		/* A worker without an ifnode is one that we discovered in the
		 * system, but which we've not been asked to configure. */
		if (!w->config.node) {
			w->use_default_policies = TRUE;
			continue;
		}

		if ((rv = ni_ifworker_bind_early(w, fsm, FALSE)) < 0)
			return rv;
	}

	if (ni_debug & NI_TRACE_APPLICATION) {
		for (i = 0; i < fsm->workers.count; ++i) {
			ni_ifworker_t *w = fsm->workers.data[i];

			if (!w->shared_users && !w->exclusive_owner)
				__ni_ifworker_print_tree("   +-> ", w, "   |   ");
		}
	}
	return 0;
}

dbus_bool_t
ni_ifworker_netif_resolve_cb(xml_node_t *node, const ni_xs_type_t *type, const xml_node_t *metadata, void *user_data)
{
	struct ni_ifworker_xml_validation_user_data *closure = user_data;
	ni_ifworker_t *w = closure->worker;
	ni_ifworker_t *child_worker = NULL;
	xml_node_t *mchild;

	for (mchild = metadata->children; mchild; mchild = mchild->next) {
		const char *attr;

		if (ni_string_eq(mchild->name, "netif-reference")) {
			ni_bool_t shared = FALSE;

			if (child_worker) {
				ni_error("%s: duplicate/conflicting references", xml_node_location(node));
				return FALSE;
			}
			if (!(child_worker = ni_ifworker_resolve_reference(closure->fsm, node, NI_IFWORKER_TYPE_NETDEV)))
				return FALSE;

			if ((attr = xml_node_get_attr(mchild, "shared")) != NULL)
				shared = ni_string_eq(attr, "true");

			ni_debug_application("%s: resolved reference to subordinate device %s", w->name, child_worker->name);
			if (!ni_ifworker_add_child(w, child_worker, node, shared))
				return FALSE;
		} else
		if (ni_string_eq(mchild->name, "modem-reference")) {
			ni_bool_t shared = FALSE;

			if (child_worker) {
				ni_error("%s: duplicate/conflicting references", xml_node_location(node));
				return FALSE;
			}
			if (!(child_worker = ni_ifworker_resolve_reference(closure->fsm, node, NI_IFWORKER_TYPE_MODEM)))
				return FALSE;

			if ((attr = xml_node_get_attr(mchild, "shared")) != NULL)
				shared = ni_string_eq(attr, "true");

			ni_debug_application("%s: resolved reference to subordinate device %s", w->name, child_worker->name);
			if (!ni_ifworker_add_child(w, child_worker, node, shared))
				return FALSE;
		} else
		if (ni_string_eq(mchild->name, "require")) {
			unsigned int min_state = NI_FSM_STATE_NONE, max_state = __NI_FSM_STATE_MAX;
			const char *method;

			if ((attr = xml_node_get_attr(mchild, "check")) == NULL
			 || !ni_string_eq(attr, "netif-child-state"))
				continue;

			if ((attr = xml_node_get_attr(mchild, "min-state")) != NULL) {
				if (!ni_ifworker_state_from_name(attr, &min_state)) {
					ni_error("%s: invalid state name min-state=\"%s\"",
							xml_node_location(mchild), attr);
					return FALSE;
				}
			}

			if ((attr = xml_node_get_attr(mchild, "max-state")) != NULL) {
				if (!ni_ifworker_state_from_name(attr, &max_state)) {
					ni_error("%s: invalid state name max-state=\"%s\"",
							xml_node_location(mchild), attr);
					return FALSE;
				}
			}

			if ((method = xml_node_get_attr(mchild, "op")) == NULL) {
				ni_error("%s: missing op attribute", xml_node_location(mchild));
				return FALSE;
			}

			if (child_worker == NULL) {
				ni_error("%s: <meta:require check=netif-child-state> without netif-reference",
						xml_node_location(mchild));
				return FALSE;
			}

			ni_ifworker_add_child_state_req(w, method, child_worker, min_state, max_state);
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
		ni_debug_application("%s%s\n", arrow, w->name);
	} else {
		char buffer[128];
		unsigned int i;

		ni_debug_application("%s%-10s", arrow, w->name);

		snprintf(buffer, sizeof(buffer), "%s%10s  |   ", branches, "");

		arrow = " +--> ";
		for (i = 0; i < w->children.count; ++i) {
			ni_ifworker_t *child = w->children.data[i];

			if (i != 0) {
				ni_debug_application("%s%10s", branches, "");
				if (i == w->children.count - 1)
					arrow = " \\--> ";
			}
			__ni_ifworker_print_tree(arrow, child, buffer);
		}
	}
}

void
ni_fsm_refresh_state(ni_fsm_t *fsm)
{
	ni_ifworker_t *w;
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		/* Always clear the object - we don't know if it's still there
		 * after we've called ni_dbus_object_refresh_children() */
		w->object = NULL;

		/* Set ifworkers to readonly if fsm is readonly */
		w->readonly = fsm->readonly;
	}

	__ni_ifworker_refresh_netdevs(fsm);
#ifdef MODEM
	__ni_ifworker_refresh_modems(fsm);
#endif

	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if (w->object == NULL) {
			ni_debug_application("device %s (%s) disappeared", w->name, w->object_path);
			ni_ifworker_update_state(w, NI_FSM_STATE_NONE, NI_FSM_STATE_DEVICE_DOWN);

			if (w->device) {
				ni_netdev_put(w->device);
				w->device = NULL;
			}
			if (w->modem) {
				ni_modem_release(w->modem);
				w->modem = NULL;
			}
			if (ni_ifworker_active(w) && !w->device_api.factory_method)
				ni_ifworker_fail(w, "device was deleted");
			w->dead = TRUE;
		} else if (!w->done)
			ni_ifworker_update_state(w, NI_FSM_STATE_DEVICE_EXISTS, __NI_FSM_STATE_MAX);
	}
}

static void
__ni_ifworker_refresh_netdevs(ni_fsm_t *fsm)
{
	static ni_dbus_object_t *list_object = NULL;
	ni_dbus_object_t *object;

	if (!list_object && !(list_object = ni_call_get_netif_list_object()))
		ni_fatal("unable to get server's interface list");

	/* Call ObjectManager.GetManagedObjects to get list of objects and their properties */
	if (!ni_dbus_object_refresh_children(list_object))
		ni_fatal("Couldn't refresh list of active network interfaces");

	for (object = list_object->children; object; object = object->next)
		ni_fsm_recv_new_netif(fsm, object, FALSE);
}

ni_ifworker_t *
ni_fsm_recv_new_netif(ni_fsm_t *fsm, ni_dbus_object_t *object, ni_bool_t refresh)
{
	ni_netdev_t *dev = ni_objectmodel_unwrap_netif(object, NULL);
	ni_ifworker_t *found = NULL;

	if ((dev == NULL || dev->name == NULL) && refresh) {
		if (!ni_dbus_object_refresh_children(object)) {
			ni_error("%s: failed to refresh netdev object", object->path);
			return NULL;
		}

		dev = ni_objectmodel_unwrap_netif(object, NULL);
	}

	if (dev == NULL || dev->name == NULL) {
		ni_error("%s: refresh failed to set up netdev object", object->path);
		return NULL;
	}

	found = ni_fsm_ifworker_by_netdev(fsm, dev);
	if (!found)
		found = ni_fsm_ifworker_by_object_path(fsm, object->path);
	if (!found) {
		ni_debug_application("received new device %s (%s)", dev->name, object->path);
		found = ni_ifworker_new(fsm, NI_IFWORKER_TYPE_NETDEV, dev->name);
		found->readonly = fsm->readonly;
		if (dev->client_info)
			ni_ifworker_refresh_client_info(found, dev->client_info);
		if (dev->client_state)
			ni_ifworker_refresh_client_state(found, dev->client_state);
	}

	if (!found->object_path)
		ni_string_dup(&found->object_path, object->path);
	if (!found->device)
		found->device = ni_netdev_get(dev);
	found->ifindex = dev->link.ifindex;
	found->object = object;

	/* Don't touch devices we're done with */

	if (!found->done) {
		if (ni_netdev_link_is_up(dev))
			ni_ifworker_update_state(found, NI_FSM_STATE_LINK_UP, __NI_FSM_STATE_MAX);
		else
			ni_ifworker_update_state(found, 0, NI_FSM_STATE_LINK_UP - 1);
	}

	return found;
}

ni_ifworker_t *
ni_fsm_recv_new_netif_path(ni_fsm_t *fsm, const char *path)
{
	static ni_dbus_object_t *list_object = NULL;
	ni_dbus_object_t *object;

	if (!list_object && !(list_object = ni_call_get_netif_list_object()))
		ni_fatal("unable to get server's netdev list");

	object = ni_dbus_object_create(list_object, path, NULL, NULL);
	return ni_fsm_recv_new_netif(fsm, object, TRUE);
}

#ifdef MODEM
static void
__ni_ifworker_refresh_modems(ni_fsm_t *fsm)
{
	static ni_dbus_object_t *list_object = NULL;
	ni_dbus_object_t *object;

	if (!list_object && !(list_object = ni_call_get_modem_list_object()))
		ni_fatal("unable to get server's modem list");

	/* Call ObjectManager.GetManagedObjects to get list of objects and their properties */
	if (!ni_dbus_object_refresh_children(list_object))
		ni_fatal("Couldn't refresh list of available modems");

	for (object = list_object->children; object; object = object->next) {
		ni_fsm_recv_new_modem(fsm, object, FALSE);
	}
}
#endif

ni_ifworker_t *
ni_fsm_recv_new_modem(ni_fsm_t *fsm, ni_dbus_object_t *object, ni_bool_t refresh)
{
	ni_ifworker_t *found = NULL;
	ni_modem_t *modem;

	modem = ni_objectmodel_unwrap_modem(object, NULL);
	if ((modem == NULL || modem->device == NULL) && refresh) {
		if (!ni_dbus_object_refresh_children(object)) {
			ni_error("%s: failed to refresh modem object", object->path);
			return NULL;
		}

		modem = ni_objectmodel_unwrap_modem(object, NULL);
	}

	if (modem == NULL || modem->device == NULL) {
		ni_error("%s: refresh failed to set up modem object", object->path);
		return NULL;
	}


	found = ni_ifworker_by_modem(fsm, modem);
	if (!found)
		found = ni_fsm_ifworker_by_object_path(fsm, object->path);
	if (!found) {
		ni_debug_application("received new modem %s (%s)", modem->device, object->path);
		found = ni_ifworker_new(fsm, NI_IFWORKER_TYPE_MODEM, modem->device);
	}

	if (!found->object_path)
		ni_string_dup(&found->object_path, object->path);
	if (!found->modem)
		found->modem = ni_modem_hold(modem);
	found->object = object;

	/* Don't touch devices we're done with */
	if (!found->done)
		ni_ifworker_update_state(found, NI_FSM_STATE_DEVICE_EXISTS, __NI_FSM_STATE_MAX);

	return found;
}

ni_ifworker_t *
ni_fsm_recv_new_modem_path(ni_fsm_t *fsm, const char *path)
{
	static ni_dbus_object_t *list_object = NULL;
	ni_dbus_object_t *object;

	if (!list_object && !(list_object = ni_call_get_modem_list_object()))
		ni_fatal("unable to get server's modem list");

	object = ni_dbus_object_create(list_object, path, NULL, NULL);
	return ni_fsm_recv_new_modem(fsm, object, TRUE);
}

static inline ni_bool_t
ni_ifworker_complete(const ni_ifworker_t *w)
{
	return w->failed || w->done || w->target_state == NI_FSM_STATE_NONE || w->target_state == w->fsm.state;
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
		ni_fsm_prompt_t prompt;
		char *node_spec, *prompt_type = NULL, *ident = NULL;
		xml_node_t *authnode;
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
		memset(&prompt, 0, sizeof(prompt));
		if (!(node_spec = strtok(detail, "|")))
			goto out;
		if ((prompt_type = strtok(NULL, "|")) != NULL)
			ident = strtok(NULL, "|");

		prompt.id = ident;
		prompt.type = NI_FSM_PROMPT_OTHER;
		if (prompt_type != NULL) {
			if (!strcasecmp(prompt_type, "password"))
				prompt.type = NI_FSM_PROMPT_PASSWORD;
			else if (!strcasecmp(prompt_type, "user"))
				prompt.type = NI_FSM_PROMPT_USERNAME;
		}

		authnode = ni_call_error_context_get_node(ctx, node_spec);
		if (ni_fsm_user_prompt_fn(&prompt, authnode, ni_fsm_user_prompt_data) == 0)
			errcode = -NI_ERROR_RETRY_OPERATION;
	}

out:
	ni_string_free(&detail);
	return errcode;
}

/*
 * Process a <meta:require> element
 */
static int
ni_ifworker_require_xml(ni_fsm_transition_t *action, const xml_node_t *req_node, xml_node_t *element, xml_node_t *config)
{
	const char *attr, *check;
	ni_fsm_require_t *require, **pos;
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
		if (!ni_ifworker_requirement_build(check, element, pos)) {
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
			require = ni_ifworker_requirement_build(check, expanded[j], pos);
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
	ni_fsm_transition_t *action = user_data;

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
	ni_fsm_prompt_t prompt;
	const char *type;

	memset(&prompt, 0, sizeof(prompt));

	prompt.string = xml_node_get_attr(metadata, "prompt");
	prompt.id = xml_node_get_attr(metadata, "id");

	if ((type = xml_node_get_attr(metadata, "type")) == NULL) {
		ni_error("%s: missing type attribute in %s element", xml_node_location(metadata), metadata->name);
		return -1;
	}
	if (!strcasecmp(type, "user"))
		prompt.type = NI_FSM_PROMPT_USERNAME;
	else if (!strcasecmp(type, "password"))
		prompt.type = NI_FSM_PROMPT_PASSWORD;
	else
		prompt.type = NI_FSM_PROMPT_OTHER;

	return ni_fsm_user_prompt_fn(&prompt, node, ni_fsm_user_prompt_data);
}

/*
 * Parse any <require> tags contained in the per-method metadata
 */
static int
ni_ifworker_map_method_requires(ni_ifworker_t *w, ni_fsm_transition_t *action,
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

		if ((rv = ni_ifworker_require_xml(action, req_nodes[i], NULL, w->config.node)) < 0)
			return rv;
	}

	return 0;
}

/*
 * Debugging: print the binding info
 */
static void
ni_ifworker_print_binding(ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	struct ni_fsm_transition_binding *bind;
	unsigned int i;

	for (i = 0, bind = action->binding; i < action->num_bindings; ++i, ++bind) {
		if (bind->method == NULL) {
			ni_trace("  %-40s %-14s   not supported by service",
					bind->service->name,
					action->common.method_name);
		} else
		if (bind->config == NULL) {
			ni_trace("  %-40s %-14s   no config in interface document%s",
					bind->service->name,
					bind->method->name,
					bind->skip_call? "; skipping call" : "");
		} else {
			ni_trace("  %-40s %-14s   mapped to <%s> @%s",
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
ni_ifworker_do_common_bind(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
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
			const ni_dbus_service_t *services[NI_IFTRANSITION_BINDINGS_MAX];
			unsigned int count;

			count = ni_dbus_object_get_all_services_for_method(w->object,
						action->common.method_name,
						services, NI_IFTRANSITION_BINDINGS_MAX);

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
		struct ni_fsm_transition_binding *bind = &action->binding[i];

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
		if (ni_dbus_xml_map_method_argument(bind->method, 0, w->config.node, &bind->config, &bind->skip_call) < 0)
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
	return -NI_ERROR_DOCUMENT_ERROR;
}

static int
ni_ifworker_do_common(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	unsigned int i, count = 0;
	int rv;

	/* Initially, enable waiting for this action */
	w->fsm.wait_for = action;

	for (i = 0; i < action->num_bindings; ++i) {
		struct ni_fsm_transition_binding *bind = &action->binding[i];
		ni_objectmodel_callback_info_t *callback_list = NULL;

		if (bind->method == NULL)
			continue;

		if (bind->skip_call)
			continue;

		ni_debug_application("%s: calling %s.%s()",
				w->name, bind->service->name, bind->method->name);

		rv = ni_call_common_xml(w->object, bind->service, bind->method, bind->config,
				&callback_list, ni_ifworker_error_handler);
		if (rv < 0) {
			if (action->common.may_fail) {
				ni_error("[ignored] %s: call to %s.%s() failed: %s", w->name,
						bind->service->name, bind->method->name, ni_strerror(rv));
				ni_ifworker_set_state(w, action->next_state);
				return 0;
			}
			ni_ifworker_fail(w, "call to %s.%s() failed: %s",
					bind->service->name, bind->method->name, ni_strerror(rv));
			return rv;
		}

		if (callback_list) {
			ni_debug_application("%s: adding callback for %s.%s()",
					w->name, bind->service->name, bind->method->name);
			ni_ifworker_add_callbacks(action, callback_list, w->name);
			count++;
		}
	}

	/* Reset wait_for this action if there are no callbacks */
	if (count == 0)
		w->fsm.wait_for = NULL;

	if (w->fsm.wait_for != NULL)
		return 0;

	ni_ifworker_set_state(w, action->next_state);
	return 0;
}

/*
 * Finite state machine - create the device if it does not exist
 * Typically, this will create just the bare interface, like a bridge
 * or bond device, without actually configuring it (such as adding
 * bridge ports).
 */
static int
ni_ifworker_bind_device_factory(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	struct ni_fsm_transition_binding *bind;
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
ni_ifworker_call_device_factory(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	if (!ni_ifworker_device_bound(w)) {
		struct ni_fsm_transition_binding *bind;
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
		w->object = ni_dbus_object_create(fsm->client_root_object, relative_path,
					NULL,
					NULL);

		ni_string_free(&object_path);

		if (!ni_dbus_object_refresh_children(w->object)) {
			ni_ifworker_fail(w, "unable to refresh new device");
			return -1;
		}

		ni_fsm_schedule_bind_methods(fsm, w);
	}

	ni_ifworker_set_state(w, action->next_state);
	return 0;
}

static inline ni_bool_t
ni_ifworker_can_delete(const ni_ifworker_t *w)
{
	return (!w->client_state.persistent &&
		ni_dbus_object_get_service_for_method(w->object, "deleteDevice"));
}

/*
 * Finite state machine
 */
#define __TRANSITION_UP_TO(__state)		.from_state = __state - 1, .next_state = __state
#define __TRANSITION_DOWN_FROM(__state)		.from_state = __state, .next_state = __state - 1

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

static ni_fsm_transition_t	ni_iftransitions[] = {
	/* -------------------------------------- *
	 * Transitions for bringing up a device
	 * -------------------------------------- */

	/* Create the device (if it's virtual). This is the only transition
	 * that takes a different approach, because it has to use a factory
	 * service, rather than the device services. */
	{
		__TRANSITION_UP_TO(NI_FSM_STATE_DEVICE_EXISTS),
		.bind_func = ni_ifworker_bind_device_factory,
		.func = ni_ifworker_call_device_factory,
		.common = { .method_name = "newDevice" },
	},

	/* This sets any device attributes, such as a MAC address */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_DEVICE_UP, "changeDevice", .call_overloading = TRUE),

	/* This sets the per-interface protocol attributes, such as forwarding */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_PROTOCOLS_UP, "changeProtocol"),

	/* This step adds device-specific filtering, if available. Typical
	 * example would be bridge filtering with ebtables. */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_FIREWALL_UP, "firewallUp"),

	/* This brings up the link layer, and sets general device attributes such
	 * as the MTU, the transfer queue length etc. */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_LINK_UP, "linkUp", .call_overloading = TRUE),

	/* If the link requires authentication, this information can be provided
	 * here; for instance ethernet 802.1x, wireless WPA, or PPP chap/pap.
	 * NOTE: This may not be the right place; we may have to fold this into
	 * the link_up step, or even do it prior to that. */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_LINK_AUTHENTICATED, "login", .call_overloading = TRUE),

	/* This brings up LLDP sender and configures it */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_LLDP_UP, "lldpUp", .call_overloading = TRUE, .may_fail = TRUE),

	/* Configure all assigned addresses and bring up the network */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_ADDRCONF_UP, "requestLease"),

	/* -------------------------------------- *
	 * Transitions for bringing down a device
	 * -------------------------------------- */
	/* Remove all assigned addresses and bring down the network */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_ADDRCONF_UP, "dropLease"),

	/* Shut down the LLDP sender */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_LLDP_UP, "lldpDown", .call_overloading = TRUE, .may_fail = TRUE),

	/* Shut down the link */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_LINK_UP, "linkDown", .call_overloading = TRUE),

	/* Shut down the firewall */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_FIREWALL_UP, "firewallDown"),

	/* Shutdown the device */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_DEVICE_UP, "shutdownDevice", .call_overloading = TRUE),

	/* Delete the device */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_DEVICE_EXISTS, "deleteDevice", .call_overloading = TRUE),

	{ .from_state = NI_FSM_STATE_NONE, .next_state = NI_FSM_STATE_NONE, .func = NULL }
};

static int
ni_fsm_schedule_init(ni_fsm_t *fsm, ni_ifworker_t *w, unsigned int from_state, unsigned int target_state)
{
	unsigned int index, num_actions;
	unsigned int cur_state;
	int increment;
	int rv;

	if (w->fsm.action_table != NULL)
		return 0;

	if (from_state <= target_state)
		increment = 1;
	else {
		increment = -1;

		/* ifdown: when device cannot be deleted, don't try. */
		if (NI_FSM_STATE_DEVICE_DOWN == target_state) {
			if (!ni_ifworker_can_delete(w))
				target_state -= increment; /* One up */
			else
				ni_debug_application("%s: Deleting device", w->name);
		}
	}

	ni_debug_application("%s: set up FSM from %s -> %s", w->name,
			ni_ifworker_state_name(from_state),
			ni_ifworker_state_name(target_state));
	num_actions = 0;

do_it_again:
	index = 0;
	for (cur_state = from_state; cur_state != target_state; ) {
		unsigned int next_state = cur_state + increment;
		const ni_fsm_transition_t *a;

		for (a = ni_iftransitions; a->func; ++a) {
			if (a->from_state == cur_state && a->next_state == next_state) {
				if (w->fsm.action_table != NULL) {

					ni_debug_application("  %s -> %s: %s()",
						ni_ifworker_state_name(cur_state),
						ni_ifworker_state_name(next_state),
						a->common.method_name);
					w->fsm.action_table[index++] = *a;
					break;
				}
				num_actions++;
			}
		}

		cur_state = next_state;
	}

	if (w->fsm.action_table == NULL) {
		w->fsm.action_table = calloc(num_actions + 1, sizeof(ni_fsm_transition_t));
		goto do_it_again;
	}
	w->fsm.next_action = w->fsm.action_table;
	w->fsm.state = from_state;
	w->target_state = target_state;

	if ((rv = ni_fsm_schedule_bind_methods(fsm, w)) < 0)
		return rv;

	/* FIXME: Add <require> targets from the interface document */

	return 0;
}

/*
 * After we have mapped out the transitions the ifworker needs to go through, we
 * need to bind each of them to a dbus call.
 * We try to do this in one go as early as possible, so that we can flag errors
 * in the document early on.
 */
static int
ni_fsm_schedule_bind_methods(ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_fsm_transition_t *action;
	unsigned int unbound = 0;
	int rv;

	if (w->use_default_policies) {
		static const unsigned int MAX_POLICIES = 64;
		const ni_fsm_policy_t *policies[MAX_POLICIES];
		unsigned int count;

		ni_debug_application("%s: applying policies", w->name);

		count = ni_fsm_policy_get_applicable_policies(fsm, w, policies, MAX_POLICIES);

		w->config.node = ni_fsm_policy_transform_document(w->config.node, policies, count);

		/* Update the control information - it may have been changed by policy */
		ni_ifworker_control_set_defaults(w);
		ni_ifworker_control_from_xml(w, xml_node_get_child(w->config.node, "control"));
	}

	ni_debug_application("%s: binding dbus calls to FSM transitions", w->name);
	for (action = w->fsm.action_table; action->func; ++action) {
		if (action->bound)
			continue;
		rv = action->bind_func(fsm, w, action);
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

unsigned int
ni_fsm_schedule(ni_fsm_t *fsm)
{
	unsigned int i, waiting, nrequested;

	while (1) {
		int made_progress = 0;

		ni_debug_application("-- refreshing interface state --");
		ni_fsm_refresh_state(fsm);

		for (i = 0; i < fsm->workers.count; ++i) {
			ni_ifworker_t *w = fsm->workers.data[i];
			ni_fsm_transition_t *action;
			unsigned int prev_state;
			int rv;

			if (ni_ifworker_complete(w)) {
				ni_ifworker_cancel_timeout(w);
				continue;
			}

			if (!w->kickstarted) {
				if (!ni_ifworker_device_bound(w))
					ni_ifworker_set_state(w, NI_FSM_STATE_DEVICE_DOWN);
				else if (w->object)
					ni_call_clear_event_filters(w->object);
				w->kickstarted = TRUE;
			}

			/* We requested a change that takes time (such as acquiring
			 * a DHCP lease). Wait for a notification from wickedd */
			if (w->fsm.wait_for) {
				ni_debug_application("%s: state=%s want=%s, wait-for=%s", w->name,
					ni_ifworker_state_name(w->fsm.state),
					ni_ifworker_state_name(w->target_state),
					ni_ifworker_state_name(w->fsm.wait_for->next_state));
				continue;
			}

			action = w->fsm.next_action;
			if (action->next_state == NI_FSM_STATE_NONE)
				w->fsm.state = w->target_state;

			if (w->fsm.state == w->target_state) {
				ni_ifworker_success(w);
				made_progress = 1;
				continue;
			}

			ni_debug_application("%s: state=%s want=%s, trying to transition to %s", w->name,
				ni_ifworker_state_name(w->fsm.state),
				ni_ifworker_state_name(w->target_state),
				ni_ifworker_state_name(w->fsm.next_action->next_state));

			if (!action->bound) {
				ni_ifworker_fail(w, "failed to bind services and methods for %s()",
						action->common.method_name);
				continue;
			}

			if (!ni_ifworker_check_dependencies(fsm, w, action)) {
				ni_debug_application("%s: defer action (pending dependencies)", w->name);
				continue;
			}

			ni_ifworker_set_secondary_timeout(w, 0, NULL);

			prev_state = w->fsm.state;
			rv = action->func(fsm, w, action);
			w->fsm.next_action++;

			if (rv >= 0) {
				made_progress = 1;
				if (w->fsm.state == action->next_state) {
					/* We should not have transitioned to the next state while
					 * we were still waiting for some event. */
					ni_assert(w->fsm.wait_for == NULL);
					ni_debug_application("%s: successfully transitioned from %s to %s",
						w->name,
						ni_ifworker_state_name(prev_state),
						ni_ifworker_state_name(w->fsm.state));
				} else {
					ni_debug_application("%s: waiting for event in state %s",
						w->name,
						ni_ifworker_state_name(w->fsm.state));
					w->fsm.wait_for = action;
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

		/* If all the requested workers are done (eg because they failed)
		 * do not wait for any of the subordinate device which might still be
		 * in the middle of being set up.
		 */
		for (i = nrequested = 0; i < fsm->workers.count; ++i) {
			ni_ifworker_t *w = fsm->workers.data[i];

			if (!ni_ifworker_complete(w))
				nrequested++;
		}

		if (nrequested == 0)
			break;
	}

	for (i = waiting = nrequested = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (!w->failed && !ni_ifworker_complete(w)) {
			waiting++;
			nrequested++;
		}
	}

	ni_debug_application("waiting for %u devices to become ready (%u explicitly requested)", waiting, nrequested);
	return nrequested;
}

static void
interface_state_change_signal(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_fsm_t *fsm = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_uuid_t event_uuid = NI_UUID_INIT;
	ni_ifworker_t *w;

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
			ni_debug_dbus("%s: got signal %s from %s; event uuid=%s",
					__func__, signal_name, object_path,
					ni_uuid_print(&event_uuid));
		else
			ni_debug_dbus("%s: got signal %s from %s; event uuid=<>",
					__func__, signal_name, object_path);
		ni_dbus_variant_destroy(&result);
	}

	fsm->event_seq += 1;
	if (!strcmp(signal_name, "addressAcquired"))
		fsm->last_event_seq[NI_EVENT_ADDRESS_ACQUIRED] = fsm->event_seq;

	if ((w = ni_fsm_ifworker_by_object_path(fsm, object_path)) != NULL) {
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

		{
			unsigned int min_state = NI_FSM_STATE_NONE, max_state = __NI_FSM_STATE_MAX;

			if (!strcmp(signal_name, "linkUp"))
				min_state = NI_FSM_STATE_LINK_UP;
			if (!strcmp(signal_name, "linkDown"))
				max_state = NI_FSM_STATE_LINK_UP - 1;
			if (!strcmp(signal_name, "addressAcquired"))
				min_state = NI_FSM_STATE_ADDRCONF_UP;
			if (!strcmp(signal_name, "addressReleased"))
				max_state = NI_FSM_STATE_ADDRCONF_UP - 1;

			ni_ifworker_update_state(w, min_state, max_state);
		}
	}

done: ;
}

ni_dbus_client_t *
ni_fsm_create_client(ni_fsm_t *fsm)
{
	ni_dbus_client_t *client;

	if (!(fsm->client_root_object = ni_call_create_client()))
		return NULL;

	client = ni_dbus_object_get_client(fsm->client_root_object);

	ni_dbus_client_add_signal_handler(client, NULL, NULL,
					NI_OBJECTMODEL_NETIF_INTERFACE,
					interface_state_change_signal,
					fsm);

	ni_dbus_client_add_signal_handler(client, NULL, NULL,
					NI_OBJECTMODEL_MODEM_INTERFACE,
					interface_state_change_signal,
					fsm);

	return client;
}

ni_bool_t
ni_fsm_do(ni_fsm_t *fsm, long *timeout_p)
{
	ni_bool_t pending_workers;

	/*
	 * This loop is small but the ordering is non-trivial.
	 *
	 *  - We should always call ni_fsm_schedule() at least once
	 *  - if an ifworker timeout fires, we should re-run
	 *    ni_fsm_schedule
	 *  - we should return a bool indicating whether there are
	 *    active workers, or whether we're done.
	 */
	do {
		pending_workers = ni_fsm_schedule(fsm);

		ni_ifworker_timeout_count = 0;
		*timeout_p = ni_timer_next_timeout();
	} while (ni_ifworker_timeout_count);

	return pending_workers;
}

void
ni_fsm_mainloop(ni_fsm_t *fsm)
{
	long timeout;

	while (!ni_caught_terminal_signal()) {
		if (!ni_fsm_do(fsm, &timeout))
			break;

		if (ni_socket_wait(timeout) != 0)
			ni_fatal("ni_socket_wait failed");

		if (ni_fsm_schedule(fsm) == 0)
			break;
	}

	ni_debug_application("finished with all devices.");
}

/*
 * Prompt for data.
 * The default implementation is to use stdio
 */
int
ni_fsm_user_prompt_default(const ni_fsm_prompt_t *p, xml_node_t *node, void *user_data)
{
	ni_stringbuf_t prompt_buf;
	int rv = -1;

	if (node == NULL)
		return -NI_ERROR_INVALID_ARGS;

	ni_stringbuf_init(&prompt_buf);

	if (p->string != NULL) {
		ni_stringbuf_puts(&prompt_buf, p->string);
	} else {
		ni_stringbuf_puts(&prompt_buf, "Please enter ");
		switch (p->type) {
		case NI_FSM_PROMPT_PASSWORD:
			ni_stringbuf_puts(&prompt_buf, "password");
			break;
		case NI_FSM_PROMPT_USERNAME:
			ni_stringbuf_puts(&prompt_buf, "user name");
			break;
		default:
			ni_stringbuf_puts(&prompt_buf, "value");
			break;
		}

		if (p->id)
			ni_stringbuf_printf(&prompt_buf, " for %s", p->id);
	}
	ni_stringbuf_puts(&prompt_buf, ": ");

	if (p->type == NI_FSM_PROMPT_PASSWORD) {
		const char *value;

		value = getpass(prompt_buf.string);
		if (value == NULL)
			goto done;

		xml_node_set_cdata(node, value);
	} else {
		char buffer[256];

		fputs(prompt_buf.string, stdout);
		fflush(stdout);

		if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
			/* EOF: User pressed Ctrl-D */
			printf("\n");
			goto done;
		}

		xml_node_set_cdata(node, buffer);
	}

	rv = 0;

done:
	ni_stringbuf_destroy(&prompt_buf);
	return rv;
}

void
ni_fsm_set_user_prompt_fn(ni_fsm_t *fsm, ni_fsm_user_prompt_fn_t *fn, void *user_data)
{
	ni_fsm_user_prompt_fn = fn;
	ni_fsm_user_prompt_data = user_data;
}
