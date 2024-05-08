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
#include <wicked/addrconf.h>
#include <wicked/modem.h>
#include <wicked/xpath.h>
#include <wicked/fsm.h>
#include <wicked/client.h>
#include <wicked/bridge.h>
#include <wicked/ovs.h>
#include <wicked/compiler.h>
#include <xml-schema.h>

#include "dbus-objects/model.h"
#include "client/ifconfig.h"
#include "appconfig.h"
#include "util_priv.h"

static ni_fsm_user_prompt_fn_t *ni_fsm_user_prompt_fn;
static void *			ni_fsm_user_prompt_data;

static ni_ifworker_t *		ni_ifworker_identify_device(ni_fsm_t *, const xml_node_t *, ni_ifworker_type_t, const char *);
static ni_ifworker_t *		__ni_ifworker_identify_device(ni_fsm_t *, const char *, const xml_node_t *, ni_ifworker_type_t, const char *);
static void			ni_ifworker_set_dependencies_xml(ni_ifworker_t *, xml_node_t *);
static int			ni_fsm_schedule_init(ni_fsm_t *fsm, ni_ifworker_t *, unsigned int, unsigned int);
static int			ni_fsm_schedule_bind_methods(ni_fsm_t *, ni_ifworker_t *);
static ni_fsm_require_t *	ni_ifworker_netif_resolver_new(xml_node_t *);
static ni_fsm_require_t *	ni_ifworker_modem_resolver_new(xml_node_t *);
static void			ni_fsm_require_list_destroy(ni_fsm_require_t **);
static void			ni_fsm_require_free(ni_fsm_require_t *);
static int			ni_ifworker_bind_device_apis(ni_ifworker_t *, const ni_dbus_service_t *);
static void			ni_ifworker_control_init(ni_ifworker_control_t *);
static void			ni_ifworker_control_destroy(ni_ifworker_control_t *);
static ni_bool_t		ni_fsm_refresh_netdevs_state(ni_fsm_t *);
#ifdef MODEM
static ni_bool_t		ni_fsm_refresh_modems_state(ni_fsm_t *);
#endif
static int			ni_fsm_user_prompt_default(const ni_fsm_prompt_t *, xml_node_t *, void *);
static void			ni_ifworker_refresh_client_state(ni_ifworker_t *, ni_client_state_t *);
static void			ni_ifworker_set_config_origin(ni_ifworker_t *, const char *);
static void			ni_ifworker_cancel_timeout(ni_ifworker_t *);
static void			ni_ifworker_cancel_secondary_timeout(ni_ifworker_t *);
static void			ni_ifworker_cancel_callbacks(ni_ifworker_t *, ni_objectmodel_callback_info_t **);
static dbus_bool_t		ni_ifworker_waiting_for_events(ni_ifworker_t *);
static void			ni_ifworker_advance_state(ni_ifworker_t *, ni_event_t);
static ni_bool_t		ni_ifworker_revert_state(ni_ifworker_t *, ni_event_t);
static void			ni_fsm_clear_hierarchy(ni_ifworker_t *);

static void			ni_ifworker_update_client_state_control(ni_ifworker_t *w);
static void			ni_ifworker_update_client_state_config(ni_ifworker_t *w);
static void			ni_ifworker_update_client_state_scripts(ni_ifworker_t *w);
static void			ni_ifworker_update_client_state(ni_ifworker_t *w);
static void			ni_ifworker_reset_client_state(ni_ifworker_t *w);

static void			ni_fsm_events_destroy(ni_fsm_event_t **);
static void			ni_fsm_process_event(ni_fsm_t *, ni_fsm_event_t *);

static const ni_fsm_transition_t *	ni_fsm_transition_first(void);
static const ni_fsm_transition_t *	ni_fsm_transition_next(const ni_fsm_transition_t *);
static const ni_fsm_transition_t *	ni_fsm_transition_find_method(const char *);

ni_fsm_t *
ni_fsm_new(void)
{
	ni_fsm_t *fsm;

	fsm = calloc(1, sizeof(*fsm));
	fsm->readonly = FALSE;

	ni_fsm_user_prompt_fn = ni_fsm_user_prompt_default;
	return fsm;
}

void
ni_fsm_free(ni_fsm_t *fsm)
{
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i)
		ni_ifworker_reset(fsm->workers.data[i]);

	ni_fsm_events_destroy(&fsm->events);
	ni_ifworker_array_destroy(&fsm->pending);
	ni_ifworker_array_destroy(&fsm->workers);
	free(fsm);
}


/*
 * fsm event processing utilities
 */
ni_fsm_event_t *
ni_fsm_event_new(const char *object_path, const char *signal_name, ni_event_t event_type)
{
	ni_fsm_event_t *ev;

	ev = xcalloc(1, sizeof(*ev));
	ni_string_dup(&ev->object_path, object_path);
	ni_string_dup(&ev->signal_name, signal_name);
	ev->event_type = event_type;
	return ev;
}

void
ni_fsm_event_free(ni_fsm_event_t *ev)
{
	if (ev) {
		ni_string_free(&ev->object_path);
		ni_string_free(&ev->signal_name);
		free(ev);
	}
}

void
ni_fsm_events_append(ni_fsm_event_t **events, ni_fsm_event_t *ev)
{
	while (*events)
		events = &(*events)->next;
	*events = ev;
}

ni_fsm_event_t *
ni_fsm_events_remove(ni_fsm_event_t **events, ni_fsm_event_t *ev)
{
	ni_fsm_event_t **pos, *cur;

	for (pos = events; (cur = *pos); pos = &cur->next) {
		if (cur == ev) {
			*pos = cur->next;
			cur->next = NULL;
			return cur;
		}
	}
	return NULL;
}

void
ni_fsm_events_delete(ni_fsm_event_t **events, ni_fsm_event_t *ev)
{
	ni_fsm_event_free(ni_fsm_events_remove(events, ev));
}

void
ni_fsm_events_destroy(ni_fsm_event_t **events)
{
	ni_fsm_event_t *ev;

	while ((ev = *events)) {
		*events = ev->next;
		ni_fsm_event_free(ev);
	}
}

void
ni_fsm_events_block(ni_fsm_t *fsm)
{
	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS, "block fsm events %u -> %u",
			 fsm->block_events, fsm->block_events + 1);
	fsm->block_events++;
}

void
ni_fsm_events_unblock(ni_fsm_t *fsm)
{
	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS, "unblock fsm events %u -> %u",
			fsm->block_events, fsm->block_events - 1);
	ni_assert(fsm->block_events > 0);
	fsm->block_events--;
}

void
ni_fsm_process_events(ni_fsm_t *fsm)
{
	ni_fsm_event_t *ev;

	while ((ev = fsm->events)) {
		fsm->events = ev->next;

		ni_fsm_events_block(fsm);
		ni_fsm_process_event(fsm, ev);
		ni_fsm_events_unblock(fsm);

		ni_fsm_event_free(ev);
	}
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
	w->target_range.max = NI_FSM_STATE_MAX;
	w->readonly = FALSE;
	w->args.release = NI_TRISTATE_DEFAULT;

	ni_ifworker_control_init(&w->control);
	ni_client_state_config_init(&w->config.meta);

	return w;
}

static ni_ifworker_t *
ni_ifworker_new(ni_ifworker_array_t *array, ni_ifworker_type_t type, const char *name)
{
	ni_ifworker_t *worker;

	worker = __ni_ifworker_new(type, name);
	ni_ifworker_array_append(array, worker);
	if (ni_ifworker_release(worker))
		return worker;
	else
		return NULL;
}

ni_ifworker_t *
ni_fsm_ifworker_new(ni_fsm_t *fsm, ni_ifworker_type_t type, const char *name)
{
	if (!fsm || ni_string_empty(name) || ni_fsm_ifworker_by_name(fsm, type, name))
		return NULL;

	return ni_ifworker_new(&fsm->workers, type, name);
}

ni_ifworker_t *
ni_ifworker_set_ref(ni_ifworker_t **ref, ni_ifworker_t *n)
{
	ni_ifworker_t *o;

	if (!ref)
		return NULL;

	o = *ref;
	if (n)
		*ref = ni_ifworker_get(n);
	else
		*ref = NULL;
	if (o)
		ni_ifworker_release(o);
	return n;
}

static void
ni_fsm_transition_bind_reset(ni_fsm_transition_bind_t *bind)
{
	xml_node_free(bind->config);
	memset(bind, 0, sizeof(*bind));
}

static ni_bool_t
ni_fsm_transition_is_down(const ni_fsm_transition_t *action)
{
	return action->from_state > action->next_state;
}

static ni_fsm_transition_t *
ni_fsm_transition_find(ni_fsm_transition_t *table, ni_fsm_state_t from, ni_fsm_state_t next)
{
	ni_fsm_transition_t *action;

	for (action = table; action && action->next_state; action++) {
		if (action->from_state == from && action->next_state == next)
			return action;
	}

	return NULL;
}

static void
ni_fsm_transition_reset(ni_fsm_transition_t *action)
{
	ni_fsm_transition_bind_t *bind;
	unsigned int i;

	for (i = 0, bind = action->binding; i < action->num_bindings; ++i, ++bind) {
		ni_fsm_transition_bind_reset(bind);
		action->bound = FALSE;
	}
}

static void
ni_ifworker_cancel_action_table_callbacks(ni_ifworker_t *w)
{
	ni_fsm_transition_t *action;

	for (action = w->fsm.action_table; action && action->next_state; action++)
		ni_ifworker_cancel_callbacks(w, &action->callbacks);
}

static void
ni_ifworker_reset_action_table(ni_ifworker_t *w)
{
	ni_fsm_transition_t *action;

	for (action = w->fsm.action_table; action && action->next_state; action++) {
		ni_fsm_transition_reset(action);
		ni_fsm_require_list_destroy(&action->require.list);
		ni_ifworker_cancel_callbacks(w, &action->callbacks);
	}
	w->fsm.wait_for = NULL;
	w->fsm.next_action = w->fsm.action_table;
}

static void
ni_ifworker_destroy_action_table(ni_ifworker_t *w)
{
	ni_ifworker_reset_action_table(w);

	free(w->fsm.action_table);
	w->fsm.next_action = NULL;
	w->fsm.action_table = NULL;
}

static void
ni_ifworker_destroy_device_api(ni_ifworker_t *w)
{
	xml_node_free(w->device_api.config);
	memset(&w->device_api, 0, sizeof(w->device_api));
}

static void
ni_ifworker_reset_fsm(ni_ifworker_t *w)
{
	if (!w)
		return;

	ni_ifworker_cancel_secondary_timeout(w);
	ni_ifworker_cancel_timeout(w);

	ni_ifworker_reset_action_table(w);

	w->fsm.state = NI_FSM_STATE_NONE;
	w->args.release = NI_TRISTATE_DEFAULT;
}

static void
ni_ifworker_destroy_fsm(ni_ifworker_t *w)
{
	ni_ifworker_reset_fsm(w);

	ni_ifworker_destroy_action_table(w);
	ni_fsm_require_list_destroy(&w->fsm.check_state_req_list);
}

void
ni_ifworker_rearm(ni_ifworker_t *w)
{
	w->target_state = NI_FSM_STATE_NONE;
	w->done = FALSE;
	w->failed = FALSE;
	w->kickstarted = FALSE;
	ni_ifworker_reset_fsm(w);
}

void
ni_ifworker_reset(ni_ifworker_t *w)
{
	/* Reset client state config and control */
	ni_ifworker_control_init(&w->control);
	ni_security_id_destroy(&w->security_id);
	ni_client_state_config_reset(&w->config.meta);

	/* Clear lowerdev/masterdev relations */
	ni_fsm_clear_hierarchy(w);

	ni_ifworker_rearm(w);
	ni_ifworker_destroy_fsm(w);
	ni_ifworker_destroy_device_api(w);

	w->readonly = FALSE;
	w->dead = FALSE;
	w->pending = FALSE;

	w->target_range.min = NI_FSM_STATE_NONE;
	w->target_range.max = NI_FSM_STATE_MAX;
}

void
ni_ifworker_free(ni_ifworker_t *w)
{
	/* Destroy applied policy references */
	ni_fsm_policy_array_destroy(&w->policies);

	/* Destroy client state config and control */
	ni_ifworker_control_destroy(&w->control);
	ni_security_id_destroy(&w->security_id);
	ni_client_state_config_reset(&w->config.meta);

	/* Destroy config and state nodes */
	xml_node_free(w->config.node);
	xml_node_free(w->state.node);

	/* Clear lowerdev/masterdev relations */
	ni_fsm_clear_hierarchy(w);

	ni_ifworker_rearm(w);
	ni_ifworker_destroy_fsm(w);
	ni_ifworker_destroy_device_api(w);

	w->readonly = FALSE;
	w->dead = FALSE;
	w->pending = FALSE;

	w->target_range.min = NI_FSM_STATE_NONE;
	w->target_range.max = NI_FSM_STATE_MAX;

	ni_string_free(&w->object_path);
	if (w->device)
		ni_netdev_put(w->device);
	if (w->modem)
		ni_modem_release(w->modem);

	ni_string_free(&w->name);
	ni_string_free(&w->old_name);
	free(w);
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

	req = xcalloc(1, sizeof(*req));
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
	w->done = TRUE;

	ni_ifworker_cancel_secondary_timeout(w);
	ni_ifworker_cancel_timeout(w);
	ni_ifworker_cancel_action_table_callbacks(w);

	if (w->progress.callback)
		w->progress.callback(w, w->fsm.state);

	if (w->completion.callback)
		w->completion.callback(w);
}

void
ni_ifworker_fail(ni_ifworker_t *w, const char *fmt, ...)
{
	char errmsg[256];
	va_list ap;

	if (w->failed)
		return;

	va_start(ap, fmt);
	vsnprintf(errmsg, sizeof(errmsg), fmt, ap);
	va_end(ap);

	ni_error("device %s: %s", w->name, ni_string_empty(errmsg) ? "failed" : errmsg);
	w->fsm.state = NI_FSM_STATE_NONE;
	w->failed = TRUE;
	w->pending = FALSE;

	__ni_ifworker_done(w);
}

void
ni_ifworker_success(ni_ifworker_t *w)
{
	__ni_ifworker_done(w);
}

/*
 * Set fsm event processing callback
 */
void
ni_fsm_set_process_event_callback(ni_fsm_t *fsm, void (*cb)(ni_fsm_t *, ni_ifworker_t *, ni_fsm_event_t *), void *user_data)
{
	fsm->process_event.callback = cb;
	fsm->process_event.user_data = user_data;
}

/*
 * Set the progress callback
 */
void
ni_ifworker_set_progress_callback(ni_ifworker_t *w, void (*cb)(ni_ifworker_t *, ni_fsm_state_t), void *user_data)
{
	w->progress.callback = cb;
	w->progress.user_data = user_data;
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
struct ni_fsm_timer_ctx {
	ni_fsm_t *		fsm;
	ni_ifworker_t *		worker;
	ni_fsm_timer_fn_t *	timeout_fn;
};

static void
ni_fsm_timer_ctx_free(ni_fsm_timer_ctx_t *tcx)
{
	free(tcx);
}

static ni_fsm_timer_ctx_t *
ni_fsm_timer_ctx_new(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_timer_fn_t *fn)
{
	ni_fsm_timer_ctx_t *tcx;

	if (!fsm || !w || !fn)
		return NULL;

	tcx = xcalloc(1, sizeof(*tcx));
	tcx->fsm = fsm;
	tcx->worker = w;
	tcx->timeout_fn = fn;
	return tcx;
}

static void
ni_fsm_timer_call(void *user_data, const ni_timer_t *timer)
{
	ni_fsm_timer_ctx_t *tcx = user_data;

	if (!timer || !tcx || !tcx->fsm || !tcx->worker || !tcx->timeout_fn) {
		ni_error("BUG: fsm worker timer call with invalid %s",
				timer ? "timer" : "timer context");
		return;
	}

	tcx->timeout_fn(timer, tcx);
	ni_fsm_timer_ctx_free(tcx);
}

static inline const ni_timer_t *
ni_fsm_timer_register(ni_timeout_t timeout, ni_fsm_timer_ctx_t *tcx)
{
	return ni_timer_register(timeout, ni_fsm_timer_call, tcx);
}

static ni_bool_t
ni_fsm_timer_cancel(const ni_timer_t **timer)
{
	ni_fsm_timer_ctx_t *tcx;

	if (timer && *timer) {
		tcx = ni_timer_cancel(*timer);
		*timer = NULL;
		ni_fsm_timer_ctx_free(tcx);
		return TRUE;
	}
	return FALSE;
}

static void
ni_ifworker_cancel_timeout(ni_ifworker_t *w)
{
	if (ni_fsm_timer_cancel(&w->fsm.timer))
		ni_debug_application("%s: cancel worker's timeout", w->name);
}

static void
ni_ifworker_cancel_secondary_timeout(ni_ifworker_t *w)
{
	if (ni_fsm_timer_cancel(&w->fsm.secondary_timer))
		ni_debug_application("%s: cancel worker's secondary timeout", w->name);
}

static void
ni_ifworker_timeout(const ni_timer_t *timer, ni_fsm_timer_ctx_t *tcx)
{
	ni_ifworker_t *w = tcx->worker;

	if (w->fsm.timer != timer) {
		ni_error("%s(%s) called with unexpected timer", __func__, w->name);
		return;
	}
	tcx->worker->fsm.timer = NULL;
	tcx->fsm->timeout_count++;

	if (ni_ifworker_waiting_for_events(w) || !ni_ifworker_complete(w) || w->pending)
		ni_ifworker_fail(w, "operation timed out");
}

static inline void
ni_ifworker_set_timeout(ni_fsm_t *fsm, ni_ifworker_t *w, ni_timeout_t timeout)
{
	ni_fsm_timer_ctx_t *tcx;

	ni_ifworker_cancel_timeout(w);

	if (!timeout || timeout == NI_IFWORKER_INFINITE_TIMEOUT)
		return;

	if (!(tcx = ni_fsm_timer_ctx_new(fsm, w, ni_ifworker_timeout)))
		return;

	w->fsm.timer = ni_fsm_timer_register(timeout, tcx);
}

static inline void
ni_ifworker_set_secondary_timeout(ni_fsm_t *fsm, ni_ifworker_t *w, ni_timeout_t timeout,
					ni_fsm_timer_fn_t *handler)
{
	ni_fsm_timer_ctx_t *tcx;

	ni_ifworker_cancel_secondary_timeout(w);

	if (!handler || !timeout || timeout == NI_IFWORKER_INFINITE_TIMEOUT)
		return;

	if (!(tcx = ni_fsm_timer_ctx_new(fsm, w, handler)))
		return;

	w->fsm.secondary_timer = ni_fsm_timer_register(timeout, tcx);
}

static ni_intmap_t __state_names[] = {
	{ "none",		NI_FSM_STATE_NONE		},
	{ "device-down",	NI_FSM_STATE_DEVICE_DOWN	},
	{ "device-exists",	NI_FSM_STATE_DEVICE_EXISTS	},
	{ "device-ready",	NI_FSM_STATE_DEVICE_READY	},
	{ "device-setup",	NI_FSM_STATE_DEVICE_SETUP	},
	{ "protocols-up",	NI_FSM_STATE_PROTOCOLS_UP	},
	{ "firewall-up",	NI_FSM_STATE_FIREWALL_UP	},
	{ "device-up",		NI_FSM_STATE_DEVICE_UP		},
	{ "link-up",		NI_FSM_STATE_LINK_UP		},
	{ "link-authenticated",	NI_FSM_STATE_LINK_AUTHENTICATED	},
	{ "lldp-up",		NI_FSM_STATE_LLDP_UP		},
	{ "addrconf-up",	NI_FSM_STATE_ADDRCONF_UP	},
	{ "network-up",		NI_FSM_STATE_NETWORK_UP		},
	{ "max",		NI_FSM_STATE_MAX		},

	{ NULL }
};

inline ni_bool_t
ni_ifworker_state_in_range(const ni_uint_range_t *range, const ni_fsm_state_t state)
{
	return state >= range->min && state <= range->max;
}

const char *
ni_ifworker_state_name(ni_fsm_state_t state)
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

ni_ifworker_array_t *
ni_ifworker_array_new(void)
{
	ni_ifworker_array_t *array;

	array = xcalloc(1, sizeof(*array));
	return array;
}

void
ni_ifworker_array_append(ni_ifworker_array_t *array, ni_ifworker_t *w)
{
	if (!array || !w)
		return;

	array->data = realloc(array->data, (array->count + 1) * sizeof(array->data[0]));
	array->data[array->count++] = ni_ifworker_get(w);
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
	if (array) {
		while (array->count)
			ni_ifworker_release(array->data[--(array->count)]);
		free(array->data);
		array->data = NULL;
	}
}

void
ni_ifworker_array_free(ni_ifworker_array_t *array)
{
	ni_ifworker_array_destroy(array);
	free(array);
}

static ni_ifworker_t *
ni_ifworker_array_find_by_objectpath(ni_ifworker_array_t *array, const char *object_path)
{
	unsigned int i;

	if (ni_string_empty(object_path))
		return NULL;

	for (i = 0; i < array->count; ++i) {
		ni_ifworker_t *w = array->data[i];

		if (ni_string_eq(w->object_path, object_path))
			return w;
	}
	return NULL;
}

static ni_ifworker_t *
ni_ifworker_array_find_by_name(const ni_ifworker_array_t *array, ni_ifworker_type_t type, const char *name)
{
	unsigned int i;

	if (ni_string_empty(name))
		return NULL;

	for (i = 0; i < array->count; ++i) {
		ni_ifworker_t *worker = array->data[i];

		if (worker->type == type && ni_string_eq(worker->name, name))
			return worker;
	}
	return NULL;
}

ni_ifworker_array_t *
ni_ifworker_array_clone(ni_ifworker_array_t *array)
{
	unsigned int i;
	ni_ifworker_array_t *clone;

	if (!array)
		return NULL;

	clone = ni_ifworker_array_new();
	for (i = 0; i < array->count; ++i)
		ni_ifworker_array_append(clone, array->data[i]);

	return clone;
}

ni_bool_t
ni_ifworker_array_remove_index(ni_ifworker_array_t *array, unsigned int index)
{
	unsigned int i;

	if (!array || index >= array->count)
		return FALSE;

	if (array->data[index])
		ni_ifworker_release(array->data[index]);

	array->count--;
	for (i = index; i < array->count; ++i)
		array->data[i] = array->data[i + 1];
	array->data[array->count] = NULL;

	return TRUE;
}

ni_bool_t
ni_ifworker_array_remove(ni_ifworker_array_t *array, ni_ifworker_t *w)
{
	unsigned int i;
	ni_bool_t found = FALSE;

	for (i = 0; i < array->count; ) {
		if (w == array->data[i]) {
			found = ni_ifworker_array_remove_index(array, i);
		} else {
			++i;
		}
	}

	return found;
}

ni_ifworker_t *
ni_fsm_ifworker_by_name(const ni_fsm_t *fsm, ni_ifworker_type_t type, const char *name)
{
	return ni_ifworker_array_find_by_name(&fsm->workers, type, name);
}

ni_ifworker_t *
ni_fsm_ifworker_by_policy_name(ni_fsm_t *fsm, ni_ifworker_type_t type, const char *policy_name)
{
	unsigned int i;
	ni_ifworker_t *w;
	char *n;

	if (!fsm || !policy_name)
		return NULL;

	for (i = 0; i < fsm->workers.count ; ++i) {
		w = fsm->workers.data[i];
		if (w && w->type == type) {
			n = ni_ifpolicy_name_from_ifname(w->name);
			if (n && ni_string_eq(n, policy_name)) {
				ni_string_free(&n);
				return w;
			}
			ni_string_free(&n);
		}
	}

	return NULL;
}

ni_ifworker_t *
ni_fsm_ifworker_by_object_path(ni_fsm_t *fsm, const char *object_path)
{
	return ni_ifworker_array_find_by_objectpath(&fsm->workers, object_path);
}

ni_ifworker_t *
ni_fsm_ifworker_by_ifindex(ni_fsm_t *fsm, unsigned int ifindex)
{
	unsigned int i;

	if (0 == ifindex)
		return NULL;

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
ni_ifworker_match_netdev_name(const ni_ifworker_t *w, const char *ifname)
{
	if (!w || ni_string_empty(ifname))
		return FALSE;

	if (ni_string_eq(w->name, ifname))
		return TRUE;

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
			"device %s requested via match is not present", ifname);
	return FALSE;
}

static ni_bool_t
__ni_ifworker_match_netdev_ifindex(unsigned int ifindex, const char *value)
{
	unsigned int index;

	if (ni_parse_uint(value, &index, 10) < 0 || !index)
		return FALSE;
	return ifindex == index;
}

ni_bool_t
ni_ifworker_match_netdev_ifindex(const ni_ifworker_t *w, unsigned int ifindex)
{
	xml_node_t *node;

	if (!ifindex)
		return FALSE;

	if (w->device && w->device->link.ifindex == ifindex)
		return TRUE;

	if (!xml_node_is_empty(w->config.node) &&
	    (node = xml_node_get_child(w->config.node, "name"))) {
		const char *namespace = xml_node_get_attr(node, "namespace");

		if (namespace && ni_string_eq(namespace, "ifindex"))
			return __ni_ifworker_match_netdev_ifindex(ifindex, node->cdata);
	}
	return FALSE;
}

ni_bool_t
ni_ifworker_match_netdev_alias(const ni_ifworker_t *w, const char *ifalias)
{
	xml_node_t *node;

	if (!ifalias)
		return FALSE;

	if (w->device && ni_string_eq(w->device->link.alias, ifalias))
		return TRUE;

	if (!xml_node_is_empty(w->config.node) &&
	    (node = xml_node_get_child(w->config.node, "alias"))) {
		if (ni_string_eq(node->cdata, ifalias))
			return TRUE;
	}
	if (!xml_node_is_empty(w->config.node) &&
	    (node = xml_node_get_child(w->config.node, "name"))) {
		const char *namespace = xml_node_get_attr(node, "namespace");

		if (namespace && ni_string_eq(namespace, "alias"))
			return ni_string_eq(node->cdata, ifalias);
	}

	return FALSE;
}

ni_bool_t
ni_ifworker_match_alias(const ni_ifworker_t *w, const char *alias)
{
	xml_node_t *node;

	if (!alias)
		return FALSE;

	if (w->device && ni_string_eq(w->device->link.alias, alias))
		return TRUE;

	if (!xml_node_is_empty(w->config.node) &&
	    (node = xml_node_get_child(w->config.node, "alias"))) {
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
ni_ifworker_resolve_reference(ni_fsm_t *fsm, xml_node_t *devnode, ni_ifworker_type_t type, const char *origin)
{
	ni_ifworker_t *child;

	if (devnode->children || devnode->cdata) {
		/* Try to identify device based on attributes given in the
		 * <device> node. */
		const char *namespace;

		namespace = xml_node_get_attr(devnode, "namespace");
		if (namespace != NULL) {
			child = __ni_ifworker_identify_device(fsm, namespace, devnode, type, origin);
		} else if (devnode->cdata) {
			const char *slave_name = devnode->cdata;
			child = ni_fsm_ifworker_by_name(fsm, type, slave_name);
			if (child == NULL) {
				ni_debug_application("%s: <%s> element references unknown device %s",
							origin, devnode->name, slave_name);
				return NULL;
			}
		} else {
			ni_warn("%s: obsolete: using <device> node without namespace attribute "
				"- please use <device namespace=\"...\"> instead", origin);
			child = ni_ifworker_identify_device(fsm, devnode, type, origin);
		}
		if (child == NULL) {
			ni_debug_application("%s: <%s> element references unknown device",
				origin, devnode->name);
			return NULL;
		}

		if (child->name == NULL) {
			ni_warn("%s: <%s> element references device with no name",
				origin, devnode->name);
		}

		ni_debug_application("%s: <%s> identified device as \"%s\"",
				origin, devnode->name, child->name);
		xml_node_set_cdata(devnode, child->name);
		if (namespace)
			xml_node_del_attr(devnode, "namespace");
	} else {
		ni_error("%s: empty device reference in <%s> element",
			origin, devnode->name);
		return NULL;
	}

	return child;
}

static ni_bool_t
ni_ifworker_set_master_device(ni_ifworker_t *slave, ni_ifworker_t *master, xml_node_t *devnode)
{
	char *location = NULL;

	if (!slave->masterdev || slave->masterdev == master ||
	    ni_string_eq(slave->masterdev->name, master->name)) {
		ni_debug_application("%s (%s): setting master device to %s",
				slave->name, xml_node_location(devnode), master->name);

		slave->masterdev = master;
		return TRUE;
	}

	if (!xml_node_is_empty(slave->masterdev->config.node))
		ni_string_dup(&location, xml_node_location(slave->masterdev->config.node));

	ni_debug_application("%s (%s): subordinate interface already has a master device %s (%s), cannot set to %s",
			slave->name, xml_node_location(devnode),
			slave->masterdev->name, location, master->name);

	ni_string_free(&location);
	return FALSE;
}

static ni_bool_t
ni_ifworker_set_lower_device(ni_ifworker_t *child, ni_ifworker_t *lower, xml_node_t *devnode)
{
	char *location = NULL;

	if (!child->lowerdev || child->lowerdev == lower ||
	    ni_string_eq(child->lowerdev->name, lower->name)) {
		ni_debug_application("%s (%s): setting lower device to %s",
				child->name, xml_node_location(devnode), lower->name);

		child->lowerdev = lower;
		return TRUE;
	}

	if (!xml_node_is_empty(child->lowerdev->config.node))
		ni_string_dup(&location, xml_node_location(child->lowerdev->config.node));

	ni_debug_application("%s (%s): subordinate interface already has a lower device %s (%s), cannot set to %s",
			child->name, xml_node_location(devnode),
			child->lowerdev->name, location, lower->name);
	ni_string_free(&location);
	return FALSE;
}

static ni_bool_t
ni_ifworker_add_child(ni_ifworker_t *parent, ni_ifworker_t *child, xml_node_t *devnode, ni_bool_t shared, ni_bool_t supplemental)
{
	unsigned int i;

	if (!supplemental) {
		if (shared) {
			/* a vlan "parent" refers to it's lower in "child" */
			if (!ni_ifworker_set_lower_device(parent, child, devnode))
				return FALSE;
		} else {
			/* master "parent" refers to it's slave in "child" */
			if (!ni_ifworker_set_master_device(child, parent, devnode))
				return FALSE;
		}
	}

	/* Check if this child is already owned by the given parent. */
	for (i = 0; i < parent->children.count; ++i) {
		if (parent->children.data[i] == child)
			return TRUE;
	}
	ni_ifworker_array_append(&parent->children, child);
	return TRUE;
}

static void
ni_ifworker_print_callbacks(const char *ifname, ni_objectmodel_callback_info_t *callback_list)
{
	ni_objectmodel_callback_info_t *cb;

	if (!ni_log_facility(NI_TRACE_EVENTS))
		return;

	if (callback_list == NULL) {
		ni_debug_events("%s: no pending callbacks", ifname);
	} else {
		ni_debug_events("%s: waiting for callbacks:", ifname);
		for (cb = callback_list; cb; cb = cb->next) {
			ni_debug_events("        %s event=%s",
					ni_uuid_print(&cb->uuid),
					cb->event);
		}
	}
}

/* Create an event wait object */
static void
ni_ifworker_add_callbacks(ni_fsm_transition_t *action, ni_objectmodel_callback_info_t *callback_list, const char *ifname)
{
	ni_objectmodel_callback_info_t **pos, *cb;

	ni_ifworker_print_callbacks(ifname, callback_list);

	for (pos = &action->callbacks; (cb = *pos) != NULL; pos = &cb->next)
		;
	*pos = callback_list;
}

static ni_objectmodel_callback_info_t *
ni_ifworker_get_callback(ni_ifworker_t *w, const ni_uuid_t *uuid, ni_bool_t remove)
{
	ni_objectmodel_callback_info_t **pos, *cb;
	ni_fsm_transition_t *action;

	if ((action = w->fsm.wait_for) == NULL)
		return NULL;
	for (pos = &action->callbacks; (cb = *pos) != NULL; pos = &cb->next) {
		if (ni_uuid_equal(&cb->uuid, uuid)) {
			if (remove) {
				*pos = cb->next;
				cb->next = NULL;
			}
			return cb;
		}
	}
	return NULL;
}

static void
ni_ifworker_cancel_callbacks(ni_ifworker_t *w, ni_objectmodel_callback_info_t **callbacks)
{
	ni_objectmodel_callback_info_t *cb;

	if (!callbacks || !*callbacks)
		return;

	ni_debug_events("%s: cancel waiting for callbacks:", w->name);
	while ((cb = *callbacks) != NULL) {
		*callbacks = cb->next;
		cb->next = NULL;
		ni_debug_events("        %s event=%s",
				ni_uuid_print(&cb->uuid), cb->event);
		ni_objectmodel_callback_info_free(cb);
	}
}

static dbus_bool_t
ni_ifworker_waiting_for_events(ni_ifworker_t *w)
{
	ni_fsm_transition_t *action;

	if ((action = w->fsm.wait_for) == NULL)
		return FALSE;
	if (action->callbacks == NULL)
		return FALSE;
	return TRUE;
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
ni_ifworker_update_client_state_control(ni_ifworker_t *w)
{
	ni_client_state_control_t ctrl;

	if (w && w->object && !w->readonly) {
		ctrl.persistent = w->control.persistent;
		ctrl.usercontrol = w->control.usercontrol;
		ctrl.require_link = w->control.link_required;
		ni_call_set_client_state_control(w->object, &ctrl);
		ni_client_state_control_debug(w->name, &ctrl, "update");
	}
}

static void
ni_ifworker_update_client_state_config(ni_ifworker_t *w)
{
	if (w && w->object && !w->readonly) {
		ni_call_set_client_state_config(w->object, &w->config.meta);
		ni_client_state_config_debug(w->name, &w->config.meta, "update");
	}
}

static void
ni_ifworker_update_client_state_scripts(ni_ifworker_t *w)
{
	ni_client_state_scripts_t scripts = { .node = NULL };

	if (w && w->object && !w->readonly && w->config.node) {
		if ((scripts.node = xml_node_get_child(w->config.node, "scripts"))) {
			ni_call_set_client_state_scripts(w->object, &scripts);
		}
	}
}

static void
ni_ifworker_update_client_state(ni_ifworker_t *w)
{
	ni_ifworker_update_client_state_control(w);
	ni_ifworker_update_client_state_config(w);
	ni_ifworker_update_client_state_scripts(w);
}

static inline void
ni_ifworker_reset_client_state_control(ni_ifworker_t *w)
{
	ni_client_state_control_t ctrl;

	if (w && w->object && !w->readonly) {
		ni_client_state_control_init(&ctrl);
		ni_call_set_client_state_control(w->object, &ctrl);
		ni_client_state_control_debug(w->name, &ctrl, "remove");
	}
}

static inline void
ni_ifworker_reset_client_state_config(ni_ifworker_t *w)
{
	ni_client_state_config_t config;

	if (w && w->object && !w->readonly) {
		ni_client_state_config_init(&config);
		ni_call_set_client_state_config(w->object, &config);
		ni_client_state_config_debug(w->name, &config, "remove");
	}
}

static inline void
ni_ifworker_reset_client_state_scripts(ni_ifworker_t *w)
{
	ni_client_state_scripts_t scripts = { .node = NULL };

	if (w && w->object && !w->readonly) {
		ni_call_set_client_state_scripts(w->object, &scripts);
		ni_debug_application("%s: %s <%s> %s", w->name,
				"remove", NI_CLIENT_STATE_XML_NODE,
				NI_CLIENT_STATE_XML_SCRIPTS_NODE);
	}
}

static inline void
ni_ifworker_reset_client_state(ni_ifworker_t *w)
{
	ni_ifworker_reset_client_state_control(w);
	ni_ifworker_reset_client_state_config(w);
	ni_ifworker_reset_client_state_scripts(w);
}

static inline ni_bool_t
ni_ifworker_empty_config(ni_ifworker_t *w)
{
	ni_assert(w);
	return ni_string_empty(w->config.meta.origin);
}

static void
ni_ifworker_set_state(ni_ifworker_t *w, unsigned int new_state)
{
	unsigned int prev_state = w->fsm.state;

	if (prev_state != new_state) {
		if (w->progress.callback)
			w->progress.callback(w, new_state);

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

		if ((new_state == NI_FSM_STATE_DEVICE_READY) && w->object && !w->readonly) {
			ni_call_clear_event_filters(w->object);
			if (prev_state > new_state)
				ni_ifworker_reset_client_state(w);
			else
				ni_ifworker_update_client_state(w);
		}

		if (w->target_state == new_state)
			ni_ifworker_success(w);
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
ni_ifworker_advance_state(ni_ifworker_t *w, ni_event_t event_type)
{
	unsigned int new_state = NI_FSM_STATE_NONE;

	if (!w->fsm.wait_for)
		return;

	switch (event_type) {
	case NI_EVENT_DEVICE_DELETE:
		new_state = NI_FSM_STATE_DEVICE_EXISTS - 1;
		break;
	case NI_EVENT_DEVICE_DOWN:
		new_state = NI_FSM_STATE_DEVICE_UP - 1;
		break;
	case NI_EVENT_DEVICE_CREATE:
		new_state = NI_FSM_STATE_DEVICE_EXISTS;
		break;
	case NI_EVENT_DEVICE_READY:
		new_state = NI_FSM_STATE_DEVICE_READY;
		break;
	case NI_EVENT_DEVICE_UP:
		new_state = NI_FSM_STATE_DEVICE_UP;
		break;
	case NI_EVENT_LINK_UP:
		new_state = NI_FSM_STATE_LINK_UP;
		break;
	case NI_EVENT_LINK_DOWN:
		new_state = NI_FSM_STATE_LINK_UP - 1;
		break;
	case NI_EVENT_ADDRESS_ACQUIRED:
		new_state = NI_FSM_STATE_ADDRCONF_UP;
		break;
	case NI_EVENT_ADDRESS_RELEASED:
		new_state = NI_FSM_STATE_ADDRCONF_UP - 1;
		break;
	default:
		return;
	}

	if (new_state == w->fsm.wait_for->next_state) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
			"%s: advance fsm state %s by signal %s: %s in transition <%s..%s>",
			w->name, ni_ifworker_state_name(w->fsm.state),
			ni_objectmodel_event_to_signal(event_type),
			ni_ifworker_state_name(new_state),
			ni_ifworker_state_name(w->fsm.wait_for->from_state),
			ni_ifworker_state_name(w->fsm.wait_for->next_state));

		ni_ifworker_set_state(w, new_state);
	}
}

static ni_bool_t
ni_ifworker_revert_state(ni_ifworker_t *w, ni_event_t event)
{
	ni_fsm_transition_t *action;
	ni_fsm_state_t state;
	ni_bool_t redo = FALSE;

	switch (event) {
	case NI_EVENT_DEVICE_DOWN:
		/* until administrative DOWN is reverted */
		state = NI_FSM_STATE_DEVICE_UP;
		event = NI_EVENT_DEVICE_UP;
		/* or it is a slave which has to enslave */
		redo = w->masterdev != NULL;
		break;

	case NI_EVENT_LINK_DOWN:
		/* until the link (carrier) is UP again */
		state = NI_FSM_STATE_LINK_UP;
		event = NI_EVENT_LINK_UP;
		redo = TRUE;
		break;

	default:
		return FALSE;
	}

	/* target is initialized, state more advanced, worker is started */
	if (!w->target_state || state > w->fsm.state || !w->kickstarted)
		return FALSE;

	/* fsm actions are initialized to UP transitions */
	if (!w->fsm.action_table || ni_fsm_transition_is_down(w->fsm.action_table))
		return FALSE;

	/* find transition which will be completed by event */
	action = ni_fsm_transition_find(w->fsm.action_table, state - 1, state);
	if (!action || !action->bound)
		return FALSE;

	/* cancel all calbacks in the action table (if any) */
	ni_ifworker_cancel_action_table_callbacks(w);

	/* reset success/failure completion flags */
	w->done = w->failed = 0;

	/* revert worker fsm to the desired transition */
	w->fsm.state = action->from_state;
	w->fsm.next_action = action;

	if (redo) {
		/* and trigger to call the action again (wait link)*/
		w->fsm.wait_for = NULL;

		ni_debug_application("%s: reverted state to %s to execute the %s action",
			w->name, ni_ifworker_state_name(w->fsm.state),
			action->common.method_name);
	} else {
		/* in executed state to wait until the event arrives */
		w->fsm.wait_for = action;

		ni_debug_application("%s: reverted state to %s and waiting for %s event",
			w->name, ni_ifworker_state_name(w->fsm.state),
			ni_event_type_to_name(event));
	}
	return TRUE;
}

static void
ni_ifworker_refresh_client_state(ni_ifworker_t *w, ni_client_state_t *cs)
{
	if (!w || !cs)
		return;

	ni_client_state_debug(w->name, cs, "refresh");

	w->control.persistent = cs->control.persistent;
	w->control.usercontrol = cs->control.usercontrol;

	if (!w->state.node)
		w->state.node = xml_node_new(ni_ifworker_type_to_string(w->type), NULL);
	if (cs->scripts.node) {
		xml_node_t *scripts = xml_node_clone(cs->scripts.node, NULL);
		xml_node_replace_child(w->state.node, scripts);
	}
}

static void
ni_ifworker_generate_uuid(ni_ifworker_t *w)
{
	ni_uuid_t *uuid;

	if (!w)
		return;

	uuid = &w->config.meta.uuid;
	if (!xml_node_is_empty(w->config.node)) {
		if (ni_ifconfig_generate_uuid(w->config.node, uuid))
			return;

		ni_warn("cannot generate uuid for %s config - hashing failed",
			w->name);
	}

	/* Generate a temporary uuid only */
	ni_uuid_generate(uuid);
}

/*
 * Reset an ifworker's control information to its defaults
 */
static void
ni_ifworker_control_init(ni_ifworker_control_t *control)
{
	ni_string_dup(&control->mode, "boot");
	ni_string_dup(&control->boot_stage, NULL);
	control->persistent    = FALSE;
	control->usercontrol   = FALSE;
	control->link_required = NI_TRISTATE_DEFAULT;
	control->link_priority = 0;
	control->link_timeout  = NI_IFWORKER_INFINITE_SECONDS;
}

static void
ni_ifworker_control_destroy(ni_ifworker_control_t *control)
{
	ni_string_free(&control->mode);
	ni_string_free(&control->boot_stage);
}

ni_ifworker_control_t *
ni_ifworker_control_new(void)
{
	ni_ifworker_control_t *_control;

	_control = xcalloc(1, sizeof(*_control));
	ni_ifworker_control_init(_control);
	return _control;
}

ni_ifworker_control_t *
ni_ifworker_control_clone(const ni_ifworker_control_t *control)
{
	ni_ifworker_control_t *_control;

	_control = xcalloc(1, sizeof(*_control));
	ni_string_dup(&_control->mode,       control->mode);
	ni_string_dup(&_control->boot_stage, control->boot_stage);
	_control->persistent    = control->persistent;
	_control->usercontrol   = control->usercontrol;
	_control->link_required = control->link_required;
	_control->link_priority = control->link_priority;
	_control->link_timeout  = control->link_timeout;
	return _control;
}

void
ni_ifworker_control_free(ni_ifworker_control_t *control)
{
	if (control) {
		ni_ifworker_control_destroy(control);
		free(control);
	}
}

/*
 * Set usercontrol flag to the worker and to all of its children
 */
ni_bool_t
ni_ifworker_control_set_usercontrol(ni_ifworker_t *w, ni_bool_t value)
{
	unsigned int i;

	if (!w || w->failed)
		return FALSE;

	if (w->control.usercontrol == value)
		return TRUE;

	if (geteuid() != 0) {
		ni_error("%s: only root is allowed to %sset usercontrol flag",
			w->name, value ? "" : "un");
		return FALSE;
	}

	if (w->control.persistent == TRUE && value == TRUE) {
		ni_error("%s: unable to allow usercontrol on persistent interface",
			w->name);
		return FALSE;
	}

	w->control.usercontrol = value;
	for (i = 0; i < w->children.count; i++) {
		ni_ifworker_t *child = w->children.data[i];
		if (!ni_ifworker_control_set_usercontrol(child, value))
			return FALSE;
	}

	return TRUE;
}

/*
 * Set persistent flag to the worker and to all of its children
 */
ni_bool_t
ni_ifworker_control_set_persistent(ni_ifworker_t *w, ni_bool_t value)
{
	unsigned int i;

	if (!w || w->failed)
		return FALSE;

	if (w->control.persistent == value)
		return TRUE;

	if (geteuid() != 0) {
		ni_error("%s: only root is allowed to change persistent flag", w->name);
		return FALSE;
	}

	if (value == FALSE) {
		ni_error("%s: unable to unset persistent flag", w->name);
		return FALSE;
	}

	/* Now we can only set persistent */
	w->control.persistent = TRUE;

	/* When persistent is set disallow user control */
	ni_ifworker_control_set_usercontrol(w, FALSE);

	/* Set persistent and usercontrol in each child worker */
	for (i = 0; i < w->children.count; i++) {
		ni_ifworker_t *child = w->children.data[i];
		if (!ni_ifworker_control_set_persistent(child, TRUE))
			return FALSE;
	}

	return TRUE;
}

/*
 * Update an ifworker's control information from XML
 */
static void
ni_ifworker_control_from_xml(ni_ifworker_t *w, xml_node_t *ctrlnode)
{
	ni_ifworker_control_t *control;
	xml_node_t *linknode, *np;
	ni_bool_t val = FALSE;

	if (!w || xml_node_is_empty(ctrlnode))
		return;

	control = &w->control;
	if ((np = xml_node_get_child(ctrlnode, "mode")) != NULL)
		ni_string_dup(&control->mode, np->cdata);
	else if (!ni_string_eq(control->mode, "boot"))
		ni_string_dup(&control->mode, "boot");

	if ((np = xml_node_get_child(ctrlnode, "boot-stage")) != NULL)
		ni_string_dup(&control->boot_stage, np->cdata);
	else if (!ni_string_eq(control->boot_stage, NULL))
		ni_string_dup(&control->boot_stage, NULL);

	if ((np = xml_node_get_child(ctrlnode, NI_CLIENT_STATE_XML_PERSISTENT_NODE)) &&
	    !ni_parse_boolean(np->cdata, &val)) {
		ni_ifworker_control_set_persistent(w, val);
	}
	if ((np = xml_node_get_child(ctrlnode, NI_CLIENT_STATE_XML_USERCONTROL_NODE)) &&
	    !ni_parse_boolean(np->cdata, &val)) {
		ni_ifworker_control_set_usercontrol(w, val);
	}

	control->link_priority = 0;
	control->link_required = NI_TRISTATE_DEFAULT;
	control->link_timeout  = NI_IFWORKER_INFINITE_SECONDS;
	if ((linknode = xml_node_get_child(ctrlnode, "link-detection")) != NULL) {
		if ((np = xml_node_get_child(linknode, "timeout")) != NULL) {
			if (ni_parse_seconds_timeout(np->cdata, &control->link_timeout)
			||  control->link_timeout == 0)
				control->link_timeout = NI_IFWORKER_INFINITE_SECONDS;
		}
		if ((np = xml_node_get_child(linknode, "priority"))) {
			ni_parse_uint(np->cdata, &control->link_priority, 10);
		}
		if ((np = xml_node_get_child(linknode, "require-link"))) {
			if (ni_string_eq(np->cdata, "true"))
				ni_tristate_set(&control->link_required, TRUE);
			else
			if (ni_string_eq(np->cdata, "false"))
				 ni_tristate_set(&control->link_required, FALSE);
		}
	}
}

/*
 * Set the configuration of an ifworker
 */
static void
ni_ifworker_set_config_origin(ni_ifworker_t *w, const char *new_origin)
{
	if (!w || ni_string_eq(w->config.meta.origin, new_origin))
		return;

	ni_string_dup(&w->config.meta.origin, new_origin);
}

static void
ni_ifworker_extra_waittime_from_xml(ni_ifworker_t *w)
{
	unsigned int extra_waittime = 0;
	const xml_node_t *brnode;

	if (!w || xml_node_is_empty(w->config.node))
		return;

	/* Adding bridge dependent values (STP, Forwarding times) */
	if ((brnode = xml_node_get_child(w->config.node, "bridge")))
		extra_waittime += ni_bridge_waittime_from_xml(brnode);

	w->extra_waittime = extra_waittime;
}

ni_iftype_t
ni_ifworker_iftype_from_xml(xml_node_t *config)
{
	ni_iftype_t iftype;

	if (!xml_node_is_empty(config)) {
		for (iftype = 0; iftype < __NI_IFTYPE_MAX; iftype++) {
			const char *iftype_name = ni_linktype_type_to_name(iftype);

			if (ni_string_empty(iftype_name))
				continue;

			if (xml_node_get_child(config, iftype_name))
				return iftype;
		}
	}

	return NI_IFTYPE_UNKNOWN;
}

ni_bool_t
ni_ifworker_set_config(ni_ifworker_t *w, xml_node_t *ifnode, const char *config_origin)
{
	xml_node_t *child;

	if (!w)
		return FALSE;

	xml_node_free(w->config.node);
	w->config.node = NULL;
	ni_client_state_config_reset(&w->config.meta);
	if (xml_node_is_empty(ifnode))
		return TRUE;

	if (!(w->config.node = xml_node_clone_ref(ifnode)))
		return FALSE;

	if ((child = xml_node_get_child(ifnode, NI_CLIENT_STATE_XML_NODE))) {
		/* cleanup obsolete stuff in case of attic configs */
		xml_node_detach(child);
		xml_node_free(child);
	}

	ni_ifworker_set_config_origin(w, config_origin);

	if ((child = xml_node_get_child(ifnode, "control")))
		ni_ifworker_control_from_xml(w, child);

	if ((child = xml_node_get_child(ifnode, "dependencies")))
		ni_ifworker_set_dependencies_xml(w, child);

	w->iftype = ni_ifworker_iftype_from_xml(ifnode);
	if (w->iftype == NI_IFTYPE_UNKNOWN) {
		if (ni_string_eq(w->name, ni_linktype_type_to_name(NI_IFTYPE_OVS_SYSTEM)))
			w->iftype = NI_IFTYPE_OVS_SYSTEM;
	}
	ni_ifworker_extra_waittime_from_xml(w);
	ni_ifworker_generate_uuid(w);
	return TRUE;
}

ni_ifworker_t *
ni_fsm_worker_identify(ni_fsm_t *fsm, const xml_node_t *node, const char *origin,
			ni_ifworker_type_t *type, const char **ifname)
{
	const char *namespace;
	xml_node_t *name;

	if (!fsm || !type || xml_node_is_empty(node))
		return NULL;

	*type = ni_ifworker_type_from_string(node->name);
	if (*type == NI_IFWORKER_TYPE_NONE)
		return NULL;

	if (!(name = xml_node_get_child(node, "name")))
		return NULL;

	if ((namespace = xml_node_get_attr(name, "namespace"))) {
		if (ifname)
			*ifname = NULL;
		return __ni_ifworker_identify_device(fsm, namespace, name, *type, origin);
	} else
	if (!ni_string_empty(name->cdata)) {
		if (ifname)
			*ifname = name->cdata;
		return ni_fsm_ifworker_by_name(fsm, *type, name->cdata);
	}

	return NULL;
}

/*
 * Given an XML document, build interface and modem objects, and policies from it.
 */
ni_ifworker_t *
ni_fsm_workers_from_xml(ni_fsm_t *fsm, xml_node_t *node, const char *origin)
{
	ni_ifworker_type_t type = NI_IFWORKER_TYPE_NONE;
	const char *ifname = NULL;
	ni_ifworker_t *w = NULL;

	if (!fsm || xml_node_is_empty(node))
		return NULL;

	if (!(w = ni_fsm_worker_identify(fsm, node, origin, &type, &ifname))) {
		if (!ifname) {
			ni_error("%s: ignoring unknown %s configuration",
				xml_node_location(node), node->name);
			return NULL;
		}
		if (!(w = ni_ifworker_new(&fsm->workers, type, ifname))) {
			ni_error("%s: cannot allocate worker for '%s' configuration",
				xml_node_location(node), node->name);
			return NULL;
		}
	}

	if (!ni_ifworker_set_config(w, node, origin)) {
		ni_error("%s: cannot apply configuration to %s '%s'",
				xml_node_location(node), node->name, w->name);
		return NULL;
	}

	return w;
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
	ni_ifworker_t *cw;

	if (req->user_data == NULL)
		return TRUE;

	if (!(cw = ni_ifworker_resolve_reference(fsm, devnode, NI_IFWORKER_TYPE_NETDEV, w->name)))
		return FALSE;

	ni_debug_application("%s: resolved reference to subordinate device %s", w->name, cw->name);
	if (!ni_ifworker_add_child(w, cw, devnode, FALSE, TRUE))
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
	ni_ifworker_t *cw;

	if (req->user_data == NULL)
		return TRUE;

	if (!(cw = ni_ifworker_resolve_reference(fsm, devnode, NI_IFWORKER_TYPE_MODEM, w->name)))
		return FALSE;

	ni_debug_application("%s: resolved reference to subordinate device %s", w->name, cw->name);
	if (!ni_ifworker_add_child(w, cw, devnode, FALSE, TRUE))
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
 * Handle link-detection timeout
 */
static void
ni_ifworker_link_detection_timeout(const ni_timer_t *timer, ni_fsm_timer_ctx_t *tcx)
{
	ni_ifworker_t *w = tcx->worker;
	ni_fsm_transition_t *action;

	if (w->fsm.secondary_timer != timer) {
		ni_error("%s(%s) called with unexpected timer", __func__, w->name);
		return;
	}
	w->fsm.secondary_timer = NULL;
	tcx->fsm->timeout_count++;

	if ((action = w->fsm.wait_for) == NULL)
		return;
	if (w->fsm.state != NI_FSM_STATE_DEVICE_UP)
		return;

	if (ni_tristate_is_disabled(w->control.link_required)) {
		ni_warn("%s: link did not came up in time, proceeding anyway", w->name);
		ni_ifworker_cancel_callbacks(w, &action->callbacks);
		ni_ifworker_set_state(w, action->next_state);
	} else {
		ni_warn("%s: link did not came up in time, waiting for event", w->name);
	}
}

/*
 * Handle dependencies that check for a specific child state.
 */
typedef struct ni_ifworker_check_state_req_check	ni_ifworker_check_state_req_check_t;
typedef struct ni_ifworker_check_state_req		ni_ifworker_check_state_req_t;
typedef struct ni_ifworker_require_resolver		ni_ifworker_require_resolver_t;

struct ni_ifworker_require_resolver {
	ni_ifworker_type_t			cwtype;
	xml_node_t *				cwnode;
	xml_node_t *				cwmeta;
};
struct ni_ifworker_check_state_req_check {
	ni_ifworker_check_state_req_check_t *	next;
	ni_ifworker_t *				worker;
	ni_ifworker_require_resolver_t *	resolver;
	ni_uint_range_t				state;
};
struct ni_ifworker_check_state_req {
	char *					method;
	ni_ifworker_check_state_req_check_t *	check;
};

static ni_ifworker_require_resolver_t *		ni_ifworker_require_resolver_new(ni_ifworker_type_t type,
								xml_node_t *node, xml_node_t *meta);
static void					ni_ifworker_require_resolver_free(ni_ifworker_require_resolver_t *);

static void					ni_ifworker_check_state_req_free(ni_fsm_require_t *);
static inline ni_ifworker_check_state_req_t *	ni_ifworker_check_state_req_cast(ni_fsm_require_t *req)
{
	if (!req || req->destroy_fn != ni_ifworker_check_state_req_free)
		return NULL;
	return (ni_ifworker_check_state_req_t *)req->user_data;
}

static inline ni_ifworker_check_state_req_check_t *
ni_ifworker_config_check_state_req_check_new(ni_ifworker_t *cw, ni_ifworker_type_t cwtype,
					xml_node_t *cwnode, xml_node_t *cwmeta,
					unsigned int min_state, unsigned int max_state)
{
	ni_ifworker_check_state_req_check_t *check;

	check = xcalloc(1, sizeof(*check));
	check->worker = cw ?  ni_ifworker_get(cw) : NULL;
	check->resolver = ni_ifworker_require_resolver_new(cwtype, cwnode, cwmeta);
	check->state.min = min_state;
	check->state.max = max_state;
	return check;
}

static inline ni_ifworker_check_state_req_check_t *
ni_ifworker_system_check_state_req_check_new(ni_ifworker_t *cw,
					unsigned int min_state, unsigned int max_state)
{
	ni_ifworker_check_state_req_check_t *check;

	check = xcalloc(1, sizeof(*check));
	check->worker = cw ?  ni_ifworker_get(cw) : NULL;
	check->resolver = NULL;
	check->state.min = min_state;
	check->state.max = max_state;
	return check;
}

static inline void
ni_ifworker_check_state_req_check_free(ni_ifworker_check_state_req_check_t *check)
{
	if (check) {
		if (check->resolver) {
			ni_ifworker_require_resolver_free(check->resolver);
			check->resolver = NULL;
		}
		if (check->worker) {
			ni_ifworker_release(check->worker);
			check->worker = NULL;
		}
		free(check);
	}
}

static ni_bool_t
ni_ifworker_check_state_req_check_find_worker(ni_ifworker_check_state_req_t *csr, ni_ifworker_t *cw)
{
	ni_ifworker_check_state_req_check_t *check;

	for (check = csr->check; check; check = check->next) {
		if (check->worker == cw)
			return TRUE;
	}
	return FALSE;
}

static inline void
ni_ifworker_check_state_req_check_list_destroy(ni_ifworker_check_state_req_t *csr)
{
	ni_ifworker_check_state_req_check_t *check;

	while ((check = csr->check)) {
		csr->check = check->next;
		ni_ifworker_check_state_req_check_free(check);
	}
}

static inline void
ni_ifworker_check_state_req_check_list_append(ni_ifworker_check_state_req_t *csr,
					ni_ifworker_check_state_req_check_t *check)
{
	ni_ifworker_check_state_req_check_t **list = &csr->check;

	while (*list)
		list = &(*list)->next;
	*list = check;
}

static ni_ifworker_t *
ni_ifworker_require_netif_resolve(ni_fsm_t *fsm, ni_ifworker_t *w, ni_ifworker_type_t type,
					xml_node_t *node, xml_node_t *meta)
{
	ni_stringbuf_t path = NI_STRINGBUF_INIT_DYNAMIC;
	ni_bool_t supplemental = FALSE;
	ni_bool_t subordinate = FALSE;
	ni_bool_t shared = FALSE;
	ni_ifworker_t *cw;
	const char *attr;

	if (!(cw = ni_ifworker_resolve_reference(fsm, node, type, w->name))) {
		xml_node_get_path(&path, node, xml_node_find_parent(node, ni_ifworker_type_to_string(w->type)));
		ni_debug_application("%s: cannot resolve reference %s to subordinate device yet",
					w->name, path.string);
		ni_stringbuf_destroy(&path);
		return NULL;
	}

	/* supplemental is an additional reference, e.g. hidden inside of openvswitch */
	if ((attr = xml_node_get_attr(meta, "supplemental")))
		supplemental = ni_string_eq(attr, "true");

	/* subordinate is a slave -> master reference, counterpart of shared=false */
	if ((attr = xml_node_get_attr(meta, "subordinate")))
		subordinate = ni_string_eq(attr, "true");
	if (!subordinate && (attr = xml_node_get_attr(meta, "shared")))
		shared = ni_string_eq(attr, "true");

	xml_node_get_path(&path, node, xml_node_find_parent(node, ni_ifworker_type_to_string(w->type)));
	ni_debug_application("%s: resolved %sreference %s to subordinate device %s", w->name,
			subordinate ? "subordinate " : (shared ? "shared " : ""),
			path.string, cw->name);
	ni_stringbuf_destroy(&path);

	if (subordinate) {
		/* slave w refers to it's master in cw */
		ni_ifworker_add_child(cw, w, node, FALSE, supplemental);
	} else
	if (shared) {
		/* vlan w refers to it's lower in cw   */
		ni_ifworker_add_child(w, cw, node, TRUE, supplemental);
	} else {
		/* master w refers to it's slave in cw */
		ni_ifworker_add_child(w, cw, node, FALSE, supplemental);
	}

	return cw;
}

static ni_ifworker_t *
ni_ifworker_require_resolve(ni_fsm_t *fsm, ni_ifworker_t *w, ni_ifworker_type_t type,
		xml_node_t *node, xml_node_t *meta)
{
	switch (type) {
	case NI_IFWORKER_TYPE_NETDEV:
		return ni_ifworker_require_netif_resolve(fsm, w, type, node, meta);
#ifdef MODEM
	case NI_IFWORKER_TYPE_MODEM:
#endif
	default:
		return NULL;
	}
}

static void
ni_ifworker_require_resolver_free(ni_ifworker_require_resolver_t *resolver)
{
	if (resolver) {
		if (resolver->cwmeta) {
			xml_node_free(resolver->cwmeta);
			resolver->cwmeta = NULL;
		}
		if (resolver->cwnode) {
			xml_node_free(resolver->cwnode);
			resolver->cwnode = NULL;
		}
		free(resolver);
	}
}

static ni_ifworker_require_resolver_t *
ni_ifworker_require_resolver_new(ni_ifworker_type_t type, xml_node_t *node, xml_node_t *meta)
{
	ni_ifworker_require_resolver_t *resolver;

	resolver = xcalloc(1, sizeof(*resolver));
	if (resolver) {
		resolver->cwtype = type;
		resolver->cwnode = xml_node_clone_ref(node);
		resolver->cwmeta = xml_node_clone_ref(meta);
	}
	return resolver;
}

static ni_bool_t
ni_ifworker_config_check_state_req_test(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_require_t *req)
{
	ni_ifworker_check_state_req_check_t *check;
	ni_ifworker_check_state_req_t *csr;
	ni_bool_t all_required_ok = TRUE;
	unsigned int state_reached = 0;
	ni_ifworker_t *cw;

	if (!(csr = ni_ifworker_check_state_req_cast(req)))
		return FALSE;

	for (check = csr->check; check; check = check->next) {
		if (check->worker || !check->resolver)
			continue;

		cw = ni_ifworker_require_resolve(fsm, w, check->resolver->cwtype,
				check->resolver->cwnode,  check->resolver->cwmeta);
		if (cw) {
			/* switch over to the worker */
			check->worker = ni_ifworker_get(cw);
			ni_ifworker_require_resolver_free(check->resolver);
			check->resolver = NULL;
		}
	}

	for (check = csr->check; check; check = check->next) {
		ni_fsm_state_t wait_for_state;
		ni_bool_t required = FALSE;

		if (!(cw = check->worker))
			continue;

		if (ni_string_eq(cw->control.mode, "off")) {
			ni_debug_application("%s: ignoring state requirements for disabled worker %s",
					w->name, cw->name);
			continue;
		}
		if (ni_string_eq(cw->control.mode, "manual") && !ni_ifworker_active(cw)) {
			ni_debug_application("%s: ignoring state requirements for inactive worker %s",
					w->name, cw->name);
			continue;
		}

		if (ni_string_eq(cw->control.mode, "boot") ||
		    ni_string_eq(cw->control.mode, "manual")) /* explicitly requested */
			required = TRUE;

		if (cw->failed) {
			ni_debug_application("%s: %sworker %s failed", w->name,
					required ? "required " : "", cw->name);
			if (required)
				all_required_ok = FALSE;
			continue;
		}

		if (cw->fsm.state < check->state.min) {
			wait_for_state = check->state.min;
		} else
		if (cw->fsm.state > check->state.max) {
			wait_for_state = check->state.max;
		} else {
			ni_debug_application("%s: %sworker %s reached %s state %s..%s",
					w->name, required ? "required " : "", cw->name,
					csr->method,
					ni_ifworker_state_name(check->state.min),
					ni_ifworker_state_name(check->state.max));
			state_reached++;
			continue;
		}

		/*
		 * Manual tweak: When the cw device should be our master, is UP (thus
		 * already configured), but not active/picked up by ifup, because not
		 * directly related to current ifup run, just continue with enslave.
		 * See bsc#948423 (comment 6ff) for more details.
		 */
		if (w->masterdev == cw && !ni_ifworker_active(cw) &&
		    ni_netdev_device_is_up(cw->device) && w->device &&
		    (ni_string_empty(w->device->link.masterdev.name) ||
		     ni_string_eq(w->device->link.masterdev.name, cw->device->name))) {
			ni_debug_application("%s: master %s is ready to enslave",
					w->name, cw->name);
			state_reached++;
			continue;
		}

		ni_debug_application("%s: waiting for %sworker %s to reach %s state %s",
				w->name, required ? "required " : "", cw->name,
				csr->method,
				ni_ifworker_state_name(wait_for_state));

		if (required)
			all_required_ok = FALSE;
	}

	return all_required_ok && state_reached > 0;
}

static ni_bool_t
ni_ifworker_system_check_state_req_test(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_require_t *req)
{
	ni_ifworker_check_state_req_check_t *check;
	ni_ifworker_check_state_req_t *csr;
	ni_bool_t all_required_ok = TRUE;
	ni_ifworker_t *cw;

	if (!(csr = ni_ifworker_check_state_req_cast(req)))
		return FALSE;

	for (check = csr->check; check; check = check->next) {
		ni_fsm_state_t wait_for_state;

		if (!(cw = check->worker))
			continue;

		if (!ni_fsm_ifworker_by_ifindex(fsm, cw->ifindex)) {
			ni_debug_application("%s: worker %s has been deleted",
					w->name, cw->name);
			continue;
		}
		if (!cw->device) {
			ni_debug_application("%s: worker %s device has been deleted",
					w->name, cw->name);
			continue;
		}
		if (cw->failed) {
			ni_debug_application("%s: worker %s failed", w->name, cw->name);
			continue;
		}

		if (cw->fsm.state < check->state.min) {
			wait_for_state = check->state.min;
		} else if (cw->fsm.state > check->state.max) {
			wait_for_state = check->state.max;
		} else {
			ni_debug_application("%s: worker %s reached %s state %s..%s",
					w->name, cw->name, csr->method,
					ni_ifworker_state_name(check->state.min),
					ni_ifworker_state_name(check->state.max));
			continue;
		}

		ni_debug_application("%s: waiting for worker %s to reach %s state %s",
				w->name, cw->name, csr->method,
				ni_ifworker_state_name(wait_for_state));
		all_required_ok = FALSE;
	}

	return all_required_ok;
}

static void
ni_ifworker_check_state_req_free(ni_fsm_require_t *req)
{
	ni_ifworker_check_state_req_t *csr;

	if ((csr = ni_ifworker_check_state_req_cast(req))) {
		ni_ifworker_check_state_req_check_list_destroy(csr);
		ni_string_free(&csr->method);
		free(csr);
	}
	if (req)
		req->user_data = NULL;
}

static ni_fsm_require_t *
ni_ifworker_check_state_req_new(ni_ifworker_check_state_req_check_t *check,
		const char *method, ni_fsm_require_fn_t *test_fn)
{
	ni_ifworker_check_state_req_t *csr;
	ni_fsm_require_t *req;

	if (!check || ni_string_empty(method))
		return NULL;

	csr = xcalloc(1, sizeof(*csr));
	ni_string_dup(&csr->method, method);

	ni_ifworker_check_state_req_check_list_append(csr, check);

	req = ni_fsm_require_new(test_fn, ni_ifworker_check_state_req_free);
	req->user_data = csr;
	return req;
}

static void
ni_ifworker_add_config_check_state_req(ni_ifworker_t *w, const char *method, ni_ifworker_t *cw,
			ni_ifworker_type_t cwtype, xml_node_t *cwnode, xml_node_t *cwmeta,
			unsigned int min_state, unsigned int max_state)
{
	ni_ifworker_check_state_req_check_t *check;
	ni_fsm_require_t *req;

	for (req = w->fsm.check_state_req_list; req; req = req->next) {
		ni_ifworker_check_state_req_t *csr;

		if (!(csr = ni_ifworker_check_state_req_cast(req)))
			continue;

		if (!ni_string_eq(csr->method, method))
			continue;

		if (cw && ni_ifworker_check_state_req_check_find_worker(csr, cw))
			continue; /* try to not add worker check twice */

		check = ni_ifworker_config_check_state_req_check_new(cw,
				cwtype, cwnode, cwmeta, min_state, max_state);
		ni_ifworker_check_state_req_check_list_append(csr, check);
		return;
	}

	check = ni_ifworker_config_check_state_req_check_new(cw,
			cwtype, cwnode, cwmeta, min_state, max_state);
	req = ni_ifworker_check_state_req_new(check, method,
			ni_ifworker_config_check_state_req_test);
	ni_fsm_require_list_insert(&w->fsm.check_state_req_list, req);
}

static void
ni_ifworker_add_system_check_state_req(ni_ifworker_t *w, const char *method,
		ni_ifworker_t *cw, unsigned int min_state, unsigned int max_state)
{
	ni_ifworker_check_state_req_check_t *check;
	ni_fsm_require_t *req;

	for (req = w->fsm.check_state_req_list; req; req = req->next) {
		ni_ifworker_check_state_req_t *csr;

		if (!(csr = ni_ifworker_check_state_req_cast(req)))
			continue;

		if (!ni_string_eq(csr->method, method))
			continue;

		if (cw && ni_ifworker_check_state_req_check_find_worker(csr, cw))
			continue; /* try to not add worker check twice */

		check = ni_ifworker_system_check_state_req_check_new(cw,
				min_state, max_state);
		ni_ifworker_check_state_req_check_list_append(csr, check);
		return;
	}

	check = ni_ifworker_system_check_state_req_check_new(cw,
			min_state, max_state);
	req = ni_ifworker_check_state_req_new(check, method,
			ni_ifworker_system_check_state_req_test);
	ni_fsm_require_list_insert(&w->fsm.check_state_req_list, req);
}

static void
ni_ifworker_get_check_state_reqs_for_method(ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	ni_fsm_require_t **list, *req;

	for (list = &w->fsm.check_state_req_list; (req = *list) != NULL; ) {
		ni_ifworker_check_state_req_check_t *check;
		ni_ifworker_check_state_req_t *csr;

		if (!(csr = ni_ifworker_check_state_req_cast(req)))
			continue;

		if (!ni_string_eq(csr->method, action->common.method_name)) {
			list = &req->next;
			continue;
		}

		for (check = csr->check; check; check = check->next) {
			ni_ifworker_t *cw = check->worker;

			ni_debug_application("%s: %s transition requires %s worker to be in state %s..%s",
				w->name, csr->method, cw ? cw->name : "unresolved",
				ni_ifworker_state_name(check->state.min),
				ni_ifworker_state_name(check->state.max));
		}

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

	ni_debug_application("%s: checking %s requirements for %s -> %s transition",
			w->name, action->common.method_name,
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
__ni_ifworker_identify_device(ni_fsm_t *fsm, const char *namespace, const xml_node_t *devnode, ni_ifworker_type_t type, const char *origin)
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
		return ni_fsm_ifworker_by_ifindex(fsm, ifindex);
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
				origin, found->name, found->object_path);
	return found;
}

static ni_ifworker_t *
ni_ifworker_identify_device(ni_fsm_t *fsm, const xml_node_t *devnode, ni_ifworker_type_t type, const char *origin)
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

		found = __ni_ifworker_identify_device(fsm, query->name, query, type, origin);
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
				origin, best->name, best->object_path);
	return best;
}

ni_ifworker_type_t
ni_ifworker_type_from_string(const char *s)
{
	if (ni_string_eq(s, NI_CLIENT_IFCONFIG))
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

ni_ifworker_type_t
ni_ifworker_type_from_object_path(const char *path, const char **suffix)
{
	if (ni_string_startswith(path, NI_OBJECTMODEL_NETIF_LIST_PATH "/")) {
		if (suffix)
			*suffix = path + sizeof(NI_OBJECTMODEL_NETIF_LIST_PATH);
		return NI_IFWORKER_TYPE_NETDEV;
	}
	if (ni_string_startswith(path, NI_OBJECTMODEL_MODEM_LIST_PATH "/")) {
		if (suffix)
			*suffix = path + sizeof(NI_OBJECTMODEL_MODEM_LIST_PATH);
		return NI_IFWORKER_TYPE_MODEM;
	}
	return NI_IFWORKER_TYPE_NONE;
}

/*
 * Get all interfaces matching some user-specified criteria
 */
static ni_bool_t
ni_fsm_ifmatch_worker_name(const ni_ifmatcher_t *match, const ni_ifworker_t *w)
{
	/*
	 * Note: match->name==NULL is matching all worker ("ifup all")
	 */
	return !match->name || ni_string_eq(w->name, match->name);
}

static ni_bool_t
ni_fsm_ifmatch_worker_type(const ni_ifmatcher_t *match, const ni_ifworker_t *w,
		ni_ifworker_type_t type)
{
	if (w->type != type) {
		/*
		 * without enabled modem support this is a noop;
		 * even with, we probably have to match modems
		 * separately as dependencies … we'll see
		 */
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
			"skipping '%s' %s: type is not %s",
			w->name, ni_ifworker_type_to_string(w->type),
			ni_ifworker_type_to_string(type));
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_netif_worker(const ni_ifmatcher_t *match, const ni_ifworker_t *w)
{
	/*
	 * well, we (still) don't handle modem workers yet and
	 * most probably never via ifup|ifdown|ifreload <modem>
	 * but either as reference/dependency or another action
	 * and probably also different matches.
	 */
	return ni_fsm_ifmatch_worker_type(match, w, NI_IFWORKER_TYPE_NETDEV);
}

static ni_bool_t
ni_fsm_ifmatch_dead_worker(const ni_ifmatcher_t *match, const ni_ifworker_t *w,
		ni_log_fn_t *logit)
{
	if (w->dead) {
		/* seems to be not used any more ... */
		logit("skipping '%s' %s: marked \"dead\"",
			w->name, ni_ifworker_type_to_string(w->type));
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_startmode(const ni_ifmatcher_t *match, const ni_ifworker_t *w,
		ni_log_fn_t *logit)
{
	if (match->ifdown)
		return TRUE;

	if (match->mode && !ni_string_eq(w->control.mode, match->mode)) {
		logit("skipping '%s' %s: control/start mode is \"%s\"",
			w->name, ni_ifworker_type_to_string(w->type),
			w->control.mode);
		return FALSE;
	}

	/* ignore_startmode is a disabled testing hack */
	if (match->ignore_startmode)
		return TRUE;

	if (ni_string_eq_nocase(w->control.mode, "off")) {
		logit("skipping '%s' %s: disabled in the configuration",
			w->name, ni_ifworker_type_to_string(w->type));
		return FALSE;
	}
	if (!match->name && ni_string_eq_nocase(w->control.mode, "manual")) {
		logit("skipping '%s' %s: control/start mode is \"%s\"",
			w->name, ni_ifworker_type_to_string(w->type),
			w->control.mode);
		return FALSE;
	}

	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_persistent(const ni_ifmatcher_t *match, const ni_ifworker_t *w,
		ni_log_fn_t *logit)
{
	const ni_client_state_t *cs = w->device ? w->device->client_state : NULL;

	/* skipping ifworkers of interfaces in persistent mode */
	if (!match->allow_persistent && cs && cs->control.persistent) {
		logit("skipping '%s' %s: persistent mode is on",
			w->name, ni_ifworker_type_to_string(w->type));
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_user_controlled(const ni_ifmatcher_t *match, const ni_ifworker_t *w,
		ni_log_fn_t *logit)
{
	/* skipping ifworkers of interfaces user must not control */
	if (!w->control.usercontrol && geteuid() != 0) {
		logit("skipping '%s' %s: user control is not allowed",
			w->name, ni_ifworker_type_to_string(w->type));
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_boot_stage(const ni_ifmatcher_t *match, const ni_ifworker_t *w,
		ni_log_fn_t *logit)
{
	if (match->boot_stage && !ni_string_eq(w->control.boot_stage, match->boot_stage)) {
		logit("skipping '%s' %s: enabled in boot stage '%s'",
			w->name, ni_ifworker_type_to_string(w->type),
			w->control.boot_stage);
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_skip_origin(const ni_ifmatcher_t *match, const ni_ifworker_t *w,
		ni_log_fn_t *logit)
{
	if (match->skip_origin) {
		ni_netdev_t *dev = w->device;
		ni_client_state_t *cs = dev ? dev->client_state : NULL;
		const char *origin = cs ? cs->config.origin : NULL;

		if (ni_string_startswith(origin, match->skip_origin)) {
			logit("skipping '%s' %s: config origin is '%s'",
				w->name, ni_ifworker_type_to_string(w->type),
				origin);
			return FALSE;
		}
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_activated(const ni_ifmatcher_t *match, const ni_ifworker_t *w,
		ni_log_fn_t *logit)
{
	/*
	 * Skip active means omit running and succeeded worker
	 * Hmm... obsolete direct setup without nanny only
	 */
	if (match->skip_active && w->kickstarted &&
	    (ni_ifworker_is_running(w) || ni_ifworker_has_succeeded(w))) {
		logit("skipping '%s' %s: already active",
			w->name, ni_ifworker_type_to_string(w->type));
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_worker_configured(const ni_ifmatcher_t *match, const ni_ifworker_t *w)
{
	/* skipping ifworkers without (xml) configuration to apply */
	if (match->require_config && !w->config.node) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
			"skipping '%s' %s: no configuration to apply",
			w->name, ni_ifworker_type_to_string(w->type));
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_device_configured(const ni_ifmatcher_t *match, const ni_ifworker_t *w)
{
	ni_client_state_t *cs = w->device ? w->device->client_state : NULL;

	/* skipping ifworkers of interfaces not configured in the past */
	if (match->require_configured && (!cs || ni_string_empty(cs->config.origin))) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
				"skipping '%s' %s: not configured by wicked",
				w->name, ni_ifworker_type_to_string(w->type));
		return FALSE;
	}

	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_config_changed(const ni_ifmatcher_t *match, const ni_ifworker_t *w)
{
	const ni_client_state_t *cs;
	ni_bool_t worker_configured;
	ni_bool_t device_configured;

	cs = w->device ? w->device->client_state : NULL;
	device_configured = cs && !ni_string_empty(cs->config.origin);
	worker_configured = !!w->config.node;

	if (device_configured && worker_configured) {
		if (!ni_uuid_equal(&cs->config.uuid, &w->config.meta.uuid))
			return TRUE;
	} else {
		if (device_configured != worker_configured)
			return TRUE;
	}

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
		"skipping '%s' %s: configuration unchanged", w->name,
		ni_ifworker_type_to_string(w->type));
	return FALSE;
}

static ni_bool_t
ni_fsm_ifmatch_conditions(const ni_ifmatcher_t *match, const ni_ifworker_t *w,
		ni_log_fn_t *logit)
{
	if (!ni_fsm_ifmatch_dead_worker(match, w, logit))
		return FALSE;
	if (!ni_fsm_ifmatch_startmode(match, w, logit))
		return FALSE;
	if (!ni_fsm_ifmatch_persistent(match, w, logit))
		return FALSE;
	if (!match->ifreload && !ni_fsm_ifmatch_worker_configured(match, w))
		return FALSE;
	if (!match->ifreload && !ni_fsm_ifmatch_device_configured(match, w))
		return FALSE;
	if (!ni_fsm_ifmatch_user_controlled(match, w, logit))
		return FALSE;
	if (!ni_fsm_ifmatch_boot_stage(match, w, logit))
		return FALSE;
	if (!ni_fsm_ifmatch_skip_origin(match, w, logit))
		return FALSE;
	if (!ni_fsm_ifmatch_activated(match, w, logit))
		return FALSE;
	return TRUE;
}

static const char *		ni_ifworker_guard_print(ni_stringbuf_t *,
						const ni_ifworker_array_t *,
						const char *);

static ni_bool_t		ni_ifworker_references_ok(
						const ni_ifworker_array_t *,
						ni_ifworker_t *);

static ni_bool_t		ni_fsm_ifmatch_pull_up(ni_fsm_t *,
						ni_ifmatcher_t *,
						ni_ifworker_array_t *,
						ni_ifworker_array_t *,
						ni_log_fn_t *,
						ni_ifworker_t *,
						ni_bool_t, ni_bool_t,
						ni_bool_t, ni_bool_t,
						ni_bool_t);

static ni_bool_t
ni_fsm_ifmatch_pull_up_ports(ni_fsm_t *fsm, ni_ifmatcher_t *match,
		ni_ifworker_array_t *matching, ni_ifworker_array_t *guard,
		ni_log_fn_t *logit, ni_ifworker_t *master,
		ni_bool_t ports, ni_bool_t links,
		ni_bool_t changed)
{
	ni_ifworker_t *port;
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		port = fsm->workers.data[i];

		if (port->masterdev != master)
			continue;

		/* desired/requested, but not mandatory */
		ni_fsm_ifmatch_pull_up(fsm, match, matching, guard, logit,
				port, FALSE, TRUE, ports, links, changed);
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_pull_up_links(ni_fsm_t *fsm, ni_ifmatcher_t *match,
		ni_ifworker_array_t *matching, ni_ifworker_array_t *guard,
		ni_log_fn_t *logit, ni_ifworker_t *lower,
		ni_bool_t ports, ni_bool_t links,
		ni_bool_t changed)
{
	ni_ifworker_t *link;
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		link = fsm->workers.data[i];

		if (link->lowerdev != lower)
			continue;

		/* desired/requested, but not mandatory */
		ni_fsm_ifmatch_pull_up(fsm, match, matching, guard, logit,
				link, TRUE, FALSE, ports, links, changed);
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_pull_up_lower(ni_fsm_t *fsm, ni_ifmatcher_t *match,
		ni_ifworker_array_t *matching, ni_ifworker_array_t *guard,
		ni_log_fn_t *logit, ni_ifworker_t *w,
		ni_bool_t master, ni_bool_t lower,
		ni_bool_t ports, ni_bool_t links,
		ni_bool_t changed)
{
	if (!w->lowerdev)
		return TRUE; /* we don't have a lower */

	if (!ni_fsm_ifmatch_pull_up(fsm, match, matching, guard, logit,
			w->lowerdev, master, lower, ports, FALSE, changed)) {

		logit("skipping '%s' %s: unable to setup lower %s '%s'",
			w->name, ni_ifworker_type_to_string(w->type),
			ni_ifworker_type_to_string(w->lowerdev->type),
			w->lowerdev->name);
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_pull_up_master(ni_fsm_t *fsm, ni_ifmatcher_t *match,
		ni_ifworker_array_t *matching, ni_ifworker_array_t *guard,
		ni_log_fn_t *logit, ni_ifworker_t *w,
		ni_bool_t master, ni_bool_t lower,
		ni_bool_t ports, ni_bool_t links,
		ni_bool_t changed)
{
	if (!w->masterdev)
		return TRUE; /* we don't have a master */

	if (!ni_fsm_ifmatch_pull_up(fsm, match, matching, guard, logit,
			w->masterdev, master, lower, FALSE, links, changed)) {

		logit("skipping '%s' %s: unable to setup master %s '%s'",
			w->name, ni_ifworker_type_to_string(w->type),
			ni_ifworker_type_to_string(w->masterdev->type),
			w->masterdev->name);
		return FALSE;
	}

	return TRUE;
}

static ni_bool_t
ni_fsm_ifmatch_pull_up(ni_fsm_t *fsm, ni_ifmatcher_t *match,
		ni_ifworker_array_t *matching, ni_ifworker_array_t *guard,
		ni_log_fn_t *logit, ni_ifworker_t *w,
		ni_bool_t master, ni_bool_t lower,
		ni_bool_t ports, ni_bool_t links,
		ni_bool_t changed)
{
	/*
	 * Each interface potentially has a master and lower reference,
	 * that are required for the setup of this interface.
	 *     [<lower>] <--lower-- <this> --master--> [<master>]
	 *
	 * Pull up this interface including the master/lower requirements
	 * or reject the setup (return FALSE) otherwise.
	 *
	 * Further, pull up ports referencing this interface via master:
	 * we "require" them e.g. to inherit/detect detect carrier.
	 *
	 * In regular ifup, we don't pull up links "on top" of this
	 * interface referring us via lower as we don't require them
	 * (they require us as lower/underlying interface).
	 *
	 * On ifreload, we set up changed and still configured workers
	 * we require (master,lower,ports) and as the ifdown part of
	 * the ifreload is shutting down links, we pull them up again.
	 */
	ni_ifworker_array_t pulled = NI_IFWORKER_ARRAY_INIT;
	unsigned int i;

	if (ni_ifworker_array_index(matching, w) != -1)
		return TRUE;

	/*
	 * We can't configure interfaces we don't have config for.
	 */
	if (!ni_fsm_ifmatch_worker_configured(match, w))
		return TRUE;

	if (match->ifreload)
		changed = changed || ni_fsm_ifmatch_config_changed(match, w);

	/*
	 * Check loop guard before pulling references.
	 */
	if (!ni_ifworker_references_ok(guard, w))
		return FALSE;

	ni_ifworker_array_append(guard, w);

	if (lower && !ni_fsm_ifmatch_pull_up_lower(fsm, match, &pulled,
			guard, logit, w, TRUE, TRUE, ports, FALSE, FALSE)) {

		ni_ifworker_array_destroy(&pulled);
		ni_ifworker_array_remove(guard, w);
		return FALSE;
	}

	if (master && !ni_fsm_ifmatch_pull_up_master(fsm, match, &pulled,
			guard, logit, w, TRUE, TRUE, FALSE, links, FALSE)) {

		ni_ifworker_array_destroy(&pulled);
		ni_ifworker_array_remove(guard, w);
		return FALSE;
	}

	if (ports && !ni_fsm_ifmatch_pull_up_ports(fsm, match, &pulled,
			guard, logit, w, TRUE, FALSE, changed)) {

		ni_ifworker_array_destroy(&pulled);
		ni_ifworker_array_remove(guard, w);
		return FALSE;
	}

	if (links && !ni_fsm_ifmatch_pull_up_links(fsm, match, &pulled,
			guard, logit, w, FALSE, TRUE, changed)) {

		ni_ifworker_array_destroy(&pulled);
		ni_ifworker_array_remove(guard, w);
		return FALSE;
	}

	ni_ifworker_array_remove(guard, w);

	if (!ni_fsm_ifmatch_conditions(match, w, logit)) {
		ni_ifworker_array_destroy(&pulled);
		return FALSE;
	}

	for (i = 0; i < pulled.count; ++i) {
		ni_ifworker_t *dep = pulled.data[i];

		if (ni_ifworker_array_index(matching, dep) == -1)
			ni_ifworker_array_append(matching, dep);
	}
	ni_ifworker_array_destroy(&pulled);

	if (match->ifreload && !changed)
		return TRUE; /* skip unchanged */

	if (ni_ifworker_array_index(matching, w) == -1)
		ni_ifworker_array_append(matching, w);

	return TRUE;
}

static ni_bool_t		ni_fsm_ifmatch_pull_down(ni_fsm_t *,
						ni_ifmatcher_t *,
						ni_ifworker_array_t *,
						ni_ifworker_array_t *,
						ni_log_fn_t *,
						ni_ifworker_t *,
						ni_bool_t);

static ni_bool_t
ni_fsm_ifmatch_pull_down_ports(ni_fsm_t *fsm, ni_ifmatcher_t *match,
		ni_ifworker_array_t *matching, ni_ifworker_array_t *guard,
		ni_log_fn_t *logit, ni_ifworker_t *master, ni_bool_t changed)
{
	ni_netdev_t *mdev, *dev;
	ni_ifworker_t *port;
	unsigned int i;
	ni_bool_t ret = TRUE;

	if (!(mdev = master->device))
		return TRUE;

	for (i = 0; i < fsm->workers.count; ++i) {
		port = fsm->workers.data[i];
		if (!(dev = port ? port->device : NULL))
			continue;

		/*
		 * consider to shutdown member ports of this master …
		 */
		if (!ni_string_eq(dev->link.masterdev.name, mdev->name)) {
			if (!match->ifreload)
				continue;

			/*
			 * … including ports, that _will_ become port of this
			 * master interface and thus while not covered by the
			 * `ifdown $this` part, relevant for the `ifup $this`
			 * part of the currently executed `ifreload $this`.
			 */
			if (!port->masterdev ||
			    !ni_string_eq(port->masterdev->name, mdev->name))
				continue;
		}

		if (!ni_fsm_ifmatch_pull_down(fsm, match, matching,
				guard, logit, port, changed))
			ret = FALSE;
	}
	return ret;
}

static ni_bool_t
ni_fsm_ifmatch_pull_down_links(ni_fsm_t *fsm, ni_ifmatcher_t *match,
		ni_ifworker_array_t *matching, ni_ifworker_array_t *guard,
		ni_log_fn_t *logit, ni_ifworker_t *lower, ni_bool_t changed)
{
	ni_netdev_t *ldev, *dev;
	ni_ifworker_t *link;
	unsigned int i;
	ni_bool_t ret = TRUE;

	if (!(ldev = lower->device))
		return TRUE;

	for (i = 0; i < fsm->workers.count; ++i) {
		link = fsm->workers.data[i];
		if (!(dev = link ? link->device : NULL))
			continue;

		/*
		 * consider to shutdown links on top of this lower …
		 */
		if (!ni_string_eq(dev->link.lowerdev.name, ldev->name)) {
			if (!match->ifreload)
				continue;

			/*
			 * … including links, that _will_ be linked to this
			 * lower interface and thus while not covered by the
			 * `ifdown $this` part, relevant for the `ifup $this`
			 * part of the currently executed `ifreload $this`.
			 */
			if (!link->lowerdev ||
			    !ni_string_eq(link->lowerdev->name, ldev->name))
				continue;
		}

		if (!ni_fsm_ifmatch_pull_down(fsm, match, matching,
				guard, logit, link, changed))
			ret = FALSE;
	}
	return ret;
}

static ni_bool_t
ni_fsm_ifmatch_pull_down(ni_fsm_t *fsm, ni_ifmatcher_t *match,
		ni_ifworker_array_t *matching, ni_ifworker_array_t *guard,
		ni_log_fn_t *logit, ni_ifworker_t *w, ni_bool_t changed)
{
	/*
	 * Each interface potentially has a master and lower reference.
	 * This interface may be the master/lower for it's ports/links:
	 *     [<ports> --master-->] <this> [<--lower-- <links>]
	 *
	 * Pull down this interface (as subtree head) when it's previously
	 * configured by us including all port,link interfaces referencing
	 * it in their->device->link.{lowerdev,masterdev}, which reflect
	 * the references in the system (kernel, ovs) exposed by wickedd.
	 *
	 * We trigger pull down of the depending ports and links first
	 * to reject the shutdown (return FALSE) of the whole subtree
	 * when this or an depending interface is marked persistent …
	 * unless we're performing a forced shutdown.
	 *
	 * On ifreload, we shutdown changed devices, that is we check
	 * previously configured interfaces with modified or deleted
	 * configuration. We pass the changed flag of this interface
	 * to pull down of all depending interfaces and OR it with
	 * their own changed state in order to detect changes and
	 * shutdown changed interfaces in subtree below this head,
	 * even this requested head did not changed itself.
	 */
	ni_ifworker_array_t pulled = NI_IFWORKER_ARRAY_INIT;
	ni_netdev_t *device;
	unsigned int i;

	if (!(device = w->device))
		return TRUE;

	if (ni_ifworker_array_index(matching, w) != -1)
		return TRUE;

	/*
	 * We don't shutdown interfaces we didn't configured.
	 * In case there are further interfaces referencing this
	 * one (e.g. VM ports in this bridge or vlans on top),
	 * the kernel will unlink or delete them when/as needed.
	 */
	if (!ni_fsm_ifmatch_device_configured(match, w))
		return TRUE; /* don't abort subtree down */

	/*
	 * When config on this interface changed, we have to pull
	 * down all ports/links referencing it via master/lower…
	 */
	if (match->ifreload)
		changed = changed || ni_fsm_ifmatch_config_changed(match, w);

	/*
	 * Check loop guard before pulling references.
	 */
	if (!ni_ifworker_references_ok(guard, w))
		return FALSE;

	ni_ifworker_array_append(guard, w);

	/*
	 * There is no reason to trigger master or lower shutdown
	 * we (as port or link) refer to -- they don't refer us.
	 *
	 * But we have to shutdown all ports and links that refer
	 * to the worker device via their master/lower device ref.
	 */
	if (!ni_fsm_ifmatch_pull_down_ports(fsm, match, &pulled,
			guard, logit, w, changed)) {

		logit("skipping '%s' %s: unable to shutdown ports",
			device->name, ni_ifworker_type_to_string(w->type));

		ni_ifworker_array_destroy(&pulled);
		ni_ifworker_array_remove(guard, w);
		return FALSE;
	}

	if (!ni_fsm_ifmatch_pull_down_links(fsm, match, &pulled,
			guard, logit, w, changed)) {

		logit("skipping '%s' %s: unable to shutdown links",
			device->name, ni_ifworker_type_to_string(w->type));

		ni_ifworker_array_destroy(&pulled);
		ni_ifworker_array_remove(guard, w);
		return FALSE;
	}

	ni_ifworker_array_remove(guard, w);

	if (!ni_fsm_ifmatch_conditions(match, w, logit)) {
		ni_ifworker_array_destroy(&pulled);
		return FALSE;
	}

	for (i = 0; i < pulled.count; ++i) {
		ni_ifworker_t *dep = pulled.data[i];

		if (ni_ifworker_array_index(matching, dep) == -1)
			ni_ifworker_array_append(matching, dep);
	}
	ni_ifworker_array_destroy(&pulled);

	if (match->ifreload && !changed)
		return TRUE; /* skip unchanged */

	if (ni_ifworker_array_index(matching, w) == -1)
		ni_ifworker_array_append(matching, w);

	return TRUE;
}

unsigned int
ni_fsm_get_matching_workers(ni_fsm_t *fsm, ni_ifmatcher_t *match,
		ni_ifworker_array_t *matching)
{
	ni_ifworker_array_t guard = NI_IFWORKER_ARRAY_INIT;
	ni_log_fn_t *logit;
	ni_ifworker_t *w;
	unsigned int i, cnt;

	if (!fsm || !match || !matching)
		return 0;

	if (ni_string_eq(match->name, "all")) {
		match->name = NULL;
		logit = ni_info;
	} else {
		logit = ni_note;
	}

	cnt = matching->count;
	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if (!ni_fsm_ifmatch_netif_worker(match, w) ||
		    !ni_fsm_ifmatch_worker_name(match, w))
			continue;

		if (!match->ifdown) {
			/*
			 * Get worker incl. config references for setup:
			 *
			 * - [1] this->lower reference: pull underlying requirements
			 *       (we can't exist or start without them at all;
			 *        e.g. eth0.42 vlan can't exist without eth0)
			 * - [2] this->master reference: pull master we're port of
			 *       (we can't finish link setup without them;
			 *        e.g. port eth0 needs it's bridge br0)
			 *
			 * ports trigger [required]:
			 *   = Desired to pick ports of the requested master,
			 *     which is the "controlling top level interface".
			 *   - [3] this<-ports: pull ports referring us as master
			 *         (e.g. br42 requests it's port eth1.42)
			 *     - [==1] port->lower: pull port lower requirements
			 *             (e.g. eth1.42 needs it's underlying eth0)
			 *
			 * links trigger [undesired]:
			 *   = Links depend on lower, but lower does not need any
			 *     links on top -- lower (L3) setup is independent.
			 *   - [4] this<-links: pull links referring us as lower
			 *         (e.g. eth0 requestst to setup eth0.* too)
			 *         - [==2] link->master: pull link masters
			 *                 (eth0.* links require their masters)
			 */
			ni_fsm_ifmatch_pull_up(fsm, match, matching, &guard,
					logit, w, TRUE, TRUE, TRUE,
					!!match->ifreload, FALSE);
			ni_ifworker_array_destroy(&guard);
		} else {
			/*
			 * Get worker incl. system references for shutdown:
			 *
			 * - [1] this<-links: pull links referencing us as lower
			 *       (e.g. shutdown bond0.42 vlan on bond0 goes down)
			 * - [2] this<-ports: pull ports referencing us as master
			 *       (e.g. shutdown eth1,eth1 on bond0 goes down)
			 */
			ni_fsm_ifmatch_pull_down(fsm, match, matching, &guard,
					logit, w, FALSE);
			ni_ifworker_array_destroy(&guard);
		}
	}

	return matching->count - cnt;
}

/*
 * Check for loops in the device tree
 */
static const char *
ni_ifworker_guard_print(ni_stringbuf_t *buf, const ni_ifworker_array_t *guard, const char *sep)
{
	const ni_ifworker_t *w;
	unsigned int i;

	for (i = 0; i < guard->count; i++) {
		w = guard->data[i];
		if (i != 0)
			ni_stringbuf_puts(buf, sep);
		ni_stringbuf_puts(buf, w->name);
	}
	return buf->string;
}

static ni_bool_t
ni_ifworker_references_ok(const ni_ifworker_array_t *guard, ni_ifworker_t *w)
{
	if (w->masterdev && w->lowerdev && ((w->masterdev == w->lowerdev) ||
	    ni_string_eq(w->masterdev->name, w->lowerdev->name))) {
		ni_ifworker_fail(w, "references %s as master and as lower device",
				w->masterdev->name);
		ni_ifworker_array_remove(&w->masterdev->children, w);
		ni_ifworker_set_ref(&w->lowerdev, NULL);
		ni_ifworker_set_ref(&w->masterdev, NULL);
		return FALSE;
	}

	if (w == w->lowerdev || (w->lowerdev && ni_string_eq(w->name, w->lowerdev->name))) {
		ni_ifworker_fail(w, "references itself as lower device");
		ni_ifworker_set_ref(&w->lowerdev, NULL);
		return FALSE;
	}

	if (w == w->masterdev || (w->masterdev && ni_string_eq(w->name, w->masterdev->name))) {
		ni_ifworker_fail(w, "references itself as master device");
		ni_ifworker_array_remove(&w->masterdev->children, w);
		ni_ifworker_set_ref(&w->masterdev, NULL);
		return FALSE;
	}

	if (ni_ifworker_array_index(guard, w) != -1) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

		ni_ifworker_guard_print(&buf, guard, " -> ");
		ni_ifworker_fail(w, "reference loop in device hierarchy branch %s -> %s",
				buf.string, w->name);
		ni_stringbuf_destroy(&buf);
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_ifworker_break_loops(ni_ifworker_array_t *guard, ni_ifworker_t *w, unsigned int lvl)
{
	unsigned int i;

	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_APPLICATION)) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

		ni_ifworker_guard_print(&buf, guard, " -> ");
		ni_trace("%*s%s\t[master: %s, lower: %s, tree branch: %s -> %s]",
				lvl, " ", w->name,
				w->masterdev ? w->masterdev->name : NULL,
				w->lowerdev ? w->lowerdev->name : NULL,
				buf.string ? buf.string : "", w->name);
		ni_stringbuf_destroy(&buf);
	}

	if (!ni_ifworker_references_ok(guard, w))
		return FALSE;
	ni_ifworker_array_append(guard, w);

	for (i = 0; i < w->children.count; i++) {
		ni_ifworker_t *c = w->children.data[i];

		if (!ni_ifworker_break_loops(guard, c, lvl + 4)) {
			ni_ifworker_array_remove(&w->children, c);
			return FALSE;
		}
		ni_ifworker_array_remove(guard, c);
	}
	return TRUE;
}

static ni_bool_t
ni_ifworkers_break_loops(ni_fsm_t *fsm)
{
	ni_ifworker_array_t guard = NI_IFWORKER_ARRAY_INIT;
	ni_ifworker_t *w;
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];
		ni_ifworker_break_loops(&guard, w, 0);
		ni_ifworker_array_destroy(&guard);
	}
	return TRUE;
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

	/* Mark all our primary devices with the requested marker values */
	for (i = 0; i < marked->count; ++i) {
		ni_ifworker_t *w = marked->data[i];

		w->target_range = marker->target_range;

		if (marker->persistent)
			ni_ifworker_control_set_persistent(w, TRUE);
	}

	count = ni_fsm_start_matching_workers(fsm, marked);
	ni_debug_application("marked %u interfaces", count);
	return count;
}

unsigned int
ni_fsm_start_matching_workers(ni_fsm_t *fsm, ni_ifworker_array_t *marked)
{
	unsigned int i, count = 0;

	for (i = 0; i < marked->count; ++i) {
		ni_ifworker_t *w = marked->data[i];

		if (w->failed)
			continue;

		if (!ni_ifworker_is_device_created(w) && !ni_ifworker_is_factory_device(w)) {
			w->pending = TRUE;
			ni_ifworker_set_timeout(fsm, w, fsm->worker_timeout);
			count++;
			continue;
		}

		if (ni_ifworker_start(fsm, w, fsm->worker_timeout) < 0) {
			ni_ifworker_fail(w, "unable to start worker");
			continue;
		}

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

		ni_ifworker_rearm(w);

		w->target_state = NI_FSM_STATE_NONE;
		if (target_range) {
			w->target_range = *target_range;
		} else {
			w->target_range.min = NI_FSM_STATE_NONE;
			w->target_range.max = NI_FSM_STATE_MAX;
		}
	}
}

static void
ni_fsm_clear_hierarchy(ni_ifworker_t *w)
{
	unsigned int i;

	if (w->masterdev) {
		ni_ifworker_array_remove(&w->masterdev->children, w);
		w->masterdev = NULL;
	}

	if (w->lowerdev) {
		w->lowerdev = NULL;
	}

	for (i = 0; i < w->children.count; i++) {
		ni_ifworker_t *child = w->children.data[i];

		if (child->masterdev == w) {
			child->masterdev = NULL;
		}

		if (child == w->lowerdev) {
			w->lowerdev = NULL;
		}
	}

	ni_ifworker_array_destroy(&w->children);
}

static void
ni_ifworker_device_delete(ni_ifworker_t *w)
{
	ni_ifworker_get(w);
	ni_debug_application("%s(%s)", __func__, w->name);

	w->ifindex = 0;
	if (w->device) {
		ni_netdev_put(w->device);
		w->device = NULL;
	}
	if (w->object) {
		ni_dbus_object_free(w->object);
		w->object = NULL;
	}
	ni_string_free(&w->object_path);
	w->object_path = NULL;

	ni_ifworker_cancel_secondary_timeout(w);
	ni_ifworker_cancel_timeout(w);

	if (ni_ifworker_is_running(w))
		ni_ifworker_fail(w, "device has been deleted");

	w->target_range.min = NI_FSM_STATE_NONE;
	w->target_range.max = NI_FSM_STATE_MAX;

	ni_ifworker_destroy_action_table(w);
	ni_ifworker_destroy_device_api(w);
	ni_ifworker_rearm(w);
	ni_fsm_clear_hierarchy(w);

	ni_ifworker_release(w);
}

void
ni_fsm_destroy_worker(ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_ifworker_get(w);

	ni_debug_application("%s(%s)", __func__, w->name);
	if (!ni_ifworker_array_remove(&fsm->workers, w)) {
		ni_ifworker_release(w);
		return;
	}

	ni_ifworker_device_delete(w);

	ni_ifworker_release(w);
}

static void
ni_ifworker_get_check_state_req_for_methods(ni_ifworker_t *w)
{
	unsigned int i;
	ni_fsm_transition_t *at = w->fsm.action_table;

	if (at == NULL)
		return;

	/* For each of the DBus calls we will execute on this device,
	 * check whether there are constraints on child devices that
	 * require the subordinate device to have a certain
	 * minimum/maximum state.
	 */
	for (i = 0; i < at[i].next_state; ++i) {
		ni_fsm_require_list_destroy(&at[i].require.list);
		ni_ifworker_get_check_state_reqs_for_method(w, &at[i]);
	}
}

int
ni_ifworker_start(ni_fsm_t *fsm, ni_ifworker_t *w, unsigned long timeout)
{
	unsigned int min_state = w->target_range.min;
	unsigned int max_state = w->target_range.max;
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

	if (max_state == NI_FSM_STATE_MAX) {
		if (min_state == NI_FSM_STATE_NONE)
			return 0;

		/* No upper bound; bring it up to min level */
		rv = ni_fsm_schedule_init(fsm, w, NI_FSM_STATE_DEVICE_DOWN, min_state);
		if (rv < 0)
			return rv;
	} else if (min_state == NI_FSM_STATE_NONE) {
		/* No lower bound; bring it down to max level */
		rv = ni_fsm_schedule_init(fsm, w, NI_FSM_STATE_MAX - 1, max_state);
		if (rv < 0)
			return rv;
	} else {
		ni_warn("%s: not handled yet: bringing device into state range [%s, %s]",
				w->name,
				ni_ifworker_state_name(min_state),
				ni_ifworker_state_name(max_state));
		return -NI_ERROR_GENERAL_FAILURE;
	}

	ni_debug_application("%s: current state=%s target state=%s",
				w->name,
				ni_ifworker_state_name(w->fsm.state),
				ni_ifworker_state_name(w->target_state));

	if (w->target_state != NI_FSM_STATE_NONE)
		ni_ifworker_set_timeout(fsm, w, timeout);

	ni_ifworker_get_check_state_req_for_methods(w);
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
	const unsigned int services_max = ni_objectmodel_service_registry_count();
	const ni_dbus_service_t *list_services[services_max];
	const ni_dbus_method_t *method;
	const char *link_type;
	unsigned int i, count;
	int rv;

	if (xml_node_is_empty(w->config.node) || w->device_api.factory_service)
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
		count = ni_objectmodel_compatible_services_for_class(netif_list_class, list_services, services_max);
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
			xml_node_free(w->device_api.config);
			w->device_api.config = xml_node_clone(config, NULL);
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
	xml_node_t *config = NULL;

	if (w->device_api.service)
		return 1;

	if (xml_node_is_empty(w->config.node))
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
	xml_node_free(w->device_api.config);
	w->device_api.config = xml_node_clone(config, NULL);
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

static inline int
ni_ifworker_bind_config_service_method_early(ni_ifworker_t *w, ni_fsm_t *fsm,
		ni_dbus_xml_validate_context_t *context,
		const ni_dbus_service_t *service,
		const ni_dbus_method_t *method,
		xml_node_t *config)
{
	xml_node_t *args = NULL;
	int rv;

	rv = ni_dbus_xml_map_method_argument(method,
			0, config, &args, NULL);
	if (rv != NI_SUCCESS) {
		ni_ifworker_fail(w, "document error: can't map %s.%s() arguments",
				service->name, method->name);
		return -NI_ERROR_DOCUMENT_ERROR;
	}

	if (args) {
		ni_debug_config_xml(args, NI_LOG_DEBUG3,
			"%s(%s) mapped %s.%s() arguments",
			__func__, w->name, service->name, method->name);

		if (!ni_dbus_xml_validate_argument(method, 0, args, context)) {
			ni_ifworker_fail(w, "failed to validate %s.%s() arguments",
					service->name, method->name);
				return -NI_ERROR_DOCUMENT_ERROR;
		}
	}
	return NI_SUCCESS;
}

static inline int
ni_ifworker_bind_config_service_actions_early(ni_ifworker_t *w, ni_fsm_t *fsm,
		ni_dbus_xml_validate_context_t *context,
		const ni_dbus_service_t *service)
{
	const ni_fsm_transition_t *action;
	const ni_dbus_method_t *method;
	int rv;

	action = ni_fsm_transition_first();
	for ( ; action; action = ni_fsm_transition_next(action)) {
		if (ni_fsm_transition_is_down(action))
			continue;

		if (ni_string_empty(action->common.method_name))
			continue;

		if (!(method = ni_dbus_service_get_method(service,
				action->common.method_name)))
			continue;

		rv = ni_ifworker_bind_config_service_method_early(
			w, fsm, context, service, method, w->config.node
		);
		if (rv != NI_SUCCESS)
			return rv;
	}

	return NI_SUCCESS;
}

int
ni_ifworker_bind_config_services_early(ni_ifworker_t *w, ni_fsm_t *fsm,
		ni_dbus_xml_validate_context_t *context)
{
	const unsigned int max = ni_objectmodel_service_registry_count();
	const ni_dbus_service_t *services[max], *service;
	const ni_dbus_class_t *class;
	unsigned int count, i;
	int rv;

	/* Hmm.. modem should not differ, but...*/
	if (w->type != NI_IFWORKER_TYPE_NETDEV)
		return NI_SUCCESS;

	if (!(class = ni_objectmodel_get_class(NI_OBJECTMODEL_NETIF_CLASS)))
		return NI_SUCCESS;

	count = ni_objectmodel_compatible_services_for_class(class, services, max);
	for (i = 0; i < count; ++i) {
		service = services[i];
		rv = ni_ifworker_bind_config_service_actions_early(
			w, fsm, context, service
		);
		if (rv != NI_SUCCESS)
			return rv;
	}
	return NI_SUCCESS;
}

int
ni_ifworker_bind_config_early(ni_ifworker_t *w, ni_fsm_t *fsm, ni_bool_t prompt_now)
{
	struct ni_ifworker_xml_validation_user_data user_data = {
		.fsm = fsm, .worker = w,
	};
	ni_dbus_xml_validate_context_t context = {
		.metadata_callback = ni_ifworker_netif_resolve_cb,
		.prompt_callback = ni_ifworker_prompt_later_cb,
		.user_data = &user_data,
	};
	int rv = 0;

	if (xml_node_is_empty(w->config.node))
		return NI_SUCCESS;

	if (prompt_now)
		context.prompt_callback = ni_ifworker_prompt_cb;

	/* First, check for factory interface */
	if ((rv = ni_ifworker_bind_device_factory_api(w)) < 0)
		goto done;

	if (w->device_api.factory_method && w->device_api.config) {
		/* The XML validation code will do a pass over the part of our XML
		 * document that's used for the newDevice() call, and call us for
		 * every bit of metadata it finds.
		 * This includes elements marked by <meta:netif-reference/>
		 * in the schema.
		 */
		if (!ni_dbus_xml_validate_argument(w->device_api.factory_method,
				1, w->device_api.config, &context))
			return -NI_ERROR_DOCUMENT_ERROR;
	}

	/*
	 * Also other methods as linkUp contain <meta:netif-reference/>
	 * we have to resolve in order to rebuild the config hierarchy.
	 */
	ni_ifworker_bind_config_services_early(w, fsm, &context);

done:
	return rv;
}

struct process_system_requires_context {
	ni_dbus_xml_traverse_context_t  base;
	ni_fsm_t *			fsm;
	ni_ifworker_t *			worker;
	ni_ifworker_t *			linked;
};

static ni_bool_t
ni_ifworker_meta_add_system_netif_check_state_require(ni_ifworker_t *w,
		ni_ifworker_t *cw, xml_node_t *meta)
{
	ni_uint_range_t range = { NI_FSM_STATE_NONE, NI_FSM_STATE_MAX };
	const ni_fsm_transition_t *action;
	const char *attr;

	if (!(attr = xml_node_get_attr(meta, "op"))) {
		ni_error("%s: invalid netif-system-state method=\"%s\"",
				xml_node_location(meta), attr ?: "");
		return FALSE;
	}

	action = ni_fsm_transition_find_method(attr);
	if (!action || !ni_fsm_transition_is_down(action))
		return FALSE;

	attr = xml_node_get_attr(meta, "min-state");
	if (attr && !ni_ifworker_state_from_name(attr, &range.min)) {
		ni_error("%s: invalid state name min-state=\"%s\"",
				xml_node_location(meta), attr);
		return FALSE;
	}

	attr = xml_node_get_attr(meta, "max-state");
	if (attr && !ni_ifworker_state_from_name(attr, &range.max)) {
		ni_error("%s: invalid state name max-state=\"%s\"",
				xml_node_location(meta), attr);
		return FALSE;
	}

	ni_ifworker_add_system_check_state_req(w,
		action->common.method_name, cw,
		range.min, range.max);

	return TRUE;
}

static ni_bool_t
ni_ifworker_meta_add_system_netif_require(ni_ifworker_t *w,
		ni_ifworker_t *cw, xml_node_t *meta)
{
	const char *check;

	check = xml_node_get_attr(meta, "check");
	if (ni_string_eq(check, "netif-system-state")) {
		ni_ifworker_meta_add_system_netif_check_state_require(
			w, cw, meta
		);
	}
	return TRUE;
}

static dbus_bool_t
process_system_requires(const ni_xs_type_t *type, const char *name,
		const ni_dbus_xml_traverse_path_t *prev,
		ni_dbus_xml_traverse_context_t *context)
{
	const ni_dbus_xml_traverse_path_t path = { .prev = prev, .name = name };
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	struct process_system_requires_context *ctx;
	ni_bool_t subordinate = FALSE;	/* port -> master */
	ni_bool_t shared = FALSE;	/* link -> lower  */
	ni_netdev_ref_t *ref = NULL;
	xml_node_t *meta;
	const char *attr;

	/* cast and verify it's the effective context */
	ctx = (struct process_system_requires_context *)context;
	if (context->process != process_system_requires)
		return FALSE; /* something wrong; abort */

	/* make sure we have some metadata node */
	if (!type->meta || !type->meta->children)
		return TRUE; /* don't abort processing */

	ni_debug_wicked_xml(type->meta, NI_LOG_DEBUG3, "%s(%s) property meta",
			__func__, ni_dbus_xml_traverse_path_print(&buf, &path));
	ni_stringbuf_destroy(&buf);

	/* little paranoia guard before accessing them */
	if (!ctx->worker->device || !ctx->linked->device)
		return TRUE; /* don't abort processing */

	if (!(meta = xml_node_get_child(type->meta, "netif-reference")))
		return TRUE; /* don't abort processing */

	if ((attr = xml_node_get_attr(meta, "subordinate")))
		subordinate = ni_string_eq(attr, "true");
	if (!subordinate && (attr = xml_node_get_attr(meta, "shared")))
		shared = ni_string_eq(attr, "true");

	if (subordinate) {
		ref = &ctx->linked->device->link.masterdev;
		if (!ni_string_eq(ctx->worker->device->name, ref->name))
			return TRUE; /* don't abort processing */

		for (meta = type->meta->children; meta; meta = meta->next) {
			if (ni_string_eq(meta->name, "require")) {
				ni_ifworker_meta_add_system_netif_require(
					ctx->linked, ctx->worker, meta
				);
			}
		}
	} else if (shared) {
		ref = &ctx->linked->device->link.lowerdev;
		if (!ni_string_eq(ctx->worker->device->name, ref->name))
			return TRUE; /* don't abort processing */

		for (meta = type->meta->children; meta; meta = meta->next) {
			if (ni_string_eq(meta->name, "require")) {
				ni_ifworker_meta_add_system_netif_require(
					ctx->worker, ctx->linked, meta
				);
			}
		}
	}

	return TRUE;
}

int
ni_ifworker_bind_system_netif_ref_early(ni_ifworker_t *w, ni_fsm_t *fsm, ni_ifworker_t *ref)
{
	struct process_system_requires_context context = {
		.base = {
			.process = process_system_requires,
		},
		.fsm = fsm,
		.worker = w,
		.linked = ref,
	};
	const ni_dbus_service_t *service;
	const ni_dbus_class_t *class;
	int rv = NI_SUCCESS;

	/*
	 * the object is bound to the netif-<iftype> class/service
	 * which extends the generic netif service (superclass).
	 */
	class = ref->object->class;
	if (class && (service = ni_objectmodel_service_by_class(class))) {
		rv = ni_dbus_xml_traverse_service_properties(service,
				&context.base);
		if (rv < NI_SUCCESS)
			return rv;
	}

	if (ref->device->link.type != NI_IFTYPE_UNKNOWN && class->superclass &&
	    (service = ni_objectmodel_service_by_class(class->superclass))) {
		rv = ni_dbus_xml_traverse_service_properties(service,
				&context.base);
		if (rv < NI_SUCCESS)
			return rv;
	}

	return rv;
}

int
ni_ifworker_bind_system_links_early(ni_ifworker_t *w, ni_fsm_t *fsm)
{
	const ni_netdev_ref_t *lower;
	ni_ifworker_t *link;
	int rv = NI_SUCCESS;
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		link = fsm->workers.data[i];

		if (!link || !link->device || !link->object)
			continue;

		lower = &link->device->link.lowerdev;
		if (!ni_string_eq(lower->name, w->name))
			continue;

		rv = ni_ifworker_bind_system_netif_ref_early(w, fsm, link);
		if (rv < NI_SUCCESS)
			return rv;
	}
	return rv;
}

int
ni_ifworker_bind_system_ports_early(ni_ifworker_t *w, ni_fsm_t *fsm)
{
	const ni_netdev_ref_t *master;
	ni_ifworker_t *port;
	int rv = NI_SUCCESS;
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		port = fsm->workers.data[i];

		if (!port || !port->device || !port->object)
			continue;

		master = &port->device->link.masterdev;
		if (!ni_string_eq(master->name, w->name))
			continue;

		rv = ni_ifworker_bind_system_netif_ref_early(w, fsm, port);
		if (rv < NI_SUCCESS)
			return rv;
	}
	return rv;
}

int
ni_ifworker_bind_system_early(ni_ifworker_t *w, ni_fsm_t *fsm)
{
	int rv = NI_SUCCESS;

	ni_ifworker_bind_system_links_early(w, fsm);
	ni_ifworker_bind_system_ports_early(w, fsm);

	return rv;
}

int
ni_ifworker_bind_early(ni_ifworker_t *w, ni_fsm_t *fsm, ni_bool_t prompt_now)
{
	int rv;

	ni_ifworker_bind_system_early(w, fsm);

	rv = ni_ifworker_bind_config_early(w, fsm, prompt_now);
	if (rv < NI_SUCCESS)
		return rv;

	ni_ifworker_get_check_state_req_for_methods(w);
	return rv;
}

/*
 * Build the hierarchy of devices.
 *
 * We need to ensure that we bring up devices in the proper order; e.g. an
 * eth interface needs to come up before any of the VLANs that reference
 * it.
 */
#define ni_fsm_print_hierarchy(logfn, fmt, args...)		\
	do {							\
		if (logfn)					\
			logfn(fmt, ##args);			\
		else						\
			ni_debug_application(fmt, ##args);	\
	} while (0)

static const char *
ni_fsm_print_worker_name_info(ni_stringbuf_t *info, const ni_ifworker_t *w)
{
	if (!info || !w)
		return NULL;

	ni_stringbuf_puts(info, w->name);
	if (w->device) {
		ni_stringbuf_putc(info, ' ');
		if (!ni_string_eq(w->name, w->device->name))
			ni_stringbuf_puts(info, w->device->name);
		ni_stringbuf_printf(info, "[%u]", w->device->link.ifindex);
	}
	return info->string;
}

static const char *
ni_fsm_config_hierarchy_mark(const ni_ifworker_array_t *marked,
	const ni_ifworker_t *w)
{
	if (w && marked && ni_ifworker_array_index(marked, w) != -1)
		return "+ ";
	else
		return "  ";
}

static void
ni_fsm_print_config_device_worker_hierarchy(const ni_fsm_t *fsm,
		const ni_ifworker_t *w, unsigned int depth,
		const ni_ifworker_array_t *marked, ni_log_fn_t *logfn)
{
	ni_stringbuf_t info = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int i;

	if (!w)
		return;

	if (!depth) {
		ni_fsm_print_hierarchy(logfn, "%s%s",
			ni_fsm_config_hierarchy_mark(marked, w),
			ni_fsm_print_worker_name_info(&info, w));
		ni_stringbuf_destroy(&info);
	}

	depth += 4;
	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *c = fsm->workers.data[i];

		if (!c || c->type != w->type)
			continue;

		if (w->lowerdev == c) {

			ni_fsm_print_hierarchy(logfn, "%s%*s %s",
					ni_fsm_config_hierarchy_mark(marked, c),
					depth, "+--",
					ni_fsm_print_worker_name_info(&info, c));
			ni_stringbuf_destroy(&info);

			ni_fsm_print_config_device_worker_hierarchy(fsm, c,
					depth + 1, marked, logfn);
			continue;
		}
		if (c->masterdev == w) {

			ni_fsm_print_hierarchy(logfn, "%s%*s %s",
					ni_fsm_config_hierarchy_mark(marked, c),
					depth, "*--",
					ni_fsm_print_worker_name_info(&info, c));
			ni_stringbuf_destroy(&info);

			ni_fsm_print_config_device_worker_hierarchy(fsm, c,
					depth + 1, marked, logfn);
		}
	}
}

void
ni_fsm_print_config_hierarchy(const ni_fsm_t *fsm,
		const ni_ifworker_array_t *marked, ni_log_fn_t *logfn)
{
	unsigned int i;

	if (!fsm)
		return;

	ni_fsm_print_hierarchy(logfn, "Config interface hierarchy structure:");

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (w && w->type == NI_IFWORKER_TYPE_NETDEV && !w->masterdev)
			ni_fsm_print_config_device_worker_hierarchy(fsm, w,
					0, marked, logfn);
	}
}

static const char *
ni_fsm_print_device_name_info(ni_stringbuf_t *info, const ni_ifworker_t *w)
{
	if (!info || !w || !w->device)
		return NULL;

	ni_stringbuf_printf(info, "%s[%u]",
			w->device->name, w->device->link.ifindex);
	return info->string;
}

static const char *
ni_fsm_system_hierarchy_mark(const ni_ifworker_array_t *marked,
		const ni_ifworker_t *w)
{
	if (w && marked && ni_ifworker_array_index(marked, w) != -1)
		return "- ";
	else
		return "  ";
}

static void
ni_fsm_print_system_device_worker_hierarchy(const ni_fsm_t *fsm,
		const ni_ifworker_t *w, unsigned int depth,
		const ni_ifworker_array_t *marked, ni_log_fn_t *logfn)
{
	ni_stringbuf_t info = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int i;

	if (!w || !w->device)
		return;

	if (!depth) {
		ni_fsm_print_hierarchy(logfn, "%s%s",
				ni_fsm_system_hierarchy_mark(marked, w),
				ni_fsm_print_device_name_info(&info, w));
		ni_stringbuf_destroy(&info);
	}

	depth += 4;
	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *c = fsm->workers.data[i];

		if (!c || !c->device || c->type != w->type)
			continue;

		if (ni_string_eq(w->device->link.lowerdev.name, c->name)) {

			ni_fsm_print_hierarchy(logfn, "%s%*s %s",
					ni_fsm_system_hierarchy_mark(marked, c),
					depth, "+--",
					ni_fsm_print_device_name_info(&info, c));
			ni_stringbuf_destroy(&info);

			ni_fsm_print_system_device_worker_hierarchy(fsm, c,
					depth + 1, marked, logfn);
			continue;
		}
		if (ni_string_eq(c->device->link.masterdev.name, w->name)) {

			ni_fsm_print_hierarchy(logfn, "%s%*s %s",
					ni_fsm_system_hierarchy_mark(marked, c),
					depth, "*--",
					ni_fsm_print_device_name_info(&info, c));
			ni_stringbuf_destroy(&info);

			ni_fsm_print_system_device_worker_hierarchy(fsm, c,
					depth + 1, marked,  logfn);
		}
	}
}

void
ni_fsm_print_system_hierarchy(const ni_fsm_t *fsm,
		const ni_ifworker_array_t *marked, ni_log_fn_t *logfn)
{
	ni_ifworker_t *w;
	unsigned int i;

	if (!fsm)
		return;

	ni_fsm_print_hierarchy(logfn, "System interface hierarchy structure:");

	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if (!w || w->type != NI_IFWORKER_TYPE_NETDEV || !w->device)
			continue;

		if (!ni_string_empty(w->device->link.masterdev.name))
			continue;

		ni_fsm_print_system_device_worker_hierarchy(fsm, w, 0,
				marked, logfn);
	}
}

int
ni_fsm_build_hierarchy(ni_fsm_t *fsm, ni_bool_t destructive)
{
	ni_ifworker_t *w;
	unsigned int i;
	int rv;

	if (!fsm)
		return NI_ERROR_INVALID_ARGS;

	ni_fsm_events_block(fsm);
	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if ((rv = ni_ifworker_bind_early(w, fsm, FALSE)) < 0) {
			if (destructive) {
				ni_fsm_destroy_worker(fsm, w);
				i--;
			}
			continue;
		}
	}

	ni_ifworkers_break_loops(fsm);
	ni_fsm_events_unblock(fsm);

	return NI_SUCCESS;
}

dbus_bool_t
ni_ifworker_netif_resolve_cb(xml_node_t *node, const ni_xs_type_t *type, const xml_node_t *metadata, void *user_data)
{
	struct ni_ifworker_xml_validation_user_data *closure = user_data;
	ni_ifworker_t *w = closure->worker;
	ni_ifworker_t *cw = NULL;
	xml_node_t *cwmeta = NULL;
	ni_ifworker_type_t cwtype = NI_IFWORKER_TYPE_NONE;
	unsigned int requires = 0;
	xml_node_t *mchild;

	for (mchild = metadata->children; mchild; mchild = mchild->next) {
		const char *attr;

		if (ni_string_eq(mchild->name, "netif-reference")) {
			if (cw) {
				ni_error("%s: duplicate/conflicting references", xml_node_location(node));
				return FALSE;
			}
			cwtype = NI_IFWORKER_TYPE_NETDEV;
			if (!(cw = ni_ifworker_require_resolve(closure->fsm, w, cwtype, node, mchild)))
				cwmeta = mchild;
		} else
#ifdef MODEM
		if (ni_string_eq(mchild->name, "modem-reference")) {
			if (cw) {
				ni_error("%s: duplicate/conflicting references", xml_node_location(node));
				return FALSE;
			}
			cwtype = NI_IFWORKER_TYPE_MODEM;
			if (!(cw = ni_ifworker_require_resolve(closure->fsm, w, cwtype, node, mchild)))
				cwmeta = mchild;
		} else
#endif
		if (ni_string_eq(mchild->name, "require")) {
			unsigned int min_state = NI_FSM_STATE_NONE, max_state = NI_FSM_STATE_MAX;
			const char *method;

			/* Ignore if there is no check attribute */
			if (!(attr = xml_node_get_attr(mchild, "check")))
				continue;

			/* Compatibility name for "netif-config-state" */
			if (ni_string_eq(attr, "netif-child-state") ||
			    ni_string_eq(attr, "netif-check-state")) {
				ni_warn("%s: obsolete <meta:require check=\"%s\" …> in the schema",
					xml_node_location(mchild), attr);
				attr = "netif-config-state";
			}

			/* Ignore if check attribute value is wrong
			 * or not applicable for config processing
			 * like netif-system-state.
			 */
			if (!ni_string_eq(attr, "netif-config-state"))
				continue;

			if (!cw) {
				if (!cwmeta) {
					ni_error("%s: <meta:require check=\"netif-config-state\" …>"
						" without reference", xml_node_location(mchild));
					return FALSE;
				}
				if (xml_node_is_empty(node)) {
					ni_stringbuf_t path = NI_STRINGBUF_INIT_DYNAMIC;

					xml_node_get_path(&path, node, xml_node_find_parent(node,
								ni_ifworker_type_to_string(w->type)));

					/* we need either cdata or children here */
					ni_error("%s: cannot resolve empty %s %s (%s)", w->name, mchild->name,
							path.string, xml_node_location(node));
					ni_stringbuf_destroy(&path);
					return FALSE;
				}
			}

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

			requires++;
			ni_ifworker_add_config_check_state_req(w, method, cw, cwtype, cw ? NULL : node,
							cw ? NULL : cwmeta, min_state, max_state);
		}
	}

	if (!requires && cwmeta) {
#if 0
		/* this would define a hard reference which we cannot map to any method;
		 * better to enforce complete schema requirement definitions instead */
		ni_ifworker_require_resolver_new(closure->fsm, w, cwtype, node, cwmeta);
#else
		ni_error("%s: schema does not specify any valid require", xml_node_location(cwmeta));
		ni_debug_wicked_xml(metadata, NI_LOG_DEBUG, "%s: see meta:%s-reference",
					xml_node_location(metadata),
					cwtype == NI_IFWORKER_TYPE_NETDEV ? "netif" : "modem");
		return FALSE;
#endif
	}

	return TRUE;
}

int
ni_ifworker_prompt_later_cb(xml_node_t *node, const ni_xs_type_t *xs_type, const xml_node_t *metadata, void *user_data)
{
	return -NI_ERROR_RETRY_OPERATION;
}

ni_bool_t
ni_fsm_refresh_state(ni_fsm_t *fsm)
{
	ni_ifworker_t *w;
	unsigned int i;

	ni_fsm_events_block(fsm);
	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		/* Always clear the object - we don't know if it's still there
		 * after we've called ni_dbus_object_refresh_children() */
		w->object = NULL;
		if (w->device) {
			ni_netdev_put(w->device);
			w->device = NULL;
		}

		/* Set ifworkers to readonly if fsm is readonly */
		w->readonly = fsm->readonly;
	}

	if (!ni_fsm_refresh_netdevs_state(fsm))
		return FALSE;
#ifdef MODEM
	if (!ni_fsm_refresh_modems_state(fsm))
		return FALSE;
#endif

	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		/* Set initial state of existing devices */
		if (w->object != NULL)
			ni_ifworker_update_state(w, NI_FSM_STATE_DEVICE_EXISTS, NI_FSM_STATE_MAX);
	}
	ni_fsm_events_unblock(fsm);

	return TRUE;
}

static ni_bool_t
ni_fsm_refresh_netdevs_state(ni_fsm_t *fsm)
{
	ni_dbus_object_t *list_object;
	ni_dbus_object_t *object;

	if (!(list_object = ni_call_get_netif_list_object())) {
		ni_error("unable to get server's interface list");
		return FALSE;
	}

	/* Call ObjectManager.GetManagedObjects to get list of objects and their properties */
	if (!ni_dbus_object_refresh_children(list_object)) {
		ni_error("Couldn't refresh list of active network interfaces");
		return FALSE;
	}

	for (object = list_object->children; object; object = object->next)
		ni_fsm_recv_new_netif(fsm, object, TRUE);
	return TRUE;
}

ni_ifworker_t *
ni_fsm_recv_new_netif(ni_fsm_t *fsm, ni_dbus_object_t *object, ni_bool_t refresh)
{
	ni_netdev_t *dev = ni_objectmodel_unwrap_netif(object, NULL);
	ni_ifworker_t *found = NULL;
	ni_bool_t renamed = FALSE;

	/* note: dev is a not yet reference counted object->handle */
	if (dev == NULL || dev->name == NULL || refresh) {
		/* keep dev, but wipe out its content (properties) */
		if (dev)
			ni_netdev_reset(dev);

		if (!ni_dbus_object_refresh_children(object))
			return NULL;

		dev = ni_objectmodel_unwrap_netif(object, NULL);
	}

	if (dev == NULL || dev->name == NULL) {
		ni_error("%s: refresh failed to set up netdev object", object->path);
		return NULL;
	}

	if (ni_netdev_device_is_ready(dev)) {
		/*
		 * if tracked as pending worker, it's over now -- device is ready
		 */
		if ((found = ni_ifworker_array_find_by_objectpath(&fsm->pending, object->path)))
			ni_ifworker_array_remove(&fsm->pending, found);

		/* lookup worker by object path (ifindex) first, then by name */
		found = ni_ifworker_array_find_by_objectpath(&fsm->workers, object->path);
		if (!found)
			found = ni_fsm_ifworker_by_name(fsm, NI_IFWORKER_TYPE_NETDEV, dev->name);
		if (!found) {
			ni_debug_application("received new ready device %s (%s)",
						dev->name, object->path);
			found = ni_ifworker_new(&fsm->workers, NI_IFWORKER_TYPE_NETDEV, dev->name);
			if (found)
				found->readonly = fsm->readonly;
		} else {
			renamed = !ni_string_eq(found->name, dev->name);
			if (renamed)
				ni_debug_application("received refresh renaming ready device %s to %s (%s)",
							found->name, dev->name, object->path);
			else
				ni_debug_application("received refresh for ready device %s (%s)",
							dev->name, object->path);
		}
		if (dev->client_state && found)
			ni_ifworker_refresh_client_state(found, dev->client_state);
	} else {
		/* even we we've created it and know the object-path/ifindex
		 * or the config refers a device by ifindex, we've to track it as
		 * pending worker to not confuse other parts (dependencies), that
		 * may use it by not-yet-stable name (rename may be in progress).
		 */
		if (!(found = ni_ifworker_array_find_by_objectpath(&fsm->pending, object->path))) {
			ni_debug_application("received new non-ready device %s (%s)",
					dev->name, object->path);
			found = ni_ifworker_new(&fsm->pending, NI_IFWORKER_TYPE_NETDEV, dev->name);
			if (found)
				found->readonly = fsm->readonly;
		} else {
			renamed = !ni_string_eq(found->name, dev->name);
			if (renamed)
				ni_debug_application("received refresh renaming non-ready device %s to %s (%s)",
						found->name, dev->name, object->path);
			else
				ni_debug_application("received refresh for non-ready device %s (%s)",
						dev->name, object->path);
		}
	}

	if (!found)
		return NULL;

	if (!found->object_path)
		ni_string_dup(&found->object_path, object->path);

	dev = ni_netdev_get(dev);
	if (found->device)
		ni_netdev_put(found->device);
	found->device = dev;

	if (renamed) {
		ni_string_dup(&found->old_name, found->name);
		ni_string_dup(&found->name, dev->name);
	} else {
		ni_string_free(&found->old_name);
	}

	found->ifindex = dev->link.ifindex;
	found->object = object;

	return found;
}

ni_ifworker_t *
ni_fsm_recv_new_netif_path(ni_fsm_t *fsm, const char *path)
{
	static ni_dbus_object_t *list_object = NULL;
	ni_dbus_object_t *object;

	if (!list_object && !(list_object = ni_call_get_netif_list_object())) {
		ni_error("unable to get server's netdev list");
		return NULL;
	}

	object = ni_dbus_object_create(list_object, path, NULL, NULL);
	return ni_fsm_recv_new_netif(fsm, object, TRUE);
}

#ifdef MODEM
static ni_bool_t
ni_fsm_refresh_modems_state(ni_fsm_t *fsm)
{
	static ni_dbus_object_t *list_object = NULL;
	ni_dbus_object_t *object;

	if (!list_object && !(list_object = ni_call_get_modem_list_object())) {
		ni_error("unable to get server's modem list");
		return FALSE;
	}

	/* Call ObjectManager.GetManagedObjects to get list of objects and their properties */
	if (!ni_dbus_object_refresh_children(list_object)) {
		ni_error("Couldn't refresh list of available modems");
		return FALSE;
	}

	for (object = list_object->children; object; object = object->next) {
		ni_fsm_recv_new_modem(fsm, object, TRUE);
	}
	return TRUE;
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
		found = ni_ifworker_new(&fsm->workers, NI_IFWORKER_TYPE_MODEM, modem->device);
	}

	if (!found)
		return NULL;

	if (!found->object_path)
		ni_string_dup(&found->object_path, object->path);
	if (!found->modem)
		found->modem = ni_modem_hold(modem);
	found->object = object;

	/* Don't touch devices we're done with */
	if (!found->done)
		ni_ifworker_update_state(found, NI_FSM_STATE_DEVICE_EXISTS, NI_FSM_STATE_MAX);

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
 * <auth class="dict">
 *   <user type="string" constraint="required">
 *     <meta:user-input type="user" prompt="Please enter openvpn user name"/>
 *   </user>
 *   <password type="string" constraint="required">
 *     <meta:user-input type="password" prompt="Please enter openvpn password"/>
 *   </password>
 * </auth>
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
 * Set method specific argument options (if any)
 */
static xml_node_t *
ni_ifworker_add_method_argument_node(xml_node_t *parent, const ni_dbus_method_t *method, unsigned int arg)
{
	ni_string_array_t names = NI_STRING_ARRAY_INIT;
	const xml_node_t *meta, *mapping;
	const char *attr = NULL;
	xml_node_t *node = NULL;
	ni_bool_t   generate;

	if (!(meta = ni_dbus_xml_get_argument_metadata(method, arg)))
		return FALSE;

	if (!(mapping = xml_node_get_child(meta, "mapping")))
		return FALSE;

	if (!(attr = xml_node_get_attr(mapping, "generate")) ||
	      ni_parse_boolean(attr, &generate) || !generate)
		return FALSE;

	if (!(attr = xml_node_get_attr(mapping, "document-node")))
		return FALSE;

	/* Convert the expected "foo/bar" node path into "<foo><bar/></foo>"
	 * node and return "bar" node, where we insert the requested options.*/
	if (ni_string_split(&names, attr, "/", 0)) {
		const char *ident;
		unsigned int i;

		for (i = 0; i < names.count; ++i) {
			ident = names.data[i];

			if (ni_string_empty(ident))
				continue;

			if ((node = xml_node_create(parent, ident)))
				parent = node;
		}
	}
	ni_string_array_destroy(&names);
	return node;
}

static xml_node_t *
ni_ifworker_add_method_argument_release(ni_ifworker_t *w, const char *name, xml_node_t *parent)
{
	if (ni_tristate_is_set(w->args.release)) {
		return xml_node_new_element_unique(name, parent,
			       ni_tristate_to_name(w->args.release));
	}
	return NULL;
}

static ni_bool_t
ni_ifworker_add_method_argument_scalar(xml_node_t *parent, ni_ifworker_t *w,
				const char *name, const ni_xs_scalar_info_t *info)
{
	if (ni_string_eq(name, "release") && ni_string_eq(info->basic_name, "boolean"))
		return ni_ifworker_add_method_argument_release(w, name, parent) != NULL;

	return FALSE;
}

static ni_bool_t
ni_ifworker_add_method_argument_type(xml_node_t *node, ni_ifworker_t *w,
				const char *name, const ni_xs_type_t *type);

static ni_bool_t
ni_ifworker_add_method_argument_dict(xml_node_t *parent, ni_ifworker_t *w,
				const char *name, const ni_xs_dict_info_t *info)
{
	const ni_xs_name_type_array_t *array;
	const ni_xs_name_type_t *entry;
	unsigned int i;

	parent = name ? xml_node_create(parent, name) : parent;
	array = info ? &info->children : NULL;
	for (i = 0; i < (array ? array->count : 0); ++i) {
		entry = &array->data[i];
		ni_ifworker_add_method_argument_type(parent, w, entry->name, entry->type);
	}
	return TRUE;
}

static ni_bool_t
ni_ifworker_add_method_argument_type(xml_node_t *node, ni_ifworker_t *w,
				const char *name, const ni_xs_type_t *type)
{
	switch (type->class) {
		case NI_XS_TYPE_DICT:
			return ni_ifworker_add_method_argument_dict(node,
					w, name, ni_xs_dict_info(type));
		case NI_XS_TYPE_SCALAR:
			return ni_ifworker_add_method_argument_scalar(node,
					w, name, ni_xs_scalar_info(type));
		default:
			return FALSE;
	}
}

static ni_bool_t
ni_ifworker_add_method_argument(ni_ifworker_t *w, ni_fsm_transition_t *action,
		const ni_dbus_service_t *service, const ni_dbus_method_t *method,
		xml_node_t *config, unsigned int arg)
{
	const ni_xs_type_t *type;
	const char *name;
	xml_node_t *node;

	if (!(type = ni_dbus_xml_get_argument_type(method, arg)))
		return FALSE;

	if (!(name = ni_dbus_xml_get_argument_name(method, arg)))
		return FALSE;

	if (!(node = ni_ifworker_add_method_argument_node(config, method, arg)))
		return FALSE;

	return ni_ifworker_add_method_argument_type(node, w, NULL, type);
}

static int
ni_ifworker_add_method_arguments(ni_ifworker_t *w, ni_fsm_transition_t *action,
		const ni_dbus_service_t *service, const ni_dbus_method_t *method,
		xml_node_t *config)
{
	unsigned int arg, nargs;

	nargs = ni_dbus_xml_method_num_args(method);
	for (arg = 0; arg < nargs; ++arg)
		ni_ifworker_add_method_argument(w, action, service, method, config, arg);
	return 0;
}

/*
 * Debugging: print the binding info
 */
static void
ni_ifworker_print_binding(ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	ni_fsm_transition_bind_t *bind;
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
 * Debugging: print the device lease info
 */
static inline void
ni_ifworker_print_device_leases(ni_ifworker_t *w)
{
	ni_addrconf_lease_t *lease;

	if (!w || !ni_debug_guard(NI_LOG_DEBUG1, NI_TRACE_EVENTS))
		return;

	if (!w->device) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
				"%s: no worker device", w->name);
	} else
	if (!w->device->leases) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
				"%s: no worker device leases", w->name);
	} else {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
				"%s: worker device leases:", w->name);
		for (lease = w->device->leases; lease; lease = lease->next) {
			ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
			ni_addrconf_flags_format(&buf, lease->flags, "|");
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
					"        %s:%s in state %s, uuid %s, flags %s",
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type),
					ni_addrconf_state_to_name(lease->state),
					ni_uuid_print(&lease->uuid),
					buf.string ? buf.string : "none");
			ni_stringbuf_destroy(&buf);
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

	if (!w->object && !w->device && ni_ifworker_is_factory_device(w))
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
		ni_fsm_transition_bind_t *bind = &action->binding[i];
		xml_node_t *config = NULL;

		/* Ensure we do not overwrite any reference we've set before */
		xml_node_free(bind->config);
		bind->config = NULL;

		/* If the interface doesn't support this method, we trivially succeed. */
		bind->method = ni_dbus_service_get_method(bind->service, action->common.method_name);
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
		 *           document-node="/some/xpath/expression"
		 *           skip-unless-present="true"
		 *           />
		 *     </foobar>
		 *   </arguments>
		 * </method>
		 *
		 * The document node is an xpath relative to the enclosing
		 * <interface> element. If the document does not contain the
		 * referenced node, and skip-unless-present is true, then we
		 * do not perform this call.
		 *
		 * Note: We clone the state/config to be able to add parameters
		 * as method specific arguments, e.g. `wicked ifdown --release`
		 * causes to generate a method specific "ipvX:dhcp/options"
		 * state node, actually:
		 *   <ipvX:dhcp>
		 *     <options>
		 *       <release>true</release>
		 *     </options>
		 *   </ipvX:dhcp>
		 * mapped to the ipvX.dhcp.dropLease(options) method argument.
		 */
		if (ni_fsm_transition_is_down(action))
			config = xml_node_clone(w->state.node, NULL);	/* down transition */
		else
			config = xml_node_clone(w->config.node, NULL);	/* up transition */

		/*
		 * Apply transition specific method options to the cloned config/state node
		 */
		ni_ifworker_add_method_arguments(w, action, bind->service, bind->method, config);

		/*
		 * Map nodes in the config / state to method arguments acc. to the schema
		 */
		if (ni_dbus_xml_map_method_argument(bind->method, 0, config, &bind->config, &bind->skip_call) < 0) {
			bind->config = NULL;
			xml_node_free(config);
			config = NULL;
			goto document_error;
		}

		/*
		 * Get reference to the mapped argument (child-)node and free the (outer) config clone
		 */
		bind->config = xml_node_clone_ref(bind->config);
		xml_node_free(config);
		config = NULL;

		/* Validate the document. This will record possible requirements, and will
		 * try to prompt for missing information.
		 */
		if (bind->config != NULL) {
			struct ni_ifworker_xml_validation_user_data user_data = {
				.fsm = fsm,
				.worker = w,
			};
			ni_dbus_xml_validate_context_t context;

			context.metadata_callback = ni_ifworker_xml_metadata_callback;
			context.prompt_callback = ni_ifworker_prompt_cb;
			context.user_data = action;

			if (!ni_dbus_xml_validate_argument(bind->method, 0, bind->config, &context)) {
				xml_node_free(bind->config);
				bind->config = NULL;
				goto document_error;
			}

			context.metadata_callback = ni_ifworker_netif_resolve_cb;
			context.prompt_callback = ni_ifworker_prompt_later_cb;
			context.user_data = &user_data;

			if (!ni_dbus_xml_validate_argument(bind->method, 0, bind->config, &context)) {
				xml_node_free(bind->config);
				bind->config = NULL;
				goto document_error;
			}
		}
	}

	return 0;

document_error:
	ni_ifworker_fail(w, "interface document error");
	return -NI_ERROR_DOCUMENT_ERROR;
}

static void
ni_ifworker_update_from_addrconf_callback(ni_addrconf_lease_t *lease, ni_objectmodel_callback_info_t *callback_list)
{
	ni_objectmodel_callback_info_t *cb;

	if (!lease || !callback_list)
		return;

	for (cb = callback_list; cb; cb = cb->next) {
		if (ni_string_eq(cb->event, "addressAcquired") ||
		    ni_string_eq(cb->event, "addressReleased")) {
			if (!cb->data.lease)
				continue;
			if (cb->data.lease->family != lease->family)
				continue;
			if (cb->data.lease->type != lease->type)
				continue;
			lease->uuid  = cb->data.lease->uuid;
			lease->state = cb->data.lease->state;
			lease->flags = cb->data.lease->flags;
			break; /* could it be more than one? */
		}
	}
}

static void
ni_ifworker_update_from_addrconf_requests(ni_ifworker_t *w, const char *service, const char *method,
			int result, ni_objectmodel_callback_info_t *callback_list)
{
	ni_string_array_t array = NI_STRING_ARRAY_INIT;
	size_t pfx = sizeof(NI_OBJECTMODEL_ADDRCONF_INTERFACE);
	size_t len = ni_string_len(service);
	unsigned int family, type;
	ni_addrconf_lease_t *lease;
	unsigned int cnt;

	if (!w || !w->device)
		return;

	if (len <= pfx || (cnt = ni_string_split(&array, service+pfx, ".", 0)) != 2)
		goto cleanup;
	if ((int)(family = ni_addrfamily_name_to_type(array.data[0])) < 0)
		goto cleanup;
	if ((int)(type = ni_addrconf_name_to_type(array.data[1])) < 0)
		goto cleanup;

	if (ni_string_eq(method, "requestLease")) {
		if (!(lease = ni_addrconf_lease_new(type, family)))
			goto cleanup;

		if (result < 0) {
			lease->state = NI_ADDRCONF_STATE_FAILED;
		} else
		if (callback_list) {
			lease->state = NI_ADDRCONF_STATE_REQUESTING;
			ni_ifworker_update_from_addrconf_callback(lease, callback_list);
		} else {
			lease->state = NI_ADDRCONF_STATE_GRANTED;
		}
		ni_netdev_set_lease(w->device, lease);
	} else
	if (ni_string_eq(method, "dropLease")) {
		if (result < 0)
			goto cleanup;

		if (callback_list) {
			if (!(lease = ni_addrconf_lease_new(type, family)))
				goto cleanup;

			lease->state = NI_ADDRCONF_STATE_RELEASING;
			ni_ifworker_update_from_addrconf_callback(lease, callback_list);
			ni_netdev_set_lease(w->device, lease);
		} else {
			/* [NI_ADDRCONF_STATE_RELEASED] and dropped */
			ni_netdev_unset_lease(w->device, family, type);
		}
	}
	ni_ifworker_print_device_leases(w);

cleanup:
	ni_string_array_destroy(&array);
}

static void
ni_ifworker_update_from_request(ni_ifworker_t *w, const char *service, const char *method,
				int result, ni_objectmodel_callback_info_t *callback_list)
{
	if (ni_string_startswith(service, NI_OBJECTMODEL_ADDRCONF_INTERFACE)) {
		ni_ifworker_update_from_addrconf_requests(w, service, method, result, callback_list);
	}
}

static int
ni_ifworker_do_common_call(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	unsigned int i, count = 0;
	int rv;

	/* Initially, enable waiting for this action */
	w->fsm.wait_for = action;

	for (i = 0; i < action->num_bindings; ++i) {
		ni_fsm_transition_bind_t *bind = &action->binding[i];
		ni_objectmodel_callback_info_t *callback_list = NULL;
		char *service = NULL;
		char *method = NULL;

		if (!bind->method || !bind->service)
			continue;

		if (bind->skip_call)
			continue;

		ni_string_dup(&service, bind->service->name);
		ni_string_dup(&method, bind->method->name);

		ni_debug_application("%s: calling %s.%s()", w->name, service, method);

		rv = ni_call_common_xml(w->object, bind->service, bind->method, bind->config,
				&callback_list, ni_ifworker_error_handler);
		ni_ifworker_update_from_request(w, service, method, rv, callback_list);
		if (rv < 0) {
			if (action->common.may_fail) {
				ni_error("[ignored] %s: call to %s.%s() failed: %s", w->name,
						service, method, ni_strerror(rv));
				ni_ifworker_set_state(w, action->next_state);
				ni_string_free(&service);
				ni_string_free(&method);
				return 0;
			}
			ni_ifworker_fail(w, "call to %s.%s() failed: %s", service, method, ni_strerror(rv));
			ni_string_free(&service);
			ni_string_free(&method);
			return rv;
		}

		if (callback_list) {
			ni_debug_application("%s: adding callback for %s.%s()", w->name, service, method);
			ni_ifworker_add_callbacks(action, callback_list, w->name);
			count++;
		}

		ni_string_free(&service);
		ni_string_free(&method);
	}

	/* Reset wait_for if there are no callbacks ... */
	if (count == 0) {
		/* ... unless this action requires ACK via event */
		if (action->next_state != NI_FSM_STATE_DEVICE_DOWN) {
			ni_ifworker_set_state(w, action->next_state);
			w->fsm.wait_for = NULL;
		}
	}

	return 0;
}

static int
ni_ifworker_do_wait_device_ready_call(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	if (ni_netdev_device_is_ready(w->device)) {
		w->fsm.wait_for = action;
		ni_ifworker_set_state(w, action->next_state);
		w->fsm.wait_for = NULL;
		return 0;
	}
	return ni_ifworker_do_common_call(fsm, w, action);
}

static unsigned int
ni_ifworker_get_ports_by_name(ni_fsm_t *fsm, const char *name, ni_ifworker_array_t *ports)
{
	unsigned int i, count;

	if (!fsm || ni_string_empty(name))
		return 0;

	count = ports ? ports->count : 0;
	for (i = 0;  i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (!w->masterdev)
			continue;
		if (!ni_string_eq(w->masterdev->name, name))
			continue;

		if (ports)
			ni_ifworker_array_append(ports, w);
		else
			count++;
	}
	return ports ? ports->count - count : count;
}

static ni_tristate_t
ni_ifworker_link_detection_guess(ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_netdev_t *dev;

	/*
	 * At the time of this call, the interface is configured
	 * by changeDevice (if needed), we're setting it UP (linkUp)
	 * and when it's not defined via config, we need to decide
	 * whether to wait for 'link-up' event signaling carrier
	 * and running state (incl. wpa on wlan) or not, before we
	 * continue with the L3 setup aka assign IP addresses, ...
	 *
	 * For some interfaces, we don't wait for link-up by default.
	 */
	if (!fsm || !w)
		return NI_TRISTATE_DEFAULT;

	switch (w->masterdev ? w->masterdev->iftype : NI_IFTYPE_UNKNOWN) {
	case NI_IFTYPE_BOND:
	case NI_IFTYPE_TEAM:
	case NI_IFTYPE_BRIDGE:
	case NI_IFTYPE_OVS_BRIDGE:
	case NI_IFTYPE_OVS_SYSTEM:
		/*
		 * Don't wait for L2 ports controlled by master,
		 * which inherit it's carrier from it's ports
		 * according to own logic (incl. monitoring)
		 * and we don't wait for link-up of the ports
		 * and also don't setup L3 on ports.
		 */
		return NI_TRISTATE_DISABLE;
	default:
		break;
	}

	switch (w->iftype) {
	case NI_IFTYPE_OVS_SYSTEM:
		/*
		 * The link state is unused on ovs datapaths.
		 */
		return NI_TRISTATE_DISABLE;

	case NI_IFTYPE_TUN:
	case NI_IFTYPE_TAP:
		/*
		 * Tun/Tap interfaces need a daemon started by
		 * an external service, PRE_UP hook, ...
		 * It may need to open a connection somewhere
		 * in the internet, ... don't require link-up.
		 */
		return NI_TRISTATE_DISABLE;

	case NI_IFTYPE_BRIDGE:
		/*
		 * A bridge inherits the carrier from a port;
		 * - When the config defines ports, wait until
		 *   they're added and the bridge gets link-up.
		 * - When the config does not define any ports:
		 *   - with STP=off: the bridge will get link-up
		 *   - with STP=on: will not reach link-up until
		 *     a port has been added externally, e.g. by
		 *     adding a VM interface to it at VM start.
		 *     Don't require the link-up, but continue to
		 *     set up L3 (e.g. static IPs), so services
		 *     (e.g. dhcp-server) are started on the
		 *     bridge to serve the VMs (while it's added).
		 */
		dev = w->device; /* changeDevice is applied */
		if (dev && dev->bridge && dev->bridge->stp &&
		    ni_ifworker_get_ports_by_name(fsm, w->name, NULL))
			return NI_TRISTATE_DISABLE;
		return NI_TRISTATE_DEFAULT;

	default:
		return NI_TRISTATE_DEFAULT;
	}

}

static int
ni_ifworker_link_detection_call(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	int ret;

	ret = ni_ifworker_do_common_call(fsm, w, action);

	if (!ni_tristate_is_set(w->control.link_required)) {
		w->control.link_required = ni_ifworker_link_detection_guess(fsm, w);
		if (ni_tristate_is_set(w->control.link_required))
			ni_ifworker_update_client_state_control(w);
	}

	if (ret >= 0 && w->fsm.wait_for) {
		if (w->control.link_timeout != NI_IFWORKER_INFINITE_SECONDS) {
			ni_ifworker_set_secondary_timeout(fsm, w,
					NI_TIMEOUT_FROM_SEC(w->control.link_timeout),
					ni_ifworker_link_detection_timeout);
		} else if (ni_tristate_is_disabled(w->control.link_required)) {
			ni_debug_application("%s: link-up state is not required, proceeding", w->name);
			ni_ifworker_cancel_callbacks(w, &action->callbacks);
			ni_ifworker_set_state(w, action->next_state);
			w->fsm.wait_for = NULL;
		}
	}
	return ret;
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
	ni_fsm_transition_bind_t *bind;
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
	xml_node_free(bind->config);
	bind->config = xml_node_clone(w->device_api.config, NULL);
	action->num_bindings++;

	rv = ni_ifworker_map_method_requires(w, action, bind->service, bind->method);
	if (rv < 0)
		return rv;

	return 0;
}

static int
ni_ifworker_call_device_factory(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	ni_netdev_t *dev;

	/* Initially, enable waiting for this action */
	w->fsm.wait_for = action;

	if (!ni_ifworker_device_bound(w)) {
		ni_fsm_transition_bind_t *bind;
		const char *relative_path = NULL;
		char *object_path;

		if (action->num_bindings == 0) {
			ni_ifworker_fail(w, "device does not exist");
			return -1;
		}
		bind = &action->binding[0];

		ni_debug_application("%s: calling device factory", w->name);
		object_path = ni_call_device_new_xml(bind->service, w->name, bind->config);
		if (object_path == NULL) {
			ni_ifworker_fail(w, "failed to create new device");
			return -1;
		}

		switch (ni_ifworker_type_from_object_path(object_path, &relative_path)) {
		case NI_IFWORKER_TYPE_NETDEV:
			if (ni_parse_uint(relative_path, &w->ifindex, 10) == 0)
				break;

			/* fall through */
		default:
			ni_ifworker_fail(w, "invalid device path %s", object_path);
			ni_string_free(&object_path);
			return -1;
		}
		ni_debug_application("created device %s (path=%s)", w->name, object_path);
		ni_string_free(&w->object_path);
		w->object_path = object_path;

		/* Lookup the object corresponding to this path. If it doesn't
		 * exist, create it on the fly (with a generic class of "netif" -
		 * the following refresh call with take care of this and correct
		 * the class.
		 */
		w->object = ni_dbus_object_create(fsm->client_root_object, object_path,
					NULL,
					NULL);

		if (!w->object || !ni_dbus_object_refresh_children(w->object)) {
			ni_ifworker_fail(w, "unable to refresh new device");
			return -1;
		}

		dev = ni_netdev_get(ni_objectmodel_unwrap_netif(w->object, NULL));
		ni_netdev_put(w->device);
		w->device = dev;

		ni_fsm_schedule_bind_methods(fsm, w);
	}

	ni_ifworker_set_state(w, action->next_state);
	w->fsm.wait_for = NULL;
	return 0;
}

/*
 * Finite state machine
 */
#define __TRANSITION_UP_TO(__state)		.from_state = __state - 1, .next_state = __state
#define __TRANSITION_DOWN_FROM(__state)		.from_state = __state, .next_state = __state - 1

#define COMMON_TRANSITION_UP_TO(__state, __meth, __more...) { \
	__TRANSITION_UP_TO(__state), \
	.bind_func = ni_ifworker_do_common_bind, \
	.call_func = ni_ifworker_do_common_call, \
	.common = { .method_name = __meth, ##__more } \
}

#define COMMON_TRANSITION_DOWN_FROM(__state, __meth, __more...) { \
	__TRANSITION_DOWN_FROM(__state), \
	.bind_func = ni_ifworker_do_common_bind, \
	.call_func = ni_ifworker_do_common_call, \
	.common = { .method_name = __meth, ##__more } \
}

#define TIMED_TRANSITION_UP_TO(__state, __timed, __meth, __more...) { \
	__TRANSITION_UP_TO(__state), \
	.bind_func = ni_ifworker_do_common_bind, \
	.call_func = ni_ifworker_ ## __timed ## _call, \
	.timeout_fn= ni_ifworker_ ## __timed ## _timeout, \
	.common = { .method_name = __meth, ##__more } \
}

#define TIMED_TRANSITION_DOWN_FROM(__state, __timed, __meth, __more...) { \
	__TRANSITION_DOWN_FROM(__state), \
	.bind_func = ni_ifworker_do_common_bind, \
	.call_func = ni_ifworker_ ## __timed ## _call, \
	.timeout_fn= ni_ifworker_ ## __timed ## _timeout, \
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
		.call_func = ni_ifworker_call_device_factory,
		.common = { .method_name = "newDevice" },
	},

	/* This state waits to become ready to set up, e.g. udev renamed */
	{
		__TRANSITION_UP_TO(NI_FSM_STATE_DEVICE_READY),
		.bind_func = ni_ifworker_do_common_bind,
		.call_func = ni_ifworker_do_wait_device_ready_call,
		.common = { .method_name = "waitDeviceReady", .call_overloading = TRUE }
	},

	/* This sets any device attributes, such as a MAC address */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_DEVICE_SETUP, "changeDevice", .call_overloading = FALSE),

	/* This sets the per-interface protocol attributes, such as forwarding */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_PROTOCOLS_UP, "changeProtocol"),

	/* This step adds device-specific filtering, if available. Typical
	 * example would be bridge filtering with ebtables. */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_FIREWALL_UP, "firewallUp"),

	/* This steps sets general link attributes such as the MTU, the transfer
	 * queue length etc., sets the link administratively UP what triggers a
	 * link negotiation / detection in the kernel.
	 */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_DEVICE_UP, "linkUp", .call_overloading = TRUE),

	/* This state causes to wait unlit the link negotiation / detection finished
	 * and we can start using it, that is authenticate ... request IP setup. */
	TIMED_TRANSITION_UP_TO(NI_FSM_STATE_LINK_UP, link_detection, "waitLinkUp", .call_overloading = TRUE),

	/* If the link requires authentication, this information can be provided
	 * here; for instance ethernet 802.1x, wireless WPA, or PPP chap/pap.
	 * NOTE: This may not be the right place; we may have to fold this into
	 * the link_up step, or even do it prior to that. */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_LINK_AUTHENTICATED, "login", .call_overloading = TRUE),

	/* This brings up LLDP sender and configures it */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_LLDP_UP, "lldpUp", .call_overloading = TRUE, .may_fail = TRUE),

	/* Configure all assigned addresses and bring up the network */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_ADDRCONF_UP, "requestLease"),

	/* Execute post-up script if any */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_NETWORK_UP, "networkUp"),

	/* -------------------------------------- *
	 * Transitions for bringing down a device
	 * -------------------------------------- */
	/* Execute pre-down script if any */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_NETWORK_UP, "networkDown"),

	/* Remove all assigned addresses and bring down the network */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_ADDRCONF_UP, "dropLease"),

	/* Shut down the LLDP sender */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_LLDP_UP, "lldpDown", .call_overloading = TRUE, .may_fail = TRUE),

	/* Shut down the link */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_DEVICE_UP, "linkDown", .call_overloading = TRUE),

	/* Shut down the firewall */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_FIREWALL_UP, "firewallDown"),

	/* Shutdown the device */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_DEVICE_SETUP, "shutdownDevice", .call_overloading = TRUE),

	/* Delete the device */
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_DEVICE_EXISTS, "deleteDevice", .call_overloading = TRUE, .may_fail = TRUE),

	{ .from_state = NI_FSM_STATE_NONE, .next_state = NI_FSM_STATE_NONE, .call_func = NULL }
};

static const ni_fsm_transition_t *
ni_fsm_transition_first(void)
{
	const ni_fsm_transition_t *action = ni_iftransitions;

	if (action && action->call_func)
		return action;
	return NULL;
}

static const ni_fsm_transition_t *
ni_fsm_transition_next(const ni_fsm_transition_t *action)
{
	if (!action || !action->call_func)
		return NULL;
	if (++action && action->call_func)
		return action;
	return NULL;
}

static const ni_fsm_transition_t *
ni_fsm_transition_find_method(const char *method)
{
	const ni_fsm_transition_t *action = ni_fsm_transition_first();

	for ( ; action; action = ni_fsm_transition_next(action)) {
		if (ni_string_eq(method, action->common.method_name))
			return action;
	}
	return NULL;
}

static int
ni_fsm_schedule_init(ni_fsm_t *fsm, ni_ifworker_t *w, unsigned int from_state, unsigned int target_state)
{
	unsigned int index, num_actions;
	unsigned int cur_state;
	int increment;
	int rv;

	if (ni_ifworker_is_running(w))
		return 0;

	if (from_state <= target_state)
		increment = 1;
	else {
		increment = -1;

		/* ifdown: when device cannot be deleted, don't try. */
		if (NI_FSM_STATE_DEVICE_DOWN == target_state) {
			if (!ni_ifworker_can_delete(w))
				target_state = NI_FSM_STATE_DEVICE_READY;
			else
				ni_debug_application("%s: Deleting device", w->name);
		}
	}

	ni_debug_application("%s: set up FSM from %s -> %s", w->name,
			ni_ifworker_state_name(from_state),
			ni_ifworker_state_name(target_state));

	num_actions = 0;

	ni_ifworker_destroy_action_table(w);
do_it_again:
	index = 0;
	for (cur_state = from_state; cur_state != target_state; ) {
		unsigned int next_state = cur_state + increment;
		const ni_fsm_transition_t *a;

		for (a = ni_iftransitions; a->call_func; ++a) {
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
		w->fsm.action_table = xcalloc(num_actions + 1, sizeof(ni_fsm_transition_t));
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

	ni_debug_application("%s: binding dbus calls to FSM transitions", w->name);
	for (action = w->fsm.action_table; action->call_func; ++action) {
		if (action->bound)
			continue;
		rv = action->bind_func(fsm, w, action);
		if (rv < 0) {
			ni_ifworker_fail(w, "unable to bind %s() call", action->common.method_name);
			return rv;
		}

		if (!action->bound)
			unbound++;
		else if (ni_log_facility(NI_TRACE_APPLICATION))
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

		for (i = 0; i < fsm->workers.count; ++i) {
			ni_ifworker_t *w = fsm->workers.data[i];
			ni_fsm_transition_t *action;
			unsigned int prev_state;
			int rv;

			ni_ifworker_get(w);

			if (w->pending)
				goto release;

			if (ni_ifworker_complete(w)) {
				ni_ifworker_cancel_secondary_timeout(w);
				ni_ifworker_cancel_timeout(w);
				goto release;
			}

			if (!w->kickstarted)
				w->kickstarted = TRUE;

			/* We requested a change that takes time (such as acquiring
			 * a DHCP lease). Wait for a notification from wickedd */
			if (w->fsm.wait_for) {
				ni_debug_application("%s: state=%s want=%s, wait-for=%s", w->name,
					ni_ifworker_state_name(w->fsm.state),
					ni_ifworker_state_name(w->target_state),
					ni_ifworker_state_name(w->fsm.wait_for->next_state));
				goto release;
			}

			action = w->fsm.next_action;
			if (action->next_state == NI_FSM_STATE_NONE)
				w->fsm.state = w->target_state;

			if (w->fsm.state == w->target_state) {
				ni_ifworker_success(w);
				made_progress = 1;
				goto release;
			}

			ni_debug_application("%s: state=%s want=%s, next transition is %s -> %s", w->name,
				ni_ifworker_state_name(w->fsm.state),
				ni_ifworker_state_name(w->target_state),
				ni_ifworker_state_name(w->fsm.next_action->from_state),
				ni_ifworker_state_name(w->fsm.next_action->next_state));

			if (!action->bound) {
				ni_ifworker_fail(w, "failed to bind services and methods for %s()",
						action->common.method_name);
				goto release;
			}

			if (!ni_ifworker_check_dependencies(fsm, w, action)) {
				ni_debug_application("%s: defer action (pending dependencies)", w->name);
				goto release;
			}

			ni_ifworker_cancel_secondary_timeout(w);

			prev_state = w->fsm.state;
			ni_fsm_events_block(fsm);

			rv = action->call_func(fsm, w, action);
			if (w->fsm.next_action)
				w->fsm.next_action++;

			if (rv >= 0) {
				made_progress = 1;

				if (w->fsm.wait_for) {
					ni_debug_application("%s: waiting for event in state %s",
						w->name, ni_ifworker_state_name(w->fsm.state));
				} else {
					ni_debug_application("%s: successfully transitioned from %s to %s",
							w->name,
							ni_ifworker_state_name(prev_state),
							ni_ifworker_state_name(w->fsm.state));
				}
			} else
			if (!w->failed) {
				/* The fsm action should really have marked this
				 * as a failure. shame on the lazy programmer. */
				ni_ifworker_fail(w, "failed to transition from %s to %s",
						ni_ifworker_state_name(prev_state),
						ni_ifworker_state_name(action->next_state));
			}

			ni_fsm_process_events(fsm);
			ni_fsm_events_unblock(fsm);
release:
			ni_ifworker_release(w);

			ni_dbus_objects_garbage_collect();
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

		if (!ni_ifworker_complete(w) || w->pending) {
			waiting++;
			nrequested++;
		}
	}

	ni_debug_application("waiting for %u devices to become ready (%u explicitly requested)", waiting, nrequested);
	return nrequested;
}

static ni_bool_t
ni_call_netif_refresh_tentative_addresses(ni_dbus_variant_t *result)
{
	ni_dbus_variant_t args = NI_DBUS_VARIANT_INIT;
	ni_dbus_object_t *list_object = NULL;
	DBusError error = DBUS_ERROR_INIT;
	dbus_bool_t rv;

	if (!result || !(list_object = ni_call_get_netif_list_object()))
		return FALSE;

	ni_dbus_variant_init_dict(&args);
	ni_dbus_dict_add_bool	(&args, "refresh",	TRUE);
	ni_dbus_dict_add_uint32	(&args, "family",	AF_INET6);
	ni_dbus_dict_add_bool	(&args, "tentative",	TRUE);
	ni_dbus_dict_add_bool	(&args, "duplicate",	FALSE);

	rv = ni_dbus_object_call_variant(list_object, NULL, "getAddresses",
						1, &args, 1, result, &error);
	if (!rv) {
		ni_dbus_print_error(&error, "%s.getAddresses() failed",
				ni_dbus_object_get_path(list_object));
		dbus_error_free(&error);
	}
	ni_dbus_variant_destroy(&args);
	return rv;
}

static ni_bool_t
ni_fsm_have_tentative_addrs(ni_fsm_t *fsm)
{
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	ni_address_t *list = NULL, *ap;
	dbus_bool_t found = FALSE;
	ni_dbus_variant_t *entry;
	ni_dbus_variant_t *array;
	const char *path;
	unsigned int i;

	if (!ni_call_netif_refresh_tentative_addresses(&result)) {
		ni_dbus_variant_destroy(&result);
		return found;
	}

	for (i = 0; (entry = ni_dbus_dict_get_entry(&result, i, &path)); ++i) {
		const char * ifname  = NULL;
		uint32_t     ifflags = 0;

		/*
		 * the result provides the device context & status aka ifflags,
		 * so we basically don't need to refresh + lookup workers devs.
		 */
		ni_dbus_dict_get_string(entry, "name",   &ifname);
		ni_dbus_dict_get_uint32(entry, "status", &ifflags);
		if (!(array = ni_dbus_dict_get(entry, "addresses")))
			continue;

		if (!(ifflags & NI_IFF_LINK_UP))
			continue;

		if (!__ni_objectmodel_set_address_list(&list, array, NULL))
			continue;

		for (ap = list; ap; ap = ap->next) {
			ni_debug_application("%s: address %s is tentative",
					ifname,
					ni_sockaddr_print(&ap->local_addr));
			found = TRUE;
		}
		ni_address_list_destroy(&list);
	}
	ni_dbus_variant_destroy(&result);

	return found;
}

void
ni_fsm_wait_tentative_addrs(ni_fsm_t *fsm)
{
	unsigned int i, count = 40; /* 10sec timeout */

	if (!fsm)
		return;

	ni_debug_application("waiting for tentative addresses");
	for (i = 0; i < count; i++) {
		if (!ni_fsm_have_tentative_addrs(fsm))
			break;
		usleep(250000);
	}

	ni_fsm_refresh_state(fsm);
}

static inline ni_addrconf_lease_t *
__find_corresponding_lease(ni_netdev_t *dev, sa_family_t family, unsigned int type)
{
	switch (family) {
	case AF_INET:
		return ni_netdev_get_lease(dev, AF_INET6, type);
	case AF_INET6:
		return ni_netdev_get_lease(dev, AF_INET,  type);
	default:
		return NULL;
	}
}

static int
address_acquired_callback_handler(ni_ifworker_t *w, const ni_objectmodel_callback_info_t *cb, ni_event_t event)
{
	ni_netdev_t *dev;
	ni_addrconf_lease_t *lease;
	ni_addrconf_lease_t *other;
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

	if (!w || !(dev = w->device)) {
		ni_error("%s: received %s event with uuid %s, but can't find a device for",
				w ? w->name : NULL, ni_objectmodel_event_to_signal(event),
				ni_uuid_print(&cb->uuid));
		return -1;	/* ignore?? */
	}
	if (!(lease = ni_netdev_get_lease_by_uuid(dev, &cb->uuid))) {
		ni_error("%s: received %s event with uuid %s, but can't find a lease for",
				w->name, ni_objectmodel_event_to_signal(event),
				ni_uuid_print(&cb->uuid));
		return -1;	/* ignore?? */
	}

	switch (event) {
	case NI_EVENT_ADDRESS_ACQUIRED:
		/* OK, it is granted -- adjust the state	*/
		lease->state = NI_ADDRCONF_STATE_GRANTED;
		break;

	case NI_EVENT_ADDRESS_DEFERRED:
		/* canceled wait -- remains requesting		*/
		lease->state = NI_ADDRCONF_STATE_REQUESTING;
		break;

	case NI_EVENT_ADDRESS_LOST:
		/* lease failed -- adjust the state		*/
		lease->state = NI_ADDRCONF_STATE_FAILED;
		break;

	default:
		ni_error("%s: received unexpected event %s -- ignoring it",
				w->name, ni_objectmodel_event_to_signal(event));
		return 0;	/* ??? */
	}
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
			"%s: adjusted %s:%s lease to state: %s, flags: 0x%02x",
			w->name,
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_type_to_name(lease->type),
			ni_addrconf_state_to_name(lease->state),
			lease->flags);
	ni_ifworker_print_device_leases(w);

	/* if there are still pending leases -- wait for them	*/
	if (ni_ifworker_waiting_for_event(w, cb->event))
		return 0;

	/* report back if to advance state or not */
	switch (lease->state) {
	case NI_ADDRCONF_STATE_REQUESTING:
	case NI_ADDRCONF_STATE_FAILED:
		if (ni_addrconf_flag_bit_is_set(lease->flags, NI_ADDRCONF_FLAGS_GROUP)) {
			other = __find_corresponding_lease(dev, lease->family, lease->type);
			if (other) {
				ni_addrconf_flags_format(&buf, other->flags, "|");
				ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
						"%s: %s:%s peer lease in state %s, flags %s",
						w->name,
						ni_addrfamily_type_to_name(other->family),
						ni_addrconf_type_to_name(other->type),
						ni_addrconf_state_to_name(other->state),
						buf.string ? buf.string : "none");
				ni_stringbuf_destroy(&buf);

				/* ok, peer lease is acquired, advance earlier */
				if (other->state == NI_ADDRCONF_STATE_GRANTED)
					return 0;
			}
		}

		if (ni_addrconf_flag_bit_is_set(lease->flags, NI_ADDRCONF_FLAGS_OPTIONAL))
			return 0;

		return 1;	/* do not advance state, wait until timeout */
	}

	return 0;
}

static void
ni_fsm_process_worker_event(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_event_t *ev)
{
	const char *event_name = ev->signal_name;
	ni_event_t  event_type = ev->event_type;

	switch (event_type) {
	case NI_EVENT_DEVICE_READY:
	case NI_EVENT_DEVICE_UP:
		/* Handle devices which were not present on ifup */
		if(w->pending) {
			w->pending = FALSE;
			if (ni_ifworker_start(fsm, w, fsm->worker_timeout) < 0)
				ni_ifworker_fail(w, "unable to start worker");
			return;
		}
		break;

	default:
		if (ni_ifworker_revert_state(w, event_type))
			return;
		break;
	}

	if (fsm->process_event.callback)
		fsm->process_event.callback(fsm, w, ev);

	if (!ni_uuid_is_null(&ev->event_uuid)) {
		ni_objectmodel_callback_info_t *cb;

		cb = ni_ifworker_get_callback(w, &ev->event_uuid, TRUE);
		if (cb) {
			ni_event_t cb_event_type;
			ni_bool_t success;
			int ret;

			if (ni_objectmodel_signal_to_event(cb->event, &cb_event_type) < 0)
				cb_event_type = __NI_EVENT_MAX;

			if ((success = (cb_event_type == event_type))) {
				ni_debug_events("... great, we were expecting this event");
			} else {
				ni_debug_events("%s: was waiting for %s event, but got %s",
						w->name, cb->event, ev->signal_name);
			}

			switch (cb_event_type) {
			case NI_EVENT_ADDRESS_ACQUIRED:
				/*
				 * When dhcp starts and there is a not-expired lease
				 * which can't be confirmed, it emits a release event
				 * before it acquires a new one and defers or fails.
				 * Uff... add it back to the wait list and continue.
				 */
				if (event_type == NI_EVENT_ADDRESS_RELEASED && w->fsm.wait_for) {
					ni_ifworker_add_callbacks(w->fsm.wait_for, cb, w->name);
					goto done;
				}

				ret = address_acquired_callback_handler(w, cb, event_type);
				success = ret >= 0;

				/* Set event_name and type to the callback event we wait for */
				if (ret == 0) {
					event_name = ni_objectmodel_event_to_signal(cb_event_type);
					event_type = cb_event_type; /* don't revert state on failure */
				}
				break;
			default:
				break;
			}

			if (!success)
				ni_ifworker_fail(w, "got signal %s", ev->signal_name);
			ni_objectmodel_callback_info_free(cb);
		}

		/* We do not update the ifworker state if we're waiting for more events
		 * of the same name. For instance, during address configuration, we might
		 * start several addrconf mechanisms in parallel; for each of them, we'll
		 * receive an addressAcquired (addressLost, ...) event. However, address
		 * configuration isn't complete until we've received *all* non-optional
		 * addressAcquired events outstanding for the running transition.
		 */
		if (ni_ifworker_waiting_for_event(w, event_name)) {
			ni_debug_application("%s: waiting for more %s events...",
						w->name, event_name);
			ni_ifworker_print_callbacks(w->name, w->fsm.wait_for ?
					w->fsm.wait_for->callbacks : NULL);
			goto done;
		}
	}

	ni_ifworker_advance_state(w, event_type);

	if (event_type == NI_EVENT_DEVICE_DELETE) {
		if (ni_ifworker_is_factory_device(w))
			ni_ifworker_device_delete(w);
		else
			ni_fsm_destroy_worker(fsm, w);
	}

done: ;
}

static ni_ifworker_t *
ni_fsm_process_rename_event(ni_fsm_t *fsm, ni_fsm_event_t *ev)
{
	ni_ifworker_t *w;

	if ((w = ni_fsm_recv_new_netif_path(fsm, ev->object_path)))
		ni_debug_events("%s: device renamed to %s", w->old_name, w->name);

	return w;
}

static void
ni_fsm_process_device_delete_event(ni_fsm_t *fsm, ni_fsm_event_t *ev, ni_ifworker_t *w)
{
	ni_dbus_object_t *netif_list;
	ni_dbus_object_t *object;

	/* device-ready worker exist and is possibly also active */
	if (w) {
		ni_ifworker_get(w);
		ni_fsm_process_worker_event(fsm, w, ev);
		ni_ifworker_release(w);
		ni_debug_application("deleted worker device with object path %s",
					ev->object_path);
	}

	/* we may have a created but not yet ready/pending worker */
	w = ni_ifworker_array_find_by_objectpath(&fsm->pending, ev->object_path);
	if (w) {
		ni_ifworker_get(w);
		ni_ifworker_array_remove(&fsm->pending, w);
		ni_ifworker_release(w);
		ni_debug_application("deleted pending device worker with object path %s",
					ev->object_path);
	}

	/* finally, we may also have an netif-list device object */
	if ((netif_list = ni_call_get_netif_list_object())) {
		for (object = netif_list->children; object; ) {
			if (ni_string_eq(object->path, ev->object_path)) {
				ni_dbus_object_free(object);
				ni_debug_application("deleted object %s from netif-list",
					ev->object_path);
				object = NULL;
			} else {
				object = object->next;
			}
		}
	}
}

static void
ni_fsm_process_event(ni_fsm_t *fsm, ni_fsm_event_t *ev)
{
	ni_ifworker_t *w;

	fsm->event_seq += 1;

	w = ni_fsm_ifworker_by_object_path(fsm, ev->object_path);

	ni_debug_events("process event signal %s from %s; uuid=<%s>",
			ni_objectmodel_event_to_signal(ev->event_type),
			ev->object_path, ni_uuid_print(&ev->event_uuid));

	/*
	 * wickedd emits explicit events with callback uuids to the requesters
	 * when it backgrounds execution / delivery of the result, e.g. to let
	 * the kernel emit its event ack after it processed them or dhcp needs
	 * to request a lease from server.
	 *
	 * Events are emitted also without uuid, that is regardless if the
	 * change was requested or triggered externally.
	 *
	 * That is, there are often two events of same type: ack for requested
	 * change with uuid followed by the unsolicited event without uuid.
	 */
	switch (ev->event_type) {
	case NI_EVENT_DEVICE_DELETE:
		ni_fsm_process_device_delete_event(fsm, ev, w);
		return;

	case NI_EVENT_DEVICE_CREATE:
		/* when there is no worker yet with assigned object-path,
		 * we refresh and allocate a pending worker first. */
		break;

	case NI_EVENT_DEVICE_RENAME:
		w = ni_fsm_process_rename_event(fsm, ev);
		break;

	case NI_EVENT_DEVICE_READY:
		if (w && w->fsm.state >= NI_FSM_STATE_DEVICE_READY) {
			if (ni_netdev_device_is_ready(w->device))
				return;
		}

		w = NULL; /* Force refresh (once) on device-ready event */
		break;

	case NI_EVENT_DEVICE_UP:
		if (w && w->fsm.state >= NI_FSM_STATE_DEVICE_UP) {
			if (ni_netdev_device_is_up(w->device))
				return;
		}

		w = NULL; /* Force refresh (once) on device-up event */
		break;

	case NI_EVENT_LINK_UP:
		if (w && !ni_netdev_link_is_up(w->device))
			w = NULL; /* refresh is needed */
		break;

	case NI_EVENT_ADDRESS_ACQUIRED:
		fsm->last_event_seq[ev->event_type] = fsm->event_seq;
		break;

	default:
		break;
	}

	if (!w) {
		/* fetch netif object properties and assign device to
		 * the pending fsm worker set or to config/ready worker.
		 */
		if (!ni_fsm_recv_new_netif_path(fsm, ev->object_path)) {
			ni_debug_application("%s: refresh failed, cannot process %s worker %s event",
					__func__, ev->object_path, ni_objectmodel_event_to_signal(ev->event_type));
			return;
		}
		w = ni_fsm_ifworker_by_object_path(fsm, ev->object_path);
		if (!w) {
			ni_debug_application("%s: No ready fsm worker for %s found to process %s event",
						__func__, ev->object_path, ni_objectmodel_event_to_signal(ev->event_type));
				return;
		}
	}

	ni_ifworker_get(w);
	/* process non-pending/ready or factory worker events */
	ni_fsm_process_worker_event(fsm, w, ev);
	ni_ifworker_release(w);
}

static void
interface_state_change_signal(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	const char *object_path = dbus_message_get_path(msg);
	const char *signal_name = dbus_message_get_member(msg);
	const char *suffix = NULL;
	ni_fsm_t *  fsm = user_data;
	ni_event_t  event_type;
	ni_fsm_event_t *ev;

	/* See if this event is a known one */
	if (ni_objectmodel_signal_to_event(signal_name, &event_type) < 0) {
		ni_warn("%s: unknown event signal %s from %s",
			__func__, signal_name, object_path);
		return;
	}

	/* Allocate and preparse/verify object-path */
	ev = ni_fsm_event_new(object_path, signal_name, event_type);
	ev->worker_type = ni_ifworker_type_from_object_path(ev->object_path, &suffix);
	switch (ev->worker_type) {
	case NI_IFWORKER_TYPE_NETDEV:
		if (ni_parse_uint(suffix, &ev->ifindex, 10) < 0 || !ev->ifindex) {
			ni_error("%s: cannot extract device index from signal %s object-path %s",
					__func__, ev->signal_name, ev->object_path);
			ni_fsm_event_free(ev);
			return;
		}
		break;

	case NI_IFWORKER_TYPE_MODEM:
		/* object-path match for now */
		break;

	default:
		ni_warn("%s: signal %s from unknown object-path %s type",
				__func__, signal_name, object_path);
		ni_fsm_event_free(ev);
		return;
	}

	/* See if this event comes with a uuid */
	{
		ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;

		int argc = ni_dbus_message_get_args_variants(msg, &result, 1);
		if (argc < 0) {
			ni_error("%s: cannot extract parameters of signal %s",
					__func__, signal_name);
			ni_fsm_event_free(ev);
			return;
		}

		ni_dbus_variant_get_uuid(&result, &ev->event_uuid);
		ni_dbus_variant_destroy(&result);
	}

	/* enqueue for processing */
	ni_fsm_events_append(&fsm->events, ev);

	if (fsm->block_events) {
		ni_debug_events("enqueue event signal %s from %s; uuid=<%s>",
				ni_objectmodel_event_to_signal(ev->event_type),
				ev->object_path, ni_uuid_print(&ev->event_uuid));
	} else {
		/* processed immediately */
		ni_fsm_process_events(fsm);
	}
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
ni_fsm_do(ni_fsm_t *fsm, ni_timeout_t *timeout)
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
		pending_workers = !!ni_fsm_schedule(fsm);

		fsm->timeout_count = 0;
		*timeout = ni_timer_next_timeout();
		ni_dbus_objects_garbage_collect();
	} while (fsm->timeout_count);

	return pending_workers;
}

void
ni_fsm_mainloop(ni_fsm_t *fsm)
{
	ni_timeout_t timeout;

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

ni_timeout_t
ni_fsm_find_max_timeout(ni_fsm_t *fsm, ni_timeout_t timeout)
{
	ni_timeout_t max = timeout;
	unsigned int i;

	if (!fsm || timeout >= NI_IFWORKER_INFINITE_TIMEOUT)
		return NI_IFWORKER_INFINITE_TIMEOUT;

	for (i = 0; i < fsm->workers.count; i++) {
		ni_ifworker_t *w = fsm->workers.data[i];
		ni_timeout_t add;

		add = NI_TIMEOUT_FROM_SEC(w->extra_waittime);
		max = max_t(ni_timeout_t, max, timeout + add);
	}

	return min_t(ni_timeout_t, max, NI_IFWORKER_INFINITE_TIMEOUT);
}

void
ni_fsm_set_user_prompt_fn(ni_fsm_t *fsm, ni_fsm_user_prompt_fn_t *fn, void *user_data)
{
	ni_fsm_user_prompt_fn = fn;
	ni_fsm_user_prompt_data = user_data;
}
