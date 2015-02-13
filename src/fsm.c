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

#include "client/ifconfig.h"
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
static ni_bool_t		__ni_ifworker_refresh_netdevs(ni_fsm_t *);
#ifdef MODEM
static ni_bool_t		__ni_ifworker_refresh_modems(ni_fsm_t *);
#endif
static int			ni_fsm_user_prompt_default(const ni_fsm_prompt_t *, xml_node_t *, void *);
static void			ni_ifworker_refresh_client_state(ni_ifworker_t *, ni_client_state_t *);
static void			ni_ifworker_set_config_origin(ni_ifworker_t *, const char *);
static void			ni_ifworker_cancel_timeout(ni_ifworker_t *);
static void			ni_ifworker_cancel_secondary_timeout(ni_ifworker_t *);
static void			ni_ifworker_cancel_callbacks(ni_ifworker_t *, ni_objectmodel_callback_info_t **);
static dbus_bool_t		ni_ifworker_waiting_for_events(ni_ifworker_t *);
static void			ni_ifworker_advance_state(ni_ifworker_t *, ni_event_t);

static void			ni_ifworker_update_client_state_control(ni_ifworker_t *w);
static inline void		ni_ifworker_update_client_state_config(ni_ifworker_t *w);

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

	ni_ifworker_control_init(&w->control);
	ni_client_state_config_init(&w->config.meta);

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

static void
__ni_ifworker_reset_fsm(ni_ifworker_t *w)
{
	ni_objectmodel_callback_info_t *cb;
	ni_fsm_require_t *req_list;

	if (!w)
		return;

	ni_ifworker_cancel_secondary_timeout(w);
	ni_ifworker_cancel_timeout(w);

	if (w->fsm.action_table) {
		ni_fsm_transition_t *action;

		for (action = w->fsm.action_table; action->next_state; action++) {
			ni_fsm_require_list_destroy(&action->require.list);
			while ((cb = action->callbacks) != NULL) {
				action->callbacks = cb->next;
				cb->next = NULL;
				ni_objectmodel_callback_info_free(cb);
			}
		}
		free(w->fsm.action_table);
	}
	w->fsm.action_table = NULL;

	req_list = w->fsm.child_state_req_list;
	memset(&w->fsm, 0, sizeof(w->fsm));
	w->fsm.child_state_req_list = req_list;
}

void
ni_ifworker_rearm(ni_ifworker_t *w)
{
	w->target_state = NI_FSM_STATE_NONE;
	w->done = FALSE;
	w->failed = FALSE;
	w->kickstarted = FALSE;
	__ni_ifworker_reset_fsm(w);
}

void
ni_ifworker_reset(ni_ifworker_t *w)
{
	ni_ifworker_cancel_secondary_timeout(w);
	ni_ifworker_cancel_timeout(w);

	ni_string_free(&w->object_path);
	ni_ifworker_control_init(&w->control);
	ni_string_free(&w->config.meta.origin);
	ni_security_id_destroy(&w->security_id);

	/* When detaching children, clear their lowerdev/masterdev ownership info */
	if (w->children.count != 0) {
		unsigned int i;

		for (i = 0; i < w->children.count; ++i) {
			ni_ifworker_t *child = w->children.data[i];

			if (child->masterdev == w)
				child->masterdev = NULL;

			if (child == w->lowerdev) {
				ni_ifworker_array_remove(&child->lowerdev_for, w);
				w->lowerdev = NULL;
			}
		}
	}
	ni_ifworker_array_destroy(&w->children);
	ni_ifworker_array_destroy(&w->lowerdev_for);

	w->target_state = NI_FSM_STATE_NONE;
	w->target_range.min = NI_FSM_STATE_NONE;
	w->target_range.max = __NI_FSM_STATE_MAX;

	/* Clear config and stats*/
	ni_client_state_config_init(&w->config.meta);

	__ni_ifworker_reset_fsm(w);
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
	if (w->device)
		ni_netdev_put(w->device);
	if (w->modem)
		ni_modem_release(w->modem);
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

	ni_ifworker_cancel_secondary_timeout(w);
	ni_ifworker_cancel_timeout(w);
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

	if (w->progress.callback)
		w->progress.callback(w, w->fsm.state);

	__ni_ifworker_done(w);
}

void
ni_ifworker_success(ni_ifworker_t *w)
{
	__ni_ifworker_done(w);

	if (w->progress.callback)
		w->progress.callback(w, w->fsm.state);
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
ni_fsm_timer_register(unsigned long timeout_ms, ni_fsm_timer_ctx_t *tcx)
{
	return ni_timer_register(timeout_ms, ni_fsm_timer_call, tcx);
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
ni_ifworker_set_timeout(ni_fsm_t *fsm, ni_ifworker_t *w, unsigned long timeout_ms)
{
	ni_fsm_timer_ctx_t *tcx;

	ni_ifworker_cancel_timeout(w);

	if (!timeout_ms || timeout_ms == NI_IFWORKER_INFINITE_TIMEOUT)
		return;

	if (!(tcx = ni_fsm_timer_ctx_new(fsm, w, ni_ifworker_timeout)))
		return;

	w->fsm.timer = ni_fsm_timer_register(timeout_ms, tcx);
}

static inline void
ni_ifworker_set_secondary_timeout(ni_fsm_t *fsm, ni_ifworker_t *w, unsigned long timeout_ms,
					ni_fsm_timer_fn_t *handler)
{
	ni_fsm_timer_ctx_t *tcx;

	ni_ifworker_cancel_secondary_timeout(w);

	if (!handler || !timeout_ms || timeout_ms == NI_IFWORKER_INFINITE_TIMEOUT)
		return;

	if (!(tcx = ni_fsm_timer_ctx_new(fsm, w, handler)))
		return;

	w->fsm.secondary_timer = ni_fsm_timer_register(timeout_ms, tcx);
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
	{ "network-up",		NI_FSM_STATE_ADDRCONF_UP	},
	{ "max",		__NI_FSM_STATE_MAX		},

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
ni_ifworker_array_find(ni_ifworker_array_t *array, ni_ifworker_type_t type, const char *ifname)
{
	unsigned int i;

	if (ni_string_empty(ifname))
		return NULL;

	for (i = 0; i < array->count; ++i) {
		ni_ifworker_t *worker = array->data[i];

		if (worker->type == type && !strcmp(worker->name, ifname))
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

void
ni_ifworker_array_remove_with_children(ni_ifworker_array_t *array, ni_ifworker_t *w)
{
	if (ni_ifworker_array_index(array, w) != -1) {
		unsigned int i;

		for (i = 0; i < w->children.count; i++) {
			ni_ifworker_array_remove_with_children(array, w->children.data[i]);
		}
		ni_ifworker_array_remove(array, w);
	}
}

static unsigned int
__ni_fsm_dbus_objectpath_to_ifindex(const char *object_path)
{
	ni_string_array_t nsa = NI_STRING_ARRAY_INIT;
	unsigned int ifindex = 0;

	if (ni_string_empty(object_path))
		goto done;

	if (!ni_string_split(&nsa, object_path, "/", 0)) {
		ni_error("unable to parse object_path=%s", object_path);
		goto done;
	}

	if (ni_parse_uint(nsa.data[nsa.count-1], &ifindex, 10) < 0) {
		ni_error("wrong ifindex value in object_path=%s", object_path);
		goto done;
	}

done:
	ni_string_array_destroy(&nsa);
	return ifindex;
}

/*
 * __ni_dbus_objectpath_to_name() allocates a string and return interface name
 */
static char *
__ni_fsm_dbus_objectpath_to_name(const char *object_path)
{
	char buf[IF_NAMESIZE+1] = { 0 };
	unsigned int ifindex;
	char *ifname = NULL;

	if (ni_string_empty(object_path))
		return NULL;;

	ifindex = __ni_fsm_dbus_objectpath_to_ifindex(object_path);
	if (!if_indextoname(ifindex, buf)) {
		ni_debug_application("unable to get ifname from ifindex=%d", ifindex);
		return NULL;
	}

	ni_string_dup(&ifname, buf);
	return ifname;
}

ni_ifworker_t *
ni_fsm_ifworker_by_name(ni_fsm_t *fsm, ni_ifworker_type_t type, const char *ifname)
{
	return ni_ifworker_array_find(&fsm->workers, type, ifname);
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
	ni_ifworker_t *w;
	char *ifname;
	unsigned int i;

	if (ni_string_empty(object_path))
		return NULL;

	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if (w->object_path && !strcmp(w->object_path, object_path))
			return w;
	}

	/* ifworker may not be refreshed (no object_path set nor ifindex) */
	ifname = __ni_fsm_dbus_objectpath_to_name(object_path);
	if (ni_string_empty(ifname))
		return NULL;

	w = ni_fsm_ifworker_by_name(fsm, NI_IFWORKER_TYPE_NETDEV, ifname);
	ni_string_free(&ifname);

	return w;
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

	/* ifworker name must be same as policy name here.
	 * If device name matches policy name then we
	 *  consider such a match as fulfilled.
	 */
	if (ni_string_eq(w->name, ifname))
		return TRUE;

	ni_error("device %s requested via match is not present", ifname);
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
			child = ni_ifworker_array_find(&fsm->workers, type, slave_name);

			if (child == NULL) {
				ni_error("%s: <%s> element references unknown device %s",
						origin, devnode->name, slave_name);
				return NULL;
			}
		} else {
			ni_warn("%s: obsolete: using <device> node without namespace attribute "
				"- please use <device namespace=\"...\"> instead", origin);
			child = ni_ifworker_identify_device(fsm, devnode, type, origin);
		}
		if (child == NULL) {
			ni_error("%s: <%s> element references unknown device",
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
	} else {
		ni_error("%s: empty device reference in <%s> element",
			origin, devnode->name);
		return NULL;
	}

	return child;
}

static xml_node_t *
__ni_generate_default_config(const char *ifname, ni_iftype_t ptype, xml_node_t *control)
{
	xml_node_t *ipv4, *ipv6, *config = NULL;

	if (ni_string_empty(ifname) || !ptype)
		goto error;

	/* Create <interface> */
	if (!(config = xml_node_new(NI_CLIENT_IFCONFIG, NULL)))
		goto error;
	/* Add <name>$ifname</name> */
	if (!xml_node_new_element(NI_CLIENT_IFCONFIG_MATCH_NAME, config, ifname))
		goto error;
	/* Add <link></link> */
	if (!xml_node_new(NI_CLIENT_IFCONFIG_LINK, config))
		goto error;
	/* Add <ipv4></ipv4> and <ipv6></ipv6> */
	if (!(ipv4 = xml_node_new(NI_CLIENT_IFCONFIG_IPV4, config)))
		goto error;
	 if (!(ipv6 = xml_node_new(NI_CLIENT_IFCONFIG_IPV6, config)))
		 goto error;

	switch (ptype) {
	/* for slaves */
	case NI_IFTYPE_BOND:
		/*
		 * STARTMODE="hotplug"
		 * BOOTPROTO="none"
		 */

		/* Add <control></control> */
		if (!(control = xml_node_new(NI_CLIENT_IFCONFIG_CONTROL, config)))
			goto error;
		/* Add <mode>hotplug</mode> */
		if (!xml_node_new_element(NI_CLIENT_IFCONFIG_MODE, control, "hotplug"))
			goto error;
		if (!xml_node_new_element(NI_CLIENT_IFCONFIG_IP_ENABLED, ipv4, "false"))
			 goto error;
		if (!xml_node_new_element(NI_CLIENT_IFCONFIG_IP_ENABLED, ipv6, "false"))
			 goto error;
	break;

	case NI_IFTYPE_BRIDGE:
		/*
		 * STARTMODE="$pstartmode"
		 * BOOTPROTO="none"
		 */

		/* Clone <control> */
		if (!xml_node_is_empty(control) && !xml_node_clone(control, config))
			goto error;
		if (!xml_node_new_element(NI_CLIENT_IFCONFIG_IP_ENABLED, ipv4, "false"))
			 goto error;
		if (!xml_node_new_element(NI_CLIENT_IFCONFIG_IP_ENABLED, ipv6, "false"))
			 goto error;
	break;

	/* lowerdevs */
	case NI_IFTYPE_VLAN:
	case NI_IFTYPE_MACVLAN:
	case NI_IFTYPE_MACVTAP:
		/*
		 * STARTMODE="$pstartmode"
		 * BOOTPROTO="static"
		 */

		/* Clone <control> */
		if (!xml_node_is_empty(control) && !xml_node_clone(control, config))
			goto error;
		if (!xml_node_new_element(NI_CLIENT_IFCONFIG_IP_ENABLED, ipv4, "true"))
			 goto error;
		if (!xml_node_new_element(NI_CLIENT_IFCONFIG_ARP_VERIFY, ipv4, "true"))
			 goto error;
		if (!xml_node_new_element(NI_CLIENT_IFCONFIG_IP_ENABLED, ipv6, "true"))
			 goto error;
	break;

	default:
		goto error;
     }

	return config;

error:
	ni_error("%s: Unable to generate default XML config (parent type %s)",
		ifname, ni_linktype_type_to_name(ptype));
	xml_node_free(config);
	return NULL;
}

static void
ni_ifworker_generate_default_config(ni_ifworker_t *parent, ni_ifworker_t *child)
{
	xml_node_t *control, *config;

	if (!parent || !child)
		return;

	ni_debug_application("%s: generating default config for %s child",
		parent->name, child->name);

	control = xml_node_get_child(parent->config.node,
		NI_CLIENT_IFCONFIG_CONTROL);
	config = __ni_generate_default_config(child->name, parent->iftype, control);

	ni_ifworker_set_config(child, config, parent->config.meta.origin);
}

static ni_bool_t
ni_ifworker_add_child_master(xml_node_t *config, const char *name)
{
	xml_node_t *link, *master;

	if (xml_node_is_empty(config) || ni_string_empty(name))
		return FALSE;

	if (!(link = xml_node_get_child(config, NI_CLIENT_IFCONFIG_LINK))) {
		if (!(link = xml_node_new(NI_CLIENT_IFCONFIG_LINK, config)))
			return FALSE;
	}

	if (!(master = xml_node_get_child(link, NI_CLIENT_IFCONFIG_MASTER))) {
		if (!xml_node_new_element(NI_CLIENT_IFCONFIG_MASTER, link, name))
			return FALSE;
	}
	else if (!ni_string_eq(master->cdata, name)) {
		ni_error("Failed adding <master>%s</master> to <link> -"
			"there is already one <master>%s</master>", name, master->cdata);
		return FALSE;
	}

	return TRUE;
}

static ni_bool_t
ni_ifworker_add_child(ni_ifworker_t *parent, ni_ifworker_t *child, xml_node_t *devnode, ni_bool_t shared)
{
	unsigned int i;
	char *other_owner;

	/* Check if this child is already owned by the given parent. */
	for (i = 0; i < parent->children.count; ++i) {
		if (parent->children.data[i] == child) {
			if (xml_node_is_empty(child->config.node))
				ni_ifworker_generate_default_config(parent, child);
			return TRUE;
		}
	}

	if (shared) {
		/* The reference allows sharing with other uses, e.g. VLANs. */
		if (parent->lowerdev) {
			if (xml_node_is_empty(parent->lowerdev->config.node)) {
				ni_error("%s (%s): subordinate interface's lowerdev %s has no config node",
					parent->name, xml_node_location(devnode), parent->lowerdev->name);
				return FALSE;
			}
			other_owner = strdup(xml_node_location(parent->lowerdev->config.node));
			ni_debug_application("%s (%s): subordinate interface already has lowerdev %s (%s)",
				parent->name, xml_node_location(devnode),
				parent->lowerdev->name, other_owner);
			free(other_owner);
			return TRUE;
		}
		else {
			parent->lowerdev = child;
			if (ni_ifworker_array_index(&child->lowerdev_for, parent) < 0)
				ni_ifworker_array_append(&child->lowerdev_for, parent);
		}
	}
	else {
		if (child->masterdev) {
			if (xml_node_is_empty(child->masterdev->config.node)) {
				ni_error("%s (%s): subordinate interface's master device %s has no config node",
					child->name, xml_node_location(devnode), child->masterdev->name);
				return FALSE;
			}
			other_owner = strdup(xml_node_location(child->masterdev->config.node));
			ni_debug_application("%s (%s): subordinate interface already has masterdev %s (%s)",
				child->name, xml_node_location(devnode),
				child->masterdev->name, other_owner);
			free(other_owner);
			return TRUE;
		}
		else
			child->masterdev = parent;
	}

	if (xml_node_is_empty(child->config.node))
		ni_ifworker_generate_default_config(parent, child);

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

static inline void
ni_ifworker_update_client_state_config(ni_ifworker_t *w)
{
	if (w && w->object && !w->readonly) {
		ni_call_set_client_state_config(w->object, &w->config.meta);
		ni_client_state_config_debug(w->name, &w->config.meta, "update");
	}
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

		if ((new_state == NI_FSM_STATE_DEVICE_READY ||
		    new_state == NI_FSM_STATE_DEVICE_SETUP) && w->object && !w->readonly) {
			ni_ifworker_update_client_state_control(w);
			ni_ifworker_update_client_state_config(w);
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
	unsigned int min_state = NI_FSM_STATE_NONE, max_state = __NI_FSM_STATE_MAX;

	switch (event_type) {
	case NI_EVENT_DEVICE_DELETE:
		max_state = NI_FSM_STATE_DEVICE_EXISTS - 1;
		break;
	case NI_EVENT_DEVICE_DOWN:
		/* We should restart FSM on successful devices */
		if (ni_ifworker_complete(w))
			ni_ifworker_rearm(w);
		max_state = NI_FSM_STATE_DEVICE_UP - 1;
		break;
	case NI_EVENT_DEVICE_CREATE:
		min_state = NI_FSM_STATE_DEVICE_EXISTS;
		break;
	case NI_EVENT_DEVICE_READY:
		min_state = NI_FSM_STATE_DEVICE_READY;
		break;
	case NI_EVENT_DEVICE_UP:
		min_state = NI_FSM_STATE_DEVICE_UP;
		break;
	case NI_EVENT_LINK_UP:
		min_state = NI_FSM_STATE_LINK_UP;
		break;
	case NI_EVENT_LINK_DOWN:
		/* We should restart FSM on successful devices */
		if (ni_ifworker_complete(w))
			ni_ifworker_rearm(w);
		max_state = NI_FSM_STATE_LINK_UP - 1;
		break;
	case NI_EVENT_ADDRESS_DEFERRED:
	case NI_EVENT_ADDRESS_ACQUIRED:
		min_state = NI_FSM_STATE_ADDRCONF_UP;
		break;
	case NI_EVENT_ADDRESS_RELEASED:
		max_state = NI_FSM_STATE_ADDRCONF_UP - 1;
		break;
	default:
		break;
	}

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
		"%s: advance fsm state by signal %s: <%s..%s>", w->name,
		ni_objectmodel_event_to_signal(event_type),
		ni_ifworker_state_name(min_state),
		ni_ifworker_state_name(max_state));

	ni_ifworker_update_state(w, min_state, max_state);
}

static void
ni_ifworker_refresh_client_state(ni_ifworker_t *w, ni_client_state_t *cs)
{
	if (!w || !cs)
		return;

	w->control.persistent = cs->control.persistent;
	w->control.usercontrol = cs->control.usercontrol;

	w->config.meta.uuid = cs->config.uuid;
	w->config.meta.owner = cs->config.owner;
	ni_ifworker_set_config_origin(w, cs->config.origin);

	ni_client_state_debug(w->name, cs, "refresh");
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
	control->link_timeout  = NI_IFWORKER_INFINITE_TIMEOUT;
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

	if (!w)
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

	if (!w)
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
	control->link_timeout  = NI_IFWORKER_INFINITE_TIMEOUT;
	if ((linknode = xml_node_get_child(ctrlnode, "link-detection")) != NULL) {
		if ((np = xml_node_get_child(linknode, "timeout")) != NULL) {
			if (ni_string_eq(np->cdata, "infinite"))
				control->link_timeout = NI_IFWORKER_INFINITE_TIMEOUT;
			else
				ni_parse_uint(np->cdata, &control->link_timeout, 10);
			if (control->link_timeout == 0)
				control->link_timeout = NI_IFWORKER_INFINITE_TIMEOUT;
			else
				control->link_timeout *= 1000;
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
	unsigned int extra_timeout = 0;
	const xml_node_t *brnode;

	if (!w || xml_node_is_empty(w->config.node))
		return;

	/* Adding bridge dependent values (STP, Forwarding times) */
	if ((brnode = xml_node_get_child(w->config.node, "bridge")))
		extra_timeout += ni_bridge_waittime_from_xml(brnode);

	w->extra_waittime = (extra_timeout*1000);
}

static ni_iftype_t
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

	if ((child = xml_node_get_child(ifnode, NI_CLIENT_STATE_XML_NODE))) {
		ni_error("%s node is specifid in %s config file - ignoring it",
			NI_CLIENT_STATE_XML_NODE, config_origin);
		xml_node_detach(child);
	}

	w->iftype = ni_ifworker_iftype_from_xml(ifnode);
	ni_ifworker_extra_waittime_from_xml(w);
}

/*
 * Given an XML document, build interface and modem objects, and policies from it.
 */
ni_bool_t
ni_fsm_workers_from_xml(ni_fsm_t *fsm, xml_node_t *ifnode, const char *origin)
{
	ni_ifworker_type_t type;
	const char *ifname = NULL;
	xml_node_t *node;
	ni_ifworker_t *w = NULL;

	if (!fsm || xml_node_is_empty(ifnode))
		return FALSE;

	type = ni_ifworker_type_from_string(ifnode->name);
	if (type == NI_IFWORKER_TYPE_NONE) {
		ni_warn("%s: ignoring non-interface element <%s>",
				xml_node_location(ifnode),
				ifnode->name);
		return FALSE;
	}

	if ((node = xml_node_get_child(ifnode, "identify")) != NULL) {
		ni_warn("%s: using obsolete <identify> element - please use <name namespace=\"...\"> instead", xml_node_location(ifnode));
		w = ni_ifworker_identify_device(fsm, node, type, origin);
	} else
	if ((node = xml_node_get_child(ifnode, "name")) != NULL) {
		const char *namespace;

		namespace = xml_node_get_attr(node, "namespace");
		if (namespace != NULL) {
			w = __ni_ifworker_identify_device(fsm, namespace, node, type, origin);
		} else {
			ifname = node->cdata;
			if (ifname && (w = ni_fsm_ifworker_by_name(fsm, type, ifname)) == NULL)
				w = ni_ifworker_new(fsm, type, ifname);
		}
	}

	if (w == NULL) {
		ni_error("%s: ignoring unknown interface configuration",
			xml_node_location(ifnode));
		return FALSE;
	}

	ni_ifworker_set_config(w, ifnode, origin);

	return TRUE;
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

	if (!(child_worker = ni_ifworker_resolve_reference(fsm, devnode, NI_IFWORKER_TYPE_NETDEV, w->name)))
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

	if (!(child_worker = ni_ifworker_resolve_reference(fsm, devnode, NI_IFWORKER_TYPE_MODEM, w->name)))
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
		ni_ifworker_fail(w, "link did not come up in specified time");
	}
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

	if (!xml_node_is_empty(w->config.node) &&
	    (config = xml_node_get_child(w->config.node, "policies"))) {
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

		if (!match->mode && !match->ignore_startmode) {
			if (ni_string_eq_nocase(w->control.mode, "off"))
				continue;

			if (!match->name && ni_string_eq_nocase(w->control.mode, "manual"))
				continue;
		}

		if (match->name && !ni_string_eq(match->name, w->name))
			continue;

		/* skipping ifworkers without xml configuration */
		if (match->require_config && !w->config.node) {
			ni_info("skipping %s interface: "
				"no configuration provided", w->name);
			continue;
		}
		/* skipping ifworkers of interfaces not configured in the past */
		if (match->require_configured &&
		    ni_string_empty(w->config.meta.origin)) {
			ni_info("skipping %s interface: "
				"device is not configured by wicked yet", w->name);
			continue;
		}
		/* skipping ifworkers of interfaces in the persistent mode */
		if (!match->allow_persistent && w->control.persistent) {
			ni_info("skipping %s interface: "
				"persistent mode is on", w->name);
			continue;
		}

		/* skipping ifworkers of interfaces user must not control */
		if (!w->control.usercontrol && geteuid() != 0) {
			ni_debug_application("skipping %s interface: "
				"user control is not allowed", w->name);
			continue;
		}

		if (match->mode && !ni_string_eq(match->mode, w->control.mode))
			continue;

		if (match->boot_stage && !ni_string_eq(match->boot_stage, w->control.boot_stage))
			continue;

		if (match->skip_origin) {
			ni_netdev_t *dev = w->device;
			ni_client_state_t *cs = dev ? dev->client_state : NULL;
			const char *origin = cs ? cs->config.origin : NULL;

			if (ni_string_startswith(origin, match->skip_origin)) {
				continue;
			}
		}

		if (match->skip_active && w->device && ni_netdev_device_is_up(w->device))
			continue;

		if (match->name) { /* Check only when particular interface specified */
			if (!match->ifdown) {
				if (w->masterdev) { /* Pull in also masterdev */
					if (ni_ifworker_array_index(result, w->masterdev) < 0)
						ni_ifworker_array_append(result, w->masterdev);
				}
				if (w->lowerdev) {
					if (ni_ifworker_array_index(result, w->lowerdev) < 0)
						ni_ifworker_array_append(result, w->lowerdev);
				}
			}
			else {
				if (w->masterdev) {
					if (ni_ifworker_array_index(result, w->masterdev) < 0) {
						ni_info("skipping %s interface: "
							"unable to ifdown due to masterdev dependency to: %s",
							w->name, w->masterdev->name);
						continue;
					}
				}

				if (w->lowerdev_for.count > 0) {
					ni_bool_t missing_dep = FALSE;
					unsigned int i;

					for (i = 0; i < w->lowerdev_for.count; i++) {
						ni_ifworker_t *dep = w->lowerdev_for.data[i];

						if (ni_ifworker_array_index(result, dep) < 0) {
							ni_info("skipping %s interface: "
								"unable to ifdown due to lowerdev dependency to: %s",
								w->name, dep->name);
							missing_dep = TRUE;
						}
					}

					if (missing_dep)
						continue;
				}
			}
		}

		if (ni_ifworker_array_index(result,w) < 0)
			ni_ifworker_array_append(result, w);
	}

	/* Collect all workers in the device graph, and sort them
	 * by increasing depth.
	 */
	ni_ifworkers_flatten(result);

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

		if (ni_ifworker_is_running(child))
			continue;

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

void
ni_ifworkers_flatten(ni_ifworker_array_t *array)
{
	unsigned int i;

	/* Note, we take the array->count outside the loop.
	 * Inside the loop, we're adding new ifworkers to the array,
	 * and do that recursively. Avoid processing these newly
	 * added devices twice.
	 * NB a simple tail recursion won't work here.
	 */
	for (i = 0; i < array->count; ++i) {
		ni_ifworker_t *w = array->data[i];

		if (w->masterdev)
			continue;

		__ni_ifworker_flatten(w, array, 0);
	}

	qsort(array->data, array->count, sizeof(array->data[0]), __ni_ifworker_depth_compare);
}

static void
__ni_fsm_pull_in_children(ni_ifworker_t *w, ni_ifworker_array_t *array)
{
	unsigned int i;

	for (i = 0; i < w->children.count; i++) {
		ni_ifworker_t *child = w->children.data[i];

		if (xml_node_is_empty(child->config.node))
			ni_ifworker_generate_default_config(w, child);

		if (xml_node_is_empty(child->config.node)) {
			ni_debug_application("%s: ignoring dependent child %s - no config",
				w->name, child->name);
			continue;
		}

		if (ni_ifworker_array_index(array, child) < 0) {
			if (ni_ifworker_complete(child))
				ni_ifworker_rearm(child);
			ni_ifworker_array_append(array, child);
		}
		__ni_fsm_pull_in_children(child, array);
	}
}

void
ni_fsm_pull_in_children(ni_ifworker_array_t *array)
{
	unsigned int i;

	if (!array)
		return;

	for (i = 0; i < array->count; i++) {
		ni_ifworker_t *w = array->data[i];

		__ni_fsm_pull_in_children(w, array);
	}
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

		w->target_range = marker->target_range;

		/* Clean client-info origin and UUID on ifdown */
		if (marker->target_range.max < NI_FSM_STATE_DEVICE_SETUP)
			ni_client_state_config_init(&w->config.meta);

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
		int rv;

		if (w->failed)
			continue;

		if (!w->device && !ni_ifworker_is_factory_device(w)) {
			w->pending = TRUE;
			ni_ifworker_set_timeout(fsm, w, fsm->worker_timeout);
			continue;
		}

		if ((rv = ni_ifworker_start(fsm, w, fsm->worker_timeout)) < 0)
			return rv;

		if (w->target_state != NI_FSM_STATE_NONE)
			count++;
	}
	ni_ifworkers_flatten(&fsm->workers);
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
			w->target_range.max = __NI_FSM_STATE_MAX;
		}
	}
}

static void
ni_fsm_clear_hierarchy(ni_ifworker_t *w)
{
	unsigned int i;

	if (w->masterdev)
		ni_ifworker_array_remove(&w->masterdev->children, w);

	if (w->lowerdev)
		ni_ifworker_array_remove(&w->lowerdev->lowerdev_for, w);

	for (i = 0; i < w->lowerdev_for.count; i++) {
		ni_ifworker_t *ldev_usr = w->lowerdev_for.data[i];

		ni_ifworker_array_remove(&ldev_usr->children, w);
		ldev_usr->lowerdev = NULL;
	}

	for (i = 0; i < w->children.count; i++) {
		ni_ifworker_t *child = w->children.data[i];

		if (child->masterdev == w)
			child->masterdev = NULL;
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

	ni_ifworker_cancel_secondary_timeout(w);
	ni_ifworker_cancel_timeout(w);

	if (ni_ifworker_active(w))
		ni_ifworker_fail(w, "device has been deleted");

	ni_fsm_clear_hierarchy(w);
	ni_ifworker_release(w);
	return TRUE;
}

int
ni_ifworker_start(ni_fsm_t *fsm, ni_ifworker_t *w, unsigned long timeout)
{
	unsigned int min_state = w->target_range.min;
	unsigned int max_state = w->target_range.max;
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

	ni_debug_application("%s: current state=%s target state=%s",
				w->name,
				ni_ifworker_state_name(w->fsm.state),
				ni_ifworker_state_name(w->target_state));

	if (w->target_state != NI_FSM_STATE_NONE)
		ni_ifworker_set_timeout(fsm, w, timeout);

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
static void		__ni_ifworker_print(const ni_ifworker_t *, unsigned int);

int
ni_fsm_build_hierarchy(ni_fsm_t *fsm, ni_bool_t destructive)
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

		if ((rv = ni_ifworker_bind_early(w, fsm, FALSE)) < 0) {
			if (destructive) {
				if (-NI_ERROR_DOCUMENT_ERROR == rv)
					ni_debug_application("%s: configuration failed", w->name);
				ni_fsm_destroy_worker(fsm, w);
				i--;
			}
		}
	}

	if (ni_log_facility(NI_TRACE_APPLICATION))
		ni_debug_application("Device hierarchy structure:");

	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (w->masterdev) {
			if (!ni_ifworker_add_child_master(w->config.node, w->masterdev->name))
				continue;
			ni_ifworker_generate_uuid(w);
		}

		if (ni_log_facility(NI_TRACE_APPLICATION)) {
			if (!w->lowerdev_for.count && !w->masterdev)
				__ni_ifworker_print(w, 0);
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
			if (!(child_worker = ni_ifworker_resolve_reference(closure->fsm, node, NI_IFWORKER_TYPE_NETDEV, w->name)))
				continue;

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
			if (!(child_worker = ni_ifworker_resolve_reference(closure->fsm, node, NI_IFWORKER_TYPE_MODEM, w->name)))
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
				ni_debug_application("%s: <meta:require check=netif-child-state> without netif-reference",
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
__ni_ifworker_print(const ni_ifworker_t *w, unsigned int depth)
{
	unsigned int i;

	if (!w)
		return;

	if (!depth) {
		ni_debug_application("%s", w->name);
		depth+=3;
	}
	for (i = 0; i < w->children.count; i++) {
		ni_ifworker_t *child = w->children.data[i];

		if (child->masterdev == w)
			ni_debug_application("%*s %s", depth, "*--", child->name);
		else if (w->lowerdev == child)
			ni_debug_application("%*s %s", depth, "+--", child->name);
		else
			ni_debug_application("%*s %s", depth, "   ", child->name);

		__ni_ifworker_print(child, depth+4);
	}
}

static void
ni_fsm_refresh_master_dev(ni_fsm_t *fsm, ni_ifworker_t *w)
{
	const char *mname;
	ni_netdev_t *dev;

	if (!fsm || !w || !(dev = w->device))
		return;

	mname = dev->link.masterdev.name;
	if (ni_string_empty(mname))
		return;

	w->masterdev = ni_fsm_ifworker_by_name(fsm,
			NI_IFWORKER_TYPE_NETDEV, mname);

	if (w->masterdev) {
		ni_ifworker_array_t *children = &w->masterdev->children;

		if (ni_ifworker_array_index(children, w) < 0)
			ni_ifworker_array_append(children, w);
	}
}

static void
ni_fsm_refresh_lower_dev(ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_ifworker_t *lower;
	const char *lname;
	ni_netdev_t *dev;

	if (!fsm || !w || !(dev = w->device))
		return;

	lname = dev->link.lowerdev.name;
	if (ni_string_empty(lname))
		return;

	lower = ni_fsm_ifworker_by_name(fsm, NI_IFWORKER_TYPE_NETDEV, lname);
	if (!lower)
		return;

	w->lowerdev = lower;
	if (ni_ifworker_array_index(&lower->lowerdev_for, w) < 0)
		ni_ifworker_array_append(&lower->lowerdev_for, w);

	if (ni_ifworker_array_index(&w->children, lower) < 0)
		ni_ifworker_array_append(&w->children, lower);
}

ni_bool_t
ni_fsm_refresh_state(ni_fsm_t *fsm)
{
	ni_ifworker_t *w;
	unsigned int i;

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

	if (!__ni_ifworker_refresh_netdevs(fsm))
		return FALSE;
#ifdef MODEM
	if (!__ni_ifworker_refresh_modems(fsm))
		return FALSE;
#endif

	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		/* Rebuild hierarchy */
		ni_fsm_refresh_master_dev(fsm, w);
		ni_fsm_refresh_lower_dev(fsm, w);

		/* Set initial state of existing devices */
		if (w->object != NULL)
			ni_ifworker_update_state(w, NI_FSM_STATE_DEVICE_EXISTS, __NI_FSM_STATE_MAX);
	}

	return TRUE;
}

static ni_bool_t
__ni_ifworker_refresh_netdevs(ni_fsm_t *fsm)
{
	static ni_dbus_object_t *list_object = NULL;
	ni_dbus_object_t *object;

	if (!list_object && !(list_object = ni_call_get_netif_list_object())) {
		ni_error("unable to get server's interface list");
		return FALSE;
	}

	/* Call ObjectManager.GetManagedObjects to get list of objects and their properties */
	if (!ni_dbus_object_refresh_children(list_object)) {
		ni_error("Couldn't refresh list of active network interfaces");
		return FALSE;
	}

	for (object = list_object->children; object; object = object->next)
		ni_fsm_recv_new_netif(fsm, object, FALSE);
	return TRUE;
}

ni_ifworker_t *
ni_fsm_recv_new_netif(ni_fsm_t *fsm, ni_dbus_object_t *object, ni_bool_t refresh)
{
	ni_netdev_t *dev = ni_objectmodel_unwrap_netif(object, NULL);
	ni_ifworker_t *found = NULL;

	if (dev == NULL || dev->name == NULL || refresh) {
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

	if (ni_netdev_device_is_ready(dev)) {
		found = ni_fsm_ifworker_by_name(fsm, NI_IFWORKER_TYPE_NETDEV, dev->name);
		if (ni_ifworker_is_config_worker(found)) {
			ni_ifworker_t *real_w = ni_fsm_ifworker_by_ifindex(fsm, dev->link.ifindex);

			if (real_w)
				ni_fsm_destroy_worker(fsm, real_w);
		}
	}
	if (!found)
		found = ni_fsm_ifworker_by_netdev(fsm, dev);
	if (!found)
		found = ni_fsm_ifworker_by_object_path(fsm, object->path);
	if (!found) {
		ni_debug_application("received new device %s (%s)", dev->name, object->path);
		found = ni_ifworker_new(fsm, NI_IFWORKER_TYPE_NETDEV, dev->name);
		found->readonly = fsm->readonly;
		if (dev->client_state)
			ni_ifworker_refresh_client_state(found, dev->client_state);
	}

	if (!found->object_path)
		ni_string_dup(&found->object_path, object->path);
	if (found->device)
		ni_netdev_put(found->device);
	found->device = ni_netdev_get(dev);
	if (!ni_string_eq(found->name, dev->name))
		ni_string_dup(&found->name, dev->name);
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
__ni_ifworker_refresh_modems(ni_fsm_t *fsm)
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
		ni_fsm_recv_new_modem(fsm, object, FALSE);
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

	if (!w->object && ni_ifworker_is_factory_device(w))
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
		ni_ifworker_update_from_request(w, bind->service->name,
				bind->method->name, rv, callback_list);
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

	/* Reset wait_for if there are no callbacks ... */
	if (count == 0) {
		/* ... unless this action requires ACK via event */
		if (action->next_state != NI_FSM_STATE_DEVICE_DOWN)
			w->fsm.wait_for = NULL;
	}

	if (w->fsm.wait_for != NULL)
		return 0;

	ni_ifworker_set_state(w, action->next_state);
	return 0;
}

static int
ni_ifworker_link_detection_call(ni_fsm_t *fsm, ni_ifworker_t *w, ni_fsm_transition_t *action)
{
	int ret;

	ret = ni_ifworker_do_common_call(fsm, w, action);

	if (!ni_tristate_is_set(w->control.link_required) && w->device)
		w->control.link_required = ni_netdev_guess_link_required(w->device);

	if (ret >= 0 && w->fsm.wait_for) {
		if (w->control.link_timeout != NI_IFWORKER_INFINITE_TIMEOUT) {
			ni_ifworker_set_secondary_timeout(fsm, w, w->control.link_timeout,
					ni_ifworker_link_detection_timeout);
		} else if (ni_tristate_is_disabled(w->control.link_required)) {
			ni_debug_application("%s: link-up state is not required, proceeding", w->name);
			ni_ifworker_cancel_callbacks(w, &action->callbacks);
			ni_ifworker_set_state(w, action->next_state);
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
			ni_ifworker_fail(w, "failed to create new device");
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
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_DEVICE_READY, "waitDeviceReady", .call_overloading = TRUE),

	/* This sets any device attributes, such as a MAC address */
	COMMON_TRANSITION_UP_TO(NI_FSM_STATE_DEVICE_SETUP, "changeDevice", .call_overloading = TRUE),

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

	/* -------------------------------------- *
	 * Transitions for bringing down a device
	 * -------------------------------------- */
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
	COMMON_TRANSITION_DOWN_FROM(NI_FSM_STATE_DEVICE_EXISTS, "deleteDevice", .call_overloading = TRUE),

	{ .from_state = NI_FSM_STATE_NONE, .next_state = NI_FSM_STATE_NONE, .call_func = NULL }
};

static int
ni_fsm_schedule_init(ni_fsm_t *fsm, ni_ifworker_t *w, unsigned int from_state, unsigned int target_state)
{
	unsigned int index, num_actions;
	unsigned int cur_state;
	int increment;
	int rv;

	if (ni_ifworker_active(w))
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
			rv = action->call_func(fsm, w, action);
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

release:
			ni_ifworker_release(w);
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

/* Workaround implementing temporarly missing auto6 wait */
static ni_bool_t
__ni_fsm_device_with_tentative_addrs(ni_netdev_t *dev)
{
	ni_address_t *ap;

	for (ap = dev->addrs; ap; ap = ap->next) {
		if (ap->family != AF_INET6)
			continue;

		if (ni_address_is_tentative(ap)) {
			ni_debug_application("-- the address %s is tentative",
				ni_sockaddr_print(&ap->local_addr));
			return TRUE;
		}
	}
	return FALSE;
}

void
ni_fsm_wait_tentative_addrs(ni_fsm_t *fsm)
{
	unsigned int i, count = 40; /* 10sec timeout */

	if (!fsm)
		return;

	if (!ni_fsm_refresh_state(fsm))
		return;

	for (i = 0; count && i < fsm->workers.count; i++) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (!w->done || !w->device)
			continue;

		if (!ni_netdev_link_is_up(w->device))
			continue;

		ni_debug_application("%s: tentative addresses check", w->name);

		if (__ni_fsm_device_with_tentative_addrs(w->device)) {
			usleep(250000);
			count--;
			if (!ni_fsm_refresh_state(fsm))
				return;
			i--; /* recheck this worker */
		}
	}
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

static ni_bool_t
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
		return FALSE;	/* ignore?? */
	}
	if (!(lease = ni_netdev_get_lease_by_uuid(dev, &cb->uuid))) {
		ni_error("%s: received %s event with uuid %s, but can't find a lease for",
				w->name, ni_objectmodel_event_to_signal(event),
				ni_uuid_print(&cb->uuid));
		return FALSE;	/* ignore?? */
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
		return TRUE;
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
		return TRUE;

	/* this is the last lease we were waiting for -- report	*/
	for (lease = dev->leases; lease; lease = lease->next) {
		if (lease->state == NI_ADDRCONF_STATE_NONE ||
		    lease->state == NI_ADDRCONF_STATE_GRANTED)
			continue;

		/* a not ready, released or failed non-optional lease -> fail */
		if (!ni_addrconf_flag_bit_is_set(lease->flags, NI_ADDRCONF_FLAGS_GROUP))
			return TRUE; /* not an error -> ifup shows status */

		/* optional type-goup peer lease -> check peer lease */
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

			if (other->state != NI_ADDRCONF_STATE_GRANTED)
				return TRUE; /* not an error -> ifup shows status */
		}
	}
	return TRUE;
}

static void
interface_state_change_signal(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_fsm_t *fsm = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_uuid_t event_uuid = NI_UUID_INIT;
	ni_event_t event_type = __NI_EVENT_MAX;
	const char *event_name = signal_name;
	ni_ifworker_t *w;

	/* See if this event is a known one and comes with a uuid */
	{
		ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
		int argc;

		argc = ni_dbus_message_get_args_variants(msg, &result, 1);
		if (argc < 0) {
			ni_error("%s: cannot extract parameters of signal %s",
					__func__, signal_name);
			return;
		}
		if (ni_objectmodel_signal_to_event(signal_name, &event_type) < 0) {
			ni_warn("%s: unknown event signal %s from %s",
				__func__, signal_name, object_path);
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
	if (event_type == NI_EVENT_ADDRESS_ACQUIRED)
		fsm->last_event_seq[NI_EVENT_ADDRESS_ACQUIRED] = fsm->event_seq;

	if (event_type == NI_EVENT_DEVICE_READY || event_type == NI_EVENT_DEVICE_UP) {
		/* Refresh device on ready & device-up */
		if (!(w = ni_fsm_recv_new_netif_path(fsm, object_path))) {
			ni_error("%s: Cannot find corresponding worker for %s",
				__func__, object_path);
			return;
		}

		/* Rebuild hierarchy */
		ni_fsm_refresh_master_dev(fsm, w);
		ni_fsm_refresh_lower_dev(fsm, w);

		/* Rebuild hierarchy in case of new device shows up */
		ni_fsm_build_hierarchy(fsm, FALSE);

		/* Handle devices which were not present on ifup */
		if(w->pending) {
			w->pending = FALSE;
			ni_ifworker_start(fsm, w, fsm->worker_timeout);
			goto done;
		}
	}

	if ((w = ni_fsm_ifworker_by_object_path(fsm, object_path)) != NULL) {
		ni_objectmodel_callback_info_t *cb = NULL;

		if (!ni_uuid_is_null(&event_uuid)) {
			cb = ni_ifworker_get_callback(w, &event_uuid, TRUE);
			if (cb) {
				ni_event_t cb_event_type;
				ni_bool_t success;

				if (ni_objectmodel_signal_to_event(cb->event, &cb_event_type) < 0)
					cb_event_type = __NI_EVENT_MAX;

				if ((success = (cb_event_type == event_type))) {
					ni_debug_events("... great, we were expecting this event");
				} else {
					ni_debug_events("%s: was waiting for %s event, but got %s",
							w->name, cb->event, signal_name);
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

					success = address_acquired_callback_handler(w, cb, event_type);

					/* Set event_name and type to the event we wait for */
					event_name = ni_objectmodel_event_to_signal(cb_event_type);
					event_type = cb_event_type; /* don't revert state on failure */
					break;
				default:
					break;
				}

				if (!success)
					ni_ifworker_fail(w, "got signal %s", signal_name);
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

		if (event_type == NI_EVENT_DEVICE_DELETE)
			ni_fsm_destroy_worker(fsm, w);
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
		pending_workers = !!ni_fsm_schedule(fsm);

		fsm->timeout_count = 0;
		*timeout_p = ni_timer_next_timeout();
	} while (fsm->timeout_count);

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

unsigned int
ni_fsm_find_max_timeout(ni_fsm_t *fsm, unsigned int timeout)
{
	unsigned int i, max;

	if (!fsm)
		return NI_IFWORKER_INFINITE_TIMEOUT;

	max = timeout;
	for (i = 0; i < fsm->workers.count; i++) {
		ni_ifworker_t *w = fsm->workers.data[i];

		max = max_t(unsigned int, max,
			fsm->worker_timeout + w->extra_waittime);
	}

	return max;
}

void
ni_fsm_set_user_prompt_fn(ni_fsm_t *fsm, ni_fsm_user_prompt_fn_t *fn, void *user_data)
{
	ni_fsm_user_prompt_fn = fn;
	ni_fsm_user_prompt_data = user_data;
}
