/*
 * Finite state machine and associated functionality for interface
 * bring-up and take-down.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __CLIENT_FSM_H__
#define __CLIENT_FSM_H__

#include <wicked/socket.h>	/* needed for ni_timer_t */
#include <wicked/secret.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus.h>
#include <wicked/xml.h>

#include "client/client_state.h"

/*
 * Interface state information
 */
typedef enum ni_fsm_state {
	NI_FSM_STATE_NONE = 0,
	NI_FSM_STATE_DEVICE_DOWN,
	NI_FSM_STATE_DEVICE_EXISTS,
	NI_FSM_STATE_DEVICE_READY,
	NI_FSM_STATE_DEVICE_SETUP,
	NI_FSM_STATE_PROTOCOLS_UP,
	NI_FSM_STATE_FIREWALL_UP,
	NI_FSM_STATE_DEVICE_UP,
	NI_FSM_STATE_LINK_UP,
	NI_FSM_STATE_LINK_AUTHENTICATED,
	NI_FSM_STATE_LLDP_UP,
	NI_FSM_STATE_ADDRCONF_UP,
	NI_FSM_STATE_NETWORK_UP,

	__NI_FSM_STATE_MAX
} ni_fsm_state_t;

typedef enum ni_config_origin_prio {
	NI_CONFIG_ORIGIN_PRIO_FIRMWARE,
	NI_CONFIG_ORIGIN_PRIO_COMPAT,
	NI_CONFIG_ORIGIN_PRIO_WICKED = 10,
	NI_CONFIG_ORIGIN_PRIO_UNKNOWN = 100,
} ni_config_origin_prio_t;

#define NI_IFWORKER_DEFAULT_TIMEOUT	30000
#define NI_IFWORKER_INFINITE_TIMEOUT	((unsigned int) -1)

typedef struct ni_fsm		ni_fsm_t;
typedef struct ni_ifworker	ni_ifworker_t;
typedef struct ni_fsm_require	ni_fsm_require_t;
typedef struct ni_fsm_policy	ni_fsm_policy_t;
typedef struct ni_fsm_event	ni_fsm_event_t;

typedef struct ni_ifworker_array {
	unsigned int		count;
	ni_ifworker_t **	data;
} ni_ifworker_array_t;
#define NI_IFWORKER_ARRAY_INIT { .count = 0, .data = NULL }

typedef struct ni_fsm_timer_ctx	ni_fsm_timer_ctx_t;
typedef void			ni_fsm_timer_fn_t(const ni_timer_t *, ni_fsm_timer_ctx_t *);

typedef struct ni_fsm_transition ni_fsm_transition_t;
typedef struct ni_fsm_transition_binding {
		const ni_dbus_service_t *service;
		const ni_dbus_method_t *method;
		xml_node_t *		config;
		ni_bool_t		skip_call;
} ni_fsm_transition_bind_t;

typedef int			ni_fsm_transition_fn_t(ni_fsm_t *, ni_ifworker_t *, ni_fsm_transition_t *);
struct ni_fsm_transition {
	ni_fsm_state_t		from_state;
	ni_fsm_state_t		next_state;
	ni_fsm_transition_fn_t *bind_func;
	ni_fsm_transition_fn_t *call_func;
	ni_fsm_timer_fn_t *	timeout_fn;

	struct {
		const char *		service_name;
		const ni_dbus_service_t *service;

		const char *		method_name;
		const ni_dbus_method_t *method;

		ni_bool_t		call_overloading;
		ni_bool_t		may_fail;
	} common;

#define NI_IFTRANSITION_BINDINGS_MAX	32
	ni_bool_t			bound;
	unsigned int			num_bindings;
	ni_fsm_transition_bind_t binding[NI_IFTRANSITION_BINDINGS_MAX];

	ni_objectmodel_callback_info_t *callbacks;

	struct {
		ni_bool_t		parsed;
		ni_fsm_require_t *	list;
	} require;
};

typedef enum {
	NI_IFWORKER_TYPE_NONE,
	NI_IFWORKER_TYPE_NETDEV,
	NI_IFWORKER_TYPE_MODEM,
} ni_ifworker_type_t;

typedef struct ni_ifworker_control {
	char *			mode;
	char *			boot_stage;
	ni_bool_t		persistent;
	ni_bool_t		usercontrol;
	ni_tristate_t		link_required;
	unsigned int		link_priority;
	unsigned int		link_timeout;
} ni_ifworker_control_t;

struct ni_ifworker {
	unsigned int		refcount;

	char *			name;
	char *			old_name;
	ni_ifworker_type_t	type;
	ni_iftype_t		iftype;

	ni_dbus_object_t *	object;
	char *			object_path;

	unsigned int		ifindex;

	ni_uint_range_t		target_range;
	unsigned int		target_state;

	unsigned int		dead		: 1,
				failed		: 1,
				done		: 1,
				kickstarted	: 1,
				pending		: 1,
				readonly	: 1;

	ni_ifworker_control_t	control;

	struct {
		xml_node_t *			node;
	} state;

	struct {
		ni_client_state_config_t	meta;
		xml_node_t *			node;
	} config;

	/* The security ID can be used as a set of identifiers
	 * to look up user name/password/pin type info in a
	 * database.
	 *
	 * It is usually set when binding the device (eg from
	 * the GSM Modem's IMEI), but can also be overwritten
	 * from the policy.
	 *
	 * It must contain at least one attribute named "class",
	 * and one or more class-specific attributes.
	 */
	ni_security_id_t	security_id;

	/* An ifworker can represent either a network device or a modem */
	ni_netdev_t *		device;
	ni_modem_t *		modem;

	struct {
		const ni_dbus_service_t *service;
		const ni_dbus_method_t *method;
		const ni_dbus_service_t *factory_service;
		const ni_dbus_method_t *factory_method;
		xml_node_t *	config;
	} device_api;

	struct {
		ni_fsm_state_t state;
		ni_fsm_transition_t *wait_for;
		ni_fsm_transition_t *next_action;
		ni_fsm_transition_t *action_table;
		const ni_timer_t *timer;
		const ni_timer_t *secondary_timer;

		ni_fsm_require_t *check_state_req_list;

	} fsm;
	unsigned int		extra_waittime;

	struct {
		void            (*callback)(ni_ifworker_t *, ni_fsm_state_t);
		void *          user_data;
	} progress;

	struct {
		void		(*callback)(ni_ifworker_t *);
		void *		user_data;
	} completion;

	ni_ifworker_t *		masterdev;
	ni_ifworker_t * 	lowerdev;

	ni_ifworker_array_t	children;
	ni_ifworker_array_t	lowerdev_for;
};

/*
 * Express requirements.
 * This is essentially a test function that is invoked "when adequate"
 */
typedef ni_fsm_require_t *	ni_fsm_require_ctor_t(xml_node_t *);
typedef ni_bool_t		ni_fsm_require_fn_t(ni_fsm_t *, ni_ifworker_t *, ni_fsm_require_t *);
typedef void			ni_fsm_require_dtor_t(ni_fsm_require_t *);

struct ni_fsm_require {
	ni_fsm_require_t *	next;

	unsigned int		event_seq;
	ni_fsm_require_fn_t *	test_fn;
	ni_fsm_require_dtor_t *	destroy_fn;

	void *			user_data;
};

struct ni_fsm_event {
	ni_fsm_event_t *	next;

	char *			object_path;
	char *			signal_name;

	ni_event_t		event_type;
	ni_uuid_t		event_uuid;

	ni_ifworker_type_t	worker_type;
	unsigned int		ifindex;
};

struct ni_fsm {
	ni_ifworker_array_t	pending;
	ni_ifworker_array_t	workers;
	unsigned int		worker_timeout;
	ni_bool_t		readonly;

	unsigned int		timeout_count;
	unsigned int		event_seq;
	unsigned int		last_event_seq[__NI_EVENT_MAX];
	unsigned int		block_events;
	ni_fsm_event_t *	events;
	struct {
		void            (*callback)(ni_fsm_t *, ni_ifworker_t *, ni_fsm_event_t *);
		void *          user_data;
	} process_event;

	ni_fsm_policy_t *	policies;

	ni_dbus_object_t *	client_root_object;
};

typedef struct ni_ifmatcher {
	const char *		name;
	const char *		mode;
	const char *		boot_stage;
	const char *		skip_origin;
	unsigned int		require_config     : 1,
				require_configured : 1,
				allow_persistent   : 1,
				ignore_startmode   : 1,
				skip_active        : 1,
				ifdown             : 1;
} ni_ifmatcher_t;

typedef struct ni_ifmarker {
	ni_uint_range_t	target_range;
	unsigned int	persistent	: 1;
} ni_ifmarker_t;

extern ni_fsm_t *		ni_fsm_new(void);
extern void			ni_fsm_free(ni_fsm_t *);

extern ni_fsm_policy_t *	ni_fsm_policy_new(ni_fsm_t *, const char *, xml_node_t *);
extern ni_fsm_policy_t *	ni_fsm_policy_ref(ni_fsm_policy_t *);
extern void			ni_fsm_policy_free(ni_fsm_policy_t *);
extern ni_bool_t		ni_fsm_policy_update(ni_fsm_policy_t *, xml_node_t *);
extern ni_bool_t		ni_fsm_policy_remove(ni_fsm_t *, ni_fsm_policy_t *);
extern ni_fsm_policy_t *	ni_fsm_policy_by_name(const ni_fsm_t *, const char *);
extern unsigned int		ni_fsm_policy_get_applicable_policies(const ni_fsm_t *, ni_ifworker_t *,
						const ni_fsm_policy_t **, unsigned int);
extern ni_bool_t		ni_fsm_exists_applicable_policy(const ni_fsm_t *, ni_fsm_policy_t *, ni_ifworker_t *);
extern xml_node_t *		ni_fsm_policy_transform_document(xml_node_t *, ni_fsm_policy_t * const *, unsigned int);
extern const char *		ni_fsm_policy_name(const ni_fsm_policy_t *);
extern const xml_node_t *	ni_fsm_policy_node(const ni_fsm_policy_t *);
extern const xml_location_t *	ni_fsm_policy_location(const ni_fsm_policy_t *);
extern const char *		ni_fsm_policy_get_origin(const ni_fsm_policy_t *);
extern ni_bool_t		ni_fsm_policies_changed_since(const ni_fsm_t *, unsigned int *tstamp);

extern ni_dbus_client_t *	ni_fsm_create_client(ni_fsm_t *);
extern ni_bool_t		ni_fsm_refresh_state(ni_fsm_t *);
extern unsigned int		ni_fsm_schedule(ni_fsm_t *);
extern ni_bool_t		ni_fsm_do(ni_fsm_t *fsm, long *timeout_p);
extern void			ni_fsm_mainloop(ni_fsm_t *);
extern void			ni_fsm_set_process_event_callback(ni_fsm_t *, void (*)(ni_fsm_t *, ni_ifworker_t *, ni_fsm_event_t *), void *);
extern unsigned int		ni_fsm_get_matching_workers(ni_fsm_t *, ni_ifmatcher_t *, ni_ifworker_array_t *);
extern unsigned int		ni_fsm_mark_matching_workers(ni_fsm_t *, ni_ifworker_array_t *, const ni_ifmarker_t *);
extern unsigned int		ni_fsm_start_matching_workers(ni_fsm_t *, ni_ifworker_array_t *);
extern void			ni_fsm_reset_matching_workers(ni_fsm_t *, ni_ifworker_array_t *, const ni_uint_range_t *, ni_bool_t);
extern void			ni_fsm_print_hierarchy(ni_fsm_t *);
extern int			ni_fsm_build_hierarchy(ni_fsm_t *, ni_bool_t);
extern ni_bool_t		ni_fsm_workers_from_xml(ni_fsm_t *, xml_node_t *, const char *);
extern unsigned int		ni_fsm_fail_count(ni_fsm_t *);
extern ni_ifworker_t *		ni_fsm_ifworker_by_object_path(ni_fsm_t *, const char *);
extern ni_ifworker_t *		ni_fsm_ifworker_by_ifindex(ni_fsm_t *, unsigned int);
extern ni_ifworker_t *		ni_fsm_ifworker_by_netdev(ni_fsm_t *, const ni_netdev_t *);
extern ni_ifworker_t *		ni_fsm_ifworker_by_name(const ni_fsm_t *, ni_ifworker_type_t, const char *);
extern ni_ifworker_t *		ni_fsm_ifworker_by_policy_name(ni_fsm_t *, ni_ifworker_type_t, const char *);
extern ni_ifworker_t *		ni_fsm_recv_new_netif(ni_fsm_t *fsm, ni_dbus_object_t *object, ni_bool_t refresh);
extern ni_ifworker_t *		ni_fsm_recv_new_netif_path(ni_fsm_t *fsm, const char *path);
extern ni_ifworker_t *		ni_fsm_recv_new_modem(ni_fsm_t *fsm, ni_dbus_object_t *object, ni_bool_t refresh);
extern ni_ifworker_t *		ni_fsm_recv_new_modem_path(ni_fsm_t *fsm, const char *path);
extern void			ni_fsm_destroy_worker(ni_fsm_t *fsm, ni_ifworker_t *w);
extern void			ni_fsm_pull_in_children(ni_ifworker_array_t *, ni_fsm_t *);
extern void			ni_fsm_wait_tentative_addrs(ni_fsm_t *);

extern ni_ifworker_type_t	ni_ifworker_type_from_string(const char *);
extern const char *		ni_ifworker_type_to_string(ni_ifworker_type_t);
extern ni_ifworker_type_t	ni_ifworker_type_from_object_path(const char *, const char **);
extern inline ni_bool_t	ni_ifworker_state_in_range(const ni_uint_range_t *, const unsigned int);
extern const char *		ni_ifworker_state_name(ni_fsm_state_t state);
extern ni_bool_t		ni_ifworker_state_from_name(const char *, unsigned int *);
extern ni_fsm_require_t *	ni_ifworker_reachability_check_new(xml_node_t *);
extern ni_bool_t		ni_ifworker_match_netdev_name(const ni_ifworker_t *, const char *);
extern ni_bool_t		ni_ifworker_match_netdev_alias(const ni_ifworker_t *, const char *);
extern ni_bool_t		ni_ifworker_match_netdev_ifindex(const ni_ifworker_t *, unsigned int);
extern ni_bool_t		ni_ifworker_match_alias(const ni_ifworker_t *, const char *);
extern ni_iftype_t		ni_ifworker_iftype_from_xml(xml_node_t *);
extern void			ni_ifworker_set_config(ni_ifworker_t *, xml_node_t *, const char *);
extern ni_bool_t		ni_ifworker_control_set_usercontrol(ni_ifworker_t *, ni_bool_t);
extern ni_bool_t		ni_ifworker_control_set_persistent(ni_ifworker_t *, ni_bool_t);
extern  void			ni_ifworker_rearm(ni_ifworker_t *);
extern void			ni_ifworker_reset(ni_ifworker_t *);
extern int			ni_ifworker_bind_early(ni_ifworker_t *, ni_fsm_t *, ni_bool_t);
extern int			ni_ifworker_start(ni_fsm_t *, ni_ifworker_t *, unsigned long);
extern void			ni_ifworker_fail(ni_ifworker_t *, const char *, ...);
extern void			ni_ifworker_success(ni_ifworker_t *);
extern void			ni_ifworker_set_progress_callback(ni_ifworker_t *, void (*)(ni_ifworker_t *, ni_fsm_state_t), void *);
extern void			ni_ifworker_set_completion_callback(ni_ifworker_t *, void (*)(ni_ifworker_t *), void *);
extern ni_rfkill_type_t		ni_ifworker_get_rfkill_type(const ni_ifworker_t *);
extern ni_ifworker_t *		ni_ifworker_set_ref(ni_ifworker_t **, ni_ifworker_t *);
extern void			ni_ifworker_free(ni_ifworker_t *);

extern ni_ifworker_control_t *	ni_ifworker_control_new(void);
extern ni_ifworker_control_t *	ni_ifworker_control_clone(const ni_ifworker_control_t *);
extern void			ni_ifworker_control_free(ni_ifworker_control_t *);

extern ni_ifworker_array_t *	ni_ifworker_array_new(void);
extern void			ni_ifworker_array_free(ni_ifworker_array_t *);
extern ni_ifworker_array_t *	ni_ifworker_array_clone(ni_ifworker_array_t *);
extern void			ni_ifworker_array_append(ni_ifworker_array_t *, ni_ifworker_t *);
extern ni_bool_t		ni_ifworker_array_remove_index(ni_ifworker_array_t *, unsigned int);
extern ni_bool_t		ni_ifworker_array_remove(ni_ifworker_array_t *, ni_ifworker_t *);
extern void			ni_ifworker_array_remove_with_children(ni_ifworker_array_t *, ni_ifworker_t *);
extern int			ni_ifworker_array_index(const ni_ifworker_array_t *, const ni_ifworker_t *);
extern void			ni_ifworker_array_destroy(ni_ifworker_array_t *);

extern unsigned int		ni_fsm_find_max_timeout(ni_fsm_t *, unsigned int);
extern void			ni_fsm_require_register_type(const char *, ni_fsm_require_ctor_t *);
extern ni_fsm_require_t *	ni_fsm_require_new(ni_fsm_require_fn_t *, ni_fsm_require_dtor_t *);

/*
 * This callback is invoked when the FSM engine needs user input
 */
enum {
	NI_FSM_PROMPT_USERNAME,
	NI_FSM_PROMPT_PASSWORD,
	NI_FSM_PROMPT_OTHER
};
typedef struct ni_fsm_prompt {
	unsigned int		type;
	const char *		string;
	const char *		id;
} ni_fsm_prompt_t;

typedef int			ni_fsm_user_prompt_fn_t(const ni_fsm_prompt_t *, xml_node_t *, void *);

extern void			ni_fsm_set_user_prompt_fn(ni_fsm_t *, ni_fsm_user_prompt_fn_t *, void *);

/*
 * Various simple inline helpers
 */
static inline ni_ifworker_t *
ni_ifworker_get(ni_ifworker_t *w)
{
	if (w) {
		ni_assert(w->refcount);
		w->refcount++;
	}
	return w;
}

static inline unsigned int
ni_ifworker_release(ni_ifworker_t *w)
{
	if (w) {
		ni_assert(w->refcount);
		w->refcount--;

		if (w->refcount == 0) {
			ni_ifworker_free(w);
		} else {
			return w->refcount;
		}
	}
	return 0;
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

static inline ni_netdev_t *
ni_ifworker_get_netdev(const ni_ifworker_t *w)
{
	if (w->type != NI_IFWORKER_TYPE_NETDEV)
		return NULL;
	return w->device;
}

static inline ni_modem_t *
ni_ifworker_get_modem(const ni_ifworker_t *w)
{
	if (w->type != NI_IFWORKER_TYPE_MODEM)
		return NULL;
	return w->modem;
}

/*
 * Returns true if the device was configured correctly
 */
static inline ni_bool_t
ni_ifworker_has_succeeded(const ni_ifworker_t *w)
{
	return w->done && !w->failed;
}

/*
 * Returns true if the worker is currently executing
 */
static inline ni_bool_t
ni_ifworker_active(const ni_ifworker_t *w)
{
	return w->fsm.action_table != NULL;
}

/*
 * Returns true if a state is one of the FSM defined states
 */
static inline ni_bool_t
ni_ifworker_is_valid_state(ni_fsm_state_t state)
{
	return  state > NI_FSM_STATE_NONE &&
		state < __NI_FSM_STATE_MAX;
}

static inline ni_bool_t
ni_ifworker_complete(const ni_ifworker_t *w)
{
	return 	w->failed || w->done || w->target_state == NI_FSM_STATE_NONE ||
		(w->target_state == w->fsm.state && ni_ifworker_is_valid_state(w->target_state));
}

static inline ni_bool_t
ni_ifworker_is_device_created(const ni_ifworker_t *w)
{
	return ni_ifworker_device_bound(w) && w->object && w->ifindex != 0 &&
		!ni_string_empty(w->object_path);
}

static inline ni_bool_t
ni_ifworker_is_running(const ni_ifworker_t *w)
{
	return w->kickstarted && !w->dead && !ni_ifworker_complete(w);
}

static inline ni_bool_t
ni_ifworker_is_factory_device(const ni_ifworker_t *w)
{
	return  w->device_api.factory_service && w->device_api.factory_method;
}

/*
 * Return true if the worker has been created from config file and has no real device
 */
static inline ni_bool_t
ni_ifworker_is_config_worker(const ni_ifworker_t *w)
{
	return !ni_ifworker_is_device_created(w) && !xml_node_is_empty(w->config.node) &&
		!ni_ifworker_is_factory_device(w);
}

static inline ni_bool_t
ni_ifworker_can_delete(const ni_ifworker_t *w)
{
	return !!ni_dbus_object_get_service_for_method(w->object, "deleteDevice");
}

#endif /* __CLIENT_FSM_H__ */
