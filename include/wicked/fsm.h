/*
 * Finite state machine and associated functionality for interface
 * bring-up and take-down.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __CLIENT_FSM_H__
#define __CLIENT_FSM_H__

#include <wicked/socket.h>	/* needed for ni_timer_t */
#include <wicked/objectmodel.h>
#include <wicked/dbus.h>
#include <wicked/xml.h>

/*
 * Interface state information
 */
enum {
	NI_FSM_STATE_NONE = 0,
	NI_FSM_STATE_DEVICE_DOWN,
	NI_FSM_STATE_DEVICE_EXISTS,
	NI_FSM_STATE_DEVICE_UP,
	NI_FSM_STATE_PROTOCOLS_UP,
	NI_FSM_STATE_FIREWALL_UP,
	NI_FSM_STATE_LINK_UP,
	NI_FSM_STATE_LINK_AUTHENTICATED,
	NI_FSM_STATE_ADDRCONF_UP,

	__NI_FSM_STATE_MAX
};

#define NI_IFWORKER_DEFAULT_TIMEOUT	20000
#define NI_IFWORKER_INFINITE_TIMEOUT	((unsigned int) -1)

typedef struct ni_fsm		ni_fsm_t;
typedef struct ni_ifworker	ni_ifworker_t;
typedef struct ni_fsm_require	ni_fsm_require_t;
typedef struct ni_fsm_policy	ni_fsm_policy_t;

typedef struct ni_ifworker_array {
	unsigned int		count;
	ni_ifworker_t **	data;
} ni_ifworker_array_t;

typedef struct ni_fsm_transition ni_fsm_transition_t;

typedef int			ni_fsm_transition_fn_t(ni_fsm_t *, ni_ifworker_t *, ni_fsm_transition_t *);
struct ni_fsm_transition {
	int			from_state;
	int			next_state;
	ni_fsm_transition_fn_t *bind_func;
	ni_fsm_transition_fn_t *func;

	struct {
		const char *		service_name;
		const ni_dbus_service_t *service;

		const char *		method_name;
		const ni_dbus_method_t *method;

		xml_node_t *		config;

		ni_bool_t		call_overloading;
	} common;

#define NI_IFTRANSITION_BINDINGS_MAX	32
	ni_bool_t			bound;
	unsigned int			num_bindings;
	struct ni_fsm_transition_binding {
		const ni_dbus_service_t *service;
		const ni_dbus_method_t *method;
		xml_node_t *		config;
		ni_bool_t		skip_call;
	} binding[NI_IFTRANSITION_BINDINGS_MAX];

	ni_objectmodel_callback_info_t *callbacks;

	struct {
		ni_bool_t		parsed;
		ni_fsm_require_t *	list;
	} require;
};

typedef enum {
	NI_IFWORKER_TYPE_NETDEV,
	NI_IFWORKER_TYPE_MODEM,
} ni_ifworker_type_t;

struct ni_ifworker {
	unsigned int		refcount;

	char *			name;
	ni_ifworker_type_t	type;

	ni_dbus_object_t *	object;
	char *			object_path;

	unsigned int		ifindex;

	ni_uint_range_t		target_range;
	int			target_state;

	unsigned int		failed		: 1,
				done		: 1;

	struct {
		char *		mode;
		char *		boot_stage;
		ni_bool_t	link_required;
		unsigned int	link_timeout;
	} control;

	struct {
		char *		origin;
		ni_uuid_t	uuid;
		xml_node_t *	node;
	}			config;
	ni_bool_t		use_default_policies;

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
		int		state;
		ni_fsm_transition_t *wait_for;
		ni_fsm_transition_t *next_action;
		ni_fsm_transition_t *action_table;
		const ni_timer_t *timer;
		const ni_timer_t *secondary_timer;

		ni_fsm_require_t *child_state_req_list;
	} fsm;

	unsigned int		shared_users;
	ni_ifworker_t *		exclusive_owner;

	ni_ifworker_t *		parent;
	unsigned int		depth;		/* depth in device graph */
	ni_ifworker_array_t	children;
};

/*
 * Express requirements.
 * This is essentially a test function that is invoked "when adequate"
 */
typedef ni_bool_t		ni_fsm_require_fn_t(ni_fsm_t *, ni_ifworker_t *, ni_fsm_require_t *);
typedef void			ni_fsm_require_dtor_t(ni_fsm_require_t *);

struct ni_fsm_require {
	ni_fsm_require_t *	next;

	unsigned int		event_seq;
	ni_fsm_require_fn_t *	test_fn;
	ni_fsm_require_dtor_t *	destroy_fn;

	void *			user_data;
};

struct ni_fsm {
	ni_ifworker_array_t	workers;
	unsigned int		worker_timeout;

	unsigned int		event_seq;
	unsigned int		last_event_seq[__NI_EVENT_MAX];

	ni_fsm_policy_t *	policies;

	ni_dbus_object_t *	client_root_object;
};


extern ni_fsm_t *		ni_fsm_new(void);
extern void			ni_fsm_free(ni_fsm_t *);

extern ni_fsm_policy_t *	ni_fsm_policy_new(ni_fsm_t *, const char *, xml_node_t *);
extern ni_fsm_policy_t *	ni_fsm_policy_by_name(ni_fsm_t *, const char *);
extern unsigned int		ni_fsm_policy_get_applicable_policies(ni_fsm_t *, ni_ifworker_t *,
						const ni_fsm_policy_t **, unsigned int);
extern xml_node_t *		ni_fsm_policy_transform_document(xml_node_t *, const ni_fsm_policy_t * const *, unsigned int);


extern ni_bool_t		ni_ifworkers_create_client(ni_fsm_t *);
extern void			ni_ifworkers_refresh_state(ni_fsm_t *);
extern int			ni_ifworkers_kickstart(ni_fsm_t *);
extern unsigned int		ni_ifworker_fsm(ni_fsm_t *);
extern void			ni_ifworker_mainloop(ni_fsm_t *);
extern unsigned int		ni_ifworkers_from_xml(ni_fsm_t *, xml_document_t *, const char *);

extern int			ni_ifworker_type_from_string(const char *);
extern ni_fsm_require_t *	ni_ifworker_reachability_check_new(xml_node_t *);
extern ni_bool_t		ni_ifworker_match_alias(const ni_ifworker_t *w, const char *alias);

extern ni_fsm_require_t *	ni_fsm_require_new(ni_fsm_require_fn_t *, ni_fsm_require_dtor_t *);

#endif /* __CLIENT_FSM_H__ */
