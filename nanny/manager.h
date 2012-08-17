/*
 * Declarations to the manager service. This service is supposed
 * to bring up interfaces in response to events, such as link detection
 * or presence of wireless networks.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_MANAGER_H__
#define __WICKED_MANAGER_H__

#include <wicked/fsm.h>
#include <wicked/secret.h>

typedef struct ni_manager	ni_manager_t;
typedef struct ni_managed_device ni_managed_device_t;
typedef struct ni_managed_policy ni_managed_policy_t;

typedef enum ni_managed_state {
	NI_MANAGED_STATE_STOPPED,
	NI_MANAGED_STATE_STARTING,
	NI_MANAGED_STATE_RUNNING,
	NI_MANAGED_STATE_STOPPING,
	NI_MANAGED_STATE_LIMBO,
	NI_MANAGED_STATE_FAILED,
} ni_managed_state_t;

struct ni_managed_device {
	ni_managed_device_t **	prev;
	ni_managed_device_t *	next;

	ni_manager_t *		manager;	// back pointer at mgr
	ni_dbus_object_t *	object;		// server object
	ni_ifworker_t *		worker;
	ni_bool_t		user_controlled;
	ni_bool_t		rfkill_blocked;

	ni_managed_state_t	state;

	unsigned int		fail_count;
	unsigned int		max_fail_count;

	ni_managed_policy_t *	selected_policy;
	unsigned int		selected_policy_seq;
	xml_node_t *		selected_config;
};

struct ni_managed_policy {
	ni_managed_policy_t *	next;

	unsigned int		seqno;
	ni_fsm_policy_t *	fsm_policy;
	xml_document_t *	doc;
};

struct ni_manager {
	ni_dbus_server_t *	server;
	ni_fsm_t *		fsm;

	ni_managed_device_t *	device_list;
	ni_managed_policy_t *	policy_list;

	unsigned int		last_policy_seq;
	ni_ifworker_array_t	recheck;
	ni_ifworker_array_t	down;

	ni_secret_db_t *	secret_db;
};

extern ni_dbus_class_t		ni_objectmodel_managed_netdev_class;
extern ni_dbus_class_t		ni_objectmodel_managed_modem_class;
extern ni_dbus_class_t		ni_objectmodel_managed_policy_class;
extern ni_dbus_class_t		ni_objectmodel_manager_class;
extern ni_dbus_service_t	ni_objectmodel_managed_netdev_service;
extern ni_dbus_service_t	ni_objectmodel_managed_modem_service;
extern ni_dbus_service_t	ni_objectmodel_managed_policy_service;
extern ni_dbus_service_t	ni_objectmodel_manager_service;

extern ni_manager_t *		ni_manager_new(void);
extern void			ni_manager_free(ni_manager_t *);
extern void			ni_manager_schedule_recheck(ni_manager_t *, ni_ifworker_t *);
extern void			ni_manager_recheck_do(ni_manager_t *mgr);
extern void			ni_manager_schedule_down(ni_manager_t *, ni_ifworker_t *);
extern void			ni_manager_down_do(ni_manager_t *mgr);
extern void			ni_manager_recheck(ni_manager_t *, ni_ifworker_t *);
extern void			ni_manager_register_device(ni_manager_t *, ni_ifworker_t *);
extern void			ni_manager_unregister_device(ni_manager_t *, ni_ifworker_t *);
extern ni_managed_device_t *	ni_manager_get_device(ni_manager_t *, ni_ifworker_t *);
extern void			ni_manager_remove_device(ni_manager_t *, ni_managed_device_t *);
extern ni_managed_policy_t *	ni_manager_get_policy(ni_manager_t *, const ni_fsm_policy_t *);
extern void			ni_manager_clear_secrets(ni_manager_t *mgr, const char *security_id, const char *path);
extern const char *		ni_manager_get_secret(ni_manager_t *, const char *, const char *);
extern void			ni_manager_rfkill_event(ni_manager_t *mgr, ni_rfkill_type_t type, ni_bool_t blocked);

extern ni_bool_t		ni_managed_netdev_enable(ni_managed_device_t *);
extern void			ni_managed_netdev_apply_policy(ni_managed_device_t *, ni_managed_policy_t *, ni_fsm_t *);
extern void			ni_managed_netdev_up(ni_managed_device_t *, unsigned int);

extern void			ni_managed_modem_apply_policy(ni_managed_device_t *, ni_managed_policy_t *, ni_fsm_t *);
extern void			ni_managed_modem_up(ni_managed_device_t *, unsigned int);

extern ni_managed_device_t *	ni_managed_device_new(ni_manager_t *, ni_ifworker_t *, ni_managed_device_t **list);
extern void			ni_managed_device_free(ni_managed_device_t *);
extern void			ni_managed_device_apply_policy(ni_managed_device_t *mdev, ni_managed_policy_t *mpolicy);
extern void			ni_managed_device_set_policy(ni_managed_device_t *, ni_managed_policy_t *, xml_node_t *);
extern void			ni_managed_device_up(ni_managed_device_t *mdev);
extern void			ni_managed_device_down(ni_managed_device_t *mdev);

extern ni_managed_policy_t *	ni_managed_policy_new(ni_manager_t *, ni_fsm_policy_t *, xml_document_t *);
extern void			ni_managed_policy_free(ni_managed_policy_t *);

extern const char *		ni_managed_state_to_string(ni_managed_state_t);

extern ni_dbus_object_t *	ni_objectmodel_register_managed_netdev(ni_dbus_server_t *, ni_managed_device_t *);
extern ni_dbus_object_t *	ni_objectmodel_register_managed_modem(ni_dbus_server_t *, ni_managed_device_t *);
extern ni_dbus_object_t *	ni_objectmodel_register_managed_policy(ni_dbus_server_t *, ni_managed_policy_t *);
extern void			ni_objectmodel_unregister_managed_device(ni_managed_device_t *);

extern void			interface_manager_register_all(ni_dbus_server_t *);
extern void			ni_objectmodel_manager_init(ni_manager_t *mgr);
extern void			ni_objectmodel_managed_netif_init(ni_dbus_server_t *);
extern void			ni_objectmodel_managed_modem_init(ni_dbus_server_t *);
extern void			ni_objectmodel_managed_policy_init(ni_dbus_server_t *);

#endif /* __WICKED_MANAGER_H__ */
