/*
 * Declarations to the nanny service. This service is supposed
 * to bring up interfaces in response to events, such as link detection
 * or presence of wireless networks.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_MANAGER_H__
#define __WICKED_MANAGER_H__

#include <wicked/fsm.h>
#include <wicked/types.h>
#include <wicked/secret.h>
#include "appconfig.h"

#ifndef NI_NANNY_POLICY_XML
#define NI_NANNY_POLICY_XML	".xml"
#endif
#ifndef NI_NANNY_POLICY_BAK
#define NI_NANNY_POLICY_BAK	".bak"
#endif

typedef struct ni_nanny		ni_nanny_t;
typedef struct ni_managed_device ni_managed_device_t;
typedef struct ni_managed_policy ni_managed_policy_t;

typedef enum ni_managed_state {
	NI_MANAGED_STATE_STOPPED,
	NI_MANAGED_STATE_BINDING,
	NI_MANAGED_STATE_STARTING,
	NI_MANAGED_STATE_RUNNING,
	NI_MANAGED_STATE_STOPPING,
	NI_MANAGED_STATE_LIMBO,
	NI_MANAGED_STATE_FAILED,
} ni_managed_state_t;

struct ni_managed_device {
	ni_managed_device_t **	prev;
	ni_managed_device_t *	next;

	ni_nanny_t *		nanny;		// back pointer at mgr
	ni_dbus_object_t *	object;		// server object
	unsigned int		ifindex;

	ni_bool_t		allowed;	// true iff user is allowed to enable it
	ni_bool_t		monitor;	// true iff we're monitoring it

	ni_bool_t		rfkill_blocked;
	ni_bool_t		missing_secrets;

	ni_managed_state_t	state;

	unsigned int		fail_count;
	unsigned int		max_fail_count;

	ni_managed_policy_t *	selected_policy;
	unsigned int		selected_policy_seq;
	xml_node_t *		selected_config;

	ni_secret_array_t	secrets;
};

typedef struct ni_nanny_user	ni_nanny_user_t;
struct ni_nanny_user {
	ni_nanny_user_t *	next;

	uid_t			uid;
	ni_secret_db_t *	secret_db;
};

struct ni_managed_policy {
	unsigned int		refcount;
	ni_managed_policy_t **	pprev;
	ni_managed_policy_t *	next;

	unsigned int		seqno;
	ni_fsm_policy_t *	fsm_policy;
};

typedef struct ni_nanny_devmatch ni_nanny_devmatch_t;
enum {
	NI_NANNY_DEVMATCH_CLASS,
	NI_NANNY_DEVMATCH_DEVICE,
};

struct ni_nanny_devmatch {
	 ni_nanny_devmatch_t *	next;

	 unsigned int		type;
	 char *			value;
	 ni_bool_t		auto_enable;

	 const ni_dbus_class_t *class;	/* if type is NI_NANNY_DEVMATCH_CLASS */
};

struct ni_nanny {
	ni_dbus_server_t *	server;
	ni_fsm_t *		fsm;

	ni_managed_device_t *	device_list;
	ni_managed_policy_t *	policy_list;

	unsigned int		last_policy_seq;
	ni_ifworker_array_t	recheck;
	ni_ifworker_array_t	down;

	ni_nanny_user_t *	users;

	ni_nanny_devmatch_t *	enable;
};

extern const ni_dbus_class_t	ni_objectmodel_managed_netif_class;
extern const ni_dbus_class_t	ni_objectmodel_managed_modem_class;
extern const ni_dbus_class_t	ni_objectmodel_managed_policy_class;
extern const ni_dbus_class_t	ni_objectmodel_nanny_class;
extern const ni_dbus_service_t	ni_objectmodel_managed_netif_service;
extern const ni_dbus_service_t	ni_objectmodel_managed_modem_service;
extern const ni_dbus_service_t	ni_objectmodel_managed_policy_service;
extern const ni_dbus_service_t	ni_objectmodel_nanny_service;

extern ni_nanny_t *		ni_nanny_new(void);
extern void			ni_nanny_start(ni_nanny_t *);
extern void			ni_nanny_free(ni_nanny_t *);
extern const char *		ni_nanny_statedir(void);
extern const char *		ni_nanny_policy_location(char **, const char *);
extern const char *		ni_nanny_policy_file_name(char **, const char *);
extern const char *		ni_nanny_policy_file_path(char **, const char *);
extern ni_bool_t		ni_nanny_policy_drop(const char *);
extern ni_bool_t		ni_nanny_policy_save(const xml_node_t *, const char *, const char *);
extern void			ni_nanny_recheck_policies(ni_nanny_t *, const ni_string_array_t *);
extern void			ni_nanny_schedule_recheck(ni_ifworker_array_t *, ni_ifworker_t *);
extern void			ni_nanny_unschedule(ni_ifworker_array_t *, ni_ifworker_t *);
extern unsigned int		ni_nanny_recheck_do(ni_nanny_t *mgr);
extern unsigned int		ni_nanny_down_do(ni_nanny_t *mgr);
extern void			ni_nanny_register_device(ni_nanny_t *, ni_ifworker_t *);
extern void			ni_nanny_unregister_device(ni_nanny_t *, ni_ifworker_t *);
extern ni_managed_device_t *	ni_nanny_get_device_by_ifindex(ni_nanny_t *, unsigned int);
extern void			ni_nanny_remove_device(ni_nanny_t *, ni_managed_device_t *);
extern ni_managed_policy_t *	ni_nanny_get_policy(ni_nanny_t *, const ni_fsm_policy_t *);
extern ni_nanny_user_t *	ni_nanny_get_user(ni_nanny_t *, uid_t);
extern ni_nanny_user_t *	ni_nanny_create_user(ni_nanny_t *, uid_t);
extern void			ni_nanny_clear_secrets(ni_nanny_t *mgr,
						const ni_security_id_t *security_id, const char *path);
extern ni_secret_t *		ni_nanny_get_secret(ni_nanny_t *, uid_t, const ni_security_id_t *, const char *);
extern void			ni_nanny_rfkill_event(ni_nanny_t *mgr, ni_rfkill_type_t type, ni_bool_t blocked);
extern int			ni_nanny_create_policy(ni_dbus_object_t **, ni_nanny_t *, xml_document_t *, const uid_t *, ni_bool_t);
extern ni_bool_t		ni_nanny_policy_drop(const char *);

extern ni_bool_t		ni_managed_netif_enable(ni_managed_device_t *);
extern void			ni_managed_netif_apply_policy(ni_managed_device_t *, ni_managed_policy_t *, ni_fsm_t *);
extern void			ni_managed_netif_up(ni_managed_device_t *, unsigned int);

extern void			ni_managed_modem_apply_policy(ni_managed_device_t *, ni_managed_policy_t *, ni_fsm_t *);
extern void			ni_managed_modem_up(ni_managed_device_t *, unsigned int);

extern ni_managed_device_t *	ni_managed_device_new(ni_nanny_t *, unsigned int, ni_managed_device_t **list);
extern void			ni_managed_device_free(ni_managed_device_t *);
extern ni_ifworker_t *		ni_managed_device_get_worker(const ni_managed_device_t *);
extern char *			ni_managed_device_get_name(ni_managed_device_t *);
extern int			ni_factory_device_apply_policy(ni_fsm_t *, ni_ifworker_t *, ni_managed_policy_t *);
extern int			ni_managed_device_apply_policy(ni_managed_device_t *mdev, ni_managed_policy_t *mpolicy);
extern void			ni_managed_device_set_policy(ni_managed_device_t *, ni_managed_policy_t *, xml_node_t *);
extern void			ni_managed_device_down(ni_managed_device_t *mdev);
extern ni_bool_t		ni_managed_policy_filename(const char *, char *, size_t);

extern ni_dbus_object_t *	ni_managed_policy_register(ni_nanny_t *, ni_fsm_policy_t *);
extern ni_managed_policy_t *	ni_managed_policy_new(ni_nanny_t *, ni_fsm_policy_t *);
extern ni_managed_policy_t *	ni_managed_policy_ref(ni_managed_policy_t *);
extern void			ni_managed_policy_free(ni_managed_policy_t *);
extern uid_t			ni_managed_policy_owner(const ni_managed_policy_t *);

extern const char *		ni_managed_state_to_string(ni_managed_state_t);

extern ni_dbus_object_t *	ni_objectmodel_register_managed_netif(ni_dbus_server_t *, ni_managed_device_t *);
extern ni_dbus_object_t *	ni_objectmodel_register_managed_modem(ni_dbus_server_t *, ni_managed_device_t *);
extern ni_dbus_object_t *	ni_objectmodel_register_managed_policy(ni_dbus_server_t *, ni_managed_policy_t *);
extern ni_bool_t		ni_objectmodel_managed_policy_save(ni_dbus_object_t *);
extern dbus_bool_t		ni_objectmodel_unregister_managed_policy(ni_dbus_server_t *, ni_managed_policy_t *);
extern void			ni_objectmodel_unregister_managed_device(ni_managed_device_t *);

extern void			interface_manager_register_all(ni_dbus_server_t *);
extern void			ni_objectmodel_nanny_init(ni_nanny_t *mgr);
extern void			ni_objectmodel_managed_netif_init(ni_dbus_server_t *);
#ifdef MODEM
extern void			ni_objectmodel_managed_modem_init(ni_dbus_server_t *);
#endif
extern void			ni_objectmodel_managed_policy_init(ni_dbus_server_t *);

/*
 * Look up managed device for a given worker
 */

/*
 * Look up managed device for a given worker
 */
static inline ni_managed_device_t *
ni_nanny_get_device(ni_nanny_t *mgr, ni_ifworker_t *w)
{
	return w ? ni_nanny_get_device_by_ifindex(mgr, w->ifindex) : NULL;
}

#endif /* __WICKED_MANAGER_H__ */
