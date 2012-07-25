
typedef struct ni_managed_netdev ni_managed_netdev_t;
struct ni_managed_netdev {
	ni_netdev_t *		dev;
	ni_bool_t		user_controlled;
};

typedef struct ni_managed_policy ni_managed_policy_t;
struct ni_managed_policy {
	ni_managed_policy_t *	next;
	ni_fsm_policy_t *	fsm_policy;
	xml_document_t *	doc;
};

extern ni_dbus_class_t		managed_netdev_class;
extern ni_dbus_class_t		managed_policy_class;
extern ni_dbus_class_t		ni_objectmodel_manager_class;
extern ni_dbus_service_t	managed_netdev_service;
extern ni_dbus_service_t	managed_policy_service;
extern ni_dbus_service_t	ni_objectmodel_manager_service;

extern ni_managed_netdev_t *	ni_managed_netdev_new(ni_netdev_t *);
extern void			ni_managed_netdev_free(ni_managed_netdev_t *);

extern ni_managed_policy_t *	ni_managed_policy_new(ni_fsm_policy_t *, xml_document_t *);
extern void			ni_managed_policy_free(ni_managed_policy_t *);

extern ni_dbus_object_t *	ni_objectmodel_register_managed_netdev(ni_dbus_server_t *, ni_managed_netdev_t *);
extern ni_dbus_object_t *	ni_objectmodel_register_managed_policy(ni_dbus_server_t *, ni_managed_policy_t *);

extern void			interface_manager_register_all(ni_dbus_server_t *);
extern void			ni_objectmodel_manager_init(ni_dbus_server_t *server, ni_fsm_t *fsm);
extern void			ni_objectmodel_managed_netif_init(ni_dbus_server_t *);
extern void			ni_objectmodel_managed_policy_init(ni_dbus_server_t *);

