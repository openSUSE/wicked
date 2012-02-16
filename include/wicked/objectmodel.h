/*
 * Wicked object model
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_OBJECTMODEL_H__
#define __WICKED_OBJECTMODEL_H__

#include <wicked/dbus.h>

extern ni_xs_scope_t *		ni_objectmodel_init(ni_dbus_server_t *);
extern void			ni_objectmodel_register_all(void);
extern ni_dbus_server_t *	ni_objectmodel_create_service(void);

extern dbus_bool_t		ni_objectmodel_create_initial_objects(ni_dbus_server_t *);
extern ni_dbus_object_t *	ni_objectmodel_register_interface(ni_dbus_server_t *, ni_interface_t *ifp);
extern dbus_bool_t		ni_objectmodel_unregister_interface(ni_dbus_server_t *, ni_interface_t *ifp);
extern int			ni_objectmodel_bind_extensions(void);
extern void			ni_objectmodel_register_class(const ni_dbus_class_t *);
extern const ni_dbus_class_t *	ni_objectmodel_get_class(const char *);


#define NI_OBJECTMODEL_NETIF_CLASS		"netif"
#define NI_OBJECTMODEL_NETIF_LIST_CLASS		"netif-list"
#define NI_OBJECTMODEL_NETIF_REQUEST_CLASS	"netif-request"
#define NI_OBJECTMODEL_ADDRCONF_REQUEST_CLASS	"addrconf-request"

extern const char *		ni_objectmodel_link_classname(ni_iftype_t);

extern const ni_dbus_service_t *ni_objectmodel_service_by_name(const char *interface_name);
extern const ni_dbus_service_t *ni_objectmodel_service_by_class(const ni_dbus_class_t *);

extern dbus_bool_t		ni_objectmodel_get_addrconf_lease(const ni_addrconf_lease_t *, ni_dbus_variant_t *);
extern dbus_bool_t		ni_objectmodel_set_addrconf_lease(ni_addrconf_lease_t *, const ni_dbus_variant_t *);

extern ni_dbus_object_t *	ni_objectmodel_wrap_interface(ni_interface_t *ifp);
extern ni_interface_t *		ni_objectmodel_unwrap_interface(const ni_dbus_object_t *, DBusError *);

extern dbus_bool_t		ni_objectmodel_interface_event(ni_dbus_server_t *, ni_interface_t *, ni_event_t, const ni_uuid_t *);

extern dbus_bool_t		ni_objectmodel_marshal_interface_request(const ni_interface_request_t *, ni_dbus_variant_t *, DBusError *);
extern dbus_bool_t		ni_objectmodel_unmarshal_interface_request(ni_interface_request_t *, const ni_dbus_variant_t *, DBusError *);

typedef struct ni_objectmodel_callback_info ni_objectmodel_callback_info_t;
struct ni_objectmodel_callback_info {
	ni_objectmodel_callback_info_t *next;
	char *			event;
	ni_uuid_t		uuid;
};

ni_objectmodel_callback_info_t *ni_objectmodel_callback_info_from_dict(const ni_dbus_variant_t *);
extern void			ni_objectmodel_callback_info_free(ni_objectmodel_callback_info_t *);

#endif /* __WICKED_OBJECTMODEL_H__ */

