/*
 * Wicked object model
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_OBJECTMODEL_H__
#define __WICKED_OBJECTMODEL_H__

#include <wicked/dbus.h>

extern void			ni_objectmodel_register_all(void);
extern ni_dbus_server_t *	ni_objectmodel_create_service(void);

extern dbus_bool_t		ni_objectmodel_create_initial_objects(ni_dbus_server_t *);
extern ni_dbus_object_t *	ni_objectmodel_register_interface(ni_dbus_server_t *, ni_interface_t *ifp);
extern dbus_bool_t		ni_objectmodel_unregister_interface(ni_dbus_server_t *, ni_interface_t *ifp);
extern const ni_dbus_service_t *ni_objectmodel_interface_port_service(int iftype);
extern int			ni_objectmodel_bind_extensions(void);
extern void			ni_objectmodel_register_class(const ni_dbus_class_t *);
extern const ni_dbus_class_t *	ni_objectmodel_get_class(const char *);

extern const ni_dbus_service_t	wicked_dbus_interface_request_service;

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
extern ni_interface_t *		ni_objectmodel_unwrap_interface(const ni_dbus_object_t *);

extern ni_dbus_object_t *	ni_objectmodel_wrap_interface_request(ni_interface_request_t *req);

#endif /* __WICKED_OBJECTMODEL_H__ */

