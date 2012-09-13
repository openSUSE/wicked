/*
 * Client side functions for wicked
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_CLIENT_H__
#define __WICKED_CLIENT_H__

#include <wicked/dbus.h>
#include <wicked/objectmodel.h>

typedef struct ni_call_error_context ni_call_error_context_t;
typedef int			ni_call_error_handler_t(ni_call_error_context_t *, const DBusError *);

extern xml_node_t *		ni_call_error_context_get_node(ni_call_error_context_t *, const char *);
extern int			ni_call_error_context_get_retries(ni_call_error_context_t *, const DBusError *);

extern ni_dbus_object_t *	ni_call_get_netif_list_object(void);
extern ni_dbus_object_t *	ni_call_get_modem_list_object(void);

extern ni_dbus_object_t *	ni_call_create_client(void);
extern char *			ni_call_device_by_name(ni_dbus_object_t *, const char *);
extern char *			ni_call_identify_device(const char *namespace, const xml_node_t *query);
extern char *			ni_call_identify_modem(const char *namespace, const xml_node_t *query);
extern char *			ni_call_device_new_xml(const ni_dbus_service_t *, const char *, xml_node_t *);
extern int			ni_call_common_xml(ni_dbus_object_t *,
					const ni_dbus_service_t *, const ni_dbus_method_t *,
					xml_node_t *, ni_objectmodel_callback_info_t **,
					ni_call_error_handler_t *error_func);
extern int			ni_call_set_client_info(ni_dbus_object_t *, const ni_device_clientinfo_t *);
extern int			ni_call_link_monitor(ni_dbus_object_t *);
extern int			ni_call_clear_event_filters(ni_dbus_object_t *);

extern int			ni_call_install_lease_xml(ni_dbus_object_t *, xml_node_t *);

#endif /* __WICKED_CLIENT_H__ */

