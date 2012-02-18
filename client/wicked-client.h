/*
 * No REST for the wicked!
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef WICKED_CLIENT_H
#define WICKED_CLIENT_H

extern int			do_ifup(int argc, char **argv);
extern int			do_ifdown(int argc, char **argv);

typedef struct ni_call_error_context ni_call_error_context_t;
typedef int			ni_call_error_handler_t(ni_call_error_context_t *, const DBusError *);

extern xml_node_t *		ni_call_error_context_get_node(ni_call_error_context_t *, const char *);

extern ni_dbus_object_t *	wicked_get_interface_object(const char *);
extern xml_node_t *		wicked_find_link_properties(const xml_node_t *);
extern xml_node_t *		wicked_find_auth_properties(const xml_node_t *, const char **link_type);
extern const ni_dbus_service_t *ni_call_link_layer_service(const char *);
extern const ni_dbus_service_t *ni_call_link_layer_factory_service(const char *);
extern const ni_dbus_service_t *ni_call_link_layer_auth_service(const char *);

extern ni_dbus_object_t *	ni_call_create_client(void);

extern char *			ni_call_link_new_xml(const ni_dbus_service_t *,
					const char *, xml_node_t *);
extern char *			ni_call_link_new_argv(const ni_dbus_service_t *, int, char **);
extern dbus_bool_t		ni_call_device_delete(ni_dbus_object_t *, ni_objectmodel_callback_info_t **);

extern dbus_bool_t		ni_call_firewall_up_xml(ni_dbus_object_t *, xml_node_t *, ni_objectmodel_callback_info_t **);
extern dbus_bool_t		ni_call_firewall_down_xml(ni_dbus_object_t *, ni_objectmodel_callback_info_t **);
extern dbus_bool_t		ni_call_link_up_xml(ni_dbus_object_t *, xml_node_t *, ni_objectmodel_callback_info_t **);
extern dbus_bool_t		ni_call_link_login_xml(ni_dbus_object_t *, xml_node_t *, ni_objectmodel_callback_info_t **,
					ni_call_error_handler_t *);
extern dbus_bool_t		ni_call_link_logout_xml(ni_dbus_object_t *, xml_node_t *, ni_objectmodel_callback_info_t **,
					ni_call_error_handler_t *);
extern dbus_bool_t		ni_call_link_change_xml(ni_dbus_object_t *, xml_node_t *, ni_objectmodel_callback_info_t **,
					ni_call_error_handler_t *);
extern dbus_bool_t		ni_call_link_down(ni_dbus_object_t *, ni_objectmodel_callback_info_t **);

extern dbus_bool_t		ni_call_request_lease(ni_dbus_object_t *object, const ni_dbus_service_t *service,
					ni_dbus_variant_t *arg, ni_objectmodel_callback_info_t **callback_list);
extern dbus_bool_t		ni_call_request_lease_xml(ni_dbus_object_t *, const ni_dbus_service_t *,
					xml_node_t *, ni_objectmodel_callback_info_t **);
extern dbus_bool_t		ni_call_drop_lease(ni_dbus_object_t *object, const ni_dbus_service_t *service,
					ni_objectmodel_callback_info_t **callback_list);

extern dbus_bool_t		ni_call_properties_from_argv(const ni_dbus_service_t *, ni_dbus_variant_t *, int, char **);

#endif /* WICKED_CLIENT_H */
