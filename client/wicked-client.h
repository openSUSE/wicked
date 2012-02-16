/*
 * No REST for the wicked!
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef WICKED_CLIENT_H
#define WICKED_CLIENT_H

extern int			do_ifup(int argc, char **argv);

extern ni_dbus_object_t *	wicked_dbus_client_create(void);
extern ni_dbus_object_t *	wicked_get_interface_object(const char *);
extern xml_node_t *		wicked_find_link_properties(const xml_node_t *);
extern const ni_dbus_service_t *wicked_link_layer_factory_service(const char *);

extern char *			wicked_create_interface_xml(const ni_dbus_service_t *,
					const char *, xml_node_t *);
extern dbus_bool_t		wicked_link_change_xml(ni_dbus_object_t *, xml_node_t *,
					unsigned int *);
extern dbus_bool_t		wicked_addrconf_xml(ni_dbus_object_t *, const ni_dbus_service_t *,
					xml_node_t *, ni_objectmodel_callback_info_t **);

#endif /* WICKED_CLIENT_H */
