/*
 * DBus generic objects (server and client side)
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DBUS_OBJECTS_H__
#define __WICKED_DBUS_OBJECTS_H__

#include <wicked/dbus.h>

extern ni_dbus_object_t *	__ni_dbus_object_new(char *);
extern void			__ni_dbus_object_free(ni_dbus_object_t *);
extern ni_dbus_object_t *	__ni_dbus_object_create(ni_dbus_object_t *root_object, const char *object_path,
					const ni_dbus_object_functions_t *functions,
					void *object_handle);
extern void			__ni_dbus_server_object_inherit(ni_dbus_object_t *child, const ni_dbus_object_t *parent);
extern void			__ni_dbus_server_object_destroy(ni_dbus_object_t *object);
extern dbus_bool_t		ni_dbus_object_register_property_interface(ni_dbus_object_t *object);

#endif /* __WICKED_DBUS_OBJECTS_H__ */
