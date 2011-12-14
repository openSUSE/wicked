/*
 * DBus generic objects (server and client side)
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DBUS_OBJECTS_H__
#define __WICKED_DBUS_OBJECTS_H__

#include <wicked/dbus.h>

extern ni_dbus_object_t *	__ni_dbus_object_new(const char *);
extern void			__ni_dbus_object_free(ni_dbus_object_t *);
extern void			__ni_dbus_server_object_inherit(ni_dbus_object_t *child, const ni_dbus_object_t *parent);
extern void			__ni_dbus_client_object_inherit(ni_dbus_object_t *child, const ni_dbus_object_t *parent);
extern void			__ni_dbus_server_object_destroy(ni_dbus_object_t *object);
extern void			__ni_dbus_client_object_destroy(ni_dbus_object_t *object);
extern void			__ni_dbus_objects_garbage_collect();
extern const ni_intmap_t *	__ni_dbus_client_object_get_error_map(const ni_dbus_object_t *);
extern dbus_bool_t		ni_dbus_object_register_property_interface(ni_dbus_object_t *object);

static inline void
__ni_dbus_object_insert(ni_dbus_object_t **pos, ni_dbus_object_t *object)
{
	object->pprev = pos;
	object->next = *pos;
	if (object->next)
		object->next->pprev = &object->next;
	*pos = object;
}

static inline void
__ni_dbus_object_unlink(ni_dbus_object_t *object)
{
	if (object->pprev) {
		*(object->pprev) = object->next;
		if (object->next)
			object->next->pprev = object->pprev;
		object->pprev = NULL;
		object->next = NULL;
	}
}

#endif /* __WICKED_DBUS_OBJECTS_H__ */
