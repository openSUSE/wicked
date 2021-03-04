/*
 * Common DBus types and functions
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_COMMON_H__
#define __WICKED_DBUS_COMMON_H__


#include <wicked/dbus.h>

#define NI_DBUS_BUS_NAME	"org.freedesktop.DBus"
#define NI_DBUS_OBJECT_PATH	"/org/freedesktop/DBus"
#define NI_DBUS_INTERFACE	"org.freedesktop.DBus"

extern const char *		ni_dbus_object_get_path(const ni_dbus_object_t *);
extern char *			ni_dbus_object_introspect(ni_dbus_object_t *object);
extern const DBusObjectPathVTable *ni_dbus_object_get_vtable(const ni_dbus_object_t *);
extern int			ni_dbus_translate_error(const DBusError *, const ni_intmap_t *);

extern const char *		ni_dbus_type_as_string(int type);

extern dbus_bool_t		ni_dbus_message_iter_get_variant_data(DBusMessageIter *iter,
					ni_dbus_variant_t *variant);
extern dbus_bool_t		ni_dbus_message_iter_append_value(DBusMessageIter *iter,
					const ni_dbus_variant_t *variant,
					const char *signature);
extern dbus_bool_t		ni_dbus_message_iter_append_variant(DBusMessageIter *iter,
					const ni_dbus_variant_t *variant);
extern dbus_bool_t		ni_dbus_message_iter_get_variant(DBusMessageIter *iter,
					ni_dbus_variant_t *variant);
extern dbus_bool_t		ni_dbus_message_iter_append_byte_array(DBusMessageIter *iter,
						const unsigned char *value, unsigned int len);
extern dbus_bool_t		ni_dbus_message_iter_append_uint32_array(DBusMessageIter *iter,
					const uint32_t *value, unsigned int len);

extern const ni_dbus_property_t *__ni_dbus_service_get_property(const ni_dbus_property_t *, const char *);


/*
 * Efficient handling of dbus dicts
 */
struct ni_dbus_dict_entry {
	/* key of the dict entry */
	const char *		key;

	/* datum associated with key */
	ni_dbus_variant_t	datum;
};

#endif /* __WICKED_DBUS_COMMON_H__ */
