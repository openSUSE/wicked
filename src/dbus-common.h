/*
 * Common DBus types and functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_COMMON_H__
#define __WICKED_DBUS_COMMON_H__


#include <wicked/dbus.h>

#define NI_DBUS_BUS_NAME	"org.freedesktop.DBus"
#define NI_DBUS_OBJECT_PATH	"/org/freedesktop/DBus"
#define NI_DBUS_INTERFACE	"org.freedesktop.DBus"

extern const char *		ni_dbus_object_get_path(const ni_dbus_object_t *);
extern const DBusObjectPathVTable *ni_dbus_object_get_vtable(const ni_dbus_object_t *);
extern int			ni_dbus_translate_error(const DBusError *, const ni_intmap_t *);

extern const char *		ni_dbus_type_as_string(int type);

extern int			ni_dbus_message_get_args(ni_dbus_message_t *, ...);
extern int			ni_dbus_message_get_args_variants(ni_dbus_message_t *msg,
					ni_dbus_variant_t *argv, unsigned int max_args);

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

/*
 * Efficient handling of dbus dicts
 */
struct ni_dbus_dict_entry {
	/* key of the dict entry */
	const char *		key;

	/* datum associated with key */
	ni_dbus_variant_t	datum;
};

struct ni_dbus_dict_entry_handler {
	const char *		name;
	int			type;
	int			array_type;
	unsigned int		array_len_min;
	unsigned int		array_len_max;

	int			(*set)(struct ni_dbus_dict_entry *, void *);
};

#define NI_DBUS_BASIC_PROPERTY(__name, __type, __setfn) \
{ .name = __name, .type = __type, .set = __setfn }
#define NI_DBUS_ARRAY_PROPERTY(__name, __array_type, __setfn) \
{ .name = __name, .type = DBUS_TYPE_ARRAY, .array_type = __array_type, .set = __setfn }

extern int			ni_dbus_process_properties(DBusMessageIter *, const struct ni_dbus_dict_entry_handler *, void *);


#endif /* __WICKED_DBUS_COMMON_H__ */
