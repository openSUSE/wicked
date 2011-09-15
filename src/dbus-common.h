/*
 * Common DBus types and functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_COMMON_H__
#define __WICKED_DBUS_COMMON_H__


#define NI_DBUS_BUS_NAME	"org.freedesktop.DBus"
#define NI_DBUS_OBJECT_PATH	"/org/freedesktop/DBus"
#define NI_DBUS_INTERFACE	"org.freedesktop.DBus"

typedef DBusMessage		ni_dbus_message_t;
typedef struct ni_dbus_connection ni_dbus_connection_t;
typedef struct ni_dbus_client	ni_dbus_client_t;
typedef struct ni_dbus_server	ni_dbus_server_t;
typedef struct ni_dbus_proxy	ni_dbus_proxy_t;
typedef struct ni_dbus_object	ni_dbus_object_t;

typedef void			ni_dbus_async_callback_t(ni_dbus_proxy_t *, ni_dbus_message_t *);
typedef void			ni_dbus_signal_handler_t(ni_dbus_connection_t *, ni_dbus_message_t *, void *);


extern const char *		ni_dbus_object_get_path(const ni_dbus_object_t *);
extern const DBusObjectPathVTable *ni_dbus_object_get_vtable(const ni_dbus_object_t *);
extern int			ni_dbus_translate_error(const DBusError *, const ni_intmap_t *);


/*
 * Efficient handling of dbus dicts
 */
struct ni_dbus_dict_entry;

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
