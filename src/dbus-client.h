/*
 * Simple DBus client functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_CLIENT_H__
#define __WICKED_DBUS_CLIENT_H__

#include <dbus/dbus.h>

typedef struct ni_dbus_client	ni_dbus_client_t;

typedef struct ni_dbus_object {
	char *			path;
	char *			interface;
	char *			local_name;
} ni_dbus_object_t;

typedef DBusMessage		ni_dbus_message_t;

typedef void			ni_dbus_msg_callback_t(ni_dbus_client_t *, ni_dbus_message_t *, void *);

extern ni_dbus_client_t *	ni_dbus_client_open(const char *bus_name);
extern void			ni_dbus_client_free(ni_dbus_client_t *);
extern void			ni_dbus_client_add_signal_handler(ni_dbus_client_t *dbc,
					const char *sender,
					const char *object_path,
					const char *object_interface,
					ni_dbus_msg_callback_t *callback);;
extern void			ni_dbus_client_set_call_timeout(ni_dbus_client_t *, unsigned int msec);
extern void			ni_dbus_client_set_application_data(ni_dbus_client_t *, void *);
extern void *			ni_dbus_client_application_data(const ni_dbus_client_t *);
extern void			ni_dbus_client_set_error_map(ni_dbus_client_t *, const ni_intmap_t *);
extern int			ni_dbus_client_translate_error(ni_dbus_client_t *, const DBusError *);
extern ni_dbus_object_t *	ni_dbus_object_new(const char *, const char *);
extern void			ni_dbus_object_free(ni_dbus_object_t *);

extern ni_dbus_message_t *	ni_dbus_method_call_new(ni_dbus_client_t *,
					const ni_dbus_object_t *, const char *method, ...);
extern ni_dbus_message_t *	ni_dbus_method_call_new_va(ni_dbus_client_t *dbus_client, const ni_dbus_object_t *obj,
					const char *method, va_list *app);
extern int			ni_dbus_call_simple(ni_dbus_client_t *, const ni_dbus_object_t *, const char *method,
					int arg_type, void *arg_ptr,
					int res_type, void *res_ptr);
extern int			ni_dbus_message_extract(ni_dbus_client_t *dbus, ni_dbus_message_t *reply, ...);
extern int			ni_dbus_message_send(ni_dbus_client_t *dbus, ni_dbus_message_t *call, ni_dbus_message_t **reply_p);
extern int			ni_dbus_call_async(ni_dbus_client_t *dbus, const ni_dbus_object_t *obj,
					ni_dbus_msg_callback_t *callback, void *user_data, const char *method, ...);
extern void			ni_dbus_mainloop(ni_dbus_client_t *);

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

#endif /* __WICKED_DBUS_CLIENT_H__ */
