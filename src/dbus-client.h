/*
 * Simple DBus client functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_CLIENT_H__
#define __WICKED_DBUS_CLIENT_H__

#include <dbus/dbus.h>

typedef struct ni_dbus_client	ni_dbus_client_t;
typedef struct ni_dbus_connection ni_dbus_connection_t;

typedef struct ni_dbus_proxy {
	ni_dbus_client_t *	client;
	char *			bus_name;
	char *			path;
	char *			interface;
	char *			local_name;
	void *			local_data;
} ni_dbus_proxy_t;

typedef DBusMessage		ni_dbus_message_t;

typedef void			ni_dbus_async_callback_t(ni_dbus_proxy_t *, ni_dbus_message_t *);
typedef void			ni_dbus_signal_handler_t(ni_dbus_connection_t *, ni_dbus_message_t *, void *);

extern ni_dbus_connection_t *	ni_dbus_connection_open(void);
extern void			ni_dbus_connection_free(ni_dbus_connection_t *);
extern int			ni_dbus_connection_call(ni_dbus_connection_t *connection,
					ni_dbus_message_t *call, ni_dbus_message_t **reply_p,
					unsigned int call_timeout, const ni_intmap_t *error_map);
extern int			ni_dbus_connection_call_async(ni_dbus_connection_t *connection,
					ni_dbus_message_t *call, unsigned int timeout,
					ni_dbus_async_callback_t *callback, ni_dbus_proxy_t *proxy);
extern int			ni_dbus_process_pending(ni_dbus_connection_t *dbc, DBusPendingCall *call);

extern ni_dbus_client_t *	ni_dbus_client_open(const char *bus_name);
extern void			ni_dbus_client_free(ni_dbus_client_t *);
extern void			ni_dbus_client_add_signal_handler(ni_dbus_client_t *client,
					const char *sender,
					const char *object_path,
					const char *object_interface,
					ni_dbus_signal_handler_t *callback,
					void *user_data);
extern void			ni_dbus_add_signal_handler(ni_dbus_connection_t *conn,
					const char *sender,
					const char *object_path,
					const char *object_interface,
					ni_dbus_signal_handler_t *callback,
					void *user_data);
extern void			ni_dbus_client_set_call_timeout(ni_dbus_client_t *, unsigned int msec);
extern void			ni_dbus_client_set_error_map(ni_dbus_client_t *, const ni_intmap_t *);
extern int			ni_dbus_client_translate_error(ni_dbus_client_t *, const DBusError *);
extern ni_dbus_proxy_t *	ni_dbus_proxy_new(ni_dbus_client_t *, const char *, const char *, const char *, void *);
extern void			ni_dbus_proxy_free(ni_dbus_proxy_t *);
extern int			ni_dbus_proxy_call_simple(const ni_dbus_proxy_t *, const char *method,
					int arg_type, void *arg_ptr,
					int res_type, void *res_ptr);
extern int			ni_dbus_proxy_call_async(ni_dbus_proxy_t *obj,
					ni_dbus_async_callback_t *callback, const char *method, ...);

extern ni_dbus_message_t *	ni_dbus_proxy_call_new(const ni_dbus_proxy_t *, const char *method, ...);
extern ni_dbus_message_t *	ni_dbus_proxy_call_new_va(const ni_dbus_proxy_t *obj,
					const char *method, va_list *app);
extern int			ni_dbus_message_get_args(ni_dbus_message_t *reply, ...);
extern int			ni_dbus_client_call(ni_dbus_client_t *client, ni_dbus_message_t *call, ni_dbus_message_t **reply_p);
extern void			ni_dbus_mainloop(ni_dbus_connection_t *);

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
