/*
 * Simple DBus connection handling functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_CONNECTION_H__
#define __WICKED_DBUS_CONNECTION_H__

#include <dbus/dbus.h>
#include "dbus-common.h"

extern ni_dbus_connection_t *	ni_dbus_connection_open(const char *bus_name);
extern void			ni_dbus_connection_free(ni_dbus_connection_t *);
extern int			ni_dbus_connection_call(ni_dbus_connection_t *connection,
					ni_dbus_message_t *call, ni_dbus_message_t **reply_p,
					unsigned int call_timeout, const ni_intmap_t *error_map);
extern int			ni_dbus_connection_call_async(ni_dbus_connection_t *connection,
					ni_dbus_message_t *call, unsigned int timeout,
					ni_dbus_async_callback_t *callback, ni_dbus_proxy_t *proxy);
extern int			ni_dbus_connection_send_message(ni_dbus_connection_t *, ni_dbus_message_t *);
extern void			ni_dbus_add_signal_handler(ni_dbus_connection_t *conn,
					const char *sender,
					const char *object_path,
					const char *object_interface,
					ni_dbus_signal_handler_t *callback,
					void *user_data);
extern void			ni_dbus_connection_register_object(ni_dbus_connection_t *, ni_dbus_object_t *);
extern void			ni_dbus_connection_unregister_object(ni_dbus_connection_t *, ni_dbus_object_t *);
extern int			ni_dbus_message_get_args(ni_dbus_message_t *reply, ...);
extern void			ni_dbus_mainloop(ni_dbus_connection_t *);

#endif /* __WICKED_DBUS_CONNECTION_H__ */
