/*
 * Common DBus types and functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_H__
#define __WICKED_DBUS_H__

#include <dbus/dbus.h>


#define WICKED_DBUS_BUS_NAME	"com.suse.Wicked"
#define WICKED_DBUS_OBJECT_PATH	"/com/suse/Wicked"
#define WICKED_DBUS_INTERFACE	"com.suse.Wicked"

typedef struct DBusMessage	ni_dbus_message_t;
typedef struct ni_dbus_connection ni_dbus_connection_t;
typedef struct ni_dbus_client	ni_dbus_client_t;
typedef struct ni_dbus_server	ni_dbus_server_t;
typedef struct ni_dbus_proxy	ni_dbus_proxy_t;
typedef struct ni_dbus_object	ni_dbus_object_t;
typedef struct ni_dbus_service	ni_dbus_service_t;

typedef void			ni_dbus_async_callback_t(ni_dbus_proxy_t *proxy,
					ni_dbus_message_t *reply);
typedef void			ni_dbus_signal_handler_t(ni_dbus_connection_t *connection,
					ni_dbus_message_t *signal_msg,
					void *user_data);
typedef int			ni_dbus_service_handler_t(ni_dbus_object_t *object,
					const char *method,
					ni_dbus_message_t *call,
					ni_dbus_message_t *reply,
					DBusError *err);


extern ni_dbus_object_t *	ni_dbus_server_register_object(ni_dbus_server_t *server,
					const char *object_path, void *object_handle);
extern ni_dbus_service_t *	ni_dbus_object_register_service(ni_dbus_object_t *object,
					const char *interface,
					ni_dbus_service_handler_t *handler);

extern ni_dbus_object_t *	ni_dbus_server_get_root_object(const ni_dbus_server_t *);
extern const char *		ni_dbus_object_get_path(const ni_dbus_object_t *);


#endif /* __WICKED_DBUS_H__ */

