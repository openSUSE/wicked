/*
 * Simple DBus client functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_CLIENT_H__
#define __WICKED_DBUS_CLIENT_H__

#include <dbus/dbus.h>
#include "dbus-connection.h"


struct ni_dbus_proxy {
	ni_dbus_proxy_t *	next;
	ni_dbus_client_t *	client;
	char *			path;
	char *			interface;
	char *			local_name;
	void *			local_data;

	const ni_dbus_proxy_functions_t *functions;

	/* List of supported DBus interfaces, obtained via
	 * GetManagedObjects */
	const ni_dbus_service_t **interfaces;

	ni_dbus_proxy_t *	children;
};

extern dbus_bool_t	ni_dbus_proxy_get_managed_objects(ni_dbus_proxy_t *, DBusError *);

#endif /* __WICKED_DBUS_CLIENT_H__ */
