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
	ni_dbus_client_t *	client;
	char *			bus_name;
	char *			path;
	char *			interface;
	char *			local_name;
	void *			local_data;
};

#endif /* __WICKED_DBUS_CLIENT_H__ */
