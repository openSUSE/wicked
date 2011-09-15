/*
 * Simple DBus server functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_SERVER_H__
#define __WICKED_DBUS_SERVER_H__

#include <dbus/dbus.h>
#include "dbus-connection.h"


extern ni_dbus_server_t *	ni_dbus_server_open(const char *bus_name, void *root_handle);
extern void			ni_dbus_server_free(ni_dbus_server_t *);

#endif /* __WICKED_DBUS_SERVER_H__ */

