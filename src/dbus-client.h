/*
 * Simple DBus client functions
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */


#ifndef __WICKED_DBUS_CLIENT_H__
#define __WICKED_DBUS_CLIENT_H__

#include <dbus/dbus.h>
#include "dbus-connection.h"


extern dbus_bool_t	ni_dbus_object_get_managed_objects(ni_dbus_object_t *, DBusError *);

#endif /* __WICKED_DBUS_CLIENT_H__ */
