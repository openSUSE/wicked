/*
 * DBus errors
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DBUS_ERRORS_H__
#define __WICKED_DBUS_ERRORS_H__

#include <dbus/dbus.h>

#define __NI_DBUS_ERROR(x)		"com.suse.Wicked." #x

#define NI_DBUS_ERROR_PROPERTY_NOT_PRESENT	__NI_DBUS_ERROR(PropertyNotPresent)
#define NI_DBUS_ERROR_AUTH_INFO_MISSING		__NI_DBUS_ERROR(AuthInfoMissing)

/* Map dbus error strings to our internal error codes */
extern int		ni_dbus_get_error(const DBusError *error, char **detail);

#endif /* __WICKED_DBUS_ERRORS_H__ */
