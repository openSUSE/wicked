/*
 * DBus errors
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DBUS_ERRORS_H__
#define __WICKED_DBUS_ERRORS_H__

#define __NI_DBUS_ERROR(x)		"com.suse.Wicked." #x

#define NI_DBUS_ERROR_PROPERTY_NOT_PRESENT	__NI_DBUS_ERROR(PropertyNotPresent)

#endif /* __WICKED_DBUS_ERRORS_H__ */
