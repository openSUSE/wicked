/*
 * DBus errors
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DBUS_ERRORS_H__
#define __WICKED_DBUS_ERRORS_H__

#include <dbus/dbus.h>
#include <wicked/objectmodel.h>

#define __NI_DBUS_ERROR(x)		NI_OBJECTMODEL_NAMESPACE "." #x

#define NI_DBUS_ERROR_PERMISSION_DENIED		__NI_DBUS_ERROR(PermissionDenied)
#define NI_DBUS_ERROR_DEVICE_NOT_KNOWN		__NI_DBUS_ERROR(DeviceNotKnown)
#define NI_DBUS_ERROR_DEVICE_BAD_HIERARCHY	__NI_DBUS_ERROR(DeviceBadHierarchy)
#define NI_DBUS_ERROR_DEVICE_IN_USE		__NI_DBUS_ERROR(DeviceInUse)
#define NI_DBUS_ERROR_DEVICE_NOT_UP		__NI_DBUS_ERROR(DeviceNotUp)
#define NI_DBUS_ERROR_DEVICE_NOT_DOWN		__NI_DBUS_ERROR(DeviceNotDown)
#define NI_DBUS_ERROR_DEVICE_NOT_COMPATIBLE	__NI_DBUS_ERROR(DeviceNotCompatible)
#define NI_DBUS_ERROR_DEVICE_EXISTS		__NI_DBUS_ERROR(DeviceExists)
#define NI_DBUS_ERROR_DEVICE_ENABLEFAILED	__NI_DBUS_ERROR(DeviceEnableFailed)
#define NI_DBUS_ERROR_DEVICE_DISABLEFAILED	__NI_DBUS_ERROR(DeviceDisableFailed)
#define NI_DBUS_ERROR_AUTH_INFO_MISSING	__NI_DBUS_ERROR(AuthInfoMissing)
#define NI_DBUS_ERROR_ADDRCONF_NO_LEASE	__NI_DBUS_ERROR(AddrconfNoLease)
#define NI_DBUS_ERROR_CANNOT_CONFIGURE_ADDRESS	__NI_DBUS_ERROR(CannotConfigureAddress)
#define NI_DBUS_ERROR_CANNOT_CONFIGURE_ROUTE	__NI_DBUS_ERROR(CannotConfigureRoute)
#define NI_DBUS_ERROR_CANNOT_MARSHAL		__NI_DBUS_ERROR(CannotMarshal)
#define NI_DBUS_ERROR_PROPERTY_NOT_PRESENT	__NI_DBUS_ERROR(PropertyNotPresent)
#define NI_DBUS_ERROR_UNRESOLVABLE_HOSTNAME	__NI_DBUS_ERROR(CannotResolveHostname)
#define NI_DBUS_ERROR_UNREACHABLE_ADDRESS	__NI_DBUS_ERROR(CannotReachAddress)
#define NI_DBUS_ERROR_POLICY_EXISTS		__NI_DBUS_ERROR(PolicyExists)
#define NI_DBUS_ERROR_POLICY_DOESNOTEXIST	__NI_DBUS_ERROR(PolicyDoesNotExist)
#define NI_DBUS_ERROR_POLICY_REPLACEFAILED	__NI_DBUS_ERROR(PolicyReplaceFailed)
#define NI_DBUS_ERROR_POLICY_DELETEFAILED	__NI_DBUS_ERROR(PolicyDeleteFailed)
#define NI_DBUS_ERROR_POLICY_UPDATEFAILED	__NI_DBUS_ERROR(PolicyUpdateFailed)
#define NI_DBUS_ERROR_RADIO_DISABLED		__NI_DBUS_ERROR(RadioDisabled)

/* Map dbus error strings to our internal error codes and vice versa */
extern int		ni_dbus_get_error(const DBusError *error, char **detail);
extern void		ni_dbus_set_error_from_code(DBusError *, int, const char *fmt, ...);
extern void		ni_dbus_print_error(const DBusError *, const char *fmt, ...);
extern dbus_bool_t	ni_dbus_error_handler(DBusError *, unsigned int, const ni_dbus_object_t *, const ni_dbus_method_t *, const char *);

static inline dbus_bool_t
ni_dbus_error_property_not_present(DBusError *error, const char *path, const char *property)
{
	dbus_set_error(error, NI_DBUS_ERROR_PROPERTY_NOT_PRESENT,
			"%s property %s not set", path, property);
	return FALSE;
}

static inline dbus_bool_t
ni_dbus_error_invalid_args(DBusError *error, const char *path, const char *method)
{
	dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
			"bad arguments in call to %s.%s()", path, method);
	return FALSE;
}

#endif /* __WICKED_DBUS_ERRORS_H__ */
