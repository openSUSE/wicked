/*
 * Error codes and representation
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>

static const char *	ni_errors[__NI_ERROR_MAX] = {
[NI_SUCCESS]				= "Success",
[NI_ERROR_GENERAL_FAILURE]		= "General failure",
[NI_ERROR_RETRY_OPERATION]		= "Retry operation",
[NI_ERROR_INVALID_ARGS]			= "Invalid arguments",
[NI_ERROR_PERMISSION_DENIED]		= "Permission denied",
[NI_ERROR_DOCUMENT_ERROR]		= "Invalid XML document",
[NI_ERROR_DEVICE_NOT_KNOWN]		= "Device not known",
[NI_ERROR_DEVICE_BAD_HIERARCHY]		= "Bad device hierarchy",
[NI_ERROR_DEVICE_IN_USE]		= "Device in use",
[NI_ERROR_DEVICE_NOT_UP]		= "Device not up",
[NI_ERROR_DEVICE_NOT_DOWN]		= "Device not down",
[NI_ERROR_DEVICE_NOT_COMPATIBLE]	= "Device not compatible with requested operation",
[NI_ERROR_DEVICE_EXISTS]		= "Device already exists",
[NI_ERROR_AUTH_INFO_MISSING]		= "Authentication information missing",
[NI_ERROR_ADDRCONF_NO_LEASE]		= "No address configuration lease set",
[NI_ERROR_CANNOT_CONFIGURE_DEVICE]	= "Cannot configure device",
[NI_ERROR_CANNOT_CONFIGURE_ADDRESS]	= "Cannot configure address",
[NI_ERROR_CANNOT_CONFIGURE_ROUTE]	= "Cannot configure route",
[NI_ERROR_DBUS_CALL_FAILED]		= "DBus call failed",
[NI_ERROR_CANNOT_MARSHAL]		= "Cannot marshal arguments for remote object call",
[NI_ERROR_SERVICE_UNKNOWN]		= "Service not known",
[NI_ERROR_PROPERTY_NOT_PRESENT]		= "Object property not present",
[NI_ERROR_METHOD_CALL_TIMED_OUT]	= "DBus method call timed out",
[NI_ERROR_METHOD_NOT_SUPPORTED]		= "Object does not support requested method",
[NI_ERROR_UNRESOLVABLE_HOSTNAME]	= "Cannot resolve hostname",
[NI_ERROR_UNREACHABLE_ADDRESS]		= "Address not reachable",
[NI_ERROR_POLICY_EXISTS]		= "Policy already exists",
[NI_ERROR_RADIO_DISABLED]		= "Wireless networking disabled",
};

const char *
ni_strerror(int errcode)
{
	const char *errstring = NULL;

	if (errcode < 0)
		errcode = -errcode;
	if (errcode < __NI_ERROR_MAX)
		errstring = ni_errors[errcode];
	if (errstring == NULL)
		return "<bad error code>";

	return errstring;
}
