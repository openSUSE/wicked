/*
 * Mapping between our internal error codes and corresponding
 * DBus errors.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/constants.h>
#include <wicked/dbus-errors.h>
#include <wicked/logging.h>
#include <wicked/util.h>

static ni_intmap_t	__ni_dbus_errors[] = {
	{ NI_DBUS_ERROR_PERMISSION_DENIED,		NI_ERROR_PERMISSION_DENIED		},
	{ NI_DBUS_ERROR_DEVICE_NOT_KNOWN,		NI_ERROR_DEVICE_NOT_KNOWN		},
	{ NI_DBUS_ERROR_DEVICE_BAD_HIERARCHY,		NI_ERROR_DEVICE_BAD_HIERARCHY		},
	{ NI_DBUS_ERROR_DEVICE_IN_USE,			NI_ERROR_DEVICE_IN_USE			},
	{ NI_DBUS_ERROR_DEVICE_NOT_UP,			NI_ERROR_DEVICE_NOT_UP			},
	{ NI_DBUS_ERROR_DEVICE_NOT_DOWN,		NI_ERROR_DEVICE_NOT_DOWN		},
	{ NI_DBUS_ERROR_DEVICE_NOT_COMPATIBLE,		NI_ERROR_DEVICE_NOT_COMPATIBLE		},
	{ NI_DBUS_ERROR_DEVICE_EXISTS,			NI_ERROR_DEVICE_EXISTS			},
	{ NI_DBUS_ERROR_AUTH_INFO_MISSING,		NI_ERROR_AUTH_INFO_MISSING		},
	{ NI_DBUS_ERROR_ADDRCONF_NO_LEASE,		NI_ERROR_ADDRCONF_NO_LEASE		},
	{ NI_DBUS_ERROR_CANNOT_CONFIGURE_ADDRESS,	NI_ERROR_CANNOT_CONFIGURE_ADDRESS	},
	{ NI_DBUS_ERROR_CANNOT_CONFIGURE_ROUTE,		NI_ERROR_CANNOT_CONFIGURE_ROUTE		},
	{ NI_DBUS_ERROR_CANNOT_MARSHAL,			NI_ERROR_CANNOT_MARSHAL			},
	{ NI_DBUS_ERROR_PROPERTY_NOT_PRESENT,		NI_ERROR_PROPERTY_NOT_PRESENT		},
	{ NI_DBUS_ERROR_UNRESOLVABLE_HOSTNAME,		NI_ERROR_UNRESOLVABLE_HOSTNAME		},
	{ NI_DBUS_ERROR_UNREACHABLE_ADDRESS,		NI_ERROR_UNREACHABLE_ADDRESS		},
	{ NI_DBUS_ERROR_DOCUMENT_ERROR,			NI_ERROR_DOCUMENT_ERROR			},
	{ NI_DBUS_ERROR_POLICY_EXISTS,			NI_ERROR_POLICY_EXISTS			},
	{ NI_DBUS_ERROR_POLICY_DOESNOTEXIST,		NI_ERROR_POLICY_DOESNOTEXIST		},
	{ NI_DBUS_ERROR_RADIO_DISABLED,			NI_ERROR_RADIO_DISABLED			},

	{ DBUS_ERROR_SERVICE_UNKNOWN,			NI_ERROR_SERVICE_UNKNOWN		},
	{ DBUS_ERROR_UNKNOWN_METHOD,			NI_ERROR_METHOD_NOT_SUPPORTED		},
	{ DBUS_ERROR_ACCESS_DENIED,			NI_ERROR_PERMISSION_DENIED		},
	{ DBUS_ERROR_NO_REPLY,				NI_ERROR_METHOD_CALL_TIMED_OUT		},
	{ DBUS_ERROR_INVALID_ARGS,			NI_ERROR_INVALID_ARGS			},

	{ NULL }
};

int
ni_dbus_get_error(const DBusError *error, char **detail)
{
	unsigned int code;

	if (ni_parse_uint_mapped(error->name, __ni_dbus_errors, &code) < 0) {
		ni_debug_dbus("unable to map DBus error %s, return GENERAL_FAILURE",
				error->name);
		return -NI_ERROR_GENERAL_FAILURE;
	}
	if (detail)
		ni_string_dup(detail, error->message);
	return -code;
}

void
ni_dbus_set_error_from_code(DBusError *error, int errcode, const char *fmt, ...)
{
	const char *errname;
	char msgbuf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	if ((errname = ni_format_uint_mapped(-errcode, __ni_dbus_errors)) == NULL)
		errname = DBUS_ERROR_FAILED;

	dbus_set_error(error, errname, "%s", msgbuf);
}

void
ni_dbus_print_error(const DBusError *error, const char *fmt, ...)
{
	va_list ap;

	if (fmt) {
		char msgbuf[1024];

		va_start(ap, fmt);
		vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
		va_end(ap);

		ni_error("%s. Server responds:", msgbuf);
	} else {
		ni_error("DBus call returns error:");
	}
	ni_error_extra("%s: %s", error->name, error->message);
}
