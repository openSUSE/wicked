/*
 * Mapping between our internal error codes and corresponding
 * DBus errors.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#include <wicked/constants.h>
#include <wicked/dbus-errors.h>
#include <wicked/logging.h>
#include <wicked/util.h>

static ni_intmap_t	__ni_dbus_errors[] = {
	{ NI_DBUS_ERROR_PERMISSION_DENIED,		NI_ERROR_PERMISSION_DENIED		},
	{ NI_DBUS_ERROR_INTERFACE_NOT_KNOWN,		NI_ERROR_INTERFACE_NOT_KNOWN		},
	{ NI_DBUS_ERROR_INTERFACE_BAD_HIERARCHY,	NI_ERROR_INTERFACE_BAD_HIERARCHY	},
	{ NI_DBUS_ERROR_INTERFACE_IN_USE,		NI_ERROR_INTERFACE_IN_USE		},
	{ NI_DBUS_ERROR_INTERFACE_NOT_UP,		NI_ERROR_INTERFACE_NOT_UP		},
	{ NI_DBUS_ERROR_INTERFACE_NOT_DOWN,		NI_ERROR_INTERFACE_NOT_DOWN		},
	{ NI_DBUS_ERROR_INTERFACE_NOT_COMPATIBLE,	NI_ERROR_INTERFACE_NOT_COMPATIBLE	},
	{ NI_DBUS_ERROR_INTERFACE_EXISTS,		NI_ERROR_INTERFACE_EXISTS		},
	{ NI_DBUS_ERROR_AUTH_INFO_MISSING,		NI_ERROR_AUTH_INFO_MISSING		},
	{ NI_DBUS_ERROR_ADDRCONF_NO_LEASE,		NI_ERROR_ADDRCONF_NO_LEASE		},
	{ NI_DBUS_ERROR_CANNOT_CONFIGURE_ADDRESS,	NI_ERROR_CANNOT_CONFIGURE_ADDRESS	},
	{ NI_DBUS_ERROR_CANNOT_CONFIGURE_ROUTE,		NI_ERROR_CANNOT_CONFIGURE_ROUTE		},
	{ NI_DBUS_ERROR_CANNOT_MARSHAL,			NI_ERROR_CANNOT_MARSHAL			},
	{ NI_DBUS_ERROR_PROPERTY_NOT_PRESENT,		NI_ERROR_PROPERTY_NOT_PRESENT		},

	{ NULL }
};

int
ni_dbus_get_error(const DBusError *error, char **detail)
{
	unsigned int code;

	if (ni_parse_int_mapped(error->name, __ni_dbus_errors, &code) < 0) {
		ni_debug_dbus("unable to map DBus error %s, return GENERAL_FAILURE",
				error->name);
		return -NI_ERROR_GENERAL_FAILURE;
	}
	if (detail)
		ni_string_dup(detail, error->message);
	return -code;
}
