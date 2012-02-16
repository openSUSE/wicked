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
	{ NI_DBUS_ERROR_AUTH_INFO_MISSING,	NI_ERROR_AUTH_INFO_MISSING	},

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
