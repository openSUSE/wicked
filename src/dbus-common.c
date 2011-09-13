/*
 * Simple DBus client functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <dbus/dbus.h>
#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wicked/util.h>
#include <wicked/logging.h>
#include "socket_priv.h"
#include "dbus-common.h"
#include "dbus-dict.h"

#define TRACE_ENTER()		ni_debug_dbus("%s()", __FUNCTION__)
#define TP()			ni_debug_dbus("TP - %s:%u", __FUNCTION__, __LINE__)

static ni_intmap_t      __ni_dbus_error_map[] = {
	{ "org.freedesktop.DBus.Error.AccessDenied",	EACCES },
	{ "org.freedesktop.DBus.Error.InvalidArgs",	EINVAL },
	{ "org.freedesktop.DBus.Error.UnknownMethod",	EOPNOTSUPP },

	{ NULL }
};


int
ni_dbus_translate_error(const DBusError *err, const ni_intmap_t *error_map)
{
	unsigned int errcode;

	ni_debug_dbus("%s(%s, msg=%s)", __FUNCTION__, err->name, err->message);

	if (error_map && ni_parse_int_mapped(err->name, error_map, &errcode) >= 0)
		return errcode;

	if (ni_parse_int_mapped(err->name, __ni_dbus_error_map, &errcode) >= 0)
		return errcode;

	ni_warn("Cannot translate DBus error <%s>", err->name);
	return EIO;
}
