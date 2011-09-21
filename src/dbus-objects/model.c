/*
 * DBus generic interfaces for wicked
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"

#define TRACE_ENTER()		ni_debug_dbus("%s()", __FUNCTION__)
#define TP()			ni_debug_dbus("TP - %s:%u", __FUNCTION__, __LINE__)

extern ni_dbus_object_t *	ni_objectmodel_new_interface(ni_dbus_server_t *server,
					const ni_dbus_service_t *service,
					const ni_dbus_variant_t *dict, DBusError *error);

static ni_dbus_service_t	wicked_dbus_netif_interface;

dbus_bool_t
ni_objectmodel_register_all(ni_dbus_server_t *server)
{
	ni_dbus_object_t *object;

	object = ni_dbus_server_register_object(server, "Interface", NULL, NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	ni_dbus_object_register_service(object, &wicked_dbus_netif_interface);
	return TRUE;
}

/*
 * This method allows clients to create new (virtual) network interfaces.
 * The first argument is the DBus service name of the interface type to
 * create, eg. com.suse.Wicked.Interface.VLAN for a vlan interface.
 * The second argument is a dict containing all the properties making up the
 * configuration of the new interface. These properties must be supported by
 * the chosen service, i.e. when creating a VLAN device, you can only specify
 * VLAN properties, but no, say, network configuration items.
 *
 * The only exception from this rule is the special property "name", which
 * can be used to requests a specific name for the newly created interface.
 */
static dbus_bool_t
__ni_dbus_netif_create(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	static const ni_dbus_service_t *all_services[] = {
		&wicked_dbus_ethernet_service,
		&wicked_dbus_vlan_service,
		NULL
	};
	const char *interface_name;
	const ni_dbus_service_t *service;
	ni_dbus_object_t *result;
	unsigned int i;

	TRACE_ENTER();
	if (!ni_dbus_variant_get_string(&argv[0], &interface_name))
		goto bad_args;

	for (i = 0; (service = all_services[i]) != NULL; ++i) {
		if (!strcmp(interface_name, service->object_interface))
			break;
	}

	if (service == NULL) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Unknown dbus interface %s", interface_name);
		return FALSE;
	}

	result = ni_objectmodel_new_interface(ni_dbus_object_get_server(object), service, &argv[1], error);
	if (!result)
		return FALSE;

#if 0
	ni_dbus_message_iter_append_object_path(&iter, ni_dbus_object_get_path(result));
#endif

	return TRUE;

bad_args:
	dbus_set_error(error, DBUS_ERROR_FAILED,
			"Bad argument in call to Interface.create()");
	return FALSE;
}

static ni_dbus_method_t		wicked_dbus_netif_methods[] = {
	{ "create",		"sa{sv}",	__ni_dbus_netif_create },
	{ NULL }
};


static ni_dbus_service_t	wicked_dbus_netif_interface = {
	.object_interface = WICKED_DBUS_INTERFACE ".Interface",
	.methods = wicked_dbus_netif_methods,
	/* .properties = wicked_dbus_netif_properties, */
};
