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
#include "debug.h"

extern ni_dbus_object_t *	ni_objectmodel_new_interface(ni_dbus_server_t *server,
					const ni_dbus_service_t *service,
					const ni_dbus_variant_t *dict, DBusError *error);

static ni_dbus_object_functions_t wicked_dbus_netif_functions;
static ni_dbus_service_t	wicked_dbus_netif_interface;

dbus_bool_t
ni_objectmodel_register_all(ni_dbus_server_t *server)
{
	ni_dbus_object_t *object;

	object = ni_dbus_server_register_object(server, "Interface",
					&wicked_dbus_netif_functions,
					NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	ni_dbus_object_register_service(object, &wicked_dbus_netif_interface);

	ni_objectmodel_dhcp4_init(server);
	ni_objectmodel_autoip_init(server);

	return TRUE;
}

const ni_dbus_service_t *
ni_objectmodel_service_by_name(const char *name)
{
	static const ni_dbus_service_t *all_services[] = {
		&wicked_dbus_netif_interface,
		&wicked_dbus_interface_service,
		&wicked_dbus_ethernet_service,
		&wicked_dbus_vlan_service,
		&wicked_dbus_bridge_service,
#if 0
		&wicked_dbus_bonding_service,
#endif
		NULL,
	};
	const ni_dbus_service_t *service;
	unsigned int i;

	for (i = 0; (service = all_services[i]) != NULL; ++i) {
		if (!strcmp(service->name, name))
			return service;
	}

	return NULL;
}

/*
 * Refresh one/all network interfaces.
 * This function is called from the dbus object handling code prior
 * to invoking any method of this object.
 */
static dbus_bool_t
wicked_dbus_netif_refresh(ni_dbus_object_t *object)
{
	ni_interface_array_t deleted = NI_INTERFACE_ARRAY_INIT;
	unsigned int i;
	ni_handle_t *nih;

	NI_TRACE_ENTER();
	if (!(nih = ni_global_state_handle())) {
		ni_error("Unable to obtain netinfo handle");
		return FALSE;
	}

	if (ni_refresh(nih, &deleted) < 0) {
		ni_error("cannot refresh interface list!");
		return FALSE;
	}

	/* When ni_refresh finds that the interface has gone away,
	 * our object_handle may no longer be valid.
	 */
	for (i = 0; i < deleted.count; ++i) {
		ni_interface_t *ifp = deleted.data[i];
		ni_dbus_object_t *child;

		for (child = object->children; child; child = child->next) {
			if (child->handle == ifp) {
				ni_dbus_object_free(child);
				break;
			}
		}
	}

	ni_interface_array_destroy(&deleted);
	return TRUE;
}


/*
 * functions associated with Wicked.Interface
 */
static ni_dbus_object_functions_t wicked_dbus_netif_functions = {
	.refresh	= wicked_dbus_netif_refresh,
};

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
		&wicked_dbus_bridge_service,
		NULL
	};
	const char *interface_name, *object_path;
	const ni_dbus_service_t *service;
	ni_dbus_object_t *result;
	DBusMessageIter iter;
	unsigned int i;

	NI_TRACE_ENTER();
	if (!ni_dbus_variant_get_string(&argv[0], &interface_name))
		goto bad_args;

	for (i = 0; (service = all_services[i]) != NULL; ++i) {
		if (!strcmp(interface_name, service->name))
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

	dbus_message_iter_init_append(reply, &iter);

	object_path = ni_dbus_object_get_path(result);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &object_path);

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
	.name = WICKED_DBUS_FACTORY_INTERFACE,
	.methods = wicked_dbus_netif_methods,
	/* .properties = wicked_dbus_netif_properties, */
};
