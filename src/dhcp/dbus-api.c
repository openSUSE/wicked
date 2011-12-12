/*
 * DBus API for wicked dhcp4 supplicant
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 *
 * Much of this code is in dbus-objects/dhcp4.c for now.
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
#include "debug.h"
#include "dhcp.h"

// Hack
extern ni_dbus_object_t *	ni_objectmodel_register_dhcp4_device(ni_dbus_server_t *, ni_dhcp_device_t *);
static void		ni_objectmodel_discover_dhcp_devices(ni_dbus_server_t *);

static ni_dbus_object_functions_t wicked_dbus_dhcpdev_functions;
static ni_dbus_service_t	wicked_dbus_dhcpdev_interface;

dbus_bool_t
ni_objectmodel_register_dhcp4(ni_dbus_server_t *server)
{
	ni_dbus_object_t *object;

	object = ni_dbus_server_register_object(server, "Interface",
					&wicked_dbus_dhcpdev_functions,
					NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	ni_dbus_object_register_service(object, &wicked_dbus_dhcpdev_interface);
	ni_objectmodel_discover_dhcp_devices(server);
	return TRUE;
}

void
ni_objectmodel_discover_dhcp_devices(ni_dbus_server_t *server)
{
	ni_handle_t *nih;
	ni_interface_t *ifp;

	NI_TRACE_ENTER();
	if (!(nih = ni_global_state_handle()))
		ni_fatal("Unable to obtain netinfo handle");

	if (ni_refresh(nih, NULL) < 0)
		ni_fatal("cannot refresh interface list!");

	for (ifp = ni_interfaces(nih); ifp; ifp = ifp->next) {
		ni_dhcp_device_t *dev;

		dev = ni_dhcp_device_new(ifp->name, ifp->link.type);
		if (!dev)
			ni_fatal("Cannot create dhcp device for %s", ifp->name);
		dev->link.ifindex = ifp->link.ifindex;

		ni_objectmodel_register_dhcp4_device(server, dev);
		ni_debug_dbus("Created device for %s", ifp->name);
	}
}

/*
 * Refresh one/all network interfaces.
 * This function is called from the dbus object handling code prior
 * to invoking any method of this object.
 */
static dbus_bool_t
wicked_dbus_dhcpdev_refresh(ni_dbus_object_t *object)
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
static ni_dbus_object_functions_t wicked_dbus_dhcpdev_functions = {
	.refresh	= wicked_dbus_dhcpdev_refresh,
};

