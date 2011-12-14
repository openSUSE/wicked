/*
 * dbus encapsulation for dhcp4 client side
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
#include <wicked/addrconf.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static ni_dbus_client_t *	dbus_dhcp_client = NULL;

/*
 * Initialize the dhcp4 client
 */
void
ni_objectmodel_dhcp4_init(ni_dbus_server_t *server)
{
	dbus_dhcp_client = ni_dbus_client_open(WICKED_DBUS_BUS_NAME_DHCP4);
	ni_dbus_client_add_signal_handler(dbus_dhcp_client, NULL, NULL,
			WICKED_DBUS_DHCP4_INTERFACE,
			ni_objectmodel_addrconf_signal_handler,
			server);
}

/*
 * Get the dhcp4 object path for the device
 */
static const char *
ni_objectmodel_dhcp4_object_path(const ni_interface_t *dev)
{
	static char object_path[256];

	snprintf(object_path, sizeof(object_path), WICKED_DBUS_OBJECT_PATH "/DHCP4/Interface/%d", dev->link.ifindex);
	return object_path;
}

/*
 * Wrap a dhcp_device in a dbus object
 */
static ni_dbus_object_t *
ni_objectmodel_dhcp4_wrap_interface(ni_interface_t *dev)
{
	return ni_dbus_client_object_new(dbus_dhcp_client,
			ni_objectmodel_dhcp4_object_path(dev),
			WICKED_DBUS_DHCP4_INTERFACE, NULL, dev);
}

/*
 * Interface.acquire(dict options)
 * Acquire a lease for the given interface.
 *
 * The options dictionary contains addrconf request properties.
 */
int
ni_objectmodel_dhcp4_acquire(ni_interface_t *dev, const ni_addrconf_request_t *req)
{
	ni_dbus_object_t *object = ni_objectmodel_dhcp4_wrap_interface(dev);
	int rv = 0;

	rv = ni_objectmodel_addrconf_acquire(object, req);
	ni_dbus_object_free(object);
	return rv;
}

/*
 * Interface.release(uuid)
 * Release a lease for the given interface.
 */
int
ni_objectmodel_dhcp4_release(ni_interface_t *dev, const ni_addrconf_lease_t *lease)
{
	ni_dbus_object_t *object = ni_objectmodel_dhcp4_wrap_interface(dev);
	int rv;

	rv = ni_objectmodel_addrconf_release(object, lease);
	ni_dbus_object_free(object);
	return rv;
}
