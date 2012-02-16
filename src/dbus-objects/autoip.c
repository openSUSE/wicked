/*
 * dbus encapsulation for ipv4ll client side
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static ni_dbus_client_t *	dbus_autoip_client = NULL;
static ni_dbus_class_t		ni_objectmodel_auto4if_class = {
	"auto4-interface",
};

static int		ni_objectmodel_autoip_acquire(const ni_addrconf_t *, ni_interface_t *);
static int		ni_objectmodel_autoip_release(const ni_addrconf_t *, ni_interface_t *, ni_addrconf_lease_t *);

static ni_addrconf_t ni_autoip_addrconf = {
	.type = NI_ADDRCONF_AUTOCONF,
	.supported_af = NI_AF_MASK_IPV4,

	.request = ni_objectmodel_autoip_acquire,
	.release = ni_objectmodel_autoip_release,
};

/*
 * Initialize the autoip4 client
 */
void
ni_objectmodel_autoip_init(ni_dbus_server_t *server)
{
	dbus_autoip_client = ni_dbus_client_open(WICKED_DBUS_BUS_NAME_AUTO4);
	ni_dbus_client_add_signal_handler(dbus_autoip_client, NULL, NULL,
			WICKED_DBUS_AUTO4_INTERFACE,
			ni_objectmodel_addrconf_signal_handler,
			server);

	/* Register our addrconf hooks for IPv4ll */
	ni_addrconf_register(&ni_autoip_addrconf);
}

/*
 * Get the autoip object path for the device
 */
static const char *
ni_objectmodel_autoip_object_path(const ni_interface_t *dev)
{
	static char object_path[256];

	snprintf(object_path, sizeof(object_path), WICKED_DBUS_OBJECT_PATH "/AUTO4/Interface/%d", dev->link.ifindex);
	return object_path;
}

/*
 * Wrap a autoip_device in a dbus object
 */
static ni_dbus_object_t *
ni_objectmodel_autoip_wrap_interface(ni_interface_t *dev)
{
	return ni_dbus_client_object_new(dbus_autoip_client,
			&ni_objectmodel_auto4if_class,
			ni_objectmodel_autoip_object_path(dev),
			WICKED_DBUS_AUTO4_INTERFACE, dev);
}

/*
 * Interface.acquire(dict options)
 * Acquire a lease for the given interface.
 *
 * The options dictionary contains addrconf request properties.
 */
int
ni_objectmodel_autoip_acquire(const ni_addrconf_t *acm, ni_interface_t *dev)
{
	ni_dbus_object_t *object = ni_objectmodel_autoip_wrap_interface(dev);
	int rv;

	rv = ni_objectmodel_addrconf_acquire(object, dev->ipv4.request[NI_ADDRCONF_AUTOCONF]);
	ni_dbus_object_free(object);
	return rv;
}

/*
 * Interface.release(uuid)
 * Release a lease for the given interface.
 */
int
ni_objectmodel_autoip_release(const ni_addrconf_t *acm, ni_interface_t *dev, ni_addrconf_lease_t *lease)
{
	ni_dbus_object_t *object = ni_objectmodel_autoip_wrap_interface(dev);
	int rv;

	rv = ni_objectmodel_addrconf_release(object, lease);
	ni_dbus_object_free(object);
	return rv;
}
