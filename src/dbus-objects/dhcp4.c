/*
 * dbus encapsulation for dhcp4 client side
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <time.h>
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
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static ni_dbus_client_t *	dbus_dhcp_client = NULL;

static int		ni_objectmodel_dhcp4_acquire(const ni_addrconf_t *acm, ni_interface_t *, const xml_node_t *);
static int		ni_objectmodel_dhcp4_release(const ni_addrconf_t *, ni_interface_t *, ni_addrconf_lease_t *);
static int		ni_objectmodel_dhcp4_is_valid(const ni_addrconf_t *, const ni_addrconf_lease_t *);
extern int		ni_dhcp_xml_from_lease(const ni_addrconf_t *, const ni_addrconf_lease_t *, xml_node_t *);
extern int		ni_dhcp_xml_to_lease(const ni_addrconf_t *, ni_addrconf_lease_t *, const xml_node_t *);

static ni_addrconf_t ni_dhcp_addrconf = {
	.type = NI_ADDRCONF_DHCP,
	.supported_af = NI_AF_MASK_IPV4,

	.request = ni_objectmodel_dhcp4_acquire,
	.release = ni_objectmodel_dhcp4_release,
	.is_valid = ni_objectmodel_dhcp4_is_valid,
	.xml_from_lease = ni_dhcp_xml_from_lease,
	.xml_to_lease = ni_dhcp_xml_to_lease,
};

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

	/* Register our addrconf hooks for DHCP */
	ni_addrconf_register(&ni_dhcp_addrconf);
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
ni_objectmodel_dhcp4_acquire(const ni_addrconf_t *acm, ni_interface_t *dev, const xml_node_t *cfg_xml)
{
	ni_dbus_object_t *object = ni_objectmodel_dhcp4_wrap_interface(dev);
	int rv = 0;

	if (!ni_interface_network_is_up(dev)) {
		ni_error("%s: link is not up, cannot configure through DHCP", dev->name);
		return -NI_ERROR_INTERFACE_NOT_UP;
	}
	if (!(dev->link.ifflags & NI_IFF_ARP_ENABLED)) {
		ni_error("%s: device does not support ARP, cannot configure through DHCP", dev->name);
		return -NI_ERROR_INTERFACE_NOT_UP;
	}

	rv = ni_objectmodel_addrconf_acquire(object, dev->ipv4.request[NI_ADDRCONF_DHCP]);
	ni_dbus_object_free(object);
	return rv;
}

/*
 * Interface.release(uuid)
 * Release a lease for the given interface.
 */
int
ni_objectmodel_dhcp4_release(const ni_addrconf_t *acm, ni_interface_t *dev, ni_addrconf_lease_t *lease)
{
	ni_dbus_object_t *object = ni_objectmodel_dhcp4_wrap_interface(dev);
	int rv;

	rv = ni_objectmodel_addrconf_release(object, lease);
	ni_dbus_object_free(object);
	return rv;
}

/*
 * Verify whether the given lease is valid or not
 */
static int
ni_objectmodel_dhcp4_is_valid(const ni_addrconf_t *acm, const ni_addrconf_lease_t *lease)
{
	time_t now = time(NULL);

	if (lease->state != NI_ADDRCONF_STATE_GRANTED)
		return 0;
	if (lease->time_acquired + lease->dhcp.lease_time <= now)
		return 0;
	return 1;
}

