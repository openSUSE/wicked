/*
 * dbus encapsulation for ethernet interfaces
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
#include "model.h"

static ni_dbus_method_t		wicked_dbus_ethernet_methods[] = {
	{ NULL }
};

#include <wicked/ethernet.h>

#define NULL_ether	((ni_ethernet_t *) 0)

void *
ni_objectmodel_get_ethernet(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	ni_ethernet_t *eth;

	if (!(eth = ni_interface_get_ethernet(ifp))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting ethernet handle for interface");
		return NULL;
	}
	return eth;
}

#define ETHERNET_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(ethernet, dbus_name, member_name, rw)

static ni_dbus_property_t	wicked_dbus_ethernet_properties[] = {
	ETHERNET_UINT_PROPERTY(links-speed, link_speed, RO),
	ETHERNET_UINT_PROPERTY(port-type, port_type, RO),
	ETHERNET_UINT_PROPERTY(duplex, duplex, RO),
	ETHERNET_UINT_PROPERTY(autoneg-enable, autoneg_enable, RO),
	{ NULL }
};


ni_dbus_service_t	wicked_dbus_ethernet_service = {
	.name = WICKED_DBUS_ETHERNET_INTERFACE,
	.methods = wicked_dbus_ethernet_methods,
	.properties = wicked_dbus_ethernet_properties,
};
