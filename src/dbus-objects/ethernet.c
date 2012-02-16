/*
 * dbus encapsulation for ethernet interfaces
 *
 * Copyright (C) 2011, 2012 Olaf Kirch <okir@suse.de>
 */

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/ethernet.h>
#include "model.h"

#include <wicked/ethernet.h>

void *
ni_objectmodel_get_ethernet(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp;
	ni_ethernet_t *eth;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return NULL;

	if (!(eth = ni_interface_get_ethernet(ifp))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting ethernet handle for interface");
		return NULL;
	}
	return eth;
}

#define ETHERNET_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(ethernet, dbus_name, member_name, rw)

const ni_dbus_property_t	ni_objectmodel_ethernet_property_table[] = {
	ETHERNET_UINT_PROPERTY(link-speed, link_speed, RO),
	ETHERNET_UINT_PROPERTY(port-type, port_type, RO),
	ETHERNET_UINT_PROPERTY(duplex, duplex, RO),
	ETHERNET_UINT_PROPERTY(autoneg-enable, autoneg_enable, RO),
	{ NULL }
};
