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

static dbus_bool_t
__ni_objectmodel_ethernet_get_address(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;
	ni_dbus_variant_set_byte_array(result, dev->link.hwaddr.data, dev->link.hwaddr.len);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_ethernet_set_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *dev;
	unsigned int len;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_byte_array_minmax(argument, dev->link.hwaddr.data, &len,
					0, sizeof(dev->link.hwaddr.data)))
		return FALSE;

	dev->link.hwaddr.len = len;
	return TRUE;
}



#define ETHERNET_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(ethernet, dbus_name, member_name, rw)

const ni_dbus_property_t	ni_objectmodel_ethernet_property_table[] = {
	ETHERNET_UINT_PROPERTY(link-speed, link_speed, RO),
	ETHERNET_UINT_PROPERTY(port-type, port_type, RO),
	ETHERNET_UINT_PROPERTY(duplex, duplex, RO),
	ETHERNET_UINT_PROPERTY(autoneg-enable, autoneg_enable, RO),

	__NI_DBUS_PROPERTY(
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			address, __ni_objectmodel_ethernet, RO),

	{ NULL }
};
