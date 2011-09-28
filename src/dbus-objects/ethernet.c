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

static ni_ethernet_t *
__wicked_dbus_ethernet_handle(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	ni_ethernet_t *eth;

	if (!(eth = ifp->ethernet)) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting ethernet property");
		return NULL;
	}
	return eth;
}

#define __pointer(type, base, offset_ptr) \
	((type *) (((caddr_t) base) + (unsigned long) offset_ptr))

#if 0
static int
__wicked_dbus_ethernet_get_int(const ni_dbus_object_t *object,
				int *member_offset,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_ethernet_t *eth;

	if (!(eth = __wicked_dbus_ethernet_handle(object, error)))
		return FALSE;

	ni_dbus_variant_set_int32(result, *__pointer(int, eth, member_offset));
	return TRUE;
}
#endif

static int
__wicked_dbus_ethernet_get_uint(const ni_dbus_object_t *object,
				unsigned int *member_offset,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_ethernet_t *eth;

	if (!(eth = __wicked_dbus_ethernet_handle(object, error)))
		return FALSE;

	ni_dbus_variant_set_uint32(result, *__pointer(unsigned int, eth, member_offset));
	return TRUE;
}

static int
__wicked_dbus_ethernet_set_uint(ni_dbus_object_t *object,
				unsigned int *member_offset,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	ni_ethernet_t *eth = ni_interface_get_ethernet(ifp);
	uint32_t value;

	if (!ni_dbus_variant_get_uint32(result, &value))
		return FALSE;
	*(__pointer(unsigned int, eth, member_offset)) = value;
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_ethernet_get_link_speed(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __wicked_dbus_ethernet_get_uint(object, &NULL_ether->link_speed, result, error);
}

static dbus_bool_t
__wicked_dbus_ethernet_set_link_speed(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	return __wicked_dbus_ethernet_set_uint(object, &NULL_ether->link_speed, result, error);
}

static dbus_bool_t
__wicked_dbus_ethernet_get_port_type(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __wicked_dbus_ethernet_get_uint(object, &NULL_ether->port_type, result, error);
}

static dbus_bool_t
__wicked_dbus_ethernet_set_port_type(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	return __wicked_dbus_ethernet_set_uint(object, &NULL_ether->port_type, result, error);
}

static dbus_bool_t
__wicked_dbus_ethernet_get_duplex(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __wicked_dbus_ethernet_get_uint(object, &NULL_ether->duplex, result, error);
}

static dbus_bool_t
__wicked_dbus_ethernet_set_duplex(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	return __wicked_dbus_ethernet_set_uint(object, &NULL_ether->duplex, result, error);
}

static dbus_bool_t
__wicked_dbus_ethernet_get_autoneg_enable(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __wicked_dbus_ethernet_get_uint(object, &NULL_ether->autoneg_enable, result, error);
}

static dbus_bool_t
__wicked_dbus_ethernet_set_autoneg_enable(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	return __wicked_dbus_ethernet_set_uint(object, &NULL_ether->autoneg_enable, result, error);
}

#define WICKED_ETHERNET_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, offsetof(ni_ethernet_t, __name), __wicked_dbus_ethernet, rw)
#define WICKED_ETHERNET_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, offsetof(ni_ethernet_t, __name), __wicked_dbus_ethernet, rw)

static ni_dbus_property_t	wicked_dbus_ethernet_properties[] = {
	WICKED_ETHERNET_PROPERTY(UINT32, link_speed, RO),
	WICKED_ETHERNET_PROPERTY(UINT32, port_type, RO),
	WICKED_ETHERNET_PROPERTY(UINT32, duplex, RO),
	WICKED_ETHERNET_PROPERTY(UINT32, autoneg_enable, RO),
	{ NULL }
};


ni_dbus_service_t	wicked_dbus_ethernet_service = {
	.name = WICKED_DBUS_INTERFACE ".Ethernet",
	.methods = wicked_dbus_ethernet_methods,
	.properties = wicked_dbus_ethernet_properties,
};
