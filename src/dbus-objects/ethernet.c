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

/*
 * property link_speed
 */
static dbus_bool_t
__wicked_dbus_ethernet_get_link_speed(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_get_property_uint(
			__wicked_dbus_ethernet_handle(object, error),
			&NULL_ether->link_speed, result);
}

static dbus_bool_t
__wicked_dbus_ethernet_set_link_speed(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(
			__wicked_dbus_ethernet_handle(object, error),
			&NULL_ether->link_speed, result);
}

/*
 * property port_type
 */
static dbus_bool_t
__wicked_dbus_ethernet_get_port_type(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_get_property_uint(
			__wicked_dbus_ethernet_handle(object, error),
			&NULL_ether->port_type, result);
}

static dbus_bool_t
__wicked_dbus_ethernet_set_port_type(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(
			__wicked_dbus_ethernet_handle(object, error),
			&NULL_ether->port_type, result);
}

/*
 * property duplex
 */
static dbus_bool_t
__wicked_dbus_ethernet_get_duplex(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_get_property_uint(
			__wicked_dbus_ethernet_handle(object, error),
			&NULL_ether->duplex, result);
}

static dbus_bool_t
__wicked_dbus_ethernet_set_duplex(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(
			__wicked_dbus_ethernet_handle(object, error),
			&NULL_ether->duplex, result);
}

/*
 * property autoneg_enable
 */
static dbus_bool_t
__wicked_dbus_ethernet_get_autoneg_enable(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_get_property_uint(
			__wicked_dbus_ethernet_handle(object, error),
			&NULL_ether->autoneg_enable, result);
}

static dbus_bool_t
__wicked_dbus_ethernet_set_autoneg_enable(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(
			__wicked_dbus_ethernet_handle(object, error),
			&NULL_ether->autoneg_enable, result);
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
