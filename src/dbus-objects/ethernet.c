/*
 * dbus encapsulation for ethernet interfaces
 *
 * Copyright (C) 2011, 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/ethernet.h>
#include <wicked/system.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "dbus-common.h"
#include "model.h"
#include "misc.h"

#include <wicked/ethernet.h>

static ni_netdev_t *	ni_objectmodel_ethernet_device_arg(const ni_dbus_variant_t *);

/*
 * Ethernet.changeDevice method
 */
static dbus_bool_t
ni_objectmodel_ethernet_setup(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *ifp, *cfg;
	dbus_bool_t rv = FALSE;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (!(cfg = ni_objectmodel_ethernet_device_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (ni_system_ethernet_setup(nc, ifp, cfg) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to set up ethernet device");
		goto out;
	}

	/*
	 * MAC change on "UP" interfaces tends to fail or
	 * cases all sort of quite strange side effects...
	 */
	if (ni_netdev_device_is_up(ifp)) {
		ni_debug_objectmodel("Skipping hardware address change on %s: "
				"device is up", ifp->name);
	} else {
		if (cfg->link.hwaddr.type == ARPHRD_VOID)
			cfg->link.hwaddr.type = ARPHRD_ETHER;
		if (!ni_link_address_is_invalid(&cfg->link.hwaddr) &&
		    ni_system_hwaddr_change(nc, ifp, &cfg->link.hwaddr) < 0) {
			ni_error("Unable to change hwaddr on ethernet interface %s",
				ifp->name);
		}
	}

	rv = TRUE;

out:
	if (cfg)
		ni_netdev_put(cfg);
	return rv;
}

/*
 * Common helper function to extract ethernet device info from a dbus dict
 */
static ni_netdev_t *
ni_objectmodel_ethernet_device_arg(const ni_dbus_variant_t *dict)
{
	ni_dbus_object_t *dev_object;
	ni_netdev_t *dev;
	dbus_bool_t rv;

	dev = ni_netdev_new(NULL, 0);
	if (!dev)
		return NULL;

	dev->link.type = NI_IFTYPE_ETHERNET;
	if (!ni_netdev_get_ethernet(dev)) {
		ni_netdev_put(dev);
		return NULL;
	}

	dev_object = ni_objectmodel_wrap_netif(dev);
	rv = ni_dbus_object_set_properties_from_dict(dev_object, &ni_objectmodel_ethernet_service, dict, NULL);
	ni_dbus_object_free(dev_object);

	if (!rv) {
		ni_netdev_put(dev);
		dev = NULL;
	}
	return dev;
}

/*
 * Functions for dealing wit Ethernet properties
 */
static ni_ethernet_t *
ni_objectmodel_ethernet_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_ethernet_t *eth;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->ethernet;

	if (!(eth = ni_netdev_get_ethernet(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error getting ethernet handle for interface");
		return NULL;
	}
	return eth;
}

static ni_ethernet_t *
ni_objectmodel_ethernet_write_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_ethernet_handle(object, TRUE, error);
}

static const ni_ethernet_t *
ni_objectmodel_ethernet_read_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_ethernet_handle(object, FALSE, error);
}

void *
ni_objectmodel_get_ethernet(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_ethernet_handle(object, write_access, error);
}

/*
 * Get set ethernet hwaddr
 */
static dbus_bool_t
ni_objectmodel_ethernet_get_address(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	return __ni_objectmodel_get_hwaddr(result, &dev->link.hwaddr);
}

static dbus_bool_t
ni_objectmodel_ethernet_set_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr);
}

static dbus_bool_t
ni_objectmodel_ethernet_get_permanent_address(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_ethernet_t *eth;

	if (!(eth = ni_objectmodel_ethernet_read_handle(object, error)))
		return FALSE;

	if (!eth->permanent_address.len)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	return __ni_objectmodel_get_hwaddr(result, &eth->permanent_address);
}

static dbus_bool_t
ni_objectmodel_ethernet_set_permanent_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_ethernet_t *eth;

	if (!(eth = ni_objectmodel_ethernet_write_handle(object, error)))
		return FALSE;

	return __ni_objectmodel_set_hwaddr(argument, &eth->permanent_address);
}


#define ETHERNET_HWADDR_PROPERTY(dbus_name, member_name, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
			dbus_name, member_name, ni_objectmodel_ethernet, RO)

const ni_dbus_property_t	ni_objectmodel_ethernet_property_table[] = {
	ETHERNET_HWADDR_PROPERTY(permanent-address, permanent_address, RO),
	ETHERNET_HWADDR_PROPERTY(address,           address,           RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ethernet_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_ethernet_setup },
	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_ethernet_service = {
	.name		= NI_OBJECTMODEL_ETHERNET_INTERFACE,
	.methods	= ni_objectmodel_ethernet_methods,
	.properties	= ni_objectmodel_ethernet_property_table,
};

