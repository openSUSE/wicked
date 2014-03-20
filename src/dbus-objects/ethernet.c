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

#include <wicked/ethernet.h>

static ni_netdev_t *	__ni_objectmodel_ethernet_device_arg(const ni_dbus_variant_t *);

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

	if (!(cfg = __ni_objectmodel_ethernet_device_arg(&argv[0]))) {
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
		if (ni_system_hwaddr_change(nc, ifp, &cfg->link.hwaddr) < 0) {
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
__ni_objectmodel_ethernet_device_arg(const ni_dbus_variant_t *dict)
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
__ni_objectmodel_ethernet_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_ethernet_t *eth;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->ethernet;

	if (!(eth = ni_netdev_get_ethernet(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting ethernet handle for interface");
		return NULL;
	}
	return eth;
}

static ni_ethernet_t *
__ni_objectmodel_ethernet_write_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_ethernet_handle(object, TRUE, error);
}

static const ni_ethernet_t *
__ni_objectmodel_ethernet_read_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_ethernet_handle(object, FALSE, error);
}

void *
ni_objectmodel_get_ethernet(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_ethernet_handle(object, write_access, error);
}

/*
 * Get set ethernet hwaddr
 */
static dbus_bool_t
__ni_objectmodel_ethernet_get_address(const ni_dbus_object_t *object,
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
__ni_objectmodel_ethernet_set_address(ni_dbus_object_t *object,
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
__ni_objectmodel_ethernet_get_permanent_address(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_ethernet_t *eth;

	if (!(eth = __ni_objectmodel_ethernet_read_handle(object, error)))
		return FALSE;

	if (!eth->permanent_address.len)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	return __ni_objectmodel_get_hwaddr(result, &eth->permanent_address);
}

static dbus_bool_t
__ni_objectmodel_ethernet_set_permanent_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_ethernet_t *eth;

	if (!(eth = __ni_objectmodel_ethernet_write_handle(object, error)))
		return FALSE;

	return __ni_objectmodel_set_hwaddr(argument, &eth->permanent_address);
}

static dbus_bool_t
__ni_objectmodel_ethernet_get_offload(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_ethernet_t *eth;
	
	if (!(eth = __ni_objectmodel_ethernet_read_handle(object, error)))
		return FALSE;

	if (ni_tristate_is_set(eth->offload.rx_csum))
		ni_dbus_dict_add_int32(result, "rx-csum", eth->offload.rx_csum);
	if (ni_tristate_is_set(eth->offload.tx_csum))
		ni_dbus_dict_add_int32(result, "tx-csum", eth->offload.tx_csum);
	if (ni_tristate_is_set(eth->offload.scatter_gather))
		ni_dbus_dict_add_int32(result, "scatter-gather", eth->offload.scatter_gather);
	if (ni_tristate_is_set(eth->offload.tso))
		ni_dbus_dict_add_int32(result, "tso", eth->offload.tso);
	if (ni_tristate_is_set(eth->offload.ufo))
		ni_dbus_dict_add_int32(result, "ufo", eth->offload.ufo);
	if (ni_tristate_is_set(eth->offload.gso))
		ni_dbus_dict_add_int32(result, "gso", eth->offload.gso);
	if (ni_tristate_is_set(eth->offload.gro))
		ni_dbus_dict_add_int32(result, "gro", eth->offload.gro);
	if (ni_tristate_is_set(eth->offload.lro))
		ni_dbus_dict_add_int32(result, "lro", eth->offload.lro);

	return TRUE;
}

static ni_bool_t
__ni_objectmodel_set_tristate(const ni_dbus_variant_t *argument,
				const char *name, ni_tristate_t *flag)
{
	int32_t val;

	if (ni_dbus_dict_get_int32(argument, name, &val)) {
		ni_tristate_set(flag, val);
		return TRUE;
	} else {
		*flag = NI_TRISTATE_DEFAULT;
		return FALSE;
	}
}

static dbus_bool_t
__ni_objectmodel_ethernet_set_offload(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_ethernet_t *eth;

	if (!(eth = __ni_objectmodel_ethernet_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	__ni_objectmodel_set_tristate(argument, "rx-csum",
					&eth->offload.rx_csum);
	__ni_objectmodel_set_tristate(argument, "tx-csum",
					&eth->offload.tx_csum);
	__ni_objectmodel_set_tristate(argument, "scatter-gather",
					&eth->offload.scatter_gather);
	__ni_objectmodel_set_tristate(argument, "tso",
					&eth->offload.tso);
	__ni_objectmodel_set_tristate(argument, "ufo",
					&eth->offload.ufo);
	__ni_objectmodel_set_tristate(argument, "gso",
					&eth->offload.gso);
	__ni_objectmodel_set_tristate(argument, "gro",
					&eth->offload.gro);
	__ni_objectmodel_set_tristate(argument, "lro",
					&eth->offload.lro);

	return TRUE;
}


#define ETHERNET_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(ethernet, dbus_name, member_name, rw)
#define ETHERNET_INT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT_PROPERTY(ethernet, dbus_name, member_name, rw)

const ni_dbus_property_t	ni_objectmodel_ethernet_property_table[] = {
	ETHERNET_UINT_PROPERTY(link-speed, link_speed, RO),
	ETHERNET_UINT_PROPERTY(port-type, port_type, RO),
	ETHERNET_UINT_PROPERTY(duplex, duplex, RO),
	ETHERNET_INT_PROPERTY(autoneg-enable, autoneg_enable, RO),

	___NI_DBUS_PROPERTY(
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			permanent-address, permanent_address, __ni_objectmodel_ethernet, RO),
	__NI_DBUS_PROPERTY(
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			address, __ni_objectmodel_ethernet, RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			offload, __ni_objectmodel_ethernet, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ethernet_methods[] = {
	{ "changeDevice",	"a{sv}",		ni_objectmodel_ethernet_setup },
	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_ethernet_service = {
	.name		= NI_OBJECTMODEL_ETHERNET_INTERFACE,
	.methods	= ni_objectmodel_ethernet_methods,
	.properties	= ni_objectmodel_ethernet_property_table,
};

