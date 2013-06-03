/*
 * DBus encapsulation for LLDP Agent configuration
 *
 * Copyright (C) 2013 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/lldp.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"
#include "misc.h"

static ni_netdev_t *	__ni_objectmodel_protocol_arg(const ni_dbus_variant_t *, const ni_dbus_service_t *);

/*
 * Common helper function to extract some specific properties of device info from a dbus dict
 */
static ni_netdev_t *
__ni_objectmodel_protocol_arg(const ni_dbus_variant_t *dict, const ni_dbus_service_t *service)
{
	ni_dbus_object_t *dev_object;
	ni_netdev_t *dev;
	dbus_bool_t rv;

	dev = ni_netdev_new(NULL, 0);
	dev->link.type = NI_IFTYPE_ETHERNET;

	dev_object = ni_objectmodel_wrap_netif(dev);
	rv = ni_dbus_object_set_properties_from_dict(dev_object, service, dict, NULL);
	ni_dbus_object_free(dev_object);

	if (!rv) {
		ni_netdev_put(dev);
		dev = NULL;
	}
	return dev;
}

/*
 * LLDP.lldpUp
 */
static dbus_bool_t
ni_objectmodel_lldp_up(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev, *cfg;
	dbus_bool_t rv = FALSE;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	ni_trace("ni_objectmodel_lldp_up(%s -> %s)", object->path, dev->name);
	if (!(cfg = __ni_objectmodel_protocol_arg(&argv[0], &ni_objectmodel_lldp_service))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (ni_system_lldp_setup(nc, dev, cfg->lldp) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to set up LLDP on device %s", dev->name);
		goto out;
	}

	rv = TRUE;

out:
	if (cfg)
		ni_netdev_put(cfg);
	return rv;
}

/*
 * LLDP.lldpDown
 */
static dbus_bool_t
ni_objectmodel_lldp_down(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 0);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (ni_system_lldp_setup(nc, dev, NULL) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to stop LLDP agent on device %s", dev->name);
		return FALSE;
	}

	return TRUE;
}

/*
 * Helper function to obtain LLDP config from dbus object
 */
static void *
ni_objectmodel_get_lldp(const ni_dbus_object_t *object, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	return ni_netdev_get_lldp(dev);
}

static ni_lldp_t *
ni_objectmodel_netif_lldp(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
			dbus_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (write_access)
		return ni_netdev_get_lldp(dev);

	if (dev->lldp)
		return dev->lldp;

	ni_dbus_error_property_not_present(error, object->path, property->name);
	return NULL;
}

static dbus_bool_t
__ni_objectmodel_netif_get_chassis_id(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		                                        ni_dbus_variant_t *dict, DBusError *error)
{
	ni_lldp_t *lldp;

	if (!(lldp = ni_objectmodel_netif_lldp(object, property, FALSE, error)))
		return FALSE;

	switch (lldp->chassis_id.type) {
	case NI_LLDP_CHASSIS_ID_INVALID:
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	case NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT:
		ni_dbus_dict_add_string(dict, "chassis-component", lldp->chassis_id.string_value);
		break;

	case NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS:
		ni_dbus_dict_add_string(dict, "ifalias", lldp->chassis_id.string_value);
		break;

	case NI_LLDP_CHASSIS_ID_PORT_COMPONENT:
		ni_dbus_dict_add_string(dict, "port-component", lldp->chassis_id.string_value);
		break;

	case NI_LLDP_CHASSIS_ID_MAC_ADDRESS:
		__ni_objectmodel_dict_add_hwaddr(dict, "mac-address", &lldp->chassis_id.mac_addr_value);
		break;

	case NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS:
		__ni_objectmodel_dict_add_sockaddr(dict, "net-address", &lldp->chassis_id.net_addr_value);
		break;

	case NI_LLDP_CHASSIS_ID_INTERFACE_NAME:
		ni_dbus_dict_add_string(dict, "ifname", lldp->chassis_id.string_value);
		break;

	default:
		ni_error("LLDP chassis-id: unsupported subtype %u", lldp->chassis_id.type);
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_set_chassis_id(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		                                        const ni_dbus_variant_t *dict, DBusError *error)
{
	const char *string_value = NULL;
	ni_lldp_t *lldp;

	if (!(lldp = ni_objectmodel_netif_lldp(object, property, TRUE, error)))
		return FALSE;

	if (ni_dbus_dict_get_string(dict, "chassis-component", &string_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT;
	} else
	if (ni_dbus_dict_get_string(dict, "ifalias", &string_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS;
	} else
	if (ni_dbus_dict_get_string(dict, "port-component", &string_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_PORT_COMPONENT;
	} else
	if (__ni_objectmodel_dict_get_hwaddr(dict, "mac-address", &lldp->chassis_id.mac_addr_value)
	 && lldp->chassis_id.mac_addr_value.len == 6) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_MAC_ADDRESS;
		lldp->chassis_id.mac_addr_value.type = NI_IFTYPE_ETHERNET;
	} else
	if (__ni_objectmodel_dict_get_sockaddr(dict, "net-address", &lldp->chassis_id.net_addr_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS;
	} else
	if (ni_dbus_dict_get_string(dict, "ifname", &string_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_INTERFACE_NAME;
	} else {
		return FALSE;
	}

	ni_string_dup(&lldp->chassis_id.string_value, string_value);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_get_port_id(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		                                        ni_dbus_variant_t *dict, DBusError *error)
{
	ni_lldp_t *lldp;

	if (!(lldp = ni_objectmodel_netif_lldp(object, property, FALSE, error)))
		return FALSE;

	switch (lldp->port_id.type) {
	case NI_LLDP_PORT_ID_INVALID:
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	case NI_LLDP_PORT_ID_INTERFACE_ALIAS:
		ni_dbus_dict_add_string(dict, "ifalias", lldp->port_id.string_value);
		break;

	case NI_LLDP_PORT_ID_PORT_COMPONENT:
		ni_dbus_dict_add_string(dict, "port-component", lldp->port_id.string_value);
		break;

	case NI_LLDP_PORT_ID_MAC_ADDRESS:
		__ni_objectmodel_dict_add_hwaddr(dict, "mac-address", &lldp->port_id.mac_addr_value);
		break;

	case NI_LLDP_PORT_ID_NETWORK_ADDRESS:
		__ni_objectmodel_dict_add_sockaddr(dict, "net-address", &lldp->port_id.net_addr_value);
		break;

	case NI_LLDP_PORT_ID_INTERFACE_NAME:
		ni_dbus_dict_add_string(dict, "ifname", lldp->port_id.string_value);
		break;

	case NI_LLDP_PORT_ID_AGENT_CIRCUIT_ID:
		ni_dbus_dict_add_string(dict, "agent-circuit-id", lldp->port_id.string_value);
		break;

	default:
		ni_error("LLDP port-id: unsupported subtype %u", lldp->port_id.type);
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_set_port_id(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		                                        const ni_dbus_variant_t *dict, DBusError *error)
{
	const char *string_value = NULL;
	ni_lldp_t *lldp;

	if (!(lldp = ni_objectmodel_netif_lldp(object, property, TRUE, error)))
		return FALSE;

	if (ni_dbus_dict_get_string(dict, "port-component", &string_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_PORT_COMPONENT;
	} else
	if (ni_dbus_dict_get_string(dict, "ifalias", &string_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_INTERFACE_ALIAS;
	} else
	if (ni_dbus_dict_get_string(dict, "port-component", &string_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_PORT_COMPONENT;
	} else
	if (__ni_objectmodel_dict_get_hwaddr(dict, "mac-address", &lldp->port_id.mac_addr_value)
	 && lldp->port_id.mac_addr_value.len == 6) {
		lldp->port_id.type = NI_LLDP_PORT_ID_MAC_ADDRESS;
		lldp->port_id.mac_addr_value.type = NI_IFTYPE_ETHERNET;
	} else
	if (__ni_objectmodel_dict_get_sockaddr(dict, "net-address", &lldp->port_id.net_addr_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_NETWORK_ADDRESS;
	} else
	if (ni_dbus_dict_get_string(dict, "ifname", &string_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_INTERFACE_NAME;
	} else
	if (ni_dbus_dict_get_string(dict, "agent-circuit-id", &string_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_AGENT_CIRCUIT_ID;
	} else {
		return FALSE;
	}

	ni_string_dup(&lldp->port_id.string_value, string_value);
	return TRUE;
}

#define LLDP_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(lldp, dbus_type, type, rw)
#define LLDP_UINT_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(lldp, dbus_type, type, rw)
#define LLDP_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(lldp, dbus_type, type, rw)

const ni_dbus_property_t	ni_objectmodel_lldp_property_table[] = {
	LLDP_UINT_PROPERTY(destination, destination, RO),
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, chassis-id, chassis_id, __ni_objectmodel_netif, RO),
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, port-id, port_id, __ni_objectmodel_netif, RO),
	LLDP_UINT_PROPERTY(ttl, ttl, RO),
	{ NULL }
};


static ni_dbus_method_t		ni_objectmodel_lldp_methods[] = {
	{ "lldpUp",	"a{sv}",	ni_objectmodel_lldp_up },
	{ "lldpDown",	"",		ni_objectmodel_lldp_down },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_lldp_service = {
	.name		= NI_OBJECTMODEL_LLDP_INTERFACE,
	.methods	= ni_objectmodel_lldp_methods,
	.properties	= ni_objectmodel_lldp_property_table,
};

