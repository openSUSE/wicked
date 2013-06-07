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

	if (ni_system_lldp_setup(dev, cfg->lldp) < 0) {
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
	ni_netdev_t *dev;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 0);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (ni_system_lldp_setup(dev, NULL) < 0) {
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

/*
 * Helper functions for getting/setting the port-id and chassis-id attributes.
 *
 *
 * The default-* settings tell LLDP to infer the appropriate value from
 * the netdevice at runtime
 */
static inline ni_bool_t
try_set_default(const ni_dbus_variant_t *dict, const char *name)
{
	char defnamebuf[64];

	snprintf(defnamebuf, sizeof(defnamebuf), "default-%s", name);
	return ni_dbus_dict_get(dict, defnamebuf) != NULL;
}

static inline ni_bool_t
try_set_string(const ni_dbus_variant_t *dict, const char *name, char **value)
{
	const char *string_value;

	ni_string_free(value);
	if (try_set_default(dict, name))
		return TRUE;

	if (ni_dbus_dict_get_string(dict, name, &string_value)) {
		ni_string_dup(value, string_value);
		return TRUE;
	}

	return FALSE;
}

static inline ni_bool_t
try_set_mac_address(const ni_dbus_variant_t *dict, const char *name, ni_hwaddr_t *value)
{
	memset(value, 0, sizeof(*value));
	if (try_set_default(dict, name))
		return TRUE;

	if (__ni_objectmodel_dict_get_hwaddr(dict, name, value) && value->len == 6) {
		value->type = NI_IFTYPE_ETHERNET;
		return TRUE;
	}

	return FALSE;
}

static inline ni_bool_t
try_set_net_address(const ni_dbus_variant_t *dict, const char *name, ni_sockaddr_t *value)
{
	memset(value, 0, sizeof(*value));
	if (try_set_default(dict, name))
		return TRUE;

	if (__ni_objectmodel_dict_get_sockaddr(dict, name, value)) {
		return TRUE;
	}

	return FALSE;
}

void
get_default(ni_dbus_variant_t *dict, const char *name)
{
	ni_dbus_variant_t *entry;

	entry = ni_dbus_dict_add(dict, name);
	ni_dbus_variant_set_byte(entry, 0);
}

void
get_string(ni_dbus_variant_t *dict, const char *name, const char *value)
{
	if (strncmp(name, "default-", 8) != 0)
		ni_fatal("get_string: bad element name %s (should start with default-", name);
	if (value == NULL || *value == '\0')
		get_default(dict, name);
	else
		ni_dbus_dict_add_string(dict, name + 8, value);
}

void
get_mac_address(ni_dbus_variant_t *dict, const char *name, const ni_hwaddr_t *value)
{
	if (strncmp(name, "default-", 8) != 0)
		ni_fatal("get_mac_address: bad element name %s (should start with default-", name);
	if (value->len == 0)
		get_default(dict, name);
	else
		__ni_objectmodel_dict_add_hwaddr(dict, name + 8, value);
}

void
get_net_address(ni_dbus_variant_t *dict, const char *name, const ni_sockaddr_t *value)
{
	if (strncmp(name, "default-", 8) != 0)
		ni_fatal("get_net_address: bad element name %s (should start with default-", name);
	if (value->ss_family == AF_UNSPEC)
		get_default(dict, name);
	else
		__ni_objectmodel_dict_add_sockaddr(dict, name + 8, value);
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
		get_string(dict, "default-chassis-component", lldp->chassis_id.string_value);
		break;

	case NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS:
		get_string(dict, "default-ifalias", lldp->chassis_id.string_value);
		break;

	case NI_LLDP_CHASSIS_ID_PORT_COMPONENT:
		get_string(dict, "default-port-component", lldp->chassis_id.string_value);
		break;

	case NI_LLDP_CHASSIS_ID_MAC_ADDRESS:
		get_mac_address(dict, "default-mac-address", &lldp->chassis_id.mac_addr_value);
		break;

	case NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS:
		get_net_address(dict, "default-net-address", &lldp->chassis_id.net_addr_value);
		break;

	case NI_LLDP_CHASSIS_ID_INTERFACE_NAME:
		get_string(dict, "default-ifname", lldp->chassis_id.string_value);
		break;

	default:
		ni_error("LLDP chassis-id: unsupported subtype %u", lldp->chassis_id.type);
		return FALSE;
	}

	return TRUE;
}

/*
 * Query the chassis-id attribute
 */

static dbus_bool_t
__ni_objectmodel_netif_set_chassis_id(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		                                        const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_lldp_t *lldp;

	if (!(lldp = ni_objectmodel_netif_lldp(object, property, TRUE, error)))
		return FALSE;

	if (try_set_string(dict, "ifname", &lldp->chassis_id.string_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_INTERFACE_NAME;
	} else
	if (try_set_string(dict, "ifalias", &lldp->chassis_id.string_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS;
	} else
	if (try_set_string(dict, "chassis-component", &lldp->chassis_id.string_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT;
	} else
	if (try_set_string(dict, "port-component", &lldp->chassis_id.string_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_PORT_COMPONENT;
	} else
	if (try_set_mac_address(dict, "mac-address", &lldp->chassis_id.mac_addr_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_MAC_ADDRESS;
	} else
	if (try_set_net_address(dict, "net-address", &lldp->chassis_id.net_addr_value)) {
		lldp->chassis_id.type = NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS;
	} else {
		ni_error("%s: don't know how to handle this", __func__);
		return FALSE;
	}

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
		get_string(dict, "default-ifalias", lldp->port_id.string_value);
		break;

	case NI_LLDP_PORT_ID_PORT_COMPONENT:
		get_string(dict, "default-port-component", lldp->port_id.string_value);
		break;

	case NI_LLDP_PORT_ID_MAC_ADDRESS:
		get_mac_address(dict, "default-mac-address", &lldp->port_id.mac_addr_value);
		break;

	case NI_LLDP_PORT_ID_NETWORK_ADDRESS:
		get_net_address(dict, "default-net-address", &lldp->port_id.net_addr_value);
		break;

	case NI_LLDP_PORT_ID_INTERFACE_NAME:
		get_string(dict, "default-ifname", lldp->port_id.string_value);
		break;

	case NI_LLDP_PORT_ID_AGENT_CIRCUIT_ID:
		get_string(dict, "default-agent-circuit-id", lldp->port_id.string_value);
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
	ni_lldp_t *lldp;

	if (!(lldp = ni_objectmodel_netif_lldp(object, property, TRUE, error)))
		return FALSE;

	if (try_set_string(dict, "ifname", &lldp->port_id.string_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_INTERFACE_NAME;
	} else
	if (try_set_string(dict, "ifalias", &lldp->port_id.string_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_INTERFACE_ALIAS;
	} else
	if (try_set_string(dict, "port-component", &lldp->port_id.string_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_PORT_COMPONENT;
	} else
	if (try_set_string(dict, "agent-circuit-id", &lldp->port_id.string_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_AGENT_CIRCUIT_ID;
	} else
	if (try_set_mac_address(dict, "mac-address", &lldp->port_id.mac_addr_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_MAC_ADDRESS;
	} else
	if (try_set_net_address(dict, "net-address", &lldp->port_id.net_addr_value)) {
		lldp->port_id.type = NI_LLDP_PORT_ID_NETWORK_ADDRESS;
	} else {
		ni_error("%s: don't know how to handle this", __func__);
		return FALSE;
	}

	return TRUE;
}

#define LLDP_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(lldp, dbus_type, type, rw)
#define LLDP_UINT_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(lldp, dbus_type, type, rw)
#define LLDP_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(lldp, dbus_type, type, rw)
#define LLDP_UINT_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(lldp, dbus_type, type, rw)

const ni_dbus_property_t	ni_objectmodel_lldp_system_property_table[] = {
	LLDP_STRING_PROPERTY(name, system.name, RO),
	LLDP_STRING_PROPERTY(descr, system.description, RO),
	LLDP_UINT_PROPERTY(capabilities, system.capabilities, RO),
	{ NULL }
};

const ni_dbus_property_t	ni_objectmodel_lldp_property_table[] = {
	LLDP_UINT_PROPERTY(destination, destination, RO),
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, chassis-id, chassis_id, __ni_objectmodel_netif, RO),
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, port-id, port_id, __ni_objectmodel_netif, RO),
	LLDP_UINT_PROPERTY(ttl, ttl, RO),

	LLDP_STRING_PROPERTY(port-description, port_description, RO),
	NI_DBUS_GENERIC_DICT_PROPERTY(system, ni_objectmodel_lldp_system_property_table, RW),
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

