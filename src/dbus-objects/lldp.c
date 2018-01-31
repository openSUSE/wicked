/*
 * DBus encapsulation for LLDP Agent configuration
 *
 * Copyright (C) 2013 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>
#include <net/ethernet.h>
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
 * Verify the LLDP configuration sent by the client
 */
static dbus_bool_t
__ni_objectmodel_lldp_verify(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			const ni_netdev_t *dev, const ni_lldp_t *lldp, DBusError *error)
{
	switch (lldp->chassis_id.type) {
	case NI_LLDP_CHASSIS_ID_INTERFACE_NAME:
		if (lldp->chassis_id.string_value != NULL
		 && !ni_string_eq(lldp->chassis_id.string_value, dev->name)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
						"bad arguments in call to %s.%s(): requesting interface name %s, "
						"which does not match the device name. Consider using default-ifname",
						object->path, method->name, lldp->chassis_id.string_value);
			return FALSE;
		}
		break;

	case NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS:
		if (lldp->chassis_id.string_value == NULL
		 && dev->link.alias == NULL) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
						"bad arguments in call to %s.%s(): requesting default interface alias, "
						"but no alias is set for this device",
						object->path, method->name);
			return FALSE;
		}
		break;

	default:
		break;
	}

	switch (lldp->port_id.type) {
	case NI_LLDP_PORT_ID_INTERFACE_NAME:
		if (lldp->port_id.string_value != NULL
		 && !ni_string_eq(lldp->port_id.string_value, dev->name)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
						"bad arguments in call to %s.%s(): requesting interface name %s, "
						"which does not match the device name. Consider using default-ifname",
						object->path, method->name, lldp->port_id.string_value);
			return FALSE;
		}
		break;

	case NI_LLDP_PORT_ID_INTERFACE_ALIAS:
		if (lldp->port_id.string_value == NULL
		 && dev->link.alias == NULL) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
						"bad arguments in call to %s.%s(): requesting default interface alias, "
						"but no alias is set for this device",
						object->path, method->name);
			return FALSE;
		}
		break;

	default:
		break;
	}

	return TRUE;
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

#if defined(NI_ENABLE_LLDP)
	ni_debug_lldp("ni_objectmodel_lldp_up(%s -> %s)", object->path, dev->name);

	if (!ni_system_lldp_available(dev)) {
		ni_debug_lldp("Cannot enable LLDP for device %s: incompatible layer 2 protocol", dev->name);
		return TRUE;
	}
#else
	return TRUE;
#endif

	if (!(cfg = __ni_objectmodel_protocol_arg(&argv[0], &ni_objectmodel_lldp_service))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (cfg->lldp
	 && !__ni_objectmodel_lldp_verify(object, method, dev, cfg->lldp, error))
		goto out;

	if (ni_system_lldp_up(dev, cfg->lldp) < 0) {
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

#if defined(NI_ENABLE_LLDP)
	if (!ni_system_lldp_available(dev)) {
		ni_debug_lldp("Cannot disable LLDP for device %s: incompatible layer 2 protocol", dev->name);
		return TRUE;
	}

	if (ni_system_lldp_down(dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to stop LLDP agent on device %s", dev->name);
		return FALSE;
	}
#endif

	return TRUE;
}

/*
 * Helper function to obtain LLDP config from dbus object
 */
static ni_lldp_t *
__ni_objectmodel_lldp_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_lldp_t *lldp;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->lldp;

	if (!(lldp = ni_netdev_get_lldp(dev)))
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to get LLDP handle for device %s", dev->name);
	return lldp;
}

static ni_lldp_t *
__ni_objectmodel_lldp_write_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_lldp_handle(object, TRUE, error);
}

static const ni_lldp_t *
__ni_objectmodel_lldp_read_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_lldp_handle(object, FALSE, error);
}

static void *
ni_objectmodel_get_lldp(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_lldp_handle(object, write_access, error);
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
try_set_string(const ni_dbus_variant_t *var, char **value)
{
	const char *string_value = NULL;

	ni_string_free(value);
	if (var != NULL && !ni_dbus_variant_get_string(var, &string_value))
		return FALSE;

	ni_string_dup(value, string_value);
	return TRUE;
}

static inline ni_bool_t
try_set_mac_address(const ni_dbus_variant_t *var, ni_hwaddr_t *value)
{
	memset(value, 0, sizeof(*value));

	if (var == NULL)
		return TRUE;
	if (__ni_objectmodel_set_hwaddr(var, value) && value->len == ETH_ALEN) {
		value->type = ARPHRD_ETHER;
		return TRUE;
	}

	return FALSE;
}

static inline ni_bool_t
try_set_net_address(const ni_dbus_variant_t *var, ni_sockaddr_t *value)
{
	memset(value, 0, sizeof(*value));

	if (var == NULL)
		return TRUE;
	if (__ni_objectmodel_get_sockaddr(var, value))
		return TRUE;

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

static ni_bool_t
__ni_objectmodel_struct_add_hwaddr(ni_dbus_variant_t *strct, const ni_hwaddr_t *value)
{
	ni_dbus_variant_t *member;

	if (!(member = ni_dbus_struct_add(strct)))
		return FALSE;
	return __ni_objectmodel_get_hwaddr(member, value);
}

static ni_bool_t
__ni_objectmodel_struct_add_sockaddr(ni_dbus_variant_t *strct, const ni_sockaddr_t *value)
{
	ni_dbus_variant_t *member;

	if (!(member = ni_dbus_struct_add(strct)))
		return FALSE;
	return __ni_objectmodel_set_sockaddr(member, value);
}

/*
 * Map chassis-id and port-id discriminants
 */
static ni_intmap_t	__ni_objectmodel_chassis_id_kind[] = {
	{ "ifname",		NI_LLDP_CHASSIS_ID_INTERFACE_NAME	},
	{ "ifalias",		NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS	},
	{ "chassis-component",	NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT	},
	{ "port-component",	NI_LLDP_CHASSIS_ID_PORT_COMPONENT	},
	{ "mac-address",	NI_LLDP_CHASSIS_ID_MAC_ADDRESS		},
	{ "net-address",	NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS	},

	{ NULL }
};

static int
__ni_objectmodel_chassis_id_name_to_type(const char *name)
{
	unsigned int type;

	if (ni_parse_uint_mapped(name, __ni_objectmodel_chassis_id_kind, &type) < 0)
		return -1;
	return type;
}

static const char *
__ni_objectmodel_chassis_id_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __ni_objectmodel_chassis_id_kind);
}

static ni_intmap_t	__ni_objectmodel_port_id_kind[] = {
	{ "ifname",		NI_LLDP_PORT_ID_INTERFACE_NAME	},
	{ "ifalias",		NI_LLDP_PORT_ID_INTERFACE_ALIAS	},
	{ "port-component",	NI_LLDP_PORT_ID_PORT_COMPONENT	},
	{ "mac-address",	NI_LLDP_PORT_ID_MAC_ADDRESS	},
	{ "net-address",	NI_LLDP_PORT_ID_NETWORK_ADDRESS	},
	{ "agent-circuit-id",	NI_LLDP_PORT_ID_AGENT_CIRCUIT_ID },

	{ NULL }
};

static int
__ni_objectmodel_port_id_name_to_type(const char *name)
{
	unsigned int type;

	if (ni_parse_uint_mapped(name, __ni_objectmodel_port_id_kind, &type) < 0)
		return -1;
	return type;
}

static const char *
__ni_objectmodel_port_id_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __ni_objectmodel_port_id_kind);
}


static dbus_bool_t
__ni_objectmodel_netif_get_chassis_id(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		                                        ni_dbus_variant_t *strct, DBusError *error)
{
	const ni_lldp_t *lldp;
	const char *kind;
	char default_kind[64];

	if (!(lldp = __ni_objectmodel_lldp_read_handle(object, error)))
		return FALSE;

	if (lldp->chassis_id.type == NI_LLDP_CHASSIS_ID_INVALID)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	kind = __ni_objectmodel_chassis_id_type_to_name(lldp->chassis_id.type);
	if (kind == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad property %s; unsupported subtype %u", property->name, lldp->chassis_id.type);
		return FALSE;
	}
	snprintf(default_kind, sizeof(default_kind), "default-%s", kind);

	ni_dbus_variant_init_struct(strct);

	switch (lldp->chassis_id.type) {
	case NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT:
	case NI_LLDP_CHASSIS_ID_INTERFACE_NAME:
	case NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS:
	case NI_LLDP_CHASSIS_ID_PORT_COMPONENT:
		if (lldp->chassis_id.string_value) {
			ni_dbus_struct_add_string(strct, kind);
			ni_dbus_struct_add_string(strct, lldp->chassis_id.string_value);
		} else {
			ni_dbus_struct_add_string(strct, default_kind);
		}
		break;

	case NI_LLDP_CHASSIS_ID_MAC_ADDRESS:
		if (lldp->chassis_id.mac_addr_value.len != 0) {
			ni_dbus_struct_add_string(strct, kind);
			__ni_objectmodel_struct_add_hwaddr(strct, &lldp->chassis_id.mac_addr_value);
		} else {
			ni_dbus_struct_add_string(strct, default_kind);
		}
		break;

	case NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS:
		if (lldp->chassis_id.net_addr_value.ss_family != AF_UNSPEC) {
			ni_dbus_struct_add_string(strct, kind);
			__ni_objectmodel_struct_add_sockaddr(strct, &lldp->chassis_id.net_addr_value);
		} else {
			ni_dbus_struct_add_string(strct, default_kind);
		}
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
		                                        const ni_dbus_variant_t *strct, DBusError *error)
{
	ni_dbus_variant_t *member;
	const char *kind;
	ni_lldp_t *lldp;
	int type;

	if (!(lldp = __ni_objectmodel_lldp_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_struct_get_string(strct, 0, &kind))
		return FALSE;

	if (!strncmp(kind, "default-", 8)) {
		/* For "default-$foobar" types, there's no subsequent members in this struct */
		member = NULL;
		kind += 8;
	} else {
		if (!(member = ni_dbus_struct_get(strct, 1)))
			return FALSE;
	}

	if ((type = __ni_objectmodel_chassis_id_name_to_type(kind)) < 0) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad value for property %s; unsupported subtype %s", property->name, kind);
		return FALSE;
	}

	switch (type) {
	case NI_LLDP_CHASSIS_ID_INTERFACE_NAME:
	case NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS:
	case NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT:
	case NI_LLDP_CHASSIS_ID_PORT_COMPONENT:
		if (!try_set_string(member, &lldp->chassis_id.string_value))
			return FALSE;
		break;

	case NI_LLDP_CHASSIS_ID_MAC_ADDRESS:
		if (!try_set_mac_address(member, &lldp->chassis_id.mac_addr_value))
			return FALSE;
		break;

	case NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS:
		if (!try_set_net_address(member, &lldp->chassis_id.net_addr_value))
			return FALSE;
		break;

	default:
		ni_error("%s: don't know how to handle chassis-id subtype %s", __func__, kind);
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_get_port_id(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		                                        ni_dbus_variant_t *strct, DBusError *error)
{
	const ni_lldp_t *lldp;
	const char *kind;
	char default_kind[64];

	if (!(lldp = __ni_objectmodel_lldp_read_handle(object, error)))
		return FALSE;

	if (lldp->port_id.type == NI_LLDP_PORT_ID_INVALID)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	kind = __ni_objectmodel_port_id_type_to_name(lldp->port_id.type);
	if (kind == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad property %s; unsupported subtype %u", property->name, lldp->port_id.type);
		return FALSE;
	}
	snprintf(default_kind, sizeof(default_kind), "default-%s", kind);

	ni_dbus_variant_init_struct(strct);

	switch (lldp->port_id.type) {
	case NI_LLDP_PORT_ID_PORT_COMPONENT:
	case NI_LLDP_PORT_ID_INTERFACE_NAME:
	case NI_LLDP_PORT_ID_INTERFACE_ALIAS:
	case NI_LLDP_PORT_ID_AGENT_CIRCUIT_ID:
		if (lldp->chassis_id.string_value) {
			ni_dbus_struct_add_string(strct, kind);
			ni_dbus_struct_add_string(strct, lldp->chassis_id.string_value);
		} else {
			ni_dbus_struct_add_string(strct, default_kind);
		}
		break;

	case NI_LLDP_PORT_ID_MAC_ADDRESS:
		if (lldp->port_id.mac_addr_value.len != 0) {
			ni_dbus_struct_add_string(strct, kind);
			__ni_objectmodel_struct_add_hwaddr(strct, &lldp->port_id.mac_addr_value);
		} else {
			ni_dbus_struct_add_string(strct, default_kind);
		}
		break;

	case NI_LLDP_PORT_ID_NETWORK_ADDRESS:
		if (lldp->port_id.net_addr_value.ss_family != AF_UNSPEC) {
			ni_dbus_struct_add_string(strct, kind);
			__ni_objectmodel_struct_add_sockaddr(strct, &lldp->port_id.net_addr_value);
		} else {
			ni_dbus_struct_add_string(strct, default_kind);
		}
		break;

	default:
		ni_error("LLDP port-id: unsupported subtype %u", lldp->port_id.type);
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_set_port_id(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		                                        const ni_dbus_variant_t *strct, DBusError *error)
{
	ni_dbus_variant_t *member;
	const char *kind;
	ni_lldp_t *lldp;
	int type;

	if (!(lldp = __ni_objectmodel_lldp_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_struct_get_string(strct, 0, &kind))
		return FALSE;

	if (!strncmp(kind, "default-", 8)) {
		/* For "default-$foobar" types, there's no subsequent members in this struct */
		member = NULL;
		kind += 8;
	} else {
		if (!(member = ni_dbus_struct_get(strct, 1)))
			return FALSE;
	}

	if ((type = __ni_objectmodel_port_id_name_to_type(kind)) < 0) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad value for property %s; unsupported subtype %s", property->name, kind);
		return FALSE;
	}

	switch (type) {
	case NI_LLDP_PORT_ID_INTERFACE_NAME:
	case NI_LLDP_PORT_ID_INTERFACE_ALIAS:
	case NI_LLDP_PORT_ID_PORT_COMPONENT:
		if (!try_set_string(member, &lldp->port_id.string_value))
			return FALSE;
		break;

	case NI_LLDP_PORT_ID_MAC_ADDRESS:
		if (!try_set_mac_address(member, &lldp->port_id.mac_addr_value))
			return FALSE;
		break;

	case NI_LLDP_PORT_ID_NETWORK_ADDRESS:
		if (!try_set_net_address(member, &lldp->port_id.net_addr_value))
			return FALSE;
		break;

	default:
		ni_error("%s: don't know how to handle port-id subtype %s", __func__, kind);
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
	{ "lldpUp",		"a{sv}",	.handler = ni_objectmodel_lldp_up },
	{ "lldpDown",		"",		.handler = ni_objectmodel_lldp_down },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_lldp_service = {
	.name		= NI_OBJECTMODEL_LLDP_INTERFACE,
	.methods	= ni_objectmodel_lldp_methods,
	.properties	= ni_objectmodel_lldp_property_table,
};

