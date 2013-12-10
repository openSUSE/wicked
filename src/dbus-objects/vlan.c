/*
 * DBus encapsulation for VLAN interfaces
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/vlan.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"


static ni_netdev_t *	__ni_objectmodel_vlan_newlink(ni_netdev_t *, const char *, DBusError *);

/*
 * Return an interface handle containing all vlan-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_vlan_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_VLAN, &ni_objectmodel_vlan_service);
}


/*
 * Create a new VLAN interface
 */
dbus_bool_t
ni_objectmodel_vlan_newlink(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *cfg, *dev;
	const char *ifname = NULL;

	NI_TRACE_ENTER();

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(cfg = __ni_objectmodel_vlan_device_arg(&argv[1])))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);

	if (!(dev = __ni_objectmodel_vlan_newlink(cfg, ifname, error))) {
		ni_netdev_put(cfg);
		return FALSE;
	}
	ni_netdev_put(cfg);

	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_vlan_newlink(ni_netdev_t *cfg, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev = NULL;
	const ni_vlan_t *vlan;
	const char *err;
	int rv;

	if (ni_string_empty(cfg->link.lowerdev.name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Incomplete arguments: need a lower device name");
		return NULL;
	}

	vlan = ni_netdev_get_vlan(cfg);
	if ((err = ni_vlan_validate(vlan))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		return NULL;
	}

	if (ni_string_empty(ifname)) {
		ifname = NULL;
		if (ni_string_empty(cfg->name) &&
		   !ni_string_printf(&cfg->name, "%s.%u",
					cfg->link.lowerdev.name, vlan->tag)) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create vlan interface: "
				"name argument missed, failed to construct");
			return NULL;
		}
	} else
	if (!ni_string_eq(cfg->name, ifname)) {
		ni_string_dup(&cfg->name, ifname);
	}
	if (ni_string_eq(cfg->name, cfg->link.lowerdev.name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot to create vlan interface: "
				"vlan name %s equal with lower device name");
		return NULL;
	}

	ni_debug_dbus("VLAN.newDevice(name=%s/%s, dev=%s, tag=%u)", ifname,
			cfg->name, cfg->link.lowerdev.name, vlan->tag);

	if ((rv = ni_system_vlan_create(nc, cfg, &dev)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || !dev
		||  (ifname && dev && !ni_string_eq(ifname, dev->name))) {
			dbus_set_error(error,
					DBUS_ERROR_FAILED,
					"Unable to create VLAN interface: %s",
					ni_strerror(rv));
			return NULL;
		}
		ni_debug_dbus("VLAN interface exists (and name matches)");
	}

	if (dev && dev->link.type != NI_IFTYPE_VLAN) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create VLAN interface: new interface is of type %s",
				ni_linktype_type_to_name(dev->link.type));
		return NULL;
	}

	return dev;
}

/*
 * Delete a VLAN interface
 */
dbus_bool_t
ni_objectmodel_vlan_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if ((rv = ni_system_vlan_delete(dev)) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Error deleting VLAN interface %s: %s",
				dev->name, ni_strerror(rv));
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	ni_dbus_object_free(object);
	return TRUE;
}


/*
 * Helper function to obtain VLAN config from dbus object
 */
static void *
ni_objectmodel_get_netdev(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_netif(object, error);
}

static ni_vlan_t *
__ni_objectmodel_vlan_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_vlan_t *vlan;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->vlan;

	if (!(vlan = ni_netdev_get_vlan(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting vlan handle for interface");
		return NULL;
	}

	return vlan;
}

static dbus_bool_t
__ni_objectmodel_vlan_get_protocol(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	ni_vlan_t *vlan;

	if (!(vlan = __ni_objectmodel_vlan_handle(object, FALSE, error)))
		return FALSE;

	ni_dbus_variant_set_uint16(result, vlan->protocol);

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_vlan_get_tag(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	ni_vlan_t *vlan;

	if (!(vlan = __ni_objectmodel_vlan_handle(object, FALSE, error)))
		return FALSE;

	ni_dbus_variant_set_uint16(result, vlan->tag);

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_vlan_set_protocol(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *result, DBusError *error)
{
	ni_vlan_t *vlan;

	if (!(vlan = __ni_objectmodel_vlan_handle(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint16(result, &vlan->protocol);
}

static dbus_bool_t
__ni_objectmodel_vlan_set_tag(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *result, DBusError *error)
{
	ni_vlan_t *vlan;

	if (!(vlan = __ni_objectmodel_vlan_handle(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint16(result, &vlan->tag);
}


#define VLAN_PROPERTY_SIGNATURE(signature, dbus_name, rw) \
		__NI_DBUS_PROPERTY(signature, dbus_name, __ni_objectmodel_vlan, rw)
#define VLAN_UINT16_PROPERTY(dbus_name, rw) \
		VLAN_PROPERTY_SIGNATURE(DBUS_TYPE_UINT16_AS_STRING, dbus_name, rw)

const ni_dbus_property_t	ni_objectmodel_vlan_property_table[] = {
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev,  device, link.lowerdev.name, RO),
	VLAN_UINT16_PROPERTY(protocol, RO),
	VLAN_UINT16_PROPERTY(tag, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_vlan_methods[] = {
	{ "deleteDevice",	"",			ni_objectmodel_vlan_delete },

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_vlan_factory_methods[] = {
	{ "newDevice",		"sa{sv}",		ni_objectmodel_vlan_newlink },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_vlan_factory_service = {
	.name		= NI_OBJECTMODEL_VLAN_INTERFACE ".Factory",
	.methods	= ni_objectmodel_vlan_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_vlan_service = {
	.name		= NI_OBJECTMODEL_VLAN_INTERFACE,
	.methods	= ni_objectmodel_vlan_methods,
	.properties	= ni_objectmodel_vlan_property_table,
};

