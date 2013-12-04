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
	ni_netdev_t *ifp;
	const char *ifname = NULL;

	NI_TRACE_ENTER();

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(ifp = __ni_objectmodel_vlan_device_arg(&argv[1])))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);

	if (!(ifp = __ni_objectmodel_vlan_newlink(ifp, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, ifp, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_vlan_newlink(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_ifp = NULL;
	const ni_vlan_t *vlan;
	int rv;

	vlan = ni_netdev_get_vlan(cfg_ifp);
	if (!vlan || !vlan->tag || !cfg_ifp->link.lowerdev.name) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Incomplete arguments (need VLAN tag and interface name)");
		goto out;
	}

	if (ni_string_empty(ifname)) {
		ifname = NULL;
		if (ni_string_empty(cfg_ifp->name) &&
		   !ni_string_printf(&cfg_ifp->name, "%s.%u",
					cfg_ifp->link.lowerdev.name, vlan->tag)) {
			dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create vlan - too many interfaces");
			goto out;
		}
	} else
	if (!ni_string_eq(cfg_ifp->name, ifname)) {
		ni_string_dup(&cfg_ifp->name, ifname);
	}

	ni_debug_dbus("VLAN.newDevice(name=%s/%s, dev=%s, tag=%u)", ifname,
			cfg_ifp->name, cfg_ifp->link.lowerdev.name, vlan->tag);

	if ((rv = ni_system_vlan_create(nc, cfg_ifp, &new_ifp)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || !new_ifp
		||  (ifname && new_ifp && !ni_string_eq(ifname, new_ifp->name))) {
			dbus_set_error(error,
					DBUS_ERROR_FAILED,
					"Unable to create VLAN interface: %s",
					ni_strerror(rv));
			goto failed;
		}
		ni_debug_dbus("VLAN interface exists (and name matches)");
	}

	if (new_ifp->link.type != NI_IFTYPE_VLAN) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create VLAN interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		goto failed;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return new_ifp;

failed:
	if (new_ifp)
		ni_netdev_put(new_ifp);
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return NULL;
}

/*
 * Delete a VLAN interface
 */
dbus_bool_t
ni_objectmodel_vlan_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *ifp;
	int rv;

	if (!(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("ifp=%s", ifp->name);
	if ((rv = ni_system_vlan_delete(ifp)) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Error deleting VLAN interface %s: %s",
				ifp->name, ni_strerror(rv));
		return FALSE;
	}

	ni_client_state_drop(ifp->link.ifindex);
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
		return dev->link.vlan;

	if (!(vlan = ni_netdev_get_vlan(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting vlan handle for interface");
		return NULL;
	}

	return vlan;
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

