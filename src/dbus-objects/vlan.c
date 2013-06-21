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
	if (!vlan || !vlan->tag || !vlan->parent.name) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Incomplete arguments (need VLAN tag and interface name)");
		goto out;
	}

	ni_debug_dbus("VLAN.newDevice(name=%s, dev=%s, tag=%u)", ifname, vlan->parent.name, vlan->tag);

	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "vlan"))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create vlan - too many interfaces");
		goto out;
	}

	if ((rv = ni_system_vlan_create(nc, ifname, vlan, &new_ifp)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS
		  || ifname == NULL || new_ifp == NULL || strcmp(ifname, new_ifp->name)) {
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

	ni_dbus_object_free(object);
	return TRUE;
}


/*
 * Helper function to obtain VLAN config from dbus object
 */
static void *
ni_objectmodel_get_vlan(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->link.vlan;

	return ni_netdev_get_vlan(dev);
}

#define VLAN_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(vlan, dbus_type, type, rw)
#define VLAN_UINT_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(vlan, dbus_type, type, rw)
#define VLAN_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(vlan, dbus_type, type, rw)

const ni_dbus_property_t	ni_objectmodel_vlan_property_table[] = {
	VLAN_STRING_PROPERTY(device, parent.name, RO),
	VLAN_UINT16_PROPERTY(tag, tag, RO),
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

