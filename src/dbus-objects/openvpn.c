/*
 * DBus encapsulation for openvpn interfaces
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/openvpn.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"

extern ni_dbus_service_t	ni_objectmodel_openvpn_service;

static ni_netdev_t *		__ni_objectmodel_openvpn_newlink(ni_netdev_t *, const char *, DBusError *);

/*
 * Return an interface handle containing all tun-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_openvpn_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_TUN, &ni_objectmodel_openvpn_service);
}


/*
 * Create a new TUN interface
 */
dbus_bool_t
ni_objectmodel_openvpn_newlink(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	const ni_dbus_class_t *class;
	ni_netdev_t *ifp;
	const char *ifname = NULL;

	NI_TRACE_ENTER();

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(ifp = __ni_objectmodel_openvpn_device_arg(&argv[1])))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);

	if (!(ifp = __ni_objectmodel_openvpn_newlink(ifp, ifname, error)))
		return FALSE;

	/* Create a DBus object for the new tunnel interface and return its object path
	 * to the caller.
	 * Since the new device is just a TUN device (no openvpn), we have to explicitly
	 * add the openvpn class interface to it.
	 */
	if ((class = ni_objectmodel_get_class("netif-openvpn")) == NULL)
		ni_warn_once("no netif-openvpn class declared by schema");
	return ni_objectmodel_netif_factory_result(server, reply, ifp, class, error);
}

static ni_netdev_t *
__ni_objectmodel_openvpn_newlink(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_dev = NULL;
	int rv;

	/* There's nothing in the device argument that we could use. */

	ni_debug_dbus("OpenVPN.newDevice(name=%s)", ifname);

	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "tun"))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create tun - too many interfaces");
		goto out;
	}

	if ((rv = ni_system_tun_create(nc, ifname, &new_dev)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS
		 && (ifname != NULL && strcmp(ifname, new_dev->name))) {
			ni_dbus_set_error_from_code(error, rv,
					"unable to create OpenVPN interface %s",
					ifname);
			goto out;
		}
		ni_debug_dbus("OpenVPN interface exists (and name matches)");
	}

	if (new_dev->link.type != NI_IFTYPE_TUN) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create OpenVPN interface: new interface is of type %s",
				ni_linktype_type_to_name(new_dev->link.type));
		ni_netdev_put(new_dev);
		new_dev = NULL;
	}

	if (ni_netdev_get_openvpn(new_dev) == NULL) {
		ni_openvpn_t *vpn = ni_openvpn_new(NULL);

		ni_netdev_set_openvpn(new_dev, vpn);
		(void) ni_openvpn_mkdir(vpn);
	}

	/* FIXME: we should make sure the openvpn config dir exists */

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return new_dev;
}

/*
 * Delete a OpenVPN interface
 */
dbus_bool_t
ni_objectmodel_openvpn_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	/* Delete the tunnel's openvpn handle. This will take care of
	 * the configuration files, keys etc. */
	ni_netdev_set_openvpn(dev, NULL);

	if ((rv = ni_system_tun_delete(dev)) < 0) {
		ni_dbus_set_error_from_code(error, rv, "Cannot delete OpenVPN interface %s", dev->name);
		return FALSE;
	}

	ni_client_state_drop(dev->name);
	return TRUE;
}

/*
 * Helper function to obtain OpenVPN handle from dbus object
 */
static void *
ni_objectmodel_get_openvpn(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_openvpn_t *vpn;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->openvpn;

	if (!(vpn = ni_netdev_get_openvpn(dev))) {
		vpn = ni_openvpn_new(NULL);
		ni_netdev_set_openvpn(dev, vpn);
	}

	return vpn;
}

#define OPENVPN_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(openvpn, dbus_type, type, rw)

const ni_dbus_property_t	ni_objectmodel_openvpn_property_table[] = {
	OPENVPN_STRING_PROPERTY(tunnel-id, ident, RO),
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_openvpn_methods[] = {
	{ "deleteDevice",	"",			ni_objectmodel_openvpn_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_openvpn_factory_methods[] = {
	{ "newDevice",		"sa{sv}",		ni_objectmodel_openvpn_newlink },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_openvpn_factory_service = {
	.name		= NI_OBJECTMODEL_OPENVPN_INTERFACE ".Factory",
	.methods	= ni_objectmodel_openvpn_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_openvpn_service = {
	.name		= NI_OBJECTMODEL_OPENVPN_INTERFACE,
	.methods	= ni_objectmodel_openvpn_methods,
	.properties	= ni_objectmodel_openvpn_property_table,
};


