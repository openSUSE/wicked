/*
 * DBus encapsulation for tun/tap interfaces
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"


static ni_netdev_t *	__ni_objectmodel_tun_newlink(ni_netdev_t *, const char *, DBusError *);

/*
 * Return an interface handle containing all tun-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_tun_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_TUN, &ni_objectmodel_tun_service);
}


/*
 * Create a new TUN interface
 */
dbus_bool_t
ni_objectmodel_tun_newlink(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *ifp;
	const char *ifname = NULL;

	NI_TRACE_ENTER();

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(ifp = __ni_objectmodel_tun_device_arg(&argv[1])))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);

	if (!(ifp = __ni_objectmodel_tun_newlink(ifp, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, ifp, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_tun_newlink(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_ifp = NULL;
	int rv;

	/* There's nothing in the device argument that we could use. */

	ni_debug_dbus(1, "TUN.newDevice(name=%s)", ifname);

	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "tun"))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create tun - too many interfaces");
		goto out;
	}

	if ((rv = ni_system_tun_create(nc, ifname, &new_ifp)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS
		 && (ifname != NULL && strcmp(ifname, new_ifp->name))) {
			ni_dbus_set_error_from_code(error, rv,
					"unable to create TUN interface %s",
					ifname);
			goto out;
		}
		ni_debug_dbus(1, "TUN interface exists (and name matches)");
	}

	if (new_ifp->link.type != NI_IFTYPE_TUN) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create TUN interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		ni_netdev_put(new_ifp);
		new_ifp = NULL;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return new_ifp;
}

/*
 * Delete a TUN interface
 */
dbus_bool_t
ni_objectmodel_tun_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *ifp;
	int rv;

	if (!(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("ifp=%s", ifp->name);
	if ((rv = ni_system_tun_delete(ifp)) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Error deleting TUN interface %s: %s",
				ifp->name, ni_strerror(rv));
		return FALSE;
	}

	ni_dbus_object_free(object);
	return TRUE;
}


const ni_dbus_property_t	ni_objectmodel_tun_property_table[] = {
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_tun_methods[] = {
	{ "deleteDevice",	"",			ni_objectmodel_tun_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_tun_factory_methods[] = {
	{ "newDevice",		"sa{sv}",		ni_objectmodel_tun_newlink },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_tun_factory_service = {
	.name		= NI_OBJECTMODEL_TUN_INTERFACE ".Factory",
	.methods	= ni_objectmodel_tun_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_tun_service = {
	.name		= NI_OBJECTMODEL_TUN_INTERFACE,
	.methods	= ni_objectmodel_tun_methods,
	.properties	= ni_objectmodel_tun_property_table,
};

