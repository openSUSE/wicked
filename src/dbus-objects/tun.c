/*
 * DBus encapsulation for tun/tap interfaces
 *
 *	Copyright (C) 2014 SÜSE LINUX Products GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Olaf Kirch <okir@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/tun.h>
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
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_TUN,
		&ni_objectmodel_tun_service);
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
	const ni_tun_t *tun;
	const char *err;
	int rv;

	/* There's nothing in the device argument that we could use. */

	ni_debug_dbus("TUN.newDevice(name=%s)", ifname);

	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "tun", 0))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create tun - too many interfaces");
		goto out;
	}

	tun = ni_netdev_get_tun(cfg_ifp);
	if ((err = ni_tun_validate(tun))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		goto out;
	}

	if ((rv = ni_system_tun_create(nc, ifname, tun, &new_ifp)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || new_ifp == NULL
		|| (ifname && new_ifp && !ni_string_eq(new_ifp->name, ifname))) {
			ni_dbus_set_error_from_code(error, rv,
					"unable to create TUN interface %s",
					ifname);
			new_ifp = NULL;
			goto out;
		}
		ni_debug_dbus("TUN interface exists (and name matches)");
	}

	if (new_ifp->link.type != NI_IFTYPE_TUN) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create TUN interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
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
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if ((rv = ni_system_tun_delete(dev)) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Error deleting TUN interface %s: %s",
				dev->name, ni_strerror(rv));
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}

/*
 * Helper function to obtain tun config from dbus object
 */
static void *
ni_objectmodel_get_tun(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->tun;

	return ni_netdev_get_tun(dev);
}

#define TUN_UINT32_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT32_PROPERTY(tun, dbus_type, type, rw)
#define TUN_BOOL_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(tun, dbus_type, type, rw)

const ni_dbus_property_t	ni_objectmodel_tun_property_table[] = {
	TUN_BOOL_PROPERTY(persistent, persistent, RO),
	TUN_UINT32_PROPERTY(owner, owner, RO),
	TUN_UINT32_PROPERTY(group, group, RO),
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

