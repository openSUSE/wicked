/*
 *	DBus encapsulation for macvlan interfaces.
 *
 *	Copyright (C) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/macvlan.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"


static ni_netdev_t *	__ni_objectmodel_macvlan_newlink(ni_netdev_t *, const char *, DBusError *);

/*
 * Return an interface handle containing all macvlan-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_macvlan_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_MACVLAN,
					&ni_objectmodel_macvlan_service);
}


/*
 * Create a new macvlan interface
 */
dbus_bool_t
ni_objectmodel_macvlan_newlink(ni_dbus_object_t *factory_object,
			const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *dev;
	const char *ifname = NULL;

	NI_TRACE_ENTER();

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(dev = __ni_objectmodel_macvlan_device_arg(&argv[1]))) {
		return ni_dbus_error_invalid_args(error,
						factory_object->path,
						method->name);
	}

	if (!(dev = __ni_objectmodel_macvlan_newlink(dev, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_macvlan_newlink(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_ifp = NULL;
	const ni_macvlan_t *macvlan;
	const char *err;
	int rv;

	macvlan = ni_netdev_get_macvlan(cfg_ifp);
	if ((err = ni_macvlan_validate(macvlan))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		goto out;
	}

	if (ni_string_empty(ifname)) {
		if (ni_string_empty(cfg_ifp->name) &&
		    (ifname = ni_netdev_make_name(nc, "macvlan"))) {
			ni_string_dup(&cfg_ifp->name, ifname);
		} else {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to create macvlan interface - name argument missed");
			goto out;
		}
		ifname = NULL;
	} else if(!ni_string_eq(cfg_ifp->name, ifname)) {
		ni_string_dup(&cfg_ifp->name, ifname);
	}

	if ((rv = ni_system_macvlan_create(nc, cfg_ifp, &new_ifp)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || new_ifp == NULL
		|| (ifname && new_ifp && !ni_string_eq(new_ifp->name, ifname))) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Unable to create macvlan interface: %s",
					ni_strerror(rv));
			new_ifp = NULL;
			goto out;
		}
	}

	if (new_ifp->link.type != NI_IFTYPE_MACVLAN) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create macvlan interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		new_ifp = NULL;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return new_ifp;
}

/*
 * Delete a macvlan interface
 */
dbus_bool_t
ni_objectmodel_macvlan_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if ((rv = ni_system_macvlan_delete(dev)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error deleting macvlan interface %s: %s",
			dev->name, ni_strerror(rv));
		return FALSE;
	}

	ni_dbus_object_free(object);
	return TRUE;
}


/*
 * Helper function to obtain macvlan config from dbus object
 */
static void *
ni_objectmodel_get_netdev(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_netif(object, error);
}

static ni_macvlan_t *
ni_objectmodel_macvlan_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_macvlan_t *macvlan;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->macvlan;

	if (!(macvlan = ni_netdev_get_macvlan(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error getting macvlan handle for interface");
		return NULL;
	}
	return macvlan;
}

static dbus_bool_t
__ni_objectmodel_macvlan_get_mode(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	ni_macvlan_t *macvlan;

	if (!(macvlan = ni_objectmodel_macvlan_handle(object, FALSE, error)))
		return FALSE;

	ni_dbus_variant_set_uint32(result, macvlan->mode);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_macvlan_get_flags(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	ni_macvlan_t *macvlan;

	if (!(macvlan = ni_objectmodel_macvlan_handle(object, FALSE, error)))
		return FALSE;

	ni_dbus_variant_set_uint16(result, macvlan->flags);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_macvlan_set_mode(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result, DBusError *error)
{
	ni_macvlan_t *macvlan;

	if (!(macvlan = ni_objectmodel_macvlan_handle(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint32(result, &macvlan->mode);
}

static dbus_bool_t
__ni_objectmodel_macvlan_set_flags(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result, DBusError *error)
{
	ni_macvlan_t *macvlan;

	if (!(macvlan = ni_objectmodel_macvlan_handle(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint16(result, &macvlan->flags);
}


#define	MACVLAN_PROPERTY_SIGNATURE(signature, dbus_name, rw) \
		__NI_DBUS_PROPERTY(signature, dbus_name, __ni_objectmodel_macvlan, rw)
#define MACVLAN_UINT32_PROPERTY(dbus_name, rw) \
		MACVLAN_PROPERTY_SIGNATURE(DBUS_TYPE_UINT32_AS_STRING, dbus_name, rw)
#define MACVLAN_UINT16_PROPERTY(dbus_name, rw) \
		MACVLAN_PROPERTY_SIGNATURE(DBUS_TYPE_UINT16_AS_STRING, dbus_name, rw)

const ni_dbus_property_t	ni_objectmodel_macvlan_property_table[] = {
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev,  device, link.lowerdev.name, RO),
	MACVLAN_UINT32_PROPERTY(mode, RO),
	MACVLAN_UINT16_PROPERTY(flags, RO),
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_macvlan_methods[] = {
	{ "deleteDevice",	"",		ni_objectmodel_macvlan_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_macvlan_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	ni_objectmodel_macvlan_newlink },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_macvlan_factory_service = {
	.name		= NI_OBJECTMODEL_MACVLAN_INTERFACE ".Factory",
	.methods	= ni_objectmodel_macvlan_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_macvlan_service = {
	.name		= NI_OBJECTMODEL_MACVLAN_INTERFACE,
	.methods	= ni_objectmodel_macvlan_methods,
	.properties	= ni_objectmodel_macvlan_property_table,
};

