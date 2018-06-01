/*
 *	DBus encapsulation for dummy interfaces.
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
 *		Karol Mroz <kmroz@suse.com>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"

static ni_netdev_t *	__ni_objectmodel_dummy_newlink(ni_netdev_t *, const char *, DBusError *);

static inline ni_netdev_t *
__ni_objectmodel_dummy_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_DUMMY,
					&ni_objectmodel_dummy_service);
}

static ni_netdev_t *
__ni_objectmodel_dummy_newlink(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev_ifp = NULL;
	int rv;

	if (ni_string_empty(ifname)) {
		if (ni_string_empty(cfg_ifp->name) &&
		    (ifname = ni_netdev_make_name(nc, "dummy", 0))) {
			ni_string_dup(&cfg_ifp->name, ifname);
		} else {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to create dummy interface: "
				"name argument missed");
			goto out;
		}
		ifname = NULL;
	} else if(!ni_string_eq(cfg_ifp->name, ifname)) {
		ni_string_dup(&cfg_ifp->name, ifname);
	}

	if (cfg_ifp->link.hwaddr.len) {
		if (cfg_ifp->link.hwaddr.type == ARPHRD_VOID)
			cfg_ifp->link.hwaddr.type = ARPHRD_ETHER;
		if (cfg_ifp->link.hwaddr.type != ARPHRD_ETHER ||
		    cfg_ifp->link.hwaddr.len != ni_link_address_length(ARPHRD_ETHER)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot create dummy interface: "
				"invalid ethernet address '%s'",
				ni_link_address_print(&cfg_ifp->link.hwaddr));
			return NULL;
		}
	}

	if ((rv = ni_system_dummy_create(nc, cfg_ifp, &dev_ifp)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || dev_ifp == NULL
		|| (ifname && dev_ifp && !ni_string_eq(dev_ifp->name, ifname))) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Unable to create dummy interface: %s",
					ni_strerror(rv));
			dev_ifp = NULL;
			goto out;
		}
		ni_debug_dbus("dummy interface exists (and name matches)");
	}

	if (dev_ifp->link.type != NI_IFTYPE_DUMMY) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create dummy interface: "
				"new interface is of type %s",
				ni_linktype_type_to_name(dev_ifp->link.type));
		dev_ifp = NULL;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return dev_ifp;
}

static dbus_bool_t
ni_objectmodel_dummy_newlink(ni_dbus_object_t *factory_object,
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
	 || !(dev = __ni_objectmodel_dummy_device_arg(&argv[1]))) {
		return ni_dbus_error_invalid_args(error,
						factory_object->path,
						method->name);
	}

	if (!(dev = __ni_objectmodel_dummy_newlink(dev, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

static dbus_bool_t
ni_objectmodel_dummy_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev, *cfg;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)) ||
	    !(cfg = __ni_objectmodel_dummy_device_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		return FALSE;
	}

	cfg->link.ifindex = dev->link.ifindex;
	if (ni_string_empty(cfg->name))
		ni_string_dup(&cfg->name, dev->name);

	if (ni_netdev_device_is_up(dev)) {
		ni_debug_objectmodel("Skipping dummy changeDevice call on %s: "
				"device is up", dev->name);
		return TRUE;
	}

	if (ni_system_dummy_change(nc, dev, cfg) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to change dummy properties on interface %s",
				dev->name);
		return FALSE;
	}

	if (cfg->link.hwaddr.type == ARPHRD_VOID)
		cfg->link.hwaddr.type = ARPHRD_ETHER;
	if (!ni_link_address_is_invalid(&cfg->link.hwaddr) &&
	    ni_system_hwaddr_change(nc, dev, &cfg->link.hwaddr) < 0) {
		ni_error("Unable to change hwaddr on dummy interface %s",
				dev->name);
		/* fail? */
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_dummy_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	if ((rv = ni_system_dummy_delete(dev)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error deleting dummy interface %s: %s",
			dev->name, ni_strerror(rv));
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}


/*
 * Helper functions to obtain dummy config from dbus object.
 */

static dbus_bool_t
__ni_objectmodel_dummy_get_address(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_get_hwaddr(result, &dev->link.hwaddr);
}

static dbus_bool_t
__ni_objectmodel_dummy_set_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr);
}

#define DUMMY_HWADDR_PROPERTY(dbus_name, rw) \
		__NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
				dbus_name, __ni_objectmodel_dummy, rw)

const ni_dbus_property_t	ni_objectmodel_dummy_property_table[] = {
	DUMMY_HWADDR_PROPERTY(address, RO),
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_dummy_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_dummy_change },
	{ "deleteDevice",	"",		.handler = ni_objectmodel_dummy_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_dummy_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_dummy_newlink },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_dummy_factory_service = {
	.name		= NI_OBJECTMODEL_DUMMY_INTERFACE ".Factory",
	.methods	= ni_objectmodel_dummy_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_dummy_service = {
	.name		= NI_OBJECTMODEL_DUMMY_INTERFACE,
	.methods	= ni_objectmodel_dummy_methods,
	.properties	= ni_objectmodel_dummy_property_table,
};
