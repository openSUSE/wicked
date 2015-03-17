/*
 *	DBus encapsulation for ipip interfaces.
 *
 *	Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
#include <wicked/tunneling.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"

static ni_netdev_t *	__ni_objectmodel_ipip_create(ni_netdev_t *, const char *, DBusError *);

static inline ni_netdev_t *
__ni_objectmodel_ipip_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_IPIP,
					&ni_objectmodel_ipip_service);
}

static ni_netdev_t *
__ni_objectmodel_ipip_create(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_ipip_t *ipip = NULL;
	ni_netdev_t *dev = NULL;
	const char *err = NULL;
	int rv;

	ipip = ni_netdev_get_ipip(cfg_ifp);
	if ((err = ni_ipip_validate(ipip))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		goto out;
	}

	if (ni_string_empty(ifname)) {
		if (ni_string_empty(cfg_ifp->name) &&
			(ifname = ni_netdev_make_name(nc, "ipip", 1))) {
			ni_string_dup(&cfg_ifp->name, ifname);
		} else {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to create ipip tunnel: "
				"name argument missed");
			goto out;
		}
		ifname = NULL;
	} else if(!ni_string_eq(cfg_ifp->name, ifname)) {
		ni_string_dup(&cfg_ifp->name, ifname);
	}

	if (cfg_ifp->link.hwaddr.len) {
		if (cfg_ifp->link.hwaddr.type == ARPHRD_VOID)
			cfg_ifp->link.hwaddr.type = ARPHRD_TUNNEL;

		if (cfg_ifp->link.hwaddr.type != ARPHRD_TUNNEL ||
		    cfg_ifp->link.hwaddr.len != ni_link_address_length(ARPHRD_TUNNEL)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot create ipip tunnel interface: "
				"invalid local address '%s'",
				ni_link_address_print(&cfg_ifp->link.hwaddr));
			return NULL;
		}
	}

	if (cfg_ifp->link.hwpeer.len) {
		if (cfg_ifp->link.hwpeer.type == ARPHRD_VOID)
			cfg_ifp->link.hwpeer.type = ARPHRD_TUNNEL;

		if (cfg_ifp->link.hwpeer.type != ARPHRD_TUNNEL ||
		    cfg_ifp->link.hwpeer.len != ni_link_address_length(ARPHRD_TUNNEL)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot create ipip tunnel interface: "
				"invalid remote address '%s'",
				ni_link_address_print(&cfg_ifp->link.hwpeer));
			return NULL;
		}
	}

	if ((rv = ni_system_tunnel_create(nc, cfg_ifp, &dev, NI_IFTYPE_IPIP) < 0)) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || dev == NULL
			|| (ifname && dev && !ni_string_eq(dev->name, ifname))) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create ipip tunnel: %s");
			dev = NULL;
			goto out;
		}
		ni_debug_dbus("ipip tunnel exists (and name matches)");
	}

	if (dev->link.type != NI_IFTYPE_IPIP) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Unable to create ipip tunnel: "
			"new interface is of type %s",
			ni_linktype_type_to_name(dev->link.type));
		dev = NULL;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return dev;
}

static dbus_bool_t
ni_objectmodel_ipip_create(ni_dbus_object_t *factory_object,
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
		||  !(dev = __ni_objectmodel_ipip_device_arg(&argv[1]))) {
		return ni_dbus_error_invalid_args(error,
						factory_object->path, method->name);
	}

	if (!(dev = __ni_objectmodel_ipip_create(dev, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

static dbus_bool_t
ni_objectmodel_ipip_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev, *cfg;
	ni_ipip_t *ipip;
	const char *err;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)) ||
		!(cfg = __ni_objectmodel_ipip_device_arg(&argv[0])) ||
		!(ni_netdev_get_ipip(dev))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		return FALSE;
	}

	ipip = ni_netdev_get_ipip(cfg);
	if ((err = ni_ipip_validate(ipip))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		return FALSE;
	}

	cfg->link.ifindex = dev->link.ifindex;
	if (ni_string_empty(cfg->name))
		ni_string_dup(&cfg->name, dev->name);

	if (ni_netdev_device_is_up(dev)) {
		ni_debug_objectmodel("Skipping ipip changeDevice call on %s: "
				"device is up", dev->name);
		return TRUE;
	}

	if (ni_system_tunnel_change(nc, dev, cfg) < 0) {
		dbus_set_error(error,
			DBUS_ERROR_FAILED,
			"Unable to change ipip properties on interface %s",
			dev->name);
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ipip_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if ((rv = ni_system_tunnel_delete(dev, NI_IFTYPE_IPIP) < 0)) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error deleting ipip tunnel %s: %s",
			dev->name, ni_strerror(rv));
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}

/*
 * Get/Set properties
 */

/*
 * Currently only used to pull ipip->tunnel data below, but kept around for later expansion.
 */
static void *
ni_objectmodel_get_ipip(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_ipip_t *ipip;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->ipip;

	if (!(ipip = ni_netdev_get_ipip(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error getting ipip handle for interface");
		return NULL;
	}

	return ipip;
}

static void *
ni_objectmodel_get_tunnel(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_tunnel_t *tunnel = NULL;
	ni_ipip_t *ipip;

	if ((ipip = ni_objectmodel_get_ipip(object, write_access, error)))
		tunnel = &ipip->tunnel;

	return tunnel;
}

static dbus_bool_t
__ni_objectmodel_ipip_get_local_addr(const ni_dbus_object_t *object,
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
__ni_objectmodel_ipip_set_local_addr(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (__ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr)) {
		dev->link.hwaddr.type = ARPHRD_TUNNEL;
		return TRUE;
	} else {
		return FALSE;
	}
}

static dbus_bool_t
__ni_objectmodel_ipip_get_remote_addr(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_get_hwaddr(result, &dev->link.hwpeer);
}

static dbus_bool_t
__ni_objectmodel_ipip_set_remote_addr(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (__ni_objectmodel_set_hwaddr(argument, &dev->link.hwpeer)) {
		dev->link.hwpeer.type = ARPHRD_TUNNEL;
		return TRUE;
	} else {
		return FALSE;
	}
}

/*
 * Property helper macros
 */
#define	IPIP_PROPERTY_SIGNATURE(signature, dbus_name, rw) \
		__NI_DBUS_PROPERTY(signature, dbus_name, __ni_objectmodel_ipip, rw)
#define IPIP_HWADDR_PROPERTY(dbus_name, suffix, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
				dbus_name, suffix, __ni_objectmodel_ipip, rw)

#define IPIP_TUNNEL_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(tunnel, dbus_type, type, rw)
#define IPIP_TUNNEL_BOOL_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(tunnel, dbus_type, type, rw)

/*
 * ipip service
 */
static const ni_dbus_property_t	ni_objectmodel_ipip_property_table[] = {
	IPIP_HWADDR_PROPERTY(local-address,	local_addr, RO),
	IPIP_HWADDR_PROPERTY(remote-address,	remote_addr, RO),
	IPIP_TUNNEL_UINT16_PROPERTY(ttl, ttl, RO),
	IPIP_TUNNEL_UINT16_PROPERTY(tos, tos, RO),
	IPIP_TUNNEL_BOOL_PROPERTY(pmtudisc, pmtudisc, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ipip_methods[] = {
	{ "changeDevice",	"a{sv}",	ni_objectmodel_ipip_change },
	{ "deleteDevice",	"",		ni_objectmodel_ipip_delete },

	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_ipip_service = {
	.name			= NI_OBJECTMODEL_IPIP_INTERFACE,
	.methods		= ni_objectmodel_ipip_methods,
	.properties		= ni_objectmodel_ipip_property_table,
};

/*
 * ipip factory service
 */
static ni_dbus_method_t		ni_objectmodel_ipip_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	ni_objectmodel_ipip_create },

	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_ipip_factory_service = {
	.name			= NI_OBJECTMODEL_IPIP_INTERFACE ".Factory",
	.methods		= ni_objectmodel_ipip_factory_methods,
};
