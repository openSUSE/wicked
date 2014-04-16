/*
 *	DBus encapsulation for tunnel (ipip) interfaces.
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

/*
 * Get/Set properties
 */
static void *
ni_objectmodel_get_tunnel(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_tunnel_t *tunnel;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->tunnel;

	if (!(tunnel = ni_netdev_get_tunnel(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error getting tunnel handle for interface");
		return NULL;
	}

	return tunnel;
}

static dbus_bool_t
__ni_objectmodel_tunnel_get_local_addr(const ni_dbus_object_t *object,
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
__ni_objectmodel_tunnel_set_local_addr(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr);
}

static dbus_bool_t
__ni_objectmodel_tunnel_get_remote_addr(const ni_dbus_object_t *object,
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
__ni_objectmodel_tunnel_set_remote_addr(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwpeer);
}

/*
 * Property helper macros
 */
#define	TUNNEL_PROPERTY_SIGNATURE(signature, dbus_name, rw) \
		__NI_DBUS_PROPERTY(signature, dbus_name, __ni_objectmodel_tunnel, rw)
#define TUNNEL_HWADDR_PROPERTY(dbus_name, suffix, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
				dbus_name, suffix, __ni_objectmodel_tunnel, rw)

#define TUNNEL_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(tunnel, dbus_type, type, rw)
#define TUNNEL_BOOL_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(tunnel, dbus_type, type, rw)

/*
 * tunnel (ipip) service
 */
static const ni_dbus_property_t	ni_objectmodel_tunnel_property_table[] = {
	TUNNEL_HWADDR_PROPERTY(local-address,	local_addr, RO),
	TUNNEL_HWADDR_PROPERTY(remote-address,	remote_addr, RO),
	TUNNEL_UINT16_PROPERTY(ttl, ttl, RO),
	TUNNEL_UINT16_PROPERTY(tos, tos, RO),
	TUNNEL_BOOL_PROPERTY(pmtudisc, pmtudisc, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_tunnel_methods[] = {
	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_tunnel_service = {
	.name			= NI_OBJECTMODEL_TUNNEL_INTERFACE,
	.methods		= ni_objectmodel_tunnel_methods,
	.properties		= ni_objectmodel_tunnel_property_table,
};

/*
 * tunnel (ipip) factory service
 */
static ni_dbus_method_t		ni_objectmodel_tunnel_factory_methods[] = {
	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_tunnel_factory_service = {
	.name			= NI_OBJECTMODEL_TUNNEL_INTERFACE ".Factory",
	.methods		= ni_objectmodel_tunnel_factory_methods,
};
