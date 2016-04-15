/*
 *	DBus encapsulation for gre interfaces.
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

static ni_netdev_t *	__ni_objectmodel_gre_create(ni_netdev_t *, const char *, DBusError *);

static inline ni_netdev_t *
__ni_objectmodel_gre_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_GRE,
					&ni_objectmodel_gre_service);
}

static ni_netdev_t *
__ni_objectmodel_gre_create(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_gre_t *gre = NULL;
	ni_netdev_t *dev = NULL;
	const char *err = NULL;
	int rv;

	gre = ni_netdev_get_gre(cfg_ifp);
	if ((err = ni_gre_validate(gre))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		goto out;
	}

	if (ni_string_empty(ifname)) {
		if (ni_string_empty(cfg_ifp->name) &&
			(ifname = ni_netdev_make_name(nc, "gre", 1))) {
			ni_string_dup(&cfg_ifp->name, ifname);
		} else {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to create gre tunnel: "
				"name argument missed");
			goto out;
		}
		ifname = NULL;
	} else if(!ni_string_eq(cfg_ifp->name, ifname)) {
		ni_string_dup(&cfg_ifp->name, ifname);
	}

	if (!ni_string_empty(cfg_ifp->link.lowerdev.name) &&
	    !ni_objectmodel_bind_netdev_ref_index(cfg_ifp->name, "gre tunnel",
					&cfg_ifp->link.lowerdev, nc, error))
		goto out;

	if (cfg_ifp->link.hwaddr.len) {
		if (cfg_ifp->link.hwaddr.type == ARPHRD_VOID)
			cfg_ifp->link.hwaddr.type = ARPHRD_IPGRE;

		if (cfg_ifp->link.hwaddr.type != ARPHRD_IPGRE ||
		    cfg_ifp->link.hwaddr.len != ni_link_address_length(ARPHRD_IPGRE)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot create gre tunnel interface: "
				"invalid local address '%s'",
				ni_link_address_print(&cfg_ifp->link.hwaddr));
			return NULL;
		}
	}

	if (cfg_ifp->link.hwpeer.len) {
		if (cfg_ifp->link.hwpeer.type == ARPHRD_VOID)
			cfg_ifp->link.hwpeer.type = ARPHRD_IPGRE;

		if (cfg_ifp->link.hwpeer.type != ARPHRD_IPGRE ||
		    cfg_ifp->link.hwpeer.len != ni_link_address_length(ARPHRD_IPGRE)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot create gre tunnel interface: "
				"invalid remote address '%s'",
				ni_link_address_print(&cfg_ifp->link.hwpeer));
			return NULL;
		}
	}

	if ((rv = ni_system_tunnel_create(nc, cfg_ifp, &dev, NI_IFTYPE_GRE) < 0)) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || dev == NULL
			|| (ifname && dev && !ni_string_eq(dev->name, ifname))) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create gre tunnel: %s");
			dev = NULL;
			goto out;
		}
		ni_debug_dbus("gre tunnel exists (and name matches)");
	}

	if (dev->link.type != NI_IFTYPE_GRE) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Unable to create gre tunnel: "
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
ni_objectmodel_gre_create(ni_dbus_object_t *factory_object,
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
		||  !(dev = __ni_objectmodel_gre_device_arg(&argv[1]))) {
		return ni_dbus_error_invalid_args(error,
						factory_object->path, method->name);
	}

	if (!(dev = __ni_objectmodel_gre_create(dev, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

static dbus_bool_t
ni_objectmodel_gre_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev, *cfg;
	ni_gre_t *gre;
	const char *err;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)) ||
		!(cfg = __ni_objectmodel_gre_device_arg(&argv[0])) ||
		!(ni_netdev_get_gre(dev))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		return FALSE;
	}

	gre = ni_netdev_get_gre(cfg);
	if ((err = ni_gre_validate(gre))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		return FALSE;
	}

	cfg->link.ifindex = dev->link.ifindex;
	if (ni_string_empty(cfg->name))
		ni_string_dup(&cfg->name, dev->name);

	if (ni_netdev_device_is_up(dev)) {
		ni_debug_objectmodel("Skipping gre changeDevice call on %s: "
				"device is up", dev->name);
		return TRUE;
	}

	if (!ni_string_empty(cfg->link.lowerdev.name) &&
	    !ni_objectmodel_bind_netdev_ref_index(cfg->name, "gre tunnel",
					&cfg->link.lowerdev, nc, error))
		return FALSE;

	if (ni_system_tunnel_change(nc, dev, cfg) < 0) {
		dbus_set_error(error,
			DBUS_ERROR_FAILED,
			"Unable to change gre properties on interface %s",
			dev->name);
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_gre_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if ((rv = ni_system_tunnel_delete(dev, NI_IFTYPE_GRE) < 0)) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error deleting gre tunnel %s: %s",
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
 * Currently only used to pull gre->tunnel data below, but kept around for later expansion.
 */
static ni_gre_t *
ni_objectmodel_get_gre(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_gre_t *gre;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->gre;

	if (!(gre = ni_netdev_get_gre(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error getting gre handle for interface");
		return NULL;
	}

	return gre;
}

static void *
ni_objectmodel_get_tunnel(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_tunnel_t *tunnel = NULL;
	ni_gre_t *gre;

	if ((gre = ni_objectmodel_get_gre(object, write_access, error)))
		tunnel = &gre->tunnel;

	return tunnel;
}

static dbus_bool_t
__ni_objectmodel_gre_get_local_addr(const ni_dbus_object_t *object,
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
__ni_objectmodel_gre_set_local_addr(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (__ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr)) {
		dev->link.hwaddr.type = ARPHRD_IPGRE;
		return TRUE;
	} else {
		return FALSE;
	}
}

static dbus_bool_t
__ni_objectmodel_gre_get_remote_addr(const ni_dbus_object_t *object,
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
__ni_objectmodel_gre_set_remote_addr(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (__ni_objectmodel_set_hwaddr(argument, &dev->link.hwpeer)) {
		dev->link.hwpeer.type = ARPHRD_IPGRE;
		return TRUE;
	} else {
		return FALSE;
	}
}

static dbus_bool_t
__ni_objectmodel_gre_get_flags(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	uint32_t flags = 0;
	ni_gre_t *gre;

	if (!(gre = ni_objectmodel_get_gre(object, FALSE, error)))
		return FALSE;

	flags = gre->flags & ~(NI_BIT(NI_GRE_FLAG_IKEY)|NI_BIT(NI_GRE_FLAG_OKEY));
	if (!flags)
		return FALSE;

	ni_dbus_variant_set_uint32(result, flags);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_gre_set_flags(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	uint32_t flags = 0;
	ni_gre_t *gre;

	if (!(gre = ni_objectmodel_get_gre(object, TRUE, error)))
		return FALSE;

	gre->flags &= (NI_BIT(NI_GRE_FLAG_IKEY)|NI_BIT(NI_GRE_FLAG_OKEY));
	if (!ni_dbus_variant_get_uint32(argument, &flags))
		return FALSE;

	gre->flags |= flags;
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_gre_get_ikey(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_gre_t *gre;

	if (!(gre = ni_objectmodel_get_gre(object, FALSE, error)))
		return FALSE;

	if (!(gre->flags & NI_BIT(NI_GRE_FLAG_IKEY)))
		return FALSE;

	ni_dbus_variant_set_byte_array(result, (unsigned char *)&gre->ikey, sizeof(gre->ikey));
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_gre_get_okey(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_gre_t *gre;

	if (!(gre = ni_objectmodel_get_gre(object, FALSE, error)))
		return FALSE;

	if (!(gre->flags & NI_BIT(NI_GRE_FLAG_OKEY)))
		return FALSE;

	ni_dbus_variant_set_byte_array(result, (unsigned char *)&gre->okey, sizeof(gre->okey));
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_gre_set_ikey(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	unsigned int len;
	ni_gre_t *gre;

	if (!(gre = ni_objectmodel_get_gre(object, TRUE, error)))
		return FALSE;

	len = sizeof(gre->ikey);
	gre->flags &= ~NI_BIT(NI_GRE_FLAG_IKEY);
	if (!ni_dbus_variant_get_byte_array_minmax(argument,
				(unsigned char *)&gre->ikey, &len, len, len))
		return FALSE;

	gre->flags |= NI_BIT(NI_GRE_FLAG_IKEY);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_gre_set_okey(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	unsigned int len;
	ni_gre_t *gre;

	if (!(gre = ni_objectmodel_get_gre(object, TRUE, error)))
		return FALSE;

	len = sizeof(gre->okey);
	gre->flags &= ~NI_BIT(NI_GRE_FLAG_OKEY);
	if (!ni_dbus_variant_get_byte_array_minmax(argument,
				(unsigned char *)&gre->okey, &len, len, len))
		return FALSE;

	gre->flags |= NI_BIT(NI_GRE_FLAG_OKEY);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_gre_get_encap(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_gre_t *gre;

	if (!(gre = ni_objectmodel_get_gre(object, FALSE, error)))
		return FALSE;

	if (gre->encap.type == NI_GRE_ENCAP_TYPE_NONE)
		return FALSE;

	ni_dbus_dict_add_uint16(result, "type",  gre->encap.type);
	ni_dbus_dict_add_uint16(result, "flags", gre->encap.flags);
	ni_dbus_dict_add_uint16(result, "sport", gre->encap.sport);
	ni_dbus_dict_add_uint16(result, "dport", gre->encap.dport);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_gre_set_encap(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_gre_t *gre;

	if (!(gre = ni_objectmodel_get_gre(object, TRUE, error)))
		return FALSE;

	memset(&gre->encap, 0, sizeof(gre->encap));
	ni_dbus_dict_get_uint16(argument, "type", &gre->encap.type);
	if (gre->encap.type != NI_GRE_ENCAP_TYPE_FOU &&
	    gre->encap.type != NI_GRE_ENCAP_TYPE_GUE)
		return FALSE;

	ni_dbus_dict_get_uint16(argument, "flags", &gre->encap.flags);
	ni_dbus_dict_get_uint16(argument, "sport", &gre->encap.sport);
	ni_dbus_dict_get_uint16(argument, "dport", &gre->encap.dport);
	return TRUE;
}

static void *
ni_objectmodel_get_netdev(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_netif(object, error);
}

/*
 * Property helper macros
 */
#define GRE_HWADDR_PROPERTY(dbus_name, suffix, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
				dbus_name, suffix, __ni_objectmodel_gre, rw)
#define GRE_IPV4_ADDR_PROPERTY(dbus_name, suffix, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
				dbus_name, suffix, __ni_objectmodel_gre, rw)
#define GRE_FLAGS_UINT32_PROPERTY(dbus_name, suffix, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_UINT32_AS_STRING, \
				dbus_name, suffix, __ni_objectmodel_gre, rw)
#define GRE_ENCAP_DICT_PROPERTY(dbus_name, suffix, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, \
				dbus_name, suffix, __ni_objectmodel_gre, rw)

#define GRE_TUNNEL_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(tunnel, dbus_type, type, rw)
#define GRE_TUNNEL_BOOL_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(tunnel, dbus_type, type, rw)

/*
 * gre tunnel service
 */
static const ni_dbus_property_t	ni_objectmodel_gre_property_table[] = {
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev, device, link.lowerdev.name, RO),
	GRE_HWADDR_PROPERTY(local-address,	local_addr, RO),
	GRE_HWADDR_PROPERTY(remote-address,	remote_addr, RO),
	GRE_TUNNEL_UINT16_PROPERTY(ttl,		ttl, RO),
	GRE_TUNNEL_UINT16_PROPERTY(tos,		tos, RO),
	GRE_TUNNEL_BOOL_PROPERTY(pmtudisc,	pmtudisc, RO),
	GRE_FLAGS_UINT32_PROPERTY(flags,	flags, RO),
	GRE_IPV4_ADDR_PROPERTY(ikey,		ikey, RO),
	GRE_IPV4_ADDR_PROPERTY(okey,		okey, RO),
	GRE_ENCAP_DICT_PROPERTY(encap,		encap, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_gre_methods[] = {
	{ "changeDevice",	"a{sv}",	ni_objectmodel_gre_change },
	{ "deleteDevice",	"",		ni_objectmodel_gre_delete },

	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_gre_service = {
	.name			= NI_OBJECTMODEL_GRE_INTERFACE,
	.methods		= ni_objectmodel_gre_methods,
	.properties		= ni_objectmodel_gre_property_table,
};

/*
 * gre tunnel factory service
 */
static ni_dbus_method_t		ni_objectmodel_gre_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	ni_objectmodel_gre_create },

	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_gre_factory_service = {
	.name			= NI_OBJECTMODEL_GRE_INTERFACE ".Factory",
	.methods		= ni_objectmodel_gre_factory_methods,
};
