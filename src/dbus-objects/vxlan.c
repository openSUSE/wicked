/*
 *	DBus encapsulation for VXLAN interfaces
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/vxlan.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"
#include "misc.h"

/*
 * Return an interface handle containing all vxlan-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
ni_objectmodel_vxlan_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_VXLAN, &ni_objectmodel_vxlan_service);
}

/*
 * Create a new vxlan interface
 */
static ni_netdev_t *
ni_objectmodel_vxlan_create(ni_netdev_t *cfg, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev = NULL;
	ni_vxlan_t *vxlan;
	const char *iftype;
	const char *err;
	int rv;

	iftype = ni_linktype_type_to_name(cfg->link.type);
	if (!iftype || !(vxlan = ni_netdev_get_vxlan(cfg)))
		goto out;

	if (ni_string_empty(ifname)) {
		if ((ifname = ni_netdev_make_name(nc, iftype, 0))) {
			ni_string_dup(&cfg->name, ifname);
		} else {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to create %s interface: "
				"name argument missed", iftype);
			goto out;
		}
		ifname = cfg->name;
	} else
	if (ni_netdev_name_is_valid(ifname) != NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to create %s interface: "
				"invalid interface name '%s'",
				iftype, ni_print_suspect(ifname, 15));
		goto out;
	} else
	if(!ni_string_eq(cfg->name, ifname)) {
		ni_string_dup(&cfg->name, ifname);
	}

	if (!ni_string_empty(cfg->link.lowerdev.name) &&
	    !ni_objectmodel_bind_netdev_ref_index(cfg->name, "vxlan link",
	    				&cfg->link.lowerdev, nc, error))
		goto out;

	if (cfg->link.hwaddr.len) {
		if (cfg->link.hwaddr.type == ARPHRD_VOID)
			cfg->link.hwaddr.type = ARPHRD_ETHER;
		if (cfg->link.hwaddr.type != ARPHRD_ETHER ||
		    cfg->link.hwaddr.len != ni_link_address_length(ARPHRD_ETHER) ||
		    ni_link_address_is_invalid(&cfg->link.hwaddr)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot create %s interface: "
				"invalid ethernet address '%s'",
				iftype, ni_link_address_print(&cfg->link.hwaddr));
			goto out;
		}
	}

	if ((err = ni_vxlan_validate(vxlan, &cfg->link.lowerdev))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: Cannot create %s interface: %s",
				ifname, iftype, err);
		goto out;
	}

	if ((rv = ni_system_vxlan_create(nc, cfg, &dev)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || dev == NULL
		|| (ifname && dev && !ni_string_eq(dev->name, ifname))) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create %s interface: %s",
				iftype, ni_strerror(rv));
			dev = NULL;
			goto out;
		}
		ni_debug_dbus("%s interface %s exists (and name matches)",
				iftype, ifname);
	}

	if (dev->link.type != cfg->link.type) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create %s interface: "
				"new interface is of type %s",
			iftype, ni_linktype_type_to_name(dev->link.type));
		dev = NULL;
	}

out:
	return dev;
}

static dbus_bool_t
ni_objectmodel_vxlan_newlink(ni_dbus_object_t *factory, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory);
	const char *ifname = NULL;
	ni_netdev_t *dev, *cfg;

	NI_TRACE_ENTER();

	ni_assert(argc == 2); /* we already verified that signature matches */
	if (!ni_dbus_variant_get_string(&argv[0], &ifname) ||
	    !(cfg = ni_objectmodel_vxlan_device_arg(&argv[1]))) {
		return ni_dbus_error_invalid_args(error, factory->path, method->name);
	}

	dev = ni_objectmodel_vxlan_create(cfg, ifname, error);
	ni_netdev_put(cfg);
	if (!dev)
		return FALSE;
	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

static dbus_bool_t
ni_objectmodel_vxlan_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev, *cfg = NULL;
	dbus_bool_t result = FALSE;
	const char *iftype;
	ni_vxlan_t *vxlan;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);
	if (!(dev = ni_objectmodel_unwrap_netif(object, error)) ||
	    !ni_netdev_get_vxlan(dev) ||
	    !(cfg = ni_objectmodel_vxlan_device_arg(&argv[0])))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	if (!(vxlan = ni_netdev_get_vxlan(cfg))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	cfg->link.ifindex = dev->link.ifindex;
	iftype = ni_linktype_type_to_name(cfg->link.type);
	if (ni_string_empty(cfg->name))
		ni_string_dup(&cfg->name, dev->name);
	else
	if (ni_netdev_name_is_valid(cfg->name) != NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to rename %s interface '%s': "
				"invalid interface name '%s'",
				iftype, dev->name,
				ni_print_suspect(cfg->name, 15));
		goto out;
	}

	if (!ni_string_empty(cfg->link.lowerdev.name) &&
	    !ni_objectmodel_bind_netdev_ref_index(cfg->name, "vxlan link",
	    				&cfg->link.lowerdev, nc, error))
		goto out;
	else
		ni_netdev_ref_set(&cfg->link.lowerdev,
				dev->link.lowerdev.name, dev->link.lowerdev.index);

	if (cfg->link.hwaddr.len) {
		if (cfg->link.hwaddr.type == ARPHRD_VOID)
			cfg->link.hwaddr.type = ARPHRD_ETHER;
		if (cfg->link.hwaddr.type != ARPHRD_ETHER ||
		    cfg->link.hwaddr.len != ni_link_address_length(ARPHRD_ETHER) ||
		    ni_link_address_is_invalid(&cfg->link.hwaddr)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot create %s interface: "
				"invalid ethernet address '%s'",
				iftype, ni_link_address_print(&cfg->link.hwaddr));
			goto out;
		}
		if (ni_system_hwaddr_change(nc, dev, &cfg->link.hwaddr) < 0) {
			ni_error("%s: unable to change %s interface hw-address",
					dev->name, iftype);
		}
		ni_link_address_init(&cfg->link.hwaddr);
	}

	/* currently just useless as we change mac separately
	 * and vxlan does not support vxlan property changes */
#if 0
	if ((err = ni_vxlan_validate(vxlan, &cfg->link.lowerdev))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: Cannot change %s interface: %s",
				ifname, iftype, err);
		goto out;
	}
#endif
	if (ni_system_vxlan_change(nc, dev, cfg) < 0) {
		dbus_set_error(error,
			DBUS_ERROR_FAILED,
			"Unable to change %s properties on interface %s",
			iftype, dev->name);
		goto out;
	}

	result = TRUE;

out:
	ni_netdev_put(cfg);
	return result;
}

/*
 * Delete a vxlan interface
 */
static dbus_bool_t
ni_objectmodel_vxlan_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if ((rv = ni_system_vxlan_delete(dev)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error deleting vxlan interface %s: %s",
			dev->name, ni_strerror(rv));
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}

/*
 * Helper function to obtain vxlan interface properties from/into dbus object
 */
static void *
ni_objectmodel_get_netdev(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_netif(object, error);
}

static dbus_bool_t
ni_objectmodel_netdev_get_address(const ni_dbus_object_t *object,
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
ni_objectmodel_netdev_set_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr);
}

static ni_vxlan_t *
ni_objectmodel_vxlan_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_vxlan_t *vxlan;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->vxlan;

	if (!(vxlan = ni_netdev_get_vxlan(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error getting vxlan handle for interface");
		return NULL;
	}
	return vxlan;
}

static void *
ni_objectmodel_get_vxlan(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_vxlan_handle(object, write_access, error);
}

static dbus_bool_t
ni_objectmodel_vxlan_get_local_ip(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_vxlan_t *vxlan;

	if (!(vxlan = ni_objectmodel_vxlan_handle(object, FALSE, error)))
		return FALSE;

	return __ni_objectmodel_set_sockaddr(result, &vxlan->local_ip);
}

static dbus_bool_t
ni_objectmodel_vxlan_set_local_ip(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_vxlan_t *vxlan;

	if (!(vxlan = ni_objectmodel_vxlan_handle(object, TRUE, error)))
		return FALSE;

	return __ni_objectmodel_get_sockaddr(argument, &vxlan->local_ip);
}

static dbus_bool_t
ni_objectmodel_vxlan_get_remote_ip(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_vxlan_t *vxlan;

	if (!(vxlan = ni_objectmodel_vxlan_handle(object, FALSE, error)))
		return FALSE;

	return __ni_objectmodel_set_sockaddr(result, &vxlan->remote_ip);
}

static dbus_bool_t
ni_objectmodel_vxlan_set_remote_ip(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_vxlan_t *vxlan;

	if (!(vxlan = ni_objectmodel_vxlan_handle(object, TRUE, error)))
		return FALSE;

	return __ni_objectmodel_get_sockaddr(argument, &vxlan->remote_ip);
}

static dbus_bool_t
ni_objectmodel_vxlan_get_src_port(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_vxlan_t *vxlan;

	if (!(vxlan = ni_objectmodel_vxlan_handle(object, FALSE, error)))
		return FALSE;

	if (vxlan->src_port.low || vxlan->src_port.high) {
		ni_dbus_variant_init_dict(result);
		if (!ni_dbus_dict_add_uint32(result, "low",  vxlan->src_port.low))
			return FALSE;
		if (!ni_dbus_dict_add_uint32(result, "high", vxlan->src_port.high))
			return FALSE;
		return TRUE;
	}
	return ni_dbus_error_property_not_present(error, object->path, property->name);
}

static dbus_bool_t
ni_objectmodel_vxlan_set_src_port(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_vxlan_t *vxlan;

	if (!(vxlan = ni_objectmodel_vxlan_handle(object, TRUE, error)))
		return FALSE;

	if (!ni_dbus_dict_get_uint16(argument, "low",  &vxlan->src_port.low))
		vxlan->src_port.low  = 0;
	if (!ni_dbus_dict_get_uint16(argument, "high", &vxlan->src_port.high))
		vxlan->src_port.high = 0;
	return TRUE;
}

/* vxlan property macros */
#define DEVICE_HWADDR_PROPERTY(type, dbus_name, rw) \
	__NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
				dbus_name, ni_objectmodel_##type, rw)
#define VXLAN_IPADDR_PROPERTY(type, dbus_name, member_name, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
				dbus_name, member_name, ni_objectmodel_##type, rw)
#define VXLAN_DICT_PROPERTY(type, dbus_name, member_name, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, dbus_name, \
				member_name, ni_objectmodel_##type, rw)
#define VXLAN_UINT32_PROPERTY(type, dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT32_PROPERTY(type, dbus_name, member_name, rw)
#define VXLAN_UINT16_PROPERTY(type, dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(vxlan, dbus_name, member_name, rw)
#define VXLAN_BOOL_PROPERTY(type, dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(type, dbus_name, member_name, rw)
#define VXLAN_DEVICE_PROPERTY(type, dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(type, dbus_name, member_name, rw)


/* VXLAN property table */
const ni_dbus_property_t	ni_objectmodel_vxlan_property_table[] = {
	DEVICE_HWADDR_PROPERTY(netdev, address,	RO),
	VXLAN_DEVICE_PROPERTY (netdev, device,			link.lowerdev.name, RO),
	VXLAN_UINT32_PROPERTY (vxlan, id,			id, RO),
	VXLAN_IPADDR_PROPERTY (vxlan, local-ip,			local_ip,  RO),
	VXLAN_IPADDR_PROPERTY (vxlan, remote-ip,		remote_ip, RO),
	VXLAN_DICT_PROPERTY   (vxlan, src-port,			src_port, RO),
	VXLAN_UINT16_PROPERTY (vxlan, dst-port,			dst_port, RO),
	VXLAN_UINT16_PROPERTY (vxlan, ttl,			ttl, RO),
	VXLAN_UINT16_PROPERTY (vxlan, tos,			tos, RO),
	VXLAN_UINT32_PROPERTY (vxlan, ageing,			ageing, RO),
	VXLAN_UINT32_PROPERTY (vxlan, max-address,		maxaddr, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, learning,			learning, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, proxy,			proxy, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, rsc,			rsc, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, l2miss,			l2miss, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, l3miss,			l3miss, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, udp-csum,			udp_csum, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, udp6-zero-csum-rx,	udp6_zero_csum_rx, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, udp6-zero-csum-tx,	udp6_zero_csum_tx, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, rem-csum-rx,		rem_csum_rx, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, rem-csum-tx,		rem_csum_tx, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, rem-csum-partial, 	rem_csum_partial, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, collect-metadata,		collect_metadata, RO),
	VXLAN_BOOL_PROPERTY   (vxlan, gbp,			gbp, RO),
#if 0
	VXLAN_BOOL_PROPERTY   (vxlan, gpe,			gpe, RO),
#endif
	{ NULL }
};

/* VXLAN method tables */
static ni_dbus_method_t		ni_objectmodel_vxlan_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_vxlan_change },
	{ "deleteDevice",	"",		.handler = ni_objectmodel_vxlan_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_vxlan_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_vxlan_newlink },

	{ NULL }
};

/* VXLAN service */
ni_dbus_service_t	ni_objectmodel_vxlan_factory_service = {
	.name		= NI_OBJECTMODEL_VXLAN_INTERFACE ".Factory",
	.methods	= ni_objectmodel_vxlan_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_vxlan_service = {
	.name		= NI_OBJECTMODEL_VXLAN_INTERFACE,
	.methods	= ni_objectmodel_vxlan_methods,
	.properties	= ni_objectmodel_vxlan_property_table,
};

