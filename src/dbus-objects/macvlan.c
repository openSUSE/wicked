/*
 *	DBus encapsulation for macvlan/macvtap interfaces.
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
#include <wicked/macvlan.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"


static ni_netdev_t *	__ni_objectmodel_macvlan_newlink(ni_netdev_t *, const char *, DBusError *);
static dbus_bool_t	__ni_objectmodel_macvlan_change(ni_netdev_t *, ni_netdev_t *, DBusError *);
static dbus_bool_t	__ni_objectmodel_macvlan_delete(ni_dbus_object_t *, const ni_dbus_method_t *,
						unsigned int, const ni_dbus_variant_t *,
						ni_dbus_message_t *, DBusError *);

/*
 * Return an interface handle containing all macvlan-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_macvlan_device_arg(const ni_dbus_variant_t *dict, unsigned int iftype)
{
	return ni_objectmodel_get_netif_argument(dict, iftype,
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
	if (!ni_dbus_variant_get_string(&argv[0], &ifname) ||
		!(dev = __ni_objectmodel_macvlan_device_arg(&argv[1], NI_IFTYPE_MACVLAN))) {
		return ni_dbus_error_invalid_args(error,
						factory_object->path,
						method->name);
	}

	if (!(dev = __ni_objectmodel_macvlan_newlink(dev, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

dbus_bool_t
ni_objectmodel_macvtap_newlink(ni_dbus_object_t *factory_object,
			const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *dev;
	const char *ifname = NULL;

	NI_TRACE_ENTER();

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname) ||
		!(dev = __ni_objectmodel_macvlan_device_arg(&argv[1], NI_IFTYPE_MACVTAP))) {
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
	ni_netdev_t *dev_ifp = NULL;
	const ni_macvlan_t *macvlan;
	const char *err;
	const char *cfg_ifp_iftype = NULL;
	int rv;

	cfg_ifp_iftype = ni_linktype_type_to_name(cfg_ifp->link.type);

	if (ni_string_empty(cfg_ifp->link.lowerdev.name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Incomplete arguments: need a lower device name");
		return NULL;
	} else
	if (!ni_netdev_ref_bind_ifindex(&cfg_ifp->link.lowerdev, nc)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
			"Unable to find %s lower device %s by name",
			cfg_ifp_iftype,
			cfg_ifp->link.lowerdev.name);
		return NULL;
	}

	macvlan = ni_netdev_get_macvlan(cfg_ifp);
	if ((err = ni_macvlan_validate(macvlan))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		goto out;
	}

	if (ni_string_empty(ifname)) {
		if (ni_string_empty(cfg_ifp->name) &&
			(ifname = ni_netdev_make_name(
				nc,
				cfg_ifp_iftype,
				0))) {
			ni_string_dup(&cfg_ifp->name, ifname);
		} else {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to create %s interface: "
				"name argument missed",
				cfg_ifp_iftype);
			goto out;
		}
		ifname = NULL;
	} else if(!ni_string_eq(cfg_ifp->name, ifname)) {
		ni_string_dup(&cfg_ifp->name, ifname);
	}
	if (ni_string_eq(cfg_ifp->name, cfg_ifp->link.lowerdev.name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
			"Cannot create %s interface: "
			"macvlan name %s equal with lower device name",
			cfg_ifp_iftype,
			cfg_ifp->name);
		return NULL;
	}

	if (cfg_ifp->link.hwaddr.len) {
		if (cfg_ifp->link.hwaddr.type == ARPHRD_VOID)
			cfg_ifp->link.hwaddr.type = ARPHRD_ETHER;
		if (cfg_ifp->link.hwaddr.type != ARPHRD_ETHER ||
		    cfg_ifp->link.hwaddr.len != ni_link_address_length(ARPHRD_ETHER)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot create %s interface: "
				"invalid ethernet address '%s'",
				cfg_ifp_iftype,
				ni_link_address_print(&cfg_ifp->link.hwaddr));
			return NULL;
		}
	}

	if ((rv = ni_system_macvlan_create(nc, cfg_ifp, &dev_ifp)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || dev_ifp == NULL
		|| (ifname && dev_ifp && !ni_string_eq(dev_ifp->name, ifname))) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Unable to create %s interface: %s",
				cfg_ifp_iftype,
				ni_strerror(rv));
			dev_ifp = NULL;
			goto out;
		}
		ni_debug_dbus("%s interface exists (and name matches)",
			cfg_ifp_iftype);
	}

	if (dev_ifp->link.type != cfg_ifp->link.type) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create %s interface: "
				"new interface is of type %s",
			cfg_ifp_iftype,
			ni_linktype_type_to_name(dev_ifp->link.type));
		dev_ifp = NULL;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return dev_ifp;
}

static dbus_bool_t
ni_objectmodel_macvlan_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev, *cfg;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)) ||
		!(cfg = __ni_objectmodel_macvlan_device_arg(&argv[0], NI_IFTYPE_MACVLAN)) ||
		!(ni_netdev_get_macvlan(dev))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		return FALSE;
	}

	return __ni_objectmodel_macvlan_change(cfg, dev, error);
}

static dbus_bool_t
ni_objectmodel_macvtap_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev, *cfg;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)) ||
		!(cfg = __ni_objectmodel_macvlan_device_arg(&argv[0], NI_IFTYPE_MACVTAP)) ||
		!(ni_netdev_get_macvlan(dev))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		return FALSE;
	}

	return __ni_objectmodel_macvlan_change(cfg, dev, error);
}

/*
 * Change a macvlan/macvtap interface
 */
static dbus_bool_t
__ni_objectmodel_macvlan_change(ni_netdev_t *cfg, ni_netdev_t *dev, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	const char *err;
	ni_macvlan_t *macvlan;
	const char *dev_iftype = NULL;

	macvlan = ni_netdev_get_macvlan(cfg);
	if ((err = ni_macvlan_validate(macvlan))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		return FALSE;
	}

	if ((cfg->link.lowerdev.index &&
	     (cfg->link.lowerdev.index != dev->link.lowerdev.index)) ||
	    (cfg->link.lowerdev.name &&
	     !ni_string_eq(cfg->link.lowerdev.name, dev->link.lowerdev.name))) {
		const char *cfg_iftype = ni_linktype_type_to_name(cfg->link.type);

		if (cfg->link.lowerdev.name) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot change %s lower device to %s",
				cfg_iftype, cfg->link.lowerdev.name);
		} else {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot change %s lower device to %u",
				cfg_iftype, cfg->link.lowerdev.index);
		}
		return FALSE;
	}
	cfg->link.lowerdev.index = dev->link.lowerdev.index;
	ni_string_dup(&cfg->link.lowerdev.name, dev->link.lowerdev.name);

	cfg->link.ifindex = dev->link.ifindex;
	if (ni_string_empty(cfg->name))
		ni_string_dup(&cfg->name, dev->name);

	dev_iftype = ni_linktype_type_to_name(dev->link.type);

	if (!macvlan->mode) {
		macvlan->mode = dev->macvlan->mode;
	} else
	if ((macvlan->mode == NI_MACVLAN_MODE_PASSTHRU) !=
	    (dev->macvlan->mode == NI_MACVLAN_MODE_PASSTHRU)) {
		/* Passthrough mode can't be set or cleared dynamically */
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot change %s mode to %s",
			dev_iftype,
			ni_macvlan_mode_to_name(macvlan->mode));
		return FALSE;
	}

	if (ni_netdev_device_is_up(dev)) {
		ni_debug_objectmodel("Skipping %s changeDevice call on %s: "
				"device is up", dev_iftype, dev->name);
		return TRUE;
	}

	if (ni_system_macvlan_change(nc, dev, cfg) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to change %s properties on interface %s",
			dev_iftype, dev->name);
		return FALSE;
	}

	if (cfg->link.hwaddr.type == ARPHRD_VOID)
		cfg->link.hwaddr.type = ARPHRD_ETHER;
	if (!ni_link_address_is_invalid(&cfg->link.hwaddr) &&
	    ni_system_hwaddr_change(nc, dev, &cfg->link.hwaddr) < 0) {
		ni_error("Unable to change hwaddr on %s interface %s",
			dev_iftype, dev->name);
		/* fail? */
	}

	return TRUE;
}

/*
 * Delete a macvlan/macvtap interface
 */
static dbus_bool_t
ni_objectmodel_macvlan_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return __ni_objectmodel_macvlan_delete(object, method, argc,
					argv, reply, error);
}

static dbus_bool_t
ni_objectmodel_macvtap_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return __ni_objectmodel_macvlan_delete(object, method, argc,
					argv, reply, error);
}

static dbus_bool_t
__ni_objectmodel_macvlan_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
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

	ni_client_state_drop(dev->link.ifindex);
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

static dbus_bool_t
__ni_objectmodel_macvlan_get_address(const ni_dbus_object_t *object,
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
__ni_objectmodel_macvlan_set_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr);
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

/* MACVLAN Properties and Methods */
#define	MACVLAN_PROPERTY_SIGNATURE(signature, dbus_name, rw) \
		__NI_DBUS_PROPERTY(signature, dbus_name, __ni_objectmodel_macvlan, rw)
#define MACVLAN_UINT32_PROPERTY(dbus_name, rw) \
		MACVLAN_PROPERTY_SIGNATURE(DBUS_TYPE_UINT32_AS_STRING, dbus_name, rw)
#define MACVLAN_UINT16_PROPERTY(dbus_name, rw) \
		MACVLAN_PROPERTY_SIGNATURE(DBUS_TYPE_UINT16_AS_STRING, dbus_name, rw)
#define MACVLAN_HWADDR_PROPERTY(dbus_name, rw) \
		__NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
				dbus_name, __ni_objectmodel_macvlan, rw)

const ni_dbus_property_t	ni_objectmodel_macvlan_property_table[] = {
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev,  device, link.lowerdev.name, RO),
	MACVLAN_HWADDR_PROPERTY(address, RO),
	MACVLAN_UINT32_PROPERTY(mode, RO),
	MACVLAN_UINT16_PROPERTY(flags, RO),
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_macvlan_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_macvlan_change },
	{ "deleteDevice",	"",		.handler = ni_objectmodel_macvlan_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_macvlan_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_macvlan_newlink },

	{ NULL }
};

/* MACVTAP Methods */
static ni_dbus_method_t		ni_objectmodel_macvtap_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_macvtap_change },
	{ "deleteDevice",	"",		.handler = ni_objectmodel_macvtap_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_macvtap_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_macvtap_newlink },

	{ NULL }
};

/* MACVLAN Service */
ni_dbus_service_t	ni_objectmodel_macvlan_factory_service = {
	.name		= NI_OBJECTMODEL_MACVLAN_INTERFACE ".Factory",
	.methods	= ni_objectmodel_macvlan_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_macvlan_service = {
	.name		= NI_OBJECTMODEL_MACVLAN_INTERFACE,
	.methods	= ni_objectmodel_macvlan_methods,
	.properties	= ni_objectmodel_macvlan_property_table,
};

/* MACVTAP Service */
ni_dbus_service_t	ni_objectmodel_macvtap_factory_service = {
	.name		= NI_OBJECTMODEL_MACVTAP_INTERFACE ".Factory",
	.methods	= ni_objectmodel_macvtap_factory_methods,
};

/* We re-use the macvlan_property_table. */
ni_dbus_service_t	ni_objectmodel_macvtap_service = {
	.name		= NI_OBJECTMODEL_MACVTAP_INTERFACE,
	.methods	= ni_objectmodel_macvtap_methods,
	.properties	= ni_objectmodel_macvlan_property_table,
};
