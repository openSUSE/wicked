/*
 *	DBus encapsulation for tun/tap interfaces
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
 *		Marius Tomaschewski <mt@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/tuntap.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"

/*
 * Create a new TUN/TAP interface
 */
static ni_netdev_t *
__ni_objectmodel_tuntap_create(ni_netdev_t *cfg, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev = NULL;
	const char *iftype;
	const ni_tuntap_t *tuntap;
	const char *err;
	int rv;

	iftype = ni_linktype_type_to_name(cfg->link.type);
	if (cfg->link.type != NI_IFTYPE_TUN && cfg->link.type != NI_IFTYPE_TAP) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
			"BUG: Cannot handle %s type in tun/tap factory", iftype);
		return NULL;
	}

	ni_debug_dbus("%s.newDevice(name=%s)", iftype, cfg->name);
	tuntap = ni_netdev_get_tuntap(cfg);
	if ((err = ni_tuntap_validate(tuntap))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		return NULL;
	}

	if (ni_string_empty(cfg->name)) {
		if (ni_string_empty(cfg->name) &&
		    (cfg->name = (char *) ni_netdev_make_name(nc, iftype, 0))) {
			ni_string_dup(&cfg->name, cfg->name);
		} else {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to create %s interface: "
				"name argument missed", iftype);
			return NULL;
		}
		cfg->name = NULL;
	} else if(!ni_string_eq(cfg->name, cfg->name)) {
		ni_string_dup(&cfg->name, cfg->name);
	}

	if (cfg->link.type == NI_IFTYPE_TAP && cfg->link.hwaddr.len) {
		if (cfg->link.hwaddr.type == ARPHRD_VOID)
			cfg->link.hwaddr.type = ARPHRD_ETHER;

		if (cfg->link.hwaddr.type != ARPHRD_ETHER
		||  cfg->link.hwaddr.len != ni_link_address_length(ARPHRD_ETHER)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"Cannot create %s interface: "
					"invalid ethernet address '%s'", iftype,
					ni_link_address_print(&cfg->link.hwaddr));
			return NULL;
		}
	}

	if ((rv = ni_system_tuntap_create(nc, cfg, &dev)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || dev == NULL
		|| (cfg->name && dev && !ni_string_eq(dev->name, cfg->name))) {
			ni_dbus_set_error_from_code(error, rv,
				"Unable to create %s interface %s",
				iftype, cfg->name);
			return NULL;
		}
		ni_debug_dbus("%s interface exists (and name matches)", iftype);
	}

	if (dev->link.type != cfg->link.type) {
		dbus_set_error(error,
			DBUS_ERROR_FAILED,
			"Unable to create %s: existing interface %s is of type %s",
			iftype, dev->name, ni_linktype_type_to_name(dev->link.type));
		return NULL;
	}

	return dev;
}

static inline ni_netdev_t *
__ni_objectmodel_tuntap_device_arg(const ni_dbus_variant_t *dict,
					const ni_iftype_t iftype)
{
	switch (iftype) {
	case NI_IFTYPE_TUN:
		return ni_objectmodel_get_netif_argument(dict, iftype,
				&ni_objectmodel_tun_service);
	case NI_IFTYPE_TAP:
		return ni_objectmodel_get_netif_argument(dict, iftype,
				&ni_objectmodel_tap_service);
	default:
		return NULL;
	}
}

static dbus_bool_t
__ni_objectmodel_tuntap_newlink(ni_iftype_t iftype, ni_dbus_object_t *factory_object,
			const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	const char *ifname = NULL;
	ni_netdev_t *dev;
	ni_netdev_t *cfg;

	NI_TRACE_ENTER();
	ni_assert(argc == 2);

	if (!ni_dbus_variant_get_string(&argv[0], &ifname) ||
	    !(cfg = __ni_objectmodel_tuntap_device_arg(&argv[1], iftype))) {
		return ni_dbus_error_invalid_args(error,
						factory_object->path,
						method->name);
	}

	ni_string_dup(&cfg->name, ifname);
	dev = __ni_objectmodel_tuntap_create(cfg, error);

	ni_netdev_put(cfg);
	if (!dev)
		return FALSE;
	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

static dbus_bool_t
ni_objectmodel_tun_newlink(ni_dbus_object_t *factory_object,
			const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return __ni_objectmodel_tuntap_newlink(NI_IFTYPE_TUN, factory_object,
						method, argc, argv, reply, error);
}

static dbus_bool_t
ni_objectmodel_tap_newlink(ni_dbus_object_t *factory_object,
			const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return __ni_objectmodel_tuntap_newlink(NI_IFTYPE_TAP, factory_object,
						method, argc, argv, reply, error);
}

static dbus_bool_t
ni_objectmodel_tuntap_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
				unsigned int argc, const ni_dbus_variant_t *argv,
				ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev, *cfg;
	ni_tuntap_t *tuntap;
	const char *err;
	const char *iftype_name;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)) ||
	    !(cfg = __ni_objectmodel_tuntap_device_arg(&argv[0], dev->link.type)) ||
	    !(ni_netdev_get_tuntap(dev))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		return FALSE;
	}

	/* changeDevice method is only needed in case of TAP devices */
	if (dev->link.type != NI_IFTYPE_TAP)
		return TRUE;

	iftype_name = ni_linktype_type_to_name(dev->link.type);

	tuntap = ni_netdev_get_tuntap(cfg);
	if ((err = ni_tuntap_validate(tuntap))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		return FALSE;
	}

	cfg->link.ifindex = dev->link.ifindex;
	if (ni_string_empty(cfg->name))
		ni_string_dup(&cfg->name, dev->name);

	if (ni_netdev_device_is_up(dev)) {
		ni_debug_objectmodel("Skipping %s changeDevice call on %s: "
				"device is up", iftype_name, dev->name);
		return TRUE;
	}

	if (ni_system_tap_change(nc, dev, cfg) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to change %s properties on interface %s",
				iftype_name, dev->name);
		return FALSE;
	}

	if (cfg->link.hwaddr.type == ARPHRD_VOID)
		cfg->link.hwaddr.type = ARPHRD_ETHER;
	if (!ni_link_address_is_invalid(&cfg->link.hwaddr) &&
	    ni_system_hwaddr_change(nc, dev, &cfg->link.hwaddr) < 0) {
		ni_error("Unable to change hwaddr on %s interface %s",
				iftype_name, dev->name);
		/* fail? */
	}

	return TRUE;
}


/*
 * Delete a TUN/TAP interface
 */
dbus_bool_t
ni_objectmodel_tuntap_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if ((rv = ni_system_tuntap_delete(dev) < 0)) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error deleting TUN/TAP interface %s: %s",
			dev->name, ni_strerror(rv));
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}

/*
 * Helper function to obtain TUN/TAP config from dbus object
 */
static void *
ni_objectmodel_get_tuntap(const ni_dbus_object_t *object,
		ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->tuntap;

	return ni_netdev_get_tuntap(dev);
}

static dbus_bool_t
__ni_objectmodel_tap_get_address(const ni_dbus_object_t *object,
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
__ni_objectmodel_tap_set_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr);
}

const ni_dbus_property_t	ni_objectmodel_tun_property_table[] = {
	NI_DBUS_GENERIC_UINT32_PROPERTY(tuntap, owner, owner, RO),
	NI_DBUS_GENERIC_UINT32_PROPERTY(tuntap, group, group, RO),
	{ NULL }
};

const ni_dbus_property_t	ni_objectmodel_tap_property_table[] = {
	__NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			address, __ni_objectmodel_tap, RO),
	NI_DBUS_GENERIC_UINT32_PROPERTY(tuntap, owner, owner, RO),
	NI_DBUS_GENERIC_UINT32_PROPERTY(tuntap, group, group, RO),
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_tuntap_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_tuntap_change },
	{ "deleteDevice",	"",		.handler = ni_objectmodel_tuntap_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_tun_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_tun_newlink },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_tap_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_tap_newlink },
	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_tun_factory_service = {
	.name		= NI_OBJECTMODEL_TUN_INTERFACE ".Factory",
	.methods	= ni_objectmodel_tun_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_tap_factory_service = {
	.name		= NI_OBJECTMODEL_TAP_INTERFACE ".Factory",
	.methods	= ni_objectmodel_tap_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_tun_service = {
	.name		= NI_OBJECTMODEL_TUN_INTERFACE,
	.methods	= ni_objectmodel_tuntap_methods,
	.properties	= ni_objectmodel_tun_property_table,
};

ni_dbus_service_t	ni_objectmodel_tap_service = {
	.name		= NI_OBJECTMODEL_TAP_INTERFACE,
	.methods	= ni_objectmodel_tuntap_methods,
	.properties	= ni_objectmodel_tap_property_table,
};
