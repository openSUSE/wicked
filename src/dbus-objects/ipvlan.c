/*
 *	Copyright (C) 2024 SUSE LLC
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
 *		Clemens Famulla-Conrad
 */
#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/ipvlan.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"
#include "wicked/constants.h"
#include "wicked/util.h"

static ni_netdev_t *
ni_objectmodel_ipvlantap_newlink(ni_netdev_t *cfg, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev = NULL;
	const ni_ipvlan_t *ipvlan;
	const char *err;
	const char *cfg_iftype = NULL;
	int rv;

	NI_TRACE_ENTER_ARGS("ifname=%s", ifname);

	cfg_iftype = ni_linktype_type_to_name(cfg->link.type);

	if (ni_string_empty(cfg->link.lowerdev.name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: Incomplete %s arguments: need a lower device name",
				ifname, cfg_iftype);
		return NULL;

	} else if (!ni_netdev_ref_bind_ifindex(&cfg->link.lowerdev, nc)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: Unable to find %s lower device %s by name",
				ifname, cfg_iftype, cfg->link.lowerdev.name);
		return NULL;
	}

	ipvlan = ni_netdev_get_ipvlan(cfg);
	if ((err = ni_ipvlan_validate(ipvlan))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: IPVLAN %s",
				ifname, err);
		return NULL;
	}

	if (!ni_string_eq(cfg->name, ifname))
		ni_string_dup(&cfg->name, ifname);

	if (ni_string_eq(cfg->name, cfg->link.lowerdev.name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: Cannot create %s interface: "
				"ipvlan name %s equal with lower device name",
				ifname, cfg_iftype, cfg->name);
		return NULL;
	}

	if ((rv = ni_system_ipvlan_create(nc, cfg, &dev)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || dev == NULL ||
		    (dev && !ni_string_eq(dev->name, ifname))) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"%s: Failed to create %s interface: %s",
					ifname, cfg_iftype, ni_strerror(rv));
			return NULL;
		}
		ni_debug_dbus("%s: %s interface exists (and name matches)",
				ifname, cfg_iftype);
	}

	if (dev->link.type != cfg->link.type) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"%s: Unable to create %s interface: "
				"new interface is of type %s",
				ifname, cfg_iftype,
				ni_linktype_type_to_name(dev->link.type));
		return NULL;
	}

	return dev;
}

/*
 * Change a ipvlan interface
 */
static dbus_bool_t
ni_objectmodel_ipvlantap_changelink(ni_netdev_t *cfg, ni_netdev_t *dev, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	const char *err;
	ni_ipvlan_t *ipvlan;
	const char *dev_iftype = NULL;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	ipvlan = ni_netdev_get_ipvlan(cfg);
	if ((err = ni_ipvlan_validate(ipvlan))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: IPVLAN %s", dev->name, err);
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

	if (ni_system_ipvlan_change(nc, dev, cfg) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to change %s properties on interface %s",
				dev_iftype, dev->name);
		return FALSE;
	}

	return TRUE;
}

/*
 * Return an interface handle containing all ipvlan/ipvtap-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
ni_objectmodel_ipvlantap_device_arg(const ni_dbus_variant_t *dict, unsigned int iftype)
{
	switch (iftype) {
	case NI_IFTYPE_IPVLAN:
		return ni_objectmodel_get_netif_argument(dict, iftype,
				    &ni_objectmodel_ipvlan_service);
	case NI_IFTYPE_IPVTAP:
		return ni_objectmodel_get_netif_argument(dict, iftype,
				    &ni_objectmodel_ipvtap_service);
	default:
		return NULL;
	}
}

static dbus_bool_t
ni_objectmodel_ipvlantap_new_device(ni_dbus_object_t *factory_object,
			const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error, ni_iftype_t type)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *dev, *cfg;
	const char *ifname = NULL;

	if (argc != 2 ||
	    !ni_dbus_variant_get_string(&argv[0], &ifname) || ni_string_empty(ifname) ||
	    !(cfg = ni_objectmodel_ipvlantap_device_arg(&argv[1], type))) {
		return ni_dbus_error_invalid_args(
				error, factory_object->path, method->name);
	}

	dev = ni_objectmodel_ipvlantap_newlink(cfg, ifname, error);
	ni_netdev_put(cfg);
	if (!dev)
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

static dbus_bool_t
ni_objectmodel_ipvlantap_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error, ni_iftype_t type)
{
	ni_netdev_t *dev, *cfg;
	dbus_bool_t ret;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || dev->link.type != type ||
	    !(cfg = ni_objectmodel_ipvlantap_device_arg(&argv[0], type))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		return FALSE;
	}

	ret = ni_objectmodel_ipvlantap_changelink(cfg, dev, error);
	ni_netdev_put(cfg);
	return ret;
}

static dbus_bool_t
ni_objectmodel_ipvlan_new_device(ni_dbus_object_t *factory_object,
			const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_ipvlantap_new_device(factory_object, method, argc, argv,
			reply, error, NI_IFTYPE_IPVLAN);
}

static dbus_bool_t
ni_objectmodel_ipvlan_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_ipvlantap_change(
			object, method, argc, argv, reply, error, NI_IFTYPE_IPVLAN);
}

static dbus_bool_t
ni_objectmodel_ipvlantap_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if ((rv = ni_system_ipvlan_delete(dev)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting ipvlan interface %s: %s",
				dev->name, ni_strerror(rv));
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ipvtap_new_device(ni_dbus_object_t *factory_object,
			const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_ipvlantap_new_device(
			factory_object, method, argc, argv, reply, error, NI_IFTYPE_IPVTAP);
}

static dbus_bool_t
ni_objectmodel_ipvtap_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_ipvlantap_change(
			object, method, argc, argv, reply, error, NI_IFTYPE_IPVTAP);
}


static void *
ni_objectmodel_get_netdev(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_netif(object, error);
}

static void *
ni_objectmodel_get_ipvlan(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_ipvlan_t *ipvlan;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->ipvlan;

	if (!(ipvlan = ni_netdev_get_ipvlan(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error getting ipvlan handle for interface");
		return NULL;
	}
	return ipvlan;
}

const ni_dbus_property_t	ni_objectmodel_ipvlan_property_table[] = {
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev, device, link.lowerdev.name, RO),
	NI_DBUS_GENERIC_UINT16_PROPERTY(ipvlan, mode, mode, RO),
	NI_DBUS_GENERIC_UINT16_PROPERTY(ipvlan, flags, flags, RO),
	{ .name = NULL }
};

static ni_dbus_method_t		ni_objectmodel_ipvlan_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_ipvlan_change },
	{ "deleteDevice",	"",		.handler = ni_objectmodel_ipvlantap_delete },
	{ .name = NULL }
};

static ni_dbus_method_t		ni_objectmodel_ipvlan_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_ipvlan_new_device },
	{ .name = NULL }
};

/* ipvlan Service */
ni_dbus_service_t	ni_objectmodel_ipvlan_factory_service = {
	.name		= NI_OBJECTMODEL_IPVLAN_INTERFACE ".Factory",
	.methods	= ni_objectmodel_ipvlan_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_ipvlan_service = {
	.name		= NI_OBJECTMODEL_IPVLAN_INTERFACE,
	.methods	= ni_objectmodel_ipvlan_methods,
	.properties	= ni_objectmodel_ipvlan_property_table,
};



static ni_dbus_method_t		ni_objectmodel_ipvtap_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_ipvtap_change },
	{ "deleteDevice",	"",		.handler = ni_objectmodel_ipvlantap_delete },
	{ .name = NULL }
};

static ni_dbus_method_t		ni_objectmodel_ipvtap_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_ipvtap_new_device },
	{ .name = NULL }
};

/* ipvtap Service */
ni_dbus_service_t	ni_objectmodel_ipvtap_factory_service = {
	.name		= NI_OBJECTMODEL_IPVTAP_INTERFACE ".Factory",
	.methods	= ni_objectmodel_ipvtap_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_ipvtap_service = {
	.name		= NI_OBJECTMODEL_IPVTAP_INTERFACE,
	.methods	= ni_objectmodel_ipvtap_methods,
	.properties	= ni_objectmodel_ipvlan_property_table,
};
