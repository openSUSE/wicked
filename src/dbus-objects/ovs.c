/*
 *	DBus encapsulation for ovs bridge interfaces
 *
 *	Copyright (C) 2015 SUSE Linux GmbH, Nuernberg, Germany.
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
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/ovs.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "dbus-common.h"
#include "model.h"
#include "debug.h"
#include "appconfig.h"


static ni_netdev_t *	__ni_objectmodel_ovs_bridge_device_arg(const ni_dbus_variant_t *);
static ni_netdev_t *	__ni_objectmodel_ovs_bridge_newlink(ni_netdev_t *, const char *, DBusError *);

/*
 * Return an interface handle containing all bridge-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_ovs_bridge_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_OVS_BRIDGE, &ni_objectmodel_ovs_bridge_service);
}

/*
 * Create a new ovs bridge interface
 */
static dbus_bool_t
__ni_objectmodel_ovs_bridge_create(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *ifp;
	const char *ifname = NULL;

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(ifp = __ni_objectmodel_ovs_bridge_device_arg(&argv[1])))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);

	if (!(ifp = __ni_objectmodel_ovs_bridge_newlink(ifp, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, ifp, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_ovs_bridge_newlink(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_ifp = NULL;
	int rv;

	ni_netdev_get_ovs_bridge(cfg_ifp);
	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "ovsbr", 0))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create ovs bridge interface - too many interfaces");
		goto out;
	}
	ni_string_dup(&cfg_ifp->name, ifname);

	if ((rv = ni_system_ovs_bridge_create(nc, cfg_ifp, &new_ifp)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || new_ifp == NULL
		|| (ifname && new_ifp && !ni_string_eq(ifname, new_ifp->name))) {
			dbus_set_error(error,
					DBUS_ERROR_FAILED,
					"Unable to create OVS bridge device: %s",
					ni_strerror(rv));
			new_ifp = NULL;
			goto out;
		}
		ni_debug_dbus("OVS bridge device %s exists (and with correct type)", ifname);
	}

	if (new_ifp->link.type != NI_IFTYPE_OVS_BRIDGE) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create ovs bridge interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		new_ifp = NULL;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return new_ifp;
}

/*
 * OVSBridge.changeDevice method
 */
static dbus_bool_t
__ni_objectmodel_ovs_bridge_setup(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *ifp, *cfg;
	dbus_bool_t rv = FALSE;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (!(cfg = __ni_objectmodel_ovs_bridge_device_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (ni_system_ovs_bridge_setup(nc, ifp, cfg) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to set up ovs bridge device");
		goto out;
	}

	if (nc)
	rv = TRUE;

out:
	if (cfg)
		ni_netdev_put(cfg);
	return rv;
}


/*
 * OVSBridge.shutdown method
 */
static dbus_bool_t
__ni_objectmodel_ovs_bridge_shutdown(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	if (ni_system_ovs_bridge_shutdown(dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error shutting down ovs bridge interface %s", dev->name);
		return FALSE;
	}
	return TRUE;
}


/*
 * OVSBridge.delete method
 */
static dbus_bool_t
__ni_objectmodel_ovs_bridge_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_ovs_bridge_delete(nc, dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting ovs bridge interface %s", dev->name);
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}


/*
 * Helper function to obtain ovs bridge config from dbus object
 */
static ni_ovs_bridge_t *
__ni_objectmodel_ovs_bridge_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_ovs_bridge_t *ovsbr;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->ovsbr;

	if (!(ovsbr = ni_netdev_get_ovs_bridge(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting ovs bridge handle for interface");
		return NULL;
	}
	return ovsbr;
}

/*
 * OVS Bridge handle access helpers
 */
static ni_ovs_bridge_t *
__ni_objectmodel_ovs_bridge_write_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_ovs_bridge_handle(object, TRUE, error);
}

static const ni_ovs_bridge_t *
__ni_objectmodel_ovs_bridge_read_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_ovs_bridge_handle(object, FALSE, error);
}

#if 0
static void *
ni_objectmodel_get_ovs_bridge(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_ovs_bridge_handle(object, write_access, error);
}
#endif

/*
 * OVS Bridge interface info properties <-> dict
 */
extern dbus_bool_t
ni_objectmodel_get_ovs_bridge_port_info(const ni_ovs_bridge_port_info_t *info,
		ni_dbus_variant_t *dict, DBusError *error)
{
	(void)error;

	if (!info || !dict)
		return FALSE;

	return TRUE;
}
extern dbus_bool_t
ni_objectmodel_set_ovs_bridge_port_info(ni_ovs_bridge_port_info_t *info,
		const ni_dbus_variant_t *dict, DBusError *error)
{
	(void)error;

	if (!info || !dict)
		return FALSE;

	return TRUE;
}

/*
 * OVS Bridge (link-request) port configuration <-> dict
 */
extern dbus_bool_t
ni_objectmodel_get_ovs_bridge_port_config(const ni_ovs_bridge_port_config_t *conf,
		ni_dbus_variant_t *dict, DBusError *error)
{
	(void)error;

	if (!conf || !dict)
		return FALSE;

	return TRUE;
}
extern dbus_bool_t
ni_objectmodel_set_ovs_bridge_port_config(ni_ovs_bridge_port_config_t *conf,
		const ni_dbus_variant_t *dict, DBusError *error)
{
	if (!conf || !dict)
		return FALSE;

	return TRUE;
}

/*
 * OVS Bridge vlan
 */
static dbus_bool_t
__ni_objectmodel_ovs_bridge_get_vlan(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	const ni_ovs_bridge_t *ovsbr;

	if (!(ovsbr = __ni_objectmodel_ovs_bridge_read_handle(object, error)))
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	if (ni_string_empty(ovsbr->config.vlan.parent.name))
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	ni_dbus_variant_init_dict(result);
	ni_dbus_dict_add_string(result, "parent", ovsbr->config.vlan.parent.name);
	ni_dbus_dict_add_uint16(result, "tag", ovsbr->config.vlan.tag);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_ovs_bridge_set_vlan(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_ovs_bridge_t *ovsbr;
	const char *parent = NULL;
	uint16_t tag = 0;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(ovsbr = __ni_objectmodel_ovs_bridge_write_handle(object, error)))
		return FALSE;

	ni_dbus_dict_get_string(argument, "parent", &parent);
	ni_dbus_dict_get_uint16(argument, "tag", &tag);

	if (!ni_string_empty(parent) && tag < 0x0fff) {
		ovsbr->config.vlan.tag = tag;
		ni_netdev_ref_set_ifname(&ovsbr->config.vlan.parent, parent);
	} else {
		ovsbr->config.vlan.tag = 0;
		ni_netdev_ref_destroy(&ovsbr->config.vlan.parent);
	}
	return TRUE;
}

/*
 * OVS Bridge properties
 */
#define OVS_BRIDGE_DICT_PROPERTY(dbus_name, member_name, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, dbus_name, \
			member_name, __ni_objectmodel_ovs_bridge, RO)
#define OVS_BRIDGE_DICT_ARRAY_PROPERTY(dbus_name, member_name, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE, \
			dbus_name, member_name, __ni_objectmodel_ovs_bridge, RO)

static ni_dbus_property_t	ni_objectmodel_ovs_bridge_properties[] = {
	OVS_BRIDGE_DICT_PROPERTY(vlan, vlan, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ovs_bridge_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = __ni_objectmodel_ovs_bridge_setup },
	{ "shutdownDevice",	"",		.handler = __ni_objectmodel_ovs_bridge_shutdown },
	{ "deleteDevice",	"",		.handler = __ni_objectmodel_ovs_bridge_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ovs_bridge_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = __ni_objectmodel_ovs_bridge_create },
	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_ovs_bridge_service = {
	.name		= NI_OBJECTMODEL_OVS_BRIDGE_INTERFACE,
	.methods	= ni_objectmodel_ovs_bridge_methods,
	.properties	= ni_objectmodel_ovs_bridge_properties,
};

ni_dbus_service_t	ni_objectmodel_ovs_bridge_factory_service = {
	.name		= NI_OBJECTMODEL_OVS_BRIDGE_INTERFACE ".Factory",
	.methods	= ni_objectmodel_ovs_bridge_factory_methods,
};
