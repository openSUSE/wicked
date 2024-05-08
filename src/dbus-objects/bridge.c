/*
 * DBus encapsulation for bridge interfaces.
 *
 * Copyright (C) 2011, 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/bridge.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include <wicked/system.h>
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static ni_netdev_t *	__ni_objectmodel_bridge_newlink(ni_netdev_t *, const char *, DBusError *);

/*
 * Return an interface handle containing all bridge-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_bridge_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_BRIDGE, &ni_objectmodel_bridge_service);
}

/*
 * Bridge.Factory.newDevice:
 * Create a new bridging interface
 */
static dbus_bool_t
ni_objectmodel_new_bridge(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *ifp;
	const char *ifname = NULL;

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(ifp = __ni_objectmodel_bridge_device_arg(&argv[1])))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);

	if (!(ifp = __ni_objectmodel_bridge_newlink(ifp, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, ifp, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_bridge_newlink(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_ifp = NULL;
	const ni_bridge_t *bridge;
	int rv;

	bridge = ni_netdev_get_bridge(cfg_ifp);

	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "br", 0))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create bridging interface - too many interfaces");
		goto out;
	}
	ni_string_dup(&cfg_ifp->name, ifname);

	if ((rv = ni_system_bridge_create(nc, cfg_ifp->name, bridge, &new_ifp)) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create bridging interface: %s",
				ni_strerror(rv));
		new_ifp = NULL;
		goto out;
	}

	if (new_ifp->link.type != NI_IFTYPE_BRIDGE) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create bridging interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		new_ifp = NULL;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return new_ifp;
}

/*
 * Bridge.changeDevice method
 */
static dbus_bool_t
ni_objectmodel_bridge_setup(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *ifp, *cfg;
	dbus_bool_t rv = FALSE;
	const char *err;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (!(cfg = __ni_objectmodel_bridge_device_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if ((err = ni_bridge_validate(cfg->bridge)) != NULL) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "invalid configuration for %s: %s",
				ifp->name, err);
		goto out;
	}

	if (ni_system_bridge_setup(nc, ifp, cfg->bridge) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to set up bridging device");
		goto out;
	}

	if (cfg->link.hwaddr.len) {
		if (cfg->link.hwaddr.type == ARPHRD_VOID)
		    cfg->link.hwaddr.type = ARPHRD_ETHER;

		if (cfg->link.hwaddr.type != ARPHRD_ETHER ||
		    ni_link_address_is_invalid(&cfg->link.hwaddr) ||
		    ni_system_hwaddr_change(nc, ifp, &cfg->link.hwaddr) < 0) {
			ni_error("Unable to change link address on bridge interface %s to '%s'",
					ifp->name, ni_link_address_print(&cfg->link.hwaddr));
			/* fail? */
		}
	}

	rv = TRUE;

out:
	if (cfg)
		ni_netdev_put(cfg);
	return rv;
}

/*
 * Bridge.shutdown method
 */
static dbus_bool_t
ni_objectmodel_shutdown_bridge(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_bridge_shutdown(dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error shutting down bridge interface %s", dev->name);
		return FALSE;
	}

	return TRUE;
}

/*
 * Bridge.delete method
 */
static dbus_bool_t
ni_objectmodel_delete_bridge(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_bridge_delete(nc, dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting bridge interface %s", dev->name);
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}

/*
 * Helper function to obtain bridge config from dbus object
 */
static ni_bridge_t *
__ni_objectmodel_bridge_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev = ni_objectmodel_unwrap_netif(object, error);
	ni_bridge_t *bridge;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->bridge;

	if (!(bridge = ni_netdev_get_bridge(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting bridge handle for interface");
		return NULL;
	}
	return bridge;
}

void *
ni_objectmodel_get_bridge(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_bridge_handle(object, write_access, error);
}

/*
 * Bridge port (link-request) configuration
 */
extern dbus_bool_t
ni_objectmodel_get_bridge_port_config(const ni_bridge_port_config_t *conf,
		ni_dbus_variant_t *dict, DBusError *error)
{
	(void)error;

	if (!conf || !dict)
		return FALSE;

	if (conf->priority != NI_BRIDGE_VALUE_NOT_SET)
		ni_dbus_dict_add_uint32(dict, "priority", conf->priority);
	if (conf->path_cost != NI_BRIDGE_VALUE_NOT_SET)
		ni_dbus_dict_add_uint32(dict, "path-cost", conf->path_cost);

	return TRUE;
}
extern dbus_bool_t
ni_objectmodel_set_bridge_port_config(ni_bridge_port_config_t *conf,
		const ni_dbus_variant_t *dict, DBusError *error)
{
	uint32_t value;

	(void)error;

	if (!conf || !dict)
		return FALSE;

	if (ni_dbus_dict_get_uint32(dict, "priority", &value))
		conf->priority = value;
	if (ni_dbus_dict_get_uint32(dict, "path-cost", &value))
		conf->path_cost = value;

	return TRUE;
}

/*
 * Bridge port interface info properties
 */
extern dbus_bool_t
ni_objectmodel_get_bridge_port_info(const ni_bridge_port_info_t *info,
		ni_dbus_variant_t *dict, DBusError *error)
{
	(void)error;

	if (!info || !dict)
		return FALSE;

	if (info->state)
		ni_dbus_dict_add_uint32(dict, "state", info->state);
	if (info->port_no)
		ni_dbus_dict_add_uint32(dict, "port-no", info->port_no);
	if (info->port_id)
		ni_dbus_dict_add_uint32(dict, "port-id", info->port_id);

	if (info->priority != NI_BRIDGE_VALUE_NOT_SET)
		ni_dbus_dict_add_uint32(dict, "priority", info->priority);
	if (info->path_cost != NI_BRIDGE_VALUE_NOT_SET)
		ni_dbus_dict_add_uint32(dict, "path-cost", info->path_cost);

	return TRUE;
}

extern dbus_bool_t
ni_objectmodel_set_bridge_port_info(ni_bridge_port_info_t *info,
		const ni_dbus_variant_t *dict, DBusError *error)
{
	uint32_t value;

	(void)error;

	if (!info || !dict)
		return FALSE;

	if (ni_dbus_dict_get_uint32(dict, "state", &value))
		info->state = value;
	if (ni_dbus_dict_get_uint32(dict, "port-no", &value))
		info->port_no = value;
	if (ni_dbus_dict_get_uint32(dict, "port-id", &value))
		info->port_id = value;

	if (ni_dbus_dict_get_uint32(dict, "priority", &value))
		info->priority = value;
	if (ni_dbus_dict_get_uint32(dict, "path-cost", &value))
		info->path_cost = value;

	return TRUE;
}

/*
 * Additional, not bridge-specific MAC/HW-Address property
 */
static dbus_bool_t
ni_objectmodel_bridge_get_address(const ni_dbus_object_t *object,
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
ni_objectmodel_bridge_set_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr);
}

#define BRIDGE_INT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT_PROPERTY(bridge, dbus_name, member_name, rw)
#define BRIDGE_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(bridge, dbus_name, member_name, rw)
#define BRIDGE_UINT16_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(bridge, dbus_name, member_name, rw)
#define BRIDGE_BOOL_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(bridge, dbus_name, member_name, rw)
#define BRIDGE_TIME_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_DOUBLE_PROPERTY(bridge, dbus_name, member_name, rw)

#define WICKED_BRIDGE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __ni_objectmodel_bridge, rw)
#define BRIDGE_HWADDR_PROPERTY(dbus_name, rw) \
	__NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
			dbus_name, ni_objectmodel_bridge, rw)

static const ni_dbus_property_t	ni_objectmodel_bridge_property_table[] = {
	BRIDGE_BOOL_PROPERTY(stp, stp, RO),
	BRIDGE_UINT_PROPERTY(priority, priority, RO),
	BRIDGE_TIME_PROPERTY(forward-delay, forward_delay, RO),
	BRIDGE_TIME_PROPERTY(aging-time, ageing_time, RO),
	BRIDGE_TIME_PROPERTY(hello-time, hello_time, RO),
	BRIDGE_TIME_PROPERTY(max-age, max_age, RO),

	BRIDGE_HWADDR_PROPERTY(address, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_bridge_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_bridge_setup },
	{ "shutdownDevice",	"",		.handler = ni_objectmodel_shutdown_bridge },
	{ "deleteDevice",	"",		.handler = ni_objectmodel_delete_bridge },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_bridge_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_new_bridge },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_bridge_service = {
	.name		= NI_OBJECTMODEL_BRIDGE_INTERFACE,
	.methods	= ni_objectmodel_bridge_methods,
	.properties	= ni_objectmodel_bridge_property_table,
};


ni_dbus_service_t	ni_objectmodel_bridge_factory_service = {
	.name		= NI_OBJECTMODEL_BRIDGE_INTERFACE ".Factory",
	.methods	= ni_objectmodel_bridge_factory_methods,
};
