/*
 *	DBus encapsulation for team interfaces
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
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/team.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static ni_netdev_t *	__ni_objectmodel_team_device_arg(const ni_dbus_variant_t *);
static ni_netdev_t *	__ni_objectmodel_team_newlink(ni_netdev_t *, const char *, DBusError *);

/*
 * Return an interface handle containing all bridge-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_team_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_TEAM, &ni_objectmodel_team_service);
}

/*
 * Create a new team interface
 */
static dbus_bool_t
ni_objectmodel_new_team(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *ifp;
	const char *ifname = NULL;

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(ifp = __ni_objectmodel_team_device_arg(&argv[1])))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);

	if (!(ifp = __ni_objectmodel_team_newlink(ifp, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, ifp, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_team_newlink(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_ifp = NULL;
	const ni_team_t *team;
	int rv;

	team = ni_netdev_get_team(cfg_ifp);

	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "team", 0))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create team interface - too many interfaces");
		goto out;
	}
	ni_string_dup(&cfg_ifp->name, ifname);

	if ((rv = ni_system_team_create(nc, cfg_ifp->name, team, &new_ifp)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create team interface '%s'", cfg_ifp->name);
		new_ifp = NULL;
		goto out;
#if 0
		if (rv != -NI_ERROR_DEVICE_EXISTS
		 && (ifname != NULL && strcmp(ifname, new_ifp->name))) {
			dbus_set_error(error,
					DBUS_ERROR_FAILED,
					"Unable to create team interface: %s",
					ni_strerror(rv));
			goto out;
		}
		ni_debug_dbus("Bonding interface exists (and name matches)");
#endif
	}

	if (new_ifp->link.type != NI_IFTYPE_TEAM) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create team interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		new_ifp = NULL;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return new_ifp;
}

/*
 * Bonding.changeDevice method
 */
static dbus_bool_t
__ni_objectmodel_team_setup(ni_dbus_object_t *object, const ni_dbus_method_t *method,
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

	if (!(cfg = __ni_objectmodel_team_device_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (ni_system_team_setup(nc, ifp, cfg->team) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to set up team device");
		goto out;
	}

	rv = TRUE;

out:
	if (cfg)
		ni_netdev_put(cfg);
	return rv;
}


/*
 * Bonding.shutdown method
 */
static dbus_bool_t
__ni_objectmodel_shutdown_team(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_team_shutdown(dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error shutting team interface down", dev->name);
		return FALSE;
	}

	return TRUE;
}


/*
 * Bonding.delete method
 */
static dbus_bool_t
__ni_objectmodel_delete_team(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_team_delete(nc, dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting team interface", dev->name);
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}


/*
 * Helper function to obtain team config from dbus object
 */
static ni_team_t *
__ni_objectmodel_team_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_team_t *team;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->team;

	if (!(team = ni_netdev_get_team(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting team handle for interface");
		return NULL;
	}
	return team;
}

static ni_team_t *
__ni_objectmodel_team_write_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_team_handle(object, TRUE, error);
}

static const ni_team_t *
__ni_objectmodel_team_read_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_team_handle(object, FALSE, error);
}

#if 0
static void *
ni_objectmodel_get_team(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_team_handle(object, write_access, error);
}
#endif

static dbus_bool_t
__ni_objectmodel_team_get_address(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_get_hwaddr(result, &dev->link.hwaddr);
}

static dbus_bool_t
__ni_objectmodel_team_set_address(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr);
}

static dbus_bool_t
__ni_objectmodel_team_get_runner(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	ni_dbus_variant_t *dict;
	const ni_team_t *team;
	const char *name;

	if (!(team = __ni_objectmodel_team_read_handle(object, error)))
		return FALSE;

	if (!team->runner.type)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	if (!(name = ni_team_runner_type_to_name(team->runner.type))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad property %s; unsupported runner name type %u",
				property->name, team->runner.type);
		return FALSE;
	}

	ni_dbus_variant_init_struct(result);
	ni_dbus_struct_add_string(result, name);
	dict = ni_dbus_struct_add(result);
	ni_dbus_variant_init_dict(dict);

	switch (team->runner.type) {
	case NI_TEAM_RUNNER_ACTIVE_BACKUP: {
			const ni_team_runner_active_backup_t *ab = &team->runner.ab;
			ni_dbus_dict_add_uint32(dict, "hwaddr_policy", ab->config.hwaddr_policy);
		}
		break;

	case NI_TEAM_RUNNER_LOAD_BALANCE: {
			const ni_team_runner_load_balance_t *lb = &team->runner.lb;
			ni_dbus_variant_t *txb;

			ni_dbus_dict_add_uint32(dict, "tx_hash", lb->config.tx_hash);
			txb = ni_dbus_dict_add(dict, "tx_balancer");
			ni_dbus_variant_init_dict(txb);
			ni_dbus_dict_add_uint32(txb, "name", lb->config.tx_balancer.type);
			ni_dbus_dict_add_uint32(txb, "balancing_interval", lb->config.tx_balancer.interval);
		}
		break;

	case NI_TEAM_RUNNER_ROUND_ROBIN:
		break;

	case NI_TEAM_RUNNER_BROADCAST:
		break;

	case NI_TEAM_RUNNER_RANDOM:
		break;

	case NI_TEAM_RUNNER_LACP: {
			const ni_team_runner_lacp_t *lacp = &team->runner.lacp;
			ni_dbus_variant_t *txb;

			ni_dbus_dict_add_bool(dict, "active", lacp->config.active);
			ni_dbus_dict_add_bool(dict, "fast_rate", lacp->config.fast_rate);
			ni_dbus_dict_add_uint16(dict, "sys_prio", lacp->config.sys_prio);
			ni_dbus_dict_add_uint16(dict, "min_ports", lacp->config.min_ports);
			ni_dbus_dict_add_uint32(dict, "select_policy", lacp->config.select_policy);

			ni_dbus_dict_add_uint32(dict, "tx_hash", lacp->config.tx_hash);
			txb = ni_dbus_dict_add(dict, "tx_balancer");
			ni_dbus_variant_init_dict(txb);
			ni_dbus_dict_add_uint32(txb, "name", lacp->config.tx_balancer.type);
			ni_dbus_dict_add_uint32(txb, "balancing_interval", lacp->config.tx_balancer.interval);
		}
		break;

	default:
		return FALSE;
	}
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_team_set_runner(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_dbus_variant_t *dict;
	const char *name;
	ni_team_t *team;

	if (!(team = __ni_objectmodel_team_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_struct_get_string(argument, 0, &name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad value for property %s; missed subtype", property->name);
		return FALSE;
	}

	if (!ni_team_runner_name_to_type(name, &team->runner.type)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad value for property %s; unsupported subtype %s", property->name, name);
		return FALSE;
	}

	if (!(dict = ni_dbus_struct_get(argument, 1))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "missed team runner member dict");
		return FALSE;
	}
	if (!ni_dbus_variant_is_dict(dict)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "team runner member is not a dict");
		return FALSE;
	}

	switch (team->runner.type) {
	case NI_TEAM_RUNNER_ACTIVE_BACKUP: {
			ni_team_runner_active_backup_t *ab = &team->runner.ab;
			uint32_t u32;

			if (ni_dbus_dict_get_uint32(dict, "hwaddr_policy", &u32))
				ab->config.hwaddr_policy = u32;
			else
				ab->config.hwaddr_policy = NI_TEAM_AB_HWADDR_POLICY_SAME_ALL;
		}
		break;

	case NI_TEAM_RUNNER_LOAD_BALANCE: {
			ni_team_runner_load_balance_t *lb = &team->runner.lb;
			ni_dbus_variant_t *txb;
			uint32_t u32;

			if (ni_dbus_dict_get_uint32(dict, "tx_hash", &u32))
				lb->config.tx_hash = u32;
			else	lb->config.tx_hash = NI_TEAM_TX_HASH_NONE;

			txb = ni_dbus_dict_get(dict, "tx_balancer");
			if (txb) {
				if (ni_dbus_dict_get_uint32(txb, "name", &u32) &&
				    ni_team_tx_balancer_type_to_name(u32))
					lb->config.tx_balancer.type = u32;
				else	lb->config.tx_balancer.type = NI_TEAM_TX_BALANCER_BASIC;
				if (ni_dbus_dict_get_uint32(txb, "balancing_interval", &u32))
					lb->config.tx_balancer.interval = u32;
				else	lb->config.tx_balancer.interval = 50;
			}
		}
		break;

	case NI_TEAM_RUNNER_ROUND_ROBIN:
		break;

	case NI_TEAM_RUNNER_BROADCAST:
		break;

	case NI_TEAM_RUNNER_RANDOM:
		break;

	case NI_TEAM_RUNNER_LACP: {
			ni_team_runner_lacp_t *lacp = &team->runner.lacp;
			ni_dbus_variant_t *txb;
			dbus_bool_t b;
			uint16_t u16;
			uint32_t u32;

			if (ni_dbus_dict_get_bool(dict, "active", &b))
				lacp->config.active = b;
			else	lacp->config.active = TRUE;

			if (ni_dbus_dict_get_uint16(dict, "sys_prio", &u16))
				lacp->config.sys_prio = u16;
			else	lacp->config.sys_prio = 255;

			if (ni_dbus_dict_get_bool(dict, "fast_rate", &b))
				lacp->config.fast_rate = b;
			else	lacp->config.fast_rate = FALSE;

			if (ni_dbus_dict_get_uint16(dict, "min_ports", &u16) && u16 < 256)
				lacp->config.sys_prio = u16;
			else	lacp->config.sys_prio = 0;

			if (ni_dbus_dict_get_uint32(dict, "select_policy", &u32))
				lacp->config.select_policy = u32;
			else	lacp->config.select_policy = NI_TEAM_LACP_SELECT_POLICY_PRIO;

			if (ni_dbus_dict_get_uint32(dict, "tx_hash", &u32))
				lacp->config.tx_hash = u32;
			else	lacp->config.tx_hash = NI_TEAM_TX_HASH_NONE;

			txb = ni_dbus_dict_get(dict, "tx_balancer");
			if (txb) {
				if (ni_dbus_dict_get_uint32(txb, "name", &u32) &&
				    ni_team_tx_balancer_type_to_name(u32))
					lacp->config.tx_balancer.type = u32;
				else	lacp->config.tx_balancer.type = NI_TEAM_TX_BALANCER_BASIC;
				if (ni_dbus_dict_get_uint32(txb, "balancing_interval", &u32))
					lacp->config.tx_balancer.interval = u32;
				else	lacp->config.tx_balancer.interval = 50;
			}
		}
		break;

	default:
		return FALSE;
	}
	return TRUE;
}

#define TEAM_INT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT_PROPERTY(team, dbus_name, member_name, rw)
#define TEAM_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(team, dbus_name, member_name, rw)
#define TEAM_HWADDR_PROPERTY(dbus_name, rw) \
	__NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
			dbus_name, __ni_objectmodel_team, rw)
#define TEAM_DICT_PROPERTY(dbus_name, member_name,rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, dbus_name, \
			member_name, __ni_objectmodel_team, RO)

static ni_dbus_property_t	ni_objectmodel_team_properties[] = {
	TEAM_DICT_PROPERTY(runner, runner, RO),
	TEAM_HWADDR_PROPERTY(address, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_team_methods[] = {
	{ "changeDevice",	"a{sv}",			__ni_objectmodel_team_setup },
	{ "shutdownDevice",	"",				__ni_objectmodel_shutdown_team },
	{ "deleteDevice",	"",				__ni_objectmodel_delete_team },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_team_factory_methods[] = {
	{ "newDevice",		"sa{sv}",			ni_objectmodel_new_team },
	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_team_service = {
	.name		= NI_OBJECTMODEL_TEAM_INTERFACE,
	.methods	= ni_objectmodel_team_methods,
	.properties	= ni_objectmodel_team_properties,
};

ni_dbus_service_t	ni_objectmodel_team_factory_service = {
	.name		= NI_OBJECTMODEL_TEAM_INTERFACE ".Factory",
	.methods	= ni_objectmodel_team_factory_methods,
};
