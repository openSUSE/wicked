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

#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/team.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "dbus-common.h"
#include "model.h"
#include "debug.h"
#include "appconfig.h"


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

static dbus_bool_t
ni_objectmodel_team_report_disabled(DBusError *error)
{
	if (ni_config_teamd_enabled())
		return TRUE;

	dbus_set_error(error, DBUS_ERROR_UNKNOWN_METHOD,
		"Unable to create team interface - teamd configuration support disabled");
	return FALSE;
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

	if (!ni_objectmodel_team_report_disabled(error))
		return FALSE;

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
	int rv;

	ni_netdev_get_team(cfg_ifp);
	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "team", 0))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create team interface - too many interfaces");
		goto out;
	}
	ni_string_dup(&cfg_ifp->name, ifname);

	if (cfg_ifp->link.hwaddr.len) {
		if (cfg_ifp->link.hwaddr.type == ARPHRD_VOID)
			cfg_ifp->link.hwaddr.type = ARPHRD_ETHER;

		if (cfg_ifp->link.hwaddr.type != ARPHRD_ETHER ||
		    cfg_ifp->link.hwaddr.len != ni_link_address_length(ARPHRD_ETHER)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"Cannot create team interface: invalid ethernet address '%s'",
					ni_link_address_print(&cfg_ifp->link.hwaddr));
			goto out;
		}
	}

	if ((rv = ni_system_team_create(nc, cfg_ifp, &new_ifp)) < 0) {
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

	if (!ni_config_teamd_enabled())
		return TRUE;

	if (!(cfg = __ni_objectmodel_team_device_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (ni_system_team_setup(nc, ifp, cfg) < 0) {
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

	if (!ni_config_teamd_enabled())
		return TRUE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_team_shutdown(dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error shutting down team interface %s", dev->name);
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

	if (!ni_objectmodel_team_report_disabled(error))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_team_delete(nc, dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting team interface %s", dev->name);
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}


/*
 * Helper function to obtain team config from dbus object
 */
static void *
ni_objectmodel_get_team(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
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
	return ni_objectmodel_get_team(object, TRUE, error);
}

static const ni_team_t *
__ni_objectmodel_team_read_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_get_team(object, FALSE, error);
}

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
__ni_objectmodel_team_get_mcast_rejoin(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_team_t *team;
	const ni_team_mcast_rejoin_t *m;

	if (!(team = __ni_objectmodel_team_read_handle(object, error)))
		return FALSE;
	m = &team->mcast_rejoin;

	if (m->count == -1U && m->interval == -1U)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	ni_dbus_variant_init_dict(result);
	if (m->count != -1U)
		ni_dbus_dict_add_uint32(result, "count", m->count);

	if (m->interval != -1U)
		ni_dbus_dict_add_uint32(result, "interval", m->interval);

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_team_set_mcast_rejoin(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_team_t *team;
	uint32_t u32;

	if (!(team = __ni_objectmodel_team_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict(argument)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "team mcast_rejoin member is not a dict");
		return FALSE;
	}

	if (ni_dbus_dict_get_uint32(argument, "count", &u32))
		team->mcast_rejoin.count = u32;

	if (ni_dbus_dict_get_uint32(argument, "interval", &u32))
		team->mcast_rejoin.interval = u32;

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_team_get_notify_peers(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_team_t *team;
	const ni_team_notify_peers_t *m;

	if (!(team = __ni_objectmodel_team_read_handle(object, error)))
		return FALSE;
	m = &team->notify_peers;

	if (m->count == -1U && m->interval == -1U)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	ni_dbus_variant_init_dict(result);
	if (m->count != -1U)
		ni_dbus_dict_add_uint32(result, "count", m->count);

	if (m->interval != -1U)
		ni_dbus_dict_add_uint32(result, "interval", m->interval);

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_team_set_notify_peers(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_team_t *team;
	uint32_t u32;

	if (!(team = __ni_objectmodel_team_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict(argument)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "team notify_peers member is not a dict");
		return FALSE;
	}

	if (ni_dbus_dict_get_uint32(argument, "count", &u32))
		team->notify_peers.count = u32;

	if (ni_dbus_dict_get_uint32(argument, "interval", &u32))
		team->notify_peers.interval = u32;

	return TRUE;
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

	ni_team_runner_init(&team->runner, team->runner.type);
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

/*
 * Helper functions to represent link_watches as a dbus dict
 */
static dbus_bool_t
__ni_objectmodel_team_link_watch_to_dict(const ni_team_link_watch_t *lw, ni_dbus_variant_t *dict,
				DBusError *error, const ni_dbus_object_t *object, const ni_dbus_property_t *property)
{
	if (!lw || !dict)
		return FALSE;

	switch(lw->type) {
	case NI_TEAM_LINK_WATCH_ETHTOOL:
		ni_dbus_dict_add_uint32(dict, "delay_up", lw->ethtool.delay_up);
		ni_dbus_dict_add_uint32(dict, "delay_down", lw->ethtool.delay_down);
		break;
	case NI_TEAM_LINK_WATCH_ARP_PING:
		if (lw->arp.source_host)
			ni_dbus_dict_add_string(dict, "source_host", lw->arp.source_host);
		if (lw->arp.target_host)
			ni_dbus_dict_add_string(dict, "target_host", lw->arp.target_host);
		if (lw->arp.interval)
			ni_dbus_dict_add_uint32(dict, "interval", lw->arp.interval);
		if (lw->arp.init_wait)
			ni_dbus_dict_add_uint32(dict, "init_wait", lw->arp.init_wait);
		if (lw->arp.validate_active)
			ni_dbus_dict_add_bool(dict, "validate_active", lw->arp.validate_active);
		if (lw->arp.validate_inactive)
			ni_dbus_dict_add_bool(dict, "validate_inactive", lw->arp.validate_inactive);
		if (lw->arp.send_always)
			ni_dbus_dict_add_bool(dict, "send_always", lw->arp.send_always);
		if (lw->arp.missed_max > 0)
			ni_dbus_dict_add_uint32(dict, "missed_max", lw->arp.missed_max);
		if (lw->arp.vlanid != UINT16_MAX)
			ni_dbus_dict_add_uint16(dict, "vlanid", lw->arp.vlanid);
		break;
	case NI_TEAM_LINK_WATCH_NSNA_PING:
		if (lw->nsna.target_host)
			ni_dbus_dict_add_string(dict, "target_host", lw->nsna.target_host);
		if (lw->nsna.interval > 0)
			ni_dbus_dict_add_uint32(dict, "interval", lw->nsna.interval);
		if (lw->nsna.init_wait > 0)
			ni_dbus_dict_add_uint32(dict, "init_wait", lw->nsna.init_wait);
		if (lw->nsna.missed_max)
			ni_dbus_dict_add_uint32(dict, "missed_max", lw->nsna.missed_max);
		break;
	case NI_TEAM_LINK_WATCH_TIPC:
		if (lw->tipc.bearer)
			ni_dbus_dict_add_string(dict, "bearer", lw->tipc.bearer);
		break;
	default:
		return  FALSE;
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_team_link_watch_from_dict(ni_team_link_watch_t *lw, const ni_dbus_variant_t *dict,
				DBusError *error, const ni_dbus_property_t *property)
{
	const char *string;
	dbus_bool_t bvalue;
	uint32_t value;
	uint16_t u16;

	if (!lw || !dict || !error)
		return FALSE;

	switch(lw->type) {
	case NI_TEAM_LINK_WATCH_ETHTOOL:
		if (ni_dbus_dict_get_uint32(dict, "delay_up", &value))
			lw->ethtool.delay_up = value;
		if (ni_dbus_dict_get_uint32(dict, "delay_down", &value))
			lw->ethtool.delay_down = value;
		break;
	case NI_TEAM_LINK_WATCH_ARP_PING:
		if (ni_dbus_dict_get_string(dict, "source_host", &string))
			ni_string_dup(&lw->arp.source_host, string);
		if (ni_dbus_dict_get_string(dict, "target_host", &string))
			ni_string_dup(&lw->arp.target_host, string);
		if (ni_dbus_dict_get_uint32(dict, "interval", &value))
			lw->arp.interval = value;
		if (ni_dbus_dict_get_uint32(dict, "init_wait", &value))
			lw->arp.init_wait = value;
		if (ni_dbus_dict_get_bool(dict, "validate_active", &bvalue))
			lw->arp.validate_active = bvalue;
		if (ni_dbus_dict_get_bool(dict, "validate_inactive", &bvalue))
			lw->arp.validate_inactive = bvalue;
		if (ni_dbus_dict_get_bool(dict, "send_always", &bvalue))
			lw->arp.send_always = bvalue;
		if (ni_dbus_dict_get_uint32(dict, "missed_max", &value))
			lw->arp.missed_max = value;
		if (ni_dbus_dict_get_uint16(dict, "vlanid", &u16))
			lw->arp.vlanid = u16;
		break;
	case NI_TEAM_LINK_WATCH_NSNA_PING:
		if (ni_dbus_dict_get_string(dict, "target_host", &string))
			ni_string_dup(&lw->nsna.target_host, string);
		if (ni_dbus_dict_get_uint32(dict, "interval", &value))
			lw->nsna.interval = value;
		if (ni_dbus_dict_get_uint32(dict, "init_wait", &value))
			lw->nsna.init_wait = value;
		if (ni_dbus_dict_get_uint32(dict, "missed_max", &value))
			lw->nsna.missed_max = value;
		break;
	case NI_TEAM_LINK_WATCH_TIPC:
		if (ni_dbus_dict_get_string(dict, "bearer", &string))
			ni_string_dup(&lw->tipc.bearer, string);
		break;
	default:
		return  FALSE;
	}

	return TRUE;
}

/*
 * Property link_watch
 */
static dbus_bool_t
__ni_objectmodel_team_get_link_watch(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	const ni_team_t *team;
	unsigned int i;

	if (!(team = __ni_objectmodel_team_read_handle(object, error)))
		return FALSE;

	if (!team->link_watch.count)
		return FALSE;

	ni_dbus_variant_init_dict(result);
	for (i = 0; i < team->link_watch.count; i++) {
		ni_team_link_watch_t *lw = team->link_watch.data[i];
		ni_dbus_variant_t *entry;
		ni_dbus_variant_t *dict;
		const char *name;

		if (!(name = ni_team_link_watch_type_to_name(lw->type)))
			continue;

		entry = ni_dbus_dict_add(result, "watch");
		ni_dbus_variant_init_struct(entry);
		ni_dbus_struct_add_string(entry, name);
		dict = ni_dbus_struct_add(entry);
		ni_dbus_variant_init_dict(dict);
		__ni_objectmodel_team_link_watch_to_dict(lw, dict, error, object, property);
	}
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_team_set_link_watch(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	const ni_dbus_variant_t *entry;
	ni_team_t *team;
	unsigned int i;

	if (!(team = __ni_objectmodel_team_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	i = 0; entry = NULL;
	while ((entry = ni_dbus_dict_get_next(argument, "watch", entry))) {
		const ni_dbus_variant_t *dict;
		ni_team_link_watch_type_t type;
		ni_team_link_watch_t *lw;
		const char *name;

		if (!ni_dbus_struct_get_string(entry, 0, &name)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"bad array element %u value for property %s; missed subtype",
					i, property->name);
			return FALSE;
		}

		if (!ni_team_link_watch_name_to_type(name, &type)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"bad array element %u for property %s; unsupported subtype %s",
					i, property->name, name);
			return FALSE;
		}

		if (!(dict = ni_dbus_struct_get(entry, 1))) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"missed team link_watch member dict in array element %u", i);
			return FALSE;
		}

		if (!ni_dbus_variant_is_dict(dict)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"team link_watch array element %u is not a dict", i);
			return FALSE;
		}

		lw = ni_team_link_watch_new(type);
		if (!__ni_objectmodel_team_link_watch_from_dict(lw, dict, error, property)) {
			ni_team_link_watch_free(lw);
			return FALSE;
		}

		ni_team_link_watch_array_append(&team->link_watch, lw);
		i++;
	}
	return TRUE;
}

/*
 * Helper function for team port config as dict
 */
extern dbus_bool_t
ni_objectmodel_get_team_port_config(const ni_team_port_config_t *conf,
		ni_dbus_variant_t *dict, DBusError *error)
{
	(void)error;

	if (!conf || !dict)
		return FALSE;

	if (conf->queue_id != -1U)
		ni_dbus_dict_add_uint32(dict, "queue_id", conf->queue_id);

	if (conf->ab.prio)
		ni_dbus_dict_add_uint32(dict, "prio", conf->ab.prio);
	if (conf->ab.sticky)
		ni_dbus_dict_add_bool(dict, "sticky", conf->ab.sticky);

	if (conf->lacp.prio)
		ni_dbus_dict_add_uint32(dict, "lacp_prio", conf->lacp.prio);
	if (conf->lacp.key)
		ni_dbus_dict_add_uint32(dict, "lacp_key", conf->lacp.key);

	return TRUE;
}

extern dbus_bool_t
ni_objectmodel_set_team_port_config(ni_team_port_config_t *conf,
		const ni_dbus_variant_t *dict, DBusError *error)
{
	dbus_bool_t b;
	uint32_t u32;

	(void)error;

	if (!conf || !dict)
		return FALSE;

	if (ni_dbus_dict_get_uint32(dict, "queue_id", &u32))
		conf->queue_id = u32;

	if (ni_dbus_dict_get_uint32(dict, "prio", &u32))
		conf->ab.prio = u32;
	if (ni_dbus_dict_get_bool(dict, "sticky", &b))
		conf->ab.sticky = b;

	if (ni_dbus_dict_get_uint32(dict, "lacp_prio", &u32))
		conf->lacp.prio = u32;

	if (ni_dbus_dict_get_uint32(dict, "lacp_key", &u32))
		conf->lacp.key = u32;

	return TRUE;
}

/*
 * team port interface info properties <-> dict
 */
static inline dbus_bool_t
ni_objectmodel_get_team_port_runner_lacp_info(const ni_team_port_runner_lacp_info_t *lacp,
		ni_dbus_variant_t *dict)
{
	ni_dbus_dict_add_uint16(dict, "aggregator-id", lacp->aggregator.id);
	ni_dbus_dict_add_bool(dict,   "selected",  lacp->selected);
	ni_dbus_dict_add_string(dict, "state",  lacp->state);

	return TRUE;
}

static inline dbus_bool_t
ni_objectmodel_get_team_port_runner_info(const ni_team_port_runner_info_t *runner,
		ni_dbus_variant_t *dict)
{
	ni_dbus_variant_t *rdict;
	ni_dbus_variant_t *ldict;
	const char *name;

	if (!(name = ni_team_runner_type_to_name(runner->type)))
		return FALSE;

	if (!(rdict = ni_dbus_dict_add(dict, "runner")))
		return FALSE;

	ni_dbus_variant_init_struct(rdict);
	ni_dbus_struct_add_string(rdict, name);
	if (!(ldict = ni_dbus_struct_add(rdict)))
		return FALSE;

	ni_dbus_variant_init_dict(ldict);
	switch (runner->type) {
	case NI_TEAM_RUNNER_LACP:
		ni_objectmodel_get_team_port_runner_lacp_info(&runner->lacp, ldict);
		break;
	default:
		/* other runner types don't have any port specific info */
		break;
	}
	return TRUE;
}
static inline dbus_bool_t
ni_objectmodel_get_team_port_link_watches_info(const ni_team_port_link_watches_info_t *watches,
		ni_dbus_variant_t *dict)
{
	ni_dbus_variant_t *wdict;

	if (!(wdict = ni_dbus_dict_add(dict, "link_watches")))
		return FALSE;

	ni_dbus_variant_init_dict(wdict);
	ni_dbus_dict_add_bool(wdict, "up", watches->up);
	return TRUE;
}
extern dbus_bool_t
ni_objectmodel_get_team_port_info(const ni_team_port_info_t *info,
		ni_dbus_variant_t *dict, DBusError *error)
{
	(void)error;

	if (!info || !dict)
		return FALSE;

	ni_objectmodel_get_team_port_runner_info(&info->runner, dict);
	ni_objectmodel_get_team_port_link_watches_info(&info->watches, dict);
	return TRUE;
}

static inline dbus_bool_t
ni_objectmodel_set_team_port_runner_lacp_info(ni_team_port_runner_lacp_info_t *lacp,
		const ni_dbus_variant_t *dict)
{
	const char *str;
	dbus_bool_t bv;
	uint16_t u16;

	if (ni_dbus_dict_get_uint16(dict, "aggregator-id", &u16))
		lacp->aggregator.id = u16;

	if (ni_dbus_dict_get_bool(dict,   "selected", &bv))
		lacp->selected = bv;

	if (ni_dbus_dict_get_string(dict, "state", &str))
		ni_string_dup(&lacp->state, str);

	return TRUE;
}
static inline dbus_bool_t
ni_objectmodel_set_team_port_runner_info(ni_team_port_runner_info_t *runner,
		const ni_dbus_variant_t *dict)
{
	const ni_dbus_variant_t *rdict;
	const ni_dbus_variant_t *ldict;
	const char *name;

	if (!(rdict = ni_dbus_dict_get(dict, "runner")))
		return FALSE;

	if (!ni_dbus_struct_get_string(rdict, 0, &name))
		return FALSE;

	if (!ni_team_runner_name_to_type(name, &runner->type))
		return FALSE;

	switch (runner->type) {
	case NI_TEAM_RUNNER_LACP:
		if ((ldict = ni_dbus_struct_get(rdict, 1)))
			ni_objectmodel_set_team_port_runner_lacp_info(&runner->lacp, ldict);
		break;
	default:
		/* other runner types don't have any port specific info */
		break;
	}
	return TRUE;
}
static inline dbus_bool_t
ni_objectmodel_set_team_port_link_watches_info(ni_team_port_link_watches_info_t *watches,
		const ni_dbus_variant_t *dict)
{
	const ni_dbus_variant_t *wdict;
	dbus_bool_t bval;

	if (!(wdict = ni_dbus_dict_get(dict, "link_watches")))
		return FALSE;

	if (ni_dbus_dict_get_bool(wdict, "up", &bval))
		watches->up = bval;

	return TRUE;
}
extern dbus_bool_t
ni_objectmodel_set_team_port_info(ni_team_port_info_t *info,
		const ni_dbus_variant_t *dict, DBusError *error)
{
	(void)error;

	if (!info || !dict)
		return FALSE;

	ni_objectmodel_set_team_port_runner_info(&info->runner, dict);
	ni_objectmodel_set_team_port_link_watches_info(&info->watches, dict);
	return TRUE;
}

#define TEAM_HWADDR_PROPERTY(dbus_name, rw) \
	__NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, \
			dbus_name, __ni_objectmodel_team, rw)
#define TEAM_DICT_PROPERTY(dbus_name, member_name,rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, dbus_name, \
			member_name, __ni_objectmodel_team, RO)
#define TEAM_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(team, dbus_name, member_name, rw)

#define TEAM_DICT_ARRAY_PROPERTY(dbus_name, member_name,rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE, \
			dbus_name, member_name, __ni_objectmodel_team, RO)

static ni_dbus_property_t	ni_objectmodel_team_properties[] = {
	TEAM_UINT_PROPERTY(debug_level, debug_level, RO),
	TEAM_DICT_PROPERTY(notify_peers, notify_peers, RO),
	TEAM_DICT_PROPERTY(mcast_rejoin, mcast_rejoin, RO),
	TEAM_DICT_PROPERTY(runner, runner, RO),
	TEAM_UINT_PROPERTY(link_watch_policy, link_watch_policy, RO),
	TEAM_DICT_PROPERTY(link_watch, link_watch, RO),

	TEAM_HWADDR_PROPERTY(address, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_team_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = __ni_objectmodel_team_setup },
	{ "shutdownDevice",	"",		.handler = __ni_objectmodel_shutdown_team },
	{ "deleteDevice",	"",		.handler = __ni_objectmodel_delete_team },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_team_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_new_team },
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
