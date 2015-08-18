/*
 *	Interfacing with teamd through dbus interface
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

#include <limits.h>

#include <wicked/util.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/netinfo.h>
#include <wicked/team.h>

#include "dbus-dict.h"
#include "dbus-common.h"
#include "dbus-objects/model.h"
#include "util_priv.h"
#include "process.h"
#include "teamd.h"
#include "json.h"


#define NI_TEAMD_CONFIG_DIR			"/run/teamd"
#define NI_TEAMD_CONFIG_FMT			NI_TEAMD_CONFIG_DIR"/%s.conf"

#define NI_TEAMD_BUS_NAME			"org.libteam.teamd"
#define NI_TEAMD_OBJECT_PATH			"/org/libteam/teamd"
#define NI_TEAMD_INTERFACE			"org.libteam.teamd"

#define NI_TEAMD_CALL_CONFIG_DUMP		"ConfigDump"
#define NI_TEAMD_CALL_CONFIG_DUMP_ACTUAL	"ConfigDumpActual"

#define NI_TEAMD_CALL_STATE_DUMP		"StateDump"
#define NI_TEAMD_CALL_STATE_ITEM_GET		"StateItemValueGet"
#define NI_TEAMD_CALL_STATE_ITEM_SET		"StateItemValueSet"

#define NI_TEAMD_CALL_PORT_ADD			"PortAdd"


struct ni_teamd_client {
	ni_dbus_client_t *	dbus;

	ni_dbus_object_t *	proxy;
};

static void			ni_teamd_dbus_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);

static ni_dbus_class_t		ni_objectmodel_teamd_client_class = {
	"teamd-client"
};
#if 0
static ni_dbus_class_t		ni_objectmodel_teamd_device_class = {
	"teamd-device"
};
#endif

static const ni_intmap_t	ni_teamd_error_names[] = {
	{ NULL,			-1			}
};

ni_teamd_client_t *
ni_teamd_client_open(const char *ifname)
{
	ni_dbus_client_t *dbc;
	ni_teamd_client_t *tdc;
	char *service_name = NULL;

	if (ni_string_empty(ifname))
		return NULL;

	ni_string_printf(&service_name, NI_TEAMD_BUS_NAME".%s", ifname);
	dbc = ni_dbus_client_open("system", service_name);
	ni_string_free(&service_name);
	if (!dbc)
		return NULL;

	ni_dbus_client_set_error_map(dbc, ni_teamd_error_names);

	tdc = xcalloc(1, sizeof(*tdc));
	tdc->proxy = ni_dbus_client_object_new(dbc, &ni_objectmodel_teamd_client_class,
			NI_TEAMD_OBJECT_PATH, NI_TEAMD_INTERFACE, tdc);
	tdc->dbus = dbc;

	ni_dbus_client_add_signal_handler(dbc,
				NI_TEAMD_BUS_NAME,	/* sender */
				NULL,			/* object path */
				NI_TEAMD_INTERFACE,	/* object interface */
				ni_teamd_dbus_signal,
				tdc);
	return tdc;
}

void
ni_teamd_client_free(ni_teamd_client_t *tdc)
{
	if (tdc) {
		if (tdc->dbus) {
			ni_dbus_client_free(tdc->dbus);
			tdc->dbus = NULL;
		}

		/* while (tdc->iflist) */

		if (tdc->proxy) {
			ni_dbus_object_free(tdc->proxy);
			tdc->proxy = NULL;
		}

		free(tdc);
	}
}

#if 0
ni_dbus_client_t *
ni_teamd_client_dbus(ni_teamd_client_t *tdc)
{
	return tdc->dbus;
}
#endif

static void
ni_teamd_dbus_signal(ni_dbus_connection_t *connection, ni_dbus_message_t *msg, void *user_data)
{
	/* ni_teamd_client_t *tdc = user_data; */
	const char *member = dbus_message_get_member(msg);

	ni_debug_dbus("teamd-client: %s signal received (not handled)", member);
}

/*
 * teamd instance dbus access methods
 */
const char *
ni_teamd_ctl_config_dump(ni_teamd_client_t *tdc, ni_bool_t actual)
{
	const char *method;
	char *dump;
	int rv;

	if (!tdc)
		return NULL;

	method =  actual ? NI_TEAMD_CALL_CONFIG_DUMP_ACTUAL :
		NI_TEAMD_CALL_CONFIG_DUMP;
	rv = ni_dbus_object_call_simple(tdc->proxy,
 				NI_TEAMD_INTERFACE, method,
				0, NULL,
				DBUS_TYPE_STRING, &dump);

	if (rv < 0) {
		ni_debug_application("Call to %s.%s() failed: %s",
			ni_dbus_object_get_path(tdc->proxy), method, ni_strerror(rv));
		return NULL;
	}

	return dump;
}

const char *
ni_teamd_ctl_state_dump(ni_teamd_client_t *tdc)
{
	char *dump;
	int rv;

	if (!tdc)
		return NULL;

	rv = ni_dbus_object_call_simple(tdc->proxy,
				NI_TEAMD_INTERFACE, NI_TEAMD_CALL_STATE_DUMP,
				0, NULL,
				DBUS_TYPE_STRING, &dump);

	if (rv < 0) {
		ni_debug_application("Call to %s."NI_TEAMD_CALL_STATE_DUMP"() failed: %s",
			ni_dbus_object_get_path(tdc->proxy), ni_strerror(rv));
		return NULL;
	}

	return dump;
}

const char *
ni_teamd_ctl_state_get_item(ni_teamd_client_t *tdc, const char *item_name)
{
	char *state_item;
	int rv;

	if (!tdc || ni_string_empty(item_name))
		return NULL;

	rv = ni_dbus_object_call_simple(tdc->proxy,
				NI_TEAMD_INTERFACE, NI_TEAMD_CALL_STATE_ITEM_GET,
				DBUS_TYPE_STRING, &item_name,
				DBUS_TYPE_STRING, &state_item);

	if (rv < 0) {
		ni_debug_application("Call to %s."NI_TEAMD_CALL_STATE_ITEM_GET"(%s) failed: %s",
			ni_dbus_object_get_path(tdc->proxy), item_name, ni_strerror(rv));
		return NULL;
	}

	return state_item;
}

int
ni_teamd_ctl_state_set_item(ni_teamd_client_t *tdc, const char *item_name, const char *item_val)
{
	ni_dbus_message_t *call, *reply;
	DBusError error;
	int rv = 0;

	if (!tdc || ni_string_empty(item_name))
		return -NI_ERROR_INVALID_ARGS;

	dbus_error_init(&error);

	call = ni_dbus_object_call_new(tdc->proxy, NI_TEAMD_CALL_STATE_ITEM_SET, 0);
	ni_dbus_message_append_string(call, item_name);
	ni_dbus_message_append_string(call, item_val);
	if ((reply = ni_dbus_client_call(tdc->dbus, call, &error)) == NULL) {
		rv = -NI_ERROR_DBUS_CALL_FAILED;
		if (dbus_error_is_set(&error))
			rv = ni_dbus_client_translate_error(tdc->dbus, &error);
	}

	if (rv < 0) {
		ni_debug_application("Call to %s."NI_TEAMD_CALL_STATE_ITEM_SET"(%s) failed: %s",
			ni_dbus_object_get_path(tdc->proxy), item_name, ni_strerror(rv));
	}

	return rv;
}

int
ni_teamd_ctl_port_add(ni_teamd_client_t *tdc, const char *portname)
{
	ni_dbus_message_t *call, *reply;
	DBusError error;
	int rv = 0;

	if (!tdc || ni_string_empty(portname))
		return -NI_ERROR_INVALID_ARGS;

	dbus_error_init(&error);
	call = ni_dbus_object_call_new(tdc->proxy, NI_TEAMD_CALL_PORT_ADD, 0);
	ni_dbus_message_append_string(call, portname);
	if ((reply = ni_dbus_client_call(tdc->dbus, call, &error)) == NULL) {
		rv = -NI_ERROR_DBUS_CALL_FAILED;
		if (dbus_error_is_set(&error))
			rv = ni_dbus_client_translate_error(tdc->dbus, &error);
	}

	if (rv < 0) {
		ni_debug_application("Call to %s."NI_TEAMD_CALL_PORT_ADD"(%s) failed: %s",
				ni_dbus_object_get_path(tdc->proxy), portname, ni_strerror(rv));
	}

	return rv;
}

int
ni_teamd_port_enslave(ni_netdev_t *master, ni_netdev_t *port, ni_team_port_config_t *config)
{
	ni_teamd_client_t *tdc;
	int ret = -1;

	if (!master || !master->name || !port || !port->name)
		return -1;

	if (!(tdc = ni_teamd_client_open(master->name)))
		return -1;

	if (ni_teamd_ctl_port_add(tdc, port->name) < 0)
		goto failure;

	ret = 0;

failure:
        ni_teamd_client_free(tdc);
	return ret;
}


/*
 * teamd discovery
 */
static int
ni_teamd_discover_runner(ni_team_t *team, ni_json_t *conf)
{
	char *name = NULL;
	ni_json_t *runner;

	if (!team || !(runner = ni_json_object_get_value(conf, "runner")))
		return -1;

	if (!ni_json_string_get(ni_json_object_get_value(runner, "name"), &name))
		goto failure;
	if (!ni_team_runner_name_to_type(name, &team->runner.type))
		goto failure;

	ni_string_free(&name);
	switch (team->runner.type) {
	case NI_TEAM_RUNNER_ACTIVE_BACKUP: {
			ni_team_runner_active_backup_t *ab = &team->runner.ab;
			int64_t i64;

			if (ni_json_int64_get(ni_json_object_get_value(runner, "hwaddr_policy"), &i64))
				ab->config.hwaddr_policy = i64;
			else	ab->config.hwaddr_policy = NI_TEAM_AB_HWADDR_POLICY_SAME_ALL;
		}
		break;

	case NI_TEAM_RUNNER_LOAD_BALANCE: {
			ni_team_runner_load_balance_t *lb = &team->runner.lb;
			unsigned int i;
			ni_json_t *tx;
			int64_t i64;

			tx = ni_json_object_get_value(runner, "tx_hash");
			lb->config.tx_hash = NI_TEAM_TX_HASH_NONE;
			for (i = 0; i < ni_json_array_entries(tx); ++i) {
				if (ni_json_string_get(ni_json_array_get(tx, i), &name)) {
					ni_team_tx_hash_bit_t bit;

					if (ni_team_tx_hash_name_to_bit(name, &bit))
						lb->config.tx_hash |= (1 << bit);
					ni_string_free(&name);
				}
			}

			tx = ni_json_object_get_value(runner, "tx_balancer");
			/* tx_balancer.name is currently always "basic" */
			if (ni_json_int64_get(ni_json_object_get_value(tx, "balancing_interval"), &i64))
				lb->config.tx_balancer.interval = i64;
			else	lb->config.tx_balancer.interval = 50;
		}
		break;

	case NI_TEAM_RUNNER_LACP: {
			ni_team_runner_lacp_t *lacp = &team->runner.lacp;
			unsigned int i;
			ni_json_t *tx;
			ni_bool_t b;
			int64_t i64;

			if (ni_json_bool_get(ni_json_object_get_value(runner, "active"), &b))
				lacp->config.active = b;
			else	lacp->config.active = TRUE;

			if (ni_json_int64_get(ni_json_object_get_value(runner, "sys_prio"), &i64))
				lacp->config.sys_prio = i64;
			else	lacp->config.sys_prio = 65535;

			if (ni_json_bool_get(ni_json_object_get_value(runner, "fast_rate"), &b))
				lacp->config.fast_rate = b;
			else	lacp->config.fast_rate = FALSE;

			if (ni_json_int64_get(ni_json_object_get_value(runner, "min_ports"), &i64))
				lacp->config.min_ports = i64;
			else	lacp->config.min_ports = 0;

			if (ni_json_int64_get(ni_json_object_get_value(runner, "agg_select_policy"), &i64))
				lacp->config.select_policy = i64;
			else	lacp->config.select_policy = NI_TEAM_LACP_SELECT_POLICY_PRIO;

			tx = ni_json_object_get_value(runner, "tx_hash");
			lacp->config.tx_hash = NI_TEAM_TX_HASH_NONE;
			for (i = 0; i < ni_json_array_entries(tx); ++i) {
				if (ni_json_string_get(ni_json_array_get(tx, i), &name)) {
					ni_team_tx_hash_bit_t bit;

					if (ni_team_tx_hash_name_to_bit(name, &bit))
						lacp->config.tx_hash |= (1 << bit);
					ni_string_free(&name);
				}
			}

			tx = ni_json_object_get_value(runner, "tx_balancer");
			/* tx_balancer.name is currently always "basic" */
			if (ni_json_int64_get(ni_json_object_get_value(tx, "balancing_interval"), &i64))
				lacp->config.tx_balancer.interval = i64;
			else	lacp->config.tx_balancer.interval = 50;
		}
		break;
	default:
		break;
	}

	return 0;
failure:
	ni_string_free(&name);
	return -1;
}

static int
ni_teamd_discover_link_watch_item_details(ni_team_link_watch_t *lw, ni_json_t *link_watch)
{
	int64_t i64;
	ni_bool_t b;

	/* return of -1 causes to fail completely, 1 permits to skip/ignore one item */
	switch(lw->type) {
	case NI_TEAM_LINK_WATCH_ETHTOOL:
		if (ni_json_int64_get(ni_json_object_get_value(link_watch, "delay_up"), &i64))
			lw->ethtool.delay_up = i64;
		if (ni_json_int64_get(ni_json_object_get_value(link_watch, "delay_down"), &i64))
			lw->ethtool.delay_down = i64;
		break;

	case NI_TEAM_LINK_WATCH_ARP_PING:
		if (!ni_json_string_get(ni_json_object_get_value(link_watch, "target_host"), &lw->arp.target_host))
			return 1;
		ni_json_string_get(ni_json_object_get_value(link_watch, "source_host"), &lw->arp.source_host);
		if (ni_json_int64_get(ni_json_object_get_value(link_watch, "interval"), &i64))
			lw->arp.interval = i64;
		if (ni_json_int64_get(ni_json_object_get_value(link_watch, "init_wait"), &i64))
			lw->arp.init_wait = i64;
		if (ni_json_bool_get(ni_json_object_get_value(link_watch, "validate_active"), &b))
			lw->arp.validate_active= b;
		if (ni_json_bool_get(ni_json_object_get_value(link_watch, "validate_inactive"), &b))
			lw->arp.validate_inactive= b;
		if (ni_json_bool_get(ni_json_object_get_value(link_watch, "send_always"), &b))
			lw->arp.send_always= b;
		if (ni_json_int64_get(ni_json_object_get_value(link_watch, "missed_max"), &i64))
			lw->arp.missed_max= i64;
		break;

	case NI_TEAM_LINK_WATCH_NSNA_PING:
		if (!ni_json_string_get(ni_json_object_get_value(link_watch, "target_host"), &lw->nsna.target_host))
			return 1;
		if (ni_json_int64_get(ni_json_object_get_value(link_watch, "interval"), &i64))
			lw->nsna.interval = i64;
		if (ni_json_int64_get(ni_json_object_get_value(link_watch, "init_wait"), &i64))
			lw->nsna.init_wait = i64;
		if (ni_json_int64_get(ni_json_object_get_value(link_watch, "missed_max"), &i64))
			lw->nsna.missed_max= i64;
		break;

	case NI_TEAM_LINK_WATCH_TIPC:
		ni_json_string_get(ni_json_object_get_value(link_watch, "tipc_bearer"), &lw->tipc.bearer);
		break;

	default:
		return 1;
	}

	return 0;
}

static int
ni_teamd_discover_link_watch_item(ni_team_link_watch_array_t *array, ni_json_t *link_watch)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_team_link_watch_type_t lwt;
	ni_team_link_watch_t *lw = NULL;
	char * name = NULL;
	int ret = -1;

	if (!ni_json_string_get(ni_json_object_get_value(link_watch, "name"), &name))
		goto failure;

	if (!ni_team_link_watch_name_to_type(name, &lwt))
		goto failure;

	if (!(lw = ni_team_link_watch_new(lwt)))
		goto failure;

	/* a -1 to fail completely, 1 to skip/ignore one item */
	if ((ret = ni_teamd_discover_link_watch_item_details(lw, link_watch)))
		goto failure;

	if (!ni_team_link_watch_array_append(array, lw))
		goto failure;

	ni_string_free(&name);
	return 0;

failure:
	ni_json_format_string(&buf, link_watch, NULL);
	ni_error("Unable to discover link_watch item: %s", buf.string);
	ni_stringbuf_destroy(&buf);
	ni_team_link_watch_free(lw);
	ni_string_free(&name);
	return ret;
}

static int
ni_teamd_discover_link_watch(ni_team_t *team, ni_json_t *conf)
{
	ni_json_t *link_watch;

	if (!team || !conf)
		goto failure;

	if (!(link_watch = ni_json_object_get_value(conf, "link_watch")))
		return 0;

	if (ni_json_is_array(link_watch)) {
		unsigned int i, count;

		count = ni_json_array_entries(link_watch);
		for (i = 0; i < count; ++i) {
			ni_json_t *w = ni_json_array_get(link_watch, i);

			if (ni_teamd_discover_link_watch_item(&team->link_watch, w) < 0)
				goto failure;
		}

		return 0;
	} else
	if (ni_json_is_object(link_watch)) {
		if (ni_teamd_discover_link_watch_item(&team->link_watch, link_watch) < 0)
			goto failure;

		return 0;
	}

failure:
	ni_error("Unable to discover link_watch");
	return -1;
}

static int
ni_teamd_discover_port_details(ni_team_port_t *port, ni_json_t *details)
{
	int64_t i64;

	if (!ni_json_is_object(details))
		return 1;

	if (ni_json_int64_get(ni_json_object_get_value(details, "queue_id"), &i64))
			port->config.queue_id = i64;

	return 0;
}

static int
ni_teamd_discover_ports(ni_team_t *team, ni_json_t *conf)
{
	ni_team_port_t *port;
	ni_json_t *ports;
	unsigned int i, count;

	if (!team || !conf)
		return -1;

	if (!(ports = ni_json_object_get_value(conf, "ports")))
		return 0;

	if (!ni_json_is_object(ports))
		return 1;

	count = ni_json_object_entries(ports);
	for (i = 0; i < count; ++i) {
		ni_json_pair_t *pair;
		ni_json_t *details;
		const char *name;

		if (!(pair = ni_json_object_get_pair_at(ports, i)))
			continue;

		name = ni_json_pair_get_name(pair);
		if (ni_string_empty(name))
			continue;
		port = ni_team_port_new();
		ni_netdev_ref_set_ifname(&port->device, name);

		details = ni_json_pair_get_value(pair);
		if (ni_teamd_discover_port_details(port, details) < 0) {
			ni_team_port_free(port);
			continue;
		}

		if (!ni_team_port_array_append(&team->ports, port)) {
			ni_team_port_free(port);
			continue;
		}
	}
	return 0;
}

int
ni_teamd_discover(ni_netdev_t *dev)
{
	ni_teamd_client_t *tdc = NULL;
	ni_json_t *conf = NULL;
	ni_team_t *team = NULL;
	const char *val;

	if (!dev || dev->link.type != NI_IFTYPE_TEAM)
		return -1;

	/* we are about to replace dev->team, so just
	 * allocate new one we can drop at any time */
	if (!(team = ni_team_new()))
		goto failure;

	if (!(tdc = ni_teamd_client_open(dev->name)))
		goto failure;

	if (!(val = ni_teamd_ctl_config_dump(tdc, TRUE)))
		goto failure;

	if (!(conf = ni_json_parse_string(val)))
		goto failure;

	if (ni_teamd_discover_runner(team, conf) < 0)
		goto failure;

	if (ni_teamd_discover_link_watch(team, conf) < 0)
		goto failure;

	if (ni_teamd_discover_ports(team, conf) < 0)
		goto failure;

	ni_netdev_set_team(dev, team);
	ni_teamd_client_free(tdc);
	ni_json_free(conf);
	return 0;

failure:
	ni_json_free(conf);
	ni_team_free(dev->team);
	ni_teamd_client_free(tdc);
	return -1;
}

/*
 * teamd startup config file
 */
const char *
ni_teamd_config_file_name(char **filename, const char *instance)
{
	return ni_string_printf(filename, NI_TEAMD_CONFIG_FMT, instance);
}

ni_json_t *
ni_teamd_config_json_runner(const ni_team_runner_t *runner)
{
	ni_json_t *object = ni_json_new_object();

	ni_json_object_set(object, "name", ni_json_new_string(
		ni_team_runner_type_to_name(runner->type)
	));

	switch (runner->type) {
	case NI_TEAM_RUNNER_ROUND_ROBIN:
		break;
	case NI_TEAM_RUNNER_ACTIVE_BACKUP: {
			const ni_team_runner_active_backup_t *ab = &runner->ab;

			ni_json_object_set(object, "hwaddr_policy", ni_json_new_string(
				ni_team_ab_hwaddr_policy_type_to_name(ab->config.hwaddr_policy)
			));
		}
		break;
	case NI_TEAM_RUNNER_LOAD_BALANCE: {
			const ni_team_runner_load_balance_t *lb = &runner->lb;
			ni_string_array_t names = NI_STRING_ARRAY_INIT;
			unsigned int i;

			if (ni_team_tx_hash_get_bit_names(lb->config.tx_hash, &names)) {
				ni_json_t *txh = ni_json_new_array();

				for (i = 0; i < names.count; ++i) {
					ni_json_array_append(txh, ni_json_new_string(names.data[i]));
				}
				ni_json_object_set(object, "tx_hash", txh);
			}
			if (lb->config.tx_balancer.interval) {
				ni_json_t *txb = ni_json_new_object();

				ni_json_object_set(txb, "name", ni_json_new_string(
					ni_team_tx_balancer_type_to_name(lb->config.tx_balancer.type)
				));
				ni_json_object_set(txb, "balancing_interval", ni_json_new_int64(
					lb->config.tx_balancer.interval
				));
				ni_json_object_set(object, "tx_balancer", txb);
			}
		}
		break;
	case NI_TEAM_RUNNER_BROADCAST:
		break;
	case NI_TEAM_RUNNER_RANDOM:
		break;
	case NI_TEAM_RUNNER_LACP: {
			const ni_team_runner_lacp_t *lacp = &runner->lacp;
			ni_string_array_t names = NI_STRING_ARRAY_INIT;
			unsigned int i;

			if (!lacp->config.active) {
				ni_json_object_set(object, "active", ni_json_new_bool(
					lacp->config.active
				));
			}
			if (lacp->config.sys_prio > 0 && lacp->config.sys_prio < 65535) {
				ni_json_object_set(object, "sys_prio", ni_json_new_int64(
					lacp->config.sys_prio
				));
			}
			if (lacp->config.fast_rate) {
				ni_json_object_set(object, "fast_rate", ni_json_new_bool(
					lacp->config.fast_rate
				));
			}
			if (lacp->config.min_ports > 0 && lacp->config.min_ports < 256) {
				ni_json_object_set(object, "min_ports", ni_json_new_int64(
					lacp->config.min_ports
				));
			}
			if (lacp->config.select_policy) {
				ni_json_object_set(object, "agg_select_policy", ni_json_new_string(
					ni_team_lacp_select_policy_type_to_name(lacp->config.select_policy)
				));
			}
			if (ni_team_tx_hash_get_bit_names(lacp->config.tx_hash, &names)) {
				ni_json_t *txh = ni_json_new_array();

				for (i = 0; i < names.count; ++i) {
					ni_json_array_append(txh, ni_json_new_string(names.data[i]));
				}
				ni_json_object_set(object, "tx_hash", txh);
			}
			if (lacp->config.tx_balancer.interval) {
				ni_json_t *txb = ni_json_new_object();

				ni_json_object_set(txb, "name", ni_json_new_string(
					ni_team_tx_balancer_type_to_name(lacp->config.tx_balancer.type)
				));
				ni_json_object_set(txb, "balancing_interval", ni_json_new_int64(
					lacp->config.tx_balancer.interval
				));
				ni_json_object_set(object, "tx_balancer", txb);
			}
		}
		break;
	default:
		ni_json_free(object);
		return NULL;
	}
	return object;
}

ni_json_t *
ni_teamd_config_json_link_watch_item(const ni_team_link_watch_t *lw)
{
	ni_json_t *object;
	const char *name;

	if (!lw || !(name = ni_team_link_watch_type_to_name(lw->type)))
		return NULL;

	if (!(object = ni_json_new_object()))
		return NULL;

	ni_json_object_set(object, "name", ni_json_new_string(name));
	switch (lw->type) {
	case NI_TEAM_LINK_WATCH_TIPC: {
			const ni_team_link_watch_tipc_t *t = &lw->tipc;

			if (!ni_string_empty(t->bearer)) {
				ni_json_object_set(object, "tipc_bearer", ni_json_new_string(t->bearer));
			}
		}
		break;

	case NI_TEAM_LINK_WATCH_ETHTOOL: {
			const ni_team_link_watch_ethtool_t *e = &lw->ethtool;

			if (e->delay_up) {
				ni_json_object_set(object, "delay_up", ni_json_new_int64(e->delay_up));
			}
			if (e->delay_down) {
				ni_json_object_set(object, "delay_down", ni_json_new_int64(e->delay_down));
			}
		}
		break;

	case NI_TEAM_LINK_WATCH_ARP_PING: {
			const ni_team_link_watch_arp_t *a = &lw->arp;

			if (!ni_string_empty(a->source_host)) {
				ni_json_object_set(object, "source_host", ni_json_new_string(a->source_host));
			}
			if (!ni_string_empty(a->target_host)) {
				ni_json_object_set(object, "target_host", ni_json_new_string(a->target_host));
			}
			if (a->interval > 0) {
				ni_json_object_set(object, "interval", ni_json_new_int64(a->interval));
			}
			if (a->init_wait > 0) {
				ni_json_object_set(object, "init_wait", ni_json_new_int64(a->init_wait));
			}
			if (a->validate_active) {
				ni_json_object_set(object, "validate_active", ni_json_new_bool(a->validate_active));
			}
			if (a->validate_inactive) {
				ni_json_object_set(object, "validate_inactive", ni_json_new_bool(a->validate_inactive));
			}
			if (a->send_always) {
				ni_json_object_set(object, "send_always", ni_json_new_bool(a->send_always));
			}
			if (a->missed_max) {
				ni_json_object_set(object, "missed_max", ni_json_new_int64(a->missed_max));
			}
		}
		break;

	case NI_TEAM_LINK_WATCH_NSNA_PING: {
			const ni_team_link_watch_nsna_t *n = &lw->nsna;

			if (!ni_string_empty(n->target_host)) {
				ni_json_object_set(object, "target_host", ni_json_new_string(n->target_host));
			}
			if (n->interval > 0) {
				ni_json_object_set(object, "interval", ni_json_new_int64(n->interval));
			}
			if (n->init_wait > 0) {
				ni_json_object_set(object, "init_wait", ni_json_new_int64(n->init_wait));
			}
			if (n->missed_max) {
				ni_json_object_set(object, "missed_max", ni_json_new_int64(n->missed_max));
			}
		}
		break;

	default:
		break;
	}

	return object;
}

ni_json_t *
ni_teamd_config_json_link_watch(const ni_team_link_watch_array_t *link_watch)
{
	const ni_team_link_watch_t *lw;
	unsigned int i;

	if (!link_watch || !link_watch->count)
		return NULL;

	if (link_watch->count == 1) {
		lw = link_watch->data[0];

		return ni_teamd_config_json_link_watch_item(lw);
	} else {
		ni_json_t *array = ni_json_new_array();
		ni_json_t *object;

		for (i = 0; i < link_watch->count; ++i) {
			lw = link_watch->data[i];

			object = ni_teamd_config_json_link_watch_item(lw);
			if (object)
				ni_json_array_append(array, object);
		}
		return array;
	}
}

int
ni_teamd_config_file_dump(FILE *fp, const char *instance, const ni_team_t *config)
{
	ni_stringbuf_t dump = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_t *object, *child;

	if (!fp || ni_string_empty(instance) || !config)
		return -1;

	object = ni_json_new_object();

	ni_json_object_set(object, "device", ni_json_new_string(instance));

	if (!(child = ni_teamd_config_json_runner(&config->runner)))
		goto failure;
	ni_json_object_set(object, "runner", child);

	if (config->link_watch.count) {
		if (!(child = ni_teamd_config_json_link_watch(&config->link_watch)))
			goto failure;
		ni_json_object_set(object, "link_watch",  child);
	}

	if (!ni_json_format_string(&dump, object, NULL))
		goto failure;

	if (fprintf(fp, "%s\n", dump.string) < 0)
		goto failure;

	ni_stringbuf_destroy(&dump);
	ni_json_free(object);
	return 0;

failure:
	ni_stringbuf_destroy(&dump);
	ni_json_free(object);
	return -1;
}

int
ni_teamd_config_file_write(const char *instance, const ni_team_t *config)
{
	char *filename = NULL;
	char tempname[PATH_MAX] = {'\0'};
	FILE *fp = NULL;
	int fd;

	if (ni_string_empty(instance) || !config)
		return -1;

	if (!ni_teamd_config_file_name(&filename, instance)) {
		ni_error("%s: cannot create teamd config file name", instance);
		return -1;
	}

	snprintf(tempname, sizeof(tempname), "%s.XXXXXX", filename);
	if ((fd = mkstemp(tempname)) < 0) {
		ni_error("%s: cannot create temporary teamd config '%s': %m", instance, tempname);
		free(filename);
		return -1;
	}

	if ((fp = fdopen(fd, "we")) == NULL) {
		ni_error("%s: cannot reopen temporary teamd config '%s': %m", instance, tempname);
		close(fd);
		unlink(tempname);
		free(filename);
		return -1;
	}

	if (ni_teamd_config_file_dump(fp, instance, config) < 0) {
		ni_error("%s: unable to generate teamd config file for '%s'", instance, filename);
		fclose(fp);
		unlink(tempname);
		free(filename);
		return -1;
	}
	fflush(fp);
	fclose(fp);

	if ((fd = rename(tempname, filename)) != 0) {
		ni_error("%s: unable to commit teamd config file to '%s'", instance, filename);
		unlink(tempname);
		free(filename);
		return -1;
	}

	ni_debug_ifconfig("%s: teamd config file written to '%s'", instance, filename);
        free(filename);
	return 0;
}

int
ni_teamd_config_file_remove(const char *instance)
{
	char *filename = NULL;
	int ret;

	if (!ni_teamd_config_file_name(&filename, instance))
		return -1;

	ret = unlink(filename);
	free(filename);
	return ret;
}

const char *ni_systemctl_tool_path()
{
	static const char *paths[] = {
		"/usr/bin/systemctl",
		"/bin/systemctl",
		NULL
	};
	return ni_find_executable(paths);
}

/*
 * teamd systemd instance service methods
 */
int
ni_teamd_service_start(const char *instance, const ni_team_t *config)
{
	const char *systemctl;
	char *service = NULL;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv;

	if (ni_string_empty(instance) || !config)
		return -1;

	if (!(systemctl = ni_systemctl_tool_path()))
		return -1;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return -1;

	if (!ni_shellcmd_add_arg(cmd, systemctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "start"))
		goto failure;

	ni_string_printf(&service, "teamd@%s.service", instance);
	if (!service || !ni_shellcmd_add_arg(cmd, service))
		goto failure;

	if (ni_teamd_config_file_write(instance, config) < 0)
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;
	ni_shellcmd_release(cmd);

	rv = ni_process_run_and_wait(pi);
	ni_process_free(pi);
	free(service);

	return rv;

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	if (service)
		free(service);
	return -1;
}

int
ni_teamd_service_stop(const char *instance)
{
	const char *systemctl;
	char *service = NULL;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv;

	if (ni_string_empty(instance))
		return -1;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return -1;

	if (!(systemctl = ni_systemctl_tool_path()))
		return -1;

	if (!ni_shellcmd_add_arg(cmd, systemctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "stop"))
		goto failure;

	ni_string_printf(&service, "teamd@%s.service", instance);
	if (!service || !ni_shellcmd_add_arg(cmd, service))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;
	ni_shellcmd_release(cmd);

	rv = ni_process_run_and_wait(pi);
	ni_process_free(pi);

	ni_teamd_config_file_remove(instance);
	free(service);

	return rv;

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	if (service)
		free(service);
	return -1;
}

