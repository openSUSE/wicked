/*
 *	wicked client ifup action and utilities
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/socket.h>
#include <wicked/fsm.h>

#include "client/ifconfig.h"

#include "wicked-client.h"
#include "appconfig.h"
#include "ifup.h"
#include "ifstatus.h"

struct ni_nanny_fsm_monitor {
	const ni_timer_t *      timer;
	ni_timeout_t		timeout;
	ni_ifworker_array_t *	marked;
};

static ni_bool_t
ni_ifup_generate_match_device(xml_node_t *node, ni_ifworker_t *w)
{
	/*
	 * Generate <device>${w->name}</device> match (self reference) node.
	 */
	if (!node || !w || ni_string_empty(w->name))
		return FALSE;

	return !!xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_DEV, node, w->name);
}

static ni_bool_t
ni_ifup_generate_match_device_ref(xml_node_t *match, const char *name)
{
	xml_node_t *ref;

	/*
	 * Generate <reference><device>${name}</device></reference>
	 * match node to a related (lower, master, …) interface name.
	 */
	if (!match || ni_string_empty(name))
		return FALSE;

	if (!(ref = xml_node_new(NI_NANNY_IFPOLICY_MATCH_REF, match)))
		return FALSE;

	if (xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_DEV, ref, name))
		return TRUE;

	xml_node_detach(ref);
	xml_node_free(ref);
	return FALSE;
}

static ni_bool_t
ni_ifup_generate_match_lower_ref(xml_node_t *match, ni_ifworker_t *w)
{
	/*
	 * If we have a lower/underlying interface (e.g. lower=bond0)
	 * reference and our (e.g. vlan bond0.42) interface can't
	 * be setup or even can't be created or exist without it,
	 * e.g.:
	 *     ip link add dev bond0.42 link bond0 type vlan id 42
	 *
	 * In the config, the lower reference does not have a fix
	 * node name, but is provided by type specific nodes, e.g.
	 * for vlan|macvlan:
	 *     <vlan|macvlan|…>
	 *       <device>${w->lowerdev}</device>
	 *     </vlan|macvlan|…>
	 * for ovs vlan (fake) bridge's parent bridge:
	 *     <ovs-bridge>
	 *       <vlan>
	 *         <parent>${w->lowerdev}</device>
	 *       </vlan>
	 *     </ovs-bridge>
	 *
	 * The w->lowerdev points to the worker resolved from the
	 * config by fsm while (config) hierarchy build, so we
	 * don't need to "find it manually".
	 */
	if (!w->lowerdev)
		return TRUE;

	return ni_ifup_generate_match_device_ref(match, w->lowerdev->name);
}

static ni_bool_t
ni_ifup_generate_match_master_ref(xml_node_t *match, ni_ifworker_t *w)
{
	/*
	 * If we are a port (e.g. bond0.42 vlan) bound to a master
	 * (e.g. br42 bridge) required for the link setup, e.g.:
	 *     ip link set dev bond0.42 master br42
	 *
	 * The <link> node provides a typed port union:
	 *   <link>
	 *     <master>${w->masterdev}</master>
	 *     <port type="${type-name}">${type-data}</port>
	 *   </link>
	 *
	 * The port type is the type of the effective master and
	 * its content is type specific port configuration node.
	 *
	 * The w->masterdev points to the worker resolved from the
	 * config by fsm while (config) hierarchy build, so we
	 * don't need to "find it manually".
	 */
	if (!w->masterdev)
		return TRUE;

	return ni_ifup_generate_match_device_ref(match, w->masterdev->name);
}

static ni_bool_t
ni_ifup_generate_match_refs(xml_node_t *match, ni_ifworker_t *w)
{
	/*
	 * Some interface types may have a lower (underlying)
	 * interface and (most) can be also bound as port to
	 * an another master reference.
	 */
	if (!ni_ifup_generate_match_lower_ref(match, w))
		return FALSE;

	if (!ni_ifup_generate_match_master_ref(match, w))
		return FALSE;

	return TRUE; /* no refa is not an error */
}

static xml_node_t *
ni_ifup_generate_match(const char *name, ni_ifworker_t *w)
{
	xml_node_t *match;

	if (!(match = xml_node_new(name, NULL)))
		goto error;

	ni_debug_wicked_xml(w->config.node, NI_LOG_DEBUG,
		"generate policy match for %s (type %s)", w->name,
		ni_linktype_type_to_name(w->iftype));

	if (!ni_ifup_generate_match_device(match, w)) {
		ni_error("%s: unable to generate policy device match",
				w->name);
		goto error;
	}

	/*
	 * The ovs-system datapath does not have any
	 * (should not have any) references to other
	 * interfaces...
	 */
	if (w->iftype == NI_IFTYPE_OVS_SYSTEM ||
	    ni_string_eq(w->name, ni_linktype_type_to_name(NI_IFTYPE_OVS_SYSTEM)))
		goto done;

	if (!ni_ifup_generate_match_refs(match, w)) {
		ni_error("%s: unable to generate policy device reference match",
				w->name);
		goto error;
	}

done:
	return match;
error:
	xml_node_free(match);
	return NULL;
}

static ni_bool_t
ni_ifup_start_policy(ni_ifworker_t *w)
{
	xml_node_t *match, *policy = NULL;
	ni_bool_t rv = FALSE;
	char *pname;

	if (!w || !w->config.node)
		return rv;

	ni_debug_application("%s: hiring nanny", w->name);

	match = ni_ifup_generate_match(NI_NANNY_IFPOLICY_MATCH, w);
	if (!match)
		goto error;

	pname  = ni_ifpolicy_name_from_ifname(w->name);
	ni_debug_application("%s: converting config into policy '%s'",
			w->name, pname);

	policy = ni_convert_cfg_into_policy_node(w->config.node, match,
			pname, w->config.meta.origin);
	ni_string_free(&pname);
	xml_node_free(match);
	if (!policy)
		goto error;

	ni_debug_application("%s: adding policy %s to nanny", w->name,
		xml_node_get_attr(policy, NI_NANNY_IFPOLICY_NAME));

	if (ni_nanny_addpolicy_node(policy, w->config.meta.origin) <= 0)
		goto error;

	ni_debug_application("%s: nanny hired!", w->name);
	ni_ifworker_success(w);

	rv = TRUE;

error:
	if (!rv)
		ni_ifworker_fail(w, "unable to apply configuration to nanny");
	xml_node_free(policy);
	return rv;
}

ni_bool_t
ni_ifup_hire_nanny(ni_ifworker_array_t *array, ni_bool_t set_persistent)
{
	unsigned int i;
	ni_bool_t rv = TRUE;
	ni_string_array_t names = NI_STRING_ARRAY_INIT;

	/* Send policies to nanny */
	for (i = 0; i < array->count; i++) {
		ni_ifworker_t *w = array->data[i];

		if (!w || xml_node_is_empty(w->config.node))
			continue;

		if (set_persistent)
			ni_client_state_set_persistent(w->config.node);

		if (!ni_ifup_start_policy(w))
			rv = FALSE;
		else {
			ni_info("%s: configuration applied to nanny", w->name);
			ni_string_array_append(&names, w->name);
		}
	}

	/* Recheck policies on modified devices */
	if (0 == array->count)
		ni_note("ifup: no matching interfaces");
	else
		ni_nanny_call_recheck(&names);

	ni_string_array_destroy(&names);
	return rv;
}

/*
 * Wickedd is sending us a signal indicating internal device state change.
 * We want to wait for this signal and when it is >= device-up return TRUE.
 * After timeout we fail...
 */
static ni_bool_t
ni_nanny_fsm_monitor_wait_by_startmode(ni_ifworker_t *worker)
{
	/*
	 * We don't need to wait for hotplug interfaces,
	 * but only for "boot" and "manual" (started by
	 * dedicated "ifup <name>" but not in "ifup all").
	 */
	if (ni_string_eq(worker->control.mode, "hotplug"))
		return FALSE;
	if (ni_string_eq(worker->control.mode, "ifplugd"))
		return FALSE;

	return TRUE;
}

static ni_bool_t
ni_nanny_fsm_monitor_remove_port(ni_ifworker_array_t *workers, ni_ifworker_t *port)
{
	/*
	 * A L2 master (bond,team,bridge,ovs-bridge) calculates it's
	 * link-up (carrier/up & running) state from it's ports using
	 * own logic (e.g. monitoring or stp) and usually requires one
	 * port only to inherit carrier itself.
	 *
	 * While a bond/team are HA constructs ("cable redundancy" to
	 * the same "peer" switch), bridge acts as switch and connects
	 * multiple ports (the broadcast domains / switches behind the
	 * "cable") with each other into one (broadcast domain[s] set).
	 * Note: A bridge with disabled STP is often mocking carrier,
	 * that is, it may report carrier even there is no port added.
	 *
	 * When master finished/reached it's target state, we can stop
	 * monitoring setup of it's hotplug ports, which are allowed to
	 * be missed completely, but in case a port is a non-hotplug one
	 * (what makes sense for bridges), we should NOT remove it from
	 * further monitoring.
	 *
	 * Both, hotplug and non-hotplug ports as well as the master
	 * itself, may be also configured to not require link aka to
	 * ignore carrier. In this case, the setup of the interface
	 * will finish earlier, but we still need to wait until the
	 * "up" run ignoring carrier finished for a non-hotplug port.
	 */
	if (ni_nanny_fsm_monitor_wait_by_startmode(port))
		return FALSE;

	return ni_ifworker_array_remove(workers, port);
}

static void
ni_nanny_fsm_monitor_remove_ports(ni_ifworker_array_t *workers, ni_ifworker_t *worker)
{
	ni_ifworker_t *port;
	unsigned int i;

	for (i = 0; i < workers->count; ) {
		port = workers->data[i];

		if (port->masterdev == worker &&
		    ni_nanny_fsm_monitor_remove_port(workers, port))
			continue;
		i++;
	}
}

static void
ni_nanny_fsm_monitor_remove_finished(ni_ifworker_array_t *workers, ni_ifworker_t *worker)
{
	ni_nanny_fsm_monitor_remove_ports(workers, worker);
	ni_ifworker_array_remove(workers, worker);
}

static void
ni_nanny_fsm_monitor_handler(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_dbus_variant_t argv = NI_DBUS_VARIANT_INIT;
	ni_nanny_fsm_monitor_t *monitor = user_data;
	ni_fsm_state_t cur_state, target_state;
	const char *ifname;
	unsigned int i;

	if (ni_string_empty(object_path) || !monitor || !monitor->marked)
		return;

	/* Deserialize dbus message */
	if (ni_dbus_message_get_args_variants(msg, &argv, 1) < 0 ||
	    !ni_dbus_variant_is_dict(&argv)) {
		ni_error("Unable to retrieve dict from signal %s,  object_path=%s",
			signal_name, object_path);
		return;
	}

	if (!ni_dbus_dict_get_uint32(&argv, "current-state", &cur_state) ||
	    !ni_dbus_dict_get_uint32(&argv, "target-state", &target_state) ||
	    !ni_dbus_dict_get_string(&argv, "ifname", &ifname)) {
		ni_error("Unable to retrieve dict's values from signal %s,  object_path=%s",
			signal_name, object_path);
		return;
	}

	ni_debug_application("received signal %s; object_path=%s; target_state=%s, state_name=%s",
		signal_name, object_path,  ni_ifworker_state_name(target_state),
		ni_ifworker_state_name(cur_state));

	for (i = 0; i < monitor->marked->count; ++i) {
		ni_ifworker_t *w = monitor->marked->data[i];

		if (cur_state != NI_FSM_STATE_NONE && cur_state != target_state)
			continue;

		if (!ni_string_eq(w->name, ifname))
			continue;

		ni_nanny_fsm_monitor_remove_finished(monitor->marked, w);
		break;
	}

	ni_dbus_variant_destroy(&argv);
}

void
ni_nanny_fsm_monitor_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_nanny_fsm_monitor_t *monitor = user_data;

	if (monitor && timer == monitor->timer) {
		monitor->timer = NULL;
		monitor->timeout = 0;
		ni_info("Interface wait time reached");
	}
}

ni_nanny_fsm_monitor_t *
ni_nanny_fsm_monitor_new(ni_fsm_t *fsm)
{
	ni_nanny_fsm_monitor_t *monitor;
	ni_dbus_client_t *client;

	if (!fsm)
		return NULL;

	if (!(fsm->client_root_object = ni_call_create_client()))
		return NULL;

	if (!(client = ni_dbus_object_get_client(fsm->client_root_object)))
		return NULL;

	monitor = calloc(1, sizeof(*monitor));
	if (monitor) {
		ni_dbus_client_add_signal_handler(client, NULL, NULL,
				NI_OBJECTMODEL_MANAGED_NETIF_INTERFACE,
				ni_nanny_fsm_monitor_handler, monitor);
	}
	return monitor;
}

ni_bool_t
ni_nanny_fsm_monitor_arm(ni_nanny_fsm_monitor_t *monitor, ni_timeout_t timeout)
{
	if (monitor) {
		monitor->timeout = timeout;
		if (monitor->timer)
			monitor->timer = ni_timer_rearm(monitor->timer, timeout);
		else
			monitor->timer = ni_timer_register(timeout,
					ni_nanny_fsm_monitor_timeout, monitor);
		return monitor->timer != NULL;
	}
	return FALSE;
}

void
ni_nanny_fsm_monitor_run(ni_nanny_fsm_monitor_t *monitor, ni_ifworker_array_t *marked, int status)
{
	if (!monitor || monitor->marked || !marked)
		return;

	monitor->marked = ni_ifworker_array_clone(marked);
	while (!ni_caught_terminal_signal()) {
		ni_timeout_t timeout;

		if (!monitor->marked || !monitor->marked->count)
			break;

		timeout = ni_timer_next_timeout();
		if (monitor->timeout == 0 ||
		    (monitor->timeout > 0 && timeout == NI_TIMEOUT_INFINITE))
			break;

		if (ni_socket_wait(timeout) != 0)
			break;
	}

	if (monitor->timer) {
		ni_timer_cancel(monitor->timer);
		monitor->timer = NULL;
	}
}

void
ni_nanny_fsm_monitor_reset(ni_nanny_fsm_monitor_t *monitor)
{
	if (monitor) {
		monitor->timeout = 0;
		if (monitor->timer) {
			ni_timer_cancel(monitor->timer);
			monitor->timer = NULL;
		}
		ni_ifworker_array_free(monitor->marked);
		monitor->marked = NULL;
	}
}

void
ni_nanny_fsm_monitor_free(ni_nanny_fsm_monitor_t *monitor)
{
	ni_nanny_fsm_monitor_reset(monitor);
	free(monitor);
}

int
ni_do_ifup(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_IFCONFIG, OPT_CONTROL_MODE, OPT_STAGE, OPT_TIMEOUT,
		OPT_SKIP_ACTIVE, OPT_SKIP_ORIGIN, OPT_PERSISTENT, OPT_TRANSIENT,
		OPT_DRY_RUN,
#ifdef NI_TEST_HACKS
		OPT_IGNORE_PRIO, OPT_IGNORE_STARTMODE,
#endif
	};

	static struct option ifup_options[] = {
		{ "help",	no_argument,       NULL,	OPT_HELP },
		{ "ifconfig",	required_argument, NULL,	OPT_IFCONFIG },
		{ "mode",	required_argument, NULL,	OPT_CONTROL_MODE },
		{ "boot-stage",	required_argument, NULL,	OPT_STAGE },
		{ "skip-active",required_argument, NULL,	OPT_SKIP_ACTIVE },
		{ "skip-origin",required_argument, NULL,	OPT_SKIP_ORIGIN },
		{ "timeout",	required_argument, NULL,	OPT_TIMEOUT },
		{ "transient", 	no_argument,		NULL,	OPT_TRANSIENT },
#ifdef NI_TEST_HACKS
		{ "ignore-prio",no_argument, NULL,	OPT_IGNORE_PRIO },
		{ "ignore-startmode",no_argument, NULL,	OPT_IGNORE_STARTMODE },
#endif
		{ "persistent",	no_argument, NULL,	OPT_PERSISTENT },
		{ "dry-run",	no_argument, NULL,	OPT_DRY_RUN },
		{ NULL }
	};

	ni_ifmatcher_t ifmatch;
	ni_ifworker_array_t ifmarked = NI_IFWORKER_ARRAY_INIT;
	ni_nanny_fsm_monitor_t *monitor = NULL;
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	ni_bool_t check_prio = TRUE, set_persistent = FALSE;
	ni_bool_t opt_transient = FALSE;
	ni_log_fn_t *dry_run = NULL;
	int c, status = NI_WICKED_RC_USAGE;
	unsigned int seconds = 0;
	ni_fsm_t *fsm;

	fsm = ni_fsm_new();
	ni_assert(fsm);
	ni_fsm_require_register_type("reachable", ni_ifworker_reachability_check_new);

	/* Allow ifup on all interfaces we have config for */
	memset(&ifmatch, 0, sizeof(ifmatch));
	ifmatch.require_configured = FALSE;
	ifmatch.allow_persistent = TRUE;
	ifmatch.require_config = TRUE;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			ni_string_array_append(&opt_ifconfig, optarg);
			break;

		case OPT_CONTROL_MODE:
			ifmatch.mode = optarg;
			break;

		case OPT_STAGE:
			ifmatch.boot_stage= optarg;
			break;

		case OPT_TIMEOUT:
			if (ni_parse_seconds_timeout(optarg, &seconds)) {
				ni_error("ifup: cannot parse timeout option \"%s\"", optarg);
				goto usage;
			}
			break;

		case OPT_SKIP_ORIGIN:
			ifmatch.skip_origin = optarg;
			break;

		case OPT_SKIP_ACTIVE:
			ifmatch.skip_active = TRUE;
			break;

#ifdef NI_TEST_HACKS
		case OPT_IGNORE_PRIO:
			check_prio = FALSE;
			break;

		case OPT_IGNORE_STARTMODE:
			ifmatch.ignore_startmode = TRUE;
			break;
#endif

		case OPT_TRANSIENT:
			opt_transient = TRUE;
			break;

		case OPT_PERSISTENT:
			set_persistent = TRUE;
			break;

		case OPT_DRY_RUN:
			dry_run = ni_note;
			break;

		default:
		case OPT_HELP:
usage:
			fprintf(stderr,
				"wicked [options] ifup [ifup-options] <ifname ...>|all\n"
				"\nSupported ifup-options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --transient\n"
				"      Enable transient interface return codes\n"
				"  --ifconfig <pathname>\n"
				"      Read interface configuration(s) from file/directory rather than using system config\n"
				"  --mode <label>\n"
				"      Only touch interfaces with matching control <mode>\n"
				"  --boot-stage <label>\n"
				"      Only touch interfaces with matching <boot-stage>\n"
				"  --skip-active\n"
				"      Do not touch running interfaces\n"
				"  --skip-origin <name>\n"
				"      Skip interfaces that have a configuration origin of <name>\n"
				"      Usually, you would use this with the name \"firmware\" to avoid\n"
				"      touching interfaces that have been set up via firmware (like iBFT) previously\n"
				"  --timeout <sec>\n"
				"      Timeout after <sec> seconds\n"
#ifdef NI_TEST_HACKS
				"  --ignore-prio\n"
				"      Ignore checking the config origin priorities\n"
				"  --ignore-startmode\n"
				"      Ignore checking the STARTMODE=off and STARTMODE=manual configs\n"
#endif
				"  --persistent\n"
				"      Set interface into persistent mode (no regular ifdown allowed)\n"
				"  --dry-run\n"
				"      Show interface hierarchies as notice with (+) markers and exit.\n"
				);
			goto cleanup;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}

	if (!(monitor = ni_nanny_fsm_monitor_new(fsm)) || !ni_fsm_refresh_state(fsm)) {
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	if (opt_ifconfig.count == 0) {
		const ni_string_array_t *sources = ni_config_sources("ifconfig");

		if (sources && sources->count)
			ni_string_array_copy(&opt_ifconfig, sources);

		if (opt_ifconfig.count == 0) {
			ni_error("ifup: unable to load interface config source list");
			status = NI_WICKED_RC_NOT_CONFIGURED;
			goto cleanup;
		}
	}

	if (!ni_ifconfig_load(fsm, opt_global_rootdir, &opt_ifconfig, check_prio, TRUE)) {
		status = NI_WICKED_RC_NOT_CONFIGURED;
		goto cleanup;
	}

	/* Set timeout how long the action is allowed to wait */
	if (seconds) {
		fsm->worker_timeout = NI_TIMEOUT_FROM_SEC(seconds);
	} else
	if (ni_wait_for_interfaces) {
		fsm->worker_timeout = ni_fsm_find_max_timeout(fsm,
				NI_TIMEOUT_FROM_SEC(ni_wait_for_interfaces));
	} else {
		fsm->worker_timeout = ni_fsm_find_max_timeout(fsm,
				NI_IFWORKER_DEFAULT_TIMEOUT);
	}

	if (fsm->worker_timeout == NI_IFWORKER_INFINITE_TIMEOUT)
		ni_debug_application("wait for interfaces infinitely");
	else
		ni_debug_application("wait %u seconds for interfaces",
					NI_TIMEOUT_SEC(fsm->worker_timeout));

	ni_nanny_fsm_monitor_arm(monitor, fsm->worker_timeout);

	if (ni_fsm_build_hierarchy(fsm, TRUE) < 0) {
		ni_error("ifup: unable to build interface hierarchy");
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	/* Get workers that match given criteria */
	status = NI_WICKED_RC_SUCCESS;
	while (optind < argc) {
		ifmatch.name = argv[optind++];

		if (!strcmp(ifmatch.name, "boot")) {
			ifmatch.name = "all";
			ifmatch.mode = "boot";
		}

		ni_fsm_get_matching_workers(fsm, &ifmatch, &ifmarked);

		if (ni_string_eq(ifmatch.name, "all") ||
		    ni_string_empty(ifmatch.name)) {
			ni_string_array_destroy(&ifnames);
			break;
		}

		if (ni_string_array_index(&ifnames, ifmatch.name) < 0)
			ni_string_array_append(&ifnames, ifmatch.name);
	}

	ni_fsm_print_system_hierarchy(fsm, NULL, dry_run);
	ni_fsm_print_config_hierarchy(fsm, &ifmarked, dry_run);
	if (dry_run)
		goto cleanup;

	if (!ni_ifup_hire_nanny(&ifmarked, set_persistent))
		status = NI_WICKED_RC_NOT_CONFIGURED;

	/* Wait for device up-transition progress events */
	ni_nanny_fsm_monitor_run(monitor, &ifmarked, status);

	ni_fsm_wait_tentative_addrs(fsm);

	status = ni_ifstatus_display_result(fsm, &ifnames, &ifmarked,
		opt_transient);

	/*
	 * Do not report any errors to systemd -- returning an error
	 * here, will cause systemd to stop the network completely.
	 */
	if (opt_systemd)
		status = NI_LSB_RC_SUCCESS;

cleanup:
	ni_string_array_destroy(&ifnames);
	ni_nanny_fsm_monitor_free(monitor);
	ni_ifworker_array_destroy(&ifmarked);
	ni_string_array_destroy(&opt_ifconfig);
	ni_fsm_free(fsm);
	return status;
}

