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
#include <wicked/fsm.h>

#include "client/ifconfig.h"

#include "wicked-client.h"
#include "ifup.h"

static xml_node_t *
__ni_ifup_generate_match(ni_ifworker_t *w)
{
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	xml_node_t *match;
	unsigned int i;

	for (i = 0; i < w->children.count; i++) {
		ni_ifworker_t *child = w->children.data[i];

		ni_string_array_append(&ifnames, child->name);
	}

	/* If no references - match against own name */
	if (0 == w->children.count)
		ni_string_array_append(&ifnames, w->name);

	match = ni_ifpolicy_generate_match(&ifnames, NI_NANNY_IFPOLICY_MATCH_COND_OR);
	ni_string_array_destroy(&ifnames);

	return match;
}

static ni_bool_t
ni_ifup_hire_nanny(ni_ifworker_t *w)
{
	xml_node_t *ifcfg = NULL, *policy = NULL;
	ni_netdev_t *dev;
	unsigned int i;
	ni_bool_t rv = FALSE;

	if (!w)
		return rv;

	ni_debug_application("%s: hiring nanny", w->name);

	/* Create a config duplicate for a policy */
	ifcfg = xml_node_clone(w->config.node, NULL);
	if (!ifcfg)
		goto error;

	ni_debug_application("%s: converting config into policy", w->name);

	policy = ni_convert_cfg_into_policy_node(ifcfg, __ni_ifup_generate_match(w), w->name, w->config.origin);
	if (!policy) {
		policy = ifcfg; /* Free cloned config*/
		goto error;
	}

	/* Add link type to match node*/
	dev = w->device;
	if (dev) {
		ni_debug_application("%s: adding link type (%s) to match",
			w->name, ni_linktype_type_to_name(dev->link.type));
		ni_ifpolicy_match_add_link_type(policy, dev->link.type);
	}

#if 0
	ni_debug_application("%s: adding minimum device state (%s) to match",
		w->name, ni_ifworker_state_name(w->fsm.state));

	/* Add minimum device state to match node */
	if (!ni_ifpolicy_match_add_min_state(policy, w->fsm.state))
		goto error;
#endif

	if (dev) {
		ni_debug_application("%s: enabling device for nanny", w->name);
		if (!ni_nanny_call_device_enable(w->name))
			goto error;
	}

	ni_debug_application("%s: adding policy %s to nanny", w->name,
		xml_node_get_attr(policy, NI_NANNY_IFPOLICY_NAME));

	if (ni_nanny_addpolicy_node(policy, w->config.origin) <= 0) {
		ni_nanny_call_device_disable(w->name);
		goto error;
	}

	ni_debug_application("%s: nanny hired!", w->name);
	ni_ifworker_success(w);

	rv = TRUE;

error:
	if (!rv)
		ni_ifworker_fail(w, "%s: unable to apply configuration to nanny", w->name);
	xml_node_free(policy);
	return rv;
}


/*
 * Wickedd is sending us a signal indicating internal device state change.
 * We want to wait for this signal and when it is >= device-up return TRUE.
 * After timeout we fail...
 */
void
ni_ifup_netif_state_change_signal_handler(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{

	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_event_t event;
	ni_ifworker_array_t *ifworkers = user_data;

	if (ni_string_empty(object_path))
		return;

	if (ni_objectmodel_signal_to_event(signal_name, &event) < 0) {
		ni_error("received broken signal \"%s\" from object \"%s\"",
			signal_name, object_path);
		return;
	}

	ni_debug_application("received signal %s; object_path=%s",
		signal_name, object_path);

	if (event >= NI_EVENT_DEVICE_UP) {
		ni_string_array_t nsa = NI_STRING_ARRAY_INIT;
		char ifname[IF_NAMESIZE+1] = { 0 };
		unsigned int i, ifindex;

		if (!ni_string_split(&nsa, object_path, "/", 0) ||
		    ni_parse_uint(nsa.data[nsa.count-1], &ifindex, 10) < 0) {
			ni_error("unable to parse object_path=%s", object_path);
			return;
		}

		if (!if_indextoname(ifindex, ifname)) {
			ni_error("unable to get ifname from ifindex=%d", ifindex);
			return;
		}

		for (i = 0; i < ifworkers->count; ++i) {
			ni_ifworker_t *w = ifworkers->data[i];

			if (ni_string_eq(w->name, ifname))
				ni_ifworker_array_remove(ifworkers, w);
		}

		ni_string_array_destroy(&nsa);
	}
}

static void
ni_ifup_timer_expires(void *user_data, const ni_timer_t *timer)
{
	int *status;

	ni_assert(user_data);
	status = user_data;

	(void) timer;
	*status = NI_WICKED_RC_ERROR;
}

int
ni_do_ifup(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_IFCONFIG, OPT_CONTROL_MODE, OPT_STAGE, OPT_TIMEOUT,
		OPT_SKIP_ACTIVE, OPT_SKIP_ORIGIN, OPT_PERSISTENT,
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
#ifdef NI_TEST_HACKS
		{ "ignore-prio",no_argument, NULL,	OPT_IGNORE_PRIO },
		{ "ignore-startmode",no_argument, NULL,	OPT_IGNORE_STARTMODE },
#endif
		{ "persistent",	no_argument, NULL,	OPT_PERSISTENT },
		{ NULL }
	};

	ni_dbus_client_t *client;
	ni_ifmatcher_t ifmatch;
	ni_ifworker_array_t ifmarked;
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	ni_bool_t check_prio = TRUE, set_persistent = FALSE;
	unsigned int i;
	ni_fsm_t *fsm;
	int c, status = NI_WICKED_RC_USAGE;
	unsigned int timeout = 0;

	fsm = ni_fsm_new();
	ni_assert(fsm);
	ni_fsm_require_register_type("reachable", ni_ifworker_reachability_check_new);

	memset(&ifmatch, 0, sizeof(ifmatch));
	memset(&ifmarked, 0, sizeof(ifmarked));

	/* Allow ifup on all interfaces we have config for */
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
			if (!strcmp(optarg, "infinite")) {
				timeout = NI_IFWORKER_INFINITE_TIMEOUT;
			} else {
				unsigned int sec;

				if (ni_parse_uint(optarg, &sec, 10) < 0) {
					ni_error("ifup: cannot parse timeout option \"%s\"", optarg);
					goto usage;
				}

				timeout = (sec * 1000)/3;
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

		case OPT_PERSISTENT:
			set_persistent = TRUE;
			break;

		default:
		case OPT_HELP:
usage:
			fprintf(stderr,
				"wicked [options] ifup [ifup-options] <ifname ...>|all\n"
				"\nSupported ifup-options:\n"
				"  --help\n"
				"      Show this help text.\n"
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
				"  --timeout <nsec>\n"
				"      Timeout after <nsec> seconds\n"
#ifdef NI_TEST_HACKS
				"  --ignore-prio\n"
				"      Ignore checking the config origin priorities\n"
				"  --ignore-startmode\n"
				"      Ignore checking the STARTMODE=off and STARTMODE=manual configs\n"
#endif
				"  --persistent\n"
				"      Set interface into persistent mode (no regular ifdown allowed)\n"
				);
			goto cleanup;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}

	if (!(client = ni_fsm_create_client(fsm))) {
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	ni_dbus_client_add_signal_handler(client, NULL, NULL,
		NI_OBJECTMODEL_NETIF_INTERFACE,
		ni_ifup_netif_state_change_signal_handler, &ifmarked);

	if (!ni_fsm_refresh_state(fsm)) {
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

	/* Client waits for device-up events for WAIT_FOR_INTERFACES / 3 */
	if (timeout)
		ni_wait_for_interfaces = timeout; /* One set by user */
	else
		ni_wait_for_interfaces *= (1000/3); /* One read from compat */

	if (ni_fsm_build_hierarchy(fsm) < 0) {
		ni_error("ifup: unable to build device hierarchy");
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_SUCCESS;

	/* Get workers that match given criteria */
	while (optind < argc) {
		ifmatch.name = argv[optind++];

		if (!strcmp(ifmatch.name, "boot")) {
			ifmatch.name = "all";
			ifmatch.mode = "boot";
		}

		ni_fsm_get_matching_workers(fsm, &ifmatch, &ifmarked);
	}

	if (0 == ifmarked.count)
		printf("ifup: no matching interfaces\n");

	for (i = 0; i < ifmarked.count; i++) {
		ni_ifworker_t *w = ifmarked.data[i];

		if (set_persistent)
			ni_cient_state_set_persistent(w->config.node);

		if (!ni_ifup_hire_nanny(w)) {
			status = NI_WICKED_RC_NOT_CONFIGURED;
			ni_error("%s: unable to apply configuration to nanny", w->name);
		}
		else
			ni_info("%s: configuration applied to nanny", w->name);
	}

	ni_timer_register(ni_wait_for_interfaces, ni_ifup_timer_expires, &status);
	while (status == NI_WICKED_RC_SUCCESS) {
		/* status is already success */
		if (0 == ifmarked.count)
			break;

		if (ni_socket_wait(ni_wait_for_interfaces) != 0)
			ni_fatal("ni_socket_wait failed");

		ni_timer_next_timeout();
	}

	/* Do not report any transient errors to systemd (e.g. dhcp
	 * or whatever not ready in time) -- returning an error may
	 * cause to stop the network completely.
	 */
	if (!opt_transient)
		status = NI_LSB_RC_SUCCESS;

cleanup:
	ni_ifworker_array_destroy(&ifmarked);
	ni_string_array_destroy(&opt_ifconfig);
	return status;
}


