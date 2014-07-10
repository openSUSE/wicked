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
#include "appconfig.h"
#include "ifup.h"

static xml_node_t *
__ni_ifup_generate_match_type_dev(ni_netdev_t *dev)
{
	const char *type;
	xml_node_t *ret;

	if (!dev || dev->link.type == NI_IFTYPE_UNKNOWN)
		return NULL;

	if (!(type = ni_linktype_type_to_name(dev->link.type)))
		return NULL;

	if (!(ret = xml_node_new(NI_NANNY_IFPOLICY_MATCH_COND_AND, NULL)))
		return NULL;

	if (!xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_DEV, ret, dev->name) ||
	    !xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_LINK_TYPE, ret, type)) {
		xml_node_free(ret);
		return NULL;
	}
	return ret;
}

static xml_node_t *
__ni_ifup_generate_match_dev(xml_node_t *node, ni_ifworker_t *w)
{
	if (!node || !w || !w->name)
		return NULL;

	/* TODO: the type has to be from config, _not_ from device
	 * (dev is probably a not ready one just using our name),
	 * but this info is lost in translation... isn't it?
	 */
#if 0 /* Unsupported - new condition to be introduced to match agains device slave and its link-type */
	if (w->device && ni_string_eq(w->name, w->device->name)) {
		xml_node_t * ret = NULL;

		if ((ret = __ni_ifup_generate_match_type_dev(w->device))) {
			xml_node_add_child(node, ret);
			return ret;
		}
	}
#endif
	return xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_DEV, node, w->name);
}

static xml_node_t *
__ni_ifup_generate_match(ni_ifworker_t *w)
{
	xml_node_t *match, *op;
	unsigned int i;

	if (!(match = xml_node_new(NI_NANNY_IFPOLICY_MATCH, NULL)))
		return NULL;

	if (!__ni_ifup_generate_match_dev(match, w)) {
		xml_node_free(match);
		return NULL;
	}

	if (w->children.count) {
		op = xml_node_new(NI_NANNY_IFPOLICY_MATCH_COND_OR, match);

		for (i = 0; i < w->children.count; i++) {
			ni_ifworker_t *child = w->children.data[i];

			if (!__ni_ifup_generate_match_dev(op, child)) {
				xml_node_free(match);
				return NULL;
			}
		}

	}

	return match;
}

static ni_bool_t
ni_ifup_start_policy(ni_ifworker_t *w)
{
	xml_node_t *ifcfg = NULL, *policy = NULL;
	ni_bool_t rv = FALSE;
	char *pname;

	if (!w)
		return rv;

	ni_debug_application("%s: hiring nanny", w->name);

	/* Create a config duplicate for a policy */
	ifcfg = xml_node_clone(w->config.node, NULL);
	if (!ifcfg)
		goto error;

	pname  = ni_ifpolicy_name_from_ifname(w->name);
	ni_debug_application("%s: converting config into policy '%s'",
			w->name, pname);

	policy = ni_convert_cfg_into_policy_node(ifcfg,
			__ni_ifup_generate_match(w),
			pname, w->config.origin);
	ni_string_free(&pname);
	if (!policy) {
		policy = ifcfg; /* Free cloned config*/
		goto error;
	}

#if 0
	/* Do we need this? */

	/* Add link type to match node*/
	if (dev) {
		ni_debug_application("%s: adding link type (%s) to match",
			w->name, ni_linktype_type_to_name(dev->link.type));
		ni_ifpolicy_match_add_link_type(policy, dev->link.type);
	}

	ni_debug_application("%s: adding minimum device state (%s) to match",
		w->name, ni_ifworker_state_name(w->fsm.state));

	/* Add minimum device state to match node */
	if (!ni_ifpolicy_match_add_min_state(policy, w->fsm.state))
		goto error;
#endif

	ni_debug_application("%s: adding policy %s to nanny", w->name,
		xml_node_get_attr(policy, NI_NANNY_IFPOLICY_NAME));

	if (ni_nanny_addpolicy_node(policy, w->config.origin) <= 0)
		goto error;

	ni_debug_application("%s: nanny hired!", w->name);
	ni_ifworker_success(w);

	rv = TRUE;

error:
	if (!rv)
		ni_ifworker_fail(w, "%s: unable to apply configuration to nanny", w->name);
	xml_node_free(policy);
	return rv;
}

static ni_bool_t
ni_ifup_hire_nanny(ni_ifworker_array_t *array, ni_bool_t set_persistent)
{
	unsigned int i;
	ni_bool_t rv = TRUE;

	/* Send policies to nanny */
	for (i = 0; i < array->count; i++) {
		ni_ifworker_t *w = array->data[i];

		if (set_persistent)
			ni_client_state_set_persistent(w->config.node);

		if (!ni_ifup_start_policy(w)) {
			ni_error("%s: unable to apply configuration to nanny", w->name);
			rv = FALSE;
		}
		else
			ni_info("%s: configuration applied to nanny", w->name);
	}

	/* Enable devices with policies */
	for (i = 0; i < array->count; i++) {
		ni_ifworker_t *w = array->data[i];
		ni_netdev_t *dev = w->device;

		/* Ignore non-existing device */
		if (!dev)
			continue;

		if (w->failed) {
			ni_debug_application("%s: disabling failed device for nanny", w->name);
			ni_nanny_call_device_disable(w->name);
		}
		else {
			ni_debug_application("%s: enabling device for nanny", w->name);
			if (!ni_nanny_call_device_enable(w->name)) {
				ni_error("%s: unable to enable device", w->name);
				rv = FALSE;
			}
		}
	}

	if (0 == array->count)
		printf("ifup: no matching interfaces\n");

	return rv;
}

/*
 * Wickedd is sending us a signal indicating internal device state change.
 * We want to wait for this signal and when it is >= device-up return TRUE.
 * After timeout we fail...
 */
void
ni_state_change_signal_handler(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_dbus_variant_t argv = NI_DBUS_VARIANT_INIT;
	ni_ifworker_array_t *ifworkers = user_data;
	ni_fsm_state_t cur_state, target_state;
	const char *ifname;
	unsigned int i;

	if (ni_string_empty(object_path))
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

	for (i = 0; i < ifworkers->count; ++i) {
		ni_ifworker_t *w = ifworkers->data[i];

		if (cur_state != NI_FSM_STATE_NONE && cur_state != target_state)
			continue;

		if (!ni_string_eq(w->name, ifname))
			continue;

		ni_warn("%s: Device %s", ifname, cur_state == target_state ? "succeeded" : "failed");
		ni_ifworker_array_remove_with_children(ifworkers, w);

	}

	ni_dbus_variant_destroy(&argv);
}

void
ni_client_timer_expires(void *user_data, const ni_timer_t *timer)
{
	int *status;

	ni_assert(user_data);
	status = user_data;

	(void) timer;
	*status = NI_WICKED_RC_ERROR;
	ni_error("Operation timeout...");
}

ni_bool_t
ni_client_create(ni_fsm_t *fsm, void *user_data)
{
	ni_dbus_client_t *client;

	if (!(fsm->client_root_object = ni_call_create_client()))
		return FALSE;

	client = ni_dbus_object_get_client(fsm->client_root_object);

	ni_dbus_client_add_signal_handler(client, NULL, NULL,
		NI_OBJECTMODEL_MANAGED_NETIF_INTERFACE,
		ni_state_change_signal_handler, user_data);

	return TRUE;
}

static int
ni_do_ifup_nanny(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_IFCONFIG, OPT_CONTROL_MODE, OPT_STAGE, OPT_TIMEOUT,
		OPT_SKIP_ACTIVE, OPT_SKIP_ORIGIN, OPT_PERSISTENT, OPT_TRANSIENT,
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
		{ NULL }
	};

	ni_ifmatcher_t ifmatch;
	ni_ifworker_array_t ifmarked;
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	ni_bool_t check_prio = TRUE, set_persistent = FALSE;
	ni_bool_t opt_transient = FALSE;
	int c, status = NI_WICKED_RC_USAGE;
	unsigned int timeout = 0;
	ni_fsm_t *fsm;

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
				timeout = sec * 1000; /* sec -> msec */
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

		case OPT_TRANSIENT:
			opt_transient = TRUE;
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

	if (!ni_client_create(fsm, &ifmarked) || !ni_fsm_refresh_state(fsm)) {
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

	/* Client waits for device-up events for WAIT_FOR_INTERFACES */
	if (timeout)
		ni_wait_for_interfaces = timeout; /* One set by user */
	else
		ni_wait_for_interfaces *= 1000;   /* in msec */

	if (ni_wait_for_interfaces)
		fsm->worker_timeout = ni_wait_for_interfaces;

	if (ni_fsm_build_hierarchy(fsm, TRUE) < 0) {
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

	ni_fsm_pull_in_children(&ifmarked);
	ni_ifworkers_flatten(&ifmarked);

	if (!ni_ifup_hire_nanny(&ifmarked, set_persistent))
		status = NI_WICKED_RC_NOT_CONFIGURED;

	/* Wait for device-up events */
	ni_timer_register(ni_wait_for_interfaces, ni_client_timer_expires, &status);
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

static int
ni_do_ifup_direct(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_IFCONFIG, OPT_CONTROL_MODE, OPT_STAGE, OPT_TIMEOUT,
		OPT_SKIP_ACTIVE, OPT_SKIP_ORIGIN, OPT_PERSISTENT, OPT_TRANSIENT,
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
		{ NULL }
	};

	ni_ifmatcher_t ifmatch;
	ni_ifmarker_t ifmarker;
	ni_ifworker_array_t ifmarked;
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	ni_bool_t check_prio = TRUE;
	ni_bool_t opt_transient = FALSE;
	unsigned int nmarked;
	ni_fsm_t *fsm;
	int c, status = NI_WICKED_RC_USAGE;
	unsigned int timeout = 0;
	const char *ptr;

	fsm = ni_fsm_new();
	ni_assert(fsm);
	ni_fsm_require_register_type("reachable", ni_ifworker_reachability_check_new);

	memset(&ifmatch, 0, sizeof(ifmatch));
	memset(&ifmarker, 0, sizeof(ifmarker));
	memset(&ifmarked, 0, sizeof(ifmarked));

	/* Allow ifup on all interfaces we have config for */
	ifmatch.require_configured = FALSE;
	ifmatch.allow_persistent = TRUE;
	ifmatch.require_config = TRUE;

	ifmarker.target_range.min = NI_FSM_STATE_ADDRCONF_UP;
	ifmarker.target_range.max = __NI_FSM_STATE_MAX;

	/*
	 * Workaround to consider WAIT_FOR_INTERFACES variable
	 * in network/config (bnc#863371, bnc#862530 timeouts).
	 * Correct would be to get it from compat layer, but
	 * the network/config is sourced in systemd service...
	 */
	if ((ptr = getenv("WAIT_FOR_INTERFACES"))) {
		unsigned int sec;

		if (ni_parse_uint(ptr, &sec, 10) == 0 &&
		    (sec * 1000 > fsm->worker_timeout)) {
			ni_debug_application("wait %u sec for interfaces", sec);
			timeout = sec * 1000;
		}
	}

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
			} else if (ni_parse_uint(optarg, &timeout, 10) >= 0) {
				timeout *= 1000; /* sec -> msec */
			} else {
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

		case OPT_PERSISTENT:
			ifmarker.persistent = TRUE;
			break;

		case OPT_TRANSIENT:
			opt_transient = TRUE;
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

	if (!ni_fsm_create_client(fsm)) {
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

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

	/* Client waits for device-up events for WAIT_FOR_INTERFACES */
	if (timeout)
		ni_wait_for_interfaces = timeout; /* One set by user */
	else
		ni_wait_for_interfaces *= 1000;   /* in msec */

	if (ni_fsm_build_hierarchy(fsm, TRUE) < 0) {
		ni_error("ifup: unable to build device hierarchy");
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	/* Get workers that match given criteria */
	nmarked = 0;
	while (optind < argc) {
		ifmatch.name = argv[optind++];

		if (!strcmp(ifmatch.name, "boot")) {
			ifmatch.name = "all";
			ifmatch.mode = "boot";
		}

		ni_fsm_get_matching_workers(fsm, &ifmatch, &ifmarked);
	}

	ni_fsm_pull_in_children(&ifmarked);

	/* Mark and start selected workers */
	if (ifmarked.count)
		nmarked = ni_fsm_mark_matching_workers(fsm, &ifmarked, &ifmarker);

	if (nmarked == 0) {
		printf("ifup: no matching interfaces\n");
		status = NI_WICKED_RC_SUCCESS;
	} else {
		if (ni_fsm_schedule(fsm) != 0)
			ni_fsm_mainloop(fsm);

		/* No error if all interfaces were good */
		status = ni_fsm_fail_count(fsm) ?
			NI_WICKED_RC_ERROR : NI_WICKED_RC_SUCCESS;

		/* Do not report any transient errors to systemd (e.g. dhcp
		 * or whatever not ready in time) -- returning an error may
		 * cause to stop the network completely.
		 */
		if (!opt_transient)
			status = NI_LSB_RC_SUCCESS;
	}

cleanup:
	ni_ifworker_array_destroy(&ifmarked);
	ni_string_array_destroy(&opt_ifconfig);
	return status;
}

int
ni_do_ifup(int argc, char **argv)
{
	if (ni_config_use_nanny())
		return ni_do_ifup_nanny(argc, argv);
	else
		return ni_do_ifup_direct(argc, argv);
}

