/*
 *	wicked client ifdown action and utilities
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
#include "ifdown.h"
#include "ifstatus.h"

static ni_bool_t
ni_ifdown_stop_policy(const char *policy_name)
{
	/* Default policy name is interface name.
	 * In case of any change other parameters
	 * should be available within ifworker
	 */
	if (!ni_nanny_call_del_policy(policy_name)) {
		ni_debug_application("Unable to delete policy named %s", policy_name);
		return FALSE;
	}

	return TRUE;
}

static ni_bool_t
ni_ifdown_stop_device(const char *device_name)
{
	if (!ni_nanny_call_device_disable(device_name)) {
		ni_debug_application("Unable to disable device named %s", device_name);
		return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_ifdown_fire_nanny(ni_ifworker_array_t *array)
{
	unsigned int i;
	char *policy_name;

	/* Deleting all requested policies */
	for (i = 0; i < array->count; i++) {
		ni_ifworker_t *w = array->data[i];

		policy_name = ni_ifpolicy_name_from_ifname(w->name);
		if (!ni_ifdown_stop_policy(policy_name)) {
			/* We ignore errors for now */;
		}
		ni_string_free(&policy_name);
	}

	/* Disabling all requested devices */
	for (i = 0; i < array->count; i++) {
		ni_ifworker_t *w = array->data[i];
		ni_netdev_t *dev = w ? w->device : NULL;

		/* Ignore non-existing device */
		if (!dev || !ni_netdev_device_is_ready(dev)) {
			continue;
		}

		if (!ni_ifdown_stop_device(w->name)) {
			/* We ignore errors for now */;
		}
	}

	return TRUE;
}

int
ni_do_ifdown(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_FORCE, OPT_DELETE, OPT_NO_DELETE, OPT_TIMEOUT,
		OPT_RELEASE, OPT_NO_RELEASE, OPT_DRY_RUN,
	};
	static struct option ifdown_options[] = {
		{ "help",	no_argument, NULL,		OPT_HELP },
		{ "force",	required_argument, NULL,	OPT_FORCE },
		{ "delete",	no_argument, NULL,		OPT_DELETE },
		{ "no-delete",	no_argument, NULL,		OPT_NO_DELETE },
		{ "release",	no_argument, NULL,		OPT_RELEASE },
		{ "no-release",	no_argument, NULL,		OPT_NO_RELEASE },
		{ "timeout",	required_argument, NULL,	OPT_TIMEOUT },
		{ "dry-run",	no_argument, NULL,		OPT_DRY_RUN },

		{ NULL }
	};
	ni_ifmatcher_t ifmatch;
	ni_ifmarker_t ifmarker;
	ni_ifworker_array_t ifmarked = NI_IFWORKER_ARRAY_INIT;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	unsigned int nmarked, max_state = NI_FSM_STATE_DEVICE_DOWN;
	unsigned int seconds = 0;
	ni_stringbuf_t sb = NI_STRINGBUF_INIT_DYNAMIC;
	ni_tristate_t opt_release = NI_TRISTATE_DEFAULT;
	ni_log_fn_t *dry_run = NULL;
	ni_fsm_t *fsm;
	int c, status = NI_WICKED_RC_USAGE;

	fsm = ni_fsm_new();
	ni_assert(fsm);
	ni_fsm_require_register_type("reachable", ni_ifworker_reachability_check_new);

	/* Allow ifdown only on non-persistent interfaces previously configured by ifup */
	memset(&ifmatch, 0, sizeof(ifmatch));
	ifmatch.require_configured = TRUE;
	ifmatch.allow_persistent = FALSE;
	ifmatch.require_config = FALSE;

	memset(&ifmarker, 0, sizeof(ifmarker));
	ifmarker.target_range.min = NI_FSM_STATE_DEVICE_DOWN;
	ifmarker.target_range.max = NI_FSM_STATE_MAX - 2;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifdown_options, NULL)) != EOF) {
		switch (c) {
		case OPT_FORCE:
			if (!ni_ifworker_state_from_name(optarg, &max_state) ||
			    !ni_ifworker_state_in_range(&ifmarker.target_range, max_state)) {
				ni_error("ifdown: wrong force option \"%s\"", optarg);
				goto usage;
			}
			/* Allow ifdown on persistent, unconfigured interfaces */
			ifmatch.require_configured = FALSE;
			ifmatch.allow_persistent = TRUE;
			ifmatch.require_config = FALSE;
			break;

		case OPT_DELETE:
			max_state = NI_FSM_STATE_DEVICE_DOWN;
			/* Allow ifdown on persistent, unconfigured interfaces */
			ifmatch.require_configured = FALSE;
			ifmatch.allow_persistent = TRUE;
			ifmatch.require_config = FALSE;
			break;

		case OPT_NO_DELETE:
			max_state = NI_FSM_STATE_DEVICE_READY;
			/* Allow ifdown only on non-persistent interfaces previously configured by ifup */
			ifmatch.require_configured = TRUE;
			ifmatch.allow_persistent = FALSE;
			ifmatch.require_config = FALSE;
			break;

		case OPT_RELEASE:
			opt_release = NI_TRISTATE_ENABLE;
			break;
		case OPT_NO_RELEASE:
			opt_release = NI_TRISTATE_DISABLE;
			break;

		case OPT_TIMEOUT:
			if (ni_parse_seconds_timeout(optarg, &seconds)) {
				ni_error("ifdown: cannot parse timeout option \"%s\"", optarg);
				goto usage;
			}
			break;

		case OPT_DRY_RUN:
			dry_run = ni_note;
			break;

		default:
		case OPT_HELP:
usage:
			ni_client_get_state_strings(&sb, &ifmarker.target_range);
			fprintf(stderr,
				"wicked [options] ifdown [ifdown-options] <ifname ...>|all\n"
				"\nSupported ifdown-options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --force <state>\n"
				"      Force putting interface into the <state> state. Despite of persistent mode being set. Possible states:\n"
				"  %s\n"
				"  --delete\n"
				"      Delete device. Despite of persistent mode being set\n"
				"  --no-delete\n"
				"      Do not attempt to delete a device, neither physical nor virtual\n"
				"  --[no-]release\n"
				"      Override active config to (not) release leases\n"
				"  --timeout <sec>\n"
				"      Timeout after <sec> seconds\n"
				"  --dry-run\n"
				"      Show system interface hierarchy as notice with (-) markers and exit.\n"
				, sb.string
				);
			ni_stringbuf_destroy(&sb);
			return status;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}

	ifmarker.target_range.min = NI_FSM_STATE_NONE;
	ifmarker.target_range.max = max_state;

	if (seconds)
		fsm->worker_timeout = NI_TIMEOUT_FROM_SEC(seconds);
	else
		fsm->worker_timeout = NI_IFWORKER_DEFAULT_TIMEOUT;
	if (fsm->worker_timeout == NI_IFWORKER_INFINITE_TIMEOUT)
		ni_debug_application("wait for interfaces infinitely");
	else
		ni_debug_application("wait %u seconds for interfaces",
					NI_TIMEOUT_SEC(fsm->worker_timeout));

	if (!ni_fsm_create_client(fsm)) {
		/* Severe error we always explicitly return */
		return NI_WICKED_RC_ERROR;
	}

	if (!ni_fsm_refresh_state(fsm)) {
		/* Severe error we always explicitly return */
		return NI_WICKED_RC_ERROR;
	}

	if (ni_fsm_build_hierarchy(fsm, FALSE) < 0) {
		ni_error("ifdown: unable to build interface hierarchy");
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	/* Get workers that match given criteria */
	status = NI_WICKED_RC_SUCCESS;
	nmarked = 0;
	while (optind < argc) {
		ifmatch.name = argv[optind++];
		ifmatch.ifdown = TRUE;

		ni_fsm_get_matching_workers(fsm, &ifmatch, &ifmarked);

		if (ni_string_eq(ifmatch.name, "all") ||
		    ni_string_empty(ifmatch.name)) {
			ni_string_array_destroy(&ifnames);
			break;
		}

		if (ni_string_array_index(&ifnames, ifmatch.name) == -1)
			ni_string_array_append(&ifnames, ifmatch.name);
	}

	ni_fsm_print_system_hierarchy(fsm, &ifmarked, dry_run);
	if (dry_run)
		goto cleanup;

	/* Mark and start selected workers */
	if (ifmarked.count) {
		/* Disable devices and delete all related policies from nanny */
		ni_ifdown_fire_nanny(&ifmarked);

		/* Advise marked workers to (not) release leases */
		if (ni_tristate_is_set(opt_release)) {
			unsigned int i;

			for (i = 0; i < ifmarked.count; ++i) {
				ni_ifworker_t *w = ifmarked.data[i];
				if (!w->control.persistent)
					w->args.release = opt_release;
			}
		}

		/* Start workers to perform actual ifdown */
		nmarked = ni_fsm_mark_matching_workers(fsm, &ifmarked, &ifmarker);
	}

	if (nmarked == 0) {
		ni_note("ifdown: no matching interfaces");
		status = NI_WICKED_RC_SUCCESS;
	} else {
		if (ni_fsm_schedule(fsm) != 0)
			ni_fsm_mainloop(fsm);

		status = ni_ifstatus_shutdown_result(fsm, &ifnames, &ifmarked);
	}

cleanup:
	ni_string_array_destroy(&ifnames);
	ni_ifworker_array_destroy(&ifmarked);
	ni_fsm_free(fsm);
	return status;
}

