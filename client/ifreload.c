/*
 *	wicked client ifreload action and utilities
 *
 *	Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include "wicked-client.h"
#include "appconfig.h"
#include "ifcheck.h"
#include "ifreload.h"

int
ni_do_ifreload(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_IFCONFIG, OPT_PERSISTENT, OPT_TRANSIENT,
#ifdef NI_TEST_HACKS
		OPT_IGNORE_PRIO, OPT_IGNORE_STARTMODE,
#endif
	};

	static struct option ifreload_options[] = {
		{ "help",	no_argument,       NULL, OPT_HELP       },
		{ "transient", 	no_argument,       NULL, OPT_TRANSIENT },
		{ "ifconfig",	required_argument, NULL, OPT_IFCONFIG   },
#ifdef NI_TEST_HACKS
		{ "ignore-prio",no_argument, NULL,	OPT_IGNORE_PRIO },
		{ "ignore-startmode",no_argument, NULL, OPT_IGNORE_STARTMODE },
#endif
		{ "persistent",	no_argument,       NULL, OPT_PERSISTENT },

		{ NULL,		no_argument,	   NULL, 0              }
	};
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	ni_ifworker_array_t up_marked = NI_IFWORKER_ARRAY_INIT;
	ni_ifworker_array_t down_marked = NI_IFWORKER_ARRAY_INIT;
	ni_ifmatcher_t ifmatch;
	ni_bool_t check_prio = TRUE;
	ni_bool_t opt_persistent = FALSE;
	ni_bool_t opt_transient = FALSE;
	int c, status = NI_WICKED_RC_USAGE;
	unsigned int nmarked, i;
	const ni_uint_range_t up_range = {
		.min = NI_FSM_STATE_ADDRCONF_UP,
		.max = __NI_FSM_STATE_MAX
	};
	const char *ptr;
	ni_fsm_t *fsm;

	/* Allow ifreload on all interfaces with a changed config */
	memset(&ifmatch, 0, sizeof(ifmatch));
	ifmatch.require_configured = FALSE;
	ifmatch.allow_persistent = TRUE;
	ifmatch.require_config = FALSE;

	fsm = ni_fsm_new();
	ni_assert(fsm);
	ni_fsm_require_register_type("reachable", ni_ifworker_reachability_check_new);

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
			fsm->worker_timeout = sec * 1000;
		}
	}

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifreload_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			ni_string_array_append(&opt_ifconfig, optarg);
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
			opt_persistent = TRUE;
			break;

		case OPT_TRANSIENT:
			opt_transient = TRUE;
			break;

		default:
		case OPT_HELP:
usage:
			fprintf(stderr,
				"wicked [options] ifreload [ifreload-options] <ifname ...>|all\n"
				"\nSupported ifreload-options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --transient\n"
				"      Enable transient interface return codes\n"
				"  --ifconfig <filename>\n"
				"      Read interface configuration(s) from file\n"
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

	/* at least one argument is required */
	if (optind >= argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	} else for (c = optind; c < argc; ++c) {
			if (ni_string_empty(argv[c])) {
				printf("ARG: %s\n", argv[c]);
				goto usage;
			}
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
			ni_error("ifreload: unable to load interface config source list");
			status = NI_WICKED_RC_NOT_CONFIGURED;
			goto cleanup;
		}
	}

	if (!ni_ifconfig_load(fsm, opt_global_rootdir, &opt_ifconfig, check_prio, TRUE)) {
		status = NI_WICKED_RC_NOT_CONFIGURED;
		goto cleanup;
	}

	/* Build the up tree */
	if (ni_fsm_build_hierarchy(fsm, TRUE) < 0) {
		ni_error("ifreload: unable to build device hierarchy");
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_SUCCESS;
	nmarked = 0;
	for (c = optind; c < argc; ++c) {
		ifmatch.name = argv[c];

		/* Getting an array of ifworkers matching arguments */
		ni_fsm_get_matching_workers(fsm, &ifmatch, &down_marked);
	}

	for (i = 0; i < down_marked.count; ++i) {
		ni_ifworker_t *w = down_marked.data[i];
		ni_netdev_t *dev = w->device;

		/* skip unused devices without config */
		if (!ni_ifcheck_worker_config_exists(w) &&
		    !ni_ifcheck_device_configured(dev)) {
			ni_info("skipping %s interface: no configuration exists and "
				"device is not configured by wicked", w->name);
			continue;
		}

		/* skip if config has not been changed */
		if (ni_ifcheck_worker_config_matches(w)) {
			ni_info("skipping %s interface: "
				"configuration unchanged", w->name);
			continue;
		}

		/* Mark persistend when requested */
		if (opt_persistent)
			w->client_state.persistent = TRUE;

		/* Remember all changed devices */
		ni_ifworker_array_append(&up_marked, w);

		/* Do not ifdown non-existing device */
		if (!dev) {
			ni_info("skipping ifdown operation for %s interface: "
				"non-existing device", w->name);
			continue;
		}

		/* Persistent do not go down but up only */
		if (ni_ifcheck_device_is_persistent(dev)) {
			ni_info("skipping ifdown operation for %s interface: "
				"persistent device", w->name);
			continue;
		}

		/* Decide how much down we go */
		if (ni_ifcheck_worker_config_exists(w)) {
			if (!ni_ifcheck_device_configured(dev)) {
				ni_info("skipping ifdown operation for %s interface: "
					"device is not configured by wicked", w->name);
				continue;
			}
			w->target_range.min = NI_FSM_STATE_NONE;
			w->target_range.max = NI_FSM_STATE_DEVICE_READY;
			nmarked++;
		} else
		if (ni_ifcheck_device_configured(dev)) {
			w->target_range.min = NI_FSM_STATE_NONE;
			w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
			nmarked++;
		}
	}

	if (0 == nmarked && 0 == up_marked.count) {
		printf("ifreload: no matching interfaces\n");
		status = NI_WICKED_RC_SUCCESS;
		goto cleanup;
	}

	/* anything to ifdown? e.g. persistent devices are skipped here */
	if (nmarked) {
		/* Run ifdown part of the reload */
		ni_debug_application("Shutting down unneeded devices");
		if (ni_fsm_start_matching_workers(fsm, &down_marked)) {
			/* Execute the down run */
			if (ni_fsm_schedule(fsm) != 0)
				ni_fsm_mainloop(fsm);
		}
	}
	else {
		ni_debug_application("No interfaces to be brought down\n");
	}

	ni_fsm_pull_in_children(&up_marked);
	/* Drop deleted or apply the up range */
	ni_fsm_reset_matching_workers(fsm, &up_marked, &up_range, FALSE);

	/* anything to ifup? */
	if (up_marked.count) {
		/* And trigger up */
		ni_debug_application("Reloading all changed devices");
		if (ni_fsm_start_matching_workers(fsm, &up_marked)) {
			/* Execute the up run */
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
	}
	else {
		ni_debug_application("No interfaces to be brought up\n");
	}

cleanup:
	ni_string_array_destroy(&opt_ifconfig);
	ni_ifworker_array_destroy(&down_marked);
	ni_ifworker_array_destroy(&up_marked);
	return status;
}
