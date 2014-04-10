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
#include "ifup.h"
#include "ifcheck.h"

int
ni_do_ifreload(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_IFCONFIG, OPT_IFPOLICY, OPT_FORCE, OPT_PERSISTENT };
	static struct option ifreload_options[] = {
		{ "help",	no_argument,       NULL, OPT_HELP       },
		{ "ifconfig",	required_argument, NULL, OPT_IFCONFIG   },
		{ "ifpolicy",	required_argument, NULL, OPT_IFPOLICY   },
		{ "force",	no_argument,       NULL, OPT_FORCE      },
		{ "persistent",	no_argument,       NULL, OPT_PERSISTENT },

		{ NULL,		no_argument,	   NULL, 0              }
	};
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	ni_ifworker_array_t marked = { 0, NULL };
	ni_ifmatcher_t ifmatch;
	ni_bool_t opt_force = FALSE;
	ni_bool_t opt_persistent = FALSE;
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
		case OPT_IFPOLICY:
			ni_string_array_append(&opt_ifconfig, optarg);
			break;

		case OPT_FORCE:
			opt_force = TRUE;
			break;
		case OPT_PERSISTENT:
			opt_persistent = TRUE;
			break;

		default:
		case OPT_HELP:
usage:
			fprintf(stderr,
				"wicked [options] ifreload [ifreload-options] <ifname ...>|all\n"
				"\nSupported ifreload-options:\n"
				"  --help\n"
				"	   Show this help text.\n"
				"  --ifconfig <filename>\n"
				"	   Read interface configuration(s) from file\n"
				"  --force\n"
				"      Force reconfiguring the interface without checking the config origin\n"
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

	if (!ni_ifconfig_load(fsm, opt_global_rootdir, &opt_ifconfig, opt_force)) {
		status = NI_WICKED_RC_NOT_CONFIGURED;
		goto cleanup;
	}

	status = NI_WICKED_RC_SUCCESS;
	nmarked = 0;
	for (c = optind; c < argc; ++c) {
		ni_ifworker_array_t temp = { 0, NULL };

		/* Getting an array of ifworkers matching argument */
		ifmatch.name = argv[c];
		if (!ni_fsm_get_matching_workers(fsm, &ifmatch, &temp))
			continue;

		for (i = 0; i < temp.count; ++i) {
			ni_ifworker_t *w = temp.data[i];
			ni_netdev_t *dev = w->device;

			/* skip duplicate matches */
			if (ni_ifworker_array_index(&marked, w) != -1)
				continue;

			/* skip unused devices without config */
			if (!ni_ifcheck_worker_config_exists(w) &&
			    !ni_ifcheck_device_configured(dev))
				continue;

			/* skip if config changed somehow */
			if (ni_ifcheck_worker_config_matches(w))
				continue;

			/* Mark persistend when requested */
			if (opt_persistent)
				w->client_state.persistent = TRUE;

			/* Remember all changed devices */
			ni_ifworker_array_append(&marked, w);

			/* Persistent do not go down but up only */
			if (!dev || ni_ifcheck_device_is_persistent(dev))
				continue;

			/* Decide how much down we go */
			if (ni_ifcheck_worker_config_exists(w)) {
				if (!ni_ifcheck_device_configured(dev))
					continue;
				w->target_range.min = NI_FSM_STATE_NONE;
				w->target_range.max = NI_FSM_STATE_DEVICE_EXISTS;
				nmarked++;
			} else
			if (ni_ifcheck_device_configured(dev)) {
				w->target_range.min = NI_FSM_STATE_NONE;
				w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
				nmarked++;
			}
		}
		ni_ifworker_array_destroy(&temp);
	}

	if (nmarked) {
		/* Run ifdown part of the reload */
		ni_debug_application("Shutting down unneeded devices");
		ni_fsm_start_matching_workers(fsm, &marked);

		/* Execute the down run */
		if (ni_fsm_schedule(fsm) != 0)
			ni_fsm_mainloop(fsm);

	}

	if (marked.count) {

		/* Drop deleted or apply the up range */
		ni_fsm_reset_matching_workers(fsm, &marked, &up_range, FALSE);

		/* And trigger up */
		ni_debug_application("Reloading all changed devices");
		nmarked = ni_fsm_start_matching_workers(fsm, &marked);

		ni_ifworker_array_destroy(&marked);
	}

	if (nmarked) {
		/* Build the up tree */
		if (ni_fsm_build_hierarchy(fsm) < 0) {
			ni_error("ifreload: unable to build device hierarchy");
			/* Severe error we always explicitly return */
			status = NI_WICKED_RC_ERROR;
			goto cleanup;
		}

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
		if (opt_systemd)
			status = NI_LSB_RC_SUCCESS;
	}

cleanup:
	ni_string_array_destroy(&opt_ifconfig);
	ni_ifworker_array_destroy(&marked);
	return status;
}
