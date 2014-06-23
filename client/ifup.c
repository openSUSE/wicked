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

#include "wicked-client.h"
#include "ifup.h"

int
ni_do_ifup(int argc, char **argv)
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
			fsm->worker_timeout = sec * 1000;
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
				fsm->worker_timeout = NI_IFWORKER_INFINITE_TIMEOUT;
			} else if (ni_parse_uint(optarg, &fsm->worker_timeout, 10) >= 0) {
				fsm->worker_timeout *= 1000; /* sec -> msec */
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

	if (ni_fsm_build_hierarchy(fsm) < 0) {
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


