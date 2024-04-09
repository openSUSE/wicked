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
#include <wicked/compiler.h>

#include "wicked-client.h"
#include "appconfig.h"
#include "ifcheck.h"
#include "ifup.h"
#include "ifdown.h"
#include "ifreload.h"
#include "ifstatus.h"

static void
ifreload_match_down(ni_fsm_t *fsm, ni_ifworker_array_t *ifmarked, const char *ifname)
{
	ni_ifmatcher_t ifmatch;

	memset(&ifmatch, 0, sizeof(ifmatch));
	ifmatch.allow_persistent = FALSE;
	ifmatch.require_configured = TRUE;
	ifmatch.require_config = FALSE;
	ifmatch.ifreload = TRUE;
	ifmatch.ifdown = TRUE;
	ifmatch.name = ifname;

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
		"ifreload: matching %s for shutdown", ifname ?: "all");

	/* to shutdown if config changed + dependencies */
	ni_fsm_get_matching_workers(fsm, &ifmatch, ifmarked);
}

static void
ifreload_match_up(ni_fsm_t *fsm, ni_ifworker_array_t *ifmarked, const char *ifname)
{
	ni_ifmatcher_t ifmatch;

	memset(&ifmatch, 0, sizeof(ifmatch));
	ifmatch.allow_persistent = TRUE;
	ifmatch.require_configured = FALSE;
	ifmatch.require_config = TRUE;
	ifmatch.ifreload = TRUE;
	ifmatch.ifdown = FALSE;
	ifmatch.name = ifname;

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
		"ifreload: matching %s for setup", ifname ?: "all");

	/* to set-up if config changed + dependencies */
	ni_fsm_get_matching_workers(fsm, &ifmatch, ifmarked);
}

static void
ifreload_match_workers(ni_fsm_t *fsm, ni_ifworker_array_t *down_marked,
		ni_ifworker_array_t *up_marked, const char *ifname)
{
	ifreload_match_down(fsm, down_marked, ifname);
	ifreload_match_up(fsm, up_marked, ifname);
}

static void
ifreload_mark_worker_down(ni_fsm_t *fsm, ni_ifworker_array_t *down_marked, ni_ifworker_t *w)
{
	/* set default: try to go down without to delete it */
	w->target_range.min = NI_FSM_STATE_NONE;
	w->target_range.max = NI_FSM_STATE_DEVICE_READY;

	/* when there is no config to apply, try to delete */
	if (!ni_ifcheck_worker_config_exists(w)) {
		w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
		return;
	}

	/*
	 * config and device type differs (e.g. bridge vs bond)
	 */
	if (w->iftype != NI_IFTYPE_UNKNOWN && w->device &&
			w->device->link.type != w->iftype) {
		w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
		return;
	}

	/*
	 * link config may have changed what may require deletion
	 */
	switch (w->iftype) {
	case NI_IFTYPE_PPP:
	case NI_IFTYPE_TEAM:
	case NI_IFTYPE_VLAN:
		/*
		 * - ppp,team config file changes require service restart
		 * - vlan id changed
		 */
		w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
		return;
	default:
		break;
	}
}

static void
ifreload_mark_workers_down(ni_fsm_t *fsm, ni_ifworker_array_t *ifmarked)
{
	ni_ifworker_t *w;
	unsigned int i;

	/* init the shutdown / deletion targets */
	for (i = 0; i < ifmarked->count; ++i) {
		w = ifmarked->data[i];
		if (w->type != NI_IFWORKER_TYPE_NETDEV)
			continue;

		ifreload_mark_worker_down(fsm, ifmarked, w);
	}
	/* second pass: check lower changes */
	for (i = 0; i < ifmarked->count; ++i) {
		w = ifmarked->data[i];

		if (w->type != NI_IFWORKER_TYPE_NETDEV)
			continue;

		if (!w->lowerdev)
			continue;

		if (w->lowerdev->target_range.max == NI_FSM_STATE_DEVICE_DOWN)
			w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
	}
}

int
ni_do_ifreload(const char *caller, int argc, char **argv)
{
	enum  {
		OPT_HELP	= 'h',
		OPT_IFCONFIG	= 'i',
		OPT_TIMEOUT	= 't',
		OPT_PERSISTENT	= 'P',
		OPT_TRANSIENT	= 'T',
		OPT_RELEASE,
		OPT_NO_RELEASE,
		OPT_DRY_RUN,
	};
	static struct option ifreload_options[] = {
		{ "help",		no_argument,		NULL,	OPT_HELP },
		{ "ifconfig",		required_argument,	NULL,	OPT_IFCONFIG },
		{ "timeout",		required_argument,	NULL,	OPT_TIMEOUT },
		{ "transient",		no_argument,		NULL,	OPT_TRANSIENT },
		{ "persistent",		no_argument,		NULL,	OPT_PERSISTENT },
		{ "release",		no_argument,		NULL,	OPT_RELEASE },
		{ "no-release",		no_argument,		NULL,	OPT_NO_RELEASE },
		{ "dry-run",		no_argument,		NULL,	OPT_DRY_RUN },

		{ NULL,			no_argument,		NULL,	0 }
	};
	ni_ifworker_array_t up_marked = NI_IFWORKER_ARRAY_INIT;
	ni_ifworker_array_t down_marked = NI_IFWORKER_ARRAY_INIT;
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	ni_nanny_fsm_monitor_t *monitor = NULL;
	ni_bool_t opt_persistent = FALSE;
	ni_bool_t opt_transient = FALSE;
	ni_tristate_t opt_release = NI_TRISTATE_DEFAULT;
	ni_log_fn_t *dry_run = NULL;
	unsigned int seconds = 0;
	int c, status = NI_WICKED_RC_USAGE;
	char *saved_argv0, *program = NULL;
	unsigned int i;
	ni_fsm_t *fsm;

	fsm = ni_fsm_new();
	ni_assert(fsm);
	ni_fsm_require_register_type("reachable", ni_ifworker_reachability_check_new);

	ni_string_printf(&program, "%s %s",	caller  ? caller  : "wicked",
						argv[0] ? argv[0] : "ifreload");
	saved_argv0 = argv[0];
	argv[0] = program;
	optind = 1;
	while ((c = getopt_long(argc, argv, "+hi:t:PT", ifreload_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			ni_string_array_append(&opt_ifconfig, optarg);
			break;

		case OPT_PERSISTENT:
			opt_persistent = TRUE;
			break;

		case OPT_TRANSIENT:
			opt_transient = TRUE;
			break;

		case OPT_TIMEOUT:
			if (ni_parse_seconds_timeout(optarg, &seconds)) {
				ni_error("%s: cannot parse timeout option \"%s\"",
						program, optarg);
				goto usage;
			}
			break;

		case OPT_RELEASE:
			opt_release = NI_TRISTATE_ENABLE;
			break;

		case OPT_NO_RELEASE:
			opt_release = NI_TRISTATE_DISABLE;
			break;

		case OPT_DRY_RUN:
			dry_run = ni_note;
			break;

		default:
		case OPT_HELP:
usage:
			fprintf(stderr,
				"%s [ifreload-options] <ifname ...>|all\n"
				"\nSupported ifreload-options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --transient\n"
				"      Enable transient interface return codes\n"
				"  --ifconfig <filename>\n"
				"      Read interface configuration(s) from file\n"
				"  --timeout <sec>\n"
				"      Timeout after <sec> seconds\n"
				"  --persistent\n"
				"      Set interface into persistent mode (no regular ifdown allowed)\n"
				"  --[no-]release\n"
				"      Override active config to (not) release leases in ifdown\n"
				"  --dry-run\n"
				"      Show interface hierarchies as notice with (+/-) markers and exit.\n"
				, program);
			goto cleanup;
		}
	}

	/* at least one argument is required */
	if (optind >= argc) {
		fprintf(stderr, "%s: missing interface argument\n", program);
		goto usage;
	}
	for (c = optind; c < argc; ++c) {
		if (ni_string_empty(argv[c]))
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
			ni_error("ifreload: unable to load interface config source list");
			status = NI_WICKED_RC_NOT_CONFIGURED;
			goto cleanup;
		}
	}

	if (!ni_ifconfig_load(fsm, opt_global_rootdir, &opt_ifconfig, TRUE, TRUE)) {
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

	/* Build the up a config relations/hierarchy tree */
	if (ni_fsm_build_hierarchy(fsm, FALSE) < 0) {
		ni_error("ifreload: unable to build interface hierarchy");
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	/* Get workers that match given criteria */
	status = NI_WICKED_RC_SUCCESS;
	for (c = optind; c < argc; ++c) {
		const char *ifname = argv[c];

		if (ni_string_eq(ifname, "all") || ni_string_empty(ifname)) {
			ifreload_match_workers(fsm, &down_marked, &up_marked, NULL);
			break;
		} else {
			ifreload_match_workers(fsm, &down_marked, &up_marked, ifname);
		}
	}
	ni_fsm_print_system_hierarchy(fsm, &down_marked, dry_run);
	ni_fsm_print_config_hierarchy(fsm, &up_marked, dry_run);
	if (dry_run)
		goto cleanup;

	if (opt_persistent) {
		for (i = 0; i < up_marked.count; ++i) {
			ni_ifworker_t *w = up_marked.data[i];
			ni_ifworker_control_set_persistent(w, TRUE);
		}
	}
	if (ni_tristate_is_set(opt_release)) {
		for (i = 0; i < down_marked.count; ++i) {
			ni_ifworker_t *w = down_marked.data[i];
			if (!w->control.persistent)
				w->args.release = opt_release;
		}
	}

	if (!down_marked.count && !up_marked.count) {
		ni_note("ifreload: no configuration changes to reload");
		status = NI_WICKED_RC_SUCCESS;
		goto cleanup;
	}

	/* anything to ifdown? e.g. persistent devices are skipped here */
	if (down_marked.count) {
		/* Run ifdown part of the reload */
		ni_debug_application("Shutting down unneeded devices");

		ifreload_mark_workers_down(fsm, &down_marked);

		/* delete policies */
		ni_ifdown_fire_nanny(&down_marked);

		/* remove delete policy only workers without devices */
		for (i = 0; i < down_marked.count; ++i) {
			ni_ifworker_t *w = down_marked.data[i];

			if (ni_ifcheck_worker_device_exists(w))
				continue;
			if (ni_ifcheck_device_configured(w->device))
				continue;

			if (ni_ifworker_array_remove(&down_marked, w))
				--i;
		}

		/* shutdown existing devices configured by us */
		if (ni_fsm_start_matching_workers(fsm, &down_marked)) {
			/* Execute the down run */
			if (ni_fsm_schedule(fsm) != 0)
				ni_fsm_mainloop(fsm);

			status = ni_ifstatus_shutdown_result(fsm, &ifnames, &down_marked);
		}
	}
	else {
		ni_debug_application("No interfaces to be brought down\n");
	}

	/* Build the up tree */
	if (ni_fsm_build_hierarchy(fsm, TRUE) < 0) {
		ni_error("ifreload: unable to build device hierarchy");
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	/* anything to ifup? */
	if (up_marked.count) {
		if (!(monitor = ni_nanny_fsm_monitor_new(fsm))) {
			/* Severe error we always explicitly return */
			status = NI_WICKED_RC_ERROR;
			goto cleanup;
		}
		ni_nanny_fsm_monitor_arm(monitor, fsm->worker_timeout);

		/* And trigger up */
		ni_debug_application("Reloading all changed devices");
		if (!ni_ifup_hire_nanny(&up_marked, opt_persistent))
			status = NI_WICKED_RC_NOT_CONFIGURED;

		/* Wait for device up-transition progress events */
		ni_nanny_fsm_monitor_run(monitor, &up_marked, status);

		ni_fsm_wait_tentative_addrs(fsm);

		status = ni_ifstatus_display_result(fsm, &ifnames, &up_marked,
			opt_transient);

		/*
		 * Do not report any errors to systemd -- returning an error
		 * here, will cause systemd to stop the network completely.
		 */
		if (opt_systemd)
			status = NI_LSB_RC_SUCCESS;
	}
	else {
		ni_debug_application("No interfaces to be brought up\n");
	}

cleanup:
	ni_string_array_destroy(&ifnames);
	ni_nanny_fsm_monitor_free(monitor);
	ni_string_array_destroy(&opt_ifconfig);
	ni_ifworker_array_destroy(&down_marked);
	ni_ifworker_array_destroy(&up_marked);
	ni_string_free(&program);
	argv[0] = saved_argv0;
	return status;
}

