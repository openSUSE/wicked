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

static ni_bool_t
ifreload_mark_add(ni_ifworker_array_t *marked, ni_ifworker_t *w)
{
	if (ni_ifworker_array_index(marked, w) != -1)
		return FALSE;

	ni_ifworker_array_append(marked, w);
	return TRUE;
}

static inline void
ifreload_mark_down_lower_deps(const ni_fsm_t *fsm, ni_ifworker_array_t *marked, ni_ifworker_t *lower,
				void (*logit)(const char *, ...) ni__printf(1, 2))
{
	ni_ifworker_t *w;
	unsigned int i;

	/* we need to shutdown also all depending worker devices c
	 * that can't exist without w device (c->lowerdev == w) */
	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if (!w || w->lowerdev != lower)
			continue;

		if (ni_ifcheck_device_is_persistent(w->device)) {
			logit("skipping %s shutdown: persistent mode is on", w->name);
			continue;
		}

		w->target_range.min = NI_FSM_STATE_NONE;
		w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;

		if (!ifreload_mark_add(marked, w))
			continue;

		ni_debug_ifconfig("marked %s for shutdown (config: %s, device: %s, target state %s) as dependency",
				w->name,
				ni_ifcheck_worker_config_exists(w) ? "exists" :
				ni_ifcheck_device_configured(w->device) ? "deleted" : "-",
				ni_ifcheck_worker_device_exists(w) ? "exists" : "-",
				ni_ifworker_state_name(w->target_range.max));
	}
}

static ni_bool_t
ifreload_mark_down(const ni_fsm_t *fsm, ni_ifworker_array_t *marked, ni_ifworker_t *w,
				void (*logit)(const char *, ...) ni__printf(1, 2),
				unsigned int depth)
{
	/* ifdown is disabled when persistent mode is on (todo: add --force?) */
	if (ni_ifcheck_device_is_persistent(w->device)) {
		logit("skipping %s shutdown: persistent mode is on", w->name);
		return FALSE;
	}

	/* initialize as if the config would have been modified */
	if (ni_ifcheck_worker_config_exists(w)) {
		w->target_range.min = NI_FSM_STATE_NONE;
		w->target_range.max = NI_FSM_STATE_DEVICE_READY;

		/* the config has been modified, but some changes require deletion */
		if (w->iftype == NI_IFTYPE_TEAM || w->iftype == NI_IFTYPE_VLAN) {
			/* examples:
			 *   - the team runner (mode) changes require teamd restart
			 *   - VlanID changed, the interface need to be recreated */
			w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
		} else
		if (w->iftype != NI_IFTYPE_UNKNOWN) {
			/* if type changed, e.g. device is bond with bridge config */
			if (w->device && w->device->link.type != w->iftype)
				w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
		}
	} else
	if (ni_ifcheck_device_configured(w->device)) {
		/* config has been removed, so just delete it if applicable (=virtual) */
		w->target_range.min = NI_FSM_STATE_NONE;
		w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
		ni_client_state_config_reset(&w->config.meta);
	} else
	if (!ni_ifcheck_worker_device_exists(w)) {
		/* when the device does not exists, delete policy in nanny (if any) */
		w->target_range.min = NI_FSM_STATE_NONE;
		w->target_range.max = NI_FSM_STATE_DEVICE_DOWN;
	} else {
		/* do not shut down devices we don't handle */
		logit("skipping %s shutdown: device was not configured by wicked", w->name);
		return FALSE;
	}

	if (depth && ni_ifcheck_worker_device_exists(w)) {
		ni_ifworker_t *c;
		unsigned int i;

		for (i = 0; i < fsm->workers.count; ++i) {
			c = fsm->workers.data[i];

			if (!ni_ifcheck_worker_device_exists(c))
				continue;

			if (!ni_string_eq(c->device->link.masterdev.name, w->name))
				continue;

			if (!ni_ifcheck_worker_config_matches(c)) {
				ni_trace("exec ifreload_mark_workers down: %s", c->name);
				ifreload_mark_down(fsm, marked, c, logit, depth - 1);
			}
		}
	}

	/* shut down depending devices because this one is deleted */
	if (w->target_range.max == NI_FSM_STATE_DEVICE_DOWN)
		ifreload_mark_down_lower_deps(fsm, marked, w, logit);

	if (!ifreload_mark_add(marked, w))
		return FALSE;

	ni_debug_ifconfig("marked %s for shutdown (config: %s, device: %s, target state %s)",
			w->name,
			ni_ifcheck_worker_config_exists(w) ? "exists" :
			ni_ifcheck_device_configured(w->device) ? "deleted" : "-",
			ni_ifcheck_worker_device_exists(w) ? "exists" : "-",
			ni_ifworker_state_name(w->target_range.max));

	return TRUE;
}

static void
ifreload_mark_up_slave_deps(const ni_fsm_t *fsm, ni_ifworker_array_t *marked, ni_ifworker_t *master,
				void (*logit)(const char *, ...) ni__printf(1, 2))
{
	ni_ifworker_t *w;
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if (!w || w->masterdev != master)
			continue;

		if (!ni_ifcheck_worker_config_exists(w)) {
			logit("skipping %s set-up: no configuration available", w->name);
			continue;
		}

		if (!ifreload_mark_add(marked, w))
			continue;

		ni_debug_ifconfig("marked %s for set-up (config: %s, device: %s, target state %s) as dependency",
				w->name,
				(ni_ifcheck_worker_config_exists(w) ?
				 (ni_ifcheck_worker_config_matches(w) ? "unchanged" : "modified") :
				 (ni_ifcheck_device_configured(w->device) ? "deleted" : "-")),
				(ni_ifcheck_worker_device_exists(w) ? "exists" : "-"),
				ni_ifworker_state_name(w->target_range.max));
	}
}

static void
ifreload_mark_up_master(const ni_fsm_t *fsm, ni_ifworker_array_t *marked, ni_ifworker_t *w,
				void (*logit)(const char *, ...) ni__printf(1, 2))
{
	if (!ni_ifcheck_worker_config_exists(w)) {
		logit("skipping %s set-up: no configuration available", w->name);
		return;
	}

	if (!ifreload_mark_add(marked, w))
		return;

	ni_debug_ifconfig("marked %s for set-up (config %s, device %s, target state %s) as dependency",
			w->name,
			(ni_ifcheck_worker_config_exists(w) ?
			 (ni_ifcheck_worker_config_matches(w) ? "unchanged" : "modified") :
			 (ni_ifcheck_device_configured(w->device) ? "deleted" : "-")),
			(ni_ifcheck_worker_device_exists(w) ? "exists" : "-"),
			ni_ifworker_state_name(w->target_range.max));
}

static void
ifreload_mark_up_lower_deps(const ni_fsm_t *fsm, ni_ifworker_array_t *marked, ni_ifworker_t *lower,
				void (*logit)(const char *, ...) ni__printf(1, 2))
{
	ni_ifworker_t *w;
	unsigned int i;

	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if (!w || w->lowerdev != lower)
			continue;

		if (!ni_ifcheck_worker_config_exists(w)) {
			logit("skipping %s set-up: no configuration available", w->name);
			continue;
		}

		/* e.g. a vlan [w] can't exist without it's lowerdev [l]
		 * and is deleted as dependency to deletion of lower [l].
		 * for now, we need to trigger set-up of it's master [m]
		 * (team0 [l] <-lower- team0.42 [w] -master-> [m] br42)
		 * to ensure it gets (re-)enslaved into it.
		 */
		if (w->masterdev)
			ifreload_mark_up_master(fsm, marked, w->masterdev, logit);

		if (!ifreload_mark_add(marked, w))
			continue;

		ni_debug_ifconfig("marked %s for set-up (config %s, device %s, target state %s) as dependency",
				w->name,
				(ni_ifcheck_worker_config_exists(w) ?
				 (ni_ifcheck_worker_config_matches(w) ? "unchanged" : "modified") :
				 (ni_ifcheck_device_configured(w->device) ? "deleted" : "-")),
				(ni_ifcheck_worker_device_exists(w) ? "exists" : "-"),
				ni_ifworker_state_name(w->target_range.max));
	}
}

static ni_bool_t
ifreload_mark_up(const ni_fsm_t *fsm, ni_ifworker_array_t *marked, ni_ifworker_t *w,
				void (*logit)(const char *, ...) ni__printf(1, 2))
{
	if (!ni_ifcheck_worker_config_exists(w)) {
		logit("skipping %s set-up: no configuration available", w->name);
		return FALSE;
	}

	/* trigger set-up for slaves to (re-)enslave them */
	ifreload_mark_up_slave_deps(fsm, marked, w, logit);

	/* trigger set-up for devices we're base / lower
	 * for as they can't exists without their base */
	ifreload_mark_up_lower_deps(fsm, marked, w, logit);

	if (!ifreload_mark_add(marked, w))
		return FALSE;

	ni_debug_ifconfig("marked %s for set-up (config %s, device %s, target state %s)",
			w->name,
			(ni_ifcheck_worker_config_exists(w) ?
			 (ni_ifcheck_worker_config_matches(w) ? "unchanged" : "modified") :
			 (ni_ifcheck_device_configured(w->device) ? "deleted" : "-")),
			(ni_ifcheck_worker_device_exists(w) ? "exists" : "-"),
			ni_ifworker_state_name(w->target_range.max));

	return TRUE;
}

static void
ifreload_mark_workers(const ni_fsm_t *fsm, ni_ifworker_array_t *down_marked, ni_ifworker_array_t *up_marked, const char *ifname)
{
	void (*logit)(const char *, ...) ni__printf(1, 2) = ifname ? ni_note : ni_info;
	ni_ifworker_t *w;
	unsigned int i;

	/* shutdown if config changed + dependencies */
	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if (w->type != NI_IFWORKER_TYPE_NETDEV)
			continue;

		if (ifname && !ni_string_eq(w->name, ifname))
			continue;

		if (!ni_ifcheck_worker_config_matches(w))
			ifreload_mark_down(fsm, down_marked, w, logit, 1);
	}

	/* set-up if config changed + dependencies */
	for (i = 0; i < fsm->workers.count; ++i) {
		w = fsm->workers.data[i];

		if (w->type != NI_IFWORKER_TYPE_NETDEV)
			continue;

		if (ifname && !ni_string_eq(w->name, ifname))
			continue;

		if (!ni_ifcheck_worker_config_matches(w))
			ifreload_mark_up(fsm, up_marked, w, logit);
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
	};
	static struct option ifreload_options[] = {
		{ "help",		no_argument,		NULL,	OPT_HELP },
		{ "ifconfig",		required_argument,	NULL,	OPT_IFCONFIG },
		{ "timeout",		required_argument,	NULL,	OPT_TIMEOUT },
		{ "transient",		no_argument,		NULL,	OPT_TRANSIENT },
		{ "persistent",		no_argument,		NULL,	OPT_PERSISTENT },
		{ "release",		no_argument,		NULL,	OPT_RELEASE },
		{ "no-release",		no_argument,		NULL,	OPT_NO_RELEASE },

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
		ni_error("ifreload: unable to build device config hierarchy");
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_SUCCESS;
	for (c = optind; c < argc; ++c) {
		const char *ifname = argv[c];

		if (ni_string_eq(ifname, "all") || ni_string_empty(ifname)) {
			ifreload_mark_workers(fsm, &down_marked, &up_marked, NULL);
			break;
		} else {
			ifreload_mark_workers(fsm, &down_marked, &up_marked, ifname);
		}
	}

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

	ni_fsm_pull_in_children(&up_marked, fsm);

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

