/*
 *	wicked client ifcheck action and utilities
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
#include "ifcheck.h"

/*
 * ifcheck utilities
 */
ni_bool_t
ni_ifcheck_device_configured(ni_netdev_t *dev)
{
	ni_device_clientinfo_t *ci;

	if (!dev || !(ci = dev->client_info) || ni_string_empty(ci->config_origin))
		return FALSE;
	return TRUE;
}

ni_bool_t
ni_ifcheck_device_is_up(ni_netdev_t *dev)
{
	return dev && !!(dev->link.ifflags & NI_IFF_DEVICE_UP);
}

ni_bool_t
ni_ifcheck_device_link_is_up(ni_netdev_t *dev)
{
	return dev && !!(dev->link.ifflags & NI_IFF_LINK_UP);
}

ni_bool_t
ni_ifcheck_device_network_is_up(ni_netdev_t *dev)
{
	return dev && !!(dev->link.ifflags & NI_IFF_NETWORK_UP);
}

unsigned int
__ifcheck_device_fsm_state(ni_netdev_t *dev)
{
	ni_device_clientinfo_t *ci;

	if (dev && (ci = dev->client_info)) {
		unsigned int state;

		if (ni_ifworker_state_from_name(ci->state, &state))
			return state;
	}
	return NI_FSM_STATE_NONE;
}

ni_bool_t
ni_ifcheck_device_fsm_is_up(ni_netdev_t *dev)
{
	return __ifcheck_device_fsm_state(dev) >= NI_FSM_STATE_DEVICE_UP;
}

ni_bool_t
ni_ifcheck_device_fsm_link_is_up(ni_netdev_t *dev)
{
	return __ifcheck_device_fsm_state(dev) >= NI_FSM_STATE_LINK_UP;
}

ni_bool_t
ni_ifcheck_device_is_persistent(ni_netdev_t *dev)
{
	return dev && dev->client_state && dev->client_state->persistent;
}

ni_bool_t
ni_ifcheck_worker_device_exists(ni_ifworker_t *w)
{
	return w && w->device;
}

ni_bool_t
ni_ifcheck_worker_device_enabled(ni_ifworker_t *w)
{
#if 0
	/* Hmm... STARTMODE=manual|off */

	if (!w || !w->control.enabled)
		return FALSE;
#endif
	return TRUE;
}

ni_bool_t
ni_ifcheck_worker_device_is_mandatory(ni_ifworker_t *w)
{
	return w && w->control.mandatory;
}

ni_bool_t
ni_ifcheck_worker_device_link_required(ni_ifworker_t *w)
{
	return w && w->control.link_required;
}

ni_bool_t
ni_ifcheck_worker_device_is_persistent(ni_ifworker_t *w)
{
	return w && w->control.persistent;
}

ni_bool_t
ni_ifcheck_worker_config_exists(ni_ifworker_t *w)
{
	return w && w->config.node;
}

ni_bool_t
ni_ifcheck_worker_config_matches(ni_ifworker_t *w)
{
	ni_netdev_t *dev;

	if (w && w->config.node && (dev = w->device)) {
		ni_device_clientinfo_t *ci = dev->client_info;

		return ci && ni_uuid_equal(&ci->config_uuid, &w->config.uuid);
	}
	return FALSE;
}

/*
 * ifcheck action
 */
int
ni_do_ifcheck(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_QUIET, OPT_IFCONFIG, OPT_STATE, OPT_CHANGED, OPT_PERSISTENT };
	static struct option ifcheck_options[] = {
		{ "help",	no_argument, NULL,		OPT_HELP },
		{ "quiet",	no_argument, NULL,		OPT_QUIET },
		{ "ifconfig",	required_argument, NULL,	OPT_IFCONFIG },
		{ "state",	required_argument, NULL,	OPT_STATE },
		{ "changed",	no_argument, NULL,		OPT_CHANGED },
		{ "persistent",	no_argument, NULL,		OPT_PERSISTENT },
		{ NULL }
	};
	static ni_ifmatcher_t ifmatch;
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	/* unsigned int nmarked; */
	ni_bool_t opt_check_changed = FALSE;
	ni_bool_t opt_quiet = FALSE;
	ni_bool_t opt_persistent = FALSE;
	const char *opt_state = NULL;
	ni_stringbuf_t sb = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int i, opt_state_val;
	ni_fsm_t *fsm;
	int c, status = NI_WICKED_RC_USAGE;

	fsm = ni_fsm_new();
	ni_assert(fsm);
	fsm->readonly = TRUE;

	/* Allow ifcheck on persistent, unconfigured interfaces */
	memset(&ifmatch, 0, sizeof(ifmatch));
	ifmatch.require_configured = FALSE;
	ifmatch.allow_persistent = TRUE;
	ifmatch.require_config = FALSE;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifcheck_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			ni_string_array_append(&opt_ifconfig, optarg);
			break;

		case OPT_STATE:
			if (!ni_ifworker_state_from_name(optarg, &opt_state_val))
				ni_warn("unknown device state \"%s\"", optarg);
			opt_state = optarg;
			break;

		case OPT_CHANGED:
			opt_check_changed = TRUE;
			break;

		case OPT_QUIET:
			opt_quiet = TRUE;
			break;

		case OPT_PERSISTENT:
			opt_persistent = TRUE;
			break;

		default:
		case OPT_HELP:
usage:
			ni_fsm_fill_state_string(&sb, NULL);
			fprintf(stderr,
				"wicked [options] ifcheck [ifcheck-options] <ifname ...>|all\n"
				"\nSupported ifcheck-options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --ifconfig <filename>\n"
				"      Read interface configuration(s) from file\n"
				"  --state <state-name>\n"
				"      Verify that the interface(s) are in the given state. Possible states:\n"
				"  %s\n"
				"  --changed\n"
				"      Verify that the interface(s) use the current configuration\n"
				"  --quiet\n"
				"      Do not print out errors, but just signal the result through exit status\n"
				"  --persistent\n"
				"      Show whether interface is in persistent mode\n",
				sb.string
				);
			ni_stringbuf_destroy(&sb);
			goto cleanup;
		}
	}

	if (optind >= argc) {
		ni_error("missing interface argument\n");
		goto usage;
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

	for (i = 0; i < opt_ifconfig.count; ++i) {
		if (!ni_ifconfig_load(fsm, opt_global_rootdir, opt_ifconfig.data[i], TRUE)) {
			status = NI_WICKED_RC_NOT_CONFIGURED;
			goto cleanup;
		}
	}

	if (!ni_fsm_create_client(fsm)) {
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	ni_fsm_refresh_state(fsm);
	status = NI_WICKED_ST_OK;

	/* nmarked = 0; */
	while (optind < argc) {
		ni_ifworker_array_t marked = { 0, NULL };
		const char *ifname = argv[optind++];
		unsigned int i;

		ifmatch.name = ifname;
		if (ni_fsm_get_matching_workers(fsm, &ifmatch, &marked) == 0) {
			ni_error("%s: no matching interfaces", ifname);
			status = NI_WICKED_RC_NO_DEVICE;
			continue;
		}

		for (i = 0; i < marked.count; ++i) {
			ni_ifworker_t *w = marked.data[i];
			ni_netdev_t *dev;
			ni_device_clientinfo_t *client_info;

			if ((dev = w->device) == NULL) {
				if (!opt_quiet) {
					ni_error("%s: device from %s does not exist",
						strcmp(ifname, "all") ? ifname : w->name, w->config.origin);
				}
				status = NI_WICKED_RC_NO_DEVICE;
				continue;
			}

			if (!opt_quiet)
				printf("wicked: %s: exists\n", w->name);

			client_info = dev->client_info;
			if (opt_check_changed) {
				if (client_info && ni_uuid_equal(&client_info->config_uuid, &w->config.uuid)) {
					if (!opt_quiet)
						printf("wicked: %s: configuration unchanged\n", w->name);
				}
				else {
					if (!opt_quiet)
						ni_error("%s: device configuration changed", w->name);
					ni_debug_wicked("%s: config file uuid is %s", w->name, ni_uuid_print(&w->config.uuid));
					ni_debug_wicked("%s: system dev. uuid is %s", w->name,
							client_info? ni_uuid_print(&client_info->config_uuid) : "NOT SET");
					status = NI_WICKED_ST_CHANGED_CONFIG;
				}
			}

			if (opt_state) {
				unsigned int state_val;
				char *state = client_info ? client_info->state : "none";
				if (!ni_ifworker_state_from_name(state, &state_val))
					state_val = NI_FSM_STATE_NONE;

				if (NI_FSM_STATE_NONE == opt_state_val || state_val >= opt_state_val) {
					if (!opt_quiet)
						printf("wicked: %s: device has state %s\n", w->name, state);
				}
				else {
					if (!opt_quiet)
						ni_error("%s: device has state %s, expected %s", w->name, state, opt_state);
					status = NI_WICKED_ST_NOT_IN_STATE;
				}
			}

			if (opt_persistent) {
				if (!w->client_state.persistent) {
					if (!opt_quiet)
						printf("wicked: %s: persistent mode is not set\n", w->name);
				}
				else {
					if (!opt_quiet)
						ni_error("%s: device configured in persistent mode", w->name);
					status = NI_WICKED_ST_PERSISTENT_ON;
				}
			}
		}
	}

cleanup:
	ni_string_array_destroy(&opt_ifconfig);
	return status;
}

