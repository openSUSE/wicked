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
#include "appconfig.h"
#include "ifcheck.h"

static ni_bool_t opt_quiet;
/*
 * ifcheck utilities
 */
ni_bool_t
ni_ifcheck_device_configured(ni_netdev_t *dev)
{
	ni_client_state_t *cs;

	if (!dev || !(cs = dev->client_state) || ni_string_empty(cs->config.origin))
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

ni_bool_t
ni_ifcheck_device_is_persistent(ni_netdev_t *dev)
{
	ni_client_state_t *cs = dev ? dev->client_state : NULL;
	return cs && cs->control.persistent;
}

ni_bool_t
ni_ifcheck_device_link_required(ni_netdev_t *dev)
{
	ni_client_state_t *cs = dev ? dev->client_state : NULL;
	ni_tristate_t link_required = NI_TRISTATE_DEFAULT;

	if (cs && ni_tristate_is_set(cs->control.require_link))
		link_required = cs->control.require_link;
	else if (dev)
		link_required = ni_netdev_guess_link_required(dev);

	return !ni_tristate_is_disabled(link_required);
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
ni_ifcheck_worker_device_link_required(ni_ifworker_t *w)
{
	ni_tristate_t link_required = NI_TRISTATE_DEFAULT;

	if (w && ni_tristate_is_set(w->control.link_required))
		link_required = w->control.link_required;
	else if (w && w->device)
		link_required = ni_netdev_guess_link_required(w->device);

	return !ni_tristate_is_disabled(link_required);
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

	if (ni_ifcheck_worker_config_exists(w) && (dev = w->device)) {
		ni_client_state_t *cs = dev->client_state;

		return cs &&
			ni_uuid_equal(&cs->config.uuid, &w->config.meta.uuid);
	}
	return FALSE;
}

ni_bool_t
ni_ifcheck_worker_not_in_state(ni_ifworker_t *w, ni_fsm_state_t state_val)
{
	ni_fsm_state_t state_dev;

	ni_assert(w);
	/* FIXME: add state mapping */
	state_dev = NI_FSM_STATE_NONE;

	if (state_val < NI_FSM_STATE_DEVICE_EXISTS && state_dev > state_val)
		return TRUE;
	if (state_dev < state_val)
		return TRUE;
	return FALSE;
}

static void
if_printf(const char *dev, const char *flag, const char *fmt, ...)
{
	va_list ap;

	if (opt_quiet)
		return;
	if (!ni_string_empty(dev)) {
		printf("%-15s", dev);
	} else {
		printf("%-6s", "");
	}
	if (!ni_string_empty(flag) && !ni_string_empty(fmt)) {
		printf(" %-22s = ", flag);
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
	printf("\n");
}

static inline void
set_status(int *status, unsigned int code)
{
	if (NI_WICKED_ST_OK == *status)
		*status = code;
}

/*
 * ifcheck action
 */
int
ni_do_ifcheck(int argc, char **argv)
{
	enum { OPT_HELP, OPT_QUIET, OPT_IFCONFIG, OPT_MISSED, OPT_CHANGED, OPT_STATE, OPT_PERSISTENT };
	static struct option ifcheck_options[] = {
		{ "help",	no_argument, NULL,		OPT_HELP },
		{ "quiet",	no_argument, NULL,		OPT_QUIET },
		{ "ifconfig",	required_argument, NULL,	OPT_IFCONFIG },
		{ "missed",	no_argument, NULL,		OPT_MISSED },
		{ "changed",	no_argument, NULL,		OPT_CHANGED },
		{ "state",	required_argument, NULL,	OPT_STATE },
		{ "persistent",	no_argument, NULL,		OPT_PERSISTENT },
		{ NULL }
	};
	static ni_ifmatcher_t ifmatch;
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	ni_uint_array_t checks = NI_UINT_ARRAY_INIT;
	ni_stringbuf_t sb = NI_STRINGBUF_INIT_DYNAMIC;
	const char *opt_state = NULL;
	ni_bool_t multiple = FALSE;
	ni_fsm_t *fsm;
	unsigned int i, opt_state_val;
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

		case OPT_MISSED:
			ni_uint_array_append(&checks, OPT_MISSED);
			break;

		case OPT_CHANGED:
			ni_uint_array_append(&checks, OPT_CHANGED);
			break;

		case OPT_STATE:
			if (!ni_ifworker_state_from_name(optarg, &opt_state_val)) {
				ni_error("Invalid device state \"%s\"", optarg);
				goto usage;
			}
			ni_uint_array_append(&checks, OPT_STATE);
			opt_state = optarg;
			break;

		case OPT_PERSISTENT:
			ni_uint_array_append(&checks, OPT_PERSISTENT);
			break;

		case OPT_QUIET:
			opt_quiet = TRUE;

			break;

		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			ni_client_get_state_strings(&sb, NULL);
			fprintf(stderr,
				"wicked [options] ifcheck [ifcheck-options] <ifname ...>|all\n"
				"\nSupported ifcheck-options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --ifconfig <filename>\n"
				"      Read interface configuration(s) from file\n"
				"  --quiet\n"
				"      Do not print out errors, but just signal the result through exit status\n"
				"  --missed\n"
				"      Check if the interface is missed\n"
				"  --changed\n"
				"      Check if the interface's configuration is changed\n"
				"  --state <state-name>\n"
				"      Check if the interface is in the given state. Possible states:\n"
				"  %s\n"
				"  --persistent\n"
				"      Check if the interface is in persistent mode\n"
				, sb.string);
			ni_stringbuf_destroy(&sb);
			goto cleanup;
		}
	}

	if (optind >= argc) {
		goto usage;
	} else for (c = optind; c < argc; ++c) {
		if (ni_string_empty(argv[c]))
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

	if (!ni_ifconfig_load(fsm, opt_global_rootdir, &opt_ifconfig, TRUE, TRUE)) {
		status = NI_WICKED_RC_NOT_CONFIGURED;
		goto cleanup;
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

	status = NI_WICKED_ST_OK;

	if (0 == checks.count)
		ni_uint_array_append(&checks, OPT_MISSED);
	/* nmarked = 0; */
	while (optind < argc) {
		ni_ifworker_array_t marked = { 0, NULL };
		const char *ifname = argv[optind++];

		ifmatch.name = ifname;
		if (ni_fsm_get_matching_workers(fsm, &ifmatch, &marked) == 0) {
			if_printf(ifname, "device exists", "no");
			set_status(&status, NI_WICKED_RC_NO_DEVICE);
			continue;
		}
		if (ni_string_eq(ifmatch.name, "all"))
			multiple = TRUE;

		for (i = 0; i < marked.count; ++i) {
			ni_ifworker_t *w = marked.data[i];
			ni_netdev_t *dev = w->device;
			ni_client_state_t *cs = dev ? dev->client_state : NULL;
			unsigned int j;

			if (ni_string_array_index(&ifnames, w->name) != -1)
				continue;
			multiple = ifnames.count ? TRUE : multiple;
			ni_string_array_append(&ifnames, w->name);

			for (j = 0; j < checks.count; j++) {
				switch (checks.data[j]) {
					ni_bool_t changed, not_in_state, persistent;

					default:
					case OPT_MISSED:
						if_printf(w->name, "device exists", (dev ? "yes" : "no"));

						if (!dev)
							set_status(&status, NI_WICKED_RC_NO_DEVICE);
						break;

					case OPT_CHANGED:
						changed = FALSE;
						if (ni_ifcheck_device_configured(dev) ||
						     (ni_ifcheck_worker_config_exists(w) &&
						      ni_ifcheck_worker_device_exists(w)))
							changed = !ni_ifcheck_worker_config_matches(w);

						if_printf(w->name, "configuration changed",
								(changed ? "yes" : "no"));
						if (changed) {
							ni_debug_wicked("%s: config file uuid is %s", w->name,
								ni_uuid_print(&w->config.meta.uuid));
							ni_debug_wicked("%s: system dev. uuid is %s", w->name,
								cs ? ni_uuid_print(&cs->config.uuid) : "NOT SET");
							set_status(&status, NI_WICKED_ST_CHANGED_CONFIG);
						}
						break;

					case OPT_STATE:
						not_in_state = ni_ifcheck_worker_not_in_state(w, opt_state_val);

						if_printf(w->name, "queried state", "%s (%s)",
							(not_in_state ? "no" : "yes"), opt_state);
						if (not_in_state)
							set_status(&status, NI_WICKED_ST_NOT_IN_STATE);
						break;

					case OPT_PERSISTENT:
						persistent = ni_ifcheck_device_is_persistent(dev);

						if_printf(w->name, "persistent", (persistent ? "yes" : "no"));
						if (persistent)
							set_status(&status, NI_WICKED_ST_PERSISTENT_ON);
						break;
				}
			}
			if (opt_quiet && status)
				goto cleanup;
		}
	}

cleanup:
	ni_string_array_destroy(&opt_ifconfig);
	ni_string_array_destroy(&ifnames);
	ni_uint_array_destroy(&checks);
	return status;
}

