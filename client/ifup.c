/*
 * Finite state machine and associated functionality for interface
 * bring-up and take-down.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
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
#include <sys/param.h>
#include <sys/stat.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/xml.h>
#include <wicked/socket.h>
#include <wicked/dbus.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/modem.h>
#include <wicked/xpath.h>
#include <wicked/fsm.h>

#include "wicked-client.h"

static ni_bool_t
ni_ifconfig_load(ni_fsm_t *fsm, const char *root, const char *location, ni_bool_t force)
{
	xml_document_array_t docs = XML_DOCUMENT_ARRAY_INIT;
	unsigned int i;

	if (!ni_ifconfig_read(&docs, root, location, FALSE))
		return FALSE;

	for (i = 0; i < docs.count; i++) {
		/* TODO: review ni_fsm_workers_from_xml return codes */
		ni_fsm_workers_from_xml(fsm, docs.data[i], force);
	}

	/* Do not destroy xml documents as referenced by the fsm workers */
	free(docs.data);

	return TRUE;
}

static ni_fsm_t *
ni_ifup_down_init(void)
{
	ni_fsm_t *fsm;

	fsm = ni_fsm_new();

	ni_fsm_require_register_type("reachable", ni_ifworker_reachability_check_new);

	return fsm;
}

static void
fill_state_string(ni_stringbuf_t *sb, const ni_uint_range_t *range)
{
	unsigned int state;

	if (!sb)
		return;

	for (state = (range ? range->min : NI_FSM_STATE_NONE);
	     state <= (range ? range->max : __NI_FSM_STATE_MAX - 1);
	     state++) {
		ni_stringbuf_printf(sb, "%s ", ni_ifworker_state_name(state));
	}
}

int
do_ifup(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_IFCONFIG, OPT_IFPOLICY, OPT_CONTROL_MODE, OPT_STAGE,
		OPT_TIMEOUT, OPT_SKIP_ACTIVE, OPT_SKIP_ORIGIN, OPT_FORCE, OPT_PERSISTENT };
	static struct option ifup_options[] = {
		{ "help",	no_argument,       NULL,	OPT_HELP },
		{ "ifconfig",	required_argument, NULL,	OPT_IFCONFIG },
		{ "ifpolicy",	required_argument, NULL,	OPT_IFPOLICY },
		{ "mode",	required_argument, NULL,	OPT_CONTROL_MODE },
		{ "boot-stage",	required_argument, NULL,	OPT_STAGE },
		{ "skip-active",required_argument, NULL,	OPT_SKIP_ACTIVE },
		{ "skip-origin",required_argument, NULL,	OPT_SKIP_ORIGIN },
		{ "timeout",	required_argument, NULL,	OPT_TIMEOUT },
		{ "force",	no_argument, NULL,	OPT_FORCE },
		{ "persistent",	no_argument, NULL,	OPT_PERSISTENT },
		{ NULL }
	};
	ni_uint_range_t state_range = { .min = NI_FSM_STATE_ADDRCONF_UP, .max = __NI_FSM_STATE_MAX };
	ni_string_array_t opt_ifconfig = NI_STRING_ARRAY_INIT;
	const char *opt_ifpolicy = NULL;
	const char *opt_control_mode = NULL;
	const char *opt_boot_stage = NULL;
	const char *opt_skip_origin = NULL;
	ni_bool_t opt_force = FALSE;
	ni_bool_t opt_skip_active = FALSE;
	ni_bool_t opt_persistent = FALSE;
	unsigned int nmarked, i;
	ni_fsm_t *fsm;
	int c, status = NI_WICKED_RC_USAGE;

	fsm = ni_ifup_down_init();

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			ni_string_array_append(&opt_ifconfig, optarg);
			break;

		case OPT_IFPOLICY:
			opt_ifpolicy = optarg;
			break;

		case OPT_CONTROL_MODE:
			opt_control_mode = optarg;
			break;

		case OPT_STAGE:
			opt_boot_stage = optarg;
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
			opt_skip_origin = optarg;
			break;

		case OPT_SKIP_ACTIVE:
			opt_skip_active = 1;
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
				"wicked [options] ifup [ifup-options] all\n"
				"wicked [options] ifup [ifup-options] <ifname> ...\n"
				"\nSupported ifup-options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --ifconfig <pathname>\n"
				"      Read interface configuration(s) from file/directory rather than using system config\n"
				"  --ifpolicy <pathname>\n"
				"      Read interface policies from the given file/directory\n"
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
				"  --force\n"
				"      Force reconfiguring the interface without checking the config origin\n"
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

	ni_fsm_refresh_state(fsm);

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
		if (!ni_ifconfig_load(fsm, opt_global_rootdir, opt_ifconfig.data[i], opt_force)) {
			status = NI_WICKED_RC_NOT_CONFIGURED;
			goto cleanup;
		}
	}

	if (opt_ifpolicy && !ni_ifconfig_load(fsm, opt_global_rootdir, opt_ifpolicy, opt_force)) {
		status = NI_WICKED_RC_NOT_CONFIGURED;
		goto cleanup;
	}

	if (ni_fsm_build_hierarchy(fsm) < 0) {
		ni_error("ifup: unable to build device hierarchy");
		/* Severe error we always explicitly return */
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	ni_fsm_set_client_state(fsm, opt_persistent);

	nmarked = 0;
	while (optind < argc) {
		static ni_ifmatcher_t ifmatch;

		memset(&ifmatch, 0, sizeof(ifmatch));
		ifmatch.name = argv[optind++];
		/* Allow ifup on all interfaces we have config for */
		ifmatch.require_configured = FALSE;
		ifmatch.allow_persistent = TRUE;
		ifmatch.require_config = TRUE;
		ifmatch.skip_active = opt_skip_active;
		ifmatch.skip_origin = opt_skip_origin;

		if (!strcmp(ifmatch.name, "boot")) {
			ifmatch.name = "all";
			ifmatch.mode = "boot";
		} else {
			ifmatch.mode = opt_control_mode;
			ifmatch.boot_stage = opt_boot_stage;
		}

		nmarked += ni_fsm_mark_matching_workers(fsm, &ifmatch, &state_range);
	}
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
		if (opt_systemd)
			status = NI_LSB_RC_SUCCESS;
	}

cleanup:
	ni_string_array_destroy(&opt_ifconfig);
	return status;
}

int
do_ifdown(int argc, char **argv)
{
	enum  { OPT_HELP, OPT_FORCE, OPT_TIMEOUT };
	static struct option ifdown_options[] = {
		{ "help",	no_argument, NULL,		OPT_HELP },
		{ "force",	required_argument, NULL,	OPT_FORCE },
		{ "timeout",	required_argument, NULL,	OPT_TIMEOUT },
		{ NULL }
	};
	static ni_ifmatcher_t ifmatch;
	ni_uint_range_t target_range = { .min = NI_FSM_STATE_DEVICE_DOWN, .max = __NI_FSM_STATE_MAX - 2};
	unsigned int nmarked, max_state = NI_FSM_STATE_DEVICE_DOWN;
	ni_stringbuf_t sb = NI_STRINGBUF_INIT_DYNAMIC;
	ni_fsm_t *fsm;
	int c, status = NI_WICKED_RC_USAGE;

	fsm = ni_ifup_down_init();

	/* Allow ifdown only on non-persistent interfaces previously configured by ifup */
	memset(&ifmatch, 0, sizeof(ifmatch));
	ifmatch.require_configured = TRUE;
	ifmatch.allow_persistent = FALSE;
	ifmatch.require_config = FALSE;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifdown_options, NULL)) != EOF) {
		switch (c) {
		case OPT_FORCE:
			if (!ni_ifworker_state_from_name(optarg, &max_state) ||
			    !ni_ifworker_state_in_range(&target_range, max_state)) {
				ni_error("ifdown: wrong force option \"%s\"", optarg);
				goto usage;
			}
			/* Allow ifdown on persistent, unconfigured interfaces */
			ifmatch.require_configured = FALSE;
			ifmatch.allow_persistent = TRUE;
			ifmatch.require_config = FALSE;
			break;

		case OPT_TIMEOUT:
			if (!strcmp(optarg, "infinite")) {
				fsm->worker_timeout = NI_IFWORKER_INFINITE_TIMEOUT;
			} else if (ni_parse_uint(optarg, &fsm->worker_timeout, 10) >= 0) {
				fsm->worker_timeout *= 1000; /* sec -> msec */
			} else {
				ni_error("ifdown: cannot parse timeout option \"%s\"", optarg);
				goto usage;
			}
			break;

		default:
		case OPT_HELP:
usage:
			fill_state_string(&sb, &target_range);
			fprintf(stderr,
				"wicked [options] ifdown [ifdown-options] all\n"
				"wicked [options] ifdown [ifdown-options] <ifname> [options ...]\n"
				"\nSupported ifdown-options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --force <state>\n"
				"      Force putting interface into the <state> state. Despite of persistent mode being set. Possible states:\n"
				"  %s\n"
				"  --timeout <nsec>\n"
				"      Timeout after <nsec> seconds\n",
				sb.string
				);
			ni_stringbuf_destroy(&sb);
			return status;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}

	target_range.min = NI_FSM_STATE_NONE;
	target_range.max = max_state;

	if (!ni_fsm_create_client(fsm))
		/* Severe error we always explicitly return */
		return NI_WICKED_RC_ERROR;

	ni_fsm_refresh_state(fsm);

	nmarked = 0;
	while (optind < argc) {
		ifmatch.name = argv[optind++];
		nmarked += ni_fsm_mark_matching_workers(fsm, &ifmatch, &target_range);
	}
	if (nmarked == 0) {
		printf("ifdown: no matching interfaces\n");
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
		if (opt_systemd)
			status = NI_LSB_RC_SUCCESS;
	}

	return status;
}

int
do_ifcheck(int argc, char **argv)
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

	fsm = ni_ifup_down_init();
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
			fill_state_string(&sb, NULL);
			fprintf(stderr,
				"wicked [options] ifcheck [ifcheck-options] all\n"
				"wicked [options] ifcheck [ifcheck-options] <ifname> ...\n"
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

