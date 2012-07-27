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


#define WICKED_IFCONFIG_DIR_PATH	"/etc/sysconfig/network"

/*
 * Read firmware ifconfig (eg iBFT)
 */
static ni_bool_t
ni_ifconfig_firmware_load(ni_fsm_t *fsm)
{
	xml_document_t *config_doc;

	ni_debug_readwrite("%s()", __func__);
	if (!(config_doc = ni_netconfig_firmware_discovery())) {
		ni_error("unable to get firmware interface definitions");
		return FALSE;
	}

	ni_fsm_workers_from_xml(fsm, config_doc, "firmware");

	/* Do *not* delete config_doc; we are keeping references to its
	 * descendant nodes in the ifworkers */
	return TRUE;
}

/*
 * Read ifconfig file(s)
 */
static dbus_bool_t
ni_ifconfig_file_load(ni_fsm_t *fsm, const char *filename)
{
	xml_document_t *config_doc;

	ni_debug_readwrite("%s(%s)", __func__, filename);
	if (!(config_doc = xml_document_read(filename))) {
		ni_error("unable to load interface definition from %s", filename);
		return FALSE;
	}

	ni_fsm_workers_from_xml(fsm, config_doc, NULL);

	/* Do *not* delete config_doc; we are keeping references to its
	 * descendant nodes in the ifworkers */
	return TRUE;
}

static dbus_bool_t
ni_ifconfig_load(ni_fsm_t *fsm, const char *pathname)
{
	char chroot_namebuf[PATH_MAX];
	struct stat stb;

	if (!strcmp(pathname, "FIRMWARE"))
		return ni_ifconfig_firmware_load(fsm);

	if (opt_global_rootdir) {
		snprintf(chroot_namebuf, sizeof(chroot_namebuf), "%s/%s", opt_global_rootdir, pathname);
		pathname = chroot_namebuf;
	}

	ni_debug_readwrite("%s(%s)", __func__, pathname);
	if (stat(pathname, &stb) < 0) {
		ni_error("%s: %m", pathname);
		return FALSE;
	}

	if (S_ISREG(stb.st_mode))
		return ni_ifconfig_file_load(fsm, pathname);
	if (S_ISDIR(stb.st_mode)) {
		ni_string_array_t files = NI_STRING_ARRAY_INIT;
		char namebuf[PATH_MAX];
		unsigned int i;

		if (ni_scandir(pathname, "*.xml", &files) == 0) {
			ni_string_array_destroy(&files);
			return TRUE;
		}
		for (i = 0; i < files.count; ++i) {
			const char *name = files.data[i];

			snprintf(namebuf, sizeof(namebuf), "%s/%s", pathname, name);
			if (!ni_ifconfig_file_load(fsm, namebuf))
				return FALSE;
		}
		ni_string_array_destroy(&files);
		return TRUE;
	}

	ni_error("%s: neither a directory nor a regular file", pathname);
	return FALSE;
}

static ni_fsm_t *
ni_ifup_down_init(void)
{
	ni_fsm_t *fsm;

	fsm = ni_fsm_new();

	ni_fsm_require_register_type("reachable", ni_ifworker_reachability_check_new);

	return fsm;
}

int
do_ifup(int argc, char **argv)
{
	enum  { OPT_IFCONFIG, OPT_IFPOLICY, OPT_CONTROL_MODE, OPT_STAGE, OPT_TIMEOUT, OPT_SKIP_ACTIVE, OPT_SKIP_ORIGIN };
	static struct option ifup_options[] = {
		{ "ifconfig",	required_argument, NULL,	OPT_IFCONFIG },
		{ "ifpolicy",	required_argument, NULL,	OPT_IFPOLICY },
		{ "mode",	required_argument, NULL,	OPT_CONTROL_MODE },
		{ "boot-stage",	required_argument, NULL,	OPT_STAGE },
		{ "skip-active",required_argument, NULL,	OPT_SKIP_ACTIVE },
		{ "skip-origin",required_argument, NULL,	OPT_SKIP_ORIGIN },
		{ "timeout",	required_argument, NULL,	OPT_TIMEOUT },
		{ NULL }
	};
	ni_uint_range_t state_range = { .min = NI_FSM_STATE_ADDRCONF_UP, .max = __NI_FSM_STATE_MAX };
	const char *opt_ifconfig = WICKED_IFCONFIG_DIR_PATH;
	const char *opt_ifpolicy = NULL;
	const char *opt_control_mode = NULL;
	const char *opt_boot_stage = NULL;
	const char *opt_skip_origin = NULL;
	ni_bool_t opt_skip_active = FALSE;
	unsigned int nmarked;
	ni_fsm_t *fsm;
	int c;

	fsm = ni_ifup_down_init();

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			opt_ifconfig = optarg;
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
			} else if (ni_parse_int(optarg, &fsm->worker_timeout) >= 0) {
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

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifup [ifup-options] all\n"
				"wicked [options] ifup [ifup-options] <ifname> ...\n"
				"\nSupported ifup-options:\n"
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
				);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}

	if (!ni_fsm_create_client(fsm))
		return 1;

	ni_fsm_refresh_state(fsm);

	if (!ni_ifconfig_load(fsm, opt_ifconfig))
		return 1;

	if (opt_ifpolicy && !ni_ifconfig_load(fsm, opt_ifpolicy))
		return 1;

	if (ni_fsm_build_hierarchy(fsm) < 0)
		ni_fatal("ifup: unable to build device hierarchy");

	nmarked = 0;
	while (optind < argc) {
		static ni_ifmatcher_t ifmatch;

		memset(&ifmatch, 0, sizeof(ifmatch));
		ifmatch.name = argv[optind++];
		ifmatch.skip_active = opt_skip_active;
		ifmatch.skip_origin = opt_skip_origin;

		if (!strcmp(ifmatch.name, "boot")) {
			ifmatch.name = "all";
			ifmatch.mode = "boot";
			ifmatch.require_config = TRUE;
		} else {
			ifmatch.mode = opt_control_mode;
			ifmatch.boot_stage = opt_boot_stage;
		}

		nmarked += ni_fsm_mark_matching_workers(fsm, &ifmatch, &state_range);
	}
	if (nmarked == 0) {
		printf("No matching interfaces\n");
		return 0;
	}

	if (ni_fsm_schedule(fsm) != 0)
		ni_fsm_mainloop(fsm);

	/* return an error code if at least one of the devices failed */
	return ni_fsm_fail_count(fsm) != 0;
}

int
do_ifdown(int argc, char **argv)
{
	enum  { OPT_IFCONFIG, OPT_DELETE, OPT_TIMEOUT };
	static struct option ifdown_options[] = {
		{ "ifconfig",	required_argument, NULL,	OPT_IFCONFIG },
		{ "delete",	no_argument, NULL,		OPT_DELETE },
		{ "timeout",	required_argument, NULL,	OPT_TIMEOUT },
		{ NULL }
	};
	static ni_ifmatcher_t ifmatch;
	ni_uint_range_t target_range = { .min = NI_FSM_STATE_NONE, .max = NI_FSM_STATE_DEVICE_UP };
	const char *opt_ifconfig = WICKED_IFCONFIG_DIR_PATH;
	unsigned int nmarked;
	/* int opt_delete = 0; */
	ni_fsm_t *fsm;
	int c;

	fsm = ni_ifup_down_init();

	memset(&ifmatch, 0, sizeof(ifmatch));

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifdown_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			opt_ifconfig = optarg;
			break;

		case OPT_DELETE:
			target_range.max = NI_FSM_STATE_DEVICE_DOWN;
			/* opt_delete = 1; */
			break;

		case OPT_TIMEOUT:
			if (!strcmp(optarg, "infinite")) {
				fsm->worker_timeout = NI_IFWORKER_INFINITE_TIMEOUT;
			} else if (ni_parse_int(optarg, &fsm->worker_timeout) >= 0) {
				fsm->worker_timeout *= 1000; /* sec -> msec */
			} else {
				ni_error("ifdown: cannot parse timeout option \"%s\"", optarg);
				goto usage;
			}
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifdown [ifdown-options] all\n"
				"wicked [options] ifdown [ifdown-options] <ifname> [options ...]\n"
				"\nSupported ifdown-options:\n"
				"  --ifconfig <filename>\n"
				"      Read interface configuration(s) from file rather than using system config\n"
				"  --delete\n"
				"      Delete virtual interfaces\n"
				"  --timeout <nsec>\n"
				"      Timeout after <nsec> seconds\n"
				);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing interface argument\n");
		goto usage;
	}

	if (!ni_ifconfig_load(fsm, opt_ifconfig))
		return 1;

	if (!ni_fsm_create_client(fsm))
		return 1;

	ni_fsm_refresh_state(fsm);

	nmarked = 0;
	while (optind < argc) {
		ifmatch.name = argv[optind++];
		nmarked += ni_fsm_mark_matching_workers(fsm, &ifmatch, &target_range);
	}
	if (nmarked == 0) {
		printf("No matching interfaces\n");
		return 0;
	}

	if (ni_fsm_schedule(fsm) != 0)
		ni_fsm_mainloop(fsm);

	/* return an error code if at least one of the devices failed */
	return ni_fsm_fail_count(fsm) != 0;
}

int
do_ifcheck(int argc, char **argv)
{
	enum  { OPT_QUIET, OPT_IFCONFIG, OPT_STATE, OPT_CHANGED };
	static struct option ifcheck_options[] = {
		{ "quiet",	no_argument, NULL,		OPT_QUIET },
		{ "ifconfig",	required_argument, NULL,	OPT_IFCONFIG },
		{ "state",	required_argument, NULL,	OPT_STATE },
		{ "changed",	no_argument, NULL,		OPT_CHANGED },
		{ NULL }
	};
	static ni_ifmatcher_t ifmatch;
	const char *opt_ifconfig = WICKED_IFCONFIG_DIR_PATH;
	/* unsigned int nmarked; */
	ni_bool_t opt_check_changed = FALSE;
	ni_bool_t opt_quiet = FALSE;
	const char *opt_state = NULL;
	ni_fsm_t *fsm;
	int c, status = 0;

	fsm = ni_ifup_down_init();

	memset(&ifmatch, 0, sizeof(ifmatch));

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifcheck_options, NULL)) != EOF) {
		switch (c) {
		case OPT_IFCONFIG:
			opt_ifconfig = optarg;
			break;

		case OPT_STATE:
			if (ni_ifworker_state_from_name(optarg) < 0)
				ni_warn("unknown device state \"%s\"", optarg);
			opt_state = optarg;
			break;

		case OPT_CHANGED:
			opt_check_changed = TRUE;
			break;

		case OPT_QUIET:
			opt_quiet = TRUE;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifcheck [ifcheck-options] all\n"
				"wicked [options] ifcheck [ifcheck-options] <ifname> ...\n"
				"\nSupported ifcheck-options:\n"
				"  --ifconfig <filename>\n"
				"      Read interface configuration(s) from file rather than using system config\n"
				"  --state <state-name>\n"
				"      Verify that the interface(s) are in the given state\n"
				"  --check-changed\n"
				"      Verify that the interface(s) use the current configuration\n"
				"  --quiet\n"
				"      Do not print out errors, but just signal the result through exit status\n"
				);
			return 1;
		}
	}

	if (optind >= argc) {
		ni_error("missing interface argument\n");
		goto usage;
	}

	if (!ni_ifconfig_load(fsm, opt_ifconfig))
		return 1;

	if (!ni_fsm_create_client(fsm))
		return 1;

	ni_fsm_refresh_state(fsm);

	/* nmarked = 0; */
	while (optind < argc) {
		ni_ifworker_array_t marked = { 0, NULL };
		const char *ifname = argv[optind++];
		unsigned int i;

		ifmatch.name = ifname;
		if (ni_fsm_get_matching_workers(fsm, &ifmatch, &marked) == 0) {
			ni_error("%s: no matching interfaces", ifname);
			status = 1;
			continue;
		}

		for (i = 0; i < marked.count; ++i) {
			ni_ifworker_t *w = marked.data[i];
			ni_netdev_t *dev;
			ni_netdev_clientinfo_t *client_info;

			if ((dev = w->device) == NULL) {
				if (!opt_quiet)
					ni_error("%s: device %s does not exist", ifname, w->object_path);
				status = 2;
				continue;
			}

			client_info = dev->client_info;
			if (opt_check_changed) {
				if (!client_info || !ni_uuid_equal(&client_info->config_uuid, &w->config.uuid)) {
					if (!opt_quiet)
						ni_error("%s: device configuration changed", w->name);
					ni_debug_wicked("%s: config file uuid is %s", w->name, ni_uuid_print(&w->config.uuid));
					ni_debug_wicked("%s: system dev. uuid is %s", w->name,
							client_info? ni_uuid_print(&client_info->config_uuid) : "NOT SET");
					status = 3;
					continue;
				}
			}

			if (opt_state) {
				if (!client_info || !ni_string_eq(client_info->state, opt_state)) {
					if (!opt_quiet)
						ni_error("%s: device has state %s, expected %s", w->name,
								client_info? client_info->state : "NONE",
								opt_state);
					status = 4;
					continue;
				}
			}

			printf("%s: exists%s%s", w->name,
					opt_check_changed? ", configuration unchanged" : "",
					opt_state? ", interface state as expected" : "");
		}
	}

	return status;
}
