/*
 * This daemon manages interfaces in response to link up/down
 * events, WLAN network reachability, etc.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#ifdef HAVE_SYSTEMD_SD_DAEMON_H
#include <systemd/sd-daemon.h>
#endif

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/objectmodel.h>
#include <wicked/modem.h>
#include <wicked/wireless.h>
#include <wicked/fsm.h>

#include "client/ifconfig.h"
#include "util_priv.h"
#include "nanny.h"

enum {
	OPT_HELP,
	OPT_VERSION,
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_LOG_LEVEL,
	OPT_LOG_TARGET,
	OPT_SYSTEMD,

	OPT_FOREGROUND,
#ifdef MODEM
	OPT_NOMODEMMGR,
#endif
};

static struct option	options[] = {
	/* common */
	{ "help",		no_argument,		NULL,	OPT_HELP },
	{ "version",		no_argument,		NULL,	OPT_VERSION },
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "log-level",		required_argument,	NULL,	OPT_LOG_LEVEL },
	{ "log-target",		required_argument,	NULL,	OPT_LOG_TARGET },
	{ "systemd",		no_argument,		NULL,	OPT_SYSTEMD },

	/* daemon */
	{ "foreground",		no_argument,		NULL,	OPT_FOREGROUND },

#ifdef MODEM
	/* specific */
	{ "no-modem-manager",	no_argument,		NULL,	OPT_NOMODEMMGR },
#endif

	{ NULL }
};

static const char *	program_name;
static const char *	opt_log_target;
static ni_bool_t	opt_foreground;
#ifdef MODEM
static ni_bool_t	opt_no_modem_manager;
#endif
static ni_bool_t	opt_systemd;

static void		babysit(void);
static void		ni_nanny_discover_state(ni_nanny_t *);

//static void		handle_interface_event(ni_netdev_t *, ni_event_t);
//static void		handle_modem_event(ni_modem_t *, ni_event_t);
static void		handle_rfkill_event(ni_rfkill_type_t, ni_bool_t, void *user_data);
static ni_bool_t	ni_nanny_config_callback(void *, const xml_node_t *);

int
main(int argc, char **argv)
{
	int c;

	ni_log_init();
	program_name = ni_basename(argv[0]);

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		case OPT_HELP:
		default:
		usage:
			fprintf(stderr,
				"%s [options]\n"
				"This command understands the following options\n"
				"  --help\n"
				"  --version\n"
				"  --config filename\n"
				"        Read configuration file <filename> instead of system default.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
				"        Use '--debug help' for a list of debug facilities.\n"
				"  --log-devel level\n"
				"        Set log level to <error|warning|notice|info|debug>.\n"
				"  --log-target target\n"
				"        Set log destination to <stderr|syslog>.\n"
				"  --foreground\n"
				"        Run as a foreground process, rather than as a daemon.\n"
				"  --log-target target\n"
				"        Set log destination target to <target>.\n"
				"  --systemd\n"
				"        Enables behavior required by systemd service\n"
				, program_name);
			return (c == OPT_HELP ? NI_LSB_RC_SUCCESS : NI_LSB_RC_USAGE);

		case OPT_VERSION:
			printf("%s %s\n", program_name, PACKAGE_VERSION);
			return NI_LSB_RC_SUCCESS;

		case OPT_CONFIGFILE:
			if (!ni_set_global_config_path(optarg)) {
				fprintf(stderr, "Unable to set config file '%s': %m\n", optarg);
				return NI_LSB_RC_ERROR;
			}
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help();
				return NI_LSB_RC_SUCCESS;
			}
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				goto usage;
			}
			break;

		case OPT_LOG_LEVEL:
			if (!ni_log_level_set(optarg)) {
				fprintf(stderr, "Bad log level \%s\"\n", optarg);
				goto usage;
			}
			break;

		case OPT_LOG_TARGET:
			opt_log_target = optarg;
			break;

		case OPT_FOREGROUND:
			opt_foreground = TRUE;
			break;

#ifdef MODEM
		case OPT_NOMODEMMGR:
			opt_no_modem_manager = TRUE;
			break;
#endif

		case OPT_SYSTEMD:
			opt_systemd = TRUE;
			break;
		}
	}

	if (optind != argc)
		goto usage;

	if (opt_log_target) {
		if (!ni_log_destination(program_name, opt_log_target)) {
			fprintf(stderr, "Bad log destination \%s\"\n",
				opt_log_target);
			goto usage;
		}
	}
	else if (opt_systemd || getppid() == 1 || !opt_foreground) { /* syslog only */
		ni_log_destination(program_name, "syslog");
	}
	else { /* syslog + stderr */
		ni_log_destination(program_name, "syslog::perror");
	}

	babysit();
	return NI_LSB_RC_SUCCESS;
}

const char *
ni_nanny_statedir(void)
{
	unsigned int fsmode = ni_global.config->statedir.mode;
	static char path[PATH_MAX] = { '\0' };
	const char *nannydir = "nanny";

	if (ni_string_empty(path)) {
		snprintf(path, sizeof(path), "%s/%s", ni_config_statedir(), nannydir);
		if (ni_mkdir_maybe(path, fsmode) < 0)
			ni_fatal("Cannot create nanny state directory \"%s\": %m", path);
	}

	return path;
}

static ni_bool_t
ni_nanny_policy_load(ni_nanny_t *mgr)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	char nanny_dir[PATH_MAX] = { '\0' };

	ni_assert(mgr);
	ni_debug_application("Loading previously saved policies:");

	snprintf(nanny_dir, sizeof(nanny_dir), "%s", ni_nanny_statedir());
	if (ni_scandir(nanny_dir, "policy*.xml", &files) != 0) {
		unsigned int i;

		for (i = 0; i < files.count; ++i) {
			char path[PATH_MAX];
			xml_document_t *doc;

			snprintf(path, sizeof(path), "%s/%s", nanny_dir, files.data[i]);
			doc = xml_document_read(path);
			if (doc == NULL) {
				ni_error("Unable to read policy file %s: %m", path);
				continue;
			}

			if (!ni_nanny_create_policy(NULL, mgr, doc, TRUE)) {
				ni_error("Unable to create policy from file '%s'", path);
			}
			xml_document_free(doc);
		}
	}

	if (files.count)
		ni_nanny_recheck_policies(mgr, NULL);

	ni_string_array_destroy(&files);
	return TRUE;
}

/*
 * Implement service for configuring the system's network interfaces
 * based on events and user-supplied policies.
 */
static void
babysit(void)
{
	ni_nanny_t *mgr;

	mgr = ni_nanny_new();

	if (ni_init_ex("nanny", ni_nanny_config_callback, mgr) < 0)
		ni_fatal("error in configuration file");

	if (!opt_foreground) {
		ni_daemon_close_t close_flags = NI_DAEMON_CLOSE_STD;

		if (ni_string_startswith(opt_log_target, "stderr"))
			close_flags &= ~NI_DAEMON_CLOSE_ERR;

		if (ni_server_background(program_name, close_flags) < 0)
			ni_fatal("unable to background server");
	}

	ni_nanny_start(mgr);

	if (ni_config_use_nanny()) {
		ni_rfkill_open(handle_rfkill_event, mgr);
		ni_nanny_discover_state(mgr);
		ni_nanny_policy_load(mgr);
	}
	else
		ni_file_remove_recursively(ni_nanny_statedir());

#ifdef HAVE_SYSTEMD_SD_DAEMON_H
	if (opt_systemd) {
		sd_notify(0, "READY=1");
	}
#endif

	while (!ni_caught_terminal_signal()) {
		long timeout = NI_IFWORKER_INFINITE_TIMEOUT;

		if (ni_config_use_nanny()) {
			do {
				ni_fsm_do(mgr->fsm, &timeout);
#if 0
			} while (ni_nanny_recheck_do(mgr) || ni_nanny_down_do(mgr));
#else
			} while (ni_nanny_recheck_do(mgr));
#endif
		}

		if (ni_socket_wait(timeout) != 0)
			ni_fatal("ni_socket_wait failed");
	}

	exit(0);
}

/*
 * At startup, discover current configuration.
 * If we have any live leases, restart address configuration for them.
 * This allows a daemon restart without losing lease state.
 */
static void
ni_nanny_discover_state(ni_nanny_t *mgr)
{
	ni_fsm_t *fsm;
	unsigned int i;

	ni_assert(mgr && mgr->fsm);

	fsm = mgr->fsm;
	ni_fsm_refresh_state(fsm);

	/* Register devices that exist */
	for (i = 0; i < fsm->workers.count; ++i) {
		ni_ifworker_t *w = fsm->workers.data[i];

		if (ni_netdev_device_is_ready(w->device))
			ni_nanny_register_device(mgr, w);
	}
}

static void
handle_rfkill_event(ni_rfkill_type_t type, ni_bool_t blocked, void *user_data)
{
	ni_nanny_t *mgr = user_data;

	ni_debug_application("rfkill: %s devices %s", ni_rfkill_type_string(type),
			blocked? "blocked" : "enabled");

	ni_nanny_rfkill_event(mgr, type, blocked);
}

/*
 * Handle config file option in <nanny> element
 */
static ni_bool_t
ni_nanny_config_callback(void *appdata, const xml_node_t *node)
{
	ni_nanny_t *nanny = appdata;
	ni_nanny_devmatch_t **pos;
	xml_node_t *child;

	pos = &nanny->enable;
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "enable")) {
			ni_nanny_devmatch_t *match = NULL;
			const char *attrval;
			char classname[64];
			unsigned int type;

			if ((attrval = xml_node_get_attr(child, "link-layer")) != NULL) {
				snprintf(classname, sizeof(classname), "netif-%s", attrval);
				attrval = classname;
				type = NI_NANNY_DEVMATCH_CLASS;
			} else
			if ((attrval = xml_node_get_attr(child, "class")) != NULL) {
				type = NI_NANNY_DEVMATCH_CLASS;
			} else
			if ((attrval = xml_node_get_attr(child, "device")) != NULL) {
				type = NI_NANNY_DEVMATCH_DEVICE;
			} else {
				ni_warn("%s: cannot parse <enable> element",
						xml_node_location(child));
				goto skip_option;
			}

			match = xcalloc(1, sizeof(*match));
			match->type = type;
			ni_string_dup(&match->value, attrval);

			if ((attrval = xml_node_get_attr(child, "auto")) != NULL
			 && !strcasecmp(attrval, "true"))
				match->auto_enable = TRUE;

			ni_debug_nanny("enable type=%u, value=%s%s", match->type, match->value,
						match->auto_enable? ", auto" : "");

			*pos = match;
			pos = &match->next;
		}

skip_option: ;
	}

	return TRUE;
}
