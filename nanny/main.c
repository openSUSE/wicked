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

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/objectmodel.h>
#include <wicked/modem.h>
#include <wicked/wireless.h>
#include <wicked/fsm.h>
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
	OPT_NOMODEMMGR,
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

	/* specific */
	{ "no-modem-manager",	no_argument,		NULL,	OPT_NOMODEMMGR },

	{ NULL }
};

static const char *	program_name;
static const char *	opt_log_target;
static ni_bool_t	opt_foreground;
static ni_bool_t	opt_no_modem_manager;
static ni_bool_t	opt_systemd;

static void		babysit(void);
static void		ni_nanny_discover_state(ni_nanny_t *);
static void		ni_nanny_netif_state_change_signal_receive(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
static void		ni_nanny_modem_state_change_signal_receive(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
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

		case OPT_NOMODEMMGR:
			opt_no_modem_manager = TRUE;
			break;

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

/*
 * Implement service for configuring the system's network interfaces
 * based on events and user-supplied policies.
 */
void
babysit(void)
{
	ni_nanny_t *mgr;

	mgr = ni_nanny_new();

	if (ni_init_ex("nanny", ni_nanny_config_callback, mgr) < 0)
		ni_fatal("error in configuration file");

	ni_nanny_start(mgr);

	if (!opt_foreground) {
		if (ni_server_background(program_name) < 0)
			ni_fatal("unable to background server");
	}

	ni_rfkill_open(handle_rfkill_event, mgr);

	ni_nanny_discover_state(mgr);

	while (!ni_caught_terminal_signal()) {
		long timeout;

		ni_nanny_recheck_do(mgr);
		ni_nanny_down_do(mgr);

		ni_fsm_do(mgr->fsm, &timeout);
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
void
ni_nanny_discover_state(ni_nanny_t *mgr)
{
	ni_dbus_client_t *client;
	unsigned int i;

	if (!(client = ni_fsm_create_client(mgr->fsm)))
		ni_fatal("Unable to create FSM client");

	ni_dbus_client_add_signal_handler(client, NULL, NULL,
			NI_OBJECTMODEL_NETIF_INTERFACE,
			ni_nanny_netif_state_change_signal_receive,
			mgr);
	ni_dbus_client_add_signal_handler(client, NULL, NULL,
			NI_OBJECTMODEL_MODEM_INTERFACE,
			ni_nanny_modem_state_change_signal_receive,
			mgr);

	ni_fsm_refresh_state(mgr->fsm);

	for (i = 0; i < mgr->fsm->workers.count; ++i) {
		ni_ifworker_t *w = mgr->fsm->workers.data[i];

		ni_nanny_register_device(mgr, w);
	}
}

/*
 * Wickedd is sending us a signal (such a linkUp/linkDown, or change in the set of
 * visible WLANs)
 */
void
ni_nanny_netif_state_change_signal_receive(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_nanny_t *mgr = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_event_t event;
	ni_managed_device_t *mdev;
	ni_ifworker_t *w;

	if (ni_objectmodel_signal_to_event(signal_name, &event) < 0) {
		ni_debug_nanny("received unknown signal \"%s\" from object \"%s\"",
				signal_name, object_path);
		return;
	}

	if (event == NI_EVENT_DEVICE_CREATE) {
		// A new device was added. Could be a virtual device like
		// a VLAN or vif, or a hotplug device
		// Create a worker and a managed_netif for this device.
		w = ni_fsm_recv_new_netif_path(mgr->fsm, object_path);
		ni_nanny_register_device(mgr, w);
		ni_nanny_schedule_recheck(mgr, w);
		return;
	}

	if ((w = ni_fsm_ifworker_by_object_path(mgr->fsm, object_path)) == NULL) {
		ni_warn("received signal \"%s\" from unknown object \"%s\"",
				signal_name, object_path);
		return;
	}

	ni_assert(w->type == NI_IFWORKER_TYPE_NETDEV);
	ni_assert(w->device);

	if (event == NI_EVENT_DEVICE_DELETE) {
		ni_debug_nanny("%s: received signal %s from %s", w->name, signal_name, object_path);
		// delete the worker and the managed netif
		ni_nanny_unregister_device(mgr, w);
		return;
	}

	if ((mdev = ni_nanny_get_device(mgr, w)) == NULL) {
		ni_debug_nanny("%s: received signal %s from %s (not a managed device)",
				w->name, signal_name, object_path);
		return;
	}

	ni_debug_nanny("%s: received signal %s; state=%s, policy=%s%s",
			w->name, signal_name,
			ni_managed_state_to_string(mdev->state),
			mdev->selected_policy? ni_fsm_policy_name(mdev->selected_policy->fsm_policy): "<none>",
			mdev->monitor? ", user controlled" : "");

	switch (event) {
	case NI_EVENT_LINK_DOWN:
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
		if (mdev->selected_policy != NULL && mdev->monitor)
			ni_nanny_schedule_down(mgr, w);
		break;

	case NI_EVENT_LINK_ASSOCIATION_LOST:
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
		if (mdev->selected_policy != NULL && mdev->monitor)
			ni_nanny_schedule_recheck(mgr, w);
		break;

	case NI_EVENT_LINK_SCAN_UPDATED:
		if (mdev->monitor)
			ni_nanny_schedule_recheck(mgr, w);
		break;

	case NI_EVENT_LINK_UP:
		// Link detection - eg for ethernet
		if (mdev->monitor)
			ni_nanny_schedule_recheck(mgr, w);
		break;

	default: ;
	}
}

/*
 * Wickedd is sending us a modem signal (usually discovery or removal of a modem)
 */
void
ni_nanny_modem_state_change_signal_receive(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_nanny_t *mgr = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_event_t event;
	ni_ifworker_t *w;

	if (ni_objectmodel_signal_to_event(signal_name, &event) < 0) {
		ni_debug_nanny("received unknown signal \"%s\" from object \"%s\"",
				signal_name, object_path);
		return;
	}

	// We receive a deviceCreate signal when a modem was plugged in
	if (event == NI_EVENT_DEVICE_CREATE) {
		w = ni_fsm_recv_new_modem_path(mgr->fsm, object_path);
		ni_nanny_register_device(mgr, w);
		ni_nanny_schedule_recheck(mgr, w);
		return;
	}

	if ((w = ni_fsm_ifworker_by_object_path(mgr->fsm, object_path)) == NULL) {
		ni_warn("received signal \"%s\" from unknown object \"%s\"",
				signal_name, object_path);
		return;
	}

	ni_debug_nanny("%s: received signal %s from %s", w->name, signal_name, object_path);
	ni_assert(w->type == NI_IFWORKER_TYPE_MODEM);
	ni_assert(w->modem);

	if (event == NI_EVENT_DEVICE_DELETE) {
		// delete the worker and the managed modem
		ni_nanny_unregister_device(mgr, w);
	} else {
		// ignore
	}
}

void
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
ni_bool_t
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
