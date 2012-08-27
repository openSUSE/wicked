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
#include "manager.h"

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_FOREGROUND,
	OPT_NOMODEMMGR,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "foreground",		no_argument,		NULL,	OPT_FOREGROUND },
	{ "no-modem-manager",	no_argument,		NULL,	OPT_NOMODEMMGR },

	{ NULL }
};

static const char *	program_name;
static int		opt_foreground = 0;
static int		opt_no_modem_manager = 0;

static void		babysit(void);
static void		ni_nanny_discover_state(ni_nanny_t *);
static void		ni_nanny_netif_state_change_signal_receive(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
static void		ni_nanny_modem_state_change_signal_receive(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
//static void		handle_interface_event(ni_netdev_t *, ni_event_t);
//static void		handle_modem_event(ni_modem_t *, ni_event_t);
static void		handle_rfkill_event(ni_rfkill_type_t, ni_bool_t, void *user_data);

int
main(int argc, char **argv)
{
	int c;

	program_name = ni_basename(argv[0]);

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"%s [options]\n"
				"This command understands the following options\n"
				"  --config filename\n"
				"        Read configuration file <filename> instead of system default.\n"
				"  --foreground\n"
				"        Run as a foreground process, rather than as a daemon.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n",
				program_name
			       );
			return 1;

		case OPT_CONFIGFILE:
			ni_set_global_config_path(optarg);
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help(stdout);
				return 0;
			}
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				return 1;
			}
			break;

		case OPT_FOREGROUND:
			opt_foreground = 1;
			break;

		case OPT_NOMODEMMGR:
			opt_no_modem_manager = 1;
			break;
		}
	}

	if (ni_init() < 0)
		return 1;

	if (optind != argc)
		goto usage;

	babysit();
	return 0;
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

	if (!opt_foreground) {
		if (ni_server_background(program_name) < 0)
			ni_fatal("unable to background server");
		ni_log_destination_syslog(program_name);
	}

	ni_rfkill_open(handle_rfkill_event, mgr);

	ni_nanny_discover_state(mgr);

	while (!ni_caught_terminal_signal()) {
		long timeout;

		ni_nanny_recheck_do(mgr);
		ni_nanny_down_do(mgr);

		ni_fsm_do(mgr->fsm, &timeout);
		if (ni_socket_wait(timeout) < 0)
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

	if ((event = ni_objectmodel_signal_to_event(signal_name)) < 0) {
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
			mdev->user_controlled? ", user controlled" : "");

	switch (event) {
	case NI_EVENT_LINK_DOWN:
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
		if (mdev->selected_policy != NULL && mdev->user_controlled)
			ni_nanny_schedule_recheck(mgr, w);
		break;

	case NI_EVENT_LINK_ASSOCIATION_LOST:
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
		if (mdev->selected_policy != NULL && mdev->user_controlled)
			ni_nanny_schedule_recheck(mgr, w);
		break;

	case NI_EVENT_LINK_SCAN_UPDATED:
		if (mdev->user_controlled)
			ni_nanny_schedule_recheck(mgr, w);
		break;

	case NI_EVENT_LINK_UP:
		// Link detection - eg for ethernet
		if (mdev->user_controlled)
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

	if ((event = ni_objectmodel_signal_to_event(signal_name)) < 0) {
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
