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

static void		interface_manager(void);
static void		ni_manager_discover_state(ni_manager_t *);
static void		ni_manager_netif_state_change_signal_receive(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
static void		ni_manager_modem_state_change_signal_receive(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
//static void		handle_interface_event(ni_netdev_t *, ni_event_t);
//static void		handle_modem_event(ni_modem_t *, ni_event_t);

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

	interface_manager();
	return 0;
}

/*
 * Implement service for configuring the system's network interfaces
 */
void
interface_manager(void)
{
	ni_manager_t *mgr;

	mgr = ni_manager_new();

	if (!opt_foreground) {
		if (ni_server_background(program_name) < 0)
			ni_fatal("unable to background server");
		ni_log_destination_syslog(program_name);
	}

	ni_manager_discover_state(mgr);

	while (!ni_caught_terminal_signal()) {
		long timeout;

		ni_manager_recheck_do(mgr);
		ni_manager_down_do(mgr);

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
ni_manager_discover_state(ni_manager_t *mgr)
{
	ni_dbus_client_t *client;
	unsigned int i;

	if (!(client = ni_fsm_create_client(mgr->fsm)))
		ni_fatal("Unable to create FSM client");

	ni_dbus_client_add_signal_handler(client, NULL, NULL,
			NI_OBJECTMODEL_NETIF_INTERFACE,
			ni_manager_netif_state_change_signal_receive,
			mgr);
	ni_dbus_client_add_signal_handler(client, NULL, NULL,
			NI_OBJECTMODEL_MODEM_INTERFACE,
			ni_manager_modem_state_change_signal_receive,
			mgr);

	ni_fsm_refresh_state(mgr->fsm);

	for (i = 0; i < mgr->fsm->workers.count; ++i) {
		ni_ifworker_t *w = mgr->fsm->workers.data[i];

		ni_manager_register_device(mgr, w);
	}
}

/*
 * Wickedd is sending us a signal (such a linkUp/linkDown, or change in the set of
 * visible WLANs)
 */
void
ni_manager_netif_state_change_signal_receive(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_manager_t *mgr = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_managed_device_t *mdev;
	ni_ifworker_t *w;

	if ((w = ni_fsm_ifworker_by_object_path(mgr->fsm, object_path)) == NULL) {
		ni_warn("received signal \"%s\" from unknown object \"%s\"",
				signal_name, object_path);
		return;
	}

	ni_debug_nanny("%s: received signal %s from %s", w->name, signal_name, object_path);
	ni_assert(w->device);

	if (ni_string_eq(signal_name, "deviceDelete")) {
		// delete the worker and the managed netif
		ni_manager_unregister_device(mgr, w);
	} else
	if (ni_string_eq(signal_name, "linkDown")) {
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
		if ((mdev = ni_manager_get_device(mgr, w)) != NULL
		 && mdev->selected_policy != NULL
		 && mdev->user_controlled)
			ni_manager_schedule_recheck(mgr, w);
	} else
	if (ni_string_eq(signal_name, "linkAssociationLost")) {
		// If we have recorded a policy for this device, it means
		// we were the ones who took it up - so bring it down
		// again
		if ((mdev = ni_manager_get_device(mgr, w)) != NULL
		 && mdev->selected_policy != NULL
		 && mdev->user_controlled)
			ni_manager_schedule_down(mgr, w);
	} else
	if (ni_string_eq(signal_name, "deviceCreate")) {
		// A new device was added. Could be a virtual device like
		// a VLAN or vif, or a hotplug modem or NIC
		// Create a worker and a managed_netif for this device.
		ni_manager_register_device(mgr, w);
		ni_manager_schedule_recheck(mgr, w);
	} else
	if (ni_string_eq(signal_name, "linkUp")) {
		// Link detection - eg for ethernet
		if ((mdev = ni_manager_get_device(mgr, w)) != NULL
		 && mdev->selected_policy == NULL
		 && mdev->user_controlled)
			ni_manager_schedule_recheck(mgr, w);
	} else {
		// ignore
	}
}

/*
 * Wickedd is sending us a modem signal (usually discovery or removal of a modem)
 */
void
ni_manager_modem_state_change_signal_receive(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_manager_t *mgr = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	const char *object_path = dbus_message_get_path(msg);
	ni_ifworker_t *w;

	ni_debug_nanny("%s(%s, %s)", __func__, object_path, signal_name);

	// We receive a deviceCreate signal when a modem was plugged in
	if (ni_string_eq(signal_name, "deviceCreate")) {
		w = ni_fsm_recv_new_modem_path(mgr->fsm, object_path);
		ni_manager_register_device(mgr, w);
		ni_manager_schedule_recheck(mgr, w);
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

	if (ni_string_eq(signal_name, "deviceDelete")) {
		// delete the worker and the managed modem
		ni_manager_unregister_device(mgr, w);
	} else {
		// ignore
	}
}
