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
#include <signal.h>
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

static ni_fsm_t *	global_fsm;
static ni_dbus_server_t *global_dbus_server;
static int		wicked_term_sig = 0;

static void		interface_manager(void);
static void		discover_state(void);
static void		handle_interface_event(ni_netdev_t *, ni_event_t);
static void		handle_modem_event(ni_modem_t *, ni_event_t);
static void		wicked_catch_term_signal(int);

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
	global_dbus_server = ni_server_listen_dbus(NI_OBJECTMODEL_DBUS_BUS_NAME_MANAGER);
	if (!global_dbus_server)
		ni_fatal("Cannot create server, giving up.");

	if (!opt_no_modem_manager) {
		if (!ni_modem_manager_init(handle_modem_event))
			ni_error("unable to initialize modem manager client");
	}

	global_fsm = ni_fsm_new();
	ni_objectmodel_manager_init(global_dbus_server, global_fsm);

	/* open global RTNL socket to listen for kernel events */
	if (ni_server_listen_interface_events(handle_interface_event) < 0)
		ni_fatal("unable to initialize netlink listener");

	if (!opt_foreground) {
		if (ni_server_background(program_name) < 0)
			ni_fatal("unable to background server");
		ni_log_destination_syslog(program_name);
	}

	discover_state();

	signal(SIGTERM, wicked_catch_term_signal);
	signal(SIGINT, wicked_catch_term_signal);

	while (wicked_term_sig == 0) {
		long timeout;

		timeout = ni_timer_next_timeout();
		if (ni_socket_wait(timeout) < 0)
			ni_fatal("ni_socket_wait failed");
	}

	ni_debug_wicked("caught signal %u, exiting", wicked_term_sig);

	exit(0);
}

void
wicked_catch_term_signal(int sig)
{
	wicked_term_sig = sig;
}

/*
 * At startup, discover current configuration.
 * If we have any live leases, restart address configuration for them.
 * This allows a daemon restart without losing lease state.
 */
void
discover_state(void)
{
	ni_netconfig_t *nc;
	ni_netdev_t *dev;
	ni_modem_t *modem;

	nc = ni_global_state_handle(1);
	if (nc == NULL)
		ni_fatal("failed to discover interface state");

	if (global_dbus_server) {
		for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next)
			ni_objectmodel_register_managed_netdev(global_dbus_server, ni_managed_netdev_new(dev));

		for (modem = ni_netconfig_modem_list(nc); modem; modem = modem->list.next)
			ni_objectmodel_register_modem(global_dbus_server, modem);
	}
}

/*
 * Handle network layer events for interface server.
 * FIXME: There should be some locking here, which prevents us from
 * calling event handlers on an interface that the admin is currently
 * mucking with manually.
 */
void
handle_interface_event(ni_netdev_t *dev, ni_event_t event)
{
	ni_uuid_t *event_uuid = NULL;

	if (global_dbus_server) {
		switch (event) {
		case NI_EVENT_DEVICE_CREATE:
			/* Create dbus object */
			ni_objectmodel_register_netif(global_dbus_server, dev, NULL);
			break;

		case NI_EVENT_DEVICE_DELETE:
			/* FIXME: cancel pending FSM workers */
			/* Delete dbus object */
			ni_objectmodel_unregister_netif(global_dbus_server, dev);
			break;

		case NI_EVENT_LINK_ASSOCIATED:
		case NI_EVENT_LINK_ASSOCIATION_LOST:
		case NI_EVENT_LINK_UP:
		case NI_EVENT_LINK_DOWN:
			if (!ni_uuid_is_null(&dev->link.event_uuid))
				event_uuid = &dev->link.event_uuid;
			/* fallthru */

		default:
			break;
		}
	}
}

/*
 * Modem event - device was plugged
 */
static void
handle_modem_event(ni_modem_t *modem, ni_event_t event)
{
	ni_debug_events("%s(%s, %s)", __func__, ni_event_type_to_name(event), modem->real_path);
	if (global_dbus_server) {
		ni_uuid_t *event_uuid = NULL;

		switch (event) {
		case NI_EVENT_DEVICE_CREATE:
			/* Create dbus object and emit event */
			ni_objectmodel_register_modem(global_dbus_server, modem);
			break;

		case NI_EVENT_DEVICE_DELETE:
			/* Emit deletion event */
			if (!ni_uuid_is_null(&modem->event_uuid))
				event_uuid = &modem->event_uuid;
			ni_objectmodel_modem_event(global_dbus_server, modem, NI_EVENT_DEVICE_DOWN, event_uuid);

			/* Delete dbus object */
			ni_objectmodel_unregister_modem(global_dbus_server, modem);
			break;

		case NI_EVENT_LINK_ASSOCIATED:
		case NI_EVENT_LINK_ASSOCIATION_LOST:
		case NI_EVENT_LINK_UP:
		case NI_EVENT_LINK_DOWN:
			if (!ni_uuid_is_null(&modem->event_uuid))
				event_uuid = &modem->event_uuid;
			/* fallthru */

		default:
			break;
		}
	}
}
