/*
 * No REST for the wicked!
 *
 * This command line utility provides a daemon interface to the network
 * configuration/information facilities.
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
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/objectmodel.h>
#include <wicked/modem.h>

#define CONFIG_WICKED_STATE_PATH	CONFIG_WICKED_STATEDIR "/state.xml"

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_FOREGROUND,
	OPT_NOFORK,
	OPT_NORECOVER,
	OPT_NOMODEMMGR,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "foreground",		no_argument,		NULL,	OPT_FOREGROUND },
	{ "no-fork",		no_argument,		NULL,	OPT_NOFORK },
	{ "no-recovery",	no_argument,		NULL,	OPT_NORECOVER },
	{ "no-modem-manager",	no_argument,		NULL,	OPT_NOMODEMMGR },

	{ NULL }
};

static int		opt_foreground = 0;
static int		opt_nofork = 0;
static int		opt_recover_leases = 1;
static int		opt_no_modem_manager = 0;
static ni_dbus_server_t *wicked_dbus_server;
static ni_xs_scope_t *	wicked_dbus_xml_schema;
static int		wicked_term_sig = 0;

static void		wicked_interface_server(void);
static void		wicked_discover_state(void);
static void		wicked_recover_addrconf(const char *filename);
static void		wicked_interface_event(ni_netdev_t *, ni_event_t);
static void		wicked_other_event(ni_event_t);
static void		wicked_modem_event(ni_modem_t *, ni_event_t);
static void		wicked_catch_term_signal(int);

int
main(int argc, char **argv)
{
	const char *progname;
	int c;

	progname = ni_basename(argv[0]);

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"%s [options]\n"
				"This command understands the following options\n"
				"  --config filename\n"
				"        Read configuration file <filename> instead of system default.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n",
				progname
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

		case OPT_NOFORK:
			opt_nofork = 1;
			break;

		case OPT_NORECOVER:
			opt_recover_leases = 0;
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

	wicked_interface_server();
	return 0;
}

/*
 * Implement service for configuring the system's network interfaces
 */
void
wicked_interface_server(void)
{
	wicked_dbus_server = ni_objectmodel_create_service();
	if (!wicked_dbus_server)
		ni_fatal("Cannot create server, giving up.");

	if (!opt_no_modem_manager) {
		if (!ni_modem_manager_init(wicked_modem_event))
			ni_error("unable to initialize modem manager client");
	}

	wicked_dbus_xml_schema = ni_objectmodel_init(wicked_dbus_server);
	if (wicked_dbus_xml_schema == NULL)
		ni_fatal("Cannot initialize objectmodel, giving up.");

	/* open global RTNL socket to listen for kernel events */
	if (ni_server_listen_interface_events(wicked_interface_event) < 0)
		ni_fatal("unable to initialize netlink listener");

	/* Listen for other events, such as RESOLVER_UPDATED */
	ni_server_listen_other_events(wicked_other_event);

	if (!opt_foreground) {
		if (ni_server_background() < 0)
			ni_fatal("unable to background server");
		ni_log_destination_syslog("wickedd");
	}

	wicked_discover_state();

	if (opt_recover_leases)
		wicked_recover_addrconf(CONFIG_WICKED_STATE_PATH);

	signal(SIGTERM, wicked_catch_term_signal);
	signal(SIGINT, wicked_catch_term_signal);

	while (wicked_term_sig == 0) {
		long timeout;

		timeout = ni_timer_next_timeout();
		if (ni_socket_wait(timeout) < 0)
			ni_fatal("ni_socket_wait failed");
	}

	ni_debug_wicked("caught signal %u, exiting", wicked_term_sig);
	ni_objectmodel_save_state(CONFIG_WICKED_STATE_PATH);

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
wicked_discover_state(void)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;
	ni_modem_t *modem;

	nc = ni_global_state_handle(1);
	if (nc == NULL)
		ni_fatal("failed to discover interface state");

	if (wicked_dbus_server) {
		for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next)
			ni_objectmodel_register_netif(wicked_dbus_server, ifp, NULL);

		for (modem = ni_netconfig_modem_list(nc); modem; modem = modem->list.next)
			ni_objectmodel_register_modem(wicked_dbus_server, modem);
	}
}

/*
 * Recover lease information from the state.xml file.
 * Note that this does *not* restart address configuration protocols like DHCP automatically;
 * this needs to happen in the respective supplicants.
 */
void
wicked_recover_addrconf(const char *filename)
{
	const char *prefix_list[] = {
		NI_OBJECTMODEL_INTERFACE ".Addrconf",
		NULL
	};

	if (!ni_file_exists(filename)) {
		ni_debug_wicked("%s: %s does not exist, skip this", __func__, filename);
		return;
	}

	/* Recover the lease information of all interfaces. */
	if (!ni_objectmodel_recover_state(filename, prefix_list)) {
		ni_error("unable to recover address configuration state");
		return;
	}

	/* FIXME: update resolver etc. */
}

/*
 * Handle network layer events for interface server.
 * FIXME: There should be some locking here, which prevents us from
 * calling event handlers on an interface that the admin is currently
 * mucking with manually.
 */
void
wicked_interface_event(ni_netdev_t *dev, ni_event_t event)
{
	ni_uuid_t *event_uuid = NULL;

	if (wicked_dbus_server) {
		switch (event) {
		case NI_EVENT_DEVICE_CREATE:
			/* Create dbus object and emit event */
			ni_objectmodel_register_netif(wicked_dbus_server, dev, NULL);
			break;

		case NI_EVENT_DEVICE_DELETE:
			/* Delete dbus object and emit event */
			ni_objectmodel_unregister_netif(wicked_dbus_server, dev);
			break;

		case NI_EVENT_LINK_ASSOCIATED:
		case NI_EVENT_LINK_ASSOCIATION_LOST:
		case NI_EVENT_LINK_UP:
		case NI_EVENT_LINK_DOWN:
			if (!ni_uuid_is_null(&dev->link.event_uuid))
				event_uuid = &dev->link.event_uuid;
			/* fallthru */

		default:
			ni_objectmodel_netif_event(wicked_dbus_server, dev, event, event_uuid);
			break;
		}
	}
}

static void
wicked_other_event(ni_event_t event)
{
	ni_debug_events("%s(%s)", __func__, ni_event_type_to_name(event));
	if (wicked_dbus_server)
		ni_objectmodel_other_event(wicked_dbus_server, event, NULL);
}

/*
 * Modem event - device was plugged
 */
static void
wicked_modem_event(ni_modem_t *modem, ni_event_t event)
{
	ni_debug_events("%s(%s, %s)", __func__, ni_event_type_to_name(event), modem->real_path);
	if (wicked_dbus_server) {
		ni_uuid_t *event_uuid = NULL;

		switch (event) {
		case NI_EVENT_DEVICE_CREATE:
			/* Create dbus object and emit event */
			ni_objectmodel_register_modem(wicked_dbus_server, modem);
			break;

		case NI_EVENT_DEVICE_DELETE:
			/* Emit deletion event */
			if (!ni_uuid_is_null(&modem->event_uuid))
				event_uuid = &modem->event_uuid;
			ni_objectmodel_modem_event(wicked_dbus_server, modem, NI_EVENT_DEVICE_DOWN, event_uuid);

			/* Delete dbus object */
			ni_objectmodel_unregister_modem(wicked_dbus_server, modem);
			break;

		case NI_EVENT_LINK_ASSOCIATED:
		case NI_EVENT_LINK_ASSOCIATION_LOST:
		case NI_EVENT_LINK_UP:
		case NI_EVENT_LINK_DOWN:
			if (!ni_uuid_is_null(&modem->event_uuid))
				event_uuid = &modem->event_uuid;
			/* fallthru */

		default:
			ni_objectmodel_modem_event(wicked_dbus_server, modem, event, event_uuid);
			break;
		}
	}
}
