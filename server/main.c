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
#include <wicked/wireless.h>
#include <wicked/modem.h>
#include "netinfo_priv.h"
#include "udev-utils.h"
#include "auto6.h"

enum {
	OPT_HELP,
	OPT_VERSION,
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_LOG_LEVEL,
	OPT_LOG_TARGET,
	OPT_SYSTEMD,

	OPT_FOREGROUND,
	OPT_RECOVER,
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

	/* specific */
	{ "recover",		no_argument,		NULL,	OPT_RECOVER },
#ifdef MODEM
	{ "no-modem-manager",	no_argument,		NULL,	OPT_NOMODEMMGR },
#endif


	{ NULL }
};

static const char *	program_name;
static const char *	opt_log_target;
static ni_bool_t	opt_foreground;
static ni_bool_t	opt_recover_state;
/* FIXME: ModemManager changed to ModemManager1 - new API -> disabled */
#ifdef MODEM
static ni_bool_t	opt_no_modem_manager = TRUE;
#endif
static ni_bool_t	opt_systemd;
static char *		opt_state_file;
static ni_dbus_server_t *dbus_server;

static void		run_interface_server(void);
static void		discover_state(ni_dbus_server_t *);
static void		recover_state(const char *filename);
static void		handle_interface_event(ni_netdev_t *, ni_event_t);
static void		handle_interface_addr_events(ni_netdev_t *, ni_event_t, const ni_address_t *);
static void		handle_interface_prefix_events(ni_netdev_t *, ni_event_t, const ni_ipv6_ra_pinfo_t *);
static void		handle_interface_nduseropt_events(ni_netdev_t *, ni_event_t);
static void		handle_rfkill_event(ni_rfkill_type_t, ni_bool_t, void *);
static void		handle_other_event(ni_event_t);
#ifdef MODEM
static void		handle_modem_event(ni_modem_t *, ni_event_t);
#endif

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
				"  --log-level level\n"
				"        Set log level to <error|warning|notice|info|debug>.\n"
				"  --log-target target\n"
				"        Set log destination to <stderr|syslog>.\n"
				"  --foreground\n"
				"        Tell the daemon to not background itself at startup.\n"
				"  --recover\n"
				"        Restart of address configuration daemons and keep state information.\n"
#ifdef MODEM
				"  --no-modem-manager\n"
				"        Skip start of modem-manager.\n"
#endif
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

		case OPT_RECOVER:
			opt_recover_state = TRUE;
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

	if (ni_init("server") < 0)
		return NI_LSB_RC_ERROR;

	if (opt_recover_state && ni_string_empty(opt_state_file)) {
		static char dirname[PATH_MAX];

		snprintf(dirname, sizeof(dirname), "%s/state.xml", ni_config_statedir());
		opt_state_file = dirname;
	}

	run_interface_server();
	return NI_LSB_RC_SUCCESS;
}

/*
 * Implement service for configuring the system's network interfaces
 */
void
run_interface_server(void)
{
	ni_xs_scope_t *	schema;

	dbus_server = ni_objectmodel_create_service();
	if (!dbus_server)
		ni_fatal("Cannot create server, giving up.");
#ifdef MODEM
	if (!opt_no_modem_manager) {
		if (!ni_modem_manager_init(handle_modem_event))
			ni_error("unable to initialize modem manager client");
	}
#endif

	schema = ni_objectmodel_init(dbus_server);
	if (schema == NULL)
		ni_fatal("Cannot initialize objectmodel, giving up.");

	/* open global RTNL socket to listen for kernel events */
	if (ni_server_listen_interface_events(handle_interface_event) < 0)
		ni_fatal("unable to initialize netlink listener");
	if (ni_server_enable_interface_addr_events(handle_interface_addr_events) < 0)
		ni_fatal("unable to initialize netlink address listener");
	if (ni_server_enable_interface_prefix_events(handle_interface_prefix_events) < 0)
		ni_fatal("unable to initialize netlink prefix listener");
	if (ni_server_enable_interface_nduseropt_events(handle_interface_nduseropt_events) < 0)
		ni_fatal("unable to initialize netlink nduseropt listener");

	if (ni_udev_is_active() && ni_udev_net_subsystem_available()) {
		if (ni_server_enable_interface_uevents() < 0)
			ni_fatal("unable to initialize udev event listener");
	} else {
		ni_server_disable_interface_uevents();
	}

	ni_rfkill_open(handle_rfkill_event, NULL);

	/* Listen for other events, such as RESOLVER_UPDATED */
	ni_server_listen_other_events(handle_other_event);

	if (!opt_foreground) {
		ni_daemon_close_t close_flags = NI_DAEMON_CLOSE_STD;

		if (ni_string_startswith(opt_log_target, "stderr"))
			close_flags &= ~NI_DAEMON_CLOSE_ERR;

		if (ni_server_background(program_name, close_flags) < 0)
			ni_fatal("unable to background server");
	}

	discover_state(dbus_server);

	if (opt_recover_state)
		recover_state(opt_state_file);

#ifdef HAVE_SYSTEMD_SD_DAEMON_H
	if (opt_systemd) {
		sd_notify(0, "READY=1");
	}
#endif

	while (!ni_caught_terminal_signal()) {
		long timeout;

		do {
			timeout = ni_timer_next_timeout();
		} while (ni_dbus_objects_garbage_collect());

		if (ni_socket_wait(timeout) != 0)
			ni_fatal("ni_socket_wait failed");
	}

	if (opt_recover_state)
		ni_objectmodel_save_state(opt_state_file);

	exit(0);
}

/*
 * At startup, discover current configuration.
 * If we have any live leases, restart address configuration for them.
 * This allows a daemon restart without losing lease state.
 */
void
discover_udev_netdev_state(ni_netdev_t *dev)
{
	if (!dev)
		return;

	if (!ni_netdev_device_is_ready(dev)) {
		if (ni_netdev_device_always_ready(dev))
			dev->link.ifflags |= NI_IFF_DEVICE_READY;
		else
		if (ni_udev_netdev_is_ready(dev))
			dev->link.ifflags |= NI_IFF_DEVICE_READY;
	}

	/* query ethtool settings which are guarded by ready
	 * flag (rules processed / already renamed by udev)
	 * as ethtool is a query by ifname...
	 */
	ni_system_ethtool_refresh(dev);
}

void
discover_state(ni_dbus_server_t *server)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;
#ifdef MODEM
	ni_modem_t *modem;
#endif

	nc = ni_global_state_handle(1);
	if (nc == NULL)
		ni_fatal("failed to discover interface state");

	if (server) {
		for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {
			discover_udev_netdev_state(ifp);
			ni_objectmodel_register_netif(server, ifp, NULL);
			if (!ni_client_state_is_valid(ifp->client_state)) {
				if (!ni_netdev_load_client_state(ifp))
					ni_netdev_discover_client_state(ifp);
			}
		}
#ifdef MODEM
		for (modem = ni_netconfig_modem_list(nc); modem; modem = modem->list.next)
			ni_objectmodel_register_modem(server, modem);
#endif
	}
}

/*
 * Recover lease information from the state.xml file.
 * Note that this does *not* restart address configuration protocols like DHCP automatically;
 * this needs to happen in the respective supplicants.
 */
void
recover_state(const char *filename)
{
	const char *prefix_list[] = {
		NI_OBJECTMODEL_ADDRCONF_INTERFACE,
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
handle_interface_event(ni_netdev_t *dev, ni_event_t event)
{
	const ni_uuid_t *event_uuid = NULL;

	if (dbus_server) {
		ni_dbus_object_t *object;

		ni_auto6_on_netdev_event(dev, event);

		object = ni_objectmodel_get_netif_object(dbus_server, dev);
		if (!object && event == NI_EVENT_DEVICE_CREATE) {
			/* A new netif was discovered or we've created one;
			 * create a dbus server object enacpsulating it.
			 *
			 * When a factory creates a virtual device, it also
			 * creates the dbus object and while the netlink
			 * event about it device arrived, we already have it.
			 *
			 * When the system discovered new device, we'll get
			 * a netlink event and create the dbus object here.
			 */
			object = ni_objectmodel_register_netif(dbus_server, dev, NULL);
		}
		if (!object) {
			/* usually a "bad event", e.g. when the underlying netdev
			 * does not exists any more, but events still arrive ... */
			ni_error("cannot handle %s event for model \"%s\" - no dbus object",
					ni_event_type_to_name(event), dev->name);
			return;
		}

		switch (event) {
		case NI_EVENT_DEVICE_CREATE:
			/* Create dbus object and emit event */
			ni_objectmodel_send_netif_event(dbus_server, object, event, NULL);
			break;

		case NI_EVENT_DEVICE_DELETE:
			/* Delete dbus object first, so that GetManagedObjects doesn't
			 * return it any longer.
			 * Note; deletion of the object will be deferred until we return
			 * to the main loop.
			 */
			ni_objectmodel_unregister_netif(dbus_server, dev);
			ni_objectmodel_send_netif_event(dbus_server, object, event, NULL);
			break;

		default:
			/* commit backgrounded action results first -- if any */
			while ((event_uuid = ni_netdev_get_event_uuid(dev, event)) != NULL)
				ni_objectmodel_send_netif_event(dbus_server, object, event, event_uuid);

			/* send unrequested events                            */
			ni_objectmodel_send_netif_event(dbus_server, object, event, NULL);
			break;
		}
	}
}

static void
handle_interface_addr_events(ni_netdev_t *dev, ni_event_t event, const ni_address_t *ap)
{
	ni_addrconf_lease_t *lease, *next;

	ni_server_trace_interface_addr_events(dev, event, ap);

	if (ap->family != AF_INET6)
		return;

	/* call ipv6 address verify which may wait for */
	for (lease = dev->leases; lease; lease = next) {
		next = lease->next;

		if (lease->family != AF_INET6)
			continue;

		if (lease->type == NI_ADDRCONF_AUTOCONF)
			continue; /* separately, bellow */

		if (lease->state != NI_ADDRCONF_STATE_APPLYING)
			continue;

		if ((event == NI_EVENT_ADDRESS_UPDATE && ni_address_is_duplicate(ap)) ||
		    (event == NI_EVENT_ADDRESS_DELETE && ni_address_is_tentative(ap))) {
			ni_address_t *la;

			/* mark addresses detected as duplicate in the lease
			 * for further handing in the lease apply procedure. */
			if ((la = ni_address_list_find(lease->addrs, &ap->local_addr)))
				ni_address_set_duplicate(la, TRUE);
		}
		ni_addrconf_updater_execute(dev, lease);
	}

	ni_auto6_on_address_event(dev, event, ap);
}

static void
handle_interface_prefix_events(ni_netdev_t *dev, ni_event_t event, const ni_ipv6_ra_pinfo_t *pi)
{
	ni_server_trace_interface_prefix_events(dev, event, pi);
	ni_auto6_on_prefix_event(dev, event, pi);
}

static void
handle_interface_nduseropt_events(ni_netdev_t *dev, ni_event_t event)
{
	ni_server_trace_interface_nduseropt_events(dev, event);
	ni_auto6_on_nduseropt_events(dev, event);
}

static void
handle_other_event(ni_event_t event)
{
	ni_debug_events("%s(%s)", __func__, ni_event_type_to_name(event));
	if (dbus_server)
		ni_objectmodel_other_event(dbus_server, event, NULL);
}

/*
 * Modem event - device was plugged
 */
#ifdef MODEM
static void
handle_modem_event(ni_modem_t *modem, ni_event_t event)
{
	ni_debug_events("%s(%s, %s)", __func__, ni_event_type_to_name(event), modem->real_path);
	if (dbus_server) {
		ni_dbus_object_t *object;
		ni_uuid_t *event_uuid = NULL;

		if (event == NI_EVENT_DEVICE_CREATE) {
			/* A new modem was discovered; create a dbus server object
			 * enacpsulating it. */
			object = ni_objectmodel_register_modem(dbus_server, modem);
		} else
		if (!(object = ni_objectmodel_get_modem_object(dbus_server, modem))) {
			ni_error("cannot send %s event for model \"%s\" - no dbus device",
				ni_event_type_to_name(event), modem->real_path);
			return;
		}

		switch (event) {
		case NI_EVENT_DEVICE_CREATE:
			/* Create dbus object and emit event */
			ni_objectmodel_send_modem_event(dbus_server, object, event, event_uuid);
			break;

		case NI_EVENT_DEVICE_DELETE:
			/* Delete dbus object first, so that GetManagedObjects doesn't
			 * return it any longer.
			 * Note; deletion of the object will be deferred until we return to
			 * the main loop.
			 */
			ni_objectmodel_unregister_modem(dbus_server, modem);

			/* Emit deletion event */
			if (!ni_uuid_is_null(&modem->event_uuid))
				event_uuid = &modem->event_uuid;
			ni_objectmodel_send_modem_event(dbus_server, object, NI_EVENT_DEVICE_DOWN, event_uuid);
			ni_objectmodel_send_modem_event(dbus_server, object, NI_EVENT_DEVICE_DELETE, NULL);
			break;

		case NI_EVENT_DEVICE_READY:
		case NI_EVENT_LINK_ASSOCIATED:
		case NI_EVENT_LINK_ASSOCIATION_LOST:
		case NI_EVENT_LINK_UP:
		case NI_EVENT_LINK_DOWN:
			if (!ni_uuid_is_null(&modem->event_uuid))
				event_uuid = &modem->event_uuid;
			/* fallthru */

		default:
			ni_objectmodel_send_modem_event(dbus_server, object, event, event_uuid);
			break;
		}
	}
}
#endif

void
handle_rfkill_event(ni_rfkill_type_t type, ni_bool_t blocked, void *user_data)
{
	ni_debug_application("rfkill: %s devices %s", ni_rfkill_type_string(type),
			blocked? "blocked" : "enabled");
}
