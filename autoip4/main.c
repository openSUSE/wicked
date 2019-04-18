/*
 * IPv4ll supplicant
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
#include <net/if_arp.h>
#ifdef HAVE_SYSTEMD_SD_DAEMON_H
#include <systemd/sd-daemon.h>
#endif

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/wireless.h>
#include <wicked/objectmodel.h>
#include "autoip4/autoip.h"

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

	{ NULL }
};

static const char *	program_name;
static const char *	opt_log_target;
static ni_bool_t	opt_systemd;
static ni_bool_t	opt_foreground;
static ni_bool_t	opt_recover_state;
static ni_dbus_server_t *autoip4_dbus_server;

static void		autoip4_supplicant(void);
static void		autoip4_discover_devices(ni_dbus_server_t *);
static void		autoip4_recover_state(ni_netdev_t *);
static void		autoip4_interface_event(ni_netdev_t *, ni_event_t);
static void		autoip4_protocol_event(enum ni_lease_event, const ni_autoip_device_t *, ni_addrconf_lease_t *);

// Hack
extern ni_dbus_object_t *ni_objectmodel_register_autoip4_device(ni_dbus_server_t *, ni_autoip_device_t *);

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
				"        Use '--debug help' for a list of facilities.\n"
				"  --log-level level\n"
				"        Set log level to <error|warning|notice|info|debug>.\n"
				"  --log-target target\n"
				"        Set log destination to <stderr|syslog>.\n"
				"  --foreground\n"
				"        Do not background the service.\n"
				"  --recover\n"
				"        Enable automatic recovery of daemon's state.\n"
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

	if (ni_init("auto4") < 0)
		return NI_LSB_RC_ERROR;

	autoip4_supplicant();
	return NI_LSB_RC_SUCCESS;
}

/*
 * At startup, discover current configuration.
 * If we have any live leases, restart address configuration for them.
 * This allows a daemon restart without losing lease state.
 */
void
autoip4_recover_state(ni_netdev_t *ifp)
{
#if 0
	ni_afinfo_t *afi = &ifp->ipv4;
	ni_addrconf_lease_t *lease;

	if (!ni_afinfo_addrconf_test(afi, NI_ADDRCONF_AUTOCONF))
		return;

	/* Don't do anything if we already have a lease for this. */
	if (afi->lease[NI_ADDRCONF_AUTOCONF] != NULL)
		return;

	lease = ni_addrconf_lease_file_read(ifp->name, NI_ADDRCONF_AUTOCONF, afi->family);
	if (lease == NULL)
		return;

	/* if lease expired, return and remove stale lease file */
	if (!ni_addrconf_lease_is_valid(lease)) {
		ni_debug_wicked("%s: removing stale %s/%s lease file", ifp->name,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
		ni_addrconf_lease_file_remove(ifp->name, NI_ADDRCONF_AUTOCONF, afi->family);
		ni_addrconf_lease_free(lease);
		return;
	}

	/* Do not install the lease; let the addrconf mechanism fill in all
	 * the details. */
	ni_addrconf_lease_free(lease);

	/* Recover the original addrconf request data here */
	afi->request[NI_ADDRCONF_AUTOCONF] = ni_addrconf_request_file_read(ifp->name, NI_ADDRCONF_AUTOCONF, afi->family);
	if (afi->request[NI_ADDRCONF_AUTOCONF] == NULL) {
		ni_error("%s: seem to have valid lease, but lost original request", ifp->name);
		return;
	}
	afi->request[NI_ADDRCONF_AUTOCONF]->reuse_unexpired = 1;

	if (1) {
		ni_error("%s: unable to reacquire lease %s/%s", ifp->name,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
		return;
	}

	ni_debug_wicked("%s: initiated recovery of %s/%s lease", ifp->name,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
#endif
}

/*
 * Functions to support the AUTO4 DBus binding
 */
static ni_dbus_service_t	__wicked_dbus_autoip4_interface = {
	.name		= NI_OBJECTMODEL_AUTO4_INTERFACE,
};


void
autoip4_register_services(ni_dbus_server_t *server)
{
	ni_dbus_object_t *root_object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_t *object;

	/* Register the root object /org/opensuse/Network/AUTO4 */
	ni_dbus_object_register_service(root_object, &__wicked_dbus_autoip4_interface);

	/* Register /org/opensuse/Network/AUTO4/Interface */
	object = ni_dbus_server_register_object(server, "Interface", &ni_dbus_anonymous_class, NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	autoip4_discover_devices(server);

	ni_autoip_set_event_handler(autoip4_protocol_event);
}

ni_bool_t
ni_autoip4_supported(const ni_netdev_t *ifp)
{
	/*
	 * currently broadcast and arp capable ether type only,
	 * we've simply did not tested it on other links ...
	 */
	switch (ifp->link.hwaddr.type) {
	case ARPHRD_ETHER:
		if (ifp->link.masterdev.index) {
			ni_debug_autoip("%s: DHCPv4 not supported on slaves",
					ifp->name);
			return FALSE;
		}

		if (!(ifp->link.ifflags & NI_IFF_ARP_ENABLED)) {
			ni_debug_autoip("%s: AutoIP not supported without "
					"ARP support", ifp->name);
			return FALSE;
		}
		/* Hmm... can this happen? */
		if (!(ifp->link.ifflags & NI_IFF_BROADCAST_ENABLED)) {
			ni_debug_autoip("%s: AutoIP not supported without "
					" broadcast support", ifp->name);
			return FALSE;
		}
		if ((ifp->link.ifflags & NI_IFF_POINT_TO_POINT)) {
			ni_debug_autoip("%s: AutoIP not supported on point-"
					"to-point interfaces", ifp->name);
			return FALSE;
		}
		break;
	default:
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_AUTOIP,
				"%s: AutoIP not supported on %s interfaces",
				ifp->name,
				ni_linktype_type_to_name(ifp->link.type));
		return FALSE;
	}
	return TRUE;
}

/*
 * Add a newly discovered device
 */
static ni_bool_t
autoip4_device_create(ni_dbus_server_t *server, const ni_netdev_t *ifp)
{
	ni_autoip_device_t *dev;
	ni_bool_t rv = FALSE;

	if ((dev = ni_autoip_device_by_index(ifp->link.ifindex)) != NULL)
		return TRUE;

	dev = ni_autoip_device_new(ifp->name, &ifp->link);
	if (!dev) {
		ni_error("Cannot allocate autoip4 device for '%s' and index %u",
			ifp->name, ifp->link.ifindex);
		return rv;
	}

	if (ni_objectmodel_register_autoip4_device(server, dev) != NULL) {
		ni_debug_autoip("Created autoip4 device for '%s' and index %u",
				ifp->name, ifp->link.ifindex);
		rv = TRUE;
	}

	/* either register autoip4 device was successful and obtained
	 * an own reference or we can drop ours here anyway ... */
	ni_autoip_device_put(dev);

	return rv;
}

/*
 * Remove a device that has disappeared
 */
static void
autoip4_device_destroy(ni_dbus_server_t *server, const ni_netdev_t *ifp)
{
	ni_autoip_device_t *dev;

	if ((dev = ni_autoip_device_by_index(ifp->link.ifindex)) != NULL) {
		ni_debug_autoip("%s: Destroying autoip4 device with index %u",
				ifp->name, ifp->link.ifindex);
		ni_autoip_device_stop(dev);
		ni_autoip_device_set_request(dev, NULL);
		ni_dbus_server_unregister_object(server, dev);
	}
}

static void
autoip4_device_destroy_all(ni_dbus_server_t *server)
{
	ni_netconfig_t *nc;
	ni_netdev_t *   ifp;

	if (!(nc = ni_global_state_handle(0)))
		return;

	for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {
		autoip4_device_destroy(server, ifp);
	}
}

void
autoip4_discover_devices(ni_dbus_server_t *server)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;

	/* Disable wireless AP scanning */
	ni_wireless_set_scanning(FALSE);

	if (!(nc = ni_global_state_handle(1)))
		ni_fatal("cannot refresh interface list!");

	for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {
		if(!ni_autoip4_supported(ifp))
			continue;

		autoip4_device_create(server, ifp);

		if (opt_recover_state)
			autoip4_recover_state(ifp);
	}
}

/*
 * Implement AUTO4 supplicant dbus service
 */
void
autoip4_supplicant(void)
{
	autoip4_dbus_server = ni_server_listen_dbus(NI_OBJECTMODEL_DBUS_BUS_NAME_AUTO4);
	if (autoip4_dbus_server == NULL)
		ni_fatal("unable to initialize dbus service");

	ni_netconfig_set_family_filter(ni_global_state_handle(0), AF_INET);
	ni_netconfig_set_discover_filter(ni_global_state_handle(0),
					NI_NETCONFIG_DISCOVER_LINK_EXTERN|
					NI_NETCONFIG_DISCOVER_ROUTE_RULES);

	ni_objectmodel_autoip4_init();

	autoip4_register_services(autoip4_dbus_server);

	/* open global RTNL socket to listen for kernel events */
	if (ni_server_listen_interface_events(autoip4_interface_event) < 0)
		ni_fatal("unable to initialize netlink listener");

	if (!opt_foreground) {
		ni_daemon_close_t close_flags = NI_DAEMON_CLOSE_STD;

		if (ni_string_startswith(opt_log_target, "stderr"))
			close_flags &= ~NI_DAEMON_CLOSE_ERR;

		if (ni_server_background(program_name, close_flags) < 0)
			ni_fatal("unable to background server");
	}

#ifdef HAVE_SYSTEMD_SD_DAEMON_H
	if (opt_systemd) {
		sd_notify(0, "READY=1");
	}
#endif

	while (!ni_caught_terminal_signal()) {
		long timeout;

		do {
			timeout = ni_timer_next_timeout();
		} while(ni_dbus_objects_garbage_collect());

		if (ni_socket_wait(timeout) != 0)
			ni_fatal("ni_socket_wait failed");
	}

	ni_server_deactivate_interface_events();

	autoip4_device_destroy_all(autoip4_dbus_server);
	ni_dbus_objects_garbage_collect();

	ni_socket_deactivate_all();
}

/*
 * Handle network layer events.
 * FIXME: There should be some locking here, which prevents us from
 * calling event handlers on an interface that the admin is currently
 * mucking with manually.
 */
void
autoip4_interface_event(ni_netdev_t *ifp, ni_event_t event)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *ofp;

	switch (event) {
	case NI_EVENT_DEVICE_CREATE:
		/* check for duplicate ifindex */
		ofp = ni_netdev_by_index(nc, ifp->link.ifindex);
		if (ofp && ofp != ifp) {
			ni_warn("duplicate ifindex in device-create event");
			return;
		}

		/* Create dbus object */
		if(ni_autoip4_supported(ifp))
			autoip4_device_create(autoip4_dbus_server, ifp);
		break;

	case NI_EVENT_DEVICE_DELETE:
		/* Delete dbus object */
		autoip4_device_destroy(autoip4_dbus_server, ifp);
		break;

#if 0
	case NI_EVENT_LINK_DOWN:
	case NI_EVENT_LINK_UP:
		ni_autoip_device_t *dev;
		dev = ni_autoip_device_by_index(ifp->link.ifindex);
		if (dev != NULL)
			;
#ifdef notyet
			/* FIXME: */
			ni_autoip_device_event(dev, event);
#endif
#endif
		break;

	default: ;
	}
}

void
autoip4_protocol_event(enum ni_lease_event ev, const ni_autoip_device_t *dev,
				ni_addrconf_lease_t *lease)
{
	ni_dbus_variant_t argv[2];
	ni_dbus_object_t *dev_object;
	ni_dbus_variant_t *var;
	int argc = 0;

	ni_debug_autoip("%s(ev=%u, dev=%d)", __func__, ev, dev->link.ifindex);

	dev_object = ni_dbus_server_find_object_by_handle(autoip4_dbus_server, dev);
	if (dev_object == NULL) {
		ni_warn("%s: no dbus object for device %s!", __func__, dev->ifname);
		return;
	}

	memset(argv, 0, sizeof(argv));
	var = &argv[argc++];
	ni_dbus_variant_set_uuid(var, &dev->request.uuid);

	if (lease) {
		var = &argv[argc++];
		ni_dbus_variant_init_dict(var);
		if (!ni_objectmodel_get_addrconf_lease(lease, var)) {
			ni_warn("%s: could not extract lease data", __func__);
			goto done;
		}
	}

	switch (ev) {
	case NI_EVENT_LEASE_ACQUIRED:
		if (lease == NULL) {
			ni_error("BUG: cannot send %s event without a lease handle",
					NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL);
			goto done;
		}
		ni_dbus_server_send_signal(autoip4_dbus_server, dev_object,
				NI_OBJECTMODEL_ADDRCONF_INTERFACE, NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL,
				argc, argv);
		break;

	case NI_EVENT_LEASE_RELEASED:
		ni_dbus_server_send_signal(autoip4_dbus_server, dev_object,
				NI_OBJECTMODEL_ADDRCONF_INTERFACE, NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL,
				argc, argv);
		break;

	case NI_EVENT_LEASE_LOST:
		ni_dbus_server_send_signal(autoip4_dbus_server, dev_object,
				NI_OBJECTMODEL_ADDRCONF_INTERFACE, NI_OBJECTMODEL_LEASE_LOST_SIGNAL,
				argc, argv);
		break;

	default:
		;
	}

done:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
}
