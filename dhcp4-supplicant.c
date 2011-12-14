/*
 * DHCP4 supplicant
 *
 * Copyright (C) 2010, 2011 Olaf Kirch <okir@suse.de>
 */

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
#include <wicked/xml.h>
#include <wicked/socket.h>
#include <wicked/dhcp.h>
#include <wicked/ipv4ll.h>
#include "dhcp4/dhcp.h"

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_FOREGROUND,
	OPT_NOFORK,
	OPT_NORECOVER,
	OPT_DBUS,
	OPT_DHCP4_CLIENT,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "foreground",		no_argument,		NULL,	OPT_FOREGROUND },
	{ "no-fork",		no_argument,		NULL,	OPT_NOFORK },
	{ "no-recovery",	no_argument,		NULL,	OPT_NORECOVER },

	{ NULL }
};

static int		opt_foreground = 0;
static int		opt_recover_leases = 1;
static ni_dbus_server_t *dhcp4_dbus_server;

static void		dhcp4_supplicant(void);
static void		dhcp4_discover_devices(ni_dbus_server_t *);
static void		dhcp4_recover_lease(ni_interface_t *, xml_node_t **);
static void		dhcp4_interface_event(ni_handle_t *, ni_interface_t *, ni_event_t);
static void		dhcp4_protocol_event(enum ni_dhcp_event, const ni_dhcp_device_t *, ni_addrconf_lease_t *);

// Hack
extern ni_dbus_object_t *ni_objectmodel_register_dhcp4_device(ni_dbus_server_t *, ni_dhcp_device_t *);

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
				"        Enable debugging for debug <facility>.\n"
				"  --foreground\n"
				"        Do not background the service.\n"
				"  --norecover\n"
				"        Disable automatic recovery of leases.\n"
				, progname
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

		case OPT_NORECOVER:
			opt_recover_leases = 0;
			break;
		}
	}

	if (ni_init() < 0)
		return 1;

	if (optind != argc)
		goto usage;

	dhcp4_supplicant();
	return 0;
}

/*
 * At startup, discover current configuration.
 * If we have any live leases, restart address configuration for them.
 * This allows a daemon restart without losing lease state.
 */
void
dhcp4_recover_lease(ni_interface_t *ifp, xml_node_t **cfg_xml)
{
	ni_afinfo_t *afi = &ifp->ipv4;
	ni_addrconf_lease_t *lease;
	ni_addrconf_t *acm;

	if (!ni_afinfo_addrconf_test(afi, NI_ADDRCONF_DHCP))
		return;

	/* Don't do anything if we already have a lease for this. */
	if (afi->lease[NI_ADDRCONF_DHCP] != NULL)
		return;

	/* Some addrconf modes do not have a backend (like ipv6 autoconf) */
	acm = ni_addrconf_get(NI_ADDRCONF_DHCP, afi->family);
	if (acm == NULL)
		return;

	lease = ni_addrconf_lease_file_read(ifp->name, NI_ADDRCONF_DHCP, afi->family);
	if (lease == NULL)
		return;

	/* if lease expired, return and remove stale lease file */
	if (!ni_addrconf_lease_is_valid(lease)) {
		ni_debug_wicked("%s: removing stale %s/%s lease file", ifp->name,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
		ni_addrconf_lease_file_remove(ifp->name, NI_ADDRCONF_DHCP, afi->family);
		ni_addrconf_lease_free(lease);
		return;
	}

	/* Do not install the lease; let the addrconf mechanism fill in all
	 * the details. */
	ni_addrconf_lease_free(lease);

	/* Recover the original addrconf request data here */
	afi->request[NI_ADDRCONF_DHCP] = ni_addrconf_request_file_read(ifp->name, NI_ADDRCONF_DHCP, afi->family);
	if (afi->request[NI_ADDRCONF_DHCP] == NULL) {
		ni_error("%s: seem to have valid lease, but lost original request", ifp->name);
		return;
	}
	afi->request[NI_ADDRCONF_DHCP]->reuse_unexpired = 1;

	if (*cfg_xml == NULL)
		*cfg_xml = ni_syntax_xml_from_interface(ni_default_xml_syntax(),
				ni_global_state_handle(), ifp);

	if (ni_addrconf_acquire_lease(acm, ifp, *cfg_xml) < 0) {
		ni_error("%s: unable to reacquire lease %s/%s", ifp->name,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
		return;
	}

	ni_debug_wicked("%s: initiated recovery of %s/%s lease", ifp->name,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
}

/*
 * Functions to support the DHCP4 DBus binding
 */
static ni_dbus_method_t		__wicked_dbus_dhcp4_methods[] = {
	{ NULL }
};

static ni_dbus_service_t	__wicked_dbus_dhcp4_interface = {
	.name = WICKED_DBUS_DHCP4_INTERFACE,
	.methods = __wicked_dbus_dhcp4_methods,
};


void
dhcp4_register_services(ni_dbus_server_t *server)
{
	ni_dbus_object_t *root_object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_t *object;

	/* Register the root object /com/suse/Wicked/DHCP4 */
	ni_dbus_object_register_service(root_object, &__wicked_dbus_dhcp4_interface);

	/* Register /com/suse/Wicked/DHCP4/Interface */
	object = ni_dbus_server_register_object(server, "Interface", NULL, NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	// ni_dbus_object_register_service(object, &wicked_dbus_dhcpdev_interface);
	dhcp4_discover_devices(server);

	ni_dhcp_set_event_handler(dhcp4_protocol_event);
}

/*
 * Add a newly discovered device
 */
static void
dhcp4_device_create(ni_dbus_server_t *server, const ni_interface_t *ifp)
{
	ni_dhcp_device_t *dev;

	dev = ni_dhcp_device_new(ifp->name, &ifp->link);
	if (!dev)
		ni_fatal("Cannot create dhcp device for %s", ifp->name);
	dev->link.ifindex = ifp->link.ifindex;

	ni_objectmodel_register_dhcp4_device(server, dev);
	ni_debug_dbus("Created device for %s", ifp->name);
}

/*
 * Remove a device that has disappeared
 */
static void
dhcp4_device_destroy(ni_dbus_server_t *server, const ni_interface_t *ifp)
{
	ni_dhcp_device_t *dev;

	ni_debug_dhcp("%s(%s, ifindex %d)", __func__, ifp->name, ifp->link.ifindex);
	if ((dev = ni_dhcp_device_by_index(ifp->link.ifindex)) != NULL)
		ni_dbus_server_unregister_object(server, dev);
}

void
dhcp4_discover_devices(ni_dbus_server_t *server)
{
	ni_handle_t *nih;
	ni_interface_t *ifp;

	if (!(nih = ni_global_state_handle()))
		ni_fatal("Unable to obtain netinfo handle");

	if (ni_refresh(nih, NULL) < 0)
		ni_fatal("cannot refresh interface list!");

	for (ifp = ni_interfaces(nih); ifp; ifp = ifp->next) {
		dhcp4_device_create(server, ifp);

		if (opt_recover_leases) {
			xml_node_t *cfg_xml = NULL;

			dhcp4_recover_lease(ifp, &cfg_xml);

			if (cfg_xml)
				xml_node_free(cfg_xml);
		}
	}
}

/*
 * Implement DHCP4 supplicant dbus service
 */
void
dhcp4_supplicant(void)
{
	dhcp4_dbus_server = ni_server_listen_dbus(WICKED_DBUS_BUS_NAME_DHCP4);
	if (dhcp4_dbus_server == NULL)
		ni_fatal("unable to initialize dbus service");

	dhcp4_register_services(dhcp4_dbus_server);

	/* open global RTNL socket to listen for kernel events */
	if (ni_server_listen_events(dhcp4_interface_event) < 0)
		ni_fatal("unable to initialize netlink listener");

	if (!opt_foreground) {
		if (ni_server_background() < 0)
			ni_fatal("unable to background server");
		ni_log_destination_syslog("wickedd");
	}

	while (1) {
		long timeout;

		timeout = ni_timer_next_timeout();
		if (ni_socket_wait(timeout) < 0)
			ni_fatal("ni_socket_wait failed");
	}

	exit(0);
}

/*
 * Handle network layer events.
 * FIXME: There should be some locking here, which prevents us from
 * calling event handlers on an interface that the admin is currently
 * mucking with manually.
 */
void
dhcp4_interface_event(ni_handle_t *nih, ni_interface_t *ifp, ni_event_t event)
{
	ni_dhcp_device_t *dev;
	ni_interface_t *ofp;

	switch (event) {
	case NI_EVENT_LINK_CREATE:
		/* check for duplicate ifindex */
		ofp = ni_interface_by_index(nih, ifp->link.ifindex);
		if (ofp && ofp != ifp) {
			ni_warn("duplicate ifindex in link-create event");
			return;
		}

		/* Create dbus object */
		dhcp4_device_create(dhcp4_dbus_server, ifp);
		break;

	case NI_EVENT_LINK_DELETE:
		/* Delete dbus object */
		dhcp4_device_destroy(dhcp4_dbus_server, ifp);
		break;

	case NI_EVENT_LINK_DOWN:
	case NI_EVENT_LINK_UP:
		dev = ni_dhcp_device_by_index(ifp->link.ifindex);
		if (dev != NULL)
			ni_dhcp_device_event(dev, event);
		break;

	default: ;
	}
}

void
dhcp4_protocol_event(enum ni_dhcp_event ev, const ni_dhcp_device_t *dev, ni_addrconf_lease_t *lease)
{
	ni_dbus_variant_t argv[1];
	ni_dbus_object_t *dev_object;
	int argc = 0;

	ni_debug_dhcp("%s(ev=%u, dev=%d)", __func__, ev, dev->link.ifindex);

	dev_object = ni_dbus_server_find_object_by_handle(dhcp4_dbus_server, dev);
	if (dev_object == NULL) {
		ni_warn("%s: no dbus object for device %s!", __func__, dev->ifname);
		return;
	}

	memset(argv, 0, sizeof(argv));
	if (lease) {
		ni_dbus_variant_t *var = &argv[argc++];

		ni_dbus_variant_init_dict(var);
		if (!ni_objectmodel_get_addrconf_lease(lease, var)) {
			ni_warn("%s: could not extract lease data", __func__);
			goto done;
		}
	}

	switch (ev) {
	case NI_DHCP_EVENT_ACQUIRED:
		ni_server_send_signal(dhcp4_dbus_server, dev_object,
				WICKED_DBUS_DHCP4_INTERFACE, "LeaseAcquired",
				argc, argv);
		break;

	case NI_DHCP_EVENT_RELEASED:
		ni_server_send_signal(dhcp4_dbus_server, dev_object,
				WICKED_DBUS_DHCP4_INTERFACE, "LeaseReleased",
				argc, argv);
		break;

	case NI_DHCP_EVENT_LOST:
		ni_server_send_signal(dhcp4_dbus_server, dev_object,
				WICKED_DBUS_DHCP4_INTERFACE, "LeaseLost",
				argc, argv);
		break;

	default:
		;
	}

done:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
}
