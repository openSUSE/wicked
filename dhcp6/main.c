/*
 *	DHCP6 supplicant -- main
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012 Marius Tomaschewski <mt@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <limits.h>
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/util.h>
#include <wicked/address.h>
#include <wicked/ipv6.h>
#include <wicked/netinfo.h>
#include <wicked/objectmodel.h>
#include <wicked/logging.h>

#include "dhcp6/dbus-api.h"

#define CONFIG_DHCP6_STATE_FILE	"dhcp6-state.xml"

enum {
	OPT_HELP,
	OPT_VERSION,
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_LOG_LEVEL,
	OPT_LOG_TARGET,

	OPT_FOREGROUND,
	OPT_NORECOVER,
};

static struct option		options[] = {
	/* common */
	{ "help",		no_argument,		NULL,	OPT_HELP },
	{ "version",		no_argument,		NULL,	OPT_VERSION },
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "log-level",		required_argument,	NULL,	OPT_LOG_LEVEL },
	{ "log-target",		required_argument,	NULL,	OPT_LOG_TARGET },

	/* daemon */
	{ "foreground",		no_argument,		NULL,	OPT_FOREGROUND },

	/* specific */
	{ "no-recovery",	no_argument,		NULL,	OPT_NORECOVER },

	{ NULL,			no_argument,		NULL,	0 }
};

static const char *		program_name;
static const char *		opt_log_target;
static int			opt_foreground;
static int			opt_no_recover_leases = 1;
static char *			opt_state_file;

static ni_dbus_server_t *	dhcp6_dbus_server;

static void			dhcp6_interface_event(ni_netdev_t *, ni_event_t);
static void			dhcp6_interface_addr_event(ni_netdev_t *, ni_event_t, const ni_address_t *);
static void			dhcp6_interface_prefix_event(ni_netdev_t *, ni_event_t, const ni_ipv6_ra_pinfo_t *);
static void			dhcp6_supplicant(void);

int
main(int argc, char **argv)
{
	int c;

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
				"  --norecover\n"
				"        Disable automatic recovery of leases.\n"
				, program_name
			       );
			return (c == OPT_HELP ? 0 : 1);

		case OPT_VERSION:
			printf("%s %s\n", program_name, PACKAGE_VERSION);
			return 0;

		case OPT_CONFIGFILE:
			if (!ni_set_global_config_path(optarg)) {
				fprintf(stderr, "Unable to set config file '%s': %m\n", optarg);
				return 1;
			}
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help();
				return 0;
			}
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				return 1;
			}
			break;

		case OPT_LOG_LEVEL:
			if (!ni_log_level_set(optarg)) {
				fprintf(stderr, "Bad log level \%s\"\n", optarg);
				return 1;
			}
			break;

		case OPT_LOG_TARGET:
			opt_log_target = optarg;
			break;

		case OPT_FOREGROUND:
			opt_foreground = 1;
			break;

		case OPT_NORECOVER:
			opt_no_recover_leases = 1;
			break;
		}
	}

	if (optind != argc)
		goto usage;

	if (opt_log_target) {
		if (!ni_log_destination(program_name, opt_log_target)) {
			fprintf(stderr, "Bad log destination \%s\"\n",
					opt_log_target);
			return 1;
		}
	} else if (opt_foreground && getppid() != 1) {
		ni_log_destination(program_name, "syslog::perror");
	} else {
		ni_log_destination(program_name, "syslog");
	}

	if (ni_init("dhcp6") < 0)
		return 1;

	if (opt_state_file == NULL) {
		static char dirname[PATH_MAX];

		snprintf(dirname, sizeof(dirname), "%s/%s", ni_config_statedir(),
							CONFIG_DHCP6_STATE_FILE);
		opt_state_file = dirname;
	}

	/* We're using randomized timeouts. Seed the RNG */
	ni_srandom();

	dhcp6_supplicant();
	return 0;
}

/*
 * Functions to support the DHCP6 DBus binding
 */
static ni_dbus_service_t	__ni_objectmodel_dhcp6_interface = {
	.name			= NI_OBJECTMODEL_DHCP6_INTERFACE,	/* org.opensuse.Network.DHCP6 */
};

static void			dhcp6_discover_devices(ni_dbus_server_t *);
static void			dhcp6_protocol_event(enum ni_dhcp6_event, const ni_dhcp6_device_t *, ni_addrconf_lease_t *);
static void			dhcp6_recover_addrconf(const char *filename);


/*
 * Register DHCP6 dbus interface services
 */
static void
dhcp6_register_services(ni_dbus_server_t *server)
{
	ni_dbus_object_t *root_object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_t *object;

	/*  Register the root object (org.opensuse.Network.DHCP6) */
	ni_dbus_object_register_service(root_object, &__ni_objectmodel_dhcp6_interface);

	/* Register /org/opensuse/Network/DHCP6/Interface */
	object = ni_dbus_server_register_object(server, "Interface", &ni_dbus_anonymous_class, NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	dhcp6_discover_devices(server);

	ni_dhcp6_set_event_handler(dhcp6_protocol_event);
}

/*
 * Add a newly discovered device
 */
static ni_bool_t
dhcp6_device_create(ni_dbus_server_t *server, const ni_netdev_t *ifp)
{
	ni_dhcp6_device_t *dev;
	ni_bool_t rv = FALSE;

	dev = ni_dhcp6_device_new(ifp->name, &ifp->link);
	if (!dev) {
		ni_error("Cannot allocate dhcp6 device for '%s' and index %u",
			ifp->name, ifp->link.ifindex);
		return rv;
	}

	if (ni_objectmodel_register_dhcp6_device(server, dev) != NULL) {
		ni_debug_dhcp("Created dhcp6 device for '%s' and index %u",
				ifp->name, ifp->link.ifindex);
		rv = TRUE;
	}

	/* either register dhcp6 device was successful and obtained
	 * an own reference or we can drop ours here anyway ... */
	ni_dhcp6_device_put(dev);

	return rv;
}

/*
 * Remove a device that has disappeared
 */
static void
dhcp6_device_destroy(ni_dbus_server_t *server, const ni_netdev_t *ifp)
{
        ni_dhcp6_device_t *dev;

	if ((dev = ni_dhcp6_device_by_index(ifp->link.ifindex)) != NULL) {
		ni_debug_dhcp("%s: Destroying dhcp6 device with index %u",
				ifp->name, ifp->link.ifindex);
                ni_dbus_server_unregister_object(server, dev);
	}
}

static void
dhcp6_device_destroy_all(ni_dbus_server_t *server)
{
	ni_netconfig_t *nc;
	ni_netdev_t *   ifp;

	if (!(nc = ni_global_state_handle(0)))
		return;

	for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {
		dhcp6_device_destroy(server, ifp);
	}
}

/*
 * Discover existing interfaces and create dhcp6 dbus devices
 */
static void
dhcp6_discover_devices(ni_dbus_server_t *server)
{
	ni_netconfig_t *nc;
	ni_netdev_t *	ifp;

	if (!(nc = ni_global_state_handle(1)))
		ni_fatal("Cannot refresh interface list!");

	for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {

		/* currently ether type only */
		if (ifp->link.arp_type != ARPHRD_ETHER)
			continue;

		(void)dhcp6_device_create(server, ifp);
	}
}

/*
 * Implement DHCP6 supplicant dbus service
 */
static void
dhcp6_supplicant(void)
{
	/* Initialize dbus server (org.opensuse.Network.DHCP6) */
	dhcp6_dbus_server = ni_server_listen_dbus(NI_OBJECTMODEL_DBUS_BUS_NAME_DHCP6);
	if (dhcp6_dbus_server == NULL)
		ni_fatal("Unable to initialize dbus server");

	ni_objectmodel_dhcp6_init();

	dhcp6_register_services(dhcp6_dbus_server);

	/* open global RTNL socket to listen for kernel events */
	if (ni_server_listen_interface_events(dhcp6_interface_event) < 0)
		ni_fatal("Unable to initialize netlink interface event listener");

	if (ni_server_enable_interface_addr_events(dhcp6_interface_addr_event) < 0)
		ni_fatal("Unable to initialize netlink address event listener");

	if (ni_server_enable_interface_prefix_events(dhcp6_interface_prefix_event) < 0)
		ni_fatal("Unable to initialize netlink prefix event listener");

	if (!opt_foreground) {
		if (ni_server_background(program_name) < 0)
			ni_fatal("Unable to background server");
	}

	if (!opt_no_recover_leases)
		dhcp6_recover_addrconf(opt_state_file);

	while (!ni_caught_terminal_signal()) {
		long timeout;

		do {
			timeout = ni_timer_next_timeout();
		} while(ni_dbus_objects_garbage_collect());

		if (ni_socket_wait(timeout) < 0)
			ni_fatal("ni_socket_wait failed");
	}
	/*
	ni_objectmodel_save_state(opt_state_file);
	*/

	ni_server_deactivate_interface_events();

	dhcp6_device_destroy_all(dhcp6_dbus_server);
	ni_dbus_objects_garbage_collect();

	ni_socket_deactivate_all();
}

/*
 * Recover lease information from the state.xml file.
 */
void
dhcp6_recover_addrconf(const char *filename)
{
	if (!ni_file_exists(filename)) {
		ni_debug_dhcp("%s: %s does not exist, skip this", __func__, filename);
		return;
	}

	/* Recover the lease information of all interfaces. */
	if (!ni_objectmodel_recover_state(filename, NULL)) {
		ni_error("unable to recover dhcp6 state");
		return;
	}

	/* Now loop over all devices that have a request associated with them,
	 * and kickstart those.
	 */
	ni_dhcp6_restart();
}

static void
dhcp6_interface_event(ni_netdev_t *ifp, ni_event_t event)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_dhcp6_device_t *dev;
	ni_netdev_t *ofp;

	ni_debug_events("%s[%u]: received interface event: %s",
			ifp->name, ifp->link.ifindex,
			ni_event_type_to_name(event));

	switch (event) {
	case NI_EVENT_DEVICE_CREATE:
		/* check for duplicate ifindex */
		ofp = ni_netdev_by_index(nc, ifp->link.ifindex);
		if (ofp && ofp != ifp) {
			/*
			 * FIXME: how/when can this happen?
			 */
			ni_warn("duplicate ifindex in device-create event");
			return;
		}

		/* Create dbus object */
		dhcp6_device_create(dhcp6_dbus_server, ifp);
	break;

	case NI_EVENT_DEVICE_DELETE:
		/* Delete dbus device object */
		dhcp6_device_destroy(dhcp6_dbus_server, ifp);
	break;

	case NI_EVENT_DEVICE_DOWN:
	case NI_EVENT_DEVICE_UP:
	case NI_EVENT_NETWORK_DOWN:
	case NI_EVENT_NETWORK_UP:
	case NI_EVENT_LINK_DOWN:
	case NI_EVENT_LINK_UP:
		dev = ni_dhcp6_device_by_index(ifp->link.ifindex);
		if (dev != NULL) {
			ni_dhcp6_device_event(dev, ifp, event);
		}
break;

default:
break;
}
}

static void
dhcp6_interface_addr_event(ni_netdev_t *ifp, ni_event_t event, const ni_address_t *addr)
{
	ni_dhcp6_device_t *dev;

	dev = ni_dhcp6_device_by_index(ifp->link.ifindex);
	if (dev != NULL) {
		ni_dhcp6_address_event(dev, ifp, event, addr);
	}
}

static void
dhcp6_interface_prefix_event(ni_netdev_t *ifp, ni_event_t event, const ni_ipv6_ra_pinfo_t *pi)
{
	ni_dhcp6_device_t *dev;

	if (!ifp || !pi)
		return;

	dev = ni_dhcp6_device_by_index(ifp->link.ifindex);
	if (dev != NULL) {
		ni_dhcp6_prefix_event(dev, ifp, event, pi);
	}
}

static void
dhcp6_protocol_event(enum ni_dhcp6_event ev, const ni_dhcp6_device_t *dev, ni_addrconf_lease_t *lease)
{
	ni_dbus_variant_t argv[4];
	ni_dbus_object_t *dev_object;
	ni_dbus_variant_t *var;
	int argc = 0;

	ni_debug_dhcp("%s(ev=%u, dev=%d, uuid=%s)", __func__, ev, dev->link.ifindex,
			dev->config ? ni_uuid_print(&dev->config->uuid) : "<none>");

	dev_object = ni_dbus_server_find_object_by_handle(dhcp6_dbus_server, dev);
	if (dev_object == NULL) {
		ni_warn("%s(%s): no dbus object for dhcp6 device!",
			__func__, dev->ifname);
		return;
	}

	memset(argv, 0, sizeof(argv));

	if (dev->config) {
		var = &argv[argc++];
		ni_dbus_variant_set_uuid(var, &dev->config->uuid);

		/* Make sure we copy the "update" flags to the lease; the
		 * server relies on us to provide this info */
		if (lease)
			lease->update = dev->config->update;
	}

	var = &argv[argc++];
	ni_dbus_variant_init_dict(var);
	if (lease) {
		if (!ni_objectmodel_get_addrconf_lease(lease, var)) {
			ni_warn("%s(%s): could not extract lease data",
				__func__, dev->ifname);
			goto done;
		}
	}

	switch (ev) {
	case NI_DHCP6_EVENT_ACQUIRED:
		if (lease == NULL) {
			ni_error("%s: BUG not send %s event without a lease handle",
				dev->ifname, NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL);
			goto done;
		}
		ni_dbus_server_send_signal(dhcp6_dbus_server, dev_object,
				NI_OBJECTMODEL_ADDRCONF_INTERFACE, NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL,
				argc, argv);
		break;

	case NI_DHCP6_EVENT_RELEASED:
		ni_dbus_server_send_signal(dhcp6_dbus_server, dev_object,
				NI_OBJECTMODEL_ADDRCONF_INTERFACE, NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL,
				argc, argv);
		break;

	case NI_DHCP6_EVENT_LOST:
		ni_dbus_server_send_signal(dhcp6_dbus_server, dev_object,
				NI_OBJECTMODEL_ADDRCONF_INTERFACE, NI_OBJECTMODEL_LEASE_LOST_SIGNAL,
				argc, argv);
		break;

	default:
		break;
	}

done:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
}

