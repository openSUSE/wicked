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
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/logging.h>
#include <wicked/objectmodel.h>

#include "dhcp6/dbus-api.h"
#include "dhcp6/device.h"
#include "dhcp6/tester.h"
#include "netinfo_priv.h"
#include "duid.h"


#define CONFIG_DHCP6_STATE_FILE	"dhcp6-state.xml"

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

	OPT_TEST,
	OPT_TEST_MODE,
	OPT_TEST_TIMEOUT,
	OPT_TEST_REQUEST,
	OPT_TEST_OUTPUT,
	OPT_TEST_OUTFMT,
};

static struct option		options[] = {
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

	/* test run */
	{ "test",		no_argument,		NULL,	OPT_TEST         },
	{ "test-mode",		required_argument,	NULL,	OPT_TEST_MODE    },
	{ "test-request",	required_argument,	NULL,	OPT_TEST_REQUEST },
	{ "test-timeout",	required_argument,	NULL,	OPT_TEST_TIMEOUT },
	{ "test-output",	required_argument,	NULL,	OPT_TEST_OUTPUT  },
	{ "test-format",	required_argument,	NULL,	OPT_TEST_OUTFMT  },
	{ NULL,			no_argument,		NULL,	0 }
};

static const char *		program_name;
static const char *		opt_log_target;
static ni_bool_t		opt_foreground;
static ni_bool_t		opt_recover_state;
static ni_bool_t		opt_systemd;
static char *			opt_state_file;

static ni_dbus_server_t *	dhcp6_dbus_server;

static void			dhcp6_interface_event(ni_netdev_t *, ni_event_t);
static void			dhcp6_interface_addr_event(ni_netdev_t *, ni_event_t, const ni_address_t *);
static void			dhcp6_interface_prefix_event(ni_netdev_t *, ni_event_t, const ni_ipv6_ra_pinfo_t *);

static void			dhcp6_supplicant(void);


int
main(int argc, char **argv)
{
	ni_dhcp6_tester_t * tester = NULL;
	int c, status = NI_WICKED_RC_USAGE;

	ni_log_init();
	program_name = ni_basename(argv[0]);

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		/* common */
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
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
				"\n"
				"  --test [test-options] <ifname>\n"
				"    test-options:\n"
				"       --test-mode    <auto|info|managed>\n"
				"       --test-request <request.xml>\n"
				"       --test-timeout <timeout in sec> (default: 20+10)\n"
				"       --test-output  <output file name>\n"
				"       --test-format  <leaseinfo|lease-xml>\n"
				, program_name
			       );
			return status;

		case OPT_VERSION:
			printf("%s %s\n", program_name, PACKAGE_VERSION);
			return NI_WICKED_RC_SUCCESS;

		case OPT_CONFIGFILE:
			if (!ni_set_global_config_path(optarg)) {
				fprintf(stderr, "Unable to set config file '%s': %m\n",
						optarg);
				return NI_WICKED_RC_ERROR;
			}
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help();
				return NI_WICKED_RC_SUCCESS;
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

		/* daemon */
		case OPT_FOREGROUND:
			opt_foreground = TRUE;
			break;

		/* specific */
		case OPT_RECOVER:
			opt_recover_state = TRUE;
			break;

		case OPT_SYSTEMD:
			opt_systemd = TRUE;
			break;

		/* test run */
		case OPT_TEST:
			opt_foreground = TRUE;
			tester = ni_dhcp6_tester_init();
			break;

		case OPT_TEST_MODE:
			if (!tester || ni_string_empty(optarg))
				goto usage;
			if (ni_dhcp6_mode_name_to_type(optarg, &tester->mode) < 0)
				goto usage;
			break;

		case OPT_TEST_REQUEST:
			if (!tester || ni_string_empty(optarg))
				goto usage;
			tester->request = optarg;
			break;

		case OPT_TEST_TIMEOUT:
			if (!tester || ni_parse_uint(optarg,
						&tester->timeout, 0) < 0)
				goto usage;
			break;

		case OPT_TEST_OUTPUT:
			if (!tester || ni_string_empty(optarg))
				goto usage;
			tester->output = optarg;
			break;

		case OPT_TEST_OUTFMT:
			if (!tester || !ni_dhcp6_tester_set_outfmt(optarg,
						&tester->outfmt))
				goto usage;
			break;
		}
	}

	if (tester) {
		if (optind < argc && !ni_string_empty(argv[optind])) {
			tester->ifname = argv[optind++];
		} else {
			fprintf(stderr, "Missing interface argument\n");
			goto usage;
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
	else if (opt_foreground && tester) {
		ni_log_destination(program_name, "stderr");
	}
	else if (opt_systemd || getppid() == 1 || !opt_foreground) { /* syslog only */
		ni_log_destination(program_name, "syslog");
	}
	else { /* syslog + stderr */
		ni_log_destination(program_name, "syslog::perror");
	}

	if (ni_init("dhcp6") < 0)
		return NI_WICKED_RC_ERROR;

	if (opt_recover_state && ni_string_empty(opt_state_file)) {
		static char dirname[PATH_MAX];

		snprintf(dirname, sizeof(dirname), "%s/%s", ni_config_statedir(),
							CONFIG_DHCP6_STATE_FILE);
		opt_state_file = dirname;
	}

	ni_netconfig_set_family_filter(ni_global_state_handle(0), AF_INET6);
	ni_netconfig_set_discover_filter(ni_global_state_handle(0),
					NI_NETCONFIG_DISCOVER_LINK_EXTERN|
					NI_NETCONFIG_DISCOVER_ROUTE_RULES);

	if (tester) {
		/* Create necessary directories if not yet there */
		ni_config_storedir();
		ni_config_statedir();

		return ni_dhcp6_tester_run(tester);
	}

	dhcp6_supplicant();
	return NI_WICKED_RC_SUCCESS;
}


/*
 * Functions to support the DHCP6 DBus binding
 */
static ni_dbus_service_t	__ni_objectmodel_dhcp6_interface = {
	.name			= NI_OBJECTMODEL_DHCP6_INTERFACE,	/* org.opensuse.Network.DHCP6 */
};

static void			dhcp6_discover_devices(ni_dbus_server_t *);
static void			dhcp6_protocol_event(enum ni_dhcp6_event, const ni_dhcp6_device_t *, ni_addrconf_lease_t *);
static void			dhcp6_recover_state(const char *filename);


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

	if ((dev = ni_dhcp6_device_by_index(ifp->link.ifindex)) != NULL)
		return TRUE;

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
		ni_dhcp6_device_stop(dev);
		ni_dhcp6_device_set_request(dev, NULL);
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
		if (!ni_dhcp6_supported(ifp))
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
		ni_daemon_close_t close_flags = NI_DAEMON_CLOSE_STD;

		if (ni_string_startswith(opt_log_target, "stderr"))
			close_flags &= ~NI_DAEMON_CLOSE_ERR;

		if (ni_server_background(program_name, close_flags) < 0)
			ni_fatal("Unable to background server");
	}

	if (opt_recover_state)
		dhcp6_recover_state(opt_state_file);

	while (!ni_caught_terminal_signal()) {
		long timeout;

		do {
			timeout = ni_timer_next_timeout();
		} while(ni_dbus_objects_garbage_collect());

		if (ni_socket_wait(timeout) != 0)
			ni_fatal("ni_socket_wait failed");
	}

	/*
	if (opt_recover_state)
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
dhcp6_recover_state(const char *filename)
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
		if (ni_dhcp6_supported(ifp))
			dhcp6_device_create(dhcp6_dbus_server, ifp);
	break;

	case NI_EVENT_DEVICE_DELETE:
		/* Delete dbus device object */
		dhcp6_device_destroy(dhcp6_dbus_server, ifp);
	break;

	case NI_EVENT_DEVICE_CHANGE:
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
		if (lease) {
			lease->update = dev->config->update;
			lease->flags = dev->config->flags;
		}
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
	case NI_DHCP6_EVENT_DEFERRED:
		ni_dbus_server_send_signal(dhcp6_dbus_server, dev_object,
				NI_OBJECTMODEL_ADDRCONF_INTERFACE, NI_OBJECTMODEL_LEASE_DEFERRED_SIGNAL,
				argc, argv);
		break;

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

