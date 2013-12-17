/*
 * DHCP4 supplicant
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
#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/wireless.h>
#include <wicked/objectmodel.h>
#include <wicked/xml.h>
#include <wicked/leaseinfo.h>

#include "dhcp4/dhcp.h"

enum {
	/* common */
	OPT_HELP,
	OPT_VERSION,
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_LOG_LEVEL,
	OPT_LOG_TARGET,
	OPT_SYSTEMD,

	/* specific */
	OPT_FOREGROUND,
	OPT_NORECOVER,

	/* test run */
	OPT_TEST,
	OPT_TEST_TIMEOUT,
	OPT_TEST_REQUEST,
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
	{ "no-recovery",	no_argument,		NULL,	OPT_NORECOVER },

	/* test run */
	{ "test",		no_argument,		NULL,	OPT_TEST         },
	{ "test-request",	required_argument,	NULL,	OPT_TEST_REQUEST },
	{ "test-timeout",	required_argument,	NULL,	OPT_TEST_TIMEOUT },

	{ NULL,			no_argument,		NULL,	0 }
};

static const char *	program_name;
static const char *	opt_log_target;
static ni_bool_t	opt_foreground;
static ni_bool_t	opt_no_recover_leases;
static ni_bool_t	opt_systemd;
static char *		opt_state_file;

static ni_dbus_server_t *dhcp4_dbus_server;

static void		dhcp4_supplicant(void);
static void		dhcp4_recover_addrconf(const char *);
static void		dhcp4_discover_devices(ni_dbus_server_t *);
static void		dhcp4_interface_event(ni_netdev_t *, ni_event_t);
static void		dhcp4_protocol_event(enum ni_dhcp_event, const ni_dhcp_device_t *, ni_addrconf_lease_t *);

// Hack
extern ni_dbus_object_t *ni_objectmodel_register_dhcp4_device(ni_dbus_server_t *, ni_dhcp_device_t *);

static int		dhcp4_test_status;
static int		dhcp4_test_run(const char *ifname, const char *request,	unsigned int timeout);

int
main(int argc, char **argv)
{
	unsigned int opt_test_run = 0;
	unsigned int opt_test_timeout = -1U;
	const char * opt_test_request = NULL;
	const char * opt_test_ifname = NULL;
	int c;

	program_name = ni_basename(argv[0]);

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		/* common */
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
				"  --log-level level\n"
				"        Set log level to <error|warning|notice|info|debug>.\n"
				"  --log-target target\n"
				"        Set log destination to <stderr|syslog>.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
				"        Use '--debug help' for a list of facilities.\n"
				"  --foreground\n"
				"        Do not background the service.\n"
				"  --norecover\n"
				"        Disable automatic recovery of leases.\n"
				"  --systemd\n"
				"        Enables behavior required by wicked.service under systemd\n"
				"\n"
				"  --test [test-options] <ifname>\n"
				"    test-options:\n"
				"       --test-request <request.xml>\n"
				"       --test-timeout <timeout in sec> (default: 10)\n"
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

		/* daemon */
		case OPT_FOREGROUND:
			opt_foreground = TRUE;
			break;

		/* specific */
		case OPT_NORECOVER:
			opt_no_recover_leases = TRUE;
			break;

		case OPT_SYSTEMD:
			opt_systemd = TRUE;
			break;

		/* test run */
		case OPT_TEST:
			opt_foreground = TRUE;
			opt_no_recover_leases = TRUE;
			opt_test_run = 1;
			break;

		case OPT_TEST_TIMEOUT:
			if (!opt_test_run || ni_parse_uint(optarg, &opt_test_timeout, 0) < 0)
				goto usage;
			break;

		case OPT_TEST_REQUEST:
			if (!opt_test_run || ni_string_empty(optarg))
				goto usage;
			opt_test_request = optarg;
			break;
		}
	}

	if (opt_test_run) {
		if (optind < argc && !ni_string_empty(argv[optind])) {
			opt_test_ifname = argv[optind++];
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
	else if (opt_foreground && opt_test_run) {
		ni_log_destination(program_name, "stderr");
	}
	else if (opt_systemd || getppid() == 1 || !opt_foreground) { /* syslog only */
		ni_log_destination(program_name, "syslog");
	}
	else { /* syslog + stderr */
		ni_log_destination(program_name, "syslog::perror");
	}

	if (ni_init("dhcp4") < 0)
		return NI_LSB_RC_ERROR;

	if (opt_state_file == NULL) {
		static char dirname[PATH_MAX];

		snprintf(dirname, sizeof(dirname), "%s/dhcp4-state.xml", ni_config_statedir());
		opt_state_file = dirname;
	}

	/* We're using randomized timeouts. Seed the RNG */
	ni_srandom();

	if (opt_test_run) {
		return dhcp4_test_run(opt_test_ifname, opt_test_request, opt_test_timeout);
	}

	dhcp4_supplicant();
	return NI_LSB_RC_SUCCESS;
}

static void
dhcp4_test_protocol_event(enum ni_dhcp_event ev, const ni_dhcp_device_t *dev,
		ni_addrconf_lease_t *lease)
{
	ni_debug_dhcp("%s(ev=%u, dev=%s[%u], config-uuid=%s)", __func__, ev,
			dev->ifname, dev->link.ifindex,
			dev->config ? ni_uuid_print(&dev->config->uuid) : "<none>");

	switch (ev) {
	case NI_DHCP_EVENT_ACQUIRED:
		if (lease && lease->state == NI_ADDRCONF_STATE_GRANTED) {
			ni_leaseinfo_dump(stdout, lease, dev->ifname, NULL);
			dhcp4_test_status = 0;
		}
		break;
	default:
		break;
	}
}

static ni_bool_t
dhcp4_test_req_xml_init(ni_dhcp4_request_t *req, xml_document_t *doc)
{
	xml_node_t *xml, *child;

	xml = xml_document_root(doc);
	if (xml && !xml->name && xml->children)
		xml = xml->children;

	/* TODO: parse using /ipv4:dhcp/request xml schema? */
	if (!xml || !ni_string_eq(xml->name, "request")) {
		ni_error("Invalid dhcp4 request xml '%s'",
				xml ? xml_node_location(xml) : NULL);
		return FALSE;
	}

	for (child = xml->children; child; child = child->next) {
		if (ni_string_eq(child->name, "uuid")) {
			if (ni_uuid_parse(&req->uuid, child->cdata) != 0)
				goto failure;
		} else
		if (ni_string_eq(child->name, "acquire-timeout")) {
			if (ni_parse_uint(child->cdata, &req->acquire_timeout, 10) != 0)
				goto failure;
		} else
		if (ni_string_eq(child->name, "hostname")) {
			if (!ni_check_domain_name(child->cdata, ni_string_len(child->cdata), 0))
				goto failure;
			ni_string_dup(&req->hostname, child->cdata);
		} else
		if (ni_string_eq(child->name, "clientid")) {
			ni_opaque_t duid;

			if (ni_parse_hex(child->cdata, duid.data, sizeof(duid.data)) <= 0)
				goto failure;
			ni_string_dup(&req->clientid, child->cdata);
		}
	}

	return TRUE;
failure:
	if (child) {
		ni_error("Cannot parse dhcp4 request '%s': %s",
				child->name, xml_node_location(child));
	}
	return FALSE;
}

static ni_bool_t
dhcp4_test_req_init(ni_dhcp4_request_t *req, const char *request)
{
	/* Apply some defaults */
	req->acquire_timeout = 10;

	if (!ni_string_empty(request)) {
		xml_document_t *doc;

		if (!(doc = xml_document_read(request))) {
			ni_error("Cannot parse dhcp4 request xml '%s'", request);
			return FALSE;
		}

		if (!dhcp4_test_req_xml_init(req, doc)) {
			xml_document_free(doc);
			return FALSE;
		}
		xml_document_free(doc);
	}

	/* Always enter dry run mode */
	req->dry_run = TRUE;
	if (ni_uuid_is_null(&req->uuid))
		ni_uuid_generate(&req->uuid);

	return TRUE;
}

static int
dhcp4_test_run(const char *ifname, const char *request, unsigned int timeout)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;
	ni_dhcp_device_t *dev;
	ni_dhcp4_request_t *req;
	int rv;

	dhcp4_test_status = 2;

	if (!(nc = ni_global_state_handle(1)))
		ni_fatal("Cannot refresh interface list!");

	if (!(ifp = ni_netdev_by_name(nc, ifname)))
		ni_fatal("Cannot find interface with name '%s'", ifname);

	switch (ifp->link.hwaddr.type) {
	case ARPHRD_ETHER:
		break;
	default:
		ni_fatal("Interface type not supported yet");
		break;
	}

	if (!(dev = ni_dhcp_device_new(ifp->name, &ifp->link)))
		ni_fatal("Cannot allocate dhcp4 client for '%s'", ifname);

	ni_dhcp_set_event_handler(dhcp4_test_protocol_event);

	if (!(req = ni_dhcp4_request_new())) {
		ni_error("Cannot allocate dhcp4 request");
		goto failure;
	}

	if (!dhcp4_test_req_init(req, request))
		goto failure;

	if (timeout != -1U)
		req->acquire_timeout = timeout;

	if ((rv = ni_dhcp_acquire(dev, req)) < 0) {
		ni_error("%s: DHCPv6 acquire request %s failed: %s",
				dev->ifname, ni_uuid_print(&req->uuid),
				ni_strerror(rv));
		goto failure;
	}

	while (!ni_caught_terminal_signal()) {
		long timeout;

		timeout = ni_timer_next_timeout();

		if (ni_socket_wait(timeout) != 0)
			break;
	}
	ni_server_deactivate_interface_events();
	ni_socket_deactivate_all();

failure:
	ni_dhcp_device_put(dev);
	ni_dhcp4_request_free(req);
	return dhcp4_test_status;
}

/*
 * At startup, discover current configuration.
 * If we have any live leases, restart address configuration for them.
 * This allows a daemon restart without losing lease state.
 */

#if 0 /* broken right now */
void
dhcp4_recover_lease(ni_netdev_t *ifp)
{
	ni_afinfo_t *afi = &ifp->ipv4;
	ni_addrconf_lease_t *lease;

	if (!ni_afinfo_addrconf_test(afi, NI_ADDRCONF_DHCP))
		return;

	/* Don't do anything if we already have a lease for this. */
	if (afi->lease[NI_ADDRCONF_DHCP] != NULL)
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

	if (1) {
		ni_error("%s: unable to reacquire lease %s/%s", ifp->name,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
		return;
	}

	ni_debug_wicked("%s: initiated recovery of %s/%s lease", ifp->name,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
}
#endif

/*
 * Functions to support the DHCP4 DBus binding
 */
static ni_dbus_service_t	__ni_objectmodel_dhcp4_interface = {
	.name		= NI_OBJECTMODEL_DHCP4_INTERFACE,
};


void
dhcp4_register_services(ni_dbus_server_t *server)
{
	ni_dbus_object_t *root_object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_t *object;

	/* Register the root object /org/opensuse/Network/DHCP4 */
	ni_dbus_object_register_service(root_object, &__ni_objectmodel_dhcp4_interface);

	/* Register /org/opensuse/Network/DHCP4/Interface */
	object = ni_dbus_server_register_object(server, "Interface", &ni_dbus_anonymous_class, NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	dhcp4_discover_devices(server);

	ni_dhcp_set_event_handler(dhcp4_protocol_event);
}

/*
 * Add a newly discovered device
 */
static ni_bool_t
dhcp4_device_create(ni_dbus_server_t *server, const ni_netdev_t *ifp)
{
	ni_dhcp_device_t *dev;
	ni_bool_t rv = FALSE;

	dev = ni_dhcp_device_new(ifp->name, &ifp->link);
	if (!dev) {
		ni_error("Cannot allocate dhcp4 device for '%s' and index %u",
			ifp->name, ifp->link.ifindex);
		return rv;
	}

	if (ni_objectmodel_register_dhcp4_device(server, dev) != NULL) {
		ni_debug_dhcp("Created dhcp4 device for '%s' and index %u",
				ifp->name, ifp->link.ifindex);
		rv = TRUE;
	}

	/* either register dhcp4 device was successful and obtained
	 * an own reference or we can drop ours here anyway ... */
	ni_dhcp_device_put(dev);

	return rv;
}

/*
 * Remove a device that has disappeared
 */
static void
dhcp4_device_destroy(ni_dbus_server_t *server, const ni_netdev_t *ifp)
{
	ni_dhcp_device_t *dev;

	if ((dev = ni_dhcp_device_by_index(ifp->link.ifindex)) != NULL) {
		ni_debug_dhcp("%s: Destroying dhcp4 device with index %u",
				ifp->name, ifp->link.ifindex);
		ni_dbus_server_unregister_object(server, dev);
	}
}

static void
dhcp4_device_destroy_all(ni_dbus_server_t *server)
{
	ni_netconfig_t *nc;
	ni_netdev_t *   ifp;

	if (!(nc = ni_global_state_handle(0)))
		return;

	for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {
		dhcp4_device_destroy(server, ifp);
	}
}

void
dhcp4_discover_devices(ni_dbus_server_t *server)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;

	/* FIXME: We should instruct the wireless code to not talk to
	 * wpa-supplicant. We're not interested in that stuff, and all
	 * it does is burn CPU cycles. */

	if (!(nc = ni_global_state_handle(1)))
		ni_fatal("cannot refresh interface list!");

	for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {
		if (ifp->link.hwaddr.type != ARPHRD_ETHER)
			continue;
		dhcp4_device_create(server, ifp);
	}
}

/*
 * Implement DHCP4 supplicant dbus service
 */
void
dhcp4_supplicant(void)
{
	dhcp4_dbus_server = ni_server_listen_dbus(NI_OBJECTMODEL_DBUS_BUS_NAME_DHCP4);
	if (dhcp4_dbus_server == NULL)
		ni_fatal("unable to initialize dbus service");

	ni_objectmodel_dhcp4_init();

	dhcp4_register_services(dhcp4_dbus_server);

	/* open global RTNL socket to listen for kernel events */
	if (ni_server_listen_interface_events(dhcp4_interface_event) < 0)
		ni_fatal("unable to initialize netlink listener");

	if (!opt_foreground) {
		if (ni_server_background(program_name) < 0)
			ni_fatal("unable to background server");
	}

	if (!opt_no_recover_leases)
		dhcp4_recover_addrconf(opt_state_file);

	while (!ni_caught_terminal_signal()) {
		long timeout;

		do {
			timeout = ni_timer_next_timeout();
		} while(ni_dbus_objects_garbage_collect());

		if (ni_socket_wait(timeout) != 0)
			ni_fatal("ni_socket_wait failed");
	}

	ni_objectmodel_save_state(opt_state_file);

	ni_server_deactivate_interface_events();

	dhcp4_device_destroy_all(dhcp4_dbus_server);
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
dhcp4_interface_event(ni_netdev_t *ifp, ni_event_t event)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_dhcp_device_t *dev;
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
		dhcp4_device_create(dhcp4_dbus_server, ifp);
		break;

	case NI_EVENT_DEVICE_DELETE:
		/* Delete dbus object */
		dhcp4_device_destroy(dhcp4_dbus_server, ifp);
		break;

	case NI_EVENT_DEVICE_UP:
	case NI_EVENT_LINK_DOWN:
	case NI_EVENT_LINK_UP:
		dev = ni_dhcp_device_by_index(ifp->link.ifindex);
		if (dev != NULL)
			ni_dhcp_device_event(dev, ifp, event);
		break;

	case NI_EVENT_DEVICE_DOWN:
		/* Someone has taken the interface down completely. Which means
		 * we shouldn't pretend we're still owning this device. So forget
		 * all leases and shut up. */
		ni_debug_dhcp("device %s went down: discard any leases", ifp->name);
		dev = ni_dhcp_device_by_index(ifp->link.ifindex);
		if (dev != NULL)
			ni_dhcp_device_stop(dev);
		break;

	default: ;
	}
}

void
dhcp4_protocol_event(enum ni_dhcp_event ev, const ni_dhcp_device_t *dev, ni_addrconf_lease_t *lease)
{
	ni_dbus_variant_t argv[4];
	ni_dbus_object_t *dev_object;
	ni_dbus_variant_t *var;
	int argc = 0;

	ni_debug_dhcp("%s(ev=%u, dev=%d, uuid=%s)", __func__, ev, dev->link.ifindex,
			dev->config? ni_uuid_print(&dev->config->uuid) : "<none>");

	dev_object = ni_dbus_server_find_object_by_handle(dhcp4_dbus_server, dev);
	if (dev_object == NULL) {
		ni_warn("%s: no dbus object for device %s!", __func__, dev->ifname);
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
			ni_warn("%s: could not extract lease data", __func__);
			goto done;
		}
	}

	switch (ev) {
	case NI_DHCP_EVENT_ACQUIRED:
		if (lease == NULL) {
			ni_error("BUG: cannot send %s event without a lease handle",
					NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL);
			goto done;
		}
		ni_dbus_server_send_signal(dhcp4_dbus_server, dev_object,
				NI_OBJECTMODEL_ADDRCONF_INTERFACE, NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL,
				argc, argv);
		break;

	case NI_DHCP_EVENT_RELEASED:
		ni_dbus_server_send_signal(dhcp4_dbus_server, dev_object,
				NI_OBJECTMODEL_ADDRCONF_INTERFACE, NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL,
				argc, argv);
		break;

	case NI_DHCP_EVENT_LOST:
		ni_dbus_server_send_signal(dhcp4_dbus_server, dev_object,
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

/*
 * Recover lease information from the state.xml file.
 */
void
dhcp4_recover_addrconf(const char *filename)
{
	if (!ni_file_exists(filename)) {
		ni_debug_wicked("%s: %s does not exist, skip this", __func__, filename);
		return;
	}

	/* Recover the lease information of all interfaces. */
	if (!ni_objectmodel_recover_state(filename, NULL)) {
		ni_error("unable to recover dhcp4 state");
		return;
	}

	/* Now loop over all devices that have a request associated with them,
	 * and kickstart those. */
	ni_dhcp_restart_leases();
}

