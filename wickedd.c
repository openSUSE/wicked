/*
 * No REST for the wicked!
 *
 * This command line utility provides a daemon interface to the network
 * configuration/information facilities.
 *
 * It uses a RESTful interface (even though it's a command line utility).
 * The idea is to make it easier to extend this to some smallish daemon
 * with a AF_LOCAL socket interface.
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
#include <wicked/socket.h>
#include <wicked/objectmodel.h>

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_FOREGROUND,
	OPT_NOFORK,
	OPT_NORECOVER,
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
static int		opt_nofork = 0;
static int		opt_recover_leases = 1;
static ni_dbus_server_t *wicked_dbus_server;
static void		(*opt_personality)(void);

static void		wicked_interface_server(void);
static void		wicked_discover_state(void);
static void		wicked_try_restart_addrconf(ni_interface_t *, ni_afinfo_t *, unsigned int);
static void		wicked_interface_event(ni_netconfig_t *, ni_interface_t *, ni_event_t);

int
main(int argc, char **argv)
{
	const char *progname;
	int c;

	opt_personality = wicked_interface_server;

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
		}
	}

	if (ni_init() < 0)
		return 1;

	if (optind != argc)
		goto usage;

	opt_personality();
	return 0;
}

/*
 * Implement service for configuring the system's network interfaces
 */
void
wicked_interface_server(void)
{
	ni_xs_scope_t *wicked_dbus_xml_schema;

	wicked_dbus_server = ni_objectmodel_create_service();
	if (!wicked_dbus_server)
		ni_fatal("Cannot create server, giving up.");

	wicked_dbus_xml_schema = ni_objectmodel_init(wicked_dbus_server);
	if (wicked_dbus_xml_schema == NULL)
		ni_fatal("Cannot initialize objectmodel, giving up.");

	/* open global RTNL socket to listen for kernel events */
	if (ni_server_listen_events(wicked_interface_event) < 0)
		ni_fatal("unable to initialize netlink listener");

	if (!opt_foreground) {
		if (ni_server_background() < 0)
			ni_fatal("unable to background server");
		ni_log_destination_syslog("wickedd");
	}

	wicked_discover_state();

	while (1) {
		long timeout;

		timeout = ni_timer_next_timeout();
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
wicked_discover_state(void)
{
	ni_netconfig_t *nc;
	ni_interface_t *ifp;

	nc = ni_global_state_handle(1);
	if (nc == NULL)
		ni_fatal("failed to discover interface state");

	if (opt_recover_leases) {
		for (ifp = ni_interfaces(nc); ifp; ifp = ifp->next) {
			unsigned int mode;

			for (mode = 0; mode < __NI_ADDRCONF_MAX; ++mode) {
				wicked_try_restart_addrconf(ifp, &ifp->ipv4, mode);
				wicked_try_restart_addrconf(ifp, &ifp->ipv6, mode);
			}
		}
	}

	if (wicked_dbus_server) {
		for (ifp = ni_interfaces(nc); ifp; ifp = ifp->next)
			ni_objectmodel_register_interface(wicked_dbus_server, ifp);
	}
}

/*
 * This does not work right now
 */
void
wicked_try_restart_addrconf(ni_interface_t *ifp, ni_afinfo_t *afi, unsigned int mode)
{
#if 0
	const ni_addrconf_t *mech;
	ni_addrconf_lease_t *lease;
	ni_addrconf_t *acm;

	if (!ni_afinfo_addrconf_test(afi, mode))
		return;

	/* Don't do anything if we already have a lease for this. */
	if (afi->lease[mode] != NULL)
		return;

	/* Some addrconf modes do not have a backend (like ipv6 autoconf) */
	acm = ni_addrconf_get(mode, afi->family);
	if (acm == NULL)
		return;

	lease = ni_addrconf_lease_file_read(ifp->name, mode, afi->family);
	if (lease == NULL)
		return;

	/* if lease expired, return and remove stale lease file */
	if (!ni_addrconf_lease_is_valid(lease)) {
		ni_debug_wicked("%s: removing stale %s/%s lease file", ifp->name,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
		ni_addrconf_lease_file_remove(ifp->name, mode, afi->family);
		ni_addrconf_lease_free(lease);
		return;
	}

	/* Do not install the lease; let the addrconf mechanism fill in all
	 * the details. */
	ni_addrconf_lease_free(lease);

	/* Recover the original addrconf request data here */
	afi->request[mode] = ni_addrconf_request_file_read(ifp->name, mode, afi->family);
	if (afi->request[mode] == NULL) {
		ni_error("%s: seem to have valid lease, but lost original request", ifp->name);
		return;
	}
	afi->request[mode]->reuse_unexpired = 1;

	if (ni_addrconf_acquire_lease(acm, ifp) < 0) {
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
 * Handle network layer events for interface server.
 * FIXME: There should be some locking here, which prevents us from
 * calling event handlers on an interface that the admin is currently
 * mucking with manually.
 */
void
wicked_interface_event(ni_netconfig_t *nc, ni_interface_t *ifp, ni_event_t event)
{
	static const char *evtype[__NI_EVENT_MAX] =  {
		[NI_EVENT_LINK_CREATE]	= "link-create",
		[NI_EVENT_LINK_DELETE]	= "link-delete",
		[NI_EVENT_LINK_UP]	= "link-up",
		[NI_EVENT_LINK_DOWN]	= "link-down",
		[NI_EVENT_NETWORK_UP]	= "network-up",
		[NI_EVENT_NETWORK_DOWN]	= "network-down",
	};
	ni_uuid_t *event_uuid = NULL;

	if (wicked_dbus_server) {
		switch (event) {
		case NI_EVENT_LINK_CREATE:
			/* Create dbus object and emit event */
			ni_objectmodel_register_interface(wicked_dbus_server, ifp);
			break;

		case NI_EVENT_LINK_DELETE:
			/* Delete dbus object and emit event */
			ni_objectmodel_unregister_interface(wicked_dbus_server, ifp);
			break;

		case NI_EVENT_LINK_UP:
		case NI_EVENT_LINK_DOWN:
			if (!ni_uuid_is_null(&ifp->link.event_uuid))
				event_uuid = &ifp->link.event_uuid;
			/* fallthru */

		default:
			ni_objectmodel_interface_event(wicked_dbus_server, ifp, event, event_uuid);
			break;
		}
	}

	if (event >= __NI_EVENT_MAX || !evtype[event])
		return;

#if 0
	ni_policy_t *policy;

	ni_debug_events("%s: %s event", ifp->name, evtype[event]);
	policy = ni_policy_match_event(nc, event, ifp);
	if (policy != NULL) {
		ni_debug_events("matched interface policy; configuring device");
		//ni_interface_configure2(nc, ifp, policy->interface);
	}
#endif
}
