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
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
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

static void		wicked_discover_state(void);
static void		wicked_try_restart_addrconf(ni_interface_t *, ni_afinfo_t *, unsigned int, xml_node_t **);
static int		wicked_accept_connection(ni_socket_t *, uid_t, gid_t);
static void		wicked_interface_event(ni_handle_t *, ni_interface_t *, ni_event_t);
static void		wicked_process_network_restcall(ni_socket_t *);

int
main(int argc, char **argv)
{
	ni_socket_t *sock;
	int c;

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"./wickedd [options]\n"
				"This command understands the following options\n"
				"  --config filename\n"
				"        Read configuration file <filename> instead of system default.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
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

	ni_addrconf_register(&ni_dhcp_addrconf);
	ni_addrconf_register(&ni_autoip_addrconf);

	if (optind != argc)
		goto usage;

	if ((sock = ni_server_listen()) < 0)
		ni_fatal("unable to initialize server socket");
	sock->accept = wicked_accept_connection;

	/* open global RTNL socket to listen for kernel events */
	if (ni_server_listen_events(wicked_interface_event) < 0)
		ni_fatal("unable to initialize netlink listener");

	if (!opt_foreground) {
		if (ni_server_background() < 0)
			return 1;
		ni_log_destination_syslog("wickedd");
	}

	wicked_discover_state();

	while (1) {
		if (ni_socket_wait(-1) < 0)
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
	ni_handle_t *nih;
	ni_interface_t *ifp;

	nih = ni_global_state_handle();
	if (nih == NULL)
		ni_fatal("Unable to get global state handle");
	if (ni_refresh(nih) < 0)
		ni_fatal("failed to discover interface state");

	if (opt_recover_leases) {
		for (ifp = ni_interfaces(nih); ifp; ifp = ifp->next) {
			xml_node_t *cfg_xml = NULL;
			unsigned int mode;

			for (mode = 0; mode < __NI_ADDRCONF_MAX; ++mode) {
				wicked_try_restart_addrconf(ifp, &ifp->ipv4, mode, &cfg_xml);
				wicked_try_restart_addrconf(ifp, &ifp->ipv6, mode, &cfg_xml);
			}

			if (cfg_xml)
				xml_node_free(cfg_xml);
		}
	}
}

void
wicked_try_restart_addrconf(ni_interface_t *ifp, ni_afinfo_t *afi, unsigned int mode, xml_node_t **cfg_xml)
{
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
 * Accept an incoming connection.
 * Return value of -1 means close the socket.
 */
static int
wicked_accept_connection(ni_socket_t *sock, uid_t uid, gid_t gid)
{
	if (uid != 0) {
		ni_error("refusing attempted connection by user %u", uid);
		return -1;
	}

	ni_debug_wicked("accepted connection from uid=%u", uid);
	if (opt_nofork) {
		wicked_process_network_restcall(sock);
	} else {
		pid_t pid;

		/* Fork the worker child */
		pid = fork();
		if (pid < 0) {
			ni_error("unable to fork worker child: %m");
			return -1;
		}

		if (pid == 0) {
			wicked_process_network_restcall(sock);
			exit(0);
		}
	}

	return -1;
}

void
wicked_process_network_restcall(ni_socket_t *sock)
{
	ni_wicked_request_t req;
	int rv;

	/* Read the request coming in from the socket. */
	ni_wicked_request_init(&req);
	rv = ni_wicked_request_parse(sock, &req);

	/* Process the call */
	if (rv >= 0)
		rv = ni_wicked_call_direct(&req);

	/* ... and send the response back. */
	ni_wicked_response_print(sock, &req, rv);

	ni_wicked_request_destroy(&req);
}

/*
 * Handle network layer events.
 * FIXME: There should be some locking here, which prevents us from
 * calling event handlers on an interface that the admin is currently
 * mucking with manually.
 */
void
wicked_interface_event(ni_handle_t *nih, ni_interface_t *ifp, ni_event_t event)
{
	static const char *evtype[__NI_EVENT_MAX] =  {
		[NI_EVENT_LINK_CREATE]	= "link-create",
		[NI_EVENT_LINK_DELETE]	= "link-delete",
		[NI_EVENT_LINK_UP]	= "link-up",
		[NI_EVENT_LINK_DOWN]	= "link-down",
		[NI_EVENT_NETWORK_UP]	= "network-up",
		[NI_EVENT_NETWORK_DOWN]	= "network-down",
	};
	ni_policy_t *policy;

	if (event >= __NI_EVENT_MAX || !evtype[event])
		return;

	ni_debug_events("%s: %s event", ifp->name, evtype[event]);
	policy = ni_policy_match_event(ni_global_policies(), event, ifp);
	if (policy != NULL) {
		ni_debug_events("matched interface policy; configuring device");
		ni_interface_configure(ni_global_state_handle(), policy->interface, NULL);
	}
}
