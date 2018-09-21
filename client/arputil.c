/*
 *	wicked client arp actions and utilities
 *
 *	Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/address.h>
#include <wicked/socket.h>
#include <wicked/util.h>

#include "netinfo_priv.h"

struct arp_ops;

struct arp_handle {
	ni_bool_t		verbose;
	unsigned int		count;
	unsigned int		interval;
	unsigned int		deadline;
	unsigned int		replies;

	struct timeval		sent_time;
	unsigned int		sent_cnt;
	unsigned int		recv_cnt;

	const char *		ifname;
	ni_sockaddr_t		ipaddr;
	ni_hwaddr_t		hwaddr;
	ni_sockaddr_t		fromip;

	ni_arp_socket_t *	sock;
	struct {
		const ni_timer_t *interval;
		const ni_timer_t *deadline;
	} timer;
	const struct arp_ops *	ops;
};

struct arp_ops {
	int		(*init)(struct arp_handle *, ni_netdev_t *, ni_netconfig_t *);
	ni_bool_t	(*send)(struct arp_handle *);
	void		(*recv)(struct arp_handle *, const ni_arp_packet_t *);
	int		(*status)(struct arp_handle *, int);
};

static void		do_arp_handle_close(struct arp_handle *);


static int
do_arp_init(struct arp_handle *handle, ni_capture_devinfo_t *dev_info)
{
	ni_netconfig_t *nc;
	ni_netdev_t *dev;

	if (!handle || !handle->ops || !dev_info) {
		ni_error("Unable to initialize arp handle structure");
	}

	nc = ni_global_state_handle(0);
	ni_netconfig_set_family_filter(nc, AF_INET);
	ni_netconfig_set_discover_filter(nc,
			NI_NETCONFIG_DISCOVER_LINK_EXTERN |
			NI_NETCONFIG_DISCOVER_ROUTE_RULES);

	if (ni_server_listen_interface_events(NULL) < 0) {
		ni_error("unable to initialize netlink link listener");
		return NI_WICKED_RC_ERROR;
	}
	if (ni_server_enable_interface_addr_events(NULL) < 0) {
		ni_error("unable to initialize netlink addr listener");
		return NI_WICKED_RC_ERROR;
	}

	if (!(nc = ni_global_state_handle(1))) {
		ni_error("Cannot refresh interface list!");
		return NI_WICKED_RC_ERROR;
	}
	if (!(dev = ni_netdev_by_name(nc, handle->ifname))) {
		ni_error("Cannot find interface with name '%s'",
				handle->ifname);
		return NI_WICKED_RC_ERROR;
	}
	if (!ni_netdev_supports_arp(dev)) {
		ni_error("%s: arp is not supported/enabled", dev->name);
		return NI_WICKED_RC_ERROR;
	}
	if (!ni_netdev_link_is_up(dev)) {
		ni_error("%s: link is not up", dev->name);
		return NI_WICKED_RC_ERROR;
	}

	if (ni_capture_devinfo_init(dev_info, dev->name, &dev->link) < 0) {
		ni_error("%s: cannot initialize capture", dev->name);
		return NI_WICKED_RC_ERROR;
	}

	if (handle->ops->init) {
		return handle->ops->init(handle, dev, nc);
	} else {
		return NI_WICKED_RC_SUCCESS;
	}
}

static ni_bool_t
do_arp_send(struct arp_handle *handle)
{
	if (!handle || !handle->ops || !handle->ops->send)
		return FALSE;

	return handle->ops->send(handle);
}

static void
do_arp_recv(ni_arp_socket_t *sock, const ni_arp_packet_t *pkt, void *user_data)
{
	struct arp_handle *handle = user_data;

	if (!sock || !pkt || pkt->op != ARPOP_REPLY)
		return;

	if (!handle || !handle->ops || !handle->ops->recv)
		return;

	handle->ops->recv(handle, pkt);
}

static int
do_arp_run(struct arp_handle *handle)
{
	ni_capture_devinfo_t dev_info;
	int ret;

	if ((ret = do_arp_init(handle, &dev_info)) != 0)
		return ret;

	handle->sock = ni_arp_socket_open(&dev_info, do_arp_recv, handle);
	if (!handle->sock || !handle->sock->user_data) {
		ni_error("%s: Cannot initialize arp socket", handle->ifname);
		do_arp_handle_close(handle);
		return NI_WICKED_RC_ERROR;
	}

	if (!do_arp_send(handle)) {
		do_arp_handle_close(handle);
		ni_error("%s: Cannot send arp packet", handle->ifname);
		return NI_WICKED_RC_ERROR;
	}

	ret = NI_WICKED_RC_ERROR;
	while (!ni_caught_terminal_signal()) {
		long timeout;

		ret = NI_WICKED_RC_SUCCESS;
		timeout = ni_timer_next_timeout();
		if (ni_socket_wait(timeout) != 0)
			break;
		ret = NI_WICKED_RC_ERROR;
	}
	do_arp_handle_close(handle);

	if (handle->ops->status)
		return handle->ops->status(handle, ret);
	return ret;
}

static void
do_arp_handle_close(struct arp_handle *handle)
{
	if (handle) {
		if (handle->timer.deadline) {
			ni_timer_cancel(handle->timer.deadline);
			handle->timer.deadline = NULL;
		}
		if (handle->timer.interval) {
			ni_timer_cancel(handle->timer.interval);
			handle->timer.interval = NULL;
		}
		if (handle->sock) {
			ni_arp_socket_close(handle->sock);
			handle->sock = NULL;
		}
		ni_server_deactivate_interface_events();
	}
}

static void
do_arp_deadline_timeout(void *user_data, const ni_timer_t *timer)
{
	struct arp_handle * handle = user_data;

	ni_assert(handle && handle->timer.deadline == timer);
	handle->timer.deadline = NULL;

	do_arp_handle_close(handle);
}

static void
do_arp_interval_timeout(void *user_data, const ni_timer_t *timer)
{
	struct arp_handle * handle = user_data;

	ni_assert(handle && handle->timer.interval == timer);
	handle->timer.interval = NULL;

	if (!do_arp_send(handle)) {
		do_arp_handle_close(handle);
	}
}

static void
do_arp_arm_deadline_timer(struct arp_handle *handle)
{
	if (handle->timer.deadline) {
		ni_timer_rearm(handle->timer.deadline, handle->deadline);
	} else {
		handle->timer.deadline = ni_timer_register(
			handle->deadline, do_arp_deadline_timeout, handle
		);
	}
}

static void
do_arp_arm_interval_timer(struct arp_handle *handle)
{
	if (handle->timer.interval) {
		ni_timer_rearm(handle->timer.interval, handle->interval);
	} else {
		handle->timer.interval = ni_timer_register(
			handle->interval, do_arp_interval_timeout, handle
		);
	}
}


/*
 * verify
 */
static int
do_arp_verify_run(struct arp_handle *handle, const char *caller, int argc, char **argv)
{
	enum {
		OPT_QUIET, OPT_VERBOSE, OPT_HELP, OPT_INTERVAL, OPT_COUNT,
	};
	static struct option      options[] = {
		{ "help",         no_argument,       NULL, OPT_HELP        },
		{ "quiet",        no_argument,       NULL, OPT_QUIET       },
		{ "verbose",      no_argument,       NULL, OPT_VERBOSE     },

		{ "count",        required_argument, NULL, OPT_COUNT       },
		{ "interval",     required_argument, NULL, OPT_INTERVAL    },

		{ NULL,           no_argument,       NULL, 0               }
	};
	int opt, status = NI_WICKED_RC_USAGE;
	char *command   = NULL;

	if (ni_string_printf(&command, "%s %s",
				caller  ? caller  : "wicked arp",
				argv[0] ? argv[0] : "verify")) {
		caller  = argv[0];
		argv[0] = command;
	} else {
		command = (char *)caller;
	}

	optind = 1;
	ni_assert(handle && handle->ops);
	while ((opt = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage\n"
				"  %s [options ...] <ifname> <IP address>\n"
				"\n"
				"Supported options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --quiet\n"
				"      Return exit status only\n"
				"  --verbose\n"
				"      Show a result info (default)\n"
				"\n"
				"  --count <count>\n"
				"      Send <count> duplicate address detection probes\n"
				"      (default: 3). Returns 4 when address is in use.\n"
				"  --interval <msec>\n"
				"      DAD probing packet sending interval in msec\n"
				"      (default: 1000..2000).\n"
				, argv[0]
			);
			goto cleanup;

		case OPT_QUIET:
			handle->verbose = FALSE;
			break;

		case OPT_VERBOSE:
			handle->verbose = TRUE;
			break;

		case OPT_COUNT:
			if (ni_parse_uint(optarg, &handle->count, 10) ||
					!handle->count) {
				ni_error("%s: Cannot parse verify count '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;

		case OPT_INTERVAL:
			if (ni_parse_uint(optarg, &handle->interval, 10) ||
					!handle->interval) {
				ni_error("%s: Cannot parse verify interval '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;
		}
	}

	if (optind + 2 != argc)
		goto usage;

	handle->ifname = argv[optind++];
	if (ni_string_empty(handle->ifname))
		goto usage;

	if (ni_sockaddr_parse(&handle->ipaddr, argv[optind], AF_INET) != 0) {
		ni_error("%s: cannot parse '%s' as IPv4 address",
				argv[0], argv[optind]);
		goto cleanup;
	}

	status = do_arp_run(handle);

cleanup:
	if (command != caller)
		argv[0] = (char *)caller;
	ni_string_free(&command);
	return status;
}

static int
do_arp_verify_init(struct arp_handle *handle, ni_netdev_t *dev, ni_netconfig_t *nc)
{
	/* a uniform random jitter of (PROBE_MAX - PROBE_MIN) */
	const ni_int_range_t jitter = { .min = 0, .max = 1000 };

	(void)nc;
	(void)dev;

	/* rfc5227 PROBE_NUM                      */
	if (!handle->count)
		handle->count	 = 3;

	/* rfc5227 random(PROBE_MIN .. PROBE_MAX) */
	if (!handle->interval)
		handle->interval = ni_timeout_randomize(1000, &jitter);

	return 0;
}

static ni_bool_t
do_arp_verify_send(struct arp_handle *handle)
{
	static const struct in_addr null = { 0 };
	ni_bool_t ret = FALSE;

	if (!handle->hwaddr.len && handle->sent_cnt < handle->count) {
		ni_debug_application("%s: arp verify: %s",
				handle->ifname,
				ni_sockaddr_print(&handle->ipaddr));

		if ((ret = ni_arp_send_request(handle->sock, null,
				handle->ipaddr.sin.sin_addr) > 0)) {

			do {
				handle->sent_cnt++;
			} while (!handle->sent_cnt);
			ni_timer_get_time(&handle->sent_time);

			do_arp_arm_interval_timer(handle);
		}
	}

	return ret;
}

static void
do_arp_verify_recv(struct arp_handle *handle, const ni_arp_packet_t *pkt)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_arp_socket_t *sock = handle->sock;
	const ni_netdev_t *ifp;
	ni_bool_t false_alarm = FALSE;
	ni_bool_t found_addr = FALSE;
	const ni_address_t *ap;
	ni_sockaddr_t addr;

	/* Is it about the address we're validating at all? */
	if (pkt->sip.s_addr != handle->ipaddr.sin.sin_addr.s_addr) {
		ni_debug_application("%s: report about different address",
				handle->ifname);
		return;
	}

	/* Ignore any ARP replies that seem to come from our own
	 * MAC address. Some helpful switches seem to generate
	 * these. */
	if (ni_link_address_equal(&sock->dev_info.hwaddr, &pkt->sha)) {
		ni_debug_application("%s: adress in use by ourself",
				handle->ifname);
		return;
	}

	/* As well as ARP replies that seem to come from our own
	 * host: dup if same address, not a dup if there are two
	 * interfaces connected to the same broadcast domain.
	 */
	ni_sockaddr_set_ipv4(&addr, pkt->sip, 0);
	for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {
		if (ifp->link.ifindex == sock->dev_info.ifindex)
			continue;

		if (!ni_netdev_link_is_up(ifp))
			continue;

		if (!ni_link_address_equal(&ifp->link.hwaddr, &pkt->sha))
			continue;

		/* OK, we have an interface matching the hwaddr,
		 * which will answer arp requests when it is on
		 * the same broadcast domain and causes a false
		 * alarm, except it really has the IP assigned.
		 */
		false_alarm = TRUE;
		for (ap = ifp->addrs; !found_addr && ap; ap = ap->next) {
			if (ap->family != AF_INET)
				continue;
			if (ni_sockaddr_equal(&ap->local_addr, &addr))
				found_addr = TRUE;
		}
	}
	if (false_alarm && !found_addr) {
		ni_debug_application("%s: reply from one of our interfaces",
				handle->ifname);
		return;
	}

	ni_debug_application("%s: IP address %s in use reported by %s",
			handle->ifname, inet_ntoa(pkt->sip),
			ni_link_address_print(&pkt->sha));

	handle->hwaddr = pkt->sha;
	do_arp_handle_close(handle);
}

static int
do_arp_verify_status(struct arp_handle *handle, int status)
{
	if (handle->verbose) {
		if (handle->hwaddr.len) {
			fprintf(stdout, "%s: IP address %s is in use by %s\n",
				handle->ifname, ni_sockaddr_print(&handle->ipaddr),
				ni_link_address_print(&handle->hwaddr));
		} else {
			fprintf(stdout, "%s: No duplicates for IP address %s detected\n",
				handle->ifname, ni_sockaddr_print(&handle->ipaddr));
		}
		fflush(stdout);
	}
	if (handle->hwaddr.len)
		status = NI_WICKED_RC_NOT_ALLOWED;
	else
		status = NI_WICKED_RC_SUCCESS;
	return status;
}


/*
 * notify
 */
static int
do_arp_notify_run(struct arp_handle *handle, const char *caller, int argc, char **argv)
{
	enum {
		OPT_QUIET, OPT_VERBOSE, OPT_HELP, OPT_INTERVAL, OPT_COUNT,
	};
	static struct option      options[] = {
		{ "help",         no_argument,       NULL, OPT_HELP        },
		{ "quiet",        no_argument,       NULL, OPT_QUIET       },
		{ "verbose",      no_argument,       NULL, OPT_VERBOSE     },

		{ "count",        required_argument, NULL, OPT_COUNT       },
		{ "interval",     required_argument, NULL, OPT_INTERVAL    },

		{ NULL,           no_argument,       NULL, 0               }
	};
	int opt, status = NI_WICKED_RC_USAGE;
	char *command   = NULL;

	if (ni_string_printf(&command, "%s %s",
				caller  ? caller  : "wicked arp",
				argv[0] ? argv[0] : "notify")) {
		caller  = argv[0];
		argv[0] = command;
	} else {
		command = (char *)caller;
	}

	optind = 1;
	ni_assert(handle && handle->ops);
	while ((opt = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage:\n"
				"  %s [options ...] <ifname> <IP address>\n"
				"\n"
				"Supported options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --quiet\n"
				"      Return exit status only\n"
				"  --verbose\n"
				"      Show a result info (default)\n"
				"\n"
				"  --count <count>\n"
				"      Announce IP address use (gratuitous ARP) <count> times\n"
				"      (default: 2).\n"
				"  --interval <msec>\n"
				"      Announcement packet sending interval in msec\n"
				"      (default: 2000).\n"
				, argv[0]
			);
			goto cleanup;

		case OPT_QUIET:
			handle->verbose = FALSE;
			break;

		case OPT_VERBOSE:
			handle->verbose = TRUE;
			break;

		case OPT_COUNT:
			if (ni_parse_uint(optarg, &handle->count, 10) ||
					!handle->count) {
				ni_error("%s: Cannot parse notify count '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;

		case OPT_INTERVAL:
			if (ni_parse_uint(optarg, &handle->interval, 10) ||
					!handle->interval) {
				ni_error("%s: Cannot parse notify interval '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;
		}
	}

	if (optind + 2 != argc)
		goto usage;

	handle->ifname = argv[optind++];
	if (ni_string_empty(handle->ifname))
		goto usage;

	if (ni_sockaddr_parse(&handle->ipaddr, argv[optind], AF_INET) != 0) {
		ni_error("%s: cannot parse '%s' as IPv4 address",
				argv[0], argv[optind]);
		goto cleanup;
	}

	status = do_arp_run(handle);

cleanup:
	if (command != caller)
		argv[0] = (char *)caller;
	ni_string_free(&command);
	return status;
}

static int
do_arp_notify_init(struct arp_handle *handle, ni_netdev_t *dev, ni_netconfig_t *nc)
{
	(void)nc;
	(void)dev;

	/* rfc5227 ANNOUNCE_NUM      */
	if (!handle->count)
		handle->count	 = 2;

	/* rfc5227 ANNOUNCE_INTERVAL */
	if (!handle->interval)
		handle->interval = 2000;

	return 0;
}

static ni_bool_t
do_arp_notify_send(struct arp_handle *handle)
{
	ni_bool_t ret = FALSE;

	if (handle->sent_cnt < handle->count) {
		ni_debug_application("%s: arp notify: %s",
				handle->ifname,
				ni_sockaddr_print(&handle->ipaddr));

		if ((ret = ni_arp_send_grat_request(handle->sock,
				handle->ipaddr.sin.sin_addr) > 0)) {

			do {
				handle->sent_cnt++;
			} while (!handle->sent_cnt);
			ni_timer_get_time(&handle->sent_time);

			if (handle->sent_cnt < handle->count) {
				do_arp_arm_interval_timer(handle);
			} else if (handle->sock) {
				do_arp_handle_close(handle);
			}
		}
	}

	return ret;
}

static int
do_arp_notify_status(struct arp_handle *handle, int status)
{
	if (handle->verbose && handle->sent_cnt /* >= handle->count */) {
		fprintf(stdout, "%s: Notified neighbours about IP address %s\n",
			handle->ifname, ni_sockaddr_print(&handle->ipaddr));
		fflush(stdout);
	}

	if (handle->sent_cnt /* >= handle->count */)
		status = NI_WICKED_RC_SUCCESS;
	else
		status = NI_WICKED_RC_NOT_RUNNING;
	return status;
}


/*
 * ping
 */
static int
do_arp_ping_run(struct arp_handle *handle, const char *caller, int argc, char **argv)
{
	enum {
		OPT_QUIET, OPT_VERBOSE, OPT_HELP, OPT_INTERVAL, OPT_COUNT,
		OPT_TIMEOUT, OPT_REPLIES, OPT_FROM_IP
	};
	static struct option      options[] = {
		{ "help",         no_argument,       NULL, OPT_HELP        },
		{ "quiet",        no_argument,       NULL, OPT_QUIET       },
		{ "verbose",      no_argument,       NULL, OPT_VERBOSE     },

		{ "count",        required_argument, NULL, OPT_COUNT       },
		{ "interval",     required_argument, NULL, OPT_INTERVAL    },

		{ "timeout",      required_argument, NULL, OPT_TIMEOUT     },
		{ "replies",      required_argument, NULL, OPT_REPLIES     },
		{ "from-ip",      required_argument, NULL, OPT_FROM_IP     },

		{ NULL,           no_argument,       NULL, 0               }
	};
	int opt, status = NI_WICKED_RC_USAGE;
	char *command   = NULL;

	if (ni_string_printf(&command, "%s %s",
				caller  ? caller  : "wicked arp",
				argv[0] ? argv[0] : "ping")) {
		caller  = argv[0];
		argv[0] = command;
	} else {
		command = (char *)caller;
	}

	optind = 1;
	ni_assert(handle && handle->ops);
	while ((opt = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage:\n"
				"  %s [options ...] <ifname> <IP address>\n"
				"\n"
				"Supported options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --quiet\n"
				"      Return exit status only\n"
				"  --verbose\n"
				"      Show a result info (default)\n"
				"\n"
				"  --count <count> | inf\n"
				"      Ping specified IP address <count> times\n"
				"      (default: infinite).\n"
				"  --interval <msec>\n"
				"      Packet sending interval in msec\n"
				"      (default: 1000).\n"
				"  --replies <count>\n"
				"      Wait unitil specified number of ping replies\n"
				"  --timeout <msec>\n"
				"      Wait for ping replies until given timeout in msec\n"
				"  --from-ip <source ip>\n"
				"      Use specified IP address as the ping source\n"
				, argv[0]
			);
			goto cleanup;

		case OPT_QUIET:
			handle->verbose = FALSE;
			break;

		case OPT_VERBOSE:
			handle->verbose = TRUE;
			break;

		case OPT_COUNT:
			if (!optarg || ni_string_startswith(optarg, "inf"))
				handle->count = -1U;
			else
			if (ni_parse_uint(optarg, &handle->count, 10) ||
					!handle->count) {
				ni_error("%s: Cannot parse ping count '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;

		case OPT_INTERVAL:
			if (ni_parse_uint(optarg, &handle->interval, 10) ||
					!handle->interval) {
				ni_error("%s: Cannot parse ping interval '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;

		case OPT_TIMEOUT:
			if (ni_parse_uint(optarg, &handle->deadline, 10)) {
				ni_error("%s: Cannot parse ping timeout '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;

		case OPT_REPLIES:
			if (ni_parse_uint(optarg, &handle->replies, 10)) {
				ni_error("%s: Cannot parse ping replies count '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;

		case OPT_FROM_IP:
			if (ni_sockaddr_parse(&handle->fromip, optarg, AF_INET) != 0) {
				ni_error("%s: cannot parse ping source IP address: '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;
		}
	}

	if (optind + 2 != argc)
		goto usage;

	handle->ifname = argv[optind++];
	if (ni_string_empty(handle->ifname))
		goto usage;

	if (ni_sockaddr_parse(&handle->ipaddr, argv[optind], AF_INET) != 0) {
		ni_error("%s: cannot parse '%s' as IPv4 address",
				argv[0], argv[optind]);
		goto cleanup;
	}

	status = do_arp_run(handle);

cleanup:
	if (command != caller)
		argv[0] = (char *)caller;
	ni_string_free(&command);
	return status;
}

static int
do_arp_ping_init(struct arp_handle *handle, ni_netdev_t *dev, ni_netconfig_t *nc)
{
	ni_address_t *ap;

	ni_assert(handle && nc && dev);

	if (!handle->count)
		handle->count	 = -1U;

	if (!handle->interval)
		handle->interval = 1000;

	if (handle->deadline) {
		if (!handle->replies)
			handle->replies = 1;

		do_arp_arm_deadline_timer(handle);
	}

	if (handle->ipaddr.ss_family != AF_INET)
		return NI_WICKED_RC_ERROR;

	if (handle->fromip.ss_family == AF_INET)  {
		if (ni_sockaddr_is_ipv4_unspecified(&handle->fromip)) {
			ni_note("%s: Using unspecified source IP address %s",
					handle->ifname, ni_sockaddr_print(&handle->fromip));
		} else
		if (!ni_address_list_find(dev->addrs, &handle->fromip)) {
			ni_note("%s: Using source IP address %s not assiged to interface",
					handle->ifname, ni_sockaddr_print(&handle->fromip));
		}
		return NI_WICKED_RC_SUCCESS;
	}

	for (ap = dev->addrs; ap ; ap = ap->next) {
		if (!ni_sockaddr_prefix_match(ap->prefixlen,
				&ap->local_addr, &handle->ipaddr))
			continue;

		ni_info("%s: Using source IP address %s from matching network",
				handle->ifname, ni_sockaddr_print(&handle->fromip));
		ni_sockaddr_set_ipv4(&handle->fromip, ap->local_addr.sin.sin_addr, 0);
		return NI_WICKED_RC_SUCCESS;
	}

	for (ap = dev->addrs; ap ; ap = ap->next) {
		if (ap->family != AF_INET)
			continue;

		ni_sockaddr_set_ipv4(&handle->fromip, ap->local_addr.sin.sin_addr, 0);
		ni_info("%s: Using source IP address %s from non-matching network",
				handle->ifname, ni_sockaddr_print(&handle->fromip));
		return NI_WICKED_RC_SUCCESS;
	}

	ni_note("%s: No usable source IP address assigned to the interface",
			handle->ifname);
	handle->fromip.ss_family = AF_INET;

	return NI_WICKED_RC_SUCCESS;
}

static void
do_arp_ping_timeout(struct arp_handle *handle, struct timeval *now)
{
	if (handle->verbose && handle->sent_cnt && timerisset(&handle->sent_time)) {
		struct timeval delta;

		if (timercmp(now, &handle->sent_time, >))
			timersub(now, &handle->sent_time, &delta);
		else
			timerclear(&delta);
	        timerclear(&handle->sent_time);

		fprintf(stdout, "%s: arp ping seq=%u time=%ld.%03ldms: no reply\n",
			handle->ifname, handle->sent_cnt,
			delta.tv_sec*1000 + delta.tv_usec/1000, delta.tv_usec%1000);
		fflush(stdout);
	}
}

static ni_bool_t
do_arp_ping_send(struct arp_handle *handle)
{
	ni_bool_t ret = FALSE;
	struct timeval now;

	ni_timer_get_time(&now);
	do_arp_ping_timeout(handle, &now);

	if (handle->count == -1U || handle->sent_cnt < handle->count) {
		ni_debug_application("%s: sending arp ping to %s",
				handle->ifname, ni_sockaddr_print(&handle->ipaddr));

		if ((ret = ni_arp_send_request(handle->sock,
						handle->fromip.sin.sin_addr,
						handle->ipaddr.sin.sin_addr) > 0)) {
			do {
				handle->sent_cnt++;
			} while (!handle->sent_cnt);
			handle->sent_time = now;

			do_arp_arm_interval_timer(handle);
		}
	}

	return ret;
}

static void
do_arp_ping_recv(struct arp_handle *handle, const ni_arp_packet_t *pkt)
{
	struct {
		char sha[NI_MAXHWADDRLEN * 3 + 1];
		char tha[NI_MAXHWADDRLEN * 3 + 1];
		char sip[INET_ADDRSTRLEN + 1];
		char tip[INET_ADDRSTRLEN + 1];
	} str = { {'\0'}, {'\0'}, {'\0'}, {'\0'} };
	struct timeval now, delta;
	ni_sockaddr_t sip;

	ni_sockaddr_set_ipv4(&sip, pkt->sip, 0);

	inet_ntop(AF_INET, &pkt->sip, str.sip, sizeof(str.sip));
	inet_ntop(AF_INET, &pkt->tip, str.tip, sizeof(str.tip));
	ni_link_address_format(&pkt->sha, str.sha, sizeof(str.sha));
	ni_link_address_format(&pkt->tha, str.tha, sizeof(str.tha));

	ni_debug_application("%s: received arp reply from %s (%s) to %s (%s)",
		handle->ifname, str.sip, str.sha, str.tip, str.tha);

	/* unrelated arp reply packet from other IPs */
	if (!ni_sockaddr_equal(&sip, &handle->ipaddr))
		return;

	ni_timer_get_time(&now);
	if (timercmp(&now, &handle->sent_time, >))
		timersub(&now, &handle->sent_time, &delta);
	else
		timerclear(&delta);
	timerclear(&handle->sent_time);
	handle->recv_cnt++;

	if (handle->verbose) {
		fprintf(stdout, "%s: arp ping seq=%u time=%ld.%03ldms: reply from %s (%s)\n",
			handle->ifname,	handle->sent_cnt,
			delta.tv_sec*1000 + delta.tv_usec/1000, delta.tv_usec%1000,
			str.sip, str.sha);
		fflush(stdout);
	}

	if (handle->replies && handle->recv_cnt >= handle->replies)
		do_arp_handle_close(handle);
}

static int
do_arp_ping_status(struct arp_handle *handle, int status)
{

	if (!ni_caught_terminal_signal()) {
		struct timeval now;

		ni_timer_get_time(&now);
		do_arp_ping_timeout(handle, &now);
	}

	if (!handle->recv_cnt) {
		status = NI_WICKED_RC_NOT_RUNNING;
	} else
	if (handle->replies || handle->deadline) {
		if (handle->recv_cnt >= handle->replies)
			status = NI_WICKED_RC_SUCCESS;
		else
			status = NI_WICKED_RC_NOT_RUNNING;
	} else {
		status = NI_WICKED_RC_SUCCESS;
	}

	return status;
}

/*
 * main
 */
static const struct arp_ops	do_arp_verify_ops = {
	.init	=	do_arp_verify_init,
	.send	=	do_arp_verify_send,
	.recv	=	do_arp_verify_recv,
	.status	=	do_arp_verify_status,
};
static const struct arp_ops	do_arp_notify_ops = {
	.init	=	do_arp_notify_init,
	.send	=	do_arp_notify_send,
	.status	=	do_arp_notify_status,
};
static const struct arp_ops	do_arp_ping_ops = {
	.init	=	do_arp_ping_init,
	.send	=	do_arp_ping_send,
	.recv	=	do_arp_ping_recv,
	.status	=	do_arp_ping_status,
};

int
ni_do_arp(const char *caller, int argc, char **argv)
{
	enum {
		OPT_QUIET, OPT_VERBOSE, OPT_HELP, OPT_INTERVAL,
		OPT_VERIFY, OPT_NOTIFY,
	};
	static struct option      options[] = {
		{ "help",         no_argument,       NULL, OPT_HELP        },
		{ "quiet",        no_argument,       NULL, OPT_QUIET       },
		{ "verbose",      no_argument,       NULL, OPT_VERBOSE     },

		{ "verify",       required_argument, NULL, OPT_VERIFY      },
		{ "notify",       required_argument, NULL, OPT_NOTIFY      },
		{ "interval",     required_argument, NULL, OPT_INTERVAL    },

		{ NULL,           no_argument,       NULL, 0               }
	};
	int               opt, status   = NI_WICKED_RC_USAGE;
	unsigned int      opt_nprobes = 0;
	unsigned int      opt_nclaims = 0;
	struct arp_handle handle;
	char *command = NULL;

	memset(&handle, 0, sizeof(handle));
	handle.verbose = TRUE;

	if (ni_string_printf(&command, "%s %s",
				caller  ? caller  : "wicked",
				argv[0] ? argv[0] : "duid")) {
		caller  = argv[0];
		argv[0] = command;
	} else {
		command = (char *)caller;
	}

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage:\n"
				"  %s [options] <action> [action options] <ifname> <IP address>\n"
				"\n"
				"Common options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --quiet\n"
				"      Return exit status only\n"
				"  --verbose\n"
				"      Show a result info (default)\n"
				"\n"
				"Deprecated options:\n"
				"  --verify <count>\n"
				"      Verify IP for duplicates on the network (DAD);\n"
				"      Returns 4, when duplicate IP address exists.\n"
				"  --notify <count>\n"
				"      Notify about IP address use (gratuitous ARP)\n"
				"  --interval <msec>\n"
				"      Packet sending interval in msec\n"
				"\n"
				"Actions:\n"
				"  verify [options] <ifname> <IP address>\n"
				"        Verify/Probe an IP address for duplicates\n"
				"\n"
				"  notify [options] <ifname> <IP address>\n"
				"        Notify/Announce IP address use to neighbours\n"
				"\n"
				"  ping   [options] <ifname> <IP address>\n"
				"        ARP ping the specified neigbour\n"
				"\n"
				, argv[0]
			);
			goto cleanup;

		case OPT_QUIET:
			handle.verbose = FALSE;
			break;

		case OPT_VERBOSE:
			handle.verbose = TRUE;
			break;

		case OPT_VERIFY:
			if (ni_parse_uint(optarg, &opt_nprobes, 10)) {
				ni_error("%s: Cannot parse valid verify count: '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;

		case OPT_NOTIFY:
			if (ni_parse_uint(optarg, &opt_nclaims, 10)) {
				ni_error("%s: Cannot parse valid notify count: '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;

		case OPT_INTERVAL:
			if (ni_parse_uint(optarg, &handle.interval, 10) || !handle.interval) {
				ni_error("%s: Cannot parse valid interval timeout: '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			break;
		}
	}

	if ((opt_nprobes || opt_nclaims) && optind + 2 == argc) {
		/*
		 * deprecated --verify or --notify options
		 */
		handle.ifname = argv[optind++];
		if (ni_string_empty(handle.ifname))
			goto usage;

		if (ni_sockaddr_parse(&handle.ipaddr, argv[optind], AF_INET) != 0) {
			ni_error("%s: cannot parse '%s' as IPv4 address", argv[0],
					argv[optind]);
			goto cleanup;
		}

		if (opt_nprobes && opt_nclaims) {
			ni_error("%s: cannot verify and notify at the same time", argv[0]);
			goto usage;
		} else
		if (opt_nprobes) {
			handle.ops = &do_arp_verify_ops;
			handle.count = opt_nprobes;
			status = do_arp_run(&handle);
		} else
		if (opt_nclaims) {
			handle.ops = &do_arp_notify_ops;
			handle.count = opt_nclaims;
			status = do_arp_run(&handle);
		} else {
			ni_error("%s: neither a verify nor a notify to send", argv[0]);
			goto usage;
		}

	} else
	if (argc > optind) {
		/*
		 * new action + action options
		 */
		char *action = argv[optind];

		if (ni_string_eq("help", action)) {
			goto usage;
		} else
		if (ni_string_eq(action, "verify") ||
		    ni_string_eq(action, "probe")) {
			handle.ops = &do_arp_verify_ops;
			status = do_arp_verify_run(&handle, command, argc - optind, argv + optind);
		} else
		if (ni_string_eq(action, "notify") ||
		    ni_string_eq(action, "claim")) {
			handle.ops = &do_arp_notify_ops;
			status = do_arp_notify_run(&handle, command, argc - optind, argv + optind);
		} else
		if (ni_string_eq(action, "ping")) {
			handle.ops = &do_arp_ping_ops;
			status = do_arp_ping_run(&handle, command, argc - optind, argv + optind);
		} else {
			ni_error("%s: Unknown action '%s'\n", argv[0], action);
			goto usage;
		}
	} else
		goto usage;

cleanup:
	if (command != caller)
		argv[0] = (char *)caller;
	ni_string_free(&command);
	return status;
}

