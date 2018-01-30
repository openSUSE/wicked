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
#include <arpa/inet.h>
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/address.h>
#include <wicked/socket.h>
#include <wicked/util.h>

#include "netinfo_priv.h"

enum { OPT_QUIET, OPT_VERBOSE, OPT_HELP, OPT_VERIFY, OPT_NOTIFY, OPT_TIMEOUT };

struct arp_handle {
	unsigned int		nprobes;
	unsigned int		nclaims;
	unsigned int		timeout;
	ni_bool_t		replies;

	const char *		ifname;
	ni_sockaddr_t		ipaddr;
	ni_hwaddr_t		hwaddr;

	ni_arp_socket_t *	sock;
	const ni_timer_t *	timer;
};

static ni_bool_t	__do_arp_validate_send(struct arp_handle *);

static void
__do_arp_handle_close(struct arp_handle *handle)
{
	if (handle) {
		if (handle->sock)
			ni_arp_socket_close(handle->sock);
		handle->sock = NULL;
		ni_server_deactivate_interface_events();
	}
}

static void
__do_arp_validate_process(ni_arp_socket_t *sock, const ni_arp_packet_t *pkt,
		void *user_data)
{
	struct arp_handle *handle = user_data;
	ni_netconfig_t *nc = ni_global_state_handle(0);
	const ni_netdev_t *ifp;
	ni_bool_t false_alarm = FALSE;
	ni_bool_t found_addr = FALSE;
	const ni_address_t *ap;
	ni_sockaddr_t addr;

	if (!pkt || pkt->op != ARPOP_REPLY || !handle->replies)
		return;

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

	ni_info("%s: adress %s in use by %s reported",
			handle->ifname,
			inet_ntoa(pkt->sip),
			ni_link_address_print(&pkt->sha));
	handle->hwaddr = pkt->sha;
}

static void
__do_arp_validate_timeout(void *user_data, const ni_timer_t *timer)
{
	struct arp_handle * handle = user_data;

	if (!user_data || !handle->timer || handle->timer != timer)
		return;

	handle->timer = NULL;
	if (!__do_arp_validate_send(handle)) {
		__do_arp_handle_close(handle);
	}
}

static void
__do_arp_validate_arm_timer(struct arp_handle *handle)
{
	if (handle->timer) {
		ni_timer_rearm(handle->timer, handle->timeout);
	} else {
		handle->timer = ni_timer_register(handle->timeout,
				__do_arp_validate_timeout, handle);
	}
}

static ni_bool_t
__do_arp_validate_send(struct arp_handle *handle)
{
	struct in_addr null = { 0 };
	ni_bool_t ret = FALSE;

	if (!handle->hwaddr.len && handle->nprobes) {
		ni_debug_application("%s: arp validate: probing for %s",
				handle->ifname,
				ni_sockaddr_print(&handle->ipaddr));

		handle->nprobes--;
		handle->replies = TRUE;
		if ((ret = ni_arp_send_request(handle->sock, null,
				handle->ipaddr.sin.sin_addr) > 0)) {
			__do_arp_validate_arm_timer(handle);
		}
	} else
	if (!handle->hwaddr.len && handle->nclaims) {
		ni_debug_application("%s: arp validate: claiming %s use",
				handle->ifname,
				ni_sockaddr_print(&handle->ipaddr));

		handle->nclaims--;
		handle->replies = FALSE;
		if ((ret = ni_arp_send_grat_request(handle->sock,
				handle->ipaddr.sin.sin_addr) > 0)) {
			if (handle->nclaims) {
				__do_arp_validate_arm_timer(handle);
			} else if (handle->sock) {
				__do_arp_handle_close(handle);
			}
		}
	}
	return ret;
}

static int
__do_arp_validate_init(struct arp_handle *handle, ni_capture_devinfo_t *dev_info)
{
	ni_netconfig_t *nc;
	ni_netdev_t *dev;

	if (ni_server_listen_interface_events(NULL) < 0) {
		ni_error("unable to initialize netlink link listener");
		return NI_LSB_RC_ERROR;
	}
	if (ni_server_enable_interface_addr_events(NULL) < 0) {
		ni_error("unable to initialize netlink addr listener");
		return NI_LSB_RC_ERROR;
	}

	if (!(nc = ni_global_state_handle(1))) {
		ni_error("Cannot refresh interface list!");
		return NI_LSB_RC_ERROR;
	}

	if (!(dev = ni_netdev_by_name(nc, handle->ifname))) {
		ni_error("Cannot find interface with name '%s'",
				handle->ifname);
		return NI_LSB_RC_ERROR;
	}
	if (!ni_netdev_supports_arp(dev)) {
		ni_error("%s: arp is not supported/enabled", dev->name);
		return NI_LSB_RC_ERROR;
	}
	if (!ni_netdev_link_is_up(dev)) {
		ni_error("%s: link is not up", dev->name);
		return NI_LSB_RC_ERROR;
	}

	if (ni_capture_devinfo_init(dev_info, dev->name, &dev->link) < 0) {
		ni_error("%s: cannot initialize capture", dev->name);
		return NI_LSB_RC_ERROR;
	}

	return 0;
}

static int
__do_arp_validate(struct arp_handle *handle)
{
	ni_capture_devinfo_t dev_info;
	int ret;

	if ((ret = __do_arp_validate_init(handle, &dev_info)) != 0)
		return ret;

	handle->sock = ni_arp_socket_open(&dev_info,
			__do_arp_validate_process, handle);
	if (!handle->sock || !handle->sock->user_data) {
		ni_error("%s: Cannot initialize arp socket", handle->ifname);
		__do_arp_handle_close(handle);
		return NI_LSB_RC_ERROR;
	}

	if (!__do_arp_validate_send(handle)) {
		__do_arp_handle_close(handle);
		ni_error("%s: Cannot send arp packet", handle->ifname);
		return NI_LSB_RC_ERROR;
	}

	ret = NI_WICKED_RC_ERROR;
	while (!ni_caught_terminal_signal()) {
		long timeout;

		ret = NI_LSB_RC_SUCCESS;
		timeout = ni_timer_next_timeout();
		if (ni_socket_wait(timeout) != 0)
			break;
		ret = NI_WICKED_RC_ERROR;
	}
	if (handle->timer) {
		ni_timer_cancel(handle->timer);
		handle->timer = NULL;
	}
	__do_arp_handle_close(handle);

	return handle->hwaddr.len ? NI_LSB_RC_NOT_ALLOWED : ret;
}

int
ni_do_arp(const char *caller, int argc, char **argv)
{
	static struct option      options[] = {
		{ "help",         no_argument,       NULL, OPT_HELP        },
		{ "quiet",        no_argument,       NULL, OPT_QUIET       },
		{ "verbose",      no_argument,       NULL, OPT_VERBOSE     },

		{ "verify",       required_argument, NULL, OPT_VERIFY      },
		{ "notify",       required_argument, NULL, OPT_NOTIFY      },
		{ "interval",     required_argument, NULL, OPT_TIMEOUT     },

		{ NULL,           no_argument,       NULL, 0               }
	};
	int               c, status = NI_WICKED_RC_USAGE;
	unsigned int      opt_verbose = OPT_VERBOSE;
	unsigned int      opt_nprobes;
	unsigned int      opt_nclaims;
	struct arp_handle handle;

	memset(&handle, 0, sizeof(handle));
	handle.nprobes = opt_nprobes = 3;
	handle.nclaims = opt_nclaims = 0;
	handle.timeout = 200;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", options, NULL)) != EOF) {
		switch (c) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
		default:
		usage:
			fprintf(stderr,
				"wicked %s [options ...] <ifname> <IP address>\n"
				"\n"
				"Supported options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --quiet\n"
				"      Return exit status only\n"
				"  --verbose\n"
				"      Show a result info (default)\n"
				"\n"
				"  --verify <count>\n"
				"      Verify IP for duplicates on the network (DAD);\n"
				"      Returns 4, when duplicate IP address exists.\n"
				"  --notify <count>\n"
				"      Notify about IP address use (gratuitous ARP)\n"
				"  --interval <msec>\n"
				"      Packet sending interval in msec\n"
				, argv[0]
			);
			goto cleanup;

		case OPT_QUIET:
		case OPT_VERBOSE:
			opt_verbose = c;
			break;

		case OPT_VERIFY:
			if (ni_parse_uint(optarg, &opt_nprobes, 10)) {
				ni_error("%s: Cannot parse verify count '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			handle.nprobes = opt_nprobes;
			break;

		case OPT_NOTIFY:
			if (ni_parse_uint(optarg, &opt_nclaims, 10)) {
				ni_error("%s: Cannot parse notify count '%s'",
						argv[0], optarg);
				goto cleanup;
			}
			handle.nclaims = opt_nclaims;
			break;

		case OPT_TIMEOUT:
			if (ni_parse_uint(optarg, &handle.timeout, 10)) {
				ni_error("%s %s: Cannot parse interval '%s'",
						argv[0], argv[1], optarg);
				goto cleanup;
			}
			break;
		}
	}

	if (optind + 2 != argc)
		goto usage;

	if (!handle.nprobes && !handle.nclaims) {
		ni_error("%s: nothing to send", argv[0]);
		goto cleanup;
	}

	handle.ifname = argv[optind++];
	if (ni_string_empty(handle.ifname))
		goto cleanup;

	if (ni_sockaddr_parse(&handle.ipaddr, argv[optind], AF_INET) != 0) {
		ni_error("%s: cannot parse '%s' as IPv4 address",
			argv[0], argv[optind]);
		goto cleanup;
	}

	status = __do_arp_validate(&handle);
	if (opt_verbose) {
		if (handle.hwaddr.len) {
			printf("%s: IP address %s is in use by %s\n",
					handle.ifname,
					ni_sockaddr_print(&handle.ipaddr),
					ni_link_address_print(&handle.hwaddr));
		} else {
			if (opt_nprobes) {
				printf("%s: No duplicates for IP address %s detected\n",
					handle.ifname,
					ni_sockaddr_print(&handle.ipaddr));
			}
			if (opt_nclaims) {
				printf("%s: Notified neighbours about IP address %s\n",
					handle.ifname,
					ni_sockaddr_print(&handle.ipaddr));
			}
		}
	}

cleanup:
	return status;
}

