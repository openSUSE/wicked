/*
 * Discover changes to network interfaces by listening to
 * netlink messages.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/socket.h>

#include "netinfo_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "config.h"

static int	__ni_rtevent_process(ni_handle_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_newlink(ni_handle_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_dellink(ni_handle_t *, const struct sockaddr_nl *, struct nlmsghdr *);

/*
 * Receive events from netlink socket and generate events.
 */
void
__ni_rtevent_read(ni_socket_t *sock)
{
	ni_handle_t *nih = sock->user_data;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[8192];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	iov.iov_base = buf;
	while (1) {
		iov.iov_len = sizeof(buf);
		int status;

		status = recvmsg(sock->__fd, &msg, 0);
		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				return;

			ni_error("netlink receive error: %m");
			ni_error("shutting down event listener");
			ni_socket_close(sock);
			return;
		}

		if (status == 0) {
			ni_warn("EOF on netlink");
			return;
		}

		if (msg.msg_namelen != sizeof(nladdr)) {
			ni_warn("sender address length == %u", msg.msg_namelen);
			continue;
		}

		for (h = (struct nlmsghdr *) buf; NLMSG_OK(h, status); h = NLMSG_NEXT(h, status)) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					ni_warn("truncated netlink message");
					continue;
				}
				ni_fatal("malformed netlink message: len=%d", len);
			}

			if (__ni_rtevent_process(nih, &nladdr, h) < 0)
				continue;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			ni_warn("truncated netlink message");
			continue;
		}
		if (status)
			ni_fatal("malformed netlink message: remnant of %d bytes", status);
	}
}

static void
__ni_interface_event(ni_handle_t *nih, ni_interface_t *ifp, ni_event_t ev)
{
	unsigned int mode;

	if (ni_global.interface_event)
		ni_global.interface_event(nih, ifp, ev);

	ni_debug_dhcp("%s(%s, %s)", __FUNCTION__, ifp->name, ni_event_type_to_name(ev));
	for (mode = 0; mode < __NI_ADDRCONF_MAX; ++mode) {
		ni_addrconf_t *acm4 = NULL, *acm6;

		if (ni_afinfo_addrconf_test(&ifp->ipv4, mode)
		 && (acm4 = ni_addrconf_get(mode, AF_INET)) != NULL
		 && acm4->interface_event)
			acm4->interface_event(acm4, ifp, ev);

		if (ni_afinfo_addrconf_test(&ifp->ipv6, mode)
		 && (acm6 = ni_addrconf_get(mode, AF_INET6)) != NULL
		 && acm6 != acm4 && acm6->interface_event)
			acm6->interface_event(acm6, ifp, ev);
	}
}

int
__ni_rtevent_process(ni_handle_t *nih, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
#define _(x)	[x] = #x
	static const char *rtnl_name[RTM_MAX] = {
	_(RTM_NEWLINK), _(RTM_DELLINK),
	_(RTM_NEWADDR), _(RTM_DELADDR),
	_(RTM_NEWROUTE), _(RTM_DELROUTE),
	_(RTM_NEWPREFIX),
	};
	int rv;

	if (h->nlmsg_type >= RTM_MAX)
		return -1;
	if (rtnl_name[h->nlmsg_type])
		ni_debug_events("received %s event", rtnl_name[h->nlmsg_type]);
	else
		ni_debug_events("received rtnetlink event %u", h->nlmsg_type);

	switch (h->nlmsg_type) {
	case RTM_NEWLINK:
		rv = __ni_rtevent_newlink(nih, nladdr, h);;
		break;

	case RTM_DELLINK:
		rv = __ni_rtevent_dellink(nih, nladdr, h);;
		break;

	/* RTM_NEWPREFIX is really the only way for us to find out whether a
	 * route prefix was configured statically, or received via a Router
	 * Advertisement */

	default:
		rv = 0;
	}

	return rv;
}

int
__ni_rtevent_newlink(ni_handle_t *nih, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	ni_interface_t *ifp, *old;
	struct ifinfomsg *ifi;
	struct rtattr *rta;
	char *ifname = NULL;

	if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_NEWLINK)))
		return -1;

	if ((rta = __ni_rta_find(IFLA_RTA(ifi), IFLA_PAYLOAD(h), IFLA_IFNAME)) == NULL) {
		warn("RTM_xxxLINK message without IFNAME");
		return -1;
	}
	ifname = (char *) RTA_DATA(rta);

	ifp = __ni_interface_new(ifname, ifi->ifi_index);
	if (__ni_interface_process_newlink(ifp, h, ifi, nih) < 0) {
		error("Problem parsing RTM_NEWLINK message for %s", ifname);
		return -1;
	}

	old = ni_interface_by_name(nih, ifname);
	if (old && old->ifindex != ifi->ifi_index) {
		/* We probably missed a deletion event. Just clobber the old interface. */
		warn("linkchange event: found interface %s with different ifindex", ifname);
		old->ifindex = ifi->ifi_index;
	}

	old = ni_interface_by_index(nih, ifi->ifi_index);
	if (old) {
		unsigned int flags_changed;

		/* If the interface name changed, update it */
		if (strcmp(ifname, old->name))
			strncpy(old->name, ifname, sizeof(old->name) - 1);

		flags_changed = old->flags ^ ifi->ifi_flags;
		old->flags = ifi->ifi_flags;

		/* Discard interface created by parsing new newlink event. */
		ni_interface_put(ifp);

		if (flags_changed & IFF_LOWER_UP) {
			if (ifi->ifi_flags & IFF_LOWER_UP)
				__ni_interface_event(nih, old, NI_EVENT_LINK_UP);
			else
				__ni_interface_event(nih, old, NI_EVENT_LINK_DOWN);
		}
		if (flags_changed & IFF_UP) {
			if (ifi->ifi_flags & IFF_UP)
				__ni_interface_event(nih, old, NI_EVENT_NETWORK_UP);
			else
				__ni_interface_event(nih, old, NI_EVENT_NETWORK_DOWN);
		}
	} else {
		ni_interface_t **pos;

		/* Add new interface to our list of devices */
		for (pos = &nih->iflist; *pos; pos = &(*pos)->next)
			;
		*pos = ifp;

		ifp->flags = ifi->ifi_flags;
		__ni_interface_event(nih, ifp, NI_EVENT_LINK_CREATE);
	}


	return 0;
}

/*
 * Process DELLINK event
 */
int
__ni_rtevent_dellink(ni_handle_t *nih, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	ni_interface_t *ifp, **pos;
	struct ifinfomsg *ifi;

	if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_DELLINK)))
		return -1;

	/* Open code interface removal. */
	for (pos = &nih->iflist; (ifp = *pos) != NULL; pos = &ifp->next) {
		if (ifp->ifindex == ifi->ifi_index) {
			*pos = ifp->next;
			ifp->ifindex = 0;
			ni_interface_put(ifp);
			break;
		}
	}

	return 0;
}

#define nl_mgrp(x)	(1 << ((x) - 1))

int
ni_server_listen_events(void (*ifevent_handler)(ni_handle_t *, ni_interface_t *, ni_event_t))
{
	struct rtnl_handle rth;
	ni_socket_t *sock;
	uint32_t groups;

	groups = nl_mgrp(RTNLGRP_LINK) |
		 nl_mgrp(RTNLGRP_IPV4_IFADDR) |
		 nl_mgrp(RTNLGRP_IPV6_IFADDR) |
		 nl_mgrp(RTNLGRP_IPV4_ROUTE) |
		 nl_mgrp(RTNLGRP_IPV6_ROUTE) |
		 nl_mgrp(RTNLGRP_IPV6_PREFIX);
	if (rtnl_open(&rth, groups) < 0) {
		error("Cannot open rtnetlink: %m");
		return -1;
	}

	fcntl(rth.fd, F_SETFL, O_NONBLOCK);

	sock = ni_socket_wrap(rth.fd, SOCK_DGRAM);
	sock->user_data = ni_global_state_handle();
	sock->data_ready = __ni_rtevent_read;
	ni_socket_activate(sock);

	ni_global.interface_event = ifevent_handler;
	return 0;
}

int
ni_rtevent_fd(ni_handle_t *nih)
{
	return nih->rth.fd;
}

