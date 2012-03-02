/*
 * Discover changes to network interfaces by listening to
 * netlink messages.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netlink/msg.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/socket.h>

#include "netinfo_priv.h"
#include "socket_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "config.h"

static int	__ni_rtevent_process(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_newlink(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_dellink(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_newprefix(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);

/*
 * Receive events from netlink socket and generate events.
 */
void
__ni_rtevent_read(ni_socket_t *sock)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	//struct nl_handle *handle = sock->user_data;
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

			if (__ni_rtevent_process(nc, &nladdr, h) < 0)
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

void
__ni_netdev_event(ni_netconfig_t *nc, ni_netdev_t *ifp, ni_event_t ev)
{
	ni_debug_dhcp("%s(%s, idx=%d, %s)", __FUNCTION__,
			ifp->name, ifp->link.ifindex, ni_event_type_to_name(ev));
	if (ni_global.interface_event)
		ni_global.interface_event(nc, ifp, ev);
}

int
__ni_rtevent_process(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
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
		rv = __ni_rtevent_newlink(nc, nladdr, h);
		break;

	case RTM_DELLINK:
		rv = __ni_rtevent_dellink(nc, nladdr, h);
		break;

	/* RTM_NEWPREFIX is really the only way for us to find out whether a
	 * route prefix was configured statically, or received via a Router
	 * Advertisement */
	case RTM_NEWPREFIX:
		rv = __ni_rtevent_newprefix(nc, nladdr, h);
		break;

	default:
		rv = 0;
	}

	return rv;
}

int
__ni_rtevent_newlink(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	ni_netdev_t *ifp, *old;
	struct ifinfomsg *ifi;
	struct nlattr *nla;
	char *ifname = NULL;
	int old_flags = -1;

	if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_NEWLINK)))
		return -1;

	if (ifi->ifi_family == AF_BRIDGE) {
		ni_debug_events("Ignoring bridge NEWLINK event");
		return 0;
	}

	if ((nla = nlmsg_find_attr(h, sizeof(*ifi), IFLA_IFNAME)) != NULL) {
		ifname = (char *) nla_data(nla);
	}

	old = ni_netdev_by_index(nc, ifi->ifi_index);
	if (old != NULL) {
		old_flags = old->link.ifflags;
		ifp = old;
	} else {
		ifp = ni_netdev_new(nc, ifname, ifi->ifi_index);
	}
	if (__ni_netdev_process_newlink(ifp, h, ifi, nc) < 0) {
		ni_error("Problem parsing RTM_NEWLINK message for %s", ifname);
		return -1;
	}

	if (ifname) {
		ni_netdev_t *conflict;

		conflict = ni_netdev_by_name(nc, ifname);
		if (conflict && conflict->link.ifindex != ifi->ifi_index) {
			/* We probably missed a deletion event. Just clobber the old interface. */
			ni_warn("linkchange event: found interface %s with different ifindex", ifname);

			/* We should purge this either now or on the next refresh */
			ni_string_dup(&conflict->name, "dead");
		}
	}

	if (old) {
		unsigned int new_flags, flags_changed;

		/* If the interface name changed, update it */
		if (ifname && strcmp(ifname, ifp->name))
			ni_string_dup(&ifp->name, ifname);

		new_flags = ifp->link.ifflags;
		flags_changed = old_flags ^ new_flags;

		if (flags_changed & NI_IFF_LINK_UP) {
			if (new_flags & NI_IFF_LINK_UP)
				__ni_netdev_event(nc, ifp, NI_EVENT_LINK_UP);
			else
				__ni_netdev_event(nc, ifp, NI_EVENT_LINK_DOWN);
		}
		if (flags_changed & NI_IFF_NETWORK_UP) {
			if (new_flags & NI_IFF_NETWORK_UP)
				__ni_netdev_event(nc, ifp, NI_EVENT_NETWORK_UP);
			else
				__ni_netdev_event(nc, ifp, NI_EVENT_NETWORK_DOWN);
		}
	} else {
		__ni_netdev_event(nc, ifp, NI_EVENT_LINK_CREATE);
	}

	if ((nla = nlmsg_find_attr(h, sizeof(*ifi), IFLA_WIRELESS)) != NULL)
		__ni_wireless_link_event(nc, ifp, nla_data(nla), nla_len(nla));

	return 0;
}

/*
 * Process DELLINK event
 */
int
__ni_rtevent_dellink(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	ni_netdev_t *ifp, **pos;
	struct ifinfomsg *ifi;

	if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_DELLINK)))
		return -1;

	if (ifi->ifi_family == AF_BRIDGE) {
		ni_debug_events("Ignoring bridge DELLINK event");
		return 0;
	}

	/* Open code interface removal. */
	for (pos = &nc->interfaces; (ifp = *pos) != NULL; pos = &ifp->next) {
		if (ifp->link.ifindex == ifi->ifi_index) {
			*pos = ifp->next;
			ifp->next = NULL;
			ifp->link.ifindex = 0;
			ifp->link.ifflags = __ni_netdev_translate_ifflags(ifi->ifi_flags);

			__ni_netdev_event(nc, ifp, NI_EVENT_LINK_DELETE);
			ni_netdev_put(ifp);
			break;
		}
	}

	return 0;
}

/*
 * Process NEWPREFIX event. This essentially maps 1:1 to IPv6 router advertisements received
 * by the kernel.
 */
int
__ni_rtevent_newprefix(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	struct prefixmsg *pfx;
	ni_netdev_t *ifp;

	if (!(pfx = ni_rtnl_prefixmsg(h, RTM_NEWPREFIX)))
		return -1;

	ifp = ni_netdev_by_index(nc, pfx->prefix_ifindex);
	if (ifp == NULL)
		return 0;

	if (__ni_netdev_process_newprefix(ifp, h, pfx) < 0) {
		ni_error("Problem parsing RTM_NEWPREFIX message for %s", ifp->name);
		return -1;
	}
	return 0;
}


#define nl_mgrp(x)	(1 << ((x) - 1))

int
ni_server_listen_events(void (*ifevent_handler)(ni_netconfig_t *, ni_netdev_t *, ni_event_t))
{
	struct nl_handle *handle;
	ni_socket_t *sock;
	uint32_t groups;
	int fd;

	groups = nl_mgrp(RTNLGRP_LINK) |
		 nl_mgrp(RTNLGRP_IPV4_IFADDR) |
		 nl_mgrp(RTNLGRP_IPV6_IFADDR) |
		 nl_mgrp(RTNLGRP_IPV4_ROUTE) |
		 nl_mgrp(RTNLGRP_IPV6_ROUTE) |
		 nl_mgrp(RTNLGRP_IPV6_PREFIX);

	handle = nl_handle_alloc();
	nl_join_groups(handle, groups);

	if (nl_connect(handle, 0) < 0) {
		ni_error("Cannot open rtnetlink: %m");
		nl_handle_destroy(handle);
		return -1;
	}

	fd = nl_socket_get_fd(handle);
	fcntl(fd, F_SETFL, O_NONBLOCK);

	sock = ni_socket_wrap(fd, SOCK_DGRAM);
	sock->user_data = handle;
	sock->receive = __ni_rtevent_read;
	ni_socket_activate(sock);

	ni_global.interface_event = ifevent_handler;
	return 0;
}
