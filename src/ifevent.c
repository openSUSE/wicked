/*
 * Discover changes to network interfaces by listening to
 * netlink messages.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netlink/msg.h>

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/socket.h>
#include <wicked/ipv6.h>

#include "netinfo_priv.h"
#include "socket_priv.h"
#include "ipv6_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "appconfig.h"

/*
 * TODO: Move the socket somewhere else & add cleanup...
 */
static ni_socket_t *	__ni_rtevent_sock;

static int	__ni_rtevent_process(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_newlink(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_dellink(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_newprefix(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_newaddr(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_deladdr(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);

static const char *	__ni_rtevent_msg_name(unsigned int);


/*
 * Helper to trigger interface events
 */
void
__ni_netdev_event(ni_netconfig_t *nc, ni_netdev_t *dev, ni_event_t ev)
{
	ni_debug_events("%s(%s, idx=%d, %s)", __FUNCTION__,
			dev->name, dev->link.ifindex, ni_event_type_to_name(ev));
	if (ni_global.interface_event)
		ni_global.interface_event(dev, ev);
}

static inline void
__ni_netdev_addr_event(ni_netdev_t *dev, ni_event_t ev, const ni_address_t *ap)
{
	if (ni_global.interface_addr_event)
		ni_global.interface_addr_event(dev, ev, ap);
}

static inline void
__ni_netdev_prefix_event(ni_netdev_t *dev, ni_event_t ev, const ni_ipv6_ra_pinfo_t *pi)
{
	if (ni_global.interface_prefix_event)
		ni_global.interface_prefix_event(dev, ev, pi);
}

/*
 * Process netlink events
 */
int
__ni_rtevent_process(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	const char *rtnl_name;
	int rv;

	if ((rtnl_name = __ni_rtevent_msg_name(h->nlmsg_type)) != NULL)
		ni_debug_events("received %s event", rtnl_name);
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

	case RTM_NEWADDR:
		rv = __ni_rtevent_newaddr(nc, nladdr, h);
		break;

	case RTM_DELADDR:
		rv = __ni_rtevent_deladdr(nc, nladdr, h);
		break;

	default:
		rv = 0;
	}

	return rv;
}

/*
 * Process NEWLINK event
 */
int
__ni_rtevent_newlink(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	ni_netdev_t *dev, *old;
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
		dev = old;
	} else {
		dev = ni_netdev_new(ifname, ifi->ifi_index);
		if (dev)
			ni_netconfig_device_append(nc, dev);
	}
	if (__ni_netdev_process_newlink(dev, h, ifi, nc) < 0) {
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
		static struct flag_transition {
			unsigned int	flag;
			unsigned int	event_up;
			unsigned int	event_down;
		} *edge, flag_transitions[] = {
			{ NI_IFF_DEVICE_UP,	NI_EVENT_DEVICE_UP,	NI_EVENT_DEVICE_DOWN	},
			{ NI_IFF_LINK_UP,	NI_EVENT_LINK_UP,	NI_EVENT_LINK_DOWN	},
			{ NI_IFF_NETWORK_UP,	NI_EVENT_NETWORK_UP,	NI_EVENT_NETWORK_DOWN	},
			{ 0 }
		};
		unsigned int i, new_flags, flags_changed;

		/* If the interface name changed, update it */
		if (ifname && strcmp(ifname, dev->name))
			ni_string_dup(&dev->name, ifname);

		new_flags = dev->link.ifflags;
		flags_changed = old_flags ^ new_flags;

		for (i = 0, edge = flag_transitions; edge->flag; ++i, ++edge) {
			if ((flags_changed & edge->flag) == 0)
				continue;
			if (new_flags & edge->flag) {
				__ni_netdev_event(nc, dev, edge->event_up);
			} else {
				if (dev->ipv6)
					ni_ipv6_ra_info_flush(&dev->ipv6->radv);
				__ni_netdev_event(nc, dev, edge->event_down);
			}
		}
	} else {
		__ni_netdev_event(nc, dev, NI_EVENT_DEVICE_CREATE);
	}

	if ((nla = nlmsg_find_attr(h, sizeof(*ifi), IFLA_WIRELESS)) != NULL)
		__ni_wireless_link_event(nc, dev, nla_data(nla), nla_len(nla));

	return 0;
}

/*
 * Process DELLINK event
 */
int
__ni_rtevent_dellink(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	ni_netdev_t *dev;

	if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_DELLINK)))
		return -1;

	if (ifi->ifi_family == AF_BRIDGE) {
		ni_debug_events("Ignoring bridge DELLINK event");
		return 0;
	}

	/* Open code interface removal. */
	if ((dev = ni_netdev_by_index(nc, ifi->ifi_index)) == NULL) {
		ni_error("bad RTM_DELLINK message for unknown interface index %d", ifi->ifi_index);
		return -1;
	} else {
		dev->link.ifflags = __ni_netdev_translate_ifflags(ifi->ifi_flags);

		__ni_netdev_event(nc, dev, NI_EVENT_DEVICE_DELETE);

		ni_netconfig_device_remove(nc, dev);
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
	ni_ipv6_devinfo_t *ipv6;
	ni_ipv6_ra_pinfo_t *pi, *old = NULL;
	ni_netdev_t *dev;

	if (!(pfx = ni_rtnl_prefixmsg(h, RTM_NEWPREFIX)))
		return -1;

	dev = ni_netdev_by_index(nc, pfx->prefix_ifindex);
	if (dev == NULL)
		return 0;

	ipv6 = ni_netdev_get_ipv6(dev);
	/*
	 * When this is the first time the link were set up,
	 * the ra managed/other config flags aren't set until
	 * the first ra (and prefix) arrive, so reread them.
	 */
	if (ipv6->radv.pinfo == NULL)
		__ni_device_refresh_ipv6_link_info(nc, dev);

	pi = xcalloc(1, sizeof(*pi));
	if (__ni_rtnl_parse_newprefix(dev->name, h, pfx, pi) < 0) {
		free(pi);
		return -1;
	}

	ni_debug_events("%s: RA<%s>, Prefix<%s/%u %s %s>[%u, %u]", dev->name,
			(ipv6->radv.managed_addr ? "managed-address" :
			(ipv6->radv.other_config ? "other-config" : "unmanaged")),
			ni_sockaddr_print(&pi->prefix), pi->length,
			(pi->on_link ? "onlink," : "not-onlink,"),
			(pi->autoconf ? "autoconf" : "no-autoconf"),
			pi->lifetime.preferred_lft, pi->lifetime.valid_lft);

	if ((old = ni_ipv6_ra_pinfo_list_remove(&ipv6->radv.pinfo, pi)) != NULL) {
		if (pi->lifetime.valid_lft > 0) {
			/* Replace with updated prefix info - most recent in front */
			ni_ipv6_ra_pinfo_list_prepend(&ipv6->radv.pinfo, pi);
			__ni_netdev_prefix_event(dev, NI_EVENT_PREFIX_UPDATE, pi);
		} else {
			/* A lifetime of 0 means the router requests a prefix remove;
			 * at least 3.0.x kernel set valid lft to 0 and keep pref. */
			free(pi);
			__ni_netdev_prefix_event(dev, NI_EVENT_PREFIX_DELETE, old);
		}
		free(old);
	} else if (pi->lifetime.valid_lft > 0) {
		/* Add prefix info - most recent in front */
		ni_ipv6_ra_pinfo_list_prepend(&ipv6->radv.pinfo, pi);
		__ni_netdev_prefix_event(dev, NI_EVENT_PREFIX_UPDATE, pi);
	} else {
		/* Request to remove unhandled prefix (missed event?), ignore it. */
		free(pi);
	}

	/* FIXME: __ni_netdev_add_autoconf_prefix fakes routes, so it is better
	 *        to subscribe to routes and then compare & mark when the route
	 *        is added/deleted by the kernel => TODO.
	 */
	if (__ni_netdev_process_newprefix(dev, h, pfx) < 0) {
		ni_error("Problem parsing RTM_NEWPREFIX message for %s", dev->name);
		/* return -1; */
	}
	return 0;
}

static int
__ni_rtevent_newaddr(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	struct ifaddrmsg *ifa;
	const ni_address_t *ap = NULL;
	ni_netdev_t *dev;

	if (!(ifa = ni_rtnl_ifaddrmsg(h, RTM_NEWADDR)))
		return -1;

	dev = ni_netdev_by_index(nc, ifa->ifa_index);
	if (dev == NULL)
		return 0;

	/*
	 * Here we just get a const pointer (=what we need)
	 * to the address stored in the list...
	 */
	if (__ni_netdev_process_newaddr_event(dev, h, ifa, &ap) < 0)
		return -1;

	__ni_netdev_addr_event(dev, NI_EVENT_ADDRESS_UPDATE, ap);
	return 0;
}

static int
__ni_rtevent_deladdr(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	struct ifaddrmsg *ifa;
	ni_address_t tmp, *ap;
	ni_netdev_t *dev;

	if (!(ifa = ni_rtnl_ifaddrmsg(h, RTM_DELADDR)))
		return -1;

	dev = ni_netdev_by_index(nc, ifa->ifa_index);
	if (dev == NULL)
		return 0;

	if (__ni_rtnl_parse_newaddr(dev->link.ifflags, h, ifa, &tmp) < 0) {
		ni_error("Problem parsing RTM_DELADDR message for %s", dev->name);
		return -1;
	}

	if ((ap = ni_address_list_find(dev->addrs, &tmp.local_addr)) != NULL) {
		__ni_netdev_addr_event(dev, NI_EVENT_ADDRESS_DELETE, ap);

		__ni_address_list_remove(&dev->addrs, ap);
	}

	return 0;
}

/*
 * Receive events from netlink socket and generate events.
 */
static int
__ni_rtevent_process_cb(struct nl_msg *msg, void *ptr)
{
	const struct sockaddr_nl *sender = nlmsg_get_src(msg);
	struct nlmsghdr *nlh;
	ni_netconfig_t *nc;

	if ((nc = ni_global_state_handle(0)) == NULL)
		return NL_SKIP;

	if (sender->nl_pid != 0) {
		ni_error("ignoring rtnetlink event message from PID %u",
			sender->nl_pid);
		return NL_SKIP;
	}

	nlh = nlmsg_hdr(msg);
	if (__ni_rtevent_process(nc, sender, nlh) < 0) {
		ni_debug_events("ignoring %s rtnetlink event",
			__ni_rtevent_msg_name(nlh->nlmsg_type));
		return NL_SKIP;
	}

	return NL_OK;
}

/*
 * Helper returning name of a rtnetlink message
 */
static const char *
__ni_rtevent_msg_name(unsigned int nlmsg_type)
{
#define _t2n(x)	[x] = #x
	static const char *rtnl_name[RTM_MAX] = {
	_t2n(RTM_NEWLINK),	_t2n(RTM_DELLINK),
	_t2n(RTM_NEWADDR),	_t2n(RTM_DELADDR),
	_t2n(RTM_NEWROUTE),	_t2n(RTM_DELROUTE),
	_t2n(RTM_NEWPREFIX),
	};
#undef _t2n

	if (nlmsg_type < RTM_MAX && rtnl_name[nlmsg_type])
		return rtnl_name[nlmsg_type];
	else
		return NULL;
}


/*
 * Receive netlink message and trigger processing by callback
 */
static void
__ni_rtevent_receive(ni_socket_t *sock)
{
	struct nl_handle *handle = sock->user_data;
	int status;

	status = nl_recvmsgs_default(handle);
	if (status != 0) {
		ni_error("netlink receive error: %m");
		ni_error("shutting down event listener");
		ni_socket_close(sock);
	}
}

/*
 * Cleanup netlink handle inside of a socket.
 */
static void
__ni_rtevent_close(ni_socket_t *sock)
{
	struct nl_handle *handle = sock->user_data;

	if (handle) {
		nl_handle_destroy(handle);
		sock->user_data = NULL;
	}
}


/*
 * Embed rtnetlink socket into ni_socket_t and set ifevent handler
 */
int
ni_server_listen_interface_events(void (*ifevent_handler)(ni_netdev_t *, ni_event_t))
{
	struct nl_handle *handle;
	ni_socket_t *sock;
	uint32_t groups = 0;
	int fd;

	if (__ni_rtevent_sock || ni_global.interface_event) {
		ni_error("Interface event handler is already set");
		return -1;
	}

	if ((handle = nl_handle_alloc()) == NULL) {
		ni_error("Cannot allocate rtnetlink event handle: %m");
		return -1;
	}

#define nl_mgrp(x)	(1 << ((x) - 1))
	groups = nl_mgrp(RTNLGRP_LINK) |
		 nl_mgrp(RTNLGRP_IPV6_IFINFO) |
		 nl_mgrp(RTNLGRP_IPV6_PREFIX);

	nl_join_groups(handle, groups);
#undef nl_mgrp

	/*
	 * Modify the callback for processing valid messages...
	 * We may pass some kind of data (event filter?) too...
	 */
	nl_socket_modify_cb(handle, NL_CB_VALID, NL_CB_CUSTOM,
				__ni_rtevent_process_cb, NULL);

	/* Required to receive async event notifications */
	nl_disable_sequence_check(handle);

	if (nl_connect(handle, NETLINK_ROUTE) < 0) {
		ni_error("Cannot open rtnetlink: %m");
		nl_handle_destroy(handle);
		return -1;
	}

	/* Enable non-blocking processing */
	nl_socket_set_nonblocking(handle);

	fd = nl_socket_get_fd(handle);
	if ((sock = ni_socket_wrap(fd, SOCK_DGRAM)) == NULL) {
		ni_error("Cannot wrap rtnetlink event socket: %m");
		nl_handle_destroy(handle);
		return -1;
	}

	sock->user_data	= handle;
	sock->receive	= __ni_rtevent_receive;
	sock->close	= __ni_rtevent_close;

	__ni_rtevent_sock         = sock;
	ni_global.interface_event = ifevent_handler;

	ni_socket_activate(__ni_rtevent_sock);

	return 0;
}

int
ni_server_enable_interface_addr_events(void (*ifaddr_handler)(ni_netdev_t *, ni_event_t, const ni_address_t *))
{
	struct nl_handle *handle;

	if (!__ni_rtevent_sock || ni_global.interface_addr_event) {
		ni_error("Interface address event handler already set");
		return -1;
	}

	handle = __ni_rtevent_sock->user_data;

	if (nl_socket_add_membership(handle, RTNLGRP_IPV4_IFADDR) < 0 ||
	    nl_socket_add_membership(handle, RTNLGRP_IPV6_IFADDR) < 0) {
		ni_error("Cannot add rtnetlink address event membership: %m");
		return -1;
	}

	ni_global.interface_addr_event = ifaddr_handler;
	return 0;
}

int
ni_server_enable_interface_prefix_events(void (*ifprefix_handler)(ni_netdev_t *, ni_event_t, const ni_ipv6_ra_pinfo_t *))
{
	if (!__ni_rtevent_sock || ni_global.interface_prefix_event) {
		ni_error("Interface prefix event handler already set");
		return -1;
	}

	/* We always subscribe to rtnl prefix group, just a question
	 * whether the app wants to receive update events or not... */

	ni_global.interface_prefix_event = ifprefix_handler;
	return 0;
}

void
ni_server_deactivate_interface_events(void)
{
	if (__ni_rtevent_sock) {
		ni_socket_deactivate(__ni_rtevent_sock);

		ni_global.interface_event = NULL;
		ni_global.interface_addr_event = NULL;
		ni_global.interface_prefix_event = NULL;
		ni_socket_release(__ni_rtevent_sock);
		__ni_rtevent_sock = NULL;
	}
}

