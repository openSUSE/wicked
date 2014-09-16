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
#include <netinet/icmp6.h>

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

/* RFC 5006, RFC 6106 */
#if defined(ND_OPT_RDNSS_INFORMATION)
#define NI_ND_OPT_RDNSS_INFORMATION	ND_OPT_RDNSS_INFORMATION
#else
#define NI_ND_OPT_RDNSS_INFORMATION	25
#endif

struct ni_nd_opt_rdnss_info_p
{
	uint8_t		nd_opt_rdnss_type;
	uint8_t		nd_opt_rdnss_len;
	uint16_t	nd_opt_rdnss_resserved1;
	uint32_t	nd_opt_rdnss_lifetime;
	/* followed by one or more IPv6 addresses */
	struct in6_addr	nd_opt_rdnss_addr[];
};

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
static int	__ni_rtevent_nduseropt(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);

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

static inline void
__ni_netdev_nduseropt_event(ni_netdev_t *dev, ni_event_t ev)
{
	if (ni_global.interface_nduseropt_event)
		ni_global.interface_nduseropt_event(dev, ev);
}

/*
 * Process netlink events
 */
int
__ni_rtevent_process(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	int rv;
#if 0
	const char *rtnl_name;

	if ((rtnl_name = __ni_rtevent_msg_name(h->nlmsg_type)) != NULL)
		ni_debug_events("received %s event", rtnl_name);
	else
		ni_debug_events("received rtnetlink event %u", h->nlmsg_type);
#endif

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

	case RTM_NEWNDUSEROPT:
		rv = __ni_rtevent_nduseropt(nc, nladdr, h);
		break;

	default:
		rv = 0;
	}

	return rv;
}

static inline ni_bool_t
__ni_netdev_still_exists(unsigned int ifindex)
{
	char namebuf[IF_NAMESIZE+1] = {'\0'};
	return if_indextoname(ifindex, namebuf) != NULL;
}

/*
 * Process device state change events
 */
void
__ni_netdev_process_events(ni_netconfig_t *nc, ni_netdev_t *dev, unsigned int old_flags)
{
	static struct flag_transition {
		unsigned int	flag;
		unsigned int	event_up;
		unsigned int	event_down;
	} *edge, flag_transitions[] = {
		{ NI_IFF_DEVICE_READY,	NI_EVENT_DEVICE_READY,	0			},
		{ NI_IFF_DEVICE_UP,	NI_EVENT_DEVICE_UP,	NI_EVENT_DEVICE_DOWN	},
		{ NI_IFF_LINK_UP,	NI_EVENT_LINK_UP,	NI_EVENT_LINK_DOWN	},
		{ NI_IFF_NETWORK_UP,	NI_EVENT_NETWORK_UP,	NI_EVENT_NETWORK_DOWN	},
	};
	size_t flags = sizeof(flag_transitions)/sizeof(flag_transitions[0]);
	unsigned int i, new_flags, flags_changed;
	ni_uint_array_t events = NI_UINT_ARRAY_INIT;

	new_flags = dev->link.ifflags;
	flags_changed = old_flags ^ new_flags;

	if (dev->created) {
		dev->created = 0;
		ni_uint_array_append(&events, NI_EVENT_DEVICE_CREATE);
	}

	/* transition up */
	for (i = 0; i < flags; ++i) {
		edge = &flag_transitions[i];
		if ((flags_changed & edge->flag) == 0)
			continue;
		if (new_flags & edge->flag) {
			ni_uint_array_append(&events, edge->event_up);
		}
	}

	/* transition down */
	for (i = flags; i-- > 0;  ) {
		edge = &flag_transitions[i];
		if ((flags_changed & edge->flag) == 0)
			continue;
		if (old_flags & edge->flag) {
			if (dev->ipv6 && edge->event_down == NI_EVENT_DEVICE_DOWN)
				ni_ipv6_ra_info_flush(&dev->ipv6->radv);

			if (edge->event_down)
				ni_uint_array_append(&events, edge->event_down);
		}
	}

	if (dev->deleted) {
		dev->deleted = 0;
		ni_uint_array_append(&events, NI_EVENT_DEVICE_DELETE);
	} else
	if (events.count == 0) {
		__ni_netdev_event(nc, dev, NI_EVENT_DEVICE_CHANGE);
	}

	for (i = 0; i < events.count; ++i) {
		__ni_netdev_event(nc, dev, events.data[i]);
	}
	ni_uint_array_destroy(&events);
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
	int old_flags = 0;

	if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_NEWLINK)))
		return -1;

	if ((nla = nlmsg_find_attr(h, sizeof(*ifi), IFLA_IFNAME)) != NULL) {
		ifname = (char *) nla_data(nla);
	}
	if (ifi->ifi_family == AF_BRIDGE) {
		ni_debug_events("%s: ignoring bridge NEWLINK event", ifname);
		return 0;
	}

	old = ni_netdev_by_index(nc, ifi->ifi_index);
	if (!__ni_netdev_still_exists(ifi->ifi_index)) {
		if (old) {
			old_flags = old->link.ifflags;
			old->link.ifflags = 0;
			old->deleted = 1;

			__ni_netdev_process_events(nc, old, old_flags);
			ni_client_state_drop(old->link.ifindex);
			ni_netconfig_device_remove(nc, old);
			return 0;
		}
		return -1;
	}

	if (old != NULL) {
		old_flags = old->link.ifflags;
		dev = old;
	} else {
		dev = ni_netdev_new(ifname, ifi->ifi_index);
		if (dev) {
			dev->created = 1;
			ni_netconfig_device_append(nc, dev);
		}
	}

	if (__ni_netdev_process_newlink(dev, h, ifi, nc) < 0) {
		ni_error("Problem parsing RTM_NEWLINK message for %s", ifname);
		return -1;
	}

	if (ifname) {
		ni_netdev_t *conflict;

		conflict = ni_netdev_by_name(nc, ifname);
		if (conflict && conflict->link.ifindex != (unsigned int)ifi->ifi_index) {
			/* We probably missed a deletion event. Just clobber the old interface. */
			ni_warn("linkchange event: found interface %s with different ifindex", ifname);

			/* We should purge this either now or on the next refresh */
			ni_string_dup(&conflict->name, "dead");
		}

		/* If the interface name changed, update it */
		if (!ni_string_eq(ifname, dev->name))
			ni_string_dup(&dev->name, ifname);
	}

	__ni_netdev_process_events(nc, dev, old_flags);

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
	struct nlattr *nla;
	const char *ifname = NULL;

	if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_DELLINK)))
		return -1;

	if ((nla = nlmsg_find_attr(h, sizeof(*ifi), IFLA_IFNAME)) != NULL) {
		ifname = (char *) nla_data(nla);
	}
	if (ifi->ifi_family == AF_BRIDGE) {
		ni_debug_events("%s: ignoring bridge DELLINK event", ifname);
		return 0;
	}

	/* Open code interface removal. */
	if ((dev = ni_netdev_by_index(nc, ifi->ifi_index)) == NULL) {
		ni_debug_events("RTM_DELLINK message for unknown interface %s index %d",
				ifname, ifi->ifi_index);
		return -1;
	} else {
		unsigned int old_flags = dev->link.ifflags;

		dev->link.ifflags = __ni_netdev_translate_ifflags(ifi->ifi_flags, old_flags);
		dev->deleted = 1;
		__ni_netdev_process_events(nc, dev, old_flags);
		ni_client_state_drop(dev->link.ifindex);
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

	pi = xcalloc(1, sizeof(*pi));
	if (__ni_rtnl_parse_newprefix(dev->name, h, pfx, pi) < 0) {
		free(pi);
		return -1;
	}

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

static int
__ni_rtevent_process_rdnss_info(ni_netdev_t *dev, const struct nd_opt_hdr *opt,
				size_t len)
{
	const struct ni_nd_opt_rdnss_info_p *rdnss;
	const struct in6_addr* addr;
	ni_ipv6_devinfo_t *ipv6;

	if (opt == NULL || len < (sizeof(*rdnss) + sizeof(*addr)))
		return -1;

	rdnss = (const struct ni_nd_opt_rdnss_info_p *)opt;

	ipv6 = ni_netdev_get_ipv6(dev);
	if (ipv6->radv.rdnss == NULL)
		ipv6->radv.rdnss = ni_ipv6_ra_rdnss_new();
	else
		ni_ipv6_ra_rdnss_reset(ipv6->radv.rdnss);

	ipv6->radv.rdnss->lifetime = ntohl(rdnss->nd_opt_rdnss_lifetime);
	len -= sizeof(*rdnss);
	addr = &rdnss->nd_opt_rdnss_addr[0];
	for ( ; len >= sizeof(*addr); len -= sizeof(*addr), ++addr) {
		if (IN6_IS_ADDR_LOOPBACK(addr) || IN6_IS_ADDR_UNSPECIFIED(addr))
			continue;
		ni_ipv6_ra_rdnss_add_server(ipv6->radv.rdnss, addr);
	}
	__ni_netdev_nduseropt_event(dev, NI_EVENT_RDNSS_UPDATE);
	return 0;
}

static int
__ni_rtevent_process_nd_radv_opts(ni_netdev_t *dev, const struct nd_opt_hdr *opt, size_t len)
{
	while (len > 0) {
		size_t opt_len;

		if (len < 2) {
			ni_error("%s: nd user option length too short", dev->name);
			return -1;
		}

		opt_len = (opt->nd_opt_len << 3);
		if (opt_len == 0) {
			ni_error("%s: zero length nd user option", dev->name);
			return -1;
		}
		else if (opt_len > len) {
			ni_error("%s: nd user option length exceeds total length",
				dev->name);
			return -1;
		}

		switch(opt->nd_opt_type) {
		case NI_ND_OPT_RDNSS_INFORMATION:
			if (__ni_rtevent_process_rdnss_info(dev, opt, opt_len) < 0) {
				ni_error("%s: Cannot process RDNSS info option",
					dev->name);
				return -1;
			}
		break;

		default:
			/* kernels up to at least 3.4 do not provide other */
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IPV6|NI_TRACE_EVENTS,
					"%s: unhandled nd user option %d",
					dev->name, opt->nd_opt_type);
		break;
		}

		len -= opt_len;
		opt = (struct nd_opt_hdr *)(((uint8_t *)opt) + opt_len);
	}
	return 0;
}

static int
__ni_rtevent_nduseropt(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	struct nduseroptmsg *msg;
	struct nd_opt_hdr *opt;
	ni_netdev_t *dev;

	if (!(msg = ni_rtnl_nduseroptmsg(h, RTM_NEWNDUSEROPT)))
		return -1;

	dev = ni_netdev_by_index(nc, msg->nduseropt_ifindex);
	if (dev == NULL)
		return 0;

	if (msg->nduseropt_icmp_type != ND_ROUTER_ADVERT ||
	    msg->nduseropt_icmp_code != 0 ||
	    msg->nduseropt_family    != AF_INET6) {
		ni_debug_events("%s: unknown rtnetlink nd user option message"
				" type %d, code %d, family %d", dev->name,
				msg->nduseropt_icmp_type,
				msg->nduseropt_icmp_code,
				msg->nduseropt_family);
		return 0;
	}

	if (!nlmsg_valid_hdr(h, sizeof(struct nduseroptmsg) + msg->nduseropt_opts_len)) {
		ni_debug_events("%s: invalid rtnetlink nd user radv option length %d",
				dev->name, msg->nduseropt_opts_len);
		return -1;
	}

	opt = (struct nd_opt_hdr *)(msg + 1);

	return __ni_rtevent_process_nd_radv_opts(dev, opt, msg->nduseropt_opts_len);
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
	_t2n(RTM_NEWPREFIX),	_t2n(RTM_NEWNDUSEROPT),
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
	struct nl_sock *nl_sock = sock->user_data;
	int status;

	status = nl_recvmsgs_default(nl_sock);
	if (status != 0) {
		ni_error("netlink receive error: %m");
		ni_error("shutting down event listener");
		ni_socket_close(sock);
	}
}

/*
 * Cleanup netlink socket inside of our socket.
 */
static void
__ni_rtevent_close(ni_socket_t *sock)
{
	struct nl_sock *nl_sock = sock->user_data;

	if (nl_sock) {
		nl_socket_free(nl_sock);
		sock->user_data = NULL;
	}
}


/*
 * Embed rtnetlink socket into ni_socket_t and set ifevent handler
 */
int
ni_server_listen_interface_events(void (*ifevent_handler)(ni_netdev_t *, ni_event_t))
{
	struct nl_sock *nl_sock;
	ni_socket_t *sock;
	uint32_t groups = 0;
	int fd;
	unsigned int rsize = 1024*1024; /* required nl_sock receive buf size */

	if (__ni_rtevent_sock || ni_global.interface_event) {
		ni_error("Interface event handler is already set");
		return -1;
	}

	if ((nl_sock = nl_socket_alloc()) == NULL) {
		ni_error("Cannot allocate rtnetlink event socket: %m");
		return -1;
	}

#define nl_mgrp(x)	(1 << ((x) - 1))
	groups = nl_mgrp(RTNLGRP_LINK) |
		 nl_mgrp(RTNLGRP_IPV6_IFINFO) |
		 nl_mgrp(RTNLGRP_IPV6_PREFIX);

	nl_join_groups(nl_sock, groups);
#undef nl_mgrp

	/*
	 * Modify the callback for processing valid messages...
	 * We may pass some kind of data (event filter?) too...
	 */
	nl_socket_modify_cb(nl_sock, NL_CB_VALID, NL_CB_CUSTOM,
				__ni_rtevent_process_cb, NULL);

	/* Required to receive async event notifications */
	nl_socket_disable_seq_check(nl_sock);

	if (nl_connect(nl_sock, NETLINK_ROUTE) < 0) {
		ni_error("Cannot open rtnetlink: %m");
		nl_socket_free(nl_sock);
		return -1;
	}

	/* Enable non-blocking processing */
	nl_socket_set_nonblocking(nl_sock);

	fd = nl_socket_get_fd(nl_sock);
	if ((sock = ni_socket_wrap(fd, SOCK_DGRAM)) == NULL) {
		ni_error("Cannot wrap rtnetlink event socket: %m");
		nl_socket_free(nl_sock);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
			(char *)&rsize, sizeof rsize)) {
		ni_warn("unable to set receive buffer to %u bytes", rsize);
	}

	sock->user_data	= nl_sock;
	sock->receive	= __ni_rtevent_receive;
	sock->close	= __ni_rtevent_close;

	__ni_rtevent_sock         = sock;
	ni_global.interface_event = ifevent_handler;

	ni_socket_activate(__ni_rtevent_sock);

	return 0;
}

void
ni_server_trace_interface_addr_events(ni_netdev_t *dev, ni_event_t event, const ni_address_t *ap)
{
	ni_stringbuf_t flags = NI_STRINGBUF_INIT_DYNAMIC;

	ni_address_format_flags(&flags, ap->family, ap->flags, NULL);
	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_EVENTS,
			"%s: %s event: %s flags[%u] %s",
			dev->name, ni_event_type_to_name(event),
			ni_sockaddr_prefix_print(&ap->local_addr, ap->prefixlen),
			ap->flags, flags.string ? flags.string : "");
	ni_stringbuf_destroy(&flags);
}

int
ni_server_enable_interface_addr_events(void (*ifaddr_handler)(ni_netdev_t *, ni_event_t, const ni_address_t *))
{
	struct nl_sock *nl_sock;

	if (!__ni_rtevent_sock || ni_global.interface_addr_event) {
		ni_error("Interface address event handler already set");
		return -1;
	}

	nl_sock = __ni_rtevent_sock->user_data;

	if (nl_socket_add_membership(nl_sock, RTNLGRP_IPV4_IFADDR) < 0 ||
	    nl_socket_add_membership(nl_sock, RTNLGRP_IPV6_IFADDR) < 0) {
		ni_error("Cannot add rtnetlink address event membership: %m");
		return -1;
	}

	ni_global.interface_addr_event = ifaddr_handler;
	return 0;
}

void
ni_server_trace_interface_prefix_events(ni_netdev_t *dev, ni_event_t event, const ni_ipv6_ra_pinfo_t *pi)
{
	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_EVENTS,
			"%s: %s IPv6 RA<%s> Prefix<%s/%u %s,%s>[%u, %u]", dev->name,
			(event == NI_EVENT_PREFIX_UPDATE ? "update" : "delete"),
			(dev->ipv6 && dev->ipv6->radv.managed_addr ? "managed" :
			(dev->ipv6 && dev->ipv6->radv.other_config ? "config" : "unmanaged")),
			ni_sockaddr_print(&pi->prefix), pi->length,
			(pi->on_link ? "onlink" : "not-onlink"),
			(pi->autoconf ? "autoconf" : "no-autoconf"),
			pi->lifetime.preferred_lft, pi->lifetime.valid_lft);
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
ni_server_trace_interface_nduseropt_events(ni_netdev_t *dev, ni_event_t event)
{
	ni_ipv6_devinfo_t *ipv6 = dev->ipv6;

	if (!ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_EVENTS))
		return;

	switch (event) {
	case NI_EVENT_RDNSS_UPDATE:
		if (ipv6 && ipv6->radv.rdnss && ipv6->radv.rdnss->addrs.count) {
			char lifetime[32] = "infinite";
			const char *rainfo;
			unsigned int i;

			rainfo = ipv6->radv.managed_addr ? "managed" :
				 ipv6->radv.other_config ? "config"  : "unmanaged";
			if (ipv6->radv.rdnss->lifetime != 0xffffffff) {
				snprintf(lifetime, sizeof(lifetime), "%u",
						ipv6->radv.rdnss->lifetime);
			}
			for (i = 0; i < ipv6->radv.rdnss->addrs.count; ++i) {
				ni_trace("%s: update IPv6 RA<%s> RDNSS<%s>[%s]",
					dev->name, rainfo,
					ni_sockaddr_print(&ipv6->radv.rdnss->addrs.data[i]),
					lifetime);
			}
		}
		break;
	default:
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_EVENTS,
			"%s: IPv6 RA %s event: ", dev->name, ni_event_type_to_name(event));
		break;
	}
}

int
ni_server_enable_interface_nduseropt_events(void (*ifnduseropt_handler)(ni_netdev_t *, ni_event_t))
{
	struct nl_sock *nl_sock;

	if (!__ni_rtevent_sock || ni_global.interface_nduseropt_event) {
		ni_error("Interface ND user opt event handler already set");
		return -1;
	}

	nl_sock = __ni_rtevent_sock->user_data;

	if (nl_socket_add_membership(nl_sock, RTNLGRP_ND_USEROPT) < 0) {
		ni_error("Cannot add rtnetlink nd user opt event membership: %m");
		return -1;
	}

	ni_global.interface_nduseropt_event = ifnduseropt_handler;
	return 0;
}

void
ni_server_deactivate_interface_events(void)
{
	ni_server_deactivate_interface_uevents();
	if (__ni_rtevent_sock) {
		ni_socket_deactivate(__ni_rtevent_sock);

		ni_global.interface_event = NULL;
		ni_global.interface_addr_event = NULL;
		ni_global.interface_prefix_event = NULL;
		ni_socket_release(__ni_rtevent_sock);
		__ni_rtevent_sock = NULL;
	}
}

