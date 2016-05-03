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
#include <wicked/route.h>
#include <wicked/ipv6.h>

#include "netinfo_priv.h"
#include "socket_priv.h"
#include "ipv6_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "appconfig.h"

#ifndef NI_ND_OPT_RDNSS_INFORMATION
#define NI_ND_OPT_RDNSS_INFORMATION	25	/* RFC 5006 */
#endif
#ifndef NI_ND_OPT_DNSSL_INFORMATION
#define NI_ND_OPT_DNSSL_INFORMATION	31	/* RFC 6106 */
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

struct ni_nd_opt_dnssl_info_p
{
	uint8_t		nd_opt_dnssl_type;
	uint8_t		nd_opt_dnssl_len;
	uint16_t	nd_opt_dnssl_resserved1;
	uint32_t	nd_opt_dnssl_lifetime;
	/* followed by one or more dns domains    */
	unsigned char	nd_opt_dnssl_list[];
};

typedef struct ni_rtevent_handle
{
	struct nl_sock *nlsock;
	ni_uint_array_t	groups;
} ni_rtevent_handle_t;

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
static int	__ni_rtevent_newroute(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_delroute(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_newrule(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
static int	__ni_rtevent_delrule(ni_netconfig_t *, const struct sockaddr_nl *, struct nlmsghdr *);
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

static inline void
__ni_netinfo_route_event(ni_netconfig_t *nc, ni_event_t ev, const ni_route_t *rp)
{
	if (ni_global.route_event)
		ni_global.route_event(nc, ev, rp);
}

static inline void
__ni_netinfo_rule_event(ni_netconfig_t *nc, ni_event_t ev, const ni_rule_t *rule)
{
	if (ni_global.rule_event)
		ni_global.rule_event(nc, ev, rule);
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

	case RTM_NEWROUTE:
		rv = __ni_rtevent_newroute(nc, nladdr, h);
		break;

	case RTM_DELROUTE:
		rv = __ni_rtevent_delroute(nc, nladdr, h);
		break;

	case RTM_NEWRULE:
		rv = __ni_rtevent_newrule(nc, nladdr, h);
		break;

	case RTM_DELRULE:
		rv = __ni_rtevent_delrule(nc, nladdr, h);
		break;

	case RTM_NEWNDUSEROPT:
		rv = __ni_rtevent_nduseropt(nc, nladdr, h);
		break;

	default:
		rv = 0;
	}

	return rv;
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
	char namebuf[IF_NAMESIZE+1] = {'\0'};
	ni_netdev_t *dev, *old;
	struct ifinfomsg *ifi;
	struct nlattr *nla;
	char *ifname = NULL;
	int old_flags = 0;

	if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_NEWLINK)))
		return -1;

	if (ifi->ifi_family == AF_BRIDGE)
		return 0;

	old = ni_netdev_by_index(nc, ifi->ifi_index);
	ifname = if_indextoname(ifi->ifi_index, namebuf);
	if (!ifname) {
		/*
		 * device (index) does not exists any more;
		 * process deletion/cleanup of the device.
		 */
		if (old) {
			old_flags = old->link.ifflags;
			old->link.ifflags = 0;
			old->deleted = 1;

			__ni_netdev_process_events(nc, old, old_flags);
			ni_client_state_drop(old->link.ifindex);
			ni_netconfig_device_remove(nc, old);
		}
		return 0;
	}

	if (old) {
		if (!ni_string_eq(old->name, ifname)) {
			ni_debug_events("%s[%u]: device renamed to %s",
					old->name, old->link.ifindex, ifname);
			ni_string_dup(&old->name, ifname);
		}
		dev = old;
		old_flags = old->link.ifflags;
	} else {
		if (!(dev = ni_netdev_new(ifname, ifi->ifi_index))) {
			ni_warn("%s[%u]: unable to allocate memory for device",
					ifname, ifi->ifi_index);
			return -1;
		}
		dev->created = 1;
		ni_netconfig_device_append(nc, dev);
	}

	if (__ni_netdev_process_newlink(dev, h, ifi, nc) < 0) {
		ni_error("Problem parsing RTM_NEWLINK message for %s", ifname);
		return -1;
	}

	if ((ifname = dev->name)) {
		ni_netdev_t *conflict;

		conflict = ni_netdev_by_name(nc, ifname);
		if (conflict && conflict->link.ifindex != (unsigned int)ifi->ifi_index) {
			/*
			 * As the events often provide an already obsolete name [2 events,
			 * we process 1st with next in read buffer], we are reading the
			 * current dev->name in advance (above).
			 *
			 * On a rename like eth0->rename1->eth1, eth1->rename2->eth0, the
			 * current dev->name is already eth1 at processing time of eth0
			 * to rename1 event. This sometimes causes that we find eth1 in
			 * our device list [eth1 -> rename2 event in the read buffer].
			 *
			 * Just update the name of the conflicting device in advance too.
			 * Next DELLINK will cleanup it, next NEWLINK event will emit the
			 * device-change (at least) or even delete (see above) when the
			 * ifindex is not valid any more.
			 */
			char *current = if_indextoname(conflict->link.ifindex, namebuf);
			ni_string_dup(&conflict->name, current ? current : "dead");
		}
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
	if (!dev) {
		ni_debug_events("ipv6 prefix info event for unknown device index: %u",
				pfx->prefix_ifindex);
		return 0;
	}

	ipv6 = ni_netdev_get_ipv6(dev);
	if (!ipv6) {
		ni_error("%s: unable to allocate device ipv6 structure: %m",
				dev->name);
		return -1;
	}

	pi = calloc(1, sizeof(*pi));
	if (!pi) {
		ni_error("%s: unable to allocate ipv6 prefix info structure: %m",
				dev->name);
		return -1;
	}

	ni_timer_get_time(&pi->lifetime.acquired);

	if (__ni_rtnl_parse_newprefix(dev->name, h, pfx, pi) < 0) {
		ni_error("%s: unable to parse ipv6 prefix info event data",
				dev->name);
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
	ni_string_free(&tmp.label);

	return 0;
}

static int
__ni_rtevent_newroute(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	struct rtmsg *rtm;
	ni_route_t *rp, *r;
	ni_route_nexthop_t *nh;
	ni_netdev_t *dev = NULL;

	if (!(rtm = ni_rtnl_rtmsg(h, RTM_NEWROUTE)))
		return -1;

	/* filter unwanted / unsupported  msgs */
	if (ni_rtnl_route_filter_msg(rtm))
		return 1;

	rp = ni_route_new();
	if (ni_rtnl_route_parse_msg(h, rtm, rp) != 0) {
		ni_route_free(rp);
		return -1;
	}

	for (nh = &rp->nh; nh; nh = nh->next) {
		if (!(dev = ni_netdev_by_index(nc, nh->device.index)))
			continue;

		if (!(r = ni_route_tables_find_match(dev->routes, rp, ni_route_equal)))
			continue;

		rp->owner = r->owner;
		ni_netconfig_route_del(nc, r, dev);
		break;
	}
	if (ni_netconfig_route_add(nc, rp, dev) < 0) {
		ni_route_free(rp);
		return -1;
	}

	__ni_netinfo_route_event(nc, NI_EVENT_ROUTE_UPDATE, rp);
	ni_route_free(rp);
	return 0;
}

static int
__ni_rtevent_delroute(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	struct rtmsg *rtm;
	ni_route_t *rp, *r;
	ni_route_nexthop_t *nh;
	ni_netdev_t *dev = NULL;

	if (!(rtm = ni_rtnl_rtmsg(h, RTM_DELROUTE)))
		return -1;

	/* filter unwanted / unsupported  msgs */
	if (ni_rtnl_route_filter_msg(rtm))
		return 1;

	rp = ni_route_new();
	if (ni_rtnl_route_parse_msg(h, rtm, rp) != 0) {
		ni_route_free(rp);
		return -1;
	}

	for (nh = &rp->nh; nh; nh = nh->next) {
		if (!(dev = ni_netdev_by_index(nc, nh->device.index)))
			continue;

		if (!(r = ni_route_tables_find_match(dev->routes, rp, ni_route_equal)))
			continue;

		__ni_netinfo_route_event(nc, NI_EVENT_ROUTE_DELETE, r);
		ni_netconfig_route_del(nc, r, dev);
		break;
	}

	ni_route_free(rp);
	return 0;
}

static int
__ni_rtevent_newrule(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	struct fib_rule_hdr *frh;
	ni_rule_t *rule;
	ni_rule_t *old;
	int ret;

	if (!(frh = ni_rtnl_fibrulemsg(h, RTM_NEWRULE)))
		return -1;

	rule = ni_rule_new();
	if ((ret = ni_rtnl_rule_parse_msg(h, frh, rule)) != 0) {
		ni_rule_free(rule);
		return ret;
	}

	old = NULL;
	if (ni_netconfig_rule_del(nc, rule, &old) == 0)
		ni_rule_free(old);

	if ((ret = ni_netconfig_rule_add(nc, rule)) != 0) {
		ni_rule_free(rule);
		return ret;
	}

	__ni_netinfo_rule_event(nc, NI_EVENT_RULE_UPDATE, rule);
	ni_rule_free(rule);
	return ret;
}

static int
__ni_rtevent_delrule(ni_netconfig_t *nc, const struct sockaddr_nl *nladdr, struct nlmsghdr *h)
{
	struct fib_rule_hdr *frh;
	ni_rule_t *rule;
	ni_rule_t *old;
	int ret;

	if (!(frh = ni_rtnl_fibrulemsg(h, RTM_NEWRULE)))
		return -1;

	rule = ni_rule_new();
	if ((ret = ni_rtnl_rule_parse_msg(h, frh, rule)) != 0) {
		ni_rule_free(rule);
		return ret;
	}

	old = NULL;
	if ((ret = ni_netconfig_rule_del(nc, rule, &old)) == 0) {
		__ni_netinfo_rule_event(nc, NI_EVENT_RULE_DELETE, old);
		ni_rule_free(old);
	}

	ni_rule_free(rule);
	return ret;
}

static int
__ni_rtevent_process_rdnss_info(ni_netdev_t *dev, const struct nd_opt_hdr *opt,
				size_t len)
{
	const struct ni_nd_opt_rdnss_info_p *ropt;
	char buf[INET6_ADDRSTRLEN+1] = {'\0'};
	const struct in6_addr* addr;
	ni_ipv6_devinfo_t *ipv6;
	unsigned int lifetime;
	struct timeval acquired;
	ni_bool_t emit = FALSE;
	const char *server;

	if (opt == NULL || len < (sizeof(*ropt) + sizeof(*addr))) {
		ni_error("%s: unable to parse ipv6 rdnss info event data -- too short",
				dev->name);
		return -1;
	}

	ipv6 = ni_netdev_get_ipv6(dev);
	if (!ipv6) {
		ni_error("%s: unable to allocate device ipv6 structure: %m",
				dev->name);
		return -1;
	}

	ropt = (const struct ni_nd_opt_rdnss_info_p *)opt;

	ni_timer_get_time(&acquired);
	lifetime = ntohl(ropt->nd_opt_rdnss_lifetime);
	len -= sizeof(*ropt);
	addr = &ropt->nd_opt_rdnss_addr[0];
	for ( ; len >= sizeof(*addr); len -= sizeof(*addr), ++addr) {
		if (IN6_IS_ADDR_LOOPBACK(addr) || IN6_IS_ADDR_UNSPECIFIED(addr)) {
			server = inet_ntop(AF_INET6, addr, buf, sizeof(buf));
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IPV6|NI_TRACE_EVENTS,
					"%s: ignoring invalid rdnss server address %s",
					dev->name, server);
			continue;
		}

		if (!ni_ipv6_ra_rdnss_list_update(&ipv6->radv.rdnss, addr,
					lifetime, &acquired)) {
			server = inet_ntop(AF_INET6, addr, buf, sizeof(buf));
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_EVENTS,
					"%s: failed to track ipv6 rnssl server %s",
					dev->name, server);
			continue;
		}

		emit = TRUE;
	}

	if (emit)
		__ni_netdev_nduseropt_event(dev, NI_EVENT_RDNSS_UPDATE);
	return 0;
}

static int
__ni_rtevent_process_dnssl_info(ni_netdev_t *dev, const struct nd_opt_hdr *opt, size_t len)
{
	const struct ni_nd_opt_dnssl_info_p *dopt;
	ni_ipv6_devinfo_t *ipv6;
	unsigned int lifetime;
	struct timeval acquired;
	size_t length, cnt, off;
	ni_bool_t emit = FALSE;
	char domain[256];

	if (opt == NULL || len < sizeof(*dopt)) {
		ni_error("%s: unable to parse ipv6 dnssl info event data -- too short",
				dev->name);
		return -1;
	}

	ipv6 = ni_netdev_get_ipv6(dev);
	if (!ipv6) {
		ni_error("%s: unable to allocate device ipv6 structure: %m",
				dev->name);
		return -1;
	}

	dopt = (const struct ni_nd_opt_dnssl_info_p *)opt;
	len -= sizeof(*dopt);

	ni_timer_get_time(&acquired);
	lifetime = ntohl(dopt->nd_opt_dnssl_lifetime);

	length = 0;
	domain[length] = '\0';
	for (off = 0; off < len ; ) {
		cnt = dopt->nd_opt_dnssl_list[off++];
		if (cnt == 0) {
			/* just padding */
			if (domain[0] == '\0')
				continue;

			domain[length] = '\0';
			if (!ni_check_domain_name(domain, length, 0)) {
				ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_EVENTS,
					"%s: ignoring suspect DNSSL domain: %s",
					dev->name, ni_print_suspect(domain, length));
			} else
			if (!ni_ipv6_ra_dnssl_list_update(&ipv6->radv.dnssl,
						domain, lifetime, &acquired)) {
				ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_IPV6|NI_TRACE_EVENTS,
						"%s: unable to track ipv6 dnssl domain %s",
						dev->name, domain);
			} else
				emit = TRUE;

			length = 0;
			domain[length] = '\0';
			continue;
		}

		if ((off + cnt >= len) || (length + cnt + 2 > sizeof(domain)))
			break;

		if (length)
			domain[length++] = '.';
		memcpy(&domain[length], &dopt->nd_opt_dnssl_list[off], cnt);
		off += cnt;
		length += cnt;
		domain[length] = '\0';
	}

	if (emit)
		__ni_netdev_nduseropt_event(dev, NI_EVENT_DNSSL_UPDATE);
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

		case NI_ND_OPT_DNSSL_INFORMATION:
			if (__ni_rtevent_process_dnssl_info(dev, opt, opt_len) < 0) {
				ni_error("%s: Cannot process DNSSL info option",
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
	if (!dev) {
		ni_debug_events("ipv6 nd user option event for unknown device index: %u",
				msg->nduseropt_ifindex);
		return 0;
	}

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

static ni_bool_t	__ni_rtevent_restart(ni_socket_t *sock);


/*
 * Receive netlink message and trigger processing by callback
 */
static void
__ni_rtevent_receive(ni_socket_t *sock)
{
	ni_rtevent_handle_t *handle = sock->user_data;
	int ret;

	if (handle && handle->nlsock) {
		do {
			ret = nl_recvmsgs_default(handle->nlsock);
		} while (ret == NLE_SUCCESS || ret == -NLE_INTR);

		switch (ret) {
		case NLE_SUCCESS:
		case -NLE_AGAIN:
			break;

		default:
			ni_error("rtnetlink event receive error: %s (%m)",
					nl_geterror(ret));
			if (__ni_rtevent_restart(sock)) {
				ni_note("restarted rtnetlink event listener");
			} else {
				ni_error("unable to restart rtnetlink event listener");
			}
			break;
		}
	}
}

/*
 * Cleanup netlink socket inside of our socket.
 */
static void
__ni_rtevent_close(ni_socket_t *sock)
{
	ni_rtevent_handle_t *handle = sock->user_data;

	if (handle) {
		if (handle->nlsock) {
			nl_socket_free(handle->nlsock);
			handle->nlsock = NULL;
		}
	}
}

static inline ni_rtevent_handle_t *
__ni_rtevent_handle_new(void)
{
	return calloc(1, sizeof(ni_rtevent_handle_t));
}

static void
__ni_rtevent_handle_free(ni_rtevent_handle_t *handle)
{
	if (handle) {
		if (handle->nlsock) {
			nl_socket_free(handle->nlsock);
			handle->nlsock = NULL;
		}
		ni_uint_array_destroy(&handle->groups);
		free(handle);
	}
}

static ni_bool_t
__ni_rtevent_join_group(ni_rtevent_handle_t *handle, unsigned int group)
{
	int ret;

	if (!group || !handle || !handle->nlsock)
		return FALSE;

	if (ni_uint_array_contains(&handle->groups, group))
		return TRUE;

	if (!ni_uint_array_append(&handle->groups, group))
		return FALSE;

	ret = nl_socket_add_membership(handle->nlsock, group);
	if (ret != NLE_SUCCESS) {
		/* remove from array? */
		ni_error("Cannot add rtnetlink group %u membership: %s",
				group, nl_geterror(ret));
		return FALSE;
	}
	return TRUE;
}

static void
__ni_rtevent_sock_error_handler(ni_socket_t *sock)
{
	ni_error("poll error on rtnetlink event socket: %m");
	if (__ni_rtevent_restart(sock)) {
		ni_note("restarted rtnetlink event listener");
	} else {
		ni_error("unable to restart rtnetlink event listener");
	}
}

static void
__ni_rtevent_sock_release_data(void *user_data)
{
	__ni_rtevent_handle_free(user_data);
}

static unsigned int
__ni_rtevent_config_recv_buff_len(void)
{
	return ni_global.config ? ni_global.config->rtnl_event.recv_buff_length : 0;
}

static unsigned int
__ni_rtevent_config_mesg_buff_len(void)
{
	return ni_global.config ? ni_global.config->rtnl_event.mesg_buff_length : 0;
}

static ni_socket_t *
__ni_rtevent_sock_open(void)
{
	unsigned int recv_buff_len = __ni_rtevent_config_recv_buff_len();
	unsigned int mesg_buff_len = __ni_rtevent_config_mesg_buff_len();
	ni_rtevent_handle_t *handle;
	ni_socket_t *sock;
	int fd, ret;

	if (!(handle = __ni_rtevent_handle_new())) {
		ni_error("Unable to allocate rtnetlink event handle: %m");
		return NULL;
	}

	if (!(handle->nlsock = nl_socket_alloc())) {
		ni_error("Cannot allocate rtnetlink event socket: %m");
		__ni_rtevent_handle_free(handle);
		return NULL;
	}

	/*
	 * Modify the callback for processing valid messages...
	 * We may pass some kind of data (event filter?) too...
	 */
	nl_socket_modify_cb(handle->nlsock, NL_CB_VALID, NL_CB_CUSTOM,
				__ni_rtevent_process_cb, NULL);

	/* Required to receive async event notifications */
	nl_socket_disable_seq_check(handle->nlsock);

	if ((ret = nl_connect(handle->nlsock, NETLINK_ROUTE)) < 0) {
		ni_error("Cannot open rtnetlink: %s", nl_geterror(ret));
		__ni_rtevent_handle_free(handle);
		return NULL;
	}

	/* Enable non-blocking processing */
	nl_socket_set_nonblocking(handle->nlsock);

	fd = nl_socket_get_fd(handle->nlsock);
	if (!(sock = ni_socket_wrap(fd, SOCK_DGRAM))) {
		ni_error("Cannot wrap rtnetlink event socket: %m");
		__ni_rtevent_handle_free(handle);
		return NULL;
	}

	if (recv_buff_len) {
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE,
				(char *)&recv_buff_len, sizeof(recv_buff_len)) &&
		    setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
				(char *)&recv_buff_len, sizeof(recv_buff_len))) {
			ni_warn("Unable to set netlink event receive buffer to %u bytes: %m",
					recv_buff_len);
		} else {
			ni_info("Using netlink event receive buffer of %u bytes",
					recv_buff_len);
		}
	}
	if (mesg_buff_len) {
		if (nl_socket_set_msg_buf_size(handle->nlsock, mesg_buff_len)) {
			ni_warn("Unable to set netlink event message buffer to %u bytes",
					mesg_buff_len);
		} else {
			ni_info("Using netlink event message buffer of %u bytes",
					mesg_buff_len);
		}
	}

	sock->user_data	= handle;
	sock->receive	= __ni_rtevent_receive;
	sock->close	= __ni_rtevent_close;
	sock->handle_error  = __ni_rtevent_sock_error_handler;
	sock->release_user_data = __ni_rtevent_sock_release_data;
	return sock;
}

static ni_bool_t
__ni_rtevent_restart(ni_socket_t *sock)
{
	ni_rtevent_handle_t *handle = sock->user_data;
	if (handle) {
		if ((__ni_rtevent_sock = __ni_rtevent_sock_open())) {
			const ni_uint_array_t *groups = &handle->groups;
			unsigned int i;

			handle = __ni_rtevent_sock->user_data;
			for (i = 0; i < groups->count; ++i) {
				__ni_rtevent_join_group(handle, groups->data[i]);
			}
			ni_socket_activate(__ni_rtevent_sock);
			return TRUE;
		}
		ni_socket_release(sock);
	}
	return FALSE;
}

/*
 * Embed rtnetlink socket into ni_socket_t and set ifevent handler
 */
int
ni_server_listen_interface_events(void (*ifevent_handler)(ni_netdev_t *, ni_event_t))
{
	ni_rtevent_handle_t *handle;
	unsigned int family;

	if (__ni_rtevent_sock || ni_global.interface_event) {
		ni_error("Interface event handler is already set");
		return -1;
	}

	if (!(__ni_rtevent_sock = __ni_rtevent_sock_open()))
		return -1;

	family = ni_netconfig_get_family_filter(ni_global_state_handle(0));
	handle = __ni_rtevent_sock->user_data;
	/* TODO: Move IPv6 info to separate function, dhcp4 does not need it */
	if (!__ni_rtevent_join_group(handle, RTNLGRP_LINK) ||
	    (family != AF_INET &&
	     !__ni_rtevent_join_group(handle, RTNLGRP_IPV6_IFINFO))) {
		ni_socket_release(__ni_rtevent_sock);
		__ni_rtevent_sock = NULL;
		return -1;
	}
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
	ni_rtevent_handle_t *handle;
	unsigned int family;

	if (!__ni_rtevent_sock || ni_global.interface_addr_event) {
		ni_error("Interface address event handler already set");
		return -1;
	}

	family = ni_netconfig_get_family_filter(ni_global_state_handle(0));
	handle = __ni_rtevent_sock->user_data;
	if ((family != AF_INET6 &&
	     !__ni_rtevent_join_group(handle, RTNLGRP_IPV4_IFADDR)) ||
	    (family != AF_INET  &&
	     !__ni_rtevent_join_group(handle, RTNLGRP_IPV6_IFADDR))) {
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
	ni_rtevent_handle_t *handle;

	if (!__ni_rtevent_sock || ni_global.interface_prefix_event) {
		ni_error("Interface prefix event handler already set");
		return -1;
	}

	handle = __ni_rtevent_sock->user_data;
	if (!__ni_rtevent_join_group(handle, RTNLGRP_IPV6_PREFIX)) {
		ni_error("Cannot add rtnetlink prefix event membership: %m");
		return -1;
	}

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
		if (ipv6 && ipv6->radv.rdnss) {
			ni_ipv6_ra_rdnss_t *rdnss;
			char lifetime[32];
			const char *rainfo;

			rainfo = ipv6->radv.managed_addr ? "managed" :
				 ipv6->radv.other_config ? "config"  : "unmanaged";

			for (rdnss = ipv6->radv.rdnss; rdnss; rdnss = rdnss->next) {
				if (rdnss->lifetime == 0xffffffff) {
					snprintf(lifetime, sizeof(lifetime), "%s",
								"infinite");
				} else {
					snprintf(lifetime, sizeof(lifetime), "%u",
								rdnss->lifetime);
				}
				ni_trace("%s: update IPv6 RA<%s> RDNSS<%s>[%s]",
					dev->name, rainfo,
					ni_sockaddr_print(&rdnss->server), lifetime);
			}
		}
		break;

	case NI_EVENT_DNSSL_UPDATE:
		if (ipv6 && ipv6->radv.dnssl) {
			ni_ipv6_ra_dnssl_t *dnssl;
			char lifetime[32];
			const char *rainfo;

			rainfo = ipv6->radv.managed_addr ? "managed" :
				 ipv6->radv.other_config ? "config"  : "unmanaged";
			for (dnssl = ipv6->radv.dnssl; dnssl; dnssl = dnssl->next) {
				if (dnssl->lifetime == 0xffffffff) {
					snprintf(lifetime, sizeof(lifetime), "%s",
								"infinite");
				} else {
					snprintf(lifetime, sizeof(lifetime), "%u",
								dnssl->lifetime);
				}
				ni_trace("%s: update IPv6 RA<%s> DNSSL<%s>[%s]",
						dev->name, rainfo,
						dnssl->domain, lifetime);
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
	ni_rtevent_handle_t *handle;

	if (!__ni_rtevent_sock || ni_global.interface_nduseropt_event) {
		ni_error("Interface ND user opt event handler already set");
		return -1;
	}

	handle = __ni_rtevent_sock->user_data;
	if (!__ni_rtevent_join_group(handle, RTNLGRP_ND_USEROPT)) {
		ni_error("Cannot add rtnetlink nd user opt event membership: %m");
		return -1;
	}
	ni_global.interface_nduseropt_event = ifnduseropt_handler;
	return 0;
}

void
ni_server_trace_route_events(ni_netconfig_t *nc, ni_event_t event, const ni_route_t *rp)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int family_trace;

	switch (rp->family) {
	case AF_INET:
		family_trace = NI_TRACE_IPV4;
		break;
	case AF_INET6:
		family_trace = NI_TRACE_IPV6;
		break;
	default:
		family_trace = 0;
		break;
	}
	ni_debug_verbose(NI_LOG_DEBUG2, family_trace|NI_TRACE_ROUTE|NI_TRACE_EVENTS,
			"%s event: %s", ni_event_type_to_name(event),
			ni_route_print(&buf, rp));
	ni_stringbuf_destroy(&buf);
}

int
ni_server_enable_route_events(void (*route_handler)(ni_netconfig_t *, ni_event_t, const ni_route_t *))
{
	ni_rtevent_handle_t *handle;

	if (!__ni_rtevent_sock) {
		ni_error("Event monitor not enabled");
		return -1;
	}
	if (ni_global.route_event) {
		ni_error("Route event handler already set");
		return 1;
	}

	handle = __ni_rtevent_sock->user_data;
	if (!__ni_rtevent_join_group(handle, RTNLGRP_IPV4_ROUTE) < 0 ||
	    !__ni_rtevent_join_group(handle, RTNLGRP_IPV6_ROUTE) < 0) {
		ni_error("Cannot add rtnetlink route event membership: %m");
		return -1;
	}
	ni_global.route_event = route_handler;
	return 0;
}

void
ni_server_trace_rule_events(ni_netconfig_t *nc, ni_event_t event, const ni_rule_t *rule)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int family_trace;

	switch (rule->family) {
	case AF_INET:
		family_trace = NI_TRACE_IPV4;
		break;
	case AF_INET6:
		family_trace = NI_TRACE_IPV6;
		break;
	default:
		family_trace = 0;
		break;
	}
	ni_debug_verbose(NI_LOG_DEBUG2, family_trace|NI_TRACE_ROUTE|NI_TRACE_EVENTS,
			"%s event: %s", ni_event_type_to_name(event),
			ni_rule_print(&buf, rule));
	ni_stringbuf_destroy(&buf);
}

int
ni_server_enable_rule_events(void (*rule_handler)(ni_netconfig_t *, ni_event_t, const ni_rule_t *))
{
	ni_rtevent_handle_t *handle;

	if (!__ni_rtevent_sock) {
		ni_error("Event monitor not enabled");
		return -1;
	}
	if (ni_global.rule_event) {
		ni_error("Rule event handler already set");
		return 1;
	}

	handle = __ni_rtevent_sock->user_data;
	if (!__ni_rtevent_join_group(handle, RTNLGRP_IPV4_RULE) < 0 ||
	    !__ni_rtevent_join_group(handle, RTNLGRP_IPV6_RULE) < 0) {
		ni_error("Cannot add rtnetlink rule event membership: %m");
		return -1;
	}
	ni_global.rule_event = rule_handler;
	return 0;
}

void
ni_server_deactivate_interface_events(void)
{
	ni_server_deactivate_interface_uevents();

	if (__ni_rtevent_sock) {
		ni_socket_t *sock = __ni_rtevent_sock;
		__ni_rtevent_sock = NULL;

		ni_socket_deactivate(sock);
		ni_socket_release(sock);
	}
	ni_global.rule_event = NULL;
	ni_global.route_event = NULL;
	ni_global.interface_event = NULL;
	ni_global.interface_addr_event = NULL;
	ni_global.interface_prefix_event = NULL;
}

