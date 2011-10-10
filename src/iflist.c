/*
 * Discover list of existing kernel interfaces and their state.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 *
 * TODO:
 *  -	Discover bonding state
 *  -	Discover bonding module params
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netlink/attr.h>
#include <netlink/msg.h>
#include <linux/ethtool.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/wireless.h>
#include <wicked/xml.h>

#include "netinfo_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "config.h"

static int	__ni_interface_process_newaddr(ni_interface_t *, struct nlmsghdr *,
				struct ifaddrmsg *, ni_handle_t *);
static int	__ni_interface_process_newroute(ni_interface_t *, struct nlmsghdr *,
				struct rtmsg *, ni_handle_t *);
static int	__ni_discover_bridge(ni_interface_t *);
static int	__ni_discover_bond(ni_interface_t *);
static int	__ni_discover_addrconf(ni_handle_t *, ni_interface_t *);

struct ni_rtnl_info {
	struct ni_nlmsg_list	nlmsg_list;
	struct ni_nlmsg *	entry;
};

struct ni_rtnl_query {
	struct ni_rtnl_info	link_info;
	struct ni_rtnl_info	addr_info;
	struct ni_rtnl_info	ipv6_info;
	struct ni_rtnl_info	route_info;
	int			ifindex;
};

/*
 * Query netlink for all relevant information
 */
static inline int
__ni_rtnl_query(ni_handle_t *nih, struct ni_rtnl_info *qr, int af, int type)
{
	ni_nlmsg_list_init(&qr->nlmsg_list);
	if (ni_nl_dump_store(nih, af, type, &qr->nlmsg_list) < 0)
		return -1;

	qr->entry = qr->nlmsg_list.head;
	return 0;
}

static inline struct nlmsghdr *
__ni_rtnl_info_next(struct ni_rtnl_info *qr)
{
	struct ni_nlmsg *entry;

	if ((entry = qr->entry) != NULL) {
		qr->entry = entry->next;
		return &entry->h;
	}

	return NULL;
}

static int
ni_rtnl_query(ni_handle_t *nih, struct ni_rtnl_query *q, int ifindex)
{
	memset(q, 0, sizeof(*q));
	q->ifindex = ifindex;

	if (__ni_rtnl_query(nih, &q->link_info, AF_UNSPEC, RTM_GETLINK) < 0
	 || __ni_rtnl_query(nih, &q->ipv6_info, AF_INET6, RTM_GETLINK) < 0
	 || __ni_rtnl_query(nih, &q->addr_info, AF_UNSPEC, RTM_GETADDR) < 0
	 || __ni_rtnl_query(nih, &q->route_info, AF_UNSPEC, RTM_GETROUTE) < 0) {
		ni_nlmsg_list_destroy(&q->link_info.nlmsg_list);
		ni_nlmsg_list_destroy(&q->addr_info.nlmsg_list);
		ni_nlmsg_list_destroy(&q->ipv6_info.nlmsg_list);
		ni_nlmsg_list_destroy(&q->route_info.nlmsg_list);
		return -1;
	}

	return 0;
}

static void
ni_rtnl_query_destroy(struct ni_rtnl_query *q)
{
	ni_nlmsg_list_destroy(&q->link_info.nlmsg_list);
	ni_nlmsg_list_destroy(&q->addr_info.nlmsg_list);
	ni_nlmsg_list_destroy(&q->ipv6_info.nlmsg_list);
	ni_nlmsg_list_destroy(&q->route_info.nlmsg_list);
}

static inline struct ifinfomsg *
ni_rtnl_query_next_link_info(struct ni_rtnl_query *q, struct nlmsghdr **hp)
{
	struct nlmsghdr *h;

	while ((h = __ni_rtnl_info_next(&q->link_info)) != NULL) {
		struct ifinfomsg *ifi;

		if ((ifi = ni_rtnl_ifinfomsg(h, RTM_NEWLINK)) != NULL) {
			if (q->ifindex < 0 || q->ifindex == ifi->ifi_index) {
				*hp = h;
				return ifi;
			}
		}
	}

	return NULL;
}

static inline struct ifinfomsg *
ni_rtnl_query_next_ipv6_link_info(struct ni_rtnl_query *q, struct nlmsghdr **hp)
{
	struct nlmsghdr *h;

	while ((h = __ni_rtnl_info_next(&q->ipv6_info)) != NULL) {
		struct ifinfomsg *ifi;

		if ((ifi = ni_rtnl_ifinfomsg(h, RTM_NEWLINK)) != NULL) {
			if (q->ifindex < 0 || q->ifindex == ifi->ifi_index) {
				*hp = h;
				return ifi;
			}
		}
	}

	return NULL;
}

static inline struct ifaddrmsg *
ni_rtnl_query_next_addr_info(struct ni_rtnl_query *q, struct nlmsghdr **hp)
{
	struct nlmsghdr *h;

	while ((h = __ni_rtnl_info_next(&q->addr_info)) != NULL) {
		struct ifaddrmsg *ifa;

		if ((ifa = ni_rtnl_ifaddrmsg(h, RTM_NEWADDR)) != NULL) {
			if (q->ifindex < 0 || q->ifindex == ifa->ifa_index) {
				*hp = h;
				return ifa;
			}
		}
	}
	return NULL;
}

static inline struct rtmsg *
ni_rtnl_query_next_route_info(struct ni_rtnl_query *q, struct nlmsghdr **hp, int *oif_idxp)
{
	struct nlmsghdr *h;

	while ((h = __ni_rtnl_info_next(&q->route_info)) != NULL) {
		int oif_index = -1;
		struct nlattr *rta;
		struct rtmsg *rtm;

		if (!(rtm = ni_rtnl_rtmsg(h, RTM_NEWROUTE)))
			continue;

		rta = nlmsg_find_attr(h, sizeof(*rtm), RTA_OIF);
		if (rta != NULL)
			oif_index = nla_get_u32(rta);

		if (q->ifindex >= 0 && oif_index != q->ifindex)
			continue;

		if (oif_idxp)
			*oif_idxp = oif_index;
		*hp = h;
		return rtm;
	}
	return NULL;
}

/*
 * Refresh all interfaces
 */
int
__ni_system_refresh_all(ni_handle_t *nih, ni_interface_t **del_list)
{
	struct ni_rtnl_query query;
	struct nlmsghdr *h;
	ni_interface_t **tail, *ifp;
	unsigned int seqno;
	int res = -1;

	seqno = ++(nih->seqno);

	if (ni_rtnl_query(nih, &query, -1) < 0)
		goto failed;

	/* Find tail of iflist */
	tail = &nih->iflist;
	while ((ifp = *tail) != NULL)
		tail = &ifp->next;

	while (1) {
		struct ifinfomsg *ifi;
		struct nlattr *nla;
		char *ifname = NULL;

		if (!(ifi = ni_rtnl_query_next_link_info(&query, &h)))
			break;

		if ((nla = nlmsg_find_attr(h, sizeof(*ifi), IFLA_IFNAME)) == NULL) {
			ni_warn("RTM_NEWLINK message without IFNAME");
			continue;
		}
		ifname = (char *) nla_data(nla);

		/* Create interface if it doesn't exist. */
		if ((ifp = ni_interface_by_index(nih, ifi->ifi_index)) == NULL) {
			ifp = __ni_interface_new(ifname, ifi->ifi_index);
			if (!ifp)
				goto failed;
			*tail = ifp;
			tail = &ifp->next;
		} else {
			/* Clear out addresses and routes */
			ni_interface_clear_addresses(ifp);
			ni_interface_clear_routes(ifp);
		}

		ifp->seq = seqno;

		if (__ni_interface_process_newlink(ifp, h, ifi, nih) < 0)
			error("Problem parsing RTM_NEWLINK message for %s", ifname);
	}

	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		if (ifp->vlan && ni_vlan_bind_ifindex(ifp->vlan, nih) < 0) {
			error("VLAN interface %s references unknown base interface (ifindex %u)",
				ifp->name, ifp->vlan->link);
			/* Ignore error and proceed */
			ni_string_dup(&ifp->vlan->interface_name, "unknown");
		}
	}

	while (1) {
		struct ifinfomsg *ifi;

		if (!(ifi = ni_rtnl_query_next_ipv6_link_info(&query, &h)))
			break;

		if ((ifp = ni_interface_by_index(nih, ifi->ifi_index)) == NULL)
			continue;

		if (__ni_interface_process_newlink_ipv6(ifp, h, ifi, nih) < 0)
			error("Problem parsing IPv6 RTM_NEWLINK message for %s", ifp->name);
	}

	while (1) {
		struct ifaddrmsg *ifa;

		if (!(ifa = ni_rtnl_query_next_addr_info(&query, &h)))
			break;

		if ((ifp = ni_interface_by_index(nih, ifa->ifa_index)) == NULL)
			continue;

		if (__ni_interface_process_newaddr(ifp, h, ifa, nih) < 0)
			error("Problem parsing RTM_NEWADDR message for %s", ifp->name);
	}

	while (1) {
		struct rtmsg *rtm;
		int oif_index;

		if (!(rtm = ni_rtnl_query_next_route_info(&query, &h, &oif_index)))
			break;

		if (oif_index >= 0) {
			ifp = ni_interface_by_index(nih, oif_index);
			if (ifp == NULL) {
				error("route specifies OIF=%u; not found!", oif_index);
				continue;
			}
		} else {
			ifp = NULL;
		}

		if (__ni_interface_process_newroute(ifp, h, rtm, nih) < 0)
			error("Problem parsing RTM_NEWROUTE message");
	}

	/* Cull any interfaces that went away */
	tail = &nih->iflist;
	while ((ifp = *tail) != NULL) {
		if (ifp->seq != seqno) {
			*tail = ifp->next;
			if (del_list == NULL) {
				ni_interface_put(ifp);
			} else {
				ifp->next = NULL;
				*del_list = ifp;
				del_list = &ifp->next;
			}
		} else {
			tail = &ifp->next;
		}
	}

	res = 0;

failed:
	ni_rtnl_query_destroy(&query);
	return res;
}

/*
 * Refresh one interfaces
 */
int
__ni_system_refresh_interface(ni_handle_t *nih, ni_interface_t *ifp)
{
	struct ni_rtnl_query query;
	struct nlmsghdr *h;
	int res = -1;

	nih->seqno++;

	if (ni_rtnl_query(nih, &query, ifp->link.ifindex) < 0)
		goto failed;

	while (1) {
		struct ifinfomsg *ifi;

		if (!(ifi = ni_rtnl_query_next_link_info(&query, &h)))
			break;

		/* Clear out addresses and routes */
		ni_interface_clear_addresses(ifp);
		ni_interface_clear_routes(ifp);

		if (__ni_interface_process_newlink(ifp, h, ifi, nih) < 0)
			error("Problem parsing RTM_NEWLINK message for %s", ifp->name);
	}

	if (ifp->vlan && ni_vlan_bind_ifindex(ifp->vlan, nih) < 0) {
		error("VLAN interface %s references unknown base interface (ifindex %u)",
			ifp->name, ifp->vlan->link);
		/* Ignore error and proceed */
		ni_string_dup(&ifp->vlan->interface_name, "unknown");
	}

	while (1) {
		struct ifaddrmsg *ifa;

		if (!(ifa = ni_rtnl_query_next_addr_info(&query, &h)))
			break;

		if (__ni_interface_process_newaddr(ifp, h, ifa, nih) < 0)
			error("Problem parsing RTM_NEWADDR message for %s", ifp->name);
	}

	while (1) {
		struct rtmsg *rtm;

		if (!(rtm = ni_rtnl_query_next_route_info(&query, &h, NULL)))
			break;

		if (__ni_interface_process_newroute(ifp, h, rtm, NULL) < 0)
			error("Problem parsing RTM_NEWROUTE message");
	}

	res = 0;

failed:
	ni_rtnl_query_destroy(&query);
	return res;
}

/*
 * Refresh interface statistics.
 * We assume that IFLA_STATS have already been covered by a generic ni_refresh;
 * all we want to do here is potentially retrieve additional stats eg via
 * ethtool.
 */
int
__ni_system_interface_stats_refresh(ni_handle_t *nih, ni_interface_t *ifp)
{
	/* This is a NOP for now */
	return 0;
}

/*
 * Translate interface flags
 */
unsigned int
__ni_interface_translate_ifflags(unsigned int ifflags)
{
	unsigned int retval = 0;

	switch (ifflags & (IFF_RUNNING | IFF_LOWER_UP | IFF_UP)) {
	case IFF_UP:
	case IFF_UP | IFF_RUNNING:
		retval = NI_IFF_DEVICE_UP;
		break;

	case IFF_UP | IFF_LOWER_UP:
	case IFF_UP | IFF_LOWER_UP | IFF_RUNNING:
		retval = NI_IFF_DEVICE_UP | NI_IFF_LINK_UP | NI_IFF_NETWORK_UP;
		break;

	case 0:
		break;

	default:
		ni_warn("unexpected combination of interface flags 0x%x", ifflags);
	}

#ifdef IFF_DORMANT
	if (ifflags & IFF_DORMANT)
		retval |= NI_IFF_POWERSAVE;
#endif
	if (ifflags & IFF_POINTOPOINT)
		retval |= NI_IFF_POINT_TO_POINT;
	if (!(ifflags & IFF_NOARP))
		retval |= NI_IFF_ARP_ENABLED;
	if (ifflags & IFF_BROADCAST)
		retval |= NI_IFF_BROADCAST_ENABLED;
	if (ifflags & IFF_MULTICAST)
		retval |= NI_IFF_MULTICAST_ENABLED;
	return retval;
}

/*
 * Refresh interface link layer given a RTM_NEWLINK message
 */
int
__ni_interface_process_newlink(ni_interface_t *ifp, struct nlmsghdr *h,
				struct ifinfomsg *ifi, ni_handle_t *nih)
{
	struct nlattr *tb[IFLA_MAX+1];
	char *ifname;

	memset(tb, 0, sizeof(tb));
	if (nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, NULL) < 0) {
		ni_error("unable to parse rtnl LINK message");
		return -1;
	}

	/* Update interface name in case it changed */
	if ((ifname = (char *) nla_data(tb[IFLA_IFNAME])) != NULL)
		strncpy(ifp->name, ifname, sizeof(ifp->name) - 1);

	ifp->link.arp_type = ifi->ifi_type;
	ifp->link.ifflags = __ni_interface_translate_ifflags(ifi->ifi_flags);
	ifp->ipv4.addrconf = NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC);
	ifp->ipv6.addrconf = NI_ADDRCONF_MASK(NI_ADDRCONF_AUTOCONF) | NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC);
	ifp->link.type = NI_IFTYPE_UNKNOWN;

#if 0
	ni_debug_ifconfig("%s: ifi flags:%s%s%s, my flags:%s%s%s", ifp->name,
		(ifi->ifi_flags & IFF_RUNNING)? " running" : "",
		(ifi->ifi_flags & IFF_LOWER_UP)? " lower_up" : "",
		(ifi->ifi_flags & IFF_UP)? " up" : "",
		(ifp->ifflags & NI_IFF_DEVICE_UP)? " device-up" : "",
		(ifp->ifflags & NI_IFF_LINK_UP)? " link-up" : "",
		(ifp->ifflags & NI_IFF_NETWORK_UP)? " network-up" : "");
#endif

	if (tb[IFLA_MTU])
		ifp->link.mtu = nla_get_u32(tb[IFLA_MTU]);
	if (tb[IFLA_TXQLEN])
		ifp->link.txqlen = nla_get_u32(tb[IFLA_TXQLEN]);
	if (tb[IFLA_COST])
		ifp->link.metric = nla_get_u32(tb[IFLA_COST]);
	if (tb[IFLA_QDISC])
		ni_string_dup(&ifp->link.qdisc, nla_get_string(tb[IFLA_QDISC]));
	if (tb[IFLA_MASTER])
		ifp->link.master = nla_get_u32(tb[IFLA_MASTER]);
	if (tb[IFLA_OPERSTATE]) {
		/* get the RFC 2863 operational status - IF_OPER_* */
	}

	if (tb[IFLA_STATS]) {
		struct rtnl_link_stats *s = nla_data(tb[IFLA_STATS]);
		ni_link_stats_t *n;

		if (!ifp->link.stats)
			ifp->link.stats = calloc(1, sizeof(*n));
		n = ifp->link.stats;

		n->rx_packets = s->rx_packets;
		n->tx_packets = s->tx_packets;
		n->rx_bytes = s->rx_bytes;
		n->tx_bytes = s->tx_bytes;
		n->rx_errors = s->rx_errors;
		n->tx_errors = s->tx_errors;
		n->rx_dropped = s->rx_dropped;
		n->tx_dropped = s->tx_dropped;
		n->multicast = s->multicast;
		n->collisions = s->collisions;
		n->rx_length_errors = s->rx_length_errors;
		n->rx_over_errors = s->rx_over_errors;
		n->rx_crc_errors = s->rx_crc_errors;
		n->rx_frame_errors = s->rx_frame_errors;
		n->rx_fifo_errors = s->rx_fifo_errors;
		n->rx_missed_errors = s->rx_missed_errors;
		n->tx_aborted_errors = s->tx_aborted_errors;
		n->tx_carrier_errors = s->tx_carrier_errors;
		n->tx_fifo_errors = s->tx_fifo_errors;
		n->tx_heartbeat_errors = s->tx_heartbeat_errors;
		n->tx_window_errors = s->tx_window_errors;
		n->rx_compressed = s->rx_compressed;
		n->tx_compressed = s->tx_compressed;
	}

	/* Extended link info.
	 * IFLA_LINKINFO is a nested set of attrs. It always contains
	 * IFLA_INFO_KIND (a string), optionally followed by xstats
	 * (no specific IFLA_* enum), optionally followed by IFLA_INFO_DATA.
	 * The latter is yet another nested set of attrs.
	 *
	 * The only driver really providing useful info through this interface
	 * is the VLAN driver.
	 *
	 * The generic tuntap driver has a LINKINFO containing only KIND ("tun").
	 */
	if (tb[IFLA_LINKINFO]) {
		struct nlattr *linkinfo[IFLA_INFO_MAX+1];
		int info_data_used = 0;

		if (nla_parse_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL) < 0) {
			ni_error("unable to parse IFLA_LINKINFO");
			return -1;
		}
		ni_string_dup(&ifp->link.kind, nla_get_string(linkinfo[IFLA_INFO_KIND]));

		if (ifp->link.kind) {
			/* Do something with these */
			if (!strcmp(ifp->link.kind, "vlan")) {
				struct nlattr *vlan_info[IFLA_VLAN_MAX+1];
				ni_vlan_t *vlancfg;

				ifp->link.type = NI_IFTYPE_VLAN;
				vlancfg = ni_interface_get_vlan(ifp);
				vlancfg->link = 0;

				/* IFLA_LINK contains the ifindex of the real ether dev */
				if (tb[IFLA_LINK])
					vlancfg->link = nla_get_u32(tb[IFLA_LINK]);

				if (nla_parse_nested(vlan_info, IFLA_VLAN_MAX, linkinfo[IFLA_INFO_DATA], NULL) >= 0) {
					vlancfg->tag = nla_get_u16(vlan_info[IFLA_VLAN_ID]);
					info_data_used = 1;
				}
			}
		}

		if (linkinfo[IFLA_INFO_DATA] && !info_data_used)
			ni_warn("%s: link info data of type %s - don't know what to do with it", ifp->name, ifp->link.kind);

		/* We may also want to inspect linkinfo[IFLA_INFO_XSTATS] */
	}

	if (ifp->link.type == NI_IFTYPE_UNKNOWN) {
		struct ethtool_drvinfo drv_info;

		switch (ifp->link.arp_type) {
		case ARPHRD_ETHER:
		case ARPHRD_NONE:	/* tun driver uses this */
			ifp->link.type = NI_IFTYPE_ETHERNET;
			if (__ni_ethtool(nih, ifp, ETHTOOL_GDRVINFO, &drv_info) >= 0) {
				const char *driver = drv_info.driver;

				if (!strcmp(driver, "tun")) {
					/* tun/tap driver */
					if (!strcmp(drv_info.bus_info, "tap"))
						ifp->link.type = NI_IFTYPE_TAP;
					else
						ifp->link.type = NI_IFTYPE_TUN;
				} else if (!strcmp(driver, "bridge")) {
					ifp->link.type = NI_IFTYPE_BRIDGE;
				} else if (!strcmp(driver, "bonding")) {
					ifp->link.type = NI_IFTYPE_BOND;
				}
			}

			/* Detect WLAN device.
			 * The official way of doing this is to check whether
			 * ioctl(SIOCGIWNAME) succeeds.
			 */
			if (__ni_wireless_get_name(nih, ifp, NULL, 0) == 0)
				ifp->link.type = NI_IFTYPE_WIRELESS;
			break;

		default:
			ifp->link.type = ni_arphrd_type_to_iftype(ifp->link.arp_type);
			break;
		}
	}

	if (tb[IFLA_ADDRESS]) {
		unsigned int alen = nla_len(tb[IFLA_ADDRESS]);
		void *data = nla_data(tb[IFLA_ADDRESS]);

		if (alen > sizeof(ifp->link.hwaddr.data))
			alen = sizeof(ifp->link.hwaddr.data);
		memcpy(ifp->link.hwaddr.data, data, alen);
		ifp->link.hwaddr.len = alen;
		ifp->link.hwaddr.type = ifp->link.type;
	} else {
		memset(&ifp->link.hwaddr, 0, sizeof(ifp->link.hwaddr));
	}

	/* dhcpcd does something very odd when shutting down an interface;
	 * in addition to removing all IPv4 addresses, it also removes any
	 * IPv6 addresses. The kernel seems to take this as "disable IPv6
	 * on this interface", and subsequently, /proc/sys/ipv6/conf/<ifname>
	 * is gone.
	 * When we bring the interface back up, everything is fine; but until
	 * then we need to ignore this glitch.
	 */
	if (ni_sysctl_ipv6_ifconfig_is_present(ifp->name)) {
		unsigned int val;

		ni_sysctl_ipv6_ifconfig_get_uint(ifp->name, "disable_ipv6", &val);
		ifp->ipv6.enabled = !val;

		ni_sysctl_ipv6_ifconfig_get_uint(ifp->name, "forwarding", &val);
		ifp->ipv6.forwarding = val;

		ni_sysctl_ipv6_ifconfig_get_uint(ifp->name, "autoconf", &val);
		if (val)
			ni_afinfo_addrconf_enable(&ifp->ipv6, NI_ADDRCONF_AUTOCONF);
		else
			ni_afinfo_addrconf_disable(&ifp->ipv6, NI_ADDRCONF_AUTOCONF);
	} else {
		ni_afinfo_addrconf_disable(&ifp->ipv6, NI_ADDRCONF_AUTOCONF);
		ifp->ipv6.enabled = ifp->ipv6.forwarding = 0;
	}

	if (ifp->link.type == NI_IFTYPE_ETHERNET)
		__ni_system_ethernet_refresh(nih, ifp);

	if (ifp->link.type == NI_IFTYPE_BRIDGE)
		__ni_discover_bridge(ifp);
	if (ifp->link.type == NI_IFTYPE_BOND)
		__ni_discover_bond(ifp);
	if (ifp->link.type == NI_IFTYPE_WIRELESS) {
		if (ni_wireless_interface_refresh(ifp) < 0)
			ni_error("%s: failed to refresh wireless info", ifp->name);
	}


	/* Check if we have DHCP running for this interface */
	__ni_discover_addrconf(nih, ifp);

	return 0;
}

/*
 * Refresh interface link layer IPv6 info given a RTM_NEWLINK message
 */
int
__ni_interface_process_newlink_ipv6(ni_interface_t *ifp, struct nlmsghdr *h,
				struct ifinfomsg *ifi, ni_handle_t *nih)
{
	struct nlattr *tb[IFLA_MAX+1];

	if (nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, NULL) < 0) {
		ni_error("unable to parse rtnl LINK message");
		return -1;
	}

	if (tb[IFLA_PROTINFO]) {
		struct nlattr *protinfo[IFLA_INET6_MAX + 1];
		unsigned int flags = 0;

		nla_parse_nested(protinfo, IFLA_INET6_MAX, tb[IFLA_PROTINFO], NULL);

		if (protinfo[IFLA_INET6_FLAGS])
			flags = nla_get_u32(protinfo[IFLA_INET6_FLAGS]);
		if (flags & IF_RA_MANAGED) {
			ni_debug_ifconfig("%s: obtain addrconf via DHCPv6", ifp->name);
		} else
		if (flags & IF_RA_OTHERCONF) {
			ni_debug_ifconfig("%s: obtain additional config via DHCPv6", ifp->name);
		}
	}

	return 0;
}

/*
 * Update interface address list given a RTM_NEWADDR message
 */
static int
__ni_interface_process_newaddr(ni_interface_t *ifp, struct nlmsghdr *h,
				struct ifaddrmsg *ifa, ni_handle_t *nih)
{
	struct nlattr *tb[IFA_MAX+1];
	ni_addrconf_lease_t *lease;
	ni_address_t tmp, *ap;

	if (nlmsg_parse(h, sizeof(*ifa), tb, IFA_MAX, NULL) < 0) {
		ni_error("unable to parse rtnl ADDR message");
		return -1;
	}
	memset(&tmp, 0, sizeof(tmp));

	/*
	 * Quoting linux/if_addr.h:
	 * IFA_ADDRESS is prefix address, rather than local interface address.
	 * It makes no difference for normally configured broadcast interfaces,
	 * but for point-to-point IFA_ADDRESS is DESTINATION address,
	 * local address is supplied in IFA_LOCAL attribute.
	 */
	if (ifp->link.ifflags & NI_IFF_POINT_TO_POINT) {
		__ni_nla_get_addr(ifa->ifa_family, &tmp.local_addr, tb[IFA_LOCAL]);
		__ni_nla_get_addr(ifa->ifa_family, &tmp.peer_addr, tb[IFA_ADDRESS]);
		/* Note iproute2 code obtains peer_addr from IFA_BROADCAST */
	} else {
		__ni_nla_get_addr(ifa->ifa_family, &tmp.local_addr, tb[IFA_ADDRESS]);
		__ni_nla_get_addr(ifa->ifa_family, &tmp.bcast_addr, tb[IFA_BROADCAST]);
	}
	__ni_nla_get_addr(ifa->ifa_family, &tmp.anycast_addr, tb[IFA_ANYCAST]);

	ap = ni_address_new(ifp, ifa->ifa_family, ifa->ifa_prefixlen, &tmp.local_addr);
	ap->scope = ifa->ifa_scope;
	ap->flags = ifa->ifa_flags;
	ap->peer_addr = tmp.peer_addr;
	ap->bcast_addr = tmp.bcast_addr;
	ap->anycast_addr = tmp.anycast_addr;

#if 0
	ni_debug_ifconfig("%-5s %-20s scope %s, flags%s%s%s",
				ifp->name, ni_address_print(&tmp.local_addr),
				(ifa->ifa_scope == RT_SCOPE_HOST)? "host" :
				 (ifa->ifa_scope == RT_SCOPE_LINK)? "link" :
				  (ifa->ifa_scope == RT_SCOPE_SITE)? "site" :
				   "universe",
				(ifa->ifa_flags & IFA_F_PERMANENT)? " permanent" : "",
				(ifa->ifa_flags & IFA_F_TEMPORARY)? " temporary" : "",
				(ifa->ifa_flags & IFA_F_TENTATIVE)? " tentative" : "");
#endif

	/* We don't have a strict criterion to distinguish autoconf addresses
	 * from manually assigned addresses. The best approximation is the
	 * IFA_F_PERMANENT flag, which is set for all statically assigned addresses,
	 * and for all link-local addresses. Strictly speaking, you can also administratively
	 * add interface addresses with a limited lifetime, but that would probably be done
	 * by some out-of-kernel autoconf mechanism, too.
	 */
	if (ifa->ifa_family == AF_INET6) {
		if (!(ifa->ifa_flags & IFA_F_PERMANENT)
		 || (ifa->ifa_scope == RT_SCOPE_LINK)) {
			ap->config_method = NI_ADDRCONF_AUTOCONF;
		}
	}

	if (ap->config_method == NI_ADDRCONF_STATIC && ni_address_probably_dynamic(ap))
		ap->config_method = NI_ADDRCONF_AUTOCONF;

	if (ap->config_method == NI_ADDRCONF_AUTOCONF) {
		/* FIXME: create a lease for AUTOCONF, and add this
		 * address to it. */
	}

	/* See if this address is owned by a lease */
	if (ap->config_method == NI_ADDRCONF_STATIC) {
		lease = __ni_interface_address_to_lease(ifp, ap);
		if (lease)
			ap->config_method = lease->type;
	}

	return 0;
}

int
__ni_interface_process_newroute(ni_interface_t *ifp, struct nlmsghdr *h,
				struct rtmsg *rtm, ni_handle_t *nih)
{
	ni_sockaddr_t src_addr, dst_addr, gw_addr;
	ni_addrconf_lease_t *lease;
	struct nlattr *tb[RTN_MAX+1];
	ni_route_t *rp;

	if (rtm->rtm_table != RT_TABLE_MAIN)
		return 0;

	if (rtm->rtm_protocol == RTPROT_REDIRECT)
		return 0;

	if (rtm->rtm_protocol != RTPROT_BOOT
	 && rtm->rtm_protocol != RTPROT_STATIC)
		return 0;

	memset(tb, 0, sizeof(tb));
	if (nlmsg_parse(h, sizeof(*rtm), tb, RTN_MAX, NULL) < 0) {
		ni_error("unable to parse rtnl ROUTE message");
		return -1;
	}

#if 0
	printf("RTM_NEWROUTE family=%d dstlen=%u srclen=%u type=%u proto=%d flags=0x%x table=%u\n",
			rtm->rtm_family,
			rtm->rtm_dst_len,
			rtm->rtm_src_len,
			rtm->rtm_type,
			rtm->rtm_protocol,
			rtm->rtm_flags,
			rtm->rtm_table
			);
#endif

	memset(&src_addr, 0, sizeof(src_addr));
	if (tb[RTA_SRC])
		__ni_nla_get_addr(rtm->rtm_family, &src_addr, tb[RTA_SRC]);

	memset(&dst_addr, 0, sizeof(dst_addr));
	if (rtm->rtm_dst_len != 0) {
		if (tb[RTA_DST] == NULL)
			return 0;
		__ni_nla_get_addr(rtm->rtm_family, &dst_addr, tb[RTA_DST]);
	}

	memset(&gw_addr, 0, sizeof(gw_addr));
	if (tb[RTA_GATEWAY] != NULL)
		__ni_nla_get_addr(rtm->rtm_family, &gw_addr, tb[RTA_GATEWAY]);

	if (rtm->rtm_src_len != 0) {
		static int warned = 0;

		if (!warned++)
			warn("Warning: encountered source route; cannot handle");
		return 0;
	}

#if 0
	if (dst_addr.ss_family == AF_UNSPEC)
		printf("Add route dst=default");
	else
		printf("Add route dst=%s/%u", ni_address_print(&dst_addr), rtm->rtm_dst_len);
	if (gw_addr.ss_family != AF_UNSPEC)
		printf(" gw=%s", ni_address_print(&gw_addr));
	if (ifp && ifp->ifindex)
		printf(" oif=%u", ifp->ifindex);
	printf("\n");
#endif

	rp = NULL;
	if (ifp) {
		rp = ni_interface_add_route(nih, ifp, rtm->rtm_dst_len, &dst_addr, &gw_addr);
	} else if (nih != NULL) {
		rp = ni_route_new(nih, rtm->rtm_dst_len, &dst_addr, &gw_addr);
	} else {
		return 0;
	}
	if (rp == NULL) {
		warn("error recording route");
		return 0;
	}

	if (tb[RTA_PRIORITY] != NULL)
		rp->priority = nla_get_u32(tb[RTA_PRIORITY]);
	rp->tos = rtm->rtm_tos;

	/* See if this route is owned by a lease */
	rp->config_method = NI_ADDRCONF_STATIC;
	if (ifp) {
		lease = __ni_interface_route_to_lease(ifp, rp);
		if (lease)
			rp->config_method = lease->type;
	}

	return 0;
}

/*
 * Discover bridge topology
 */
static int
__ni_discover_bridge(ni_interface_t *ifp)
{
	ni_bridge_t *bridge;
	ni_string_array_t ports;
	unsigned int i;

	if (ifp->link.type != NI_IFTYPE_BRIDGE)
		return 0;

	bridge = ni_interface_get_bridge(ifp);

	ni_sysfs_bridge_get_config(ifp->name, bridge);
	ni_sysfs_bridge_get_status(ifp->name, &bridge->status);

	ni_string_array_init(&ports);
	ni_sysfs_bridge_get_port_names(ifp->name, &ports);
	for (i = 0; i < ports.count; ++i)
		ni_bridge_add_port_name(bridge, ports.data[i]);
	ni_string_array_destroy(&ports);

	for (i = 0; i < bridge->ports.count; ++i) {
		ni_bridge_port_t *port = bridge->ports.data[i];
		ni_sysfs_bridge_port_get_config(port->name, port);
		ni_sysfs_bridge_port_get_status(port->name, &port->status);
	}

	return 0;
}

/*
 * Discover bonding configuration
 */
static int
__ni_discover_bond(ni_interface_t *ifp)
{
	ni_bonding_t *bonding;

	if (ifp->link.type != NI_IFTYPE_BOND)
		return 0;

	bonding = ni_interface_get_bonding(ifp);

	if (ni_bonding_parse_sysfs_attrs(ifp->name, bonding) < 0) {
		error("error retrieving bonding attribute from sysfs");
		return -1;
	}

	return 0;
}

/*
 * Discover whether we have any addrconf daemons running on this interface.
 */
int
__ni_discover_addrconf(ni_handle_t *nih, ni_interface_t *ifp)
{
	const ni_addrconf_t *acm;
	unsigned int pos;
	xml_node_t *xml = NULL;
	unsigned int i;

	__ni_assert_initialized();

	for (i = 0; i < __NI_ADDRCONF_MAX; ++i) {
		if (ni_addrconf_lease_is_valid(ifp->ipv4.lease[i]))
			ni_afinfo_addrconf_enable(&ifp->ipv4, i);
	}
	for (i = 0; i < __NI_ADDRCONF_MAX; ++i) {
		if (ni_addrconf_lease_is_valid(ifp->ipv6.lease[i]))
			ni_afinfo_addrconf_enable(&ifp->ipv6, i);
	}

	for (acm = ni_addrconf_list_first(&pos); acm; acm = ni_addrconf_list_next(&pos)) {
		if (!acm->test)
			continue;

		/* Represent interface as XML */
		if (xml == NULL) {
			xml = ni_syntax_xml_from_interface(ni_default_xml_syntax(), nih, ifp);
			if (!xml)
				return 0;
		}

		/* Check if the extension is active */
		if (ni_addrconf_check(acm, ifp, xml)) {
			debug_ifconfig("%s: %s is active on%s%s", ifp->name,
					ni_addrconf_type_to_name(acm->type),
					(acm->supported_af & NI_AF_MASK_IPV4)? " ipv4" : "",
					(acm->supported_af & NI_AF_MASK_IPV6)? " ipv6" : "");
			if (acm->supported_af & NI_AF_MASK_IPV4)
				ni_afinfo_addrconf_enable(&ifp->ipv4, acm->type);
			if (acm->supported_af & NI_AF_MASK_IPV6)
				ni_afinfo_addrconf_enable(&ifp->ipv6, acm->type);
		}
	}

	if (xml)
		xml_node_free(xml);
	return 0;
}
