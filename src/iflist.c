/*
 * Discover list of existing kernel interfaces and their state.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netlink/attr.h>
#include <netlink/msg.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/addrconf.h>
#include <wicked/route.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/system.h>
#include <wicked/vlan.h>
#include <wicked/wireless.h>
#include <wicked/infiniband.h>
#include <wicked/linkstats.h>

#include "netinfo_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "appconfig.h"

static int		__ni_process_ifinfomsg(ni_linkinfo_t *link, struct nlmsghdr *h,
					struct ifinfomsg *ifi, ni_netconfig_t *);
static int		__ni_netdev_process_newaddr(ni_netdev_t *dev, struct nlmsghdr *h,
					struct ifaddrmsg *ifa);
static int		__ni_netdev_process_newroute(ni_netdev_t *, struct nlmsghdr *,
					struct rtmsg *, ni_netconfig_t *);
static int		__ni_discover_bridge(ni_netdev_t *);
static int		__ni_discover_bond(ni_netdev_t *);
static int		__ni_discover_addrconf(ni_netdev_t *);
static int		__ni_discover_infiniband(ni_netdev_t *);
static ni_route_t *	__ni_netdev_add_autoconf_prefix(ni_netdev_t *, const ni_sockaddr_t *, unsigned int, const struct prefix_cacheinfo *);
static ni_addrconf_lease_t *__ni_netdev_get_autoconf_lease(ni_netdev_t *, unsigned int);

struct ni_rtnl_info {
	struct ni_nlmsg_list	nlmsg_list;
	struct ni_nlmsg *	entry;
};

struct ni_rtnl_query {
	struct ni_rtnl_info	link_info;
	struct ni_rtnl_info	addr_info;
	struct ni_rtnl_info	ipv6_info;
	struct ni_rtnl_info	route_info;
	unsigned int		ifindex;
};

/*
 * Query netlink for all relevant information
 */
static inline int
__ni_rtnl_query(struct ni_rtnl_info *qr, int af, int type)
{
	ni_nlmsg_list_init(&qr->nlmsg_list);
	if (ni_nl_dump_store(af, type, &qr->nlmsg_list) < 0)
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

static void
ni_rtnl_query_destroy(struct ni_rtnl_query *q)
{
	ni_nlmsg_list_destroy(&q->link_info.nlmsg_list);
	ni_nlmsg_list_destroy(&q->addr_info.nlmsg_list);
	ni_nlmsg_list_destroy(&q->ipv6_info.nlmsg_list);
	ni_nlmsg_list_destroy(&q->route_info.nlmsg_list);
}

static int
ni_rtnl_query(struct ni_rtnl_query *q, unsigned int ifindex)
{
	memset(q, 0, sizeof(*q));
	q->ifindex = ifindex;

	if (__ni_rtnl_query(&q->link_info, AF_UNSPEC, RTM_GETLINK) < 0
	 || __ni_rtnl_query(&q->ipv6_info, AF_INET6, RTM_GETLINK) < 0
	 || __ni_rtnl_query(&q->addr_info, AF_UNSPEC, RTM_GETADDR) < 0
	 || __ni_rtnl_query(&q->route_info, AF_UNSPEC, RTM_GETROUTE) < 0) {
		ni_rtnl_query_destroy(q);
		return -1;
	}

	return 0;
}

static int
ni_rtnl_query_link(struct ni_rtnl_query *q, unsigned int ifindex)
{
	memset(q, 0, sizeof(*q));
	q->ifindex = ifindex;

	if (__ni_rtnl_query(&q->link_info, AF_UNSPEC, RTM_GETLINK) < 0) {
		ni_rtnl_query_destroy(q);
		return -1;
	}

	return 0;
}

static int
ni_rtnl_query_ipv6_link(struct ni_rtnl_query *q, unsigned int ifindex)
{
	memset(q, 0, sizeof(*q));
	q->ifindex = ifindex;

	if (__ni_rtnl_query(&q->ipv6_info, AF_INET6, RTM_GETLINK) < 0) {
		ni_rtnl_query_destroy(q);
		return -1;
	}

	return 0;
}

static inline struct ifinfomsg *
ni_rtnl_query_next_link_info(struct ni_rtnl_query *q, struct nlmsghdr **hp)
{
	struct nlmsghdr *h;

	while ((h = __ni_rtnl_info_next(&q->link_info)) != NULL) {
		struct ifinfomsg *ifi;

		if ((ifi = ni_rtnl_ifinfomsg(h, RTM_NEWLINK)) != NULL) {
			if (!q->ifindex || q->ifindex == (unsigned int)ifi->ifi_index) {
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
			if (!q->ifindex || q->ifindex == (unsigned int)ifi->ifi_index) {
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
			if (!q->ifindex || q->ifindex == ifa->ifa_index) {
				*hp = h;
				return ifa;
			}
		}
	}
	return NULL;
}

static inline struct rtmsg *
ni_rtnl_query_next_route_info(struct ni_rtnl_query *q, struct nlmsghdr **hp, unsigned int *oif_idxp)
{
	struct nlmsghdr *h;

	while ((h = __ni_rtnl_info_next(&q->route_info)) != NULL) {
		unsigned oif_index = 0;
		struct nlattr *rta;
		struct rtmsg *rtm;

		if (!(rtm = ni_rtnl_rtmsg(h, RTM_NEWROUTE)))
			continue;

		rta = nlmsg_find_attr(h, sizeof(*rtm), RTA_OIF);
		if (rta != NULL)
			oif_index = nla_get_u32(rta);

		if (q->ifindex && oif_index != q->ifindex)
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
__ni_system_refresh_interfaces(ni_netconfig_t *nc)
{
	ni_assert(nc == ni_global_state_handle(0));
	return __ni_system_refresh_all(nc, NULL);
}

int
__ni_system_refresh_all(ni_netconfig_t *nc, ni_netdev_t **del_list)
{
	struct ni_rtnl_query query;
	struct nlmsghdr *h;
	ni_netdev_t **tail, *dev;
	unsigned int seqno;
	int res = -1;

	seqno = ++__ni_global_seqno;

	if (ni_rtnl_query(&query, 0) < 0)
		goto failed;

	/* Find tail of iflist */
	tail = ni_netconfig_device_list_head(nc);
	while ((dev = *tail) != NULL)
		tail = &dev->next;

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
		if ((dev = ni_netdev_by_index(nc, ifi->ifi_index)) == NULL) {
			ni_pci_dev_t *pci_dev;

			dev = ni_netdev_new(ifname, ifi->ifi_index);
			if (!dev)
				goto failed;

			if ((pci_dev = ni_sysfs_netdev_get_pci(ifname)) != NULL)
				ni_netdev_set_pci(dev, pci_dev);

			/* FIXME: use ni_netconfig_device_append() */
			*tail = dev;
			tail = &dev->next;
		} else {
			/* Clear out addresses and routes */
			ni_netdev_clear_addresses(dev);
			ni_netdev_clear_routes(dev);
		}

		dev->seq = seqno;

		if (__ni_netdev_process_newlink(dev, h, ifi, nc) < 0)
			ni_error("Problem parsing RTM_NEWLINK message for %s", ifname);
	}

	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next) {
		if (dev->link.vlan && ni_netdev_ref_bind_ifindex(&dev->link.vlan->parent, nc) < 0) {
			ni_error("VLAN interface %s references unknown base interface (ifindex %u)",
				dev->name, dev->link.vlan->parent.index);
			/* Ignore error and proceed */
			ni_string_dup(&dev->link.vlan->parent.name, "unknown");
		}
	}

	while (1) {
		struct ifinfomsg *ifi;

		if (!(ifi = ni_rtnl_query_next_ipv6_link_info(&query, &h)))
			break;

		if ((dev = ni_netdev_by_index(nc, ifi->ifi_index)) == NULL)
			continue;

		if (__ni_netdev_process_newlink_ipv6(dev, h, ifi) < 0)
			ni_error("Problem parsing IPv6 RTM_NEWLINK message for %s", dev->name);
	}

	while (1) {
		struct ifaddrmsg *ifa;

		if (!(ifa = ni_rtnl_query_next_addr_info(&query, &h)))
			break;

		if ((dev = ni_netdev_by_index(nc, ifa->ifa_index)) == NULL)
			continue;

		if (__ni_netdev_process_newaddr(dev, h, ifa) < 0)
			ni_error("Problem parsing RTM_NEWADDR message for %s", dev->name);
	}

	while (1) {
		struct rtmsg *rtm;
		unsigned int oif_index = 0;

		if (!(rtm = ni_rtnl_query_next_route_info(&query, &h, &oif_index)))
			break;

		if (oif_index) {
			dev = ni_netdev_by_index(nc, oif_index);
			if (dev == NULL) {
				ni_error("route specifies OIF=%u; not found!", oif_index);
				continue;
			}
		} else {
			dev = NULL;
		}

		if (__ni_netdev_process_newroute(dev, h, rtm, nc) < 0)
			ni_error("Problem parsing RTM_NEWROUTE message");
	}

	/* Cull any interfaces that went away */
	tail = ni_netconfig_device_list_head(nc);
	while ((dev = *tail) != NULL) {
		if (dev->seq != seqno) {
			*tail = dev->next;
			if (del_list == NULL) {
				ni_netdev_put(dev);
			} else {
				dev->next = NULL;
				*del_list = dev;
				del_list = &dev->next;
			}
		} else {
			tail = &dev->next;
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
__ni_system_refresh_interface(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	struct ni_rtnl_query query;
	struct nlmsghdr *h;
	int res = -1;

	__ni_global_seqno++;

	if (ni_rtnl_query(&query, dev->link.ifindex) < 0)
		goto failed;

	while (1) {
		struct ifinfomsg *ifi;

		if (!(ifi = ni_rtnl_query_next_link_info(&query, &h)))
			break;

		/* Clear out addresses and routes */
		ni_netdev_clear_addresses(dev);
		ni_netdev_clear_routes(dev);

		if (__ni_netdev_process_newlink(dev, h, ifi, nc) < 0)
			ni_error("Problem parsing RTM_NEWLINK message for %s", dev->name);
	}

	while (1) {
		struct ifaddrmsg *ifa;

		if (!(ifa = ni_rtnl_query_next_addr_info(&query, &h)))
			break;

		if (__ni_netdev_process_newaddr(dev, h, ifa) < 0)
			ni_error("Problem parsing RTM_NEWADDR message for %s", dev->name);
	}

	while (1) {
		struct rtmsg *rtm;

		if (!(rtm = ni_rtnl_query_next_route_info(&query, &h, NULL)))
			break;

		if (__ni_netdev_process_newroute(dev, h, rtm, NULL) < 0)
			ni_error("Problem parsing RTM_NEWROUTE message");
	}

	res = 0;

failed:
	ni_rtnl_query_destroy(&query);
	return res;
}

/*
 * Refresh the link info of one interface
 */
int
__ni_device_refresh_link_info(ni_netconfig_t *nc, ni_linkinfo_t *link)
{
	struct ni_rtnl_query query;
	struct nlmsghdr *h;
	int rv = 0;

	__ni_global_seqno++;

	if ((rv = ni_rtnl_query_link(&query, link->ifindex)) < 0)
		goto done;

	while (1) {
		struct ifinfomsg *ifi;

		if (!(ifi = ni_rtnl_query_next_link_info(&query, &h)))
			break;

		if ((rv = __ni_process_ifinfomsg(link, h, ifi, nc)) < 0) {
			ni_error("Problem parsing RTM_NEWLINK message");
			goto done;
		}
	}

done:
	ni_rtnl_query_destroy(&query);
	return rv;
}

/*
 * Refresh the ipv6 link info of one interface
 */
int
__ni_device_refresh_ipv6_link_info(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	struct ni_rtnl_query query;
	struct nlmsghdr *h;
	int rv = 0;

	(void)nc; /* unused */

	__ni_global_seqno++;

	if ((rv = ni_rtnl_query_ipv6_link(&query, dev->link.ifindex)) < 0)
		goto done;

	while (1) {
		struct ifinfomsg *ifi;

		if (!(ifi = ni_rtnl_query_next_ipv6_link_info(&query, &h)))
			break;

		if (ifi->ifi_family != AF_INET6)
			continue;
		if (ifi->ifi_index <= 0)
			continue;
		if ((unsigned int)ifi->ifi_index != dev->link.ifindex)
			continue;

		if ((rv = __ni_netdev_process_newlink_ipv6(dev, h, ifi)) < 0) {
			ni_error("Problem parsing IPv6 RTM_NEWLINK message for %s",
				dev->name);
			goto done;
		}
	}

done:
	ni_rtnl_query_destroy(&query);
	return rv;
}

/*
 * Refresh interface statistics.
 * We assume that IFLA_STATS have already been covered by a generic ni_refresh;
 * all we want to do here is potentially retrieve additional stats eg via
 * ethtool.
 */
int
__ni_system_interface_stats_refresh(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	int rv = 0;

	if (dev->link.ethtool_stats
	 && (rv = __ni_ethtool_stats_refresh(dev->name, dev->link.ethtool_stats)) < 0)
		return rv;

	/* More stats may go here, such as routing statistics */

	return 0;
}

/*
 * Translate interface flags
 */
unsigned int
__ni_netdev_translate_ifflags(unsigned int ifflags)
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
 * Refresh interface link layer given a parsed RTM_NEWLINK message attrs
 */
static int
__ni_process_ifinfomsg_linkinfo(ni_linkinfo_t *link, const char *ifname,
				struct nlattr **tb, struct nlmsghdr *h,
				struct ifinfomsg *ifi, ni_netconfig_t *nc)
{
	link->arp_type = ifi->ifi_type;
	link->ifflags = __ni_netdev_translate_ifflags(ifi->ifi_flags);
	link->type = NI_IFTYPE_UNKNOWN; /* FIXME: we do we reset this?! */

	if (tb[IFLA_MTU])
		link->mtu = nla_get_u32(tb[IFLA_MTU]);
	if (tb[IFLA_TXQLEN])
		link->txqlen = nla_get_u32(tb[IFLA_TXQLEN]);
	if (tb[IFLA_COST])
		link->metric = nla_get_u32(tb[IFLA_COST]);
	if (tb[IFLA_QDISC])
		ni_string_dup(&link->qdisc, nla_get_string(tb[IFLA_QDISC]));
	if (tb[IFLA_MASTER])
		link->master = nla_get_u32(tb[IFLA_MASTER]);
	if (tb[IFLA_IFALIAS])
		ni_string_dup(&link->alias, nla_get_string(tb[IFLA_IFALIAS]));
	if (tb[IFLA_OPERSTATE]) {
		/* get the RFC 2863 operational status - IF_OPER_* */
		link->oper_state = nla_get_u8(tb[IFLA_OPERSTATE]);
	}

	if (tb[IFLA_STATS]) {
		struct rtnl_link_stats *s = nla_data(tb[IFLA_STATS]);
		ni_link_stats_t *n;

		if (!link->stats)
			link->stats = calloc(1, sizeof(*n));
		n = link->stats;

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
		struct nlattr *nl_linkinfo[IFLA_INFO_MAX+1];

		if (nla_parse_nested(nl_linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL) < 0) {
			ni_error("unable to parse IFLA_LINKINFO");
			return -1;
		}
		ni_string_dup(&link->kind, nla_get_string(nl_linkinfo[IFLA_INFO_KIND]));

		if (link->kind && !strcmp(link->kind, "vlan")) {
			struct nlattr *vlan_info[IFLA_VLAN_MAX+1];
			ni_vlan_t *vlan;

			/* There's more info in this LINKINFO; extract it in the caller
			 * as we don't have access to the containing ni_netdev_t here */
			link->type = NI_IFTYPE_VLAN;

			if (!(vlan = link->vlan))
				link->vlan = vlan = ni_vlan_new();

			/* IFLA_LINK contains the ifindex of the real ether dev */
			if (tb[IFLA_LINK]) {
				vlan->parent.index = nla_get_u32(tb[IFLA_LINK]);

				if (ni_netdev_ref_bind_ifname(&vlan->parent, nc) < 0) {
					ni_error("VLAN interface %s references unknown base interface (ifindex %u)",
							ifname, vlan->parent.index);
					/* Ignore error and proceed */
				}
			} else {
				ni_netdev_ref_destroy(&vlan->parent);
			}

			if (nla_parse_nested(vlan_info, IFLA_VLAN_MAX, nl_linkinfo[IFLA_INFO_DATA], NULL) >= 0)
				vlan->tag = nla_get_u16(vlan_info[IFLA_VLAN_ID]);
		}
	}

	if (link->type == NI_IFTYPE_UNKNOWN) {
		struct ethtool_drvinfo drv_info;

		switch (link->arp_type) {
		case ARPHRD_ETHER:
		case ARPHRD_NONE:	/* tun driver uses this */
			link->type = NI_IFTYPE_ETHERNET;
			memset(&drv_info, 0, sizeof(drv_info));
			if (__ni_ethtool(ifname, ETHTOOL_GDRVINFO, &drv_info) >= 0) {
				const char *driver = drv_info.driver;

				if (!strcmp(driver, "tun")) {
					/* tun/tap driver */
					if (!strcmp(drv_info.bus_info, "tap"))
						link->type = NI_IFTYPE_TAP;
					else
						link->type = NI_IFTYPE_TUN;
				} else if (!strcmp(driver, "bridge")) {
					link->type = NI_IFTYPE_BRIDGE;
				} else if (!strcmp(driver, "bonding")) {
					link->type = NI_IFTYPE_BOND;
				}

				if (drv_info.n_stats != 0 && link->ethtool_stats == NULL)
					link->ethtool_stats = __ni_ethtool_stats_init(ifname, &drv_info);
			}

			/* Detect WLAN device.
			 * The official way of doing this is to check whether
			 * ioctl(SIOCGIWNAME) succeeds.
			 */
			if (__ni_wireless_get_name(ifname, NULL, 0) == 0)
				link->type = NI_IFTYPE_WIRELESS;
			break;

		case ARPHRD_INFINIBAND:
			link->type = NI_IFTYPE_INFINIBAND;
			if (ni_sysfs_bonding_is_master(ifname))
				link->type = NI_IFTYPE_BOND;
			else if (ni_sysfs_netif_exists(ifname, "parent"))
				link->type = NI_IFTYPE_INFINIBAND_CHILD;
			break;

		default:
			link->type = ni_arphrd_type_to_iftype(link->arp_type);
			break;
		}
	}

	if (tb[IFLA_ADDRESS]) {
		unsigned int alen = nla_len(tb[IFLA_ADDRESS]);
		void *data = nla_data(tb[IFLA_ADDRESS]);

		if (alen > sizeof(link->hwaddr.data))
			alen = sizeof(link->hwaddr.data);
		memcpy(link->hwaddr.data, data, alen);
		link->hwaddr.len = alen;
		link->hwaddr.type = link->type;
	} else {
		memset(&link->hwaddr, 0, sizeof(link->hwaddr));
	}

	return 0;
}

/*
 * Refresh interface ipv6 protocol info given a parsed RTM_NEWLINK message attr
 */
static int
__ni_process_ifinfomsg_ipv6info(ni_netdev_t *dev, struct nlattr *ifla_protinfo)
{
	if (ifla_protinfo) {
		struct nlattr *ipv6info[IFLA_INET6_MAX + 1];
		unsigned int flags = 0;
		ni_ipv6_devinfo_t *ipv6;

		nla_parse_nested(ipv6info, IFLA_INET6_MAX, ifla_protinfo, NULL);
		if (ipv6info[IFLA_INET6_FLAGS])
			flags = nla_get_u32(ipv6info[IFLA_INET6_FLAGS]);

		ipv6 = ni_netdev_get_ipv6(dev);
		if (flags & IF_RA_MANAGED) {
			ipv6->radv.managed_addr = TRUE;
			ipv6->radv.other_config = TRUE;
			ni_debug_ifconfig("%s: obtain addrconf via DHCPv6", dev->name);
		} else
		if (flags & IF_RA_OTHERCONF) {
			ipv6->radv.managed_addr = FALSE;
			ipv6->radv.other_config = TRUE;
			ni_debug_ifconfig("%s: obtain additional config via DHCPv6", dev->name);
		} else {
			ipv6->radv.managed_addr = FALSE;
			ipv6->radv.other_config = FALSE;
			ni_debug_ifconfig("%s: no DHCPv6 config suggestion in RA", dev->name);
		}
	}
	return 0;
}

/*
 * Refresh interface link layer given a RTM_NEWLINK message
 */
int
__ni_process_ifinfomsg(ni_linkinfo_t *link, struct nlmsghdr *h,
				struct ifinfomsg *ifi, ni_netconfig_t *nc)
{
	struct nlattr *tb[IFLA_MAX+1];
	char *ifname;

	memset(tb, 0, sizeof(tb));
	if (nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, NULL) < 0) {
		ni_error("unable to parse rtnl LINK message");
		return -1;
	}

	if ((ifname = (char *) nla_data(tb[IFLA_IFNAME])) == NULL) {
		ni_warn("RTM_NEWLINK message without IFNAME");
		return -1;
	}

	return __ni_process_ifinfomsg_linkinfo(link, ifname, tb, h, ifi, nc);
}


/*
 * Refresh complete interface link info given a RTM_NEWLINK message
 */
int
__ni_netdev_process_newlink(ni_netdev_t *dev, struct nlmsghdr *h,
				struct ifinfomsg *ifi, ni_netconfig_t *nc)
{
	struct nlattr *tb[IFLA_MAX+1];
	char *ifname;
	int rv;

	memset(tb, 0, sizeof(tb));
	if (nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, NULL) < 0) {
		ni_error("unable to parse rtnl LINK message");
		return -1;
	}

	if ((ifname = (char *) nla_data(tb[IFLA_IFNAME])) == NULL) {
		ni_warn("RTM_NEWLINK message without IFNAME");
		return -1;
	} else if (!dev->name || !ni_string_eq(dev->name, ifname)) {
		ni_string_dup(&dev->name, ifname);
	}

	rv = __ni_process_ifinfomsg_linkinfo(&dev->link, dev->name, tb, h, ifi, nc);
	if (rv < 0)
		return rv;

#if 0
	ni_debug_ifconfig("%s: ifi flags:%s%s%s, my flags:%s%s%s, oper_state=%d/%s", dev->name,
		(ifi->ifi_flags & IFF_RUNNING)? " running" : "",
		(ifi->ifi_flags & IFF_LOWER_UP)? " lower_up" : "",
		(ifi->ifi_flags & IFF_UP)? " up" : "",
		(dev->link.ifflags & NI_IFF_DEVICE_UP)? " device-up" : "",
		(dev->link.ifflags & NI_IFF_LINK_UP)? " link-up" : "",
		(dev->link.ifflags & NI_IFF_NETWORK_UP)? " network-up" : "",
		dev->link.oper_state,
		ni_oper_state_type_to_name(dev->link.oper_state));
#endif

	ni_system_ipv4_devinfo_get(dev, NULL);
	ni_system_ipv6_devinfo_get(dev, NULL);

	__ni_process_ifinfomsg_ipv6info(dev, tb[IFLA_PROTINFO]);

	switch (dev->link.type) {
	case NI_IFTYPE_ETHERNET:
		__ni_system_ethernet_refresh(dev);
		break;

	case NI_IFTYPE_INFINIBAND:
	case NI_IFTYPE_INFINIBAND_CHILD:
		__ni_discover_infiniband(dev);
		break;

	case NI_IFTYPE_BRIDGE:
		__ni_discover_bridge(dev);
		break;
	case NI_IFTYPE_BOND:
		__ni_discover_bond(dev);
		break;

	case NI_IFTYPE_WIRELESS:
		rv = ni_wireless_interface_refresh(dev);
		if (rv == -NI_ERROR_RADIO_DISABLED) {
			ni_debug_ifconfig("%s: radio disabled, not refreshing wireless info", dev->name);
			ni_netdev_set_wireless(dev, NULL);
		} else 
		if (rv < 0)
			ni_error("%s: failed to refresh wireless info", dev->name);
		break;

	default:
		break;
	}

	/* Check if we have DHCP running for this interface */
	__ni_discover_addrconf(dev);

	return 0;
}

/*
 * Refresh interface link layer IPv6 info given a RTM_NEWLINK message
 */
int
__ni_netdev_process_newlink_ipv6(ni_netdev_t *dev, struct nlmsghdr *h, struct ifinfomsg *ifi)
{
	struct nlattr *tb[IFLA_MAX+1];

	if (nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, NULL) < 0) {
		ni_error("unable to parse rtnl LINK message");
		return -1;
	}

	return __ni_process_ifinfomsg_ipv6info(dev, tb[IFLA_PROTINFO]);
}

/*
 * Parse IPv6 prefixes received via router advertisements
 */
int
__ni_rtnl_parse_newprefix(const char *ifname, struct nlmsghdr *h, struct prefixmsg *pfx,
				ni_ipv6_ra_pinfo_t *pi)
{
	struct nlattr *tb[PREFIX_MAX+1];
	const struct prefix_cacheinfo *cache_info = NULL;

	if (pfx->prefix_family != AF_INET6) {
		ni_error("%s: not a rtnl IPv6 prefix info message", ifname);
		return -1;
	}
	if (nlmsg_parse(h, sizeof(*pfx), tb, PREFIX_MAX, NULL) < 0) {
		ni_error("%s: unable to parse rtnl PREFIX message", ifname);
		return -1;
	}

	if (tb[PREFIX_ADDRESS] == NULL) {
		ni_error("%s: rtnl NEWPREFIX message without address", ifname);
		return -1;
	}
	__ni_nla_get_addr(pfx->prefix_family, &pi->prefix, tb[PREFIX_ADDRESS]);
	if (pi->prefix.ss_family != AF_INET6) {
		ni_error("%s: unable to parse rtnl PREFIX address", ifname);
		return -1;
	}

	if (tb[PREFIX_CACHEINFO]) {
		cache_info = (struct prefix_cacheinfo *) tb[PREFIX_CACHEINFO];
		pi->lifetime.preferred_lft = cache_info->preferred_time;
		pi->lifetime.valid_lft = cache_info->valid_time;
	} else {
		ni_error("%s: rtnl PREFIX message without lifetimes", ifname);
		return -1;
	}

	pi->length = pfx->prefix_len;
	pi->on_link = pfx->prefix_flags & IF_PREFIX_ONLINK;
	pi->autoconf = pfx->prefix_flags & IF_PREFIX_AUTOCONF;
	return 0;
}

/*
 * Record IPv6 prefixes received via router advertisements
 */
int
__ni_netdev_process_newprefix(ni_netdev_t *dev, struct nlmsghdr *h, struct prefixmsg *pfx)
{
	struct nlattr *tb[PREFIX_MAX+1];
	const struct prefix_cacheinfo *cache_info = NULL;
	ni_sockaddr_t address;

	if (pfx->prefix_family != AF_INET6)
		return 0;

	/* We're only interested in recording address prefixes that
	 * can be used for autoconf */
	if (!(pfx->prefix_flags & IF_PREFIX_AUTOCONF))
		return 0;

	if (nlmsg_parse(h, sizeof(*pfx), tb, PREFIX_MAX, NULL) < 0) {
		ni_error("%s: unable to parse rtnl PREFIX message", dev->name);
		return -1;
	}

	if (tb[PREFIX_ADDRESS] == NULL) {
		ni_error("%s: rtnl NEWPREFIX message without address", dev->name);
		return -1;
	}

	if (tb[PREFIX_CACHEINFO])
		cache_info = (struct prefix_cacheinfo *) tb[PREFIX_CACHEINFO];


	__ni_nla_get_addr(pfx->prefix_family, &address, tb[PREFIX_ADDRESS]);

	/*
	 * FIXME: I don't really see the reason to fake routes;
	 *        the kernel creates routes and we receive them.
	 */
	if (__ni_netdev_add_autoconf_prefix(dev, &address, pfx->prefix_len, cache_info) == NULL)
		return -1;
	return 0;
}

ni_route_t *
__ni_netdev_add_autoconf_prefix(ni_netdev_t *dev, const ni_sockaddr_t *addr, unsigned int pfxlen, const struct prefix_cacheinfo *cache_info)
{
	ni_addrconf_lease_t *lease;
	ni_route_table_t *tab;
	ni_route_t *rp = NULL;
	unsigned int i;

	ni_debug_ifconfig("%s(dev=%s, prefix=%s/%u", __func__, dev->name, ni_sockaddr_print(addr), pfxlen);

	lease = __ni_netdev_get_autoconf_lease(dev, addr->ss_family);
	if ((tab = ni_route_tables_find(lease->routes, RT_TABLE_MAIN))) {
		for (i = 0; i < tab->routes.count; ++i) {
			rp = tab->routes.data[i];

			if (rp->prefixlen == pfxlen
			&& ni_sockaddr_prefix_match(pfxlen, &rp->destination, addr))
				break;

			rp = NULL;
		}
	}

	if (rp == NULL) {
		rp = ni_route_create(pfxlen, addr, NULL, 0, &lease->routes);
	}

	if (cache_info && rp) {
		rp->ipv6_cache_info.valid_lft = cache_info->valid_time;
		rp->ipv6_cache_info.preferred_lft = cache_info->preferred_time;
	}

	return rp;
}

/*
 * Update interface address list given a RTM_NEWADDR message
 */
int
__ni_rtnl_parse_newaddr(unsigned ifflags, struct nlmsghdr *h, struct ifaddrmsg *ifa, ni_address_t *ap)
{
	struct nlattr *tb[IFA_MAX+1];

	memset(tb, 0, sizeof(tb));
	if (nlmsg_parse(h, sizeof(*ifa), tb, IFA_MAX, NULL) < 0) {
		ni_error("unable to parse rtnl ADDR message");
		return -1;
	}

	memset(ap, 0, sizeof(*ap));
	ap->family	= ifa->ifa_family;
	ap->prefixlen	= ifa->ifa_prefixlen;
	ap->scope	= ifa->ifa_scope;
	ap->flags	= ifa->ifa_flags;

	/*
	 * Quoting linux/if_addr.h:
	 * IFA_ADDRESS is prefix address, rather than local interface address.
	 * It makes no difference for normally configured broadcast interfaces,
	 * but for point-to-point IFA_ADDRESS is DESTINATION address,
	 * local address is supplied in IFA_LOCAL attribute.
	 */
	if (ifflags & NI_IFF_POINT_TO_POINT) {
		__ni_nla_get_addr(ifa->ifa_family, &ap->local_addr, tb[IFA_LOCAL]);
		__ni_nla_get_addr(ifa->ifa_family, &ap->peer_addr, tb[IFA_ADDRESS]);
		/* Note iproute2 code obtains peer_addr from IFA_BROADCAST */
		/* When I read and remember it correctly, iproute2 is using:
		 *   !tb[IFA_BROADCAST] && tb[IFA_LOCAL] && tb[IFA_ADDRESS]
		 * instead of the p-t-p flag ...
		 */
	} else {
		__ni_nla_get_addr(ifa->ifa_family, &ap->local_addr, tb[IFA_ADDRESS]);
		if (tb[IFA_BROADCAST]) {
			__ni_nla_get_addr(ifa->ifa_family, &ap->bcast_addr, tb[IFA_BROADCAST]);
		} else if(ifa->ifa_family == AF_INET && tb[IFA_ADDRESS] && ifa->ifa_prefixlen < 32) {
			ap->bcast_addr = ap->local_addr;
			ap->bcast_addr.sin.sin_addr.s_addr |= htonl(0xFFFFFFFFUL >> ifa->ifa_prefixlen);
		}
	}
	__ni_nla_get_addr(ifa->ifa_family, &ap->anycast_addr, tb[IFA_ANYCAST]);

	if (tb[IFA_CACHEINFO]) {
		struct ifa_cacheinfo *ci = (struct ifa_cacheinfo *) tb[IFA_CACHEINFO];

		ap->ipv6_cache_info.valid_lft = ci->ifa_valid;
		ap->ipv6_cache_info.preferred_lft = ci->ifa_prefered;
	}

	if (tb[IFA_LABEL] != NULL)
		ni_string_dup(&ap->label, nla_get_string(tb[IFA_LABEL]));

	return 0;
}

int
__ni_netdev_process_newaddr_event(ni_netdev_t *dev, struct nlmsghdr *h, struct ifaddrmsg *ifa, const ni_address_t **hint)
{
	ni_addrconf_lease_t *lease = NULL;
	ni_address_t tmp, *ap;

	if (__ni_rtnl_parse_newaddr(dev->link.ifflags, h, ifa, &tmp) < 0)
		return -1;

	ap = ni_address_list_find(dev->addrs, &tmp.local_addr);
	if (!ap) {
		ap = ni_netdev_add_address(dev, tmp.family, tmp.prefixlen, &tmp.local_addr);
	}
	ap->scope = tmp.scope;
	ap->flags = tmp.flags;
	ap->peer_addr = tmp.peer_addr;
	ap->bcast_addr = tmp.bcast_addr;
	ap->anycast_addr = tmp.anycast_addr;
	ap->ipv6_cache_info = tmp.ipv6_cache_info;
	if (!ni_string_eq(ap->label, tmp.label)) {
		ni_string_dup(&ap->label, tmp.label);
	}
	ni_string_free(&tmp.label);

	if (ap->config_lease == NULL)
		lease = __ni_netdev_address_to_lease(dev, ap);

	if (lease == NULL) {
		int probably_autoconf = 0;

		/* We don't have a strict criterion to distinguish autoconf addresses
		 * from manually assigned addresses. The best approximation is the
		 * IFA_F_PERMANENT flag, which is set for all statically assigned addresses,
		 * and for all link-local addresses. Strictly speaking, you can also administratively
		 * add interface addresses with a limited lifetime, but that would probably be done
		 * by some out-of-kernel autoconf mechanism, too.
		 */
		if (ifa->ifa_family == AF_INET6) {
			if (!(ifa->ifa_flags & IFA_F_PERMANENT) || (ifa->ifa_scope == RT_SCOPE_LINK))
				probably_autoconf = 1;
			else if (ni_address_probably_dynamic(ap))
				probably_autoconf = 1;
		} else
		if (ifa->ifa_family == AF_INET) {
			probably_autoconf = ni_address_probably_dynamic(ap);
		}

		if (probably_autoconf)
			lease = __ni_netdev_get_autoconf_lease(dev, ifa->ifa_family);
	}

	ap->config_lease = lease;

#if 0
	ni_debug_ifconfig("%s[%u]: address %s scope %s, flags%s%s%s%s%s%s%s%s [%02x], lft{%u,%u}, owned by %s",
			dev->name, dev->link.ifindex,
			ni_sockaddr_print(&ap->local_addr),
			(ap->scope == RT_SCOPE_HOST)? "host" :
			 (ap->scope == RT_SCOPE_LINK)? "link" :
			  (ap->scope == RT_SCOPE_SITE)? "site" :
			   "universe",
			(ap->flags & IFA_F_TEMPORARY)?   " temporary" : "",
			(ap->flags & IFA_F_PERMANENT)?   " permanent" : " dynamic",
			(ap->flags & IFA_F_TENTATIVE)?   " tentative" : "",
			(ap->flags & IFA_F_DADFAILED)?   " dadfailed" : "",
			(ap->flags & IFA_F_DEPRECATED)?  " deprecated": "",
			(ap->flags & IFA_F_OPTIMISTIC)?  " optimistic": "",
			(ap->flags & IFA_F_HOMEADDRESS)? " home"      : "",
			(ap->flags & IFA_F_NODAD)?       " nodad"     : "",
			(unsigned int)ap->flags,
			ap->ipv6_cache_info.valid_lft,
			ap->ipv6_cache_info.preferred_lft,
			(ap->config_lease? ni_addrconf_type_to_name(ap->config_lease->type) : "nobody"));
#endif

	if (hint)
		*hint = ap;

	return 0;
}

static int
__ni_netdev_process_newaddr(ni_netdev_t *dev, struct nlmsghdr *h, struct ifaddrmsg *ifa)
{
	return __ni_netdev_process_newaddr_event(dev, h, ifa, NULL);
}

int
__ni_netdev_process_newroute(ni_netdev_t *dev, struct nlmsghdr *h,
				struct rtmsg *rtm, ni_netconfig_t *nc)
{
	ni_sockaddr_t src_addr, dst_addr, gw_addr;
	ni_addrconf_lease_t *lease;
	struct nlattr *tb[RTN_MAX+1];
	ni_route_t *rp;

	if (rtm->rtm_table != RT_TABLE_MAIN)
		return 0;

	switch (rtm->rtm_protocol) {
	case RTPROT_REDIRECT:
		return 0;

	default:
		break;
	}

	memset(tb, 0, sizeof(tb));
	if (nlmsg_parse(h, sizeof(*rtm), tb, RTN_MAX, NULL) < 0) {
		ni_error("unable to parse rtnl ROUTE message");
		return -1;
	}

#if 0
	ni_debug_ifconfig("RTM_NEWROUTE family=%d dstlen=%u srclen=%u type=%s proto=%s flags=0x%x table=%s scope=%s",
			rtm->rtm_family,
			rtm->rtm_dst_len,
			rtm->rtm_src_len,
			ni_route_type_type_to_name(rtm->rtm_type),
			ni_route_protocol_type_to_name(rtm->rtm_protocol),
			rtm->rtm_flags,
			ni_route_table_type_to_name(rtm->rtm_table),
			ni_route_scope_type_to_name(rtm->rtm_scope)
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
			ni_warn("Warning: encountered source route; cannot handle");
		return 0;
	}

#if 0
	if (dst_addr.ss_family == AF_UNSPEC)
		printf("Add route dst=default");
	else
		printf("Add route dst=%s/%u", ni_sockaddr_print(&dst_addr), rtm->rtm_dst_len);
	if (gw_addr.ss_family != AF_UNSPEC)
		printf(" gw=%s", ni_sockaddr_print(&gw_addr));
	if (dev && dev->link.ifindex)
		printf(" oif=%u", dev->link.ifindex);
	printf("\n");
#endif

	rp = NULL;
	if (dev) {
		rp = ni_netdev_add_route(dev, rtm->rtm_dst_len, &dst_addr, &gw_addr, rtm->rtm_table);
	}
	if (rp == NULL) {
		ni_warn("error recording route");
		return 0;
	}

	rp->type = rtm->rtm_type;
	rp->scope = rtm->rtm_scope;
	rp->protocol = rtm->rtm_protocol;
	rp->table = rtm->rtm_table;
	rp->tos = rtm->rtm_tos;

	if (tb[RTA_PRIORITY] != NULL)
		rp->priority = nla_get_u32(tb[RTA_PRIORITY]);

	if (tb[RTA_METRICS] != NULL) {
		struct nlattr *rtattrs[__RTAX_MAX+1], *rtax;

		if (nla_parse_nested(rtattrs, __RTAX_MAX, tb[RTA_METRICS], NULL) < 0) {
			ni_error("unable to parse RTA_METRICS");
			return -1;
		}
		if ((rtax = rtattrs[RTAX_MTU]) != NULL)
			rp->mtu = nla_get_u32(rtax);
		if ((rtax = rtattrs[RTAX_WINDOW]) != NULL)
			rp->window = nla_get_u32(rtax);
		if ((rtax = rtattrs[RTAX_RTT]) != NULL)
			rp->rtt = nla_get_u32(rtax);
		if ((rtax = rtattrs[RTAX_RTTVAR]) != NULL)
			rp->rttvar = nla_get_u32(rtax);
		if ((rtax = rtattrs[RTAX_SSTHRESH]) != NULL)
			rp->ssthresh = nla_get_u32(rtax);
		if ((rtax = rtattrs[RTAX_CWND]) != NULL)
			rp->cwnd = nla_get_u32(rtax);
		if ((rtax = rtattrs[RTAX_INITCWND]) != NULL)
			rp->initcwnd = nla_get_u32(rtax);
		if ((rtax = rtattrs[RTAX_ADVMSS]) != NULL)
			rp->advmss = nla_get_u32(rtax);
		if ((rtax = rtattrs[RTAX_HOPLIMIT]) != NULL)
			rp->hoplimit = nla_get_u32(rtax);
		if ((rtax = rtattrs[RTAX_RTO_MIN]) != NULL)
			rp->rto_min = nla_get_u32(rtax);
	}

	/* See if this route is owned by a lease */
	if (dev) {
		lease = __ni_netdev_route_to_lease(dev, rp);
		if (lease)
			rp->config_lease = lease;
	}

	return 0;
}

ni_addrconf_lease_t *
__ni_netdev_get_autoconf_lease(ni_netdev_t *dev, unsigned int af)
{
	ni_addrconf_lease_t *lease;

	if ((lease = ni_netdev_get_lease(dev, af, NI_ADDRCONF_AUTOCONF)) == NULL) {
		lease = ni_addrconf_lease_new(NI_ADDRCONF_AUTOCONF, af);
		lease->state = NI_ADDRCONF_STATE_GRANTED;
		ni_netdev_set_lease(dev, lease);

		/* In the IPv6 case, add the default prefix for link-local autoconf.
		 * This is always on. */
		if (af == AF_INET6) {
			ni_sockaddr_t prefix;

			ni_sockaddr_parse(&prefix, "fe80::", AF_INET6);
			ni_route_create(64, &prefix, NULL, 0, &lease->routes);
		}
	}
	return lease;
}

void
__ni_netdev_track_ipv6_autoconf(ni_netdev_t *dev, int enable)
{
	if (!enable) {
		ni_netdev_unset_lease(dev, AF_INET6, NI_ADDRCONF_AUTOCONF);
	} else {
		(void) __ni_netdev_get_autoconf_lease(dev, AF_INET6);
	}
}

/*
 * Discover bridge topology
 */
static int
__ni_discover_bridge(ni_netdev_t *dev)
{
	ni_bridge_t *bridge;
	ni_string_array_t ports;
	unsigned int i;

	if (dev->link.type != NI_IFTYPE_BRIDGE)
		return 0;

	bridge = ni_netdev_get_bridge(dev);

	ni_sysfs_bridge_get_config(dev->name, bridge);
	ni_sysfs_bridge_get_status(dev->name, &bridge->status);

	ni_string_array_init(&ports);
	ni_sysfs_bridge_get_port_names(dev->name, &ports);
	ni_bridge_ports_destroy(bridge);

	for (i = 0; i < ports.count; ++i) {
		const char *ifname = ports.data[i];
		unsigned int index;
		ni_bridge_port_t *port;

		if ((index = if_nametoindex(ifname)) == 0) {
			/* Looks like someone is renaming interfaces while we're
			 * trying to discover them :-( */
			ni_error("%s: port interface %s has index 0?!", __func__, ifname);
			continue;
		}
		port = ni_bridge_port_new(bridge, ifname, index);

		ni_sysfs_bridge_port_get_config(port->ifname, port);
		ni_sysfs_bridge_port_get_status(port->ifname, &port->status);
	}
	ni_string_array_destroy(&ports);

	return 0;
}

/*
 * Discover bonding configuration
 */
static int
__ni_discover_bond(ni_netdev_t *dev)
{
	ni_bonding_t *bonding;

	if (dev->link.type != NI_IFTYPE_BOND)
		return 0;

	bonding = ni_netdev_get_bonding(dev);

	if (ni_bonding_parse_sysfs_attrs(dev->name, bonding) < 0) {
		ni_error("error retrieving bonding attribute from sysfs");
		return -1;
	}

	return 0;
}

/*
 * Discover infiniband configuration
 */
static int
__ni_discover_infiniband(ni_netdev_t *dev)
{
	ni_infiniband_t *ib;
	char *value = NULL;
	unsigned int pkey;
	int ret = 0;

	if (dev->link.type != NI_IFTYPE_INFINIBAND &&
	    dev->link.type != NI_IFTYPE_INFINIBAND_CHILD)
		return 0;

	if (!(ib = ni_netdev_get_infiniband(dev)))
		return -1;

	if (ni_sysfs_netif_get_string(dev->name, "mode", &value) < 0
	   || !ni_infiniband_get_mode_flag(value, &ib->mode)) {
		ni_error("%s: unable to retrieve infiniband mode attribute from sysfs",
			dev->name);
		ret = -1;
	}
	ni_string_free(&value);

	if (ni_sysfs_netif_get_uint(dev->name, "umcast", &ib->umcast) < 0) {
		ni_error("%s: unable to retrieve infiniband umcast attribute from sysfs",
			dev->name);
		ret = -1;
	}

	if (ni_sysfs_netif_get_uint(dev->name, "pkey", &pkey) < 0) {
		ni_error("%s: unable to retrieve infiniband paritition key from sysfs",
			dev->name);
		ret = -1;
	}
	ib->pkey = pkey;

	if (dev->link.type != NI_IFTYPE_INFINIBAND_CHILD)
		return ret;

	if (ni_sysfs_netif_get_string(dev->name, "parent", &value) < 0) {
		ni_error("%s: unable to retrieve infiniband child's parent interface name",
			dev->name);
		ret = -1;
	} else if (!ni_string_eq(ib->parent.name, value)) {
		ni_string_free(&ib->parent.name);
		ib->parent.name = value;
	} else {
		ni_string_free(&value);
	}

	return ret;
}

/*
 * Discover whether we have any addrconf daemons running on this interface.
 */
int
__ni_discover_addrconf(ni_netdev_t *dev)
{
	ni_addrconf_lease_t *lease;

	__ni_assert_initialized();

	for (lease = dev->leases; lease; lease = lease->next) {
		switch (lease->family) {
		case AF_INET:
			//ni_afinfo_addrconf_enable(&dev->ipv4, lease->type);
			break;
		case AF_INET6:
			//ni_afinfo_addrconf_enable(&dev->ipv6, lease->type);
			break;
		}
	}

	return 0;
}
