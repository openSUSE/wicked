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
#include <netinet/ip.h>
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
#include <wicked/macvlan.h>
#include <wicked/wireless.h>
#include <wicked/infiniband.h>
#include <wicked/tuntap.h>
#include <wicked/tunneling.h>
#include <wicked/linkstats.h>

#if defined(HAVE_RTA_MARK)
#  include <netlink/netlink.h>
#elif defined(HAVE_LINUX_RTNETLINK_H) && defined(HAVE_LINUX_RTA_MARK)
#  include <linux/rtnetlink.h>
#  define  HAVE_RTA_MARK HAVE_LINUX_RTA_MARK
#endif

#if defined(HAVE_IFLA_VLAN_PROTOCOL)
#  ifndef	ETH_P_8021Q
#  define	ETH_P_8021Q	0x8100
#  endif
#  ifndef	ETH_P_8021AD
#  define	ETH_P_8021AD	0x88A8
#  endif
#endif
#include <linux/if_tunnel.h>

#include "netinfo_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "appconfig.h"
#include "teamd.h"
#include "ovs.h"


static int		__ni_process_ifinfomsg(ni_linkinfo_t *link, struct nlmsghdr *h,
					struct ifinfomsg *ifi, ni_netconfig_t *);
static int		__ni_netdev_process_newaddr(ni_netdev_t *dev, struct nlmsghdr *h,
					struct ifaddrmsg *ifa);
static int		__ni_netdev_process_newroute(ni_netdev_t *, struct nlmsghdr *,
					struct rtmsg *, ni_netconfig_t *);
static int		__ni_discover_bridge(ni_netdev_t *);
static int		__ni_discover_bond(ni_netdev_t *);
static int		__ni_discover_addrconf(ni_netdev_t *);
static int		__ni_discover_infiniband(ni_netdev_t *, ni_netconfig_t *);
static int		__ni_discover_vlan(ni_netdev_t *, struct nlattr **, ni_netconfig_t *);
static int		__ni_discover_macvlan(ni_netdev_t *, struct nlattr **, ni_netconfig_t *);
static int		__ni_discover_tuntap(ni_netdev_t *);
static int		__ni_discover_tunneling(ni_netdev_t *, struct nlattr **);
static void		__ni_tunnel_trace(ni_netdev_t *, struct nlattr **);
static void		__ni_tunnel_gre_trace(ni_netdev_t *, struct nlattr **);
static int		__ni_discover_sit(ni_netdev_t *, struct nlattr **, struct nlattr**);
static int		__ni_discover_ipip(ni_netdev_t *, struct nlattr **, struct nlattr**);
static int		__ni_discover_gre(ni_netdev_t *, struct nlattr **, struct nlattr**);

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
	int rv;

	ni_nlmsg_list_init(&qr->nlmsg_list);
retry:
	rv = ni_nl_dump_store(af, type, &qr->nlmsg_list);
	switch (rv) {
	case NLE_SUCCESS:
		qr->entry = qr->nlmsg_list.head;
		break;
	case -NLE_DUMP_INTR:
		ni_nlmsg_list_destroy(&qr->nlmsg_list);
		goto retry;
	default:
		qr->entry = NULL;
		break;
	}
	return rv;
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

static int
ni_rtnl_query_addr_info(struct ni_rtnl_query *q, unsigned int ifindex)
{
	memset(q, 0, sizeof(*q));
	q->ifindex = ifindex;

	if (__ni_rtnl_query(&q->addr_info, AF_UNSPEC, RTM_GETADDR) < 0) {
		ni_rtnl_query_destroy(q);
		return -1;
	}

	return 0;
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

static int
ni_rtnl_query_route_info(struct ni_rtnl_query *q, unsigned int ifindex)
{
	memset(q, 0, sizeof(*q));
	q->ifindex = ifindex;

	if (__ni_rtnl_query(&q->route_info, AF_UNSPEC, RTM_GETROUTE) < 0) {
		ni_rtnl_query_destroy(q);
		return -1;
	}

	return 0;
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

static void
__ni_address_list_reset_seq(ni_address_t *addrs)
{
	ni_address_t *ap;

	for (ap = addrs; ap; ap = ap->next)
		ap->seq = 0;
}

static void
__ni_address_list_drop_by_seq(ni_address_t **tail, unsigned int seq)
{
	ni_address_t *ap;

	while ((ap = *tail)) {
		if (ap->seq != seq) {
			*tail = ap->next;
			ni_address_free(ap);
		} else {
			tail = &ap->next;
		}
	}
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
	static int refresh = 0;
	struct ni_rtnl_query query;
	struct nlmsghdr *h;
	ni_netdev_t **tail, *dev;
	unsigned int seqno;
	int res = -1;

	do {
		seqno = ++__ni_global_seqno;
	} while (!seqno);

	if (!refresh) {
		refresh = 1;
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
				"Full refresh of all interfaces (bootstrap)");
	} else {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_EVENTS,
				"Full refresh of all interfaces (enforced)");
	}

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
		ifname = nla_get_string(nla);

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
			if (!ni_string_eq(dev->name, ifname))
				ni_string_dup(&dev->name, ifname);

			/* Clear out addresses and routes */
			__ni_address_list_reset_seq(dev->addrs);
			ni_netdev_clear_routes(dev);
		}

		dev->seq = seqno;

		if (__ni_netdev_process_newlink(dev, h, ifi, nc) < 0)
			ni_error("Problem parsing RTM_NEWLINK message for %s", ifname);
	}

	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next) {
		if (dev->link.masterdev.index && !dev->link.masterdev.name) {
			if (!ni_netdev_ref_bind_ifname(&dev->link.masterdev, nc)) {
				ni_info("Interface %s references unknown master device (ifindex %u)",
					dev->name, dev->link.masterdev.index);
			}
			/* Ignore error and proceed */
		}
		if (dev->link.lowerdev.index && !dev->link.lowerdev.name) {
			if (!ni_netdev_ref_bind_ifname(&dev->link.lowerdev, nc)) {
				ni_info("Interface %s references unknown lower device (ifindex %u)",
					dev->name, dev->link.lowerdev.index);
			}
			/* Ignore error and proceed */
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
		__ni_address_list_drop_by_seq(&dev->addrs, seqno);
		if (dev->seq != seqno) {
			*tail = dev->next;
			if (del_list == NULL) {
				ni_client_state_drop(dev->link.ifindex);
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

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
			"Full refresh of %s interface",
			dev->name);

	do {
		__ni_global_seqno++;
	} while (!__ni_global_seqno);

	if (ni_rtnl_query(&query, dev->link.ifindex) < 0)
		goto failed;

	dev->seq = 0;
	while (1) {
		struct ifinfomsg *ifi;
		struct nlattr *nla;
		const char *ifname;

		if (!(ifi = ni_rtnl_query_next_link_info(&query, &h)))
			break;

		if ((nla = nlmsg_find_attr(h, sizeof(*ifi), IFLA_IFNAME)) == NULL) {
			ni_warn("RTM_NEWLINK message without IFNAME");
			continue;
		}

		ifname = nla_get_string(nla);
		if (!ni_string_eq(dev->name, ifname))
			ni_string_dup(&dev->name, ifname);

		/* Clear out addresses and routes */
		dev->seq = __ni_global_seqno;
		__ni_address_list_reset_seq(dev->addrs);
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
	__ni_address_list_drop_by_seq(&dev->addrs, dev->seq);

	while (1) {
		struct rtmsg *rtm;

		if (!(rtm = ni_rtnl_query_next_route_info(&query, &h, NULL)))
			break;

		if (__ni_netdev_process_newroute(dev, h, rtm, nc) < 0)
			ni_error("Problem parsing RTM_NEWROUTE message");
	}

	res = 0;

failed:
	ni_rtnl_query_destroy(&query);
	return res;
}

/*
 * Refresh addresses
 */
int
__ni_system_refresh_interface_addrs(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	struct ni_rtnl_query query;
	struct nlmsghdr *h;
	int res = -1;

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
			"Refresh of %s interface address",
			dev->name);

	do {
		dev->seq = ++__ni_global_seqno;
	} while (!dev->seq);

	if (ni_rtnl_query_addr_info(&query, dev->link.ifindex) < 0)
		goto failed;

	__ni_address_list_reset_seq(dev->addrs);
	while (1) {
		struct ifaddrmsg *ifa;

		if (!(ifa = ni_rtnl_query_next_addr_info(&query, &h)))
			break;

		if (__ni_netdev_process_newaddr(dev, h, ifa) < 0)
			ni_error("Problem parsing RTM_NEWADDR message for %s", dev->name);
	}
	__ni_address_list_drop_by_seq(&dev->addrs, dev->seq);

	res = 0;

failed:
	ni_rtnl_query_destroy(&query);
	return res;
}

/*
 * Refresh routes
 */
int
__ni_system_refresh_interface_routes(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	struct ni_rtnl_query query;
	struct nlmsghdr *h;
	int res = -1;

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
			"Refresh of %s interface routes",
			dev->name);

	__ni_global_seqno++;
	if (ni_rtnl_query_route_info(&query, dev->link.ifindex) < 0)
		goto failed;

	ni_netdev_clear_routes(dev);
	while (1) {
		struct rtmsg *rtm;

		if (!(rtm = ni_rtnl_query_next_route_info(&query, &h, NULL)))
			break;

		if (__ni_netdev_process_newroute(dev, h, rtm, nc) < 0)
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
	ni_netdev_t *dev;
	int rv = 0;

	dev = nc ? ni_netdev_by_index(nc, link->ifindex) : NULL;
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
			"Link %s[%u] info refresh",
			dev ? dev->name : "",
			link->ifindex);

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

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_EVENTS,
			"IPv6 link info refresh of %s interface",
			dev->name);

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
__ni_netdev_translate_ifflags(unsigned int ifflags, unsigned int prev)
{
	unsigned int retval = (prev & NI_IFF_DEVICE_READY);

	switch (ifflags & (IFF_RUNNING | IFF_LOWER_UP | IFF_UP)) {
	case IFF_UP:
	case IFF_UP | IFF_RUNNING:
		retval = NI_IFF_DEVICE_READY | NI_IFF_DEVICE_UP;
		break;

	case IFF_UP | IFF_LOWER_UP:
	case IFF_UP | IFF_LOWER_UP | IFF_RUNNING:
		retval = NI_IFF_DEVICE_READY | NI_IFF_DEVICE_UP |
			 NI_IFF_LINK_UP | NI_IFF_NETWORK_UP;
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

static void
__ni_process_ifinfomsg_linktype(ni_linkinfo_t *link, const char *ifname)
{
	ni_iftype_t tmp_link_type = NI_IFTYPE_UNKNOWN;
	struct ethtool_drvinfo drv_info;
	const char *driver = NULL;
	char *path = NULL;
	const char *base;

	/* Try to get linktype from kind string. */
	if (!__ni_linkinfo_kind_to_type(link->kind, &tmp_link_type))
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: unknown link-info kind: %s", ifname, link->kind);

	switch (tmp_link_type) {
	case NI_IFTYPE_TUN:
		/* link->kind from IFLA_LINKINFO is always 'tun' for both tun
		 * and tap device. Need this additional check to distinguish.
		 */
		if (link->hwaddr.type == ARPHRD_ETHER)
			tmp_link_type = NI_IFTYPE_TAP;
		break;

	case NI_IFTYPE_UNKNOWN:
		switch (link->hwaddr.type) {
		case ARPHRD_LOOPBACK:
			tmp_link_type = NI_IFTYPE_LOOPBACK;

			break;

		case ARPHRD_ETHER:
			/* We're at the very least an ethernet. */
			tmp_link_type = NI_IFTYPE_ETHERNET;

			/*
			 * Try to detect if this is a  WLAN device.
			 * The official way of doing this is to check whether
			 * ioctl(SIOCGIWNAME) succeeds.
			 */
			if (__ni_wireless_get_name(ifname, NULL, 0) == 0)
				tmp_link_type = NI_IFTYPE_WIRELESS;

			memset(&drv_info, 0, sizeof(drv_info));
			if (__ni_ethtool(ifname, ETHTOOL_GDRVINFO, &drv_info) >= 0) {
				driver = drv_info.driver;
				if (!strcmp(driver, "tun")) {
					if (!strcmp(drv_info.bus_info, "tap"))
						tmp_link_type = NI_IFTYPE_TAP;
					else
						tmp_link_type = NI_IFTYPE_TUN;
				} else if (!strcmp(driver, "bridge")) {
					tmp_link_type = NI_IFTYPE_BRIDGE;
				} else if (!strcmp(driver, "bonding")) {
					tmp_link_type = NI_IFTYPE_BOND;
				} else if (!strcmp(driver, "802.1Q VLAN Support")) {
					tmp_link_type = NI_IFTYPE_VLAN;
				} else if (!strcmp(driver, "openvswitch")) {
					static const char *ovs_system = NULL;

					/* special openvswitch datapath (master) device */
					if (ovs_system == NULL)
						ovs_system = ni_linktype_type_to_name(NI_IFTYPE_OVS_SYSTEM);
					if (ni_string_eq(ifname, ovs_system))
						tmp_link_type = NI_IFTYPE_OVS_SYSTEM;
					else
						tmp_link_type = NI_IFTYPE_OVS_BRIDGE;
				}
			}

			break;

		case ARPHRD_INFINIBAND:
			if (ni_sysfs_netif_exists(ifname, "parent"))
				tmp_link_type = NI_IFTYPE_INFINIBAND_CHILD;
			else
				tmp_link_type = NI_IFTYPE_INFINIBAND;

			break;

		case ARPHRD_SLIP:
			/* s390 ctc devices on ctcm + iucv? */
			if (ni_sysfs_netif_readlink(ifname, "device/subsystem", &path)) {
				base = ni_basename(path);
				if (ni_string_eq(base, "ccwgroup"))
					tmp_link_type = NI_IFTYPE_CTCM;
				else
					if (ni_string_eq(base, "iucv"))
						tmp_link_type = NI_IFTYPE_IUCV;
				ni_string_free(&path);
			}

			break;

		case ARPHRD_SIT:
			tmp_link_type = NI_IFTYPE_SIT;

			break;

		case ARPHRD_IPGRE:
			tmp_link_type = NI_IFTYPE_GRE;

			break;

		case ARPHRD_TUNNEL:
			tmp_link_type = NI_IFTYPE_IPIP;

			break;

		case ARPHRD_TUNNEL6:
			tmp_link_type = NI_IFTYPE_TUNNEL6;

			break;

		default:
			break;
		}

		break;

	default:
		break;
	}

	/* We only want to perform any assignments to link->type if it has not
	 * yet been touched.
	 */
	if (link->type == NI_IFTYPE_UNKNOWN) {
		if (tmp_link_type == NI_IFTYPE_UNKNOWN) {
			/* We've failed to discover a link type, leave as is. */
			ni_debug_ifconfig("%s: Failed to discover link type, arp type is 0x%x, kind %s",
				ifname, link->hwaddr.type, link->kind);
		} else {
			/* Our link has no type yet, so let's assign. */
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
					"%s: Setting interface link type to %s",
					ifname, ni_linktype_type_to_name(tmp_link_type));
			link->type = tmp_link_type;
		}
	} else
	if (link->type != tmp_link_type) {
		/* We're trying to re-assign a link type, Disallow. */
		ni_error("%s: Ignoring attempt to reset existing interface link type from %s to %s",
			ifname, ni_linktype_type_to_name(link->type),
			ni_linktype_type_to_name(tmp_link_type));
	}
}

/*
 * Refresh interface link layer given a parsed RTM_NEWLINK message attrs
 */
static int
__ni_process_ifinfomsg_linkinfo(ni_linkinfo_t *link, const char *ifname,
				struct nlattr **tb, struct nlmsghdr *h,
				struct ifinfomsg *ifi, ni_netconfig_t *nc)
{
	link->hwaddr.type = link->hwpeer.type = ifi->ifi_type;
	link->ifflags = __ni_netdev_translate_ifflags(ifi->ifi_flags, link->ifflags);

	if (ni_netdev_link_always_ready(link))
		link->ifflags |= NI_IFF_DEVICE_READY;

	if (tb[IFLA_ADDRESS]) {
		unsigned int alen = nla_len(tb[IFLA_ADDRESS]);
		void *data = nla_data(tb[IFLA_ADDRESS]);

		if (alen > sizeof(link->hwaddr.data))
			alen = sizeof(link->hwaddr.data);

		memcpy(link->hwaddr.data, data, alen);
		link->hwaddr.len = alen;
		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS,
				"IFLA_ADDRESS: %s",
				ni_link_address_print(&link->hwaddr));
	}
	if (tb[IFLA_BROADCAST]) {
		unsigned int alen = nla_len(tb[IFLA_BROADCAST]);
		void *data = nla_data(tb[IFLA_BROADCAST]);

		if (alen > sizeof(link->hwpeer.data))
			alen = sizeof(link->hwpeer.data);
		memcpy(link->hwpeer.data, data, alen);
		link->hwpeer.len = alen;
		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS,
				"IFLA_BROADCAST: %s",
				ni_link_address_print(&link->hwpeer));
	}

	if (tb[IFLA_MTU])
		link->mtu = nla_get_u32(tb[IFLA_MTU]);
	if (tb[IFLA_TXQLEN])
		link->txqlen = nla_get_u32(tb[IFLA_TXQLEN]);
	if (tb[IFLA_COST])
		link->metric = nla_get_u32(tb[IFLA_COST]);
	if (tb[IFLA_QDISC])
		ni_string_dup(&link->qdisc, nla_get_string(tb[IFLA_QDISC]));

	if (tb[IFLA_LINK]) {
		link->lowerdev.index = nla_get_u32(tb[IFLA_LINK]);
		if (!ni_netdev_ref_bind_ifname(&link->lowerdev, nc)) {
			/* Drop old ifname, we will try it again later */
			ni_string_free(&link->lowerdev.name);
		}
	} else if (link->lowerdev.index) {
		ni_netdev_ref_destroy(&link->lowerdev);
	}

	if (tb[IFLA_MASTER]) {
		link->masterdev.index = nla_get_u32(tb[IFLA_MASTER]);
		if (!ni_netdev_ref_bind_ifname(&link->masterdev, nc)) {
			/* Drop old ifname, we will try it again later */
			ni_string_free(&link->masterdev.name);
		}
	} else if (link->masterdev.index) {
		ni_netdev_ref_destroy(&link->masterdev);
	}

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

		if ((n = link->stats)) {
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
	}

	/* Extended link info. Let's use it to try to determine link->type.
	 *
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

		if (nl_linkinfo[IFLA_INFO_KIND])
			ni_string_dup(&link->kind, nla_get_string(nl_linkinfo[IFLA_INFO_KIND]));

		if (ni_string_empty(link->kind)) {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: extended link-info without kind", ifname);

		} else {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: extended link-info kind: %s", ifname, link->kind);
		}
	}

	/* Attempt to determine linktype. */
	__ni_process_ifinfomsg_linktype(link, ifname);

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
		ni_bool_t old_managed_addr;
		ni_bool_t old_other_config;
		ni_ipv6_devinfo_t *ipv6;

		nla_parse_nested(ipv6info, IFLA_INET6_MAX, ifla_protinfo, NULL);
		if (ipv6info[IFLA_INET6_FLAGS])
			flags = nla_get_u32(ipv6info[IFLA_INET6_FLAGS]);

		ipv6 = ni_netdev_get_ipv6(dev);
		old_managed_addr = ipv6->radv.managed_addr;
		old_other_config = ipv6->radv.other_config;
		if (flags & IF_RA_MANAGED) {
			ipv6->radv.managed_addr = TRUE;
			ipv6->radv.other_config = TRUE;
			if (ipv6->radv.managed_addr != old_managed_addr ||
			    ipv6->radv.other_config != old_other_config) {
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
					"%s: obtain config and address via DHCPv6",
					dev->name);
			}
		} else
		if (flags & IF_RA_OTHERCONF) {
			ipv6->radv.managed_addr = FALSE;
			ipv6->radv.other_config = TRUE;
			if (ipv6->radv.managed_addr != old_managed_addr ||
			    ipv6->radv.other_config != old_other_config) {
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
					"%s: obtain config only via DHCPv6",
					dev->name);
			}
		} else {
			ipv6->radv.managed_addr = FALSE;
			ipv6->radv.other_config = FALSE;
			if (ipv6->radv.managed_addr != old_managed_addr ||
			    ipv6->radv.other_config != old_other_config) {
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
					"%s: no DHCPv6 suggestion in RA",
					dev->name);
			}
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

	if (tb[IFLA_IFNAME]) {
		ifname = nla_get_string(tb[IFLA_IFNAME]);
	} else {
		ni_warn("RTM_NEWLINK message without IFNAME");
		return -1;
	}

	return __ni_process_ifinfomsg_linkinfo(link, ifname, tb, h, ifi, nc);
}

static int
__ni_process_ifinfomsg_af_ipv4_conf(ni_netdev_t *dev, struct nlattr *nla)
{
	int32_t *array;
	int bytes;

	array = nla_data(nla);
	bytes = nla_len(nla);
	if (bytes <= 0 || !array || (bytes % 4))
		return -1;

	return __ni_ipv4_devconf_process_flags(dev, array, bytes / 4);
}

static int
__ni_process_ifinfomsg_af_ipv4(ni_netdev_t *dev, struct nlattr *nla, ni_bool_t *ipv4_conf)
{
	struct nlattr *tb[IFLA_INET_MAX + 1];

	if (!nla)
		return -1;

	memset(tb, 0, sizeof(tb));
	if (nla_parse_nested(tb, IFLA_INET_MAX, nla, NULL) < 0)
		return -1;

	if (tb[IFLA_INET_CONF]) {
		if (!__ni_process_ifinfomsg_af_ipv4_conf(dev, tb[IFLA_INET_CONF]) && ipv4_conf)
			*ipv4_conf = TRUE;
	}

	return 0;
}

static int
__ni_process_ifinfomsg_af_ipv6_conf(ni_netdev_t *dev, struct nlattr *nla)
{
	int32_t *array;
	int bytes;

	array = nla_data(nla);
	bytes = nla_len(nla);
	if (bytes <= 0 || !array || (bytes % 4))
		return -1;

	return __ni_ipv6_devconf_process_flags(dev, array, bytes / 4);
}

static int
__ni_process_ifinfomsg_af_ipv6(ni_netdev_t *dev, struct nlattr *nla, ni_bool_t *ipv6_conf)
{
	struct nlattr *tb[IFLA_INET6_MAX + 1];

	if (!nla)
		return -1;

	memset(tb, 0, sizeof(tb));
	if (nla_parse_nested(tb, IFLA_INET6_MAX, nla, NULL) < 0)
		return -1;

	if (tb[IFLA_INET6_CONF]) {
		if (!__ni_process_ifinfomsg_af_ipv6_conf(dev, tb[IFLA_INET6_CONF]) && ipv6_conf)
			*ipv6_conf = TRUE;
	}

	return 0;
}

static int
__ni_process_ifinfomsg_af_spec(ni_netdev_t *dev, struct nlattr *ifla_af_spec)
{
	/*
	 * not every newlink provides device sysctl's;
	 * we get them on a refresh and on any change
	 * and this is IMO completely sufficient.
	 */
	static ni_bool_t ipv4_conf = FALSE;
	static ni_bool_t ipv6_conf = FALSE;

	if (ifla_af_spec) {
		struct nlattr *af;
		int rem;

		nla_for_each_nested(af, ifla_af_spec, rem) {
			switch (nla_type(af)) {
			case AF_INET:
				__ni_process_ifinfomsg_af_ipv4(dev, af, &ipv4_conf);
				break;
			case AF_INET6:
				__ni_process_ifinfomsg_af_ipv6(dev, af, &ipv6_conf);
				break;
			default:
				break;
			}
		}
	}

	/* don't read sysfs when device (name) is not ready */
	if (ni_netdev_device_is_ready(dev)) {
		if (!ipv4_conf) {
			ni_system_ipv4_devinfo_get(dev, NULL);
		}
		if (!ipv6_conf) {
			ni_system_ipv6_devinfo_get(dev, NULL);
		}
	}

	return 0;
}

/*
 * Refresh complete interface link info given a RTM_NEWLINK message
 */
int
__ni_netdev_process_newlink(ni_netdev_t *dev, struct nlmsghdr *h,
				struct ifinfomsg *ifi, ni_netconfig_t *nc)
{
	struct nlattr *tb[IFLA_MAX+1];
	int rv;

	memset(tb, 0, sizeof(tb));
	if (nlmsg_parse(h, sizeof(*ifi), tb, IFLA_MAX, NULL) < 0) {
		ni_error("%s[%u] unable to parse rtnl LINK message",
				dev->name, dev->link.ifindex);
		return -1;
	}

	/* Note: we explicitly update name on query/event as needed
	 * before this function is called. While event processing,
	 * we explicitely query the current name to avoid an update
	 * to an already obsolete name provided in the event data.
	 * Thus just update device name in case it is missed.
	 */
	if (ni_string_empty(dev->name)) {
		if (!tb[IFLA_IFNAME]) {
			ni_warn("%s[#%u] RTM_NEWLINK message without IFNAME",
					dev->name, dev->link.ifindex);
			return -1;
		}
		ni_string_dup(&dev->name, nla_get_string(tb[IFLA_IFNAME]));
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

	__ni_process_ifinfomsg_af_spec(dev, tb[IFLA_AF_SPEC]);
	__ni_process_ifinfomsg_ipv6info(dev, tb[IFLA_PROTINFO]);

	switch (dev->link.type) {
	case NI_IFTYPE_ETHERNET:
		__ni_system_ethernet_refresh(dev);
		break;

	case NI_IFTYPE_INFINIBAND:
	case NI_IFTYPE_INFINIBAND_CHILD:
		__ni_discover_infiniband(dev, nc);
		break;

	case NI_IFTYPE_BRIDGE:
		__ni_discover_bridge(dev);
		break;
	case NI_IFTYPE_BOND:
		__ni_discover_bond(dev);
		break;

	case NI_IFTYPE_VLAN:
		__ni_discover_vlan(dev, tb, nc);
		break;

	case NI_IFTYPE_MACVLAN:
	case NI_IFTYPE_MACVTAP:
		__ni_discover_macvlan(dev, tb, nc);
		break;

	case NI_IFTYPE_TUN:
	case NI_IFTYPE_TAP:
		__ni_discover_tuntap(dev);
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

	case NI_IFTYPE_IPIP:
	case NI_IFTYPE_GRE:
	case NI_IFTYPE_SIT:
		__ni_discover_tunneling(dev, tb);
		break;

	case NI_IFTYPE_TEAM:
		/*
		 * is using gennl, rtnl_link provides a kind only,
		 * so we unfortunatelly have to ask teamd here and
		 * even worser, by name...
		 */
		if (ni_config_teamd_enabled() && ni_netdev_device_is_ready(dev))
			ni_teamd_discover(dev);
		break;

	case NI_IFTYPE_OVS_BRIDGE:
		if (ni_netdev_device_is_ready(dev))
			ni_ovs_bridge_discover(dev, nc);
		break;

	default:
		break;
	}

	/* Check if we have DHCP running for this interface */
	__ni_discover_addrconf(dev);

	return 0;
}

int
__ni_discover_vlan(ni_netdev_t *dev, struct nlattr **tb, ni_netconfig_t *nc)
{
	struct nlattr *link_info[IFLA_INFO_MAX+1];
	struct nlattr *info_data[IFLA_VLAN_MAX+1];
	ni_vlan_t *vlan;

	if (!dev || !tb || !(vlan = ni_netdev_get_vlan(dev))) {
		ni_error("%s: Unable to discover vlan interface details",
			dev ? dev->name : NULL);
		return -1;
	}

	/* IFLA_LINKINFO is extended interface info. Not all interfaces will
	 * provide this.
	 */
	if (!tb[IFLA_LINKINFO]) {
		ni_debug_ifconfig("%s: no extended linkinfo data provided",
				dev ? dev->name : NULL);
		return 0;
	}

	if (nla_parse_nested(link_info, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL) < 0) {
		ni_error("%s: unable to parse IFLA_LINKINFO", dev->name);
		return -1;
	}

	if (nla_parse_nested(info_data, IFLA_VLAN_MAX, link_info[IFLA_INFO_DATA], NULL) < 0) {
		ni_error("%s: unable to parse vlan IFLA_INFO_DATA", dev->name);
		return -1;
	}

	vlan->protocol = NI_VLAN_PROTOCOL_8021Q;
#ifdef HAVE_IFLA_VLAN_PROTOCOL
	if (info_data[IFLA_VLAN_PROTOCOL]) {
		uint16_t p = nla_get_u16(info_data[IFLA_VLAN_PROTOCOL]);
		switch (ntohs(p)) {
		case ETH_P_8021Q:
			vlan->protocol = NI_VLAN_PROTOCOL_8021Q;
			break;
		case ETH_P_8021AD:
			vlan->protocol = NI_VLAN_PROTOCOL_8021AD;
			break;
		}
	}
#endif

	vlan->tag = nla_get_u16(info_data[IFLA_VLAN_ID]);

	return 0;
}

int
__ni_discover_macvlan(ni_netdev_t *dev, struct nlattr **tb, ni_netconfig_t *nc)
{
	struct nlattr *link_info[IFLA_INFO_MAX+1];
	struct nlattr *info_data[IFLA_VLAN_MAX+1];
	ni_macvlan_t *macvlan;

	if (!dev || !tb || !(macvlan = ni_netdev_get_macvlan(dev))) {
		ni_error("%s: Unable to discover macvlan interface details",
			dev ? dev->name : NULL);
		return -1;
	}

	/* IFLA_LINKINFO is extended interface info. Not all interfaces will
	 * provide this.
	 */
	if (!tb[IFLA_LINKINFO]) {
		ni_debug_ifconfig("%s: no extended linkinfo data provided",
				dev ? dev->name : NULL);
		return 0;
	}

	if (nla_parse_nested(link_info, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL) < 0) {
		ni_error("%s: unable to parse IFLA_LINKINFO", dev->name);
		return -1;
	}

	if (nla_parse_nested(info_data, IFLA_MACVLAN_MAX, link_info[IFLA_INFO_DATA], NULL) < 0) {
		ni_error("%s: unable to parse macvlan IFLA_INFO_DATA", dev->name);
		return -1;
	}

	if (info_data[IFLA_MACVLAN_MODE])
		macvlan->mode = nla_get_u32(info_data[IFLA_MACVLAN_MODE]);

	if (info_data[IFLA_MACVLAN_FLAGS])
		macvlan->flags = nla_get_u16(info_data[IFLA_MACVLAN_FLAGS]);

	return 0;
}

int
__ni_discover_tuntap(ni_netdev_t *dev)
{
	ni_tuntap_t *cfg;
	int rv = -1;

	if (!dev) {
		ni_error("Unable to discover NULL interface details");
		return rv;
	}

	if (dev->link.type != NI_IFTYPE_TUN && dev->link.type != NI_IFTYPE_TAP) {
		ni_error("%s: Attempt to discover %s interface details for TUN/TAP",
			ni_linktype_type_to_name(dev->link.type), dev->name);
		return rv;
	}

	cfg = ni_netdev_get_tuntap(dev);
	if ((rv = ni_tuntap_parse_sysfs_attrs(dev->name, cfg) < 0))
		ni_error("error retrieving %s attribute from sysfs",
			ni_linktype_type_to_name(dev->link.type));

	return rv;
}

static int
__ni_discover_tunnel(ni_tunnel_t *tunnel, unsigned int type, struct nlattr **info_data)
{
	uint8_t pmtudisc = 0;

	if (!tunnel) {
		return -1;
	}

	switch(type) {
	case NI_IFTYPE_IPIP:
	case NI_IFTYPE_SIT:
		if (info_data[IFLA_IPTUN_TTL])
			tunnel->ttl = nla_get_u8(info_data[IFLA_IPTUN_TTL]);

		if (info_data[IFLA_IPTUN_TOS])
			tunnel->tos = nla_get_u8(info_data[IFLA_IPTUN_TOS]);

		if (info_data[IFLA_IPTUN_PMTUDISC]) {
			pmtudisc = nla_get_u8(info_data[IFLA_IPTUN_PMTUDISC]);
			tunnel->pmtudisc = pmtudisc ? TRUE : FALSE;
		}
		if (info_data[IFLA_IPTUN_FLAGS])
			tunnel->iflags = nla_get_u16(info_data[IFLA_IPTUN_FLAGS]);

		break;

	case NI_IFTYPE_GRE:
		if (info_data[IFLA_GRE_TTL])
			tunnel->ttl = nla_get_u8(info_data[IFLA_GRE_TTL]);

		if (info_data[IFLA_GRE_TOS])
			tunnel->tos = nla_get_u8(info_data[IFLA_GRE_TOS]);

		if (info_data[IFLA_GRE_PMTUDISC]) {
			pmtudisc = nla_get_u8(info_data[IFLA_GRE_PMTUDISC]);
			tunnel->pmtudisc = pmtudisc ? TRUE : FALSE;
		}
		if (info_data[IFLA_GRE_FLAGS])
			tunnel->iflags = nla_get_u16(info_data[IFLA_GRE_FLAGS]);

		break;
	}

	return 0;
}

static int
__ni_discover_tunnel_addresses(ni_linkinfo_t *link, unsigned int type, struct nlattr **info_data)
{
	uint32_t ip;

	switch(type) {
	case NI_IFTYPE_IPIP:
	case NI_IFTYPE_SIT:
		if (info_data[IFLA_IPTUN_LOCAL]) {
			ip = nla_get_u32(info_data[IFLA_IPTUN_LOCAL]);
			ni_link_address_set(&link->hwaddr, link->hwaddr.type, &ip, sizeof(ip));
		}

		if (info_data[IFLA_IPTUN_REMOTE]) {
			ip = nla_get_u32(info_data[IFLA_IPTUN_REMOTE]);
			ni_link_address_set(&link->hwpeer, link->hwpeer.type, &ip, sizeof(ip));
		}
		break;

	case NI_IFTYPE_GRE:
		if (info_data[IFLA_GRE_LOCAL]) {
			ip = nla_get_u32(info_data[IFLA_GRE_LOCAL]);
			ni_link_address_set(&link->hwaddr, link->hwaddr.type, &ip, sizeof(ip));
		}

		if (info_data[IFLA_GRE_REMOTE]) {
			ip = nla_get_u32(info_data[IFLA_GRE_REMOTE]);
			ni_link_address_set(&link->hwpeer, link->hwpeer.type, &ip, sizeof(ip));
		}
	}

	return 0;
}

static int
__ni_discover_sit(ni_netdev_t *dev, struct nlattr **link_info, struct nlattr **info_data)
{
	ni_sit_t *sit;

	if (!(sit = ni_netdev_get_sit(dev)) ||
		__ni_discover_tunnel(&sit->tunnel, NI_IFTYPE_SIT, info_data) < 0 ||
		__ni_discover_tunnel_addresses(&dev->link, NI_IFTYPE_SIT, info_data) < 0) {

		ni_error("%s: Unable to discover sit tunnel details",
			dev ? dev->name : NULL);

		return -1;
	}

	if (sit->tunnel.iflags & SIT_ISATAP)
		sit->isatap = TRUE;

	return 0;
}

/*
 * Discover ipip interfaces.
 */
static int
__ni_discover_ipip(ni_netdev_t *dev, struct nlattr **link_info, struct nlattr **info_data)
{
	ni_ipip_t *ipip;

	if (!(ipip = ni_netdev_get_ipip(dev)) ||
		__ni_discover_tunnel(&ipip->tunnel, NI_IFTYPE_IPIP, info_data) < 0 ||
		__ni_discover_tunnel_addresses(&dev->link, NI_IFTYPE_IPIP, info_data)) {
		ni_error("%s: Unable to discover ipip tunnel details",
			dev ? dev->name : NULL);
		return -1;
	}

	return 0;
}

static int
__ni_discover_gre(ni_netdev_t *dev, struct nlattr **link_info, struct nlattr **info_data)
{
	ni_gre_t *gre;

	if (!(gre = ni_netdev_get_gre(dev)) ||
		__ni_discover_tunnel(&gre->tunnel, NI_IFTYPE_GRE, info_data) < 0 ||
		__ni_discover_tunnel_addresses(&dev->link, NI_IFTYPE_GRE, info_data)) {
		ni_error("%s: Unable to discover gre tunnel details",
			dev ? dev->name : NULL);
		return -1;
	}

	return 0;
}

/*
 * Dump tunnel data for debugging purposes.
 */
static void
__ni_tunnel_trace(ni_netdev_t *dev, struct nlattr **info_data)
{
	ni_sockaddr_t addr;
	uint32_t link;
	uint16_t flags;
	uint8_t pmtudisc;
	uint8_t proto;
	uint8_t tos;
	uint8_t ttl;

	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
		if (info_data[IFLA_IPTUN_LINK]) {
			link = nla_get_u32(info_data[IFLA_IPTUN_LINK]);
			ni_trace("%s:IFLA_IPTUN_LINK: %u", dev->name, link);
		}
		if (info_data[IFLA_IPTUN_LOCAL]) {
			__ni_nla_get_addr(AF_INET, &addr, info_data[IFLA_IPTUN_LOCAL]);
			ni_trace("%s:IFLA_IPTUN_LOCAL: %s", dev->name, ni_sockaddr_print(&addr));
		}
		if (info_data[IFLA_IPTUN_REMOTE]) {
			__ni_nla_get_addr(AF_INET, &addr, info_data[IFLA_IPTUN_REMOTE]);
			ni_trace("%s:IFLA_IPTUN_REMOTE: %s", dev->name, ni_sockaddr_print(&addr));
		}
		if (info_data[IFLA_IPTUN_TTL]) {
			ttl = nla_get_u8(info_data[IFLA_IPTUN_TTL]);
			ni_trace("%s:IFLA_IPTUN_TTL: %u", dev->name, ttl);
		}
		if (info_data[IFLA_IPTUN_TOS]) {
			tos = nla_get_u8(info_data[IFLA_IPTUN_TOS]);
			ni_trace("%s:IFLA_IPTUN_TOS: %u", dev->name, tos);
		}
		if (info_data[IFLA_IPTUN_PMTUDISC]) {
			pmtudisc = nla_get_u8(info_data[IFLA_IPTUN_PMTUDISC]);
			ni_trace("%s:IFLA_IPTUN_PMTUDISC: %u", dev->name, pmtudisc);
		}
		if (info_data[IFLA_IPTUN_PROTO]) {
			proto = nla_get_u8(info_data[IFLA_IPTUN_PROTO]);
			ni_trace("%s:IFLA_IPTUN_PROTO: %u", dev->name, proto);
		}
		if (info_data[IFLA_IPTUN_FLAGS]) {
			flags = nla_get_u16(info_data[IFLA_IPTUN_FLAGS]);
			ni_trace("%s:IFLA_IPTUN_FLAGS: %u", dev->name, flags);
		}
	}
}

/*
 * Dump gre tunnel data for debugging purposes.
 */
static void
__ni_tunnel_gre_trace(ni_netdev_t *dev, struct nlattr **info_data)
{
	ni_sockaddr_t addr;
	uint32_t link;
	uint16_t flags;
	uint8_t pmtudisc;
	uint8_t tos;
	uint8_t ttl;

	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
		if (info_data[IFLA_GRE_LINK]) {
			link = nla_get_u32(info_data[IFLA_GRE_LINK]);
			ni_trace("%s:IFLA_GRE_LINK: %u", dev->name, link);
		}
		if (info_data[IFLA_GRE_LOCAL]) {
			__ni_nla_get_addr(AF_INET, &addr, info_data[IFLA_GRE_LOCAL]);
			ni_trace("%s:IFLA_GRE_LOCAL: %s", dev->name, ni_sockaddr_print(&addr));
		}
		if (info_data[IFLA_GRE_REMOTE]) {
			__ni_nla_get_addr(AF_INET, &addr, info_data[IFLA_GRE_REMOTE]);
			ni_trace("%s:IFLA_GRE_REMOTE: %s", dev->name, ni_sockaddr_print(&addr));
		}
		if (info_data[IFLA_GRE_TTL]) {
			ttl = nla_get_u8(info_data[IFLA_GRE_TTL]);
			ni_trace("%s:IFLA_GRE_TTL: %u", dev->name, ttl);
		}
		if (info_data[IFLA_GRE_TOS]) {
			tos = nla_get_u8(info_data[IFLA_GRE_TOS]);
			ni_trace("%s:IFLA_GRE_TOS: %u", dev->name, tos);
		}
		if (info_data[IFLA_GRE_PMTUDISC]) {
			pmtudisc = nla_get_u8(info_data[IFLA_GRE_PMTUDISC]);
			ni_trace("%s:IFLA_GRE_PMTUDISC: %u", dev->name, pmtudisc);
		}
		if (info_data[IFLA_GRE_FLAGS]) {
			flags = nla_get_u16(info_data[IFLA_GRE_FLAGS]);
			ni_trace("%s:IFLA_GRE_FLAGS: %u", dev->name, flags);
		}
	}
}

/*
 * Catch-all for (currentl sit, ipip and gre) tunnel discovery.
 */
static int
__ni_discover_tunneling(ni_netdev_t *dev, struct nlattr **tb)
{
	struct nlattr *link_info[IFLA_INFO_MAX+1];
	struct nlattr *iptun_data[IFLA_IPTUN_MAX+1];
	struct nlattr *gre_data[IFLA_GRE_MAX+1];

	if (!dev || !tb) {
		ni_error("%s: Unable to discover interface details",
			dev ? dev->name : NULL);
		return -1;
	}

	/* IFLA_LINKINFO is extended interface info. Not all interfaces will
	 * provide this.
	 */
	if (!tb[IFLA_LINKINFO]) {
		ni_debug_ifconfig("%s: no extended linkinfo data provided",
				dev ? dev->name : NULL);
		return 0;
	}

	if (nla_parse_nested(link_info, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL) < 0) {
		ni_error("%s: unable to parse IFLA_LINKINFO", dev->name);
		return -1;
	}

	switch (dev->link.type) {
	case NI_IFTYPE_IPIP:
		if (link_info[IFLA_INFO_DATA] &&
			nla_parse_nested(iptun_data, IFLA_IPTUN_MAX, link_info[IFLA_INFO_DATA], NULL) < 0) {
			ni_error("%s: unable to parse IFLA_INFO_DATA", dev->name);
			return -1;
		}
		__ni_tunnel_trace(dev, iptun_data);
		__ni_discover_ipip(dev, link_info, iptun_data);
		break;

	case NI_IFTYPE_SIT:
		if (link_info[IFLA_INFO_DATA] &&
			nla_parse_nested(iptun_data, IFLA_IPTUN_MAX, link_info[IFLA_INFO_DATA], NULL) < 0) {
			ni_error("%s: unable to parse IFLA_INFO_DATA", dev->name);
			return -1;
		}
		__ni_tunnel_trace(dev, iptun_data);
		__ni_discover_sit(dev, link_info, iptun_data);
		break;

	case NI_IFTYPE_GRE:
		if (link_info[IFLA_INFO_DATA] &&
			nla_parse_nested(gre_data, IFLA_GRE_MAX, link_info[IFLA_INFO_DATA], NULL) < 0) {
			ni_error("%s: unable to parse IFLA_INFO_DATA", dev->name);
			return -1;
		}
		__ni_tunnel_gre_trace(dev, gre_data);
		__ni_discover_gre(dev, link_info, gre_data);
		break;

	default:
		break;
	}

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
		cache_info = __ni_nla_get_data(sizeof(*cache_info), tb[PREFIX_CACHEINFO]);
		if (cache_info) {
			pi->lifetime.preferred_lft = cache_info->preferred_time;
			pi->lifetime.valid_lft = cache_info->valid_time;
		} else {
			ni_error("%s: cannot get rtnl PREFIX message lifetimes data", ifname);
			return -1;
		}
	} else {
		ni_error("%s: rtnl PREFIX message without lifetimes", ifname);
		return -1;
	}

	pi->length = pfx->prefix_len;
	pi->on_link = pfx->prefix_flags & IF_PREFIX_ONLINK;
	pi->autoconf = pfx->prefix_flags & IF_PREFIX_AUTOCONF;
	return 0;
}

static inline void
__newaddr_trace(unsigned int family, const char *name, struct nlattr *attr)
{
	ni_sockaddr_t temp;
	if (attr && name) {
		if (__ni_nla_get_addr(family, &temp, attr))
			ni_trace("newaddr[%s]: ---", name);
		else
			ni_trace("newaddr[%s]: %s", name, ni_sockaddr_print(&temp));
	} else if(name) {
		ni_trace("newaddr[%s]: NULL", name);
	}
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

	if (ni_log_level_at(NI_LOG_DEBUG3) && (ni_log_facility(NI_TRACE_EVENTS))) {
		ni_trace("newaddr(%s): family %d, prefixlen %u, scope %u, flags %u",
			(ifflags & NI_IFF_POINT_TO_POINT) ? "ptp" : "brd",
			ap->family, ap->prefixlen, ap->scope, ap->flags);
		__newaddr_trace(ifa->ifa_family, __ni_string(IFA_LOCAL), tb[IFA_LOCAL]);
		__newaddr_trace(ifa->ifa_family, __ni_string(IFA_ADDRESS), tb[IFA_ADDRESS]);
		__newaddr_trace(ifa->ifa_family, __ni_string(IFA_BROADCAST), tb[IFA_BROADCAST]);
		__newaddr_trace(ifa->ifa_family, __ni_string(IFA_ANYCAST), tb[IFA_ANYCAST]);
	}

	/*
	 * Quoting linux/if_addr.h:
	 * IFA_ADDRESS is prefix address, rather than local interface address.
	 * It makes no difference for normally configured broadcast interfaces,
	 * but for point-to-point IFA_ADDRESS is DESTINATION address,
	 * local address is supplied in IFA_LOCAL attribute.
	 */
	if (ifflags & NI_IFF_POINT_TO_POINT) {
		if (tb[IFA_LOCAL]) {
			/* local peer remote */
			__ni_nla_get_addr(ifa->ifa_family, &ap->local_addr, tb[IFA_LOCAL]);
			__ni_nla_get_addr(ifa->ifa_family, &ap->peer_addr, tb[IFA_ADDRESS]);
		} else
		if (tb[IFA_ADDRESS]) {
			/* local only, e.g. tunnel ipv6 link layer address */
			__ni_nla_get_addr(ifa->ifa_family, &ap->local_addr, tb[IFA_ADDRESS]);
		}
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
		const struct ifa_cacheinfo *ci;
		ci = __ni_nla_get_data(sizeof(*ci), tb[IFA_CACHEINFO]);
		if (ci) {
			ni_timer_get_time(&ap->ipv6_cache_info.since);
			ap->ipv6_cache_info.valid_lft = ci->ifa_valid;
			ap->ipv6_cache_info.preferred_lft = ci->ifa_prefered;
		}
	}

	if (tb[IFA_LABEL] != NULL)
		ni_string_dup(&ap->label, nla_get_string(tb[IFA_LABEL]));

	return 0;
}

int
__ni_netdev_process_newaddr_event(ni_netdev_t *dev, struct nlmsghdr *h, struct ifaddrmsg *ifa,
					const ni_address_t **hint)
{
	ni_address_t tmp, *ap;

	if (__ni_rtnl_parse_newaddr(dev->link.ifflags, h, ifa, &tmp) < 0)
		return -1;

	ap = ni_address_list_find(dev->addrs, &tmp.local_addr);
	if (!ap) {
		ap = ni_netdev_add_address(dev, tmp.family, tmp.prefixlen, &tmp.local_addr);
		if (!ap) {
			ni_string_free(&tmp.label);
			return -1;
		}
	}
	ap->seq = dev->seq;
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

	if (ap->owner == NI_ADDRCONF_NONE) {
		ni_addrconf_lease_t *lease;

		if ((lease = __ni_netdev_address_to_lease(dev, ap, 0)))
			ap->owner = lease->type;
	}

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
			(ap->owner ? ni_addrconf_type_to_name(ap->owner) : "none"));
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


static inline ni_bool_t
__ni_newroute_filter_msg(struct rtmsg *rtm)
{
	switch (rtm->rtm_family) {
	case AF_INET:
	case AF_INET6:
		break;
	default:
		/* AF_DECnet, AF_IPX */
		return TRUE;
	}

	switch (rtm->rtm_type) {
	case RTN_LOCAL:
	case RTN_UNICAST:
	case RTN_PROHIBIT:
	case RTN_BLACKHOLE:
	case RTN_UNREACHABLE:
		break;
	default:
	/* Filter out for now */
	case RTN_NAT:
	case RTN_THROW:
	case RTN_ANYCAST:
	case RTN_MULTICAST:
	case RTN_BROADCAST:
	case RTN_XRESOLVE:
	case RTN_UNSPEC:
		return TRUE;
	}

	switch ((unsigned int)rtm->rtm_table) {
	case RT_TABLE_LOCAL:
	case RT_TABLE_UNSPEC:
	case RT_TABLE_MAX:
		return TRUE;
	default:
		break;
	}

	switch (rtm->rtm_protocol) {
	case RTPROT_REDIRECT:
		return TRUE;
	default:
		break;
	}

	if (rtm->rtm_src_len != 0)
		return TRUE;

	if (rtm->rtm_flags & RTM_F_CLONED)
		return TRUE;

	return FALSE;
}

static int
__ni_process_newroute_nexthop(ni_route_t *rp, ni_route_nexthop_t *nh,
				struct rtnexthop *rtnh)
{
	if (rtnh->rtnh_ifindex <= 0) {
		ni_warn("Cannot parse rtnl multipath route with interface index %d",
			rtnh->rtnh_ifindex);
		return 1;
	}

	nh->device.index = rtnh->rtnh_ifindex;
	nh->weight = rtnh->rtnh_hops + 1;
	nh->flags = rtnh->rtnh_flags;

	if (rtnh->rtnh_len > sizeof(*rtnh)) {
		struct nlattr *ntb[RTA_MAX + 1];

		if (nla_parse(ntb, RTA_MAX, (struct nlattr *)RTNH_DATA(rtnh),
				rtnh->rtnh_len - sizeof(*rtnh), NULL) < 0) {
			ni_warn("Cannot parse rtnl multipath route attributes");
			return 1;
		}

		if (ntb[RTA_GATEWAY]) {
			if (__ni_nla_get_addr(rp->family, &nh->gateway,
						ntb[RTA_GATEWAY]) != 0) {
				ni_warn("Cannot parse rtnl multipath route gateway");
				return 1;
			}
		}
		if (ntb[RTA_FLOW]) {
			nh->realm = nla_get_u32(ntb[RTA_FLOW]);
		}
	}

	return 0;
}

static int
__ni_process_newroute_multipath(ni_route_t *rp, struct nlattr *multipath)
{
	struct rtnexthop *rtnh = RTA_DATA(multipath);
	size_t len = nla_len(multipath);
	ni_route_nexthop_t *nh = &rp->nh, **tail = &nh;

	while (len >= sizeof(*rtnh) && len >= rtnh->rtnh_len) {
		if (nh == NULL) {
			*tail = nh = ni_route_nexthop_new();
		}

		if (__ni_process_newroute_nexthop(rp, nh, rtnh) != 0)
			return 1;

		len -= RTNH_ALIGN(rtnh->rtnh_len);
		rtnh = RTNH_NEXT(rtnh);
		tail = &nh->next;
		nh   = NULL;
	}
	return len == 0 ? 0 : -1;
}

static int
__ni_process_newroute_metrics(ni_route_t *rp, struct nlattr *metrics)
{
	struct nlattr *rtattrs[__RTAX_MAX+1], *rtax;

	if (nla_parse_nested(rtattrs, __RTAX_MAX, metrics, NULL) < 0) {
		ni_warn("Cannot parse rtnl route metrics attributes");
		return 1;
	}
	if ((rtax = rtattrs[RTAX_LOCK]) != NULL)
		rp->lock = nla_get_u32(rtax);
	if ((rtax = rtattrs[RTAX_MTU]) != NULL)
		rp->mtu = nla_get_u32(rtax);
	if ((rtax = rtattrs[RTAX_WINDOW]) != NULL)
		rp->window = nla_get_u32(rtax);
	if ((rtax = rtattrs[RTAX_RTT]) != NULL) {
		rp->rtt = nla_get_u32(rtax);
		rp->rtt /= 8;
	}
	if ((rtax = rtattrs[RTAX_RTTVAR]) != NULL) {
		rp->rttvar = nla_get_u32(rtax);
		rp->rttvar /= 4;
	}
	if ((rtax = rtattrs[RTAX_SSTHRESH]) != NULL)
		rp->ssthresh = nla_get_u32(rtax);
	if ((rtax = rtattrs[RTAX_CWND]) != NULL)
		rp->cwnd = nla_get_u32(rtax);
	if ((rtax = rtattrs[RTAX_ADVMSS]) != NULL)
		rp->advmss = nla_get_u32(rtax);
	if ((rtax = rtattrs[RTAX_REORDERING]) != NULL)
		rp->reordering = nla_get_u32(rtax);
	if ((rtax = rtattrs[RTAX_HOPLIMIT]) != NULL) {
		rp->hoplimit = nla_get_u32(rtax);
		if (rp->hoplimit == -1U)
			rp->hoplimit = 0;
	}
	if ((rtax = rtattrs[RTAX_INITCWND]) != NULL)
		rp->initcwnd = nla_get_u32(rtax);
	if ((rtax = rtattrs[RTAX_FEATURES]) != NULL)
		rp->features = nla_get_u32(rtax);
	if ((rtax = rtattrs[RTAX_RTO_MIN]) != NULL)
		rp->rto_min = nla_get_u32(rtax);
#if defined(RTAX_INITRWND)
	if ((rtax = rtattrs[RTAX_INITRWND]) != NULL)
		rp->initrwnd = nla_get_u32(rtax);
#endif

	return 0;
}

int
__ni_netdev_record_newroute(ni_netconfig_t *nc, ni_netdev_t *dev, ni_route_t *rp)
{
	ni_stringbuf_t  buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_uint_array_t idx = NI_UINT_ARRAY_INIT;
	ni_route_nexthop_t *nh;
	int ret = 1;

	if (!nc || !rp)
		return -1;

	for (nh = &rp->nh; ret != -1 && nh; nh = nh->next) {
		if (nh->device.index == 0 ||
		    ni_uint_array_contains(&idx, nh->device.index))
			continue;

		if (!dev || (nh->device.index != dev->link.ifindex)) {
			dev = ni_netdev_by_index(nc, nh->device.index);
		}

		if (!dev) {
			ni_warn("Unable to find route device with index %u: %s",
				nh->device.index, ni_route_print(&buf, rp));
			ni_stringbuf_destroy(&buf);
			ret = -1;
		} else
		if (!ni_route_tables_add_route(&dev->routes, ni_route_ref(rp))) {
			ni_warn("Unable to record route for device %s[%u]: %s",
				dev->name, dev->link.ifindex, ni_route_print(&buf, rp));
			ni_stringbuf_destroy(&buf);
			ret = -1;
		} else
		if (!ni_uint_array_append(&idx, nh->device.index)) {
			ni_warn("Unable to track route device index %u",
				nh->device.index);
			ret = -1;
		} else {
#if 0
			ni_debug_ifconfig("Route recorded for device %s[%u]: %s",
				dev->name, dev->link.ifindex, ni_route_print(&buf, rp));
			ni_stringbuf_destroy(&buf);
#endif
			ret = 0;
		}
	}

	ni_uint_array_destroy(&idx);
	return ret;
}

int
__ni_netdev_process_newroute(ni_netdev_t *dev, struct nlmsghdr *h,
				struct rtmsg *rtm, ni_netconfig_t *nc)
{
	ni_addrconf_lease_t *lease;
	struct nlattr *tb[RTA_MAX+1];
	ni_route_t *rp;
	int ret = 1;

#if 0
	char *table_name = NULL;
	ni_debug_ifconfig("RTM_NEWROUTE family=%d dstlen=%u srclen=%u type=%s proto=%s flags=0x%x table=%s scope=%s",
			rtm->rtm_family,
			rtm->rtm_dst_len,
			rtm->rtm_src_len,
			ni_route_type_type_to_name(rtm->rtm_type),
			ni_route_protocol_type_to_name(rtm->rtm_protocol),
			rtm->rtm_flags,
			ni_route_table_type_to_name(rtm->rtm_table, &table_name),
			ni_route_scope_type_to_name(rtm->rtm_scope)
			);
	ni_string_free(&table_name);
#endif

	/* filter unwanted / unsupported  msgs */
	if (__ni_newroute_filter_msg(rtm))
		return 1;

	memset(tb, 0, sizeof(tb));
	if (nlmsg_parse(h, sizeof(*rtm), tb, RTN_MAX, NULL) < 0) {
		ni_warn("Cannot parse rtnl route message");
		return 1;
	}

	rp = ni_route_new();
	rp->family = rtm->rtm_family;
	rp->type = rtm->rtm_type;
	rp->table = rtm->rtm_table;
	if (tb[RTA_TABLE] != NULL) {
		rp->table = nla_get_u32(tb[RTA_TABLE]);
	}
	rp->scope = rtm->rtm_scope;
	rp->protocol = rtm->rtm_protocol;
	rp->flags = rtm->rtm_flags;
	rp->tos = rtm->rtm_tos;

	rp->prefixlen = rtm->rtm_dst_len;
	if (rtm->rtm_dst_len == 0) {
		rp->destination.ss_family = rtm->rtm_family;
	} else
	if (__ni_nla_get_addr(rtm->rtm_family, &rp->destination, tb[RTA_DST]) != 0) {
		ni_warn("Cannot parse rtnl route destination address");
		goto failure;
	}

	if (dev) {
		rp->seq = dev->seq;
		rp->nh.device.index = dev->link.ifindex;
		/*
		 * Hmm... not now.
		 * Better to resolve it when needed I think, so we
		 * don't need to care about interface renames.
		 */
#if 0
		ni_string_dup(&rp->nh.device.name, dev->name);
#endif
	}
	if (tb[RTA_GATEWAY] != NULL) {
		if (__ni_nla_get_addr(rtm->rtm_family, &rp->nh.gateway,
					tb[RTA_GATEWAY]) != 0) {
			ni_warn("Cannot parse rtnl route gateway address");
			goto failure;
		}
	} else
	if (tb[RTA_MULTIPATH] != NULL) {
		if (__ni_process_newroute_multipath(rp, tb[RTA_MULTIPATH]) != 0)
			goto failure;
	}

	if (tb[RTA_PREFSRC] != NULL)
		__ni_nla_get_addr(rtm->rtm_family, &rp->pref_src, tb[RTA_PREFSRC]);

	if (tb[RTA_PRIORITY] != NULL)
		rp->priority = nla_get_u32(tb[RTA_PRIORITY]);

	if (tb[RTA_FLOW] != NULL)
		rp->realm = nla_get_u32(tb[RTA_FLOW]);

#if defined(HAVE_RTA_MARK)
	if (tb[RTA_MARK] != NULL)
		rp->mark = nla_get_u32(tb[RTA_MARK]);
#endif

	if (tb[RTA_METRICS] != NULL) {
		if (__ni_process_newroute_metrics(rp, tb[RTA_METRICS]) != 0)
			goto failure;
	}

	/* Add routes to the device[s] references in hops -- once */
	if ((ret = __ni_netdev_record_newroute(nc, dev, rp)) < 0)
		goto failure;

	(void)lease;
#if 0
	/* See if this route is owned by a lease */
	if (dev) {
		lease = __ni_netdev_route_to_lease(dev, rp);
		if (lease)
			rp->owner = lease->type;
	}
#endif

failure:
	/* Release our reference */
	ni_route_free(rp);
	return ret;
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
__ni_discover_infiniband(ni_netdev_t *dev, ni_netconfig_t *nc)
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
	} else if (!ni_string_eq(dev->link.lowerdev.name, value)) {
		ni_string_free(&dev->link.lowerdev.name);
		dev->link.lowerdev.name = value;
		ni_netdev_ref_bind_ifindex(&dev->link.lowerdev, nc);
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
