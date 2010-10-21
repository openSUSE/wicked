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
#include <linux/ethtool.h>

#include <wicked/netinfo.h>
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

/*
 * Refresh all interfaces
 */
int
__ni_system_refresh_all(ni_handle_t *nih)
{
	ni_interface_t **tail, *ifp;
	struct ni_nlmsg_list link_info, addr_info, route_info;
	struct ni_nlmsg *entry;
	unsigned int seqno;
	int res = -1;

	seqno = ++(nih->seqno);

	ni_nlmsg_list_init(&link_info);
	ni_nlmsg_list_init(&addr_info);
	ni_nlmsg_list_init(&route_info);

	if (ni_rtnl_dump_store(nih, RTM_GETLINK, &link_info) < 0
	 || ni_rtnl_dump_store(nih, RTM_GETADDR, &addr_info) < 0
	 || ni_rtnl_dump_store(nih, RTM_GETROUTE, &route_info) < 0)
		goto failed;

	/* Find tail of iflist */
	tail = &nih->iflist;
	while ((ifp = *tail) != NULL)
		tail = &ifp->next;

	for (entry = link_info.head; entry; entry = entry->next) {
		struct nlmsghdr *h = &entry->h;
		struct ifinfomsg *ifi;
		struct rtattr *rta;
		char *ifname = NULL;

		if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_NEWLINK)))
			continue;

		if ((rta = __ni_rta_find(IFLA_RTA(ifi), IFLA_PAYLOAD(h), IFLA_IFNAME)) == NULL) {
			warn("RTM_NEWLINK message without IFNAME");
			continue;
		}
		ifname = (char *) RTA_DATA(rta);

		/* Create interface if it doesn't exist. */
		if ((ifp = ni_interface_by_index(nih, ifi->ifi_index)) == NULL) {
			ifp = __ni_interface_new(ifname, ifi->ifi_index);
			if (!ifp)
				goto failed;
			*tail = ifp;
			tail = &ifp->next;
		} else {
			/* Clear out addresses and routes */
			__ni_interface_clear_addresses(ifp);
			__ni_interface_clear_routes(ifp);
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

	for (entry = addr_info.head; entry; entry = entry->next) {
		struct nlmsghdr *h = &entry->h;
		struct ifaddrmsg *ifa;

		if (!(ifa = ni_rtnl_ifaddrmsg(h, RTM_NEWADDR)))
			continue;

		if ((ifp = ni_interface_by_index(nih, ifa->ifa_index)) == NULL)
			continue;

		if (__ni_interface_process_newaddr(ifp, h, ifa, nih) < 0)
			error("Problem parsing RTM_NEWADDR message for %s", ifp->name);
	}

	for (entry = route_info.head; entry; entry = entry->next) {
		struct nlmsghdr *h = &entry->h;
		struct rtattr *rta;
		struct rtmsg *rtm;

		if (!(rtm = ni_rtnl_rtmsg(h, RTM_NEWROUTE)))
			continue;

		rta = __ni_rta_find(RTM_RTA(rtm), RTM_PAYLOAD(h), RTA_OIF);
		if (rta != NULL) {
			unsigned int oif_index;

			__ni_rta_get_uint(&oif_index, rta);
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
			ni_interface_put(ifp);
		} else {
			tail = &ifp->next;
		}
	}

	res = 0;

failed:
	ni_nlmsg_list_destroy(&link_info);
	ni_nlmsg_list_destroy(&addr_info);
	ni_nlmsg_list_destroy(&route_info);
	return res;
}

/*
 * Refresh one interfaces
 */
int
__ni_system_refresh_interface(ni_handle_t *nih, ni_interface_t *ifp)
{
	struct ni_nlmsg_list link_info, addr_info, route_info;
	struct ni_nlmsg *entry;
	int	res = -1;

	nih->seqno++;

	ni_nlmsg_list_init(&link_info);
	ni_nlmsg_list_init(&addr_info);
	ni_nlmsg_list_init(&route_info);

	if (ni_rtnl_dump_store(nih, RTM_GETLINK, &link_info) < 0
	 || ni_rtnl_dump_store(nih, RTM_GETADDR, &addr_info) < 0
	 || ni_rtnl_dump_store(nih, RTM_GETROUTE, &route_info) < 0)
		goto failed;

	for (entry = link_info.head; entry; entry = entry->next) {
		struct nlmsghdr *h = &entry->h;
		struct ifinfomsg *ifi;

		if (!(ifi = ni_rtnl_ifinfomsg(h, RTM_NEWLINK)))
			continue;

		/* Only refresh the interface we're interested in. */
		if (ifp->ifindex != ifi->ifi_index)
			continue;

		/* Clear out addresses and routes */
		__ni_interface_clear_addresses(ifp);
		__ni_interface_clear_routes(ifp);

		if (__ni_interface_process_newlink(ifp, h, ifi, nih) < 0)
			error("Problem parsing RTM_NEWLINK message for %s", ifp->name);
	}

	if (ifp->vlan && ni_vlan_bind_ifindex(ifp->vlan, nih) < 0) {
		error("VLAN interface %s references unknown base interface (ifindex %u)",
			ifp->name, ifp->vlan->link);
		/* Ignore error and proceed */
		ni_string_dup(&ifp->vlan->interface_name, "unknown");
	}

	for (entry = addr_info.head; entry; entry = entry->next) {
		struct nlmsghdr *h = &entry->h;
		struct ifaddrmsg *ifa;

		if (!(ifa = ni_rtnl_ifaddrmsg(h, RTM_NEWADDR)))
			continue;

		if (ifa->ifa_index != ifp->ifindex)
			continue;

		if (__ni_interface_process_newaddr(ifp, h, ifa, nih) < 0)
			error("Problem parsing RTM_NEWADDR message for %s", ifp->name);
	}

	for (entry = route_info.head; entry; entry = entry->next) {
		struct nlmsghdr *h = &entry->h;
		unsigned int oif_index;
		struct rtattr *rta;
		struct rtmsg *rtm;

		if (!(rtm = ni_rtnl_rtmsg(h, RTM_NEWROUTE)))
			continue;

		rta = __ni_rta_find(RTM_RTA(rtm), RTM_PAYLOAD(h), RTA_OIF);
		if (rta == NULL)
			continue;
		
		__ni_rta_get_uint(&oif_index, rta);
		if (oif_index != ifp->ifindex)
			continue;

		if (__ni_interface_process_newroute(ifp, h, rtm, NULL) < 0)
			error("Problem parsing RTM_NEWROUTE message");
	}

	res = 0;

failed:
	ni_nlmsg_list_destroy(&link_info);
	ni_nlmsg_list_destroy(&addr_info);
	ni_nlmsg_list_destroy(&route_info);
	return res;
}

/*
 * Refresh interface link layer given a RTM_NEWLINK message
 */
int
__ni_interface_process_newlink(ni_interface_t *ifp, struct nlmsghdr *h,
				struct ifinfomsg *ifi, ni_handle_t *nih)
{
	struct rtattr *tb[IFLA_MAX+1];
	char *ifname;

	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(h));

	/* Update interface name in case it changed */
	if ((ifname = (char *) RTA_DATA(tb[IFLA_IFNAME])) != NULL)
		strncpy(ifp->name, ifname, sizeof(ifp->name) - 1);

	ifp->arp_type = ifi->ifi_type;
	ifp->flags = ifi->ifi_flags;
	ifp->ipv4.config = NI_ADDRCONF_STATIC;
	ifp->ipv6.config = NI_ADDRCONF_AUTOCONF;
	ifp->type = NI_IFTYPE_UNKNOWN;

	__ni_rta_get_uint(&ifp->mtu, tb[IFLA_MTU]);
	__ni_rta_get_uint(&ifp->txqlen, tb[IFLA_TXQLEN]);
	__ni_rta_get_uint(&ifp->metric, tb[IFLA_COST]);
	__ni_rta_get_string(&ifp->qdisc, tb[IFLA_QDISC]);
	__ni_rta_get_uint(&ifp->master, tb[IFLA_MASTER]);

	if (tb[IFLA_STATS]) {
		struct rtnl_link_stats *s = RTA_DATA(tb[IFLA_STATS]);
		ni_link_stats_t *n;

		if (!ifp->link_stats)
			ifp->link_stats = calloc(1, sizeof(*n));
		n = ifp->link_stats;

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
		struct rtattr *linkinfo[IFLA_INFO_MAX+1];
		int info_data_used = 0;

		parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);
		__ni_rta_get_string(&ifp->kind, linkinfo[IFLA_INFO_KIND]);

		if (ifp->kind) {
			/* Do something with these */
			if (!strcmp(ifp->kind, "vlan")) {
				struct rtattr *vlan_info[IFLA_VLAN_MAX+1];
				ni_vlan_t *vlancfg;

				ifp->type = NI_IFTYPE_VLAN;
				vlancfg = ni_interface_get_vlan(ifp);
				vlancfg->link = 0;

				/* IFLA_LINK contains the ifindex of the real ether dev */
				__ni_rta_get_uint(&vlancfg->link, tb[IFLA_LINK]);

				parse_rtattr_nested(vlan_info, IFLA_VLAN_MAX, linkinfo[IFLA_INFO_DATA]);
				__ni_rta_get_uint16(&vlancfg->tag, vlan_info[IFLA_VLAN_ID]);
				info_data_used = 1;
			}
		}

		if (linkinfo[IFLA_INFO_DATA] && !info_data_used)
			warn("iflist: link info data of type %s - don't know what to do with it", ifp->kind);
	}

	if (ifp->type == NI_IFTYPE_UNKNOWN) {
		struct ethtool_drvinfo drv_info;

		switch (ifp->arp_type) {
		case ARPHRD_ETHER:
		case ARPHRD_NONE:	/* tun driver uses this */
			ifp->type = NI_IFTYPE_ETHERNET;
			if (__ni_ethtool(nih, ifp, ETHTOOL_GDRVINFO, &drv_info) >= 0) {
				const char *driver = drv_info.driver;

				if (!strcmp(driver, "tun")) {
					/* tun/tap driver */
					if (!strcmp(drv_info.bus_info, "tap"))
						ifp->type = NI_IFTYPE_TAP;
					else
						ifp->type = NI_IFTYPE_TUN;
				} else if (!strcmp(driver, "bridge")) {
					ifp->type = NI_IFTYPE_BRIDGE;
				} else if (!strcmp(driver, "bonding")) {
					ifp->type = NI_IFTYPE_BOND;
				}
			}

			/* FIXME: detect WLAN device */
			break;

		default:
			ifp->type = ni_arphrd_type_to_iftype(ifp->arp_type);
			break;
		}
	}

	if (tb[IFLA_ADDRESS]) {
		unsigned int alen = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
		void *data = RTA_DATA(tb[IFLA_ADDRESS]);

		if (alen > sizeof(ifp->hwaddr.data))
			alen = sizeof(ifp->hwaddr.data);
		memcpy(ifp->hwaddr.data, data, alen);
		ifp->hwaddr.len = alen;
		ifp->hwaddr.type = ifp->type;
	} else {
		memset(&ifp->hwaddr, 0, sizeof(ifp->hwaddr));
	}

	if (ifp->type == NI_IFTYPE_BRIDGE)
		__ni_discover_bridge(ifp);
	if (ifp->type == NI_IFTYPE_BOND)
		__ni_discover_bond(ifp);

	/* Check if we have DHCP running for this interface */
	__ni_discover_addrconf(nih, ifp);

	return 0;
}

/*
 * Update interface address list given a RTM_NEWADDR message
 */
static int
__ni_interface_process_newaddr(ni_interface_t *ifp, struct nlmsghdr *h,
				struct ifaddrmsg *ifa, ni_handle_t *nih)
{
	struct rtattr *tb[IFA_MAX+1];
	ni_addrconf_lease_t *lease;
	ni_address_t tmp, *ap;

	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(h));
	memset(&tmp, 0, sizeof(tmp));

	/*
	 * Quoting linux/if_addr.h:
	 * IFA_ADDRESS is prefix address, rather than local interface address.
	 * It makes no difference for normally configured broadcast interfaces,
	 * but for point-to-point IFA_ADDRESS is DESTINATION address,
	 * local address is supplied in IFA_LOCAL attribute.
	 */
	if (ifp->flags & IFF_POINTOPOINT) {
		__ni_rta_get_addr(ifa->ifa_family, &tmp.local_addr, tb[IFA_LOCAL]);
		__ni_rta_get_addr(ifa->ifa_family, &tmp.peer_addr, tb[IFA_ADDRESS]);
		/* Note iproute2 code obtains peer_addr from IFA_BROADCAST */
	} else {
		__ni_rta_get_addr(ifa->ifa_family, &tmp.local_addr, tb[IFA_ADDRESS]);
		__ni_rta_get_addr(ifa->ifa_family, &tmp.bcast_addr, tb[IFA_BROADCAST]);
	}
	__ni_rta_get_addr(ifa->ifa_family, &tmp.anycast_addr, tb[IFA_ANYCAST]);

	ap = ni_address_new(ifp, ifa->ifa_family, ifa->ifa_prefixlen, &tmp.local_addr);
	ap->scope = ifa->ifa_scope;
	ap->flags = ifa->ifa_flags;
	ap->peer_addr = tmp.peer_addr;
	ap->bcast_addr = tmp.bcast_addr;
	ap->anycast_addr = tmp.anycast_addr;

	/* See if this address is owned by a lease */
	lease = __ni_interface_address_to_lease(ifp, ap);
	if (lease)
		ap->config_method = lease->type;

	return 0;
}

int
__ni_interface_process_newroute(ni_interface_t *ifp, struct nlmsghdr *h,
				struct rtmsg *rtm, ni_handle_t *nih)
{
	struct sockaddr_storage src_addr, dst_addr, gw_addr;
	ni_addrconf_lease_t *lease;
	struct rtattr *tb[RTN_MAX+1];
	ni_route_t *rp;

	if (rtm->rtm_table != RT_TABLE_MAIN)
		return 0;

	if (rtm->rtm_protocol == RTPROT_REDIRECT)
		return 0;

	if (rtm->rtm_protocol != RTPROT_BOOT
	 && rtm->rtm_protocol != RTPROT_STATIC)
		return 0;

	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, RTN_MAX, RTM_RTA(rtm), RTM_PAYLOAD(h));

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
		__ni_rta_get_addr(rtm->rtm_family, &src_addr, tb[RTA_SRC]);

	memset(&dst_addr, 0, sizeof(dst_addr));
	if (rtm->rtm_dst_len != 0) {
		if (tb[RTA_DST] == NULL)
			return 0;
		__ni_rta_get_addr(rtm->rtm_family, &dst_addr, tb[RTA_DST]);
	}

	memset(&gw_addr, 0, sizeof(gw_addr));
	if (tb[RTA_GATEWAY] != NULL)
		__ni_rta_get_addr(rtm->rtm_family, &gw_addr, tb[RTA_GATEWAY]);

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
	if (oif_index)
		printf(" oif=%u", oif_index);
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
		__ni_rta_get_uint(&rp->priority, tb[RTA_PRIORITY]);
	rp->tos = rtm->rtm_tos;

	/* See if this route is owned by a lease */
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

	if (ifp->type != NI_IFTYPE_BRIDGE)
		return 0;

	bridge = ni_interface_get_bridge(ifp);
	ni_sysfs_bridge_get_config(ifp->name, &bridge->config);

	ni_string_array_init(&ports);
	ni_sysfs_bridge_get_port_names(ifp->name, &ports);
	for (i = 0; i < ports.count; ++i)
		ni_bridge_add_port(bridge, ports.data[i]);
	ni_string_array_destroy(&ports);

	for (i = 0; i < bridge->ports.count; ++i) {
		ni_bridge_port_t *port = bridge->ports.data[i];
		ni_sysfs_bridge_port_get_config(port->name, &port->config);
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

	if (ifp->type != NI_IFTYPE_BOND)
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
	const void *pos;
	xml_node_t *xml = NULL;
	unsigned int i;

	__ni_assert_initialized();

	for (i = 0; i < __NI_ADDRCONF_MAX; ++i) {
		if (ifp->ipv4.lease[i]) {
			ifp->ipv4.config = i;
			break;
		}
	}
	for (i = 0; i < __NI_ADDRCONF_MAX; ++i) {
		if (ifp->ipv6.lease[i]) {
			ifp->ipv6.config = i;
			break;
		}
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
				ifp->ipv4.config = acm->type;
			if (acm->supported_af & NI_AF_MASK_IPV6)
				ifp->ipv6.config = acm->type;
		}
	}

	if (xml)
		xml_node_free(xml);
	return 0;
}
