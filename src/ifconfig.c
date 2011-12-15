/*
 * Things to do when bringing an interface up or down
 *
 * Copyright (C) 2009-2011 Olaf Kirch <okir@suse.de>
 *
 * Link layer:
 *  - handle ethtool options
 *  - set device MTU
 *  - set link layer addr
 *  - set other LL options
 *  - bring up link layer
 */


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netlink/msg.h>
#include <time.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/vlan.h>
#include <wicked/xml.h>

#include "netinfo_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "config.h"
#include "debug.h"

#define BOND_DEVICE_MUST_BE_UP_WHEN_MESSING_WITH_SLAVES 1

static int	__ni_interface_addrconf(ni_netconfig_t *, int,  ni_interface_t *, ni_afinfo_t *);
static int	__ni_interface_extension_delete(ni_netconfig_t *, ni_interface_t *);
static int	__ni_interface_update_ipv6_settings(ni_netconfig_t *, ni_interface_t *, const ni_afinfo_t *);
static int	__ni_interface_update_addrs(ni_interface_t *ifp,
				int family, ni_addrconf_mode_t mode,
				ni_address_t **cfg_addr_list);
static int	__ni_interface_update_routes(ni_interface_t *ifp,
				int family, ni_addrconf_mode_t mode,
				ni_route_t **cfg_route_list);

static int	__ni_rtnl_link_create_vlan(const char *, const ni_vlan_t *, unsigned int);
static int	__ni_rtnl_link_up(const ni_interface_t *, const ni_interface_request_t *);
static int	__ni_rtnl_link_down(const ni_interface_t *, int);
static int	__ni_rtnl_send_deladdr(ni_interface_t *, const ni_address_t *);
static int	__ni_rtnl_send_newaddr(ni_interface_t *, const ni_address_t *, int);
static int	__ni_rtnl_send_delroute(ni_interface_t *, ni_route_t *);
static int	__ni_rtnl_send_newroute(ni_interface_t *, ni_route_t *, int);

/*
 * Bring up an interface
 * ni_system_interface_up
 */
int
ni_system_interface_up(ni_netconfig_t *nc, ni_interface_t *ifp, const ni_interface_request_t *ifp_req)
{
	int res;

	if (ifp == NULL || ifp_req == NULL)
		return -NI_ERROR_INVALID_ARGS;

	ni_debug_ifconfig("%s(%s)", __func__, ifp->name);

	/* FIXME: perform sanity check on configuration data */


	/* If we want to disable ipv6 or ipv6 autoconf, we need to do so prior to bringing
	 * the interface up. */
	if (__ni_interface_update_ipv6_settings(nc, ifp, ifp_req->ipv6) < 0)
		return -1;

	if (ifp_req->ifflags & (NI_IFF_DEVICE_UP|NI_IFF_LINK_UP|NI_IFF_NETWORK_UP)) {
		ni_debug_ifconfig("bringing up %s", ifp->name);
		if (__ni_rtnl_link_up(ifp, ifp_req)) {
			ni_error("%s: failed to bring up interface (rtnl error)", ifp->name);
			return -1;
		}
		ifp->link.ifflags |= ifp_req->ifflags;
	} else {
		ni_debug_ifconfig("shutting down interface %s", ifp->name);
		if (__ni_rtnl_link_down(ifp, RTM_NEWLINK)) {
			ni_error("unable to shut down interface %s", ifp->name);
			return -1;
		}
		/* down is down is down */
		ifp->up_requesters = 0;
	}

	__ni_global_seqno++;

	res = -1;

	if (!ni_interface_network_is_up(ifp)) {
		if (ifp_req->ipv4)
			ifp_req->ipv4->addrconf = 0;
		if (ifp_req->ipv6)
			ifp_req->ipv6->addrconf = 0;
	}

	if ((res = __ni_interface_addrconf(nc, AF_INET, ifp, ifp_req->ipv4)) < 0
	 || (res = __ni_interface_addrconf(nc, AF_INET6, ifp, ifp_req->ipv6)) < 0)
		goto failed;

	res = __ni_system_refresh_interface(nc, ifp);

failed:
	return res;
}

/*
 * Shut down an interface
 * ni_system_interface_down
 */
int
ni_system_interface_down(ni_netconfig_t *nc, ni_interface_t *ifp)
{
	int res = -1;

	if (ifp == NULL)
		return -NI_ERROR_INVALID_ARGS;

	ni_debug_ifconfig("%s(%s)", __func__, ifp->name);
	ni_assert(nc == ni_global_state_handle(0));

	__ni_global_seqno++;

	/* First do the addrconf fandango, then take down the interface
	 * itself. We need to do DHCP release and related stuff... */
	if ((res = __ni_interface_addrconf(nc, AF_INET, ifp, NULL)) >= 0
	 && (res = __ni_interface_addrconf(nc, AF_INET6, ifp, NULL)) >= 0)
		res = __ni_system_refresh_interface(nc, ifp);

	ni_debug_ifconfig("shutting down interface %s", ifp->name);
	if (__ni_rtnl_link_down(ifp, RTM_NEWLINK)) {
		ni_error("unable to shut down interface %s", ifp->name);
		return -1;
	}
	/* down is down is down */
	ifp->up_requesters = 0;

	return res;
}

/*
 * An address configuration agent sends a lease update.
 */
int
__ni_system_interface_update_lease(ni_interface_t *ifp, ni_addrconf_lease_t *lease)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	unsigned int update_mask;
	ni_afinfo_t *afi;
	int res;

	ni_debug_ifconfig("%s: received %s/%s lease update; state %s", ifp->name,
			ni_addrconf_type_to_name(lease->type),
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_state_to_name(lease->state));

	if ((res = __ni_system_refresh_interface(nc, ifp)) < 0)
		return -1;

	if (!(afi = __ni_interface_address_info(ifp, lease->family))) {
		ni_error("%s: unable to update lease - unknown address family", ifp->name);
		return -1;
	}

	update_mask = ni_config_addrconf_update_mask(ni_global.config, lease->type);
#if 0
	update_mask &= afi->request[lease->type]->update;
#endif

	res = __ni_interface_update_addrs(ifp, lease->family, lease->type, &lease->addrs);
	if (res < 0) {
		ni_error("%s: error updating interface config from %s lease",
				ifp->name, 
				ni_addrconf_type_to_name(lease->type));
		return res;
	}

	/* Refresh state here - routes may have disappeared, for instance,
	 * when we took away the address. */
	if ((res = __ni_system_refresh_interface(nc, ifp)) < 0)
		return res;

	/* Loop over all routes and remove those no longer covered by the lease.
	 * Ignore all routes covered by other address config mechanisms.
	 */
	res = __ni_interface_update_routes(ifp, lease->family, lease->type, &lease->routes);
	if (res < 0) {
		ni_error("%s: error updating interface config from %s lease",
				ifp->name, 
				ni_addrconf_type_to_name(lease->type));
		return res;
	}

	ni_interface_set_lease(ifp, lease);
	ni_system_update_from_lease(nc, ifp, lease);

	return 0;
}

/*
 * Delete the given interface
 * ni_system_interface_delete
 */
int
ni_system_interface_delete(ni_netconfig_t *nc, const char *ifname)
{
	ni_interface_t *ifp;

	ni_debug_ifconfig("ni_system_interface_delete(%s)", ifname);

	/* FIXME: perform sanity check on configuration data */

	ifp = ni_interface_by_name(nc, ifname);
	if (ifp == NULL) {
		error("cannot delete interface %s - not known", ifname);
		return -1;
	}

	switch (ifp->link.type) {
	case NI_IFTYPE_LOOPBACK:
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_WIRELESS:
	case NI_IFTYPE_DUMMY:
		ni_error("cannot destroy %s interfaces", ni_linktype_type_to_name(ifp->link.type));
		return -1;

	case NI_IFTYPE_VLAN:
		if (__ni_rtnl_link_down(ifp, RTM_DELLINK)) {
			error("could not destroy VLAN interface %s", ifp->name);
			return -1;
		}
		break;

	case NI_IFTYPE_BRIDGE:
		if (__ni_brioctl_del_bridge(ifp->name) < 0) {
			error("could not destroy bridge interface %s", ifp->name);
			return -1;
		}
		break;

	case NI_IFTYPE_BOND:
		if (ni_sysfs_bonding_delete_master(ifp->name) < 0) {
			error("could not destroy bonding interface %s", ifp->name);
			return -1;
		}
		break;

	default:
		return __ni_interface_extension_delete(nc, ifp);
	}

	return 0;
}

/*
 * Create a VLAN interface
 * ni_system_vlan_create
 */
int
ni_system_vlan_create(ni_netconfig_t *nc, const char *ifname, const ni_vlan_t *cfg_vlan, ni_interface_t **ifpp)
{
	ni_interface_t *ifp, *phys_dev;
	ni_vlan_t *cur_vlan = NULL;

	ifp = ni_interface_by_vlan_tag(nc, cfg_vlan->tag);
	if (ifp != NULL) {
		ni_error("%s: VLAN interface with tag 0x%x already exists", ifname, cfg_vlan->tag);
		return -1;
	}

	phys_dev = ni_interface_by_name(nc, cfg_vlan->physdev_name);
	if (!phys_dev || !phys_dev->link.ifindex) {
		ni_error("Cannot create VLAN interface %s: interface %s does not exist",
				ifname, cfg_vlan->physdev_name);
		return -1;
	}

	ni_debug_ifconfig("%s: creating VLAN device", ifname);
	if (__ni_rtnl_link_create_vlan(ifname, cfg_vlan, phys_dev->link.ifindex)) {
		error("unable to create vlan interface %s", ifname);
		return -1;
	}

	/* Refresh interface status */
	__ni_system_refresh_interfaces(nc);

	ifp = ni_interface_by_vlan_tag(nc, cfg_vlan->tag);
	if (ifp == NULL) {
		error("tried to create interface %s; still not found", ifname);
		return -1;
	}

	if (!(cur_vlan = ifp->link.vlan))
		return -1;

	{
		ni_interface_t *real_dev;

		if (!cfg_vlan->physdev_name)
			return -1;
		real_dev = ni_interface_by_name(nc, cfg_vlan->physdev_name);
		if (!real_dev || !real_dev->link.ifindex) {
			error("Cannot bring up VLAN interface %s: %s does not exist",
					ifname, cfg_vlan->physdev_name);
			return -1;
		}

#if 0
		/* Now bring up the underlying ethernet device if it's not up yet.
		 * Note, we don't change anything except its link status */
		if (!ni_interface_network_is_up(real_dev)
		 && __ni_system_interface_bringup(nc, real_dev) < 0) {
			error("Cannot bring up VLAN interface %s: %s not ready yet",
					ifname, cfg_vlan->physdev_name);
			return -1;
		}
#endif
	}

	*ifpp = ifp;
	return 0;
}

/*
 * Delete a VLAN interface
 * ni_system_vlan_delete
 */
int
ni_system_vlan_delete(ni_interface_t *ifp)
{
	if (__ni_rtnl_link_down(ifp, RTM_DELLINK)) {
		ni_error("could not destroy VLAN interface %s", ifp->name);
		return -1;
	}
	return 0;
}

/*
 * Create a bridge interface
 * ni_system_bridge_create
 */
int
ni_system_bridge_create(ni_netconfig_t *nc, const char *ifname,
			const ni_bridge_t *cfg_bridge, ni_interface_t **ifpp)
{
	ni_interface_t *ifp;

	ni_debug_ifconfig("%s: creating bridge interface", ifname);
	if (__ni_brioctl_add_bridge(ifname) < 0) {
		ni_error("__ni_brioctl_add_bridge(%s) failed", ifname);
		return -1;
	}

	/* Refresh interface status */
	__ni_system_refresh_interfaces(nc);

	ifp = ni_interface_by_name(nc, ifname);
	if (ifp == NULL) {
		ni_error("tried to create interface %s; still not found", ifname);
		return -1;
	}

	if (ni_interface_update_bridge_config(nc, ifp, cfg_bridge) < 0) {
		ni_error("ni_system_bridge_create: failed to apply config");
		return -1;
	}

	*ifpp = ifp;
	return 0;
}

/*
 * Given data provided by the user, update the bridge config
 * __ni_system_bridge_update - Make internal
 */
int
ni_interface_update_bridge_config(ni_netconfig_t *nc, ni_interface_t *ifp, const ni_bridge_t *bcfg)
{
	ni_bridge_t *bridge;
	unsigned int i;

	if (ifp->link.type != NI_IFTYPE_BRIDGE) {
		ni_error("%s: %s is not a bridge interface", __func__, ifp->name);
		return -1;
	}

	if (ni_sysfs_bridge_update_config(ifp->name, bcfg) < 0) {
		ni_error("%s: failed to update sysfs attributes for %s", __func__, ifp->name);
		return -1;
	}

	bridge = ni_interface_get_bridge(ifp);
	ni_sysfs_bridge_get_config(ifp->name, bridge);
	ni_sysfs_bridge_get_status(ifp->name, &bridge->status);

	for (i = 0; i < bcfg->ports.count; ++i) {
		if (ni_system_bridge_add_port(nc, ifp, bcfg->ports.data[i]) < 0)
			return -1;
	}
	return 0;
}

/*
 * Delete a bridge interface
 * ni_system_bridge_delete
 */
int
ni_system_bridge_delete(ni_netconfig_t *nc, ni_interface_t *ifp)
{
	if (__ni_brioctl_del_bridge(ifp->name) < 0) {
		ni_error("could not destroy bridge interface %s", ifp->name);
		return -1;
	}
	return 0;
}

/*
 * Add a port to a bridge interface
 * ni_system_bridge_add_port
 */
int
ni_system_bridge_add_port(ni_netconfig_t *nc, ni_interface_t *ifp, ni_bridge_port_t *port)
{
	ni_bridge_t *bridge = ni_interface_get_bridge(ifp);
	ni_interface_t *pif;
	unsigned int i;
	int rv;

	if ((pif = port->device) == NULL && pif->name)
		pif = ni_interface_by_name(nc, pif->name);

	if (pif == NULL) {
		ni_error("%s: cannot add port - %s not known", ifp->name, pif->name);
		return -NI_ERROR_INTERFACE_NOT_KNOWN;
	}
	if (pif->link.ifindex == 0) {
		ni_error("%s: cannot add port - %s has no ifindex?!", ifp->name, pif->name);
		return -NI_ERROR_INTERFACE_NOT_KNOWN;
	}

	if (pif == ifp) {
		ni_error("%s: cannot add interface as its own bridge port", ifp->name);
		return -NI_ERROR_INTERFACE_BAD_HIERARCHY;
	}
	for (i = 0; i < bridge->ports.count; ++i) {
		if (bridge->ports.data[i]->device == pif) {
			ni_error("%s: interface %s is already port", ifp->name, pif->name);
			return -NI_ERROR_INTERFACE_BAD_HIERARCHY;
		}
	}

	if ((rv = __ni_brioctl_add_port(ifp->name, pif->link.ifindex)) < 0) {
		ni_error("%s: cannot add port %s: %s", ifp->name, pif->name,
				ni_strerror(rv));
		return rv;
	}

	/* Now configure the newly added port */
	if ((rv = ni_sysfs_bridge_port_update_config(pif->name, port)) < 0) {
		ni_error("%s: failed to configure port %s: %s", ifp->name, pif->name,
				ni_strerror(rv));
		return rv;
	}

	ni_bridge_add_port(bridge, port);
	return 0;
}

/*
 * Remove a port from a bridge interface
 * ni_system_bridge_remove_port
 */
int
ni_system_bridge_remove_port(ni_netconfig_t *nc, ni_interface_t *ifp, int port_ifindex)
{
	ni_bridge_t *bridge = ni_interface_get_bridge(ifp);
	int rv;

	if (port_ifindex == 0) {
		ni_error("%s: cannot remove port: bad ifindex", ifp->name);
		return -NI_ERROR_INTERFACE_NOT_KNOWN;
	}

	if ((rv = __ni_brioctl_del_port(ifp->name, port_ifindex)) < 0) {
		ni_error("%s: cannot remove port: %s", ifp->name, ni_strerror(rv));
		return rv;
	}

	ni_bridge_del_port_ifindex(bridge, port_ifindex);
	return 0;
}

/*
 * Shut down interface link layer via an extension
 */
static int
__ni_interface_extension_delete(ni_netconfig_t *nc, ni_interface_t *ifp)
{
	ni_extension_t *ex;
	xml_node_t *xml = NULL;
	int res;

	ex = ni_config_find_linktype_extension(ni_global.config, ifp->link.type);
	if (ex == NULL) {
		error("cannot configure %s interface - not implemented yet",
				ni_linktype_type_to_name(ifp->link.type));
		return -1;
	}

#if 0
	xml = ni_syntax_xml_from_interface(ni_global.xml_syntax, nc, ifp);
	if (!xml)
		return -1;
#endif

	res = ni_extension_stop(ex, ifp->name, xml);

	xml_node_free(xml);
	return res;
}

/*
 * Update the IPv6 sysctl settings for the given interface
 */
int
__ni_interface_update_ipv6_settings(ni_netconfig_t *nc, ni_interface_t *ifp, const ni_afinfo_t *afi)
{
	int enable = afi? afi->enabled : 0;
	int brought_up = 0;
	int rv = -1;

	/* You can confuse the kernel IPv6 code to a degree that it will
	 * remove /proc/sys/ipv6/conf/<ifname> completely. dhcpcd in particular
	 * seems rather good at that. 
	 * The only way to recover from that is by upping the interface briefly.
	 */
	if (!ni_sysctl_ipv6_ifconfig_is_present(ifp->name)) {
		if (__ni_rtnl_link_up(ifp, NULL) >= 0) {
			unsigned int count = 100;

			while (count-- && !ni_sysctl_ipv6_ifconfig_is_present(ifp->name))
				usleep(100000);
			brought_up = 1;
		}
	}

	if (ni_sysctl_ipv6_ifconfig_set_uint(ifp->name, "disable_ipv6", !enable) < 0) {
		ni_error("%s: cannot %s ipv6", ifp->name, enable? "enable" : "disable");
		goto out;
	}
	if (enable) {
		int autoconf = ni_afinfo_addrconf_test(afi, NI_ADDRCONF_STATIC);

		if (ni_sysctl_ipv6_ifconfig_set_uint(ifp->name, "autoconf", autoconf) < 0) {
			ni_error("%s: cannot %s ipv6 autoconf", ifp->name, autoconf? "enable" : "disable");
			goto out;
		}
		if (ni_sysctl_ipv6_ifconfig_set_uint(ifp->name, "forwarding", afi->forwarding) < 0) {
			ni_error("%s: cannot %s ipv6 forwarding", ifp->name, afi->forwarding? "enable" : "disable");
			goto out;
		}
	}
	rv = 0;

out:
	if (brought_up)
		__ni_rtnl_link_down(ifp, RTM_NEWLINK);

	return rv;
}

/*
 * Create a VLAN interface via netlink
 */
static int
__ni_rtnl_link_create_vlan(const char *ifname, const ni_vlan_t *vlan, unsigned int phys_ifindex)
{
	struct nlattr *linkinfo;
	struct nlattr *data;
	struct ifinfomsg ifi;
	struct nl_msg *msg;
	int len;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);

	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	/* VLAN:
	 *  INFO_KIND must be "vlan"
	 *  INFO_DATA must contain VLAN_ID
	 *  LINK must contain the link ID of the real ethernet device
	 */
	debug_ifconfig("__ni_rtnl_link_create(%s, vlan, %u, %s)",
			ifname, vlan->tag, vlan->physdev_name);

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		return -1;
	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "vlan");

	if (!(data = nla_nest_start(msg, IFLA_INFO_DATA)))
		return -1;

	NLA_PUT_U16(msg, IFLA_VLAN_ID, vlan->tag);
	nla_nest_end(msg, data);
	nla_nest_end(msg, linkinfo);

	/* Note, IFLA_LINK must be outside of IFLA_LINKINFO */
	NLA_PUT_U32(msg, IFLA_LINK, phys_ifindex);

	len = strlen(ifname) + 1;
	if (len == 1 || len > IFNAMSIZ) {
		error("\"%s\" is not a valid device identifier", ifname);
		return -1;
	}
	NLA_PUT_STRING(msg, IFLA_IFNAME, ifname);

	if (ni_nl_talk(msg) < 0)
		goto failed;

	ni_debug_ifconfig("successfully created interface %s", ifname);
	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -1;
}

/*
 * Simple rtnl message without attributes
 */
static inline int
__ni_rtnl_simple(int msgtype, unsigned int flags, void *data, size_t len)
{
	struct nl_msg *msg;
	int rv = -1;

	msg = nlmsg_alloc_simple(msgtype, flags);

	if (nlmsg_append(msg, data, len, NLMSG_ALIGNTO) < 0) {
		ni_error("%s: nlmsg_append failed", __func__);
	} else
	if (ni_nl_talk(msg) < 0) {
		ni_debug_ifconfig("%s: rtnl_talk failed", __func__);
	} else {
		rv = 0; /* success */
	}

	nlmsg_free(msg);
	return rv;
}

/*
 * Bring down/delete an interface
 */
static int
__ni_rtnl_link_down(const ni_interface_t *ifp, int cmd)
{
	struct ifinfomsg ifi;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = ifp->link.ifindex;
	ifi.ifi_change = IFF_UP;

	return __ni_rtnl_simple(cmd, 0, &ifi, sizeof(ifi));
}

/*
 * (Re-)configure an interface
 */
static int
__ni_rtnl_link_up(const ni_interface_t *ifp, const ni_interface_request_t *cfg)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;

	if (ifp->link.ifindex == 0) {
		ni_error("%s: bad interface index for %s", __func__, ifp->name);
		return -NI_ERROR_INTERFACE_NOT_KNOWN;
	}

	NI_TRACE_ENTER_ARGS("%s, idx=%d", ifp->name, ifp->link.ifindex);
	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = ifp->link.ifindex;
	ifi.ifi_change = IFF_UP;
	ifi.ifi_flags = IFF_UP;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_CREATE);

	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (cfg) {
		if (cfg->mtu && cfg->mtu != ifp->link.mtu)
			NLA_PUT_U32(msg, IFLA_MTU, cfg->mtu);

		if (cfg->txqlen && cfg->txqlen != ifp->link.txqlen)
			NLA_PUT_U32(msg, IFLA_TXQLEN, cfg->txqlen);

#if 0
		/* Need different way to set hwaddr */
		if (cfg->link.hwaddr.type != NI_IFTYPE_UNKNOWN && cfg->link.hwaddr.len != 0
		 && !ni_link_address_equal(&cfg->link.hwaddr, &ifp->link.hwaddr))
			NLA_PUT(msg, IFLA_ADDRESS, cfg->link.hwaddr.len, cfg->link.hwaddr.data);
#endif

		/* FIXME: handle COST, QDISC, MASTER */
	}

	if (ni_nl_talk(msg) < 0) {
		ni_debug_ifconfig("%s: rtnl_talk failed", __func__);
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -1;
}

static inline int
addattr_sockaddr(struct nl_msg *msg, int type, const ni_sockaddr_t *addr)
{
	unsigned int offset, len;

	if (!__ni_address_info(addr->ss_family, &offset, &len))
		return -1;

	return nla_put(msg, type, len, ((const caddr_t) addr) + offset);
}

static ni_address_t *
__ni_interface_address_list_contains(ni_address_t **list, const ni_address_t *ap)
{
	ni_address_t *ap2;

	if (ap->local_addr.ss_family == AF_INET) {
		const struct sockaddr_in *sin1, *sin2;

		sin1 = &ap->local_addr.sin;
		for (ap2 = *list; ap2; ap2 = ap2->next) {
			if (ap2->local_addr.ss_family != AF_INET)
				continue;
			sin2 = &ap2->local_addr.sin;
			if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr)
				continue;

			if (!ni_address_equal(&ap->peer_addr, &ap2->peer_addr))
				continue;

			return ap2;
		}
	}

	if (ap->local_addr.ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin1, *sin2;

		sin1 = &ap->local_addr.six;
		for (ap2 = *list; ap2; ap2 = ap2->next) {
			if (ap2->local_addr.ss_family != AF_INET6)
				continue;
			sin2 = &ap2->local_addr.six;
			if (!memcmp(&sin1->sin6_addr, &sin2->sin6_addr, 16))
				return ap2;
		}
	}

	return 0;
}

static int
__ni_rtnl_send_newaddr(ni_interface_t *ifp, const ni_address_t *ap, int flags)
{
	struct ifaddrmsg ifa;
	struct nl_msg *msg;
	int len;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&ap->local_addr), ap->prefixlen);

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_index = ifp->link.ifindex;
	ifa.ifa_family = ap->family;
	ifa.ifa_prefixlen = ap->prefixlen;

	/* Handle ifa_scope */
	if (ap->scope >= 0)
		ifa.ifa_scope = ap->scope;
	else if (ni_address_is_loopback(ap))
		ifa.ifa_scope = RT_SCOPE_HOST;
	else
		ifa.ifa_scope = 0; /* aka global */

	msg = nlmsg_alloc_simple(RTM_NEWADDR, flags);
	if (nlmsg_append(msg, &ifa, sizeof(ifa), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (addattr_sockaddr(msg, IFA_LOCAL, &ap->local_addr))
		goto nla_put_failure;

	if (ap->peer_addr.ss_family != AF_UNSPEC) {
		if (addattr_sockaddr(msg, IFA_ADDRESS, &ap->peer_addr))
			goto nla_put_failure;
	} else {
		if (addattr_sockaddr(msg, IFA_ADDRESS, &ap->local_addr))
			goto nla_put_failure;
	}

	if (ap->bcast_addr.ss_family != AF_UNSPEC
	 && addattr_sockaddr(msg, IFA_BROADCAST, &ap->bcast_addr))
		goto nla_put_failure;

	if (ap->anycast_addr.ss_family != AF_UNSPEC
	 && addattr_sockaddr(msg, IFA_ANYCAST, &ap->anycast_addr))
		goto nla_put_failure;

	len = strlen(ap->label);
	if (len) {
		if (memcmp(ap->label, ifp->name, len) != 0) {
			ni_error("when specifying an interface label, the device name must "
			   "be a prefix of the label");
			goto failed;
		}
		NLA_PUT_STRING(msg, IFA_LABEL, ap->label);
	}

	if (ni_nl_talk(msg) < 0) {
		ni_error("%s(%s/%u): ni_nl_talk failed", __func__,
				ni_address_print(&ap->local_addr),
				ap->prefixlen);
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -1;
}

static int
__ni_rtnl_send_deladdr(ni_interface_t *ifp, const ni_address_t *ap)
{
	struct ifaddrmsg ifa;
	struct nl_msg *msg;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&ap->local_addr), ap->prefixlen);

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_index = ifp->link.ifindex;
	ifa.ifa_family = ap->family;
	ifa.ifa_prefixlen = ap->prefixlen;

	msg = nlmsg_alloc_simple(RTM_DELADDR, 0);
	if (nlmsg_append(msg, &ifa, sizeof(ifa), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (addattr_sockaddr(msg, IFA_LOCAL, &ap->local_addr))
		goto nla_put_failure;

	if (ap->peer_addr.ss_family != AF_UNSPEC) {
		if (addattr_sockaddr(msg, IFA_ADDRESS, &ap->peer_addr))
			goto nla_put_failure;
	} else {
		if (addattr_sockaddr(msg, IFA_ADDRESS, &ap->local_addr))
			goto nla_put_failure;
	}

	if (ni_nl_talk(msg) < 0) {
		ni_error("%s(%s/%u): rtnl_talk failed", __func__,
				ni_address_print(&ap->local_addr),
				ap->prefixlen);
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -1;
}

/*
 * Add a static route
 */
static int
__ni_rtnl_send_newroute(ni_interface_t *ifp, ni_route_t *rp, int flags)
{
	struct rtmsg rt;
	struct nl_msg *msg;

	ni_debug_ifconfig("%s(%s)", __FUNCTION__, ni_route_print(rp));

	memset(&rt, 0, sizeof(rt));

	rt.rtm_family = rp->family;
	rt.rtm_table = RT_TABLE_MAIN;
	rt.rtm_protocol = RTPROT_BOOT;
	rt.rtm_scope = RT_SCOPE_UNIVERSE;
	rt.rtm_type = RTN_UNICAST;
	rt.rtm_tos = rp->tos;

	rt.rtm_dst_len = rp->prefixlen;

#ifdef notyet
	if (req.rt.rtm_type == RTN_LOCAL ||
	    req.rt.rtm_type == RTN_BROADCAST ||
	    req.rt.rtm_type == RTN_NAT ||
	    req.rt.rtm_type == RTN_ANYCAST)
		req.rt.rtm_table = RT_TABLE_LOCAL;

	switch (req.rt.rtm_type) {
	case RTN_LOCAL:
	case RTN_NAT:
		req.rt.rtm_scope = RT_SCOPE_HOST;
		break;

	case RTN_BROADCAST:
	case RTN_MULTICAST:
	case RTN_ANYCAST:
		req.rt.rtm_scope = RT_SCOPE_LINK;
		break;

	case RTN_UNICAST:
	case RTN_UNSPEC:
		if (rp->gateway.ss_family == AF_UNSPEC)
			req.rt.rtm_scope = RT_SCOPE_LINK;
		break;
	}
#endif

	msg = nlmsg_alloc_simple(RTM_NEWROUTE, flags);
	if (nlmsg_append(msg, &rt, sizeof(rt), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (rp->destination.ss_family == AF_UNSPEC) {
		/* default destination, just leave RTA_DST blank */
	} else if (addattr_sockaddr(msg, RTA_DST, &rp->destination))
		goto nla_put_failure;

	if (rp->nh.gateway.ss_family != AF_UNSPEC
	 && addattr_sockaddr(msg, RTA_GATEWAY, &rp->nh.gateway))
		goto nla_put_failure;

	NLA_PUT_U32(msg, RTA_OIF, ifp->link.ifindex);

	/* Add metrics if needed */
	if (rp->mtu) {
		struct nlattr *mxrta;

		mxrta = nla_nest_start(msg, RTA_METRICS);
		if (mxrta == NULL)
			goto nla_put_failure;

		if (rp->mtu)
			NLA_PUT_U32(msg, RTAX_MTU, rp->mtu);

		nla_nest_end(msg, mxrta);
	}

	if (ni_nl_talk(msg) < 0) {
		error("%s(%s): rtnl_talk failed", __FUNCTION__, ni_route_print(rp));
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -NI_ERROR_CANNOT_CONFIGURE_ROUTE;
}

static int
__ni_rtnl_send_delroute(ni_interface_t *ifp, ni_route_t *rp)
{
	struct rtmsg rt;
	struct nl_msg *msg;

	ni_debug_ifconfig("%s(%s)", __FUNCTION__, ni_route_print(rp));

	memset(&rt, 0, sizeof(rt));
	rt.rtm_family = rp->family;
	rt.rtm_table = RT_TABLE_MAIN;
	rt.rtm_protocol = RTPROT_BOOT;
	rt.rtm_scope = RT_SCOPE_NOWHERE;
	rt.rtm_type = RTN_UNICAST;
	rt.rtm_tos = rp->tos;

	rt.rtm_dst_len = rp->prefixlen;

	msg = nlmsg_alloc_simple(RTM_DELROUTE, 0);
	if (nlmsg_append(msg, &rt, sizeof(rt), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	/* For the default route, just leave RTA_DST blank */
	if (rp->destination.ss_family != AF_UNSPEC
	 && addattr_sockaddr(msg, RTA_DST, &rp->destination))
		goto nla_put_failure;

	if (rp->nh.gateway.ss_family != AF_UNSPEC
	 && addattr_sockaddr(msg, RTA_GATEWAY, &rp->nh.gateway))
		goto nla_put_failure;

	NLA_PUT_U32(msg, RTA_OIF, ifp->link.ifindex);

	if (ni_nl_talk(msg) < 0) {
		ni_error("%s(%s): rtnl_talk failed", __FUNCTION__, ni_route_print(rp));
		goto failed;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	ni_error("failed to encode netlink attr");
failed:
	nlmsg_free(msg);
	return -1;
}

/*
 * Check if a route already exists.
 */
static ni_route_t *
__ni_interface_route_list_contains(ni_route_t **list, const ni_route_t *rp)
{
	ni_route_t *rp2;

	for (rp2 = *list; rp2; rp2 = rp2->next) {
		if (rp->family != rp2->family
		 || rp->prefixlen != rp2->prefixlen)
			continue;

		if (rp->prefixlen && !ni_address_equal(&rp->destination, &rp2->destination))
			continue;

		if (rp->family == AF_INET) {
			/* ipv4 matches routing entries by [prefix, tos, priority] */
			if (rp->tos == rp2->tos
			 && rp->priority == rp2->priority)
				return rp2;
		} else 
		if (rp->family == AF_INET6) {
			/* ipv6 matches routing entries by [dst pfx, src pfx, priority] */
			/* We don't support source routes yet. */
			if (rp->priority == rp2->priority)
				return rp2;
		}
	}

	return NULL;
}

static inline ni_extension_t *
__ni_addrconf_extension(int type, int family)
{
	return ni_config_find_addrconf_extension(ni_global.config, type, family);
}

/*
 * Change the addrconf request for a given address family and address configuration
 * protocol
 */
/* static */ int
__ni_addrconf_update_request(ni_afinfo_t *afinfo, ni_addrconf_mode_t mode,
				ni_addrconf_request_t **req_p,
				ni_interface_t *ifp)
{
	ni_addrconf_request_t *req = *req_p;
	ni_addrconf_lease_t *lease;
	ni_addrconf_t *acm;
	int rv;

	if (mode == NI_ADDRCONF_STATIC)
		return NI_SUCCESS;

	/* IPv6 autoconf takes care of itself */
	if (afinfo->family == AF_INET6 && mode == NI_ADDRCONF_AUTOCONF) {
		if (req && !afinfo->lease[mode]) {
			afinfo->lease[mode] = ni_addrconf_lease_new(mode, afinfo->family);
			afinfo->lease[mode]->state = NI_ADDRCONF_STATE_GRANTED;
		} else
		if (!req && afinfo->lease[mode]) {
			ni_addrconf_lease_free(afinfo->lease[mode]);
			afinfo->lease[mode] = NULL;
		}

		return NI_SUCCESS;
	}

	acm = ni_addrconf_get(mode, afinfo->family);
	if (acm == NULL) {
		ni_error("address configuration mode %s not supported for %s",
			ni_addrconf_type_to_name(mode),
			ni_addrfamily_type_to_name(afinfo->family));
		return NI_SUCCESS;
	}

	/* Check whether the new addrconf request is identical with the existing request. */
	if (afinfo->request[mode] && ni_addrconf_request_equal(req, afinfo->request[mode])) {
		/* FIXME: we may want to support a way to force a restart of the
		 * addrconf service for this interface */
		return NI_SUCCESS;
	}

	__ni_afinfo_set_addrconf_request(afinfo, mode, req);
	*req_p = NULL; /* all your addrconf request now belong to us */

	/* If the extension is already active, no need to start it once
	 * more. If needed, we could do a restart in this case. */
	if (ni_afinfo_addrconf_test(afinfo, mode)) {
		lease = afinfo->lease[mode];
		if (lease && lease->state == NI_ADDRCONF_STATE_GRANTED)
			return NI_SUCCESS;
	}

	ni_afinfo_addrconf_enable(afinfo, mode);
	if ((rv = ni_addrconf_acquire_lease(acm, ifp)) < 0)
		return rv;

	/* If the extension supports more than just this address
	 * family, make sure we update the interface status accordingly.
	 * Otherwise we will start the service multiple times.
	 */
	if (acm->supported_af & NI_AF_MASK_IPV4)
		ni_afinfo_addrconf_enable(&ifp->ipv4, acm->type);
	if (acm->supported_af & NI_AF_MASK_IPV6)
		ni_afinfo_addrconf_enable(&ifp->ipv6, acm->type);

	/* Write out the addrconf request data; this is used when
	 * we restart the wicked service. */
	if (afinfo->request[mode] != NULL)
		ni_addrconf_request_file_write(ifp->name, afinfo->request[mode]);

	return NI_SUCCESS;
}

/*
 * Update the addresses and routes assigned to an interface
 * for a given addrconf method
 */
static int
__ni_interface_update_addrs(ni_interface_t *ifp,
				int family, ni_addrconf_mode_t mode,
				ni_address_t **cfg_addr_list)
{
	ni_address_t *ap, *next;
	int rv;

	for (ap = ifp->addrs; ap; ap = next) {
		ni_address_t *ap2;

		next = ap->next;
		if (ap->family != family)
			continue;

		/* See if the config list contains the address we've found in the
		 * system. */
		ap2 = __ni_interface_address_list_contains(cfg_addr_list, ap);
		if (ap2 != NULL) {
			/* Okay, we think this address should be managed via the
			 * specified addrconf method. Make sure this is actually
			 * the case.
			 * Note that the code analyzing the current system state
			 * may mis-classify an address as STATIC, so allow for some
			 * leeway here.
			 */
			if (ap->config_method != mode
			 && ap->config_method != NI_ADDRCONF_STATIC) {
				ni_warn("address %s covered by a %s lease",
					ni_address_print(&ap->local_addr),
					ni_addrconf_type_to_name(ap->config_method));
			} else {
				ap->config_method = mode;
			}
		}

		/* Even interfaces with static network config may have
		 * dynamically configured addresses. Don't touch these.
		 *
		 * Unfortunately, we cannot determine this for sure;
		 * the fact whether an IPv6 address was assigned by
		 * the admin or via autoconf is not part of the NEWADDR
		 * message. We have to guess, thus.
		 */
		if (ap->config_method != mode)
			continue;

		if (ap2 != NULL) {
			/* Check whether we need to update */
			if ((ap2->scope == -1 || ap->scope == ap2->scope)
			 && (ap2->label[0] == '\0' || !strcmp(ap->label, ap2->label))
			 && ni_address_equal(&ap->bcast_addr, &ap2->bcast_addr)
			 && ni_address_equal(&ap->anycast_addr, &ap2->anycast_addr)) {
				/* Current address as configured, no need to change. */
				ni_debug_ifconfig("address %s/%u exists; no need to reconfigure",
					ni_address_print(&ap->local_addr), ap->prefixlen);
				ap2->seq = __ni_global_seqno;
				continue;
			}

			ni_debug_ifconfig("existing address %s/%u needs to be reconfigured",
					ni_address_print(&ap->local_addr),
					ap->prefixlen);
		}

		if ((rv = __ni_rtnl_send_deladdr(ifp, ap)) < 0)
			return rv;
	}

	/* Loop over all addresses in the configuration and create
	 * those that don't exist yet.
	 */
	for (ap = *cfg_addr_list; ap; ap = ap->next) {
		if (ap->family != family
		 || ap->seq == __ni_global_seqno)
			continue;

		ni_debug_ifconfig("Adding new interface address %s/%u",
				ni_address_print(&ap->local_addr),
				ap->prefixlen);
		if ((rv = __ni_rtnl_send_newaddr(ifp, ap, NLM_F_CREATE)) < 0)
			return rv;
	}

	return 0;
}

static int
__ni_interface_update_routes(ni_interface_t *ifp,
				int family, ni_addrconf_mode_t mode,
				ni_route_t **cfg_route_list)
{
	ni_route_t *rp, *next;
	int rv = 0;

	/* Loop over all routes currently assigned to the interface.
	 * If the configuration no longer specifies it, delete it.
	 * We need to mimic the kernel's matching behavior when modifying
	 * the configuration of existing routes.
	 */
	for (rp = ifp->routes; rp; rp = next) {
		ni_route_t *rp2;

		next = rp->next;
		if (rp->family != family)
			continue;

		/* See if the config list contains the route we've found in the
		 * system. */
		rp2 = __ni_interface_route_list_contains(cfg_route_list, rp);
		if (rp2 != NULL) {
			/* Okay, we think this address should be managed via the
			 * specified addrconf method. Make sure this is actually
			 * the case.
			 * Note that the code analyzing the current system state
			 * may mis-classify an address as STATIC, so allow for some
			 * leeway here.
			 */
			if (rp->config_method != mode
			 && rp->config_method != NI_ADDRCONF_STATIC) {
				ni_warn("route %s covered by a %s lease",
					ni_route_print(rp),
					ni_addrconf_type_to_name(rp->config_method));
			} else {
				rp->config_method = mode;
			}
		}

		/* Even interfaces with static network config may have
		 * dynamically configured routes. Don't touch these.
		 */
		if (rp->config_method != mode)
			continue;

		if (rp2 != NULL) {
			if (__ni_rtnl_send_newroute(ifp, rp2, NLM_F_REPLACE) >= 0) {
				ni_debug_ifconfig("%s: successfully updated existing route %s",
						ifp->name, ni_route_print(rp));
				rp2->seq = __ni_global_seqno;
				continue;
			}

			ni_error("%s: failed to update route %s", ifp->name, ni_route_print(rp));
		}

		ni_debug_ifconfig("%s: trying to delete existing route %s",
				ifp->name, ni_route_print(rp));
		if ((rv = __ni_rtnl_send_delroute(ifp, rp)) < 0)
			return rv;
	}

	/* Loop over all addresses in the configuration and create
	 * those that don't exist yet.
	 */
	for (rp = *cfg_route_list; rp; rp = rp->next) {
		if (rp->family != family
		 || rp->seq == __ni_global_seqno)
			continue;

		ni_debug_ifconfig("%s: adding new route %s", ifp->name, ni_route_print(rp));
		if ((rv = __ni_rtnl_send_newroute(ifp, rp, NLM_F_CREATE)) < 0)
			return rv;
	}

	return rv;
}

/*
 * IPv6 autoconf takes care of itself. All we need to do is record that we
 * have a "lease".
 */
static int
__ni_interface_addrconf_dummy(ni_netconfig_t *nc, ni_interface_t *ifp, int family,
			ni_addrconf_mode_t mode, ni_addrconf_request_t *req)
{
	ni_afinfo_t *cur_afi = __ni_interface_address_info(ifp, family);
	ni_addrconf_lease_t *lease;

	lease = cur_afi->lease[mode];
	if (req == NULL) {
		ni_afinfo_addrconf_disable(cur_afi, mode);

		if (lease != NULL) {
			ni_debug_ifconfig("%s: disabling %s/%s", ifp->name,
					ni_addrfamily_type_to_name(family),
					ni_addrconf_type_to_name(mode));
			ni_interface_set_lease(ifp, NULL);
		}
		return 0;
	}

	if (req != NULL && lease == NULL) {
		ni_debug_ifconfig("%s: bringing up %s/%s",
				ifp->name, ni_addrconf_type_to_name(mode),
				ni_addrfamily_type_to_name(family));
		lease = ni_addrconf_lease_new(mode, family);
		lease->state = NI_ADDRCONF_STATE_GRANTED;
		ni_interface_set_lease(ifp, lease);
		ni_afinfo_addrconf_enable(cur_afi, mode);
	}
	return 0;
}

/*
 * Perform address configuration for random address configuration modes
 */
static int
__ni_interface_addrconf_static(ni_netconfig_t *nc, ni_interface_t *ifp, int family,
			ni_addrconf_mode_t mode, ni_addrconf_request_t *req)
{
	ni_afinfo_t *cur_afi = __ni_interface_address_info(ifp, family);
	int rv;

	if (req == NULL) {
		ni_address_t *null_addrs = NULL;

		ni_debug_ifconfig("%s: shutting down %s/%s",
				ifp->name, ni_addrconf_type_to_name(mode),
				ni_addrfamily_type_to_name(family));
		ni_afinfo_addrconf_disable(cur_afi, mode);

		/* Loop over all addresses currently assigned to the interface.
		 * If the configuration no longer specifies it, delete it.
		 * We need to mimic the kernel's matching behavior when modifying
		 * the configuration of existing addresses.
		 */
		return __ni_interface_update_addrs(ifp, family, mode, &null_addrs);
	}

	ni_debug_ifconfig("%s: bringing up %s/%s",
			ifp->name, ni_addrconf_type_to_name(mode),
			ni_addrfamily_type_to_name(family));
	ni_afinfo_addrconf_enable(cur_afi, mode);

	/* Loop over all addresses currently assigned to the interface.
	 * If the configuration no longer specifies it, delete it.
	 * We need to mimic the kernel's matching behavior when modifying
	 * the configuration of existing addresses.
	 */
	rv = __ni_interface_update_addrs(ifp, family, mode, &req->statik.addrs);
	if (rv < 0)
		return rv;

	/* Changing addresses may mess up routing.
	 * Refresh interface */
	if ((rv = __ni_system_refresh_interface(nc, ifp)) < 0)
		return rv;

	rv = __ni_interface_update_routes(ifp, family, mode, &req->statik.routes);

	return rv;
}

/*
 * An ifup request may be just a re-send of an existing setting. In this case,
 * we may decide that there is no need to re-do the address configuration.
 */
static int
__ni_addrconf_request_changed(ni_interface_t *ifp, int family,
			ni_addrconf_mode_t mode, ni_addrconf_request_t *req)
{
	static ni_uuid_t req_uuid;
	ni_afinfo_t *cur_afi = __ni_interface_address_info(ifp, family);

	if (cur_afi->request[mode] == NULL) {
		if (req == NULL)
			return 0;
	} else
	/* Check whether the new addrconf request is identical with the existing request. */
	if (req && ni_addrconf_request_equal(req, cur_afi->request[mode])) {
		ni_addrconf_lease_t *lease = cur_afi->lease[mode];
		time_t now = time(NULL);

		/* Do not re-acquire lease if it was acquired within the last 10 seconds */
		if (lease && lease->time_acquired < now && now <= lease->time_acquired + 10)
			return 0;
	}

	if (ni_uuid_is_null(&req_uuid)) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		req_uuid.words[0] = tv.tv_sec;
		req_uuid.words[1] = tv.tv_usec;
		req_uuid.words[2] = getpid();
	}

	if (req) {
		req_uuid.words[3]++;
		req->uuid = req_uuid;
	}

	__ni_afinfo_set_addrconf_request(cur_afi, mode, req);
	return 1;
}

/*
 * Perform address configuration for random address configuration modes
 */
static int
__ni_interface_addrconf_other(ni_netconfig_t *nc, ni_interface_t *ifp, int family,
			ni_addrconf_mode_t mode, ni_addrconf_request_t *req)
{
	ni_afinfo_t *cur_afi = __ni_interface_address_info(ifp, family);
	ni_addrconf_lease_t *lease;
	ni_addrconf_t *acm;
	int rv;

	acm = ni_addrconf_get(mode, family);
	if (acm == NULL) {
		if (req == NULL)
			return 0;

		ni_error("address configuration mode %s not supported for %s",
			ni_addrconf_type_to_name(mode),
			ni_addrfamily_type_to_name(family));
		return -1; // PROTOCOL_NOT_SUPPORTED
	}

	lease = cur_afi->lease[mode];
	if (req == NULL) {
		__ni_afinfo_set_addrconf_request(cur_afi, mode, NULL);
		ni_afinfo_addrconf_disable(cur_afi, mode);

		if (lease != NULL) {
			ni_debug_ifconfig("%s: disabling %s/%s", ifp->name,
					ni_addrfamily_type_to_name(family),
					ni_addrconf_type_to_name(mode));
			return ni_addrconf_drop_lease(acm, ifp);
		}
		return 0;
	}

	/* If the extension is already active, no need to start it once
	 * more. If needed, we could do a restart in this case. */
	if (lease != NULL) {
		if (!ni_uuid_is_null(&lease->uuid)
		 && ni_uuid_equal(&lease->uuid, &req->uuid)
		 && lease->state == NI_ADDRCONF_STATE_GRANTED)
			return 0;
	}

	ni_afinfo_addrconf_enable(cur_afi, mode);
	if ((rv = ni_addrconf_acquire_lease(acm, ifp)) < 0)
		return rv;

	/* If the extension supports more than just this address
	 * family, make sure we update the interface status accordingly.
	 * Otherwise we will start the service multiple times.
	 */
	if (acm->supported_af & NI_AF_MASK_IPV4)
		ni_afinfo_addrconf_enable(&ifp->ipv4, acm->type);
	if (acm->supported_af & NI_AF_MASK_IPV6)
		ni_afinfo_addrconf_enable(&ifp->ipv6, acm->type);

	/* Write out the addrconf request data; this is used when
	 * we restart the wicked service. */
	if (req != NULL)
		ni_addrconf_request_file_write(ifp->name, req);
	
	return 0;
}

/*
 * Configure addresses for a given address family.
 */
static int
__ni_interface_addrconf(ni_netconfig_t *nc, int family, ni_interface_t *ifp, ni_afinfo_t *cfg_afi)
{
	ni_afinfo_t null_afi = { .family = family };
	unsigned int mode;
	int rv = -1;

	ni_debug_ifconfig("__ni_interface_addrconf(%s, af=%s, afi=%p)", ifp->name,
			ni_addrfamily_type_to_name(family), cfg_afi);

	/* Passing in a NULL address family info means delete all addresses for this interface
	 * and cancel all leases. */
	if (cfg_afi == NULL)
		cfg_afi = &null_afi;

	/* Now bring up addrconf services */
	for (mode = 0; mode < __NI_ADDRCONF_MAX; ++mode) {
		ni_addrconf_request_t *req = cfg_afi->request[mode];

		/* IPv6 autoconf takes care of itself */
		if (family == AF_INET6 && mode == NI_ADDRCONF_AUTOCONF) {
			rv = __ni_interface_addrconf_dummy(nc, ifp, family, mode, req);
		} else
		if (mode == NI_ADDRCONF_STATIC) {
			rv = __ni_interface_addrconf_static(nc, ifp, family, mode, req);
		} else {
			if (!__ni_addrconf_request_changed(ifp, family, mode, req))
				continue;

			/* __ni_addrconf_request_changed assigned the request to ifp,
			 * so make sure it's not deleted when the caller frees
			 * the ni_interface_request */
			cfg_afi->request[mode] = NULL;

			rv = __ni_interface_addrconf_other(nc, ifp, family, mode, req);
		}

		if (rv < 0)
			return rv;
	}

	return 0;
}
