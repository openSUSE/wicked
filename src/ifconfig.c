/*
 * Things to do when bringing an interface up or down
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
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
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <arpa/inet.h> /* debug */

#include <wicked/netinfo.h>
#include <wicked/xml.h>

#include "netinfo_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "config.h"

#define BOND_DEVICE_MUST_BE_UP_WHEN_MESSING_WITH_SLAVES 1

static int	__ni_system_interface_bringup(ni_handle_t *, ni_interface_t *);
static int	__ni_interface_for_config(ni_handle_t *, const ni_interface_t *, ni_interface_t **);
static int	__ni_interface_addrconf(ni_handle_t *, int,  ni_interface_t *, ni_interface_t *, xml_node_t *);
static int	__ni_interface_bridge_configure(ni_handle_t *, ni_interface_t *, ni_interface_t **);
static int	__ni_interface_vlan_configure(ni_handle_t *, ni_interface_t *, ni_interface_t **);
static int	__ni_interface_bond_configure(ni_handle_t *, ni_interface_t *, ni_interface_t **);
static int	__ni_interface_extension_configure(ni_handle_t *, ni_interface_t *, xml_node_t *, ni_interface_t **);
static int	__ni_interface_extension_delete(ni_handle_t *, ni_interface_t *);
static int	__ni_rtnl_link_create(ni_handle_t *, ni_interface_t *);
static int	__ni_rtnl_link_up(ni_handle_t *, ni_interface_t *, const ni_interface_t *);
static int	__ni_rtnl_link_down(ni_handle_t *, ni_interface_t *, int);
static int	__ni_rtnl_send_deladdr(ni_handle_t *, ni_interface_t *, const ni_address_t *);
static int	__ni_rtnl_send_newaddr(ni_handle_t *, ni_interface_t *, const ni_address_t *, int);
static int	__ni_rtnl_send_delroute(ni_handle_t *, ni_interface_t *, ni_route_t *);
static int	__ni_rtnl_send_newroute(ni_handle_t *, ni_interface_t *, ni_route_t *, int);

/*
 * Configure a given interface
 */
int
__ni_system_interface_configure(ni_handle_t *nih, ni_interface_t *cfg, xml_node_t *cfg_xml)
{
	ni_interface_t *ifp;
	int res;

	debug_ifconfig("__ni_system_interface_configure(%s)", cfg->name);
	/* FIXME: perform sanity check on configuration data */

	res = __ni_interface_for_config(nih, cfg, &ifp);
	if (res) {
		error("interface config does not uniquely determine an interface");
		return res;
	}

	if (ifp && ifp->type != cfg->type) {
		error("cannot configure interface %s: interface type changes!", cfg->name);
		return -1;
	}

	/* If the interface doesn't exist, and we're NOT asked to bring it
	 * up, consider our job done.
	 * Note that we may be asked to create an interface without bringing
	 * up its network layer; that happens eg when you want to build a
	 * bridge containing virtual interfaces like a bond, or a VLAN */
	if (ifp == NULL) {
		if ((cfg->flags & (IFF_LOWER_UP|IFF_UP)) == 0)
			return 0;
	}

	switch (cfg->type) {
	case NI_IFTYPE_LOOPBACK:
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_DUMMY:
		break;

	case NI_IFTYPE_BRIDGE:
		res = __ni_interface_bridge_configure(nih, cfg, &ifp);
		break;

	case NI_IFTYPE_VLAN:
		res = __ni_interface_vlan_configure(nih, cfg, &ifp);
		break;

	case NI_IFTYPE_BOND:
		res = __ni_interface_bond_configure(nih, cfg, &ifp);
		break;

	default:
		res = __ni_interface_extension_configure(nih, cfg, cfg_xml, &ifp);
		break;
	}

	if (res < 0)
		return -1;
	if (ifp == NULL) {
		ni_error("shouldn't happen: interface doesn't exist after creation");
		return -1;
	}

	if (cfg->flags & IFF_UP) {
		debug_ifconfig("bringing up interface %s", ifp->name);
		if (__ni_rtnl_link_up(nih, ifp, cfg)) {
			error("__ni_rtnl_link_up(%s) failed", ifp->name);
			return -1;
		}
	} else {
		debug_ifconfig("shutting down interface %s", ifp->name);
		if (__ni_rtnl_link_down(nih, ifp, RTM_NEWLINK)) {
			error("unable to shut down interface %s", ifp->name);
			return -1;
		}

		/* This will take care of shutting down dhcp */
		cfg->ipv4.config = NI_ADDRCONF_STATIC;
		cfg->ipv6.config = NI_ADDRCONF_STATIC;
	}

	nih->seqno++;

	res = -1;

	if (__ni_interface_addrconf(nih, AF_INET, ifp, cfg, cfg_xml) < 0
	 || __ni_interface_addrconf(nih, AF_INET6, ifp, cfg, cfg_xml) < 0)
		goto failed;

	res = __ni_system_refresh_interface(nih, ifp);

failed:
	return res;
}

/*
 * An address configuration agent sends a lease update.
 */
int
__ni_system_interface_update_lease(ni_handle_t *nih, ni_interface_t *ifp, ni_addrconf_lease_t *lease)
{
	int res, changed = 0;
	ni_afinfo_t *afi;
	ni_address_t *ap;
	ni_route_t *rp;

	ni_debug_ifconfig("%s: received new lease (state %s)", ifp->name,
			ni_addrconf_state_to_name(lease->state));

	if ((res = __ni_system_refresh_interface(nih, ifp)) < 0)
		return -1;

	if (!(afi = __ni_interface_address_info(ifp, lease->family))) {
		ni_error("%s: unable to update lease - unknown address family", ifp->name);
		return -1;
	}
	ni_trace("existing lease: %p", afi->lease[lease->type]);

	/* Loop over all addresses and remove those no longer covered by the lease.
	 * Ignore all addresses covered by other address config mechanisms.
	 */
	nih->seqno++;
	for (ap = ifp->addrs; ap; ap = ap->next) {
		ni_address_t *lap;

		if (ap->family != lease->family)
			continue;

		/* We do NOT check whether we classified the address correctly.
		 * It may still be around for some reason after we exited
		 * previously, or we lost track of it for some other reason. */
		lap = __ni_lease_owns_address(lease, ap);
		if (lap) {
			ni_debug_ifconfig("%s: %s/%u exists already",
				ni_addrconf_type_to_name(lease->type),
				ni_address_print(&ap->local_addr),
				ap->prefixlen);

			if (ap->config_method != lease->type
			 && ap->config_method != NI_ADDRCONF_STATIC) {
				ni_warn("address covered by a %s lease",
					ni_addrconf_type_to_name(ap->config_method));
			}
			ap->config_method = lease->type;
			lap->seq = nih->seqno;
		} else if (ap->config_method == lease->type) {
			ni_debug_ifconfig("%s: removing address %s/%u",
				ni_addrconf_type_to_name(lease->type),
				ni_address_print(&ap->local_addr),
				ap->prefixlen);
			if (__ni_rtnl_send_deladdr(nih, ifp, ap))
				return -1;
			changed = 1;
		}
	}

	/* Loop over all lease addresses and add those not yet configured */
	for (ap = lease->addrs; ap; ap = ap->next) {
		if (ap->seq == nih->seqno)
			continue;

		if (__ni_rtnl_send_newaddr(nih, ifp, ap, NLM_F_CREATE))
			return -1;
		changed = 1;
	}

	/* Refresh state here - routes may have disappeared, for instance,
	 * when we took away the address. */
	if (changed && __ni_system_refresh_interface(nih, ifp) < 0)
		return -1;
	changed = 0;

	/* Loop over all routes and remove those no longer covered by the lease.
	 * Ignore all routes covered by other address config mechanisms.
	 */
	for (rp = ifp->routes; rp; rp = rp->next) {
		ni_route_t *lrp;

		if (rp->family != lease->family)
			continue;

		/* We do NOT check whether we classified the address correctly.
		 * It may still be around for some reason after we exited
		 * previously, or we lost track of it for some other reason. */
		lrp = __ni_lease_owns_route(lease, rp);
		if (lrp) {
			ni_debug_ifconfig("%s: route %s/%u exists already",
				ni_addrconf_type_to_name(lease->type),
				ni_address_print(&rp->destination),
				rp->prefixlen);

			if (rp->config_method != lease->type
			 && rp->config_method != NI_ADDRCONF_STATIC) {
				ni_warn("route covered by a %s lease",
					ni_addrconf_type_to_name(rp->config_method));
			}
			rp->config_method = lease->type;
			lrp->seq = nih->seqno;
		} else if (rp->config_method == lease->type) {
			ni_debug_ifconfig("%s: removing route %s/%u",
				ni_addrconf_type_to_name(lease->type),
				ni_address_print(&rp->destination),
				rp->prefixlen);
			if (__ni_rtnl_send_delroute(nih, ifp, rp))
				return -1;
			changed = 1;
		}
	}

	/* Loop over all lease routes and add those not yet configured */
	for (rp = lease->routes; rp; rp = rp->next) {
		if (rp->seq == nih->seqno)
			continue;

		if (__ni_rtnl_send_newroute(nih, ifp, rp, NLM_F_CREATE))
			return -1;
		changed = 1;
	}

	ni_interface_set_lease(nih, ifp, lease);
	return 0;
}

/*
 * Bringup a network interface.
 * This is used eg when we're asked to bring up a VLAN device and find
 * that the underlying NIC is still down.
 *
 * Note the interface argument we're given represents a system device,
 * not the administrative interface configuration. For this reason, we
 * first clone the device.
 */
int
__ni_system_interface_bringup(ni_handle_t *nih, ni_interface_t *ifp)
{
	ni_interface_t *cfg;
	int res = -1;

	if (!(cfg = ni_interface_clone(ifp)))
		return -1;

	cfg->flags |= IFF_UP;

	res = __ni_rtnl_link_up(nih, ifp, cfg);
	if (res >= 0) {
		__ni_system_refresh_interface(nih, ifp);
	}

	ni_interface_put(cfg);
	return res;
}

/*
 * Delete the given interface
 */
int
__ni_system_interface_delete(ni_handle_t *nih, const char *ifname)
{
	ni_interface_t *ifp;

	debug_ifconfig("__ni_system_interface_delete(%s)", ifname);

	/* FIXME: perform sanity check on configuration data */

	ifp = ni_interface_by_name(nih, ifname);
	if (ifp == NULL) {
		error("cannot delete interface %s - not known", ifname);
		return -1;
	}

	switch (ifp->type) {
	case NI_IFTYPE_LOOPBACK:
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_DUMMY:
		ni_error("cannot destroy %s interfaces", ni_linktype_type_to_name(ifp->type));
		return -1;

	case NI_IFTYPE_VLAN:
		if (__ni_rtnl_link_down(nih, ifp, RTM_DELLINK)) {
			error("could not destroy VLAN interface %s", ifp->name);
			return -1;
		}
		break;

	case NI_IFTYPE_BRIDGE:
		if (__ni_brioctl_del_bridge(nih, ifp->name) < 0) {
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
		return __ni_interface_extension_delete(nih, ifp);
	}

	return 0;
}

/*
 * Identify the interface for a given configuration.
 * The interface may be identified by one or more of
 *  -	interface name
 *  -	MAC address
 *  -	PCI bus ID
 *  -	possibly more
 */
static int
__ni_interface_for_config(ni_handle_t *nih, const ni_interface_t *cfg, ni_interface_t **res)
{
	ni_interface_t *ifp = NULL;

	*res = NULL;
	if (cfg->name) {
		ifp = ni_interface_by_name(nih, cfg->name);
		if (ifp) {
			if (cfg->hwaddr.len
			 && !ni_link_address_equal(&ifp->hwaddr, &cfg->hwaddr))
				return -1;
			*res = ifp;
			return 0;
		}
	}

	if (cfg->hwaddr.len) {
		ifp = ni_interface_by_hwaddr(nih, &cfg->hwaddr);
		if (ifp) {
			if (*res && *res != ifp)
				return -1;
			*res = ifp;
		}
	}

	return 0;
}

/*
 * Helper function - do something to all ports of a bridge
 */
static int
__ni_interface_bridge_allports(ni_handle_t *nih, const char *ifname,
				const ni_string_array_t *port_names,
				int (*func)(ni_handle_t *, const char *, unsigned int),
				const char *activity)
{
	unsigned int i;

	for (i = 0; i < port_names->count; ++i) {
		const char *portname = port_names->data[i];
		ni_interface_t *pif;

		if (!(pif = ni_interface_by_name(nih, portname)) || pif->ifindex == 0) {
			error("%s: cannot %s - %s not known", ifname, activity, portname);
			return -1;
		}

		if (func(nih, ifname, pif->ifindex) < 0) {
			error("%s: cannot %s %s: %m", ifname, activity, portname);
			return -1;
		}
	}

	return 0;
}


/*
 * Handle link transformation for bridge
 */
static int
__ni_interface_bridge_configure(ni_handle_t *nih, ni_interface_t *cfg, ni_interface_t **ifpp)
{
	ni_interface_t *ifp = *ifpp;
	ni_bridge_t *cur_bridge = NULL, *cfg_bridge;

	if (!(cfg_bridge = cfg->bridge))
		return -1;

	/* make sure port names in bridge config are unique */
	if (!ni_string_array_is_uniq(&cfg_bridge->port_names)) {
		error("%s: duplicate port names in configuration", cfg->name);
		return -1;
	}

	if (ifp == NULL) {
		debug_ifconfig("%s: creating bridge interface", cfg->name);
		if (__ni_brioctl_add_bridge(nih, cfg->name) < 0) {
			error("__ni_brioctl_add_bridge(%s) failed", cfg->name);
			return -1;
		}

		/* Refresh interface status */
		ni_refresh(nih);

		if (__ni_interface_for_config(nih, cfg, &ifp) < 0 || ifp == NULL) {
			error("tried to create interface %s; still not found", cfg->name);
			return -1;
		}
	}

	if (!(cur_bridge = ifp->bridge))
		return -1;

	{
		ni_string_array_t add_ports, del_ports, comm_ports;
		int rv;

		ni_string_array_init(&add_ports);
		ni_string_array_init(&del_ports);
		ni_string_array_init(&comm_ports);

		ni_string_array_comm(&cur_bridge->port_names, &cfg_bridge->port_names,
				&del_ports,	/* names only in cur_bridge */
				&add_ports,	/* names only in cfg_bridge */
				&comm_ports);	/* names in both definitions */

		/* First, add new ports */
		rv = __ni_interface_bridge_allports(nih, ifp->name,
				&add_ports, __ni_brioctl_add_port,
				"add bridge port");

		/* Then, delete ports that should go away */
		if (rv >= 0)
			rv = __ni_interface_bridge_allports(nih, ifp->name,
				&del_ports, __ni_brioctl_del_port,
				"delete bridge port");

		ni_string_array_destroy(&add_ports);
		ni_string_array_destroy(&del_ports);
		ni_string_array_destroy(&comm_ports);

		if (rv < 0)
			return -1;
	}

	*ifpp = ifp;
	return 0;
}

/*
 * Handle link transformation for vlan
 */
static int
__ni_interface_vlan_configure(ni_handle_t *nih, ni_interface_t *cfg, ni_interface_t **ifpp)
{
	ni_interface_t *ifp = *ifpp;
	ni_vlan_t *cur_vlan = NULL, *cfg_vlan;

	if (!(cfg_vlan = cfg->vlan))
		return -1;

	if (ifp == NULL) {
		debug_ifconfig("%s: creating VLAN device", cfg->name);
		if (__ni_rtnl_link_create(nih, cfg)) {
			error("unable to create vlan interface %s", cfg->name);
			return -1;
		}

		/* Refresh interface status */
		ni_refresh(nih);

		if (__ni_interface_for_config(nih, cfg, &ifp) < 0 || ifp == NULL) {
			error("tried to create interface %s; still not found", cfg->name);
			return -1;
		}
	}

	if (!(cur_vlan = ifp->vlan))
		return -1;

	{
		ni_interface_t *real_dev;

		if (!cfg_vlan->interface_name)
			return -1;
		real_dev = ni_interface_by_name(nih, cfg_vlan->interface_name);
		if (!real_dev || !real_dev->ifindex) {
			error("Cannot bring up VLAN interface %s: %s does not exist",
					cfg->name, cfg_vlan->interface_name);
			return -1;
		}

		/* Now bring up the underlying ethernet device if it's not up yet.
		 * Note, we don't change anything except its link status */
		if (!(real_dev->flags & IFF_UP)
		 && __ni_system_interface_bringup(nih, real_dev) < 0) {
			error("Cannot bring up VLAN interface %s: %s not ready yet",
					cfg->name, cfg_vlan->interface_name);
			return -1;
		}
	}

	*ifpp = ifp;
	return 0;
}

/*
 * Handle link transformation for bonding device
 */
static int
__ni_interface_bond_configure(ni_handle_t *nih, ni_interface_t *cfg, ni_interface_t **ifpp)
{
	ni_interface_t *ifp = *ifpp;
	ni_bonding_t *cur_bond = NULL, *cfg_bond;
	unsigned int i;

	if (!(cfg_bond = cfg->bonding))
		return -1;

	for (i = 0; i < cfg_bond->slave_names.count; ++i) {
		const char *slave_name = cfg_bond->slave_names.data[i];
		ni_interface_t *slave_dev;

		slave_dev = ni_interface_by_name(nih, slave_name);
		if (!slave_dev) {
			ni_error("%s: slave %s does not exist", cfg->name, slave_name);
			return -1;
		}

		if (slave_dev->flags & IFF_UP) {
			ni_error("%s: cannot enslave interface %s - device is UP, should be down",
					cfg->name, slave_name);
			return -1;
		}
	}

	if (ifp == NULL) {
		if (!ni_sysfs_bonding_available()) {
			unsigned int i, success = 0;

#if 0
			/* Load the bonding module */
			if (ni_modprobe("bonding") < 0)
				return -1;
#endif

			/* Wait for bonding_masters to appear */
			for (i = 0; i < 400; ++i) {
				if ((success = ni_sysfs_bonding_available()) != 0)
					break;
				usleep(25000);
			}
			if (!success) {
				error("unable to load bonding module - couldn't find bonding_masters");
				return -1;
			}
		}

		if (!ni_sysfs_bonding_is_master(cfg->name)) {
			int success = 0;

			debug_ifconfig("%s: creating bond master", cfg->name);
			if (ni_sysfs_bonding_add_master(cfg->name) >= 0) {
				unsigned int i;

				/* Wait for bonding_masters to appear */
				for (i = 0; i < 400; ++i) {
					if ((success = ni_sysfs_bonding_is_master(cfg->name)) != 0)
						break;
					usleep(25000);
				}
			}

			if (!success) {
				error("unable to create bonding device %s", cfg->name);
				return -1;
			}
		}

		/* Refresh interface status */
		ni_refresh(nih);

		if (__ni_interface_for_config(nih, cfg, &ifp) < 0 || ifp == NULL) {
			error("tried to create interface %s; still not found", cfg->name);
			return -1;
		}
	}

	if (!(cur_bond = ifp->bonding))
		return -1;

	if (ifp->flags & IFF_UP) {
		/* FIXME: we ought to compare attributes that can only be
		 * changed when interface is down, and return an error if
		 * they're not current. */
	}

	/* Store attributes stage 0 - most attributes need to be written prior to
	   bringing up the interface */
	if (ni_bonding_write_sysfs_attrs(cfg->name, cfg_bond, cur_bond, 0) < 0) {
		ni_error("%s: error configuring bonding device (stage 1)", cfg->name);
		return -1;
	}

	/* Bring up the interface now - we need to do this if we ultimately
	 * wish to shut it down. Otherwise the kernel won't let us mess
	 * with the list of slaves. */
	if (BOND_DEVICE_MUST_BE_UP_WHEN_MESSING_WITH_SLAVES || (cfg->flags & IFF_UP)) {
		if (!(ifp->flags & IFF_UP) && __ni_system_interface_bringup(nih, ifp) < 0) {
			ni_error("%s: unable to bring up interface", cfg->name);
			return -1;
		}

		/* FIXME: we may want to ensure that any slaves to be
		 * added are down. The kernel will throw an error anyway. */
	}

	if (ni_sysfs_bonding_set_list_attr(cfg->name, "slaves", &cfg_bond->slave_names) < 0) {
		ni_error("%s: could not configure slaves", cfg->name);
		return -1;
	}

	if ((ifp->flags & IFF_UP)
	 && ni_bonding_write_sysfs_attrs(cfg->name, cfg_bond, cur_bond, 1) < 0) {
		ni_error("%s: error configuring bonding device (stage 1)", cfg->name);
		return -1;
	}

	*ifpp = ifp;
	return 0;
}

/*
 * Configure interface link layer via an extension
 */
static int
__ni_interface_extension_configure(ni_handle_t *nih, ni_interface_t *cfg, xml_node_t *cfg_xml, ni_interface_t **ifpp)
{
	ni_extension_t *ex;

	ex = ni_config_find_linktype_extension(ni_global.config, cfg->type);
	if (ex == NULL) {
		error("cannot configure %s interface - not implemented yet",
				ni_linktype_type_to_name(cfg->type));
		return -1;
	}

	return ni_extension_start(ex, cfg->name, cfg_xml);
}

/*
 * Shut down interface link layer via an extension
 */
static int
__ni_interface_extension_delete(ni_handle_t *nih, ni_interface_t *ifp)
{
	ni_extension_t *ex;
	xml_node_t *xml;
	int res;

	ex = ni_config_find_linktype_extension(ni_global.config, ifp->type);
	if (ex == NULL) {
		error("cannot configure %s interface - not implemented yet",
				ni_linktype_type_to_name(ifp->type));
		return -1;
	}

	xml = ni_syntax_xml_from_interface(ni_global.xml_syntax, nih, ifp);
	if (!xml)
		return -1;

	res = ni_extension_stop(ex, ifp->name, xml);

	xml_node_free(xml);
	return res;
}

/*
 * Create an interface via netlink - currently used by VLAN only
 */
static int
__ni_rtnl_link_create(ni_handle_t *nih, ni_interface_t *cfg)
{
	ni_interface_t *real_dev;
	struct {
		struct nlmsghdr	hdr;
		struct ifinfomsg ii;
		char buffer[1024];
	} req;
	int len;

	memset(&req, 0, sizeof(req));
	req.ii.ifi_family = AF_UNSPEC;
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ii));
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.hdr.nlmsg_type = RTM_NEWLINK;

	if (cfg->type == NI_IFTYPE_VLAN) {
		struct rtattr *linkinfo;
		struct rtattr *data;
		ni_vlan_t *vlan;

		/* VLAN:
		 *  INFO_KIND must be "vlan"
		 *  INFO_DATA must contain VLAN_ID
		 *  LINK must contain the link ID of the real ethernet device
		 */
		if ((vlan = cfg->vlan) == NULL) {
			error("Cannot create VLAN interface - no configuration!");
			return -1;
		}

		debug_ifconfig("__ni_rtnl_link_create(%s, vlan, %u, %s)",
				cfg->name, vlan->tag, vlan->interface_name);

		if (!(linkinfo = __ni_rta_begin_linkinfo(&req.hdr, sizeof(req), "vlan")))
			return -1;

		data = __ni_rta_begin_nested(&req.hdr, sizeof(req), IFLA_INFO_DATA);
		addattr16(&req.hdr, sizeof(req), IFLA_VLAN_ID, vlan->tag);
		__ni_rta_end_nested(&req.hdr, data);

		/* IFLA_LINK - must be outside of IFLA_LINKINFO, so first
		 * close off the linkinfo part */
		__ni_rta_end_nested(&req.hdr, linkinfo);

		real_dev = ni_interface_by_name(nih, cfg->vlan->interface_name);
		if (!real_dev || !real_dev->ifindex) {
			error("Cannot create VLAN interface %s: interface %s does not exist",
					cfg->name, cfg->vlan->interface_name);
			return -1;
		}
		addattr32(&req.hdr, sizeof(req), IFLA_LINK, real_dev->ifindex);
	} else {
		error("Cannot create an interface of type %d through netlink", cfg->type);
		return -1;
	}

	len = strlen(cfg->name) + 1;
	if (len == 1 || len > IFNAMSIZ) {
		error("\"%s\" is not a valid device identifier", cfg->name);
		return -1;
	}
	addattr_l(&req.hdr, sizeof(req), IFLA_IFNAME, cfg->name, len);

	if (ni_rtnl_talk(nih, &req.hdr) < 0)
		return -1;

	debug_ifconfig("successfully created interface %s", cfg->name);
	return 0;
}

/*
 * Bring down/delete an interface
 */
static int
__ni_rtnl_link_down(ni_handle_t *nih, ni_interface_t *ifp, int cmd)
{
	struct {
		struct nlmsghdr	hdr;
		struct ifinfomsg ii;
	} req;

	memset(&req, 0, sizeof(req));
	req.ii.ifi_family = AF_UNSPEC;
	req.ii.ifi_index = ifp->ifindex;
	req.ii.ifi_change = IFF_UP;
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ii));
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.hdr.nlmsg_type = cmd;

	if (ni_rtnl_talk(nih, &req.hdr) < 0)
		return -1;

	return 0;
}

/*
 * (Re-)configure an interface
 */
static int
__ni_rtnl_link_up(ni_handle_t *nih, ni_interface_t *ifp, const ni_interface_t *cfg)
{
	struct {
		struct nlmsghdr	hdr;
		struct ifinfomsg ii;
		char		buffer[1024];
	} req;

	memset(&req, 0, sizeof(req));
	req.ii.ifi_family = AF_UNSPEC;
	req.ii.ifi_index = ifp->ifindex;
	req.ii.ifi_change = IFF_UP;
	req.ii.ifi_flags = IFF_UP;
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ii));
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.hdr.nlmsg_type = RTM_NEWLINK;

	if (cfg->mtu && cfg->mtu != ifp->mtu)
		addattr_l(&req.hdr, sizeof(req), IFLA_MTU, &cfg->mtu, 4);

	if (cfg->txqlen && cfg->txqlen != ifp->txqlen)
		addattr_l(&req.hdr, sizeof(req), IFLA_TXQLEN, &cfg->txqlen, 4);

	if (cfg->hwaddr.type != NI_IFTYPE_UNKNOWN && cfg->hwaddr.len != 0
	 && !ni_link_address_equal(&cfg->hwaddr, &ifp->hwaddr))
		addattr_l(&req.hdr, sizeof(req), IFLA_ADDRESS, cfg->hwaddr.data, cfg->hwaddr.len);

	/* FIXME: handle COST, QDISC, MASTER */

	if (ni_rtnl_talk(nih, &req.hdr) < 0) {
		debug_ifconfig("%s: rtnl_talk failed", __FUNCTION__);
		return -1;
	}

	/* Refresh from rtnl response? */
	ifp->flags |= IFF_UP;

	return 0;
}

static inline int
addattr_sockaddr(struct nlmsghdr *h, size_t size, int type, const struct sockaddr_storage *addr)
{
	unsigned int offset, len;

	if (!__ni_address_info(addr->ss_family, &offset, &len))
		return -1;

	return addattr_l(h, size, type, ((const caddr_t) addr) + offset, len);
}

static ni_address_t *
__ni_interface_address_exists(const ni_interface_t *ifp, const ni_address_t *ap)
{
	ni_address_t *ap2;

	if (ap->local_addr.ss_family == AF_INET) {
		const struct sockaddr_in *sin1, *sin2;
		uint32_t mask = ~(0xFFFFFFFF >> ap->prefixlen);

		sin1 = (const struct sockaddr_in *) &ap->local_addr;
		for (ap2 = ifp->addrs; ap2; ap2 = ap2->next) {
			if (ap2->local_addr.ss_family != AF_INET)
				continue;
			sin2 = (const struct sockaddr_in *) &ap2->local_addr;
			if ((ntohl(sin1->sin_addr.s_addr ^ sin2->sin_addr.s_addr) & mask) != 0)
				continue;

			if (!ni_address_equal(&ap->peer_addr, &ap2->peer_addr))
				continue;

			return ap2;
		}
	}

	if (ap->local_addr.ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin1, *sin2;

		sin1 = (const struct sockaddr_in6 *) &ap->local_addr;
		for (ap2 = ifp->addrs; ap2; ap2 = ap2->next) {
			if (ap2->local_addr.ss_family != AF_INET)
				continue;
			sin2 = (const struct sockaddr_in6 *) &ap2->local_addr;
			if (!memcmp(&sin1->sin6_addr, &sin2->sin6_addr, 16))
				return ap2;
		}
	}

	return 0;
}

static int
__ni_rtnl_send_newaddr(ni_handle_t *nih, ni_interface_t *ifp, const ni_address_t *ap, int flags)
{
	struct {
		struct nlmsghdr	hdr;
		struct ifaddrmsg ifa;
		char		buffer[1024];
	} req;
	int len;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&ap->local_addr), ap->prefixlen);

	memset(&req, 0, sizeof(req));
	req.ifa.ifa_index = ifp->ifindex;
	req.ifa.ifa_family = ap->family;
	req.ifa.ifa_prefixlen = ap->prefixlen;
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifa));
	req.hdr.nlmsg_flags = NLM_F_REQUEST | flags;
	req.hdr.nlmsg_type = RTM_NEWADDR;

	if (addattr_sockaddr(&req.hdr, sizeof(req), IFA_LOCAL, &ap->local_addr))
		return -1;

	if (ap->peer_addr.ss_family != AF_UNSPEC) {
		if (addattr_sockaddr(&req.hdr, sizeof(req), IFA_ADDRESS, &ap->peer_addr))
			return -1;
	} else {
		if (addattr_sockaddr(&req.hdr, sizeof(req), IFA_ADDRESS, &ap->local_addr))
			return -1;
	}

	if (ap->bcast_addr.ss_family != AF_UNSPEC
	 && addattr_sockaddr(&req.hdr, sizeof(req), IFA_BROADCAST, &ap->bcast_addr))
		return -1;

	if (ap->anycast_addr.ss_family != AF_UNSPEC
	 && addattr_sockaddr(&req.hdr, sizeof(req), IFA_ANYCAST, &ap->anycast_addr))
		return -1;

	len = strlen(ap->label);
	if (len) {
		if (memcmp(ap->label, ifp->name, len) != 0) {
			error("when specifying an interface label, the device name must "
			   "be a prefix of the label");
			return -1;
		}
		if (addattr_l(&req.hdr, sizeof(req), IFA_LABEL, ap->label, len + 1))
			return -1;
	}

	/* Handle ifa_scope */
	if (ap->scope >= 0)
		req.ifa.ifa_scope = ap->scope;
	else if (ni_address_is_loopback(ap))
		req.ifa.ifa_scope = RT_SCOPE_HOST;
	else
		req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;

	if (ni_rtnl_talk(nih, &req.hdr) < 0) {
		ni_error("%s(%s/%u): rtnl_talk failed", __FUNCTION__,
				ni_address_print(&ap->local_addr),
				ap->prefixlen);
		return -1;
	}

	return 0;
}

static int
__ni_rtnl_send_deladdr(ni_handle_t *nih, ni_interface_t *ifp, const ni_address_t *ap)
{
	struct {
		struct nlmsghdr	hdr;
		struct ifaddrmsg ifa;
		char		buffer[1024];
	} req;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&ap->local_addr), ap->prefixlen);

	memset(&req, 0, sizeof(req));
	req.ifa.ifa_index = ifp->ifindex;
	req.ifa.ifa_family = ap->family;
	req.ifa.ifa_prefixlen = ap->prefixlen;
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifa));
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.hdr.nlmsg_type = RTM_DELADDR;

	if (addattr_sockaddr(&req.hdr, sizeof(req), IFA_LOCAL, &ap->local_addr))
		return -1;

	if (ap->peer_addr.ss_family != AF_UNSPEC) {
		if (addattr_sockaddr(&req.hdr, sizeof(req), IFA_ADDRESS, &ap->peer_addr))
			return -1;
	} else {
		if (addattr_sockaddr(&req.hdr, sizeof(req), IFA_ADDRESS, &ap->local_addr))
			return -1;
	}

	if (ni_rtnl_talk(nih, &req.hdr) < 0) {
		ni_error("%s(%s/%u): rtnl_talk failed", __FUNCTION__,
				ni_address_print(&ap->local_addr),
				ap->prefixlen);
		return -1;
	}

	return 0;
}

/*
 * Add a static route
 */
static int
__ni_rtnl_send_newroute(ni_handle_t *nih, ni_interface_t *ifp, ni_route_t *rp, int flags)
{
	struct {
		struct nlmsghdr hdr;
		struct rtmsg rt;
		char buffer[1024];
	} req;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&rp->destination), rp->prefixlen);

	memset(&req, 0, sizeof(req));

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.hdr.nlmsg_flags = NLM_F_REQUEST|flags;
	req.hdr.nlmsg_type = RTM_NEWROUTE;
	req.rt.rtm_family = rp->family;
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.rt.rtm_protocol = RTPROT_BOOT;
	req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	req.rt.rtm_type = RTN_UNICAST;
	req.rt.rtm_tos = rp->tos;

	req.rt.rtm_dst_len = rp->prefixlen;

	if (rp->destination.ss_family == AF_UNSPEC) {
		/* default destination, just leave RTA_DST blank */
	} else if (addattr_sockaddr(&req.hdr, sizeof(req), RTA_DST, &rp->destination))
		return -1;

	if (rp->nh.gateway.ss_family != AF_UNSPEC
	 && addattr_sockaddr(&req.hdr, sizeof(req), RTA_GATEWAY, &rp->nh.gateway))
		return -1;

	addattr32(&req.hdr, sizeof(req), RTA_OIF, ifp->ifindex);

	/* Add metrics if needed */
	if (1) {
		struct rtattr *mxrta;
		char  mxbuf[256];

		mxrta = (void*) mxbuf;
		mxrta->rta_type = RTA_METRICS;
		mxrta->rta_len = RTA_LENGTH(0);

		if (rp->mtu)
			rta_addattr32(mxrta, sizeof(mxbuf), RTAX_MTU, rp->mtu);

		if (mxrta->rta_len > RTA_LENGTH(0)
		 && addattr_l(&req.hdr, sizeof(req), RTA_METRICS, RTA_DATA(mxrta), RTA_PAYLOAD(mxrta)))
			return -1;
	}

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

	if (ni_rtnl_talk(nih, &req.hdr) < 0) {
		error("%s(%s/%u): rtnl_talk failed", __FUNCTION__,
				ni_address_print(&rp->destination),
				rp->prefixlen);
		return -1;
	}

	return 0;
}

static int
__ni_rtnl_send_delroute(ni_handle_t *nih, ni_interface_t *ifp, ni_route_t *rp)
{
	struct {
		struct nlmsghdr hdr;
		struct rtmsg rt;
		char buffer[1024];
	} req;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&rp->destination), rp->prefixlen);

	memset(&req, 0, sizeof(req));

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.hdr.nlmsg_type = RTM_DELROUTE;
	req.rt.rtm_family = rp->family;
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.rt.rtm_protocol = RTPROT_BOOT;
	req.rt.rtm_scope = RT_SCOPE_NOWHERE;
	req.rt.rtm_type = RTN_UNICAST;
	req.rt.rtm_tos = rp->tos;

	req.rt.rtm_dst_len = rp->prefixlen;

	if (rp->destination.ss_family == AF_UNSPEC) {
		/* default destination, just leave RTA_DST blank */
	} else if (addattr_sockaddr(&req.hdr, sizeof(req), RTA_DST, &rp->destination))
		return -1;

	if (rp->nh.gateway.ss_family != AF_UNSPEC
	 && addattr_sockaddr(&req.hdr, sizeof(req), RTA_GATEWAY, &rp->nh.gateway))
		return -1;

	addattr32(&req.hdr, sizeof(req), RTA_OIF, ifp->ifindex);

	if (ni_rtnl_talk(nih, &req.hdr) < 0) {
		error("%s(%s/%u): rtnl_talk failed", __FUNCTION__,
				ni_address_print(&rp->destination),
				rp->prefixlen);
		return -1;
	}

	return 0;
}

/*
 * Check if a route already exists.
 */
static ni_route_t *
__ni_interface_route_exists(const ni_interface_t *ifp, const ni_route_t *rp)
{
	ni_route_t *rp2;

	for (rp2 = ifp->routes; rp2; rp2 = rp2->next) {
		if (rp->family != rp2->family
		 || rp->prefixlen != rp2->prefixlen)
			continue;

		if (!ni_address_equal(&rp->destination, &rp2->destination))
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
 * Configure addresses for a given address family.
 */
static int
__ni_interface_addrconf(ni_handle_t *nih, int family, ni_interface_t *ifp, ni_interface_t *cfg,
			xml_node_t *cfg_xml)
{
	ni_afinfo_t *cfg_afi, *cur_afi;
	ni_addrconf_t *cfg_acm, *cur_acm;
	xml_node_t *xml = NULL;

	debug_ifconfig("__ni_interface_addrconf(%s, af=%s)", ifp->name,
			ni_addrfamily_type_to_name(family));

	if (family == AF_INET) {
		cfg_afi = &cfg->ipv4;
		cur_afi = &ifp->ipv4;
	} else if (family == AF_INET6) {
		cfg_afi = &cfg->ipv6;
		cur_afi = &ifp->ipv6;
	} else
		return -1;

	/* If we're chaging to a different addrconf mode, stop the current
	 * service. */
	cur_acm = ni_addrconf_get(cur_afi->config, family);
	if (cur_acm && cfg_afi->config != cur_afi->config) {
		if (ni_addrconf_drop_lease(cur_acm, ifp) < 0)
			return -1;
		cur_acm = NULL;
	}

	if (cfg_afi->config == NI_ADDRCONF_STATIC) {
		ni_address_t *ap, *next;
		ni_route_t *rp;

		/* Loop over all addresses currently assigned to the interface.
		 * If the configuration no longer specifies it, delete it.
		 * We need to mimic the kernel's matching behavior when modifying
		 * the configuration of existing addresses.
		 */
		for (ap = ifp->addrs; ap; ap = next) {
			ni_address_t *ap2;

			next = ap->next;
			if (ap->family != family)
				continue;

			/* Even interfaces with static network config may have
			 * dynamically configured addresses. Don't touch these.
			 *
			 * Unfortunately, we cannot determine this for sure;
			 * the fact whether an IPv6 address was assigned by
			 * the admin or via autoconf is not part of the NEWADDR
			 * message. We have to guess, thus.
			 */
			if (__ni_address_probably_dynamic(cfg_afi, ap))
				continue;

			ap2 = __ni_interface_address_exists(cfg, ap);
			if (ap2 != NULL) {
				/* Check whether we need to update */
				if ((ap2->scope == -1 || ap->scope == ap2->scope)
				 && (ap2->label[0] == '\0' || !strcmp(ap->label, ap2->label))
				 && ni_address_equal(&ap->bcast_addr, &ap2->bcast_addr)
				 && ni_address_equal(&ap->anycast_addr, &ap2->anycast_addr)) {
					/* Current address as configured, no need to change. */
					debug_ifconfig("address %s/%u exists; no need to reconfigure",
						ni_address_print(&ap->local_addr), ap->prefixlen);
					ap2->seq = nih->seqno;
					continue;
				}

				debug_ifconfig("existing address %s/%u needs to be reconfigured",
						ni_address_print(&ap->local_addr),
						ap->prefixlen);
			}

			if (__ni_rtnl_send_deladdr(nih, ifp, ap))
				goto error;

			/* rtnl should not delete interfaces right away,
			 * but it's okay to mark them as deleted. */
		}

		/* Loop over all addresses in the configuration and create
		 * those that don't exist yet.
		 */
		for (ap = cfg->addrs; ap; ap = ap->next) {
			if (ap->family != family
			 || ap->seq == nih->seqno)
				continue;

			debug_ifconfig("Adding new interface address %s/%u",
					ni_address_print(&ap->local_addr),
					ap->prefixlen);
			if (__ni_rtnl_send_newaddr(nih, ifp, ap, NLM_F_CREATE))
				goto error;
		}

		/* Changing addresses may mess up routing.
		 * Refresh interface */
		if (__ni_system_refresh_interface(nih, ifp) < 0)
			goto error;

		/* Loop over all routes currently assigned to the interface.
		 * If the configuration no longer specifies it, delete it.
		 * We need to mimic the kernel's matching behavior when modifying
		 * the configuration of existing routes.
		 */
		for (rp = ifp->routes; rp; rp = rp->next) {
			ni_route_t *rp2;

			if (rp->family != family)
				continue;

			rp2 = __ni_interface_route_exists(cfg, rp);
			if (rp2 != NULL) {
				if (__ni_rtnl_send_newroute(nih, ifp, rp2, NLM_F_REPLACE) >= 0) {
					debug_ifconfig("%s: successfully updated existing route %s/%u",
							ifp->name, ni_address_print(&rp->destination),
							rp->prefixlen);
					rp2->seq = nih->seqno;
					continue;
				}

				error("%s: failed to update route %s/%u",
						ifp->name, ni_address_print(&rp->destination),
						rp->prefixlen);
			}

			if (__ni_rtnl_send_delroute(nih, ifp, rp))
				goto error;
		}

		/* Loop over all addresses in the configuration and create
		 * those that don't exist yet.
		 */
		for (rp = cfg->routes; rp; rp = rp->next) {
			if (rp->family != family
			 || rp->seq == nih->seqno)
				continue;

			debug_ifconfig("%s: adding new route %s/%u",
					ifp->name, ni_address_print(&rp->destination),
					rp->prefixlen);
			if (__ni_rtnl_send_newroute(nih, ifp, rp, NLM_F_CREATE))
				goto error;
		}
	} else if (cfg_afi->config == NI_ADDRCONF_AUTOCONF) {
		if (family != AF_INET6) {
			error("autoconf not supported for address family");
			goto error;
		}
	} else
	if ((cfg_acm = ni_addrconf_get(cfg_afi->config, family)) != NULL) {
		ni_addrconf_lease_t *lease;
		ni_dhclient_info_t *tmp;

		tmp = cur_afi->dhcp;
		cur_afi->dhcp = cfg_afi->dhcp;
		cfg_afi->dhcp = tmp;

		/* If the extension is already active, no need to start it once
		 * more. If needed, we could do a restart in this case. */
		if (cfg_afi->config == cur_afi->config) {
			lease = cur_afi->lease[cfg_afi->config];
			if (lease && lease->state == NI_ADDRCONF_STATE_GRANTED)
				return 0;
		}

		cur_afi->config = cfg_afi->config;
		if (ni_addrconf_acquire_lease(cfg_acm, ifp, NULL) < 0)
			goto error;

		/* If the extension supports more than just this address
		 * family, make sure we update the interface status accordingly.
		 * Otherwise we will start the service multiple times.
		 */
		if (cfg_acm->supported_af & NI_AF_MASK_IPV4)
			ifp->ipv4.config = cfg_acm->type;
		if (cfg_acm->supported_af & NI_AF_MASK_IPV6)
			ifp->ipv6.config = cfg_acm->type;
	} else {
		error("address configuration mode %s not supported for %s",
				ni_addrconf_type_to_name(cfg_afi->config),
				ni_addrfamily_type_to_name(cfg_afi->family));
		goto error;
	}

	if (xml)
		xml_node_free(xml);
	return 0;

error:
	if (xml)
		xml_node_free(xml);
	return -1;
}
