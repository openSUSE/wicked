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
#include <netlink/msg.h>
#include <arpa/inet.h> /* debug */

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/xml.h>

#include "netinfo_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "config.h"

#define BOND_DEVICE_MUST_BE_UP_WHEN_MESSING_WITH_SLAVES 1

static int	__ni_system_interface_bringup(ni_handle_t *, ni_interface_t *);
static int	__ni_interface_for_config(ni_handle_t *, const ni_interface_t *, ni_interface_t **);
static int	__ni_interface_addrconf(ni_handle_t *, int,  ni_interface_t *, const ni_interface_t *);
static int	__ni_interface_bridge_configure(ni_handle_t *, const ni_interface_t *, ni_interface_t **);
static int	__ni_interface_vlan_configure(ni_handle_t *, const ni_interface_t *, ni_interface_t **);
static int	__ni_interface_bond_configure(ni_handle_t *, const ni_interface_t *, ni_interface_t **);
static int	__ni_interface_extension_configure(ni_handle_t *, const ni_interface_t *, ni_interface_t **);
static int	__ni_interface_extension_delete(ni_handle_t *, ni_interface_t *);
static int	__ni_interface_update_ipv6_settings(ni_handle_t *, ni_interface_t *, const ni_interface_t *);
static int	__ni_rtnl_link_create_vlan(ni_handle_t *, const char *, const ni_vlan_t *);
static int	__ni_rtnl_link_create(ni_handle_t *, const ni_interface_t *);
static int	__ni_rtnl_link_up(ni_handle_t *, const ni_interface_t *, const ni_interface_t *);
static int	__ni_rtnl_link_down(ni_handle_t *, const ni_interface_t *, int);
static int	__ni_rtnl_send_deladdr(ni_handle_t *, ni_interface_t *, const ni_address_t *);
static int	__ni_rtnl_send_newaddr(ni_handle_t *, ni_interface_t *, const ni_address_t *, int);
static int	__ni_rtnl_send_delroute(ni_handle_t *, ni_interface_t *, ni_route_t *);
static int	__ni_rtnl_send_newroute(ni_handle_t *, ni_interface_t *, ni_route_t *, int);

/*
 * Configure a given interface
 */
int
__ni_system_interface_configure(ni_handle_t *nih, ni_interface_t *ifp, const ni_interface_t *cfg)
{
	int res;

	debug_ifconfig("__ni_system_interface_configure(%s)", cfg->name);
	/* FIXME: perform sanity check on configuration data */

	if (ni_interface_network_is_up(cfg) && !ni_interface_link_is_up(cfg)) {
		ni_error("%s: configuration specifies network-up and link-down", cfg->name);
		return -1;
	}
	if (ni_interface_link_is_up(cfg) && !ni_interface_device_is_up(cfg)) {
		ni_error("%s: configuration specifies link-up and device-down", cfg->name);
		return -1;
	}

	if (ifp == NULL) {
		res = __ni_interface_for_config(nih, cfg, &ifp);
		if (res) {
			error("interface config does not uniquely determine an interface");
			return res;
		}
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
		if (!ni_interface_device_is_up(cfg))
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
		res = __ni_interface_extension_configure(nih, cfg, &ifp);
		break;
	}

	if (res < 0)
		return -1;
	if (ifp == NULL) {
		ni_error("shouldn't happen: interface doesn't exist after creation");
		return -1;
	}

	/* If we want to disable ipv6 or ipv6 autoconf, we need to do so prior to bringing
	 * the interface up. */
	if (__ni_interface_update_ipv6_settings(nih, ifp, cfg) < 0)
		return -1;

	if (cfg->ifflags & (NI_IFF_DEVICE_UP|NI_IFF_LINK_UP|NI_IFF_NETWORK_UP)) {
		ni_debug_ifconfig("bringing up %s", ifp->name);
		if (__ni_rtnl_link_up(nih, ifp, cfg)) {
			ni_error("%s: failed to bring up interface (rtnl error)", ifp->name);
			return -1;
		}
		ifp->ifflags |= cfg->ifflags;
	} else {
		ni_debug_ifconfig("shutting down interface %s", ifp->name);
		if (__ni_rtnl_link_down(nih, ifp, RTM_NEWLINK)) {
			ni_error("unable to shut down interface %s", ifp->name);
			return -1;
		}
		/* down is down is down */
		ifp->up_requesters = 0;
	}

	nih->seqno++;

	res = -1;

	if (__ni_interface_addrconf(nih, AF_INET, ifp, cfg) < 0
	 || __ni_interface_addrconf(nih, AF_INET6, ifp, cfg) < 0)
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
	unsigned int update_mask;
	int res, changed = 0;
	ni_afinfo_t *afi;
	ni_address_t *ap;
	ni_route_t *rp;

	ni_debug_ifconfig("%s: received %s/%s lease update; state %s", ifp->name,
			ni_addrconf_type_to_name(lease->type),
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_state_to_name(lease->state));

	if ((res = __ni_system_refresh_interface(nih, ifp)) < 0)
		return -1;

	if (!(afi = __ni_interface_address_info(ifp, lease->family))) {
		ni_error("%s: unable to update lease - unknown address family", ifp->name);
		return -1;
	}

	update_mask = ni_config_addrconf_update_mask(ni_global.config, lease->type);
#if 0
	update_mask &= afi->request[lease->type]->update;
#endif

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

#if 0
		if (ni_route_is_default(rp)
		 && !__ni_addrconf_should_update(update_mask, NI_ADDRCONF_UPDATE_DEFAULT_ROUTE)) {
			ni_debug_ifconfig("%s: ignoring default route update", ifp->name);
			continue;
		}
#endif

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

		ni_debug_ifconfig("%s: adding new route %s/%u from lease",
				ifp->name, ni_address_print(&rp->destination),
				rp->prefixlen);
		if (__ni_rtnl_send_newroute(nih, ifp, rp, NLM_F_CREATE) < 0)
			return -1;
		changed = 1;
	}

	ni_interface_set_lease(nih, ifp, lease);

	ni_system_update_from_lease(nih, ifp, lease);

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
	int res = -1;

	res = __ni_rtnl_link_up(nih, ifp, NULL);
	if (res >= 0)
		__ni_system_refresh_interface(nih, ifp);

	return res;
}

/*
 * Bring up a network interface temporarily, e.g. for a wireless scan.
 */
int
__ni_interface_begin_activity(ni_handle_t *nih, ni_interface_t *ifp, ni_interface_activity_t activity)
{
	if (ifp->ifflags & NI_IFF_DEVICE_UP) {
		/* Remember that the interface was up by admin's choice */
		if (ifp->up_requesters == 0)
			ifp->up_requesters |= 1 << NI_INTERFACE_ADMIN;
	} else {
		if (__ni_system_interface_bringup(nih, ifp) < 0)
			return -1;
	}

	ifp->up_requesters |= 1 << activity;
	return 0;
}

int
__ni_interface_check_activity(ni_handle_t *nih, ni_interface_t *ifp, ni_interface_activity_t activity)
{
	return !!(ifp->up_requesters & (1 << activity));
}

int
__ni_interface_end_activity(ni_handle_t *nih, ni_interface_t *ifp, ni_interface_activity_t activity)
{
	if (ifp->up_requesters & (1 << activity)) {
		ifp->up_requesters &= ~(1 << activity);

		if (ifp->up_requesters == 0) {
			/* Bring it down */
			__ni_rtnl_link_down(nih, ifp, RTM_NEWLINK);
		} else if (ifp->up_requesters == 1 << NI_INTERFACE_ADMIN) {
			/* The only ongoing activity is "administration", which
			 * is the default activity. Just clear the bitfield */
			ifp->up_requesters = 0;
		}
	}
	return 0;
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
	case NI_IFTYPE_WIRELESS:
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
__ni_interface_bridge_configure(ni_handle_t *nih, const ni_interface_t *cfg, ni_interface_t **ifpp)
{
	ni_interface_t *ifp = *ifpp;
	ni_bridge_t *cur_bridge = NULL, *cfg_bridge;
	ni_string_array_t cfg_bridge_ports;

	if (!(cfg_bridge = cfg->bridge))
		return -1;

	/* FIXME: IMO bridge_add_port should enforce this */
	ni_string_array_init(&cfg_bridge_ports);
	ni_bridge_get_port_names(cfg_bridge, &cfg_bridge_ports);
	/* make sure port names in bridge config are unique */
	if (!ni_string_array_is_uniq(&cfg_bridge_ports)) {
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
		ni_refresh(nih, NULL);

		if (__ni_interface_for_config(nih, cfg, &ifp) < 0 || ifp == NULL) {
			error("tried to create interface %s; still not found", cfg->name);
			return -1;
		}
	}

	if (!(cur_bridge = ifp->bridge))
		return -1;

	{
		ni_string_array_t add_ports, del_ports, comm_ports;
		ni_string_array_t cur_bridge_ports;
		int rv;

		ni_string_array_init(&add_ports);
		ni_string_array_init(&del_ports);
		ni_string_array_init(&comm_ports);

		ni_string_array_init(&cur_bridge_ports);
		ni_bridge_get_port_names(cur_bridge, &cur_bridge_ports);

		ni_string_array_comm(&cur_bridge_ports, &cfg_bridge_ports,
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
		ni_string_array_destroy(&cur_bridge_ports);
		ni_string_array_destroy(&cfg_bridge_ports);

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
__ni_interface_vlan_configure(ni_handle_t *nih, const ni_interface_t *cfg, ni_interface_t **ifpp)
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
		ni_refresh(nih, NULL);

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
		if (!ni_interface_network_is_up(real_dev)
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
 * Create a VLAN interface
 */
int
ni_interface_create_vlan(ni_handle_t *nih, const char *ifname, const ni_vlan_t *cfg_vlan, ni_interface_t **ifpp)
{
	ni_interface_t *ifp;
	ni_vlan_t *cur_vlan = NULL;

	ifp = ni_interface_by_vlan_tag(nih, cfg_vlan->tag);
	if (ifp != NULL) {
		ni_error("%s: VLAN interface with tag 0x%x already exists", ifname, cfg_vlan->tag);
		return -1;
	}

	debug_ifconfig("%s: creating VLAN device", ifname);
	if (__ni_rtnl_link_create_vlan(nih, ifname, cfg_vlan)) {
		error("unable to create vlan interface %s", ifname);
		return -1;
	}

	/* Refresh interface status */
	ni_refresh(nih, NULL);

	ifp = ni_interface_by_vlan_tag(nih, cfg_vlan->tag);
	if (ifp == NULL) {
		error("tried to create interface %s; still not found", ifname);
		return -1;
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
					ifname, cfg_vlan->interface_name);
			return -1;
		}

		/* Now bring up the underlying ethernet device if it's not up yet.
		 * Note, we don't change anything except its link status */
		if (!ni_interface_network_is_up(real_dev)
		 && __ni_system_interface_bringup(nih, real_dev) < 0) {
			error("Cannot bring up VLAN interface %s: %s not ready yet",
					ifname, cfg_vlan->interface_name);
			return -1;
		}
	}

	*ifpp = ifp;
	return 0;
}

/*
 * Delete a VLAN interface
 */
int
ni_interface_delete_vlan(ni_handle_t *nih, ni_interface_t *ifp)
{
	if (__ni_rtnl_link_down(nih, ifp, RTM_DELLINK)) {
		ni_error("could not destroy VLAN interface %s", ifp->name);
		return -1;
	}
	return 0;
}

/*
 * Handle link transformation for bonding device
 */
static int
__ni_interface_bond_configure(ni_handle_t *nih, const ni_interface_t *cfg, ni_interface_t **ifpp)
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

		if (ni_interface_network_is_up(slave_dev)) {
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
		ni_refresh(nih, NULL);

		if (__ni_interface_for_config(nih, cfg, &ifp) < 0 || ifp == NULL) {
			error("tried to create interface %s; still not found", cfg->name);
			return -1;
		}
	}

	if (!(cur_bond = ifp->bonding))
		return -1;

	if (ni_interface_network_is_up(ifp)) {
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
	if (BOND_DEVICE_MUST_BE_UP_WHEN_MESSING_WITH_SLAVES || ni_interface_network_is_up(cfg)) {
		if (!ni_interface_network_is_up(ifp) && __ni_system_interface_bringup(nih, ifp) < 0) {
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

	if (ni_interface_network_is_up(ifp)
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
__ni_interface_extension_configure(ni_handle_t *nih, const ni_interface_t *cfg, ni_interface_t **ifpp)
{
	ni_extension_t *ex;

	ex = ni_config_find_linktype_extension(ni_global.config, cfg->type);
	if (ex == NULL) {
		ni_debug_ifconfig("cannot configure %s interface - not implemented yet",
				ni_linktype_type_to_name(cfg->type));
		return 0;
	}

	return ni_extension_start(ex, cfg->name, NULL);
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
 * Update the IPv6 sysctl settings for the given interface
 */
int
__ni_interface_update_ipv6_settings(ni_handle_t *nih, ni_interface_t *ifp, const ni_interface_t *cfg)
{
	int brought_up = 0;
	int rv = -1;

	/* You can confuse the kernel IPv6 code to a degree that it will
	 * remove /proc/sys/ipv6/conf/<ifname> completely. dhcpcd in particular
	 * seems rather good at that. 
	 * The only way to recover from that is by upping the interface briefly.
	 */
	if (!ni_sysctl_ipv6_ifconfig_is_present(cfg->name)) {
		if (__ni_rtnl_link_up(nih, ifp, cfg) >= 0) {
			unsigned int count = 100;

			while (count-- && !ni_sysctl_ipv6_ifconfig_is_present(cfg->name))
				usleep(100000);
			brought_up = 1;
		}
	}

	if (ni_sysctl_ipv6_ifconfig_set_uint(cfg->name, "disable_ipv6", !cfg->ipv6.enabled) < 0) {
		ni_error("%s: cannot %s ipv6", cfg->name, cfg->ipv6.enabled? "enable" : "disable");
		goto out;
	}
	if (cfg->ipv6.enabled) {
		int autoconf = ni_afinfo_addrconf_test(&cfg->ipv6, NI_ADDRCONF_STATIC);

		if (ni_sysctl_ipv6_ifconfig_set_uint(cfg->name, "autoconf", autoconf) < 0) {
			ni_error("%s: cannot %s ipv6 autoconf", cfg->name, autoconf? "enable" : "disable");
			goto out;
		}
		if (ni_sysctl_ipv6_ifconfig_set_uint(cfg->name, "forwarding", cfg->ipv6.forwarding) < 0) {
			ni_error("%s: cannot %s ipv6 forwarding", cfg->name, cfg->ipv6.forwarding? "enable" : "disable");
			goto out;
		}
	}
	rv = 0;

out:
	if (brought_up)
		__ni_rtnl_link_down(nih, cfg, RTM_NEWLINK);

	return rv;
}

/*
 * Create a VLAN interface via netlink
 */
static int
__ni_rtnl_link_create_vlan(ni_handle_t *nih, const char *ifname, const ni_vlan_t *vlan)
{
	ni_interface_t *real_dev;
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
			ifname, vlan->tag, vlan->interface_name);

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		return -1;
	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "vlan");

	if (!(data = nla_nest_start(msg, IFLA_INFO_DATA)))
		return -1;

	NLA_PUT_U16(msg, IFLA_VLAN_ID, vlan->tag);
	nla_nest_end(msg, data);
	nla_nest_end(msg, linkinfo);

	/* Note, IFLA_LINK must be outside of IFLA_LINKINFO */

	real_dev = ni_interface_by_name(nih, vlan->interface_name);
	if (!real_dev || !real_dev->ifindex) {
		error("Cannot create VLAN interface %s: interface %s does not exist",
				ifname, vlan->interface_name);
		return -1;
	}
	NLA_PUT_U32(msg, IFLA_LINK, real_dev->ifindex);

	len = strlen(ifname) + 1;
	if (len == 1 || len > IFNAMSIZ) {
		error("\"%s\" is not a valid device identifier", ifname);
		return -1;
	}
	NLA_PUT_STRING(msg, IFLA_IFNAME, ifname);

	if (ni_nl_talk(nih, msg) < 0)
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
 * Create an interface via netlink - currently used by VLAN only
 */
static int
__ni_rtnl_link_create(ni_handle_t *nih, const ni_interface_t *cfg)
{
	ni_interface_t *real_dev;
	struct ifinfomsg ifi;
	struct nl_msg *msg;
	int len;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);

	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (cfg->type == NI_IFTYPE_VLAN) {
		struct nlattr *linkinfo;
		struct nlattr *data;
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

		if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
			return -1;
		NLA_PUT_STRING(msg, IFLA_INFO_KIND, "vlan");

		if (!(data = nla_nest_start(msg, IFLA_INFO_DATA)))
			return -1;

		NLA_PUT_U16(msg, IFLA_VLAN_ID, vlan->tag);
		nla_nest_end(msg, data);
		nla_nest_end(msg, linkinfo);

		/* Note, IFLA_LINK must be outside of IFLA_LINKINFO */

		real_dev = ni_interface_by_name(nih, cfg->vlan->interface_name);
		if (!real_dev || !real_dev->ifindex) {
			error("Cannot create VLAN interface %s: interface %s does not exist",
					cfg->name, cfg->vlan->interface_name);
			return -1;
		}
		NLA_PUT_U32(msg, IFLA_LINK, real_dev->ifindex);
	} else {
		error("Cannot create an interface of type %d through netlink", cfg->type);
		return -1;
	}

	len = strlen(cfg->name) + 1;
	if (len == 1 || len > IFNAMSIZ) {
		error("\"%s\" is not a valid device identifier", cfg->name);
		return -1;
	}
	NLA_PUT_STRING(msg, IFLA_IFNAME, cfg->name);

	if (ni_nl_talk(nih, msg) < 0)
		goto failed;

	ni_debug_ifconfig("successfully created interface %s", cfg->name);
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
__ni_rtnl_simple(ni_handle_t *nih, int msgtype, unsigned int flags, void *data, size_t len)
{
	struct nl_msg *msg;
	int rv = -1;

	msg = nlmsg_alloc_simple(msgtype, flags);

	if (nlmsg_append(msg, data, len, NLMSG_ALIGNTO) < 0) {
		ni_error("%s: nlmsg_append failed", __func__);
	} else
	if (ni_nl_talk(nih, msg) < 0) {
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
__ni_rtnl_link_down(ni_handle_t *nih, const ni_interface_t *ifp, int cmd)
{
	struct ifinfomsg ifi;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = ifp->ifindex;
	ifi.ifi_change = IFF_UP;

	return __ni_rtnl_simple(nih, cmd, 0, &ifi, sizeof(ifi));
}

/*
 * (Re-)configure an interface
 */
static int
__ni_rtnl_link_up(ni_handle_t *nih, const ni_interface_t *ifp, const ni_interface_t *cfg)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = ifp->ifindex;
	ifi.ifi_change = IFF_UP;
	ifi.ifi_flags = IFF_UP;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_CREATE);

	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (cfg) {
		if (cfg->mtu && cfg->mtu != ifp->mtu)
			NLA_PUT_U32(msg, IFLA_MTU, cfg->mtu);

		if (cfg->txqlen && cfg->txqlen != ifp->txqlen)
			NLA_PUT_U32(msg, IFLA_TXQLEN, cfg->txqlen);

		if (cfg->hwaddr.type != NI_IFTYPE_UNKNOWN && cfg->hwaddr.len != 0
		 && !ni_link_address_equal(&cfg->hwaddr, &ifp->hwaddr))
			NLA_PUT(msg, IFLA_ADDRESS, cfg->hwaddr.len, cfg->hwaddr.data);

		/* FIXME: handle COST, QDISC, MASTER */
	}

	if (ni_nl_talk(nih, msg) < 0) {
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
__ni_interface_address_exists(const ni_interface_t *ifp, const ni_address_t *ap)
{
	ni_address_t *ap2;

	if (ap->local_addr.ss_family == AF_INET) {
		const struct sockaddr_in *sin1, *sin2;

		sin1 = &ap->local_addr.sin;
		for (ap2 = ifp->addrs; ap2; ap2 = ap2->next) {
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
		for (ap2 = ifp->addrs; ap2; ap2 = ap2->next) {
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
__ni_rtnl_send_newaddr(ni_handle_t *nih, ni_interface_t *ifp, const ni_address_t *ap, int flags)
{
	struct ifaddrmsg ifa;
	struct nl_msg *msg;
	int len;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&ap->local_addr), ap->prefixlen);

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_index = ifp->ifindex;
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

	if (ni_nl_talk(nih, msg) < 0) {
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
__ni_rtnl_send_deladdr(ni_handle_t *nih, ni_interface_t *ifp, const ni_address_t *ap)
{
	struct ifaddrmsg ifa;
	struct nl_msg *msg;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&ap->local_addr), ap->prefixlen);

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_index = ifp->ifindex;
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

	if (ni_nl_talk(nih, msg) < 0) {
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
__ni_rtnl_send_newroute(ni_handle_t *nih, ni_interface_t *ifp, ni_route_t *rp, int flags)
{
	struct rtmsg rt;
	struct nl_msg *msg;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&rp->destination), rp->prefixlen);

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

	NLA_PUT_U32(msg, RTA_OIF, ifp->ifindex);

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

	if (ni_nl_talk(nih, msg) < 0) {
		error("%s(%s/%u): rtnl_talk failed", __FUNCTION__,
				ni_address_print(&rp->destination),
				rp->prefixlen);
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
__ni_rtnl_send_delroute(ni_handle_t *nih, ni_interface_t *ifp, ni_route_t *rp)
{
	struct rtmsg rt;
	struct nl_msg *msg;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&rp->destination), rp->prefixlen);

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

	NLA_PUT_U32(msg, RTA_OIF, ifp->ifindex);

	if (ni_nl_talk(nih, msg) < 0) {
		ni_error("%s(%s/%u): rtnl_talk failed", __FUNCTION__,
				ni_address_print(&rp->destination),
				rp->prefixlen);
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
__ni_interface_addrconf(ni_handle_t *nih, int family, ni_interface_t *ifp, const ni_interface_t *cfg)
{
	const ni_afinfo_t *cfg_afi;
	ni_afinfo_t *cur_afi;
	xml_node_t *xml = NULL;
	unsigned int cfg_addrconf;
	unsigned int mode;

	debug_ifconfig("__ni_interface_addrconf(%s, af=%s)", ifp->name,
			ni_addrfamily_type_to_name(family));

	cfg_afi = __ni_interface_address_info(cfg, family);
	cur_afi = __ni_interface_address_info(ifp, family);
	if (!cfg_afi || !cur_afi)
		return -1;

	if (!cfg_afi->enabled)
		return 0;

	cfg_addrconf = cfg_afi->addrconf;
	if (!ni_interface_network_is_up(cfg))
		cfg_addrconf = 0;

	/* If we're disabling an addrconf mode, stop the respective service */
	for (mode = 0; mode < __NI_ADDRCONF_MAX; ++mode) {
		ni_addrconf_t *acm;

		if (ni_afinfo_addrconf_test(cur_afi, mode)
		 && !NI_ADDRCONF_TEST(cfg_addrconf, mode)) {
			ni_debug_ifconfig("%s: disabling %s/%s", ifp->name,
					ni_addrfamily_type_to_name(family),
					ni_addrconf_type_to_name(mode));
			ni_afinfo_addrconf_disable(cur_afi, mode);
			acm = ni_addrconf_get(mode, family);
			if (acm && ni_addrconf_drop_lease(acm, ifp) < 0)
				return -1;
			// ni_interface_clear_lease(ifp, mode, family);
		}
	}

	if (NI_ADDRCONF_TEST(cfg_addrconf, NI_ADDRCONF_STATIC)) {
		ni_address_t *ap, *next;
		ni_route_t *rp;

		/* Loop over all addresses currently assigned to the interface.
		 * If the configuration no longer specifies it, delete it.
		 * We need to mimic the kernel's matching behavior when modifying
		 * the configuration of existing addresses.
		 */
		ni_afinfo_addrconf_enable(cur_afi, NI_ADDRCONF_STATIC);
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
			if (ap->config_method != NI_ADDRCONF_STATIC)
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

			/* Even interfaces with static network config may have
			 * dynamically configured routes. Don't touch these.
			 */
			if (rp->config_method != NI_ADDRCONF_STATIC)
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

			ni_debug_ifconfig("%s: trying to delete existing route %s/%u",
					ifp->name, ni_address_print(&rp->destination),
					rp->prefixlen);
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
	}

	/* Now bring up addrconf services */
	for (mode = 0; mode < __NI_ADDRCONF_MAX; ++mode) {
		ni_addrconf_lease_t *lease;
		ni_addrconf_t *acm;

		if (mode == NI_ADDRCONF_STATIC)
			continue;

		if (!NI_ADDRCONF_TEST(cfg_addrconf, mode))
			continue;

		/* IPv6 autoconf takes care of itself */
		if (family == AF_INET6 && mode == NI_ADDRCONF_AUTOCONF) {
			if (!cur_afi->lease[NI_ADDRCONF_AUTOCONF]) {
				cur_afi->lease[NI_ADDRCONF_AUTOCONF] = ni_addrconf_lease_new(NI_ADDRCONF_AUTOCONF, family);
				cur_afi->lease[NI_ADDRCONF_AUTOCONF]->state = NI_ADDRCONF_STATE_GRANTED;
			}
			continue;
		}

		acm = ni_addrconf_get(mode, family);
		if (acm == NULL) {
			ni_error("address configuration mode %s not supported for %s",
				ni_addrconf_type_to_name(mode),
				ni_addrfamily_type_to_name(cfg_afi->family));
			continue;
		}

		__ni_afinfo_set_addrconf_request(cur_afi, mode,
				ni_addrconf_request_clone(cfg_afi->request[mode]));

		/* If the extension is already active, no need to start it once
		 * more. If needed, we could do a restart in this case. */
		if (ni_afinfo_addrconf_test(cur_afi, mode)) {
			lease = cur_afi->lease[mode];
			if (lease && lease->state == NI_ADDRCONF_STATE_GRANTED)
				continue;
		}

		ni_afinfo_addrconf_enable(cur_afi, mode);
		if (ni_addrconf_acquire_lease(acm, ifp, NULL) < 0)
			goto error;

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
		if (cur_afi->request[mode] != NULL)
			ni_addrconf_request_file_write(ifp->name, cur_afi->request[mode]);
	}

	if (xml)
		xml_node_free(xml);

	return 0;

error:
	if (xml)
		xml_node_free(xml);
	return -1;
}
