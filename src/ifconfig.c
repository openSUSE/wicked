/*
 * Things to do when bringing an interface up or down
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *
 * Link layer:
 *  - handle ethtool options
 *  - set device MTU
 *  - set link layer addr
 *  - set other LL options
 *  - bring up link layer
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include <wicked/route.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/vlan.h>
#include <wicked/system.h>
#include <wicked/wireless.h>

#include "netinfo_priv.h"
#include "sysfs.h"
#include "kernel.h"
#include "appconfig.h"
#include "debug.h"

static int	__ni_netdev_update_ipv6_settings(ni_netdev_t *, const ni_afinfo_t *);
static int	__ni_netdev_update_addrs(ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_address_t *cfg_addr_list);
static int	__ni_netdev_update_routes(ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_route_t *cfg_route_list);
static int	__ni_rtnl_link_create_vlan(const char *, const ni_vlan_t *, unsigned int);
static int	__ni_rtnl_link_up(const ni_netdev_t *, const ni_netdev_req_t *);
static int	__ni_rtnl_link_down(const ni_netdev_t *, int);
static int	__ni_rtnl_send_deladdr(ni_netdev_t *, const ni_address_t *);
static int	__ni_rtnl_send_newaddr(ni_netdev_t *, const ni_address_t *, int);
static int	__ni_rtnl_send_delroute(ni_netdev_t *, ni_route_t *);
static int	__ni_rtnl_send_newroute(ni_netdev_t *, ni_route_t *, int);

int
ni_system_interface_link_change(ni_netdev_t *dev, const ni_netdev_req_t *ifp_req)
{
	unsigned int ifflags;
	int res;

	if (dev == NULL)
		return -NI_ERROR_INVALID_ARGS;

	ni_debug_ifconfig("%s(%s)", __func__, dev->name);

	/* FIXME: perform sanity check on configuration data */

	ifflags = ifp_req? ifp_req->ifflags : 0;
	if (ifflags & (NI_IFF_DEVICE_UP|NI_IFF_LINK_UP|NI_IFF_NETWORK_UP)) {
		ni_debug_ifconfig("bringing up %s", dev->name);

		/* If we want to disable ipv6 or ipv6 autoconf, we need to do so prior to bringing
		 * the interface up. */
		if (__ni_netdev_update_ipv6_settings(dev, ifp_req->ipv6) < 0)
			return -1;

		if (__ni_rtnl_link_up(dev, ifp_req)) {
			ni_error("%s: failed to bring up interface (rtnl error)", dev->name);
			return -1;
		}

		if (dev->link.type == NI_IFTYPE_WIRELESS)
			ni_wireless_connect(dev);
	} else {
		/* FIXME: Shut down any addrconf services on this interface?
		 * We should expect these services to detect the link down event...
		 */

		if (dev->link.type == NI_IFTYPE_WIRELESS)
			ni_wireless_disconnect(dev);

		/* Now take down the link for real */
		ni_debug_ifconfig("shutting down interface %s", dev->name);
		if (__ni_rtnl_link_down(dev, RTM_NEWLINK)) {
			ni_error("unable to shut down interface %s", dev->name);
			return -1;
		}
	}

	__ni_global_seqno++;

	res = __ni_system_refresh_interface(ni_global_state_handle(0), dev);
	return res;
}

/*
 * An address configuration agent sends a lease update.
 */
int
__ni_system_interface_update_lease(ni_netdev_t *dev, ni_addrconf_lease_t **lease_p)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_addrconf_lease_t *lease = *lease_p, *old_lease = NULL;
	int res;

	ni_debug_ifconfig("%s: received %s/%s lease update; state %s", dev->name,
			ni_addrconf_type_to_name(lease->type),
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_state_to_name(lease->state));

	if ((res = __ni_system_refresh_interface(nc, dev)) < 0)
		return -1;

	/* Use the existing lease handle to identify those addresses already
	 * owned by this addrconf protocol.
	 * While we're getting the old lease, detach it from the interface
	 * (but don't delete it yet).
	 */
	old_lease = __ni_netdev_find_lease(dev, lease->family, lease->type, 1);

	if (lease->state == NI_ADDRCONF_STATE_GRANTED)
		res = __ni_netdev_update_addrs(dev, old_lease, lease->addrs);
	else
		res = __ni_netdev_update_addrs(dev, old_lease, NULL);
	if (res < 0) {
		ni_error("%s: error updating interface config from %s lease",
				dev->name, 
				ni_addrconf_type_to_name(lease->type));
		goto out;
	}

	/* Refresh state here - routes may have disappeared, for instance,
	 * when we took away the address. */
	if ((res = __ni_system_refresh_interface(nc, dev)) < 0)
		goto out;

	/* Loop over all routes and remove those no longer covered by the lease.
	 * Ignore all routes covered by other address config mechanisms.
	 */
	if (lease->state == NI_ADDRCONF_STATE_GRANTED)
		res = __ni_netdev_update_routes(dev, old_lease, lease->routes);
	else
		res = __ni_netdev_update_routes(dev, old_lease, NULL);
	if (res < 0) {
		ni_error("%s: error updating interface config from %s lease",
				dev->name, 
				ni_addrconf_type_to_name(lease->type));
		goto out;
	}

	if (lease->state == NI_ADDRCONF_STATE_GRANTED) {
		ni_netdev_set_lease(dev, lease);
		*lease_p = NULL;
	}

	lease->update &= ni_config_addrconf_update_mask(ni_global.config, lease->type);
	ni_system_update_from_lease(lease);

out:
	if (old_lease)
		ni_addrconf_lease_free(old_lease);
	return res;
}

/*
 * Delete the given interface
 * ni_system_interface_delete
 */
int
ni_system_interface_delete(ni_netconfig_t *nc, const char *ifname)
{
	ni_netdev_t *dev;

	ni_debug_ifconfig("ni_system_interface_delete(%s)", ifname);

	/* FIXME: perform sanity check on configuration data */

	dev = ni_netdev_by_name(nc, ifname);
	if (dev == NULL) {
		ni_error("cannot delete interface %s - not known", ifname);
		return -1;
	}

	switch (dev->link.type) {
	case NI_IFTYPE_LOOPBACK:
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_WIRELESS:
	case NI_IFTYPE_DUMMY:
		ni_error("cannot destroy %s interfaces", ni_linktype_type_to_name(dev->link.type));
		return -1;

	case NI_IFTYPE_VLAN:
		if (__ni_rtnl_link_down(dev, RTM_DELLINK)) {
			ni_error("could not destroy VLAN interface %s", dev->name);
			return -1;
		}
		break;

	case NI_IFTYPE_BRIDGE:
		if (__ni_brioctl_del_bridge(dev->name) < 0) {
			ni_error("could not destroy bridge interface %s", dev->name);
			return -1;
		}
		break;

	case NI_IFTYPE_BOND:
		if (ni_sysfs_bonding_delete_master(dev->name) < 0) {
			ni_error("could not destroy bonding interface %s", dev->name);
			return -1;
		}
		break;

	default:
		ni_error("%s not implemented for link type %u (%s)",
				__func__, dev->link.type,
				ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	return 0;
}

/*
 * Create a VLAN interface
 * ni_system_vlan_create
 */
int
ni_system_vlan_create(ni_netconfig_t *nc, const char *ifname, const ni_vlan_t *cfg_vlan, ni_netdev_t **dev_ret)
{
	ni_netdev_t *dev, *phys_dev;
	ni_vlan_t *cur_vlan = NULL;

	*dev_ret = NULL;

	dev = ni_netdev_by_vlan_name_and_tag(nc, cfg_vlan->physdev_name, cfg_vlan->tag);
	if (dev != NULL) {
		/* This is not necessarily an error */
		*dev_ret = dev;
		return -NI_ERROR_DEVICE_EXISTS;
	}

	phys_dev = ni_netdev_by_name(nc, cfg_vlan->physdev_name);
	if (!phys_dev || !phys_dev->link.ifindex) {
		ni_error("Cannot create VLAN interface %s: interface %s does not exist",
				ifname, cfg_vlan->physdev_name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	ni_debug_ifconfig("%s: creating VLAN device", ifname);
	if (__ni_rtnl_link_create_vlan(ifname, cfg_vlan, phys_dev->link.ifindex)) {
		ni_error("unable to create vlan interface %s", ifname);
		return -1;
	}

	/* Refresh interface status */
	__ni_system_refresh_interfaces(nc);

	dev = ni_netdev_by_vlan_name_and_tag(nc, cfg_vlan->physdev_name, cfg_vlan->tag);
	if (dev == NULL) {
		ni_error("tried to create interface %s; still not found", ifname);
		return -1;
	}

	if (!(cur_vlan = dev->link.vlan))
		return -1;

	{
		ni_netdev_t *real_dev;

		if (!cfg_vlan->physdev_name)
			return -1;
		real_dev = ni_netdev_by_name(nc, cfg_vlan->physdev_name);
		if (!real_dev || !real_dev->link.ifindex) {
			ni_error("Cannot bring up VLAN interface %s: %s does not exist",
					ifname, cfg_vlan->physdev_name);
			return -NI_ERROR_DEVICE_NOT_KNOWN;
		}
	}

	*dev_ret = dev;
	return 0;
}

/*
 * Delete a VLAN interface
 */
int
ni_system_vlan_delete(ni_netdev_t *dev)
{
	if (__ni_rtnl_link_down(dev, RTM_DELLINK)) {
		ni_error("could not destroy VLAN interface %s", dev->name);
		return -1;
	}
	return 0;
}

/*
 * Create a bridge interface
 */
int
ni_system_bridge_create(ni_netconfig_t *nc, const char *ifname,
			const ni_bridge_t *cfg_bridge, ni_netdev_t **dev_ret)
{
	ni_netdev_t *dev;

	ni_debug_ifconfig("%s: creating bridge interface", ifname);
	if (__ni_brioctl_add_bridge(ifname) < 0) {
		ni_error("__ni_brioctl_add_bridge(%s) failed", ifname);
		return -1;
	}

	/* Refresh interface status */
	__ni_system_refresh_interfaces(nc);

	dev = ni_netdev_by_name(nc, ifname);
	if (dev == NULL) {
		ni_error("tried to create interface %s; still not found", ifname);
		return -1;
	}

	*dev_ret = dev;
	return 0;
}

/*
 * Given data provided by the user, update the bridge config
 */
int
ni_system_bridge_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_bridge_t *bcfg)
{
	if (dev->link.type != NI_IFTYPE_BRIDGE) {
		ni_error("%s: %s is not a bridge interface", __func__, dev->name);
		return -1;
	}

	if (ni_sysfs_bridge_update_config(dev->name, bcfg) < 0) {
		ni_error("%s: failed to update sysfs attributes for %s", __func__, dev->name);
		return -1;
	}

	return __ni_system_refresh_interface(nc, dev);
}

/*
 * Delete a bridge interface
 */
int
ni_system_bridge_delete(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	if (__ni_brioctl_del_bridge(dev->name) < 0) {
		ni_error("could not destroy bridge interface %s", dev->name);
		return -1;
	}
	return 0;
}

/*
 * Add a port to a bridge interface
 * Note, in case of success, the bridge will have taken ownership of the port object.
 */
int
ni_system_bridge_add_port(ni_netconfig_t *nc, ni_netdev_t *brdev, ni_bridge_port_t *port)
{
	ni_bridge_t *bridge = ni_netdev_get_bridge(brdev);
	ni_netdev_t *pif = NULL;
	int rv;

	if (port->ifindex)
		pif = ni_netdev_by_index(nc, port->ifindex);
	else if (port->ifname)
		pif = ni_netdev_by_name(nc, port->ifname);

	if (pif == NULL) {
		ni_error("%s: cannot add port - interface not known", brdev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}
	if (pif->link.ifindex == 0) {
		ni_error("%s: cannot add port - %s has no ifindex?!", brdev->name, pif->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	/* This should be a more elaborate check - neither device can be an ancestor of
	 * the other, or we create a loop.
	 */
	if (pif == brdev) {
		ni_error("%s: cannot add interface as its own bridge port", brdev->name);
		return -NI_ERROR_DEVICE_BAD_HIERARCHY;
	}

	if (ni_bridge_port_by_index(bridge, pif->link.ifindex) != NULL) {
		ni_error("%s: interface %s is already port", brdev->name, pif->name);
		return -NI_ERROR_DEVICE_BAD_HIERARCHY;
	}

	if ((rv = __ni_brioctl_add_port(brdev->name, pif->link.ifindex)) < 0) {
		ni_error("%s: cannot add port %s: %s", brdev->name, pif->name,
				ni_strerror(rv));
		return rv;
	}

	/* Now configure the newly added port */
	if ((rv = ni_sysfs_bridge_port_update_config(brdev->name, port)) < 0) {
		ni_error("%s: failed to configure port %s: %s", brdev->name, pif->name,
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
ni_system_bridge_remove_port(ni_netconfig_t *nc, ni_netdev_t *dev, int port_ifindex)
{
	ni_bridge_t *bridge = ni_netdev_get_bridge(dev);
	int rv;

	if (port_ifindex == 0) {
		ni_error("%s: cannot remove port: bad ifindex", dev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	if ((rv = __ni_brioctl_del_port(dev->name, port_ifindex)) < 0) {
		ni_error("%s: cannot remove port: %s", dev->name, ni_strerror(rv));
		return rv;
	}

	ni_bridge_del_port_ifindex(bridge, port_ifindex);
	return 0;
}

/*
 * Create a bonding device
 */
int
ni_system_bond_create(ni_netconfig_t *nc, const char *ifname, const ni_bonding_t *bond, ni_netdev_t **dev_ret)
{
	ni_netdev_t *dev;

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
			ni_error("unable to load bonding module - couldn't find bonding_masters");
			return -1;
		}
	}

	if (!ni_sysfs_bonding_is_master(ifname)) {
		int success = 0;

		ni_debug_ifconfig("%s: creating bond master", ifname);
		if (ni_sysfs_bonding_add_master(ifname) >= 0) {
			unsigned int i;

			/* Wait for bonding_masters to appear */
			for (i = 0; i < 400; ++i) {
				if ((success = ni_sysfs_bonding_is_master(ifname)) != 0)
					break;
				usleep(25000);
			}
		}

		if (!success) {
			ni_error("unable to create bonding device %s", ifname);
			return -1;
		}
	}

	/* Refresh interface status */
	__ni_system_refresh_interfaces(nc);

	if ((dev = ni_netdev_by_name(nc, ifname)) == NULL) {
		ni_error("tried to create interface %s; still not found", ifname);
		return -1;
	}

	*dev_ret = dev;
	return 0;
}

/*
 * Set up an ethernet device
 */
int
ni_system_ethernet_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_ethernet_t *dev_cfg)
{
	if (__ni_system_ethernet_update(dev, dev_cfg) < 0) {
		ni_error("%s: failed to update ethernet device settings", dev->name);
		return -1;
	}

	return 0;
}

/*
 * Set up a bonding device
 */
int
ni_system_bond_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_bonding_t *bond_cfg)
{
	const char *complaint;
	ni_bonding_t *bond;

	complaint = ni_bonding_validate(bond_cfg);
	if (complaint != NULL) {
		ni_error("%s: cannot set up bonding device: %s", dev->name, complaint);
		return -NI_ERROR_INVALID_ARGS;
	}

	if ((bond = ni_netdev_get_bonding(dev)) == NULL) {
		ni_error("%s: not a bonding interface ", dev->name);
		return -1;
	}

	/* Store attributes stage 0 - most attributes need to be written prior to
	   bringing up the interface */
	if (ni_bonding_write_sysfs_attrs(dev->name, bond_cfg, bond, 0) < 0) {
		ni_error("%s: error configuring bonding device (stage 0)", dev->name);
		return -1;
	}

	/* Update the list of slave devices */
	if (ni_sysfs_bonding_set_list_attr(dev->name, "slaves", &bond_cfg->slave_names) < 0) {
		ni_error("%s: could not update list of slaves", dev->name);
		return -NI_ERROR_PERMISSION_DENIED;
	}

	/* If the interface is up, we can assign the primary interface right away.
	 * Otherwise, we have to remember it and assign it later */
	ni_string_dup(&bond->requested_primary, bond_cfg->primary);

	if (ni_netdev_device_is_up(dev)) {
		if (ni_bonding_write_sysfs_attrs(dev->name, bond_cfg, bond, 1) < 0) {
			ni_error("%s: error configuring bonding device (stage 1)", dev->name);
			return -1;
		}
	}
	return 0;
}

/*
 * Delete a bonding device
 */
int
ni_system_bond_delete(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	if (ni_sysfs_bonding_delete_master(dev->name) < 0) {
		ni_error("could not destroy bonding interface %s", dev->name);
		return -1;
	}
	return 0;
}

/*
 * Add slave to a bond
 */
int
ni_system_bond_add_slave(ni_netconfig_t *nc, ni_netdev_t *dev, unsigned int slave_idx)
{
	ni_bonding_t *bond = dev->bonding;
	ni_netdev_t *slave_dev;

	if (bond == NULL) {
		ni_error("%s: %s is not a bonding device", __func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_COMPATIBLE;
	}

	slave_dev = ni_netdev_by_index(nc, slave_idx);
	if (slave_dev == NULL) {
		ni_error("%s: trying to add unknown interface to bond %s", __func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	if (ni_netdev_network_is_up(slave_dev)) {
		ni_error("%s: trying to enslave %s, which is in use", dev->name, slave_dev->name);
		return -NI_ERROR_DEVICE_NOT_DOWN;
	}

	/* Silently ignore duplicate slave attach */
	if (ni_string_array_index(&bond->slave_names, slave_dev->name) >= 0)
		return 0;

	ni_bonding_add_slave(bond, slave_dev->name);
	if (ni_sysfs_bonding_set_list_attr(dev->name, "slaves", &bond->slave_names) < 0) {
		ni_error("%s: could not update list of slaves", dev->name);
		return -NI_ERROR_PERMISSION_DENIED;
	}

	return 0;
}

/*
 * Remove a slave from a bond
 */
int
ni_system_bond_remove_slave(ni_netconfig_t *nc, ni_netdev_t *dev, unsigned int slave_idx)
{
	ni_bonding_t *bond = dev->bonding;
	ni_netdev_t *slave_dev;
	int idx;

	if (bond == NULL) {
		ni_error("%s: %s is not a bonding device", __func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_COMPATIBLE;
	}

	slave_dev = ni_netdev_by_index(nc, slave_idx);
	if (slave_dev == NULL) {
		ni_error("%s: trying to add unknown interface to bond %s", __func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	/* Silently ignore duplicate slave removal */
	if ((idx = ni_string_array_index(&bond->slave_names, slave_dev->name)) < 0)
		return 0;

	ni_string_array_remove_index(&bond->slave_names, idx);
	if (ni_sysfs_bonding_set_list_attr(dev->name, "slaves", &bond->slave_names) < 0) {
		ni_error("%s: could not update list of slaves", dev->name);
		return -NI_ERROR_PERMISSION_DENIED;
	}

	return 0;
}

/*
 * Create a tun interface
 */
int
ni_system_tun_create(ni_netconfig_t *nc, const char *ifname, ni_netdev_t **dev_ret)
{
	ni_netdev_t *dev;
	char *newname;

	ni_debug_ifconfig("%s: creating tun interface", ifname);
	if ((newname = __ni_tuntap_create_tun(ifname)) == NULL) {
		ni_error("__ni_tuntap_create_tun(%s) failed", ifname);
		return -1;
	}

	/* Refresh interface status */
	__ni_system_refresh_interfaces(nc);

	dev = ni_netdev_by_name(nc, newname);
	free(newname);

	if (dev == NULL) {
		ni_error("tried to create tun interface %s; still not found", ifname);
		return -1;
	}

	*dev_ret = dev;
	return 0;
}

/*
 * Delete a tun interface
 */
int
ni_system_tun_delete(ni_netdev_t *dev)
{
	int rv;

	if ((rv = __ni_tuntap_delete(dev->name)) < 0) {
		ni_error("could not destroy tun/tap interface %s", dev->name);
		return rv;
	}
	return 0;
}

/*
 * Update the IPv6 sysctl settings for the given interface
 */
int
__ni_netdev_update_ipv6_settings(ni_netdev_t *dev, const ni_afinfo_t *afi)
{
	int enable = afi? afi->enabled : 0;
	int brought_up = 0;
	int rv = -1;

	/* You can confuse the kernel IPv6 code to a degree that it will
	 * remove /proc/sys/ipv6/conf/<ifname> completely. dhcpcd in particular
	 * seems rather good at that. 
	 * The only way to recover from that is by upping the interface briefly.
	 */
	if (!ni_sysctl_ipv6_ifconfig_is_present(dev->name)) {
		if (__ni_rtnl_link_up(dev, NULL) >= 0) {
			unsigned int count = 100;

			while (count-- && !ni_sysctl_ipv6_ifconfig_is_present(dev->name))
				usleep(100000);
			brought_up = 1;
		}
	}

	if (ni_sysctl_ipv6_ifconfig_set_uint(dev->name, "disable_ipv6", !enable) < 0) {
		ni_error("%s: cannot %s ipv6", dev->name, enable? "enable" : "disable");
		goto out;
	}
	if (enable) {
		int autoconf = ni_afinfo_addrconf_test(afi, NI_ADDRCONF_STATIC);

		if (ni_sysctl_ipv6_ifconfig_set_uint(dev->name, "autoconf", autoconf) < 0) {
			ni_error("%s: cannot %s ipv6 autoconf", dev->name, autoconf? "enable" : "disable");
			goto out;
		}
		if (ni_sysctl_ipv6_ifconfig_set_uint(dev->name, "forwarding", afi->forwarding) < 0) {
			ni_error("%s: cannot %s ipv6 forwarding", dev->name, afi->forwarding? "enable" : "disable");
			goto out;
		}
	}
	rv = 0;

out:
	if (brought_up)
		__ni_rtnl_link_down(dev, RTM_NEWLINK);

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
	ni_debug_ifconfig("__ni_rtnl_link_create(%s, vlan, %u, %s)",
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
		ni_error("\"%s\" is not a valid device identifier", ifname);
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
__ni_rtnl_link_down(const ni_netdev_t *dev, int cmd)
{
	struct ifinfomsg ifi;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = dev->link.ifindex;
	ifi.ifi_change = IFF_UP;

	return __ni_rtnl_simple(cmd, 0, &ifi, sizeof(ifi));
}

/*
 * (Re-)configure an interface
 */
static int
__ni_rtnl_link_up(const ni_netdev_t *dev, const ni_netdev_req_t *cfg)
{
	struct ifinfomsg ifi;
	struct nl_msg *msg;

	if (dev->link.ifindex == 0) {
		ni_error("%s: bad interface index for %s", __func__, dev->name);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	NI_TRACE_ENTER_ARGS("%s, idx=%d", dev->name, dev->link.ifindex);
	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = dev->link.ifindex;
	ifi.ifi_change = IFF_UP;
	ifi.ifi_flags = IFF_UP;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_CREATE);

	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (cfg) {
		if (cfg->mtu && cfg->mtu != dev->link.mtu)
			NLA_PUT_U32(msg, IFLA_MTU, cfg->mtu);

		if (cfg->txqlen && cfg->txqlen != dev->link.txqlen)
			NLA_PUT_U32(msg, IFLA_TXQLEN, cfg->txqlen);

#if 0
		/* Need different way to set hwaddr */
		if (cfg->link.hwaddr.type != NI_IFTYPE_UNKNOWN && cfg->link.hwaddr.len != 0
		 && !ni_link_address_equal(&cfg->link.hwaddr, &dev->link.hwaddr))
			NLA_PUT(msg, IFLA_ADDRESS, cfg->link.hwaddr.len, cfg->link.hwaddr.data);
#endif

		if (cfg->alias && !ni_string_eq(dev->link.alias, cfg->alias))
			NLA_PUT_STRING(msg, IFLA_IFALIAS, cfg->alias);

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
__ni_netdev_address_list_contains(ni_address_t *list, const ni_address_t *ap)
{
	ni_address_t *ap2;

	if (ap->local_addr.ss_family == AF_INET) {
		const struct sockaddr_in *sin1, *sin2;

		sin1 = &ap->local_addr.sin;
		for (ap2 = list; ap2; ap2 = ap2->next) {
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
		for (ap2 = list; ap2; ap2 = ap2->next) {
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
__ni_rtnl_send_newaddr(ni_netdev_t *dev, const ni_address_t *ap, int flags)
{
	struct ifaddrmsg ifa;
	struct nl_msg *msg;
	int len;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&ap->local_addr), ap->prefixlen);

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_index = dev->link.ifindex;
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
		if (memcmp(ap->label, dev->name, len) != 0) {
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
__ni_rtnl_send_deladdr(ni_netdev_t *dev, const ni_address_t *ap)
{
	struct ifaddrmsg ifa;
	struct nl_msg *msg;

	ni_debug_ifconfig("%s(%s/%u)", __FUNCTION__, ni_address_print(&ap->local_addr), ap->prefixlen);

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_index = dev->link.ifindex;
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
__ni_rtnl_send_newroute(ni_netdev_t *dev, ni_route_t *rp, int flags)
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

	if (rp->table >= 0)
		rt.rtm_table = rp->table;
	if (rp->protocol >= 0)
		rt.rtm_protocol = rp->protocol;
	if (rp->scope >= 0)
		rt.rtm_scope = rp->scope;
	if (rp->type >= 0)
		rt.rtm_type = rp->type;

	if (rt.rtm_type == RTN_LOCAL ||
	    rt.rtm_type == RTN_BROADCAST ||
	    rt.rtm_type == RTN_NAT ||
	    rt.rtm_type == RTN_ANYCAST)
		rt.rtm_table = RT_TABLE_LOCAL;

	switch (rt.rtm_type) {
	case RTN_LOCAL:
	case RTN_NAT:
		rt.rtm_scope = RT_SCOPE_HOST;
		break;

	case RTN_BROADCAST:
	case RTN_MULTICAST:
	case RTN_ANYCAST:
		rt.rtm_scope = RT_SCOPE_LINK;
		break;

	case RTN_UNICAST:
	case RTN_UNSPEC:
		if (rp->nh.gateway.ss_family == AF_UNSPEC)
			rt.rtm_scope = RT_SCOPE_LINK;
		break;
	}

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

	if (dev && dev->link.ifindex)
		NLA_PUT_U32(msg, RTA_OIF, dev->link.ifindex);

	/* Add metrics if needed */
	if (rp->mtu) {
		struct nlattr *mxrta;

		mxrta = nla_nest_start(msg, RTA_METRICS);
		if (mxrta == NULL)
			goto nla_put_failure;

		if (rp->mtu)
			NLA_PUT_U32(msg, RTAX_MTU, rp->mtu);
		if (rp->window)
			NLA_PUT_U32(msg, RTAX_WINDOW, rp->window);
		if (rp->rtt)
			NLA_PUT_U32(msg, RTAX_RTT, rp->rtt);
		if (rp->rttvar)
			NLA_PUT_U32(msg, RTAX_RTTVAR, rp->rttvar);
		if (rp->ssthresh)
			NLA_PUT_U32(msg, RTAX_SSTHRESH, rp->ssthresh);
		if (rp->cwnd)
			NLA_PUT_U32(msg, RTAX_CWND, rp->cwnd);
		if (rp->rto_min)
			NLA_PUT_U32(msg, RTAX_RTO_MIN, rp->rto_min);
		if (rp->advmss)
			NLA_PUT_U32(msg, RTAX_ADVMSS, rp->advmss);

		nla_nest_end(msg, mxrta);
	}

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
	return -NI_ERROR_CANNOT_CONFIGURE_ROUTE;
}

static int
__ni_rtnl_send_delroute(ni_netdev_t *dev, ni_route_t *rp)
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

	NLA_PUT_U32(msg, RTA_OIF, dev->link.ifindex);

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
__ni_netdev_route_list_contains(ni_route_t *list, const ni_route_t *rp)
{
	ni_route_t *rp2;

	for (rp2 = list; rp2; rp2 = rp2->next) {
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

/*
 * Update the addresses and routes assigned to an interface
 * for a given addrconf method
 */
static int
__ni_netdev_update_addrs(ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_address_t *cfg_addr_list)
{
	ni_address_t *ap, *next;
	int rv;

	for (ap = dev->addrs; ap; ap = next) {
		ni_address_t *new_addr;

		next = ap->next;

		/* See if the config list contains the address we've found in the
		 * system. */
		new_addr = __ni_netdev_address_list_contains(cfg_addr_list, ap);

		/* Do not touch addresses not managed by us. */
		if (ap->config_lease == NULL) {
			if (new_addr == NULL)
				continue;

			/* Address was assigned to device, but we did not track it.
			 * Could be due to a daemon restart - simply assume this
			 * is ours now. */
			ap->config_lease = old_lease;
		}

		/* If the address was managed by us (ie its owned by a lease with
		 * the same family/addrconf mode), then we want to check whether
		 * it's co-owned by any other lease. It's possible that an address
		 * is configured through several different protocols, and we don't
		 * want to delete such an address until the last of these protocols
		 * has shut down. */
		if (ap->config_lease == old_lease) {
			ni_addrconf_lease_t *other;

			if ((other = __ni_netdev_address_to_lease(dev, ap)) != NULL)
				ap->config_lease = other;
		}

		if (ap->config_lease != old_lease) {
			/* The existing address is managed by a different
			 * addrconf mode.
			 */
			if (new_addr != NULL) {
				ni_warn("%s: address %s covered by a %s lease",
					dev->name,
					ni_address_print(&ap->local_addr),
					ni_addrconf_type_to_name(ap->config_lease->type));
			}

			continue;
		}

		if (new_addr != NULL) {
			/* Check whether we need to update */
			if ((new_addr->scope == -1 || ap->scope == new_addr->scope)
			 && (new_addr->label[0] == '\0' || !strcmp(ap->label, new_addr->label))
			 && ni_address_equal(&ap->bcast_addr, &new_addr->bcast_addr)
			 && ni_address_equal(&ap->anycast_addr, &new_addr->anycast_addr)) {
				/* Current address as configured, no need to change. */
				ni_debug_ifconfig("address %s/%u exists; no need to reconfigure",
					ni_address_print(&ap->local_addr), ap->prefixlen);
				new_addr->seq = __ni_global_seqno;
				continue;
			}

			ni_debug_ifconfig("existing address %s/%u needs to be reconfigured",
					ni_address_print(&ap->local_addr),
					ap->prefixlen);
		}

		if ((rv = __ni_rtnl_send_deladdr(dev, ap)) < 0)
			return rv;
	}

	/* Loop over all addresses in the configuration and create
	 * those that don't exist yet.
	 */
	for (ap = cfg_addr_list; ap; ap = ap->next) {
		if (ap->seq == __ni_global_seqno)
			continue;

		ni_debug_ifconfig("Adding new interface address %s/%u",
				ni_address_print(&ap->local_addr),
				ap->prefixlen);
		if ((rv = __ni_rtnl_send_newaddr(dev, ap, NLM_F_CREATE)) < 0)
			return rv;
	}

	return 0;
}

static int
__ni_netdev_update_routes(ni_netdev_t *dev,
				const ni_addrconf_lease_t *old_lease,
				ni_route_t *cfg_route_list)
{
	ni_route_t *rp, *next;
	int rv = 0;

	/* Loop over all routes currently assigned to the interface.
	 * If the configuration no longer specifies it, delete it.
	 * We need to mimic the kernel's matching behavior when modifying
	 * the configuration of existing routes.
	 */
	for (rp = dev->routes; rp; rp = next) {
		ni_route_t *new_route;

		next = rp->next;

		/* See if the config list contains the route we've found in the
		 * system. */
		new_route = __ni_netdev_route_list_contains(cfg_route_list, rp);

		/* Do not touch route not managed by us. */
		if (rp->config_lease == NULL) {
			if (new_route == NULL)
				continue;

			/* Address was assigned to device, but we did not track it.
			 * Could be due to a daemon restart - simply assume this
			 * is ours now. */
			rp->config_lease = old_lease;
		}

		/* If the route was managed by us (ie its owned by a lease with
		 * the same family/addrconf mode), then we want to check whether
		 * it's owned by any other lease. It's possible that a route
		 * is configured through different protocols. */
		if (rp->config_lease == old_lease) {
			ni_addrconf_lease_t *other;

			if ((other = __ni_netdev_route_to_lease(dev, rp)) != NULL)
				rp->config_lease = other;
		}

		if (rp->config_lease != old_lease) {
			/* The existing route is managed by a different
			 * addrconf mode.
			 */
			if (new_route != NULL) {
				ni_warn("route %s covered by a %s lease",
					ni_route_print(rp),
					ni_addrconf_type_to_name(rp->config_lease->type));
			}
			continue;
		}

		if (new_route != NULL) {
			if (__ni_rtnl_send_newroute(dev, new_route, NLM_F_REPLACE) >= 0) {
				ni_debug_ifconfig("%s: successfully updated existing route %s",
						dev->name, ni_route_print(rp));
				new_route->seq = __ni_global_seqno;
				continue;
			}

			ni_error("%s: failed to update route %s", dev->name, ni_route_print(rp));
		}

		ni_debug_ifconfig("%s: trying to delete existing route %s",
				dev->name, ni_route_print(rp));
		if ((rv = __ni_rtnl_send_delroute(dev, rp)) < 0)
			return rv;
	}

	/* Loop over all addresses in the configuration and create
	 * those that don't exist yet.
	 */
	for (rp = cfg_route_list; rp; rp = rp->next) {
		if (rp->seq == __ni_global_seqno)
			continue;

		ni_debug_ifconfig("%s: adding new route %s", dev->name, ni_route_print(rp));
		if ((rv = __ni_rtnl_send_newroute(dev, rp, NLM_F_CREATE)) < 0)
			return rv;
	}

	return rv;
}

