/*
 * Handle network interface objects
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <signal.h>
#include <time.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/ethernet.h>
#include <wicked/wireless.h>
#include <wicked/vlan.h>
#include <wicked/openvpn.h>
#include <wicked/ppp.h>
#include <wicked/socket.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include <wicked/route.h>
#include <wicked/ibft.h>
#include "netinfo_priv.h"
#include "appconfig.h"

/*
 * Constructor for network interface.
 * Takes interface name and ifindex.
 */
ni_netdev_t *
__ni_netdev_new(const char *name, unsigned int index)
{
	ni_netdev_t *dev;

	dev = calloc(1, sizeof(*dev) * 2);
	if (!dev)
		return NULL;

	dev->users = 1;
	dev->link.type = NI_IFTYPE_UNKNOWN;
	dev->link.arp_type = ARPHRD_NONE;
	dev->link.hwaddr.type = ARPHRD_NONE;
	dev->link.ifindex = index;

	if (name)
		dev->name = xstrdup(name);

	/* Initialize address family specific info */
	__ni_afinfo_init(&dev->ipv4, AF_INET);
	__ni_afinfo_init(&dev->ipv6, AF_INET6);

	return dev;
}

ni_netdev_t *
ni_netdev_new(ni_netconfig_t *nc, const char *name, unsigned int index)
{
	ni_netdev_t *dev;

	dev = __ni_netdev_new(name, index);
	if (nc && dev)
		ni_netconfig_device_append(nc, dev);
	
	return dev;
}

/*
 * Destructor function (and assorted helpers)
 */
void
ni_netdev_clear_addresses(ni_netdev_t *dev)
{
	ni_address_list_destroy(&dev->addrs);
}

void
ni_netdev_clear_routes(ni_netdev_t *dev)
{
	ni_route_list_destroy(&dev->routes);
}

static void
ni_netdev_free(ni_netdev_t *dev)
{
	ni_string_free(&dev->name);
	ni_string_free(&dev->link.qdisc);
	ni_string_free(&dev->link.kind);
	ni_string_free(&dev->link.alias);

	/* Clear out addresses, stats */
	ni_netdev_clear_addresses(dev);
	ni_netdev_clear_routes(dev);
	ni_netdev_set_link_stats(dev, NULL);
	ni_netdev_set_ethernet(dev, NULL);
	ni_netdev_set_bonding(dev, NULL);
	ni_netdev_set_bridge(dev, NULL);
	ni_netdev_set_vlan(dev, NULL);
	ni_netdev_set_wireless(dev, NULL);
	ni_netdev_set_openvpn(dev, NULL);
	ni_netdev_set_ppp(dev, NULL);
	ni_netdev_set_ibft_nic(dev, NULL);

	ni_addrconf_lease_list_destroy(&dev->leases);

	free(dev);
}

/*
 * Reference counting of interface objects
 */
ni_netdev_t *
ni_netdev_get(ni_netdev_t *dev)
{
	if (!dev->users)
		return NULL;
	dev->users++;
	return dev;
}

int
ni_netdev_put(ni_netdev_t *dev)
{
	if (!dev->users) {
		ni_error("ni_netdev_put: bad mojo");
		return 0;
	}
	dev->users--;
	if (dev->users == 0) {
		ni_netdev_free(dev);
		return 0;
	}
	return dev->users;
}

/*
 * This is a convenience function for adding routes to an interface.
 */
ni_route_t *
ni_netdev_add_route(ni_netdev_t *dev,
				unsigned int prefix_len,
				const ni_sockaddr_t *dest,
				const ni_sockaddr_t *gw)
{
	return __ni_route_new(&dev->routes, prefix_len, dest, gw);
}

/*
 * Get the interface's VLAN information
 */
ni_vlan_t *
ni_netdev_get_vlan(ni_netdev_t *dev)
{
	if (!dev->link.vlan)
		dev->link.vlan = __ni_vlan_new();
	return dev->link.vlan;
}

void
ni_netdev_set_vlan(ni_netdev_t *dev, ni_vlan_t *vlan)
{
	if (dev->link.vlan)
		ni_vlan_free(dev->link.vlan);
	dev->link.vlan = vlan;
}

/*
 * Get the interface's bridge information
 */
ni_bridge_t *
ni_netdev_get_bridge(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_BRIDGE)
		return NULL;
	if (!dev->bridge)
		dev->bridge = ni_bridge_new();
	return dev->bridge;
}

void
ni_netdev_set_bridge(ni_netdev_t *dev, ni_bridge_t *bridge)
{
	if (dev->bridge)
		ni_bridge_free(dev->bridge);
	dev->bridge = bridge;
}

/*
 * Get the interface's bonding information
 */
ni_bonding_t *
ni_netdev_get_bonding(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_BOND)
		return NULL;
	if (!dev->bonding)
		dev->bonding = ni_bonding_new();
	return dev->bonding;
}

void
ni_netdev_set_bonding(ni_netdev_t *dev, ni_bonding_t *bonding)
{
	if (dev->bonding)
		ni_bonding_free(dev->bonding);
	dev->bonding = bonding;
}

/*
 * Get the interface's ethernet information
 */
ni_ethernet_t *
ni_netdev_get_ethernet(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_ETHERNET)
		return NULL;
	if (!dev->ethernet)
		dev->ethernet = calloc(1, sizeof(ni_ethernet_t));
	return dev->ethernet;
}

void
ni_netdev_set_ethernet(ni_netdev_t *dev, ni_ethernet_t *ethernet)
{
	if (dev->ethernet)
		ni_ethernet_free(dev->ethernet);
	dev->ethernet = ethernet;
}

/*
 * Set the interface's wireless info
 */
ni_wireless_t *
ni_netdev_get_wireless(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_WIRELESS)
		return NULL;
	if (!dev->wireless)
		dev->wireless = ni_wireless_new(dev);
	return dev->wireless;
}

void
ni_netdev_set_wireless(ni_netdev_t *dev, ni_wireless_t *wireless)
{
	if (dev->wireless)
		ni_wireless_free(dev->wireless);
	dev->wireless = wireless;
}

/*
 * Set the interface's openvpn info
 */
ni_openvpn_t *
ni_netdev_get_openvpn(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_TUN)
		return NULL;
	return dev->openvpn;
}

void
ni_netdev_set_openvpn(ni_netdev_t *dev, ni_openvpn_t *openvpn)
{
	if (dev->openvpn)
		ni_openvpn_free(dev->openvpn);
	dev->openvpn = openvpn;
}

/*
 * Set the interface's ppp info
 */
ni_ppp_t *
ni_netdev_get_ppp(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_PPP)
		return NULL;
	return dev->ppp;
}

void
ni_netdev_set_ppp(ni_netdev_t *dev, ni_ppp_t *ppp)
{
	if (dev->ppp)
		ni_ppp_free(dev->ppp);
	dev->ppp = ppp;
}

/*
 * Set the interface's link stats
 */
void
ni_netdev_set_link_stats(ni_netdev_t *dev, ni_link_stats_t *stats)
{
	if (dev->link.stats)
		free(dev->link.stats);
	dev->link.stats = stats;
}

/*
 * Set the interface's ibft nic info
 */
void
ni_netdev_set_ibft_nic(ni_netdev_t *dev, ni_ibft_nic_t *nic)
{
	if (nic)
		nic = ni_ibft_nic_ref(nic);
	if (dev->ibft_nic)
		ni_ibft_nic_free(dev->ibft_nic);

	dev->ibft_nic = nic;
}

/*
 * Locate any lease for the same addrconf mechanism
 */
ni_addrconf_lease_t *
__ni_netdev_find_lease(ni_netdev_t *dev, int family, ni_addrconf_mode_t type, int remove)
{
	ni_addrconf_lease_t *lease, **pos;

	for (pos = &dev->leases; (lease = *pos) != NULL; pos = &lease->next) {
		if (lease->type == type && lease->family == family) {
			if (remove) {
				*pos = lease->next;
				lease->next = NULL;
			}
			return lease;
		}
	}

	return NULL;
}

/*
 * We received an updated lease from an addrconf agent.
 */
int
ni_netdev_set_lease(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_addrconf_lease_t **pos;

	ni_netdev_unset_lease(dev, lease->family, lease->type);
	for (pos = &dev->leases; *pos != NULL; pos = &(*pos)->next)
		;

	*pos = lease;
	return 0;
}

int
ni_netdev_unset_lease(ni_netdev_t *dev, int family, ni_addrconf_mode_t type)
{
	ni_addrconf_lease_t *lease;

	if ((lease = __ni_netdev_find_lease(dev, family, type, 1)) != NULL)
		ni_addrconf_lease_free(lease);
	return 0;
}

ni_addrconf_lease_t *
ni_netdev_get_lease(ni_netdev_t *dev, int family, ni_addrconf_mode_t type)
{
	return __ni_netdev_find_lease(dev, family, type, 0);
}

ni_addrconf_lease_t *
ni_netdev_get_lease_by_owner(ni_netdev_t *dev, const char *owner)
{
	ni_addrconf_lease_t *lease;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (ni_string_eq(lease->owner, owner))
			return lease;
	}

	return NULL;
}

/*
 * Given an address, look up the lease owning it
 */
ni_addrconf_lease_t *
__ni_netdev_address_to_lease(ni_netdev_t *dev, const ni_address_t *ap)
{
	ni_addrconf_lease_t *lease;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (__ni_lease_owns_address(lease, ap))
			return lease;
	}

	return NULL;
}

int
__ni_lease_owns_address(const ni_addrconf_lease_t *lease, const ni_address_t *match)
{
	time_t now = time(NULL);
	ni_address_t *ap;

	if (!lease || lease->family != match->family)
		return 0;

	/* IPv6 autoconf is special; we record the IPv6 address prefixes in the
	 * lease. */
	if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_AUTOCONF) {
		ni_route_t *rp;

		for (rp = lease->routes; rp; rp = rp->next) {
			if (rp->prefixlen != match->prefixlen)
				continue;
			if (rp->expires && rp->expires <= now)
				continue;
			if (ni_address_prefix_match(rp->prefixlen, &rp->destination, &match->local_addr))
				return 1;
		}
	}

	for (ap = lease->addrs; ap; ap = ap->next) {
		if (ap->prefixlen != match->prefixlen)
			continue;
		if (ap->expires && ap->expires <= now)
			continue;

		/* Note: for IPv6 autoconf, we will usually have recorded the
		 * address prefix only; the address that will eventually be picked
		 * by the autoconf logic will be different */
		if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_AUTOCONF) {
			if (!ni_address_prefix_match(match->prefixlen, &ap->local_addr, &match->local_addr))
				continue;
		} else {
			if (ni_address_equal(&ap->local_addr, &match->local_addr))
				continue;
		}

		if (ni_address_equal(&ap->peer_addr, &match->peer_addr)
		 && ni_address_equal(&ap->anycast_addr, &match->anycast_addr))
			return 1;
	}
	return 0;
}

/*
 * Given a route, look up the lease owning it
 */
ni_addrconf_lease_t *
__ni_netdev_route_to_lease(ni_netdev_t *dev, const ni_route_t *rp)
{
	ni_addrconf_lease_t *lease;
	ni_address_t *ap;

	if (!dev || !rp)
		return NULL;

	for (lease = dev->leases; lease; lease = lease->next) {
		/* First, check if this is an interface route */
		for (ap = lease->addrs; ap; ap = ap->next) {
			if (rp->prefixlen == ap->prefixlen
			 && ni_address_prefix_match(ap->prefixlen, &rp->destination, &ap->local_addr))
				return lease;
		}

		if (__ni_lease_owns_route(lease, rp))
			return lease;
	}

	return NULL;
}

ni_route_t *
__ni_lease_owns_route(const ni_addrconf_lease_t *lease, const ni_route_t *rp)
{
	ni_route_t *own;

	if (!lease)
		return 0;

	for (own = lease->routes; own; own = own->next) {
		if (ni_route_equal(own, rp))
			return own;
	}
	return NULL;
}

/*
 * Guess the interface type based on its name and characteristics
 * We should really make this configurable!
 */
static ni_intmap_t __ifname_types[] = {
	{ "ib",		NI_IFTYPE_INFINIBAND	},
	{ "ip6tunl",	NI_IFTYPE_TUNNEL6	},
	{ "ipip",	NI_IFTYPE_TUNNEL	},
	{ "sit",	NI_IFTYPE_SIT		},
	{ "tun",	NI_IFTYPE_TUN		},

	{ NULL }
};
int
ni_netdev_guess_type(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_UNKNOWN)
		return dev->link.type;

	if (dev->name == NULL)
		return dev->link.type;

	dev->link.type = NI_IFTYPE_ETHERNET;
	if (!strcmp(dev->name, "lo")) {
		dev->link.type = NI_IFTYPE_LOOPBACK;
	} else {
		ni_intmap_t *map;

		for (map = __ifname_types; map->name; ++map) {
			unsigned int len = strlen(map->name);

			if (!strncmp(dev->name, map->name, len)
			 && isdigit(dev->name[len])) {
				dev->link.type = map->value;
				break;
			}
		}
	}

	return dev->link.type;
}

/*
 * Functions for handling lists of interfaces
 */
void
__ni_netdev_list_destroy(ni_netdev_t **list)
{
	ni_netdev_t *dev;

	while ((dev = *list) != NULL) {
		*list = dev->next;
		ni_netdev_put(dev);
	}
}

void
__ni_netdev_list_append(ni_netdev_t **list, ni_netdev_t *new_ifp)
{
	ni_netdev_t *dev;

	while ((dev = *list) != NULL)
		list = &dev->next;

	new_ifp->next = NULL;
	*list = new_ifp;
}

