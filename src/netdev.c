/*
 * Handle network interface objects
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <net/if_arp.h>
#include <netlink/netlink.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/ethernet.h>
#include <wicked/infiniband.h>
#include <wicked/wireless.h>
#include <wicked/vlan.h>
#include <wicked/macvlan.h>
#include <wicked/openvpn.h>
#include <wicked/ppp.h>
#include <wicked/tuntap.h>
#include <wicked/socket.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include <wicked/route.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/pci.h>
#include <wicked/lldp.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "appconfig.h"

/*
 * Constructor for network interface.
 * Takes interface name and ifindex.
 */
ni_netdev_t *
ni_netdev_new(const char *name, unsigned int index)
{
	ni_netdev_t *dev;

	dev = calloc(1, sizeof(*dev) * 2);
	if (!dev)
		return NULL;

	dev->users = 1;
	dev->link.type = NI_IFTYPE_UNKNOWN;
	dev->link.hwaddr.type = ARPHRD_VOID;
	dev->link.ifindex = index;

	if (name)
		dev->name = xstrdup(name);

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
	ni_route_tables_destroy(&dev->routes);
}

static void
ni_netdev_free(ni_netdev_t *dev)
{
	ni_string_free(&dev->name);
	ni_string_free(&dev->link.qdisc);
	ni_string_free(&dev->link.kind);
	ni_string_free(&dev->link.alias);
	ni_netdev_ref_destroy(&dev->link.lowerdev);
	ni_netdev_ref_destroy(&dev->link.masterdev);

	/* Clear out addresses, stats */
	ni_netdev_clear_addresses(dev);
	ni_netdev_clear_routes(dev);
	ni_netdev_set_link_stats(dev, NULL);
	ni_netdev_set_ethernet(dev, NULL);
	ni_netdev_set_infiniband(dev, NULL);
	ni_netdev_set_bonding(dev, NULL);
	ni_netdev_set_bridge(dev, NULL);
	ni_netdev_set_vlan(dev, NULL);
	ni_netdev_set_macvlan(dev, NULL);
	ni_netdev_set_wireless(dev, NULL);
	ni_netdev_set_openvpn(dev, NULL);
	ni_netdev_set_ppp(dev, NULL);
	ni_netdev_set_dcb(dev, NULL);
	ni_netdev_set_lldp(dev, NULL);
	ni_netdev_set_client_info(dev, NULL);
	ni_netdev_set_client_state(dev, NULL);

	ni_netdev_set_ipv4(dev, NULL);
	ni_netdev_set_ipv6(dev, NULL);

	ni_netdev_set_pci(dev, NULL);
	ni_netdev_clear_event_filters(dev);

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
 * This is a convenience function for adding addresses to an interface.
 */
ni_address_t *
ni_netdev_add_address(ni_netdev_t *dev, unsigned int af, unsigned int prefix_len, const ni_sockaddr_t *local_addr)
{
	return ni_address_new(af, prefix_len, local_addr, &dev->addrs);
}

/*
 * This is a convenience function for adding routes to an interface.
 */
ni_route_t *
ni_netdev_add_route(ni_netdev_t *dev,
				unsigned int prefix_len,
				const ni_sockaddr_t *dest,
				const ni_sockaddr_t *gw,
				unsigned int table)
{
	return ni_route_create(prefix_len, dest, gw, table, &dev->routes);
}

/*
 * Get the interface's VLAN information
 */
ni_vlan_t *
ni_netdev_get_vlan(ni_netdev_t *dev)
{
	if (!dev->vlan)
		dev->vlan = ni_vlan_new();
	return dev->vlan;
}

void
ni_netdev_set_vlan(ni_netdev_t *dev, ni_vlan_t *vlan)
{
	if (dev->vlan)
		ni_vlan_free(dev->vlan);
	dev->vlan = vlan;
}

/*
 * Get the interface's TUN/TAP information
 */
ni_tuntap_t *
ni_netdev_get_tuntap(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_TUN && dev->link.type != NI_IFTYPE_TAP)
		return NULL;

	if (!dev->tuntap)
		dev->tuntap = ni_tuntap_new();
	return dev->tuntap;
}

void
ni_netdev_set_tuntap(ni_netdev_t *dev, ni_tuntap_t *cfg)
{
	if (dev->tuntap)
		ni_tuntap_free(dev->tuntap);
	dev->tuntap = cfg;
}

/*
 * Get the interface's MACVLAN information
 */
ni_macvlan_t *
ni_netdev_get_macvlan(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_MACVLAN)
		return NULL;

	if (!dev->macvlan)
		dev->macvlan = ni_macvlan_new();
	return dev->macvlan;
}

void
ni_netdev_set_macvlan(ni_netdev_t *dev, ni_macvlan_t *macvlan)
{
	if (dev->macvlan)
		ni_macvlan_free(dev->macvlan);
	dev->macvlan = macvlan;
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
		dev->ethernet = ni_ethernet_new();
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
 * Get the interface's infiniband information
 */
ni_infiniband_t *
ni_netdev_get_infiniband(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_INFINIBAND &&
	    dev->link.type != NI_IFTYPE_INFINIBAND_CHILD)
		return NULL;
	if (!dev->infiniband)
		dev->infiniband = ni_infiniband_new();
	return dev->infiniband;
}

void
ni_netdev_set_infiniband(ni_netdev_t *dev, ni_infiniband_t *infiniband)
{
	if (dev->infiniband)
		ni_infiniband_free(dev->infiniband);
	dev->infiniband = infiniband;
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
 * Set the interface's ppp info
 */
ni_dcb_t *
ni_netdev_get_dcb(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_ETHERNET)
		return NULL;
	return dev->dcb;
}

void
ni_netdev_set_dcb(ni_netdev_t *dev, ni_dcb_t *dcb)
{
	if (dev->dcb)
		ni_dcb_free(dev->dcb);
	dev->dcb = dcb;
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
 * Set the PCI device info
 */
void
ni_netdev_set_pci(ni_netdev_t *dev, ni_pci_dev_t *pci_dev)
{
	if (dev->pci_dev)
		ni_pci_dev_free(dev->pci_dev);
	dev->pci_dev = pci_dev;
}

/*
 * Set the interface's client_info.
 * This information is not intepreted by the server at all, but
 * we retain it for the client.
 */
void
ni_netdev_set_client_info(ni_netdev_t *dev, ni_device_clientinfo_t *client_info)
{
	if (dev->client_info == client_info)
		return;
	if (dev->client_info)
		ni_device_clientinfo_free(dev->client_info);

	dev->client_info = client_info;
}

ni_device_clientinfo_t *
ni_netdev_get_client_info(ni_netdev_t *dev)
{
	return dev ? dev->client_info : NULL;
}

ni_device_clientinfo_t *
ni_device_clientinfo_new(void)
{
	ni_device_clientinfo_t *client_info;

	client_info = xcalloc(1, sizeof(*client_info));
	return client_info;
}

void
ni_device_clientinfo_free(ni_device_clientinfo_t *client_info)
{
	ni_string_free(&client_info->state);
	ni_string_free(&client_info->config_origin);
	free(client_info);
}

/*
 * Set the interface's client_state structure.
 * This information is not intepreted by the server at all, but
 * we retain it for the client.
 */
void
ni_netdev_set_client_state(ni_netdev_t *dev, ni_client_state_t *client_state)
{
	if (dev->client_state == client_state)
		return;
	if (dev->client_state)
		ni_client_state_free(dev->client_state);

	dev->client_state = client_state;
}

ni_client_state_t *
ni_netdev_get_client_state(ni_netdev_t *dev)
{
	return dev ? dev->client_state : NULL;
}

void
ni_netdev_load_client_state(ni_netdev_t *dev)
{
	ni_client_state_t client_state;

	if (!ni_netdev_get_client_state(dev)) {
		ni_client_state_init(&client_state);
		if (ni_client_state_load(&client_state, dev->link.ifindex)) {
			ni_netdev_set_client_state(dev, ni_client_state_clone(&client_state));
			ni_debug_ifconfig("loading client-state structure from a file for %s",
				dev->name);
		}
	}
}

/*
 * Set the interface's lldp info
 */
ni_lldp_t *
ni_netdev_get_lldp(ni_netdev_t *dev)
{
	if (!dev->lldp)
		dev->lldp = ni_lldp_new();
	return dev->lldp;
}

void
ni_netdev_set_lldp(ni_netdev_t *dev, ni_lldp_t *lldp)
{
	ni_lldp_free(dev->lldp);
	dev->lldp = lldp;
}

/*
 * Handle event filters
 */
static ni_event_filter_t *
__ni_event_filter_new(unsigned int mask)
{
	ni_event_filter_t *efp;

	efp = xcalloc(1, sizeof(*efp));
	ni_uuid_generate(&efp->uuid);
	efp->event_mask = mask;

	return efp;
}

static void
__ni_event_filter_free(ni_event_filter_t *efp)
{
	free(efp);
}

void
ni_netdev_clear_event_filters(ni_netdev_t *dev)
{
	ni_event_filter_t *efp;

	while ((efp = dev->event_filter) != NULL) {
		dev->event_filter = efp->next;
		__ni_event_filter_free(efp);
	}
}

const ni_uuid_t *
ni_netdev_add_event_filter(ni_netdev_t *dev, unsigned int mask)
{
	ni_event_filter_t *efp = __ni_event_filter_new(mask);

	efp->next = dev->event_filter;
	dev->event_filter = efp;

	return &efp->uuid;
}

const ni_uuid_t *
ni_netdev_get_event_uuid(ni_netdev_t *dev, ni_event_t ev)
{
	ni_event_filter_t **pos, *efp;

	for (pos = &dev->event_filter; (efp = *pos) != NULL; pos = &efp->next) {
		if (efp->event_mask & (1 << ev)) {
			static ni_uuid_t ret_uuid;
			
			ret_uuid = efp->uuid;
			*pos = efp->next;
			__ni_event_filter_free(efp);
			return &ret_uuid;
		}
	}

	return NULL;
}

/*
 * Locate any lease for the same addrconf mechanism
 */
ni_addrconf_lease_t *
__ni_netdev_find_lease(ni_netdev_t *dev, unsigned int family, ni_addrconf_mode_t type, int remove)
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
ni_netdev_unset_lease(ni_netdev_t *dev, unsigned int family, ni_addrconf_mode_t type)
{
	ni_addrconf_lease_t *lease;

	if ((lease = __ni_netdev_find_lease(dev, family, type, 1)) != NULL)
		ni_addrconf_lease_free(lease);
	return 0;
}

ni_addrconf_lease_t *
ni_netdev_get_lease(ni_netdev_t *dev, unsigned int family, ni_addrconf_mode_t type)
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

ni_bool_t
__ni_lease_owns_address(const ni_addrconf_lease_t *lease, const ni_address_t *match)
{
	ni_address_t *ap;

	if (!lease || lease->family != match->family)
		return 0;

	/* IPv6 autoconf is special; we record the IPv6 address prefixes in the
	 * lease. */
	if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_AUTOCONF) {
		ni_route_table_t *tab;
		ni_route_t *rp;
		unsigned int i;

		tab = ni_route_tables_find(lease->routes, RT_TABLE_MAIN);
		for (i = 0; tab && i < tab->routes.count; ++i) {
			rp = tab->routes.data[i];

			if (rp->prefixlen != match->prefixlen)
				continue;
			if (ni_sockaddr_prefix_match(rp->prefixlen, &rp->destination, &match->local_addr))
				return TRUE;
		}
	}

	for (ap = lease->addrs; ap; ap = ap->next) {
		if (ap->prefixlen != match->prefixlen)
			continue;

		/* Note: for IPv6 autoconf, we will usually have recorded the
		 * address prefix only; the address that will eventually be picked
		 * by the autoconf logic will be different */
		if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_AUTOCONF) {
			if (!ni_sockaddr_prefix_match(match->prefixlen, &ap->local_addr, &match->local_addr))
				continue;
		} else {
			if (!ni_sockaddr_equal(&ap->local_addr, &match->local_addr))
				continue;
		}

		if (ni_sockaddr_equal(&ap->peer_addr, &match->peer_addr)
		 && ni_sockaddr_equal(&ap->anycast_addr, &match->anycast_addr))
			return TRUE;
	}
	return FALSE;
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
			 && ni_sockaddr_prefix_match(ap->prefixlen, &rp->destination, &ap->local_addr))
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
	ni_route_table_t *tab;
	ni_route_t *own;
	unsigned int i;

	if (!lease)
		return 0;

	if ((tab = ni_route_tables_find(lease->routes, rp->table))) {
		for (i = 0; i < tab->routes.count; ++i) {
			own = tab->routes.data[i];
			if (own && ni_route_equal(own, rp))
				return own;
		}
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
	{ "tap",	NI_IFTYPE_TAP		},

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

