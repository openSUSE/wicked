/*
 * Handle network interface objects
 *
 * Copyright (C) 2009-2011 Olaf Kirch <okir@suse.de>
 */
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
#include <wicked/socket.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include "netinfo_priv.h"
#include "config.h"

/*
 * Constructor for network interface.
 * Takes interface name and ifindex.
 */
ni_interface_t *
__ni_interface_new(const char *name, unsigned int index)
{
	ni_interface_t *ifp;

	ifp = calloc(1, sizeof(*ifp) * 2);
	if (!ifp)
		return NULL;

	ifp->users = 1;
	ifp->startmode.ifaction[NI_IFACTION_BOOT].action = NI_INTERFACE_START;
	ifp->startmode.ifaction[NI_IFACTION_BOOT].mandatory = 1;
	ifp->startmode.ifaction[NI_IFACTION_BOOT].wait = 30;
	ifp->startmode.ifaction[NI_IFACTION_SHUTDOWN].action = NI_INTERFACE_STOP;
	ifp->startmode.ifaction[NI_IFACTION_MANUAL_UP].action = NI_INTERFACE_START;
	ifp->startmode.ifaction[NI_IFACTION_MANUAL_UP].mandatory = 1;
	ifp->startmode.ifaction[NI_IFACTION_MANUAL_UP].wait = 30;
	ifp->startmode.ifaction[NI_IFACTION_MANUAL_DOWN].action = NI_INTERFACE_STOP;
	ifp->link.type = NI_IFTYPE_UNKNOWN;
	ifp->link.arp_type = ARPHRD_NONE;
	ifp->link.hwaddr.type = ARPHRD_NONE;
	ifp->link.ifindex = index;

	if (name)
		ifp->name = xstrdup(name);

	/* Initialize address family specific info */
	__ni_afinfo_init(&ifp->ipv4, AF_INET);
	__ni_afinfo_init(&ifp->ipv6, AF_INET6);

	return ifp;
}

ni_interface_t *
ni_interface_new(ni_netconfig_t *nc, const char *name, unsigned int index)
{
	ni_interface_t *ifp;

	ifp = __ni_interface_new(name, index);
	if (nc && ifp)
		__ni_interface_list_append(&nc->interfaces, ifp);
	
	return ifp;
}

ni_interface_t *
ni_interface_clone(const ni_interface_t *ofp)
{
	ni_interface_t *ifp;

	ifp = __ni_interface_new(ofp->name, ofp->link.ifindex);
	if (!ifp)
		goto failed;

#define C(member)	ifp->member = ofp->member
#define D(member, clone_fn)	\
		do { \
			if (ofp->member) { \
				ifp->member = clone_fn(ofp->member); \
				if (!ifp->member) \
					goto failed; \
			} \
		} while (0)
	C(link.ifflags);
	C(link.type);
	C(link.arp_type);
	C(link.hwaddr);
	/* FIXME: clone routes, addrs */
	C(link.mtu);
	C(link.metric);
	C(link.txqlen);
	C(link.master);
	D(link.qdisc, xstrdup);
	D(link.kind, xstrdup);
	D(link.vlan, ni_vlan_clone);
	C(ipv4.enabled);
	C(ipv4.forwarding);
	C(ipv4.addrconf);
	C(ipv6.enabled);
	C(ipv6.forwarding);
	C(ipv6.addrconf);
	D(addrs, __ni_address_list_clone);
	D(routes, __ni_route_list_clone);
	D(bonding, ni_bonding_clone);
	D(bridge, ni_bridge_clone);
	D(ethernet, ni_ethernet_clone);
	C(startmode);
#undef C
#undef D

	return ifp;

failed:
	ni_error("Failed to clone interface data for interface %s", ofp->name);
	if (ifp)
		ni_interface_put(ifp);
	return NULL;
}

/*
 * Destructor function (and assorted helpers)
 */
void
ni_interface_clear_addresses(ni_interface_t *ifp)
{
	ni_address_list_destroy(&ifp->addrs);
}

void
ni_interface_clear_routes(ni_interface_t *ifp)
{
	ni_route_list_destroy(&ifp->routes);
}

static void
ni_interface_free(ni_interface_t *ifp)
{
	ni_string_free(&ifp->name);
	ni_string_free(&ifp->link.qdisc);
	ni_string_free(&ifp->link.kind);

	/* Clear out addresses, stats */
	ni_interface_clear_addresses(ifp);
	ni_interface_clear_routes(ifp);
	ni_interface_set_link_stats(ifp, NULL);
	ni_interface_set_ethernet(ifp, NULL);
	ni_interface_set_bonding(ifp, NULL);
	ni_interface_set_bridge(ifp, NULL);
	ni_interface_set_vlan(ifp, NULL);
	ni_interface_set_wireless(ifp, NULL);
	ni_interface_set_wireless_scan(ifp, NULL);

	__ni_afinfo_destroy(&ifp->ipv4);
	__ni_afinfo_destroy(&ifp->ipv6);

	ni_addrconf_lease_list_destroy(&ifp->leases);

	free(ifp);
}

/*
 * Reference counting of interface objects
 */
ni_interface_t *
ni_interface_get(ni_interface_t *ifp)
{
	if (!ifp->users)
		return NULL;
	ifp->users++;
	return ifp;
}

int
ni_interface_put(ni_interface_t *ifp)
{
	if (!ifp->users) {
		ni_error("ni_interface_put: bad mojo");
		return 0;
	}
	ifp->users--;
	if (ifp->users == 0) {
		ni_interface_free(ifp);
		return 0;
	}
	return ifp->users;
}

/*
 * This is a convenience function for adding routes to an interface.
 */
ni_route_t *
ni_interface_add_route(ni_interface_t *ifp,
				unsigned int prefix_len,
				const ni_sockaddr_t *dest,
				const ni_sockaddr_t *gw)
{
	return __ni_route_new(&ifp->routes, prefix_len, dest, gw);
}

/*
 * Get the interface's VLAN information
 */
ni_vlan_t *
ni_interface_get_vlan(ni_interface_t *ifp)
{
	if (!ifp->link.vlan)
		ifp->link.vlan = __ni_vlan_new();
	return ifp->link.vlan;
}

void
ni_interface_set_vlan(ni_interface_t *ifp, ni_vlan_t *vlan)
{
	if (ifp->link.vlan)
		ni_vlan_free(ifp->link.vlan);
	ifp->link.vlan = vlan;
}

/*
 * Get the interface's bridge information
 */
ni_bridge_t *
ni_interface_get_bridge(ni_interface_t *ifp)
{
	if (!ifp->bridge)
		ifp->bridge = ni_bridge_new();
	return ifp->bridge;
}

void
ni_interface_set_bridge(ni_interface_t *ifp, ni_bridge_t *bridge)
{
	if (ifp->bridge)
		ni_bridge_free(ifp->bridge);
	ifp->bridge = bridge;
}

/*
 * Get the interface's bonding information
 */
ni_bonding_t *
ni_interface_get_bonding(ni_interface_t *ifp)
{
	if (!ifp->bonding)
		ifp->bonding = ni_bonding_new();
	return ifp->bonding;
}

void
ni_interface_set_bonding(ni_interface_t *ifp, ni_bonding_t *bonding)
{
	if (ifp->bonding)
		ni_bonding_free(ifp->bonding);
	ifp->bonding = bonding;
}

/*
 * Get the interface's ethernet information
 */
ni_ethernet_t *
ni_interface_get_ethernet(ni_interface_t *ifp)
{
	if (!ifp->ethernet)
		ifp->ethernet = calloc(1, sizeof(ni_ethernet_t));
	return ifp->ethernet;
}

void
ni_interface_set_ethernet(ni_interface_t *ifp, ni_ethernet_t *ethernet)
{
	if (ifp->ethernet)
		ni_ethernet_free(ifp->ethernet);
	ifp->ethernet = ethernet;
}

/*
 * Set the interface's wireless info
 */
void
ni_interface_set_wireless(ni_interface_t *ifp, ni_wireless_t *wireless)
{
	if (ifp->wireless)
		ni_wireless_free(ifp->wireless);
	ifp->wireless = wireless;
}

void
ni_interface_set_wireless_scan(ni_interface_t *ifp, ni_wireless_scan_t *scan)
{
	if (ifp->wireless_scan)
		ni_wireless_scan_free(ifp->wireless_scan);
	ifp->wireless_scan = scan;
}

/*
 * Set the interface's link stats
 */
void
ni_interface_set_link_stats(ni_interface_t *ifp, ni_link_stats_t *stats)
{
	if (ifp->link.stats)
		free(ifp->link.stats);
	ifp->link.stats = stats;
}

int
ni_interface_set_addrconf_request(ni_interface_t *dev, ni_addrconf_request_t *req)
{
	ni_assert(req->owner);
	req->next = dev->addrconf;
	dev->addrconf = req;
	return 0;
}

ni_addrconf_request_t *
ni_interface_get_addrconf_request(ni_interface_t *dev, const ni_uuid_t *uuid)
{
	ni_addrconf_request_t **pos, *req;

	if (!uuid) {
		ni_error("%s: NULL uuid?!", __func__);
		return NULL;
	}
	for (pos = &dev->addrconf; (req = *pos) != NULL; pos = &req->next) {
		if (ni_uuid_equal(&req->uuid, uuid)) {
			*pos = req->next;
			return req;
		}
	}
	return NULL;
}

/*
 * Locate any lease for the same addrconf mechanism
 */
static ni_addrconf_lease_t *
__ni_interface_find_lease(ni_interface_t *ifp, int family, ni_addrconf_mode_t type, int remove)
{
	ni_addrconf_lease_t *lease, **pos;

	for (pos = &ifp->leases; (lease = *pos) != NULL; pos = &lease->next) {
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
ni_interface_set_lease(ni_interface_t *ifp, ni_addrconf_lease_t *lease)
{
	ni_addrconf_lease_t **pos;

	ni_interface_unset_lease(ifp, lease->family, lease->type);
	for (pos = &ifp->leases; *pos != NULL; pos = &(*pos)->next)
		;

	*pos = lease;
	return 0;
}

int
ni_interface_unset_lease(ni_interface_t *ifp, int family, ni_addrconf_mode_t type)
{
	ni_addrconf_lease_t *lease;

	if ((lease = __ni_interface_find_lease(ifp, family, type, 1)) != NULL)
		ni_addrconf_lease_free(lease);
	return 0;
}

ni_addrconf_lease_t *
ni_interface_get_lease(ni_interface_t *dev, int family, ni_addrconf_mode_t type)
{
	return __ni_interface_find_lease(dev, family, type, 0);
}

/*
 * Given an address, look up the lease owning it
 */
ni_addrconf_lease_t *
__ni_interface_address_to_lease(ni_interface_t *ifp, const ni_address_t *ap)
{
	ni_addrconf_lease_t *lease;

	for (lease = ifp->leases; lease; lease = lease->next) {
		if (__ni_lease_owns_address(lease, ap))
			return lease;
	}

	return NULL;
}

ni_address_t *
__ni_lease_owns_address(const ni_addrconf_lease_t *lease, const ni_address_t *ap)
{
	time_t now = time(NULL);
	ni_address_t *own;

	if (!lease)
		return 0;
	for (own = lease->addrs; own; own = own->next) {
		if (own->prefixlen != ap->prefixlen)
			continue;
		if (own->expires && own->expires <= now)
			continue;

		/* Note: for IPv6 autoconf, we will usually have recorded the
		 * address prefix only; the address that will eventually be picked
		 * by the autoconf logic will be different */
		if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_AUTOCONF) {
			if (!ni_address_prefix_match(ap->prefixlen, &own->local_addr, &ap->local_addr))
				continue;
		} else {
			if (ni_address_equal(&own->local_addr, &ap->local_addr))
				continue;
		}

		if (ni_address_equal(&own->peer_addr, &ap->peer_addr)
		 && ni_address_equal(&own->anycast_addr, &ap->anycast_addr))
			return own;
	}
	return NULL;
}

/*
 * Given a route, look up the lease owning it
 */
ni_addrconf_lease_t *
__ni_interface_route_to_lease(ni_interface_t *ifp, const ni_route_t *rp)
{
	ni_addrconf_lease_t *lease;
	ni_address_t *ap;

	if (!ifp || !rp)
		return NULL;

	for (lease = ifp->leases; lease; lease = lease->next) {
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
 * Check whether an interface is up.
 * To be up, it needs to have all *UP flag set, and must have acquired
 * all the requested leases.
 * FIXME: OBSOLETE
 */
int
__ni_interface_is_up(const ni_interface_t *ifp)
{
	unsigned int upflags = NI_IFF_NETWORK_UP | NI_IFF_LINK_UP | NI_IFF_DEVICE_UP;

	if ((ifp->link.ifflags ^ upflags) & upflags) {
		ni_debug_ifconfig("%s: not all layers are up", ifp->name);
		return 0;
	}

	return 1;
}

/*
 * Check whether an interface is down.
 * To be down, it needs to have at least the NETWORK_UP flag cleared.
 */
int
__ni_interface_is_down(const ni_interface_t *ifp)
{
	if (ifp->link.ifflags & NI_IFF_NETWORK_UP) {
		ni_debug_ifconfig("%s: network layer is still up", ifp->name);
		return 0;
	}

	return 1;
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
ni_interface_guess_type(ni_interface_t *ifp)
{
	if (ifp->link.type != NI_IFTYPE_UNKNOWN)
		return ifp->link.type;

	if (ifp->name == NULL)
		return ifp->link.type;

	ifp->link.type = NI_IFTYPE_ETHERNET;
	if (!strcmp(ifp->name, "lo")) {
		ifp->link.type = NI_IFTYPE_LOOPBACK;
	} else {
		ni_intmap_t *map;

		for (map = __ifname_types; map->name; ++map) {
			unsigned int len = strlen(map->name);

			if (!strncmp(ifp->name, map->name, len)
			 && isdigit(ifp->name[len])) {
				ifp->link.type = map->value;
				break;
			}
		}
	}

	return ifp->link.type;
}

/*
 * Functions for handling arrays of interfaces
 */
void
ni_interface_array_init(ni_interface_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_interface_array_append(ni_interface_array_t *array, ni_interface_t *ifp)
{
	if ((array->count & 15) == 0) {
		array->data = realloc(array->data, (array->count + 16) * sizeof(ni_interface_t *));
		assert(array->data);
	}
	array->data[array->count++] = ifp;
}

int
ni_interface_array_index(const ni_interface_array_t *array, const ni_interface_t *ifp)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		if (array->data[i] == ifp)
			return i;
	}
	return -1;
}

void
ni_interface_array_destroy(ni_interface_array_t *array)
{
	free(array->data);
	memset(array, 0, sizeof(*array));
}

/*
 * Functions for handling lists of interfaces
 */
void
__ni_interface_list_destroy(ni_interface_t **list)
{
	ni_interface_t *ifp;

	while ((ifp = *list) != NULL) {
		*list = ifp->next;
		ni_interface_put(ifp);
	}
}

void
__ni_interface_list_append(ni_interface_t **list, ni_interface_t *new_ifp)
{
	ni_interface_t *ifp;

	while ((ifp = *list) != NULL)
		list = &ifp->next;

	new_ifp->next = NULL;
	*list = new_ifp;
}

