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
#include <wicked/team.h>
#include <wicked/ovs.h>
#include <wicked/ethernet.h>
#include <wicked/infiniband.h>
#include <wicked/wireless.h>
#include <wicked/vlan.h>
#include <wicked/vxlan.h>
#include <wicked/macvlan.h>
#include <wicked/openvpn.h>
#include <wicked/ppp.h>
#include <wicked/tuntap.h>
#include <wicked/tunneling.h>
#include <wicked/socket.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include <wicked/route.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/pci.h>
#include <wicked/lldp.h>
#include <wicked/fsm.h>
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

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->users = 1;
	dev->link.type = NI_IFTYPE_UNKNOWN;
	dev->link.hwaddr.type = ARPHRD_VOID;
	dev->link.hwpeer.type = ARPHRD_VOID;
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

void
ni_netdev_slaveinfo_destroy(ni_slaveinfo_t *slave)
{
	switch (slave->type) {
	case NI_IFTYPE_BOND:
		ni_bonding_slave_info_free(slave->bond);
		break;
	default:
		break;
	}
	free(slave->kind);
	memset(slave, 0, sizeof(*slave));
}

static void
ni_netdev_free(ni_netdev_t *dev)
{
	/* Clear out linkinfo */
	ni_string_free(&dev->link.qdisc);
	ni_string_free(&dev->link.kind);
	ni_string_free(&dev->link.alias);
	ni_netdev_ref_destroy(&dev->link.lowerdev);
	ni_netdev_ref_destroy(&dev->link.masterdev);
	ni_netdev_slaveinfo_destroy(&dev->link.slave);
	ni_netdev_set_link_stats(dev, NULL);

	/* Clear out addresses, routes, ... */
	ni_netdev_clear_addresses(dev);
	ni_netdev_clear_routes(dev);
	ni_netdev_set_ethernet(dev, NULL);
	ni_netdev_set_infiniband(dev, NULL);
	ni_netdev_set_bonding(dev, NULL);
	ni_netdev_set_team(dev, NULL);
	ni_netdev_set_bridge(dev, NULL);
	ni_netdev_set_ovs_bridge(dev, NULL);
	ni_netdev_set_vlan(dev, NULL);
	ni_netdev_set_vxlan(dev, NULL);
	ni_netdev_set_macvlan(dev, NULL);
	ni_netdev_set_ipip(dev, NULL);
	ni_netdev_set_sit(dev, NULL);
	ni_netdev_set_gre(dev, NULL);
	ni_netdev_set_wireless(dev, NULL);
	ni_netdev_set_openvpn(dev, NULL);
	ni_netdev_set_ppp(dev, NULL);
	ni_netdev_set_dcb(dev, NULL);
	ni_netdev_set_lldp(dev, NULL);
	ni_netdev_set_client_state(dev, NULL);

	ni_netdev_set_ipv4(dev, NULL);
	ni_netdev_set_ipv6(dev, NULL);
	ni_netdev_set_auto6(dev, NULL);

	ni_netdev_set_pci(dev, NULL);
	ni_netdev_set_ethtool(dev, NULL);
	ni_netdev_clear_event_filters(dev);

	ni_addrconf_lease_list_destroy(&dev->leases);

	ni_string_free(&dev->name);
	free(dev);
}

/*
 * Reference counting of interface objects
 */
ni_netdev_t *
ni_netdev_get(ni_netdev_t *dev)
{
	if (dev) {
		ni_assert(dev->users);
		dev->users++;
	}
	return dev;
}

unsigned int
ni_netdev_put(ni_netdev_t *dev)
{
	if (dev) {
		ni_assert(dev->users);
		dev->users--;

		if (dev->users == 0)
			ni_netdev_free(dev);
		else
			return dev->users;
	}
	return 0;
}

ni_bool_t
ni_netdev_link_always_ready(ni_linkinfo_t *link)
{
	switch (link->type) {
	case NI_IFTYPE_LOOPBACK:
		return TRUE;
	default:
		if (ni_server_disabled_uevents())
			return TRUE;
		return FALSE;
	}
}
ni_bool_t
ni_netdev_device_always_ready(ni_netdev_t *dev)
{
	return dev ? ni_netdev_link_always_ready(&dev->link) : FALSE;
}

ni_bool_t
ni_netdev_device_is_ready(ni_netdev_t *dev)
{
	return dev ? dev->link.ifflags & NI_IFF_DEVICE_READY : FALSE;
}

ni_tristate_t
ni_netdev_guess_link_required(const ni_netdev_t *dev)
{
	ni_tristate_t link_required = NI_TRISTATE_DEFAULT;

	switch (dev->link.type) {
	case NI_IFTYPE_OVS_SYSTEM:
	case NI_IFTYPE_TUN:
	case NI_IFTYPE_TAP:
		ni_tristate_set(&link_required, FALSE);
		break;

	case NI_IFTYPE_BRIDGE:
		if (dev->bridge && dev->bridge->stp && !dev->bridge->ports.count)
			ni_tristate_set(&link_required, FALSE);
		break;

	default:
		break;
	}
	return link_required;
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
 * Get the interface's VXLAN information
 */
ni_vxlan_t *
ni_netdev_get_vxlan(ni_netdev_t *dev)
{
	if (!dev->vxlan)
		dev->vxlan = ni_vxlan_new();
	return dev->vxlan;
}

void
ni_netdev_set_vxlan(ni_netdev_t *dev, ni_vxlan_t *vxlan)
{
	if (dev->vxlan)
		ni_vxlan_free(dev->vxlan);
	dev->vxlan = vxlan;
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
 * Get sit tunnel data.
 */
ni_sit_t *
ni_netdev_get_sit(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_SIT)
		return NULL;

	if (!dev->sit)
		dev->sit = ni_sit_new();

	return dev->sit;
}

/*
 * Get ipip tunnel data.
 */
ni_ipip_t *
ni_netdev_get_ipip(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_IPIP)
		return NULL;

	if (!dev->ipip)
		dev->ipip = ni_ipip_new();

	return dev->ipip;
}

/*
 * Get gre tunnel data.
 */
ni_gre_t *
ni_netdev_get_gre(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_GRE)
		return NULL;

	if (!dev->gre)
		dev->gre = ni_gre_new();

	return dev->gre;
}

void
ni_netdev_set_sit(ni_netdev_t *dev, ni_sit_t *sit)
{
	if (dev->sit)
		ni_sit_free(dev->sit);

	dev->sit = sit;
}

void
ni_netdev_set_ipip(ni_netdev_t *dev, ni_ipip_t *ipip)
{
	if (dev->ipip)
		ni_ipip_free(dev->ipip);

	dev->ipip = ipip;
}


void
ni_netdev_set_gre(ni_netdev_t *dev, ni_gre_t *gre)
{
	if (dev->gre)
		ni_gre_free(dev->gre);

	dev->gre = gre;
}

/*
 * Get the interface's MACVLAN information
 */
ni_macvlan_t *
ni_netdev_get_macvlan(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_MACVLAN &&
		dev->link.type != NI_IFTYPE_MACVTAP)
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
 * Get the interface's ovs bridge information
 */
ni_ovs_bridge_t *
ni_netdev_get_ovs_bridge(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_OVS_BRIDGE)
		return NULL;
	if (!dev->ovsbr)
		dev->ovsbr = ni_ovs_bridge_new();
	return dev->ovsbr;
}

void
ni_netdev_set_ovs_bridge(ni_netdev_t *dev, ni_ovs_bridge_t *ovsbr)
{
	if (dev->ovsbr)
		ni_ovs_bridge_free(dev->ovsbr);
	dev->ovsbr = ovsbr;
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
 * Get team interface information
 */
ni_team_t *
ni_netdev_get_team(ni_netdev_t *dev)
{
	if (dev->link.type != NI_IFTYPE_TEAM)
		return NULL;
	if (!dev->team)
		dev->team = ni_team_new();
	return dev->team;
}

void
ni_netdev_set_team(ni_netdev_t *dev, ni_team_t *team)
{
	ni_team_free(dev->team);
	dev->team = team;
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
	if (!dev->ppp)
		dev->ppp = ni_ppp_new();
	return dev->ppp;
}

void
ni_netdev_set_ppp(ni_netdev_t *dev, ni_ppp_t *ppp)
{
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
	if (!dev)
		return NULL;

	if (!dev->client_state)
		dev->client_state = ni_client_state_new(0);

	return dev->client_state;
}

ni_bool_t
ni_netdev_load_client_state(ni_netdev_t *dev)
{
	ni_client_state_t cs;

	ni_client_state_init(&cs);
	if (dev && ni_client_state_load(&cs, dev->link.ifindex)) {
		ni_netdev_set_client_state(dev, ni_client_state_clone(&cs));
		ni_debug_ifconfig("loading %s structure from a file for %s",
			NI_CLIENT_STATE_XML_NODE, dev->name);
		return TRUE;
	}

	return FALSE;
}

void
ni_netdev_discover_client_state(ni_netdev_t *dev)
{
	ni_fsm_state_t state = NI_FSM_STATE_DEVICE_EXISTS;
	ni_client_state_t *cs;

	if (!dev)
		return;

	if (ni_netdev_device_is_up(dev))
		state = NI_FSM_STATE_DEVICE_UP;
	if (ni_netdev_link_is_up(dev))
		state = NI_FSM_STATE_LINK_UP;
	if (ni_netdev_network_is_up(dev))
		state = NI_FSM_STATE_LINK_UP;

	cs = ni_client_state_new(state);

	ni_netdev_set_client_state(dev, cs);
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
ni_netdev_get_lease_by_uuid(ni_netdev_t *dev, const ni_uuid_t *uuid)
{
	ni_addrconf_lease_t *lease;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (ni_uuid_equal(&lease->uuid, uuid))
			return lease;
	}
	return NULL;
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
__ni_netdev_address_to_lease(ni_netdev_t *dev, const ni_address_t *ap, unsigned int minprio)
{
	ni_addrconf_lease_t *lease;
	ni_addrconf_lease_t *found = NULL;
	unsigned int prio;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (ap->family != lease->family)
			continue;

		if ((prio = ni_addrconf_lease_get_priority(lease)) < minprio)
			continue;

		if (!__ni_lease_owns_address(lease, ap))
			continue;

		if (!found || prio > ni_addrconf_lease_get_priority(found))
			found = lease;
	}

	return found;
}

ni_bool_t
__ni_lease_owns_address(const ni_addrconf_lease_t *lease, const ni_address_t *match)
{
	ni_address_t *ap;

	if (!lease || lease->family != match->family)
		return 0;

	for (ap = lease->addrs; ap; ap = ap->next) {
		if (ap->prefixlen != match->prefixlen)
			continue;

		if (!ni_sockaddr_equal(&ap->local_addr, &match->local_addr))
				continue;

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
__ni_netdev_route_to_lease(ni_netdev_t *dev, const ni_route_t *rp, unsigned int minprio)
{
	ni_addrconf_lease_t *lease;
	ni_addrconf_lease_t *found = NULL;
	ni_address_t *ap;
	unsigned int prio;

	if (!dev || !rp)
		return NULL;

	for (lease = dev->leases; lease; lease = lease->next) {
		if (rp->family != lease->family)
			continue;

		if ((prio = ni_addrconf_lease_get_priority(lease)) < minprio)
			continue;

		/* First, check if this is an interface route */
		for (ap = lease->addrs; ap; ap = ap->next) {
			if (ni_sockaddr_is_specified(&rp->nh.gateway))
				continue;
			if (rp->prefixlen != ap->prefixlen)
				continue;
			if (!ni_sockaddr_prefix_match(ap->prefixlen,
				&rp->destination, &ap->local_addr))
				continue;

			if (!found || prio > ni_addrconf_lease_get_priority(found))
				found = lease;
		}

		if (__ni_lease_owns_route(lease, rp)) {
			if (!found || prio > ni_addrconf_lease_get_priority(found))
				found = lease;
		}
	}

	return found;
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
	{ "ipip",	NI_IFTYPE_IPIP		},
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

ni_bool_t
ni_netdev_supports_arp(ni_netdev_t *dev)
{
	if (dev) {
		switch (dev->link.hwaddr.type) {
		case ARPHRD_LOOPBACK:
			return FALSE;
		default:
			return dev->link.ifflags & NI_IFF_ARP_ENABLED;
		}
	}
	return FALSE;
}

static size_t
__ni_netdev_name_is_valid(const char *ifname)
{
	size_t i, len = ni_string_len(ifname);

	if (!len || len >= IFNAMSIZ)
		return 0;

	for(i = 0; i < len; ++i) {
		if(isalnum((unsigned char)ifname[i]) ||
				ifname[i] == '-' ||
				ifname[i] == '_' ||
				ifname[i] == '.')
			continue;
		return 0;
	}
	return len;
}

ni_bool_t
ni_netdev_name_is_valid(const char *ifname)
{
	const char *black_list[] = {
		"all", "default", NULL
	}, **ptr;

	if (!__ni_netdev_name_is_valid(ifname))
		return FALSE;

	if (!isalnum((unsigned char)ifname[0]))
		return FALSE;

	for (ptr = black_list; *ptr; ptr++) {
		if (ni_string_eq(*ptr, ifname))
			return FALSE;
	}

	return TRUE;
}

static size_t
__ni_netdev_alias_label_is_valid(const char *alabel)
{
	size_t i, len = ni_string_len(alabel);

	if (!len || len >= IFNAMSIZ)
		return 0;

	for(i = 0; i < len; ++i) {
		if(isalnum((unsigned char)alabel[i]) ||
				alabel[i] == '-' ||
				alabel[i] == '_' ||
				alabel[i] == '.' ||
				alabel[i] == ':')
			continue;
		return 0;
	}
	return len;
}


ni_bool_t
ni_netdev_alias_label_is_valid(const char *ifname, const char *alabel)
{
	size_t nlen = ni_string_len(ifname);
	size_t alen = ni_string_len(alabel);

	/* assume ifname is verified already/separately */
	if (!nlen || !alen || alen >= IFNAMSIZ)
		return FALSE;

	if (!strncmp(ifname, alabel, nlen)) {
		/* alabel is equal to ifname/no label */
		if (alen == nlen)
			return TRUE;

		/* alabel contains "<ifname>:" prefix */
		return  __ni_netdev_alias_label_is_valid(alabel + nlen) > 0;
	} else if (alen + nlen + 1 < IFNAMSIZ) {
		/* alabel without "<ifname>:" prefix  */
		return __ni_netdev_alias_label_is_valid(alabel) > 0;
	} else {
		/* "<ifname>:<alabel>" is too long    */
		return FALSE;
	}
}

