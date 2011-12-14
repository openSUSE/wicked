/*
 * Translation between internal representation and netcf XML
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/resolver.h>
#include <wicked/ethernet.h>
#include <wicked/wireless.h>
#include <wicked/nis.h>
#include <wicked/xml.h>

#include "netinfo_priv.h"
#include "kernel.h"

static ni_interface_t *	__ni_netcf_xml_to_interface(ni_syntax_t *, ni_netconfig_t *, xml_node_t *);
static int		__ni_netcf_xml_to_vlan(ni_syntax_t *, ni_netconfig_t *,
					ni_interface_t *, xml_node_t *);
static int		__ni_netcf_xml_to_bridge(ni_syntax_t *, ni_netconfig_t *,
					ni_interface_t *, xml_node_t *);
static int		__ni_netcf_xml_to_bonding(ni_syntax_t *, ni_netconfig_t *,
					ni_interface_t *, xml_node_t *);
static int		__ni_netcf_xml_to_static_ifcfg(ni_syntax_t *syntax, int af,
					ni_interface_t *ifp, xml_node_t *protnode);

static xml_node_t *	__ni_netcf_xml_from_interface(ni_syntax_t *, const ni_interface_t *, xml_node_t *);
static void		__ni_netcf_xml_from_address_config(ni_syntax_t *syntax,
				const ni_afinfo_t *afi,
				const ni_interface_t *ifp, xml_node_t *ifnode);
static xml_node_t *	__ni_netcf_xml_from_static_ifcfg(ni_syntax_t *syntax,
				int af, const ni_interface_t *ifp, xml_node_t *);
static void		__ni_netcf_xml_from_route(ni_route_t *, xml_node_t *);
static void		__ni_netcf_xml_from_bridge(ni_syntax_t *syntax, ni_bridge_t *bridge, xml_node_t *);
static void		__ni_netcf_xml_from_bridge_config(ni_bridge_t *, const char *, xml_node_t *);
static void		__ni_netcf_xml_from_bridge_port_config(ni_bridge_t *, const char *, const char *, xml_node_t *);
static void		__ni_netcf_xml_from_bonding(ni_syntax_t *syntax, ni_bonding_t *bonding, xml_node_t *);
static void		__ni_netcf_xml_from_vlan(ni_syntax_t *syntax, ni_vlan_t *vlan, xml_node_t *fp);
static xml_node_t *	__ni_netcf_xml_from_interface_stats(ni_syntax_t *, ni_netconfig_t *,
				const ni_interface_t *, xml_node_t *);

static xml_node_t *	__ni_netcf_xml_from_policy(ni_syntax_t *, const ni_policy_t *, xml_node_t *);
static xml_node_t *	__ni_netcf_xml_from_ethernet(ni_syntax_t *, const ni_ethernet_t *, xml_node_t *);
static xml_node_t *	__ni_netcf_xml_from_wireless(ni_syntax_t *, const ni_wireless_t *, xml_node_t *);
static xml_node_t *	__ni_netcf_xml_from_wireless_scan(ni_syntax_t *, const ni_wireless_scan_t *, xml_node_t *);
static xml_node_t *	__ni_netcf_xml_from_addrconf_req(ni_syntax_t *, const ni_addrconf_request_t *, xml_node_t *);
static xml_node_t *	__ni_netcf_xml_from_lease(ni_syntax_t *, const ni_addrconf_lease_t *, xml_node_t *parent);
static xml_node_t *	__ni_netcf_xml_from_nis(ni_syntax_t *, const ni_nis_info_t *, xml_node_t *);
static xml_node_t *	__ni_netcf_xml_from_resolver(ni_syntax_t *, const ni_resolver_info_t *, xml_node_t *);
static ni_policy_t *	__ni_netcf_xml_to_policy(ni_syntax_t *, xml_node_t *);
static ni_ethernet_t *	__ni_netcf_xml_to_ethernet(ni_syntax_t *, const xml_node_t *);
static ni_wireless_scan_t *__ni_netcf_xml_to_wireless_scan(ni_syntax_t *, const xml_node_t *);
static ni_addrconf_request_t *__ni_netcf_xml_to_addrconf_req(ni_syntax_t *, const xml_node_t *, int);
static ni_addrconf_lease_t *__ni_netcf_xml_to_lease(ni_syntax_t *, const xml_node_t *);
static ni_nis_info_t *	__ni_netcf_xml_to_nis(ni_syntax_t *, const xml_node_t *);
static ni_resolver_info_t *__ni_netcf_xml_to_resolver(ni_syntax_t *, const xml_node_t *);
static xml_node_t *	__ni_netcf_xml_from_behavior(const ni_ifbehavior_t *, xml_node_t *);
static int		__ni_netcf_xml_to_behavior(ni_ifbehavior_t *, const xml_node_t *);

static const char *	__ni_netcf_get_iftype(const ni_interface_t *);
static int		__ni_netcf_set_iftype(ni_interface_t *, const char *);
static const char *	__ni_netcf_get_startmode(const ni_interface_t *);
static int		__ni_netcf_set_startmode(ni_interface_t *, const char *);
static const char *	__ni_netcf_get_bonding_mode(int mode);
static int		__ni_netcf_set_bonding_mode(const char *, unsigned int *);
static const char *	__ni_netcf_get_arpmon_validation(int mode);
static int		__ni_netcf_set_arpmon_validation(const char *, unsigned int *);
static const char *	__ni_netcf_get_af(int af);
static int		__ni_netcf_set_af(const char *, int *);
/*
static const char *	__ni_netcf_get_boolean(int val);
*/
static int		__ni_netcf_get_boolean_attr(const xml_node_t *, const char *, int *);
static void		__ni_netcf_add_string_child(xml_node_t *, const char *, const char *);
static void		__ni_netcf_add_uint_child(xml_node_t *, const char *, unsigned int);
static void		__ni_netcf_add_string_array_child(xml_node_t *, const char *, const ni_string_array_t *);
static void		__ni_netcf_get_string_child(const xml_node_t *, const char *, char **);
static void		__ni_netcf_get_uint_child(const xml_node_t *, const char *, unsigned int *);
static void		__ni_netcf_get_string_array_child(const xml_node_t *, const char *, ni_string_array_t *);

ni_syntax_t *
__ni_syntax_netcf(const char *pathname)
{
	ni_syntax_t *syntax;

	syntax = calloc(1, sizeof(ni_syntax_t));
	syntax->schema = "netcf";
	syntax->base_path = xstrdup(pathname);
	syntax->xml_from_interface = __ni_netcf_xml_from_interface;
	syntax->xml_to_interface = __ni_netcf_xml_to_interface;
	syntax->xml_from_interface_stats = __ni_netcf_xml_from_interface_stats;
	syntax->xml_from_policy = __ni_netcf_xml_from_policy;
	syntax->xml_to_policy = __ni_netcf_xml_to_policy;
	syntax->xml_from_ethernet = __ni_netcf_xml_from_ethernet;
	syntax->xml_to_ethernet = __ni_netcf_xml_to_ethernet;
	syntax->xml_from_wireless_scan = __ni_netcf_xml_from_wireless_scan;
	syntax->xml_to_wireless_scan = __ni_netcf_xml_to_wireless_scan;
	syntax->xml_from_lease = __ni_netcf_xml_from_lease;
	syntax->xml_to_lease = __ni_netcf_xml_to_lease;
	syntax->xml_from_request = __ni_netcf_xml_from_addrconf_req;
	syntax->xml_to_request = __ni_netcf_xml_to_addrconf_req;
	syntax->xml_from_nis = __ni_netcf_xml_from_nis;
	syntax->xml_to_nis = __ni_netcf_xml_to_nis;
	syntax->xml_from_resolver = __ni_netcf_xml_from_resolver;
	syntax->xml_to_resolver = __ni_netcf_xml_to_resolver;

	return syntax;
}

ni_syntax_t *
__ni_syntax_netcf_strict(const char *pathname)
{
	ni_syntax_t *syntax;

	syntax = __ni_syntax_netcf(pathname);
	syntax->strict = 1;
	return syntax;
}

ni_interface_t *
__ni_netcf_xml_to_interface(ni_syntax_t *syntax, ni_netconfig_t *nc, xml_node_t *ifnode)
{
	ni_interface_t *ifp;
	const char *attrval;
	xml_node_t *node, *child;

	if ((attrval = xml_node_get_attr(ifnode, "name")) != NULL) {
		ifp = nc_interface_new(nc, attrval, 0);
	} else {
		ifp = nc_interface_new(nc, NULL, 0);
	}

	if ((attrval = xml_node_get_attr(ifnode, "type")) != NULL) {
		if (__ni_netcf_set_iftype(ifp, attrval) < 0) {
			error("unknown/unsupported interface type %s", attrval);
			return NULL;
		}
	} else {
		ni_error("<interface> element without type");
		return NULL;
	}

	/* netcf source code claims there's support for a uuid element, but
	 * I can't see how it's handled. */
	if ((node = xml_node_get_child(ifnode, "uuid")) != NULL) {
		if (ni_uuid_parse(&ifp->uuid, node->cdata) < 0) {
			error("%s: cannot parse uuid", ifp->name);
			return NULL;
		}
	}

	/* Variant netcf */
	if (!syntax->strict && (node = xml_node_get_child(ifnode, "status")) != NULL) {
		unsigned int flags = ifp->link.ifflags;
		const char *opmode = NULL;

		if ((attrval = xml_node_get_attr(node, "device")) && !strcmp(attrval, "up"))
			flags |= NI_IFF_DEVICE_UP;
		if ((attrval = xml_node_get_attr(node, "link")) && !strcmp(attrval, "up"))
			flags |= NI_IFF_LINK_UP;
		if ((attrval = xml_node_get_attr(node, "network")) && !strcmp(attrval, "up"))
			flags |= NI_IFF_NETWORK_UP;
		if ((opmode = xml_node_get_attr(node, "mode")) != NULL) {
			if (!strcmp(opmode, "point-to-point")) {
				flags |= NI_IFF_POINT_TO_POINT;
			} else {
				ni_warn("%s: unsupported attribute <status mode=\"%s\">", ifp->name, opmode);
				opmode = NULL;
			}
		}
		if (opmode == NULL) {
			flags |= NI_IFF_ARP_ENABLED | NI_IFF_BROADCAST_ENABLED | NI_IFF_MULTICAST_ENABLED;
			if ((attrval = xml_node_get_attr(node, "arp")) && !strcmp(attrval, "disabled"))
				flags &= ~NI_IFF_ARP_ENABLED;
			if ((attrval = xml_node_get_attr(node, "broadcast")) && !strcmp(attrval, "disabled"))
				flags &= ~NI_IFF_BROADCAST_ENABLED;
			if ((attrval = xml_node_get_attr(node, "broadcast")) && !strcmp(attrval, "disabled"))
				flags &= ~NI_IFF_MULTICAST_ENABLED;
		}

		ifp->link.ifflags = flags;
	}

	if (syntax->strict) {
		node = xml_node_get_child(ifnode, "start");
		if (node && (attrval = xml_node_get_attr(node, "mode")) != NULL) {
			if (__ni_netcf_set_startmode(ifp, attrval) < 0) {
				ni_error("unknown/unsupported interface start mode %s", attrval);
				return NULL;
			}
		}
	} else {
		node = xml_node_get_child(ifnode, "behavior");
		if (node && __ni_netcf_xml_to_behavior(&ifp->startmode, node) < 0) {
			ni_error("cannot parse interface <behavior> element");
			return NULL;
		}
	}

	node = xml_node_get_child(ifnode, "mtu");
	if (node && xml_node_get_attr_uint(node, "size", &ifp->link.mtu) < 0)
		return NULL;

	node = xml_node_get_child(ifnode, "mac");
	if (node && (attrval = xml_node_get_attr(node, "address")) != NULL) {
		if (ni_link_address_parse(&ifp->link.hwaddr, ifp->link.type, attrval) < 0) {
			error("cannot parse link level address %s", attrval);
			return NULL;
		}
	}

	/* For a newly created interface, address config defaults
	 * to DHCP (IPv4) and AUTOCONF (IPv6), respectively
	 */
	/* For now, the semantics of a missing <protocol> element
	 * are a bit weird.
	 * IPv4: No <protocol> element means DHCP
	 * IPv6: No <protocol> element means AUTOCONF
	 */
	ifp->ipv4.addrconf = NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC) |
			     NI_ADDRCONF_MASK(NI_ADDRCONF_DHCP);
	ifp->ipv6.addrconf = NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC) |
			     NI_ADDRCONF_MASK(NI_ADDRCONF_AUTOCONF);

	/* Hunt for "protocol" children */
	for (node = ifnode->children; node; node = node->next) {
		ni_afinfo_t *afi;

		if (strcmp(node->name, "protocol") != 0)
			continue;

		attrval = xml_node_get_attr(node, "family");
		if (!attrval) {
			error("interface protocol node without family attribute");
			return NULL;
		}

		if (!strcmp(attrval, "ipv4")) {
			afi = &ifp->ipv4;
		} else if (!strcmp(attrval, "ipv6")) {
			afi = &ifp->ipv6;
		} else {
			error("ignoring unknown address family %s", attrval);
			continue;
		}

		afi->addrconf = 0;
		afi->enabled = 1;

		for (child = node->children; child; child = child->next) {
			int mode;

			mode = ni_addrconf_name_to_type(child->name);
			if (mode >= 0) {
				ni_afinfo_addrconf_enable(afi, mode);
				afi->request[mode] = __ni_netcf_xml_to_addrconf_req(syntax, child, afi->family);
				if (afi->request[mode] == NULL) {
					ni_error("error parsing %s information", child->name);
					return NULL;
				}
				continue;
			}

			if (!syntax->strict) {
				if (!strcmp(child->name, "disable")) {
					afi->enabled = 0;
					continue;
				}
				if (!strcmp(child->name, "lease")) {
					ni_addrconf_lease_t *lease;

					lease = __ni_netcf_xml_to_lease(syntax, child);
					if (!lease) {
						ni_error("error parsing lease element");
						return NULL;
					}
					if (lease->family != afi->family || lease->type >= __NI_ADDRCONF_MAX) {
						ni_addrconf_lease_free(lease);
						continue;
					}

					mode = lease->type;
					if (afi->lease[mode])
						ni_addrconf_lease_free(afi->lease[mode]);
					afi->lease[mode] = lease;
				}
			}
		}

		/* Pull in static configuration */
		if (__ni_netcf_xml_to_static_ifcfg(syntax, afi->family, ifp, node))
			return NULL;
		ni_afinfo_addrconf_enable(afi, NI_ADDRCONF_STATIC);
	}

	switch (ifp->link.type) {
	case NI_IFTYPE_BRIDGE:
		if (__ni_netcf_xml_to_bridge(syntax, nc, ifp, ifnode))
			return NULL;
		break;
	case NI_IFTYPE_BOND:
		if (__ni_netcf_xml_to_bonding(syntax, nc, ifp, ifnode))
			return NULL;
		break;
	case NI_IFTYPE_VLAN:
		if (__ni_netcf_xml_to_vlan(syntax, nc, ifp, ifnode))
			return NULL;
		break;
	case NI_IFTYPE_ETHERNET:
		child = xml_node_get_child(ifnode, "ethernet");
		if (child)
			ni_interface_set_ethernet(ifp, __ni_netcf_xml_to_ethernet(syntax, child));
		break;

	default: ;
	}
	return ifp;
}

int
__ni_netcf_xml_to_vlan(ni_syntax_t *syntax, ni_netconfig_t *nc,
				ni_interface_t *ifp, xml_node_t *ifnode)
{
	xml_node_t *vnode, *rnode;
	const char *attrval;
	ni_vlan_t *vlan;

	if (!(vnode = xml_node_get_child(ifnode, "vlan"))) {
		error("VLAN interface %s: xml config has no vlan element", ifp->name);
		return -1;
	}

	vlan = ni_interface_get_vlan(ifp);

	if (!(attrval = xml_node_get_attr(vnode, "tag"))) {
		error("VLAN interface %s: vlan element has no tag attribute", ifp->name);
		return -1;
	}
	vlan->tag = strtoul(attrval, NULL, 0);

	if (!(rnode = xml_node_get_child(vnode, "interface"))) {
		error("VLAN interface %s: vlan element has no interface element", ifp->name);
		return -1;
	}
	if (!(attrval = xml_node_get_attr(rnode, "name"))) {
		error("VLAN interface %s: vlan interface element has no name attribute", ifp->name);
		return -1;
	}
	vlan->physdev_name = xstrdup(attrval);

	return 0;
}

/*
 * Obtain bridge configuration from XML
 */
static int
__ni_netcf_xml_to_bridge(ni_syntax_t *syntax, ni_netconfig_t *nc,
				ni_interface_t *ifp, xml_node_t *ifnode)
{
	xml_node_t *brnode, *child;
	ni_bridge_t *bridge;

	if (!(brnode = xml_node_get_child(ifnode, "bridge"))) {
		error("bridge interface %s: xml config has no bridge element", ifp->name);
		return -1;
	}

	bridge = ni_interface_get_bridge(ifp);

	/* stp disabled is default -- is it mandatory for netcf? */
	if (ni_bridge_set_stp(bridge, xml_node_get_attr(brnode, "stp")) < 0) {
		error("bridge interface %s: bridge element lacks stp attribute", ifp->name);
		return -1;
	}

	ni_bridge_set_forward_delay(bridge, xml_node_get_attr(brnode, "forward-delay"));
	if (!syntax->strict) {
		ni_bridge_set_ageing_time(bridge, xml_node_get_attr(brnode, "ageing-time"));
		ni_bridge_set_hello_time(bridge, xml_node_get_attr(brnode, "hello-time"));
		ni_bridge_set_max_age(bridge, xml_node_get_attr(brnode, "max-age"));
		ni_bridge_set_priority(bridge, xml_node_get_attr(brnode, "priority"));
	}

	for (child = brnode->children; child; child = child->next) {
		const char *ifname;

		if (strcmp(child->name, "interface"))
			continue;

		if (!(ifname = xml_node_get_attr(child, "name"))) {
			error("bridge interface %s: interface element lacks name attribute", ifp->name);
			return -1;
		}

		ni_bridge_add_port_name(bridge, ifname);
		if (!syntax->strict) {
			ni_bridge_port_set_priority(bridge, ifname,
				xml_node_get_attr(child, "priority"));
			ni_bridge_port_set_path_cost(bridge, ifname,
				xml_node_get_attr(child, "path-cost"));
		}
	}

	return 0;
}

/*
 * Obtain bonding configuration from XML
 */
int
__ni_netcf_xml_to_bonding(ni_syntax_t *syntax, ni_netconfig_t *nc,
			ni_interface_t *ifp, xml_node_t *ifnode)
{
	xml_node_t *bdnode, *child;
	ni_bonding_t *bonding;
	const char *attrval;

	if (!(bdnode = xml_node_get_child(ifnode, "bond"))) {
		error("bond interface %s: xml config has no bond element", ifp->name);
		return -1;
	}

	bonding = ni_interface_get_bonding(ifp);

	if (!(attrval = xml_node_get_attr(bdnode, "mode"))) {
		error("bond interface %s: bond element lacks mode attribute", ifp->name);
		return -1;
	}
	if (__ni_netcf_set_bonding_mode(attrval, &bonding->mode) < 0) {
		error("bond interface %s: unsupported bonding mode \"%s\"", ifp->name, attrval);
		return -1;
	}

	if ((child = xml_node_get_child(bdnode, "arpmon")) != NULL) {
		xml_node_t *grandchild;

		bonding->monitoring = NI_BOND_MONITOR_ARP;

		/* FIXME: set default values? */
		if (xml_node_get_attr_uint(child, "interval", &bonding->arpmon.interval) < 0) {
			error("bond interface %s: incomplete arpmon definition", ifp->name);
			return -1;
		}

		bonding->arpmon.validate = NI_BOND_VALIDATE_NONE;
		if ((attrval = xml_node_get_attr(child, "validate")) != NULL
		 && __ni_netcf_set_arpmon_validation(attrval, &bonding->arpmon.validate) < 0) {
			error("bond interface %s: arpmon validate=\"%s\" not supported", ifp->name, attrval);
			return -1;
		}

		for (grandchild = child->children; grandchild; grandchild = grandchild->next) {
			if (strcmp(grandchild->name, "target"))
				continue;

			if ((attrval = xml_node_get_attr(grandchild, "ip")) != NULL) {
				struct in_addr dummy;

				if (inet_aton(attrval, &dummy) == 0) {
					error("bond interface %s: bad arpmon target \"%s\"", ifp->name, attrval);
					return -1;
				}
				ni_string_array_append(&bonding->arpmon.targets, attrval);
			}
		}
	} else
	if ((child = xml_node_get_child(bdnode, "miimon")) != NULL) {
		bonding->monitoring = NI_BOND_MONITOR_MII;

		/* FIXME: set default values? */
		if (xml_node_get_attr_uint(child, "freq", &bonding->miimon.frequency) < 0
		 || xml_node_get_attr_uint(child, "validate", &bonding->arpmon.validate) < 0) {
			error("bond interface %s: incomplete miimon definition", ifp->name);
			return -1;
		}

		xml_node_get_attr_uint(child, "updelay", &bonding->miimon.updelay);
		xml_node_get_attr_uint(child, "downdelay", &bonding->miimon.downdelay);

		if ((attrval = xml_node_get_attr(child, "carrier")) != NULL) {
			if (!strcmp(attrval, "ioctl"))
				bonding->miimon.carrier_detect = NI_BOND_CARRIER_DETECT_IOCTL;
			else
				bonding->miimon.carrier_detect = NI_BOND_CARRIER_DETECT_NETIF;
		}
	} else {
		error("bond interface %s: unsupported monitoring mode", ifp->name);
		return -1;
	}

	ni_string_free(&bonding->primary);
	for (child = bdnode->children; child; child = child->next) {
		const char *ifname;
		int primary = 0;

		if (strcmp(child->name, "interface"))
			continue;

		if (!(ifname = xml_node_get_attr(child, "name"))) {
			error("bonding interface %s: interface element lacks name attribute", ifp->name);
			return -1;
		}

		if (__ni_netcf_get_boolean_attr(child, "primary", &primary) >= 0 && primary) {
			if (bonding->primary != NULL)
				ni_warn("oops, XML definition specifies more than one primary slave");
			ni_string_dup(&bonding->primary, ifname);
		}
		ni_bonding_add_slave(bonding, ifname);
	}

	return 0;
}


static int
__ni_netcf_xml_to_address(xml_node_t *node, int af,
			const char *addrname, ni_sockaddr_t *addr,
			const char *pfxname, unsigned int *prefixlen)
{
	const char *attrval;

	/* Get the local address */
	if (!(attrval = xml_node_get_attr(node, addrname))) {
		if (prefixlen)
			*prefixlen = 0;
		return 0;
	}

	if (ni_address_parse(addr, attrval, af)) {
		error("unable to parse ip addr %s", attrval);
		return -1;
	}

	/* Get the prefix length */
	if (prefixlen) {
		*prefixlen = ~0;
		if (pfxname && xml_node_get_attr_uint(node, pfxname, prefixlen))
			return -1;

		if (*prefixlen == ~0)
			*prefixlen = ni_address_length(af) * 8;
	}

	return 0;
}

int
__ni_netcf_xml_to_static_ifcfg(ni_syntax_t *syntax, int af, ni_interface_t *ifp, xml_node_t *protnode)
{
	xml_node_t *node;

	__ni_global_seqno++;

	for (node = protnode->children; node; node = node->next) {
		ni_sockaddr_t addr;
		unsigned int prefixlen;
		ni_address_t *ap;

		if (strcmp(node->name, "ip") != 0)
			continue;

		/* Get the local address and prefix */
		if (__ni_netcf_xml_to_address(node, af, "address", &addr, "prefix", &prefixlen))
			return -1;

		if (addr.ss_family != af) {
			error("missing address attribute in <ip> node");
			return -1;
		}

		ap = ni_address_new(ifp, af, prefixlen, &addr);

		/* Check if there's a peer address */
		if (__ni_netcf_xml_to_address(node, af, "peer", &ap->peer_addr, NULL, NULL))
			return -1;
	}

	for (node = protnode->children; node; node = node->next) {
		ni_sockaddr_t dest_addr, gw_addr;
		unsigned int prefixlen;

		if (strcmp(node->name, "route") != 0)
			continue;

		memset(&dest_addr, 0, sizeof(dest_addr));
		memset(&gw_addr, 0, sizeof(gw_addr));

		/* Get the destination address and prefix (optional) */
		if (__ni_netcf_xml_to_address(node, af, "address", &dest_addr, "prefix", &prefixlen))
			return -1;

		/* Get the gateway address (optional) */
		if (__ni_netcf_xml_to_address(node, af, "gateway", &gw_addr, NULL, NULL))
			return -1;

		ni_interface_add_route(NULL, ifp, prefixlen, &dest_addr, &gw_addr);
	}


	return 0;
}

/*
 * Build XML structure for a given interface
 */
xml_node_t *
__ni_netcf_xml_from_interface(ni_syntax_t *syntax, const ni_interface_t *ifp, xml_node_t *parent)
{
	xml_node_t *ifnode, *node;

	ifnode = xml_node_new("interface", parent);
	xml_node_add_attr(ifnode, "type", __ni_netcf_get_iftype(ifp));
	if (ifp->name)
		xml_node_add_attr(ifnode, "name", ifp->name);

	if (!ni_uuid_is_null(&ifp->uuid)) {
		node = xml_node_new("uuid", ifnode);
		xml_node_set_cdata(node, ni_uuid_print(&ifp->uuid));
	}

	/* Variant netcf */
	if (!syntax->strict && ifp->link.ifflags) {
		unsigned int flags = ifp->link.ifflags;

		node = xml_node_new("status", ifnode);

		xml_node_add_attr(node, "device",
				(flags & NI_IFF_DEVICE_UP)? "up" : "down");
		xml_node_add_attr(node, "link",
				(flags & NI_IFF_LINK_UP)? "up" : "down");
		xml_node_add_attr(node, "network",
				(flags & NI_IFF_NETWORK_UP)? "up" : "down");
		if (flags & NI_IFF_POINT_TO_POINT) {
			xml_node_add_attr(node, "mode", "point-to-point");
		} else {
			if (!(flags & NI_IFF_ARP_ENABLED))
				xml_node_add_attr(node, "arp", "disabled");
			if (!(flags & NI_IFF_BROADCAST_ENABLED))
				xml_node_add_attr(node, "broadcast", "disabled");
			if (!(flags & NI_IFF_MULTICAST_ENABLED))
				xml_node_add_attr(node, "multicast", "disabled");
		}
	}

	if (syntax->strict) {
		node = xml_node_new("start", ifnode);
		xml_node_add_attr(node, "mode", __ni_netcf_get_startmode(ifp));
		if (ifp->link.mtu) {
			node = xml_node_new("mtu", ifnode);
			xml_node_add_attr_uint(node, "size", ifp->link.mtu);
		}
	} else {
		__ni_netcf_xml_from_behavior(&ifp->startmode, ifnode);
	}

	if (ifp->link.hwaddr.len) {
		node = xml_node_new("mac", ifnode);
		xml_node_add_attr(node, "address", ni_link_address_print(&ifp->link.hwaddr));
	}

	__ni_netcf_xml_from_address_config(syntax, &ifp->ipv4, ifp, ifnode);
	__ni_netcf_xml_from_address_config(syntax, &ifp->ipv6, ifp, ifnode);

	if (ifp->bridge)
		__ni_netcf_xml_from_bridge(syntax, ifp->bridge, ifnode);
	if (ifp->bonding)
		__ni_netcf_xml_from_bonding(syntax, ifp->bonding, ifnode);
	if (ifp->link.vlan)
		__ni_netcf_xml_from_vlan(syntax, ifp->link.vlan, ifnode);
	if (ifp->ethernet)
		__ni_netcf_xml_from_ethernet(syntax, ifp->ethernet, ifnode);
	if (ifp->wireless)
		__ni_netcf_xml_from_wireless(syntax, ifp->wireless, ifnode);

	return ifnode;
}

/*
 * Helper:
 * Build XML structure for a given slave interface (eg the ethernet device
 * unterlying a VLAN device)
 */
static xml_node_t *
__ni_netcf_xml_from_slave_interface(const char *slave_name, xml_node_t *parent)
{
	xml_node_t *ifnode;

	ifnode = xml_node_new("interface", parent);
	xml_node_add_attr(ifnode, "name", slave_name);

	return ifnode;
}

static inline xml_node_t *
__ni_netcf_make_protocol_node(xml_node_t *ifnode, int af)
{
	xml_node_t *node;

	node = xml_node_new("protocol", ifnode);
	xml_node_add_attr(node, "family", __ni_netcf_get_af(af));
	return node;
}

/*
 * For a given address family, produce XML describing the address configuration
 * (static, with all addresses used; or DHCP; or possibly others too)
 */
static void
__ni_netcf_xml_from_address_config(ni_syntax_t *syntax, const ni_afinfo_t *afi,
			const ni_interface_t *ifp, xml_node_t *ifnode)
{
	xml_node_t *protnode = NULL;
	unsigned int mode;

	if (afi->enabled) {
		if (ni_afinfo_addrconf_test(afi, NI_ADDRCONF_STATIC))
			protnode = __ni_netcf_xml_from_static_ifcfg(syntax, afi->family, ifp, ifnode);

		if (!protnode)
			protnode = __ni_netcf_make_protocol_node(ifnode, afi->family);

		for (mode = 0; mode < __NI_ADDRCONF_MAX; ++mode) {
			ni_addrconf_request_t *req;
			ni_addrconf_lease_t *lease;

			if (mode == NI_ADDRCONF_STATIC || !ni_afinfo_addrconf_test(afi, mode))
				continue;

			if (syntax->strict && mode != NI_ADDRCONF_DHCP)
				continue;

			if ((req = afi->request[mode]) != NULL) {
				__ni_netcf_xml_from_addrconf_req(syntax, req, protnode);
			} else {
				const char *acname;

				acname = ni_addrconf_type_to_name(mode);
				if (acname != NULL)
					xml_node_new(acname, protnode);
			}

			if ((lease = afi->lease[mode]) != NULL)
				__ni_netcf_xml_from_lease(syntax, lease, protnode);
		}
	} else if (!syntax->strict) {
		protnode = __ni_netcf_make_protocol_node(ifnode, afi->family);
		xml_node_new("disabled", protnode);
	}
}

static xml_node_t *
__ni_netcf_xml_from_static_ifcfg(ni_syntax_t *syntax, int af,
			const ni_interface_t *ifp, xml_node_t *ifnode)
{
	xml_node_t *protnode = NULL;
	ni_address_t *ap;
	ni_route_t *rp;

	__ni_global_seqno++;
	for (ap = ifp->addrs; ap; ap = ap->next) {
		xml_node_t *addrnode;

		if (ap->family != af || ap->config_method != NI_ADDRCONF_STATIC)
			continue;

		if (!protnode)
			protnode = __ni_netcf_make_protocol_node(ifnode, af);

		addrnode = xml_node_new("ip", protnode);
		xml_node_add_attr(addrnode, "address", ni_address_print(&ap->local_addr));
		if (ap->peer_addr.ss_family != AF_UNSPEC)
			xml_node_add_attr(addrnode, "peer", ni_address_print(&ap->peer_addr));
		xml_node_add_attr_uint(addrnode, "prefix", ap->prefixlen);

#ifdef notdef
		for (rp = nc->routes; rp; rp = rp->next) {
			// FIXME: this check works for IPv4 only;
			// IPv6 routing is different.
			if (ni_address_can_reach(ap, &rp->nh.gateway))
				rp->seq = __ni_global_seqno;
		}
#endif
	}

	if (protnode) {
		/* variant netcf can express a richer variety of IP routes */
		for (rp = ifp->routes; rp; rp = rp->next) {
			/* strict netcf: ignore non-default routes; we cannot map these. */
			if (syntax->strict && rp->prefixlen != 0)
				continue;
			if (rp->family == af)
				__ni_netcf_xml_from_route(rp, protnode);
		}

#ifdef notdef
		for (rp = nc->routes; rp; rp = rp->next) {
			/* strict netcf: ignore non-default routes; we cannot map these. */
			if (syntax->strict && rp->prefixlen != 0)
				continue;
			if (rp->seq == __ni_global_seqno)
				__ni_netcf_xml_from_route(rp, protnode);
		}
#endif
	}

	return protnode;
}

/*
 * Helper:
 * Generate XML representation of a network route
 */
static void
__ni_netcf_xml_from_route(ni_route_t *rp, xml_node_t *protnode)
{
	xml_node_t *routenode;

	routenode = xml_node_new("route", protnode);

	if (rp->prefixlen != 0) {
		xml_node_add_attr(routenode, "address", ni_address_print(&rp->destination));
		xml_node_add_attr_uint(routenode, "prefix", rp->prefixlen);
	}

	if (rp->nh.gateway.ss_family != AF_UNSPEC)
		xml_node_add_attr(routenode, "gateway", ni_address_print(&rp->nh.gateway));
}

/*
 * Generate XML representation of a bridge configuration
 */
static ni_intmap_t	__ni_netcf_bridge_cfg_attr_map[] = {
	{ "stp",		NI_BRIDGE_STP_ENABLED	},
	{ "forward-delay",	NI_BRIDGE_FORWARD_DELAY	},
	{ "ageing-time",	NI_BRIDGE_AGEING_TIME	},
	{ "hello-time",		NI_BRIDGE_HELLO_TIME	},
	{ "max-age",		NI_BRIDGE_MAX_AGE	},
	{ "priority",		NI_BRIDGE_PRIORITY	},
	{ NULL						}
};

static ni_intmap_t	__ni_netcf_bridge_port_cfg_attr_map[] = {
	{ "priority",		NI_BRIDGE_PORT_PRIORITY	},
	{ "path-cost",		NI_BRIDGE_PORT_PATH_COST},
	{ NULL						}
};

static void
__ni_netcf_xml_from_bridge_config(ni_bridge_t *bridge, const char *attr, xml_node_t *node)
{
	unsigned int opt;
	char *value = NULL;

	if (ni_parse_int_mapped(attr, __ni_netcf_bridge_cfg_attr_map, &opt) < 0)
		return;

	if (ni_bridge_get(bridge, opt, &value) > 0) {
		xml_node_add_attr(node, attr, value);
		ni_string_free(&value);
	}
}

static void
__ni_netcf_xml_from_bridge_port_config(ni_bridge_t *bridge, const char *port,
					const char *attr, xml_node_t *node)
{
	unsigned int opt;
	char *value = NULL;

	if (ni_parse_int_mapped(attr, __ni_netcf_bridge_port_cfg_attr_map, &opt) < 0)
		return;

	if (ni_bridge_port_get(bridge, port, opt, &value) > 0) {
		xml_node_add_attr(node, attr, value);
		ni_string_free(&value);
	}
}
static void
__ni_netcf_xml_from_bridge_status(ni_bridge_t *bridge, xml_node_t *brnode)
{
	xml_node_t *snode;

	snode = xml_node_new("status", brnode);
	if (bridge->status.root_id)
		xml_node_set_cdata(xml_node_new("root-id", snode), bridge->status.root_id);
	if (bridge->status.bridge_id)
		xml_node_set_cdata(xml_node_new("bridge-id", snode), bridge->status.bridge_id);
	if (bridge->status.group_addr)
		xml_node_set_cdata(xml_node_new("group-address", snode), bridge->status.group_addr);
}

static void
__ni_netcf_xml_from_bridge(ni_syntax_t *syntax, ni_bridge_t *bridge, xml_node_t *ifnode)
{
	xml_node_t *brnode;
	unsigned int i;

	brnode = xml_node_new("bridge", ifnode);
	__ni_netcf_xml_from_bridge_config(bridge, "stp", brnode);
	__ni_netcf_xml_from_bridge_config(bridge, "forward-delay", brnode);

	if (!syntax->strict) {
		__ni_netcf_xml_from_bridge_config(bridge, "ageing-time", brnode);
		__ni_netcf_xml_from_bridge_config(bridge, "hello-time", brnode);
		__ni_netcf_xml_from_bridge_config(bridge, "priority", brnode);
		__ni_netcf_xml_from_bridge_config(bridge, "max-age", brnode);
		__ni_netcf_xml_from_bridge_status(bridge, brnode);
	}

	/* FIXME: strict netcf now wants to represent a VLAN port as
	 *  <vlan tag="..."><interface ../></vlan>
	 */
	for (i = 0; i < bridge->ports.count; ++i) {
		xml_node_t *port_node;
		char       *port_name;

		port_name = bridge->ports.data[i]->name;
		port_node = __ni_netcf_xml_from_slave_interface(port_name, brnode);
		if (!syntax->strict) {
			__ni_netcf_xml_from_bridge_port_config(bridge, port_name,
				"priority", port_node);
			__ni_netcf_xml_from_bridge_port_config(bridge, port_name,
				"path-cost", port_node);
		}
	}
}

/*
 * Generate XML representation of a bonding configuration
 */
void
__ni_netcf_xml_from_bonding(ni_syntax_t *syntax, ni_bonding_t *bonding, xml_node_t *ifnode)
{
	xml_node_t *bdnode;
	unsigned int i, j;

	bdnode = xml_node_new("bond", ifnode);
	xml_node_add_attr(bdnode, "mode", __ni_netcf_get_bonding_mode(bonding->mode));

	if (bonding->monitoring == NI_BOND_MONITOR_ARP) {
		xml_node_t *arpnode;

		arpnode = xml_node_new("arpmon", bdnode);
		xml_node_add_attr_uint(arpnode, "interval",
				bonding->arpmon.interval);

		for (j = 0; j < bonding->arpmon.targets.count; ++j) {
			xml_node_t *tgtnode;

			tgtnode = xml_node_new("target", arpnode);
			xml_node_add_attr(tgtnode, "ip", bonding->arpmon.targets.data[j]);
		}

		xml_node_add_attr(arpnode, "validate",
				__ni_netcf_get_arpmon_validation(bonding->arpmon.validate));
	} else if (bonding->monitoring == NI_BOND_MONITOR_MII) {
		xml_node_t *miinode;

		miinode = xml_node_new("miimon", bdnode);
		xml_node_add_attr_uint(miinode, "freq", bonding->miimon.frequency);
		if (bonding->miimon.updelay)
			xml_node_add_attr_uint(miinode, "updelay", bonding->miimon.updelay);
		if (bonding->miimon.downdelay)
			xml_node_add_attr_uint(miinode, "downdelay", bonding->miimon.downdelay);
		if (bonding->miimon.carrier_detect == NI_BOND_CARRIER_DETECT_IOCTL)
			xml_node_add_attr(miinode, "carrier", "ioctl");
		else
			xml_node_add_attr(miinode, "carrier", "netif");
	} else {
		assert(0);
	}

	for (i = 0; i < bonding->slave_names.count; ++i) {
		const char *slave_name = bonding->slave_names.data[i];
		xml_node_t *slave_node;

		slave_node = __ni_netcf_xml_from_slave_interface(slave_name, bdnode);
		if (bonding->primary && !strcmp(bonding->primary, slave_name))
			xml_node_add_attr(slave_node, "primary", "yes");
	}
}

/*
 * Generate XML representation of a VLAN configuration
 */
static void
__ni_netcf_xml_from_vlan(ni_syntax_t *syntax, ni_vlan_t *vlan, xml_node_t *ifnode)
{
	xml_node_t *vlnode;

	vlnode = xml_node_new("vlan", ifnode);
	xml_node_add_attr_uint(vlnode, "tag", vlan->tag);
	if (vlan->physdev_name) {
		xml_node_t *ifchild;

		ifchild = xml_node_new("interface", vlnode);
		xml_node_add_attr(ifchild, "name", vlan->physdev_name);
	}
}

/*
 * XML addrconf request representation
 */
static xml_node_t *
__ni_netcf_xml_from_addrconf_req(ni_syntax_t *syntax, const ni_addrconf_request_t *req, xml_node_t *proto_node)
{
	xml_node_t *dhnode, *child;
	const char *acname;

	if (req == NULL)
		return NULL;

	acname = ni_addrconf_type_to_name(req->type);
	if (acname == NULL) {
		ni_error("Oops, unexpected addrconf request of type %u", req->type);
		return NULL;
	}

	dhnode = xml_node_new(acname, proto_node);

	if (syntax->strict) {
		/* strict netcf only allows peerdns="yes" so far */
		if (ni_addrconf_should_update(req, NI_ADDRCONF_UPDATE_RESOLVER))
			xml_node_add_attr(dhnode, "peerdns", "yes");
		return dhnode;
	}

	if (req->acquire_timeout)
		__ni_netcf_add_uint_child(dhnode, "acquire-timeout", req->acquire_timeout);
	if (req->reuse_unexpired)
		xml_node_new("reuse-unexpired", dhnode);

	if (req->type == NI_ADDRCONF_DHCP) {
		if (req->dhcp.hostname)
			__ni_netcf_add_string_child(dhnode, "hostname", req->dhcp.hostname);
		if (req->dhcp.clientid)
			__ni_netcf_add_string_child(dhnode, "client-id", req->dhcp.clientid);
		if (req->dhcp.vendor_class)
			__ni_netcf_add_string_child(dhnode, "vendor-class", req->dhcp.vendor_class);
		if (req->dhcp.lease_time)
			__ni_netcf_add_uint_child(dhnode, "lease-time", req->dhcp.lease_time);
	}

	if (req->update != 0) {
		unsigned int target;

		child = xml_node_new("update", dhnode);
		for (target = 0; target < __NI_ADDRCONF_UPDATE_MAX; ++target) {
			const char *name;

			if (!ni_addrconf_should_update(req, target))
				continue;

			if (!(name = ni_addrconf_update_target_to_name(target))) {
				ni_warn("cannot represent update target %u", target);
				continue;
			}

			xml_node_new(name, child);
		}
	}

	return dhnode;
}

static ni_addrconf_request_t *
__ni_netcf_xml_to_addrconf_req(ni_syntax_t *syntax, const xml_node_t *dhnode, int req_family)
{
	int req_type = -1;
	ni_addrconf_request_t *req;
	xml_node_t *child;

	req_type = ni_addrconf_name_to_type(dhnode->name);
	if (req_type < 0) {
		ni_error("cannot parse addrconf element <%s>", dhnode->name);
		return NULL;
	}

	req = ni_addrconf_request_new(req_type, req_family);
	if (syntax->strict) {
		/* strict netcf only allows peerdns="yes" so far */
		int dodns = 0;

		__ni_netcf_get_boolean_attr(dhnode, "peerdns", &dodns);
		if (dodns)
			ni_addrconf_set_update(req, NI_ADDRCONF_UPDATE_RESOLVER);
		return req;
	}

	__ni_netcf_get_uint_child(dhnode, "acquire-timeout", &req->acquire_timeout);
	req->reuse_unexpired = !!xml_node_get_child(dhnode, "reuse-unexpired");

	if (req_type == NI_ADDRCONF_DHCP) {
		__ni_netcf_get_string_child(dhnode, "hostname", &req->dhcp.hostname);
		__ni_netcf_get_string_child(dhnode, "client-id", &req->dhcp.clientid);
		__ni_netcf_get_string_child(dhnode, "vendor-class", &req->dhcp.vendor_class);
		__ni_netcf_get_uint_child(dhnode, "lease-time", &req->dhcp.lease_time);
	}

	if ((child = xml_node_get_child(dhnode, "update")) != NULL) {
		xml_node_t *node;

		for (node = child->children; node; node = node->next) {
			int target;

			if ((target = ni_addrconf_name_to_update_target(node->name)) < 0) {
				ni_warn("ignoring unknown addrconf update target \"%s\"", node->name);
			} else {
				ni_addrconf_set_update(req, target);
			}
		}
	}

	return req;
}

/*
 * XML addrconf lease representation
 */
static xml_node_t *
__ni_netcf_xml_from_lease(ni_syntax_t *syntax, const ni_addrconf_lease_t *lease, xml_node_t *parent)
{
	const ni_addrconf_t *mech;
	xml_node_t *node;

	node = xml_node_new("lease", parent);
	xml_node_add_attr(node, "type", ni_addrconf_type_to_name(lease->type));
	xml_node_add_attr(node, "family", ni_addrfamily_type_to_name(lease->family));
	xml_node_add_attr(node, "state", ni_addrconf_state_to_name(lease->state));
	xml_node_add_attr_uint(node, "time", lease->time_acquired);

	__ni_netcf_add_string_child(node, "hostname", lease->hostname);
	__ni_netcf_add_string_array_child(node, "log-server", &lease->log_servers);
	__ni_netcf_add_string_array_child(node, "lpr-server", &lease->lpr_servers);
	__ni_netcf_add_string_array_child(node, "ntp-server", &lease->ntp_servers);
	__ni_netcf_add_string_array_child(node, "slp-server", &lease->slp_servers);
	__ni_netcf_add_string_array_child(node, "slp-scopes", &lease->slp_scopes);
	__ni_netcf_add_string_array_child(node, "netbios-name-server", &lease->netbios_name_servers);
	__ni_netcf_add_string_array_child(node, "netbios-dd-server", &lease->netbios_dd_servers);
	__ni_netcf_add_string_child(node, "netbios-domain", lease->netbios_domain);
	__ni_netcf_add_string_child(node, "netbios-scope", lease->netbios_scope);

	if (lease->resolver)
		__ni_netcf_xml_from_resolver(syntax, lease->resolver, node);
	if (lease->nis)
		__ni_netcf_xml_from_nis(syntax, lease->nis, node);

	{
		ni_interface_t dummy;

		memset(&dummy, 0, sizeof(dummy));
		dummy.addrs = lease->addrs;
		dummy.routes = lease->routes;
		__ni_netcf_xml_from_static_ifcfg(syntax, lease->family, &dummy, node);
	}

	/* Convert protocol specific data to xml */
	mech = ni_addrconf_get(lease->type, lease->family);
	if (mech && mech->xml_from_lease)
		mech->xml_from_lease(mech, lease, node);

	return node;
}

static ni_addrconf_lease_t *
__ni_netcf_xml_to_lease(ni_syntax_t *syntax, const xml_node_t *node)
{
	const ni_addrconf_t *mech;
	ni_addrconf_lease_t *lease = NULL;
	xml_node_t *prot, *child;
	const char *name;
	int lease_type, lease_family, lease_state;

	if (!(name = xml_node_get_attr(node, "type"))
	 || (lease_type = ni_addrconf_name_to_type(name)) < 0) {
		ni_error("netcf: cannot parse lease; no or unsupported type");
		return NULL;
	}

	if (!(name = xml_node_get_attr(node, "family"))
	 || (lease_family = ni_addrfamily_name_to_type(name)) < 0) {
		ni_error("netcf: cannot parse lease; no or unsupported address family");
		return NULL;
	}

	if (!(name = xml_node_get_attr(node, "state"))
	 || (lease_state = ni_addrconf_name_to_state(name)) < 0) {
		ni_error("netcf: cannot parse lease; no or unsupported state");
		return NULL;
	}

	lease = ni_addrconf_lease_new(lease_type, lease_family);
	lease->state = lease_state;
	xml_node_get_attr_uint(node, "time", &lease->time_acquired);
	__ni_netcf_get_string_child(node, "hostname", &lease->hostname);
	__ni_netcf_get_string_array_child(node, "log-server", &lease->log_servers);
	__ni_netcf_get_string_array_child(node, "lpr-server", &lease->lpr_servers);
	__ni_netcf_get_string_array_child(node, "ntp-server", &lease->ntp_servers);
	__ni_netcf_get_string_array_child(node, "slp-server", &lease->slp_servers);
	__ni_netcf_get_string_array_child(node, "slp-scopes", &lease->slp_scopes);
	__ni_netcf_get_string_array_child(node, "netbios-name-server", &lease->netbios_name_servers);
	__ni_netcf_get_string_array_child(node, "netbios-dd-server", &lease->netbios_dd_servers);
	__ni_netcf_get_string_child(node, "netbios-domain", &lease->netbios_domain);
	__ni_netcf_get_string_child(node, "netbios-scope", &lease->netbios_scope);

	/* FIXME: we want to have one single loop over all children. */
	for (child = node->children; child; child = child->next) {
		if (!strcmp(child->name, "resolver")) {
			if (lease->resolver == NULL)
				lease->resolver = __ni_netcf_xml_to_resolver(syntax, child);
			continue;
		}
		if (!strcmp(child->name, "nis")) {
			if (lease->nis == NULL)
				lease->nis = __ni_netcf_xml_to_nis(syntax, child);
			continue;
		}
	}

	/* Hunt for "protocol" children */
	for (prot = node->children; prot; prot = prot->next) {
		ni_interface_t dummy;
		int af;

		if (strcmp(prot->name, "protocol") != 0)
			continue;

		name = xml_node_get_attr(prot, "family");
		if (!name) {
			error("interface protocol node without family attribute");
			goto failed;
		}

		if (__ni_netcf_set_af(name, &af) < 0) {
			ni_error("ignoring unknown address family %s", name);
			continue;
		}

		/* We need this freaking handle only for the seqno thing :-( */
		memset(&dummy, 0, sizeof(dummy));
		if (__ni_netcf_xml_to_static_ifcfg(syntax, af, &dummy, prot))
			goto failed;

		lease->addrs = dummy.addrs;
		lease->routes = dummy.routes;
	}

	/* Set protocol specific data from xml */
	mech = ni_addrconf_get(lease->type, lease->family);
	if (mech && mech->xml_to_lease)
		mech->xml_to_lease(mech, lease, node);

	return lease;

failed:
	if (lease)
		ni_addrconf_lease_free(lease);
	return NULL;
}

/*
 * Render NIS config as XML
 */
static xml_node_t *
__ni_netcf_xml_from_nis(ni_syntax_t *syntax, const ni_nis_info_t *nis, xml_node_t *parent)
{
	xml_node_t *node, *domnode;
	unsigned int i, j;

	node = xml_node_new("nis", parent);

	if (nis->domainname)
		xml_node_new_element("domainname", node, nis->domainname);

	for (i = 0; i < nis->domains.count; ++i) {
		ni_nis_domain_t *dom = nis->domains.data[i];

		domnode = xml_node_new("domain", node);
		xml_node_add_attr(domnode, "name", dom->domainname);
		xml_node_add_attr(domnode, "binding", ni_nis_binding_type_to_name(dom->binding));
		for (j = 0; j < dom->servers.count; ++j)
			xml_node_new_element("server", domnode, dom->servers.data[j]);
	}

	domnode = xml_node_new("default", node);
	xml_node_add_attr(domnode, "binding", ni_nis_binding_type_to_name(nis->default_binding));
	for (j = 0; j < nis->default_servers.count; ++j)
		xml_node_new_element("server", domnode, nis->default_servers.data[j]);

	return node;
}

static ni_nis_info_t *
__ni_netcf_xml_to_nis(ni_syntax_t *syntax, const xml_node_t *node)
{
	ni_nis_info_t *nis;
	xml_node_t *child;
	const char *attrval;

	nis = ni_nis_info_new();
	for (child = node->children; child; child = child->next) {
		ni_string_array_t *servers = NULL;
		xml_node_t *snode;
		int binding;

		if (!strcmp(child->name, "domainname")) {
			ni_string_dup(&nis->domainname, child->cdata);
		} else
		if (!strcmp(child->name, "domain")) {
			ni_nis_domain_t *dom;

			if (!(attrval = xml_node_get_attr(child, "name"))) {
				ni_error("NIS domain without name attribute");
				goto error;
			}
			dom = ni_nis_domain_new(nis, attrval);

			if ((attrval = xml_node_get_attr(child, "binding")) != NULL) {
				if ((binding = ni_nis_binding_name_to_type(attrval)) < 0) {
					ni_error("unsupported NIS binding mode %s", attrval);
					goto error;
				}
				dom->binding = binding;
			}

			servers = &dom->servers;
		} else
		if (!strcmp(child->name, "default")) {
			if ((attrval = xml_node_get_attr(child, "binding")) != NULL) {
				if ((binding = ni_nis_binding_name_to_type(attrval)) < 0) {
					ni_error("unsupported NIS binding mode %s", attrval);
					goto error;
				}
				nis->default_binding = binding;
			}

			servers = &nis->default_servers;
		}

		if (servers) {
			for (snode = child->children; snode; snode = snode->next) {
				if (!strcmp(snode->name, "server") && snode->cdata)
					ni_string_array_append(servers, snode->cdata);
			}
		}
	}

	return nis;

error:
	ni_nis_info_free(nis);
	return NULL;
}

/*
 * Render resolver config as XML
 */
static xml_node_t *
__ni_netcf_xml_from_resolver(ni_syntax_t *syntax, const ni_resolver_info_t *resolver, xml_node_t *parent)
{
	xml_node_t *node, *child;
	unsigned int i;

	node = xml_node_new("resolver", parent);
	if (resolver->default_domain)
		xml_node_new_element("default-domain", node, resolver->default_domain);

	if (resolver->dns_servers.count) {
		child = xml_node_new("name-servers", node);
		for (i = 0; i < resolver->dns_servers.count; ++i) {
			xml_node_t *anode = xml_node_new("address", child);

			xml_node_add_attr(anode, "ip", resolver->dns_servers.data[i]);
		}
	}

	if (resolver->dns_search.count) {
		child = xml_node_new("search-list", node);
		for (i = 0; i < resolver->dns_search.count; ++i)
			xml_node_new_element("domain", child, resolver->dns_search.data[i]);
	}

	return node;
}

static ni_resolver_info_t *
__ni_netcf_xml_to_resolver(ni_syntax_t *syntax, const xml_node_t *node)
{
	ni_resolver_info_t *resolver;
	xml_node_t *child;
	const char *attrval;

	resolver = ni_resolver_info_new();
	for (child = node->children; child; child = child->next) {
		if (!strcmp(child->name, "default-domain")) {
			ni_string_dup(&resolver->default_domain, child->cdata);
		} else
		if (!strcmp(child->name, "name-servers")) {
			xml_node_t *nsnode;

			for (nsnode = child->children; nsnode; nsnode = nsnode->next) {
				struct in_addr addr;

				if (strcmp(nsnode->name, "address"))
					continue;
				if (!(attrval = xml_node_get_attr(nsnode, "ip")))
					continue;
				if (inet_aton(attrval, &addr) == 0) {
					ni_error("invalid name server address \"%s\"", attrval);
					goto error;
				}
				ni_string_array_append(&resolver->dns_servers, attrval);
			}
		} else
		if (!strcmp(child->name, "search-list")) {
			xml_node_t *senode;

			for (senode = child->children; senode; senode = senode->next) {
				if (strcmp(senode->name, "domain") || senode->cdata == NULL)
					continue;
				ni_string_array_append(&resolver->dns_search, senode->cdata);
			}
		}
	}

	return resolver;

error:
	ni_resolver_info_free(resolver);
	return NULL;
}

/*
 * Handle interface behavior
 */
static xml_node_t *
__ni_netcf_xml_from_behavior(const ni_ifbehavior_t *beh, xml_node_t *parent)
{
	xml_node_t *node = xml_node_new("behavior", parent);
	xml_node_t *child, *grandchild;
	unsigned int type;

	for (type = 0; type < __NI_IFACTION_MAX; ++type) {
		const ni_ifaction_t *ifa = &beh->ifaction[type];
		const char *acname, *response;

		switch (ifa->action) {
		case NI_INTERFACE_START:
			response = "start";
			break;
		case NI_INTERFACE_STOP:
			response = "stop";
			break;
		default:
			continue;
		}
		if (!(acname = ni_ifaction_type_to_name(type)))
			continue;

		child = xml_node_new(acname, node);
		xml_node_add_attr(child, "action", response);
		if (ifa->mandatory)
			xml_node_new("mandatory", child);
		if (ifa->only_if_link)
			xml_node_new("only-if-link", child);
		if (ifa->wait) {
			grandchild = xml_node_new("wait", child);
			xml_node_add_attr_uint(grandchild, "seconds", ifa->wait);
		}
	}

	return node;
}

static int
__ni_netcf_xml_to_behavior(ni_ifbehavior_t *beh, const xml_node_t *node)
{
	xml_node_t *child, *grandchild;

	memset(beh, 0, sizeof(*beh));
	for (child = node->children; child; child = child->next) {
		ni_evaction_t action = NI_INTERFACE_IGNORE;
		ni_ifaction_t *ifa;
		const char *attrval;
		int idx;

		if ((attrval = xml_node_get_attr(child, "action")) != NULL) {
			if (!strcmp(attrval, "start"))
				action = NI_INTERFACE_START;
			else if (!strcmp(attrval, "stop"))
				action = NI_INTERFACE_STOP;
			else {
				ni_error("cannot parse interface behavior; bad <%s action=\"%s\">",
						child->name, attrval);
				return -1;
			}
		}

		if ((idx = ni_ifaction_name_to_type(child->name)) < 0 || idx >= __NI_IFACTION_MAX) {
			ni_warn("ignoring unsupported interface behavior element <%s>", child->name);
			continue;
		}

		ifa = &beh->ifaction[idx];
		ifa->action = action;

		if (xml_node_get_child(child, "mandatory"))
			ifa->mandatory = 1;
		if (xml_node_get_child(child, "only-if-link"))
			ifa->only_if_link = 1;
		if ((grandchild = xml_node_get_child(child, "wait")) != NULL)
			xml_node_get_attr_uint(grandchild, "seconds", &ifa->wait);
	}
	return 0;
}

/*
 * Represent policy objects
 */
static xml_node_t *
__ni_netcf_xml_from_policy(ni_syntax_t *syntax, const ni_policy_t *policy, xml_node_t *parent)
{
	const char *event_name;
	xml_node_t *node;

	if ((event_name = ni_event_type_to_name(policy->event)) == NULL) {
		ni_error("unknown event type %u", policy->event);
		return NULL;
	}

	node = xml_node_new("policy", parent);
	xml_node_add_attr(node, "event", event_name);

	if (policy->interface) {
		if (__ni_netcf_xml_from_interface(syntax, policy->interface, node) < 0)
			return NULL;
	}
	return node;
}

static ni_policy_t *
__ni_netcf_xml_to_policy(ni_syntax_t *syntax, xml_node_t *node)
{
	ni_policy_t *policy = NULL;
	const char *event_name;
	xml_node_t *child;
	int event;

	if (!(event_name = xml_node_get_attr(node, "event"))) {
		ni_error("%s: missing policy event", __FUNCTION__);
		return NULL;
	}
	if ((event = ni_event_name_to_type(event_name)) < 0) {
		ni_error("%s: unknown policy event \"%s\"", __FUNCTION__, event_name);
		return NULL;
	}

	policy = ni_policy_new(event);
	if ((child = xml_node_get_child(node, "interface")) != NULL) {
		ni_netconfig_t dummy_netconfig;
		ni_interface_t *ifp;

		memset(&dummy_netconfig, 0, sizeof(dummy_netconfig));
		ifp = __ni_netcf_xml_to_interface(syntax, &dummy_netconfig, child);

		if (ifp == NULL) {
			ni_error("%s: cannot parse interface descriptor", __FUNCTION__);
			goto failed;
		}
		policy->interface = ni_interface_get(ifp);
	}

	return policy;

failed:
	if (policy)
		ni_policy_free(policy);
	return NULL;
}

/*
 * Encode/decode ethtool settings
 */
static inline void
__ni_netcf_put_tristate(xml_node_t *node, const char *name, ni_ether_tristate_t value)
{
	switch (value) {
	case NI_ETHERNET_SETTING_ENABLE:
		xml_node_add_attr(node, name, "on");
		break;

	case NI_ETHERNET_SETTING_DISABLE:
		xml_node_add_attr(node, name, "off");
		break;

	default: ;
	}
}

static inline void
__ni_netcf_get_tristate(const xml_node_t *node, const char *name, ni_ether_tristate_t *value)
{
	int bv;

	if (__ni_netcf_get_boolean_attr(node, name, &bv) >= 0)
		*value = bv? NI_ETHERNET_SETTING_ENABLE : NI_ETHERNET_SETTING_DISABLE;
}

xml_node_t *
__ni_netcf_xml_from_ethernet(ni_syntax_t *syntax, const ni_ethernet_t *ether, xml_node_t *parent)
{
	xml_node_t *node, *child;
	const char *attrval;

	node = xml_node_new("ethernet", parent);
	if (ether->link_speed)
		xml_node_add_attr_uint(node, "speed", ether->link_speed);

	switch (ether->duplex) {
	case NI_ETHERNET_DUPLEX_FULL:
		xml_node_add_attr(node, "duplex", "full"); break;

	case NI_ETHERNET_DUPLEX_HALF:
		xml_node_add_attr(node, "duplex", "half"); break;

	default: ;
	}

	__ni_netcf_put_tristate(node, "autoneg", ether->autoneg_enable);

	if ((attrval = ni_ethernet_port_type_to_name(ether->port_type)) != NULL)
		xml_node_add_attr(node, "port", attrval);

	child = xml_node_new("offload", node);
	__ni_netcf_put_tristate(child, "rx-csum", ether->offload.rx_csum);
	__ni_netcf_put_tristate(child, "tx-csum", ether->offload.tx_csum);
	__ni_netcf_put_tristate(child, "scatter-gather", ether->offload.scatter_gather);
	__ni_netcf_put_tristate(child, "tso", ether->offload.tso);
	__ni_netcf_put_tristate(child, "ufo", ether->offload.ufo);
	__ni_netcf_put_tristate(child, "gso", ether->offload.gso);
	__ni_netcf_put_tristate(child, "gro", ether->offload.gro);
	__ni_netcf_put_tristate(child, "lro", ether->offload.lro);

	/* FIXME: need intmap for port type */

	if (ether->identify_time) {
		child = xml_node_new("identify", node);
		xml_node_add_attr_uint(child, "time", ether->identify_time);
	}

	return node;
}

ni_ethernet_t *
__ni_netcf_xml_to_ethernet(ni_syntax_t *syntax, const xml_node_t *node)
{
	ni_ethernet_t *ether = ni_ethernet_alloc();
	const char *attrval;
	xml_node_t *child;

	xml_node_get_attr_uint(node, "speed", &ether->link_speed);

	if ((attrval = xml_node_get_attr(node, "duplex")) != NULL) {
		if (!strcmp(attrval, "full"))
			ether->duplex = NI_ETHERNET_DUPLEX_FULL;
		else if (!strcmp(attrval, "half"))
			ether->duplex = NI_ETHERNET_DUPLEX_HALF;
	}

	if ((attrval = xml_node_get_attr(node, "port")) != NULL)
		ether->port_type = ni_ethernet_name_to_port_type(attrval);

	__ni_netcf_get_tristate(node, "autoneg", &ether->autoneg_enable);

	if ((child = xml_node_get_child(node, "offload")) != NULL) {
		__ni_netcf_get_tristate(child, "rx-csum", &ether->offload.rx_csum);
		__ni_netcf_get_tristate(child, "tx-csum", &ether->offload.tx_csum);
		__ni_netcf_get_tristate(child, "scatter-gather", &ether->offload.scatter_gather);
		__ni_netcf_get_tristate(child, "tso", &ether->offload.tso);
		__ni_netcf_get_tristate(child, "ufo", &ether->offload.ufo);
		__ni_netcf_get_tristate(child, "gso", &ether->offload.gso);
		__ni_netcf_get_tristate(child, "gro", &ether->offload.gro);
		__ni_netcf_get_tristate(child, "lro", &ether->offload.lro);
	}

	return ether;
}

/*
 * Helper function for representing bitmaps
 */
static int
__ni_netcf_xml_from_bitmap(xml_node_t *node, const char *name,
				unsigned int bitmap,
				const char *(*mapfunc)(unsigned int))
{
	unsigned int bit;

	if (bitmap == 0)
		return 0;

	node = xml_node_new(name, node);
	for (bit = 0; bit < 8 * sizeof(bitmap); ++bit) {
		const char *bit_name;

		if (!(bitmap & (1 << bit)))
			continue;

		if (!(bit_name = mapfunc(bit)))
			continue;

		xml_node_new(bit_name, node);
	}
	return 0;
}

/*
 * Represent wireless interface info
 */
xml_node_t *
__ni_netcf_xml_from_wireless(ni_syntax_t *syntax, const ni_wireless_t *wlan, xml_node_t *parent)
{
	xml_node_t *node, *child;

	node = xml_node_new("wireless", parent);

	child = xml_node_new("capabilities", node);
	__ni_netcf_xml_from_bitmap(child, "eap-methods",
			wlan->capabilities.eap_methods,
			ni_wireless_eap_method_to_name);
	__ni_netcf_xml_from_bitmap(child, "pairwise-ciphers",
			wlan->capabilities.pairwise_ciphers,
			ni_wireless_cipher_to_name);
	__ni_netcf_xml_from_bitmap(child, "group-ciphers",
			wlan->capabilities.group_ciphers,
			ni_wireless_cipher_to_name);
	__ni_netcf_xml_from_bitmap(child, "key-management",
			wlan->capabilities.keymgmt_algos,
			ni_wireless_key_management_to_name);
#ifdef notyet
	__ni_netcf_xml_from_bitmap(child, "auth-algos",
			wlan->capabilities.auth_algos,
			ni_wireless_auth_algo_to_name);
#endif
	__ni_netcf_xml_from_bitmap(child, "wpa-protocols",
			wlan->capabilities.wpa_protocols,
			ni_wireless_auth_mode_to_name);

	return 0;
}

/*
 * Encode/decode interface statistics
 */
static inline void
__ni_netcf_xml_from_rxtx(xml_node_t *parent, const char *name, unsigned long rx_value, unsigned long tx_value)
{
	xml_node_t *child = NULL;

	if (rx_value) {
		child = xml_node_new(name, parent);
		xml_node_add_attr_ulong(child, "rx", rx_value);
	}

	if (tx_value) {
		if (!child)
			child = xml_node_new(name, parent);
		xml_node_add_attr_ulong(child, "tx", tx_value);
	}
}

static inline void
__ni_netcf_xml_to_rxtx(xml_node_t *node, unsigned long *rx_value, unsigned long *tx_value)
{
	if (rx_value)
		xml_node_get_attr_ulong(node, "rx", rx_value);
	if (tx_value)
		xml_node_get_attr_ulong(node, "tx", tx_value);
}

xml_node_t *
__ni_netcf_xml_from_interface_stats(ni_syntax_t *syntax, ni_netconfig_t *nc,
				const ni_interface_t *ifp, xml_node_t *parent)
{
	xml_node_t *node = xml_node_new("stats", parent);
	xml_node_t *stats;

	if (ifp->link.stats) {
		const ni_link_stats_t *ls = ifp->link.stats;
		xml_node_t *child;

		stats = xml_node_new("link", node);
		__ni_netcf_xml_from_rxtx(stats, "packets", ls->rx_packets, ls->tx_packets);
		__ni_netcf_xml_from_rxtx(stats, "bytes", ls->rx_bytes, ls->tx_bytes);
		__ni_netcf_xml_from_rxtx(stats, "errors", ls->rx_errors, ls->tx_errors);
		__ni_netcf_xml_from_rxtx(stats, "dropped", ls->rx_dropped, ls->tx_dropped);
		__ni_netcf_xml_from_rxtx(stats, "compressed", ls->rx_compressed, ls->tx_compressed);

		child = xml_node_new("rx-errors", stats);
		if (ls->rx_length_errors)
			xml_node_add_attr_ulong(child, "bad-length", ls->rx_length_errors);
		if (ls->rx_over_errors)
			xml_node_add_attr_ulong(child, "ring-overrun", ls->rx_over_errors);
		if (ls->rx_crc_errors)
			xml_node_add_attr_ulong(child, "bad-crc", ls->rx_crc_errors);
		if (ls->rx_frame_errors)
			xml_node_add_attr_ulong(child, "bad-frame", ls->rx_frame_errors);
		if (ls->rx_fifo_errors)
			xml_node_add_attr_ulong(child, "fifo-overrun", ls->rx_fifo_errors);
		if (ls->rx_missed_errors)
			xml_node_add_attr_ulong(child, "missed", ls->rx_missed_errors);

		child = xml_node_new("tx-errors", stats);
		if (ls->tx_aborted_errors)
			xml_node_add_attr_ulong(child, "aborted", ls->tx_aborted_errors);
		if (ls->tx_carrier_errors)
			xml_node_add_attr_ulong(child, "carrier", ls->tx_carrier_errors);
		if (ls->tx_fifo_errors)
			xml_node_add_attr_ulong(child, "fifo", ls->tx_fifo_errors);
		if (ls->tx_heartbeat_errors)
			xml_node_add_attr_ulong(child, "heartbeat", ls->tx_heartbeat_errors);
		if (ls->tx_window_errors)
			xml_node_add_attr_ulong(child, "window", ls->tx_window_errors);
	}

	return node;
}

xml_node_t *
__ni_netcf_xml_to_interface_stats(ni_syntax_t *syntax, ni_netconfig_t *nc,
				ni_interface_t *ifp, xml_node_t *node)
{
	xml_node_t *stats;

	for (stats = node->children; stats; stats = stats->next) {
		if (!strcmp(stats->name, "link")) {
			ni_link_stats_t *ls = xcalloc(1, sizeof(*ls));
			xml_node_t *child;

			for (child = stats->children; child; child = child->next) {
				if (!strcmp(child->name, "packets"))
					__ni_netcf_xml_to_rxtx(child, &ls->rx_packets, &ls->tx_packets);
				else if (!strcmp(child->name, "bytes"))
					__ni_netcf_xml_to_rxtx(child, &ls->rx_bytes, &ls->tx_bytes);
				else if (!strcmp(child->name, "errors"))
					__ni_netcf_xml_to_rxtx(child, &ls->rx_errors, &ls->tx_errors);
				else if (!strcmp(child->name, "dropped"))
					__ni_netcf_xml_to_rxtx(child, &ls->rx_dropped, &ls->tx_dropped);
				else if (!strcmp(child->name, "compressed"))
					__ni_netcf_xml_to_rxtx(child, &ls->rx_compressed, &ls->tx_compressed);
				else if (!strcmp(child->name, "rx-errors")) {
					xml_node_get_attr_ulong(child, "bad-length", &ls->rx_length_errors);
					xml_node_get_attr_ulong(child, "ring-overrun", &ls->rx_over_errors);
					xml_node_get_attr_ulong(child, "bad-crc", &ls->rx_crc_errors);
					xml_node_get_attr_ulong(child, "bad-frame", &ls->rx_frame_errors);
					xml_node_get_attr_ulong(child, "fifo-overrun", &ls->rx_fifo_errors);
					xml_node_get_attr_ulong(child, "missed", &ls->rx_missed_errors);
				} else if (!strcmp(child->name, "tx-errors")) {
					xml_node_get_attr_ulong(child, "aborted", &ls->tx_aborted_errors);
					xml_node_get_attr_ulong(child, "carrier", &ls->tx_carrier_errors);
					xml_node_get_attr_ulong(child, "fifo", &ls->tx_fifo_errors);
					xml_node_get_attr_ulong(child, "heartbeat", &ls->tx_heartbeat_errors);
					xml_node_get_attr_ulong(child, "window", &ls->tx_window_errors);
				}
			}

			ni_interface_set_link_stats(ifp, ls);
		}
	}

	return node;
}

/*
 * Encode/decode wireless auth info
 */
static xml_node_t *
__ni_netcf_xml_from_wireless_auth_info(ni_syntax_t *syntax, ni_wireless_auth_info_t *auth, xml_node_t *parent)
{
	xml_node_t *node = xml_node_new("auth", parent);
	xml_node_t *child;
	unsigned int i;

	xml_node_add_attr(node, "mode", ni_wireless_auth_mode_to_name(auth->mode));
	xml_node_add_attr_uint(node, "version", auth->version);
	xml_node_new_element("group-cipher", node, ni_wireless_cipher_to_name(auth->group_cipher));

	child = xml_node_new("pairwise-ciphers", node);
	for (i = 0; i < auth->pairwise_ciphers.count; ++i) {
		xml_node_new_element("cipher", child, ni_wireless_cipher_to_name(auth->pairwise_ciphers.value[i]));
	}

	child = xml_node_new("key-management", node);
	for (i = 0; i < auth->key_management.count; ++i) {
		xml_node_new_element("algorithm", child, ni_wireless_key_management_to_name(auth->key_management.value[i]));
	}
	return node;
}

static ni_wireless_auth_info_t *
__ni_netcf_xml_to_wireless_auth_info(ni_syntax_t *syntax, xml_node_t *node)
{
	ni_wireless_auth_info_t *auth;
	const char *attrval;
	unsigned int version;
	int mode;

	if (!(attrval = xml_node_get_attr(node, "mode"))
	 || (mode = ni_wireless_name_to_auth_mode(attrval)) < 0
	 || !(attrval = xml_node_get_attr(node, "version"))
	 || ni_parse_int(attrval, &version) < 0) {
		ni_error("wireless auth info: bad or missing mode/version attr");
		return NULL;
	}

	auth = ni_wireless_auth_info_new(mode, version);

	/* FIXME: add cipher info */

	return auth;
}

/*
 * Encode/decode wireless network
 */
static xml_node_t *
__ni_netcf_xml_from_wireless_network(ni_syntax_t *syntax, const ni_wireless_network_t *net, xml_node_t *parent)
{
	xml_node_t *node = xml_node_new("network", parent);
	xml_node_t *child;

	if (net->access_point.len)
		xml_node_new_element("access-point", node, ni_link_address_print(&net->access_point));
	xml_node_new_element("mode", node, ni_wireless_mode_to_name(net->mode));

	/* We need to escape the ESSID; it may be the result of a wireless
	 * scan; thus we cannot assume it is safe to use as XML CDATA.
	 * FIXME: we really want to handle this in the xml reader/writer code!
	 */
	if (net->essid) {
		const char *essid = net->essid;

		if (strchr(essid, '<') || strchr(essid, '>'))
			essid = "INVALID";
		child = xml_node_new_element("essid", node, essid);

		if (net->essid_encode_index)
			xml_node_add_attr_uint(child, "key-index", net->essid_encode_index);
	}

	if (net->channel || net->frequency) {
		child = xml_node_new("channel", node);
		if (net->channel)
			xml_node_add_attr_uint(child, "index", net->channel);
		if (net->frequency)
			xml_node_add_attr_double(child, "frequency", net->frequency);
	}

	if (net->bitrates.count) {
		char ratebuf[64];
		unsigned int i;

		child = xml_node_new("bitrates", node);
		for (i = 0; i < net->bitrates.count; ++i) {
			snprintf(ratebuf, sizeof(ratebuf), "%u", net->bitrates.value[i]);
			xml_node_new_element("rate", child, ratebuf);
		}
	}

	child = xml_node_new("security", node);
	xml_node_add_attr(child, "mode", ni_wireless_security_to_name(net->encode.mode));

	child = xml_node_new("key", child);
	if (net->encode.key_index)
		xml_node_add_attr_uint(child, "index", net->encode.key_index);
	if (net->encode.key_required)
		xml_node_add_attr_uint(child, "required", 1);
	if (net->encode.key_len)
		xml_node_set_cdata(child, ni_print_hex(net->encode.key_data, net->encode.key_len));

	/* add authentication data */
	if (net->auth_info.count) {
		unsigned int i;

		child = xml_node_new("auth-supported", node);
		for (i = 0; i < net->auth_info.count; ++i) {
			ni_wireless_auth_info_t *auth = net->auth_info.data[i];

			if (!__ni_netcf_xml_from_wireless_auth_info(syntax, auth, child))
				return NULL;
		}
	}

	return node;
}

static ni_wireless_network_t *
__ni_netcf_xml_to_wireless_network(ni_syntax_t *syntax, xml_node_t *node)
{
	ni_wireless_network_t *net = ni_wireless_network_new();
	xml_node_t *child;
	const char *attrval;

	if ((attrval = xml_node_get_attr(node, "access-point")) != NULL
	 && ni_link_address_parse(&net->access_point, NI_IFTYPE_WIRELESS, attrval) < 0) {
		ni_error("cannot parse %s: bad attribute access-point=%s",
				node->name, attrval);
		goto failed;
	}

	for (child = node->children; child; child = child->next) {
		if (!strcmp(child->name, "mode")) {
			net->mode = ni_wireless_name_to_mode(child->cdata);
			if (net->mode == NI_WIRELESS_MODE_UNKNOWN) {
				ni_error("cannot parse %s: bad mode %s",
						node->name, child->cdata);
				goto failed;
			}
		} else
		if (!strcmp(child->name, "essid")) {
			ni_string_dup(&net->essid, child->cdata);
			if ((attrval = xml_node_get_attr(child, "key-index")) != NULL)
				ni_parse_int(attrval, &net->essid_encode_index);
		} else
		if (!strcmp(child->name, "channel")) {
			if ((attrval = xml_node_get_attr(child, "index")) != NULL)
				ni_parse_int(attrval, &net->channel);
			if ((attrval = xml_node_get_attr(child, "frequency")) != NULL)
				ni_parse_double(attrval, &net->frequency);
		} else
		if (!strcmp(child->name, "bitrates")) {
			xml_node_t *gchild;

			for (gchild = child->children; gchild; gchild = gchild->next) {
				unsigned int rate;

				if (ni_parse_int(gchild->cdata, &rate) >= 0
				 && net->bitrates.count < NI_WIRELESS_BITRATES_MAX)
					net->bitrates.value[net->bitrates.count++] = rate;
			}
		} else
		if (!strcmp(child->name, "security")) {
			xml_node_t *gchild;

			if ((attrval = xml_node_get_attr(child, "mode")) != NULL) {
				net->encode.mode = ni_wireless_name_to_security(attrval);
			}

			if ((gchild = xml_node_get_child(child, "key")) != NULL) {
				if ((attrval = xml_node_get_attr(gchild, "index")) != NULL
				 && ni_parse_int(attrval, &net->encode.key_index) < 0) {
					ni_error("wireless security: bad key index=\"%s\" attr",
							attrval);
					goto failed;
				}
				if ((attrval = xml_node_get_attr(gchild, "required")) != NULL
				 && !strcmp(attrval, "1"))
					net->encode.key_required = 1;

				if (gchild->cdata) {
					unsigned char key_data[512];
					int key_len;

					key_len = ni_parse_hex(gchild->cdata, key_data, sizeof(key_data));
					if (key_len) {
						ni_error("wireless security: cannot parse key data");
						goto failed;
					}
					ni_wireless_network_set_key(net, key_data, key_len);
					memset(key_data, 0, sizeof(key_data));
				}
			}
		} else
		if (!strcmp(child->name, "auth-supported")) {
			xml_node_t *gchild;

			for (gchild = child->children; gchild; gchild = gchild->next) {
				ni_wireless_auth_info_t *auth;

				if (!strcmp(gchild->name, "auth")) {
					auth = __ni_netcf_xml_to_wireless_auth_info(syntax, gchild);
					if (!auth)
						goto failed;
					ni_wireless_auth_info_array_append(&net->auth_info, auth);
				}
			}
		} else
			continue;
	}
	return net;

failed:
	ni_wireless_network_free(net);
	return NULL;
}

/*
 * Encode/decode wireless scan results
 */
static xml_node_t *
__ni_netcf_xml_from_wireless_scan(ni_syntax_t *syntax, const ni_wireless_scan_t *scan, xml_node_t *parent)
{
	xml_node_t *node = xml_node_new("wireless-scan", parent);
	unsigned int i;

	for (i = 0; i < scan->networks.count; ++i) {
		ni_wireless_network_t *net = scan->networks.data[i];

		if (!__ni_netcf_xml_from_wireless_network(syntax, net, node))
			return NULL;
	}

	return node;
}

static ni_wireless_scan_t *
__ni_netcf_xml_to_wireless_scan(ni_syntax_t *syntax, const xml_node_t *node)
{
	ni_wireless_scan_t *scan = ni_wireless_scan_new();
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (!strcmp(child->name, "network")) {
			ni_wireless_network_t *net;

			net = __ni_netcf_xml_to_wireless_network(syntax, child);
			if (!net)
				goto failed;
			ni_wireless_network_array_append(&scan->networks, net);
		}
	}

	return scan;

failed:
	ni_wireless_scan_free(scan);
	return NULL;
}

/*
 * Map address family to string and vice versa
 */
const char *
__ni_netcf_get_af(int af)
{
	switch (af) {
	case AF_INET:
		return "ipv4";
	case AF_INET6:
		return "ipv6";
	}
	return NULL;
}

int
__ni_netcf_set_af(const char *name, int *afp)
{
	if (!strcmp(name, "ipv4")) {
		*afp = AF_INET;
	} else if (!strcmp(name, "ipv6")) {
		*afp = AF_INET6;
	} else {
		return -1;
	}
	return 0;
}

struct __ni_netcf_iftype_map {
	int		type;
	const char *	name;
	unsigned int	arp_type;
} __ni_netcf_iftype_map[] = {
      {	NI_IFTYPE_UNKNOWN,	"unknown",		ARPHRD_NONE	},
      {	NI_IFTYPE_LOOPBACK,	"loopback",		ARPHRD_LOOPBACK	},
      {	NI_IFTYPE_ETHERNET,	"ethernet",		ARPHRD_ETHER	},
      {	NI_IFTYPE_BRIDGE,	"bridge",		ARPHRD_ETHER	},
      {	NI_IFTYPE_BOND,		"bond",			ARPHRD_ETHER	},
      {	NI_IFTYPE_VLAN,		"vlan",			ARPHRD_ETHER	},
      {	NI_IFTYPE_WIRELESS,	"wireless",		ARPHRD_ETHER	},
      {	NI_IFTYPE_INFINIBAND,	"infiniband",		ARPHRD_INFINIBAND },
      {	NI_IFTYPE_PPP,		"ppp",			ARPHRD_PPP	},
      {	NI_IFTYPE_SLIP,		"slip",			ARPHRD_SLIP	},
      {	NI_IFTYPE_SIT,		"sit",			ARPHRD_SIT	},
      {	NI_IFTYPE_GRE,		"gre",			ARPHRD_IPGRE	},
      {	NI_IFTYPE_ISDN,		"isdn",			ARPHRD_NONE	},
      {	NI_IFTYPE_TUNNEL,	"tunnel",		ARPHRD_TUNNEL	},
      {	NI_IFTYPE_TUNNEL6,	"tunnel6",		ARPHRD_TUNNEL6	},
      {	NI_IFTYPE_TUN,		"virtual-tunnel",	ARPHRD_ETHER	},
      {	NI_IFTYPE_TAP,		"virtual-tap",		ARPHRD_ETHER	},
      {	NI_IFTYPE_DUMMY,	"dummy",		ARPHRD_LOOPBACK	},

      {	NI_IFTYPE_UNKNOWN, NULL }
};

static const char *
__ni_netcf_get_iftype(const ni_interface_t *ifp)
{
	struct __ni_netcf_iftype_map *mp = __ni_netcf_iftype_map;

	for (; mp->name; ++mp) {
		if (mp->type == ifp->link.type)
			return mp->name;
	}

	return NULL;
}

static int
__ni_netcf_set_iftype(ni_interface_t *ifp, const char *name)
{
	struct __ni_netcf_iftype_map *mp = __ni_netcf_iftype_map;

	for (; mp->name; ++mp) {
		if (!strcmp(mp->name, name)) {
			ifp->link.type = mp->type;
			ifp->link.arp_type = mp->arp_type;
			return 0;
		}
	}

	return -1;
}

static const char *
__ni_netcf_get_startmode(const ni_interface_t *ifp)
{
	if (ifp->startmode.ifaction[NI_IFACTION_BOOT].action == NI_INTERFACE_START)
		return "onboot";
	return "none";
}

static int
__ni_netcf_set_startmode(ni_interface_t *ifp, const char *name)
{
	if (!strcmp(name, "onboot")) {
		ifp->startmode.ifaction[NI_IFACTION_BOOT].action  = NI_INTERFACE_START;
		ifp->startmode.ifaction[NI_IFACTION_SHUTDOWN].action  = NI_INTERFACE_STOP;
		ifp->startmode.ifaction[NI_IFACTION_MANUAL_UP].action  = NI_INTERFACE_START;
		ifp->startmode.ifaction[NI_IFACTION_MANUAL_DOWN].action  = NI_INTERFACE_STOP;
	} else if (!strcmp(name, "none")) {
		ifp->startmode.ifaction[NI_IFACTION_BOOT].action  = NI_INTERFACE_IGNORE;
		ifp->startmode.ifaction[NI_IFACTION_SHUTDOWN].action  = NI_INTERFACE_STOP;
		ifp->startmode.ifaction[NI_IFACTION_MANUAL_UP].action  = NI_INTERFACE_START;
		ifp->startmode.ifaction[NI_IFACTION_MANUAL_DOWN].action  = NI_INTERFACE_STOP;
	} else
		return -1;
	return 0;
}

/*
 * Bondig mode text representation
 */
static ni_intmap_t __bonding_modes[] = {
	{ "balance-rr",		NI_BOND_MODE_BALANCE_RR },
	{ "active-backup",	NI_BOND_MODE_ACTIVE_BACKUP },
	{ "balance-xor",	NI_BOND_MODE_BALANCE_XOR },
	{ "broadcast",		NI_BOND_MODE_BROADCAST },
	{ "802.3ad",		NI_BOND_MODE_802_3AD },
	{ "balance-tlb",	NI_BOND_MODE_BALANCE_TLB },
	{ "balance-alb",	NI_BOND_MODE_BALANCE_ALB },

	{ NULL }
};

static const char *
__ni_netcf_get_bonding_mode(int mode)
{
	const char *value;

	value = ni_format_int_mapped(mode, __bonding_modes);
	return value?: "balance-rr";
}

static int
__ni_netcf_set_bonding_mode(const char *value, unsigned int *var)
{
	return ni_parse_int_mapped(value, __bonding_modes, var);
}


/*
 * Bonding arpmon - validate modes
 */
static ni_intmap_t __arpmon_validation[] = {
	{ "none",		NI_BOND_VALIDATE_NONE },
	{ "active",		NI_BOND_VALIDATE_ACTIVE },
	{ "backup",		NI_BOND_VALIDATE_BACKUP },
	{ "all",		NI_BOND_VALIDATE_ALL },

	{ NULL }
};

static const char *
__ni_netcf_get_arpmon_validation(int mode)
{
	const char *value;

	value = ni_format_int_mapped(mode, __arpmon_validation);
	return value?: "none";
}

static int
__ni_netcf_set_arpmon_validation(const char *value, unsigned int *var)
{
	return ni_parse_int_mapped(value, __arpmon_validation, var);
}

/*
static const char *
__ni_netcf_get_boolean(int val)
{
	return val? "on" : "off";
}
*/

static int
__ni_netcf_get_boolean_attr(const xml_node_t *node, const char *attrname, int *var)
{
	const char *attrval;

	*var = 0;
	if (!(attrval = xml_node_get_attr(node, attrname)))
		return -1;

	if (!strcmp(attrval, "on") || !strcmp(attrval, "yes"))
		*var = 1;
	else if (!strcmp(attrval, "off") || !strcmp(attrval, "no"))
		*var = 0;
	else {
		ni_error("unexpected boolean value <%s %s=\"%s\"> ignored",
				node->name, attrname, attrval);
		return -1;
	}
	return 0;
}

static void
__ni_netcf_add_string_child(xml_node_t *node, const char *name, const char *value)
{
	if (value) {
		node = xml_node_new(name, node);
		xml_node_set_cdata(node, value);
	}
}

static void
__ni_netcf_add_uint_child(xml_node_t *node, const char *name, unsigned int value)
{
	char buffer[64];

	snprintf(buffer, sizeof(buffer), "%u", value);
	__ni_netcf_add_string_child(node, name, buffer);
}

static void
__ni_netcf_add_string_array_child(xml_node_t *node, const char *name, const ni_string_array_t *list)
{
	unsigned int i;

	if (list && list->count) {
		for (i = 0; i < list->count; ++i)
			__ni_netcf_add_string_child(node, name, list->data[i]);
	}
}

static void
__ni_netcf_get_string_child(const xml_node_t *node, const char *name, char **var)
{
	node = xml_node_get_child(node, name);

	ni_string_free(var);
	if (node && node->cdata)
		ni_string_dup(var, node->cdata);
}

static void
__ni_netcf_get_uint_child(const xml_node_t *node, const char *name, unsigned int *var)
{
	node = xml_node_get_child(node, name);

	if (node && node->cdata)
		*var = strtoul(node->cdata, NULL, 0);
	else
		*var = 0;
}

static void
__ni_netcf_get_string_array_child(const xml_node_t *node, const char *name, ni_string_array_t *list)
{
	for (node = node->children; node; node = node->next) {
		if (node->name && !strcmp(node->name, name) && node->cdata)
			ni_string_array_append(list, node->cdata);
	}
}
