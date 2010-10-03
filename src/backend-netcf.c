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
#include <wicked/xml.h>

#include "netinfo_priv.h"
#include "kernel.h"

static ni_interface_t *	__ni_netcf_xml_to_interface(ni_syntax_t *, ni_handle_t *, xml_node_t *);
static int		__ni_netcf_xml_to_vlan(ni_syntax_t *, ni_handle_t *,
					ni_interface_t *, xml_node_t *);
static int		__ni_netcf_xml_to_bridge(ni_syntax_t *, ni_handle_t *,
					ni_interface_t *, xml_node_t *);
static int		__ni_netcf_xml_to_bonding(ni_syntax_t *, ni_handle_t *,
					ni_interface_t *, xml_node_t *);
static int		__ni_netcf_xml_to_static_ifcfg(ni_syntax_t *syntax, ni_handle_t *nih,
				int af, ni_interface_t *ifp, xml_node_t *protnode);
static int		__ni_netcf_xml_to_dhcp(ni_syntax_t *, ni_handle_t *,
				ni_dhclient_info_t *, xml_node_t *);

static xml_node_t *	__ni_netcf_xml_from_interface(ni_syntax_t *, ni_handle_t *,
				const ni_interface_t *, xml_node_t *);
static void		__ni_netcf_xml_from_address_config(ni_syntax_t *syntax, ni_handle_t *nih,
				const ni_afinfo_t *afi,
				const ni_interface_t *ifp, xml_node_t *ifnode);
static xml_node_t *	__ni_netcf_xml_from_static_ifcfg(ni_syntax_t *syntax, ni_handle_t *nih,
				int af, const ni_interface_t *ifp, xml_node_t *);
static void		__ni_netcf_xml_from_route(ni_route_t *, xml_node_t *);
static void		__ni_netcf_xml_from_bridge(ni_syntax_t *syntax, ni_handle_t *nih,
				ni_bridge_t *bridge, xml_node_t *);
static void		__ni_netcf_xml_from_bonding(ni_syntax_t *syntax, ni_handle_t *nih,
				ni_bonding_t *bonding, xml_node_t *);
static void		__ni_netcf_xml_from_vlan(ni_syntax_t *syntax, ni_handle_t *nih,
				ni_vlan_t *vlan, xml_node_t *fp);
static void		__ni_netcf_xml_from_dhcp(ni_syntax_t *, ni_handle_t *,
				ni_dhclient_info_t *, xml_node_t *);
static xml_node_t *	__ni_netcf_xml_from_lease(ni_syntax_t *, const ni_addrconf_state_t *, xml_node_t *parent);
static ni_addrconf_state_t *__ni_netcf_xml_to_lease(ni_syntax_t *, const xml_node_t *);

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
static const char *	__ni_netcf_get_boolean(int val);
static int		__ni_netcf_get_boolean_attr(xml_node_t *, const char *, int *);
static void		__ni_netcf_add_string_child(xml_node_t *, const char *, const char *);
static void		__ni_netcf_add_string_array_child(xml_node_t *, const char *, const ni_string_array_t *);
static void		__ni_netcf_get_string_child(const xml_node_t *, const char *, char **);
static void		__ni_netcf_get_string_array_child(const xml_node_t *, const char *, ni_string_array_t *);

ni_syntax_t *
__ni_syntax_netcf(const char *pathname)
{
	ni_syntax_t *syntax;

	syntax = calloc(1, sizeof(ni_syntax_t));
	syntax->schema = "netcf";
	syntax->base_path = pathname? strdup(pathname) : NULL;
	syntax->xml_from_interface = __ni_netcf_xml_from_interface;
	syntax->xml_to_interface = __ni_netcf_xml_to_interface;
	syntax->xml_from_lease = __ni_netcf_xml_from_lease;
	syntax->xml_to_lease = __ni_netcf_xml_to_lease;

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
__ni_netcf_xml_to_interface(ni_syntax_t *syntax, ni_handle_t *nih, xml_node_t *ifnode)
{
	ni_interface_t *ifp;
	const char *attrval;
	xml_node_t *node;

	if ((attrval = xml_node_get_attr(ifnode, "name")) != NULL) {
		ifp = ni_interface_new(nih, attrval, 0);
	} else {
		ifp = ni_interface_new(nih, "anon", 0);
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
		if ((attrval = xml_node_get_attr(node, "link")) && !strcmp(attrval, "up"))
			ifp->flags |= IFF_LOWER_UP;
		if ((attrval = xml_node_get_attr(node, "network")) && !strcmp(attrval, "up"))
			ifp->flags |= IFF_UP;
	}

	node = xml_node_get_child(ifnode, "start");
	if (node && (attrval = xml_node_get_attr(node, "mode")) != NULL) {
		if (__ni_netcf_set_startmode(ifp, attrval) < 0) {
			error("unknown/unsupported interface start mode %s", attrval);
			return NULL;
		}
	}

	node = xml_node_get_child(ifnode, "mtu");
	if (node && xml_node_get_attr_uint(node, "size", &ifp->mtu) < 0)
		return NULL;

	node = xml_node_get_child(ifnode, "mac");
	if (node && (attrval = xml_node_get_attr(node, "address")) != NULL) {
		if (ni_link_address_parse(&ifp->hwaddr, ifp->type, attrval) < 0) {
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

	/* Hunt for "protocol" children */
	for (node = ifnode->children; node; node = node->next) {
		ni_afinfo_t *afi;
		xml_node_t *child;

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

		if ((child = xml_node_get_child(node, "dhcp")) != NULL) {
			afi->dhcp = ni_dhclient_info_new();
			afi->config = NI_ADDRCONF_DHCP;
			if (__ni_netcf_xml_to_dhcp(syntax, nih, afi->dhcp, child) < 0) {
				ni_error("error parsing dhcp information");
				return NULL;
			}
			continue;
		}

		/* Looks like we have a static configuration */
		if (__ni_netcf_xml_to_static_ifcfg(syntax, nih, afi->family, ifp, node))
			return NULL;
		afi->config = NI_ADDRCONF_STATIC;
	}

	switch (ifp->type) {
	case NI_IFTYPE_BRIDGE:
		if (__ni_netcf_xml_to_bridge(syntax, nih, ifp, ifnode))
			return NULL;
		break;
	case NI_IFTYPE_BOND:
		if (__ni_netcf_xml_to_bonding(syntax, nih, ifp, ifnode))
			return NULL;
		break;
	case NI_IFTYPE_VLAN:
		if (__ni_netcf_xml_to_vlan(syntax, nih, ifp, ifnode))
			return NULL;
		break;
	}
	return ifp;
}

int
__ni_netcf_xml_to_vlan(ni_syntax_t *syntax, ni_handle_t *nih,
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
	vlan->interface_name = strdup(attrval);

	return 0;
}

/*
 * Obtain bridge configuration from XML
 */
static int
__ni_netcf_xml_to_bridge(ni_syntax_t *syntax, ni_handle_t *nih,
				ni_interface_t *ifp, xml_node_t *ifnode)
{
	xml_node_t *brnode, *child;
	ni_bridge_t *bridge;

	if (!(brnode = xml_node_get_child(ifnode, "bridge"))) {
		error("bridge interface %s: xml config has no bridge element", ifp->name);
		return -1;
	}

	bridge = ni_interface_get_bridge(ifp);

	if (__ni_netcf_get_boolean_attr(brnode, "stp", &bridge->stp_enabled) < 0) {
		error("bridge interface %s: bridge element lacks stp attribute", ifp->name);
		return -1;
	}
	xml_node_get_attr_uint(brnode, "forward-delay", &bridge->forward_delay);

	for (child = brnode->children; child; child = child->next) {
		const char *ifname;

		if (strcmp(child->name, "interface"))
			continue;

		if (!(ifname = xml_node_get_attr(child, "name"))) {
			error("bridge interface %s: interface element lacks name attribute", ifp->name);
			return -1;
		}

		ni_bridge_add_port(bridge, ifname);
	}

	return 0;
}

/*
 * Obtain bonding configuration from XML
 */
int
__ni_netcf_xml_to_bonding(ni_syntax_t *syntax, ni_handle_t *nih,
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
			const char *addrname, struct sockaddr_storage *addr,
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
__ni_netcf_xml_to_static_ifcfg(ni_syntax_t *syntax, ni_handle_t *nih,
			int af, ni_interface_t *ifp, xml_node_t *protnode)
{
	xml_node_t *node;

	nih->seqno++;

	for (node = protnode->children; node; node = node->next) {
		struct sockaddr_storage addr;
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
		struct sockaddr_storage dest_addr, gw_addr;
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

		ni_interface_add_route(nih, ifp, prefixlen, &dest_addr, &gw_addr);
	}


	return 0;
}

/*
 * Extract DHCP configuration from XML
 */
static int
__ni_netcf_xml_to_dhcp(ni_syntax_t *syntax, ni_handle_t *nih,
			ni_dhclient_info_t *dhcp, xml_node_t *dhnode)
{
	xml_node_t *child;
	const char *attrval;

	if (syntax->strict) {
		/* strict netcf only allows peerdns="yes" so far */
		__ni_netcf_get_boolean_attr(dhnode, "peerdns", &dhcp->update.resolver);
		return 0;
	}

	if ((child = xml_node_get_child(dhnode, "lease")) != NULL) {
		if ((attrval = xml_node_get_attr(child, "timeout")) != NULL) {
			if (!strcmp(attrval, "infinite"))
				dhcp->lease.timeout = DHCP_TIMEOUT_INFINITE;
			else if (ni_parse_int(attrval, &dhcp->lease.timeout) < 0)
				return -1;
		}

		dhcp->lease.reuse_unexpired = !!xml_node_get_child(child, "reuse-unexpired");
		dhcp->lease.release_on_exit = !!xml_node_get_child(child, "release-on-exit");
	}

	if ((child = xml_node_get_child(dhnode, "request")) != NULL) {
		if ((attrval = xml_node_get_attr(child, "hostname")) != NULL)
			ni_string_dup(&dhcp->request.hostname, attrval);
		if ((attrval = xml_node_get_attr(child, "clientid")) != NULL)
			ni_string_dup(&dhcp->request.clientid, attrval);
		if ((attrval = xml_node_get_attr(child, "vendor-class")) != NULL)
			ni_string_dup(&dhcp->request.vendor_class, attrval);

		if ((attrval = xml_node_get_attr(child, "lease-time")) != NULL) {
			if (!strcmp(attrval, "infinite"))
				dhcp->request.lease_time = DHCP_TIMEOUT_INFINITE;
			else if (ni_parse_int(attrval, &dhcp->request.lease_time) < 0)
				return -1;
		}
	}

	if ((child = xml_node_get_child(dhnode, "update")) != NULL) {
		dhcp->update.hostname = !!xml_node_get_child(child, "hostname");
		dhcp->update.resolver = !!xml_node_get_child(child, "resolver");
		dhcp->update.hosts_file = !!xml_node_get_child(child, "hosts-file");
		dhcp->update.default_route = !!xml_node_get_child(child, "default-route");
		dhcp->update.ntp_servers = !!xml_node_get_child(child, "ntp-servers");
		dhcp->update.nis_servers = !!xml_node_get_child(child, "nis-servers");
		dhcp->update.smb_config = !!xml_node_get_child(child, "smb-config");
	}

	return 0;
}

/*
 * Build XML structure for a given interface
 */
xml_node_t *
__ni_netcf_xml_from_interface(ni_syntax_t *syntax, ni_handle_t *nih,
			const ni_interface_t *ifp, xml_node_t *parent)
{
	xml_node_t *ifnode, *node;

	ifnode = xml_node_new("interface", parent);
	xml_node_add_attr(ifnode, "type", __ni_netcf_get_iftype(ifp));
	xml_node_add_attr(ifnode, "name", ifp->name);

	if (!ni_uuid_is_null(&ifp->uuid)) {
		node = xml_node_new("uuid", ifnode);
		xml_node_set_cdata(node, ni_uuid_print(&ifp->uuid));
	}

	/* Variant netcf */
	if (!syntax->strict && ifp->flags) {
		node = xml_node_new("status", ifnode);

		xml_node_add_attr(node, "link",
				(ifp->flags & IFF_LOWER_UP)? "up" : "down");
		xml_node_add_attr(node, "network",
				(ifp->flags & IFF_UP)? "up" : "down");
	}

	node = xml_node_new("start", ifnode);
	xml_node_add_attr(node, "mode", __ni_netcf_get_startmode(ifp));
	if (ifp->mtu) {
		node = xml_node_new("mtu", ifnode);
		xml_node_add_attr_uint(node, "size", ifp->mtu);
	}

	if (ifp->hwaddr.len) {
		node = xml_node_new("mac", ifnode);
		xml_node_add_attr(node, "address", ni_link_address_print(&ifp->hwaddr));
	}

	__ni_netcf_xml_from_address_config(syntax, nih, &ifp->ipv4, ifp, ifnode);
	__ni_netcf_xml_from_address_config(syntax, nih, &ifp->ipv6, ifp, ifnode);

	if (ifp->bridge)
		__ni_netcf_xml_from_bridge(syntax, nih, ifp->bridge, ifnode);
	if (ifp->bonding)
		__ni_netcf_xml_from_bonding(syntax, nih, ifp->bonding, ifnode);
	if (ifp->vlan)
		__ni_netcf_xml_from_vlan(syntax, nih, ifp->vlan, ifnode);

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
__ni_netcf_xml_from_address_config(ni_syntax_t *syntax, ni_handle_t *nih,
			const ni_afinfo_t *afi,
			const ni_interface_t *ifp, xml_node_t *ifnode)
{
	const char *acname;
	unsigned int type;
	xml_node_t *protnode = NULL;

	switch (afi->config) {
	case NI_ADDRCONF_STATIC:
		protnode = __ni_netcf_xml_from_static_ifcfg(syntax, nih, afi->family, ifp, ifnode);
		break;

	case NI_ADDRCONF_DHCP:
	case NI_ADDRCONF_IBFT: /* Variant netcf */
		if (!protnode)
			protnode = __ni_netcf_make_protocol_node(ifnode, afi->family);

		if (afi->config == NI_ADDRCONF_DHCP) {
			__ni_netcf_xml_from_dhcp(syntax, nih, afi->dhcp, protnode);
		} else {
			/* Create node with no attrs or children */
			acname = ni_addrconf_type_to_name(afi->config);
			assert(acname);

			xml_node_new(acname, protnode);
		}
		break;
	}

	for (type = 0; type < __NI_ADDRCONF_MAX; ++type) {
		ni_addrconf_state_t *lease = afi->lease[type];

		if (lease) {
			if (!protnode)
				protnode = __ni_netcf_make_protocol_node(ifnode, afi->family);
			__ni_netcf_xml_from_lease(syntax, lease, ifnode);
		}
	}
}

static xml_node_t *
__ni_netcf_xml_from_static_ifcfg(ni_syntax_t *syntax, ni_handle_t *nih, int af,
			const ni_interface_t *ifp, xml_node_t *ifnode)
{
	xml_node_t *protnode = NULL;
	ni_address_t *ap;
	ni_route_t *rp;

	nih->seqno++;
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

		for (rp = nih->routes; rp; rp = rp->next) {
			// FIXME: this check works for IPv4 only;
			// IPv6 routing is different.
			if (ni_address_can_reach(ap, &rp->nh.gateway))
				rp->seq = nih->seqno;
		}
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
		for (rp = nih->routes; rp; rp = rp->next) {
			/* strict netcf: ignore non-default routes; we cannot map these. */
			if (syntax->strict && rp->prefixlen != 0)
				continue;
			if (rp->seq == nih->seqno)
				__ni_netcf_xml_from_route(rp, protnode);
		}
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
static void
__ni_netcf_xml_from_bridge(ni_syntax_t *syntax, ni_handle_t *nih,
				ni_bridge_t *bridge, xml_node_t *ifnode)
{
	xml_node_t *brnode;
	unsigned int i;

	brnode = xml_node_new("bridge", ifnode);
	xml_node_add_attr(brnode, "stp", __ni_netcf_get_boolean(bridge->stp_enabled));
	xml_node_add_attr_uint(brnode, "forward-delay", bridge->forward_delay);

	/* FIXME: strict netcf now wants to represent a VLAN port as
	 *  <vlan tag="..."><interface ../></vlan>
	 */
	for (i = 0; i < bridge->port_names.count; ++i)
		__ni_netcf_xml_from_slave_interface(bridge->port_names.data[i], brnode);
}

/*
 * Generate XML representation of a bonding configuration
 */
void
__ni_netcf_xml_from_bonding(ni_syntax_t *syntax, ni_handle_t *nih,
			ni_bonding_t *bonding, xml_node_t *ifnode)
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
__ni_netcf_xml_from_vlan(ni_syntax_t *syntax, ni_handle_t *nih, ni_vlan_t *vlan,
			xml_node_t *ifnode)
{
	xml_node_t *vlnode;

	vlnode = xml_node_new("vlan", ifnode);
	xml_node_add_attr_uint(vlnode, "tag", vlan->tag);
	if (vlan->interface_name) {
		xml_node_t *ifchild;

		ifchild = xml_node_new("interface", vlnode);
		xml_node_add_attr(ifchild, "name", vlan->interface_name);
	}
}

/*
 * Generate XML representation for DHCP client configuration
 */
static void
__ni_netcf_xml_from_dhcp(ni_syntax_t *syntax, ni_handle_t *nih,
			ni_dhclient_info_t *dhcp, xml_node_t *proto_node)
{
	xml_node_t *dhnode, *child;

	dhnode = xml_node_new("dhcp", proto_node);
	if (dhcp == NULL)
		return;

	if (syntax->strict) {
		/* strict netcf only allows peerdns="yes" so far */
		if (dhcp->update.resolver)
			xml_node_add_attr(dhnode, "peerdns", "yes");
		return;
	}

	if (dhcp->lease.timeout || dhcp->lease.reuse_unexpired || dhcp->lease.release_on_exit) {
		child = xml_node_new("lease", dhnode);

		if (dhcp->lease.timeout == DHCP_TIMEOUT_INFINITE)
			xml_node_add_attr(child, "timeout", "infinite");
		else if (dhcp->lease.timeout)
			xml_node_add_attr_uint(child, "timeout", dhcp->lease.timeout);

		if (dhcp->lease.reuse_unexpired)
			xml_node_new("reuse-unexpired", child);
		if (dhcp->lease.release_on_exit)
			xml_node_new("release-on-exit", child);
	}

	if (dhcp->request.hostname || dhcp->request.clientid
	 || dhcp->request.vendor_class || dhcp->request.lease_time) {
		child = xml_node_new("request", dhnode);

		if (dhcp->request.hostname)
			xml_node_add_attr(child, "hostname", dhcp->request.hostname);
		if (dhcp->request.clientid)
			xml_node_add_attr(child, "clientid", dhcp->request.clientid);
		if (dhcp->request.vendor_class)
			xml_node_add_attr(child, "vendor-class", dhcp->request.vendor_class);

		if (dhcp->request.lease_time == DHCP_TIMEOUT_INFINITE)
			xml_node_add_attr(child, "lease-time", "infinite");
		else if (dhcp->request.lease_time)
			xml_node_add_attr_uint(child, "lease-time", dhcp->request.lease_time);
	}

	if (dhcp->update.hostname
	 || dhcp->update.resolver
	 || dhcp->update.hosts_file
	 || dhcp->update.default_route
	 || dhcp->update.ntp_servers
	 || dhcp->update.nis_servers
	 || dhcp->update.smb_config) {
		child = xml_node_new("update", dhnode);

		if (dhcp->update.hostname)
			xml_node_new("hostname", child);
		if (dhcp->update.resolver)
			xml_node_new("resolver", child);
		if (dhcp->update.hosts_file)
			xml_node_new("hosts-file", child);
		if (dhcp->update.default_route)
			xml_node_new("default-route", child);
		if (dhcp->update.ntp_servers)
			xml_node_new("ntp-servers", child);
		if (dhcp->update.nis_servers)
			xml_node_new("nis-servers", child);
		if (dhcp->update.smb_config)
			xml_node_new("smb-config", child);
	}
}

/*
 * Generate XML from lease
 */
static xml_node_t *
__ni_netcf_xml_from_lease(ni_syntax_t *syntax, const ni_addrconf_state_t *lease, xml_node_t *parent)
{
	xml_node_t *node;

	node = xml_node_new("lease", parent);
	xml_node_add_attr(node, "type", ni_addrconf_type_to_name(lease->type));
	xml_node_add_attr(node, "family", ni_addrfamily_type_to_name(lease->family));
	xml_node_add_attr(node, "state", ni_addrconf_state_to_name(lease->state));

	__ni_netcf_add_string_child(node, "hostname", lease->hostname);
	__ni_netcf_add_string_array_child(node, "log-server", &lease->log_servers);
	__ni_netcf_add_string_array_child(node, "dns-server", &lease->dns_servers);
	__ni_netcf_add_string_array_child(node, "dns-search", &lease->dns_search);
	__ni_netcf_add_string_array_child(node, "nis-server", &lease->nis_servers);
	__ni_netcf_add_string_child(node, "nis-domain", lease->nis_domain);
	__ni_netcf_add_string_array_child(node, "ntp-server", &lease->ntp_servers);
	__ni_netcf_add_string_array_child(node, "slp-server", &lease->slp_servers);
	__ni_netcf_add_string_array_child(node, "netbios-server", &lease->netbios_servers);
	__ni_netcf_add_string_child(node, "netbios-domain", lease->netbios_domain);

	{
		ni_handle_t dummy_handle;
		ni_interface_t dummy;

		memset(&dummy_handle, 0, sizeof(dummy_handle));
		memset(&dummy, 0, sizeof(dummy));
		dummy.addrs = lease->addrs;
		dummy.routes = lease->routes;
		__ni_netcf_xml_from_static_ifcfg(syntax, &dummy_handle,
				lease->family, &dummy, node);
	}

	return node;
}

static ni_addrconf_state_t *
__ni_netcf_xml_to_lease(ni_syntax_t *syntax, const xml_node_t *node)
{
	ni_addrconf_state_t *lease = NULL;
	ni_handle_t *nih = NULL;
	xml_node_t *prot;
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

	lease = ni_addrconf_state_new(lease_type, lease_family);
	lease->state = lease_state;
	__ni_netcf_get_string_child(node, "hostname", &lease->hostname);
	__ni_netcf_get_string_array_child(node, "log-server", &lease->log_servers);
	__ni_netcf_get_string_array_child(node, "dns-server", &lease->dns_servers);
	__ni_netcf_get_string_array_child(node, "dns-search", &lease->dns_search);
	__ni_netcf_get_string_array_child(node, "nis-server", &lease->nis_servers);
	__ni_netcf_get_string_child(node, "nis-domain", &lease->nis_domain);
	__ni_netcf_get_string_array_child(node, "ntp-server", &lease->ntp_servers);
	__ni_netcf_get_string_array_child(node, "slp-server", &lease->slp_servers);
	__ni_netcf_get_string_array_child(node, "netbios-server", &lease->netbios_servers);
	__ni_netcf_get_string_child(node, "netbios-domain", &lease->netbios_domain);

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
		if (!nih)
			nih = ni_dummy_open();

		memset(&dummy, 0, sizeof(dummy));
		if (__ni_netcf_xml_to_static_ifcfg(syntax, nih, af, &dummy, prot))
			goto failed;

		lease->addrs = dummy.addrs;
		lease->routes = dummy.routes;
	}

	if (nih)
		ni_close(nih);
	return lease;

failed:
	if (lease)
		ni_addrconf_state_free(lease);
	if (nih)
		ni_close(nih);
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
		if (mp->type == ifp->type)
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
			ifp->type = mp->type;
			ifp->arp_type = mp->arp_type;
			return 0;
		}
	}

	return -1;
}

static const char *
__ni_netcf_get_startmode(const ni_interface_t *ifp)
{
	switch (ifp->startmode) {
	default:
	case NI_START_ONBOOT:
		return "onboot";
	case NI_START_DISABLE:
	case NI_START_MANUAL:
		return "none";
	}
}

static int
__ni_netcf_set_startmode(ni_interface_t *ifp, const char *name)
{
	if (!strcmp(name, "onboot"))
		ifp->startmode = NI_START_ONBOOT;
	else
	if (!strcmp(name, "none"))
		ifp->startmode = NI_START_MANUAL;
	else
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


static const char *
__ni_netcf_get_boolean(int val)
{
	return val? "on" : "off";
}

static int
__ni_netcf_get_boolean_attr(xml_node_t *node, const char *attrname, int *var)
{
	const char *attrval;

	*var = 0;
	if (!(attrval = xml_node_get_attr(node, attrname)))
		return -1;

	if (!strcmp(attrval, "on") || !strcmp(attrval, "yes"))
		*var = 1;
	else if (!strcmp(attrval, "off") || !strcmp(attrval, "no"))
		*var = 0;
	else
		error("unexpected boolean value <%s %s=\"%s\"> ignored",
				node->name, attrname, attrval);
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
__ni_netcf_get_string_array_child(const xml_node_t *node, const char *name, ni_string_array_t *list)
{
	for (node = node->children; node; node = node->next) {
		if (node->name && !strcmp(node->name, name) && node->cdata)
			ni_string_array_append(list, node->cdata);
	}
}
