/*
 *	wicked client configuration reading for dracut cmdline schema.
 *
 *	Copyright (C) 2019 SUSE Software Solutions Germany GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Rubén Torrero Marijnissen <rtorreromarijnissen@suse.com>
 *		Marius Tomaschewski <mt@suse.de>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <net/if_arp.h>
#include <sys/time.h>
#include <netlink/netlink.h>

#include <wicked/util.h>
#include <wicked/address.h>
#include <wicked/types.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/xml.h>
#include <wicked/netinfo.h>
#include <wicked/bridge.h>
#include <wicked/vlan.h>
#include <wicked/bonding.h>
#include <wicked/team.h>

#include "client/wicked-client.h"
#include "client/read-config.h"
#include "client/ifxml.h"
#include "client/dracut/cmdline.h"
#include "buffer.h"

/*
 * default bond settings specified in dracut.cmdline(7) with
 * additional explicit miimon=100 -- also a kernel default
 * same to mode=balance-rr (unlucky as it needs switch setup).
 */
#define NI_DRACUT_CMDLINE_DEF_BOND_NAME		"bond0"
#define NI_DRACUT_CMDLINE_DEF_BOND_SLAVES	"eth0,eth1"
#define NI_DRACUT_CMDLINE_DEF_BOND_OPTIONS	"mode=balance-rr,miimon=100"

 /*
  * default team settings specified in dracut.cmdline(7) are
  * defined as: `team=team0:eth0,eth1:activebackup`
  * (see recent dracut version, older don't specify this).
  */
#define NI_DRACUT_CMDLINE_DEF_TEAM_NAME		"team0"
#define NI_DRACUT_CMDLINE_DEF_TEAM_PORTS	"eth0,eth1"
#define NI_DRACUT_CMDLINE_DEF_TEAM_RUNNER	"activebackup"

typedef enum {
	NI_DRACUT_PARAM_IFNAME = 0U,
	NI_DRACUT_PARAM_BOND,
	NI_DRACUT_PARAM_TEAM,
	NI_DRACUT_PARAM_VLAN,
	NI_DRACUT_PARAM_BRIDGE,
	NI_DRACUT_PARAM_IP,
} ni_dracut_cmdline_param_t;

static const ni_intmap_t	dracut_params[] = {
	/* interface type vars  */
	{ "bond",		NI_DRACUT_PARAM_BOND		},
	{ "team",		NI_DRACUT_PARAM_TEAM		},
	{ "vlan",		NI_DRACUT_PARAM_VLAN		},
	{ "bridge",		NI_DRACUT_PARAM_BRIDGE		},

	/* ip and route config  */
	{ "ip",			NI_DRACUT_PARAM_IP		},

	/* interface matches    */
	{ "ifname",		NI_DRACUT_PARAM_IFNAME		},

	{ NULL,			-1U				}
};

typedef enum {
	NI_DRACUT_BOOTPROTO_OFF = 0U,
	NI_DRACUT_BOOTPROTO_NONE,
	NI_DRACUT_BOOTPROTO_DHCP,
	NI_DRACUT_BOOTPROTO_ON,
	NI_DRACUT_BOOTPROTO_ANY,
	NI_DRACUT_BOOTPROTO_DHCP6,
	NI_DRACUT_BOOTPROTO_AUTO6,
	NI_DRACUT_BOOTPROTO_IBFT,
} ni_dracut_cmdline_bootproto_t;

static const ni_intmap_t	bootprotos[] = {
	{ "off",		NI_DRACUT_BOOTPROTO_OFF		},
	{ "none",		NI_DRACUT_BOOTPROTO_NONE	},
	{ "dhcp",		NI_DRACUT_BOOTPROTO_DHCP	},
	{ "on",			NI_DRACUT_BOOTPROTO_ON		},
	{ "any",		NI_DRACUT_BOOTPROTO_ANY		},
	{ "dhcp6",		NI_DRACUT_BOOTPROTO_DHCP6	},
	{ "auto6",		NI_DRACUT_BOOTPROTO_AUTO6	},
	{ "ibft",		NI_DRACUT_BOOTPROTO_IBFT	},

	{ NULL,			-1U				}
};

static inline char *
token_peek(char *ptr, char sep)
{
	return ptr ? strchr(ptr, sep) : NULL;
}

static inline char *
token_next(char *ptr, char sep)
{
	char *end;

	if ((end = token_peek(ptr, sep)))
		*end++ = '\0';

	return end;
}

static ni_bool_t
ni_dracut_cmdline_add_bootproto_dhcp(ni_compat_netdev_t *nd, const char *val)
{
	ni_ipv4_devinfo_t *ipv4;

	if (!(ipv4 = ni_netdev_get_ipv4(nd->dev)))
		return FALSE;

	ni_tristate_set(&ipv4->conf.enabled, TRUE);
	ni_tristate_set(&ipv4->conf.arp_verify, TRUE);

	nd->dhcp4.enabled = TRUE;
	nd->dhcp4.defer_timeout = 15; /* dhcp4 seems to need it explicitly */

	return TRUE;
}

static ni_bool_t
ni_dracut_cmdline_add_bootproto_dhcp6(ni_compat_netdev_t *nd, const char *val)
{
	ni_ipv6_devinfo_t *ipv6;

	if (!(ipv6 = ni_netdev_get_ipv6(nd->dev)))
		return FALSE;
	ni_tristate_set(&ipv6->conf.enabled, TRUE);

	nd->dhcp6.enabled = TRUE;

	return TRUE;
}

static ni_bool_t
ni_dracut_cmdline_parse_bootproto(ni_compat_netdev_t *nd, const char *val)
{
	unsigned int bootproto_type;

	if (ni_parse_uint_mapped(val, bootprotos, &bootproto_type) < 0)
		return FALSE;

	switch (bootproto_type) {
	case NI_DRACUT_BOOTPROTO_OFF:
	case NI_DRACUT_BOOTPROTO_NONE:
		return TRUE;

	case NI_DRACUT_BOOTPROTO_ON:
	case NI_DRACUT_BOOTPROTO_ANY:
	case NI_DRACUT_BOOTPROTO_DHCP:
		return ni_dracut_cmdline_add_bootproto_dhcp(nd, val);

	case NI_DRACUT_BOOTPROTO_DHCP6:
		return ni_dracut_cmdline_add_bootproto_dhcp6(nd, val);

	case NI_DRACUT_BOOTPROTO_AUTO6:
	case NI_DRACUT_BOOTPROTO_IBFT:
		ni_warn("Bootproto not implemented yet!\n");
		break;

	default:
		ni_warn("Bootproto unsupported!\n");
		break;
	}

	return FALSE;
}

/**
 * Adds a new compat_netdev_t to the array using
 * ifname as name or if it exists, adds the lladdr/mtu to it
 */
static ni_compat_netdev_t *
ni_dracut_cmdline_add_netdev(ni_compat_netdev_array_t *nda, const char *ifname, const ni_hwaddr_t *lladdr, const unsigned int *mtu, const int iftype)
{
	ni_compat_netdev_t *nd;

	if (!(nd = ni_compat_netdev_by_name(nda, ifname))) {
		if (!(nd = ni_compat_netdev_new(ifname)))
			return NULL;

		ni_compat_netdev_array_append(nda, nd);
	}


	/* We only apply the iftype if it hasn't been applied before
	 * (to avoid overwriting netdevs created by bridge=..., vlan=... etc) */
	if (nd->dev->link.type == NI_IFTYPE_UNKNOWN)
		nd->dev->link.type = iftype;

	if (!ni_link_address_is_invalid(lladdr)) {
		/* The link mac address is not a "generic" interface property,
		 * but can be applied only on (ether) interfaces supporting it,
		 * e.g. ethernet, bridge, bond, team, vlan (not on infiniband
		 * ppp, tunnels, ...).
		 * Assume it's (physical) ethernet interface if configured to
		 * apply a link address, but the interface does not have type.
		 */
		if (nd->dev->link.type == NI_IFTYPE_UNKNOWN)
			nd->dev->link.type = NI_IFTYPE_ETHERNET;

		/* request to modify the link address aka `ip link set address <mac> dev <ifname>` */
		ni_link_address_set(&nd->dev->link.hwaddr, lladdr->type, lladdr->data, lladdr->len);
	}

	if (mtu) {
		/* request to set the mtu */
		nd->dev->link.mtu = *mtu;
	}

	return nd;
}

static ni_bool_t
ni_dracut_cmdline_add_team_port(ni_compat_netdev_array_t *nda, ni_netdev_t *dev, const char *portname)
{
	ni_compat_netdev_t *nd;

	if (!ni_netdev_name_is_valid(portname) || ni_string_eq(dev->name, portname)) {
		ni_warn("dracut:cmdline team '%s': rejecting suspect port interface name '%s'",
				dev->name, ni_print_suspect(portname, ni_string_len(portname)));
		return FALSE;
	}

	if (!(nd = ni_dracut_cmdline_add_netdev(nda, portname, NULL, 0, NI_IFTYPE_UNKNOWN))) {
		ni_warn("dracut:cmdline team '%s': unable to create port interface structure",
				dev->name);
		return FALSE;
	}

	if (!ni_string_empty(nd->dev->link.masterdev.name) &&
	    !ni_string_eq(dev->name, nd->dev->link.masterdev.name)) {
		ni_warn("dracut:cmdline team '%s': rejecting port '%s' already enslaved in '%s'",
				dev->name, portname, nd->dev->link.masterdev.name);
		return FALSE;
	}

	/* each port/slave refers via master to the team interface */
	ni_netdev_ref_set_ifname(&nd->dev->link.masterdev, dev->name);

	return TRUE;
}

static ni_compat_netdev_t *
ni_dracut_cmdline_add_team(ni_compat_netdev_array_t *nda, const char *master, char *slaves, const char *runner)
{
	ni_team_runner_type_t rtype;
	ni_compat_netdev_t *nd;
	unsigned int cnt;
	char *name;

	if (!ni_netdev_name_is_valid(master)) {
		ni_warn("dracut:cmdline team: rejecting suspect interface name '%s'",
				ni_print_suspect(master, ni_string_len(master)));
		return NULL;
	}

	if (!(nd = ni_dracut_cmdline_add_netdev(nda, master, NULL, NULL, NI_IFTYPE_TEAM)) ||
	    !ni_netdev_get_team(nd->dev)) {
		ni_warn("dracut:cmdline team '%s': unable to create team interface structure",
				master);
		return NULL;
	}

	if (!ni_team_runner_name_to_type(runner, &rtype)) {
		ni_warn("dracut:cmdline team '%s': rejecting suspect runner type '%s'",
				master, ni_print_suspect(runner, ni_string_len(runner)));
	}
	ni_team_runner_init(&nd->dev->team->runner, rtype);

	for (cnt = 0, name = slaves; name; name = slaves) {
		slaves = token_next(slaves, ',');
		if (ni_dracut_cmdline_add_team_port(nda, nd->dev, name))
			cnt++;
	}
	if (!cnt) {
		ni_warn("dracut:cmdline team '%s': no valid port interfaces defined",
				master);
	}
	return nd;
}

static ni_bool_t
ni_dracut_cmdline_set_bond_options(ni_netdev_t *dev, char *options)
{
	char *option, *key, *val;
	ni_bonding_t *bond;

	if (!(bond = ni_netdev_get_bonding(dev)))
		return FALSE;

	for (option = options; option; option = options) {
		options = token_next(options, ',');

		key = option;
		val = token_next(option, '=');

		/* substitute semicolon into expected colon-separated format */
		if (ni_string_eq(key, "arp_ip_target")) {
			char *found;
			while ((found = strchr(val, ';')))
				*found = ',';
		}
		if (ni_string_empty(key) || ni_string_empty(val) ||
		    !ni_bonding_set_option(bond, key, val)) {
			ni_warn("dracut:cmdline bond '%s': rejecting invalid option '%s'='%s'",
					dev->name, key ? key : "", val ? val : "");
		}
	}

	return TRUE;
}

static ni_bool_t
ni_dracut_cmdline_add_bond_port(ni_compat_netdev_array_t *nda, ni_netdev_t *dev, const char *portname)
{
	ni_compat_netdev_t *nd;
#if 0
	ni_bonding_t *bond;
#endif
	if (!ni_netdev_name_is_valid(portname) || ni_string_eq(dev->name, portname)) {
		ni_warn("dracut:cmdline bond '%s': rejecting suspect port interface name '%s'",
				dev->name, ni_print_suspect(portname, ni_string_len(portname)));
		return FALSE;
	}

	if (!(nd = ni_dracut_cmdline_add_netdev(nda, portname, NULL, 0, NI_IFTYPE_UNKNOWN))) {
		ni_warn("dracut:cmdline bridge '%s': unable to create port '%s' interface structure",
				dev->name, portname);
		return FALSE;
	}

	if (!ni_string_empty(nd->dev->link.masterdev.name) &&
	    !ni_string_eq(dev->name, nd->dev->link.masterdev.name)) {
		ni_warn("dracut:cmdline bond '%s': rejecting port '%s' already enslaved in '%s'",
				dev->name, portname, nd->dev->link.masterdev.name);
		return FALSE;
	}

	/* each port/slave device refers via master to the bond device */
	ni_netdev_ref_set_ifname(&nd->dev->link.masterdev, dev->name);

#if 0
	/* port/slave list in bond is deprecated / unused by wickedd */
	if ((bond = ni_netdev_get_bonding(dev)))
		ni_bonding_add_slave(bond, port);
#endif
	return TRUE;
}

static ni_compat_netdev_t *
ni_dracut_cmdline_add_bond(ni_compat_netdev_array_t *nda, const char *bondname, char *slaves,
				const char *options, const unsigned int *mtu)
{
	ni_compat_netdev_t *nd;
	char *opts = NULL;
	unsigned int cnt;
	const char *err;
	char *name;

	if (!ni_netdev_name_is_valid(bondname)) {
		ni_warn("dracut:cmdline bond: rejecting suspect interface name '%s'",
				ni_print_suspect(bondname, ni_string_len(bondname)));
		return NULL;
	}

	if (!(nd = ni_dracut_cmdline_add_netdev(nda, bondname, NULL, mtu, NI_IFTYPE_BOND)) ||
	    !ni_netdev_get_bonding(nd->dev)) {
		ni_warn("dracut:cmdline bond '%s': unable to create bond interface structure",
				bondname);
		return NULL;
	}

	/* parse options first, so we can discard and reset if invalid */
	ni_string_dup(&opts, options);
	ni_dracut_cmdline_set_bond_options(nd->dev, opts);
	ni_string_free(&opts);

	if ((err = ni_bonding_validate(nd->dev->bonding))) {
		ni_warn("dracut:cmdline bond '%s': rejecting invalid options: %s", bondname,
				ni_print_suspect(options, ni_string_len(options)));
		ni_netdev_set_bonding(nd->dev, NULL);

		ni_netdev_get_bonding(nd->dev);
		ni_string_dup(&opts, NI_DRACUT_CMDLINE_DEF_BOND_OPTIONS);
		ni_dracut_cmdline_set_bond_options(nd->dev, opts);
		ni_string_free(&opts);
	}

	for (cnt = 0, name = slaves; name; name = slaves) {
		slaves = token_next(slaves, ',');
		if (ni_dracut_cmdline_add_bond_port(nda, nd->dev, name))
			cnt++;
	}
	if (!cnt) {
		ni_warn("dracut:cmdline bond '%s': no valid port interfaces defined",
				bondname);
	}

	return nd;
}

static ni_bool_t
ni_dracut_cmdline_add_bridge_port(ni_compat_netdev_array_t *nda, ni_netdev_t *dev, const char *portname)
{
	ni_compat_netdev_t *nd;

	if (!ni_netdev_name_is_valid(portname) || ni_string_eq(dev->name, portname)) {
		ni_warn("dracut:cmdline bridge '%s': rejecting suspect port interface name '%s'",
				dev->name, ni_print_suspect(portname, ni_string_len(portname)));
		return FALSE;
	}

	if (!(nd = ni_dracut_cmdline_add_netdev(nda, portname, NULL, 0, NI_IFTYPE_UNKNOWN))) {
		ni_warn("dracut:cmdline bridge '%s': unable to create port '%s' interface structure",
				dev->name, portname);
		return FALSE;
	}

	if (!ni_string_empty(nd->dev->link.masterdev.name) &&
	    !ni_string_eq(dev->name, nd->dev->link.masterdev.name)) {
		ni_warn("dracut:cmdline bridge '%s': rejecting port '%s' already enslaved in '%s'",
				dev->name, portname, nd->dev->link.masterdev.name);
		return FALSE;
	}

	/* each port/slave refers via master to the bridge interface */
	ni_netdev_ref_set_ifname(&nd->dev->link.masterdev, dev->name);

	return TRUE;
}

static ni_compat_netdev_t *
ni_dracut_cmdline_add_bridge(ni_compat_netdev_array_t *nda, const char *brname, char *ports)
{
	ni_compat_netdev_t *nd;
	unsigned int cnt;
	char *name;

	if (!ni_netdev_name_is_valid(brname)) {
		ni_warn("dracut:cmdline bridge: rejecting suspect interface name '%s'",
				ni_print_suspect(brname, ni_string_len(brname)));
		return NULL;
	}

	if (!(nd = ni_dracut_cmdline_add_netdev(nda, brname, NULL, NULL, NI_IFTYPE_BRIDGE)) ||
	    !ni_netdev_get_bridge(nd->dev)) {
		ni_warn("dracut:cmdline bridge '%s': unable to create bridge interface structure",
				brname);
		return NULL;
	}

	for (cnt = 0, name = ports; name; name = ports) {
		ports = token_next(ports, ',');
		if (ni_dracut_cmdline_add_bridge_port(nda, nd->dev, name))
			cnt++;
	}

	return nd;
}

static ni_bool_t
ni_dracut_cmdline_vlan_tag_from_name(const char *vlanname, unsigned int *tag)
{
	const char *vlantag;
	size_t len;

	if ((vlantag = strrchr(vlanname, '.'))) {
		/* name.<TAG> */
		++vlantag;
	} else {
		/* name<TAG>  */
		len = ni_string_len(vlanname);
		vlantag = &vlanname[len];
		while (len-- && isdigit((unsigned char)vlantag[-1]))
			vlantag--;
	}
	return ni_parse_uint(vlantag, tag, 10) == 0;
}

static ni_bool_t
ni_dracut_cmdline_add_vlan(ni_compat_netdev_array_t *nda, const char *vlanname, const char *etherdev)
{
	ni_compat_netdev_t *nd;
	unsigned int tag = 0;
	const char *err;
	ni_vlan_t *vlan;

	if (!ni_netdev_name_is_valid(vlanname)) {
		ni_warn("dracut:cmdline vlan: suspect interface name '%s'",
				ni_print_suspect(vlanname, ni_string_len(vlanname)));
		return FALSE;
	}
	if (!ni_netdev_name_is_valid(etherdev)) {
		ni_warn("dracut:cmdline vlan '%s': suspect base interface '%s'",
				vlanname, ni_print_suspect(etherdev, ni_string_len(etherdev)));
		return FALSE;
	}
	if (ni_string_eq(vlanname, etherdev)) {
		ni_warn("dracut:cmdline vlan '%s': interface name self-reference '%s'",
				vlanname, ni_print_suspect(etherdev, ni_string_len(etherdev)));
		return FALSE;
	}
	if (!ni_dracut_cmdline_vlan_tag_from_name(vlanname, &tag) || tag > USHRT_MAX) {
		ni_warn("dracut:cmdline vlan '%s': cannot parse tag from interface name",
				vlanname);
		return FALSE;
	}
	if (!ni_dracut_cmdline_add_netdev(nda, etherdev, NULL, NULL, NI_IFTYPE_UNKNOWN)) {
		ni_warn("dracut:cmdline vlan '%s': unable to create base interface '%s' structure",
				vlanname, etherdev);
		return FALSE;
	}

	vlan = ni_vlan_new();
	vlan->protocol = NI_VLAN_PROTOCOL_8021Q;
	vlan->tag = tag;

	if ((err = ni_vlan_validate(vlan))) {
		ni_error("dracut:cmdline vlan '%s': %s", vlanname, err);
		ni_vlan_free(vlan);
		return FALSE;
	}

	if (!(nd = ni_dracut_cmdline_add_netdev(nda, vlanname, NULL, NULL, NI_IFTYPE_VLAN))) {
		ni_warn("dracut:cmdline vlan '%s': unable to create vlan interface structure",
				vlanname);
		ni_vlan_free(vlan);
		return FALSE;
	}

	ni_string_dup(&nd->dev->link.lowerdev.name, etherdev);
	ni_netdev_set_vlan(nd->dev, vlan);

	return TRUE;
}

/**
 * ip={dhcp|on|any|dhcp6|auto6|either6} syntax variant
 */
static ni_bool_t
parse_ip1(ni_compat_netdev_array_t *nda, char *val)
{
	unsigned int bootproto;
	ni_compat_netdev_t *compat;

	if (ni_parse_uint_mapped(val, bootprotos, &bootproto))
			return FALSE;

	compat = ni_dracut_cmdline_add_netdev(nda, NULL, NULL, NULL, NI_IFTYPE_UNKNOWN);

	return ni_dracut_cmdline_parse_bootproto(compat, val);
}

/**
 * ip=<interface>:{dhcp|on|any|dhcp6|auto6}[:[<mtu>][:<macaddr>]] syntax variant
 */
static ni_bool_t
parse_ip2(ni_compat_netdev_array_t *nda, char *val, const char *ifname)
{
	char *mac, *mtu;
	ni_hwaddr_t lladdr, *lladdr_p = NULL;
	unsigned int mtu_u32, bootproto, *mtu_p = NULL;

	ni_compat_netdev_t *compat;

	if (!ni_netdev_name_is_valid(ifname))
		return FALSE;

	if ((mtu = token_next(val, ':'))) {

		if (token_peek(mtu, ':')) {
			mac = token_next(mtu, ':');
			ni_link_address_parse(&lladdr, ARPHRD_VOID, mac);
			if (lladdr.len == 6)
				lladdr.type = ARPHRD_ETHER;
			else if (lladdr.len == 20)
				lladdr.type = ARPHRD_INFINIBAND;

			lladdr_p = &lladdr;
		}

		if (mtu && *mtu != '\0') {
			ni_parse_uint(mtu, &mtu_u32, 10);
			mtu_p = &mtu_u32;
		}

	} else {
		if (ni_parse_uint_mapped(val, bootprotos, &bootproto))
			return FALSE;
	}

	compat = ni_dracut_cmdline_add_netdev(nda, ifname, lladdr_p, mtu_p, NI_IFTYPE_UNKNOWN);

	return ni_dracut_cmdline_parse_bootproto(compat, val);
}

/**
 * ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<mtu>][:<macaddr>]]
 */
static ni_bool_t
parse_ip3(ni_compat_netdev_array_t *nda, char *val, const char *client_ip)
{
	ni_sockaddr_t peer_addr, netmask, client_addr, gateway_addr;
	ni_ipv4_devinfo_t *ipv4;
	ni_ipv6_devinfo_t *ipv6;
	ni_compat_netdev_t *nd = NULL;
	char *params[9] = {NULL};
	const char *peer, *mask, *gateway, *hostname, *ifname, *bootproto, *mtu, *hwaddr;
	unsigned int i, offset = 0, mtu_u32;
	unsigned int peer_prefixlen = ~0U;
	unsigned int client_prefixlen = ~0U;
	ni_hwaddr_t lladdr;
	ni_route_t *rp;

	if (ni_string_empty(val))
		return FALSE;

	for (i = 0; i < 9; ++i) {
		params[i] = val;
		if (!token_peek(val, ':'))
			break;

		val = token_next(val, ':');
	}

	peer = i >= offset ? params[offset++] : NULL;
	gateway = i >= offset ? params[offset++] : NULL;
	mask = i >= offset ? params[offset++] : NULL;
	hostname = i >= offset ? params[offset++] : NULL;
	ifname = i >= offset ? params[offset++] : NULL;
	bootproto = i >= offset ? params[offset++] : NULL;
	mtu = hwaddr = i >= offset ? params[offset++] : NULL;
	hwaddr = i >= offset ? params[offset++] : hwaddr;

	// Parse the params into sockaddrs
	if (!client_ip || ni_sockaddr_parse(&client_addr, client_ip, AF_UNSPEC) == -1)
		return FALSE;

	if (peer)	// Peer is optional
		ni_sockaddr_prefix_parse(peer, &peer_addr, &peer_prefixlen);

	if (!gateway || ni_sockaddr_parse(&gateway_addr, gateway, AF_UNSPEC) == -1)
		return FALSE;

	if (ni_sockaddr_parse(&netmask, mask, AF_INET) == -1)
		return FALSE;

	client_prefixlen = ni_sockaddr_netmask_bits(&netmask);

	// Create the netdev using the hwaddr / mtu params
	if (params[offset] == NULL)
		nd = ni_dracut_cmdline_add_netdev(nda, ifname, NULL, NULL, NI_IFTYPE_UNKNOWN);

	else if (mtu && !ni_parse_uint(mtu, &mtu_u32, 10)) {
		if (!ni_link_address_parse(&lladdr, ARPHRD_ETHER, hwaddr))
			nd = ni_dracut_cmdline_add_netdev(nda, ifname, &lladdr, &mtu_u32, NI_IFTYPE_UNKNOWN);
		else
			nd = ni_dracut_cmdline_add_netdev(nda, ifname, NULL, &mtu_u32, NI_IFTYPE_UNKNOWN);
	} else {
		if (hwaddr && !ni_link_address_parse(&lladdr, ARPHRD_ETHER, hwaddr)) {
			nd = ni_dracut_cmdline_add_netdev(nda, ifname, &lladdr, NULL, NI_IFTYPE_UNKNOWN);
		}
	}
	ni_assert(nd);

	// Add the bootproto
	ni_dracut_cmdline_parse_bootproto(nd, bootproto);

	// Add the hostname
	ni_string_dup(&nd->dhcp4.hostname, hostname);

	// Add the address
	if (client_addr.ss_family == AF_INET) {
		ipv4 = ni_netdev_get_ipv4(nd->dev);
		ni_tristate_set(&ipv4->conf.enabled, TRUE);
		ni_tristate_set(&ipv4->conf.arp_verify, TRUE);
	} else if (client_addr.ss_family == AF_INET6) {
		ipv6 = ni_netdev_get_ipv6(nd->dev);
		ni_tristate_set(&ipv6->conf.enabled, TRUE);
	}
	ni_address_create(client_addr.ss_family, client_prefixlen, &client_addr, &nd->dev->addrs);

	// Add the default gw route
	rp = ni_route_create(0, NULL, &gateway_addr, RT_TABLE_MAIN);
	if (!ni_route_tables_add_route(&nd->dev->routes, rp)) {
		ni_route_free(rp);
		return FALSE;
	}
	ni_route_free(rp);

	return TRUE;
}

/**
 * Guess what IP param syntax variant we have to parse and call the
 * appropriate function.
 */
static ni_bool_t
ni_dracut_cmdline_parse_opt_ip(ni_compat_netdev_array_t *nd, ni_var_t *param)
{
	char *end, *beg;

	if (ni_string_empty(param->value))
		return FALSE;

	if ((beg = token_peek(param->value, '['))) {
		if (!(end = token_next(param->value, ']')))
			return FALSE;
		if (!(end = token_next(end, ':')))
			return FALSE;

		return parse_ip3(nd, end, beg + 1);
	} else
	if (isdigit((unsigned int)*param->value)) {
		if (!(end = token_next(param->value, ':')))
			return FALSE;

		return parse_ip3(nd, end, param->value);
	} else
	if ((end = token_next(param->value, ':'))) {
		return parse_ip2(nd, end, param->value);
	} else {
		return parse_ip1(nd, param->value);
	}
	return TRUE;
}

/** Parse bonding configuration applying default values when not provided
 * bond=<bondname>[:<bondslaves>:[:<options>[:<mtu>]]]
 */
static ni_bool_t
ni_dracut_cmdline_parse_opt_bond(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *next;
	char *bonddname = NI_DRACUT_CMDLINE_DEF_BOND_NAME;
	char default_slaves[] = NI_DRACUT_CMDLINE_DEF_BOND_SLAVES;
	char *slaves = default_slaves;
	char *opts = NI_DRACUT_CMDLINE_DEF_BOND_OPTIONS;
	unsigned int mtu_u32 = 0;
	char *mtu = NULL;

	if (ni_string_empty(param->value))
		goto add_bond;

	bonddname = param->value;
	if (!(next = token_next(bonddname, ':')))
		goto add_bond;

	slaves = next;
	if (!(next = token_next(slaves, ':')))
		goto add_bond;

	opts = next;
	if (!(next = token_next(opts, ':')))
		goto add_bond;

	mtu = next;
	if (ni_parse_uint(mtu, &mtu_u32, 10)) {
		ni_error("cmdline: invalid mtu value\n");
		return FALSE;
	}

add_bond:
	return !!ni_dracut_cmdline_add_bond(nda, bonddname, slaves, opts, &mtu_u32);
}

static ni_bool_t
ni_dracut_cmdline_parse_opt_team(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *master = NI_DRACUT_CMDLINE_DEF_TEAM_NAME;
	char *runner = NI_DRACUT_CMDLINE_DEF_TEAM_RUNNER;
	char default_ports[] =  NI_DRACUT_CMDLINE_DEF_TEAM_PORTS;
	char *slaves = default_ports;
	char *next;

	if (ni_string_empty(param->value))
		goto add_team;

	master = param->value;
	if (!(next = token_next(master, ':')))
		goto add_team;

	slaves = next;
	if (!(next = token_next(slaves, ':')))
		goto add_team;

	runner = next;
	if (!(next = token_next(runner, ':')))
		goto add_team;

add_team:
	return !!ni_dracut_cmdline_add_team(nda, master, slaves, runner);
}

static ni_bool_t
ni_dracut_cmdline_parse_opt_bridge(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *brname, *ports;

	if (ni_string_empty(param->value))
		return FALSE;

	brname = param->value;
	if (!(ports = token_next(param->value, ':')))
		return FALSE;

	/*
	 * currently, dracut does not support any options,
	 * we just ensure to terminate the slaves/port list
	 * when it starts to supports some.
	 * It's safe as ':' is invalid in interface names
	 * anyway (reserved for labels aka alias fakes).
	 */
	token_next(ports, ':');

	return !!ni_dracut_cmdline_add_bridge(nda, brname, ports);
}

/*
 * ifname=<name>:<mac>
 *
 * This parameter does not create any interface config, but adds an
 * identify match to rename an interface (potentially) using wrong
 * name, e.g. still kernel assigned "random eth0" name, to a name
 * used by other parameters like `ip=` or bridge, bond, ...  port.
 *
 * Thus it is important to parse all the other parameters before.
 * When the interface is not configured otherwise and there will be
 * no interface config for, we sill expose them as emenent nodes
 * in the config source specific meta option value.
 */
static ni_bool_t
ni_dracut_cmdline_parse_opt_ifname(ni_compat_netdev_array_t *nda, xml_node_t *ovalue, ni_var_t *param)
{
	char *mac, *ifname;
	ni_hwaddr_t hwaddr;
	ni_compat_netdev_t *nd;

	ifname = param->value;
	mac = token_next(param->value, ':');
	if (!ni_netdev_name_is_valid(ifname)) {
		ni_warn("dracut:cmdline %s: suspect interface name '%s'", param->name,
				ni_print_suspect(ifname, ni_string_len(ifname)));
		return FALSE;
	}
	if (!mac || ni_link_address_parse(&hwaddr, ARPHRD_ETHER, mac) ||
	    ni_link_address_is_invalid(&hwaddr)) {
		ni_warn("dracut:cmdline %s: suspect mac address '%s'", param->name,
				ni_print_suspect(mac, ni_string_len(mac)));
		return FALSE;
	}

	/* expose pre-parsed meta-data option elements to the caller */
	xml_node_new_element("name", ovalue, ifname);
	xml_node_new_element("mac", ovalue, mac);

	if ((nd = ni_compat_netdev_by_name(nda, ifname))) {
		/* request to match / identify by (persistent) hwaddr to rename it (if needed) */
		ni_link_address_set(&nd->identify.hwaddr, hwaddr.type, hwaddr.data, hwaddr.len);
	}

	return TRUE;
}

static ni_bool_t
ni_dracut_cmdline_parse_opt_vlan(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *vlanname;
	char *etherdev;

	vlanname = param->value;
	etherdev = token_next(param->value, ':');
	return ni_dracut_cmdline_add_vlan(nda, vlanname, etherdev);
}


/**
 * Identify what function needs to be called to handle the supplied param
 **/
static ni_bool_t
ni_dracut_cmdline_parse_param(ni_dracut_cmdline_param_t type, ni_var_t *var,
				xml_node_t *ovalue, ni_compat_netdev_array_t *nd)
{
	switch (type) {
		case NI_DRACUT_PARAM_IFNAME:
			return ni_dracut_cmdline_parse_opt_ifname(nd, ovalue, var);
		case NI_DRACUT_PARAM_BOND:
			return ni_dracut_cmdline_parse_opt_bond(nd, var);
		case NI_DRACUT_PARAM_TEAM:
			return ni_dracut_cmdline_parse_opt_team(nd, var);
		case NI_DRACUT_PARAM_VLAN:
			return ni_dracut_cmdline_parse_opt_vlan(nd, var);
		case NI_DRACUT_PARAM_BRIDGE:
			return ni_dracut_cmdline_parse_opt_bridge(nd, var);
		case NI_DRACUT_PARAM_IP:
			return ni_dracut_cmdline_parse_opt_ip(nd, var);
		default:
			ni_error("Dracut cmdline parameter '%s' is not supported yet!\n", var->name);
			return FALSE;
	}
}

/**
 * This function will apply the params found in the params array to the compat_netdev array
 */
static ni_bool_t
ni_dracut_cmdline_parse_params(ni_var_array_t *params, xml_node_t *options, ni_compat_netdev_array_t *nd)
{
	const ni_intmap_t *type;
	xml_node_t *option;
	xml_node_t *ovalue;
	unsigned int pos;
	ni_var_t *param;

	if (!params || !options || !nd)
		return FALSE;

	/* 1st, parse known params in desired map order (links first, ip, ...) */
	for (type = dracut_params; type->name; ++type) {
		const ni_var_t match = { .name = (char *)type->name, .value = NULL };

		pos = 0;
		while ((pos = ni_var_array_find(params, pos, &match, ni_var_name_equal, NULL)) != -1U) {
			param = &params->data[pos];

			/* add config parser specific meta option and mark processed */
			option = xml_node_new("option", options);
			xml_node_add_attr(option, "processed", ni_format_boolean(TRUE));
			xml_node_new_element("key", option, param->name);
			ovalue = xml_node_new_element("value", option, param->value);

			ni_dracut_cmdline_parse_param(type->value, param, ovalue, nd);

			/*
			 * not all options are parsed into compat netdev
			 * but may parse the value cdata into child node
			 * elements, so detect and reset the cdata then.
			 */
			if (ovalue->children)
				xml_node_set_cdata(ovalue, NULL);

			/* finally, remove param we've processed */
			ni_var_array_remove_at(params, pos);
		}
	}

	/* 2nd, add all unprocessed params into config parser specific meta options */
	for (pos = 0; pos < params->count; ++pos) {
		param = &params->data[pos];

		option = xml_node_new("option", options);
		xml_node_add_attr(option, "processed", ni_format_boolean(FALSE));
		xml_node_new_element("key", option, param->name);
		xml_node_new_element("value", option, param->value);
	}

	return TRUE;
}

/**
 * parse 'ip="foo bar" blub=hoho' lines with key[=<quoted-value|value>]
 * @return <0 on error, 0 when param extracted, >0 to skip/ignore (crap or empty param)
 */
static int
ni_dracut_cmdline_param_parse_and_unquote(ni_stringbuf_t *param, ni_buffer_t *buf)
{
	int quote = 0, esc = 0, parse = 0, cc;

	while ((cc = ni_buffer_getc(buf)) != EOF) {
		if (parse) {
			if (quote) {
				if (esc) {
					/* only \" for now */
					ni_stringbuf_putc(param, cc);
					esc = 0;
				} else
				if (cc == '\\') {
					esc = cc;
				} else
				if (cc == quote)
					quote = 0;
				else
					ni_stringbuf_putc(param, cc);
			} else {
				if (cc == '\'')
					quote = cc;
				else
				if (cc == '"')
					quote = cc;
				else
				if (isspace((unsigned int)cc))
					return FALSE;
				else
					ni_stringbuf_putc(param, cc);
			}
		} else {
			/* skip spaces before/after */
			if (isspace((unsigned int)cc))
				continue;

			parse = 1;
			ni_stringbuf_putc(param, cc);
		}
	}

	return param->len == 0;
}

/**
 * Take a stringbuf line and parse all the variables in the line
 * into a ni_var_array_t
 */
static ni_bool_t
ni_dracut_cmdline_line_parse(ni_var_array_t *params, ni_stringbuf_t *line)
{
	ni_stringbuf_t param = NI_STRINGBUF_INIT_DYNAMIC;
	char *name;
	char *value;
	ni_buffer_t buf;
	int ret;

	if (!params || !line)
		return FALSE;

	if (ni_string_empty(line->string))
		return TRUE;

	ni_buffer_init_reader(&buf, line->string, line->len);
	while (!(ret = ni_dracut_cmdline_param_parse_and_unquote(&param, &buf))) {
		if (ni_string_empty(param.string))
			continue;
		name = strdup(param.string);
		value = strchr(name, '=');
		if (value && *value != '\0') {
			*value = '\0';
			++value;
		} else {
			value = NULL;
		}
		ni_var_array_append(params, name, value);
		ni_stringbuf_clear(&param);
	}
	ni_stringbuf_destroy(&param);

	return ret != -1;
}

/**
 * Read file into a stringbuf  and run line processing on it
 */
static ni_bool_t
ni_dracut_cmdline_file_parse(ni_var_array_t *params, const char *filename)
{
	ni_stringbuf_t line = NI_STRINGBUF_INIT_DYNAMIC;
	char buf[BUFSIZ], eol;
	size_t len;
	FILE *file;

	if (!params || ni_string_empty(filename))
		return FALSE;

	if (!(file = fopen(filename, "r")))
		return FALSE;

	memset(&buf, 0, sizeof(buf));
	while (fgets(buf, sizeof(buf), file)) {
		len = strcspn(buf, "\r\n");
		eol = buf[len];
		buf[len] = '\0';

		if (len)
			ni_stringbuf_puts(&line, buf);
		if (eol) {
			ni_dracut_cmdline_line_parse(params, &line);
			ni_stringbuf_clear(&line);
		}
	}

	/* EOF while reading line with missing EOL termination */
	if (line.len) {
		ni_dracut_cmdline_line_parse(params, &line);
		ni_stringbuf_clear(&line);
	}

	ni_stringbuf_destroy(&line);
	fclose(file);
	return TRUE;
}

/** Main function, should read the dracut cmdline input and do mainly two things:
 *   - Parse the input and separate it in a string array where each string is exactly one config param
 *   - Construct the ni_compat_netdev struct
 */
ni_bool_t
ni_ifconfig_read_dracut_cmdline(xml_document_array_t *array,
			const char *type, const char *root, const char *path,
			ni_ifconfig_kind_t kind, ni_bool_t check_prio, ni_bool_t raw)
{
	ni_compat_ifconfig_t conf;
	ni_compat_ifconfig_init(&conf, type);
	ni_var_array_t params = NI_VAR_ARRAY_INIT;
	xml_document_t *doc;
	xml_node_t *options;

	/*
	 * expose config parser specific "meta options"
	 * to the caller in order to:
	 * - see options that were in the source config
	 * - mark processed vs. unprocessed options
	 * - parse / pre-process option values which
	 *   do not result in any ifcomfig/ifpolicy
	 *   but may be needed in e.g. in bootstrap
	 */
	if (!(options = xml_node_new("options", NULL)))
		return FALSE;

	xml_node_add_attr(options, "origin", "dracut:cmdline:");
	if (!(doc = xml_document_create(NULL, options))) {
		xml_node_free(options);
		return FALSE;
	}
	xml_node_location_relocate(doc->root, "<dracut:cmdline>");
	if (!xml_document_array_append(array, doc)) {
		xml_document_free(doc);
		return FALSE;
	}

	if (ni_dracut_cmdline_file_parse(&params, path)) {
		/*
		 * note: parsing "consumes"/modifies params
		 */
		ni_dracut_cmdline_parse_params(&params, options, &conf.netdevs);
		ni_var_array_destroy(&params);

		if (kind == NI_IFCONFIG_KIND_POLICY)
			ni_compat_generate_policies(array, &conf, check_prio, raw);
		else
			ni_compat_generate_interfaces(array, &conf, check_prio, raw);
		return TRUE;
	}
	ni_var_array_destroy(&params);

	return FALSE;
}
