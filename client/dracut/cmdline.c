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

#include <ctype.h>
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
#include "client/ifconfig.h"
#include "client/dracut/cmdline.h"
#include "buffer.h"

typedef enum {
	NI_DRACUT_PARAM_IFNAME = 0U,
	NI_DRACUT_PARAM_BRIDGE,
	NI_DRACUT_PARAM_BOND,
	NI_DRACUT_PARAM_TEAM,
	NI_DRACUT_PARAM_VLAN,
	NI_DRACUT_PARAM_IP,
} ni_cmdlineconfig_dracut_params_t;

static const ni_intmap_t	dracut_params[] = {
	{ "ifname",		NI_DRACUT_PARAM_IFNAME		},
	{ "bridge",		NI_DRACUT_PARAM_BRIDGE		},
	{ "bond",		NI_DRACUT_PARAM_BOND		},
	{ "team",		NI_DRACUT_PARAM_TEAM		},
	{ "vlan",		NI_DRACUT_PARAM_VLAN		},
	{ "ip",			NI_DRACUT_PARAM_IP		},

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
} ni_cmdlineconfig_dracut_bootprotos_t;

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

const char *
ni_dracut_param_name(unsigned int *param)
{
	return ni_format_uint_mapped(*param, dracut_params);
}

static ni_bool_t
ni_dracut_cmdline_set_bonding_options(ni_netdev_t *dev, const char *options)
{
	ni_string_array_t temp;
	ni_bonding_t *bond;
	unsigned int i;
	ni_bool_t ret = TRUE;

	if ((bond = ni_netdev_get_bonding(dev)) == NULL)
		return FALSE;

	ni_string_array_init(&temp);
	ni_string_split(&temp, options, ",", 0);
	for (i = 0; i < temp.count; ++i) {
		char *key = temp.data[i];
		char *val = strchr(key, '=');

		if (val != NULL)
			*val++ = '\0';

		/**
		 * Substitute semicolon into expected colon-separated format
		 * when we find a arp_ip_target list
		 */
		if (ni_string_eq(key, "arp_ip_target")) {
			char *found;
			while ((found = strchr(val, (int) ';')))
				*found = ',';
		}
		if (ni_string_empty(key) || ni_string_empty(val)) {
			ni_error("%s: Unable to parse bonding options '%s'",
				dev->name, options);
			ret = FALSE;
			break;
		}
		if (!ni_bonding_set_option(bond, key, val)) {
			ni_error("%s: Unable to parse bonding option: %s=%s",
				dev->name, key, val);
			ret = FALSE;
			break;
		}
	}
	ni_string_array_destroy(&temp);

	return ret;
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
 * ifname as name or if it exists, adds the hwaddr/mtu to it
 */
static ni_compat_netdev_t *
ni_dracut_cmdline_add_netdev(ni_compat_netdev_array_t *nda, const char *ifname, const ni_hwaddr_t *hwaddr, const unsigned int *mtu, const int iftype)
{
	ni_compat_netdev_t *nd;

	nd = ni_compat_netdev_by_name(nda, ifname);

	/* We only apply the iftype if it hasn't been applied before
	   (to avoid overwriting netdevs created by bridge=..., vlan=... etc) */
	if (nd && (nd->dev->link.type == NI_IFTYPE_UNKNOWN))
		nd->dev->link.type = iftype;
	if (!nd) {
		nd = ni_compat_netdev_new(ifname);

		/* Assume default NI_IFTYPE_ETHERNET for newly created netdevs */
		nd->dev->link.type = iftype == NI_IFTYPE_UNKNOWN ?
			NI_IFTYPE_ETHERNET : iftype;
	}

	if (ifname && nd && hwaddr) {
		memcpy(nd->dev->link.hwaddr.data, hwaddr->data, hwaddr->len);
		nd->dev->link.hwaddr.len = hwaddr->len;
		nd->dev->link.hwaddr.type = hwaddr->type;
	}

	if (mtu) {
		nd->dev->link.mtu = *mtu;
	}

	ni_compat_netdev_array_append(nda, nd);

	return nd;
}

static ni_compat_netdev_t *
ni_dracut_cmdline_add_team(ni_compat_netdev_array_t *nda, const char *master, char *slaves)
{
	ni_team_t *team;
	ni_team_port_t *port;
	ni_compat_netdev_t *nd;

	char *next;

	nd = ni_dracut_cmdline_add_netdev(nda, master, NULL, NULL, NI_IFTYPE_TEAM);
	team = ni_netdev_get_team(nd->dev);
	ni_team_runner_init(&team->runner, NI_TEAM_RUNNER_ACTIVE_BACKUP);
	for (next = token_peek(slaves, ','); next; slaves = next, next = token_peek(slaves, ',')) {

		++next;
		token_next(slaves, ',');
		if (!ni_netdev_name_is_valid(slaves)) {
			ni_warn("rejecting suspect port name '%s'", slaves);
			continue;
		}
		port = ni_team_port_new();
		ni_netdev_ref_set_ifname(&port->device, slaves);
		ni_team_port_array_append(&team->ports, port);
	}
	port = ni_team_port_new();
	ni_netdev_ref_set_ifname(&port->device, slaves);
	ni_team_port_array_append(&team->ports, port);

	return nd;
}

static ni_compat_netdev_t *
ni_dracut_cmdline_add_bond(ni_compat_netdev_array_t *nda, const char *bondname, char *slaves, const char *options, const unsigned int *mtu)
{
	ni_bonding_t *bonding;
	ni_compat_netdev_t *nd;
	char *names = slaves;
	char *next;

	nd = ni_dracut_cmdline_add_netdev(nda, bondname, NULL, mtu, NI_IFTYPE_BOND);
	bonding = ni_netdev_get_bonding(nd->dev);

	for (next = token_peek(names, ','); next; names = next, next = token_peek(names, ',')) {
		++next;
		token_next(names, ',');
		if (!ni_netdev_name_is_valid(names)) {
			ni_warn("rejecting suspect port name '%s'", names);
			continue;
		}
		ni_bonding_add_slave(bonding, names);
	}
	ni_bonding_add_slave(bonding, names);

	ni_dracut_cmdline_set_bonding_options(nd->dev, options);

	return nd;
}

static ni_compat_netdev_t *
ni_dracut_cmdline_add_bridge(ni_compat_netdev_array_t *nda, const char *brname, char *ports)
{
	ni_bridge_t *bridge;
	ni_compat_netdev_t *nd;
	char *names = ports;
	char *next;

	nd = ni_dracut_cmdline_add_netdev(nda, brname, NULL, NULL, NI_IFTYPE_BRIDGE);
	bridge = ni_netdev_get_bridge(nd->dev);

	for (next = token_peek(names, ','); next; names = next, next = token_peek(names, ',')) {
		++next;
		token_next(names, ',');
		if (!ni_netdev_name_is_valid(names)) {
			ni_warn("rejecting suspect port name '%s'", names);
			continue;
		}
		ni_bridge_port_new(bridge, names, 0);
	}
	ni_bridge_port_new(bridge, names, 0);

	return nd;
}

static ni_compat_netdev_t *
ni_dracut_cmdline_add_vlan(ni_compat_netdev_array_t *nda, const char *vlanname, const char *etherdev)
{
	const char *vlantag;
	ni_vlan_t *vlan;
	ni_compat_netdev_t *nd;
	unsigned int tag = 0;
	size_t len;

	if (!ni_netdev_name_is_valid(vlanname)) {
		ni_error("Rejecting suspect interface name: %s", vlanname);
		return FALSE;
	}

	nd = ni_dracut_cmdline_add_netdev(nda, vlanname, NULL, NULL, NI_IFTYPE_VLAN);
	vlan = ni_netdev_get_vlan(nd->dev);

	if (ni_string_eq(vlanname, etherdev)) {
		ni_error("%s: vlan interface name self-reference",
			vlanname);
		return FALSE;
	}

	if ((vlantag = strrchr(vlanname, '.')) != NULL) {
		/* name.<TAG> */
		++vlantag;
	} else {
		/* name<TAG> */
		len = ni_string_len(vlanname);
		vlantag = &vlanname[len];
		while(len > 0 && isdigit((unsigned char)vlantag[-1]))
			vlantag--;
	}

	if (ni_parse_uint(vlantag, &tag, 10) < 0) {
		ni_error("%s: Cannot parse vlan-tag from interface name",
			nd->dev->name);
		return FALSE;
	}
	vlan->protocol = NI_VLAN_PROTOCOL_8021Q;
	vlan->tag = tag;

	return nd;
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
	ni_address_new(client_addr.ss_family, client_prefixlen, &client_addr, &nd->dev->addrs);

	// Add the default gw
	if (!ni_route_create(0, NULL, &gateway_addr, RT_TABLE_MAIN, &nd->dev->routes))
		return FALSE;

	return TRUE;
}

/**
 * Guess what IP param syntax variant we have to parse and call the
 * appropriate function.
 */
ni_bool_t
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
ni_bool_t
ni_dracut_cmdline_parse_opt_bond(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *next;
	char *bonddname = "bond0";
	char default_slaves[] = "eth0,eth1";
	char *slaves = default_slaves;
	char *opts = "mode=balance-rr";
	char *mtu = NULL;
	unsigned int mtu_u32;

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

ni_bool_t
ni_dracut_cmdline_parse_opt_team(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *next, *master, *slaves;

	if (ni_string_empty(param->value))
		return FALSE;

	master = param->value;
	if (!(next = token_next(master, ':')))
		return FALSE;
	slaves = next;

	ni_dracut_cmdline_add_team(nda, master, slaves);

	return TRUE;
}

ni_bool_t
ni_dracut_cmdline_parse_opt_bridge(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *end, *beg;

	if (ni_string_empty(param->value))
		return FALSE;

	beg = param->value;

	if (!(end = token_next(param->value, ':')))
		return FALSE;

	ni_dracut_cmdline_add_bridge(nda, beg, end);

	return TRUE;
}

ni_bool_t
ni_dracut_cmdline_parse_opt_ifname(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *mac, *ifname;
	ni_hwaddr_t lladdr;
	ni_compat_netdev_t *nd;

	if (ni_string_empty(param->value))
		return FALSE;

	ifname = param->value;

	if (!(mac = token_next(param->value, ':')))
		return FALSE;

	if (ni_link_address_parse(&lladdr, ARPHRD_ETHER, mac))
		return FALSE;

	nd = ni_dracut_cmdline_add_netdev(nda, ifname, NULL, NULL, NI_IFTYPE_UNKNOWN);
	memcpy(nd->identify.hwaddr.data, lladdr.data, lladdr.len);
	nd->identify.hwaddr.len = lladdr.len;
	nd->identify.hwaddr.type = lladdr.type;

	return TRUE;
}

ni_bool_t
ni_dracut_cmdline_parse_opt_vlan(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *end, *beg;

	if (ni_string_empty(param->value))
		return FALSE;

	beg = param->value;

	if (!(end = token_next(param->value, ':')))
		return FALSE;

	ni_dracut_cmdline_add_vlan(nda, end, beg);
	return TRUE;
}


/**
 * Identify what function needs to be called to handle the supplied param
 **/
ni_bool_t
ni_dracut_cmdline_call_param_handler(ni_var_t *var, ni_compat_netdev_array_t *nd)
{
	unsigned int param_type;

	if (ni_parse_uint_mapped(var->name, dracut_params, &param_type) < 0)
		return FALSE;

	switch (param_type) {
		case NI_DRACUT_PARAM_IP:
			ni_dracut_cmdline_parse_opt_ip(nd, var);
			break;
		case NI_DRACUT_PARAM_BOND:
                        ni_dracut_cmdline_parse_opt_bond(nd, var);
			break;
		case NI_DRACUT_PARAM_BRIDGE:
                        ni_dracut_cmdline_parse_opt_bridge(nd, var);
			break;
		case NI_DRACUT_PARAM_TEAM:
                        ni_dracut_cmdline_parse_opt_team(nd, var);
			break;
		case NI_DRACUT_PARAM_IFNAME:
                        ni_dracut_cmdline_parse_opt_ifname(nd, var);
			break;
		case NI_DRACUT_PARAM_VLAN:
                        ni_dracut_cmdline_parse_opt_vlan(nd, var);
			break;

		default:
			ni_error("Dracut param %s not supported yet!\n", var->name);
			return FALSE;
	}

	return TRUE;
}

/**
 * This function will apply the params found in the params array to the compat_netdev array
 */
static ni_bool_t
ni_dracut_cmdline_apply(const ni_var_array_t *params, ni_compat_netdev_array_t *nd)
{
	unsigned int i, pos;
	char *pptr;

	if (!params)
		return FALSE;

	for (i = 0; (pptr = (char *) ni_dracut_param_name(&i)); ++i) {
		const ni_var_t match = { .name = pptr, .value = NULL };
		pos = 0;
		while ((pos = ni_var_array_find(params, pos, &match, &ni_var_name_equal, NULL)) != -1U) {
			ni_dracut_cmdline_call_param_handler(&params->data[pos], nd);
			++pos;
		}
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
	xml_node_t *options, *option;
	unsigned int i;

	doc = xml_document_new();
	options = xml_node_new("options", xml_document_root(doc));
	xml_node_add_attr(options, "origin", "dracut:cmdline:");
	xml_document_array_append(array, doc);

	if (ni_dracut_cmdline_file_parse(&params, path)) {
		for (i = 0; i < params.count; ++i) {
			option = xml_node_new("option", options);
			xml_node_new_element("key", option, params.data[i].name);
			xml_node_new_element("value", option, params.data[i].value);
		}

		ni_dracut_cmdline_apply(&params, &conf.netdevs);

#if 0
		/* TODO:
		 * we currently convert config to policy later
		 */
		kind = ni_ifconfig_kind_guess(kind);
#endif
		if (kind == NI_IFCONFIG_KIND_POLICY)
			ni_compat_generate_policies(array, &conf, check_prio, raw);
		else
			ni_compat_generate_interfaces(array, &conf, check_prio, raw);
		return TRUE;
	}

	return FALSE;
}
