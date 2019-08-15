/*
 *	wicked addrconf utilities for dhcp6 specific lease
 *
 *	Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Karol Mroz <kmroz@suse.com>
 *		Marius Tomaschewski <mt@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <inttypes.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/socket.h>	/* ni_time functions */
#include <wicked/xml.h>

#include "duid.h"
#include "util_priv.h"
#include "leasefile.h"
#include "dhcp6/lease.h"
#include "dhcp6/options.h"


/*
 * dhcp6 lease data to xml
 */
static int
__ni_dhcp6_lease_head_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	ni_sockaddr_t addr;

	xml_node_new_element("client-id", node,
				ni_duid_print_hex(&lease->dhcp6.client_id));
	xml_node_new_element("server-id", node,
				ni_duid_print_hex(&lease->dhcp6.server_id));
	ni_sockaddr_set_ipv6(&addr, lease->dhcp6.server_addr, 0);
	xml_node_new_element("server-address", node,
				ni_sockaddr_print(&addr));
	xml_node_new_element_uint("server-preference", node,
				lease->dhcp6.server_pref);
	if (lease->dhcp6.rapid_commit)
		xml_node_new_element("rapid-commit", node, NULL);

	if (!ni_string_empty(lease->hostname))
		xml_node_new_element("hostname", node, lease->hostname);

	return 0;
}

static int
__ni_dhcp6_lease_status_to_xml(const ni_dhcp6_status_t *status, xml_node_t *node)
{
	xml_node_t *snode;

	if (status->code != NI_DHCP6_STATUS_SUCCESS ||
	    !ni_string_empty(status->message)) {
		snode = xml_node_new("status", node);

		xml_node_new_element_uint("code", snode, status->code);
		if (status->message) {
			xml_node_new_element("message", snode, status->message);
		}
	}
	return 0;
}

static int
__ni_dhcp6_lease_ia_addr_to_xml(const ni_dhcp6_ia_addr_t *iadr, uint16_t type,
				xml_node_t *node)
{
	ni_sockaddr_t addr;
	char *tmp = NULL;

	ni_sockaddr_set_ipv6(&addr, iadr->addr, 0);
	switch (type) {
	case NI_DHCP6_OPTION_IA_TA:
	case NI_DHCP6_OPTION_IA_NA:
		xml_node_new_element("address", node, ni_sockaddr_print(&addr));
		break;

	case NI_DHCP6_OPTION_IA_PD:
		ni_string_printf(&tmp, "%s/%u", ni_sockaddr_print(&addr), iadr->plen);
		xml_node_new_element("prefix",  node, tmp);
		ni_string_free(&tmp);
		break;

	default:
		return -1;
	}

	xml_node_new_element_uint("preferred-lft", node, iadr->preferred_lft);
	xml_node_new_element_uint("valid-lft", node, iadr->valid_lft);
	/* xml_node_new_element_uint("flags", node, iadr->flags); */
	__ni_dhcp6_lease_status_to_xml(&iadr->status, node);

	return 0;
}

static int
__ni_dhcp6_lease_ia_data_to_xml(const ni_dhcp6_ia_t *ia, xml_node_t *node)
{
	const char *ia_address = ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_ADDRESS);
	const char *ia_prefix  = ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_PREFIX);
	const ni_dhcp6_ia_addr_t *iadr;
	struct timeval acquired;
	xml_node_t *iadr_node;
	unsigned int count = 0;
	char buf[32] = { '\0' };
	int ret;

	switch (ia->type) {
	case NI_DHCP6_OPTION_IA_TA:
		xml_node_new_element_uint("interface-id", node, ia->iaid);
		ni_time_timer_to_real(&ia->acquired, &acquired);
		snprintf(buf, sizeof(buf), "%"PRId64, (int64_t)acquired.tv_sec);
		xml_node_new_element("acquired", node, buf);
		break;
	case NI_DHCP6_OPTION_IA_NA:
	case NI_DHCP6_OPTION_IA_PD:
		xml_node_new_element_uint("interface-id", node, ia->iaid);
		ni_time_timer_to_real(&ia->acquired, &acquired);
		snprintf(buf, sizeof(buf), "%"PRId64, (int64_t)acquired.tv_sec);
		xml_node_new_element("acquired", node, buf);
		xml_node_new_element_uint("renewal-time", node, ia->renewal_time);
		xml_node_new_element_uint("rebind-time", node, ia->rebind_time);
		break;
	default:
		return -1;
	}

	for (iadr = ia->addrs; iadr; iadr = iadr->next) {
		switch (ia->type) {
		case NI_DHCP6_OPTION_IA_NA:
		case NI_DHCP6_OPTION_IA_TA:
			iadr_node = xml_node_new(ia_address, NULL);
			break;
		case NI_DHCP6_OPTION_IA_PD:
			iadr_node = xml_node_new(ia_prefix, NULL);
			break;
		default:
			return -1;
		}
		ret = __ni_dhcp6_lease_ia_addr_to_xml(iadr, ia->type, iadr_node);
		if (ret) {
			xml_node_free(iadr_node);
			if (ret < 0)
				return -1;
		} else {
			count++;
			xml_node_add_child(node, iadr_node);
		}
	}
	__ni_dhcp6_lease_status_to_xml(&ia->status, node);
	return count == 0 ? 1 : 0;
}

static int
__ni_dhcp6_lease_ia_type_to_xml(const ni_dhcp6_ia_t *ia_list, unsigned ia_type,
				xml_node_t *node)
{
	const ni_dhcp6_ia_t *ia;
	xml_node_t *ia_node;
	const char *ia_name = ni_dhcp6_option_name(ia_type);
	unsigned int count = 0;
	int ret;

	for (ia = ia_list; ia; ia = ia->next) {
		if (ia->type != ia_type)
			continue;

		ia_node = xml_node_new(ia_name, NULL);
		if ((ret = __ni_dhcp6_lease_ia_data_to_xml(ia, ia_node) == 0)) {
			xml_node_add_child(node, ia_node);
			count++;
		} else {
			xml_node_free(ia_node);
			if (ret < 0)
				return ret;
		}
	}
	return count == 0 ? 1 : 0;
}

int
__ni_dhcp6_lease_boot_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	xml_node_t *data;
	unsigned int i;

	if (ni_string_empty(lease->dhcp6.boot_url) || !lease->dhcp6.boot_params.count)
		return 1;

	data = xml_node_new("boot", node);
	xml_node_new_element("url", data, lease->dhcp6.boot_url);
	for (i = 0; i < lease->dhcp6.boot_params.count; ++i) {
		if (ni_string_empty(lease->dhcp6.boot_params.data[i]))
			continue;
		xml_node_new_element("param", data, lease->dhcp6.boot_params.data[i]);
	}
	return 0;
}

int
ni_dhcp6_lease_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	static const struct group_map {
		const char *name;
		int       (*func)(const ni_addrconf_lease_t *, xml_node_t *, const char *);
	} *g, group_map[] = {
		{ NI_ADDRCONF_LEASE_XML_DNS_DATA_NODE, ni_addrconf_lease_dns_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_NTP_DATA_NODE, ni_addrconf_lease_ntp_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_SIP_DATA_NODE, ni_addrconf_lease_sip_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_PTZ_DATA_NODE, ni_addrconf_lease_ptz_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_OPTS_DATA_NODE, ni_addrconf_lease_opts_data_to_xml },
		{ NULL, NULL }
	};
	xml_node_t *data;

	if (!node || !lease)
		return -1;

	if (lease->family != AF_INET6 || lease->type != NI_ADDRCONF_DHCP)
		return -1;

	if (__ni_dhcp6_lease_head_to_xml(lease, node) != 0)
		return -1;

	if (__ni_dhcp6_lease_ia_type_to_xml(lease->dhcp6.ia_list,
				NI_DHCP6_OPTION_IA_NA, node) < 0)
		return -1;
	if (__ni_dhcp6_lease_ia_type_to_xml(lease->dhcp6.ia_list,
				NI_DHCP6_OPTION_IA_TA, node) < 0)
		return -1;
	if (__ni_dhcp6_lease_ia_type_to_xml(lease->dhcp6.ia_list,
				NI_DHCP6_OPTION_IA_PD, node) < 0)
		return -1;

	if (__ni_dhcp6_lease_boot_to_xml(lease, node) < 0)
		return -1;

	for (g = group_map; g && g->name && g->func; ++g) {
		data = xml_node_new(g->name, NULL);
		if (g->func(lease, data, ifname) == 0) {
			xml_node_add_child(node, data);
		} else {
			xml_node_free(data);
		}
	}

	return 0;
}

int
ni_dhcp6_lease_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	xml_node_t *data;
	int ret;

	if (!lease || !node)
		return -1;

	if (!(data = ni_addrconf_lease_xml_new_type_node(lease, NULL)))
		return -1;

	if ((ret = ni_dhcp6_lease_data_to_xml(lease, data, ifname)) == 0)
		xml_node_add_child(node, data);
	else
		xml_node_free(data);
	return ret;
}

/*
 * dhcp6 lease data from xml
 */
static int
__ni_dhcp6_lease_status_from_xml(ni_dhcp6_status_t *status, const xml_node_t *node)
{
	const xml_node_t *child;
	unsigned int value;

	ni_dhcp6_status_clear(status);
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "code")) {
			if (ni_parse_uint(child->cdata, &value, 10) != 0
					|| value > 0xffff)
				return -1;
			status->code = value;
		} else
		if (ni_string_eq(child->name, "message") && child->cdata) {
			ni_string_dup(&status->message, child->cdata);
		}
	}
	return 0;
}

static int
__ni_dhcp6_lease_ia_addr_from_xml(ni_dhcp6_ia_addr_t *iadr, unsigned int type,
					const xml_node_t *node)
{
	const xml_node_t *child;
	const char *name;
	ni_sockaddr_t addr;
	unsigned int value;

	name = (type == NI_DHCP6_OPTION_IA_PD) ? "prefix" : "address";
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, name) && child->cdata) {
			if (type == NI_DHCP6_OPTION_IA_PD) {
				if (!ni_sockaddr_prefix_parse(child->cdata,
							&addr, &value)
					|| value == 0 || value > 128
					|| addr.ss_family != AF_INET6)
					return -1;
				iadr->addr = addr.six.sin6_addr;
				iadr->plen = value;
			} else {
				if (ni_sockaddr_parse(&addr, child->cdata,
							AF_INET6) != 0)
					return -1;
				iadr->addr = addr.six.sin6_addr;
				iadr->plen = 0;
			}
		} else
		if (ni_string_eq(child->name, "preferred-lft") && child->cdata) {
			if (ni_parse_uint(child->cdata, &value, 10) != 0)
				return -1;
			iadr->preferred_lft = value;
		} else
		if (ni_string_eq(child->name, "valid-lft") && child->cdata) {
			if (ni_parse_uint(child->cdata, &value, 10) != 0)
				return -1;
			iadr->valid_lft = value;
		} else
		if (ni_string_eq(child->name, "status")) {
			if (__ni_dhcp6_lease_status_from_xml(&iadr->status, child) < 0)
				return -1;
		}
	}

	ni_sockaddr_set_ipv6(&addr, iadr->addr, 0);
	if (ni_sockaddr_is_ipv6_specified(&addr))
		return 0;
	else
		return 1;
}

static int
__ni_dhcp6_lease_ia_data_from_xml(ni_dhcp6_ia_t *ia, const xml_node_t *node)
{
	const char *iadr_name;
	const xml_node_t *child;
	ni_dhcp6_ia_addr_t *iadr;
	int ret;

	if (ia->type == NI_DHCP6_OPTION_IA_PD) {
		iadr_name = ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_PREFIX);
	} else {
		iadr_name = ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_ADDRESS);
	}

	ni_timer_get_time(&ia->acquired); /* pre-init */
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "interface-id")) {
			if (ni_parse_uint(child->cdata, &ia->iaid, 10) !=  0)
				return -1;
		} else
		if (ni_string_eq(child->name, "acquired")) {
			struct timeval acquired;
			int64_t sec;

			if (ni_parse_int64(child->cdata, &sec, 10))
				return -1;

			acquired.tv_sec = sec;
			acquired.tv_usec = 0;
			ni_time_real_to_timer(&acquired, &ia->acquired);
		} else
		if (ni_string_eq(child->name, "renewal-time") &&
		    ia->type != NI_DHCP6_OPTION_IA_TA) {
			if (ni_parse_uint(child->cdata, &ia->renewal_time, 10) != 0)
				return -1;
		} else
		if (ni_string_eq(child->name, "rebind-time") &&
		    ia->type != NI_DHCP6_OPTION_IA_TA) {
			if (ni_parse_uint(child->cdata, &ia->rebind_time, 10) != 0)
				return -1;
		} else
		if (ni_string_eq(child->name, iadr_name)) {
			iadr = ni_dhcp6_ia_addr_new(in6addr_any, 0);
			ret = __ni_dhcp6_lease_ia_addr_from_xml(iadr, ia->type, child);
			if (ret) {
				ni_dhcp6_ia_addr_free(iadr);
				if (ret < 0)
					return ret;
			} else {
				ni_dhcp6_ia_addr_list_append(&ia->addrs, iadr);
			}
		} else
		if (ni_string_eq(child->name, "status")) {
			if (__ni_dhcp6_lease_status_from_xml(&ia->status, child) < 0)
				return -1;
		}
	}
	return 0;
}

static int
__ni_dhcp6_lease_ia_type_from_xml(ni_dhcp6_ia_t **ia_list, unsigned int ia_type,
					const xml_node_t *node)
{
	ni_dhcp6_ia_t *ia;
	int ret;

	ia = ni_dhcp6_ia_new(ia_type, 0);
	if ((ret = __ni_dhcp6_lease_ia_data_from_xml(ia, node)) == 0) {
		ni_dhcp6_ia_list_append(ia_list, ia);
		return 0;
	} else {
		ni_dhcp6_ia_free(ia);
	}
	return 0;
}

int
__ni_dhcp6_lease_boot_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "url") && child->cdata) {
			ni_string_dup(&lease->dhcp6.boot_url, child->cdata);
		} else
		if (ni_string_eq(child->name, "param") && child->cdata) {
			ni_string_array_append(&lease->dhcp6.boot_params, child->cdata);
		}
	}
	return 0;
}

int
ni_dhcp6_lease_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	const char *ia_na_name = ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_NA);
	const char *ia_ta_name = ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_TA);
	const char *ia_pd_name = ni_dhcp6_option_name(NI_DHCP6_OPTION_IA_PD);
	unsigned int value;
	ni_sockaddr_t addr;
	xml_node_t *child;

	if (!lease || !node)
		return -1;

	lease->dhcp6.rapid_commit = FALSE;
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "client-id") && child->cdata) {
			if (!ni_duid_parse_hex(&lease->dhcp6.client_id, child->cdata))
				return -1;
		} else
		if (ni_string_eq(child->name, "server-id") && child->cdata) {
			if (!ni_duid_parse_hex(&lease->dhcp6.server_id, child->cdata))
				return -1;
		} else
		if (ni_string_eq(child->name, "server-address") && child->cdata) {
			if (ni_sockaddr_parse(&addr, child->cdata, AF_INET6) < 0)
				return -1;
			lease->dhcp6.server_addr = addr.six.sin6_addr;
		} else
		if (ni_string_eq(child->name, "server-preference") && child->cdata) {
			if (ni_parse_uint(child->cdata, &value, 10) != 0 || value > 255)
				return -1;
			lease->dhcp6.server_pref = value;
		} else
		if (ni_string_eq(child->name, "rapid-commit")) {
			lease->dhcp6.rapid_commit = TRUE;
		} else
		if (ni_string_eq(child->name, "hostname") && child->cdata) {
			ni_string_dup(&lease->hostname, child->cdata);
		}

		if (ni_string_eq(child->name, ia_na_name)) {
			if (__ni_dhcp6_lease_ia_type_from_xml(&lease->dhcp6.ia_list,
						NI_DHCP6_OPTION_IA_NA, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, ia_ta_name)) {
			if (__ni_dhcp6_lease_ia_type_from_xml(&lease->dhcp6.ia_list,
						NI_DHCP6_OPTION_IA_TA, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, ia_pd_name)) {
			if (__ni_dhcp6_lease_ia_type_from_xml(&lease->dhcp6.ia_list,
						NI_DHCP6_OPTION_IA_PD, child) < 0)
				return -1;
		} else

		if (ni_string_eq(child->name, "boot")) {
			if (__ni_dhcp6_lease_boot_from_xml(lease, child) < 0)
				return -1;
		} else

		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_DNS_DATA_NODE)) {
			if (ni_addrconf_lease_dns_data_from_xml(lease, child, ifname) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_NTP_DATA_NODE)) {
			if (ni_addrconf_lease_ntp_data_from_xml(lease, child, ifname) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_SIP_DATA_NODE)) {
			if (ni_addrconf_lease_sip_data_from_xml(lease, child, ifname) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_PTZ_DATA_NODE)) {
			if (ni_addrconf_lease_ptz_data_from_xml(lease, child, ifname) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_OPTS_DATA_NODE)) {
			if (ni_addrconf_lease_opts_data_from_xml(lease, child, ifname) < 0)
				return -1;
		}
	}
	return 0;
}

int
ni_dhcp6_lease_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	if (!node || !lease)
		return -1;

	if (lease->family != AF_INET6 || lease->type != NI_ADDRCONF_DHCP)
		return -1;

	if (!(node = ni_addrconf_lease_xml_get_type_node(lease, node)))
		return -1;

	return ni_dhcp6_lease_data_from_xml(lease, node, ifname);
}
