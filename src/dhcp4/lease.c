/*
 *	wicked addrconf utilities for dhcp4 specific lease
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Olaf Kirch <okir@suse.de>
 *		Karol Mroz <kmroz@suse.com>
 *		Marius Tomaschewski <mt@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <arpa/inet.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/xml.h>

#include "duid.h"
#include "util_priv.h"
#include "leasefile.h"
#include "dhcp4/lease.h"


/*
 * dhcp4 lease data to xml
 */
static int
__ni_dhcp4_lease_boot_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	ni_sockaddr_t addr;
	xml_node_t *boot;

	boot = xml_node_new("boot", NULL);
	if (lease->dhcp4.boot_saddr.s_addr) {
		ni_sockaddr_set_ipv4(&addr, lease->dhcp4.boot_saddr, 0);
		xml_node_new_element("server-address", boot, ni_sockaddr_print(&addr));
	}
	if (!ni_string_empty(lease->dhcp4.boot_sname)) {
		xml_node_new_element("server-name", boot, lease->dhcp4.boot_sname);
	}
	if (!ni_string_empty(lease->dhcp4.boot_file)) {
		xml_node_new_element("filename", boot, lease->dhcp4.boot_file);
	}
	if (boot->children) {
		xml_node_add_child(node, boot);
		return 0;
	} else {
		xml_node_free(boot);
		return 1;
	}
}

static int
__ni_dhcp4_lease_head_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	ni_sockaddr_t addr;

	if (lease->dhcp4.client_id.len) {
		xml_node_new_element("client-id", node, ni_print_hex(
					lease->dhcp4.client_id.data,
					lease->dhcp4.client_id.len));
	}
	if (lease->dhcp4.server_id.s_addr) {
		ni_sockaddr_set_ipv4(&addr, lease->dhcp4.server_id, 0);
		xml_node_new_element("server-id", node, ni_sockaddr_print(&addr));
	}
	if (lease->dhcp4.relay_addr.s_addr) {
		ni_sockaddr_set_ipv4(&addr, lease->dhcp4.relay_addr, 0);
		xml_node_new_element("relay-address", node, ni_sockaddr_print(&addr));
	}
	if (lease->dhcp4.lease_time)
		xml_node_new_element_uint("lease-time", node, lease->dhcp4.lease_time);
	if (lease->dhcp4.renewal_time)
		xml_node_new_element_uint("renewal-time", node, lease->dhcp4.renewal_time);
	if (lease->dhcp4.rebind_time)
		xml_node_new_element_uint("rebind-time", node, lease->dhcp4.rebind_time);

	if (!ni_string_empty(lease->hostname))
		xml_node_new_element("hostname", node, lease->hostname);

	if (lease->dhcp4.address.s_addr) {
		ni_sockaddr_set_ipv4(&addr, lease->dhcp4.address, 0);
		xml_node_new_element("address", node, ni_sockaddr_print(&addr));
	}
	if (lease->dhcp4.netmask.s_addr) {
		ni_sockaddr_set_ipv4(&addr, lease->dhcp4.netmask, 0);
		xml_node_new_element("netmask", node, ni_sockaddr_print(&addr));
	}
	if (lease->dhcp4.broadcast.s_addr) {
		ni_sockaddr_set_ipv4(&addr, lease->dhcp4.broadcast, 0);
		xml_node_new_element("broadcast", node, ni_sockaddr_print(&addr));
	}
	if (lease->dhcp4.mtu)
		xml_node_new_element_uint("mtu", node, lease->dhcp4.mtu);

	__ni_dhcp4_lease_boot_to_xml(lease, node);

	if (!ni_string_empty(lease->dhcp4.root_path))
		xml_node_new_element("root-path", node, lease->dhcp4.root_path);

	if (!ni_string_empty(lease->dhcp4.message))
		xml_node_new_element("message", node, lease->dhcp4.message);

	return 0;
}

int
ni_dhcp4_lease_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	static const struct group_map {
		const char *name;
		int       (*func)(const ni_addrconf_lease_t *lease, xml_node_t *node);
	} *g, group_map[] = {
		{ NI_ADDRCONF_LEASE_XML_ROUTES_DATA_NODE, ni_addrconf_lease_routes_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_DNS_DATA_NODE, ni_addrconf_lease_dns_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_NTP_DATA_NODE, ni_addrconf_lease_ntp_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_NIS_DATA_NODE, ni_addrconf_lease_nis_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_NDS_DATA_NODE, ni_addrconf_lease_nds_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_SMB_DATA_NODE, ni_addrconf_lease_smb_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_SIP_DATA_NODE, ni_addrconf_lease_sip_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_SLP_DATA_NODE, ni_addrconf_lease_slp_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_LPR_DATA_NODE, ni_addrconf_lease_lpr_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_LOG_DATA_NODE, ni_addrconf_lease_log_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_PTZ_DATA_NODE, ni_addrconf_lease_ptz_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_OPTS_DATA_NODE, ni_addrconf_lease_opts_data_to_xml },
		{ NULL,	NULL }
	};
	xml_node_t *data;

	if (!node || !lease)
		return -1;

	if (lease->family != AF_INET || lease->type != NI_ADDRCONF_DHCP)
		return -1;

	if (__ni_dhcp4_lease_head_to_xml(lease, node) != 0)
		return -1;

	for (g = group_map; g && g->name && g->func; ++g) {
		data = xml_node_new(g->name, NULL);
		if (g->func(lease, data) == 0) {
			xml_node_add_child(node, data);
		} else {
			xml_node_free(data);
		}
	}

	return 0;
}

int
ni_dhcp4_lease_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	xml_node_t *data;
	int ret;

	if (!lease || !node)
		return -1;

	if (!(data = ni_addrconf_lease_xml_new_type_node(lease, NULL)))
		return -1;

	if ((ret = ni_dhcp4_lease_data_to_xml(lease, data)) == 0)
		xml_node_add_child(node, data);
	else
		xml_node_free(data);
	return ret;
}


/*
 * dhcp4 lease data from xml
 */
static int
__ni_dhcp4_lease_boot_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node)
{
	xml_node_t *child;
	ni_sockaddr_t addr;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "server-address") && child->cdata) {
			if (ni_sockaddr_parse(&addr, child->cdata, AF_INET) < 0)
				return -1;
			lease->dhcp4.boot_saddr = addr.sin.sin_addr;
		} else
		if (ni_string_eq(child->name, "server-name") && child->cdata) {
			ni_string_dup(&lease->dhcp4.boot_sname, child->cdata);
		} else
		if (ni_string_eq(child->name, "filename") && child->cdata) {
			ni_string_dup(&lease->dhcp4.boot_file, child->cdata);
		}
	}
	return 0;
}

int
ni_dhcp4_lease_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node)
{
	xml_node_t *child;
	unsigned int value;
	ni_sockaddr_t addr;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "client-id") && child->cdata) {
			int len;

			len = ni_parse_hex(child->cdata, lease->dhcp4.client_id.data,
						sizeof(lease->dhcp4.client_id.data));
			if (len < 0)
				return -1;
			lease->dhcp4.client_id.len = len;
		} else
		if (ni_string_eq(child->name, "server-id") && child->cdata) {
			if (ni_sockaddr_parse(&addr, child->cdata, AF_INET) < 0)
				return -1;
			lease->dhcp4.server_id = addr.sin.sin_addr;
		} else
		if (ni_string_eq(child->name, "relay-address") && child->cdata) {
			if (ni_sockaddr_parse(&addr, child->cdata, AF_INET) < 0)
				return -1;
			lease->dhcp4.relay_addr = addr.sin.sin_addr;
		} else
		if (ni_string_eq(child->name, "lease-time") && child->cdata) {
			if (ni_parse_uint(child->cdata, &value, 10) != 0)
				return -1;
			lease->dhcp4.lease_time = value;
		} else
		if (ni_string_eq(child->name, "renewal-time") && child->cdata) {
			if (ni_parse_uint(child->cdata, &value, 10) != 0)
				return -1;
			lease->dhcp4.renewal_time = value;
		} else
		if (ni_string_eq(child->name, "rebind-time") && child->cdata) {
			if (ni_parse_uint(child->cdata, &value, 10) != 0)
				return -1;
			lease->dhcp4.rebind_time = value;
		} else

		if (ni_string_eq(child->name, "address") && child->cdata) {
			if (ni_sockaddr_parse(&addr, child->cdata, AF_INET) < 0)
				return -1;
			lease->dhcp4.address = addr.sin.sin_addr;
		} else
		if (ni_string_eq(child->name, "netmask") && child->cdata) {
			if (ni_sockaddr_parse(&addr, child->cdata, AF_INET) < 0)
				return -1;
			lease->dhcp4.netmask = addr.sin.sin_addr;
		} else
		if (ni_string_eq(child->name, "broadcast") && child->cdata) {
			if (ni_sockaddr_parse(&addr, child->cdata, AF_INET) < 0)
				return -1;
			lease->dhcp4.broadcast = addr.sin.sin_addr;
		} else
		if (ni_string_eq(child->name, "mtu") && child->cdata) {
			if (ni_parse_uint(child->cdata, &value, 10) != 0 ||
					value == 0 || value > 0xffff) /* ahm */
				return -1;
			lease->dhcp4.mtu = value;
		} else

		if (ni_string_eq(child->name, "hostname") && child->cdata) {
			ni_string_dup(&lease->hostname, child->cdata);
		} else

		if (ni_string_eq(child->name, "boot") && child->children) {
			if (__ni_dhcp4_lease_boot_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, "root-path") && child->cdata) {
			ni_string_dup(&lease->dhcp4.root_path, child->cdata);
		} else

		if (ni_string_eq(child->name, "message") && child->cdata) {
			ni_string_dup(&lease->dhcp4.message, child->cdata);
		} else

		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_ROUTES_DATA_NODE)) {
			if (ni_addrconf_lease_routes_data_from_xml(lease, child) < 0)
				return -1;
		} else

		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_DNS_DATA_NODE)) {
			if (ni_addrconf_lease_dns_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_NTP_DATA_NODE)) {
			if (ni_addrconf_lease_ntp_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_NIS_DATA_NODE)) {
			if (ni_addrconf_lease_nis_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_NDS_DATA_NODE)) {
			if (ni_addrconf_lease_nds_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_SMB_DATA_NODE)) {
			if (ni_addrconf_lease_smb_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_SIP_DATA_NODE)) {
			if (ni_addrconf_lease_sip_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_SLP_DATA_NODE)) {
			if (ni_addrconf_lease_slp_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_LOG_DATA_NODE)) {
			if (ni_addrconf_lease_log_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_LPR_DATA_NODE)) {
			if (ni_addrconf_lease_lpr_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_PTZ_DATA_NODE)) {
			if (ni_addrconf_lease_ptz_data_from_xml(lease, child) < 0)
				return -1;
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_OPTS_DATA_NODE)) {
			if (ni_addrconf_lease_opts_data_from_xml(lease, child) < 0)
				return -1;
		}
	}
	return 0;
}

int
ni_dhcp4_lease_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node)
{
	if (!node || !lease)
		return -1;

	if (lease->family != AF_INET || lease->type != NI_ADDRCONF_DHCP)
		return -1;

	if (!(node = ni_addrconf_lease_xml_get_type_node(lease, node)))
		return -1;

	return ni_dhcp4_lease_data_from_xml(lease, node);
}
