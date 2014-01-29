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
__ni_dhcp4_lease_head_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	ni_sockaddr_t addr;

	if (lease->dhcp4.client_id[0]) {
		xml_node_new_element("client-id", node, lease->dhcp4.client_id);
	}
	if (lease->dhcp4.servername[0]) {
		xml_node_new_element("server-name", node, lease->dhcp4.servername);
	}
	if (lease->dhcp4.serveraddress.s_addr) {
		ni_sockaddr_set_ipv4(&addr, lease->dhcp4.serveraddress, 0);
		xml_node_new_element("server-address", node, ni_sockaddr_print(&addr));
	}

	if (lease->dhcp4.lease_time)
		xml_node_new_element_uint("lease-time", node, lease->dhcp4.lease_time);
	if (lease->dhcp4.renewal_time)
		xml_node_new_element_uint("renewal-time", node, lease->dhcp4.renewal_time);
	if (lease->dhcp4.rebind_time)
		xml_node_new_element_uint("rebind-time", node, lease->dhcp4.rebind_time);

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

	if (!ni_string_empty(lease->hostname))
		xml_node_new_element("hostname", node, lease->hostname);

	if (!ni_string_empty(lease->dhcp4.bootfile))
		xml_node_new_element("boot-file", node, lease->dhcp4.bootfile);
	if (!ni_string_empty(lease->dhcp4.rootpath))
		xml_node_new_element("root-path", node, lease->dhcp4.rootpath);

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
int
ni_dhcp4_lease_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node)
{
	xml_node_t *child;
	unsigned int value;
	ni_sockaddr_t addr;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "client-id") && child->cdata) {
			if (ni_string_len(child->cdata) >= sizeof(lease->dhcp4.client_id))
				return -1;
			strncpy(lease->dhcp4.client_id, child->cdata,
					sizeof(lease->dhcp4.client_id)-1);
			lease->dhcp4.client_id[sizeof(lease->dhcp4.client_id)-1] = '\0';
		} else
		if (ni_string_eq(child->name, "server-name") && child->cdata) {
			if (ni_string_len(child->cdata) >= sizeof(lease->dhcp4.servername))
				return -1;
			strncpy(lease->dhcp4.servername, child->cdata,
					sizeof(lease->dhcp4.servername)-1);
			lease->dhcp4.servername[sizeof(lease->dhcp4.servername)-1] = '\0';
		} else
		if (ni_string_eq(child->name, "server-address") && child->cdata) {
			if (ni_sockaddr_parse(&addr, child->cdata, AF_INET) < 0)
				return -1;
			lease->dhcp4.serveraddress = addr.sin.sin_addr;
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

		if (ni_string_eq(child->name, "boot-file") && child->cdata) {
			ni_string_dup(&lease->dhcp4.bootfile, child->cdata);
		} else
		if (ni_string_eq(child->name, "root-path") && child->cdata) {
			ni_string_dup(&lease->dhcp4.rootpath, child->cdata);
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
