/*
 *	wicked addrconf lease file utilities
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
#ifndef   __WICKED_ADDRCONF_LEASEFILE_H__
#define   __WICKED_ADDRCONF_LEASEFILE_H__


/*
 * constants to avoid construction using the
 * ni_addrconf/family_type_to_name functions.
 */
#define	NI_ADDRCONF_LEASE_XML_NODE			"lease"
#define NI_ADDRCONF_LEASE_XML_DHCP4_NODE		"ipv4:dhcp"
#define NI_ADDRCONF_LEASE_XML_DHCP6_NODE		"ipv6:dhcp"
#define NI_ADDRCONF_LEASE_XML_AUTO4_NODE		"ipv4:auto"
#define NI_ADDRCONF_LEASE_XML_AUTO6_NODE		"ipv6:auto"
#define NI_ADDRCONF_LEASE_XML_STATIC4_NODE		"ipv4:static"
#define NI_ADDRCONF_LEASE_XML_STATIC6_NODE		"ipv6:static"
#define NI_ADDRCONF_LEASE_XML_INTRINSIC4_NODE		"ipv4:intrinsic"
#define NI_ADDRCONF_LEASE_XML_INTRINSIC6_NODE		"ipv6:intrinsic"

/*
 * common lease data group container nodes
 */
#define NI_ADDRCONF_LEASE_XML_ADDRS_DATA_NODE		"addresses"
#define NI_ADDRCONF_LEASE_XML_ROUTES_DATA_NODE		"routes"
#define NI_ADDRCONF_LEASE_XML_DNS_DATA_NODE		"dns"
#define NI_ADDRCONF_LEASE_XML_NIS_DATA_NODE		"nis"
#define NI_ADDRCONF_LEASE_XML_NTP_DATA_NODE		"ntp"
#define NI_ADDRCONF_LEASE_XML_NDS_DATA_NODE		"nds"
#define NI_ADDRCONF_LEASE_XML_SMB_DATA_NODE		"smb"
#define NI_ADDRCONF_LEASE_XML_SIP_DATA_NODE		"sip"
#define NI_ADDRCONF_LEASE_XML_SLP_DATA_NODE		"slp"
#define NI_ADDRCONF_LEASE_XML_LPR_DATA_NODE		"lpr"
#define NI_ADDRCONF_LEASE_XML_LOG_DATA_NODE		"log"
#define NI_ADDRCONF_LEASE_XML_PTZ_DATA_NODE		"timezone"
#define NI_ADDRCONF_LEASE_XML_OPTS_DATA_NODE		"options"


/*
 * utils to create and find family:type node
 */
extern const char *
ni_addrconf_lease_xml_new_type_name(const ni_addrconf_lease_t *);
extern xml_node_t *
ni_addrconf_lease_xml_new_type_node(const ni_addrconf_lease_t *, xml_node_t *);
extern const xml_node_t *
ni_addrconf_lease_xml_get_type_node(const ni_addrconf_lease_t *, const xml_node_t *);


/*
 * convert lease / data to xml
 */
extern int
ni_addrconf_lease_addrs_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_routes_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_dns_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_nis_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_ntp_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_nds_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_smb_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_sip_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_slp_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_log_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_lpr_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_ptz_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);
extern int
ni_addrconf_lease_opts_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);


/*
 * convert xml to lease / data
 */
extern int
ni_addrconf_lease_addrs_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_routes_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_dns_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_nis_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_ntp_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_nds_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_smb_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_sip_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_slp_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_log_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_lpr_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_ptz_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);
extern int
ni_addrconf_lease_opts_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);


#endif /* __WICKED_ADDRCONF_LEASEFILE_H__ */
