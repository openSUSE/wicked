/*
 *	DHCP6 option utilities used in addrconf / lease and supplicant
 *
 *	Copyright (C) 2010-2023 SUSE LLC
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
 *	along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski
 */
#ifndef NI_WICKED_DHCP6_OPTIONS_H
#define NI_WICKED_DHCP6_OPTIONS_H

#include <wicked/types.h>
#include <wicked/slist.h>
#include <wicked/address.h>


struct ni_dhcp6_status {
	uint16_t		code;
	char *			message;
};

typedef struct ni_dhcp6_ia_pd_excl {
	struct in6_addr		addr;
	uint8_t			plen;
} ni_dhcp6_ia_pd_excl_t;

struct ni_dhcp6_ia_addr {
	ni_dhcp6_ia_addr_t *	next;
	unsigned int		flags;

	uint16_t		type;
	struct in6_addr		addr;
	uint8_t			plen;
	uint32_t		preferred_lft;
	uint32_t		valid_lft;
	ni_dhcp6_status_t	status;
	ni_dhcp6_ia_pd_excl_t * excl;
};

struct ni_dhcp6_ia {
	ni_dhcp6_ia_t *		next;
	unsigned int		flags;

	uint16_t		type;
	uint32_t		iaid;
	struct timeval		acquired;
	uint32_t		renewal_time;
	uint32_t		rebind_time;
	ni_dhcp6_ia_addr_t *	addrs;
	ni_dhcp6_status_t	status;
};

/*
 * DHCPv6 Status Codes
 * http://tools.ietf.org/html/rfc3315#section-24.4
 *
 * Success         0 Success.
 * UnspecFail      1 Failure, reason unspecified; this
 *                   status code is sent by either a client
 *                   or a server to indicate a failure not
 *                   explicitly specified in this document.
 * NoAddrsAvail    2 Server has no addresses available to
 *                   assign to the IA(s).
 * NoBinding       3 Client record (binding) unavailable.
 * NotOnLink       4 The prefix for the address is not appropriate
 *                   for the link to which the client is attached.
 * UseMulticast    5 Sent by a server to a client to force the
 *                   client to send messages to the server using
 *                   the All_DHCP_Relay_Agents_and_Servers address.
 */
enum NI_DHCP6_STATUS_CODE {
	NI_DHCP6_STATUS_SUCCESS			= 0,
	NI_DHCP6_STATUS_FAILURE			= 1,
	NI_DHCP6_STATUS_NOADDRS			= 2,
	NI_DHCP6_STATUS_NOBINDING		= 3,
	NI_DHCP6_STATUS_NOTONLINK		= 4,
	NI_DHCP6_STATUS_USEMULTICAST		= 5,

	NI_DHCP6_STATUS_CODE_MAX
};

/*
 * DHCPv6 Option Codes
 *
 * http://tools.ietf.org/html/rfc3315#section-24.3
 *
 * [Last Updated: 2012-03-29]
 * http://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xml
 */
enum NI_DHCP6_OPTION {
	/*					   0:	  Reserved   */
	NI_DHCP6_OPTION_CLIENTID		=  1,	/* [RFC3315] */
	NI_DHCP6_OPTION_SERVERID		=  2,
	NI_DHCP6_OPTION_IA_NA			=  3,
	NI_DHCP6_OPTION_IA_TA			=  4,
	NI_DHCP6_OPTION_IA_ADDRESS		=  5,
	NI_DHCP6_OPTION_ORO			=  6,
	NI_DHCP6_OPTION_PREFERENCE		=  7,
	NI_DHCP6_OPTION_ELAPSED_TIME		=  8,
	NI_DHCP6_OPTION_RELAY_MSG		=  9,
	/*					  10:	  Unassigned */
	NI_DHCP6_OPTION_AUTH			= 11,
	NI_DHCP6_OPTION_UNICAST			= 12,
	NI_DHCP6_OPTION_STATUS_CODE		= 13,
	NI_DHCP6_OPTION_RAPID_COMMIT		= 14,
	NI_DHCP6_OPTION_USER_CLASS		= 15,
	NI_DHCP6_OPTION_VENDOR_CLASS		= 16,
	NI_DHCP6_OPTION_VENDOR_OPTS		= 17,
	NI_DHCP6_OPTION_INTERFACE_ID		= 18,
	NI_DHCP6_OPTION_RECONF_MSG		= 19,
	NI_DHCP6_OPTION_RECONF_ACCEPT		= 20,
	NI_DHCP6_OPTION_SIP_SERVER_D		= 21,	/* [RFC3319] */
	NI_DHCP6_OPTION_SIP_SERVER_A		= 22,
	NI_DHCP6_OPTION_DNS_SERVERS		= 23,	/* [RFC3646] */
	NI_DHCP6_OPTION_DNS_DOMAINS		= 24,
	NI_DHCP6_OPTION_IA_PD			= 25,	/* [RFC3633] */
	NI_DHCP6_OPTION_IA_PREFIX		= 26,
	NI_DHCP6_OPTION_NIS_SERVERS		= 27,	/* [RFC3898] */
	NI_DHCP6_OPTION_NISP_SERVERS		= 28,
	NI_DHCP6_OPTION_NIS_DOMAIN_NAME		= 29,
	NI_DHCP6_OPTION_NISP_DOMAIN_NAME	= 30,
	NI_DHCP6_OPTION_SNTP_SERVERS		= 31,	/* [RFC4075] */
	NI_DHCP6_OPTION_INFO_REFRESH_TIME	= 32,	/* [RFC4242] */
	NI_DHCP6_OPTION_BCMCS_SERVER_D		= 33,	/* [RFC4280] */
	NI_DHCP6_OPTION_BCMCS_SERVER_A		= 34,
	/*					  35:	  Unassigned */
	NI_DHCP6_OPTION_GEOCONF_CIVIC		= 36,	/* [RFC4776] */
	NI_DHCP6_OPTION_REMOTE_ID		= 37,	/* [RFC4649] */
	NI_DHCP6_OPTION_SUBSCRIBER_ID		= 38,	/* [RFC4580] */
	NI_DHCP6_OPTION_FQDN			= 39,	/* [RFC4704] */
	NI_DHCP6_OPTION_PANA_AGENT		= 40,	/* [RFC5192] */
	NI_DHCP6_OPTION_POSIX_TZ_STRING		= 41,	/* [RFC4833] */
	NI_DHCP6_OPTION_POSIX_TZ_DBNAME		= 42,	/* [RFC4833] */
	NI_DHCP6_OPTION_ERO			= 43,	/* [RFC4994] */
	NI_DHCP6_OPTION_LQ_QUERY		= 44,	/* [RFC5007] */
	NI_DHCP6_OPTION_CLIENT_DATA		= 45,
	NI_DHCP6_OPTION_CLT_TIME		= 46,
	NI_DHCP6_OPTION_LQ_RELAY_DATA		= 47,
	NI_DHCP6_OPTION_LQ_CLIENT_LINK		= 48,
	NI_DHCP6_OPTION_MIP6_HNINF		= 49,	/* [RFC-ietf-mip6-hiopt-17] */
	NI_DHCP6_OPTION_MIP6_RELAY		= 50,	/* [RFC-ietf-mip6-hiopt-17] */
	NI_DHCP6_OPTION_V6_LOST			= 51,	/* [RFC5223] */
	NI_DHCP6_OPTION_CAPWAP_AC_V6		= 52,	/* [RFC5417] */
	NI_DHCP6_OPTION_RELAY_ID		= 53,	/* [RFC5460] */
	NI_DHCP6_OPTION_MOS_ADDRESSES		= 54,	/* [RFC5678] */
	NI_DHCP6_OPTION_MOS_DOMAINS		= 55,
	NI_DHCP6_OPTION_NTP_SERVER		= 56,	/* [RFC5908] */
	NI_DHCP6_OPTION_V6_ACCESS_DOMAIN	= 57,	/* [RFC5986] */
	NI_DHCP6_OPTION_SIP_UA_CS_LIST		= 58,	/* [RFC6011] */
	NI_DHCP6_OPTION_BOOTFILE_URL		= 59,	/* [RFC5970] */
	NI_DHCP6_OPTION_BOOTFILE_PARAM		= 60,	/* [RFC5970] */
	NI_DHCP6_OPTION_CLIENT_ARCH_TYPE	= 61,	/* [RFC5970] */
	NI_DHCP6_OPTION_NII			= 62,	/* [RFC5970] */
	NI_DHCP6_OPTION_GEOLOCATION		= 63,	/* [RFC6225] */
	NI_DHCP6_OPTION_AFTR_NAME		= 64,	/* [RFC6334] */
	NI_DHCP6_OPTION_ERP_LOCAL_DOMAIN	= 65,	/* [RFC6440] */
	NI_DHCP6_OPTION_RSOO			= 66,	/* [RFC6422] */
	NI_DHCP6_OPTION_PD_EXCLUDE		= 67,	/* [RFC6603] */
	NI_DHCP6_OPTION_VSS			= 68,	/* [RFC6607] */
	NI_DHCP6_OPTION_SOL_MAX_RT		= 82,	/* [RFC7083,RFC7084,RFC7550,RFC8415] */
	NI_DHCP6_OPTION_INF_MAX_RT		= 83,	/* [RFC7083,RFC7084,RFC7550,RFC8415] */

	__NI_DHCP6_OPTION_MAX
};

extern ni_dhcp6_status_t *	ni_dhcp6_status_new(void);
extern void			ni_dhcp6_status_clear(ni_dhcp6_status_t *);
extern void			ni_dhcp6_status_destroy(ni_dhcp6_status_t **);
extern const char *		ni_dhcp6_status_name(unsigned int);
extern unsigned int		ni_dhcp6_status_code(const ni_dhcp6_status_t *);
extern const char *		ni_dhcp6_status_message(const ni_dhcp6_status_t *);

extern const char *		ni_dhcp6_option_name(unsigned int);

extern ni_dhcp6_ia_pd_excl_t *	ni_dhcp6_ia_pd_excl_new(const struct in6_addr, unsigned int);
extern void			ni_dhcp6_ia_pd_excl_free(ni_dhcp6_ia_pd_excl_t **);

extern ni_dhcp6_ia_addr_t *	ni_dhcp6_ia_prefix_new (const struct in6_addr, unsigned int);
extern ni_dhcp6_ia_addr_t *	ni_dhcp6_ia_address_new(const struct in6_addr, unsigned int);

extern ni_dhcp6_ia_addr_t *	ni_dhcp6_ia_addr_new(unsigned int, const struct in6_addr,
							unsigned int);
extern ni_dhcp6_ia_addr_t *	ni_dhcp6_ia_addr_clone(const ni_dhcp6_ia_addr_t *);
extern void			ni_dhcp6_ia_addr_free(ni_dhcp6_ia_addr_t *);

extern ni_bool_t		ni_dhcp6_ia_addr_equal_address(const ni_dhcp6_ia_addr_t *,
							const ni_dhcp6_ia_addr_t *);
extern ni_bool_t		ni_dhcp6_ia_addr_equal_prefix(const ni_dhcp6_ia_addr_t *,
							const ni_dhcp6_ia_addr_t *);

extern ni_bool_t		ni_dhcp6_ia_addr_is_usable(const ni_dhcp6_ia_addr_t *);
extern ni_bool_t		ni_dhcp6_ia_addr_is_deleted(const ni_dhcp6_ia_addr_t *);

extern unsigned int		ni_dhcp6_ia_addr_valid_lft(const ni_dhcp6_ia_addr_t *,
							const struct timeval *, const struct timeval *);
extern unsigned int		ni_dhcp6_ia_addr_preferred_lft(const ni_dhcp6_ia_addr_t *,
							const struct timeval *, const struct timeval *);

extern				ni_declare_slist_append(ni_dhcp6_ia_addr);
extern				ni_declare_slist_remove(ni_dhcp6_ia_addr);
extern				ni_declare_slist_delete(ni_dhcp6_ia_addr);
extern				ni_declare_slist_destroy(ni_dhcp6_ia_addr);
extern				ni_declare_slist_copy(ni_dhcp6_ia_addr);
extern				ni_declare_slist_count(ni_dhcp6_ia_addr);

typedef ni_bool_t		ni_dhcp6_ia_addr_match_fn_t(const ni_dhcp6_ia_addr_t *,
						const ni_dhcp6_ia_addr_t *);
extern ni_dhcp6_ia_addr_t *	ni_dhcp6_ia_addr_list_find(ni_dhcp6_ia_addr_t *,
						const ni_dhcp6_ia_addr_t *,
						ni_dhcp6_ia_addr_match_fn_t *);

extern ni_dhcp6_ia_t *		ni_dhcp6_ia_new(unsigned int, unsigned int);
extern ni_dhcp6_ia_t *		ni_dhcp6_ia_na_new(unsigned int iaid);
extern ni_dhcp6_ia_t *		ni_dhcp6_ia_ta_new(unsigned int iaid);
extern ni_dhcp6_ia_t *		ni_dhcp6_ia_pd_new(unsigned int iaid);
extern ni_dhcp6_ia_t *		ni_dhcp6_ia_clone(const ni_dhcp6_ia_t *);
extern void			ni_dhcp6_ia_free(ni_dhcp6_ia_t *);
extern ni_bool_t		ni_dhcp6_ia_type_na(const ni_dhcp6_ia_t *);
extern ni_bool_t		ni_dhcp6_ia_type_ta(const ni_dhcp6_ia_t *);
extern ni_bool_t		ni_dhcp6_ia_type_pd(const ni_dhcp6_ia_t *);

extern				ni_declare_slist_append(ni_dhcp6_ia);
extern				ni_declare_slist_remove(ni_dhcp6_ia);
extern				ni_declare_slist_delete(ni_dhcp6_ia);
extern				ni_declare_slist_destroy(ni_dhcp6_ia);
extern				ni_declare_slist_copy(ni_dhcp6_ia);
extern				ni_declare_slist_count(ni_dhcp6_ia);

typedef ni_bool_t		ni_dhcp6_ia_match_fn_t(const ni_dhcp6_ia_t *,
						const ni_dhcp6_ia_t *);
extern ni_dhcp6_ia_t *		ni_dhcp6_ia_list_find(ni_dhcp6_ia_t *,
						const ni_dhcp6_ia_t *,
						ni_dhcp6_ia_match_fn_t *);

#endif /* NI_WICKED_DHCP6_OPTIONS_H */
