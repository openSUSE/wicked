/*
 *	DHCP6 option utilities used in addrconf / lease and supplicant
 *
 *	Copyright (C) 2010-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdint.h>
#include <wicked/time.h>
#include <wicked/util.h>
#include "dhcp6/options.h"
#include "util_priv.h"

/*
 * status
 */
static const char *	ni_dhcp6_status_code_names[NI_DHCP6_STATUS_CODE_MAX] = {
	[NI_DHCP6_STATUS_SUCCESS]	= "Success",
	[NI_DHCP6_STATUS_FAILURE]	= "UnspecFail",
	[NI_DHCP6_STATUS_NOADDRS]	= "NoAddrsAvail",
	[NI_DHCP6_STATUS_NOBINDING]	= "NoBinding",
	[NI_DHCP6_STATUS_NOTONLINK]	= "NotOnLink",
	[NI_DHCP6_STATUS_USEMULTICAST]	= "UseMulticast",
};

const char *
ni_dhcp6_status_name(unsigned int code)
{
	static char namebuf[64];
	const char *name = NULL;

	if (code < NI_DHCP6_STATUS_CODE_MAX)
		name = ni_dhcp6_status_code_names[code];

	if (!name && code <= UINT16_MAX) {
		snprintf(namebuf, sizeof(namebuf), "[%u]", code);
		name = namebuf;
	}
	return name;
}

unsigned int
ni_dhcp6_status_code(const ni_dhcp6_status_t *status)
{
	return status ? status->code : -1U;
}

const char *
ni_dhcp6_status_message(const ni_dhcp6_status_t *status)
{
	return status ? status->message : NULL;
}

ni_dhcp6_status_t *
ni_dhcp6_status_new(void)
{
	return calloc(1, sizeof(ni_dhcp6_status_t));
}

void
ni_dhcp6_status_clear(ni_dhcp6_status_t *status)
{
	if (status) {
		status->code = 0;
		ni_string_free(&status->message);
	}
}

void
ni_dhcp6_status_destroy(ni_dhcp6_status_t **status)
{
	if (status && *status) {
		ni_dhcp6_status_clear(*status);
		free(*status);
		*status = NULL;
	}
}

/*
 * ia addr
 */
extern ni_dhcp6_ia_addr_t *
ni_dhcp6_ia_addr_new(unsigned int type, const struct in6_addr addr, unsigned int plen)
{
	ni_dhcp6_ia_addr_t *iadr;

	iadr = calloc(1, sizeof(*iadr));
	if (iadr) {
		iadr->type = type;
		iadr->addr = addr;
		iadr->plen = plen;
	}
	return iadr;
}

/*
 * ia-address
 */
ni_dhcp6_ia_addr_t *
ni_dhcp6_ia_address_new(const struct in6_addr addr, unsigned int plen)
{
	return ni_dhcp6_ia_addr_new(NI_DHCP6_OPTION_IA_ADDRESS, addr, plen);
}
/*
 * ia-prefix
 */
ni_dhcp6_ia_addr_t *
ni_dhcp6_ia_prefix_new(const struct in6_addr addr, unsigned int plen)
{
	return ni_dhcp6_ia_addr_new(NI_DHCP6_OPTION_IA_PREFIX, addr, plen);
}

/*
 * ia-prefix pd-exclude
 */
ni_dhcp6_ia_pd_excl_t *
ni_dhcp6_ia_pd_excl_new(const struct in6_addr addr, unsigned int plen)
{
	ni_dhcp6_ia_pd_excl_t *excl;

	excl = calloc(1, sizeof(*excl));
	if (excl) {
		excl->addr = addr;
		excl->plen = plen;
	}
	return excl;
}

void
ni_dhcp6_ia_pd_excl_free(ni_dhcp6_ia_pd_excl_t **excl)
{
	if (excl && *excl) {
		free(*excl);
		*excl = NULL;
	}
}

ni_dhcp6_ia_addr_t *
ni_dhcp6_ia_addr_clone(const ni_dhcp6_ia_addr_t *iadr)
{
	ni_dhcp6_ia_addr_t *nadr;

	if (!iadr || !(nadr = ni_dhcp6_ia_addr_new(iadr->type, iadr->addr, iadr->plen)))
		return NULL;

	if (iadr->excl &&
	    !(nadr->excl = ni_dhcp6_ia_pd_excl_new(iadr->excl->addr, iadr->excl->plen)))
		goto failure;

	nadr->flags = iadr->flags;
	nadr->valid_lft = iadr->valid_lft;
	nadr->preferred_lft = iadr->preferred_lft;
	nadr->status.code = iadr->status.code;
	if (!ni_string_dup(&nadr->status.message, iadr->status.message))
		goto failure;

	return nadr;

failure:
	ni_dhcp6_ia_addr_free(nadr);
	return NULL;
}

void
ni_dhcp6_ia_addr_free(ni_dhcp6_ia_addr_t *iadr)
{
	if (iadr) {
		ni_dhcp6_status_clear(&iadr->status);
		ni_dhcp6_ia_pd_excl_free(&iadr->excl);
		free(iadr);
	}
}

ni_bool_t
ni_dhcp6_ia_addr_equal_address(const ni_dhcp6_ia_addr_t *a, const ni_dhcp6_ia_addr_t *b)
{
	return IN6_ARE_ADDR_EQUAL(&a->addr, &b->addr);
}

ni_bool_t
ni_dhcp6_ia_addr_equal_prefix(const ni_dhcp6_ia_addr_t *a, const ni_dhcp6_ia_addr_t *b)
{
	return a->plen == b->plen && ni_dhcp6_ia_addr_equal_address(a, b);
}

ni_bool_t
ni_dhcp6_ia_addr_is_deleted(const ni_dhcp6_ia_addr_t *iadr)
{
	/* This is a stop using this iadr order from server. */
	return iadr && iadr->valid_lft == NI_LIFETIME_EXPIRED;
}

ni_bool_t
ni_dhcp6_ia_addr_is_usable(const ni_dhcp6_ia_addr_t *iadr)
{
	/* This is an invalid iadr lifetime combination. */
	if (!iadr || iadr->preferred_lft > iadr->valid_lft)
		return FALSE;

	/* This is some well-known nonsense we reject...  */
	if (IN6_IS_ADDR_UNSPECIFIED(&iadr->addr) ||
	    IN6_IS_ADDR_LOOPBACK(&iadr->addr) ||
	    IN6_IS_ADDR_LINKLOCAL(&iadr->addr) ||
	    IN6_IS_ADDR_MULTICAST(&iadr->addr))
		return FALSE;
	return TRUE;
}

unsigned int
ni_dhcp6_ia_addr_valid_lft(const ni_dhcp6_ia_addr_t *iadr, const struct timeval *acquired, const struct timeval *now)
{
	return iadr ? ni_lifetime_left(iadr->valid_lft, acquired, now) : NI_LIFETIME_EXPIRED;
}

unsigned int
ni_dhcp6_ia_addr_preferred_lft(const ni_dhcp6_ia_addr_t *iadr, const struct timeval *acquired, const struct timeval *now)
{
	return iadr ? ni_lifetime_left(iadr->preferred_lft, acquired, now) : NI_LIFETIME_EXPIRED;
}

/*
 * ia address list
 */
ni_bool_t
ni_dhcp6_ia_addr_list_append(ni_dhcp6_ia_addr_t **list, ni_dhcp6_ia_addr_t *iadr)
{
	if (list && iadr) {
		while (*list)
			list = &(*list)->next;
		*list = iadr;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_dhcp6_ia_addr_list_remove(ni_dhcp6_ia_addr_t **list, ni_dhcp6_ia_addr_t *iadr)
{
	ni_dhcp6_ia_addr_t **pos, *cur;

	if (list && iadr) {
		for (pos = list; (cur = *pos); pos = &cur->next) {
			if (iadr == cur) {
				*pos =  cur->next;
				cur->next = NULL;
				return TRUE;
			}
		}
	}
	return FALSE;
}

ni_bool_t
ni_dhcp6_ia_addr_list_delete(ni_dhcp6_ia_addr_t **list, ni_dhcp6_ia_addr_t *iadr)
{
	if (ni_dhcp6_ia_addr_list_remove(list, iadr)) {
		ni_dhcp6_ia_addr_free(iadr);
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_dhcp6_ia_addr_list_copy(ni_dhcp6_ia_addr_t **dst, const ni_dhcp6_ia_addr_t *src)
{
	const ni_dhcp6_ia_addr_t *iadr;
	ni_dhcp6_ia_addr_t *nadr;

	ni_dhcp6_ia_addr_list_destroy(dst);
	for (iadr = src; iadr; iadr = iadr->next) {
		nadr = ni_dhcp6_ia_addr_clone(iadr);

		if (ni_dhcp6_ia_addr_list_append(dst, nadr))
			continue;

		ni_dhcp6_ia_addr_free(nadr);
		ni_dhcp6_ia_addr_list_destroy(dst);
		return FALSE;
	}
	return TRUE;
}

size_t
ni_dhcp6_ia_addr_list_count(const ni_dhcp6_ia_addr_t *list)
{
	const ni_dhcp6_ia_addr_t *iadr;
	size_t count = 0;

	for (iadr = list; iadr; iadr = iadr->next)
		count++;

	return count;
}

void
ni_dhcp6_ia_addr_list_destroy(ni_dhcp6_ia_addr_t **list)
{
	ni_dhcp6_ia_addr_t *iadr;

	if (list) {
		while ((iadr = *list)) {
			*list = iadr->next;
			ni_dhcp6_ia_addr_free(iadr);
		}
	}
}

ni_dhcp6_ia_addr_t *
ni_dhcp6_ia_addr_list_find(ni_dhcp6_ia_addr_t *head, const ni_dhcp6_ia_addr_t *adr,
			ni_dhcp6_ia_addr_match_fn_t *match)
{
	ni_dhcp6_ia_addr_t *cur;

	if (!adr || !match)
		return NULL;

	for (cur = head; cur; cur = cur->next) {
		if (match(cur, adr))
			return cur;
	}

	return NULL;
}


/*
 * ia
 */
ni_dhcp6_ia_t *
ni_dhcp6_ia_new(unsigned int type, unsigned int iaid)
{
	ni_dhcp6_ia_t *ia;

	ia = calloc(1, sizeof(*ia));
	if (ia) {
		ia->type = type;
		ia->iaid = iaid;
	}
	return ia;
}
ni_dhcp6_ia_t *
ni_dhcp6_ia_na_new(unsigned int iaid)
{
	return ni_dhcp6_ia_new(NI_DHCP6_OPTION_IA_NA, iaid);
}
ni_dhcp6_ia_t *
ni_dhcp6_ia_ta_new(unsigned int iaid)
{
	return ni_dhcp6_ia_new(NI_DHCP6_OPTION_IA_TA, iaid);
}
ni_dhcp6_ia_t *
ni_dhcp6_ia_pd_new(unsigned int iaid)
{
	return ni_dhcp6_ia_new(NI_DHCP6_OPTION_IA_PD, iaid);
}

ni_dhcp6_ia_t *
ni_dhcp6_ia_clone(const ni_dhcp6_ia_t *ia)
{
	ni_dhcp6_ia_t *nia;

	if (!ia || !(nia = ni_dhcp6_ia_new(ia->type, ia->iaid)))
		return NULL;

	nia->flags = ia->flags;
	nia->rebind_time = ia->rebind_time;
	nia->renewal_time = ia->renewal_time;
	nia->acquired = ia->acquired;
	nia->status.code = ia->status.code;
	if (!ni_string_dup(&nia->status.message, ia->status.message))
		goto failure;

	if (!ni_dhcp6_ia_addr_list_copy(&nia->addrs, ia->addrs))
		goto failure;

	return nia;

failure:
	ni_dhcp6_ia_free(nia);
	return NULL;
}

void
ni_dhcp6_ia_free(ni_dhcp6_ia_t *ia)
{
	if (ia) {
		ni_dhcp6_status_clear(&ia->status);
		ni_dhcp6_ia_addr_list_destroy(&ia->addrs);
		free(ia);
	}
}

ni_bool_t
ni_dhcp6_ia_type_na(const ni_dhcp6_ia_t *ia)
{
	return ia->type == NI_DHCP6_OPTION_IA_NA;
}
ni_bool_t
ni_dhcp6_ia_type_ta(const ni_dhcp6_ia_t *ia)
{
	return ia->type == NI_DHCP6_OPTION_IA_TA;
}
ni_bool_t
ni_dhcp6_ia_type_pd(const ni_dhcp6_ia_t *ia)
{
	return ia->type == NI_DHCP6_OPTION_IA_PD;
}

/*
 * ia list
 */
ni_bool_t
ni_dhcp6_ia_list_append(ni_dhcp6_ia_t **list, ni_dhcp6_ia_t *ia)
{
	if (list && ia) {
		while (*list)
			list = &(*list)->next;
		*list = ia;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_dhcp6_ia_list_remove(ni_dhcp6_ia_t **list, ni_dhcp6_ia_t *ia)
{
	ni_dhcp6_ia_t **pos, *cur;

	if (list && ia) {
		for (pos = list; (cur = *pos); pos = &cur->next) {
			if (ia == cur) {
				*pos =  cur->next;
				cur->next = NULL;
				return TRUE;
			}
		}
	}
	return FALSE;
}

ni_bool_t
ni_dhcp6_ia_list_delete(ni_dhcp6_ia_t **list, ni_dhcp6_ia_t *ia)
{
	if (ni_dhcp6_ia_list_remove(list, ia)) {
		ni_dhcp6_ia_free(ia);
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_dhcp6_ia_list_copy(ni_dhcp6_ia_t **dst, const ni_dhcp6_ia_t *src)
{
	const ni_dhcp6_ia_t *ia;
	ni_dhcp6_ia_t *nia;

	ni_dhcp6_ia_list_destroy(dst);
	for (ia = src; ia; ia = ia->next) {
		nia = ni_dhcp6_ia_clone(ia);

		if (ni_dhcp6_ia_list_append(dst, nia))
			continue;

		ni_dhcp6_ia_free(nia);
		ni_dhcp6_ia_list_destroy(dst);
		return FALSE;
	}
	return TRUE;
}

size_t
ni_dhcp6_ia_list_count(const ni_dhcp6_ia_t *list)
{
	const ni_dhcp6_ia_t *ia;
	size_t count = 0;

	for (ia = list; ia; ia = ia->next)
		count++;

	return count;
}

void
ni_dhcp6_ia_list_destroy(ni_dhcp6_ia_t **list)
{
	ni_dhcp6_ia_t *ia;

	if (list) {
		while ((ia = *list) != NULL) {
			*list = ia->next;
			ni_dhcp6_ia_free(ia);
		}
	}
}

ni_dhcp6_ia_t *
ni_dhcp6_ia_list_find(ni_dhcp6_ia_t *head, const ni_dhcp6_ia_t *ia,
			ni_dhcp6_ia_match_fn_t *match)
{
	ni_dhcp6_ia_t *cur;

	if (!ia || !match)
		return NULL;

	for (cur = head; cur; cur = cur->next) {
		if (match(cur, ia))
			return cur;
	}

	return NULL;
}


/*
 * Map DHCP6 options to names
 */
static const char *__dhcp6_option_names[__NI_DHCP6_OPTION_MAX] = {
	[NI_DHCP6_OPTION_CLIENTID]          =	"client-id",
	[NI_DHCP6_OPTION_SERVERID]          =	"server-id",
	[NI_DHCP6_OPTION_IA_NA]             =	"ia-na",
	[NI_DHCP6_OPTION_IA_TA]             =	"ia-ta",
	[NI_DHCP6_OPTION_IA_ADDRESS]        =	"ia-address",
	[NI_DHCP6_OPTION_ORO]               =	"oro",
	[NI_DHCP6_OPTION_PREFERENCE]        =	"preference",
	[NI_DHCP6_OPTION_ELAPSED_TIME]      =	"elapsed-time",
	[NI_DHCP6_OPTION_RELAY_MSG]         =	"relay-msg",
	[NI_DHCP6_OPTION_AUTH]              =	"auth",
	[NI_DHCP6_OPTION_UNICAST]           =	"unicast",
	[NI_DHCP6_OPTION_STATUS_CODE]       =	"status-code",
	[NI_DHCP6_OPTION_RAPID_COMMIT]      =	"rapid-commit",
	[NI_DHCP6_OPTION_USER_CLASS]        =	"user-class",
	[NI_DHCP6_OPTION_VENDOR_CLASS]      =	"vendor-class",
	[NI_DHCP6_OPTION_VENDOR_OPTS]       =	"vendor-opts",
	[NI_DHCP6_OPTION_INTERFACE_ID]      =	"interface-id",
	[NI_DHCP6_OPTION_RECONF_MSG]        =	"reconf-msg",
	[NI_DHCP6_OPTION_RECONF_ACCEPT]     =	"reconf-accept",
	[NI_DHCP6_OPTION_SIP_SERVER_D]      =	"sip-server-names",
	[NI_DHCP6_OPTION_SIP_SERVER_A]      =	"sip-server-addresses",
	[NI_DHCP6_OPTION_DNS_SERVERS]       =	"dns-servers",
	[NI_DHCP6_OPTION_DNS_DOMAINS]       =	"dns-domains",
	[NI_DHCP6_OPTION_IA_PD]             =	"ia-pd",
	[NI_DHCP6_OPTION_IA_PREFIX]         =	"ia-prefix",
	[NI_DHCP6_OPTION_NIS_SERVERS]       =	"nis-servers",
	[NI_DHCP6_OPTION_NISP_SERVERS]      =	"nisplus-servers",
	[NI_DHCP6_OPTION_NIS_DOMAIN_NAME]   =	"nis-domain",
	[NI_DHCP6_OPTION_NISP_DOMAIN_NAME]  =	"nisplus-domain",
	[NI_DHCP6_OPTION_SNTP_SERVERS]      =	"sntp-servers",
	[NI_DHCP6_OPTION_INFO_REFRESH_TIME] =	"info-refresh-time",
	[NI_DHCP6_OPTION_BCMCS_SERVER_D]    =	"bcms-domains",
	[NI_DHCP6_OPTION_BCMCS_SERVER_A]    =	"bcms-servers",
	[NI_DHCP6_OPTION_GEOCONF_CIVIC]     =	"geoconf-civic",
	[NI_DHCP6_OPTION_REMOTE_ID]         =	"remote-id",
	[NI_DHCP6_OPTION_SUBSCRIBER_ID]     =	"subscriber-id",
	[NI_DHCP6_OPTION_FQDN]              =	"fqdn",
	[NI_DHCP6_OPTION_PANA_AGENT]        =	"pana-agent",
	[NI_DHCP6_OPTION_POSIX_TZ_STRING]   =	"posix-tz-string",
	[NI_DHCP6_OPTION_POSIX_TZ_DBNAME]  =	"posix-tz-dbname",
	[NI_DHCP6_OPTION_ERO]               =	"ero",
	[NI_DHCP6_OPTION_LQ_QUERY]          =	"lq-query",
	[NI_DHCP6_OPTION_CLIENT_DATA]       =	"client-data",
	[NI_DHCP6_OPTION_CLT_TIME]          =	"clt-time",
	[NI_DHCP6_OPTION_LQ_RELAY_DATA]     =	"lq-relay-data",
	[NI_DHCP6_OPTION_LQ_CLIENT_LINK]    =	"lq-cient-link",
	[NI_DHCP6_OPTION_MIP6_HNINF]        =	"mip6-hninf",
	[NI_DHCP6_OPTION_MIP6_RELAY]        =	"mip6-relay",
	[NI_DHCP6_OPTION_V6_LOST]           =	"v6-lost",
	[NI_DHCP6_OPTION_CAPWAP_AC_V6]      =	"capwap-ac-v6",
	[NI_DHCP6_OPTION_RELAY_ID]          =	"relay-id",
	[NI_DHCP6_OPTION_MOS_ADDRESSES]     =	"mos-addresses",
	[NI_DHCP6_OPTION_MOS_DOMAINS]       =	"mos-domains",
	[NI_DHCP6_OPTION_NTP_SERVER]        =	"ntp-server",
	[NI_DHCP6_OPTION_V6_ACCESS_DOMAIN]  =	"v6-access-domain",
	[NI_DHCP6_OPTION_SIP_UA_CS_LIST]    =	"sip-ua-cs-list",
	[NI_DHCP6_OPTION_BOOTFILE_URL]      =	"bootfile-url",
	[NI_DHCP6_OPTION_BOOTFILE_PARAM]    =	"bootfile-param",
	[NI_DHCP6_OPTION_CLIENT_ARCH_TYPE]  =	"client-arch-type",
	[NI_DHCP6_OPTION_NII]               =	"nii",
	[NI_DHCP6_OPTION_GEOLOCATION]       =	"geolocation",
	[NI_DHCP6_OPTION_AFTR_NAME]         =	"aftr-name",
	[NI_DHCP6_OPTION_ERP_LOCAL_DOMAIN]  =	"erp-local-domain",
	[NI_DHCP6_OPTION_RSOO]              =	"rsoo",
	[NI_DHCP6_OPTION_PD_EXCLUDE]        =	"pd-exclude",
	[NI_DHCP6_OPTION_VSS]               =	"vss",
	[NI_DHCP6_OPTION_SOL_MAX_RT]        =	"sol-max-rt",
	[NI_DHCP6_OPTION_INF_MAX_RT]        =	"inf-max-rt",
};

const char *
ni_dhcp6_option_name(unsigned int option)
{
	static char namebuf[64];
	const char *name = NULL;

	if (option < __NI_DHCP6_OPTION_MAX)
		name = __dhcp6_option_names[option];

	if (!name) {
		snprintf(namebuf, sizeof(namebuf), "[%u]", option);
		name = namebuf;
	}
	return name;
}
