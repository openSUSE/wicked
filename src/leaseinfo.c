/*
 *	Lease information extraction for output to files.
 *
 *	Copyright (C) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 *		Karol Mroz <kmroz@suse.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#include <wicked/leaseinfo.h>

#include <wicked/logging.h>
#include <wicked/util.h>
#include <wicked/address.h>
#include <wicked/addrconf.h>
#include <wicked/resolver.h>
#include <wicked/netinfo.h>
#include <wicked/nis.h>
#include <wicked/route.h>

#include "util_priv.h"
#include "dhcp6/options.h"
#include "dbus-objects/model.h"
#include "dbus-objects/misc.h"

static const char *	__ni_keyword_format(char **, const char *,
					const char *, unsigned int);
static void		__ni_leaseinfo_print_string(FILE *, const char *,
					const char *, const char *,
					const char *, unsigned int);
static void		__ni_leaseinfo_print_string_array(FILE *, const char *,
					const char *, const ni_string_array_t *,
					const char *);
static void		__ni_leaseinfo_dhcp4_dump(FILE *,
				const ni_addrconf_lease_t *,
				const char *);
static void		__ni_leaseinfo_dhcp6_dump(FILE *,
				const ni_addrconf_lease_t *,
				const char *);
static void		__ni_leaseinfo_print_addrs(FILE *, const char *,
					ni_address_t *, unsigned int);
static void		__ni_leaseinfo_print_routes(FILE *, const char *,
					ni_route_table_t *, unsigned int);
static void		__ni_leaseinfo_print_nis(FILE *, const char *,
					ni_nis_info_t *);
static void		__ni_leaseinfo_print_resolver(FILE *, const char *,
					ni_resolver_info_t *);
static void		__ni_leaseinfo_print_netbios(FILE *, const char *,
					const ni_addrconf_lease_t *);
static void		__ni_leaseinfo_dump(FILE *, const ni_addrconf_lease_t *,
				const char *, const char *);
#if 0
static const char *	__ni_leaseinfo_strftime(time_t);
#endif

static const char *
__ni_keyword_format(char **key, const char *prefix,
                    const char *var, unsigned int index)
{
	if (!prefix)
		prefix = "";

	if (index)
		return ni_string_printf(key, "%s%s_%u", prefix, var, index);
	else
		return ni_string_printf(key, "%s%s", prefix, var);
}

static void
__ni_leaseinfo_print_string(FILE *out, const char *prefix, const char *name,
			const char *val, const char *default_val,
			unsigned int index)
{
	char *key = NULL;
	const char *val_to_print = NULL;

	if (!val && !default_val)
		return;

	if (strlen(val) == 0 && !default_val)
		return;

	val_to_print = val ? val : default_val;

	fprintf(out, "%s='%s'\n", __ni_keyword_format
		(&key, prefix, name, index),
		val_to_print);

	ni_string_free(&key);
}

static void
__ni_leaseinfo_print_string_array(FILE *out, const char *prefix, const char *name,
				const ni_string_array_t *str_arr, const char *sep)
{
	char *key = NULL;
	unsigned int i;
	ni_bool_t doneone;

	if (!str_arr || str_arr->count == 0)
		return;

	if (!sep)
		sep = " ";

	doneone = FALSE;
	fprintf(out, "%s='", __ni_keyword_format
		(&key, prefix, name, 0));

	for (i = 0; i < str_arr->count; ++i) {
		if (doneone)
			fprintf(out, " ");
		fprintf(out, "%s", str_arr->data[i]);
		doneone = TRUE;
	}
	fprintf(out, "'\n");

	ni_string_free(&key);
}

static void
__ni_leaseinfo_print_addrs(FILE *out, const char *prefix, ni_address_t *addrs,
				unsigned int family)
{
	ni_address_t *ap;
	ni_sockaddr_t sa;
	unsigned int i;
	char *buf = NULL;

	for (i = 0, ap = addrs; ap; ++i, ap = ap->next) {
		if (family != AF_UNSPEC && family != ap->local_addr.ss_family)
			continue;

		switch (ap->local_addr.ss_family) {
		case AF_INET:
			__ni_leaseinfo_print_string(out, prefix, "IPADDR",
						ni_sockaddr_print(&ap->local_addr),
						NULL, i);

			ni_sockaddr_build_netmask(ap->family,ap->prefixlen, &sa);
			__ni_leaseinfo_print_string(out, prefix, "NETMASK",
						ni_sockaddr_print(&sa), NULL, i);

			sa.sin.sin_addr.s_addr &= ap->local_addr.sin.sin_addr.s_addr;
			__ni_leaseinfo_print_string(out, prefix, "NETWORK",
						ni_sockaddr_print(&sa), NULL, i);

			ni_string_printf(&buf, "%u", ap->prefixlen);
			__ni_leaseinfo_print_string(out, prefix, "PREFIXLEN",
						buf, NULL, i);
			ni_string_free(&buf);
			break;

		case AF_INET6:
			__ni_leaseinfo_print_string(out, prefix, "IPADDR",
						ni_sockaddr_print(&ap->local_addr),
						NULL, i);

			ni_string_printf(&buf, "%u", ap->prefixlen);
			__ni_leaseinfo_print_string(out, prefix, "PREFIXLEN",
						buf, NULL, i);
			ni_string_free(&buf);
			break;

		default:
			break;
		}
	}
}

static void
__ni_leaseinfo_format_route(ni_string_array_t *routes, ni_string_array_t *gates, ni_route_t *rp)
{
	ni_route_nexthop_t *nh;
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_sockaddr_t nogateway;
	ni_sockaddr_t netmask;

	memset(&nogateway, 0, sizeof(nogateway));
	for (nh = &rp->nh; nh; nh = nh->next) {
		if (ni_sockaddr_is_specified(&rp->destination)) {
			/* (network) ROUTES + = 'dest,netmask/prefixlen,gateway' */
			ni_stringbuf_puts(&buf, ni_sockaddr_print(&rp->destination));
			ni_stringbuf_putc(&buf, ',');

			switch (rp->family) {
			case AF_INET:
				ni_sockaddr_build_netmask(rp->family, rp->prefixlen,
							&netmask);
				ni_stringbuf_puts(&buf, ni_sockaddr_print(&netmask));
				break;
			case AF_INET6:
				ni_stringbuf_printf(&buf, "%u", rp->prefixlen);
				break;
			default: ;
			}
			ni_stringbuf_putc(&buf, ',');

			if (ni_sockaddr_is_specified(&nh->gateway)) {
				ni_stringbuf_puts(&buf, ni_sockaddr_print(&nh->gateway));
			} else {
				nogateway.ss_family = rp->family;
				ni_stringbuf_puts(&buf, ni_sockaddr_print(&nogateway));
			}

			if (!ni_string_empty(buf.string)) {
				if (ni_string_array_index(routes, buf.string) == -1)
					ni_string_array_append(routes, buf.string);
			}
		} else if (ni_sockaddr_is_specified(&nh->gateway)) {
			/* (default) GATEWAYS += 'gateway' */
			ni_stringbuf_puts(&buf, ni_sockaddr_print(&nh->gateway));
			if (!ni_string_empty(buf.string)) {
				if (ni_string_array_index(gates, buf.string) == -1)
					ni_string_array_append(gates, buf.string);
			}
		}
		ni_stringbuf_destroy(&buf);
	}
}

static void
__ni_leaseinfo_print_routes(FILE *out, const char *prefix,
			ni_route_table_t *routes, unsigned int family)
{
	ni_string_array_t routes_entry_arr = NI_STRING_ARRAY_INIT;
	ni_string_array_t gw_entry_arr = NI_STRING_ARRAY_INIT;
	ni_route_table_t *rtp;
	ni_route_t *rp;
	unsigned int i;

	for (rtp = routes; rtp; rtp = rtp->next) {
		if (!ni_string_eq(ni_route_table_type_to_name(rtp->tid), "main"))
			continue;

		for (i = 0; i < rtp->routes.count; ++i) {
			const char *type;

			rp = rtp->routes.data[i];
			if (family != AF_UNSPEC && family != rp->family)
				continue;

			if (rp->table != rtp->tid)
				continue;

			type = ni_route_type_type_to_name(rp->type);
			if (ni_string_eq(type, "unicast") ||
			    ni_string_eq(type, "local")) {
				__ni_leaseinfo_format_route(&routes_entry_arr,
								&gw_entry_arr, rp);
			}
		}
	}

	__ni_leaseinfo_print_string_array(out, prefix, "ROUTES",
					&routes_entry_arr, " ");
	__ni_leaseinfo_print_string_array(out, prefix, "GATEWAYS",
					&gw_entry_arr, " ");

	ni_string_array_destroy(&routes_entry_arr);
	ni_string_array_destroy(&gw_entry_arr);
}

static void
__ni_leaseinfo_print_nis(FILE *out, const char *prefix, ni_nis_info_t *nis)
{
	unsigned int i;

	if (!nis)
		return;

	__ni_leaseinfo_print_string(out, prefix, "NISDOMAIN", nis->domainname,
				NULL, 0);

	__ni_leaseinfo_print_string_array(out, prefix, "NISSERVERS",
					&nis->default_servers, " ");

	for (i = 0; i < nis->domains.count; ++i) {
		__ni_leaseinfo_print_string(out, prefix, "NISDOMAIN",
					nis->domains.data[i]->domainname,
					NULL, i);

		__ni_leaseinfo_print_string_array(out, prefix, "NISSERVERS",
						&nis->domains.data[i]->servers,
						" ");
	}
}

static void
__ni_leaseinfo_print_resolver(FILE *out, const char *prefix,
			ni_resolver_info_t *resolver)
{
	if (!resolver)
		return;

	__ni_leaseinfo_print_string(out, prefix, "DNSDOMAIN",
				resolver->default_domain, NULL, 0);

	__ni_leaseinfo_print_string_array(out, prefix, "DNSSERVERS",
					&resolver->dns_servers, " ");

	__ni_leaseinfo_print_string_array(out, prefix, "DNSSEARCH",
					&resolver->dns_search, " ");
}

static void
__ni_leaseinfo_print_netbios(FILE *out, const char *prefix,
			const ni_addrconf_lease_t *lease)
{
	/* Netbios Name Servers */
	__ni_leaseinfo_print_string_array(out, prefix, "NETBIOSNAMESERVER",
					&lease->netbios_name_servers, " ");

	/* Netbios Datagram Distribution Servers */
	__ni_leaseinfo_print_string_array(out, prefix, "NETBIOSDDSERVER",
					&lease->netbios_dd_servers, " ");

	/* Netbios Scope */
	__ni_leaseinfo_print_string(out, prefix, "NETBIOSSCOPE",
				lease->netbios_scope,
				NULL, 0);

	/* Netbios Type */
	__ni_leaseinfo_print_string(out, prefix, "NETBIOSNODETYPE",
				ni_netbios_node_type_to_name(lease->netbios_type),
				NULL, 0);
}

#if 0
static const char *
__ni_leaseinfo_strftime(time_t t)
{
	static char buf[64];

	if (t == 0)
		return NULL;

	buf[0] = '\0';
	strftime(buf, sizeof(buf), "%F-%T", localtime(&t));

	return buf;
}
#endif

static void
__ni_leaseinfo_dhcp4_dump(FILE *out, const ni_addrconf_lease_t *lease,
			const char *prefix)
{
	char *key = NULL;
	ni_sockaddr_t sa;

#if 0
	/* serveraddress */
	ni_sockaddr_set_ipv4(&sa, lease->dhcp.serveraddress, 0);
	__ni_leaseinfo_print_string(out, prefix, "DHCPSID",
				ni_sockaddr_print(&sa), NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "DHCPSNAME",
				lease->dhcp.servername,
				NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "CLIENTID",
				lease->dhcp.client_id,
				"", 0);
#endif

	/*
	 * Hmm...
	 * Address and netmask specified as part of generic dump, so not
	 * duplicating here.
	 */
	ni_sockaddr_set_ipv4(&sa, lease->dhcp.broadcast, 0);
	if (ni_sockaddr_is_specified(&sa)) {
		__ni_leaseinfo_print_string(out, prefix, "BROADCAST",
					ni_sockaddr_print(&sa), NULL, 0);
	}

#if 0
	if (lease->dhcp.mtu) {
		fprintf(out, "%s='%"PRIu16"'\n", __ni_keyword_format
			(&key, prefix, "MTU", 0),
			lease->dhcp.mtu);
	}

	__ni_leaseinfo_print_string(out, prefix, "LEASETIME",
				__ni_leaseinfo_strftime(lease->dhcp.lease_time),
				NULL, 0);
	__ni_leaseinfo_print_string(out, prefix, "RENEWALTIME",
				__ni_leaseinfo_strftime(lease->dhcp.renewal_time),
				NULL, 0);
	__ni_leaseinfo_print_string(out, prefix, "REBINDTIME",
				__ni_leaseinfo_strftime(lease->dhcp.rebind_time),
				NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "MESSAGE",
				lease->dhcp.message,
				NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "BOOTFILE",
				lease->dhcp.bootfile,
				NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "ROOTPATH",
				lease->dhcp.rootpath,
				NULL, 0);
#endif

	ni_string_free(&key);
}

static void
__ni_leaseinfo_dhcp6_dump(FILE *out, const ni_addrconf_lease_t *lease,
			const char *prefix)
{
#if 0
	struct ni_dhcp6_ia *ia_p = NULL;
	int i;
	char *key = NULL;
	ni_sockaddr_t sa;

	__ni_leaseinfo_print_string(out, prefix, "CLIENTID",
				ni_print_hex(lease->dhcp6.client_id.data,
					     lease->dhcp6.client_id.len),
				"", 0);
	__ni_leaseinfo_print_string(out, prefix, "DHCP6SNAME",
				ni_print_hex(lease->dhcp6.server_id.data,
					     lease->dhcp6.server_id.len),
				NULL, 0);
	fprintf(out, "%s='%"PRIu8"'\n", __ni_keyword_format
		(&key, prefix, "SERVERPREF", 0),
		lease->dhcp6.server_pref);

	ni_sockaddr_set_ipv6(&sa, lease->dhcp6.server_addr, 0);
	__ni_leaseinfo_print_string(out, prefix, "DHCP6SID",
				ni_sockaddr_print(&sa), NULL, 0);

	if (lease->dhcp6.rapid_commit)
		__ni_leaseinfo_print_string(out, prefix, "RAPIDCOMMIT",
					"TRUE", NULL, 0);

	/* dhcp6 status */
	if (lease->dhcp6.status) {
		fprintf(out, "%s='%"PRIu16"'\n", __ni_keyword_format
			(&key, prefix, "DHCP6STATUSCODE", 0),
			lease->dhcp6.status->code);
		__ni_leaseinfo_print_string(out, prefix, "DHCP6STATUSMESSAGE",
					lease->dhcp6.status->message,
					NULL, 0);
	}

	/* dhcp6 addressing */
	for (i = 0, ia_p = lease->dhcp6.ia_list; ia_p; ++i, ia_p = ia_p->next) {
		ni_sockaddr_t sa;

		/* skip NI_DHCP6_OPTION_IA_PD for now */
		if (ia_p->type != NI_DHCP6_OPTION_IA_NA &&
		    ia_p->type != NI_DHCP6_OPTION_IA_TA)
			continue;

		ni_sockaddr_set_ipv6(&sa, ia_p->addrs->addr, 0);
		__ni_leaseinfo_print_string(out, prefix, "IALIST_IN6_ADDR",
					ni_sockaddr_print(&sa),
					NULL, i);
		__ni_leaseinfo_print_string(out, prefix,
					"IALIST_IN6_TIMEACQUIRED",
					__ni_leaseinfo_strftime(
						ia_p->time_acquired),
					NULL, i);
		__ni_leaseinfo_print_string(out, prefix,
					"IALIST_IN6_RENEWALTIME",
					__ni_leaseinfo_strftime(
						ia_p->renewal_time),
					NULL, i);
		__ni_leaseinfo_print_string(out, prefix,
					"IALIST_IN6_REBINDTIME",
					__ni_leaseinfo_strftime(
						ia_p->rebind_time),
					NULL, i);
	}

	ni_string_free(&key);
#endif
}

static void
__ni_leaseinfo_dump(FILE *out, const ni_addrconf_lease_t *lease,
		const char *ifname, const char *prefix)
{
#if 0
	unsigned int i;
#endif
	char *key = NULL;

	__ni_leaseinfo_print_string(out, prefix, "INTERFACE", ifname, "", 0);

#if 0
	/* wicked specific vars */

	__ni_leaseinfo_print_string(out, prefix, "TYPE",
				ni_addrconf_type_to_name(lease->type),
				NULL, 0);
	__ni_leaseinfo_print_string(out, prefix, "FAMILY",
				ni_addrfamily_type_to_name(lease->family),
				NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "OWNER", lease->owner, NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "UUID", ni_uuid_print(&lease->uuid), NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "STATE",
				ni_addrconf_state_to_name(lease->state),
				NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "TIMEACQUIRED",
				__ni_leaseinfo_strftime(lease->time_acquired),
				NULL, 0);

	fprintf(out, "%s='%u'\n", __ni_keyword_format
		(&key, prefix, "UPDATE", 0),
		lease->update);

	/* end wicked specific vars */

	__ni_leaseinfo_print_string(out, prefix, "HOSTNAME", lease->hostname,
				NULL, 0);
#endif

	__ni_leaseinfo_print_addrs(out, prefix, lease->addrs, lease->family);

	__ni_leaseinfo_print_routes(out, prefix, lease->routes, lease->family);

	/* Only applicable for ipv4. */
	if (lease->family == AF_INET)
		__ni_leaseinfo_print_nis(out, prefix, lease->nis);

	__ni_leaseinfo_print_resolver(out, prefix, lease->resolver);

#if 0
	/* Log Servers */
	for (i = 0; i < lease->log_servers.count; ++i) {
		__ni_leaseinfo_print_string(out, prefix, "LOGSERVER",
					lease->log_servers.data[i],
					NULL, i);
	}
#endif

	/* NTP Servers */
	__ni_leaseinfo_print_string_array(out, prefix, "NTPSERVERS",
					&lease->ntp_servers, " ");

	/* Only applicable for ipv4. */
	if (lease->family == AF_INET)
		__ni_leaseinfo_print_netbios(out, prefix, lease);

#if 0
	/* Service Locator Servers */
	for (i = 0; i < lease->slp_servers.count; ++i) {
		__ni_leaseinfo_print_string(out, prefix, "SLPSERVERS",
					lease->slp_servers.data[i],
					NULL, i);
	}

	/* Service Locator Scopes */
	for (i = 0; i < lease->slp_scopes.count; ++i) {
		__ni_leaseinfo_print_string(out, prefix, "SLPSCOPES",
					lease->slp_scopes.data[i],
					NULL, i);
	}

	/* SIP Servers */
	for (i = 0; i < lease->sip_servers.count; ++i) {
		__ni_leaseinfo_print_string(out, prefix, "SIPSERVERS",
					lease->sip_servers.data[i],
					NULL, i);
	}

	/* LPR Servers */
	for (i = 0; i < lease->lpr_servers.count; ++i) {
		__ni_leaseinfo_print_string(out, prefix, "LPRSERVERS",
					lease->lpr_servers.data[i],
					NULL, i);
	}
#endif

	ni_string_free(&key);
}

char *
ni_leaseinfo_path(const char *ifname, const ni_addrconf_mode_t type,
		const unsigned int family)
{
	char *filename = NULL;

	ni_string_printf(&filename, "%s/leaseinfo.%s.%s.%s",
			ni_config_statedir(), ifname,
			ni_addrconf_type_to_name(type),
			ni_addrfamily_type_to_name(family));

	return filename;
}

void
ni_leaseinfo_dump(FILE *out, const ni_addrconf_lease_t *lease,
		const char *ifname, const char *prefix)
{

	char *filename = NULL;

	if (!lease) {
		ni_error("Cannot dump info from NULL lease.");
		return;
	}

	if (lease->state == NI_ADDRCONF_STATE_RELEASED) {
		ni_debug_dhcp("Lease to dump has been released.");
		ni_leaseinfo_remove(ifname, lease->type, lease->family);
	}

	/* If we're supplied a FILE pointer, use it. Otherwise, open a file based
	 * based on lease info (ifname, type, family).
	 */
	if (!out) {
		if ((filename = ni_leaseinfo_path(ifname, lease->type, lease->family)) == NULL) {
			ni_error("Unable to set leaseinfo file path for creation.");
			return;
		}

		if ((out = fopen(filename, "w")) == NULL) {
			ni_error("Cannot open %s", filename);
			return;
		}
	}

	__ni_leaseinfo_dump(out, lease, ifname, prefix);

	switch(lease->type) {
	case NI_ADDRCONF_DHCP:
		switch (lease->family) {
		case AF_INET:
			__ni_leaseinfo_dhcp4_dump(out, lease, prefix);
			break;
		case AF_INET6:
			__ni_leaseinfo_dhcp6_dump(out, lease, prefix);
			break;
		default:
			ni_error("Unsupported lease family (%u).", lease->family);
			break;
		}
		break;
	default:
		ni_error("Unsupported lease type (%u).", lease->type);
		break;
	}

	fclose(out);
	ni_string_free(&filename);
}

void
ni_leaseinfo_remove(const char *ifname, const ni_addrconf_mode_t type,
		const unsigned int family)
{
	char *filename = NULL;

	if ((filename = ni_leaseinfo_path(ifname, type, family)) == NULL) {
		ni_error("Unable to get leaseinfo file path for removal.");
		return;
	}

	ni_debug_dhcp("Removing leaseinfo file: %s", filename);
	unlink(filename);
	ni_string_free(&filename);
}
