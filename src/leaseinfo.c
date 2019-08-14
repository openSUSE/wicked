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
#include <ctype.h>
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
#include <wicked/socket.h>	/* ni_time functions */

#include "appconfig.h"
#include "util_priv.h"
#include "dhcp6/options.h"
#include "dhcp.h"

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
				const char *, const char *);
static void		__ni_leaseinfo_dhcp6_dump(FILE *,
				const ni_addrconf_lease_t *,
				const char *, const char *);
static void		__ni_leaseinfo_print_addrs(FILE *, const char *,
					ni_address_t *, unsigned int);
static void		__ni_leaseinfo_print_routes(FILE *, const char *,
					ni_route_table_t *, unsigned int);
static void		__ni_leaseinfo_print_nis(FILE *, const char *,
					ni_nis_info_t *);
static void		__ni_leaseinfo_print_resolver(FILE *, const char *,
					ni_resolver_info_t *, const char *);
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

	if (ni_string_empty(val) && !default_val)
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
	ni_sockaddr_t nm;
	ni_sockaddr_t net;
	unsigned int i;
	char *buf = NULL;

	for (i = 0, ap = addrs; ap; ap = ap->next) {
		if (family != AF_UNSPEC && family != ap->local_addr.ss_family)
			continue;

		switch (ap->local_addr.ss_family) {
		case AF_INET:
			ni_string_printf(&buf, "%s/%u",
						ni_sockaddr_print(&ap->local_addr),
						ap->prefixlen);
			__ni_leaseinfo_print_string(out, prefix, "IPADDR",
						buf, NULL, i);
			ni_string_free(&buf);

			ni_sockaddr_build_netmask(ap->family,ap->prefixlen, &nm);
			__ni_leaseinfo_print_string(out, prefix, "NETMASK",
						ni_sockaddr_print(&nm), NULL, i);

			ni_sockaddr_set_ipv4(&net, nm.sin.sin_addr, 0);
			net.sin.sin_addr.s_addr &= ap->local_addr.sin.sin_addr.s_addr;
			__ni_leaseinfo_print_string(out, prefix, "NETWORK",
						ni_sockaddr_print(&net), NULL, i);

			if (!ni_sockaddr_is_unspecified(&ap->bcast_addr)) {
				__ni_leaseinfo_print_string(out, prefix, "BROADCAST",
						ni_sockaddr_print(&ap->bcast_addr), NULL, i);
			}

			ni_string_printf(&buf, "%u", ap->prefixlen);
			__ni_leaseinfo_print_string(out, prefix, "PREFIXLEN",
						buf, NULL, i);
			ni_string_free(&buf);

			++i;
			break;

		case AF_INET6:
			ni_string_printf(&buf, "%s/%u",
						ni_sockaddr_print(&ap->local_addr),
						ap->prefixlen);
			__ni_leaseinfo_print_string(out, prefix, "IPADDR",
						buf, NULL, i);
			ni_string_free(&buf);

			ni_string_printf(&buf, "%u", ap->prefixlen);
			__ni_leaseinfo_print_string(out, prefix, "PREFIXLEN",
						buf, NULL, i);
			ni_string_free(&buf);

			++i;
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

	memset(&nogateway, 0, sizeof(nogateway));
	for (nh = &rp->nh; nh; nh = nh->next) {
		if (ni_sockaddr_is_specified(&rp->destination)) {
			/* (network) ROUTES + = 'destination,prefixlen,gateway' */
			ni_stringbuf_puts(&buf, ni_sockaddr_print(&rp->destination));
			ni_stringbuf_putc(&buf, ',');
			ni_stringbuf_printf(&buf, "%u", rp->prefixlen);
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
	char *name = NULL;

	for (rtp = routes; rtp; rtp = rtp->next) {
		if (!ni_string_eq(ni_route_table_type_to_name(rtp->tid, &name), "main"))
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
	ni_string_free(&name);
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

static const char *
__ni_leaseinfo_qualify_addr(char **qualified, const char *address, const char *ifname)
{
	ni_sockaddr_t addr;

	if (ni_sockaddr_parse(&addr, address, AF_UNSPEC))
		return NULL;

	if (ni_sockaddr_is_ipv6_linklocal(&addr)) {
		ni_string_printf(qualified, "%s%%%s", address, ifname);
	} else {
		ni_string_dup(qualified, address);
	}
	return *qualified;
}

static void
__ni_leaseinfo_qualify_addrs(ni_string_array_t *out,  const ni_string_array_t *in, const char *ifname)
{
	char *qualified = NULL;
	unsigned int i;

	for (i = 0; i < in->count; ++i) {
		const char *address = in->data[i];
		if (__ni_leaseinfo_qualify_addr(&qualified, address, ifname))
			ni_string_array_append(out, qualified);
		ni_string_free(&qualified);
	}
}

static void
__ni_leaseinfo_print_resolver(FILE *out, const char *prefix,
			ni_resolver_info_t *resolver, const char *ifname)
{
	ni_string_array_t dns_servers = NI_STRING_ARRAY_INIT;

	if (!resolver)
		return;

	__ni_leaseinfo_print_string(out, prefix, "DNSDOMAIN",
				resolver->default_domain, NULL, 0);

	__ni_leaseinfo_qualify_addrs(&dns_servers, &resolver->dns_servers, ifname);
	__ni_leaseinfo_print_string_array(out, prefix, "DNSSERVERS",
					&dns_servers, " ");
	ni_string_array_destroy(&dns_servers);

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

static ni_bool_t
__ni_leaseinfo_convert_dhcp_name(ni_stringbuf_t *result, const char *prefix, const char *name)
{
	size_t i, old, len = ni_string_len(name);

	if (!result || !len)
		return FALSE;

	if (!ni_string_empty(prefix))
		ni_stringbuf_puts(result, prefix);

	old = result->len;
	for (i = 0; i < len; ++i) {
		switch (name[i]) {
		case '-':
		case '_':
			break;
		case '.':
		case '/':
			ni_stringbuf_putc(result, '_');
			break;
		default:
			ni_stringbuf_putc(result, toupper(name[i]));
			break;
		}
	}
	return !ni_string_empty(result->string + old);
}

static void
__ni_leaseinfo_print_dhcp_opts(FILE *out, const char *prefix,
				const ni_dhcp_option_decl_t *custom,
				const ni_dhcp_option_t *options)
{
	ni_stringbuf_t name = NI_STRINGBUF_INIT_DYNAMIC;
	const ni_dhcp_option_decl_t *decl;
	const ni_dhcp_option_t *opt;
	ni_var_array_t *vars;
	char *hstr = NULL;

	for (opt = options; opt; opt = opt->next) {
		if (!opt->code)
			continue;

		ni_stringbuf_clear(&name);
		decl = ni_dhcp_option_decl_list_find_by_code(custom, opt->code);
		if (decl && (vars = ni_dhcp_option_to_vars(opt, decl))) {
			unsigned int i;
			ni_var_t *var;

			for (i = 0, var = vars->data; i < vars->count; ++i, ++var) {
				if (__ni_leaseinfo_convert_dhcp_name(&name, "OPTION_", var->name))
					__ni_leaseinfo_print_string(out, prefix, name.string,
							var->value, NULL, 0);
				ni_stringbuf_destroy(&name);
			}
			ni_var_array_free(vars);
			continue;
		}

		if (ni_stringbuf_printf(&name, "UNKNOWN_%u", opt->code) < 0 ||
				ni_string_empty(name.string))
			continue;

		hstr = ni_sprint_hex(opt->data, opt->len);
		__ni_leaseinfo_print_string(out, prefix, name.string, hstr, "", 0);
		ni_string_free(&hstr);
	}
	ni_stringbuf_destroy(&name);
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
			const char *ifname, const char *prefix)
{
	const ni_config_dhcp4_t *config;
	char *key = NULL;
	ni_sockaddr_t sa;


	/*
	 * Hmm...
	 * Address and netmask specified as part of generic dump, so not
	 * duplicating here.
	 */
	if (lease->dhcp4.client_id.len) {
		__ni_leaseinfo_print_string(out, prefix, "CLIENTID",
				ni_print_hex(lease->dhcp4.client_id.data,
				lease->dhcp4.client_id.len), "", 0);
	}
	ni_sockaddr_set_ipv4(&sa, lease->dhcp4.server_id, 0);
	if (ni_sockaddr_is_specified(&sa)) {
		__ni_leaseinfo_print_string(out, prefix, "SERVERID",
					ni_sockaddr_print(&sa), NULL, 0);
	}
	ni_sockaddr_set_ipv4(&sa, lease->dhcp4.relay_addr, 0);
	if (ni_sockaddr_is_specified(&sa)) {
		__ni_leaseinfo_print_string(out, prefix, "RELAYADDR",
					ni_sockaddr_print(&sa), NULL, 0);
	}
	if (lease->dhcp4.sender_hwa) {
		__ni_leaseinfo_print_string(out, prefix, "SENDERHWADDR",
					lease->dhcp4.sender_hwa, NULL, 0);
	}

	{
		struct timeval acquired;

		ni_time_timer_to_real(&lease->acquired, &acquired);
		fprintf(out, "%s='%"PRId64"'\n", __ni_keyword_format
				(&key, prefix, "ACQUIRED", 0),
				(int64_t) acquired.tv_sec);
	}
	if (lease->dhcp4.lease_time)  {
		fprintf(out, "%s='%"PRIu32"'\n", __ni_keyword_format
				(&key, prefix, "LEASETIME", 0),
				lease->dhcp4.lease_time);
	}
	if (lease->dhcp4.renewal_time) {
		fprintf(out, "%s='%"PRIu32"'\n", __ni_keyword_format
				(&key, prefix, "RENEWALTIME", 0),
				lease->dhcp4.renewal_time);
	}
	if (lease->dhcp4.rebind_time) {
		fprintf(out, "%s='%"PRIu32"'\n", __ni_keyword_format
				(&key, prefix, "REBINDTIME", 0),
				lease->dhcp4.rebind_time);
	}

	ni_sockaddr_set_ipv4(&sa, lease->dhcp4.boot_saddr, 0);
	if (ni_sockaddr_is_specified(&sa)) {
		__ni_leaseinfo_print_string(out, prefix, "BOOTSERVERADDR",
				ni_sockaddr_print(&sa), NULL, 0);
	}
	if (lease->dhcp4.boot_sname) {
		__ni_leaseinfo_print_string(out, prefix, "BOOTSERVERNAME",
					lease->dhcp4.boot_sname,
					NULL, 0);
	}
	__ni_leaseinfo_print_string(out, prefix, "BOOTFILE",
				lease->dhcp4.boot_file,
				NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "ROOTPATH",
				lease->dhcp4.root_path,
				NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "MESSAGE",
				lease->dhcp4.message,
				NULL, 0);

	if (lease->dhcp4.mtu) {
		fprintf(out, "%s='%"PRIu16"'\n", __ni_keyword_format
			(&key, prefix, "MTU", 0),
			lease->dhcp4.mtu);
	}

	config = ni_config_dhcp4_find_device(ifname);
	__ni_leaseinfo_print_dhcp_opts(out, prefix, config ?
			config->custom_options : NULL,
			lease->dhcp4.options);

	ni_string_free(&key);
}

static void
__ni_leaseinfo_dhcp6_dump(FILE *out, const ni_addrconf_lease_t *lease,
			const char *ifname, const char *prefix)
{
	const ni_config_dhcp6_t *config;
	char *key = NULL;
	ni_sockaddr_t sa;

	{
		struct timeval acquired;

		ni_time_timer_to_real(&lease->acquired, &acquired);
		fprintf(out, "%s='%"PRIu64"'\n", __ni_keyword_format
				(&key, prefix, "ACQUIRED", 0),
				(uint64_t) acquired.tv_sec);
	}

	if (lease->dhcp6.client_id.len) {
		__ni_leaseinfo_print_string(out, prefix, "CLIENTID",
				ni_print_hex(lease->dhcp6.client_id.data,
					lease->dhcp6.client_id.len), "", 0);
	}

	if (lease->dhcp6.server_id.len) {
		__ni_leaseinfo_print_string(out, prefix, "SERVERID",
				ni_print_hex(lease->dhcp6.server_id.data,
					lease->dhcp6.server_id.len), "", 0);
	}
	ni_sockaddr_set_ipv6(&sa, lease->dhcp6.server_addr, 0);
	if (ni_sockaddr_is_specified(&sa)) {
		__ni_leaseinfo_print_string(out, prefix, "SERVERADDR",
				ni_sockaddr_print(&sa), NULL, 0);
	}
	if (lease->dhcp6.server_pref) {
		fprintf(out, "%s='%"PRIu8"'\n", __ni_keyword_format
			(&key, prefix, "SERVERPREF", 0),
			lease->dhcp6.server_pref);
	}
	if (lease->dhcp6.rapid_commit) {
		fprintf(out, "%s='%s'\n", __ni_keyword_format
			(&key, prefix, "RAPIDCOMMIT", 0), "TRUE");
	}
	if (lease->dhcp6.boot_url) {
		__ni_leaseinfo_print_string(out, prefix, "BOOTFILEURL",
					lease->dhcp6.boot_url, NULL, 0);
	}
	if (lease->dhcp6.boot_params.count) {
		unsigned int i;

		for (i = 0; i < lease->dhcp6.boot_params.count; ++i) {
			const char *param = lease->dhcp6.boot_params.data[i];
			if (!param)
				continue;
			__ni_leaseinfo_print_string(out, prefix,
					"BOOTFILEPARAM", param, NULL, i);
		}
	}

	config = ni_config_dhcp6_find_device(ifname);
	__ni_leaseinfo_print_dhcp_opts(out, prefix, config ?
			config->custom_options : NULL,
			lease->dhcp6.options);

	ni_string_free(&key);
}

static void
__ni_leaseinfo_dump(FILE *out, const ni_addrconf_lease_t *lease,
		const char *ifname, const char *prefix)
{
	unsigned int i;
	char *key = NULL;

	__ni_leaseinfo_print_string(out, prefix, "INTERFACE", ifname, "", 0);

	/* wicked specific vars */

	__ni_leaseinfo_print_string(out, prefix, "TYPE",
				ni_addrconf_type_to_name(lease->type),
				NULL, 0);
	__ni_leaseinfo_print_string(out, prefix, "FAMILY",
				ni_addrfamily_type_to_name(lease->family),
				NULL, 0);
	__ni_leaseinfo_print_string(out, prefix, "UUID",
				ni_uuid_print(&lease->uuid), NULL, 0);

	/* hostname, addrs, routes */
	__ni_leaseinfo_print_string(out, prefix, "HOSTNAME", lease->hostname,
				NULL, 0);

	__ni_leaseinfo_print_addrs(out, prefix, lease->addrs, lease->family);

	__ni_leaseinfo_print_routes(out, prefix, lease->routes, lease->family);

	/* Only applicable for ipv4. */
	if (lease->family == AF_INET)
		__ni_leaseinfo_print_nis(out, prefix, lease->nis);

	/* DNS Servers and Domains */
	__ni_leaseinfo_print_resolver(out, prefix, lease->resolver, ifname);

	/* NTP Servers */
	__ni_leaseinfo_print_string_array(out, prefix, "NTPSERVERS",
					&lease->ntp_servers, " ");

	/* NDS Servers */
	__ni_leaseinfo_print_string_array(out, prefix, "NDSSERVERS",
					&lease->nds_servers, " ");

	/* NDS Context */
	__ni_leaseinfo_print_string_array(out, prefix, "NDSCONTEXT",
					&lease->nds_context, " ");

	/* NDS Tree */
	__ni_leaseinfo_print_string(out, prefix, "NDSTREE", lease->nds_tree,
				NULL, 0);

	/* Only applicable for ipv4. */
	if (lease->family == AF_INET)
		__ni_leaseinfo_print_netbios(out, prefix, lease);

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

	/* Log Servers */
	for (i = 0; i < lease->log_servers.count; ++i) {
		__ni_leaseinfo_print_string(out, prefix, "LOGSERVER",
					lease->log_servers.data[i],
					NULL, i);
	}

	__ni_leaseinfo_print_string(out, prefix, "POSIXTZSTRING",
				lease->posix_tz_string, NULL, 0);

	__ni_leaseinfo_print_string(out, prefix, "POSIXTZDBNAME",
				lease->posix_tz_dbname, NULL, 0);

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
	ni_bool_t close_out_fp = TRUE; /* Used to prevent unwanted closure of
					* things like stdout.
					*/

	if (!lease) {
		ni_error("Cannot dump info from NULL lease.");
		return;
	}

	if (lease->state == NI_ADDRCONF_STATE_RELEASED) {
		ni_debug_dhcp("Lease to dump has been released.");
		ni_leaseinfo_remove(ifname, lease->type, lease->family);
	}

	/* If we're supplied a FILE pointer, use it. Otherwise, open a file based
	 * on lease info (ifname, type, family).
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
	} else {
		/* A fp passed to us, don't close it! */
		close_out_fp = FALSE;
	}

	__ni_leaseinfo_dump(out, lease, ifname, prefix);

	switch (lease->type) {
	case NI_ADDRCONF_DHCP:
		switch (lease->family) {
		case AF_INET:
			__ni_leaseinfo_dhcp4_dump(out, lease, ifname, prefix);
			break;
		case AF_INET6:
			__ni_leaseinfo_dhcp6_dump(out, lease, ifname, prefix);
			break;
		default:
			ni_error("Unsupported lease family (%u).", lease->family);
			break;
		}
		break;

	default:
		/* Don't complain; if there's a lease type we don't know,
		 * then it's probably fine if we just save the standard
		 * information. */
		break;
	}

	if (close_out_fp)
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
