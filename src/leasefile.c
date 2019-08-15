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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/address.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include <wicked/route.h>
#include <wicked/logging.h>
#include <wicked/xml.h>

#include "appconfig.h"
#include "leasefile.h"
#include "dhcp.h"
#include "dhcp4/lease.h"
#include "dhcp6/lease.h"
#include "netinfo_priv.h"

/*
 * utility returning a family + type specific node / name
 */
static const char *
__ni_addrconf_lease_xml_new_type_name(unsigned int family, unsigned int type)
{
	switch (family) {
	case AF_INET:
		switch (type) {
		case NI_ADDRCONF_DHCP:
			return NI_ADDRCONF_LEASE_XML_DHCP4_NODE;
		case NI_ADDRCONF_STATIC:
			return NI_ADDRCONF_LEASE_XML_STATIC4_NODE;
		case NI_ADDRCONF_AUTOCONF:
			return NI_ADDRCONF_LEASE_XML_AUTO4_NODE;
		case NI_ADDRCONF_INTRINSIC:
			return NI_ADDRCONF_LEASE_XML_INTRINSIC4_NODE;
		default: ;
		}
		break;
	case AF_INET6:
		switch (type) {
		case NI_ADDRCONF_DHCP:
			return NI_ADDRCONF_LEASE_XML_DHCP6_NODE;
		case NI_ADDRCONF_STATIC:
			return NI_ADDRCONF_LEASE_XML_STATIC6_NODE;
		case NI_ADDRCONF_AUTOCONF:
			return NI_ADDRCONF_LEASE_XML_AUTO6_NODE;
		case NI_ADDRCONF_INTRINSIC:
			return NI_ADDRCONF_LEASE_XML_INTRINSIC6_NODE;
		default: ;
		}
		break;
	default: ;
	}
	return NULL;
}

const char *
ni_addrconf_lease_xml_new_type_name(const ni_addrconf_lease_t *lease)
{
	if (!lease)
		return NULL;
	return __ni_addrconf_lease_xml_new_type_name(lease->family, lease->type);
}

xml_node_t *
ni_addrconf_lease_xml_new_type_node(const ni_addrconf_lease_t *lease,
					xml_node_t *node)
{
	const char *name = NULL;

	name = ni_addrconf_lease_xml_new_type_name(lease);
	return name ? xml_node_new(name, node) : NULL;
}

const xml_node_t *
ni_addrconf_lease_xml_get_type_node(const ni_addrconf_lease_t *lease,
					const xml_node_t *node)
{
	const char *name = NULL;

	name = ni_addrconf_lease_xml_new_type_name(lease);
	return name ? xml_node_get_child(node, name) : NULL;
}

/*
 * utils to dump lease or a part of to xml
 */
static int
__ni_string_array_to_xml(const ni_string_array_t *array, const char *name, xml_node_t *node)
{
	unsigned int i, count = 0;

	for (i = 0; i < array->count; ++i) {
		const char *item = array->data[i];
		if (ni_string_empty(item))
			continue;
		count++;
		xml_node_new_element(name, node, item);
	}
	return count ? 0 : 1;
}

int
ni_addrconf_lease_addrs_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	unsigned int count = 0;
	xml_node_t *anode;
	ni_address_t *ap;

	(void)ifname;
	for (ap = lease->addrs; ap; ap = ap->next) {
		if (lease->family != ap->local_addr.ss_family ||
			!ni_sockaddr_is_specified(&ap->local_addr))
			continue;

		count++;
		anode = xml_node_new("address", node);
		xml_node_new_element("local", anode, ni_sockaddr_prefix_print
				(&ap->local_addr, ap->prefixlen));

		if (ap->peer_addr.ss_family == ap->family) {
			xml_node_new_element("peer", anode, ni_sockaddr_print
					(&ap->peer_addr));
		}
		if (ap->anycast_addr.ss_family == ap->family) {
			xml_node_new_element("anycast", anode, ni_sockaddr_print
					(&ap->anycast_addr));
		}
		if (ap->bcast_addr.ss_family == ap->family) {
			xml_node_new_element("broadcast", anode, ni_sockaddr_print
					(&ap->bcast_addr));
		}
		if (ap->family == AF_INET && ap->label)
			xml_node_new_element("label", anode, ap->label);

		if (ap->cache_info.preferred_lft != NI_LIFETIME_INFINITE) {
			xml_node_t *cnode = xml_node_new("cache-info", anode);
			xml_node_new_element_uint("preferred-lifetime", cnode,
					ap->cache_info.preferred_lft);
			xml_node_new_element_uint("valid-lifetime", cnode,
					ap->cache_info.valid_lft);
		}
	}
	return count ? 0 : 1;
}

int
ni_addrconf_lease_routes_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	ni_route_table_t *tab;
	ni_route_nexthop_t *nh;
	xml_node_t *route, *hop;
	ni_route_t *rp;
	unsigned int count = 0;
	unsigned int i;

	(void)ifname;
	/* A very limitted view */
	for (tab = lease->routes; tab; tab = tab->next) {
		if (tab->tid != 254) /* RT_TABLE_MAIN for now */
			continue;

		for (i = 0; i < tab->routes.count; ++i) {
			if (!(rp = tab->routes.data[i]))
				continue;

			route = xml_node_new("route", NULL);
			if (ni_sockaddr_is_specified(&rp->destination)) {
				xml_node_new_element("destination", route,
					ni_sockaddr_prefix_print(&rp->destination,
								rp->prefixlen));
			}
			for (nh = &rp->nh; nh; nh = nh->next) {
				if (!ni_sockaddr_is_specified(&nh->gateway))
					continue;

				hop = xml_node_new("nexthop", route);
				xml_node_new_element("gateway", hop,
					ni_sockaddr_print(&nh->gateway));
			}
			if (route->children) {
				xml_node_add_child(node, route);
				count++;
			} else {
				xml_node_free(route);
			}
		}
	}
	return count ? 0 : 1;
}

int
ni_addrconf_lease_dns_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	ni_resolver_info_t *dns;
	unsigned int count = 0;

	(void)ifname;
	dns = lease->resolver;
	if (!dns || (ni_string_empty(dns->default_domain) &&
			dns->dns_servers.count == 0 &&
			dns->dns_search.count == 0))
		return 1;

	if (dns->default_domain) {
		xml_node_new_element("domain", node, dns->default_domain);
		count++;
	}
	if (__ni_string_array_to_xml(&dns->dns_servers, "server", node) == 0)
		count++;
	if (__ni_string_array_to_xml(&dns->dns_search, "search", node) == 0)
		count++;

	return count ? 0 : 1;
}

int
ni_addrconf_lease_nis_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	unsigned int count = 0;
	unsigned int i, j;
	ni_nis_info_t *nis;
	xml_node_t *data;

	(void)ifname;

	nis = lease->nis;
	if (!nis)
		return 1;

	/* Default domain */
	data = xml_node_new("default", NULL);
	if (!ni_string_empty(nis->domainname)) {
		count++;
		xml_node_new_element("domain", data, nis->domainname);
	}
	if (nis->default_binding == NI_NISCONF_BROADCAST ||
	    nis->default_binding == NI_NISCONF_STATIC) {
		/* no SLP here */
		count++;
		xml_node_new_element("binding", data,
			ni_nis_binding_type_to_name(nis->default_binding));
	}
	/* Only in when static binding? */
	for (i = 0; i < nis->default_servers.count; ++i) {
		const char *server = nis->default_servers.data[i];
		if (ni_string_empty(server))
			continue;
		count++;
		xml_node_new_element("server", data, server);
	}
	if (count) {
		xml_node_add_child(node, data);
	}

	/* Further domains */
	for (i = 0; i < nis->domains.count; ++i) {
		ni_nis_domain_t *dom = nis->domains.data[i];
		if (!dom || ni_string_empty(dom->domainname))
			continue;

		count++;
		data = xml_node_new("domain", node);
		xml_node_new_element("domain", data, dom->domainname);
		if (ni_nis_binding_type_to_name(nis->default_binding)) {
			xml_node_new_element("binding", data,
				ni_nis_binding_type_to_name(nis->default_binding));
		}
		for (j = 0; j < dom->servers.count; ++j) {
			const char *server = dom->servers.data[j];
			if (ni_string_empty(server))
				continue;
			xml_node_new_element("server", data, server);
		}
	}

	return count ? 0 : 1;
}

int
ni_addrconf_lease_ntp_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	(void)ifname;
	return __ni_string_array_to_xml(&lease->ntp_servers, "server", node);
}

int
ni_addrconf_lease_nds_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	unsigned int count = 0;

	(void)ifname;
	if (__ni_string_array_to_xml(&lease->nds_servers, "server", node) == 0)
		count++;
	if (__ni_string_array_to_xml(&lease->nds_context, "context", node) == 0)
		count++;
	if (!ni_string_empty(lease->nds_tree)) {
		count++;
		xml_node_new_element("tree", node, lease->nds_tree);
	}
	return count ? 0 : 1;
}

int
ni_addrconf_lease_smb_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	unsigned int count = 0;
	const char *nbt;

	(void)ifname;
	if (__ni_string_array_to_xml(&lease->netbios_name_servers, "name-server", node) == 0)
		count++;
	if (__ni_string_array_to_xml(&lease->netbios_dd_servers, "dd-server", node) == 0)
		count++;
	if (!ni_string_empty(lease->netbios_scope)) {
		count++;
		xml_node_new_element("scope", node, lease->netbios_scope);
	}
	if ((nbt = ni_netbios_node_type_to_name(lease->netbios_type))) {
		count++;
		xml_node_new_element("type", node, nbt);
	}
	return count ? 0 : 1;
}

int
ni_addrconf_lease_sip_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	(void)ifname;
	return __ni_string_array_to_xml(&lease->sip_servers, "server", node);
}

int
ni_addrconf_lease_slp_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	unsigned int count = 0;

	(void)ifname;
	if (__ni_string_array_to_xml(&lease->slp_scopes, "scopes", node) == 0)
		count++;
	if (__ni_string_array_to_xml(&lease->slp_servers, "server", node) == 0)
		count++;
	return count ? 0 : 1;
}

int
ni_addrconf_lease_lpr_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	(void)ifname;
	return __ni_string_array_to_xml(&lease->lpr_servers, "server", node);
}

int
ni_addrconf_lease_log_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	(void)ifname;
	return __ni_string_array_to_xml(&lease->log_servers, "server", node);
}

int
ni_addrconf_lease_ptz_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	unsigned int ret = 1;

	(void)ifname;
	if (!ni_string_empty(lease->posix_tz_string)) {
		xml_node_new_element("posix-string", node, lease->posix_tz_string);
		ret = 0;
	}
	if (!ni_string_empty(lease->posix_tz_dbname)) {
		xml_node_new_element("posix-dbname", node, lease->posix_tz_dbname);
		ret = 0;
	}
	return ret;
}

static xml_node_t *
ni_addrconf_lease_opts_data_unknown_to_xml(const ni_dhcp_option_t *opt)
{
	xml_node_t *node = NULL;
	char *name = NULL;
	char *hstr = NULL;

	if (!ni_string_printf(&name, "unknown-%u", opt->code))
		goto failure;

	if (!(node = xml_node_new(name, NULL)))
		goto failure;

	xml_node_new_element_uint("code", node, opt->code);
	if (opt->len && opt->data) {
		if (!(hstr = ni_sprint_hex(opt->data, opt->len)))
			goto failure;
		xml_node_new_element("data", node, hstr);
	}

	return node;

failure:
	ni_string_free(&hstr);
	ni_string_free(&name);
	xml_node_free(node);
	return NULL;
}

int
ni_addrconf_lease_opts_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	const ni_dhcp_option_t *options, *opt;
	const ni_dhcp_option_decl_t *declared;

	if (lease->family == AF_INET  && lease->type == NI_ADDRCONF_DHCP) {
		const ni_config_dhcp4_t *config = ni_config_dhcp4_find_device(ifname);
		declared = config ? config->custom_options : NULL;
		options = lease->dhcp4.options;
	} else
	if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_DHCP) {
		const ni_config_dhcp6_t *config = ni_config_dhcp6_find_device(ifname);
		declared = config ? config->custom_options : NULL;
		options = lease->dhcp6.options;
	} else
		return 1;

	for (opt = options; opt; opt = opt->next) {
		const ni_dhcp_option_decl_t *decl;
		xml_node_t *ret;

		if (!opt->code)
			continue;

		decl = ni_dhcp_option_decl_list_find_by_code(declared, opt->code);
		if (decl) {
			ret = ni_dhcp_option_to_xml(opt, decl);
		} else {
			ret = ni_addrconf_lease_opts_data_unknown_to_xml(opt);
		}
		if (ret)
			xml_node_add_child(node, ret);
	}

	if (node->children)
		return 0;
	else
		return 1;
}

static int
__ni_addrconf_lease_info_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	struct timeval acquired;
	char buf[32] = { '\0' };

	xml_node_new_element("family", node, ni_addrfamily_type_to_name(lease->family));
	xml_node_new_element("type", node, ni_addrconf_type_to_name(lease->type));
	if (!ni_string_empty(lease->owner))
		xml_node_new_element("owner", node, lease->owner);
	if (!ni_uuid_is_null(&lease->uuid))
		xml_node_new_element("uuid", node, ni_uuid_print(&lease->uuid));
	xml_node_new_element("state", node, ni_addrconf_state_to_name(lease->state));

	ni_time_timer_to_real(&lease->acquired, &acquired);
	snprintf(buf, sizeof(buf), "%"PRId64, (int64_t)acquired.tv_sec);
	xml_node_new_element("acquired", node, buf);

	snprintf(buf, sizeof(buf), "0x%08x", lease->update);
	xml_node_new_element("update", node, buf);
	return 0;
}

static int
ni_addrconf_lease_static_data_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	static const struct group_map {
		const char *name;
		int       (*func)(const ni_addrconf_lease_t *, xml_node_t *, const char *);
	} *g, group_map[] = {
		{ NI_ADDRCONF_LEASE_XML_ADDRS_DATA_NODE, ni_addrconf_lease_addrs_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_ROUTES_DATA_NODE, ni_addrconf_lease_routes_data_to_xml },
		{ NI_ADDRCONF_LEASE_XML_DNS_DATA_NODE, ni_addrconf_lease_dns_data_to_xml },
		{ NULL, NULL }
	};
	xml_node_t *data;

	if (!ni_string_empty(lease->hostname))
		xml_node_new_element("hostname", node, lease->hostname);

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

static int
__ni_addrconf_lease_static_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	xml_node_t *data;
	int ret = 1;

	if (!lease || !node)
		return -1;

	if (!(data = ni_addrconf_lease_xml_new_type_node(lease, NULL)))
		return -1;

	if ((ret = ni_addrconf_lease_static_data_to_xml(lease, data, ifname)) == 0)
		xml_node_add_child(node, data);
	else
		xml_node_free(data);
	return ret;
}

static int
__ni_addrconf_lease_dhcp_to_xml(const ni_addrconf_lease_t *lease, xml_node_t *node, const char *ifname)
{
	switch (lease->family) {
	case AF_INET:
		return ni_dhcp4_lease_to_xml(lease, node, ifname);
	case AF_INET6:
		return ni_dhcp6_lease_to_xml(lease, node, ifname);
	default:
		return -1;
	}
}

int
ni_addrconf_lease_to_xml(const ni_addrconf_lease_t *lease, xml_node_t **result, const char *ifname)
{
	xml_node_t *node;
	int ret = -1;

	if (!lease || !result) {
		errno = EINVAL;
		return -1;
	}

	*result = NULL; /* initialize... */
	node = xml_node_new(NI_ADDRCONF_LEASE_XML_NODE, NULL);
	switch (lease->type) {
	case NI_ADDRCONF_STATIC:
	case NI_ADDRCONF_AUTOCONF:
	case NI_ADDRCONF_INTRINSIC:
		if ((ret = __ni_addrconf_lease_info_to_xml(lease, node)) != 0)
			break;

		if ((ret = __ni_addrconf_lease_static_to_xml(lease, node, ifname)) != 0)
			break;
		break;

	case NI_ADDRCONF_DHCP:
		if ((ret = __ni_addrconf_lease_info_to_xml(lease, node)) != 0)
			break;

		if ((ret = __ni_addrconf_lease_dhcp_to_xml(lease, node, ifname)) != 0)
			break;

		break;
	default: ;		/* fall through error */
	}

	if (ret == 0) {
		*result = node;
	} else {
		xml_node_free(node);
	}
	return ret;
}

/*
 * utils to parse lease or a lease data group from xml
 */
static int
__ni_addrconf_lease_info_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node)
{
	ni_bool_t update = FALSE;
	xml_node_t *child;
	int value;

	if (!lease || !node)
		return -1;

	ni_timer_get_time(&lease->acquired); /* pre-init */
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "family")) {
			if ((value = ni_addrfamily_name_to_type(child->cdata)) == -1)
				return -1;
			lease->family = value;
		} else
		if (ni_string_eq(child->name, "type")) {
			if ((value = ni_addrconf_name_to_type(child->cdata)) == -1)
				return -1;
			lease->type = value;
		} else
		if (ni_string_eq(child->name, "owner")) {
			if (!ni_string_empty(child->cdata))
				ni_string_dup(&lease->owner, child->cdata);
		} else
		if (ni_string_eq(child->name, "uuid")) {
			if (ni_uuid_parse(&lease->uuid, child->cdata) != 0)
				return -1;
		} else
		if (ni_string_eq(child->name, "state")) {
			if ((lease->state = ni_addrconf_name_to_state(child->cdata)) < 0)
				lease->state = NI_ADDRCONF_STATE_NONE;
		} else
		if (ni_string_eq(child->name, "update")) {
			if (ni_parse_uint(child->cdata, &lease->update, 16) != 0)
				return -1;
			update = TRUE;
		}
		if (ni_string_eq(child->name, "acquired")) {
			struct timeval acquired;
			int64_t sec;

			if (ni_parse_int64(child->cdata, &sec, 10))
				return -1;

			acquired.tv_sec = sec;
			acquired.tv_usec = 0;
			ni_time_real_to_timer(&acquired, &lease->acquired);
		}
	}
	if (!update)
		lease->update = ni_config_addrconf_update_mask(lease->type, lease->family);

	return 0;
}

static int
__ni_addrconf_lease_static_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "hostname") && child->cdata) {
			ni_string_dup(&lease->hostname, child->cdata);
		} else
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_ADDRS_DATA_NODE)) {
			if (ni_addrconf_lease_addrs_data_from_xml(lease, child, ifname) < 0)
				return -1;
		}
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_ROUTES_DATA_NODE)) {
			if (ni_addrconf_lease_routes_data_from_xml(lease, child, ifname) < 0)
				return -1;
		}
		if (ni_string_eq(child->name, NI_ADDRCONF_LEASE_XML_DNS_DATA_NODE)) {
			if (ni_addrconf_lease_dns_data_from_xml(lease, child, ifname) < 0)
				return -1;
		}
	}
	return 0;
}

static int
__ni_addrconf_lease_static_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	if (!node || !lease)
		return -1;

	if (!(node = ni_addrconf_lease_xml_get_type_node(lease, node)))
		return -1;

	return __ni_addrconf_lease_static_data_from_xml(lease, node, ifname);
}

static int
__ni_addrconf_lease_dhcp_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	switch (lease->family) {
	case AF_INET:
		return ni_dhcp4_lease_from_xml(lease, node, ifname);
	case AF_INET6:
		return ni_dhcp6_lease_from_xml(lease, node, ifname);
	default:
		return -1;
	}
}

static int
__ni_addrconf_lease_addr_from_xml(ni_address_t **ap_list, unsigned int family, const xml_node_t *node)
{
	const xml_node_t *child;
	ni_sockaddr_t addr;
	unsigned int plen;
	ni_address_t *ap;

	if (!(child = xml_node_get_child(node, "local")))
		return 1;

	if (ni_sockaddr_prefix_parse(child->cdata, &addr, &plen))
		return -1;

	if (family != addr.ss_family ||
	    (family == AF_INET  && plen > 32) ||
	    (family == AF_INET6 && plen > 128))
		return -1;

	if (!(ap = ni_address_new(family, plen, &addr, NULL)))
		return -1;

	if ((child = xml_node_get_child(node, "peer"))) {
		if (ni_sockaddr_parse(&ap->peer_addr, child->cdata, family) != 0)
			goto failure;
	}
	if ((child = xml_node_get_child(node, "anycast"))) {
		if (ni_sockaddr_parse(&ap->anycast_addr, child->cdata, family) != 0)
			goto failure;
	}
	if ((child = xml_node_get_child(node, "broadcast"))) {
		if (ni_sockaddr_parse(&ap->bcast_addr, child->cdata, family) != 0)
			goto failure;
	}

	if (family == AF_INET && (child = xml_node_get_child(node, "label"))) {
		ni_string_dup(&ap->label, child->cdata);
	}

	if ((child = xml_node_get_child(node, "cache-info"))) {
		xml_node_t *cnode;
		unsigned int lft;

		if ((cnode = xml_node_get_child(child, "preferred-lifetime"))) {
			if (ni_parse_uint(child->cdata, &lft, 10) != 0)
				goto failure;
			ap->cache_info.preferred_lft = lft;
		}
		if ((cnode = xml_node_get_child(child, "valid-lifetime"))) {
			if (ni_parse_uint(child->cdata, &lft, 10) != 0)
				goto failure;
			ap->cache_info.valid_lft = lft;
		}
	}

	ni_address_list_append(ap_list, ap);
	return 0;

failure:
	ni_address_free(ap);
	return -1;
}

int
ni_addrconf_lease_addrs_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	const xml_node_t *child;

	(void)ifname;
	for (child = node->children; child; child = child->next) {
		if (!ni_string_eq(child->name, "address"))
			continue;

		if (__ni_addrconf_lease_addr_from_xml(&lease->addrs, lease->family, child))
			continue;
	}
	return 0;
}

static int
__ni_addrconf_lease_route_nh_from_xml(ni_route_t *rp, const xml_node_t *node)
{
	const xml_node_t *child;
	ni_route_nexthop_t *nh = NULL;
	ni_sockaddr_t addr;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "gateway") && child->cdata) {
			if (ni_sockaddr_parse(&addr, child->cdata, AF_UNSPEC) != 0)
				return -1;
			if (rp->family != addr.ss_family)
				return -1;
			if (nh == NULL) {
				nh = ni_route_nexthop_new();
				if (!nh)
					return -1;
				ni_route_nexthop_list_append(&rp->nh.next, nh);
			}
			nh->gateway = addr;
			nh = NULL;
		}
	}
	return 0;
}

static int
__ni_addrconf_lease_route_from_xml(ni_route_t *rp, const xml_node_t *node)
{
	const xml_node_t *child;
	ni_sockaddr_t addr;
	unsigned int plen;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "destination") && child->cdata) {
			if (!ni_sockaddr_prefix_parse(child->cdata, &addr, &plen))
				return -1;
			if (rp->family != addr.ss_family)
				return -1;
			if ((rp->family == AF_INET  && plen > 32) ||
			    (rp->family == AF_INET6 && plen > 128))
				return -1;
			rp->destination = addr;
			rp->prefixlen = plen;
		} else
		if (ni_string_eq(child->name, "nexthop")) {
			if (__ni_addrconf_lease_route_nh_from_xml(rp, child) != 0)
				return -1;
		}
	}
	return 0;
}

int
ni_addrconf_lease_routes_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	const xml_node_t *child;
	ni_route_t *rp;

	(void)ifname;
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "route")) {
			rp = ni_route_new();
			if (!rp)
				return -1;
			rp->family = lease->family;
			rp->table = ni_route_guess_table(rp);
			if (__ni_addrconf_lease_route_from_xml(rp, child) != 0) {
				ni_route_free(rp);
			} else
			if (!ni_route_tables_add_route(&lease->routes, rp)) {
				ni_route_free(rp);
				return -1;
			}
		}
	}
	return 0;
}

int
ni_addrconf_lease_dns_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	ni_resolver_info_t *dns;
	const xml_node_t *child;

	(void)ifname;
	if (!(dns = ni_resolver_info_new()))
		return -1;

	if (lease->resolver) {
		ni_resolver_info_free(lease->resolver);
		lease->resolver = NULL;
	}

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "domain") &&
				!ni_string_empty(child->cdata)) {
			ni_string_dup(&dns->default_domain, child->cdata);
		} else
		if (ni_string_eq(child->name, "server") &&
				!ni_string_empty(child->cdata)) {
			ni_string_array_append(&dns->dns_servers, child->cdata);
		} else
		if (ni_string_eq(child->name, "search") &&
				!ni_string_empty(child->cdata)) {
			ni_string_array_append(&dns->dns_search, child->cdata);
		}
	}

	if (ni_string_empty(dns->default_domain) &&
			dns->dns_servers.count == 0 &&
			dns->dns_search.count == 0) {
		ni_resolver_info_free(dns);
		return 1;
	}
	lease->resolver = dns;
	return 0;
}

int
ni_addrconf_lease_dns_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	if (!(node = xml_node_get_child(node, "dns")))
		return 1;
	return ni_addrconf_lease_dns_data_from_xml(lease, node, ifname);
}

int
__ni_addrconf_lease_nis_domain_from_xml(ni_nis_info_t *nis, const xml_node_t *node)
{
	const xml_node_t *child;
	ni_nis_domain_t *dom = NULL;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "domain") && child->cdata) {
			if (!(dom = ni_nis_domain_find(nis, child->cdata)))
				dom = ni_nis_domain_new(nis, child->cdata);
			else
				return -1;
		}
	}
	if (dom) {
		for (child = node->children; child; child = child->next) {
			if (ni_string_eq(child->name, "binding") &&
				!ni_string_empty(child->cdata)) {
				int b = ni_nis_binding_name_to_type(child->cdata);
				if (b != -1) {
					dom->binding = (unsigned int)b;
				}
			}
			if (ni_string_eq(child->name, "server")) {
				if (!ni_string_empty(child->cdata)) {
					ni_string_array_append(&dom->servers,
								child->cdata);
				}
			}
		}
	}
	return dom ? 0 : 1;
}

int
ni_addrconf_lease_nis_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	const xml_node_t *child, *gc;
	ni_nis_info_t *nis;

	(void)ifname;
	if (!(nis = ni_nis_info_new()))
		return -1;

	if (lease->nis) {
		ni_nis_info_free(lease->nis);
		lease->nis = NULL;
	}

	nis->default_binding = NI_NISCONF_STATIC;
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "default")) {
			for (gc = child->children; gc; gc = gc->next) {
				if (ni_string_eq(gc->name, "domain") &&
					!ni_string_empty(gc->cdata)) {
					ni_string_dup(&nis->domainname, gc->cdata);
				} else
				if (ni_string_eq(gc->name, "binding") &&
					ni_string_eq(gc->cdata, "broadcast")) {
					nis->default_binding = NI_NISCONF_BROADCAST;
				} else
				if (ni_string_eq(gc->name, "server") &&
					!ni_string_empty(gc->cdata)) {
					ni_string_array_append(&nis->default_servers,
								gc->cdata);
				}
			}
		} else
		if (ni_string_eq(child->name, "domain")) {
			if (__ni_addrconf_lease_nis_domain_from_xml(nis, child) != 0)
				continue;
		}
	}

	if (nis->default_binding == NI_NISCONF_STATIC &&
	    ni_string_empty(nis->domainname) &&
	    nis->default_servers.count == 0 &&
	    nis->domains.count == 0) {
		ni_nis_info_free(nis);
		return 1;
	}
	lease->nis = nis;
	return 0;
}

int
ni_addrconf_lease_nds_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	const xml_node_t *child;

	(void)ifname;
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "tree") && !ni_string_empty(child->cdata)) {
			ni_string_dup(&lease->nds_tree, child->cdata);
		} else
		if (ni_string_eq(child->name, "server") && !ni_string_empty(child->cdata)) {
			ni_string_array_append(&lease->nds_servers, child->cdata);
		} else
		if (ni_string_eq(child->name, "context") && !ni_string_empty(child->cdata)) {
			ni_string_array_append(&lease->nds_context, child->cdata);
		}
	}
	return 0;
}

int
ni_addrconf_lease_smb_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	const xml_node_t *child;

	(void)ifname;
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "type") && child->cdata) {
			if (!ni_netbios_node_type_to_code(child->cdata, &lease->netbios_type))
				return -1;
		} else
		if (ni_string_eq(child->name, "scope") && !ni_string_empty(child->cdata)) {
			ni_string_dup(&lease->netbios_scope, child->cdata);
		} else
		if (ni_string_eq(child->name, "name-server") && !ni_string_empty(child->cdata)) {
			ni_string_array_append(&lease->netbios_name_servers, child->cdata);
		} else
		if (ni_string_eq(child->name, "dd-server") && !ni_string_empty(child->cdata)) {
			ni_string_array_append(&lease->netbios_dd_servers, child->cdata);
		}
	}
	return 0;
}

static int
__ni_string_array_from_xml(ni_string_array_t *array, const char *name, const xml_node_t *node)
{
	const xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, name) && !ni_string_empty(child->cdata)) {
			ni_string_array_append(array, child->cdata);
		}
	}
	return 0;
}

int
ni_addrconf_lease_ntp_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	(void)ifname;
	return __ni_string_array_from_xml(&lease->ntp_servers, "server", node);
}

int
ni_addrconf_lease_slp_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	int ret;

	(void)ifname;
	if ((ret = __ni_string_array_from_xml(&lease->slp_servers, "server", node)) != 0)
		return ret;
	if ((ret = __ni_string_array_from_xml(&lease->slp_scopes, "scope", node)) != 0)
		return ret;
	return 0;
}

int
ni_addrconf_lease_sip_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	(void)ifname;
	return __ni_string_array_from_xml(&lease->sip_servers, "server", node);
}

int
ni_addrconf_lease_log_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	(void)ifname;
	return __ni_string_array_from_xml(&lease->log_servers, "server", node);
}

int
ni_addrconf_lease_lpr_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	(void)ifname;
	return __ni_string_array_from_xml(&lease->lpr_servers, "server", node);
}

int
ni_addrconf_lease_ptz_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	const xml_node_t *child;

	(void)ifname;
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "posix-string") &&
		    !ni_string_empty(child->cdata)) {
			ni_string_dup(&lease->posix_tz_string, child->cdata);
		} else
		if (ni_string_eq(child->name, "posix-dbname") &&
		    !ni_string_empty(child->cdata)) {
			ni_string_dup(&lease->posix_tz_dbname, child->cdata);
		}
	}
	return 0;
}

static ni_dhcp_option_t *
ni_addrconf_lease_opts_data_unknown_from_xml(const xml_node_t *node)
{
	const xml_node_t *cnode, *dnode;
	ni_dhcp_option_t *opt;
	unsigned char *data;
	unsigned int code;
	size_t size;
	int len;

	if (!(cnode = xml_node_get_child(node, "code")))
		return NULL;

	if (ni_parse_uint(cnode->cdata, &code, 10) != 0 || !code)
		return NULL;

	if (!(opt = ni_dhcp_option_new(code, 0, NULL)))
		return NULL;

	if (!(dnode = xml_node_get_child(node, "data")))
		return opt;

	if (!(size = ni_string_len(dnode->cdata)))
		return opt;

	size = (size / 3) + 1;
	data = calloc(1, size);
	if (data && (len = ni_parse_hex(dnode->cdata, data, size)) > 0) {
		ni_dhcp_option_append(opt, len, data);
		free(data);
		return opt;
	} else {
		ni_dhcp_option_free(opt);
		free(data);
		return NULL;
	}
}

int
ni_addrconf_lease_opts_data_from_xml(ni_addrconf_lease_t *lease, const xml_node_t *node, const char *ifname)
{
	ni_dhcp_option_t **options = NULL, *opt;
	const ni_dhcp_option_decl_t *declared;
	const xml_node_t *child;

	if (!lease || !node)
		return 1;

	if (lease->family == AF_INET  && lease->type == NI_ADDRCONF_DHCP) {
		const ni_config_dhcp4_t *config = ni_config_dhcp4_find_device(ifname);
		declared = config ? config->custom_options : NULL;
		options = &lease->dhcp4.options;
	} else
	if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_DHCP) {
		const ni_config_dhcp6_t *config = ni_config_dhcp6_find_device(ifname);
		declared = config ? config->custom_options : NULL;
		options = &lease->dhcp6.options;
	} else
		return 1;

	for (child = node->children; child; child = child->next) {
		const ni_dhcp_option_decl_t *decl;

		opt  = NULL;
		decl = ni_dhcp_option_decl_list_find_by_name(declared, child->name);
		if (decl) {
			opt = ni_dhcp_option_from_xml(child, decl);
		} else {
			opt = ni_addrconf_lease_opts_data_unknown_from_xml(child);
		}
		if (!ni_dhcp_option_list_append(options, opt))
			ni_dhcp_option_free(opt);
	}
	return 0;
}

int
ni_addrconf_lease_from_xml(ni_addrconf_lease_t **leasep, const xml_node_t *root, const char *ifname)
{
	const xml_node_t *node = root;
	ni_addrconf_lease_t *lease;
	int ret = -1;

	if (root && !ni_string_eq(root->name, NI_ADDRCONF_LEASE_XML_NODE))
		node = xml_node_get_child(root, NI_ADDRCONF_LEASE_XML_NODE);

	if (!node || !leasep)
		return ret;

	*leasep = NULL; /* initialize... */
	if (!(lease  = ni_addrconf_lease_new(__NI_ADDRCONF_MAX, AF_UNSPEC)))
		return ret;

	if ((ret = __ni_addrconf_lease_info_from_xml(lease, node)) != 0) {
		ni_addrconf_lease_free(lease);
		return ret;
	}

	switch (lease->type) {
	case NI_ADDRCONF_STATIC:
	case NI_ADDRCONF_AUTOCONF:
	case NI_ADDRCONF_INTRINSIC:
		ret = __ni_addrconf_lease_static_from_xml(lease, node, ifname);
		break;

	case NI_ADDRCONF_DHCP:
		ret = __ni_addrconf_lease_dhcp_from_xml(lease, node, ifname);
		break;
	default: ;		/* fall through error */
	}

	if (ret) {
		ni_addrconf_lease_free(lease);
	} else {
		*leasep = lease;
	}
	return ret;
}

/*
 * lease file read and write routines
 */
static const char *		__ni_addrconf_lease_file_path(char **,
				const char *, const char *, int, int);
static void			__ni_addrconf_lease_file_remove(
				const char *, const char *, int, int);

/*
 * Write a lease to a file
 */
int
ni_addrconf_lease_file_write(const char *ifname, ni_addrconf_lease_t *lease)
{
	char tempname[PATH_MAX] = {'\0'};
	ni_bool_t fallback = FALSE;
	char *filename = NULL;
	xml_node_t *xml = NULL;
	FILE *fp = NULL;
	int ret = -1;
	int fd;

	if (lease->state == NI_ADDRCONF_STATE_RELEASED) {
		ni_addrconf_lease_file_remove(ifname, lease->type, lease->family);
		return 0;
	}

	if (!__ni_addrconf_lease_file_path(&filename, ni_config_storedir(),
					ifname, lease->type, lease->family)) {
		ni_error("Cannot construct lease file name: %m");
		return -1;
	}

	ni_debug_dhcp("Preparing xml lease data for '%s'", filename);
	if ((ret = ni_addrconf_lease_to_xml(lease, &xml, ifname)) != 0) {
		if (ret > 0) {
			ni_debug_dhcp("Skipped, %s:%s leases are disabled",
		                        ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type));
		} else {
			ni_error("Unable to represent %s:%s lease as XML",
					ni_addrfamily_type_to_name(lease->family),
					ni_addrconf_type_to_name(lease->type));
		}
		goto failed;
	}

	snprintf(tempname, sizeof(tempname), "%s.XXXXXX", filename);
	if ((fd = mkstemp(tempname)) < 0) {
		if (errno == EROFS && __ni_addrconf_lease_file_path(&filename,
						ni_config_statedir(), ifname,
						lease->type, lease->family)) {
			ni_debug_dhcp("Read-only filesystem, try fallback to %s",
					filename);
			snprintf(tempname, sizeof(tempname), "%s.XXXXXX", filename);
			fd = mkstemp(tempname);
			fallback = TRUE;
		}
		if (fd < 0) {
			ni_error("Cannot create temporary lease file '%s': %m",
					tempname);
			tempname[0] = '\0';
			ret = -1;
			goto failed;
		}
	}
	if ((fp = fdopen(fd, "we")) == NULL) {
		ret = -1;
		close(fd);
		ni_error("Cannot reopen temporary lease file '%s': %m", tempname);
		goto failed;
	}

	ni_debug_dhcp("Writing lease to temporary file for '%s'", filename);
	xml_node_print(xml, fp);
	fclose(fp);
	xml_node_free(xml);

	if ((ret = rename(tempname, filename)) != 0) {
		ni_error("Unable to rename temporary lease file '%s' to '%s': %m",
				tempname, filename);
		goto failed;
	} else if (!fallback) {
		__ni_addrconf_lease_file_remove(ni_config_statedir(),
				ifname, lease->type, lease->family);
	}

	ni_debug_dhcp("Lease written to file '%s'", filename);
	ni_string_free(&filename);
	return 0;

failed:
	if (fp)
		fclose(fp);
	if (xml)
		xml_node_free(xml);
	if (tempname[0])
		unlink(tempname);
	ni_string_free(&filename);
	return -1;
}

/*
 * Read a lease from a file
 */
ni_addrconf_lease_t *
ni_addrconf_lease_file_read(const char *ifname, int type, int family)
{
	ni_addrconf_lease_t *lease = NULL;
	xml_node_t *xml = NULL, *lnode;
	char *filename = NULL;
	FILE *fp;

	if (!__ni_addrconf_lease_file_path(&filename,
				ni_config_statedir(),
				ifname, type, family)) {
		ni_error("Unable to construct lease file name: %m");
		return NULL;
	}

	if ((fp = fopen(filename, "re")) == NULL) {
		if (errno == ENOENT) {
			if (__ni_addrconf_lease_file_path(&filename,
						ni_config_storedir(),
						ifname, type, family))
				fp = fopen(filename, "re");
		}
		if (fp == NULL) {
			if (errno != ENOENT) {
				ni_error("Unable to open %s for reading: %m",
						filename);
			}
			ni_string_free(&filename);
			return NULL;
		}
	}

	ni_debug_dhcp("Reading lease from %s", filename);
	xml = xml_node_scan(fp, filename);
	fclose(fp);

	if (xml == NULL) {
		ni_error("Unable to parse %s", filename);
		ni_string_free(&filename);
		return NULL;
	}

	/* find the lease node already here, so we can report it */
	if (!ni_string_eq(xml->name, NI_ADDRCONF_LEASE_XML_NODE))
		lnode = xml_node_get_child(xml, NI_ADDRCONF_LEASE_XML_NODE);
	else
		lnode = xml;
	if (!lnode) {
		ni_error("File '%s' does not contain a valid lease", filename);
		ni_string_free(&filename);
		xml_node_free(xml);
		return NULL;
	}

	if (ni_addrconf_lease_from_xml(&lease, xml, ifname) < 0) {
		ni_error("Unable to parse xml lease file '%s'", filename);
		ni_string_free(&filename);
		xml_node_free(xml);
		return NULL;
	}

	ni_string_free(&filename);
	xml_node_free(xml);
	return lease;
}

/*
 * Remove a lease file
 */
static void
__ni_addrconf_lease_file_remove(const char *dir, const char *ifname,
				int type, int family)
{
	char *filename = NULL;

	if (!__ni_addrconf_lease_file_path(&filename, dir, ifname, type, family))
		return;

	if (ni_file_exists(filename) && unlink(filename) == 0)
		ni_debug_dhcp("removed %s", filename);
	ni_string_free(&filename);
}

void
ni_addrconf_lease_file_remove(const char *ifname, int type, int family)
{
	__ni_addrconf_lease_file_remove(ni_config_statedir(), ifname, type, family);
	__ni_addrconf_lease_file_remove(ni_config_storedir(), ifname, type, family);
}

static const char *
__ni_addrconf_lease_file_path(char **path, const char *dir,
		const char *ifname, int type, int family)
{
	const char *t = ni_addrconf_type_to_name(type);
	const char *f = ni_addrfamily_type_to_name(family);

	if (!path || ni_string_empty(dir) || ni_string_empty(ifname) || !t || !f)
		return NULL;
	return ni_string_printf(path, "%s/lease-%s-%s-%s.xml", dir, ifname, t, f);
}

ni_bool_t
ni_addrconf_lease_file_exists(const char *ifname, int type, int family)
{
	char *filename = NULL;

	if (__ni_addrconf_lease_file_path(&filename, ni_config_statedir(), ifname, type, family)) {
		if (ni_file_exists(filename)) {
			ni_string_free(&filename);
			return TRUE;
		}
	}
	if (__ni_addrconf_lease_file_path(&filename, ni_config_storedir(), ifname, type, family)) {
		if (ni_file_exists(filename)) {
			ni_string_free(&filename);
			return TRUE;
		}
	}
	ni_string_free(&filename);
	return FALSE;
}

