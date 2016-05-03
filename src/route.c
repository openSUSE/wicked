/*
 *	Handling of ip routing.
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2016 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *		Olaf Kirch <okir@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <netlink/netlink.h>
#if !defined(IP6_RT_PRIO_USER) || !defined(IP6_RT_PRIO_ADDRCONF)
#include <linux/ipv6_route.h>
#endif

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/route.h>
#include "util_priv.h"
#include "debug.h"

#define NI_ROUTE_ARRAY_CHUNK		16
#define NI_RULE_ARRAY_CHUNK		4

#define IPROUTE2_RT_TABLES_FILE		"/etc/iproute2/rt_tables"


/*
 * Names for route type
 */
static const ni_intmap_t	ni_route_type_names[] = {
	{ "unicast",		RTN_UNICAST		},
	{ "local",		RTN_LOCAL		},
	{ "broadcast",		RTN_BROADCAST		},
	{ "anycast",		RTN_ANYCAST		},
	{ "multicast",		RTN_MULTICAST		},
	{ "blackhole",		RTN_BLACKHOLE		},
	{ "unreachable",	RTN_UNREACHABLE		},
	{ "prohibit",		RTN_PROHIBIT		},
	{ "throw",		RTN_THROW		},
	{ "nat",		RTN_NAT			},
	{ "xresolve",		RTN_XRESOLVE		},

	{ NULL,			RTN_UNSPEC		},
};

/*
 * Names for route table
 */
static const ni_intmap_t	ni_route_table_names[] = {
	{ "compat",		RT_TABLE_COMPAT		},
	{ "default",		RT_TABLE_DEFAULT	},
	{ "main",		RT_TABLE_MAIN		},
	{ "local",		RT_TABLE_LOCAL		},

	{ NULL,			RT_TABLE_UNSPEC		},
};

/*
 * Names for route scope
 */
static const ni_intmap_t	ni_route_scope_names[] = {
	{ "universe",		RT_SCOPE_UNIVERSE	},
	{ "site",		RT_SCOPE_SITE		},
	{ "link",		RT_SCOPE_LINK		},
	{ "host",		RT_SCOPE_HOST		},
	{ "nowhere",		RT_SCOPE_NOWHERE	},

	{ NULL,			RT_SCOPE_UNIVERSE	}
};

/*
 * Names for route protocol
 */
static const ni_intmap_t	ni_route_protocol_names[] = {
	{ "redirect",		RTPROT_REDIRECT		},
	{ "kernel",		RTPROT_KERNEL		},
	{ "boot",		RTPROT_BOOT		},
	{ "static",		RTPROT_STATIC		},
	/* protocols >= STATIC are not interpreted by the kernel */
	{ "gated",		RTPROT_GATED		},
	{ "ra",			RTPROT_RA		},
	{ "mrt",		RTPROT_MRT		},
	{ "zebra",		RTPROT_ZEBRA		},
	{ "bird",		RTPROT_BIRD		},
	{ "dnrouted",		RTPROT_DNROUTED		},
	{ "xorp",		RTPROT_XORP		},
	{ "ntk",		RTPROT_NTK		},
	{ "dhcp",		RTPROT_DHCP		},

	{ NULL,			RTPROT_UNSPEC		}
};

/*
 * Names for bit numbers of route [next-hop] flags and lock bits.
 * Note: We need the bits to generate a bitmap in constants.xml.
 */
static const ni_intmap_t	ni_route_flags_bits[] = {
	{ "notify",		8  /* RTM_F_NOTIFY   */	},
	{ "cloned",		9  /* RTM_F_CLONED   */	},
	{ "equalize",		10 /* RTM_F_EQUALIZE */	},
	{ "prefix",		11 /* RTM_F_PREFIX   */	},

	{ NULL,			0			}
};
static const ni_intmap_t	ni_route_nh_flags_bits[] = {
	{ "dead",		0  /* RTNH_F_DEAD     */},
	{ "pervasive",		1  /* RTNH_F_PERVASIVE*/},
	{ "online",		2  /* RTNH_F_ONLINK   */},

	{ NULL,			0			}
};
static const ni_intmap_t	ni_route_mxlock_bits[] = {
	{ "mtu",		RTAX_MTU		},
	{ "window",		RTAX_WINDOW		},
	{ "rtt",		RTAX_RTT		},
	{ "rttvar",		RTAX_RTTVAR		},
	{ "ssthresh",		RTAX_SSTHRESH		},
	{ "cwnd",		RTAX_CWND		},
	{ "advmss",		RTAX_ADVMSS		},
	{ "reordering",		RTAX_REORDERING		},
	{ "hoplimit",		RTAX_HOPLIMIT		},
	{ "initcwnd",		RTAX_INITCWND		},
	{ "features",		RTAX_FEATURES		},
	{ "rto_min",		RTAX_RTO_MIN		},
#if defined(RTAX_INITRWND)
	{ "initrwnd",		RTAX_INITRWND		},
#endif

	{ NULL,			0			},
};


/*
 * ni_route functions
 */
ni_route_t *
ni_route_new(void)
{
	ni_route_t *rp;

	rp = xcalloc(1, sizeof(ni_route_t));
	if (rp)
		rp->users = 1;
	return rp;
}

ni_route_t *
ni_route_create(unsigned int prefixlen, const ni_sockaddr_t *dest,
		const ni_sockaddr_t *gw, unsigned int table,
		ni_route_table_t **list)
{
	static const ni_sockaddr_t null_addr;
	ni_route_t *rp;
	int af;

	if (!dest)
		dest = &null_addr;
	if (!gw)
		gw = &null_addr;

	af = dest->ss_family;
	if (gw->ss_family == AF_UNSPEC) {
		/* No gateway - this is a direct subnet route.
		 * Just make sure the destination is not the default
		 * route. */
		if (af == AF_UNSPEC) {
			ni_error("Cannot add route - destination and gw are both 0/0");
			return NULL;
		}
	} else {
		if (af == AF_UNSPEC) {
			af = gw->ss_family;
		} else
		if (dest->ss_family != gw->ss_family) {
			ni_error("Cannot create route - destination and gateway address "
					"family mismatch");
			return NULL;
		}
	}

	if (!(rp = ni_route_new()))
		return NULL;

	rp->family = af;
	rp->prefixlen = prefixlen;
	rp->destination = *dest;
	if (!ni_sockaddr_is_specified(gw))
		rp->nh.gateway.ss_family = af;
	else
		rp->nh.gateway = *gw;
	if (rp->destination.ss_family == AF_UNSPEC) {
		memset(&rp->destination, 0, sizeof(rp->destination));
		rp->destination.ss_family = af;
	}

	rp->type = RTN_UNICAST;
	rp->protocol = RTPROT_BOOT;
	rp->scope = ni_route_guess_scope(rp);
	if (ni_route_is_valid_table(table))
		rp->table = table;
	else
		rp->table = ni_route_guess_table(rp);

	if (list) {
		if (!ni_route_tables_add_route(list, rp)) {
			ni_route_free(rp);
			rp = NULL;
		}
	}
	return rp;
}

ni_route_t *
ni_route_clone(const ni_route_t *src)
{
	ni_route_t *rp;

	if (src) {
		rp = ni_route_new();
		if (ni_route_copy(rp, src))
			return rp;

		ni_route_free(rp);
	}
	return NULL;
}

static ni_bool_t
ni_route_copy_options(ni_route_t *rp, const ni_route_t *src)
{
	if (!rp || !src)
		return FALSE;
#define C(x)	rp->x = src->x
	C(owner);
	C(family);
	C(prefixlen);
	C(destination);
	C(pref_src);
	C(priority);
	C(flags);
	C(realm);
	C(mark);
	C(tos);

	C(table);
	C(type);
	C(scope);
	C(protocol);

	C(lock);
	C(mtu);
	C(rtt);
	C(rttvar);
	C(window);
	C(cwnd);
	C(initcwnd);
	C(initrwnd);
	C(ssthresh);
	C(advmss);
	C(rto_min);
	C(hoplimit);
	C(features);
	C(reordering);

	C(ipv6_cache_info);
#undef C
	return TRUE;
}

ni_bool_t
ni_route_copy(ni_route_t *rp, const ni_route_t *src)
{
	if (!ni_route_copy_options(rp, src))
		return FALSE;

	return ni_route_replace_hops(rp, &src->nh);
}

ni_route_t *
ni_route_ref(ni_route_t *rp)
{
	if (!rp)
		return NULL;

	ni_assert(rp->users);
	rp->users++;
	return rp;
}

static inline void
do_route_free(ni_route_t *rp)
{
	ni_route_nexthop_list_destroy(&rp->nh.next);
	ni_route_nexthop_destroy(&rp->nh);

	free(rp);
}

void
ni_route_free(ni_route_t *rp)
{
	if (!rp)
		return;

	ni_assert(rp->users);
	rp->users--;
	if (rp->users == 0) {
		do_route_free(rp);
	}
}

ni_bool_t
ni_route_update_options(ni_route_t *rp, const ni_route_t *src)
{
	if (!rp || !src)
		return FALSE;

#define CC(x)	if (src->x) rp->x = src->x
	CC(owner);
	/* skip family, prefixlen */
	CC(priority);
	CC(flags);
	CC(realm);
	CC(mark);
	CC(tos);
	/* skip table, type */
	CC(scope);
	CC(protocol);
	CC(lock);
	CC(mtu);
	CC(rtt);
	CC(rttvar);
	CC(window);
	CC(cwnd);
	CC(initcwnd);
	CC(initrwnd);
	CC(ssthresh);
	CC(advmss);
	CC(rto_min);
	CC(hoplimit);
	CC(features);
	CC(reordering);
#undef  CC
	rp->ipv6_cache_info = src->ipv6_cache_info;

	return TRUE;
}

ni_bool_t
ni_route_update(ni_route_t *rp, const ni_route_t *src)
{
	if (!rp || !src)
		return FALSE;

	if (rp->family != src->family)
		return FALSE;

	if (rp->table != src->table)
		return FALSE;

	if (rp->type  != src->type)
		return FALSE;

	if (rp->prefixlen != src->prefixlen)
		return FALSE;

	if (rp->prefixlen && !ni_sockaddr_equal(&rp->destination, &src->destination))
		return FALSE;

	if (!ni_route_replace_hops(rp, &src->nh))
		return FALSE;

	if (ni_sockaddr_is_specified(&src->pref_src))
		rp->pref_src = src->pref_src;

	return ni_route_update_options(rp, src);
}

ni_bool_t
ni_route_replace_hops(ni_route_t *rp, const ni_route_nexthop_t *sh)
{
	ni_route_nexthop_t *nh;

	if (!rp)
		return FALSE;

	ni_route_nexthop_list_destroy(&rp->nh.next);
	ni_route_nexthop_destroy(&rp->nh);

	for (nh = &rp->nh; sh; sh = sh->next, nh = nh->next) {
		if (!ni_route_nexthop_copy(nh, sh))
			return FALSE;
		if (sh->next)
			nh->next = ni_route_nexthop_new();
	}
	return TRUE;
}

ni_route_t *
ni_route_squash_hops(const ni_route_array_t *routes, const ni_route_t *rp)
{
	ni_route_nexthop_t **tail = NULL, *nh;
	const ni_route_nexthop_t *sh;
	ni_route_t *result = NULL;
	const ni_route_t *sr;
	unsigned int i;

	if (!rp || !routes || !routes->count)
		return NULL;

	result = ni_route_new();
	if (!ni_route_copy_options(result, rp)) {
		ni_route_free(result);
		return NULL;
	}

	nh = &result->nh;
	tail = &nh;
	for (i = 0; i < routes->count; ++i) {
		sr = routes->data[i];
		for (sh = &sr->nh; sh; sh = sh->next) {
			if (!(nh = *tail))
				*tail = nh = ni_route_nexthop_new();

			if (!ni_route_nexthop_copy(nh, sh)) {
				ni_route_free(result);
				return NULL;
			}
			tail = &nh->next;
		}
	}
	return result;
}

unsigned int
ni_route_expand_hops(ni_route_array_t *routes, const ni_route_t *rp)
{
	const ni_route_nexthop_t *nh;
	ni_route_t *r = NULL;
	unsigned int count;

	if (!rp || !routes)
		return FALSE;

	count = routes->count;
	for (nh = &rp->nh; nh; nh = nh->next) {
		r = ni_route_new();

		if (ni_route_copy_options(r, rp) &&
		    ni_route_nexthop_copy(&r->nh, nh) &&
		    ni_route_array_append(routes, r))
			continue;

		ni_route_free(r);
		while (routes->count > count) {
			if (!ni_route_array_delete(routes, routes->count - 1))
				break;
		}
		return 0;
	}
	return routes->count - count;
}

ni_route_t *
ni_route_drop_ifindex_hops(const ni_route_t *sr, unsigned int index)
{
	const ni_route_nexthop_t *sh;
	ni_route_nexthop_t *nh, **tail = NULL;
	ni_route_t *rp = NULL;

	if (!sr || !index)
		return NULL;

	for (sh = &sr->nh; sh;  sh = sh->next) {
		if (!sh->device.index || index == sh->device.index)
			continue;
		if (rp == NULL) {
			rp = ni_route_new();
			if (!rp)
				return NULL;
			nh = &rp->nh;
			if (!ni_route_copy_options(rp, sr) ||
			    !ni_route_nexthop_copy(nh, sh)) {
				ni_route_free(rp);
				return NULL;
			}
		} else {
			*tail = nh = ni_route_nexthop_new();
			if (!ni_route_nexthop_copy(nh, sh)) {
				ni_route_free(rp);
				return NULL;
			}
		}
		tail = &nh->next;
	}
	return rp;
}

void
ni_route_bind_ifname(ni_route_t *rp, ni_netconfig_t *nc, ni_netdev_t *dev)
{
	ni_route_nexthop_t  *nh;

	/* Set device names in hops of a route discovered from system
	 * with an optional dev as an resolved current/cached device.
	 */
	for (nh = &rp->nh; nh;  nh = nh->next)
		ni_route_nexthop_bind_ifname(nh, nc, dev);
}

void
ni_route_bind_ifindex(ni_route_t *rp, ni_netconfig_t *nc, ni_netdev_t *dev, unsigned int ifflags)
{
	ni_route_nexthop_t  *nh;

	/* Set device indices in hops of a configuration/lease route
	 * with optional dev as the default (current/lease) device.
	 */
	for (nh = &rp->nh; nh;  nh = nh->next)
		ni_route_nexthop_bind_ifindex(nh, nc, dev, ifflags);
}

ni_bool_t
ni_route_equal_destination(const ni_route_t *r1, const ni_route_t *r2)
{
	if (ni_route_equal_ref(r1, r2))
		return TRUE;

	if (r1->family != r2->family)
		return FALSE;

	if (r1->prefixlen != r2->prefixlen)
		return FALSE;

	if (r1->prefixlen && !ni_sockaddr_equal(&r1->destination, &r2->destination))
		return FALSE;

	if (r1->family == AF_INET) {
		/*
		 * ipv4 matches routing entries by [prefix, tos, priority]
		 */
		if (r1->tos != r2->tos || r1->priority != r2->priority)
			return FALSE;
	} else
	if (r1->family == AF_INET6) {
		/*
		 * ipv6 matches routing entries by [src pfx, dst pfx, priority]
		 * and automatically assigns priority (metrics) to them.
		 *
		 * we don't support source routes yet and filter them out, so
		 * all routes have a "from all" source for now.
		 */
		unsigned int p1 = r1->priority;
		unsigned int p2 = r2->priority;
		if (!p1) {
			if (!ni_route_type_needs_nexthop(r1->type))
				p1 = IP6_RT_PRIO_USER;
			else
			if (ni_route_via_gateway(r1))
				p1 = IP6_RT_PRIO_USER;
			else
				p1 = IP6_RT_PRIO_ADDRCONF;
		}
		if (!p2) {
			if (!ni_route_type_needs_nexthop(r2->type))
				p2 = IP6_RT_PRIO_USER;
			else
			if (ni_route_via_gateway(r2))
				p2 = IP6_RT_PRIO_USER;
			else
				p2 = IP6_RT_PRIO_ADDRCONF;
		}
		if (p1 != p2)
			return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_route_equal_pref_source(const ni_route_t *r1, const ni_route_t *r2)
{
	return ni_sockaddr_equal(&r1->pref_src, &r2->pref_src);
}

ni_bool_t
ni_route_equal_options(const ni_route_t *r1, const ni_route_t *r2)
{
#define NE(x)	if (r1->x != r2->x) return FALSE;
	NE(realm);
	NE(mark);
	NE(scope);
	NE(protocol);
	NE(lock);
	NE(mtu);
	NE(rtt);
	NE(rttvar);
	NE(window);
	NE(cwnd);
	NE(initcwnd);
	NE(initrwnd);
	NE(ssthresh);
	NE(advmss);
	NE(rto_min);
	NE(hoplimit);
	NE(features);
	NE(reordering);
#undef  NE
	return TRUE;
}

ni_bool_t
ni_route_equal_gateways(const ni_route_t *r1, const ni_route_t *r2)
{
	const ni_route_nexthop_t *nh1, *nh2;

	if (ni_route_equal_ref(r1, r2))
		return TRUE;

	nh1 = &r1->nh;
	nh2 = &r2->nh;
	while (nh1 && nh2) {
		if (!ni_route_nexthop_equal_gateway(nh1, nh2))
			return FALSE;
		nh1 = nh1->next;
		nh2 = nh2->next;
	}
	return nh1 == nh2;
}

ni_bool_t
ni_route_equal_hops(const ni_route_t *r1, const ni_route_t *r2)
{
	const ni_route_nexthop_t *nh1, *nh2;

	if (ni_route_equal_ref(r1, r2))
		return TRUE;

	nh1 = &r1->nh;
	nh2 = &r2->nh;
	while (nh1 && nh2) {
		if (!ni_route_nexthop_equal(nh1, nh2))
			return FALSE;
		nh1 = nh1->next;
		nh2 = nh2->next;
	}
	return ni_route_nexthop_equal(nh1, nh2);
}

ni_bool_t
ni_route_equal_ref(const ni_route_t *r1, const ni_route_t *r2)
{
	return r1 == r2;
}

ni_bool_t
ni_route_equal(const ni_route_t *r1, const ni_route_t *r2)
{
	if (!r1 || !r2)
		return r1 == r2;

	if (!ni_route_equal_destination(r1, r2))
		return FALSE;

	/* corner case? when a direct route without pref-src
	 * exists and same prefix address gets added, kernel
	 * will add a route (duplicate) with a pref-src set.
	 */
	if (!ni_route_equal_pref_source(r1, r2))
		return FALSE;

	if (!ni_route_equal_options(r1, r2))
		return FALSE;

	if (!ni_route_equal_hops(r1, r2))
		return FALSE;

	return TRUE;
}

static int
do_route_cmp_show(int ret, const char *what)
{
#ifdef NI_ROUTE_TRACE_CMP_LEVEL
	if (ret) {
		ni_debug_verbose(NI_ROUTE_TRACE_CMP_LEVEL, NI_TRACE_IFCONFIG,
				"route %s cmp ==>> %d", what, ret);
	}
#endif
	return ret;
}

static int
ni_route_sort_cmp(const ni_route_t *r1, const ni_route_t *r2)
{
#define do_cmp(a, b)	(a > b ? 1 : a < b ? -1 : 0)
	int ret;
#ifdef NI_ROUTE_TRACE_CMP_LEVEL
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;

	ni_debug_verbose(NI_ROUTE_TRACE_CMP_LEVEL, NI_TRACE_IFCONFIG,
			"route cmp 1: %s", ni_route_print(&out, r1));
	ni_stringbuf_destroy(&out);

	ni_debug_verbose(NI_ROUTE_TRACE_CMP_LEVEL, NI_TRACE_IFCONFIG,
			"      and 2: %s", ni_route_print(&out, r2));
	ni_stringbuf_destroy(&out);
#endif
	if (!r1 || !r2)
		return do_route_cmp_show(do_cmp(r1, r2), "pointer");

	if ((ret = do_cmp(r1->table, r2->table)))
		return do_route_cmp_show(ret, "table");

	if ((ret = do_cmp(r1->family, r2->family)))
		return do_route_cmp_show(ret, "family");

	if ((ret = (ni_route_via_gateway(r1) ? 1 : 0) - (ni_route_via_gateway(r2) ? 1 : 0)))
		return do_route_cmp_show(ret, "via gw");

	if ((ret = do_cmp(r1->prefixlen, r2->prefixlen)))
		return do_route_cmp_show(-ret, "prefix-len");

	if ((ret = ni_sockaddr_compare(&r1->destination, &r2->destination)))
		return do_route_cmp_show(ret, "destination");

	if ((ret = do_cmp(r1->priority, r2->priority)))
		return do_route_cmp_show(ret, "priority");

	return 0;
#undef do_cmp
}

static const char *
ni_route_print_flags(ni_stringbuf_t *out, unsigned int flags,
		const ni_intmap_t *map, const char *prefix, const char *sep)
{
	size_t beg = out->len;
	unsigned int i;

	for (i = 0; map && map->name; ++map) {
		if (flags & (1 << map->value)) {
			ni_stringbuf_puts(out, i++ ? sep : prefix);
			ni_stringbuf_puts(out, map->name);
		}
	}
	return out->string ? out->string + beg : NULL;
}

const char *
ni_route_print(ni_stringbuf_t *out, const ni_route_t *rp)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	const ni_route_nexthop_t *nh;
	const char *ptr;

	if (!out || !rp || rp->family == AF_UNSPEC ||
	    rp->destination.ss_family != rp->family)
		return NULL;

	if ((ptr = ni_addrfamily_type_to_name(rp->family))) {
		ni_stringbuf_printf(out, "%s ", ptr);
	}

	ni_stringbuf_printf(out, "%s/%u",
		ni_sockaddr_print(&rp->destination), rp->prefixlen);

	for (nh = &rp->nh; nh; nh = nh->next) {
		ni_netdev_t *dev;

		if (rp->nh.next) {
			ni_stringbuf_printf(out, " nexthop");
		}
		if (ni_sockaddr_is_specified(&nh->gateway)) {
			ni_stringbuf_printf(out, " via %s",
					ni_sockaddr_print(&nh->gateway));
		}
		if (nh->device.name) {
			if (nh->device.index)
				ni_stringbuf_printf(out, " dev %s#%u",	nh->device.name,
									nh->device.index);
			else
				ni_stringbuf_printf(out, " dev %s",	nh->device.name);
		} else
		if (nh->device.index) {
			dev = nc ? ni_netdev_by_index(nc, nh->device.index) : NULL;
			if (!dev || !dev->name)
				ni_stringbuf_printf(out, " dev #%u",	nh->device.index);
			else
				ni_stringbuf_printf(out, " dev %s#%u",	dev->name,
									dev->link.ifindex);
		}
		if (!rp->nh.next)
			continue;

		if (nh->weight) {
			ni_stringbuf_printf(out, " weight %u", nh->weight);
		}
		if (nh->realm > 0) {
			ni_stringbuf_printf(out, " realm %u", nh->realm);
		}
		if (nh->flags > 0) {
			ni_route_print_flags(out, nh->flags,
					ni_route_nh_flags_bits,
					" flags ", "|");
		}
	}

	/* kern */
	if (rp->type != RTN_UNSPEC) {
		if ((ptr = ni_route_type_type_to_name(rp->type))) {
			ni_stringbuf_printf(out, " type %s", ptr);
		} else {
			ni_stringbuf_printf(out, " type %u", rp->type);
		}
	}
	if (rp->table != RT_TABLE_UNSPEC) {
		char *name = NULL;
		if ((ptr = ni_route_table_type_to_name(rp->table, &name)))
			ni_stringbuf_printf(out, " table %s", ptr);
		else
			ni_stringbuf_printf(out, " table %u", rp->table);
		ni_string_free(&name);
	}
	if ((ptr = ni_route_scope_type_to_name(rp->scope))) {
		ni_stringbuf_printf(out, " scope %s", ptr);
	} else {
		ni_stringbuf_printf(out, " scope %u", rp->scope);
	}
	if (rp->protocol != RTPROT_UNSPEC) {
		if ((ptr = ni_route_protocol_type_to_name(rp->protocol))) {
			ni_stringbuf_printf(out, " protocol %s", ptr);
		} else {
			ni_stringbuf_printf(out, " protocol %u", rp->protocol);
		}
	}

	/* other attrs */
	if (rp->flags > 0) {
		ni_route_print_flags(out, rp->flags,
				ni_route_flags_bits, " flags ", "|");
	}
	if (ni_sockaddr_is_specified(&rp->pref_src)) {
		ni_stringbuf_printf(out, " pref-src %s",
				ni_sockaddr_print(&rp->pref_src));
	}
	if (rp->priority > 0) {
		ni_stringbuf_printf(out, " priority %u", rp->priority);
	}
	if (rp->realm > 0) {
		ni_stringbuf_printf(out, " realm %u", rp->realm);
	}
	if (rp->tos > 0) {
		/* TODO: names */
		ni_stringbuf_printf(out, " tos 0x%02x", rp->tos);
	}

	/* metrics */
	if (rp->mtu > 0) {
		if (rp->lock & (1<<RTAX_MTU))
			ni_stringbuf_printf(out, " mtu lock %u", rp->mtu);
		else
			ni_stringbuf_printf(out, " mtu %u", rp->mtu);
	}
	if (rp->window > 0) {
		if (rp->lock & (1<<RTAX_WINDOW))
			ni_stringbuf_printf(out, " window lock %u", rp->window);
		else
			ni_stringbuf_printf(out, " window %u", rp->window);
	}
	if (rp->rtt > 0) {
		if (rp->lock & (1<<RTAX_RTT))
			ni_stringbuf_printf(out, " rtt lock %u", rp->rtt);
		else
			ni_stringbuf_printf(out, " rtt %u", rp->rtt);
	}
	if (rp->rttvar > 0) {
		if (rp->lock & (1<<RTAX_RTTVAR))
			ni_stringbuf_printf(out, " rttvar %u", rp->rttvar);
		else
			ni_stringbuf_printf(out, " rttvar %u", rp->rttvar);
	}
	if (rp->ssthresh > 0) {
		if (rp->lock & (1<<RTAX_SSTHRESH))
			ni_stringbuf_printf(out, " ssthresh lock %u", rp->ssthresh);
		else
			ni_stringbuf_printf(out, " ssthresh %u", rp->ssthresh);
	}
	if (rp->cwnd > 0) {
		if (rp->lock & (1<<RTAX_CWND))
			ni_stringbuf_printf(out, " cwnd lock %u", rp->cwnd);
		else
			ni_stringbuf_printf(out, " cwnd %u", rp->cwnd);
	}
	if (rp->advmss > 0) {
		if (rp->lock & (1<<RTAX_ADVMSS))
			ni_stringbuf_printf(out, " advmss lock %u", rp->advmss);
		else
			ni_stringbuf_printf(out, " advmss %u", rp->advmss);
	}
	if (rp->reordering > 0) {
		if (rp->lock & (1<<RTAX_REORDERING))
			ni_stringbuf_printf(out, " reordering lock %u", rp->reordering);
		else
			ni_stringbuf_printf(out, " reordering %u", rp->reordering);
	}
	if (rp->hoplimit > 0) {
		if (rp->lock & (1<<RTAX_HOPLIMIT))
			ni_stringbuf_printf(out, " hoplimit lock %u", rp->hoplimit);
		else
			ni_stringbuf_printf(out, " hoplimit %u", rp->hoplimit);
	}
	if (rp->initcwnd > 0) {
		if (rp->lock & (1<<RTAX_INITCWND))
			ni_stringbuf_printf(out, " initcwnd lock %u", rp->initcwnd);
		else
			ni_stringbuf_printf(out, " initcwnd %u", rp->initcwnd);
	}
	if (rp->features > 0) {
		if (rp->lock & (1<<RTAX_FEATURES))
			ni_stringbuf_printf(out, " features lock %u", rp->features);
		else
			ni_stringbuf_printf(out, " features %u", rp->features);
	}
	if (rp->rto_min > 0) {
		if (rp->lock & (1<<RTAX_RTO_MIN))
			ni_stringbuf_printf(out, " rto_min lock %u", rp->rto_min);
		else
			ni_stringbuf_printf(out, " rto_min %u", rp->rto_min);
	}
	if (rp->initrwnd > 0) {
#if defined(RTAX_INITRWND)
		if (rp->lock & (1<<RTAX_INITRWND))
			ni_stringbuf_printf(out, " initrwnd lock %u", rp->initrwnd);
		else
#endif
			ni_stringbuf_printf(out, " initrwnd %u", rp->initrwnd);
	}

	return out->string;
}

const char *
ni_route_type_type_to_name(unsigned int type)
{
	return ni_format_uint_maybe_mapped(type, ni_route_type_names);
}

const char *
ni_route_table_type_to_name(unsigned int type, char **name)
{
	const char *res = NULL;

	if (!name)
		return NULL;

	if ((res = ni_format_uint_mapped(type, ni_route_table_names))) {
		ni_string_dup(name, res);
		return *name;
	}

	if (ni_intmap_file_get_name(IPROUTE2_RT_TABLES_FILE, &type, name))
		return *name;

	/* Last resort. Convert type to string and return as name */
	return ni_string_printf(name, "%u", type);
}

const char *
ni_route_scope_type_to_name(unsigned int type)
{
	return ni_format_uint_maybe_mapped(type, ni_route_scope_names);
}

const char *
ni_route_protocol_type_to_name(unsigned int type)
{
	return ni_format_uint_maybe_mapped(type, ni_route_protocol_names);
}

const char *
ni_route_flag_bit_to_name(unsigned int bit)
{
	return ni_format_uint_mapped(bit, ni_route_flags_bits);
}

const char *
ni_route_nh_flag_bit_to_name(unsigned int bit)
{
	return ni_format_uint_mapped(bit, ni_route_nh_flags_bits);
}

const char *
ni_route_metrics_lock_bit_to_name(unsigned int bit)
{
	return ni_format_uint_mapped(bit, ni_route_mxlock_bits);
}

ni_bool_t
ni_route_type_name_to_type(const char *name, unsigned int *type)
{
	unsigned int value;

	if (!type || !name)
		return FALSE;

	if (ni_parse_uint_maybe_mapped(name, ni_route_type_names, &value, 10) < 0)
		return FALSE;

	*type = value;
	return TRUE;
}

ni_bool_t
ni_route_table_name_to_type(const char *name, unsigned int *table)
{
	unsigned int value;
	char *name_from_file = NULL;

	if (!table || !name)
		return FALSE;

	if (ni_parse_uint_maybe_mapped(name, ni_route_table_names, &value, 10) != -1) {
		*table = value;
		return TRUE;
	}

	ni_string_dup(&name_from_file, name);
	if (ni_intmap_file_get_value(IPROUTE2_RT_TABLES_FILE, &value, &name_from_file)) {
		*table = value;
		ni_string_free(&name_from_file);
		return TRUE;
	}
	ni_string_free(&name_from_file);

	if (ni_parse_uint(name, &value, 10) == 0) {
		*table = value;
		return TRUE;
	}

	return FALSE;
}

ni_bool_t
ni_route_scope_name_to_type(const char *name, unsigned int *scope)
{
	unsigned int value;

	if (!scope || !name)
		return FALSE;

	if (ni_parse_uint_maybe_mapped(name, ni_route_scope_names, &value, 10) < 0)
		return FALSE;

	*scope = value;
	return TRUE;
}

ni_bool_t
ni_route_protocol_name_to_type(const char *name, unsigned int *proto)
{
	unsigned int value;

	if (!proto || !name)
		return FALSE;

	if (ni_parse_uint_maybe_mapped(name, ni_route_protocol_names, &value, 10) < 0)
		return FALSE;

	*proto = value;
	return TRUE;
}

ni_bool_t
ni_route_flags_get_names(unsigned int flags, ni_string_array_t *names)
{
	const ni_intmap_t *map;

	if (!names)
		return FALSE;

	ni_string_array_destroy(names);
	for (map = ni_route_flags_bits; map->name; ++map) {
		if (flags & (1 << map->value)) {
			ni_string_array_append(names, map->name);
		}
	}
	return TRUE;
}

ni_bool_t
ni_route_nh_flags_get_names(unsigned int flags, ni_string_array_t *names)
{
	const ni_intmap_t *map;

	if (!names)
		return FALSE;

	ni_string_array_destroy(names);
	for (map = ni_route_nh_flags_bits; map->name; ++map) {
		if (flags & (1 << map->value)) {
			ni_string_array_append(names, map->name);
		}
	}
	return TRUE;
}

ni_bool_t
ni_route_metrics_lock_get_names(unsigned int lock, ni_string_array_t *names)
{
	const ni_intmap_t *map;
	unsigned int n = 0;

	for (map = ni_route_mxlock_bits; map->name; ++map) {
		if (lock & (1 << map->value)) {
			ni_string_array_append(names, map->name);
			++n;
		}
	}
	return n;
}

ni_bool_t
ni_route_metrics_lock_set(const char *name, unsigned int *lock)
{
	unsigned int bit = 0;

	if (!lock || ni_parse_uint_mapped(name, ni_route_mxlock_bits, &bit) < 0)
		return FALSE;

	*lock |= (1 << bit);

	return TRUE;
}

ni_bool_t
ni_route_type_needs_nexthop(unsigned int type)
{
	switch (type) {
	case RTN_THROW:
	case RTN_PROHIBIT:
	case RTN_BLACKHOLE:
	case RTN_UNREACHABLE:
		return FALSE;
	default:
		return TRUE;
	}
}

unsigned int
ni_route_guess_table(ni_route_t *rp)
{
	if (rp) {
		switch (rp->type) {
		case RTN_LOCAL:
		case RTN_NAT:
		case RTN_BROADCAST:
		case RTN_ANYCAST:
			return RT_TABLE_LOCAL;
		break;

		default: ;
		}
	}
	return RT_TABLE_MAIN;
}

unsigned int
ni_route_guess_scope(ni_route_t *rp)
{
	if (rp) {
		switch (rp->type) {
		case RTN_LOCAL:
		case RTN_NAT:
			return RT_SCOPE_HOST;

		case RTN_BROADCAST:
		case RTN_MULTICAST:
		case RTN_ANYCAST:
			return RT_SCOPE_LINK;

		case RTN_UNICAST:
		case RTN_UNSPEC:
			if (!ni_sockaddr_is_specified(&rp->nh.gateway))
				return RT_SCOPE_LINK;
		default: ;
		}
	}
	return RT_SCOPE_UNIVERSE;
}

ni_bool_t
ni_route_is_valid_type(unsigned int type)
{
	return type > RTN_UNSPEC && type <= RTN_MAX;
}

ni_bool_t
ni_route_is_valid_table(unsigned int table)
{
	return table > RT_TABLE_UNSPEC && table < RT_TABLE_MAX;
}

ni_bool_t
ni_route_is_valid_scope(unsigned int scope)
{
	return scope < RT_SCOPE_NOWHERE;
}

ni_bool_t
ni_route_is_valid_protocol(unsigned int protocol)
{
	return protocol > RTPROT_UNSPEC && protocol <= UCHAR_MAX;
}

ni_bool_t
ni_route_is_multipath(const ni_route_t *rp)
{
	return rp->nh.next != NULL;
}

ni_bool_t
ni_route_contains_hop(const ni_route_t *rp, const ni_route_nexthop_t *nh)
{
	const ni_route_nexthop_t *hop = &rp->nh;

	while ((hop = ni_route_nexthop_find_by_device(hop, &nh->device))) {
		if (ni_route_nexthop_equal_gateway(hop, nh))
			return TRUE;
		hop = hop->next;
	}
	return FALSE;
}

ni_bool_t
ni_route_contains_hops(const ni_route_t *rp, const ni_route_nexthop_t *list)
{
	const ni_route_nexthop_t *nh;
	ni_bool_t match = FALSE;

	if (rp) for (nh = list; nh; nh = nh->next) {
		if (!ni_route_contains_hop(rp, nh))
			return FALSE;
		match = TRUE;
	}
	return match;
}

ni_bool_t
ni_route_via_gateway(const ni_route_t *rp)
{
	const ni_route_nexthop_t *nh;

	for (nh = (rp ? &rp->nh : NULL); nh; nh = nh->next) {
		if (ni_sockaddr_is_specified(&nh->gateway))
			return TRUE;
	}
	return FALSE;
}

/*
 * ni_route_nexthop functions
 */
ni_route_nexthop_t *
ni_route_nexthop_new(void)
{
	return xcalloc(1, sizeof(ni_route_nexthop_t));
}

void
ni_route_nexthop_destroy(ni_route_nexthop_t *hop)
{
	if (hop) {
		ni_netdev_ref_destroy(&hop->device);
		memset(hop, 0, sizeof(*hop));
	}
}

void
ni_route_nexthop_free(ni_route_nexthop_t *hop)
{
	if (hop) {
		ni_route_nexthop_destroy(hop);
		free(hop);
	}
}

ni_bool_t
ni_route_nexthop_copy(ni_route_nexthop_t *dst, const ni_route_nexthop_t *src)
{
	if (src && dst) {
		dst->gateway = src->gateway;
		dst->weight  = src->weight;
		dst->flags   = src->flags;
		dst->realm   = src->realm;
		dst->device.index = src->device.index;
		return ni_string_dup(&dst->device.name, src->device.name);
	}
	return FALSE;
}

ni_bool_t
ni_route_nexthop_empty(const ni_route_nexthop_t *nh)
{
	if (nh) {
		if (nh->device.index || nh->device.name)
			return FALSE;
		if (ni_sockaddr_is_specified(&nh->gateway))
			return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_route_nexthop_equal(const ni_route_nexthop_t *lh, const  ni_route_nexthop_t *rh)
{
	if (!lh || !rh)
		return lh == rh;

	if (!ni_route_nexthop_equal_device(lh, rh))
		return FALSE;

	return ni_route_nexthop_equal_gateway(lh, rh);
}

ni_bool_t
ni_route_nexthop_equal_device(const ni_route_nexthop_t *lh, const  ni_route_nexthop_t *rh)
{
	if (lh->device.index && rh->device.index)
		return lh->device.index == rh->device.index;
	else
		return ni_string_eq(lh->device.name, rh->device.name);
}

ni_bool_t
ni_route_nexthop_equal_gateway(const ni_route_nexthop_t *lh, const  ni_route_nexthop_t *rh)
{
	return ni_sockaddr_equal(&lh->gateway, &rh->gateway);
}

ni_bool_t
ni_route_nexthop_bound(const ni_route_nexthop_t *nh)
{
	return nh && nh->device.index;
}

void
ni_route_nexthop_bind_ifname(ni_route_nexthop_t *nh, ni_netconfig_t *nc, ni_netdev_t *dev)
{
	if (dev && nh->device.index == dev->link.ifindex) {
		if (!ni_string_eq(nh->device.name, dev->name))
			ni_string_dup(&nh->device.name, dev->name);
	} else {
		ni_netdev_ref_bind_ifname(&nh->device, nc);
	}
}

void
ni_route_nexthop_bind_ifindex(ni_route_nexthop_t *nh, ni_netconfig_t *nc, ni_netdev_t *dev,
				unsigned int ifflags)
{
	if (dev && ni_string_empty(nh->device.name))
		ni_netdev_ref_set(&nh->device, dev->name, dev->link.ifindex);
	else
	if (dev && ni_string_eq(nh->device.name, dev->name))
		ni_netdev_ref_set_ifindex(&nh->device, dev->link.ifindex);
	else
	if (!ni_string_empty(nh->device.name)) {
		dev = ni_netdev_by_name(nc, nh->device.name);
		if (dev && (dev->link.ifflags & ifflags))
			nh->device.index = dev->link.ifindex;
	}
}

/*
 * ni_route_nexthop list functions
 */
void
ni_route_nexthop_list_append(ni_route_nexthop_t **list, ni_route_nexthop_t *nh)
{
	ni_route_nexthop_t *hop;

	while ((hop = *list) != NULL)
		list = &hop->next;
	*list = nh;
}

void
ni_route_nexthop_list_destroy(ni_route_nexthop_t **list)
{
	ni_route_nexthop_t *hop;

	while ((hop = *list) != NULL) {
		*list = hop->next;
		ni_route_nexthop_free(hop);
	}
}

const ni_route_nexthop_t *
ni_route_nexthop_find_by_ifname(const ni_route_nexthop_t *head, const char *ifname)
{
	const ni_route_nexthop_t *nh;

	for (nh = head; nh;  nh = nh->next) {
		if (ni_string_eq(ifname, nh->device.name))
			return nh;
	}
	return NULL;
}

const ni_route_nexthop_t *
ni_route_nexthop_find_by_ifindex(const ni_route_nexthop_t *head, unsigned int ifindex)
{
	const ni_route_nexthop_t *nh;

	for (nh = head; nh;  nh = nh->next) {
		if (ifindex == nh->device.index)
			return nh;
	}
	return NULL;
}

const ni_route_nexthop_t *
ni_route_nexthop_find_by_device(const ni_route_nexthop_t *head, const ni_netdev_ref_t *device)
{
	const ni_route_nexthop_t *nh;

	if (device) for (nh = head; nh;  nh = nh->next) {
		if (nh->device.index && device->index) {
			if (nh->device.index == device->index)
				return nh;
		} else {
			if (ni_string_eq(nh->device.name, device->name))
				return nh;
		}
	}
	return NULL;
}

const ni_route_nexthop_t *
ni_route_nexthop_find_by_gateway(const ni_route_nexthop_t *head, const ni_sockaddr_t *gateway)
{
	const ni_route_nexthop_t *nh;

	if (gateway) for (nh = head; nh;  nh = nh->next) {
		if (ni_sockaddr_equal(gateway, &nh->gateway))
			return nh;
	}
	return NULL;
}

/*
 * ni_route_array functions
 */
ni_route_array_t *
ni_route_array_new(void)
{
	return xcalloc(1, sizeof(ni_route_array_t));
}

void
ni_route_array_free(ni_route_array_t *nra)
{
	if (nra) {
		ni_route_array_destroy(nra);
		free(nra);
	}
}

void
ni_route_array_init(ni_route_array_t *nra)
{
	memset(nra, 0, sizeof(*nra));
}

void
ni_route_array_destroy(ni_route_array_t *nra)
{
	if (nra) {
		while (nra->count) {
			nra->count--;
			ni_route_free(nra->data[nra->count]);
		}
		free(nra->data);
		nra->data = NULL;
	}
}

static ni_bool_t
ni_route_array_realloc(ni_route_array_t *nra, unsigned int newsize)
{
	ni_route_t **newdata;
	unsigned int i;

	if ((UINT_MAX - NI_ROUTE_ARRAY_CHUNK) <= newsize)
		return FALSE;

	newsize = (newsize + NI_ROUTE_ARRAY_CHUNK);
	newdata = xrealloc(nra->data, newsize * sizeof(ni_route_t *));
	if (!newdata)
		return FALSE;

	nra->data = newdata;
	for (i = nra->count; i < newsize; ++i) {
		nra->data[i] = NULL;
	}
	return TRUE;
}

ni_bool_t
ni_route_array_append(ni_route_array_t *nra, ni_route_t *rp)
{
	if (!nra || !rp)
		return FALSE;

	if ((nra->count % NI_ROUTE_ARRAY_CHUNK) == 0 &&
	    !ni_route_array_realloc(nra, nra->count))
		return FALSE;

	nra->data[nra->count++] = rp;
	return TRUE;
}

ni_route_t *
ni_route_array_remove(ni_route_array_t *nra, unsigned int index)
{
	ni_route_t *rp;

	if(!nra || index >= nra->count)
		return NULL;

	rp = nra->data[index];
	nra->count--;
	if (index < nra->count) {
		memmove(&nra->data[index], &nra->data[index + 1],
			(nra->count - index) * sizeof(ni_route_t *));
	}
	nra->data[nra->count] = NULL;

	/* Don't bother with shrinking the array. It's not worth the trouble */
	return rp;
}

ni_route_t *
ni_route_array_remove_ref(ni_route_array_t *nra, const ni_route_t *rp)
{
	unsigned int i;

	if (!nra || !rp)
		return NULL;

	for (i = 0; i < nra->count; i++) {
		if (rp == nra->data[i])
			return ni_route_array_remove(nra, i);
	}
	return NULL;
}

ni_bool_t
ni_route_array_delete(ni_route_array_t *nra, unsigned int index)
{
	ni_route_t *rp;

	if ((rp = ni_route_array_remove(nra, index))) {
		ni_route_free(rp);
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_route_array_delete_ref(ni_route_array_t *nra, const ni_route_t *rp)
{
	ni_route_t *r;

	if ((r = ni_route_array_remove_ref(nra, rp))) {
		ni_route_free(r);
		return TRUE;
	}
	return FALSE;
}

ni_route_t *
ni_route_array_get(ni_route_array_t *nra, unsigned int index)
{
	if (!nra || index >= nra->count)
		return NULL;
	return nra->data[index];
}

ni_route_t *
ni_route_array_ref(ni_route_array_t *nra, unsigned int index)
{
	return ni_route_ref(ni_route_array_get(nra, index));
}

ni_route_t *
ni_route_array_find_match(ni_route_array_t *nra, const ni_route_t *rp,
		ni_bool_t (*match)(const ni_route_t *, const ni_route_t *))
{
	ni_route_t *r;
	unsigned int i;

	if (!nra || !rp || !match)
		return NULL;

	for (i = 0; i < nra->count; ++i) {
		if (!(r = nra->data[i]))
			continue;

		if (match(r, rp))
			return r;
	}
	return NULL;
}

unsigned int
ni_route_array_find_matches(ni_route_array_t *nra, const ni_route_t *rp,
		ni_bool_t (*match)(const ni_route_t *, const ni_route_t *),
		ni_route_array_t *matches)
{
	unsigned int count;
	unsigned int i;
	ni_route_t *r;

	if (!nra || !rp || !match || !matches)
		return 0;

	count = matches->count;
	for (i = 0; i < nra->count; ++i) {
		if (!(r = nra->data[i]))
			continue;

		if (!match(r, rp))
			continue;

		/* do not add same route (another ref) multiple times */
		if (!ni_route_array_find_match(matches, r, ni_route_equal_ref))
			ni_route_array_append(matches, ni_route_ref(r));
	}
	return matches->count - count;
}

static int
ni_route_sort_cmp_rev(const ni_route_t *r1, const ni_route_t *r2)
{
	return 0 - ni_route_sort_cmp(r1, r2);
}

static int
ni_route_qsort_r_cmp(const void *_r1, const void *_r2, void *_cmp)
{
	const ni_route_t *r1 = *(const ni_route_t **)_r1;
	const ni_route_t *r2 = *(const ni_route_t **)_r2;
	ni_route_cmp_fn *rt_cmp = (ni_route_cmp_fn *)_cmp;
	return rt_cmp(r1, r2);
}

void
ni_route_array_qsort(ni_route_array_t *nra, ni_route_cmp_fn *cmp_fn)
{
	if (!nra || !nra->count || !cmp_fn)
		return;

	qsort_r(&nra->data[0], nra->count, sizeof(nra->data[0]),
			ni_route_qsort_r_cmp, cmp_fn);
}

void
ni_route_array_sort(ni_route_array_t *nra)
{
	ni_route_array_qsort(nra, ni_route_sort_cmp);
}

void
ni_route_array_sort_rev(ni_route_array_t *nra)
{
	ni_route_array_qsort(nra, ni_route_sort_cmp_rev);
}


/*
 * ni_route_table functions
 */
static inline ni_route_table_t *
do_route_table_new(unsigned int tid)
{
	ni_route_table_t *tab;

	tab = xcalloc(1, sizeof(*tab));
	if (tab)
		tab->tid = tid;
	return tab;
}

ni_route_table_t *
ni_route_table_new(unsigned int tid)
{
	if (!ni_route_is_valid_table(tid))
		return NULL;

	return do_route_table_new(tid);
}

void
ni_route_table_free(ni_route_table_t *tab)
{
	ni_route_table_clear(tab);
	free(tab);
}


void
ni_route_table_clear(ni_route_table_t *tab)
{
	if (tab) {
		ni_route_array_destroy(&tab->routes);
	}
}

/*
 * ni_route_tables list functions
 */
ni_bool_t
ni_route_tables_add_route(ni_route_table_t **list, ni_route_t *rp)
{
	ni_route_table_t *tab;

	if (rp && (tab = ni_route_tables_get(list, rp->table)))
		return ni_route_array_append(&tab->routes, rp);
	return FALSE;
}

ni_bool_t
ni_route_tables_add_routes(ni_route_table_t **list, ni_route_array_t *routes)
{
	ni_route_t *rp;
	unsigned int i;

	if (!list || !routes)
		return FALSE;

	for (i = 0; (rp = ni_route_array_ref(routes, i)); ++i) {
		if (!ni_route_tables_add_route(list, rp))
			return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_route_tables_del_route(ni_route_table_t *list, ni_route_t *rp)
{
	ni_route_table_t *tab;

	if (!rp || !(tab = ni_route_tables_find(list, rp->table)))
		return FALSE;

	return ni_route_array_delete_ref(&tab->routes, rp);
}

ni_route_t *
ni_route_tables_find_match(ni_route_table_t *list, const ni_route_t *rp,
		ni_bool_t (*match)(const ni_route_t *, const ni_route_t *))
{
	ni_route_table_t *tab;

	if (!rp || !(tab = ni_route_tables_find(list, rp->table)))
		return NULL;
	return ni_route_array_find_match(&tab->routes, rp, match);
}

unsigned int
ni_route_tables_find_matches(ni_route_table_t *list, const ni_route_t *rp,
		ni_bool_t (*match)(const ni_route_t *, const ni_route_t *),
		ni_route_array_t *matches)
{
	ni_route_table_t *tab;

	if (!rp || !(tab = ni_route_tables_find(list, rp->table)))
		return 0;

	return ni_route_array_find_matches(&tab->routes, rp, match, matches);
}

ni_route_table_t *
ni_route_tables_find(ni_route_table_t *list, unsigned int tid)
{
	ni_route_table_t *tab;

	if (!list || tid == RT_TABLE_UNSPEC || tid == RT_TABLE_MAX)
		return NULL;

	for (tab = list; tab; tab = tab->next) {
		if (tab->tid == tid)
			return tab;
	}
	return NULL;
}

ni_bool_t
ni_route_tables_empty(const ni_route_table_t *list)
{
	const ni_route_table_t *tab;

	for (tab = list; tab; tab = tab->next) {
		if (tab->routes.count)
			return FALSE;
	}
	return TRUE;
}

ni_route_table_t *
ni_route_tables_get(ni_route_table_t **list, unsigned int tid)
{
	ni_route_table_t *pos, *tab;

	if (!list || !ni_route_is_valid_table(tid))
		return NULL;

	while ((pos = *list) != NULL) {
		if (tid == pos->tid)
			return pos;
		if (tid <  pos->tid)
			break;
		list = &pos->next;
	}

	if ((tab = do_route_table_new(tid))) {
		tab->next = pos;
		*list = tab;
	}
	return tab;
}

void
ni_route_tables_destroy(ni_route_table_t **list)
{
	ni_route_table_t *tab;

	while ((tab = *list) != NULL) {
		*list = tab->next;
		ni_route_table_free(tab);
	}
}

/*
 * routing policy rules
 */
ni_rule_t *
ni_rule_new(void)
{
	ni_rule_t *rule;

	rule = xcalloc(1, sizeof(*rule));
	if (rule) {
		rule->refcount = 1;

		rule->suppress_prefixlen = -1U;
		rule->suppress_ifgroup = -1U;
	}
	return rule;
}

ni_rule_t *
ni_rule_ref(ni_rule_t *rule)
{
	if (rule) {
		ni_assert(rule->refcount);
		rule->refcount++;
	}
	return rule;
}

ni_bool_t
ni_rule_copy(ni_rule_t *dst, const ni_rule_t *src)
{
	if (!dst || !src)
		return FALSE;

#define C(x)	dst->x = src->x
	C(owner);
	C(set);
	C(seq);

	C(family);
	C(flags);
	C(pref);
	C(table);
	C(action);
	C(target);
	C(src);
	C(dst);
	C(tos);
	C(realm);
	C(fwmark);
	C(fwmask);
	C(suppress_prefixlen);
	C(suppress_ifgroup);
	C(iif.index);
	C(oif.index);
#undef C
	if (!ni_string_dup(&dst->iif.name, src->iif.name))
		return FALSE;
	if (!ni_string_dup(&dst->oif.name, src->oif.name))
		return FALSE;
	return TRUE;
}

ni_rule_t *
ni_rule_clone(const ni_rule_t *src)
{
	ni_rule_t *dst;

	if (src) {
		dst = ni_rule_new();
		if (ni_rule_copy(dst, src))
			return dst;

		ni_rule_free(dst);
	}
	return NULL;
}

static void
do_rule_free(ni_rule_t *rule)
{
	ni_netdev_ref_destroy(&rule->iif);
	ni_netdev_ref_destroy(&rule->oif);
	free(rule);
}

void
ni_rule_free(ni_rule_t *rule)
{
	if (rule) {
		ni_assert(rule->refcount);
		rule->refcount--;
		if (rule->refcount == 0)
			do_rule_free(rule);
	}
}

static int
do_rule_cmp_show(int ret, const char *what)
{
#ifdef NI_RULE_TRACE_CMP_LEVEL
	if (NI_RULE_TRACE_CMP_SHOW_ALL || ret)
	ni_debug_verbose(NI_RULE_TRACE_CMP_LEVEL, NI_TRACE_IFCONFIG,
			"rule %s cmp ==>> %d", what, ret);
#endif
	return ret;
}

static int
ni_rule_cmp_match(const ni_rule_t *r1, const ni_rule_t *r2)
{
#define do_cmp(a, b)    (a > b ? 1 : a < b ? -1 : 0)
	int ret;

	/* pref is auto assigned by the kernel, except explicitly
	 * requested by the user. compare only, when both rules
	 * have their final prefs assigned, so we can match(find)
	 * an "auto" rules against rules with final prefs.
	 */
	if ((r1->set & NI_RULE_SET_PREF) && (r2->set & NI_RULE_SET_PREF)) {
		if ((ret = do_rule_cmp_show(do_cmp(r1->pref, r2->pref), "pref")))
			return ret;
	}

	if ((ret = do_rule_cmp_show(do_cmp((r1->flags & NI_BIT(NI_RULE_INVERT)),
					   (r2->flags & NI_BIT(NI_RULE_INVERT))),
				"invert")))
		return ret;

	if ((ret = do_rule_cmp_show(do_cmp(r1->src.len, r2->src.len), "src.len")))
		return ret;
	if (r1->src.len && (ret = do_rule_cmp_show(ni_sockaddr_compare(&r1->src.addr, &r2->src.addr),
				"src.addr")))
		return ret;

	if ((ret = do_rule_cmp_show(do_cmp(r1->dst.len, r2->dst.len), "dst.len")))
		return ret;
	if (r1->dst.len && (ret = do_rule_cmp_show(ni_sockaddr_compare(&r1->dst.addr, &r2->dst.addr),
				"dst.addr")))
		return ret;

	if ((ret = do_rule_cmp_show(do_cmp(r1->tos, r2->tos), "tos")))
		return ret;

	if ((ret = do_rule_cmp_show(do_cmp(r1->fwmark, r2->fwmark), "fwmark")))
		return ret;
	if ((ret = do_rule_cmp_show(do_cmp(r1->fwmask, r2->fwmask), "fwmask")))
		return ret;

	if ((ret = do_rule_cmp_show(ni_string_cmp(r1->iif.name, r2->iif.name), "iif.name")))
		return ret;
	if ((ret = do_rule_cmp_show(ni_string_cmp(r1->oif.name, r2->oif.name), "oif.name")))
		return ret;

	return 0;
#undef  do_cmp
}

static int
ni_rule_cmp_action(const ni_rule_t *r1, const ni_rule_t *r2)
{
#define do_cmp(a, b)    (a > b ? 1 : a < b ? -1 : 0)
	int ret;

	if ((ret = do_rule_cmp_show(do_cmp(r1->action, r2->action), "action")))
		return ret;

	if ((ret = do_rule_cmp_show(do_cmp(r1->table, r2->table), "table")))
		return ret;

	if ((ret = do_rule_cmp_show(do_cmp(r1->target, r2->target), "target")))
		return ret;

	return 0;
#undef  do_cmp
}

static int
ni_rule_cmp_suppressors(const ni_rule_t *r1, const ni_rule_t *r2)
{
#define do_cmp(a, b)    (a > b ? 1 : a < b ? -1 : 0)
	int ret;

	if ((ret = do_rule_cmp_show(do_cmp(r1->suppress_prefixlen, r2->suppress_prefixlen),
					"suppress_prefixlen")))
		return ret;

	if ((ret = do_rule_cmp_show(do_cmp(r1->suppress_ifgroup, r2->suppress_ifgroup),
					"suppress_ifgroup")))
		return ret;

	return 0;
#undef	do_cmp
}

static int
ni_rule_cmp(const ni_rule_t *r1, const ni_rule_t *r2)
{
#define do_cmp(a, b)    (a > b ? 1 : a < b ? -1 : 0)
	int ret;

	if (!r1 || !r2)
		return do_rule_cmp_show(do_cmp(r1, r2), "pointer");

	if ((ret = do_rule_cmp_show(do_cmp(r1->family, r2->family), "family")))
		return ret;

	if ((ret = do_rule_cmp_show(ni_rule_cmp_match(r1, r2), "match")))
		return ret;

	if ((ret = do_rule_cmp_show(ni_rule_cmp_action(r1, r2), "action")))
		return ret;

	if ((ret = do_rule_cmp_show(ni_rule_cmp_suppressors(r1, r2), "suppressors")))
		return ret;

	return do_rule_cmp_show(0, "equal rule");
#undef do_cmp
}

ni_bool_t
ni_rule_equal(const ni_rule_t *r1, const ni_rule_t *r2)
{
#ifdef NI_RULE_TRACE_CMP_LEVEL
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;

	ni_rule_print(&out, r1);
	ni_stringbuf_puts(&out, ") =?= (");
	ni_rule_print(&out, r2);
	ni_debug_verbose(NI_RULE_TRACE_CMP_LEVEL, NI_TRACE_IFCONFIG,
			"rule cmp (%s)", out.string);
	ni_stringbuf_destroy(&out);
#endif

	return ni_rule_cmp(r1, r2) == 0;
}

ni_bool_t
ni_rule_equal_ref(const ni_rule_t *r1, const ni_rule_t *r2)
{
	return r1 == r1;
}

ni_bool_t
ni_rule_equal_match(const ni_rule_t *r1, const ni_rule_t *r2)
{
	int ret;

#define do_cmp(a, b)    (a > b ? 1 : a < b ? -1 : 0)
	if (!r1 || !r2)
		return do_rule_cmp_show(do_cmp(r1, r2), "pointer");

	if ((ret = do_rule_cmp_show(do_cmp(r1->family, r2->family), "family")))
		return ret;

	return do_rule_cmp_show(ni_rule_cmp_match(r1, r2), "match") == 0;
#undef do_cmp
}

ni_bool_t
ni_rule_equal_action(const ni_rule_t *r1, const ni_rule_t *r2)
{
	int ret;

#define do_cmp(a, b)    (a > b ? 1 : a < b ? -1 : 0)
	if (!r1 || !r2)
		return do_rule_cmp_show(do_cmp(r1, r2), "pointer");

	if ((ret = do_rule_cmp_show(do_cmp(r1->family, r2->family), "family")))
		return ret;

	return do_rule_cmp_show(ni_rule_cmp_action(r1, r2), "action") == 0;
#undef do_cmp
}

static const ni_intmap_t	ni_rule_action_names[] = {
	{ "lookup",		NI_RULE_ACTION_TO_TBL		},
	{ "goto",		NI_RULE_ACTION_GOTO		},
	{ "nop",		NI_RULE_ACTION_NOP		},
	{ "blackhole",		NI_RULE_ACTION_BLACKHOLE	},
	{ "unreachable",	NI_RULE_ACTION_UNREACHABLE	},
	{ "prohibit",		NI_RULE_ACTION_PROHIBIT		},
	{ NULL,			NI_RULE_ACTION_NONE		}
};

const char *
ni_rule_action_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_rule_action_names);
}

ni_bool_t
ni_rule_action_name_to_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_rule_action_names, type) == 0;
}

#if 0
static const ni_intmap_t	ni_rule_flag_bit_names[] = {
	{ "permanent",		NI_RULE_PERMANENT		},
	{ "invert",		NI_RULE_INVERT			},
	{ "unresolved",		NI_RULE_UNRESOLVED		},
	{ "iif-detached",	NI_RULE_IIF_DETACHED		},
	{ "oif-detached",	NI_RULE_OIF_DETACHED		},
	{ NULL,			-1U				}
};

const char *
ni_rule_flag_bit_to_name(unsigned int bit)
{
	return ni_format_uint_mapped(bit, ni_rule_flag_bit_names);
}

ni_bool_t
ni_rule_flag_name_to_bit(const char *name, unsigned int *bit)
{
	return ni_parse_uint_mapped(name, ni_rule_flag_bit_names, bit) == 0;
}
#endif

const char *
ni_rule_print(ni_stringbuf_t *out, const ni_rule_t *rule)
{
	char *tmp = NULL;
	const char *ptr;

	if (!out || !rule || rule->family == AF_UNSPEC || rule->action == NI_RULE_ACTION_NONE)
		return NULL;

	if ((ptr = ni_addrfamily_type_to_name(rule->family)))
		ni_stringbuf_printf(out, "%s", ptr);

	if (rule->set & NI_RULE_SET_PREF)
		ni_stringbuf_printf(out, " pref %u", rule->pref);
	else
		ni_stringbuf_printf(out, " pref auto");

	if (rule->flags & NI_BIT(NI_RULE_INVERT))
		ni_stringbuf_printf(out, " not", rule->pref);

	if (rule->src.len)
		ni_stringbuf_printf(out, " from %s/%u",
				ni_sockaddr_print(&rule->src.addr), rule->src.len);
	else
		ni_stringbuf_printf(out, " from all");

	if (rule->dst.len)
		ni_stringbuf_printf(out, " to %s/%u",
				ni_sockaddr_print(&rule->dst.addr), rule->dst.len);

	if (rule->iif.name)
		ni_stringbuf_printf(out, " iif %s%s", rule->iif.name,
				rule->flags & NI_BIT(NI_RULE_IIF_DETACHED) ?
				" [detached]" : "");

	if (rule->oif.name)
		ni_stringbuf_printf(out, " oif %s%s", rule->oif.name,
				rule->flags & NI_BIT(NI_RULE_OIF_DETACHED) ?
				" [detached]" : "");

	if (rule->tos)
		ni_stringbuf_printf(out, " tos 0x%02x", rule->tos);

	if (rule->fwmark || rule->fwmask) {
		if (rule->fwmask != 0xFFFFFFFF)
			ni_stringbuf_printf(out, " fwmark 0x%x/0x%x",
					rule->fwmark, rule->fwmask);
		else
			ni_stringbuf_printf(out, " fwmark 0x%x", rule->fwmark);
	}

	if (rule->realm)
		ni_stringbuf_printf(out, " realm %u", rule->realm);

	if (rule->table) {
		if ((ptr = ni_route_table_type_to_name(rule->table, &tmp)))
			ni_stringbuf_printf(out, " table %s", ptr);
		else
			ni_stringbuf_printf(out, " table %u", rule->table);
		ni_string_free(&tmp);

		if (rule->suppress_prefixlen && rule->suppress_prefixlen != -1U)
			ni_stringbuf_printf(out, " suppress-prefixlen %u",
					rule->suppress_prefixlen);

		if (rule->suppress_ifgroup && rule->suppress_ifgroup != -1U)
			ni_stringbuf_printf(out, " suppress-ifgroup %u",
					rule->suppress_prefixlen);
	}

	switch (rule->action) {
	case NI_RULE_ACTION_TO_TBL:
		break;

	case NI_RULE_ACTION_GOTO:
		ni_stringbuf_printf(out, " goto %u%s", rule->target,
				rule->flags & NI_BIT(NI_RULE_UNRESOLVED) ?
				" [unresolved]" : "");
		break;

	case NI_RULE_ACTION_NOP:
		ni_stringbuf_printf(out, " nop");
		break;

	case NI_RULE_ACTION_BLACKHOLE:
		ni_stringbuf_printf(out, " blackhole");
		break;

	case NI_RULE_ACTION_UNREACHABLE:
		ni_stringbuf_printf(out, " unreachable");
		break;

	case NI_RULE_ACTION_PROHIBIT:
		ni_stringbuf_printf(out, " prohibit");
		break;

	case RTN_NAT:
		/* NAT is gone in >2.6, but kernel ignores the
		 * map-to addr and does not reject the type...
		 */
		ni_stringbuf_printf(out, " masquerade [deprecated]");
		break;

	default:
		break;
	}

	return out ? out->string : NULL;
}

void
ni_rule_array_init(ni_rule_array_t *rules)
{
	memset(rules, 0, sizeof(*rules));
}

void
ni_rule_array_destroy(ni_rule_array_t *rules)
{
	if (rules) {
		while (rules->count) {
			rules->count--;
			ni_rule_free(rules->data[rules->count]);
		}
		free(rules->data);
		rules->data = NULL;
	}
}

ni_rule_array_t *
ni_rule_array_new(void)
{
	return xcalloc(1, sizeof(ni_rule_array_t));
}

void
ni_rule_array_free(ni_rule_array_t *rules)
{
	ni_rule_array_destroy(rules);
	free(rules);
}

unsigned int
ni_rule_array_index(const ni_rule_array_t *rules, const ni_rule_t *rule)
{
	unsigned int i;
	ni_rule_t *r;

	if (rules) {
		for (i = 0; i < rules->count; ++i) {
			r = rules->data[i];
			if (r == rule)
				return i;
		}
	}
	return -1U;
}

static ni_bool_t
ni_rule_array_realloc(ni_rule_array_t *rules, unsigned int newsize)
{
	ni_rule_t **newdata;
	unsigned int i;

	if ((UINT_MAX - NI_RULE_ARRAY_CHUNK) <= newsize)
		return FALSE;

	newsize = (newsize + NI_RULE_ARRAY_CHUNK);
	newdata = xrealloc(rules->data, newsize * sizeof(ni_rule_t *));
	if (!newdata)
		return FALSE;

	rules->data = newdata;
	for (i = rules->count; i < newsize; ++i)
		rules->data[i] = NULL;

	return TRUE;
}

ni_bool_t
ni_rule_array_append(ni_rule_array_t *rules, ni_rule_t *rule)
{
	if (!rules || !rule)
		return FALSE;

	if ((rules->count % NI_RULE_ARRAY_CHUNK) == 0 &&
	    !ni_rule_array_realloc(rules, rules->count))
		return FALSE;

	rules->data[rules->count++] = rule;
	return TRUE;
}

ni_bool_t
ni_rule_array_insert(ni_rule_array_t *rules, unsigned int index, ni_rule_t *rule)
{
	if (!rules || !rule)
		return FALSE;

	if (index >= rules->count)
		return ni_rule_array_append(rules, rule);

	if ((rules->count % NI_RULE_ARRAY_CHUNK) == 0 &&
	    !ni_rule_array_realloc(rules, rules->count))
		return FALSE;

	memmove(&rules->data[index + 1], &rules->data[index],
		(rules->count - index) * sizeof(ni_rule_t *));
	rules->data[index] = rule;
	rules->count++;
	return TRUE;
}

ni_bool_t
ni_rule_array_delete(ni_rule_array_t *rules, unsigned int index)
{
	ni_rule_t *rule;

	if ((rule = ni_rule_array_remove(rules, index))) {
		ni_rule_free(rule);
		return TRUE;
	}
	return FALSE;
}

ni_rule_t *
ni_rule_array_remove(ni_rule_array_t *rules, unsigned int index)
{
	ni_rule_t *rule;

	if (!rules || index >= rules->count)
		return NULL;

	rule = rules->data[index];
	rules->count--;
	if (index < rules->count) {
		memmove(&rules->data[index], &rules->data[index + 1],
			(rules->count - index) * sizeof(ni_rule_t *));
	}
	rules->data[rules->count] = NULL;

	/* Don't bother with shrinking the array. It's not worth the trouble */
	return rule;
}

ni_rule_t *
ni_rule_array_get(ni_rule_array_t *rules, unsigned int index)
{
	if (!rules || index >= rules->count)
		return NULL;
	return rules->data[index];
}

ni_rule_t *
ni_rule_array_find_match(const ni_rule_array_t *rules, const ni_rule_t *rule,
		ni_bool_t (*match)(const ni_rule_t *, const ni_rule_t *))
{
	unsigned int i;
	ni_rule_t *r;

	if (!rules || !rule || !match)
		return NULL;

	for (i = 0; i < rules->count; ++i) {
		r = rules->data[i];
		if (r && match(r, rule))
			return r;
	}

	return NULL;
}

unsigned int
ni_rule_array_find_matches(const ni_rule_array_t *rules, const ni_rule_t *rule,
		ni_bool_t (*match)(const ni_rule_t *, const ni_rule_t *),
		ni_rule_array_t *matches)
{
	unsigned int i, count = 0;
	ni_rule_t *r;

	if (!rules || !rule || !match || !matches)
		return count;

	for (i = 0; i < rules->count; ++i) {
		r = rules->data[i];
		if (!r || !match(r, rule))
			continue;

		if (ni_rule_array_index(matches, r) != -1U)
			continue;

		if (ni_rule_array_append(matches, ni_rule_ref(r)))
			count++;
	}

	return count;
}

