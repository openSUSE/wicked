/*
 * Handling of ip routing.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 * Copyright (C) 2012-2013 Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <netlink/netlink.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/route.h>
#include "util_priv.h"

#define NI_ROUTE_ARRAY_CHUNK		16


/*
 * Names for route type
 */
static const ni_intmap_t	__ni_route_type_names[] = {
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
static const ni_intmap_t	__ni_route_table_names[] = {
	{ "compat",		RT_TABLE_COMPAT		},
	{ "default",		RT_TABLE_DEFAULT	},
	{ "main",		RT_TABLE_MAIN		},
	{ "local",		RT_TABLE_LOCAL		},

	{ NULL,			RT_TABLE_UNSPEC		},
};

/*
 * Names for route scope
 */
static const ni_intmap_t	__ni_route_scope_names[] = {
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
static const ni_intmap_t	__ni_route_protocol_names[] = {
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
static const ni_intmap_t	__ni_route_flags_bits[] = {
	{ "notify",		8  /* RTM_F_NOTIFY   */	},
	{ "cloned",		9  /* RTM_F_CLONED   */	},
	{ "equalize",		10 /* RTM_F_EQUALIZE */	},
	{ "prefix",		11 /* RTM_F_PREFIX   */	},

	{ NULL,			0			}
};
static const ni_intmap_t	__ni_route_nh_flags_bits[] = {
	{ "dead",		0  /* RTNH_F_DEAD     */},
	{ "pervasive",		1  /* RTNH_F_PERVASIVE*/},
	{ "online",		2  /* RTNH_F_ONLINK   */},

	{ NULL,			0			}
};
static const ni_intmap_t	__ni_route_mxlock_bits[] = {
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

	rp = ni_route_new();
	rp->family = af;
	rp->prefixlen = prefixlen;
	rp->destination = *dest;
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
	ni_route_nexthop_t *nh;
	const ni_route_nexthop_t *srcnh;

	rp = ni_route_new();

#define C(x)	rp->x = src->x
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
#undef C

	for (nh = &rp->nh, srcnh = &src->nh; srcnh; srcnh = srcnh->next, nh = nh->next) {
		ni_route_nexthop_copy(nh, srcnh);
		if (srcnh->next) {
			nh->next = ni_route_nexthop_new();
		}
	}

	return rp;
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
__ni_route_free(ni_route_t *rp)
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
		__ni_route_free(rp);
	}
}

ni_bool_t
ni_route_equal_destination(const ni_route_t *r1, const ni_route_t *r2)
{
	if (r1->family != r2->family)
		return FALSE;

	if (r1->prefixlen != r2->prefixlen)
		return FALSE;

	if (r1->prefixlen && !ni_sockaddr_equal(&r1->destination, &r2->destination))
		return FALSE;

	if (r1->family == AF_INET) {
		/* ipv4 matches routing entries by [prefix, tos, priority] */
		if (r1->tos != r2->tos || r1->priority != r2->priority)
			return FALSE;
	} else
	if (r1->family == AF_INET6) {
		/* ipv6 matches routing entries by [dst pfx, src pfx, priority];
		 * we don't support source routes yet. */
		if (r1->priority != r2->priority)
			return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_route_equal_gateways(const ni_route_t *r1, const ni_route_t *r2)
{
	const ni_route_nexthop_t *nh1, *nh2;

	nh1 = &r1->nh;
	nh2 = &r2->nh;
	while (nh1 && nh2) {
		if (!ni_sockaddr_equal(&nh1->gateway, &nh2->gateway))
			return FALSE;
		nh1 = nh1->next;
		nh2 = nh2->next;
	}
	return nh1 == nh2;
}

ni_bool_t
ni_route_equal(const ni_route_t *r1, const ni_route_t *r2)
{

	if (!ni_route_equal_destination(r1, r2))
		return FALSE;
	return ni_route_equal_gateways(r1, r2);
}

const char *
__ni_route_print_flags(ni_stringbuf_t *out, unsigned int flags,
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
			ni_stringbuf_printf(out, " dev %s", nh->device.name);
		} else if ((dev = ni_netdev_by_index(nc, nh->device.index))) {
			ni_stringbuf_printf(out, " dev %s", dev->name);
		} else /* if (nh->device.index) */ {
			ni_stringbuf_printf(out, " dev #%u", nh->device.index);
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
			__ni_route_print_flags(out, nh->flags,
					__ni_route_nh_flags_bits,
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
		if ((ptr = ni_route_table_type_to_name(rp->table))) {
			ni_stringbuf_printf(out, " table %s", ptr);
		} else {
			ni_stringbuf_printf(out, " table %u", rp->table);
		}
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
		__ni_route_print_flags(out, rp->flags,
				__ni_route_flags_bits, " flags ", "|");
	}
	if (ni_sockaddr_is_specified(&rp->pref_src)) {
		ni_stringbuf_printf(out, " pref-src %s",
				ni_sockaddr_print(&rp->pref_src));
	}
	if (rp->priority > 0) {
		ni_stringbuf_printf(out, " priority %u", rp->priority);
	}
	if (rp->realm > 0) {
		ni_stringbuf_printf(out, " realm %u", nh->realm);
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
	return ni_format_uint_maybe_mapped(type, __ni_route_type_names);
}

const char *
ni_route_table_type_to_name(unsigned int type)
{
	return ni_format_uint_maybe_mapped(type, __ni_route_table_names);
}

const char *
ni_route_scope_type_to_name(unsigned int type)
{
	return ni_format_uint_maybe_mapped(type, __ni_route_scope_names);
}

const char *
ni_route_protocol_type_to_name(unsigned int type)
{
	return ni_format_uint_maybe_mapped(type, __ni_route_protocol_names);
}

const char *
ni_route_flag_bit_to_name(unsigned int bit)
{
	return ni_format_uint_mapped(bit, __ni_route_flags_bits);
}

const char *
ni_route_nh_flag_bit_to_name(unsigned int bit)
{
	return ni_format_uint_mapped(bit, __ni_route_nh_flags_bits);
}

const char *
ni_route_metrics_lock_bit_to_name(unsigned int bit)
{
	return ni_format_uint_mapped(bit, __ni_route_mxlock_bits);
}

ni_bool_t
ni_route_type_name_to_type(const char *name, unsigned int *type)
{
	unsigned int value;

	if (!type || !name)
		return FALSE;

	if (ni_parse_uint_maybe_mapped(name, __ni_route_type_names, &value, 10) < 0)
		return FALSE;

	*type = value;
	return TRUE;
}

ni_bool_t
ni_route_table_name_to_type(const char *name, unsigned int *table)
{
	unsigned int value;

	if (!table || !name)
		return FALSE;

	if (ni_parse_uint_maybe_mapped(name, __ni_route_table_names, &value, 10) < 0)
		return FALSE;

	*table = value;
	return TRUE;
}

ni_bool_t
ni_route_scope_name_to_type(const char *name, unsigned int *scope)
{
	unsigned int value;

	if (!scope || !name)
		return FALSE;

	if (ni_parse_uint_maybe_mapped(name, __ni_route_scope_names, &value, 10) < 0)
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

	if (ni_parse_uint_maybe_mapped(name, __ni_route_protocol_names, &value, 10) < 0)
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
	for (map = __ni_route_flags_bits; map->name; ++map) {
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
	for (map = __ni_route_nh_flags_bits; map->name; ++map) {
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

	for (map = __ni_route_mxlock_bits; map->name; ++map) {
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

	if (!lock || ni_parse_uint_mapped(name, __ni_route_mxlock_bits, &bit) < 0)
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
			if (rp->nh.gateway.ss_family == AF_UNSPEC)
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

void
ni_route_nexthop_copy(ni_route_nexthop_t *dst, const ni_route_nexthop_t *src)
{
	if (src && dst) {
		dst->gateway = src->gateway;
		dst->weight  = src->weight;
		dst->flags   = src->flags;
		dst->realm   = src->realm;
		dst->device.index = src->device.index;
		if (src->device.name)
			ni_string_dup(&dst->device.name, src->device.name);
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

static void
__ni_route_array_realloc(ni_route_array_t *nra, unsigned int newsize)
{
	ni_route_t **newdata;
	unsigned int i;

	newsize = (newsize + NI_ROUTE_ARRAY_CHUNK);
	newdata = xrealloc(nra->data, newsize * sizeof(ni_route_t *));

	nra->data = newdata;
	for (i = nra->count; i < newsize; ++i) {
		nra->data[i] = NULL;
	}
}

ni_bool_t
ni_route_array_append(ni_route_array_t *nra, ni_route_t *rp)
{
	if (!nra || !rp)
		return FALSE;

	/* Hmm.. should we sort them here? */
	if ((nra->count % NI_ROUTE_ARRAY_CHUNK) == 0)
		__ni_route_array_realloc(nra, nra->count);

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

/*
 * ni_route_table functions
 */
static inline ni_route_table_t *
__ni_route_table_new(unsigned int tid)
{
	ni_route_table_t *tab;

	tab = xcalloc(1, sizeof(*tab));
	tab->tid = tid;
	return tab;
}

ni_route_table_t *
ni_route_table_new(unsigned int tid)
{
	if (!ni_route_is_valid_table(tid))
		return NULL;

	return __ni_route_table_new(tid);
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

	if (rp && (tab = ni_route_tables_get(list, rp->table))) {
		return ni_route_array_append(&tab->routes, rp);
	}
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

ni_route_table_t *
ni_route_tables_get(ni_route_table_t **list, unsigned int tid)
{
	ni_route_table_t *pos, *tab;

	if (!list || tid == RT_TABLE_UNSPEC || tid == RT_TABLE_MAX)
		return NULL;

	while ((pos = *list) != NULL) {
		if (tid == pos->tid)
			return pos;
		if (tid <  pos->tid)
			break;
		list = &pos->next;
	}

	if ((tab = __ni_route_table_new(tid))) {
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

