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
#include <netlink/netlink.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/route.h>
#include "util_priv.h"


/*
 * ni_route functions
 */
ni_route_t *
ni_route_new(void)
{
	ni_route_t *rp;

	rp = xcalloc(1, sizeof(ni_route_t));
	return rp;
}

ni_route_t *
ni_route_create(unsigned int prefixlen, const ni_sockaddr_t *dest,
		const ni_sockaddr_t *gw, ni_route_t **list)
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
	rp->scope = RT_SCOPE_UNIVERSE;
	rp->protocol = RTPROT_BOOT;
	rp->table = RT_TABLE_MAIN;

	if (list)
		ni_route_list_append(list, rp);

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
	C(source);

	C(type);
	C(scope);
	C(protocol);
	C(table);
	C(tos);
	C(priority);
	C(mtu);
	C(mtu_lock);
	C(advmss);
	C(rtt);
	C(rttvar);
	C(window);
	C(cwnd);
	C(initcwnd);
	C(initrwnd);
	C(ssthresh);
	C(realm);
	C(rto_min);
	C(hoplimit);
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


void
ni_route_free(ni_route_t *rp)
{
	ni_route_nexthop_list_destroy(&rp->nh.next);
	ni_route_nexthop_destroy(&rp->nh);

	free(rp);
}

ni_bool_t
ni_route_equal(const ni_route_t *r1, const ni_route_t *r2)
{
	const ni_route_nexthop_t *nh1, *nh2;

	if (r1->prefixlen != r2->prefixlen
	 || !ni_sockaddr_equal(&r1->destination, &r2->destination))
		return FALSE;

	if (r1->priority != r2->priority)
		return FALSE;

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

const char *
ni_route_print(ni_stringbuf_t *out, const ni_route_t *rp)
{
	const ni_route_nexthop_t *nh;
	const char *ptr;

	if (!out || !rp || rp->family == AF_UNSPEC ||
	    rp->destination.ss_family != rp->family)
		return NULL;

	if ((ptr = ni_addrfamily_type_to_name(rp->family))) {
		ni_stringbuf_printf(out, "%s ", ptr);
	}
	if (rp->type != RTN_UNSPEC &&
	    (ptr = ni_route_type_type_to_name(rp->type))) {
		ni_stringbuf_printf(out, "%s ", ptr);
	}

	ni_stringbuf_printf(out, "%s/%u",
		ni_sockaddr_print(&rp->destination), rp->prefixlen);

	for (nh = &rp->nh; nh; nh = nh->next) {
		if (rp->nh.next) {
			ni_stringbuf_printf(out, " nexthop");
		}
		if (ni_sockaddr_is_specified(&nh->gateway)) {
			ni_stringbuf_printf(out, " via %s",
					ni_sockaddr_print(&nh->gateway));
		}
		if (nh->device.name) {
			ni_stringbuf_printf(out, " dev %s", nh->device.name);
		}
		if (!rp->nh.next)
			continue;

		if (nh->weight) {
			ni_stringbuf_printf(out, " weight %u", nh->weight);
		}
		if (nh->flags & RTNH_F_DEAD) {
			ni_stringbuf_printf(out, " dead");
		}
		if (nh->flags & RTNH_F_PERVASIVE) {
			ni_stringbuf_printf(out, " pervasive");
		}
		if (nh->flags & RTNH_F_ONLINK) {
			ni_stringbuf_printf(out, " onlink");
		}
	}

	if (rp->table != RT_TABLE_UNSPEC &&
	    rp->table != RT_TABLE_MAIN &&
	    (ptr = ni_route_table_type_to_name(rp->table))) {
		ni_stringbuf_printf(out, " table %s", ptr);
	}
	if (rp->protocol != RTPROT_UNSPEC &&
	    rp->protocol != RTPROT_BOOT &&
	    (ptr = ni_route_protocol_type_to_name(rp->protocol))) {
		ni_stringbuf_printf(out, " protocol %s", ptr);
	}
	if (rp->scope != RT_SCOPE_UNIVERSE &&
	    (ptr = ni_route_scope_type_to_name(rp->scope))) {
		ni_stringbuf_printf(out, " scope %s", ptr);
	}
	if (ni_sockaddr_is_specified(&rp->source)) {
		ni_stringbuf_printf(out, " src %s",
				ni_sockaddr_print(&rp->source));
	}
	if (rp->priority > 0) {
		ni_stringbuf_printf(out, " priority %u", rp->priority);
	}
	if (rp->tos > 0) {
		/* TODO: names */
		ni_stringbuf_printf(out, " tos 0x%02x", rp->tos);
	}
	if (rp->mtu > 0) {
		ni_stringbuf_printf(out, " mtu %u", rp->mtu);
		if (rp->mtu_lock)
			ni_stringbuf_printf(out, " lock");
	}
	if (rp->realm > 0) {
		/* TODO: names */
		ni_stringbuf_printf(out, " realm %u", rp->realm);
	}
	if (rp->advmss > 0) {
		ni_stringbuf_printf(out, " advmss %u", rp->advmss);
	}
	if (rp->rtt > 0) {
		ni_stringbuf_printf(out, " rtt %u", rp->rtt);
	}
	if (rp->rttvar > 0) {
		ni_stringbuf_printf(out, " rttvar %u", rp->rttvar);
	}
	if (rp->window > 0) {
		ni_stringbuf_printf(out, " window %u", rp->window);
	}
	if (rp->cwnd > 0) {
		ni_stringbuf_printf(out, " cwnd %u", rp->cwnd);
	}
	if (rp->initcwnd > 0) {
		ni_stringbuf_printf(out, " initcwnd %u", rp->initcwnd);
	}
	if (rp->initrwnd > 0) {
		ni_stringbuf_printf(out, " initrwnd %u", rp->initrwnd);
	}
	if (rp->ssthresh > 0) {
		ni_stringbuf_printf(out, " ssthresh %u", rp->ssthresh);
	}
	if (rp->rto_min > 0) {
		ni_stringbuf_printf(out, " rto_min %u", rp->rto_min);
	}
	if (rp->hoplimit > 0) {
		ni_stringbuf_printf(out, " hoplimit %u", rp->hoplimit);
	}
	if (rp->reordering > 0) {
		ni_stringbuf_printf(out, " reordering %u", rp->reordering);
	}

	return out->string;
}

/*
 * ni_route list functions
 */
void
ni_route_list_destroy(ni_route_t **list)
{
	ni_route_t *rp;

	while ((rp = *list) != NULL) {
		*list = rp->next;
		ni_route_free(rp);
	}
}

void
ni_route_list_append(ni_route_t **list, ni_route_t *new_route)
{
	ni_route_t *rp;

	while ((rp = *list) != NULL)
		list = &rp->next;
	*list = new_route;
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
		dst->device.index = src->device.index;
		if (src->device.name)
			ni_string_dup(&dst->device.name, src->device.name);
		if (src->device.dev) /* never used/set, but ... */
			dst->device.dev = ni_netdev_get(src->device.dev);
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

