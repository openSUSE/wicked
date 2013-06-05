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
	C(metric);
	C(mtu);
	C(mtu_lock);
	C(priority);
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
ni_route_print(const ni_route_t *rp)
{
	char *dest, destbuf[128], gwbuf[128];
	static char abuf[256];

	dest = destbuf;
	if (rp->prefixlen == 0) {
		dest = "default";
	} else {
		ni_sockaddr_format(&rp->destination, destbuf, sizeof(destbuf));
	}

	if (rp->nh.gateway.ss_family) {
		snprintf(abuf, sizeof(abuf), "%s via %s", dest,
				ni_sockaddr_format(&rp->nh.gateway, gwbuf, sizeof(gwbuf)));
	} else {
		snprintf(abuf, sizeof(abuf), "%s", dest);
	}
	return abuf;
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

