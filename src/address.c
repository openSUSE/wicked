/*
 * Handling of network and link layer addresses.
 * Currently, just about formatting addresses for display.
 *
 * Copyright (C) 2009 Olaf Kirch <okir@suse.de>
 */

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/if_tr.h>
#include <linux/if_infiniband.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include "netinfo_priv.h"


#define offsetof(type, member) \
	((unsigned long) &(((type *) NULL)->member))

static const unsigned char *__ni_address_data(const ni_sockaddr_t *, unsigned int *);

ni_address_t *
ni_address_new(ni_interface_t *ifp, int af, unsigned int prefix_len, const ni_sockaddr_t *local_addr)
{
	return __ni_address_new(&ifp->addrs, af, prefix_len, local_addr);
}

ni_address_t *
__ni_address_new(ni_address_t **list_head, int af, unsigned int prefix_len, const ni_sockaddr_t *local_addr)
{
	ni_address_t *ap, **tail;

	assert(!local_addr || local_addr->ss_family == af);

	tail = list_head;
	while ((ap = *tail) != NULL)
		tail = &ap->next;

	ap = calloc(1, sizeof(*ap));
	ap->config_method = NI_ADDRCONF_STATIC;
	ap->family = af;
	ap->prefixlen = prefix_len;
	ap->scope = -1;
	if (local_addr)
		ap->local_addr = *local_addr;

	/* FIXME: is this the right place to do this? */
	if (af == AF_INET && local_addr) {
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *) &ap->bcast_addr;
		memcpy(sin, local_addr, sizeof(*sin));
		sin->sin_addr.s_addr |= htonl(0xFFFFFFFFUL >> prefix_len);
	}

	/* FIXME: we need to do this as long as we don't track the IPv6
	 * prefixes received via RAs. */
	if (af == AF_INET6) {
		const unsigned char *data;
		unsigned int len;

		data = __ni_address_data(&ap->local_addr, &len);
		if (data && data[0] == 0xFE && data[1] == 0x80) {
			/* Link-local; always autoconf */
			ap->config_method = NI_ADDRCONF_AUTOCONF;
		}
	}

	*tail = ap;
	return ap;
}

ni_address_t *
ni_address_clone(const ni_address_t *src)
{
	ni_address_t *dst;

	if (!src)
		return NULL;

	dst = malloc(sizeof(*dst));
	memcpy(dst, src, sizeof(*src));
	return dst;
}

void
ni_address_free(ni_address_t *ap)
{
	free(ap);
}

void
ni_address_list_append(ni_address_t **list, ni_address_t *ap)
{
	while (*list)
		list = &(*list)->next;
	*list = ap;
}

int
__ni_address_list_dedup(ni_address_t **list)
{
	ni_address_t **pos, *ap;
	ni_address_t **pos2, *ap2;

	for (pos = list; (ap = *pos) != NULL; pos = &ap->next) {
		for (pos2 = &ap->next; (ap2 = *pos2) != NULL; ) {
			if (ni_address_equal(&ap->local_addr, &ap2->local_addr)) {
				if (memcmp(ap, ap2, sizeof(*ap)) != 0)
					return -1; // duplicate address
				*pos2 = ap2->next;
				ni_address_free(ap2);
			} else {
				pos2 = &ap2->next;
			}
		}
	}

	return 0;
}

ni_address_t *
__ni_address_list_find(ni_address_t *list, const ni_sockaddr_t *addr)
{
	ni_address_t *ap;

	for (ap = list; ap != NULL; ap = ap->next) {
		if (ni_address_equal(&ap->local_addr, addr))
			return ap;
	}
	return NULL;
}

void
ni_address_list_destroy(ni_address_t **list)
{
	ni_address_t *ap;

	while ((ap = *list) != NULL) {
		*list = ap->next;
		ni_address_free(ap);
	}
}

ni_address_t *
__ni_address_list_clone(const ni_address_t *src)
{
	ni_address_t *dst = NULL, **tail = &dst;

	while (src) {
		*tail = ni_address_clone(src);
		tail = &(*tail)->next;
		src = src->next;
	}
	return dst;
}

int
__ni_address_info(int af, unsigned int *offset, unsigned int *len)
{
	switch (af) {
	case AF_INET:
		*offset = offsetof(struct sockaddr_in, sin_addr);
		*len = 4;
		return 1;
	case AF_INET6:
		*offset = offsetof(struct sockaddr_in6, sin6_addr);
		*len = 16;
		return 1;
	}

	return 0;
}

const unsigned char *
__ni_address_data(const ni_sockaddr_t *ss, unsigned int *len)
{
	unsigned int offset;

	*len = 0;
	if (ss == NULL)
		return NULL;
	if (!__ni_address_info(ss->ss_family, &offset, len))
		return NULL;

	return ((const unsigned char *) ss) + offset;
}

unsigned int
ni_address_length(int af)
{
	switch (af) {
	case AF_INET:
		return 4;
	case AF_INET6:
		return 16;
	}
	return 0;
}

int
ni_address_prefix_match(unsigned int prefix_bits, const ni_sockaddr_t *laddr, const ni_sockaddr_t *gw)
{
	const unsigned char *laddr_ptr, *gw_ptr;
	unsigned int offset = 0, len;
	unsigned int cc;

	laddr_ptr = __ni_address_data(laddr, &len);
	gw_ptr = __ni_address_data(gw, &len);
	if (!laddr_ptr || !gw_ptr || laddr->ss_family != gw->ss_family)
		return 0;

	if (prefix_bits > (len * 8))
		prefix_bits = len * 8;

	if (prefix_bits > 8) {
		if (memcmp(laddr_ptr, gw_ptr, prefix_bits / 8))
			return 0;
		offset = prefix_bits / 8;
		prefix_bits = prefix_bits % 8;
	}

	/* If the prefix length is not a multiple of 8, we need to check the
	 * top N bits of the next octet. */
	if (prefix_bits != 0) {
		cc = laddr_ptr[offset] ^ gw_ptr[offset];
		if ((0xFF00 & (cc << prefix_bits)) != 0)
			return 0;
	}

	return 1;
}

int
ni_address_can_reach(const ni_address_t *laddr, const ni_sockaddr_t *gw)
{
	if (laddr->family != gw->ss_family)
		return 0;

	/* if (laddr->peer_addr.ss_family != AF_UNSPEC) { ... } */
	return ni_address_prefix_match(laddr->prefixlen, &laddr->local_addr, gw);
}

int
ni_address_is_loopback(const ni_address_t *laddr)
{
	if (laddr->family == AF_INET
	 && laddr->local_addr.ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *) &laddr->local_addr;
		uint32_t inaddr;

		inaddr = ntohl(sin->sin_addr.s_addr);
		return (inaddr >> 24) == IN_LOOPBACKNET;
	}

	return 0;
}

int
ni_address_equal(const ni_sockaddr_t *ss1, const ni_sockaddr_t *ss2)
{
	const unsigned char *ap1, *ap2;
	unsigned int len;

	if (ss1->ss_family != ss2->ss_family)
		return 0;
	if (ss1->ss_family == AF_UNSPEC)
		return 1;

	ap1 = __ni_address_data(ss1, &len);
	ap2 = __ni_address_data(ss2, &len);
	if (!ap1 || !ap2 || ss1->ss_family != ss2->ss_family)
		return 0;

	return !memcmp(ap1, ap2, len);
}

int
ni_address_probably_dynamic(const ni_address_t *ap)
{
	const unsigned char *addr;
	unsigned int len;

	switch (ap->family) {
	case AF_INET6:
		/* For IPv6 with static configuration, consider all link-local
		 * prefixes as dynamic.
		 */
		if ((addr = __ni_address_data(&ap->local_addr, &len)) != NULL)
			return addr[0] == 0xFE && addr[1] == 0x80;
		break;

	case AF_INET:
		/* Consider all IPv4 zeroconf addresses (169.254/24) as autoconf */
		if ((addr = __ni_address_data(&ap->local_addr, &len)) != NULL)
			return addr[0] == 169 && addr[1] == 254;
		break;
	}

	return 0;
}

int
ni_address_format(const ni_sockaddr_t *ss, char *abuf, size_t buflen)
{
	switch (ss->ss_family) {
	case AF_INET:
		inet_ntop(AF_INET, &((struct sockaddr_in *) ss)->sin_addr,
				abuf, buflen);
		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *) ss)->sin6_addr,
				abuf, buflen);
		break;

	default:
		snprintf(abuf, buflen, "Unknown AF %d", ss->ss_family);
		return 0;
	}

	return 0;

}

const char *
ni_address_print(const ni_sockaddr_t *ss)
{
	static char abuf[128];

	if (ni_address_format(ss, abuf, sizeof(abuf)) < 0)
		return NULL;
	return abuf;
}

static int
__ni_parse_ipv4shorthand(ni_sockaddr_t *ss, const char *string)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) ss;
	uint32_t addr = 0;
	unsigned int i;

	for (i = 0; i < 4; ++i) {
		unsigned long octet;

		addr <<= 8;
		if (*string) {
			octet = strtoul(string, (char **) &string, 10);
			if (octet > 255)
				return -1;
			addr |= octet;
			if (*string) {
				if (*string != '.')
					return -1;
				++string;
			}
		}
	}

	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(addr);
	return 0;
}

int
ni_address_parse(ni_sockaddr_t *ss, const char *string, int af)
{
	memset(ss, 0, sizeof(*ss));

	if (!string || !*string)
		return -1;

	if ((af == AF_UNSPEC || af == AF_INET6)
	 && inet_pton(AF_INET6, string, &((struct sockaddr_in6 *) ss)->sin6_addr) == 1) {
		ss->ss_family = AF_INET6;
		return 0;
	}
	if ((af == AF_UNSPEC || af == AF_INET)
	 && inet_pton(AF_INET, string, &((struct sockaddr_in *) ss)->sin_addr) == 1) {
		ss->ss_family = AF_INET;
		return 0;
	}

	/* This may be something like "127" or "10.2", which are sometimes used
	 * as shorthand in ifcfg and ifroute files */
	if ((af == AF_UNSPEC || af == AF_INET)
	 && isdigit(string[0]) && !strchr(string, ':')) {
		if (__ni_parse_ipv4shorthand(ss, string) >= 0)
			return 0;
	}

	return -1;
}

unsigned int
ni_netmask_bits(const ni_sockaddr_t *mask)
{
	unsigned int	offset, len, i, bits = 0;
	unsigned char	*raw;

	if (!__ni_address_info(mask->ss_family, &offset, &len))
		return 0;

	raw = &((unsigned char *) mask)[offset];
	for (i = 0; i < len; ++i) {
		unsigned char cc = *raw++;

		if (cc == 0xFF) {
			bits += 8;
		} else {
			while (cc & 0x80) {
				bits++;
				cc <<= 1;
			}
			break;
		}
	}

	return bits;
}

int
ni_build_netmask(int af, unsigned int prefix_len, ni_sockaddr_t *mask)
{
	unsigned int	offset, len, i, bits;
	unsigned char	*raw;

	memset(mask, 0, sizeof(*mask));
	mask->ss_family = af;

	if (!__ni_address_info(af, &offset, &len))
		return -1;

	raw = &((unsigned char *) mask)[offset];
	for (i = 0; i < len && prefix_len != 0; ++i) {
		bits = (prefix_len < 8)? prefix_len : 8;
		*raw++ = 0xFF00 >> bits;
		prefix_len -= bits;
	}

	return prefix_len? -1 : 0;
}

int
ni_link_address_format(const ni_hwaddr_t *hwa, char *abuf, size_t len)
{
	unsigned int i, j;

	switch (hwa->type) {
	case NI_IFTYPE_TUNNEL:
	case NI_IFTYPE_SIT:
	case NI_IFTYPE_GRE:
		if (inet_ntop(AF_INET, hwa->data, abuf, len) == 0)
			return -1;
		return 0;

	case NI_IFTYPE_TUNNEL6:
		if (inet_ntop(AF_INET6, hwa->data, abuf, len) == 0)
			return -1;
		return 0;

	default:
		for (i = j = 0; i < hwa->len; ++i) {
			if (j + 4 >= len)
				break;
			if (i)
				abuf[j++] = ':';
			snprintf(abuf + j, len - j, "%02x", hwa->data[i]);
			j += 2;
		}
		break;
	}

	return 0;
}

int
ni_link_address_parse(ni_hwaddr_t *hwa, unsigned int type, const char *string)
{
	unsigned int len = 0, octet;

	memset(hwa, 0, sizeof(*hwa));
	switch (type) {
	case NI_IFTYPE_TUNNEL:
	case NI_IFTYPE_SIT:
	case NI_IFTYPE_GRE:
	case NI_IFTYPE_TUNNEL6:
		error("%s: setting tunnel addrs not yet implemented",
				__FUNCTION__);
		return -1;
	}

	/* Default format is aa:bb:cc:.. with hex octets */
	while (1) {
		octet = strtoul(string, (char **) &string, 16);
		if (octet > 255)
			return -1;
		hwa->data[len++] = octet;
		if (*string == '\0')
			break;
		if (*string != ':')
			return -1;
		++string;
		if (len >= NI_MAXHWADDRLEN)
			return -1;
	}

	hwa->type = type;
	hwa->len = len;
	return 0;
}

const char *
ni_link_address_print(const ni_hwaddr_t *hwa)
{
	static char abuf[128];

	if (ni_link_address_format(hwa, abuf, sizeof(abuf)) < 0)
		return NULL;
	return abuf;
}

int
ni_link_address_equal(const ni_hwaddr_t *hwa1, const ni_hwaddr_t *hwa2)
{
	if (hwa1->type != hwa2->type
	 || hwa1->len != hwa2->len)
		return 0;
	return !memcmp(hwa1->data, hwa2->data, hwa1->len);
}

unsigned int
ni_link_address_length(int iftype)
{
	switch (iftype) {
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_VLAN:
	case NI_IFTYPE_BRIDGE:
		return ETH_ALEN;

	case NI_IFTYPE_TOKENRING:
		return TR_ALEN;

	case NI_IFTYPE_FIREWIRE:
		return 8;	/* EUI64 */

	case NI_IFTYPE_INFINIBAND:
		return INFINIBAND_ALEN;
	}

	return 0;
}

int
ni_link_address_get_broadcast(int iftype, ni_hwaddr_t *hwa)
{
	hwa->type = iftype;
	hwa->len = ni_link_address_length(iftype);
	if (hwa->len == 0)
		return -1;

	if (iftype == NI_IFTYPE_INFINIBAND) {
		/* Broadcast address for IPoIB */
		static const uint8_t ipoib_bcast_addr[] = {
			0x00, 0xff, 0xff, 0xff,
			0xff, 0x12, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
		};
		memcpy(hwa->data, ipoib_bcast_addr, hwa->len);
	} else {
		memset(hwa->data, 0xff, hwa->len);
	}

	return 0;
}

ni_route_t *
__ni_route_new(ni_route_t **list, unsigned int prefixlen, const ni_sockaddr_t *dest, const ni_sockaddr_t *gw)
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
			error("Cannot add route - destination and gw are both 0/0");
			return NULL;
		}
	} else {
		if (af == AF_UNSPEC) {
			af = gw->ss_family;
		} else
		if (dest->ss_family != gw->ss_family) {
			error("Cannot create route - destination and gateway address "
					"family mismatch");
			return NULL;
		}
	}

	rp = calloc(1, sizeof(ni_route_t));
	rp->family = af;
	rp->prefixlen = prefixlen;
	rp->destination = *dest;
	rp->nh.gateway = *gw;
	if (rp->destination.ss_family == AF_UNSPEC) {
		memset(&rp->destination, 0, sizeof(rp->destination));
		rp->destination.ss_family = af;
	}

	if (list)
		__ni_route_list_append(list, rp);

	return rp;
}

ni_route_t *
ni_route_new(ni_handle_t *nih, unsigned int prefixlen, const ni_sockaddr_t *dest, const ni_sockaddr_t *gw)
{
	return __ni_route_new(&nih->routes, prefixlen, dest, gw);
}

void
ni_route_free(ni_route_t *rp)
{
	free(rp);
}

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
__ni_route_list_append(ni_route_t **list, ni_route_t *new_route)
{
	ni_route_t *rp;

	while ((rp = *list) != NULL)
		list = &rp->next;
	*list = new_route;
}


ni_route_t *
__ni_route_list_clone(const ni_route_t *src)
{
	ni_route_t *dst;

	if (!src)
		return NULL;

	dst = malloc(sizeof(*dst));
	memcpy(dst, src, sizeof(*src));

	dst->next = __ni_route_list_clone(src->next);
	return dst;
}

int
ni_route_equal(const ni_route_t *r1, const ni_route_t *r2)
{
	const ni_route_nexthop_t *nh1, *nh2;
	if (r1->prefixlen != r2->prefixlen
	 || !ni_address_equal(&r1->destination, &r2->destination))
		return 0;

	nh1 = &r1->nh;
	nh2 = &r2->nh;
	while (nh1 && nh2) {
		if (!ni_address_equal(&nh1->gateway, &nh2->gateway))
			return 0;
		nh1 = nh1->next;
		nh2 = nh2->next;
	}
	return nh1 == nh2;
}

/*
 * Address configuration mechanisms
 */
static ni_addrconf_t *		ni_addrconf_table_ipv4[__NI_ADDRCONF_MAX];
static ni_addrconf_t *		ni_addrconf_table_ipv6[__NI_ADDRCONF_MAX];

void
ni_addrconf_register(ni_addrconf_t *acm)
{
	if (acm->type >= __NI_ADDRCONF_MAX)
		return;

	if ((acm->supported_af & NI_AF_MASK_IPV4)
	 && !ni_addrconf_table_ipv4[acm->type])
		ni_addrconf_table_ipv4[acm->type] = acm;
	if ((acm->supported_af & NI_AF_MASK_IPV6)
	 && !ni_addrconf_table_ipv6[acm->type])
		ni_addrconf_table_ipv6[acm->type] = acm;
}

static inline ni_addrconf_t *
__ni_addrconf_get(unsigned int type, unsigned int af)
{
	ni_addrconf_t *mech;

	if (type >= __NI_ADDRCONF_MAX)
		return NULL;

	switch (af) {
	case AF_UNSPEC:
		if ((mech = ni_addrconf_table_ipv4[type]) == NULL)
			mech = ni_addrconf_table_ipv6[type];
		break;
	case AF_INET:
		mech = ni_addrconf_table_ipv4[type];
		break;
	case AF_INET6:
		mech = ni_addrconf_table_ipv6[type];
		break;
	default:
		return NULL;
	}
	return mech;
}

ni_addrconf_t *
ni_addrconf_get(int type, int af)
{
	return __ni_addrconf_get(type, af);
}

const ni_addrconf_t *
ni_addrconf_list_first(unsigned int *pos)
{
	*pos = 0;
	return ni_addrconf_list_next(pos);
}

const ni_addrconf_t *
ni_addrconf_list_next(unsigned int *pos)
{
	unsigned int afidx = *pos & 0xFF;
	unsigned int mode = *pos >> 8;
	ni_addrconf_t *mech = NULL;

	switch (afidx) {
	case 0:
		while (mode < __NI_ADDRCONF_MAX) {
			if ((mech = __ni_addrconf_get(mode++, AF_INET)) != NULL)
				goto done;
		}
		mode = 0;
		afidx++;
	case 1:
		while (mode < __NI_ADDRCONF_MAX) {
			if ((mech = __ni_addrconf_get(mode++, AF_INET6)) != NULL)
				goto done;
		}
		afidx++;
	}

done:
	*pos = afidx | (mode << 8);
	return mech;
}

/*
 * Acquire/drop an addrconf lease
 * Note, this may not be instantaneous - rather, this will usually trigger
 * the acquisition of a lease. We will receive an event later on informing
 * us of the lease.
 */
int
ni_addrconf_acquire_lease(const ni_addrconf_t *acm, ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	/* This needs to get better */
	if (acm->supported_af & NI_AF_MASK_IPV4) {
		if (!ifp->ipv4.lease[acm->type])
			ifp->ipv4.lease[acm->type] = ni_addrconf_lease_new(acm->type, AF_INET);
		ifp->ipv4.lease[acm->type]->state = NI_ADDRCONF_STATE_REQUESTING;
	}
	if (acm->supported_af & NI_AF_MASK_IPV6) {
		if (!ifp->ipv6.lease[acm->type])
			ifp->ipv6.lease[acm->type] = ni_addrconf_lease_new(acm->type, AF_INET);
		ifp->ipv6.lease[acm->type]->state = NI_ADDRCONF_STATE_REQUESTING;
	}

	return acm->request(acm, ifp, cfg_xml);
}

int
ni_addrconf_drop_lease(const ni_addrconf_t *acm, ni_interface_t *ifp)
{
	ni_addrconf_lease_t *lease = NULL;
	int rv;

	/* This needs to get better */
	if (acm->supported_af & NI_AF_MASK_IPV4) {
		if ((lease = ifp->ipv4.lease[acm->type]) != NULL)
			lease->state = NI_ADDRCONF_STATE_RELEASING;
	}
	if (acm->supported_af & NI_AF_MASK_IPV6) {
		if ((lease = ifp->ipv6.lease[acm->type]) != NULL)
			lease->state = NI_ADDRCONF_STATE_RELEASING;
	}

	/* Call the release handler for this aconf mechanism. Note
	 * we give it the *intended* interface state (which is down)
	 * even though the interface is still up at this point.
	 * (It has to be up, otherwise DHCP would have a hard time
	 * sending any packets).
	 */
	{
		unsigned int oflags = ifp->ifflags;

		ni_interface_network_mark_down(ifp);
		rv = acm->release(acm, ifp, lease);
		ifp->ifflags = oflags;
	}

	if (acm->supported_af & NI_AF_MASK_IPV4) {
		if ((lease = ifp->ipv4.lease[acm->type]) && lease->state == NI_ADDRCONF_STATE_RELEASED) {
			ni_addrconf_lease_free(lease);
			ifp->ipv4.lease[acm->type] = NULL;
		}
	}
	if (acm->supported_af & NI_AF_MASK_IPV6) {
		if ((lease = ifp->ipv6.lease[acm->type]) && lease->state == NI_ADDRCONF_STATE_RELEASED) {
			ni_addrconf_lease_free(lease);
			ifp->ipv6.lease[acm->type] = NULL;
		}
	}

	return rv;
}

int
ni_addrconf_lease_is_valid(const ni_addrconf_lease_t *lease)
{
	ni_addrconf_t *acm;

	if (lease == NULL)
		return 0;
	if ((acm = ni_addrconf_get(lease->type, lease->family)) != NULL
	 && acm->is_valid)
		return acm->is_valid(acm, lease);

	return lease->state == NI_ADDRCONF_STATE_GRANTED;
}

/*
 * Test whether an address configuration method is active
 */
int
ni_addrconf_check(const ni_addrconf_t *acm, const ni_interface_t *ifp, const xml_node_t *cfg_xml)
{
	if (!acm->test)
		return 0;
	return acm->test(acm, ifp, cfg_xml);
}
