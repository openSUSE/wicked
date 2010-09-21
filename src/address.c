/*
 * Handling of network and link layer addresses.
 * Currently, just about formatting addresses for display.
 *
 * Copyright (C) 2009 Olaf Kirch <okir@suse.de>
 */

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include "netinfo_priv.h"


#define offsetof(type, member) \
	((unsigned long) &(((type *) NULL)->member))

ni_address_t *
ni_address_new(ni_interface_t *ifp, int af,
		unsigned int prefix_len,
		const struct sockaddr_storage *local_addr)
{
	ni_address_t *ap, **tail;

	assert(!local_addr || local_addr->ss_family == af);

	tail = &ifp->addrs;
	while ((ap = *tail) != NULL)
		tail = &ap->next;

	ap = calloc(1, sizeof(*ap));
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

	*tail = ap;
	return ap;
}

void
ni_address_free(ni_address_t *ap)
{
	free(ap);
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
	ni_address_t *dst;

	if (!src)
		return NULL;

	dst = malloc(sizeof(*dst));
	memcpy(dst, src, sizeof(*src));

	dst->next = __ni_address_list_clone(src->next);
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
__ni_address_data(const struct sockaddr_storage *ss, unsigned int *len)
{
	unsigned int offset;

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
ni_address_prefix_match(unsigned int prefix_bits, const struct sockaddr_storage *laddr,
			const struct sockaddr_storage *gw)
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
ni_address_can_reach(const ni_address_t *laddr, const struct sockaddr_storage *gw)
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
ni_address_equal(const struct sockaddr_storage *ss1, const struct sockaddr_storage *ss2)
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
__ni_address_probably_dynamic(const ni_afinfo_t *afi, const ni_address_t *ap)
{
	const unsigned char *addr;
	unsigned int len;

	if (afi->family != ap->family)
		return 0;
	switch (afi->family) {
	case AF_INET6:
		/* For IPv6 autoconf, simply assume all addresses are dynamic */
		if (afi->config == NI_ADDRCONF_AUTOCONF)
			return 1;

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
ni_address_format(const struct sockaddr_storage *ss,
				char *abuf, size_t buflen)
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
ni_address_print(const struct sockaddr_storage *ss)
{
	static char abuf[128];

	if (ni_address_format(ss, abuf, sizeof(abuf)) < 0)
		return NULL;
	return abuf;
}

static int
__ni_parse_ipv4shorthand(struct sockaddr_storage *ss, const char *string)
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
ni_address_parse(struct sockaddr_storage *ss, const char *string, int af)
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
ni_netmask_bits(const struct sockaddr_storage *mask)
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
ni_build_netmask(int af, unsigned int prefix_len, struct sockaddr_storage *mask)
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

ni_route_t *
__ni_route_new(ni_route_t **list, unsigned int prefixlen,
		const struct sockaddr_storage *dest,
		const struct sockaddr_storage *gw)
{
	ni_route_t *rp;
	int af;

	if (!dest || !gw)
		return NULL;

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

	/* Find the list tail */
	while ((rp = *list) != NULL)
		list = &rp->next;

	rp = calloc(1, sizeof(ni_route_t));
	rp->family = af;
	rp->prefixlen = prefixlen;
	rp->destination = *dest;
	rp->nh.gateway = *gw;
	if (rp->destination.ss_family == AF_UNSPEC) {
		memset(&rp->destination, 0, sizeof(rp->destination));
		rp->destination.ss_family = af;
	}

	*list = rp;
	return rp;
}

ni_route_t *
ni_route_new(ni_handle_t *nih, unsigned int prefixlen,
		const struct sockaddr_storage *dest,
		const struct sockaddr_storage *gw)
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

