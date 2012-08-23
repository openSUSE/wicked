/*
 * Handling of network and link layer addresses.
 * Currently, just about formatting addresses for display.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/if_tr.h>
#include <linux/if_infiniband.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <wicked/netinfo.h>
#include <wicked/route.h>
#include <wicked/addrconf.h>
#include "netinfo_priv.h"


#ifndef offsetof
# define offsetof(type, member) \
	((unsigned long) &(((type *) NULL)->member))
#endif

static const unsigned char *__ni_address_data(const ni_sockaddr_t *, unsigned int *);

ni_address_t *
ni_address_new(ni_netdev_t *dev, int af, unsigned int prefix_len, const ni_sockaddr_t *local_addr)
{
	return __ni_address_new(&dev->addrs, af, prefix_len, local_addr);
}

ni_address_t *
__ni_address_new(ni_address_t **list_head, int af, unsigned int prefix_len, const ni_sockaddr_t *local_addr)
{
	ni_address_t *ap, **tail;

	ni_assert(!local_addr || local_addr->ss_family == af);

	tail = list_head;
	while ((ap = *tail) != NULL)
		tail = &ap->next;

	ap = calloc(1, sizeof(*ap));
	ap->family = af;
	ap->prefixlen = prefix_len;
	ap->scope = -1;
	if (local_addr)
		ap->local_addr = *local_addr;

	/* FIXME: is this the right place to do this? */
	if (af == AF_INET && local_addr && prefix_len < 32) {
		ap->bcast_addr = *local_addr;
		ap->bcast_addr.sin.sin_addr.s_addr |= htonl(0xFFFFFFFFUL >> prefix_len);
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

ni_bool_t
__ni_address_list_remove(ni_address_t **list, ni_address_t *ap)
{
	ni_address_t **pos, *cur;

	for (pos = list; (cur = *pos) != NULL; pos = &cur->next) {
		if (cur == ap) {
			*pos = cur->next;
			ni_address_free(cur);
			return TRUE;
		}
	}
	return FALSE;
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

ni_bool_t
__ni_address_info(int af, unsigned int *offset, unsigned int *len)
{
	switch (af) {
	case AF_INET:
		*offset = offsetof(struct sockaddr_in, sin_addr);
		*len = 4;
		return TRUE;
	case AF_INET6:
		*offset = offsetof(struct sockaddr_in6, sin6_addr);
		*len = 16;
		return TRUE;
	}

	return FALSE;
}

static const unsigned char *
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

void
ni_sockaddr_set_ipv4(ni_sockaddr_t *ap, struct in_addr ipv4, uint16_t port)
{
	memset(ap, 0, sizeof(*ap));
	ap->sin.sin_family = AF_INET;
	ap->sin.sin_addr = ipv4;
	ap->sin.sin_port = htons(port);
}

void
ni_sockaddr_set_ipv6(ni_sockaddr_t *ap, struct in6_addr ipv6, uint16_t port)
{
	memset(ap, 0, sizeof(*ap));
	ap->six.sin6_family = AF_INET6;
	ap->six.sin6_addr = ipv6;
	ap->six.sin6_port = htons(port);
}

ni_bool_t
ni_address_prefix_match(unsigned int prefix_bits, const ni_sockaddr_t *laddr, const ni_sockaddr_t *gw)
{
	const unsigned char *laddr_ptr, *gw_ptr;
	unsigned int offset = 0, len;
	unsigned int cc;

	laddr_ptr = __ni_address_data(laddr, &len);
	gw_ptr = __ni_address_data(gw, &len);
	if (!laddr_ptr || !gw_ptr || laddr->ss_family != gw->ss_family)
		return FALSE;

	if (prefix_bits > (len * 8))
		prefix_bits = len * 8;

	if (prefix_bits > 8) {
		if (memcmp(laddr_ptr, gw_ptr, prefix_bits / 8))
			return FALSE;
		offset = prefix_bits / 8;
		prefix_bits = prefix_bits % 8;
	}

	/* If the prefix length is not a multiple of 8, we need to check the
	 * top N bits of the next octet. */
	if (prefix_bits != 0) {
		cc = laddr_ptr[offset] ^ gw_ptr[offset];
		if ((0xFF00 & (cc << prefix_bits)) != 0)
			return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_address_can_reach(const ni_address_t *laddr, const ni_sockaddr_t *gw)
{
	if (laddr->family != gw->ss_family)
		return FALSE;

	/* if (laddr->peer_addr.ss_family != AF_UNSPEC) { ... } */
	return ni_address_prefix_match(laddr->prefixlen, &laddr->local_addr, gw);
}

ni_bool_t
ni_address_is_loopback(const ni_address_t *laddr)
{
	if (laddr->family == AF_INET && laddr->local_addr.ss_family == AF_INET) {
		uint32_t inaddr;

		inaddr = ntohl(laddr->local_addr.sin.sin_addr.s_addr);
		return (inaddr >> 24) == IN_LOOPBACKNET;
	}
	if (laddr->family == AF_INET6 && laddr->local_addr.ss_family == AF_INET6)
		return IN6_IS_ADDR_LOOPBACK(&laddr->local_addr.six.sin6_addr);

	return FALSE;
}

ni_bool_t
ni_address_is_linklocal(const ni_address_t *laddr)
{
	if (laddr->family == AF_INET6 && laddr->local_addr.ss_family == AF_INET6)
		return IN6_IS_ADDR_LINKLOCAL(&laddr->local_addr.six.sin6_addr);

	return FALSE;
}

ni_bool_t
ni_address_is_tentative(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_TENTATIVE;
}

ni_bool_t
ni_address_is_duplicate(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_DADFAILED;
}

ni_bool_t
ni_address_equal(const ni_sockaddr_t *ss1, const ni_sockaddr_t *ss2)
{
	const unsigned char *ap1, *ap2;
	unsigned int len;

	if (ss1->ss_family != ss2->ss_family)
		return FALSE;
	if (ss1->ss_family == AF_UNSPEC)
		return TRUE;

	ap1 = __ni_address_data(ss1, &len);
	ap2 = __ni_address_data(ss2, &len);
	if (!ap1 || !ap2 || ss1->ss_family != ss2->ss_family)
		return FALSE;

	return !memcmp(ap1, ap2, len);
}

ni_bool_t
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

const char *
ni_address_format(const ni_sockaddr_t *ss, char *abuf, size_t buflen)
{
	switch (ss->ss_family) {
	case AF_INET:
		inet_ntop(AF_INET, &ss->sin.sin_addr, abuf, buflen);
		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &ss->six.sin6_addr, abuf, buflen);
		break;

	default:
		snprintf(abuf, buflen, "Unknown AF %d", ss->ss_family);
		break;
	}

	return abuf;

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
	struct in_addr in_addr = { .s_addr = 0 };
	unsigned int i;

	for (i = 0; i < 4; ++i) {
		unsigned long octet;

		in_addr.s_addr <<= 8;
		if (*string) {
			octet = strtoul(string, (char **) &string, 10);
			if (octet > 255)
				return -1;
			in_addr.s_addr |= octet;
			if (*string) {
				if (*string != '.')
					return -1;
				++string;
			}
		}
	}

	ni_sockaddr_set_ipv4(ss, in_addr, 0);
	return 0;
}

int
ni_address_parse(ni_sockaddr_t *ss, const char *string, int af)
{
	memset(ss, 0, sizeof(*ss));

	if (!string || !*string)
		return -1;

	if ((af == AF_UNSPEC || af == AF_INET6)
	 && inet_pton(AF_INET6, string, &ss->six.sin6_addr) == 1) {
		ss->ss_family = AF_INET6;
		return 0;
	}
	if ((af == AF_UNSPEC || af == AF_INET)
	 && inet_pton(AF_INET, string, &ss->sin.sin_addr) == 1) {
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
		ni_format_hex(hwa->data, hwa->len, abuf, len);
		break;
	}

	return 0;
}

int
ni_link_address_set(ni_hwaddr_t *hwa, int iftype, const void *data, size_t len)
{
	memset(hwa, 0, sizeof(*hwa));
	if (len > NI_MAXHWADDRLEN) {
		ni_error("%s: link address too long (len = %lu)",
				__FUNCTION__, (long) len);
		return -1;
	}

	memcpy(hwa->data, data, len);
	hwa->type = iftype;
	hwa->len = len;

	return 0;
}

int
ni_link_address_parse(ni_hwaddr_t *hwa, unsigned int type, const char *string)
{
	int len;

	memset(hwa, 0, sizeof(*hwa));
	switch (type) {
	case NI_IFTYPE_TUNNEL:
	case NI_IFTYPE_SIT:
	case NI_IFTYPE_GRE:
	case NI_IFTYPE_TUNNEL6:
		ni_error("%s: setting tunnel addrs not yet implemented",
				__FUNCTION__);
		return -1;
	}

	/* Default format is aa:bb:cc:.. with hex octets */
	if ((len = ni_parse_hex(string, hwa->data, NI_MAXHWADDRLEN)) < 0)
		return len;

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

ni_bool_t
ni_link_address_equal(const ni_hwaddr_t *hwa1, const ni_hwaddr_t *hwa2)
{
	if (hwa1->type != hwa2->type
	 || hwa1->len != hwa2->len)
		return FALSE;
	return !memcmp(hwa1->data, hwa2->data, hwa1->len);
}

unsigned int
ni_link_address_length(int iftype)
{
	switch (iftype) {
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_WIRELESS:
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

	rp = calloc(1, sizeof(ni_route_t));
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
		__ni_route_list_append(list, rp);

	return rp;
}

ni_route_t *
ni_route_new(ni_netconfig_t *nc, unsigned int prefixlen, const ni_sockaddr_t *dest, const ni_sockaddr_t *gw)
{
	ni_route_t *rp;

	if ((rp = __ni_route_new(NULL, prefixlen, dest, gw)) != NULL)
		ni_netconfig_route_append(nc, rp);
	return rp;
}

void
ni_route_free(ni_route_t *rp)
{
	ni_route_nexthop_t *nh;

	while ((nh = rp->nh.next) != NULL) {
		rp->nh.next = nh;
		free(nh);
	}
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


ni_bool_t
ni_route_equal(const ni_route_t *r1, const ni_route_t *r2)
{
	const ni_route_nexthop_t *nh1, *nh2;
	if (r1->prefixlen != r2->prefixlen
	 || !ni_address_equal(&r1->destination, &r2->destination))
		return FALSE;

	nh1 = &r1->nh;
	nh2 = &r2->nh;
	while (nh1 && nh2) {
		if (!ni_address_equal(&nh1->gateway, &nh2->gateway))
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
		ni_address_format(&rp->destination, destbuf, sizeof(destbuf));
	}

	if (rp->nh.gateway.ss_family) {
		snprintf(abuf, sizeof(abuf), "%s via %s", dest,
				ni_address_format(&rp->nh.gateway, gwbuf, sizeof(gwbuf)));
	} else {
		snprintf(abuf, sizeof(abuf), "%s", dest);
	}
	return abuf;
}


/*
 * Pack sockaddrs
 */
typedef union ni_packed_netaddr {
	uint16_t	family;
	unsigned char	sin[2 + 4];
	unsigned char	six[2 + 16];
	unsigned char	raw[2 + 62];
} ni_packed_netaddr_t;

typedef struct ni_packed_prefixed_netaddr {
	uint16_t	prefix;
	ni_packed_netaddr_t netaddr;
} ni_packed_prefixed_netaddr_t;

static int
__ni_sockaddr_to_netaddr(const ni_sockaddr_t *sockaddr, ni_packed_netaddr_t *netaddr)
{
	const void *aptr;
	unsigned int alen;

	if (!(aptr = __ni_address_data(sockaddr, &alen)))
		return -1;

	if (2 + alen >= sizeof(netaddr->raw))
		return -1;

	netaddr->family = ntohs(sockaddr->ss_family);
	memcpy(netaddr->raw + 2, aptr, alen);

	return 2 + alen;
}

static ni_sockaddr_t *
__ni_netaddr_to_sockaddr(const ni_packed_netaddr_t *netaddr, ni_sockaddr_t *sockaddr)
{
	const void *aptr;
	unsigned int alen;

	sockaddr->ss_family = ntohs(netaddr->family);
	if (!(aptr = __ni_address_data(sockaddr, &alen)))
		return NULL;
	if (alen + 2 > sizeof(netaddr->raw))
		return NULL;

	memcpy((void *) aptr, netaddr->raw + 2, alen);
	return sockaddr;
}

ni_opaque_t *
ni_sockaddr_pack(const ni_sockaddr_t *sockaddr, ni_opaque_t *pack)
{
	ni_packed_netaddr_t netaddr;
	int len;

	ni_assert(sizeof(pack->data) >= sizeof(netaddr));
	len = __ni_sockaddr_to_netaddr(sockaddr, &netaddr);
	if (len < 0)
		return NULL;
	memcpy(pack->data, &netaddr, len);
	pack->len = len;
	return pack;
}

ni_sockaddr_t *
ni_sockaddr_unpack(ni_sockaddr_t *sockaddr, const ni_opaque_t *pack)
{
	ni_packed_netaddr_t netaddr;

	if (pack->len < 2 || pack->len > sizeof(netaddr))
		return NULL;
	memset(&netaddr, 0, sizeof(netaddr));
	memcpy(&netaddr, pack->data, pack->len);

	return __ni_netaddr_to_sockaddr(&netaddr, sockaddr);
}

ni_opaque_t *
ni_sockaddr_prefix_pack(const ni_sockaddr_t *sockaddr, unsigned int prefix, ni_opaque_t *pack)
{
	ni_packed_prefixed_netaddr_t pfx_netaddr;
	unsigned int max_prefix;
	int len;

	len = __ni_sockaddr_to_netaddr(sockaddr, &pfx_netaddr.netaddr);
	if (len < 0)
		return NULL;

	/* Truncate the prefix len. This is also useful if the caller wants to
	 * tell us "just use the entire address"
	 */
	max_prefix = 8 * (len - 2);
	if (prefix >= max_prefix)
		prefix = max_prefix;
	pfx_netaddr.prefix = htons(prefix);

	memcpy(pack->data, &pfx_netaddr, 2 + len);
	pack->len = 2 + len;

	return pack;
}

ni_sockaddr_t *
ni_sockaddr_prefix_unpack(ni_sockaddr_t *sockaddr, unsigned int *prefix, const ni_opaque_t *pack)
{
	ni_packed_prefixed_netaddr_t pfx_netaddr;

	if (pack->len < 4)
		return NULL;
	if (pack->len < 2 || pack->len > sizeof(pfx_netaddr))
		return NULL;
	memset(&pfx_netaddr, 0, sizeof(pfx_netaddr));
	memcpy(&pfx_netaddr, pack->data, pack->len);

	*prefix = ntohs(pfx_netaddr.prefix);
	return __ni_netaddr_to_sockaddr(&pfx_netaddr.netaddr, sockaddr);
}

