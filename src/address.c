/*
 * Handling of network and link layer addresses.
 * Currently, just about formatting addresses for display.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 * Copyright (C) 2012-2013 Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/if_tr.h>
#include <net/if_arp.h>
#include <linux/if_addr.h>
#include <linux/if_infiniband.h>
#include <netlink/netlink.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/time.h>
#include <wicked/route.h>
#include "util_priv.h"

#define	NI_ADDRESS_ARRAY_CHUNK		16

#ifndef offsetof
# define offsetof(type, member) \
	((unsigned long) &(((type *) NULL)->member))
#endif

static const unsigned char *__ni_sockaddr_data(const ni_sockaddr_t *, unsigned int *);

/*
 * ni_address functions
 */
static ni_address_t *
do_address_new(void)
{
	ni_address_t *ap;

	ap = xcalloc(1, sizeof(*ap));
	if (ap) {
		ap->refcount = 1;
		ap->cache_info.valid_lft = NI_LIFETIME_INFINITE;
		ap->cache_info.preferred_lft = NI_LIFETIME_INFINITE;
	}
	return ap;
}

ni_address_t *
ni_address_new(int af, unsigned int prefix_len, const ni_sockaddr_t *local_addr, ni_address_t **list_head)
{
	ni_address_t *ap;

	if (local_addr && local_addr->ss_family != af)
		return NULL;

	ap = do_address_new();
	if (!ap)
		return NULL;

	ap->family = af;
	ap->prefixlen = prefix_len;
	ap->scope = -1;
	if (local_addr)
		ap->local_addr = *local_addr;

	if (list_head) {
		ni_address_list_append(list_head, ap);
	}
	return ap;
}

ni_address_t *
ni_address_ref(ni_address_t *ap)
{
	if (ap) {
		ni_assert(ap->refcount);
		ap->refcount++;
		return ap;
	}
	return NULL;
}

ni_bool_t
ni_address_copy(ni_address_t *dst, const ni_address_t *src)
{
	if (src && dst) {
		dst->owner	= src->owner;
		dst->seq	= src->seq;
		dst->family	= src->family;
		dst->flags	= src->flags;
		dst->scope	= src->scope;
		dst->prefixlen	= src->prefixlen;
		dst->local_addr = src->local_addr;
		dst->peer_addr	= src->peer_addr;
		dst->bcast_addr	= src->bcast_addr;
		dst->anycast_addr    = src->anycast_addr;
		dst->cache_info = src->cache_info;
		ni_string_dup(&dst->label, src->label);
	}
	return FALSE;
}

ni_address_t *
ni_address_clone(const ni_address_t *src)
{
	ni_address_t *dst;

	dst = do_address_new();
	if (ni_address_copy(dst, src))
		return dst;

	ni_address_free(dst);
	return NULL;
}

void
ni_address_free(ni_address_t *ap)
{
	if (ap) {
		ni_assert(ap->refcount);
		ap->refcount--;
		if (ap->refcount != 0)
			return;

		ni_string_free(&ap->label);
		free(ap);
	}
}

ni_bool_t
ni_address_equal_ref(const ni_address_t *ap1, const ni_address_t *ap2)
{
	return ap1 == ap2;
}

ni_bool_t
ni_address_equal_local_addr(const ni_address_t *ap1, const ni_address_t *ap2)
{
	if (!ap1 || !ap2)
		return ni_address_equal_ref(ap1, ap2);
	else
		return ni_sockaddr_equal(&ap1->local_addr, &ap2->local_addr);
}

static const ni_intmap_t	__ni_address_ipv4_flag_map[] = {
	{ "secondary",		IFA_F_SECONDARY		},
	{ "permanent",		IFA_F_PERMANENT		},
	{ "deprecated",		IFA_F_DEPRECATED	},
	{ NULL,			0			}
};

static const ni_intmap_t	__ni_address_ipv6_flag_map[] = {
	{ "temporary",		IFA_F_TEMPORARY		},
	{ "nodad",		IFA_F_NODAD		},
	{ "optimistic",		IFA_F_OPTIMISTIC	},
	{ "duplicate",		IFA_F_DADFAILED		},
	{ "homeaddress",	IFA_F_HOMEADDRESS	},
	{ "deprecated",		IFA_F_DEPRECATED	},
	{ "tentative",		IFA_F_TENTATIVE		},
	{ "permanent",		IFA_F_PERMANENT		},
	{ "mngtmpaddr",		IFA_F_MANAGETEMPADDR	},
	{ "noprefixroute",	IFA_F_NOPREFIXROUTE	},
	{ "autojoin",		IFA_F_MCAUTOJOIN	},
	{ "stable-privacy",	IFA_F_STABLE_PRIVACY	},
	{ NULL,			0			}
};

const char *
ni_address_format_flags(ni_stringbuf_t *buf, unsigned int family,
			unsigned int flags, const char *sep)
{
	const ni_intmap_t *map;
	unsigned int i = 0;

	if (!buf)
		return NULL;
	switch (family) {
	case AF_INET:	map = __ni_address_ipv4_flag_map; break;
	case AF_INET6:	map = __ni_address_ipv6_flag_map; break;
	default:	return NULL;
	}

	if (ni_string_empty(sep))
		sep = "|";

	/* invert permanent flag same to iproute2 */
	if (flags & IFA_F_PERMANENT) {
		flags &= ~IFA_F_PERMANENT;
	} else {
		ni_stringbuf_puts(buf, "dynamic");
		i++;
	}
	for ( ; map->name; ++map) {
		if (flags & map->value) {
			if (i++)
				ni_stringbuf_puts(buf, sep);
			ni_stringbuf_puts(buf, map->name);
		}
	}
	return buf->string;
}

const char *
ni_address_print(ni_stringbuf_t *out, const ni_address_t *ap)
{
	ni_stringbuf_t flags = NI_STRINGBUF_INIT_DYNAMIC;
	ni_address_cache_info_t lft;
	const char *beg, *ptr;

	if (!out || !ap || ap->family == AF_UNSPEC)
		return NULL;

	beg = out->string;
	if ((ptr = ni_addrfamily_type_to_name(ap->family)))
		ni_stringbuf_printf(out, "%s", ptr);

	if (ni_sockaddr_is_specified(&ap->local_addr)) {
		ni_stringbuf_printf(out, " %s", ni_sockaddr_print(&ap->local_addr));
		if (ap->prefixlen)
			ni_stringbuf_printf(out, "/%u", ap->prefixlen);
	} else
	if (ni_sockaddr_is_specified(&ap->anycast_addr)) {
		ni_stringbuf_printf(out, " anycast %s", ni_sockaddr_print(&ap->anycast_addr));
		if (ap->prefixlen)
			ni_stringbuf_printf(out, "/%u", ap->prefixlen);
	}
	if (ni_sockaddr_is_specified(&ap->peer_addr))
		ni_stringbuf_printf(out, " peer %s", ni_sockaddr_print(&ap->peer_addr));
	else
	if (ni_sockaddr_is_specified(&ap->bcast_addr))
		ni_stringbuf_printf(out, " brd %s", ni_sockaddr_print(&ap->local_addr));

	if (ni_route_is_valid_scope(ap->scope) &&
	    (ptr = ni_route_scope_type_to_name(ap->scope)))
		ni_stringbuf_printf(out, " scope %s", ptr);

	if (ap->cache_info.preferred_lft == NI_LIFETIME_INFINITE)
		ni_address_format_flags(&flags, ap->family, ap->flags | IFA_F_PERMANENT, NULL);
	else
		ni_address_format_flags(&flags, ap->family, ap->flags & ~IFA_F_PERMANENT, NULL);
	if (flags.string)
		ni_stringbuf_printf(out, " flags %s", flags.string);
	ni_stringbuf_destroy(&flags);

	if (ap->family == AF_INET && ap->label)
		ni_stringbuf_printf(out, " label %s", ap->label);

	ni_address_cache_info_rebase(&lft, &ap->cache_info, NULL);
	if (lft.preferred_lft != NI_LIFETIME_INFINITE) {
		ni_stringbuf_printf(out, " valid-lft ");
		ni_lifetime_print_valid(out, lft.valid_lft);
		ni_stringbuf_printf(out, " pref-lft ");
		ni_lifetime_print_preferred(out, lft.preferred_lft);
	}

	return beg ? beg : out->string;
}

ni_bool_t
ni_address_is_loopback(const ni_address_t *laddr)
{
	if (laddr->family == laddr->local_addr.ss_family)
		return ni_sockaddr_is_loopback(&laddr->local_addr);

	return FALSE;
}

ni_bool_t
ni_address_is_linklocal(const ni_address_t *laddr)
{
	if (laddr->family == laddr->local_addr.ss_family)
		return ni_sockaddr_is_linklocal(&laddr->local_addr);

	return FALSE;
}

ni_bool_t
ni_address_is_tentative(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_TENTATIVE ? TRUE : FALSE;
}

ni_bool_t
ni_address_is_duplicate(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_DADFAILED ? TRUE : FALSE;
}

ni_bool_t
ni_address_is_temporary(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_TEMPORARY ? TRUE : FALSE;
}

ni_bool_t
ni_address_is_permanent(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_PERMANENT ? TRUE : FALSE;
}

ni_bool_t
ni_address_is_deprecated(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_DEPRECATED ? TRUE : FALSE;
}

ni_bool_t
ni_address_is_mngtmpaddr(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_MANAGETEMPADDR ? TRUE : FALSE;
}

ni_bool_t
ni_address_is_nodad(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_NODAD;
}

ni_bool_t
ni_address_is_noprefixroute(const ni_address_t *laddr)
{
	return laddr->flags & IFA_F_NOPREFIXROUTE;
}

ni_bool_t
ni_address_can_reach(const ni_address_t *laddr, const ni_sockaddr_t *gw)
{
	if (laddr->family != gw->ss_family)
		return FALSE;

	/* if (laddr->peer_addr.ss_family != AF_UNSPEC) { ... } */
	return ni_sockaddr_prefix_match(laddr->prefixlen, &laddr->local_addr, gw);
}

void
ni_address_set_tentative(ni_address_t *laddr, ni_bool_t tentative)
{
	if (tentative)
		laddr->flags |= IFA_F_TENTATIVE;
	else
		laddr->flags &= ~IFA_F_TENTATIVE;
}

void
ni_address_set_duplicate(ni_address_t *laddr, ni_bool_t duplicate)
{
	if (duplicate)
		laddr->flags |= IFA_F_DADFAILED;
	else
		laddr->flags &= ~IFA_F_DADFAILED;
}

void
ni_address_set_temporary(ni_address_t *laddr, ni_bool_t temporary)
{
	if (temporary)
		laddr->flags |= IFA_F_TEMPORARY;
	else
		laddr->flags &= ~IFA_F_TEMPORARY;
}

void
ni_address_set_mngtmpaddr(ni_address_t *laddr, ni_bool_t temporary)
{
	if (temporary)
		laddr->flags |= IFA_F_MANAGETEMPADDR;
	else
		laddr->flags &= ~IFA_F_MANAGETEMPADDR;
}

void
ni_address_set_nodad(ni_address_t *laddr, ni_bool_t nodad)
{
	if (nodad)
		laddr->flags |= IFA_F_NODAD;
	else
		laddr->flags &= ~IFA_F_NODAD;
}

void
ni_address_set_noprefixroute(ni_address_t *laddr, ni_bool_t noprefixroute)
{
	if (noprefixroute)
		laddr->flags |= IFA_F_NOPREFIXROUTE;
	else
		laddr->flags &= ~IFA_F_NOPREFIXROUTE;
}

unsigned int
ni_address_valid_lft(const ni_address_t *ap, const struct timeval *current)
{
	return ap ? ni_lifetime_left(ap->cache_info.valid_lft,
			&ap->cache_info.acquired, current) : NI_LIFETIME_EXPIRED;
}

unsigned int
ni_address_preferred_lft(const ni_address_t *ap, const struct timeval *current)
{
	return ap ? ni_lifetime_left(ap->cache_info.preferred_lft,
			&ap->cache_info.acquired, current) : NI_LIFETIME_EXPIRED;
}

ni_bool_t
ni_address_lft_is_valid(const ni_address_t *ap, const struct timeval *current)
{
	return ni_address_valid_lft(ap, current) != NI_LIFETIME_EXPIRED;
}

ni_bool_t
ni_address_lft_is_preferred(const ni_address_t *ap, const struct timeval *current)
{
	return ni_address_preferred_lft(ap, current) != NI_LIFETIME_EXPIRED;
}


/*
 * ni_address list functions
 */
void
ni_address_list_append(ni_address_t **list, ni_address_t *ap)
{
	while (*list)
		list = &(*list)->next;
	*list = ap;
}

void
ni_address_list_dedup(ni_address_t **list)
{
	ni_address_t **pos, *ap;
	ni_address_t **pos2, *ap2;

	for (pos = list; (ap = *pos) != NULL; pos = &ap->next) {
		for (pos2 = &ap->next; (ap2 = *pos2) != NULL; ) {
			if (ni_sockaddr_equal(&ap->local_addr, &ap2->local_addr)) {
				if (ap->prefixlen != ap2->prefixlen
				 || ap->scope != ap2->scope) {
					ni_warn("%s(): duplicate address %s with prefix or scope mismatch",
							__func__, ni_sockaddr_print(&ap->local_addr));
				}
				*pos2 = ap2->next;
				ni_address_free(ap2);
			} else {
				pos2 = &ap2->next;
			}
		}
	}
}

unsigned int
ni_address_list_count(ni_address_t *list)
{
	unsigned int count = 0;
	ni_address_t *ap;

	for (ap = list; ap != NULL; ap = ap->next)
		count++;
	return count;
}

ni_address_t *
ni_address_list_find(ni_address_t *list, const ni_sockaddr_t *addr)
{
	ni_address_t *ap;

	for (ap = list; ap != NULL; ap = ap->next) {
		if (ni_sockaddr_equal(&ap->local_addr, addr))
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

void
ni_address_array_init(ni_address_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_address_array_destroy(ni_address_array_t *array)
{
	if (array) {
		while (array->count) {
			array->count--;
			ni_address_free(array->data[array->count]);
		}
		free(array->data);
		array->data = NULL;
	}
}

static ni_bool_t
ni_address_array_realloc(ni_address_array_t *array, unsigned int newlen)
{
	ni_address_t ** newdata;
	size_t          newsize;
	unsigned int    i;

	if (!array || (UINT_MAX - NI_ADDRESS_ARRAY_CHUNK) <= newlen)
		return FALSE;

	newlen += NI_ADDRESS_ARRAY_CHUNK;
	newsize = newlen * sizeof(ni_address_t *);
	newdata = xrealloc(array->data, newsize);
	if (!newdata)
		return FALSE;

	array->data = newdata;
	for (i = array->count; i < newlen; ++i)
		array->data[i] = NULL;
	return TRUE;
}

ni_bool_t
ni_address_array_append(ni_address_array_t *array, ni_address_t *ap)
{
	if (!array)
		return FALSE;

	if ((array->count % NI_ADDRESS_ARRAY_CHUNK) == 0 &&
	    !ni_address_array_realloc(array, array->count))
		return FALSE;

	array->data[array->count++] = ap;
	return TRUE;
}

ni_address_t *
ni_address_array_remove_at(ni_address_array_t *array, unsigned int index)
{
	ni_address_t *ap;

	if (!array || index >= array->count)
		return NULL;

	ap = array->data[index];
	array->count--;
	if (index < array->count) {
		memmove(&array->data[index], &array->data[index + 1],
			(array->count - index) * sizeof(ni_address_t *));
	}
	array->data[array->count] = NULL;

	return ap;
}

ni_bool_t
ni_address_array_delete_at(ni_address_array_t *array, unsigned int index)
{
	if (!array || index >= array->count)
		return FALSE;

	ni_address_free(ni_address_array_remove_at(array, index));
	return TRUE;
}

ni_address_t *
ni_address_array_remove(ni_address_array_t *array, const ni_address_t *ap)
{
	unsigned int index;

	if ((index = ni_address_array_index(array, ap)) == -1U)
		return NULL;
	return ni_address_array_remove_at(array, index);
}

ni_bool_t
ni_address_array_delete(ni_address_array_t *array, const ni_address_t *ap)
{
	unsigned int index;

	if ((index = ni_address_array_index(array, ap)) == -1U)
		return FALSE;
	return ni_address_array_delete_at(array, index);
}

ni_address_t *
ni_address_array_at(ni_address_array_t *array, unsigned int index)
{
	if (!array || index >= array->count)
		return NULL;

	return array->data[index];
}

ni_bool_t
ni_address_array_get(ni_address_array_t *array, unsigned int index, ni_address_t **ret)
{
	if (!array || index >= array->count || !ret)
		return FALSE;

	*ret = array->data[index];
	return TRUE;
}

ni_bool_t
ni_address_array_set(ni_address_array_t *array, unsigned int index, ni_address_t *ap)
{
	ni_address_t *a;

	if (!array || index >= array->count)
		return FALSE;

	a = array->data[index];
	if (!ni_address_equal_ref(a, ap)) {
		ni_address_free(a);
		array->data[index] = ap;
	}
	return TRUE;
}

unsigned int
ni_address_array_index(const ni_address_array_t *array, const ni_address_t *ap)
{
	const ni_address_t *a;
	unsigned int i;

	if (array) {
		for (i = 0; i < array->count; ++i) {
			a = array->data[i];
			if (ni_address_equal_ref(a, ap))
				return i;
		}
	}
	return -1U;
}

ni_address_t *
ni_address_array_find_match(ni_address_array_t *array, const ni_address_t *ap, unsigned int *index,
				ni_bool_t (*match)(const ni_address_t *, const ni_address_t *))
{
	ni_address_t *a;
	unsigned int i;

	if (array) {
		match = match ?: ni_address_equal_ref;

		for (i = index ? *index : 0; i < array->count; ++i) {
			a = array->data[i];
			if (match(a, ap)) {
				if (index)
					*index = i;
				return a;
			}
		}
	}
	if (index)
		*index = -1U;
	return NULL;
}


/*
 * ni_af_sockaddr functions
 */
unsigned int
ni_af_address_length(int af)
{
	switch (af) {
	case AF_INET:
		return 4;
	case AF_INET6:
		return 16;
	}
	return 0;
}

unsigned int
ni_af_address_prefixlen(int af)
{
	switch (af) {
	case AF_INET:
	case AF_INET6:
		return ni_af_address_length(af) * 8;
	break;
	default:
		return 0;
	}
}

ni_bool_t
ni_af_sockaddr_info(int af, unsigned int *offset, unsigned int *len)
{
	switch (af) {
	case AF_INET:
		*offset = offsetof(struct sockaddr_in, sin_addr);
		*len = ni_af_address_length(af);
		return TRUE;
	case AF_INET6:
		*offset = offsetof(struct sockaddr_in6, sin6_addr);
		*len = ni_af_address_length(af);
		return TRUE;
	}

	return FALSE;
}

/*
 * ni_sockaddr functions
 */
ni_bool_t
ni_sockaddr_is_ipv4_loopback(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET) {
		uint32_t inaddr;

		inaddr = ntohl(saddr->sin.sin_addr.s_addr);
		return (inaddr >> 24) == IN_LOOPBACKNET;
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv4_linklocal(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET) {
		uint32_t inaddr;

		inaddr = ntohl(saddr->sin.sin_addr.s_addr);

		/* rfc3927, 169.254.0.0/16 */
		return (inaddr >> 16) == 0xa9fe;
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv4_broadcast(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET) {
		/* ntohl not needed here as all bytes are same */
		return	saddr->sin.sin_addr.s_addr == INADDR_BROADCAST;
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv4_multicast(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET) {
		return IN_MULTICAST(ntohl(saddr->sin.sin_addr.s_addr));
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv4_specified(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET) {
		/* ntohl not needed here as all bytes are same */
		return	saddr->sin.sin_addr.s_addr != INADDR_ANY &&
			saddr->sin.sin_addr.s_addr != INADDR_BROADCAST;
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv4_unspecified(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET) {
		/* ntohl not needed here as all bytes are same */
		return	saddr->sin.sin_addr.s_addr == INADDR_ANY;
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv6_loopback(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET6) {
		return IN6_IS_ADDR_LOOPBACK(&saddr->six.sin6_addr);
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv6_linklocal(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET6) {
		return IN6_IS_ADDR_LINKLOCAL(&saddr->six.sin6_addr);
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv6_sitelocal(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET6) {
		return	IN6_IS_ADDR_SITELOCAL(&saddr->six.sin6_addr);
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv6_multicast(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET6) {
		return	IN6_IS_ADDR_MULTICAST(&saddr->six.sin6_addr);
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv6_v4mapped(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET6) {
		return	IN6_IS_ADDR_V4MAPPED(&saddr->six.sin6_addr);
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv6_v4compat(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET6) {
		return	IN6_IS_ADDR_V4COMPAT(&saddr->six.sin6_addr);
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv6_specified(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET6) {
		return	!IN6_IS_ADDR_UNSPECIFIED(&saddr->six.sin6_addr);
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_ipv6_unspecified(const ni_sockaddr_t *saddr)
{
	if (saddr->ss_family == AF_INET6) {
		return	IN6_IS_ADDR_UNSPECIFIED(&saddr->six.sin6_addr);
	}
	return FALSE;
}

ni_bool_t
ni_sockaddr_is_loopback(const ni_sockaddr_t *saddr)
{
	switch (saddr->ss_family) {
	case AF_INET:
		return ni_sockaddr_is_ipv4_loopback(saddr);
	case AF_INET6:
		return ni_sockaddr_is_ipv6_loopback(saddr);
	default:
		return FALSE;
	}
}

ni_bool_t
ni_sockaddr_is_linklocal(const ni_sockaddr_t *saddr)
{
	switch (saddr->ss_family) {
	case AF_INET:
		return ni_sockaddr_is_ipv4_linklocal(saddr);
	case AF_INET6:
		return ni_sockaddr_is_ipv6_linklocal(saddr);
	default:
		return FALSE;
	}
}

ni_bool_t
ni_sockaddr_is_multicast(const ni_sockaddr_t *saddr)
{
	switch (saddr->ss_family) {
	case AF_INET:
		return ni_sockaddr_is_ipv4_multicast(saddr);
	case AF_INET6:
		return ni_sockaddr_is_ipv6_multicast(saddr);
	default:
		return FALSE;
	}
}

ni_bool_t
ni_sockaddr_is_specified(const ni_sockaddr_t *saddr)
{
	switch (saddr->ss_family) {
	case AF_INET:
		return ni_sockaddr_is_ipv4_specified(saddr);
	case AF_INET6:
		return ni_sockaddr_is_ipv6_specified(saddr);
	default:
		return FALSE;
	}
}

ni_bool_t
ni_sockaddr_is_unspecified(const ni_sockaddr_t *saddr)
{
	switch (saddr->ss_family) {
	case AF_INET:
		return ni_sockaddr_is_ipv4_unspecified(saddr);
	case AF_INET6:
		return ni_sockaddr_is_ipv6_unspecified(saddr);
	default:
		return TRUE;
	}
}

static const unsigned char *
__ni_sockaddr_data(const ni_sockaddr_t *ss, unsigned int *len)
{
	unsigned int offset;

	*len = 0;
	if (ss == NULL)
		return NULL;
	if (!ni_af_sockaddr_info(ss->ss_family, &offset, len))
		return NULL;

	return ((const unsigned char *) ss) + offset;
}

int
ni_sockaddr_compare(const ni_sockaddr_t *ss1, const ni_sockaddr_t *ss2)
{
	const unsigned char *ap1, *ap2;
	unsigned int len1, len2;

	if (!ss1 || !ss2)
		return ss1 > ss2 ? 1 : ss1 < ss2 ? -1 : 0;

	if (ss1->ss_family != ss2->ss_family)
		return ss1->ss_family - ss2->ss_family;

	if (ss1->ss_family == AF_UNSPEC)
		return 0;

	ap1 = __ni_sockaddr_data(ss1, &len1);
	ap2 = __ni_sockaddr_data(ss2, &len2);
	if (!ap1 || !ap2)
		return ap1 > ap2 ? 1 : ap1 < ap2 ? -1 : 0;

	if (len1 != len2)
		return len1 > len2 ? 1 : -1;

	if (len1 == 0)
		return 0;

	return memcmp(ap1, ap2, len1);
}

ni_bool_t
ni_sockaddr_equal(const ni_sockaddr_t *ss1, const ni_sockaddr_t *ss2)
{
	const unsigned char *ap1, *ap2;
	unsigned int len;

	if (ss1->ss_family != ss2->ss_family)
		return FALSE;
	if (ss1->ss_family == AF_UNSPEC)
		return TRUE;

	ap1 = __ni_sockaddr_data(ss1, &len);
	ap2 = __ni_sockaddr_data(ss2, &len);
	if (!ap1 || !ap2 || ss1->ss_family != ss2->ss_family)
		return FALSE;

	return !memcmp(ap1, ap2, len);
}


ni_bool_t
ni_sockaddr_prefix_match(unsigned int prefix_bits, const ni_sockaddr_t *laddr, const ni_sockaddr_t *gw)
{
	const unsigned char *laddr_ptr, *gw_ptr;
	unsigned int offset = 0, len;
	unsigned int cc;

	laddr_ptr = __ni_sockaddr_data(laddr, &len);
	gw_ptr = __ni_sockaddr_data(gw, &len);
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

const char *
ni_sockaddr_format(const ni_sockaddr_t *ss, char *abuf, size_t buflen)
{
	switch (ss->ss_family) {
	case AF_INET:
		return inet_ntop(AF_INET, &ss->sin.sin_addr, abuf, buflen);

	case AF_INET6:
		return inet_ntop(AF_INET6, &ss->six.sin6_addr, abuf, buflen);

	default:
		return NULL;
	}
}

const char *
ni_sockaddr_print(const ni_sockaddr_t *ss)
{
	static char abuf[128];

	return ni_sockaddr_format(ss, abuf, sizeof(abuf));
}

const char *
ni_sockaddr_prefix_print(const ni_sockaddr_t *ss, unsigned int pfxlen)
{
	static char abuf[128];
	const char *s;

	if (!(s = ni_sockaddr_print(ss)))
		return NULL;

	snprintf(abuf, sizeof(abuf), "%s/%u", s, pfxlen);
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

	in_addr.s_addr = htonl(in_addr.s_addr);
	ni_sockaddr_set_ipv4(ss, in_addr, 0);
	return 0;
}

int
ni_sockaddr_parse(ni_sockaddr_t *ss, const char *string, int af)
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

ni_bool_t
ni_sockaddr_prefix_parse(const char *address_string, ni_sockaddr_t *addr, unsigned int *prefixlen)
{
	char *string, *sp;
	ni_bool_t rv = FALSE;

	string = xstrdup(address_string);
	if ((sp = strchr(string, '/')) != NULL) {
		*sp++ = '\0';
		*prefixlen = strtoul(sp, NULL, 0);
	} else {
		*prefixlen = ~0U;
	}

	if (ni_sockaddr_parse(addr, string, AF_UNSPEC) >= 0)
		rv = TRUE;

	free(string);
	return rv;
}

unsigned int
ni_sockaddr_netmask_bits(const ni_sockaddr_t *mask)
{
	unsigned int	offset, len, i, bits = 0;
	unsigned char	*raw;

	if (!ni_af_sockaddr_info(mask->ss_family, &offset, &len))
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
ni_sockaddr_build_netmask(int af, unsigned int prefix_len, ni_sockaddr_t *mask)
{
	unsigned int	offset, len, i, bits;
	unsigned char	*raw;

	memset(mask, 0, sizeof(*mask));
	mask->ss_family = af;

	if (!ni_af_sockaddr_info(af, &offset, &len))
		return -1;

	raw = &((unsigned char *) mask)[offset];
	for (i = 0; i < len && prefix_len != 0; ++i) {
		bits = (prefix_len < 8)? prefix_len : 8;
		*raw++ = 0xFF00 >> bits;
		prefix_len -= bits;
	}

	return prefix_len? -1 : 0;
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

	if (!(aptr = __ni_sockaddr_data(sockaddr, &alen)))
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
	if (!(aptr = __ni_sockaddr_data(sockaddr, &alen)))
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

/*
 * Handle sockaddr arrays
 */
void
ni_sockaddr_array_init(ni_sockaddr_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_sockaddr_array_destroy(ni_sockaddr_array_t *array)
{
	if (array->data)
		free(array->data);
	memset(array, 0, sizeof(*array));
}

void
ni_sockaddr_array_append(ni_sockaddr_array_t *array, const ni_sockaddr_t *sa)
{
	if ((array->count % 4) == 0)
		array->data = xrealloc(array->data, (array->count + 4) * sizeof(array->data[0]));
	array->data[array->count++] = *sa;
}

/*
 * ni_link_address functions
 */
void
ni_link_address_init(ni_hwaddr_t *hwa)
{
	memset(hwa, 0, sizeof(*hwa));
	hwa->type = ARPHRD_VOID;
}

int
ni_link_address_format(const ni_hwaddr_t *hwa, char *abuf, size_t len)
{
	switch (hwa->type) {
	case ARPHRD_SIT:
	case ARPHRD_IPGRE:
	case ARPHRD_TUNNEL:
		if (inet_ntop(AF_INET, hwa->data, abuf, len) == 0)
			return -1;
		return 0;

	case ARPHRD_TUNNEL6:
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
ni_link_address_set(ni_hwaddr_t *hwa, unsigned short arp_type, const void *data, size_t len)
{
	ni_link_address_init(hwa);
	if (len > NI_MAXHWADDRLEN) {
		ni_error("%s: link address too long (len = %lu)",
				__FUNCTION__, (long) len);
		return -1;
	}

	memcpy(hwa->data, data, len);
	hwa->type = arp_type;
	hwa->len = len;

	return 0;
}

static int
__ni_link_sockaddr_parse(ni_hwaddr_t *hwa, unsigned short arp_type,
			const char *string, unsigned int family)
{
	ni_sockaddr_t ss;

	if (ni_sockaddr_parse(&ss, string, family) < 0)
		return -1;

	switch (ss.ss_family) {
	case AF_INET:
		hwa->type = arp_type;
		hwa->len = ni_af_address_length(ss.ss_family);
		memcpy(hwa->data, &ss.sin.sin_addr, hwa->len);
		return 0;

	case AF_INET6:
		hwa->type = arp_type;
		hwa->len = ni_af_address_length(ss.ss_family);
		memcpy(hwa->data, &ss.six.sin6_addr, hwa->len);
		return 0;

	default:
		ni_error("%s: link address parsing not yet implemented",
				__FUNCTION__);
		return -1;
	}
}

int
ni_link_address_parse(ni_hwaddr_t *hwa, unsigned short arp_type, const char *string)
{
	ni_hwaddr_t tmp;
	int len;

	ni_link_address_init(hwa);
	switch (arp_type) {
	case ARPHRD_SIT:
	case ARPHRD_IPGRE:
	case ARPHRD_TUNNEL:
		return __ni_link_sockaddr_parse(hwa, arp_type, string, AF_INET);

	case ARPHRD_TUNNEL6:
		return __ni_link_sockaddr_parse(hwa, arp_type, string, AF_INET6);

	default:
		break;
	}

	/* Default format is aa:bb:cc:.. with hex octets */
	if ((len = ni_parse_hex(string, tmp.data, NI_MAXHWADDRLEN)) < 0)
		return -1;

	if (arp_type != ARPHRD_VOID && ni_link_address_length(arp_type) != (unsigned int)len)
		return -1;

	memcpy(hwa->data, tmp.data, len);
	hwa->type = arp_type;
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
ni_link_address_length(unsigned short arp_type)
{
	switch (arp_type) {
	case ARPHRD_SIT:
	case ARPHRD_IPGRE:
	case ARPHRD_TUNNEL:
		return ni_af_address_length(AF_INET);

	case ARPHRD_TUNNEL6:
		return ni_af_address_length(AF_INET6);

	case ARPHRD_ETHER:
		return ETH_ALEN;

	case ARPHRD_IEEE802_TR:
#		ifndef	TR_ALEN
#		define	TR_ALEN		ETH_ALEN
#		endif
		return TR_ALEN;

	case ARPHRD_IEEE1394:
#		ifndef	FWNET_ALEN
#		define	FWNET_ALEN	8	/* EUI64 */
#		endif
		return	FWNET_ALEN;

	case ARPHRD_INFINIBAND:
		return INFINIBAND_ALEN;
	}

	return 0;
}

int
ni_link_address_get_broadcast(unsigned short arp_type, ni_hwaddr_t *hwa)
{
	hwa->type = arp_type;
	hwa->len = ni_link_address_length(arp_type);

	if (hwa->len == 0)
		return -1;

	switch (arp_type) {
	case ARPHRD_INFINIBAND:
		{
			/* Broadcast address for IPoIB */
			static const uint8_t ipoib_bcast_addr[] = {
				0x00, 0xff, 0xff, 0xff,
				0xff, 0x12, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
			};
			memcpy(hwa->data, ipoib_bcast_addr, hwa->len);
		}
		break;
	case ARPHRD_ETHER:
	default:
		memset(hwa->data, 0xff, hwa->len);
		break;
	}

	return 0;
}

ni_bool_t
ni_link_address_is_broadcast(const ni_hwaddr_t *hwa)
{
	ni_hwaddr_t brd;

	if (!hwa || ni_link_address_get_broadcast(hwa->type, &brd) < 0)
		return FALSE;
	return memcmp(hwa->data, brd.data, brd.len) == 0;
}

/*
 * Utility to reject apparently invalid/unusable hwaddrs,
 * initially with all bits zeroed and all set (broadcast).
 * We may add other possibilities later.
 *
 * To say if it is valid, you have to know it's purpose.
 */
ni_bool_t
ni_link_address_is_invalid(const ni_hwaddr_t *hwa)
{
	unsigned short i;
	unsigned char z, b;

	if (!hwa)
		return TRUE;

	switch (hwa->type) {
	case ARPHRD_VOID:
		return TRUE;

	case ARPHRD_NONE:
	case ARPHRD_PPP:
		return hwa->len != 0;

	case ARPHRD_INFINIBAND:
		if (hwa->len != ni_link_address_length(hwa->type))
			return TRUE;

		for (z = 0, i = 0; i < hwa->len; ++i)
			z |= hwa->data[i];

		if (z == 0x00)
			return TRUE;

		return ni_link_address_is_broadcast(hwa);

	case ARPHRD_ETHER:
	case ARPHRD_IEEE802_TR:
	default:
		if (hwa->len != ni_link_address_length(hwa->type))
			return TRUE;

		for (b = 0xFF, z = 0, i = 0; i < hwa->len; ++i) {
			b &= hwa->data[i];
			z |= hwa->data[i];
		}
		return z == 0x00 || b == 0xff;
	}
	return FALSE;
}

/*
 * Address, ... cache-info lifetime utils.
 */
static const ni_intmap_t	ni_lifetime_valid_names_map[] = {
	{ "infinite",		NI_LIFETIME_INFINITE	},
	{ "expired",		NI_LIFETIME_EXPIRED	},

	{ NULL,			0			}
};

static const ni_intmap_t	ni_lifetime_preferred_names_map[] = {
	{ "infinite",		NI_LIFETIME_INFINITE	},
	{ "deprecated",		NI_LIFETIME_EXPIRED	},

	{ NULL,			0			}
};

static const char *
ni_lifetime_print(ni_stringbuf_t *out, unsigned int lft, const ni_intmap_t *map)
{
	const char *str;

	if (out) {
		str = map ? ni_format_uint_mapped(lft, map) : NULL;
		if (str)
			ni_stringbuf_puts(out, str);
		else
			ni_stringbuf_printf(out, "%u", lft);

		return out->string;
	}
	return NULL;
}

const char *
ni_lifetime_print_valid(ni_stringbuf_t *out, unsigned int lft)
{
	return ni_lifetime_print(out, lft, ni_lifetime_valid_names_map);
}

const char *
ni_lifetime_print_preferred(ni_stringbuf_t *out, unsigned int lft)
{
	return ni_lifetime_print(out, lft, ni_lifetime_preferred_names_map);
}

unsigned int
ni_lifetime_left(unsigned int lifetime, const struct timeval *acquired, const struct timeval *current)
{
	struct timeval now, dif;

	switch (lifetime) {
	case NI_LIFETIME_INFINITE:
	case NI_LIFETIME_EXPIRED:
		return lifetime;

	default:
		if (!acquired || !timerisset(acquired))
			return lifetime;
		break;
	}

	if (!current || !timerisset(current)) {
		ni_timer_get_time(&now);
		current = &now;
	}

	if (timercmp(current, acquired, >)) {
		timersub(current, acquired, &dif);
		if ((unsigned long)lifetime >= (unsigned long)dif.tv_sec) {
			lifetime -= dif.tv_sec;
			return lifetime;
		}
	}
	return NI_LIFETIME_EXPIRED;
}

void
ni_address_cache_info_rebase(ni_address_cache_info_t *res, const ni_address_cache_info_t *lft, const struct timeval *base)
{
	#define rebase_lft(lft, dif) (lft -= lft > dif ? dif : lft)
	struct timeval now, dif;

	*res = *lft;

	if (!timerisset(&lft->acquired))
		return;

	if (lft->valid_lft == NI_LIFETIME_INFINITE &&
	    (lft->preferred_lft == NI_LIFETIME_INFINITE ||
	     lft->preferred_lft == NI_LIFETIME_EXPIRED))
		return;

	if (!base || !timerisset(base))
		ni_timer_get_time(&now);
	else
		now = *base;

	if (!timercmp(&now, &lft->acquired, >))
		return;
	timersub(&now, &lft->acquired, &dif);

	res->acquired = now;
	if (res->valid_lft == NI_LIFETIME_INFINITE)
		rebase_lft(res->preferred_lft, (unsigned long)dif.tv_sec);
	else
	if (rebase_lft(res->valid_lft, (unsigned long)dif.tv_sec))
		rebase_lft(res->preferred_lft, (unsigned long)dif.tv_sec);
	else
		res->preferred_lft = NI_LIFETIME_EXPIRED;
	#undef rebase_lft
}
