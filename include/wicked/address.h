/*
 * Global header file for netinfo library
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_ADDRESS_H__
#define __WICKED_ADDRESS_H__

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include <wicked/types.h>
#include <wicked/util.h>

#define NI_LIFETIME_EXPIRED	0
#define NI_LIFETIME_INFINITE	0xffffffffU

union ni_sockaddr {
	sa_family_t		ss_family;
	struct sockaddr_storage	ss;
	struct sockaddr        	sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	six;
};

typedef struct ni_sockaddr_array {
	unsigned int		count;
	ni_sockaddr_t *		data;
} ni_sockaddr_array_t;

typedef struct ni_address_cache_info {
	struct timeval		acquired;
	unsigned int		valid_lft;
	unsigned int		preferred_lft;
} ni_address_cache_info_t;

typedef struct ni_address {
	unsigned int		refcount;
	struct ni_address *	next;

	ni_addrconf_mode_t	owner;		/* configured through lease */
	unsigned int		seq;

	unsigned int		family;
	unsigned int		flags;
	int			scope;
	unsigned int		prefixlen;
	ni_sockaddr_t		local_addr;
	ni_sockaddr_t		peer_addr;
	ni_sockaddr_t		anycast_addr;
	ni_sockaddr_t		bcast_addr;
	char *			label;

	ni_address_cache_info_t	cache_info;
} ni_address_t;

typedef struct ni_address_array {
	unsigned int		count;
	ni_address_t **		data;
} ni_address_array_t;

#define NI_ADDRESS_ARRAY_INIT	{ .count = 0, .data = NULL }

extern ni_bool_t	ni_sockaddr_is_ipv4_loopback(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv4_linklocal(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv4_broadcast(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv4_multicast(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv4_specified(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv4_unspecified(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv6_loopback(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv6_linklocal(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv6_sitelocal(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv6_multicast(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv6_v4mapped(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv6_v4compat(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv6_specified(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_ipv6_unspecified(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_loopback(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_linklocal(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_multicast(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_specified(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_is_unspecified(const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_equal(const ni_sockaddr_t *, const ni_sockaddr_t *);
extern int		ni_sockaddr_compare(const ni_sockaddr_t *, const ni_sockaddr_t *);
extern ni_bool_t	ni_sockaddr_prefix_match(unsigned int, const ni_sockaddr_t *, const ni_sockaddr_t *);

extern void		ni_sockaddr_set_ipv4(ni_sockaddr_t *, struct in_addr, uint16_t);
extern void		ni_sockaddr_set_ipv6(ni_sockaddr_t *, struct in6_addr, uint16_t);
extern const char *	ni_sockaddr_format(const ni_sockaddr_t *ss, char *abuf, size_t buflen);
extern const char *	ni_sockaddr_print(const ni_sockaddr_t *ss);
extern const char *	ni_sockaddr_prefix_print(const ni_sockaddr_t *, unsigned int);
extern int		ni_sockaddr_parse(ni_sockaddr_t *ss, const char *string, int af);
extern ni_bool_t	ni_sockaddr_prefix_parse(const char *, ni_sockaddr_t *, unsigned int *);
extern unsigned int	ni_sockaddr_netmask_bits(const ni_sockaddr_t *mask);
extern int		ni_sockaddr_build_netmask(int, unsigned int, ni_sockaddr_t *);

extern ni_opaque_t *	ni_sockaddr_pack(const ni_sockaddr_t *, ni_opaque_t *);
extern ni_sockaddr_t *	ni_sockaddr_unpack(ni_sockaddr_t *, const ni_opaque_t *);
extern ni_opaque_t *	ni_sockaddr_prefix_pack(const ni_sockaddr_t *, unsigned int, ni_opaque_t *);
extern ni_sockaddr_t *	ni_sockaddr_prefix_unpack(ni_sockaddr_t *, unsigned int *, const ni_opaque_t *);

extern void		ni_sockaddr_array_init(ni_sockaddr_array_t *);
extern void		ni_sockaddr_array_destroy(ni_sockaddr_array_t *);
extern void		ni_sockaddr_array_append(ni_sockaddr_array_t *, const ni_sockaddr_t *);

extern ni_bool_t	ni_af_sockaddr_info(int, unsigned int *, unsigned int *);
extern unsigned int	ni_af_address_length(int af);
extern unsigned int	ni_af_address_prefixlen(int af);

extern ni_address_t *	ni_address_new(int af, unsigned int prefix_len,
					const ni_sockaddr_t *local_addr,
					ni_address_t **list);
extern ni_address_t *	ni_address_ref(ni_address_t *);
extern ni_bool_t	ni_address_copy(ni_address_t *, const ni_address_t *);
extern ni_address_t *	ni_address_clone(const ni_address_t *);
extern void		ni_address_free(ni_address_t *);
extern ni_bool_t	ni_address_equal_ref(const ni_address_t *, const ni_address_t *);
extern ni_bool_t	ni_address_equal_local_addr(const ni_address_t *, const ni_address_t *);
extern const char *	ni_address_format_flags(ni_stringbuf_t *, unsigned int, unsigned int, const char *);
extern const char *	ni_address_print(ni_stringbuf_t *, const ni_address_t *);
extern ni_bool_t	ni_address_can_reach(const ni_address_t *laddr, const ni_sockaddr_t *gw);
extern ni_bool_t	ni_address_is_loopback(const ni_address_t *laddr);
extern ni_bool_t	ni_address_is_linklocal(const ni_address_t *laddr);
extern ni_bool_t	ni_address_is_duplicate(const ni_address_t *laddr);
extern ni_bool_t	ni_address_is_tentative(const ni_address_t *laddr);
extern ni_bool_t	ni_address_is_temporary(const ni_address_t *laddr);
extern ni_bool_t	ni_address_is_permanent(const ni_address_t *laddr);
extern ni_bool_t	ni_address_is_deprecated(const ni_address_t *laddr);
extern ni_bool_t	ni_address_is_mngtmpaddr(const ni_address_t *laddr);
extern ni_bool_t	ni_address_is_noprefixroute(const ni_address_t *laddr);

extern void		ni_address_set_temporary(ni_address_t *, ni_bool_t);
extern void		ni_address_set_mngtmpaddr(ni_address_t *, ni_bool_t);
extern void		ni_address_set_tentative(ni_address_t *, ni_bool_t);
extern void		ni_address_set_duplicate(ni_address_t *, ni_bool_t);
extern void		ni_address_set_noprefixroute(ni_address_t *, ni_bool_t);

extern unsigned int	ni_address_valid_lft(const ni_address_t *, const struct timeval *);
extern unsigned int	ni_address_preferred_lft(const ni_address_t *, const struct timeval *);
extern ni_bool_t	ni_address_lft_is_valid(const ni_address_t *, const struct timeval *);
extern ni_bool_t	ni_address_lft_is_preferred(const ni_address_t *, const struct timeval *);

extern void		ni_address_list_append(ni_address_t **, ni_address_t *);
extern void		ni_address_list_destroy(ni_address_t **);
extern void		ni_address_list_dedup(ni_address_t **);
extern ni_address_t *	ni_address_list_find(ni_address_t *, const ni_sockaddr_t *);
extern unsigned int	ni_address_list_count(ni_address_t *list);

extern void		ni_address_array_init(ni_address_array_t *);
extern void		ni_address_array_destroy(ni_address_array_t *);
extern ni_bool_t	ni_address_array_append(ni_address_array_t *, ni_address_t *);
extern ni_bool_t	ni_address_array_delete(ni_address_array_t *, const ni_address_t *);
extern ni_bool_t	ni_address_array_delete_at(ni_address_array_t *, unsigned int);
extern ni_address_t *	ni_address_array_remove(ni_address_array_t *, const ni_address_t *);
extern ni_address_t *	ni_address_array_remove_at(ni_address_array_t *, unsigned int);
extern ni_address_t *	ni_address_array_at(ni_address_array_t *, unsigned int);
extern ni_bool_t	ni_address_array_get(ni_address_array_t *, unsigned int, ni_address_t **);
extern ni_bool_t	ni_address_array_set(ni_address_array_t *, unsigned int, ni_address_t *);
extern unsigned int	ni_address_array_index(const ni_address_array_t *, const ni_address_t *);
extern ni_address_t *	ni_address_array_find_match(ni_address_array_t *, const ni_address_t *, unsigned int *,
					ni_bool_t (*match)(const ni_address_t *, const ni_address_t *));

extern const char *	ni_lifetime_print_valid(ni_stringbuf_t *, unsigned int);
extern const char *	ni_lifetime_print_preferred(ni_stringbuf_t *, unsigned int);
extern unsigned int	ni_lifetime_left(unsigned int, const struct timeval *, const struct timeval *);
extern void		ni_address_cache_info_rebase(ni_address_cache_info_t *, const ni_address_cache_info_t *,
					const struct timeval *);

#endif /* __WICKED_ADDRESS_H__ */
