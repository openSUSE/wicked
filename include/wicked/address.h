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

union ni_sockaddr {
	sa_family_t		ss_family;
	struct sockaddr_storage	ss;
	struct sockaddr        	sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	six;
};

typedef struct ni_address {
	struct ni_address *	next;

	const ni_addrconf_lease_t *config_lease;	/* configured through lease */

	unsigned int		seq;
	unsigned int		family;
	unsigned int		flags;
	int			scope;
	unsigned int		prefixlen;
	ni_sockaddr_t		local_addr;
	ni_sockaddr_t		peer_addr;
	ni_sockaddr_t		anycast_addr;
	ni_sockaddr_t		bcast_addr;
	char			label[IFNAMSIZ];

	ni_ipv6_cache_info_t	ipv6_cache_info;
} ni_address_t;

/* FIXME: rename these to ni_sockaddr_* */
extern const char *	ni_address_format(const ni_sockaddr_t *ss, char *abuf, size_t buflen);
extern const char *	ni_address_print(const ni_sockaddr_t *ss);
extern int		ni_address_parse(ni_sockaddr_t *ss, const char *string, int af);
extern unsigned int	ni_address_length(int af);
extern unsigned int	ni_netmask_bits(const ni_sockaddr_t *mask);
extern int		ni_build_netmask(int, unsigned int, ni_sockaddr_t *);
extern ni_bool_t	ni_address_prefix_match(unsigned int, const ni_sockaddr_t *,
				const ni_sockaddr_t *);
extern ni_bool_t	ni_address_equal(const ni_sockaddr_t *, const ni_sockaddr_t *);
extern ni_bool_t	__ni_address_info(int, unsigned int *, unsigned int *);

extern void		ni_sockaddr_set_ipv4(ni_sockaddr_t *, struct in_addr, uint16_t);
extern void		ni_sockaddr_set_ipv6(ni_sockaddr_t *, struct in6_addr, uint16_t);
extern ni_opaque_t *	ni_sockaddr_pack(const ni_sockaddr_t *, ni_opaque_t *);
extern ni_sockaddr_t *	ni_sockaddr_unpack(ni_sockaddr_t *, const ni_opaque_t *);
extern ni_opaque_t *	ni_sockaddr_prefix_pack(const ni_sockaddr_t *, unsigned int, ni_opaque_t *);
extern ni_sockaddr_t *	ni_sockaddr_prefix_unpack(ni_sockaddr_t *, unsigned int *, const ni_opaque_t *);

extern const char *	ni_sockaddr_prefix_print(const ni_sockaddr_t *, unsigned int);
extern ni_bool_t	ni_sockaddr_prefix_parse(const char *, ni_sockaddr_t *, unsigned int *);

extern ni_address_t *	ni_address_new(int af, unsigned int prefix_len,
				const ni_sockaddr_t *local_addr,
				ni_address_t **list);
extern void		ni_address_list_append(ni_address_t **, ni_address_t *);
extern void		ni_address_list_destroy(ni_address_t **);
extern void		ni_address_free(ni_address_t *);


#endif /* __WICKED_ADDRESS_H__ */
