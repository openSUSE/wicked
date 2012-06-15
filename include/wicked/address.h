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
	time_t			expires;		/* when address expires (ipv6) */
} ni_address_t;

#endif /* __WICKED_ADDRESS_H__ */
