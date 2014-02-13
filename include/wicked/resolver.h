/*
 * Resolver definitions for wicked
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_RESOLVER_H__
#define __WICKED_RESOLVER_H__

#include <wicked/types.h>
#include <wicked/util.h>

#define _PATH_RESOLV_CONF	"/etc/resolv.conf"

struct ni_resolver_info {
	char *			default_domain;
	ni_string_array_t	dns_servers;
	ni_string_array_t	dns_search;
};

extern ni_resolver_info_t *	ni_resolver_info_new(void);
extern void			ni_resolver_info_free(ni_resolver_info_t *);
extern ni_resolver_info_t *	ni_resolver_parse_resolv_conf(const char *);
extern int			ni_resolver_write_resolv_conf(const char *, const ni_resolver_info_t *, const char *);

extern int			ni_resolve_hostname_timed(const char *hostname, int af, ni_sockaddr_t *addr, unsigned int timeout);
extern int			ni_resolve_hostnames_timed(int af, unsigned int count, const char *hostnames[], ni_sockaddr_t *addrs, unsigned int timeout);

extern int			ni_resolve_reverse_timed(const ni_sockaddr_t *addr, char **name, unsigned int timeout);

#endif /* __WICKED_RESOLVER_H__ */

