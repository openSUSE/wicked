/*
 * Resolver definitions for wicked
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_RESOLVER_H__
#define __WICKED_RESOLVER_H__

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

#endif /* __WICKED_RESOLVER_H__ */

