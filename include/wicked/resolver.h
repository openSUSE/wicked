/*
 *	Resolver definitions for wicked
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2010-2022 SUSE LLC
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Olaf Kirch
 *		Marius Tomaschewski
 */

#ifndef NI_WICKED_RESOLVER_H
#define NI_WICKED_RESOLVER_H

#include <wicked/types.h>
#include <wicked/util.h>

#define NI_PATH_RESOLV_CONF	"/etc/resolv.conf"

struct ni_resolver_info {
	char *			default_domain;
	ni_string_array_t	dns_servers;
	ni_string_array_t	dns_search;
};

extern ni_resolver_info_t *	ni_resolver_info_new(void);
extern ni_resolver_info_t *	ni_resolver_info_clone(const ni_resolver_info_t *);
extern void			ni_resolver_info_free(ni_resolver_info_t *);
extern ni_resolver_info_t *	ni_resolver_parse_resolv_conf(const char *);
extern int			ni_resolver_write_resolv_conf(const char *, const ni_resolver_info_t *, const char *);

extern int			ni_resolve_hostname_timed(const char *hostname, int af, ni_sockaddr_t *addr, unsigned int timeout);
extern int			ni_resolve_hostnames_timed(int af, unsigned int count, const char *hostnames[], ni_sockaddr_t *addrs, unsigned int timeout);

extern int			ni_resolve_reverse_timed(const ni_sockaddr_t *addr, char **name, unsigned int timeout);

#endif /* NI_WICKED_RESOLVER_H */

