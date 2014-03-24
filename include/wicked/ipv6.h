/*
 * IPv6 device settings
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_IPv6_H__
#define __WICKED_IPv6_H__

#include <sys/socket.h>
#include <stdio.h>
#include <net/if.h>
#include <netinet/in.h>

#include <wicked/types.h>

typedef struct ni_ipv6_ra_rdnss	ni_ipv6_ra_rdnss_t;

enum {
	NI_IPV6_PRIVACY_DEFAULT		= -1,
	NI_IPV6_PRIVACY_DISABLED	=  0,
	NI_IPV6_PRIVACY_PREFER_PUBLIC	=  1,
	NI_IPV6_PRIVACY_PREFER_TEMPORARY=  2,
};

struct ni_ipv6_devconf {
	ni_tristate_t		enabled;
	ni_tristate_t		forwarding;
	ni_tristate_t		autoconf;

	ni_tristate_t		accept_redirects;
	int			privacy; /* -1 for lo & p-t-p otherwise 0, 1, >1 */
};

struct ni_ipv6_ra_pinfo {
	ni_ipv6_ra_pinfo_t *	next;

	ni_sockaddr_t		prefix;
	unsigned int		length;

	ni_bool_t		on_link;
	ni_bool_t		autoconf;
	ni_ipv6_cache_info_t	lifetime;
};

struct ni_ipv6_ra_rdnss {
	unsigned int		lifetime;
	ni_sockaddr_array_t	addrs;
};

struct ni_ipv6_ra_info {
	ni_bool_t		managed_addr;	/* address config available via DHCPv6  */
	ni_bool_t		other_config;	/* non-address config only via DHCPv6   */

	ni_ipv6_ra_pinfo_t *	pinfo;
	ni_ipv6_ra_rdnss_t *	rdnss;
};

struct ni_ipv6_devinfo {
	ni_ipv6_devconf_t	conf;
	ni_ipv6_ra_info_t	radv;
};

extern ni_bool_t		ni_ipv6_supported(void);

extern ni_ipv6_devinfo_t *	ni_netdev_get_ipv6(ni_netdev_t *);
extern void			ni_netdev_set_ipv6(ni_netdev_t *, ni_ipv6_devconf_t *);

extern ni_ipv6_devinfo_t *	ni_ipv6_devinfo_new(void);
extern void			ni_ipv6_devinfo_free(ni_ipv6_devinfo_t *);

extern int			ni_system_ipv6_devinfo_get(ni_netdev_t *, ni_ipv6_devinfo_t *);
extern int			ni_system_ipv6_devinfo_set(ni_netdev_t *, const ni_ipv6_devconf_t *);

extern const char *		ni_ipv6_devconf_privacy_to_name(int privacy);

#endif /* __WICKED_IPv6_H__ */
