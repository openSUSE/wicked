/*
 * Private header file with ipv6 specific utility functions.
 * No user serviceable parts inside.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __IPV6_PRIV_H__
#define __IPV6_PRIV_H__

#include <wicked/types.h>
#include <wicked/ipv6.h>

extern void			ni_ipv6_ra_info_flush(ni_ipv6_ra_info_t *);

extern void			ni_ipv6_ra_pinfo_list_destroy(ni_ipv6_ra_pinfo_t **);
extern void			ni_ipv6_ra_pinfo_list_prepend(ni_ipv6_ra_pinfo_t **,
							ni_ipv6_ra_pinfo_t *);
extern ni_ipv6_ra_pinfo_t *	ni_ipv6_ra_pinfo_list_remove(ni_ipv6_ra_pinfo_t **,
							const ni_ipv6_ra_pinfo_t *);


extern ni_ipv6_ra_rdnss_t *	ni_ipv6_ra_rdnss_new(void);
extern void			ni_ipv6_ra_rdnss_free(ni_ipv6_ra_rdnss_t *);
extern void			ni_ipv6_ra_rdnss_reset(ni_ipv6_ra_rdnss_t *);
extern void			ni_ipv6_ra_rdnss_add_server(ni_ipv6_ra_rdnss_t *,
							const struct in6_addr *);

extern ni_bool_t		ni_icmpv6_ra_solicit(const ni_netdev_ref_t *,
							const ni_hwaddr_t *);

#endif /* __IPV6_PRIV_H__ */
