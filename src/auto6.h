/*
 *	IPv6 autoconf related helper functions
 *
 *	Copyright (C) 2016 SUSE Linux GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifndef WICKED_AUTO6_H
#define WICKED_AUTO6_H

#include <wicked/types.h>
#include <wicked/ipv6.h>

typedef struct ni_auto6_request ni_auto6_request_t;

struct ni_auto6_request {
	ni_bool_t		enabled;
	unsigned int		defer_timeout;
	unsigned int		update;
};

extern void			ni_auto6_request_init(ni_auto6_request_t *);
extern void			ni_auto6_request_destroy(ni_auto6_request_t *);

extern int			ni_auto6_acquire(ni_netdev_t *, const ni_auto6_request_t *);
extern int			ni_auto6_release(ni_netdev_t *);


extern void			ni_auto6_on_netdev_event(ni_netdev_t *, ni_event_t);
extern void			ni_auto6_on_prefix_event(ni_netdev_t *, ni_event_t,
							const ni_ipv6_ra_pinfo_t *);
extern void			ni_auto6_on_address_event(ni_netdev_t *, ni_event_t,
							const ni_address_t *);
extern void			ni_auto6_on_nduseropt_events(ni_netdev_t *, ni_event_t);

#endif /* WICKED_AUTO6_H */
