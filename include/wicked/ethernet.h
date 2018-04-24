/*
 * ethernet definitions for netinfo
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef NI_WICKED_ETHERNET_H
#define NI_WICKED_ETHERNET_H

#include <wicked/types.h>

struct ni_ethernet {
	ni_hwaddr_t		permanent_address;
};

extern ni_ethernet_t *	ni_ethernet_new(void);
extern void		ni_ethernet_free(ni_ethernet_t *);

#endif /* NI_WICKED_ETHERNET_H */
