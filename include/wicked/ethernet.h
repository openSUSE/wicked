/*
 * ethernet definitions for netinfo
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_ETHERNET_H__
#define __WICKED_ETHERNET_H__

#include <wicked/types.h>

struct ni_ethernet {
	unsigned int		link_speed;
};

#endif /* __WICKED_ETHERNET_H__ */
