/*
 * vlan definitions for netinfo
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 * Copyright (C) 2013 Marius Tomaschewski <mt@suse.de>
 */

#ifndef __WICKED_VLAN_H__
#define __WICKED_VLAN_H__

#include <wicked/types.h>

struct ni_vlan {
	uint16_t		tag;
	ni_netdev_ref_t		parent;
};

extern ni_vlan_t *	ni_vlan_new(void);
extern void		ni_vlan_free(ni_vlan_t *);

#endif /* __WICKED_VLAN_H__ */
