/*
 * vlan definitions for netinfo
 *
 * Copyright (C) 2009-2011 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_VLAN_H__
#define __WICKED_VLAN_H__

#include <wicked/types.h>

struct ni_vlan {
	char *			physdev_name;
	unsigned int		physdev_index;	/* when parsing system state, this is the
						 * ifindex of the master */
	uint16_t		tag;
	ni_interface_t *	interface_dev;
};

extern int		ni_vlan_bind_ifindex(ni_vlan_t *, ni_netconfig_t *);
extern void		ni_vlan_free(ni_vlan_t *);
extern ni_vlan_t *	ni_vlan_clone(const ni_vlan_t *);


#endif /* __WICKED_VLAN_H__ */
