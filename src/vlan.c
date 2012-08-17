/*
 * Routines for handling VLAN devices.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>
#include <arpa/inet.h>

#include <wicked/vlan.h>
#include "netinfo_priv.h"

/*
 * Create a new VLAN device
 */
ni_vlan_t *
__ni_vlan_new(void)
{
	ni_vlan_t *vlan;

	vlan = calloc(1, sizeof(ni_vlan_t));
	return vlan;
}

static inline void
__ni_vlan_unbind(ni_vlan_t *vlan)
{
	if (vlan->interface_dev)
		ni_netdev_put(vlan->interface_dev);
	vlan->interface_dev = NULL;
}

/*
 * Given an interface index, locate the the base interface
 */
int
ni_vlan_bind_ifindex(ni_vlan_t *vlan, ni_netconfig_t *nc)
{
	ni_netdev_t *real_dev;

	if (!vlan)
		return -1;

	real_dev = ni_netdev_by_index(nc, vlan->physdev_index);
	if (real_dev == NULL)
		return -1;

	ni_string_dup(&vlan->physdev_name, real_dev->name);
	vlan->interface_dev = ni_netdev_get(real_dev);
	return 0;
}

void
__ni_vlan_destroy(ni_vlan_t *vlan)
{
	__ni_vlan_unbind(vlan);
	ni_string_free(&vlan->physdev_name);
	vlan->physdev_index = 0;
}

void
ni_vlan_free(ni_vlan_t *vlan)
{
	__ni_vlan_destroy(vlan);
	free(vlan);
}


