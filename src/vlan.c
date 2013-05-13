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
#include <stdlib.h>

#include <wicked/vlan.h>
#include <wicked/netinfo.h>
#include "util_priv.h"

/*
 * Create a new VLAN device
 */
ni_vlan_t *
ni_vlan_new(void)
{
	ni_vlan_t *vlan;

	vlan = xcalloc(1, sizeof(ni_vlan_t));
	return vlan;
}

void
ni_vlan_free(ni_vlan_t *vlan)
{
	ni_netdev_ref_destroy(&vlan->parent);
	free(vlan);
}


