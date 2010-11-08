/*
 * Routines for handling VLAN devices.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include "netinfo_priv.h"

/*
 * Clone a device's VLAN configuration
 */
ni_vlan_t *
ni_vlan_clone(const ni_vlan_t *src)
{
	ni_vlan_t *dst;

	dst = calloc(1, sizeof(ni_vlan_t));
	if (!dst)
		return NULL;

	dst->tag = src->tag;
	if (src->interface_name
	 && !(dst->interface_name = strdup(src->interface_name)))
		goto failed;

	return dst;

failed:
	error("Error clonding vlan configuration");
	ni_vlan_free(dst);
	return NULL;
}

static inline void
__ni_vlan_unbind(ni_vlan_t *vlan)
{
	if (vlan->interface_dev)
		ni_interface_put(vlan->interface_dev);
	vlan->interface_dev = NULL;
}

/*
 * Given an interface index, locate the the base interface
 */
int
ni_vlan_bind_ifindex(ni_vlan_t *vlan, ni_handle_t *nih)
{
	ni_interface_t *real_dev;

	if (!vlan)
		return -1;

	real_dev = ni_interface_by_index(nih, vlan->link);
	if (real_dev == NULL)
		return -1;

	ni_string_dup(&vlan->interface_name, real_dev->name);
	vlan->interface_dev = ni_interface_get(real_dev);
	return 0;
}

int
ni_vlan_bind(ni_interface_t *ifp, ni_handle_t *nih)
{
	ni_vlan_t *vlan;
	ni_interface_t *child;

	if (!(vlan = ifp->vlan))
		return 0;

	__ni_vlan_unbind(vlan);

	child = ni_interface_by_name(nih, vlan->interface_name);
	if (!child) {
		ni_bad_reference(nih, ifp, vlan->interface_name);
		return -1;
	}
	vlan->interface_dev = ni_interface_get(child);

	/* We do not mark the child as being owned by the VLAN.
	 * In fact, there can be many VLANs per eth device, and
	 * the eth device can be configured in its own right */
#if 0
	child->parent = ifp;
#endif

	return 0;
}

void
ni_vlan_free(ni_vlan_t *vlan)
{
	__ni_vlan_unbind(vlan);
	free(vlan->interface_name);
	free(vlan);
}

