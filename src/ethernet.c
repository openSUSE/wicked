/*
 * Routines for handling Ethernet devices.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <net/if_arp.h>
#include <errno.h>

#include <wicked/util.h>
#include <wicked/ethernet.h>
#include <wicked/ethtool.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "kernel.h"


/*
 * Allocate ethernet struct
 */
ni_ethernet_t *
ni_ethernet_new(void)
{
	ni_ethernet_t *ethernet;
	ethernet = calloc(1, sizeof(*ethernet));
	if (ethernet)
		ni_link_address_init(&ethernet->permanent_address);
	return ethernet;
}

void
ni_ethernet_free(ni_ethernet_t *ethernet)
{
	free(ethernet);
}

/*
 * Get ethernet specific settings from the kernel
 */
void
__ni_system_ethernet_refresh(ni_netdev_t *dev)
{
	ni_ethernet_t *ethernet;
	ni_ethtool_t *ethtool;

	if (!ni_netdev_device_is_ready(dev) || !dev->link.ifindex)
		return;

	/* A permanent address is not strictly ethernet specific,
	 * we just don't query it along with ethtool options as
	 * most (virtual) devices provide all-zeroes hw-address.
	 *
	 * As infiniband does not permit to change hw-address,
	 * it never differs from the normal dev->link.hwaddr.
	 */
	ethernet = ni_ethernet_new();
	ethernet->permanent_address.type = dev->link.hwaddr.type;
	if ((ethtool = ni_netdev_get_ethtool(dev))) {
		ni_netdev_ref_t ref = NI_NETDEV_REF_INIT;

		ref.name = dev->name;
		ref.index = dev->link.ifindex;
		ni_ethtool_get_permanent_address(&ref, ethtool,
				&ethernet->permanent_address);
	}
	ni_netdev_set_ethernet(dev, ethernet);
}


/*
 * Write ethernet settings back to kernel
 */
void
__ni_system_ethernet_update(ni_netdev_t *dev, ni_ethernet_t *ethernet)
{
	/* currently nothing ethernet specific to apply */
	__ni_system_ethernet_refresh(dev);
}
