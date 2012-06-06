/*
 * Handle IPv4 settings for network devices
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "util_priv.h"
#include <wicked/netinfo.h>
#include <wicked/ipv4.h>


/*
 * Set the interface's ipv4 info
 */
ni_ipv4_devinfo_t *
ni_netdev_get_ipv4(ni_netdev_t *dev)
{
	if (dev->ipv4 == NULL)
		dev->ipv4 = ni_ipv4_devinfo_new();
	return dev->ipv4;
}

void
ni_netdev_set_ipv4(ni_netdev_t *dev, ni_ipv4_devinfo_t *ipv4)
{
	if (dev->ipv4)
		ni_ipv4_devinfo_free(dev->ipv4);
	dev->ipv4 = ipv4;
}

ni_ipv4_devinfo_t *
ni_ipv4_devinfo_new(void)
{
	ni_ipv4_devinfo_t *ipv4;

	ipv4 = xcalloc(1, sizeof(*ipv4));
	ipv4->enabled = TRUE;
	return ipv4;
}

void
ni_ipv4_devinfo_free(ni_ipv4_devinfo_t *ipv4)
{
	free(ipv4);
}

