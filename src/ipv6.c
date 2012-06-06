/*
 * Handle IPv6 settings for network devices
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
#include <wicked/ipv6.h>


/*
 * Set the interface's ipv6 info
 */
ni_ipv6_devinfo_t *
ni_netdev_get_ipv6(ni_netdev_t *dev)
{
	if (dev->ipv6 == NULL)
		dev->ipv6 = ni_ipv6_devinfo_new();
	return dev->ipv6;
}

void
ni_netdev_set_ipv6(ni_netdev_t *dev, ni_ipv6_devinfo_t *ipv6)
{
	if (dev->ipv6)
		ni_ipv6_devinfo_free(dev->ipv6);
	dev->ipv6 = ipv6;
}

ni_ipv6_devinfo_t *
ni_ipv6_devinfo_new(void)
{
	ni_ipv6_devinfo_t *ipv6;

	ipv6 = xcalloc(1, sizeof(*ipv6));
	ipv6->enabled = TRUE;
	return ipv6;
}

void
ni_ipv6_devinfo_free(ni_ipv6_devinfo_t *ipv6)
{
	free(ipv6);
}

