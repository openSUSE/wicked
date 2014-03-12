/*
 * Handle IPv4 settings for network devices
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/logging.h>

#include "util_priv.h"
#include "sysfs.h"

/*
 * Reset to ipv4 config defaults
 */
static void
__ni_ipv4_devconf_reset(ni_ipv4_devconf_t *conf)
{
	conf->enabled = TRUE;
	conf->forwarding = FALSE;
	conf->accept_redirects = FALSE;
}

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
ni_netdev_set_ipv4(ni_netdev_t *dev, ni_ipv4_devconf_t *conf)
{
	if (conf != NULL) {
		ni_netdev_get_ipv4(dev);
		dev->ipv4->conf = *conf;
	} else if (dev->ipv4) {
		ni_ipv4_devinfo_free(dev->ipv4);
		dev->ipv4 = NULL;
	}
}

ni_ipv4_devinfo_t *
ni_ipv4_devinfo_new(void)
{
	ni_ipv4_devinfo_t *ipv4;

	ipv4 = xcalloc(1, sizeof(*ipv4));
	ipv4->conf.arp_verify = TRUE;
	ipv4->conf.arp_notify = FALSE;
	__ni_ipv4_devconf_reset(&ipv4->conf);
	return ipv4;
}

void
ni_ipv4_devinfo_free(ni_ipv4_devinfo_t *ipv4)
{
	free(ipv4);
}

/*
 * Discover current IPv4 device settings
 */
int
ni_system_ipv4_devinfo_get(ni_netdev_t *dev, ni_ipv4_devinfo_t *ipv4)
{
	if (ipv4 == NULL)
		ipv4 = ni_netdev_get_ipv4(dev);

	if (ni_sysctl_ipv4_ifconfig_is_present(dev->name)) {
		unsigned int val;

		if (ni_sysctl_ipv4_ifconfig_get_uint(dev->name, "forwarding", &val) >= 0)
			ipv4->conf.forwarding = val;
		if (ni_sysctl_ipv4_ifconfig_get_uint(dev->name, "arp_notify", &val) >= 0)
			ipv4->conf.arp_notify = val;
		if (ni_sysctl_ipv4_ifconfig_get_uint(dev->name, "accept_redirects", &val) >= 0)
			ipv4->conf.accept_redirects = val;
	} else {
		/* Reset to defaults */
		__ni_ipv4_devconf_reset(&ipv4->conf);
	}

	return 0;
}

/*
 * Update the device's IPv6 settings
 */
static inline int
__ni_system_ipv4_devinfo_change_uint(const char *ifname, const char *attr, unsigned int value)
{
	if (value == NI_IPV6_KERNEL_DEFAULT)
		return 0;

	if (ni_sysctl_ipv4_ifconfig_set_uint(ifname, attr, value) < 0) {
		ni_error("%s: cannot set ipv4 device attr %s=%u", ifname, attr, value);
		return -1;
	}

	return 0;
}

int
ni_system_ipv4_devinfo_set(ni_netdev_t *dev, const ni_ipv4_devconf_t *conf)
{
	int rv = 0;

	if (__ni_system_ipv4_devinfo_change_uint(dev->name, "forwarding",
						conf->forwarding) < 0
	 || __ni_system_ipv4_devinfo_change_uint(dev->name, "arp_notify",
						conf->arp_notify) < 0
	 || __ni_system_ipv4_devinfo_change_uint(dev->name, "accept_redirects",
						conf->accept_redirects) < 0)
		rv = -1;

	return rv;
}

