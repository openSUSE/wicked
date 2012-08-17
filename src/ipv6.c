/*
 * Handle IPv6 settings for network devices
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/ipv6.h>
#include <wicked/logging.h>

#include "util_priv.h"
#include "sysfs.h"

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
	ipv6->autoconf = TRUE;
	ipv6->forwarding = FALSE;
	ipv6->accept_redirects = NI_IPV6_KERNEL_DEFAULT;
	ipv6->privacy = FALSE;
	return ipv6;
}

void
ni_ipv6_devinfo_free(ni_ipv6_devinfo_t *ipv6)
{
	free(ipv6);
}

/*
 * Discover current IPv6 device settings
 */
int
ni_system_ipv6_devinfo_get(ni_netdev_t *dev, ni_ipv6_devinfo_t *ipv6)
{
	if (ipv6 == NULL)
		ipv6 = ni_netdev_get_ipv6(dev);

	/*
	 * dhcpcd does something very odd when shutting down an interface;
	 * in addition to removing all IPv4 addresses, it also removes any
	 * IPv6 addresses. The kernel seems to take this as "disable IPv6
	 * on this interface", and subsequently, /proc/sys/ipv6/conf/<ifname>
	 * is gone.
	 * When we bring the interface back up, everything is fine; but until
	 * then we need to ignore this glitch.
	 */
	if (ni_sysctl_ipv6_ifconfig_is_present(dev->name)) {
		unsigned int val;

		if (ni_sysctl_ipv6_ifconfig_get_uint(dev->name, "disable_ipv6", &val) >= 0)
			ipv6->enabled = !val;

		if (ni_sysctl_ipv6_ifconfig_get_uint(dev->name, "forwarding", &val) >= 0)
			ipv6->forwarding = val;

		if (ni_sysctl_ipv6_ifconfig_get_uint(dev->name, "autoconf", &val) >= 0)
			ipv6->autoconf = val;

		if (ni_sysctl_ipv6_ifconfig_get_uint(dev->name, "accept_redirects", &val) >= 0)
			ipv6->accept_redirects = val;

		if (ni_sysctl_ipv6_ifconfig_get_uint(dev->name, "use_tempaddr", &val) >= 0)
			ipv6->privacy = val;
	} else {
		/* Reset to defaults */
		ni_netdev_set_ipv6(dev, ni_ipv6_devinfo_new());
	}

	return 0;
}

/*
 * Update the device's IPv6 settings
 */
static inline int
__ni_system_ipv6_devinfo_change_uint(const char *ifname, const char *attr, unsigned int value)
{
	if (value == NI_IPV6_KERNEL_DEFAULT)
		return 0;

	if (ni_sysctl_ipv6_ifconfig_set_uint(ifname, attr, value) < 0) {
		ni_error("%s: cannot set ipv6 device attr %s=%u", ifname, attr, value);
		return -1;
	}

	return 0;
}

int
ni_system_ipv6_devinfo_set(ni_netdev_t *dev, const ni_ipv6_devinfo_t *ipv6)
{
	int rv = 0;

	if (__ni_system_ipv6_devinfo_change_uint(dev->name, "disable_ipv6", ipv6->enabled) < 0)
		return -1;

	/* If we're disabling IPv6 on this interface, we're done! */
	if (!ipv6->enabled)
		return 0;

	if (__ni_system_ipv6_devinfo_change_uint(dev->name, "autoconf", ipv6->autoconf) < 0
	 || __ni_system_ipv6_devinfo_change_uint(dev->name, "forwarding", ipv6->forwarding) < 0
	 || __ni_system_ipv6_devinfo_change_uint(dev->name, "accept_redirects", ipv6->accept_redirects) < 0
	 || __ni_system_ipv6_devinfo_change_uint(dev->name, "tempaddr", ipv6->privacy) < 0)
		rv = -1;

	return rv;
}

