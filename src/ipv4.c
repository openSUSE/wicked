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
	conf->forwarding = NI_TRISTATE_DEFAULT;
	conf->arp_notify = NI_TRISTATE_DEFAULT;
	conf->accept_redirects = NI_TRISTATE_DEFAULT;
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
	ipv4->conf.enabled = NI_TRISTATE_DEFAULT;
	ipv4->conf.arp_verify = NI_TRISTATE_DEFAULT;
	ipv4->conf.arp_notify = NI_TRISTATE_DEFAULT;
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

	if (!ni_tristate_is_set(ipv4->conf.enabled))
		ipv4->conf.enabled = NI_TRISTATE_ENABLE;

	if (!ni_tristate_is_set(ipv4->conf.arp_verify))
		ipv4->conf.arp_verify = NI_TRISTATE_ENABLE;

	if (ni_sysctl_ipv4_ifconfig_is_present(dev->name)) {
		int val;

		if (ni_sysctl_ipv4_ifconfig_get_int(dev->name, "forwarding", &val) >= 0)
			ni_tristate_set(&ipv4->conf.forwarding, val);

		if (ni_sysctl_ipv4_ifconfig_get_int(dev->name, "arp_notify", &val) >= 0)
			ni_tristate_set(&ipv4->conf.arp_notify, val);

		if (ni_sysctl_ipv4_ifconfig_get_int(dev->name, "accept_redirects", &val) >= 0)
			ni_tristate_set(&ipv4->conf.accept_redirects, val);
	} else {
		ni_warn("%s: cannot get ipv4 device attributes", dev->name);

		/* Reset to defaults */
		__ni_ipv4_devconf_reset(&ipv4->conf);
	}

	return 0;
}

/*
 * Update the device's IPv4 settings
 */
static inline int
__ni_system_ipv4_devinfo_change_int(const char *ifname, const char *attr, int value)
{
	if (!ni_tristate_is_set(value))
		return 1;

	if (ni_sysctl_ipv4_ifconfig_set_int(ifname, attr, value) < 0) {
		ni_warn("%s: cannot set ipv4 device attr %s=%u",
				ifname, attr, value);
		return -1;
	}

	return 0;
}

int
ni_system_ipv4_devinfo_set(ni_netdev_t *dev, const ni_ipv4_devconf_t *conf)
{
	ni_ipv4_devinfo_t *ipv4;
	ni_tristate_t arp_notify;

	if (!conf || !(ipv4 = ni_netdev_get_ipv4(dev)))
		return -1;

	if (ni_tristate_is_set(conf->enabled))
		ni_tristate_set(&ipv4->conf.enabled, conf->enabled);

	if (__ni_system_ipv4_devinfo_change_int(dev->name, "forwarding",
						conf->forwarding) == 0)
		ipv4->conf.forwarding = conf->forwarding;

	if (ni_tristate_is_set(conf->arp_verify))
		ni_tristate_set(&ipv4->conf.arp_verify, conf->arp_verify);

	arp_notify = ni_tristate_is_set(conf->arp_notify) ?
			conf->arp_notify : conf->arp_verify;
	if (__ni_system_ipv4_devinfo_change_int(dev->name, "arp_notify",
					arp_notify) == 0)
		ipv4->conf.arp_notify = arp_notify;

	if (__ni_system_ipv4_devinfo_change_int(dev->name, "accept_redirects",
						conf->accept_redirects) == 0)
		ipv4->conf.accept_redirects = conf->accept_redirects;

	return 0;
}

