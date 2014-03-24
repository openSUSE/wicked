/*
 * Handle IPv6 settings for network devices
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <errno.h>

#include "ipv6_priv.h"
#include "util_priv.h"
#include "sysfs.h"

#define NI_PROC_SYS_NET_IPV6_DIR	"/proc/sys/net/ipv6"

#define NI_IPV6_RA_RDNSS_ADDRS_CHUNK	4

/*
 * Check if ipv6 is supported or disabled
 * via ipv6.disabled=1 kernel command line.
 */
ni_bool_t
ni_ipv6_supported(void)
{
	return ni_isdir(NI_PROC_SYS_NET_IPV6_DIR);
}

/*
 * Reset to ipv6 config defaults
 */
static void
__ni_ipv6_devconf_reset(ni_ipv6_devconf_t *conf)
{
	conf->enabled = NI_TRISTATE_DEFAULT;
	conf->autoconf = NI_TRISTATE_DEFAULT;
	conf->forwarding = NI_TRISTATE_DEFAULT;
	conf->accept_redirects = NI_TRISTATE_DEFAULT;
	conf->privacy = NI_TRISTATE_DEFAULT;
}

/*
 * Reset to ipv6 config defaults
 */
static void
__ni_ipv6_ra_info_reset(ni_ipv6_ra_info_t *radv)
{
	radv->managed_addr = FALSE;
	radv->other_config = FALSE;

	ni_ipv6_ra_pinfo_list_destroy(&radv->pinfo);
	ni_ipv6_ra_rdnss_free(radv->rdnss);
	radv->rdnss = NULL;
}

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
ni_netdev_set_ipv6(ni_netdev_t *dev, ni_ipv6_devconf_t *conf)
{
	if (conf != NULL) {
		ni_netdev_get_ipv6(dev);
		dev->ipv6->conf = *conf;
	} else if (dev->ipv6) {
		ni_ipv6_devinfo_free(dev->ipv6);
		dev->ipv6 = NULL;
	}
}

ni_ipv6_devinfo_t *
ni_ipv6_devinfo_new(void)
{
	ni_ipv6_devinfo_t *ipv6;

	ipv6 = xcalloc(1, sizeof(*ipv6));
	__ni_ipv6_devconf_reset(&ipv6->conf);
	__ni_ipv6_ra_info_reset(&ipv6->radv);
	return ipv6;
}

void
ni_ipv6_devinfo_free(ni_ipv6_devinfo_t *ipv6)
{
	if (ipv6)
		__ni_ipv6_ra_info_reset(&ipv6->radv);
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

	if (!ni_ipv6_supported()) {
		__ni_ipv6_devconf_reset(&ipv6->conf);
		__ni_ipv6_ra_info_reset(&ipv6->radv);
		ipv6->conf.enabled = NI_TRISTATE_DISABLE;
		return 0;
	}

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
		int val;

		if (ni_sysctl_ipv6_ifconfig_get_int(dev->name, "disable_ipv6", &val) >= 0)
			ni_tristate_set(&ipv6->conf.enabled, !val);

		if (ni_sysctl_ipv6_ifconfig_get_int(dev->name, "forwarding", &val) >= 0)
			ni_tristate_set(&ipv6->conf.forwarding, !!val);

		if (ni_sysctl_ipv6_ifconfig_get_int(dev->name, "autoconf", &val) >= 0)
			ni_tristate_set(&ipv6->conf.autoconf, !!val);

		if (ni_sysctl_ipv6_ifconfig_get_int(dev->name, "accept_redirects", &val) >= 0)
			ni_tristate_set(&ipv6->conf.accept_redirects, !!val);

		if (ni_sysctl_ipv6_ifconfig_get_int(dev->name, "use_tempaddr", &val) >= 0)
			ipv6->conf.privacy = val < -1 ? -1 : (val > 2 ? 2 : val);
	} else {
		ni_warn("%s: cannot get ipv6 device attributes", dev->name);

		/* Reset to defaults */
		__ni_ipv6_devconf_reset(&ipv6->conf);
		__ni_ipv6_ra_info_reset(&ipv6->radv);
	}

	return 0;
}

/*
 * Update the device's IPv6 settings
 */
static inline int
__ni_system_ipv6_devinfo_change_int(const char *ifname, const char *attr, int value)
{
	if (!ni_tristate_is_set(value))
		return 1;

	if (ni_sysctl_ipv6_ifconfig_set_int(ifname, attr, value) < 0) {
		ni_warn("%s: cannot set ipv6 device attr %s=%u",
				ifname, attr, value);
		return -1;
	}

	return 0;
}

int
ni_system_ipv6_devinfo_set(ni_netdev_t *dev, const ni_ipv6_devconf_t *conf)
{
	ni_ipv6_devinfo_t *ipv6;

	if (!conf || !(ipv6 = ni_netdev_get_ipv6(dev)))
		return -1;

	if (!ni_ipv6_supported()) {
		ipv6->conf.enabled = NI_TRISTATE_DISABLE;
		if (ni_tristate_is_enabled(conf->enabled)) {
			errno = EAFNOSUPPORT;
			return -1;
		}
		return 0;
	}

	if (ni_tristate_is_set(conf->enabled)) {
		if (__ni_system_ipv6_devinfo_change_int(dev->name, "disable_ipv6",
				ni_tristate_is_enabled(conf->enabled) ? 0 : 1) < 0)
			return -1;

		ni_tristate_set(&ipv6->conf.enabled, conf->enabled);
	}

	/* If we're disabling IPv6 on this interface, we're done! */
	if (ni_tristate_is_disabled(conf->enabled)) {
		__ni_ipv6_ra_info_reset(&dev->ipv6->radv);
		return 0;
	}

	if (__ni_system_ipv6_devinfo_change_int(dev->name, "autoconf",
						conf->autoconf) == 0)
		ipv6->conf.autoconf = conf->autoconf;

	if (__ni_system_ipv6_devinfo_change_int(dev->name, "forwarding",
						conf->forwarding) == 0)
		ipv6->conf.forwarding = conf->forwarding;

	if (__ni_system_ipv6_devinfo_change_int(dev->name, "accept_redirects",
						conf->accept_redirects) == 0)
		ipv6->conf.accept_redirects = conf->accept_redirects;

	if (ipv6->conf.privacy != NI_TRISTATE_DEFAULT) {
		/* kernel is using -1 for loopback, ptp, ... */
		if (__ni_system_ipv6_devinfo_change_int(dev->name,
			"use_tempaddr",	conf->privacy) == 0) {
			ipv6->conf.privacy = conf->privacy;
		}
	}

	return 0;
}

void
ni_ipv6_ra_info_flush(ni_ipv6_ra_info_t *radv)
{
	ni_ipv6_ra_pinfo_list_destroy(&radv->pinfo);
}

void
ni_ipv6_ra_pinfo_list_prepend(ni_ipv6_ra_pinfo_t **list, ni_ipv6_ra_pinfo_t *pi)
{
	pi->next = *list;
	*list = pi;
}

void
ni_ipv6_ra_pinfo_list_destroy(ni_ipv6_ra_pinfo_t **list)
{
	ni_ipv6_ra_pinfo_t *pi;

	while ((pi = *list) != NULL) {
		*list = pi->next;
		free(pi);
	}
}

ni_ipv6_ra_pinfo_t *
ni_ipv6_ra_pinfo_list_remove(ni_ipv6_ra_pinfo_t **list, const ni_ipv6_ra_pinfo_t *pi)
{
	ni_ipv6_ra_pinfo_t **pos, *cur;

	for (pos = list; (cur = *pos) != NULL; pos = &cur->next) {
		if (cur->length != pi->length)
			continue;
		if (ni_sockaddr_equal(&cur->prefix, &pi->prefix)) {
			*pos = cur->next;
			cur->next = NULL;
			return cur;
		}
	}
	return NULL;
}

ni_ipv6_ra_rdnss_t *
ni_ipv6_ra_rdnss_new()
{
	return xcalloc(1, sizeof(ni_ipv6_ra_rdnss_t));
}

void
ni_ipv6_ra_rdnss_free(ni_ipv6_ra_rdnss_t *rdnss)
{
	if (rdnss) {
		ni_sockaddr_array_destroy(&rdnss->addrs);
		free(rdnss);
	}
}

void
ni_ipv6_ra_rdnss_reset(ni_ipv6_ra_rdnss_t *rdnss)
{
	if (rdnss) {
		rdnss->lifetime = 0;
		ni_sockaddr_array_destroy(&rdnss->addrs);
	}
}

void
ni_ipv6_ra_rdnss_add_server(ni_ipv6_ra_rdnss_t *rdnss, const struct in6_addr *ipv6)
{
	ni_sockaddr_t sockaddr;

	if (rdnss && ipv6) {
		ni_sockaddr_set_ipv6(&sockaddr, *ipv6, 0);
		ni_sockaddr_array_append(&rdnss->addrs, &sockaddr);
	}
}

const char *
ni_ipv6_devconf_privacy_to_name(int privacy)
{
	static const ni_intmap_t	__privacy_names[] = {
		{ "default",		NI_IPV6_PRIVACY_DEFAULT		},
		{ "disable",		NI_IPV6_PRIVACY_DISABLED	},
		{ "prefer-public",	NI_IPV6_PRIVACY_PREFER_PUBLIC	},
		{ "prefer-temporary",	NI_IPV6_PRIVACY_PREFER_TEMPORARY},
		{ NULL,			NI_IPV6_PRIVACY_DEFAULT		}
	};
	if (privacy < NI_IPV6_PRIVACY_DEFAULT)
		privacy = NI_IPV6_PRIVACY_DEFAULT;
	else
	if (privacy > NI_IPV6_PRIVACY_PREFER_TEMPORARY)
		privacy = NI_IPV6_PRIVACY_PREFER_TEMPORARY;

	return ni_format_uint_mapped(privacy, __privacy_names);
}

