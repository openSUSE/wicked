/*
 * Handle IPv4 settings for network devices
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/ipv4.h>
#include <errno.h>

#include "util_priv.h"
#include "sysfs.h"

/*
 * index values for the variables in ipv4_devconf,
 * basically a copy from linux/ip.h + NI_ prefix.
 *
 * Note, that ipv6 flags start at 0, ipv4 at 1!
 */
enum
{
	NI_IPV4_DEVCONF_FORWARDING = 1,
	NI_IPV4_DEVCONF_MC_FORWARDING,
	NI_IPV4_DEVCONF_PROXY_ARP,
	NI_IPV4_DEVCONF_ACCEPT_REDIRECTS,
	NI_IPV4_DEVCONF_SECURE_REDIRECTS,
	NI_IPV4_DEVCONF_SEND_REDIRECTS,
	NI_IPV4_DEVCONF_SHARED_MEDIA,
	NI_IPV4_DEVCONF_RP_FILTER,
	NI_IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE,
	NI_IPV4_DEVCONF_BOOTP_RELAY,
	NI_IPV4_DEVCONF_LOG_MARTIANS,
	NI_IPV4_DEVCONF_TAG,
	NI_IPV4_DEVCONF_ARPFILTER,
	NI_IPV4_DEVCONF_MEDIUM_ID,
	NI_IPV4_DEVCONF_NOXFRM,
	NI_IPV4_DEVCONF_NOPOLICY,
	NI_IPV4_DEVCONF_FORCE_IGMP_VERSION,
	NI_IPV4_DEVCONF_ARP_ANNOUNCE,
	NI_IPV4_DEVCONF_ARP_IGNORE,
	NI_IPV4_DEVCONF_PROMOTE_SECONDARIES,
	NI_IPV4_DEVCONF_ARP_ACCEPT,
	NI_IPV4_DEVCONF_ARP_NOTIFY,
	NI_IPV4_DEVCONF_ACCEPT_LOCAL,
	NI_IPV4_DEVCONF_SRC_VMARK,
	NI_IPV4_DEVCONF_PROXY_ARP_PVLAN,
	NI_IPV4_DEVCONF_ROUTE_LOCALNET,
	NI_IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL,
	NI_IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL,
	__NI_IPV4_DEVCONF_MAX
};
/*
 * Map of net/ipv4/conf/<ifname>/<flag name> to constants
 */
static const ni_intmap_t	__ipv4_devconf_sysctl_name_map[] = {
	{ "forwarding",				NI_IPV4_DEVCONF_FORWARDING		},
	{ "mc_forwarding",			NI_IPV4_DEVCONF_MC_FORWARDING	},
	{ "proxy_arp",				NI_IPV4_DEVCONF_PROXY_ARP		},
	{ "accept_redirects",			NI_IPV4_DEVCONF_ACCEPT_REDIRECTS	},
	{ "secure_redirects",			NI_IPV4_DEVCONF_SECURE_REDIRECTS	},
	{ "send_redirects",			NI_IPV4_DEVCONF_SEND_REDIRECTS	},
	{ "shared_media",			NI_IPV4_DEVCONF_SHARED_MEDIA	},
	{ "rp_filter",				NI_IPV4_DEVCONF_RP_FILTER		},
	{ "accept_source_route",		NI_IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE},
	{ "bootp_relay",			NI_IPV4_DEVCONF_BOOTP_RELAY	},
	{ "log_martians",			NI_IPV4_DEVCONF_LOG_MARTIANS	},
	{ "tag",				NI_IPV4_DEVCONF_TAG		},
	{ "arp_filter",				NI_IPV4_DEVCONF_ARPFILTER		},
	{ "medium_id",				NI_IPV4_DEVCONF_MEDIUM_ID		},
	{ "disable_xfrm",			NI_IPV4_DEVCONF_NOXFRM		},
	{ "disable_policy",			NI_IPV4_DEVCONF_NOPOLICY		},
	{ "force_igmp_version",			NI_IPV4_DEVCONF_FORCE_IGMP_VERSION	},
	{ "arp_announce",			NI_IPV4_DEVCONF_ARP_ANNOUNCE	},
	{ "arp_ignore",				NI_IPV4_DEVCONF_ARP_IGNORE		},
	{ "promote_secondaries",		NI_IPV4_DEVCONF_PROMOTE_SECONDARIES},
	{ "arp_accept",				NI_IPV4_DEVCONF_ARP_ACCEPT		},
	{ "arp_notify",				NI_IPV4_DEVCONF_ARP_NOTIFY		},
	{ "accept_local",			NI_IPV4_DEVCONF_ACCEPT_LOCAL	},
	{ "src_valid_mark",			NI_IPV4_DEVCONF_SRC_VMARK		},
	{ "proxy_arp_pvlan",			NI_IPV4_DEVCONF_PROXY_ARP_PVLAN	},
	{ "route_localnet",			NI_IPV4_DEVCONF_ROUTE_LOCALNET	},
	{ "igmpv2_unsolicited_report_interval",	NI_IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL },
	{ "igmpv3_unsolicited_report_interval",	NI_IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL },
	{ NULL,					__NI_IPV4_DEVCONF_MAX		},
};

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
 * Update the device's IPv4 settings
 */
static inline int
__change_int(const char *ifname, const char *attr, int value)
{
	if (!ni_tristate_is_set(value))
		return 1;

	if (ni_sysctl_ipv4_ifconfig_set_int(ifname, attr, value) < 0) {
		if (errno == EROFS || errno == ENOENT) {
			ni_info("%s: cannot set ipv4.conf.%s = %d attribute: %m",
					ifname, attr, value);
			return 1;
		} else {
			ni_warn("%s: cannot set ipv4.conf.%s = %d attribute: %m",
					ifname, attr, value);
			return -errno;
		}
	}

	return 0;
}

static ni_bool_t
__tristate_changed(ni_tristate_t cfg, ni_tristate_t sys)
{
	return ni_tristate_is_set(cfg) && cfg != sys;
}

int
ni_system_ipv4_devinfo_set(ni_netdev_t *dev, const ni_ipv4_devconf_t *conf)
{
	ni_ipv4_devinfo_t *ipv4;
	ni_tristate_t arp_notify;
	ni_bool_t can_arp;
	int ret;

	if (!conf || !(ipv4 = ni_netdev_get_ipv4(dev)))
		return -1;

	if (ni_tristate_is_set(conf->enabled))
		ni_tristate_set(&ipv4->conf.enabled, conf->enabled);

	if (__tristate_changed(conf->forwarding, ipv4->conf.forwarding)) {
		ret = __change_int(dev->name, "forwarding", conf->forwarding);
		if (ret < 0)
			return ret;
		if (ret == 0)
			ipv4->conf.forwarding = conf->forwarding;
	}

	can_arp = ni_netdev_supports_arp(dev);
	if (ni_tristate_is_set(conf->arp_verify) && can_arp)
		ni_tristate_set(&ipv4->conf.arp_verify, conf->arp_verify);
	else
		ni_tristate_set(&ipv4->conf.arp_verify, FALSE);

	arp_notify = ni_tristate_is_set(conf->arp_notify) && can_arp ?
			conf->arp_notify : conf->arp_verify;

	if (__tristate_changed(arp_notify, ipv4->conf.arp_notify)) {
		ret = __change_int(dev->name, "arp_notify", arp_notify);
		if (ret < 0)
			return ret;
		if (ret == 0)
			ipv4->conf.arp_notify = arp_notify;
	}

	if (__tristate_changed(conf->accept_redirects, ipv4->conf.accept_redirects)) {
		ret = __change_int(dev->name, "accept_redirects", conf->accept_redirects);
		if (ret < 0)
			return ret;
		if (ret == 0)
			ipv4->conf.accept_redirects = conf->accept_redirects;
	}

	return 0;
}

static inline const char *
ni_ipv4_devconf_flag_to_sysctl_name(unsigned int flag)
{
	return ni_format_uint_mapped(flag, __ipv4_devconf_sysctl_name_map);
}

static int
__ni_ipv4_devconf_process_flag(ni_netdev_t *dev, unsigned int flag, int value)
{
	ni_ipv4_devinfo_t *ipv4 = dev->ipv4;
	unsigned int level;
	int unused = 0;

	switch (flag) {
	case NI_IPV4_DEVCONF_FORWARDING:
		ipv4->conf.forwarding = !!value;
		break;
	case NI_IPV4_DEVCONF_ACCEPT_REDIRECTS:
		ipv4->conf.accept_redirects = !!value;
		break;
	case NI_IPV4_DEVCONF_ARP_NOTIFY:
		ipv4->conf.arp_notify = !!value;
		break;
	default:
		/* TODO: handle more (all) of them */
		unused = TRUE;
		break;
	}

	level = NI_LOG_DEBUG1 + unused;
	if (ni_debug_guard(level, NI_TRACE_EVENTS|NI_TRACE_IPV4)) {
		const char *name;

		name = ni_ipv4_devconf_flag_to_sysctl_name(flag);
		if (name) {
			ni_trace("%s[%u]: get ipv4.conf.%s = %d%s",
				dev->name, dev->link.ifindex, name,
				value, unused ? " (unused)" : "");
		} else {
			ni_trace("%s[%u]: get ipv4.conf.[%u] = %d%s",
				dev->name, dev->link.ifindex, flag,
				value, unused ? " (unused)" : "");
		}
	}
	return unused;
}

int
__ni_ipv4_devconf_process_flags(ni_netdev_t *dev, int32_t *array, unsigned int count)
{
	ni_ipv4_devinfo_t *ipv4;
	unsigned int i;

	if (!array || !dev || !(ipv4 = ni_netdev_get_ipv4(dev)))
		return -1;

	for (i = 0; i < count; ++i) {
		int32_t value = array[i];
		/*
		 * unlike ipv6 the flags start at 1 not at 0;
		 * we keep it same as defined in linux/ip.h.
		 */
		if (__ni_ipv4_devconf_process_flag(dev, i + 1, value) < 0)
			return -1;
	}

	/* Some additional pieces of configuration we care about */
	if (!ni_tristate_is_set(ipv4->conf.enabled)) {
		ipv4->conf.enabled = NI_TRISTATE_ENABLE;
	}

	if (!ni_tristate_is_set(ipv4->conf.arp_verify)) {
		ipv4->conf.arp_verify = ni_netdev_supports_arp(dev) ?
			NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;
	}
	return 0;
}

