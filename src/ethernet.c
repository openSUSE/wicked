/*
 * Routines for handling Ethernet devices.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <errno.h>

#include <wicked/ethernet.h>
#include "netinfo_priv.h"
#include "kernel.h"

static int	__ni_system_ethernet_get(const char *, ni_ethernet_t *);

/*
 * Allocate ethernet struct
 */
ni_ethernet_t *
ni_ethernet_alloc(void)
{
	return xcalloc(1, sizeof(ni_ethernet_t));
}

/*
 * Clone a device's Ethernet settings
 */
ni_ethernet_t *
ni_ethernet_clone(const ni_ethernet_t *src)
{
	ni_ethernet_t *dst;

	dst = xcalloc(1, sizeof(ni_ethernet_t));

	*dst = *src;
	return dst;
}

void
ni_ethernet_free(ni_ethernet_t *ethernet)
{
	free(ethernet);
}

/*
 * Translate between port types and strings
 */
static ni_intmap_t	__ni_ethernet_port_types[] = {
	{ "default",		NI_ETHERNET_PORT_DEFAULT	},
	{ "twisted-pair",	NI_ETHERNET_PORT_TP	},
	{ "aui",		NI_ETHERNET_PORT_AUI	},
	{ "bnc",		NI_ETHERNET_PORT_BNC	},
	{ "mii",		NI_ETHERNET_PORT_MII	},
	{ "fibre",		NI_ETHERNET_PORT_FIBRE	},

	{ NULL }
	};

ni_ether_port_t
ni_ethernet_name_to_port_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __ni_ethernet_port_types, &value) < 0)
		return NI_ETHERNET_PORT_DEFAULT;
	return value;
}

const char *
ni_ethernet_port_type_to_name(ni_ether_port_t port_type)
{
	return ni_format_int_mapped(port_type, __ni_ethernet_port_types);
}

/*
 * Translate ethtool constants to our internal constants
 */
typedef struct __ni_ethtool_map {
	int		ethtool_value;
	int		wicked_value;
} __ni_ethtool_map_t;

static __ni_ethtool_map_t	__ni_ethtool_speed_map[] = {
	{ SPEED_10,		10	},
	{ SPEED_100,		100	},
	{ SPEED_1000,		1000	},
	{ SPEED_2500,		2500	},
	{ SPEED_10000,		10000	},
	{ 65535,		0	},
	{ -1 }
};

static __ni_ethtool_map_t	__ni_ethtool_duplex_map[] = {
	{ DUPLEX_HALF,		NI_ETHERNET_DUPLEX_HALF },
	{ DUPLEX_FULL,		NI_ETHERNET_DUPLEX_FULL },
	{ 255,			NI_ETHERNET_DUPLEX_NONE },
	{ -1 }
};

static __ni_ethtool_map_t	__ni_ethtool_port_map[] = {
	{ PORT_TP,		NI_ETHERNET_PORT_TP },
	{ PORT_AUI,		NI_ETHERNET_PORT_AUI },
	{ PORT_BNC,		NI_ETHERNET_PORT_BNC },
	{ PORT_MII,		NI_ETHERNET_PORT_MII },
	{ PORT_FIBRE,		NI_ETHERNET_PORT_FIBRE },
	{ -1 }
};

static int
__ni_ethtool_to_wicked(const __ni_ethtool_map_t *map, int value)
{
	while (map->wicked_value >= 0) {
		if (map->ethtool_value == value)
			return map->wicked_value;
		map++;
	}
	return -1;
}

/*
 * Get a value from ethtool
 */
typedef struct __ni_ioctl_info {
	int		number;
	const char *	name;
	unsigned int	not_supported;
} __ni_ioctl_info_t;

static int
__ni_ethtool_get_value(const char *ifname, __ni_ioctl_info_t *ioc)
{
	struct ethtool_value eval;

	if (ioc->not_supported) {
		errno = EOPNOTSUPP;
		return -1;
	}

	if (__ni_ethtool(ifname, ioc->number, &eval) < 0) {
		ni_error("%s: ETHTOOL_%s failed: %m", ifname, ioc->name);
		if (errno == EOPNOTSUPP)
			ioc->not_supported = 1;
		return -1;
	}

	return eval.data;
}

/*
 * Get a value from ethtool, and convert to tristate.
 */
static int
__ni_ethtool_get_tristate(const char *ifname, __ni_ioctl_info_t *ioc)
{
	int value;

	if ((value = __ni_ethtool_get_value(ifname, ioc)) < 0)
		return NI_ETHERNET_SETTING_DEFAULT;

	return value? NI_ETHERNET_SETTING_ENABLE : NI_ETHERNET_SETTING_DISABLE;
}

/*
 * Get ethtool settings from the kernel
 */
int
__ni_system_ethernet_refresh(ni_interface_t *ifp)
{
	ni_ethernet_t *ether;

	ether = ni_ethernet_alloc();
	if (__ni_system_ethernet_get(ifp->name, ether) < 0) {
		ni_ethernet_free(ether);
		return -1;
	}

	ni_interface_set_ethernet(ifp, ether);
	return 0;
}

int
__ni_system_ethernet_get(const char *ifname, ni_ethernet_t *ether)
{
	static __ni_ioctl_info_t __ethtool_gflags = { ETHTOOL_GFLAGS, "GFLAGS" };
	static __ni_ioctl_info_t __ethtool_grxcsum = { ETHTOOL_GRXCSUM, "GRXCSUM" };
	static __ni_ioctl_info_t __ethtool_gtxcsum = { ETHTOOL_GTXCSUM, "GTXCSUM" };
	static __ni_ioctl_info_t __ethtool_gsg = { ETHTOOL_GSG, "GSG" };
	static __ni_ioctl_info_t __ethtool_gtso = { ETHTOOL_GTSO, "GTSO" };
	static __ni_ioctl_info_t __ethtool_gufo = { ETHTOOL_GUFO, "GUFO" };
	static __ni_ioctl_info_t __ethtool_ggso = { ETHTOOL_GGSO, "GGSO" };
#ifdef ETHTOOL_GGRO
	static __ni_ioctl_info_t __ethtool_ggro = { ETHTOOL_GGRO, "GGRO" };
#else
	static __ni_ioctl_info_t __ethtool_ggro = { -1, "GGRO", 1 };
#endif
	struct ethtool_cmd ecmd;
	int mapped, value;

	if (__ni_ethtool(ifname, ETHTOOL_GSET, &ecmd) < 0) {
		ni_error("%s: ETHTOOL_GSET failed: %m", ifname);
		return -1;
	}


	mapped = __ni_ethtool_to_wicked(__ni_ethtool_speed_map, ethtool_cmd_speed(&ecmd));
	if (mapped >= 0)
		ether->link_speed = mapped;
	else
		ether->link_speed = ethtool_cmd_speed(&ecmd);

	mapped = __ni_ethtool_to_wicked(__ni_ethtool_duplex_map, ecmd.duplex);
	if (mapped < 0) {
		ni_warn("%s: unknown duplex setting %d", ifname, ecmd.duplex);
	} else {
		ether->duplex = mapped;
	}

	mapped = __ni_ethtool_to_wicked(__ni_ethtool_port_map, ecmd.port);
	if (mapped < 0) {
		ni_warn("%s: unknown port setting %d", ifname, ecmd.port);
	} else {
		ether->port_type = mapped;
	}

	ether->autoneg_enable = (ecmd.autoneg? NI_ETHERNET_SETTING_ENABLE : NI_ETHERNET_SETTING_DISABLE);

	/* Not used yet:
	    phy_address
	    transceiver
	 */

	ether->offload.rx_csum = __ni_ethtool_get_tristate(ifname, &__ethtool_grxcsum);
	ether->offload.tx_csum = __ni_ethtool_get_tristate(ifname, &__ethtool_gtxcsum);
	ether->offload.scatter_gather = __ni_ethtool_get_tristate(ifname, &__ethtool_gsg);
	ether->offload.tso = __ni_ethtool_get_tristate(ifname, &__ethtool_gtso);
	ether->offload.ufo = __ni_ethtool_get_tristate(ifname, &__ethtool_gufo);
	ether->offload.gso = __ni_ethtool_get_tristate(ifname, &__ethtool_ggso);
	ether->offload.gro = __ni_ethtool_get_tristate(ifname, &__ethtool_ggro);

	value = __ni_ethtool_get_value(ifname, &__ethtool_gflags);
	if (value >= 0)
		ether->offload.lro = (value & ETH_FLAG_LRO)? NI_ETHERNET_SETTING_ENABLE : NI_ETHERNET_SETTING_DISABLE;

	return 0;
}
