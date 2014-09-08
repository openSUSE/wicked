/*
 * Routines for handling Ethernet devices.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <errno.h>

#include <wicked/util.h>
#include <wicked/ethernet.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "kernel.h"

#define ALL_ADVERTISED_MODES			\
	(ADVERTISED_10baseT_Half |		\
	 ADVERTISED_10baseT_Full |		\
	 ADVERTISED_100baseT_Half |		\
	 ADVERTISED_100baseT_Full |		\
	 ADVERTISED_1000baseT_Half |		\
	 ADVERTISED_1000baseT_Full |		\
	 ADVERTISED_2500baseX_Full |		\
	 ADVERTISED_10000baseKX4_Full |		\
	 ADVERTISED_10000baseKR_Full |		\
	 ADVERTISED_10000baseR_FEC |		\
	 ADVERTISED_20000baseMLD2_Full |	\
	 ADVERTISED_20000baseKR2_Full |		\
	 ADVERTISED_40000baseKR4_Full |		\
	 ADVERTISED_40000baseCR4_Full |		\
	 ADVERTISED_40000baseSR4_Full |		\
	 ADVERTISED_40000baseLR4_Full)

#define ALL_ADVERTISED_FLAGS			\
	(ADVERTISED_10baseT_Half |		\
	 ADVERTISED_10baseT_Full |		\
	 ADVERTISED_100baseT_Half |		\
	 ADVERTISED_100baseT_Full |		\
	 ADVERTISED_1000baseT_Half |		\
	 ADVERTISED_1000baseT_Full |		\
	 ADVERTISED_Autoneg |			\
	 ADVERTISED_TP |			\
	 ADVERTISED_AUI |			\
	 ADVERTISED_MII |			\
	 ADVERTISED_FIBRE |			\
	 ADVERTISED_BNC |			\
	 ADVERTISED_10000baseT_Full |		\
	 ADVERTISED_Pause |			\
	 ADVERTISED_Asym_Pause |		\
	 ADVERTISED_2500baseX_Full |		\
	 ADVERTISED_Backplane |			\
	 ADVERTISED_1000baseKX_Full |		\
	 ADVERTISED_10000baseKX4_Full |		\
	 ADVERTISED_10000baseKR_Full |		\
	 ADVERTISED_10000baseR_FEC |		\
	 ADVERTISED_20000baseMLD2_Full |	\
	 ADVERTISED_20000baseKR2_Full |		\
	 ADVERTISED_40000baseKR4_Full |		\
	 ADVERTISED_40000baseCR4_Full |		\
	 ADVERTISED_40000baseSR4_Full |		\
	 ADVERTISED_40000baseLR4_Full)

static int	__ni_system_ethernet_get(const char *, ni_ethernet_t *);
static int	__ni_system_ethernet_set(const char *, const ni_ethernet_t *);

/*
 * Allocate ethernet struct
 */
ni_ethernet_t *
ni_ethernet_new(void)
{
	ni_ethernet_t *ether;
	ether = xcalloc(1, sizeof(ni_ethernet_t));
	ni_link_address_init(&ether->permanent_address);
	ether->wol.support		= __NI_ETHERNET_WOL_DEFAULT;
	ether->wol.options		= __NI_ETHERNET_WOL_DEFAULT;
	ether->autoneg_enable		= NI_TRISTATE_DEFAULT;
	ether->offload.rx_csum		= NI_TRISTATE_DEFAULT;
	ether->offload.tx_csum		= NI_TRISTATE_DEFAULT;
	ether->offload.scatter_gather	= NI_TRISTATE_DEFAULT;
	ether->offload.tso		= NI_TRISTATE_DEFAULT;
	ether->offload.ufo		= NI_TRISTATE_DEFAULT;
	ether->offload.gso		= NI_TRISTATE_DEFAULT;
	ether->offload.gro		= NI_TRISTATE_DEFAULT;
	ether->offload.lro		= NI_TRISTATE_DEFAULT;
	return ether;
}

void
ni_ethernet_free(ni_ethernet_t *ethernet)
{
	if (ethernet) {
		free(ethernet->wol.sopass);
		free(ethernet);
	}
}

/*
 * Translate between port types and strings
 */
static ni_intmap_t	__ni_ethernet_port_types[] = {
	{ "tp",			NI_ETHERNET_PORT_TP	},
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

	if (ni_parse_uint_mapped(name, __ni_ethernet_port_types, &value) < 0)
		return NI_ETHERNET_PORT_DEFAULT;
	return value;
}

const char *
ni_ethernet_port_type_to_name(ni_ether_port_t port_type)
{
	return ni_format_uint_mapped(port_type, __ni_ethernet_port_types);
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

static const __ni_ethtool_map_t	__ni_ethtool_wol_map[] = {
	{ WAKE_PHY,		(1<<NI_ETHERNET_WOL_PHY)	},
	{ WAKE_UCAST,		(1<<NI_ETHERNET_WOL_UCAST)	},
	{ WAKE_MCAST,		(1<<NI_ETHERNET_WOL_MCAST)	},
	{ WAKE_BCAST,		(1<<NI_ETHERNET_WOL_BCAST)	},
	{ WAKE_ARP,		(1<<NI_ETHERNET_WOL_ARP)	},
	{ WAKE_MAGIC,		(1<<NI_ETHERNET_WOL_MAGIC)	},
	{ WAKE_MAGICSECURE,	(1<<NI_ETHERNET_WOL_SECUREON)	},
	{ -1,			-1				}
};

static const ni_intmap_t	__ni_ethernet_wol_map[] = {
	{ "p",			NI_ETHERNET_WOL_PHY	},
	{ "phy",		NI_ETHERNET_WOL_PHY	},
	{ "u",			NI_ETHERNET_WOL_UCAST	},
	{ "unicast",		NI_ETHERNET_WOL_UCAST	},
	{ "m",			NI_ETHERNET_WOL_MCAST	},
	{ "multicast",		NI_ETHERNET_WOL_MCAST	},
	{ "b",			NI_ETHERNET_WOL_BCAST	},
	{ "broadcast",		NI_ETHERNET_WOL_BCAST	},
	{ "a",			NI_ETHERNET_WOL_ARP	},
	{ "arp",		NI_ETHERNET_WOL_ARP	},
	{ "g",			NI_ETHERNET_WOL_MAGIC	},
	{ "magic",		NI_ETHERNET_WOL_MAGIC	},
	{ "s",			NI_ETHERNET_WOL_SECUREON},
	{ "secure-on",		NI_ETHERNET_WOL_SECUREON},
	{ NULL,			-1U			}
};

const char *
ni_ethernet_wol_options_format(ni_stringbuf_t *buf, int options, const char *sep)
{
	if (options == __NI_ETHERNET_WOL_DISABLE)
		ni_stringbuf_puts(buf, "d");
	else
		ni_format_bitmap(buf, __ni_ethernet_wol_map, options, sep);

	return buf->string;
}

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

static unsigned int
__ni_ethtool_to_wicked_bits(const __ni_ethtool_map_t *map, unsigned int mask)
{
	const __ni_ethtool_map_t *m;
	unsigned int ret = 0;

	for (m = map; m && m->wicked_value >= 0; m++) {
		if (m->ethtool_value & mask)
			ret |= m->wicked_value;
	}
	return ret;
}

static int
__ni_wicked_to_ethtool(const __ni_ethtool_map_t *map, int value)
{
	while (map->wicked_value >= 0) {
		if (map->wicked_value == value)
			return map->ethtool_value;
		map++;
	}
	return -1;
}

static unsigned int
__ni_wicked_to_ethtool_bits(const __ni_ethtool_map_t *map, unsigned int mask)
{
	const __ni_ethtool_map_t *m;
	unsigned int ret = 0;

	for (m = map; m && m->wicked_value >= 0; m++) {
		if (m->wicked_value & mask)
			ret |= m->ethtool_value;
	}
	return ret;
}

/*
 * Get/set ethtool values
 */
typedef struct __ni_ioctl_info {
	int		number;
	const char *	name;
	unsigned int	not_supported;
} __ni_ioctl_info_t;

#ifndef ETHTOOL_GGRO
# define ETHTOOL_GGRO -1
# define ETHTOOL_SGRO -1
#endif

static __ni_ioctl_info_t __ethtool_gflags = { ETHTOOL_GFLAGS, "GFLAGS" };
static __ni_ioctl_info_t __ethtool_grxcsum = { ETHTOOL_GRXCSUM, "GRXCSUM" };
static __ni_ioctl_info_t __ethtool_gtxcsum = { ETHTOOL_GTXCSUM, "GTXCSUM" };
static __ni_ioctl_info_t __ethtool_gsg = { ETHTOOL_GSG, "GSG" };
static __ni_ioctl_info_t __ethtool_gtso = { ETHTOOL_GTSO, "GTSO" };
static __ni_ioctl_info_t __ethtool_gufo = { ETHTOOL_GUFO, "GUFO" };
static __ni_ioctl_info_t __ethtool_ggso = { ETHTOOL_GGSO, "GGSO" };
static __ni_ioctl_info_t __ethtool_ggro = { ETHTOOL_GGRO, "GGRO" };
static __ni_ioctl_info_t __ethtool_gstrings = { ETHTOOL_GSTRINGS, "GSTRINGS" };
static __ni_ioctl_info_t __ethtool_gstats = { ETHTOOL_GSTATS, "GSTATS" };
static __ni_ioctl_info_t __ethtool_sflags = { ETHTOOL_SFLAGS, "SFLAGS" };
static __ni_ioctl_info_t __ethtool_srxcsum = { ETHTOOL_SRXCSUM, "SRXCSUM" };
static __ni_ioctl_info_t __ethtool_stxcsum = { ETHTOOL_STXCSUM, "STXCSUM" };
static __ni_ioctl_info_t __ethtool_ssg = { ETHTOOL_SSG, "SSG" };
static __ni_ioctl_info_t __ethtool_stso = { ETHTOOL_STSO, "STSO" };
static __ni_ioctl_info_t __ethtool_sufo = { ETHTOOL_SUFO, "SUFO" };
static __ni_ioctl_info_t __ethtool_sgso = { ETHTOOL_SGSO, "SGSO" };
static __ni_ioctl_info_t __ethtool_sgro = { ETHTOOL_SGRO, "SGRO" };
static __ni_ioctl_info_t __ethtool_gwol = { ETHTOOL_GWOL, "GWOL" };
static __ni_ioctl_info_t __ethtool_swol = { ETHTOOL_SWOL, "SWOL" };

static int
__ni_ethtool_do(const char *ifname, __ni_ioctl_info_t *ioc, void *evp)
{
	if (ioc->not_supported) {
		errno = EOPNOTSUPP;
		return -1;
	}

	if (__ni_ethtool(ifname, ioc->number, evp) < 0) {
		ni_error("%s: ETHTOOL_%s failed: %m", ifname, ioc->name);
		if (errno == EOPNOTSUPP)
			ioc->not_supported = 1;
		return -1;
	}

	return 0;
}

static int
__ni_ethtool_get_value(const char *ifname, __ni_ioctl_info_t *ioc)
{
	struct ethtool_value eval;

	memset(&eval, 0, sizeof(eval));
	if (__ni_ethtool_do(ifname, ioc, &eval) < 0)
		return -1;

	return eval.data;
}

static int
__ni_ethtool_set_value(const char *ifname, __ni_ioctl_info_t *ioc, int value)
{
	struct ethtool_value eval;

	memset(&eval, 0, sizeof(eval));
	eval.data = value;
	return __ni_ethtool_do(ifname, ioc, &eval);
}

/*
 * Get list of strings
 */
static int
__ni_ethtool_get_strings(const char *ifname, int set_id, unsigned int num, struct ni_ethtool_counter *counters)
{
	typedef char eth_gstring[ETH_GSTRING_LEN];
	struct ethtool_gstrings *ap;
	eth_gstring *strings;
	unsigned int i;

	ap = xcalloc(1, sizeof(*ap) + num * ETH_GSTRING_LEN);
	ap->string_set = set_id;
	ap->len = num;

	if (__ni_ethtool_do(ifname, &__ethtool_gstrings, ap) < 0)
		return -1;

	strings = (eth_gstring *)(ap + 1);
	for (i = 0; i < ap->len; ++i)
		ni_string_dup(&counters[i].name, strings[i]);

	free(ap);
	return 0;
}

/*
 * Get statistics
 */
static int
__ni_ethtool_get_stats(const char *ifname, unsigned int num, struct ni_ethtool_counter *counters)
{
	struct ethtool_stats *sp;
	unsigned int i;
	uint64_t *stats;

	sp = xcalloc(1, sizeof(*sp) + num * sizeof(uint64_t));
	sp->n_stats = num;

	if (__ni_ethtool_do(ifname, &__ethtool_gstats, sp) < 0)
		return -1;

	stats = (uint64_t *)(sp + 1);
	for (i = 0; i < num; ++i)
		counters[i].value = stats[i];

	return 0;
}

/*
 * Get a value from ethtool, and convert to tristate.
 */
static int
__ni_ethtool_get_tristate(const char *ifname, __ni_ioctl_info_t *ioc)
{
	int value;

	if ((value = __ni_ethtool_get_value(ifname, ioc)) < 0)
		return NI_TRISTATE_DEFAULT;

	return value? NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;
}

static int
__ni_ethtool_set_tristate(const char *ifname, __ni_ioctl_info_t *ioc, int value)
{
	int kern_value;

	if (value == NI_TRISTATE_DEFAULT)
		return 0;

	kern_value = (value == NI_TRISTATE_ENABLE);
	return __ni_ethtool_set_value(ifname, ioc, kern_value);
}

static int
__ni_ethtool_get_wol(const char *ifname, ni_ethernet_wol_t *wol)
{
	struct ethtool_wolinfo wolinfo;
	ni_stringbuf_t buf;

	memset(&wolinfo, 0, sizeof(wolinfo));
	if (__ni_ethtool_do(ifname, &__ethtool_gwol, &wolinfo) < 0) {
		wol->support = wol->options = __NI_ETHERNET_WOL_DISABLE;
		if (wol->sopass)
			free(wol->sopass);
		return -1;
	}

	wol->support = __ni_ethtool_to_wicked_bits(__ni_ethtool_wol_map, wolinfo.supported);
	wol->options  = __ni_ethtool_to_wicked_bits(__ni_ethtool_wol_map, wolinfo.wolopts);

	if (wol->support & (1<<NI_ETHERNET_WOL_SECUREON)
	&&  NI_MAXHWADDRLEN > sizeof(wolinfo.sopass)) {
		if (!wol->sopass)
			wol->sopass = calloc(1, sizeof(ni_hwaddr_t));
		if (wol->sopass) {
			wol->sopass->type = ARPHRD_ETHER;
			wol->sopass->len = sizeof(wolinfo.sopass);
			memcpy(wol->sopass->data, wolinfo.sopass, sizeof(wolinfo.sopass));
		}
	}

	ni_stringbuf_init(&buf);
	ni_format_bitmap(&buf, __ni_ethernet_wol_map, wol->support, "|");
	ni_stringbuf_puts(&buf, " -> ");
	ni_format_bitmap(&buf, __ni_ethernet_wol_map, wol->options, "|");
	ni_stringbuf_destroy(&buf);

	return 0;
}

static int
__ni_ethtool_set_wol(const char *ifname, const ni_ethernet_wol_t *wol)
{
	struct ethtool_wolinfo wolinfo;
	unsigned int wanted;
	ni_stringbuf_t buf;

	if (wol->options == __NI_ETHERNET_WOL_DEFAULT)
		return 0;

	memset(&wolinfo, 0, sizeof(wolinfo));

	/* Try to grab existing options before setting. */
	__ni_ethtool_do(ifname, &__ethtool_gwol, &wolinfo);

	/* Wicked sets __NI_ETHERNET_WOL_DISABLE = -1. The kernel, however,
	 * uses 0 for disabled.
	 */
	wanted = wol->options != __NI_ETHERNET_WOL_DISABLE ?
		__ni_wicked_to_ethtool_bits(__ni_ethtool_wol_map, wol->options) :
		0;
	wolinfo.wolopts = wanted;

	if ((wanted & wolinfo.supported) != wolinfo.wolopts)
		wolinfo.wolopts = (wanted & wolinfo.supported);

	if (wol->sopass && wol->sopass->len && wol->sopass->len == sizeof(wolinfo.sopass)) {
		memcpy(wolinfo.sopass, wol->sopass->data, sizeof(wolinfo.sopass));
	}

	ni_stringbuf_init(&buf);
	ni_format_bitmap(&buf, __ni_ethernet_wol_map, __ni_ethtool_to_wicked_bits(__ni_ethtool_wol_map, wolinfo.supported), "|");
	ni_stringbuf_puts(&buf, " -> ");
	ni_format_bitmap(&buf, __ni_ethernet_wol_map, __ni_ethtool_to_wicked_bits(__ni_ethtool_wol_map, wolinfo.wolopts), "|");
	ni_stringbuf_destroy(&buf);

	if (__ni_ethtool_do(ifname, &__ethtool_swol, &wolinfo) < 0) {
		ni_error("%s: cannot set new wake-on-lan settings: %m", ifname);
		return -1;
	}

	return 0;
}

/*
 * Handle ethtool stats
 */
ni_ethtool_stats_t *
__ni_ethtool_stats_init(const char *ifname, const struct ethtool_drvinfo *drv_info)
{
	ni_ethtool_stats_t *stats;

	stats = xcalloc(1, sizeof(*stats));
	stats->count = drv_info->n_stats;
	stats->data = xcalloc(stats->count, sizeof(struct ni_ethtool_counter));

	if (__ni_ethtool_get_strings(ifname, ETH_SS_STATS, stats->count, stats->data) < 0) {
		__ni_ethtool_stats_free(stats);
		return NULL;
	}

	return stats;
}

int
__ni_ethtool_stats_refresh(const char *ifname, ni_ethtool_stats_t *stats)
{
	return __ni_ethtool_get_stats(ifname, stats->count, stats->data);
}

void
__ni_ethtool_stats_free(ni_ethtool_stats_t *stats)
{
	unsigned int i;

	for (i = 0; i < stats->count; ++i)
		ni_string_free(&stats->data[i].name);
	free(stats->data);
	free(stats);
}

/*
 * Get ethtool settings from the kernel
 */
int
__ni_system_ethernet_refresh(ni_netdev_t *dev)
{
	ni_ethernet_t *ether;

	ether = ni_ethernet_new();
	ether->permanent_address.type = dev->link.hwaddr.type;
	if (__ni_system_ethernet_get(dev->name, ether) < 0) {
		ni_ethernet_free(ether);
		return -1;
	}

	ni_netdev_set_ethernet(dev, ether);
	return 0;
}

int
__ni_system_ethernet_get(const char *ifname, ni_ethernet_t *ether)
{
	struct ethtool_cmd ecmd;
	int mapped, value;

	memset(&ecmd, 0, sizeof(ecmd));
	if (__ni_ethtool(ifname, ETHTOOL_GSET, &ecmd) < 0) {
		if (errno != EOPNOTSUPP)
			ni_error("%s: ETHTOOL_GSET failed: %m", ifname);
		return -1;
	}

	mapped = __ni_ethtool_to_wicked(__ni_ethtool_speed_map, ethtool_cmd_speed(&ecmd));
	if (mapped >= 0)
		ether->link_speed = mapped;
	else
		ether->link_speed = ethtool_cmd_speed(&ecmd);

	mapped = __ni_ethtool_to_wicked(__ni_ethtool_duplex_map, ecmd.duplex);
	if (mapped < 0)
		ni_warn("%s: unknown duplex setting %d", ifname, ecmd.duplex);
	else
		ether->duplex = mapped;

	mapped = __ni_ethtool_to_wicked(__ni_ethtool_port_map, ecmd.port);
	if (mapped < 0)
		ni_warn("%s: unknown port setting %d", ifname, ecmd.port);
	else
		ether->port_type = mapped;

	ether->autoneg_enable = (ecmd.autoneg? NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE);

	/* Not used yet:
	    phy_address
	    transceiver
	 */

	__ni_ethtool_get_wol(ifname, &ether->wol);

	ether->offload.rx_csum = __ni_ethtool_get_tristate(ifname, &__ethtool_grxcsum);
	ether->offload.tx_csum = __ni_ethtool_get_tristate(ifname, &__ethtool_gtxcsum);
	ether->offload.scatter_gather = __ni_ethtool_get_tristate(ifname, &__ethtool_gsg);
	ether->offload.tso = __ni_ethtool_get_tristate(ifname, &__ethtool_gtso);
	ether->offload.ufo = __ni_ethtool_get_tristate(ifname, &__ethtool_gufo);
	ether->offload.gso = __ni_ethtool_get_tristate(ifname, &__ethtool_ggso);
	ether->offload.gro = __ni_ethtool_get_tristate(ifname, &__ethtool_ggro);

	value = __ni_ethtool_get_value(ifname, &__ethtool_gflags);
	if (value >= 0)
		ether->offload.lro = (value & ETH_FLAG_LRO)? NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;

	/* Get the permanent address */
	{
		struct {
			struct ethtool_perm_addr h;
			unsigned char data[NI_MAXHWADDRLEN];
		} parm;

		memset(&parm, 0, sizeof(parm));
		parm.h.size = sizeof(parm.data);
		if (__ni_ethtool(ifname, ETHTOOL_GPERMADDR, &parm) < 0) {
			ni_warn("%s: ETHTOOL_GPERMADDR failed", ifname);
		} else
		if (ni_link_address_length(ether->permanent_address.type) == parm.h.size) {
			ni_link_address_set(&ether->permanent_address,
					ether->permanent_address.type,
					parm.data, parm.h.size);
		}
	}

	return 0;
}

/*
 * Write ethtool settings back to kernel
 */
int
__ni_system_ethernet_update(ni_netdev_t *dev, const ni_ethernet_t *ether)
{
	if (__ni_system_ethernet_set(dev->name, ether) < 0)
		return -1;

	return __ni_system_ethernet_refresh(dev);
}

/*
 * Based on ecmd.speed and ecmd.duplex, determine ecmd.advertising.
 */
static void
__ni_system_ethernet_set_advertising(const char *ifname, struct ethtool_cmd *ecmd)
{
	if (!ecmd)
		return;

	if (ecmd->speed == SPEED_10 && ecmd->duplex == DUPLEX_HALF)
		ecmd->advertising = ADVERTISED_10baseT_Half;
	else if (ecmd->speed == SPEED_10 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_10baseT_Full;
	else if (ecmd->speed == SPEED_100 &&
		ecmd->duplex == DUPLEX_HALF)
		ecmd->advertising = ADVERTISED_100baseT_Half;
	else if (ecmd->speed == SPEED_100 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_100baseT_Full;
	else if (ecmd->speed == SPEED_1000 &&
		ecmd->duplex == DUPLEX_HALF)
		ecmd->advertising = ADVERTISED_1000baseT_Half;
	else if (ecmd->speed == SPEED_1000 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_1000baseT_Full;
	else if (ecmd->speed == SPEED_2500 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_2500baseX_Full;
	else if (ecmd->speed == SPEED_10000 &&
		ecmd->duplex == DUPLEX_FULL)
		ecmd->advertising = ADVERTISED_10000baseT_Full;
	else
		/* auto negotiate without forcing,
		 * all supported speeds will be assigned below
		 */
		ecmd->advertising = 0;

	if (ecmd->autoneg && ecmd->advertising == 0) {
		/* Auto negotiation enabled, but with
		 * unspecified speed and duplex: enable all
		 * supported speeds and duplexes.
		 */
		ecmd->advertising = (ecmd->advertising &
				~ALL_ADVERTISED_MODES) |
			(ALL_ADVERTISED_MODES &
				ecmd->supported);
		/* If driver supports unknown flags, we cannot
		 * be sure that we enable all link modes.
		 */
		if ((ecmd->supported & ALL_ADVERTISED_FLAGS) != ecmd->supported) {
			ni_error("%s: Driver supports one or more unknown flags",
				ifname);
		}
	} else if (ecmd->advertising > 0) {
		/* Enable all requested modes. */
		ecmd->advertising = (ecmd->advertising & ~ALL_ADVERTISED_MODES) |
			ecmd->advertising;
	}
}

int
__ni_system_ethernet_set(const char *ifname, const ni_ethernet_t *ether)
{
	struct ethtool_cmd ecmd;
	int mapped, value;

	__ni_ethtool_set_wol(ifname, &ether->wol);

	memset(&ecmd, 0, sizeof(ecmd));
	if (__ni_ethtool(ifname, ETHTOOL_GSET, &ecmd) < 0) {
		if (errno != EOPNOTSUPP)
			ni_error("%s: ETHTOOL_GSET failed: %m", ifname);
		return -1;
	}

	if (ether->link_speed) {
		mapped = __ni_wicked_to_ethtool(__ni_ethtool_speed_map, ether->link_speed);
		if (mapped < 0)
			mapped = ether->link_speed;
		ethtool_cmd_speed_set(&ecmd, mapped);
	}

	if (ether->duplex != NI_ETHERNET_DUPLEX_DEFAULT) {
		mapped = __ni_wicked_to_ethtool(__ni_ethtool_duplex_map, ether->duplex);
		if (mapped >= 0)
			ecmd.duplex = mapped;
	}

	if (ether->port_type != NI_ETHERNET_PORT_DEFAULT) {
		mapped = __ni_wicked_to_ethtool(__ni_ethtool_port_map, ether->port_type);
		if (mapped >= 0)
			ecmd.port = mapped;
	}

	switch (ether->autoneg_enable) {
	case NI_TRISTATE_ENABLE:
		ecmd.autoneg = 1;
		break;
	case NI_TRISTATE_DISABLE:
		ecmd.autoneg = 0;
		break;
	default: ;
	}

	/* Not used yet:
	    phy_address
	    transceiver
	 */


	__ni_ethtool_set_tristate(ifname, &__ethtool_srxcsum, ether->offload.rx_csum);
	__ni_ethtool_set_tristate(ifname, &__ethtool_stxcsum, ether->offload.tx_csum);
	__ni_ethtool_set_tristate(ifname, &__ethtool_ssg, ether->offload.scatter_gather);
	__ni_ethtool_set_tristate(ifname, &__ethtool_stso, ether->offload.tso);
	__ni_ethtool_set_tristate(ifname, &__ethtool_sufo, ether->offload.ufo);
	__ni_ethtool_set_tristate(ifname, &__ethtool_sgso, ether->offload.gso);
	__ni_ethtool_set_tristate(ifname, &__ethtool_sgro, ether->offload.gro);

	if (ether->offload.lro != NI_TRISTATE_DEFAULT) {
		value = __ni_ethtool_get_value(ifname, &__ethtool_gflags);
		if (value >= 0) {
			if (ether->offload.lro == NI_TRISTATE_ENABLE)
				value |= ETH_FLAG_LRO;
			else
				value &= ~ETH_FLAG_LRO;
		}
		__ni_ethtool_set_value(ifname, &__ethtool_sflags, value);
	}

	__ni_system_ethernet_set_advertising(ifname, &ecmd);

	if (__ni_ethtool(ifname, ETHTOOL_SSET, &ecmd) < 0) {
		if (errno != EOPNOTSUPP)
			ni_error("%s: ETHTOOL_SSET failed: %m", ifname);
		return -1;
	}

	return 0;
}
