/*
 *	ethtool handling routines
 *
 *	Copyright (C) 2018 SUSE LINUX GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *		Nirmoy Das <ndas@suse.de>
 *		Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>
#include <linux/ethtool.h>
#include <errno.h>

#include <wicked/util.h>
#include <wicked/ethtool.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "kernel.h"

/*
 * support mask to not repeat ioctl
 * calls that returned EOPNOTSUPP.
 */
enum {
	NI_ETHTOOL_SUPP_GET_DRIVER_INFO,
	NI_ETHTOOL_SUPP_GET_PERM_HWADDR,
	NI_ETHTOOL_SUPP_GET_PRIV_FLAGS,
	NI_ETHTOOL_SUPP_SET_PRIV_FLAGS,
	NI_ETHTOOL_SUPP_GET_LINK_DETECTED,
	NI_ETHTOOL_SUPP_GET_LINK_LEGACY,
	NI_ETHTOOL_SUPP_SET_LINK_LEGACY,
	NI_ETHTOOL_SUPP_GET_LINK_SETTINGS,
	NI_ETHTOOL_SUPP_SET_LINK_SETTINGS,
	NI_ETHTOOL_SUPP_GET_WAKE_ON_LAN,
	NI_ETHTOOL_SUPP_SET_WAKE_ON_LAN,
	NI_ETHTOOL_SUPP_GET_FEATURES,
	NI_ETHTOOL_SUPP_SET_FEATURES,
	NI_ETHTOOL_SUPP_GET_LEGACY_RXCSUM,
	NI_ETHTOOL_SUPP_SET_LEGACY_RXCSUM,
	NI_ETHTOOL_SUPP_GET_LEGACY_TXCSUM,
	NI_ETHTOOL_SUPP_SET_LEGACY_TXCSUM,
	NI_ETHTOOL_SUPP_GET_LEGACY_SG,
	NI_ETHTOOL_SUPP_SET_LEGACY_SG,
	NI_ETHTOOL_SUPP_GET_LEGACY_TSO,
	NI_ETHTOOL_SUPP_SET_LEGACY_TSO,
	NI_ETHTOOL_SUPP_GET_LEGACY_UFO,
	NI_ETHTOOL_SUPP_SET_LEGACY_UFO,
	NI_ETHTOOL_SUPP_GET_LEGACY_GSO,
	NI_ETHTOOL_SUPP_SET_LEGACY_GSO,
	NI_ETHTOOL_SUPP_GET_LEGACY_GRO,
	NI_ETHTOOL_SUPP_SET_LEGACY_GRO,
	NI_ETHTOOL_SUPP_GET_LEGACY_FLAGS,
	NI_ETHTOOL_SUPP_SET_LEGACY_FLAGS,
	NI_ETHTOOL_SUPP_GET_EEE,
	NI_ETHTOOL_SUPP_SET_EEE,
	NI_ETHTOOL_SUPP_GET_RING,
	NI_ETHTOOL_SUPP_SET_RING,
	NI_ETHTOOL_SUPP_GET_CHANNELS,
	NI_ETHTOOL_SUPP_SET_CHANNELS,
	NI_ETHTOOL_SUPP_GET_COALESCE,
	NI_ETHTOOL_SUPP_SET_COALESCE,
	NI_ETHTOOL_SUPP_GET_PAUSE,
	NI_ETHTOOL_SUPP_SET_PAUSE,

	NI_ETHTOOL_SUPPORT_MAX
};
static inline ni_bool_t
ni_ethtool_supported(const ni_ethtool_t *ethtool, unsigned int flag)
{
	return ethtool && ni_bitfield_testbit(&ethtool->supported, flag);
}

static inline ni_bool_t
ni_ethtool_set_supported(ni_ethtool_t *ethtool, unsigned int flag, ni_bool_t enable)
{
	return ethtool ? ni_bitfield_turnbit(&ethtool->supported, flag, enable) : FALSE;
}

/*
 * ethtool cmd error logging utilities
 */
typedef struct ni_ethtool_cmd_info {
	int		cmd;
	const char *	name;
} ni_ethtool_cmd_info_t;

static int
ni_ethtool_call(const ni_netdev_ref_t *ref, const ni_ethtool_cmd_info_t *ioc, void *evp, const char *flag)
{
	int ret;

	/*
	 * unfortunately the ethtool ioctl is not considering ifr.ifr_ifindex;
	 * we're using ref in hope there will be ethtool over netlink one day.
	 */
	ret = __ni_ethtool(ref->name, ioc->cmd, evp);
	if (ret < 0) {
		ret = -errno;
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s[%u]: ethtool %s%s failed: %m",
					ref->name, ref->index, ioc->name, flag ? flag : "");
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
					"%s[%u]: ethtool %s%s failed: %m",
					ref->name, ref->index, ioc->name, flag ? flag : "");
		errno = -ret;
	}
	return ret;
}

/*
 * ethtool uint param utils
 */
static int
ni_ethtool_check_uint_param(const ni_netdev_ref_t *ref, const char *cmd, const char *param,
			unsigned int want, unsigned int *curr, unsigned int max)
{
	if (!curr || *curr == want)
		return FALSE;

	if (want > max) {
		ni_warn("%s: ethtool %s %s crossed max limit %u",
				ref->name, cmd, param, max);
		return FALSE;
	} else {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: ethtool %s%s option from %u to %u",
				ref->name, cmd, param, *curr, want);
		*curr = want;
		return TRUE;
	}
}
static int
ni_ethtool_set_uint_param(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, unsigned int supported,
			const ni_ethtool_cmd_info_t *info, void *ecmd, const char *param,
			unsigned int want, unsigned int *curr, unsigned int max)
{
	unsigned int save = *curr;
	int ret;

	if (!ni_ethtool_supported(ethtool, supported))
		return -EOPNOTSUPP;

	if (!ni_ethtool_check_uint_param(ref, info->name, param, want, curr, max))
		return -EINVAL;

	ret = ni_ethtool_call(ref, info, ecmd, param);
	ni_ethtool_set_supported(ethtool, supported, ret != -EOPNOTSUPP);

	if (ret != 0)
		*curr = save;
	return ret;
}


/*
 * ethtool gstring set utils
 */
static unsigned int
ni_ethtool_get_gstring_count(const ni_netdev_ref_t *ref, const char *hint, unsigned int sset)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GSSET_INFO = {
		ETHTOOL_GSSET_INFO,     "get "
	};
	struct {
		struct ethtool_sset_info hdr;
		uint32_t buffer[1];
	} sset_info;

	memset(&sset_info, 0, sizeof(sset_info));
	sset_info.hdr.sset_mask = (1ULL << sset);

	if (ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GSSET_INFO, &sset_info, hint) < 0)
		return 0;

	errno = 0;
	if (sset_info.hdr.sset_mask != (1ULL << sset))
		return 0;

	return sset_info.hdr.data[0];
}

static struct ethtool_gstrings *
ni_ethtool_get_gstrings(const ni_netdev_ref_t *ref, const char *hint, unsigned int sset, unsigned int count)
{
	ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GSTRINGS = {
		ETHTOOL_GSTRINGS, "get "
	};
	struct ethtool_gstrings *gstrings;
	unsigned int i;

	if (!count || count == -1U)
		return NULL;

	gstrings = calloc(1, sizeof(*gstrings) + count * ETH_GSTRING_LEN);
	if (!gstrings) {
		ni_warn("%s: unable to allocate %u ethtool %s", ref->name, count, hint);
		return NULL;
	}

	gstrings->string_set = sset;
	gstrings->len = count;
	if (ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GSTRINGS, gstrings, hint) < 0) {
		int err = errno;
		free(gstrings);
		errno = err;
		return NULL;
	}

	/* ensure the strings are null-terminated */
	if (gstrings->len > count)
		gstrings->len = count;
	for (i = 0; i < gstrings->len; i++)
		gstrings->data[(i + 1) * ETH_GSTRING_LEN - 1] = 0;

	return gstrings;
}


/*
 * driver-info (GDRVINFO)
 */
void
ni_ethtool_driver_info_free(ni_ethtool_driver_info_t *info)
{
	if (info) {
		ni_string_free(&info->driver);
		ni_string_free(&info->version);
		ni_string_free(&info->fw_version);
		ni_string_free(&info->bus_info);
		ni_string_free(&info->erom_version);
		free(info);
	}
}

ni_ethtool_driver_info_t *
ni_ethtool_driver_info_new(void)
{
	ni_ethtool_driver_info_t *info;

	info = calloc(1, sizeof(*info));
	return info;
}

int
ni_ethtool_get_driver_info(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GDRVINFO = {
		ETHTOOL_GDRVINFO,      "get driver-info"
	};
	struct ethtool_drvinfo drv_info;
	ni_ethtool_driver_info_t *info;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_DRIVER_INFO))
		return -EOPNOTSUPP;

	ni_ethtool_driver_info_free(ethtool->driver_info);
	ethtool->driver_info = NULL;

	memset(&drv_info, 0, sizeof(drv_info));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GDRVINFO, &drv_info, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_DRIVER_INFO,
				ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (!(info = ni_ethtool_driver_info_new()))
		return -ENOMEM;

	drv_info.driver[sizeof(drv_info.driver)-1] = '\0';
	if (!ni_string_empty(drv_info.driver) && !ni_string_eq(drv_info.driver, "N/A"))
		ni_string_dup(&info->driver, drv_info.driver);
	drv_info.version[sizeof(drv_info.version)-1] = '\0';
	if (!ni_string_empty(drv_info.version) && !ni_string_eq(drv_info.version, "N/A"))
		ni_string_dup(&info->version, drv_info.version);
	drv_info.fw_version[sizeof(drv_info.fw_version)-1] = '\0';
	if (!ni_string_empty(drv_info.fw_version) && !ni_string_eq(drv_info.fw_version, "N/A"))
		ni_string_dup(&info->fw_version, drv_info.fw_version);
	 drv_info.bus_info[sizeof(drv_info.bus_info)-1] = '\0';
	 if (!ni_string_empty(drv_info.bus_info) && !ni_string_eq(drv_info.bus_info, "N/A"))
		 ni_string_dup(&info->bus_info, drv_info.bus_info);
	 drv_info.erom_version[sizeof(drv_info.erom_version)-1] = '\0';
	 if (!ni_string_empty(drv_info.erom_version) && !ni_string_eq(drv_info.erom_version, "N/A"))
		 ni_string_dup(&info->erom_version, drv_info.erom_version);

	if ((info->supports.n_priv_flags = drv_info.n_priv_flags))
		info->supports.bitmap |= NI_BIT(NI_ETHTOOL_DRIVER_SUPP_PRIV_FLAGS);
	if ((info->supports.n_stats = drv_info.n_stats))
		info->supports.bitmap |= NI_BIT(NI_ETHTOOL_DRIVER_SUPP_STATS);
	if ((info->supports.testinfo_len = drv_info.testinfo_len))
		info->supports.bitmap |= NI_BIT(NI_ETHTOOL_DRIVER_SUPP_TEST);
	if ((info->supports.eedump_len = drv_info.eedump_len))
		info->supports.bitmap |= NI_BIT(NI_ETHTOOL_DRIVER_SUPP_EEPROM);
	if ((info->supports.regdump_len = drv_info.regdump_len))
		info->supports.bitmap |= NI_BIT(NI_ETHTOOL_DRIVER_SUPP_REGDUMP);

	ethtool->driver_info = info;

	return 0;
}

static const ni_intmap_t	ni_ethtool_driver_supports_bits[] = {
	{ "priv-flags",		NI_ETHTOOL_DRIVER_SUPP_PRIV_FLAGS	},
	{ "statistics",		NI_ETHTOOL_DRIVER_SUPP_STATS		},
	{ "selftest",		NI_ETHTOOL_DRIVER_SUPP_TEST		},
	{ "eeprom-access",	NI_ETHTOOL_DRIVER_SUPP_EEPROM		},
	{ "register-dump",	NI_ETHTOOL_DRIVER_SUPP_REGDUMP		},

	{ NULL,			-1U					}
};

const char *
ni_ethtool_driver_supports_map_bit(ni_ethtool_driver_supports_bit_t bit)
{
	return ni_format_uint_mapped(bit, ni_ethtool_driver_supports_bits);
}


/*
 * perm-address (GPERMADDR)
 */
int
ni_ethtool_get_permanent_address(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, ni_hwaddr_t *perm_addr)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GPERMADDR = {
		ETHTOOL_GPERMADDR,	"get perm-addr"
	};
	struct {
		struct ethtool_perm_addr h;
		unsigned char data[NI_MAXHWADDRLEN];
	} ecmd;
	int ret;

	if (!perm_addr)
		return -EINVAL;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_PERM_HWADDR))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ecmd.h.size = sizeof(ecmd.data);
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GPERMADDR, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_PERM_HWADDR,
				ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (ecmd.h.size && ecmd.h.size == ni_link_address_length(perm_addr->type))
		return ni_link_address_set(perm_addr, perm_addr->type, ecmd.data, ecmd.h.size);

	perm_addr->len = 0;
	return -EINVAL;
}


/*
 * priv-flags (GPFLAGS,SPFLAGS)
 */
void
ni_ethtool_priv_flags_free(ni_ethtool_priv_flags_t *priv_flags)
{
	if (priv_flags) {
		ni_string_array_destroy(&priv_flags->names);
		free(priv_flags);
	}
}

ni_ethtool_priv_flags_t *
ni_ethtool_priv_flags_new(void)
{
	ni_ethtool_priv_flags_t *pflags;

	pflags = calloc(1, sizeof(*pflags));
	return pflags;
}

static inline int
ni_ethtool_get_priv_flags_names(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, ni_string_array_t *names)
{
	struct ethtool_gstrings *gstrings;
	unsigned int count, i;
	ni_stringbuf_t buf;
	const char *name;

	count = ni_ethtool_get_gstring_count(ref, " priv-flags count", ETH_SS_PRIV_FLAGS);
	if (!count) {
		if (errno == EOPNOTSUPP && ethtool->driver_info)
			count = ethtool->driver_info->supports.n_priv_flags;

		if (!count) {
			ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_PRIV_FLAGS, FALSE);
			return -EOPNOTSUPP;
		}
	}
	if (count > 32)
		count = 32;
	gstrings = ni_ethtool_get_gstrings(ref, " priv-flags names", ETH_SS_PRIV_FLAGS, count);
	if (!gstrings) {
		if (errno == EOPNOTSUPP)
			ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_PRIV_FLAGS, FALSE);
		free(gstrings);
		return errno ? -errno : -1;
	}

	ni_stringbuf_init(&buf);
	for (i = 0; i < gstrings->len; ++i) {
		name = (const char *)(gstrings->data + i * ETH_GSTRING_LEN);
		ni_stringbuf_put(&buf, name, ETH_GSTRING_LEN);
		ni_stringbuf_trim_head(&buf, " \t\n");
		ni_stringbuf_trim_tail(&buf, " \t\n");
		ni_string_array_append(names, buf.string);
		ni_stringbuf_destroy(&buf);
	}
	free(gstrings);

	if (names->count == count)
		return 0;

	ni_string_array_destroy(names);
	return -ENOMEM; /* array append */
}

static inline int
ni_ethtool_get_priv_flags_bitmap(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, unsigned int *bitmap)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GPFLAGS = {
		ETHTOOL_GPFLAGS,	"get priv-flag values"
	};
	struct ethtool_value ecmd;
	int ret;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GPFLAGS, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_PRIV_FLAGS,
				ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	*bitmap = ecmd.data;
	return 0;
}

int
ni_ethtool_get_priv_flags(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	int ret = 0;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_PRIV_FLAGS))
		return -EOPNOTSUPP;

	if (!ethtool->priv_flags) {
		if (!(ethtool->priv_flags = ni_ethtool_priv_flags_new()))
			return -ENOMEM;
	}

	ethtool->priv_flags->bitmap = 0;
	ret = ni_ethtool_get_priv_flags_bitmap(ref, ethtool, &ethtool->priv_flags->bitmap);
	if (ret < 0) {
		ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_PRIV_FLAGS, ret != -EOPNOTSUPP);
		goto cleanup;
	}

	if (!ethtool->priv_flags->names.count) {
		ret = ni_ethtool_get_priv_flags_names(ref, ethtool, &ethtool->priv_flags->names);
		if (ret < 0)
			goto cleanup;
	}

	return 0;

cleanup:
	ni_ethtool_priv_flags_free(ethtool->priv_flags);
	ethtool->priv_flags = NULL;
	return ret;
}

int
ni_ethtool_set_priv_flags(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, const ni_ethtool_priv_flags_t *pflags)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SPFLAGS = {
		ETHTOOL_SPFLAGS,	"set priv-flags"
	};
	struct ethtool_value ecmd;
	unsigned int i, bit;
	const char *name;
	ni_bool_t enabled;
	int ret;

	if (!pflags || !pflags->names.count)
		return 1; /* nothing to set */
	if (!ethtool->priv_flags && (ret = ni_ethtool_get_priv_flags(ref, ethtool)) < 0)
		return ret;
	if (!ethtool->priv_flags || !ethtool->priv_flags->names.count)
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ecmd.data = ethtool->priv_flags->bitmap;
	/* set every single bit separately in case one fails? */
	for (i = 0; i < pflags->names.count; ++i) {
		name = pflags->names.data[i];
		if (ni_string_empty(name))
			continue;

		enabled = !!(pflags->bitmap & NI_BIT(i));
		bit = ni_string_array_index(&ethtool->priv_flags->names, name);
		if (bit == -1U) {
			ni_info("%s: unable to set unknown driver private flag '%s'",
					ref->name, name);
			continue;
		}

		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: setting driver private flag '%s' to %s",
				ref->name, name, ni_format_boolean(enabled));
		if (enabled)
			ecmd.data |= NI_BIT(bit);
		else
			ecmd.data &= ~NI_BIT(bit);
	}
	if (ecmd.data == ethtool->priv_flags->bitmap)
		return 0;

	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_SPFLAGS, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_SET_PRIV_FLAGS,
				ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	return 0;
}

int
ni_ethtool_get_link_detected(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GLINK  = {
		ETHTOOL_GLINK,		"get link detection (GLINK"
	};
	struct ethtool_value ecmd;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_DETECTED))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GLINK, &ecmd,  NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_DETECTED,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	ni_tristate_set(&ethtool->link_detected, !!ecmd.data);
	return 0;
}

/*
 * Link control and status settings
 */
void
ni_ethtool_link_settings_free(ni_ethtool_link_settings_t *settings)
{
	if (settings) {
		ni_bitfield_destroy(&settings->supported);
		ni_bitfield_destroy(&settings->advertising);
		ni_bitfield_destroy(&settings->lp_advertising);
		free(settings);
	}
}

static inline void
ni_ethtool_link_settings_init(ni_ethtool_link_settings_t *settings)
{
	if (settings) {
		settings->autoneg	= NI_TRISTATE_DEFAULT;
		settings->port		= NI_ETHTOOL_PORT_DEFAULT;
		settings->speed		= NI_ETHTOOL_SPEED_UNKNOWN;
		settings->duplex	= NI_ETHTOOL_DUPLEX_UNKNOWN;
		settings->transceiver	= NI_ETHTOOL_XCVR_UNKNOWN;
		settings->phy_address	= NI_ETHTOOL_PHYAD_UNKNOWN;
	}
}

ni_ethtool_link_settings_t *
ni_ethtool_link_settings_new(void)
{
	ni_ethtool_link_settings_t *settings;

	settings = calloc(1, sizeof(*settings));
	ni_ethtool_link_settings_init(settings);
	return settings;
}

/*
 * Link mode bit names
 * as separate tables
 */
static const ni_intmap_t		ni_ethtool_link_adv_speed_names[] = {
	{ "10baseT-Half",		ETHTOOL_LINK_MODE_10baseT_Half_BIT		},
	{ "10baseT/Half",		ETHTOOL_LINK_MODE_10baseT_Half_BIT		},
	{ "10baseT-Full",		ETHTOOL_LINK_MODE_10baseT_Full_BIT		},
	{ "10baseT/Full",		ETHTOOL_LINK_MODE_10baseT_Full_BIT		},
	{ "100baseT-Half",		ETHTOOL_LINK_MODE_100baseT_Half_BIT		},
	{ "100baseT/Half",		ETHTOOL_LINK_MODE_100baseT_Half_BIT		},
	{ "100baseT-Full",		ETHTOOL_LINK_MODE_100baseT_Full_BIT		},
	{ "100baseT/Full",		ETHTOOL_LINK_MODE_100baseT_Full_BIT		},
	{ "1000baseT-Half",		ETHTOOL_LINK_MODE_1000baseT_Half_BIT		},
	{ "1000baseT/Half",		ETHTOOL_LINK_MODE_1000baseT_Half_BIT		},
	{ "1000baseT-Full",		ETHTOOL_LINK_MODE_1000baseT_Full_BIT		},
	{ "1000baseT/Full",		ETHTOOL_LINK_MODE_1000baseT_Full_BIT		},
	{ "1000baseX-Full",		ETHTOOL_LINK_MODE_1000baseX_Full_BIT		},
	{ "1000baseX/Full",		ETHTOOL_LINK_MODE_1000baseX_Full_BIT		},
	{ "1000baseKX-Full",		ETHTOOL_LINK_MODE_1000baseKX_Full_BIT		},
	{ "1000baseKX/Full",		ETHTOOL_LINK_MODE_1000baseKX_Full_BIT		},
	{ "2500baseT-Full",		ETHTOOL_LINK_MODE_2500baseT_Full_BIT		},
	{ "2500baseT/Full",		ETHTOOL_LINK_MODE_2500baseT_Full_BIT		},
	{ "2500baseX-Full",		ETHTOOL_LINK_MODE_2500baseX_Full_BIT		},
	{ "2500baseX/Full",		ETHTOOL_LINK_MODE_2500baseX_Full_BIT		},
	{ "5000baseT-Full",		ETHTOOL_LINK_MODE_5000baseT_Full_BIT		},
	{ "5000baseT/Full",		ETHTOOL_LINK_MODE_5000baseT_Full_BIT		},
	{ "10000baseT-Full",		ETHTOOL_LINK_MODE_10000baseT_Full_BIT		},
	{ "10000baseT/Full",		ETHTOOL_LINK_MODE_10000baseT_Full_BIT		},
	{ "10000baseKX4-Full",		ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT		},
	{ "10000baseKX4/Full",		ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT		},
	{ "10000baseKR-Full",		ETHTOOL_LINK_MODE_10000baseKR_Full_BIT		},
	{ "10000baseKR/Full",		ETHTOOL_LINK_MODE_10000baseKR_Full_BIT		},
	{ "10000baseR-FEC",		ETHTOOL_LINK_MODE_10000baseR_FEC_BIT		},
	{ "10000baseR/FEC",		ETHTOOL_LINK_MODE_10000baseR_FEC_BIT		},
	{ "10000baseCR-Full",		ETHTOOL_LINK_MODE_10000baseCR_Full_BIT		},
	{ "10000baseCR/Full",		ETHTOOL_LINK_MODE_10000baseCR_Full_BIT		},
	{ "10000baseSR-Full",		ETHTOOL_LINK_MODE_10000baseSR_Full_BIT		},
	{ "10000baseSR/Full",		ETHTOOL_LINK_MODE_10000baseSR_Full_BIT		},
	{ "10000baseLR-Full",		ETHTOOL_LINK_MODE_10000baseLR_Full_BIT		},
	{ "10000baseLR/Full",		ETHTOOL_LINK_MODE_10000baseLR_Full_BIT		},
	{ "10000baseLRM-Full",		ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT		},
	{ "10000baseLRM/Full",		ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT		},
	{ "10000baseER-Full",		ETHTOOL_LINK_MODE_10000baseER_Full_BIT		},
	{ "10000baseER/Full",		ETHTOOL_LINK_MODE_10000baseER_Full_BIT		},
	{ "20000baseMLD2-Full",		ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT	},
	{ "20000baseMLD2/Full",		ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT	},
	{ "20000baseKR2-Full",		ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT		},
	{ "20000baseKR2/Full",		ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT		},
	{ "25000baseCR-Full",		ETHTOOL_LINK_MODE_25000baseCR_Full_BIT		},
	{ "25000baseCR/Full",		ETHTOOL_LINK_MODE_25000baseCR_Full_BIT		},
	{ "25000baseKR-Full",		ETHTOOL_LINK_MODE_25000baseKR_Full_BIT		},
	{ "25000baseKR/Full",		ETHTOOL_LINK_MODE_25000baseKR_Full_BIT		},
	{ "25000baseSR-Full",		ETHTOOL_LINK_MODE_25000baseSR_Full_BIT		},
	{ "25000baseSR/Full",		ETHTOOL_LINK_MODE_25000baseSR_Full_BIT		},
	{ "40000baseKR4-Full",		ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT		},
	{ "40000baseKR4/Full",		ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT		},
	{ "40000baseCR4-Full",		ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT		},
	{ "40000baseCR4/Full",		ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT		},
	{ "40000baseSR4-Full",		ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT		},
	{ "40000baseSR4/Full",		ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT		},
	{ "40000baseLR4-Full",		ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT		},
	{ "40000baseLR4/Full",		ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT		},
	{ "50000baseCR2-Full",		ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT		},
	{ "50000baseCR2/Full",		ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT		},
	{ "50000baseKR2-Full",		ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT		},
	{ "50000baseKR2/Full",		ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT		},
	{ "50000baseSR2-Full",		ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT		},
	{ "50000baseSR2/Full",		ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT		},
	{ "56000baseKR4-Full",		ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT		},
	{ "56000baseKR4/Full",		ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT		},
	{ "56000baseCR4-Full",		ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT		},
	{ "56000baseCR4/Full",		ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT		},
	{ "56000baseSR4-Full",		ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT		},
	{ "56000baseSR4/Full",		ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT		},
	{ "56000baseLR4-Full",		ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT		},
	{ "56000baseLR4/Full",		ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT		},
	{ "100000baseKR4-Full",		ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT	},
	{ "100000baseKR4/Full",		ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT	},
	{ "100000baseSR4-Full",		ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT	},
	{ "100000baseSR4/Full",		ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT	},
	{ "100000baseCR4-Full",		ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT	},
	{ "100000baseCR4/Full",		ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT	},
	{ "100000baseLR4-ER4-Full",	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT	},
	{ "100000baseLR4-ER4/Full",	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT	},

	{ NULL,			-1U							}
};
static const ni_intmap_t		ni_ethtool_link_adv_autoneg_names[] = {
	{ "Autoneg",			ETHTOOL_LINK_MODE_Autoneg_BIT			},

	{ NULL,			-1U							}
};
static const ni_intmap_t		ni_ethtool_link_adv_pause_names[] = {
	{ "Symetric",			ETHTOOL_LINK_MODE_Pause_BIT			},
	{ "Asymetric",			ETHTOOL_LINK_MODE_Asym_Pause_BIT		},

	{ NULL,			-1U							}
};
static const ni_intmap_t		ni_ethtool_link_adv_port_names[] = {
	{ "TP",				ETHTOOL_LINK_MODE_TP_BIT			},
	{ "AUI",			ETHTOOL_LINK_MODE_AUI_BIT			},
	{ "MII",			ETHTOOL_LINK_MODE_MII_BIT			},
	{ "BNC",			ETHTOOL_LINK_MODE_BNC_BIT			},
	{ "FIBRE",			ETHTOOL_LINK_MODE_FIBRE_BIT			},
	{ "Backplane",			ETHTOOL_LINK_MODE_Backplane_BIT			},

	{ NULL,			-1U							}
};
static const ni_intmap_t		ni_ethtool_link_adv_fec_names[] = {
	{ "None",			ETHTOOL_LINK_MODE_FEC_NONE_BIT			},
	{ "BaseR",			ETHTOOL_LINK_MODE_FEC_BASER_BIT 		},
	{ "RS",				ETHTOOL_LINK_MODE_FEC_RS_BIT			},

	{ NULL,			-1U							}
};

unsigned int
ni_ethtool_link_mode_nwords(void)
{
	return (__ETHTOOL_LINK_MODE_LAST + 32) / 32;
}

unsigned int
ni_ethtool_link_mode_nbits(void)
{
	return ni_ethtool_link_mode_nwords() * 32;
}

const char *
ni_ethtool_link_adv_name(unsigned int type)
{
	const char *name;

	if ((name = ni_ethtool_link_adv_speed_name(type)))
		return name;
	if ((name = ni_ethtool_link_adv_pause_name(type)))
		return name;
	if ((name = ni_ethtool_link_adv_port_name(type)))
		return name;
	if ((name = ni_ethtool_link_adv_fec_name(type)))
		return name;
	return ni_format_uint_mapped(type, ni_ethtool_link_adv_autoneg_names);
}

ni_bool_t
ni_ethtool_link_adv_type(const char *name, unsigned int *type)
{
	if (ni_ethtool_link_adv_speed_type(name, type))
		return TRUE;
	if (ni_ethtool_link_adv_pause_type(name, type))
		return TRUE;
	if (ni_ethtool_link_adv_port_type(name, type))
		return TRUE;
	if (ni_ethtool_link_adv_fec_type(name, type))
		return TRUE;
	return ni_parse_uint_mapped(name, ni_ethtool_link_adv_autoneg_names, type) == 0;
}

ni_bool_t
ni_ethtool_link_adv_autoneg(const ni_bitfield_t *bitfield)
{
	return	ni_bitfield_testbit(bitfield, ETHTOOL_LINK_MODE_Autoneg_BIT);
}

ni_bool_t
ni_ethtool_link_adv_set_autoneg(ni_bitfield_t *bitfield, ni_bool_t enabled)
{
	if (enabled)
		return ni_bitfield_setbit(bitfield, ETHTOOL_LINK_MODE_Autoneg_BIT);
	else
		return ni_bitfield_clearbit(bitfield, ETHTOOL_LINK_MODE_Autoneg_BIT);
}

const char *
ni_ethtool_link_adv_pause_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_link_adv_pause_names);
}

ni_bool_t
ni_ethtool_link_adv_pause_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_link_adv_pause_names, type) == 0;
}

const char *
ni_ethtool_link_adv_port_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_link_adv_port_names);
}

ni_bool_t
ni_ethtool_link_adv_port_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_link_adv_port_names, type) == 0;
}

const char *
ni_ethtool_link_adv_speed_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_link_adv_speed_names);
}

ni_bool_t
ni_ethtool_link_adv_speed_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_link_adv_speed_names, type) == 0;
}

const char *
ni_ethtool_link_adv_fec_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_link_adv_fec_names);
}

ni_bool_t
ni_ethtool_link_adv_fec_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_link_adv_fec_names, type) == 0;
}

/*
 * Link port types
 */
static const ni_intmap_t		ni_ethtool_link_port_type_names[] =  {
	{ "TP",				NI_ETHTOOL_PORT_TP				},
	{ "AUI",			NI_ETHTOOL_PORT_AUI				},
	{ "BNC",			NI_ETHTOOL_PORT_BNC				},
	{ "MII",			NI_ETHTOOL_PORT_MII				},
	{ "DA",				NI_ETHTOOL_PORT_DA				},
	{ "Fibre",			NI_ETHTOOL_PORT_FIBRE				},
	{ "None",			NI_ETHTOOL_PORT_NONE				},
	{ "Other",			NI_ETHTOOL_PORT_OTHER				},

	{ NULL,				NI_ETHTOOL_PORT_DEFAULT				}
};

const char *
ni_ethtool_link_port_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_link_port_type_names);
}

ni_bool_t
ni_ethtool_link_port_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_link_port_type_names, type) == 0;
}

/*
 * Link duplex types
 */
static const ni_intmap_t		ni_ethtool_link_duplex_names[] = {
	{ "half",			NI_ETHTOOL_DUPLEX_HALF				},
	{ "full",			NI_ETHTOOL_DUPLEX_FULL				},

	{ NULL,				NI_ETHTOOL_DUPLEX_UNKNOWN			}
};

const char *
ni_ethtool_link_duplex_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_link_duplex_names);
}

ni_bool_t
ni_ethtool_link_duplex_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_link_duplex_names, type) == 0;
}

/*
 * Link MDIO
 */
static const ni_intmap_t		ni_ethtool_link_mdio_names[] = {
	{ "C22",			NI_ETHTOOL_MDIO_SUPPORTS_C22			},
	{ "C45",			NI_ETHTOOL_MDIO_SUPPORTS_C45			},

	{ NULL,				-1U						}
};

const char *
ni_ethtool_link_mdio_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_link_mdio_names);
}

ni_bool_t
ni_ethtool_link_mdio_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_link_mdio_names, type) == 0;
}

/*
 * Link transceiver / xcvr
 */
static const ni_intmap_t		ni_ethtool_link_xcvr_names[] = {
	{ "internal",			NI_ETHTOOL_XCVR_INTERNAL			},
	{ "external",			NI_ETHTOOL_XCVR_EXTERNAL			},

	{ NULL,				NI_ETHTOOL_XCVR_UNKNOWN				}
};

const char *
ni_ethtool_link_xcvr_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_link_xcvr_names);
}

ni_bool_t
ni_ethtool_link_xcvr_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_link_xcvr_names, type) == 0;
}

/*
 * Link MDI(-X)
 */
static const ni_intmap_t		ni_ethtool_link_mdix_names[] = {
	{ "mdi",			NI_ETHTOOL_MDI					},
	{ "mdi-x",			NI_ETHTOOL_MDI_X				},
	{ "auto-mdi",			NI_ETHTOOL_MDI_AUTO				},
	{ "auto-mdi-x",			NI_ETHTOOL_MDI_X_AUTO				},

	{ NULL,				-1U						}
};

const char *
ni_ethtool_link_mdix_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_link_mdix_names);
}

ni_bool_t
ni_ethtool_link_mdix_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_link_mdix_names, type) == 0;
}

/*
 * Map MDI(-X) control and status to our enum
 */
static void
ni_ethtool_get_link_settings_map_mdix(ni_ethtool_link_settings_t *link, uint8_t ctrl, uint8_t status)
{
	if (ctrl == ETH_TP_MDI)
		link->tp_mdix = NI_ETHTOOL_MDI;
	else
	if (ctrl == ETH_TP_MDI_X)
		link->tp_mdix = NI_ETHTOOL_MDI_X;
	else
	if (ctrl == ETH_TP_MDI_AUTO) {
		if (status == ETH_TP_MDI)
			link->tp_mdix = NI_ETHTOOL_MDI_AUTO;
		else
		if (status == ETH_TP_MDI_X)
			link->tp_mdix = NI_ETHTOOL_MDI_X_AUTO;
	}
}

/*
 * Utility to check if link mode array has a bit/word set
 * to avoid useless empty dicts on the wire/in show-xml.
 */
static ni_bool_t
ni_ethtool_get_link_settings_adv_isset(int8_t nwords, const uint32_t *words)
{
	int8_t word;

	for (word = 0; word < nwords; ++word) {
		if (words[word])
			return TRUE;
	}
	return FALSE;
}

/*
 * Set link advertising bits by speed and duplex
 */
static void
ni_ethtool_set_adv_by_speed(ni_bitfield_t *adv, unsigned int speed, uint8_t duplex)
{
	switch (speed) {
	case SPEED_10:
		if (duplex == NI_ETHTOOL_DUPLEX_HALF || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10baseT_Half_BIT);
		}
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10baseT_Full_BIT);
		}
		break;
	case SPEED_100:
		if (duplex == NI_ETHTOOL_DUPLEX_HALF || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_100baseT_Half_BIT);
		}
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_100baseT_Full_BIT);
		}
		break;
	case SPEED_1000:
		if (duplex == NI_ETHTOOL_DUPLEX_HALF || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_1000baseT_Half_BIT);
		}
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_1000baseT_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_1000baseX_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_1000baseKX_Full_BIT);
		}
		break;
	case SPEED_2500:
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_2500baseT_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_2500baseX_Full_BIT);
		}
		break;
	case SPEED_5000:
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_5000baseT_Full_BIT);
		}
		break;
	case SPEED_10000:
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10000baseT_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10000baseCR_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10000baseER_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10000baseKR_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10000baseLR_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10000baseSR_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_10000baseR_FEC_BIT);
		}
		break;
	case SPEED_20000:
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT);
		}
		break;
	case SPEED_25000:
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_25000baseCR_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_25000baseKR_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_25000baseSR_Full_BIT);
		}
		break;
	case SPEED_40000:
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT);
		}
		break;
	case SPEED_50000:
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT);
		}
		break;
	case SPEED_56000:
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT);
		}
		break;
	case SPEED_100000:
		if (duplex == NI_ETHTOOL_DUPLEX_FULL || duplex == NI_ETHTOOL_DUPLEX_UNKNOWN) {
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT);
			ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT);
		}
		break;
	default:
		break;
	}
}

/*
 * Set link non-mode advertising bit flags
 */
static void
ni_ethtool_set_adv_flags_bitfield(ni_bitfield_t *adv)
{
	ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_Autoneg_BIT);
	ni_bitfield_setbit(adv, ETHTOOL_LINK_MODE_Pause_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_Asym_Pause_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_TP_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_AUI_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_MII_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_BNC_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_FIBRE_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_Backplane_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_FEC_NONE_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_FEC_BASER_BIT);
	ni_bitfield_setbit(adv,	ETHTOOL_LINK_MODE_FEC_RS_BIT);
}

/*
 * Set custom link mode advertising, by speed or all supported
 */
static void
ni_ethtool_set_advertise(ni_bitfield_t *adv, const ni_bitfield_t *sup,
		const ni_bitfield_t *old, const ni_netdev_ref_t *ref,
		const ni_ethtool_link_settings_t *cfg)
{
	ni_bitfield_t tmp = NI_BITFIELD_INIT;
	ni_bitfield_t flg = NI_BITFIELD_INIT;
	unsigned int bit, bits;
	ni_bool_t want, have;
	const char *modify;
	const char *name;
	char *hex = NULL;

	ni_ethtool_set_adv_flags_bitfield(&flg);
	if ((bits = ni_bitfield_bits(&cfg->advertising))) {
		/* inform or clear unsupported custom advertise modes */

		for (bit = 0; bit < bits; ++bit) {
			/* ignore requested non-mode flags... */
			if (ni_bitfield_testbit(&flg, bit))
				continue;

			/* do we have to change this mode?    */
			want   = ni_bitfield_testbit(&cfg->advertising, bit);
			have   = ni_bitfield_testbit(old, bit);
			modify = NULL;
			if (want && !have)
				modify = "enable";
			else
			if (have && !want)
				modify = "disable";
			else {
				ni_bitfield_turnbit(adv, bit, have);
				continue;
			}

			/* get the name or hex value of it */
			if (!(name = ni_ethtool_link_adv_name(bit))) {
				ni_bitfield_setbit(&tmp, bit);
				ni_bitfield_format(&tmp, &hex, FALSE);
				ni_bitfield_destroy(&tmp);
				name = hex;
			}

			if (ni_bitfield_testbit(sup, bit)) {
				ni_bitfield_turnbit(adv, bit, want);

				ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to %s advertise of link mode '%s'",
					ref->name, modify, name);
			} else {
				ni_bitfield_clearbit(adv, bit);

				ni_warn("%s: ethtool request to %s advertise of link mode '%s'"
					" is unsupported", ref->name, modify, name);
			}
			ni_string_free(&hex);
		}
	} else {
		/* no custom advertise, try to set from speed and duplex */
		ni_ethtool_set_adv_by_speed(adv, cfg->speed, cfg->duplex);

		bits = ni_bitfield_bits(adv);
		for (bit = 0; bit < bits; ++bit) {
			want   = ni_bitfield_testbit(adv, bit);
			have   = ni_bitfield_testbit(old, bit);
			modify = NULL;
			if (want && !have)
				modify = "enable";
			else
			if (have && !want)
				modify = "disable";
			else {
				ni_bitfield_turnbit(adv, bit, have);
				continue;
			}

			if (!(name = ni_ethtool_link_adv_name(bit))) {
				ni_bitfield_setbit(&tmp, bit);
				ni_bitfield_format(&tmp, &hex, FALSE);
				ni_bitfield_destroy(&tmp);
				name = hex;
			}

			if (ni_bitfield_testbit(sup, bit)) {
				ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to %s advertise link mode '%s' by speed",
					ref->name, modify, name);
			} else {
				/* discard unsupported modes _we've_ choosen by speed */
				ni_bitfield_clearbit(adv, bit);
				ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_IFCONFIG,
					"%s: ethtool request to %s advertise link mode '%s' by speed"
					" is unsupported", ref->name, modify, name);
			}
			ni_string_free(&hex);
		}
	}

	if (!ni_bitfield_isset(adv)) {
		/* no advertise mode bits set yet, enable all supported */
		ni_bitfield_set_data(adv, ni_bitfield_get_data(sup), ni_bitfield_bytes(sup));
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
			"%s: ethtool request to advertise all supported link modes",
			ref->name);
	}

	/* safeguard to ensure, adv is at least as long as old settings */
	if ((bits = ni_bitfield_bits(old)) && bits > ni_bitfield_bits(adv)) {
		ni_bitfield_turnbit(adv, bits - 1, ni_bitfield_testbit(adv, bits - 1));
	}
}

/*
 * Legacy link settings ioctl (GSET,SSET)
 */
static int
ni_ethtool_get_link_settings_legacy(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GSET  = {
		ETHTOOL_GSET,		"get link-settings (GSET)"
	};
	ni_ethtool_link_settings_t *link;
	struct {
		struct ethtool_cmd settings;
	} ecmd;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_LEGACY))
		return -EOPNOTSUPP;

	ni_ethtool_link_settings_free(ethtool->link_settings);
	ethtool->link_settings = NULL;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GSET, &ecmd.settings, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_LEGACY,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (!(link = ni_ethtool_link_settings_new()))
		return -ENOMEM;

	link->autoneg   = ecmd.settings.autoneg == AUTONEG_ENABLE;
	link->port      = ecmd.settings.port;
	link->speed     = ethtool_cmd_speed(&ecmd.settings);
	link->duplex    = ecmd.settings.duplex;

	if (link->port == NI_ETHTOOL_PORT_TP) {
		ni_ethtool_get_link_settings_map_mdix(link,
				ecmd.settings.eth_tp_mdix_ctrl,
				ecmd.settings.eth_tp_mdix);
	}

	link->transceiver  = ecmd.settings.transceiver;
	link->phy_address  = ecmd.settings.phy_address;
	link->mdio_support = ecmd.settings.mdio_support;

	link->nwords = sizeof(ecmd.settings.supported) / 4;
	if (ni_ethtool_get_link_settings_adv_isset(link->nwords, &ecmd.settings.supported)) {
		ni_bitfield_set_data(&link->supported, &ecmd.settings.supported,
						sizeof(ecmd.settings.supported));
	}
	if (ni_ethtool_get_link_settings_adv_isset(link->nwords, &ecmd.settings.advertising)) {
		ni_bitfield_set_data(&link->advertising, &ecmd.settings.advertising,
						sizeof(ecmd.settings.advertising));
	}
	if (ni_ethtool_get_link_settings_adv_isset(link->nwords, &ecmd.settings.lp_advertising)) {
		ni_bitfield_set_data(&link->advertising, &ecmd.settings.lp_advertising,
						sizeof(ecmd.settings.lp_advertising));
	}

	ethtool->link_settings = link;
	return 0;
}

static int
ni_ethtool_set_link_settings_legacy(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool,
					const ni_ethtool_link_settings_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GSET  = {
		ETHTOOL_GSET,		"get link-settings (GSET)"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SSET  = {
		ETHTOOL_SSET,		"set link-settings (SSET)"
	};
	struct {
		struct ethtool_cmd settings;
	} ecmd;
	ni_bitfield_t adv = NI_BITFIELD_INIT;
	ni_bitfield_t sup = NI_BITFIELD_INIT;
	ni_bitfield_t old = NI_BITFIELD_INIT;
	int ret;

	if (!cfg)
		return 1;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_LEGACY) ||
	    !ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_LINK_LEGACY))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GSET, &ecmd.settings, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_LEGACY,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (ni_tristate_is_enabled(cfg->autoneg)) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to enable link auto-negotiation",
				ref->name);
		ecmd.settings.autoneg = AUTONEG_ENABLE;
	} else
	if (ni_tristate_is_disabled(cfg->autoneg)) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to disable link auto-negotiation",
				ref->name);
		ecmd.settings.autoneg = AUTONEG_DISABLE;
	}

	if (cfg->speed && cfg->speed != NI_ETHTOOL_SPEED_UNKNOWN &&
	    ethtool_cmd_speed(&ecmd.settings) != cfg->speed &&
	    ethtool_validate_speed(cfg->speed)) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set speed to %u",
				ref->name, cfg->speed);
		ethtool_cmd_speed_set(&ecmd.settings, cfg->speed);
	}
	if (cfg->duplex != NI_ETHTOOL_DUPLEX_UNKNOWN && ecmd.settings.duplex != cfg->duplex) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set duplex to %s",
				ref->name, ni_ethtool_link_duplex_name(cfg->duplex));
		ecmd.settings.duplex = cfg->duplex;
	}

	if (cfg->port != NI_ETHTOOL_PORT_DEFAULT && ecmd.settings.port != cfg->port) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set port type %s",
				ref->name, ni_ethtool_link_port_name(cfg->port));
		ecmd.settings.port = cfg->port;
	}
	if (cfg->phy_address != NI_ETHTOOL_PHYAD_UNKNOWN &&
	    cfg->phy_address != ecmd.settings.phy_address) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set PHY address to %u",
				ref->name, cfg->phy_address);
		ecmd.settings.phy_address = cfg->phy_address;
	}
	if (cfg->transceiver != NI_ETHTOOL_XCVR_UNKNOWN &&
	    cfg->transceiver != ecmd.settings.transceiver) {
		const char *xcvr = ni_ethtool_link_xcvr_name(cfg->transceiver);
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set transceiver to %s [deprecated]",
				ref->name, xcvr ? xcvr : ni_sprint_uint(cfg->transceiver));
		ecmd.settings.transceiver = cfg->transceiver;
	}

	if (cfg->tp_mdix != ETH_TP_MDI_INVALID) {
		if (ecmd.settings.eth_tp_mdix_ctrl != ETH_TP_MDI_INVALID) {
			switch (cfg->tp_mdix) {
			case NI_ETHTOOL_MDI:
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
						"%s: ethtool request to set %s", ref->name,
						ni_ethtool_link_mdix_name(cfg->tp_mdix));
				ecmd.settings.eth_tp_mdix_ctrl = ETH_TP_MDI;
				break;
			case NI_ETHTOOL_MDI_X:
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
						"%s: ethtool request to set %s", ref->name,
						ni_ethtool_link_mdix_name(cfg->tp_mdix));
				ecmd.settings.eth_tp_mdix_ctrl = ETH_TP_MDI_X;
				break;
			default:
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
						"%s: ethtool request to set auto mdi/mdi-x",
						ref->name);
				ecmd.settings.eth_tp_mdix_ctrl = ETH_TP_MDI_AUTO;
				break;
			}
		} else {
			ni_warn("%s: ethtool does not support to set link MDI/MDI-X", ref->name);
		}
	}

	if (ecmd.settings.autoneg == AUTONEG_ENABLE) {
		ni_bitfield_set_data(&sup, &ecmd.settings.supported, sizeof(ecmd.settings.supported));
		ni_bitfield_set_data(&old, &ecmd.settings.advertising, sizeof(ecmd.settings.advertising));

		/* apply adv bitfield data to advertising in the settings */
		ni_ethtool_set_advertise(&adv, &sup, &old, ref, cfg);
		if (ni_bitfield_bytes(&adv) >= sizeof(ecmd.settings.advertising)) {
			memcpy(&ecmd.settings.advertising, ni_bitfield_get_data(&adv),
						sizeof(ecmd.settings.advertising));
		}
		ni_bitfield_destroy(&sup);
		ni_bitfield_destroy(&old);
		ni_bitfield_destroy(&adv);
	}

	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_SSET, &ecmd.settings, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_SET_LINK_LEGACY,
				ret != -EOPNOTSUPP);

	return ret;
}

/*
 * Link settings (GLINKSETTINGS,SLINKSETTINGS)
 */
static int
ni_ethtool_get_link_settings_current(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GLINKSETINGS = {
		ETHTOOL_GLINKSETTINGS,	"get link settings"
	};
	struct {
		struct ethtool_link_settings settings;
		uint32_t link_mode_maps[SCHAR_MAX * 3];
	} ecmd;
	ni_ethtool_link_settings_t *link;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_SETTINGS))
		return -EOPNOTSUPP;

	ni_ethtool_link_settings_free(ethtool->link_settings);
	ethtool->link_settings = NULL;

	memset(&ecmd, 0, sizeof(ecmd));
	if (ethtool->link_settings && ethtool->link_settings->nwords > 0)
		ecmd.settings.link_mode_masks_nwords = ethtool->link_settings->nwords;
	else
		ecmd.settings.link_mode_masks_nwords = ni_ethtool_link_mode_nwords();

	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GLINKSETINGS, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_SETTINGS,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (ecmd.settings.link_mode_masks_nwords < 0) {
		int8_t nwords = -ecmd.settings.link_mode_masks_nwords;
		/*
		 * if src/linux/ethtool.h does not match kernel nwords,
		 * kernel reports it as negative number ... retry.
		 */
		memset(&ecmd, 0, sizeof(ecmd));
		ecmd.settings.link_mode_masks_nwords = nwords;
		if ((ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GLINKSETINGS, &ecmd, NULL)) < 0)
			return ret;
	}

	if (!(link = ni_ethtool_link_settings_new()))
		return -ENOMEM;

	link->autoneg   = ecmd.settings.autoneg == AUTONEG_ENABLE;
	link->port      = ecmd.settings.port;
	link->speed     = ecmd.settings.speed;
	link->duplex    = ecmd.settings.duplex;

	if (link->port == NI_ETHTOOL_PORT_TP) {
		ni_ethtool_get_link_settings_map_mdix(link,
				ecmd.settings.eth_tp_mdix_ctrl,
				ecmd.settings.eth_tp_mdix);
	}

	link->transceiver  = ecmd.settings.transceiver;
	link->phy_address  = ecmd.settings.phy_address;
	link->mdio_support = ecmd.settings.mdio_support;

	if (ecmd.settings.link_mode_masks_nwords > 0) {
		size_t len, off;

		link->nwords = ecmd.settings.link_mode_masks_nwords;
		len = link->nwords * sizeof(uint32_t);

		off = 0;
		if (ni_ethtool_get_link_settings_adv_isset(link->nwords,
					&ecmd.link_mode_maps[off])) {
			ni_bitfield_set_data(&link->supported,
					&ecmd.link_mode_maps[off], len);
		}

		off += link->nwords;
		if (ni_ethtool_get_link_settings_adv_isset(link->nwords,
					&ecmd.link_mode_maps[off])) {
			ni_bitfield_set_data(&link->advertising,
				&ecmd.link_mode_maps[off], len);
		}

		off += link->nwords;
		if (ni_ethtool_get_link_settings_adv_isset(link->nwords,
					&ecmd.link_mode_maps[off])) {
			ni_bitfield_set_data(&link->lp_advertising,
				&ecmd.link_mode_maps[off], len);
		}
	}

	ethtool->link_settings = link;
	return 0;
}

static int
ni_ethtool_set_link_settings_current(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool,
					const ni_ethtool_link_settings_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GLINKSETINGS = {
		ETHTOOL_GLINKSETTINGS,	"get link settings"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SLINKSETINGS = {
		ETHTOOL_SLINKSETTINGS,	"set link settings"
	};
	struct {
		struct ethtool_link_settings settings;
		uint32_t link_mode_maps[SCHAR_MAX * 3];
	} ecmd;
	ni_bitfield_t adv = NI_BITFIELD_INIT;
	ni_bitfield_t sup = NI_BITFIELD_INIT;
	ni_bitfield_t old = NI_BITFIELD_INIT;
	int ret;

	if (!cfg)
		return 1;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_SETTINGS) ||
	    !ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_LINK_SETTINGS))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	if (ethtool->link_settings && ethtool->link_settings->nwords > 0)
		ecmd.settings.link_mode_masks_nwords = ethtool->link_settings->nwords;
	else
		ecmd.settings.link_mode_masks_nwords = ni_ethtool_link_mode_nwords();

	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GLINKSETINGS, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_LINK_SETTINGS,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (ecmd.settings.link_mode_masks_nwords < 0) {
		int8_t nwords = -ecmd.settings.link_mode_masks_nwords;
		/*
		 * if src/linux/ethtool.h does not match kernel nwords,
		 * kernel reports it as negative number ... retry.
		 */
		memset(&ecmd, 0, sizeof(ecmd));
		ecmd.settings.link_mode_masks_nwords = nwords;
		if ((ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GLINKSETINGS, &ecmd, NULL)) < 0)
			return ret;
		if (ecmd.settings.link_mode_masks_nwords < 0 ||
		    ecmd.settings.link_mode_masks_nwords != nwords) {
			ni_warn("%s: link mode nwords detection failure (%d vs. %d)",
				ref->name, ecmd.settings.link_mode_masks_nwords, nwords);
			ecmd.settings.link_mode_masks_nwords = 0;
		}
	}

	if (ni_tristate_is_enabled(cfg->autoneg)) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to enable link auto-negotiation",
				ref->name);
		ecmd.settings.autoneg = AUTONEG_ENABLE;
	} else
	if (ni_tristate_is_disabled(cfg->autoneg)) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to disable link auto-negotiation",
				ref->name);
		ecmd.settings.autoneg = AUTONEG_DISABLE;
	}

	if (cfg->speed && cfg->speed != NI_ETHTOOL_SPEED_UNKNOWN &&
	    ecmd.settings.speed != cfg->speed && ethtool_validate_speed(cfg->speed)) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set speed to %u",
				ref->name, cfg->speed);
		ecmd.settings.speed = cfg->speed;
	}
	if (cfg->duplex != NI_ETHTOOL_DUPLEX_UNKNOWN && ecmd.settings.duplex != cfg->duplex) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set duplex to %s",
				ref->name, ni_ethtool_link_duplex_name(cfg->duplex));
		ecmd.settings.duplex = cfg->duplex;
	}

	if (cfg->port != NI_ETHTOOL_PORT_DEFAULT && ecmd.settings.port != cfg->port) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set port type %s",
				ref->name, ni_ethtool_link_port_name(cfg->port));
		ecmd.settings.port = cfg->port;
	}
	if (cfg->phy_address != NI_ETHTOOL_PHYAD_UNKNOWN &&
	    cfg->phy_address != ecmd.settings.phy_address) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set PHY address to %u",
				ref->name, cfg->phy_address);
		ecmd.settings.phy_address = cfg->phy_address;
	}
	if (cfg->transceiver != NI_ETHTOOL_XCVR_UNKNOWN &&
	    cfg->transceiver != ecmd.settings.transceiver) {
		const char *xcvr = ni_ethtool_link_xcvr_name(cfg->transceiver);
		ni_warn("%s: ethtool request to set transceiver to %s [read-only]",
			ref->name, xcvr ? xcvr : ni_sprint_uint(cfg->transceiver));
	}

	if (cfg->tp_mdix != ETH_TP_MDI_INVALID) {
		if (ecmd.settings.eth_tp_mdix_ctrl != ETH_TP_MDI_INVALID) {
			switch (cfg->tp_mdix) {
			case NI_ETHTOOL_MDI:
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
						"%s: ethtool request to set %s", ref->name,
						ni_ethtool_link_mdix_name(cfg->tp_mdix));
				ecmd.settings.eth_tp_mdix_ctrl = ETH_TP_MDI;
				break;
			case NI_ETHTOOL_MDI_X:
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
						"%s: ethtool request to set %s", ref->name,
						ni_ethtool_link_mdix_name(cfg->tp_mdix));
				ecmd.settings.eth_tp_mdix_ctrl = ETH_TP_MDI_X;
				break;
			default:
				ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
						"%s: ethtool request to set auto mdi/mdi-x",
						ref->name);
				ecmd.settings.eth_tp_mdix_ctrl = ETH_TP_MDI_AUTO;
				break;
			}
		} else {
			ni_warn("%s: ethtool does not support to set link MDI/MDI-X", ref->name);
		}
	}

	if (ecmd.settings.autoneg == AUTONEG_ENABLE &&
	    ecmd.settings.link_mode_masks_nwords > 0) {
		int8_t nwords   = ecmd.settings.link_mode_masks_nwords;
		size_t off, len = nwords * sizeof(uint32_t);

		off = 0;
		ni_bitfield_set_data(&sup, &ecmd.link_mode_maps[off], len);

		off += nwords;
		ni_bitfield_set_data(&old, &ecmd.link_mode_maps[off], len);

		/* apply adv bitfield data to advertising in the settings */
		ni_ethtool_set_advertise(&adv, &sup, &old, ref, cfg);
		if (ni_bitfield_bytes(&adv) >= len) {
			memcpy(&ecmd.link_mode_maps[off], ni_bitfield_get_data(&adv), len);
		}
		ni_bitfield_destroy(&sup);
		ni_bitfield_destroy(&old);
		ni_bitfield_destroy(&adv);
	}

	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_SLINKSETINGS, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_SET_LINK_SETTINGS,
				ret != -EOPNOTSUPP);
	return ret;
}

int
ni_ethtool_get_link_settings(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	int ret;

	ret = ni_ethtool_get_link_settings_current(ref, ethtool);
	if (ret != -EOPNOTSUPP)
		return ret;

	return ni_ethtool_get_link_settings_legacy(ref, ethtool);
}

int
ni_ethtool_set_link_settings(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool,
				const ni_ethtool_link_settings_t *cfg)
{
	int ret;

	ret = ni_ethtool_set_link_settings_current(ref, ethtool, cfg);
	if (ret != -EOPNOTSUPP)
		return ret;

	return ni_ethtool_set_link_settings_legacy(ref, ethtool, cfg);
}

/*
 * Wake-On-LAN (GWOL,SWOL)
 */
void
ni_ethtool_wake_on_lan_free(ni_ethtool_wake_on_lan_t *wol)
{
	if (wol) {
		memset(wol, 0, sizeof(*wol));
		free(wol);
	}
}

ni_ethtool_wake_on_lan_t *
ni_ethtool_wake_on_lan_new(void)
{
	ni_ethtool_wake_on_lan_t *wol;

	wol = calloc(1, sizeof(*wol));
	if (wol) {
		wol->support = NI_ETHTOOL_WOL_DEFAULT;
		wol->options = NI_ETHTOOL_WOL_DEFAULT;
	}
	return wol;
}

static const ni_intmap_t		ni_ethtool_wol_flag_names[] = {
	{ "phy",			NI_ETHTOOL_WOL_PHY				},
	{ "p",				NI_ETHTOOL_WOL_PHY				},
	{ "unicast",			NI_ETHTOOL_WOL_UCAST				},
	{ "u",				NI_ETHTOOL_WOL_UCAST				},
	{ "multicast",			NI_ETHTOOL_WOL_MCAST				},
	{ "m",				NI_ETHTOOL_WOL_MCAST				},
	{ "broadcast",			NI_ETHTOOL_WOL_BCAST				},
	{ "b",				NI_ETHTOOL_WOL_BCAST				},
	{ "arp",			NI_ETHTOOL_WOL_ARP				},
	{ "a",				NI_ETHTOOL_WOL_ARP				},
	{ "magic",			NI_ETHTOOL_WOL_MAGIC				},
	{ "g",				NI_ETHTOOL_WOL_MAGIC				},
	{ "secure-on",			NI_ETHTOOL_WOL_SECUREON				},
	{ "s",				NI_ETHTOOL_WOL_SECUREON				},

	{ NULL,				-1U						},
};

const char *
ni_ethtool_wol_flag_name(unsigned int flag)
{
	return ni_format_uint_mapped(flag, ni_ethtool_wol_flag_names);
}

ni_bool_t
ni_ethtool_wol_flag_type(const char *name, unsigned int *flag)
{
	return ni_parse_uint_mapped(name, ni_ethtool_wol_flag_names, flag) == 0;
}

const char *
ni_ethtool_wol_flags_format(ni_stringbuf_t *buf, unsigned int mask, const char *sep)
{
	return ni_format_bitmap(buf, ni_ethtool_wol_flag_names, mask, sep);
}

int
ni_ethtool_get_wake_on_lan(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GWOL = {
		ETHTOOL_GWOL,	"get wake-on-lan"
	};
	struct ethtool_wolinfo wolinfo;
	ni_ethtool_wake_on_lan_t *wol;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_WAKE_ON_LAN))
		return -EOPNOTSUPP;

	ni_ethtool_wake_on_lan_free(ethtool->wake_on_lan);
	ethtool->wake_on_lan = NULL;

	memset(&wolinfo, 0, sizeof(wolinfo));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GWOL, &wolinfo, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_WAKE_ON_LAN,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (!(wol = ni_ethtool_wake_on_lan_new()))
		return -ENOMEM;

	wol->support = wolinfo.supported;
	wol->options = wolinfo.wolopts;

	if ((wol->options & NI_BIT(NI_ETHTOOL_WOL_SECUREON)) &&
	    (NI_MAXHWADDRLEN > sizeof(wolinfo.sopass))) {
		wol->sopass.type = ARPHRD_ETHER;
		wol->sopass.len = sizeof(wolinfo.sopass);
		memcpy(&wol->sopass.data, wolinfo.sopass, sizeof(wolinfo.sopass));
	}

	ethtool->wake_on_lan = wol;
	return 0;
}

int
ni_ethtool_set_wake_on_lan(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, const ni_ethtool_wake_on_lan_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GWOL = {
		ETHTOOL_GWOL,	"get wake-on-lan"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SWOL = {
		ETHTOOL_SWOL,	"set wake-on-lan"
	};
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	struct ethtool_wolinfo wolinfo;
	int ret;

	if (!cfg || cfg->options == NI_ETHTOOL_WOL_DEFAULT)
		return 1;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_WAKE_ON_LAN) ||
	    !ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_WAKE_ON_LAN))
		return -EOPNOTSUPP;

	memset(&wolinfo, 0, sizeof(wolinfo));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GWOL, &wolinfo, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_WAKE_ON_LAN,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (cfg->options != NI_ETHTOOL_WOL_DISABLE) {
		unsigned int ok  = cfg->options & wolinfo.supported;
		unsigned int bad = cfg->options & ~ok;

		if (ok)	{
			/* we can set some at least */
			wolinfo.wolopts = ok;

			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: ethtool request to enable wake-on-lan modes: %s",
				ref->name, ni_ethtool_wol_flags_format(&buf, wolinfo.wolopts, NULL));
			ni_stringbuf_destroy(&buf);
		}
		if (bad) {
			/* unsupported or invalid */
			ni_ethtool_wol_flags_format(&buf, bad, NULL);
			ni_warn("%s: ethtool request to enable unsupported wake-on-lan modes: "
					" %s%s(0x%x) ignored", ref->name,
					buf.string ? buf.string : "",
					buf.string ? " " : "", bad);
			ni_stringbuf_destroy(&buf);
		}
	} else {
		/* request to disable wol */
		wolinfo.wolopts = 0;
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
			"%s: ethtool request to disable wake-on-lan", ref->name);
	}

	if ((wolinfo.wolopts & NI_BIT(NI_ETHTOOL_WOL_SECUREON)) && cfg->sopass.len) {
		if (cfg->sopass.len != sizeof(wolinfo.sopass)) {
			ni_warn("%s: invalid wake-on-lan secure-on password length %u",
					ref->name, cfg->sopass.len);
		} else {
			memcpy(wolinfo.sopass, &cfg->sopass.data, sizeof(wolinfo.sopass));
		}
	}

	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_SWOL, &wolinfo, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_SET_WAKE_ON_LAN,
			ret != -EOPNOTSUPP);

	return ret;
}


/*
 * offload and other known features name id's.
 *
 * Note: this is our private feature->map.type enum
 * we're using to map aliases and kernel names to it.
 *
 * Unknown features (from kernel or config) are using
 * a deep copy of the name and the unknown type -1U.
 *
 * The type has absolutely nothing in common with
 * kernel bits (include/linux/netdev_features.h),
 * which are stored in the (bitmap) feature->index.
 */
typedef enum {
	/* constants used to set via old offload ioctls */
	NI_ETHTOOL_FEATURE_F_LEGACY_SG,
	NI_ETHTOOL_FEATURE_F_LEGACY_HW_CSUM,
	NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_TX,
	NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_RX,
	NI_ETHTOOL_FEATURE_F_LEGACY_GSO,
	NI_ETHTOOL_FEATURE_F_LEGACY_GRO,
	NI_ETHTOOL_FEATURE_F_LEGACY_TSO,
	NI_ETHTOOL_FEATURE_F_LEGACY_UFO,
	NI_ETHTOOL_FEATURE_F_LEGACY_LRO,
	NI_ETHTOOL_FEATURE_F_LEGACY_NTUPLE,
	NI_ETHTOOL_FEATURE_F_LEGACY_RXHASH,
	NI_ETHTOOL_FEATURE_F_LEGACY_RXCSUM,

	/* constants used to set via new feature ioctl */
	NI_ETHTOOL_FEATURE_F_SG,
	NI_ETHTOOL_FEATURE_F_IP_CSUM,
	NI_ETHTOOL_FEATURE_F_HW_CSUM,
	NI_ETHTOOL_FEATURE_F_IPV6_CSUM,
	NI_ETHTOOL_FEATURE_F_HIGHDMA,
	NI_ETHTOOL_FEATURE_F_FRAGLIST,
	NI_ETHTOOL_FEATURE_F_HW_VLAN_CTAG_TX,
	NI_ETHTOOL_FEATURE_F_HW_VLAN_CTAG_RX,
	NI_ETHTOOL_FEATURE_F_HW_VLAN_CTAG_FILTER,
	NI_ETHTOOL_FEATURE_F_HW_VLAN_STAG_TX,
	NI_ETHTOOL_FEATURE_F_HW_VLAN_STAG_RX,
	NI_ETHTOOL_FEATURE_F_HW_VLAN_STAG_FILTER,
	NI_ETHTOOL_FEATURE_F_VLAN_CHALLENGED,
	NI_ETHTOOL_FEATURE_F_GSO,
	NI_ETHTOOL_FEATURE_F_GSO_ROBUST,
	NI_ETHTOOL_FEATURE_F_GSO_PARTIAL,
	NI_ETHTOOL_FEATURE_F_GSO_GRE,
	NI_ETHTOOL_FEATURE_F_GSO_IPIP,
	NI_ETHTOOL_FEATURE_F_GSO_SIT,
	NI_ETHTOOL_FEATURE_F_GSO_UDP_TUNNEL,
	NI_ETHTOOL_FEATURE_F_GSO_UDP_TUNNEL_CSUM,
	NI_ETHTOOL_FEATURE_F_GSO_IPXIP4,
	NI_ETHTOOL_FEATURE_F_GSO_IPXIP6,
	NI_ETHTOOL_FEATURE_F_GSO_GRE_CSUM,
	NI_ETHTOOL_FEATURE_F_GSO_SCTP,
	NI_ETHTOOL_FEATURE_F_GSO_ESP,
	NI_ETHTOOL_FEATURE_F_GRO,
	NI_ETHTOOL_FEATURE_F_GRO_HW,
	NI_ETHTOOL_FEATURE_F_LLTX,
	NI_ETHTOOL_FEATURE_F_NETNS_LOCAL,
	NI_ETHTOOL_FEATURE_F_LRO,
	NI_ETHTOOL_FEATURE_F_UFO,
	NI_ETHTOOL_FEATURE_F_TSO_ECN,
	NI_ETHTOOL_FEATURE_F_TSO_MANGLEID,
	NI_ETHTOOL_FEATURE_F_TSO6,
	NI_ETHTOOL_FEATURE_F_TSO,
	NI_ETHTOOL_FEATURE_F_FSO,
	NI_ETHTOOL_FEATURE_F_FCOE_CRC,
	NI_ETHTOOL_FEATURE_F_SCTP_CSUM,
	NI_ETHTOOL_FEATURE_F_FCOE_MTU,
	NI_ETHTOOL_FEATURE_F_NTUPLE,
	NI_ETHTOOL_FEATURE_F_RXHASH,
	NI_ETHTOOL_FEATURE_F_RXCSUM,
	NI_ETHTOOL_FEATURE_F_NOCACHE_COPY,
	NI_ETHTOOL_FEATURE_F_LOOPBACK,
	NI_ETHTOOL_FEATURE_F_RXFCS,
	NI_ETHTOOL_FEATURE_F_RXALL,
	NI_ETHTOOL_FEATURE_F_HW_L2FW_DOFFLOAD,
	NI_ETHTOOL_FEATURE_F_BUSY_POLL,
	NI_ETHTOOL_FEATURE_F_HW_TC,
	NI_ETHTOOL_FEATURE_F_HW_ESP,
	NI_ETHTOOL_FEATURE_F_HW_ESP_TX_CSUM,
	NI_ETHTOOL_FEATURE_F_RX_UDP_TUNNEL_PORT,

	NI_ETHTOOL_FEATURE_UNKNOWN = -1U
} ni_ethtool_feature_id_t;

static const ni_intmap_t		ni_ethtool_feature_name_map[] = {
	/* known feature name and alias map, -1U and allocated name for unknown features
	 * k: kernel name, l: long ethtool name, s: short ethtool name, w: old schema */
/*k*/	{ "tx-scatter-gather",			NI_ETHTOOL_FEATURE_F_SG			},
/*s*/	{ "sg",					NI_ETHTOOL_FEATURE_F_LEGACY_SG		},
/*l,w*/	{ "scatter-gather",			NI_ETHTOOL_FEATURE_F_LEGACY_SG		},
	{ "tx-checksum-ipv4",			NI_ETHTOOL_FEATURE_F_IP_CSUM		},
/*k*/	{ "tx-checksum-ip-generic",		NI_ETHTOOL_FEATURE_F_HW_CSUM		},
/*s*/	{ "tx",					NI_ETHTOOL_FEATURE_F_LEGACY_HW_CSUM	},
/*l*/	{ "tx-checksumming",			NI_ETHTOOL_FEATURE_F_LEGACY_HW_CSUM	},
/*w*/	{ "tx-csum",				NI_ETHTOOL_FEATURE_F_LEGACY_HW_CSUM	},
	{ "tx-checksum-ipv6",			NI_ETHTOOL_FEATURE_F_IPV6_CSUM		},
	{ "highdma",				NI_ETHTOOL_FEATURE_F_HIGHDMA		},
	{ "tx-scatter-gather-fraglist",		NI_ETHTOOL_FEATURE_F_FRAGLIST		},
/*k*/	{ "tx-vlan-hw-insert",			NI_ETHTOOL_FEATURE_F_HW_VLAN_CTAG_TX	},
/*s,w*/	{ "txvlan",				NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_TX	},
/*l*/	{ "tx-vlan-offload",			NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_TX	},
/*k*/	{ "rx-vlan-hw-parse",			NI_ETHTOOL_FEATURE_F_HW_VLAN_CTAG_RX	},
/*s,w*/	{ "rxvlan",				NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_RX	},
/*l*/	{ "rx-vlan-offload",			NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_RX	},
	{ "rx-vlan-filter",			NI_ETHTOOL_FEATURE_F_HW_VLAN_CTAG_FILTER},
	{ "tx-vlan-stag-hw-insert",		NI_ETHTOOL_FEATURE_F_HW_VLAN_STAG_TX	},
	{ "rx-vlan-stag-hw-parse",		NI_ETHTOOL_FEATURE_F_HW_VLAN_STAG_RX	},
	{ "rx-vlan-stag-filter",		NI_ETHTOOL_FEATURE_F_HW_VLAN_STAG_FILTER},
	{ "vlan-challenged",			NI_ETHTOOL_FEATURE_F_VLAN_CHALLENGED	},
/*k*/	{ "tx-generic-segmentation",		NI_ETHTOOL_FEATURE_F_GSO		},
/*s,w*/	{ "gso",				NI_ETHTOOL_FEATURE_F_LEGACY_GSO		},
/*l*/	{ "generic-segmentation-offload",	NI_ETHTOOL_FEATURE_F_LEGACY_GSO		},
	{ "tx-gso-robust",			NI_ETHTOOL_FEATURE_F_GSO_ROBUST		},
	{ "tx-gso-partial",			NI_ETHTOOL_FEATURE_F_GSO_PARTIAL	},
	{ "tx-gre-segmentation",		NI_ETHTOOL_FEATURE_F_GSO_GRE		},
	{ "tx-gre-csum-segmentation",		NI_ETHTOOL_FEATURE_F_GSO_GRE_CSUM	},
	{ "tx-ipxip4-segmentation",		NI_ETHTOOL_FEATURE_F_GSO_IPXIP4		},
	{ "tx-ipxip6-segmentation",		NI_ETHTOOL_FEATURE_F_GSO_IPXIP6		},
	{ "tx-ipip-segmentation",		NI_ETHTOOL_FEATURE_F_GSO_IPIP		},
	{ "tx-sit-segmentation",		NI_ETHTOOL_FEATURE_F_GSO_SIT		},
	{ "tx-udp_tnl-segmentation",		NI_ETHTOOL_FEATURE_F_GSO_UDP_TUNNEL	},
	{ "tx-udp_tnl-csum-segmentation",	NI_ETHTOOL_FEATURE_F_GSO_UDP_TUNNEL_CSUM},
	{ "tx-sctp-segmentation",		NI_ETHTOOL_FEATURE_F_GSO_SCTP		},
	{ "tx-esp-segmentation",		NI_ETHTOOL_FEATURE_F_GSO_ESP		},
	{ "tx-lockless",			NI_ETHTOOL_FEATURE_F_LLTX		},
	{ "netns-local",			NI_ETHTOOL_FEATURE_F_NETNS_LOCAL	},
/*k*/	{ "rx-gro",				NI_ETHTOOL_FEATURE_F_GRO		},
/*s,w*/	{ "gro",				NI_ETHTOOL_FEATURE_F_LEGACY_GRO		},
/*l*/	{ "generic-receive-offload",		NI_ETHTOOL_FEATURE_F_LEGACY_GRO		},
	{ "rx-gro-hw",				NI_ETHTOOL_FEATURE_F_GRO_HW		},
/*k*/	{ "rx-lro",				NI_ETHTOOL_FEATURE_F_LRO		},
/*s,w*/	{ "lro",				NI_ETHTOOL_FEATURE_F_LEGACY_LRO		},
/*l*/	{ "large-receive-offload",		NI_ETHTOOL_FEATURE_F_LEGACY_LRO		},
/*k*/	{ "tx-tcp-segmentation",		NI_ETHTOOL_FEATURE_F_TSO		},
/*s,w*/	{ "tso",				NI_ETHTOOL_FEATURE_F_LEGACY_TSO		},
/*l*/	{ "tcp-segmentation-offload",		NI_ETHTOOL_FEATURE_F_LEGACY_TSO		},
/*k*/	{ "tx-udp-fragmentation",		NI_ETHTOOL_FEATURE_F_UFO		},
/*s,w*/	{ "ufo",				NI_ETHTOOL_FEATURE_F_LEGACY_UFO		},
/*l*/	{ "udp-fragmentation-offload",		NI_ETHTOOL_FEATURE_F_LEGACY_UFO		},
	{ "tx-tcp-ecn-segmentation",		NI_ETHTOOL_FEATURE_F_TSO_ECN		},
	{ "tx-tcp-mangleid-segmentation",	NI_ETHTOOL_FEATURE_F_TSO_MANGLEID	},
	{ "tx-tcp6-segmentation",		NI_ETHTOOL_FEATURE_F_TSO6		},
	{ "tx-fcoe-segmentation",		NI_ETHTOOL_FEATURE_F_FSO		},
	{ "tx-checksum-fcoe-crc",		NI_ETHTOOL_FEATURE_F_FCOE_CRC		},
	{ "tx-checksum-sctp",			NI_ETHTOOL_FEATURE_F_SCTP_CSUM		},
	{ "fcoe-mtu",				NI_ETHTOOL_FEATURE_F_FCOE_MTU		},
/*k*/	{ "rx-ntuple-filter",			NI_ETHTOOL_FEATURE_F_NTUPLE		},
/*s,w*/	{ "ntuple",				NI_ETHTOOL_FEATURE_F_LEGACY_NTUPLE	},
/*l*/	{ "ntuple-filters",			NI_ETHTOOL_FEATURE_F_LEGACY_NTUPLE	},
/*k*/	{ "rx-hashing",				NI_ETHTOOL_FEATURE_F_RXHASH		},
/*s,w*/	{ "rxhash",				NI_ETHTOOL_FEATURE_F_LEGACY_RXHASH	},
/*l*/	{ "receive-hashing",			NI_ETHTOOL_FEATURE_F_LEGACY_RXHASH	},
/*k*/	{ "rx-checksum",			NI_ETHTOOL_FEATURE_F_RXCSUM		},
/*s*/	{ "rx",					NI_ETHTOOL_FEATURE_F_LEGACY_RXCSUM	},
/*l*/	{ "rx-checksumming",			NI_ETHTOOL_FEATURE_F_LEGACY_RXCSUM	},
/*w*/	{ "rx-csum",				NI_ETHTOOL_FEATURE_F_LEGACY_RXCSUM	},
	{ "tx-nocache-copy",			NI_ETHTOOL_FEATURE_F_NOCACHE_COPY	},
	{ "loopback",				NI_ETHTOOL_FEATURE_F_LOOPBACK		},
	{ "rx-fcs",				NI_ETHTOOL_FEATURE_F_RXFCS		},
	{ "rx-all",				NI_ETHTOOL_FEATURE_F_RXALL		},
	{ "l2-fwd-offload",			NI_ETHTOOL_FEATURE_F_HW_L2FW_DOFFLOAD,	},
	{ "busy-poll",				NI_ETHTOOL_FEATURE_F_BUSY_POLL		},
	{ "hw-tc-offload",			NI_ETHTOOL_FEATURE_F_HW_TC		},
	{ "esp-hw-offload",			NI_ETHTOOL_FEATURE_F_HW_ESP		},
	{ "esp-tx-csum-hw-offload",		NI_ETHTOOL_FEATURE_F_HW_ESP_TX_CSUM	},
	{ "rx-udp_tunnel-port-offload",		NI_ETHTOOL_FEATURE_F_RX_UDP_TUNNEL_PORT	},

	{ NULL,					NI_ETHTOOL_FEATURE_UNKNOWN		}
};

static const char *
ni_ethtool_feature_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_ethtool_feature_name_map);
}

static ni_bool_t
ni_ethtool_feature_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, ni_ethtool_feature_name_map, type) == 0;
}

static ni_bool_t
ni_ethtool_feature_is_legacy(unsigned int type)
{
	switch (type) {
	case NI_ETHTOOL_FEATURE_F_LEGACY_SG:
	case NI_ETHTOOL_FEATURE_F_LEGACY_HW_CSUM:
	case NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_TX:
	case NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_RX:
	case NI_ETHTOOL_FEATURE_F_LEGACY_TSO:
	case NI_ETHTOOL_FEATURE_F_LEGACY_GSO:
	case NI_ETHTOOL_FEATURE_F_LEGACY_GRO:
	case NI_ETHTOOL_FEATURE_F_LEGACY_UFO:
	case NI_ETHTOOL_FEATURE_F_LEGACY_LRO:
	case NI_ETHTOOL_FEATURE_F_LEGACY_NTUPLE:
	case NI_ETHTOOL_FEATURE_F_LEGACY_RXHASH:
	case NI_ETHTOOL_FEATURE_F_LEGACY_RXCSUM:
		return TRUE;

	default:
		return FALSE;
	}
}

static void
ni_ethtool_feature_free(ni_ethtool_feature_t *feature)
{
	if (feature) {
		if (feature->map.value == NI_ETHTOOL_FEATURE_UNKNOWN)
			free((char *)feature->map.name);
		feature->map.name = NULL;
		free(feature);
	}
}

static ni_ethtool_feature_t *
ni_ethtool_feature_new(const char *name, unsigned int index)
{
	ni_ethtool_feature_t *feature;
	char *copy = NULL;

	/* ensure every feature has a name   */
	if (ni_string_empty(name))
		return NULL;

	feature = calloc(1, sizeof(*feature));
	if (!feature)
		return NULL;

	/* set kernel index (-1U on undef)   */
	feature->index = index;

	/* set id when it's a known feature  */
	if (ni_ethtool_feature_type(name, &feature->map.value) &&
	    (feature->map.name = ni_ethtool_feature_name(feature->map.value)))
		return feature;

	/* or deep copy unknown feature name */
	feature->map.value = NI_ETHTOOL_FEATURE_UNKNOWN;
	if (ni_string_dup(&copy, name) && (feature->map.name = copy))
		return feature;

	ni_ethtool_feature_free(feature);
	return NULL;
}

static void
ni_ethtool_features_destroy(ni_ethtool_features_t *features)
{
	if (features) {
		while (features->count) {
			features->count--;
			ni_ethtool_feature_free(features->data[features->count]);
		}
		free(features->data);
		features->data = NULL;
	}
}

void
ni_ethtool_features_free(ni_ethtool_features_t *features)
{
	if (features) {
		ni_ethtool_features_destroy(features);
		free(features);
	}
}

ni_ethtool_features_t *
ni_ethtool_features_new(void)
{
	ni_ethtool_features_t *features;

	features = calloc(1, sizeof(*features));
	return features;
}

#define NI_ETHTOOL_FEATURE_ARRAY_CHUNK		16

static inline ni_bool_t
ni_ethtool_features_realloc(ni_ethtool_features_t *features, unsigned int newsize)
{
	ni_ethtool_feature_t **newdata;
	unsigned int i;

	if (!features || (UINT_MAX - NI_ETHTOOL_FEATURE_ARRAY_CHUNK) <= newsize)
		return FALSE;

	newsize = (newsize + NI_ETHTOOL_FEATURE_ARRAY_CHUNK);
	newdata = realloc(features->data, newsize * sizeof(*newdata));
	if (!newdata)
		return FALSE;

	features->data = newdata;
	for (i = features->count; i < newsize; ++i)
		features->data[i] = NULL;
	return TRUE;
}

static ni_bool_t
ni_ethtool_features_add(ni_ethtool_features_t *features, ni_ethtool_feature_t *feature)
{
	if (!features || !feature)
		return FALSE;

	if ((features->count % NI_ETHTOOL_FEATURE_ARRAY_CHUNK) == 0 &&
	    !ni_ethtool_features_realloc(features, features->count))
		return FALSE;

	features->data[features->count++] = feature;
	return TRUE;
}

static ni_ethtool_feature_t *
ni_ethtool_features_get(ni_ethtool_features_t *features, const char *name)
{
	ni_ethtool_feature_t *feature;
	unsigned int i, known;

	if (!features || ni_string_empty(name))
		return NULL;

	if (ni_ethtool_feature_type(name, &known)) {
		for (i = 0; i < features->count; ++i) {
			if (!(feature = features->data[i]))
				continue;

			if (known == feature->map.value)
				return feature;
		}
	} else {
		for (i = 0; i < features->count; ++i) {
			if (!(feature = features->data[i]))
				continue;

			if (ni_string_eq(name, feature->map.name))
				return feature;
		}
	}
	return NULL;
}

ni_ethtool_feature_t *
ni_ethtool_features_set(ni_ethtool_features_t *features, const char *name, ni_ethtool_feature_value_t value)
{
	ni_ethtool_feature_t *feature;

	if ((feature = ni_ethtool_features_get(features, name))) {
		feature->value = value;
		return feature;
	} else
	if ((feature = ni_ethtool_feature_new(name, -1U))) {
		feature->value = value;
		if (ni_ethtool_features_add(features, feature))
			return feature;
		ni_ethtool_feature_free(feature);
	}
	return NULL;
}

static unsigned int
ni_ethtool_get_feature_count(const ni_netdev_ref_t *ref)
{
	return ni_ethtool_get_gstring_count(ref, "features count", ETH_SS_FEATURES);
}

static struct ethtool_gstrings *
ni_ethtool_get_feature_names(const ni_netdev_ref_t *ref, unsigned int count)
{
	return ni_ethtool_get_gstrings(ref, "feature names", ETH_SS_FEATURES, count);
}

#define ni_ethtool_get_feature_blocks(n)	(((n) + 31U) / 32U)

static struct ethtool_gfeatures *
ni_ethtool_get_feature_values(const ni_netdev_ref_t *ref, unsigned int count)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GFEATURES = {
		ETHTOOL_GFEATURES, "get feature values"
	};
	struct ethtool_gfeatures *gfeatures;
	unsigned int blocks;

	blocks = ni_ethtool_get_feature_blocks(count);
	gfeatures = calloc(1, sizeof(*gfeatures) + blocks * sizeof(gfeatures->features[0]));
	if (!gfeatures) {
		int err = errno;
		ni_warn("%s: unable to allocate %u ethtool feature values", ref->name, count);
		errno = err;
		return NULL;
	}

	gfeatures->size = blocks;
	if (ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GFEATURES, gfeatures, NULL) < 0) {
		int err = errno;
		free(gfeatures);
		errno = err;
		return NULL;
	}

	if (gfeatures->size > blocks) {
		int err = errno;
		ni_warn("%s: kernel returned %u feature block size instead of %u",
				ref->name, gfeatures->size, blocks);
		free(gfeatures);
		errno = err;
		return NULL;
	}

	return gfeatures;
}

static int
ni_ethtool_get_features_init(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, ni_bool_t unavailable)
{
	struct ethtool_gfeatures *gfeatures;
	struct ethtool_gstrings *gstrings;
	ni_ethtool_features_t *features;
	ni_ethtool_feature_t *feature;
	unsigned int i, count;

	if (!ethtool->features && !(ethtool->features = ni_ethtool_features_new()))
		return -ENOMEM;

	features = ethtool->features;
	if (!features->total && !(features->total = ni_ethtool_get_feature_count(ref))) {
		ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_FEATURES, FALSE);
		return -EOPNOTSUPP;
	}

	gfeatures = ni_ethtool_get_feature_values(ref, features->total);
	if (!gfeatures || !gfeatures->size) {
		if (errno == EOPNOTSUPP)
			ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_FEATURES, FALSE);
		features->total = 0;
		free(gfeatures);
		return errno;
	}

	gstrings = ni_ethtool_get_feature_names(ref, features->total);
	if (!gstrings || !gstrings->len) {
		if (errno == EOPNOTSUPP)
			ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_FEATURES, FALSE);
		features->total = 0;
		free(gfeatures);
		free(gstrings);
		return errno;
	}

	count = gfeatures->size * 32U;
	if (count > gstrings->len)
		count = gstrings->len;

	for (i = 0; i < count; ++i) {
		struct ethtool_get_features_block *block;
		const char *name;
		unsigned int bit;

		name = (const char *)(gstrings->data + i * ETH_GSTRING_LEN);
		block = &gfeatures->features[i/32U];
		bit = NI_BIT(i % 32U);

		/* don't store unavailable features except requested */
		if (!((block->available & bit) || unavailable))
			continue;

		if (!(feature = ni_ethtool_feature_new(name, i)))
			continue;

		feature->value = NI_ETHTOOL_FEATURE_OFF;
		if (!(block->available & bit) || (block->never_changed & bit)) {
			feature->value |= NI_ETHTOOL_FEATURE_FIXED;
			if (block->active & bit)
				feature->value |= NI_ETHTOOL_FEATURE_ON;
		} else if ((block->requested & bit) ^ (block->active & bit)) {
			feature->value |= NI_ETHTOOL_FEATURE_REQUESTED;
			if (block->requested & bit)
				feature->value |= NI_ETHTOOL_FEATURE_ON;
		} else {
			if (block->active & bit)
				feature->value |= NI_ETHTOOL_FEATURE_ON;
		}
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: get ethtool feature[%u] %s: %s%s",
				ref->name, feature->index, feature->map.name,
				feature->value & NI_ETHTOOL_FEATURE_ON ? "on" : "off",
				feature->value & NI_ETHTOOL_FEATURE_FIXED ? " fixed" :
				feature->value & NI_ETHTOOL_FEATURE_REQUESTED ? " requested" : "");

		if (!ni_ethtool_features_add(features, feature)) {
			ni_warn("%s: unable to store feature %s: %m", ref->name, feature->map.name);
			ni_ethtool_feature_free(feature);
		}
	}

	free(gstrings);
	free(gfeatures);
	return 0;
}

static int
ni_ethtool_get_features_update(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	struct ethtool_gfeatures *gfeatures;
	ni_ethtool_features_t *features;
	ni_ethtool_feature_t *feature;
	unsigned int i, count;

	if (!ethtool || !(features = ethtool->features) || !features->total)
		return -EINVAL;

	gfeatures = ni_ethtool_get_feature_values(ref, features->total);
	if (!gfeatures || !gfeatures->size) {
		if (errno == EOPNOTSUPP)
			ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_FEATURES, FALSE);
		free(gfeatures);
		return errno;
	}

	count = gfeatures->size * 32U;
	for (i = 0; i < features->count; ++i) {
		struct ethtool_get_features_block *block;
		unsigned int bit;

		feature = features->data[i];
		if (!feature || feature->index == -1U || feature->index >= count) {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: get ethtool feature[%u] %s: invalid index",
				ref->name, i, feature ? feature->map.name : NULL);
			continue;
		}

		block = &gfeatures->features[feature->index/32U];
		bit = NI_BIT(feature->index % 32U);

		feature->value = NI_ETHTOOL_FEATURE_OFF;
		if (!(block->available & bit) || (block->never_changed & bit)) {
			feature->value |= NI_ETHTOOL_FEATURE_FIXED;
			if (block->active & bit)
				feature->value |= NI_ETHTOOL_FEATURE_ON;
		} else if ((block->requested & bit) ^ (block->active & bit)) {
			feature->value |= NI_ETHTOOL_FEATURE_REQUESTED;
			if (block->requested & bit)
				feature->value |= NI_ETHTOOL_FEATURE_ON;
		} else {
			if (block->active & bit)
				feature->value |= NI_ETHTOOL_FEATURE_ON;
		}
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: get ethtool feature[%u] %s: %s%s",
				ref->name, feature->index, feature->map.name,
				feature->value & NI_ETHTOOL_FEATURE_ON ? "on" : "off",
				feature->value & NI_ETHTOOL_FEATURE_FIXED ? " fixed" :
				feature->value & NI_ETHTOOL_FEATURE_REQUESTED ? " requested" : "");
	}

	free(gfeatures);
	return 0;
}

static int
ni_ethtool_get_value(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, unsigned int supp,
		const ni_ethtool_cmd_info_t *cmd, const char *name, uint32_t *value)
{
	struct ethtool_value ecmd;
	int ret;

	if (!ni_ethtool_supported(ethtool, supp))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, cmd, &ecmd, name);
	if (ret == 0)
		*value = ecmd.data;
	ni_ethtool_set_supported(ethtool, supp, ret != -EOPNOTSUPP);
	return ret;
}

static inline int
ni_ethtool_get_legacy_offload(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool,
				unsigned int supp, const char *name,
				const ni_ethtool_cmd_info_t *cmd)
{
	uint32_t value;
	int ret;

	ret = ni_ethtool_get_value(ref, ethtool, supp, cmd, name, &value);
	if (ret == 0) {
		ni_ethtool_features_set(ethtool->features, name, value ?
				NI_ETHTOOL_FEATURE_ON : NI_ETHTOOL_FEATURE_OFF);
	}
	return ret;
}

static int
ni_ethtool_get_legacy_flags(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GFLAGS = {
		ETHTOOL_GFLAGS,	"get flags"
	};
	uint32_t value;
	int ret;

	ret = ni_ethtool_get_value(ref, ethtool,
			NI_ETHTOOL_SUPP_GET_LEGACY_FLAGS,
			&NI_ETHTOOL_CMD_GFLAGS, NULL, &value);
	if (ret == 0) {
		ni_ethtool_features_set(ethtool->features, "txvlan",
				value & ETH_FLAG_TXVLAN ?
				NI_ETHTOOL_FEATURE_ON : NI_ETHTOOL_FEATURE_OFF);

		ni_ethtool_features_set(ethtool->features, "rxvlan",
				value & ETH_FLAG_RXVLAN ?
				NI_ETHTOOL_FEATURE_ON : NI_ETHTOOL_FEATURE_OFF);

		ni_ethtool_features_set(ethtool->features, "lro",
				value & ETH_FLAG_LRO ?
				NI_ETHTOOL_FEATURE_ON : NI_ETHTOOL_FEATURE_OFF);

		ni_ethtool_features_set(ethtool->features, "ntuple",
				value & ETH_FLAG_NTUPLE ?
				NI_ETHTOOL_FEATURE_ON : NI_ETHTOOL_FEATURE_OFF);

		ni_ethtool_features_set(ethtool->features, "rxhash",
				value & ETH_FLAG_RXHASH ?
				NI_ETHTOOL_FEATURE_ON : NI_ETHTOOL_FEATURE_OFF);
	}
	return ret;
}

static int
ni_ethtool_get_features_legacy(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const struct {
		const char *			name;
		const unsigned int		supp;
		const ni_ethtool_cmd_info_t	cmd;
	} offloads[] = {
		{ "rx-csum",		NI_ETHTOOL_SUPP_GET_LEGACY_RXCSUM,
					{ ETHTOOL_GRXCSUM, "get " }	},
		{ "tx-csum",		NI_ETHTOOL_SUPP_GET_LEGACY_TXCSUM,
					{ ETHTOOL_GTXCSUM, "get " }	},
		{ "scatter-gather",	NI_ETHTOOL_SUPP_GET_LEGACY_SG,
					{ ETHTOOL_GSG,     "get " }	},
		{ "tso",		NI_ETHTOOL_SUPP_GET_LEGACY_TSO,
					{ ETHTOOL_GTSO,    "get " }	},
		{ "ufo",		NI_ETHTOOL_SUPP_GET_LEGACY_UFO,
					{ ETHTOOL_GUFO,    "get " }	},
		{ "gso",		NI_ETHTOOL_SUPP_GET_LEGACY_GSO,
					{ ETHTOOL_GGSO,    "get " }	},
		{ "gro",		NI_ETHTOOL_SUPP_GET_LEGACY_GRO,
					{ ETHTOOL_GGRO,    "get " }	},
		{ .name = NULL,						}
	}, *offload;

	if (ethtool->features) {
		ni_ethtool_features_destroy(ethtool->features);
	} else {
		ethtool->features = ni_ethtool_features_new();
		if (!ethtool->features)
			return -ENOMEM;
	}

	for (offload = offloads; offload->name; offload++) {
		ni_ethtool_get_legacy_offload(ref, ethtool, offload->supp,
						offload->name, &offload->cmd);
	}
	ni_ethtool_get_legacy_flags(ref, ethtool);

	return ethtool->features->count == 0 ? -EOPNOTSUPP : 0;
}

static int
ni_ethtool_get_features_current(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, ni_bool_t unavailable)
{
	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_FEATURES))
		return -EOPNOTSUPP;

	if (!ethtool->features || !ethtool->features->total)
		return ni_ethtool_get_features_init(ref, ethtool, unavailable);
	else
		return ni_ethtool_get_features_update(ref, ethtool);
}

int
ni_ethtool_get_features(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, ni_bool_t unavailable)
{
	int ret;

	ret = ni_ethtool_get_features_current(ref, ethtool, unavailable);
	if (ret != -EOPNOTSUPP)
		return ret;

	return ni_ethtool_get_features_legacy(ref, ethtool);
}

static int
ni_ethtool_set_value(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, unsigned int supp,
		const ni_ethtool_cmd_info_t *cmd, const char *name, uint32_t value)
{
	struct ethtool_value ecmd;
	int ret;

	if (!ni_ethtool_supported(ethtool, supp))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ecmd.data = value;
	ret = ni_ethtool_call(ref, cmd, &ecmd, name);
	ni_ethtool_set_supported(ethtool, supp, ret != -EOPNOTSUPP);
	return ret;
}

static int
ni_ethtool_set_legacy_flag_bit(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool,
			const char *name, unsigned int flag, ni_bool_t enable)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GFLAGS = {
		ETHTOOL_GFLAGS,		"get flags "
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SFLAGS = {
		ETHTOOL_SFLAGS,		"set flags "
	};
	uint32_t value = 0;
	int ret;

	ret = ni_ethtool_get_value(ref, ethtool,
			NI_ETHTOOL_SUPP_GET_LEGACY_FLAGS,
			&NI_ETHTOOL_CMD_GFLAGS, name, &value);
	if (ret == 0) {
		if (enable && !(value & flag))
			value |= flag;
		else
		if (!enable && (value & flag))
			value &= ~flag;
		else
			return ret;

		ret = ni_ethtool_set_value(ref, ethtool,
				NI_ETHTOOL_SUPP_SET_LEGACY_FLAGS,
				&NI_ETHTOOL_CMD_SFLAGS, name, value);
	}
	return ret;
}

static int
ni_ethtool_set_features_legacy(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool,
				const ni_ethtool_features_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SRXCSUM = {
		ETHTOOL_SRXCSUM,	"set rx-csum"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_STXCSUM = {
		ETHTOOL_STXCSUM,	"set tx-csum"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SSG = {
		ETHTOOL_SSG,		"set scatter-gather"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_STSO = {
		ETHTOOL_STSO,		"set tso"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SUFO = {
		ETHTOOL_SUFO,		"set ufo"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SGSO = {
		ETHTOOL_SGSO,		"set gso"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SGRO = {
		ETHTOOL_SGRO,		"set gro"
	};
	const ni_ethtool_feature_t *feature;
	unsigned int i;
	uint32_t value;

	if (!cfg || !cfg->count)
		return 1;

	for (i = 0; i < cfg->count;  ++i) {
		if (!(feature = cfg->data[i]))
			continue;

		value = !!(feature->value & NI_ETHTOOL_FEATURE_ON);
		switch (feature->map.value) {
		case NI_ETHTOOL_FEATURE_F_LEGACY_RXCSUM:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_value(ref, ethtool,
					NI_ETHTOOL_SUPP_SET_LEGACY_RXCSUM,
					&NI_ETHTOOL_CMD_SRXCSUM, NULL, value);
			break;
		case NI_ETHTOOL_FEATURE_F_LEGACY_HW_CSUM:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_value(ref, ethtool,
					NI_ETHTOOL_SUPP_SET_LEGACY_TXCSUM,
					&NI_ETHTOOL_CMD_STXCSUM, NULL, value);
			break;
		case NI_ETHTOOL_FEATURE_F_LEGACY_SG:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_value(ref, ethtool,
					NI_ETHTOOL_SUPP_SET_LEGACY_SG,
					&NI_ETHTOOL_CMD_SSG, NULL, value);
			break;

		case NI_ETHTOOL_FEATURE_F_LEGACY_TSO:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_value(ref, ethtool,
					NI_ETHTOOL_SUPP_SET_LEGACY_TSO,
					&NI_ETHTOOL_CMD_STSO, NULL, value);
			break;

		case NI_ETHTOOL_FEATURE_F_LEGACY_UFO:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_value(ref, ethtool,
					NI_ETHTOOL_SUPP_SET_LEGACY_UFO,
					&NI_ETHTOOL_CMD_SUFO, NULL, value);
			break;

		case NI_ETHTOOL_FEATURE_F_LEGACY_GSO:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_value(ref, ethtool,
					NI_ETHTOOL_SUPP_SET_LEGACY_GSO,
					&NI_ETHTOOL_CMD_SGSO, NULL, value);
			break;

		case NI_ETHTOOL_FEATURE_F_LEGACY_GRO:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_value(ref, ethtool,
					NI_ETHTOOL_SUPP_SET_LEGACY_GRO,
					&NI_ETHTOOL_CMD_SGRO, NULL, value);
			break;

		case NI_ETHTOOL_FEATURE_F_LEGACY_LRO:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_legacy_flag_bit(ref, ethtool, "lro",
					ETH_FLAG_LRO, value);
			break;

		case NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_TX:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_legacy_flag_bit(ref, ethtool, "txvlan",
					ETH_FLAG_TXVLAN, value);
			break;

		case NI_ETHTOOL_FEATURE_F_LEGACY_HW_VLAN_CTAG_RX:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_legacy_flag_bit(ref, ethtool, "rxvlan",
					ETH_FLAG_RXVLAN, value);
			break;

		case NI_ETHTOOL_FEATURE_F_LEGACY_NTUPLE:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_legacy_flag_bit(ref, ethtool, "ntuple",
					ETH_FLAG_NTUPLE, value);
			break;
		case NI_ETHTOOL_FEATURE_F_LEGACY_RXHASH:
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
					"%s: ethtool request to set feature '%s' to %s",
					ref->name, feature->map.name, value ? "on" : "off");
			ni_ethtool_set_legacy_flag_bit(ref, ethtool, "rxhash",
					ETH_FLAG_RXHASH, value);
			break;

		case NI_ETHTOOL_FEATURE_UNKNOWN:
			if (ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_FEATURES))
				break;

			ni_warn("%s: cannot set unknown feature '%s' using legacy ioctl",
					ref->name, feature->map.name);
			break;
		default:
			if (ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_FEATURES))
				break;

			ni_warn("%s: cannot set unsupported feature '%s' using legacy ioctl",
					ref->name, feature->map.name);
			break;
		}
	}

	return 0;
}

static int
ni_ethtool_set_features_current(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool,
			const ni_ethtool_features_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SFEATURES = {
		ETHTOOL_SFEATURES, "set feature values"
	};
	const ni_ethtool_feature_t *want, *have;
	struct ethtool_sfeatures *sfeatures;
	unsigned int i, bit, blocks, count;
	int ret;

	if (!cfg || !cfg->count)
		return 1;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_FEATURES) ||
	    !ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_FEATURES))
		return -EOPNOTSUPP;

	if (!ethtool->features || !ethtool->features->total) {
		if ((ret = ni_ethtool_get_features_current(ref, ethtool, FALSE)) < 0)
			return ret;
	}

	blocks = ni_ethtool_get_feature_blocks(ethtool->features->total);
	sfeatures = calloc(1, sizeof(*sfeatures) + blocks * sizeof(sfeatures->features[0]));
	if (!sfeatures) {
		ni_warn("%s: unable to allocate ethtool feature value data", ref->name);
		return -ENOMEM;
	}

	ret = 1;
	sfeatures->size = blocks;
	count = sfeatures->size * 32U;
	for (i = 0; i < cfg->count; ++i) {
		struct ethtool_set_features_block *block;

		if (!(want = cfg->data[i]))
			continue;

		have = ni_ethtool_features_get(ethtool->features, want->map.name);
		if (!have || have->index == -1U || have->index >= count) {
			/* Don't complain about known legacy offload ioctl's,
			 * which may represent a set of multiple features...
			 * To set them via features, use their feature name,
			 * not their legacy offload name.
			 */
			if (ni_ethtool_feature_is_legacy(want->map.value))
				continue;

			ni_warn("%s: cannot set unsupported feature '%s' to '%s'",
				ref->name, want->map.name,
				!!(want->value & NI_ETHTOOL_FEATURE_ON) ? "on" : "off");
			continue;
		}

		block = &sfeatures->features[have->index/32U];
		bit = NI_BIT(have->index % 32U);

		ret = 0;
		block->valid |= bit;
		if (want->value & NI_ETHTOOL_FEATURE_ON)
			block->requested |= bit;

		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: ethtool request to set feature[%u] '%s' to %s",
				ref->name, have->index, have->map.name,
				!!(want->value & NI_ETHTOOL_FEATURE_ON) ? "on" : "off");
	}

	if (ret == 0) {
		ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_SFEATURES, sfeatures, NULL);
		ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_SET_FEATURES,
				ret != -EOPNOTSUPP);
	}

	free(sfeatures);
	return ret;
}

int
ni_ethtool_set_features(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool,
			const ni_ethtool_features_t *cfg)
{
	int current, legacy;

	legacy = ni_ethtool_set_features_legacy(ref, ethtool, cfg);

	current = ni_ethtool_set_features_current(ref, ethtool, cfg);
	if (current == -EOPNOTSUPP)
		return legacy;

	return current;
}


/*
 * eee (GEEE,SEEE)
 */
void
ni_ethtool_eee_free(ni_ethtool_eee_t *eee)
{
	if (eee) {
		ni_bitfield_destroy(&eee->speed.supported);
		ni_bitfield_destroy(&eee->speed.advertising);
		ni_bitfield_destroy(&eee->speed.lp_advertising);
		free(eee);
	}
}

ni_ethtool_eee_t *
ni_ethtool_eee_new(void)
{
	ni_ethtool_eee_t *eee;

	eee = calloc(1, sizeof(*eee));
	if (eee) {
		eee->status.enabled = NI_TRISTATE_DEFAULT;
		eee->status.active  = NI_TRISTATE_DEFAULT;
		eee->tx_lpi.enabled = NI_TRISTATE_DEFAULT;
		eee->tx_lpi.timer   = NI_ETHTOOL_EEE_DEFAULT;
	}
	return eee;
}

int
ni_ethtool_get_eee(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GEEE = {
		ETHTOOL_GEEE,		"get eee"
	};
	struct ethtool_eee ecmd;
	ni_ethtool_eee_t *eee;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_EEE))
		return -EOPNOTSUPP;

	ni_ethtool_eee_free(ethtool->eee);
	ethtool->eee = NULL;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GEEE, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_EEE,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (!(eee = ni_ethtool_eee_new()))
		return -ENOMEM;

	eee->status.enabled = ecmd.eee_enabled;
	eee->status.active = ecmd.eee_active;

	eee->tx_lpi.enabled = ecmd.tx_lpi_enabled;
	eee->tx_lpi.timer = ecmd.tx_lpi_timer;

	ni_bitfield_set_data(&eee->speed.supported,      &ecmd.supported,     sizeof(ecmd.supported));
	ni_bitfield_set_data(&eee->speed.advertising,    &ecmd.advertised,    sizeof(ecmd.advertised));
	ni_bitfield_set_data(&eee->speed.lp_advertising, &ecmd.lp_advertised, sizeof(ecmd.lp_advertised));

	ethtool->eee = eee;
	return ret;
}

int
ni_ethtool_set_eee(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, const ni_ethtool_eee_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GEEE = {
		ETHTOOL_GEEE,		"get eee"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SEEE = {
		ETHTOOL_SEEE,		"change eee "
	};
	struct ethtool_eee ecmd;
	int ret;

	if (!cfg)
		return 1;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_EEE) ||
	    !ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_EEE))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GEEE, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_EEE,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (cfg->status.enabled != NI_TRISTATE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_EEE,
				&NI_ETHTOOL_CMD_SEEE, &ecmd, "enable",
				cfg->status.enabled, &ecmd.eee_enabled,
				NI_TRISTATE_ENABLE);
	}
	if (ni_bitfield_isset(&cfg->speed.advertising) &&
	    ni_bitfield_bytes(&cfg->speed.advertising) >= sizeof(unsigned int)) {
		unsigned int advertised;
		memcpy(&advertised, ni_bitfield_get_data(&cfg->speed.advertising),
					sizeof(advertised));
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_EEE,
				&NI_ETHTOOL_CMD_SEEE, &ecmd, "advertise",
				advertised, &ecmd.advertised, -1U);
	}
	if (cfg->tx_lpi.enabled != NI_TRISTATE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_EEE,
				&NI_ETHTOOL_CMD_SEEE, &ecmd, "tx-lpi",
				cfg->tx_lpi.enabled, &ecmd.tx_lpi_enabled,
				NI_TRISTATE_ENABLE);
	}
	if (cfg->tx_lpi.timer != NI_ETHTOOL_EEE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_EEE,
				&NI_ETHTOOL_CMD_SEEE, &ecmd, "tx-lpi-timer",
				cfg->tx_lpi.timer, &ecmd.tx_lpi_timer,
				NI_ETHTOOL_EEE_DEFAULT);
	}
	return ret;
}


/*
 * ring (GRINGPARAM,SRINGPARAM)
 */
void
ni_ethtool_ring_free(ni_ethtool_ring_t *ring)
{
	free(ring);
}

ni_ethtool_ring_t *
ni_ethtool_ring_new(void)
{
	ni_ethtool_ring_t *ring;

	ring = calloc(1, sizeof(*ring));
	if (ring) {
		ring->tx	= NI_ETHTOOL_RING_DEFAULT;
		ring->rx        = NI_ETHTOOL_RING_DEFAULT;
		ring->rx_mini	= NI_ETHTOOL_RING_DEFAULT;
		ring->rx_jumbo  = NI_ETHTOOL_RING_DEFAULT;
	}
	return ring;
}

int
ni_ethtool_get_ring(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GRINGPARAM = {
		ETHTOOL_GRINGPARAM,		"get ring"
	};
	struct ethtool_ringparam ecmd;
	ni_ethtool_ring_t *ring;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_RING))
		return -EOPNOTSUPP;

	ni_ethtool_ring_free(ethtool->ring);
	ethtool->ring = NULL;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GRINGPARAM, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_RING,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (!(ring = ni_ethtool_ring_new()))
		return -ENOMEM;

	ring->tx        = ecmd.tx_pending;
	ring->rx        = ecmd.rx_pending;
	ring->rx_mini   = ecmd.rx_mini_pending;
	ring->rx_jumbo  = ecmd.rx_jumbo_pending;

	ethtool->ring = ring;
	return ret;
}

int
ni_ethtool_set_ring(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, const ni_ethtool_ring_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GRINGPARAM = {
		ETHTOOL_GRINGPARAM,		"get ring"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SGRINGPARAM = {
		ETHTOOL_SRINGPARAM,		"change ring "
	};
	struct ethtool_ringparam ecmd;
	int ret;

	if (!cfg)
		return 1;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_RING) ||
	    !ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_RING))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GRINGPARAM, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_RING,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (cfg->tx != NI_ETHTOOL_RING_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_RING,
				&NI_ETHTOOL_CMD_SGRINGPARAM, &ecmd, "tx", cfg->tx,
				&ecmd.tx_pending, ecmd.tx_max_pending);
	}
	if (cfg->rx != NI_ETHTOOL_RING_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_RING,
				&NI_ETHTOOL_CMD_SGRINGPARAM, &ecmd, "rx", cfg->rx,
				&ecmd.rx_pending, ecmd.rx_max_pending);
	}
	if (cfg->rx_jumbo != NI_ETHTOOL_RING_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_RING,
				&NI_ETHTOOL_CMD_SGRINGPARAM, &ecmd, "rx-jumbo", cfg->rx_jumbo,
				&ecmd.rx_jumbo_pending, ecmd.rx_jumbo_max_pending);
	}
	if (cfg->rx_mini != NI_ETHTOOL_RING_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_RING,
				&NI_ETHTOOL_CMD_SGRINGPARAM, &ecmd, "rx-mini", cfg->rx_mini,
				&ecmd.rx_mini_pending, ecmd.rx_mini_max_pending);
	}

	return 0;
}


/*
 * channels (GCHANNELS,SCHANNELS)
 */
void
ni_ethtool_channels_free(ni_ethtool_channels_t *channels)
{
	free(channels);
}

ni_ethtool_channels_t *
ni_ethtool_channels_new(void)
{
	ni_ethtool_channels_t *channels;

	channels = calloc(1, sizeof(*channels));
	if (channels) {
		channels->tx	   = NI_ETHTOOL_CHANNELS_DEFAULT;
		channels->rx       = NI_ETHTOOL_CHANNELS_DEFAULT;
		channels->other    = NI_ETHTOOL_CHANNELS_DEFAULT;
		channels->combined = NI_ETHTOOL_CHANNELS_DEFAULT;
	}
	return channels;
}

int
ni_ethtool_get_channels(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GCHANNELS = {
		ETHTOOL_GCHANNELS,		"get channels"
	};
	struct ethtool_channels ecmd;
	ni_ethtool_channels_t *channels;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_CHANNELS))
		return -EOPNOTSUPP;

	ni_ethtool_channels_free(ethtool->channels);
	ethtool->channels = NULL;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GCHANNELS, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_CHANNELS,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (!(channels = ni_ethtool_channels_new()))
		return -ENOMEM;

	channels->tx       = ecmd.tx_count;
	channels->rx       = ecmd.rx_count;
	channels->other    = ecmd.other_count;
	channels->combined = ecmd.combined_count;

	ethtool->channels = channels;
	return ret;
}

int
ni_ethtool_set_channels(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, const ni_ethtool_channels_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GCHANNELS = {
		ETHTOOL_GCHANNELS,		"get channels"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SCHANNELS = {
		ETHTOOL_SCHANNELS,		"set channels "
	};
	struct ethtool_channels ecmd;
	int ret;

	if (!cfg)
		return 1;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_CHANNELS) ||
	    !ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_CHANNELS))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GCHANNELS, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_CHANNELS,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (cfg->tx != NI_ETHTOOL_CHANNELS_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_CHANNELS,
				&NI_ETHTOOL_CMD_SCHANNELS, &ecmd, "tx", cfg->tx,
				&ecmd.tx_count, ecmd.max_tx);
	}
	if (cfg->rx != NI_ETHTOOL_CHANNELS_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_CHANNELS,
				&NI_ETHTOOL_CMD_SCHANNELS, &ecmd, "rx", cfg->rx,
				&ecmd.rx_count, ecmd.max_rx);
	}
	if (cfg->other != NI_ETHTOOL_CHANNELS_DEFAULT)  {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_CHANNELS,
				&NI_ETHTOOL_CMD_SCHANNELS, &ecmd, "other", cfg->other,
				&ecmd.other_count, ecmd.max_other);
	}
	if (cfg->combined != NI_ETHTOOL_CHANNELS_DEFAULT)  {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_CHANNELS,
				&NI_ETHTOOL_CMD_SCHANNELS, &ecmd, "combined", cfg->combined,
				&ecmd.combined_count, ecmd.max_combined);
	}

	return 0;
}


/*
 * coalesce (GCOALESCE,SCOALESCE)
 */
void
ni_ethtool_coalesce_free(ni_ethtool_coalesce_t *coalesce)
{
	free(coalesce);
}

ni_ethtool_coalesce_t *
ni_ethtool_coalesce_new(void)
{
	ni_ethtool_coalesce_t *coalesce;

	coalesce = calloc(1, sizeof(*coalesce));
	if (coalesce) {
		coalesce->adaptive_tx       = NI_TRISTATE_DEFAULT;
		coalesce->adaptive_rx       = NI_TRISTATE_DEFAULT;

		coalesce->pkt_rate_low      = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->pkt_rate_high     = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->sample_interval   = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->stats_block_usecs = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->tx_usecs          = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_usecs_irq      = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_usecs_low      = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_usecs_high     = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->tx_frames         = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_frames_irq     = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_frames_low     = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->tx_frames_high    = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->rx_usecs          = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_usecs_irq      = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_usecs_low      = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_usecs_high     = NI_ETHTOOL_COALESCE_DEFAULT;

		coalesce->rx_frames         = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_frames_irq     = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_frames_high    = NI_ETHTOOL_COALESCE_DEFAULT;
		coalesce->rx_frames_low     = NI_ETHTOOL_COALESCE_DEFAULT;
	}
	return coalesce;
}

int
ni_ethtool_get_coalesce(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GCOALESCE = {
		ETHTOOL_GCOALESCE,		"get coalesce"
	};
	struct ethtool_coalesce ecmd;
	ni_ethtool_coalesce_t *coalesce;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_COALESCE))
		return -EOPNOTSUPP;

	ni_ethtool_coalesce_free(ethtool->coalesce);
	ethtool->coalesce = NULL;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GCOALESCE, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_COALESCE,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (!(coalesce = ni_ethtool_coalesce_new()))
		return -ENOMEM;

	ni_tristate_set(&coalesce->adaptive_tx, ecmd.use_adaptive_tx_coalesce);
	ni_tristate_set(&coalesce->adaptive_rx, ecmd.use_adaptive_rx_coalesce);

	coalesce->pkt_rate_low          = ecmd.pkt_rate_low;
	coalesce->pkt_rate_high         = ecmd.pkt_rate_high;

	coalesce->sample_interval       = ecmd.rate_sample_interval;
	coalesce->stats_block_usecs     = ecmd.stats_block_coalesce_usecs;

	coalesce->tx_usecs              = ecmd.tx_coalesce_usecs;
	coalesce->tx_usecs_irq          = ecmd.tx_coalesce_usecs_irq;
	coalesce->tx_usecs_low          = ecmd.tx_coalesce_usecs_low;
	coalesce->tx_usecs_high         = ecmd.tx_coalesce_usecs_high;

	coalesce->tx_frames             = ecmd.tx_max_coalesced_frames;
	coalesce->tx_frames_irq         = ecmd.tx_max_coalesced_frames_irq;
	coalesce->tx_frames_low         = ecmd.tx_max_coalesced_frames_low;
	coalesce->tx_frames_high        = ecmd.tx_max_coalesced_frames_high;

	coalesce->rx_usecs              = ecmd.rx_coalesce_usecs;
	coalesce->rx_usecs_irq          = ecmd.rx_coalesce_usecs_irq;
	coalesce->rx_usecs_low          = ecmd.rx_coalesce_usecs_low;
	coalesce->rx_usecs_high         = ecmd.rx_coalesce_usecs_high;

	coalesce->rx_frames             = ecmd.rx_max_coalesced_frames;
	coalesce->rx_frames_irq         = ecmd.rx_max_coalesced_frames_irq;
	coalesce->rx_frames_low         = ecmd.rx_max_coalesced_frames_low;
	coalesce->rx_frames_high        = ecmd.rx_max_coalesced_frames_high;

	ethtool->coalesce = coalesce;
	return ret;
}

int
ni_ethtool_set_coalesce(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, const ni_ethtool_coalesce_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GCOALESCE = {
		ETHTOOL_GCOALESCE,		"get coalesce "
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SCOALESCE = {
		ETHTOOL_SCOALESCE,		"set coalesce "
	};
	struct ethtool_coalesce ecmd;
	int ret;

	if (!cfg)
		return 1;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_COALESCE) ||
	    !ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_COALESCE))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GCOALESCE, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_COALESCE,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (cfg->adaptive_tx != NI_TRISTATE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "adaptive-tx",
				cfg->adaptive_tx, &ecmd.use_adaptive_tx_coalesce,
				NI_TRISTATE_ENABLE);
	}
	if (cfg->adaptive_rx != NI_TRISTATE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "adaptive-rx",
				cfg->adaptive_rx, &ecmd.use_adaptive_rx_coalesce,
				NI_TRISTATE_ENABLE);
	}

	if (cfg->pkt_rate_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "pkt-rate-low",
				cfg->pkt_rate_low, &ecmd.pkt_rate_low,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->pkt_rate_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "pkt-rate-high",
				cfg->pkt_rate_high, &ecmd.pkt_rate_high,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}

	if (cfg->sample_interval != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "sample-interval",
				cfg->sample_interval, &ecmd.rate_sample_interval,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->stats_block_usecs != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "stats-block-usecs",
				cfg->stats_block_usecs, &ecmd.stats_block_coalesce_usecs,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}

	if (cfg->tx_usecs != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "tx-usecs",
				cfg->tx_usecs, &ecmd.tx_coalesce_usecs,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->tx_usecs_irq != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "tx-usecs-irq",
				cfg->tx_usecs_irq, &ecmd.tx_coalesce_usecs_irq,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->tx_usecs_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "tx-usecs-low",
				cfg->tx_usecs_low, &ecmd.tx_coalesce_usecs_low,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->tx_usecs_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "tx-usecs-high",
				cfg->tx_usecs_high, &ecmd.tx_coalesce_usecs_high,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}

	if (cfg->tx_frames != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "tx-frames",
				cfg->tx_frames, &ecmd.tx_max_coalesced_frames,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->tx_frames_irq != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "tx-frames-irq",
				cfg->tx_frames_irq, &ecmd.tx_max_coalesced_frames_irq,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->tx_frames_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "tx-frames-low",
				cfg->tx_frames_low, &ecmd.tx_max_coalesced_frames_low,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->tx_frames_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "tx-frames-high",
				cfg->tx_frames_high, &ecmd.tx_max_coalesced_frames_high,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}


	if (cfg->rx_usecs != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "rx-usecs",
				cfg->rx_usecs, &ecmd.rx_coalesce_usecs,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->rx_usecs_irq != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "rx-usecs-irq",
				cfg->rx_usecs_irq, &ecmd.rx_coalesce_usecs_irq,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->rx_usecs_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "rx-usecs-low",
				cfg->rx_usecs_low, &ecmd.rx_coalesce_usecs_low,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->rx_usecs_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "rx-usecs-high",
				cfg->rx_usecs_high, &ecmd.rx_coalesce_usecs_high,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}

	if (cfg->rx_frames != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "rx-frames",
				cfg->rx_frames, &ecmd.rx_max_coalesced_frames,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->rx_frames_irq != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "rx-frames-irq",
				cfg->rx_frames_irq, &ecmd.rx_max_coalesced_frames_irq,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->rx_frames_low != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "rx-frames-low",
				cfg->rx_frames_low, &ecmd.rx_max_coalesced_frames_low,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}
	if (cfg->rx_frames_high != NI_ETHTOOL_COALESCE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_COALESCE,
				&NI_ETHTOOL_CMD_SCOALESCE, &ecmd, "rx-frames-high",
				cfg->rx_frames_high, &ecmd.rx_max_coalesced_frames_high,
				NI_ETHTOOL_COALESCE_DEFAULT);
	}

	return 0;
}

/*
 * pause (GPAUSEPARAM,SPAUSEPARAM)
 */
void
ni_ethtool_pause_free(ni_ethtool_pause_t *pause)
{
	free(pause);
}

ni_ethtool_pause_t *
ni_ethtool_pause_new(void)
{
	ni_ethtool_pause_t *pause;

	pause = calloc(1, sizeof(*pause));
	if (pause) {
		pause->tx	   = NI_TRISTATE_DEFAULT;
		pause->rx          = NI_TRISTATE_DEFAULT;
		pause->autoneg     = NI_TRISTATE_DEFAULT;
	}

	return pause;
}

int
ni_ethtool_get_pause(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GPAUSE = {
		ETHTOOL_GPAUSEPARAM,		"get pause"
	};
	struct ethtool_pauseparam ecmd;
	ni_ethtool_pause_t *pause;
	int ret;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_PAUSE))
		return -EOPNOTSUPP;

	ni_ethtool_pause_free(ethtool->pause);
	ethtool->pause = NULL;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GPAUSE, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_PAUSE,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (!(pause = ni_ethtool_pause_new()))
		return -ENOMEM;
	ni_tristate_set(&pause->tx, ecmd.tx_pause);
	ni_tristate_set(&pause->rx, ecmd.rx_pause);
	ni_tristate_set(&pause->autoneg, ecmd.autoneg);

	ethtool->pause = pause;
	return ret;
}

int
ni_ethtool_set_pause(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, const ni_ethtool_pause_t *cfg)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GPAUSE = {
		ETHTOOL_GPAUSEPARAM,		"get pause"
	};
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_SPAUSE = {
		ETHTOOL_SPAUSEPARAM,		"set pause"
	};
	struct ethtool_pauseparam ecmd;
	int ret;

	if (!cfg)
		return 1;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_PAUSE) ||
	    !ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_SET_PAUSE))
		return -EOPNOTSUPP;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ref, &NI_ETHTOOL_CMD_GPAUSE, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_PAUSE,
			ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	if (cfg->tx != NI_TRISTATE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_PAUSE,
				&NI_ETHTOOL_CMD_SPAUSE, &ecmd, "tx",
				cfg->tx, &ecmd.tx_pause,
				NI_TRISTATE_ENABLE);
	}

	if (cfg->rx != NI_TRISTATE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_PAUSE,
				&NI_ETHTOOL_CMD_SPAUSE, &ecmd, "rx",
				cfg->rx, &ecmd.rx_pause,
				NI_TRISTATE_ENABLE);
	}

	if (cfg->autoneg != NI_TRISTATE_DEFAULT) {
		ni_ethtool_set_uint_param(ref, ethtool, NI_ETHTOOL_SUPP_SET_PAUSE,
				&NI_ETHTOOL_CMD_SPAUSE, &ecmd, "autoneg",
				cfg->autoneg, &ecmd.autoneg,
				NI_TRISTATE_ENABLE);
	}
	return 0;
}


/*
 * main system refresh and setup functions
 */
static ni_bool_t
ni_ethtool_refresh(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;
	ni_netdev_ref_t ref;

	if (!dev || !(ethtool = ni_netdev_get_ethtool(dev)))
		return FALSE;

	ref.name = dev->name;
	ref.index = dev->link.ifindex;
	if (!ethtool->driver_info)
		ni_ethtool_get_driver_info(&ref, ethtool);
	ni_ethtool_get_priv_flags(&ref, ethtool);
	ni_ethtool_get_link_detected(&ref, ethtool);
	ni_ethtool_get_link_settings(&ref, ethtool);
	ni_ethtool_get_wake_on_lan(&ref, ethtool);
	ni_ethtool_get_features(&ref, ethtool, FALSE);
	ni_ethtool_get_eee(&ref, ethtool);
	ni_ethtool_get_ring(&ref, ethtool);
	ni_ethtool_get_channels(&ref, ethtool);
	ni_ethtool_get_coalesce(&ref, ethtool);
	ni_ethtool_get_pause(&ref, ethtool);

	return TRUE;
}

void
ni_system_ethtool_refresh(ni_netdev_t *dev)
{
	if (!ni_netdev_device_is_ready(dev) || !dev->link.ifindex)
		return;

	ni_ethtool_refresh(dev);
}

int
ni_system_ethtool_setup(ni_netconfig_t *nc, ni_netdev_t *dev, const ni_netdev_t *cfg)
{
	ni_netdev_ref_t ref;

	if (!ni_netdev_device_is_ready(dev) || !dev->link.ifindex)
		return -1;

	if (!dev->ethtool && !ni_ethtool_refresh(dev))
		return -1;

	ref.name = dev->name;
	ref.index = dev->link.ifindex;
	if (cfg && cfg->ethtool) {
		ni_ethtool_set_priv_flags(&ref, dev->ethtool, cfg->ethtool->priv_flags);
		ni_ethtool_set_link_settings(&ref, dev->ethtool, cfg->ethtool->link_settings);
		ni_ethtool_set_wake_on_lan(&ref, dev->ethtool, cfg->ethtool->wake_on_lan);
		ni_ethtool_set_features(&ref, dev->ethtool, cfg->ethtool->features);
		ni_ethtool_set_eee(&ref, dev->ethtool, cfg->ethtool->eee);
		ni_ethtool_set_ring(&ref, dev->ethtool, cfg->ethtool->ring);
		ni_ethtool_set_channels(&ref, dev->ethtool, cfg->ethtool->channels);
		ni_ethtool_set_coalesce(&ref, dev->ethtool, cfg->ethtool->coalesce);
		ni_ethtool_set_pause(&ref, dev->ethtool, cfg->ethtool->pause);
		ni_ethtool_refresh(dev);
	}
	return 0;
}

/*
 * main netdev ethtool struct get/set helpers
 */
void
ni_ethtool_free(ni_ethtool_t *ethtool)
{
	if (ethtool) {
		ni_bitfield_destroy(&ethtool->supported);
		ni_ethtool_driver_info_free(ethtool->driver_info);
		ni_ethtool_priv_flags_free(ethtool->priv_flags);
		ni_ethtool_link_settings_free(ethtool->link_settings);
		ni_ethtool_wake_on_lan_free(ethtool->wake_on_lan);
		ni_ethtool_features_free(ethtool->features);
		ni_ethtool_eee_free(ethtool->eee);
		ni_ethtool_ring_free(ethtool->ring);
		ni_ethtool_channels_free(ethtool->channels);
		ni_ethtool_coalesce_free(ethtool->coalesce);
		free(ethtool);
	}
}

static inline void
ni_ethtool_init(ni_ethtool_t *ethtool)
{
	if (ethtool)  {
		unsigned int flag;

		/* initially, everything is supported */
		for (flag = 0; flag < NI_ETHTOOL_SUPPORT_MAX; ++flag)
			ni_bitfield_setbit(&ethtool->supported, flag);

		ethtool->link_detected = NI_TRISTATE_DEFAULT;
	}
}

ni_ethtool_t *
ni_ethtool_new(void)
{
	ni_ethtool_t *ethtool;

	ethtool = calloc(1, sizeof(*ethtool));
	ni_ethtool_init(ethtool);
	return ethtool;
}

ni_ethtool_t *
ni_netdev_get_ethtool(ni_netdev_t *dev)
{
	if (!dev->ethtool)
		dev->ethtool = ni_ethtool_new();
	return dev->ethtool;
}

ni_ethtool_driver_info_t *
ni_netdev_get_ethtool_driver_info(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->driver_info)
		ethtool->driver_info = ni_ethtool_driver_info_new();
	return ethtool->driver_info;
}

ni_ethtool_priv_flags_t *
ni_netdev_get_ethtool_priv_flags(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->priv_flags)
		ethtool->priv_flags = ni_ethtool_priv_flags_new();
	return ethtool->priv_flags;
}

ni_ethtool_link_settings_t *
ni_netdev_get_ethtool_link_settings(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->link_settings)
		ethtool->link_settings = ni_ethtool_link_settings_new();
	return ethtool->link_settings;
}

ni_ethtool_wake_on_lan_t *
ni_netdev_get_ethtool_wake_on_lan(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->wake_on_lan)
		ethtool->wake_on_lan = ni_ethtool_wake_on_lan_new();
	return ethtool->wake_on_lan;
}

ni_ethtool_features_t *
ni_netdev_get_ethtool_features(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->features)
		ethtool->features = ni_ethtool_features_new();
	return ethtool->features;
}

ni_ethtool_eee_t *
ni_netdev_get_ethtool_eee(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->eee)
		ethtool->eee = ni_ethtool_eee_new();
	return ethtool->eee;
}

ni_ethtool_ring_t *
ni_netdev_get_ethtool_ring(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->ring)
		ethtool->ring = ni_ethtool_ring_new();
	return ethtool->ring;
}

ni_ethtool_channels_t *
ni_netdev_get_ethtool_channels(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->channels)
		ethtool->channels = ni_ethtool_channels_new();
	return ethtool->channels;
}

ni_ethtool_coalesce_t *
ni_netdev_get_ethtool_coalesce(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->coalesce)
		ethtool->coalesce = ni_ethtool_coalesce_new();
	return ethtool->coalesce;
}

ni_ethtool_pause_t *
ni_netdev_get_ethtool_pause(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_netdev_get_ethtool(dev)))
		return NULL;
	if (!ethtool->pause)
		ethtool->pause = ni_ethtool_pause_new();
	return ethtool->pause;
}

void
ni_netdev_set_ethtool(ni_netdev_t *dev, ni_ethtool_t *ethtool)
{
	if (dev->ethtool)
		ni_ethtool_free(dev->ethtool);
	dev->ethtool = ethtool;
}

