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
	NI_ETHTOOL_SUPP_GET_PRIV_FLAGS,
	NI_ETHTOOL_SUPP_SET_PRIV_FLAGS,

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
ni_ethtool_call(const char *ifname, const ni_ethtool_cmd_info_t *ioc, void *evp, const char *flag)
{
	int ret;

	ret = __ni_ethtool(ifname, ioc->cmd, evp);
	if (ret < 0) {
		ret = -errno;
		if (errno != EOPNOTSUPP && errno != ENODEV)
			ni_warn("%s: ethtool %s%s failed: %m", ifname, ioc->name, flag ? flag : "");
		else
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG,
				"%s: ethtool %s%s failed: %m", ifname, ioc->name, flag ? flag : "");
		errno = -ret;
	}
	return ret;
}

/*
 * ethtool gstring set utils
 */
static unsigned int
ni_ethtool_get_gstring_count(const char *ifname, const char *hint, unsigned int sset)
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

	if (ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GSSET_INFO, &sset_info, hint) < 0)
		return 0;

	errno = 0;
	if (sset_info.hdr.sset_mask != (1ULL << sset))
		return 0;

	return sset_info.hdr.data[0];
}

static struct ethtool_gstrings *
ni_ethtool_get_gstrings(const char *ifname, const char *hint, unsigned int sset, unsigned int count)
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
		ni_warn("%s: unable to allocate %u ethtool %s", ifname, count, hint);
		return NULL;
	}

	gstrings->string_set = sset;
	gstrings->len = count;
	if (ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GSTRINGS, gstrings, hint) < 0) {
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
ni_ethtool_get_driver_info(const char *ifname, ni_ethtool_t *ethtool)
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
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GDRVINFO, &drv_info, NULL);
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

static const ni_intmap_t	ni_ethternet_driver_supports_bits[] = {
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
	return ni_format_uint_mapped(bit, ni_ethternet_driver_supports_bits);
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
ni_ethtool_get_priv_flags_names(const char *ifname, ni_ethtool_t *ethtool, ni_string_array_t *names)
{
	struct ethtool_gstrings *gstrings;
	unsigned int count, i;
	ni_stringbuf_t buf;
	const char *name;

	count = ni_ethtool_get_gstring_count(ifname, " priv-flags count", ETH_SS_PRIV_FLAGS);
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
	gstrings = ni_ethtool_get_gstrings(ifname, " priv-flags names", ETH_SS_PRIV_FLAGS, count);
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
ni_ethtool_get_priv_flags_bitmap(const char *ifname, ni_ethtool_t *ethtool, unsigned int *bitmap)
{
	static const ni_ethtool_cmd_info_t NI_ETHTOOL_CMD_GPFLAGS = {
		ETHTOOL_GPFLAGS,	"get priv-flag values"
	};
	struct ethtool_value ecmd;
	int ret;

	memset(&ecmd, 0, sizeof(ecmd));
	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_GPFLAGS, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_PRIV_FLAGS,
				ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	*bitmap = ecmd.data;
	return 0;
}

int
ni_ethtool_get_priv_flags(const char *ifname, ni_ethtool_t *ethtool)
{
	int ret = 0;

	if (!ni_ethtool_supported(ethtool, NI_ETHTOOL_SUPP_GET_PRIV_FLAGS))
		return -EOPNOTSUPP;

	if (!ethtool->priv_flags) {
		if (!(ethtool->priv_flags = ni_ethtool_priv_flags_new()))
			return -ENOMEM;
	}

	ethtool->priv_flags->bitmap = 0;
	ret = ni_ethtool_get_priv_flags_bitmap(ifname, ethtool, &ethtool->priv_flags->bitmap);
	if (ret < 0) {
		ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_GET_PRIV_FLAGS, ret != -EOPNOTSUPP);
		goto cleanup;
	}

	if (!ethtool->priv_flags->names.count) {
		ret = ni_ethtool_get_priv_flags_names(ifname, ethtool, &ethtool->priv_flags->names);
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
ni_ethtool_set_priv_flags(const char *ifname, ni_ethtool_t *ethtool, const ni_ethtool_priv_flags_t *pflags)
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
	if (!ethtool->priv_flags && (ret = ni_ethtool_get_priv_flags(ifname, ethtool)) < 0)
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
					ifname, name);
			continue;
		}

		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"%s: setting driver private flag '%s' to %s",
				ifname, name, ni_format_boolean(enabled));
		if (enabled)
			ecmd.data |= NI_BIT(bit);
		else
			ecmd.data &= ~NI_BIT(bit);
	}
	if (ecmd.data == ethtool->priv_flags->bitmap)
		return 0;

	ret = ni_ethtool_call(ifname, &NI_ETHTOOL_CMD_SPFLAGS, &ecmd, NULL);
	ni_ethtool_set_supported(ethtool, NI_ETHTOOL_SUPP_SET_PRIV_FLAGS,
				ret != -EOPNOTSUPP);
	if (ret < 0)
		return ret;

	return 0;
}

/*
 * main system refresh and setup functions
 */
static ni_bool_t
ni_ethtool_refresh(ni_netdev_t *dev)
{
	ni_ethtool_t *ethtool;

	if (!dev || !(ethtool = ni_netdev_get_ethtool(dev)))
		return FALSE;

	if (!ethtool->driver_info)
		ni_ethtool_get_driver_info(dev->name, ethtool);
	ni_ethtool_get_priv_flags(dev->name, ethtool);

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
	if (!ni_netdev_device_is_ready(dev) || !dev->link.ifindex)
		return -1;

	if (!dev->ethtool && !ni_ethtool_refresh(dev))
		return -1;

	if (cfg && cfg->ethtool) {
		ni_ethtool_set_priv_flags(dev->name, dev->ethtool, cfg->ethtool->priv_flags);
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

void
ni_netdev_set_ethtool(ni_netdev_t *dev, ni_ethtool_t *ethtool)
{
	if (dev->ethtool)
		ni_ethtool_free(dev->ethtool);
	dev->ethtool = ethtool;
}

