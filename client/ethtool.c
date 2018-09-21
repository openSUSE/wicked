/*
 *	wicked client ethtool utilities
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
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/ethtool.h>
#include <wicked/util.h>

struct ethtool_args {
	int	argc;
	char **	argv;
};

struct ethtool_opt {
	const char *	name;
	int		(*func)(const ni_netdev_ref_t *, ni_ethtool_t *, struct ethtool_args *args);
	const char *	usage;
	ni_bool_t       alias;
};


/*
 * driver-info
 */
static int
get_ethtool_driver_info(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	const ni_ethtool_driver_info_t *info;
	unsigned int n;

	(void)args;
	if (ni_ethtool_get_driver_info(ref, ethtool) < 0 || !(info = ethtool->driver_info))
		return -1;

	printf("driver-info:\n");
	if (!ni_string_empty(info->driver))
		printf("\tdriver: %s\n", info->driver);
	if (!ni_string_empty(info->version))
		printf("\tversion: %s\n", info->version);
	if (!ni_string_empty(info->bus_info))
		printf("\tbus-info: %s\n", info->bus_info);
	if (!ni_string_empty(info->fw_version))
		printf("\tfirmware-version: %s\n", info->fw_version);
	if (!ni_string_empty(info->erom_version))
		printf("\texpansion-rom-version: %s\n", info->erom_version);
	printf("\tsupports:\n");
	for (n = 0; n <= NI_ETHTOOL_DRIVER_SUPP_REGDUMP; ++n) {
		printf("\t\t%s: %s\n",
				ni_ethtool_driver_supports_map_bit(n),
				info->supports.bitmap & NI_BIT(n) ? "yes" : "no");
	}

	return 0;
}


/*
 * private-flags
 */
static int
get_ethtool_priv_flags(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	const ni_ethtool_priv_flags_t *pflags;
	const char *name;
	unsigned int n;

	(void)args;
	if (ni_ethtool_get_priv_flags(ref, ethtool) < 0 || !(pflags = ethtool->priv_flags))
		return -1;

	printf("private-flags:\n");
	for (n = 0; n < pflags->names.count; ++n) {
		name = pflags->names.data[n];
		printf("\t%s: %s\n", name, pflags->bitmap & NI_BIT(n) ? "on" : "off");
	}
	return 0;
}

static int
set_ethtool_priv_flags(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_priv_flags_t *pflags;
	ni_bool_t enabled;
	char *key, *val;
	int ret = -1, n;

	if (!(pflags = ni_ethtool_priv_flags_new()))
		return ret;

	for (n = 0; n + 1 < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		val = args->argv[n];

		if (ni_parse_boolean(val, &enabled) ||
		    ni_string_array_append(&pflags->names, key))
			goto cleanup;

		if (enabled)
			pflags->bitmap |= NI_BIT(pflags->names.count - 1);
	}

	ret = ni_ethtool_set_priv_flags(ref, ethtool, pflags);

cleanup:
	ni_ethtool_priv_flags_free(pflags);
	return ret;
}


/*
 * link-detected
 */
static int
get_ethtool_link_detected(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	(void)args;
	if (ni_ethtool_get_link_detected(ref, ethtool) < 0 || !ni_tristate_is_set(ethtool->link_detected))
		return -1;

	printf("link-detected: %s\n", ni_format_boolean(ethtool->link_detected));
	return 0;
}


/*
 * link-settings
 */
static inline ni_bool_t
get_ethtool_link_adv_name_array(ni_string_array_t *array, ni_bitfield_t *bitfield,
				const char * (*bit_to_name)(unsigned int))
{
	unsigned int bit, bits, count;
	const char *name;

	count = array->count;
	bits = ni_bitfield_bits(bitfield);
	for (bit = 0; bit < bits; ++bit) {
		if (!ni_bitfield_testbit(bitfield, bit))
			continue;

		if (!(name = bit_to_name(bit)))
			continue;

		if (ni_string_array_append(array, name) == 0)
			ni_bitfield_clearbit(bitfield, bit);
	}
	return array->count > count;
}

static void
get_ethtool_link_advertising(const char *type, ni_bitfield_t *bitfield)
{
	ni_string_array_t tmp = NI_STRING_ARRAY_INIT;
	char *hexstr = NULL;
	unsigned int n;

	if (!ni_bitfield_isset(bitfield) || !type)
		return;

	printf("\t%s:\n", type);
	printf("\t\tautoneg: %s\n", ni_format_boolean(ni_ethtool_link_adv_autoneg(bitfield)));
	ni_ethtool_link_adv_set_autoneg(bitfield, FALSE);

	if (get_ethtool_link_adv_name_array(&tmp, bitfield, ni_ethtool_link_adv_port_name)) {
		printf("\t\tport-types:\n");
		for (n = 0; n < tmp.count; ++n) {
			printf("\t\t\ttype: %s\n", tmp.data[n]);
		}
	}
	ni_string_array_destroy(&tmp);

	if (get_ethtool_link_adv_name_array(&tmp, bitfield, ni_ethtool_link_adv_speed_name)) {
		printf("\t\tspeed-modes:\n");
		for (n = 0; n < tmp.count; ++n) {
			printf("\t\t\tmode: %s\n", tmp.data[n]);
		}
	}
	ni_string_array_destroy(&tmp);

	if (get_ethtool_link_adv_name_array(&tmp, bitfield, ni_ethtool_link_adv_pause_name)) {
		printf("\t\tpause-frames:\n");
		for (n = 0; n < tmp.count; ++n) {
			printf("\t\t\ttype: %s\n", tmp.data[n]);
		}
	}
	ni_string_array_destroy(&tmp);

	if (get_ethtool_link_adv_name_array(&tmp, bitfield, ni_ethtool_link_adv_fec_name)) {
		printf("\t\tfec-modes:\n");
		for (n = 0; n < tmp.count; ++n) {
			printf("\t\t\tmode: %s\n", tmp.data[n]);
		}
	}
	ni_string_array_destroy(&tmp);

	if (get_ethtool_link_adv_name_array(&tmp, bitfield, ni_ethtool_link_adv_port_name)) {
		printf("\t\tport-types:\n");
		for (n = 0; n < tmp.count; ++n) {
			printf("\t\t\ttype: %s\n", tmp.data[n]);
		}
	}
	ni_string_array_destroy(&tmp);

	if (ni_bitfield_isset(bitfield) && ni_bitfield_format(bitfield, &hexstr, TRUE))
		printf("\t\tunknown: %s\n", hexstr);
	ni_string_free(&hexstr);
}

static int
get_ethtool_link_settings(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_link_settings_t *link;
	const char *name;

	(void)args;
	if (ni_ethtool_get_link_settings(ref, ethtool) < 0 || !(link = ethtool->link_settings))
		return -1;

	printf("link-settings:\n");
	if (ni_tristate_is_set(link->autoneg))
		printf("\tautoneg: %s\n", ni_format_boolean(link->autoneg));
	if (link->speed != NI_ETHTOOL_SPEED_UNKNOWN)
		printf("\tspeed: %u\n", link->speed);
	if ((name = ni_ethtool_link_duplex_name(link->duplex)))
		printf("\tduplex: %s\n", name);
	if ((name = ni_ethtool_link_port_name(link->port)))
		printf("\tport: %s\n", name);
	if ((name = ni_ethtool_link_mdix_name(link->tp_mdix)))
		printf("\tmdix: %s\n", name);
	if ((name = ni_ethtool_link_mdio_name(link->mdio_support)))
		printf("\tmdio: %s\n", name);
	if (link->phy_address != NI_ETHTOOL_PHYAD_UNKNOWN)
		printf("\tphy-address: %u\n", link->phy_address);
	if (link->transceiver != NI_ETHTOOL_XCVR_UNKNOWN)
		printf("\ttransceiver: %u\n", link->transceiver);

	get_ethtool_link_advertising("supported", &link->supported);
	get_ethtool_link_advertising("advertising",  &link->advertising);
	get_ethtool_link_advertising("lp-advertising", &link->lp_advertising);
	return 0;
}

static inline ni_bool_t
set_ethtool_link_advertise(const char *value, ni_bitfield_t *bitfield)
{
	ni_string_array_t tmp = NI_STRING_ARRAY_INIT;
	unsigned int i, bit;
	ni_bool_t ret = FALSE;

	if (ni_string_split(&tmp, value, ",", 0)) {
		ret = tmp.count > 0;

		for (i = 0; i < tmp.count; ++i) {
			value = tmp.data[i];
			if (ni_ethtool_link_adv_type(value, &bit))
				ni_bitfield_setbit(bitfield, bit);
			else
			if (!(ret = ni_bitfield_parse(bitfield, value, 0)))
				break;
		}
	}
	ni_string_array_destroy(&tmp);
	return ret;
}

static int
set_ethtool_link_settings(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_link_settings_t *link;
	char *key = NULL, *val = NULL;
	unsigned int value;
	ni_bool_t enabled;
	int ret = -1, n;

	if (!(link = ni_ethtool_link_settings_new()))
		return ret;

	for (n = 0; n < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		if (n < args->argc)
			val = args->argv[n];
		else
			break;

		if (ni_string_eq(key, "autoneg")) {
			if (ni_parse_boolean(val, &enabled) != 0)
				break;
			ni_tristate_set(&link->autoneg, enabled);
		} else
		if (ni_string_eq(key, "speed")) {
			if (ni_parse_uint(val, &value, 10) != 0)
				break;
			link->speed = value;
		} else
		if (ni_string_eq(key, "duplex")) {
			if (!ni_ethtool_link_duplex_type(val, &value))
				break;
			link->duplex = value;
		} else
		if (ni_string_eq(key, "port")) {
			if (!ni_ethtool_link_port_type(val, &value))
				break;
			link->port = value;
		} else
		if (ni_string_eq(key, "mdix")) {
			if (!ni_ethtool_link_mdix_type(val, &value))
				break;
			link->tp_mdix = value;
		} else
		if (ni_string_eq(key, "phy-address")) {
			if (ni_parse_uint(val, &value, 10) != 0)
				break;
			link->phy_address = value;
		} else
		if (ni_string_eq(key, "transceiver")) {
			if (!ni_ethtool_link_xcvr_type(val, &value))
				break;
			link->transceiver = value;
		} else
		if (ni_string_eq(key, "advertise")) {
			if (!set_ethtool_link_advertise(val, &link->advertising))
				break;
		} else {
			val = key;
			key = NULL;
			break;
		}

		key = NULL;
		val = NULL;
	}

	if (key) {
		if (val)
			fprintf(stderr, "%s: cannot parse link '%s' argument '%s'\n",
					ref->name, key, val);
		else
			fprintf(stderr, "%s: missing link '%s' value argument\n",
					ref->name, key);
	} else {
		if (val)
			fprintf(stderr, "%s: unknown link setting name '%s'\n",
					ref->name, val);
		else
			ret = ni_ethtool_set_link_settings(ref, ethtool, link);
	}
	ni_ethtool_link_settings_free(link);
	return ret;
}


/*
 * wake_on_lan
 */
static int
get_ethtool_wake_on_lan(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_wake_on_lan_t *wol;
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

	(void)args;
	if (ni_ethtool_get_wake_on_lan(ref, ethtool) < 0 || !(wol = ethtool->wake_on_lan))
		return -1;

	printf("wake-on-lan:\n");
	ni_ethtool_wol_flags_format(&buf, wol->options, ",");
	printf("\toptions: %s\n", buf.string ? buf.string : "disabled");
	ni_stringbuf_destroy(&buf);

	return 0;
}

static ni_bool_t
set_ethtool_wake_on_lan_letterjam(ni_ethtool_wake_on_lan_t *wol, const char *value)
{
	unsigned int options = NI_ETHTOOL_WOL_DISABLE;

	while(*value) {
		switch (*value) {
		case 'p': options |= NI_BIT(NI_ETHTOOL_WOL_PHY);	break;
		case 'u': options |= NI_BIT(NI_ETHTOOL_WOL_UCAST);	break;
		case 'm': options |= NI_BIT(NI_ETHTOOL_WOL_MCAST);	break;
		case 'b': options |= NI_BIT(NI_ETHTOOL_WOL_BCAST);	break;
		case 'a': options |= NI_BIT(NI_ETHTOOL_WOL_ARP);	break;
		case 'g': options |= NI_BIT(NI_ETHTOOL_WOL_MAGIC);	break;
		case 's': options |= NI_BIT(NI_ETHTOOL_WOL_SECUREON);	break;
		case 'd': wol->options = NI_ETHTOOL_WOL_DISABLE;	break;
		default:  return FALSE;
		}
		value++;
	}

	if (wol->options == NI_ETHTOOL_WOL_DEFAULT)
		wol->options = options;

	return TRUE;
}

static ni_bool_t
set_ethtool_wake_on_lan_options(ni_ethtool_wake_on_lan_t *wol, const char *value)
{
	ni_string_array_t tmp = NI_STRING_ARRAY_INIT;
	unsigned int i, flag;
	unsigned int options;
	ni_bool_t ret = TRUE;

	if (!ni_string_split(&tmp, value, ",|", 0))
		return FALSE;

	if (tmp.count == 1) {
		value = tmp.data[0];

		if (set_ethtool_wake_on_lan_letterjam(wol, value))
			goto cleanup;
	}

	options = NI_ETHTOOL_WOL_DISABLE;
	for (i = 0; i < tmp.count; ++i) {
		value = tmp.data[i];

		if (ni_string_eq(value, "d") ||
		    ni_string_eq(value, "disable") ||
		    ni_string_eq(value, "disabled")) {
			wol->options = NI_ETHTOOL_WOL_DISABLE;
			break;
		}

		if (ni_ethtool_wol_flag_type(value, &flag))
			options |= NI_BIT(flag);
		else
			ret = FALSE;
	}

	if (ret && wol->options == NI_ETHTOOL_WOL_DEFAULT)
		wol->options = options;

cleanup:
	ni_string_array_destroy(&tmp);
	return ret;
}

static int
set_ethtool_wake_on_lan(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_wake_on_lan_t *wol;
	char *key = NULL, *val = NULL;
	int ret = -1, n;

	if (!(wol = ni_ethtool_wake_on_lan_new()))
		return ret;

	for (n = 0; n < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		if (n < args->argc)
			val = args->argv[n];
		else
			break;

		if (ni_string_eq(key, "options")) {
			if (!set_ethtool_wake_on_lan_options(wol, val))
				break;
		} else
		if (ni_string_eq(key, "sopass")) {
			if (ni_link_address_parse(&wol->sopass, ARPHRD_ETHER, val) < 0)
				break;
		} else {
			val = key;
			key = NULL;
		}

		key = NULL;
		val = NULL;
	}

	if (wol->sopass.len && !(wol->options & NI_BIT(NI_ETHTOOL_WOL_SECUREON)))
		wol->options |= NI_BIT(NI_ETHTOOL_WOL_SECUREON);

	if (key) {
		if (val)
			fprintf(stderr, "%s: cannot parse wake-on-lan %s' value argument '%s'\n",
					ref->name, key, val);
		else
			fprintf(stderr, "%s: missing wake-on-lan '%s' value argument\n",
					ref->name, key);
	} else {
		if (val)
			fprintf(stderr, "%s: unknown wake-on-lan setting name '%s'\n",
					ref->name, val);
		else
			ret = ni_ethtool_set_wake_on_lan(ref, ethtool, wol);
	}

	ni_ethtool_wake_on_lan_free(wol);
	return ret;
}


/*
 * features
 */
static int
get_ethtool_features(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	const ni_ethtool_features_t *features;
	const ni_ethtool_feature_t *feature;
	const char *name;
	unsigned int n;

	(void)args;
	if (ni_ethtool_get_features(ref, ethtool, TRUE) < 0 || !(features = ethtool->features))
		return -1;

	printf("features:\n");
	for (n = 0; n < features->count; ++n) {
		feature = features->data[n];
		name = feature->map.name;
		printf("\t%s: ", name);
		printf("%s%s\n", feature->value & NI_ETHTOOL_FEATURE_ON ? "on" : "off",
				feature->value & NI_ETHTOOL_FEATURE_FIXED ? " fixed" :
				feature->value & NI_ETHTOOL_FEATURE_REQUESTED ? " requested" : "");
	}
	return 0;
}

static int
set_ethtool_features(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_features_t *features;
	char *key = NULL, *val = NULL;
	ni_bool_t enabled;
	int ret = -1, n;

	if (!(features = ni_ethtool_features_new()))
		return ret;

	for (n = 0; n < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		if (n < args->argc)
			val = args->argv[n];
		else
			break;

		if (ni_parse_boolean(val, &enabled) < 0)
			break;

		ni_ethtool_features_set(features, key, enabled ?
				NI_ETHTOOL_FEATURE_ON : NI_ETHTOOL_FEATURE_OFF);

		key = NULL;
		val = NULL;
	}

	if (key) {
		if (val)
			fprintf(stderr, "%s: cannot parse feature '%s' value argument '%s'\n",
					ref->name, key, val);
		else
			fprintf(stderr, "%s: missing feature '%s' value argument\n",
					ref->name, key);
	} else {
		ret = ni_ethtool_set_features(ref, ethtool, features);
	}

	ni_ethtool_features_free(features);
	return ret;
}


/*
 * eee
 */
static void
get_ethtool_eee_advertising(const char *type, ni_bitfield_t *bitfield)
{
	ni_string_array_t tmp = NI_STRING_ARRAY_INIT;
	unsigned int n;
	char * hexstr = NULL;

	if (!ni_bitfield_isset(bitfield) || !type)
		return;

	printf("\t%s:\n", type);
	if (get_ethtool_link_adv_name_array(&tmp, bitfield, ni_ethtool_link_adv_speed_name)) {
		printf("\t\tspeed-modes:\n");
		for (n = 0; n < tmp.count; ++n) {
			printf("\t\t\tmode: %s\n", tmp.data[n]);
		}
	}
	ni_string_array_destroy(&tmp);

	if (ni_bitfield_isset(bitfield) && ni_bitfield_format(bitfield, &hexstr, TRUE))
		printf("\t\tunknown: %s\n", hexstr);
	ni_string_free(&hexstr);
}

static int
get_ethtool_eee(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_eee_t *eee;

	if (ni_ethtool_get_eee(ref, ethtool) < 0 || !(eee = ethtool->eee))
		return -1;

	printf("eee:\n");
	printf("\tenabled: %s\n", eee->status.enabled ? "on" : "off");
	printf("\tactive: %s\n", eee->status.active ? "on" : "off");
	printf("\ttx-lpi: %s\n", eee->tx_lpi.enabled ? "on" : "off");
	printf("\ttx-timer: %u\n", eee->tx_lpi.timer);
	get_ethtool_eee_advertising("supported", &eee->speed.supported);
	get_ethtool_eee_advertising("advertising", &eee->speed.advertising);
	get_ethtool_eee_advertising("lp-advertising", &eee->speed.lp_advertising);

	return 0;
}

static int
set_ethtool_eee(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_eee_t *eee;
	char *key = NULL, *val = NULL;
	ni_bool_t enabled;
	int ret = -1, n;

	if (!(eee = ni_ethtool_eee_new()))
		return ret;

	for (n = 0; n < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		if (n < args->argc)
			val = args->argv[n];
		else
			break;
		if (ni_string_eq(key, "eee")) {
			if (ni_parse_boolean(val, &enabled) != 0)
				break;
			ni_tristate_set(&eee->status.enabled, enabled);
		} else
		if (ni_string_eq(key, "tx-lpi")) {
			if (ni_parse_boolean(val, &enabled) != 0)
				break;
			ni_tristate_set(&eee->tx_lpi.enabled, enabled);
		} else
		if (ni_string_eq(key, "tx-timer")) {
			ni_parse_uint(val, &eee->tx_lpi.timer, 10);
		} else
		if (ni_string_eq(key, "advertise")) {
			if (!set_ethtool_link_advertise(val, &eee->speed.advertising))
				break;
		} else {
			val = key;
			key = NULL;
			break;
		}

		key = NULL;
		val = NULL;
	}

	if (key) {
		if (val)
			fprintf(stderr, "%s: cannot parse eee '%s' argument '%s'\n",
					ref->name, key, val);
		else
			fprintf(stderr, "%s: missing eee '%s' value argument\n",
					ref->name, key);
	} else {
		if (val)
			fprintf(stderr, "%s: unknown eee setting name '%s'\n",
					ref->name, val);
		else
			ret = ni_ethtool_set_eee(ref, ethtool, eee);
	}
	ni_ethtool_eee_free(eee);
	return ret;
}


/*
 * ring
 */
static int
get_ethtool_ring(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_ring_t *ring;

	if (ni_ethtool_get_ring(ref, ethtool) < 0 || !(ring = ethtool->ring))
		return -1;

	printf("ring:\n");
	printf("\ttx: %u\n", ring->tx);
	printf("\ttx: %u\n", ring->rx);
	printf("\trx-mini: %u\n", ring->rx_mini);
	printf("\trx-jumbo: %u\n", ring->rx_jumbo);

	return 0;
}

static int
set_ethtool_ring(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_ring_t *ring;
	char *key = NULL, *val = NULL;
	int ret = -1, n;

	if (!(ring = ni_ethtool_ring_new()))
		return ret;

	for (n = 0; n < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		if (n < args->argc)
			val = args->argv[n];
		else
			break;
		if (ni_string_eq(key, "tx")) {
			ni_parse_uint(val, &ring->tx, 10);
		} else
		if (ni_string_eq(key, "rx")) {
			ni_parse_uint(val, &ring->rx, 10);
		} else
		if (ni_string_eq(key, "rx-jumbo") ||
				ni_string_eq(key, "rx_jumbo")) {
			ni_parse_uint(val, &ring->rx_jumbo, 10);
		} else
		if (ni_string_eq(key, "rx-mini") ||
				ni_string_eq(key, "rx_mini")) {
			ni_parse_uint(val, &ring->rx_mini, 10);
		} else {
			val = key;
			key = NULL;
			break;
		}

		key = NULL;
		val = NULL;
	}

	if (key) {
		if (val)
			fprintf(stderr, "%s: cannot parse ring '%s' argument '%s'\n",
					ref->name, key, val);
		else
			fprintf(stderr, "%s: missing ring '%s' value argument\n",
					ref->name, key);
	} else {
		if (val)
			fprintf(stderr, "%s: unknown ring setting name '%s'\n",
					ref->name, val);
		else
			ret = ni_ethtool_set_ring(ref, ethtool, ring);
	}
	ni_ethtool_ring_free(ring);
	return ret;
}


/*
 * channels
 */
static int
get_ethtool_channels(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_channels_t *channels;

	if (ni_ethtool_get_channels(ref, ethtool) < 0 || !(channels = ethtool->channels))
		return -1;

	printf("channels:\n");
	printf("\ttx: %u\n", channels->tx);
	printf("\trx: %u\n", channels->rx);
	printf("\tother: %u\n", channels->other);
	printf("\tcombined: %u\n", channels->combined);

	return 0;
}

static int
set_ethtool_channels(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_channels_t *channels;
	char *key = NULL, *val = NULL;
	int ret = -1, n;

	if (!(channels = ni_ethtool_channels_new()))
		return ret;

	for (n = 0; n < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		if (n < args->argc)
			val = args->argv[n];
		else
			break;
		if (ni_string_eq(key, "tx")) {
			ni_parse_uint(val, &channels->tx, 10);
		} else
		if (ni_string_eq(key, "rx")) {
			ni_parse_uint(val, &channels->rx, 10);
		} else
		if (ni_string_eq(key, "other")) {
			ni_parse_uint(val, &channels->other, 10);
		} else
		if (ni_string_eq(key, "combined")) {
			ni_parse_uint(val, &channels->combined, 10);
		} else {
			val = key;
			key = NULL;
			break;
		}

		key = NULL;
		val = NULL;
	}

	if (key) {
		if (val)
			fprintf(stderr, "%s: cannot parse channels '%s' argument '%s'\n",
					ref->name, key, val);
		else
			fprintf(stderr, "%s: missing channels '%s' value argument\n",
					ref->name, key);
	} else {
		if (val)
			fprintf(stderr, "%s: unknown channels setting name '%s'\n",
					ref->name, val);
		else
			ret = ni_ethtool_set_channels(ref, ethtool, channels);
	}
	ni_ethtool_channels_free(channels);
	return ret;
}


/*
 * coalesce
 */
static int
get_ethtool_coalesce(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_coalesce_t *coalesce;

	if (ni_ethtool_get_coalesce(ref, ethtool) < 0 || !(coalesce = ethtool->coalesce))
		return -1;

	printf("coalesce:\n");
	printf("\tadaptive-tx: %s\n", coalesce->adaptive_tx ? "on" : "off");
	printf("\tadaptive-rx: %s\n", coalesce->adaptive_rx ? "on" : "off");

	printf("\tpkt-rate-low: %u\n", coalesce->pkt_rate_low);
	printf("\tpkt-rate-high: %u\n", coalesce->pkt_rate_high);

	printf("\tsample-interval: %u\n", coalesce->sample_interval);
	printf("\tstats-block-usecs: %u\n", coalesce->stats_block_usecs);

	printf("\ttx-usecs: %u\n", coalesce->tx_usecs);
	printf("\trx-usecs-irq: %u\n", coalesce->rx_usecs_irq);
	printf("\ttx-usecs-low %u\n", coalesce->tx_usecs_low);
	printf("\ttx-usecs-high: %u\n", coalesce->tx_usecs_high);

	printf("\ttx-frames: %u\n", coalesce->tx_frames);
	printf("\ttx-frames-irq: %u\n", coalesce->tx_frames_irq);
	printf("\ttx-frames-low: %u\n", coalesce->tx_frames_low);
	printf("\ttx-frames-high: %u\n", coalesce->tx_frames_high);

	printf("\trx-usecs: %u\n", coalesce->rx_usecs);
	printf("\ttx-usecs-irq: %u\n", coalesce->tx_usecs_irq);
	printf("\trx-usecs-low: %u\n", coalesce->rx_usecs_low);
	printf("\trx-usecs-high: %u\n", coalesce->rx_usecs_high);

	printf("\trx-frames: %u\n", coalesce->rx_frames);
	printf("\trx-frames-irq: %u\n", coalesce->rx_frames_irq);
	printf("\trx-frames-low: %u\n", coalesce->rx_frames_low);
	printf("\trx-frames-high: %u\n", coalesce->rx_frames_high);

	return 0;
}

static int
set_ethtool_coalesce(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_coalesce_t *coalesce;
	char *key = NULL, *val = NULL;
	ni_bool_t enabled;
	int ret = -1, n;

	if (!(coalesce = ni_ethtool_coalesce_new()))
		return ret;

	for (n = 0; n < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		if (n < args->argc)
			val = args->argv[n];
		else
			break;
		if (ni_string_eq(key, "adaptive-rx")) {
			if (ni_parse_boolean(val, &enabled) != 0)
				break;
			ni_tristate_set(&coalesce->adaptive_rx, enabled);
		} else
		if (ni_string_eq(key, "adaptive-tx")) {
			if (ni_parse_boolean(val, &enabled) != 0)
				break;
			ni_tristate_set(&coalesce->adaptive_tx, enabled);
		} else
		if (ni_string_eq(key, "rx-usecs")) {
			ni_parse_uint(val, &coalesce->rx_usecs, 10);
		} else
		if (ni_string_eq(key, "rx-frames")) {
			ni_parse_uint(val, &coalesce->rx_frames, 10);
		} else
		if (ni_string_eq(key, "rx-usecs-irq")) {
			ni_parse_uint(val, &coalesce->rx_usecs_irq, 10);
		} else
		if (ni_string_eq(key, "rx-frames-irq")) {
			ni_parse_uint(val, &coalesce->rx_frames_irq, 10);
		} else
		if (ni_string_eq(key, "tx-usecs")) {
			ni_parse_uint(val, &coalesce->tx_usecs, 10);
		} else
		if (ni_string_eq(key, "tx-frames")) {
			ni_parse_uint(val, &coalesce->tx_frames, 10);
		} else
		if (ni_string_eq(key, "tx-usecs-irq")) {
			ni_parse_uint(val, &coalesce->tx_usecs_irq, 10);
		} else
		if (ni_string_eq(key, "tx-frames-irq")) {
			ni_parse_uint(val, &coalesce->rx_frames_irq, 10);
		} else
		if (ni_string_eq(key, "stats-block-usecs")) {
			ni_parse_uint(val, &coalesce->stats_block_usecs, 10);
		} else
		if (ni_string_eq(key, "pkt-rate-low")) {
			ni_parse_uint(val, &coalesce->pkt_rate_low, 10);
		} else
		if (ni_string_eq(key, "rx-usecs-low")) {
			ni_parse_uint(val, &coalesce->rx_usecs_low, 10);
		} else
		if (ni_string_eq(key, "rx-frames-low")) {
			ni_parse_uint(val, &coalesce->rx_frames_low, 10);
		} else
		if (ni_string_eq(key, "tx-usecs-low")) {
			ni_parse_uint(val, &coalesce->tx_usecs_low, 10);
		} else
		if (ni_string_eq(key, "tx-frames-low")) {
			ni_parse_uint(val, &coalesce->tx_frames_low, 10);
		} else
		if (ni_string_eq(key, "pkt-rate-high")) {
			ni_parse_uint(val, &coalesce->pkt_rate_high, 10);
		} else
		if (ni_string_eq(key, "rx-usecs-high")) {
			ni_parse_uint(val, &coalesce->rx_usecs_high, 10);
		} else
		if (ni_string_eq(key, "rx-frames-high")) {
			ni_parse_uint(val, &coalesce->rx_frames_high, 10);
		} else
		if (ni_string_eq(key, "tx-usecs-high")) {
			ni_parse_uint(val, &coalesce->tx_usecs_high, 10);
		} else
		if (ni_string_eq(key, "tx-frames-high")) {
			ni_parse_uint(val, &coalesce->tx_frames_high, 10);
		} else
		if (ni_string_eq(key, "sample_interval")) {
			ni_parse_uint(val, &coalesce->sample_interval, 10);
		} else {
			val = key;
			key = NULL;
			break;
		}

		key = NULL;
		val = NULL;
	}

	if (key) {
		if (val)
			fprintf(stderr, "%s: cannot parse coalesce '%s' argument '%s'\n",
					ref->name, key, val);
		else
			fprintf(stderr, "%s: missing coalesce '%s' value argument\n",
					ref->name, key);
	} else {
		if (val)
			fprintf(stderr, "%s: unknown coalesce setting name '%s'\n",
					ref->name, val);
		else
			ret = ni_ethtool_set_coalesce(ref, ethtool, coalesce);
	}
	ni_ethtool_coalesce_free(coalesce);
	return ret;
}

/*
 * pause
 */
static int
get_ethtool_pause(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_pause_t *pause;

	if (ni_ethtool_get_pause(ref, ethtool) < 0 || !(pause = ethtool->pause))
		return -1;

	printf("pause:\n");
	printf("\ttx: %s\n", pause->tx ? "on" : "off");
	printf("\trx: %s\n", pause->rx ? "on" : "off");
	printf("\tautoneg: %s\n", pause->autoneg ? "on" : "off");

	return 0;
}

static int
set_ethtool_pause(const ni_netdev_ref_t *ref, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_pause_t *pause;
	char *key = NULL, *val = NULL;
	ni_bool_t enabled;
	int ret = -1, n;

	if (!(pause = ni_ethtool_pause_new()))
		return ret;

	for (n = 0; n < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		if (n < args->argc)
			val = args->argv[n];
		else
			break;
		if (ni_string_eq(key, "tx")) {
			if (ni_parse_boolean(val, &enabled) != 0)
				break;
			ni_tristate_set(&pause->tx, enabled);
		} else
		if (ni_string_eq(key, "rx")) {
			if (ni_parse_boolean(val, &enabled) != 0)
				break;
			ni_tristate_set(&pause->rx, enabled);
		} else
		if (ni_string_eq(key, "autoneg")) {
			if (ni_parse_boolean(val, &enabled) != 0)
				break;
			ni_tristate_set(&pause->autoneg, enabled);
		} else {
			val = key;
			key = NULL;
			break;
		}

		key = NULL;
		val = NULL;
	}

	if (key) {
		if (val)
			fprintf(stderr, "%s: cannot parse pause '%s' argument '%s'\n",
					ref->name, key, val);
		else
			fprintf(stderr, "%s: missing pause '%s' value argument\n",
					ref->name, key);
	} else {
		if (val)
			fprintf(stderr, "%s: unknown pause setting name '%s'\n",
					ref->name, val);
		else
			ret = ni_ethtool_set_pause(ref, ethtool, pause);
	}
	ni_ethtool_pause_free(pause);
	return ret;
}


/*
 * option table
 */
static const struct ethtool_opt	ethtool_opts[] = {
	/* get */
	{	"--get-driver-info",	.func	= get_ethtool_driver_info,			},
	{	"--get-private-flags",	.func	= get_ethtool_priv_flags,			},
	{	"--get-priv-flags",	.func	= get_ethtool_priv_flags,	.alias = TRUE	},
	{	"--get-link-detected",	.func	= get_ethtool_link_detected,			},
	{	"--get-link-settings",	.func	= get_ethtool_link_settings,			},
	{	"--get-wake-on-lan",	.func	= get_ethtool_wake_on_lan,			},
	{	"--get-wol",		.func	= get_ethtool_wake_on_lan,	.alias = TRUE	},
	{	"--get-features",	.func	= get_ethtool_features,				},
	{	"--get-offload",	.func	= get_ethtool_features,		.alias = TRUE	},
	{	"--get-eee",		.func	= get_ethtool_eee,				},
	{	"--get-ring",		.func	= get_ethtool_ring,				},
	{	"--get-channels",	.func	= get_ethtool_channels,				},
	{	"--get-coalesce",	.func	= get_ethtool_coalesce,				},
	{	"--get-pause",	        .func	= get_ethtool_pause,		                },

	/* show == alias to get */
	{	"--show-driver-info",	.func	= get_ethtool_driver_info,	.alias = TRUE	},
	{	"--show-private-flags",	.func	= get_ethtool_priv_flags,	.alias = TRUE	},
	{	"--show-priv-flags",	.func	= get_ethtool_priv_flags,	.alias = TRUE	},
	{	"--show-link-settings",	.func	= get_ethtool_link_settings,	.alias = TRUE	},
	{	"--show-wake-on-lan",	.func	= get_ethtool_wake_on_lan,	.alias = TRUE	},
	{	"--show-wol",		.func	= get_ethtool_wake_on_lan,	.alias = TRUE	},
	{	"--show-features",	.func	= get_ethtool_features,		.alias = TRUE	},
	{	"--show-offload",	.func	= get_ethtool_features,		.alias = TRUE	},
	{	"--show-eee",		.func	= get_ethtool_eee,		.alias = TRUE	},
	{	"--show-ring",		.func	= get_ethtool_ring,		.alias = TRUE	},
	{	"--show-channels",	.func	= get_ethtool_channels,		.alias = TRUE	},
	{	"--show-coalesce",	.func	= get_ethtool_coalesce,		.alias = TRUE	},
	{	"--show-pause",	        .func	= get_ethtool_pause,		.alias = TRUE	},

	{	"",			.func	= NULL,		.usage = ""			},

	/* set */
	{	"--set-private-flags",	.func	= set_ethtool_priv_flags,
					.usage	= "<private-flag-name on|off> ..."		},
	{	"--set-priv-flags",	.func	= set_ethtool_priv_flags,	.alias = TRUE	},
	{	"--set-link-settings",	.func	= set_ethtool_link_settings,
					.usage	= "[setting-name on|off] ..."			},
	{	"--set-wake-on-lan",	.func	= set_ethtool_wake_on_lan,
					.usage	= "[options d|p,u,m,b,a,m,s] [sopass <hex-str>]"},
	{	"--set-wol",		.func	= set_ethtool_wake_on_lan,	.alias = TRUE	},
	{	"--set-features",	.func	= set_ethtool_features,
					.usage	= "[feature-name on|off] ..."			},
	{	"--set-offload",	.func	= set_ethtool_features,		.alias = TRUE	},
	{	"--set-eee",		.func	= set_ethtool_eee,
					.usage	= "[eee on|off] ..."				},
	{	"--set-ring",		.func	= set_ethtool_ring,
					.usage	= "[rx 1] ..."					},
	{	"--set-channels",	.func	= set_ethtool_channels,
					.usage	= "[rx 1] ..."					},
	{	"--set-coalesce",	.func	= set_ethtool_coalesce,
					.usage	= "[coalesce-name on|off|N] ..."		},
	{	"--set-pause",	        .func	= set_ethtool_pause,
					.usage	= "[pause-name on|off] ..."			},

	{	NULL										}
};

void
ethtool_opt_usage(const struct ethtool_opt *opt)
{
	if (opt->usage)
		fprintf(stderr, "  %-20s\t%s\n", opt->name, opt->usage);
	else if (!opt->alias)
		fprintf(stderr, "  %s\n", opt->name);
}

const struct ethtool_opt *
ethtool_opt_find(const struct ethtool_opt *opts, const char *name)
{
	const struct ethtool_opt *opt;

	for (opt = opts; opt && opt->name; opt++) {
		if (opt->func && ni_string_eq(opt->name, name))
			return opt;
	}
	return NULL;
}

static void
ethtool_args_set(struct ethtool_args *args, char **argn, int argc, char *argv[])
{
	args->argv = argv;
	args->argc = 0;
	while (args->argc < argc) {
		if (ni_string_startswith(argv[args->argc], "--"))
			break;
		args->argc++;
	}
	*argn = argv[args->argc];
	argv[args->argc] = NULL;
}

int
ni_do_ethtool(const char *caller, int argc, char **argv)
{
	enum { OPT_HELP };
	static struct option      options[] = {
		{ "help",         no_argument,       NULL, OPT_HELP        },

		{ NULL,           no_argument,       NULL, 0               }
	};
	int c, n, status = NI_WICKED_RC_USAGE;
	const struct ethtool_opt *opt;
	ni_netdev_ref_t ref = { 0, NULL };
	ni_ethtool_t *ethtool = NULL;

	optind = 1;
	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"wicked %s [global options ...] <ifname> <action options [arguments] > ...\n"
				"\n"
				"Supported global options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"\n"
				"Supported action options:\n"
				, argv[0]
			);
			for (opt = ethtool_opts; opt && opt->name; opt++)
				ethtool_opt_usage(opt);
			goto cleanup;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "%s: missing interface argument\n\n", argv[0]);
		goto usage;
	}
	if (optind + 1 >= argc) {
		fprintf(stderr, "%s: missing interface action option\n\n", argv[0]);
		goto usage;
	}

	status = NI_WICKED_RC_ERROR;
	ni_netdev_ref_init(&ref, argv[optind], if_nametoindex(argv[optind]));
	if (!ref.index) {
		fprintf(stderr, "%s: cannot find interface with name '%s'\n", argv[0], argv[optind]);
		goto cleanup;
	}
	if (!(ethtool = ni_ethtool_new())) {
		fprintf(stderr, "%s: cannot allocate ethtool parameters for '%s'\n", argv[0], ref.name);
		goto cleanup;
	}

	status = NI_WICKED_RC_SUCCESS;
	for (n = ++optind; n < argc; ) {
		if ((opt = ethtool_opt_find(ethtool_opts, argv[n]))) {
			struct ethtool_args args;
			char * argn;

			ethtool_args_set(&args, &argn, argc - n - 1, argv + n + 1);
			n += args.argc + 1;
			if (opt->func(&ref, ethtool, &args) < 0)
				status = NI_WICKED_RC_ERROR;
			argv[n] = argn;
		} else
		if (!ni_string_eq(argv[n], "--")) {
			fprintf(stderr, "%s: unknown interface action option '%s'\n\n",
					argv[0], argv[n]);
			status = NI_WICKED_RC_USAGE;
			goto cleanup;
		} else
			n++;
	}

cleanup:
	ni_ethtool_free(ethtool);
	ni_netdev_ref_destroy(&ref);
	return status;
}

