/*
 *	DBus encapsulation of the ethtool service
 *
 *	Copyright (C) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
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

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/ethtool.h>
#include <wicked/system.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include <net/if_arp.h>
#include <limits.h>
#include "dbus-common.h"
#include "model.h"
#include "debug.h"
#include "misc.h"


/*
 * Extract ethtool properties from a dbug dict argument.
 * We're re-using device properties from ni_objectmodel_ethtool_service,
 * which are derived from changeDevice method configuration properties.
 */
static ni_netdev_t *
ni_objectmodel_ethtool_request_arg(const ni_dbus_variant_t *argument)
{
	if (!ni_dbus_variant_is_dict(argument))
		return NULL;

	return ni_objectmodel_get_netif_argument(argument, NI_IFTYPE_UNKNOWN,
						&ni_objectmodel_ethtool_service);
}


/*
 * ethtool.changeDevice method
 */
static dbus_bool_t
ni_objectmodel_ethtool_setup(ni_dbus_object_t *object, const ni_dbus_method_t *method,
		unsigned int argc, const ni_dbus_variant_t *argv,
		ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev, *cfg;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (!(cfg = ni_objectmodel_ethtool_request_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		return FALSE;
	}

	if (ni_system_ethtool_setup(NULL, dev, cfg) < 0)  {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to apply ethtool settings");
		ni_netdev_put(cfg);
		return FALSE;
	}

	ni_netdev_put(cfg);
	return TRUE;
}


/*
 * retrieve an ethtool handle from dbus netif object
 */
static ni_ethtool_t *
ni_objectmodel_ethtool_handle(const ni_dbus_object_t *object,
		ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->ethtool;

	return ni_netdev_get_ethtool(dev);
}

static const ni_ethtool_t *
ni_objectmodel_ethtool_read_handle(const ni_dbus_object_t *object,
		DBusError *error)
{
	return ni_objectmodel_ethtool_handle(object, FALSE, error);
}

static ni_ethtool_t *
ni_objectmodel_ethtool_write_handle(const ni_dbus_object_t *object,
		DBusError *error)
{
	return ni_objectmodel_ethtool_handle(object, TRUE, error);
}


/*
 * get/set ethtool.driver-info properties
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_driver_info(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_driver_info_t *info;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!(info = ethtool->driver_info))
		return FALSE;

	if (info->driver)
		ni_dbus_dict_add_string(result, "driver", info->driver);
	if (info->version)
		ni_dbus_dict_add_string(result, "version", info->version);
	if (info->bus_info)
		ni_dbus_dict_add_string(result, "bus-info", info->bus_info);
	if (info->fw_version)
		ni_dbus_dict_add_string(result, "firmware-version", info->fw_version);
	if (info->erom_version)
		ni_dbus_dict_add_string(result, "expansion-rom-version", info->erom_version);

	if (info->supports.bitmap)
		ni_dbus_dict_add_uint32(result, "supports", info->supports.bitmap);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_driver_info(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_driver_info_t *info;
	ni_ethtool_t *ethtool;
	const char *str;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_driver_info_free(ethtool->driver_info);
	if (!(ethtool->driver_info = ni_ethtool_driver_info_new()))
		return FALSE;

	info = ethtool->driver_info;
	if (ni_dbus_dict_get_string(argument, "driver", &str))
		ni_string_dup(&info->driver, str);
	if (ni_dbus_dict_get_string(argument, "version", &str))
		ni_string_dup(&info->version, str);
	if (ni_dbus_dict_get_string(argument, "bus-info", &str))
		ni_string_dup(&info->bus_info, str);
	if (ni_dbus_dict_get_string(argument, "firmware-version", &str))
		ni_string_dup(&info->fw_version, str);
	if (ni_dbus_dict_get_string(argument, "expansion-rom-version", &str))
		ni_string_dup(&info->erom_version, str);

	ni_dbus_dict_get_uint32(argument, "supports", &info->supports.bitmap);

	return TRUE;
}


/*
 * get/set ethtool.priv-flags
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_priv_flags(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_priv_flags_t *priv;
	const ni_ethtool_t *ethtool;
	ni_dbus_variant_t *dict;
	const char *name;
	unsigned int i;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;
	if (!(priv = ethtool->priv_flags) || !priv->names.count || priv->names.count > 32)
		return FALSE;

	ni_dbus_dict_array_init(result);
	for (i = 0; i < priv->names.count; ++i) {
		name = priv->names.data[i];
		if (ni_string_empty(name))
			continue;

		if (!(dict = ni_dbus_dict_array_add(result)))
			continue;
		ni_dbus_dict_add_string(dict, "name", name);
		ni_dbus_dict_add_bool(dict, "enabled", !!(priv->bitmap & NI_BIT(i)));
	}
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_priv_flags(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	const ni_dbus_variant_t *dict;
	ni_ethtool_t *ethtool;
	unsigned int i, len;
	dbus_bool_t enabled;
	ni_stringbuf_t buf;
	const char *name;

	if (!ni_dbus_variant_is_dict_array(argument))
		return FALSE;
	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_priv_flags_free(ethtool->priv_flags);
	if (!(ethtool->priv_flags = ni_ethtool_priv_flags_new()))
		return FALSE;

	if ((len = argument->array.len) > 32)
		len = 32;

	ni_stringbuf_init(&buf);
	for (i = 0; i < argument->array.len; ++i) {
		dict = &argument->variant_array_value[i];
		if (!ni_dbus_variant_is_dict(dict))
			continue;

		if (!ni_dbus_dict_get_string(dict, "name", &name) ||
		    !ni_dbus_dict_get_bool(dict, "enabled", &enabled))
			continue;

		ni_stringbuf_put(&buf, name, ni_string_len(name));
		ni_stringbuf_trim_head(&buf, " \t\n");
		ni_stringbuf_trim_tail(&buf, " \t\n");
		if (ni_string_empty(buf.string))
			continue;

		if (ni_string_array_append(&ethtool->priv_flags->names, buf.string) == 0) {
			if (enabled)
				ethtool->priv_flags->bitmap |= NI_BIT(i);
		}
		ni_stringbuf_destroy(&buf);
	}
	return TRUE;
}

/*
 * get/set ethtool.link_settings
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_link_detected(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!ni_tristate_is_set(ethtool->link_detected))
		return FALSE;

	ni_dbus_variant_set_int32(result, ethtool->link_detected);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_link_detected(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	return ni_dbus_variant_get_int32(argument, &ethtool->link_detected);
}

/*
 * get/set ethtool.link_settings
 */
static const ni_ethtool_link_settings_t *
ni_objectmodel_ethtool_link_settings_read_handle(const ni_dbus_object_t *object,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return NULL;
	return ethtool->link_settings;
}

static ni_ethtool_link_settings_t *
ni_objectmodel_ethtool_link_settings_write_handle(const ni_dbus_object_t *object,
		DBusError *error)
{
	ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return NULL;

	ni_ethtool_link_settings_free(ethtool->link_settings);
	ethtool->link_settings = ni_ethtool_link_settings_new();
	return ethtool->link_settings;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_autoneg_into_dict(ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	if (ni_dbus_dict_add_bool(dict, "autoneg", ni_ethtool_link_adv_autoneg(bitfield))) {
		ni_ethtool_link_adv_set_autoneg(bitfield, FALSE);
		return TRUE;
	}
	return FALSE;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_bitfield_into_array(ni_string_array_t *array,
		ni_bitfield_t *bitfield, const char * (*bit_to_name)(unsigned int))
{
	/* we're using a temporary string array (instead
	 * of direct ni_dbus_variant_append_string_array)
	 * to omit empty dbus dict array entries... */
	unsigned int bit, bits;
	const char *name;

	bits = ni_bitfield_bits(bitfield);
	for (bit = 0; bit < bits; ++bit) {
		if (!ni_bitfield_testbit(bitfield, bit))
			continue;

		if (!(name = bit_to_name(bit)))
			continue;

		if (ni_string_array_append(array, name) == 0)
			ni_bitfield_clearbit(bitfield, bit);
	}
	return array->count > 0;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_pause_into_dict(ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	ni_string_array_t  tmp = NI_STRING_ARRAY_INIT;
	ni_dbus_variant_t *ent;

	if (!dict || !ni_bitfield_words(bitfield))
		return FALSE;

	if (!ni_objectmodel_ethtool_link_adv_bitfield_into_array(&tmp,
				bitfield, ni_ethtool_link_adv_pause_name))
		return FALSE;

	if (!(ent = ni_dbus_dict_add(dict, "pause-frames"))) {
		ni_string_array_destroy(&tmp);
		return FALSE;
	}

	ni_dbus_variant_set_string_array(ent, (const char **)tmp.data, tmp.count);
	ni_string_array_destroy(&tmp);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_ports_into_dict(ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	ni_string_array_t  tmp = NI_STRING_ARRAY_INIT;
	ni_dbus_variant_t *ent;

	if (!dict || !ni_bitfield_words(bitfield))
		return FALSE;

	if (!ni_objectmodel_ethtool_link_adv_bitfield_into_array(&tmp,
				bitfield, ni_ethtool_link_adv_port_name))
		return FALSE;

	if (!(ent = ni_dbus_dict_add(dict, "port-types"))) {
		ni_string_array_destroy(&tmp);
		return FALSE;
	}

	ni_dbus_variant_set_string_array(ent, (const char **)tmp.data, tmp.count);
	ni_string_array_destroy(&tmp);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_speed_into_dict(ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	ni_string_array_t  tmp = NI_STRING_ARRAY_INIT;
	ni_dbus_variant_t *ent;

	if (!dict || !ni_bitfield_words(bitfield))
		return FALSE;

	if (!ni_objectmodel_ethtool_link_adv_bitfield_into_array(&tmp,
				bitfield, ni_ethtool_link_adv_speed_name))
		return FALSE;

	if (!(ent = ni_dbus_dict_add(dict, "speed-modes"))) {
		ni_string_array_destroy(&tmp);
		return FALSE;
	}

	ni_dbus_variant_set_string_array(ent, (const char **)tmp.data, tmp.count);
	ni_string_array_destroy(&tmp);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_fec_modes_into_dict(ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	ni_string_array_t  tmp = NI_STRING_ARRAY_INIT;
	ni_dbus_variant_t *ent;

	if (!dict || !ni_bitfield_words(bitfield))
		return FALSE;

	if (!ni_objectmodel_ethtool_link_adv_bitfield_into_array(&tmp,
				bitfield, ni_ethtool_link_adv_fec_name))
		return FALSE;

	if (!(ent = ni_dbus_dict_add(dict, "fec-modes"))) {
		ni_string_array_destroy(&tmp);
		return FALSE;
	}

	ni_dbus_variant_set_string_array(ent, (const char **)tmp.data, tmp.count);
	ni_string_array_destroy(&tmp);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_unknown_into_dict(ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	char *hexstr = NULL;
	unsigned int words;

	words = ni_bitfield_words(bitfield);
	while (words) {
		if (!bitfield->field[words - 1])
			words--;
		else
			break;
	}
	if (!dict || !words)
		return FALSE;

	if (!ni_bitfield_format(bitfield, &hexstr, TRUE) || !hexstr)
		return FALSE;

	if (!ni_dbus_dict_add_string(dict, "unknown", hexstr)) {
		ni_string_free(&hexstr);
		return FALSE;
	}

	ni_string_free(&hexstr);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_into_dict(ni_dbus_variant_t *dict,
		const char *name, const ni_bitfield_t *bitfield)
{
	ni_bitfield_t tmpfield = NI_BITFIELD_INIT;
	ni_dbus_variant_t *child;

	if (!dict || ni_string_empty(name) || !ni_bitfield_bits(bitfield))
		return FALSE;

	if (!(child = ni_dbus_dict_add(dict, name)))
		return FALSE;

	ni_dbus_variant_init_dict(child);
	ni_bitfield_set_data(&tmpfield, ni_bitfield_get_data(bitfield), ni_bitfield_bytes(bitfield));
	ni_objectmodel_ethtool_link_adv_autoneg_into_dict(child, &tmpfield);
	ni_objectmodel_ethtool_link_adv_ports_into_dict(child, &tmpfield);
	ni_objectmodel_ethtool_link_adv_speed_into_dict(child, &tmpfield);
	ni_objectmodel_ethtool_link_adv_pause_into_dict(child, &tmpfield);
	ni_objectmodel_ethtool_link_adv_fec_modes_into_dict(child, &tmpfield);
	ni_objectmodel_ethtool_link_adv_unknown_into_dict(child, &tmpfield);
	ni_bitfield_destroy(&tmpfield);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_autoneg_from_dict(const ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	dbus_bool_t bvalue;

	if (ni_dbus_dict_get_bool(dict, "autoneg", &bvalue)) {
		ni_ethtool_link_adv_set_autoneg(bitfield, bvalue);
		return TRUE;
	}
	return FALSE;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_bitfield_from_array(const ni_dbus_variant_t *array,
		ni_bitfield_t *bitfield, ni_bool_t (*name_to_bit)(const char *, unsigned int *))
{
	const char *value;
	unsigned int bit;
	size_t len, pos;

	if (!ni_dbus_variant_is_string_array(array))
		return FALSE;

	if ((len = array->array.len) > ni_ethtool_link_mode_nbits())
		len = ni_ethtool_link_mode_nbits();

	for (pos = 0; pos < len; ++pos) {
		value = array->string_array_value[pos];
		if (name_to_bit(value, &bit))
			ni_bitfield_setbit(bitfield, bit);
		else
			ni_bitfield_parse(bitfield, value, 0);
	}
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_pause_from_dict(const ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	const ni_dbus_variant_t *array;

	if (!(array = ni_dbus_dict_get(dict, "pause-frames")))
		return FALSE;

	return ni_objectmodel_ethtool_link_adv_bitfield_from_array(array,
			bitfield, ni_ethtool_link_adv_pause_type);
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_ports_from_dict(const ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	const ni_dbus_variant_t *array;

	if (!(array = ni_dbus_dict_get(dict, "port-types")))
		return FALSE;

	return ni_objectmodel_ethtool_link_adv_bitfield_from_array(array,
			bitfield, ni_ethtool_link_adv_port_type);
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_speed_from_dict(const ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	const ni_dbus_variant_t *array;

	if (!(array = ni_dbus_dict_get(dict, "speed-modes")))
		return FALSE;

	return ni_objectmodel_ethtool_link_adv_bitfield_from_array(array,
			bitfield, ni_ethtool_link_adv_speed_type);
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_fec_modes_from_dict(const ni_dbus_variant_t *dict,
		ni_bitfield_t *bitfield)
{
	const ni_dbus_variant_t *array;

	if (!(array = ni_dbus_dict_get(dict, "fec-modes")))
		return FALSE;

	return ni_objectmodel_ethtool_link_adv_bitfield_from_array(array,
			bitfield, ni_ethtool_link_adv_fec_type);
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_unknown_from_dict(const ni_dbus_variant_t *dict,
		 ni_bitfield_t *bitfield)
{
	const char *hexstr = NULL;

	if (!ni_dbus_dict_get_string(dict, "unknown", &hexstr))
		return FALSE;

	return ni_bitfield_parse(bitfield, hexstr, 0);
}

static dbus_bool_t
ni_objectmodel_ethtool_link_adv_from_dict(const ni_dbus_variant_t *dict,
		const char *name, ni_bitfield_t *bitfield)
{
	const ni_dbus_variant_t *child;

	if (!dict || !ni_string_empty(name) || !bitfield)
		return FALSE;

	if (!(child = ni_dbus_dict_get(dict, name)))
		return TRUE;

	ni_objectmodel_ethtool_link_adv_autoneg_from_dict(child, bitfield);
	ni_objectmodel_ethtool_link_adv_ports_from_dict(child, bitfield);
	ni_objectmodel_ethtool_link_adv_speed_from_dict(child, bitfield);
	ni_objectmodel_ethtool_link_adv_pause_from_dict(child, bitfield);
	ni_objectmodel_ethtool_link_adv_fec_modes_from_dict(child, bitfield);
	ni_objectmodel_ethtool_link_adv_unknown_from_dict(child, bitfield);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_get_link_settings(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_link_settings_t *link;

	if (!(link = ni_objectmodel_ethtool_link_settings_read_handle(object, error)))
		return FALSE;

	ni_dbus_variant_init_dict(result);
	if (ni_tristate_is_set(link->autoneg))
		ni_dbus_dict_add_int32(result, "autoneg", link->autoneg);
	if (link->speed != NI_ETHTOOL_SPEED_UNKNOWN)
		ni_dbus_dict_add_uint32(result, "speed",  link->speed);
	if (link->duplex != NI_ETHTOOL_DUPLEX_UNKNOWN)
		ni_dbus_dict_add_uint32(result, "duplex", link->duplex);
	if (link->port != NI_ETHTOOL_PORT_DEFAULT)
		ni_dbus_dict_add_uint32(result, "port",   link->port);

	if (link->port == NI_ETHTOOL_PORT_TP && link->tp_mdix)
		ni_dbus_dict_add_uint32(result, "mdix", link->tp_mdix);
	if (link->mdio_support != NI_ETHTOOL_MDI_INVALID)
		ni_dbus_dict_add_uint32(result, "mdio", link->mdio_support);
	if (link->phy_address != NI_ETHTOOL_PHYAD_UNKNOWN)
		ni_dbus_dict_add_uint32(result, "phy-address",  link->phy_address);
	if (link->transceiver != NI_ETHTOOL_XCVR_UNKNOWN)
		ni_dbus_dict_add_uint32(result, "transceiver",  link->transceiver);

	ni_objectmodel_ethtool_link_adv_into_dict(result, "supported", &link->supported);
	ni_objectmodel_ethtool_link_adv_into_dict(result, "advertising", &link->advertising);
	ni_objectmodel_ethtool_link_adv_into_dict(result, "lp-advertising", &link->lp_advertising);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_link_settings(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_link_settings_t *link;
	const ni_dbus_variant_t *adv;
	uint32_t uv32;
	int32_t sv32;

	if (!(link = ni_objectmodel_ethtool_link_settings_write_handle(object, error)))
		return FALSE;

	if (ni_dbus_dict_get_int32(argument, "autoneg", &sv32) && ni_tristate_is_set(sv32))
		ni_tristate_set(&link->autoneg, sv32);
	if (ni_dbus_dict_get_uint32(argument, "speed",  &uv32) && uv32 <= INT_MAX)
		link->speed  = uv32;
	if (ni_dbus_dict_get_uint32(argument, "duplex", &uv32) && uv32 < NI_ETHTOOL_DUPLEX_UNKNOWN)
		link->duplex = uv32;
	if (ni_dbus_dict_get_uint32(argument, "port",   &uv32) && uv32 <= NI_ETHTOOL_PORT_OTHER)
		link->port   = uv32;

	if (ni_dbus_dict_get_uint32(argument, "mdix", &uv32))
		link->tp_mdix  = uv32;
	if (ni_dbus_dict_get_uint32(argument, "mdio", &uv32))
		link->mdio_support = uv32;
	if (ni_dbus_dict_get_uint32(argument, "phy-address", &uv32))
		link->phy_address  = uv32;
	if (ni_dbus_dict_get_uint32(argument, "transceiver", &uv32))
		link->transceiver  = uv32;

	if ((adv = ni_dbus_dict_get(argument, "advertise"))) {
		/* config */
		ni_objectmodel_ethtool_link_adv_bitfield_from_array(adv,
				&link->advertising, ni_ethtool_link_adv_type);
	} else {
		/* states */
		ni_objectmodel_ethtool_link_adv_from_dict(argument, "supported", &link->supported);
		ni_objectmodel_ethtool_link_adv_from_dict(argument, "advertising", &link->advertising);
		ni_objectmodel_ethtool_link_adv_from_dict(argument, "lp-advertising", &link->lp_advertising);
	}

	return TRUE;
}

/*
 * get/set ethtool.wake-on-lan
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_wake_on_lan(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_wake_on_lan_t *wol;
	const ni_ethtool_t *ethtool;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!(wol = ethtool->wake_on_lan))
		return FALSE;

	if (wol->support == NI_ETHTOOL_WOL_DEFAULT ||
	    wol->support == NI_ETHTOOL_WOL_DISABLE)
		return FALSE;

	ni_dbus_variant_init_dict(result);
	ni_dbus_dict_add_uint32(result, "support", wol->support);
	if (wol->options != NI_ETHTOOL_WOL_DEFAULT)
		ni_dbus_dict_add_uint32(result, "options", wol->options);

	/* from config it is VOID, hide sopass from kernel with type ETHER */
	if (wol->sopass.len && wol->sopass.type == ARPHRD_VOID &&
	    wol->sopass.len == ni_link_address_length(ARPHRD_ETHER))
		__ni_objectmodel_dict_add_hwaddr(result, "sopass", &wol->sopass);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_wake_on_lan(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_wake_on_lan_t *wol;
	ni_ethtool_t *ethtool;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_wake_on_lan_free(ethtool->wake_on_lan);
	if (!(ethtool->wake_on_lan = ni_ethtool_wake_on_lan_new()))
		return FALSE;
	wol = ethtool->wake_on_lan;

	ni_dbus_dict_get_uint32(argument, "support", &wol->support);
	ni_dbus_dict_get_uint32(argument, "options", &wol->options);
	__ni_objectmodel_dict_get_hwaddr(argument, "sopass", &wol->sopass);

	return TRUE;
}

/*
 * get/set ethtool.features (offloads)
 */
static dbus_bool_t
ni_objectmodel_ethtool_feature_into_dict(ni_dbus_variant_t *dict,
				const ni_ethtool_feature_t *feature)
{
	if (!dict || !feature || ni_string_empty(feature->map.name))
		return FALSE;

	ni_dbus_dict_add_string(dict, "name", feature->map.name);
	ni_dbus_dict_add_bool(dict, "enabled", !!(feature->value & NI_ETHTOOL_FEATURE_ON));
	if (feature->value & NI_ETHTOOL_FEATURE_FIXED)
		ni_dbus_dict_add_bool(dict, "fixed", TRUE);
	else
	if (feature->value & NI_ETHTOOL_FEATURE_REQUESTED)
		ni_dbus_dict_add_bool(dict, "requested", TRUE);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_get_features(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_feature_t *feature;
	const ni_ethtool_t *ethtool;
	ni_dbus_variant_t *dict;
	unsigned int i;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!ethtool->features || !ethtool->features->count)
		return FALSE;

	ni_dbus_dict_array_init(result);
	for (i = 0; i < ethtool->features->count; ++i) {
		if (!(feature = ethtool->features->data[i]))
			continue;

		if (!(dict = ni_dbus_dict_array_add(result)))
			continue;

		ni_objectmodel_ethtool_feature_into_dict(dict, feature);
	}
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_feature_from_dict(const ni_dbus_variant_t *dict,
					ni_ethtool_features_t *features)
{
	ni_ethtool_feature_value_t value;
	dbus_bool_t enabled;
	const char *name;

	if (!ni_dbus_dict_get_string(dict, "name", &name))
		return FALSE;

	if (!ni_dbus_dict_get_bool(dict, "enabled", &enabled))
		return FALSE;

	value = enabled ? NI_ETHTOOL_FEATURE_ON : NI_ETHTOOL_FEATURE_OFF;
	if (ni_dbus_dict_get_bool(dict, "fixed", &enabled) && enabled)
		value |= NI_ETHTOOL_FEATURE_FIXED;
	else
	if (ni_dbus_dict_get_bool(dict, "requested", &enabled) && enabled)
		value |= NI_ETHTOOL_FEATURE_REQUESTED;

	return !!ni_ethtool_features_set(features, name, value);
}

static dbus_bool_t
ni_objectmodel_ethtool_set_features(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	const ni_dbus_variant_t *dict;
	ni_ethtool_t *ethtool;
	unsigned int i;

	if (!argument || !ni_dbus_variant_is_dict_array(argument))
		return FALSE;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_features_free(ethtool->features);
	if (!(ethtool->features = ni_ethtool_features_new()))
		return FALSE;

	for (i = 0; i < argument->array.len; ++i) {
		dict = &argument->variant_array_value[i];
		if (!ni_dbus_variant_is_dict(dict))
			continue;

		ni_objectmodel_ethtool_feature_from_dict(dict, ethtool->features);
	}
	return TRUE;
}

/*
 * get/set ethtool.eee
 */
static dbus_bool_t
ni_objectmodel_ethtool_eee_adv_into_dict(ni_dbus_variant_t *dict,
		const char *entry, const ni_bitfield_t *bitfield)
{
	ni_bitfield_t tmpfield = NI_BITFIELD_INIT;
	ni_dbus_variant_t *array;
	unsigned int bit, bits;
	char *hexstr = NULL;
	const char *name;

	if (!dict || !ni_bitfield_isset(bitfield))
		return FALSE;

	if (!(array = ni_dbus_dict_add(dict, entry)))
		return FALSE;

	ni_dbus_variant_init_string_array(array);

	/* known modes by name */
	bits = ni_bitfield_bits(bitfield);
	for (bit = 0; bit < bits; ++bit) {
		if (!ni_bitfield_testbit(bitfield, bit))
			continue;

		if (!(name = ni_ethtool_link_adv_speed_name(bit)))
			ni_bitfield_setbit(&tmpfield, bit);
		else
		if (!ni_dbus_variant_append_string_array(array, name))
			ni_bitfield_setbit(&tmpfield, bit);
	}

	/* unknown modes as hex */
	if (ni_bitfield_isset(&tmpfield)) {
		if (ni_bitfield_format(&tmpfield, &hexstr, TRUE) && hexstr)
			ni_dbus_variant_append_string_array(array, hexstr);
		ni_string_free(&hexstr);
	}

	ni_bitfield_destroy(&tmpfield);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_eee_adv_from_dict(const ni_dbus_variant_t *dict,
		const char *entry, ni_bitfield_t *bitfield)
{
	const ni_dbus_variant_t *array;

	if (!(array = ni_dbus_dict_get(dict, entry)))
		return FALSE;

	return ni_objectmodel_ethtool_link_adv_bitfield_from_array(array,
			bitfield, ni_ethtool_link_adv_speed_type);
}

static dbus_bool_t
ni_objectmodel_ethtool_get_eee(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{

	const ni_ethtool_t *ethtool;
	const ni_ethtool_eee_t *eee;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!(eee = ethtool->eee))
		return FALSE;

	if (eee->status.enabled != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "enabled", eee->status.enabled);
	if (eee->status.active != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "active", eee->status.active);

	ni_objectmodel_ethtool_eee_adv_into_dict(result, "supported", &eee->speed.supported);
	ni_objectmodel_ethtool_eee_adv_into_dict(result, "advertising", &eee->speed.advertising);
	ni_objectmodel_ethtool_eee_adv_into_dict(result, "lp-advertising", &eee->speed.lp_advertising);

	if (eee->tx_lpi.enabled != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "tx-lpi", eee->tx_lpi.enabled);
	if (eee->tx_lpi.timer != NI_ETHTOOL_EEE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-timer", eee->tx_lpi.timer);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_eee(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	const ni_dbus_variant_t *adv;
	ni_ethtool_t *ethtool;
	ni_ethtool_eee_t *eee;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_eee_free(ethtool->eee);
	if (!(ethtool->eee = ni_ethtool_eee_new()))
		return FALSE;
	eee = ethtool->eee;

	ni_dbus_dict_get_int32(argument, "enabled", &eee->status.enabled);
	ni_dbus_dict_get_int32(argument, "active",  &eee->status.active);

	ni_dbus_dict_get_int32(argument, "tx-lpi", &eee->tx_lpi.enabled);
	ni_dbus_dict_get_uint32(argument, "tx-timer", &eee->tx_lpi.timer);

	if ((adv = ni_dbus_dict_get(argument, "advertise"))) {
		/* config */
		ni_objectmodel_ethtool_link_adv_bitfield_from_array(adv,
				&eee->speed.advertising, ni_ethtool_link_adv_speed_type);
	} else {
		/* states */
		ni_objectmodel_ethtool_eee_adv_from_dict(argument, "supported", &eee->speed.supported);
		ni_objectmodel_ethtool_eee_adv_from_dict(argument, "advertising", &eee->speed.advertising);
		ni_objectmodel_ethtool_eee_adv_from_dict(argument, "lp-advertising", &eee->speed.lp_advertising);
	}

	return TRUE;
}

/*
 * get/set ethtool.ring
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_ring(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_ring_t *ring;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!(ring = ethtool->ring))
		return FALSE;

	if (ring->tx != NI_ETHTOOL_RING_DEFAULT)
		ni_dbus_dict_add_int32(result, "tx", ring->tx);

	if (ring->rx != NI_ETHTOOL_RING_DEFAULT)
		ni_dbus_dict_add_int32(result, "rx", ring->rx);

	if (ring->rx_mini != NI_ETHTOOL_RING_DEFAULT)
		ni_dbus_dict_add_int32(result, "rx-mini", ring->rx_mini);

	if (ring->rx_jumbo != NI_ETHTOOL_RING_DEFAULT)
		ni_dbus_dict_add_int32(result, "rx-jumbo", ring->rx_jumbo);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_ring(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;
	ni_ethtool_ring_t *ring;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_ring_free(ethtool->ring);
	if (!(ethtool->ring = ni_ethtool_ring_new()))
		return FALSE;
	ring = ethtool->ring;

	ni_dbus_dict_get_uint32(argument, "tx", &ring->tx);
	ni_dbus_dict_get_uint32(argument, "rx", &ring->rx);
	ni_dbus_dict_get_uint32(argument, "rx-mini", &ring->rx_mini);
	ni_dbus_dict_get_uint32(argument, "rx-jumbo", &ring->rx_jumbo);

	return TRUE;
}


/*
 * get/set ethtool.channels
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_channels(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_channels_t *channels;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!(channels = ethtool->channels))
		return FALSE;

	if (channels->tx != NI_ETHTOOL_CHANNELS_DEFAULT)
		ni_dbus_dict_add_int32(result, "tx", channels->tx);

	if (channels->rx != NI_ETHTOOL_CHANNELS_DEFAULT)
		ni_dbus_dict_add_int32(result, "rx", channels->rx);

	if (channels->other != NI_ETHTOOL_CHANNELS_DEFAULT)
		ni_dbus_dict_add_int32(result, "other", channels->other);

	if (channels->combined != NI_ETHTOOL_CHANNELS_DEFAULT)
		ni_dbus_dict_add_int32(result, "combined", channels->combined);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_channels(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;
	ni_ethtool_channels_t *channels;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_channels_free(ethtool->channels);
	if (!(ethtool->channels = ni_ethtool_channels_new()))
		return FALSE;
	channels = ethtool->channels;

	ni_dbus_dict_get_uint32(argument, "tx", &channels->tx);
	ni_dbus_dict_get_uint32(argument, "rx", &channels->rx);
	ni_dbus_dict_get_uint32(argument, "other", &channels->other);
	ni_dbus_dict_get_uint32(argument, "combined", &channels->combined);

	return TRUE;
}


/*
 * get/set ethtool.coalesce
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_coalesce(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_coalesce_t *coalesce;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!(coalesce = ethtool->coalesce))
		return FALSE;

	if (coalesce->adaptive_tx != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "adaptive-tx", coalesce->adaptive_tx);

	if (coalesce->adaptive_rx != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "adaptive-rx", coalesce->adaptive_rx);


	if (coalesce->pkt_rate_low != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "pkt-rate-low", coalesce->pkt_rate_low);

	if (coalesce->pkt_rate_high != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "pkt-rate-high", coalesce->pkt_rate_high);


	if (coalesce->sample_interval != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "sample-interval", coalesce->sample_interval);

	if (coalesce->stats_block_usecs != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "stats-block-usecs", coalesce->stats_block_usecs);


	if (coalesce->tx_usecs != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-usecs", coalesce->tx_usecs);

	if (coalesce->tx_usecs_irq != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-usecs-irq", coalesce->tx_usecs_irq);

	if (coalesce->tx_usecs_low != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-usecs-low", coalesce->tx_usecs_low);

	if (coalesce->tx_usecs_high != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-usecs-high", coalesce->tx_usecs_high);


	if (coalesce->tx_frames != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-frames", coalesce->tx_frames);

	if (coalesce->tx_frames_irq != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-frames-irq", coalesce->tx_frames_irq);

	if (coalesce->tx_frames_low != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-frames-low", coalesce->tx_frames_low);

	if (coalesce->tx_frames_high != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "tx-frames-high", coalesce->tx_frames_high);


	if (coalesce->rx_usecs != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "rx-usecs", coalesce->rx_usecs);

	if (coalesce->rx_usecs_irq != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "rx-usecs-irq", coalesce->rx_usecs_irq);

	if (coalesce->rx_usecs_low != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "rx-usecs-low", coalesce->rx_usecs_low);

	if (coalesce->rx_usecs_high != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "rx-usecs-high", coalesce->rx_usecs_high);


	if (coalesce->rx_frames != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "rx-frames", coalesce->rx_frames);

	if (coalesce->rx_frames_irq != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "rx-frames-irq", coalesce->rx_frames_irq);

	if (coalesce->rx_frames_low != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "rx-frames-low", coalesce->rx_frames_low);

	if (coalesce->rx_frames_high != NI_ETHTOOL_COALESCE_DEFAULT)
		ni_dbus_dict_add_uint32(result, "rx-frames-high", coalesce->rx_frames_high);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_coalesce(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;
	ni_ethtool_coalesce_t *coalesce;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_coalesce_free(ethtool->coalesce);
	if (!(ethtool->coalesce = ni_ethtool_coalesce_new()))
		return FALSE;
	coalesce = ethtool->coalesce;

	ni_dbus_dict_get_int32(argument, "adaptive-tx", &coalesce->adaptive_tx);
	ni_dbus_dict_get_int32(argument, "adaptive-rx", &coalesce->adaptive_rx);

	ni_dbus_dict_get_uint32(argument, "pkt-rate-low", &coalesce->pkt_rate_low);
	ni_dbus_dict_get_uint32(argument, "pkt-rate-high", &coalesce->pkt_rate_high);

	ni_dbus_dict_get_uint32(argument, "sample-interval", &coalesce->sample_interval);
	ni_dbus_dict_get_uint32(argument, "stats-block-usecs", &coalesce->stats_block_usecs);

	ni_dbus_dict_get_uint32(argument, "tx-usecs", &coalesce->tx_usecs);
	ni_dbus_dict_get_uint32(argument, "tx-usecs-irq", &coalesce->tx_usecs_irq);
	ni_dbus_dict_get_uint32(argument, "tx-usecs-low", &coalesce->tx_usecs_low);
	ni_dbus_dict_get_uint32(argument, "tx-usecs-high", &coalesce->tx_usecs_high);

	ni_dbus_dict_get_uint32(argument, "tx-frames", &coalesce->tx_frames);
	ni_dbus_dict_get_uint32(argument, "tx-frames-irq", &coalesce->tx_frames_irq);
	ni_dbus_dict_get_uint32(argument, "tx-frames-low", &coalesce->tx_frames_low);
	ni_dbus_dict_get_uint32(argument, "tx-frames-high", &coalesce->tx_frames_high);

	ni_dbus_dict_get_uint32(argument, "rx-usecs", &coalesce->rx_usecs);
	ni_dbus_dict_get_uint32(argument, "rx-usecs-irq", &coalesce->rx_usecs_irq);
	ni_dbus_dict_get_uint32(argument, "rx-usecs-low", &coalesce->rx_usecs_low);
	ni_dbus_dict_get_uint32(argument, "rx-usecs-high", &coalesce->rx_usecs_high);

	ni_dbus_dict_get_uint32(argument, "rx-frames", &coalesce->rx_frames);
	ni_dbus_dict_get_uint32(argument, "rx-frames-irq", &coalesce->rx_frames_irq);
	ni_dbus_dict_get_uint32(argument, "rx-frames-low", &coalesce->rx_frames_low);
	ni_dbus_dict_get_uint32(argument, "rx-frames-high", &coalesce->rx_frames_high);

	return TRUE;
}

/*
 * get/set ethtool.pause
 */
static dbus_bool_t
ni_objectmodel_ethtool_get_pause(const ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		ni_dbus_variant_t *result,
		DBusError *error)
{
	const ni_ethtool_t *ethtool;
	const ni_ethtool_pause_t *pause;

	if (!(ethtool = ni_objectmodel_ethtool_read_handle(object, error)))
		return FALSE;

	if (!(pause = ethtool->pause))
		return FALSE;

	if (pause->tx != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "tx", pause->tx);

	if (pause->rx != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "rx", pause->rx);

	if (pause->autoneg != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "autoneg", pause->autoneg);

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_ethtool_set_pause(ni_dbus_object_t *object,
		const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument,
		DBusError *error)
{
	ni_ethtool_t *ethtool;
	ni_ethtool_pause_t *pause;

	if (!(ethtool = ni_objectmodel_ethtool_write_handle(object, error)))
		return FALSE;

	ni_ethtool_pause_free(ethtool->pause);
	if (!(ethtool->pause = ni_ethtool_pause_new()))
		return FALSE;
	pause = ethtool->pause;

	ni_dbus_dict_get_int32(argument, "tx", &pause->tx);
	ni_dbus_dict_get_int32(argument, "rx", &pause->rx);
	ni_dbus_dict_get_int32(argument, "autoneg", &pause->autoneg);

	return TRUE;
}



/*
 * ethtool service properties
 */
#define ETHTOOL_DICT_PROPERTY(dbus_name, fstem_name, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, dbus_name, \
			fstem_name, ni_objectmodel_ethtool, rw)
#define ETHTOOL_DICTS_PROPERTY(dbus_name, fstem_name, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_ARRAY_SIGNATURE, dbus_name, \
			fstem_name, ni_objectmodel_ethtool, rw)
#define	ETHTOOL_UINT_PROPERTY(dbus_name, fstem_name, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_UINT32_AS_STRING, dbus_name, \
			fstem_name, ni_objectmodel_ethtool, rw)

static const ni_dbus_property_t		ni_objectmodel_ethtool_properties[] = {
	/* read-only (show-xml) info    */
	ETHTOOL_DICT_PROPERTY	(driver-info,	driver_info,		RO),
	ETHTOOL_UINT_PROPERTY	(link-detected,	link_detected,		RO),

	/* also setup config properties */
	ETHTOOL_DICT_PROPERTY	(link-settings,	link_settings,		RO),
	ETHTOOL_DICTS_PROPERTY  (private-flags,	priv_flags,		RO),
	ETHTOOL_DICT_PROPERTY	(wake-on-lan,	wake_on_lan,		RO),
	ETHTOOL_DICTS_PROPERTY	(features,	features,		RO),
	ETHTOOL_DICT_PROPERTY	(eee,		eee,			RO),
	ETHTOOL_DICT_PROPERTY	(ring,		ring,			RO),
	ETHTOOL_DICT_PROPERTY	(channels,	channels,		RO),
	ETHTOOL_DICT_PROPERTY	(coalesce,	coalesce,		RO),
	ETHTOOL_DICT_PROPERTY	(pause,	        pause,   		RO),

	{ NULL }
};

/*
 * ethtool service methods
 */
static const ni_dbus_method_t		ni_objectmodel_ethtool_methods[] = {
	{ "changeDevice",		"a{sv}",	.handler = ni_objectmodel_ethtool_setup },
	{ NULL }
};

/*
 * ethtool service definitions
 */
ni_dbus_service_t			ni_objectmodel_ethtool_service = {
	.name				= NI_OBJECTMODEL_ETHTOOL_INTERFACE,
	.methods			= ni_objectmodel_ethtool_methods,
	.properties			= ni_objectmodel_ethtool_properties,
};

