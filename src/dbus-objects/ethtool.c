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
#include "dbus-common.h"
#include "model.h"
#include "debug.h"


/*
 * Extract ethtool properties from a dbug dict argument.
 * We're re-using device properties from ni_objectmodel_ethtool_service,
 * which are derived from changeDevice method configuration propeties.
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
 * ethtool service properties
 */
#define ETHTOOL_DICT_PROPERTY(dbus_name, fstem_name, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, dbus_name, \
			fstem_name, ni_objectmodel_ethtool, rw)
#define ETHTOOL_DICTS_PROPERTY(dbus_name, fstem_name, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_ARRAY_SIGNATURE, dbus_name, \
			fstem_name, ni_objectmodel_ethtool, rw)

static const ni_dbus_property_t		ni_objectmodel_ethtool_properties[] = {
	/* read-only (show-xml) info    */
	ETHTOOL_DICT_PROPERTY	(driver-info,	driver_info,		RO),
	ETHTOOL_DICTS_PROPERTY  (private-flags,	priv_flags,		RO),

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

