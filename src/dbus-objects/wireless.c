/*
 * dbus encapsulation for wireless interfaces
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wireless.h>
#include "dbus-common.h"
#include "model.h"

static ni_wireless_t *
__ni_objectmodel_get_wireless(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp;
	ni_wireless_t *wlan;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return NULL;

	if (!(wlan = ifp->wireless)) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting wireless handle for interface");
		return NULL;
	}
	return wlan;
}

static ni_wireless_scan_t *
__ni_objectmodel_get_scan(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return NULL;

	return ifp->wireless_scan;
}


/* Same as above, except returns a void pointer */
void *
ni_objectmodel_get_wireless(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_get_wireless(object, error);
}

static dbus_bool_t
__ni_objectmodel_wireless_get_network(const ni_wireless_network_t *network,
				ni_dbus_variant_t *dict,
				DBusError *error)
{
	unsigned int i;

	ni_dbus_dict_add_string(dict, "essid",
				ni_wireless_print_ssid(&network->essid));

	if (network->access_point.len)
		ni_dbus_dict_add_byte_array(dict, "access-point",
				network->access_point.data,
				network->access_point.len);

	ni_dbus_dict_add_uint32(dict, "mode", network->mode);
	if (network->channel)
		ni_dbus_dict_add_uint32(dict, "channel", network->channel);
	if (network->scan_info.frequency)
		ni_dbus_dict_add_double(dict, "frequency", network->scan_info.frequency);
	if (network->scan_info.max_bitrate)
		ni_dbus_dict_add_uint32(dict, "max-bitrate", network->scan_info.max_bitrate);

	for (i = 0; i < network->scan_info.supported_auth_modes.count; ++i) {
		ni_wireless_auth_info_t *auth_info = network->scan_info.supported_auth_modes.data[i];
		ni_dbus_variant_t *child;

		child = ni_dbus_dict_add(dict, "auth-info");
		ni_dbus_variant_init_dict(child);

		ni_dbus_dict_add_uint32(child, "mode", auth_info->mode);
		ni_dbus_dict_add_uint32(child, "version", auth_info->version);
		ni_dbus_dict_add_uint32(child, "group-cipher", auth_info->group_cipher);
		ni_dbus_dict_add_uint32(child, "pairwise-ciphers", auth_info->pairwise_ciphers);
		ni_dbus_dict_add_uint32(child, "key-management", auth_info->pairwise_ciphers);
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_wireless_get_scan(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_wireless_scan_t *scan;
	ni_dbus_variant_t *child;
	unsigned int i;

	if (!(scan = __ni_objectmodel_get_scan(object, error)))
		return TRUE;

	ni_dbus_dict_add_uint32(result, "timestamp", scan->timestamp);
	for (i = 0; i < scan->networks.count; ++i) {
		child = ni_dbus_dict_add(result, "network");
		ni_dbus_variant_init_dict(child);
		if (!__ni_objectmodel_wireless_get_network(scan->networks.data[i], child, error))
			return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_wireless_set_scan(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_wireless_t *wlan;

	if (!(wlan = __ni_objectmodel_get_wireless(object, error)))
		return FALSE;

	return TRUE;
}



#define WIRELESS_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(wireless, dbus_name, member_name, rw)
#define WIRELESS_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(wireless, dbus_name, member_name, rw)

const ni_dbus_property_t	ni_objectmodel_wireless_property_table[] = {
	WIRELESS_UINT_PROPERTY(eap-methods, capabilities.eap_methods, RO),
	WIRELESS_UINT_PROPERTY(pairwise-ciphers, capabilities.pairwise_ciphers, RO),
	WIRELESS_UINT_PROPERTY(group-ciphers, capabilities.group_ciphers, RO),
	WIRELESS_UINT_PROPERTY(key-management, capabilities.keymgmt_algos, RO),
	WIRELESS_UINT_PROPERTY(auth-methods, capabilities.auth_algos, RO),
	WIRELESS_UINT_PROPERTY(wpa-protocols, capabilities.wpa_protocols, RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			scan, __ni_objectmodel_wireless, RO),

	{ NULL }
};

