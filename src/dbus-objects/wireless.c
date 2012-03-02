/*
 * dbus encapsulation for wireless interfaces
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wireless.h>
#include <wicked/dbus-errors.h>
#include "dbus-common.h"
#include "model.h"

static dbus_bool_t	ni_objectmodel_get_wireless_request(ni_wireless_network_t *,
				const ni_dbus_variant_t *, DBusError *);

static dbus_bool_t
ni_objectmodel_wireless_set_scanning(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	dbus_bool_t enable;

	if (argc != 1 || !ni_dbus_variant_get_bool(argv, &enable)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: expected one boolean argument",
				object->path, method->name);
		return FALSE;
	}

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (ni_wireless_interface_set_scanning(dev, enable) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"%s: unable to %s scanning mode",
				dev->name,
				enable? "enable" : "disable");
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wireless_device_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *ifp;
	ni_wireless_network_t *net;
	dbus_bool_t rv = FALSE;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	net = ni_wireless_network_new();
	if (!ni_objectmodel_get_wireless_request(net, &argv[0], error))
		goto error;

	if (net->essid.len != 0) {
		dbus_bool_t was_up = FALSE;

		was_up = (ifp->wireless->assoc.state == NI_WIRELESS_ESTABLISHED);

		if (net->keymgmt_proto == NI_WIRELESS_KEY_MGMT_PSK
		 && net->wpa_psk.key.len == 0
		 && net->wpa_psk.passphrase == NULL) {
			dbus_set_error(error, NI_DBUS_ERROR_AUTH_INFO_MISSING,
					"wpa-psk.passphrase|PASSWORD|%.*s",
					net->essid.len, net->essid.data);
			goto error;
		}

		/* We're asked to associate with the given network */
		if (ni_wireless_set_network(ifp, net) < 0) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"could not associate");
			goto error;
		}

		if (!was_up || ifp->wireless->assoc.state == NI_WIRELESS_ESTABLISHED) {
			rv = TRUE;
		} else {
			/* Link is not associated yet. Tell the caller to wait for an event. */
			if (ni_uuid_is_null(&ifp->link.event_uuid))
				ni_uuid_generate(&ifp->link.event_uuid);
			rv =  __ni_objectmodel_return_callback_info(reply, NI_EVENT_LINK_ASSOCIATED,
					&ifp->link.event_uuid, error);
		}
	} else {
		/* We're asked to disconnect */
		if (ni_wireless_disconnect(ifp) < 0) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"could not disconnect from wireless network");
			goto error;
		}

		if (ifp->wireless->assoc.state == NI_WIRELESS_NOT_ASSOCIATED) {
			rv = TRUE;
		} else {
			/* Link is not associated yet. Tell the caller to wait for an event. */
			if (ni_uuid_is_null(&ifp->link.event_uuid))
				ni_uuid_generate(&ifp->link.event_uuid);
			rv =  __ni_objectmodel_return_callback_info(reply, NI_EVENT_LINK_ASSOCIATION_LOST,
					&ifp->link.event_uuid, error);
		}
	}

	ni_wireless_network_put(net);
	return rv;

error:
	ni_wireless_network_put(net);
	return FALSE;
}

dbus_bool_t
ni_objectmodel_get_wireless_request(ni_wireless_network_t *net,
				const ni_dbus_variant_t *var, DBusError *error)
{
	const ni_dbus_variant_t *child;
	const char *string;

	if (!ni_dbus_variant_is_dict(var)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "expected dict argument");
		return FALSE;
	}

	if ((child = ni_dbus_dict_get(var, "essid")) != NULL) {
		unsigned int len;

		if (ni_dbus_variant_get_byte_array_minmax(child, net->essid.data, &len, 0, sizeof(net->essid.data))) {
			net->essid.len = len;
		} else
		if (ni_dbus_variant_get_string(child, &string)) {
			len = strlen(string);
			if (len > sizeof(net->essid.data))
				return FALSE;
			memcpy(net->essid.data, string, len);
			net->essid.len = len;
		} else {
			return FALSE;
		}
	}

	if ((child = ni_dbus_dict_get(var, "access-point")) != NULL) {
		ni_hwaddr_t *hwaddr = &net->access_point;
		unsigned int len;

		if (!ni_dbus_variant_get_byte_array_minmax(child, hwaddr->data, &len, 0, sizeof(hwaddr->data)))
			return FALSE;
		hwaddr->type = NI_IFTYPE_WIRELESS;
		hwaddr->len = len;
	}

	if (ni_dbus_dict_get_string(var, "mode", &string)) {
		net->mode = ni_wireless_name_to_mode(string);
		if (net->mode == NI_WIRELESS_MODE_UNKNOWN)
			return FALSE;
	}

	if ((child = ni_dbus_dict_get(var, "wpa-psk")) != NULL) {
		ni_dbus_variant_t *attr;

		net->auth_proto = NI_WIRELESS_AUTH_WPA2;
		net->keymgmt_proto = NI_WIRELESS_KEY_MGMT_PSK;
		if (ni_dbus_dict_get_string(child, "passphrase", &string))
			ni_string_dup(&net->wpa_psk.passphrase, string);

		if ((attr = ni_dbus_dict_get(child, "key")) != NULL) {
			ni_opaque_t *key = &net->wpa_psk.key;
			unsigned int key_len;

			if (!ni_dbus_variant_get_byte_array_minmax(attr, key->data, &key_len, 64, 64))
				return FALSE;
			key->len = key_len;
		}
	}

	return TRUE;
}

static ni_wireless_t *
__ni_objectmodel_get_wireless(const ni_dbus_object_t *object, DBusError *error)
{
	ni_netdev_t *ifp;
	ni_wireless_t *wlan;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return NULL;

	if (!(wlan = ni_interface_get_wireless(ifp))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting wireless handle for interface");
		return NULL;
	}
	return wlan;
}

static ni_wireless_scan_t *
__ni_objectmodel_get_scan(const ni_dbus_object_t *object, DBusError *error)
{
	ni_wireless_t *wlan;

	if (!(wlan = __ni_objectmodel_get_wireless(object, error)))
		return NULL;

	return wlan->scan;
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

static ni_dbus_method_t		ni_objectmodel_wireless_methods[] = {
	{ "setScanning",	DBUS_TYPE_BOOLEAN_AS_STRING,	ni_objectmodel_wireless_set_scanning	},
	{ "deviceChange",	"a{sv}",			ni_objectmodel_wireless_device_change	},

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_wireless_service = {
	.name		= NI_OBJECTMODEL_WIRELESS_INTERFACE,
	.methods	= ni_objectmodel_wireless_methods,
	.properties	= ni_objectmodel_wireless_property_table,
};

