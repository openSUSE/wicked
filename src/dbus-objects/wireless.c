/*
 * dbus encapsulation for wireless interfaces
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>
#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wireless.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "dbus-common.h"
#include "model.h"

static dbus_bool_t	ni_objectmodel_get_wireless_request(ni_wireless_config_t *,
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

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
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
__ni_objectmodel_wireless_net_disconnect(ni_netdev_t *dev, ni_dbus_message_t *reply, DBusError *error)
{
	if (ni_wireless_disconnect(dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"could not disconnect from wireless network");
		return FALSE;
	}

	if (dev->wireless->assoc.state != NI_WIRELESS_NOT_ASSOCIATED) {
		const ni_uuid_t *uuid;

		/* Link is associated. Tell the caller to wait for an event. */
		uuid = ni_netdev_add_event_filter(dev,
					(1 << NI_EVENT_LINK_ASSOCIATED) |
					(1 << NI_EVENT_LINK_ASSOCIATION_LOST));
		return __ni_objectmodel_return_callback_info(reply, NI_EVENT_LINK_ASSOCIATION_LOST,
					uuid, NULL, error);
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wireless_change_device(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	ni_wireless_t *wlan;
	ni_wireless_network_t *net;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (!(wlan = ni_netdev_get_wireless(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"wireless change request on non-wireless interface");
		return FALSE;
	}

	ni_wireless_config_destroy(&wlan->conf);
	if (!ni_objectmodel_get_wireless_request(&wlan->conf, &argv[0], error)) {
		ni_wireless_config_destroy(&wlan->conf);
		return FALSE;
	}

	if (0 == wlan->conf.networks.count) {
		if (wlan->assoc.state != NI_WIRELESS_NOT_ASSOCIATED) /* We're asked to disconnect */
			return __ni_objectmodel_wireless_net_disconnect(dev, reply, error);
		else
			return TRUE; /* Accept wireless with no network configuration */
	}

	/* FIXME: Only one network supported - association to the first network in the networks array */
	ni_assert(wlan->conf.networks.data && *wlan->conf.networks.data);

	net = ni_wireless_network_get(wlan->conf.networks.data[0]);
	if (0 == net->essid.len) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"no essid specified for a given wireless network");
		goto error;
	}

	switch (net->keymgmt_proto) {
	case NI_WIRELESS_KEY_MGMT_PSK:
		if (net->wpa_psk.passphrase == NULL) {
			dbus_set_error(error, NI_DBUS_ERROR_AUTH_INFO_MISSING,
					"wpa-psk.passphrase|PASSWORD|%s",
					ni_wireless_print_ssid(&net->essid));
			goto error;
		}
		break;

	case NI_WIRELESS_KEY_MGMT_EAP:
		if (net->wpa_eap.identity == NULL) {
			dbus_set_error(error, NI_DBUS_ERROR_AUTH_INFO_MISSING,
					"wpa-eap.identity|USERNAME|%s",
					ni_wireless_print_ssid(&net->essid));
			goto error;
		}
		if (net->wpa_eap.phase2.method != NI_WIRELESS_EAP_NONE
		 && net->wpa_eap.phase2.password == NULL) {
			dbus_set_error(error, NI_DBUS_ERROR_AUTH_INFO_MISSING,
					"wpa-eap.phase2.password|PASSWORD|%s",
					ni_wireless_print_ssid(&net->essid));
			goto error;
		}
		break;

	case NI_WIRELESS_KEY_MGMT_802_1X:
		/* FIXME: handle 802.1x */

	default: ;
	}

	/* We're asked to associate with the given network */
	if (ni_wireless_set_network(dev, net) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"could not associate");
		goto error;
	}

	ni_wireless_network_put(net);
	return TRUE;

error:
	ni_wireless_network_put(net);
	return FALSE;
}

static dbus_bool_t
ni_objectmodel_get_wireless_request_net(ni_wireless_network_t *net,
				const ni_dbus_variant_t *var, DBusError *error)
{
	const ni_dbus_variant_t *child;
	const char *string;
	uint32_t value;
	dbus_bool_t  bool_value;

	if (!ni_dbus_variant_is_dict(var)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "expected dict argument");
		return FALSE;
	}

	if ((child = ni_dbus_dict_get(var, "essid")) != NULL) {
		if (!ni_dbus_variant_get_string(child, &string) ||
		    !ni_wireless_parse_ssid(string, &net->essid)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "invald wireless ssid %s", string);
			return FALSE;
		}
	}

	if ((child = ni_dbus_dict_get(var, "access-point")) != NULL) {
		ni_hwaddr_t hwaddr;
		unsigned int len;

		if (!ni_dbus_variant_get_byte_array_minmax(child, hwaddr.data, &len, 0,
		    sizeof(hwaddr.data)) || ni_link_address_length(ARPHRD_ETHER) != len) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "invald wireless access point address");
			return FALSE;
		}
		hwaddr.type = ARPHRD_ETHER;
		hwaddr.len = len;
		net->access_point = hwaddr;
	}

	if (ni_dbus_dict_get_uint32(var, "mode", &value)) {
		if (!ni_wireless_mode_to_name(value)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "invalid wireless mode %u", value);
			return FALSE;
		}
		net->mode = value;
	}

	if ((child = ni_dbus_dict_get(var, "wpa-psk")) != NULL) {
		net->keymgmt_proto = NI_WIRELESS_KEY_MGMT_PSK;
		if (!ni_dbus_dict_get_uint32(child, "auth-proto", &net->auth_proto))
			net->auth_proto = NI_WIRELESS_AUTH_MODE_NONE;
		/* 'key' member has been removed
		 * do parsing a string here: may be a 64 len HEX digit string or a 8..63 ASCII char passphrase
		*/
		if (ni_dbus_dict_get_string(child, "passphrase", &string))
			ni_string_dup(&net->wpa_psk.passphrase, string);
	} else
	if ((child = ni_dbus_dict_get(var, "wpa-eap")) != NULL) {
		ni_dbus_variant_t *gchild;

		net->keymgmt_proto = NI_WIRELESS_KEY_MGMT_EAP;
		if (!ni_dbus_dict_get_uint32(child, "auth-proto", &net->auth_proto))
			net->auth_proto = NI_WIRELESS_AUTH_MODE_NONE;

		if (ni_dbus_dict_get_string(child, "identity", &string))
			ni_string_dup(&net->wpa_eap.identity, string);
		if (ni_dbus_dict_get_uint32(child, "method", &value))
			net->wpa_eap.method = value;

		gchild = ni_dbus_dict_get(child, "phase1");
		if (gchild && ni_dbus_variant_is_dict(gchild)) {
			if (ni_dbus_dict_get_uint32(gchild, "peap-version", &value))
				net->wpa_eap.phase1.peapver = value;
			else
				net->wpa_eap.phase1.peapver = -1U;
			if (ni_dbus_dict_get_bool(gchild, "peap-label", &bool_value))
				net->wpa_eap.phase1.peaplabel = bool_value;
		}

		gchild = ni_dbus_dict_get(child, "phase2");
		if (gchild && ni_dbus_variant_is_dict(gchild)) {
			if (ni_dbus_dict_get_uint32(gchild, "method", &value))
				net->wpa_eap.phase2.method = value;
			if (ni_dbus_dict_get_string(gchild, "password", &string))
				ni_string_dup(&net->wpa_eap.phase2.password, string);
		}

		gchild = ni_dbus_dict_get(child, "tls");
		if (gchild && ni_dbus_variant_is_dict(gchild)) {
			/* FIXME: handle optional CA cert, keys and such.
			 * If not provided, use system certs */
		}
	}

	return TRUE;
}

dbus_bool_t
ni_objectmodel_get_wireless_request(ni_wireless_config_t *conf,
				const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_wireless_network_t *net;
	ni_dbus_variant_t *var;
	const char *string = NULL;
	uint32_t value;

	if (!ni_dbus_variant_is_dict(dict)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "expected dict argument");
		return FALSE;
	}

	if (ni_dbus_dict_get_string(dict, "country", &string)) {
		if (ni_string_len(string) != 2) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"invalid wireless country %s", string);
			return FALSE;
		}
		ni_string_dup(&conf->country, string);
		string = NULL;
	}

	if (ni_dbus_dict_get_uint32(dict, "ap-scan", &value)) {
		if (value > NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"invalid wireless ap-scan mode %u", value);
			return FALSE;
		}
		conf->ap_scan = value;
	}

	if (ni_dbus_dict_get_string(dict, "wpa-driver", &string)) {
		if (!ni_check_printable(string, ni_string_len(string)) ||
			!ni_wpa_driver_string_validate(string)) {
				dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
						"invalid wireless driver %s", string);
				return FALSE;
		}
		ni_string_dup(&conf->driver, string);
		string = NULL;
	}

	var = NULL;
	while ((var = ni_dbus_dict_get_next(dict, "network", var)) != NULL) {
		if (!ni_dbus_variant_is_dict(var))
			return FALSE;

		if (!(net = ni_wireless_network_new()))
			return FALSE;

		if (!ni_objectmodel_get_wireless_request_net(net, var, error)) {
			ni_wireless_network_free(net);
			return FALSE;
		}
		ni_wireless_network_array_append(&conf->networks, net);
	}

	return TRUE;
}

static ni_wireless_t *
__ni_objectmodel_wireless_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_wireless_t *wlan;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->wireless;

	if (!(wlan = ni_netdev_get_wireless(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting wireless handle for interface");
		return NULL;
	}
	return wlan;
}

static ni_wireless_t *
__ni_objectmodel_wireless_write_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_wireless_handle(object, TRUE, error);
}

static const ni_wireless_t *
__ni_objectmodel_wireless_read_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_wireless_handle(object, FALSE, error);
}

static ni_wireless_scan_t *
__ni_objectmodel_get_scan(const ni_dbus_object_t *object, DBusError *error)
{
	const ni_wireless_t *wlan;

	if (!(wlan = __ni_objectmodel_wireless_read_handle(object, error)))
		return NULL;

	return wlan->scan;
}


/* Same as above, except returns a void pointer */
void *
ni_objectmodel_get_wireless(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_wireless_handle(object, write_access, error);
}

static dbus_bool_t
__ni_objectmodel_wireless_get_network(const ni_wireless_network_t *network,
				ni_dbus_variant_t *dict,
				DBusError *error)
{
	unsigned int i;

	ni_dbus_dict_add_string(dict, "essid", ni_wireless_print_ssid(&network->essid));

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
		ni_dbus_dict_add_uint32(child, "key-management", auth_info->keymgmt_algos);
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_wireless_set_network(ni_wireless_network_t *network,
				const ni_dbus_variant_t *dict,
				DBusError *error)
{
	ni_dbus_variant_t *child;
	const char *string;
	uint32_t valu32;
	double valdbl;

	if (ni_dbus_dict_get_string(dict, "essid", &string)
	 && !ni_wireless_parse_ssid(string, &network->essid))
		return FALSE;

	if ((child = ni_dbus_dict_get(dict, "access-point")) != NULL) {
		__ni_objectmodel_set_hwaddr(child, &network->access_point);
		network->access_point.type = ARPHRD_ETHER;
	}

	if (ni_dbus_dict_get_uint32(dict, "mode", &valu32))
		network->mode = valu32;
	if (ni_dbus_dict_get_uint32(dict, "channel", &valu32))
		network->channel = valu32;
	if (ni_dbus_dict_get_double(dict, "frequency", &valdbl))
		network->scan_info.frequency = valdbl;
	if (ni_dbus_dict_get_uint32(dict, "max-bitrate", &valu32))
		network->scan_info.max_bitrate = valu32;

	child = NULL;
	while ((child = ni_dbus_dict_get_next(dict, "auth-info", child)) != NULL) {
		ni_wireless_auth_info_t *auth_info;
		uint32_t mode, version;

		if (!ni_dbus_dict_get_uint32(child, "mode", &mode)
		 || !ni_dbus_dict_get_uint32(child, "version", &version))
			return FALSE;

		auth_info = ni_wireless_auth_info_new(mode, version);
		ni_wireless_auth_info_array_append(&network->scan_info.supported_auth_modes, auth_info);

		if (ni_dbus_dict_get_uint32(child, "group-cipher", &valu32))
			auth_info->group_cipher = valu32;
		if (ni_dbus_dict_get_uint32(child, "pairwise-ciphers", &valu32))
			auth_info->pairwise_ciphers = valu32;
		if (ni_dbus_dict_get_uint32(child, "key-management", &valu32))
			auth_info->keymgmt_algos = valu32;
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

	ni_dbus_dict_add_int64(result, "timestamp", scan->timestamp.tv_sec);
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
	ni_wireless_scan_t *scan;
	const ni_dbus_variant_t *child;
	int64_t value64;

	if (!(wlan = __ni_objectmodel_wireless_write_handle(object, error)))
		return FALSE;

	if ((scan = wlan->scan) != NULL)
		ni_wireless_scan_free(scan);

	wlan->scan = scan = ni_wireless_scan_new(NULL, 0);
	if (ni_dbus_dict_get_int64(argument, "timestamp", &value64)) {
		scan->timestamp.tv_sec = value64;
		scan->timestamp.tv_usec = 0;
	}

	child = NULL;
	while ((child = ni_dbus_dict_get_next(argument, "network", child)) != NULL) {
		ni_wireless_network_t *net;

		if (!(net = ni_wireless_network_new()))
			return FALSE;

		if (!__ni_objectmodel_wireless_set_network(net, child, error)) {
			ni_wireless_network_free(net);
			return FALSE;
		}

		ni_wireless_network_array_append(&scan->networks, net);
	}

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
	{ "setScanning",	DBUS_TYPE_BOOLEAN_AS_STRING,	.handler = ni_objectmodel_wireless_set_scanning	},
	{ "changeDevice",	"a{sv}",			.handler = ni_objectmodel_wireless_change_device },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_wireless_service = {
	.name		= NI_OBJECTMODEL_WIRELESS_INTERFACE,
	.methods	= ni_objectmodel_wireless_methods,
	.properties	= ni_objectmodel_wireless_property_table,
};

