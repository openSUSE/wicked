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

static dbus_bool_t	ni_objectmodel_get_wireless_request(const char *, ni_wireless_config_t *,
							const ni_dbus_variant_t *, DBusError *);

#if 0
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
#endif

static dbus_bool_t
ni_objectmodel_wireless_change_device(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_wireless_config_t conf;
	ni_netdev_t *dev;
	int ret;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)) || !ni_netdev_get_wireless(dev)) {
		if (!dbus_error_is_set(error)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"wireless change request on non-wireless interface");
		}
		return FALSE;
	}

	ni_wireless_config_init(&conf);
	if (!ni_objectmodel_get_wireless_request(dev->name, &conf, &argv[0], error)) {
		ni_wireless_config_destroy(&conf);
		if (!dbus_error_is_set(error)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s: invalid wireless change device request", dev->name);
		}
		return FALSE;
	}

	if ((ret = ni_wireless_setup(dev, &conf)) < 0) {
		ni_dbus_set_error_from_code(error, ret,
				"%s: unable to setup wireless interface", dev->name);
		ni_wireless_config_destroy(&conf);
		return FALSE;
	}

	ni_wireless_config_destroy(&conf);
	return TRUE;
}


static dbus_bool_t
ni_objectmodel_shutdown_wireless(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (ni_wireless_shutdown(dev)){
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error shutting down wireless interface %s", dev->name);
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmode_bitmap_from_dbus(uint32_t *out, const ni_intmap_t *map, const ni_dbus_variant_t *dict,
		const char *name, DBusError *error, const char *ifname)
{
	uint32_t value, mask = 0;
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

	if (!ni_dbus_variant_is_dict(dict))
		return FALSE;

	if (ni_dbus_dict_get_uint32(dict, name, &value)) {
		ni_format_bitmap_string(&buf, map, value, &mask, " ");
		ni_stringbuf_destroy(&buf);
		if (mask != value) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid bitmap %s %02x", ifname, name, value & ~mask);
			return FALSE;
		}
		*out = value;
	}
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_get_wireless_request_wep(const char *ifname, ni_wireless_network_t *net,
				const ni_dbus_variant_t *var, DBusError *error)
{
	const ni_dbus_variant_t *dict, *key;
	const char *string;
	unsigned int key_idx;
	uint32_t value;

	if ((dict = ni_dbus_dict_get(var, "wep")) == NULL)
		return TRUE;

	if (!ni_dbus_variant_is_dict(dict)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid wep format - dict expected", ifname);
		return FALSE;
	}

	ni_dbus_dict_get_uint32(dict, "auth-algo", &net->auth_algo);

	net->keymgmt_proto |= NI_BIT(NI_WIRELESS_KEY_MGMT_NONE);
	if (ni_dbus_dict_get_uint32(dict, "default-key", &value))
		net->default_key = value;

	key = NULL;
	key_idx = 0;
	while ((key = ni_dbus_dict_get_next(dict, "key", key)) && key_idx < NI_WIRELESS_WEP_KEY_COUNT) {
		if (!ni_dbus_variant_get_string(key, &string)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid wep key keyidx:%u - string expected", ifname, key_idx-1);
			return FALSE;
		}
		if (!ni_wireless_wep_key_parse(&net->wep_keys[key_idx++], string)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid wep key format keyidx:%u", ifname, key_idx-1);
			return FALSE;
		}
	}
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_get_wireless_request_wpa_common(const char *ifname, ni_wireless_network_t *net,
				const ni_dbus_variant_t *dict, DBusError *error)
{
	if (!ni_dbus_variant_is_dict(dict))
		return FALSE;

	if (!ni_objectmode_bitmap_from_dbus(&net->auth_proto, ni_wireless_protocol_map(), dict,
				"auth-proto", error, ifname))
	       return FALSE;

	if (!ni_objectmode_bitmap_from_dbus(&net->group_cipher, ni_wireless_group_map(), dict,
				"group-cipher", error, ifname))
	       return FALSE;

	if (!ni_objectmode_bitmap_from_dbus(&net->pairwise_cipher, ni_wireless_group_map(), dict,
				"pairwise-cipher", error, ifname))
	       return FALSE;

	if (ni_dbus_dict_get_uint32(dict, "pmf", &net->pmf)) {
		if (ni_wireless_pmf_to_name(net->pmf)== NULL)
			return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_get_wireless_request_psk(const char *ifname, ni_wireless_network_t *net,
				const ni_dbus_variant_t *var, DBusError *error)
{
	const ni_dbus_variant_t *child;
	const char *string;

	if ((child = ni_dbus_dict_get(var, "wpa-psk")) == NULL)
		return TRUE;

	/* 'key' member has been removed
	 * do parsing a string here: may be a 64 len HEX digit string or a 8..63 ASCII char passphrase
	*/
	if (!ni_dbus_dict_get_string(child, "passphrase", &string)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Missing mandatory passphrase in wpa-psk settings", ifname);
		return FALSE;
	}
	ni_string_dup(&net->wpa_psk.passphrase, string);

	if (!ni_objectmodel_get_wireless_request_wpa_common(ifname, net, child, error))
		return FALSE;

	return TRUE;
}

static ni_wireless_blob_t *
ni_wireless_blob_from_struct(const ni_dbus_variant_t *var)
{
	ni_wireless_blob_t *blob;
	const char *type = NULL;
	const char *str = NULL;
	ni_dbus_variant_t *data;

	if (!var)
		return NULL;

	if (!ni_dbus_variant_is_struct(var))
		return NULL;

	if (!ni_dbus_struct_get_string(var, 0, &type))
		return NULL;

	if (!(blob = calloc(1, sizeof(ni_wireless_blob_t))))
		return NULL;

	if (ni_string_eq(type, "hex") || ni_string_eq(type, "file")) {
		blob->is_string = FALSE;

		if(!(data = ni_dbus_struct_get(var, 1)))
			goto error;

		if (!ni_dbus_variant_is_byte_array(data))
			goto error;

		ni_byte_array_init(&blob->byte_array);
		if (ni_byte_array_put(&blob->byte_array, data->byte_array_value, data->array.len) != data->array.len)
			goto error;

	} else {
		blob->is_string = TRUE;
		if (!ni_dbus_struct_get_string(var, 1, &str))
			goto error;

		if (!ni_string_dup(&blob->str, str))
			goto error;
	}

	return blob;

error:
	if (blob)
		ni_wireless_blob_free(&blob);
	return NULL;
}


static dbus_bool_t
ni_objectmodel_get_wireless_request_eap(const char *ifname, ni_wireless_network_t *net,
				const ni_dbus_variant_t *var, DBusError *error)
{
	const ni_dbus_variant_t *child, *eap, *cert;
	const char *string;
	dbus_bool_t bool_value;
	uint32_t value;

	if (!(eap = ni_dbus_dict_get(var, "wpa-eap")))
		return TRUE;

	if (!ni_objectmodel_get_wireless_request_wpa_common(ifname, net, eap, error))
		return FALSE;

	if (ni_dbus_dict_get_string(eap, "identity", &string))
		ni_string_dup(&net->wpa_eap.identity, string);

	if (!ni_dbus_dict_get_uint32(eap, "method", &value)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Missing mandatory eap method in wpa-eap settings", ifname);
		return FALSE;
	}
	net->wpa_eap.method = value;

	child = ni_dbus_dict_get(eap, "phase1");
	if (child && ni_dbus_variant_is_dict(child)) {
		if (ni_dbus_dict_get_uint32(child, "peap-version", &value))
			net->wpa_eap.phase1.peapver = value;
		else
			net->wpa_eap.phase1.peapver = -1U;
		if (ni_dbus_dict_get_bool(child, "peap-label", &bool_value))
			net->wpa_eap.phase1.peaplabel = bool_value;
	}

	child = ni_dbus_dict_get(eap, "phase2");
	if (child && ni_dbus_variant_is_dict(child)) {
		if (ni_dbus_dict_get_uint32(child, "method", &value))
			net->wpa_eap.phase2.method = value;
		if (ni_dbus_dict_get_string(child, "password", &string))
			ni_string_dup(&net->wpa_eap.phase2.password, string);
	}

	child = ni_dbus_dict_get(eap, "tls");
	if (child && ni_dbus_variant_is_dict(child)) {

		if ((cert = ni_dbus_dict_get(child, "ca-cert"))) {
			if (!(net->wpa_eap.tls.ca_cert = ni_wireless_blob_from_struct(cert))) {
				dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid certificate ca-cert", ifname);
				return FALSE;
			}
		}

		if ((cert = ni_dbus_dict_get(child, "client-cert"))) {
			if (!(net->wpa_eap.tls.client_cert = ni_wireless_blob_from_struct(cert))) {
				dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid certificate client-cert", ifname);
				return FALSE;
			}
		}

		if ((cert = ni_dbus_dict_get(child, "client-key"))) {
			if (!(net->wpa_eap.tls.client_key = ni_wireless_blob_from_struct(cert))) {
				dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid client-key", ifname);
				return FALSE;
			}
		}

		if (ni_dbus_dict_get_string(child, "client-key-passwd", &string))
			ni_string_dup(&net->wpa_eap.tls.client_key_passwd, string);
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_get_wireless_request_net(const char *ifname, ni_wireless_network_t *net,
				const ni_dbus_variant_t *var, DBusError *error)
{
	const ni_dbus_variant_t *child;
	const char *string = NULL;
	uint32_t value;
	dbus_bool_t boolean;

	if (!ni_dbus_variant_is_dict(var)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "expected dict argument");
		return FALSE;
	}

	if ((child = ni_dbus_dict_get(var, "essid")) != NULL) {
		if (!ni_dbus_variant_get_string(child, &string) ||
		    !ni_wireless_ssid_parse(&net->essid, string)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "invalid wireless ssid %s", string);
			return FALSE;
		}
	}

	if (ni_dbus_dict_get_bool(var, "scan-ssid", &boolean))
		net->scan_ssid = !!boolean;

	if (ni_dbus_dict_get_uint32(var, "priority", &value))
		net->priority = value;

	if ((child = ni_dbus_dict_get(var, "access-point")) != NULL) {
		ni_hwaddr_t hwaddr;
		unsigned int len;

		if (!ni_dbus_variant_get_byte_array_minmax(child, hwaddr.data, &len, 0,
		    sizeof(hwaddr.data)) || ni_link_address_length(ARPHRD_ETHER) != len) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "invalid wireless access point address");
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

	if (ni_dbus_dict_get_uint32(var, "channel", &value))
		net->channel = value;

	if (ni_dbus_dict_get_string(var, "frequency-list", &string)) {
		ni_string_array_t errors = NI_STRING_ARRAY_INIT;
		ni_stringbuf_t tmp = NI_STRINGBUF_INIT_DYNAMIC;

		if (!ni_wireless_frequency_list_parse_string(string, &net->frequency_list, &errors)) {
			if (!dbus_error_is_set(error))
				dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
						"%s: invalid frequency-list: '%s'",
						ifname,
						ni_stringbuf_join(&tmp, &errors, " ")),

			ni_string_array_destroy(&errors);
			ni_stringbuf_destroy(&tmp);
			return FALSE;
		}
	}

	if (ni_dbus_dict_get_uint32(var, "fragment-size", &value))
		net->fragment_size = value;

	net->auth_proto = 0;

	if (!ni_objectmode_bitmap_from_dbus(&net->keymgmt_proto, ni_wireless_key_management_map(), var,
				"key-management", error, ifname))
	       return FALSE;

	if (!ni_objectmodel_get_wireless_request_wep(ifname, net, var, error)) {
		if (!dbus_error_is_set(error))
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: unexpected error in wep configuration", ifname);
		return FALSE;
	}

	if (!ni_objectmodel_get_wireless_request_psk(ifname, net, var, error)) {
		if (!dbus_error_is_set(error))
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: unexpected error in wpa-psk configuration", ifname);
		return FALSE;
	}

	if (!ni_objectmodel_get_wireless_request_eap(ifname, net, var, error)) {
		if (!dbus_error_is_set(error))
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: unexpected error in wpa-eap configuration", ifname);
		return FALSE;
	}

	if ((net->keymgmt_proto & NI_WIRELESS_KEY_MGMT_DEFAULT_EAP) && !net->wpa_eap.method) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid config, missing <eap><method>", ifname);
		return FALSE;
	}

	if ((net->keymgmt_proto & NI_WIRELESS_KEY_MGMT_DEFAULT_PSK) &&
	    ni_string_empty(net->wpa_psk.passphrase)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid config, missing <wpa-psk><passphrase>", ifname);
		return FALSE;
	}

	return TRUE;
}

dbus_bool_t
ni_objectmodel_get_wireless_request(const char *ifname, ni_wireless_config_t *conf,
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

	if ((var = ni_dbus_dict_get(dict, "networks"))){
		unsigned int i;
		ni_dbus_variant_t *network_dict;

		if (!ni_dbus_variant_is_dict_array(var))
			return FALSE;

		for (i = 0; i < var->array.len; ++i) {
			network_dict = &var->variant_array_value[i];

			if (!ni_dbus_variant_is_dict(network_dict))
				return FALSE;

			if (!(net = ni_wireless_network_new()))
				return FALSE;
			net->index = i;

			if (!ni_objectmodel_get_wireless_request_net(ifname, net, network_dict, error)) {
				ni_wireless_network_drop(&net);
				return FALSE;
			}
			if (!ni_wireless_network_array_append(&conf->networks, net)) {
				ni_wireless_network_drop(&net);
				return FALSE;
			}
		}
	}

	return TRUE;
}

void *
ni_objectmodel_get_wireless(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
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

static dbus_bool_t
ni_objectmodel_bss_wpa_to_dict(ni_wireless_bss_t *bss, ni_dbus_variant_t *dict)
{
	ni_dbus_variant_t *v;

	if (!bss->wpa.key_mgmt && !bss->wpa.pairwise_cipher && !bss->wpa.group_cipher)
		return TRUE;

	if (!(v = ni_dbus_dict_add(dict, "wpa")))
		return FALSE;
	ni_dbus_variant_init_dict(v);

	if (bss->wpa.key_mgmt)
		if (!ni_dbus_dict_add_uint32(v, "key-management", bss->wpa.key_mgmt))
			return FALSE;

	if (bss->wpa.pairwise_cipher)
		if (!ni_dbus_dict_add_uint32(v, "pairwise-cipher", bss->wpa.pairwise_cipher))
			return FALSE;

	if (bss->wpa.group_cipher)
		if (!ni_dbus_dict_add_uint32(v, "group-cipher", bss->wpa.group_cipher))
			return FALSE;

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_bss_rsn_to_dict(ni_wireless_bss_t *bss, ni_dbus_variant_t *dict)
{
	ni_dbus_variant_t *v;

	if (!bss->rsn.key_mgmt && !bss->rsn.pairwise_cipher &&
			!bss->rsn.group_cipher && !bss->rsn.mgmt_group_cipher)
		return TRUE;

	if (!(v = ni_dbus_dict_add(dict, "rsn")))
		return FALSE;
	ni_dbus_variant_init_dict(v);

	if (bss->rsn.key_mgmt)
		if (!ni_dbus_dict_add_uint32(v, "key-management", bss->rsn.key_mgmt))
			return FALSE;

	if (bss->rsn.pairwise_cipher)
		if (!ni_dbus_dict_add_uint32(v, "pairwise-cipher", bss->rsn.pairwise_cipher))
			return FALSE;

	if (bss->rsn.group_cipher)
		if (!ni_dbus_dict_add_uint32(v, "group-cipher", bss->rsn.group_cipher))
			return FALSE;

	if (bss->rsn.mgmt_group_cipher)
		if (!ni_dbus_dict_add_uint32(v, "management-group", bss->rsn.mgmt_group_cipher))
			return FALSE;

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_bss_to_dict(ni_wireless_bss_t *bss, ni_dbus_variant_t *dict, time_t age_offset, DBusError *error)
{
	ni_dbus_variant_t *v;
	ni_stringbuf_t sbuf = NI_STRINGBUF_INIT_DYNAMIC;

	if (!ni_dbus_dict_add_string(dict, "ssid", ni_wireless_ssid_print(&bss->ssid, &sbuf))){
		ni_stringbuf_destroy(&sbuf);
		return FALSE;
	}
	ni_stringbuf_destroy(&sbuf);

	if (!ni_dbus_dict_add_byte_array(dict, "bssid", bss->bssid.data, bss->bssid.len))
		return FALSE;

	if (!ni_objectmodel_bss_wpa_to_dict(bss, dict))
		return FALSE;

	if (!ni_objectmodel_bss_rsn_to_dict(bss, dict))
		return FALSE;

	if (bss->wps.type){
		if (!(v = ni_dbus_dict_add(dict, "wps")))
			return FALSE;
		ni_dbus_variant_init_dict(v);
		if (!ni_dbus_dict_add_string(v, "type", bss->wps.type))
			return FALSE;
	}

	if (!ni_dbus_dict_add_bool(dict, "privacy", bss->privacy))
		return FALSE;
	if (!ni_dbus_dict_add_uint32(dict, "mode", bss->wireless_mode))
		return FALSE;
	if (!ni_dbus_dict_add_uint32(dict, "channel", bss->channel))
		return FALSE;
	if (!ni_dbus_dict_add_uint32(dict, "rate-max", bss->rate_max))
		return FALSE;
	if (!ni_dbus_dict_add_int16(dict, "signal", bss->signal))
		return FALSE;
	if (!ni_dbus_dict_add_uint32(dict, "age", bss->age + age_offset))
		return FALSE;

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wireless_get_scan_results(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_wireless_t *wlan;
	ni_dbus_variant_t *dict;
	ni_wireless_bss_t *bss;
	struct timeval now;
	time_t age_offset = 0;

	ni_dbus_dict_array_init(result);

	if (!(wlan = ni_objectmodel_get_wireless(object, FALSE, error)))
		return FALSE;

	if (ni_timer_get_time(&now) == 0)
		age_offset = now.tv_sec - wlan->scan.last_update.tv_sec;

	for(bss = wlan->scan.bsss; bss; bss = bss->next){
		if (!(dict = ni_dbus_dict_array_add(result)))
			return FALSE;

		if (!ni_objectmodel_bss_to_dict(bss, dict, age_offset, error)){
			return FALSE;
		}
	}
	return TRUE;
}


static dbus_bool_t
ni_objectmodel_bss_wpa_from_dict(ni_wireless_bss_t *bss, const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_variant_t *wpa;

	if (!(wpa = ni_dbus_dict_get(dict, "wpa")))
		return TRUE;
	if (!ni_dbus_variant_is_dict(wpa))
		return FALSE;

	/* they are optional */
	ni_dbus_dict_get_uint32(wpa, "key-management", &bss->wpa.key_mgmt);
	ni_dbus_dict_get_uint32(wpa, "pairwise-cipher", &bss->wpa.pairwise_cipher);
	ni_dbus_dict_get_uint32(wpa, "group-cipher", &bss->wpa.group_cipher);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_bss_rsn_from_dict(ni_wireless_bss_t *bss, const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_variant_t *rsn;

	if (!(rsn = ni_dbus_dict_get(dict, "rsn")))
		return TRUE;
	if (!ni_dbus_variant_is_dict(rsn))
		return FALSE;

	/* they are optional */
	ni_dbus_dict_get_uint32(rsn, "key-management", &bss->rsn.key_mgmt);
	ni_dbus_dict_get_uint32(rsn, "pairwise-cipher", &bss->rsn.pairwise_cipher);
	ni_dbus_dict_get_uint32(rsn, "group-cipher", &bss->rsn.group_cipher);
	ni_dbus_dict_get_uint32(rsn, "management-group", &bss->rsn.mgmt_group_cipher);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_bss_from_dict(ni_wireless_bss_t *bss, const ni_dbus_variant_t *dict, DBusError *error)
{
	const char *str;
	ni_dbus_variant_t *var;
	dbus_bool_t boolean;

	if (!ni_dbus_dict_get_string(dict, "ssid", &str))
		return FALSE;
	if (!ni_wireless_ssid_parse(&bss->ssid, str))
		return FALSE;

	if (!(var = ni_dbus_dict_get(dict, "bssid")))
		return FALSE;
	if (!ni_dbus_variant_is_byte_array(var))
		return FALSE;
	ni_link_address_set(&bss->bssid, ARPHRD_ETHER, var->byte_array_value, var->array.len);

	if (!ni_objectmodel_bss_wpa_from_dict(bss, dict, error))
		return FALSE;

	if (!ni_objectmodel_bss_rsn_from_dict(bss, dict, error))
		return FALSE;

	if ((var = ni_dbus_dict_get(dict, "wps")) &&
	    ni_dbus_dict_get_string(var, "type", &str)){
		if (!ni_string_dup(&bss->wps.type, str))
			return FALSE;
	}

	if (!ni_dbus_dict_get_bool(dict, "privacy", &boolean))
		return FALSE;
	bss->privacy = !!boolean;

	if (!ni_dbus_dict_get_uint32(dict, "mode", &bss->wireless_mode))
		return FALSE;
	if (!ni_dbus_dict_get_uint32(dict, "channel", &bss->channel))
		return FALSE;
	if (!ni_dbus_dict_get_uint32(dict, "rate-max", &bss->rate_max))
		return FALSE;
	if (!ni_dbus_dict_get_int16(dict, "signal", &bss->signal))
		return FALSE;
	if (!ni_dbus_dict_get_uint32(dict, "age", &bss->age))
		return FALSE;

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wireless_set_scan_results(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *arg,
				DBusError *error)
{
	size_t i;
	ni_wireless_bss_t *bss;
	ni_wireless_t *wlan;

	if (!(wlan = ni_objectmodel_get_wireless(object, FALSE, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict_array(arg))
		return FALSE;

	if (ni_timer_get_time(&wlan->scan.last_update) != 0)
		return FALSE;

	for (i=0; i < arg->array.len; i++){
		if ((bss = ni_wireless_bss_new())){
			if(!ni_objectmodel_bss_from_dict(bss, &arg->variant_array_value[i], error))
				return FALSE;
			if (!ni_wireless_bss_list_append(&wlan->scan.bsss, bss))
				ni_wireless_bss_free(&bss);
		}
	}
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wireless_get_current_connection(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_wireless_t *wlan;
	ni_stringbuf_t sbuf = NI_STRINGBUF_INIT_DYNAMIC;
	struct timeval now;

	ni_dbus_variant_init_dict(result);

	if (!(wlan = ni_objectmodel_get_wireless(object, FALSE, error)))
		return FALSE;

	if (!ni_dbus_dict_add_uint32(result, "state", wlan->assoc.state))
		return FALSE;

	if (wlan->assoc.bssid.len > 0) {
		if (!ni_dbus_dict_add_byte_array(result, "bssid", wlan->assoc.bssid.data, wlan->assoc.bssid.len))
			return FALSE;


		if (!ni_dbus_dict_add_string(result, "ssid", ni_wireless_ssid_print(&wlan->assoc.ssid, &sbuf))){
			ni_stringbuf_destroy(&sbuf);
			return FALSE;
		}
		ni_stringbuf_destroy(&sbuf);

		if (!ni_dbus_dict_add_int16(result, "signal", wlan->assoc.signal))
			return FALSE;

		if (ni_timer_get_time(&now) == 0)
			if (!ni_dbus_dict_add_uint32(result, "duration", now.tv_sec - wlan->assoc.established_time.tv_sec))
				return FALSE;

		if (!ni_string_empty(wlan->assoc.auth_mode))
			if (!ni_dbus_dict_add_string(result, "authmode", wlan->assoc.auth_mode))
				return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wireless_set_current_connection(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_dbus_variant_t *bssid;
	ni_wireless_t *wlan;
	uint32_t duration;
	const char *tmp;

	if (!(wlan = ni_objectmodel_get_wireless(object, FALSE, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict(argument))
		return FALSE;

	if (!ni_dbus_dict_get_uint32(argument, "state", &wlan->assoc.state))
		return FALSE;

	if ((bssid = ni_dbus_dict_get(argument, "bssid"))) {
		if (!ni_dbus_variant_is_byte_array(bssid))
			return FALSE;

		ni_link_address_set(&wlan->assoc.bssid, ARPHRD_ETHER, bssid->byte_array_value, bssid->array.len);

		if (ni_dbus_dict_get_string(argument, "ssid", &tmp))
			if (!ni_wireless_ssid_parse(&wlan->assoc.ssid, tmp))
				return FALSE;

		if (!ni_dbus_dict_get_int16(argument, "signal", &wlan->assoc.signal))
			return FALSE;

		if (ni_dbus_dict_get_uint32(argument, "duration", &duration) &&
   		    ni_timer_get_time(&wlan->assoc.established_time) == 0) {
			wlan->assoc.established_time.tv_sec -= duration;
		}

		if (ni_dbus_dict_get_string(argument, "authmode", &tmp))
			ni_string_dup(&wlan->assoc.auth_mode, tmp);

	}
	return TRUE;
}


#define WIRELESS_INT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT_PROPERTY(wireless, dbus_name, member_name, rw)
#define WIRELESS_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(wireless, dbus_name, member_name, rw)
#define WIRELESS_DICT_ARRAY_PROPERTY(dbus_name, member_name, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE, \
			dbus_name, member_name, ni_objectmodel_wireless, RO)
#define WIRELESS_DICT_PROPERTY(dbus_name, member_name, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE,  dbus_name, member_name, ni_objectmodel_wireless, RO)


const ni_dbus_property_t	ni_objectmodel_wireless_capabilities[] = {
	WIRELESS_UINT_PROPERTY(pairwise-ciphers, capabilities.pairwise_ciphers, RO),
	WIRELESS_UINT_PROPERTY(group-ciphers, capabilities.group_ciphers, RO),
	WIRELESS_UINT_PROPERTY(group-mgmt-ciphers, capabilities.group_mgmt_ciphers, RO),
	WIRELESS_UINT_PROPERTY(key-management, capabilities.keymgmt_algos, RO),
	WIRELESS_UINT_PROPERTY(auth-methods, capabilities.auth_algos, RO),
	WIRELESS_UINT_PROPERTY(wpa-protocols, capabilities.wpa_protocols, RO),
	WIRELESS_UINT_PROPERTY(operation-modes, capabilities.oper_modes, RO),
	WIRELESS_UINT_PROPERTY(scan-modes, capabilities.scan_modes, RO),
	WIRELESS_INT_PROPERTY (max-scan-ssid, capabilities.max_scan_ssid, RO),

	{ NULL }
};

const ni_dbus_property_t	ni_objectmodel_wireless_property_table[] = {
	NI_DBUS_GENERIC_DICT_PROPERTY(capabilities, ni_objectmodel_wireless_capabilities),
	WIRELESS_DICT_PROPERTY(current-connection, current_connection, RO),
	WIRELESS_DICT_ARRAY_PROPERTY(scan-results, scan_results, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_wireless_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_wireless_change_device },
	{ "shutdownDevice",	"",		.handler = ni_objectmodel_shutdown_wireless },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_wireless_service = {
	.name		= NI_OBJECTMODEL_WIRELESS_INTERFACE,
	.methods	= ni_objectmodel_wireless_methods,
	.properties	= ni_objectmodel_wireless_property_table,
};

