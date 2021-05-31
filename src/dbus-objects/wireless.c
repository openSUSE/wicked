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
ni_objectmodel_get_wireless_request_wep(const char *ifname, ni_wireless_network_t *net,
				const ni_dbus_variant_t *var, DBusError *error)
{
	const ni_dbus_variant_t *dict, *key;
	const char *string;
	unsigned int key_idx;
	uint32_t value;

	if ((dict = ni_dbus_dict_get(var, "wep")) == NULL)
		return TRUE;

	if (!ni_dbus_variant_is_dict(dict)){
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid wep format - dict expected", ifname);
		return FALSE;
	}

	ni_dbus_dict_get_uint32(dict, "auth-algo", &net->auth_algo);

	net->keymgmt_proto |= NI_BIT(NI_WIRELESS_KEY_MGMT_NONE);
	if (ni_dbus_dict_get_uint32(dict, "default-key", &value))
		net->default_key = value;

	key = NULL;
	key_idx = 0;
	while((key = ni_dbus_dict_get_next(dict, "key", key)) && key_idx < NI_WIRELESS_WEP_KEY_COUNT) {
		if (!ni_dbus_variant_get_string(key, &string)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid wep key keyidx:%u - string expected", ifname, key_idx-1);
			return FALSE;
		}
		if (!ni_wireless_wep_key_parse(&net->wep_keys[key_idx++], string)){
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: Invalid wep key format keyidx:%u", ifname, key_idx-1);
			return FALSE;
		}
	}
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_get_wireless_request_net(const char *ifname, ni_wireless_network_t *net,
				const ni_dbus_variant_t *var, DBusError *error)
{
	const ni_dbus_variant_t *child;
	const char *string;
	uint32_t value;
	dbus_bool_t boolean;

	if (!ni_dbus_variant_is_dict(var)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "expected dict argument");
		return FALSE;
	}

	if ((child = ni_dbus_dict_get(var, "essid")) != NULL) {
		if (!ni_dbus_variant_get_string(child, &string) ||
		    !ni_wireless_ssid_parse(&net->essid, string)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "invald wireless ssid %s", string);
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

	if (ni_dbus_dict_get_uint32(var, "channel", &value))
		net->channel = value;

	if (ni_dbus_dict_get_uint32(var, "fragment-size", &value))
		net->fragment_size = value;

	net->auth_proto = 0;

	if(!ni_objectmodel_get_wireless_request_wep(ifname, net, var, error)){
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: unexpected error in wep configuration", ifname);
		return FALSE;
	}

	if ((child = ni_dbus_dict_get(var, "wpa-psk")) != NULL) {
		net->keymgmt_proto |= NI_BIT(NI_WIRELESS_KEY_MGMT_PSK);
		if (ni_dbus_dict_get_uint32(child, "auth-proto", &value))
			net->auth_proto |= value;
		/* 'key' member has been removed
		 * do parsing a string here: may be a 64 len HEX digit string or a 8..63 ASCII char passphrase
		*/
		if (ni_dbus_dict_get_string(child, "passphrase", &string))
			ni_string_dup(&net->wpa_psk.passphrase, string);
	} else
	if ((child = ni_dbus_dict_get(var, "wpa-eap")) != NULL) {
		ni_dbus_variant_t *gchild;

		net->keymgmt_proto |= NI_BIT(NI_WIRELESS_KEY_MGMT_EAP);
		if (ni_dbus_dict_get_uint32(child, "auth-proto", &value))
			net->auth_proto |= value;

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
			if (ni_dbus_dict_get_bool(gchild, "peap-label", &boolean))
				net->wpa_eap.phase1.peaplabel = boolean;
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

	if (net->keymgmt_proto == 0)
		net->keymgmt_proto = NI_BIT(NI_WIRELESS_KEY_MGMT_NONE);

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

			if (!ni_objectmodel_get_wireless_request_net(ifname, net, network_dict, error)) {
				ni_wireless_network_put(net);
				return FALSE;
			}
			ni_wireless_network_array_append(&conf->networks, net);
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
	if (!ni_dbus_dict_add_uint32(dict, "wireless-mode", bss->wireless_mode))
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
ni_objectmodel_wireless_set_scan_results(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	/* ignore this, as we do not want to get scan results from Nanny! */
	return TRUE;
}

#define WIRELESS_INT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT_PROPERTY(wireless, dbus_name, member_name, rw)
#define WIRELESS_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(wireless, dbus_name, member_name, rw)
#define WIRELESS_DICT_ARRAY_PROPERTY(dbus_name, member_name, rw) \
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE, \
			dbus_name, member_name, ni_objectmodel_wireless, RO)

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
	NI_DBUS_GENERIC_DICT_PROPERTY(capabilities, ni_objectmodel_wireless_capabilities, RO),
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

