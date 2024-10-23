/*
 *	Routines for handling Wireless devices.
 *
 *	Holie cowe, the desygne of thefe Wyreless Extensions is indisputablie baroque!
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2023 SUSE LLC
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
 *		Olaf Kirch
 *		Marius Tomaschewski
 *		Pawel Wieczorkiewicz
 *		Rubén Torrero Marijnissen
 *		Clemens Famulla-Conrad
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/wireless.h>
#include <wicked/socket.h>
#include <wicked/netinfo.h>
#include "refcount_priv.h"
#include "array_priv.h"
#include "socket_priv.h"
#include "netinfo_priv.h"
#include "wpa-supplicant.h"

#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <net/if_arp.h>		/* For ARPHRD_ETHER */


#ifndef NI_WIRELESS_WPA_DRIVER_DEFAULT
#define NI_WIRELESS_WPA_DRIVER_DEFAULT		"nl80211,wext"
#endif

static void		__ni_wireless_scan_timer_arm(ni_wireless_scan_t *, ni_netdev_t *, unsigned int);
static int		ni_wireless_scan_sync_bss(ni_wireless_scan_t *scan, const ni_wpa_bss_t *bss);
static int		ni_wireless_trigger_scan(ni_netdev_t *dev, ni_wpa_nif_t *wif, ni_bool_t active_scan);
static void		ni_wireless_scan_set_defaults(ni_wireless_scan_t *scan);
static void		ni_wireless_scan_destroy(ni_wireless_scan_t *scan);
static void		ni_wireless_bss_set(ni_wireless_bss_t *wireless_bss, const ni_wpa_bss_t *bss);
static void		ni_wireless_on_state_change(ni_wpa_nif_t *, ni_wpa_nif_state_t, ni_wpa_nif_state_t);
static void		ni_wireless_on_properties_changed(ni_wpa_nif_t *wif, ni_dbus_variant_t *props);
static void             ni_wireless_set_state(ni_netdev_t *dev, ni_wireless_assoc_state_t new_state);

static ni_bool_t	__ni_wireless_scanning_enabled = TRUE;

/*
 * WPA supplicant names to wireless constant maps
 */
static const ni_intmap_t			ni_wireless_wpa_pairwise_map[] = {
	/* as required for networks and also used in capabilities					*/
	{ "CCMP-256",				NI_WIRELESS_CIPHER_CCMP256				},
	{ "GCMP-256",				NI_WIRELESS_CIPHER_GCMP256				},
	{ "CCMP",				NI_WIRELESS_CIPHER_CCMP					},
	{ "GCMP",				NI_WIRELESS_CIPHER_GCMP					},
	{ "TKIP",				NI_WIRELESS_CIPHER_TKIP					},
	{ "NONE",				NI_WIRELESS_CIPHER_NONE					},

	{ NULL }
};

static const ni_intmap_t			ni_wireless_wpa_group_map[] = {
	/* as required for networks and also used in capabilities					*/
	{ "CCMP-256",				NI_WIRELESS_CIPHER_CCMP256				},
	{ "GCMP-256",				NI_WIRELESS_CIPHER_GCMP256				},
	{ "CCMP",				NI_WIRELESS_CIPHER_CCMP					},
	{ "GCMP",				NI_WIRELESS_CIPHER_GCMP					},
	{ "TKIP",				NI_WIRELESS_CIPHER_TKIP					},
	{ "WEP104",				NI_WIRELESS_CIPHER_WEP104				},
	{ "WEP40",				NI_WIRELESS_CIPHER_WEP40				},

	{ NULL }
};

static const ni_intmap_t			ni_wireless_wpa_group_mgmt_map[] = {
	/* as required for networks and also used in capabilities					*/
	{ "AES-128-CMAC",			NI_WIRELESS_CIPHER_AES128_CMAC				},
	{ "AES128CMAC",				NI_WIRELESS_CIPHER_AES128_CMAC				},
	{ "BIP-GMAC-128",			NI_WIRELESS_CIPHER_BIP_GMAC128				},
	{ "BIPGMAC128",				NI_WIRELESS_CIPHER_BIP_GMAC128				},
	{ "BIP-GMAC-256",			NI_WIRELESS_CIPHER_BIP_GMAC256				},
	{ "BIPGMAC256",				NI_WIRELESS_CIPHER_BIP_GMAC256				},
	{ "BIP-CMAC-256",			NI_WIRELESS_CIPHER_BIP_CMAC256				},
	{ "BIPCMAC256",				NI_WIRELESS_CIPHER_BIP_CMAC256				},

	{ NULL }
};

static const ni_intmap_t			ni_wireless_wpa_key_mgmt_map[] = {
	/*  Used to map NI_WIRELESS_KEY_MGMT to wpa_supplicant dbus names and wise versa */
	{ "NONE",				NI_WIRELESS_KEY_MGMT_NONE				},
	{ "IEEE8021X",				NI_WIRELESS_KEY_MGMT_802_1X				},
	{ "WPA-PSK",				NI_WIRELESS_KEY_MGMT_PSK				},
	{ "FT-PSK",				NI_WIRELESS_KEY_MGMT_FT_PSK				},
	/* wpa_supplicant uses WPA-FT-PSK in BSS->key-management but FT-PSK in configuration */
	{ "WPA-FT-PSK",				NI_WIRELESS_KEY_MGMT_FT_PSK				},
	{ "WPA-PSK-SHA256",			NI_WIRELESS_KEY_MGMT_PSK_SHA256				},
	{ "WPA-EAP",				NI_WIRELESS_KEY_MGMT_EAP				},
	{ "WPA-EAP-SHA256",			NI_WIRELESS_KEY_MGMT_EAP_SHA256				},
	{ "FT-EAP",				NI_WIRELESS_KEY_MGMT_FT_EAP				},
	/* same reason as WPA-FT-PSK */
	{ "WPA-FT-EAP",				NI_WIRELESS_KEY_MGMT_FT_EAP				},
	{ "FT-EAP-SHA384",			NI_WIRELESS_KEY_MGMT_FT_EAP_SHA384			},
	{ "SAE",				NI_WIRELESS_KEY_MGMT_SAE				},
	{ "FT-SAE",				NI_WIRELESS_KEY_MGMT_FT_SAE				},
	{ "WPS",				NI_WIRELESS_KEY_MGMT_WPS				},
	{ "WPA-EAP-SUITE-B",			NI_WIRELESS_KEY_MGMT_EAP_SUITE_B			},
	{ "WPA-EAP-SUITE-B-192",		NI_WIRELESS_KEY_MGMT_EAP_SUITE_B_192			},
	{ "OSEM",				NI_WIRELESS_KEY_MGMT_OSEM				},
	{ "FILS-SHA256",			NI_WIRELESS_KEY_MGMT_FILS_SHA256			},
	{ "FILS-SHA384",			NI_WIRELESS_KEY_MGMT_FILS_SHA384			},
	{ "FT-FILS-SHA256",			NI_WIRELESS_KEY_MGMT_FT_FILS_SHA256			},
	{ "FT-FILS-SHA384",			NI_WIRELESS_KEY_MGMT_FT_FILS_SHA384			},
	{ "OWE",				NI_WIRELESS_KEY_MGMT_OWE				},
	{ "DPP",				NI_WIRELESS_KEY_MGMT_DPP				},
	{ NULL }
};

static const ni_intmap_t			ni_wireless_wpa_protocol_map[] = {
	/* as required for networks and also used in capabilities					*/
	{ "RSN",				NI_WIRELESS_AUTH_PROTO_RSN				},
	{ "WPA",				NI_WIRELESS_AUTH_PROTO_WPA				},

	{ NULL }
};

static const ni_intmap_t			ni_wireless_wpa_auth_algo_map[] = {
	/* as required for networks and also used in capabilities					*/
	{ "OPEN",				NI_WIRELESS_AUTH_OPEN					},
	{ "SHARED",				NI_WIRELESS_AUTH_SHARED					},
	{ "LEAP",				NI_WIRELESS_AUTH_LEAP					},

	{ NULL }
};

static const ni_intmap_t			ni_wireless_wpa_scan_mode_caps_map[] = {
	/* as used in capabilities, networks are using int values in ap_scan and other settings		*/
	{ "active",				NI_WIRELESS_SCAN_MODE_ACTIVE				},
	{ "passive",				NI_WIRELESS_SCAN_MODE_PASSIVE				},
	{ "ssid",				NI_WIRELESS_SCAN_MODE_SSID				},

	{ NULL }
};

static const ni_intmap_t			ni_wireless_wpa_oper_mode_caps_map[] = {
	/* as used in capabilities, network are using int values in mode settings			*/
	{ "infrastructure",			NI_WIRELESS_MODE_MANAGED				},
	{ "ad-hoc",				NI_WIRELESS_MODE_ADHOC					},
	{ "ap",					NI_WIRELESS_MODE_MASTER					},
	{ "p2p",				NI_WIRELESS_MODE_P2P					},
	{ "mesh",				NI_WIRELESS_MODE_MESH					},

	{ NULL }
};

static const ni_intmap_t			ni_wireless_wpa_eap_method_map[] = {
	{ "MD5",				NI_WIRELESS_EAP_MD5 },
	{ "MSCHAPV2",				NI_WIRELESS_EAP_MSCHAPV2},
	{ "OTP",				NI_WIRELESS_EAP_OTP},
	{ "GTC",				NI_WIRELESS_EAP_GTC},
	{ "TLS",				NI_WIRELESS_EAP_TLS},
	{ "PEAP",				NI_WIRELESS_EAP_PEAP},
	{ "TTLS",				NI_WIRELESS_EAP_TTLS},
	{ "PAP",				NI_WIRELESS_EAP_PAP},

	{ NULL }
};
/*
 * END wpa-supplicant names to constant maps
 */

static ni_bool_t
ni_wireless_wpa_group_mgmt_type(const char *name, ni_wireless_cipher_t *type)
{
	if (!type || ni_parse_uint_mapped(name, ni_wireless_wpa_group_mgmt_map, type) < 0)
		return FALSE;
	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_pairwise_type(const char *name, ni_wireless_cipher_t *type)
{
	if (!type || ni_parse_uint_mapped(name, ni_wireless_wpa_pairwise_map, type) < 0)
		return FALSE;
	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_pairwise_mask(const ni_string_array_t *array, unsigned int *mask)
{
	unsigned int i;
	ni_wireless_cipher_t cipher;
	*mask = 0;

	for(i = 0; i < array->count; i++){
		if (!ni_wireless_wpa_pairwise_type(array->data[i], &cipher)){
			ni_error("Failed to map %s to ni_wireless_cipher_t", array->data[i]);
			*mask = 0;
			return FALSE;
		}
		*mask |= NI_BIT(cipher);
	}

	return TRUE;
}

static const char *
ni_wireless_wpa_eap_method(ni_wireless_eap_method_t method)
{
	return ni_format_uint_mapped(method, ni_wireless_wpa_eap_method_map);
}

static ni_bool_t
ni_wireless_wpa_key_mgmt_type(const char *name, ni_wireless_key_mgmt_t *type)
{
	if (!type || ni_parse_uint_mapped(name, ni_wireless_wpa_key_mgmt_map, type) < 0)
		return FALSE;
	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_key_mgmt_mask(const ni_string_array_t *array, unsigned int *mask)
{
	size_t i;
	ni_wireless_key_mgmt_t key_mgmt;
	*mask = 0;

	for(i = 0; i < array->count; i++){
		if (!ni_wireless_wpa_key_mgmt_type(array->data[i], &key_mgmt)){
			ni_error("Failed to map %s to ni_wireless_key_mgmt_t", array->data[i]);
			*mask = 0;
			return FALSE;
		}
		*mask |= NI_BIT(key_mgmt);
	}

	return TRUE;
}

const ni_intmap_t *
ni_wireless_protocol_map()
{
	return ni_wireless_wpa_protocol_map;
}

static ni_netdev_t *
ni_wireless_unwrap_wpa_nif(ni_wpa_nif_t *wif)
{
	ni_netdev_ref_t *device = &wif->device;
	ni_netdev_t *dev;

	if (!(dev = ni_netdev_ref_resolve(device, NULL))){
		ni_error("Unknown interface %s(%d)", device->name, device->index);
		return NULL;
	}

	if (dev->link.type != NI_IFTYPE_WIRELESS){
		ni_error("Device isn't from type wireless %s(%d)", device->name, device->index);
		return NULL;
	}

	if (!dev->wireless){
		ni_error("Device %s(%d) doesn't have a wireless extension", device->name, device->index);
		return NULL;
	}

	return dev;

}

static void
ni_wireless_on_network_added(ni_wpa_nif_t *wif, const char *path, const ni_wpa_net_properties_t *props)
{
	//TODO evaluate if we need this information somehow or not.
}

static void
ni_wireless_on_scan_done(ni_wpa_nif_t *wif, const ni_wpa_bss_t *bss_list)
{
	ni_netdev_ref_t *device = &wif->device;
	ni_netdev_t *dev;
	ni_wireless_t *wlan;
	ni_wireless_bss_t *bss;
	ni_stringbuf_t sbuf = NI_STRINGBUF_INIT_DYNAMIC;

	if (!(dev = ni_wireless_unwrap_wpa_nif(wif))){
		ni_error("%s -- Unable to unwrap wpa_nif_t", __func__);
		return;
	}
	wlan = dev->wireless;

	ni_wireless_scan_sync_bss(&wlan->scan, bss_list);

	ni_debug_wireless("Scan done on interface `%s`", device->name);
	for(bss = wlan->scan.bsss; bss; bss = bss->next){
		ni_debug_wireless("Found ssid:`%s` bssid:%s Signal:%d Age:%d Channel:%u (%uMHz)",
				ni_wireless_ssid_print(&bss->ssid, &sbuf),
				ni_link_address_print(&bss->bssid),
				bss->signal, bss->age, bss->channel, bss->frequency);
		ni_stringbuf_destroy(&sbuf);
	}
	__ni_netdev_event(NULL, dev, NI_EVENT_LINK_SCAN_UPDATED);
}

static ni_wpa_nif_t*
ni_wireless_get_wpa_interface(ni_netdev_t *dev)
{
	ni_wpa_client_t *wpa;

	if (!(wpa = ni_wpa_client()))
		return NULL;

	return ni_wpa_nif_by_index(wpa, dev->link.ifindex);
}

/*
 * Refresh what we think we know about this interface.
 *
 * Called from __ni_netdev_process_newlink() which was triggered by a
 * RTM_NEWLINK message.
 *
 */
int
ni_wireless_interface_refresh(ni_netdev_t *dev)
{
	ni_wireless_t *wlan;

	if (ni_rfkill_disabled(NI_RFKILL_TYPE_WIRELESS))
		return -NI_ERROR_RADIO_DISABLED;

	if (!dev || !(wlan = ni_netdev_get_wireless(dev)))
		return -NI_ERROR_GENERAL_FAILURE;

	if (!wlan->scan.timer && wlan->scan.interval > 0)
		__ni_wireless_scan_timer_arm(&wlan->scan, dev, 1);

	return 0;
}

/*
 * Enable/disable wireless AP scanning on a device
 */
int
ni_wireless_interface_set_scanning(ni_netdev_t *dev, ni_bool_t enable)
{
	ni_wireless_t *wlan;

	if ((wlan = ni_netdev_get_wireless(dev)) == NULL) {
		ni_error("%s: no wireless info for device", dev->name);
		return -1;
	}

	if (enable) {
		if (wlan->scan.interval == 0)
			wlan->scan.interval = NI_WIRELESS_DEFAULT_SCAN_INTERVAL;

		__ni_wireless_scan_timer_arm(&wlan->scan, dev, 1);
	} else {
		wlan->scan.interval = 0;
		if (wlan->scan.timer){
			ni_timer_cancel(wlan->scan.timer);
			wlan->scan.timer = NULL;
		}
	}

	return 0;
}

/*
 * Enable/disable AP scanning globally.
 * This is just the default setting for newly registered devices.
 * A client can still override this on a per device basis by calling
 * ni_wireless_interface_set_scanning()
 */
void
ni_wireless_set_scanning(ni_bool_t enable)
{
	__ni_wireless_scanning_enabled = enable;
}

static void
ni_wireless_scan_add_bss(ni_wireless_scan_t *scan, ni_wireless_bss_t *bss)
{
	ni_wireless_bss_t **next = &scan->bsss;

	ni_assert(bss->next == NULL);

	while(*next != NULL) next = &(*next)->next;
	*next = bss;
}

unsigned int
ni_wireless_frequency_to_channel(unsigned int frequency)
{
	if (frequency >= 5950) {
		return (frequency - 5950) / 5;

	} else if (frequency > 5000) {
		return (frequency - 5000) / 5;

	} else if (frequency >= 4915) {
		return (frequency - 4915) / 5 + 183;

	} else if (frequency == 2484) {
		return 14;

	} else {
		return (frequency - 2407) / 5;
	}
}

static ni_bool_t
ni_wireless_band2freq_list(ni_uint_array_t *array, const char *value)
{
	static const unsigned int freq_set_2_4ghz[] = {
		2412, 2417, 2422, 2427, 2432, 2437, 2442,
		2447, 2452, 2457, 2462, 2467, 2472, 2484,
		0
	};
	static const unsigned int freq_set_5ghz[] = {
		4920, 4940, 4960, 4980, 4955, 4975, 5040, 5060, 5080,
		5160, 5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5340,
		5480, 5500, 5520, 5540, 5560, 5580, 5600, 5620, 5640, 5660, 5680, 5700, 5720,
		5745, 5765, 5785, 5805, 5825, 5845, 5865, 5885,
		5860, 5870, 5880, 5890, 5900, 5910, 5920, 5935, 5940, 5945, 5960, 5980,
		0
	};
	static const unsigned int freq_set_6ghz[] = {
		5935, 5955, 5975, 5995, 6015, 6035, 6055, 6075, 6095, 6115, 6135, 6155, 6175,
		6195, 6215, 6235, 6255, 6275, 6295, 6315, 6335, 6355, 6375, 6395, 6415, 6435,
		6455, 6475, 6495, 6515, 6535, 6555, 6575, 6595, 6615, 6635, 6655, 6675, 6695,
		6715, 6735, 6755, 6775, 6795, 6815, 6835, 6855, 6875, 6895, 6915, 6935, 6955,
		6975, 6995, 7015, 7035, 7055, 7075, 7095, 7115,
		0
	};

	static const struct ni_wireless_freq_set_data {
		ni_wireless_frequency_set_t	set;
		const unsigned int *		freqs;
	} freq_sets[] = {
		{ NI_WIRELESS_FREQUENCY_SET_2_4GHz,	freq_set_2_4ghz},
		{ NI_WIRELESS_FREQUENCY_SET_5GHz,	freq_set_5ghz},
		{ NI_WIRELESS_FREQUENCY_SET_6GHz,	freq_set_6ghz},

		{ NI_WIRELESS_FREQUENCY_SET_NONE,	NULL }
	}, *ptr;
	ni_wireless_frequency_set_t set;
	const unsigned int *freq;

	if (!ni_wireless_frequency_set_type(value, &set))
		return FALSE;

	for (ptr = freq_sets; ptr->freqs; ptr++) {
		if (ptr->set != set)
			continue;

		for (freq = ptr->freqs; *freq; freq++) {
			if (ni_uint_array_index(array, *freq) == -1U)
				if (!ni_uint_array_append(array, *freq))
					return FALSE;
		}
	}

	return TRUE;
}

ni_bool_t
ni_wireless_frequency_list_parse_string(const char *value, ni_string_array_t *array,
		ni_string_array_t *errors)
{
	ni_string_array_t tmp = NI_STRING_ARRAY_INIT;
	ni_wireless_frequency_set_t freq_set;
	unsigned int i, num, old_errors;
	const char *tmp_str = NULL;

	if (!array || !value || !errors)
		return FALSE;

	old_errors = errors->count;

	ni_string_split(&tmp, value, " \t", 0);

	for (i = 0; i < tmp.count; i++) {
		if (ni_wireless_frequency_set_type(tmp.data[i], &freq_set)) {
			tmp_str = ni_wireless_frequency_set_name(freq_set);
			if (ni_string_array_index(array, tmp_str) == -1)
				ni_string_array_append(array, tmp_str);
		} else if (!ni_parse_uint(tmp.data[i], &num, 10) && num >= NI_WIRELESS_FREQUENCY_MIN) {
			if (ni_string_array_index(array, tmp.data[i]) == -1)
				ni_string_array_append(array, tmp.data[i]);
		} else {
			ni_string_array_append(errors, tmp.data[i]);
		}
	}

	ni_string_array_destroy(&tmp);

	return old_errors == errors->count;
}

ni_bool_t
ni_wireless_frequency_list_expand(ni_uint_array_t *expanded_freq, const ni_string_array_t *values,
		ni_string_array_t *errors)
{
	unsigned int i;
	ni_bool_t ret = TRUE;
	unsigned int tmp;

	if (!values || !errors)
		return FALSE;

	for (i = 0; i < values->count; i++) {
		if (ni_wireless_band2freq_list(expanded_freq, values->data[i])) {
			continue;
		} else if (!ni_parse_uint(values->data[i], &tmp, 10) &&
				tmp >= NI_WIRELESS_FREQUENCY_MIN) {
			if (ni_uint_array_index(expanded_freq, tmp) == -1U)
				ni_uint_array_append(expanded_freq, tmp);
		} else {
			ret = FALSE;
			ni_string_array_append(errors, values->data[i]);
		}
	}
	return ret;
}

static int
ni_wireless_scan_sync_bss(ni_wireless_scan_t *scan, const ni_wpa_bss_t *bss)
{
	int cnt = 0;
	ni_wireless_bss_t *wireless_bss;

	ni_timer_get_time(&scan->last_update);
	ni_wireless_bss_list_destroy(&scan->bsss);

	for(; bss; bss = bss->next){
		if (!(wireless_bss = ni_wireless_bss_new()))
			break;
		ni_wireless_bss_set(wireless_bss, bss);
		ni_wireless_scan_add_bss(scan, wireless_bss);
		cnt++;
	}
	return cnt;
}

static void
__ni_wireless_scan_timeout(void *ptr, const ni_timer_t *timer)
{
	ni_netdev_t *dev = ptr;
	ni_wireless_scan_t *scan;
	ni_wpa_nif_t *wif;

	if (!dev || !dev->wireless )
		return;

	scan = &dev->wireless->scan;
	if (scan->timer == timer)
		scan->timer = NULL;

	if (scan->interval == 0)
		return;

	/* If the device is down, we cannot scan */
	if (!ni_netdev_device_is_up(dev))
		return;

	if (!(wif = ni_wireless_get_wpa_interface(dev)))
		return;

	ni_wireless_trigger_scan(dev, wif, FALSE);
	__ni_wireless_scan_timer_arm(scan, dev, scan->interval);
	ni_wpa_nif_drop(&wif);
}

static void
__ni_wireless_scan_timer_arm(ni_wireless_scan_t *scan, ni_netdev_t *dev, unsigned int timeout)
{
	timeout = 1000 * timeout;

	if (scan->timer == NULL) {
		scan->timer = ni_timer_register(timeout,
				__ni_wireless_scan_timeout,
				dev);
	} else {
		ni_timer_rearm(scan->timer, timeout);
	}
}

static ni_bool_t
ni_wireless_wpa_net_format_bitmap(ni_wpa_net_properties_t *properties, unsigned int value, const ni_intmap_t *map, ni_wpa_net_property_type_t net_prop)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	const char *name, *str_value;
	ni_bool_t ret;

	if (value == 0)
		return TRUE;

	name = ni_wpa_net_property_name(net_prop);
	str_value = ni_format_bitmap_string(&buf, map, value, NULL, " ");

	ret = name && value && ni_dbus_dict_add_string(properties, name, str_value);

	ni_stringbuf_destroy(&buf);
	return ret;
}

static ni_bool_t
ni_wireless_wpa_net_format_wep(ni_wpa_net_properties_t *properties, const ni_wireless_network_t *net)
{
	size_t len, i;
	char *key;
	unsigned char key_data[NI_WIRELESS_WEP_KEY_LEN_104];
	const char *name;

	if (net->auth_algo == NI_WIRELESS_AUTH_ALGO_NONE)
		return TRUE;

	if (!ni_wireless_wpa_net_format_bitmap(properties, net->auth_algo,
			ni_wireless_wpa_auth_algo_map, NI_WPA_NET_PROPERTY_AUTH_ALG))
		return FALSE;

	name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_WEP_TX_KEYIDX);
	if (!name || !ni_dbus_dict_add_int32(properties, name, net->default_key))
		return FALSE;

	for(i = 0; i < NI_WIRELESS_WEP_KEY_COUNT; i++){
		key = net->wep_keys[i];
		len = ni_string_len(key);

		if (len == 0)
			continue;

		switch(i){
		default:
			name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_WEP_KEY0);
			break;
		case 1:
			name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_WEP_KEY1);
			break;
		case 2:
			name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_WEP_KEY2);
			break;
		case 3:
			name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_WEP_KEY3);
			break;
		}

		switch(len){
		case NI_WIRELESS_WEP_KEY_LEN_40:
		case NI_WIRELESS_WEP_KEY_LEN_104:
			if (!ni_dbus_dict_add_string(properties, name, key))
				return FALSE;
			break;

		case NI_WIRELESS_WEP_KEY_LEN_40_HEX:
		case NI_WIRELESS_WEP_KEY_LEN_104_HEX:
			if ((len = ni_parse_hex_data(key, key_data, sizeof(key_data), NULL)))
				if (!ni_dbus_dict_add_byte_array(properties, name, key_data, len))
					return FALSE;
			break;
		default:
			ni_warn("Unknown WEP key format len=%zu", len);
		}
	}
	return TRUE;
}

static ni_bool_t
ni_wireless_net_format_blob(ni_wpa_net_properties_t *properties, const ni_wireless_network_t *net,
		const ni_wireless_blob_t *blob, ni_wpa_net_property_type_t type)
{
	const char *name;
	ni_stringbuf_t sb = NI_STRINGBUF_INIT_DYNAMIC;

	if (!blob)
		return TRUE;

	if (!(name = ni_wpa_net_property_name(type)))
		return FALSE;

	if (blob->is_string){
		if (!ni_dbus_dict_add_string(properties, name, blob->str))
			return FALSE;

	} else {
		ni_stringbuf_printf(&sb, "blob://net_%d_%s", net->index, name);
		if (!ni_dbus_dict_add_string(properties, name, sb.string)) {
			ni_stringbuf_destroy(&sb);
			return FALSE;
		}
		ni_stringbuf_destroy(&sb);
	}

	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_net_format_psk(ni_wpa_net_properties_t *properties, const ni_wireless_network_t *net)
{
	const char *name;
	unsigned char data[32];

	if (ni_string_empty(net->wpa_psk.passphrase))
		return TRUE;

	if (!(name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_PSK)))
		return FALSE;

	if (ni_string_len(net->wpa_psk.passphrase) == 64){
		if(ni_parse_hex_data(net->wpa_psk.passphrase, data, sizeof(data), NULL) != sizeof(data)){
			ni_error("Failed to parse wpa_psk");
			return FALSE;
		}
		if (!ni_dbus_dict_add_byte_array(properties, name, data, sizeof(data)))
			return FALSE;

	} else {
		if (!ni_dbus_dict_add_string(properties, name, net->wpa_psk.passphrase))
			return FALSE;
	}

	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_net_format_eap(ni_wpa_net_properties_t *properties, const ni_wireless_network_t *net)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	const char *name, *value;

	if (!net->wpa_eap.method)
		return TRUE;

	name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_EAP);
	value = ni_wireless_wpa_eap_method(net->wpa_eap.method);
	if (!name || !value || !ni_dbus_dict_add_string(properties, name, value))
		goto error;

	if (net->wpa_eap.identity){
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_IDENTITY);
		if (!name || !ni_dbus_dict_add_string(properties, name, net->wpa_eap.identity))
			goto error;
	}

	if (net->wpa_eap.anonid){
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_ANONYMOUS_IDENTITY);
		if (!name || !ni_dbus_dict_add_string(properties, name, net->wpa_eap.anonid))
			goto error;
	}

	if (net->wpa_eap.phase1.peapver < INT_MAX){
		ni_stringbuf_truncate(&buf, 0);
		ni_stringbuf_printf(&buf, "peapver=%d", net->wpa_eap.phase1.peapver);
		if (net->wpa_eap.phase1.peaplabel)
			ni_stringbuf_printf(&buf, " peaplabel=1");
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_PHASE1);
		if (!name || !ni_dbus_dict_add_string(properties, name, buf.string))
			goto error;
	}

	if (net->wpa_eap.phase2.method != NI_WIRELESS_EAP_NONE){
		value = ni_wireless_wpa_eap_method(net->wpa_eap.phase2.method);
		if (!value) goto error;
		ni_stringbuf_truncate(&buf, 0);
		ni_stringbuf_printf(&buf, "auth=%s", value);
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_PHASE2);
		if (!name || !ni_dbus_dict_add_string(properties, name, buf.string))
			goto error;

		if (net->wpa_eap.phase2.password){
			name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_PASSWORD);
			if (!name || !ni_dbus_dict_add_string(properties, name, net->wpa_eap.phase2.password))
				goto error;
		}
	}

	if (!ni_wireless_net_format_blob(properties, net, net->wpa_eap.tls.ca_cert, NI_WPA_NET_PROPERTY_CA_CERT))
		goto error;
	if (!ni_wireless_net_format_blob(properties, net, net->wpa_eap.tls.client_cert, NI_WPA_NET_PROPERTY_CLIENT_CERT))
		goto error;
	if (!ni_wireless_net_format_blob(properties, net, net->wpa_eap.tls.client_key, NI_WPA_NET_PROPERTY_PRIVATE_KEY))
		goto error;

	if (net->wpa_eap.tls.client_key_passwd) {
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_PRIVATE_KEY_PASSWD);
		if (!name || !ni_dbus_dict_add_string(properties, name, net->wpa_eap.tls.client_key_passwd))
			goto error;
	}

	return TRUE;

error:
	ni_stringbuf_destroy(&buf);
	ni_error("Failed to format EAP configuration.");
	return FALSE;
}

static ni_bool_t
ni_wireless_wpa_map_wireless_mode(ni_wireless_mode_t m, int *ret)
{
	switch(m) {
	case NI_WIRELESS_MODE_MANAGED:
		*ret = 0;
		break;
	case NI_WIRELESS_MODE_ADHOC:
		*ret = 1;
		break;
	case NI_WIRELESS_MODE_MASTER:
		*ret = 2;
		break;
	default:
		return FALSE;
	};

	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_map_pmf(ni_wireless_pmf_t p, int *ret)
{
	switch(p) {
	case NI_WIRELESS_PMF_DISABLED:
		*ret = 0;
		break;
	case NI_WIRELESS_PMF_OPTIONAL:
		*ret = 1;
		break;
	case NI_WIRELESS_PMF_REQUIRED:
		*ret = 2;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_net_format_freq_list(ni_wpa_net_properties_t *properties, const ni_string_array_t *freq_list)
{
	ni_stringbuf_t sb = NI_STRINGBUF_INIT_DYNAMIC;
	ni_string_array_t errors = NI_STRING_ARRAY_INIT;
	ni_uint_array_t frequencies = NI_UINT_ARRAY_INIT;
	ni_bool_t ret = FALSE;
	const char *name;

	if (!properties || !freq_list)
		return FALSE;

	if (freq_list->count == 0)
		return TRUE;

	if (!ni_wireless_frequency_list_expand(&frequencies, freq_list, &errors)) {
		ni_error("Invalid frequency-list: '%s'", ni_stringbuf_join(&sb, &errors, " "));
		goto out;
	}

	if (!(name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_FREQ_LIST)))
		goto out;

	if (!ni_dbus_dict_add_string(properties, name, ni_stringbuf_join_uint(&sb, &frequencies, " ")))
		goto out;

	ret = TRUE;

out:
	ni_stringbuf_destroy(&sb);
	ni_string_array_destroy(&errors);
	ni_uint_array_destroy(&frequencies);

	return ret;
}

static ni_bool_t
ni_wireless_wpa_net_format(ni_wpa_net_properties_t *properties, const ni_wireless_network_t *net)
{
	const char *name;
        int ival;

	if (!properties || !net)
		return FALSE;

	/* SSID is mandatory */
	if (net->essid.len == 0)
		return FALSE;

	name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_SSID);
	if (!name || !ni_dbus_dict_add_byte_array(properties, name, net->essid.data, net->essid.len))
		return FALSE;

	if (net->priority && net->priority < INT_MAX) {
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_PRIORITY);
		if (!name || !ni_dbus_dict_add_int32(properties, name, net->priority))
			return FALSE;
	}

	if (net->scan_ssid){
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_SCAN_SSID);
		if (!name || !ni_dbus_dict_add_int32(properties, name, net->scan_ssid))
			return FALSE;
	}

	if (net->access_point.len){
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_BSSID);
		if (!name || !ni_dbus_dict_add_string(properties, name,	ni_link_address_print(&net->access_point)))
			return FALSE;
	}

	if (ni_wireless_wpa_map_wireless_mode(net->mode, &ival)){
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_MODE);
		if (!name || !ni_dbus_dict_add_int32(properties, name, ival))
			return FALSE;
	} else {
		/* other modes not supported by wpa_supplicant */
		return FALSE;
	}

	/* XXX skip net->channel for now, as it is only used by infrastructure mode */

	if (!ni_wireless_wpa_net_format_freq_list(properties, &net->frequency_list))
		return FALSE;

	if (net->fragment_size > 0){
		name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_FRAGMENT_SIZE);
		if (!name || !ni_dbus_dict_add_int32(properties, name, net->fragment_size))
			return FALSE;
	}

	if (!ni_wireless_wpa_net_format_wep(properties, net))
		return FALSE;

	if (!ni_wireless_wpa_net_format_bitmap(properties, net->auth_proto,
			ni_wireless_wpa_protocol_map, NI_WPA_NET_PROPERTY_PROTO))
		return FALSE;

	if (!ni_wireless_wpa_net_format_bitmap(properties, net->keymgmt_proto,
			ni_wireless_wpa_key_mgmt_map, NI_WPA_NET_PROPERTY_KEY_MGMT))
		return FALSE;

	if (!ni_wireless_wpa_net_format_bitmap(properties, net->pairwise_cipher,
			ni_wireless_wpa_pairwise_map, NI_WPA_NET_PROPERTY_PAIRWISE))
		return FALSE;

	if (!ni_wireless_wpa_net_format_bitmap(properties, net->group_cipher,
			ni_wireless_wpa_pairwise_map, NI_WPA_NET_PROPERTY_GROUP))
		return FALSE;

	if (net->pmf != NI_WIRELESS_PMF_NOT_SPECIFIED) {
		if (ni_wireless_wpa_map_pmf(net->pmf, &ival)) {
			name = ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_IEEE80211W);
			if (!name || !ni_dbus_dict_add_int32(properties, name, ival))
				return FALSE;
		} else {
			return FALSE;
		}
	}

	if (!ni_wireless_wpa_net_format_psk(properties, net))
		return FALSE;

	if (!ni_wireless_wpa_net_format_eap(properties, net))
		return FALSE;

	return !ni_dbus_dict_is_empty(properties);
}

static ni_bool_t
ni_wireless_wpa_set_blob(ni_wpa_nif_t *wif, const ni_wireless_network_t *net,
		const ni_wireless_blob_t *blob, ni_wpa_net_property_type_t type)
{
	const char *name;
	int rv;
	ni_stringbuf_t sb = NI_STRINGBUF_INIT_DYNAMIC;

	if (!blob || blob->is_string)
		return TRUE;

	if (!(name = ni_wpa_net_property_name(type)))
		return FALSE;

	if (ni_stringbuf_printf(&sb, "net_%d_%s", net->index, name) < 0)
		goto error;

	rv = ni_wpa_nif_add_blob(wif, sb.string, blob->byte_array.data, blob->byte_array.len);
	if (rv == -NI_ERROR_ENTRY_EXISTS){
		/* remove it first and try again */
		if (ni_wpa_nif_remove_blob(wif, sb.string) ||
		    ni_wpa_nif_add_blob(wif, sb.string, blob->byte_array.data, blob->byte_array.len))
			goto error;
	}

	ni_stringbuf_destroy(&sb);
	return TRUE;

error:
	ni_stringbuf_destroy(&sb);
	return FALSE;
}

static ni_bool_t
ni_wireless_wpa_set_blobs(ni_wpa_nif_t *wif, const ni_wireless_network_t *net)
{
	if (!ni_wireless_wpa_set_blob(wif, net, net->wpa_eap.tls.ca_cert, NI_WPA_NET_PROPERTY_CA_CERT))
		return FALSE;
	if (!ni_wireless_wpa_set_blob(wif, net, net->wpa_eap.tls.client_cert, NI_WPA_NET_PROPERTY_CLIENT_CERT))
		return FALSE;
	if (!ni_wireless_wpa_set_blob(wif, net, net->wpa_eap.tls.client_key, NI_WPA_NET_PROPERTY_PRIVATE_KEY))
		return FALSE;
	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_nif_config_differs(ni_wpa_nif_t *wif, const ni_wireless_config_t *conf)
{
	ni_string_array_t drvs = NI_STRING_ARRAY_INIT;

	if (!ni_string_empty(conf->driver) && !ni_string_empty(wif->properties.driver) &&
	    ni_string_split(&drvs, conf->driver, ",", 0) &&
	    ni_string_array_index(&drvs, wif->properties.driver) == -1) {
		ni_string_array_destroy(&drvs);
		ni_debug_wpa("%s: wpa driver '%s' not in configured driver list '%s'",
				wif->device.name, wif->properties.driver, conf->driver);
		return TRUE;
	}
	ni_string_array_destroy(&drvs);

	return FALSE; /* No difference detected, we can use it */
}

static ni_bool_t
ni_wireless_update_wpa_nif_capability_mask(const char *ifname, ni_wpa_nif_capability_type_t type,
					const ni_intmap_t *map, unsigned int *mask,
					const ni_string_array_t *names)
{
	const char * name;
	unsigned int flag;
	unsigned int i;

	if (!map || !mask || !names)
		return FALSE;

	*mask = 0;
	for (i = 0; i < names->count; ++i) {
		name = names->data[i];
		if (ni_parse_uint_mapped(name, map, &flag) < 0)
			ni_debug_wpa("%s: unable to translate %s capability %s",
					ifname, ni_wpa_nif_capability_name(type), name);
		else if (flag < 8 * sizeof(*mask))
			*mask |= NI_BIT(flag);
	}
	return TRUE;
}

static int
ni_wireless_update_wpa_nif_capabilities(ni_netdev_t *dev, const ni_wpa_nif_capabilities_t *capabilities)
{
	ni_wireless_t *wlan;

	if (!dev || !(wlan = ni_netdev_get_wireless(dev)) || !capabilities)
		return FALSE;

	ni_wireless_update_wpa_nif_capability_mask(dev->name,
			NI_WPA_NIF_CAPABILITY_PAIRWISE,		ni_wireless_wpa_pairwise_map,
			&wlan->capabilities.pairwise_ciphers,	&capabilities->pairwise);

	ni_wireless_update_wpa_nif_capability_mask(dev->name,
			NI_WPA_NIF_CAPABILITY_GROUP,		ni_wireless_wpa_group_map,
			&wlan->capabilities.group_ciphers,	&capabilities->group);

	ni_wireless_update_wpa_nif_capability_mask(dev->name,
			NI_WPA_NIF_CAPABILITY_GROUP_MGMT,	ni_wireless_wpa_group_mgmt_map,
			&wlan->capabilities.group_mgmt_ciphers,	&capabilities->group_mgmt);

	ni_wireless_update_wpa_nif_capability_mask(dev->name,
			NI_WPA_NIF_CAPABILITY_KEY_MGMT,		ni_wireless_wpa_key_mgmt_map,
			&wlan->capabilities.keymgmt_algos,	&capabilities->key_mgmt);

	ni_wireless_update_wpa_nif_capability_mask(dev->name,
			NI_WPA_NIF_CAPABILITY_PROTOCOL,		ni_wireless_wpa_protocol_map,
			&wlan->capabilities.wpa_protocols,	&capabilities->protocol);

	ni_wireless_update_wpa_nif_capability_mask(dev->name,
			NI_WPA_NIF_CAPABILITY_AUTH_ALG,		ni_wireless_wpa_auth_algo_map,
			&wlan->capabilities.auth_algos,		&capabilities->auth_alg);

	ni_wireless_update_wpa_nif_capability_mask(dev->name,
			NI_WPA_NIF_CAPABILITY_SCAN,		ni_wireless_wpa_scan_mode_caps_map,
			&wlan->capabilities.scan_modes,		&capabilities->scan);

	ni_wireless_update_wpa_nif_capability_mask(dev->name,
			NI_WPA_NIF_CAPABILITY_MODES,		ni_wireless_wpa_oper_mode_caps_map,
			&wlan->capabilities.oper_modes,		&capabilities->modes);

	wlan->capabilities.max_scan_ssid = capabilities->max_scan_ssid;

	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_complete_network(ni_netdev_t *dev, ni_wireless_network_t *net)
{
	ni_wireless_t *wlan;
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC,
		       buf2 = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int wpa3_like_key_mgmt =
		(NI_WIRELESS_KEY_MGMT_DEFAULT_PSK | NI_WIRELESS_KEY_MGMT_DEFAULT_EAP | NI_WIRELESS_KEY_MGMT_DEFAULT_OPEN)
		& ~(NI_BIT(NI_WIRELESS_KEY_MGMT_PSK) | NI_BIT(NI_WIRELESS_KEY_MGMT_EAP) | NI_BIT(NI_WIRELESS_KEY_MGMT_NONE));
	unsigned int require_pmf_key_mgmt =
		NI_BIT(NI_WIRELESS_KEY_MGMT_SAE) | NI_BIT(NI_WIRELESS_KEY_MGMT_EAP_SUITE_B) |
		NI_BIT(NI_WIRELESS_KEY_MGMT_EAP_SUITE_B_192) |
		NI_BIT(NI_WIRELESS_KEY_MGMT_OWE);
	unsigned int ft_key_mgmt =
		NI_BIT(NI_WIRELESS_KEY_MGMT_FT_EAP) | NI_BIT(NI_WIRELESS_KEY_MGMT_FT_EAP_SHA384) |
		NI_BIT(NI_WIRELESS_KEY_MGMT_FT_FILS_SHA256) | NI_BIT(NI_WIRELESS_KEY_MGMT_FT_FILS_SHA384) |
		NI_BIT(NI_WIRELESS_KEY_MGMT_FT_PSK) | NI_BIT(NI_WIRELESS_KEY_MGMT_FT_SAE);

	if (!(wlan = ni_netdev_get_wireless(dev)))
		return FALSE;

	if (net->keymgmt_proto == 0) {
		if (!ni_string_empty(net->wpa_psk.passphrase))
			net->keymgmt_proto = wlan->capabilities.keymgmt_algos & NI_WIRELESS_KEY_MGMT_DEFAULT_PSK;

		if (net->wpa_eap.method)
			net->keymgmt_proto = wlan->capabilities.keymgmt_algos & NI_WIRELESS_KEY_MGMT_DEFAULT_EAP;

		/* if the interface do not support PMF, skip key-mgmt which requires it. */
		if (wlan->capabilities.group_mgmt_ciphers == 0)
			net->keymgmt_proto &= ~(require_pmf_key_mgmt);

		if (!ni_wpa_client_has_capability(NULL, "ft"))
			net->keymgmt_proto &= ~(ft_key_mgmt);

		if (net->keymgmt_proto == 0)
			net->keymgmt_proto = wlan->capabilities.keymgmt_algos & NI_WIRELESS_KEY_MGMT_DEFAULT_OPEN;

		ni_debug_wireless("%s: set key-management for '%s' to %s", dev->name,
				ni_wireless_ssid_print(&net->essid, &buf2),
				ni_format_bitmap(&buf, ni_wireless_key_management_map(),
					net->keymgmt_proto, ", "));
		ni_stringbuf_destroy(&buf);
		ni_stringbuf_destroy(&buf2);
	}

	if (net->pmf == NI_WIRELESS_PMF_NOT_SPECIFIED &&
	    (net->keymgmt_proto & wpa3_like_key_mgmt) &&
	    wlan->capabilities.group_mgmt_ciphers != 0 ) {
		net->pmf = NI_WIRELESS_PMF_OPTIONAL;
		ni_debug_wireless("%s: set pmf for '%s' to %s", dev->name,
				ni_wireless_ssid_print(&net->essid, &buf),
				ni_wireless_pmf_to_name(net->pmf));
		ni_stringbuf_destroy(&buf);
	}

	return TRUE;
}

static ni_bool_t
ni_wireless_wpa_complete_networks(ni_netdev_t *dev, ni_wireless_network_array_t *networks)
{
	unsigned int i;

	for (i = 0; i < networks->count; ++i)
		if (!ni_wireless_wpa_complete_network(dev, networks->data[i]))
			return FALSE;
	return TRUE;
}

static int
ni_wireless_setup_networks(ni_netdev_t *dev, ni_wpa_nif_t *wif, const ni_wireless_network_array_t *networks)
{
	ni_wpa_net_properties_t properties = NI_DBUS_VARIANT_INIT;
	const ni_wireless_network_t *network;
	unsigned int i;

	/*
	 * TODO: make something more useful here like compare
	 * and update existing (if needed), add new and delete
	 * networks that aren't in the config.
	 * For now: delete everything + add requested.
	 */
	if (ni_wpa_nif_del_all_networks(wif) != NI_SUCCESS)
		return NI_ERROR_GENERAL_FAILURE;

	for (i = 0; i < networks->count; ++i) {
		if (!(network = networks->data[i]))
			continue;

		ni_wireless_wpa_set_blobs(wif, network);

		ni_dbus_variant_init_dict(&properties);
		if (!ni_wireless_wpa_net_format(&properties, network)){
			ni_error("Failed to format wireless network config '%.*s'",
					network->essid.len, network->essid.data);
			continue;
		}

		ni_wpa_nif_add_network(wif, &properties, NULL);
		ni_dbus_variant_destroy(&properties);
	}

	return 0;
}

static int
ni_wireless_trigger_scan(ni_netdev_t *dev, ni_wpa_nif_t *wif, ni_bool_t active_scan)
{
	ni_wireless_t *wlan = dev->wireless;

	if (!wif->properties.scanning){
		ni_wpa_nif_flush_bss(wif, wlan->scan.max_age);
		ni_timer_get_time(&wlan->scan.last_trigger);
		return ni_wpa_nif_trigger_scan(wif, active_scan);
	}
	return -NI_ERROR_RETRY_OPERATION;
}

static void
ni_wireless_on_wpa_supplicant_start(ni_netdev_t *dev)
{
	ni_wireless_t *wlan = ni_netdev_get_wireless(dev);
	int ret;

	if (!wlan || !wlan->conf)
		return;

	ni_debug_wireless("%s: On wpa_supplicant start - try to reconfigure!", dev->name);
	if ((ret = ni_wireless_setup(dev, wlan->conf)) == 0) {
		ni_debug_wireless("%s: Setup of wireless successful after wpa_supplicant start", dev->name);
		if (wlan->reconnect)
			if ((ret = ni_wireless_connect(dev)))
				ni_error("%s: wireless connect failed with %d", dev->name, ret);
	} else
		ni_error("%s: Setup of wireless failed with %d after wpa_supplicant restart!", dev->name, ret);
}

static void
ni_wireless_on_wpa_supplicant_stop(ni_netdev_t *dev)
{
	ni_note("%s: wpa_supplicant stopped!", dev->name);
	ni_wireless_set_state(dev, NI_WIRELESS_NOT_ASSOCIATED);
}

int
ni_wireless_setup(ni_netdev_t *dev, ni_wireless_config_t *conf)
{
	ni_wpa_nif_t *wif = NULL;
	ni_wpa_client_t *wpa;
	const char * name;
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT, *var, *data;
	ni_wireless_t *wlan;
	int ret;

	ni_wpa_client_ops_t ops = {
		.on_wpa_supplicant_start = ni_wireless_on_wpa_supplicant_start,
		.on_wpa_supplicant_stop = ni_wireless_on_wpa_supplicant_stop
	};
	ni_wpa_nif_ops_t wif_ops = {
		.on_network_added = ni_wireless_on_network_added,
		.on_scan_done = ni_wireless_on_scan_done,
		.on_state_change = ni_wireless_on_state_change,
		.on_properties_changed = ni_wireless_on_properties_changed,
	};

	if (!dev || !conf || !(wlan = ni_netdev_get_wireless(dev)))
		return -NI_ERROR_INVALID_ARGS;

	if (ni_rfkill_disabled(NI_RFKILL_TYPE_WIRELESS))
		return -NI_ERROR_RADIO_DISABLED;

	if (!(wpa = ni_wpa_client()))
		return -1;

	if (!ni_wpa_client_set_ops(dev->link.ifindex, &ops))
		ni_warn("%s: Failed to add wpa_client opthandler", dev->name);

	ret = ni_wpa_get_interface(wpa, dev->name, dev->link.ifindex, &wif);
	if (ret == 0 && wif && ni_wireless_wpa_nif_config_differs(wif, conf)) {
		ret = ni_wpa_del_interface(wif->client, ni_dbus_object_get_path(wif->object));
		ni_wpa_nif_drop(&wif);
		if (ret == 0)
			ret = -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	if (ret < 0) {
		if (ret != -NI_ERROR_DEVICE_NOT_KNOWN)
			goto out;
		ni_dbus_variant_init_dict(&arg);

		name = ni_wpa_nif_property_name(NI_WPA_NIF_PROPERTY_IFNAME);
		ni_dbus_dict_add_string(&arg, name, dev->name);

		name = ni_wpa_nif_property_name(NI_WPA_NIF_PROPERTY_DRIVER);
		ni_dbus_dict_add_string(&arg, name, conf->driver ?: NI_WIRELESS_WPA_DRIVER_DEFAULT);

		ret = ni_wpa_add_interface(wpa, dev->link.ifindex, &arg, &wif);
		ni_dbus_variant_destroy(&arg);
		if (ret < 0)
			goto out;
	}

	ni_wpa_nif_set_ops(wif, &wif_ops);

	ni_dbus_variant_init_dict(&arg);

	if (conf->country && !ni_string_eq(wif->properties.country, conf->country)) {
		name = ni_wpa_nif_property_name(NI_WPA_NIF_PROPERTY_COUNTRY);
		var = ni_dbus_dict_add(&arg, name);
		data = ni_dbus_variant_init_variant(var);
		ni_dbus_variant_set_string(data, conf->country);
	}

	if (conf->ap_scan != wif->properties.ap_scan) {
		name = ni_wpa_nif_property_name(NI_WPA_NIF_PROPERTY_AP_SCAN);
		var = ni_dbus_dict_add(&arg, name);
		data = ni_dbus_variant_init_variant(var);
		ni_dbus_variant_set_uint32(data, conf->ap_scan);
	}

	ret = ni_wpa_nif_set_properties(wif, &arg);
	ni_dbus_variant_destroy(&arg);
	if (ret < 0)
		goto out;

	if ((ret = ni_wireless_update_wpa_nif_capabilities(dev, &wif->capabilities)) < 0)
		goto out;

	if (!ni_wireless_wpa_complete_networks(dev, &conf->networks)) {
		ret = -1;
		goto out;
	}

	if ((ret = ni_wireless_setup_networks(dev, wif, &conf->networks)) != 0)
		goto out;

	/* setup successfull, store configuration for expected wpa_supplicant restarts */
	if (!wlan->conf)
		wlan->conf = ni_wireless_config_new();
	if (!ni_wireless_config_copy(wlan->conf, conf)) {
		ni_error("%s: copy current config failed", dev->name);
		ni_wireless_config_free(&wlan->conf);
	}

	if (wlan->scan.interval > 0)
		__ni_wireless_scan_timer_arm(&wlan->scan, dev, 1);
out:
	ni_wpa_nif_drop(&wif);
	return ret;
}

int
ni_wireless_shutdown(ni_netdev_t *dev)
{
	ni_wpa_nif_t *wif;
	int ret;

	if (!(wif = ni_wireless_get_wpa_interface(dev)))
		return NI_SUCCESS;

	ni_wpa_client_del_ops(dev->link.ifindex);
	ret = ni_wpa_del_interface(wif->client, ni_dbus_object_get_path(wif->object));
	ni_wpa_nif_drop(&wif);
	return ret;
}

int
ni_wireless_connect(ni_netdev_t *dev)
{
	ni_wpa_nif_t *wif = NULL;
	ni_wireless_t *wlan;
	int ret;

	ni_debug_wireless("%s(%s)", __func__, dev->name);
	if (!(wlan = dev->wireless))
		return -NI_ERROR_INVALID_ARGS;

	if (!(wif = ni_wireless_get_wpa_interface(dev))) {
		ni_warn("Wireless connect failed - unknown interface %s(%d)",
				dev->name, dev->link.ifindex);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	if (ni_rfkill_disabled(NI_RFKILL_TYPE_WIRELESS)) {
		ni_wpa_nif_drop(&wif);
		return -NI_ERROR_RADIO_DISABLED;
	}

	if (!(ret = ni_wpa_nif_set_all_networks_property_enabled(wif, TRUE)))
		wlan->reconnect = TRUE;

	ni_wpa_nif_drop(&wif);
	return ret;
}

/*
 * Disconnect
 */
int
ni_wireless_disconnect(ni_netdev_t *dev)
{
	ni_wpa_nif_t *wif;
	ni_wireless_t *wlan;
	int ret;

	ni_debug_wireless("%s(%s)", __func__, dev->name);
	if (!(wlan = dev->wireless))
		return -NI_ERROR_INVALID_ARGS;
	wlan->reconnect = FALSE;

	if (!(wif = ni_wireless_get_wpa_interface(dev))) {
		ni_warn("Wireless disconnect failed - unknown interface %s(%d)",
				dev->name, dev->link.ifindex);
		return -NI_ERROR_DEVICE_NOT_KNOWN;
	}

	if (ni_rfkill_disabled(NI_RFKILL_TYPE_WIRELESS)) {
		ni_wpa_nif_drop(&wif);
		return -NI_ERROR_RADIO_DISABLED;
	}


	ret = ni_wpa_nif_set_all_networks_property_enabled(wif, FALSE);

	ni_wpa_nif_drop(&wif);
	return ret;
}

/*
 * Check whether we've lost our association with the AP
 */
static void
ni_wireless_set_association_timer(ni_wireless_t *wlan, const ni_timer_t *new_timer)
{
	if (wlan->assoc.timer != NULL)
		ni_timer_cancel(wlan->assoc.timer);
	wlan->assoc.timer = new_timer;
}

static void
__ni_wireless_association_timeout(void *ptr, const ni_timer_t *timer)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev = ptr;
	ni_wireless_t *wlan = dev->wireless;

	if (wlan->assoc.timer != timer)
		return;

	ni_debug_wireless("%s: association timed out", dev->name);
	wlan->assoc.timer = NULL;

	__ni_netdev_event(nc, dev, NI_EVENT_LINK_ASSOCIATION_LOST);
}

static void
ni_wireless_update_association_timer(ni_netdev_t *dev)
{
	ni_wireless_t *wlan = dev->wireless;

	if (wlan->assoc.state == NI_WIRELESS_ESTABLISHED) {
		ni_wireless_set_association_timer(wlan, NULL);
	} else {
		const ni_timer_t *new_timer;
		unsigned int timeout;

		if (wlan->assoc.timer != NULL)
			return;

		if ((timeout = wlan->assoc.fail_delay) == 0)
			timeout = NI_WIRELESS_ASSOC_FAIL_DELAY;
		new_timer = ni_timer_register(1000 * timeout,
				__ni_wireless_association_timeout,
				dev);
		ni_wireless_set_association_timer(wlan, new_timer);
	}
}

static ni_wireless_assoc_state_t
ni_wpa_nif_state_to_wireless_state(ni_wpa_nif_state_t state)
{
	switch (state) {
	case NI_WPA_NIF_STATE_INACTIVE:
	case NI_WPA_NIF_STATE_SCANNING:
	case NI_WPA_NIF_STATE_DISCONNECTED:
	default:
		return NI_WIRELESS_NOT_ASSOCIATED;

	case NI_WPA_NIF_STATE_ASSOCIATING:
		return NI_WIRELESS_ASSOCIATING;

	case NI_WPA_NIF_STATE_ASSOCIATED:
	case NI_WPA_NIF_STATE_AUTHENTICATING:
	case NI_WPA_NIF_STATE_4WAY_HANDSHAKE:
	case NI_WPA_NIF_STATE_GROUP_HANDSHAKE:
		return NI_WIRELESS_AUTHENTICATING;

	case NI_WPA_NIF_STATE_COMPLETED:
		return NI_WIRELESS_ESTABLISHED;
	}
}

static void
ni_wireless_sync_assoc_with_current_bss(ni_wireless_t *wlan, ni_wpa_nif_t *wif)
{
	ni_wpa_bss_t *bss;

	if (wlan->assoc.state == NI_WIRELESS_ESTABLISHED && (bss = ni_wpa_nif_get_current_bss(wif)) ){
		ni_link_address_set(&wlan->assoc.bssid, ARPHRD_ETHER, bss->properties.bssid.data, bss->properties.bssid.len);

		wlan->assoc.ssid.len = 0;
		if (bss->properties.ssid.len <= NI_WIRELESS_ESSID_MAX_LEN){
			wlan->assoc.ssid.len = bss->properties.ssid.len;
			memcpy(wlan->assoc.ssid.data, bss->properties.ssid.data, bss->properties.ssid.len);
		}

		wlan->assoc.signal = bss->properties.signal;
		wlan->assoc.frequency = bss->properties.frequency;
		ni_wpa_bss_drop(&bss);

	} else {
		ni_link_address_init(&wlan->assoc.bssid);
		wlan->assoc.signal = 0;
		wlan->assoc.frequency = 0;
		wlan->assoc.ssid.len = 0;
		ni_string_free(&wlan->assoc.auth_mode);
	}
}

static void
ni_wireless_set_state(ni_netdev_t *dev, ni_wireless_assoc_state_t new_state)
{
	ni_wireless_t *wlan;
	ni_wpa_nif_t *wif = NULL;

	if (!(wlan = dev->wireless)) {
		ni_warn("On state change received on %s but is't not wireless", dev->name);
		return;
	}

	if (new_state == wlan->assoc.state)
		return;

	wlan->assoc.state = new_state;

	if (new_state == NI_WIRELESS_ESTABLISHED){
		wif = ni_wireless_get_wpa_interface(dev);
		ni_timer_get_time(&wlan->assoc.established_time);
		__ni_netdev_event(NULL, dev, NI_EVENT_LINK_ASSOCIATED);
	}
	ni_wireless_sync_assoc_with_current_bss(wlan, wif);
	ni_wpa_nif_drop(&wif);

	/* We keep track of when we were last changing to or
	 * from fully authenticated state.
	 * We use this to decide when to give up and announce
	 * that we've lost the network - see the timer handling
	 * code above.
	 */
	ni_wireless_update_association_timer(dev);
}

/*
 * Callback from wpa_supplicant client whenever the association state changes
 * in a significant way.
 */
static void
ni_wireless_on_state_change(ni_wpa_nif_t *wif, ni_wpa_nif_state_t old_state, ni_wpa_nif_state_t new_state)
{
	ni_netdev_t *dev;

	if (!(dev = ni_wireless_unwrap_wpa_nif(wif))){
		ni_error("%s -- Unable to unwrap wpa_nif_t", __func__);
		return;
	}
	ni_wireless_set_state(dev, ni_wpa_nif_state_to_wireless_state(new_state));
}

static void
ni_wireless_on_properties_changed(ni_wpa_nif_t *wif, ni_dbus_variant_t *props)
{
	ni_wireless_t *wlan;
	ni_netdev_t *dev;
	const char *tmp;

	if (!(dev = ni_wireless_unwrap_wpa_nif(wif))){
		ni_error("%s -- Unable to unwrap wpa_nif_t", __func__);
		return;
	}

	if (!(wlan = dev->wireless))
		return;

	if (ni_dbus_dict_get(props, ni_wpa_nif_property_name(NI_WPA_NIF_PROPERTY_CURRENT_BSS))){
		ni_wireless_sync_assoc_with_current_bss(wlan, wif);
	}

	if (ni_dbus_dict_get_string(props, ni_wpa_nif_property_name(NI_WPA_NIF_PROPERTY_CURRENT_AUTH_MODE), &tmp)) {
		if (ni_string_empty(tmp))
			ni_string_free(&wlan->assoc.auth_mode);
		else
			ni_string_dup(&wlan->assoc.auth_mode, tmp);
	}
}

/*
 * rtnetlink sent us an RTM_NEWLINK event with IFLA_WIRELESS info
 */
int
__ni_wireless_link_event(ni_netconfig_t *nc, ni_netdev_t *dev, void *data, size_t len)
{
	/* ni_debug_wireless("%s: ignoring wireless event", dev->name); */
	return 0;
}

static ni_intmap_t __ni_wireless_mode_names[] = {
	{ "unknown",		NI_WIRELESS_MODE_UNKNOWN },
	{ "auto",		NI_WIRELESS_MODE_AUTO },
	{ "ad-hoc", 		NI_WIRELESS_MODE_ADHOC },
	{ "adhoc", 		NI_WIRELESS_MODE_ADHOC },
	{ "infrastructure",	NI_WIRELESS_MODE_MANAGED },
	{ "managed",		NI_WIRELESS_MODE_MANAGED },
	{ "ap",			NI_WIRELESS_MODE_MASTER },
	{ "master",		NI_WIRELESS_MODE_MASTER },
	{ "repeater",		NI_WIRELESS_MODE_REPEATER },
	{ "secondary",		NI_WIRELESS_MODE_SECONDARY },
	{ "monitor",		NI_WIRELESS_MODE_MONITOR },
	{ "mesh",		NI_WIRELESS_MODE_MESH },
	{ "p2p",		NI_WIRELESS_MODE_P2P },
	{ NULL }
};

const char *
ni_wireless_mode_to_name(ni_wireless_mode_t mode)
{
	return ni_format_uint_mapped(mode, __ni_wireless_mode_names);
}

ni_bool_t
ni_wireless_name_to_mode(const char *string, unsigned int *value)
{
	if (ni_parse_uint_mapped(string, __ni_wireless_mode_names, value) < 0)
		return FALSE;
	return TRUE;
}

static const ni_intmap_t			ni_wireless_auth_proto_names[] = {
	{ "wpa",		NI_WIRELESS_AUTH_PROTO_WPA },
	{ "rsn",		NI_WIRELESS_AUTH_PROTO_RSN },
	{ "wpa1",		NI_WIRELESS_AUTH_PROTO_WPA },
	{ "wpa2",		NI_WIRELESS_AUTH_PROTO_RSN },
	{ NULL }
};

const ni_intmap_t *
ni_wireless_auth_proto_map(void)
{
	return ni_wireless_auth_proto_names;
}

const char *
ni_wireless_auth_proto_to_name(ni_wireless_auth_proto_t proto)
{
	return ni_format_uint_mapped(proto, ni_wireless_auth_proto_names);
}

ni_bool_t
ni_wireless_name_to_auth_proto(const char *string, ni_wireless_auth_proto_t *proto)
{
	if (ni_parse_uint_mapped(string, ni_wireless_auth_proto_names, proto) < 0)
		return FALSE;
	return TRUE;
}

static ni_intmap_t __ni_wireless_auth_algo_names[] = {
	{ "open",		NI_WIRELESS_AUTH_OPEN },
	{ "shared",		NI_WIRELESS_AUTH_SHARED },
	{ "leap",		NI_WIRELESS_AUTH_LEAP },
	{ NULL }
};

const ni_intmap_t *
ni_wireless_auth_algo_map(void)
{
	return __ni_wireless_auth_algo_names;
}

const char *
ni_wireless_auth_algo_to_name(ni_wireless_auth_algo_t algo)
{
	return ni_format_uint_mapped(algo, __ni_wireless_auth_algo_names);
}

ni_bool_t
ni_wireless_name_to_auth_algo(const char *string, unsigned int *value)
{
	if (ni_parse_uint_mapped(string, __ni_wireless_auth_algo_names, value) < 0)
		return FALSE;
	return TRUE;
}

static const ni_intmap_t			ni_wireless_cipher_names[] = {
	{ "none",				NI_WIRELESS_CIPHER_NONE					},
	{ "proprietary",			NI_WIRELESS_CIPHER_PROPRIETARY				},
	{ "wep40",				NI_WIRELESS_CIPHER_WEP40				},
	{ "wep104",				NI_WIRELESS_CIPHER_WEP104				},
	{ "wrap",				NI_WIRELESS_CIPHER_WRAP					},
	{ "tkip",				NI_WIRELESS_CIPHER_TKIP					},
	{ "ccmp",				NI_WIRELESS_CIPHER_CCMP					},
	{ "ccmp-256",				NI_WIRELESS_CIPHER_CCMP256				},
	{ "gcmp",				NI_WIRELESS_CIPHER_GCMP					},
	{ "gcmp-256",				NI_WIRELESS_CIPHER_GCMP256				},
	{ "aes-128-cmac",			NI_WIRELESS_CIPHER_AES128_CMAC				},
	{ "bip-gmac-128",			NI_WIRELESS_CIPHER_BIP_GMAC128				},
	{ "bip-gmac-256",			NI_WIRELESS_CIPHER_BIP_GMAC256				},
	{ "bip-cmac-256",			NI_WIRELESS_CIPHER_BIP_CMAC256				},
	{ NULL }
};

const char *
ni_wireless_cipher_to_name(ni_wireless_cipher_t mode)
{
	return ni_format_uint_mapped(mode, ni_wireless_cipher_names);
}

ni_bool_t
ni_wireless_name_to_cipher(const char *string, unsigned int *value)
{
	if (ni_parse_uint_mapped(string, ni_wireless_cipher_names, value) < 0)
		return FALSE;
	return TRUE;
}

const ni_intmap_t *
ni_wireless_pairwise_map(void)
{
	return ni_wireless_wpa_pairwise_map;
}

const ni_intmap_t *
ni_wireless_group_map(void)
{
	return ni_wireless_wpa_group_map;
}

static const ni_intmap_t ni_wireless_key_mgmt_map[] = {
	/* As required for networks and also used in capabilities.
	 * Used to parse from XML/ifcfg files into c-structures.                                       */
	{ "none",			NI_WIRELESS_KEY_MGMT_NONE },
	{ "proprietary",		NI_WIRELESS_KEY_MGMT_PROPRIETARY },
	{ "wpa-eap",			NI_WIRELESS_KEY_MGMT_EAP },
	{ "wpa-psk",			NI_WIRELESS_KEY_MGMT_PSK },
	{ "ieee802-1x",			NI_WIRELESS_KEY_MGMT_802_1X },
	{ "ft-psk",			NI_WIRELESS_KEY_MGMT_FT_PSK},
	{ "wpa-psk-sha256",		NI_WIRELESS_KEY_MGMT_PSK_SHA256},
	{ "wpa-eap-sha256",		NI_WIRELESS_KEY_MGMT_EAP_SHA256},
	{ "ft-eap",			NI_WIRELESS_KEY_MGMT_FT_EAP},
	{ "ft-eap-sha384",		NI_WIRELESS_KEY_MGMT_FT_EAP_SHA384},
	{ "wps",			NI_WIRELESS_KEY_MGMT_WPS},
	{ "sae",			NI_WIRELESS_KEY_MGMT_SAE},
	{ "ft-sae",			NI_WIRELESS_KEY_MGMT_FT_SAE},
	{ "wpa-eap-suite-b",		NI_WIRELESS_KEY_MGMT_EAP_SUITE_B},
	{ "wpa-eap-suite-b-192",	NI_WIRELESS_KEY_MGMT_EAP_SUITE_B_192},
	{ "osem",			NI_WIRELESS_KEY_MGMT_OSEM},
	{ "fils-sha256",		NI_WIRELESS_KEY_MGMT_FILS_SHA256},
	{ "fils-sha384",		NI_WIRELESS_KEY_MGMT_FILS_SHA384},
	{ "ft-fils-sha256",		NI_WIRELESS_KEY_MGMT_FT_FILS_SHA256},
	{ "ft-fils-sha384",		NI_WIRELESS_KEY_MGMT_FT_FILS_SHA384},
	{ "owe",			NI_WIRELESS_KEY_MGMT_OWE},
	{ "dpp",			NI_WIRELESS_KEY_MGMT_DPP},
	{ NULL }
};

const char *
ni_wireless_key_management_to_name(ni_wireless_key_mgmt_t mode)
{
	return ni_format_uint_mapped(mode, ni_wireless_key_management_map());
}

const ni_intmap_t *
ni_wireless_key_management_map(void)
{
	return ni_wireless_key_mgmt_map;
}

static ni_intmap_t __ni_wireless_eap_method_names[] = {
	{ "none",	NI_WIRELESS_EAP_NONE	},
	{ "md5",	NI_WIRELESS_EAP_MD5	},
	{ "tls",	NI_WIRELESS_EAP_TLS	},
	{ "pap",	NI_WIRELESS_EAP_PAP},
	{ "chap",	NI_WIRELESS_EAP_CHAP},
	{ "mschap",	NI_WIRELESS_EAP_MSCHAP},
	{ "mschapv2",	NI_WIRELESS_EAP_MSCHAPV2},
	{ "peap",	NI_WIRELESS_EAP_PEAP	},
	{ "ttls",	NI_WIRELESS_EAP_TTLS	},
	{ "gtc",	NI_WIRELESS_EAP_GTC	},
	{ "otp",	NI_WIRELESS_EAP_OTP	},
	{ "leap",	NI_WIRELESS_EAP_LEAP	},
	{ "psk",	NI_WIRELESS_EAP_PSK	},
	{ "pax",	NI_WIRELESS_EAP_PAX	},
	{ "sake",	NI_WIRELESS_EAP_SAKE	},
	{ "gpsk",	NI_WIRELESS_EAP_GPSK	},
	{ "wsc",	NI_WIRELESS_EAP_WSC	},
	{ "ikev2",	NI_WIRELESS_EAP_IKEV2	},
	{ "tnc",	NI_WIRELESS_EAP_TNC	},
	{ "fast",	NI_WIRELESS_EAP_FAST	},
	{ "aka",	NI_WIRELESS_EAP_AKA	},
	{ "aka_prime",	NI_WIRELESS_EAP_AKA_PRIME	},
	{ "sim",	NI_WIRELESS_EAP_SIM	},
	{ NULL }
};

const char *
ni_wireless_eap_method_to_name(ni_wireless_eap_method_t mode)
{
	return ni_format_uint_mapped(mode, __ni_wireless_eap_method_names);
}

ni_bool_t
ni_wireless_name_to_eap_method(const char *string, unsigned int *value)
{
	if (ni_parse_uint_mapped(string, __ni_wireless_eap_method_names, value) < 0)
		return FALSE;
	return TRUE;
}

const char *
ni_wireless_scan_mode_to_name(ni_wireless_scan_mode_t mode)
{
	/* we're using 1:1 wpa-supplicant scan mode capability map here */
	return ni_format_uint_mapped(mode, ni_wireless_wpa_scan_mode_caps_map);
}

static ni_intmap_t __ni_wireless_assoc_state_names[] = {
	{ "not-associated",	NI_WIRELESS_NOT_ASSOCIATED },
	{ "associating",	NI_WIRELESS_ASSOCIATING },
	{ "authenticating",	NI_WIRELESS_AUTHENTICATING },
	{ "established",	NI_WIRELESS_ESTABLISHED },
	{ NULL }
};

const char *
ni_wireless_assoc_state_to_name(ni_wireless_assoc_state_t state)
{
	return ni_format_uint_mapped(state, __ni_wireless_assoc_state_names);
}

static ni_intmap_t __ni_wireless_pmf_names[] = {
	{ "disabled",	NI_WIRELESS_PMF_DISABLED },
	{ "optional",	NI_WIRELESS_PMF_OPTIONAL },
	{ "required",	NI_WIRELESS_PMF_REQUIRED },
	{ NULL,			0}
};

extern const char *
ni_wireless_pmf_to_name(ni_wireless_pmf_t pmf)
{
	return ni_format_uint_mapped(pmf, __ni_wireless_pmf_names);
}

extern ni_bool_t
ni_wireless_name_to_pmf(const char *val, ni_wireless_pmf_t *out)
{
	return ni_parse_uint_mapped(val, __ni_wireless_pmf_names, out) == 0;
}

static const ni_intmap_t	ni_wireless_frequency_set_names[] = {
	{ "2.4GHz",		NI_WIRELESS_FREQUENCY_SET_2_4GHz	},
	{ "2,4GHz",		NI_WIRELESS_FREQUENCY_SET_2_4GHz	},
	{ "5GHz",		NI_WIRELESS_FREQUENCY_SET_5GHz		},
	{ "6GHz",		NI_WIRELESS_FREQUENCY_SET_6GHz		},

	{ NULL,			NI_WIRELESS_FREQUENCY_SET_NONE		}
};

const char *
ni_wireless_frequency_set_name(ni_wireless_frequency_set_t set)
{
	return ni_format_uint_mapped(set, ni_wireless_frequency_set_names);
}

ni_bool_t
ni_wireless_frequency_set_type(const char *name, ni_wireless_frequency_set_t *set)
{
	return ni_parse_uint_mapped(name, ni_wireless_frequency_set_names, set) == 0;
}

/*
 * Wireless interface config
 */
static inline void
ni_wireless_config_set_defaults(ni_wireless_config_t *conf)
{
	conf->ap_scan = NI_WIRELESS_AP_SCAN_SUPPLICANT_AUTO;
}


ni_wireless_config_t *
ni_wireless_config_new()
{
	ni_wireless_config_t *conf;

	if (!(conf = calloc(1, sizeof(ni_wireless_config_t)))) {
		ni_error_oom();
		return NULL;
	}
	ni_wireless_config_set_defaults(conf);
	return conf;
}

void
ni_wireless_config_free(ni_wireless_config_t **conf)
{
	if (!conf || !*conf)
		return;

	ni_wireless_config_destroy(*conf);
	free(*conf);
	*conf = NULL;
}

ni_bool_t
ni_wireless_config_init(ni_wireless_config_t *conf)
{
	if (conf) {
		memset(conf, 0, sizeof(*conf));
		ni_wireless_config_set_defaults(conf);
		return TRUE;
	}
	return FALSE;
}

void
ni_wireless_config_destroy(ni_wireless_config_t *conf)
{
	if (conf) {
		ni_string_free(&conf->country);
		ni_string_free(&conf->driver);
		ni_wireless_network_array_destroy(&conf->networks);

		ni_wireless_config_init(conf);
	}
}

ni_bool_t
ni_wireless_config_copy(ni_wireless_config_t *dst, ni_wireless_config_t *src)
{
	if (!src || !dst)
		return FALSE;

	if (dst == src)
		return TRUE;

	if (!ni_string_dup(&dst->country, src->country))
		return FALSE;

	dst->ap_scan = src->ap_scan;

	if (!ni_string_dup(&dst->driver, src->driver))
		return FALSE;

	ni_wireless_network_array_destroy(&dst->networks);
	if (!ni_wireless_network_array_copy(&dst->networks, &src->networks))
		return FALSE;

	return TRUE;
}

ni_bool_t
ni_wireless_config_has_essid(ni_wireless_config_t *conf, ni_wireless_ssid_t *essid)
{
	unsigned int i, count;
	ni_wireless_network_t *net;

	ni_assert(conf != NULL && essid != NULL);

	for (i = 0, count = conf->networks.count; i < count; i++) {
		net = conf->networks.data[i];
		if (ni_wireless_ssid_eq(&net->essid, essid))
			return TRUE;
	}

	return FALSE;
}

ni_wireless_t *
ni_wireless_new(void)
{
	ni_wireless_t *wlan;

	if (!(wlan = calloc(1, sizeof(ni_wireless_t)))) {
		ni_error_oom();
		return NULL;
	}

	ni_wireless_scan_set_defaults(&wlan->scan);
	return wlan;
}

void
ni_wireless_free(ni_wireless_t *wireless)
{
	if (wireless) {
		if (wireless->assoc.timer)
			ni_timer_cancel(wireless->assoc.timer);
		ni_string_free(&wireless->assoc.auth_mode);
		ni_wireless_config_free(&wireless->conf);
		ni_wireless_scan_destroy(&wireless->scan);
		free(wireless);
	}
}

static void
ni_wireless_bss_set(ni_wireless_bss_t *wireless_bss, const ni_wpa_bss_t *bss)
{
	const ni_wpa_bss_properties_t *props = &bss->properties;

	wireless_bss->bssid.len = props->bssid.len;
	memcpy(wireless_bss->bssid.data, props->bssid.data, props->bssid.len);

	wireless_bss->ssid.len = props->ssid.len;
	memcpy(wireless_bss->ssid.data, props->ssid.data, props->ssid.len);

	ni_wireless_wpa_key_mgmt_mask(&props->wpa.key_mgmt, &wireless_bss->wpa.key_mgmt);
	ni_wireless_wpa_pairwise_mask(&props->wpa.pairwise, &wireless_bss->wpa.pairwise_cipher);
	ni_wireless_wpa_pairwise_type(props->wpa.group, &wireless_bss->wpa.group_cipher);

	ni_wireless_wpa_key_mgmt_mask(&props->rsn.key_mgmt, &wireless_bss->rsn.key_mgmt);
	ni_wireless_wpa_pairwise_mask(&props->rsn.pairwise, &wireless_bss->rsn.pairwise_cipher);
	ni_wireless_wpa_pairwise_type(props->rsn.group, &wireless_bss->rsn.group_cipher);
	ni_wireless_wpa_group_mgmt_type(props->rsn.mgmt_group, &wireless_bss->rsn.mgmt_group_cipher);

	wireless_bss->privacy = props->privacy;

	ni_wireless_name_to_mode(props->mode, &wireless_bss->wireless_mode);
	wireless_bss->frequency = props->frequency;
	wireless_bss->channel = ni_wireless_frequency_to_channel(props->frequency);
	wireless_bss->rate_max = props->rate_max;
	wireless_bss->signal = props->signal;
	wireless_bss->age = props->age;
}

ni_wireless_bss_t *
ni_wireless_bss_new()
{
	ni_wireless_bss_t *bss;

	if (!(bss = calloc(1, sizeof(ni_wireless_bss_t)))) {
		ni_error_oom();
		return NULL;
	}
	return bss;
}

void
ni_wireless_bss_init(ni_wireless_bss_t *bss)
{
	memset(bss, 0, sizeof(*bss));
}

void
ni_wireless_bss_destroy(ni_wireless_bss_t *bss)
{
	ni_string_free(&bss->wps.type);
	ni_wireless_bss_init(bss);
}

void
ni_wireless_bss_free(ni_wireless_bss_t **bss)
{
	ni_wireless_bss_destroy(*bss);
	free(*bss);
	*bss = NULL;
}

void
ni_wireless_bss_list_destroy(ni_wireless_bss_t **list)
{
	ni_wireless_bss_t *bss;

	if (list) {
		while ((bss = *list)) {
			*list = bss->next;
			ni_wireless_bss_free(&bss);
		}
		*list = NULL;
	}
}

ni_bool_t
ni_wireless_bss_list_append(ni_wireless_bss_t **list, ni_wireless_bss_t *bss)
{
	if (!list || !bss)
		return FALSE;

	while (*list)
		list = &(*list)->next;
	*list = bss;
	return TRUE;
}

ni_wireless_bss_t *
ni_wireless_bss_list_find_by_bssid(ni_wireless_bss_t * const *list, const ni_hwaddr_t *bssid)
{
	if (!list || !bssid)
		return NULL;

	for(; *list; list = &(*list)->next)
		if (ni_link_address_equal(&(*list)->bssid, bssid))
			return *list;

	return NULL;
}

void
ni_wireless_scan_destroy(ni_wireless_scan_t *scan)
{
	if (scan->timer)
		ni_timer_cancel(scan->timer);

	ni_wireless_bss_list_destroy(&scan->bsss);
	memset(scan, 0, sizeof(*scan));
}

void
ni_wireless_scan_set_defaults(ni_wireless_scan_t *scan)
{
	scan->interval = __ni_wireless_scanning_enabled ? NI_WIRELESS_DEFAULT_SCAN_INTERVAL : 0;
	scan->max_age = NI_WIRELESS_SCAN_MAX_AGE;
}

ni_wireless_blob_t *
ni_wireless_blob_new_from_str(const char *str)
{
	ni_wireless_blob_t *blob;

	if (!(blob = calloc(1, sizeof(ni_wireless_blob_t)))) {
		ni_error_oom();
		return NULL;
	}

	blob->is_string = TRUE;
	if (!ni_string_dup(&blob->str, str)){
		free(blob);
		return NULL;
	}
	return blob;
}

void
ni_wireless_blob_free(ni_wireless_blob_t **blob_p)
{
	if (blob_p && *blob_p) {
		ni_wireless_blob_t *blob = *blob_p;
		if (blob->is_string) {
			memset(blob->str, 0, ni_string_len(blob->str));
			ni_string_free(&blob->str);
		} else
			ni_byte_array_destroy(&blob->byte_array);

		free(blob);
		*blob_p = NULL;
	}
}

/*
 * Wireless network objects
 */
static ni_bool_t
ni_wireless_network_init(ni_wireless_network_t *net)
{
	memset(net, 0, sizeof(*net));

	net->scan_ssid = TRUE;
	net->mode = NI_WIRELESS_MODE_MANAGED;
	net->wpa_eap.phase1.peapver = INT_MAX;

	return TRUE;
}

void
ni_wireless_network_destroy(ni_wireless_network_t *net)
{
	ni_wireless_wep_key_array_destroy(net->wep_keys);
	ni_string_clear(&net->wpa_psk.passphrase);
	ni_string_clear(&net->wpa_eap.phase2.password);
	ni_string_clear(&net->wpa_eap.tls.client_key_passwd);

	ni_string_clear(&net->wpa_eap.identity);
	ni_string_clear(&net->wpa_eap.anonid);
	ni_wireless_blob_free(&net->wpa_eap.tls.ca_cert);
	ni_wireless_blob_free(&net->wpa_eap.tls.client_cert);
	ni_wireless_blob_free(&net->wpa_eap.tls.client_key);
	ni_string_array_destroy(&net->frequency_list);

	memset(net, 0, sizeof(*net));
}

static ni_define_refcounted_free(ni_wireless_network);
extern ni_define_refcounted_new(ni_wireless_network);
extern ni_define_refcounted_drop(ni_wireless_network);
extern ni_define_refcounted_ref(ni_wireless_network);

void
ni_wireless_wep_key_array_destroy(char **array)
{
	unsigned int i;

	for (i = 0; i < NI_WIRELESS_WEP_KEY_COUNT; i++)
		ni_string_clear(&array[i]);
}

/*
 * Wireless network arrays
 */
extern ni_define_ptr_array_init(ni_wireless_network);
static ni_define_ptr_array_realloc(ni_wireless_network, 1);
extern ni_define_ptr_array_append(ni_wireless_network);
extern ni_define_ptr_array_destroy(ni_wireless_network);

ni_bool_t
ni_wireless_network_array_copy(ni_wireless_network_array_t *dst, ni_wireless_network_array_t *src)
{
	unsigned int i;

	if (!dst || !src)
		return FALSE;

	for (i = 0; i < src->count; ++i) {
		ni_wireless_network_t *ref = ni_wireless_network_ref(src->data[i]);

		if (ref && !ni_wireless_network_array_append(dst, ref)) {
			ni_wireless_network_free(ref);
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * Helper function to print and parse an SSID
 * Non-printable characters and anything fishy is represented
 * as \\xXX hex escape characters as formatted by the iwlist
 * scanning command and wpa-supplicant.
 */
const char *
ni_wireless_ssid_print_data(const unsigned char *data, size_t len, ni_stringbuf_t *out)
{
	unsigned int i, j = 0;

	if (!data || len > NI_WIRELESS_ESSID_MAX_LEN)
		return NULL;

	for (i = j = 0; i < len; ++i) {
		unsigned char cc = data[i];

		if (isalnum(cc) || cc == '-' || cc == '_' || cc == ' ') {
			ni_stringbuf_putc(out, cc);
		} else {
			ni_stringbuf_printf(out, "\\x%02X", cc);
			j += 4;
		}
	}

	return out->string;
}

const char *
ni_wireless_ssid_print(const ni_wireless_ssid_t *ssid, ni_stringbuf_t *out)
{
	return ni_wireless_ssid_print_data(ssid->data, ssid->len, out);
}

static inline unsigned int
__ni_wireless_ssid_parse_hex(unsigned char *out, const char *str, size_t len)
{
	unsigned long val;
	unsigned int pos;
	char *eos = NULL;
	char buf[3];

	for (pos = 0; pos < 2 && (size_t)pos < len; ) {
		unsigned char cc = str[pos];

		if (!isxdigit(cc))
			break;

		buf[pos++] = cc;
	}

	if (pos) {
		buf[pos] = '\0';
		val = strtoul(&buf[0], &eos, 16);
		if (*eos != '\0' || val > 255)
			return 0;
		*out = val;
	}
	return pos;
}

static inline unsigned int
__ni_wireless_ssid_parse_oct(unsigned char *out, const char *str, size_t len)
{
	unsigned int val = 0;
	unsigned int pos;

	for (pos = 0; pos < 3 && (size_t)pos < len; ) {
		unsigned char cc = str[pos];

		if (cc < '0' || '7' < cc)
			break;

		val = (val << 3) | (cc - '0');
		pos++;
	}
	if (pos)
		*out = val;
	return pos;
}

static ni_bool_t
ni_wireless_ssid_put(ni_wireless_ssid_t *ssid, unsigned char cc)
{
	if (ssid->len >= sizeof(ssid->data))
		return FALSE;
	ssid->data[ssid->len++] = cc;
	return TRUE;
}

static inline int
__ni_wireless_ssid_parse_esc(unsigned char *cc, const char *s, const char *e)
{
	switch (*s) {
	case '\\':	*cc = '\\';		return 1;
	case '"':	*cc = '"';		return 1;
	case 'n':	*cc = '\n';		return 1;
	case 'r':	*cc = '\r';		return 1;
	case 't':	*cc = '\t';		return 1;
	case 'e':	*cc = '\033';		return 1;
	case 'x':
		return __ni_wireless_ssid_parse_hex(cc, s + 1, e - s - 1) + 1;
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
		return __ni_wireless_ssid_parse_oct(cc, s, e - s);
	default:
		return 0;
	}
}

ni_bool_t
ni_wireless_ssid_parse(ni_wireless_ssid_t *ssid, const char *in)
{
	const char *s = in;
	const char *e;
	int ret;

	if (!in || !ssid)
		goto bad_ssid;

	e = s + ni_string_len(s);
	memset(ssid, 0, sizeof(*ssid));
	while (e > s) {
		unsigned char cc = *s++;

		if (cc == '\\') {
			ret = __ni_wireless_ssid_parse_esc(&cc, s, e);
			if (ret < 0)
				goto bad_ssid;
			s += ret;
		}

		if (!ni_wireless_ssid_put(ssid, cc))
			goto bad_ssid;
	}

	return TRUE;

bad_ssid:
	ni_debug_wireless("unable to parse wireless ssid \"%s\"", in);
	return FALSE;
}

ni_bool_t
ni_wireless_ssid_eq(ni_wireless_ssid_t *a, ni_wireless_ssid_t *b)
{
	if (a == NULL || b == NULL)
		return a == b;

	if (a->len == b->len)
		if (!memcmp(a->data, b->data, a->len))
			return TRUE;

	return FALSE;
}

static ni_bool_t
ni_wireless_wep_key_validate_string(const char *key)
{
	size_t len;

	if (!key)
		return FALSE;

	len = ni_string_len(key);
	switch(len){
	case NI_WIRELESS_WEP_KEY_LEN_40:
	case NI_WIRELESS_WEP_KEY_LEN_104:
	case NI_WIRELESS_WEP_KEY_LEN_128:
		return ni_check_printable(key, len);
	default:
		return FALSE;
	}
}

static ni_bool_t
ni_wireless_wep_key_validate_hexstring(const char *key)
{
	size_t len;
	unsigned char key_data[NI_WIRELESS_WEP_KEY_LEN_128];

	if (!key)
		return FALSE;

	len = ni_string_len(key);
	switch(len){
	case NI_WIRELESS_WEP_KEY_LEN_40_HEX:
	case NI_WIRELESS_WEP_KEY_LEN_104_HEX:
	case NI_WIRELESS_WEP_KEY_LEN_128_HEX:
		return ni_parse_hex_data(key, key_data, sizeof(key_data), NULL) > 0;
	default:
		return FALSE;
	}
}

ni_bool_t
ni_wireless_wep_key_parse(char **out, const char *key)
{
	char *_out = NULL;
	if (!key)
		return FALSE;

	if (ni_string_startswith(key, "s:") && ni_wireless_wep_key_validate_string(key+2)) {
		if (out)
			return ni_string_dup(out, key+2);
		return TRUE;

	} else if (ni_string_startswith(key, "h:") && ni_wireless_wep_key_validate_hexstring(key+2)) {
		if (out)
			return ni_string_dup(out, key+2);
		return TRUE;

	} else {
		if (!ni_string_dup(&_out, key))
			return FALSE;
		ni_string_remove_char(_out, '-');
		ni_string_remove_char(_out, ':');

		if (ni_wireless_wep_key_validate_hexstring(_out)) {
			if(!out)
				ni_string_free(&_out);
			else
				*out = _out;
			return TRUE;
		}
	}

	return FALSE;
}
