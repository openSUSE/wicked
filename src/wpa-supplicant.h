/*
 * Interfacing with wpa_supplicant through dbus interface
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 *
 */
#ifndef WICKED_WPA_SUPPLICANT_CLIENT_H
#define WICKED_WPA_SUPPLICANT_CLIENT_H

#include <wicked/wireless.h>
#include "dbus-connection.h"


typedef struct ni_wpa_client			ni_wpa_client_t;
typedef struct ni_wpa_nif			ni_wpa_nif_t;
typedef struct ni_wpa_nif_ops			ni_wpa_nif_ops_t;
typedef struct ni_wpa_nif_properties		ni_wpa_nif_properties_t;
typedef struct ni_wpa_nif_capabilities		ni_wpa_nif_capabilities_t;
typedef        ni_dbus_variant_t		ni_wpa_net_properties_t;
typedef struct ni_wpa_bss			ni_wpa_bss_t;
typedef struct ni_wpa_bss_properties		ni_wpa_bss_properties_t;


typedef enum {
	NI_WPA_NIF_STATE_UNKNOWN,
	NI_WPA_NIF_STATE_DISCONNECTED,
	NI_WPA_NIF_STATE_INACTIVE,
	NI_WPA_NIF_STATE_SCANNING,
	NI_WPA_NIF_STATE_AUTHENTICATING,
	NI_WPA_NIF_STATE_ASSOCIATING,
	NI_WPA_NIF_STATE_ASSOCIATED,
	NI_WPA_NIF_STATE_4WAY_HANDSHAKE,
	NI_WPA_NIF_STATE_GROUP_HANDSHAKE,
	NI_WPA_NIF_STATE_COMPLETED,
} ni_wpa_nif_state_t;

typedef enum {
	NI_WPA_NIF_CAPABILITY_PAIRWISE,
	NI_WPA_NIF_CAPABILITY_GROUP,
	NI_WPA_NIF_CAPABILITY_GROUP_MGMT,
	NI_WPA_NIF_CAPABILITY_KEY_MGMT,
	NI_WPA_NIF_CAPABILITY_PROTOCOL,
	NI_WPA_NIF_CAPABILITY_AUTH_ALG,
	NI_WPA_NIF_CAPABILITY_SCAN,
	NI_WPA_NIF_CAPABILITY_MODES,
	NI_WPA_NIF_CAPABILITY_MAX_SCAN_SSID,
} ni_wpa_nif_capability_type_t;

typedef enum {
	NI_WPA_NIF_PROPERTY_CAPABILITIES,
	NI_WPA_NIF_PROPERTY_STATE,
	NI_WPA_NIF_PROPERTY_SCANNING,
	NI_WPA_NIF_PROPERTY_AP_SCAN,
	NI_WPA_NIF_PROPERTY_BSS_EXPIRE_AGE,
	NI_WPA_NIF_PROPERTY_BSS_EXPIRE_COUNT,
	NI_WPA_NIF_PROPERTY_COUNTRY,
	NI_WPA_NIF_PROPERTY_IFNAME,
	NI_WPA_NIF_PROPERTY_DRIVER,
	NI_WPA_NIF_PROPERTY_BRIDGE,
	NI_WPA_NIF_PROPERTY_CONFIG_FILE,
	NI_WPA_NIF_PROPERTY_CURRENT_BSS,
	NI_WPA_NIF_PROPERTY_CURRENT_NETWORK,
	NI_WPA_NIF_PROPERTY_CURRENT_AUTH_MODE,
	NI_WPA_NIF_PROPERTY_BLOBS,
	NI_WPA_NIF_PROPERTY_BSSS,
	NI_WPA_NIF_PROPERTY_NETWORKS,
	NI_WPA_NIF_PROPERTY_FAST_REAUTH,
	NI_WPA_NIF_PROPERTY_SCAN_INTERVAL,
	NI_WPA_NIF_PROPERTY_PKCS11_ENGINE_PATH,
	NI_WPA_NIF_PROPERTY_PKCS11_MODULE_PATH,
	NI_WPA_NIF_PROPERTY_DISCONNECT_REASON,
	NI_WPA_NIF_PROPERTY_AUTH_STATUS_CODE,
	NI_WPA_NIF_PROPERTY_ASSOC_STATUS_CODE,
	NI_WPA_NIF_PROPERTY_STATIONS,
	NI_WPA_NIF_PROPERTY_CTRL_INTERFACE,
	NI_WPA_NIF_PROPERTY_CTRL_INTERFACE_GROUP,
	NI_WPA_NIF_PROPERTY_EAPOL_VERSION,
	NI_WPA_NIF_PROPERTY_BG_SCAN,
	NI_WPA_NIF_PROPERTY_DISABLE_SCAN_OFFLOAD,
	NI_WPA_NIF_PROPERTY_OPENSC_ENGINE_PATH,
	NI_WPA_NIF_PROPERTY_OPENSSL_CIPHERS,
	NI_WPA_NIF_PROPERTY_PCSC_READER,
	NI_WPA_NIF_PROPERTY_PCSC_PIN,
	NI_WPA_NIF_PROPERTY_EXTERNAL_SIM,
	NI_WPA_NIF_PROPERTY_DRIVER_PARAM,
	NI_WPA_NIF_PROPERTY_DOT11_RSNA_CONFIG_PMK_LIFETIME,
	NI_WPA_NIF_PROPERTY_DOT11_RSNA_CONFIG_PMK_REAUTH_THRESHOLD,
	NI_WPA_NIF_PROPERTY_DOT11_RSNA_CONFIG_SA_TIMEOUT,
	NI_WPA_NIF_PROPERTY_UPDATE_CONFIG,
	NI_WPA_NIF_PROPERTY_UUID,
	NI_WPA_NIF_PROPERTY_AUTO_UUID,
	NI_WPA_NIF_PROPERTY_DEVICE_NAME,
	NI_WPA_NIF_PROPERTY_MANUFACTURER,
	NI_WPA_NIF_PROPERTY_MODEL_NAME,
	NI_WPA_NIF_PROPERTY_MODEL_NUMBER,
	NI_WPA_NIF_PROPERTY_SERIAL_NUMBER,
	NI_WPA_NIF_PROPERTY_DEVICE_TYPE,
	NI_WPA_NIF_PROPERTY_OS_VERSION,
	NI_WPA_NIF_PROPERTY_CONFIG_METHODS,
	NI_WPA_NIF_PROPERTY_WPS_CRED_PROCESSING,
	NI_WPA_NIF_PROPERTY_WPS_CRED_ADD_SAE,
	NI_WPA_NIF_PROPERTY_WPS_VENDOR_EXT_M1,
	NI_WPA_NIF_PROPERTY_SEC_DEVICE_TYPE,
	NI_WPA_NIF_PROPERTY_P2P_LISTEN_REG_CLASS,
	NI_WPA_NIF_PROPERTY_P2P_LISTEN_CHANNEL,
	NI_WPA_NIF_PROPERTY_P2P_OPER_REG_CLASS,
	NI_WPA_NIF_PROPERTY_P2P_OPER_CHANNEL,
	NI_WPA_NIF_PROPERTY_P2P_GO_INTENT,
	NI_WPA_NIF_PROPERTY_P2P_SSID_POSTFIX,
	NI_WPA_NIF_PROPERTY_PERSISTENT_RECONNECT,
	NI_WPA_NIF_PROPERTY_P2P_INTRA_BSS,
	NI_WPA_NIF_PROPERTY_P2P_GROUP_IDLE,
	NI_WPA_NIF_PROPERTY_P2P_GO_FREQ_CHANGE_POLICY,
	NI_WPA_NIF_PROPERTY_P2P_PASSPHRASE_LEN,
	NI_WPA_NIF_PROPERTY_P2P_PREF_CHAN,
	NI_WPA_NIF_PROPERTY_P2P_NO_GO_FREQ,
	NI_WPA_NIF_PROPERTY_P2P_ADD_CLI_CHAN,
	NI_WPA_NIF_PROPERTY_P2P_OPTIMIZE_LISTEN_CHAN,
	NI_WPA_NIF_PROPERTY_P2P_GO_HT40,
	NI_WPA_NIF_PROPERTY_P2P_GO_VHT,
	NI_WPA_NIF_PROPERTY_P2P_GO_HE,
	NI_WPA_NIF_PROPERTY_P2P_DISABLED,
	NI_WPA_NIF_PROPERTY_P2P_GO_CT_WINDOW,
	NI_WPA_NIF_PROPERTY_P2P_NO_GROUP_IFACE,
	NI_WPA_NIF_PROPERTY_P2P_IGNORE_SHARED_FREQ,
	NI_WPA_NIF_PROPERTY_IP_ADDR_GO,
	NI_WPA_NIF_PROPERTY_IP_ADDR_MASK,
	NI_WPA_NIF_PROPERTY_IP_ADDR_START,
	NI_WPA_NIF_PROPERTY_IP_ADDR_END,
	NI_WPA_NIF_PROPERTY_P2P_CLI_PROBE,
	NI_WPA_NIF_PROPERTY_P2P_DEVICE_RANDOM_MAC_ADDR,
	NI_WPA_NIF_PROPERTY_P2P_DEVICE_PERSISTENT_MAC_ADDR,
	NI_WPA_NIF_PROPERTY_P2PINTERFACE_RANDOM_MAC_ADDR,
	NI_WPA_NIF_PROPERTY_BSS_MAX_COUNT,
	NI_WPA_NIF_PROPERTY_FILTER_SSIDS,
	NI_WPA_NIF_PROPERTY_FILTER_RSSI,
	NI_WPA_NIF_PROPERTY_MAX_NUM_STA,
	NI_WPA_NIF_PROPERTY_AP_ISOLATE,
	NI_WPA_NIF_PROPERTY_DISASSOC_LOW_ACK,
	NI_WPA_NIF_PROPERTY_INTERWORKING,
	NI_WPA_NIF_PROPERTY_HESSID,
	NI_WPA_NIF_PROPERTY_ACCESS_NETWORK_TYPE,
	NI_WPA_NIF_PROPERTY_GO_INTERWORKING,
	NI_WPA_NIF_PROPERTY_GO_ACCESS_NETWORK_TYPE,
	NI_WPA_NIF_PROPERTY_GO_INTERNET,
	NI_WPA_NIF_PROPERTY_GO_VENUE_GROUP,
	NI_WPA_NIF_PROPERTY_GO_VENUE_TYPE,
	NI_WPA_NIF_PROPERTY_PBC_IN_M1,
	NI_WPA_NIF_PROPERTY_AUTOSCAN,
	NI_WPA_NIF_PROPERTY_WPS_NFC_DEV_PW_ID,
	NI_WPA_NIF_PROPERTY_WPS_NFC_DH_PUB_KEY,
	NI_WPA_NIF_PROPERTY_WPS_NFC_DH_PRIV_KEY,
	NI_WPA_NIF_PROPERTY_WPS_NFC_DEV_PW,
	NI_WPA_NIF_PROPERTY_EXT_PASSWORD_BACKEND,
	NI_WPA_NIF_PROPERTY_P2P_GO_MAX_INACTIVITY,
	NI_WPA_NIF_PROPERTY_AUTO_INTERWORKING,
	NI_WPA_NIF_PROPERTY_OKC,
	NI_WPA_NIF_PROPERTY_PMF,
	NI_WPA_NIF_PROPERTY_SAE_GROUPS,
	NI_WPA_NIF_PROPERTY_DTIM_PERIOD,
	NI_WPA_NIF_PROPERTY_BEACON_INT,
	NI_WPA_NIF_PROPERTY_AP_VENDOR_ELEMENTS,
	NI_WPA_NIF_PROPERTY_IGNIRE_OLD_SCAN_RES,
	NI_WPA_NIF_PROPERTY_FREQ_LIST,
	NI_WPA_NIF_PROPERTY_SCAN_CUR_FREQ,
	NI_WPA_NIF_PROPERTY_SCHED_SCAN_INTERVAL,
	NI_WPA_NIF_PROPERTY_SCHED_SCAN_START_DELAY,
	NI_WPA_NIF_PROPERTY_TDLS_EXTERNAL_CONTROL,
	NI_WPA_NIF_PROPERTY_OSU_DIR,
	NI_WPA_NIF_PROPERTY_WOWLAN_TRIGGERS,
	NI_WPA_NIF_PROPERTY_P2P_SEARCH_DELAY,
	NI_WPA_NIF_PROPERTY_MAC_ADDR,
	NI_WPA_NIF_PROPERTY_RAND_ADDR_LIFETIME,
	NI_WPA_NIF_PROPERTY_PREASSOC_MAC_ADDR,
	NI_WPA_NIF_PROPERTY_KEY_MGMT_OFFLOAD,
	NI_WPA_NIF_PROPERTY_PASSIVE_SCAN,
	NI_WPA_NIF_PROPERTY_REASSOC_SAME_BSS_OPTIM,
	NI_WPA_NIF_PROPERTY_WPS_PRIORITY,
	NI_WPA_NIF_PROPERTY_CERT_IN_CB,
	NI_WPA_NIF_PROPERTY_WPA_RSC_RELAXATION,
	NI_WPA_NIF_PROPERTY_SCHED_SCAN_PLANS,
	NI_WPA_NIF_PROPERTY_GAS_ADDRESS3,
	NI_WPA_NIF_PROPERTY_FTM_RESPONDER,
	NI_WPA_NIF_PROPERTY_FTM_INITIATOR,
	NI_WPA_NIF_PROPERTY_GAS_RAND_ADDR_LIFETIME,
	NI_WPA_NIF_PROPERTY_GAS_RAMD_MAC_ADDR,
	NI_WPA_NIF_PROPERTY_DPP_CONFIG_PROCESSING,
	NI_WPA_NIF_PROPERTY_COLOC_INTF_REPORTING,
} ni_wpa_nif_property_type_t;

typedef enum {
	NI_WPA_NET_PROPERTY_SSID,
	NI_WPA_NET_PROPERTY_SCAN_SSID,
	NI_WPA_NET_PROPERTY_BSSID,
	NI_WPA_NET_PROPERTY_BSSID_HINT,
	NI_WPA_NET_PROPERTY_BSSID_BLACKLIST,
	NI_WPA_NET_PROPERTY_BSSID_WHITELIST,
	NI_WPA_NET_PROPERTY_PSK,
	NI_WPA_NET_PROPERTY_MEM_ONLY_PSK,
	NI_WPA_NET_PROPERTY_SAE_PASSWORD,
	NI_WPA_NET_PROPERTY_SAE_PASSWORD_ID,
	NI_WPA_NET_PROPERTY_PROTO,
	NI_WPA_NET_PROPERTY_KEY_MGMT,
	NI_WPA_NET_PROPERTY_BG_SCAN_PERIOD,
	NI_WPA_NET_PROPERTY_PAIRWISE,
	NI_WPA_NET_PROPERTY_GROUP,
	NI_WPA_NET_PROPERTY_GROUP_MGMT,
	NI_WPA_NET_PROPERTY_AUTH_ALG,
	NI_WPA_NET_PROPERTY_SCAN_FREQ,
	NI_WPA_NET_PROPERTY_FREQ_LIST,
	NI_WPA_NET_PROPERTY_HT,
	NI_WPA_NET_PROPERTY_VHT,
	NI_WPA_NET_PROPERTY_HT40,
	NI_WPA_NET_PROPERTY_MAX_OPER_CHWIDTH,
	NI_WPA_NET_PROPERTY_VHT_CENTER_FREQ1,
	NI_WPA_NET_PROPERTY_VHT_CENTER_FREQ2,
	NI_WPA_NET_PROPERTY_ENGINE,
	NI_WPA_NET_PROPERTY_ENGINE2,
	NI_WPA_NET_PROPERTY_EAPOL_FLAGS,
	NI_WPA_NET_PROPERTY_SIM_NUM,
	NI_WPA_NET_PROPERTY_ERP,
	NI_WPA_NET_PROPERTY_WEP_TX_KEYIDX,
	NI_WPA_NET_PROPERTY_WEP_KEY0,
	NI_WPA_NET_PROPERTY_WEP_KEY1,
	NI_WPA_NET_PROPERTY_WEP_KEY2,
	NI_WPA_NET_PROPERTY_WEP_KEY3,
	NI_WPA_NET_PROPERTY_PRIORITY,
	NI_WPA_NET_PROPERTY_EAP_WORKAROUND,
	NI_WPA_NET_PROPERTY_FRAGMENT_SIZE,
	NI_WPA_NET_PROPERTY_OCSP,
	NI_WPA_NET_PROPERTY_MODE,
	NI_WPA_NET_PROPERTY_PROACTIVE_KEY_CACHING,
	NI_WPA_NET_PROPERTY_DISABLED,
	NI_WPA_NET_PROPERTY_IEEE80211W,
	NI_WPA_NET_PROPERTY_PEERKEY,
	NI_WPA_NET_PROPERTY_MIXED_CELL,
	NI_WPA_NET_PROPERTY_FREQUENCY,
	NI_WPA_NET_PROPERTY_FIXED_FREQ,
	NI_WPA_NET_PROPERTY_WPA_PTK_REKEY,
	NI_WPA_NET_PROPERTY_GROUP_REKEY,
	NI_WPA_NET_PROPERTY_IGNORE_BROADCAST_SSID,
	NI_WPA_NET_PROPERTY_AP_MAX_INACTIVITY,
	NI_WPA_NET_PROPERTY_DTIM_PERIOD,
	NI_WPA_NET_PROPERTY_BEACON_INT,
	NI_WPA_NET_PROPERTY_MAC_ADDR,
	NI_WPA_NET_PROPERTY_PBSS,
	NI_WPA_NET_PROPERTY_FILS_DH_GROUP,
	NI_WPA_NET_PROPERTY_OWE_GROUP,
	NI_WPA_NET_PROPERTY_OWE_ONLY,
	NI_WPA_NET_PROPERTY_MULTI_AP_BACKHAUL_STA,
	NI_WPA_NET_PROPERTY_FT_EAP_PMKSA_CACHING,
	NI_WPA_NET_PROPERTY_WPS_DISABLED,
	NI_WPA_NET_PROPERTY_EAP,
	NI_WPA_NET_PROPERTY_IDENTITY,
	NI_WPA_NET_PROPERTY_ANONYMOUS_IDENTITY,
	NI_WPA_NET_PROPERTY_PHASE1,
	NI_WPA_NET_PROPERTY_PHASE2,
	NI_WPA_NET_PROPERTY_PASSWORD,
	NI_WPA_NET_PROPERTY_CA_CERT,
	NI_WPA_NET_PROPERTY_CLIENT_CERT,
	NI_WPA_NET_PROPERTY_PRIVATE_KEY,
	NI_WPA_NET_PROPERTY_PRIVATE_KEY_PASSWD,

} ni_wpa_net_property_type_t;

struct ni_wpa_nif_ops {
	void (*on_network_added)(ni_wpa_nif_t*, const char*, const ni_wpa_net_properties_t*);
	void (*on_network_selected)(ni_wpa_nif_t*, const char*);
	void (*on_network_removed)(ni_wpa_nif_t*, const char*);
	void (*on_scan_done)(ni_wpa_nif_t*, const ni_wpa_bss_t *);
	void (*on_state_change)(ni_wpa_nif_t*, ni_wpa_nif_state_t old_state, ni_wpa_nif_state_t new_state);
	void (*on_properties_changed)(ni_wpa_nif_t*, ni_dbus_variant_t*);
};

struct ni_wpa_nif_capabilities {
	/* read-only capabilities			*/
	ni_string_array_t			pairwise;
	ni_string_array_t			group;
	ni_string_array_t			group_mgmt;
	ni_string_array_t			key_mgmt;
	ni_string_array_t			protocol;
	ni_string_array_t			auth_alg;
	ni_string_array_t			scan;
	ni_string_array_t			modes;
	int					max_scan_ssid;
};

struct	ni_wpa_nif_properties {
	/* writeable via CreateInterface only		*/
	char *					ifname;
	char *					bridge;
	char *					driver;

	/* writeable via Properties.Set			*/
	char *					country;
	unsigned int				ap_scan;
	ni_bool_t				fast_reauth;
	int					scan_interval;
	unsigned int				bss_expire_age;
	unsigned int				bss_expire_count;

	/* read-only properties				*/
	char *					current_network_path;
	char *					current_bss_path;
	ni_string_array_t			network_paths;
	ni_string_array_t			bss_paths;
	ni_bool_t				scanning;
	char *					current_auth_mode;
};

struct ni_wpa_nif {
	ni_wpa_nif_t *				next;

	ni_wpa_client_t *			client;
	ni_dbus_object_t *			object;

	ni_netdev_ref_t				device;

	ni_wpa_nif_ops_t			ops;

	struct {
		struct timeval			timestamp;
		unsigned char			pending;
	} scan;

	struct timeval				acquired;
	ni_wpa_nif_state_t			state;

	ni_wpa_nif_properties_t			properties;
	ni_wpa_nif_capabilities_t		capabilities;

	ni_wpa_bss_t *				bsss;
};

struct ni_wpa_bss_properties {
	ni_byte_array_t			bssid;
	ni_byte_array_t			ssid;

	struct {
		ni_string_array_t	key_mgmt;
		ni_string_array_t	pairwise;
		char *			group;
	} wpa;
	struct {
		ni_string_array_t	key_mgmt;
		ni_string_array_t	pairwise;
		char *			group;
		char *			mgmt_group;
	} rsn;
	struct {
		char *			type;
	} wps;

	ni_byte_array_t			ies;
	ni_bool_t			privacy;
	char *				mode;
	uint16_t			frequency;
	uint32_t			rate_max;
	int16_t				signal;
	uint32_t			age;
};

struct ni_wpa_bss {
	ni_wpa_nif_t *				wif;
	ni_dbus_object_t *			object;
	ni_wpa_bss_t *				next;

	ni_wpa_bss_properties_t			properties;
};

extern ni_wpa_client_t *			ni_wpa_client();

extern int					ni_wpa_get_interface(ni_wpa_client_t *, const char *, unsigned int,
								ni_wpa_nif_t **);
extern int					ni_wpa_add_interface(ni_wpa_client_t *, unsigned int,
								ni_dbus_variant_t *, ni_wpa_nif_t **);
extern int					ni_wpa_del_interface(ni_wpa_client_t *, const char *);

extern int					ni_wpa_nif_set_properties(ni_wpa_nif_t *, const ni_dbus_variant_t *);

extern int					ni_wpa_nif_add_network(ni_wpa_nif_t *wif, const ni_wpa_net_properties_t *conf,
								ni_stringbuf_t *path);
extern int					ni_wpa_nif_del_network(ni_wpa_nif_t *, const char *);
extern int					ni_wpa_nif_del_all_networks(ni_wpa_nif_t *);
extern int					ni_wpa_nif_set_all_networks_property_enabled(ni_wpa_nif_t *wif, ni_bool_t enable);


extern void 					ni_wpa_nif_set_ops(ni_wpa_nif_t *, ni_wpa_nif_ops_t *);
extern ni_wpa_nif_t *				ni_wpa_nif_by_index(ni_wpa_client_t *wpa, unsigned int ifindex);
extern ni_bool_t				ni_wpa_nif_scan_in_progress(ni_wpa_nif_t *);
extern int					ni_wpa_nif_trigger_scan(ni_wpa_nif_t *, ni_bool_t);
extern ni_bool_t				ni_wpa_nif_retrieve_scan(ni_wpa_nif_t *, ni_wireless_scan_t *);
extern int					ni_wpa_nif_flush_bss(ni_wpa_nif_t *wif, uint32_t max_age);
extern ni_wpa_bss_t *				ni_wpa_nif_get_current_bss(ni_wpa_nif_t *);

extern const char *				ni_wpa_nif_property_name(ni_wpa_nif_property_type_t);
extern ni_bool_t				ni_wpa_nif_property_type(const char *, ni_wpa_nif_property_type_t *);
extern const char *				ni_wpa_nif_capability_name(ni_wpa_nif_capability_type_t);
extern ni_bool_t				ni_wpa_nif_capability_type(const char *, ni_wpa_nif_capability_type_t *);

extern const char *				ni_wpa_net_property_name(ni_wpa_net_property_type_t);
extern ni_bool_t				ni_wpa_net_property_type(const char *, ni_wpa_net_property_type_t *);

#endif /* WICKED_WPA_SUPPLICANT_CLIENT_H */
