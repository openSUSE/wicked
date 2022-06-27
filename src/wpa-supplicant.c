/*
 * Interfacing with wpa_supplicant through dbus interface
 * https://w1.fi/wpa_supplicant/devel/dbus.html
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/netinfo.h>

#include "wpa-supplicant.h"


#define NI_WPA_BUS_NAME				"fi.w1.wpa_supplicant1"
#define NI_WPA_INTERFACE			"fi.w1.wpa_supplicant1"
#define NI_WPA_NIF_INTERFACE			NI_WPA_INTERFACE ".Interface"
#define NI_WPA_NET_INTERFACE			NI_WPA_INTERFACE ".Network"
#define NI_WPA_BSS_INTERFACE			NI_WPA_INTERFACE ".BSS"
#define NI_WPA_OBJECT_PATH			"/fi/w1/wpa_supplicant1"
#define NI_WPA_OBJECT_PATH_NONE			"/"
#define NI_WPA_NIF_OBJECT_PREFIX		"/Interfaces/"
#define NI_WPA_NET_OBJECT_PREFIX		"/Networks/"

#define SIGNAL_ERR(path, member, msg, ...) \
	ni_error("%s: %s signal processing error: " msg, path, member, ##__VA_ARGS__);

typedef struct ni_wpa_ops_handler		ni_wpa_ops_handler_t;
struct ni_wpa_ops_handler {
	ni_wpa_ops_handler_t			*next;
	ni_wpa_client_ops_t			ops;
	unsigned int				ifindex;
};

struct ni_wpa_client {
	ni_dbus_client_t *			dbus;
	ni_dbus_object_t *			object;

	ni_wpa_nif_t *				nifs;
	ni_wpa_ops_handler_t			*ops_handler_list;

	ni_wpa_client_properties_t		properties;
};
static ni_wpa_client_t *			wpa_client; /* singelton */

static const ni_dbus_class_t			ni_objectmodel_wpa_class = {
	.name		= "wpa-client"
};

static const ni_dbus_class_t			ni_objectmodel_wpa_nif_class;
static const ni_dbus_class_t			ni_objectmodel_wpa_bss_class;

static const ni_dbus_service_t			ni_objectmodel_wpa_nif_service;
static const ni_dbus_service_t			ni_objectmodel_wpa_bss_service;


static ni_dbus_client_t *			ni_wpa_client_dbus(ni_wpa_client_t *);
static void					ni_wpa_client_properties_destroy(ni_wpa_client_properties_t *);
static void					ni_wpa_client_properties_init(ni_wpa_client_properties_t *);
static int					ni_wpa_client_refresh(ni_wpa_client_t *);

static ni_wpa_nif_t *				ni_wpa_nif_by_path(ni_wpa_client_t *wpa, const char *object_path);


static ni_wpa_nif_t *				ni_wpa_nif_new(ni_wpa_client_t *, const char *, unsigned int);
static void					ni_wpa_nif_free(ni_wpa_nif_t *);
static int					ni_wpa_nif_refresh(ni_wpa_nif_t *);
static void					ni_wpa_nif_refresh_all_bss(ni_wpa_nif_t *wif);

static ni_dbus_object_t *			ni_objectmodel_wpa_nif_object_new(ni_wpa_client_t *, ni_wpa_nif_t *, const char *);

static ni_wpa_nif_t *				ni_objectmodel_wpa_nif_unwrap(const ni_dbus_object_t *, DBusError *);

static void					ni_wpa_dbus_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
static void					ni_wpa_nif_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
static void					ni_wpa_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);

static ni_wpa_bss_t *				ni_wpa_bss_new(ni_wpa_nif_t *wif, const char *object_path);
static void					ni_wpa_bss_free(ni_wpa_bss_t *bss);
static ni_bool_t				ni_wpa_bss_list_append(ni_wpa_bss_t **list, ni_wpa_bss_t *bss);
static ni_bool_t				ni_wpa_bss_list_remove_by_path(ni_wpa_bss_t **list, const char *path);
static ni_wpa_bss_t *				ni_wpa_bss_list_find_by_path(ni_wpa_bss_t **list, const char *object_path);
static void					ni_wpa_bss_list_destroy(ni_wpa_bss_t **list);
static int					ni_wpa_bss_refresh(ni_wpa_bss_t * bss);
static ni_wpa_bss_t *				ni_wpa_nif_find_or_create_bss(ni_wpa_nif_t *wif, const char *object_path);


/*
 * Map wpa_supplicant errors
 */
static const ni_intmap_t	ni_wpa_error_names[] = {
	{ "fi.w1.wpa_supplicant1.InterfaceUnknown",		NI_ERROR_DEVICE_NOT_KNOWN		},
	{ "fi.w1.wpa_supplicant1.InterfaceExists",		NI_ERROR_DEVICE_EXISTS			},
	{ "fi.w1.wpa_supplicant1.InvalidArgs",			NI_ERROR_INVALID_ARGS			},
	{ "fi.w1.wpa_supplicant1.NetworkUnknown",		NI_ERROR_PROPERTY_NOT_PRESENT		},
	{ "fi.w1.wpa_supplicant1.UnknownError",			NI_ERROR_GENERAL_FAILURE		},
	{ "fi.w1.wpa_supplicant1.BlobUnknown",			NI_ERROR_ENTRY_NOT_KNOWN		},
	{ "fi.w1.wpa_supplicant1.BlobExists",			NI_ERROR_ENTRY_EXISTS			},

	{ NULL }
};

static const ni_intmap_t			ni_wpa_nif_capability_map[] = {
	{ "Pairwise",				NI_WPA_NIF_CAPABILITY_PAIRWISE				},
	{ "Group",				NI_WPA_NIF_CAPABILITY_GROUP				},
	{ "GroupMgmt",				NI_WPA_NIF_CAPABILITY_GROUP_MGMT			},
	{ "KeyMgmt",				NI_WPA_NIF_CAPABILITY_KEY_MGMT				},
	{ "Protocol",				NI_WPA_NIF_CAPABILITY_PROTOCOL				},
	{ "AuthAlg",				NI_WPA_NIF_CAPABILITY_AUTH_ALG				},
	{ "Scan",				NI_WPA_NIF_CAPABILITY_SCAN				},
	{ "Modes",				NI_WPA_NIF_CAPABILITY_MODES				},
	{ "MaxScanSSID",			NI_WPA_NIF_CAPABILITY_MAX_SCAN_SSID			},

	{ NULL }
};

static const ni_intmap_t			ni_wpa_nif_property_map[] =  {
	{ "Capabilities",			NI_WPA_NIF_PROPERTY_CAPABILITIES			},
	{ "State",				NI_WPA_NIF_PROPERTY_STATE				},
	{ "Scanning",				NI_WPA_NIF_PROPERTY_SCANNING				},
	{ "ApScan",				NI_WPA_NIF_PROPERTY_AP_SCAN				},
	{ "BSSExpireAge",			NI_WPA_NIF_PROPERTY_BSS_EXPIRE_AGE			},
	{ "BSSExpireCount",			NI_WPA_NIF_PROPERTY_BSS_EXPIRE_COUNT			},
	{ "Country",				NI_WPA_NIF_PROPERTY_COUNTRY				},
	{ "Ifname",				NI_WPA_NIF_PROPERTY_IFNAME				},
	{ "Driver",				NI_WPA_NIF_PROPERTY_DRIVER				},
	{ "BridgeIfname",			NI_WPA_NIF_PROPERTY_BRIDGE				},
	{ "ConfigFile",				NI_WPA_NIF_PROPERTY_CONFIG_FILE				},
	{ "CurrentBSS",				NI_WPA_NIF_PROPERTY_CURRENT_BSS				},
	{ "CurrentNetwork",			NI_WPA_NIF_PROPERTY_CURRENT_NETWORK			},
	{ "CurrentAuthMode",			NI_WPA_NIF_PROPERTY_CURRENT_AUTH_MODE			},
	{ "Blobs",				NI_WPA_NIF_PROPERTY_BLOBS				},
	{ "BSSs",				NI_WPA_NIF_PROPERTY_BSSS				},
	{ "Networks",				NI_WPA_NIF_PROPERTY_NETWORKS				},
	{ "FastReauth",				NI_WPA_NIF_PROPERTY_FAST_REAUTH				},
	{ "ScanInterval",			NI_WPA_NIF_PROPERTY_SCAN_INTERVAL			},
	{ "PKCS11EnginePath",			NI_WPA_NIF_PROPERTY_PKCS11_ENGINE_PATH			},
	{ "PKCS11ModulePath",			NI_WPA_NIF_PROPERTY_PKCS11_MODULE_PATH			},
	{ "DisconnectReason",			NI_WPA_NIF_PROPERTY_DISCONNECT_REASON			},
	{ "AuthStatusCode",			NI_WPA_NIF_PROPERTY_AUTH_STATUS_CODE			},
	{ "AssocStatusCode",			NI_WPA_NIF_PROPERTY_ASSOC_STATUS_CODE			},
	{ "Stations",				NI_WPA_NIF_PROPERTY_STATIONS				},
	{ "CtrlInterface",			NI_WPA_NIF_PROPERTY_CTRL_INTERFACE			},
	{ "CtrlInterfaceGroup",			NI_WPA_NIF_PROPERTY_CTRL_INTERFACE_GROUP		},
	{ "EapolVersion",			NI_WPA_NIF_PROPERTY_EAPOL_VERSION			},
	{ "Bgscan",				NI_WPA_NIF_PROPERTY_BG_SCAN				},
	{ "DisableScanOffload",			NI_WPA_NIF_PROPERTY_DISABLE_SCAN_OFFLOAD		},
	{ "OpenscEnginePath",			NI_WPA_NIF_PROPERTY_OPENSC_ENGINE_PATH			},
	{ "OpensslCiphers",			NI_WPA_NIF_PROPERTY_OPENSSL_CIPHERS			},
	{ "PcscReader",				NI_WPA_NIF_PROPERTY_PCSC_READER				},
	{ "PcscPin",				NI_WPA_NIF_PROPERTY_PCSC_PIN				},
	{ "ExternalSim",			NI_WPA_NIF_PROPERTY_EXTERNAL_SIM			},
	{ "DriverParam",			NI_WPA_NIF_PROPERTY_DRIVER_PARAM			},
	{ "Dot11RSNAConfigPMKLifetime",		NI_WPA_NIF_PROPERTY_DOT11_RSNA_CONFIG_PMK_LIFETIME	},
	{ "Dot11RSNAConfigPMKReauthThreshold",	NI_WPA_NIF_PROPERTY_DOT11_RSNA_CONFIG_PMK_REAUTH_THRESHOLD},
	{ "Dot11RSNAConfigSATimeout",		NI_WPA_NIF_PROPERTY_DOT11_RSNA_CONFIG_SA_TIMEOUT	},
	{ "UpdateConfig",			NI_WPA_NIF_PROPERTY_UPDATE_CONFIG			},
	{ "Uuid",				NI_WPA_NIF_PROPERTY_UUID				},
	{ "AutoUuid",				NI_WPA_NIF_PROPERTY_AUTO_UUID				},
	{ "DeviceName",				NI_WPA_NIF_PROPERTY_DEVICE_NAME				},
	{ "Manufacturer",			NI_WPA_NIF_PROPERTY_MANUFACTURER			},
	{ "ModelName",				NI_WPA_NIF_PROPERTY_MODEL_NAME				},
	{ "ModelNumber",			NI_WPA_NIF_PROPERTY_MODEL_NUMBER			},
	{ "SerialNumber",			NI_WPA_NIF_PROPERTY_SERIAL_NUMBER			},
	{ "DeviceType",				NI_WPA_NIF_PROPERTY_DEVICE_TYPE				},
	{ "OsVersion",				NI_WPA_NIF_PROPERTY_OS_VERSION				},
	{ "ConfigMethods",			NI_WPA_NIF_PROPERTY_CONFIG_METHODS			},
	{ "WpsCredProcessing",			NI_WPA_NIF_PROPERTY_WPS_CRED_PROCESSING			},
	{ "WpsCredAddSae",			NI_WPA_NIF_PROPERTY_WPS_CRED_ADD_SAE			},
	{ "WpsVendorExtM1",			NI_WPA_NIF_PROPERTY_WPS_VENDOR_EXT_M1			},
	{ "SecDeviceType",			NI_WPA_NIF_PROPERTY_SEC_DEVICE_TYPE			},
	{ "P2pListenRegClass",			NI_WPA_NIF_PROPERTY_P2P_LISTEN_REG_CLASS		},
	{ "P2pListenChannel",			NI_WPA_NIF_PROPERTY_P2P_LISTEN_CHANNEL			},
	{ "P2pOperRegClass",			NI_WPA_NIF_PROPERTY_P2P_OPER_REG_CLASS			},
	{ "P2pOperChannel",			NI_WPA_NIF_PROPERTY_P2P_OPER_CHANNEL			},
	{ "P2pGoIntent",			NI_WPA_NIF_PROPERTY_P2P_GO_INTENT			},
	{ "P2pSsidPostfix",			NI_WPA_NIF_PROPERTY_P2P_SSID_POSTFIX			},
	{ "PersistentReconnect",		NI_WPA_NIF_PROPERTY_PERSISTENT_RECONNECT		},
	{ "P2pIntraBss",			NI_WPA_NIF_PROPERTY_P2P_INTRA_BSS			},
	{ "P2pGroupIdle",			NI_WPA_NIF_PROPERTY_P2P_GROUP_IDLE			},
	{ "P2pGoFreqChangePolicy",		NI_WPA_NIF_PROPERTY_P2P_GO_FREQ_CHANGE_POLICY		},
	{ "P2pPassphraseLen",			NI_WPA_NIF_PROPERTY_P2P_PASSPHRASE_LEN			},
	{ "P2pPrefChan",			NI_WPA_NIF_PROPERTY_P2P_PREF_CHAN			},
	{ "P2pNoGoFreq",			NI_WPA_NIF_PROPERTY_P2P_NO_GO_FREQ			},
	{ "P2pAddCliChan",			NI_WPA_NIF_PROPERTY_P2P_ADD_CLI_CHAN			},
	{ "P2pOptimizeListenChan",		NI_WPA_NIF_PROPERTY_P2P_OPTIMIZE_LISTEN_CHAN		},
	{ "P2pGoHt40",				NI_WPA_NIF_PROPERTY_P2P_GO_HT40				},
	{ "P2pGoVht",				NI_WPA_NIF_PROPERTY_P2P_GO_VHT				},
	{ "P2pGoHe",				NI_WPA_NIF_PROPERTY_P2P_GO_HE				},
	{ "P2pDisabled",			NI_WPA_NIF_PROPERTY_P2P_DISABLED			},
	{ "P2pGoCtwindow",			NI_WPA_NIF_PROPERTY_P2P_GO_CT_WINDOW			},
	{ "P2pNoGroupIface",			NI_WPA_NIF_PROPERTY_P2P_NO_GROUP_IFACE			},
	{ "P2pIgnoreSharedFreq",		NI_WPA_NIF_PROPERTY_P2P_IGNORE_SHARED_FREQ		},
	{ "IpAddrGo",				NI_WPA_NIF_PROPERTY_IP_ADDR_GO				},
	{ "IpAddrMask",				NI_WPA_NIF_PROPERTY_IP_ADDR_MASK			},
	{ "IpAddrStart",			NI_WPA_NIF_PROPERTY_IP_ADDR_START			},
	{ "IpAddrEnd",				NI_WPA_NIF_PROPERTY_IP_ADDR_END				},
	{ "P2pCliProbe",			NI_WPA_NIF_PROPERTY_P2P_CLI_PROBE			},
	{ "P2pDeviceRandomMacAddr",		NI_WPA_NIF_PROPERTY_P2P_DEVICE_RANDOM_MAC_ADDR		},
	{ "P2pDevicePersistentMacAddr",		NI_WPA_NIF_PROPERTY_P2P_DEVICE_PERSISTENT_MAC_ADDR	},
	{ "P2pInterfaceRandomMacAddr",		NI_WPA_NIF_PROPERTY_P2PINTERFACE_RANDOM_MAC_ADDR	},
	{ "BssMaxCount",			NI_WPA_NIF_PROPERTY_BSS_MAX_COUNT			},
	{ "FilterSsids",			NI_WPA_NIF_PROPERTY_FILTER_SSIDS			},
	{ "FilterRssi",				NI_WPA_NIF_PROPERTY_FILTER_RSSI				},
	{ "MaxNumSta",				NI_WPA_NIF_PROPERTY_MAX_NUM_STA				},
	{ "ApIsolate",				NI_WPA_NIF_PROPERTY_AP_ISOLATE				},
	{ "DisassocLowAck",			NI_WPA_NIF_PROPERTY_DISASSOC_LOW_ACK			},
	{ "Interworking",			NI_WPA_NIF_PROPERTY_INTERWORKING			},
	{ "Hessid",				NI_WPA_NIF_PROPERTY_HESSID				},
	{ "AccessNetworkType",			NI_WPA_NIF_PROPERTY_ACCESS_NETWORK_TYPE			},
	{ "GoInterworking",			NI_WPA_NIF_PROPERTY_GO_INTERWORKING			},
	{ "GoAccessNetworkType",		NI_WPA_NIF_PROPERTY_GO_ACCESS_NETWORK_TYPE		},
	{ "GoInternet",				NI_WPA_NIF_PROPERTY_GO_INTERNET				},
	{ "GoVenueGroup",			NI_WPA_NIF_PROPERTY_GO_VENUE_GROUP			},
	{ "GoVenueType",			NI_WPA_NIF_PROPERTY_GO_VENUE_TYPE			},
	{ "PbcInM1",				NI_WPA_NIF_PROPERTY_PBC_IN_M1				},
	{ "Autoscan",				NI_WPA_NIF_PROPERTY_AUTOSCAN				},
	{ "WpsNfcDevPwId",			NI_WPA_NIF_PROPERTY_WPS_NFC_DEV_PW_ID			},
	{ "WpsNfcDhPubkey",			NI_WPA_NIF_PROPERTY_WPS_NFC_DH_PUB_KEY			},
	{ "WpsNfcDhPrivkey",			NI_WPA_NIF_PROPERTY_WPS_NFC_DH_PRIV_KEY			},
	{ "WpsNfcDevPw",			NI_WPA_NIF_PROPERTY_WPS_NFC_DEV_PW			},
	{ "ExtPasswordBackend",			NI_WPA_NIF_PROPERTY_EXT_PASSWORD_BACKEND		},
	{ "P2pGoMaxInactivity",			NI_WPA_NIF_PROPERTY_P2P_GO_MAX_INACTIVITY		},
	{ "AutoInterworking",			NI_WPA_NIF_PROPERTY_AUTO_INTERWORKING			},
	{ "Okc",				NI_WPA_NIF_PROPERTY_OKC					},
	{ "Pmf",				NI_WPA_NIF_PROPERTY_PMF					},
	{ "SaeGroups",				NI_WPA_NIF_PROPERTY_SAE_GROUPS				},
	{ "DtimPeriod",				NI_WPA_NIF_PROPERTY_DTIM_PERIOD				},
	{ "BeaconInt",				NI_WPA_NIF_PROPERTY_BEACON_INT				},
	{ "ApVendorElements",			NI_WPA_NIF_PROPERTY_AP_VENDOR_ELEMENTS			},
	{ "IgnoreOldScanRes",			NI_WPA_NIF_PROPERTY_IGNIRE_OLD_SCAN_RES			},
	{ "FreqList",				NI_WPA_NIF_PROPERTY_FREQ_LIST				},
	{ "ScanCurFreq",			NI_WPA_NIF_PROPERTY_SCAN_CUR_FREQ			},
	{ "SchedScanInterval",			NI_WPA_NIF_PROPERTY_SCHED_SCAN_INTERVAL			},
	{ "SchedScanStartDelay",		NI_WPA_NIF_PROPERTY_SCHED_SCAN_START_DELAY		},
	{ "TdlsExternalControl",		NI_WPA_NIF_PROPERTY_TDLS_EXTERNAL_CONTROL		},
	{ "OsuDir",				NI_WPA_NIF_PROPERTY_OSU_DIR				},
	{ "WowlanTriggers",			NI_WPA_NIF_PROPERTY_WOWLAN_TRIGGERS			},
	{ "P2pSearchDelay",			NI_WPA_NIF_PROPERTY_P2P_SEARCH_DELAY			},
	{ "MacAddr",				NI_WPA_NIF_PROPERTY_MAC_ADDR				},
	{ "RandAddrLifetime",			NI_WPA_NIF_PROPERTY_RAND_ADDR_LIFETIME			},
	{ "PreassocMacAddr",			NI_WPA_NIF_PROPERTY_PREASSOC_MAC_ADDR			},
	{ "KeyMgmtOffload",			NI_WPA_NIF_PROPERTY_KEY_MGMT_OFFLOAD			},
	{ "PassiveScan",			NI_WPA_NIF_PROPERTY_PASSIVE_SCAN			},
	{ "ReassocSameBssOptim",		NI_WPA_NIF_PROPERTY_REASSOC_SAME_BSS_OPTIM		},
	{ "WpsPriority",			NI_WPA_NIF_PROPERTY_WPS_PRIORITY			},
	{ "CertInCb",				NI_WPA_NIF_PROPERTY_CERT_IN_CB				},
	{ "WpaRscRelaxation",			NI_WPA_NIF_PROPERTY_WPA_RSC_RELAXATION			},
	{ "SchedScanPlans",			NI_WPA_NIF_PROPERTY_SCHED_SCAN_PLANS			},
	{ "GasAddress3",			NI_WPA_NIF_PROPERTY_GAS_ADDRESS3			},
	{ "FtmResponder",			NI_WPA_NIF_PROPERTY_FTM_RESPONDER			},
	{ "FtmInitiator",			NI_WPA_NIF_PROPERTY_FTM_INITIATOR			},
	{ "GasRandAddrLifetime",		NI_WPA_NIF_PROPERTY_GAS_RAND_ADDR_LIFETIME		},
	{ "GasRandMacAddr",			NI_WPA_NIF_PROPERTY_GAS_RAMD_MAC_ADDR			},
	{ "DppConfigProcessing",		NI_WPA_NIF_PROPERTY_DPP_CONFIG_PROCESSING		},
	{ "ColocIntfReporting",			NI_WPA_NIF_PROPERTY_COLOC_INTF_REPORTING		},

	{ NULL }
};

static const ni_intmap_t			ni_wpa_net_property_map[] =  {
	{ "ssid",				NI_WPA_NET_PROPERTY_SSID				},
	{ "scan_ssid",				NI_WPA_NET_PROPERTY_SCAN_SSID				},
	{ "bssid",				NI_WPA_NET_PROPERTY_BSSID				},
	{ "bssid_hint",				NI_WPA_NET_PROPERTY_BSSID_HINT				},
	{ "bssid_blacklist",			NI_WPA_NET_PROPERTY_BSSID_BLACKLIST			},
	{ "bssid_whitelist",			NI_WPA_NET_PROPERTY_BSSID_WHITELIST			},
	{ "psk",				NI_WPA_NET_PROPERTY_PSK					},
	{ "mem_only_psk",			NI_WPA_NET_PROPERTY_MEM_ONLY_PSK			},
	{ "sae_password",			NI_WPA_NET_PROPERTY_SAE_PASSWORD			},
	{ "sae_password_id",			NI_WPA_NET_PROPERTY_SAE_PASSWORD_ID			},
	{ "proto",				NI_WPA_NET_PROPERTY_PROTO				},
	{ "key_mgmt",				NI_WPA_NET_PROPERTY_KEY_MGMT				},
	{ "bg_scan_period",			NI_WPA_NET_PROPERTY_BG_SCAN_PERIOD			},
	{ "pairwise",				NI_WPA_NET_PROPERTY_PAIRWISE				},
	{ "group",				NI_WPA_NET_PROPERTY_GROUP				},
	{ "group_mgmt",				NI_WPA_NET_PROPERTY_GROUP_MGMT				},
	{ "auth_alg",				NI_WPA_NET_PROPERTY_AUTH_ALG				},
	{ "scan_freq",				NI_WPA_NET_PROPERTY_SCAN_FREQ				},
	{ "freq_list",				NI_WPA_NET_PROPERTY_FREQ_LIST				},
	{ "ht",					NI_WPA_NET_PROPERTY_HT					},
	{ "vht",				NI_WPA_NET_PROPERTY_VHT					},
	{ "ht40",				NI_WPA_NET_PROPERTY_HT40				},
	{ "max_oper_chwidth",			NI_WPA_NET_PROPERTY_MAX_OPER_CHWIDTH			},
	{ "vht_center_freq1",			NI_WPA_NET_PROPERTY_VHT_CENTER_FREQ1			},
	{ "vht_center_freq2",			NI_WPA_NET_PROPERTY_VHT_CENTER_FREQ2			},
	{ "engine",				NI_WPA_NET_PROPERTY_ENGINE				},
	{ "engine2",				NI_WPA_NET_PROPERTY_ENGINE2				},
	{ "eapol_flags",			NI_WPA_NET_PROPERTY_EAPOL_FLAGS				},
	{ "sim_num",				NI_WPA_NET_PROPERTY_SIM_NUM				},
	{ "erp",				NI_WPA_NET_PROPERTY_ERP					},
	{ "wep_tx_keyidx",			NI_WPA_NET_PROPERTY_WEP_TX_KEYIDX			},
	{ "wep_key0",				NI_WPA_NET_PROPERTY_WEP_KEY0				},
	{ "wep_key1",				NI_WPA_NET_PROPERTY_WEP_KEY1				},
	{ "wep_key2",				NI_WPA_NET_PROPERTY_WEP_KEY2				},
	{ "wep_key3",				NI_WPA_NET_PROPERTY_WEP_KEY3				},
	{ "priority",				NI_WPA_NET_PROPERTY_PRIORITY				},
	{ "eap_workaround",			NI_WPA_NET_PROPERTY_EAP_WORKAROUND			},
	{ "fragment_size",			NI_WPA_NET_PROPERTY_FRAGMENT_SIZE			},
	{ "ocsp",				NI_WPA_NET_PROPERTY_OCSP				},
	{ "mode",				NI_WPA_NET_PROPERTY_MODE				},
	{ "proactive_key_caching",		NI_WPA_NET_PROPERTY_PROACTIVE_KEY_CACHING		},
	{ "disabled",				NI_WPA_NET_PROPERTY_DISABLED				},
	{ "ieee80211w",				NI_WPA_NET_PROPERTY_IEEE80211W				},
	{ "peerkey",				NI_WPA_NET_PROPERTY_PEERKEY				},
	{ "mixed_cell",				NI_WPA_NET_PROPERTY_MIXED_CELL				},
	{ "frequency",				NI_WPA_NET_PROPERTY_FREQUENCY				},
	{ "fixed_freq",				NI_WPA_NET_PROPERTY_FIXED_FREQ				},
	{ "wpa_ptk_rekey",			NI_WPA_NET_PROPERTY_WPA_PTK_REKEY			},
	{ "group_rekey",			NI_WPA_NET_PROPERTY_GROUP_REKEY				},
	{ "ignore_broadcast_ssid",		NI_WPA_NET_PROPERTY_IGNORE_BROADCAST_SSID		},
	{ "ap_max_inactivity",			NI_WPA_NET_PROPERTY_AP_MAX_INACTIVITY			},
	{ "dtim_period",			NI_WPA_NET_PROPERTY_DTIM_PERIOD				},
	{ "beacon_int",				NI_WPA_NET_PROPERTY_BEACON_INT				},
	{ "mac_addr",				NI_WPA_NET_PROPERTY_MAC_ADDR				},
	{ "pbss",				NI_WPA_NET_PROPERTY_PBSS				},
	{ "fils_dh_group",			NI_WPA_NET_PROPERTY_FILS_DH_GROUP			},
	{ "owe_group",				NI_WPA_NET_PROPERTY_OWE_GROUP				},
	{ "owe_only",				NI_WPA_NET_PROPERTY_OWE_ONLY				},
	{ "multi_ap_backhaul_sta",		NI_WPA_NET_PROPERTY_MULTI_AP_BACKHAUL_STA		},
	{ "ft_eap_pmksa_caching",		NI_WPA_NET_PROPERTY_FT_EAP_PMKSA_CACHING		},
	{ "wps_disabled",			NI_WPA_NET_PROPERTY_WPS_DISABLED			},
	{ "eap",				NI_WPA_NET_PROPERTY_EAP					},
	{ "identity",				NI_WPA_NET_PROPERTY_IDENTITY				},
	{ "anonymous_identity",			NI_WPA_NET_PROPERTY_ANONYMOUS_IDENTITY			},
	{ "phase1",				NI_WPA_NET_PROPERTY_PHASE1				},
	{ "phase2",				NI_WPA_NET_PROPERTY_PHASE2				},
	{ "password",				NI_WPA_NET_PROPERTY_PASSWORD				},
	{ "ca_cert",				NI_WPA_NET_PROPERTY_CA_CERT				},
	{ "client_cert",			NI_WPA_NET_PROPERTY_CLIENT_CERT				},
	{ "private_key",			NI_WPA_NET_PROPERTY_PRIVATE_KEY				},
	{ "private_key_passwd",			NI_WPA_NET_PROPERTY_PRIVATE_KEY_PASSWD			},

	{ NULL }
};


static ni_wpa_client_t *
ni_wpa_client_open()
{
	ni_dbus_client_t *dbc;
	ni_wpa_client_t *wpa;

	dbc = ni_dbus_client_open("system", NI_WPA_BUS_NAME);
	if (!dbc){
		ni_error("unable to connect to wpa_supplicant");
		return NULL;
	}

	ni_dbus_client_set_error_map(dbc, ni_wpa_error_names);

	if (!(wpa = calloc(1, sizeof(*wpa)))){
		ni_error("Unable to create wpa client - out of memory");
		return NULL;
	}
	ni_wpa_client_properties_init(&wpa->properties);

	wpa->object = ni_dbus_client_object_new(dbc, &ni_objectmodel_wpa_class,
			NI_WPA_OBJECT_PATH, NI_WPA_INTERFACE, wpa);
	wpa->dbus = dbc;

	ni_dbus_client_add_signal_handler(dbc,
				NI_WPA_BUS_NAME,	/* sender */
				NULL,			/* object path */
				NI_WPA_INTERFACE,	/* object interface */
				ni_wpa_signal,
				wpa);

	ni_dbus_client_add_signal_handler(dbc,
				NI_WPA_BUS_NAME,	/* sender */
				NULL,			/* object path */
				NI_WPA_NIF_INTERFACE,	/* object interface */
				ni_wpa_nif_signal,
				wpa);

	ni_dbus_client_add_signal_handler(dbc,
				NI_DBUS_BUS_NAME,	/* sender */
				NULL,			/* object path */
				NI_DBUS_INTERFACE,	/* object interface */
				ni_wpa_dbus_signal,
				wpa);

	ni_wpa_client_refresh(wpa);

	return wpa;
}

ni_wpa_ops_handler_t*
ni_wpa_ops_handler_new(unsigned int ifindex)
{
	ni_wpa_ops_handler_t *handler;

	handler = calloc(1, sizeof(*handler));
	if (!handler) {
		ni_error("Unable to alloc wpa client ops_handler -- out of memory");
		return NULL;
	}
	handler->ifindex = ifindex;
	return handler;
}

void
ni_wpa_ops_handler_free(ni_wpa_ops_handler_t *handler)
{
	if (handler)
		free(handler);
}

void
ni_wpa_ops_handler_list_append(ni_wpa_ops_handler_t **list, ni_wpa_ops_handler_t *handler)
{
	while (*list)
		list = &(*list)->next;
	*list = handler;
}

ni_wpa_ops_handler_t *
ni_wpa_ops_handler_find(ni_wpa_ops_handler_t **list, unsigned int ifindex)
{
	ni_wpa_ops_handler_t *handler;

	for (handler = *list; handler; handler = handler->next) {
		if (handler->ifindex == ifindex)
			return handler;
	}
	return NULL;
}

ni_bool_t
ni_wpa_ops_handler_list_delete(ni_wpa_ops_handler_t **list, ni_wpa_ops_handler_t *handler)
{
	ni_wpa_ops_handler_t **pos, *cur;

	for (pos = list; (cur = *pos); pos = &cur->next) {
		if (cur == handler) {
			*pos = cur->next;
			cur->next = NULL;
			ni_wpa_ops_handler_free(cur);
			return TRUE;
		}
	}
	return FALSE;
}

ni_bool_t
ni_wpa_client_set_ops(unsigned int ifindex, ni_wpa_client_ops_t* ops)
{
	ni_wpa_client_t *wpa = ni_wpa_client();
	ni_wpa_ops_handler_t *new;

	if (ni_wpa_ops_handler_find(&wpa->ops_handler_list, ifindex))
		return TRUE;

	new = ni_wpa_ops_handler_new(ifindex);
	if (!new)
		return FALSE;
	new->ops = *ops;

	ni_wpa_ops_handler_list_append(&wpa->ops_handler_list, new);
	return TRUE;
}

ni_bool_t
ni_wpa_client_del_ops(unsigned int ifindex)
{
	ni_wpa_client_t *wpa = ni_wpa_client();
	ni_wpa_ops_handler_t *handler;

	if ((handler = ni_wpa_ops_handler_find(&wpa->ops_handler_list, ifindex)))
		return ni_wpa_ops_handler_list_delete(&wpa->ops_handler_list, handler);

	return FALSE;
}

#if 0
static void
ni_wpa_client_free(ni_wpa_client_t *wpa)
{
	ni_wpa_nif_t *wif;
	ni_wpa_ops_handler_t *handler;

	if (wpa->dbus) {
		ni_dbus_client_free(wpa->dbus);
		wpa->dbus = NULL;
	}

	while ((wif = wpa->nifs) != NULL) {
		wpa->nifs = wif->next;
		wif->next = NULL;
		wif->client = NULL;
		ni_wpa_nif_free(wif);
	}

	ni_wpa_client_properties_destroy(&wpa->properties);

	while ((handler = wpa->ops_handler_list) != NULL)
		ni_wpa_ops_handler_list_delete(&wpa->ops_handler_list, handler);

	if (wpa->object) {
		ni_dbus_object_free(wpa->object);
		wpa->object = NULL;
	}

	free(wpa);
}
#endif

ni_wpa_client_t *
ni_wpa_client()
{
	if (!wpa_client)
		wpa_client = ni_wpa_client_open();
	return wpa_client;
}


ni_dbus_client_t *
ni_wpa_client_dbus(ni_wpa_client_t *wpa)
{
	return wpa->dbus;
}

static ni_wpa_client_t *
ni_objectmodel_wpa_client_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_wpa_client_t *wpa;

	if (!object) {
		if (error)
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Cannot unwrap wpa client interface from a NULL dbus object");
		return NULL;
	}

	wpa = object->handle;
	if (ni_dbus_object_isa(object, &ni_objectmodel_wpa_class))
		return wpa;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot unwrap wpa client interface from incompatible object %s of class %s",
				object->path, object->class->name);
	return NULL;
}

static void *
ni_objectmodel_get_wpa_client_properties(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_wpa_client_t *wpa = NULL;
	ni_wpa_client_properties_t *props = NULL;

	if ((wpa = ni_objectmodel_wpa_client_unwrap(object, error)))
		props = &wpa->properties;

	return props;

}

const ni_dbus_property_t	ni_objectmodel_wpa_client_properties[] =  {
	NI_DBUS_GENERIC_STRING_PROPERTY(wpa_client_properties, DebugLevel, debug_level, RO),
	NI_DBUS_GENERIC_BOOL_PROPERTY(wpa_client_properties, DebugTimestamp, debug_timestamp, RO),
	NI_DBUS_GENERIC_BOOL_PROPERTY(wpa_client_properties, DebugShowKeys, debug_show_keys, RO),
	NI_DBUS_GENERIC_OBJECT_PATH_ARRAY_PROPERTY(wpa_client_properties, Interfaces, interfaces, RO),
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(wpa_client_properties, EapMethods, eap_methods, RO),
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(wpa_client_properties, Capabilities, capabilities, RO),
	NI_DBUS_GENERIC_BYTE_ARRAY_PROPERTY(wpa_client_properties, WFDIEs, wfdies, RO),
	{ NULL }
};

static const ni_dbus_service_t	ni_objectmodel_wpa_client_service = {
	.name		= NI_WPA_BUS_NAME,
	.properties	= ni_objectmodel_wpa_client_properties
};

static void
ni_wpa_client_properties_destroy(ni_wpa_client_properties_t *props)
{
	ni_string_free(&props->debug_level);
	ni_string_array_destroy(&props->interfaces);
	ni_string_array_destroy(&props->eap_methods);
	ni_string_array_destroy(&props->capabilities);
	ni_byte_array_destroy(&props->wfdies);
}

static void
ni_wpa_client_properties_init(ni_wpa_client_properties_t *props)
{
	memset(props, 0, sizeof(*props));
	ni_string_array_init(&props->interfaces);
	ni_string_array_init(&props->eap_methods);
	ni_string_array_init(&props->capabilities);
	ni_byte_array_init(&props->wfdies);
}

static int
ni_wpa_client_refresh(ni_wpa_client_t *wpa)
{
	DBusError error = DBUS_ERROR_INIT;
	int rv = -NI_ERROR_DBUS_CALL_FAILED;

	if (!wpa || !wpa->object)
		return -NI_ERROR_INVALID_ARGS;

	if (!ni_dbus_object_refresh_properties(wpa->object, &ni_objectmodel_wpa_client_service, &error)) {
		if (dbus_error_is_set(&error))
			rv = ni_dbus_client_translate_error(ni_wpa_client_dbus(wpa), &error);
		return rv;
	}

	if (ni_debug_guard(NI_LOG_DEBUG, NI_TRACE_WPA)) {
		unsigned int i;
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
		ni_wpa_client_properties_t *props = &wpa->properties;
		const char *interface = ni_dbus_object_get_default_interface(wpa->object);

		ni_debug_wpa("%s: Property DebugLevel=%s", interface,
				props->debug_level ?: "");
		ni_debug_wpa("%s: Property DebugTimestamp=%s", interface,
				props->debug_timestamp ? "true" : "false");
		ni_debug_wpa("%s: Property DebugShowKeys=%s", interface,
				props->debug_show_keys ? "true" : "false");
		ni_debug_wpa("%s: Property Interfaces=%s", interface,
				ni_stringbuf_join(&buf, &props->interfaces, ", "));
		ni_stringbuf_truncate(&buf, 0);
		ni_debug_wpa("%s: Property EapMethods=%s", interface,
				ni_stringbuf_join(&buf, &props->eap_methods, ", "));
		ni_stringbuf_truncate(&buf, 0);
		ni_debug_wpa("%s: Property Capabilities=%s", interface,
				ni_stringbuf_join(&buf, &props->capabilities, ", "));
		ni_stringbuf_truncate(&buf, 0);
		for (i = 0; i < props->wfdies.len; i++)
			ni_stringbuf_printf(&buf, "%02hhx ", props->wfdies.data[i]);
		ni_debug_wpa("%s: Property WFDIEs=%s", interface, buf.string ?: "");
		ni_stringbuf_destroy(&buf);
	}
	return NI_SUCCESS;
}

ni_bool_t
ni_wpa_client_has_capability(ni_wpa_client_t *wpa, const char *capability)
{
	if (!wpa && !(wpa = ni_wpa_client()))
		return FALSE;

	return ni_string_array_index(&wpa->properties.capabilities, capability) != -1;
}

static ni_bool_t
ni_wpa_nif_list_add(ni_wpa_client_t *wpa, ni_wpa_nif_t *wif)
{
	if (!wpa || !wif || wif->client)
		return FALSE;

	wif->client = wpa;
	wif->next = wpa->nifs;
	wpa->nifs = wif;

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_WPA,
			"%s: interface %p device %s added",
			__func__, wif, wif ? wif->device.name : NULL);
	return TRUE;
}

static ni_bool_t
ni_wpa_nif_list_remove(ni_wpa_client_t *wpa, ni_wpa_nif_t *wif)
{
	ni_wpa_nif_t **pos, *cur;

	if (!wpa || !wif)
		return FALSE;

	for (pos = &wpa->nifs; (cur = *pos); pos =  &cur->next) {
		if (wif == cur) {
			*pos =  cur->next;
			cur->next = NULL;
			cur->client = NULL;
			ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_WPA,
					"%s: interface %p device %s removed",
					__func__, wif, wif ? wif->device.name : NULL);
			return TRUE;
		}
	}
	return FALSE;
}

ni_wpa_nif_t *
ni_wpa_nif_by_index(ni_wpa_client_t *wpa, unsigned int ifindex)
{
	ni_wpa_nif_t *wif;

	for (wif = wpa->nifs; wif; wif = wif->next) {
		if (wif->device.index == ifindex)
			return wif;
	}
	return NULL;
}

ni_wpa_nif_t *
ni_wpa_nif_by_path(ni_wpa_client_t *wpa, const char *object_path)
{
	ni_wpa_nif_t *wif;

	for (wif = wpa->nifs; wif; wif = wif->next) {
		ni_dbus_object_t *obj = wif->object;

		if (obj && ni_string_eq(obj->path, object_path))
			return wif;
	}
	return NULL;
}

static ni_wpa_nif_t *
ni_wpa_nif_new(ni_wpa_client_t *wpa, const char *ifname, unsigned int ifindex)
{
	ni_wpa_nif_t *wif;

	if (!(wif = calloc(1, sizeof(*wif)))) {
		ni_error("%s: Unable to alloc wpa interface -- out of memory", ifname);
		return NULL;
	}
	ni_netdev_ref_set(&wif->device, ifname, ifindex);

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_WPA,
			"%s: interface %p device %s allocated",
			__func__, wif, wif ? wif->device.name : NULL);

	if (!wpa || ni_wpa_nif_list_add(wpa, wif))
		return wif;

	ni_wpa_nif_free(wif);
	return NULL;
}

void
ni_wpa_nif_set_ops(ni_wpa_nif_t *wif, ni_wpa_nif_ops_t *ops)
{
	ni_wpa_nif_ops_t null_ops = { 0 };

	if (!wif || !ops)
		return;

	/* The ops should not be changed once they are set! */
	ni_assert(memcmp(&wif->ops, &null_ops, sizeof(ni_wpa_nif_ops_t)) == 0 ||
			memcmp(&wif->ops, ops, sizeof(ni_wpa_nif_ops_t)) == 0);
	wif->ops = *ops;
}

const char *
ni_wpa_nif_capability_name(ni_wpa_nif_capability_type_t type)
{
	return ni_format_uint_mapped(type, ni_wpa_nif_capability_map);
}

ni_bool_t
ni_wpa_nif_capability_type(const char *name, ni_wpa_nif_capability_type_t *type)
{
	if (!type || ni_parse_uint_mapped(name, ni_wpa_nif_capability_map, type) < 0)
		return FALSE;
	return TRUE;
}

static void
ni_wpa_nif_capabilities_destroy(ni_wpa_nif_capabilities_t *capabilities)
{
	if (capabilities) {
		ni_string_array_destroy(&capabilities->pairwise);
		ni_string_array_destroy(&capabilities->group);
		ni_string_array_destroy(&capabilities->group_mgmt);
		ni_string_array_destroy(&capabilities->key_mgmt);
		ni_string_array_destroy(&capabilities->protocol);
		ni_string_array_destroy(&capabilities->auth_alg);
		ni_string_array_destroy(&capabilities->scan);
		ni_string_array_destroy(&capabilities->modes);
		capabilities->max_scan_ssid = 0;
	}
}

const char *
ni_wpa_nif_property_name(ni_wpa_nif_property_type_t type)
{
	return ni_format_uint_mapped(type, ni_wpa_nif_property_map);
}

ni_bool_t
ni_wpa_nif_property_type(const char *name, ni_wpa_nif_property_type_t *type)
{
	if (!type || ni_parse_uint_mapped(name, ni_wpa_nif_property_map, type) < 0)
		return FALSE;
	return TRUE;
}

static void
ni_wpa_nif_properties_init(ni_wpa_nif_properties_t *properties)
{
	memset(properties, 0, sizeof(*properties));
}

static void
ni_wpa_nif_properties_destroy(ni_wpa_nif_properties_t *properties)
{
	if (properties) {
		ni_string_free(&properties->ifname);
		ni_string_free(&properties->bridge);
		ni_string_free(&properties->driver);
		ni_string_free(&properties->country);
		ni_string_free(&properties->current_network_path);
		ni_string_free(&properties->current_bss_path);
		ni_string_array_destroy(&properties->network_paths);
		ni_string_array_destroy(&properties->bss_paths);
		ni_string_free(&properties->current_auth_mode);

		ni_wpa_nif_properties_init(properties);
	}
}

static void
ni_wpa_nif_free(ni_wpa_nif_t *wif)
{
	if (wif) {
		ni_dbus_object_t *object = wif->object;

		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_WPA,
				"%s: interface %p device %s",
				__func__, wif, wif ? wif->device.name : NULL);

		/* release binding with dbus object */
		wif->object = NULL;
		if (object) {
			/*
			 * clear pointer to object and back,
			 * so destructor does not call us...
			 */
			object->handle = NULL;
			ni_dbus_object_free(object);
		}

		/* release binding with wpa client  */
		ni_wpa_nif_list_remove(wif->client, wif);
		wif->client = NULL;

		/* release member data and ourself  */
		ni_netdev_ref_destroy(&wif->device);
		ni_wpa_nif_properties_destroy(&wif->properties);
		ni_wpa_nif_capabilities_destroy(&wif->capabilities);
		ni_wpa_bss_list_destroy(&wif->bsss);
		free(wif);
	}
}

static ni_dbus_object_t *
ni_objectmodel_wpa_nif_object_new(ni_wpa_client_t *wpa, ni_wpa_nif_t *wif, const char *object_path)
{
	ni_dbus_object_t *object;

	if (!wpa || !wpa->object || ni_string_empty(object_path))
		return NULL;

	object = ni_dbus_object_create(wpa->object, object_path,
			&ni_objectmodel_wpa_nif_class, wif);

	if (object) {
		ni_dbus_object_set_default_interface(object, NI_WPA_NIF_INTERFACE);
		if (wif)
			wif->object = object;
		ni_debug_wpa("Created wpa interface object with object-path: %s", object_path);
	}
	return object;
}

static int
ni_wpa_nif_refresh(ni_wpa_nif_t *wif)
{
	DBusError error = DBUS_ERROR_INIT;
	int rv = -NI_ERROR_DBUS_CALL_FAILED;

	if (!wif || !wif->object)
		return -NI_ERROR_INVALID_ARGS;

	if (!ni_dbus_object_refresh_properties(wif->object, &ni_objectmodel_wpa_nif_service, &error)) {
		if (dbus_error_is_set(&error))
			rv = ni_dbus_client_translate_error(ni_wpa_client_dbus(wif->client), &error);
		return rv;
	} else {
		ni_timer_get_time(&wif->acquired);
		return 0;
	}
}

void ni_wpa_nif_init_bsss(ni_wpa_nif_t * wif)
{
	size_t i;

	if (wif->properties.current_bss_path)
		ni_wpa_nif_find_or_create_bss(wif, wif->properties.current_bss_path);

	for(i=0; i < wif->properties.bss_paths.count; i++){
		ni_wpa_nif_find_or_create_bss(wif, wif->properties.bss_paths.data[i]);
	}

	ni_wpa_nif_refresh_all_bss(wif);
}

/*
 * Obtain object handle for an interface
 */
int
ni_wpa_get_interface(ni_wpa_client_t *wpa, const char *ifname, unsigned int ifindex, ni_wpa_nif_t **result_p)
{
	static const char *method = "GetInterface";
	ni_wpa_nif_t *wif = NULL;
	const char *interface = NULL;
	char *object_path = NULL;
	int rv = -NI_ERROR_GENERAL_FAILURE;

	if (!wpa || !ifindex || ni_string_empty(ifname) || !result_p)
		return -NI_ERROR_INVALID_ARGS;

	interface = ni_dbus_object_get_default_interface(wpa->object);
	ni_debug_wpa("Calling %s.%s(%s)", interface, method, ifname);

	rv = ni_dbus_object_call_simple(wpa->object, interface, method,
			DBUS_TYPE_STRING,	&ifname,
			DBUS_TYPE_OBJECT_PATH,	&object_path);
	if (rv < 0)
		goto failed;

	ni_debug_wpa("Call to %s.%s(%s) returned object-path: %s",
			interface, method, ifname, object_path);

	wif = ni_wpa_nif_by_path(wpa, object_path);
	if (wif) {
		ni_netdev_ref_set(&wif->device, ifname, ifindex);
	} else {
		if (!(wif = ni_wpa_nif_new(wpa, ifname, ifindex))) {
			rv = -NI_ERROR_GENERAL_FAILURE;
			goto failed;
		}
	}

	if (!wif->object && !ni_objectmodel_wpa_nif_object_new(wpa, wif, object_path)) {
		ni_debug_wpa("Failed to create wpa interface object with object-path: %s", object_path);
		rv = -NI_ERROR_GENERAL_FAILURE;
		goto failed;
	}

	if (!timerisset(&wif->acquired)) {
		rv = ni_wpa_nif_refresh(wif);
		if (rv < 0)
			goto failed;

		ni_wpa_nif_init_bsss(wif);
	}

	ni_string_free(&object_path);
	*result_p = wif;
	return 0;

failed:
	ni_wpa_nif_free(wif);
	ni_string_free(&object_path);
	return rv;
}

int
ni_wpa_add_interface(ni_wpa_client_t *wpa, unsigned int ifindex,
			ni_dbus_variant_t *arg, ni_wpa_nif_t **result_p)
{
	static const char *method = "CreateInterface";
	ni_dbus_message_t *call = NULL, *reply = NULL;
	ni_dbus_variant_t resp = NI_DBUS_VARIANT_INIT;
	const char *ifname, *name;
	DBusError error = DBUS_ERROR_INIT;
	ni_wpa_nif_t *wif;
	const char *interface = NULL;
	const char *object_path = NULL;
	int rv = -1;

	name = ni_wpa_nif_property_name(NI_WPA_NIF_PROPERTY_IFNAME);
	if (!wpa || !ifindex || !arg || !name || !ni_dbus_dict_get_string(arg, name, &ifname) || !result_p)
		return -NI_ERROR_INVALID_ARGS;

	wif = ni_wpa_nif_by_index(wpa, ifindex);
	if (wif)
		return -NI_ERROR_DEVICE_EXISTS;

	interface = ni_dbus_object_get_default_interface(wpa->object);
	ni_debug_wpa("Calling %s.%s(%s)", interface, method, ifname);

	if (!ni_dbus_object_call_variant(wpa->object, interface, method,
					1, arg, 1, &resp, &error)) {
		ni_error("%s: dbus call %s.%s() failed (%s: %s)", ifname,
				ni_dbus_object_get_path(wpa->object), method,
				error.name, error.message);
		rv = -NI_ERROR_INVALID_ARGS;
		goto cleanup;
	}

	if (!ni_dbus_variant_get_object_path(&resp, &object_path)) {
		ni_error("%s: unexpected result in reply to %s.%s()", ifname,
				ni_dbus_object_get_path(wpa->object), method);
		rv = -NI_ERROR_INVALID_ARGS;
		goto cleanup;
	}

	ni_debug_wpa("Call to %s.%s(%s) returned object-path: %s",
			interface, method, ifname, object_path);

	wif = ni_wpa_nif_by_path(wpa, object_path);
	if (wif) {
		/*
		 * InterfaceAdded signal created it before CreateInterface returned
		 * the object-path, so we just need to bind the device reference...
		 */
		ni_netdev_ref_set(&wif->device, ifname, ifindex);
	} else {
		if (!(wif = ni_wpa_nif_new(wpa, ifname, ifindex))) {
			ni_error("%s: unable to allocate new interface structure for %s", ifname, object_path);
			rv = -NI_ERROR_GENERAL_FAILURE;
			goto cleanup;
		}

		if (!ni_objectmodel_wpa_nif_object_new(wpa, wif, object_path)) {
			ni_debug_wpa("%s: failed to create wpa interface object with object-path: %s", ifname, object_path);
			rv = -NI_ERROR_GENERAL_FAILURE;
			goto cleanup;
		}

		if (!timerisset(&wif->acquired)) {
			rv = ni_wpa_nif_refresh(wif);
			if (rv < 0)
				goto cleanup;
		}
	}

	ni_debug_wpa("%s: bound new wpa interface %s to wicked interface with ifindex %u",
			ifname, object_path, ifindex);

	*result_p = wif;
	rv = 0;

cleanup:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	ni_dbus_variant_destroy(&resp);

	if (rv != 0 && wif)
		ni_wpa_nif_free(wif);

	return rv;
}

int
ni_wpa_del_interface(ni_wpa_client_t *wpa, const char *object_path)
{
	static const char *method = "RemoveInterface";
	const char *interface = NULL;
	char *path = NULL;
	int rv = -1;

	if (!wpa || ni_string_empty(object_path))
		return -NI_ERROR_INVALID_ARGS;

	/* copy the path in case it is wif->object->path;
	 * wif gets deleted before call returns
	 */
	if (!ni_string_dup(&path, object_path))
		return -NI_ERROR_GENERAL_FAILURE;

	interface = ni_dbus_object_get_default_interface(wpa->object);
	ni_debug_wpa("Calling %s.%s(%s)", interface, method, path);

	rv = ni_dbus_object_call_simple(wpa->object, interface, method,
			DBUS_TYPE_OBJECT_PATH,	&path,
			DBUS_TYPE_INVALID,	NULL);

	if (rv && rv != -NI_ERROR_DEVICE_NOT_KNOWN) {
		ni_error("Unable to delete wpa interface with the path %s: %s",
				path, ni_strerror(rv));
	} else {
		ni_debug_wpa("Call to %s.%s(%s) returned success",
			interface, method, path);
		rv = 0;
	}
	ni_string_free(&path);
	return rv;
}

int
ni_wpa_nif_set_properties(ni_wpa_nif_t *wif, const ni_dbus_variant_t *properties)
{
	DBusError error = DBUS_ERROR_INIT;
	unsigned int i;
	int err = 0;

	if (!wif || !properties || !ni_dbus_variant_is_dict(properties))
		return -NI_ERROR_INVALID_ARGS;

	for (i=0; i < properties->array.len; i++) {
		ni_dbus_dict_entry_t * e = &properties->dict_array_value[i];

		if (!ni_dbus_object_send_property(wif->object, NI_WPA_NIF_INTERFACE,
						e->key, &e->datum, &error)) {
			ni_error("%s failed: %s (%s)", __func__, error.name, error.message);
			dbus_error_free(&error);
			err = -1;
			continue;
		}
	}
	return err;
}


int
ni_wpa_net_set_property_enabled(ni_wpa_nif_t *wif, const char *path, ni_bool_t enabled)
{
	const char *name = "Enabled";
	char *path_cpy = NULL;
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_object_t dummy;
	ni_dbus_variant_t variant = NI_DBUS_VARIANT_INIT;
	ni_dbus_variant_t *value;
	int err = NI_SUCCESS;

	if (!ni_string_dup(&path_cpy, path))
		return NI_ERROR_GENERAL_FAILURE;

	value = ni_dbus_variant_init_variant(&variant);
	ni_dbus_variant_set_bool(value, enabled);

	memset(&dummy, 0, sizeof(dummy));
	dummy.client_object = wif->object->client_object;
	dummy.path = path_cpy;

	ni_debug_wpa("%s: Calling %s.Enabled(%d)", wif->device.name, dummy.path, enabled);
	if (!ni_dbus_object_send_property(&dummy, NI_WPA_NET_INTERFACE,	name, &variant, &error)) {
		ni_error("%s Enable network failed: %s (%s)", __func__, error.name, error.message);
		err = -NI_ERROR_GENERAL_FAILURE;
	}

	ni_dbus_variant_destroy(&variant);
	ni_string_free(&path_cpy);

	return err;
}

int
ni_wpa_nif_set_all_networks_property_enabled(ni_wpa_nif_t *wif, ni_bool_t enable)
{
	unsigned int i;
	int ret = NI_SUCCESS;
	ni_string_array_t *paths = &wif->properties.network_paths;

	for(i =0; i < paths->count; i++){
		if (ni_wpa_net_set_property_enabled(wif, ni_string_array_at(paths, i), enable) != NI_SUCCESS){
			ret = -NI_ERROR_GENERAL_FAILURE;
		}
	}
	return ret;
}

static ni_bool_t
ni_debug_escape_net_property(const char *prop_name)
{
	ni_wpa_net_property_type_t type;
	size_t i;
	ni_wpa_net_property_type_t escape_props[] = {
		NI_WPA_NET_PROPERTY_PSK,
		NI_WPA_NET_PROPERTY_SAE_PASSWORD,
		NI_WPA_NET_PROPERTY_WEP_KEY0,
		NI_WPA_NET_PROPERTY_WEP_KEY1,
		NI_WPA_NET_PROPERTY_WEP_KEY2,
		NI_WPA_NET_PROPERTY_WEP_KEY3,
		NI_WPA_NET_PROPERTY_PASSWORD
	};

	if (!ni_wpa_net_property_type(prop_name, &type))
		return FALSE;

	for (i=0; i < (sizeof(escape_props)/sizeof(*escape_props)); i++) {
		if (type == escape_props[i])
			return TRUE;
	}
	return FALSE;
}

void
ni_debug_wpa_print_network_properties(const char *devname, const ni_wpa_net_properties_t *conf)
{
	size_t i;
	const char *escape_string = "***";
	ni_stringbuf_t sbuf = NI_STRINGBUF_INIT_DYNAMIC;

	if (!ni_debug_guard(NI_LOG_DEBUG, NI_TRACE_WPA))
		return;

	if (!ni_dbus_variant_is_dict(conf)) {
		ni_error("Unable to print wpa network properties");
		return;
	}

	ni_debug_wpa("%s: Network properties {", devname);
	for (i=0; i < conf->array.len; i++){
		ni_dbus_dict_entry_t * e = &conf->dict_array_value[i];
		const char *value = NULL;
		if (ni_string_eq(e->key, ni_wpa_net_property_name(NI_WPA_NET_PROPERTY_SSID)))
			value = ni_wireless_ssid_print_data(e->datum.byte_array_value, e->datum.array.len, &sbuf);
		else if (ni_debug_escape_net_property(e->key))
			value = escape_string;
		else
			value = ni_dbus_variant_sprint(&e->datum);

		ni_debug_wpa("%s:     %-10s: %s", devname, e->key, value);
		ni_stringbuf_destroy(&sbuf);
	}
	ni_debug_wpa("%s: }", devname);
}

int
ni_wpa_nif_add_network(ni_wpa_nif_t *wif, const ni_wpa_net_properties_t *conf, ni_stringbuf_t *path)
{
	static const char *method = "AddNetwork";
	ni_dbus_variant_t resp = NI_DBUS_VARIANT_INIT;
	int err = -NI_ERROR_GENERAL_FAILURE;
	DBusError error = DBUS_ERROR_INIT;
	const char *object_path = NULL;
	const char *interface = NULL;

	if (!wif || !wif->object || !conf)
		return -NI_ERROR_INVALID_ARGS;

	interface = ni_dbus_object_get_default_interface(wif->object);
	ni_debug_wpa("%s: Calling %s.%s()", wif->device.name, interface, method);
	ni_debug_wpa_print_network_properties(wif->device.name, conf);

	err = -NI_ERROR_DBUS_CALL_FAILED;
	if (!ni_dbus_object_call_variant(wif->object, interface, method,
					1, (ni_dbus_variant_t*)conf, 1, &resp, &error)) {
		ni_error("%s: dbus call %s.%s() failed (%s: %s)", wif->device.name,
				ni_dbus_object_get_path(wif->object), method,
				error.name, error.message);

		if (dbus_error_is_set(&error))
			err = ni_dbus_client_translate_error(ni_wpa_client_dbus(wif->client), &error);

		goto cleanup;
	}

	if (!ni_dbus_variant_get_object_path(&resp, &object_path)) {
		ni_error("%s: unexpected result in reply to %s.%s()", wif->device.name,
				ni_dbus_object_get_path(wif->object), method);
		goto cleanup;
	}

	ni_debug_wpa("Call to %s.%s(%s) returned object-path: %s",
			interface, method, wif->device.name, object_path);

	if (ni_string_array_index(&wif->properties.network_paths, object_path) < 0)
		ni_string_array_append(&wif->properties.network_paths, object_path);

	if (path)
		ni_stringbuf_puts(path, object_path);

	err = NI_SUCCESS;
cleanup:
	dbus_error_free(&error);
	ni_dbus_variant_destroy(&resp);
	return err;
}


int
ni_wpa_nif_del_all_networks(ni_wpa_nif_t *wif)
{
	static const char *method = "RemoveAllNetworks";
	const char *interface = NULL;
	int err = -NI_ERROR_GENERAL_FAILURE;

	if (!wif || !wif->object)
		return -NI_ERROR_INVALID_ARGS;

	interface = ni_dbus_object_get_default_interface(wif->object);
	ni_debug_wpa("%s: Calling %s.%s()", wif->device.name, interface, method);

	err = ni_dbus_object_call_simple(wif->object, interface, method,
			DBUS_TYPE_INVALID,	NULL,
			DBUS_TYPE_INVALID,	NULL);
	if (err){
		ni_error("%s: Unable to delete all networks from interface: %s",
				wif->device.name, ni_strerror(err));
	} else {
		ni_debug_wpa("%s: Call to %s.%s() returned success",
				wif->device.name, interface, method);

		/* Refresh properties, cause we do not get NetworkRemoved signals */
		err = ni_wpa_nif_refresh(wif);
	}

	return err;
}

int
ni_wpa_nif_flush_bss(ni_wpa_nif_t *wif, uint32_t max_age)
{
	static const char *method = "FlushBSS";
	const char *interface = NULL;
	int err = -NI_ERROR_GENERAL_FAILURE;

	if (!wif || !wif->object)
		return -NI_ERROR_INVALID_ARGS;

	interface = ni_dbus_object_get_default_interface(wif->object);
	ni_debug_wpa("%s: Calling %s.%s()", wif->device.name, interface, method);

	err = ni_dbus_object_call_simple(wif->object, interface, method,
			DBUS_TYPE_UINT32,	&max_age,
			DBUS_TYPE_INVALID,	NULL);
	if (err){
		ni_error("%s: Unable to flush BSS from interface: %s",
				wif->device.name, ni_strerror(err));
	} else {
		ni_debug_wpa("%s: Call to %s.%s() returned success",
				wif->device.name, interface, method);
		err = NI_SUCCESS;
	}

	return err;
}

int
ni_wpa_nif_del_network(ni_wpa_nif_t *wif, const char *object_path)
{
	static const char *method = "RemoveNetwork";
	const char *interface = NULL;
	char *path = NULL;
	int err = -NI_ERROR_GENERAL_FAILURE;

	if (!wif || !wif->object || ni_string_empty(object_path))
		return -NI_ERROR_INVALID_ARGS;

	/*
	 * copy the path in case it is net->object-path;
	 * net gets deleted before the call returns
	 */
	if (!ni_string_dup(&path, object_path))
		return -NI_ERROR_GENERAL_FAILURE;

	interface = ni_dbus_object_get_default_interface(wif->object);
	ni_debug_wpa("%s: Calling %s.%s(%s)", wif->device.name, interface, method, path);

	err = ni_dbus_object_call_simple(wif->object, interface, method,
			DBUS_TYPE_OBJECT_PATH,	&path,
			DBUS_TYPE_INVALID,	NULL);
	if (err && err != -NI_ERROR_PROPERTY_NOT_PRESENT) {
		ni_error("%s: Unable to delete wpa network with path %s from interface: %s",
				wif->device.name, path, ni_strerror(err));
	} else {
		ni_debug_wpa("%s: Call to %s.%s(%s) returned success",
				wif->device.name, interface, method, path);
		err = NI_SUCCESS;
	}

	ni_string_free(&path);
	return err;
}

int
ni_wpa_nif_add_blob(ni_wpa_nif_t *wif, const char *name, unsigned const char *data, size_t len)
{
	static const char *method = "AddBlob";
	ni_dbus_variant_t args[2] = { NI_DBUS_VARIANT_INIT, NI_DBUS_VARIANT_INIT };
	int err = -NI_ERROR_GENERAL_FAILURE;
	DBusError error = DBUS_ERROR_INIT;
	const char *interface = NULL;

	if (!wif || !wif->object || !name || !data)
		return -NI_ERROR_INVALID_ARGS;

	ni_dbus_variant_set_string(&args[0], name);
	ni_dbus_variant_set_byte_array(&args[1], data, len);

	interface = ni_dbus_object_get_default_interface(wif->object);
	ni_debug_wpa("%s: Calling %s.%s(%s, len=%zu)", wif->device.name, interface, method, name, len);

	err = -NI_ERROR_DBUS_CALL_FAILED;
	if (!ni_dbus_object_call_variant(wif->object, interface, method,
					2, args, 0, NULL, &error)) {
		ni_error("%s: dbus call %s.%s(%s, len=%zu) failed (%s: %s)", wif->device.name,
				ni_dbus_object_get_path(wif->object), method, name, len,
				error.name, error.message);

		if (dbus_error_is_set(&error))
			err = ni_dbus_client_translate_error(ni_wpa_client_dbus(wif->client), &error);

		goto cleanup;
	}

	err = NI_SUCCESS;
cleanup:
	dbus_error_free(&error);
	ni_dbus_variant_destroy(&args[0]);
	ni_dbus_variant_destroy(&args[1]);
	return err;
}

int
ni_wpa_nif_remove_blob(ni_wpa_nif_t *wif, const char *name)
{
	static const char *method = "RemoveBlob";
	const char *interface = NULL;

	if (!wif || !wif->object || !name)
		return -NI_ERROR_INVALID_ARGS;

	interface = ni_dbus_object_get_default_interface(wif->object);
	ni_debug_wpa("%s: Calling %s.%s(%s)", wif->device.name, interface, method, name);

	return ni_dbus_object_call_simple(wif->object, interface, method,
			DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID, NULL);
}

int
ni_wpa_nif_get_blob(ni_wpa_nif_t *wif, const char *name, unsigned char **data, size_t *len)
{
	static const char *method = "GetBlob";
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	ni_dbus_variant_t resp = NI_DBUS_VARIANT_INIT;
	int err = -NI_ERROR_GENERAL_FAILURE;
	DBusError error = DBUS_ERROR_INIT;
	const char *interface = NULL;

	if (!wif || !wif->object || !name || !data)
		return -NI_ERROR_INVALID_ARGS;

	ni_dbus_variant_set_string(&arg, name);

	interface = ni_dbus_object_get_default_interface(wif->object);
	ni_debug_wpa("%s: Calling %s.%s(%s)", wif->device.name, interface, method, name);

	err = -NI_ERROR_DBUS_CALL_FAILED;
	if (!ni_dbus_object_call_variant(wif->object, interface, method,
					1, &arg, 1, &resp, &error)) {
		ni_error("%s: dbus call %s.%s(%s) failed (%s: %s)", wif->device.name,
				ni_dbus_object_get_path(wif->object), method, name,
				error.name, error.message);

		if (dbus_error_is_set(&error))
			err = ni_dbus_client_translate_error(ni_wpa_client_dbus(wif->client), &error);

		goto cleanup;
	}

	if (!ni_dbus_variant_is_byte_array(&resp)) {
		err = -NI_ERROR_DBUS_CALL_FAILED;
		goto cleanup;
	}

	if (!(*data = malloc(resp.array.len))) {
		err = -NI_ERROR_GENERAL_FAILURE;
		goto cleanup;
	}

	memcpy(*data, resp.byte_array_value, resp.array.len);
	*len = resp.array.len;

	err = NI_SUCCESS;
cleanup:
	dbus_error_free(&error);
	ni_dbus_variant_destroy(&arg);
	ni_dbus_variant_destroy(&resp);
	return err;
}

const char *
ni_wpa_net_property_name(ni_wpa_net_property_type_t type)
{
	return ni_format_uint_mapped(type, ni_wpa_net_property_map);
}

ni_bool_t
ni_wpa_net_property_type(const char *name, ni_wpa_net_property_type_t *type)
{
	if (!type || ni_parse_uint_mapped(name, ni_wpa_net_property_map, type) < 0)
		return FALSE;
	return TRUE;
}

/*
 * WPA interface states
 */
static const ni_intmap_t	ni_wpa_nif_state_names[] = {
	{ "INTERFACE_DISABLED",	NI_WPA_NIF_STATE_INACTIVE	},
	{ "DISCONNECTED",	NI_WPA_NIF_STATE_DISCONNECTED },
	{ "INACTIVE",		NI_WPA_NIF_STATE_INACTIVE	},
	{ "SCANNING",		NI_WPA_NIF_STATE_SCANNING	},
	{ "AUTHENTICATING",	NI_WPA_NIF_STATE_AUTHENTICATING },
	{ "ASSOCIATING",	NI_WPA_NIF_STATE_ASSOCIATING },
	{ "ASSOCIATED",		NI_WPA_NIF_STATE_ASSOCIATED },
	{ "4WAY_HANDSHAKE",	NI_WPA_NIF_STATE_4WAY_HANDSHAKE },
	{ "GROUP_HANDSHAKE",	NI_WPA_NIF_STATE_GROUP_HANDSHAKE },
	{ "COMPLETED",		NI_WPA_NIF_STATE_COMPLETED },
	{ NULL }
};

static ni_wpa_nif_state_t
ni_wpa_name_to_nif_state(const char *name)
{
	unsigned int res;

	if (ni_parse_uint_mapped(name, ni_wpa_nif_state_names, &res) < 0) {
		ni_error("%s: could not map interface state %s", __func__, name);
		return NI_WPA_NIF_STATE_UNKNOWN;
	}
	return res;
}

static const char *
ni_wpa_nif_state_to_name(ni_wpa_nif_state_t ifs)
{
	return ni_format_uint_mapped(ifs, ni_wpa_nif_state_names);
}

int
ni_wpa_nif_trigger_scan(ni_wpa_nif_t *wif, ni_bool_t active_scanning)
{
	static const char *method = "Scan";
	const char *interface = NULL;
	ni_dbus_variant_t dict = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	int rv = -NI_ERROR_INVALID_ARGS;

	if (!wif || !wif->object)
		return -NI_ERROR_INVALID_ARGS;

	interface = ni_dbus_object_get_default_interface(wif->object);
	ni_debug_wpa("%s: Calling %s.%s()", wif->device.name, interface, method);

	ni_dbus_variant_init_dict(&dict);
	if (!ni_dbus_dict_add_string(&dict, "Type", active_scanning ? "active" : "passive")){
		rv = -NI_ERROR_GENERAL_FAILURE;
		goto cleanup;
	}

	if (!ni_dbus_object_call_variant(wif->object, interface, method,
					1, &dict, 0, NULL, &error)){
		ni_error("%s: dbus call %s.%s() failed (%s: %s)",
				wif->device.name,
				ni_dbus_object_get_path(wif->object), method,
				error.name, error.message);

		if (dbus_error_is_set(&error))
			rv = ni_dbus_client_translate_error(ni_wpa_client_dbus(wif->client), &error);

		goto cleanup;
	}

	ni_timer_get_time(&wif->scan.timestamp);
	wif->scan.pending = 1;

	rv = NI_SUCCESS;

cleanup:
	ni_dbus_variant_destroy(&dict);

	return rv;
}

/*
 * Check whether a scan is still in progress
 */
ni_bool_t
ni_wpa_nif_scan_in_progress(ni_wpa_nif_t *wif)
{
	return wif->properties.scanning;
}

ni_bool_t
ni_wpa_nif_disconnect(ni_wpa_nif_t *dev)
{
	int rv;

	rv = ni_dbus_object_call_simple(dev->object,
			NI_WPA_NIF_INTERFACE, "disconnect",
			DBUS_TYPE_INVALID, NULL,
			DBUS_TYPE_INVALID, NULL);
	if (rv < 0) {
		ni_error("%s() failed: %s", __func__, ni_strerror(rv));
		return FALSE;
	}
	return TRUE;
}


static void
ni_wpa_nif_set_state(ni_wpa_nif_t *wif, ni_wpa_nif_state_t new_state)
{
	ni_wpa_nif_state_t old_state = wif->state;

	ni_debug_wpa("%s: state change %s -> %s",
			wif->device.name,
			ni_wpa_nif_state_to_name(old_state),
			ni_wpa_nif_state_to_name(new_state));

	if (old_state == new_state)
		return;

	wif->state = new_state;
	if (wif->ops.on_state_change)
		wif->ops.on_state_change(wif, old_state, new_state);
}

static void
ni_wpa_nif_refresh_all_bss(ni_wpa_nif_t *wif)
{
	ni_wpa_bss_t *bss;

	for(bss = wif->bsss; bss; bss = bss->next){
		if (ni_wpa_bss_refresh(bss) != 0){
			ni_error("Failed to refresh bss %s ", bss->object->path);
		}
	}
}

static ni_wpa_bss_t *
ni_wpa_nif_find_or_create_bss(ni_wpa_nif_t *wif, const char *object_path)
{
	ni_wpa_bss_t *bss;

	bss = ni_wpa_bss_list_find_by_path(&wif->bsss, object_path);
	if (!bss){
		if (!(bss = ni_wpa_bss_new(wif, object_path))){
			ni_error("%s: failed to create BSS (%s)", __func__, object_path);
			return NULL;
		}
		ni_wpa_bss_list_append(&wif->bsss, bss);
	}
	return bss;
}

static void
ni_wpa_nif_signal_scan_done(ni_wpa_nif_t *wif, const char *member, ni_dbus_message_t *msg)
{
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	const char * path = ni_dbus_object_get_path(wif->object);
	dbus_bool_t success = FALSE;

	if (ni_dbus_message_get_args_variants(msg, &arg, 1) != 1 ||
	    !ni_dbus_variant_get_bool(&arg, &success) ){
		SIGNAL_ERR(path, member, "unable to extract arg: boolean");
		goto cleanup;
	}

	if (success)
		ni_wpa_nif_refresh_all_bss(wif);

	if (wif->ops.on_scan_done)
		wif->ops.on_scan_done(wif, wif->bsss);

cleanup:
	ni_dbus_variant_destroy(&arg);
}

static void
ni_wpa_nif_signal_bss_added(ni_wpa_nif_t *wif, const char *member, ni_dbus_message_t *msg)
{
	const char *path = ni_dbus_object_get_path(wif->object);
	ni_dbus_variant_t argv[2] = { NI_DBUS_VARIANT_INIT, NI_DBUS_VARIANT_INIT };
	const char *bss_path = NULL;
	ni_wpa_bss_t *bss;

	if (ni_dbus_message_get_args_variants(msg, argv, 2) != 2 ||
	    !ni_dbus_variant_get_object_path(&argv[0], &bss_path) ||
	    !ni_dbus_variant_is_dict(&argv[1]) ){
		SIGNAL_ERR(path, member, "unable to extract args: object-path, property-dict");
		goto cleanup;
	}

	if (!(bss = ni_wpa_nif_find_or_create_bss(wif, bss_path))){
		goto cleanup;
	}

	if (!ni_dbus_object_set_properties_from_dict(bss->object, &ni_objectmodel_wpa_bss_service, &argv[1], NULL)) {
		SIGNAL_ERR(path, member, "unable to set properties for BSS (%s)", bss_path);
		ni_wpa_bss_list_remove_by_path(&wif->bsss, bss_path);
	}

cleanup:
	ni_dbus_variant_destroy(&argv[0]);
	ni_dbus_variant_destroy(&argv[1]);
}

static void
ni_wpa_nif_signal_bss_removed(ni_wpa_nif_t *wif, const char *member, ni_dbus_message_t *msg)
{
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	const char *path = ni_dbus_object_get_path(wif->object);
	const char *bss_path = NULL;

	if (ni_dbus_message_get_args_variants(msg, &arg, 1) != 1 ||
            !ni_dbus_variant_get_object_path(&arg, &bss_path) ){
		SIGNAL_ERR(path, member, "unable to extract arg: object-path");
		goto cleanup;
	}

	ni_wpa_bss_list_remove_by_path(&wif->bsss, bss_path);

cleanup:
	ni_dbus_variant_destroy(&arg);
}

ni_wpa_bss_t *
ni_wpa_nif_get_current_bss(ni_wpa_nif_t *wif)
{
	const char *path;
	ni_wpa_bss_t *bss;

	if (ni_wpa_nif_refresh(wif) < 0)
		return NULL;

	path = wif->properties.current_bss_path;
	if (!path || !ni_string_startswith(path, ni_dbus_object_get_path(wif->object)))
		return NULL;

	if (!(bss = ni_wpa_nif_find_or_create_bss(wif, path)))
		return NULL;

	if(ni_wpa_bss_refresh(bss) != NI_SUCCESS){
		ni_wpa_bss_list_remove_by_path(&wif->bsss, path);
		return NULL;
	}
	return bss;
}

static void
ni_wpa_bss_properties_destroy(ni_wpa_bss_properties_t *props)
{
	ni_byte_array_destroy(&props->bssid);
	ni_byte_array_destroy(&props->ssid);

	ni_string_array_destroy(&props->wpa.key_mgmt);
	ni_string_array_destroy(&props->wpa.pairwise);
	ni_string_free(&props->wpa.group);

	ni_string_array_destroy(&props->rsn.key_mgmt);
	ni_string_array_destroy(&props->rsn.pairwise);
	ni_string_free(&props->rsn.group);
	ni_string_free(&props->rsn.mgmt_group);

	ni_string_free(&props->wps.type);

	ni_byte_array_destroy(&props->ies);
	ni_string_free(&props->mode);
}

static void
ni_wpa_bss_properties_init(ni_wpa_bss_properties_t *props)
{
	ni_byte_array_init(&props->bssid);
	ni_byte_array_init(&props->ssid);

	ni_string_array_init(&props->wpa.key_mgmt);
	ni_string_array_init(&props->wpa.pairwise);

	ni_string_array_init(&props->rsn.key_mgmt);
	ni_string_array_init(&props->rsn.pairwise);

	ni_byte_array_init(&props->ies);
}

static void
ni_wpa_bss_free(ni_wpa_bss_t *bss)
{
	if (!bss)
		return;
	ni_dbus_object_t *object = bss->object;

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_WPA, "%s: object %p, bss %p ",	__func__, object, bss);

	bss->object = NULL;
	if (object) {
		object->handle = NULL;
		ni_dbus_object_free(object);
	}
	bss->wif = NULL;

	ni_wpa_bss_properties_destroy(&bss->properties);
	free(bss);
}

static ni_bool_t
ni_wpa_bss_list_append(ni_wpa_bss_t **list, ni_wpa_bss_t *bss)
{
	if (!list || !bss)
		return FALSE;

	while (*list)
		list = &(*list)->next;
	*list = bss;
	return TRUE;
}

static ni_bool_t
ni_wpa_bss_list_remove_by_path(ni_wpa_bss_t **list, const char *path)
{
	ni_wpa_bss_t *i;

	if (!list || !path)
		return FALSE;

	for(i = *list; i; i = i->next){
		if (ni_string_eq(i->object->path, path)){
			*list = i->next;
			ni_wpa_bss_free(i);
			return TRUE;
		}
		list = &i->next;
	}
	return FALSE;
}

static void
ni_wpa_bss_list_destroy(ni_wpa_bss_t **list)
{
	ni_wpa_bss_t *bss;

	if (list) {
		while ((bss = *list)) {
			*list = bss->next;
			ni_wpa_bss_free(bss);
		}
		*list = NULL;
	}
}

static ni_wpa_bss_t *
ni_wpa_bss_list_find_by_path(ni_wpa_bss_t **list, const char *object_path)
{
	ni_wpa_bss_t *i;

	if (!list || !object_path)
		return NULL;

	for(i = *list; i; i = i->next)
		if (ni_string_eq(i->object->path, object_path))
			return i;

	return NULL;
}


static ni_wpa_bss_t *
ni_wpa_bss_new(ni_wpa_nif_t *wif, const char *object_path)
{
	ni_wpa_bss_t *		bss;
	ni_dbus_object_t *	object;

	if (ni_string_empty(object_path))
		return NULL;

	if (!(bss = calloc(1, sizeof(*bss)))) {
		ni_error("Unable to alloc wpa BSS -- out of memory");
		return NULL;
	}

	object = ni_dbus_object_create(wif->object, object_path,
			&ni_objectmodel_wpa_bss_class, bss);

	if (!object){
		free(bss);
		return NULL;
	}
	bss->object = object;

	ni_dbus_object_set_default_interface(object, NI_WPA_BSS_INTERFACE);

	ni_wpa_bss_properties_init(&bss->properties);

	return bss;
}

static int
ni_wpa_bss_refresh(ni_wpa_bss_t * bss)
{
	DBusError error = DBUS_ERROR_INIT;
	int rv = -NI_ERROR_DBUS_CALL_FAILED;

	if (!bss || !bss->object)
		return -NI_ERROR_INVALID_ARGS;

	if (!ni_dbus_object_refresh_properties(bss->object, &ni_objectmodel_wpa_bss_service, &error)) {
		if (dbus_error_is_set(&error))
			rv = ni_dbus_client_translate_error(bss->wif->client->dbus, &error);
		return rv;
	}
	return 0;
}

static ni_wpa_bss_t *
ni_objectmodel_wpa_bss_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_wpa_bss_t *bss;

	if (!object) {
		if (error)
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Cannot unwrap wpa bss interface from a NULL dbus object");
		return NULL;
	}

	bss = object->handle;
	if (ni_dbus_object_isa(object, &ni_objectmodel_wpa_bss_class))
		return bss;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot unwrap wpa BSS interface from incompatible object %s of class %s",
				object->path, object->class->name);
	return NULL;
}


static void *
ni_objectmodel_get_wpa_bss_properties(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_wpa_bss_t *bss = NULL;
	ni_wpa_bss_properties_t *props = NULL;

	if ((bss = ni_objectmodel_wpa_bss_unwrap(object, error)))
		props = &bss->properties;

	return props;
}

static dbus_bool_t
ni_objectmodel_wpa_bss_properties_get_Rates(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	return FALSE; /* read-only, we do not expose Rates to wpa-supplicant */
}


static dbus_bool_t
ni_objectmodel_wpa_bss_properties_set_Rates(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	size_t i;
	uint32_t max = 0;
	ni_wpa_bss_t *bss = NULL;

	if (!(bss = ni_objectmodel_wpa_bss_unwrap(object, error)))
		return FALSE;

	if (!ni_dbus_variant_is_uint32_array(argument))
		return FALSE;

	for(i=0; i < argument->array.len; i++){
		max = max_t(uint32_t, max, argument->uint32_array_value[i]);
	}
	bss->properties.rate_max = max;

	return TRUE;
}

const ni_dbus_property_t	ni_objectmodel_wpa_bss_properties_wpa[] = {
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(wpa_bss_properties, KeyMgmt, wpa.key_mgmt, RO),
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(wpa_bss_properties, Pairwise, wpa.pairwise, RO),
	NI_DBUS_GENERIC_STRING_PROPERTY(wpa_bss_properties, Group, wpa.group, RO),
	{ NULL }
};

const ni_dbus_property_t	ni_objectmodel_wpa_bss_properties_rsn[] = {
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(wpa_bss_properties, KeyMgmt, rsn.key_mgmt, RO),
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(wpa_bss_properties, Pairwise, rsn.pairwise, RO),
	NI_DBUS_GENERIC_STRING_PROPERTY(wpa_bss_properties, Group, rsn.group, RO),
	NI_DBUS_GENERIC_STRING_PROPERTY(wpa_bss_properties, MgmtGroup, rsn.mgmt_group, RO),
	{ NULL }
};

const ni_dbus_property_t	ni_objectmodel_wpa_bss_properties_wps[] = {
	NI_DBUS_GENERIC_STRING_PROPERTY(wpa_bss_properties, Type, wps.type, RO),
	{ NULL }
};

const ni_dbus_property_t	ni_objectmodel_wpa_bss_properties[] =  {
	NI_DBUS_GENERIC_BYTE_ARRAY_PROPERTY(wpa_bss_properties, BSSID, bssid, RO),
	NI_DBUS_GENERIC_BYTE_ARRAY_PROPERTY(wpa_bss_properties, SSID, ssid, RO),
	NI_DBUS_GENERIC_DICT_PROPERTY(WPA, ni_objectmodel_wpa_bss_properties_wpa),
	NI_DBUS_GENERIC_DICT_PROPERTY(RSN, ni_objectmodel_wpa_bss_properties_rsn),
	NI_DBUS_GENERIC_DICT_PROPERTY(WPS, ni_objectmodel_wpa_bss_properties_wps),
	NI_DBUS_GENERIC_BYTE_ARRAY_PROPERTY(wpa_bss_properties, IEs, ies, RO),
	NI_DBUS_GENERIC_BOOL_PROPERTY(wpa_bss_properties, Privacy, privacy, RO),
	NI_DBUS_GENERIC_STRING_PROPERTY(wpa_bss_properties, Mode, mode, RO),
	NI_DBUS_GENERIC_UINT16_PROPERTY(wpa_bss_properties, Frequency, frequency, RO),
	NI_DBUS_PROPERTY(UINT32_ARRAY, Rates, ni_objectmodel_wpa_bss_properties, RO),
	NI_DBUS_GENERIC_INT16_PROPERTY(wpa_bss_properties, Signal, signal, RO),
	NI_DBUS_GENERIC_UINT32_PROPERTY(wpa_bss_properties, Age, age, RO),
	{ NULL }
};

static const ni_dbus_class_t			ni_objectmodel_wpa_bss_class = {
	.name		= "wpa-bss",
};

static const ni_dbus_service_t	ni_objectmodel_wpa_bss_service = {
	.name		= NI_WPA_BSS_INTERFACE,
	.properties	= ni_objectmodel_wpa_bss_properties
};

#if 0
static dbus_bool_t
ni_objectmodel_wpa_net_is_quoted_property(const char *name)
{
	static const char * const unquoted[] = {
		"key_mgmt", "proto", "pairwise", "auth_alg", "group", "eap",
		"bssid", "scan_freq", "freq_list", "scan_ssid", "bssid_hint",
		"bssid_blacklist", "bssid_whitelist", "group_mgmt",
		"mesh_basic_rates","go_p2p_dev_addr", "p2p_client_list",
		"psk_list",
		NULL
	};
	unsigned int i;

	for (i = 0; unquoted[i]; ++i) {
		if (ni_string_eq(name, unquoted[i]))
			return FALSE;
	}
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_net_unquote_property(ni_stringbuf_t *unquoted, const char *quoted)
{
	size_t len;

	if (!unquoted)
		return FALSE;

	len = ni_string_len(quoted);
	if (len < 2 || quoted[0] != '"' || quoted[len - 1] != '"')
		return FALSE;

	ni_stringbuf_clear(unquoted);
	if (len > 2)
		ni_stringbuf_put(unquoted, quoted + 1, len - 2);
	return TRUE;
}
#endif

/*
 * Handle interface capabilities
 */
static inline int
__ni_wpa_set_string_array(struct ni_dbus_dict_entry *entry, ni_string_array_t *array)
{
	ni_dbus_variant_t *variant = &entry->datum;
	unsigned int i;

	for (i = 0; i < variant->array.len; ++i)
		ni_string_array_append(array, variant->string_array_value[i]);

	return 0;
}

static inline int
__ni_wpa_translate_caps(struct ni_dbus_dict_entry *entry, unsigned int *bits,
				const char *what, const ni_intmap_t *names)
{
	ni_dbus_variant_t *variant = &entry->datum;
	unsigned int i;

	*bits = 0;
	for (i = 0; i < variant->array.len; ++i) {
		const char *name = variant->string_array_value[i];
		unsigned int value;

		if (ni_parse_uint_mapped(name, names, &value) < 0)
			ni_warn("unable to translate %s %s", what, name);
		else if (value < 8 * sizeof(*bits))
			*bits |= (1 << value);
	}

	return 0;
}


static ni_intmap_t __ni_wpa_driver_names[] = {
	{ "wext",		NI_WIRELESS_WPA_DRIVER_WEXT	},
	{ "nl80211",	NI_WIRELESS_WPA_DRIVER_NL80211	},
	{ "hostap",		NI_WIRELESS_WPA_DRIVER_HOSTAP	},
	{ "wired",		NI_WIRELESS_WPA_DRIVER_WIRED	},
	{ "ralink",		NI_WIRELESS_WPA_DRIVER_RALINK	},
	{ NULL }
};

ni_bool_t
ni_wpa_driver_from_string(const char *string, unsigned int *value)
{
	if (ni_parse_uint_mapped(string, __ni_wpa_driver_names, value) < 0)
		return FALSE;
	return TRUE;
}

const char *
ni_wpa_driver_as_string(ni_wireless_wpa_driver_t drv)
{
	return ni_format_uint_mapped(drv, __ni_wpa_driver_names);
}

static ni_bool_t
ni_wpa_driver_check_name(const char *name)
{
	ni_wireless_wpa_driver_t drv;

	for (drv = NI_WIRELESS_WPA_DRIVER_WEXT; drv < NI_WIRELESS_WPA_DRIVER_COUNT; drv++)
		if (ni_string_eq_nocase(name, ni_wpa_driver_as_string(drv)))
			return TRUE;

	return FALSE;
}

ni_bool_t
ni_wpa_driver_string_validate(const char *string)
{
	unsigned int i;
	ni_string_array_t drv;

	if (!string)
		return FALSE;

	ni_string_array_init(&drv);
	ni_string_split(&drv, string, ",", NI_WIRELESS_WPA_DRIVER_COUNT);

	if (0 == drv.count) {
		ni_string_array_destroy(&drv);
		return FALSE;
	}

	for (i = 0; i < drv.count; i++) {
		if (!ni_wpa_driver_check_name(drv.data[i])) {
			ni_string_array_destroy(&drv);
			return FALSE;
		}
	}

	ni_string_array_destroy(&drv);
	return TRUE;
}


static void
ni_objectmodel_wpa_nif_object_destroy(ni_dbus_object_t *object)
{
	ni_wpa_nif_t *wif = object->handle;

	object->handle = NULL;
	if (wif && wif->object) {
		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_WPA,
				"%s: object %p, free interface %p device %s",
				__func__, object, wif, wif ? wif->device.name : NULL);
		wif->object = NULL;
		ni_wpa_nif_free(wif);
	}
}

static ni_wpa_nif_t *
ni_objectmodel_wpa_nif_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_wpa_nif_t *wif;

	if (!object) {
		if (error)
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Cannot unwrap wpa network interface from a NULL dbus object");
		return NULL;
	}

	wif = object->handle;
	if (ni_dbus_object_isa(object, &ni_objectmodel_wpa_nif_class))
		return wif;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot unwrap wpa network interface from incompatible object %s of class %s",
				object->path, object->class->name);
	return NULL;
}

static void *
ni_objectmodel_get_wpa_nif_capabilities(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_wpa_nif_capabilities_t *caps = NULL;
	ni_wpa_nif_t *wif;

	if ((wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		caps = &wif->capabilities;

	return caps;
}

static void *
ni_objectmodel_get_wpa_nif_properties(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_wpa_nif_properties_t *props = NULL;
	ni_wpa_nif_t *wif;

	if ((wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		props = &wif->properties;

	return props;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_get_state(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	return FALSE; /* read-only, we do not expose state to wpa-supplicant */
}

static dbus_bool_t
ni_objectmodel_wpa_nif_set_state(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_nif_t *wif;
	const char *state;

	if (!ni_dbus_variant_get_string(argument, &state) || ni_string_empty(state))
		return FALSE;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	ni_wpa_nif_set_state(wif, ni_wpa_name_to_nif_state(state));
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_get_country(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	const ni_wpa_nif_t *wif;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	if (!wif->properties.country)
		return FALSE;

	ni_dbus_variant_set_string(result, wif->properties.country);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_set_country(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_nif_t *wif;
	const char *country = NULL;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_string(argument, &country))
		return FALSE;

	if (ni_string_empty(country))
		ni_string_free(&wif->properties.country);
	else
		ni_string_dup(&wif->properties.country, country);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_get_ap_scan(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	const ni_wpa_nif_t *wif;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	ni_dbus_variant_set_uint32(result, wif->properties.ap_scan);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_set_ap_scan(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_nif_t *wif;
	uint32_t value;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_uint32(argument, &value))
		return FALSE;

	wif->properties.ap_scan = value;
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_get_fast_reauth(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	const ni_wpa_nif_t *wif;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	ni_dbus_variant_set_bool(result, wif->properties.fast_reauth);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_set_fast_reauth(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_nif_t *wif;
	dbus_bool_t value;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_bool(argument, &value))
		return FALSE;

	wif->properties.fast_reauth = value;
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_get_scan_interval(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	const ni_wpa_nif_t *wif;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	ni_dbus_variant_set_int32(result, wif->properties.scan_interval);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_set_scan_interval(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_nif_t *wif;
	int32_t value;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_int32(argument, &value))
		return FALSE;

	wif->properties.scan_interval = value;
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_get_bss_expire_age(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	const ni_wpa_nif_t *wif;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	ni_dbus_variant_set_uint32(result, wif->properties.bss_expire_age);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_set_bss_expire_age(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_nif_t *wif;
	uint32_t value;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_uint32(argument, &value))
		return FALSE;

	wif->properties.bss_expire_age = value;
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_get_bss_expire_count(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	const ni_wpa_nif_t *wif;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	ni_dbus_variant_set_uint32(result, wif->properties.bss_expire_count);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_wpa_nif_set_bss_expire_count(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_nif_t *wif;
	uint32_t value;

	if (!(wif = ni_objectmodel_wpa_nif_unwrap(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_uint32(argument, &value))
		return FALSE;

	wif->properties.bss_expire_count = value;
	return TRUE;
}

#define	WPA_NIF_CAP_STRING_ARRAY_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(wpa_nif_capabilities, dbus_name, member_name, rw)
#define	WPA_NIF_CAP_INT32_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT32_PROPERTY(wpa_nif_capabilities, dbus_name, member_name, rw)

#define	WPA_NIF_DICT_PROPERTY(dbus_name, fstem) \
	NI_DBUS_GENERIC_DICT_PROPERTY(dbus_name, ni_objectmodel_wpa_nif_##fstem)
#define	WPA_NIF_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(wpa_nif_properties, dbus_name, member_name, rw)
#define WPA_NIF_OBJECT_PATH_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_OBJECT_PATH_PROPERTY(wpa_nif_properties, dbus_name, member_name, rw)
#define WPA_NIF_OBJECT_PATH_ARRAY_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_OBJECT_PATH_ARRAY_PROPERTY(wpa_nif_properties, dbus_name, member_name, rw)

#define	WPA_NIF_CUSTOM_PROPERTY(type, dbus_name, fstem, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_SIGNATURE(type), dbus_name, fstem, ni_objectmodel_wpa_nif, rw)
#define WPA_NIF_PROPERTY(type, dbus_name, fstem, rw) \
	NI_DBUS_GENERIC_##type##_PROPERTY(wpa_nif_properties, dbus_name, fstem, rw)

static const ni_dbus_property_t			ni_objectmodel_wpa_nif_capabilities[] = {
	WPA_NIF_CAP_STRING_ARRAY_PROPERTY(	Pairwise,		pairwise,		RO),
	WPA_NIF_CAP_STRING_ARRAY_PROPERTY(	Group,			group,			RO),
	WPA_NIF_CAP_STRING_ARRAY_PROPERTY(	GroupMgmt,		group_mgmt,		RO),
	WPA_NIF_CAP_STRING_ARRAY_PROPERTY(	KeyMgmt,		key_mgmt,		RO),
	WPA_NIF_CAP_STRING_ARRAY_PROPERTY(	Protocol,		protocol,		RO),
	WPA_NIF_CAP_STRING_ARRAY_PROPERTY(	AuthAlg,		auth_alg,		RO),
	WPA_NIF_CAP_STRING_ARRAY_PROPERTY(	Scan,			scan,			RO),
	WPA_NIF_CAP_STRING_ARRAY_PROPERTY(	Modes,			modes,			RO),
	WPA_NIF_CAP_INT32_PROPERTY(		MaxScanSSID,		max_scan_ssid,		RO),

	{ NULL }
};

static const ni_dbus_property_t			ni_objectmodel_wpa_nif_properties[] = {
	/* read-only properties & capabilities */
	WPA_NIF_DICT_PROPERTY(			Capabilities,		capabilities),
	WPA_NIF_CUSTOM_PROPERTY(STRING,		State,			state,			RO),

	WPA_NIF_OBJECT_PATH_PROPERTY(		CurrentNetwork,		current_network_path,	RO),
	WPA_NIF_OBJECT_PATH_PROPERTY(		CurrentBSS,		current_bss_path,	RO),
	WPA_NIF_OBJECT_PATH_ARRAY_PROPERTY(	Networks,		network_paths,		RO),
	WPA_NIF_OBJECT_PATH_ARRAY_PROPERTY(	BSSs,			bss_paths,		RO),
	WPA_NIF_PROPERTY(BOOL,			Scanning,		scanning,		RO),
	WPA_NIF_PROPERTY(STRING,		CurrentAuthMode,	current_auth_mode,	RO),

	/* read-only properties, writeable as CreateInterface arguments only */
	WPA_NIF_STRING_PROPERTY(		Ifname,			ifname,			RO),
	WPA_NIF_STRING_PROPERTY(		BridgeIfname,		bridge,			RO),
	WPA_NIF_STRING_PROPERTY(		Driver,			driver,			RO),

	/* read+writeable (via Properties.Set()) */
	WPA_NIF_CUSTOM_PROPERTY(STRING,		Country,		country,		RO),
	WPA_NIF_CUSTOM_PROPERTY(UINT32,		ApScan,			ap_scan,		RO),
	WPA_NIF_CUSTOM_PROPERTY(BOOLEAN,	FastReauth,		fast_reauth,		RO),
	WPA_NIF_CUSTOM_PROPERTY(INT32,		ScanInterval,		scan_interval,		RO),
	WPA_NIF_CUSTOM_PROPERTY(UINT32,		BSSExpireAge,		bss_expire_age,		RO),
	WPA_NIF_CUSTOM_PROPERTY(UINT32,		BSSExpireCount,		bss_expire_count,	RO),

	{ NULL }
};

static const ni_dbus_class_t			ni_objectmodel_wpa_nif_class = {
	.name		= "wpa-interface",
	.destroy	= ni_objectmodel_wpa_nif_object_destroy,
};

static const ni_dbus_service_t			ni_objectmodel_wpa_nif_service = {
	.name		= NI_WPA_NIF_INTERFACE,
	.properties	= ni_objectmodel_wpa_nif_properties,
	.compatible	= &ni_objectmodel_wpa_nif_class,
};

const char *
__ni_print_string_array(const ni_string_array_t *array)
{
	static char buffer[256];
	unsigned int i, pos, bufsize;

	if (array->count == 0)
		return "<>";

	bufsize = sizeof(buffer);
	for (i = pos = 0; i < array->count; ++i) {
		const char *s = array->data[i];
		unsigned int len;

		if (i != 0) {
			if (pos + 3 >= bufsize)
				break;
			strcpy(buffer + pos, ", ");
			pos += 2;
		}

		if (s == NULL)
			s = "\"\"";
		len = strlen(s);
		if (pos + len + 1 >= bufsize)
			break;

		strcpy(buffer + pos, s);
		pos += len;
	}

	return buffer;
}

static void
ni_wpa_signal_interface_added(ni_wpa_client_t *wpa, const char *member, ni_dbus_message_t *msg)
{
	ni_dbus_variant_t argv[2] = { NI_DBUS_VARIANT_INIT, NI_DBUS_VARIANT_INIT };
	const char *path = NULL;
	ni_wpa_nif_t *wif;

	if (ni_dbus_message_get_args_variants(msg, argv, 2) != 2 ||
	    !ni_dbus_variant_is_dict(&argv[1])) {
		ni_error("%s signal: unable to extract args: object-path, propetry-dict", member);
		goto cleanup;
	}
	if (!ni_dbus_variant_get_object_path(&argv[0], &path) ||
	    !ni_string_startswith(path, NI_WPA_OBJECT_PATH NI_WPA_NIF_OBJECT_PREFIX)) {
		ni_error("%s signal: invalid object path %s", member, path);
		goto cleanup;
	}

	wif = ni_wpa_nif_by_path(wpa, path);
	if (wif) {
		ni_debug_wpa("%s signal: reusing an already known interface object %s", member, path);
		ni_wpa_nif_properties_destroy(&wif->properties);
		ni_wpa_nif_capabilities_destroy(&wif->capabilities);
		timerclear(&wif->acquired);
	} else {
		if (!(wif = ni_wpa_nif_new(wpa, NULL, 0))) {
			ni_error("%s signal: unable to allocate new interface structure for %s", member, path);
			goto cleanup;
		}
		if (!ni_objectmodel_wpa_nif_object_new(wpa, wif, path)) {
			ni_error("%s signal: failed to create wpa interface object with path: %s", member, path);
			ni_wpa_nif_free(wif);
			goto cleanup;
		}
	}

	if (!ni_dbus_object_set_properties_from_dict(wif->object, &ni_objectmodel_wpa_nif_service, &argv[1], NULL)) {
		ni_wpa_nif_properties_destroy(&wif->properties);
		ni_wpa_nif_capabilities_destroy(&wif->capabilities);
		ni_error("%s signal: unable to set properties from dict for %s", member, path);
	} else {
		ni_debug_wpa("%s signal for %s interface processed", member, path);
		ni_timer_get_time(&wif->acquired);
	}

cleanup:
	ni_dbus_variant_destroy(&argv[0]);
	ni_dbus_variant_destroy(&argv[1]);
}

static void
ni_wpa_signal_interface_removed(ni_wpa_client_t *wpa, const char *member, ni_dbus_message_t *msg)
{
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	const char *path = NULL;
	ni_wpa_nif_t *wif;

	if (ni_dbus_message_get_args_variants(msg, &arg, 1) != 1) {
		ni_error("%s signal: unable to extract args: object-path", member);
		goto cleanup;
	}
	if (!ni_dbus_variant_get_object_path(&arg, &path) ||
	    !ni_string_startswith(path, NI_WPA_OBJECT_PATH NI_WPA_NIF_OBJECT_PREFIX)) {
		ni_error("%s signal: invalid object path %s", member, path);
		goto cleanup;
	}

	if ((wif = ni_wpa_nif_by_path(wpa, path)))
		ni_wpa_nif_free(wif);

cleanup:
	ni_dbus_variant_destroy(&arg);
}

static void
ni_wpa_nif_signal_properties_changed(ni_wpa_nif_t *wif, const char *member, ni_dbus_message_t *msg)
{
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	const char *path = ni_dbus_object_get_path(wif->object);

	if (ni_dbus_message_get_args_variants(msg, &arg, 1) < 1 || !ni_dbus_variant_is_dict(&arg) ){
		SIGNAL_ERR(path, member, "unable to extract property-dict");
		goto cleanup;
	}

	if (!ni_dbus_object_set_properties_from_dict(wif->object, &ni_objectmodel_wpa_nif_service, &arg, NULL)) {
		ni_wpa_nif_properties_destroy(&wif->properties);
		ni_wpa_nif_capabilities_destroy(&wif->capabilities);
		SIGNAL_ERR(path, member, "unable to set properties from dict");
		timerclear(&wif->acquired);
	} else {
		ni_timer_get_time(&wif->acquired);
		if (wif->ops.on_properties_changed)
			wif->ops.on_properties_changed(wif, &arg);
	}

cleanup:
	ni_dbus_variant_destroy(&arg);
}

static void
ni_wpa_nif_signal_network_added(ni_wpa_nif_t *wif, const char *member, ni_dbus_message_t *msg)
{
	const char *path = ni_dbus_object_get_path(wif->object);
	ni_dbus_variant_t argv[2] = { NI_DBUS_VARIANT_INIT, NI_DBUS_VARIANT_INIT };
	const char *net_path = NULL;
	int argc = 0;

	if ((argc = ni_dbus_message_get_args_variants(msg, argv, 2)) != 2 ||
		!ni_dbus_variant_is_dict(&argv[1])) {
		SIGNAL_ERR(path, member, "unable to extract args: object-path, propertry-dict");
		goto cleanup;
	}
	if (!ni_dbus_variant_get_object_path(&argv[0], &net_path) || !ni_string_startswith(net_path, path)) {
		SIGNAL_ERR(path, member, "invalid object path `%s`", net_path);
		goto cleanup;
	}

	if (ni_string_array_index(&wif->properties.network_paths, net_path) < 0)
		ni_string_array_append(&wif->properties.network_paths, net_path);

	/* FIXME: retrieve properties from network, the one from the event are useless! */
	if (wif->ops.on_network_added)
		wif->ops.on_network_added(wif, net_path, &argv[1]);

cleanup:
	while (argc > 0)
		ni_dbus_variant_destroy(&argv[--argc]);

}

static void
ni_wpa_nif_signal_network_selected(ni_wpa_nif_t *wif, const char *member, ni_dbus_message_t *msg)
{
	const char *path = ni_dbus_object_get_path(wif->object);
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	const char *net_path = NULL;

	if (ni_dbus_message_get_args_variants(msg, &arg, 1) != 1) {
		SIGNAL_ERR(path, member, "unable to extract arg: object-path");
		goto cleanup;
	}
	if (!ni_dbus_variant_get_object_path(&arg, &net_path) ||
	    !ni_string_startswith(net_path, path)) {
		SIGNAL_ERR(path, member, "invalid object-path `%s`", net_path);
		goto cleanup;
	}

	if (!ni_string_dup(&wif->properties.current_network_path, net_path))
		goto cleanup;

	if (wif->ops.on_network_selected)
		wif->ops.on_network_selected(wif, wif->properties.current_network_path);

cleanup:
	ni_dbus_variant_destroy(&arg);
}

static void
ni_wpa_nif_signal_network_removed(ni_wpa_nif_t *wif, const char *member, ni_dbus_message_t *msg)
{
	const char *path = ni_dbus_object_get_path(wif->object);
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	const char *net_path = NULL;

	if (ni_dbus_message_get_args_variants(msg, &arg, 1) != 1) {
		SIGNAL_ERR(path, member, "unable to extract arg: object-path");
		goto cleanup;
	}

	if (!ni_dbus_variant_get_object_path(&arg, &net_path) ||
	    !ni_string_startswith(net_path, path)) {
		SIGNAL_ERR(path, member, "invalid object-path `%s`", net_path);
		goto cleanup;
	}

	ni_string_array_remove_match(&wif->properties.network_paths, path, 0);

	if (wif->ops.on_network_removed)
		wif->ops.on_network_removed(wif, path);

cleanup:
	ni_dbus_variant_destroy(&arg);
}

static void
ni_wpa_nif_signal_eap(ni_wpa_nif_t *wif, const char *member, ni_dbus_message_t *msg)
{
	const char *path = ni_dbus_object_get_path(wif->object);
	ni_dbus_variant_t args[2] = { NI_DBUS_VARIANT_INIT, NI_DBUS_VARIANT_INIT };
	const char *status, *parameter;

	if (ni_dbus_message_get_args_variants(msg, args, 2) != 2 ||
	    !ni_dbus_variant_get_string(&args[0], &status) ||
	    !ni_dbus_variant_get_string(&args[1], &parameter) ) {
		SIGNAL_ERR(path, member, "unable to extract args: string, string");
		goto cleanup;
	}

	if (ni_string_len(parameter) > 0)
		ni_debug_wpa("%s: EAP %s: %s", wif->device.name, status, parameter);
	else
		ni_debug_wpa("%s: EAP %s", wif->device.name, status);

cleanup:
	ni_dbus_variant_destroy(&args[0]);
	ni_dbus_variant_destroy(&args[1]);
}

static void
ni_wpa_handle_wpa_supplicant_start(ni_wpa_client_t *wpa)
{
	ni_wpa_ops_handler_t *handler;
	ni_netconfig_t *nc;
	ni_netdev_t *dev;

	if (!(nc = ni_global_state_handle(0))) {
		ni_error("%s: Failed to get global net state", __func__);
		return;
	}

	ni_wpa_client_refresh(wpa);

	for (handler = wpa->ops_handler_list; handler; handler = handler->next) {
		if ((dev = ni_netdev_by_index(nc, handler->ifindex)) &&
		    handler->ops.on_wpa_supplicant_start)
			handler->ops.on_wpa_supplicant_start(dev);
	}
}

static void
ni_wpa_handle_wpa_supplicant_stop(ni_wpa_client_t *wpa)
{
	ni_wpa_ops_handler_t *handler;
	ni_netdev_t *dev;
	ni_wpa_nif_t *wif;
	ni_netconfig_t *nc;

	while ((wif = wpa->nifs) != NULL)
		ni_wpa_nif_free(wif);

	ni_wpa_client_properties_destroy(&wpa->properties);

	if (!(nc = ni_global_state_handle(0))) {
		ni_error("%s: Failed to get global net state", __func__);
		return;
	}

	for (handler = wpa->ops_handler_list; handler; handler = handler->next) {
		if ((dev = ni_netdev_by_index(nc, handler->ifindex)) &&
		    handler->ops.on_wpa_supplicant_stop)
			handler->ops.on_wpa_supplicant_stop(dev);
	}
}

static void
ni_wpa_dbus_signal(ni_dbus_connection_t *connection, ni_dbus_message_t *msg, void *user_data)
{
	ni_wpa_client_t *wpa = (ni_wpa_client_t*) user_data;
	ni_dbus_variant_t args[3] = { NI_DBUS_VARIANT_INIT, NI_DBUS_VARIANT_INIT, NI_DBUS_VARIANT_INIT};
	const char *member = dbus_message_get_member(msg);
	const char *path = dbus_message_get_path(msg);
	const char *name = NULL;
	const char *old_owner = NULL;
	const char *new_owner = NULL;

	if (!ni_string_eq(member, "NameOwnerChanged"))
		return;

	if (ni_dbus_message_get_args_variants(msg, args, 3) != 3
		|| !ni_dbus_variant_get_string(&args[0], &name)
		|| !ni_dbus_variant_get_string(&args[1], &old_owner)
		|| !ni_dbus_variant_get_string(&args[2], &new_owner)
		){
		SIGNAL_ERR(path, member, "unable to extract property-dict");
		goto cleanup;
	}

	if (ni_string_eq(name, NI_WPA_INTERFACE)) {
		if (ni_string_empty(old_owner) && !ni_string_empty(new_owner)) {
			ni_debug_wpa("Start of wpa_supplicant (new owner '%s')", new_owner);
			ni_wpa_handle_wpa_supplicant_start(wpa);
		}
		else if (!ni_string_empty(old_owner) && ni_string_empty(new_owner)) {
			ni_debug_wpa("Stop of wpa_supplicant (old owner '%s')", old_owner);
			ni_wpa_handle_wpa_supplicant_stop(wpa);
		}
	}


cleanup:
	ni_dbus_variant_destroy(&args[0]);
	ni_dbus_variant_destroy(&args[1]);
	ni_dbus_variant_destroy(&args[2]);
}

static void
ni_wpa_nif_signal(ni_dbus_connection_t *connection, ni_dbus_message_t *msg, void *user_data)
{
	struct ni_wpa_nif_signal_map {
	    const char* name;
	    void (*func)(ni_wpa_nif_t *wif, const char *member, ni_dbus_message_t *msg);
	} *i, signal_map[] = {
		{ "PropertiesChanged",	ni_wpa_nif_signal_properties_changed },
		{ "NetworkAdded",	ni_wpa_nif_signal_network_added },
		{ "NetworkSelected",	ni_wpa_nif_signal_network_selected },
		{ "NetworkRemoved",	ni_wpa_nif_signal_network_removed },
		{ "BSSAdded",		ni_wpa_nif_signal_bss_added },
		{ "BSSRemoved",		ni_wpa_nif_signal_bss_removed },
		{ "ScanDone",		ni_wpa_nif_signal_scan_done },
		{ "EAP",		ni_wpa_nif_signal_eap },
		{ NULL }
	};
	const char *member = dbus_message_get_member(msg);
	const char *path = dbus_message_get_path(msg);
	ni_wpa_client_t *wpa = user_data;
	ni_wpa_nif_t *wif;

	if (!(wif = ni_wpa_nif_by_path(wpa, path))){
		ni_warn("%s: received signal `%s` for unknown interface", path, member);
		return;
	}

	for(i = signal_map; i->name; i++){
		if (ni_string_eq(member, i->name)) {
			i->func(wif, member, msg);
			ni_debug_wpa("%s: signal `%s` processed", path, member);
			break;
		}
	}

	if (!i->name)
		ni_debug_wpa("%s: received signal `%s` not processed (not implemented)", path, member);
}

static void
ni_wpa_signal(ni_dbus_connection_t *connection, ni_dbus_message_t *msg, void *user_data)
{
	struct ni_wpa_signal_map {
	    const char* name;
	    void (*func)(ni_wpa_client_t *wpa, const char *member, ni_dbus_message_t *msg);
	} *i, signal_map[] = {
		{ "InterfaceAdded",	ni_wpa_signal_interface_added },
		{ "InterfaceRemoved",	ni_wpa_signal_interface_removed },
		{ NULL }
	};
	const char *member = dbus_message_get_member(msg);
	const char *path = dbus_message_get_path(msg);
	ni_wpa_client_t *wpa = user_data;

	for(i = signal_map; i->name; i++){
		if (ni_string_eq(member, i->name)) {
			i->func(wpa, member, msg);
			ni_debug_wpa("%s: signal `%s` processed", path, member);
			break;
		}
	}
	if (!i->name)
		ni_debug_wpa("%s: received signal `%s` not processed (not implemented)", path, member);
}
