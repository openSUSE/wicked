/*
 * Wireless declarations for netinfo.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef NI_WICKED_WIRELESS_H
#define NI_WICKED_WIRELESS_H

#include <sys/mman.h>

#include <wicked/types.h>
#include <wicked/time.h>
#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/refcount.h>

typedef enum ni_wireless_mode {
	NI_WIRELESS_MODE_UNKNOWN,
	NI_WIRELESS_MODE_AUTO,
	NI_WIRELESS_MODE_ADHOC,
	NI_WIRELESS_MODE_MANAGED,
	NI_WIRELESS_MODE_MASTER,
	NI_WIRELESS_MODE_REPEATER,
	NI_WIRELESS_MODE_SECONDARY,
	NI_WIRELESS_MODE_MONITOR,
	NI_WIRELESS_MODE_MESH,
	NI_WIRELESS_MODE_P2P,
} ni_wireless_mode_t;

typedef enum ni_wireless_security {
	NI_WIRELESS_SECURITY_DEFAULT = 0,
	NI_WIRELESS_SECURITY_RESTRICTED,
	NI_WIRELESS_SECURITY_OPEN,
} ni_wireless_security_t;

typedef enum ni_wireless_cipher {
	NI_WIRELESS_CIPHER_NONE,
	NI_WIRELESS_CIPHER_PROPRIETARY,
	NI_WIRELESS_CIPHER_WEP40,
	NI_WIRELESS_CIPHER_TKIP,
	NI_WIRELESS_CIPHER_WRAP,
	NI_WIRELESS_CIPHER_CCMP,
	NI_WIRELESS_CIPHER_WEP104,
	NI_WIRELESS_CIPHER_CCMP256,
	NI_WIRELESS_CIPHER_GCMP256,
	NI_WIRELESS_CIPHER_GCMP,
	NI_WIRELESS_CIPHER_AES128_CMAC,
	NI_WIRELESS_CIPHER_BIP_GMAC128,
	NI_WIRELESS_CIPHER_BIP_GMAC256,
	NI_WIRELESS_CIPHER_BIP_CMAC256,
} ni_wireless_cipher_t;

typedef enum ni_wireless_key_mgmt {
	NI_WIRELESS_KEY_MGMT_NONE,
	NI_WIRELESS_KEY_MGMT_EAP,
	NI_WIRELESS_KEY_MGMT_PSK,
	NI_WIRELESS_KEY_MGMT_802_1X,
	NI_WIRELESS_KEY_MGMT_PROPRIETARY,
	NI_WIRELESS_KEY_MGMT_FT_PSK,
	NI_WIRELESS_KEY_MGMT_FT_EAP,
	NI_WIRELESS_KEY_MGMT_FT_EAP_SHA384,
	NI_WIRELESS_KEY_MGMT_PSK_SHA256,
	NI_WIRELESS_KEY_MGMT_EAP_SHA256,
	NI_WIRELESS_KEY_MGMT_SAE,
	NI_WIRELESS_KEY_MGMT_FT_SAE,
	NI_WIRELESS_KEY_MGMT_WPS,
	NI_WIRELESS_KEY_MGMT_EAP_SUITE_B,
	NI_WIRELESS_KEY_MGMT_EAP_SUITE_B_192,
	NI_WIRELESS_KEY_MGMT_OSEM,
	NI_WIRELESS_KEY_MGMT_FILS_SHA256,
	NI_WIRELESS_KEY_MGMT_FILS_SHA384,
	NI_WIRELESS_KEY_MGMT_FT_FILS_SHA256,
	NI_WIRELESS_KEY_MGMT_FT_FILS_SHA384,
	NI_WIRELESS_KEY_MGMT_OWE,
	NI_WIRELESS_KEY_MGMT_DPP
} ni_wireless_key_mgmt_t;

typedef enum ni_wireless_eap_method {
	NI_WIRELESS_EAP_NONE,
	NI_WIRELESS_EAP_MD5,
	NI_WIRELESS_EAP_TLS,
	NI_WIRELESS_EAP_PAP,
	NI_WIRELESS_EAP_CHAP,
	NI_WIRELESS_EAP_MSCHAP,
	NI_WIRELESS_EAP_MSCHAPV2,
	NI_WIRELESS_EAP_PEAP,
	NI_WIRELESS_EAP_TTLS,
	NI_WIRELESS_EAP_GTC,
	NI_WIRELESS_EAP_OTP,
	NI_WIRELESS_EAP_LEAP,
	NI_WIRELESS_EAP_PSK,
	NI_WIRELESS_EAP_PAX,
	NI_WIRELESS_EAP_SAKE,
	NI_WIRELESS_EAP_GPSK,
	NI_WIRELESS_EAP_WSC,
	NI_WIRELESS_EAP_IKEV2,
	NI_WIRELESS_EAP_TNC,
	NI_WIRELESS_EAP_FAST,
	NI_WIRELESS_EAP_AKA,
	NI_WIRELESS_EAP_AKA_PRIME,
	NI_WIRELESS_EAP_SIM,
} ni_wireless_eap_method_t;

/*
 * The wireless auth stuff should probably go to its own header
 * file so we can reuse stuff for 802.1x
 */
typedef enum ni_wireless_auth_proto {
	NI_WIRELESS_AUTH_PROTO_WPA,
	NI_WIRELESS_AUTH_PROTO_RSN,
} ni_wireless_auth_proto_t;

typedef enum ni_wireless_auth_algo {
	NI_WIRELESS_AUTH_ALGO_NONE,
	NI_WIRELESS_AUTH_OPEN,
	NI_WIRELESS_AUTH_SHARED,
	NI_WIRELESS_AUTH_LEAP,
} ni_wireless_auth_algo_t;

typedef enum ni_wireless_assoc_state {
	NI_WIRELESS_NOT_ASSOCIATED,
	NI_WIRELESS_ASSOCIATING,
	NI_WIRELESS_AUTHENTICATING,
	NI_WIRELESS_ESTABLISHED,
} ni_wireless_assoc_state_t;

typedef enum ni_wireless_wpa_driver {
	NI_WIRELESS_WPA_DRIVER_WEXT,
	NI_WIRELESS_WPA_DRIVER_NL80211,
	NI_WIRELESS_WPA_DRIVER_HOSTAP,
	NI_WIRELESS_WPA_DRIVER_WIRED,
	NI_WIRELESS_WPA_DRIVER_RALINK,
	NI_WIRELESS_WPA_DRIVER_COUNT,
} ni_wireless_wpa_driver_t;

typedef enum ni_wireless_ap_scan {
	NI_WIRELESS_AP_SCAN_DRIVER = 0,
	NI_WIRELESS_AP_SCAN_SUPPLICANT_AUTO,
	NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH,
} ni_wireless_ap_scan_mode_t;

typedef enum ni_wireless_scan_mode {
	NI_WIRELESS_SCAN_MODE_ACTIVE,
	NI_WIRELESS_SCAN_MODE_PASSIVE,
	NI_WIRELESS_SCAN_MODE_SSID,
} ni_wireless_scan_mode_t;

typedef enum ni_wireless_pmf {
    NI_WIRELESS_PMF_NOT_SPECIFIED = 0,
    NI_WIRELESS_PMF_DISABLED,
    NI_WIRELESS_PMF_OPTIONAL,
    NI_WIRELESS_PMF_REQUIRED,
} ni_wireless_pmf_t;

#define NI_WIRELESS_PAIRWISE_CIPHERS_MAX	4

typedef struct ni_wireless_auth_info {
	ni_wireless_auth_proto_t	proto;
	unsigned int			version;
	ni_wireless_cipher_t		group_cipher;
	unsigned int			pairwise_ciphers;
	unsigned int			keymgmt_algos;
} ni_wireless_auth_info_t;

typedef struct ni_wireless_auth_info_array {
	unsigned int			count;
	ni_wireless_auth_info_t **	data;
} ni_wireless_auth_info_array_t;

typedef struct ni_wireless_network ni_wireless_network_t;

#define NI_WIRELESS_ESSID_MAX_LEN	32

typedef struct ni_wireless_ssid {
	unsigned int			len;
	unsigned char			data[NI_WIRELESS_ESSID_MAX_LEN];
} ni_wireless_ssid_t;

typedef struct ni_wireless_blob {
	ni_bool_t			is_string;
	union {
		char *			str;
		ni_byte_array_t		byte_array;
	};
} ni_wireless_blob_t;

#define NI_WIRELESS_BITRATES_MAX	32
#define NI_WIRELESS_WEP_KEY_COUNT	4

enum ni_wireless_wep_key_len {
	NI_WIRELESS_WEP_KEY_LEN_40 = 40 / 8,				    /* like: "clown" */
	NI_WIRELESS_WEP_KEY_LEN_104 = 104 / 8,
	NI_WIRELESS_WEP_KEY_LEN_128 = 128 / 8,

	NI_WIRELESS_WEP_KEY_LEN_40_HEX = NI_WIRELESS_WEP_KEY_LEN_40 * 2,    /* like: "deedbeef01" */
	NI_WIRELESS_WEP_KEY_LEN_104_HEX = NI_WIRELESS_WEP_KEY_LEN_104 * 2,
	NI_WIRELESS_WEP_KEY_LEN_128_HEX = NI_WIRELESS_WEP_KEY_LEN_128 * 2
};

struct ni_wireless_network {
	unsigned int			refcount;
	ni_bool_t			notified;		/* did we send an event for this? */
	unsigned int			index;			/* Just a index of the network per interface */

	unsigned int			priority;
	ni_wireless_ssid_t		essid;
	unsigned int			essid_encode_index;
	ni_bool_t			scan_ssid;
	ni_hwaddr_t			access_point;
	ni_wireless_mode_t		mode;
	unsigned int			channel;
	unsigned int			fragment_size;		/* used with EAP */

	unsigned int			auth_proto;
	unsigned int			auth_algo;
	unsigned int			keymgmt_proto;
	unsigned int			pairwise_cipher;
	unsigned int			group_cipher;
	ni_wireless_pmf_t		pmf;

	char *wep_keys[NI_WIRELESS_WEP_KEY_COUNT];
	unsigned int default_key;

	struct ni_wireless_wpa_psk {
		char *			passphrase;
	} wpa_psk;

	struct ni_wireless_wpa_eap {
		ni_wireless_eap_method_t method;
		char *			identity;
		char *			anonid;

		/* Outer authentication */
		struct {
			unsigned int peapver;
			ni_bool_t peaplabel;
		} phase1;

		/* Inner authentication */
		struct {
			ni_wireless_eap_method_t method;
			char *		password;
		} phase2;

		struct {
			ni_wireless_blob_t *ca_cert;
			ni_wireless_blob_t *client_cert;
			ni_wireless_blob_t *client_key;
			char *client_key_passwd;
		} tls;
	} wpa_eap;

};

typedef struct ni_wireless_bss ni_wireless_bss_t;

struct ni_wireless_bss {
	ni_wireless_bss_t *	next;

	ni_hwaddr_t		bssid;
	ni_wireless_ssid_t	ssid;
	struct {
		unsigned int		key_mgmt;	 /* ni_wireless_key_mgmt_t as bitmask */
		unsigned int		pairwise_cipher; /* ni_wireless_cipher_t as bitmask */
		ni_wireless_cipher_t	group_cipher;
	} wpa;
	struct {
		unsigned int		key_mgmt;	 /* ni_wireless_key_mgmt_t as bitmask */
		unsigned int		pairwise_cipher; /* ni_wireless_cipher_t as bitmask */
		ni_wireless_cipher_t	group_cipher;
		ni_wireless_cipher_t	mgmt_group_cipher;
	} rsn;
	struct {
		char *			type;
	} wps;
	ni_bool_t		privacy;
	ni_wireless_mode_t	wireless_mode;
	uint32_t		channel;
	uint32_t		rate_max;
	int16_t			signal;
	uint32_t		age;
};

typedef struct ni_wireless_network_array {
	unsigned int		count;
	ni_wireless_network_t **data;
} ni_wireless_network_array_t;

typedef struct ni_wireless_interface_capabilities {
	unsigned int		pairwise_ciphers;
	unsigned int		group_ciphers;
	unsigned int		group_mgmt_ciphers;
	unsigned int		keymgmt_algos;
	unsigned int		auth_algos;
	unsigned int		wpa_protocols;
	unsigned int		oper_modes;
	unsigned int		scan_modes;
	int			max_scan_ssid;
} ni_wireless_interface_capabilities_t;

typedef struct ni_wireless_config {
	char *					country;
	ni_wireless_ap_scan_mode_t			ap_scan;
	char *					driver;
	ni_wireless_network_array_t		networks;
} ni_wireless_config_t;

typedef struct ni_wireless_scan {
	/* Scanning interval, if 0 then scanning is disabled */
	unsigned int			interval;

	/* Time in seconds after which we forget BSSes */
	unsigned int			max_age;

	struct timeval			last_trigger;
	struct timeval			last_update;

	const ni_timer_t *		timer;

	ni_wireless_bss_t *		bsss;
} ni_wireless_scan_t;

struct ni_wireless {
	ni_bool_t				reconnect;
	ni_wireless_interface_capabilities_t	capabilities;

	ni_wireless_config_t *			conf;
	ni_wireless_scan_t			scan;

	/* Association information */
	struct {
		const ni_timer_t *		timer;
		unsigned int			fail_delay;
		struct timeval			established_time;
		ni_wireless_assoc_state_t	state;
		ni_wireless_ssid_t		ssid;
		ni_hwaddr_t			bssid;
		int16_t				signal;
		char *				auth_mode;
	} assoc;
};

#define NI_WIRELESS_DEFAULT_SCAN_INTERVAL	60
#define NI_WIRELESS_ASSOC_FAIL_DELAY		60
#define NI_WIRELESS_SCAN_MAX_AGE		600
#define NI_WIRELESS_KEY_MGMT_DEFAULT_PSK	(						\
						NI_BIT(NI_WIRELESS_KEY_MGMT_PSK) |		\
						NI_BIT(NI_WIRELESS_KEY_MGMT_SAE) |		\
						NI_BIT(NI_WIRELESS_KEY_MGMT_FT_SAE) |		\
						NI_BIT(NI_WIRELESS_KEY_MGMT_PSK_SHA256) |	\
						NI_BIT(NI_WIRELESS_KEY_MGMT_FT_PSK)		\
						)
#define NI_WIRELESS_KEY_MGMT_DEFAULT_EAP	(						\
						NI_BIT(NI_WIRELESS_KEY_MGMT_EAP) |		\
						NI_BIT(NI_WIRELESS_KEY_MGMT_EAP_SHA256) |	\
						NI_BIT(NI_WIRELESS_KEY_MGMT_FT_EAP) |		\
						NI_BIT(NI_WIRELESS_KEY_MGMT_FT_EAP_SHA384) |	\
						NI_BIT(NI_WIRELESS_KEY_MGMT_EAP_SUITE_B) |	\
						NI_BIT(NI_WIRELESS_KEY_MGMT_EAP_SUITE_B_192)	\
						)
#define NI_WIRELESS_KEY_MGMT_DEFAULT_OPEN	(						\
						NI_BIT(NI_WIRELESS_KEY_MGMT_NONE) |		\
						NI_BIT(NI_WIRELESS_KEY_MGMT_OWE)		\
						)

extern ni_wireless_t *			ni_wireless_new(ni_netdev_t *);
extern void				ni_wireless_free(ni_wireless_t *);
extern int				ni_wireless_setup(ni_netdev_t *, ni_wireless_config_t *);
extern int				ni_wireless_shutdown(ni_netdev_t *);

extern void				ni_wireless_set_scanning(ni_bool_t enable);
extern int				ni_wireless_interface_set_scanning(ni_netdev_t *, ni_bool_t);
extern int				ni_wireless_interface_refresh(ni_netdev_t *);
extern int				ni_wireless_set_network(ni_netdev_t *, ni_wireless_network_t *);
extern int				ni_wireless_connect(ni_netdev_t *);
extern int				ni_wireless_disconnect(ni_netdev_t *);

extern ni_wireless_config_t *		ni_wireless_config_new();
extern void				ni_wireless_config_free(ni_wireless_config_t **);
extern ni_bool_t			ni_wireless_config_init(ni_wireless_config_t *);
extern void				ni_wireless_config_destroy(ni_wireless_config_t *);
extern void				ni_wireless_config_copy(ni_wireless_config_t *, ni_wireless_config_t *);
extern ni_bool_t			ni_wireless_config_has_essid(ni_wireless_config_t *, ni_wireless_ssid_t *);

extern ni_wireless_scan_t *		ni_wireless_scan_new(ni_netdev_t *, unsigned int);
extern void				ni_wireless_scan_free(ni_wireless_scan_t *);

extern ni_wireless_blob_t *		ni_wireless_blob_new_from_str(const char *);
extern void				ni_wireless_blob_free(ni_wireless_blob_t **);

extern void				ni_wireless_network_array_init(ni_wireless_network_array_t *);
extern void				ni_wireless_network_array_append(ni_wireless_network_array_t *, ni_wireless_network_t *);
extern void				ni_wireless_network_array_destroy(ni_wireless_network_array_t *);
extern void				ni_wireless_network_array_copy(ni_wireless_network_array_t *, ni_wireless_network_array_t *);

extern ni_wireless_bss_t *		ni_wireless_bss_new();
extern void				ni_wireless_bss_init(ni_wireless_bss_t *bss);
extern void				ni_wireless_bss_free(ni_wireless_bss_t **bss);
extern void				ni_wireless_bss_destroy(ni_wireless_bss_t *bss);
extern void				ni_wireless_bss_free_all(ni_wireless_bss_t **bss);
extern ni_wireless_bss_t *		ni_wireless_bss_list_find_by_bssid(ni_wireless_bss_t * const *, const ni_hwaddr_t *);
extern ni_bool_t			ni_wireless_bss_list_append(ni_wireless_bss_t **, ni_wireless_bss_t *);
extern void				ni_wireless_bss_list_destroy(ni_wireless_bss_t **);

extern ni_wireless_auth_info_t *	ni_wireless_auth_info_new(ni_wireless_auth_proto_t, unsigned int version);
extern void				ni_wireless_auth_info_add_pairwise_cipher(ni_wireless_auth_info_t *, ni_wireless_cipher_t);
extern void				ni_wireless_auth_info_add_key_management(ni_wireless_auth_info_t *, ni_wireless_key_mgmt_t);
extern void				ni_wireless_auth_info_free(ni_wireless_auth_info_t *);
extern void				ni_wireless_auth_info_array_init(ni_wireless_auth_info_array_t *);
extern void				ni_wireless_auth_info_array_append(ni_wireless_auth_info_array_t *, ni_wireless_auth_info_t *);
extern void				ni_wireless_auth_info_array_destroy(ni_wireless_auth_info_array_t *);

extern void				ni_wireless_wep_key_array_destroy(char **);
extern ni_bool_t			ni_wireless_wep_key_parse(char **out, const char *key);
extern void				ni_wireless_association_changed(unsigned int ifindex, ni_wireless_assoc_state_t new_state);

extern const char *			ni_wireless_ssid_print_data(const unsigned char *data, size_t len, ni_stringbuf_t *out);
extern const char *			ni_wireless_ssid_print(const ni_wireless_ssid_t *, ni_stringbuf_t *out);
extern ni_bool_t			ni_wireless_ssid_parse(ni_wireless_ssid_t *, const char *);
extern ni_bool_t			ni_wireless_ssid_eq(ni_wireless_ssid_t *, ni_wireless_ssid_t *);

extern const char *			ni_wireless_mode_to_name(ni_wireless_mode_t);
extern ni_bool_t			ni_wireless_name_to_mode(const char *, unsigned int *);
extern const ni_intmap_t *		ni_wireless_auth_proto_map(void);
extern const char *			ni_wireless_auth_proto_to_name(ni_wireless_auth_proto_t);
extern ni_bool_t			ni_wireless_name_to_auth_proto(const char *, unsigned int *);
extern const ni_intmap_t *		ni_wireless_auth_algo_map(void);
extern const char *			ni_wireless_auth_algo_to_name(ni_wireless_auth_algo_t);
extern ni_bool_t			ni_wireless_name_to_auth_algo(const char *, unsigned int *);
extern const char *			ni_wireless_cipher_to_name(ni_wireless_cipher_t);
extern ni_bool_t			ni_wireless_name_to_cipher(const char *, unsigned int *);
extern const ni_intmap_t *		ni_wireless_protocol_map();
extern const ni_intmap_t *		ni_wireless_pairwise_map(void);
extern const ni_intmap_t *		ni_wireless_group_map(void);
extern const char *			ni_wireless_key_management_to_name(ni_wireless_key_mgmt_t);
extern const ni_intmap_t *		ni_wireless_key_management_map(void);
extern ni_bool_t			ni_wireless_name_to_key_management(const char *, unsigned int *);
extern const char *			ni_wireless_eap_method_to_name(ni_wireless_eap_method_t);
extern ni_bool_t			ni_wireless_name_to_eap_method(const char *, unsigned int *);
extern const char *			ni_wireless_scan_mode_to_name(ni_wireless_scan_mode_t);
const char *				ni_wireless_assoc_state_to_name(ni_wireless_assoc_state_t);
extern const char *			ni_wireless_pmf_to_name(ni_wireless_pmf_t);
extern ni_bool_t			ni_wireless_name_to_pmf(const char *, ni_wireless_pmf_t *);

extern ni_bool_t			ni_wpa_driver_from_string(const char *, unsigned int *);
extern const char *			ni_wpa_driver_as_string(ni_wireless_wpa_driver_t);
extern ni_bool_t			ni_wpa_driver_string_validate(const char *);

/* rfkill support */
typedef void				ni_rfkill_event_handler_t(ni_rfkill_type_t, ni_bool_t, void *user_data);

extern int				ni_rfkill_open(ni_rfkill_event_handler_t *, void *user_data);
extern ni_bool_t			ni_rfkill_disabled(ni_rfkill_type_t);
extern const char *			ni_rfkill_type_string(ni_rfkill_type_t type);

extern					ni_declare_refcounted_new(ni_wireless_network);
extern					ni_declare_refcounted_drop(ni_wireless_network);

#endif /* NI_WICKED_WIRELESS_H */
