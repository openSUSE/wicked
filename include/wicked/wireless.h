/*
 * Wireless declarations for netinfo.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_WIRELESS_H__
#define __WICKED_WIRELESS_H__

#include <sys/mman.h>

#include <wicked/types.h>
#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/socket.h>	/* for the timer stuff */

typedef enum ni_wireless_mode {
	NI_WIRELESS_MODE_UNKNOWN,
	NI_WIRELESS_MODE_AUTO,
	NI_WIRELESS_MODE_ADHOC,
	NI_WIRELESS_MODE_MANAGED,
	NI_WIRELESS_MODE_MASTER,
	NI_WIRELESS_MODE_REPEATER,
	NI_WIRELESS_MODE_SECONDARY,
	NI_WIRELESS_MODE_MONITOR,
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
} ni_wireless_cipher_t;

typedef enum ni_wireless_key_mgmt {
	NI_WIRELESS_KEY_MGMT_NONE,
	NI_WIRELESS_KEY_MGMT_EAP,
	NI_WIRELESS_KEY_MGMT_PSK,
	NI_WIRELESS_KEY_MGMT_802_1X,
	NI_WIRELESS_KEY_MGMT_PROPRIETARY,
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
typedef enum ni_wireless_auth_mode {
	NI_WIRELESS_AUTH_MODE_NONE,
	NI_WIRELESS_AUTH_WPA1,
	NI_WIRELESS_AUTH_WPA2,
} ni_wireless_auth_mode_t;

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

#define NI_WIRELESS_PAIRWISE_CIPHERS_MAX	4

typedef struct ni_wireless_auth_info {
	ni_wireless_auth_mode_t		mode;
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

#define NI_WIRELESS_ESSID_MAX_LEN 32

typedef struct ni_wireless_ssid {
	unsigned int			len;
	unsigned char			data[NI_WIRELESS_ESSID_MAX_LEN];
} ni_wireless_ssid_t;

typedef struct ni_wireless_blob {
	char *				name;
	size_t				size;
	unsigned char *			data;
} ni_wireless_blob_t;

#define NI_WIRELESS_BITRATES_MAX	32
#define NI_WIRELESS_WEP_KEY_COUNT	4

enum ni_wireless_wep_key_len {
	NI_WIRELESS_WEP_KEY_LEN_40 = 40,
	NI_WIRELESS_WEP_KEY_LEN_64 = 64,
	NI_WIRELESS_WEP_KEY_LEN_104 = 104,
	NI_WIRELESS_WEP_KEY_LEN_128 = 128,
};

struct ni_wireless_network {
	unsigned int			refcount;
	ni_bool_t			notified;		/* did we send an event for this? */

	unsigned int			priority;
	ni_wireless_ssid_t		essid;
	unsigned int			essid_encode_index;
	ni_bool_t			scan_ssid;
	ni_hwaddr_t			access_point;
	ni_wireless_mode_t		mode;
	unsigned int			channel;
	unsigned int			fragment_size;		/* used with EAP */

	struct ni_wireless_scan_info {
		struct timeval 		timestamp;
		ni_bool_t		updating;		/* retrieving new scan info */
		int			noise;
		double			level;			/* in dBm*/
		double			quality;		/* n/70 */
		double			frequency;		/* in GHz */
		unsigned int		max_bitrate;		/* in Mbps */

		/* We need to fix this; this is a 16bit word directly from wpa_supplicant */
		uint16_t		capabilities;

		/* Information on the auth modes supported by the AP */
		ni_wireless_auth_info_array_t supported_auth_modes;
	} scan_info;

	ni_wireless_auth_mode_t		auth_proto;
	ni_wireless_auth_algo_t		auth_algo;
	ni_wireless_key_mgmt_t		keymgmt_proto;
	ni_wireless_cipher_t		cipher;
	ni_wireless_cipher_t		pairwise_cipher;
	ni_wireless_cipher_t		group_cipher;

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

typedef struct ni_wireless_network_array {
	unsigned int		count;
	ni_wireless_network_t **data;
} ni_wireless_network_array_t;

typedef struct ni_wireless_interface_capabilities {
	unsigned int		eap_methods;
	unsigned int		pairwise_ciphers;
	unsigned int		group_ciphers;
	unsigned int		keymgmt_algos;
	unsigned int		auth_algos;
	unsigned int		wpa_protocols;
} ni_wireless_interface_capabilities_t;

typedef struct ni_wireless_config {
	char *					country;
	ni_wireless_ap_scan_mode_t			ap_scan;
	char *					driver;
	ni_wireless_network_array_t		networks;
} ni_wireless_config_t;

struct ni_wireless {
	ni_wireless_interface_capabilities_t	capabilities;

	ni_wireless_config_t			conf;
	ni_wireless_scan_t *			scan;

	/* Association information */
	struct {
		const ni_timer_t *		timer;
		unsigned int			fail_delay;
		ni_wireless_assoc_state_t	state;
		ni_wireless_network_t *		network;
		ni_hwaddr_t			access_point;
	} assoc;
};

#define NI_WIRELESS_DEFAUT_SCAN_INTERVAL	60
#define NI_WIRELESS_ASSOC_FAIL_DELAY		60
#define NI_WIRELESS_SCAN_MAX_AGE		600

struct ni_wireless_scan {
	/* Scanning interval */
	unsigned int			interval;

	/* Time in seconds after which we forget BSSes */
	unsigned int			max_age;

	struct timeval			timestamp;
	unsigned int			lifetime;
	ni_wireless_network_array_t	networks;

	const ni_timer_t *		timer;
};

extern void		ni_wireless_set_scanning(ni_bool_t enable);
extern ni_wireless_t *	ni_wireless_new(ni_netdev_t *);
extern int		ni_wireless_interface_set_scanning(ni_netdev_t *, ni_bool_t);
extern int		ni_wireless_interface_refresh(ni_netdev_t *);
extern ni_wireless_network_t *ni_wireless_network_new(void);
extern void		ni_wireless_free(ni_wireless_t *);
extern int		ni_wireless_set_network(ni_netdev_t *, ni_wireless_network_t *);
extern int		ni_wireless_connect(ni_netdev_t *);
extern int		ni_wireless_disconnect(ni_netdev_t *);
extern void		ni_wireless_config_destroy(ni_wireless_config_t *);
extern ni_wireless_scan_t *ni_wireless_scan_new(ni_netdev_t *, unsigned int);
extern void		ni_wireless_scan_free(ni_wireless_scan_t *);

ni_wireless_blob_t *ni_wireless_blob_new(const char *);
void ni_wireless_blob_free(ni_wireless_blob_t *);
extern void		ni_wireless_network_free(ni_wireless_network_t *);
void		ni_wireless_wep_key_array_destroy(char **);
extern void		ni_wireless_network_array_init(ni_wireless_network_array_t *);
extern void		ni_wireless_network_array_append(ni_wireless_network_array_t *, ni_wireless_network_t *);
extern void		ni_wireless_network_array_destroy(ni_wireless_network_array_t *);
extern ni_wireless_auth_info_t *ni_wireless_auth_info_new(ni_wireless_auth_mode_t, unsigned int version);
extern void		ni_wireless_auth_info_add_pairwise_cipher(ni_wireless_auth_info_t *, ni_wireless_cipher_t);
extern void		ni_wireless_auth_info_add_key_management(ni_wireless_auth_info_t *, ni_wireless_key_mgmt_t);
extern void		ni_wireless_auth_info_free(ni_wireless_auth_info_t *);
extern void		ni_wireless_auth_info_array_init(ni_wireless_auth_info_array_t *);
extern void		ni_wireless_auth_info_array_append(ni_wireless_auth_info_array_t *, ni_wireless_auth_info_t *);
extern void		ni_wireless_auth_info_array_destroy(ni_wireless_auth_info_array_t *);
extern void		ni_wireless_association_changed(unsigned int ifindex, ni_wireless_assoc_state_t new_state);

extern const char *	ni_wireless_print_ssid(const ni_wireless_ssid_t *);
extern ni_bool_t	ni_wireless_parse_ssid(const char *, ni_wireless_ssid_t *);
extern ni_bool_t		ni_wireless_match_ssid(ni_wireless_ssid_t *, ni_wireless_ssid_t *);
extern ni_bool_t		ni_wireless_essid_already_exists(ni_wireless_t *, ni_wireless_ssid_t *);

extern const char *	ni_wireless_mode_to_name(ni_wireless_mode_t);
extern ni_bool_t	ni_wireless_name_to_mode(const char *, unsigned int *);
extern const char *	ni_wireless_security_to_name(ni_wireless_security_t);
extern ni_bool_t	ni_wireless_name_to_security(const char *, unsigned int *);
extern const char *	ni_wireless_auth_mode_to_name(ni_wireless_auth_mode_t);
extern ni_bool_t	ni_wireless_name_to_auth_mode(const char *, unsigned int *);
extern const char *	ni_wireless_auth_algo_to_name(ni_wireless_auth_algo_t);
extern ni_bool_t	ni_wireless_name_to_auth_algo(const char *, unsigned int *);
extern const char *	ni_wireless_cipher_to_name(ni_wireless_cipher_t);
extern ni_bool_t	ni_wireless_name_to_cipher(const char *, unsigned int *);
extern const char *	ni_wireless_key_management_to_name(ni_wireless_key_mgmt_t);
extern ni_bool_t	ni_wireless_name_to_key_management(const char *, unsigned int *);
extern const char *	ni_wireless_eap_method_to_name(ni_wireless_eap_method_t);
extern ni_bool_t	ni_wireless_name_to_eap_method(const char *, unsigned int *);

extern ni_bool_t		ni_wpa_driver_from_string(const char *, unsigned int *);
extern const char *		ni_wpa_driver_as_string(ni_wireless_wpa_driver_t);
extern ni_bool_t		ni_wpa_driver_string_validate(const char *);

/* rfkill support */
typedef void		ni_rfkill_event_handler_t(ni_rfkill_type_t, ni_bool_t, void *user_data);
extern int		ni_rfkill_open(ni_rfkill_event_handler_t *, void *user_data);
extern const char *	ni_rfkill_type_string(ni_rfkill_type_t type);
extern ni_bool_t	ni_rfkill_disabled(ni_rfkill_type_t);

static inline ni_wireless_network_t *
ni_wireless_network_get(ni_wireless_network_t *net)
{
	ni_assert(net->refcount);
	net->refcount++;

	return net;
}

static inline void
ni_wireless_network_put(ni_wireless_network_t *net)
{
	ni_assert(net->refcount);
	if (--(net->refcount) == 0)
		ni_wireless_network_free(net);
}

static inline void
ni_wireless_passwd_clear(ni_wireless_network_t *net)
{
	if (net) {
		ni_wireless_wep_key_array_destroy(net->wep_keys);
		ni_string_clear(&net->wpa_psk.passphrase);
		ni_string_clear(&net->wpa_eap.phase2.password);
		ni_string_clear(&net->wpa_eap.tls.client_key_passwd);

		/* No need to   lock  that page in memory anymore */
		munlock(net, sizeof(*net));
	}
}

#endif /* __WICKED_WIRELESS_H__ */
