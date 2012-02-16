/*
 * Wireless declarations for netinfo.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_WIRELESS_H__
#define __WICKED_WIRELESS_H__

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
	NI_WIRELESS_EAP_MD5,
	NI_WIRELESS_EAP_TLS,
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
} ni_wireless_eap_method_t;

/*
 * The wireless auth stuff should probably go to its own header
 * file so we can reuse stuff for 802.1x
 */
typedef enum ni_wireless_auth_mode {
	NI_WIRELESS_AUTH_NONE,
	NI_WIRELESS_AUTH_WPA1,
	NI_WIRELESS_AUTH_WPA2,
	NI_WIRELESS_AUTH_UNKNOWN,
} ni_wireless_auth_mode_t;

typedef enum ni_wireless_auth_algo {
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

typedef struct ni_wireless_ssid {
	unsigned int			len;
	unsigned char			data[32];
} ni_wireless_ssid_t;

#define NI_WIRELESS_BITRATES_MAX	32

struct ni_wireless_network {
	unsigned int			refcount;
	time_t				expires;

	ni_wireless_ssid_t		essid;
	unsigned int			essid_encode_index;
	ni_hwaddr_t			access_point;
	ni_wireless_mode_t		mode;
	unsigned int			channel;

	struct ni_wireless_scan_info {
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
	ni_wireless_auth_algo_t		ath_algo;
	ni_wireless_key_mgmt_t		keymgmt_proto;
	ni_wireless_cipher_t		cipher;
	ni_wireless_cipher_t		pairwise_cipher;
	ni_wireless_cipher_t		group_cipher;
	ni_wireless_eap_method_t	eap_method;

	struct {
		ni_wireless_security_t	mode;
		unsigned int		key_required : 1,
					key_present : 1;
		unsigned int		key_index;

		unsigned int		key_len;
		unsigned char *		key_data;
	} encode;

	struct ni_wireless_wpa_psk {
		char *			passphrase;
		ni_opaque_t		key;
	} wpa_psk;

};

typedef struct ni_wireless_interface_capabilities {
	unsigned int		eap_methods;
	unsigned int		pairwise_ciphers;
	unsigned int		group_ciphers;
	unsigned int		keymgmt_algos;
	unsigned int		auth_algos;
	unsigned int		wpa_protocols;
} ni_wireless_interface_capabilities_t;

struct ni_wireless {
	ni_wireless_interface_capabilities_t capabilities;

	ni_bool_t		enable_ap_scan;
	ni_wireless_scan_t *	scan;

	/* Association information */
	struct {
		const ni_timer_t *	timer;
		unsigned int		fail_delay;
		ni_wireless_assoc_state_t state;
		ni_wireless_network_t *	network;
		ni_hwaddr_t		access_point;
	} assoc;
};

typedef struct ni_wireless_network_array {
	unsigned int		count;
	ni_wireless_network_t **data;
} ni_wireless_network_array_t;


#define NI_WIRELESS_ASSOC_FAIL_DELAY	60
#define NI_WIRELESS_SCAN_MAX_AGE	600

struct ni_wireless_scan {
	/* Time in seconds after which we forget BSSes */
	unsigned int		max_age;

	time_t			timestamp;
	time_t			lifetime;
	ni_wireless_network_array_t networks;

	void *			pending;
};

extern ni_wireless_t *	ni_wireless_new(void);
extern int		ni_wireless_interface_set_scanning(ni_interface_t *, ni_bool_t);
extern int		ni_wireless_interface_refresh(ni_interface_t *);
extern ni_wireless_network_t *ni_wireless_network_new(void);
extern void		ni_wireless_free(ni_wireless_t *);
extern ni_wireless_scan_t *ni_wireless_scan_new(void);
extern void		ni_wireless_scan_free(ni_wireless_scan_t *);
extern int		ni_wireless_set_network(ni_interface_t *, ni_wireless_network_t *);
extern int		ni_wireless_connect(ni_interface_t *);
extern int		ni_wireless_disconnect(ni_interface_t *);
extern void		ni_wireless_network_set_key(ni_wireless_network_t *, const unsigned char *, size_t);
extern void		ni_wireless_network_free(ni_wireless_network_t *);
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

extern const char *	ni_wireless_mode_to_name(ni_wireless_mode_t);
extern ni_wireless_mode_t ni_wireless_name_to_mode(const char *);
extern const char *	ni_wireless_security_to_name(ni_wireless_security_t);
extern ni_wireless_security_t ni_wireless_name_to_security(const char *);
extern const char *	ni_wireless_auth_mode_to_name(ni_wireless_auth_mode_t);
extern ni_wireless_auth_mode_t ni_wireless_name_to_auth_mode(const char *);
extern const char *	ni_wireless_auth_algo_to_name(ni_wireless_auth_algo_t);
extern ni_wireless_auth_algo_t ni_wireless_name_to_auth_algo(const char *);
extern const char *	ni_wireless_cipher_to_name(ni_wireless_cipher_t);
extern ni_wireless_cipher_t ni_wireless_name_to_cipher(const char *);
extern const char *	ni_wireless_key_management_to_name(ni_wireless_key_mgmt_t);
extern ni_wireless_key_mgmt_t ni_wireless_name_to_key_management(const char *);
extern const char *	ni_wireless_eap_method_to_name(ni_wireless_eap_method_t);
extern ni_wireless_eap_method_t ni_wireless_name_to_eap_method(const char *);

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

#endif /* __WICKED_WIRELESS_H__ */
