/*
 * Interfacing with wpa_supplicant through dbus interface
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_WPA_CLIENT_H__
#define __WICKED_WPA_CLIENT_H__

#include <wicked/wireless.h>

typedef enum {
	NI_WPA_IFSTATE_UNKNOWN,
	NI_WPA_IFSTATE_INACTIVE,
	NI_WPA_IFSTATE_SCANNING,
	NI_WPA_IFSTATE_DISCONNECTED,
	NI_WPA_IFSTATE_ASSOCIATING,
	NI_WPA_IFSTATE_ASSOCIATED,
	NI_WPA_IFSTATE_COMPLETED,
	NI_WPA_IFSTATE_4WAY_HANDSHAKE,
	NI_WPA_IFSTATE_GROUP_HANDSHAKE,
} ni_wpa_ifstate_t;

typedef struct ni_wpa_client	ni_wpa_client_t;
typedef struct ni_wpa_interface	ni_wpa_interface_t;
typedef struct ni_wpa_network	ni_wpa_network_t;
typedef struct ni_wpa_scan	ni_wpa_scan_t;

struct ni_wpa_network {
	time_t			expires;

	ni_wireless_ssid_t	essid;
	ni_hwaddr_t		access_point;

	int32_t			noise;
	double			frequency;	/* in GHz */
	double			level;		/* in dBm*/
	double			quality;	/* n/70 */
	unsigned int		max_bitrate;	/* in Bit/s, 1e6 based */
	uint16_t		capabilities;

	ni_wireless_auth_mode_t	auth_proto;
	ni_wireless_auth_algo_t	auth_algo;
	ni_wireless_auth_algo_t	ath_algo;
	ni_wireless_key_mgmt_t	keymgmt_proto;
	ni_wireless_cipher_t	cipher;
	ni_wireless_cipher_t	pairwise_cipher;
	ni_wireless_cipher_t	group_cipher;
	ni_wireless_eap_method_t eap_method;

	ni_opaque_t *		wpaie;
	ni_opaque_t *		wpsie;
	ni_opaque_t *		rsnie;
};

struct ni_wpa_interface_capabilities {
	ni_string_array_t	eap_methods;
	ni_string_array_t	pairwise_ciphers;
	ni_string_array_t	group_ciphers;
	ni_string_array_t	keymgmt_algos;
	ni_string_array_t	auth_algos;
	ni_string_array_t	wpa_protocols;
};

struct ni_wpa_interface {
	ni_wpa_interface_t *	next;

	ni_wpa_client_t *	wpa_client;

	char *			ifname;
	ni_wpa_ifstate_t	state;
	ni_dbus_object_t *	proxy;

	time_t			last_scan;

	ni_wireless_interface_capabilities_t capabilities;

	ni_wpa_scan_t *		pending;
};

extern ni_wpa_client_t *ni_wpa_client_open(void);
extern void		ni_wpa_client_free(ni_wpa_client_t *wpa);
extern ni_wpa_interface_t *ni_wpa_interface_bind(ni_wpa_client_t *wpa, const char *ifname);
extern ni_wpa_interface_t *ni_wpa_client_interface_by_local_name(ni_wpa_client_t *wpa, const char *ifname);
extern ni_wpa_interface_t *ni_wpa_client_interface_by_path(ni_wpa_client_t *wpa, const char *object_path);
extern int		ni_wpa_interface_request_scan(ni_wpa_client_t *, ni_wpa_interface_t *,
				ni_wireless_scan_t *);
extern int		ni_wpa_interface_retrieve_scan(ni_wpa_client_t *, ni_wpa_interface_t *,
				ni_wireless_scan_t *);
extern ni_wpa_ifstate_t	ni_wpa_name_to_ifstate(const char *name);
extern const char *	ni_wpa_ifstate_to_name(ni_wpa_ifstate_t);

extern struct ni_dbus_client *ni_wpa_client_dbus(ni_wpa_client_t *);

#endif /* __WICKED_WPA_CLIENT_H__ */
