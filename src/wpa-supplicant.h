/*
 * Interfacing with wpa_supplicant through dbus interface
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
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
typedef struct ni_wpa_bss	ni_wpa_bss_t;
typedef struct ni_wpa_scan	ni_wpa_scan_t;

struct ni_wpa_bss_properties {
	ni_hwaddr_t		bssid;

	struct ni_wpa_ssid {
		unsigned int	len;
		unsigned char	data[32];
	} essid;

	int32_t			noise;
	int32_t			frequency;	/* in MHz */
	int32_t			level;		/* 256 == 0dBm */
	int32_t			quality;	/* n/70 */
	int32_t			maxrate;	/* in Bit/s, 1e6 based */
	uint16_t		capabilities;

	ni_opaque_t *		wpaie;
	ni_opaque_t *		wpsie;
	ni_opaque_t *		rsnie;
};

struct ni_wpa_bss {
	ni_wpa_bss_t *		next;

	ni_dbus_object_t *	proxy;

	ni_wpa_scan_t *		scan;
	time_t			last_seen;

	struct ni_wpa_bss_properties properties;
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
	ni_wpa_bss_t *		bss_list;

	ni_wireless_interface_capabilities_t capabilities;

	ni_wpa_scan_t *		pending;
};

extern ni_wpa_client_t *ni_wpa_client_open(void);
extern void		ni_wpa_client_free(ni_wpa_client_t *wpa);
extern ni_wpa_interface_t *ni_wpa_interface_bind(ni_wpa_client_t *wpa, const char *ifname);
extern ni_wpa_interface_t *ni_wpa_client_interface_by_local_name(ni_wpa_client_t *wpa, const char *ifname);
extern ni_wpa_interface_t *ni_wpa_client_interface_by_path(ni_wpa_client_t *wpa, const char *object_path);
extern ni_wpa_bss_t *	ni_wpa_interface_bss_by_path(ni_wpa_interface_t *, const char *);
extern int		ni_wpa_interface_request_scan(ni_wpa_client_t *, ni_wpa_interface_t *,
				ni_wireless_scan_t *);
extern int		ni_wpa_interface_retrieve_scan(ni_wpa_client_t *, ni_wpa_interface_t *,
				ni_wireless_scan_t *);
extern ni_wpa_ifstate_t	ni_wpa_name_to_ifstate(const char *name);
extern const char *	ni_wpa_ifstate_to_name(ni_wpa_ifstate_t);

extern struct ni_dbus_client *ni_wpa_client_dbus(ni_wpa_client_t *);

#endif /* __WICKED_WPA_CLIENT_H__ */
