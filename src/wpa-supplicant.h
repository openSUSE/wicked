/*
 * Interfacing with wpa_supplicant through dbus interface
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_WPA_CLIENT_H__
#define __WICKED_WPA_CLIENT_H__

#include <wicked/wireless.h>
#include "dbus-connection.h"

typedef enum {
	NI_WPA_IFSTATE_UNKNOWN,
	NI_WPA_IFSTATE_INACTIVE,
	NI_WPA_IFSTATE_SCANNING,
	NI_WPA_IFSTATE_DISCONNECTED,
	NI_WPA_IFSTATE_ASSOCIATING,
	NI_WPA_IFSTATE_ASSOCIATED,
	NI_WPA_IFSTATE_AUTHENTICATING,
	NI_WPA_IFSTATE_COMPLETED,
	NI_WPA_IFSTATE_4WAY_HANDSHAKE,
	NI_WPA_IFSTATE_GROUP_HANDSHAKE,
} ni_wpa_ifstate_t;

typedef struct ni_wpa_client	ni_wpa_client_t;
typedef struct ni_wpa_interface	ni_wpa_interface_t;

struct ni_wpa_interface {
	ni_wpa_interface_t *	next;

	ni_wpa_client_t *	wpa_client;

	char *			ifname;
	unsigned int		ifindex;

	ni_wpa_ifstate_t	state;
	ni_dbus_object_t *	proxy;

	struct {
		struct timeval	timestamp;
		unsigned char	pending;
	} scan;

	struct {
		ni_dbus_object_t *proxy;
		ni_wireless_network_t *config;
	} requested_association;

	ni_wireless_interface_capabilities_t capabilities;
};

extern ni_wpa_client_t *ni_wpa_client_open(void);
extern void		ni_wpa_client_free(ni_wpa_client_t *wpa);
extern ni_wpa_interface_t *ni_wpa_interface_bind(ni_wpa_client_t *wpa, ni_netdev_t *dev);
extern ni_wpa_interface_t *ni_wpa_client_interface_by_local_name(ni_wpa_client_t *wpa, const char *ifname);
extern ni_wpa_interface_t *ni_wpa_client_interface_by_path(ni_wpa_client_t *wpa, const char *object_path);
extern ni_bool_t	ni_wpa_interface_scan_in_progress(ni_wpa_interface_t *);
extern int		ni_wpa_interface_request_scan(ni_wpa_interface_t *, ni_wireless_scan_t *);
extern ni_bool_t	ni_wpa_interface_retrieve_scan(ni_wpa_interface_t *, ni_wireless_scan_t *);
extern int		ni_wpa_interface_associate(ni_wpa_interface_t *, ni_wireless_network_t *, ni_wireless_ap_scan_mode_t);
extern int		ni_wpa_interface_disassociate(ni_wpa_interface_t *, ni_wireless_ap_scan_mode_t);
extern ni_wpa_ifstate_t	ni_wpa_name_to_ifstate(const char *name);
extern const char *	ni_wpa_ifstate_to_name(ni_wpa_ifstate_t);

extern struct ni_dbus_client *ni_wpa_client_dbus(ni_wpa_client_t *);

#endif /* __WICKED_WPA_CLIENT_H__ */
