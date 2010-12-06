/*
 * Wireless declarations for netinfo.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_WIRELESS_H__
#define __WICKED_WIRELESS_H__

#include <wicked/types.h>

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
	NI_WIRELESS_KEY_MGMT_PSK,
	NI_WIRELESS_KEY_MGMT_802_1X,
	NI_WIRELESS_KEY_MGMT_PROPRIETARY,
} ni_wireless_key_mgmt_t;

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

#define NI_WIRELESS_PAIRWISE_CIPHERS_MAX	4

typedef struct ni_wireless_auth_info {
	ni_wireless_auth_mode_t		mode;
	unsigned int			version;
	ni_wireless_cipher_t		group_cipher;
	struct {
		unsigned int		count;
		ni_wireless_cipher_t	value[NI_WIRELESS_PAIRWISE_CIPHERS_MAX];
	} pairwise_ciphers;
	struct {
		unsigned int		count;
		ni_wireless_key_mgmt_t	value[NI_WIRELESS_PAIRWISE_CIPHERS_MAX];
	} key_management;
} ni_wireless_auth_info_t;

typedef struct ni_wireless_auth_info_array {
	unsigned int			count;
	ni_wireless_auth_info_t **	data;
} ni_wireless_auth_info_array_t;

typedef struct ni_wireless_network ni_wireless_network_t;

#define NI_WIRELESS_BITRATES_MAX	32

struct ni_wireless_network {
	char *			essid;
	unsigned int		essid_encode_index;
	ni_hwaddr_t		access_point;
	ni_wireless_mode_t	mode;
	unsigned int		channel;
	double			frequency;

	struct {
		ni_wireless_security_t mode;
		unsigned int	key_required : 1,
				key_present : 1;
		unsigned int	key_index;

		unsigned int	key_len;
		unsigned char *	key_data;
	} encode;

	ni_wireless_auth_info_array_t auth_info;

	struct {
		unsigned int	count;
		unsigned int	value[NI_WIRELESS_BITRATES_MAX];
	} bitrates;
};

struct ni_wireless {
	ni_wireless_network_t	network;
	ni_hwaddr_t		access_point;
};

typedef struct ni_wireless_network_array {
	unsigned int		count;
	ni_wireless_network_t **data;
} ni_wireless_network_array_t;

struct ni_wireless_scan {
	time_t			timestamp;
	time_t			lifetime;
	ni_wireless_network_array_t networks;
};

extern ni_wireless_network_t *ni_wireless_network_new(void);
extern void		ni_wireless_free(ni_wireless_t *);
extern ni_wireless_scan_t *ni_wireless_scan_new(void);
extern void		ni_wireless_scan_free(ni_wireless_scan_t *);
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

extern const char *	ni_wireless_mode_to_name(ni_wireless_mode_t);
extern ni_wireless_mode_t ni_wireless_name_to_mode(const char *);
extern const char *	ni_wireless_security_to_name(ni_wireless_security_t);
extern ni_wireless_security_t ni_wireless_name_to_security(const char *);
extern const char *	ni_wireless_auth_mode_to_name(ni_wireless_auth_mode_t);
extern ni_wireless_auth_mode_t ni_wireless_name_to_auth_mode(const char *);
extern const char *	ni_wireless_cipher_to_name(ni_wireless_cipher_t);
extern ni_wireless_cipher_t ni_wireless_name_to_cipher(const char *);
extern const char *	ni_wireless_key_management_to_name(ni_wireless_key_mgmt_t);
extern ni_wireless_key_mgmt_t ni_wireless_name_to_key_management(const char *);

#endif /* __WICKED_WIRELESS_H__ */
