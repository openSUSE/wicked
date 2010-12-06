/*
 * Routines for handling Wireless devices.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <errno.h>
#include <math.h>

#include <wicked/wireless.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "buffer.h"
#include "kernel.h"

#ifndef IWEVLAST
# define IWEVLAST	IWEVPMKIDCAND
#endif

#ifndef IW_IE_CIPHER_NONE
# define IW_IE_CIPHER_NONE       0
# define IW_IE_CIPHER_WEP40      1
# define IW_IE_CIPHER_TKIP       2
# define IW_IE_CIPHER_WRAP       3
# define IW_IE_CIPHER_CCMP       4
# define IW_IE_CIPHER_WEP104     5
# define IW_IE_KEY_MGMT_NONE     0
# define IW_IE_KEY_MGMT_802_1X   1
# define IW_IE_KEY_MGMT_PSK      2
#endif


static void		__ni_wireless_end_scan(void *);
static int		__ni_wireless_get_scan_event(ni_buffer_t *, ni_wireless_scan_t *, ni_wireless_network_t **);
static void		__ni_wireless_network_destroy(ni_wireless_network_t *net);

typedef int		__ni_wireless_event_dissector(ni_buffer_t *, struct iw_event *);

struct __ni_wireless_scan_data {
	ni_handle_t *	handle;
	ni_interface_t *interface;
};

static __ni_wireless_event_dissector *standard_ioctl_handlers[SIOCIWLAST - SIOCIWFIRST + 1];
static __ni_wireless_event_dissector *standard_event_handlers[IWEVLAST - IWEVFIRST + 1];
static const char *	standard_ioctl_names[SIOCIWLAST - SIOCIWFIRST + 1];
static const char *	standard_event_names[IWEVLAST - IWEVFIRST + 1];

int
__ni_wireless_request_scan(ni_handle_t *nih, ni_interface_t *ifp)
{
	struct __ni_wireless_scan_data *helper;
	ni_wireless_scan_t *scan;
	struct iwreq wrq;

	if (ifp->type != NI_IFTYPE_WIRELESS) {
		ni_error("%s: cannot do wireless scan on this interface", ifp->name);
		return -1;
	}

	/* FIXME: if we have a pending scan, cancel it (and its timer) first */

	scan = ni_wireless_scan_new();
	ni_interface_set_wireless_scan(ifp, scan);
	scan->timestamp = time(NULL);
	scan->lifetime = 60;

	/* Bring up the interface for scanning */
	if (!(ifp->ifflags & NI_IFF_DEVICE_UP)) {
		if (__ni_interface_begin_activity(nih, ifp, NI_INTERFACE_WIRELESS_SCAN) < 0) {
			ni_error("%s: could not bring interface up for wireless scan",
					ifp->name);
			return -1;
		}
	}

	/* Initiate the scan */
	memset(&wrq, 0, sizeof(wrq));
	if (__ni_wireless_ext(nih, ifp, SIOCSIWSCAN, NULL, 0, 0) < 0) {
		ni_error("unable to initiate wireless scan: %m");
		__ni_interface_end_activity(nih, ifp, NI_INTERFACE_WIRELESS_SCAN);
		return -1;
	}

	ni_debug_ifconfig("%s: requested wireless scan", ifp->name);

	helper = xcalloc(1, sizeof(*helper));
	helper->handle = nih;
	helper->interface = ni_interface_get(ifp);

	ni_timer_register(25000, __ni_wireless_end_scan, helper);
	return 0;
}

void
__ni_wireless_end_scan(void *data)
{
	struct __ni_wireless_scan_data *helper = data;
	ni_interface_t *ifp = helper->interface;
	ni_handle_t *nih = helper->handle;

	ni_debug_ifconfig("%s() called", __func__);
	if (__ni_wireless_get_scan_results(nih, ifp) < 0)
		ni_warn("%s: scan failed", ifp->name);
	__ni_interface_end_activity(nih, ifp, NI_INTERFACE_WIRELESS_SCAN);

	ni_interface_put(helper->interface);
	free(helper);
}

int
__ni_wireless_get_scan_results(ni_handle_t *nih, ni_interface_t *ifp)
{
	ni_wireless_scan_t *scan;
	ni_wireless_network_t *current = NULL;
	ni_buffer_t evbuf;
	void *buffer = NULL;
	size_t buflen = 8192;

	if (!__ni_interface_check_activity(nih, ifp, NI_INTERFACE_WIRELESS_SCAN))
		return 0;

	while (1) {
		void *nb;
		int len;

		if ((nb = realloc(buffer, buflen)) == NULL) {
			ni_error("%s: out of memory", __func__);
			goto failed;
		}
		buffer = nb;

		if ((len = __ni_wireless_ext(nih, ifp, SIOCGIWSCAN, buffer, buflen, 0)) >= 0) {
			buflen = len;
			break;
		}

		if (errno == EAGAIN) {
			usleep(100000);
			continue;
		}

		if (errno == E2BIG) {
			if (buflen >= 8 * 1024 * 1024) {
				ni_error("scan result doesn't fit buffer");
				goto failed;
			}
			continue;
		}

		ni_error("%s: ioctl(SIOCGIWSCAN) failed: %m", ifp->name);
		goto failed;
	}

	ni_buffer_init_reader(&evbuf, buffer, buflen);

	scan = ni_wireless_scan_new();
	ni_interface_set_wireless_scan(ifp, scan);

	ni_debug_ifconfig("%s(%s)", __func__, ifp->name);
	while (ni_buffer_count(&evbuf)) {
		if (__ni_wireless_get_scan_event(&evbuf, scan, &current) < 0)
			goto failed;
	}

	return 0;

failed:
	if (buffer)
		free(buffer);
	return -1;
}

/*
 * Helper function to set AP address
 */
static inline void
__ni_wireless_set_ap(ni_hwaddr_t *hwa, const void *ap_addr)
{
	hwa->type = NI_IFTYPE_WIRELESS;
	hwa->len = ETH_ALEN;
	memcpy(hwa->data, ap_addr, ETH_ALEN);
}

typedef struct __ni_kernel_map_t {
	int		kernel_value;
	int		wicked_value;
} __ni_kernel_map_t;

static __ni_kernel_map_t	__ni_wireless_mode_map[] = {
	{ IW_MODE_AUTO,		NI_WIRELESS_MODE_AUTO},
	{ IW_MODE_ADHOC,	NI_WIRELESS_MODE_ADHOC},
	{ IW_MODE_INFRA,	NI_WIRELESS_MODE_MANAGED},
	{ IW_MODE_MASTER,	NI_WIRELESS_MODE_MASTER},
	{ IW_MODE_REPEAT,	NI_WIRELESS_MODE_REPEATER},
	{ IW_MODE_SECOND,	NI_WIRELESS_MODE_SECONDARY},
	{ IW_MODE_MONITOR,	NI_WIRELESS_MODE_MONITOR},
	{ -1 }
};

static __ni_kernel_map_t	__ni_wireless_cipher_map[] = {
	{ IW_IE_CIPHER_NONE,	NI_WIRELESS_CIPHER_NONE },
	{ IW_IE_CIPHER_WEP40,	NI_WIRELESS_CIPHER_WEP40 },
	{ IW_IE_CIPHER_TKIP,	NI_WIRELESS_CIPHER_TKIP },
	{ IW_IE_CIPHER_CCMP,	NI_WIRELESS_CIPHER_CCMP },
	{ IW_IE_CIPHER_WRAP,	NI_WIRELESS_CIPHER_WRAP },
	{ IW_IE_CIPHER_WEP104,	NI_WIRELESS_CIPHER_WEP104 },
	{ -1 }
};

static __ni_kernel_map_t	__ni_wireless_key_mgmt_map[] = {
	{ IW_IE_KEY_MGMT_NONE,	NI_WIRELESS_KEY_MGMT_NONE },
	{ IW_IE_KEY_MGMT_PSK,	NI_WIRELESS_KEY_MGMT_PSK },
	{ IW_IE_KEY_MGMT_802_1X,NI_WIRELESS_KEY_MGMT_802_1X },
	{ -1 }
};

static int
__ni_kernel_to_wicked(const __ni_kernel_map_t *map, int value)
{
	while (map->wicked_value >= 0) {
		if (map->kernel_value == value)
			return map->wicked_value;
		map++;
	}
	return -1;
}

static ni_intmap_t __ni_wireless_mode_names[] = {
	{ "unknown",		NI_WIRELESS_MODE_UNKNOWN },
	{ "auto",		NI_WIRELESS_MODE_AUTO },
	{ "adhoc",		NI_WIRELESS_MODE_ADHOC },
	{ "managed",		NI_WIRELESS_MODE_MANAGED },
	{ "master",		NI_WIRELESS_MODE_MASTER },
	{ "repeater",		NI_WIRELESS_MODE_REPEATER },
	{ "secondary",		NI_WIRELESS_MODE_SECONDARY },
	{ "monitor",		NI_WIRELESS_MODE_MONITOR },
	{ NULL }
};

const char *
ni_wireless_mode_to_name(ni_wireless_mode_t mode)
{
	return ni_format_int_mapped(mode, __ni_wireless_mode_names);
}

static ni_intmap_t __ni_wireless_security_names[] = {
	{ "default",		NI_WIRELESS_SECURITY_DEFAULT },
	{ "open",		NI_WIRELESS_SECURITY_OPEN },
	{ "restricted",		NI_WIRELESS_SECURITY_RESTRICTED },
	{ NULL }
};

const char *
ni_wireless_security_to_name(ni_wireless_security_t mode)
{
	return ni_format_int_mapped(mode, __ni_wireless_security_names);
}

static ni_intmap_t __ni_wireless_auth_mode_names[] = {
	{ "default",		NI_WIRELESS_AUTH_NONE },
	{ "wpa1",		NI_WIRELESS_AUTH_WPA1 },
	{ "wpa2",		NI_WIRELESS_AUTH_WPA2 },
	{ "unknown",		NI_WIRELESS_AUTH_UNKNOWN },
	{ NULL }
};

const char *
ni_wireless_auth_mode_to_name(ni_wireless_auth_mode_t mode)
{
	return ni_format_int_mapped(mode, __ni_wireless_auth_mode_names);
}

static ni_intmap_t __ni_wireless_cipher_names[] = {
	{ "none",		NI_WIRELESS_CIPHER_NONE },
	{ "proprietary",	NI_WIRELESS_CIPHER_PROPRIETARY },
	{ "wep40",		NI_WIRELESS_CIPHER_WEP40 },
	{ "tkip",		NI_WIRELESS_CIPHER_TKIP },
	{ "wrap",		NI_WIRELESS_CIPHER_WRAP },
	{ "ccmp",		NI_WIRELESS_CIPHER_CCMP },
	{ "wep104",		NI_WIRELESS_CIPHER_WEP104 },
	{ NULL }
};

const char *
ni_wireless_cipher_to_name(ni_wireless_cipher_t mode)
{
	return ni_format_int_mapped(mode, __ni_wireless_cipher_names);
}

static ni_intmap_t __ni_wireless_key_mgmt_names[] = {
	{ "none",		NI_WIRELESS_KEY_MGMT_NONE },
	{ "proprietary",	NI_WIRELESS_KEY_MGMT_PROPRIETARY },
	{ "psk",		NI_WIRELESS_KEY_MGMT_PSK },
	{ "802.1x",		NI_WIRELESS_KEY_MGMT_802_1X },
	{ NULL }
};

const char *
ni_wireless_key_management_to_name(ni_wireless_key_mgmt_t mode)
{
	return ni_format_int_mapped(mode, __ni_wireless_key_mgmt_names);
}

/*
 * Key index is 1-based.
 */
static inline void
__ni_wireless_set_key_index(unsigned int *key_index, unsigned int value)
{
	value &= IW_ENCODE_INDEX;
	*key_index = (value > 1)? value - 1 : 0;
}

/*
 * Process information elements
 */
static inline int
__ni_wireless_process_ie_cipher(ni_buffer_t *bp, const unsigned char *wpa_oui, ni_wireless_cipher_t *result)
{
	unsigned char buffer[4];

	if (ni_buffer_get(bp, buffer, 4) < 0)
		return -1;

	*result = NI_WIRELESS_CIPHER_PROPRIETARY;
	if (memcmp(buffer, wpa_oui, 3) == 0) {
		int mapped = __ni_kernel_to_wicked(__ni_wireless_cipher_map, buffer[3]);
		if (mapped >= 0)
			*result = mapped;
	}

	return 0;
}

static inline int
__ni_wireless_process_ie_key_mgmt(ni_buffer_t *bp, const unsigned char *wpa_oui, ni_wireless_key_mgmt_t *result)
{
	unsigned char buffer[4];

	if (ni_buffer_get(bp, buffer, 4) < 0)
		return -1;

	*result = NI_WIRELESS_KEY_MGMT_PROPRIETARY;
	if (memcmp(buffer, wpa_oui, 3) == 0) {
		int mapped = __ni_kernel_to_wicked(__ni_wireless_key_mgmt_map, buffer[3]);
		if (mapped >= 0)
			*result = mapped;
	}

	return 0;
}

static inline int
__ni_buffer_get_le16(ni_buffer_t *bp)
{
	unsigned char temp[2];

	if (ni_buffer_get(bp, temp, 2) < 0)
		return -1;
	return temp[0] | (temp[1] << 8);
}

static inline int
__ni_wireless_process_wpa_common(ni_wireless_network_t *net, ni_buffer_t *bp,
			ni_wireless_auth_mode_t auth_mode, const unsigned char *wpa_oui)
{
	ni_wireless_auth_info_t *auth;
	int version, count;

	if ((version = __ni_buffer_get_le16(bp)) < 0)
		return -1;

	auth = ni_wireless_auth_info_new(auth_mode, version);
	ni_wireless_auth_info_array_append(&net->auth_info, auth);

	/* Everything else is optional, so failure to get sufficient
	 * data from the buffer is non-terminal. */
	if (__ni_wireless_process_ie_cipher(bp, wpa_oui, &auth->group_cipher) < 0)
		return 0;

	/* Array of pairwise ciphers */
	if ((count = __ni_buffer_get_le16(bp)) < 0)
		return 0;

	/* Clear default list of pairwise ciphers */
	auth->pairwise_ciphers.count = 0;
	while (count--) {
		ni_wireless_cipher_t cipher;

		if (__ni_wireless_process_ie_cipher(bp, wpa_oui, &cipher) < 0)
			return -1;
		ni_wireless_auth_info_add_pairwise_cipher(auth, cipher);
	}

	/* Array of auth suites */
	if ((count = __ni_buffer_get_le16(bp)) < 0)
		return 0;

	while (count--) {
		ni_wireless_key_mgmt_t algo;

		if (__ni_wireless_process_ie_key_mgmt(bp, wpa_oui, &algo) < 0)
			return -1;
		ni_wireless_auth_info_add_key_management(auth, algo);
	}

	return 0;
}

static inline int
__ni_wireless_process_wpa1(ni_wireless_network_t *net, void *ptr, size_t len)
{
	static unsigned char wpa1_oui[] = {0x00, 0x50, 0xf2};
	unsigned char buffer[3];
	ni_buffer_t data;

	ni_buffer_init_reader(&data, ptr, len);
	if (ni_buffer_get(&data, buffer, 3) < 0)
		return -1;

	if (memcmp(buffer, wpa1_oui, 3)) {
		ni_debug_ifconfig("skipping non-WPA1 IE (OUI=%02x:%02x:%02x)",
				buffer[0], buffer[1], buffer[0]);
		return 0;
	}

	if (ni_buffer_get(&data, buffer, 1) < 0)
		return -1;
	if (buffer[0] != 0x01)
		return 0;

	return __ni_wireless_process_wpa_common(net, &data, NI_WIRELESS_AUTH_WPA1, wpa1_oui);
}

static inline int
__ni_wireless_process_wpa2(ni_wireless_network_t *net, void *ptr, size_t len)
{
	static unsigned char wpa2_oui[] = {0x00, 0x0f, 0xac};
	ni_buffer_t data;

	ni_buffer_init_reader(&data, ptr, len);
	return __ni_wireless_process_wpa_common(net, &data, NI_WIRELESS_AUTH_WPA2, wpa2_oui);
}

static inline int
__ni_wireless_process_ie(ni_wireless_network_t *net, void *ptr, size_t len)
{
	ni_buffer_t data;

	ni_buffer_init_reader(&data, ptr, len);
	while (ni_buffer_count(&data) >= 2) {
		unsigned char type, len;
		int rv;

		if (ni_buffer_get(&data, &type, 1) < 0
		 || ni_buffer_get(&data, &len, 1) < 0)
			goto format_error;

		if (ni_buffer_count(&data) < len)
			goto format_error;
		ptr = ni_buffer_head(&data);
		data.head += len;

		switch (type) {
		case 0xdd:
			rv = __ni_wireless_process_wpa1(net, ptr, len);
			break;

		case 0x30:
			rv = __ni_wireless_process_wpa2(net, ptr, len);
			break;
		}
		if (rv < 0)
			return -1;
	}
	return 0;

format_error:
	ni_error("error processing wireless Information Elements");
	return -1;
}

/*
 * Extract wireless event.
 * Holie cowe, the desygne of thif Inter-face is indisputablie baroque!
 */
static int
__ni_wireless_get_scan_event(ni_buffer_t *bp, ni_wireless_scan_t *scan, ni_wireless_network_t **netp)
{
	struct iw_event iwe;
	const char *ioctl_name = NULL;
	ni_wireless_network_t *net;
	ni_buffer_t packet = { NULL };
	__ni_wireless_event_dissector *dissect = NULL;

	/* Peek at the command/length part of the event */
	if (ni_buffer_get(bp, &iwe, IW_EV_LCP_PK_LEN) < 0)
		goto format_error;

	switch (iwe.cmd) {
	case SIOCIWFIRST ... SIOCIWLAST:
		ioctl_name = standard_ioctl_names[iwe.cmd - SIOCIWFIRST];
		dissect = standard_ioctl_handlers[iwe.cmd - SIOCIWFIRST];
		break;

	case IWEVFIRST ... IWEVLAST:
		ioctl_name = standard_event_names[iwe.cmd - IWEVFIRST];
		dissect = standard_event_handlers[iwe.cmd - IWEVFIRST];
		break;
	}

#if 0
	ni_trace("%s: cmd=0x%x/%s len=%d; left=%u", __func__, iwe.cmd,
			ioctl_name?: "SIOC***", iwe.len, ni_buffer_count(bp));
#endif

	{
		unsigned int payload_len;

		if (iwe.len < IW_EV_LCP_PK_LEN)
			goto format_error;
		payload_len = iwe.len - IW_EV_LCP_PK_LEN;
		if (payload_len > ni_buffer_count(bp))
			goto format_error;
		ni_buffer_init_reader(&packet, ni_buffer_head(bp), payload_len);
		bp->head += payload_len;
	}

	if (dissect == NULL)
		return 0;

	while (ni_buffer_count(&packet)) {
		double freq;
		int mapped;

		if (dissect(&packet, &iwe) < 0) {
			ni_debug_ifconfig("%s(): unable to parse packet (ioctl 0x%x)", __func__, iwe.cmd);
			goto format_error;
		}

		if (iwe.cmd == SIOCGIWAP) {
			const struct sockaddr *sap = &iwe.u.ap_addr;

			*netp = net = ni_wireless_network_new();
			ni_wireless_network_array_append(&scan->networks, net);
			__ni_wireless_set_ap(&net->access_point, &sap->sa_data);
			return 0;
		}

		if ((net = *netp) == NULL) {
			ni_warn("%s: skipping wireless event %d", __func__, iwe.cmd);
			return 0;
		}

		switch (iwe.cmd) {
		case SIOCGIWESSID:
			/* FIXME: properly escape non-ascii characters; handle encode index
			 * and hidden ESSID */
			if (iwe.u.essid.flags == 0) {
				ni_string_free(&net->essid);
			} else {
				ni_string_set(&net->essid, (char *) iwe.u.data.pointer, iwe.u.data.length);

				__ni_wireless_set_key_index(&net->essid_encode_index, iwe.u.essid.flags);
			}
			break;
		case SIOCGIWFREQ:
			// freq = iw_freq2float(&iwe.u.freq);
			freq = iwe.u.freq.m * pow(10, iwe.u.freq.e);
			if (freq < 1024)
				net->channel = freq;
			else
				net->frequency = freq;
			break;
		case SIOCGIWMODE:
			mapped = __ni_kernel_to_wicked(__ni_wireless_mode_map, iwe.u.mode);
			if (mapped < 0)
				ni_warn("unknown wireless mode %d", iwe.u.mode);
			else
				net->mode = mapped;
			break;

		case SIOCGIWENCODE:
			if (iwe.u.data.pointer) {
				/* set the encoding key */
				net->encode.key_len = iwe.u.data.length;
				net->encode.key_data = malloc(net->encode.key_len);
				memcpy(net->encode.key_data, iwe.u.data.pointer, net->encode.key_len);
			}
			net->encode.key_required = !(iwe.u.data.flags & IW_ENCODE_DISABLED);

			__ni_wireless_set_key_index(&net->encode.key_index, iwe.u.data.flags);
			if (iwe.u.data.flags & IW_ENCODE_RESTRICTED)
				net->encode.mode = NI_WIRELESS_SECURITY_RESTRICTED;
			else if (iwe.u.data.flags & IW_ENCODE_OPEN)
				net->encode.mode = NI_WIRELESS_SECURITY_OPEN;

			break;

		case SIOCGIWRATE:
			if (net->bitrates.count < NI_WIRELESS_BITRATES_MAX)
				net->bitrates.value[net->bitrates.count++] = iwe.u.bitrate.value;
			break;

		case IWEVQUAL:
			/* We should really try to get the link quality info here... */
			break;

		case IWEVGENIE:
			if (__ni_wireless_process_ie(net, iwe.u.data.pointer, iwe.u.data.length) < 0)
				return -1;
			break;
		}
	}

	return 0;

format_error:
	ni_error("format error in wireless event stream");
	return -1;
}

/*
 * Wireless interface config
 */
ni_wireless_t *
ni_wireless_new(void)
{
	return xcalloc(1, sizeof(ni_wireless_t));
}

void
ni_wireless_free(ni_wireless_t *wireless)
{
	__ni_wireless_network_destroy(&wireless->network);
	free(wireless);
}

/*
 * Wireless scan objects
 */
ni_wireless_scan_t *
ni_wireless_scan_new(void)
{
	return xcalloc(1, sizeof(ni_wireless_scan_t));
}

void
ni_wireless_scan_free(ni_wireless_scan_t *scan)
{
	ni_wireless_network_array_destroy(&scan->networks);
}

/*
 * Wireless network objects
 */
ni_wireless_network_t *
ni_wireless_network_new(void)
{
	return xcalloc(1, sizeof(ni_wireless_network_t));
}

void
__ni_wireless_network_destroy(ni_wireless_network_t *net)
{
	ni_string_free(&net->essid);
	if (net->encode.key_data) {
		free(net->encode.key_data);
		memset(&net->encode, 0, sizeof(net->encode));
	}
	ni_wireless_auth_info_array_destroy(&net->auth_info);
}

void
ni_wireless_network_free(ni_wireless_network_t *net)
{
	__ni_wireless_network_destroy(net);
	free(net);
}

/*
 * Wireless network arrays
 */
void
ni_wireless_network_array_init(ni_wireless_network_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_wireless_network_array_append(ni_wireless_network_array_t *array, ni_wireless_network_t *net)
{
	array->data = realloc(array->data, (array->count + 1) * sizeof(ni_wireless_network_t *));
	array->data[array->count++] = net;
}

void
ni_wireless_network_array_destroy(ni_wireless_network_array_t *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i)
		ni_wireless_network_free(array->data[i]);
	free(array->data);
	memset(array, 0, sizeof(*array));
}

/*
 * Wireless auth info
 */
ni_wireless_auth_info_t *
ni_wireless_auth_info_new(ni_wireless_auth_mode_t mode, unsigned int version)
{
	ni_wireless_auth_info_t *auth;

	auth = xcalloc(1, sizeof(*auth));
	auth->mode = mode;
	auth->version = version;
	auth->group_cipher = NI_WIRELESS_CIPHER_TKIP;
	auth->pairwise_ciphers.count = 1;
	auth->pairwise_ciphers.value[0] = NI_WIRELESS_CIPHER_TKIP;

	return auth;
}

void
ni_wireless_auth_info_add_pairwise_cipher(ni_wireless_auth_info_t *auth, ni_wireless_cipher_t cipher)
{
	if (auth->pairwise_ciphers.count < NI_WIRELESS_PAIRWISE_CIPHERS_MAX)
		auth->pairwise_ciphers.value[auth->pairwise_ciphers.count++] = cipher;
}

void
ni_wireless_auth_info_add_key_management(ni_wireless_auth_info_t *auth, ni_wireless_key_mgmt_t algo)
{
	if (auth->key_management.count < NI_WIRELESS_PAIRWISE_CIPHERS_MAX)
		auth->key_management.value[auth->key_management.count++] = algo;
}

void
ni_wireless_auth_info_free(ni_wireless_auth_info_t *auth)
{
	free(auth);
}

void
ni_wireless_auth_info_array_init(ni_wireless_auth_info_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_wireless_auth_info_array_append(ni_wireless_auth_info_array_t *array, ni_wireless_auth_info_t *auth)
{
	array->data = realloc(array->data, (array->count + 1) * sizeof(auth));
	array->data[array->count++] = auth;
}

void
ni_wireless_auth_info_array_destroy(ni_wireless_auth_info_array_t *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i)
		ni_wireless_auth_info_free(array->data[i]);
	memset(array, 0, sizeof(*array));
}

/*
 * Extract wireless event payloads from buffer
 */
static int
__ni_wireless_event_null(ni_buffer_t *bp, struct iw_event *iwe)
{
	ni_buffer_clear(bp);
	return 0;
}

static inline int
__ni_wireless_event_payload(ni_buffer_t *bp, struct iw_event *iwe, unsigned int offset, size_t len)
{
	//ni_trace("%s(cmd=0x%x, len=%u) - avail=%u", __func__, iwe->cmd, len, ni_buffer_count(bp));
	if (ni_buffer_get(bp, ((char *) iwe) + offset + IW_EV_LCP_PK_LEN, len - IW_EV_LCP_PK_LEN) < 0)
		return -1;
	return 0;
}

static int
__ni_wireless_event_char(ni_buffer_t *bp, struct iw_event *iwe)
{
	return __ni_wireless_event_payload(bp, iwe, 0, IW_EV_CHAR_PK_LEN);
}

static int
__ni_wireless_event_uint(ni_buffer_t *bp, struct iw_event *iwe)
{
	return __ni_wireless_event_payload(bp, iwe, 0, IW_EV_UINT_PK_LEN);
}

static int
__ni_wireless_event_param(ni_buffer_t *bp, struct iw_event *iwe)
{
	return __ni_wireless_event_payload(bp, iwe, 0, IW_EV_PARAM_PK_LEN);
}

static int
__ni_wireless_event_freq(ni_buffer_t *bp, struct iw_event *iwe)
{
	return __ni_wireless_event_payload(bp, iwe, 0, IW_EV_FREQ_PK_LEN);
}

static int
__ni_wireless_event_addr(ni_buffer_t *bp, struct iw_event *iwe)
{
	return __ni_wireless_event_payload(bp, iwe, 0, IW_EV_ADDR_PK_LEN);
}

static int
__ni_wireless_event_point(ni_buffer_t *bp, struct iw_event *iwe)
{
	unsigned int offset = IW_EV_POINT_OFF;
	unsigned int length = IW_EV_POINT_PK_LEN;
	unsigned int data_len;

	if (ni_buffer_get(bp, ((char *) iwe) + offset + IW_EV_LCP_PK_LEN, length - IW_EV_LCP_PK_LEN) < 0)
		return -1;

	data_len = iwe->u.data.length;
	if (data_len > ni_buffer_count(bp))
		return -1;

	iwe->u.data.pointer = data_len? ni_buffer_head(bp) : NULL;
	bp->head += data_len;
	return 0;
}


/*
 * Stuff copied from iwlib.c, which says in the header:
 *     This file is released under the GPL license.
 *     Copyright (c) 1997-2007 Jean Tourrilhes <jt@hpl.hp.com>
 */
static __ni_wireless_event_dissector *standard_ioctl_handlers[SIOCIWLAST - SIOCIWFIRST + 1] = {
	[SIOCSIWCOMMIT	- SIOCIWFIRST] = __ni_wireless_event_null,
	[SIOCGIWNAME	- SIOCIWFIRST] = __ni_wireless_event_char,
	[SIOCSIWNWID	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWNWID	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWFREQ	- SIOCIWFIRST] = __ni_wireless_event_freq,
	[SIOCGIWFREQ	- SIOCIWFIRST] = __ni_wireless_event_freq,
	[SIOCSIWMODE	- SIOCIWFIRST] = __ni_wireless_event_uint,
	[SIOCGIWMODE	- SIOCIWFIRST] = __ni_wireless_event_uint,
	[SIOCSIWSENS	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWSENS	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWRANGE	- SIOCIWFIRST] = __ni_wireless_event_null,
	[SIOCGIWRANGE	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWPRIV	- SIOCIWFIRST] = __ni_wireless_event_null,
	[SIOCGIWPRIV	- SIOCIWFIRST] = __ni_wireless_event_null,
	[SIOCSIWSTATS	- SIOCIWFIRST] = __ni_wireless_event_null,
	[SIOCGIWSTATS	- SIOCIWFIRST] = __ni_wireless_event_null,
	[SIOCSIWSPY	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCGIWSPY	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWTHRSPY	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCGIWTHRSPY	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWAP	- SIOCIWFIRST] = __ni_wireless_event_addr,
	[SIOCGIWAP	- SIOCIWFIRST] = __ni_wireless_event_addr,
	[SIOCSIWMLME	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCGIWAPLIST	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWSCAN	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCGIWSCAN	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWESSID	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCGIWESSID	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWNICKN	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCGIWNICKN	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWRATE	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWRATE	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWRTS	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWRTS	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWFRAG	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWFRAG	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWTXPOW	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWTXPOW	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWRETRY	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWRETRY	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWENCODE	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCGIWENCODE	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWPOWER	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWPOWER	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWMODUL	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWMODUL	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWGENIE	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCGIWGENIE	- SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWAUTH	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCGIWAUTH	- SIOCIWFIRST] = __ni_wireless_event_param,
	[SIOCSIWENCODEEXT - SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCGIWENCODEEXT - SIOCIWFIRST] = __ni_wireless_event_point,
	[SIOCSIWPMKSA - SIOCIWFIRST] = __ni_wireless_event_point,
};

static const char *standard_ioctl_names[SIOCIWLAST - SIOCIWFIRST + 1] = {
	[SIOCSIWCOMMIT	- SIOCIWFIRST] =  "SIOCSIWCOMMIT",
	[SIOCGIWNAME	- SIOCIWFIRST] =  "SIOCGIWNAME",
	[SIOCSIWNWID	- SIOCIWFIRST] =  "SIOCSIWNWID",
	[SIOCGIWNWID	- SIOCIWFIRST] =  "SIOCGIWNWID",
	[SIOCSIWFREQ	- SIOCIWFIRST] =  "SIOCSIWFREQ",
	[SIOCGIWFREQ	- SIOCIWFIRST] =  "SIOCGIWFREQ",
	[SIOCSIWMODE	- SIOCIWFIRST] =  "SIOCSIWMODE",
	[SIOCGIWMODE	- SIOCIWFIRST] =  "SIOCGIWMODE",
	[SIOCSIWSENS	- SIOCIWFIRST] =  "SIOCSIWSENS",
	[SIOCGIWSENS	- SIOCIWFIRST] =  "SIOCGIWSENS",
	[SIOCSIWRANGE	- SIOCIWFIRST] =  "SIOCSIWRANGE",
	[SIOCGIWRANGE	- SIOCIWFIRST] =  "SIOCGIWRANGE",
	[SIOCSIWPRIV	- SIOCIWFIRST] =  "SIOCSIWPRIV",
	[SIOCGIWPRIV	- SIOCIWFIRST] =  "SIOCGIWPRIV",
	[SIOCSIWSTATS	- SIOCIWFIRST] =  "SIOCSIWSTATS",
	[SIOCGIWSTATS	- SIOCIWFIRST] =  "SIOCGIWSTATS",
	[SIOCSIWSPY	- SIOCIWFIRST] =  "SIOCSIWSPY",
	[SIOCGIWSPY	- SIOCIWFIRST] =  "SIOCGIWSPY",
	[SIOCSIWTHRSPY	- SIOCIWFIRST] =  "SIOCSIWTHRSPY",
	[SIOCGIWTHRSPY	- SIOCIWFIRST] =  "SIOCGIWTHRSPY",
	[SIOCSIWAP	- SIOCIWFIRST] =  "SIOCSIWAP",
	[SIOCGIWAP	- SIOCIWFIRST] =  "SIOCGIWAP",
	[SIOCSIWMLME	- SIOCIWFIRST] =  "SIOCSIWMLME",
	[SIOCGIWAPLIST	- SIOCIWFIRST] =  "SIOCGIWAPLIST",
	[SIOCSIWSCAN	- SIOCIWFIRST] =  "SIOCSIWSCAN",
	[SIOCGIWSCAN	- SIOCIWFIRST] =  "SIOCGIWSCAN",
	[SIOCSIWESSID	- SIOCIWFIRST] =  "SIOCSIWESSID",
	[SIOCGIWESSID	- SIOCIWFIRST] =  "SIOCGIWESSID",
	[SIOCSIWNICKN	- SIOCIWFIRST] =  "SIOCSIWNICKN",
	[SIOCGIWNICKN	- SIOCIWFIRST] =  "SIOCGIWNICKN",
	[SIOCSIWRATE	- SIOCIWFIRST] =  "SIOCSIWRATE",
	[SIOCGIWRATE	- SIOCIWFIRST] =  "SIOCGIWRATE",
	[SIOCSIWRTS	- SIOCIWFIRST] =  "SIOCSIWRTS",
	[SIOCGIWRTS	- SIOCIWFIRST] =  "SIOCGIWRTS",
	[SIOCSIWFRAG	- SIOCIWFIRST] =  "SIOCSIWFRAG",
	[SIOCGIWFRAG	- SIOCIWFIRST] =  "SIOCGIWFRAG",
	[SIOCSIWTXPOW	- SIOCIWFIRST] =  "SIOCSIWTXPOW",
	[SIOCGIWTXPOW	- SIOCIWFIRST] =  "SIOCGIWTXPOW",
	[SIOCSIWRETRY	- SIOCIWFIRST] =  "SIOCSIWRETRY",
	[SIOCGIWRETRY	- SIOCIWFIRST] =  "SIOCGIWRETRY",
	[SIOCSIWENCODE	- SIOCIWFIRST] =  "SIOCSIWENCODE",
	[SIOCGIWENCODE	- SIOCIWFIRST] =  "SIOCGIWENCODE",
	[SIOCSIWPOWER	- SIOCIWFIRST] =  "SIOCSIWPOWER",
	[SIOCGIWPOWER	- SIOCIWFIRST] =  "SIOCGIWPOWER",
	[SIOCSIWMODUL	- SIOCIWFIRST] =  "SIOCSIWMODUL",
	[SIOCGIWMODUL	- SIOCIWFIRST] =  "SIOCGIWMODUL",
	[SIOCSIWGENIE	- SIOCIWFIRST] =  "SIOCSIWGENIE",
	[SIOCGIWGENIE	- SIOCIWFIRST] =  "SIOCGIWGENIE",
	[SIOCSIWAUTH	- SIOCIWFIRST] =  "SIOCSIWAUTH",
	[SIOCGIWAUTH	- SIOCIWFIRST] =  "SIOCGIWAUTH",
	[SIOCSIWENCODEEXT - SIOCIWFIRST] =  "SIOCSIWENCODEEXT",
	[SIOCGIWENCODEEXT - SIOCIWFIRST] =  "SIOCGIWENCODEEXT",
	[SIOCSIWPMKSA - SIOCIWFIRST]   =  "SIOCSIWPMKSA",
};

static __ni_wireless_event_dissector *standard_event_handlers[IWEVLAST - IWEVFIRST + 1] = {
	[IWEVTXDROP	- IWEVFIRST] = __ni_wireless_event_addr,
#if 0
	[IWEVQUAL	- IWEVFIRST] = __ni_wireless_event_QUAL,
#endif
	[IWEVCUSTOM	- IWEVFIRST] = __ni_wireless_event_point,
	[IWEVREGISTERED	- IWEVFIRST] = __ni_wireless_event_addr,
	[IWEVEXPIRED	- IWEVFIRST] = __ni_wireless_event_addr,
	[IWEVGENIE	- IWEVFIRST] = __ni_wireless_event_point,
	[IWEVMICHAELMICFAILURE - IWEVFIRST] = __ni_wireless_event_point,
	[IWEVASSOCREQIE	- IWEVFIRST] = __ni_wireless_event_point,
	[IWEVASSOCRESPIE- IWEVFIRST] = __ni_wireless_event_point,
	[IWEVPMKIDCAND	- IWEVFIRST] = __ni_wireless_event_point,
};

static const char *standard_event_names[IWEVLAST - IWEVFIRST + 1] = {
	[IWEVTXDROP	- IWEVFIRST] = "IWEVTXDROP",
	[IWEVQUAL	- IWEVFIRST] = "IWEVQUAL",
	[IWEVCUSTOM	- IWEVFIRST] = "IWEVCUSTOM",
	[IWEVREGISTERED	- IWEVFIRST] = "IWEVREGISTERED",
	[IWEVEXPIRED	- IWEVFIRST] = "IWEVEXPIRED",
	[IWEVGENIE	- IWEVFIRST] = "IWEVGENIE",
	[IWEVMICHAELMICFAILURE- IWEVFIRST] = "IWEVMICHAELMICFAILURE",
	[IWEVASSOCREQIE	- IWEVFIRST] = "IWEVASSOCREQIE",
	[IWEVASSOCRESPIE- IWEVFIRST] = "IWEVASSOCRESPIE",
	[IWEVPMKIDCAND	- IWEVFIRST] = "IWEVPMKIDCAND",
};

#if 0
static const unsigned int standard_ioctl_num = (sizeof(standard_ioctl_descr) /
						sizeof(struct iw_ioctl_description));

/*
 * Meta-data about all the additional standard Wireless Extension events
 * we know about.
 */
static const struct iw_ioctl_description standard_event_descr[]
	[IWEVTXDROP	- IWEVFIRST]
			= __ni_wireless_event_addr,
	},
	[IWEVQUAL	- IWEVFIRST]
			= __ni_wireless_event_QUAL,
	},
	[IWEVCUSTOM	- IWEVFIRST]
			= __ni_wireless_event_point,
		.token_size	= 1,
		.max_tokens	= IW_CUSTOM_MAX,
	},
	[IWEVREGISTERED	- IWEVFIRST]
			= __ni_wireless_event_addr,
	},
	[IWEVEXPIRED	- IWEVFIRST]
			= __ni_wireless_event_addr,
	},
	[IWEVGENIE	- IWEVFIRST]
			= __ni_wireless_event_point,
		.token_size	= 1,
		.max_tokens	= IW_GENERIC_IE_MAX,
	},
	[IWEVMICHAELMICFAILURE	- IWEVFIRST]
			= __ni_wireless_event_point,
		.token_size	= 1,
		.max_tokens	= sizeof(struct iw_michaelmicfailure),
	},
	[IWEVASSOCREQIE	- IWEVFIRST]
			= __ni_wireless_event_point,
		.token_size	= 1,
		.max_tokens	= IW_GENERIC_IE_MAX,
	},
	[IWEVASSOCRESPIE	- IWEVFIRST]
			= __ni_wireless_event_point,
		.token_size	= 1,
		.max_tokens	= IW_GENERIC_IE_MAX,
	},
	[IWEVPMKIDCAND	- IWEVFIRST]
			= __ni_wireless_event_point,
		.token_size	= 1,
		.max_tokens	= sizeof(struct iw_pmkid_cand),
	},
};
static const unsigned int standard_event_num = (sizeof(standard_event_descr) /
						sizeof(struct iw_ioctl_description));

/* Size (in bytes) of various events */
static const int event_type_size[]
	IW_EV_LCP_PK_LEN,	/* __ni_wireless_event_null */
	0,
	IW_EV_char_PK_LEN,	/* __ni_wireless_event_char */
	0,
	IW_EV_uint_PK_LEN,	/* __ni_wireless_event_uint */
	IW_EV_freq_PK_LEN,	/* __ni_wireless_event_freq */
	IW_EV_addr_PK_LEN,	/* __ni_wireless_event_addr */
	0,
	IW_EV_point_PK_LEN,	/* Without variable payload */
	IW_EV_param_PK_LEN,	/* __ni_wireless_event_param */
	IW_EV_QUAL_PK_LEN,	/* __ni_wireless_event_QUAL */
};
#endif
