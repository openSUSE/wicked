/*
 * Interfacing with wpa_supplicant through dbus interface
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 *
 * Activating interface
 *  interface.setAPScan(1) (or 2)
 *
 *  interface.addNetwork(void)
 *	returns an object handle for the network
 *
 *  [watch for signals on this handle]
 *	type='signal',sender='fi.epitest.hostap.WPASupplicant',path='/fi/epitest/hostap/WPASupplicant/Interfaces/0/Networks/0',interface='fi.epitest.hostap.WPASupplicant.Network'
 *
 *  network.set(dict)
 *	Supported dict elements
 *	key_mgmt (string)
 *	scan_ssid (integer): 1
 *	psk (byte array): funny encoding?
 *	ssid (byte array)
 *
 *  interface.selectNetwork(objectPath)
 *
 * On timeout:
 *  interface.disconnect()
 *  interface.removeNetwork(objectPath)
 */

#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <wicked/util.h>
#include <netinfo_priv.h>
#include <errno.h>
#include <ctype.h>

#include "dbus-client.h"
#include "dbus-dict.h"
#include "wpa-supplicant.h"
#include "wireless_priv.h"


#define NI_WPA_BUS_NAME		"fi.epitest.hostap.WPASupplicant"
#define NI_WPA_OBJECT_PATH	"/fi/epitest/hostap/WPASupplicant"
#define NI_WPA_INTERFACE	"fi.epitest.hostap.WPASupplicant"
#define NI_WPA_IF_PATH_PFX	"/fi/epitest/hostap/WPASupplicant/Interfaces/"
#define NI_WPA_IF_INTERFACE	"fi.epitest.hostap.WPASupplicant.Interface"
#define NI_WPA_BSS_INTERFACE	"fi.epitest.hostap.WPASupplicant.BSSID"

struct ni_wpa_client {
	ni_dbus_client_t *	dbus;

	ni_dbus_proxy_t *	proxy;
	ni_wpa_interface_t *	iflist;
};

#define NI_WPA_SCAN_RUNNING	0
#define NI_WPA_SCAN_BSSLIST	1
#define NI_WPA_SCAN_PROPERTIES	2
struct ni_wpa_scan {
	unsigned int		count;
	unsigned int		state;
};

static int		ni_wpa_get_interface(ni_wpa_client_t *, const char *, ni_wpa_interface_t **);
static int		ni_wpa_add_interface(ni_wpa_client_t *, const char *, ni_wpa_interface_t **);
static void		ni_wpa_interface_free(ni_wpa_interface_t *);
static int		ni_wpa_prepare_interface(ni_wpa_client_t *, ni_wpa_interface_t *, const char *);
static int		ni_wpa_interface_get_state(ni_wpa_client_t *, ni_wpa_interface_t *);
static int		ni_wpa_interface_get_capabilities(ni_wpa_client_t *, ni_wpa_interface_t *);
static void		ni_wpa_bss_request_properties(ni_wpa_client_t *wpa, ni_wpa_bss_t *bss);
static void		ni_wpa_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
static void		ni_wpa_scan_put(ni_wpa_scan_t *);
static ni_wpa_scan_t *	ni_wpa_scan_get(ni_wpa_scan_t *);
static char *		__ni_wpa_escape_essid(const struct ni_wpa_bss_properties *);

/*
 * Map wpa_supplicant errors
 */
static ni_intmap_t	__ni_wpa_error_names[] = {
	{ "fi.epitest.hostap.WPASupplicant.InvalidInterface",	ENOENT },
	{ "fi.epitest.hostap.WPASupplicant.AddError",		ENODEV },

	{ NULL }
};

ni_wpa_client_t *
ni_wpa_client_open(void)
{
	ni_dbus_client_t *dbc;
	ni_wpa_client_t *wpa;

	dbc = ni_dbus_client_open(NI_WPA_BUS_NAME);
	if (!dbc)
		return NULL;

	ni_dbus_client_set_error_map(dbc, __ni_wpa_error_names);

	wpa = xcalloc(1, sizeof(*wpa));
	wpa->proxy = ni_dbus_proxy_new(dbc, NI_WPA_BUS_NAME, NI_WPA_OBJECT_PATH, NI_WPA_INTERFACE, wpa);
	wpa->dbus = dbc;

	ni_dbus_client_add_signal_handler(dbc,
				NI_WPA_BUS_NAME,	/* sender */
				NULL,			/* object path */
				NI_WPA_IF_INTERFACE,	/* object interface */
				ni_wpa_signal,
				wpa);

	return wpa;
}

void
ni_wpa_client_free(ni_wpa_client_t *wpa)
{
	ni_wpa_interface_t *ifp;

	if (wpa->dbus) {
		ni_dbus_client_free(wpa->dbus);
		wpa->dbus = NULL;
	}

	while ((ifp = wpa->iflist) != NULL) {
		wpa->iflist = ifp->next;
		ni_wpa_interface_free(ifp);
	}

	if (wpa->proxy) {
		ni_dbus_proxy_free(wpa->proxy);
		wpa->proxy = NULL;
	}

	free(wpa);
}

ni_dbus_client_t *
ni_wpa_client_dbus(ni_wpa_client_t *wpa)
{
	return wpa->dbus;
}

ni_wpa_interface_t *
ni_wpa_client_interface_by_local_name(ni_wpa_client_t *wpa, const char *ifname)
{
	ni_wpa_interface_t *ifp;

	for (ifp = wpa->iflist; ifp; ifp = ifp->next) {
		if (!strcmp(ifp->ifname, ifname))
			return ifp;
	}
	return NULL;
}

ni_wpa_interface_t *
ni_wpa_client_interface_by_path(ni_wpa_client_t *wpa, const char *object_path)
{
	ni_wpa_interface_t *ifp;

	for (ifp = wpa->iflist; ifp; ifp = ifp->next) {
		ni_dbus_proxy_t *obj = ifp->proxy;

		if (obj && !strcmp(obj->path, object_path))
			return ifp;
	}
	return NULL;
}

static ni_wpa_interface_t *
ni_wpa_interface_new(ni_wpa_client_t *wpa, const char *ifname)
{
	ni_wpa_interface_t *ifp;

	ifp = xcalloc(1, sizeof(*ifp));
	ni_string_dup(&ifp->ifname, ifname);
	ifp->wpa_client = wpa;

	ifp->next = wpa->iflist;
	wpa->iflist = ifp;

	return ifp;
}

ni_wpa_bss_t *
ni_wpa_interface_bss_by_path(ni_wpa_interface_t *ifp, const char *object_path)
{
	ni_wpa_bss_t *bss;

	ni_assert(ifp->proxy != NULL);
	for (bss = ifp->bss_list; bss; bss = bss->next) {
		ni_dbus_proxy_t *obj = bss->proxy;

		if (obj && !strcmp(obj->path, object_path))
			return bss;
	}

	bss = xcalloc(1, sizeof(*bss));
	bss->proxy = ni_dbus_proxy_new(ifp->proxy->client, NI_WPA_BUS_NAME, object_path, NI_WPA_BSS_INTERFACE, bss);
	bss->next = ifp->bss_list;
	ifp->bss_list = bss;

	return bss;
}

static void
ni_wpa_bss_properties_destroy(struct ni_wpa_bss_properties *props)
{
	if (props->wpaie)
		ni_opaque_free(props->wpaie);
	if (props->wpsie)
		ni_opaque_free(props->wpsie);
	if (props->rsnie)
		ni_opaque_free(props->rsnie);
	memset(props, 0, sizeof(*props));
}

static void
ni_wpa_bss_free(ni_wpa_bss_t *bss)
{
	if (bss->proxy) {
		ni_dbus_proxy_free(bss->proxy);
		bss->proxy = NULL;
	}
	if (bss->scan) {
		ni_wpa_scan_put(bss->scan);
		bss->scan = NULL;
	}
	ni_wpa_bss_properties_destroy(&bss->properties);

	free(bss);
}

/*
 * Bind an interface, ie. call wpa_supplicant to see whether it
 * knows about the interface, and if not create it.
 * Note this is a synchronous call.
 */
ni_wpa_interface_t *
ni_wpa_interface_bind(ni_wpa_client_t *wpa, const char *ifname)
{
	ni_wpa_interface_t *ifp = NULL;
	int rv;

	rv = ni_wpa_get_interface(wpa, ifname, &ifp);
	if (rv < 0) {
		if (rv != -ENOENT)
			goto failed;

		ni_debug_wireless("%s: interface does not exist", ifname);
		rv = ni_wpa_add_interface(wpa, ifname, &ifp);
		if (rv < 0)
			goto failed;
	}

	return ifp;

failed:
	ni_error("%s(%s): %s", __func__, ifname, strerror(-rv));
	return NULL;
}

/*
 * Unbind the interface, i.e. forget about the DBUS object
 * we've attached to.
 */
static void
ni_wpa_interface_unbind(ni_wpa_interface_t *ifp)
{
	ni_wpa_bss_t *bss;

	if (ifp->proxy) {
		ni_dbus_proxy_free(ifp->proxy);
		ifp->proxy = NULL;
	}

	while ((bss = ifp->bss_list) != NULL) {
		ifp->bss_list = bss->next;
		ni_wpa_bss_free(bss);
	}
}

static void
ni_wpa_interface_free(ni_wpa_interface_t *ifp)
{
	ni_string_free(&ifp->ifname);
	ni_wpa_interface_unbind(ifp);
	free(ifp);
}

/*
 * Obtain object handle for an interface
 */
static int
ni_wpa_get_interface(ni_wpa_client_t *wpa, const char *ifname, ni_wpa_interface_t **result_p)
{
	ni_wpa_interface_t *ifp;
	char *object_path = NULL;
	int rv = -1;

	ifp = ni_wpa_client_interface_by_local_name(wpa, ifname);
	if (ifp == NULL)
		ifp = ni_wpa_interface_new(wpa, ifname);

	if (ifp->proxy == NULL) {
		rv = ni_dbus_proxy_call_simple(wpa->proxy, "getInterface",
				DBUS_TYPE_STRING, &ifname,
				DBUS_TYPE_OBJECT_PATH, &object_path);
		if (rv < 0)
			goto failed;

		rv = ni_wpa_prepare_interface(wpa, ifp, object_path);
		if (rv < 0)
			goto failed;

		ni_string_free(&object_path);
	}

	*result_p = ifp;
	return 0;

failed:
	ni_wpa_interface_unbind(ifp);
	ni_string_free(&object_path);
	return rv;
}

static int
ni_wpa_add_interface(ni_wpa_client_t *wpa, const char *ifname, ni_wpa_interface_t **result_p)
{
	ni_dbus_message_t *call = NULL, *reply = NULL;
	ni_wpa_interface_t *ifp;
	char *object_path = NULL;
	int rv = -1;

	ifp = ni_wpa_client_interface_by_local_name(wpa, ifname);
	if (ifp == NULL)
		ifp = ni_wpa_interface_new(wpa, ifname);

	if (ifp->proxy == NULL) {
		DBusMessageIter iter, dict_iter;

		/* Build the addInterface call, using the given interface name
		 * and specify "wext" as the driver parameter. */
		call = ni_dbus_method_call_new_va(wpa->proxy, "addInterface", NULL);
		if (call == NULL) {
			ni_error("%s: could not build message", __func__);
			rv = -EINVAL;
			goto failed;
		}

		dbus_message_iter_init_append(call, &iter);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &ifname);
		if (!ni_dbus_dict_open_write(&iter, &dict_iter)
		 || !ni_dbus_dict_append_string(&dict_iter, "driver", "wext")
		 || !ni_dbus_dict_close_write(&iter, &dict_iter)) {
			ni_error("dbus marshalling error");
			rv = -EINVAL;
			goto failed;
		}

		/* Do the message call */
		if ((rv = ni_dbus_client_call(wpa->dbus, call, &reply)) < 0) {
			ni_error("dbus call failed: %s", strerror(-rv));
			goto failed;
		}

		rv = ni_dbus_message_get_args(reply, DBUS_TYPE_OBJECT_PATH, &object_path, 0);
		if (rv < 0)
			goto failed;

		rv = ni_wpa_prepare_interface(wpa, ifp, object_path);
		if (rv < 0)
			goto failed;
	}

	*result_p = ifp;
	rv = 0;

cleanup:
	ni_string_free(&object_path);
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	return rv;

failed:
	ni_wpa_interface_unbind(ifp);
	goto cleanup;
}

static int
ni_wpa_prepare_interface(ni_wpa_client_t *wpa, ni_wpa_interface_t *ifp, const char *object_path)
{
	int rv;

	ifp->proxy = ni_dbus_proxy_new(wpa->dbus, NI_WPA_BUS_NAME, object_path, NI_WPA_IF_INTERFACE, ifp);

	/* Get current interface state. */
	rv = ni_wpa_interface_get_state(wpa, ifp);
	if (rv < 0)
		return rv;

	rv = ni_wpa_interface_get_capabilities(wpa, ifp);
	if (rv < 0)
		return rv;

	return 0;
}

/*
 * WPA interface states
 */
static ni_intmap_t	__ni_wpa_state_names[] = {
	{ "INACTIVE",		NI_WPA_IFSTATE_INACTIVE	},
	{ "SCANNING",		NI_WPA_IFSTATE_SCANNING	},
	{ "DISCONNECTED",	NI_WPA_IFSTATE_DISCONNECTED },
	{ "ASSOCIATING",	NI_WPA_IFSTATE_ASSOCIATING },
	{ "ASSOCIATED",		NI_WPA_IFSTATE_ASSOCIATED },
	{ "COMPLETED",		NI_WPA_IFSTATE_COMPLETED },
	{ "4WAY_HANDSHAKE",	NI_WPA_IFSTATE_4WAY_HANDSHAKE },
	{ "GROUP_HANDSHAKE",	NI_WPA_IFSTATE_GROUP_HANDSHAKE },

	{ NULL }
};

ni_wpa_ifstate_t
ni_wpa_name_to_ifstate(const char *name)
{
	unsigned int res;

	if (ni_parse_int_mapped(name, __ni_wpa_state_names, &res) < 0) {
		ni_error("%s: could not map interface state %s", __func__, name);
		return NI_WPA_IFSTATE_UNKNOWN;
	}
	return res;
}

const char *
ni_wpa_ifstate_to_name(ni_wpa_ifstate_t ifs)
{
	return ni_format_int_mapped(ifs, __ni_wpa_state_names);
}

/*
 * Call wpa_supplicant to get the interface state.
 * This is only done when first obtaining the object path;
 * subsequently, we rely on wpa_supplicant sending us an update
 * whenever the state changes
 */
static int
ni_wpa_interface_get_state(ni_wpa_client_t *wpa, ni_wpa_interface_t *ifp)
{
	char *state = NULL;
	int rv = -1;

	rv = ni_dbus_proxy_call_simple(ifp->proxy, "state",
			DBUS_TYPE_INVALID, NULL,
			DBUS_TYPE_STRING, &state);
	if (rv >= 0)
		ifp->state = ni_wpa_name_to_ifstate(state);

	ni_string_free(&state);
	return rv;
}

/*
 * Handle scan objects
 */
static void
ni_wpa_scan_put(ni_wpa_scan_t *scan)
{
	if (scan == NULL)
		return;

	ni_assert(scan->count != 0);
	if (scan->count-- == 1) {
		/* FIXME: call back */
		ni_debug_wireless("%s(%p): released", __func__, scan);
		free(scan);
	}
}

static ni_wpa_scan_t *
ni_wpa_scan_get(ni_wpa_scan_t *scan)
{
	if (scan) {
		ni_assert(scan->count != 0);
		scan->count++;
	}
	return scan;
}

/*
 * Request an interface scan
 */
int
ni_wpa_interface_request_scan(ni_wpa_client_t *wpa, ni_wpa_interface_t *ifp, ni_wireless_scan_t *scan)
{
	uint32_t value;
	int rv = -1;

	rv = ni_dbus_proxy_call_simple(ifp->proxy, "scan",
			DBUS_TYPE_INVALID, NULL,
			DBUS_TYPE_UINT32, &value);

	ni_debug_wireless("%s: requested scan, value=%u", ifp->ifname, value);
	if (rv >= 0 && ifp->pending == NULL) {
		struct ni_wpa_scan *st = xcalloc(1, sizeof(*st));

		st->state = NI_WPA_SCAN_RUNNING;
		st->count = 1;
		ifp->pending = st;
	}

	return rv;
}

/*
 * Copy scan results from wpa objects to geneic ni_wireless_scan_t object
 */
int
ni_wpa_interface_retrieve_scan(ni_wpa_client_t *wpa, ni_wpa_interface_t *ifp, ni_wireless_scan_t *scan)
{
	time_t too_old = time(NULL) - scan->max_age;
	ni_wpa_bss_t *bss, **pos;

	ni_debug_wireless("%s: retrieve scan results", ifp->ifname);

	/* Prune old BSSes */
	for (pos = &ifp->bss_list; (bss = *pos) != NULL; ) {
		if (bss->last_seen < too_old) {
			*pos = bss->next;
			ni_wpa_bss_free(bss);
		} else {
			pos = &bss->next;
		}
	}

	ni_wireless_network_array_destroy(&scan->networks);
	for (bss = ifp->bss_list; bss; bss = bss->next) {
		static double bitrates[NI_WIRELESS_BITRATES_MAX] = {
			1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54,
		};
		struct ni_wpa_bss_properties *bpp = &bss->properties;
		ni_wireless_network_t *net;

		net = ni_wireless_network_new();
		net->access_point = bpp->bssid;
		net->frequency = bpp->frequency * 1e6;
		net->essid = __ni_wpa_escape_essid(bpp);

		if (bpp->wpsie)
			__ni_wireless_process_ie(net, bpp->wpsie->data, bpp->wpsie->len);
		if (bpp->wpaie)
			__ni_wireless_process_ie(net, bpp->wpaie->data, bpp->wpaie->len);
		if (bpp->rsnie)
			__ni_wireless_process_ie(net, bpp->rsnie->data, bpp->rsnie->len);

		/* wpa_supplicant doesn't give us the full list of supported bitrates,
		 * so we cheat a little here. */
		if (bpp->maxrate) {
			unsigned int i;

			for (i = 0; i < NI_WIRELESS_BITRATES_MAX; ++i) {
				unsigned int rate = bitrates[i] * 1e6;

				if (rate && rate < bpp->maxrate)
					net->bitrates.value[net->bitrates.count++] = rate;
			}
			if (net->bitrates.count < NI_WIRELESS_BITRATES_MAX)
				net->bitrates.value[net->bitrates.count++] = bpp->maxrate;
		}

		ni_wireless_network_array_append(&scan->networks, net);
	}
	return 0;
}

static char *
__ni_wpa_escape_essid(const struct ni_wpa_bss_properties *bpp)
{
	unsigned int i, j;
	char *result;

	result = malloc(4 * bpp->essid.len + 1);
	if (result == NULL)
		return NULL;

	for (i = j = 0; i < bpp->essid.len; ++i) {
		unsigned char cc = bpp->essid.data[i];

		if (isalnum(cc) || cc == '-' || cc == '_' || cc == ' ') {
			result[j++] = cc;
		} else {
			sprintf(result + j, "\\%03o", cc);
			j += 4;
		}
	}
	result[j] = '\0';

	return result;
}

/*
 * wpa_supplicant signals a StateChange event for a given interface.
 * Loop up the interface by object path and update its state.
 *
 * FIXME: notify upper layers
 */
static void
ni_wpa_interface_state_change_event(ni_wpa_client_t *wpa,
		const char *object_path,
		ni_wpa_ifstate_t from_state,
		ni_wpa_ifstate_t to_state)
{
	ni_wpa_interface_t *ifp;

	ifp = ni_wpa_client_interface_by_path(wpa, object_path);
	if (ifp == NULL) {
		ni_debug_wireless("Ignore state change on untracked interface %s",
				object_path);
		return;
	}

	ni_debug_wireless("%s: state changed %s -> %s",
			ifp->ifname,
			ni_wpa_ifstate_to_name(from_state),
			ni_wpa_ifstate_to_name(to_state));

	if (to_state == NI_WPA_IFSTATE_DISCONNECTED)
		ni_wpa_interface_unbind(ifp);
	ifp->state = to_state;
}

/*
 * Handle async retrieval of scan results.
 * The results of a scan consists of a list of object path names,
 * each of which identifies a BSS object.
 */
static void
ni_wpa_interface_scan_results(ni_dbus_proxy_t *proxy, ni_dbus_message_t *msg)
{
	ni_wpa_interface_t *ifp = proxy->local_data;
	ni_wpa_client_t *wpa = ifp->wpa_client;
	char **object_path_array = NULL;
	unsigned int object_path_count = 0;
	int rv;

	ni_debug_wireless("%s(%s)", __func__, ifp->ifname);
	rv = ni_dbus_message_get_args(msg,
			DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
			&object_path_array,
			&object_path_count,
			0);
	if (rv >= 0) {
		ni_wpa_scan_t *scan = NULL;
		unsigned int i;

		if ((scan = ifp->pending) != NULL) {
			if (scan->state == NI_WPA_SCAN_BSSLIST) {
				scan->state = NI_WPA_SCAN_PROPERTIES;
			} else {
				scan = NULL;
			}
		}

		ifp->last_scan = time(NULL);
		for (i = 0; i < object_path_count; ++i) {
			const char *path = object_path_array[i];
			ni_wpa_bss_t *bss;

			bss = ni_wpa_interface_bss_by_path(ifp, path);
			bss->last_seen = ifp->last_scan;

			ni_wpa_bss_request_properties(wpa, bss);

			if (scan) {
				ni_wpa_scan_put(bss->scan);
				bss->scan = ni_wpa_scan_get(scan);
			}
		}
	}

	ni_wpa_scan_put(ifp->pending);
	ifp->pending = NULL;

	if (object_path_array)
		dbus_free_string_array(object_path_array);
}

/*
 * wpa_supplicant signals ScanResultsAvailable.
 * Look up the interface identified by the object path provided,
 * and add the new BSSes
 */
static void
ni_wpa_interface_scan_results_available_event(ni_wpa_client_t *wpa, const char *object_path)
{
	ni_wpa_interface_t *ifp;
	ni_wpa_scan_t *scan;

	ifp = ni_wpa_client_interface_by_path(wpa, object_path);
	if (ifp == NULL || ifp->proxy == NULL) {
		ni_debug_wireless("Ignore scan results on untracked interface %s", object_path);
		return;
	}

	if ((scan = ifp->pending) != NULL && scan->state == NI_WPA_SCAN_RUNNING)
		scan->state = NI_WPA_SCAN_BSSLIST;

	ni_debug_wireless("%s: scan results available - retrieving them", ifp->ifname);
	ni_dbus_proxy_call_async(ifp->proxy,
			ni_wpa_interface_scan_results,
			"scanResults",
			0);
}

/*
 * Helper functions to set BSS properties from the DBUS dict object
 * provided by wpa_supplicant.
 */
static int
__ni_wpa_bss_set_bssid(struct ni_dbus_dict_entry *entry, void *ptr)
{
	struct ni_wpa_bss_properties *props = ptr;

	return ni_link_address_set(&props->bssid, NI_IFTYPE_WIRELESS, entry->bytearray_value, entry->array_len);
}

static int
__ni_wpa_bss_set_essid(struct ni_dbus_dict_entry *entry, void *ptr)
{
	struct ni_wpa_bss_properties *props = ptr;

	if (entry->array_len > sizeof(props->essid.data))
		return -1;

	memcpy(props->essid.data, entry->bytearray_value, entry->array_len);
	props->essid.len = entry->array_len;
	return 0;
}

#define __set_basic(field_name, type) \
	({ ((struct ni_wpa_bss_properties *) ptr)->field_name = entry->type ##_value; 0;})

static int
__ni_wpa_bss_set_frequency(struct ni_dbus_dict_entry *entry, void *ptr)
{
	return __set_basic(frequency, int32);
}

static int
__ni_wpa_bss_set_noise(struct ni_dbus_dict_entry *entry, void *ptr)
{
	return __set_basic(noise, int32);
}

static int
__ni_wpa_bss_set_level(struct ni_dbus_dict_entry *entry, void *ptr)
{
	return __set_basic(level, int32);
}

static int
__ni_wpa_bss_set_maxrate(struct ni_dbus_dict_entry *entry, void *ptr)
{
	return __set_basic(maxrate, int32);
}

static int
__ni_wpa_bss_set_quality(struct ni_dbus_dict_entry *entry, void *ptr)
{
	return __set_basic(quality, int32);
}

static int
__ni_wpa_set_blob(struct ni_dbus_dict_entry *entry, ni_opaque_t **op)
{
	if (*op)
		ni_opaque_free(*op);
	*op = ni_opaque_new(entry->bytearray_value, entry->array_len);
	return 0;
}

static int
__ni_wpa_bss_set_wpaie(struct ni_dbus_dict_entry *entry, void *ptr)
{
	return __ni_wpa_set_blob(entry, &((struct ni_wpa_bss_properties *) ptr)->wpaie);
}

static int
__ni_wpa_bss_set_wpsie(struct ni_dbus_dict_entry *entry, void *ptr)
{
	return __ni_wpa_set_blob(entry, &((struct ni_wpa_bss_properties *) ptr)->wpsie);
}

static int
__ni_wpa_bss_set_rsnie(struct ni_dbus_dict_entry *entry, void *ptr)
{
	return __ni_wpa_set_blob(entry, &((struct ni_wpa_bss_properties *) ptr)->rsnie);
}

static struct ni_dbus_dict_entry_handler __bss_property_handlers[] = {
	NI_DBUS_ARRAY_PROPERTY("bssid", DBUS_TYPE_BYTE, __ni_wpa_bss_set_bssid),
	NI_DBUS_ARRAY_PROPERTY("ssid", DBUS_TYPE_BYTE, __ni_wpa_bss_set_essid),
	NI_DBUS_BASIC_PROPERTY("frequency", DBUS_TYPE_INT32, __ni_wpa_bss_set_frequency),
	NI_DBUS_BASIC_PROPERTY("level", DBUS_TYPE_INT32, __ni_wpa_bss_set_level),
	NI_DBUS_BASIC_PROPERTY("noise", DBUS_TYPE_INT32, __ni_wpa_bss_set_noise),
	NI_DBUS_BASIC_PROPERTY("maxrate", DBUS_TYPE_INT32, __ni_wpa_bss_set_maxrate),
	NI_DBUS_BASIC_PROPERTY("quality", DBUS_TYPE_INT32, __ni_wpa_bss_set_quality),
	NI_DBUS_BASIC_PROPERTY("capabilities", DBUS_TYPE_UINT16, NULL),

	{ .name = "wpaie", .type = DBUS_TYPE_ARRAY, .array_type = DBUS_TYPE_BYTE, .array_len_max = 8192 ,
	  .set = __ni_wpa_bss_set_wpaie },
	{ .name = "wpsie", .type = DBUS_TYPE_ARRAY, .array_type = DBUS_TYPE_BYTE, .array_len_max = 8192 ,
	  .set = __ni_wpa_bss_set_wpsie },
	{ .name = "rsnie", .type = DBUS_TYPE_ARRAY, .array_type = DBUS_TYPE_BYTE, .array_len_max = 8192 ,
	  .set = __ni_wpa_bss_set_rsnie },

	{ NULL }
};

/*
 * Callback invoked when the properties() call on a BSS object returns.
 */
static void
ni_wpa_bss_properties_result(ni_dbus_proxy_t *proxy, ni_dbus_message_t *msg)
{
	ni_wpa_bss_t *bss = proxy->local_data;
	ni_wpa_scan_t *scan;
	struct ni_wpa_bss_properties *props;
	DBusMessageIter iter, dict_iter;

	dbus_message_iter_init(msg, &iter);
	if (!ni_dbus_dict_open_read(&iter, &dict_iter))
		goto failed;

	props = &bss->properties;
	ni_wpa_bss_properties_destroy(props);

	if (ni_dbus_process_properties(&dict_iter, __bss_property_handlers, props) < 0)
		goto failed;

	ni_debug_wireless("Updated BSS %s, essid=%.*s, freq=%.3f GHz, quality=%u/70, noise=%u, level=%d dBm, maxrate=%u MB/s",
			ni_link_address_print(&props->bssid),
			props->essid.len, props->essid.data,
			props->frequency * 1e-3,
			props->quality,
			props->noise,
			(int) (props->level - 256),
			props->maxrate / 1000000);

	if ((scan = bss->scan) != NULL) {
		ni_wpa_scan_put(scan);
		bss->scan = NULL;
	}

	return;

failed:
	ni_error("trouble parsing BSS properties response");
}

/*
 * Ask for current properties of a BSS object.
 * This is an async call.
 */
static void
ni_wpa_bss_request_properties(ni_wpa_client_t *wpa, ni_wpa_bss_t *bss)
{
	ni_dbus_proxy_call_async(bss->proxy,
			ni_wpa_bss_properties_result,
			"properties",
			0);
}

/*
 * Handle interface capabilities
 */
static inline int
__ni_wpa_set_string_array(struct ni_dbus_dict_entry *entry, ni_string_array_t *array)
{
	unsigned int i;

	for (i = 0; i < entry->array_len; ++i)
		ni_string_array_append(array, entry->strarray_value[i]);

	return 0;
}

static inline int
__ni_wpa_translate_caps(struct ni_dbus_dict_entry *entry, unsigned int *bits,
				const char *what, const ni_intmap_t *names)
{
	unsigned int i;

	*bits = 0;
	for (i = 0; i < entry->array_len; ++i) {
		const char *name = entry->strarray_value[i];
		unsigned int value;

		if (ni_parse_int_mapped(name, names, &value) < 0)
			ni_warn("unable to translate %s %s", what, name);
		else if (value < 8 * sizeof(*bits))
			*bits |= (1 << value);
	}

	return 0;
}

static ni_intmap_t __ni_wpa_eap_method_names[] = {
	{ "MD5",	NI_WIRELESS_EAP_MD5	},
	{ "TLS",	NI_WIRELESS_EAP_TLS	},
	{ "MSCHAPV2",	NI_WIRELESS_EAP_MSCHAPV2},
	{ "PEAP",	NI_WIRELESS_EAP_PEAP	},
	{ "TTLS",	NI_WIRELESS_EAP_TTLS	},
	{ "GTC",	NI_WIRELESS_EAP_GTC	},
	{ "OTP",	NI_WIRELESS_EAP_OTP	},
	{ "LEAP",	NI_WIRELESS_EAP_LEAP	},
	{ "PSK",	NI_WIRELESS_EAP_PSK	},
	{ "PAX",	NI_WIRELESS_EAP_PAX	},
	{ "SAKE",	NI_WIRELESS_EAP_SAKE	},
	{ "GPSK",	NI_WIRELESS_EAP_GPSK	},
	{ "WSC",	NI_WIRELESS_EAP_WSC	},
	{ "IKEV2",	NI_WIRELESS_EAP_IKEV2	},
	{ "TNC",	NI_WIRELESS_EAP_TNC	},

	{ NULL }
};

static ni_intmap_t __ni_wpa_cipher_names[] = {
	{ "CCMP",		NI_WIRELESS_CIPHER_CCMP		},
	{ "TKIP",		NI_WIRELESS_CIPHER_TKIP		},
	{ "WEP40",		NI_WIRELESS_CIPHER_WEP40	},
	{ "WEP104",		NI_WIRELESS_CIPHER_WEP104	},
	{ "WRAP",		NI_WIRELESS_CIPHER_WRAP		},
	{ NULL }
};

static ni_intmap_t __ni_wpa_keymgmt_names[] = {
	{ "NONE",		NI_WIRELESS_KEY_MGMT_NONE	},
	{ "WPA-EAP",		NI_WIRELESS_KEY_MGMT_EAP	},
	{ "WPA-PSK",		NI_WIRELESS_KEY_MGMT_PSK	},
	{ "IEEE8021X",		NI_WIRELESS_KEY_MGMT_802_1X	},
	{ NULL }
};

static ni_intmap_t __ni_wpa_auth_names[] = {
	{ NULL }
};

static ni_intmap_t __ni_wpa_protocol_names[] = {
	{ "WPA",		NI_WIRELESS_AUTH_WPA1		},
	{ "RSN",		NI_WIRELESS_AUTH_WPA2		},

	{ NULL }
};

static int
__ni_wpa_ifcapabilities_set_eap(struct ni_dbus_dict_entry *entry, void *ptr)
{
	struct ni_wireless_interface_capabilities *caps = ptr;

	return __ni_wpa_translate_caps(entry, &caps->eap_methods, "eap method", __ni_wpa_eap_method_names);
}

static int
__ni_wpa_ifcapabilities_set_pairwise(struct ni_dbus_dict_entry *entry, void *ptr)
{
	struct ni_wireless_interface_capabilities *caps = ptr;

	return __ni_wpa_translate_caps(entry, &caps->pairwise_ciphers, "pairwise cipher", __ni_wpa_cipher_names);
}

static int
__ni_wpa_ifcapabilities_set_group_ciphers(struct ni_dbus_dict_entry *entry, void *ptr)
{
	struct ni_wireless_interface_capabilities *caps = ptr;

	return __ni_wpa_translate_caps(entry, &caps->group_ciphers, "group cipher", __ni_wpa_cipher_names);
}

static int
__ni_wpa_ifcapabilities_set_keymgmt_algos(struct ni_dbus_dict_entry *entry, void *ptr)
{
	struct ni_wireless_interface_capabilities *caps = ptr;

	return __ni_wpa_translate_caps(entry, &caps->keymgmt_algos, "key management algorithm", __ni_wpa_keymgmt_names);
}

static int
__ni_wpa_ifcapabilities_set_auth_algos(struct ni_dbus_dict_entry *entry, void *ptr)
{
	struct ni_wireless_interface_capabilities *caps = ptr;

	return __ni_wpa_translate_caps(entry, &caps->auth_algos, "authentiction algorithm", __ni_wpa_auth_names);
}

static int
__ni_wpa_ifcapabilities_set_wpa_protocols(struct ni_dbus_dict_entry *entry, void *ptr)
{
	struct ni_wireless_interface_capabilities *caps = ptr;

	return __ni_wpa_translate_caps(entry, &caps->wpa_protocols, "wpa protocol", __ni_wpa_protocol_names);
}

static struct ni_dbus_dict_entry_handler __interface_capability_handlers[] = {
	NI_DBUS_ARRAY_PROPERTY("eap", DBUS_TYPE_STRING, __ni_wpa_ifcapabilities_set_eap),
	NI_DBUS_ARRAY_PROPERTY("pairwise", DBUS_TYPE_STRING, __ni_wpa_ifcapabilities_set_pairwise),
	NI_DBUS_ARRAY_PROPERTY("group", DBUS_TYPE_STRING, __ni_wpa_ifcapabilities_set_group_ciphers),
	NI_DBUS_ARRAY_PROPERTY("key_mgmt", DBUS_TYPE_STRING, __ni_wpa_ifcapabilities_set_keymgmt_algos),
	NI_DBUS_ARRAY_PROPERTY("auth_alg", DBUS_TYPE_STRING, __ni_wpa_ifcapabilities_set_auth_algos),
	NI_DBUS_ARRAY_PROPERTY("proto", DBUS_TYPE_STRING, __ni_wpa_ifcapabilities_set_wpa_protocols),

	{ NULL }
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

static int
ni_wpa_interface_capabilities_result(ni_dbus_message_t *msg, ni_wpa_interface_t *ifp)
{
	ni_wireless_interface_capabilities_t *caps;
	DBusMessageIter iter, dict_iter;

	dbus_message_iter_init(msg, &iter);
	if (!ni_dbus_dict_open_read(&iter, &dict_iter))
		goto failed;

	caps = &ifp->capabilities;
	if (ni_dbus_process_properties(&dict_iter, __interface_capability_handlers, caps) < 0)
		goto failed;

#if 0
	ni_debug_wireless("%s interface capabilities", ifp->ifname);
	ni_debug_wireless("  eap methods: %s", __ni_print_string_array(&caps->eap_methods));
	ni_debug_wireless("  pairwise ciphers: %s", __ni_print_string_array(&caps->pairwise_ciphers));
	ni_debug_wireless("  group ciphers: %s", __ni_print_string_array(&caps->group_ciphers));
	ni_debug_wireless("  keymgmt: %s", __ni_print_string_array(&caps->keymgmt_algos));
	ni_debug_wireless("  auth: %s", __ni_print_string_array(&caps->auth_algos));
	ni_debug_wireless("  wpa protos: %s", __ni_print_string_array(&caps->wpa_protocols));
#endif

	return 0;

failed:
	ni_error("trouble parsing interface capabilities response");
	return -1;
	return 0;
}

int
ni_wpa_interface_get_capabilities(ni_wpa_client_t *wpa, ni_wpa_interface_t *ifp)
{
	ni_dbus_message_t *call = NULL, *reply = NULL;
	int rv = -1;

	call = ni_dbus_method_call_new(wpa->dbus, ifp->proxy, "capabilities",
			0);
	if (call == NULL) {
		ni_error("%s: could not build message", __func__);
		rv = -EINVAL;
		goto failed;
	}

	if ((rv = ni_dbus_client_call(wpa->dbus, call, &reply)) < 0) {
		ni_error("dbus call failed: %s", strerror(-rv));
		goto failed;
	}

	rv = ni_wpa_interface_capabilities_result(reply, ifp);

failed:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	return rv;
}

/*
 * Translate WPA interface capabilities to wicked wireless constants
 */
int
ni_wpa_interface_retrieve_capabilities(ni_wpa_interface_t *wif,
				ni_wireless_interface_capabilities_t *caps)
{
	*caps = wif->capabilities;
	return 0;
}

void
ni_wpa_signal(ni_dbus_connection_t *connection, ni_dbus_message_t *msg, void *user_data)
{
	ni_wpa_client_t *wpa = user_data;
	const char *member = dbus_message_get_member(msg);
	int rv;

	if (!strcmp(member, "StateChange")) {
		char *from_state = NULL, *to_state = NULL;

		rv = ni_dbus_message_get_args(msg,
					DBUS_TYPE_STRING, &to_state,
					DBUS_TYPE_STRING, &from_state,
					0);
		if (rv >= 0) {
			ni_wpa_interface_state_change_event(wpa,
					dbus_message_get_path(msg),
					ni_wpa_name_to_ifstate(from_state),
					ni_wpa_name_to_ifstate(to_state));
		} else {
			ni_error("%s signal: unable to extract args: %s", member, strerror(-rv));
		}
		ni_string_free(&from_state);
		ni_string_free(&to_state);
	} else
	if (!strcmp(member, "ScanResultsAvailable")) {
		ni_wpa_interface_scan_results_available_event(wpa, dbus_message_get_path(msg));
	} else {
		ni_debug_wireless("%s signal received (not handled)", member);
	}
}
