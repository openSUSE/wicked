/*
 * Interfacing with wpa_supplicant through dbus interface
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
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
#include "dbus-common.h"
#include "dbus-objects/model.h"
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

	ni_dbus_object_t *	proxy;
	ni_wpa_interface_t *	iflist;
};

#define NI_WPA_SCAN_RUNNING	0
#define NI_WPA_SCAN_BSSLIST	1
#define NI_WPA_SCAN_PROPERTIES	2
struct ni_wpa_scan {
	unsigned int		count;
	unsigned int		state;
};

static ni_dbus_class_t		ni_objectmodel_wpa_class = {
	"wpa"
};
static ni_dbus_class_t		ni_objectmodel_wpanet_class = {
	"wpa-network"
};
static ni_dbus_class_t		ni_objectmodel_wpaif_class = {
	"wpa-interface"
};

static int		ni_wpa_get_interface(ni_wpa_client_t *, const char *, ni_wpa_interface_t **);
static int		ni_wpa_add_interface(ni_wpa_client_t *, const char *, ni_wpa_interface_t **);
static void		ni_wpa_interface_free(ni_wpa_interface_t *);
static int		ni_wpa_prepare_interface(ni_wpa_client_t *, ni_wpa_interface_t *, const char *);
static int		ni_wpa_interface_get_state(ni_wpa_client_t *, ni_wpa_interface_t *);
static int		ni_wpa_interface_get_capabilities(ni_wpa_client_t *, ni_wpa_interface_t *);
static void		ni_wpa_network_request_properties(ni_wpa_client_t *wpa, ni_wpa_network_t *network);
static void		ni_wpa_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
static void		ni_wpa_scan_put(ni_wpa_scan_t *);
static const char *	ni_wpa_auth_protocol_as_string(ni_wireless_auth_mode_t, DBusError *);
static dbus_bool_t	ni_wpa_auth_protocol_from_string(const char *, ni_wireless_auth_mode_t *, DBusError *);
static const char *	ni_wpa_auth_algorithm_as_string(ni_wireless_auth_algo_t, DBusError *);
static dbus_bool_t	ni_wpa_auth_algorithm_from_string(const char *, ni_wireless_auth_algo_t *, DBusError *);
static const char *	ni_wpa_keymgmt_protocol_as_string(ni_wireless_key_mgmt_t, DBusError *);
static dbus_bool_t	ni_wpa_keymgmt_protocol_from_string(const char *, ni_wireless_key_mgmt_t *, DBusError *);
static const char *	ni_wpa_cipher_as_string(ni_wireless_cipher_t, DBusError *);
static dbus_bool_t	ni_wpa_cipher_from_string(const char *, ni_wireless_cipher_t *, DBusError *);
static const char *	ni_wpa_eap_method_as_string(ni_wireless_eap_method_t, DBusError *);
static dbus_bool_t	ni_wpa_eap_method_from_string(const char *, ni_wireless_eap_method_t *, DBusError *);

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

	dbc = ni_dbus_client_open("system", NI_WPA_BUS_NAME);
	if (!dbc)
		return NULL;

	ni_dbus_client_set_error_map(dbc, __ni_wpa_error_names);

	wpa = xcalloc(1, sizeof(*wpa));
	wpa->proxy = ni_dbus_client_object_new(dbc, &ni_objectmodel_wpa_class,
			NI_WPA_OBJECT_PATH, NI_WPA_INTERFACE, wpa);
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
		ni_dbus_object_free(wpa->proxy);
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
		ni_dbus_object_t *obj = ifp->proxy;

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

ni_wpa_network_t *
ni_wpa_interface_network_by_path(ni_wpa_interface_t *ifp, const char *object_path)
{
	ni_wpa_network_t *net, **pos;

	ni_assert(ifp->proxy != NULL);
	for (pos = &ifp->scanned_networks; (net = *pos) != NULL; pos = &net->next) {
		ni_dbus_object_t *obj = net->proxy;

		if (obj && !strcmp(obj->path, object_path))
			return net;
	}

	net = xcalloc(1, sizeof(*net));
	net->proxy = ni_dbus_client_object_new(ni_dbus_object_get_client(ifp->proxy),
				&ni_objectmodel_wpanet_class,
				object_path, NI_WPA_BSS_INTERFACE, net);
	*pos = net;

	return net;
}

static void
ni_wpa_network_properties_destroy(ni_wpa_network_t *net)
{
	if (net->wpaie)
		ni_opaque_free(net->wpaie);
	if (net->wpsie)
		ni_opaque_free(net->wpsie);
	if (net->rsnie)
		ni_opaque_free(net->rsnie);

	memset(net, 0, sizeof(*net));
}

static void
ni_wpa_network_free(ni_wpa_network_t *net)
{
	if (net->proxy) {
		ni_dbus_object_free(net->proxy);
		net->proxy = NULL;
	}

	ni_wpa_network_properties_destroy(net);

	free(net);
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
	ni_wpa_network_t *net;

	if (ifp->proxy) {
		ni_dbus_object_free(ifp->proxy);
		ifp->proxy = NULL;
	}

	while ((net = ifp->scanned_networks) != NULL) {
		ifp->scanned_networks = net->next;
		ni_wpa_network_free(net);
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
		rv = ni_dbus_object_call_simple(wpa->proxy,
				NULL, "getInterface",
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
	ni_dbus_variant_t argv[2], resp[1];
	const char *object_path = NULL;
	int rv = -1;

	memset(argv, 0, sizeof(argv));
	memset(resp, 0, sizeof(resp));

	ifp = ni_wpa_client_interface_by_local_name(wpa, ifname);
	if (ifp == NULL)
		ifp = ni_wpa_interface_new(wpa, ifname);

	if (ifp->proxy == NULL) {
		DBusError error = DBUS_ERROR_INIT;

		ni_dbus_variant_set_string(&argv[0], ifname);
		ni_dbus_variant_init_dict(&argv[1]);
		ni_dbus_dict_add_string(&argv[1], "driver", "wext");

		if (!ni_dbus_object_call_variant(wpa->proxy,
					NULL, "addInterface",
					2, argv, 1, resp, &error)) {
			ni_error("%s: dbus call failed (%s: %s)", __func__,
					error.name, error.message);
			rv = -EINVAL;
			goto failed;
		}

		if (resp[0].type != DBUS_TYPE_OBJECT_PATH
		 || !ni_dbus_variant_get_string(&resp[0], &object_path)) {
			ni_error("%s: unexpected type in reply", __func__);
			rv = -EINVAL;
			goto failed;
		}

		rv = ni_wpa_prepare_interface(wpa, ifp, object_path);
		if (rv < 0)
			goto failed;
	}

	*result_p = ifp;
	rv = 0;

cleanup:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	ni_dbus_variant_destroy(&argv[0]);
	ni_dbus_variant_destroy(&argv[1]);
	ni_dbus_variant_destroy(&resp[0]);
	return rv;

failed:
	ni_wpa_interface_unbind(ifp);
	goto cleanup;
}

static int
ni_wpa_prepare_interface(ni_wpa_client_t *wpa, ni_wpa_interface_t *ifp, const char *object_path)
{
	int rv;

	ifp->proxy = ni_dbus_client_object_new(wpa->dbus, &ni_objectmodel_wpaif_class,
			object_path, NI_WPA_IF_INTERFACE, ifp);

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

	rv = ni_dbus_object_call_simple(ifp->proxy,
			NULL, "state",
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

/*
 * Request an interface scan
 */
int
ni_wpa_interface_request_scan(ni_wpa_client_t *wpa, ni_wpa_interface_t *ifp, ni_wireless_scan_t *scan)
{
	uint32_t value;
	int rv = -1;

	rv = ni_dbus_object_call_simple(ifp->proxy,
			NULL, "scan",
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
	ni_wpa_network_t *wpa_net, **pos;

	ni_debug_wireless("%s: retrieve scan results", ifp->ifname);

	/* Prune old BSSes */
	for (pos = &ifp->scanned_networks; (wpa_net = *pos) != NULL; ) {
		if (wpa_net->last_seen < too_old) {
			*pos = wpa_net->next;
			ni_wpa_network_free(wpa_net);
		} else {
			pos = &wpa_net->next;
		}
	}

	ni_wireless_network_array_destroy(&scan->networks);
	for (wpa_net = ifp->scanned_networks; wpa_net; wpa_net = wpa_net->next) {
		static double bitrates[NI_WIRELESS_BITRATES_MAX] = {
			1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54,
		};
		ni_wireless_network_t *net;

		net = ni_wireless_network_new();
		net->access_point = wpa_net->bssid;
		net->frequency = wpa_net->frequency * 1e6;
		net->essid = wpa_net->essid;
		net->max_bitrate = wpa_net->maxrate;

		if (wpa_net->wpsie)
			__ni_wireless_process_ie(net, wpa_net->wpsie->data, wpa_net->wpsie->len);
		if (wpa_net->wpaie)
			__ni_wireless_process_ie(net, wpa_net->wpaie->data, wpa_net->wpaie->len);
		if (wpa_net->rsnie)
			__ni_wireless_process_ie(net, wpa_net->rsnie->data, wpa_net->rsnie->len);

		/* wpa_supplicant doesn't give us the full list of supported bitrates,
		 * so we cheat a little here. */
		if (wpa_net->maxrate) {
			unsigned int i;

			for (i = 0; i < NI_WIRELESS_BITRATES_MAX; ++i) {
				unsigned int rate = bitrates[i] * 1e6;

				if (rate && rate < wpa_net->maxrate)
					net->bitrates.value[net->bitrates.count++] = rate;
			}
			if (net->bitrates.count < NI_WIRELESS_BITRATES_MAX)
				net->bitrates.value[net->bitrates.count++] = wpa_net->maxrate;
		}

		ni_wireless_network_array_append(&scan->networks, net);
	}
	return 0;
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

#if 0
	if (to_state == NI_WPA_IFSTATE_DISCONNECTED)
		ni_wpa_interface_unbind(ifp);
#endif
	ifp->state = to_state;
}

/*
 * Handle async retrieval of scan results.
 * The results of a scan consists of a list of object path names,
 * each of which identifies a BSS object.
 */
static void
ni_wpa_interface_scan_results(ni_dbus_object_t *proxy, ni_dbus_message_t *msg)
{
	ni_wpa_interface_t *ifp = proxy->handle;
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
			ni_wpa_network_t *net;

			net = ni_wpa_interface_network_by_path(ifp, path);
			net->last_seen = ifp->last_scan;

			ni_wpa_network_request_properties(wpa, net);
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
	ni_dbus_object_call_async(ifp->proxy,
			ni_wpa_interface_scan_results,
			"scanResults",
			0);
}

/*
 * Specify the DBus properties for BSS objects
 */
static inline ni_wpa_network_t *
__wpa_get_network(const ni_dbus_object_t *object)
{
	ni_wpa_network_t *net = object->handle;

	return net;
}

static dbus_bool_t
__wpa_dbus_bss_get_bssid(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_byte_array(argument, net->bssid.data, net->bssid.len);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_bssid(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	unsigned int len;

	if (!ni_dbus_variant_get_byte_array_minmax(argument,
				net->bssid.data, &len,
				0, sizeof(net->bssid.data)))
		return FALSE;
	net->bssid.type = NI_IFTYPE_WIRELESS;
	net->bssid.len = len;
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_ssid(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_byte_array(argument, net->essid.data, net->essid.len);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_ssid(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	unsigned int len;

	if (!ni_dbus_variant_get_byte_array_minmax(argument,
				net->essid.data, &len,
				0, sizeof(net->essid.data)))
		return FALSE;
	net->essid.len = len;
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_noise(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->noise);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_noise(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_int32(argument, &net->noise);
}

static dbus_bool_t
__wpa_dbus_bss_get_frequency(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->frequency);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_frequency(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_int32(argument, &net->frequency);
}

static dbus_bool_t
__wpa_dbus_bss_get_level(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->level);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_level(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_int32(argument, &net->level);
}

static dbus_bool_t
__wpa_dbus_bss_get_quality(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->quality);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_quality(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_int32(argument, &net->quality);
}

static dbus_bool_t
__wpa_dbus_bss_get_maxrate(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->maxrate);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_maxrate(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_int32(argument, &net->maxrate);
}

static dbus_bool_t
__wpa_dbus_bss_get_capabilities(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_uint16(argument, net->capabilities);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_capabilities(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_uint16(argument, &net->capabilities);
}

static dbus_bool_t
__wpa_get_blob(const ni_opaque_t *op, ni_dbus_variant_t *variant)
{
	ni_dbus_variant_set_byte_array(variant, op->data, op->len);
	return TRUE;
}

static dbus_bool_t
__wpa_set_blob(const ni_dbus_variant_t *variant, ni_opaque_t **op)
{
	if (variant->type != DBUS_TYPE_ARRAY
	 || variant->array.element_type != DBUS_TYPE_BYTE
	 || variant->array.len > 8192)
		return FALSE;

	if (*op)
		ni_opaque_free(*op);
	*op = ni_opaque_new(variant->byte_array_value, variant->array.len);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_wpaie(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return __wpa_get_blob(net->wpaie, argument);
}

static dbus_bool_t
__wpa_dbus_bss_set_wpaie(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return __wpa_set_blob(argument, &net->wpaie);
}

static dbus_bool_t
__wpa_dbus_bss_get_wpsie(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return __wpa_get_blob(net->wpsie, argument);
}

static dbus_bool_t
__wpa_dbus_bss_set_wpsie(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return __wpa_set_blob(argument, &net->wpsie);
}

static dbus_bool_t
__wpa_dbus_bss_get_rsnie(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return __wpa_get_blob(net->rsnie, argument);
}

static dbus_bool_t
__wpa_dbus_bss_set_rsnie(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);

	return __wpa_set_blob(argument, &net->rsnie);
}

static dbus_bool_t
__wpa_dbus_bss_get_proto(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!(value = ni_wpa_auth_protocol_as_string(net->auth_proto, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_proto(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_auth_protocol_from_string(value, &net->auth_proto, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_auth_alg(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!(value = ni_wpa_auth_algorithm_as_string(net->auth_algo, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_auth_alg(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_auth_algorithm_from_string(value, &net->auth_algo, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_key_mgmt(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!(value = ni_wpa_keymgmt_protocol_as_string(net->keymgmt_proto, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_key_mgmt(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_keymgmt_protocol_from_string(value, &net->keymgmt_proto, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_cipher(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!(value = ni_wpa_cipher_as_string(net->cipher, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_cipher(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_cipher_from_string(value, &net->cipher, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_pairwise(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!(value = ni_wpa_cipher_as_string(net->pairwise_cipher, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_pairwise(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_cipher_from_string(value, &net->pairwise_cipher, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_group(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!(value = ni_wpa_cipher_as_string(net->group_cipher, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_group(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_cipher_from_string(value, &net->group_cipher, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_eap(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!(value = ni_wpa_eap_method_as_string(net->eap_method, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_eap(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wpa_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_eap_method_from_string(value, &net->eap_method, error);
}


#define WPA_BSS_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __wpa_dbus_bss, rw)
#define WPA_BSS_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wpa_dbus_bss, rw)

static ni_dbus_property_t	wpa_bss_properties[] = {
	WPA_BSS_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, bssid, RO),
	WPA_BSS_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, ssid, RO),
	WPA_BSS_PROPERTY(INT32, noise, RO),
	WPA_BSS_PROPERTY(INT32, frequency, RO),
	WPA_BSS_PROPERTY(INT32, level, RO),
	WPA_BSS_PROPERTY(INT32, quality, RO),
	WPA_BSS_PROPERTY(INT32, maxrate, RO),
	WPA_BSS_PROPERTY(UINT16, capabilities, RO),
	WPA_BSS_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, wpaie, RO),
	WPA_BSS_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, wpsie, RO),
	WPA_BSS_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, rsnie, RO),

//	WPA_BSS_PROPERTY(STRING, psk, RO),
	WPA_BSS_PROPERTY(STRING, proto, RO),
	WPA_BSS_PROPERTY(STRING, key_mgmt, RO),
	WPA_BSS_PROPERTY(STRING, cipher, RO),
	WPA_BSS_PROPERTY(STRING, pairwise, RO),
	WPA_BSS_PROPERTY(STRING, group, RO),
	WPA_BSS_PROPERTY(STRING, auth_alg, RO),
	WPA_BSS_PROPERTY(STRING, eap, RO),
//	WPA_BSS_PROPERTY(STRING, identity, RO),
//	WPA_BSS_PROPERTY(STRING, anonymous_identity, RO),
//	WPA_BSS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, password, RO),
//	WPA_BSS_PROPERTY(STRING, wep_key0, RO),
//	WPA_BSS_PROPERTY(STRING, wep_key1, RO),
//	WPA_BSS_PROPERTY(STRING, wep_key2, RO),
//	WPA_BSS_PROPERTY(STRING, wep_key3, RO),
//	WPA_BSS_PROPERTY(INT32, wep_tx_keyid, RO),

	{ NULL }
};

ni_dbus_service_t	wpa_bssid_interface = {
	.name = NI_WPA_BSS_INTERFACE,
	.properties = wpa_bss_properties,
};

/*
 * Callback invoked when the properties() call on a BSS object returns.
 */
static void
ni_wpa_bss_properties_result(ni_dbus_object_t *proxy, ni_dbus_message_t *msg)
{
	ni_wpa_network_t *net = proxy->handle;
	ni_dbus_variant_t dict;
	DBusMessageIter iter;

	dbus_message_iter_init(msg, &iter);

	ni_dbus_variant_init_dict(&dict);
	if (!ni_dbus_message_iter_get_variant_data(&iter, &dict))
		goto failed;

	ni_wpa_network_properties_destroy(net);

	if (!ni_dbus_object_set_properties_from_dict(proxy, &wpa_bssid_interface, &dict))
		goto failed;

	ni_debug_wireless("Updated BSS %s, essid=%.*s, freq=%.3f GHz, quality=%u/70, noise=%u, level=%d dBm, maxrate=%u MB/s",
			ni_link_address_print(&net->bssid),
			net->essid.len, net->essid.data,
			net->frequency * 1e-3,
			net->quality,
			net->noise,
			(int) (net->level - 256),
			net->maxrate / 1000000);

	ni_dbus_variant_destroy(&dict);
	return;

failed:
	ni_error("trouble parsing BSS properties response");
	ni_dbus_variant_destroy(&dict);
}

/*
 * Ask for current properties of a BSS object.
 * This is an async call.
 */
static void
ni_wpa_network_request_properties(ni_wpa_client_t *wpa, ni_wpa_network_t *net)
{
	ni_dbus_object_call_async(net->proxy,
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
	{ "OPEN",		NI_WIRELESS_AUTH_OPEN		},
	{ "SHARED",		NI_WIRELESS_AUTH_SHARED		},
	{ "LEAP",		NI_WIRELESS_AUTH_LEAP		},
	{ NULL }
};

static ni_intmap_t __ni_wpa_protocol_names[] = {
	{ "WPA",		NI_WIRELESS_AUTH_WPA1		},
	{ "RSN",		NI_WIRELESS_AUTH_WPA2		},

	{ NULL }
};

static const char *
ni_wpa_auth_protocol_as_string(ni_wireless_auth_mode_t auth_mode, DBusError *error)
{
	const char *res;

	if (!(res = ni_format_int_mapped(auth_mode, __ni_wpa_protocol_names))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"cannot render auth protocol %u(%s)",
				auth_mode, ni_wireless_auth_mode_to_name(auth_mode));
	}
	return res;
}

static dbus_bool_t
ni_wpa_auth_protocol_from_string(const char *string, ni_wireless_auth_mode_t *auth_mode, DBusError *error)
{
	unsigned int value;

	if (ni_parse_int_mapped(string, __ni_wpa_protocol_names, &value) < 0) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"auth protocol \"%s\" not understood", string);
		return FALSE;
	}
	*auth_mode = value;
	return TRUE;
}

static const char *
ni_wpa_auth_algorithm_as_string(ni_wireless_auth_algo_t auth_algo, DBusError *error)
{
	const char *res;

	if (!(res = ni_format_int_mapped(auth_algo, __ni_wpa_auth_names))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"cannot render auth algorithm %u(%s)",
				auth_algo, ni_wireless_auth_algo_to_name(auth_algo));
	}
	return res;
}

static dbus_bool_t
ni_wpa_auth_algorithm_from_string(const char *string, ni_wireless_auth_algo_t *auth_algo, DBusError *error)
{
	unsigned int value;

	if (ni_parse_int_mapped(string, __ni_wpa_auth_names, &value) < 0) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"auth algorithm \"%s\" not understood", string);
		return FALSE;
	}
	*auth_algo = value;
	return TRUE;
}

static const char *
ni_wpa_keymgmt_protocol_as_string(ni_wireless_key_mgmt_t proto, DBusError *error)
{
	const char *res;

	if (!(res = ni_format_int_mapped(proto, __ni_wpa_keymgmt_names))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"cannot render keymgmt protocol %u(%s)",
				proto, ni_wireless_key_management_to_name(proto));
	}
	return res;
}

static dbus_bool_t
ni_wpa_keymgmt_protocol_from_string(const char *string, ni_wireless_key_mgmt_t *proto, DBusError *error)
{
	unsigned int value;

	if (ni_parse_int_mapped(string, __ni_wpa_keymgmt_names, &value) < 0) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"keymgmt protocol \"%s\" not understood", string);
		return FALSE;
	}
	*proto = value;
	return TRUE;
}

static const char *
ni_wpa_cipher_as_string(ni_wireless_cipher_t proto, DBusError *error)
{
	const char *res;

	if (!(res = ni_format_int_mapped(proto, __ni_wpa_cipher_names))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"cannot render cipher %u(%s)",
				proto, ni_wireless_cipher_to_name(proto));
	}
	return res;
}

static dbus_bool_t
ni_wpa_cipher_from_string(const char *string, ni_wireless_cipher_t *proto, DBusError *error)
{
	unsigned int value;

	if (ni_parse_int_mapped(string, __ni_wpa_cipher_names, &value) < 0) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"cipher \"%s\" not understood", string);
		return FALSE;
	}
	*proto = value;
	return TRUE;
}

static const char *
ni_wpa_eap_method_as_string(ni_wireless_eap_method_t proto, DBusError *error)
{
	const char *res;

	if (!(res = ni_format_int_mapped(proto, __ni_wpa_eap_method_names))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"cannot render eap method %u(%s)",
				proto, ni_wireless_eap_method_to_name(proto));
	}
	return res;
}

static dbus_bool_t
ni_wpa_eap_method_from_string(const char *string, ni_wireless_eap_method_t *proto, DBusError *error)
{
	unsigned int value;

	if (ni_parse_int_mapped(string, __ni_wpa_eap_method_names, &value) < 0) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"eap method \"%s\" not understood", string);
		return FALSE;
	}
	*proto = value;
	return TRUE;
}

static inline struct ni_wireless_interface_capabilities *
__wpa_ifcap_properties(const ni_dbus_object_t *object)
{
	ni_wpa_interface_t *wif = object->handle;

	return &wif->capabilities;
}

static dbus_bool_t
__wpa_get_capabilities(unsigned int bits, ni_dbus_variant_t *variant,
			const char *what, const ni_intmap_t *names)
{
	return FALSE;
}

static dbus_bool_t
__wpa_set_capabilities(const ni_dbus_variant_t *variant, unsigned int *bits,
			const char *what, const ni_intmap_t *names)
{
	unsigned int i;

	*bits = 0;
	for (i = 0; i < variant->array.len; ++i) {
		const char *name = variant->string_array_value[i];
		unsigned int value;

		if (ni_parse_int_mapped(name, names, &value) < 0)
			ni_warn("unable to translate %s %s", what, name);
		else if (value < 8 * sizeof(*bits))
			*bits |= (1 << value);
	}

	return TRUE;
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_get_eap(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_get_capabilities(caps->wpa_protocols, argument, "wpa protocol", __ni_wpa_protocol_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_set_eap(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_set_capabilities(argument, &caps->eap_methods, "eap protocol", __ni_wpa_eap_method_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_get_pairwise(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_get_capabilities(caps->pairwise_ciphers, argument, "pairwise cipher", __ni_wpa_cipher_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_set_pairwise(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_set_capabilities(argument, &caps->pairwise_ciphers, "pairwise cipher", __ni_wpa_cipher_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_get_group(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_get_capabilities(caps->group_ciphers, argument, "group cipher", __ni_wpa_cipher_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_set_group(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_set_capabilities(argument, &caps->group_ciphers, "group cipher", __ni_wpa_cipher_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_get_key_mgmt(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_get_capabilities(caps->keymgmt_algos, argument, "key management algorithm", __ni_wpa_keymgmt_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_set_key_mgmt(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_set_capabilities(argument, &caps->keymgmt_algos, "key management algorithm", __ni_wpa_keymgmt_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_get_auth_alg(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_get_capabilities(caps->auth_algos, argument, "authentication algorithm", __ni_wpa_auth_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_set_auth_alg(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_set_capabilities(argument, &caps->auth_algos, "authentication algorithm", __ni_wpa_auth_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_get_proto(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_get_capabilities(caps->wpa_protocols, argument, "wpa algorithm", __ni_wpa_protocol_names);
}

static dbus_bool_t
__wpa_dbus_ifcapabilities_set_proto(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	struct ni_wireless_interface_capabilities *caps = __wpa_ifcap_properties(object);

	return __wpa_set_capabilities(argument, &caps->wpa_protocols, "wpa algorithm", __ni_wpa_protocol_names);
}

#define WPA_IFCAP_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __wpa_dbus_ifcapabilities, rw)
#define WPA_IFCAP_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wpa_dbus_ifcapabilities, rw)

static ni_dbus_property_t	wpa_ifcap_properties[] = {
	WPA_IFCAP_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, eap, RO),
	WPA_IFCAP_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, pairwise, RO),
	WPA_IFCAP_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, group, RO),
	WPA_IFCAP_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, key_mgmt, RO),
	WPA_IFCAP_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, auth_alg, RO),
	WPA_IFCAP_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, proto, RO),
	WPA_IFCAP_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, eap, RO),

	{ NULL }
};

ni_dbus_service_t	wpa_ifcap_interface = {
	.name = NI_WPA_IF_INTERFACE,
	.properties = wpa_ifcap_properties,
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

int
ni_wpa_interface_get_capabilities(ni_wpa_client_t *wpa, ni_wpa_interface_t *ifp)
{
	ni_dbus_message_t *call = NULL, *reply = NULL;
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_variant_t dict;
	DBusMessageIter iter;
	int rv = -1;

	call = ni_dbus_object_call_new(ifp->proxy, "capabilities", 0);
	if (call == NULL) {
		ni_error("%s: could not build message", __func__);
		rv = -EINVAL;
		goto failed;
	}

	if ((reply = ni_dbus_client_call(wpa->dbus, call, &error)) == NULL) {
		ni_error("dbus call failed: %s (%s)", error.name, error.message);
		goto failed;
	}

	dbus_message_iter_init(reply, &iter);

	ni_dbus_variant_init_dict(&dict);
	if (!ni_dbus_message_iter_get_variant_data(&iter, &dict))
		goto failed;
	rv = ni_dbus_object_set_properties_from_dict(ifp->proxy, &wpa_ifcap_interface, &dict);

#if 0
	if (rv) {
		ni_wireless_interface_capabilities_t *caps = &ifp->capabilities;

		ni_debug_wireless("%s interface capabilities", ifp->ifname);
		ni_debug_wireless("  eap methods: %s", __ni_print_string_array(&caps->eap_methods));
		ni_debug_wireless("  pairwise ciphers: %s", __ni_print_string_array(&caps->pairwise_ciphers));
		ni_debug_wireless("  group ciphers: %s", __ni_print_string_array(&caps->group_ciphers));
		ni_debug_wireless("  keymgmt: %s", __ni_print_string_array(&caps->keymgmt_algos));
		ni_debug_wireless("  auth: %s", __ni_print_string_array(&caps->auth_algos));
		ni_debug_wireless("  wpa protos: %s", __ni_print_string_array(&caps->wpa_protocols));
	}
#endif

failed:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	ni_dbus_variant_destroy(&dict);
	dbus_error_free(&error);
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
