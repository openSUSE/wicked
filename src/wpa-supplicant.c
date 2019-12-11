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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <time.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <wicked/util.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/netinfo.h>

#include "dbus-dict.h"
#include "dbus-common.h"
#include "dbus-objects/model.h"
#include "wpa-supplicant.h"
#include "wireless_priv.h"
#include "util_priv.h"


#define NI_WPA_BUS_NAME		"fi.epitest.hostap.WPASupplicant"
#define NI_WPA_OBJECT_PATH	"/fi/epitest/hostap/WPASupplicant"
#define NI_WPA_INTERFACE	"fi.epitest.hostap.WPASupplicant"
#define NI_WPA_IF_PATH_PFX	"/fi/epitest/hostap/WPASupplicant/Interfaces/"
#define NI_WPA_IF_INTERFACE	"fi.epitest.hostap.WPASupplicant.Interface"
#define NI_WPA_BSS_INTERFACE	"fi.epitest.hostap.WPASupplicant.BSSID"
#define NI_WPA_NETWORK_INTERFACE "fi.epitest.hostap.WPASupplicant.Network"

struct ni_wpa_client {
	ni_dbus_client_t *	dbus;

	ni_dbus_object_t *	proxy;
	ni_wpa_interface_t *	iflist;
};

static ni_dbus_class_t		ni_objectmodel_wpa_class = {
	.name = "wpa-client"
};
static ni_dbus_class_t		ni_objectmodel_wpanet_class;
static ni_dbus_class_t		ni_objectmodel_wpadev_class = {
	.name = "wpa-device"
};
static ni_dbus_service_t	ni_wpa_bssid_service;
static ni_dbus_service_t	ni_wpa_network_service;
static ni_dbus_service_t	ni_wpa_device_service;

static int		ni_wpa_get_interface(ni_wpa_client_t *, const char *, unsigned int, ni_wpa_interface_t **);
static int		ni_wpa_add_interface(ni_wpa_client_t *, const char *, unsigned int, ni_wpa_interface_t **);
static void		ni_wpa_interface_free(ni_wpa_interface_t *);
static int		ni_wpa_prepare_interface(ni_wpa_client_t *, ni_wpa_interface_t *, const char *);
static int		ni_wpa_interface_get_state(ni_wpa_client_t *, ni_wpa_interface_t *);
static int		ni_wpa_interface_get_capabilities(ni_wpa_client_t *, ni_wpa_interface_t *);
static void		ni_wpa_interface_update_state(ni_wpa_interface_t *, ni_wpa_ifstate_t);
static void		ni_wpa_network_request_properties(ni_dbus_object_t *);
static void		ni_wpa_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
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
	{ "fi.epitest.hostap.WPASupplicant.InvalidInterface",	NI_ERROR_DEVICE_NOT_KNOWN },
	{ "fi.epitest.hostap.WPASupplicant.AddError",		NI_ERROR_CANNOT_CONFIGURE_DEVICE },

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
	ni_wpa_interface_t *wpa_dev;

	if (wpa->dbus) {
		ni_dbus_client_free(wpa->dbus);
		wpa->dbus = NULL;
	}

	while ((wpa_dev = wpa->iflist) != NULL) {
		wpa->iflist = wpa_dev->next;
		ni_wpa_interface_free(wpa_dev);
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
ni_wpa_client_interface_by_index(ni_wpa_client_t *wpa, unsigned int ifindex)
{
	ni_wpa_interface_t *wpa_dev;

	for (wpa_dev = wpa->iflist; wpa_dev; wpa_dev = wpa_dev->next) {
		if (wpa_dev->ifindex == ifindex)
			return wpa_dev;
	}
	return NULL;
}

ni_wpa_interface_t *
ni_wpa_client_interface_by_path(ni_wpa_client_t *wpa, const char *object_path)
{
	ni_wpa_interface_t *wpa_dev;

	for (wpa_dev = wpa->iflist; wpa_dev; wpa_dev = wpa_dev->next) {
		ni_dbus_object_t *obj = wpa_dev->proxy;

		if (obj && !strcmp(obj->path, object_path))
			return wpa_dev;
	}
	return NULL;
}

static ni_wpa_interface_t *
ni_wpa_interface_new(ni_wpa_client_t *wpa, const char *ifname, unsigned int ifindex)
{
	ni_wpa_interface_t *wpa_dev;

	wpa_dev = xcalloc(1, sizeof(*wpa_dev));
	ni_string_dup(&wpa_dev->ifname, ifname);
	wpa_dev->ifindex = ifindex;
	wpa_dev->wpa_client = wpa;

	wpa_dev->next = wpa->iflist;
	wpa->iflist = wpa_dev;

	return wpa_dev;
}

ni_dbus_object_t *
ni_wpa_interface_network_by_path(ni_wpa_interface_t *wpa_dev, const char *object_path)
{
	ni_dbus_object_t *dev_object, *net_object;

	ni_assert((dev_object = wpa_dev->proxy) != NULL);

	net_object = ni_dbus_object_create(dev_object, object_path,
			&ni_objectmodel_wpanet_class, NULL);
	if (net_object == NULL) {
		ni_error("could not create dbus object %s", object_path);
		return NULL;
	}
	if (net_object->handle == NULL) {
		ni_debug_wireless("new object %s", net_object->path);
		ni_dbus_object_set_default_interface(net_object, NI_WPA_BSS_INTERFACE);

		if (!(net_object->handle = ni_wireless_network_new())) {
			ni_error("could not create wireless network for object %s",
				net_object->path);
			ni_dbus_object_free(net_object);
			return NULL;
		}
	}

	return net_object;
}

static void
ni_wpa_network_properties_destroy(ni_wireless_network_t *net)
{
	memset(&net->essid, 0, sizeof(net->essid));

	ni_wireless_auth_info_array_destroy(&net->scan_info.supported_auth_modes);
	memset(&net->scan_info, 0, sizeof(net->scan_info));
}

static void
ni_wpa_network_object_destroy(ni_dbus_object_t *obj)
{
	ni_wireless_network_t *net;

	if ((net = obj->handle) != NULL) {
		ni_wireless_network_put(net);
		obj->handle = NULL;
	}
}

static ni_dbus_class_t		ni_objectmodel_wpanet_class = {
	.name		= "wpa-network",
	.destroy	= ni_wpa_network_object_destroy,
};

/*
 * Bind an interface, ie. call wpa_supplicant to see whether it
 * knows about the interface, and if not create it.
 * Note this is a synchronous call.
 */
ni_wpa_interface_t *
ni_wpa_interface_bind(ni_wpa_client_t *wpa, ni_netdev_t *dev)
{
	ni_wpa_interface_t *wpa_dev = NULL;
	int rv;

	rv = ni_wpa_get_interface(wpa, dev->name, dev->link.ifindex, &wpa_dev);
	if (rv < 0) {
		if (rv != -NI_ERROR_DEVICE_NOT_KNOWN)
			goto failed;

		ni_debug_wireless("%s: interface does not exist", dev->name);
		rv = ni_wpa_add_interface(wpa, dev->name, dev->link.ifindex, &wpa_dev);
		if (rv < 0)
			goto failed;
	}

	return wpa_dev;

failed:
	ni_error("%s(%s): %s", __func__, dev->name, strerror(-rv));
	return NULL;
}

/*
 * Unbind the interface, i.e. forget about the DBUS object
 * we've attached to.
 */
static void
ni_wpa_interface_unbind(ni_wpa_interface_t *wpa_dev)
{
	if (wpa_dev->proxy) {
		ni_dbus_object_free(wpa_dev->proxy);
		wpa_dev->proxy = NULL;
	}

	/* An child objects, such as networks, will be freed implicitly
	 * by the call to ni_dbus_object_free above. */
}

static void
ni_wpa_interface_free(ni_wpa_interface_t *wpa_dev)
{
	ni_string_free(&wpa_dev->ifname);
	ni_wpa_interface_unbind(wpa_dev);
	free(wpa_dev);
}

static inline ni_wireless_network_t *
__ni_wpa_interface_next_network(ni_dbus_object_t **pnext, ni_dbus_object_t **pthis)
{
	ni_dbus_object_t *child;
	ni_wireless_network_t *net = NULL;

	while ((child = *pnext) != NULL) {
		*pnext = child->next;

		if (child->class == &ni_objectmodel_wpanet_class) {
			net = child->handle;
			break;
		}
	}

	if (pthis)
		*pthis = child;
	return net;
}

static ni_wireless_network_t *
ni_wpa_interface_first_network(ni_wpa_interface_t *dev, ni_dbus_object_t **pnext, ni_dbus_object_t **pthis)
{
	ni_dbus_object_t *obj;

	if ((obj = dev->proxy) == NULL)
		return NULL;

	if ((obj = ni_dbus_object_lookup(obj, "BSSIDs")) == NULL)
		return NULL;

	*pnext = obj->children;
	return __ni_wpa_interface_next_network(pnext, pthis);
}

static ni_wireless_network_t *
ni_wpa_interface_next_network(ni_wpa_interface_t *dev, ni_dbus_object_t **pnext, ni_dbus_object_t **pthis)
{
	return __ni_wpa_interface_next_network(pnext, pthis);
}

static unsigned int
ni_wpa_interface_expire_networks(ni_wpa_interface_t *dev, unsigned int max_age)
{
	ni_dbus_object_t *dev_object, *pos, *cur;
	ni_wireless_network_t *net;
	unsigned int num_expired = 0;
	struct timeval expired;

	if ((dev_object = dev->proxy) == NULL)
		return 0;

	ni_timer_get_time(&expired);
	expired.tv_sec -= max_age;
	for (net = ni_wpa_interface_first_network(dev, &pos, &cur); net;
	     net = ni_wpa_interface_next_network(dev, &pos, &cur)) {
		if (timerisset(&net->scan_info.timestamp) &&
		    timercmp(&net->scan_info.timestamp, &expired, <)) {
			/* This will also remove child from the list of dev_object->children */
			ni_dbus_object_free(cur);
			num_expired++;
		}
	}
	return num_expired;
}

/*
 * Obtain object handle for an interface
 */
static int
ni_wpa_get_interface(ni_wpa_client_t *wpa, const char *ifname, unsigned int ifindex, ni_wpa_interface_t **result_p)
{
	ni_wpa_interface_t *wpa_dev;
	char *object_path = NULL;
	int rv = -1;

	wpa_dev = ni_wpa_client_interface_by_index(wpa, ifindex);
	if (wpa_dev == NULL)
		wpa_dev = ni_wpa_interface_new(wpa, ifname, ifindex);

	if (wpa_dev->proxy == NULL) {
		rv = ni_dbus_object_call_simple(wpa->proxy,
				NULL, "getInterface",
				DBUS_TYPE_STRING, &ifname,
				DBUS_TYPE_OBJECT_PATH, &object_path);
		if (rv < 0)
			goto failed;

		rv = ni_wpa_prepare_interface(wpa, wpa_dev, object_path);
		if (rv < 0)
			goto failed;

		ni_string_free(&object_path);
	}

	*result_p = wpa_dev;
	return 0;

failed:
	ni_wpa_interface_unbind(wpa_dev);
	ni_string_free(&object_path);
	return rv;
}

static int
ni_wpa_add_interface(ni_wpa_client_t *wpa, const char *ifname, unsigned int ifindex, ni_wpa_interface_t **result_p)
{
	ni_dbus_message_t *call = NULL, *reply = NULL;
	ni_wpa_interface_t *wpa_dev;
	ni_dbus_variant_t argv[2], resp[1];
	const char *object_path = NULL;
	int rv = -1;

	memset(argv, 0, sizeof(argv));
	memset(resp, 0, sizeof(resp));

	wpa_dev = ni_wpa_client_interface_by_index(wpa, ifindex);
	if (wpa_dev == NULL)
		wpa_dev = ni_wpa_interface_new(wpa, ifname, ifindex);

	if (wpa_dev->proxy == NULL) {
		DBusError error = DBUS_ERROR_INIT;

		ni_dbus_variant_set_string(&argv[0], ifname);
		ni_dbus_variant_init_dict(&argv[1]);
		ni_dbus_dict_add_string(&argv[1], "driver", "wext");

		if (!ni_dbus_object_call_variant(wpa->proxy,
					NULL, "addInterface",
					2, argv, 1, resp, &error)) {
			ni_error("%s: dbus call failed (%s: %s)", __func__,
					error.name, error.message);
			rv = -NI_ERROR_INVALID_ARGS;
			goto failed;
		}

		if (resp[0].type != DBUS_TYPE_OBJECT_PATH
		 || !ni_dbus_variant_get_object_path(&resp[0], &object_path)) {
			ni_error("%s: unexpected type in reply", __func__);
			rv = -NI_ERROR_INVALID_ARGS;
			goto failed;
		}

		rv = ni_wpa_prepare_interface(wpa, wpa_dev, object_path);
		if (rv < 0)
			goto failed;
	}

	*result_p = wpa_dev;
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
	ni_wpa_interface_unbind(wpa_dev);
	goto cleanup;
}

static int
ni_wpa_prepare_interface(ni_wpa_client_t *wpa, ni_wpa_interface_t *wpa_dev, const char *object_path)
{
	int rv;

	wpa_dev->proxy = ni_dbus_client_object_new(wpa->dbus, &ni_objectmodel_wpadev_class,
			object_path, NI_WPA_IF_INTERFACE, wpa_dev);

	/* Get current interface state. */
	rv = ni_wpa_interface_get_state(wpa, wpa_dev);
	if (rv < 0)
		return rv;

	rv = ni_wpa_interface_get_capabilities(wpa, wpa_dev);
	if (rv < 0)
		return rv;

	return 0;
}

/*
 * WPA interface states
 */
static ni_intmap_t	__ni_wpa_state_names[] = {
	{ "INACTIVE",		NI_WPA_IFSTATE_INACTIVE	},
	{ "INTERFACE_DISABLED",	NI_WPA_IFSTATE_INACTIVE	},
	{ "SCANNING",		NI_WPA_IFSTATE_SCANNING	},
	{ "DISCONNECTED",	NI_WPA_IFSTATE_DISCONNECTED },
	{ "ASSOCIATING",	NI_WPA_IFSTATE_ASSOCIATING },
	{ "ASSOCIATED",		NI_WPA_IFSTATE_ASSOCIATED },
	{ "AUTHENTICATING",	NI_WPA_IFSTATE_AUTHENTICATING },
	{ "COMPLETED",		NI_WPA_IFSTATE_COMPLETED },
	{ "4WAY_HANDSHAKE",	NI_WPA_IFSTATE_4WAY_HANDSHAKE },
	{ "GROUP_HANDSHAKE",	NI_WPA_IFSTATE_GROUP_HANDSHAKE },

	{ NULL }
};

ni_wpa_ifstate_t
ni_wpa_name_to_ifstate(const char *name)
{
	unsigned int res;

	if (ni_parse_uint_mapped(name, __ni_wpa_state_names, &res) < 0) {
		ni_error("%s: could not map interface state %s", __func__, name);
		return NI_WPA_IFSTATE_UNKNOWN;
	}
	return res;
}

const char *
ni_wpa_ifstate_to_name(ni_wpa_ifstate_t ifs)
{
	return ni_format_uint_mapped(ifs, __ni_wpa_state_names);
}

/*
 * Call wpa_supplicant to get the interface state.
 * This is only done when first obtaining the object path;
 * subsequently, we rely on wpa_supplicant sending us an update
 * whenever the state changes
 */
static int
ni_wpa_interface_get_state(ni_wpa_client_t *wpa, ni_wpa_interface_t *wpa_dev)
{
	char *state = NULL;
	int rv = -1;

	rv = ni_dbus_object_call_simple(wpa_dev->proxy,
			NULL, "state",
			DBUS_TYPE_INVALID, NULL,
			DBUS_TYPE_STRING, &state);
	if (rv >= 0)
		ni_wpa_interface_update_state(wpa_dev, ni_wpa_name_to_ifstate(state));

	ni_string_free(&state);
	return rv;
}

/*
 * Set AP scanning
 */
static dbus_bool_t
ni_wpa_interface_set_ap_scan(ni_wpa_interface_t *dev, unsigned int level)
{
	uint32_t value = level;
	int rv;

	rv = ni_dbus_object_call_simple(dev->proxy,
			NULL, "setAPScan",
			DBUS_TYPE_UINT32, &value,
			DBUS_TYPE_INVALID, NULL);

	if (rv < 0) {
		ni_error("%s.setAPScan(%u) failed", dev->ifname, level);
		return FALSE;
	}

	return TRUE;
}

/*
 * Request an interface scan
 */
int
ni_wpa_interface_request_scan(ni_wpa_interface_t *wpa_dev, ni_wireless_scan_t *scan)
{
	uint32_t value;
	int rv = -1;

	rv = ni_dbus_object_call_simple(wpa_dev->proxy,
			NULL, "scan",
			DBUS_TYPE_INVALID, NULL,
			DBUS_TYPE_UINT32, &value);

	ni_timer_get_time(&scan->timestamp);
	wpa_dev->scan.timestamp = scan->timestamp;
	wpa_dev->scan.pending = 1;
	return rv;
}

/*
 * Check whether a scan is still in progress
 */
ni_bool_t
ni_wpa_interface_scan_in_progress(ni_wpa_interface_t *wpa_dev)
{
	ni_wireless_network_t *net;
	ni_dbus_object_t *pos;

	if (wpa_dev->scan.pending)
		return TRUE;

	for (net = ni_wpa_interface_first_network(wpa_dev, &pos, NULL); net; net = ni_wpa_interface_next_network(wpa_dev, &pos, NULL)) {
		if (net->scan_info.updating)
			return TRUE;
	}
	return FALSE;
}

/*
 * Copy scan results from wpa objects to generic ni_wireless_scan_t object
 * Returns TRUE iff the list of networks in scanning range changed.
 */
ni_bool_t
ni_wpa_interface_retrieve_scan(ni_wpa_interface_t *wpa_dev, ni_wireless_scan_t *scan)
{
	ni_wireless_network_t *net;
	ni_dbus_object_t *pos;
	ni_bool_t send_event = FALSE;

	/* Prune old BSSes */
	if (ni_wpa_interface_expire_networks(wpa_dev, scan->interval + 1) == 0) {
		/* Nothing pruned. If we didn't receive new scan results in the
		 * mean time, there's nothing we need to do. */
		if (!timercmp(&scan->timestamp, &wpa_dev->scan.timestamp, !=))
			return FALSE;

		send_event = TRUE;
	}

	ni_wireless_network_array_destroy(&scan->networks);
	for (net = ni_wpa_interface_first_network(wpa_dev, &pos, NULL); net; net = ni_wpa_interface_next_network(wpa_dev, &pos, NULL)) {
		/* We mix networks learned through scanning with those we configured manually.
		 * We can tell them apart by their timestamp field. Manually configured networks
		 * have no scan_info.
		 *
		 * Note, we may just be in the process of obtaining the BSS properties of a
		 * new network from wpa-supplicant. In this case, the access_point has not been
		 * set yet.
		 */
		if (timerisset(&net->scan_info.timestamp) && net->access_point.len != 0) {
			ni_wireless_network_array_append(&scan->networks, net);
			if (!net->notified) {
				net->notified = TRUE;
				send_event = TRUE;
			}
		}
	}
	scan->timestamp = wpa_dev->scan.timestamp;

	return send_event;
}

/*
 * Call the addNetwork() method
 */
char *
ni_wpa_interface_add_network(ni_wpa_interface_t *dev)
{
	char *object_path = NULL;
	int rv;

	rv = ni_dbus_object_call_simple(dev->proxy,
			NI_WPA_IF_INTERFACE, "addNetwork",
			DBUS_TYPE_INVALID, NULL,
			DBUS_TYPE_OBJECT_PATH, &object_path);
	if (rv < 0)
		return NULL;
	return object_path;
}

dbus_bool_t
ni_wpa_interface_remove_network(ni_wpa_interface_t *dev, const char *object_path)
{
	int rv;

	rv = ni_dbus_object_call_simple(dev->proxy,
			NI_WPA_IF_INTERFACE, "removeNetwork",
			DBUS_TYPE_OBJECT_PATH, &object_path,
			DBUS_TYPE_INVALID, NULL);
	return rv >= 0;
}

ni_bool_t
ni_wpa_interface_select_network(ni_wpa_interface_t *dev, ni_dbus_object_t *net_object)
{
	const char *object_path = net_object->path;
	int rv;

	rv = ni_dbus_object_call_simple(dev->proxy,
			NI_WPA_IF_INTERFACE, "selectNetwork",
			DBUS_TYPE_OBJECT_PATH, &object_path,
			DBUS_TYPE_INVALID, NULL);
	if (rv < 0) {
		ni_error("%s(%s) failed: %s", __func__, dev->ifname, ni_strerror(rv));
		return FALSE;
	}
	return TRUE;
}

ni_bool_t
ni_wpa_interface_disconnect(ni_wpa_interface_t *dev)
{
	int rv;

	rv = ni_dbus_object_call_simple(dev->proxy,
			NI_WPA_IF_INTERFACE, "disconnect",
			DBUS_TYPE_INVALID, NULL,
			DBUS_TYPE_INVALID, NULL);
	if (rv < 0) {
		ni_error("%s() failed: %s", __func__, ni_strerror(rv));
		return FALSE;
	}
	return TRUE;
}

/*
 * Call a network's set() method
 */
int
ni_wpa_network_set(ni_dbus_object_t *net_object, ni_wireless_network_t *net)
{
	ni_dbus_variant_t dict = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	ni_wireless_network_t *old_net;
	dbus_bool_t rv = FALSE;

	if ((old_net = net_object->handle) != NULL) {
		ni_wireless_network_put(old_net);
		net_object->handle = NULL;
	}

	net_object->handle = ni_wireless_network_get(net);

	ni_dbus_variant_init_dict(&dict);
	if (!ni_dbus_object_get_properties_as_dict(net_object, &ni_wpa_network_service, &dict, NULL)) {
		ni_error("failed to obtain wireless network properties");
		goto done;
	}

	/* FIXME: This call may fail if NetworkManager or anybody else removes the
	 * network object we created.
	 * We should probably add a new network object and retry in this case...
	 */
	if (!ni_dbus_object_call_variant(net_object, NI_WPA_NETWORK_INTERFACE, "set", 1, &dict, 0, NULL, &error)) {
		ni_error("%s failed: %s (%s)", __func__, error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	rv = TRUE;

done:
	ni_dbus_variant_destroy(&dict);
	return rv;
}

/*
 * The user asks us to configure the interface
 */
int
ni_wpa_interface_associate(ni_wpa_interface_t *dev, ni_wireless_network_t *net, ni_wireless_ap_scan_mode_t ap_scan)
{
	ni_dbus_object_t *net_object;

	ni_debug_wireless("%s(dev=%s, essid='%s')", __func__, dev->ifname,
			ni_wireless_print_ssid(&net->essid));

	/* FIXME: make sure we have all the keys/pass phrases etc to
	 * associate. */

	ni_wpa_interface_set_ap_scan(dev, ap_scan);

	if ((net_object = dev->requested_association.proxy) == NULL) {
		char *object_path;

		/* Call addNetwork to add the network object */
		object_path = ni_wpa_interface_add_network(dev);
		if (object_path == NULL)
			return -1;

		net_object = ni_wpa_interface_network_by_path(dev, object_path);
		free(object_path);

		if (net_object == NULL)
			return -1;
		dev->requested_association.proxy = net_object;
	}

	if (!ni_wpa_network_set(net_object, net))
		return -1;

	if (!ni_wpa_interface_select_network(dev, net_object))
		return -1;

	/* When we return, this means we initiated the association with
	 * the given AP. When the interface changes to COMPLETED, we
	 * will inform the upper layers through an event.
	 */
	 ni_wireless_passwd_clear(net);

	return 0;
}

int
ni_wpa_interface_disassociate(ni_wpa_interface_t *wpa_dev, ni_wireless_ap_scan_mode_t ap_scan)
{
	ni_dbus_object_t *net_object;

	if ((net_object = wpa_dev->requested_association.proxy) != NULL) {
		if (!ni_wpa_interface_remove_network(wpa_dev, net_object->path)) {
			ni_error("%s: failed to remove network", wpa_dev->ifname);
			return -1;
		}

		/* __ni_dbus_object_unlink(net_object); */
		ni_dbus_object_free(net_object);
		wpa_dev->requested_association.proxy = NULL;
	}

	if (!ni_wpa_interface_disconnect(wpa_dev)) {
		ni_error("%s: failed to disconnect", wpa_dev->ifname);
		return -1;
	}

	if (wpa_dev->requested_association.config) {
		ni_wireless_network_put(wpa_dev->requested_association.config);
		wpa_dev->requested_association.config = NULL;
	}

	ni_wpa_interface_set_ap_scan(wpa_dev, ap_scan);
	return 0;
}

/*
 * wpa_supplicant signals a StateChange event for a given interface.
 * Look up the interface by object path and update its state.
 *
 * FIXME: notify upper layers
 */
static void
ni_wpa_interface_state_change_event(ni_wpa_client_t *wpa,
		const char *object_path,
		ni_wpa_ifstate_t from_state,
		ni_wpa_ifstate_t to_state)
{
	ni_wpa_interface_t *wpa_dev;

	wpa_dev = ni_wpa_client_interface_by_path(wpa, object_path);
	if (wpa_dev == NULL) {
		ni_debug_wireless("Ignore state change on untracked interface %s",
				object_path);
		return;
	}

	ni_debug_wireless("%s: state changed %s -> %s",
			wpa_dev->ifname,
			ni_wpa_ifstate_to_name(from_state),
			ni_wpa_ifstate_to_name(to_state));

	ni_wpa_interface_update_state(wpa_dev, to_state);
}

static void
ni_wpa_interface_update_state(ni_wpa_interface_t *dev, ni_wpa_ifstate_t new_state)
{
	ni_wireless_assoc_state_t assoc_state;

	dev->state = new_state;
	switch (new_state) {
	case NI_WPA_IFSTATE_INACTIVE:
	case NI_WPA_IFSTATE_SCANNING:
	case NI_WPA_IFSTATE_DISCONNECTED:
		assoc_state = NI_WIRELESS_NOT_ASSOCIATED;
		break;

	case NI_WPA_IFSTATE_ASSOCIATING:
		assoc_state = NI_WIRELESS_ASSOCIATING;
		break;

	case NI_WPA_IFSTATE_ASSOCIATED:
	case NI_WPA_IFSTATE_AUTHENTICATING:
	case NI_WPA_IFSTATE_4WAY_HANDSHAKE:
	case NI_WPA_IFSTATE_GROUP_HANDSHAKE:
		assoc_state = NI_WIRELESS_AUTHENTICATING;
		break;

	case NI_WPA_IFSTATE_COMPLETED:
		assoc_state = NI_WIRELESS_ESTABLISHED;
		break;

	default:
		return;
	}

	ni_wireless_association_changed(dev->ifindex, assoc_state);
}

/*
 * Handle async retrieval of scan results.
 * The results of a scan consists of a list of object path names,
 * each of which identifies a BSS object.
 */
static void
ni_wpa_interface_scan_results(ni_dbus_object_t *proxy, ni_dbus_message_t *msg)
{
	ni_wpa_interface_t *wpa_dev = proxy->handle;
	char **object_path_array = NULL;
	unsigned int object_path_count = 0;
	int rv;

	rv = ni_dbus_message_get_args(msg,
			DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
			&object_path_array,
			&object_path_count,
			0);
	wpa_dev->scan.pending = 0;

	if (rv >= 0) {
		unsigned int i;

		ni_timer_get_time(&wpa_dev->scan.timestamp);
		for (i = 0; i < object_path_count; ++i) {
			const char *path = object_path_array[i];
			ni_dbus_object_t *net_object;
			ni_wireless_network_t *net;

			if (!(net_object = ni_wpa_interface_network_by_path(wpa_dev, path)))
				continue;

			net = net_object->handle;
			net->scan_info.updating = TRUE;
			ni_wpa_network_request_properties(net_object);
		}
	}

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
	ni_wpa_interface_t *wpa_dev;

	wpa_dev = ni_wpa_client_interface_by_path(wpa, object_path);
	if (wpa_dev == NULL || wpa_dev->proxy == NULL) {
		ni_debug_wireless("Ignore scan results on untracked interface %s", object_path);
		return;
	}

	ni_debug_wireless("%s: scan results available - retrieving them", wpa_dev->ifname);
	ni_dbus_object_call_async(wpa_dev->proxy,
			ni_wpa_interface_scan_results,
			"scanResults",
			0);
}

/*
 * Specify the DBus properties for BSS objects
 */
static inline ni_wireless_network_t *
__wpa_get_network(const ni_dbus_object_t *object)
{
	ni_wireless_network_t *net = object->handle;

	return net;
}

static inline dbus_bool_t
__ni_dbus_property_not_present_error(DBusError *error, const ni_dbus_property_t *property)
{
	dbus_set_error(error, NI_DBUS_ERROR_PROPERTY_NOT_PRESENT, "property %s not present", property->name);
	return FALSE;
}

static dbus_bool_t
__wpa_dbus_bss_get_no_property(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	return __ni_dbus_property_not_present_error(error, property);
}

static dbus_bool_t
__wpa_dbus_bss_get_bssid(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	if (net->access_point.len != ni_link_address_length(ARPHRD_ETHER))
		return __ni_dbus_property_not_present_error(error, property);

	ni_dbus_variant_set_byte_array(argument, net->access_point.data, net->access_point.len);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_bssid(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	unsigned int len;

	if (!ni_dbus_variant_get_byte_array_minmax(argument,
				net->access_point.data, &len,
				0, sizeof(net->access_point.data)))
		return FALSE;

	if (len == ni_link_address_length(ARPHRD_ETHER)) {
		net->access_point.type = ARPHRD_ETHER;
		net->access_point.len = len;
	} else {
		ni_link_address_init(&net->access_point);
	}
	return TRUE;
}


static dbus_bool_t
__wpa_dbus_net_get_bssid(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *bssid;

	if (net->access_point.type != ARPHRD_ETHER ||
	    net->access_point.len  != ni_link_address_length(ARPHRD_ETHER))
		return __ni_dbus_property_not_present_error(error, property);

	/* Send '\0' for "any" and "off" */
	if (ni_link_address_is_invalid(&net->access_point))
		bssid = NULL;
	else
		bssid = ni_link_address_print(&net->access_point);
	ni_dbus_variant_set_string(argument, bssid);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_net_set_bssid(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *bssid;

	if (ni_dbus_variant_get_string(argument, &bssid)) {
		if (ni_string_empty(bssid))
			ni_link_address_init(&net->access_point);
		else
		if (ni_link_address_parse(&net->access_point, ARPHRD_ETHER, bssid) != 0)
			return FALSE;
	}
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_ssid(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_byte_array(argument, net->essid.data, net->essid.len);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_ssid(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
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
	ni_wireless_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->scan_info.noise);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_noise(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_int32(argument, &net->scan_info.noise);
}

static dbus_bool_t
__wpa_dbus_bss_get_frequency(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	if (net->scan_info.frequency == 0)
		return __ni_dbus_property_not_present_error(error, property);

	/* Convert GHz -> MHz */
	ni_dbus_variant_set_int32(argument, 1000 * net->scan_info.frequency);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_frequency(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	unsigned int freq;

	if (!ni_dbus_variant_get_uint(argument, &freq))
		return FALSE;
	/* Convert MHz -> GHz */
	net->scan_info.frequency = freq * 1e-3;
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_level(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	/* wpa_supplicant expects the level as a 256-biased value */
	ni_dbus_variant_set_int32(argument, net->scan_info.level + 256);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_level(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	int32_t level;

	if (!ni_dbus_variant_get_int32(argument, &level))
		return FALSE;
	net->scan_info.level = level - 256;
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_quality(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->scan_info.quality * 70);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_quality(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	int32_t quality;

	if (!ni_dbus_variant_get_int32(argument, &quality))
		return FALSE;
	net->scan_info.quality = quality / 70.0;
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_maxrate(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->scan_info.max_bitrate);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_maxrate(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_uint(argument, &net->scan_info.max_bitrate);
}

static dbus_bool_t
__wpa_dbus_bss_get_capabilities(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_uint16(argument, net->scan_info.capabilities);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_capabilities(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_uint16(argument, &net->scan_info.capabilities);
}

static dbus_bool_t
__wpa_bss_process_ie(ni_wireless_network_t *net, const ni_dbus_variant_t *var)
{
	if (var->type != DBUS_TYPE_ARRAY
	 || var->array.element_type != DBUS_TYPE_BYTE
	 || var->array.len > 8192)
		return FALSE;

	__ni_wireless_process_ie(net, var->byte_array_value, var->array.len);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_wpaie(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	return __wpa_bss_process_ie(net, argument);
}

static dbus_bool_t
__wpa_dbus_bss_set_wpsie(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	return __wpa_bss_process_ie(net, argument);
}

#define __wpa_dbus_bss_get_wpaie	__wpa_dbus_bss_get_no_property
#define __wpa_dbus_bss_get_wpsie	__wpa_dbus_bss_get_no_property
#define __wpa_dbus_bss_get_rsnie	__wpa_dbus_bss_get_no_property

static dbus_bool_t
__wpa_dbus_bss_set_rsnie(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	return __wpa_bss_process_ie(net, argument);
}

static dbus_bool_t
__wpa_dbus_bss_get_proto(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
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
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_auth_protocol_from_string(value, &net->auth_proto, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_auth_alg(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
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
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_auth_algorithm_from_string(value, &net->auth_algo, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_key_mgmt(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
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
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_keymgmt_protocol_from_string(value, &net->keymgmt_proto, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_cipher(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (net->cipher == NI_WIRELESS_CIPHER_NONE)
		return __ni_dbus_property_not_present_error(error, property);
	if (!(value = ni_wpa_cipher_as_string(net->cipher, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_cipher(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_cipher_from_string(value, &net->cipher, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_pairwise(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (net->pairwise_cipher == NI_WIRELESS_CIPHER_NONE)
		return __ni_dbus_property_not_present_error(error, property);
	if (!(value = ni_wpa_cipher_as_string(net->pairwise_cipher, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_pairwise(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_cipher_from_string(value, &net->pairwise_cipher, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_group(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (net->group_cipher == NI_WIRELESS_CIPHER_NONE)
		return __ni_dbus_property_not_present_error(error, property);
	if (!(value = ni_wpa_cipher_as_string(net->group_cipher, error)))
		return FALSE;
	ni_dbus_variant_set_string(argument, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_group(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_cipher_from_string(value, &net->group_cipher, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_psk(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	/* wpa_supplicant expects us to encode the passphrase as
	 * string, and the key as a byte array. */
	if (net->wpa_psk.passphrase) {
		ni_dbus_variant_set_string(argument, net->wpa_psk.passphrase);
/*	FIXME - passphrase needs to be converted depends on the size
	} else
	if (net->wpa_psk.key.len) {
		ni_dbus_variant_set_byte_array(argument,
				net->wpa_psk.key.data,
				net->wpa_psk.key.len);
*/	} else {
		return __ni_dbus_property_not_present_error(error, property);
	}
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_psk(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	return FALSE;
}

static dbus_bool_t
__wpa_dbus_bss_get_scan_ssid(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->scan_ssid);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_scan_ssid(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	unsigned int temp;

	if (ni_dbus_variant_get_uint(argument, &temp))
		return FALSE;
	net->scan_ssid = temp;
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_fragment_size(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	ni_dbus_variant_set_int32(argument, net->fragment_size);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_fragment_size(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	return ni_dbus_variant_get_uint(argument, &net->fragment_size);
}

static dbus_bool_t
__wpa_dbus_bss_get_eap(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *eap;

	switch (net->keymgmt_proto) {
		case NI_WIRELESS_KEY_MGMT_EAP:
		case NI_WIRELESS_KEY_MGMT_802_1X:
			if (NI_WIRELESS_EAP_NONE == net->wpa_eap.method)
				eap = "TTLS PEAP TLS";
			else {
				eap = ni_wpa_eap_method_as_string(net->wpa_eap.method, error);
				if (ni_string_empty(eap))
					goto not_present;
			}
			break;
		default:
			goto not_present;
	}

	ni_dbus_variant_set_string(argument, eap);
	return TRUE;

not_present:
	return __ni_dbus_property_not_present_error(error, property);
}

static dbus_bool_t
__wpa_dbus_bss_set_eap(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	return ni_wpa_eap_method_from_string(value, &net->wpa_eap.method, error);
}

static dbus_bool_t
__wpa_dbus_bss_get_identity(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	if (net->keymgmt_proto != NI_WIRELESS_KEY_MGMT_EAP
	 && net->keymgmt_proto != NI_WIRELESS_KEY_MGMT_802_1X)
		return __ni_dbus_property_not_present_error(error, property);

	if (net->wpa_eap.identity == NULL)
		return __ni_dbus_property_not_present_error(error, property);

	ni_dbus_variant_set_string(argument, net->wpa_eap.identity);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_identity(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	ni_string_dup(&net->wpa_eap.identity, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_password(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	if (net->keymgmt_proto != NI_WIRELESS_KEY_MGMT_EAP
	 && net->keymgmt_proto != NI_WIRELESS_KEY_MGMT_802_1X)
		return __ni_dbus_property_not_present_error(error, property);

	if (ni_string_empty(net->wpa_eap.phase2.password))
		return __ni_dbus_property_not_present_error(error, property);

	ni_dbus_variant_set_string(argument, net->wpa_eap.phase2.password);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_password(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;

	ni_string_dup(&net->wpa_eap.phase2.password, value);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_get_phase1(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

	if (net->keymgmt_proto == NI_WIRELESS_KEY_MGMT_EAP) {
		switch (net->wpa_eap.method) {
		case NI_WIRELESS_EAP_NONE:
		case NI_WIRELESS_EAP_PEAP:
			ni_stringbuf_printf(&buf, "peaplabel=%u", net->wpa_eap.phase1.peaplabel);
			if (net->wpa_eap.phase1.peapver != -1U)
				ni_stringbuf_printf(&buf, "peapver=%u", net->wpa_eap.phase1.peapver);

			ni_dbus_variant_set_string(argument, buf.string);
			ni_stringbuf_destroy(&buf);
			break;

		/* Ignore for now */
		default:
			break;
		}

		return TRUE;
	}

	return __ni_dbus_property_not_present_error(error, property);
}

static dbus_bool_t
__wpa_dbus_bss_set_phase1(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	return FALSE;
}

static dbus_bool_t
__wpa_dbus_bss_get_phase2(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	const char *eap_name;

	if (net->keymgmt_proto == NI_WIRELESS_KEY_MGMT_EAP) {
		switch (net->wpa_eap.method) {
		/* For now autheap= option is not supported */
		default:
			if (NI_WIRELESS_EAP_NONE == net->wpa_eap.phase2.method)
				eap_name = "any";
			else {
				eap_name = ni_wpa_eap_method_as_string(net->wpa_eap.phase2.method, error);
				if (ni_string_empty(eap_name))
					goto not_present;
			}

			ni_stringbuf_printf(&buf, "auth=%s", eap_name);
			ni_dbus_variant_set_string(argument, buf.string);
			ni_stringbuf_destroy(&buf);
			return TRUE;
		}
	}

not_present:
	return __ni_dbus_property_not_present_error(error, property);
}

static dbus_bool_t
__wpa_dbus_bss_set_phase2(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	return FALSE;
}

static dbus_bool_t
__wpa_dbus_bss_get_ca_path(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
		ni_dbus_variant_t *argument, DBusError *error)
{
	ni_wireless_network_t *net = __wpa_get_network(object);

	if (net->keymgmt_proto != NI_WIRELESS_KEY_MGMT_EAP
	 && net->keymgmt_proto != NI_WIRELESS_KEY_MGMT_802_1X)
		return __ni_dbus_property_not_present_error(error, property);

	if (net->wpa_eap.tls.ca_cert == NULL
	 || net->wpa_eap.tls.ca_cert->name == NULL)
		return __ni_dbus_property_not_present_error(error, property);

	ni_dbus_variant_set_string(argument, net->wpa_eap.tls.ca_cert->name);
	return TRUE;
}

static dbus_bool_t
__wpa_dbus_bss_set_ca_path(ni_dbus_object_t *object, const ni_dbus_property_t *property,
		const ni_dbus_variant_t *argument, DBusError *error)
{
	return FALSE;
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

#if 0
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
#endif

	{ NULL }
};

static ni_dbus_service_t	ni_wpa_bssid_service = {
	.name		= NI_WPA_BSS_INTERFACE,
	.properties	= wpa_bss_properties,
	.compatible	= &ni_objectmodel_wpanet_class,
};

#define WPA_NET_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __wpa_dbus_net, rw)
#define WPA_NET_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wpa_dbus_net, rw)

static ni_dbus_property_t	wpa_network_properties[] = {
	WPA_NET_PROPERTY(STRING, bssid, RO),
	WPA_BSS_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING, ssid, RO),
	WPA_BSS_PROPERTY(INT32, frequency, RO),

	WPA_BSS_PROPERTY(STRING, psk, RO),
	WPA_BSS_PROPERTY(STRING, proto, RO),
	WPA_BSS_PROPERTY(STRING, key_mgmt, RO),
	WPA_BSS_PROPERTY(STRING, cipher, RO),
	WPA_BSS_PROPERTY(STRING, pairwise, RO),
	WPA_BSS_PROPERTY(STRING, group, RO),
	WPA_BSS_PROPERTY(STRING, auth_alg, RO),

	WPA_BSS_PROPERTY(INT32, scan_ssid, RO),
	WPA_BSS_PROPERTY(INT32, fragment_size, RO),

	WPA_BSS_PROPERTY(STRING, eap, RO),
	WPA_BSS_PROPERTY(STRING, phase1, RO),
	WPA_BSS_PROPERTY(STRING, phase2, RO),
	/* The following three are encoded as a byte array by NetworkManager */
	WPA_BSS_PROPERTY(STRING, identity, RO),
	WPA_BSS_PROPERTY(STRING, password, RO),
	WPA_BSS_PROPERTY(STRING, ca_path, RO),

//	WPA_BSS_PROPERTY(STRING, anonymous_identity, RO),
//	WPA_BSS_PROPERTY(STRING, wep_key0, RO),
//	WPA_BSS_PROPERTY(STRING, wep_key1, RO),
//	WPA_BSS_PROPERTY(STRING, wep_key2, RO),
//	WPA_BSS_PROPERTY(STRING, wep_key3, RO),
//	WPA_BSS_PROPERTY(INT32, wep_tx_keyid, RO),

	{ NULL }
};

static ni_dbus_service_t	ni_wpa_network_service = {
	.name		= NI_WPA_NETWORK_INTERFACE,
	.properties	= wpa_network_properties,
	.compatible	= &ni_objectmodel_wpanet_class,
};

/*
 * Callback invoked when the properties() call on a BSS object returns.
 */
static void
ni_wpa_bss_properties_result(ni_dbus_object_t *proxy, ni_dbus_message_t *msg)
{
	ni_wireless_network_t *net = proxy->handle;
	ni_dbus_variant_t dict = NI_DBUS_VARIANT_INIT;
	ni_wireless_ssid_t old_essid;
	DBusMessageIter iter;

	dbus_message_iter_init(msg, &iter);

	ni_dbus_variant_init_dict(&dict);
	if (!ni_dbus_message_iter_get_variant_data(&iter, &dict))
		goto failed;

	old_essid = net->essid;
	ni_wpa_network_properties_destroy(net);

	if (!ni_dbus_object_set_properties_from_dict(proxy, &ni_wpa_bssid_service, &dict, NULL))
		goto failed;

	ni_debug_wireless("Updated BSS %s, freq=%.3f GHz, quality=%.2f, noise=%u, level=%.2f dBm, maxrate=%u MB/s, essid='%s'",
			ni_link_address_print(&net->access_point),
			net->scan_info.frequency,
			net->scan_info.quality,
			net->scan_info.noise,
			net->scan_info.level,
			net->scan_info.max_bitrate / 1000000,
			ni_wireless_print_ssid(&net->essid));

	if (net->notified && memcmp(&old_essid, &net->essid, sizeof(old_essid)) != 0) {
		ni_debug_wireless("%s: essid changed", ni_link_address_print(&net->access_point));
		net->notified = FALSE;
	}
	ni_timer_get_time(&net->scan_info.timestamp);

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
ni_wpa_network_request_properties(ni_dbus_object_t *net_object)
{
	ni_dbus_object_call_async(net_object,
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

		if (ni_parse_uint_mapped(name, names, &value) < 0)
			ni_warn("unable to translate %s %s", what, name);
		else if (value < 8 * sizeof(*bits))
			*bits |= (1 << value);
	}

	return 0;
}

static ni_intmap_t __ni_wpa_eap_method_names[] = {
	{ "MD5",	NI_WIRELESS_EAP_MD5	},
	{ "TLS",	NI_WIRELESS_EAP_TLS	},
	{ "PAP",	NI_WIRELESS_EAP_PAP},
	{ "CHAP",	NI_WIRELESS_EAP_CHAP},
	{ "MSCHAP",	NI_WIRELESS_EAP_MSCHAP},
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
	{ "FAST",	NI_WIRELESS_EAP_FAST	},
	{ "AKA",	NI_WIRELESS_EAP_AKA	},
	{ "AKA'",	NI_WIRELESS_EAP_AKA_PRIME	},
	{ "SIM",	NI_WIRELESS_EAP_SIM	},

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

static ni_intmap_t __ni_wpa_driver_names[] = {
	{ "wext",		NI_WIRELESS_WPA_DRIVER_WEXT	},
	{ "nl80211",	NI_WIRELESS_WPA_DRIVER_NL80211	},
	{ "hostap",		NI_WIRELESS_WPA_DRIVER_HOSTAP	},
	{ "wired",		NI_WIRELESS_WPA_DRIVER_WIRED	},
	{ "ralink",		NI_WIRELESS_WPA_DRIVER_RALINK	},
	{ NULL }
};

ni_bool_t
ni_wpa_driver_from_string(const char *string, unsigned int *value)
{
	if (ni_parse_uint_mapped(string, __ni_wpa_driver_names, value) < 0)
		return FALSE;
	return TRUE;
}

const char *
ni_wpa_driver_as_string(ni_wireless_wpa_driver_t drv)
{
	return ni_format_uint_mapped(drv, __ni_wpa_driver_names);
}

static ni_bool_t
ni_wpa_driver_check_name(const char *name)
{
	ni_wireless_wpa_driver_t drv;

	for (drv = NI_WIRELESS_WPA_DRIVER_WEXT; drv < NI_WIRELESS_WPA_DRIVER_COUNT; drv++)
		if (ni_string_eq_nocase(name, ni_wpa_driver_as_string(drv)))
			return TRUE;

	return FALSE;
}

ni_bool_t
ni_wpa_driver_string_validate(const char *string)
{
	unsigned int i;
	ni_string_array_t drv;

	if (!string)
		return FALSE;

	ni_string_array_init(&drv);
	ni_string_split(&drv, string, ",", NI_WIRELESS_WPA_DRIVER_COUNT);

	if (0 == drv.count) {
		ni_string_array_destroy(&drv);
		return FALSE;
	}

	for (i = 0; i < drv.count; i++) {
		if (!ni_wpa_driver_check_name(drv.data[i])) {
			ni_string_array_destroy(&drv);
			return FALSE;
		}
	}

	ni_string_array_destroy(&drv);
	return TRUE;
}

static const char *
ni_wpa_auth_protocol_as_string(ni_wireless_auth_mode_t auth_mode, DBusError *error)
{
	const char *res;

	if (auth_mode == NI_WIRELESS_AUTH_MODE_NONE) {
		dbus_set_error(error, NI_DBUS_ERROR_PROPERTY_NOT_PRESENT, "auth-mode property not set");
		return FALSE;
	}
	if (!(res = ni_format_uint_mapped(auth_mode, __ni_wpa_protocol_names))) {
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

	if (ni_parse_uint_mapped(string, __ni_wpa_protocol_names, &value) < 0) {
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

	if (auth_algo == NI_WIRELESS_AUTH_ALGO_NONE) {
		dbus_set_error(error, NI_DBUS_ERROR_PROPERTY_NOT_PRESENT, "auth-algo property not set");
		return FALSE;
	}
	if (!(res = ni_format_uint_mapped(auth_algo, __ni_wpa_auth_names))) {
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

	if (ni_parse_uint_mapped(string, __ni_wpa_auth_names, &value) < 0) {
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

	if (!(res = ni_format_uint_mapped(proto, __ni_wpa_keymgmt_names))) {
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

	if (ni_parse_uint_mapped(string, __ni_wpa_keymgmt_names, &value) < 0) {
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

	if (!(res = ni_format_uint_mapped(proto, __ni_wpa_cipher_names))) {
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

	if (ni_parse_uint_mapped(string, __ni_wpa_cipher_names, &value) < 0) {
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

	if (!(res = ni_format_uint_mapped(proto, __ni_wpa_eap_method_names))) {
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

	if (ni_parse_uint_mapped(string, __ni_wpa_eap_method_names, &value) < 0) {
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

		if (ni_parse_uint_mapped(name, names, &value) < 0)
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

static ni_dbus_service_t	ni_wpa_device_service = {
	.name		= NI_WPA_IF_INTERFACE,
	.properties	= wpa_ifcap_properties,
	.compatible	= &ni_objectmodel_wpadev_class,
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
ni_wpa_interface_get_capabilities(ni_wpa_client_t *wpa, ni_wpa_interface_t *wpa_dev)
{
	ni_dbus_message_t *call = NULL, *reply = NULL;
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_variant_t dict = NI_DBUS_VARIANT_INIT;
	DBusMessageIter iter;
	int rv = -1;

	call = ni_dbus_object_call_new(wpa_dev->proxy, "capabilities", 0);
	if (call == NULL) {
		ni_error("%s: could not build message", __func__);
		rv = -NI_ERROR_INVALID_ARGS;
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
	rv = ni_dbus_object_set_properties_from_dict(wpa_dev->proxy, &ni_wpa_device_service, &dict, NULL);

#if 0
	if (rv) {
		ni_wireless_interface_capabilities_t *caps = &wpa_dev->capabilities;

		ni_debug_wireless("%s interface capabilities", wpa_dev->ifname);
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
