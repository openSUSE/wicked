/*
 * Generic dbus client functions for address configuration
 * services implemented as separate DBus services (like dhcp).
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/route.h>
#include <wicked/system.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include <wicked/resolver.h>
#include "netinfo_priv.h"	/* for __ni_system_interface_update_lease */
#include "dbus-common.h"
#include "model.h"
#include "debug.h"
#include "util_priv.h"
#include "appconfig.h"
#include "addrconf.h"
#include "auto6.h"


const ni_dbus_class_t		ni_objectmodel_addrconf_device_class = {
	.name		= "addrconf-device",
};

static ni_dbus_class_t		ni_objectmodel_auto4_request_class =  {
	.name		= "auto4-request",
};

typedef struct ni_dbus_addrconf_forwarder {

	struct {
	    const char *	interface;
	} caller;
	struct {
	    ni_dbus_client_t *	client;
	    const char *	bus_name;
	    const char *	interface;
	    const char *	object_path;
	} supplicant;

	struct {
	    ni_dbus_class_t *	class;
	    unsigned int	mask;
	} request;

	unsigned int		addrfamily;
	ni_addrconf_mode_t	addrconf;

	ni_dbus_class_t		class;
} ni_dbus_addrconf_forwarder_t;

static dbus_bool_t	ni_objectmodel_addrconf_forwarder_call(ni_dbus_addrconf_forwarder_t *forwarder,
					ni_netdev_t *dev, const char *method_name,
					const ni_uuid_t *uuid, const ni_dbus_variant_t *dict,
					DBusError *error);
static dbus_bool_t	ni_objectmodel_addrconf_forward_drop(ni_dbus_addrconf_forwarder_t *forwarder,
					ni_netdev_t *dev, const ni_dbus_variant_t *dict,
					ni_dbus_message_t *reply, DBusError *error);
static int		ni_objectmodel_addrconf_complete_drop(ni_netdev_t *dev, ni_addrconf_lease_t *lease);

static dbus_bool_t	ni_objectmodel_addrconf_fallback_request(ni_netdev_t *dev, unsigned int family);
static dbus_bool_t	ni_objectmodel_addrconf_fallback_release(ni_netdev_t *dev, unsigned int family);
static dbus_bool_t	ni_objectmodel_addrconf_fallback_reinstall(ni_netdev_t *dev, ni_addrconf_lease_t *lease);
static dbus_bool_t	ni_objectmodel_set_auto6_request_dict(ni_auto6_request_t *, const ni_dbus_variant_t *, DBusError *);

#define NI_OBJECTMODEL_ADDRCONF_IPV4STATIC_INTERFACE	NI_OBJECTMODEL_ADDRCONF_INTERFACE ".ipv4.static"
#define NI_OBJECTMODEL_ADDRCONF_IPV6STATIC_INTERFACE	NI_OBJECTMODEL_ADDRCONF_INTERFACE ".ipv6.static"
#define NI_OBJECTMODEL_ADDRCONF_IPV4DHCP_INTERFACE	NI_OBJECTMODEL_ADDRCONF_INTERFACE ".ipv4.dhcp"
#define NI_OBJECTMODEL_ADDRCONF_IPV6DHCP_INTERFACE	NI_OBJECTMODEL_ADDRCONF_INTERFACE ".ipv6.dhcp"
#define NI_OBJECTMODEL_ADDRCONF_IPV4AUTO_INTERFACE	NI_OBJECTMODEL_ADDRCONF_INTERFACE ".ipv4.auto"
#define NI_OBJECTMODEL_ADDRCONF_IPV6AUTO_INTERFACE	NI_OBJECTMODEL_ADDRCONF_INTERFACE ".ipv6.auto"

void
ni_objectmodel_register_addrconf_classes(void)
{
	ni_objectmodel_register_class(&ni_objectmodel_addrconf_device_class);
}

/*
 * Extract interface index from object path.
 * Path names must be NI_OBJECTMODEL_OBJECT_PATH "/" <something> "/Interface/" <index>
 */
static ni_netdev_t *
ni_objectmodel_addrconf_path_to_device(const char *path)
{
	unsigned int ifindex;
	ni_netconfig_t *nc;
	char cc;

	if (strncmp(path, NI_OBJECTMODEL_OBJECT_PATH, strlen(NI_OBJECTMODEL_OBJECT_PATH)))
		return NULL;
	path += strlen(NI_OBJECTMODEL_OBJECT_PATH);

	if (*path++ != '/')
		return NULL;
	while ((cc = *path++) != '/') {
		if (cc == '\0')
			return NULL;
	}

	if (strncmp(path, "Interface/", 10))
		return NULL;
	path += 10;

	if (ni_parse_uint(path, &ifindex, 10) < 0)
		return NULL;

	if (!(nc = ni_global_state_handle(0))) {
		ni_error("%s: unable to get global handle", __func__);
		return NULL;
	}

	return ni_netdev_by_index(nc, ifindex);
}

/*
 * Utility to apply device name context to lease routes
 */
static ni_bool_t
__ni_objectmodel_routes_bind_device_name(ni_route_table_t *routes, const char *ifname)
{
	ni_route_table_t *tab;
	ni_route_nexthop_t *nh;
	ni_route_t *rp;
	unsigned int i, count = 0;

	for (tab = routes; tab; tab = tab->next) {
		for (i = 0; i < tab->routes.count; ++i) {
			if (!(rp = tab->routes.data[i]))
				continue;

			for (nh = &rp->nh; nh; nh = nh->next) {
				if (ifname && !nh->device.name) {
					ni_string_dup(&nh->device.name, ifname);
					count++;
				} else
				if (ni_string_eq(nh->device.name, ifname)) {
					count++;
				}
			}
		}
	}
	return count > 0;
}

void
ni_objectmodel_addrconf_fallback_action(ni_netdev_t *dev, ni_event_t ifevent,
					unsigned int family, ni_addrconf_lease_t *lease)
{
	if (!dev || family == AF_UNSPEC)
		return;

	switch (ifevent) {
	case NI_EVENT_ADDRESS_ACQUIRED:
		ni_objectmodel_addrconf_fallback_release(dev, family);
		break;
	case NI_EVENT_ADDRESS_DEFERRED:
		ni_objectmodel_addrconf_fallback_request(dev, family);
		break;
	case NI_EVENT_ADDRESS_RELEASED:
		ni_objectmodel_addrconf_fallback_reinstall(dev, lease);
		break;
	default:
		break;
	}
}

dbus_bool_t
ni_objectmodel_addrconf_send_event(ni_netdev_t *dev, ni_event_t ifevent, ni_uuid_t *uuid)
{
	ni_dbus_object_t *object;

	object = ni_objectmodel_get_netif_object(__ni_objectmodel_server, dev);
	if (object) {
		return ni_objectmodel_send_netif_event(__ni_objectmodel_server, object,
				ifevent, ni_uuid_is_null(uuid) ? NULL : uuid);
	}
	return FALSE;
}

/*
 * Callback from addrconf supplicant whenever it acquired, released or lost a lease.
 *
 * FIXME SECURITY:
 * Is it good enough to check for the sender interface to avoid that someone is sending
 * us spoofed lease messages?!
 */
void
ni_objectmodel_addrconf_signal_handler(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_dbus_addrconf_forwarder_t *forwarder = user_data;
	const char *signal_name = dbus_message_get_member(msg);
	ni_netdev_t *ifp;
	ni_addrconf_lease_t *lease = NULL;
	ni_dbus_variant_t argv[16];
	ni_uuid_t uuid = NI_UUID_INIT;
	ni_event_t ifevent;
	int rv, argc, optind = 0;

	memset(argv, 0, sizeof(argv));
	argc = ni_dbus_message_get_args_variants(msg, argv, 16);
	if (argc < 0) {
		ni_error("%s: cannot parse arguments for signal %s", __func__, signal_name);
		goto done;
	}

	ifp = ni_objectmodel_addrconf_path_to_device(dbus_message_get_path(msg));
	if (ifp == NULL) {
		ni_debug_dbus("%s: received signal %s for unknown interface %s", __func__,
				signal_name, dbus_message_get_path(msg));
		goto done;
	}

	lease = ni_addrconf_lease_new(forwarder->addrconf, forwarder->addrfamily);

	if (argc != 1 && argc != 2) {
		ni_warn("%s: ignoring %s event from %s: bad number of arguments (%u)",
				__func__, signal_name, dbus_message_get_path(msg), argc);
		goto done;
	}

	if (argc == 2 && !ni_dbus_variant_get_uuid(&argv[optind++], &uuid)) {
		ni_debug_dbus("%s: unable to parse uuid argument", __func__);
		goto done;
	}

	if (!ni_objectmodel_set_addrconf_lease(lease, &argv[optind++])) {
		ni_error("%s: unable to parse lease argument received from %s", __func__,
				dbus_message_get_sender(msg));
		goto done;
	}

	ni_debug_dbus("received signal %s for interface %s (ifindex %d),"
			" lease %s:%s/%s, uuid=%s, update=0x%x, flags=0x%x",
			signal_name, ifp->name, ifp->link.ifindex,
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_type_to_name(lease->type),
			ni_addrconf_state_to_name(lease->state),
			ni_uuid_print(&uuid), lease->update, lease->flags);

	if (!strcmp(signal_name, NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL)) {
		if (lease->state != NI_ADDRCONF_STATE_GRANTED) {
			ni_error("%s: unexpected lease state in signal %s", __func__, signal_name);
			goto done;
		}

		ifevent = NI_EVENT_ADDRESS_ACQUIRED;

		__ni_objectmodel_routes_bind_device_name(lease->routes, ifp->name);
		if (!__ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_DEFAULT_ROUTE)) {
			ni_route_table_t *tab;
			ni_route_t *rp;
			unsigned int i;

			for (tab = lease->routes; tab; tab = tab->next) {
				for (i = 0; i < tab->routes.count; ++i) {
					if (!(rp = tab->routes.data[i]))
						continue;

					if (ni_sockaddr_is_specified(&rp->destination))
						continue;

					if (ni_route_array_delete_at(&tab->routes, i))
						i--;
				}
			}
		}
	} else if (!strcmp(signal_name, NI_OBJECTMODEL_LEASE_DEFERRED_SIGNAL)) {
		ni_addrconf_lease_t *_lease;

		/*
		 * we don't have a lease here -- it is currently still requested.
		 * so we do not update the system, just trigger event to inform
		 * client that it needs more time than defer timeout.
		 */
		_lease = ni_netdev_get_lease(ifp, lease->family, lease->type);
		if (!_lease || !ni_uuid_equal(&_lease->uuid, &uuid))
			goto done;

		lease->state = _lease->state = NI_ADDRCONF_STATE_REQUESTING;
		ifevent = NI_EVENT_ADDRESS_DEFERRED;

		if (ni_addrconf_flag_bit_is_set(_lease->flags, NI_ADDRCONF_FLAGS_PRIMARY))
			ni_objectmodel_addrconf_fallback_action(ifp, ifevent, _lease->family, NULL);

		ni_objectmodel_addrconf_send_event(ifp, ifevent, &uuid);
		goto done;
	} else if (!strcmp(signal_name, NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL)) {
		/*
		 * We should have an lease updater already running and expect
		 * the supplicant sends us a signal once it finished it's part.
		 */
		lease->state = NI_ADDRCONF_STATE_RELEASING;
		ifevent = NI_EVENT_ADDRESS_RELEASED;

		/* inform the running updater, that supplicant finished */
		if (ni_objectmodel_addrconf_complete_drop(ifp, lease))
			goto done;

	} else if (!strcmp(signal_name, NI_OBJECTMODEL_LEASE_LOST_SIGNAL)) {
		lease->state = NI_ADDRCONF_STATE_FAILED;
		ifevent = NI_EVENT_ADDRESS_LOST;
	} else {
		/* Ignore unknown signal */
		goto done;
	}

	/*
	 * The following call updates the system with the information given in
	 * the lease. This includes setting all addresses, as well as updating
	 * resolver and hostname, if provided.
	 * When a lease is dropped, we either fall back to the config information
	 * from the next best lease, or if there is none, we restore the original
	 * system settings.
	 *
	 * On success, the specified event is emitted.
	 *
	 * Note, lease may be NULL after this, as the interface object
	 * takes ownership of it.
	 *
	 * Return code 0 is success, < 0 on error.
	 */
	if ((rv = __ni_system_interface_update_lease(ifp, &lease, ifevent)) < 0) {
		ni_warn("%s: failed to process %s:%s lease %s%s on signal %s%s%s",
				ifp->name,
				ni_addrfamily_type_to_name(forwarder->addrfamily),
				ni_addrconf_type_to_name(forwarder->addrconf),
				lease ? "in state " : "(dropped)",
				lease ? ni_addrconf_state_to_name(lease->state) : "",
				signal_name,
				ni_uuid_is_null(&uuid) ? "" : " uuid ",
				ni_uuid_is_null(&uuid) ? "" : ni_uuid_print(&uuid));
		ni_objectmodel_addrconf_send_event(ifp, NI_EVENT_ADDRESS_LOST, &uuid);
	}

done:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
	ni_addrconf_lease_drop(&lease);
}

/*
 * Utility to verbosely get device lease in requests
 */
static inline ni_addrconf_lease_t *
ni_objectmodel_addrconf_get_lease(ni_netdev_t *dev, unsigned int family, unsigned int type)
{
	ni_addrconf_lease_t *lease;

	lease = ni_netdev_get_lease(dev, family, type);
	if (lease) {
		/* found previous lease to replace or drop*/
		ni_debug_objectmodel("%s: found previous %s:%s lease in state %s uuid %s%s",
				dev->name,
				ni_addrfamily_type_to_name(lease->family),
				ni_addrconf_type_to_name(lease->type),
				ni_addrconf_state_to_name(lease->state),
				ni_uuid_is_null(&lease->uuid) ? "null" : ni_uuid_print(&lease->uuid),
				lease->updater ? " -- canceling active updater" : "");
		if (lease->old && lease->old->updater) {
			/* should not happen -- bug */
			ni_error("%s: previous lease %s:%s in state %s replaces lease with active updater!",
				dev->name,
				ni_addrfamily_type_to_name(lease->old->family),
				ni_addrconf_type_to_name(lease->old->type),
				ni_addrconf_state_to_name(lease->old->state));
			ni_addrconf_updater_free(&lease->old->updater);
		}
		ni_addrconf_updater_free(&lease->updater);
	} else {
		ni_debug_objectmodel("%s: no previous %s:%s lease found", dev->name,
				ni_addrfamily_type_to_name(family),
				ni_addrconf_type_to_name(type));
	}
	return lease;
}

/*
 * Generic functions for static address configuration
 */
static dbus_bool_t
ni_objectmodel_addrconf_static_request(ni_dbus_object_t *object, unsigned int addrfamily,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_addrconf_lease_t *lease = NULL;
	const ni_dbus_variant_t *dict;
	const char *string_value;
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"requestLease: expected one dict argument");
		return FALSE;
	}
	dict = &argv[0];

	ni_objectmodel_addrconf_get_lease(dev, addrfamily, NI_ADDRCONF_STATIC);

	lease = ni_addrconf_lease_new(NI_ADDRCONF_STATIC, addrfamily);
	lease->state = NI_ADDRCONF_STATE_GRANTED;
	ni_uuid_generate(&lease->uuid);

	if (!__ni_objectmodel_set_address_dict(&lease->addrs, dict, error)
	 || !__ni_objectmodel_set_route_dict(&lease->routes, dict, error)
	 || !__ni_objectmodel_set_rule_dict(&lease->rules, addrfamily, dict, error)
	 || !__ni_objectmodel_set_resolver_dict(&lease->resolver, dict, error)) {
		ni_addrconf_lease_drop(&lease);
		return FALSE;
	}

	__ni_objectmodel_routes_bind_device_name(lease->routes, dev->name);

	if (__ni_objectmodel_get_domain_string(dict, "hostname", &string_value))
		ni_string_dup(&lease->hostname, string_value);

	/* mark all addresses tentative, causing to verify them */
	ni_addrconf_lease_addrs_set_tentative(lease, TRUE);

	rv = __ni_system_interface_update_lease(dev, &lease, NI_EVENT_ADDRESS_ACQUIRED);
	ni_addrconf_lease_drop(&lease);

	if (rv < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Error configuring static %s addresses: %s",
				ni_addrfamily_type_to_name(addrfamily),
				ni_strerror(rv));
		return FALSE;
	} else
	if (rv > 0 && (lease = ni_netdev_get_lease(dev, addrfamily, NI_ADDRCONF_STATIC))) {
		ni_objectmodel_callback_data_t data = { .lease = lease };

		/* Tell the client to wait for an addressAcquired event with the given uuid
		 * when the lease apply finished */
		return __ni_objectmodel_return_callback_info(reply, NI_EVENT_ADDRESS_ACQUIRED,
								&lease->uuid, &data, error);
	}

	/* Don't return anything. */
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_addrconf_static_drop(ni_dbus_object_t *object, unsigned int addrfamily,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_addrconf_lease_t *lease = NULL;
	ni_uuid_t uuid = NI_UUID_INIT;
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	lease = ni_objectmodel_addrconf_get_lease(dev, addrfamily, NI_ADDRCONF_STATIC);
	if (!lease)
		return TRUE; /* nothing to do */

	uuid = lease->uuid;
	if ((lease = ni_addrconf_lease_new(NI_ADDRCONF_STATIC, addrfamily))) {
		lease->state = NI_ADDRCONF_STATE_RELEASING;
		lease->uuid  = uuid;
	}
	rv = __ni_system_interface_update_lease(dev, &lease, NI_EVENT_ADDRESS_RELEASED);
	ni_addrconf_lease_drop(&lease);

	/* Check again whether we still have a lease and let the client wait for it's release. */
	if (rv > 0 && (lease = ni_netdev_get_lease(dev, addrfamily, NI_ADDRCONF_STATIC))) {
		ni_objectmodel_callback_data_t data = { .lease = lease };

		/* Tell the client to wait for an addressReleased event with the given uuid */
		return __ni_objectmodel_return_callback_info(reply, NI_EVENT_ADDRESS_RELEASED,
								&lease->uuid, &data, error);
	} else
	if (rv < 0) {
		/* unable to start removal / some allocation error */
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"%s: failed to drop %s:%s lease", dev->name,
				ni_addrfamily_type_to_name(addrfamily),
				ni_addrconf_type_to_name(NI_ADDRCONF_STATIC));
		return FALSE;
	}
	ni_debug_objectmodel("%s: lease %s:%s dropped immediately", dev->name,
				ni_addrfamily_type_to_name(addrfamily),
				ni_addrconf_type_to_name(NI_ADDRCONF_STATIC));
	return TRUE; /* done immediately */
}

/*
 * Configure static IPv4 addresses
 */
static dbus_bool_t
ni_objectmodel_addrconf_ipv4_static_request(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_addrconf_static_request(object, AF_INET, argc, argv, reply, error);
}

static dbus_bool_t
ni_objectmodel_addrconf_ipv4_static_drop(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_addrconf_static_drop(object, AF_INET, reply, error);
}

/*
 * Configure static IPv6 addresses
 */
static dbus_bool_t
ni_objectmodel_addrconf_ipv6_static_request(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_addrconf_static_request(object, AF_INET6, argc, argv, reply, error);
}

static dbus_bool_t
ni_objectmodel_addrconf_ipv6_static_drop(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_addrconf_static_drop(object, AF_INET6, reply, error);
}

/*
 * Forward an addrconf request to a supplicant service, such as DHCP or zeroconf
 *
 * What we do here is:
 *
 *  - create an addrconf request handle, and register it with the interface
 *  - assign a uuid
 *  - assign an event ID
 *  - forward the request, along with the uuid
 *  - when we receive a lease event with the matching uuid,
 *    broadcast a corresponding interface event (with the assigned even ID)
 *
 * Note, we do not record the contents of the addrconf request, which may be totally
 * free-form. We just pass it on to the respective addrconf service.
 */
static dbus_bool_t
ni_objectmodel_addrconf_forward_request(ni_dbus_addrconf_forwarder_t *forwarder,
			ni_netdev_t *dev, const ni_dbus_variant_t *dict,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_addrconf_lease_t *lease;
	dbus_bool_t rv, enabled;
	uint32_t flags = 0;

	/* If the caller tells us to disable this addrconf family, we may need
	 * to do a release() call. */
	if (!ni_dbus_dict_get_bool(dict, "enabled", &enabled) || !enabled)
		return ni_objectmodel_addrconf_forward_drop(forwarder, dev, NULL, reply, error);

	if (ni_dbus_dict_get_uint32(dict, "flags", &flags))
		flags &= forwarder->request.mask;
	else
		flags = 0;

	/* Check whether we already have a lease on this interface. */
	lease = ni_objectmodel_addrconf_get_lease(dev, forwarder->addrfamily, forwarder->addrconf);
	if (!lease) {
		/* We didn't have a lease for this address family and addrconf protocol yet.
		 * Create one and track it. */
		if (!(lease = ni_addrconf_lease_new(forwarder->addrconf, forwarder->addrfamily)))
			return FALSE;

		lease->state = NI_ADDRCONF_STATE_REQUESTING;
		ni_uuid_generate(&lease->uuid);
		ni_netdev_set_lease(dev, lease);
	}
	lease->flags = flags;

	rv = ni_objectmodel_addrconf_forwarder_call(forwarder, dev, "acquire", &lease->uuid, dict, error);
	if (rv) {
		ni_objectmodel_callback_data_t data = { .lease = lease };

		lease->state = NI_ADDRCONF_STATE_REQUESTING;

		/* Tell the client to wait for an addressAcquired event with the given uuid */
		return __ni_objectmodel_return_callback_info(reply, NI_EVENT_ADDRESS_ACQUIRED,
								&lease->uuid, &data, error);
	} else if (lease->state == NI_ADDRCONF_STATE_REQUESTING) {
		ni_netdev_unset_lease(dev, lease->family, lease->type);
	}
	return rv;
}

/*
 * Forward an addrconf drop call to a supplicant service, such as DHCP or zeroconf
 */
typedef struct ni_addrconf_drop_args {
	struct {
		ni_tristate_t	release;
	} dhcp;
} ni_addrconf_drop_args_t;

typedef struct ni_addrconf_drop_forward {
	ni_addrconf_action_t		action;
	ni_dbus_addrconf_forwarder_t *	fwdr;
	ni_addrconf_drop_args_t		args;
} ni_addrconf_drop_forward_t;

typedef struct ni_addrconf_drop_collect {
	ni_addrconf_action_t		action;
	unsigned int			deadline;
	ni_bool_t			complete;
} ni_addrconf_drop_collect_t;

static int				ni_addrconf_drop_forward_exec(ni_netdev_t *, ni_addrconf_lease_t *);
static int				ni_addrconf_drop_collect_exec(ni_netdev_t *, ni_addrconf_lease_t *);
static ni_addrconf_action_t *		ni_addrconf_drop_collect_complete(ni_addrconf_lease_t *);

static inline void
ni_addrconf_drop_args_init(ni_addrconf_drop_args_t *args)
{
	args->dhcp.release = NI_TRISTATE_DEFAULT;
}

static inline ni_bool_t
ni_addrconf_drop_args_from_variant(const ni_dbus_addrconf_forwarder_t *fwdr,
		ni_addrconf_drop_args_t *args, const ni_dbus_variant_t *var)
{
	dbus_bool_t bv;

	switch (fwdr->addrconf) {
	case NI_ADDRCONF_DHCP:
		if (var && ni_dbus_dict_get_bool(var, "release", &bv))
			ni_tristate_set(&args->dhcp.release, bv);
		return TRUE;
	default:
		return FALSE;
	}
}

static inline ni_bool_t
ni_addrconf_drop_args_into_variant(const ni_dbus_addrconf_forwarder_t *fwdr,
		ni_dbus_variant_t *var, const ni_addrconf_drop_args_t *args)
{
	switch (fwdr->addrconf) {
	case NI_ADDRCONF_DHCP:
		ni_dbus_variant_init_dict(var);
		if (ni_tristate_is_set(args->dhcp.release))
			ni_dbus_dict_add_bool(var, "release",
					ni_tristate_is_enabled(args->dhcp.release));
		return TRUE;
	default:
		return FALSE;
	}
}

static ni_addrconf_drop_forward_t *
ni_addrconf_drop_forward_cast(ni_addrconf_action_t *action)
{
	if (!action || action->exec != ni_addrconf_drop_forward_exec)
		return NULL;
	return (ni_addrconf_drop_forward_t *)action;
}

static int
ni_addrconf_drop_forward_exec(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	const ni_addrconf_drop_forward_t *action;
	ni_dbus_variant_t var = NI_DBUS_VARIANT_INIT;
	ni_dbus_variant_t *args = NULL;
	DBusError error = DBUS_ERROR_INIT;

	if (!dev || !lease || !lease->updater)
		return -1;

	if (!(action = ni_addrconf_drop_forward_cast(lease->updater->action)))
		return -1;

	ni_debug_objectmodel("%s: forwarding drop for lease=%s:%s in state=%s uuid=%s",
			dev->name,
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_type_to_name(lease->type),
			ni_addrconf_state_to_name(lease->state),
			ni_uuid_is_null(&lease->uuid) ? "null" : ni_uuid_print(&lease->uuid));

	if (ni_addrconf_drop_args_into_variant(action->fwdr, &var, &action->args))
		args = &var;

	if (!ni_objectmodel_addrconf_forwarder_call(action->fwdr, dev, "drop",
						&lease->uuid, args, &error)) {
		ni_dbus_variant_destroy(&var);
		switch (ni_dbus_get_error(&error, NULL)) {
		case -NI_ERROR_ADDRCONF_NO_LEASE:
			ni_debug_objectmodel("%s: no %s:%s lease to release by supplicant",
					dev->name,
					ni_addrfamily_type_to_name(action->fwdr->addrfamily),
					ni_addrconf_type_to_name(action->fwdr->addrconf));
			break;
		case -NI_ERROR_METHOD_NOT_SUPPORTED:
			ni_debug_objectmodel("%s: lease %s:%s is not supported on device",
					dev->name,
					ni_addrfamily_type_to_name(action->fwdr->addrfamily),
					ni_addrconf_type_to_name(action->fwdr->addrconf));
			break;
		default:
			ni_debug_objectmodel("%s: service returned %s (%s)",
				action->fwdr->supplicant.interface,
				error.name, error.message);
			break;
		}
		dbus_error_free(&error);

		/* suplicant finished release (returned error) */
		ni_addrconf_drop_collect_complete(lease);
	}
	ni_dbus_variant_destroy(&var);

	/* supplicant will signal us when it finished it's part */
	return 0;
}

static inline void
ni_addrconf_drop_forward_free(ni_addrconf_drop_forward_t *act)
{
	/* nothing to free inside */
	free(act);
}

static ni_addrconf_drop_forward_t *
ni_addrconf_drop_forward_new(ni_dbus_addrconf_forwarder_t *forwarder)
{
	static const char *info = "forwarding drop lease";
	ni_addrconf_drop_forward_t *act;

	if (!forwarder || !(act = calloc(1, sizeof(*act))))
		return NULL;

	act->fwdr = forwarder;
	act->action.info = info;
	act->action.exec = ni_addrconf_drop_forward_exec;
	ni_addrconf_drop_args_init(&act->args);
	return act;
}

static ni_addrconf_drop_collect_t *
ni_addrconf_drop_collect_cast(ni_addrconf_action_t *action)
{
	if (!action || action->exec != ni_addrconf_drop_collect_exec)
		return NULL;
	return (ni_addrconf_drop_collect_t *)action;
}

static inline ni_bool_t
ni_addrconf_drop_collect_test(ni_addrconf_updater_t *updater, ni_addrconf_drop_collect_t *collect)
{
	if (collect->complete)
		return TRUE;

	if (collect->deadline && !ni_lifetime_left(collect->deadline, &updater->astart, NULL))
		return TRUE;

	return FALSE;
}

static int
ni_addrconf_drop_collect_exec(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_addrconf_drop_collect_t *collect;

	if (!dev || !lease || !lease->updater)
		return -1;

	if (!(collect = ni_addrconf_drop_collect_cast(lease->updater->action)))
		return -1;

	if (ni_addrconf_drop_collect_test(lease->updater, collect)) {
		lease->state = NI_ADDRCONF_STATE_RELEASED;
		return 0;
	}
	return 1;
}

static inline void
ni_addrconf_drop_collect_free(ni_addrconf_drop_collect_t *act)
{
	/* nothing to free inside */
	free(act);
}

static ni_addrconf_drop_collect_t *
ni_addrconf_drop_collect_new(void)
{
	static const char *info = "collecting drop event";
	ni_addrconf_drop_collect_t *act;

	if (!(act = calloc(1, sizeof(*act))))
		return NULL;

	act->deadline = 10; /* worst case 10 sec no-reply deadline
			       (buggy/stopped/crashed supplicant) */
	act->action.info = info;
	act->action.exec = ni_addrconf_drop_collect_exec;
	return act;
}

static ni_bool_t
ni_addrconf_drop_actions_arm(ni_dbus_addrconf_forwarder_t *forwarder,
				ni_addrconf_updater_t *updater,
				const ni_dbus_variant_t *dict)
{
	ni_addrconf_drop_forward_t *forward = NULL;
	ni_addrconf_drop_collect_t *collect = NULL;
	ni_addrconf_action_t *pos;

	if (!updater)
		return FALSE;

	if (!(forward = ni_addrconf_drop_forward_new(forwarder)))
		goto failure;

	ni_addrconf_drop_args_from_variant(forwarder, &forward->args, dict);

	if (!(collect = ni_addrconf_drop_collect_new()))
		goto failure;

	/*
	 * Insert the forward action behind address removal
	 * and append the collect action as the last action.
	 */
	pos = ni_addrconf_action_list_find_exec(updater->action,
				ni_addrconf_action_addrs_remove);

	if (pos) {
		/* insert or append cannot fail -- checked conditions above */
		ni_addrconf_action_list_insert(&pos->next, &forward->action);
		ni_addrconf_action_list_append(&pos->next, &collect->action);
		return TRUE;
	}

failure:
	ni_addrconf_drop_collect_free(collect);
	ni_addrconf_drop_forward_free(forward);
	return FALSE;
}

static ni_addrconf_action_t *
ni_addrconf_drop_collect_complete(ni_addrconf_lease_t *lease)
{
	ni_addrconf_drop_collect_t *collect;
	ni_addrconf_action_t *action;

	if (!lease || !lease->updater)
		return NULL;

	action = ni_addrconf_action_list_find_exec(lease->updater->action,
					ni_addrconf_drop_collect_exec);
	if (!(collect = (ni_addrconf_drop_collect_t *)action))
		return NULL;

	collect->complete = TRUE;

	return action;
}

static int
ni_objectmodel_addrconf_complete_drop(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_addrconf_lease_t *current;
	ni_addrconf_action_t *action;

	if (!dev || !lease)
		return -1; /* discard invalid signals */

	/*
	 * supplicant signaled it finished it's part of the drop/release,
	 * find a releasing lease with running removal updater
	 */
	current = ni_netdev_get_lease(dev, lease->family, lease->type);
	if (!current || !current->updater || current->state != NI_ADDRCONF_STATE_RELEASING)
		return 0; /* execute default lease removal */

	if (!ni_uuid_equal(&current->uuid, &lease->uuid))
		return -1; /* discard invalid signals */

	/* find action collecting the signal and mark it complete */
	if ((action = ni_addrconf_drop_collect_complete(current))) {
		ni_debug_objectmodel("%s: completed drop for %s:%s lease in state %s uuid %s%s%s",
				dev->name,
				ni_addrfamily_type_to_name(current->family),
				ni_addrconf_type_to_name(current->type),
				ni_addrconf_state_to_name(current->state),
				ni_uuid_is_null(&current->uuid) ? "null" : ni_uuid_print(&current->uuid),
				current->updater ? "updater is active: " : "no active updater",
				current->updater && current->updater->action ?  current->updater->action->info : "");

		/* when it's already collecting, let the updater
		 * finish without to waste time until next run.
		 */
		if (action == current->updater->action)
			ni_addrconf_updater_execute(dev, current);

		return 1; /* skip default lease removal */
	}

	return 0; /* execute default lease removal */
}

static dbus_bool_t
ni_objectmodel_addrconf_forward_drop(ni_dbus_addrconf_forwarder_t *forwarder,
				ni_netdev_t *dev, const ni_dbus_variant_t *dict,
				ni_dbus_message_t *reply, DBusError *error)
{
	ni_uuid_t uuid = NI_UUID_INIT;
	ni_addrconf_lease_t *lease;
	int rv = -1;

	lease = ni_objectmodel_addrconf_get_lease(dev, forwarder->addrfamily, forwarder->addrconf);
	if (!lease)
		return TRUE; /* nothing to do */

	/* Create an empty removal lease in releasing state */
	uuid = lease->uuid;
	if (!(lease = ni_addrconf_lease_new(forwarder->addrconf, forwarder->addrfamily))) {
		dbus_set_error(error, "%s: failed to allocate removal %s:%s lease", dev->name,
				ni_addrfamily_type_to_name(forwarder->addrfamily),
				ni_addrconf_type_to_name(forwarder->addrconf));
		return FALSE;
	}
	lease->state = NI_ADDRCONF_STATE_RELEASING;
	lease->uuid = uuid;

	/* Initiate system interface background lease removal */
	rv = __ni_system_interface_update_lease(dev, &lease, NI_EVENT_ADDRESS_RELEASED);

	/* Check again whether we still have a lease and let the client wait for it's release. */
	if (rv > 0 && (lease = ni_netdev_get_lease(dev, forwarder->addrfamily, forwarder->addrconf))) {
		ni_objectmodel_callback_data_t data = { .lease = lease };

		/* arm actions to drop/release supplicant lease and collect result */
		ni_addrconf_drop_actions_arm(forwarder, lease->updater, dict);

		/* Tell the client to wait for an addressReleased event with the given uuid */
		return __ni_objectmodel_return_callback_info(reply, NI_EVENT_ADDRESS_RELEASED,
								&lease->uuid, &data, error);
	} else
	if (rv < 0) {
		/* unable to start removal / some allocation error */
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"%s: failed to drop %s:%s lease", dev->name,
				ni_addrfamily_type_to_name(forwarder->addrfamily),
				ni_addrconf_type_to_name(forwarder->addrconf));
		return FALSE;
	}

	ni_debug_objectmodel("%s: lease %s:%s dropped immediately", dev->name,
				ni_addrfamily_type_to_name(forwarder->addrfamily),
				ni_addrconf_type_to_name(forwarder->addrconf));
	return TRUE; /* Done immediately */
}

/*
 * Create client handle for addrconf forwarder
 */
static dbus_bool_t
ni_objectmodel_addrconf_forwarder_call(ni_dbus_addrconf_forwarder_t *forwarder,
				ni_netdev_t *dev, const char *method_name,
				const ni_uuid_t *uuid, const ni_dbus_variant_t *dict,
				DBusError *error)
{
	ni_dbus_object_t *object;
	char object_path[256];
	ni_dbus_variant_t argv[2];
	int argc = 0;
	dbus_bool_t rv;

	if (forwarder->supplicant.client == NULL) {
		forwarder->supplicant.client = ni_create_dbus_client(forwarder->supplicant.bus_name);
		if (forwarder->supplicant.client == NULL) {
			dbus_set_error(error, DBUS_ERROR_FAILED, "unable to create call forwarder for %s",
					forwarder->supplicant.bus_name);
			return FALSE;
		}

		ni_dbus_client_add_signal_handler(forwarder->supplicant.client,
				forwarder->supplicant.bus_name,		/* sender must be the supplicant */
				NULL,					/* any object */
				NI_OBJECTMODEL_ADDRCONF_INTERFACE,	/* interface */
				ni_objectmodel_addrconf_signal_handler,
				forwarder);
	}

	/* Build the path of the object to talk to in the supplicant service */
	snprintf(object_path, sizeof(object_path), "%s/%u",
			forwarder->supplicant.object_path, dev->link.ifindex);

	object = ni_dbus_client_object_new(forwarder->supplicant.client,
				&forwarder->class, object_path,
				forwarder->supplicant.interface, NULL);

	/* Build the arguments. Note that we don't clone the dict, we just assign it
	 * to argv[1]. Thus, we must make sure we never call ni_dbus_variant_destroy on argv[1] */
	memset(argv, 0, sizeof(argv));
	ni_dbus_variant_set_uuid(&argv[argc++], uuid);
	if (dict)
		argv[argc++] = *dict;

	/* Call the supplicant's method */
	rv = ni_dbus_object_call_variant(object, forwarder->supplicant.interface, method_name, argc, argv, 0, NULL, error);

	ni_dbus_object_free(object);
	ni_dbus_variant_destroy(&argv[0]);

	return rv;
}

/*
 * Configure IPv4 addresses via DHCP
 */
static ni_dbus_addrconf_forwarder_t dhcp4_forwarder = {
	.caller = {
		.interface	= NI_OBJECTMODEL_ADDRCONF_IPV4DHCP_INTERFACE,
	},
	.supplicant = {
		.bus_name	= NI_OBJECTMODEL_DBUS_BUS_NAME_DHCP4,
		.interface	= NI_OBJECTMODEL_DHCP4_INTERFACE,
		.object_path	= NI_OBJECTMODEL_OBJECT_PATH "/DHCP4/Interface",
	},
	.request	= {
		.class	= NULL,
		.mask	= (1U << NI_ADDRCONF_FLAGS_GROUP)
			| (1U << NI_ADDRCONF_FLAGS_PRIMARY)
			| (1U << NI_ADDRCONF_FLAGS_OPTIONAL),
	},
	.addrfamily	= AF_INET,
	.addrconf	= NI_ADDRCONF_DHCP,
	.class = {
		.name	= "netif-dhcp4-forwarder",
	}
};

static dbus_bool_t
ni_objectmodel_addrconf_ipv4_dhcp_request(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_addrconf_forwarder_t *forwarder = &dhcp4_forwarder;
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: expected one dict argument",
				forwarder->caller.interface, method->name);
		return FALSE;
	}

	return ni_objectmodel_addrconf_forward_request(forwarder, dev, &argv[0], reply, error);
}

static dbus_bool_t
ni_objectmodel_addrconf_ipv4_dhcp_drop(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	const ni_dbus_variant_t *req = argc ? &argv[0] : NULL;
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	return ni_objectmodel_addrconf_forward_drop(&dhcp4_forwarder, dev, req, reply, error);
}

/*
 * Configure IPv6 addresses via DHCP
 */
static ni_dbus_addrconf_forwarder_t dhcp6_forwarder = {
	.caller = {
		.interface	= NI_OBJECTMODEL_ADDRCONF_IPV6DHCP_INTERFACE,
	},
	.supplicant = {
		.bus_name	= NI_OBJECTMODEL_DBUS_BUS_NAME_DHCP6,
		.interface	= NI_OBJECTMODEL_DHCP6_INTERFACE,
		.object_path	= NI_OBJECTMODEL_OBJECT_PATH "/DHCP6/Interface",
	},
	.request	= {
		.class	= NULL,
		.mask	= (1U << NI_ADDRCONF_FLAGS_GROUP)
			| (1U << NI_ADDRCONF_FLAGS_OPTIONAL),
	},
	.addrfamily	= AF_INET6,
	.addrconf	= NI_ADDRCONF_DHCP,
	.class = {
		.name	= "netif-dhcp6-forwarder",
	}
};

static dbus_bool_t
ni_objectmodel_addrconf_ipv6_dhcp_request(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_addrconf_forwarder_t *forwarder = &dhcp6_forwarder;
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: expected one dict argument",
				forwarder->caller.interface, method->name);
		return FALSE;
	}

	return ni_objectmodel_addrconf_forward_request(forwarder, dev, &argv[0], reply, error);
}

static dbus_bool_t
ni_objectmodel_addrconf_ipv6_dhcp_drop(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	const ni_dbus_variant_t *req = argc ? &argv[0] : NULL;
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	return ni_objectmodel_addrconf_forward_drop(&dhcp6_forwarder, dev, req, reply, error);
}

/*
 * Configure IPv4 addresses via IPv4ll
 */
static ni_dbus_addrconf_forwarder_t auto4_forwarder = {
	.caller = {
		.interface	= NI_OBJECTMODEL_ADDRCONF_IPV4AUTO_INTERFACE,
	},
	.supplicant = {
		.bus_name	= NI_OBJECTMODEL_DBUS_BUS_NAME_AUTO4,
		.interface	= NI_OBJECTMODEL_AUTO4_INTERFACE,
		.object_path	= NI_OBJECTMODEL_OBJECT_PATH "/AUTO4/Interface",
	},
	.request	= {
		.class	= &ni_objectmodel_auto4_request_class,
		.mask	= (1U << NI_ADDRCONF_FLAGS_FALLBACK),
	},
	.addrfamily	= AF_INET,
	.addrconf	= NI_ADDRCONF_AUTOCONF,
	.class = {
		.name	= "netif-auto4-forwarder",
	}
};

static dbus_bool_t
ni_objectmodel_addrconf_ipv4_auto_request(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_addrconf_forwarder_t *forwarder = &auto4_forwarder;
	ni_objectmodel_callback_data_t data = { .lease = NULL };
	const ni_dbus_variant_t *dict;
	ni_addrconf_lease_t *lease;
	dbus_bool_t enabled;
	ni_netdev_t *dev;
	uint32_t flags;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: expected one dict argument",
				forwarder->caller.interface, method->name);
		return FALSE;
	}

	dict = &argv[0];
	if (!ni_dbus_dict_get_bool(dict, "enabled", &enabled) || !enabled)
		return ni_objectmodel_addrconf_forward_drop(forwarder, dev, NULL, reply, error);

	if (ni_dbus_dict_get_uint32(dict, "flags", &flags))
		flags &= forwarder->request.mask;
	else
		flags = 0;

	if (!ni_addrconf_flag_bit_is_set(flags, NI_ADDRCONF_FLAGS_FALLBACK))
		return ni_objectmodel_addrconf_forward_request(forwarder, dev, dict, reply, error);

	lease = ni_objectmodel_addrconf_get_lease(dev, forwarder->addrfamily, forwarder->addrconf);
	if (!lease) {
		if (!(lease = ni_addrconf_lease_new(forwarder->addrconf, forwarder->addrfamily)))
			return FALSE;

		ni_netdev_set_lease(dev, lease);
	}
	ni_uuid_generate(&lease->uuid);
	lease->state = NI_ADDRCONF_STATE_REQUESTING;
	lease->flags = flags;
	data.lease = lease;
	return __ni_objectmodel_return_callback_info(reply, NI_EVENT_ADDRESS_ACQUIRED, &lease->uuid, &data, error);
}

static dbus_bool_t
ni_objectmodel_addrconf_ipv4_auto_drop(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_addrconf_forwarder_t *forwarder = &auto4_forwarder;
	ni_addrconf_lease_t *lease;
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	/* When we get a drop request, remove fallback flag to not trigger reinstall ... */
	lease = ni_objectmodel_addrconf_get_lease(dev, forwarder->addrfamily, forwarder->addrconf);
	if (lease)
		lease->flags = 0;

	return ni_objectmodel_addrconf_forward_drop(forwarder, dev, NULL, reply, error);
}

/*
 * Fallback lease request
 */
static ni_addrconf_lease_t *
ni_objectmodel_addrconf_fallback_find_lease(ni_netdev_t *dev, unsigned int family)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease;

	for (lease = dev->leases; lease; lease = lease->next) {
		ni_addrconf_flags_format(&buf, lease->flags, "|");
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_OBJECTMODEL,
			"%s(%s): check %s fallback lease %s:%s, state: %s, flags: %s",
			__func__, dev->name, ni_addrfamily_type_to_name(family),
			ni_addrfamily_type_to_name(lease->family),
			ni_addrconf_type_to_name(lease->type),
			ni_addrconf_state_to_name(lease->state),
			buf.string ? buf.string : "none");
		ni_stringbuf_destroy(&buf);

		if (lease->family != family)
			continue;
		if (ni_addrconf_flag_bit_is_set(lease->flags, NI_ADDRCONF_FLAGS_FALLBACK))
			return lease;
	}
	return NULL;
}

static dbus_bool_t
ni_objectmodel_addrconf_fallback_request(ni_netdev_t *dev, unsigned int family)
{
	ni_dbus_variant_t dict = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	ni_addrconf_lease_t *lease;
	dbus_bool_t rv = FALSE;

	if (!(lease = ni_objectmodel_addrconf_fallback_find_lease(dev, family))) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_OBJECTMODEL,
			"%s(%s): no %s fallback lease active", __func__,
			dev->name, ni_addrfamily_type_to_name(family));
		return FALSE;
	}

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_OBJECTMODEL,
		"%s(%s): found %s fallback lease %s:%s", __func__,
		dev->name, ni_addrfamily_type_to_name(family),
		ni_addrfamily_type_to_name(lease->family),
		ni_addrconf_type_to_name(lease->type));

	if (lease->type == NI_ADDRCONF_AUTOCONF && lease->family == AF_INET) {
		ni_dbus_addrconf_forwarder_t *forwarder = &auto4_forwarder;
		ni_auto4_request_t *req = ni_auto4_request_new();

		/* make sure, we enter requesting state here */
		lease->state = NI_ADDRCONF_STATE_REQUESTING;

		req->enabled = TRUE;
		req->flags = lease->flags;
		req->uuid = lease->uuid;

		memset(&dict, 0, sizeof(dict));
		if (!ni_objectmodel_get_auto4_request_dict(req, &dict, &error)) {
			ni_dbus_variant_destroy(&dict);
			ni_auto4_request_free(req);
			return FALSE;
		}

		rv = ni_objectmodel_addrconf_forwarder_call(forwarder, dev, "acquire",
				&lease->uuid, &dict, &error);
		if (!rv) {
			ni_debug_objectmodel("%s: service returned %s (%s)",
					forwarder->supplicant.interface,
					error.name, error.message);
			/* emit failure... */
		}
		ni_dbus_variant_destroy(&dict);
		dbus_error_free(&error);
	}
	return rv;
}

static dbus_bool_t
ni_objectmodel_addrconf_fallback_release(ni_netdev_t *dev, unsigned int family)
{
	DBusError error = DBUS_ERROR_INIT;
	ni_addrconf_lease_t *lease;
	dbus_bool_t rv = FALSE;

	if (!(lease = ni_objectmodel_addrconf_fallback_find_lease(dev, family))) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_OBJECTMODEL,
			"%s(%s): no %s fallback lease active", __func__,
			dev->name, ni_addrfamily_type_to_name(family));
		return FALSE;
	}

	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_OBJECTMODEL,
		"%s(%s): found %s fallback lease %s:%s", __func__,
		dev->name, ni_addrfamily_type_to_name(family),
		ni_addrfamily_type_to_name(lease->family),
		ni_addrconf_type_to_name(lease->type));

	if (lease->type == NI_ADDRCONF_AUTOCONF && lease->family == AF_INET) {
		ni_dbus_addrconf_forwarder_t *forwarder = &auto4_forwarder;

		rv = ni_objectmodel_addrconf_forwarder_call(forwarder, dev, "drop",
				&lease->uuid, NULL, &error);
		if (!rv) {
			switch (ni_dbus_get_error(&error, NULL)) {
			case -NI_ERROR_ADDRCONF_NO_LEASE:
				ni_debug_objectmodel("%s: no %s/%s lease", dev->name,
						ni_addrconf_type_to_name(forwarder->addrconf),
						ni_addrfamily_type_to_name(forwarder->addrfamily));

				if (ni_addrconf_flag_bit_is_set(lease->flags, NI_ADDRCONF_FLAGS_FALLBACK)) {
					/* bsc#1220996 - on fallback lease, it just wasn't triggered,
					 * so we need to change state and inform nanny that it's done. */
					lease->state = NI_ADDRCONF_STATE_REQUESTING;
					ni_objectmodel_addrconf_send_event(dev,
							NI_EVENT_ADDRESS_DEFERRED, &lease->uuid);
				}
				rv = TRUE;
				break;
			default:
				ni_debug_objectmodel("%s: service returned %s (%s)",
						forwarder->supplicant.interface,
						error.name, error.message);
				break;
			}
		}
		dbus_error_free(&error);
	}
	return rv;
}

static dbus_bool_t
ni_objectmodel_addrconf_fallback_reinstall(ni_netdev_t *dev, ni_addrconf_lease_t *lease)
{
	ni_addrconf_lease_t *nlease;

	if (!dev || !lease)
		return FALSE;

	nlease = ni_addrconf_lease_new(lease->type, lease->family);
	nlease->state = NI_ADDRCONF_STATE_RELEASED;
	if (lease->old) {
		nlease->flags = lease->old->flags;
		nlease->uuid = lease->old->uuid;
	} else {
		nlease->flags = lease->flags;
		nlease->uuid = lease->uuid;
	}
	/* Hmm... generate a new uuid? */
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_OBJECTMODEL,
		"%s: reinstalled released fallback lease", dev->name);
	ni_netdev_set_lease(dev, nlease);
	return TRUE;
}

/*
 * Configure IPv6 autoconf
 */
static dbus_bool_t
ni_objectmodel_addrconf_ipv6_auto_release(ni_netdev_t *dev, ni_bool_t background,
			ni_dbus_object_t *object, const ni_dbus_method_t *method,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_addrconf_lease_t *lease;
	int ret;

	ni_objectmodel_addrconf_get_lease(dev, AF_INET6, NI_ADDRCONF_AUTOCONF);

	if ((ret = ni_auto6_release(dev, background)) == 0)
		return TRUE;

	if (ret > 0 && (lease = ni_netdev_get_lease(dev, AF_INET6, NI_ADDRCONF_AUTOCONF))) {
		ni_objectmodel_callback_data_t data = { .lease = lease };

		return __ni_objectmodel_return_callback_info(reply,
				NI_EVENT_ADDRESS_RELEASED, &lease->uuid, &data, error);
	}

	dbus_set_error(error, DBUS_ERROR_FAILED,
			"%s.%s: failed to release lease",
			NI_OBJECTMODEL_ADDRCONF_IPV6AUTO_INTERFACE, method->name);
	return FALSE;
}

static dbus_bool_t
ni_objectmodel_addrconf_ipv6_auto_request(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_addrconf_lease_t *lease;
	ni_auto6_request_t req;
	ni_netdev_t *dev;
	int ret;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	ni_auto6_request_init(&req);
	if (argc != 1 || !ni_objectmodel_set_auto6_request_dict(&req, &argv[0], error)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: expected one auto6 request dict argument",
				NI_OBJECTMODEL_ADDRCONF_IPV6AUTO_INTERFACE, method->name);
		return FALSE;
	}

	if (!req.enabled) {
		/* force to create a releasing lease and run in background,
		 * which we're using for lease info callback data...  */
		ni_auto6_request_destroy(&req);
		return ni_objectmodel_addrconf_ipv6_auto_release(dev, TRUE, object,
								method, reply, error);
	}

	ni_objectmodel_addrconf_get_lease(dev, AF_INET6, NI_ADDRCONF_AUTOCONF);

	ret = ni_auto6_acquire(dev, &req);
	ni_auto6_request_destroy(&req);
	if (ret >= 0 && (lease = ni_netdev_get_lease(dev, AF_INET6, NI_ADDRCONF_AUTOCONF))) {
		ni_objectmodel_callback_data_t data = { .lease = lease };

		return __ni_objectmodel_return_callback_info(reply,
				NI_EVENT_ADDRESS_ACQUIRED, &lease->uuid, &data, error);
	}

	dbus_set_error(error, DBUS_ERROR_FAILED,
			"%s.%s: failed to acquire lease",
			NI_OBJECTMODEL_ADDRCONF_IPV6AUTO_INTERFACE, method->name);
	return FALSE;
}

static dbus_bool_t
ni_objectmodel_addrconf_ipv6_auto_drop(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	/* normal dropLease can just return 0 when there is no lease on device */
	return ni_objectmodel_addrconf_ipv6_auto_release(dev, FALSE, object, method, reply, error);
}

/*
 * Generic lease properties
 */
static dbus_bool_t
__ni_objectmodel_addrconf_generic_get_lease(const ni_dbus_object_t *object,
				ni_addrconf_mode_t mode, unsigned int addrfamily,
				ni_dbus_variant_t *dict,
				DBusError *error)
{
	ni_netdev_t *dev;
	const ni_addrconf_lease_t *lease;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

#if 0
	NI_TRACE_ENTER_ARGS("dev=%s, af=%s, mode=%s", dev->name,
			ni_addrfamily_type_to_name(addrfamily),
			ni_addrconf_type_to_name(mode));
#endif
	if (!(lease = ni_netdev_get_lease(dev, addrfamily, mode)))
		return FALSE;

	ni_dbus_dict_add_uint32(dict, "state", lease->state);
	if (lease->flags)
		ni_dbus_dict_add_uint32(dict, "flags", lease->flags);
	if (!ni_uuid_is_null(&lease->uuid))
		ni_dbus_dict_add_uuid(dict,   "uuid", &lease->uuid);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_addrconf_generic_set_lease(ni_dbus_object_t *object,
				ni_addrconf_mode_t mode, unsigned int addrfamily,
				const ni_dbus_variant_t *dict,
				DBusError *error)
{
	ni_netdev_t *dev;
	uint32_t state;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (ni_dbus_dict_get_uint32(dict, "state", &state)) {
		ni_addrconf_lease_t *lease;

		lease = ni_addrconf_lease_new(mode, addrfamily);
		lease->state = state;
		ni_dbus_dict_get_uuid(dict,   "uuid", &lease->uuid);
		ni_dbus_dict_get_uint32(dict, "flags", &lease->flags);
		ni_netdev_set_lease(dev, lease);
	}
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv4_static_get_lease(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_get_lease(object, NI_ADDRCONF_STATIC, AF_INET, result, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv4_static_set_lease(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_set_lease(object, NI_ADDRCONF_STATIC, AF_INET, argument, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv4_dhcp_get_lease(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_get_lease(object, NI_ADDRCONF_DHCP, AF_INET, result, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv4_dhcp_set_lease(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_set_lease(object, NI_ADDRCONF_DHCP, AF_INET, argument, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv6_dhcp_get_lease(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_get_lease(object, NI_ADDRCONF_DHCP, AF_INET6, result, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv6_dhcp_set_lease(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_set_lease(object, NI_ADDRCONF_DHCP, AF_INET6, argument, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv4_auto_get_lease(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_get_lease(object, NI_ADDRCONF_AUTOCONF, AF_INET, result, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv4_auto_set_lease(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_set_lease(object, NI_ADDRCONF_AUTOCONF, AF_INET, argument, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv6_auto_get_lease(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_get_lease(object, NI_ADDRCONF_AUTOCONF, AF_INET6, result, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv6_auto_set_lease(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_set_lease(object, NI_ADDRCONF_AUTOCONF, AF_INET6, argument, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv6_static_get_lease(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_get_lease(object, NI_ADDRCONF_STATIC, AF_INET6, result, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv6_static_set_lease(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_set_lease(object, NI_ADDRCONF_STATIC, AF_INET6, argument, error);
}

static ni_dbus_property_t		ni_objectmodel_addrconf_ipv4_static_properties[] = {
	__NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, lease, __ni_objectmodel_addrconf_ipv4_static, RO),
	{ NULL }
};

static ni_dbus_property_t		ni_objectmodel_addrconf_ipv6_static_properties[] = {
	__NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, lease, __ni_objectmodel_addrconf_ipv6_static, RO),
	{ NULL }
};

static ni_dbus_property_t		ni_objectmodel_addrconf_ipv4_dhcp_properties[] = {
	__NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, lease, __ni_objectmodel_addrconf_ipv4_dhcp, RO),
	{ NULL }
};

static ni_dbus_property_t		ni_objectmodel_addrconf_ipv6_dhcp_properties[] = {
	__NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, lease, __ni_objectmodel_addrconf_ipv6_dhcp, RO),
	{ NULL }
};

static ni_dbus_property_t		ni_objectmodel_addrconf_ipv4_auto_properties[] = {
	__NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, lease, __ni_objectmodel_addrconf_ipv4_auto, RO),
	{ NULL }
};

static ni_dbus_property_t		ni_objectmodel_addrconf_ipv6_auto_properties[] = {
	__NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, lease, __ni_objectmodel_addrconf_ipv6_auto, RO),
	{ NULL }
};

/*
 * Addrconf methods
 */
static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv4_static_methods[] = {
	{ "requestLease",	"a{sv}",	.handler = ni_objectmodel_addrconf_ipv4_static_request },
	{ "dropLease",		"",		.handler = ni_objectmodel_addrconf_ipv4_static_drop },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv6_static_methods[] = {
	{ "requestLease",	"a{sv}",	.handler = ni_objectmodel_addrconf_ipv6_static_request },
	{ "dropLease",		"",		.handler = ni_objectmodel_addrconf_ipv6_static_drop },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv4_dhcp_methods[] = {
	{ "requestLease",	"a{sv}",	.handler = ni_objectmodel_addrconf_ipv4_dhcp_request },
	{ "dropLease",		"a{sv}",	.handler = ni_objectmodel_addrconf_ipv4_dhcp_drop },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv6_dhcp_methods[] = {
	{ "requestLease",	"a{sv}",	.handler = ni_objectmodel_addrconf_ipv6_dhcp_request },
	{ "dropLease",		"a{sv}",	.handler = ni_objectmodel_addrconf_ipv6_dhcp_drop },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv4_auto_methods[] = {
	{ "requestLease",	"a{sv}",	.handler = ni_objectmodel_addrconf_ipv4_auto_request },
	{ "dropLease",		"",		.handler = ni_objectmodel_addrconf_ipv4_auto_drop },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv6_auto_methods[] = {
	{ "requestLease",	"a{sv}",	.handler = ni_objectmodel_addrconf_ipv6_auto_request },
	{ "dropLease",		"",		.handler = ni_objectmodel_addrconf_ipv6_auto_drop },
	{ NULL }
};

/*
 * IPv4 and IPv6 addrconf request service
 */
ni_dbus_service_t			ni_objectmodel_addrconf_ipv4_static_service = {
	.name		= NI_OBJECTMODEL_ADDRCONF_IPV4STATIC_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv4_static_methods,
	.properties	= ni_objectmodel_addrconf_ipv4_static_properties,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv6_static_service = {
	.name		= NI_OBJECTMODEL_ADDRCONF_IPV6STATIC_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv6_static_methods,
	.properties	= ni_objectmodel_addrconf_ipv6_static_properties,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv4_dhcp_service = {
	.name		= NI_OBJECTMODEL_ADDRCONF_IPV4DHCP_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv4_dhcp_methods,
	.properties	= ni_objectmodel_addrconf_ipv4_dhcp_properties,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv6_dhcp_service = {
	.name		= NI_OBJECTMODEL_ADDRCONF_IPV6DHCP_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv6_dhcp_methods,
	.properties	= ni_objectmodel_addrconf_ipv6_dhcp_properties,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv4_auto_service = {
	.name		= NI_OBJECTMODEL_ADDRCONF_IPV4AUTO_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv4_auto_methods,
	.properties	= ni_objectmodel_addrconf_ipv4_auto_properties,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv6_auto_service = {
	.name		= NI_OBJECTMODEL_ADDRCONF_IPV6AUTO_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv6_auto_methods,
	.properties	= ni_objectmodel_addrconf_ipv6_auto_properties,
};


/*
 * Auto4 supplicant request
 */

ni_auto4_request_t *
ni_auto4_request_new(void)
{
	ni_auto4_request_t *req;

	req = xmalloc(sizeof(*req));
	ni_auto4_request_init(req, FALSE);
	return req;
}

void
ni_auto4_request_init(ni_auto4_request_t *req, ni_bool_t enabled)
{
	if (req) {
		memset(req, 0, sizeof(*req));
		req->enabled = enabled;
	}
}

ni_bool_t
ni_auto4_request_copy(ni_auto4_request_t *dst, const ni_auto4_request_t *src)
{
	if (dst && src) {
		*dst = *src;
		return TRUE;
	}
	return FALSE;
}

void
ni_auto4_request_destroy(ni_auto4_request_t *req)
{
	if (req) {
		memset(req, 0, sizeof(*req));
	}
}

void
ni_auto4_request_free(ni_auto4_request_t *req)
{
	ni_auto4_request_destroy(req);
	free(req);
}

static ni_auto4_request_t *
__ni_objectmodel_get_auto4_request(const ni_dbus_object_t *object, DBusError *error)
{
	if (!object) {
		if (error) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Cannot unwrap auto4 request from a NULL dbus object");
		}
		return NULL;
	}
	if (!ni_dbus_object_isa(object, &ni_objectmodel_auto4_request_class)) {
		if (error)  {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"method not compatible with object %s of class %s (not auto4 request)",
					object->path, object->class->name);
		}
		return NULL;
	}
	return object->handle;
}

static void *
ni_objectmodel_get_auto4_request(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_get_auto4_request(object, error);
}

static ni_dbus_property_t		ni_objectmodel_auto4_request_properties[] = {
	NI_DBUS_GENERIC_BOOL_PROPERTY(auto4_request, enabled, enabled, RO),
	NI_DBUS_GENERIC_UINT_PROPERTY(auto4_request, flags, flags, RO),
	NI_DBUS_GENERIC_UUID_PROPERTY(auto4_request, uuid, uuid, RO),
	{ NULL }
};

static ni_dbus_service_t		ni_objectmodel_auto4_request_service = {
	.name		= NI_OBJECTMODEL_AUTO4_INTERFACE".Request",
	.compatible	= &ni_objectmodel_auto4_request_class,
	.properties	= ni_objectmodel_auto4_request_properties,
};

dbus_bool_t
ni_objectmodel_get_auto4_request_dict(const ni_auto4_request_t *req, ni_dbus_variant_t *dict, DBusError *error)
{
	ni_auto4_request_t tmp;
	ni_dbus_object_t obj;

	if (!req || !dict || !ni_auto4_request_copy(&tmp, req))
		return FALSE;

	memset(&obj, 0, sizeof(obj));
	obj.handle = &tmp;
	obj.class = &ni_objectmodel_auto4_request_class;

	ni_dbus_variant_init_dict(dict);
	return ni_dbus_object_get_properties_as_dict(&obj, &ni_objectmodel_auto4_request_service, dict, error);
}

dbus_bool_t
ni_objectmodel_set_auto4_request_dict(ni_auto4_request_t *req, const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_object_t obj;

	if (!req || !dict || !ni_dbus_variant_is_dict(dict))
		return FALSE;

	memset(&obj, 0, sizeof(obj));
	obj.handle = req;
	obj.class = &ni_objectmodel_auto4_request_class;

	return ni_dbus_object_set_properties_from_dict(&obj, &ni_objectmodel_auto4_request_service, dict, error);
}

/*
 * Auto6 request from dict
 */
static dbus_bool_t
ni_objectmodel_set_auto6_request_dict(ni_auto6_request_t *req, const ni_dbus_variant_t *dict, DBusError *error)
{
	dbus_bool_t enabled;

	(void)error;

	if (!req || !dict || !ni_dbus_variant_is_dict(dict))
		return FALSE;

	if (ni_dbus_dict_get_bool(dict, "enabled", &enabled))
		req->enabled = enabled;

	ni_dbus_dict_get_uint32(dict, "defer-timeout", &req->defer_timeout);

	if (!ni_dbus_dict_get_uint32(dict, "update", &req->update))
		req->update = 0;

	return TRUE;
}

