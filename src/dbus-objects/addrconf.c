/*
 * Generic dbus client functions for address configuration
 * services implemented as separate DBus services (like dhcp,
 * ipv4ll)
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

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
#include <wicked/system.h>
#include "netinfo_priv.h"	/* for __ni_system_interface_update_lease */
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

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

	int			addrfamily;
	ni_addrconf_mode_t	addrconf;

	ni_dbus_class_t		class;
} ni_dbus_addrconf_forwarder_t;


#define WICKED_DBUS_ADDRCONF_IPV4STATIC_INTERFACE	WICKED_DBUS_INTERFACE ".Addrconf.ipv4.static"
#define WICKED_DBUS_ADDRCONF_IPV4DHCP_INTERFACE		WICKED_DBUS_INTERFACE ".Addrconf.ipv4.dhcp"
#define WICKED_DBUS_ADDRCONF_IPV4AUTO_INTERFACE		WICKED_DBUS_INTERFACE ".Addrconf.ipv4.auto"
#define WICKED_DBUS_ADDRCONF_IPV6STATIC_INTERFACE	WICKED_DBUS_INTERFACE ".Addrconf.ipv6.static"

/*
 * Extract interface index from object path.
 * Path names must be WICKED_DBUS_OBJECT_PATH "/" <something> "/Interface/" <index>
 */
static ni_interface_t *
ni_objectmodel_addrconf_path_to_device(const char *path)
{
	unsigned int ifindex;
	ni_netconfig_t *nc;
	char cc;

	if (strncmp(path, WICKED_DBUS_OBJECT_PATH, strlen(WICKED_DBUS_OBJECT_PATH)))
		return NULL;
	path += strlen(WICKED_DBUS_OBJECT_PATH);

	if (*path++ != '/')
		return NULL;
	while ((cc = *path++) != '/') {
		if (cc == '\0')
			return NULL;
	}

	if (strncmp(path, "Interface/", 10))
		return NULL;
	path += 10;

	if (ni_parse_int(path, &ifindex) < 0)
		return NULL;

	nc = ni_global_state_handle(1);
	if (nc == NULL) {
		ni_error("%s: unable to refresh interfaces", __func__);
		return NULL;
	}

	return ni_interface_by_index(nc, ifindex);
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
	ni_interface_t *ifp;
	ni_addrconf_request_t *req = NULL;
	ni_addrconf_lease_t *lease = NULL;
	ni_dbus_variant_t argv[16];
	ni_uuid_t uuid = NI_UUID_INIT;
	int argc, optind = 0;

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

	if (argc == 2) {
		unsigned int dummy;

		if (!ni_dbus_variant_get_byte_array_minmax(&argv[optind++], uuid.octets, &dummy, 16, 16)) {
			ni_debug_dbus("%s: unable to parse uuid argument", __func__);
			goto done;
		}
	}

	if (!ni_objectmodel_set_addrconf_lease(lease, &argv[optind++])) {
		ni_debug_dbus("%s: unable to parse lease argument", __func__);
		goto done;
	}

	/* Check if there's an addrconf request with corresponding uuid.
	 * If so, there's a client somewhere waiting for that event.
	 * We use the UUID that's passed back and forth to make sure we
	 * really match the event we were expecting to match.
	 */
	if (!ni_uuid_is_null(&uuid))
		req = ni_interface_get_addrconf_request(ifp, &uuid);

	ni_debug_dbus("received signal %s for interface %s (ifindex %d), lease %s/%s",
			signal_name, ifp->name, ifp->link.ifindex,
			ni_addrconf_type_to_name(lease->type),
			ni_addrfamily_type_to_name(lease->family));
	if (!strcmp(signal_name, "LeaseAcquired")) {
		if (lease->state != NI_ADDRCONF_STATE_GRANTED) {
			ni_error("%s: unexpected lease state in signal %s", __func__, signal_name);
			goto done;
		}

		if (!ni_uuid_is_null(&uuid))
			ni_objectmodel_interface_event(NULL, ifp, NI_EVENT_ADDRESS_ACQUIRED, &uuid);

		/* Note, lease may be NULL after this, as the interface object
		 * takes ownership of it. */
		__ni_system_interface_update_lease(ifp, &lease);

		if (__ni_interface_is_up(ifp))
			ni_objectmodel_interface_event(NULL, ifp, NI_EVENT_NETWORK_UP, NULL);
	} else if (!strcmp(signal_name, "LeaseReleased")) {
		lease->state = NI_ADDRCONF_STATE_RELEASED;
		__ni_system_interface_update_lease(ifp, &lease);

		if (!ni_uuid_is_null(&uuid))
			ni_objectmodel_interface_event(NULL, ifp, NI_EVENT_ADDRESS_RELEASED, &uuid);

		if (__ni_interface_is_down(ifp))
			ni_objectmodel_interface_event(NULL, ifp, NI_EVENT_NETWORK_DOWN, NULL);
	} else if (!strcmp(signal_name, "LeaseLost")) {
		lease->state = NI_ADDRCONF_STATE_FAILED;
		__ni_system_interface_update_lease(ifp, &lease);
		ni_objectmodel_interface_event(NULL, ifp, NI_EVENT_ADDRESS_LOST, NULL);
	} else {
		/* Ignore unknown signal */
	}

done:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
	if (lease)
		ni_addrconf_lease_free(lease);
	if (req)
		ni_addrconf_request_free(req);
}

/*
 * Configure static IPv4 addresses
 */
static dbus_bool_t
ni_objectmodel_addrconf_ipv4_static_configure(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_addrconf_lease_t *lease = NULL;
	const ni_dbus_variant_t *dict;
	ni_interface_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: exected one dict argument",
				WICKED_DBUS_ADDRCONF_IPV4STATIC_INTERFACE, method->name);
		return FALSE;
	}
	dict = &argv[0];

	lease = ni_addrconf_lease_new(NI_ADDRCONF_STATIC, AF_INET);
	if (!__ni_objectmodel_set_address_dict(&lease->addrs, dict, error)
	 || !__ni_objectmodel_set_route_dict(&lease->routes, dict, error)) {
		ni_addrconf_lease_free(lease);
		return FALSE;
	}

	rv = __ni_system_interface_update_lease(dev, &lease);
	if (lease)
		ni_addrconf_lease_free(lease);

	if (rv < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Error configuring static IPv4 addresses: %s",
				ni_strerror(rv));
		return FALSE;
	} else {
		/* A NULL event ID tells the caller that we're done, there's no event
		 * to wait for. */
		ni_dbus_message_append_uint32(reply, 0);
	}

	return TRUE;
}

/*
 * Configure static IPv6 addresses
 */
static dbus_bool_t
ni_objectmodel_addrconf_ipv6_static_configure(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_addrconf_lease_t *lease = NULL;
	const ni_dbus_variant_t *dict;
	ni_interface_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: exected one dict argument",
				WICKED_DBUS_ADDRCONF_IPV4STATIC_INTERFACE, method->name);
		return FALSE;
	}
	dict = &argv[0];

	/* FIXME: what we should do here is
	 *  - create an empty addrconf request, with no uuid or event ID
	 *  - create a lease object with the provided addresses and routes
	 *  - install the lease (ie configure addresses)
	 */

	lease = ni_addrconf_lease_new(NI_ADDRCONF_STATIC, AF_INET6);
	if (!__ni_objectmodel_set_address_dict(&lease->addrs, dict, error)
	 || !__ni_objectmodel_set_route_dict(&lease->routes, dict, error))
		return FALSE;

	rv = __ni_system_interface_update_lease(dev, &lease);
	if (lease)
		ni_addrconf_lease_free(lease);

	if (rv < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Error configuring static IPv6 addresses: %s",
				ni_strerror(rv));
		return FALSE;
	} else {
		/* A NULL event ID tells the caller that we're done, there's no event
		 * to wait for. */
		ni_dbus_message_append_uint32(reply, 0);
	}

	return TRUE;
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
static ni_addrconf_request_t *
ni_objectmodel_addrconf_forward(ni_dbus_addrconf_forwarder_t *forwarder,
			ni_interface_t *dev, const char *method_name,
			const ni_dbus_variant_t *dict,
			DBusError *error)
{
	ni_dbus_object_t *object;
	ni_addrconf_request_t *req;
	char object_path[256];

	if (forwarder->supplicant.client == NULL) {
		forwarder->supplicant.client = ni_create_dbus_client(forwarder->supplicant.bus_name);
		if (forwarder->supplicant.client == NULL) {
			dbus_set_error(error, "unable to create call forwarder for %s",
					forwarder->supplicant.bus_name);
			return NULL;
		}

		ni_dbus_client_add_signal_handler(forwarder->supplicant.client, NULL, NULL,
				forwarder->supplicant.interface,
				ni_objectmodel_addrconf_signal_handler,
				forwarder);
	}

	/* Create a request, generate a uuid and assign an event ID */
	req = ni_addrconf_request_new(forwarder->caller.interface);
	ni_uuid_generate(&req->uuid);

	/* Install it with the interface */
	ni_interface_set_addrconf_request(dev, req);

	/* Build the path of the object to talk to in the supplicant service */
	snprintf(object_path, sizeof(object_path), "%s/%u",
			forwarder->supplicant.object_path, dev->link.ifindex);

	object = ni_dbus_client_object_new(forwarder->supplicant.client,
				&forwarder->class, object_path,
				forwarder->supplicant.interface, NULL);

	/* Call the supplicant's method */
	if (!ni_dbus_object_call_variant(object, forwarder->supplicant.interface, method_name, 1, dict, 0, NULL, error))
		return NULL;

	return req;
}

/*
 * Configure IPv4 addresses via DHCP
 */
static dbus_bool_t
ni_objectmodel_addrconf_ipv4_dhcp_configure(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	static ni_dbus_addrconf_forwarder_t forwarder = {
		.caller = {
			.interface	= WICKED_DBUS_ADDRCONF_IPV4DHCP_INTERFACE,
		},
		.supplicant = {
			.bus_name	= WICKED_DBUS_BUS_NAME_DHCP4,
			.interface	= WICKED_DBUS_DHCP4_INTERFACE,
			.object_path	= WICKED_DBUS_OBJECT_PATH "/DHCP4/Interface",
		},
		.addrfamily	= AF_INET,
		.addrconf	= NI_ADDRCONF_DHCP,
		.class = {
			.name	= "netif-dhcp-forwarder",
		}
	};
	ni_interface_t *dev;
	ni_addrconf_request_t *req;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: exected one dict argument",
				WICKED_DBUS_ADDRCONF_IPV4DHCP_INTERFACE, method->name);
		return FALSE;
	}

	req = ni_objectmodel_addrconf_forward(&forwarder, dev, "acquire", &argv[0], error);
	if (req == NULL)
		return FALSE;

	/* Tell the client to wait for an addressAcquired event with the given uuid */
	return __ni_objectmodel_return_callback_info(reply, NI_EVENT_ADDRESS_ACQUIRED, &req->uuid, error);
}

/*
 * Configure IPv4 addresses via IPv4ll
 */
static dbus_bool_t
ni_objectmodel_addrconf_ipv4ll_configure(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	static ni_dbus_addrconf_forwarder_t forwarder = {
		.caller = {
			.interface	= WICKED_DBUS_ADDRCONF_IPV4AUTO_INTERFACE,
		},
		.supplicant = {
			.bus_name	= WICKED_DBUS_BUS_NAME_AUTO4,
			.interface	= WICKED_DBUS_AUTO4_INTERFACE,
			.object_path	= WICKED_DBUS_OBJECT_PATH "/AUTO4/Interface",
		},
		.addrfamily	= AF_INET,
		.addrconf	= NI_ADDRCONF_AUTOCONF,
		.class = {
			.name	= "netif-ipv4ll-forwarder",
		}
	};
	ni_addrconf_request_t *req = NULL;
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: exected one dict argument",
				WICKED_DBUS_ADDRCONF_IPV4AUTO_INTERFACE, method->name);
		return FALSE;
	}

	req = ni_objectmodel_addrconf_forward(&forwarder, dev, "acquire", &argv[0], error);
	if (req == NULL)
		return FALSE;

	/* Tell the client to wait for an addressAcquired event with the given uuid */
	return __ni_objectmodel_return_callback_info(reply, NI_EVENT_ADDRESS_ACQUIRED, &req->uuid, error);
}

/*
 * Addrconf methods
 */
static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv4_static_methods[] = {
	{ "configure",		"a{sv}",		ni_objectmodel_addrconf_ipv4_static_configure },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv6_static_methods[] = {
	{ "configure",		"a{sv}",		ni_objectmodel_addrconf_ipv6_static_configure },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv4_dhcp_methods[] = {
	{ "configure",		"a{sv}",		ni_objectmodel_addrconf_ipv4_dhcp_configure },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv4ll_methods[] = {
	{ "configure",		"a{sv}",		ni_objectmodel_addrconf_ipv4ll_configure },
	{ NULL }
};

/*
 * IPv4 and IPv6 addrconf request service
 */
ni_dbus_service_t			ni_objectmodel_addrconf_ipv4_static_service = {
	.name		= WICKED_DBUS_ADDRCONF_IPV4STATIC_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv4_static_methods,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv6_static_service = {
	.name		= WICKED_DBUS_ADDRCONF_IPV4STATIC_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv6_static_methods,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv4_dhcp_service = {
	.name		= WICKED_DBUS_ADDRCONF_IPV4DHCP_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv4_dhcp_methods,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv4ll_service = {
	.name		= WICKED_DBUS_ADDRCONF_IPV4AUTO_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv4ll_methods,
};

