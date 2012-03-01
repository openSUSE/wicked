/*
 * Generic dbus client functions for address configuration
 * services implemented as separate DBus services (like dhcp,
 * ipv4ll)
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
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

static dbus_bool_t	ni_objectmodel_addrconf_forwarder_call(ni_dbus_addrconf_forwarder_t *forwarder,
					ni_interface_t *dev, const char *method_name,
					const ni_uuid_t *uuid, const ni_dbus_variant_t *dict,
					DBusError *error);

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
	ni_addrconf_lease_t *lease = NULL;
	ni_dbus_variant_t argv[16];
	ni_uuid_t uuid = NI_UUID_INIT;
	ni_event_t ifevent;
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

	ni_debug_dbus("received signal %s for interface %s (ifindex %d), lease %s/%s, uuid=%s",
			signal_name, ifp->name, ifp->link.ifindex,
			ni_addrconf_type_to_name(lease->type),
			ni_addrfamily_type_to_name(lease->family),
			ni_print_hex(uuid.octets, 16));
	if (!strcmp(signal_name, "LeaseAcquired")) {
		if (lease->state != NI_ADDRCONF_STATE_GRANTED) {
			ni_error("%s: unexpected lease state in signal %s", __func__, signal_name);
			goto done;
		}

		ifevent = NI_EVENT_ADDRESS_ACQUIRED;

		if (!__ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_DEFAULT_ROUTE)) {
			/* FIXME: remove any default routes from the lease */
		}
	} else if (!strcmp(signal_name, "LeaseReleased")) {
		lease->state = NI_ADDRCONF_STATE_RELEASED;
		ifevent = NI_EVENT_ADDRESS_RELEASED;
	} else if (!strcmp(signal_name, "LeaseLost")) {
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
	 * Note, lease may be NULL after this, as the interface object
	 * takes ownership of it.
	 */
	__ni_system_interface_update_lease(ifp, &lease);

	/* Potentially, there's a client somewhere waiting for that event.
	 * We use the UUID that's passed back and forth to make sure we
	 * really match the event we were expecting to match.
	 */
	ni_objectmodel_interface_event(NULL, ifp, ifevent, ni_uuid_is_null(&uuid)? NULL : &uuid);

done:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
	if (lease)
		ni_addrconf_lease_free(lease);
}

/*
 * Generic functions for static address configuration
 */
static dbus_bool_t
ni_objectmodel_addrconf_static_request(ni_dbus_object_t *object, int addrfamily,
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
				"requestLease: expected one dict argument");
		return FALSE;
	}
	dict = &argv[0];

	lease = ni_addrconf_lease_new(NI_ADDRCONF_STATIC, addrfamily);
	lease->state = NI_ADDRCONF_STATE_GRANTED;

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
				"Error configuring static %s addresses: %s",
				ni_addrfamily_type_to_name(addrfamily),
				ni_strerror(rv));
		return FALSE;
	}

	/* Don't return anything. */
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_addrconf_static_drop(ni_dbus_object_t *object, int addrfamily,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_addrconf_lease_t *lease = NULL;
	ni_interface_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_STATIC, addrfamily);
	lease->state = NI_ADDRCONF_STATE_RELEASED;

	rv = __ni_system_interface_update_lease(dev, &lease);
	if (lease)
		ni_addrconf_lease_free(lease);

	if (rv < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Error dropping static %s addresses: %s",
				ni_addrfamily_type_to_name(addrfamily),
				ni_strerror(rv));
		return FALSE;
	}

	/* Don't return anything */
	return TRUE;
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
			ni_interface_t *dev, const ni_dbus_variant_t *dict,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_uuid_t req_uuid;
	dbus_bool_t rv;

	/* Generate a uuid and assign an event ID */
	ni_uuid_generate(&req_uuid);

	if (ni_interface_get_lease(dev, forwarder->addrfamily, forwarder->addrconf) == NULL) {
		ni_addrconf_lease_t *lease;

		lease = ni_addrconf_lease_new(forwarder->addrconf, forwarder->addrfamily);
		lease->state = NI_ADDRCONF_STATE_REQUESTING;
		lease->uuid = req_uuid;
		ni_interface_set_lease(dev, lease);
	}

	rv = ni_objectmodel_addrconf_forwarder_call(forwarder, dev, "acquire", &req_uuid, dict, error);
	if (rv) {
		/* Tell the client to wait for an addressAcquired event with the given uuid */
		rv =  __ni_objectmodel_return_callback_info(reply, NI_EVENT_ADDRESS_ACQUIRED, &req_uuid, error);
	}
	return rv;
}

/*
 * Forward an addrconf drop call to a supplicant service, such as DHCP or zeroconf
 */
static dbus_bool_t
ni_objectmodel_addrconf_forward_release(ni_dbus_addrconf_forwarder_t *forwarder,
			ni_interface_t *dev, const ni_dbus_variant_t *dict,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_addrconf_lease_t *lease;
	dbus_bool_t rv;

	/* If we have no lease, neither pending nor granted, there's nothing we need to do.
	 */
	if ((lease = ni_interface_get_lease(dev, forwarder->addrfamily, forwarder->addrconf)) == NULL)
		return TRUE;

	rv = ni_objectmodel_addrconf_forwarder_call(forwarder, dev, "drop", &lease->uuid, NULL, error);
	if (rv
	 && (lease = ni_interface_get_lease(dev, forwarder->addrfamily, forwarder->addrconf)) != NULL) {
		/* Tell the client to wait for an addressAcquired event with the given uuid */
		rv =  __ni_objectmodel_return_callback_info(reply, NI_EVENT_ADDRESS_RELEASED, &lease->uuid, error);
	}
	return rv;
}

/*
 * Create client handle for addrconf forwarder
 */
static dbus_bool_t
ni_objectmodel_addrconf_forwarder_call(ni_dbus_addrconf_forwarder_t *forwarder,
				ni_interface_t *dev, const char *method_name,
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
			dbus_set_error(error, "unable to create call forwarder for %s",
					forwarder->supplicant.bus_name);
			return FALSE;
		}

		ni_dbus_client_add_signal_handler(forwarder->supplicant.client, NULL, NULL,
				forwarder->supplicant.interface,
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

static dbus_bool_t
ni_objectmodel_addrconf_ipv4_dhcp_request(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: expected one dict argument",
				WICKED_DBUS_ADDRCONF_IPV4DHCP_INTERFACE, method->name);
		return FALSE;
	}

	return ni_objectmodel_addrconf_forward_request(&dhcp4_forwarder, dev, &argv[0], reply, error);
}

static dbus_bool_t
ni_objectmodel_addrconf_ipv4_dhcp_drop(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	return ni_objectmodel_addrconf_forward_release(&dhcp4_forwarder, dev, NULL, reply, error);
}

/*
 * Configure IPv4 addresses via IPv4ll
 */
static ni_dbus_addrconf_forwarder_t ipv4ll_forwarder = {
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

static dbus_bool_t
ni_objectmodel_addrconf_ipv4ll_request(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: expected one dict argument",
				WICKED_DBUS_ADDRCONF_IPV4AUTO_INTERFACE, method->name);
		return FALSE;
	}

	return ni_objectmodel_addrconf_forward_request(&ipv4ll_forwarder, dev, &argv[0], reply, error);
}

static dbus_bool_t
ni_objectmodel_addrconf_ipv4ll_drop(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	return ni_objectmodel_addrconf_forward_release(&ipv4ll_forwarder, dev, NULL, reply, error);
}

/*
 * Generic lease properties
 */
static dbus_bool_t
__ni_objectmodel_addrconf_generic_get_lease(const ni_dbus_object_t *object,
				ni_addrconf_mode_t mode, int addrfamily,
				ni_dbus_variant_t *dict,
				DBusError *error)
{
	ni_interface_t *dev;
	const ni_addrconf_lease_t *lease;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

#if 0
	NI_TRACE_ENTER_ARGS("dev=%s, af=%s, mode=%s", dev->name,
			ni_addrfamily_type_to_name(addrfamily),
			ni_addrconf_type_to_name(mode));
#endif
	if (!(lease = ni_interface_get_lease(dev, addrfamily, mode)))
		return TRUE;

	ni_dbus_dict_add_uint32(dict, "state", lease->state);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_addrconf_generic_set_lease(ni_dbus_object_t *object,
				ni_addrconf_mode_t mode, int addrfamily,
				const ni_dbus_variant_t *dict,
				DBusError *error)
{
	ni_interface_t *dev;
	uint32_t state;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (ni_dbus_dict_get_uint32(dict, "state", &state)) {
		ni_addrconf_lease_t *lease;

		lease = ni_addrconf_lease_new(mode, addrfamily);
		lease->state = state;
		ni_interface_set_lease(dev, lease);
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
__ni_objectmodel_addrconf_ipv4ll_get_lease(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_get_lease(object, NI_ADDRCONF_AUTOCONF, AF_INET, result, error);
}

static dbus_bool_t
__ni_objectmodel_addrconf_ipv4ll_set_lease(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_addrconf_generic_set_lease(object, NI_ADDRCONF_AUTOCONF, AF_INET, argument, error);
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

static ni_dbus_property_t		ni_objectmodel_addrconf_ipv4ll_properties[] = {
	__NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, lease, __ni_objectmodel_addrconf_ipv4ll, RO),
	{ NULL }
};

/*
 * Addrconf methods
 */
static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv4_static_methods[] = {
	{ "requestLease",	"a{sv}",		ni_objectmodel_addrconf_ipv4_static_request },
	{ "dropLease",		"",			ni_objectmodel_addrconf_ipv4_static_drop },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv6_static_methods[] = {
	{ "requestLease",	"a{sv}",		ni_objectmodel_addrconf_ipv6_static_request },
	{ "dropLease",		"",			ni_objectmodel_addrconf_ipv6_static_drop },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv4_dhcp_methods[] = {
	{ "requestLease",	"a{sv}",		ni_objectmodel_addrconf_ipv4_dhcp_request },
	{ "dropLease",		"",			ni_objectmodel_addrconf_ipv4_dhcp_drop },
	{ NULL }
};

static const ni_dbus_method_t		ni_objectmodel_addrconf_ipv4ll_methods[] = {
	{ "requestLease",	"a{sv}",		ni_objectmodel_addrconf_ipv4ll_request },
	{ "dropLease",		"",			ni_objectmodel_addrconf_ipv4ll_drop },
	{ NULL }
};

/*
 * IPv4 and IPv6 addrconf request service
 */
ni_dbus_service_t			ni_objectmodel_addrconf_ipv4_static_service = {
	.name		= WICKED_DBUS_ADDRCONF_IPV4STATIC_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv4_static_methods,
	.properties	= ni_objectmodel_addrconf_ipv4_static_properties,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv6_static_service = {
	.name		= WICKED_DBUS_ADDRCONF_IPV6STATIC_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv6_static_methods,
	.properties	= ni_objectmodel_addrconf_ipv6_static_properties,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv4_dhcp_service = {
	.name		= WICKED_DBUS_ADDRCONF_IPV4DHCP_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv4_dhcp_methods,
	.properties	= ni_objectmodel_addrconf_ipv4_dhcp_properties,
};

ni_dbus_service_t			ni_objectmodel_addrconf_ipv4ll_service = {
	.name		= WICKED_DBUS_ADDRCONF_IPV4AUTO_INTERFACE,
	.methods	= ni_objectmodel_addrconf_ipv4ll_methods,
	.properties	= ni_objectmodel_addrconf_ipv4ll_properties,
};

