/*
 * dbus encapsulation for network interfaces
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
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static ni_dbus_object_functions_t wicked_dbus_interface_functions;

extern const ni_dbus_service_t	wicked_dbus_interface_request_service; /* XXX */

/*
 * Build a dbus-object encapsulating a network device.
 * If @server is non-NULL, register the object with a canonical object path
 */
static ni_dbus_object_t *
__ni_objectmodel_build_interface_object(ni_dbus_server_t *server, ni_interface_t *ifp)
{
	ni_dbus_object_t *object;
	const ni_dbus_service_t *link_layer_service;

	if (server != NULL) {
		object = ni_dbus_server_register_object(server,
						ni_objectmodel_interface_path(ifp),
						&wicked_dbus_interface_functions,
						ni_interface_get(ifp));
	} else {
		object = ni_dbus_object_new(NULL,
						&wicked_dbus_interface_functions,
						ni_interface_get(ifp));
	}

	if (object == NULL)
		ni_fatal("Unable to create dbus object for interface %s", ifp->name);

	ni_dbus_object_register_service(object, &wicked_dbus_interface_service);

	link_layer_service = ni_objectmodel_link_layer_service(ifp->link.type);
	if (link_layer_service != NULL)
		ni_dbus_object_register_service(object, link_layer_service);

	return object;
}


/*
 * Register a network interface with our dbus server,
 * and add the appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_register_interface(ni_dbus_server_t *server, ni_interface_t *ifp)
{
	return __ni_objectmodel_build_interface_object(server, ifp);
}

/*
 * Unregister a network interface from our dbus server.
 */
dbus_bool_t
ni_objectmodel_unregister_interface(ni_dbus_server_t *server, ni_interface_t *ifp)
{
	if (ni_dbus_server_unregister_object(server, ifp)) {
		ni_debug_dbus("unregistered interface %s", ifp->name);
		return 1;
	}

	return 0;
}

/*
 * Return the canonical object path for an interface object
 */
const char *
ni_objectmodel_interface_path(const ni_interface_t *ifp)
{
	static char object_path[256];
	char sane_name[IFNAMSIZ+5], *sp;

	if (strlen(ifp->name) >= sizeof(sane_name))
		return NULL;
	strcpy(sane_name, ifp->name);
	for (sp = sane_name; *sp; ++sp) {
		if (*sp == '.')
			*sp = '_';
	}

	snprintf(object_path, sizeof(object_path), "Interface/%s", sane_name);
	return object_path;
}

/*
 * Build a dummy dbus object encapsulating a network interface,
 * and add the appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_wrap_interface(ni_interface_t *ifp)
{
	return __ni_objectmodel_build_interface_object(NULL, ifp);
}

ni_dbus_object_t *
ni_objectmodel_wrap_interface_request(ni_interface_request_t *req)
{
	return ni_dbus_object_new(NULL, NULL, req);
}

/*
 * Based on the network link layer type, return the DBus service implementing this
 */
const ni_dbus_service_t *
ni_objectmodel_link_layer_service(int iftype)
{
	switch (iftype) {
	case NI_IFTYPE_ETHERNET:
		return &wicked_dbus_ethernet_service;
		break;

	case NI_IFTYPE_VLAN:
		return &wicked_dbus_vlan_service;
		break;

	case NI_IFTYPE_BRIDGE:
		return &wicked_dbus_bridge_service;
		break;

	case NI_IFTYPE_BOND:
		return &wicked_dbus_bond_service;
		break;

	default: ;
	}

	return NULL;
}

/*
 * Based on the network link layer type, return the DBus dummy service
 * describing the port properties
 */
const ni_dbus_service_t *
ni_objectmodel_interface_port_service(int iftype)
{
	switch (iftype) {
	case NI_IFTYPE_BRIDGE:
		return &wicked_dbus_bridge_port_dummy_service;
		break;

	default: ;
	}

	return NULL;
}

/*
 * Create a new virtual interface (vlan, bridge, bond, ...)
 */
ni_dbus_object_t *
ni_objectmodel_new_interface(ni_dbus_server_t *server, const ni_dbus_service_t *service,
			const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_object_t *object = NULL, *result = NULL;
	ni_interface_t *ifp = NULL;
	const char *ifname = NULL;

	if (!ni_dbus_variant_is_dict(dict))
		goto bad_args;

	if (ni_dbus_dict_get_string(dict, "name", &ifname)) {
		ni_netconfig_t *nc = ni_global_state_handle(0);

		if (ni_interface_by_name(nc, ifname)) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot create interface %s - already exists", ifname);
			goto error;
		}
	}

	ifp = __ni_interface_new(ifname, 0);
	if (!ifp) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Internal error - cannot create network interface");
		return NULL;
	}

	/* Hack: we shouldn't modify a const dict */
	ni_dbus_dict_delete_entry((ni_dbus_variant_t *) dict, "name");

	object = ni_dbus_object_new(NULL, &wicked_dbus_interface_functions, ifp);
	ni_dbus_object_register_service(object, &wicked_dbus_interface_service);
	ni_dbus_object_register_service(object, service);

	/* Set up the interface description */
	if (!ni_dbus_object_set_properties_from_dict(object, service, dict)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Unable to extract interface definition from arguments");
		goto error;
	}

	if (service == &wicked_dbus_vlan_service) {
		result = ni_objectmodel_new_vlan(server, object, error);
	} else
	if (service == &wicked_dbus_bridge_service) {
		result = ni_objectmodel_new_bridge(server, object, error);
	} else
	if (service == &wicked_dbus_bond_service) {
		result = ni_objectmodel_new_bond(server, object, error);
	} else {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot create network interface for %s - not implemented yet",
				service->name);
		goto error;
	}

	if (result == NULL && !dbus_error_is_set(error)) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create interface");
	}

	ni_dbus_object_free(object);
	object = NULL;

	ni_interface_put(ifp);
	return result;

bad_args:
	dbus_set_error(error, DBUS_ERROR_FAILED,
			"Bad argument in call to Interface.create()");

error:
	if (object)
		ni_dbus_object_free(object);
	if (ifp)
		ni_interface_put(ifp);
	return NULL;
}

/*
 * Interface.up(dict options)
 * Bring up the network interface, and assign the requested addresses.
 * In the case of virtual interfaces like VLANs or bridges, the interface
 * must have been created and configured prior to this call.
 *
 * The options dictionary contains interface properties.
 */
static dbus_bool_t
__wicked_dbus_interface_up(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_interface_t *dev = object->handle;
	ni_dbus_object_t *cfg_object;
	ni_interface_request_t *req;
	dbus_bool_t ret = FALSE;
	int rv;

	NI_TRACE_ENTER_ARGS("ifp=%s", dev->name);

	/* Build a dummy object for the configuration data */
	req = ni_interface_request_new();
	req->ifflags = NI_IFF_NETWORK_UP | NI_IFF_LINK_UP | NI_IFF_DEVICE_UP;

	cfg_object = ni_dbus_object_new(NULL, NULL, req);

	/* Extract configuration from dict */
	if (!ni_dbus_object_set_properties_from_dict(cfg_object, &wicked_dbus_interface_request_service, &argv[0])) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Cannot extract interface configuration from property dict");
		goto failed;
	}

	if ((rv = ni_system_interface_up(nc, dev, req)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot configure interface %s: %s", dev->name,
				ni_strerror(rv));
		goto failed;
	}

	ret = TRUE;

failed:
	ni_interface_request_free(req);
	if (cfg_object)
		ni_dbus_object_free(cfg_object);
	return ret;
}

/*
 * Interface.down(void)
 * Bring down the network interface.
 *
 * The options dictionary contains interface properties.
 */
static dbus_bool_t
__wicked_dbus_interface_down(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_interface_t *dev = object->handle;
	dbus_bool_t ret = FALSE;
	int rv;

	NI_TRACE_ENTER_ARGS("ifp=%s", dev->name);

	if ((rv = ni_system_interface_down(nc, dev)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot shutdown interface %s: %s", dev->name,
				ni_strerror(rv));
		goto failed;
	}

	ret = TRUE;

failed:
	return ret;
}

/*
 * The DBus object is destroyed; detach the network interface handle
 */
static void
wicked_dbus_interface_destroy(ni_dbus_object_t *object)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_assert(ifp);
	ni_interface_put(ifp);
}

static ni_dbus_object_functions_t wicked_dbus_interface_functions = {
	.destroy	= wicked_dbus_interface_destroy,
};

static ni_dbus_method_t		wicked_dbus_interface_methods[] = {
	{ "up",			"a{sv}",		__wicked_dbus_interface_up },
	{ "down",		"",			__wicked_dbus_interface_down },
#if 0
	{ "addAddress",		"a{sv}",		__wicked_dbus_interface_add_address },
	{ "removeAddress",	"a{sv}",		__wicked_dbus_interface_remove_address },
	{ "addRoute",		"a{sv}",		__wicked_dbus_interface_add_route },
	{ "removeRoute",	"a{sv}",		__wicked_dbus_interface_remove_route },
#endif
	{ NULL }
};

/*
 * Interface property handlers
 */
#define NULL_interface		((ni_interface_t *) NULL)

/*
 * Property name
 */
static dbus_bool_t
__wicked_dbus_interface_get_name(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_string(result, ifp->name);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_set_name(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;
	ni_string_dup(&ifp->name, value);
	return TRUE;
}

/*
 * property name
 */
static dbus_bool_t
__wicked_dbus_interface_get_type(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_get_property_uint(
			ni_dbus_object_get_handle(object),
			&NULL_interface->link.type, result);
}

static dbus_bool_t
__wicked_dbus_interface_set_type(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(
			ni_dbus_object_get_handle(object),
			&NULL_interface->link.type, argument);
}

/*
 * property Interface.ifflags
 */
static dbus_bool_t
__wicked_dbus_interface_get_ifflags(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_get_property_uint(
			ni_dbus_object_get_handle(object),
			&NULL_interface->link.ifflags, result);
}

static dbus_bool_t
__wicked_dbus_interface_set_ifflags(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(
			ni_dbus_object_get_handle(object),
			&NULL_interface->link.ifflags, argument);
}

/*
 * property Interface.mtu
 */
static dbus_bool_t
__wicked_dbus_interface_get_mtu(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	return __ni_objectmodel_get_property_uint(
			ni_dbus_object_get_handle(object),
			&NULL_interface->link.mtu, result);
}

static dbus_bool_t
__wicked_dbus_interface_set_mtu(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(
			ni_dbus_object_get_handle(object),
			&NULL_interface->link.mtu, argument);
}

static dbus_bool_t
__wicked_dbus_interface_update_mtu(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	uint32_t value;

	if (!ni_dbus_variant_get_uint32(argument, &value))
		return FALSE;
#if 0
	if (!ni_interface_update_mtu(ifp, mtu))
		return FALSE;
#else
	ni_warn("%s not yet implemented", __FUNCTION__);
#endif
	ifp->link.mtu = value;
	return TRUE;
}

/*
 * Property Interface.hwaddr
 */
static dbus_bool_t
__wicked_dbus_interface_get_hwaddr(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_byte_array(result, ifp->link.hwaddr.data, ifp->link.hwaddr.len);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_set_hwaddr(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	unsigned int addrlen;

	ifp->link.hwaddr.type = ifp->link.type;
	if (!ni_dbus_variant_get_byte_array_minmax(argument,
				ifp->link.hwaddr.data, &addrlen,
				0, sizeof(ifp->link.hwaddr.data)))
		return FALSE;
	ifp->link.hwaddr.len = addrlen;
	return TRUE;
}

/* FIXME: need function to update hwaddr */

/*
 * Helper functions for getting and setting socket addresses
 */
static inline dbus_bool_t
__wicked_dbus_add_sockaddr(ni_dbus_variant_t *dict, const char *name, const ni_sockaddr_t *ss)
{
	const unsigned char *adata;
	unsigned int offset, len;

	if (!__ni_address_info(ss->ss_family, &offset, &len))
		return FALSE;

	adata = ((const unsigned char *) ss) + offset;
	return ni_dbus_dict_add_byte_array(dict, name, adata, len);
}

static inline dbus_bool_t
__wicked_dbus_get_sockaddr(const ni_dbus_variant_t *dict, const char *name, ni_sockaddr_t *ss, int af)
{
	const ni_dbus_variant_t *var;
	unsigned int offset, len;
	unsigned int alen;

	if (!(var = ni_dbus_dict_get(dict, name)))
		return FALSE;

	if (!__ni_address_info(af, &offset, &len))
		return FALSE;

	memset(ss, 0, sizeof(*ss));
	ss->ss_family = af;
	return ni_dbus_variant_get_byte_array_minmax(var,
			((unsigned char *) ss) + offset, &alen,
			len, len);
}

/*
 * Property Interface.addrs
 * This one is rather complex
 */
static dbus_bool_t
__wicked_dbus_interface_get_addrs(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_dict_array_init(result);
	return __wicked_dbus_get_address_list(ifp->addrs, result, error);
}

static dbus_bool_t
__wicked_dbus_interface_set_addrs(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	return __wicked_dbus_set_address_list(&ifp->addrs, argument, error);
}

/*
 * Property Interface.routes
 * This one is rather complex, too.
 */
static dbus_bool_t
__wicked_dbus_interface_get_routes(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_dict_array_init(result);
	return __wicked_dbus_get_route_list(ifp->routes, result, error);
}

static dbus_bool_t
__wicked_dbus_interface_set_routes(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	return __wicked_dbus_set_route_list(&ifp->routes, argument, error);
}

#define WICKED_INTERFACE_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name,__wicked_dbus_interface, rw)
#define WICKED_INTERFACE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_interface, rw)

static ni_dbus_property_t	wicked_dbus_interface_properties[] = {
	WICKED_INTERFACE_PROPERTY(STRING, name, RO),
	WICKED_INTERFACE_PROPERTY(UINT32, ifflags, RO),
	WICKED_INTERFACE_PROPERTY(UINT32, type, RO),
	WICKED_INTERFACE_PROPERTY(UINT32, mtu, RW),
	WICKED_INTERFACE_PROPERTY_SIGNATURE(
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			hwaddr, RO),

	/* addresses is an array of dicts */
	WICKED_INTERFACE_PROPERTY_SIGNATURE(
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
			addrs, RO),

	WICKED_INTERFACE_PROPERTY_SIGNATURE(
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
			routes, RO),
	{ NULL }
};

const ni_dbus_service_t	wicked_dbus_interface_service = {
	.name = WICKED_DBUS_NETIF_INTERFACE,
	.methods = wicked_dbus_interface_methods,
	.properties = wicked_dbus_interface_properties,
};

/*
 * a dbus dict object expects the "key" strings to be static, and does
 * not dup them. So we cannot use a string buffer on the heap to build
 * "foobar-request" and "foobar-lease" strings.
 */
static const char *
__wicked_addrconf_type_string(unsigned int mode, int req)
{
	static char string[2][__NI_ADDRCONF_MAX][128];
	unsigned int rq = req? 1 : 0;

	if (string[rq][mode][0] == '\0') {
		const char *acname = ni_addrconf_type_to_name(mode);

		if (acname == NULL)
			return NULL;
		snprintf(string[rq][mode], sizeof(string[rq][mode]),
					"%s-%s", acname, req? "request" : "lease");
	}
	return string[rq][mode];
}

/*
 * These helper functions assist in marshalling InterfaceRequests
 */
static dbus_bool_t
__wicked_dbus_get_afinfo(const ni_afinfo_t *afi, dbus_bool_t request_only,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	unsigned int i;

	if (!afi->enabled)
		return TRUE;
	ni_dbus_dict_add_bool(result, "forwarding", !!afi->forwarding);

	for (i = 0; i < __NI_ADDRCONF_MAX; ++i) {
		ni_addrconf_request_t *req;
		ni_addrconf_lease_t *lease;
		ni_dbus_variant_t *dict;
		const char *rqname, *lsname;

		rqname = __wicked_addrconf_type_string(i, 1);
		lsname = __wicked_addrconf_type_string(i, 0);
		if (!rqname || !lsname)
			continue;

		if ((req = afi->request[i]) != NULL) {
			dict = ni_dbus_dict_add(result, rqname);
			ni_dbus_variant_init_dict(dict);
			if (!__wicked_dbus_get_addrconf_request(req, dict, error))
				return FALSE;
		}
		if (request_only)
			continue;

		if ((lease = afi->lease[i]) != NULL) {
			dict = ni_dbus_dict_add(result, lsname);

			ni_dbus_variant_init_dict(dict);
			if (!__wicked_dbus_get_addrconf_lease(lease, dict, error))
				return FALSE;
		}
	}
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_set_afinfo(ni_afinfo_t *afi,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	dbus_bool_t bool_value;
	unsigned int i;

	afi->enabled = 1;
	afi->addrconf = 0;
	if (ni_dbus_dict_get_bool(argument, "forwarding", &bool_value))
		afi->forwarding = bool_value;

	for (i = 0; i < __NI_ADDRCONF_MAX; ++i) {
		const ni_dbus_variant_t *dict;
		const char *rqname, *lsname;

		rqname = __wicked_addrconf_type_string(i, 1);
		lsname = __wicked_addrconf_type_string(i, 0);
		if (!rqname || !lsname)
			continue;

		dict = ni_dbus_dict_get(argument, rqname);
		if (dict != NULL) {
			ni_addrconf_request_t *req = ni_addrconf_request_new(i, afi->family);

			__ni_afinfo_set_addrconf_request(afi, i, req);

			if (!__wicked_dbus_set_addrconf_request(req, dict, error))
				return FALSE;

			ni_afinfo_addrconf_enable(afi, i);
		}

		dict = ni_dbus_dict_get(argument, lsname);
		if (dict != NULL) {
			ni_addrconf_lease_t *lease = ni_addrconf_lease_new(i, afi->family);

			__ni_afinfo_set_addrconf_lease(afi, i, lease);
			if (!__wicked_dbus_set_addrconf_lease(lease, dict, error))
				return FALSE;
		}
	}
	return TRUE;
}

/*
 * Property InterfaceRequest.ipv4
 */
static dbus_bool_t
__wicked_dbus_interface_request_get_ipv4(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_request_t *req = ni_dbus_object_get_handle(object);

	ni_dbus_variant_init_dict(result);
	if (req->ipv4 && !__wicked_dbus_get_afinfo(req->ipv4, TRUE, result, error))
		return FALSE;
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_request_set_ipv4(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_request_t *req = ni_dbus_object_get_handle(object);

	if (!req->ipv4)
		req->ipv4 = ni_afinfo_new(AF_INET);
	if (!__wicked_dbus_set_afinfo(req->ipv4, argument, error))
		return FALSE;
	return TRUE;
}

/*
 * Property InterfaceRequest.ipv6
 */
static dbus_bool_t
__wicked_dbus_interface_request_get_ipv6(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_request_t *req = ni_dbus_object_get_handle(object);

	if (req->ipv6 && !__wicked_dbus_get_afinfo(req->ipv6, TRUE, result, error))
		return FALSE;
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_request_set_ipv6(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_request_t *req = ni_dbus_object_get_handle(object);

	if (!req->ipv6)
		req->ipv6 = ni_afinfo_new(AF_INET6);
	if (!__wicked_dbus_set_afinfo(req->ipv6, argument, error))
		return FALSE;
	return TRUE;
}

#define WICKED_INTERFACE_REQUEST_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __wicked_dbus_interface_request, rw)
#define WICKED_INTERFACE_REQUEST_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_interface_request, rw)

static ni_dbus_property_t	wicked_dbus_interface_request_properties[] = {
#if 0
	WICKED_INTERFACE_REQUEST_PROPERTY(UINT32, ifflags, RO),
	WICKED_INTERFACE_REQUEST_PROPERTY(UINT32, mtu, RO),
#endif

	WICKED_INTERFACE_REQUEST_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv4, RO),
	WICKED_INTERFACE_REQUEST_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv6, RO),
	{ NULL }
};

#define WICKED_DBUS_NETIF_REQUEST_INTERFACE WICKED_DBUS_NETIF_INTERFACE "Request"

const ni_dbus_service_t	wicked_dbus_interface_request_service = {
	.name = WICKED_DBUS_NETIF_REQUEST_INTERFACE,
	.properties = wicked_dbus_interface_request_properties,
};
