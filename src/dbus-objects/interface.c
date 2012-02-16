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

static void		ni_objectmodel_netif_destroy(ni_dbus_object_t *object);

static ni_dbus_class_t		ni_objectmodel_netif_class = {
	.name		= NI_OBJECTMODEL_NETIF_CLASS,
	.destroy	= ni_objectmodel_netif_destroy,
};
static ni_dbus_class_t		ni_objectmodel_ifreq_class = {
	.name		= NI_OBJECTMODEL_NETIF_REQUEST_CLASS,
};

static const ni_dbus_service_t	wicked_dbus_interface_service;
extern const ni_dbus_service_t	wicked_dbus_interface_request_service; /* XXX */

/*
 * For all link layer types, create a dbus object class named "netif-$linktype".
 * This allows to define extensions and interface for specific link layers.
 */
void
ni_objectmodel_register_netif_classes(void)
{
	const ni_dbus_class_t *base_class = &ni_objectmodel_netif_class;
	ni_dbus_class_t *link_class;
	unsigned int iftype;

	/* register the netif class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(base_class);

	/* register the netif interface */
	ni_objectmodel_register_service(&wicked_dbus_interface_service);

	for (iftype = 0; iftype < __NI_IFTYPE_MAX; ++iftype) {
		const char *classname;

		if (!(classname = ni_objectmodel_link_classname(iftype)))
			continue;

		/* Create the new link class */
		link_class = xcalloc(1, sizeof(*link_class));
		ni_string_dup(&link_class->name, classname);
		link_class->superclass = base_class;

		/* inherit all methods from netif */
		link_class->init_child = base_class->init_child;
		link_class->destroy = base_class->destroy;
		link_class->refresh = base_class->refresh;

		/* Register this class */
		ni_objectmodel_register_class(link_class);
	}
}

/*
 * For a given link type, return a canonical class name
 */
const char *
ni_objectmodel_link_classname(ni_iftype_t link_type)
{
	const char *link_type_name;
	static char namebuf[128];

	if (link_type == NI_IFTYPE_UNKNOWN)
		return NULL;

	if (!(link_type_name = ni_linktype_type_to_name(link_type)))
		return NULL;

	snprintf(namebuf, sizeof(namebuf), "netif-%s", link_type_name);
	return namebuf;
}

/*
 * Build a dbus-object encapsulating a network device.
 * If @server is non-NULL, register the object with a canonical object path
 */
static ni_dbus_object_t *
__ni_objectmodel_build_interface_object(ni_dbus_server_t *server, ni_interface_t *ifp)
{
	const char *classname;
	const ni_dbus_class_t *class = NULL;
	ni_dbus_object_t *object;

	if ((classname = ni_objectmodel_link_classname(ifp->link.type)) != NULL)
		class = ni_objectmodel_get_class(classname);
	if (class == NULL)
		class = &ni_objectmodel_netif_class;

	if (server != NULL) {
		object = ni_dbus_server_register_object(server,
						ni_objectmodel_interface_path(ifp),
						class, ni_interface_get(ifp));
	} else {
		object = ni_dbus_object_new(class, NULL, ni_interface_get(ifp));
	}

	if (object == NULL)
		ni_fatal("Unable to create dbus object for interface %s", ifp->name);

	ni_objectmodel_bind_compatible_interfaces(object);
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

	snprintf(object_path, sizeof(object_path), "Interface/%u", ifp->link.ifindex);
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
	return ni_dbus_object_new(&ni_objectmodel_ifreq_class, NULL, req);
}

ni_interface_t *
ni_objectmodel_unwrap_interface(const ni_dbus_object_t *object)
{
	ni_interface_t *dev = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_netif_class))
		return dev;
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
	ni_interface_t *dev = ni_objectmodel_unwrap_interface(object);
	ni_dbus_object_t *cfg_object;
	ni_interface_request_t *req;
	dbus_bool_t ret = FALSE;
	int rv;

	NI_TRACE_ENTER_ARGS("ifp=%s", dev->name);

	/* Create an interface_request object and wrap it in a dbus object */
	req = ni_interface_request_new();
	cfg_object = ni_objectmodel_wrap_interface_request(req);

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

	if (__ni_interface_is_up(dev))
		ni_objectmodel_interface_event(object, "InterfaceUp");

	ret = TRUE;

failed:
	ni_interface_request_free(req);
	if (cfg_object)
		ni_dbus_object_free(cfg_object);
	return ret;
}

/*
 * Broadcast an event that the interface is up
 */
dbus_bool_t
ni_objectmodel_interface_event(ni_dbus_object_t *object, const char *signal_name)
{
	ni_dbus_server_t *server;

	if (!(server = ni_dbus_object_get_server(object))
	 && !(server = __ni_objectmodel_server)) {
		ni_error("%s: help! No dbus server handle! Cannot send signal.", __func__);
		return FALSE;
	}

	ni_debug_dbus("sending interface event \"%s\" for %s", signal_name, ni_dbus_object_get_path(object));
	ni_dbus_server_send_signal(server, object, WICKED_DBUS_NETIF_INTERFACE, signal_name, 0, NULL);
	return TRUE;
}

dbus_bool_t
__ni_objectmodel_interface_event(ni_interface_t *dev, const char *signal_name)
{
	ni_dbus_object_t *object;
	
	object = ni_dbus_server_find_object_by_handle(__ni_objectmodel_server, dev);
	if (object != NULL) {
		return ni_objectmodel_interface_event(object, signal_name);
	}

	ni_warn("unable to find dbus object for interface %s. Cannot send signal \"%s\".",
			dev->name, signal_name);
	return FALSE;
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
	ni_interface_t *dev = ni_objectmodel_unwrap_interface(object);
	dbus_bool_t ret = FALSE;
	int rv;

	NI_TRACE_ENTER_ARGS("ifp=%s", dev->name);

	if ((rv = ni_system_interface_down(nc, dev)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot shutdown interface %s: %s", dev->name,
				ni_strerror(rv));
		goto failed;
	}

	if (__ni_interface_is_down(dev))
		ni_objectmodel_interface_event(object, "InterfaceDown");

	ret = TRUE;

failed:
	return ret;
}

/*
 * The DBus object is destroyed; detach the network interface handle
 */
static void
ni_objectmodel_netif_destroy(ni_dbus_object_t *object)
{
	ni_interface_t *ifp = ni_objectmodel_unwrap_interface(object);

	NI_TRACE_ENTER_ARGS("object=%s, dev=%p", object->path, ifp);
	ni_assert(ifp);
	ni_interface_put(ifp);
}

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
static void *
ni_objectmodel_get_interface(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_unwrap_interface(object);
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
#define INTERFACE_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(interface, dbus_name, member_name, rw)
#define INTERFACE_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(interface, dbus_name, member_name, rw)

static ni_dbus_property_t	wicked_dbus_interface_properties[] = {
	INTERFACE_STRING_PROPERTY(name, name, RO),
	INTERFACE_UINT_PROPERTY(ifindex, link.ifindex, RO),
	INTERFACE_UINT_PROPERTY(flags, link.ifflags, RO),
	INTERFACE_UINT_PROPERTY(type, link.type, RO),
	INTERFACE_UINT_PROPERTY(mtu, link.mtu, RO),
	INTERFACE_UINT_PROPERTY(txqlen, link.txqlen, RO),
	WICKED_INTERFACE_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			hwaddr, RO),

	/* addresses and routes is an array of dicts */
	WICKED_INTERFACE_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE,
			addrs, RO),

	WICKED_INTERFACE_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE,
			routes, RO),
	{ NULL }
};

static const ni_dbus_service_t	wicked_dbus_interface_service = {
	.name		= WICKED_DBUS_NETIF_INTERFACE,
	.compatible	= &ni_objectmodel_netif_class,
	.methods	= wicked_dbus_interface_methods,
	.properties	= wicked_dbus_interface_properties,
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
static void *
ni_objectmodel_get_interface_request(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_dbus_object_get_handle(object);
}

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

#define INTERFACE_REQUEST_UINT_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(interface_request, dbus_name, name, rw)
#define INTERFACE_REQUEST_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_interface_request, rw)

static ni_dbus_property_t	wicked_dbus_interface_request_properties[] = {
	INTERFACE_REQUEST_UINT_PROPERTY(flags, ifflags, RO),
	INTERFACE_REQUEST_UINT_PROPERTY(mtu, mtu, RO),
	INTERFACE_REQUEST_UINT_PROPERTY(metric, metric, RO),
	INTERFACE_REQUEST_UINT_PROPERTY(txqlen, txqlen, RO),

	INTERFACE_REQUEST_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv4, RO),
	INTERFACE_REQUEST_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv6, RO),
	{ NULL }
};

#define WICKED_DBUS_NETIF_REQUEST_INTERFACE WICKED_DBUS_NETIF_INTERFACE "Request"

const ni_dbus_service_t	wicked_dbus_interface_request_service = {
	.name		= WICKED_DBUS_NETIF_REQUEST_INTERFACE,
	.compatible	= &ni_objectmodel_ifreq_class,
	.properties	= wicked_dbus_interface_request_properties,
};
