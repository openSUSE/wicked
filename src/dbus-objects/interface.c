/*
 * DBus encapsulation for network interfaces
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
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

extern dbus_bool_t	ni_objectmodel_netif_list_refresh(ni_dbus_object_t *);
static void		ni_objectmodel_netif_destroy(ni_dbus_object_t *object);

static ni_dbus_class_t		ni_objectmodel_netif_class = {
	.name		= NI_OBJECTMODEL_NETIF_CLASS,
	.destroy	= ni_objectmodel_netif_destroy,
};
static ni_dbus_class_t		ni_objectmodel_ifreq_class = {
	.name		= NI_OBJECTMODEL_NETIF_REQUEST_CLASS,
};

static const ni_dbus_class_t	ni_objectmodel_netif_list_class;
static ni_dbus_service_t	ni_objectmodel_netif_list_service;
static ni_dbus_service_t	ni_objectmodel_netif_service;
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv4_static_service;
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv6_static_service;
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv4_dhcp_service;
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv4ll_service;
static ni_dbus_property_t	ni_objectmodel_netif_request_properties[];

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

	/* register the netif-list class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(&ni_objectmodel_netif_list_class);

	/* register the netif class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(base_class);

	/* register the netif interface */
	ni_objectmodel_register_service(&ni_objectmodel_netif_service);

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

	ni_objectmodel_register_service(&ni_objectmodel_netif_list_service);

	/* register our built-in addrconf services */
	ni_objectmodel_addrconf_ipv4_static_service.compatible = &ni_objectmodel_netif_class;
	ni_objectmodel_register_service(&ni_objectmodel_addrconf_ipv4_static_service);

	ni_objectmodel_addrconf_ipv6_static_service.compatible = &ni_objectmodel_netif_class;
	ni_objectmodel_register_service(&ni_objectmodel_addrconf_ipv6_static_service);

	ni_objectmodel_addrconf_ipv4_dhcp_service.compatible = &ni_objectmodel_netif_class;
	ni_objectmodel_register_service(&ni_objectmodel_addrconf_ipv4_dhcp_service);

	ni_objectmodel_addrconf_ipv4ll_service.compatible = &ni_objectmodel_netif_class;
	ni_objectmodel_register_service(&ni_objectmodel_addrconf_ipv4ll_service);
}

/*
 * netif list class
 */
void
ni_objectmodel_create_netif_list(ni_dbus_server_t *server)
{
	ni_dbus_object_t *object;

	/* Register com.suse.Wicked.Interface, which is the list of all interfaces */
	object = ni_dbus_server_register_object(server, "Interface",
					&ni_objectmodel_netif_list_class,
					NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	ni_objectmodel_bind_compatible_interfaces(object);
}


/*
 * The init_child method is needed by the client side when GetManagedObjects
 * returns an interface we haven't heard of before.
 * FIXME: We should really clean this up and use this callback exclusively from
 * GetManagedObjects, to avoid any bad side effects.
 */
static dbus_bool_t
ni_objectmodel_netif_list_init_child(ni_dbus_object_t *object)
{
	static const ni_dbus_class_t *netif_class = NULL;
	ni_interface_t *ifp;

	if (netif_class == NULL) {
		const ni_dbus_service_t *netif_service;

		netif_service = ni_objectmodel_service_by_name(WICKED_DBUS_NETIF_INTERFACE);
		ni_assert(netif_service);

		netif_class = netif_service->compatible;
	}

	ifp = ni_interface_new(NULL, NULL, 0);
	object->class = netif_class;
	object->handle = ifp;

	return TRUE;
}

static const ni_dbus_class_t	ni_objectmodel_netif_list_class = {
	.name		= NI_OBJECTMODEL_NETIF_LIST_CLASS,
	.refresh	= ni_objectmodel_netif_list_refresh,
	.init_child	= ni_objectmodel_netif_list_init_child,
};

/*
 * Refresh the netif list
 * This function is called from the dbus object handling code prior
 * to invoking any method of this object.
 *
 * GetManagedObject relies on this - without this, we'd never
 * refresh the interface properties.
 * Note that this still doesn't fix things when calling GetManagedObjects
 * or GetAllProperties on a netif object directly; we haven't assigned
 * refresh handlers to these.
 */
dbus_bool_t
ni_objectmodel_netif_list_refresh(ni_dbus_object_t *object)
{
	ni_netconfig_t *nc;

	NI_TRACE_ENTER();
	if (!(nc = ni_global_state_handle(1))) {
		ni_error("failed to refresh network interfaces");
		return FALSE;
	}

	/* Note, we do not have to deal with removal of interfaces
	 * that have been destroyed. We should be notified of these
	 * automatically via RTM_DELLINK */

	return TRUE;
}


static ni_dbus_service_t	ni_objectmodel_netif_list_service = {
	.name		= WICKED_DBUS_NETIFLIST_INTERFACE,
	.compatible	= &ni_objectmodel_netif_list_class,
};

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
ni_objectmodel_unwrap_interface(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *dev = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_netif_class))
		return dev;
	if (error)
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"method not compatible with object %s of class %s (not a network interface)",
				object->path, object->class->name);
	return NULL;
}

/*
 * Helper functions to extract all properties from a dict argument
 */
static dbus_bool_t
get_properties_from_dict(const ni_dbus_service_t *service, void *handle, const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_object_t dummy;

	memset(&dummy, 0, sizeof(dummy));
	dummy.class = service->compatible;
	dummy.handle = handle;

	if (!ni_dbus_object_set_properties_from_dict(&dummy, service, dict)) {
		if (error)
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "Cannot extract argument from property dict");
		return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
put_properties_to_dict(const ni_dbus_service_t *service, const void *handle, ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_object_t dummy;

	memset(&dummy, 0, sizeof(dummy));
	dummy.class = service->compatible;
	dummy.handle = (void *) handle;

	ni_dbus_variant_init_dict(dict);
	if (!ni_dbus_object_get_properties_as_dict(&dummy, service, dict)) {
		if (error)
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "Cannot encode argument as property dict");
		return FALSE;
	}

	return TRUE;
}

static ni_dbus_service_t	ni_objectmodel_netifreq_service = {
	.name		= WICKED_DBUS_NETIF_INTERFACE "Request",
	.compatible	= &ni_objectmodel_ifreq_class,
	.properties	= ni_objectmodel_netif_request_properties,
};


dbus_bool_t
ni_objectmodel_marshal_interface_request(const ni_interface_request_t *req, ni_dbus_variant_t *dict, DBusError *error)
{
	return put_properties_to_dict(&ni_objectmodel_netifreq_service, req, dict, error);
}

dbus_bool_t
ni_objectmodel_unmarshal_interface_request(ni_interface_request_t *req, const ni_dbus_variant_t *dict, DBusError *error)
{
	return get_properties_from_dict(&ni_objectmodel_netifreq_service, req, dict, error);
}

/*
 * Interface.linkChange(dict options)
 *
 * Bring up the network interface, and assign the requested addresses.
 * In the case of virtual interfaces like VLANs or bridges, the interface
 * must have been created and configured prior to this call.
 *
 * The options dictionary contains interface properties.
 */
static dbus_bool_t
ni_objectmodel_netif_link_change(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_interface_t *dev;
	ni_interface_request_t *req = NULL;
	dbus_bool_t ret = FALSE;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("ifp=%s", dev->name);

	/* Create an interface_request object and extract configuration from dict */
	req = ni_interface_request_new();
	if (!ni_objectmodel_unmarshal_interface_request(req, &argv[0], error))
		goto failed;

	if ((rv = ni_system_interface_link_change(nc, dev, req)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot configure interface %s: %s", dev->name,
				ni_strerror(rv));
	} else {
		ni_dbus_message_append_uint32(reply, dev->link.ifflags);

		if (ni_interface_link_is_up(dev))
			__ni_objectmodel_interface_event(NULL, object, NI_EVENT_LINK_UP, 0);

		ret = TRUE;
	}

failed:
	if (req)
		ni_interface_request_free(req);
	return ret;
}

/*
 * Broadcast an interface event
 * The optional uuid argument helps the client match e.g. notifications
 * from an addrconf service against its current state.
 */
dbus_bool_t
ni_objectmodel_interface_event(ni_dbus_server_t *server, ni_interface_t *dev,
			ni_event_t ifevent, const ni_uuid_t *uuid)
{
	ni_dbus_object_t *object;

	if (ifevent >= __NI_EVENT_MAX)
		return FALSE;

	if (!server && !(server = __ni_objectmodel_server)) {
		ni_error("%s: help! No dbus server handle! Cannot send signal.", __func__);
		return FALSE;
	}

	object = ni_dbus_server_find_object_by_handle(server, dev);
	if (object == NULL) {
		ni_warn("no dbus object for interface %s. Cannot send signal", dev->name);
		return FALSE;
	}

	return __ni_objectmodel_interface_event(server, object, ifevent, uuid);
}

dbus_bool_t
__ni_objectmodel_interface_event(ni_dbus_server_t *server, ni_dbus_object_t *object,
			ni_event_t ifevent, const ni_uuid_t *uuid)
{
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	const char *signal_name = NULL;
	unsigned int argc = 0;

	if (!(signal_name = __ni_objectmodel_event_to_signal(ifevent)))
		return FALSE;

	if (!server
	 && !(server = ni_dbus_object_get_server(object))
	 && !(server = __ni_objectmodel_server)) {
		ni_error("%s: help! No dbus server handle! Cannot send signal.", __func__);
		return FALSE;
	}

	if (uuid) {
		ni_dbus_variant_set_uuid(&arg, uuid);
		argc++;
	}

	ni_debug_dbus("sending interface event \"%s\" for %s", signal_name, ni_dbus_object_get_path(object));
	ni_dbus_server_send_signal(server, object, WICKED_DBUS_NETIF_INTERFACE, signal_name, argc, &arg);

	ni_dbus_variant_destroy(&arg);
	return TRUE;
}

const char *
__ni_objectmodel_event_to_signal(ni_event_t event)
{
	static const char *ifevent_signals[__NI_EVENT_MAX] = {
	[NI_EVENT_LINK_UP]		= "linkUp",
	[NI_EVENT_LINK_DOWN]		= "linkDown",
	[NI_EVENT_NETWORK_UP]		= "networkUp",
	[NI_EVENT_NETWORK_DOWN]		= "networkDown",
	[NI_EVENT_ADDRESS_ACQUIRED]	= "addressAcquired",
	[NI_EVENT_ADDRESS_RELEASED]	= "addressReleased",
	[NI_EVENT_ADDRESS_LOST]		= "addressLost",
	};

	if (event >= __NI_EVENT_MAX)
		return NULL;

	return ifevent_signals[event];
}

/*
 * Interface.down(void)
 * Bring down the network interface.
 *
 * The options dictionary contains interface properties.
 */
static dbus_bool_t
ni_objectmodel_netif_link_down(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_interface_t *dev;
	dbus_bool_t ret = FALSE;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("ifp=%s", dev->name);

	if ((rv = ni_system_interface_down(nc, dev)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot shutdown interface %s: %s", dev->name,
				ni_strerror(rv));
		goto failed;
	}

#if 0
	if (__ni_interface_is_down(dev))
		ni_objectmodel_interface_event(object, "InterfaceDown");
#endif

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
	ni_interface_t *ifp;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, NULL)))
		return;

	NI_TRACE_ENTER_ARGS("object=%s, dev=%p", object->path, ifp);
	ni_assert(ifp);
	ni_interface_put(ifp);
}

static ni_dbus_method_t		ni_objectmodel_netif_methods[] = {
	{ "linkChange",		"a{sv}",		ni_objectmodel_netif_link_change },
	{ "down",		"",			ni_objectmodel_netif_link_down },
	{ NULL }
};

/*
 * Interface property handlers
 */
static void *
ni_objectmodel_get_interface(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_unwrap_interface(object, NULL);
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
	ni_interface_t *ifp;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	ni_dbus_variant_set_byte_array(result, ifp->link.hwaddr.data, ifp->link.hwaddr.len);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_set_hwaddr(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp;
	unsigned int addrlen;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

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
__wicked_dbus_interface_get_addresses(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_dict_array_init(result);
	return __wicked_dbus_get_address_list(ifp->addrs, result, error);
}

static dbus_bool_t
__wicked_dbus_interface_set_addresses(ni_dbus_object_t *object,
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

/*
 * Get/set afinfo
 */
static dbus_bool_t
__wicked_dbus_get_afinfo(ni_afinfo_t *afi, ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_dict_add_bool(dict, "enabled", afi->enabled);
	ni_dbus_dict_add_bool(dict, "forwarding", afi->forwarding);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_set_afinfo(ni_afinfo_t *afi, const ni_dbus_variant_t *dict, DBusError *error)
{
	dbus_bool_t value;

	if (ni_dbus_dict_get_bool(dict, "enabled", &value))
		afi->enabled = value;
	if (ni_dbus_dict_get_bool(dict, "forwarding", &value))
		afi->forwarding = value;

	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_get_ipv4(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	return __wicked_dbus_get_afinfo(&dev->ipv4, argument, error);
}

static dbus_bool_t
__wicked_dbus_interface_set_ipv4(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	return __wicked_dbus_set_afinfo(&dev->ipv4, argument, error);
}

static dbus_bool_t
__wicked_dbus_interface_get_ipv6(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	return __wicked_dbus_get_afinfo(&dev->ipv6, argument, error);
}

static dbus_bool_t
__wicked_dbus_interface_set_ipv6(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *dev;

	if (!(dev = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	return __wicked_dbus_set_afinfo(&dev->ipv6, argument, error);
}

#define INTERFACE_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name,__wicked_dbus_interface, rw)
#define INTERFACE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_interface, rw)
#define INTERFACE_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(interface, dbus_name, member_name, rw)
#define INTERFACE_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(interface, dbus_name, member_name, rw)

#ifndef NI_DBUS_DICT_ARRAY_SIGNATURE
# define NI_DBUS_DICT_ARRAY_SIGNATURE DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE
#endif
#ifndef NI_DBUS_BYTE_ARRAY_SIGNATURE
# define NI_DBUS_BYTE_ARRAY_SIGNATURE DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING
#endif

static ni_dbus_property_t	ni_objectmodel_netif_properties[] = {
	INTERFACE_STRING_PROPERTY(name, name, RO),
	INTERFACE_UINT_PROPERTY(index, link.ifindex, RO),
	INTERFACE_UINT_PROPERTY(status, link.ifflags, RO),
	INTERFACE_UINT_PROPERTY(link-type, link.type, RO),
	INTERFACE_UINT_PROPERTY(mtu, link.mtu, RO),
	INTERFACE_UINT_PROPERTY(txqlen, link.txqlen, RO),

	INTERFACE_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv4, RO),
	INTERFACE_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv6, RO),

	/* This should really go to the link layer classes */
	INTERFACE_PROPERTY_SIGNATURE(NI_DBUS_BYTE_ARRAY_SIGNATURE, hwaddr, RO),

	/* addresses and routes is an array of dicts */
	INTERFACE_PROPERTY_SIGNATURE(NI_DBUS_DICT_ARRAY_SIGNATURE, addresses, RO),
	INTERFACE_PROPERTY_SIGNATURE(NI_DBUS_DICT_ARRAY_SIGNATURE, routes, RO),

	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_netif_service = {
	.name		= WICKED_DBUS_NETIF_INTERFACE,
	.compatible	= &ni_objectmodel_netif_class,
	.methods	= ni_objectmodel_netif_methods,
	.properties	= ni_objectmodel_netif_properties,
};

/*
 * These helper functions assist in marshalling InterfaceRequests
 */
static void *
ni_objectmodel_get_interface_request(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_dbus_object_get_handle(object);
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
	if (req->ipv4 && !__wicked_dbus_get_afinfo(req->ipv4, result, error))
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

	if (req->ipv6 && !__wicked_dbus_get_afinfo(req->ipv6, result, error))
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

static ni_dbus_property_t	ni_objectmodel_netif_request_properties[] = {
	INTERFACE_REQUEST_UINT_PROPERTY(status, ifflags, RO),
	INTERFACE_REQUEST_UINT_PROPERTY(mtu, mtu, RO),
	INTERFACE_REQUEST_UINT_PROPERTY(metric, metric, RO),
	INTERFACE_REQUEST_UINT_PROPERTY(txqlen, txqlen, RO),

	INTERFACE_REQUEST_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv4, RO),
	INTERFACE_REQUEST_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv6, RO),

	{ NULL }
};

