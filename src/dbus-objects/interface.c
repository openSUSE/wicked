/*
 * DBus encapsulation for network interfaces
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include <wicked/system.h>
#include <wicked/xml.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

extern dbus_bool_t	ni_objectmodel_netif_list_refresh(ni_dbus_object_t *);
static void		ni_objectmodel_register_netif_factory_service(ni_dbus_service_t *);
static void		ni_objectmodel_netif_initialize(ni_dbus_object_t *object);
static void		ni_objectmodel_netif_destroy(ni_dbus_object_t *object);

const ni_dbus_class_t		ni_objectmodel_netif_class = {
	.name		= NI_OBJECTMODEL_NETIF_CLASS,
	.initialize	= ni_objectmodel_netif_initialize,
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
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv6_dhcp_service;
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv4ll_service;
extern ni_dbus_service_t	ni_objectmodel_wireless_service;
static ni_dbus_property_t	ni_objectmodel_netif_request_properties[];

/*
 * For all link layer types, create a dbus object class named "netif-$linktype".
 * This allows to define extensions and interface for specific link layers.
 */
void
ni_objectmodel_register_netif_classes(void)
{
	ni_dbus_class_t *link_class;
	unsigned int iftype;

	/* register the netif-list class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(&ni_objectmodel_netif_list_class);

	/* register the netif class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(&ni_objectmodel_netif_class);

	for (iftype = 0; iftype < __NI_IFTYPE_MAX; ++iftype) {
		const char *classname;

		if (!(classname = ni_objectmodel_link_classname(iftype)))
			continue;

		/* Create and register the new link class */
		link_class = ni_objectmodel_class_new(classname, &ni_objectmodel_netif_class);
		ni_objectmodel_register_class(link_class);
	}
}

void
ni_objectmodel_register_netif_services(void)
{
	ni_objectmodel_register_service(&ni_objectmodel_netif_service);
	ni_objectmodel_register_service(&ni_objectmodel_netif_list_service);

	/* register built-in protocol services */
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_ipv4_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_ipv6_service);

	/* register our built-in addrconf services */
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv4_static_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv6_static_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv4_dhcp_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv6_dhcp_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv4ll_service);

	/* LLDP agent */
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_lldp_service);

	ni_objectmodel_register_netif_service(NI_IFTYPE_ETHERNET, &ni_objectmodel_ethernet_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_VLAN, &ni_objectmodel_vlan_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_MACVLAN, &ni_objectmodel_macvlan_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_BOND, &ni_objectmodel_bond_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_BRIDGE, &ni_objectmodel_bridge_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_WIRELESS, &ni_objectmodel_wireless_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_TUN, &ni_objectmodel_tun_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_TUN, &ni_objectmodel_openvpn_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_INFINIBAND, &ni_objectmodel_ibparent_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_INFINIBAND_CHILD, &ni_objectmodel_ibchild_service);

	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_bond_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_bridge_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_vlan_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_macvlan_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_tun_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_openvpn_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_ibchild_factory_service);

	/* Register all builtin naming services */
	ni_objectmodel_register_ns_builtin();
}

static void
ni_objectmodel_register_netif_factory_service(ni_dbus_service_t *svc)
{
	svc->compatible = &ni_objectmodel_netif_list_class;
	ni_objectmodel_register_service(svc);
}

void
ni_objectmodel_register_netif_service(ni_iftype_t iftype, ni_dbus_service_t *svc)
{
	svc->compatible = ni_objectmodel_link_class(iftype);
	ni_assert(svc->compatible);

	ni_objectmodel_register_service(svc);
}

/*
 * netif list class
 */
void
ni_objectmodel_create_netif_list(ni_dbus_server_t *server)
{
	ni_dbus_object_t *object;

	/* Register the list of all interfaces */
	object = ni_dbus_server_register_object(server,
					NI_OBJECTMODEL_NETIF_LIST_PATH,
					&ni_objectmodel_netif_list_class,
					NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	ni_objectmodel_bind_compatible_interfaces(object);
}

static const ni_dbus_class_t	ni_objectmodel_netif_list_class = {
	.name		= NI_OBJECTMODEL_NETIF_LIST_CLASS,
	.list = {
		.item_class = &ni_objectmodel_netif_class,
	},
	.refresh	= ni_objectmodel_netif_list_refresh,
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
 *
 * FIXME: remove this ruin and the dbus_class.list stuff with it
 */
dbus_bool_t
ni_objectmodel_netif_list_refresh(ni_dbus_object_t *object)
{
	ni_netconfig_t *nc;

	if (!(nc = ni_global_state_handle(1))) {
		ni_error("failed to refresh network interfaces");
		return FALSE;
	}

	/* Note, we do not have to deal with removal of interfaces
	 * that have been destroyed. We should be notified of these
	 * automatically via RTM_DELLINK */

	return TRUE;
}

/*
 * General dbus object lookup
 * FIXME: move this to model.c
 */
ni_dbus_object_t *
ni_objectmodel_resolve_name(ni_dbus_object_t *parent, const char *naming_service, const ni_dbus_variant_t *var)
{
	ni_dbus_object_t *result = NULL;
	ni_objectmodel_ns_t *ns;
	const char *key, *value;

	if (!(ns = ni_objectmodel_get_ns(naming_service))) {
		ni_warn("unknown naming service \"%s\"", naming_service);
		return NULL;
	}

	if (ni_dbus_variant_get_string(var, &value)) {
		if (ns->lookup_by_name == NULL)
			return NULL;
		result = ns->lookup_by_name(ns, value);
	} else {
		/* Loop over all dict entries and append them to the var array */
		ni_var_array_t attrs = NI_VAR_ARRAY_INIT;
		const ni_dbus_variant_t *dict = var;
		unsigned int i = 0;

		while ((var = ni_dbus_dict_get_entry(dict, i++, &key)) != NULL) {
			if (!ni_dbus_variant_get_string(var, &value))
				goto done;
			ni_var_array_set(&attrs, key, value);
		}

		result = ni_objectmodel_lookup_by_attrs(parent, ns, &attrs);
done:
		ni_var_array_destroy(&attrs);
	}
	return result;
}

/*
 * InterfaceList.identifyDevice
 */
static dbus_bool_t
ni_objectmodel_netif_list_device_by_name(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc;
	const char *name;
	ni_netdev_t *dev;

	if (argc != 1 || !ni_dbus_variant_get_string(&argv[0], &name))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	if (!(nc = ni_global_state_handle(0)) || !(dev = ni_netdev_by_name(nc, name))) {
		dbus_set_error(error, NI_DBUS_ERROR_DEVICE_NOT_KNOWN,
				"failed to identify interface %s", name);
		return FALSE;
	}

	ni_dbus_message_append_string(reply, ni_objectmodel_netif_full_path(dev));
	return TRUE;
}

/*
 * InterfaceList.identifyDevice
 */
static dbus_bool_t
ni_objectmodel_netif_list_identify_device(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	const char *namespace;
	ni_dbus_object_t *found;

	if (argc != 2
	 || !ni_dbus_variant_get_string(&argv[0], &namespace)
	 || (!ni_dbus_variant_is_dict(&argv[1]) && argv[1].type != DBUS_TYPE_STRING))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	found = ni_objectmodel_resolve_name(object, namespace, &argv[1]);
	if (found == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_DEVICE_NOT_KNOWN,
				"unable to identify interface via %s", namespace);
		return FALSE;
	}

	if (ni_objectmodel_unwrap_netif(found, NULL) == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_DEVICE_NOT_KNOWN,
				"failed to identify interface via %s - naming service returned "
				"a %s object", namespace, found->class->name);
		return FALSE;
	}

	ni_dbus_message_append_string(reply, found->path);
	return TRUE;
}

static ni_dbus_method_t		ni_objectmodel_netif_list_methods[] = {
	{ "deviceByName",	"s",		ni_objectmodel_netif_list_device_by_name },
	{ "identifyDevice",	"sa{sv}",	ni_objectmodel_netif_list_identify_device },
	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_netif_list_service = {
	.name		= NI_OBJECTMODEL_NETIFLIST_INTERFACE,
	.compatible	= &ni_objectmodel_netif_list_class,
	.methods	= ni_objectmodel_netif_list_methods,
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

const ni_dbus_class_t *
ni_objectmodel_link_class(ni_iftype_t iftype)
{
	const ni_dbus_class_t *class = NULL;
	const char *classname;

	if ((classname = ni_objectmodel_link_classname(iftype)) != NULL)
		class = ni_objectmodel_get_class(classname);
	if (class == NULL)
		class = &ni_objectmodel_netif_class;
	return class;
}

/*
 * Build a dbus-object encapsulating a network device.
 * If @server is non-NULL, register the object with a canonical object path
 */
static ni_dbus_object_t *
__ni_objectmodel_build_netif_object(ni_dbus_server_t *server, ni_netdev_t *dev, const ni_dbus_class_t *requested_class)
{
	const ni_dbus_class_t *class;
	ni_dbus_object_t *object;

	class = ni_objectmodel_link_class(dev->link.type);

	/* If the caller requests a specific class for this object, it must be a
	 * subclass of the link type class. */
	if (requested_class) {
		if (!ni_dbus_class_is_subclass(requested_class, class)) {
			ni_warn("ignoring caller specified class %s for netdev %s (class %s)",
					requested_class->name, dev->name, class->name);
		} else {
			class = requested_class;
		}
	}

	if (server != NULL) {
		object = ni_dbus_server_register_object(server,
						ni_objectmodel_netif_path(dev),
						class, ni_netdev_get(dev));
	} else {
		object = ni_dbus_object_new(class, NULL, ni_netdev_get(dev));
	}

	if (object == NULL)
		ni_fatal("Unable to create dbus object for network interface %s", dev->name);

	ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}


/*
 * Register a network interface with our dbus server,
 * and add the appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_register_netif(ni_dbus_server_t *server, ni_netdev_t *ifp, const ni_dbus_class_t *override_class)
{
	return __ni_objectmodel_build_netif_object(server, ifp, override_class);
}

/*
 * Unregister a network interface from our dbus server.
 */
dbus_bool_t
ni_objectmodel_unregister_netif(ni_dbus_server_t *server, ni_netdev_t *ifp)
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
ni_objectmodel_netif_path(const ni_netdev_t *ifp)
{
	static char object_path[256];

	snprintf(object_path, sizeof(object_path), "Interface/%u", ifp->link.ifindex);
	return object_path;
}

const char *
ni_objectmodel_netif_full_path(const ni_netdev_t *ifp)
{
	static char object_path[256];

	snprintf(object_path, sizeof(object_path), NI_OBJECTMODEL_OBJECT_PATH "/Interface/%u", ifp->link.ifindex);
	return object_path;
}

/*
 * Common helper function to extract a network device argument from a properties dict.
 * The attributes are specific to a given DBus interface.
 */
ni_netdev_t *
ni_objectmodel_get_netif_argument(const ni_dbus_variant_t *dict, ni_iftype_t iftype, const ni_dbus_service_t *service)
{
	ni_dbus_object_t *dev_object;
	ni_netdev_t *dev;
	dbus_bool_t rv;

	dev = ni_netdev_new(NULL, 0);
	dev->link.type = iftype;

	dev_object = ni_objectmodel_wrap_netif(dev);
	rv = ni_dbus_object_set_properties_from_dict(dev_object, service, dict, NULL);
	ni_dbus_object_free(dev_object);

	if (!rv) {
		ni_netdev_put(dev);
		dev = NULL;
	}
	return dev;
}

/*
 * Device factory functions need to register the newly created interface with the
 * dbus service, and return the device's object path
 */
dbus_bool_t
ni_objectmodel_netif_factory_result(ni_dbus_server_t *server, ni_dbus_message_t *reply,
				ni_netdev_t *dev, const ni_dbus_class_t *override_class,
				DBusError *error)
{
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	ni_dbus_object_t *new_object;
	dbus_bool_t rv;

	new_object = ni_dbus_server_find_object_by_handle(server, dev);
	if (new_object == NULL)
		new_object = ni_objectmodel_register_netif(server, dev, override_class);
	if (!new_object) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"failed to register new device %s",
				dev->name);
		return FALSE;
	}

	/* For now, we return a string here. This should really be an object-path,
	 * though. */
	ni_dbus_variant_set_string(&result, new_object->path);

	rv = ni_dbus_message_serialize_variants(reply, 1, &result, error);
	ni_dbus_variant_destroy(&result);

	return rv;
}

/*
 * Build a dummy dbus object encapsulating a network interface,
 * and add the appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_wrap_netif(ni_netdev_t *ifp)
{
	return __ni_objectmodel_build_netif_object(NULL, ifp, NULL);
}

ni_dbus_object_t *
ni_objectmodel_wrap_netif_request(ni_netdev_req_t *req)
{
	return ni_dbus_object_new(&ni_objectmodel_ifreq_class, NULL, req);
}

ni_netdev_t *
ni_objectmodel_unwrap_netif(const ni_dbus_object_t *object, DBusError *error)
{
	ni_netdev_t *dev = object->handle;

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
 * Given a network device, look up the server object encapsulating it
 */
ni_dbus_object_t *
ni_objectmodel_get_netif_object(ni_dbus_server_t *server, const ni_netdev_t *dev)
{
	ni_dbus_object_t *object;

	if (!dev)
		return NULL;

	if (!server && !(server = __ni_objectmodel_server))
		return NULL;

	object = ni_dbus_server_find_object_by_handle(server, dev);
	if (object == NULL)
		return NULL;

	if (!ni_dbus_object_isa(object, &ni_objectmodel_netif_class)) {
		ni_error("%s: netdev is encapsulated by a %s class object", __func__, object->class->name);
		return NULL;
	}

	return object;
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

	return ni_dbus_object_set_properties_from_dict(&dummy, service, dict, error);
}

static dbus_bool_t
put_properties_to_dict(const ni_dbus_service_t *service, const void *handle, ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_object_t dummy;

	memset(&dummy, 0, sizeof(dummy));
	dummy.class = service->compatible;
	dummy.handle = (void *) handle;

	ni_dbus_variant_init_dict(dict);
	return ni_dbus_object_get_properties_as_dict(&dummy, service, dict, error);
}

static ni_dbus_service_t	ni_objectmodel_netifreq_service = {
	.name		= NI_OBJECTMODEL_NETIF_INTERFACE "Request",
	.compatible	= &ni_objectmodel_ifreq_class,
	.properties	= ni_objectmodel_netif_request_properties,
};


dbus_bool_t
ni_objectmodel_marshal_netdev_request(const ni_netdev_req_t *req, ni_dbus_variant_t *dict, DBusError *error)
{
	return put_properties_to_dict(&ni_objectmodel_netifreq_service, req, dict, error);
}

dbus_bool_t
ni_objectmodel_unmarshal_netdev_request(ni_netdev_req_t *req, const ni_dbus_variant_t *dict, DBusError *error)
{
	return get_properties_from_dict(&ni_objectmodel_netifreq_service, req, dict, error);
}

/*
 * Interface.setMonitor(bool)
 *
 * Bring up the network interface, and assign the requested addresses.
 * In the case of virtual interfaces like VLANs or bridges, the interface
 * must have been created and configured prior to this call.
 *
 * The options dictionary contains interface properties.
 */
static dbus_bool_t
ni_objectmodel_netif_link_monitor(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	/* Create an interface_request object and extract configuration from dict */
	if (argc != 0)
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	if ((rv = ni_system_interface_link_monitor(dev)) < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"failed to enable monitoring for interface %s",
				dev->name);
		return FALSE;
	}
	return TRUE;
}

/*
 * Interface.getNames()
 *
 * Bring up the network interface, and assign the requested addresses.
 * In the case of virtual interfaces like VLANs or bridges, the interface
 * must have been created and configured prior to this call.
 *
 * The options dictionary contains interface properties.
 */
static dbus_bool_t
ni_objectmodel_netif_get_names(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	ni_netdev_t *dev;
	xml_node_t *names;
	dbus_bool_t rv = FALSE;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	/* Create an interface_request object and extract configuration from dict */
	if (argc != 0)
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	names = ni_objectmodel_get_names(object);

	ni_objectmodel_get_name_array(names, &result);
	rv = ni_dbus_message_serialize_variants(reply, 1, &result, error);
	ni_dbus_variant_destroy(&result);

	/* Destroy the XML object last - the results dict will reference the
	 * attribute name strings while it's around */
	if (names)
		xml_node_free(names);
	return rv;
}

/*
 * Interface.clearEventFilters()
 */
static dbus_bool_t
ni_objectmodel_netif_clear_event_filters(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	/* Create an interface_request object and extract configuration from dict */
	if (argc != 0)
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	ni_netdev_clear_event_filters(dev);
	return TRUE;
}

/*
 * Interface.linkUp(dict options)
 *
 * Bring up the network interface, and wait for link negotiation to complete.
 * In the case of virtual interfaces like VLANs or bridges, the interface
 * must have been created and configured prior to this call.
 *
 * The options dictionary contains interface properties.
 */
static dbus_bool_t
ni_objectmodel_netif_link_up(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	ni_netdev_req_t *req = NULL;
	dbus_bool_t ret = FALSE;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	/* Create an interface_request object and extract configuration from dict */
	if (argc != 1)
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	req = ni_netdev_req_new();
	if (!ni_objectmodel_unmarshal_netdev_request(req, &argv[0], error))
		goto failed;
	req->ifflags = NI_IFF_LINK_UP | NI_IFF_NETWORK_UP;

	if ((rv = ni_system_interface_link_change(dev, req)) < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"failed to configure interface %s", dev->name);
		ret = FALSE;
		goto failed;
	}

	ret = TRUE;

	/* If the link is up, there's nothing to return */
	if (!(dev->link.ifflags & NI_IFF_LINK_UP)) {
		const ni_uuid_t *uuid;

		/* Link is not up yet. Tell the caller to wait for an event. */
		uuid = ni_netdev_add_event_filter(dev, (1 << NI_EVENT_LINK_UP) | (1 << NI_EVENT_LINK_DOWN));
		ret = __ni_objectmodel_return_callback_info(reply, NI_EVENT_LINK_UP, uuid, error);
	}

failed:
	if (req)
		ni_netdev_req_free(req);
	return ret;
}

static dbus_bool_t
ni_objectmodel_netif_link_down(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	if ((rv = ni_system_interface_link_change(dev, NULL)) < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"failed to shut down interface %s", dev->name);
		return FALSE;
	}

	return TRUE;
}

/*
 * Interface.installLease()
 *
 * This is used by network layers such as PPP or OpenVPN to inform wickedd about
 * some intrinsic address configuration.
 *
 * The options dictionary contains address and route properties.
 */
static dbus_bool_t
ni_objectmodel_netif_install_lease(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	ni_addrconf_lease_t *lease;
	dbus_bool_t ret = FALSE;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	/* Create an interface_request object and extract configuration from dict */
	if (argc != 1)
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	lease = ni_addrconf_lease_new(NI_ADDRCONF_INTRINSIC, AF_INET);
	if (!__ni_objectmodel_set_addrconf_lease(lease, &argv[0], error))
		goto failed;

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
	rv = __ni_system_interface_update_lease(dev, &lease);
	if (rv < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"failed to install intrinsic lease on interface %s", dev->name);
		goto failed;
	}

	ret = TRUE;

failed:
	if (lease)
		ni_addrconf_lease_free(lease);
	return ret;
}

/*
 * Interface.setClientInfo()
 *
 * This is used by clients to record a uuid identifying the configuration used, and
 * a "state" string that helps them track where they are.
 */
static dbus_bool_t
ni_objectmodel_netif_set_client_info(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	ni_device_clientinfo_t *client_info;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	client_info = ni_device_clientinfo_new();
	if (!ni_objectmodel_netif_client_info_from_dict(client_info, &argv[0])) {
		ni_device_clientinfo_free(client_info);
		return ni_dbus_error_invalid_args(error, object->path, method->name);
	}

	ni_netdev_set_client_info(dev, client_info);
	return TRUE;
}

/*
 * Interface.setClientState()
 *
 * This is used by clients to record the initial state of an interface, persistent flag
 * and timestamps of the initial and last ifup operations.
 */
static dbus_bool_t
ni_objectmodel_netif_set_client_state(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	ni_client_state_t *client_state;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	client_state = ni_client_state_new(0);
	if (!ni_objectmodel_netif_client_state_from_dict(client_state, &argv[0])) {
		ni_client_state_free(client_state);
		return ni_dbus_error_invalid_args(error, object->path, method->name);
	}

	ni_netdev_set_client_state(dev, client_state);
	if (ni_netdev_get_client_state(dev)) {
		ni_client_state_save(client_state, dev->link.ifindex);
		ni_debug_dbus("saving client-state structure into a file for %s", dev->name);
	}

	return TRUE;
}

/*
 * Broadcast an interface event
 * The optional uuid argument helps the client match e.g. notifications
 * from an addrconf service against its current state.
 */
dbus_bool_t
ni_objectmodel_send_netif_event(ni_dbus_server_t *server, ni_dbus_object_t *object,
			ni_event_t ifevent, const ni_uuid_t *uuid)
{
	if (ifevent >= __NI_EVENT_MAX)
		return FALSE;

	if (!server && !(server = __ni_objectmodel_server)) {
		ni_error("%s: help! No dbus server handle! Cannot send signal.", __func__);
		return FALSE;
	}

	return __ni_objectmodel_device_event(server, object, NI_OBJECTMODEL_NETIF_INTERFACE, ifevent, uuid);
}

dbus_bool_t
__ni_objectmodel_device_event(ni_dbus_server_t *server, ni_dbus_object_t *object,
			const char *interface, ni_event_t ifevent, const ni_uuid_t *uuid)
{
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	const char *signal_name = NULL;
	unsigned int argc = 0;

	if (!(signal_name = ni_objectmodel_event_to_signal(ifevent))) {
		ni_warn("%s: no signal name for event %u", __func__, ifevent);
		return FALSE;
	}

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

	ni_debug_dbus("sending device event \"%s\" for %s", signal_name, ni_dbus_object_get_path(object));
	ni_dbus_server_send_signal(server, object, interface, signal_name, argc, &arg);

	ni_dbus_variant_destroy(&arg);
	return TRUE;
}

static ni_intmap_t	__ni_objectmodel_event_names[] = {
	{ "deviceCreate",		NI_EVENT_DEVICE_CREATE },
	{ "deviceDelete",		NI_EVENT_DEVICE_DELETE },
	{ "deviceUp",			NI_EVENT_DEVICE_UP },
	{ "deviceDown",			NI_EVENT_DEVICE_DOWN },
	{ "linkAssociated",		NI_EVENT_LINK_ASSOCIATED },
	{ "linkAssociationLost",	NI_EVENT_LINK_ASSOCIATION_LOST },
	{ "linkScanUpdated",		NI_EVENT_LINK_SCAN_UPDATED },
	{ "linkUp",			NI_EVENT_LINK_UP },
	{ "linkDown",			NI_EVENT_LINK_DOWN },
	{ "networkUp",			NI_EVENT_NETWORK_UP },
	{ "networkDown",		NI_EVENT_NETWORK_DOWN },
	{ "addressAcquired",		NI_EVENT_ADDRESS_ACQUIRED },
	{ "addressReleased",		NI_EVENT_ADDRESS_RELEASED },
	{ "addressLost",		NI_EVENT_ADDRESS_LOST },
	{ "resolverUpdated",		NI_EVENT_RESOLVER_UPDATED },
	{ "hostnameUpdated",		NI_EVENT_HOSTNAME_UPDATED },
	{ "genericUpdated",		NI_EVENT_GENERIC_UPDATED },

	{ NULL, 0 }
};

const char *
ni_objectmodel_event_to_signal(ni_event_t event)
{
	return ni_format_uint_mapped(event, __ni_objectmodel_event_names);
}

int
ni_objectmodel_signal_to_event(const char *signal, ni_event_t *ep)
{
	unsigned int event;

	if (!signal || !ep)
		return -1;

	if (ni_parse_uint_mapped(signal, __ni_objectmodel_event_names, &event) < 0)
		return -1;

	*ep = event;
	return 0;
}

/*
 * A new DBus object encapsulating a dummy netdev is created.
 * This is called on the client side from GetManagedObject
 */
static void
ni_objectmodel_netif_initialize(ni_dbus_object_t *object)
{
	ni_assert(object->handle == NULL);
	object->handle = ni_netdev_new(NULL, 0);
}

/*
 * The DBus object is destroyed; detach the network interface handle
 */
static void
ni_objectmodel_netif_destroy(ni_dbus_object_t *object)
{
	ni_netdev_t *ifp;

	if (!(ifp = ni_objectmodel_unwrap_netif(object, NULL)))
		return;

	NI_TRACE_ENTER_ARGS("object=%s, dev=%p", object->path, ifp);
	ni_assert(ifp);
	ni_netdev_put(ifp);
}

static ni_dbus_method_t		ni_objectmodel_netif_methods[] = {
	{ "linkUp",		"a{sv}",		ni_objectmodel_netif_link_up },
	{ "linkDown",		"",			ni_objectmodel_netif_link_down },
	{ "installLease",	"a{sv}",		ni_objectmodel_netif_install_lease },
	{ "setClientState",	"a{sv}",		ni_objectmodel_netif_set_client_state },
	{ "setClientInfo",	"a{sv}",		ni_objectmodel_netif_set_client_info },
	{ "linkMonitor",	"",			ni_objectmodel_netif_link_monitor },
	{ "getNames",		"",			ni_objectmodel_netif_get_names },
	{ "clearEventFilters",	"",			ni_objectmodel_netif_clear_event_filters },
	{ NULL }
};

/*
 * Interface property handlers
 */
static void *
ni_objectmodel_get_netdev(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_netif(object, error);
}

/*
 * Property Interface.hwaddr
 */
static dbus_bool_t
__ni_objectmodel_netif_get_hwaddr(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *ifp;

	if (!(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	ni_dbus_variant_set_byte_array(result, ifp->link.hwaddr.data, ifp->link.hwaddr.len);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_set_hwaddr(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *ifp;
	unsigned int addrlen;

	if (!(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

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
__ni_objectmodel_netif_get_addresses(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_dict_array_init(result);
	return __ni_objectmodel_get_address_list(ifp->addrs, result, error);
}

static dbus_bool_t
__ni_objectmodel_netif_set_addresses(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *ifp = ni_dbus_object_get_handle(object);

	return __ni_objectmodel_set_address_list(&ifp->addrs, argument, error);
}

/*
 * Property Interface.routes
 * This one is rather complex, too.
 */
static dbus_bool_t
__ni_objectmodel_netif_get_routes(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_dict_array_init(result);
	return __ni_objectmodel_get_route_list(ifp->routes, result, error);
}

static dbus_bool_t
__ni_objectmodel_netif_set_routes(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *ifp = ni_dbus_object_get_handle(object);

	return __ni_objectmodel_set_route_list(&ifp->routes, argument, error);
}

/*
 * Property Interface.client_info
 */
static dbus_bool_t
__ni_objectmodel_netif_get_client_info(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *dev = ni_dbus_object_get_handle(object);
	ni_device_clientinfo_t *client_info;

	if ((client_info = dev->client_info) == NULL)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	ni_dbus_variant_init_dict(result);
	return ni_objectmodel_netif_client_info_to_dict(client_info, result);
}

dbus_bool_t
ni_objectmodel_netif_client_info_to_dict(const ni_device_clientinfo_t *client_info, ni_dbus_variant_t *dict)
{
	if (client_info->state)
		ni_dbus_dict_add_string(dict, "state", client_info->state);
	if (client_info->config_origin)
		ni_dbus_dict_add_string(dict, "config-origin", client_info->config_origin);

	if (!ni_uuid_is_null(&client_info->config_uuid))
		ni_dbus_dict_add_byte_array(dict, "config-uuid",
				client_info->config_uuid.octets,
				sizeof(client_info->config_uuid.octets));
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_set_client_info(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev = ni_dbus_object_get_handle(object);
	ni_device_clientinfo_t *client_info;

	client_info = ni_device_clientinfo_new();
	if (!ni_objectmodel_netif_client_info_from_dict(client_info, argument)) {
		ni_device_clientinfo_free(client_info);
		return FALSE;
	}
	ni_netdev_set_client_info(dev, client_info);
	return TRUE;
}

dbus_bool_t
ni_objectmodel_netif_client_info_from_dict(ni_device_clientinfo_t *client_info, const ni_dbus_variant_t *dict)
{
	ni_dbus_variant_t *child;
	const char *sval;

	if (ni_dbus_dict_get_string(dict, "state", &sval))
		ni_string_dup(&client_info->state, sval);
	if (ni_dbus_dict_get_string(dict, "config-origin", &sval))
		ni_string_dup(&client_info->config_origin, sval);
	if ((child = ni_dbus_dict_get(dict, "config-uuid")) != NULL)
		ni_dbus_variant_get_uuid(child, &client_info->config_uuid);

	return TRUE;
}

/*
 * Property Interface.client_state
 */
static dbus_bool_t
__ni_objectmodel_netif_get_client_state(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *dev = ni_dbus_object_get_handle(object);
	ni_client_state_t *client_state;

	if ((client_state = dev->client_state) == NULL)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	ni_dbus_variant_init_dict(result);
	return ni_objectmodel_netif_client_state_to_dict(client_state, result);
}

dbus_bool_t
ni_objectmodel_netif_client_state_to_dict(const ni_client_state_t *client_state, ni_dbus_variant_t *dict)
{
	char *value = NULL;

	ni_dbus_dict_add_bool(dict, NI_CLIENT_STATE_XML_PERSISTENT_NODE,
		(dbus_bool_t) client_state->persistent);
	ni_dbus_dict_add_uint32(dict, NI_CLIENT_STATE_XML_INIT_STATE_NODE,
		client_state->init_state);

	ni_dbus_dict_add_string(dict, NI_CLIENT_STATE_XML_INIT_TIME_NODE,
		ni_client_state_print_timeval(&client_state->init_time, &value));
	ni_string_free(&value);

	ni_dbus_dict_add_string(dict, NI_CLIENT_STATE_XML_LAST_TIME_NODE,
		ni_client_state_print_timeval(&client_state->last_time, &value));
	ni_string_free(&value);

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_set_client_state(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev = ni_dbus_object_get_handle(object);
	ni_client_state_t *client_state;

	client_state = ni_client_state_new(0);
	if (!ni_objectmodel_netif_client_state_from_dict(client_state, argument)) {
		ni_client_state_free(client_state);
		return FALSE;
	}
	ni_netdev_set_client_state(dev, client_state);
	return TRUE;
}

dbus_bool_t
ni_objectmodel_netif_client_state_from_dict(ni_client_state_t *client_state, const ni_dbus_variant_t *dict)
{
	const char *sval;

	ni_dbus_dict_get_bool(dict, NI_CLIENT_STATE_XML_PERSISTENT_NODE,
		(dbus_bool_t *) &client_state->persistent);
	ni_dbus_dict_get_uint32(dict, NI_CLIENT_STATE_XML_INIT_STATE_NODE,
		&client_state->init_state);

	if (ni_dbus_dict_get_string(dict, NI_CLIENT_STATE_XML_INIT_TIME_NODE, &sval)) {
		if (!ni_client_state_parse_timeval(sval, &client_state->init_time))
			return FALSE;
	}

	if (ni_dbus_dict_get_string(dict, NI_CLIENT_STATE_XML_LAST_TIME_NODE, &sval)) {
		if (!ni_client_state_parse_timeval(sval, &client_state->last_time))
			return FALSE;
	}

	return TRUE;
}

/*
 * Properties of an interface
 */
#define NETIF_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __ni_objectmodel_netif, rw)

static ni_dbus_property_t	ni_objectmodel_netif_properties[] = {
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev, name, name, RO),
	NI_DBUS_GENERIC_UINT_PROPERTY(netdev, index, link.ifindex, RO),
	NI_DBUS_GENERIC_UINT_PROPERTY(netdev, status, link.ifflags, RO),
	NI_DBUS_GENERIC_UINT_PROPERTY(netdev, link-type, link.type, RO),
	NI_DBUS_GENERIC_UINT_PROPERTY(netdev, mtu, link.mtu, RO),
	NI_DBUS_GENERIC_UINT_PROPERTY(netdev, txqlen, link.txqlen, RO),
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev, alias, link.alias, RO),
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev, master, link.masterdev.name, RO),

	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE,
				client-info, client_info,
				__ni_objectmodel_netif, RO),
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE,
				client-state, client_state,
				__ni_objectmodel_netif, RO),

	/* This should really go to the link layer classes */
	NETIF_PROPERTY_SIGNATURE(NI_DBUS_BYTE_ARRAY_SIGNATURE, hwaddr, RO),

	/* addresses and routes is an array of dicts */
	NETIF_PROPERTY_SIGNATURE(NI_DBUS_DICT_ARRAY_SIGNATURE, addresses, RO),
	NETIF_PROPERTY_SIGNATURE(NI_DBUS_DICT_ARRAY_SIGNATURE, routes, RO),

	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_netif_service = {
	.name		= NI_OBJECTMODEL_NETIF_INTERFACE,
	.compatible	= &ni_objectmodel_netif_class,
	.methods	= ni_objectmodel_netif_methods,
	.properties	= ni_objectmodel_netif_properties,
};

/*
 * These helper functions assist in marshalling InterfaceRequests
 */
static void *
ni_objectmodel_get_netdev_req(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	/* FIXME: check for object class */
	return ni_dbus_object_get_handle(object);
}

#define NETIF_REQUEST_UINT_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(netdev_req, dbus_name, name, rw)
#define NETIF_REQUEST_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __ni_objectmodel_netif_request, rw)

static ni_dbus_property_t	ni_objectmodel_netif_request_properties[] = {
	NETIF_REQUEST_UINT_PROPERTY(status, ifflags, RO),
	NETIF_REQUEST_UINT_PROPERTY(mtu, mtu, RO),
	NETIF_REQUEST_UINT_PROPERTY(metric, metric, RO),
	NETIF_REQUEST_UINT_PROPERTY(txqlen, txqlen, RO),

	{ NULL }
};

