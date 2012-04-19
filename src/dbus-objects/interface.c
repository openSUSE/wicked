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
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

extern dbus_bool_t	ni_objectmodel_netif_list_refresh(ni_dbus_object_t *);
static void		ni_objectmodel_register_device_factory_service(ni_dbus_service_t *);
static void		ni_objectmodel_register_device_service(ni_iftype_t, ni_dbus_service_t *);
static void		ni_objectmodel_netif_initialize(ni_dbus_object_t *object);
static void		ni_objectmodel_netif_destroy(ni_dbus_object_t *object);

static ni_dbus_class_t		ni_objectmodel_netif_class = {
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
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv4ll_service;
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv4_ibft_service;
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv6_ibft_service;
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

	/* register the netif interface */
	ni_objectmodel_register_service(&ni_objectmodel_netif_service);

	for (iftype = 0; iftype < __NI_IFTYPE_MAX; ++iftype) {
		const char *classname;

		if (!(classname = ni_objectmodel_link_classname(iftype)))
			continue;

		/* Create and register the new link class */
		link_class = ni_objectmodel_class_new(classname, &ni_objectmodel_netif_class);
		ni_objectmodel_register_class(link_class);
	}

	ni_objectmodel_register_service(&ni_objectmodel_netif_list_service);

	/* register our built-in addrconf services */
	ni_objectmodel_register_device_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv4_static_service);
	ni_objectmodel_register_device_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv6_static_service);
	ni_objectmodel_register_device_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv4_dhcp_service);
	ni_objectmodel_register_device_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv4ll_service);
//	ni_objectmodel_register_device_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv4_ibft_service);
//	ni_objectmodel_register_device_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv6_ibft_service);

	ni_objectmodel_register_device_service(NI_IFTYPE_ETHERNET, &ni_objectmodel_ethernet_service);
	ni_objectmodel_register_device_service(NI_IFTYPE_VLAN, &ni_objectmodel_vlan_service);
	ni_objectmodel_register_device_service(NI_IFTYPE_BOND, &ni_objectmodel_bond_service);
	ni_objectmodel_register_device_service(NI_IFTYPE_BRIDGE, &ni_objectmodel_bridge_service);
	ni_objectmodel_register_device_service(NI_IFTYPE_WIRELESS, &ni_objectmodel_wireless_service);
	ni_objectmodel_register_device_service(NI_IFTYPE_TUN, &ni_objectmodel_tun_service);
	ni_objectmodel_register_device_service(NI_IFTYPE_TUN, &ni_objectmodel_openvpn_service);

	ni_objectmodel_register_device_factory_service(&ni_objectmodel_bond_factory_service);
	ni_objectmodel_register_device_factory_service(&ni_objectmodel_bridge_factory_service);
	ni_objectmodel_register_device_factory_service(&ni_objectmodel_vlan_factory_service);
	ni_objectmodel_register_device_factory_service(&ni_objectmodel_tun_factory_service);
	ni_objectmodel_register_device_factory_service(&ni_objectmodel_openvpn_factory_service);

	/* Register all builtin naming services */
	ni_objectmodel_register_ns_builtin();
}

static void
ni_objectmodel_register_device_factory_service(ni_dbus_service_t *svc)
{
	svc->compatible = &ni_objectmodel_netif_list_class;
	ni_objectmodel_register_service(svc);
}

static void
ni_objectmodel_register_device_service(ni_iftype_t iftype, ni_dbus_service_t *svc)
{
	if (iftype == NI_IFTYPE_UNKNOWN)
		svc->compatible = &ni_objectmodel_netif_class;
	else
		svc->compatible = ni_objectmodel_get_class(ni_objectmodel_link_classname(iftype));
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

	/* Register com.suse.Wicked.Interface, which is the list of all interfaces */
	object = ni_dbus_server_register_object(server, "Interface",
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
ni_objectmodel_resolve_name(ni_dbus_object_t *parent, const char *naming_service, const char *attribute, const ni_dbus_variant_t *var)
{
	ni_dbus_object_t *result = NULL;
	ni_objectmodel_ns_t *ns;
	ni_var_array_t attrs = { 0, NULL };
	const char *key, *value;

	if (!(ns = ni_objectmodel_get_ns(naming_service))) {
		ni_warn("unknown naming service \"%s\"", naming_service);
		return NULL;
	}

	if (ni_dbus_variant_get_string(var, &value)) {
		if (attribute == NULL) {
			if (ns->lookup_by_name == NULL)
				return NULL;
			return ns->lookup_by_name(ns, value);
		}

		/* A single attribute.
		 * <foo:bar>blabla</foo:bar> is a shorthand for
		 * "query naming service foo, asking for interfaces with
		 * attribute "bar" equal to "blabla". This is the same as
		 *  <foo>
		 *    <bar>blabla</bar>
		 *  </foo>
		 */
		ni_var_array_set(&attrs, attribute, value);
	} else {
		/* Loop over all dict entries and append them to the var array */
		const ni_dbus_variant_t *dict = var;
		unsigned int i = 0;

		while ((var = ni_dbus_dict_get_entry(dict, i++, &key)) != NULL) {
			if (!ni_dbus_variant_get_string(var, &value))
				return NULL;
			ni_var_array_set(&attrs, key, value);
		}
	}

	result = ni_objectmodel_lookup_by_attrs(parent, ns, &attrs);
	ni_var_array_destroy(&attrs);

	return result;
}

/*
 * InterfaceList.identifyDevice
 */
static dbus_bool_t
ni_objectmodel_netif_list_identify_device(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	const ni_dbus_variant_t *dict, *var;
	const char *name;
	char *copy, *naming_service, *attribute;
	ni_dbus_object_t *found;

	ni_assert(argc == 1);
	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);
	dict = &argv[0];

	if ((var = ni_dbus_dict_get_entry(dict, 0, &name)) == NULL)
		goto invalid_args;

	ni_debug_dbus("%s(name=%s)", __func__, name);
	copy = naming_service = strdup(name);
	if ((attribute = strchr(copy, ':')) != NULL)
		*attribute++ = '\0';

	found = ni_objectmodel_resolve_name(object, naming_service, attribute, var);
	free(copy);

	if (found == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_DEVICE_NOT_KNOWN,
				"unable to identify interface via %s", name);
		return FALSE;
	}

	if (ni_objectmodel_unwrap_netif(found, NULL) == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_DEVICE_NOT_KNOWN,
				"failed to identify interface via %s - naming service returned "
				"a %s object", name, found->class->name);
		return FALSE;
	}

	ni_dbus_message_append_string(reply, found->path);
	return TRUE;

invalid_args:
	return ni_dbus_error_invalid_args(error, object->path, method->name);
}

static ni_dbus_method_t		ni_objectmodel_netif_list_methods[] = {
	{ "identifyDevice",	"a{sv}",	ni_objectmodel_netif_list_identify_device },
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

/*
 * Build a dbus-object encapsulating a network device.
 * If @server is non-NULL, register the object with a canonical object path
 */
static ni_dbus_object_t *
__ni_objectmodel_build_netif_object(ni_dbus_server_t *server, ni_netdev_t *dev, const ni_dbus_class_t *requested_class)
{
	const char *classname;
	const ni_dbus_class_t *class = NULL;
	ni_dbus_object_t *object;

	if ((classname = ni_objectmodel_link_classname(dev->link.type)) != NULL)
		class = ni_objectmodel_get_class(classname);
	if (class == NULL)
		class = &ni_objectmodel_netif_class;

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

	dev = ni_netdev_new(NULL, NULL, 0);
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
 * Interface.linkUp(dict options)
 *
 * Bring up the network interface, and assign the requested addresses.
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
		/* Link is not up yet. Tell the caller to wait for an event. */
		if (ni_uuid_is_null(&dev->link.event_uuid))
			ni_uuid_generate(&dev->link.event_uuid);
		ret = __ni_objectmodel_return_callback_info(reply, NI_EVENT_LINK_UP, &dev->link.event_uuid, error);
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
 * Broadcast an interface event
 * The optional uuid argument helps the client match e.g. notifications
 * from an addrconf service against its current state.
 */
dbus_bool_t
ni_objectmodel_netif_event(ni_dbus_server_t *server, ni_netdev_t *dev,
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

	return __ni_objectmodel_device_event(server, object, NI_OBJECTMODEL_NETIF_INTERFACE, ifevent, uuid);
}

dbus_bool_t
__ni_objectmodel_device_event(ni_dbus_server_t *server, ni_dbus_object_t *object,
			const char *interface, ni_event_t ifevent, const ni_uuid_t *uuid)
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

	ni_debug_dbus("sending device event \"%s\" for %s", signal_name, ni_dbus_object_get_path(object));
	ni_dbus_server_send_signal(server, object, interface, signal_name, argc, &arg);

	ni_dbus_variant_destroy(&arg);
	return TRUE;
}

const char *
__ni_objectmodel_event_to_signal(ni_event_t event)
{
	static const char *ifevent_signals[__NI_EVENT_MAX] = {
	[NI_EVENT_DEVICE_UP]		= "deviceUp",
	[NI_EVENT_DEVICE_DOWN]		= "deviceDown",
	[NI_EVENT_LINK_ASSOCIATED]	= "linkAssociated",
	[NI_EVENT_LINK_ASSOCIATION_LOST]= "linkAssociationLost",
	[NI_EVENT_LINK_UP]		= "linkUp",
	[NI_EVENT_LINK_DOWN]		= "linkDown",
	[NI_EVENT_NETWORK_UP]		= "networkUp",
	[NI_EVENT_NETWORK_DOWN]		= "networkDown",
	[NI_EVENT_ADDRESS_ACQUIRED]	= "addressAcquired",
	[NI_EVENT_ADDRESS_RELEASED]	= "addressReleased",
	[NI_EVENT_ADDRESS_LOST]		= "addressLost",
	[NI_EVENT_RESOLVER_UPDATED]	= "resolverUpdated",
	};

	if (event >= __NI_EVENT_MAX)
		return NULL;

	return ifevent_signals[event];
}

/*
 * A new DBus object encapsulating a dummy netdev is created.
 * This is called on the client side from GetManagedObject
 */
static void
ni_objectmodel_netif_initialize(ni_dbus_object_t *object)
{
	ni_assert(object->handle == NULL);
	object->handle = ni_netdev_new(NULL, NULL, 0);
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
	{ NULL }
};

/*
 * Interface property handlers
 */
static void *
ni_objectmodel_get_netdev(const ni_dbus_object_t *object, DBusError *error)
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
 * Get/set afinfo
 */
static dbus_bool_t
__ni_objectmodel_get_afinfo(ni_afinfo_t *afi, ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_dict_add_bool(dict, "enabled", afi->enabled);
	ni_dbus_dict_add_bool(dict, "forwarding", afi->forwarding);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_set_afinfo(ni_afinfo_t *afi, const ni_dbus_variant_t *dict, DBusError *error)
{
	dbus_bool_t value;

	if (ni_dbus_dict_get_bool(dict, "enabled", &value))
		afi->enabled = value;
	if (ni_dbus_dict_get_bool(dict, "forwarding", &value))
		afi->forwarding = value;

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_get_ipv4(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	return __ni_objectmodel_get_afinfo(&dev->ipv4, argument, error);
}

static dbus_bool_t
__ni_objectmodel_netif_set_ipv4(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	return __ni_objectmodel_set_afinfo(&dev->ipv4, argument, error);
}

static dbus_bool_t
__ni_objectmodel_netif_get_ipv6(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	return __ni_objectmodel_get_afinfo(&dev->ipv6, argument, error);
}

static dbus_bool_t
__ni_objectmodel_netif_set_ipv6(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	return __ni_objectmodel_set_afinfo(&dev->ipv6, argument, error);
}

#define NETIF_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __ni_objectmodel_netif, rw)
#define NETIF_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __ni_objectmodel_netif, rw)
#define NETIF_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev, dbus_name, member_name, rw)
#define NETIF_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(netdev, dbus_name, member_name, rw)

#ifndef NI_DBUS_DICT_ARRAY_SIGNATURE
# define NI_DBUS_DICT_ARRAY_SIGNATURE DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE
#endif
#ifndef NI_DBUS_BYTE_ARRAY_SIGNATURE
# define NI_DBUS_BYTE_ARRAY_SIGNATURE DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING
#endif

static ni_dbus_property_t	ni_objectmodel_netif_properties[] = {
	NETIF_STRING_PROPERTY(name, name, RO),
	NETIF_UINT_PROPERTY(index, link.ifindex, RO),
	NETIF_UINT_PROPERTY(status, link.ifflags, RO),
	NETIF_UINT_PROPERTY(link-type, link.type, RO),
	NETIF_UINT_PROPERTY(mtu, link.mtu, RO),
	NETIF_UINT_PROPERTY(txqlen, link.txqlen, RO),
	NETIF_STRING_PROPERTY(alias, link.alias, RO),

	NETIF_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv4, RO),
	NETIF_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv6, RO),

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
ni_objectmodel_get_netdev_req(const ni_dbus_object_t *object, DBusError *error)
{
	/* FIXME: check for object class */
	return ni_dbus_object_get_handle(object);
}

/*
 * Property InterfaceRequest.ipv4
 */
static dbus_bool_t
__ni_objectmodel_netif_request_get_ipv4(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_req_t *req = ni_dbus_object_get_handle(object);

	ni_dbus_variant_init_dict(result);
	if (req->ipv4 && !__ni_objectmodel_get_afinfo(req->ipv4, result, error))
		return FALSE;
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_request_set_ipv4(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_req_t *req = ni_dbus_object_get_handle(object);

	if (!req->ipv4)
		req->ipv4 = ni_afinfo_new(AF_INET);
	if (!__ni_objectmodel_set_afinfo(req->ipv4, argument, error))
		return FALSE;
	return TRUE;
}

/*
 * Property InterfaceRequest.ipv6
 */
static dbus_bool_t
__ni_objectmodel_netif_request_get_ipv6(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_req_t *req = ni_dbus_object_get_handle(object);

	if (req->ipv6 && !__ni_objectmodel_get_afinfo(req->ipv6, result, error))
		return FALSE;
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_request_set_ipv6(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_req_t *req = ni_dbus_object_get_handle(object);

	if (!req->ipv6)
		req->ipv6 = ni_afinfo_new(AF_INET6);
	if (!__ni_objectmodel_set_afinfo(req->ipv6, argument, error))
		return FALSE;
	return TRUE;
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

	NETIF_REQUEST_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv4, RO),
	NETIF_REQUEST_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, ipv6, RO),

	{ NULL }
};

