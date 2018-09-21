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
#include "xml-schema.h"
#include "appconfig.h"
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
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv4_auto_service;
extern ni_dbus_service_t	ni_objectmodel_addrconf_ipv6_auto_service;
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
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv4_auto_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_addrconf_ipv6_auto_service);

	/* LLDP agent */
	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_lldp_service);

	ni_objectmodel_register_netif_service(NI_IFTYPE_UNKNOWN, &ni_objectmodel_ethtool_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_ETHERNET, &ni_objectmodel_ethernet_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_VLAN, &ni_objectmodel_vlan_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_VXLAN, &ni_objectmodel_vxlan_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_MACVLAN, &ni_objectmodel_macvlan_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_MACVTAP, &ni_objectmodel_macvtap_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_DUMMY, &ni_objectmodel_dummy_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_BOND, &ni_objectmodel_bond_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_TEAM, &ni_objectmodel_team_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_BRIDGE, &ni_objectmodel_bridge_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_OVS_BRIDGE, &ni_objectmodel_ovs_bridge_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_WIRELESS, &ni_objectmodel_wireless_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_TUN, &ni_objectmodel_tun_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_TAP, &ni_objectmodel_tap_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_SIT, &ni_objectmodel_sit_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_IPIP, &ni_objectmodel_ipip_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_GRE, &ni_objectmodel_gre_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_INFINIBAND, &ni_objectmodel_ibparent_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_INFINIBAND_CHILD, &ni_objectmodel_ibchild_service);
	ni_objectmodel_register_netif_service(NI_IFTYPE_PPP, &ni_objectmodel_ppp_service);

	if (ni_config_teamd_enabled())
		ni_objectmodel_register_netif_factory_service(&ni_objectmodel_team_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_bond_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_bridge_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_ovs_bridge_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_vlan_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_vxlan_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_macvlan_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_macvtap_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_dummy_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_tun_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_tap_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_ibchild_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_sit_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_ipip_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_gre_factory_service);
	ni_objectmodel_register_netif_factory_service(&ni_objectmodel_ppp_factory_service);

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
	/* We're notified about automatically via RTM_NEW/DELLINK */
	(void)object;

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

/*
 * InterfaceList.getAddresses
 */
static dbus_bool_t
ni_objectmodel_netif_list_get_addresses_args(const ni_dbus_variant_t *args,
					dbus_bool_t *refresh, unsigned int *family,
					ni_tristate_t *tentative, ni_tristate_t *duplicate)
{
	dbus_bool_t bv;
	uint32_t u32;

	if (!ni_dbus_variant_is_dict(args))
			return FALSE;

	ni_dbus_dict_get_bool(args, "refresh", refresh);

	if (ni_dbus_dict_get_uint32(args, "family", &u32))
		*family = u32;

	if (ni_dbus_dict_get_bool(args, "tentative", &bv))
		ni_tristate_set(tentative, bv);

	if (ni_dbus_dict_get_bool(args, "duplicate", &bv))
		ni_tristate_set(duplicate, bv);

	return TRUE;
}

static dbus_bool_t
match_netif_list_get_addresses_tristate(ni_tristate_t want, dbus_bool_t flag)
{
	if (ni_tristate_is_set(want)) {
		/* include if flag set */
		if (ni_tristate_is_enabled(want) && !flag)
			return FALSE;

		/* exclude if flag set */
		if (ni_tristate_is_disabled(want) && flag)
			return FALSE;
	}
	return TRUE;
}

static dbus_bool_t
match_netif_list_get_addresses_filter(const ni_address_t *ap, unsigned int family,
				ni_tristate_t tentative, ni_tristate_t duplicate)
{
	if (family != AF_UNSPEC && (family != ap->family))
		return FALSE;

	if (!match_netif_list_get_addresses_tristate(tentative, ni_address_is_tentative(ap)))
		return FALSE;

	if (!match_netif_list_get_addresses_tristate(duplicate, ni_address_is_duplicate(ap)))
		return FALSE;

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_netif_list_get_addresses(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_tristate_t duplicate = NI_TRISTATE_DEFAULT;
	ni_tristate_t tentative = NI_TRISTATE_DEFAULT;
	unsigned int family = AF_UNSPEC;
	dbus_bool_t refresh = TRUE;
	ni_netdev_t *dev;
	dbus_bool_t rv;

	if (!reply || !argv || argc != 1 ||
	    !ni_objectmodel_netif_list_get_addresses_args(&argv[0], &refresh, &family,
							  &tentative, &duplicate)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s: invalid refresh and filter argument dict",
				object->path, method->name);
		return FALSE;
	}

	NI_TRACE_ENTER_ARGS("refresh=%s, family=%s, tentative=%s, duplicate=%s",
			ni_format_boolean(refresh),
			ni_addrfamily_type_to_name(family),
			tentative == NI_TRISTATE_DEFAULT ? "ignored" :
			tentative == NI_TRISTATE_DISABLE ? "exclude" :
			tentative == NI_TRISTATE_ENABLE  ? "include" : NULL,
			duplicate == NI_TRISTATE_DEFAULT ? "ignored" :
			duplicate == NI_TRISTATE_DISABLE ? "exclude" :
			duplicate == NI_TRISTATE_ENABLE  ? "include" : NULL);

	/* if refresh, then all (it updates default state);
	 * just return a filtered result when requested ...
	 */
	if (refresh && (!nc || __ni_system_refresh_addrs(nc, AF_UNSPEC) < 0)) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to refresh address list");
		return FALSE;
	}

	ni_dbus_variant_init_dict(&result);
	for (dev = nc ? ni_netconfig_devlist(nc) : NULL; dev; dev = dev->next) {
		ni_dbus_variant_t *addresses = NULL;
		const ni_address_t *ap;
		const char *path;

		path = ni_objectmodel_netif_full_path(dev);
		if (ni_string_empty(path))
			continue;

		for (ap = dev->addrs; ap; ap = ap->next) {
			ni_dbus_variant_t *dict;

			/* some sanity checks ... */
			if (ap->family == AF_UNSPEC)
				continue;
			if (ap->family != ap->local_addr.ss_family)
				continue;

			if (!match_netif_list_get_addresses_filter(ap,
						family, tentative, duplicate))
				continue;

			if (!addresses) {
				if (!(dict = ni_dbus_dict_add(&result, path)))
					break;

				ni_dbus_variant_init_dict(dict);
				ni_dbus_dict_add_string(dict, "name",  dev->name);
				ni_dbus_dict_add_uint32(dict, "index", dev->link.ifindex);
				ni_dbus_dict_add_uint32(dict, "status", dev->link.ifflags);

				if (!(addresses = ni_dbus_dict_add(dict, "addresses")))
					break;
				ni_dbus_dict_array_init(addresses);
			}

			if ((dict = ni_dbus_dict_array_add(addresses)))
				__ni_objectmodel_address_to_dict(ap, dict);
		}
	}

	rv = ni_dbus_message_serialize_variants(reply, 1, &result, error);
	ni_dbus_variant_destroy(&result);
	return rv;
}

static ni_dbus_method_t		ni_objectmodel_netif_list_methods[] = {
	{ "deviceByName",	"s",		.handler = ni_objectmodel_netif_list_device_by_name },
	{ "identifyDevice",	"sa{sv}",	.handler = ni_objectmodel_netif_list_identify_device },
	{ "getAddresses",	"a{sv}",	.handler = ni_objectmodel_netif_list_get_addresses },
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

	if (object == NULL) {
		ni_error("Unable to create dbus object for network interface %s", dev->name);
		return NULL;
	}

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
	ni_netdev_t *dev;

	if (!object) {
		if (error)
			dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot unwrap network interface from a NULL dbus object");
		return NULL;
	}

	dev = object->handle;
	if (ni_dbus_object_isa(object, &ni_objectmodel_netif_class))
		return dev;
	if (error)
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"method not compatible with object %s of class %s (not a network interface)",
				object->path, object->class->name);
	return NULL;
}

ni_netdev_req_t *
ni_objectmodel_unwrap_netif_request(const ni_dbus_object_t *object, DBusError *error)
{
	ni_netdev_req_t *req;

	if (!object) {
		if (error)
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Cannot unwrap network interface request from a NULL dbus object");
		return NULL;
	}

	req = object->handle;
	if (ni_dbus_object_isa(object, &ni_objectmodel_ifreq_class))
		return req;
	if (error)
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"method not compatible with object %s of class %s (not a network interface request)",
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
	ni_netconfig_t *nc = ni_global_state_handle(0);
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

	if (req->mtu) {
		if (dev->link.lowerdev.index) {
			ni_netdev_t *lower;

			lower = ni_netdev_by_index(nc, dev->link.lowerdev.index);
			if (lower && req->mtu > lower->link.mtu) {
				ni_info("Lowering requested %s mtu %u to lower device mtu %u",
					dev->name, req->mtu, lower->link.mtu);
				req->mtu = lower->link.mtu;
			}
		}

		if  (req->mtu != dev->link.mtu)
		     ni_system_mtu_change(nc, dev, req->mtu);

		req->mtu = 0;
	}

	req->ifflags = NI_IFF_LINK_UP | NI_IFF_NETWORK_UP;
	if ((rv = ni_system_interface_link_change(dev, req)) < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"failed to configure interface %s", dev->name);
		ret = FALSE;
		goto failed;
	}

	ret = TRUE;

	/* When device's link is administatively UP already, no callback is needed.
	 * Otherwise let the caller wait until the kernel sends event with an "ACK"
	 * with the link UP flag.
	 *
	 * Note: This method sets the UP flag (device-up) and *triggers* a link
	 * (carrier) negotiation / detection in the kernel, causing to reach the
	 * link-up automatically once the negotiation/detection finished.
	 */
	if (!ni_netdev_device_is_up(dev)) {
		const ni_uuid_t *uuid;

		/* Link has been administatively set UP. Tell the caller to wait for an event. */
		uuid = ni_netdev_add_event_filter(dev, (1 << NI_EVENT_DEVICE_UP) | (1 << NI_EVENT_DEVICE_DOWN));
		ret = __ni_objectmodel_return_callback_info(reply, NI_EVENT_DEVICE_UP, uuid, NULL, error);
	}

failed:
	if (req)
		ni_netdev_req_free(req);
	return ret;
}

static dbus_bool_t
ni_objectmodel_netif_wait_link_up(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	const ni_uuid_t *uuid;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	/* Create an interface_request object and extract configuration from dict */
	if (argc != 0)
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	if (!ni_netdev_device_is_up(dev))
		return FALSE;

	if (ni_netdev_link_is_up(dev))
		return TRUE;

	/* Do not wait for slaves, master provides the link state */
	if (dev->link.masterdev.index)
		return TRUE;

	/*
	 * Device is up and link negotiation is triggered, but isn't finished yet.
	 * Tell the caller to wait until link-up event.
	 */
	uuid = ni_netdev_add_event_filter(dev,  (1 << NI_EVENT_LINK_UP) | (1 << NI_EVENT_LINK_DOWN));

	return __ni_objectmodel_return_callback_info(reply, NI_EVENT_LINK_UP, uuid, NULL, error);
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

	if (ni_netdev_device_is_up(dev)) {
		const ni_uuid_t *uuid;

		uuid = ni_netdev_add_event_filter(dev, (1 << NI_EVENT_DEVICE_DOWN));

		return __ni_objectmodel_return_callback_info(reply, NI_EVENT_DEVICE_DOWN, uuid, NULL, error);
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
	ni_addrconf_lease_t *lease = NULL;
	dbus_bool_t ret = FALSE;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	/* Create an interface_request object and extract configuration from dict */
	if (argc != 1)
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	lease = ni_addrconf_lease_new(NI_ADDRCONF_INTRINSIC, AF_INET);

	/* Set the lease information from the argument dict.
	 * This can overwrite the lease type and addrfamily.
	 */
	{
		const ni_dbus_variant_t *dict = &argv[0], *child;
		uint32_t value32;

		if (ni_dbus_dict_get_uint32(dict, "type", &value32))
			lease->type = value32;
		if (ni_dbus_dict_get_uint32(dict, "family", &value32))
			lease->family = value32;
		lease->update = ~0;

		child = ni_dbus_dict_get(dict, "lease");
		if (child == NULL)
			lease->state = NI_ADDRCONF_STATE_RELEASED;
		else
		if (!__ni_objectmodel_set_addrconf_lease(lease, child, error))
			goto failed;
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
	rv = __ni_system_interface_update_lease(dev, &lease, __NI_EVENT_MAX);
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

static void
__ni_objectmodel_netif_set_client_state_save_trigger(ni_netdev_t *dev)
{
	if (dev && dev->client_state) {
		ni_client_state_save(dev->client_state, dev->link.ifindex);
		ni_debug_dbus("saving %s structure into a file for %s",
			NI_CLIENT_STATE_XML_NODE, dev->name);
	}
}

/*
 * Interface.setClientControl()
 *
 * This is used by clients to record control flags
 */
static dbus_bool_t
ni_objectmodel_netif_set_client_state_control(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	ni_client_state_t *cs;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	cs = ni_netdev_get_client_state(dev);
	if (!ni_objectmodel_netif_client_state_control_from_dict(&cs->control, &argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	__ni_objectmodel_netif_set_client_state_save_trigger(dev);
	return TRUE;
}

/*
 * Interface.setClientConfig()
 *
 * This is used by clients to record configuration origin and UUID
 */
static dbus_bool_t
ni_objectmodel_netif_set_client_state_config(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	ni_client_state_t *cs;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	cs = ni_netdev_get_client_state(dev);
	if (!ni_objectmodel_netif_client_state_config_from_dict(&cs->config, &argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	__ni_objectmodel_netif_set_client_state_save_trigger(dev);
	return TRUE;
}

/*
 * Interface.setClientScripts()
 *
 * This method is used by the client to record script set.
 */
static dbus_bool_t
ni_objectmodel_netif_set_client_state_scripts(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	xml_node_t *args;
	ni_client_state_t *cs;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	if (!(args = ni_dbus_xml_deserialize_arguments(method, 1, &argv[0], NULL, NULL)))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	cs = ni_netdev_get_client_state(dev);
	ni_client_state_scripts_parse_xml(args, &cs->scripts);
	xml_node_free(args);

	__ni_objectmodel_netif_set_client_state_save_trigger(dev);
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

	ni_debug_dbus("sending device event \"%s\" for %s; uuid=<%s>", signal_name,
			ni_dbus_object_get_path(object), uuid ? ni_uuid_print(uuid) : "");
	ni_dbus_server_send_signal(server, object, interface, signal_name, argc, &arg);

	ni_dbus_variant_destroy(&arg);
	return TRUE;
}

static ni_intmap_t	__ni_objectmodel_event_names[] = {
	{ "deviceCreate",		NI_EVENT_DEVICE_CREATE },
	{ "deviceDelete",		NI_EVENT_DEVICE_DELETE },
	{ "deviceChange",		NI_EVENT_DEVICE_CHANGE },
	{ "deviceRename",		NI_EVENT_DEVICE_RENAME },
	{ "deviceReady",		NI_EVENT_DEVICE_READY },
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
	{ "addressDeferred",		NI_EVENT_ADDRESS_DEFERRED },
	{ "addressLost",		NI_EVENT_ADDRESS_LOST },
	{ "resolverUpdated",		NI_EVENT_RESOLVER_UPDATED },
	{ "hostnameUpdated",		NI_EVENT_HOSTNAME_UPDATED },
	{ "genericUpdated",		NI_EVENT_GENERIC_UPDATED },

	{ NULL, 0 }
};

static dbus_bool_t
ni_objectmodel_netif_wait_device_ready(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	const ni_uuid_t *uuid;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);

	/* Create an interface_request object and extract configuration from dict */
	if (argc != 0)
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	if (ni_netdev_device_is_up(dev))
		return TRUE;

	if (!ni_server_listens_uevents())
		return TRUE;

	if (ni_netdev_device_is_ready(dev))
		return TRUE;

	/* Device is not yet ready. Tell the caller to wait for an event. */
	uuid = ni_netdev_add_event_filter(dev,  (1 << NI_EVENT_DEVICE_READY) |
						(1 << NI_EVENT_DEVICE_UP));

	return __ni_objectmodel_return_callback_info(reply, NI_EVENT_DEVICE_READY, uuid, NULL, error);
}

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
	ni_client_state_drop(ifp->link.ifindex);
	ni_netdev_put(ifp);
}

static ni_dbus_method_t		ni_objectmodel_netif_methods[] = {
	{ "linkUp",		"a{sv}",	.handler = ni_objectmodel_netif_link_up },
	{ "linkDown",		"",		.handler = ni_objectmodel_netif_link_down },
	{ "installLease",	"a{sv}",	.handler = ni_objectmodel_netif_install_lease },
	{ "setClientControl",	"a{sv}",	.handler = ni_objectmodel_netif_set_client_state_control },
	{ "setClientConfig",	"a{sv}",	.handler = ni_objectmodel_netif_set_client_state_config },
	{ "setClientScripts",	"a{sv}",	.handler = ni_objectmodel_netif_set_client_state_scripts },
	{ "linkMonitor",	"",		.handler = ni_objectmodel_netif_link_monitor },
	{ "getNames",		"",		.handler = ni_objectmodel_netif_get_names },
	{ "clearEventFilters",	"",		.handler = ni_objectmodel_netif_clear_event_filters },
	{ "waitDeviceReady",	"",		.handler = ni_objectmodel_netif_wait_device_ready },
	{ "waitLinkUp",		"",		.handler = ni_objectmodel_netif_wait_link_up },
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
 * Property Interface.client_state
 */
static dbus_bool_t
__ni_objectmodel_netif_get_client_state(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *dev = ni_dbus_object_get_handle(object);
	ni_client_state_t *cs = NULL;

	if (dev)
		cs = dev->client_state;

	if (!cs)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	ni_dbus_variant_init_dict(result);
	return ni_objectmodel_netif_client_state_to_dict(cs, result);
}

dbus_bool_t
ni_objectmodel_netif_client_state_to_dict(const ni_client_state_t *cs, ni_dbus_variant_t *dict)
{
	if (!cs || !dict)
		return FALSE;

	if (!ni_objectmodel_netif_client_state_control_to_dict(&cs->control, dict) ||
	    !ni_objectmodel_netif_client_state_config_to_dict(&cs->config, dict))
		return FALSE;

	ni_objectmodel_netif_client_state_scripts_to_dict(&cs->scripts, dict);
	return TRUE;
}

dbus_bool_t
ni_objectmodel_netif_client_state_control_to_dict(const ni_client_state_control_t *ctrl, ni_dbus_variant_t *dict)
{
	ni_dbus_variant_t *var;

	if (!ctrl || !dict)
		return FALSE;

	if (!(var = ni_dbus_dict_add(dict, NI_CLIENT_STATE_XML_CONTROL_NODE)))
		return FALSE;
	ni_dbus_variant_init_dict(var);

	if (!ni_dbus_dict_add_bool(var, NI_CLIENT_STATE_XML_PERSISTENT_NODE,
	    (dbus_bool_t) ctrl->persistent)) {
		return FALSE;
	}

	if (!ni_dbus_dict_add_bool(var, NI_CLIENT_STATE_XML_USERCONTROL_NODE,
	    (dbus_bool_t) ctrl->usercontrol)) {
		return FALSE;
	}

	if (ni_tristate_is_set(ctrl->require_link)) {
		if (!ni_dbus_dict_add_bool(var, NI_CLIENT_STATE_XML_REQUIRE_LINK_NODE,
			(dbus_bool_t) ni_tristate_is_disabled(ctrl->require_link))) {
			return FALSE;
		}
	}

	return TRUE;
}

dbus_bool_t
ni_objectmodel_netif_client_state_config_to_dict(const ni_client_state_config_t *conf, ni_dbus_variant_t *dict)
{
	ni_dbus_variant_t *var;

	if (!conf || !dict)
		return FALSE;

	if (!(var = ni_dbus_dict_add(dict, NI_CLIENT_STATE_XML_CONFIG_NODE)))
		return FALSE;
	ni_dbus_variant_init_dict(var);

	if (!ni_dbus_dict_add_string(var, NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE,
	    conf->origin)) {
		return FALSE;
	}

	if (!ni_dbus_dict_add_byte_array(var, NI_CLIENT_STATE_XML_CONFIG_UUID_NODE,
	    conf->uuid.octets, sizeof(conf->uuid.octets))) {
		return FALSE;
	}

	if (!ni_dbus_dict_add_uint32(var, NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE,
	    conf->owner)) {
		return FALSE;
	}

	return TRUE;
}

dbus_bool_t
ni_objectmodel_netif_client_state_scripts_to_dict(const ni_client_state_scripts_t *scripts, ni_dbus_variant_t *dict)
{
	ni_dbus_variant_t *sv, *tv;
	xml_node_t *tn, *sn;

	if (!scripts || !dict)
		return FALSE;

	if (!scripts->node || !scripts->node->children)
		return TRUE;

	if (!ni_string_eq(scripts->node->name, NI_CLIENT_STATE_XML_SCRIPTS_NODE))
		return FALSE;

	if (!(sv = ni_dbus_dict_add(dict, scripts->node->name)))
		return FALSE;

	ni_dbus_variant_init_dict(sv);
	for (tn = scripts->node->children; tn; tn = tn->next) {
		if (!tn->children || !(tv = ni_dbus_dict_add(sv, tn->name)))
			continue;

		ni_dbus_variant_init_dict(tv);
		for (sn = tn->children; sn; sn = sn->next) {
			if (!sn->name || !sn->cdata)
				continue;
			ni_dbus_dict_add_string(tv, sn->name, sn->cdata);
		}
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netif_set_client_state(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev = ni_dbus_object_get_handle(object);
	ni_client_state_t *cs;

	cs = ni_netdev_get_client_state(dev);
	if (!ni_objectmodel_netif_client_state_from_dict(cs, argument)) {
		ni_netdev_set_client_state(dev, NULL);
		return FALSE;
	}

	return TRUE;
}

dbus_bool_t
ni_objectmodel_netif_client_state_from_dict(ni_client_state_t *cs, const ni_dbus_variant_t *dict)
{
	ni_assert(cs && dict);

	if (!ni_objectmodel_netif_client_state_control_from_dict(&cs->control, dict) ||
	    !ni_objectmodel_netif_client_state_config_from_dict(&cs->config, dict))
		return FALSE;

	ni_objectmodel_netif_client_state_scripts_from_dict(&cs->scripts, dict);
	return TRUE;
}

dbus_bool_t
ni_objectmodel_netif_client_state_control_from_dict(ni_client_state_control_t *ctrl, const ni_dbus_variant_t *dict)
{
	const ni_dbus_variant_t *var;
	dbus_bool_t val;

	if (!(var = ni_dbus_dict_get(dict, NI_CLIENT_STATE_XML_CONTROL_NODE)))
		return FALSE;

	if (ni_dbus_dict_get_bool(var, NI_CLIENT_STATE_XML_PERSISTENT_NODE, &val))
		ctrl->persistent = val;

	if (ni_dbus_dict_get_bool(var, NI_CLIENT_STATE_XML_USERCONTROL_NODE, &val))
		ctrl->usercontrol = val;

	if (ni_dbus_dict_get_bool(var, NI_CLIENT_STATE_XML_REQUIRE_LINK_NODE, &val))
		ni_tristate_set(&ctrl->require_link, val);
	else
		ctrl->require_link = NI_TRISTATE_DEFAULT;

	return TRUE;
}

dbus_bool_t
ni_objectmodel_netif_client_state_config_from_dict(ni_client_state_config_t *conf, const ni_dbus_variant_t *dict)
{
	const ni_dbus_variant_t *var, *child;
	const char *sval;

	if (!(var = ni_dbus_dict_get(dict, NI_CLIENT_STATE_XML_CONFIG_NODE)))
		return FALSE;

	if (!(child = ni_dbus_dict_get(var, NI_CLIENT_STATE_XML_CONFIG_UUID_NODE)))
		return FALSE;

	if (!ni_dbus_variant_get_uuid(child, &conf->uuid))
		return FALSE;

	if (ni_dbus_dict_get_string(var,
	    NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE, &sval)) {
		ni_string_dup(&conf->origin, sval);
	}
	else
		return FALSE;

	if (!ni_dbus_dict_get_uint32(var, NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE,
	    &conf->owner)) {
		return FALSE;
	}

	return TRUE;
}

dbus_bool_t
ni_objectmodel_netif_client_state_scripts_from_dict(ni_client_state_scripts_t *scripts, const ni_dbus_variant_t *dict)
{
	const ni_dbus_variant_t *sv, *tv;
	const char *key, *script;
	unsigned int t, s;
	xml_node_t *tn;

	if (!(dict = ni_dbus_dict_get(dict, NI_CLIENT_STATE_XML_SCRIPTS_NODE)))
		return FALSE;

	ni_client_state_scripts_reset(scripts);
	scripts->node = xml_node_new(NI_CLIENT_STATE_XML_SCRIPTS_NODE, NULL);

	for (t = 0; (tv = ni_dbus_dict_get_entry(dict, t, &key)) ; ++t) {
		if (!key || !ni_dbus_variant_is_dict(tv))
			continue;

		tn = xml_node_new(key, scripts->node);
		for (s = 0; (sv = ni_dbus_dict_get_entry(tv, s, &key)); ++s) {
			if (!key || !ni_dbus_variant_get_string(sv, &script))
				continue;
			xml_node_new_element(key, tn, script);
		}
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
				client-state, client_state,
				__ni_objectmodel_netif, RO),

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

static dbus_bool_t
__ni_objectmodel_netdev_req_get_port(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	const ni_netdev_req_t *req;
	ni_dbus_variant_t *dict;
	const char *name;

	if (!(req = ni_objectmodel_unwrap_netif_request(object, error)))
		return FALSE;
	if (!req->port)
		return FALSE;

	switch (req->port->type) {
	case NI_IFTYPE_TEAM:
	case NI_IFTYPE_BOND:
	case NI_IFTYPE_BRIDGE:
	case NI_IFTYPE_OVS_BRIDGE:
		if ((name = ni_linktype_type_to_name(req->port->type)))
			break;
		/* fall through */
	default:
		return ni_dbus_error_property_not_present(error, object->path, property->name);
	}

	ni_dbus_variant_init_struct(result);
	ni_dbus_struct_add_string(result, name);
	dict = ni_dbus_struct_add(result);
	ni_dbus_variant_init_dict(dict);

	switch (req->port->type) {
	case NI_IFTYPE_TEAM: {
			const ni_team_port_config_t *pconf = &req->port->team;

			if (!__ni_objectmodel_get_team_port_config(pconf, dict, error))
				return FALSE;
		}
		break;

	case NI_IFTYPE_OVS_BRIDGE: {
			const ni_ovs_bridge_port_config_t *pconf = &req->port->ovsbr;

			if (!__ni_objectmodel_get_ovs_bridge_port_config(pconf, dict, error))
				return FALSE;
		}
		break;

	case NI_IFTYPE_BOND:
	case NI_IFTYPE_BRIDGE:
	default:
		break;
	}
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_netdev_req_set_port(ni_dbus_object_t *object, const ni_dbus_property_t *property,
					const ni_dbus_variant_t *argument, DBusError *error)
{
	const ni_dbus_variant_t *dict;
	ni_netdev_req_t *req;
	const char *name;
	ni_iftype_t type;

	if (!(req = ni_objectmodel_unwrap_netif_request(object, error)))
		return FALSE;

	if (!ni_dbus_struct_get_string(argument, 0, &name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad value for property %s; missed type", property->name);
		return FALSE;
	}

	type = ni_linktype_name_to_type(name);
	switch (type) {
	case NI_IFTYPE_TEAM:
	case NI_IFTYPE_BOND:
	case NI_IFTYPE_BRIDGE:
	case NI_IFTYPE_OVS_BRIDGE:
		break;
	default:
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"bad value for property %s; unsupported type %s", property->name, name);
		return FALSE;
	}

	if (!(dict = ni_dbus_struct_get(argument, 1))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "missed netdev request port member dict");
		return FALSE;
	}
	if (!ni_dbus_variant_is_dict(dict)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "netdev request port data is not a dict");
		return FALSE;
	}

	if (req->port)
		ni_netdev_port_req_free(req->port);
	if (!(req->port = ni_netdev_port_req_new(type))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "unable to allocate netdev request %s port data", name);
		return FALSE;
	}

	switch (req->port->type) {
	case NI_IFTYPE_TEAM: {
			ni_team_port_config_t *pconf = &req->port->team;

			if (!__ni_objectmodel_set_team_port_config(pconf, dict, error))
				return FALSE;
		}
		break;

	case NI_IFTYPE_OVS_BRIDGE: {
			ni_ovs_bridge_port_config_t *pconf = &req->port->ovsbr;

			if (!__ni_objectmodel_set_ovs_bridge_port_config(pconf, dict, error))
				return FALSE;
		}
		break;

	case NI_IFTYPE_BOND:
	case NI_IFTYPE_BRIDGE:
	default:
		dbus_set_error(error, DBUS_ERROR_FAILED, "unable to initialize netdev request %s port data", name);
		return FALSE;
	}
	return TRUE;
}

#define NETIF_REQUEST_UINT_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(netdev_req, dbus_name, name, rw)
#define NETIF_REQUEST_STRING_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev_req, dbus_name, name, rw)
#define NETIF_REQUEST_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __ni_objectmodel_netdev_req, rw)
#define NETIF_REQUEST_UNION_PROPERTY(name, rw) \
	NETIF_REQUEST_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, name, rw)

static ni_dbus_property_t	ni_objectmodel_netif_request_properties[] = {
	NETIF_REQUEST_UINT_PROPERTY(status, ifflags, RO),
	NETIF_REQUEST_UINT_PROPERTY(mtu, mtu, RO),
	NETIF_REQUEST_UINT_PROPERTY(metric, metric, RO),
	NETIF_REQUEST_UINT_PROPERTY(txqlen, txqlen, RO),
	NETIF_REQUEST_STRING_PROPERTY(alias, alias, RO),
	NETIF_REQUEST_STRING_PROPERTY(master, master.name, RO),
	NETIF_REQUEST_UNION_PROPERTY(port, RO),

	{ NULL }
};

