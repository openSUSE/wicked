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
#include <wicked/logging.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"

#define WICKED_NETIF_MODIFIED(bf, member) \
	ni_bitfield_testbit(bf, offsetof(ni_interface_t, member))

static ni_dbus_object_functions_t wicked_dbus_interface_functions;

/*
 * Register a network interface with our dbus server, and add the
 * appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_register_interface(ni_dbus_server_t *server, ni_interface_t *ifp)
{
	ni_dbus_object_t *object;
	const ni_dbus_service_t *link_layer_service;
	char object_path[256];

	snprintf(object_path, sizeof(object_path), "Interface/%s", ifp->name);
	object = ni_dbus_server_register_object(server, object_path,
					&wicked_dbus_interface_functions,
					ni_interface_get(ifp));
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interface %s", ifp->name);

	ni_dbus_object_register_service(object, &wicked_dbus_interface_service);

	link_layer_service = ni_objectmodel_link_layer_service(ifp->type);
	if (link_layer_service != NULL)
		ni_dbus_object_register_service(object, link_layer_service);

	return object;
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

	default: ;
	}

	return NULL;
}

ni_dbus_object_t *
ni_objectmodel_new_interface(ni_dbus_server_t *server, const ni_dbus_service_t *service,
			const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_dbus_object_t *object = NULL, *result = NULL;
	ni_interface_t *ifp = NULL;
	unsigned int i;

	if (!ni_dbus_variant_is_dict(dict))
		goto bad_args;

	ifp = __ni_interface_new(NULL, 0);
	if (!ifp) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Internal error - cannot create network interface");
		return NULL;
	}

	object = ni_dbus_object_new(NULL, &wicked_dbus_interface_functions, ifp);

	for (i = 0; i < dict->array.len; ++i) {
		const ni_dbus_dict_entry_t *entry = &dict->dict_array_value[i];
		const ni_dbus_property_t *prop;

		if (!strcmp(entry->key, "name")) {
			const char *ifname;

			/* fail if interface exists already */
			{
				ni_handle_t *nih = ni_global_state_handle();

				if (ni_interface_by_name(nih, ifname)) {
					dbus_set_error(error, DBUS_ERROR_FAILED,
						"Cannot create interface %s - already exists",
						ifname);
					goto error;
				}
			}

			if (ni_dbus_variant_get_string(&entry->datum, &ifname))
				ni_string_dup(&ifp->name, ifname);
			continue;
		}

		if (!(prop = ni_dbus_service_get_property(service, entry->key))) {
			ni_debug_dbus("Unknown property %s when creating a %s object",
					entry->key, service->object_interface);
			continue;
		}

		if (!prop->set) {
			ni_debug_dbus("Property %s has no set function (when creating a %s object)",
					entry->key, service->object_interface);
			continue;
		}

		if (!prop->set(object, prop, &entry->datum, error)) {
			if (!dbus_error_is_set(error))
				dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
						"Error setting property \"%s\"", prop->name);
			goto error;
		}
	}

	if (service == &wicked_dbus_vlan_service) {
		/* xxx */
		result = ni_objectmodel_new_vlan(server, object);
	} else {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot create network interface for %s - not implemented yet",
				service->object_interface);
		goto error;
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
	ni_interface_put(ifp);
	return NULL;
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

/*
 * Refresh one/all network interfaces.
 * This function is called from the dbus object handling code prior
 * to invoking any method of this object.
 */
static dbus_bool_t
wicked_dbus_interface_refresh(ni_dbus_object_t *object)
{
	ni_handle_t *nih;

	if (!(nih = ni_global_state_handle())) {
		ni_error("Unable to obtain netinfo handle");
		return FALSE;
	}
	if (ni_refresh(nih) < 0) {
		ni_error("cannot refresh interface list!");
		return FALSE;
	}

	/* FIXME: when ni_refresh finds that the interface has
	 * gone away, our object_handle may no longer be valid.
	 */

	return TRUE;
}

#if 0
static ni_dbus_object_t *
wicked_dbus_interface_create_shadow(const ni_dbus_object_t *object)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	ni_interface_t *shadow_ifp;
	ni_handle_t *nih;

	ni_assert(ifp);
	if (!(nih = ni_global_state_handle())) {
		ni_error("Unable to obtain netinfo handle");
		return NULL;
	}

	shadow_ifp = __ni_interface_new(ifp->name, ifp->ifindex);
	if (!shadow_ifp) {
		ni_error("Unable to create shadow interface");
		return NULL;
	}

	return ni_dbus_object_new_shadow(object, shadow_ifp);
}

static dbus_bool_t
wicked_dbus_interface_modify(ni_dbus_object_t *object,
				const ni_dbus_object_t *shadow_object,
				const ni_bitfield_t *bf)
{
	if (WICKED_NETIF_MODIFIED(bf, mtu)) {
		ni_debug_dbus("change of mtu requested");
		return TRUE;
	}

	ni_error("%s() not implemented", __FUNCTION__);
	return FALSE;
}
#endif

static ni_dbus_object_functions_t wicked_dbus_interface_functions = {
	.destroy	= wicked_dbus_interface_destroy,
	.refresh	= wicked_dbus_interface_refresh,
};

static ni_dbus_method_t		wicked_dbus_interface_methods[] = {
	{ NULL }
};

static dbus_bool_t
__wicked_dbus_interface_get_type(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_uint32(result, ifp->type);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_set_type(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	uint32_t value;

	if (!ni_dbus_variant_get_uint32(argument, &value))
		return FALSE;
	ifp->type =value;
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_get_ifflags(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_uint32(result, ifp->ifflags);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_set_ifflags(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	uint32_t value;

	if (!ni_dbus_variant_get_uint32(argument, &value))
		return FALSE;
	ifp->ifflags = value;
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_get_mtu(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_uint32(result, ifp->mtu);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_set_mtu(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	uint32_t value;

	if (!ni_dbus_variant_get_uint32(argument, &value))
		return FALSE;
	ifp->mtu = value;
	return TRUE;
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
	ifp->mtu = value;
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_get_hwaddr(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_byte_array(result, ifp->hwaddr.data, ifp->hwaddr.len);
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

	ifp->hwaddr.type = ifp->type;
	if (!ni_dbus_variant_get_byte_array_minmax(argument,
				ifp->hwaddr.data, &addrlen,
				0, sizeof(ifp->hwaddr.data)))
		return FALSE;
	ifp->hwaddr.len = addrlen;
	return TRUE;
}

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

static dbus_bool_t
__wicked_dbus_interface_get_addrs(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	const ni_address_t *ap;

	ni_dbus_dict_array_init(result);
	for (ap = ifp->addrs; ap; ap = ap->next) {
		ni_dbus_variant_t *dict;

		if (ap->family != ap->local_addr.ss_family)
			continue;

		/* Append a new element to the array */
		dict = ni_dbus_dict_array_add(result);

		ni_dbus_dict_add_uint32(dict, "family", ap->family);
		ni_dbus_dict_add_uint32(dict, "prefixlen", ap->prefixlen);
		ni_dbus_dict_add_uint32(dict, "config", ap->config_method);
		__wicked_dbus_add_sockaddr(dict, "local", &ap->local_addr);
		if (ap->peer_addr.ss_family == ap->family)
			__wicked_dbus_add_sockaddr(dict, "peer", &ap->peer_addr);
		if (ap->anycast_addr.ss_family == ap->family)
			__wicked_dbus_add_sockaddr(dict, "anycast", &ap->anycast_addr);
	}

	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_set_addrs(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	unsigned int i;

	if (!ni_dbus_variant_is_dict_array(argument)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: argument type mismatch",
				__FUNCTION__);
		return FALSE;
	}

	for (i = 0; i < argument->array.len; ++i) {
		ni_dbus_variant_t *dict = &argument->variant_array_value[i];
		uint32_t family, prefixlen;
		ni_sockaddr_t local_addr;
		ni_address_t *ap;

		if (!ni_dbus_dict_get_uint32(dict, "family", &family)
		 || !ni_dbus_dict_get_uint32(dict, "prefixlen", &prefixlen)
		 || !__wicked_dbus_get_sockaddr(dict, "local", &local_addr, family))
			continue;

		ap = ni_address_new(ifp, family, prefixlen, &local_addr);

		__wicked_dbus_get_sockaddr(dict, "peer", &ap->peer_addr, family);
		__wicked_dbus_get_sockaddr(dict, "anycast", &ap->anycast_addr, family);
	}
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_get_routes(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	const ni_route_t *rp;

	ni_dbus_dict_array_init(result);
	for (rp = ifp->routes; rp; rp = rp->next) {
		ni_dbus_variant_t *dict, *hops;
		const ni_route_nexthop_t *nh;

		if (rp->family != rp->destination.ss_family)
			continue;

		/* Append a new element to the array */
		if (!(dict = ni_dbus_dict_array_add(result)))
			return FALSE;
		ni_dbus_variant_init_dict(dict);

		ni_dbus_dict_add_uint32(dict, "family", rp->family);
		ni_dbus_dict_add_uint32(dict, "prefixlen", rp->prefixlen);
		ni_dbus_dict_add_uint32(dict, "config", rp->config_method);
		if (rp->mtu)
			ni_dbus_dict_add_uint32(dict, "mtu", rp->mtu);
		if (rp->tos)
			ni_dbus_dict_add_uint32(dict, "tos", rp->tos);
		if (rp->priority)
			ni_dbus_dict_add_uint32(dict, "priority", rp->priority);
		if (rp->prefixlen)
			__wicked_dbus_add_sockaddr(dict, "destination", &rp->destination);

		hops = ni_dbus_dict_add(dict, "nexthop");
		ni_dbus_dict_array_init(hops);
		for (nh = &rp->nh; nh; nh = nh->next) {
			ni_dbus_variant_t *nhdict;

			nhdict = ni_dbus_dict_array_add(hops);

			__wicked_dbus_add_sockaddr(nhdict, "gateway", &nh->gateway);
			if (nh->device)
				ni_dbus_dict_add_string(nhdict, "device", nh->device);
			if (nh->weight)
				ni_dbus_dict_add_uint32(nhdict, "weight", nh->weight);
			if (nh->flags)
				ni_dbus_dict_add_uint32(nhdict, "flags", nh->flags);
		}
	}

	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_set_routes(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return TRUE;
}

#define WICKED_INTERFACE_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, offsetof(ni_interface_t, __name),__wicked_dbus_interface, rw)
#define WICKED_INTERFACE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, offsetof(ni_interface_t, __name), __wicked_dbus_interface, rw)

static ni_dbus_property_t	wicked_dbus_interface_properties[] = {
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

ni_dbus_service_t	wicked_dbus_interface_service = {
	.object_interface = WICKED_DBUS_INTERFACE ".Interface",
	.methods = wicked_dbus_interface_methods,
	.properties = wicked_dbus_interface_properties,
};
