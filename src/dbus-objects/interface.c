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
#include "model.h"

static ni_dbus_service_t	wicked_dbus_interface_interface;
static ni_dbus_object_functions_t wicked_dbus_interface_functions;

ni_dbus_object_t *
ni_objectmodel_create_interface(ni_dbus_server_t *server, ni_interface_t *ifp)
{
	ni_dbus_object_t *object;
	char object_path[256];

	snprintf(object_path, sizeof(object_path), "Interface/%s", ifp->name);
	object = ni_dbus_server_register_object(server, object_path,
					&wicked_dbus_interface_functions,
					ni_interface_get(ifp));
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interface %s", ifp->name);

	ni_dbus_object_register_service(object, &wicked_dbus_interface_interface);

	return object;

	switch (ifp->type) {
	case NI_IFTYPE_ETHERNET:
		ni_objectmodel_register_ethernet_interface(object);
		break;

	default: ;
	}
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

static ni_dbus_object_functions_t wicked_dbus_interface_functions = {
	.destroy	= wicked_dbus_interface_destroy,
	.refresh	= wicked_dbus_interface_refresh,
//	.create_shadow	= wicked_dbus_interface_create_shadow,
//	.modify		= wicked_dbus_interface_modify,
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
__wicked_dbus_interface_get_status(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_uint32(result, ifp->ifflags);
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
__wicked_dbus_interface_get_hwaddr(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_byte_array(result, ifp->hwaddr.data, ifp->hwaddr.len);
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

static dbus_bool_t
__wicked_dbus_interface_get_addresses(const ni_dbus_object_t *object,
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
		ni_dbus_variant_init_variant_array(hops);
		for (nh = &rp->nh; nh; nh = nh->next) {
			ni_dbus_variant_t *nhdict;

			nhdict = ni_dbus_variant_append_variant_element(hops);
			ni_dbus_variant_init_dict(nhdict);

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

#define WICKED_INTERFACE_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __wicked_dbus_interface, rw)
#define WICKED_INTERFACE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_interface, rw)

static ni_dbus_property_t	wicked_dbus_interface_properties[] = {
	WICKED_INTERFACE_PROPERTY(UINT32, status, RO),
	WICKED_INTERFACE_PROPERTY(UINT32, type, RO),
	WICKED_INTERFACE_PROPERTY(UINT32, mtu, RO),
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
			addresses, RO),

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

static ni_dbus_service_t	wicked_dbus_interface_interface = {
	.object_interface = WICKED_DBUS_INTERFACE ".Interface",
	.methods = wicked_dbus_interface_methods,
	.properties = wicked_dbus_interface_properties,
};
