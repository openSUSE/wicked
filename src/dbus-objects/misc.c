/*
 * DBus encapsulation for various second-tier network structs
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
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

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
 * Retrieve an address list as an array of dbus dicts
 */
dbus_bool_t
__wicked_dbus_get_address_list(ni_address_t *list,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_address_t *ap;

	for (ap = list; ap; ap = ap->next) {
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

/*
 * Build an address list from a dbus dict
 */
dbus_bool_t
__wicked_dbus_set_address_list(ni_address_t **list,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
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

		ap = __ni_address_new(list, family, prefixlen, &local_addr);

		__wicked_dbus_get_sockaddr(dict, "peer", &ap->peer_addr, family);
		__wicked_dbus_get_sockaddr(dict, "anycast", &ap->anycast_addr, family);
	}
	return TRUE;
}

/*
 * Retrieve a route list as an array of dbus dicts
 */
dbus_bool_t
__wicked_dbus_get_route_list(ni_route_t *list,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_route_t *rp;

	for (rp = list; rp; rp = rp->next) {
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

/*
 * Build a route list from a dbus dict
 */
dbus_bool_t
__wicked_dbus_set_route_list(ni_route_t **list,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	unsigned int i;

	if (!ni_dbus_variant_is_dict_array(argument)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: argument type mismatch",
				__FUNCTION__);
		return FALSE;
	}

	for (i = 0; i < argument->array.len; ++i) {
		ni_dbus_variant_t *dict = &argument->variant_array_value[i];
		const ni_dbus_variant_t *hops;
		uint32_t family, prefixlen, config, value;
		ni_sockaddr_t destination;
		ni_route_t *rp;

		if (!ni_dbus_dict_get_uint32(dict, "family", &family)
		 || !ni_dbus_dict_get_uint32(dict, "prefixlen", &prefixlen)
		 || !ni_dbus_dict_get_uint32(dict, "config", &config))
			continue;

		if (prefixlen == 0) {
			memset(&destination, 0, sizeof(destination));
		} else if (!__wicked_dbus_get_sockaddr(dict, "destination", &destination, family)) {
			ni_debug_dbus("Cannot set route: prefixlen=%u, but no destination", prefixlen);
			continue;
		}

		rp = calloc(1, sizeof(*rp));
		rp->family = family;
		rp->prefixlen = prefixlen;
		rp->destination = destination;
		__ni_route_list_append(list, rp);

		if (ni_dbus_dict_get_uint32(dict, "mtu", &value))
			rp->mtu = value;
		if (ni_dbus_dict_get_uint32(dict, "tos", &value))
			rp->tos = value;
		if (ni_dbus_dict_get_uint32(dict, "priority", &value))
			rp->priority = value;

		hops = ni_dbus_dict_get(dict, "nexthop");
		if (hops && ni_dbus_variant_is_dict_array(hops)) {
			ni_route_nexthop_t *nh = &rp->nh, **nhpos = &nh;
			unsigned int j;

			for (j = 0; j < hops->array.len; ++j) {
				ni_dbus_variant_t *nhdict = &hops->variant_array_value[j];
				const char *string;
				uint32_t value;
				ni_sockaddr_t gateway;

				if (!__wicked_dbus_get_sockaddr(nhdict, "gateway", &gateway, family)) {
					ni_debug_dbus("%s: bad nexthop gateway", __FUNCTION__);
					return FALSE;
				}

				if (nh == NULL)
					*nhpos = nh = calloc(1, sizeof(*nh));

				nh->gateway = gateway;
				if (ni_dbus_dict_get_string(nhdict, "device", &string))
					ni_string_dup(&nh->device, string);
				if (ni_dbus_dict_get_uint32(nhdict, "weight", &value))
					nh->weight = value;
				if (ni_dbus_dict_get_uint32(nhdict, "flags", &value))
					nh->flags = value;

				nhpos = &nh->next;
				nh = NULL;
			}
		}
	}
	return TRUE;
}

/*
 * Build a DBus dict from an addrconf request
 */
dbus_bool_t
__wicked_dbus_get_addrconf_request(const ni_addrconf_request_t *req,
						ni_dbus_variant_t *result,
						DBusError *error)
{
	ni_dbus_dict_add_uint32(result, "settle-timeout", req->settle_timeout);
	ni_dbus_dict_add_uint32(result, "acquire-timeout", req->acquire_timeout);

	if (req->family == AF_INET && req->type == NI_ADDRCONF_DHCP) {
		if (req->dhcp.hostname)
			ni_dbus_dict_add_string(result, "dhcp-hostname", req->dhcp.hostname);
		if (req->dhcp.clientid)
			ni_dbus_dict_add_string(result, "dhcp-clientid", req->dhcp.clientid);
		if (req->dhcp.vendor_class)
			ni_dbus_dict_add_string(result, "dhcp-vendor-class", req->dhcp.vendor_class);
		if (req->dhcp.lease_time)
			ni_dbus_dict_add_uint32(result, "dhcp-lease-time", req->dhcp.lease_time);
	}
	if (req->type == NI_ADDRCONF_STATIC) {
		ni_dbus_variant_t *child;

		if (req->statik.addrs) {
			child = ni_dbus_dict_add(result, "static-addresses");
			ni_dbus_dict_array_init(child);
			if (!__wicked_dbus_get_address_list(req->statik.addrs, child, error))
				return FALSE;
		}
		if (req->statik.routes) {
			child = ni_dbus_dict_add(result, "static-routes");
			ni_dbus_dict_array_init(child);
			if (!__wicked_dbus_get_route_list(req->statik.routes, child, error))
				return FALSE;
		}
	}
	ni_dbus_dict_add_uint32(result, "update", req->update);

	return TRUE;
}

dbus_bool_t
__wicked_dbus_set_addrconf_request(ni_addrconf_request_t *req,
						const ni_dbus_variant_t *argument,
						DBusError *error)
{
	const char *string_value;
	uint32_t value32;

	if (ni_dbus_dict_get_uint32(argument, "settle-timeout", &value32))
		req->settle_timeout = value32;
	if (ni_dbus_dict_get_uint32(argument, "acquire-timeout", &value32))
		req->acquire_timeout = value32;

	if (req->family == AF_INET && req->type == NI_ADDRCONF_DHCP) {
		if (ni_dbus_dict_get_string(argument, "dhcp-hostname", &string_value))
			ni_string_dup(&req->dhcp.hostname, string_value);
		if (ni_dbus_dict_get_string(argument, "dhcp-clientid", &string_value))
			ni_string_dup(&req->dhcp.clientid, string_value);
		if (ni_dbus_dict_get_string(argument, "dhcp-vendor-class", &string_value))
			ni_string_dup(&req->dhcp.vendor_class, string_value);
		if (ni_dbus_dict_get_uint32(argument, "lease-time", &value32))
			req->dhcp.lease_time = value32;
	}
	if (req->type == NI_ADDRCONF_STATIC) {
		const ni_dbus_variant_t *child;

		if ((child = ni_dbus_dict_get(argument, "static-addresses")) != NULL
		 && !__wicked_dbus_set_address_list(&req->statik.addrs, child, error))
			return FALSE;
		if ((child = ni_dbus_dict_get(argument, "static-routes")) != NULL
		 && !__wicked_dbus_set_route_list(&req->statik.routes, child, error))
			return FALSE;
	}

	if (ni_dbus_dict_get_uint32(argument, "update", &value32))
		req->update = value32;

	return TRUE;
}
