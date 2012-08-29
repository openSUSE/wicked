/*
 * DBus encapsulation for various second-tier network structs
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include <wicked/route.h>
#include <wicked/addrconf.h>
#include <wicked/resolver.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static dbus_bool_t		__ni_objectmodel_callback_info_to_dict(const ni_objectmodel_callback_info_t *, ni_dbus_variant_t *);
static dbus_bool_t		__ni_objectmodel_address_to_dict(const ni_address_t *, ni_dbus_variant_t *);
static ni_address_t *		__ni_objectmodel_address_from_dict(ni_address_t **, const ni_dbus_variant_t *);
static dbus_bool_t		__ni_objectmodel_route_to_dict(const ni_route_t *, ni_dbus_variant_t *);
static ni_route_t *		__ni_objectmodel_route_from_dict(ni_route_t **, const ni_dbus_variant_t *);

/*
 * Helper functions for getting and setting socket addresses
 */
static inline dbus_bool_t
__ni_dbus_variant_get_opaque(const ni_dbus_variant_t *var, ni_opaque_t *packed)
{
	unsigned int len;

	if (!ni_dbus_variant_get_byte_array_minmax(var, packed->data, &len, 0, sizeof(packed->data)))
		return FALSE;
	packed->len = len;
	return TRUE;
}

static inline dbus_bool_t
__ni_dbus_variant_set_sockaddr(ni_dbus_variant_t *var, const ni_sockaddr_t *sockaddr)
{
	ni_opaque_t packed;

	if (!ni_sockaddr_pack(sockaddr, &packed))
		return FALSE;

	ni_dbus_variant_set_byte_array(var, packed.data, packed.len);
	return TRUE;
}

static inline dbus_bool_t
__ni_dbus_variant_set_sockaddr_prefix(ni_dbus_variant_t *var, const ni_sockaddr_t *sockaddr, unsigned int prefix_len)
{
	ni_opaque_t packed;

	if (!ni_sockaddr_prefix_pack(sockaddr, prefix_len, &packed))
		return FALSE;

	ni_dbus_variant_set_byte_array(var, packed.data, packed.len);
	return TRUE;
}

static inline dbus_bool_t
__ni_dbus_variant_get_sockaddr(const ni_dbus_variant_t *var, ni_sockaddr_t *sockaddr)
{
	ni_opaque_t packed;

	if (!__ni_dbus_variant_get_opaque(var, &packed))
		return FALSE;
	if (!ni_sockaddr_unpack(sockaddr, &packed))
		return FALSE;

	return TRUE;
}

static inline dbus_bool_t
__ni_dbus_variant_get_sockaddr_prefix(const ni_dbus_variant_t *var, ni_sockaddr_t *sockaddr, unsigned int *prefixlen)
{
	ni_opaque_t packed;

	if (!__ni_dbus_variant_get_opaque(var, &packed))
		return FALSE;
	if (!ni_sockaddr_prefix_unpack(sockaddr, prefixlen, &packed))
		return FALSE;

	return TRUE;
}

static inline dbus_bool_t
__ni_dbus_dict_add_sockaddr(ni_dbus_variant_t *dict, const char *name, const ni_sockaddr_t *sockaddr)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, name)))
		return FALSE;
	return __ni_dbus_variant_set_sockaddr(dst, sockaddr);
}

static inline dbus_bool_t
__ni_dbus_dict_add_sockaddr_prefix(ni_dbus_variant_t *dict, const char *name, const ni_sockaddr_t *sockaddr, unsigned int prefix_len)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, name)))
		return FALSE;

	return __ni_dbus_variant_set_sockaddr_prefix(dst, sockaddr, prefix_len);
}

static inline dbus_bool_t
__ni_dbus_dict_get_sockaddr(const ni_dbus_variant_t *dict, const char *name, ni_sockaddr_t *sockaddr)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, name)))
		return FALSE;
	return __ni_dbus_variant_get_sockaddr(var, sockaddr);
}

static inline dbus_bool_t
__ni_dbus_dict_get_sockaddr_prefix(const ni_dbus_variant_t *dict, const char *name, ni_sockaddr_t *sockaddr, unsigned int *prefixlen)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, name)))
		return FALSE;
	return __ni_dbus_variant_get_sockaddr_prefix(var, sockaddr, prefixlen);
}

/*
 * Get/set a hwaddr_t member
 */
dbus_bool_t
__ni_objectmodel_set_hwaddr(const ni_dbus_variant_t *argument, ni_hwaddr_t *hwaddr)
{
	unsigned int len;

	if (!ni_dbus_variant_get_byte_array_minmax(argument, hwaddr->data, &len, 0, sizeof(hwaddr->data)))
		return FALSE;

	hwaddr->len = len;
	return TRUE;
}

dbus_bool_t
__ni_objectmodel_get_hwaddr(ni_dbus_variant_t *result, const ni_hwaddr_t *hwaddr)
{
	ni_dbus_variant_set_byte_array(result, hwaddr->data, hwaddr->len);
	return TRUE;
}

/*
 * Add or retrieve an array of strings to a dict.
 * Empty string arrays are omitted, rather than being encoded as a
 * zero length array.
 */
static inline void
__ni_objectmodel_set_string_array(ni_dbus_variant_t *dict, const char *name, const ni_string_array_t *ap)
{
	ni_dbus_variant_t *child;

	if (ap->count != 0) {
		child = ni_dbus_dict_add(dict, name);
		ni_dbus_variant_set_string_array(child, (const char **) ap->data, ap->count);
	}
}

static inline dbus_bool_t
__ni_objectmodel_get_string_array(ni_string_array_t *ap, const ni_dbus_variant_t *var, DBusError *error)
{
	unsigned int i, len;

	if (!ni_dbus_variant_is_string_array(var))
		return FALSE;

	if ((len = var->array.len) > 64)
		len = 64;

	for (i = 0; i < len; ++i)
		ni_string_array_append(ap, var->string_array_value[i]);
	return TRUE;
}

/*
 * Represent an address list as an array of dbus dicts
 *
 * The dbus representation will be something like
 *  <array>
 *    <element>
 *      ... dict entries ...
 *    </element>
 *    <element>
 *      ... dict entries ...
 *    </element>
 *  </array>
 */
dbus_bool_t
__ni_objectmodel_get_address_list(ni_address_t *list,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_address_t *ap;
	dbus_bool_t rv = TRUE;

	for (ap = list; ap && rv; ap = ap->next) {
		ni_dbus_variant_t *dict;

		if (ap->family != ap->local_addr.ss_family)
			continue;

		/* Append a new element to the array */
		dict = ni_dbus_dict_array_add(result);

		rv = __ni_objectmodel_address_to_dict(ap, dict);
	}

	return rv;
}

dbus_bool_t
__ni_objectmodel_set_address_list(ni_address_t **list,
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

		(void) __ni_objectmodel_address_from_dict(list, dict);
	}
	return TRUE;
}

/*
 * Retrieve an address list as multiple "address" elements in a dict
 *
 * The dbus representation will be something like
 *   <dict>
 *     <address>
 *      ... dict entries ...
 *     </address>
 *     <address>
 *      ... dict entries ...
 *     </address>
 *   </dict>
 */
dbus_bool_t
__ni_objectmodel_get_address_dict(ni_address_t *list,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_address_t *ap;
	dbus_bool_t rv = TRUE;

	for (ap = list; ap && rv; ap = ap->next) {
		ni_dbus_variant_t *dict;

		if (ap->family != ap->local_addr.ss_family)
			continue;

		/* Append a new element to the array */
		dict = ni_dbus_dict_add(result, "address");
		ni_dbus_variant_init_dict(dict);

		rv = __ni_objectmodel_address_to_dict(ap, dict);
	}

	return rv;
}

dbus_bool_t
__ni_objectmodel_set_address_dict(ni_address_t **list,
				const ni_dbus_variant_t *dict,
				DBusError *error)
{
	ni_dbus_variant_t *var;

	if (!ni_dbus_variant_is_dict(dict)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: argument type mismatch",
				__FUNCTION__);
		return FALSE;
	}

	var = NULL;
	while ((var = ni_dbus_dict_get_next(dict, "address", var)) != NULL) {
		if (!ni_dbus_variant_is_dict(var))
			return FALSE;
		(void) __ni_objectmodel_address_from_dict(list, var);
	}
	return TRUE;
}

/*
 * Common functions to represent an assigned address as a dict
 */
dbus_bool_t
__ni_objectmodel_address_to_dict(const ni_address_t *ap, ni_dbus_variant_t *dict)
{
	__ni_dbus_dict_add_sockaddr_prefix(dict, "local", &ap->local_addr, ap->prefixlen);
	if (ap->peer_addr.ss_family == ap->family)
		__ni_dbus_dict_add_sockaddr(dict, "peer", &ap->peer_addr);
	if (ap->anycast_addr.ss_family == ap->family)
		__ni_dbus_dict_add_sockaddr(dict, "anycast", &ap->anycast_addr);

	if (ap->ipv6_cache_info.preferred_lft || ap->ipv6_cache_info.valid_lft) {
		ni_dbus_variant_t *var;

		var = ni_dbus_dict_add(dict, "cache-info");
		ni_dbus_variant_init_dict(var);

		ni_dbus_dict_add_uint32(var, "preferred-lifetime", ap->ipv6_cache_info.preferred_lft);
		ni_dbus_dict_add_uint32(var, "valid-lifetime", ap->ipv6_cache_info.valid_lft);
	}

	if (ap->config_lease)
		ni_dbus_dict_add_uint32(dict, "owner", ap->config_lease->type);

	return TRUE;
}

ni_address_t *
__ni_objectmodel_address_from_dict(ni_address_t **list, const ni_dbus_variant_t *dict)
{
	ni_address_t *ap = NULL;
	ni_sockaddr_t local_addr;
	unsigned int prefixlen;

	if (__ni_dbus_dict_get_sockaddr_prefix(dict, "local", &local_addr, &prefixlen)) {
		const ni_dbus_variant_t *var;

		ap = __ni_address_new(list, local_addr.ss_family, prefixlen, &local_addr);

		__ni_dbus_dict_get_sockaddr(dict, "peer", &ap->peer_addr);
		__ni_dbus_dict_get_sockaddr(dict, "anycast", &ap->anycast_addr);

		if ((var = ni_dbus_dict_get(dict, "cache-info")) != NULL) {
			uint32_t value;

			if (ni_dbus_dict_get_uint32(var, "preferred-lifetime", &value))
				ap->ipv6_cache_info.preferred_lft = value;
			if (ni_dbus_dict_get_uint32(var, "valid-lifetime", &value))
				ap->ipv6_cache_info.valid_lft = value;
		}

#if 0
		if (ni_dbus_dict_get_uint32(dict, "owner", &value))
			ap->config_method = value;
#endif
	}

	return ap;
}

/*
 * Retrieve a route list as an array of dbus dicts
 *
 * The dbus representation will be something like
 *  <array>
 *    <element>
 *      ... dict entries ...
 *    </element>
 *    <element>
 *      ... dict entries ...
 *    </element>
 *  </array>
 */
dbus_bool_t
__ni_objectmodel_get_route_list(ni_route_t *list,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_route_t *rp;
	dbus_bool_t rv = TRUE;

	for (rp = list; rp && rv; rp = rp->next) {
		ni_dbus_variant_t *dict;

		if (rp->family != rp->destination.ss_family)
			continue;

		/* Append a new element to the array */
		if (!(dict = ni_dbus_dict_array_add(result)))
			return FALSE;
		ni_dbus_variant_init_dict(dict);

		rv = __ni_objectmodel_route_to_dict(rp, dict);
	}

	return rv;
}

/*
 * Build a route list from a dbus dict
 */
dbus_bool_t
__ni_objectmodel_set_route_list(ni_route_t **list,
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

		(void) __ni_objectmodel_route_from_dict(list, dict);
	}
	return TRUE;
}

/*
 * Retrieve a route list as multiple "route" elements in a dict
 *
 * The dbus representation will be something like
 *   <dict>
 *     <route>
 *      ... dict entries ...
 *     </route>
 *     <route>
 *      ... dict entries ...
 *     </route>
 *   </dict>
 */
dbus_bool_t
__ni_objectmodel_get_route_dict(ni_route_t *list,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_route_t *rp;
	dbus_bool_t rv = TRUE;

	for (rp = list; rp && rv; rp = rp->next) {
		ni_dbus_variant_t *dict;

		if (rp->family != rp->destination.ss_family)
			continue;

		/* Append a new element to the array */
		dict = ni_dbus_dict_add(result, "route");
		ni_dbus_variant_init_dict(dict);

		rv = __ni_objectmodel_route_to_dict(rp, dict);
	}

	return rv;
}

dbus_bool_t
__ni_objectmodel_set_route_dict(ni_route_t **list,
				const ni_dbus_variant_t *dict,
				DBusError *error)
{
	ni_dbus_variant_t *var;

	if (!ni_dbus_variant_is_dict(dict)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: argument type mismatch",
				__FUNCTION__);
		return FALSE;
	}

	var = NULL;
	while ((var = ni_dbus_dict_get_next(dict, "route", var)) != NULL) {
		if (!ni_dbus_variant_is_dict(var))
			return FALSE;
		(void) __ni_objectmodel_route_from_dict(list, var);
	}
	return TRUE;
}

/*
 * Common functions to represent an assigned route as a dict
 */
dbus_bool_t
__ni_objectmodel_route_to_dict(const ni_route_t *rp, ni_dbus_variant_t *dict)
{
	const ni_route_nexthop_t *nh;
	ni_dbus_variant_t *child;

	__ni_dbus_dict_add_sockaddr_prefix(dict, "destination", &rp->destination, rp->prefixlen);

	child = ni_dbus_dict_add(dict, "kern");
	ni_dbus_variant_init_dict(child);
	if (rp->type)
		ni_dbus_dict_add_uint32(child, "rt-type", rp->type);
	if (rp->protocol)
		ni_dbus_dict_add_uint32(child, "rt-protocol", rp->protocol);
	if (rp->table)
		ni_dbus_dict_add_uint32(child, "rt-table", rp->table);
	ni_dbus_dict_add_uint32(child, "rt-scope", rp->scope);

	if (rp->config_lease)
		ni_dbus_dict_add_uint32(dict, "owner", rp->config_lease->type);
	if (rp->mtu)
		ni_dbus_dict_add_uint32(dict, "mtu", rp->mtu);
	if (rp->tos)
		ni_dbus_dict_add_uint32(dict, "tos", rp->tos);
	if (rp->priority)
		ni_dbus_dict_add_uint32(dict, "priority", rp->priority);

	if (rp->nh.gateway.ss_family != AF_UNSPEC) {
		for (nh = &rp->nh; nh; nh = nh->next) {
			ni_dbus_variant_t *nhdict;

			nhdict = ni_dbus_dict_add(dict, "nexthop");
			ni_dbus_variant_init_dict(nhdict);

			__ni_dbus_dict_add_sockaddr(nhdict, "gateway", &nh->gateway);
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

ni_route_t *
__ni_objectmodel_route_from_dict(ni_route_t **list, const ni_dbus_variant_t *dict)
{
	const ni_dbus_variant_t *nhdict, *child;
	uint32_t prefixlen, value;
	ni_sockaddr_t destination;
	ni_route_t *rp;

	if (!__ni_dbus_dict_get_sockaddr_prefix(dict, "destination", &destination, &prefixlen))
		return NULL;

	rp = ni_route_new(prefixlen, &destination, NULL, list);

	if (ni_dbus_dict_get_uint32(dict, "mtu", &value))
		rp->mtu = value;
	if (ni_dbus_dict_get_uint32(dict, "tos", &value))
		rp->tos = value;
	if (ni_dbus_dict_get_uint32(dict, "priority", &value))
		rp->priority = value;
#if 0
	/* FIXME: need to create dummy lease here */
	if (!ni_dbus_dict_get_uint32(dict, "owner", &value))
		rp->config_method = value;
#endif

	if ((child = ni_dbus_dict_get(dict, "kern")) != NULL) {
		if (ni_dbus_dict_get_uint32(dict, "rt-type", &value))
			rp->type = value;
		if (ni_dbus_dict_get_uint32(dict, "rt-protocol", &value))
			rp->protocol = value;
		if (ni_dbus_dict_get_uint32(dict, "rt-table", &value))
			rp->table = value;
		if (ni_dbus_dict_get_uint32(dict, "rt-scope", &value))
			rp->scope = value;
	}

	if ((nhdict = ni_dbus_dict_get(dict, "nexthop")) != NULL) {
		ni_route_nexthop_t *nh = &rp->nh, **nhpos = &nh;

		while (nhdict) {
			const char *string;
			uint32_t value;
			ni_sockaddr_t gateway;

			if (!__ni_dbus_dict_get_sockaddr(nhdict, "gateway", &gateway)) {
				ni_debug_dbus("%s: bad nexthop gateway", __func__);
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

			nhdict = ni_dbus_dict_get_next(dict, "nexthop", nhdict);
			nhpos = &nh->next;
			nh = NULL;
		}
	}

	return rp;
}

/*
 * Build a DBus dict from an addrconf lease
 */
dbus_bool_t
__ni_objectmodel_get_addrconf_lease(const ni_addrconf_lease_t *lease,
						ni_dbus_variant_t *result,
						DBusError *error)
{
	ni_dbus_variant_t *child;

	ni_dbus_dict_add_uint32(result, "state", lease->state);
	ni_dbus_dict_add_uint32(result, "acquired", lease->time_acquired);
	ni_dbus_dict_add_uint32(result, "update", lease->update);

	if (!(child = ni_dbus_dict_add(result, "uuid")))
		return FALSE;
	ni_dbus_variant_set_uuid(child, &lease->uuid);

	if (lease->hostname)
		ni_dbus_dict_add_string(result, "hostname", lease->hostname);

	if (lease->addrs) {
		child = ni_dbus_dict_add(result, "addresses");
		ni_dbus_dict_array_init(child);
		if (!__ni_objectmodel_get_address_list(lease->addrs, child, error))
			return FALSE;
	}
	if (lease->routes) {
		child = ni_dbus_dict_add(result, "routes");
		ni_dbus_dict_array_init(child);
		if (!__ni_objectmodel_get_route_list(lease->routes, child, error))
			return FALSE;
	}

	if (lease->resolver) {
		ni_resolver_info_t *resolv = lease->resolver;

		child = ni_dbus_dict_add(result, "resolver");
		ni_dbus_variant_init_dict(child);

		if (resolv->default_domain)
			ni_dbus_dict_add_string(child, "default-domain", resolv->default_domain);
		__ni_objectmodel_set_string_array(child, "servers", &resolv->dns_servers);
		__ni_objectmodel_set_string_array(child, "search", &resolv->dns_search);
	}

	/* TBD: NIS information */

	__ni_objectmodel_set_string_array(result, "log-servers", &lease->log_servers);
	__ni_objectmodel_set_string_array(result, "ntp-servers", &lease->ntp_servers);
	__ni_objectmodel_set_string_array(result, "slp-servers", &lease->slp_servers);
	__ni_objectmodel_set_string_array(result, "slp-scopes", &lease->slp_scopes);
	__ni_objectmodel_set_string_array(result, "sip-servers", &lease->sip_servers);
	__ni_objectmodel_set_string_array(result, "lpr-servers", &lease->lpr_servers);

	__ni_objectmodel_set_string_array(result, "netbios-name-servers", &lease->netbios_name_servers);
	__ni_objectmodel_set_string_array(result, "netbios-dd-servers", &lease->netbios_dd_servers);
	if (lease->netbios_domain)
		ni_dbus_dict_add_string(result, "netbios-domain", lease->netbios_domain);
	if (lease->netbios_scope)
		ni_dbus_dict_add_string(result, "netbios-scope", lease->netbios_scope);

	return TRUE;
}

dbus_bool_t
ni_objectmodel_get_addrconf_lease(const ni_addrconf_lease_t *lease, ni_dbus_variant_t *result)
{
	DBusError error = DBUS_ERROR_INIT;

	if (!__ni_objectmodel_get_addrconf_lease(lease, result, &error)) {
		ni_error("Unable to encode lease: %s (%s)", error.name, error.message);
		dbus_error_free(&error);
		return FALSE;
	}

	return TRUE;
}

dbus_bool_t
__ni_objectmodel_set_addrconf_lease(ni_addrconf_lease_t *lease,
						const ni_dbus_variant_t *argument,
						DBusError *error)
{
	const ni_dbus_variant_t *child;
	const char *string_value;
	uint32_t value32;

	if (ni_dbus_dict_get_uint32(argument, "state", &value32))
		lease->state = value32;
	if (ni_dbus_dict_get_uint32(argument, "acquired", &value32))
		lease->time_acquired = value32;

	/* If the caller didn't tell us what to update, we assume we should
	 * update all facilities */
	if (ni_dbus_dict_get_uint32(argument, "update", &value32))
		lease->update = value32;
	else
		lease->update = ~0;

	if (ni_dbus_dict_get_string(argument, "hostname", &string_value))
		ni_string_dup(&lease->hostname, string_value);

	if ((child = ni_dbus_dict_get(argument, "uuid")) != NULL
	 && !ni_dbus_variant_get_uuid(child, &lease->uuid))
		return FALSE;

	if ((child = ni_dbus_dict_get(argument, "addresses")) != NULL
	 && !__ni_objectmodel_set_address_list(&lease->addrs, child, error))
		return FALSE;

	if ((child = ni_dbus_dict_get(argument, "routes")) != NULL
	 && !__ni_objectmodel_set_route_list(&lease->routes, child, error))
		return FALSE;

	if ((child = ni_dbus_dict_get(argument, "resolver")) != NULL) {
		ni_resolver_info_t *resolv = ni_resolver_info_new();
		ni_dbus_variant_t *list;

		lease->resolver = resolv;
		if (ni_dbus_dict_get_string(child, "default-domain", &string_value))
			ni_string_dup(&resolv->default_domain, string_value);

		if ((list = ni_dbus_dict_get(child, "servers")) != NULL
		 && !__ni_objectmodel_get_string_array(&resolv->dns_servers, list, error))
			return FALSE;
		if ((list = ni_dbus_dict_get(child, "search")) != NULL
		 && !__ni_objectmodel_get_string_array(&resolv->dns_search, list, error))
			return FALSE;
	}

	/* TBD: NIS information */

	if ((child = ni_dbus_dict_get(argument, "log-servers")) != NULL
	 && !__ni_objectmodel_get_string_array(&lease->log_servers, child, error))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "ntp-servers")) != NULL
	 && !__ni_objectmodel_get_string_array(&lease->ntp_servers, child, error))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "slp-servers")) != NULL
	 && !__ni_objectmodel_get_string_array(&lease->slp_servers, child, error))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "slp-scopes")) != NULL
	 && !__ni_objectmodel_get_string_array(&lease->slp_scopes, child, error))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "sip-servers")) != NULL
	 && !__ni_objectmodel_get_string_array(&lease->sip_servers, child, error))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "lpr-servers")) != NULL
	 && !__ni_objectmodel_get_string_array(&lease->lpr_servers, child, error))
		return FALSE;

	if ((child = ni_dbus_dict_get(argument, "netbios-name-servers")) != NULL
	 && !__ni_objectmodel_get_string_array(&lease->netbios_name_servers, child, error))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "netbios-dd-servers")) != NULL
	 && !__ni_objectmodel_get_string_array(&lease->netbios_dd_servers, child, error))
		return FALSE;
	if (ni_dbus_dict_get_string(argument, "netbios-domain", &string_value))
		ni_string_dup(&lease->netbios_domain, string_value);
	if (ni_dbus_dict_get_string(argument, "netbios-scope", &string_value))
		ni_string_dup(&lease->netbios_scope, string_value);

	return TRUE;
}

dbus_bool_t
ni_objectmodel_set_addrconf_lease(ni_addrconf_lease_t *lease, const ni_dbus_variant_t *argument)
{
	DBusError error = DBUS_ERROR_INIT;

	if (!__ni_objectmodel_set_addrconf_lease(lease, argument, &error)) {
		ni_error("Unable to decode lease: %s (%s)", error.name, error.message);
		dbus_error_free(&error);
		return FALSE;
	}

	return TRUE;
}

/*
 * Handle security_id
 */
dbus_bool_t
ni_objectmodel_unmarshal_security_id(ni_security_id_t *security_id, const ni_dbus_variant_t *argument)
{
	const char *key, *value;
	const ni_dbus_variant_t *var;
	unsigned int i;

	for (i = 0; (var = ni_dbus_dict_get_entry(argument, i, &key)) != NULL; ++i) {
		if (!ni_dbus_variant_get_string(var, &value))
			return FALSE;

		if (ni_string_eq(key, "class"))
			ni_string_dup(&security_id->class, value);
		else
			ni_security_id_set_attr(security_id, key, value);
	}

	return TRUE;
}

dbus_bool_t
ni_objectmodel_marshal_security_id(const ni_security_id_t *security_id, ni_dbus_variant_t *argument)
{
	unsigned int i;

	ni_dbus_variant_init_dict(argument);
	ni_dbus_dict_add_string(argument, "class", security_id->class);
	for (i = 0; i < security_id->attributes.count; ++i) {
		ni_var_t *var = &security_id->attributes.data[i];

		if (!ni_string_eq(var->name, "class"))
		ni_dbus_dict_add_string(argument, var->name, var->value);
	}

	return TRUE;
}

/*
 * When we've forwarded an addrconf call to a supplicant, such as dhcp4
 * or ipv4ll, we need to return to the caller the uuid and event he's supposed
 * to wait for.
 */
dbus_bool_t
__ni_objectmodel_return_callback_info(ni_dbus_message_t *reply, ni_event_t event, const ni_uuid_t *uuid, DBusError *error)
{
	ni_dbus_variant_t dict = NI_DBUS_VARIANT_INIT;
	ni_objectmodel_callback_info_t callback;
	dbus_bool_t rv;

	memset(&callback, 0, sizeof(callback));
	if (!(callback.event = (char *) ni_objectmodel_event_to_signal(event))) {
		ni_error("cannot return callback info for unknown event %s",
				ni_event_type_to_name(event));
		return FALSE;
	}
	callback.uuid = *uuid;

	ni_dbus_variant_init_dict(&dict);
	rv = __ni_objectmodel_callback_info_to_dict(&callback, &dict);
	if (rv)
		rv = ni_dbus_message_serialize_variants(reply, 1, &dict, error);
	ni_dbus_variant_destroy(&dict);

	return rv;
}

static dbus_bool_t
__ni_objectmodel_callback_info_to_dict(const ni_objectmodel_callback_info_t *cb, ni_dbus_variant_t *dict)
{
	while (cb) {
		ni_dbus_variant_t *info_dict;

		info_dict = ni_dbus_dict_add(dict, "callback");
		ni_dbus_variant_init_dict(info_dict);

		ni_dbus_dict_add_string(info_dict, "event", cb->event);
		ni_dbus_variant_set_uuid(ni_dbus_dict_add(info_dict, "uuid"), &cb->uuid);

		cb = cb->next;
	}

	return TRUE;
}

ni_objectmodel_callback_info_t *
ni_objectmodel_callback_info_from_dict(const ni_dbus_variant_t *dict)
{
	ni_objectmodel_callback_info_t *result = NULL;
	ni_dbus_variant_t *child = NULL, *var;

	while ((child = ni_dbus_dict_get_next(dict, "callback", child)) != NULL) {
		ni_objectmodel_callback_info_t *cb;
		const char *event;

		cb = calloc(1, sizeof(*cb));
		if (ni_dbus_dict_get_string(child, "event", &event))
			ni_string_dup(&cb->event, event);
		if ((var = ni_dbus_dict_get(child, "uuid")) != NULL)
			ni_dbus_variant_get_uuid(var, &cb->uuid);

		cb->next = result;
		result = cb;
	}

	return result;
}

void
ni_objectmodel_callback_info_free(ni_objectmodel_callback_info_t *cb)
{
	ni_string_free(&cb->event);
	free(cb);
}

