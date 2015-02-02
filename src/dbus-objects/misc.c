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
#include <arpa/inet.h>
#include <netlink/netlink.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/route.h>
#include <wicked/addrconf.h>
#include <wicked/resolver.h>
#include <wicked/xml.h>
#include <wicked/nis.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "misc.h"
#include "model.h"
#include "debug.h"

static dbus_bool_t		__ni_objectmodel_callback_info_to_dict(const ni_objectmodel_callback_info_t *, ni_dbus_variant_t *);
static dbus_bool_t		__ni_objectmodel_address_to_dict(const ni_address_t *, ni_dbus_variant_t *);
static ni_address_t *		__ni_objectmodel_address_from_dict(ni_address_t **, const ni_dbus_variant_t *);
static dbus_bool_t		__ni_objectmodel_route_to_dict(const ni_route_t *, ni_dbus_variant_t *);
static ni_route_t *		__ni_objectmodel_route_from_dict(ni_route_table_t **, const ni_dbus_variant_t *);

/*
 * Helper functions for getting and setting socket addresses
 */
dbus_bool_t
__ni_objectmodel_get_opaque(const ni_dbus_variant_t *var, ni_opaque_t *packed)
{
	unsigned int len;

	if (!ni_dbus_variant_get_byte_array_minmax(var, packed->data, &len, 0, sizeof(packed->data)))
		return FALSE;
	packed->len = len;
	return TRUE;
}

dbus_bool_t
__ni_objectmodel_set_sockaddr(ni_dbus_variant_t *var, const ni_sockaddr_t *sockaddr)
{
	ni_opaque_t packed;

	if (!ni_sockaddr_pack(sockaddr, &packed))
		return FALSE;

	ni_dbus_variant_set_byte_array(var, packed.data, packed.len);
	return TRUE;
}

dbus_bool_t
__ni_objectmodel_set_sockaddr_prefix(ni_dbus_variant_t *var, const ni_sockaddr_t *sockaddr, unsigned int prefix_len)
{
	ni_opaque_t packed;

	if (!ni_sockaddr_prefix_pack(sockaddr, prefix_len, &packed))
		return FALSE;

	ni_dbus_variant_set_byte_array(var, packed.data, packed.len);
	return TRUE;
}

dbus_bool_t
__ni_objectmodel_get_sockaddr(const ni_dbus_variant_t *var, ni_sockaddr_t *sockaddr)
{
	ni_opaque_t packed;

	if (!__ni_objectmodel_get_opaque(var, &packed))
		return FALSE;
	if (!ni_sockaddr_unpack(sockaddr, &packed))
		return FALSE;

	return TRUE;
}

dbus_bool_t
__ni_objectmodel_get_sockaddr_prefix(const ni_dbus_variant_t *var, ni_sockaddr_t *sockaddr, unsigned int *prefixlen)
{
	ni_opaque_t packed;

	if (!__ni_objectmodel_get_opaque(var, &packed))
		return FALSE;
	if (!ni_sockaddr_prefix_unpack(sockaddr, prefixlen, &packed))
		return FALSE;

	return TRUE;
}

dbus_bool_t
__ni_objectmodel_dict_add_sockaddr(ni_dbus_variant_t *dict, const char *name, const ni_sockaddr_t *sockaddr)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, name)))
		return FALSE;
	return __ni_objectmodel_set_sockaddr(dst, sockaddr);
}

dbus_bool_t
__ni_objectmodel_dict_add_sockaddr_prefix(ni_dbus_variant_t *dict, const char *name, const ni_sockaddr_t *sockaddr, unsigned int prefix_len)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, name)))
		return FALSE;

	return __ni_objectmodel_set_sockaddr_prefix(dst, sockaddr, prefix_len);
}

dbus_bool_t
__ni_objectmodel_dict_add_hwaddr(ni_dbus_variant_t *dict, const char *name, const ni_hwaddr_t *hwaddr)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, name)))
		return FALSE;
	return __ni_objectmodel_get_hwaddr(dst, hwaddr);
}

dbus_bool_t
__ni_objectmodel_dict_get_sockaddr(const ni_dbus_variant_t *dict, const char *name, ni_sockaddr_t *sockaddr)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, name)))
		return FALSE;
	return __ni_objectmodel_get_sockaddr(var, sockaddr);
}

dbus_bool_t
__ni_objectmodel_dict_get_sockaddr_prefix(const ni_dbus_variant_t *dict, const char *name, ni_sockaddr_t *sockaddr, unsigned int *prefixlen)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, name)))
		return FALSE;
	return __ni_objectmodel_get_sockaddr_prefix(var, sockaddr, prefixlen);
}

dbus_bool_t
__ni_objectmodel_dict_get_hwaddr(const ni_dbus_variant_t *dict, const char *name, ni_hwaddr_t *hwaddr)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, name)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(var, hwaddr);
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

static inline dbus_bool_t
__ni_objectmodel_get_printable_array(ni_string_array_t *ap, const ni_dbus_variant_t *var, DBusError *error, const char *key)
{
	unsigned int i, len;

	if (!ni_dbus_variant_is_string_array(var))
		return FALSE;

	if ((len = var->array.len) > 64)
		len = 64;

	for (i = 0; i < len; ++i) {
		const char *string_value = var->string_array_value[i];
		if (ni_check_printable(string_value, len)) {
			ni_string_array_append(ap, string_value);
		} else {
			ni_debug_objectmodel("Discarded suspect objectmodel %s: %s",
					key, ni_print_suspect(string_value, len));
			return FALSE;
		}
	}
	return TRUE;
}

dbus_bool_t
__ni_objectmodel_get_domain_string(const ni_dbus_variant_t *dict, const char *key, const char **value)
{
	const char *string_value = NULL;
	size_t len;

	if (ni_dbus_dict_get_string(dict, key, &string_value)) {
		len = ni_string_len(string_value);
		if (ni_check_domain_name(string_value, len, 0)) {
			*value = string_value;
			return TRUE;
		}
		ni_debug_objectmodel("Discarded suspect objectmodel %s: %s",
					key, ni_print_suspect(string_value, len));
	}
	return FALSE;
}

static inline dbus_bool_t
__ni_objectmodel_get_pathname_string(const ni_dbus_variant_t *dict, const char *key, const char **value)
{
	const char *string_value = NULL;
	size_t len;
	if (ni_dbus_dict_get_string(dict, key, &string_value)) {
		len = ni_string_len(string_value);
		if (ni_check_pathname(string_value, len)) {
			*value = string_value;
			return TRUE;
		}
		ni_debug_objectmodel("Discarded suspect objectmodel %s: %s",
				key, ni_print_suspect(string_value, len));
	}
	return FALSE;
}

static inline dbus_bool_t
__ni_objectmodel_get_printable_string(const ni_dbus_variant_t *dict, const char *key, const char **value)
{
	const char *string_value = NULL;
	size_t len;
	if (ni_dbus_dict_get_string(dict, key, &string_value)) {
		len = ni_string_len(string_value);
		if (ni_check_printable(string_value, len)) {
			*value = string_value;
			return TRUE;
		}
		ni_debug_objectmodel("Discarded suspect objectmodel %s: %s",
				key, ni_print_suspect(string_value, len));
	}
	return FALSE;
}

static inline dbus_bool_t
__ni_objectmodel_get_domain_array(ni_string_array_t *ap, const ni_dbus_variant_t *var, DBusError *error, const char *key)
{
	unsigned int i, len;
	const char *vstr;
	size_t vlen;

	if (!ni_dbus_variant_is_string_array(var))
		return FALSE;

	if ((len = var->array.len) > 64)
		len = 64;

	for (i = 0; i < len; ++i) {
		vstr = var->string_array_value[i];
		vlen = ni_string_len(vstr);

		if (ni_check_domain_name(vstr, vlen, 0)) {
			ni_string_array_append(ap, vstr);
			continue;
		}
		ni_debug_objectmodel("Discarded suspect objectmodel %s: %s",
				key, ni_print_suspect(vstr, vlen));
	}
	return TRUE;
}

static inline dbus_bool_t
__ni_objectmodel_get_server_array(ni_string_array_t *ap, const ni_dbus_variant_t *var, DBusError *error, const char *key)
{
	unsigned int i, len;
	ni_sockaddr_t addr;
	const char *vstr;
	size_t vlen;

	if (!ni_dbus_variant_is_string_array(var))
		return FALSE;

	if ((len = var->array.len) > 64)
		len = 64;

	for (i = 0; i < len; ++i) {
		vstr = var->string_array_value[i];
		vlen = ni_string_len(vstr);

		if (vlen > 0 && strchr(vstr, ':') != NULL) {
			/* IPv6 address */
			if (inet_pton(AF_INET6, vstr, &addr.six.sin6_addr) == 1) {
				ni_string_array_append(ap, vstr);
				continue;
			}
		} else if (ni_check_domain_name(vstr, vlen, 0)) {
			/* IPv4 address or FQDN */
			ni_string_array_append(ap, vstr);
			continue;
		}

		ni_debug_objectmodel("Discarded suspect objectmodel %s: %s",
				key, ni_print_suspect(vstr, vlen));
	}
	return TRUE;
}

static inline dbus_bool_t
__ni_objectmodel_get_address_array(ni_string_array_t *ap, const ni_dbus_variant_t *var, DBusError *error, const char *key)
{
	unsigned int i, len;
	ni_sockaddr_t addr;
	const char *vstr;
	size_t vlen;

	if (!ni_dbus_variant_is_string_array(var))
		return FALSE;

	if ((len = var->array.len) > 64)
		len = 64;

	for (i = 0; i < len; ++i) {
		vstr = var->string_array_value[i];
		vlen = ni_string_len(vstr);

		if (vlen > 0 && strchr(vstr, ':') != NULL) {
			/* IPv6 address */
			if (inet_pton(AF_INET6, vstr, &addr.six.sin6_addr) == 1) {
				ni_string_array_append(ap, vstr);
				continue;
			}
		} else if (vlen > 0) {
			/* IPv4 address */
			if (inet_pton(AF_INET, vstr, &addr.sin.sin_addr) == 1) {
				ni_string_array_append(ap, vstr);
				continue;
			}
		}

		ni_debug_objectmodel("Discarded suspect objectmodel %s: %s",
				key, ni_print_suspect(vstr, vlen));
	}
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

dbus_bool_t
__ni_objectmodel_set_resolver_dict(ni_resolver_info_t **resinfo,
				const ni_dbus_variant_t *dict,
				DBusError *error)
{
	ni_resolver_info_t *resolv = NULL;
	ni_dbus_variant_t *child;
	const char *string_value;

	if (!ni_dbus_variant_is_dict(dict)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: argument type mismatch",
				__FUNCTION__);
		return FALSE;
	}

	if ((child = ni_dbus_dict_get(dict, "resolver")) != NULL) {
		ni_dbus_variant_t *list;

		resolv = ni_resolver_info_new();
		if (__ni_objectmodel_get_domain_string(child,
					"default-domain", &string_value))
			ni_string_dup(&resolv->default_domain, string_value);

		if ((list = ni_dbus_dict_get(child, "servers")) != NULL
		&& !__ni_objectmodel_get_address_array(&resolv->dns_servers,
					list, error, "dns-server"))
			goto failure;

		if ((list = ni_dbus_dict_get(child, "search")) != NULL
		&& !__ni_objectmodel_get_domain_array(&resolv->dns_search,
					list, error, "dns-search"))
			goto failure;
	}

	*resinfo = resolv;
	return TRUE;

failure:
	if (resolv)
		ni_resolver_info_free(resolv);
	return FALSE;
}

/*
 * Common functions to represent an assigned address as a dict
 */
dbus_bool_t
__ni_objectmodel_address_to_dict(const ni_address_t *ap, ni_dbus_variant_t *dict)
{
	__ni_objectmodel_dict_add_sockaddr_prefix(dict, "local", &ap->local_addr, ap->prefixlen);
	if (ap->peer_addr.ss_family == ap->family)
		__ni_objectmodel_dict_add_sockaddr(dict, "peer", &ap->peer_addr);
	if (ap->anycast_addr.ss_family == ap->family)
		__ni_objectmodel_dict_add_sockaddr(dict, "anycast", &ap->anycast_addr);
	if (ap->bcast_addr.ss_family == ap->family)
		__ni_objectmodel_dict_add_sockaddr(dict, "broadcast", &ap->bcast_addr);

	if (ap->flags)
		ni_dbus_dict_add_uint32(dict, "flags", ap->flags);

	if (ap->family == AF_INET && ap->label)
		ni_dbus_dict_add_string(dict, "label", ap->label);

	if (ap->ipv6_cache_info.preferred_lft || ap->ipv6_cache_info.valid_lft) {
		ni_dbus_variant_t *var;

		var = ni_dbus_dict_add(dict, "cache-info");
		ni_dbus_variant_init_dict(var);

		ni_dbus_dict_add_uint32(var, "preferred-lifetime", ap->ipv6_cache_info.preferred_lft);
		ni_dbus_dict_add_uint32(var, "valid-lifetime", ap->ipv6_cache_info.valid_lft);
	}

	if (ap->owner != NI_ADDRCONF_NONE)
		ni_dbus_dict_add_uint32(dict, "owner", ap->owner);

	return TRUE;
}

ni_address_t *
__ni_objectmodel_address_from_dict(ni_address_t **list, const ni_dbus_variant_t *dict)
{
	ni_address_t *ap = NULL;
	ni_sockaddr_t local_addr;
	unsigned int prefixlen;

	if (__ni_objectmodel_dict_get_sockaddr_prefix(dict, "local", &local_addr, &prefixlen)) {
		const ni_dbus_variant_t *var;
		const char *label;

		ap = ni_address_new(local_addr.ss_family, prefixlen, &local_addr, NULL);
		if (!ap)
			return NULL;

		__ni_objectmodel_dict_get_sockaddr(dict, "peer", &ap->peer_addr);
		__ni_objectmodel_dict_get_sockaddr(dict, "anycast", &ap->anycast_addr);
		__ni_objectmodel_dict_get_sockaddr(dict, "broadcast", &ap->bcast_addr);

		/* Do we need to translate them and map to names?
		 * The usable flags differ between address families and
		 * ipv6 temporary flag is same bit as secondary in ipv4.
		 */
		ni_dbus_dict_get_uint32(dict, "flags", &ap->flags);
		if (ap->family == AF_INET) {
			if (ni_dbus_dict_get_string(dict, "label", &label))
				ni_string_dup(&ap->label, label);
		}

		if ((var = ni_dbus_dict_get(dict, "cache-info")) != NULL) {
			uint32_t prefered_lft = 0, valid_lft = 0;

			ni_dbus_dict_get_uint32(var, "preferred-lifetime", &prefered_lft);
			ni_dbus_dict_get_uint32(var, "valid-lifetime", &valid_lft);

			/* as they're there, they've to be valid */
			if (!valid_lft || prefered_lft > valid_lft) {
				ni_address_free(ap);
				return NULL;
			}
			ap->ipv6_cache_info.preferred_lft = prefered_lft;
			ap->ipv6_cache_info.valid_lft = valid_lft;
		}

		if (ni_dbus_dict_get_uint32(dict, "owner", &ap->owner)) {
			if (ap->owner >= __NI_ADDRCONF_MAX)
				ap->owner = NI_ADDRCONF_NONE;
		}

		ni_address_list_append(list, ap);
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
__ni_objectmodel_get_route_list(ni_route_table_t *list,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_route_table_t *tab;
	const ni_route_t *rp;
	unsigned int i;
	dbus_bool_t rv = TRUE;

	for (tab = list; rv && tab; tab = tab->next) {
		for (i = 0; rv && i < tab->routes.count; ++i) {
			ni_dbus_variant_t *dict;

			if ((rp = tab->routes.data[i]) == NULL)
				continue;

			if (rp->family != rp->destination.ss_family)
				continue;

			/* Append a new element to the array */
			if (!(dict = ni_dbus_dict_array_add(result)))
				return FALSE;
			ni_dbus_variant_init_dict(dict);

			rv = __ni_objectmodel_route_to_dict(rp, dict);
		}
	}

	return rv;
}

/*
 * Build a route list from a dbus dict
 */
dbus_bool_t
__ni_objectmodel_set_route_list(ni_route_table_t **list,
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
__ni_objectmodel_get_route_dict(ni_route_table_t *list,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_route_table_t *tab;
	const ni_route_t *rp;
	unsigned int i;
	dbus_bool_t rv = TRUE;

	for (tab = list; rv && tab; tab = tab->next) {
		for (i = 0; rv && i < tab->routes.count; ++i) {
			ni_dbus_variant_t *dict;

			if ((rp = tab->routes.data[i]) == NULL)
				continue;

			if (rp->family != rp->destination.ss_family)
				continue;

			/* Append a new element to the array */
			dict = ni_dbus_dict_add(result, "route");
			ni_dbus_variant_init_dict(dict);

			rv = __ni_objectmodel_route_to_dict(rp, dict);
		}
	}

	return rv;
}

dbus_bool_t
__ni_objectmodel_set_route_dict(ni_route_table_t **list,
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

	__ni_objectmodel_dict_add_sockaddr_prefix(dict, "destination",
				&rp->destination, rp->prefixlen);

	if (ni_sockaddr_is_specified(&rp->pref_src))
		__ni_objectmodel_dict_add_sockaddr(dict, "pref-source", &rp->pref_src);
	if (rp->priority)
		ni_dbus_dict_add_uint32(dict, "priority", rp->priority);
	if (rp->flags)
		ni_dbus_dict_add_uint32(dict, "flags", rp->flags);
	if (rp->realm)
		ni_dbus_dict_add_uint32(dict, "realm", rp->realm);
	if (rp->mark)
		ni_dbus_dict_add_uint32(dict, "mark", rp->mark);
	if (rp->tos)
		ni_dbus_dict_add_uint32(dict, "tos", rp->tos);

	if (rp->nh.gateway.ss_family != AF_UNSPEC) {
		for (nh = &rp->nh; nh; nh = nh->next) {
			ni_dbus_variant_t *nhdict;

			nhdict = ni_dbus_dict_add(dict, "nexthop");
			ni_dbus_variant_init_dict(nhdict);

			__ni_objectmodel_dict_add_sockaddr(nhdict, "gateway", &nh->gateway);
			if (nh->device.name)
				ni_dbus_dict_add_string(nhdict, "device", nh->device.name);
			if (nh->weight)
				ni_dbus_dict_add_uint32(nhdict, "weight", nh->weight);
			if (nh->flags)
				ni_dbus_dict_add_uint32(nhdict, "flags", nh->flags);
			if (nh->realm)
				ni_dbus_dict_add_uint32(nhdict, "realm", nh->realm);
		}
	}

	child = ni_dbus_dict_add(dict, "kern");
	ni_dbus_variant_init_dict(child);
	if (rp->table) {
		const char *name = NULL;
		char *tmp_name = NULL;
		if ((name = ni_route_table_type_to_name(rp->table, &tmp_name)))
			ni_dbus_dict_add_string(child, "table", name);
		else
			ni_error("failed to obtain name of routing table %u", rp->table);
		ni_string_free(&tmp_name);
	}
	if (rp->type)
		ni_dbus_dict_add_uint32(child, "type", rp->type);
	ni_dbus_dict_add_uint32(child, "scope", rp->scope);
	if (rp->protocol)
		ni_dbus_dict_add_uint32(child, "protocol", rp->protocol);

	child = ni_dbus_dict_add(dict, "metrics");
	ni_dbus_variant_init_dict(child);
	if (rp->lock)
		ni_dbus_dict_add_uint32(child, "lock", rp->lock);
	if (rp->mtu)
		ni_dbus_dict_add_uint32(child, "mtu", rp->mtu);
	if (rp->window)
		ni_dbus_dict_add_uint32(child, "window", rp->window);
	if (rp->rtt)
		ni_dbus_dict_add_uint32(child, "rtt", rp->rtt);
	if (rp->rttvar)
		ni_dbus_dict_add_uint32(child, "rttvar", rp->rttvar);
	if (rp->ssthresh)
		ni_dbus_dict_add_uint32(child, "ssthresh", rp->ssthresh);
	if (rp->cwnd)
		ni_dbus_dict_add_uint32(child, "cwnd", rp->cwnd);
	if (rp->advmss)
		ni_dbus_dict_add_uint32(child, "advmss", rp->advmss);
	if (rp->reordering)
		ni_dbus_dict_add_uint32(child, "reordering", rp->reordering);
	if (rp->hoplimit)
		ni_dbus_dict_add_uint32(child, "hoplimit", rp->hoplimit);
	if (rp->initcwnd)
		ni_dbus_dict_add_uint32(child, "initcwnd", rp->initcwnd);
	if (rp->features)
		ni_dbus_dict_add_uint32(child, "features", rp->features);
	if (rp->rto_min)
		ni_dbus_dict_add_uint32(child, "rto_min", rp->rto_min);
	if (rp->initrwnd)
		ni_dbus_dict_add_uint32(child, "initrwnd", rp->initrwnd);

	if (rp->owner)
		ni_dbus_dict_add_uint32(dict, "owner", rp->owner);

	return TRUE;
}

static ni_bool_t
__ni_objectmodel_route_nexthop_from_dict(ni_route_nexthop_t *nh, const ni_dbus_variant_t *nhdict)
{
	const char *string;
	uint32_t value;

	/*
	 * we cannot check if a hop contains device and/or gateway
	 * as we don't have the (interface) context of the route.
	 */
	if (ni_dbus_dict_get(nhdict, "gateway")) {
		if (!__ni_objectmodel_dict_get_sockaddr(nhdict, "gateway", &nh->gateway)) {
			ni_debug_dbus("%s: invalid route hop gateway %u", __func__, value);
			return FALSE;
		}
	}

	if (ni_dbus_dict_get_string(nhdict, "device", &string)) {
		if (!ni_netdev_name_is_valid(string)) {
			ni_debug_dbus("%s: invalid route hop device name: %s", __func__,
					ni_print_suspect(string, ni_string_len(string)));
			return FALSE;
		}
		ni_string_dup(&nh->device.name, string);
	}

	if (ni_dbus_dict_get_uint32(nhdict, "weight", &value))
		nh->weight = value;
	if (ni_dbus_dict_get_uint32(nhdict, "flags", &value))
		nh->flags = value;
	if (ni_dbus_dict_get_uint32(nhdict, "realm", &value))
		nh->realm = value;

	return TRUE;
}

static ni_bool_t
__ni_objectmodel_route_kern_from_dict(ni_route_t *rp, const ni_dbus_variant_t *rtkern,
				ni_bool_t *table_ok, ni_bool_t *scope_ok)
{
	uint32_t value;
	const char *string = NULL;

	if (ni_dbus_dict_get_uint32(rtkern, "type", &value)) {
		if (!ni_route_is_valid_type(value)) {
			ni_debug_dbus("%s: invalid route type %u", __func__, value);
			return FALSE;
		}
		rp->type = value;
	}
	if (ni_dbus_dict_get_string(rtkern, "table", &string)) {
		if (!ni_route_table_name_to_type(string, &value) ||
			!ni_route_is_valid_table(value)) {
			ni_debug_dbus("%s: invalid route table %u", __func__, value);
			return FALSE;
		}
		rp->table = value;
		*table_ok = TRUE;
	}
	if (ni_dbus_dict_get_uint32(rtkern, "scope", &value)) {
		if (!ni_route_is_valid_scope(value)) {
			ni_debug_dbus("%s: invalid route scope %u", __func__, value);
			return FALSE;
		}
		rp->scope = value;
		*scope_ok = TRUE;
	}
	if (ni_dbus_dict_get_uint32(rtkern, "protocol", &value)) {
		if (!ni_route_is_valid_protocol(value)) {
			ni_debug_dbus("%s: invalid route protocol %u", __func__, value);
			return FALSE;
		}
		rp->protocol = value;
	}
	return TRUE;
}

ni_route_t *
__ni_objectmodel_route_from_dict(ni_route_table_t **list, const ni_dbus_variant_t *dict)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	const ni_dbus_variant_t *nhdict, *child;
	ni_route_t *rp = NULL;
	uint32_t value;
	ni_bool_t scope_ok = FALSE;
	ni_bool_t table_ok = FALSE;

	rp = ni_route_new();
	rp->type = RTN_UNICAST;
	rp->table = RT_TABLE_MAIN;
	rp->scope = RT_SCOPE_NOWHERE;
	rp->protocol = RTPROT_BOOT;

	if ((child = ni_dbus_dict_get(dict, "kern")) != NULL) {
		if (!__ni_objectmodel_route_kern_from_dict(rp, child, &table_ok, &scope_ok))
			goto failure;
	}

	if (!table_ok)
		rp->table = ni_route_guess_table(rp);

	if (ni_route_type_needs_nexthop(rp->type) &&
	    (nhdict = ni_dbus_dict_get(dict, "nexthop")) != NULL) {
		ni_route_nexthop_t *nh = &rp->nh, **nhpos = &nh;

		while (nh) {
			if (!__ni_objectmodel_route_nexthop_from_dict(nh, nhdict))
				goto failure;

			if (rp->nh.gateway.ss_family != AF_UNSPEC &&
			    rp->nh.gateway.ss_family != nh->gateway.ss_family) {
				ni_debug_dbus("%s: route nexthop with gateway family mix",
						__func__);
				goto failure;
			}

			nhdict = ni_dbus_dict_get_next(dict, "nexthop", nhdict);
			if (nhdict) {
				nhpos = &nh->next;
				*nhpos = nh = ni_route_nexthop_new();
			} else {
				nh = NULL;
			}
		}
	}

	if (!scope_ok)
		rp->scope = ni_route_guess_scope(rp);

	if (!__ni_objectmodel_dict_get_sockaddr_prefix(dict, "destination",
				&rp->destination, &rp->prefixlen)) {
		/* omitted destination just means it is a default route */
		rp->destination.ss_family = rp->nh.gateway.ss_family;
		rp->prefixlen = 0;
	}

	/*
	 * Hmm... check device default route / default route without a gateway?
	 */
	if (rp->destination.ss_family == AF_UNSPEC) {
		ni_debug_dbus("%s: unknown route destination family", __func__);
		goto failure;
	} else
	if (rp->nh.gateway.ss_family != AF_UNSPEC &&
	    rp->nh.gateway.ss_family != rp->destination.ss_family) {
		ni_debug_dbus("%s: unknown route with destination/gateway family mix", __func__);
		goto failure;
	}
	rp->family = rp->destination.ss_family;

	__ni_objectmodel_dict_get_sockaddr(dict, "pref-source", &rp->pref_src);
	if (ni_dbus_dict_get_uint32(dict, "priority", &value))
		rp->priority = value;
	if (ni_dbus_dict_get_uint32(dict, "flags", &value))
		rp->flags = value;
	if (ni_dbus_dict_get_uint32(dict, "realm", &value))
		rp->realm = value;
	if (ni_dbus_dict_get_uint32(dict, "mark", &value))
		rp->mark = value;
	if (ni_dbus_dict_get_uint32(dict, "tos", &value))
		rp->tos = value;

	if ((child = ni_dbus_dict_get(dict, "metrics")) != NULL) {
		if (ni_dbus_dict_get_uint32(child, "lock", &value))
			rp->lock = value;
		if (ni_dbus_dict_get_uint32(child, "mtu", &value))
			rp->mtu = value;
		if (ni_dbus_dict_get_uint32(child, "window", &value))
			rp->window = value;
		if (ni_dbus_dict_get_uint32(child, "rtt", &value))
			rp->rtt = value;
		if (ni_dbus_dict_get_uint32(child, "rttvar", &value))
			rp->rttvar = value;
		if (ni_dbus_dict_get_uint32(child, "ssthresh", &value))
			rp->ssthresh = value;
		if (ni_dbus_dict_get_uint32(child, "cwnd", &value))
			rp->cwnd = value;
		if (ni_dbus_dict_get_uint32(child, "advmss", &value))
			rp->advmss = value;
		if (ni_dbus_dict_get_uint32(child, "reordering", &value))
			rp->reordering = value;
		if (ni_dbus_dict_get_uint32(child, "hoplimit", &value))
			rp->hoplimit = value;
		if (ni_dbus_dict_get_uint32(child, "initcwnd", &value))
			rp->initcwnd = value;
		if (ni_dbus_dict_get_uint32(child, "features", &value))
			rp->features = value;
		if (ni_dbus_dict_get_uint32(child, "rto_min", &value))
			rp->rto_min = value;
		if (ni_dbus_dict_get_uint32(child, "initrwnd", &value))
			rp->initrwnd = value;
	}

	if (ni_dbus_dict_get_uint32(dict, "owner", &rp->owner)) {
		if (rp->owner >= __NI_ADDRCONF_MAX)
			rp->owner = NI_ADDRCONF_NONE;
	}

	if (ni_route_tables_add_route(list, rp))
		return rp;

failure:
	ni_debug_dbus("%s: Cannot get complete route from dbus dict (%s)",
			__func__, ni_route_print(&buf, rp));
	ni_stringbuf_destroy(&buf);
	if (rp) {
		ni_route_free(rp);
	}
	return NULL;
}

/*
 * Build a DBus dict from an addrconf lease
 */
static void
__ni_objectmodel_get_addrconf_dhcp4_dict(const struct ni_addrconf_lease_dhcp4 *dhcp4,
					ni_dbus_variant_t *dict)
{
	if (dhcp4->client_id.len) {
		ni_dbus_dict_add_string(dict, "client-id", ni_print_hex
				(dhcp4->client_id.data, dhcp4->client_id.len));
	}
	if (dhcp4->server_id.s_addr) {
		ni_dbus_dict_add_string(dict, "server-id",
				inet_ntoa(dhcp4->server_id));
	}
	if (dhcp4->relay_addr.s_addr) {
		ni_dbus_dict_add_string(dict, "relay-address",
				inet_ntoa(dhcp4->relay_addr));
	}
	if (dhcp4->mtu) {
		ni_dbus_dict_add_uint16(dict, "mtu", dhcp4->mtu);
	}
	if (dhcp4->lease_time) {
		ni_dbus_dict_add_uint32(dict, "lease-time", dhcp4->lease_time);
	}
	if (dhcp4->renewal_time) {
		ni_dbus_dict_add_uint32(dict, "renewal-time", dhcp4->renewal_time);
	}
	if (dhcp4->rebind_time) {
		ni_dbus_dict_add_uint32(dict, "rebind-time", dhcp4->rebind_time);
	}
	if (dhcp4->boot_saddr.s_addr) {
		ni_dbus_dict_add_string(dict, "boot-server-address",
						inet_ntoa(dhcp4->boot_saddr));
	}
	if (dhcp4->boot_sname) {
		ni_dbus_dict_add_string(dict, "boot-server-name",
						dhcp4->boot_sname);
	}
	if (dhcp4->boot_file) {
		ni_dbus_dict_add_string(dict, "boot-filename",
						dhcp4->boot_file);
	}
	if (dhcp4->root_path) {
		ni_dbus_dict_add_string(dict, "root-path",
						dhcp4->root_path);
	}
	if (dhcp4->message) {
		ni_dbus_dict_add_string(dict, "message",
						dhcp4->message);
	}
}

static void
__ni_objectmodel_get_addrconf_dhcp6_dict(const struct ni_addrconf_lease_dhcp6 *dhcp6,
					ni_dbus_variant_t *dict)
{
	ni_sockaddr_t addr;

	if (dhcp6->client_id.len) {
		ni_dbus_dict_add_string(dict, "client-id", ni_print_hex
				(dhcp6->client_id.data, dhcp6->client_id.len));
	}
	if (dhcp6->server_id.len) {
		ni_dbus_dict_add_string(dict, "server-id", ni_print_hex(
				dhcp6->server_id.data, dhcp6->server_id.len));
	}
	ni_sockaddr_set_ipv6(&addr, dhcp6->server_addr, 0);
	if (ni_sockaddr_is_specified(&addr)) {
		ni_dbus_dict_add_string(dict, "server-address",
				ni_sockaddr_print(&addr));
	}
	if (dhcp6->server_pref) {
		ni_dbus_dict_add_uint16(dict, "server-preference", dhcp6->server_pref);
	}
	if (dhcp6->rapid_commit) {
		ni_dbus_dict_add_bool(dict, "rapid-commit", dhcp6->rapid_commit);
	}

	/* Hmm... status + ia_list: only if we need it */

	if (dhcp6->boot_url) {
		ni_dbus_dict_add_string(dict, "bootfile-url", dhcp6->boot_url);
	}
	if (dhcp6->boot_params.count) {
		__ni_objectmodel_set_string_array(dict, "bootfile-params",
							&dhcp6->boot_params);
	}
}

dbus_bool_t
__ni_objectmodel_get_addrconf_lease(const ni_addrconf_lease_t *lease,
						ni_dbus_variant_t *result,
						DBusError *error)
{
	ni_dbus_variant_t *child;

	ni_dbus_dict_add_uint32(result, "state", lease->state);
	ni_dbus_dict_add_uint32(result, "acquired", lease->time_acquired);
	ni_dbus_dict_add_uint32(result, "update", lease->update);

	ni_dbus_dict_add_uint32(result, "flags", lease->flags);
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

	if (lease->nis) {
		ni_nis_info_t *nis = lease->nis;

		child = ni_dbus_dict_add(result, "nis");
		ni_dbus_variant_init_dict(child);

		if (nis->domainname)
			ni_dbus_dict_add_string(child, "domainname", nis->domainname);
		ni_dbus_dict_add_uint32(child, "binding", nis->default_binding);
		__ni_objectmodel_set_string_array(child, "servers", &nis->default_servers);
	}

	__ni_objectmodel_set_string_array(result, "log-servers", &lease->log_servers);
	__ni_objectmodel_set_string_array(result, "ntp-servers", &lease->ntp_servers);
	__ni_objectmodel_set_string_array(result, "slp-servers", &lease->slp_servers);
	__ni_objectmodel_set_string_array(result, "slp-scopes", &lease->slp_scopes);
	__ni_objectmodel_set_string_array(result, "sip-servers", &lease->sip_servers);
	__ni_objectmodel_set_string_array(result, "lpr-servers", &lease->lpr_servers);

	__ni_objectmodel_set_string_array(result, "nds-servers", &lease->nds_servers);
	__ni_objectmodel_set_string_array(result, "nds-context", &lease->nds_context);
	if (lease->nds_tree)
		ni_dbus_dict_add_string  (result, "nds-tree",    lease->nds_tree);

	__ni_objectmodel_set_string_array(result, "netbios-name-servers", &lease->netbios_name_servers);
	__ni_objectmodel_set_string_array(result, "netbios-dd-servers", &lease->netbios_dd_servers);
	if (lease->netbios_type)
		ni_dbus_dict_add_string(result, "netbios-node-type",
				ni_netbios_node_type_to_name(lease->netbios_type));
	if (lease->netbios_scope)
		ni_dbus_dict_add_string(result, "netbios-scope", lease->netbios_scope);

	if (lease->posix_tz_string)
		ni_dbus_dict_add_string(result, "posix-timezone-string",
						lease->posix_tz_string);
	if (lease->posix_tz_dbname)
		ni_dbus_dict_add_string(result, "posix-timezone-dbname",
						lease->posix_tz_dbname);

	if (lease->family == AF_INET  && lease->type == NI_ADDRCONF_DHCP) {
		child = ni_dbus_dict_add(result, "ipv4:dhcp");
		ni_dbus_variant_init_dict(child);

		__ni_objectmodel_get_addrconf_dhcp4_dict(&lease->dhcp4, child);
	} else
	if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_DHCP) {
		child = ni_dbus_dict_add(result, "ipv6:dhcp");
		ni_dbus_variant_init_dict(child);

		__ni_objectmodel_get_addrconf_dhcp6_dict(&lease->dhcp6, child);
	}
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

static dbus_bool_t
__ni_objectmodel_set_addrconf_dhcp4_data(struct ni_addrconf_lease_dhcp4 *dhcp4,
					const ni_dbus_variant_t *dict,
					DBusError *error)
{
	const char *string_value;
	uint32_t value32;
	uint16_t value16;
	ni_sockaddr_t addr;
	int len;

	if (ni_dbus_dict_get_string(dict, "client-id", &string_value)) {
		if ((len = ni_parse_hex(string_value, dhcp4->client_id.data,
					sizeof(dhcp4->client_id.data))) < 0)
			return FALSE;
		dhcp4->client_id.len = (unsigned int)len;
	}
	if (ni_dbus_dict_get_string(dict, "server-id", &string_value)) {
		if (ni_sockaddr_parse(&addr, string_value, AF_INET) < 0)
			return FALSE;
		dhcp4->server_id = addr.sin.sin_addr;
	}
	if (ni_dbus_dict_get_string(dict, "relay-address", &string_value)) {
		if (ni_sockaddr_parse(&addr, string_value, AF_INET) < 0)
			return FALSE;
		dhcp4->relay_addr = addr.sin.sin_addr;
	}
	if (ni_dbus_dict_get_uint16(dict, "mtu", &value16))
		dhcp4->mtu = value16;
	if (ni_dbus_dict_get_uint32(dict, "lease-time", &value32))
		dhcp4->lease_time = value32;
	if (ni_dbus_dict_get_uint32(dict, "renewal-time", &value32))
		dhcp4->renewal_time = value32;
	if (ni_dbus_dict_get_uint32(dict, "rebind-time", &value32))
		dhcp4->rebind_time = value32;
	if (ni_dbus_dict_get_string(dict, "boot-server-address", &string_value)) {
		if (ni_sockaddr_parse(&addr, string_value, AF_INET) < 0)
			return FALSE;
		dhcp4->boot_saddr = addr.sin.sin_addr;
	}
	if (__ni_objectmodel_get_domain_string(dict, "boot-server-name", &string_value))
		ni_string_dup(&dhcp4->boot_sname, string_value);
	if (__ni_objectmodel_get_pathname_string(dict, "boot-filename", &string_value))
		ni_string_dup(&dhcp4->boot_file, string_value);
	if (__ni_objectmodel_get_pathname_string(dict, "root-path", &string_value))
		ni_string_dup(&dhcp4->root_path, string_value);
	if (__ni_objectmodel_get_printable_string(dict, "message", &string_value))
		ni_string_dup(&dhcp4->message, string_value);

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_set_addrconf_dhcp6_data(struct ni_addrconf_lease_dhcp6 *dhcp6,
					const ni_dbus_variant_t *dict,
					DBusError *error)
{
	ni_dbus_variant_t *var;
	const char *string_value;
	dbus_bool_t bool_value;
	uint16_t value16;
	ni_sockaddr_t addr;
	int len;

	if (ni_dbus_dict_get_string(dict, "client-id", &string_value)) {
		if ((len = ni_parse_hex(string_value, dhcp6->client_id.data,
					sizeof(dhcp6->client_id.data))) < 0)
			return FALSE;
		dhcp6->client_id.len = len;
	}
	if (ni_dbus_dict_get_string(dict, "server-id", &string_value)) {
		if ((len = ni_parse_hex(string_value, dhcp6->server_id.data,
					sizeof(dhcp6->server_id.data))) < 0)
			return FALSE;
		dhcp6->server_id.len = len;
	}
	if (ni_dbus_dict_get_string(dict, "server-address", &string_value)) {
		if (ni_sockaddr_parse(&addr, string_value, AF_INET6) < 0)
			return FALSE;
		dhcp6->server_addr = addr.six.sin6_addr;
	}
	if (ni_dbus_dict_get_uint16(dict, "server-preference", &value16) &&
			value16 < 255)
		dhcp6->server_pref = value16;

	if (ni_dbus_dict_get_bool(dict, "rapid-commit", &bool_value))
		dhcp6->rapid_commit = bool_value;

	/* Hmm... status + ia_list: only if we need it */

	if (__ni_objectmodel_get_printable_string(dict, "bootfile-url", &string_value))
		ni_string_dup(&dhcp6->boot_url, string_value);

	if ((var = ni_dbus_dict_get(dict, "bootfile-params")) != NULL
	 && !__ni_objectmodel_get_printable_array(&dhcp6->boot_params, var,
						error, "bootfile-params"))
		return FALSE;

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

	if (ni_dbus_dict_get_uint32(argument, "update", &value32))
		lease->update = value32;

	if (ni_dbus_dict_get_uint32(argument, "flags", &value32))
		lease->flags = value32;
	if ((child = ni_dbus_dict_get(argument, "uuid")) != NULL
	 && !ni_dbus_variant_get_uuid(child, &lease->uuid))
		return FALSE;

	if (__ni_objectmodel_get_domain_string(argument, "hostname", &string_value))
		ni_string_dup(&lease->hostname, string_value);

	if ((child = ni_dbus_dict_get(argument, "addresses")) != NULL
	 && !__ni_objectmodel_set_address_list(&lease->addrs, child, error))
		return FALSE;

	if ((child = ni_dbus_dict_get(argument, "routes")) != NULL
	 && !__ni_objectmodel_set_route_list(&lease->routes, child, error))
		return FALSE;

	if (!__ni_objectmodel_set_resolver_dict(&lease->resolver, argument, error))
		return FALSE;

	if ((child = ni_dbus_dict_get(argument, "nis")) != NULL) {
		ni_nis_info_t *nis = ni_nis_info_new();
		ni_dbus_variant_t *list;

		lease->nis = nis;
		if (__ni_objectmodel_get_domain_string(child, "domainname",
								&string_value))
			ni_string_dup(&nis->domainname, string_value);

		if (ni_dbus_dict_get_uint32(child, "binding", &value32))
			nis->default_binding = value32;

		if ((list = ni_dbus_dict_get(child, "servers")) != NULL
		 && !__ni_objectmodel_get_address_array(&nis->default_servers, list,
							error, "servers"))
			return FALSE;
	}

	if ((child = ni_dbus_dict_get(argument, "log-servers")) != NULL
	 && !__ni_objectmodel_get_address_array(&lease->log_servers, child, error,
						"log-servers"))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "ntp-servers")) != NULL
	 && !__ni_objectmodel_get_address_array(&lease->ntp_servers, child, error,
						"ntp-servers"))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "slp-servers")) != NULL
	 && !__ni_objectmodel_get_address_array(&lease->slp_servers, child, error,
						"slp-servers"))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "slp-scopes")) != NULL
	 && !__ni_objectmodel_get_domain_array(&lease->slp_scopes, child, error,
						"slp-scopes"))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "sip-servers")) != NULL
	 && !__ni_objectmodel_get_server_array(&lease->sip_servers, child, error,
						"sip-servers"))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "lpr-servers")) != NULL
	 && !__ni_objectmodel_get_address_array(&lease->lpr_servers, child, error,
						"lpr-servers"))
		return FALSE;

	if ((child = ni_dbus_dict_get(argument, "nds-servers")) != NULL
	 && !__ni_objectmodel_get_address_array(&lease->nds_servers, child, error,
						"nds-servers"))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "nds-context")) != NULL
	 && !__ni_objectmodel_get_printable_array(&lease->nds_context, child, error,
						"nds-context"))
		return FALSE;
	if (__ni_objectmodel_get_printable_string(argument, "nds-tree", &string_value))
		ni_string_dup(&lease->nds_tree, string_value);

	if ((child = ni_dbus_dict_get(argument, "netbios-name-servers")) != NULL
	 && !__ni_objectmodel_get_address_array(&lease->netbios_name_servers, child,
						error, "netbios-name-servers"))
		return FALSE;
	if ((child = ni_dbus_dict_get(argument, "netbios-dd-servers")) != NULL
	 && !__ni_objectmodel_get_address_array(&lease->netbios_dd_servers, child,
						error, "netbios-dd-servers"))
		return FALSE;
	if (ni_dbus_dict_get_string(argument, "netbios-node-type", &string_value))
		ni_netbios_node_type_to_code(string_value, &lease->netbios_type);
	if (__ni_objectmodel_get_domain_string(argument, "netbios-scope", &string_value))
		ni_string_dup(&lease->netbios_scope, string_value);

	if (__ni_objectmodel_get_printable_string(argument, "posix-timezone-string",
				&string_value))
		ni_string_dup(&lease->posix_tz_string, string_value);

	if (__ni_objectmodel_get_pathname_string(argument, "posix-timezone-dbname",
				&string_value))
		ni_string_dup(&lease->posix_tz_dbname, string_value);

	if (lease->family == AF_INET  && lease->type == NI_ADDRCONF_DHCP &&
	    (child = ni_dbus_dict_get(argument, "ipv4:dhcp")) != NULL) {
		if (!__ni_objectmodel_set_addrconf_dhcp4_data(&lease->dhcp4, child, error))
			return FALSE;
	} else
	if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_DHCP &&
	    (child = ni_dbus_dict_get(argument, "ipv6:dhcp")) != NULL) {
		if (!__ni_objectmodel_set_addrconf_dhcp6_data(&lease->dhcp6, child, error))
			return FALSE;
	}

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
 * Handle an array of names
 */
dbus_bool_t
ni_objectmodel_get_name_array(const xml_node_t *names, ni_dbus_variant_t *result)
{
	const xml_node_t *name;

	ni_dbus_dict_array_init(result);
	if (names == NULL)
		return TRUE;

	for (name = names->children; name; name = name->next) {
		ni_dbus_variant_t *dict;
		const xml_node_t *attr;

		dict = ni_dbus_dict_array_add(result);
		ni_dbus_dict_add_string(dict, "namespace",
				xml_node_get_attr(name, "namespace"));

		dict = ni_dbus_dict_add(dict, "name");
		ni_dbus_variant_init_dict(dict);
		for (attr = name->children; attr; attr = attr->next)
			ni_dbus_dict_add_string(dict, attr->name, attr->cdata);
	}

	return TRUE;
}

dbus_bool_t
ni_objectmodel_set_name_array(xml_node_t *names, const ni_dbus_variant_t *argument)
{
	unsigned int i, j;
	xml_node_t *name;

	if (!ni_dbus_variant_is_dict_array(argument))
		return FALSE;

	for (i = 0; i < argument->array.len; ++i) {
		const ni_dbus_variant_t *dict, *child = NULL;
		const char *key, *value;

		dict = &argument->variant_array_value[i];
		if (!(ni_dbus_dict_get_string(dict, "namespace", &value)))
			continue;

		name = xml_node_new("name", names);
		xml_node_add_attr(name, "namespace", value);

		if (!(dict = ni_dbus_dict_get(dict, "name")))
			continue;

		for (j = 0; (child = ni_dbus_dict_get_entry(dict, j, &key)) != NULL; ++j) {
			if (ni_dbus_variant_get_string(child, &value))
				xml_node_new_element(key, name, value);
		}
	}

	return TRUE;
}

/*
 * When we've forwarded an addrconf call to a supplicant, such as dhcp4
 * or ipv4ll, we need to return to the caller the uuid and event he's supposed
 * to wait for.
 */
dbus_bool_t
__ni_objectmodel_return_callback_info(ni_dbus_message_t *reply, ni_event_t event,
		const ni_uuid_t *uuid, const ni_objectmodel_callback_data_t *data,
		DBusError *error)
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
	if (data && data->lease) {
		/* const/shallow, just to put into dict */
		callback.data.lease = data->lease;
	}

	ni_dbus_variant_init_dict(&dict);
	rv = __ni_objectmodel_callback_info_to_dict(&callback, &dict);
	if (rv)
		rv = ni_dbus_message_serialize_variants(reply, 1, &dict, error);
	ni_dbus_variant_destroy(&dict);

	return rv;
}

static dbus_bool_t
__ni_objectmodel_lease_info_to_dict(const ni_addrconf_lease_t *lease, ni_dbus_variant_t *dict)
{
	if (!lease ||
	    !ni_addrconf_type_to_name(lease->type) ||
	    !ni_addrfamily_type_to_name(lease->family) ||
	    !ni_addrconf_state_to_name(lease->state))
		return FALSE;

	dict = ni_dbus_dict_add(dict, "lease");
	ni_dbus_variant_init_dict(dict);
	ni_dbus_dict_add_uint32(dict, "family", lease->family);
	ni_dbus_dict_add_uint32(dict, "type",   lease->type);
	ni_dbus_dict_add_uint32(dict, "state",  lease->state);
	ni_dbus_dict_add_uint32(dict, "flags",  lease->flags);
	if (!ni_uuid_is_null(&lease->uuid))
		ni_dbus_dict_add_uuid(dict, "uuid", &lease->uuid);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_callback_data_to_dict(const ni_objectmodel_callback_info_t *cb, ni_dbus_variant_t *dict)
{
	ni_event_t event;

	if (!cb || !dict || ni_objectmodel_signal_to_event(cb->event, &event) < 0)
		return FALSE;

	switch (event) {
	case NI_EVENT_ADDRESS_ACQUIRED:
	case NI_EVENT_ADDRESS_RELEASED:
	case NI_EVENT_ADDRESS_DEFERRED:
	case NI_EVENT_ADDRESS_LOST:
		__ni_objectmodel_lease_info_to_dict(cb->data.lease, dict);
		break;
	default:
		break;
	}
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_callback_info_to_dict(const ni_objectmodel_callback_info_t *cb, ni_dbus_variant_t *dict)
{
	while (cb) {
		ni_dbus_variant_t *info_dict;

		info_dict = ni_dbus_dict_add(dict, "callback");
		ni_dbus_variant_init_dict(info_dict);

		ni_dbus_dict_add_string(info_dict, "event", cb->event);
		ni_dbus_dict_add_uuid(info_dict, "uuid", &cb->uuid);
		__ni_objectmodel_callback_data_to_dict(cb, info_dict);

		cb = cb->next;
	}

	return TRUE;
}

static ni_addrconf_lease_t *
__ni_objectmodel_lease_info_from_dict(const ni_dbus_variant_t *dict)
{
	unsigned int type, family, state;
	ni_addrconf_lease_t *lease;

	dict = ni_dbus_dict_get(dict, "lease");
	if (!dict || !ni_dbus_variant_is_dict(dict))
		return NULL;

	if (!ni_dbus_dict_get_uint32(dict, "family", &family) ||
	    !ni_addrfamily_type_to_name(family))
		return NULL;

	if (!ni_dbus_dict_get_uint32(dict, "type", &type) ||
	    !ni_addrconf_type_to_name(type))
		return NULL;

	if (!ni_dbus_dict_get_uint32(dict, "state", &state) ||
	    !ni_addrconf_state_to_name(state))
		return NULL;

	if (!(lease = ni_addrconf_lease_new(type, family)))
		return NULL;

	lease->state = state;
	ni_dbus_dict_get_uint32(dict, "flags", &lease->flags);
	ni_dbus_dict_get_uuid(dict, "uuid",  &lease->uuid);
	return lease;
}

static dbus_bool_t
__ni_objectmodel_callback_data_from_dict(ni_objectmodel_callback_info_t *cb, ni_dbus_variant_t *dict)
{
	ni_event_t event;

	if (!cb || !dict || ni_objectmodel_signal_to_event(cb->event, &event) < 0)
		return FALSE;

	switch (event) {
	case NI_EVENT_ADDRESS_ACQUIRED:
	case NI_EVENT_ADDRESS_RELEASED:
	case NI_EVENT_ADDRESS_DEFERRED:
	case NI_EVENT_ADDRESS_LOST:
		cb->data.lease = __ni_objectmodel_lease_info_from_dict(dict);
		break;
	default:
		break;
	}
	return TRUE;
}

ni_objectmodel_callback_info_t *
ni_objectmodel_callback_info_from_dict(const ni_dbus_variant_t *dict)
{
	ni_objectmodel_callback_info_t *result = NULL, **tail;
	ni_dbus_variant_t *child = NULL;

	tail = &result;
	while ((child = ni_dbus_dict_get_next(dict, "callback", child)) != NULL) {
		ni_objectmodel_callback_info_t *cb;
		const char *event;

		if ((cb = calloc(1, sizeof(*cb)))) {
			if (ni_dbus_dict_get_string(child, "event", &event))
				ni_string_dup(&cb->event, event);
			ni_dbus_dict_get_uuid(child, "uuid", &cb->uuid);
			__ni_objectmodel_callback_data_from_dict(cb, child);
			*tail = cb;
			tail = &cb->next;
		}
	}

	return result;
}

void
ni_objectmodel_callback_info_free(ni_objectmodel_callback_info_t *cb)
{
	if (cb) {
		if (cb->data.lease)
			ni_addrconf_lease_free(cb->data.lease);
		ni_string_free(&cb->event);
		free(cb);
	}
}

