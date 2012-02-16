/*
 * Routines for detecting and monitoring network interfaces.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 *
 * TODO
 *  -	Check that the module options specified for the bonding
 *	module do not conflict between interfaces
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <signal.h>
#include <time.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/ethernet.h>
#include <wicked/wireless.h>
#include <wicked/vlan.h>
#include <wicked/socket.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include "netinfo_priv.h"
#include "dbus-server.h"
#include "config.h"
#include "xml-schema.h"

#define DEFAULT_ADDRCONF_IPV4 (\
			NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC) |\
			NI_ADDRCONF_MASK(NI_ADDRCONF_DHCP))
#define DEFAULT_ADDRCONF_IPV6 (\
			NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC) |\
			NI_ADDRCONF_MASK(NI_ADDRCONF_AUTOCONF))

/*
 * Global data for netinfo library
 */
ni_global_t	ni_global;
unsigned int	__ni_global_seqno;

/*
 * Global initialization of application
 */
int
ni_init()
{
	int explicit_config = 1;

	if (ni_global.initialized) {
		error("ni_init called twice");
		return -1;
	}

	if (ni_global.config_path == NULL) {
		ni_string_dup(&ni_global.config_path, NI_DEFAULT_CONFIG_PATH);
		explicit_config = 0;
	}

	if (ni_file_exists(ni_global.config_path)) {
		ni_global.config = ni_config_parse(ni_global.config_path);
		if (!ni_global.config) {
			error("Unable to parse netinfo configuration file");
			return -1;
		}
	} else {
		if (explicit_config) {
			error("Configuration file %s does not exist",
					ni_global.config_path);
			return -1;
		}
		/* Create empty default configuration */
		ni_global.config = ni_config_new();
	}

	/* Our socket code relies on us ignoring this */
	signal(SIGPIPE, SIG_IGN);

	ni_global.initialized = 1;
	return 0;
}

void
ni_set_global_config_path(const char *pathname)
{
	ni_string_dup(&ni_global.config_path, pathname);
}

/*
 * Utility functions for starting/stopping the wicked daemon,
 * and for connecting to it
 */
int
ni_server_background(void)
{
	ni_config_fslocation_t *fsloc = &ni_global.config->pidfile;

	return ni_daemonize(fsloc->path, fsloc->mode);
}

ni_dbus_server_t *
ni_server_listen_dbus(const char *dbus_name)
{
	__ni_assert_initialized();
	if (dbus_name == NULL)
		dbus_name = ni_global.config->dbus_name;
	if (dbus_name == NULL) {
		ni_error("%s: no bus name specified", __FUNCTION__);
		return NULL;
	}

	return ni_dbus_server_open(dbus_name, NULL);
}

ni_xs_scope_t *
ni_server_dbus_xml_schema(void)
{
	const char *filename = ni_global.config->dbus_xml_schema_file;
	ni_xs_scope_t *scope;

	if (filename == NULL) {
		ni_error("Cannot create dbus xml schema: no schema path configured");
		return NULL;
	}

	scope = ni_dbus_xml_init();
	if (ni_xs_process_schema_file(filename, scope) < 0) {
		ni_error("Cannot create dbus xml schema: error in schema definition");
		ni_xs_scope_free(scope);
		return NULL;
	}

	return scope;
}

void
__ni_afinfo_set_addrconf_request(ni_afinfo_t *afi, unsigned int mode, ni_addrconf_request_t *req)
{
	if (mode >= __NI_ADDRCONF_MAX) {
		ni_error("%s: bad addrconf mode %u", __FUNCTION__, mode);
		return;
	}
	if (afi->request[mode])
		ni_addrconf_request_free(afi->request[mode]);
	afi->request[mode] = req;
}

void
__ni_afinfo_set_addrconf_lease(ni_afinfo_t *afi, unsigned int mode, ni_addrconf_lease_t *lease)
{
	ni_assert(lease->type == mode);
	if (mode >= __NI_ADDRCONF_MAX) {
		ni_error("%s: bad addrconf mode %u", __FUNCTION__, mode);
		return;
	}
	if (afi->lease[mode])
		ni_addrconf_lease_free(afi->lease[mode]);
	if (lease->state == NI_ADDRCONF_STATE_GRANTED) {
		afi->lease[mode] = lease;
	} else {
		afi->lease[mode] = NULL;
	}
}

int
__ni_afinfo_is_up(const ni_afinfo_t *afi, const ni_interface_t *ifp)
{
	unsigned int mode;

	for (mode = 0; mode < __NI_ADDRCONF_MAX; ++mode) {
		if (!ni_afinfo_addrconf_test(afi, mode))
			continue;
		if (afi->request[mode] && !afi->lease[mode]) {
			ni_debug_ifconfig("%s: still waiting for %s/%s lease",
					ifp->name,
					ni_addrconf_type_to_name(mode),
					ni_addrfamily_type_to_name(afi->family));
			return 0;
		}
	}

	return 1;
}

/*
 * Constructor/destructor for netconfig handles
 */
ni_netconfig_t *
ni_netconfig_new(void)
{
	ni_netconfig_t *nc;

	nc = calloc(1, sizeof(*nc));
	return nc;
}

void
ni_netconfig_free(ni_netconfig_t *nc)
{
	ni_netconfig_destroy(nc);
	free(nc);
}

void
ni_netconfig_init(ni_netconfig_t *nc)
{
	memset(nc, 0, sizeof(*nc));
}

void
ni_netconfig_destroy(ni_netconfig_t *nc)
{
	__ni_interface_list_destroy(&nc->interfaces);
	ni_route_list_destroy(&nc->routes);
	memset(nc, 0, sizeof(*nc));
}

/*
 * Get the list of all discovered interfaces, given a
 * netinfo handle.
 */
ni_interface_t *
ni_interfaces(ni_netconfig_t *nc)
{
	return nc->interfaces;
}

/*
 * Find interface by name
 */
ni_interface_t *
ni_interface_by_name(ni_netconfig_t *nc, const char *name)
{
	ni_interface_t *ifp;

	for (ifp = nc->interfaces; ifp; ifp = ifp->next) {
		if (ifp->name && !strcmp(ifp->name, name))
			return ifp;
	}

	return NULL;
}

/*
 * Find interface by its ifindex
 */
ni_interface_t *
ni_interface_by_index(ni_netconfig_t *nc, unsigned int ifindex)
{
	ni_interface_t *ifp;

	for (ifp = nc->interfaces; ifp; ifp = ifp->next) {
		if (ifp->link.ifindex == ifindex)
			return ifp;
	}

	return NULL;
}

/*
 * Find interface by its LL address
 */
ni_interface_t *
ni_interface_by_hwaddr(ni_netconfig_t *nc, const ni_hwaddr_t *lla)
{
	ni_interface_t *ifp;

	if (!lla || !lla->len)
		return NULL;

	for (ifp = nc->interfaces; ifp; ifp = ifp->next) {
		if (ni_link_address_equal(&ifp->link.hwaddr, lla))
			return ifp;
	}

	return NULL;
}

/*
 * Find VLAN interface by its tag
 */
ni_interface_t *
ni_interface_by_vlan_tag(ni_netconfig_t *nc, uint16_t tag)
{
	ni_interface_t *ifp;

	for (ifp = nc->interfaces; ifp; ifp = ifp->next) {
		if (ifp->link.type == NI_IFTYPE_VLAN
		 && ifp->link.vlan
		 && ifp->link.vlan->tag == tag)
			return ifp;
	}

	return NULL;
}

/*
 * Handle interface_request objects
 */
ni_interface_request_t *
ni_interface_request_new(void)
{
	ni_interface_request_t *req;

	req = xcalloc(1, sizeof(*req));
	return req;
}

void
ni_interface_request_free(ni_interface_request_t *req)
{
	if (req->ipv4)
		ni_afinfo_free(req->ipv4);
	if (req->ipv6)
		ni_afinfo_free(req->ipv6);
	free(req);
}

/*
 * Address configuration info
 */
ni_afinfo_t *
ni_afinfo_new(int family)
{
	ni_afinfo_t *afi = xcalloc(1, sizeof(*afi));

	__ni_afinfo_init(afi, family);
	return afi;
}

void
__ni_afinfo_init(ni_afinfo_t *afi, int family)
{
	afi->family = family;
	if (family == AF_INET)
		afi->addrconf = DEFAULT_ADDRCONF_IPV4;
	else if (family == AF_INET6)
		afi->addrconf = DEFAULT_ADDRCONF_IPV6;
	afi->enabled = 1;
}

void
__ni_afinfo_destroy(ni_afinfo_t *afi)
{
	unsigned int i;

	for (i = 0; i < __NI_ADDRCONF_MAX; ++i) {
		if (afi->request[i]) {
			ni_addrconf_request_free(afi->request[i]);
			afi->request[i] = NULL;
		}
		if (afi->lease[i]) {
			ni_addrconf_lease_free(afi->lease[i]);
			afi->lease[i] = NULL;
		}
	}
}

void
ni_afinfo_free(ni_afinfo_t *afi)
{
	__ni_afinfo_destroy(afi);
	free(afi);
}

/*
 * addrconf requests
 */
ni_addrconf_request_t *
ni_addrconf_request_new(unsigned int type, unsigned int af)
{
	ni_addrconf_request_t *dhcp;

	dhcp = xcalloc(1, sizeof(*dhcp));

	dhcp->type = type;
	dhcp->family = af;
	dhcp->acquire_timeout = 0;	/* means infinite */
	dhcp->reuse_unexpired = 1;
	dhcp->update = ~0;

	return dhcp;
}

ni_addrconf_request_t *
ni_addrconf_request_clone(const ni_addrconf_request_t *src)
{
	ni_addrconf_request_t *dst;

	if (src == NULL)
		return NULL;

	dst = ni_addrconf_request_new(src->type, src->family);
	dst->reuse_unexpired = src->reuse_unexpired;
	dst->settle_timeout = src->settle_timeout;
	dst->acquire_timeout = src->acquire_timeout;
	ni_string_dup(&dst->dhcp.hostname, src->dhcp.hostname);
	ni_string_dup(&dst->dhcp.clientid, src->dhcp.clientid);
	ni_string_dup(&dst->dhcp.vendor_class, src->dhcp.vendor_class);
	dst->dhcp.lease_time = src->dhcp.lease_time;
	dst->update = src->update;

	return dst;
}

void
ni_addrconf_request_free(ni_addrconf_request_t *req)
{
	ni_string_free(&req->dhcp.hostname);
	ni_string_free(&req->dhcp.clientid);
	ni_string_free(&req->dhcp.vendor_class);

	ni_address_list_destroy(&req->statik.addrs);
	ni_route_list_destroy(&req->statik.routes);
	free(req);
}

int
ni_addrconf_request_equal(const ni_addrconf_request_t *req1, const ni_addrconf_request_t *req2)
{
	if (req1->type != req2->type
	 || req1->family != req2->family
	 || req1->update != req2->update)
		return 0;

	if (req1->type == NI_ADDRCONF_DHCP && req1->family == AF_INET) {
		if (ni_string_eq(req1->dhcp.hostname, req2->dhcp.hostname)
		 || ni_string_eq(req1->dhcp.clientid, req2->dhcp.clientid)
		 || ni_string_eq(req1->dhcp.vendor_class, req2->dhcp.vendor_class)
		 || req1->dhcp.lease_time != req2->dhcp.lease_time)
			return 0;
	}

	return 1;
}

/*
 * Address configuration state (aka leases)
 */
ni_addrconf_lease_t *
ni_addrconf_lease_new(int type, int family)
{
	ni_addrconf_lease_t *lease;

	lease = calloc(1, sizeof(*lease));
	lease->type = type;
	lease->family = family;
	return lease;
}

void
ni_addrconf_lease_free(ni_addrconf_lease_t *lease)
{
	ni_addrconf_lease_destroy(lease);
	free(lease);
}

void
ni_addrconf_lease_destroy(ni_addrconf_lease_t *lease)
{
	ni_string_free(&lease->hostname);
	ni_string_free(&lease->netbios_domain);
	ni_string_free(&lease->netbios_scope);
	ni_string_array_destroy(&lease->log_servers);
	ni_string_array_destroy(&lease->ntp_servers);
	ni_string_array_destroy(&lease->netbios_name_servers);
	ni_string_array_destroy(&lease->netbios_dd_servers);
	ni_string_array_destroy(&lease->slp_servers);
	ni_string_array_destroy(&lease->slp_scopes);
	ni_address_list_destroy(&lease->addrs);
	ni_route_list_destroy(&lease->routes);

	if (lease->nis) {
		ni_nis_info_free(lease->nis);
		lease->nis = NULL;
	}
	if (lease->resolver) {
		ni_resolver_info_free(lease->resolver);
		lease->resolver = NULL;
	}

	switch (lease->type) {
	case NI_ADDRCONF_DHCP:
		ni_string_free(&lease->dhcp.message);
		ni_string_free(&lease->dhcp.rootpath);
		break;

	default: ;
	}
}

/*
 * Helper functions for backends like RedHat's or SUSE.
 * This is used to make interface behavior to STARTMODE and vice versa.
 */
const ni_ifbehavior_t *
__ni_netinfo_get_behavior(const char *name, const struct __ni_ifbehavior_map *map)
{
	for (; map->name; ++map) {
		if (!strcmp(map->name, name))
			return &map->behavior;
	}
	return NULL;
}

static unsigned int
__ni_behavior_to_mask(const ni_ifbehavior_t *beh)
{
	unsigned int mask = 0;

#define INSPECT(what) { \
	mask <<= 2; \
	switch (beh->ifaction[NI_IFACTION_##what].action) { \
	case NI_INTERFACE_START: \
		mask |= 1; break; \
	case NI_INTERFACE_STOP: \
		mask |= 2; break; \
	default: ; \
	} \
}
	INSPECT(MANUAL_UP);
	INSPECT(MANUAL_DOWN);
	INSPECT(BOOT);
	INSPECT(SHUTDOWN);
	INSPECT(LINK_UP);
	INSPECT(LINK_DOWN);
#undef INSPECT

	return mask;
}

/*
 * Out of a set of predefined interface behaviors, try to find the one that matches
 * best.
 * In the approach implemented here, we compare the action configured as response to specific
 * events. In order of decreasing precedence, we check:
 *	manual, boot, shutdown, link_up, link_down
 */
const char *
__ni_netinfo_best_behavior(const ni_ifbehavior_t *beh, const struct __ni_ifbehavior_map *map)
{
	unsigned int beh_mask = __ni_behavior_to_mask(beh);
	const char *best_match = NULL;
	unsigned int best_mask = 0;

	for (; map->name; ++map) {
		unsigned int this_mask = __ni_behavior_to_mask(&map->behavior) & beh_mask;

		if (this_mask > best_mask) {
			best_match = map->name;
			best_mask = this_mask;
		}
	}

	return best_match;
}
