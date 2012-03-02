/*
 * Routines for detecting and monitoring network interfaces.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
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
		ni_error("ni_init called twice");
		return -1;
	}

	if (ni_global.config_path == NULL) {
		ni_string_dup(&ni_global.config_path, NI_DEFAULT_CONFIG_PATH);
		explicit_config = 0;
	}

	if (ni_file_exists(ni_global.config_path)) {
		ni_global.config = ni_config_parse(ni_global.config_path);
		if (!ni_global.config) {
			ni_error("Unable to parse netinfo configuration file");
			return -1;
		}
	} else {
		if (explicit_config) {
			ni_error("Configuration file %s does not exist",
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

	return ni_dbus_server_open(ni_global.config->dbus_type, dbus_name, NULL);
}

ni_dbus_client_t *
ni_create_dbus_client(const char *dbus_name)
{
	__ni_assert_initialized();
	if (dbus_name == NULL)
		dbus_name = ni_global.config->dbus_name;
	if (dbus_name == NULL) {
		ni_error("%s: no bus name specified", __FUNCTION__);
		return NULL;
	}

	return ni_dbus_client_open(ni_global.config->dbus_type, dbus_name);
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
	__ni_netdev_list_destroy(&nc->interfaces);
	ni_route_list_destroy(&nc->routes);
	memset(nc, 0, sizeof(*nc));
}

/*
 * Get the list of all discovered interfaces, given a
 * netinfo handle.
 */
ni_netdev_t *
ni_netconfig_devlist(ni_netconfig_t *nc)
{
	return nc->interfaces;
}

/*
 * Find interface by name
 */
ni_netdev_t *
ni_netdev_by_name(ni_netconfig_t *nc, const char *name)
{
	ni_netdev_t *ifp;

	for (ifp = nc->interfaces; ifp; ifp = ifp->next) {
		if (ifp->name && !strcmp(ifp->name, name))
			return ifp;
	}

	return NULL;
}

/*
 * Find interface by its ifindex
 */
ni_netdev_t *
ni_netdev_by_index(ni_netconfig_t *nc, unsigned int ifindex)
{
	ni_netdev_t *ifp;

	for (ifp = nc->interfaces; ifp; ifp = ifp->next) {
		if (ifp->link.ifindex == ifindex)
			return ifp;
	}

	return NULL;
}

/*
 * Find interface by its LL address
 */
ni_netdev_t *
ni_netdev_by_hwaddr(ni_netconfig_t *nc, const ni_hwaddr_t *lla)
{
	ni_netdev_t *ifp;

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
ni_netdev_t *
ni_netdev_by_vlan_name_and_tag(ni_netconfig_t *nc, const char *physdev_name, uint16_t tag)
{
	ni_netdev_t *ifp;

	if (!physdev_name || !tag)
		return NULL;
	for (ifp = nc->interfaces; ifp; ifp = ifp->next) {
		if (ifp->link.type == NI_IFTYPE_VLAN
		 && ifp->link.vlan
		 && ifp->link.vlan->tag == tag
		 && ifp->link.vlan->physdev_name
		 && !strcmp(ifp->link.vlan->physdev_name, physdev_name))
			return ifp;
	}

	return NULL;
}

/*
 * Create a unique interface name
 */
const char *
ni_netdev_make_name(ni_netconfig_t *nc, const char *stem)
{
	static char namebuf[64];
	unsigned int num;

	for (num = 0; num < 65536; ++num) {
		snprintf(namebuf, sizeof(namebuf), "%s%u", stem, num);
		if (!ni_netdev_by_name(nc, namebuf))
			return namebuf;
	}

	return NULL;
}

/*
 * Handle interface_request objects
 */
ni_netdev_req_t *
ni_netdev_req_new(void)
{
	ni_netdev_req_t *req;

	req = xcalloc(1, sizeof(*req));
	return req;
}

void
ni_netdev_req_free(ni_netdev_req_t *req)
{
	if (req->ipv4)
		ni_afinfo_free(req->ipv4);
	if (req->ipv6)
		ni_afinfo_free(req->ipv6);
	ni_string_free(&req->alias);
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
ni_afinfo_free(ni_afinfo_t *afi)
{
	free(afi);
}

/*
 * Address configuration state (aka leases)
 */
ni_addrconf_lease_t *
ni_addrconf_lease_new(int type, int family)
{
	ni_addrconf_lease_t *lease;

	lease = calloc(1, sizeof(*lease));
	lease->seqno = __ni_global_seqno++;
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
	ni_string_free(&lease->owner);
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

void
ni_addrconf_lease_list_destroy(ni_addrconf_lease_t **list)
{
	ni_addrconf_lease_t *lease;

	while ((lease = *list) != NULL) {
		*list = lease->next;
		ni_addrconf_lease_free(lease);
	}
}
