/*
 * Functions to represent DHCPv4 specific lease information as XML
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <arpa/inet.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/xml.h>
#include "util_priv.h"

static void		__ni_dhcp4_put_string(xml_node_t *, const char *, const char *);
static void		__ni_dhcp4_put_addr(xml_node_t *, const char *, struct in_addr);
static void		__ni_dhcp4_put_uint32(xml_node_t *, const char *, uint32_t);
static void		__ni_dhcp4_put_uint16(xml_node_t *, const char *, uint16_t);
static int		__ni_dhcp4_get_string(const xml_node_t *, const char *, char **);
static int		__ni_dhcp4_get_addr(const xml_node_t *, const char *, struct in_addr *);
static int		__ni_dhcp4_get_uint32(const xml_node_t *, const char *, uint32_t *);
static int		__ni_dhcp4_get_uint16(const xml_node_t *, const char *, uint16_t *);

int
ni_dhcp4_xml_from_lease(const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	node = xml_node_new("dhcp4", node);
	if (lease->dhcp4.serveraddress.s_addr)
		__ni_dhcp4_put_addr(node, "server-address", lease->dhcp4.serveraddress);
	if (lease->dhcp4.servername[0])
		__ni_dhcp4_put_string(node, "server-name", lease->dhcp4.servername);
	if (lease->dhcp4.address.s_addr)
		__ni_dhcp4_put_addr(node, "address", lease->dhcp4.address);
	if (lease->dhcp4.netmask.s_addr)
		__ni_dhcp4_put_addr(node, "netmask", lease->dhcp4.netmask);
	if (lease->dhcp4.broadcast.s_addr)
		__ni_dhcp4_put_addr(node, "broadcast", lease->dhcp4.broadcast);
	if (lease->dhcp4.lease_time)
		__ni_dhcp4_put_uint32(node, "lease-time", lease->dhcp4.lease_time);
	if (lease->dhcp4.renewal_time)
		__ni_dhcp4_put_uint32(node, "renewal-time", lease->dhcp4.renewal_time);
	if (lease->dhcp4.rebind_time)
		__ni_dhcp4_put_uint32(node, "rebind-time", lease->dhcp4.rebind_time);
	if (lease->dhcp4.mtu)
		__ni_dhcp4_put_uint16(node, "mtu", lease->dhcp4.mtu);

	return 0;
}

int
ni_dhcp4_xml_to_lease(ni_addrconf_lease_t *lease, const xml_node_t *node)
{
	char *server_name = NULL;

	if (!(node = xml_node_get_child(node, "dhcp4")))
		return -1;

	__ni_dhcp4_get_string(node, "server-name", &server_name);
	if (server_name) {
		strncpy(lease->dhcp4.servername, server_name, sizeof(lease->dhcp4.servername)-1);
		ni_string_free(&server_name);
	}

	__ni_dhcp4_get_addr(node, "server-address", &lease->dhcp4.serveraddress);
	__ni_dhcp4_get_addr(node, "address", &lease->dhcp4.address);
	__ni_dhcp4_get_addr(node, "netmask", &lease->dhcp4.netmask);
	__ni_dhcp4_get_addr(node, "broadcast", &lease->dhcp4.broadcast);
	__ni_dhcp4_get_uint32(node, "lease-time", &lease->dhcp4.lease_time);
	__ni_dhcp4_get_uint32(node, "renewal-time", &lease->dhcp4.renewal_time);
	__ni_dhcp4_get_uint32(node, "rebind-time", &lease->dhcp4.rebind_time);
	__ni_dhcp4_get_uint16(node, "mtu", &lease->dhcp4.mtu);
	return 0;
}

static void
__ni_dhcp4_put_string(xml_node_t *node, const char *name, const char *value)
{
	node = xml_node_new(name, node);
	node->cdata = xstrdup(value);
}

static void
__ni_dhcp4_put_addr(xml_node_t *node, const char *name, struct in_addr addr)
{
	__ni_dhcp4_put_string(node, name, inet_ntoa(addr));
}

static void
__ni_dhcp4_put_uint32(xml_node_t *node, const char *name, uint32_t value)
{
	char buffer[64];

	snprintf(buffer, sizeof(buffer), "%u", value);
	__ni_dhcp4_put_string(node, name, buffer);
}

static void
__ni_dhcp4_put_uint16(xml_node_t *node, const char *name, uint16_t value)
{
	char buffer[64];

	snprintf(buffer, sizeof(buffer), "%u", value);
	__ni_dhcp4_put_string(node, name, buffer);
}

static inline const char *
__ni_dhcp4_get_cdata(const xml_node_t *node, const char *name)
{
	if (!(node = xml_node_get_child(node, name)))
		return NULL;
	return node->cdata;
}

static int
__ni_dhcp4_get_string(const xml_node_t *node, const char *name, char **res)
{
	const char *value;

	if ((value = __ni_dhcp4_get_cdata(node, name)) != NULL)
		ni_string_dup(res, value);
	return 0;
}

static int
__ni_dhcp4_get_addr(const xml_node_t *node, const char *name, struct in_addr *res)
{
	const char *value;

	if ((value = __ni_dhcp4_get_cdata(node, name)) != NULL)
		return inet_aton(value, res);
	return 0;
}

static int
__ni_dhcp4_get_uint32(const xml_node_t *node, const char *name, uint32_t *res)
{
	const char *value;

	if ((value = __ni_dhcp4_get_cdata(node, name)) != NULL)
		*res = strtoul(value, NULL, 0);
	return 0;
}

static int
__ni_dhcp4_get_uint16(const xml_node_t *node, const char *name, uint16_t *res)
{
	const char *value;

	if ((value = __ni_dhcp4_get_cdata(node, name)) != NULL)
		*res = strtoul(value, NULL, 0);
	return 0;
}
