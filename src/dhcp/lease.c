/*
 * Functions to represent DHCP specific lease information as XML
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/xml.h>
#include "util_priv.h"

static void		__ni_dhcp_put_string(xml_node_t *, const char *, const char *);
static void		__ni_dhcp_put_addr(xml_node_t *, const char *, struct in_addr);
static void		__ni_dhcp_put_uint32(xml_node_t *, const char *, uint32_t);
static void		__ni_dhcp_put_uint16(xml_node_t *, const char *, uint16_t);
static int		__ni_dhcp_get_string(const xml_node_t *, const char *, char **);
static int		__ni_dhcp_get_addr(const xml_node_t *, const char *, struct in_addr *);
static int		__ni_dhcp_get_uint32(const xml_node_t *, const char *, uint32_t *);
static int		__ni_dhcp_get_uint16(const xml_node_t *, const char *, uint16_t *);

int
ni_dhcp_lease_matches_request(const ni_addrconf_lease_t *lease, const ni_addrconf_request_t *req)
{
	if (req->dhcp.hostname && !ni_string_eq(req->dhcp.hostname, lease->hostname))
		return 0;

	if (req->dhcp.clientid && !ni_string_eq(req->dhcp.clientid, lease->dhcp.client_id))
		return 0;

	return 1;
}

int
ni_dhcp_xml_from_lease(const ni_addrconf_t *aconf,
				const ni_addrconf_lease_t *lease, xml_node_t *node)
{
	node = xml_node_new("dhcp", node);
	if (lease->dhcp.serveraddress.s_addr)
		__ni_dhcp_put_addr(node, "server-address", lease->dhcp.serveraddress);
	if (lease->dhcp.servername[0])
		__ni_dhcp_put_string(node, "server-name", lease->dhcp.servername);
	if (lease->dhcp.address.s_addr)
		__ni_dhcp_put_addr(node, "address", lease->dhcp.address);
	if (lease->dhcp.netmask.s_addr)
		__ni_dhcp_put_addr(node, "netmask", lease->dhcp.netmask);
	if (lease->dhcp.broadcast.s_addr)
		__ni_dhcp_put_addr(node, "broadcast", lease->dhcp.broadcast);
	if (lease->dhcp.lease_time)
		__ni_dhcp_put_uint32(node, "lease-time", lease->dhcp.lease_time);
	if (lease->dhcp.renewal_time)
		__ni_dhcp_put_uint32(node, "renewal-time", lease->dhcp.renewal_time);
	if (lease->dhcp.rebind_time)
		__ni_dhcp_put_uint32(node, "rebind-time", lease->dhcp.rebind_time);
	if (lease->dhcp.mtu)
		__ni_dhcp_put_uint16(node, "mtu", lease->dhcp.mtu);

	return 0;
}

int
ni_dhcp_xml_to_lease(const ni_addrconf_t *aconf, ni_addrconf_lease_t *lease, const xml_node_t *node)
{
	char *server_name = NULL;

	if (!(node = xml_node_get_child(node, "dhcp")))
		return -1;

	__ni_dhcp_get_string(node, "server-name", &server_name);
	if (server_name) {
		strncpy(lease->dhcp.servername, server_name, sizeof(lease->dhcp.servername)-1);
		ni_string_free(&server_name);
	}

	__ni_dhcp_get_addr(node, "server-address", &lease->dhcp.serveraddress);
	__ni_dhcp_get_addr(node, "address", &lease->dhcp.address);
	__ni_dhcp_get_addr(node, "netmask", &lease->dhcp.netmask);
	__ni_dhcp_get_addr(node, "broadcast", &lease->dhcp.broadcast);
	__ni_dhcp_get_uint32(node, "lease-time", &lease->dhcp.lease_time);
	__ni_dhcp_get_uint32(node, "renewal-time", &lease->dhcp.renewal_time);
	__ni_dhcp_get_uint32(node, "rebind-time", &lease->dhcp.rebind_time);
	__ni_dhcp_get_uint16(node, "mtu", &lease->dhcp.mtu);
	return 0;
}

static void
__ni_dhcp_put_string(xml_node_t *node, const char *name, const char *value)
{
	node = xml_node_new(name, node);
	node->cdata = xstrdup(value);
}

static void
__ni_dhcp_put_addr(xml_node_t *node, const char *name, struct in_addr addr)
{
	__ni_dhcp_put_string(node, name, inet_ntoa(addr));
}

static void
__ni_dhcp_put_uint32(xml_node_t *node, const char *name, uint32_t value)
{
	char buffer[64];

	snprintf(buffer, sizeof(buffer), "%u", value);
	__ni_dhcp_put_string(node, name, buffer);
}

static void
__ni_dhcp_put_uint16(xml_node_t *node, const char *name, uint16_t value)
{
	char buffer[64];

	snprintf(buffer, sizeof(buffer), "%u", value);
	__ni_dhcp_put_string(node, name, buffer);
}

static inline const char *
__ni_dhcp_get_cdata(const xml_node_t *node, const char *name)
{
	if (!(node = xml_node_get_child(node, name)))
		return NULL;
	return node->cdata;
}

static int
__ni_dhcp_get_string(const xml_node_t *node, const char *name, char **res)
{
	const char *value;

	if ((value = __ni_dhcp_get_cdata(node, name)) != NULL)
		ni_string_dup(res, value);
	return 0;
}

static int
__ni_dhcp_get_addr(const xml_node_t *node, const char *name, struct in_addr *res)
{
	const char *value;

	if ((value = __ni_dhcp_get_cdata(node, name)) != NULL)
		return inet_aton(value, res);
	return 0;
}

static int
__ni_dhcp_get_uint32(const xml_node_t *node, const char *name, uint32_t *res)
{
	const char *value;

	if ((value = __ni_dhcp_get_cdata(node, name)) != NULL)
		*res = strtoul(value, NULL, 0);
	return 0;
}

static int
__ni_dhcp_get_uint16(const xml_node_t *node, const char *name, uint16_t *res)
{
	const char *value;

	if ((value = __ni_dhcp_get_cdata(node, name)) != NULL)
		*res = strtoul(value, NULL, 0);
	return 0;
}
