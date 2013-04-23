/*
 * Handing bridge interfaces.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/bridge.h>
#include "netinfo_priv.h"

#define NI_BRIDGE_PORT_ARRAY_CHUNK	16

static void			ni_bridge_port_array_init(ni_bridge_port_array_t *);
static void			ni_bridge_port_array_destroy(ni_bridge_port_array_t *);
static void			__ni_bridge_port_array_realloc(ni_bridge_port_array_t *,
					unsigned int);
static int			__ni_bridge_port_array_append(ni_bridge_port_array_t *,
					ni_bridge_port_t *);



ni_bridge_port_t *
ni_bridge_port_new(ni_bridge_t *bridge, const char *ifname, unsigned int ifindex)
{
	ni_bridge_port_t *port;

	port = calloc(1, sizeof(ni_bridge_port_t));
	if (!port)
		ni_fatal("%s: out of memory", __FUNCTION__);

	ni_string_dup(&port->ifname, ifname);
	port->ifindex = ifindex;
	/* apply "not set" defaults */
	port->priority = NI_BRIDGE_VALUE_NOT_SET;
	port->path_cost = NI_BRIDGE_VALUE_NOT_SET;

	if (bridge)
		__ni_bridge_port_array_append(&bridge->ports, port);
	return port;
}

void
ni_bridge_port_free(ni_bridge_port_t *port)
{
	ni_string_free(&port->ifname);
	ni_bridge_port_status_destroy(&port->status);
	free(port);
}

static void
ni_bridge_port_array_init(ni_bridge_port_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

static void
ni_bridge_port_array_destroy(ni_bridge_port_array_t *array)
{
	while (array->count > 0)
		ni_bridge_port_free(array->data[--array->count]);
	free(array->data);
	ni_bridge_port_array_init(array);
}

static void
__ni_bridge_port_array_realloc(ni_bridge_port_array_t *array, unsigned int newsize)
{
	ni_bridge_port_t **newdata;
	unsigned int i;

	newsize = (newsize + NI_BRIDGE_PORT_ARRAY_CHUNK);
	newdata = realloc(array->data, newsize * sizeof(ni_bridge_port_t));
	if (!newdata)
		ni_fatal("%s: out of memory", __FUNCTION__);

	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		array->data[i] = NULL;
}

static int
__ni_bridge_port_array_append(ni_bridge_port_array_t *array, ni_bridge_port_t *port)
{
	if ((array->count % NI_BRIDGE_PORT_ARRAY_CHUNK) == 0)
		__ni_bridge_port_array_realloc(array, array->count);

	array->data[array->count++] = port;
	return 0;
}

static int
ni_bridge_port_array_remove_index(ni_bridge_port_array_t *array, unsigned int pos)
{
	unsigned int i;

	if (pos >= array->count)
		return -1;

	ni_bridge_port_free(array->data[pos]);
	/* make it less cumbersome... */
	array->data[pos] = NULL;
	for (i = pos + 1; i < array->count; ++i) {
		array->data[i - 1] = array->data[i];
		array->data[i] = NULL;
	}
	array->count--;
	return 0;
}

/*
 * Locate a port given its name or index
 */
ni_bridge_port_t *
ni_bridge_port_by_index(const ni_bridge_t *bridge, unsigned int ifindex)
{
	ni_bridge_port_t **pp, *port;
	unsigned int i;

	for (i = 0, pp = bridge->ports.data; i < bridge->ports.count; ++i) {
		port = *pp++;
		if (port->ifindex == ifindex)
			return port;
	}
	return NULL;
}

ni_bridge_port_t *
ni_bridge_port_by_name(const ni_bridge_t *bridge, const char *ifname)
{
	ni_bridge_port_t **pp, *port;
	unsigned int i;

	if (ifname == NULL)
		return NULL;

	for (i = 0, pp = bridge->ports.data; i < bridge->ports.count; ++i) {
		port = *pp++;
		if (ni_string_eq(port->ifname, ifname))
			return port;
	}
	return NULL;
}

/*
 * Add a port to the bridge configuration
 * Note, in case of success, the bridge will have taken ownership of the port object.
 */
int
ni_bridge_add_port(ni_bridge_t *bridge, ni_bridge_port_t *port)
{
	if (!port)
		return -1;

	if (port->ifindex && ni_bridge_port_by_index(bridge, port->ifindex))
		return -1;
	if (port->ifname && ni_bridge_port_by_name(bridge, port->ifname))
		return -1;

	__ni_bridge_port_array_append(&bridge->ports, port);
	return 0;
}


int
ni_bridge_del_port(ni_bridge_t *bridge, unsigned int ifindex)
{
	ni_bridge_port_t **pp, *port;
	unsigned int i;

	for (i = 0, pp = bridge->ports.data; i < bridge->ports.count; ++i) {
		port = *pp++;
		if (port->ifindex == ifindex) {
			ni_bridge_port_array_remove_index(&bridge->ports, i);
			return 0;
		}
	}
	return -1;
}

int
ni_bridge_del_port_ifindex(ni_bridge_t *bridge, int ifindex)
{
	ni_bridge_port_t **pp, *port;
	unsigned int i;

	for (i = 0, pp = bridge->ports.data; i < bridge->ports.count; ++i) {
		port = *pp++;
		if (port->ifindex == ifindex) {
			ni_bridge_port_array_remove_index(&bridge->ports, i);
			return 0;
		}
	}
	return -1;
}

void
ni_bridge_get_port_names(const ni_bridge_t *bridge, ni_string_array_t *names)
{
	unsigned int i;

	if (!bridge || !names)
		return;
	for (i = 0; i < bridge->ports.count; ++i) {
		ni_bridge_port_t *port = bridge->ports.data[i];
		if (port && port->ifname && *port->ifname)
			ni_string_array_append(names, port->ifname);
	}
}

/*
 * Bridge constructor and new operator
 */
static void
__ni_bridge_init(ni_bridge_t *bridge)
{
	/* apply "not set" defaults */
	bridge->stp = FALSE;
	bridge->forward_delay = NI_BRIDGE_VALUE_NOT_SET;
	bridge->ageing_time = NI_BRIDGE_VALUE_NOT_SET;
	bridge->hello_time = NI_BRIDGE_VALUE_NOT_SET;
	bridge->max_age = NI_BRIDGE_VALUE_NOT_SET;
	bridge->priority = NI_BRIDGE_VALUE_NOT_SET;
}

ni_bridge_t *
ni_bridge_new(void)
{
	ni_bridge_t *bridge;

	bridge = calloc(1, sizeof(*bridge));
	if (bridge)
		__ni_bridge_init(bridge);
	return bridge;
}

/*
 * Bridge destructor and delete operator
 */
static void
__ni_bridge_destroy(ni_bridge_t *bridge)
{
	ni_bridge_port_array_destroy(&bridge->ports);
	ni_bridge_status_destroy(&bridge->status);
}

void
ni_bridge_free(ni_bridge_t *bridge)
{
	__ni_bridge_destroy(bridge);
	free(bridge);
}

void
ni_bridge_status_destroy(ni_bridge_status_t *bs)
{
	ni_string_free(&bs->root_id);
	ni_string_free(&bs->bridge_id);
	ni_string_free(&bs->group_addr);
	memset(bs, 0, sizeof(*bs));
}

void
ni_bridge_port_status_destroy(ni_bridge_port_status_t *ps)
{
	ni_string_free(&ps->designated_root);
	ni_string_free(&ps->designated_bridge);
}

void
ni_bridge_ports_destroy(ni_bridge_t *bridge)
{
	ni_bridge_port_array_destroy(&bridge->ports);
}
