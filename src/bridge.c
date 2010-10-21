/*
 * Handing bridge interfaces.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include "netinfo_priv.h"

#define NI_BRIDGE_PORT_ARRAY_CHUNK	16

static ni_bridge_port_t *	__ni_bridge_port_create(const char *);
static ni_bridge_port_t *	__ni_bridge_port_clone(const ni_bridge_port_t *);
static void			__ni_bridge_port_destroy(ni_bridge_port_t *);

static void			ni_bridge_port_array_init(ni_bridge_port_array_t *);
static int			ni_bridge_port_array_copy(ni_bridge_port_array_t *,
					const ni_bridge_port_array_t *);
static void			ni_bridge_port_array_destroy(ni_bridge_port_array_t *);
static void			__ni_bridge_port_array_realloc(ni_bridge_port_array_t *,
					unsigned int);
static int			__ni_bridge_port_array_append(ni_bridge_port_array_t *,
					ni_bridge_port_t *);

static ni_bridge_port_t *
__ni_bridge_port_create(const char *name)
{
	ni_bridge_port_t *newport;

	newport = calloc(1, sizeof(ni_bridge_port_t));
	if (!newport)
		ni_fatal("%s: out of memory", __FUNCTION__);

	ni_string_dup(&newport->name, name);
	return newport;
}
static ni_bridge_port_t *
__ni_bridge_port_clone(const ni_bridge_port_t *port)
{
	ni_bridge_port_t *newport;

	newport = __ni_bridge_port_create(port->name);
	memcpy(&newport->config, &port->config, sizeof(newport->config));
	return newport;
}
static void
__ni_bridge_port_destroy(ni_bridge_port_t *port)
{
	if (port->name)
		free(port->name);
	free(port);
}

static void
ni_bridge_port_array_init(ni_bridge_port_array_t *array)
{
	memset(array, 0, sizeof(*array));
}
static int
ni_bridge_port_array_copy(ni_bridge_port_array_t *dst, const ni_bridge_port_array_t *src)
{
	unsigned int i;
	ni_bridge_port_array_destroy(dst);
	for (i = 0; i < src->count; ++i) {
		if (__ni_bridge_port_array_append(dst,
			__ni_bridge_port_clone(src->data[i])) < 0)
			return -1;
	}
	return 0;
}
static void
ni_bridge_port_array_destroy(ni_bridge_port_array_t *array)
{
	while(array->count > 0)
		__ni_bridge_port_destroy(array->data[--array->count]);
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

/*
 * Add a port to the bridge configuration
 */
void
ni_bridge_add_port(ni_bridge_t *bridge, const char *ifname)
{
	__ni_bridge_port_array_append(&bridge->ports,
		__ni_bridge_port_create(ifname));
	ni_string_array_append(&bridge->port_names, ifname);
}

/*
 * Binding callback for the bridge config.
 * This looks up interface config for all ports, and binds it
 */
int
ni_bridge_bind(ni_interface_t *parent, ni_handle_t *nih)
{
	ni_bridge_t *bridge = parent->bridge;
	unsigned int i = 0;

	ni_interface_array_destroy(&bridge->port_devs);
	for (i = 0; i < bridge->port_names.count; ++i) {
		const char *ifname = bridge->port_names.data[i];
		ni_interface_t *slave;

		slave = ni_interface_by_name(nih, ifname);
		if (slave == NULL) {
			ni_bad_reference(nih, parent, ifname);
			return -1;
		}

		ni_interface_array_append(&bridge->port_devs, slave);
		slave->parent = parent;
	}
	return 0;
}

/*
 * Create a copy of a bridge's configuration
 */
ni_bridge_t *
ni_bridge_clone(const ni_bridge_t *src)
{
	ni_bridge_t *dst;

	dst = calloc(1, sizeof(ni_bridge_t));
	if (!dst)
		return NULL;

	dst->stp_enabled = src->stp_enabled;
	dst->forward_delay = src->forward_delay;
	if (ni_string_array_copy(&dst->port_names, &src->port_names) < 0)
		goto failed;
	if (ni_bridge_port_array_copy(&dst->ports, &src->ports) < 0)
		goto failed;

	return dst;

failed:
	error("Error clonding bridge configuration");
	ni_bridge_free(dst);
	return NULL;
}

/*
 * Free bridge information
 */
void
ni_bridge_free(ni_bridge_t *bridge)
{
	ni_bridge_port_array_destroy(&bridge->ports);
	ni_string_array_destroy(&bridge->port_names);
	ni_interface_array_destroy(&bridge->port_devs);
	free(bridge);
}
