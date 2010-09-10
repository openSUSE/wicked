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

/*
 * Add a port to the bridge configuration
 */
void
ni_bridge_add_port(ni_bridge_t *bridge, const char *ifname)
{
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
	if (!ni_string_array_copy(&dst->port_names, &src->port_names))
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
	ni_string_array_destroy(&bridge->port_names);
	ni_interface_array_destroy(&bridge->port_devs);
	free(bridge);
}
