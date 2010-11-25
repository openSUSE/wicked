/*
 * Routines for handling Ethernet devices.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include "netinfo_priv.h"
#include <wicked/ethernet.h>

/*
 * Clone a device's VLAN configuration
 */
ni_ethernet_t *
ni_ethernet_clone(const ni_ethernet_t *src)
{
	ni_ethernet_t *dst;

	dst = calloc(1, sizeof(ni_ethernet_t));
	if (!dst)
		return NULL;

	*dst = *src;
	return dst;
}

void
ni_ethernet_free(ni_ethernet_t *ethernet)
{
	free(ethernet);
}


