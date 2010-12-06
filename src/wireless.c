/*
 * Routines for handling Wireless devices.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <errno.h>

#include <wicked/wireless.h>
#include "netinfo_priv.h"
#include "kernel.h"

extern ni_wireless_scan_t *	ni_wireless_scan_new(void);

static void			__ni_wireless_network_destroy(ni_wireless_network_t *net);

int
ni_system_wireless_scan(ni_handle_t *nih, ni_interface_t *ifp)
{
	ni_wireless_scan_t *scan;

	if (ifp->type != NI_IFTYPE_WIRELESS) {
		ni_error("%s: cannot do wireless scan on this interface", ifp->name);
		return -1;
	}

	scan = ni_wireless_scan_new();
	ni_interface_set_wireless_scan(ifp, scan);
	scan->timestamp = time(NULL);
	scan->lifetime = 60;

	/* Bring up the interface for scanning */
	if (!(ifp->ifflags & NI_IFF_DEVICE_UP)) {
		if (__ni_interface_begin_activity(nih, ifp, NI_INTERFACE_WIRELESS_SCAN) < 0) {
			ni_error("%s: could not bring interface up for wireless scan",
					ifp->name);
			return -1;
		}
	}

	/* Initiate the scan */

	return 0;
}

/*
 * Wireless interface config
 */
ni_wireless_t *
ni_wireless_new(void)
{
	return xcalloc(1, sizeof(ni_wireless_t));
}

void
ni_wireless_free(ni_wireless_t *wireless)
{
	__ni_wireless_network_destroy(&wireless->network);
	free(wireless);
}

/*
 * Wireless scan objects
 */
ni_wireless_scan_t *
ni_wireless_scan_new(void)
{
	return xcalloc(1, sizeof(ni_wireless_scan_t));
}

void
ni_wireless_scan_free(ni_wireless_scan_t *scan)
{
	ni_wireless_network_array_destroy(&scan->networks);
}

/*
 * Wireless network objects
 */
ni_wireless_network_t *
ni_wireless_network_new(void)
{
	return xcalloc(1, sizeof(ni_wireless_network_t));
}

void
__ni_wireless_network_destroy(ni_wireless_network_t *net)
{
	ni_string_free(&net->essid);
}

void
ni_wireless_network_free(ni_wireless_network_t *net)
{
	__ni_wireless_network_destroy(net);
	free(net);
}

/*
 * Wireless network arrays
 */
void
ni_wireless_network_array_init(ni_wireless_network_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_wireless_network_array_append(ni_wireless_network_array_t *array, ni_wireless_network_t *net)
{
	array->data = realloc(array->data, (array->count + 1) * sizeof(ni_wireless_network_t *));
	array->data[array->count++] = net;
}

void
ni_wireless_network_array_destroy(ni_wireless_network_array_t *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i)
		ni_wireless_network_free(array->data[i]);
	free(array->data);
	memset(array, 0, sizeof(*array));
}
