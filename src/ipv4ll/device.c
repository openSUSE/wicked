/*
 * An IPv4LL RFC 3927 supplicant for wicked
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include "netinfo_priv.h"
#include "autoip.h"
#include "config.h"

ni_autoip_device_t *	ni_autoip_active;

/*
 * Create and destroy autoip device handles
 */
ni_autoip_device_t *
ni_autoip_device_new(const char *ifname, unsigned int iftype)
{
	ni_autoip_device_t *dev, **pos;

	for (pos = &ni_autoip_active; (dev = *pos) != NULL; pos = &dev->next)
		;

	dev = calloc(1, sizeof(*dev));
	ni_string_dup(&dev->ifname, ifname);
	dev->devinfo.ifname = dev->ifname;
	dev->devinfo.iftype = iftype;
	dev->devinfo.mtu = 1500;
	dev->fsm.state = NI_AUTOIP_STATE_INIT;

	/* append to end of list */
	*pos = dev;

	return dev;
}

ni_autoip_device_t *
ni_autoip_device_find(const char *ifname)
{
	ni_autoip_device_t *dev;

	for (dev = ni_autoip_active; dev; dev = dev->next) {
		if (!strcmp(dev->ifname, ifname))
			return dev;
	}

	return NULL;
}

static void
ni_autoip_device_close(ni_autoip_device_t *dev)
{
	if (dev->capture)
		ni_capture_free(dev->capture);
	dev->capture = NULL;
}

void
ni_autoip_device_stop(ni_autoip_device_t *dev)
{
	/* Clear the lease. This will trigger an event to wickedd
	 * with a lease that has state RELEASED. */
	ni_autoip_device_drop_lease(dev);
	ni_autoip_device_close(dev);
}

void
ni_autoip_device_set_lease(ni_autoip_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (dev->lease != lease) {
		if (dev->lease)
			ni_addrconf_lease_free(dev->lease);
		dev->lease = lease;
	}
}

void
ni_autoip_device_drop_lease(ni_autoip_device_t *dev)
{
	ni_addrconf_lease_t *lease;

	if ((lease = dev->lease) != NULL) {
		/* if we've configured the network using this
		 * lease, we need to isse a link down request */
		dev->notify = 1;

		/* delete the lease file. */
		ni_addrconf_lease_file_remove(dev->ifname, lease->type, lease->family);
		ni_autoip_device_set_lease(dev, NULL);

		/* Go back to square one */
		dev->fsm.state = NI_AUTOIP_STATE_INIT;
	}
}

void
ni_autoip_device_free(ni_autoip_device_t *dev)
{
	ni_autoip_device_t **pos;

	ni_autoip_device_drop_lease(dev);
	ni_autoip_device_close(dev);
	ni_string_free(&dev->ifname);

	for (pos = &ni_autoip_active; *pos; pos = &(*pos)->next) {
		if (*pos == dev) {
			*pos = dev->next;
			break;
		}
	}
	free(dev);
}

/*
 * Process a request to reconfigure the device (ie rebind a lease, or discover
 * a new lease).
 */
int
ni_autoip_device_reconfigure(ni_autoip_device_t *dev, const ni_interface_t *ifp)
{
	if (ifp->flags & IFF_NOARP) {
		ni_error("%s: device does not support ARP, cannot configure for IPv4LL", ifp->name);
		return -1;
	}
	if (dev->devinfo.iftype != ifp->type) {
		ni_error("%s: reconfig changes device type!", dev->ifname);
		return -1;
	}
	if (ifp->hwaddr.len == 0) {
		ni_error("%s: empty MAC address, cannot do IPv4LL", dev->ifname);
		return -1;
	}
	dev->devinfo.arp_type = ifp->arp_type;
	dev->devinfo.ifindex = if_nametoindex(ifp->name);
	dev->devinfo.mtu = ifp->mtu;
	dev->devinfo.hwaddr = ifp->hwaddr;

	if (dev->devinfo.arp_type == ARPHRD_NONE) {
		ni_warn("%s: no arp_type, using ether", __FUNCTION__);
		dev->devinfo.arp_type = ARPHRD_ETHER;
	}

	/* Go back to INIT state to force a reclaim */
	dev->fsm.state = NI_AUTOIP_STATE_INIT;
	return 1;
}

int
ni_autoip_device_start(ni_autoip_device_t *dev)
{
	ni_autoip_device_drop_lease(dev);
	dev->failed = 0;

	if (ni_autoip_fsm_select(dev) < 0) {
		ni_error("%s: unable to initiate discovery", dev->ifname);
		return -1;
	}

	return 0;
}
