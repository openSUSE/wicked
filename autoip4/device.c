/*
 * An IPv4LL RFC 3927 supplicant for wicked
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include "appconfig.h"

ni_autoip_device_t *	ni_autoip_active;

/*
 * Create and destroy autoip device handles
 */
ni_autoip_device_t *
ni_autoip_device_new(const char *ifname, const ni_linkinfo_t *link)
{
	ni_autoip_device_t *dev, **pos;

	for (pos = &ni_autoip_active; (dev = *pos) != NULL; pos = &dev->next)
		;

	if (!(dev = calloc(1, sizeof(*dev))))
		return NULL;

	dev->users = 1;
	dev->fsm.state = NI_AUTOIP_STATE_INIT;

	dev->link.ifindex = link->ifindex;
	ni_string_dup(&dev->ifname, ifname);

	if (ni_capture_devinfo_init(&dev->devinfo, ifname, link) < 0) {
		ni_autoip_device_put(dev);
		return NULL;
	}

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

ni_autoip_device_t *
ni_autoip_device_by_index(unsigned int ifindex)
{
	ni_autoip_device_t *dev;

	for (dev = ni_autoip_active; dev; dev = dev->next) {
		if (dev->link.ifindex == ifindex)
			return dev;
	}

	return NULL;
}

static void
ni_autoip_device_close(ni_autoip_device_t *dev)
{
	if (dev->arp_socket)
		ni_arp_socket_close(dev->arp_socket);
	dev->arp_socket = NULL;

	if (dev->fsm.timer) {
		ni_timer_cancel(dev->fsm.timer);
		dev->fsm.timer = NULL;
	}
}

void
ni_autoip_device_stop(ni_autoip_device_t *dev)
{
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

	ni_assert(dev->users == 0);
	ni_debug_autoip("%s: Deleting autoip4 device with index %u",
			dev->ifname, dev->link.ifindex);

	ni_autoip_device_drop_lease(dev);
	ni_autoip_device_close(dev);

	ni_capture_devinfo_destroy(&dev->devinfo);

	ni_string_free(&dev->ifname);

	for (pos = &ni_autoip_active; *pos; pos = &(*pos)->next) {
		if (*pos == dev) {
			*pos = dev->next;
			break;
		}
	}
	free(dev);
}

ni_autoip_device_t *
ni_autoip_device_get(ni_autoip_device_t *dev)
{
	ni_assert(dev->users);
	dev->users++;
	return dev;
}

void
ni_autoip_device_put(ni_autoip_device_t *dev)
{
	ni_assert(dev->users);
	if (--(dev->users) == 0)
		ni_autoip_device_free(dev);
}

/*
 * Process a request to reconfigure the device (ie rebind a lease, or discover
 * a new lease).
 */
int
ni_autoip_device_refresh(ni_autoip_device_t *dev)
{
	ni_netconfig_t *nih = ni_global_state_handle(0);
	ni_netdev_t *ifp;
	int rv = -1;

	/* Go back to INIT state to force a reclaim */
	dev->fsm.state = NI_AUTOIP_STATE_INIT;

	ifp = nih ? ni_netdev_by_index(nih, dev->link.ifindex) : NULL;
	if (!ifp || (rv = __ni_device_refresh_link_info(nih, &ifp->link)) < 0) {
		ni_error("%s: cannot refresh interface: %s", dev->ifname, ni_strerror(rv));
		return rv;
	}

	return ni_capture_devinfo_refresh(&dev->devinfo, dev->ifname, &ifp->link);
}

int
ni_autoip_device_start(ni_autoip_device_t *dev)
{
	dev->failed = 0;

	if (ni_autoip_fsm_select(dev) < 0) {
		ni_error("%s: unable to initiate discovery", dev->ifname);
		return -1;
	}

	return 0;
}

void
ni_autoip_device_set_request(ni_autoip_device_t *dev, const ni_auto4_request_t *request)
{
	if (dev) {
		ni_auto4_request_destroy(&dev->request);
		if (request)
			ni_auto4_request_copy(&dev->request, request);
	}
}

/*
 * Acquire an IPv4ll lease
 */
int
ni_autoip_acquire(ni_autoip_device_t *dev, const ni_auto4_request_t *request)
{
	if (!dev || !request)
		return -1;

	ni_autoip_device_stop(dev);
	ni_autoip_device_set_request(dev, request);
	ni_note("%s: Request to acquire AUTOv4 lease with UUID %s",
			dev->ifname, ni_uuid_print(&request->uuid));

	ni_autoip_device_set_lease(dev, ni_addrconf_lease_file_read(dev->ifname,
					NI_ADDRCONF_AUTOCONF, AF_INET));
	if (ni_autoip_device_start(dev) < 0)
		return -1;
	return 1;
}

static void
ni_autoip_start_release(void *user_data, const ni_timer_t *timer)
{
	ni_autoip_device_t *dev = user_data;

	if (dev->fsm.timer != timer)
		return;
	dev->fsm.timer = NULL;

	ni_autoip_fsm_release(dev);
	ni_autoip_device_stop(dev);
	ni_autoip_device_set_request(dev, NULL);
}

int
ni_autoip_release(ni_autoip_device_t *dev, const ni_uuid_t *req_uuid)
{
	char *rel_uuid = NULL;

	ni_string_dup(&rel_uuid, ni_uuid_print(req_uuid));
	if (dev->lease == NULL || !dev->request.enabled) {
		ni_info("%s: Request to release AUTOv4%s%s: no lease", dev->ifname,
			rel_uuid ? " using UUID " : "", rel_uuid ? rel_uuid : "");
		ni_string_free(&rel_uuid);

		ni_autoip_device_stop(dev);
		ni_autoip_device_set_request(dev, NULL);
		return -NI_ERROR_ADDRCONF_NO_LEASE;
	}
	ni_note("%s: Request to release AUTOv4 lease%s%s: releasing...",  dev->ifname,
			rel_uuid ? " with UUID " : "", rel_uuid ? rel_uuid : "");
	ni_string_free(&rel_uuid);

	/* we do not send out any release request, but an event
	 * about the released lease, which should be sent after
	 * we've returned TRUE result about to the caller...
	 */
	ni_autoip_device_close(dev);
	dev->lease->uuid = *req_uuid;
	dev->request.uuid = *req_uuid;
	dev->fsm.timer = ni_timer_register(0, ni_autoip_start_release, dev);
	return 1;
}

