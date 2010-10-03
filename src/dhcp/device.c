/*
 * DHCP client for wicked.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <net/if_arp.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include "dhcp.h"
#include "protocol.h"

ni_dhcp_device_t *	ni_dhcp_active;

static void		ni_dhcp_device_free(ni_dhcp_device_t *);

/*
 * Create and destroy dhcp device handles
 */
ni_dhcp_device_t *
ni_dhcp_device_new(const char *ifname, unsigned int iftype)
{
	ni_dhcp_device_t *dev;

	dev = calloc(1, sizeof(*dev));
	ni_string_dup(&dev->ifname, ifname);
	dev->system.iftype = iftype;
	dev->system.mtu = MTU_MAX;

	dev->listen_fd = -1;

	dev->start_time = time(NULL);
	dev->state = NI_DHCP_STATE_INIT;

	/* FIXME: should add to end of list */
	dev->next = ni_dhcp_active;
	ni_dhcp_active = dev;

	return dev;
}

ni_dhcp_device_t *
ni_dhcp_device_find(const char *ifname)
{
	ni_dhcp_device_t *dev;

	for (dev = ni_dhcp_active; dev; dev = dev->next) {
		if (!strcmp(dev->ifname, ifname))
			return dev;
	}

	return NULL;
}

void
ni_dhcp_device_stop(const char *ifname)
{
	ni_dhcp_device_t *dev, **pos;

	for (pos = &ni_dhcp_active; (dev = *pos) != NULL; pos = &dev->next) {
		if (!strcmp(dev->ifname, ifname)) {
			*pos = dev->next;
			ni_dhcp_device_free(dev);
			return;
		}
	}
}


static void
ni_dhcp_device_close(ni_dhcp_device_t *dev)
{
	if (dev->capture)
		ni_capture_free(dev->capture);
	dev->capture = NULL;

	if (dev->listen_fd >= 0)
		close(dev->listen_fd);
	dev->listen_fd = -1;
}

static void
ni_dhcp_device_free(ni_dhcp_device_t *dev)
{
	ni_dhcp_device_drop_buffer(dev);
	ni_dhcp_device_drop_lease(dev);
	ni_string_free(&dev->ifname);
	ni_dhcp_device_close(dev);
	free(dev);
}

unsigned int
ni_dhcp_device_uptime(const ni_dhcp_device_t *dev, unsigned int clamp)
{
	unsigned int uptime;

	uptime = time(NULL) - dev->start_time;
	return (uptime < clamp)? uptime : clamp;
}

void
ni_dhcp_device_set_lease(ni_dhcp_device_t *dev, ni_dhcp_lease_t *lease)
{
	if (dev->lease != lease) {
		if (dev->lease)
			ni_dhcp_lease_free(dev->lease);
		dev->lease = lease;
	}
}

void
ni_dhcp_device_drop_lease(ni_dhcp_device_t *dev)
{
	if (dev->lease) {
		/* FIXME: if we've configured the network using this
		 * lease, we need to isse a link down request */

		/* FIXME: delete the lease file. */
		ni_dhcp_lease_free(dev->lease);
		dev->lease = NULL;
	}
}

int
ni_dhcp_device_reconfigure(ni_dhcp_device_t *dev, const ni_interface_t *ifp)
{
	ni_dhclient_info_t *info;
	ni_dhcp_config_t *config;
	int changed = 0;

	if (!(info = ifp->ipv4.dhcp)) {
		ni_error("%s: no DHCP config data given", ifp->name);
		return -1;
	}

	if (dev->system.iftype != ifp->type) {
		ni_error("%s: reconfig changes device type!", dev->ifname);
		return -1;
	}
	dev->system.arp_type = ifp->arp_type;
	dev->system.ifindex = if_nametoindex(ifp->name);
	dev->system.mtu = ifp->mtu;

	if (!ni_link_address_equal(&ifp->hwaddr, &dev->system.hwaddr)) {
		dev->system.hwaddr = ifp->hwaddr;
		changed = 1;
	}

	if (dev->system.arp_type == ARPHRD_NONE) {
		ni_warn("%s: no arp_type, using ether", __FUNCTION__);
		dev->system.arp_type = ARPHRD_ETHER;
	}

	config = calloc(1, sizeof(*config));
	config->resend_timeout = NI_DHCP_RESEND_TIMEOUT_INIT;
	config->request_timeout = info->lease.timeout?: NI_DHCP_REQUEST_TIMEOUT;

	if (info->request.hostname
	 && strcmp(config->hostname, info->request.hostname)) {
		strncpy(config->hostname, info->request.hostname,
				sizeof(config->hostname) - 1);
		changed = 1;
	}
	if (info->request.clientid) {
		ni_hwaddr_t hwaddr;

		/* Check if it's a hardware address */
		if (ni_link_address_parse(&hwaddr, ifp->type, info->request.clientid) == 0) {
			ni_opaque_set(&config->clientid, hwaddr.data, hwaddr.len);
		} else {
			/* nope, use as-is */
			unsigned int len = strlen(info->request.clientid) + 1;

			ni_opaque_set(&config->clientid, info->request.clientid, len);
		}
	} else {
		/* Set client ID from interface hwaddr */
		ni_opaque_set(&config->clientid, dev->system.hwaddr.data, dev->system.hwaddr.len);
	}

	if (info->request.vendor_class)
		strncpy(config->classid, info->request.vendor_class, sizeof(config->classid) - 1);

	config->flags = DHCP_DO_ARP | DHCP_DO_CSR | DHCP_DO_MSCSR;
	if (info->update.hostname)
		config->flags |= DHCP_DO_HOSTNAME;
	if (info->update.resolver)
		config->flags |= DHCP_DO_RESOLVER;
	if (info->update.nis_servers)
		config->flags |= DHCP_DO_NIS;
	if (info->update.ntp_servers)
		config->flags |= DHCP_DO_NTP;
	if (info->update.default_route)
		config->flags |= DHCP_DO_GATEWAY;

	if (dev->config == NULL || memcmp(dev->config, config, sizeof(*config)) != 0) {
		if (dev->config)
			free(dev->config);
		dev->config = config;
	} else {
		free(config);
	}
	return changed;
}

int
ni_dhcp_device_start(ni_dhcp_device_t *dev)
{
	if (0 /* && info->lease.reuse_unexpired */) {
		if (!dev->lease) {
			/* TBD: retrieve existing lease */
			/* TBD: check whether it matches our config
			 * (eg the hostname we're supposed to request) */
		}

		/* check if it is still valid. */
		if (dev->lease /* && !still_valid(dev->lease) */)
			ni_dhcp_device_drop_lease(dev);
	} else {
		ni_dhcp_device_drop_lease(dev);
	}

	ni_dhcp_device_drop_buffer(dev);

	dev->failed = 0;
	if (ni_dhcp_fsm_discover(dev) < 0) {
		ni_error("unable to initiate discovery");
		return -1;
	}

	return 0;
}

void
ni_dhcp_device_alloc_buffer(ni_dhcp_device_t *dev)
{
	unsigned int mtu = 0;
	void *pkt;

	mtu = dev->system.mtu;
	if (mtu == 0)
		mtu = MTU_MAX;

	if (dev->message.size == mtu) {
		ni_buffer_clear(&dev->message);
	} else {
		ni_dhcp_device_drop_buffer(dev);

		pkt = calloc(1, mtu);
		ni_buffer_init(&dev->message, pkt, mtu);
	}
}

void
ni_dhcp_device_drop_buffer(ni_dhcp_device_t *dev)
{
	if (dev->message.base)
		free(dev->message.base);
	memset(&dev->message, 0, sizeof(dev->message));
}

#if 0
int
ni_dhcp_wait(struct pollfd *pfd, unsigned int count, unsigned int maxfd)
{
	ni_dhcp_device_t *monitor[maxfd];
	ni_dhcp_device_t *dev;
	struct timeval now;
	long timeout = -1;
	unsigned int i, offset = count;

	gettimeofday(&now, NULL);
	for (dev = ni_dhcp_active; dev && count < maxfd; dev = dev->next) {
		if (dev->capture) {
			monitor[count] = dev;
			pfd[count].fd = ni_capture_desc(dev->capture);
			pfd[count].events = POLLIN;
			count++;
		}

		timeout = __ni_dhcp_timeout(timeout, &now, &dev->expires);
		timeout = __ni_dhcp_timeout(timeout, &now, &dev->retrans.deadline);
	}

	if (poll(pfd, count, timeout) < 0) {
		if (errno == EINTR)
			return 0;
		ni_fatal("poll returns error: %m");
	}

	for (i = offset; i < count; ++i) {
		ni_dhcp_device_t *dev = monitor[i];

		if (pfd[i].revents & POLLIN)
			ni_dhcp_device_process_packet(dev);
	}

	gettimeofday(&now, NULL);
	for (dev = ni_dhcp_active; dev && count < maxfd; dev = dev->next) {
		if (__ni_dhcp_timed_out(&now, &dev->expires)) {
			ni_dhcp_fsm_timeout(dev);
		} else
		if (__ni_dhcp_timed_out(&now, &dev->retrans.deadline)) {
			ni_dhcp_device_retransmit(dev);
		}
	}

	return 0;
}
#endif

ni_dhcp_device_t *
ni_dhcp_device_get_changed(void)
{
	ni_dhcp_device_t *dev;

	for (dev = ni_dhcp_active; dev; dev = dev->next) {
		if (dev->notify) {
			dev->notify = 0;
			return dev;
		}
	}

	return NULL;
}

int
ni_dhcp_device_send_message(ni_dhcp_device_t *dev, unsigned int msg_code, const ni_dhcp_lease_t *lease)
{
	static uint32_t ni_dhcp_xid;
	int rv;

	/* Assign a new XID to this message */
	if (ni_dhcp_xid == 0)
		ni_dhcp_xid = random();
	dev->xid = ni_dhcp_xid++;

	if (ni_dhcp_socket_open(dev) < 0) {
		ni_error("unable to open capture socket");
		return -1;
	}

	ni_debug_dhcp("sending %s with xid 0x%x", ni_dhcp_message_name(msg_code), dev->xid);

	/* Allocate an empty buffer */
	ni_dhcp_device_alloc_buffer(dev);

	/* Build the DHCP message */
	rv = ni_dhcp_build_message(dev, msg_code, lease, &dev->message);

	/* FIXME: during renewal, we really want to unicast the request */
	if (rv >= 0) {
		rv = ni_capture_broadcast(dev->capture,
					ni_buffer_head(&dev->message),
					ni_buffer_count(&dev->message));
	}

	if (rv >= 0) {
		dev->retrans.timeout = dev->config->resend_timeout;
		dev->retrans.increment = dev->config->resend_timeout;
		ni_dhcp_device_arm_retransmit(dev);
	}

	return rv;
}

void
ni_dhcp_device_retransmit(ni_dhcp_device_t *dev)
{
	int rv;

	ni_debug_dhcp("%s: retransmit request", dev->ifname);

	if (ni_buffer_count(&dev->message) == 0) {
		ni_error("ni_dhcp_device_retransmit: no message!?");
		ni_dhcp_device_disarm_retransmit(dev);
		return;
	}

	if (dev->retrans.increment)
		dev->retrans.timeout += dev->retrans.increment;
	else
		dev->retrans.timeout <<= 1;
	if (dev->retrans.timeout > NI_DHCP_RESEND_TIMEOUT_MAX)
		dev->retrans.timeout = NI_DHCP_RESEND_TIMEOUT_MAX;

	rv = ni_capture_broadcast(dev->capture,
				ni_buffer_head(&dev->message),
				ni_buffer_count(&dev->message));

	/* We don't care whether sending failed or not. Quite possibly
	 * it's a temporary condition, so continue */
	if (rv < 0)
		ni_warn("%s: sending message failed", dev->ifname);
	ni_dhcp_device_arm_retransmit(dev);
}

void
ni_dhcp_device_arm_retransmit(ni_dhcp_device_t *dev)
{
	unsigned long timeout = dev->retrans.timeout * 1000;

	/* We're supposed to add a random jitter of +/-1 sec */
	timeout += (random() % 2000) - 1000;

	ni_debug_dhcp("%s: arming retransmit timer (%lu msec)",
			dev->ifname, timeout);

	gettimeofday(&dev->retrans.deadline, NULL);
	dev->retrans.deadline.tv_sec += timeout / 1000;
	dev->retrans.deadline.tv_usec += (timeout % 1000) * 1000;
	if (dev->retrans.deadline.tv_usec < 0) {
		dev->retrans.deadline.tv_sec -= 1;
		dev->retrans.deadline.tv_usec += 1000000;
	} else
	if (dev->retrans.deadline.tv_usec > 1000000) {
		dev->retrans.deadline.tv_sec += 1;
		dev->retrans.deadline.tv_usec -= 1000000;
	}
}

void
ni_dhcp_device_disarm_retransmit(ni_dhcp_device_t *dev)
{
	/* Clear retransmit timer */
	timerclear(&dev->retrans.deadline);
	dev->retrans.timeout = 0;

	/* Drop the message buffer */
	ni_dhcp_device_drop_buffer(dev);
}
