/*
 * DHCP client for wicked.
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
#include <wicked/logging.h>
#include "netinfo_priv.h"
#include "dhcp.h"
#include "protocol.h"
#include "config.h"

ni_dhcp_device_t *	ni_dhcp_active;

/*
 * Create and destroy dhcp device handles
 */
ni_dhcp_device_t *
ni_dhcp_device_new(const char *ifname, unsigned int iftype)
{
	ni_dhcp_device_t *dev, **pos;

	for (pos = &ni_dhcp_active; (dev = *pos) != NULL; pos = &dev->next)
		;

	dev = calloc(1, sizeof(*dev));
	ni_string_dup(&dev->ifname, ifname);
	dev->users = 1;
	dev->system.ifname = dev->ifname;
	dev->system.iftype = iftype;
	dev->system.mtu = MTU_MAX;
	dev->listen_fd = -1;
	dev->start_time = time(NULL);
	dev->fsm.state = NI_DHCP_STATE_INIT;

	/* append to end of list */
	*pos = dev;

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

static void
ni_dhcp_device_close(ni_dhcp_device_t *dev)
{
	if (dev->capture)
		ni_capture_free(dev->capture);
	dev->capture = NULL;

	if (dev->listen_fd >= 0)
		close(dev->listen_fd);
	dev->listen_fd = -1;

	ni_dhcp_device_arp_close(dev);
}

void
ni_dhcp_device_stop(ni_dhcp_device_t *dev)
{
	/* Clear the lease. This will trigger an event to wickedd
	 * with a lease that has state RELEASED. */
	ni_dhcp_fsm_commit_lease(dev, NULL);
	ni_dhcp_device_close(dev);

	/* Drop existing config */
	if (dev->config)
		free(dev->config);
	dev->config = NULL;
}

void
ni_dhcp_device_free(ni_dhcp_device_t *dev)
{
	ni_dhcp_device_t **pos;

	ni_assert(dev->users == 0);
	ni_dhcp_device_drop_buffer(dev);
	ni_dhcp_device_drop_lease(dev);
	ni_dhcp_device_drop_best_offer(dev);
	ni_dhcp_device_close(dev);
	ni_string_free(&dev->ifname);

	for (pos = &ni_dhcp_active; *pos; pos = &(*pos)->next) {
		if (*pos == dev) {
			*pos = dev->next;
			break;
		}
	}
	free(dev);
}

/*
 * Refcount handling
 */
ni_dhcp_device_t *
ni_dhcp_device_get(ni_dhcp_device_t *dev)
{
	ni_assert(dev->users);
	dev->users++;
	return dev;
}

void
ni_dhcp_device_put(ni_dhcp_device_t *dev)
{
	ni_assert(dev->users);
	if (--(dev->users) == 0)
		ni_dhcp_device_free(dev);
}


unsigned int
ni_dhcp_device_uptime(const ni_dhcp_device_t *dev, unsigned int clamp)
{
	unsigned int uptime;

	uptime = time(NULL) - dev->start_time;
	return (uptime < clamp)? uptime : clamp;
}

void
ni_dhcp_device_set_lease(ni_dhcp_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (dev->lease != lease) {
		if (dev->lease)
			ni_addrconf_lease_free(dev->lease);
		dev->lease = lease;
	}
}

void
ni_dhcp_device_drop_lease(ni_dhcp_device_t *dev)
{
	ni_addrconf_lease_t *lease;

	if ((lease = dev->lease) != NULL) {
		/* FIXME: if we've configured the network using this
		 * lease, we need to isse a link down request */

		/* delete the lease file. */
		ni_addrconf_lease_file_remove(dev->ifname, lease->type, lease->family);
		ni_addrconf_lease_free(lease);
		dev->lease = NULL;

		/* Go back to square one */
		dev->fsm.state = NI_DHCP_STATE_INIT;
	}
}

void
ni_dhcp_device_drop_best_offer(ni_dhcp_device_t *dev)
{
	dev->best_offer.weight = -1;
	if (dev->best_offer.lease)
		ni_addrconf_lease_free(dev->best_offer.lease);
	dev->best_offer.lease = NULL;
}

/*
 * Refresh the device info prior to taking any actions
 */
int
ni_dhcp_device_refresh(ni_dhcp_device_t *dev)
{
	ni_handle_t *nih = ni_global_state_handle();
	int rv;

	if ((rv = __ni_device_refresh_link_info(nih, &dev->link)) < 0) {
		ni_error("%s: cannot refresh interface: %s",
				__func__, ni_strerror(rv));
		return rv;
	}

	if (dev->system.iftype != dev->link.type) {
		ni_error("%s: reconfig changes device type!", dev->ifname);
		return -1;
	}

	if (dev->link.hwaddr.len == 0) {
		ni_error("%s: empty MAC address, cannot do DHCP", dev->ifname);
		return -1;
	}
	dev->system.ifindex = dev->link.ifindex;
	dev->system.arp_type = dev->link.arp_type;
	dev->system.iftype = dev->link.type;
	dev->system.mtu = dev->link.mtu;
	dev->system.hwaddr = dev->link.hwaddr;

	if (dev->system.arp_type == ARPHRD_NONE) {
		ni_warn("%s: no arp_type, using ether", __FUNCTION__);
		dev->system.arp_type = ARPHRD_ETHER;
	}

	return 0;
}

/*
 * Process a request to reconfigure the device (ie rebind a lease, or discover
 * a new lease).
 */
int
ni_dhcp_acquire(ni_dhcp_device_t *dev, const ni_addrconf_request_t *info)
{
	ni_dhcp_config_t *config;
	const char *classid;
	int rv;

	if ((rv = ni_dhcp_device_refresh(dev)) < 0)
		return rv;

	config = calloc(1, sizeof(*config));
	config->resend_timeout = NI_DHCP_RESEND_TIMEOUT_INIT;
	config->request_timeout = info->acquire_timeout?: NI_DHCP_REQUEST_TIMEOUT;
	config->initial_discovery_timeout = NI_DHCP_DISCOVERY_TIMEOUT;

	config->max_lease_time = ni_dhcp_config_max_lease_time();
	if (config->max_lease_time == 0)
		config->max_lease_time = ~0U;
	if (info->dhcp.lease_time && info->dhcp.lease_time < config->max_lease_time)
		config->max_lease_time = info->dhcp.lease_time;

	if (info->dhcp.hostname)
		strncpy(config->hostname, info->dhcp.hostname, sizeof(config->hostname) - 1);

	if (info->dhcp.clientid) {
		strncpy(config->client_id, info->dhcp.clientid, sizeof(config->client_id)-1);
		ni_dhcp_parse_client_id(&config->raw_client_id, dev->link.type, info->dhcp.clientid);
	} else {
		/* Set client ID from interface hwaddr */
		strncpy(config->client_id, ni_link_address_print(&dev->system.hwaddr), sizeof(config->client_id)-1);
		ni_dhcp_set_client_id(&config->raw_client_id, &dev->system.hwaddr);
	}

	classid = ni_dhcp_config_vendor_class();
	if (classid)
		strncpy(config->classid, classid, sizeof(config->classid) - 1);

	config->flags = DHCP_DO_ARP | DHCP_DO_CSR | DHCP_DO_MSCSR;
	if (ni_addrconf_should_update(info, NI_ADDRCONF_UPDATE_HOSTNAME))
		config->flags |= DHCP_DO_HOSTNAME;
	if (ni_addrconf_should_update(info, NI_ADDRCONF_UPDATE_RESOLVER))
		config->flags |= DHCP_DO_RESOLVER;
	if (ni_addrconf_should_update(info, NI_ADDRCONF_UPDATE_NIS))
		config->flags |= DHCP_DO_NIS;
	if (ni_addrconf_should_update(info, NI_ADDRCONF_UPDATE_NTP))
		config->flags |= DHCP_DO_NTP;
	if (ni_addrconf_should_update(info, NI_ADDRCONF_UPDATE_DEFAULT_ROUTE))
		config->flags |= DHCP_DO_GATEWAY;

	if (dev->config)
		free(dev->config);
	dev->config = config;

	/* If we're asked to reclaim an existing lease, try to load it. */
	if (info->reuse_unexpired && ni_dhcp_fsm_recover_lease(dev, info) >= 0)
		return 0;

	if (dev->lease) {
		if (!ni_addrconf_lease_is_valid(dev->lease)
		 || !ni_dhcp_lease_matches_request(dev->lease, info)) {
			ni_debug_dhcp("%s: lease doesn't match request", dev->ifname);
			ni_dhcp_device_drop_lease(dev);
			dev->notify = 1;
		}
	}

	/* Go back to INIT state to force a rediscovery */
	dev->fsm.state = NI_DHCP_STATE_INIT;
	ni_dhcp_device_start(dev);
	return 1;
}

/*
 * Process a request to unconfigure the device (ie drop the lease).
 */
int
ni_dhcp_release(ni_dhcp_device_t *dev, const ni_uuid_t *lease_uuid)
{
	ni_error("%s: %s not yet implemented", dev->ifname, __func__);
	return -1;
}

int
ni_dhcp_device_start(ni_dhcp_device_t *dev)
{
	ni_dhcp_device_drop_lease(dev);
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
ni_dhcp_device_send_message(ni_dhcp_device_t *dev, unsigned int msg_code, const ni_addrconf_lease_t *lease)
{
	static uint32_t ni_dhcp_xid;
	ni_timeout_param_t timeout;
	int rv;

	/* Assign a new XID to this message */
	if (ni_dhcp_xid == 0)
		ni_dhcp_xid = random();
	dev->dhcp.xid = ni_dhcp_xid++;

	if (ni_dhcp_socket_open(dev) < 0) {
		ni_error("unable to open capture socket");
		goto transient_failure;
	}

	ni_debug_dhcp("sending %s with xid 0x%x", ni_dhcp_message_name(msg_code), dev->dhcp.xid);

	/* Allocate an empty buffer */
	ni_dhcp_device_alloc_buffer(dev);

	/* Build the DHCP message */
	if ((rv = ni_dhcp_build_message(dev, msg_code, lease, &dev->message)) < 0) {
		/* This is really terminal */
		ni_error("unable to build DHCP message");
		return -1;
	}

	switch (msg_code) {
	case DHCP_DECLINE:
	case DHCP_RELEASE:
		rv = ni_capture_broadcast(dev->capture, &dev->message, NULL);
		break;

	case DHCP_DISCOVER:
	case DHCP_REQUEST:
	case DHCP_INFORM:
		memset(&timeout, 0, sizeof(timeout));
		timeout.timeout = dev->config->resend_timeout;
		timeout.increment = dev->config->resend_timeout;
		timeout.max_jitter = 1;	/* add a random jitter of +/-1 sec */
		timeout.max_timeout = NI_DHCP_RESEND_TIMEOUT_MAX;

		/* FIXME: during renewal, we really want to unicast the request */
		rv = ni_capture_broadcast(dev->capture, &dev->message, &timeout);
		break;

	default:
		ni_warn("not sure whether I should retransmit %s message",
				ni_dhcp_message_name(msg_code));
	}
	if (rv < 0)
		ni_debug_dhcp("unable to broadcast message");

	return 0;

transient_failure:
	/* We ran into a transient problem, such as being unable to open
	 * a raw socket. We should schedule a "short" timeout after which
	 * we should re-try the operation. */
	/* FIXME: Not done yet. */
	return 0;
}

void
ni_dhcp_device_disarm_retransmit(ni_dhcp_device_t *dev)
{
	/* Clear retransmit timer */
	if (dev->capture)
		ni_capture_disarm_retransmit(dev->capture);

	/* Drop the message buffer */
	ni_dhcp_device_drop_buffer(dev);
}

void
ni_dhcp_device_force_retransmit(ni_dhcp_device_t *dev, unsigned int delay)
{
	if (dev->capture)
		ni_capture_force_retransmit(dev->capture, delay);
}

void
ni_dhcp_device_arp_close(ni_dhcp_device_t *dev)
{
	if (dev->arp.handle) {
		ni_arp_socket_close(dev->arp.handle);
		dev->arp.handle = NULL;
	}
}

/*
 * Parse a client id
 */
void
ni_dhcp_parse_client_id(ni_opaque_t *raw, int iftype, const char *cooked)
{
	ni_hwaddr_t hwaddr;

	/* Check if it's a hardware address */
	if (ni_link_address_parse(&hwaddr, iftype, cooked) == 0) {
		ni_dhcp_set_client_id(raw, &hwaddr);
	} else {
		/* nope, use as-is */
		unsigned int len = strlen(cooked);

		if (len > sizeof(raw->data) - 1)
			len = sizeof(raw->data) - 1;

		raw->data[0] = 0;
		memcpy(raw->data + 1, cooked, len);
		raw->len = len + 1;
	}
}

/*
 * Set the client ID from a link layer address, according to RFC 2131
 */
void
ni_dhcp_set_client_id(ni_opaque_t *raw, const ni_hwaddr_t *hwa)
{
	if (hwa->len + 1 > sizeof(raw->data))
		ni_fatal("%s: not enough room for MAC address", __FUNCTION__);
	raw->data[0] = ni_iftype_to_arphrd_type(hwa->type);
	memcpy(raw->data + 1, hwa->data, hwa->len);
	raw->len = hwa->len + 1;
}

/*
 * Functions for accessing various global DHCP configuration options
 */
const char *
ni_dhcp_config_vendor_class(void)
{
	const struct ni_config_dhcp *dhconf = &ni_global.config->addrconf.dhcp;

	return dhconf->vendor_class;
}

int
ni_dhcp_config_ignore_server(struct in_addr addr)
{
	const struct ni_config_dhcp *dhconf = &ni_global.config->addrconf.dhcp;
	const char *name = inet_ntoa(addr);

	return (ni_string_array_index(&dhconf->ignore_servers, name) >= 0);
}

int
ni_dhcp_config_have_server_preference(void)
{
	const struct ni_config_dhcp *dhconf = &ni_global.config->addrconf.dhcp;
	return dhconf->num_preferred_servers != 0;
}

int
ni_dhcp_config_server_preference(struct in_addr addr)
{
	const struct ni_config_dhcp *dhconf = &ni_global.config->addrconf.dhcp;
	const ni_server_preference_t *pref = dhconf->preferred_server;
	unsigned int i;

	for (i = 0; i < dhconf->num_preferred_servers; ++i, ++pref) {
		if (pref->address.ss_family != AF_INET)
			continue;
		if (pref->address.sin.sin_addr.s_addr == addr.s_addr)
			return pref->weight;
	}
	return 0;
}

unsigned int
ni_dhcp_config_max_lease_time(void)
{
	return ni_global.config->addrconf.dhcp.lease_time;
}
