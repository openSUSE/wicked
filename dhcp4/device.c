/*
 * DHCP4 client for wicked.
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
#include <wicked/logging.h>
#include <wicked/xml.h>
#include "netinfo_priv.h"
#include "appconfig.h"

#include "dhcp4/dhcp.h"
#include "dhcp4/protocol.h"


static unsigned int	ni_dhcp4_do_bits(unsigned int);
static const char *	__ni_dhcp4_print_doflags(unsigned int);

ni_dhcp4_device_t *	ni_dhcp4_active;

/*
 * Create and destroy dhcp4 device handles
 */
ni_dhcp4_device_t *
ni_dhcp4_device_new(const char *ifname, const ni_linkinfo_t *link)
{
	ni_dhcp4_device_t *dev, **pos;

	for (pos = &ni_dhcp4_active; (dev = *pos) != NULL; pos = &dev->next)
		;

	dev = calloc(1, sizeof(*dev));
	ni_string_dup(&dev->ifname, ifname);
	dev->users = 1;
	dev->listen_fd = -1;
	dev->link.ifindex = link->ifindex;

	if (ni_capture_devinfo_init(&dev->system, dev->ifname, link) < 0) {
		ni_error("%s: cannot set up %s for DHCP4", __func__, ifname);
		ni_dhcp4_device_put(dev);
		return NULL;
	}

	dev->start_time = time(NULL);
	dev->fsm.state = NI_DHCP4_STATE_INIT;

	/* append to end of list */
	*pos = dev;

	return dev;
}

ni_dhcp4_device_t *
ni_dhcp4_device_by_index(unsigned int ifindex)
{
	ni_dhcp4_device_t *dev;

	for (dev = ni_dhcp4_active; dev; dev = dev->next) {
		if (dev->system.ifindex == ifindex)
			return dev;
	}

	return NULL;
}

static void
ni_dhcp4_device_close(ni_dhcp4_device_t *dev)
{
	ni_capture_free(dev->capture);
	dev->capture = NULL;

	if (dev->listen_fd >= 0)
		close(dev->listen_fd);
	dev->listen_fd = -1;

	if (dev->fsm.timer) {
		ni_warn("%s: timer active for %s", __func__, dev->ifname);
		ni_timer_cancel(dev->fsm.timer);
		dev->fsm.timer = NULL;
	}

	ni_dhcp4_device_arp_close(dev);
}

void
ni_dhcp4_device_stop(ni_dhcp4_device_t *dev)
{
	ni_dhcp4_device_close(dev);

	/* Drop existing config and request */
	ni_dhcp4_device_set_config(dev, NULL);
	ni_dhcp4_device_set_request(dev, NULL);
}

void
ni_dhcp4_device_set_config(ni_dhcp4_device_t *dev, ni_dhcp4_config_t *config)
{
	free(dev->config);
	dev->config = config;
}

void
ni_dhcp4_device_set_request(ni_dhcp4_device_t *dev, ni_dhcp4_request_t *request)
{
	if (dev->request)
		ni_dhcp4_request_free(dev->request);
	dev->request = request;
}

void
ni_dhcp4_device_free(ni_dhcp4_device_t *dev)
{
	ni_dhcp4_device_t **pos;

	ni_assert(dev->users == 0);
	ni_debug_dhcp("%s: Deleting dhcp4 device with index %u",
			dev->ifname, dev->link.ifindex);

	ni_dhcp4_device_drop_buffer(dev);
	ni_dhcp4_device_drop_lease(dev);
	ni_dhcp4_device_drop_best_offer(dev);
	ni_dhcp4_device_close(dev);
	ni_string_free(&dev->system.ifname);
	ni_string_free(&dev->ifname);

	/* Drop existing config and request */
	ni_dhcp4_device_set_config(dev, NULL);
	ni_dhcp4_device_set_request(dev, NULL);

	for (pos = &ni_dhcp4_active; *pos; pos = &(*pos)->next) {
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
ni_dhcp4_device_t *
ni_dhcp4_device_get(ni_dhcp4_device_t *dev)
{
	ni_assert(dev->users);
	dev->users++;
	return dev;
}

void
ni_dhcp4_device_put(ni_dhcp4_device_t *dev)
{
	ni_assert(dev->users);
	if (--(dev->users) == 0)
		ni_dhcp4_device_free(dev);
}


unsigned int
ni_dhcp4_device_uptime(const ni_dhcp4_device_t *dev, unsigned int clamp)
{
	unsigned int uptime;

	uptime = time(NULL) - dev->start_time;
	return (uptime < clamp)? uptime : clamp;
}

void
ni_dhcp4_device_set_lease(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (dev->lease != lease) {
		if (dev->lease)
			ni_addrconf_lease_free(dev->lease);
		dev->lease = lease;
		if (dev->config && lease)
			lease->uuid = dev->config->uuid;
	}
}

void
ni_dhcp4_device_drop_lease(ni_dhcp4_device_t *dev)
{
	ni_addrconf_lease_t *lease;

	if ((lease = dev->lease) != NULL) {
		ni_addrconf_lease_free(lease);
		dev->lease = NULL;

		/* Go back to square one */
		dev->fsm.state = NI_DHCP4_STATE_INIT;
	}
}

void
ni_dhcp4_device_set_best_offer(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease,
							int weight)
{
	if (dev->best_offer.lease && dev->best_offer.lease != lease)
		ni_addrconf_lease_free(dev->best_offer.lease);
	dev->best_offer.lease = lease;
	dev->best_offer.weight = weight;
	if (dev->config && lease)
		lease->uuid = dev->config->uuid;
}

void
ni_dhcp4_device_drop_best_offer(ni_dhcp4_device_t *dev)
{
	dev->best_offer.weight = -1;
	if (dev->best_offer.lease)
		ni_addrconf_lease_free(dev->best_offer.lease);
	dev->best_offer.lease = NULL;
}

/*
 * Refresh the device mtu and MAC address info prior to taking any actions
 */
int
ni_dhcp4_device_refresh(ni_dhcp4_device_t *dev)
{
	ni_netconfig_t *nih = ni_global_state_handle(0);
	int rv;

	if ((rv = __ni_device_refresh_link_info(nih, &dev->link)) < 0) {
		ni_error("%s: cannot refresh interface: %s",
				__func__, ni_strerror(rv));
		return rv;
	}

	return ni_capture_devinfo_refresh(&dev->system, dev->ifname, &dev->link);
}

/*
 * Process a request to reconfigure the device (ie rebind a lease, or discover
 * a new lease).
 */
int
ni_dhcp4_acquire(ni_dhcp4_device_t *dev, const ni_dhcp4_request_t *info)
{
	ni_dhcp4_config_t *config;
	const char *classid;
	size_t len;
	int rv;

	if ((rv = ni_dhcp4_device_refresh(dev)) < 0)
		return rv;

	config = xcalloc(1, sizeof(*config));

	/* RFC 2131 4.1 suggests these values */
	config->capture_retry_timeout = NI_DHCP4_RESEND_TIMEOUT_INIT;
	config->capture_max_timeout = NI_DHCP4_RESEND_TIMEOUT_MAX;

	config->dry_run = info->dry_run;
	config->start_delay = info->start_delay;
	config->defer_timeout = info->start_delay;
	config->acquire_timeout = info->acquire_timeout;
	config->uuid = info->uuid;
	config->flags = info->flags;
	config->update = info->update;
	config->route_priority = info->route_priority;
	config->recover_lease = info->recover_lease;
	config->release_lease = info->release_lease;

	config->max_lease_time = ni_dhcp4_config_max_lease_time();
	if (config->max_lease_time == 0)
		config->max_lease_time = ~0U;
	if (info->lease_time && info->lease_time < config->max_lease_time)
		config->max_lease_time = info->lease_time;

	if ((len = ni_string_len(info->hostname)) > 0) {
		if (ni_check_domain_name(info->hostname, len, 0)) {
			strncpy(config->hostname, info->hostname, sizeof(config->hostname) - 1);
		} else {
			ni_debug_dhcp("Discarded request to use suspect hostname: '%s'",
				ni_print_suspect(info->hostname, len));
		}
	}

	if (info->clientid) {
		ni_dhcp4_parse_client_id(&config->client_id, dev->system.hwaddr.type,
					 info->clientid);
	} else {
		/* Set client ID from interface hwaddr */
		ni_dhcp4_set_client_id(&config->client_id, &dev->system.hwaddr);
	}

	if ((classid = info->vendor_class) == NULL)
		classid = ni_dhcp4_config_vendor_class();
	if (classid)
		strncpy(config->classid, classid, sizeof(config->classid) - 1);

	config->doflags = DHCP4_DO_DEFAULT;
	config->doflags |= ni_dhcp4_do_bits(info->update);

	if (ni_debug & NI_TRACE_DHCP) {
		ni_trace("Received request:");
		ni_trace("  acquire-timeout %u", config->acquire_timeout);
		ni_trace("  lease-time      %u", config->max_lease_time);
		ni_trace("  start-delay     %u", config->start_delay);
		ni_trace("  hostname        %s", config->hostname[0]? config->hostname : "<none>");
		ni_trace("  vendor-class    %s", config->classid[0]? config->classid : "<none>");
		ni_trace("  client-id       %s", ni_print_hex(config->client_id.data, config->client_id.len));
		ni_trace("  uuid            %s", ni_uuid_print(&config->uuid));
		ni_trace("  update-flags    %s", __ni_dhcp4_print_doflags(config->doflags));
		ni_trace("  recover_lease   %s", config->recover_lease ? "true" : "false");
		ni_trace("  release_lease   %s", config->release_lease ? "true" : "false");
	}

	ni_dhcp4_device_set_config(dev, config);

	if (!dev->lease)
		ni_dhcp4_recover_lease(dev);

	if (dev->lease) {
		if (config->client_id.len && !ni_opaque_eq(&config->client_id, &dev->lease->dhcp4.client_id)) {
			ni_debug_dhcp("%s: lease doesn't match request", dev->ifname);
			ni_dhcp4_device_drop_lease(dev);
			dev->notify = 1;
		} else {
			/* Lease may be good */
			dev->fsm.state = NI_DHCP4_STATE_REBOOT;
		}
	}

	ni_note("%s: Request to acquire DHCPv4 lease with UUID %s",
		dev->ifname, ni_uuid_print(&config->uuid));

	if (ni_dhcp4_device_start(dev) < 0)
		return -1;
	return 1;
}

/*
 * When the supplicant restarts, we reload the state from file, and check
 * for which devices we have existing requests.
 *
 * For now, we go through a full discover/request cycle. If this proves
 * a too coarse approach, we should probably store the current leases
 * in the state file as well, and just do a renew/rebind.
 */
void
ni_dhcp4_restart_leases(void)
{
	ni_dhcp4_device_t *dev;

	for (dev = ni_dhcp4_active; dev; dev = dev->next) {
		if (dev->request)
			ni_dhcp4_acquire(dev, dev->request);
	}
}

/*
 * Translate a bitmap of NI_ADDRCONF_UPDATE_* flags into a bitmap of
 * DHCP4_DO_* masks
 */
static unsigned int
ni_dhcp4_do_bits(unsigned int update_flags)
{
	static unsigned int	do_mask[32] = {
	[NI_ADDRCONF_UPDATE_DEFAULT_ROUTE]	= DHCP4_DO_GATEWAY,
	[NI_ADDRCONF_UPDATE_HOSTNAME]		= DHCP4_DO_HOSTNAME,
	[NI_ADDRCONF_UPDATE_DNS]		= DHCP4_DO_DNS,
	[NI_ADDRCONF_UPDATE_NIS]		= DHCP4_DO_NIS,
	[NI_ADDRCONF_UPDATE_NTP]		= DHCP4_DO_NTP,
	};
	unsigned int bit, result = 0;

	for (bit = 0; bit < 32; ++bit) {
		if (update_flags & (1 << bit))
			result |= do_mask[bit];
	}
	return result;
}

static const char *
__ni_dhcp4_print_doflags(unsigned int flags)
{
	static ni_intmap_t flag_names[] = {
	{ "arp",		DHCP4_DO_ARP		},
	{ "csr",		DHCP4_DO_CSR		},
	{ "mscsr",		DHCP4_DO_MSCSR		},
	{ "gateway",		DHCP4_DO_GATEWAY	},
	{ "hostname",		DHCP4_DO_HOSTNAME	},
	{ "dns",		DHCP4_DO_DNS		},
	{ "nis",		DHCP4_DO_NIS		},
	{ "ntp",		DHCP4_DO_NTP		},
	{ NULL }
	};
	static char buffer[1024];
	char *pos = buffer;
	unsigned int mask;

	*pos = '\0';
	for (mask = 1; mask != 0; mask <<= 1) {
		const char *name;

		if ((flags & mask) == 0)
			continue;
		if (!(name = ni_format_uint_mapped(mask, flag_names)))
			continue;
		snprintf(pos, buffer + sizeof(buffer) - pos, "%s%s",
				(pos == buffer)? "" : ", ",
				name);
		pos += strlen(pos);
	}
	if (buffer[0] == '\0')
		return "<none>";

	return buffer;
}

/*
 * Process a request to unconfigure the device (ie drop the lease).
 */
int
ni_dhcp4_release(ni_dhcp4_device_t *dev, const ni_uuid_t *lease_uuid)
{
	char *rel_uuid = NULL;
	char *our_uuid = NULL;

	if (dev->lease == NULL) {
		ni_error("%s: no lease set", dev->ifname);
		return -NI_ERROR_ADDRCONF_NO_LEASE;
	}

	ni_string_dup(&rel_uuid, ni_uuid_print(lease_uuid));
	ni_string_dup(&our_uuid, ni_uuid_print(&dev->lease->uuid));
	if (lease_uuid && !ni_uuid_equal(lease_uuid, &dev->lease->uuid)) {
		ni_warn("%s: lease UUID %s to release does not match current lease UUID %s",
			dev->ifname, rel_uuid, our_uuid);
		ni_string_free(&rel_uuid);
		ni_string_free(&our_uuid);
		return -NI_ERROR_ADDRCONF_NO_LEASE;
	}
	ni_string_free(&our_uuid);

	ni_note("%s: Request to release DHCPv4 lease%s%s",  dev->ifname,
		rel_uuid ? " with UUID " : "", rel_uuid ? rel_uuid : "");
	ni_string_free(&rel_uuid);

	/* We just send out a singe RELEASE without waiting for the
	 * server's reply. We just keep our fingers crossed that it's
	 * getting out. If it doesn't, it's rather likely the network
	 * is hosed anyway, so there's little point in delaying. */
	ni_dhcp4_fsm_release(dev);

	ni_dhcp4_device_stop(dev);
	return 0;
}

/*
 * Handle link up/down events
 */
void
ni_dhcp4_device_event(ni_dhcp4_device_t *dev, ni_netdev_t *ifp, ni_event_t event)
{
	switch (event) {
	case NI_EVENT_DEVICE_UP:
		if (!ni_string_eq(dev->ifname, ifp->name)) {
			ni_debug_dhcp("%s: Updating interface name to %s",
					dev->ifname, ifp->name);
			ni_string_dup(&dev->ifname, ifp->name);
		}
		/* Does return -1 on failure. */
		ni_dhcp4_device_refresh(dev);
		break;

	case NI_EVENT_LINK_DOWN:
		ni_debug_dhcp("%s: link went down", dev->ifname);
		ni_dhcp4_fsm_link_down(dev);
		break;

	case NI_EVENT_LINK_UP:
		ni_debug_dhcp("%s: link came up", dev->ifname);
		ni_dhcp4_fsm_link_up(dev);
		break;

	default: ;
	}
}

int
ni_dhcp4_device_start(ni_dhcp4_device_t *dev)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;

	ni_dhcp4_device_drop_buffer(dev);
	dev->failed = 0;

	nc = ni_global_state_handle(0);
	if(!nc || !(ifp = ni_netdev_by_index(nc, dev->link.ifindex))) {
		ni_error("%s: unable to start device", dev->ifname);
		return -1;
	}

	if (ni_netdev_link_is_up(ifp)) {
		ni_dhcp4_fsm_link_up(dev);
		return 0;
	} else {
		ni_debug_dhcp("%s: defered start until link is up",
				dev->ifname);
	}
	return 1;
}

void
ni_dhcp4_device_alloc_buffer(ni_dhcp4_device_t *dev)
{
	unsigned int mtu = 0;

	mtu = dev->system.mtu;
	if (mtu == 0)
		mtu = MTU_MAX;

	if (dev->message.size == mtu) {
		ni_buffer_clear(&dev->message);
	} else {
		ni_dhcp4_device_drop_buffer(dev);
		ni_buffer_init_dynamic(&dev->message, mtu);
	}
}

void
ni_dhcp4_device_drop_buffer(ni_dhcp4_device_t *dev)
{
	ni_buffer_destroy(&dev->message);
}

static int
ni_dhcp4_device_prepare_message(void *data)
{
	ni_dhcp4_device_t *dev = data;

	/* Allocate an empty buffer */
	ni_dhcp4_device_alloc_buffer(dev);

	/* Build the DHCP4 message */
	if (ni_dhcp4_build_message(dev, dev->transmit.msg_code, dev->transmit.lease, &dev->message) < 0) {
		/* This is really terminal */
		ni_error("unable to build DHCP4 message");
		return -1;
	}
	return 0;
}

int
ni_dhcp4_device_send_message(ni_dhcp4_device_t *dev, unsigned int msg_code, const ni_addrconf_lease_t *lease)
{
	ni_buffer_t *buf = &dev->message;
	static uint32_t ni_dhcp4_xid;
	ni_timeout_param_t timeout;
	int rv;

	/* Assign a new XID to this message */
	if (ni_dhcp4_xid == 0)
		ni_dhcp4_xid = random();
	dev->dhcp4.xid = ni_dhcp4_xid++;

	dev->transmit.msg_code = msg_code;
	dev->transmit.lease = lease;

	if (ni_dhcp4_socket_open(dev) < 0) {
		ni_error("unable to open capture socket");
		goto transient_failure;
	}

	ni_debug_dhcp("sending %s with xid 0x%x", ni_dhcp4_message_name(msg_code), htonl(dev->dhcp4.xid));

	if ((rv = ni_dhcp4_device_prepare_message(dev)) < 0)
		return -1;

	switch (msg_code) {
	case DHCP4_DECLINE:
	case DHCP4_RELEASE:
		rv = ni_capture_send(dev->capture, buf, NULL);
		break;

	case DHCP4_DISCOVER:
	case DHCP4_REQUEST:
	case DHCP4_INFORM:
		memset(&timeout, 0, sizeof(timeout));
		timeout.timeout = dev->config->capture_retry_timeout;
		timeout.increment = -1;
		timeout.max_timeout = dev->config->capture_timeout;
		timeout.nretries = -1;
		timeout.jitter.min = -1;/* add a random jitter of +/-1 sec */
		timeout.jitter.max = 1;
		timeout.timeout_callback = ni_dhcp4_device_prepare_message;
		timeout.timeout_data = dev;

		if (dev->fsm.state == NI_DHCP4_STATE_RENEWING) {
			struct sockaddr_in sin = {
				.sin_family = AF_INET,
				.sin_addr.s_addr = lease->dhcp4.server_id.s_addr,
				.sin_port = htons(DHCP4_SERVER_PORT),
			};
			rv = sendto(dev->listen_fd, ni_buffer_head(buf), ni_buffer_count(buf), 0, (struct sockaddr *)&sin, sizeof(sin));
		} else
			rv = ni_capture_send(dev->capture, buf, &timeout);
		break;

	default:
		ni_warn("not sure whether I should retransmit %s message",
				ni_dhcp4_message_name(msg_code));
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

int
ni_dhcp4_device_send_message_unicast(ni_dhcp4_device_t *dev, unsigned int msg_code, const ni_addrconf_lease_t *lease)
{
	/* FIXME: not implemented yet. We'd need to record the
	 * server's hwaddr for this and reuse it here.
	 * So fall back to broadcast.
	 */
	return ni_dhcp4_device_send_message(dev, msg_code, lease);
}

void
ni_dhcp4_device_disarm_retransmit(ni_dhcp4_device_t *dev)
{
	/* Clear retransmit timer */
	if (dev->capture)
		ni_capture_disarm_retransmit(dev->capture);

	/* Drop the message buffer */
	ni_dhcp4_device_drop_buffer(dev);
}

void
ni_dhcp4_device_force_retransmit(ni_dhcp4_device_t *dev, unsigned int delay)
{
	if (dev->capture)
		ni_capture_force_retransmit(dev->capture, delay);
}

void
ni_dhcp4_device_arp_close(ni_dhcp4_device_t *dev)
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
ni_dhcp4_parse_client_id(ni_opaque_t *raw, unsigned short arp_type, const char *cooked)
{
	ni_hwaddr_t hwaddr;

	/* Check if it's a hardware address */
	if (ni_link_address_parse(&hwaddr, arp_type, cooked) == 0) {
		ni_dhcp4_set_client_id(raw, &hwaddr);
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
ni_dhcp4_set_client_id(ni_opaque_t *raw, const ni_hwaddr_t *hwa)
{
	if ((size_t)hwa->len + 1 > sizeof(raw->data))
		ni_fatal("%s: not enough room for MAC address", __FUNCTION__);
	raw->data[0] = hwa->type;
	memcpy(raw->data + 1, hwa->data, hwa->len);
	raw->len = hwa->len + 1;
}

/*
 * Functions for accessing various global DHCP4 configuration options
 */
const char *
ni_dhcp4_config_vendor_class(void)
{
	const struct ni_config_dhcp4 *dhconf = &ni_global.config->addrconf.dhcp4;

	return dhconf->vendor_class;
}

int
ni_dhcp4_config_ignore_server(struct in_addr addr)
{
	const struct ni_config_dhcp4 *dhconf = &ni_global.config->addrconf.dhcp4;
	const char *name = inet_ntoa(addr);

	return (ni_string_array_index(&dhconf->ignore_servers, name) >= 0);
}

int
ni_dhcp4_config_have_server_preference(void)
{
	const struct ni_config_dhcp4 *dhconf = &ni_global.config->addrconf.dhcp4;
	return dhconf->num_preferred_servers != 0;
}

int
ni_dhcp4_config_server_preference(struct in_addr addr)
{
	const struct ni_config_dhcp4 *dhconf = &ni_global.config->addrconf.dhcp4;
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
ni_dhcp4_config_max_lease_time(void)
{
	return ni_global.config->addrconf.dhcp4.lease_time;
}
