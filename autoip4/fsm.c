/*
 * An IPv4LL RFC 3927 supplicant for wicked
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/route.h>
#include <wicked/logging.h>
#include "autoip.h"

/* The IPv4LL address range is 169.254.1.0 to 169.254.254.255 inclusive */
#define IPV4LL_ADDRESS_FIRST		0xA9FE0100
#define IPV4LL_ADDRESS_LAST		0xA9FEFEFF
#define IPV4LL_ADDRESS_RANGE		(IPV4LL_ADDRESS_LAST - IPV4LL_ADDRESS_FIRST + 1)

/* How long we wait before we send out the first probe */
#define IPV4LL_PROBE_DELAY_MIN		0
#define IPV4LL_PROBE_DELAY_MAX		1000

#define IPV4LL_ANNOUNCE_COUNT		0	/* do not announce -- we deliver the lease
						   to wickedd and the announce will take place
						   there. */
#define IPV4LL_MAX_CONFLICTS		10
#define IPV4LL_RATE_LIMIT_INTERVAL	60000
#define IPV4LL_DEFEND_INTERVAL		10000

static ni_autoip_event_handler_t *	ni_autoip_fsm_event_handler;

extern int	ni_autoip_device_get_address(ni_autoip_device_t *, struct in_addr *);
static int	ni_autoip_send_arp(ni_autoip_device_t *);
static void	ni_autoip_fsm_set_timeout(ni_autoip_device_t *, ni_timeout_t, ni_timeout_t);
static void	__ni_autoip_fsm_timeout(void *, const ni_timer_t *);


void
ni_autoip_set_event_handler(ni_autoip_event_handler_t func)
{
	ni_autoip_fsm_event_handler = func;
}

void
ni_autoip_send_event(enum ni_lease_event ev, const ni_autoip_device_t *dev,
			ni_addrconf_lease_t *lease)
{
	if (ni_autoip_fsm_event_handler)
		ni_autoip_fsm_event_handler(ev, dev, lease);
}

int
ni_autoip_fsm_select(ni_autoip_device_t *dev)
{
	ni_address_t *ap;
	const ni_config_arp_t *arpcfg;

	/*
	 * RFC 3927, Section 2.1:
	 * Hosts that are equipped with persistent storage MAY, for each
	 * interface, record the IPv4 address they have selected.  On booting,
	 * hosts with a previously recorded address SHOULD use that address as
	 * their first candidate when probing.
	 */
	if (dev->fsm.state == NI_AUTOIP_STATE_CLAIMED && dev->autoip.candidate.s_addr != 0) {
		ni_debug_autoip("%s: trying to reclaim %s",
					dev->ifname, inet_ntoa(dev->autoip.candidate));
	} else if (dev->lease && (ap = dev->lease->addrs) &&
			ni_sockaddr_is_ipv4_linklocal(&ap->local_addr) &&
			dev->autoip.candidate.s_addr == 0) {
		dev->autoip.candidate = dev->lease->addrs->local_addr.sin.sin_addr;
		ni_debug_autoip("%s: trying to reuse our previous address %s",
				dev->ifname, inet_ntoa(dev->autoip.candidate));
	} else {
		dev->autoip.candidate.s_addr = htonl(IPV4LL_ADDRESS_FIRST + (random() % IPV4LL_ADDRESS_RANGE));
#if 0
		if (dev->autoip.nconflicts == 0) {
			ni_trace("DEBUG CODE ACTIVE");
			inet_aton("169.254.102.187", &dev->autoip.candidate);
		}
#endif
		ni_debug_autoip("%s: selected new candidate address %s",
				dev->ifname, inet_ntoa(dev->autoip.candidate));
	}

	arpcfg = ni_config_addrconf_arp(NI_ADDRCONF_AUTOCONF, dev->ifname);
	ni_arp_verify_reset(&dev->autoip.verify, &arpcfg->verify);

	if (!ni_arp_verify_add_in_addr(&dev->autoip.verify, dev->autoip.candidate)) {
		ni_warn("%s: unable to add IP address %s to arp verify",
				dev->ifname, inet_ntoa(dev->autoip.candidate));
		ni_autoip_fsm_set_timeout(dev, IPV4LL_PROBE_DELAY_MIN, IPV4LL_PROBE_DELAY_MAX);
		return 0;
	}

	dev->fsm.state = NI_AUTOIP_STATE_CLAIMING;
	/*
	 * RFC 3927, Section 2.2.1:
	 * When ready to begin probing, the host should then wait for a random
	 * time interval selected uniformly in the range zero to PROBE_WAIT
	 * seconds [...]
	 *
	 * [...] if the number of conflicts exceeds MAX_CONFLICTS then the host
	 * MUST limit the rate at which it probes for new addresses to no more
	 * than one new address per RATE_LIMIT_INTERVAL.
	 */
	if (dev->autoip.nconflicts > IPV4LL_MAX_CONFLICTS)
		ni_autoip_fsm_set_timeout(dev, IPV4LL_RATE_LIMIT_INTERVAL, IPV4LL_RATE_LIMIT_INTERVAL);
	else
		ni_autoip_fsm_set_timeout(dev, IPV4LL_PROBE_DELAY_MIN, IPV4LL_PROBE_DELAY_MAX);
	return 0;
}

void
ni_autoip_fsm_conflict(ni_autoip_device_t *dev)
{
	ni_autoip_device_drop_lease(dev);
	dev->autoip.nconflicts++;
	ni_autoip_fsm_select(dev);
}

/*
 * (b) If a host currently has active TCP connections or other reasons
 * to prefer to keep the same IPv4 address, and it has not seen any
 * other conflicting ARP packets within the last DEFEND_INTERVAL
 * seconds, then it MAY elect to attempt to defend its address by
 * recording the time that the conflicting ARP packet was received, and
 * then broadcasting one single ARP announcement, giving its own IP and
 * hardware addresses as the sender addresses of the ARP.  Having done
 * this, the host can then continue to use the address normally without
 * any further special action.  However, if this is not the first
 * conflicting ARP packet the host has seen, and the time recorded for
 * the previous conflicting ARP packet is recent, within DEFEND_INTERVAL
 * seconds, then the host MUST immediately cease using this address and
 * configure a new IPv4 Link-Local address as described above.  This is
 * necessary to ensure that two hosts do not get stuck in an endless
 * loop with both hosts trying to defend the same address.
 */
void
ni_autoip_fsm_defend(ni_autoip_device_t *dev, const ni_hwaddr_t *hwa)
{
	struct timeval now, delta;

	if (dev->fsm.state != NI_AUTOIP_STATE_CLAIMED) {
		ni_error("%s: shouldn't be called in state %s", __FUNCTION__,
				ni_autoip_fsm_state_name(dev->fsm.state));
		return;
	}

	ni_timer_get_time(&now);
	if (timerisset(&dev->autoip.last_defense) && timercmp(&now, &dev->autoip.last_defense, >)) {
		timersub(&now, &dev->autoip.last_defense, &delta);
		if (delta.tv_sec < IPV4LL_DEFEND_INTERVAL) {
			ni_debug_autoip("%s: failed to defend address %s (claimed by %s)", dev->ifname,
					inet_ntoa(dev->autoip.candidate),
					ni_link_address_print(hwa));
			ni_autoip_fsm_conflict(dev);
			return;
		}
	}

	dev->autoip.last_defense = now;
	ni_arp_send_reply(dev->arp_socket,
			dev->autoip.candidate,
			hwa, dev->autoip.candidate);
}

ni_addrconf_lease_t *
ni_autoip_fsm_build_lease(ni_autoip_device_t *dev)
{
	ni_addrconf_lease_t *lease;
	ni_sockaddr_t addr;

	ni_debug_autoip("%s: building lease", dev->ifname);
	lease = ni_addrconf_lease_new(NI_ADDRCONF_AUTOCONF, AF_INET);

	memset(&addr, 0, sizeof(addr));
	addr.sin.sin_family = AF_INET;
	addr.sin.sin_addr = dev->autoip.candidate;
	ni_address_create(AF_INET, 16, &addr, &lease->addrs);

	ni_sockaddr_parse(&addr, "169.254.0.0", AF_INET);
	ni_route_create(16, &addr, NULL, 0, &lease->routes);

	lease->state = NI_ADDRCONF_STATE_GRANTED;
	ni_timer_get_time(&lease->acquired);
	lease->uuid = dev->request.uuid;
	lease->flags = dev->request.flags;

	return lease;
}

static int
ni_autoip_fsm_commit_lease(ni_autoip_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (lease) {
		ni_debug_autoip("%s: committing lease", dev->ifname);
		ni_autoip_device_set_lease(dev, lease);

		/* Write the lease to lease cache */
		ni_addrconf_lease_file_write(dev->ifname, lease);

		/* Inform the master about the newly acquired lease */
		ni_autoip_send_event(NI_EVENT_LEASE_ACQUIRED, dev, lease);
	} else {
		ni_debug_autoip("%s: dropping lease", dev->ifname);
		if ((lease = dev->lease) != NULL) {
			lease->state = NI_ADDRCONF_STATE_RELEASED;
			lease->uuid =  dev->request.uuid;
			ni_autoip_send_event(NI_EVENT_LEASE_RELEASED, dev, lease);
		}
		ni_autoip_device_drop_lease(dev);
	}
	return 0;
}

void
ni_autoip_fsm_release(ni_autoip_device_t *dev)
{
	ni_autoip_fsm_commit_lease(dev, NULL);
}

static void
ni_autoip_fsm_process_arp(ni_arp_socket_t *sock, const ni_arp_packet_t *pkt, void *user_data)
{
	ni_autoip_device_t *dev = (ni_autoip_device_t *) user_data;
	ni_arp_address_t *vap;
	ni_stringbuf_t sb = NI_STRINGBUF_INIT_DYNAMIC;

	if (!(vap = ni_arp_reply_match_address(sock, &dev->autoip.verify.ipaddrs, pkt)))
		return;

	switch (dev->fsm.state) {
	case NI_AUTOIP_STATE_CLAIMING:
		ni_debug_autoip("%s: autoip4 address conflict %s", dev->ifname,
				ni_address_print(&sb, vap->address));
		ni_autoip_fsm_conflict(dev);
		break;

	case NI_AUTOIP_STATE_CLAIMED:
		ni_debug_autoip("%s: autoip4 defend address %s (claimed by %s)",
				dev->ifname, ni_address_print(&sb, vap->address),
				ni_link_address_print(&pkt->sha));
		ni_autoip_fsm_defend(dev, &pkt->sha);
		break;

	default:
		/* ignore */;
	}
}

int
ni_autoip_send_arp(ni_autoip_device_t *dev)
{
	ni_timeout_t timeout;

	if (dev->arp_socket == NULL) {
		dev->arp_socket = ni_arp_socket_open(&dev->devinfo,
				ni_autoip_fsm_process_arp, dev);
		if (dev->arp_socket == NULL)
			return -1;
	}

	switch (ni_arp_verify_send(dev->arp_socket, &dev->autoip.verify, &timeout)) {
	case NI_ARP_SEND_PROGRESS:
		ni_autoip_fsm_set_timeout(dev, timeout, timeout);
		return 0;
	case NI_ARP_SEND_FAILURE:
		ni_autoip_fsm_conflict(dev);
		return -1;
	case NI_ARP_SEND_COMPLETE:
	default:
		dev->fsm.state = NI_AUTOIP_STATE_CLAIMED;
		ni_autoip_fsm_commit_lease(dev, ni_autoip_fsm_build_lease(dev));
		dev->autoip.nconflicts = 0;
		timerclear(&dev->autoip.last_defense);
		return 0;
	}
}

void
ni_autoip_fsm_set_timeout(ni_autoip_device_t *dev, ni_timeout_t wait_min, ni_timeout_t wait_max)
{
	if (wait_max != 0) {
		ni_timeout_t wait = ni_timeout_random_range(wait_min, wait_max);

		ni_debug_autoip("%s: setting timeout to %llu ms", dev->ifname, wait);
		if (dev->fsm.timer)
			ni_timer_rearm(dev->fsm.timer, wait);
		else
			dev->fsm.timer = ni_timer_register(wait, __ni_autoip_fsm_timeout, dev);
	}
}

/*
 * Timeout handling
 */
static void
__ni_autoip_fsm_timeout(void *handle, const ni_timer_t *timer)
{
	ni_autoip_device_t *dev = handle;

	if (dev->fsm.timer != timer) {
		ni_warn("%s: stale timer for %s", __func__, dev->ifname);
		return;
	}
	dev->fsm.timer = NULL;

	switch (dev->fsm.state) {
	case NI_AUTOIP_STATE_INIT:
		ni_autoip_fsm_select(dev);
		break;

	case NI_AUTOIP_STATE_CLAIMING:
		ni_autoip_send_arp(dev);
		return;

	default:
		ni_error("%s: unexpected state", __FUNCTION__);
	}
}

const char *
ni_autoip_fsm_state_name(ni_autoip_state_t state)
{
	switch (state) {
	case NI_AUTOIP_STATE_INIT:
		return "INIT";
	case NI_AUTOIP_STATE_CLAIMING:
		return "CLAIMING";
	case NI_AUTOIP_STATE_CLAIMED:
		return "CLAIMED";
	}

	return "UNKNOWN";
}
