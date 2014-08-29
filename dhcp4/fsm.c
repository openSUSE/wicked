/*
 * DHCP4 client for wicked - finite state machine.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/route.h>
#include <netlink/netlink.h>
#include "netinfo_priv.h"
#include "buffer.h"

#include "dhcp4/dhcp.h"
#include "dhcp4/protocol.h"


#define NAK_BACKOFF_MAX		60	/* seconds */

static int		ni_dhcp4_fsm_arp_validate(ni_dhcp4_device_t *);
static const char *	ni_dhcp4_fsm_state_name(int);

static int		ni_dhcp4_process_offer(ni_dhcp4_device_t *, ni_addrconf_lease_t *);
static int		ni_dhcp4_process_ack(ni_dhcp4_device_t *, ni_addrconf_lease_t *);
static int		ni_dhcp4_process_nak(ni_dhcp4_device_t *);
static void		ni_dhcp4_fsm_process_arp_packet(ni_arp_socket_t *, const ni_arp_packet_t *, void *);
static void		ni_dhcp4_fsm_fail_lease(ni_dhcp4_device_t *);
static int		ni_dhcp4_fsm_validate_lease(ni_dhcp4_device_t *, ni_addrconf_lease_t *);
static void		ni_dhcp4_send_event(enum ni_dhcp4_event, ni_dhcp4_device_t *, ni_addrconf_lease_t *);
static void		__ni_dhcp4_fsm_timeout(void *, const ni_timer_t *);

static ni_dhcp4_event_handler_t *ni_dhcp4_fsm_event_handler;

int
ni_dhcp4_fsm_process_dhcp4_packet(ni_dhcp4_device_t *dev, ni_buffer_t *msgbuf)
{
	ni_dhcp4_message_t *message;
	ni_addrconf_lease_t *lease = NULL;
	int msg_code;

	if (dev->fsm.state == NI_DHCP4_STATE_VALIDATING) {
		/* We arrive here, when some dhcp4 packet arrives after
		 * we've got and processed an ACK already. Just ignore.
		 */
		ni_debug_dhcp("%s: ignoring dhcp4 packet arrived in state VALIDATING",
				dev->ifname);
		return -1;
	}

	if (!(message = ni_buffer_pull_head(msgbuf, sizeof(*message)))) {
		ni_debug_dhcp("short DHCP4 packet (%u bytes)", ni_buffer_count(msgbuf));
		return -1;
	}
	if (dev->dhcp4.xid == 0) {
		ni_debug_dhcp("unexpected packet on %s", dev->ifname);
		return -1;
	}
	if (dev->dhcp4.xid != message->xid) {
		ni_debug_dhcp("ignoring packet with wrong xid 0x%x (expected 0x%x)",
				htonl(message->xid), htonl(dev->dhcp4.xid));
		return -1;
	}

	msg_code = ni_dhcp4_parse_response(message, msgbuf, &lease);
	if (msg_code < 0) {
		/* Ignore this message, time out later */
		ni_error("unable to parse DHCP4 response");
		return -1;
	}

	/* set reqest client-id in the response early to have it in test mode */
	ni_opaque_set(&lease->dhcp4.client_id,	dev->config->client_id.data,
						dev->config->client_id.len);

	ni_debug_dhcp("%s: received %s message in state %s",
			dev->ifname, ni_dhcp4_message_name(msg_code),
			ni_dhcp4_fsm_state_name(dev->fsm.state));

	/* When receiving a DHCP4 OFFER, verify sender address against list of
	 * servers to ignore, and preferred servers. */
	if (msg_code == DHCP4_OFFER && dev->fsm.state == NI_DHCP4_STATE_SELECTING) {
		struct in_addr srv_addr = lease->dhcp4.server_id;
		int weight = 0;

		if (ni_dhcp4_config_ignore_server(srv_addr)) {
			ni_debug_dhcp("%s: ignoring DHCP4 offer from %s",
					dev->ifname, inet_ntoa(srv_addr));
			goto out;
		}

		/* If we're scanning all offers, we need to decide whether
		 * this offer is accepted, or whether we want to wait for
		 * more.
		 */
		if (!dev->dhcp4.accept_any_offer) {

			/* Check if we have any preferred servers. */
			weight = ni_dhcp4_config_server_preference(srv_addr);

			/* If we're refreshing an existing lease (eg after link disconnect
			 * and reconnect), we accept the offer if it comes from the same
			 * server as the original one.
			 */
			if (dev->lease
			 && dev->lease->dhcp4.server_id.s_addr == srv_addr.s_addr)
				weight = 100;

			ni_debug_dhcp("received lease offer from %s; server weight=%d (best offer=%d)",
					inet_ntoa(lease->dhcp4.server_id), weight,
					dev->best_offer.weight);

			/* negative weight means never. */
			if (weight < 0)
				goto out;

			/* weight between 0 and 100 means maybe. */
			if (weight < 100) {
				if (dev->best_offer.weight < weight) {
					ni_dhcp4_device_set_best_offer(dev, lease, weight);
					return 0;
				}
				goto out;
			}
			/* If the weight has maximum value, just accept this offer. */
		}
		ni_dhcp4_device_set_best_offer(dev, lease, weight);
		lease = NULL;
	}

	/* We've received a valid response; if something goes wrong now
	 * it's nothing that could be fixed by retransmitting the message.
	 *
	 * The only exception would be if we ever do some filtering or
	 * matching of OFFERs - then we would certainly want to keep
	 * waiting for additional packets.
	 */
	ni_dhcp4_device_disarm_retransmit(dev);
	dev->dhcp4.xid = 0;

	/* move to next stage of protocol */
	switch (msg_code) {
	case DHCP4_OFFER:
		if (dev->fsm.state != NI_DHCP4_STATE_SELECTING)
			goto ignore;

		/* process best offer set above */
		ni_dhcp4_process_offer(dev, dev->best_offer.lease);
		break;

	case DHCP4_ACK:
		if (dev->fsm.state == NI_DHCP4_STATE_INIT) {
			/*
			 * Received a decline ACK -- wait until
			 * timeout before we restart from begin
			 */
			ni_dhcp4_device_drop_lease(dev);
			break;
		}

		if (dev->fsm.state != NI_DHCP4_STATE_REQUESTING
		 && dev->fsm.state != NI_DHCP4_STATE_RENEWING
		 && dev->fsm.state != NI_DHCP4_STATE_REBOOT
		 && dev->fsm.state != NI_DHCP4_STATE_REBINDING)
			goto ignore;

		ni_dhcp4_process_ack(dev, lease);
		lease = NULL;
		break;

	case DHCP4_NAK:
		/* The RFC 2131 state diagram says, ignore NAKs in state BOUND.
		 * I guess we also have no use for NAK replies to a DHCP4_DISCOVER
		 */
		if (dev->fsm.state == NI_DHCP4_STATE_SELECTING
		 || dev->fsm.state == NI_DHCP4_STATE_BOUND)
			goto ignore;

		ni_dhcp4_process_nak(dev);
		break;

	default:
	ignore:
		ni_debug_dhcp("ignoring %s in state %s",
				ni_dhcp4_message_name(msg_code),
				ni_dhcp4_fsm_state_name(dev->fsm.state));
		break;
	}

out:
	if (lease && dev->lease != lease)
		ni_addrconf_lease_free(lease);

	/* If we received a message other than NAK, reset the NAK
	 * backoff timer. */
	if (msg_code != DHCP4_NAK)
		dev->dhcp4.nak_backoff = 1;

	return 0;
}

static void
ni_dhcp4_fsm_restart(ni_dhcp4_device_t *dev)
{
	dev->fsm.state = NI_DHCP4_STATE_INIT;

	ni_dhcp4_device_disarm_retransmit(dev);
	if (dev->fsm.timer) {
		ni_timer_cancel(dev->fsm.timer);
		dev->fsm.timer = NULL;
	}
	dev->dhcp4.xid = 0;
	dev->config->elapsed_timeout = 0;

	ni_dhcp4_device_drop_lease(dev);
}

static void
ni_dhcp4_fsm_set_timeout_msec(ni_dhcp4_device_t *dev, unsigned int msec)
{
	if (msec != 0) {
		ni_debug_dhcp("%s: setting fsm timeout to %u msec", dev->ifname, msec);
		if (dev->fsm.timer)
			ni_timer_rearm(dev->fsm.timer, msec);
		else
			dev->fsm.timer = ni_timer_register(msec, __ni_dhcp4_fsm_timeout, dev);
	}
}

static void
ni_dhcp4_fsm_set_timeout(ni_dhcp4_device_t *dev, unsigned int seconds)
{
	ni_dhcp4_fsm_set_timeout_msec(dev, 1000 * seconds);
}

void
ni_dhcp4_fsm_set_deadline(ni_dhcp4_device_t *dev, time_t deadline)
{
	time_t now = time(NULL);

	if (now < deadline)
		ni_dhcp4_fsm_set_timeout(dev, deadline - now);
	else
		ni_error("ni_dhcp4_fsm_set_deadline(%s): cannot go back in time", dev->ifname);
}

static void
__ni_dhcp4_fsm_discover(ni_dhcp4_device_t *dev, int scan_offers)
{
	ni_addrconf_lease_t *lease;

	if (dev->config->elapsed_timeout)
		ni_info("%s: Reinitiating DHCPv4 discovery (ifindex %d)", dev->ifname, dev->link.ifindex);
	else
		ni_info("%s: Initiating DHCPv4 discovery (ifindex %d)", dev->ifname, dev->link.ifindex);

	/* If we already have a lease, try asking for the same.
	 * If not, create a dummy lease with NULL fields.
	 * Note: if DISCOVER for the old lease times out,
	 * we should fall back to asking for anything.
	 */
	if ((lease = dev->lease) == NULL)
		lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET);
	lease->uuid = dev->config->uuid;

	dev->fsm.state = NI_DHCP4_STATE_SELECTING;
	dev->dhcp4.accept_any_offer = 1;

	ni_debug_dhcp("valid lease: %d; have prefs: %d",
			ni_addrconf_lease_is_valid(dev->lease),
			ni_dhcp4_config_have_server_preference());
	if (ni_addrconf_lease_is_valid(dev->lease)
	 || (scan_offers && ni_dhcp4_config_have_server_preference())) {
		dev->dhcp4.accept_any_offer = 0;
	}

	dev->config->capture_timeout = dev->config->capture_max_timeout;
	if (dev->config->acquire_timeout && dev->config->acquire_timeout - dev->config->elapsed_timeout < dev->config->capture_max_timeout)
		dev->config->capture_timeout = dev->config->acquire_timeout - dev->config->elapsed_timeout;
	ni_dhcp4_fsm_set_timeout(dev, dev->config->capture_timeout);

	ni_dhcp4_device_send_message(dev, DHCP4_DISCOVER, lease);

	ni_dhcp4_device_drop_best_offer(dev);

	if (lease != dev->lease)
		ni_addrconf_lease_free(lease);
}

static void
ni_dhcp4_fsm_discover(ni_dhcp4_device_t *dev)
{
	dev->start_time = time(NULL);
	dev->config->elapsed_timeout = 0;
	__ni_dhcp4_fsm_discover(dev, 1);
}

static void
ni_dhcp4_fsm_request(ni_dhcp4_device_t *dev, const ni_addrconf_lease_t *lease)
{
	dev->fsm.state = NI_DHCP4_STATE_REQUESTING;
	dev->config->capture_timeout = dev->config->capture_max_timeout;
	if (dev->config->acquire_timeout && dev->config->acquire_timeout - dev->config->elapsed_timeout < dev->config->capture_max_timeout)
		dev->config->capture_timeout = dev->config->acquire_timeout - dev->config->elapsed_timeout;
	ni_dhcp4_fsm_set_timeout(dev, dev->config->capture_timeout);

	ni_dhcp4_device_send_message(dev, DHCP4_REQUEST, lease);
}

static void
ni_dhcp4_fsm_renewal(ni_dhcp4_device_t *dev)
{
	ni_info("%s: Initiating renewal of DHCPv4 lease",
		dev->ifname);

	dev->start_time = time(NULL);
	dev->fsm.state = NI_DHCP4_STATE_RENEWING;
	ni_dhcp4_fsm_set_deadline(dev,
			dev->lease->time_acquired + dev->lease->dhcp4.rebind_time);
	ni_dhcp4_device_send_message_unicast(dev, DHCP4_REQUEST, dev->lease);
}

static void
ni_dhcp4_fsm_reboot(ni_dhcp4_device_t *dev)
{
	time_t now = time(NULL);
	time_t expire_time, deadline = now + 10;

	/* RFC 2131, 3.2 (see also 3.1) */
	ni_debug_dhcp("trying to confirm lease for %s", dev->ifname);

	dev->config->elapsed_timeout = 0;
	dev->start_time = time(NULL);
	dev->fsm.state = NI_DHCP4_STATE_REBOOT;

	expire_time = dev->lease->time_acquired + dev->lease->dhcp4.rebind_time;
	if (expire_time > now && deadline > expire_time)
		deadline = expire_time;
	dev->config->capture_timeout = deadline - now;

	ni_dhcp4_fsm_set_timeout(dev, dev->config->capture_timeout);
	ni_dhcp4_device_send_message(dev, DHCP4_REQUEST, dev->lease);
}

static void
ni_dhcp4_fsm_rebind(ni_dhcp4_device_t *dev)
{
	time_t expire_time, now = time(NULL);

	ni_info("%s: Initiating rebind of DHCPv4 lease",
		dev->ifname);

	dev->start_time = time(NULL);
	dev->fsm.state = NI_DHCP4_STATE_REBINDING;
	dev->lease->dhcp4.server_id.s_addr = 0;
	expire_time = dev->lease->time_acquired + dev->lease->dhcp4.lease_time;
	dev->config->capture_timeout = dev->config->capture_max_timeout;
	if (expire_time > now) {
		if (expire_time - now < dev->config->capture_max_timeout)
			dev->config->capture_timeout = expire_time - now;
		ni_dhcp4_fsm_set_deadline(dev, expire_time);
	} else
		ni_dhcp4_fsm_set_timeout(dev, dev->config->capture_timeout);
	ni_dhcp4_device_send_message(dev, DHCP4_REQUEST, dev->lease);
}

static void
ni_dhcp4_fsm_decline(ni_dhcp4_device_t *dev)
{
	ni_warn("%s: Declining DHCPv4 lease with address %s", dev->ifname,
		inet_ntoa(dev->lease->dhcp4.address));

	dev->start_time = time(NULL);
	dev->fsm.state = NI_DHCP4_STATE_INIT;
	ni_dhcp4_device_send_message(dev, DHCP4_DECLINE, dev->lease);

	/* FIXME: we should record the bad lease, and ignore it
	 * when the server offers it again. */

	/* RFC 2131 mandates we should wait for 10 seconds before
	 * retrying discovery. */
	ni_dhcp4_fsm_set_timeout(dev, 10);
}

void
ni_dhcp4_fsm_release(ni_dhcp4_device_t *dev)
{
	if (!dev->config) {
		ni_debug_dhcp("%s: not configured, dropping lease", dev->ifname);
		ni_dhcp4_fsm_commit_lease(dev, NULL);
	}

	ni_debug_dhcp("%s: releasing lease", dev->ifname);
	ni_dhcp4_device_send_message(dev, DHCP4_RELEASE, dev->lease);

	ni_dhcp4_fsm_commit_lease(dev, NULL);
}

/*
 * We never received any response. Deal with the traumatic rejection.
 */
static void
ni_dhcp4_fsm_timeout(ni_dhcp4_device_t *dev)
{
	ni_dhcp4_config_t *conf = dev->config;
	ni_debug_dhcp("%s: timeout in state %s",
			dev->ifname, ni_dhcp4_fsm_state_name(dev->fsm.state));
	dev->fsm.timer = NULL;

	conf->elapsed_timeout += conf->capture_timeout;

	switch (dev->fsm.state) {
	case NI_DHCP4_STATE_INIT:
		/* We get here if we previously received a NAK, and have
		 * started to back off, or if we declined a lease because
		 * the address was already in use. */
		ni_dhcp4_device_drop_lease(dev);
		ni_dhcp4_fsm_discover(dev);
		break;

	case NI_DHCP4_STATE_SELECTING:
		if (!dev->dhcp4.accept_any_offer) {

			/* We were scanning all offers to check for a best offer.
			 * There was no perfect match, but we may have a "good enough"
			 * match. Check for it. */
			if (dev->best_offer.lease) {
				ni_addrconf_lease_t *lease = dev->best_offer.lease;

				ni_debug_dhcp("accepting lease offer from %s; server weight=%d",
						inet_ntoa(lease->dhcp4.server_id),
						dev->best_offer.weight);
				ni_dhcp4_process_offer(dev, lease);
				return;
			}

			ni_dhcp4_fsm_fail_lease(dev);
			dev->start_time = time(NULL);
		}
		if (conf->acquire_timeout == 0) {
			ni_debug_dhcp("%s: discovery got no (valid) reply, retrying.", dev->ifname);
			__ni_dhcp4_fsm_discover(dev, 0);
			return;
		} else if (conf->elapsed_timeout < conf->acquire_timeout) {
			ni_debug_dhcp("%s: discovery got no (valid) reply, retrying. %u seconds left until timeout.",
					dev->ifname, conf->acquire_timeout - conf->elapsed_timeout);
			__ni_dhcp4_fsm_discover(dev, 0);
			return;
		}
		/* fallthrough */

	case NI_DHCP4_STATE_REQUESTING:
		if (conf->acquire_timeout && conf->elapsed_timeout < conf->acquire_timeout) {
			ni_debug_dhcp("%s: discovery got no (valid) reply, retrying. %u seconds left until timeout.",
					dev->ifname, conf->acquire_timeout - conf->elapsed_timeout);
			ni_dhcp4_fsm_request(dev, dev->transmit.lease);
			return;
		}
		ni_error("%s: DHCP4 discovery failed", dev->ifname);
		ni_dhcp4_fsm_fail_lease(dev);
		ni_dhcp4_fsm_restart(dev);

		ni_dhcp4_send_event(NI_DHCP4_EVENT_LOST, dev, NULL);

		/* Now decide whether we should keep trying */
		if (dev->config->acquire_timeout == 0)
			ni_dhcp4_fsm_discover(dev);
		break;

	case NI_DHCP4_STATE_VALIDATING:
		/* Send the next ARP probe */
		ni_dhcp4_fsm_arp_validate(dev);
		break;

	case NI_DHCP4_STATE_BOUND:
		ni_dhcp4_fsm_renewal(dev);
		break;

	case NI_DHCP4_STATE_RENEWING:
		ni_error("unable to renew lease within renewal period; trying to rebind");
		ni_dhcp4_fsm_rebind(dev);
		break;

	case NI_DHCP4_STATE_REBINDING:
		ni_error("unable to rebind lease");
		ni_dhcp4_fsm_restart(dev);
		ni_dhcp4_fsm_set_timeout(dev, 10);
		break;

	case NI_DHCP4_STATE_REBOOT:
		ni_error("unable to confirm lease");
		ni_dhcp4_fsm_commit_lease(dev, NULL);
		ni_dhcp4_fsm_set_timeout(dev, 10);
		break;

	default:
		;
	}
}

static void
__ni_dhcp4_fsm_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_dhcp4_device_t *dev = user_data;

	if (dev->fsm.timer != timer) {
		ni_warn("%s: bad timer handle", __func__);
		return;
	}

	ni_dhcp4_fsm_timeout(dev);
}

/*
 * These functions get called when the link goes down/up.
 * We use these to be smart about renewing a lease.
 */
void
ni_dhcp4_fsm_link_up(ni_dhcp4_device_t *dev)
{
	dev->start_time = time(NULL);

	if (dev->config == NULL)
		return;

	switch (dev->fsm.state) {
	case NI_DHCP4_STATE_INIT:
		/* We get here if we aborted a discovery operation. */
		ni_dhcp4_fsm_discover(dev);
		break;

	case NI_DHCP4_STATE_BOUND:
	case NI_DHCP4_STATE_REBOOT:
		/* The link went down and came back up. We may now be on a
		 * completely different network, and our lease may no longer
		 * be valid.
		 * Do a quick renewal, which means we'll try to renew the lease
		 * for 10 seconds. If that fails, we drop the lease and revert
		 * to state INIT.
		 */
		if (dev->lease)
			ni_dhcp4_fsm_reboot(dev);
		else
			ni_dhcp4_fsm_discover(dev);
		break;

	default:
		break;
	}
}

void
ni_dhcp4_fsm_link_down(ni_dhcp4_device_t *dev)
{
	if (dev->config == NULL)
		return;

	switch (dev->fsm.state) {
	case NI_DHCP4_STATE_INIT:
	case NI_DHCP4_STATE_SELECTING:
	case NI_DHCP4_STATE_REQUESTING:
	case NI_DHCP4_STATE_VALIDATING:
		ni_dhcp4_device_arp_close(dev);
		ni_dhcp4_device_drop_lease(dev);
		ni_dhcp4_fsm_restart(dev);
		break;

	default: ;
	}
}

static int
ni_dhcp4_process_offer(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	char abuf1[INET_ADDRSTRLEN];
	char abuf2[INET_ADDRSTRLEN];

	/* TBD: We should be smarter here.
	 *
	 *  -	track "bad" leases, and blacklist them for a while.
	 *	(eg addresses that fail the ARP check).
	 *
	 *  -	try to detect if we woke up in a different network
	 *	environment; in that case there's no point in attempting
	 *	to renew the same old lease forever. Some MS based DHCP
	 *	servers in airports and hotels never seem to send NAKs
	 *	in such as case.
	 */

	inet_ntop(AF_INET, &lease->dhcp4.address, abuf1, sizeof(abuf1));
	inet_ntop(AF_INET, &lease->dhcp4.server_id, abuf2, sizeof(abuf2));

	ni_info("%s: Received offer for %s from %s", dev->ifname, abuf1, abuf2);
	if (dev->config->dry_run == NI_DHCP4_RUN_OFFER) {
		ni_dhcp4_send_event(NI_DHCP4_EVENT_ACQUIRED, dev, lease);
		ni_dhcp4_fsm_restart(dev);
		ni_dhcp4_device_stop(dev);
	} else {
		ni_info("%s: Requesting DHCPv4 lease with timeout %u sec",
			dev->ifname, dev->config->acquire_timeout);
		dev->start_time = time(NULL);
		dev->config->elapsed_timeout = 0;
		ni_dhcp4_fsm_request(dev, lease);
	}
	return 0;
}

static int
ni_dhcp4_process_ack(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (lease->dhcp4.lease_time == 0) {
		lease->dhcp4.lease_time = DHCP4_DEFAULT_LEASETIME;
		ni_debug_dhcp("server supplied no lease time, assuming %u seconds",
				lease->dhcp4.lease_time);
	}

	if (lease->dhcp4.rebind_time >= lease->dhcp4.lease_time) {
		ni_debug_dhcp("%s: dhcp4.rebind_time greater than dhcp4.lease_time, using default", dev->ifname);
		lease->dhcp4.rebind_time = lease->dhcp4.lease_time * 7 / 8;
	} else if (lease->dhcp4.rebind_time == 0) {
		ni_debug_dhcp("%s: no dhcp4.rebind_time supplied, using default", dev->ifname);
		lease->dhcp4.rebind_time = lease->dhcp4.lease_time * 7 / 8;
	}

	if (lease->dhcp4.renewal_time >= lease->dhcp4.rebind_time) {
		ni_debug_dhcp("%s: dhcp4.renewal_time greater than dhcp4.rebind_time, using default", dev->ifname);
		lease->dhcp4.renewal_time = lease->dhcp4.lease_time / 2;
	} else if (lease->dhcp4.renewal_time == 0) {
		ni_debug_dhcp("%s: no dhcp4.renewal_time supplied, using default", dev->ifname);
		lease->dhcp4.renewal_time = lease->dhcp4.lease_time / 2;
	}

	if (lease->dhcp4.renewal_time > dev->config->max_lease_time) {
		ni_debug_dhcp("clamping lease time to %u sec", dev->config->max_lease_time);
		lease->dhcp4.renewal_time = dev->config->max_lease_time;
	}

	/* set lease to validate and commit or decline */
	ni_dhcp4_device_set_lease(dev, lease);

	if (dev->config->doflags & DHCP4_DO_ARP) {
		/*
		 * When we cannot init validate [arp], commit it.
		 */
		if (ni_dhcp4_fsm_validate_lease(dev, lease) < 0)
			ni_dhcp4_fsm_commit_lease(dev, lease);
	} else {
		ni_dhcp4_fsm_commit_lease(dev, lease);
	}

	return 0;
}

int
ni_dhcp4_fsm_commit_lease(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	ni_capture_free(dev->capture);
	dev->capture = NULL;

	if (lease) {
		ni_debug_dhcp("%s: committing lease", dev->ifname);
		if (dev->config->dry_run == NI_DHCP4_RUN_NORMAL) {
			ni_debug_dhcp("%s: schedule renewal of lease in %u seconds",
					dev->ifname, lease->dhcp4.renewal_time);
			ni_dhcp4_fsm_set_timeout(dev, lease->dhcp4.renewal_time);
		}

		/* If the user requested a specific route metric, apply it now */
		if (dev->config) {
			ni_route_table_t *tab;
			ni_route_t *rp;
			unsigned int i;

			for (tab = lease->routes; tab; tab = tab->next) {
				for (i = 0; i < tab->routes.count; ++i) {
					if ((rp = tab->routes.data[i]) == NULL)
						continue;
					rp->protocol = RTPROT_DHCP;
					rp->priority = dev->config->route_priority;
				}
			}
		}

		ni_dhcp4_device_set_lease(dev, lease);
		dev->fsm.state = NI_DHCP4_STATE_BOUND;

		ni_note("%s: Committed DHCPv4 lease with address %s "
			"(lease time %u sec, renew in %u sec, rebind in %u sec)",
			dev->ifname, inet_ntoa(lease->dhcp4.address),
			lease->dhcp4.lease_time, lease->dhcp4.renewal_time,
			lease->dhcp4.rebind_time);

		/* Write the lease to lease cache */
		if (dev->config->dry_run != NI_DHCP4_RUN_OFFER) {
			ni_addrconf_lease_file_write(dev->ifname, lease);
		}

		/* Notify anyone who cares that we've (re-)acquired the lease */
		ni_dhcp4_send_event(NI_DHCP4_EVENT_ACQUIRED, dev, lease);

		if (dev->config->dry_run != NI_DHCP4_RUN_NORMAL) {
			ni_dhcp4_fsm_restart(dev);
			ni_dhcp4_device_stop(dev);
		}
	} else {

		/* Delete old lease file */
		if ((lease = dev->lease) != NULL) {
			ni_note("%s: Dropped DHCPv4 lease with UUID %s",
				dev->ifname, ni_uuid_print(&lease->uuid));

			lease->state = NI_ADDRCONF_STATE_RELEASED;
			ni_dhcp4_send_event(NI_DHCP4_EVENT_RELEASED, dev, lease);

			if (!dev->config || dev->config->dry_run != NI_DHCP4_RUN_OFFER) {
				ni_addrconf_lease_file_remove(dev->ifname, lease->type, lease->family);
			}
			ni_dhcp4_device_drop_lease(dev);
		}

		ni_dhcp4_fsm_restart(dev);
	}

	return 0;
}

/*
 * Reload an old lease from file, and see whether we can reuse it.
 * This is used during restart of wickedd.
 */
int
ni_dhcp4_recover_lease(ni_dhcp4_device_t *dev)
{
	ni_addrconf_lease_t *lease;
	ni_sockaddr_t addr;

	if (dev->lease)
		return 1;

	lease = ni_addrconf_lease_file_read(dev->ifname, NI_ADDRCONF_DHCP, AF_INET);
	if (!lease)
		return -1;

	/* We cannot renew/rebind/reboot without it */
	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.server_id, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: discarding existing lease, no server-id",
				dev->ifname);
		goto discard;
	}
	ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: recovered lease with UUID %s", dev->ifname, ni_uuid_print(&lease->uuid));

	ni_dhcp4_device_set_lease(dev, lease);
	return 0;

discard:
	ni_addrconf_lease_free(lease);
	return -1;
}

void
ni_dhcp4_fsm_fail_lease(ni_dhcp4_device_t *dev)
{
	ni_debug_dhcp("%s: failing lease", dev->ifname);

	ni_dhcp4_fsm_restart(dev);
	ni_capture_free(dev->capture);
	dev->capture = NULL;

	ni_dhcp4_device_set_lease(dev, NULL);
	dev->notify = 1;
	dev->failed = 1;
}

static ni_bool_t
__ni_dhcp4_address_on_device(const ni_netdev_t *ifp, struct in_addr ipv4)
{
	const ni_address_t *ap;
	ni_sockaddr_t addr;

	ni_sockaddr_set_ipv4(&addr, ipv4, 0);
	for (ap = ifp->addrs; ap; ap = ap->next) {
		if (ap->family != AF_INET)
			continue;

		if (ni_sockaddr_equal(&ap->local_addr, &addr))
			return TRUE;
	}
	return FALSE;
}

static ni_bool_t
__ni_dhcp4_address_on_link(ni_dhcp4_device_t *dev, struct in_addr ipv4)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;

	nc = ni_global_state_handle(0);
	if (!nc || !(ifp = ni_netdev_by_index(nc, dev->link.ifindex)))
		return FALSE;

	return __ni_dhcp4_address_on_device(ifp, ipv4);
}

int
ni_dhcp4_fsm_validate_lease(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	/*
	 * When the address is already set on the link, we
	 * don't need to validate it and just commit it.
	 */
	if (__ni_dhcp4_address_on_link(dev, lease->dhcp4.address)) {
		ni_debug_dhcp("%s: address %s is on link, omit validation",
				dev->ifname, inet_ntoa(lease->dhcp4.address));
		ni_dhcp4_fsm_commit_lease(dev, lease);
		return 0;
	}

	ni_info("%s: Validating DHCPv4 address %s",
		dev->ifname, inet_ntoa(lease->dhcp4.address));

	/* For ARP validations, we will send 3 ARP queries with a timeout
	 * of 200ms each.
	 * The "claims" part is really for IPv4LL
	 */
	dev->arp.nprobes = 3;
	dev->arp.nclaims = 0;

	/* dhcp4cd source code says:
	 * IEEE1394 cannot set ARP target address according to RFC2734
	 */
	if (dev->system.hwaddr.type == ARPHRD_IEEE1394)
		dev->arp.nclaims = 0;

	if (ni_dhcp4_fsm_arp_validate(dev) < 0) {
		ni_debug_dhcp("%s: unable to validate lease", dev->ifname);
		return -1;
	}

	dev->fsm.state = NI_DHCP4_STATE_VALIDATING;
	return 0;
}

int
ni_dhcp4_fsm_arp_validate(ni_dhcp4_device_t *dev)
{
	struct in_addr null = { 0 };
	struct in_addr claim;

	if (!dev->lease)
		return -1;

	claim = dev->lease->dhcp4.address;
	if (dev->arp.handle == NULL) {
		dev->arp.handle = ni_arp_socket_open(&dev->system,
				ni_dhcp4_fsm_process_arp_packet, dev);
		if (!dev->arp.handle->user_data) {
			ni_error("%s: unable to create ARP handle", dev->ifname);
			return -1;
		}
	}

	if (dev->arp.nprobes) {
		ni_debug_dhcp("%s: arp validate: probing for %s",
				dev->ifname, inet_ntoa(claim));
		ni_arp_send_request(dev->arp.handle, null, claim);
		dev->arp.nprobes--;
	} else if (dev->arp.nclaims) {
		ni_debug_dhcp("%s: arp validate: claiming %s",
				dev->ifname, inet_ntoa(claim));
		ni_arp_send_grat_request(dev->arp.handle, claim);
		dev->arp.nclaims--;
	} else {
		/* Wow, we're done! */
		ni_info("%s: Successfully validated DHCPv4 address %s",
			dev->ifname, inet_ntoa(claim));
		ni_dhcp4_fsm_commit_lease(dev, dev->lease);
		ni_dhcp4_device_arp_close(dev);
		return 0;
	}

	ni_dhcp4_fsm_set_timeout_msec(dev, NI_DHCP4_ARP_TIMEOUT);
	return 0;
}

void
ni_dhcp4_fsm_process_arp_packet(ni_arp_socket_t *arph, const ni_arp_packet_t *pkt, void *user_data)
{
	ni_dhcp4_device_t *dev = user_data;
	ni_netconfig_t *nc = ni_global_state_handle(0);
	const ni_netdev_t *ifp;
	ni_bool_t false_alarm = FALSE;
	ni_bool_t found_addr = FALSE;

	if (!pkt || pkt->op != ARPOP_REPLY || !dev->lease)
		return;

	/* Is it about the address we're validating at all? */
	if (pkt->sip.s_addr != dev->lease->dhcp4.address.s_addr)
		return;

	/* Ignore any ARP replies that seem to come from our own
	 * MAC address. Some helpful switches seem to generate
	 * these. */
	if (ni_link_address_equal(&dev->system.hwaddr, &pkt->sha))
		return;

	/* As well as ARP replies that seem to come from our own
	 * host: dup if same address, not a dup if there are two
	 * interfaces connected to the same broadcast domain.
	 */
	for (ifp = ni_netconfig_devlist(nc); ifp; ifp = ifp->next) {
		if (ifp->link.ifindex == dev->link.ifindex)
			continue;

		if (!ni_netdev_link_is_up(ifp))
			continue;

		if (!ni_link_address_equal(&ifp->link.hwaddr, &pkt->sha))
			continue;

		/* OK, we have an interface matching the hwaddr,
		 * which will answer arp requests when it is on
		 * the same broadcast domain and causes a false
		 * alarm, except it really has the IP assigned.
		 */
		false_alarm = TRUE;
		if (__ni_dhcp4_address_on_device(ifp, pkt->sip))
			found_addr = TRUE;
	}
	if (false_alarm && !found_addr)
		return;

	ni_debug_dhcp("%s: address %s already in use by %s",
			dev->ifname, inet_ntoa(pkt->sip),
			ni_link_address_print(&pkt->sha));
	ni_dhcp4_device_arp_close(dev);
	ni_dhcp4_fsm_decline(dev);
}

/*
 * NAKs in different states need to be treated differently.
 */
static int
ni_dhcp4_process_nak(ni_dhcp4_device_t *dev)
{
	switch (dev->fsm.state) {
	case NI_DHCP4_STATE_BOUND:
		/* RFC says discard NAKs received in state BOUND */
		return 0;

	default:
		/* FIXME: how do we handle a NAK response to an INFORM? */
		ni_dhcp4_device_drop_lease(dev);
		break;
	}

	/* Move back to state INIT */
	ni_dhcp4_fsm_restart(dev);

	if (dev->dhcp4.nak_backoff == 0)
		dev->dhcp4.nak_backoff = 1;

	/* If we constantly get NAKs then we should slowly back off */
	ni_debug_dhcp("Received NAK, backing off for %u seconds", dev->dhcp4.nak_backoff);
	ni_dhcp4_fsm_set_timeout(dev, dev->dhcp4.nak_backoff);

	dev->dhcp4.nak_backoff *= 2;
	if (dev->dhcp4.nak_backoff > NAK_BACKOFF_MAX)
		dev->dhcp4.nak_backoff = NAK_BACKOFF_MAX;
	return 0;
}

/*
 * Set the protocol event callback
 */
void
ni_dhcp4_set_event_handler(ni_dhcp4_event_handler_t func)
{
	ni_dhcp4_fsm_event_handler = func;
}

void
ni_dhcp4_send_event(enum ni_dhcp4_event ev, ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (ni_dhcp4_fsm_event_handler)
		ni_dhcp4_fsm_event_handler(ev, dev, lease);
}

/*
 * Helper function to print name of DHCP4 FSM state
 */
static const char *__dhcp4_state_name[__NI_DHCP4_STATE_MAX] = {
 [NI_DHCP4_STATE_INIT]		= "INIT",
 [NI_DHCP4_STATE_SELECTING]	= "SELECTING",
 [NI_DHCP4_STATE_REQUESTING]	= "REQUESTING",
 [NI_DHCP4_STATE_VALIDATING]	= "VALIDATING",
 [NI_DHCP4_STATE_BOUND]		= "BOUND",
 [NI_DHCP4_STATE_RENEWING]	= "RENEWING",
 [NI_DHCP4_STATE_REBINDING]	= "REBINDING",
 [NI_DHCP4_STATE_REBOOT]	= "REBOOT",
 [NI_DHCP4_STATE_RELEASED]	= "RELEASED",
};

const char *
ni_dhcp4_fsm_state_name(int state)
{
	const char *name = NULL;

	if (0 <= state && state < __NI_DHCP4_STATE_MAX)
		name = __dhcp4_state_name[state];
	return name? name : "UNKNOWN STATE";
}
