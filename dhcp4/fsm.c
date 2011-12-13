/*
 * DHCP client for wicked - finite state machine.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

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
#include "netinfo_priv.h"
#include "dhcp.h"
#include "protocol.h"
#include "buffer.h"

#define NAK_BACKOFF_MAX		60	/* seconds */

static int		ni_dhcp_fsm_request(ni_dhcp_device_t *, const ni_addrconf_lease_t *);
static int		ni_dhcp_fsm_arp_validate(ni_dhcp_device_t *);
static int		ni_dhcp_fsm_renewal(ni_dhcp_device_t *);
static int		ni_dhcp_fsm_rebind(ni_dhcp_device_t *);
static int		ni_dhcp_fsm_decline(ni_dhcp_device_t *);
static const char *	ni_dhcp_fsm_state_name(int);

static int		ni_dhcp_process_offer(ni_dhcp_device_t *, ni_addrconf_lease_t *);
static int		ni_dhcp_process_ack(ni_dhcp_device_t *, ni_addrconf_lease_t *);
static int		ni_dhcp_process_nak(ni_dhcp_device_t *);
static void		ni_dhcp_fsm_process_arp_packet(ni_arp_socket_t *, const ni_arp_packet_t *, void *);
static void		ni_dhcp_fsm_fail_lease(ni_dhcp_device_t *);
static int		ni_dhcp_fsm_validate_lease(ni_dhcp_device_t *, ni_addrconf_lease_t *);
static void		ni_dhcp_send_event(enum ni_dhcp_event, ni_dhcp_device_t *, ni_addrconf_lease_t *);
static void		__ni_dhcp_fsm_timeout(void *, const ni_timer_t *);

static ni_dhcp_event_handler_t *ni_dhcp_fsm_event_handler;

int
ni_dhcp_fsm_process_dhcp_packet(ni_dhcp_device_t *dev, ni_buffer_t *msgbuf)
{
	ni_dhcp_message_t *message;
	ni_addrconf_lease_t *lease = NULL;
	int msg_code;

	if (dev->fsm.state == NI_DHCP_STATE_VALIDATING) {
		ni_error("%s: shouldn't get here in state VALIDATING", __FUNCTION__);
		return -1;
	}

	if (!(message = ni_buffer_pull_head(msgbuf, sizeof(*message)))) {
		ni_debug_dhcp("short DHCP packet (%u bytes)", ni_buffer_count(msgbuf));
		return -1;
	}
	if (dev->dhcp.xid == 0) {
		ni_debug_dhcp("unexpected packet on %s", dev->ifname);
		return -1;
	}
	if (dev->dhcp.xid != message->xid) {
		ni_debug_dhcp("ignoring packet with wrong xid 0x%x (expected 0x%x)",
				message->xid, dev->dhcp.xid);
		return -1;
	}

	msg_code = ni_dhcp_parse_response(message, msgbuf, &lease);
	if (msg_code < 0) {
		/* Ignore this message, time out later */
		ni_error("unable to parse DHCP response");
		return -1;
	}

	ni_debug_dhcp("%s: received %s message in state %s",
			dev->ifname, ni_dhcp_message_name(msg_code),
			ni_dhcp_fsm_state_name(dev->fsm.state));

	/* When receiving a DHCP OFFER, verify sender address against list of
	 * servers to ignore, and preferred servers. */
	if (msg_code == DHCP_OFFER && dev->fsm.state == NI_DHCP_STATE_SELECTING) {
		struct in_addr srv_addr = { .s_addr = message->siaddr };

		if (ni_dhcp_config_ignore_server(srv_addr)) {
			ni_debug_dhcp("%s: ignoring DHCP offer from %s",
					dev->ifname, inet_ntoa(srv_addr));
			goto out;
		}

		/* If we're scanning all offers, we need to decide whether
		 * this offer is accepted, or whether we want to wait for
		 * more.
		 */
		if (!dev->dhcp.accept_any_offer) {
			int weight = 0;

			/* Check if we have any preferred servers. */
			weight = ni_dhcp_config_server_preference(srv_addr);

			/* If we're refreshing an existing lease (eg after link disconnect
			 * and reconnect), we accept the offer if it comes from the same
			 * server as the original one.
			 */
			if (dev->lease
			 && dev->lease->dhcp.serveraddress.s_addr == srv_addr.s_addr)
				weight = 100;

			ni_debug_dhcp("received lease offer from %s; server weight=%d (best offer=%d)",
					inet_ntoa(lease->dhcp.serveraddress), weight,
					dev->best_offer.weight);

			/* negative weight means never. */
			if (weight < 0)
				goto out;

			/* weight between 0 and 100 means maybe. */
			if (weight < 100) {
				if (dev->best_offer.weight < weight) {
					if (dev->best_offer.lease != NULL)
						ni_addrconf_lease_free(dev->best_offer.lease);
					dev->best_offer.lease = NULL;
					dev->best_offer.weight = weight;
					dev->best_offer.lease = lease;
					return 0;
				}
				goto out;
			}

			/* If the weight has maximum value, just accept this offer. */
		}
	}

	/* We've received a valid response; if something goes wrong now
	 * it's nothing that could be fixed by retransmitting the message.
	 *
	 * The only exception would be if we ever do some filtering or
	 * matching of OFFERs - then we would certainly want to keep
	 * waiting for additional packets.
	 */
	ni_dhcp_device_disarm_retransmit(dev);
	dev->dhcp.xid = 0;

	/* move to next stage of protocol */
	switch (msg_code) {
	case DHCP_OFFER:
		if (dev->fsm.state != NI_DHCP_STATE_SELECTING)
			goto ignore;
		ni_dhcp_process_offer(dev, lease);
		break;

	case DHCP_ACK:
		if (dev->fsm.state != NI_DHCP_STATE_REQUESTING
		 && dev->fsm.state != NI_DHCP_STATE_RENEWING
		 && dev->fsm.state != NI_DHCP_STATE_REBINDING)
			goto ignore;
		ni_dhcp_process_ack(dev, lease);
		break;

	case DHCP_NAK:
		/* The RFC 2131 state diagram says, ignore NAKs in state BOUND.
		 * I guess we also have no use for NAK replies to a DHCP_DISCOVER
		 */
		if (dev->fsm.state == NI_DHCP_STATE_SELECTING
		 || dev->fsm.state == NI_DHCP_STATE_BOUND)
			goto ignore;
		ni_dhcp_process_nak(dev);
		break;

	default:
	ignore:
		ni_debug_dhcp("ignoring %s in state %s",
				ni_dhcp_message_name(msg_code),
				ni_dhcp_fsm_state_name(dev->fsm.state));
		break;
	}

out:
	if (dev->lease != lease)
		ni_addrconf_lease_free(lease);

	/* If we received a message other than NAK, reset the NAK
	 * backoff timer. */
	if (msg_code != DHCP_NAK)
		dev->dhcp.nak_backoff = 1;

	return 0;
}

static void
ni_dhcp_fsm_restart(ni_dhcp_device_t *dev)
{
	dev->fsm.state = NI_DHCP_STATE_INIT;

	ni_dhcp_device_disarm_retransmit(dev);
	if (dev->fsm.timer) {
		ni_timer_cancel(dev->fsm.timer);
		dev->fsm.timer = NULL;
	}
	dev->dhcp.xid = 0;

	ni_dhcp_device_drop_lease(dev);
}

void
ni_dhcp_fsm_set_timeout_msec(ni_dhcp_device_t *dev, unsigned int msec)
{
	if (msec != 0) {
		ni_debug_dhcp("%s: setting timeout to %u msec", dev->ifname, msec);
		if (dev->fsm.timer)
			ni_timer_rearm(dev->fsm.timer, msec);
		else
			dev->fsm.timer = ni_timer_register(msec, __ni_dhcp_fsm_timeout, dev);
	}
}

void
ni_dhcp_fsm_set_timeout(ni_dhcp_device_t *dev, unsigned int seconds)
{
	ni_dhcp_fsm_set_timeout_msec(dev, 1000 * seconds);
}

void
ni_dhcp_fsm_set_deadline(ni_dhcp_device_t *dev, time_t deadline)
{
	time_t now = time(NULL);

	if (now < deadline)
		ni_dhcp_fsm_set_timeout(dev, deadline - now);
	else
		ni_error("ni_dhcp_fsm_set_deadline(%s): cannot go back in time", dev->ifname);
}

int
__ni_dhcp_fsm_discover(ni_dhcp_device_t *dev, int scan_offers)
{
	ni_addrconf_lease_t *lease;
	int rv;

	ni_debug_dhcp("initiating discovery for %s (ifindex %d)", dev->ifname, dev->link.ifindex);

	/* If we already have a lease, try asking for the same.
	 * If not, create a dummy lease with NULL fields.
	 * Note: if DISCOVER for the old lease times out,
	 * we should fall back to asking for anything.
	 */
	if ((lease = dev->lease) == NULL)
		lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET);

	rv = ni_dhcp_device_send_message(dev, DHCP_DISCOVER, lease);

	dev->fsm.state = NI_DHCP_STATE_SELECTING;

	dev->dhcp.accept_any_offer = 1;
	ni_debug_dhcp("valid lease: %d; have prefs: %d",
			ni_addrconf_lease_is_valid(dev->lease),
			ni_dhcp_config_have_server_preference());
	if (ni_addrconf_lease_is_valid(dev->lease)
	 || (scan_offers && ni_dhcp_config_have_server_preference())) {
		ni_dhcp_fsm_set_timeout(dev, dev->config->initial_discovery_timeout);
		dev->dhcp.accept_any_offer = 0;
	} else {
		ni_dhcp_fsm_set_timeout(dev, dev->config->request_timeout);
	}

	ni_dhcp_device_drop_best_offer(dev);

	if (lease != dev->lease)
		ni_addrconf_lease_free(lease);
	return rv;
}

int
ni_dhcp_fsm_discover(ni_dhcp_device_t *dev)
{
	return __ni_dhcp_fsm_discover(dev, 1);
}

int
ni_dhcp_fsm_request(ni_dhcp_device_t *dev, const ni_addrconf_lease_t *lease)
{
	int rv;

	ni_debug_dhcp("requesting lease for %s, timeout %d",
			dev->ifname, dev->config->request_timeout);
	rv = ni_dhcp_device_send_message(dev, DHCP_REQUEST, lease);

	/* Ignore the return value; sending the request may actually
	 * fail transiently */
	ni_dhcp_fsm_set_timeout(dev, dev->config->request_timeout);
	dev->fsm.state = NI_DHCP_STATE_REQUESTING;

	return rv;
}

int
ni_dhcp_fsm_renewal(ni_dhcp_device_t *dev)
{
	int rv;

	ni_debug_dhcp("trying to renew lease for %s", dev->ifname);

	/* FIXME: we should really unicast the request here. */
	rv = ni_dhcp_device_send_message(dev, DHCP_REQUEST, dev->lease);

	ni_dhcp_fsm_set_deadline(dev,
			dev->lease->time_acquired + dev->lease->dhcp.rebind_time);
	dev->fsm.state = NI_DHCP_STATE_RENEWING;
	return rv;
}

int
ni_dhcp_fsm_rebind(ni_dhcp_device_t *dev)
{
	int rv;

	ni_debug_dhcp("trying to rebind lease for %s", dev->ifname);
	dev->lease->dhcp.serveraddress.s_addr = 0;

	rv = ni_dhcp_device_send_message(dev, DHCP_REQUEST, dev->lease);

	ni_dhcp_fsm_set_deadline(dev,
			dev->lease->time_acquired + dev->lease->dhcp.lease_time);
	dev->fsm.state = NI_DHCP_STATE_REBINDING;
	return rv;
}

int
ni_dhcp_fsm_decline(ni_dhcp_device_t *dev)
{
	ni_debug_dhcp("%s: declining lease", dev->ifname);
	ni_dhcp_device_send_message(dev, DHCP_DECLINE, dev->lease);

	/* FIXME: we should record the bad lease, and ignore it
	 * when the server offers it again. */

	/* RFC 2131 mandates we should wait for 10 seconds before
	 * retrying discovery. */
	ni_dhcp_fsm_set_timeout(dev, 10);
	dev->fsm.state = NI_DHCP_STATE_INIT;
	return 0;
}

int
ni_dhcp_fsm_release(ni_dhcp_device_t *dev)
{
	if (!dev->lease)
		return 0;

	if (dev->fsm.state != NI_DHCP_STATE_BOUND) {
		ni_error("%s called in state %s", __FUNCTION__,
				ni_dhcp_fsm_state_name(dev->fsm.state));
		return -1;
	}

	ni_debug_dhcp("%s: releasing lease", dev->ifname);
	ni_dhcp_device_send_message(dev, DHCP_RELEASE, dev->lease);

	/* FIXME: we should record the bad lease, and ignore it
	 * when the server offers it again. */

	/* RFC 2131 mandates we should wait for 10 seconds before
	 * retrying discovery. */
	ni_dhcp_fsm_set_timeout(dev, 10);
	dev->fsm.state = NI_DHCP_STATE_INIT;
	return 0;
}

/*
 * We never received any response. Deal with the traumatic rejection.
 */
static void
ni_dhcp_fsm_timeout(ni_dhcp_device_t *dev)
{
	ni_debug_dhcp("%s: timeout in state %s", dev->ifname, ni_dhcp_fsm_state_name(dev->fsm.state));
	dev->fsm.timer = NULL;

	switch (dev->fsm.state) {
	case NI_DHCP_STATE_INIT:
		/* We get here if we previously received a NAK, and have
		 * started to back off, or if we declined a lease because
		 * the address was already in use. */
		ni_dhcp_fsm_discover(dev);
		break;

	case NI_DHCP_STATE_SELECTING:
		if (!dev->dhcp.accept_any_offer) {
			ni_dhcp_config_t *conf = dev->config;

			/* We were scanning all offers to check for a best offer.
			 * There was no perfect match, but we may have a "good enough"
			 * match. Check for it. */
			if (dev->best_offer.lease) {
				ni_addrconf_lease_t *lease = dev->best_offer.lease;

				ni_debug_dhcp("accepting lease offer from %s; server weight=%d",
						inet_ntoa(lease->dhcp.serveraddress),
						dev->best_offer.weight);
				ni_dhcp_process_offer(dev, lease);
				return;
			}

			ni_dhcp_fsm_fail_lease(dev);
			if (conf->initial_discovery_timeout < conf->request_timeout) {
				__ni_dhcp_fsm_discover(dev, 0);
				return;
			}
		}
		/* fallthrough */

	case NI_DHCP_STATE_REQUESTING:
		ni_error("%s: DHCP discovery failed", dev->ifname);
		ni_dhcp_fsm_fail_lease(dev);
		ni_dhcp_fsm_restart(dev);

		/* Now decide whether we should keep trying */
		if (dev->config->request_timeout == ~0U)
			ni_dhcp_fsm_discover(dev);
		break;

	case NI_DHCP_STATE_VALIDATING:
		/* Send the next ARP probe */
		ni_dhcp_fsm_arp_validate(dev);
		break;

	case NI_DHCP_STATE_BOUND:
		ni_dhcp_fsm_renewal(dev);
		break;

	case NI_DHCP_STATE_RENEWING:
		ni_error("unable to renew lease within renewal period; trying to rebind");
		ni_dhcp_fsm_rebind(dev);
		break;

	case NI_DHCP_STATE_REBINDING:
		ni_error("unable to rebind lease");
		ni_dhcp_fsm_restart(dev);
		/* FIXME: now decide whether we should try to re-discover */
		break;

	default:
		;
	}
}

static void
__ni_dhcp_fsm_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_dhcp_device_t *dev = user_data;

	if (dev->fsm.timer != timer) {
		ni_warn("%s: bad timer handle", __func__);
		return;
	}

	ni_dhcp_fsm_timeout(dev);
}

/*
 * These functions get called when the link goes down/up.
 * We use these to be smart about renewing a lease.
 */
void
ni_dhcp_fsm_link_up(ni_dhcp_device_t *dev)
{
	if (dev->config == NULL)
		return;

	ni_debug_dhcp("%s: link came back up", dev->ifname);
	switch (dev->fsm.state) {
	case NI_DHCP_STATE_INIT:
		/* We get here if we aborted a discovery operation. */
		ni_dhcp_fsm_discover(dev);
		break;

	case NI_DHCP_STATE_BOUND:
		/* The link went down and came back up. We may now be on a
		 * completely different network, and our lease may no longer
		 * be valid.
		 * Do a quick renewal.
		 */
		ni_dhcp_fsm_renewal(dev);
		break;

	default:
		break;
	}
}

void
ni_dhcp_fsm_link_down(ni_dhcp_device_t *dev)
{
	if (dev->config == NULL)
		return;

	ni_debug_dhcp("%s: link went down", dev->ifname);
	switch (dev->fsm.state) {
	case NI_DHCP_STATE_INIT:
	case NI_DHCP_STATE_SELECTING:
	case NI_DHCP_STATE_REQUESTING:
	case NI_DHCP_STATE_VALIDATING:
		ni_dhcp_device_drop_lease(dev);
		ni_dhcp_fsm_restart(dev);
		break;

	default: ;
	}
}

static int
ni_dhcp_process_offer(ni_dhcp_device_t *dev, ni_addrconf_lease_t *lease)
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

	inet_ntop(AF_INET, &lease->dhcp.address, abuf1, sizeof(abuf1));
	inet_ntop(AF_INET, &lease->dhcp.serveraddress, abuf2, sizeof(abuf2));

	if (lease->dhcp.servername[0])
		ni_debug_dhcp("Received offer for %s from %s (%s)",
			abuf1, abuf2, lease->dhcp.servername);
	else
		ni_debug_dhcp("Received offer for %s from %s", abuf1, abuf2);

	ni_dhcp_fsm_request(dev, lease);
	return 0;
}

static int
ni_dhcp_process_ack(ni_dhcp_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (lease->dhcp.lease_time == 0) {
		lease->dhcp.lease_time = DHCP_DEFAULT_LEASETIME;
		ni_debug_dhcp("server supplied no lease time, assuming %u seconds",
				lease->dhcp.lease_time);
	}

	if (lease->dhcp.rebind_time >= lease->dhcp.lease_time) {
		ni_debug_dhcp("%s: dhcp.rebind_time greater than dhcp.lease_time, using default", dev->ifname);
		lease->dhcp.rebind_time = lease->dhcp.lease_time * 7 / 8;
	} else if (lease->dhcp.rebind_time == 0) {
		ni_debug_dhcp("%s: no dhcp.rebind_time supplied, using default", dev->ifname);
		lease->dhcp.rebind_time = lease->dhcp.lease_time * 7 / 8;
	}

	if (lease->dhcp.renewal_time >= lease->dhcp.rebind_time) {
		ni_debug_dhcp("%s: dhcp.renewal_time greater than dhcp.rebind_time, using default", dev->ifname);
		lease->dhcp.renewal_time = lease->dhcp.lease_time / 2;
	} else if (lease->dhcp.renewal_time == 0) {
		ni_debug_dhcp("%s: no dhcp.renewal_time supplied, using default", dev->ifname);
		lease->dhcp.renewal_time = lease->dhcp.lease_time / 2;
	}

	if (lease->dhcp.renewal_time > dev->config->max_lease_time) {
		ni_debug_dhcp("clamping lease time to %u sec", dev->config->max_lease_time);
		lease->dhcp.renewal_time = dev->config->max_lease_time;
	}

	if (dev->config->flags & DHCP_DO_ARP) {
		/* should we do this on renew as well? */
		ni_dhcp_fsm_validate_lease(dev, lease);
	} else {
		ni_dhcp_fsm_commit_lease(dev, lease);
	}

	return 0;
}

int
ni_dhcp_fsm_commit_lease(ni_dhcp_device_t *dev, ni_addrconf_lease_t *lease)
{
        if (dev->capture)
		ni_capture_free(dev->capture);
	dev->capture = NULL;

	if (lease) {
		ni_debug_dhcp("%s: committing lease", dev->ifname);
		ni_debug_dhcp("%s: schedule renewal of lease in %u seconds",
				dev->ifname, lease->dhcp.renewal_time);
		ni_dhcp_fsm_set_timeout(dev, lease->dhcp.renewal_time);

		/* Save the client id we used */
		strncpy(lease->dhcp.client_id, dev->config->client_id,
				sizeof(lease->dhcp.client_id)-1);

		ni_dhcp_device_set_lease(dev, lease);
		dev->fsm.state = NI_DHCP_STATE_BOUND;

		/* Write the lease to lease cache */
		ni_addrconf_lease_file_write(dev->ifname, lease);

		/* Notify anyone who cares that we've (re-)acquired the lease */
		ni_dhcp_send_event(NI_DHCP_EVENT_ACQUIRED, dev, lease);
	} else {
		ni_debug_dhcp("%s: dropped lease", dev->ifname);

		/* Delete old lease file */
		if ((lease = dev->lease) != NULL) {
			ni_dhcp_send_event(NI_DHCP_EVENT_RELEASED, dev, lease);
			ni_addrconf_lease_file_remove(dev->ifname, lease->type, lease->family);
			ni_dhcp_device_drop_lease(dev);
			lease = NULL;
		}

		ni_dhcp_fsm_restart(dev);
	}
	dev->notify = 1;

	return 0;
}

/*
 * Reload an old lease from file, and see whether we can reuse it.
 * This is used during restart of wickedd.
 */
int
ni_dhcp_fsm_recover_lease(ni_dhcp_device_t *dev, const ni_addrconf_request_t *req)
{
	ni_addrconf_lease_t *lease;
	time_t now = time(NULL), then;

	/* Don't recover anything if we already have a lease attached. */
	if (dev->lease != NULL)
		return -1;

	lease = ni_addrconf_lease_file_read(dev->ifname, NI_ADDRCONF_DHCP, AF_INET);
	if (!lease)
		return -1;

	if (lease->state != NI_ADDRCONF_STATE_GRANTED)
		goto discard;

	ni_debug_dhcp("trying to recover dhcp lease, now inspecting");
	then = lease->time_acquired;
	if (now < then) {
		ni_debug_dhcp("%s: found time-warped lease (hi, grand-grand-pa)", __FUNCTION__);
		goto discard;
	}

	if (now >= then + lease->dhcp.lease_time) {
		ni_debug_dhcp("%s: found expired lease", __FUNCTION__);
		goto discard;
	}

	if (!ni_dhcp_lease_matches_request(lease, req)) {
		ni_debug_dhcp("%s: lease doesn't match request", __FUNCTION__);
		goto discard;
	}

	ni_dhcp_device_set_lease(dev, lease);

	if (now >= then + lease->dhcp.rebind_time) {
		ni_dhcp_fsm_rebind(dev);
	} else
	if (now >= then + lease->dhcp.renewal_time) {
		ni_dhcp_fsm_renewal(dev);
	} else {
		ni_dhcp_fsm_set_deadline(dev, then + lease->dhcp.renewal_time);
		dev->fsm.state = NI_DHCP_STATE_BOUND;
	}

	ni_debug_dhcp("%s: recovered old lease; now in state=%s",
			dev->ifname, ni_dhcp_fsm_state_name(dev->fsm.state));
	dev->notify = 1;
	return 0;

discard:
	ni_addrconf_lease_free(lease);
	return -1;
}

void
ni_dhcp_fsm_fail_lease(ni_dhcp_device_t *dev)
{
	ni_debug_dhcp("%s: failing lease", dev->ifname);

	ni_dhcp_fsm_restart(dev);
        if (dev->capture)
		ni_capture_free(dev->capture);
	dev->capture = NULL;

	ni_dhcp_device_set_lease(dev, NULL);
	dev->notify = 1;
	dev->failed = 1;
}

int
ni_dhcp_fsm_validate_lease(ni_dhcp_device_t *dev, ni_addrconf_lease_t *lease)
{
	/* For ARP validations, we will send 3 ARP queries with a timeout
	 * of 200ms each.
	 * The "claims" part is really for IPv4LL
	 */
	dev->arp.nprobes = 3;
	dev->arp.nclaims = 0;

	/* dhcpcd source code says:
	 * IEEE1394 cannot set ARP target address according to RFC2734
	 */
	if (dev->system.arp_type == ARPHRD_IEEE1394)
		dev->arp.nclaims = 0;

	if (lease)
		ni_dhcp_device_set_lease(dev, lease);

	if (ni_dhcp_fsm_arp_validate(dev) < 0)
		goto decline;

	dev->fsm.state = NI_DHCP_STATE_VALIDATING;
	return 0;

decline:
	ni_debug_dhcp("unable to validate lease, declining");
	return -1;
}

int
ni_dhcp_fsm_arp_validate(ni_dhcp_device_t *dev)
{
	struct in_addr claim = dev->lease->dhcp.address;
	struct in_addr null = { 0 };

	if (dev->arp.handle == NULL) {
		dev->arp.handle = ni_arp_socket_open(&dev->system, ni_dhcp_fsm_process_arp_packet, dev);
		if (!dev->arp.handle->user_data) {
			ni_error("unable to create ARP handle");
			return -1;
		}
	}

	if (dev->arp.nprobes) {
		ni_debug_dhcp("arp_validate: probing for %s", inet_ntoa(claim));
		ni_arp_send_request(dev->arp.handle, null, claim);
		dev->arp.nprobes--;
	} else if (dev->arp.nclaims) {
		ni_debug_dhcp("arp_validate: claiming %s", inet_ntoa(claim));
		ni_arp_send_grat_reply(dev->arp.handle, claim);
		dev->arp.nclaims--;
	} else {
		/* Wow, we're done! */
		ni_debug_dhcp("successfully validated %s", inet_ntoa(claim));
		ni_dhcp_fsm_commit_lease(dev, dev->lease);
		ni_dhcp_device_arp_close(dev);
		return 0;
	}

	ni_dhcp_fsm_set_timeout_msec(dev, NI_DHCP_ARP_TIMEOUT);
	return 0;
}

void
ni_dhcp_fsm_process_arp_packet(ni_arp_socket_t *arph, const ni_arp_packet_t *pkt, void *user_data)
{
	ni_dhcp_device_t *dev = user_data;

	if (pkt->op != ARPOP_REPLY)
		return;

	/* Ignore any ARP replies that seem to come from our own
	 * MAC address. Some helpful switches seem to generate
	 * these. */
	if (ni_link_address_equal(&dev->system.hwaddr, &pkt->sha))
		return;

	if (pkt->sip.s_addr == dev->lease->dhcp.address.s_addr) {
		ni_debug_dhcp("address %s already in use by %s",
				inet_ntoa(pkt->sip),
				ni_link_address_print(&pkt->sha));
		ni_dhcp_fsm_decline(dev);
	}
}

/*
 * FIXME: NAKs in different states need to be treated differently.
 */
static int
ni_dhcp_process_nak(ni_dhcp_device_t *dev)
{
	switch (dev->fsm.state) {
	case NI_DHCP_STATE_BOUND:
		/* RFC says discard NAKs received in state BOUND */
		return 0;

	default:
		/* FIXME: how do we handle a NAK response to an INFORM? */
		ni_dhcp_device_drop_lease(dev);
		break;
	}

	/* Move back to state INIT */
	ni_dhcp_fsm_restart(dev);

	if (dev->dhcp.nak_backoff == 0)
		dev->dhcp.nak_backoff = 1;

	/* If we constantly get NAKs then we should slowly back off */
	ni_debug_dhcp("Received NAK, backing off for %u seconds", dev->dhcp.nak_backoff);
	ni_dhcp_fsm_set_timeout(dev, dev->dhcp.nak_backoff);

	dev->dhcp.nak_backoff *= 2;
	if (dev->dhcp.nak_backoff > NAK_BACKOFF_MAX)
		dev->dhcp.nak_backoff = NAK_BACKOFF_MAX;
	return 0;
}

/*
 * Set the protocol event callback
 */
void
ni_dhcp_set_event_handler(ni_dhcp_event_handler_t func)
{
	ni_dhcp_fsm_event_handler = func;
}

void
ni_dhcp_send_event(enum ni_dhcp_event ev, ni_dhcp_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (ni_dhcp_fsm_event_handler)
		ni_dhcp_fsm_event_handler(ev, dev, lease);
}
/*
 * Helper function to print name of DHCP FSM state
 */
static const char *__dhcp_state_name[__NI_DHCP_STATE_MAX] = {
 [NI_DHCP_STATE_INIT]		= "INIT",
 [NI_DHCP_STATE_SELECTING]	= "SELECTING",
 [NI_DHCP_STATE_REQUESTING]	= "REQUESTING",
 [NI_DHCP_STATE_VALIDATING]	= "VALIDATING",
 [NI_DHCP_STATE_BOUND]		= "BOUND",
 [NI_DHCP_STATE_RENEWING]	= "RENEWING",
 [NI_DHCP_STATE_REBINDING]	= "REBINDING",
 [NI_DHCP_STATE_REBOOT]		= "REBOOT",
 [NI_DHCP_STATE_RENEW_REQUESTED]= "RENEW_REQUESTED",
 [NI_DHCP_STATE_RELEASED]	= "RELEASED",
};

const char *
ni_dhcp_fsm_state_name(int state)
{
	const char *name = NULL;

	if (0 <= state && state < __NI_DHCP_STATE_MAX)
		name = __dhcp_state_name[state];
	return name? name : "UNKNOWN STATE";
}
