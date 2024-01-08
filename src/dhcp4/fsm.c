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

#include "dhcp4/dhcp4.h"
#include "dhcp4/protocol.h"


static ni_bool_t		ni_dhcp4_address_on_link(ni_dhcp4_device_t *, struct in_addr);
static int			ni_dhcp4_fsm_arp_validate(ni_dhcp4_device_t *);

static int			ni_dhcp4_process_offer(ni_dhcp4_device_t *, ni_addrconf_lease_t *);
static int			ni_dhcp4_process_ack(ni_dhcp4_device_t *, ni_addrconf_lease_t *);
static int			ni_dhcp4_process_nak(ni_dhcp4_device_t *);
static void			ni_dhcp4_fsm_fail_lease(ni_dhcp4_device_t *);
static int			ni_dhcp4_fsm_validate_lease(ni_dhcp4_device_t *, ni_addrconf_lease_t *);

static void			ni_dhcp4_send_event(enum ni_dhcp4_event, ni_dhcp4_device_t *, ni_addrconf_lease_t *);
static void			__ni_dhcp4_fsm_timeout(void *, const ni_timer_t *);

static ni_timeout_param_t *	ni_dhcp4_timeout_param_init_increment(ni_timeout_param_t *,
									unsigned int);
static ni_timeout_param_t *	ni_dhcp4_timeout_param_init_decrement(ni_timeout_param_t *,
									unsigned int);
static void			ni_dhcp4_timeout_param_trace(const char *, const char *,
							const ni_timeout_param_t *,
							unsigned int, ni_timeout_t);

static unsigned int		ni_dhcp4_lease_lifetime(const ni_addrconf_lease_t *,
							const struct timeval *);
static unsigned int		ni_dhcp4_lease_rebind_time(const ni_addrconf_lease_t *,
							const struct timeval *);
static unsigned int		ni_dhcp4_lease_renewal_time(const ni_addrconf_lease_t *,
							const struct timeval *);


static ni_dhcp4_event_handler_t *ni_dhcp4_fsm_event_handler;

static void
ni_dhcp4_defer_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_dhcp4_device_t *dev = user_data;

	if (dev->timer.defer != timer) {
		ni_warn("%s: bad defer timer handle", __func__);
		return;
	}
	dev->timer.defer = NULL;

	ni_note("%s: defer timeout %u reached in state %s",
		dev->ifname, dev->config->defer_timeout,
		ni_dhcp4_fsm_state_name(dev->fsm.state));

	if (dev->fsm.state == NI_DHCP4_STATE_REBOOT &&
	    ni_dhcp4_lease_lifetime(dev->lease, NULL)) {

		if (ni_dhcp4_fsm_validate_lease(dev, dev->lease))
			ni_dhcp4_fsm_commit_lease(dev, dev->lease);
	} else {
		ni_dhcp4_send_event(NI_DHCP4_EVENT_DEFERRED, dev, NULL);
	}
}

static void
ni_dhcp4_acquire_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_dhcp4_device_t *dev = user_data;

	if (dev->timer.acquire != timer) {
		ni_warn("%s: bad acquire timer handle", __func__);
		return;
	}
	dev->timer.acquire = NULL;

	ni_note("%s: acquire timeout %u reached in state %s",
		dev->ifname, dev->config->acquire_timeout,
		ni_dhcp4_fsm_state_name(dev->fsm.state));

	dev->fsm.state = NI_DHCP4_STATE_INIT;
	dev->dhcp4.xid = 0;

	ni_dhcp4_device_drop_best_offer(dev);
	ni_dhcp4_device_drop_lease(dev);
	ni_dhcp4_device_stop(dev);

	ni_dhcp4_send_event(NI_DHCP4_EVENT_LOST, dev, NULL);
}

ni_bool_t
ni_dhcp4_defer_timer_arm(ni_dhcp4_device_t *dev)
{
	ni_timeout_t timeout;

	if (!dev || !dev->config || !dev->config->defer_timeout)
		return FALSE;

	timeout = NI_TIMEOUT_FROM_SEC(dev->config->defer_timeout);
	if (!dev->timer.defer || !ni_timer_rearm(dev->timer.defer, timeout)) {
		dev->timer.defer = NULL;
		return !!ni_dhcp4_timer_arm(&dev->timer.defer, timeout,
				ni_dhcp4_defer_timeout, dev);
	}

	return TRUE;
}

ni_bool_t
ni_dhcp4_acquire_timer_arm(ni_dhcp4_device_t *dev)
{
	ni_timeout_t timeout;

	if (!dev || !dev->config || !dev->config->acquire_timeout)
		return FALSE;

	timeout = NI_TIMEOUT_FROM_SEC(dev->config->acquire_timeout);
	if (!dev->timer.acquire || !ni_timer_rearm(dev->timer.acquire, timeout)) {
		dev->timer.acquire = NULL;
		return !!ni_dhcp4_timer_arm(&dev->timer.acquire, timeout,
				ni_dhcp4_acquire_timeout, dev);
	}
	return TRUE;
}

int
ni_dhcp4_fsm_process_dhcp4_packet(ni_dhcp4_device_t *dev, ni_buffer_t *msgbuf, ni_sockaddr_t *from)
{
	ni_dhcp4_message_t *message;
	ni_addrconf_lease_t *lease = NULL;
	const char *sender = NULL;
	int msg_code;

	if (dev->fsm.state == NI_DHCP4_STATE_VALIDATING) {
		/* We arrive here, when some dhcp4 packet arrives after
		 * we've got and processed an ACK already. Just ignore.
		 */
		sender = ni_capture_from_hwaddr_print(from);
		ni_debug_dhcp("%s: ignoring dhcp4 packet%s%s arrived in state VALIDATING",
				dev->ifname, sender ? " from " : "", sender ? sender : "");
		return -1;
	}

	if (!(message = ni_buffer_pull_head(msgbuf, sizeof(*message)))) {
		sender = ni_capture_from_hwaddr_print(from);
		ni_debug_dhcp("%s: short dhcp4 packet (%zu bytes)%s%s", dev->ifname,
				ni_buffer_count(msgbuf),
				sender ? " sender " : "", sender ? sender : "");
		return -1;
	}
	if (dev->dhcp4.xid == 0) {
		sender = ni_capture_from_hwaddr_print(from);
		ni_debug_dhcp("%s: unexpected packet with 0 xid%s%s", dev->ifname,
				sender ? " sender " : "", sender ? sender : "");
		return -1;
	}
	if (dev->dhcp4.xid != ntohl(message->xid)) {
		sender = ni_capture_from_hwaddr_print(from);
		ni_debug_dhcp("%s: ignoring packet with wrong xid 0x%x (expected 0x%x)%s%s",
				dev->ifname, ntohl(message->xid), dev->dhcp4.xid,
				sender ? " sender " : "", sender ? sender : "");
		return -1;
	}

	msg_code = ni_dhcp4_parse_response(dev->config, message, msgbuf, &lease);
	sender = ni_capture_from_hwaddr_print(from);
	if (msg_code < 0) {
		/* Ignore this message, time out later */
		ni_error("%s: unable to parse DHCP4 response%s%s", dev->ifname,
				sender ? " sender " : "", sender ? sender : "");
		return -1;
	}
	ni_string_dup(&lease->dhcp4.sender_hwa, sender);
	sender = lease->dhcp4.sender_hwa;

	/*
	 * The lease lifetime starts at the original request send time.
	 *
	 * See https://www.rfc-editor.org/rfc/rfc2131#section-4.4.1
	 *   The client records the lease expiration time as the sum
	 *   of the time at which the original request was sent and
	 *   the duration of the lease from the DHCPACK message.
	 */
	lease->acquired = dev->transmit.start;

	if (dev->config->client_id.len && !lease->dhcp4.client_id.len) {
		/*
		 * https://tools.ietf.org/html/rfc6842:
		 *
		 *   If the 'client identifier' option is present in a message received
		 *   from a client, the server MUST return the 'client identifier' option,
		 *   unaltered, in its response message.
		 *
		 * Often (as of now) servers don't send it back, even the hlen was 0 and
		 * the client sent a client-id, causing that the client has only xid to
		 * identify responses to it's own messages.
		 * Servers not sending it back risk, that a relay agent drops responses
		 * with hlen 0 and without client-id as permitted by RFC2131 (MAY).
		 *
		 * Infiniband, ppp, ... don't have hwaddr or don't set it as it does not
		 * fit into the dhcp4 chaddr field and use client-id only instead.
		 */
		ni_debug_dhcp("%s: server does not send client-id back", dev->ifname);
	} else
	if (lease->dhcp4.client_id.len &&
	    !ni_opaque_eq(&dev->config->client_id, &lease->dhcp4.client_id)) {
		/*
		 * https://tools.ietf.org/html/rfc6842:
		 *
		 *   When a client receives a DHCP message containing a 'client
		 *   identifier' option, the client MUST compare that client
		 *   identifier to the one it is configured to send.
		 *   If the two client identifiers do not match, the client MUST
		 *   silently discard the message.
		 */
		ni_debug_dhcp("%s: ignoring packet with not matching client-id%s%s",
				dev->ifname, sender ? " sender " : "", sender ? sender : "");
		ni_addrconf_lease_free(lease);
		return -1;
	}

	ni_debug_dhcp("%s: received %s message xid 0x%x in state %s%s%s",
			dev->ifname, ni_dhcp4_message_name(msg_code), ntohl(message->xid),
			ni_dhcp4_fsm_state_name(dev->fsm.state),
			sender ? " sender " : "", sender ? sender : "");

	if (lease->dhcp4.client_id.len) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: and matching client id %s", dev->ifname,
				ni_print_hex(lease->dhcp4.client_id.data,
						lease->dhcp4.client_id.len));
	}

	/* set request client-id in the response early to have it in test mode */
	if (!lease->dhcp4.client_id.len && dev->config->client_id.len) {
		ni_opaque_set(&lease->dhcp4.client_id,	dev->config->client_id.data,
							dev->config->client_id.len);
	}


	/* When receiving a DHCP4 OFFER, verify sender address against list of
	 * servers to ignore, and preferred servers. */
	if (msg_code == DHCP4_OFFER && dev->fsm.state == NI_DHCP4_STATE_SELECTING) {
		struct in_addr srv_addr = lease->dhcp4.server_id;
		const char *ipaddr = inet_ntoa(srv_addr);
		ni_hwaddr_t hwaddr;
		int weight = 0;

		if (sender && ni_dhcp4_config_ignore_server(sender)) {
			ni_debug_dhcp("%s: ignoring DHCP4 offer from %s%s%s%s (blacklisted)",
					dev->ifname, inet_ntoa(srv_addr),
					sender ? " (" : "",
					sender ? sender : "",
					sender ? ")" : "");
			goto out;
		}
		if (ipaddr && ni_dhcp4_config_ignore_server(ipaddr)) {
			ni_debug_dhcp("%s: ignoring DHCP4 offer from %s%s%s%s (blacklisted)",
					dev->ifname, inet_ntoa(srv_addr),
					sender ? " (" : "",
					sender ? sender : "",
					sender ? ")" : "");
			goto out;
		}

		/* If we're scanning all offers, we need to decide whether
		 * this offer is accepted, or whether we want to wait for
		 * more.
		 */
		if (!dev->dhcp4.accept_any_offer) {

			/* Check if we have any preferred servers. */
			ni_capture_from_hwaddr_set(&hwaddr, from);
			if (!(weight = ni_dhcp4_config_server_preference_ipaddr(srv_addr)))
				weight = ni_dhcp4_config_server_preference_hwaddr(&hwaddr);

			/* If we're refreshing an existing lease (eg after link disconnect
			 * and reconnect), we accept the offer if it comes from the same
			 * server as the original one.
			 */
			if (dev->lease
			 && dev->lease->dhcp4.server_id.s_addr == srv_addr.s_addr)
				weight = 100;

			ni_debug_dhcp("%s: received lease offer from %s; server weight=%d (best offer=%d)",
					dev->ifname, inet_ntoa(lease->dhcp4.server_id),
					weight,	dev->best_offer.weight);

			/* negative weight means never. */
			if (weight < 0)
				goto out;

			/* weight between 0 and 100 means maybe. */
			if (weight < 100) {
				if (dev->best_offer.weight < weight) {
					ni_dhcp4_device_set_best_offer(dev, &lease, weight);
					return 0;
				}
				/* OK, but it is not better than previous */
			} else {
				/* If the weight has maximum value, just accept this offer. */
				ni_dhcp4_device_set_best_offer(dev, &lease, weight);
			}
		} else {
			ni_dhcp4_device_set_best_offer(dev, &lease, weight);
		}
	}

	/* We've received a valid response; if something goes wrong now
	 * it's nothing that could be fixed by retransmitting the message.
	 *
	 * An exception is the best-offer filtering above, but it's done.
	 */
	ni_dhcp4_device_disarm_retransmit(dev);

	/* move to next stage of protocol */
	switch (msg_code) {
	case DHCP4_OFFER:
		switch (dev->fsm.state) {
		case NI_DHCP4_STATE_SELECTING:
			/* process best offer set above */
			ni_dhcp4_process_offer(dev, dev->best_offer.lease);
			break;
		case NI_DHCP4_STATE_INIT:
		case NI_DHCP4_STATE_REQUESTING:
		case NI_DHCP4_STATE_VALIDATING:
		case NI_DHCP4_STATE_BOUND:
		case NI_DHCP4_STATE_RENEWING:
		case NI_DHCP4_STATE_REBINDING:
		case NI_DHCP4_STATE_REBOOT:
		case NI_DHCP4_STATE_DOWN:
		case __NI_DHCP4_STATE_MAX:
			goto ignore;
		}
		break;

	case DHCP4_ACK:
		switch (dev->fsm.state) {
		case NI_DHCP4_STATE_INIT:
			/*
			 * Received a decline ACK -- wait until
			 * timeout before we restart from begin
			 */
			ni_dhcp4_device_drop_lease(dev);
			break;
		case NI_DHCP4_STATE_REQUESTING:
		case NI_DHCP4_STATE_RENEWING:
		case NI_DHCP4_STATE_REBINDING:
		case NI_DHCP4_STATE_REBOOT:
			if (ni_dhcp4_process_ack(dev, lease) < 0)
				goto ignore;
			break;
		case NI_DHCP4_STATE_SELECTING:
		case NI_DHCP4_STATE_VALIDATING:
		case NI_DHCP4_STATE_BOUND:
		case NI_DHCP4_STATE_DOWN:
		case __NI_DHCP4_STATE_MAX:
			goto ignore;
		}
		break;

	case DHCP4_NAK:
		switch (dev->fsm.state) {
		case NI_DHCP4_STATE_SELECTING:
		case NI_DHCP4_STATE_BOUND:
			/* The RFC 2131 state diagram says, ignore NAKs in state BOUND.
			 * I guess we also have no use for NAK replies to a DHCP4_DISCOVER
			 */
			goto ignore;
		case NI_DHCP4_STATE_INIT:
		case NI_DHCP4_STATE_REQUESTING:
		case NI_DHCP4_STATE_VALIDATING:
		case NI_DHCP4_STATE_RENEWING:
		case NI_DHCP4_STATE_REBINDING:
		case NI_DHCP4_STATE_REBOOT:
		case NI_DHCP4_STATE_DOWN:
		case __NI_DHCP4_STATE_MAX:
			ni_dhcp4_process_nak(dev);
		}
		break;
	default:
	ignore:
		ni_debug_dhcp("%s: ignoring %s in state %s", dev->ifname,
				ni_dhcp4_message_name(msg_code),
				ni_dhcp4_fsm_state_name(dev->fsm.state));
		break;
	}

out:
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
	ni_dhcp4_timer_disarm(&dev->fsm.timer);

	dev->dhcp4.xid = 0;

	ni_dhcp4_device_drop_lease(dev);
}

static void
ni_dhcp4_fsm_set_timeout_msec(ni_dhcp4_device_t *dev, ni_timeout_t msec)
{
	ni_debug_dhcp("%s: setting fsm timeout to %u.%03u sec", dev->ifname,
			NI_TIMEOUT_SEC(msec), NI_TIMEOUT_MSEC(msec));
	if (dev->fsm.timer)
		ni_timer_rearm(dev->fsm.timer, msec);
	else
		ni_dhcp4_timer_arm(&dev->fsm.timer, msec, __ni_dhcp4_fsm_timeout, dev);
}

static void
ni_dhcp4_fsm_set_timeout_sec(ni_dhcp4_device_t *dev, unsigned int seconds)
{
	ni_dhcp4_fsm_set_timeout_msec(dev, NI_TIMEOUT_FROM_SEC(seconds));
}

unsigned int
ni_dhcp4_fsm_start_delay(unsigned int start_delay)
{
	ni_int_range_t range = {
		.min = min_t(unsigned int, start_delay, NI_DHCP4_START_DELAY_MIN),
		.max = min_t(unsigned int, start_delay, NI_DHCP4_START_DELAY_MAX),
	};
	unsigned int sec = min_t(unsigned int, start_delay, NI_DHCP4_START_DELAY_MIN);
	return ni_timeout_randomize(sec, &range);
}

static ni_bool_t
ni_dhcp4_fsm_discover(ni_dhcp4_device_t *dev)
{
	ni_addrconf_lease_t *lease;

	/* If we already have a lease, try asking for the same.
	 * If not, create a dummy lease with NULL fields.
	 */
	if ((lease = ni_addrconf_lease_clone(dev->lease)))
		dev->lease->uuid = dev->config->uuid;
	else
	if (!(lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET)))
		return FALSE;

	lease->uuid = dev->config->uuid;
	lease->fqdn.enabled = NI_TRISTATE_DEFAULT;
	lease->fqdn.qualify = dev->config->fqdn.qualify;
	ni_string_free(&lease->hostname);

	dev->fsm.state = NI_DHCP4_STATE_SELECTING;
	ni_dhcp4_new_xid(dev);

	/*
	 * Try to get the same/preferred lease until 1st resend
	 * timeout (- jitter) and fall back to ask for any after.
	 */
	ni_timer_get_time(&dev->start_time);
	dev->transmit.start = dev->start_time;
	ni_dhcp4_timeout_param_init_increment(&dev->transmit.params, NI_LIFETIME_INFINITE);
	ni_dhcp4_timeout_param_trace(dev->ifname, "discover",
			&dev->transmit.params, NI_LIFETIME_INFINITE, 0);

	if (ni_addrconf_lease_is_valid(dev->lease) ||
	    ni_dhcp4_config_have_server_preference()) {
		dev->dhcp4.accept_any_offer = 0;
		ni_dhcp4_fsm_set_timeout_sec(dev, NI_DHCP4_RESEND_TIMEOUT_INIT - 1);
	} else {
		dev->dhcp4.accept_any_offer = 1;
		ni_dhcp4_fsm_set_timeout_sec(dev, NI_DHCP4_DISCOVER_RESTART);
	}
	ni_debug_dhcp("valid lease: %d; have prefs: %d, accept any: %s",
			ni_addrconf_lease_is_valid(dev->lease),
			ni_dhcp4_config_have_server_preference(),
			ni_format_boolean(dev->dhcp4.accept_any_offer));

	ni_info("%s: Initiating DHCPv4 discovery", dev->ifname);
	ni_dhcp4_device_drop_best_offer(dev);

	ni_dhcp4_device_send_message_broadcast(dev, DHCP4_DISCOVER, lease);
	ni_addrconf_lease_free(lease);
	return TRUE;

}

static ni_bool_t
ni_dhcp4_fsm_request(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (!lease)
		return FALSE;

	/*
	 * https://www.rfc-editor.org/rfc/rfc2131#section-3.1, 3.:
	 *
	 *   DHCPREQUEST message MUST use the same value in the DHCP message
	 *   header's 'secs' field and be sent to the same IP broadcast
	 *   address as the original DHCPDISCOVER message.
	 *
	 * https://www.rfc-editor.org/rfc/rfc2131#section-4.4.1
	 *
	 *   The DHCPREQUEST message contains the same 'xid' as the DHCPOFFER
	 *   message. The client records the lease expiration time as the sum
	 *   of the time at which the original request was sent and the
	 *   duration of the lease from the DHCPACK message.
	 *
	 * Thus we do not update start_time used for 'secs' nor set new 'xid'
	 * and use the transmit.start time for lease->acquired time in ack().
	 */
	ni_timer_get_time(&dev->transmit.start);
	ni_dhcp4_timeout_param_init_increment(&dev->transmit.params,
						NI_DHCP4_REQUEST_TIMEOUT);
	ni_dhcp4_timeout_param_trace(dev->ifname, "request",
			&dev->transmit.params, NI_DHCP4_REQUEST_TIMEOUT, 0);

	ni_info("%s: Initiating request of DHCPv4 lease", dev->ifname);
	dev->fsm.state = NI_DHCP4_STATE_REQUESTING;

	ni_dhcp4_fsm_set_timeout_sec(dev, NI_DHCP4_REQUEST_TIMEOUT);
	ni_dhcp4_device_send_message_broadcast(dev, DHCP4_REQUEST, lease);
	return TRUE;
}

static ni_bool_t
ni_dhcp4_fsm_renewal_retransmit(ni_dhcp4_device_t *dev)
{
	ni_timeout_t timeout;
	struct timeval now;
	unsigned int lft;

	if (!dev->lease)
		return FALSE;

	if (!ni_timeout_recompute(&dev->transmit.params))
		return FALSE; /* nretries limit reached */

	ni_timer_get_time(&now);
	lft = ni_dhcp4_lease_rebind_time(dev->lease, &now);
	if (lft == NI_LIFETIME_EXPIRED)
		return FALSE;

	timeout = min_t(ni_timeout_t, (ni_timeout_t)lft, ni_timeout_randomize(
			dev->transmit.params.timeout, &dev->transmit.params.jitter
	));
	if (timeout == (ni_timeout_t)NI_LIFETIME_EXPIRED)
		return FALSE;

	ni_info("%s: Retransmitting renewal of DHCPv4 lease", dev->ifname);
	ni_dhcp4_fsm_set_timeout_sec(dev, timeout);
	ni_dhcp4_device_send_message_unicast(dev, DHCP4_REQUEST, dev->lease);
	return TRUE;
}

static ni_bool_t
ni_dhcp4_fsm_renewal_init(ni_dhcp4_device_t *dev)
{
	ni_timeout_t timeout;
	unsigned int lft;

	if (!dev->lease)
		return FALSE;

	/*
	 * https://www.rfc-editor.org/rfc/rfc2131#section-4.4.5
	 *
	 * In both RENEWING and REBINDING states, if the client receives no
	 * response to its DHCPREQUEST message, the client SHOULD wait
	 * one-half of the remaining time until T2 (in RENEWING state) [...]
	 * down to a minimum of 60 seconds, before retransmitting [...]
	 *
	 * We're using NI_DHCP4_RESEND_TIMEOUT_INIT (4 seconds) minimum
	 * instead of 60 seconds.
	 */
	ni_timer_get_time(&dev->start_time);
	lft = ni_dhcp4_lease_rebind_time(dev->lease, &dev->start_time);
	if (lft == NI_LIFETIME_EXPIRED)
		return FALSE;

	dev->transmit.start = dev->start_time;
	ni_dhcp4_timeout_param_init_decrement(&dev->transmit.params, lft >> 1);
	timeout = ni_timeout_randomize(dev->transmit.params.timeout,
			&dev->transmit.params.jitter);

	ni_dhcp4_timeout_param_trace(dev->ifname, "renewal",
			&dev->transmit.params, lft, timeout);
	if (timeout == (ni_timeout_t)NI_LIFETIME_EXPIRED)
		return FALSE;

	/* Init xid, state and send renewal request */
	dev->fsm.state = NI_DHCP4_STATE_RENEWING;
	ni_dhcp4_new_xid(dev);

	ni_info("%s: Initiating renewal of DHCPv4 lease", dev->ifname);
	ni_dhcp4_fsm_set_timeout_sec(dev, timeout);
	ni_dhcp4_device_send_message_unicast(dev, DHCP4_REQUEST, dev->lease);
	return TRUE;
}

static ni_bool_t
ni_dhcp4_fsm_rebind(ni_dhcp4_device_t *dev)
{
	unsigned int lft;

	if (!dev->lease)
		return FALSE;

	/*
	 * https://www.rfc-editor.org/rfc/rfc2131#section-4.4.5
	 *
	 * In both RENEWING and REBINDING states, if the client receives no
	 * response to its DHCPREQUEST message, the client SHOULD wait [...]
	 * one-half of the remaining lease time (in REBINDING state),
	 * down to a minimum of 60 seconds, before retransmitting [...]
	 *
	 * We're using NI_DHCP4_RESEND_TIMEOUT_INIT (4 seconds) minimum
	 * instead of 60 seconds.
	 */
	ni_timer_get_time(&dev->start_time);
	lft = ni_dhcp4_lease_lifetime(dev->lease, &dev->start_time);
	if (lft == NI_LIFETIME_EXPIRED)
		return FALSE;

	dev->transmit.start = dev->start_time;
	ni_dhcp4_timeout_param_init_decrement(&dev->transmit.params, lft >> 1);
	ni_dhcp4_timeout_param_trace(dev->ifname, "rebind",
			&dev->transmit.params, lft, 0);

	/* Init xid, state and send rebind request */
	dev->fsm.state = NI_DHCP4_STATE_REBINDING;
	ni_dhcp4_new_xid(dev);

	ni_info("%s: Initiating rebind of DHCPv4 lease", dev->ifname);
	ni_dhcp4_fsm_set_timeout_sec(dev, lft);
	ni_dhcp4_device_send_message_broadcast(dev, DHCP4_REQUEST, dev->lease);
	return TRUE;
}

static ni_bool_t
ni_dhcp4_fsm_reboot_request(ni_dhcp4_device_t *dev)
{
	ni_addrconf_lease_t *lease;
	unsigned int lft;

	if ((lease = ni_addrconf_lease_clone(dev->lease)))
		dev->lease->uuid = dev->config->uuid;
	else
		return FALSE;

	lease->uuid = dev->config->uuid;
	lease->fqdn.enabled = NI_TRISTATE_DEFAULT;
	lease->fqdn.qualify = dev->config->fqdn.qualify;
	ni_string_free(&lease->hostname);

	/*
	 * Retransmit until reboot timeout or lease expires.
	 *
	 * On (user) ifup aka acquire call and not responding dhcp server,
	 * we'll enter bound state earlier via defer timeout (15 sec).
	 */
	ni_timer_get_time(&dev->start_time);
	lft = min_t(unsigned int, NI_DHCP4_REBOOT_TIMEOUT,
			ni_dhcp4_lease_lifetime(lease, &dev->start_time)
	);

	dev->transmit.start = dev->start_time;
	ni_dhcp4_timeout_param_init_increment(&dev->transmit.params, lft);
	ni_dhcp4_timeout_param_trace(dev->ifname, "reboot",
			&dev->transmit.params, lft, 0);
	if (lft == NI_LIFETIME_EXPIRED) {
		ni_addrconf_lease_free(lease);
		return FALSE;
	}

	/* Init xid, state and send reboot request */
	dev->fsm.state = NI_DHCP4_STATE_REBOOT;
	ni_dhcp4_new_xid(dev);

	ni_info("%s: Initiating reboot confirmation of DHCPv4 lease", dev->ifname);
	ni_dhcp4_fsm_set_timeout_sec(dev, lft);
	ni_dhcp4_device_send_message_broadcast(dev, DHCP4_REQUEST, lease);
	ni_addrconf_lease_free(lease);
	return TRUE;
}

static void
ni_dhcp4_fsm_reboot_dad_success(ni_dhcp4_device_t *dev)
{
	dev->link.reconnect = FALSE;
	if (!ni_dhcp4_fsm_reboot_request(dev)) {
		ni_dhcp4_device_drop_lease(dev);
		ni_dhcp4_fsm_discover(dev);
	}
}

static void
ni_dhcp4_fsm_reboot_dad_failure(ni_dhcp4_device_t *dev)
{
	if (dev->lease) {
		ni_addrconf_lease_file_remove(dev->ifname,
				dev->lease->type, dev->lease->family);
		ni_dhcp4_fsm_fail_lease(dev);
	}
	ni_dhcp4_fsm_discover(dev);
}

static ni_bool_t
ni_dhcp4_fsm_reboot_dad_validate(ni_dhcp4_device_t *dev)
{
	const ni_config_arp_t *arpcfg = ni_config_addrconf_arp(NI_ADDRCONF_DHCP, dev->ifname);

	if (!(dev->config->doflags & DHCP4_DO_ARP)) {
		ni_debug_dhcp("%s: arp validation disabled", dev->ifname);
		return FALSE;
	}

	if (!ni_dhcp4_address_on_link(dev, dev->lease->dhcp4.address)) {
		ni_debug_dhcp("%s: address %s is not on link, omit validation",
				dev->ifname, inet_ntoa(dev->lease->dhcp4.address));
		return FALSE;
	}

	ni_info("%s: Validating DHCPv4 address %s",
			dev->ifname, inet_ntoa(dev->lease->dhcp4.address));

	ni_arp_verify_reset(&dev->arp.verify, &arpcfg->verify);
	if (!ni_arp_verify_add_in_addr(&dev->arp.verify, dev->lease->dhcp4.address)) {
		ni_error("%s: unable to add IP address %s to arp verify", dev->ifname,
				inet_ntoa(dev->lease->dhcp4.address));
		return FALSE;
	}

	dev->arp.dad_success  = ni_dhcp4_fsm_reboot_dad_success;
	dev->arp.dad_failure  = ni_dhcp4_fsm_reboot_dad_failure;

	dev->fsm.state = NI_DHCP4_STATE_VALIDATING;

	if (ni_dhcp4_fsm_arp_validate(dev) < 0) {
		ni_debug_dhcp("%s: unable to validate lease", dev->ifname);
		ni_arp_verify_destroy(&dev->arp.verify);
		return FALSE;
	}
	return TRUE;
}

static ni_bool_t
ni_dhcp4_fsm_reboot(ni_dhcp4_device_t *dev)
{
	unsigned int lft;

	if (!dev->lease)
		return FALSE;

	/*
	 * Retransmit until reboot timeout or lease expires.
	 *
	 * On (user) ifup aka acquire call and not responding dhcp server,
	 * we'll enter bound state earlier via defer timeout (15 sec).
	 */
	ni_timer_get_time(&dev->start_time);
	lft = min_t(unsigned int, NI_DHCP4_REBOOT_TIMEOUT,
			ni_dhcp4_lease_lifetime(dev->lease, &dev->start_time)
	);
	if (lft == NI_LIFETIME_EXPIRED)
		return FALSE;

	if (dev->link.reconnect && ni_dhcp4_fsm_reboot_dad_validate(dev))
		return TRUE;

	return ni_dhcp4_fsm_reboot_request(dev);
}

static ni_bool_t
ni_dhcp4_fsm_decline(ni_dhcp4_device_t *dev)
{
	if (!dev->lease)
		return FALSE;

	ni_timer_get_time(&dev->start_time);
	dev->transmit.start = dev->start_time;
	ni_dhcp4_timeout_param_init_increment(&dev->transmit.params, 0);
	ni_dhcp4_timeout_param_trace(dev->ifname, "decline",
			&dev->transmit.params, 0, 0);

	/*
	 * there is actually no decline state; we send the decline message
	 * and enter init -> selecting state after decline backoff is over.
	 */
	dev->fsm.state = NI_DHCP4_STATE_INIT;
	ni_dhcp4_new_xid(dev);

	ni_warn("%s: Declining DHCPv4 lease with address %s", dev->ifname,
			inet_ntoa(dev->lease->dhcp4.address));

	/*
	 * RFC 2131 3.1: "5. [...] The client SHOULD wait a minimum of
	 * ten seconds before restarting the configuration process to
	 * avoid excessive network traffic in case of looping."
	 *
	 * RFC 2131 4.3.3: "If the server receives a DHCPDECLINE message
	 * [...] The server MUST mark the network address as not available
	 * and SHOULD notify the local system administrator of a possible
	 * configuration problem."
	 *
	 * That is, server will offer a different address from it's pool
	 * next time (SHOULD, but is not required to verify them) or in
	 * case of static lease reserved for _this_ client, we'll get the
	 * same address again and again. In such cases, either an another
	 * client is wrongly using the address (or the clients are using
	 * the same dhcp identity) or the server is misconfigured and we
	 * need to retry getting an address until this issue is fixed.
	 *
	 * We may make the backoff configurable and/or increment it...
	 */

	ni_dhcp4_fsm_set_timeout_sec(dev, NI_DHCP4_DECLINE_BACKOFF);
	ni_dhcp4_device_send_message_broadcast(dev, DHCP4_DECLINE, dev->lease);
	return TRUE;
}

void
ni_dhcp4_fsm_release(ni_dhcp4_device_t *dev)
{
	if (dev->config == NULL || dev->lease == NULL)
		return;
	if (dev->config->release_lease) {
		ni_debug_dhcp("%s: releasing lease", dev->ifname);

		ni_timer_get_time(&dev->start_time);
		dev->transmit.start = dev->start_time;
		ni_dhcp4_timeout_param_init_increment(&dev->transmit.params, 0);
		ni_dhcp4_timeout_param_trace(dev->ifname, "release",
				&dev->transmit.params, 0, 0);

		ni_dhcp4_device_send_message_broadcast(dev, DHCP4_RELEASE, dev->lease);
		ni_dhcp4_fsm_commit_lease(dev, NULL);
	} else {
		ni_dhcp4_send_event(NI_DHCP4_EVENT_RELEASED, dev, dev->lease);
		ni_dhcp4_device_drop_lease(dev);
		ni_dhcp4_fsm_restart(dev);
	}
}

void
ni_dhcp4_fsm_release_init(ni_dhcp4_device_t *dev)
{
	/* there is currently no releasing state... */
	dev->fsm.state = NI_DHCP4_STATE_INIT;
	ni_dhcp4_new_xid(dev);
	ni_dhcp4_fsm_release(dev);
}

/*
 * We never received any response. Deal with the traumatic rejection.
 */
static void
ni_dhcp4_fsm_timeout(ni_dhcp4_device_t *dev)
{
	ni_dhcp4_config_t *conf = dev->config;
	unsigned int lft;

	ni_debug_dhcp("%s: timeout in state %s",
			dev->ifname, ni_dhcp4_fsm_state_name(dev->fsm.state));

	switch (dev->fsm.state) {
	case NI_DHCP4_STATE_INIT:
		/* We get here if we previously received a NAK, and have
		 * started to back off, or if we declined a lease because
		 * the address was already in use. */
		ni_dhcp4_device_drop_lease(dev);
		ni_dhcp4_fsm_discover(dev);
		break;

	case NI_DHCP4_STATE_SELECTING:
		/*
		 * When we have an offer from prefered server (e.g. same lease),
		 * take it -- otherwise evaluate to accept any other offer.
		 */
		if (dev->best_offer.lease) {
			ni_debug_dhcp("accepting lease offer from %s; server weight=%d",
					inet_ntoa(dev->best_offer.lease->dhcp4.server_id),
					dev->best_offer.weight);
			ni_dhcp4_process_offer(dev, dev->best_offer.lease);
			return;
		} else if (!dev->dhcp4.accept_any_offer) {
			ni_debug_dhcp("%s: discovery got no preferred lease, accept any",
					dev->ifname);
		}

		dev->dhcp4.accept_any_offer = 1;
		if ((lft = ni_lifetime_left(NI_DHCP4_DISCOVER_RESTART,
						&dev->start_time, NULL)))
			ni_dhcp4_fsm_set_timeout_sec(dev, lft);
		else
			ni_dhcp4_fsm_discover(dev);
		break;

	case NI_DHCP4_STATE_REQUESTING:
		ni_warn("%s: DHCP4 lease offer request failed", dev->ifname);

		ni_dhcp4_fsm_restart(dev);
		ni_dhcp4_fsm_set_timeout_sec(dev, ni_dhcp4_fsm_start_delay(conf->start_delay));
		break;

	case NI_DHCP4_STATE_VALIDATING:
		/* Send the next ARP probe */
		ni_dhcp4_fsm_arp_validate(dev);
		break;

	case NI_DHCP4_STATE_BOUND:
		if (ni_dhcp4_fsm_renewal_init(dev))
			return;

		if (ni_dhcp4_fsm_rebind(dev))
			return;

		ni_dhcp4_fsm_fail_lease(dev);
		ni_dhcp4_fsm_set_timeout_sec(dev, ni_dhcp4_fsm_start_delay(conf->start_delay));
		break;

	case NI_DHCP4_STATE_RENEWING:
		if (ni_dhcp4_fsm_renewal_retransmit(dev))
			return;

		ni_warn("%s: unable to renew lease; trying to rebind",
				dev->ifname);

		if (ni_dhcp4_fsm_rebind(dev))
			return;

		ni_warn("%s: unable to init lease rebind; restarting to discover new",
				dev->ifname);

		ni_dhcp4_fsm_fail_lease(dev);
		ni_dhcp4_fsm_set_timeout_sec(dev, ni_dhcp4_fsm_start_delay(conf->start_delay));
		break;

	case NI_DHCP4_STATE_REBINDING:
		ni_warn("%s: unable to rebind lease; restarting to discover new",
				dev->ifname);

		ni_dhcp4_fsm_fail_lease(dev);
		ni_dhcp4_fsm_set_timeout_sec(dev, ni_dhcp4_fsm_start_delay(conf->start_delay));
		break;

	case NI_DHCP4_STATE_REBOOT:
		ni_warn("%s: unable to confirm lease; restarting to discover new",
				dev->ifname);

		if (ni_dhcp4_lease_lifetime(dev->lease, NULL)) {
			if (ni_dhcp4_fsm_validate_lease(dev, dev->lease))
				ni_dhcp4_fsm_commit_lease(dev, dev->lease);
			break;
		}
		ni_dhcp4_fsm_restart(dev);
		ni_dhcp4_fsm_set_timeout_sec(dev, ni_dhcp4_fsm_start_delay(conf->start_delay));
		break;

	case NI_DHCP4_STATE_DOWN:
		/* lease expired while the link is down, remove lease from the
		 * interface and wait until [nanny] (re-)acquire request .. */
		if (!dev->lease)
			break;

		ni_debug_dhcp("%s: dropping expired lease in state %s",
				dev->ifname,
				ni_dhcp4_fsm_state_name(dev->fsm.state));

		ni_dhcp4_device_drop_lease(dev);
		ni_dhcp4_send_event(NI_DHCP4_EVENT_LOST, dev, NULL);
		break;

	case __NI_DHCP4_STATE_MAX:
		break;
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
	dev->fsm.timer = NULL;

	ni_dhcp4_fsm_timeout(dev);
}

/*
 * These functions get called when the link goes down/up.
 * We use these to be smart about renewing a lease.
 */
void
ni_dhcp4_fsm_link_up(ni_dhcp4_device_t *dev)
{
	ni_timer_get_time(&dev->start_time);

	if (dev->config == NULL)
		return;

	switch (dev->fsm.state) {
	case NI_DHCP4_STATE_INIT:
		/* We get here if we start without a valid lease. */
		ni_dhcp4_fsm_discover(dev);
		break;
	case NI_DHCP4_STATE_REBOOT:
		/* The link went down and came back up. We may now be on a
		 * completely different network, and our lease may no longer
		 * be valid.
		 * Enter reboot, which means we'll try to confirm the lease.
		 * If that fails, we drop the lease and revert to state INIT.
		 */
		if (!ni_dhcp4_fsm_reboot(dev))
			ni_dhcp4_fsm_discover(dev);
		break;
	case NI_DHCP4_STATE_SELECTING:
	case NI_DHCP4_STATE_REQUESTING:
	case NI_DHCP4_STATE_VALIDATING:
	case NI_DHCP4_STATE_BOUND:
	case NI_DHCP4_STATE_RENEWING:
	case NI_DHCP4_STATE_REBINDING:
		break;
	case NI_DHCP4_STATE_DOWN:
	case __NI_DHCP4_STATE_MAX:
		break;
	}
}

void
ni_dhcp4_fsm_link_down(ni_dhcp4_device_t *dev)
{
	unsigned int lft;

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
	case NI_DHCP4_STATE_BOUND:
	case NI_DHCP4_STATE_REBOOT:
	case NI_DHCP4_STATE_RENEWING:
	case NI_DHCP4_STATE_REBINDING:
		ni_dhcp4_device_disarm_retransmit(dev);
		ni_capture_free(dev->capture);
		dev->capture = NULL;

		ni_dhcp4_timer_disarm(&dev->fsm.timer);
		ni_dhcp4_device_arp_close(dev);
		ni_dhcp4_socket_close(dev);

		dev->fsm.state = NI_DHCP4_STATE_DOWN;
		lft = ni_dhcp4_lease_lifetime(dev->lease, NULL);
		if (lft != NI_LIFETIME_EXPIRED ||
		    lft != NI_LIFETIME_INFINITE)
			ni_dhcp4_fsm_set_timeout_sec(dev, lft);
		break;
	case NI_DHCP4_STATE_DOWN:
	case __NI_DHCP4_STATE_MAX:
		break;
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
		ni_info("%s: Requesting DHCPv4 lease offer", dev->ifname);
		ni_dhcp4_fsm_request(dev, lease);
	}
	return 0;
}

static int
ni_dhcp4_process_ack(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	struct timeval now;
	unsigned int lft;

	if (lease->dhcp4.lease_time > dev->config->max_lease_time) {
		ni_debug_dhcp("%s: clamping lease time from %u to %u sec",
				dev->ifname, lease->dhcp4.lease_time,
				dev->config->max_lease_time);

		lease->dhcp4.lease_time = dev->config->max_lease_time;
	}

	if (lease->dhcp4.lease_time == NI_LIFETIME_INFINITE) {
		if (!lease->dhcp4.rebind_time) {
			ni_debug_dhcp("%s: adjusting rebind time (T2) from %u to %s",
					dev->ifname, lease->dhcp4.rebind_time,
					ni_sprint_timeout(NI_LIFETIME_INFINITE));
			lease->dhcp4.rebind_time = NI_LIFETIME_INFINITE;
		}
		if (!lease->dhcp4.renewal_time) {
			ni_debug_dhcp("%s: adjusting renewal time (T1) from %u to %s",
					dev->ifname, lease->dhcp4.renewal_time,
					ni_sprint_timeout(NI_LIFETIME_INFINITE));
			lease->dhcp4.renewal_time = NI_LIFETIME_INFINITE;
		}
		if (lease->dhcp4.renewal_time > lease->dhcp4.rebind_time) {
			lft = (unsigned long long)lease->dhcp4.rebind_time * 8 / 14;
			ni_debug_dhcp("%s: adjusting renewal time (T1) %u greater"
					" than rebind time (T2) %u to %u",
					dev->ifname, lease->dhcp4.renewal_time,
					lease->dhcp4.rebind_time, lft);
			lease->dhcp4.renewal_time = lft;
		}
	} else {
		if (!lease->dhcp4.rebind_time ||
		     lease->dhcp4.rebind_time > lease->dhcp4.lease_time) {
			lft = (unsigned long long)lease->dhcp4.lease_time * 7 / 8;
			ni_debug_dhcp("%s: adjusting rebind time (T2) %u greater"
					" than lease time %u to %u",
					dev->ifname, lease->dhcp4.renewal_time,
					lease->dhcp4.rebind_time, lft);
			lease->dhcp4.rebind_time = lft;
		}

		if (!lease->dhcp4.renewal_time ||
		     lease->dhcp4.renewal_time > lease->dhcp4.rebind_time) {
			lft = (unsigned long long)lease->dhcp4.rebind_time * 8 / 14;
			ni_debug_dhcp("%s: adjusting renewal time (T1) %u greater"
					" than rebind time (T2) %u to %u",
					dev->ifname, lease->dhcp4.renewal_time,
					lease->dhcp4.rebind_time, lft);
			lease->dhcp4.renewal_time = lft;
		}
	}

	ni_timer_get_time(&now);
	lft = ni_dhcp4_lease_lifetime(lease, &now);
	if (lft < NI_DHCP4_LEASE_TIME_MIN) {
		if (lft == NI_LIFETIME_EXPIRED)
			ni_debug_dhcp("%s: server provided lease already expired", dev->ifname);
		else
			ni_debug_dhcp("%s: server provided lease almost expired (%u sec left)",
					dev->ifname, lft);
		return -1;
	} else if (lft == NI_LIFETIME_INFINITE) {
		ni_debug_dhcp("%s: server provided lease is valid infinitely", dev->ifname);
	} else {
		ni_debug_dhcp("%s: server provided lease is valid for %u sec", dev->ifname, lft);
	}

	/* set lease to validate and commit or decline */
	ni_dhcp4_device_set_lease(dev, lease);

	/*
	 * When we cannot init validate [arp], commit it.
	 */
	if (ni_dhcp4_fsm_validate_lease(dev, lease))
		ni_dhcp4_fsm_commit_lease(dev, lease);

	return 0;
}

int
ni_dhcp4_fsm_commit_lease(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	ni_capture_free(dev->capture);
	dev->capture = NULL;

	if (lease) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
		struct timeval now;
		unsigned int lease_time;
		unsigned int rebind_time;
		unsigned int renewal_time;

		ni_debug_dhcp("%s: committing lease", dev->ifname);
		ni_dhcp4_device_disarm_retransmit(dev);
		ni_dhcp4_device_timer_disarm(dev);

		ni_timer_get_time(&now);
		lease_time = ni_dhcp4_lease_lifetime(lease, &now);
		rebind_time = ni_dhcp4_lease_rebind_time(lease, &now);
		renewal_time = ni_dhcp4_lease_renewal_time(lease, &now);
		if (dev->config->dry_run == NI_DHCP4_RUN_NORMAL) {
			if (renewal_time != NI_LIFETIME_EXPIRED &&
			    renewal_time != NI_LIFETIME_INFINITE) {
				ni_debug_dhcp("%s: schedule lease renewal in %u seconds",
						dev->ifname, renewal_time);
				ni_dhcp4_fsm_set_timeout_sec(dev, renewal_time);
			} else
			if (rebind_time != NI_LIFETIME_EXPIRED &&
			    rebind_time != NI_LIFETIME_INFINITE) {
				renewal_time = 1; /* renew time already reached */
				ni_debug_dhcp("%s: schedule lease renewal in %u second",
						dev->ifname, renewal_time);
				ni_dhcp4_fsm_set_timeout_sec(dev, renewal_time);
			} else
			if (lease_time != NI_LIFETIME_INFINITE) {
				rebind_time = 1; /* rebind time already reached */
				ni_debug_dhcp("%s: schedule lease rebind in %u second",
						dev->ifname, rebind_time);
				ni_dhcp4_fsm_set_timeout_sec(dev, rebind_time);
			}
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
					if (dev->config->route_set_src) {
						ni_sockaddr_set_ipv4(&rp->pref_src,
							lease->dhcp4.address, 0);
					}
				}
			}
		}

		ni_dhcp4_device_set_lease(dev, lease);
		dev->fsm.state = NI_DHCP4_STATE_BOUND;
		dev->link.reconnect = FALSE;

		ni_stringbuf_printf(&buf, "%s", ni_sprint_timeout(lease_time));
		if (renewal_time != NI_LIFETIME_INFINITE)
			ni_stringbuf_printf(&buf, ", renew in %u sec", renewal_time);
		if (rebind_time != NI_LIFETIME_INFINITE)
			ni_stringbuf_printf(&buf, ", rebind in %u sec", rebind_time);

		ni_note("%s: Committed DHCPv4 lease with address %s (lease time %s)",
				dev->ifname, inet_ntoa(lease->dhcp4.address), buf.string);
		ni_stringbuf_destroy(&buf);

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

static ni_timeout_param_t *
ni_dhcp4_timeout_param_init_increment(ni_timeout_param_t *params, unsigned int lft)
{
	memset(params, 0, sizeof(*params));
	if (lft != NI_LIFETIME_EXPIRED) {
		params->nretries	= -1; /* unlimitted retries  */
		params->increment	= -1; /* exponential backoff */
		params->jitter.min	= lft > 1 ? -1 : 0;
		params->jitter.max	= lft > NI_DHCP4_RESEND_TIMEOUT_INIT ? 1 : 0;
		params->max_timeout	= NI_DHCP4_RESEND_TIMEOUT_MAX;
		params->timeout		= NI_DHCP4_RESEND_TIMEOUT_INIT;
	}
	return params;
}

static ni_timeout_param_t *
ni_dhcp4_timeout_param_init_decrement(ni_timeout_param_t *params, unsigned int lft)
{
	memset(params, 0, sizeof(*params));
	if (lft != NI_LIFETIME_EXPIRED) {
		params->nretries	= -1; /* unlimitted retries  */
		params->decrement	= -1; /* exponential backoff */
		params->jitter.min	= -1;
		params->jitter.max	=  1;
		params->min_timeout	= NI_DHCP4_RESEND_TIMEOUT_INIT;
		params->timeout		= params->min_timeout > lft
					? params->min_timeout : lft;
	}
	return params;
}

static void
ni_dhcp4_timeout_param_trace(const char *dev, const char *info,
				const ni_timeout_param_t *params,
				unsigned int lft, ni_timeout_t rt)
{
	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_DHCP)) {
		ni_trace("%s: %-8s time left : %u",     dev, info, lft);
		ni_trace("%s: param.nretries    : %d",   dev, params->nretries);
		ni_trace("%s: params.timeout    : %llu", dev, params->timeout);
		ni_trace("%s: params.jitter.min : %d",   dev, params->jitter.min);
		ni_trace("%s: params.jitter.max : %d",   dev, params->jitter.max);
		ni_trace("%s: param.increment   : %d",   dev, params->increment);
		ni_trace("%s: params.max_timeout: %llu", dev, params->max_timeout);
		ni_trace("%s: param.decrement   : %d",   dev, params->decrement);
		ni_trace("%s: params.min_timeout: %llu", dev, params->min_timeout);
		if (rt) {
			ni_trace("%s: randomized timeout: %llu", dev, rt);
		}
	}
}

static unsigned int
ni_dhcp4_lease_lifetime(const ni_addrconf_lease_t *lease, const struct timeval *now)
{
	if (lease)
		return ni_lifetime_left(lease->dhcp4.lease_time, &lease->acquired, now);
	else
		return NI_LIFETIME_EXPIRED;
}

static unsigned int
ni_dhcp4_lease_rebind_time(const ni_addrconf_lease_t *lease, const struct timeval *now)
{
	if (lease)
		return ni_lifetime_left(lease->dhcp4.rebind_time, &lease->acquired, now);
	else
		return NI_LIFETIME_EXPIRED;
}

static unsigned int
ni_dhcp4_lease_renewal_time(const ni_addrconf_lease_t *lease, const struct timeval *now)
{
	if (lease)
		return ni_lifetime_left(lease->dhcp4.renewal_time, &lease->acquired, now);
	else
		return NI_LIFETIME_EXPIRED;
}

/*
 * Verify if (recovered) lease is usable.
 */
static ni_bool_t
ni_dhcp4_verify_lease(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	ni_sockaddr_t addr;
	unsigned int lft;

	lft = ni_dhcp4_lease_lifetime(lease, NULL);
	if (lft == NI_LIFETIME_EXPIRED) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: discarding lease with UUID %s: expired",
				dev->ifname, ni_uuid_print(&lease->uuid));
		return FALSE;
	}

	if (dev->config->client_id.len &&
	    !ni_opaque_eq(&dev->config->client_id, &lease->dhcp4.client_id)) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: discarding lease with UUID %s: client id changed",
				dev->ifname, ni_uuid_print(&lease->uuid));
		return FALSE;
	}

	ni_sockaddr_set_ipv4(&addr, lease->dhcp4.server_id, 0);
	if (!ni_sockaddr_is_ipv4_specified(&addr)) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: discarding lease with UUID %s: missed server-id",
				dev->ifname, ni_uuid_print(&lease->uuid));
		return FALSE;
	}

	if (lft == NI_LIFETIME_INFINITE) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: reusing lease with UUID %s with infinite lifetime",
				dev->ifname, ni_uuid_print(&lease->uuid));
	} else {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: reusing lease with UUID %s valid for %usec",
				dev->ifname, ni_uuid_print(&lease->uuid), lft);
	}
	return TRUE;
}

/*
 * Recover currently active lease or try to load last lease from lease file.
 */
int
ni_dhcp4_recover_lease(ni_dhcp4_device_t *dev)
{
	ni_addrconf_lease_t *lease;

	if (dev->lease) {
		lease = dev->lease;

		lease->uuid = dev->config->uuid;
		ni_debug_dhcp("%s: verify if currently active lease is still valid",
				dev->ifname);

		if (!ni_dhcp4_verify_lease(dev, lease)) {
			ni_addrconf_lease_file_remove(dev->ifname, lease->type, lease->family);

			ni_dhcp4_fsm_fail_lease(dev);
			return -1;
		}
	} else {
		if (!(lease = ni_addrconf_lease_file_read(dev->ifname, NI_ADDRCONF_DHCP, AF_INET)))
			return -1;

		lease->uuid = dev->config->uuid;
		ni_debug_dhcp("%s: verify if lease loaded from file is still valid",
				dev->ifname);

		if (!ni_dhcp4_verify_lease(dev, lease)) {
			ni_addrconf_lease_file_remove(dev->ifname, lease->type, lease->family);

			ni_addrconf_lease_free(lease);
			return -1;
		}

		ni_dhcp4_device_set_lease(dev, lease);
	}

	return 0;
}

void
ni_dhcp4_fsm_fail_lease(ni_dhcp4_device_t *dev)
{
	ni_debug_dhcp("%s: failing lease in state %s", dev->ifname,
			ni_dhcp4_fsm_state_name(dev->fsm.state));

	ni_dhcp4_fsm_restart(dev);
	ni_capture_free(dev->capture);
	dev->capture = NULL;

	ni_dhcp4_send_event(NI_DHCP4_EVENT_LOST, dev, NULL);
}

static ni_bool_t
ni_dhcp4_address_on_device(const ni_netdev_t *ifp, struct in_addr ipv4)
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
ni_dhcp4_address_on_link(ni_dhcp4_device_t *dev, struct in_addr ipv4)
{
	ni_netconfig_t *nc;
	ni_netdev_t *ifp;

	nc = ni_global_state_handle(0);
	if (!nc || !(ifp = ni_netdev_by_index(nc, dev->link.ifindex)))
		return FALSE;

	return ni_dhcp4_address_on_device(ifp, ipv4);
}

int
ni_dhcp4_fsm_validate_lease(ni_dhcp4_device_t *dev, ni_addrconf_lease_t *lease)
{
	const ni_config_arp_t *arpcfg;

	/* Check whether arp validation has been disabled */
	if (!dev || !lease || !dev->config)
		return -1;

	if (!(dev->config->doflags & DHCP4_DO_ARP)) {
		ni_debug_dhcp("%s: arp validation disabled", dev->ifname);
		return 1;
	}

	/*
	 * This function is called by process ACK to verify new lease.
	 * Renew + Rebind just extend lease time and do not need DAD;
	 * Reboot validates before dhcp request if address is on link.
	 */
	if (ni_dhcp4_address_on_link(dev, lease->dhcp4.address)) {
		ni_debug_dhcp("%s: address %s is on link, omit validation in state %s",
				dev->ifname, inet_ntoa(lease->dhcp4.address),
				ni_dhcp4_fsm_state_name(dev->fsm.state));
		return 1;
	}


	ni_info("%s: Validating DHCPv4 address %s",
		dev->ifname, inet_ntoa(lease->dhcp4.address));

	arpcfg = ni_config_addrconf_arp(NI_ADDRCONF_DHCP, dev->ifname);
	ni_arp_verify_reset(&dev->arp.verify, &arpcfg->verify);
	if (!ni_arp_verify_add_in_addr(&dev->arp.verify, lease->dhcp4.address)) {
		ni_error("%s: add in_addr failed!", dev->ifname);
		return FALSE;
	}

	dev->fsm.state = NI_DHCP4_STATE_VALIDATING;

	if (ni_dhcp4_fsm_arp_validate(dev) < 0) {
		ni_debug_dhcp("%s: unable to validate lease", dev->ifname);
		ni_arp_verify_destroy(&dev->arp.verify);
		return -1;
	}

	return 0;
}

static void
ni_dhcp4_fsm_process_arp(ni_arp_socket_t *sock, const ni_arp_packet_t *pkt, void *user_data)
{
	ni_dhcp4_device_t *dev = (ni_dhcp4_device_t *) user_data;
	ni_arp_address_t *vap;
	ni_stringbuf_t sb = NI_STRINGBUF_INIT_DYNAMIC;
	const char *hwaddr;

	if (!(vap = ni_arp_reply_match_address(sock, &dev->arp.verify.ipaddrs, pkt)))
		return;

	if (ni_address_is_duplicate(vap->address)) {
		ni_debug_application("%s: DHCPv4 ignore further reply about duplicate address %s from %s",
				sock->dev_info.ifname, ni_address_print(&sb, vap->address),
				ni_link_address_print(&pkt->sha));
		ni_stringbuf_destroy(&sb);
		return;
	}

	ni_address_set_duplicate(vap->address, TRUE);

	hwaddr = ni_link_address_print(&pkt->sha);
	ni_error("%s: DHCPv4 duplicate address %s detected%s%s%s!",
			sock->dev_info.ifname, ni_address_print(&sb, vap->address),
			hwaddr ? " (in use by " : "", hwaddr ? hwaddr : "", hwaddr ? ")" : "");

	ni_arp_verify_destroy(&dev->arp.verify);
	ni_dhcp4_device_arp_close(dev);
	if (dev->arp.dad_failure) {
		dev->arp.dad_failure(dev);
		dev->arp.dad_failure = NULL;
		dev->arp.dad_success = NULL;
	} else {
		ni_dhcp4_fsm_decline(dev);
	}
}


int
ni_dhcp4_fsm_arp_validate(ni_dhcp4_device_t *dev)
{
	ni_timeout_t timeout;

	if (!dev->lease)
		return -1;

	if (dev->arp.handle == NULL) {
		dev->arp.handle = ni_arp_socket_open(&dev->system,
				ni_dhcp4_fsm_process_arp, dev);
		if (!dev->arp.handle || !dev->arp.handle->user_data) {
			ni_error("%s: unable to create ARP handle", dev->ifname);
			return -1;
		}
	}

	switch (ni_arp_verify_send(dev->arp.handle, &dev->arp.verify, &timeout)) {
	case NI_ARP_SEND_PROGRESS:
		ni_dhcp4_fsm_set_timeout_msec(dev, timeout);
		return 0;
	case NI_ARP_SEND_COMPLETE:
		ni_info("%s: Successfully verified DHCPv4 address %s",
			dev->ifname, inet_ntoa(dev->lease->dhcp4.address));
		/* fallthrough */
	case NI_ARP_SEND_FAILURE:
	default:
		ni_dhcp4_device_arp_close(dev);
		ni_arp_verify_destroy(&dev->arp.verify);
		if (dev->arp.dad_success) {
			dev->arp.dad_success(dev);
			dev->arp.dad_success = NULL;
			dev->arp.dad_failure = NULL;
		} else {
			ni_dhcp4_fsm_commit_lease(dev, dev->lease);
		}
		return 0;
	}
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

	case NI_DHCP4_STATE_INIT:
	case NI_DHCP4_STATE_SELECTING:
	case NI_DHCP4_STATE_REQUESTING:
	case NI_DHCP4_STATE_VALIDATING:
	case NI_DHCP4_STATE_RENEWING:
	case NI_DHCP4_STATE_REBINDING:
	case NI_DHCP4_STATE_REBOOT:
		/* FIXME: how do we handle a NAK response to an INFORM? */
		ni_dhcp4_device_drop_lease(dev);
		break;
	case NI_DHCP4_STATE_DOWN:
	case __NI_DHCP4_STATE_MAX:
		break;
	}

	/* Move back to state INIT */
	ni_dhcp4_fsm_restart(dev);

	if (dev->dhcp4.nak_backoff == 0)
		dev->dhcp4.nak_backoff = 1;

	/* If we constantly get NAKs then we should slowly back off */
	ni_debug_dhcp("Received NAK, backing off for %u seconds", dev->dhcp4.nak_backoff);
	ni_dhcp4_fsm_set_timeout_sec(dev, dev->dhcp4.nak_backoff);

	dev->dhcp4.nak_backoff *= 2;
	if (dev->dhcp4.nak_backoff > NI_DHCP4_NAK_BACKOFF_MAX)
		dev->dhcp4.nak_backoff = NI_DHCP4_NAK_BACKOFF_MAX;
	return 0;
}

/*
 * Set the protocol event callback
 */
static const ni_intmap_t	dhcp4_event_names[] = {
	{ "ACQUIRED",	NI_DHCP4_EVENT_ACQUIRED },
	{ "RELEASED",	NI_DHCP4_EVENT_RELEASED },
	{ "DEFERRED",	NI_DHCP4_EVENT_DEFERRED },
	{ "LOST",	NI_DHCP4_EVENT_LOST     },
	{ NULL }
};

const char *
ni_dhcp4_event_name(enum ni_dhcp4_event ev)
{
	return ni_format_uint_mapped(ev, dhcp4_event_names);
}

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
 [NI_DHCP4_STATE_DOWN]		= "DOWN",
 [NI_DHCP4_STATE_INIT]		= "INIT",
 [NI_DHCP4_STATE_SELECTING]	= "SELECTING",
 [NI_DHCP4_STATE_REQUESTING]	= "REQUESTING",
 [NI_DHCP4_STATE_VALIDATING]	= "VALIDATING",
 [NI_DHCP4_STATE_BOUND]		= "BOUND",
 [NI_DHCP4_STATE_RENEWING]	= "RENEWING",
 [NI_DHCP4_STATE_REBINDING]	= "REBINDING",
 [NI_DHCP4_STATE_REBOOT]	= "REBOOT",
};

const char *
ni_dhcp4_fsm_state_name(enum fsm_state state)
{
	const char *name = NULL;

	if (state < __NI_DHCP4_STATE_MAX)
		name = __dhcp4_state_name[state];
	return name? name : "UNKNOWN STATE";
}
