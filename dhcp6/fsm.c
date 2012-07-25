/*
 *	DHCP6 supplicant -- finite client state machine.
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012 Marius Tomaschewski <mt@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/logging.h>

#include "dhcp6/dhcp6.h"
#include "dhcp6/device.h"
#include "dhcp6/protocol.h"
#include "dhcp6/duid.h"
#include "dhcp6/fsm.h"

static void			ni_dhcp6_fsm_timeout(ni_dhcp6_device_t *);
static void             	__ni_dhcp6_fsm_timeout(void *, const ni_timer_t *);

static int			ni_dhcp6_fsm_solicit      (ni_dhcp6_device_t *);
static int			__ni_dhcp6_fsm_solicit    (ni_dhcp6_device_t *, int);

static int			ni_dhcp6_fsm_request_lease(ni_dhcp6_device_t *, const ni_addrconf_lease_t *);
static int			ni_dhcp6_fsm_confirm_lease(ni_dhcp6_device_t *, const ni_addrconf_lease_t *);

static int			ni_dhcp6_fsm_commit_lease (ni_dhcp6_device_t *dev, ni_addrconf_lease_t *);

static int			ni_dhcp6_fsm_request_info (ni_dhcp6_device_t *);

static void			ni_dhcp6_send_event(enum ni_dhcp6_event, const ni_dhcp6_device_t *, ni_addrconf_lease_t *);

/*
 * Global fsm handler
 */
static ni_dhcp6_event_handler_t *ni_dhcp6_fsm_event_handler;


int
ni_dhcp6_fsm_start(ni_dhcp6_device_t *dev)
{
#if 0
        if (dev->config->info_only) {
		return ni_dhcp6_fsm_request_info(dev);
        }
        else if(link_were_down_and_have_valid_lease(dev->lease)) {
		return ni_dhcp6_fsm_confirm_lease(dev, dev->lease);
        }
        else {
		/* drop old lease here ? */
        }
#endif
	ni_dhcp6_device_set_lease(dev, NULL);
	ni_dhcp6_device_drop_best_offer(dev);

	return ni_dhcp6_fsm_solicit(dev);
}

int
ni_dhcp6_fsm_retransmit(ni_dhcp6_device_t *dev)
{
	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_SELECTING:
		return __ni_dhcp6_fsm_solicit(dev, 0);

	case NI_DHCP6_STATE_REQUESTING:
		return ni_dhcp6_fsm_request_lease(dev, dev->best_offer.lease);

	case NI_DHCP6_STATE_CONFIRMING:
		return ni_dhcp6_fsm_confirm_lease(dev, dev->lease);

	case NI_DHCP6_STATE_REQUESTING_INFO:
		return ni_dhcp6_fsm_request_info(dev);

	default:
		return -1;
	}
}

void
ni_dhcp6_fsm_set_timeout_msec(ni_dhcp6_device_t *dev, unsigned long msec)
{
	dev->fsm.fail_on_timeout = 0;
	if (msec != 0) {
		ni_debug_dhcp("%s: setting timeout to %lu msec", dev->ifname, msec);
		if (dev->fsm.timer) {
			ni_timer_rearm(dev->fsm.timer, msec);
		} else {
			dev->fsm.timer = ni_timer_register(msec, __ni_dhcp6_fsm_timeout, dev);
		}
	}
}

static void
__ni_dhcp6_fsm_timeout(void *user_data, const ni_timer_t *timer)
{
	ni_dhcp6_device_t *dev = user_data;

	if (dev->fsm.timer != timer) {
		ni_warn("%s: bad timer handle", __func__);
		return;
	}

	ni_dhcp6_fsm_timeout(dev);
}


static void
ni_dhcp6_fsm_timeout(ni_dhcp6_device_t *dev)
{
	ni_debug_dhcp("%s: timeout in state %s%s",
			dev->ifname, ni_dhcp6_fsm_state_name(dev->fsm.state),
			dev->fsm.fail_on_timeout? " (fatal failure)" : "");

	dev->fsm.timer = NULL;

	if (dev->retrans.delay) {
		dev->retrans.delay = 0;
		ni_dhcp6_device_transmit_start(dev);
	}

	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_SELECTING:

		/* the weight has maximum value, just accept this offer */
		if (dev->best_offer.lease) {
			dev->dhcp6.xid = 0;
			ni_dhcp6_device_retransmit_disarm(dev);

			if (dev->best_offer.lease->dhcp6.rapid_commit) {
				ni_dhcp6_fsm_commit_lease(dev, dev->best_offer.lease);
				dev->best_offer.lease = NULL;
				dev->best_offer.weight = -1;
			} else {
				ni_dhcp6_fsm_request_lease(dev, dev->best_offer.lease);
			}
		}
		break;

	case NI_DHCP6_STATE_REQUESTING:
		break;

	case NI_DHCP6_STATE_VALIDATING:
		break;

	case NI_DHCP6_STATE_BOUND:
		break;

	default:
		break;
	}
}

static inline ni_bool_t
__choose_best_offer(const ni_dhcp6_device_t *dev, const ni_addrconf_lease_t *lease, int weight)
{
	/* when we don't have any or this is a better offer, remember it */
	if (dev->best_offer.lease == NULL || dev->best_offer.weight < weight)
		return TRUE;

	/* ignore when we have a better offer */
	if (dev->best_offer.weight > weight)
		return FALSE;

	/* prefer equal weight offer from the last server we've used */
	if (dev->lease && dev->lease->dhcp6.server_id.len > 0 &&
	    !IN6_IS_ADDR_UNSPECIFIED(&dev->lease->dhcp6.server_addr)) {

		if (IN6_ARE_ADDR_EQUAL(&dev->lease->dhcp6.server_addr, &lease->dhcp6.server_addr) ||
		    ni_opaque_eq(&dev->lease->dhcp6.server_id, &lease->dhcp6.server_id))
			return TRUE;
	}
	return FALSE;
}

int
ni_dhcp6_fsm_process_client_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_stringbuf_t ignore_hint = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease = NULL;
	unsigned int  msg_type = 0;
	unsigned int  msg_xid = 0;
	int weight = 0;
	int rv = -1;

	if (ni_dhcp6_client_parse_response(dev, msgbuf, &msg_type, &msg_xid, &lease) < 0)
		return -1;

	ni_debug_dhcp("%s: received %s message xid 0x%06x in state %s from %s%%%u",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
			ni_dhcp6_fsm_state_name(dev->fsm.state),
			ni_dhcp6_address_print(sender), dev->link.ifindex);

	/* set the server address in the lease */
	memcpy(&lease->dhcp6.server_addr, sender, sizeof(lease->dhcp6.server_addr));

	ni_stringbuf_printf(&ignore_hint, ": unexpected");
	switch (msg_type) {
	case NI_DHCP6_ADVERTISE:
		if (dev->fsm.state != NI_DHCP6_STATE_SELECTING)
			goto ignore;

		if (lease->dhcp6.status && lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_stringbuf_printf(&ignore_hint, ": status %s - %s",
						ni_dhcp6_status_name(lease->dhcp6.status->code),
						lease->dhcp6.status->message);
			goto ignore;
		}

		if (lease->dhcp6.rapid_commit) {
			ni_stringbuf_printf(&ignore_hint, ": rapid commit set?!");
			goto ignore;
		}

		/* check if the config provides/overrides the preference */
		if (!ni_dhcp6_config_server_preference(	&lease->dhcp6.server_addr,
							&lease->dhcp6.server_id,
							&weight)) {
			weight = lease->dhcp6.server_pref;
		}

		if (weight < 0) {
			ni_stringbuf_printf(&ignore_hint, ": blacklisted server");
			goto ignore;
		}

		if(__choose_best_offer(dev, lease, weight)) {
			ni_addrconf_dhcp6_lease_free(dev->best_offer.lease);
			dev->best_offer.weight = weight;
			dev->best_offer.lease = lease;
			lease = NULL;
		}

		/* the weight has maximum value, just accept this offer */
		if (dev->best_offer.weight >= 255) {
		        if (dev->fsm.timer) {
		                ni_timer_cancel(dev->fsm.timer);
		                dev->fsm.timer = NULL;
		        }
			dev->dhcp6.xid = 0;
			ni_dhcp6_device_retransmit_disarm(dev);

			ni_dhcp6_fsm_request_lease(dev, dev->best_offer.lease);
		}
		break;

	case NI_DHCP6_REPLY:
		switch (dev->fsm.state) {
		case NI_DHCP6_STATE_INIT:
			ni_stringbuf_printf(&ignore_hint, ": unexpected");
			goto ignore;

		case NI_DHCP6_STATE_SELECTING:
			if (lease->dhcp6.status && lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
				ni_stringbuf_printf(&ignore_hint, ": status %s - %s",
							ni_dhcp6_status_name(lease->dhcp6.status->code),
							lease->dhcp6.status->message);
				goto ignore;
			}

			if (!lease->dhcp6.rapid_commit) {
				ni_stringbuf_printf(&ignore_hint, ": rapid commit not set");
				goto ignore;
			}

			/*
			 * 17.1.4. says it is our decision if we accept unrequested rapid-commit or not.
			 * The message is already filtered by last xid, so when we are here, we didn't
			 * sent Request yet.
			 */

			/* check if the config provides/overrides the preference */
			if (!ni_dhcp6_config_server_preference( &lease->dhcp6.server_addr,
								&lease->dhcp6.server_id,
								&weight)) {
				weight = lease->dhcp6.server_pref;
			}
			if (weight < 0) {
				ni_stringbuf_printf(&ignore_hint, ": blacklisted server");
				goto ignore;
			}

			if(__choose_best_offer(dev, lease, weight)) {
				ni_addrconf_dhcp6_lease_free(dev->best_offer.lease);
				dev->best_offer.weight = weight;
				dev->best_offer.lease = lease;
				lease = NULL;
			}

			/* the weight has maximum value, just accept this lease */
			if (dev->best_offer.weight >= 255) {
			        if (dev->fsm.timer) {
			                ni_timer_cancel(dev->fsm.timer);
			                dev->fsm.timer = NULL;
			        }
				dev->dhcp6.xid = 0;
				ni_dhcp6_device_retransmit_disarm(dev);

				ni_dhcp6_fsm_commit_lease(dev, dev->best_offer.lease);
				dev->best_offer.lease = NULL;
				dev->best_offer.weight = -1;
			}
			break;

		case NI_DHCP6_STATE_REQUESTING:
			if (lease->dhcp6.status && lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
				ni_stringbuf_printf(&ignore_hint, ": status %s - %s",
							ni_dhcp6_status_name(lease->dhcp6.status->code),
							lease->dhcp6.status->message);
				goto ignore;
			}

			if (!dev->best_offer.lease) {
				ni_stringbuf_printf(&ignore_hint, ": lease reply without request");
				goto ignore;
			}

			/*
			 * best offer points to the lease we've requested -- check that the
			 * server in the reply matches the server we request the lease from.
			 */
			if (!IN6_ARE_ADDR_EQUAL(&dev->best_offer.lease->dhcp6.server_addr, &lease->dhcp6.server_addr) ||
			    !ni_opaque_eq(&dev->best_offer.lease->dhcp6.server_id, &lease->dhcp6.server_id)) {
				ni_stringbuf_printf(&ignore_hint, ": lease reply from another server?!");
				goto ignore;
			}

		        if (dev->fsm.timer) {
		                ni_timer_cancel(dev->fsm.timer);
		                dev->fsm.timer = NULL;
		        }
			dev->dhcp6.xid = 0;
			ni_dhcp6_device_retransmit_disarm(dev);

			ni_dhcp6_fsm_commit_lease(dev, dev->best_offer.lease);
			dev->best_offer.lease = NULL;
			dev->best_offer.weight = 0;
			break;

		default:
			goto ignore;
		}
		break;
        default:
	ignore:
		ni_debug_dhcp("%s: ignoring %s message xid 0x%06x in state %s from %s%s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_address_print(sender),
				(ignore_hint.string ? ignore_hint.string : ""));
		break;
	}

	if (lease && dev->lease != lease) {
		ni_addrconf_dhcp6_lease_free(lease);
	}
	return rv;
}

static int
ni_dhcp6_fsm_solicit(ni_dhcp6_device_t *dev)
{
	return __ni_dhcp6_fsm_solicit(dev, 1);
}

static int
__ni_dhcp6_fsm_solicit(ni_dhcp6_device_t *dev, int scan_offers)
{
	ni_addrconf_lease_t *lease;
	int rv = -1;

	/*
	 * /rfc3315#section-17.1.1
	 *
	 * If we already have a lease, we
	 * "[...] include addresses in the IAs as a hint to the server
	 * about addresses for which the client has a preference. [...]
	 * The client uses IA_NA options to request the assignment of
	 * non-temporary addresses and uses IA_TA options to request
	 * the assignment of temporary addresses.[...]"
	 *
	 * If not, create a dummy lease with NULL fields.
	 */
	if ((lease = dev->lease) == NULL) {
		lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);

		/* TODO: add addrs from interface as hint */
	}

	if (dev->retrans.count == 0) {
		ni_debug_dhcp("%s[%u]: Initiating DHCPv6 Server Solicitation",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_init_message(dev, NI_DHCP6_SOLICIT, lease) != 0)
			goto cleanup;

		dev->fsm.state = NI_DHCP6_STATE_SELECTING;

		/* FIXME: */
		dev->dhcp6.accept_any_offer = scan_offers;

		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		ni_debug_dhcp("%s[%u]: Retransmitting DHCPv6 Server Solicitation",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_SOLICIT, &dev->message, lease) != 0)
			goto cleanup;

		rv = ni_dhcp6_device_transmit(dev);
	}

cleanup:
	if (lease != dev->lease) {
		ni_addrconf_dhcp6_lease_free(lease);
	}
	return rv;
}

static int
ni_dhcp6_fsm_request_lease(ni_dhcp6_device_t *dev, const ni_addrconf_lease_t *lease)
{
	int rv = -1;

	if (!lease)
		return -1;

	if (dev->retrans.count == 0) {
		ni_debug_dhcp("%s[%u]: Initiating DHCPv6 Lease Request",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_init_message(dev, NI_DHCP6_REQUEST, lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_REQUESTING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		ni_debug_dhcp("%s[%u]: Retransmitting DHCPv6 Lease Request",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_REQUEST, &dev->message, lease) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

static int
ni_dhcp6_fsm_confirm_lease(ni_dhcp6_device_t *dev, const ni_addrconf_lease_t *lease)
{
	int rv = -1;

	if (!lease)
		return -1;

	if (dev->retrans.count == 0) {
		ni_debug_dhcp("%s[%u]: Initiating DHCPv6 Lease Confirmation",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_init_message(dev, NI_DHCP6_CONFIRM, lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_CONFIRMING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else if (dev->fsm.state == NI_DHCP6_STATE_CONFIRMING) {

		ni_debug_dhcp("%s[%u]: Retransmitting DHCPv6 Lease Confirmation",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_CONFIRM, &dev->message, lease) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

static int
ni_dhcp6_fsm_request_info(ni_dhcp6_device_t *dev)
{
	int rv = -1;

	if (dev->retrans.count == 0) {
		ni_debug_dhcp("%s[%u]: Initiating DHCPv6 Info Request",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_init_message(dev, NI_DHCP6_INFO_REQUEST, NULL) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_REQUESTING_INFO;
		dev->dhcp6.accept_any_offer = 1;

		rv = ni_dhcp6_device_transmit_init(dev);
	} else if (dev->fsm.state == NI_DHCP6_STATE_REQUESTING_INFO) {

		ni_debug_dhcp("%s[%u]: Retransmitting DHCPv6 Info Request",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_INFO_REQUEST, &dev->message, NULL) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

static int
ni_dhcp6_fsm_commit_lease(ni_dhcp6_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (lease) {
		/* OK, now we can provide the lease to wicked,
		 * that will set the IPs causing kernel to
		 * perform IPv6 dad.
		 *
		 * As soon as dad finished, we can change to
		 * BOUND state and wait until renew etc.
		 */

		/*
		 * dev->fsm.state = NI_DHCP6_STATE_VALIDATING;
		 *
		 * For now:
		 */
		dev->fsm.state = NI_DHCP6_STATE_BOUND;
		/*
		 * Calculate the renewal_time from ia's addr pref_lft, ...
		 *
		 * ni_dhcp6_fsm_set_timeout_msec(dev, renewal_time);
		 *
		 */
		ni_dhcp6_device_set_lease(dev, lease);

		ni_addrconf_lease_file_write(dev->ifname, lease);

		ni_dhcp6_send_event(NI_DHCP6_EVENT_ACQUIRED, dev, lease);
	} else {
		if ((lease = dev->lease) != NULL) {

			lease->state = NI_ADDRCONF_STATE_RELEASED;

			ni_dhcp6_send_event(NI_DHCP6_EVENT_RELEASED, dev, lease);

			ni_addrconf_lease_file_remove(dev->ifname, lease->type,
							lease->family);
			ni_dhcp6_device_drop_lease(dev);
			ni_dhcp6_device_drop_best_offer(dev);
			dev->fsm.state = NI_DHCP6_STATE_INIT;
		}

		//ni_dhcp6_fsm_restart(dev);
	}
	return 0;
}

/*
 * Set the protocol event callback
 */
void
ni_dhcp6_set_event_handler(ni_dhcp6_event_handler_t func)
{
        ni_dhcp6_fsm_event_handler = func;
}

static void
ni_dhcp6_send_event(enum ni_dhcp6_event ev, const ni_dhcp6_device_t *dev, ni_addrconf_lease_t *lease)
{
        if (ni_dhcp6_fsm_event_handler)
                ni_dhcp6_fsm_event_handler(ev, dev, lease);
}

/*
 * Helper function to print name of DHCP FSM state
 */
static const char *__dhcp6_state_name[__NI_DHCP6_STATE_MAX] = {
	[NI_DHCP6_STATE_INIT]           = "INIT",
	[NI_DHCP6_STATE_SELECTING]      = "SELECTING",
	[NI_DHCP6_STATE_REQUESTING]     = "REQUESTING",
	[NI_DHCP6_STATE_VALIDATING]     = "VALIDATING",
	[NI_DHCP6_STATE_BOUND]          = "BOUND",
	[NI_DHCP6_STATE_RENEWING]       = "RENEWING",
	[NI_DHCP6_STATE_REBINDING]      = "REBINDING",
	[NI_DHCP6_STATE_REBOOT]         = "REBOOT",
	[NI_DHCP6_STATE_RENEW_REQUESTED]= "RENEW_REQUESTED",
	[NI_DHCP6_STATE_RELEASED]       = "RELEASED",
	[NI_DHCP6_STATE_REQUESTING_INFO]= "REQUESTING INFO",
};

const char *
ni_dhcp6_fsm_state_name(int state)
{
        const char *name = NULL;

        if (state >= 0 && state < __NI_DHCP6_STATE_MAX)
        	name = __dhcp6_state_name[state];

        return name ? name : "UNKNOWN STATE";
}
