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

#include <time.h>

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
static int			ni_dhcp6_fsm_renew(ni_dhcp6_device_t *);
static int			ni_dhcp6_fsm_rebind(ni_dhcp6_device_t *);
static int			ni_dhcp6_fsm_decline(ni_dhcp6_device_t *);
static int			ni_dhcp6_fsm_release(ni_dhcp6_device_t *);

static int			ni_dhcp6_fsm_commit_lease (ni_dhcp6_device_t *, ni_addrconf_lease_t *);

static int			ni_dhcp6_fsm_request_info (ni_dhcp6_device_t *);

static void			ni_dhcp6_send_event(enum ni_dhcp6_event, const ni_dhcp6_device_t *, ni_addrconf_lease_t *);

/*
 * How long to wait until an address is ready to use
 */
#define NI_DHCP6_WAIT_IAADDR_READY		2000


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

	case NI_DHCP6_STATE_RENEWING:
		return ni_dhcp6_fsm_renew(dev);
	break;

	case NI_DHCP6_STATE_REBINDING:
		return ni_dhcp6_fsm_rebind(dev);
	break;

	case NI_DHCP6_STATE_DECLINING:
		return ni_dhcp6_fsm_decline(dev);
	break;

	case NI_DHCP6_STATE_RELEASING:
		return ni_dhcp6_fsm_release(dev);
	break;

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
	} else if (dev->fsm.timer) {
		ni_timer_cancel(dev->fsm.timer);
		dev->fsm.timer = NULL;
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

	if (dev->fsm.fail_on_timeout) {
		dev->fsm.fail_on_timeout = 0;

		switch (dev->fsm.state) {
		case NI_DHCP6_STATE_WAIT_READY:
			/*
			 * Link-layer address were not available in time...
			 */
			ni_error("%s[%u]: Unable to initialize DHCPv6",
					dev->ifname, dev->link.ifindex);
			break;

		default:
			ni_error("%s[%u]: FSM BUG", dev->ifname, dev->link.ifindex);
			break;
		}

		ni_dhcp6_device_stop(dev);
		return;
	}

	if (dev->retrans.delay) {
		dev->retrans.delay = 0;
		ni_dhcp6_device_transmit_start(dev);
	}

	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_WAIT_READY:
		/*
		 * Link-layer address is ready, but some another not...
		 */
		ni_dhcp6_device_start(dev);
		break;

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
		/* FIXME: */
		break;

	case NI_DHCP6_STATE_VALIDATING:
		/* FIXME: */
		dev->fsm.state = NI_DHCP6_STATE_BOUND;
		break;

	case NI_DHCP6_STATE_BOUND:
		/* FIXME: not ready yet
		 * ni_dhcp6_fsm_renew(dev);
		 */
		break;

	case NI_DHCP6_STATE_RENEWING:
		ni_dhcp6_fsm_rebind(dev);
		break;

	case NI_DHCP6_STATE_REBINDING:
		/* FIXME: */
		break;

	case NI_DHCP6_STATE_DECLINING:
		/* FIXME: */
		break;

	case NI_DHCP6_STATE_RELEASING:
		/* FIXME: */
		break;

	default:
		break;
	}
}

static void
__ni_dhcp6_fsm_ia_addr_update(ni_netdev_t *ifp, ni_dhcp6_device_t *dev, const ni_address_t *addr)
{
	ni_address_t *ap;
	struct ni_dhcp6_ia *ia;
	struct ni_dhcp6_ia_addr *iadr;
	unsigned int tentative = 0;
	unsigned int duplicate = 0;

	for (ap = ifp->addrs; ap; ap = ap->next) {
		if (ap->family != AF_INET6 || ap->local_addr.ss_family != AF_INET6)
			continue;

		for (ia = dev->lease->dhcp6.ia_list; ia; ia = ia->next) {
			if (ia->type != NI_DHCP6_OPTION_IA_NA ||
			    ia->type != NI_DHCP6_OPTION_IA_TA)
				continue;

			for (iadr = ia->addrs; iadr; iadr = iadr->next) {
				if (IN6_ARE_ADDR_EQUAL(&iadr->addr, &ap->local_addr.six.sin6_addr)) {
					if (ni_address_is_duplicate(ap)) {
						duplicate++;

						ni_dhcp6_ia_addr_mark(iadr, NI_DHCP6_IA_ADDR_DECLINE);

						ni_debug_dhcp("%s: address %s is duplicate, marked for decline",
							dev->ifname, ni_sockaddr_print(&ap->local_addr));
					} else
					if (ni_address_is_tentative(ap)) {
						tentative++;

						ni_debug_dhcp("%s: address %s is marked tentative -> wait",
							dev->ifname, ni_sockaddr_print(&ap->local_addr));
					}
				}
			}
		}
	}

	if (tentative)
		return;

	if (duplicate) {
		/* FIXME: decline is not ready yet...
		ni_dhcp6_fsm_decline(dev);
		*/
		return;
	}

	if (tentative == 0) {
		dev->fsm.state = NI_DHCP6_STATE_BOUND;
		/* TODO: renew is not ready yet...
		ni_dhcp6_fsm_set_timeout_msec(dev, 360 * 1000);
		*/
	}
}

static void
__ni_dhcp6_fsm_address_update(ni_netdev_t *ifp, ni_dhcp6_device_t *dev, const ni_address_t *addr)
{
	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_WAIT_READY:
		if (!dev->config) {
			ni_error("%s[%u]: BUG -- wait ready without config",
					dev->ifname, dev->link.ifindex);

			ni_dhcp6_device_stop(dev);
			return;
		}
		ni_dhcp6_device_address_event(ifp, dev, NI_EVENT_ADDRESS_UPDATE, addr);
		break;

	case NI_DHCP6_STATE_VALIDATING:
		if (!dev->lease) {
			ni_error("%s[%u]: BUG -- cannot validate lease addrs without lease",
					dev->ifname, dev->link.ifindex);

			ni_dhcp6_device_stop(dev);
			return;
		}
		__ni_dhcp6_fsm_ia_addr_update(ifp, dev, addr);
		break;
	}

}

void
ni_dhcp6_address_event(ni_netdev_t *ifp, ni_event_t event, const ni_address_t *addr)
{
	ni_dhcp6_device_t *dev;

	if ((dev = ni_dhcp6_device_by_index(ifp->link.ifindex)) == NULL)
		return;

	ni_debug_events("%s[%u]: received interface address event: %s %s",
		dev->ifname, dev->link.ifindex, ni_event_type_to_name(event),
		ni_sockaddr_print(&addr->local_addr));

	switch (event) {
	case NI_EVENT_ADDRESS_UPDATE:
		__ni_dhcp6_fsm_address_update(ifp, dev, addr);
		break;

	case NI_EVENT_ADDRESS_DELETE:
		break;

	default:
		break;
	}
}

static inline ni_bool_t
__fsm_select_best_offer(const ni_dhcp6_device_t *dev, const ni_addrconf_lease_t *lease, int weight)
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

static int
__fsm_select_process_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_stringbuf_t ignore_hint = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease = NULL;
	unsigned int  msg_type = 0;
	unsigned int  msg_xid = 0;
	int weight = 0;
	int rv = -1;

	if (ni_dhcp6_parse_client_header(msgbuf, &msg_type, &msg_xid) < 0) {
		ni_error("%s: short DHCP6 client packet (%u bytes) from %s",
				dev->ifname, ni_buffer_count(msgbuf),
				ni_dhcp6_address_print(sender));
		return -1;
	}

	if (ni_dhcp6_check_client_header(dev, sender, msg_type, msg_xid) < 0)
		return -1;

	ni_stringbuf_printf(&ignore_hint, ": unexpected");
	switch (msg_type) {
	case NI_DHCP6_REPLY:
	case NI_DHCP6_ADVERTISE:
		ni_debug_dhcp("%s: received %s message xid 0x%06x in state %s from %s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_address_print(sender));

		lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
		lease->state = NI_ADDRCONF_STATE_GRANTED;
		lease->type = NI_ADDRCONF_DHCP;
		lease->time_acquired = time(NULL);
		/* set the server address in the lease */
		memcpy(&lease->dhcp6.server_addr, sender, sizeof(lease->dhcp6.server_addr));

		if (ni_dhcp6_parse_client_options(dev, msgbuf, lease) < 0) {
			ni_error("%s: unable to parse options in %s message xid 0x%06x from %s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_address_print(sender));
			goto failure;
		}

		if (ni_dhcp6_check_message_duids(dev, sender, msg_type, msg_xid, lease) < 0)
			goto failure;
	break;

	default:
		goto ignore;
	break;
	}

	switch (msg_type) {
	case NI_DHCP6_ADVERTISE:
		/*
		 * We've to discard all advertise messages with status NI_DHCP6_STATUS_NOADDRS;
		 * the another codes IMO don't fit here, so we discard all unsuccessful codes.
		 */
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

		if(__fsm_select_best_offer(dev, lease, weight)) {
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
		rv = 0;
	break;

	case NI_DHCP6_REPLY:
		/*
		 * Hmm...
		 */
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

		if(__fsm_select_best_offer(dev, lease, weight)) {
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
		rv = 0;
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

failure:
	if (lease != NULL && dev->lease != lease) {
		ni_addrconf_dhcp6_lease_free(lease);
	}
	return rv;
}

static int
__fsm_request_process_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_stringbuf_t ignore_hint = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease = NULL;
	unsigned int  msg_type = 0;
	unsigned int  msg_xid = 0;
	int rv = -1;

	if (ni_dhcp6_parse_client_header(msgbuf, &msg_type, &msg_xid) < 0) {
		ni_error("%s: short DHCP6 client packet (%u bytes) from %s",
				dev->ifname, ni_buffer_count(msgbuf),
				ni_dhcp6_address_print(sender));
		return -1;
	}

	if (ni_dhcp6_check_client_header(dev, sender, msg_type, msg_xid) < 0)
		return -1;

	ni_stringbuf_printf(&ignore_hint, ": unexpected");
	switch (msg_type) {
	case NI_DHCP6_REPLY:
		ni_debug_dhcp("%s: received %s message xid 0x%06x in state %s from %s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_address_print(sender));

		lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
		lease->state = NI_ADDRCONF_STATE_GRANTED;
		lease->type = NI_ADDRCONF_DHCP;
		lease->time_acquired = time(NULL);
		/* set the server address in the lease */
		memcpy(&lease->dhcp6.server_addr, sender, sizeof(lease->dhcp6.server_addr));

		if (ni_dhcp6_parse_client_options(dev, msgbuf, lease) < 0) {
			ni_error("%s: unable to parse options in %s message xid 0x%06x from %s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_address_print(sender));
			goto failure;
		}

		if (ni_dhcp6_check_message_duids(dev, sender, msg_type, msg_xid, lease) < 0)
			goto failure;

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

		ni_dhcp6_fsm_commit_lease(dev, lease);
		ni_addrconf_dhcp6_lease_free(dev->best_offer.lease);
		dev->best_offer.lease = NULL;
		dev->best_offer.weight = -1;
		rv = 0;
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

failure:
	if (lease && dev->lease != lease) {
		ni_addrconf_dhcp6_lease_free(lease);
	}
	return rv;
}

static int
__fsm_confirm_process_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_stringbuf_t ignore_hint = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease = NULL;
	unsigned int  msg_type = 0;
	unsigned int  msg_xid = 0;
	int rv = -1;

	if (ni_dhcp6_parse_client_header(msgbuf, &msg_type, &msg_xid) < 0) {
		ni_error("%s: short DHCP6 client packet (%u bytes) from %s",
				dev->ifname, ni_buffer_count(msgbuf),
				ni_dhcp6_address_print(sender));
		return -1;
	}

	if (ni_dhcp6_check_client_header(dev, sender, msg_type, msg_xid) < 0)
		return -1;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	lease->time_acquired = time(NULL);
	/* set the server address in the lease */
	memcpy(&lease->dhcp6.server_addr, sender, sizeof(lease->dhcp6.server_addr));

	if (ni_dhcp6_parse_client_options(dev, msgbuf, lease) < 0) {
		ni_error("%s: unable to parse options in %s message xid 0x%06x from %s",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
			ni_dhcp6_address_print(sender));
		goto failure;
	}

	ni_stringbuf_printf(&ignore_hint, ": TODO");
	switch (msg_type) {
	case NI_DHCP6_REPLY:
	default:
//	ignore:
		ni_debug_dhcp("%s: ignoring %s message xid 0x%06x in state %s from %s%s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_address_print(sender),
				(ignore_hint.string ? ignore_hint.string : ""));
	break;
	}

failure:
	if (lease && dev->lease != lease) {
		ni_addrconf_dhcp6_lease_free(lease);
	}
	return rv;
}

static int
__fsm_renew_process_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_stringbuf_t ignore_hint = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease = NULL;
	unsigned int  msg_type = 0;
	unsigned int  msg_xid = 0;
	int rv = -1;

	if (ni_dhcp6_parse_client_header(msgbuf, &msg_type, &msg_xid) < 0) {
		ni_error("%s: short DHCP6 client packet (%u bytes) from %s",
				dev->ifname, ni_buffer_count(msgbuf),
				ni_dhcp6_address_print(sender));
		return -1;
	}

	if (ni_dhcp6_check_client_header(dev, sender, msg_type, msg_xid) < 0)
		return -1;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	lease->time_acquired = time(NULL);
	/* set the server address in the lease */
	memcpy(&lease->dhcp6.server_addr, sender, sizeof(lease->dhcp6.server_addr));

	if (ni_dhcp6_parse_client_options(dev, msgbuf, lease) < 0) {
		ni_error("%s: unable to parse options in %s message xid 0x%06x from %s",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
			ni_dhcp6_address_print(sender));
		goto failure;
	}

	ni_stringbuf_printf(&ignore_hint, ": TODO");
	switch (msg_type) {
	case NI_DHCP6_REPLY:
	default:
//	ignore:
		ni_debug_dhcp("%s: ignoring %s message xid 0x%06x in state %s from %s%s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_address_print(sender),
				(ignore_hint.string ? ignore_hint.string : ""));
	break;
	}

failure:
	if (lease && dev->lease != lease) {
		ni_addrconf_dhcp6_lease_free(lease);
	}
	return rv;
}


static int
__fsm_rebind_process_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_stringbuf_t ignore_hint = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease = NULL;
	unsigned int  msg_type = 0;
	unsigned int  msg_xid = 0;
	int rv = -1;

	if (ni_dhcp6_parse_client_header(msgbuf, &msg_type, &msg_xid) < 0) {
		ni_error("%s: short DHCP6 client packet (%u bytes) from %s",
				dev->ifname, ni_buffer_count(msgbuf),
				ni_dhcp6_address_print(sender));
		return -1;
	}

	if (ni_dhcp6_check_client_header(dev, sender, msg_type, msg_xid) < 0)
		return -1;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	lease->time_acquired = time(NULL);
	/* set the server address in the lease */
	memcpy(&lease->dhcp6.server_addr, sender, sizeof(lease->dhcp6.server_addr));

	if (ni_dhcp6_parse_client_options(dev, msgbuf, lease) < 0) {
		ni_error("%s: unable to parse options in %s message xid 0x%06x from %s",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
			ni_dhcp6_address_print(sender));
		goto failure;
	}

	ni_stringbuf_printf(&ignore_hint, ": TODO");
	switch (msg_type) {
	case NI_DHCP6_REPLY:
	default:
//	ignore:
		ni_debug_dhcp("%s: ignoring %s message xid 0x%06x in state %s from %s%s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_address_print(sender),
				(ignore_hint.string ? ignore_hint.string : ""));
	break;
	}

failure:
	if (lease && dev->lease != lease) {
		ni_addrconf_dhcp6_lease_free(lease);
	}
	return rv;
}


static int
__fsm_decline_process_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_stringbuf_t ignore_hint = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease = NULL;
	unsigned int  msg_type = 0;
	unsigned int  msg_xid = 0;
	int rv = -1;

	if (ni_dhcp6_parse_client_header(msgbuf, &msg_type, &msg_xid) < 0) {
		ni_error("%s: short DHCP6 client packet (%u bytes) from %s",
				dev->ifname, ni_buffer_count(msgbuf),
				ni_dhcp6_address_print(sender));
		return -1;
	}

	if (ni_dhcp6_check_client_header(dev, sender, msg_type, msg_xid) < 0)
		return -1;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	lease->time_acquired = time(NULL);
	/* set the server address in the lease */
	memcpy(&lease->dhcp6.server_addr, sender, sizeof(lease->dhcp6.server_addr));

	if (ni_dhcp6_parse_client_options(dev, msgbuf, lease) < 0) {
		ni_error("%s: unable to parse options in %s message xid 0x%06x from %s",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
			ni_dhcp6_address_print(sender));
		goto failure;
	}

	ni_stringbuf_printf(&ignore_hint, ": TODO");
	switch (msg_type) {
	case NI_DHCP6_REPLY:
	default:
//	ignore:
		ni_debug_dhcp("%s: ignoring %s message xid 0x%06x in state %s from %s%s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_address_print(sender),
				(ignore_hint.string ? ignore_hint.string : ""));
	break;
	}

failure:
	if (lease && dev->lease != lease) {
		ni_addrconf_dhcp6_lease_free(lease);
	}
	return rv;
}

static int
__fsm_release_process_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_stringbuf_t ignore_hint = NI_STRINGBUF_INIT_DYNAMIC;
	ni_addrconf_lease_t *lease = NULL;
	unsigned int  msg_type = 0;
	unsigned int  msg_xid = 0;
	int rv = -1;

	if (ni_dhcp6_parse_client_header(msgbuf, &msg_type, &msg_xid) < 0) {
		ni_error("%s: short DHCP6 client packet (%u bytes) from %s",
				dev->ifname, ni_buffer_count(msgbuf),
				ni_dhcp6_address_print(sender));
		return -1;
	}

	if (ni_dhcp6_check_client_header(dev, sender, msg_type, msg_xid) < 0)
		return -1;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	lease->time_acquired = time(NULL);
	/* set the server address in the lease */
	memcpy(&lease->dhcp6.server_addr, sender, sizeof(lease->dhcp6.server_addr));

	if (ni_dhcp6_parse_client_options(dev, msgbuf, lease) < 0) {
		ni_error("%s: unable to parse options in %s message xid 0x%06x from %s",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
			ni_dhcp6_address_print(sender));
		goto failure;
	}

	ni_stringbuf_printf(&ignore_hint, ": TODO");
	switch (msg_type) {
	case NI_DHCP6_REPLY:
	default:
//	ignore:
		ni_debug_dhcp("%s: ignoring %s message xid 0x%06x in state %s from %s%s",
				dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_address_print(sender),
				(ignore_hint.string ? ignore_hint.string : ""));
	break;
	}

failure:
	if (lease && dev->lease != lease) {
		ni_addrconf_dhcp6_lease_free(lease);
	}
	return rv;
}

int
ni_dhcp6_fsm_process_client_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_BOUND:
		/* TODO: reconfigure */
	break;

	case NI_DHCP6_STATE_SELECTING:
		return __fsm_select_process_packet(dev, msgbuf, sender);
	break;

	case NI_DHCP6_STATE_REQUESTING:
		return __fsm_request_process_packet(dev, msgbuf, sender);
	break;

	case NI_DHCP6_STATE_CONFIRMING:
		return __fsm_confirm_process_packet(dev, msgbuf, sender);
	break;

	case NI_DHCP6_STATE_RENEWING:
		return __fsm_renew_process_packet(dev, msgbuf, sender);
	break;

	case NI_DHCP6_STATE_REBINDING:
		return __fsm_rebind_process_packet(dev, msgbuf, sender);
	break;

	case NI_DHCP6_STATE_DECLINING:
		return __fsm_decline_process_packet(dev, msgbuf, sender);
	break;

	case NI_DHCP6_STATE_RELEASING:
		return __fsm_release_process_packet(dev, msgbuf, sender);
	break;

	case NI_DHCP6_STATE_REQUESTING_INFO:
		return __fsm_release_process_packet(dev, msgbuf, sender);
	break;

	case NI_DHCP6_STATE_INIT:
	case NI_DHCP6_STATE_WAIT_READY:
	case NI_DHCP6_STATE_VALIDATING:
	default:
		ni_debug_dhcp("Ignored packet in state %s",
				ni_dhcp6_fsm_state_name(dev->fsm.state));
		break;
	}
	return -1;
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

		dev->dhcp6.xid = 0;
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

		dev->dhcp6.xid = 0;
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

		dev->dhcp6.xid = 0;
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
ni_dhcp6_fsm_renew(ni_dhcp6_device_t *dev)
{
	int rv = -1;

	if (!dev->lease)
		return -1;

	if (dev->retrans.count == 0) {
		ni_debug_dhcp("%s[%u]: Initiating DHCPv6 Lease Renew",
				dev->ifname, dev->link.ifindex);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_RENEW, dev->lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_RENEWING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		ni_debug_dhcp("%s[%u]: Retransmitting DHCPv6 Lease Renew",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_RENEW, &dev->message, dev->lease) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

static int
ni_dhcp6_fsm_rebind(ni_dhcp6_device_t *dev)
{
	int rv = -1;

	if (!dev->lease)
		return -1;

	if (dev->retrans.count == 0) {
		ni_debug_dhcp("%s[%u]: Initiating DHCPv6 Lease Rebind",
				dev->ifname, dev->link.ifindex);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_REBIND, dev->lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_REBINDING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		ni_debug_dhcp("%s[%u]: Retransmitting DHCPv6 Lease Rebind",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_REBIND, &dev->message, dev->lease) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

static int
ni_dhcp6_fsm_decline(ni_dhcp6_device_t *dev)
{
	int rv = -1;

	if (!dev->lease)
		return -1;

	if (dev->retrans.count == 0) {
		ni_debug_dhcp("%s[%u]: Initiating DHCPv6 Lease Decline",
				dev->ifname, dev->link.ifindex);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_DECLINE, dev->lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_DECLINING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		ni_debug_dhcp("%s[%u]: Retransmitting DHCPv6 Lease Decline",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_DECLINE, &dev->message, dev->lease) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

static int
ni_dhcp6_fsm_release(ni_dhcp6_device_t *dev)
{
	int rv = -1;

	if (!dev->lease)
		return -1;

	if (dev->retrans.count == 0) {
		ni_debug_dhcp("%s[%u]: Initiating DHCPv6 Lease Rebind",
				dev->ifname, dev->link.ifindex);

		/* currently everything */
		ni_dhcp6_ia_release_matching(dev->lease->dhcp6.ia_list, NULL, 0);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_REBIND, dev->lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_REBINDING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		ni_debug_dhcp("%s[%u]: Retransmitting DHCPv6 Lease Rebind",
				dev->ifname, dev->link.ifindex);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_REBIND, &dev->message, dev->lease) != 0)
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

		dev->dhcp6.xid = 0;
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

#if 0
void
__calculate_lease_times(ni_addrconf_lease_t *lease, unsigned int cur_time)
{
	struct ni_dhcp6_ia *ia;
	struct ni_dhcp6_ia_addr *addr;
	unsigned int addr_count;
	unsigned int address_expire, tmp;
	unsigned int renew = NI_DHCP6_INFINITE_LIFETIME, rebind = NI_DHCP6_INFINITE_LIFETIME;

	for (ia = lease->dhcp6.ia_na; ia; ia = ia->next) {
		for (addr = ia->addrs; addr; addr = addr->next) {
			;
		}

		if (ia->renewal_time == NI_DHCP6_INFINITE_LIFETIME) {
			tmp = NI_DHCP6_INFINITE_LIFETIME;
		} else if (ia->renewal_time == 0) {
			tmp = ia->time_acquired + address_expire;
		} else {
			tmp = ia->time_acquired + ia->renewal_time;
		}

		if (tmp < renew)
			renew = tmp;

		if (ia->rebind_time == NI_DHCP6_INFINITE_LIFETIME) {
			tmp = NI_DHCP6_INFINITE_LIFETIME;
		} else if (ia->rebind_time == 0) {
			tmp = ia->time_acquired + address_expire + (address_expire/2);
		} else {
			tmp = ia->time_acquired + ia->rebind_time;
		}

	}
}
#endif

static int
ni_dhcp6_fsm_commit_lease(ni_dhcp6_device_t *dev, ni_addrconf_lease_t *lease)
{
	if (lease) {
		/* OK, now we can provide the lease to wicked,
		 * that will set the IPs causing kernel to
		 * perform IPv6 dad.
		 *
		 * As soon as dad finished, we can change to
		 * BOUND state and wait until renew etc. or
		 * DECLINE the address on dad failure.
		 */

		ni_dhcp6_device_set_lease(dev, lease);

		dev->fsm.state = NI_DHCP6_STATE_VALIDATING;
		ni_dhcp6_fsm_set_timeout_msec(dev, NI_DHCP6_WAIT_IAADDR_READY);

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
	[NI_DHCP6_STATE_WAIT_READY]	= "WAITING READY",
	[NI_DHCP6_STATE_SELECTING]      = "SELECTING",
	[NI_DHCP6_STATE_CONFIRMING]	= "CONFIRMING",
	[NI_DHCP6_STATE_REQUESTING]     = "REQUESTING",
	[NI_DHCP6_STATE_VALIDATING]     = "VALIDATING",
	[NI_DHCP6_STATE_BOUND]          = "BOUND",
	[NI_DHCP6_STATE_RENEWING]       = "RENEWING",
	[NI_DHCP6_STATE_REBINDING]	= "REBINDING",
	[NI_DHCP6_STATE_RELEASING]	= "RELEASING",
	[NI_DHCP6_STATE_DECLINING]	= "DECLINING",
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
