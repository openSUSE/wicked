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

struct ni_dhcp6_message {
	struct in6_addr		sender;
	unsigned int		type;
	unsigned int		xid;

	ni_addrconf_lease_t *	lease;
};

static void			ni_dhcp6_fsm_timeout(ni_dhcp6_device_t *);
static void             	__ni_dhcp6_fsm_timeout(void *, const ni_timer_t *);
static void			ni_dhcp6_fsm_timer_cancel(ni_dhcp6_device_t *);

static int			ni_dhcp6_fsm_solicit      (ni_dhcp6_device_t *);
static int			__ni_dhcp6_fsm_solicit    (ni_dhcp6_device_t *, int);
static int			__ni_dhcp6_fsm_release    (ni_dhcp6_device_t *, unsigned int);
static int			ni_dhcp6_fsm_request_lease(ni_dhcp6_device_t *, const ni_addrconf_lease_t *);
static int			ni_dhcp6_fsm_confirm_lease(ni_dhcp6_device_t *, const ni_addrconf_lease_t *);
static int			ni_dhcp6_fsm_renew(ni_dhcp6_device_t *);
static int			ni_dhcp6_fsm_rebind(ni_dhcp6_device_t *);
static int			ni_dhcp6_fsm_decline(ni_dhcp6_device_t *);
static int			ni_dhcp6_fsm_request_info (ni_dhcp6_device_t *);

static int			ni_dhcp6_fsm_commit_lease (ni_dhcp6_device_t *, ni_addrconf_lease_t *);
static int			ni_dhcp6_fsm_bound(ni_dhcp6_device_t *);

static unsigned int		ni_dhcp6_fsm_get_renewal_timeout(ni_dhcp6_device_t *);
static unsigned int		ni_dhcp6_fsm_get_rebind_timeout(ni_dhcp6_device_t *);
static unsigned int		ni_dhcp6_fsm_get_expire_timeout(ni_dhcp6_device_t *);

static unsigned int		ni_dhcp6_fsm_mark_renew_ia(ni_dhcp6_device_t *);
static unsigned int		ni_dhcp6_fsm_mark_rebind_ia(ni_dhcp6_device_t *);

static void			ni_dhcp6_send_event(enum ni_dhcp6_event, const ni_dhcp6_device_t *, ni_addrconf_lease_t *);

static int			__fsm_parse_client_options(ni_dhcp6_device_t *, struct ni_dhcp6_message *, ni_buffer_t *);



/*
 * How long to wait until an address is ready to use
 * For now we use 2 sec: DAD default of 1 sec + time
 * needed to send to wicked and apply to the system...
 */
#define NI_DHCP6_WAIT_IAADDR_READY		2000


/*
 * Global fsm handler
 */
static ni_dhcp6_event_handler_t *ni_dhcp6_fsm_event_handler;

static ni_bool_t
ni_dhcp6_lease_with_active_address(const ni_addrconf_lease_t *lease)
{
	struct timeval now;

	if (!ni_addrconf_lease_is_valid(lease))
		return FALSE;

	if (lease->type != NI_ADDRCONF_DHCP || lease->family != AF_INET6)
		return FALSE;

	if (ni_timer_get_time(&now) < 0)
		return FALSE;

	return ni_dhcp6_ia_list_count_active(lease->dhcp6.ia_list, &now) > 0;
}

int
ni_dhcp6_fsm_start(ni_dhcp6_device_t *dev)
{
	if (!dev->config)
		return -1;

	switch (dev->config->mode) {
	default:
		ni_error("%s: fsm start in invalid mode %u",
			dev->ifname, dev->config->mode);
		return -1;

	case NI_DHCP6_MODE_AUTO:
		/* this should not happen */
		ni_warn("%s: fsm start in mode %s", dev->ifname,
			ni_dhcp6_mode_type_to_name(dev->config->mode));
		return 1;	/* not ready, wait for RA hint */

	case NI_DHCP6_MODE_INFO:
		ni_dhcp6_fsm_reset(dev);

		if (ni_dhcp6_lease_with_active_address(dev->lease)) {
			return __ni_dhcp6_fsm_release(dev, 0);
		}

		ni_dhcp6_device_drop_lease(dev);
		return ni_dhcp6_fsm_request_info(dev);

	case NI_DHCP6_MODE_MANAGED:
		ni_dhcp6_fsm_reset(dev);

		if (ni_dhcp6_lease_with_active_address(dev->lease)) {
			return ni_dhcp6_fsm_confirm_lease(dev, dev->lease);
		}

		ni_dhcp6_device_drop_lease(dev);
		return ni_dhcp6_fsm_solicit(dev);
	}
}

void
ni_dhcp6_fsm_reset(ni_dhcp6_device_t *dev)
{
	dev->fsm.state = NI_DHCP6_STATE_INIT;

	ni_dhcp6_fsm_timer_cancel(dev);
	ni_dhcp6_device_retransmit_disarm(dev);

	/* device? It is temporary fsm data */
	ni_dhcp6_device_drop_best_offer(dev);
}

static int
ni_dhcp6_fsm_restart(ni_dhcp6_device_t *dev)
{
	ni_dhcp6_fsm_reset(dev);
	return ni_dhcp6_fsm_start(dev);
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
ni_dhcp6_fsm_timer_cancel(ni_dhcp6_device_t *dev)
{
	dev->fsm.fail_on_timeout = 0;
	if (dev->fsm.timer) {
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
	dev->fsm.timer = NULL;

	ni_dhcp6_fsm_timeout(dev);
}


static void
ni_dhcp6_fsm_timeout(ni_dhcp6_device_t *dev)
{
	ni_debug_dhcp("%s: timeout in state %s%s",
			dev->ifname, ni_dhcp6_fsm_state_name(dev->fsm.state),
			dev->fsm.fail_on_timeout? " (fatal failure)" : "");

	if (dev->fsm.fail_on_timeout) {
		dev->fsm.fail_on_timeout = 0;

		ni_dhcp6_device_stop(dev);
		return;
	}

	if (dev->retrans.delay) {
		ni_debug_dhcp("%s: starting to transmit after initial delay",
				dev->ifname);
		dev->retrans.delay = 0;
		ni_dhcp6_device_transmit_start(dev);
		return;
	}

	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_INIT:
		if (dev->config->mode == NI_DHCP6_MODE_AUTO) {
			ni_addrconf_lease_t *lease;
			/*
			 * No DHCPv6 on the network in auto mode -- provide
			 * a dummy lease, so wicked does not report failure.
			 */
			lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
			lease->state = NI_ADDRCONF_STATE_GRANTED;
			lease->update = 0; /* dev->config->update; */
			lease->time_acquired = time(NULL);
			ni_dhcp6_fsm_commit_lease(dev, lease);
			return;
		}
		break;

	case NI_DHCP6_STATE_SELECTING:

		/* the weight has maximum value, just accept this offer */
		if (dev->best_offer.lease) {
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

	case NI_DHCP6_STATE_CONFIRMING:
		/*
		 * http://tools.ietf.org/html/rfc3315#section-18.1.2
		 *
		 * "[...]
		 * client SHOULD continue to use any IP addresses, using the
		 * last known lifetimes [...] and SHOULD continue to use any
		 * other previously obtained configuration parameters.
		 * [...]"
		 */
		if (dev->lease) {
			/*
			 * Commit current lease to continue using it.
			 *
			 * TODO: Verify this.
			 *   Currently we apply with original lifetimes,
			 *   we may update IA addrs to remaining times.
			 */
			ni_dhcp6_fsm_reset(dev);
			ni_dhcp6_fsm_commit_lease(dev, dev->lease);
		} else {
			/* Lease vanished?! Restart from request... */
			ni_dhcp6_device_restart(dev);
		}
		break;

	case NI_DHCP6_STATE_REQUESTING:
		/* FIXME: */
		break;

	case NI_DHCP6_STATE_VALIDATING:
		ni_dhcp6_fsm_bound(dev);
		break;

	case NI_DHCP6_STATE_BOUND:
		ni_dhcp6_fsm_renew(dev);
		break;

	case NI_DHCP6_STATE_RENEWING:
		ni_dhcp6_fsm_reset(dev);
		ni_dhcp6_fsm_rebind(dev);
		break;

	case NI_DHCP6_STATE_REBINDING:
		ni_dhcp6_device_drop_lease(dev);
		ni_dhcp6_fsm_restart(dev);
		break;

	case NI_DHCP6_STATE_DECLINING:
		/* FIXME: */
		break;

	case NI_DHCP6_STATE_RELEASING:
		ni_dhcp6_device_drop_lease(dev);
		ni_dhcp6_device_stop(dev);
		break;

	default:
		break;
	}
}

static inline ni_bool_t
__fsm_select_best_offer(const ni_dhcp6_device_t *dev, const ni_addrconf_lease_t *lease, int weight)
{
	/* ignore offers without any lease addrs */
	if (ni_address_list_count(lease->addrs) == 0)
		return FALSE;

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
__fsm_select_process_msg(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts, char **hint)
{
	int weight = 0;
	int rv = 1;

	switch (msg->type) {
	case NI_DHCP6_ADVERTISE:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;


		if (msg->lease->dhcp6.rapid_commit) {
			ni_string_printf(hint, "advertise with rapid commit option");
			goto cleanup;
		}

		/*
		 * We've to discard all advertise messages with status NI_DHCP6_STATUS_NOADDRS;
		 * the another codes IMO don't fit here, so we discard all unsuccessful codes.
		 */
		if (msg->lease->dhcp6.status && msg->lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_string_printf(hint, "status %s - %s",
					ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
					msg->lease->dhcp6.status->message);
			goto cleanup;
		}

		/* check if the config provides/overrides the preference */
		if (!ni_dhcp6_config_server_preference(	&msg->lease->dhcp6.server_addr,
							&msg->lease->dhcp6.server_id,
							&weight)) {
			weight = msg->lease->dhcp6.server_pref;
		}

		if (weight < 0) {
			ni_string_printf(hint, "blacklisted server");
			goto cleanup;
		}

		if(__fsm_select_best_offer(dev, msg->lease, weight)) {
			if (dev->best_offer.lease)
				ni_addrconf_lease_free(dev->best_offer.lease);
			dev->best_offer.weight = weight;
			dev->best_offer.lease = msg->lease;
			msg->lease = NULL;
		} else {
			goto cleanup;
		}

		/* the weight has maximum value, just accept this offer */
		if (dev->best_offer.weight >= 255) {
			ni_dhcp6_fsm_timer_cancel(dev);
			ni_dhcp6_device_retransmit_disarm(dev);

			ni_dhcp6_fsm_request_lease(dev, dev->best_offer.lease);
		}
		rv = 0;
	break;

	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;

		/*
		 * Hmm...
		 */
		if (msg->lease->dhcp6.status && msg->lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
						msg->lease->dhcp6.status->message);
			goto cleanup;
		}

		if (!msg->lease->dhcp6.rapid_commit) {
			ni_string_printf(hint, "rapid commit not set");
			goto cleanup;
		}

		/*
		 * 17.1.4. says it is our decision if we accept unrequested rapid-commit or not.
		 * The message is already filtered by last xid, so when we are here, we didn't
		 * sent Request yet.
		 */

		/* check if the config provides/overrides the preference */
		if (!ni_dhcp6_config_server_preference( &msg->lease->dhcp6.server_addr,
							&msg->lease->dhcp6.server_id,
							&weight)) {
			weight = msg->lease->dhcp6.server_pref;
		}
		if (weight < 0) {
			ni_string_printf(hint, "blacklisted server");
			goto cleanup;
		}

		if(__fsm_select_best_offer(dev, msg->lease, weight)) {
			if (dev->best_offer.lease)
				ni_addrconf_lease_free(dev->best_offer.lease);
			dev->best_offer.weight = weight;
			dev->best_offer.lease = msg->lease;
			msg->lease = NULL;
		} else {
			goto cleanup;
		}

		/* the weight has maximum value, just accept this lease */
		if (dev->best_offer.weight >= 255) {
			ni_dhcp6_fsm_timer_cancel(dev);
			ni_dhcp6_device_retransmit_disarm(dev);

			ni_dhcp6_fsm_commit_lease(dev, dev->best_offer.lease);
			dev->best_offer.lease = NULL;
			dev->best_offer.weight = -1;
		}
		rv = 0;
	break;

	default:
	break;
	}

cleanup:
	return rv;
}

static int
__fsm_request_process_msg(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts, char **hint)
{
	int rv = 1;

	switch (msg->type) {
	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;

		if (!dev->best_offer.lease) {
			ni_string_printf(hint, "lease request reply without request");
			goto cleanup;
		}

		/*
		 * best offer points to the lease we've requested -- check that the
		 * server in the reply matches the server we request the lease from.
		 */
		if (!IN6_ARE_ADDR_EQUAL(&dev->best_offer.lease->dhcp6.server_addr, &msg->lease->dhcp6.server_addr) ||
		    !ni_opaque_eq(&dev->best_offer.lease->dhcp6.server_id, &msg->lease->dhcp6.server_id)) {
			ni_string_printf(hint, "lease request reply from another server");
			goto cleanup;
		}

		if (msg->lease->dhcp6.status && msg->lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
						msg->lease->dhcp6.status->message);
			goto cleanup;
		}

		/*
		 * FIXME: exact match check!! for now, it needs at least equal address count
		 */
		if (ni_address_list_count(msg->lease->addrs) < ni_address_list_count(dev->best_offer.lease->addrs))
			goto cleanup;

		ni_dhcp6_fsm_timer_cancel(dev);
		ni_dhcp6_device_retransmit_disarm(dev);

		ni_dhcp6_fsm_commit_lease(dev, msg->lease);
		msg->lease = NULL;

		ni_dhcp6_device_drop_best_offer(dev);
		rv = 0;
	break;

	default:
	break;
	}

cleanup:
	return rv;
}

static int
__fsm_confirm_process_msg(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts, char **hint)
{

	int rv = 1;

	switch (msg->type) {
	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;
		/*
		 * http://tools.ietf.org/html/rfc3315#section-18.1.8
		 * "[...]
		 * When the client receives a NotOnLink status from the server in
		 * response to a Confirm message, the client performs DHCP server
		 * solicitation, as described in section 17, and client-initiated
		 * configuration as described in section 18. If the client receives
		 * any Reply messages that do not indicate a NotOnLink status, the
		 * client can use the addresses in the IA and ignore any messages
		 * that indicate a NotOnLink status.[...]"
		 *
		 * Basically it means we have to use best_offer here and wait for
		 * (success) message similar with solicit...
		 */
		if (!dev->lease) {
			ni_string_printf(hint, "confirm reply without a lease?!");
			goto cleanup;
		}

		if (msg->lease->dhcp6.status == NULL) {
			ni_string_printf(hint, "confirm reply without status");
			goto cleanup;
		}

		if (dev->lease &&
		    msg->lease->dhcp6.status->code == NI_DHCP6_STATUS_SUCCESS) {
			ni_dhcp6_fsm_reset(dev);
			ni_dhcp6_fsm_commit_lease(dev, dev->lease);
			rv = 0;
		} else
		if (msg->lease->dhcp6.status->code == NI_DHCP6_STATUS_NOTONLINK) {
			ni_dhcp6_device_drop_lease(dev);
			ni_dhcp6_device_restart(dev);
			rv = 0;
		} else {
			ni_string_printf(hint, "status %s - %s",
				ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
				msg->lease->dhcp6.status->message);
			goto cleanup;
		}
	break;

	default:
	break;
	}

cleanup:
	return rv;
}

static int
__fsm_renew_process_msg(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts, char **hint)
{
	int rv = 1;

	switch (msg->type) {
	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;

		if (!dev->lease) {
			ni_string_printf(hint, "renew reply without a lease");
			goto cleanup;
		}

		if (msg->lease->dhcp6.status && msg->lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
						msg->lease->dhcp6.status->message);
			goto cleanup;
		}

		/*
		 * check that the server in the reply matches the server we request the renew from.
		 */
		if (!IN6_ARE_ADDR_EQUAL(&dev->lease->dhcp6.server_addr, &msg->lease->dhcp6.server_addr) ||
		    !ni_opaque_eq(&dev->lease->dhcp6.server_id, &msg->lease->dhcp6.server_id)) {
			ni_string_printf(hint, "renew reply from another server");
			goto cleanup;
		}

		/*
		 * FIXME: exact match check!! for now, it needs at least equal address count
		 */
		if (ni_address_list_count(msg->lease->addrs) < ni_address_list_count(dev->lease->addrs))
			goto cleanup;

		ni_dhcp6_fsm_timer_cancel(dev);
		ni_dhcp6_device_retransmit_disarm(dev);

		/*
		 * FIXME: implement update/merge of the leases!!!
		 */
		ni_dhcp6_fsm_commit_lease(dev, msg->lease);
		msg->lease = NULL;
		rv = 0;
	break;

	default:
	break;
	}

cleanup:
	return rv;
}


static int
__fsm_rebind_process_msg(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts, char **hint)
{
	int rv = 1;

	switch (msg->type) {
	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;

		if (!dev->lease) {
			ni_string_printf(hint, "rebind reply without a lease");
			goto cleanup;
		}

		if (msg->lease->dhcp6.status && msg->lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
						msg->lease->dhcp6.status->message);
			goto cleanup;
		}

		/*
		 * FIXME: Well... this wrong. We rebind here. handle as offer.
		 */
#if 1
		if (!IN6_ARE_ADDR_EQUAL(&dev->lease->dhcp6.server_addr, &msg->lease->dhcp6.server_addr) ||
		    !ni_opaque_eq(&dev->lease->dhcp6.server_id, &msg->lease->dhcp6.server_id)) {
			ni_string_printf(hint, "rebind reply from another server");
			goto cleanup;
		}
#else
		/* check if the config provides/overrides the preference */
		if (!ni_dhcp6_config_server_preference( &msg->lease->dhcp6.server_addr,
							&msg->lease->dhcp6.server_id,
							&weight)) {
			weight = msg->lease->dhcp6.server_pref;
		}
		if (weight < 0) {
			ni_string_printf(hint, "blacklisted server");
			goto cleanup;
		}

		if(__fsm_select_best_offer(dev, msg->lease, weight)) {
			if (dev->best_offer.lease)
				ni_addrconf_lease_free(dev->best_offer.lease);
			dev->best_offer.weight = weight;
			dev->best_offer.lease = msg->lease;
			msg->lease = NULL;
		} else {
			goto cleanup;
		}

		/* the weight has maximum value, just accept this lease */
		if (dev->best_offer.weight >= 255) {
			ni_dhcp6_fsm_timer_cancel(dev);
			ni_dhcp6_device_retransmit_disarm(dev);

			ni_dhcp6_fsm_commit_lease(dev, dev->best_offer.lease);
			dev->best_offer.lease = NULL;
			dev->best_offer.weight = -1;
		}
#endif

		/* FIXME: exact match check!! for now, it needs at least equal address count */
		if (ni_address_list_count(msg->lease->addrs) > 1)
			goto cleanup;

		ni_dhcp6_fsm_timer_cancel(dev);
		ni_dhcp6_device_retransmit_disarm(dev);

		/*
		 * FIXME: implement update/merge of the leases!!!
		 */
		ni_dhcp6_fsm_commit_lease(dev, msg->lease);
		msg->lease = NULL;
		rv = 0;
	break;

	default:
	break;
	}

cleanup:
	return rv;
}


static int
__fsm_decline_process_msg(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts, char **hint)
{
	int rv = 1;

	switch (msg->type) {
	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;

		if (!dev->lease) {
			ni_string_printf(hint, "decline reply without a lease");
			goto cleanup;
		}

		ni_error("Can't parse DECLINE message replies");
	break;

	default:
	break;
	}

cleanup:
	return rv;
}

static int
__fsm_release_process_msg(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts, char **hint)
{
	int rv = 1;

	switch (msg->type) {
	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;

		if (!dev->lease) {
			ni_string_printf(hint, "release reply without a lease");
			goto cleanup;
		}

		/*
		 * check that the server in the reply matches the server we request the renew from.
		 */
		if (!IN6_ARE_ADDR_EQUAL(&dev->lease->dhcp6.server_addr, &msg->lease->dhcp6.server_addr) ||
		    !ni_opaque_eq(&dev->lease->dhcp6.server_id, &msg->lease->dhcp6.server_id)) {
			ni_string_printf(hint, "release reply from another server");
			goto cleanup;
		}

		if (msg->lease->dhcp6.status == NULL) {
			ni_string_printf(hint, "release reply without status");
			goto cleanup;
		}

		if (msg->lease->dhcp6.status->code == NI_DHCP6_STATUS_SUCCESS ||
		    msg->lease->dhcp6.status->code == NI_DHCP6_STATUS_NOTONLINK) {
			ni_debug_dhcp("%s: Received release reply %s %s -- comitting release",
					dev->ifname,
					ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
					msg->lease->dhcp6.status->message);

			ni_dhcp6_fsm_reset(dev);
			if (dev->config->mode == NI_DHCP6_MODE_INFO) {
				ni_dhcp6_device_drop_lease(dev);
				ni_dhcp6_fsm_restart(dev);
			} else {
				ni_dhcp6_fsm_commit_lease(dev, NULL);
			}
			rv = 0;
		} else {
			ni_string_printf(hint, "status %s - %s",
				ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
				msg->lease->dhcp6.status->message);
			goto cleanup;
		}

	break;

	default:
	break;
	}

cleanup:
	return rv;
}

static int
__fsm_inforeq_process_msg(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts, char **hint)
{
	int rv = 1;

	switch (msg->type) {
	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;

		if (msg->lease->dhcp6.status && msg->lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
						msg->lease->dhcp6.status->message);
			goto cleanup;
		}

		ni_dhcp6_fsm_timer_cancel(dev);
		ni_dhcp6_device_retransmit_disarm(dev);

		ni_dhcp6_fsm_commit_lease(dev, msg->lease);
		msg->lease = NULL;
		rv = 0;
	break;

	default:
	break;
	}

cleanup:
	return rv;
}

static int
__fsm_parse_client_options(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts)
{
	ni_addrconf_lease_t *lease = NULL;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	lease->time_acquired = time(NULL);
	/* set the server address in the lease */
	memcpy(&lease->dhcp6.server_addr, &msg->sender, sizeof(lease->dhcp6.server_addr));

	if (ni_dhcp6_parse_client_options(dev, opts, lease) < 0) {
		ni_error("%s: unable to parse options in %s message xid 0x%06x from %s",
			dev->ifname, ni_dhcp6_message_name(msg->type),
			msg->xid, ni_dhcp6_address_print(&msg->sender));
		goto failure;
	}

	if (lease->dhcp6.client_id.len == 0) {
		ni_error("%s: ignoring %s message xid 0x%06x from %s: client-id missed",
				dev->ifname, ni_dhcp6_message_name(msg->type), msg->xid,
				ni_dhcp6_address_print(&msg->sender));
		goto failure;
	}
	if (lease->dhcp6.server_id.len == 0) {
		ni_error("%s]: ignoring %s message xid 0x%06x from %s: server-id missed",
			dev->ifname, ni_dhcp6_message_name(msg->type), msg->xid,
			ni_dhcp6_address_print(&msg->sender));
		goto failure;
	}
	if (!ni_opaque_eq(&dev->config->client_duid, &lease->dhcp6.client_id)) {
		ni_error("%s: ignoring %s message xid 0x%06x from %s: client-id differs",
			dev->ifname, ni_dhcp6_message_name(msg->type), msg->xid,
			ni_dhcp6_address_print(&msg->sender));
		goto failure;
	}

	msg->lease = lease;
	return 0;

failure:
	ni_addrconf_lease_free(lease);
	return -1;
}

int
ni_dhcp6_fsm_process_client_message(ni_dhcp6_device_t *dev, unsigned int msg_type, unsigned int msg_xid,
					ni_buffer_t *options, const struct in6_addr *sender)
{
	char * hint = NULL;
	struct ni_dhcp6_message msg;
	int state = dev->fsm.state;
	int rv = 1;

	msg.sender = *sender;
	msg.type = msg_type;
	msg.xid = msg_xid;
	msg.lease = NULL;

	ni_debug_dhcp("%s: received %s message xid 0x%06x in state %s from %s",
			dev->ifname, ni_dhcp6_message_name(msg.type), msg.xid,
			ni_dhcp6_fsm_state_name(dev->fsm.state),
			ni_dhcp6_address_print(&msg.sender));

	ni_string_printf(&hint, "unexpected");
	switch (state) {
	case NI_DHCP6_STATE_SELECTING:
		rv = __fsm_select_process_msg(dev, &msg, options, &hint);
	break;
	case NI_DHCP6_STATE_REQUESTING:
		rv = __fsm_request_process_msg(dev, &msg, options, &hint);
	break;
	case NI_DHCP6_STATE_CONFIRMING:
		rv = __fsm_confirm_process_msg(dev, &msg, options, &hint);
	break;
	case NI_DHCP6_STATE_RENEWING:
		rv = __fsm_renew_process_msg(dev, &msg, options, &hint);
	break;
	case NI_DHCP6_STATE_REBINDING:
		rv = __fsm_rebind_process_msg(dev, &msg, options, &hint);
	break;
	case NI_DHCP6_STATE_DECLINING:
		rv = __fsm_decline_process_msg(dev, &msg, options, &hint);
	break;
	case NI_DHCP6_STATE_RELEASING:
		rv = __fsm_release_process_msg(dev, &msg, options, &hint);
	break;
	case NI_DHCP6_STATE_REQUESTING_INFO:
		rv = __fsm_inforeq_process_msg(dev, &msg, options, &hint);
	break;

	default:
	break;
	}

	if (rv > 0) {
		ni_debug_dhcp("%s: ignoring %s message xid 0x%06x in state %s from %s%s%s",
			dev->ifname, ni_dhcp6_message_name(msg_type), msg_xid,
			ni_dhcp6_fsm_state_name(state), ni_dhcp6_address_print(sender),
			(hint ? ": " : ""), (hint ? hint : ""));
	}
	ni_string_free(&hint);

	if (msg.lease != NULL && msg.lease != dev->lease)
		ni_addrconf_lease_free(msg.lease);

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
		ni_debug_dhcp("%s: Initiating DHCPv6 Server Solicitation",
				dev->ifname);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_SOLICIT, lease) != 0)
			goto cleanup;

		dev->fsm.state = NI_DHCP6_STATE_SELECTING;

		/* FIXME: */
		dev->dhcp6.accept_any_offer = scan_offers;

		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		ni_debug_dhcp("%s: Retransmitting DHCPv6 Server Solicitation",
				dev->ifname);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_SOLICIT, &dev->message, lease) != 0)
			goto cleanup;

		rv = ni_dhcp6_device_transmit(dev);
	}

cleanup:
	if (lease != dev->lease) {
		ni_addrconf_lease_free(lease);
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
		ni_debug_dhcp("%s: Initiating DHCPv6 Lease Request",
				dev->ifname);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_REQUEST, lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_REQUESTING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		ni_debug_dhcp("%s: Retransmitting DHCPv6 Lease Request",
				dev->ifname);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_REQUEST, &dev->message, lease) != 0)
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
		ni_debug_dhcp("%s: Initiating DHCPv6 Info Request",
				dev->ifname);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_INFO_REQUEST, NULL) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_REQUESTING_INFO;
		dev->dhcp6.accept_any_offer = 1;

		rv = ni_dhcp6_device_transmit_init(dev);
	} else if (dev->fsm.state == NI_DHCP6_STATE_REQUESTING_INFO) {

		ni_debug_dhcp("%s: Retransmitting DHCPv6 Info Request",
				dev->ifname);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_INFO_REQUEST, &dev->message, NULL) != 0)
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
		ni_debug_dhcp("%s: Initiating DHCPv6 Lease Confirmation",
				dev->ifname);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_CONFIRM, lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_CONFIRMING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else if (dev->fsm.state == NI_DHCP6_STATE_CONFIRMING) {

		ni_debug_dhcp("%s: Retransmitting DHCPv6 Lease Confirmation",
				dev->ifname);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_CONFIRM, &dev->message, lease) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

static int
ni_dhcp6_fsm_renew(ni_dhcp6_device_t *dev)
{
	unsigned int deadline;
	struct timeval now;
	int rv = -1;

	if (!dev->lease)
		return -1;

	if (dev->retrans.count == 0) {
		if (ni_dhcp6_fsm_mark_renew_ia(dev) == 0) {
			/* TODO: apply >0 jitter ? */
			ni_warn("Unable to find any IA requiring a renew");
			ni_dhcp6_fsm_set_timeout_msec(dev, 1001);
			dev->fsm.fail_on_timeout = 1;
			return 1;
		}

		deadline = ni_dhcp6_fsm_get_rebind_timeout(dev);
		ni_timer_get_time(&now);
		now.tv_sec += deadline;

		ni_debug_dhcp("%s: Initiating DHCPv6 Renew, duration %u sec until %s",
				dev->ifname, deadline, ni_dhcp6_print_timeval(&now));

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_RENEW, dev->lease) != 0)
			return -1;

		dev->retrans.duration = deadline * 1000;
		dev->fsm.state = NI_DHCP6_STATE_RENEWING;

		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		/* Pickup more IA's that reached renewal time */
		ni_dhcp6_fsm_mark_renew_ia(dev);

		ni_debug_dhcp("%s: Retransmitting DHCPv6 Renew", dev->ifname);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_RENEW, &dev->message, dev->lease) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

static int
ni_dhcp6_fsm_rebind(ni_dhcp6_device_t *dev)
{
	unsigned int deadline;
	struct timeval now;
	int rv = -1;

	if (!dev->lease)
		return -1;

	if (dev->retrans.count == 0) {
		/* TODO: this function has to return count
		 *       of all IA's marked for REBIND...
		 *
		 *       we've to force rebind from addr
		 *       update event when addr changes
		 *       its flags to deprecated...
		 */
		if (ni_dhcp6_fsm_mark_rebind_ia(dev) == 0) {
			/* TODO: apply >0 jitter ? */
			ni_warn("Unable to find any IA requiring a rebind");
			ni_dhcp6_fsm_set_timeout_msec(dev, 1002);
			dev->fsm.fail_on_timeout = 1;
			return 1;
		}

		deadline = ni_dhcp6_fsm_get_expire_timeout(dev);
		ni_timer_get_time(&now);
		now.tv_sec += deadline;

		ni_debug_dhcp("%s: Initiating DHCPv6 Rebind, duration %u sec until %s",
				dev->ifname, deadline, ni_dhcp6_print_timeval(&now));

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_REBIND, dev->lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_REBINDING;
		dev->retrans.duration = deadline * 1000;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		/* Pickup more IA's that reached rebind time
		 * and all which reached the renewal time... */
		ni_dhcp6_fsm_mark_renew_ia(dev);
		ni_dhcp6_fsm_mark_rebind_ia(dev);

		ni_debug_dhcp("%s: Retransmitting DHCPv6 Rebind", dev->ifname);

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
		ni_debug_dhcp("%s: Initiating DHCPv6 Decline", dev->ifname);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_DECLINE, dev->lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_DECLINING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		ni_debug_dhcp("%s: Retransmitting DHCPv6 Decline", dev->ifname);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_DECLINE, &dev->message, dev->lease) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

static int
__ni_dhcp6_fsm_release(ni_dhcp6_device_t *dev, unsigned int nretries)
{
	int rv = -1;

	if (!dev->lease)
		return -1;

	if (dev->retrans.count == 0) {
		ni_debug_dhcp("%s: Initiating DHCPv6 Release", dev->ifname);

		/* currently all addresses */
		ni_dhcp6_ia_release_matching(dev->lease->dhcp6.ia_list, NULL, 0);

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_RELEASE, dev->lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_RELEASING;
		rv = ni_dhcp6_device_transmit_init(dev);
		if (nretries) {
			dev->retrans.params.nretries = nretries;
		}
	} else {
		ni_debug_dhcp("%s: Retransmitting DHCPv6 Release", dev->ifname);

		if (ni_dhcp6_build_message(dev, NI_DHCP6_RELEASE, &dev->message, dev->lease) != 0)
			return -1;

		rv = ni_dhcp6_device_transmit(dev);
	}
	return rv;
}

int
ni_dhcp6_fsm_release(ni_dhcp6_device_t *dev)
{
	/* When all IA's are expired, just commit a release */
	if (ni_dhcp6_lease_with_active_address(dev->lease)) {
		return __ni_dhcp6_fsm_release(dev, 0);
	}

	if (dev->config->mode == NI_DHCP6_MODE_INFO) {
		ni_dhcp6_device_drop_lease(dev);
		return ni_dhcp6_fsm_restart(dev);
	} else {
		return ni_dhcp6_fsm_commit_lease(dev, NULL);
	}
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
			ni_dhcp6_device_stop(dev);
		}

		ni_dhcp6_fsm_restart(dev);
	}
	return 0;
}

static int
ni_dhcp6_fsm_bound(ni_dhcp6_device_t *dev)
{
	unsigned int timeout;
	struct timeval now;

	if (!dev->lease)
		return -1;

	timeout = ni_dhcp6_fsm_get_renewal_timeout(dev);
	if (timeout > 0) {
		dev->fsm.state = NI_DHCP6_STATE_BOUND;

		if (timeout == NI_DHCP6_INFINITE_LIFETIME) {
			/* Hmm... */
			ni_debug_dhcp("%s: Reached %s state with infinite lifetime",
					dev->ifname,
					ni_dhcp6_fsm_state_name(dev->fsm.state));
		} else {
			ni_timer_get_time(&now);
			now.tv_sec += timeout;

			ni_debug_dhcp("%s: Reached %s state, scheduled RENEW in %u sec at %s",
					dev->ifname, ni_dhcp6_fsm_state_name(dev->fsm.state),
					timeout, ni_dhcp6_print_timeval(&now));

			ni_dhcp6_fsm_set_timeout_msec(dev, timeout * 1000);
		}
		return 0;
	}

	/* no time left start renew now */
	return ni_dhcp6_fsm_renew(dev);
}

static unsigned int
__ni_dhcp6_fsm_mark_ia_by_time(ni_dhcp6_device_t *dev,  unsigned int (*get_ia_time)(ni_dhcp6_ia_t *),
							unsigned int flag)
{
	unsigned int rt, diff, aq;
	unsigned int count;
	struct timeval now;
	ni_dhcp6_ia_t *ia;

	count = 0;
	ni_timer_get_time(&now);
	for (ia = dev->lease->dhcp6.ia_list; ia; ia = ia->next) {
		rt = get_ia_time(ia);

		if ((aq = ia->time_acquired) == 0)
			aq = dev->lease->time_acquired;

		if (now.tv_sec > aq) {
			diff = (now.tv_sec - aq);
			if (diff + 1 >= rt) {
				ia->flags |= flag;
				++ count;
			}
		}
	}
	return count;
}

static unsigned int
ni_dhcp6_fsm_mark_renew_ia(ni_dhcp6_device_t *dev)
{
	return __ni_dhcp6_fsm_mark_ia_by_time(dev, ni_dhcp6_ia_get_renewal_time, NI_DHCP6_IA_RENEW);
}

static unsigned int
ni_dhcp6_fsm_mark_rebind_ia(ni_dhcp6_device_t *dev)
{
	return __ni_dhcp6_fsm_mark_ia_by_time(dev, ni_dhcp6_ia_get_rebind_time, NI_DHCP6_IA_REBIND);
}

static ni_dhcp6_ia_t *
__ni_dhcp6_fsm_find_lowest_ia(ni_dhcp6_ia_t *list, unsigned int (*get_ia_time)(ni_dhcp6_ia_t *),
				unsigned int *ia_lft)
{
	unsigned int lowest, lt;
	ni_dhcp6_ia_t *ia, *ia_low;

	lowest = 0;
	ia_low = NULL;
	for (ia = list; ia; ia = ia->next) {
		lt = get_ia_time(ia);
		if (ia_low == NULL || lowest > lt) {
			ia_low = ia;
			lowest = lt;
		}
	}
	if (ia_lft)
		*ia_lft = lowest;
	return ia_low;
}

static unsigned int
__ni_dhcp6_fsm_get_timeout(ni_dhcp6_device_t *dev, unsigned int (*get_ia_time)(ni_dhcp6_ia_t *))
{
	unsigned int lt, aq, diff;
	struct timeval now;
	ni_dhcp6_ia_t *ia = NULL;

	ia = __ni_dhcp6_fsm_find_lowest_ia(dev->lease->dhcp6.ia_list,
						get_ia_time, &lt);
	if (!ia)
		return 0;

	/* Infinite lease time .. should we ever refresh it? */
	if (lt ==  NI_DHCP6_INFINITE_LIFETIME)
		return lt;

	if (lt > 0) {
		aq = ia->time_acquired;
		ni_timer_get_time(&now);

		if (aq == 0 && (aq = dev->lease->time_acquired) == 0) {
			ni_warn("%s(%s): lease/ia time_acquired is 0 ?!",
				dev->ifname, __func__);
			aq = now.tv_sec;
		}
		if (now.tv_sec > aq) {
			diff = (now.tv_sec - aq);
			if (lt > diff)
				lt -= diff;
		}
	}
	return lt;
}

static unsigned int
ni_dhcp6_fsm_get_renewal_timeout(ni_dhcp6_device_t *dev)
{
	return __ni_dhcp6_fsm_get_timeout(dev, ni_dhcp6_ia_get_renewal_time);
}

static unsigned int
ni_dhcp6_fsm_get_rebind_timeout(ni_dhcp6_device_t *dev)
{
	return __ni_dhcp6_fsm_get_timeout(dev, ni_dhcp6_ia_get_rebind_time);
}


static unsigned int
ni_dhcp6_fsm_get_expire_timeout(ni_dhcp6_device_t *dev)
{
	unsigned int lt, at, diff;
	struct timeval now;
	ni_dhcp6_ia_t *ia = NULL;

	ia = __ni_dhcp6_fsm_find_lowest_ia(dev->lease->dhcp6.ia_list,
				ni_dhcp6_ia_min_preferred_lft, &lt);
	if (!ia)
		return 0;

	/* Infinite lease time .. should we ever refresh it? */
	if (lt ==  NI_DHCP6_INFINITE_LIFETIME)
		return lt;

	/*
	 * Hmm... we have to wait until "valid lifetimes of all
	 *        the addresses assigned to the IA expire" ...
	 *        not until max preferred.
	 *
	 *        This basically means, until the kernel deleted
	 *        _all_ addresses from this IA.
	 *        For the moment, we wait until max preferred_lft.
	 */
	/* lt = ni_dhcp6_ia_max_valid_lft(ia); */

	lt = ni_dhcp6_ia_max_preferred_lft(ia);
	if (lt > 0) {
		at = ia->time_acquired;
		ni_timer_get_time(&now);

		if (at == 0 && (at = dev->lease->time_acquired) == 0) {
			ni_warn("%s(%s): lease/ia time_acquired is 0 ?!",
				dev->ifname, __func__);
			at = now.tv_sec;
		}
		if (now.tv_sec > at) {
			diff = (now.tv_sec - at);
			if (lt > diff)
				lt -= diff;
		}
	}
	return lt;
}


/*
 * interface address event handlers
 */
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
				if (!IN6_ARE_ADDR_EQUAL(&iadr->addr, &ap->local_addr.six.sin6_addr))
					continue;

				if (ni_address_is_duplicate(ap)) {
					duplicate++;

					iadr->flags |= NI_DHCP6_IA_ADDR_DECLINE;
					ni_debug_dhcp("%s: address %s is duplicate, marked for decline",
							dev->ifname,
							ni_sockaddr_print(&ap->local_addr));
				} else
				if (ni_address_is_tentative(ap)) {
					tentative++;

					ni_debug_dhcp("%s: address %s is marked tentative -> wait",
							dev->ifname,
							ni_sockaddr_print(&ap->local_addr));
				}
			}
		}
	}

	if (tentative)
		return;

	if (duplicate) {
		ni_dhcp6_fsm_decline(dev);
		return;
	}

	if (tentative == 0) {
		ni_dhcp6_fsm_bound(dev);
	}
}

static void
__ni_dhcp6_fsm_address_update(ni_dhcp6_device_t *dev, ni_netdev_t *ifp, const ni_address_t *addr)
{
	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_INIT:
		if (dev->config) {
			ni_dhcp6_device_start(dev);
		}
	break;

	case NI_DHCP6_STATE_VALIDATING:
		if (dev->lease) {
			__ni_dhcp6_fsm_ia_addr_update(ifp, dev, addr);
		}
	break;

	default:
	break;
	}
}

void
ni_dhcp6_fsm_address_event(ni_dhcp6_device_t *dev, ni_netdev_t *ifp, ni_event_t event, const ni_address_t *addr)
{
#if 0
	if (addr && addr->family == AF_INET6) {
		ni_debug_events("%s: received interface ipv6 address event: %s %s",
			dev->ifname, ni_event_type_to_name(event),
			ni_sockaddr_print(&addr->local_addr));
	}
#endif

	switch (event) {
	case NI_EVENT_ADDRESS_UPDATE:
		__ni_dhcp6_fsm_address_update(dev, ifp, addr);
	break;

	case NI_EVENT_ADDRESS_DELETE:
	break;

	default:
	break;
	}
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
