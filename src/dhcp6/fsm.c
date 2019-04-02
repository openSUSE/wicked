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
#include <sys/time.h>

#include <wicked/logging.h>
#include <wicked/resolver.h>

#include "dhcp6/dhcp6.h"
#include "dhcp6/device.h"
#include "dhcp6/protocol.h"
#include "dhcp6/fsm.h"
#include "duid.h"


struct ni_dhcp6_message {
	struct in6_addr		sender;
	unsigned int		type;
	unsigned int		xid;

	ni_addrconf_lease_t *	lease;
};

static void			ni_dhcp6_fsm_timeout(ni_dhcp6_device_t *);
static void			ni_dhcp6_fsm_fail_timeout(ni_dhcp6_device_t *);
static void             	__ni_dhcp6_fsm_timeout(void *, const ni_timer_t *);
static void			ni_dhcp6_fsm_timer_cancel(ni_dhcp6_device_t *);
static unsigned int		ni_dhcp6_remaining_time(struct timeval *, unsigned int);

static int			ni_dhcp6_fsm_solicit      (ni_dhcp6_device_t *);
static int			__ni_dhcp6_fsm_release    (ni_dhcp6_device_t *, unsigned int);
static int			ni_dhcp6_fsm_request_lease(ni_dhcp6_device_t *, const ni_addrconf_lease_t *);
static int			ni_dhcp6_fsm_confirm_lease(ni_dhcp6_device_t *, const ni_addrconf_lease_t *);
static int			ni_dhcp6_fsm_renew(ni_dhcp6_device_t *);
static int			ni_dhcp6_fsm_rebind(ni_dhcp6_device_t *);
static int			ni_dhcp6_fsm_decline(ni_dhcp6_device_t *);
static int			ni_dhcp6_fsm_request_info (ni_dhcp6_device_t *);

static int			ni_dhcp6_fsm_accept_offer(ni_dhcp6_device_t *dev);
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
		return ni_dhcp6_fsm_solicit(dev);

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

int
ni_dhcp6_fsm_retransmit_end(ni_dhcp6_device_t *dev)
{
	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_RELEASING:
		ni_dhcp6_fsm_commit_lease(dev, NULL);
		ni_dhcp6_device_stop(dev);
		return 0;
	default:
		return -1;
	}
}

void
ni_dhcp6_fsm_set_timeout_msec(ni_dhcp6_device_t *dev, unsigned long msec)
{
	if (msec != 0) {
		ni_debug_dhcp("%s: setting fsm timeout to %lu msec", dev->ifname, msec);
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
__show_remaining_timeouts(ni_dhcp6_device_t *dev, const char *info)
{
	if (dev->config->defer_timeout) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: %s in state %s, remaining defer   timeout: %u of %u",
				dev->ifname, info,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_remaining_time(&dev->start_time,
					dev->config->defer_timeout),
				dev->config->defer_timeout);
	}
	if (dev->config->acquire_timeout) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
			"%s: %s in state %s, remaining acquire timeout: %u of %u",
				dev->ifname, info,
				ni_dhcp6_fsm_state_name(dev->fsm.state),
				ni_dhcp6_remaining_time(&dev->start_time,
					dev->config->acquire_timeout),
				dev->config->acquire_timeout);
	}
}

static void
ni_dhcp6_fsm_fail_timeout(ni_dhcp6_device_t *dev)
{
	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_INIT:
		/* acquire timeout was specified and is over;
		 * no RA which would arm info/managed mode.
		 */
		__show_remaining_timeouts(dev, "FAILURE");
		ni_dhcp6_send_event(NI_DHCP6_EVENT_LOST, dev, NULL);
		ni_dhcp6_device_drop_best_offer(dev);
		ni_dhcp6_device_drop_lease(dev);
		break;

	case NI_DHCP6_STATE_SELECTING:
	case NI_DHCP6_STATE_REQUESTING_INFO:
		/* acquire timeout was specified and is over;
		 * no usable dhcp server response received.
		 */
		__show_remaining_timeouts(dev, "FAILURE");

		/* Hmm... can this happen somehow? IMO useless */
		if (ni_dhcp6_fsm_accept_offer(dev) == 0)
			return;

		ni_dhcp6_send_event(NI_DHCP6_EVENT_LOST, dev, NULL);
		ni_dhcp6_device_drop_best_offer(dev);
		ni_dhcp6_device_drop_lease(dev);
		break;

	default:
		break;
	}

	ni_dhcp6_device_stop(dev);
}

static void
ni_dhcp6_fsm_timeout(ni_dhcp6_device_t *dev)
{
	if (dev->retrans.delay) {
		ni_debug_dhcp("%s: starting to transmit after initial delay",
				dev->ifname);
		dev->retrans.delay = 0;
		ni_dhcp6_device_transmit_start(dev);
		return;
	}

	ni_debug_dhcp("%s: timeout in state %s%s",
			dev->ifname, ni_dhcp6_fsm_state_name(dev->fsm.state),
			dev->fsm.fail_on_timeout ? " (failure)" : "");

	if (dev->fsm.fail_on_timeout) {
		dev->fsm.fail_on_timeout = 0;
		ni_dhcp6_fsm_fail_timeout(dev);
		return;
	}

	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_INIT:
		/*
		 * defer timeout was specified and is over;
		 * no RA which would arm info/managed mode.
		 */
		__show_remaining_timeouts(dev, "TIMEOUT");

		if (dev->config->defer_timeout) {
			unsigned int deadline;

			/* Do we still need this safeguard? */
			deadline = ni_dhcp6_remaining_time(&dev->start_time,
						dev->config->defer_timeout);
			if (deadline) {
				deadline *= 1000;
				ni_dhcp6_fsm_set_timeout_msec(dev, deadline);
				dev->fsm.fail_on_timeout = 0;
				return;
			}
		}

		ni_dhcp6_send_event(NI_DHCP6_EVENT_DEFERRED, dev, NULL);
		if (dev->config->acquire_timeout) {
			unsigned int deadline;

			deadline = ni_dhcp6_remaining_time(&dev->start_time,
					dev->config->acquire_timeout);
			if (deadline) {
				deadline *= 1000;
				ni_dhcp6_fsm_set_timeout_msec(dev, deadline);
				dev->fsm.fail_on_timeout = 1;
				return;
			}
		} /* infinite timeout, just continue monitoring */
		break;

	case NI_DHCP6_STATE_SELECTING:
	case NI_DHCP6_STATE_REQUESTING_INFO:
		/*
		 * defer timeout was specified and is over;
		 * no usable dhcp server response received
		 * [or no address in managed mode offers
		 *  and we've discarded them (RFC MUST)].
		 */
		__show_remaining_timeouts(dev, "TIMEOUT");

		if (ni_dhcp6_fsm_accept_offer(dev) == 0)
			return;

		ni_dhcp6_send_event(NI_DHCP6_EVENT_DEFERRED, dev, NULL);
		if (dev->config->acquire_timeout) {
			unsigned int deadline;

			deadline = ni_dhcp6_remaining_time(&dev->start_time,
					dev->config->acquire_timeout);
			if (deadline) {
				deadline *= 1000;
				ni_dhcp6_fsm_set_timeout_msec(dev, deadline);
				dev->fsm.fail_on_timeout = 1;
				return;
			}
		} /* infinite timeout, just continue selecting */
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
		if (dev->config->mode == NI_DHCP6_MODE_INFO)
			ni_dhcp6_fsm_request_info(dev);
		else
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
		ni_dhcp6_fsm_commit_lease(dev, NULL);
		ni_dhcp6_device_drop_lease(dev);
		ni_dhcp6_device_stop(dev);
		break;

	default:
		break;
	}
}

static inline ni_bool_t
__fsm_select_best_offer(const ni_dhcp6_device_t *dev, const ni_addrconf_lease_t *lease, int pref, int weight)
{
	/* when we don't have any or this is a better offer, remember it */
	if (dev->best_offer.lease == NULL || dev->best_offer.weight < weight)
		return TRUE;

	/* ignore when we have an offer providing more requested things */
	if (dev->best_offer.weight > weight) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: we have a better offer than weight %d",
				dev->ifname, weight);
		return FALSE;
	}

	/* prefer offer from server with a higher server preference */
	if (dev->best_offer.pref < pref) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
				"%s: prefer offer from server with higher preference %d",
				dev->ifname, pref);
		return TRUE;
	}

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
	unsigned int count;
	int weight = 0;
	int pref = 0;
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
		 * We've to (RFC MUST) discard all advertise messages with
		 * status NI_DHCP6_STATUS_NOADDRS; the another codes IMO
		 * don't fit here ... simply discard all unsuccessful codes.
		 */
		if (msg->lease->dhcp6.status &&
		    msg->lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_string_printf(hint, "status %s - %s",
				ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
				msg->lease->dhcp6.status->message);
			goto cleanup;
		} else {
			ni_dhcp6_ia_t *ia;
			for (ia = msg->lease->dhcp6.ia_list; ia; ia = ia->next) {
				if (ia->status.code == NI_DHCP6_STATUS_NOADDRS) {
					ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(ia->status.code),
						ia->status.message ? ia->status.message :
						"no addresses available");
					goto cleanup;
				}
			}
		}

		/* check if the config provides/overrides the preference */
		if (!ni_dhcp6_config_server_preference(	&msg->lease->dhcp6.server_addr,
							&msg->lease->dhcp6.server_id,
							&pref)) {
			pref = msg->lease->dhcp6.server_pref;
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: dhcp6 server preference %u",
					dev->ifname, msg->lease->dhcp6.server_pref);
		} else {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: dhcp6 server preference %u overriden by config to %d",
					dev->ifname, msg->lease->dhcp6.server_pref, pref);
		}
		if (pref < 0) {
			ni_string_printf(hint, "blacklisted server");
			goto cleanup;
		}

		/* Hmm... we currently do not request prefixes;
		 * server forgot to set NI_DHCP6_STATUS_NOADDRS,
		 * reset weight for offers without any lease addrs
		 */
		count = ni_address_list_count(msg->lease->addrs);
		if (count) {
			weight += count;
		} else {
			ni_string_printf(hint, "lease offer without address");
			goto cleanup;
		}

		if (__fsm_select_best_offer(dev, msg->lease, pref, weight)) {
			ni_dhcp6_device_set_best_offer(dev, msg->lease, pref, weight);
			msg->lease = NULL;
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: recorded regular offer with pref %d and weight %d",
					dev->ifname, dev->best_offer.pref, dev->best_offer.weight);
		} else if (!dev->best_offer.lease) {
			ni_string_printf(hint, "%s: unacceptable regular offer with pref %d and weight %d",
						dev->ifname, pref, weight);
			goto cleanup;
		}

		if (dev->best_offer.lease && dev->retrans.count > 0) {
			/* if the weight has maximum value, just accept this offer */
			if (dev->best_offer.pref > 254) {
				ni_dhcp6_fsm_timer_cancel(dev);
				rv = ni_dhcp6_fsm_accept_offer(dev);
			} else {
				ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
						"%s: waiting for better offers than pref %d and weight %d",
						dev->ifname, dev->best_offer.pref, dev->best_offer.weight);
			}
		}
		rv = 0;
	break;

	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;

		if (!msg->lease->dhcp6.rapid_commit) {
			ni_string_printf(hint, "rapid commit not set");
			goto cleanup;
		}


		/*
		 * Hmm...
		 */
		if (msg->lease->dhcp6.status &&
			msg->lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
						msg->lease->dhcp6.status->message);
			goto cleanup;
		} else {
			ni_dhcp6_ia_t *ia;
			for (ia = msg->lease->dhcp6.ia_list; ia; ia = ia->next) {
				if (ia->status.code == NI_DHCP6_STATUS_NOADDRS) {
					ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(ia->status.code),
						ia->status.message ? ia->status.message :
						"no addresses available");
					goto cleanup;
				}
			}
		}

		/*
		 * 17.1.4. says it is our decision if we accept unrequested rapid-commit or not.
		 * The message is already filtered by last xid we've send.
		 */

		/* check if the config provides/overrides the preference */
		if (!ni_dhcp6_config_server_preference(	&msg->lease->dhcp6.server_addr,
							&msg->lease->dhcp6.server_id,
							&pref)) {
			pref = msg->lease->dhcp6.server_pref;
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: dhcp6 server preference %u",
					dev->ifname, msg->lease->dhcp6.server_pref);
		} else {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: dhcp6 server preference %u overriden by config to %d",
					dev->ifname, msg->lease->dhcp6.server_pref, pref);
		}
		if (pref < 0) {
			ni_string_printf(hint, "blacklisted server");
			goto cleanup;
		}

		/* reset weight for offers without any lease addrs */
		count = ni_address_list_count(msg->lease->addrs);
		if (!count) {
			ni_string_printf(hint, "rapid-commit lease without address");
			goto cleanup;
		}
		weight += count;

		if (__fsm_select_best_offer(dev, msg->lease, pref, weight)) {
			ni_dhcp6_device_set_best_offer(dev, msg->lease, pref, weight);
			msg->lease = NULL;
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: recorded rapid-commit offer with pref %d and weight %d",
					dev->ifname, dev->best_offer.pref, dev->best_offer.weight);
		} else if (!dev->best_offer.lease) {
			ni_string_printf(hint, "%s: unacceptable rapid-commmit offer with pref %d and weight %d",
						dev->ifname, pref, weight);
			goto cleanup;
		}

		if (dev->best_offer.lease && dev->retrans.count > 0) {
			/* if the weight has maximum value, just accept this offer */
			if (dev->best_offer.pref > 254) {
				ni_dhcp6_fsm_timer_cancel(dev);
				rv = ni_dhcp6_fsm_accept_offer(dev);
			} else {
				ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
						"%s: waiting for better offers than pref %d and weight %d",
						dev->ifname, dev->best_offer.pref, dev->best_offer.weight);
			}
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

		if (msg->lease->dhcp6.status &&
		    msg->lease->dhcp6.status->code != NI_DHCP6_STATUS_SUCCESS) {
			ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
						msg->lease->dhcp6.status->message);
			ni_dhcp6_device_drop_best_offer(dev);
			ni_dhcp6_device_restart(dev);
			goto cleanup;
		} else {
			ni_dhcp6_ia_t *ia;
			for (ia = msg->lease->dhcp6.ia_list; ia; ia = ia->next) {
				if (ia->status.code == NI_DHCP6_STATUS_NOADDRS) {
					ni_string_printf(hint, "status %s - %s",
						ni_dhcp6_status_name(ia->status.code),
						ia->status.message ? ia->status.message :
						"no addresses available");
					goto cleanup;
				}
			}
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

static const ni_dhcp6_ia_addr_t *
ni_fsm_confirm_process_find_ia_addrs_status(const ni_dhcp6_ia_addr_t *addrs, unsigned int status)
{
	const ni_dhcp6_ia_addr_t *iaddr;

	for (iaddr = addrs; iaddr; iaddr = iaddr->next) {
		if (ni_dhcp6_status_code(&iaddr->status) == status)
			return iaddr;
	}
	return NULL;
}

static const ni_dhcp6_ia_t *
ni_fsm_confirm_process_find_ia_status(const ni_dhcp6_ia_t *ia_list, unsigned int status,
					const ni_dhcp6_ia_addr_t **iaddr)
{
	const ni_dhcp6_ia_t *ia;

	for (ia = ia_list; ia; ia = ia->next) {
		if ((*iaddr = ni_fsm_confirm_process_find_ia_addrs_status(ia->addrs, status)))
			return ia;
		else if (ni_dhcp6_status_code(&ia->status) == status)
			return ia;
	}
	return NULL;
}

static int
ni_fsm_confirm_process_reply_status(ni_dhcp6_device_t *dev, const ni_addrconf_lease_t *lease, char **hint)
{
	const ni_dhcp6_ia_addr_t *iaddr = NULL;
	const ni_dhcp6_status_t *status;
	const ni_dhcp6_ia_t *ia;
	const char *message;

	if ((ia = ni_fsm_confirm_process_find_ia_status(lease->dhcp6.ia_list, NI_DHCP6_STATUS_NOTONLINK, &iaddr))) {
		status = iaddr ? &iaddr->status : &ia->status;
		message = ni_dhcp6_status_message(status);

		ni_note("%s: link change confirmation in reply with status %s", dev->ifname,
				message ? message : ni_dhcp6_status_name(status->code));

		return NI_DHCP6_STATUS_NOTONLINK;
	} else if (ni_dhcp6_status_code(lease->dhcp6.status) == NI_DHCP6_STATUS_NOTONLINK) {
		status = lease->dhcp6.status;
		message = ni_dhcp6_status_message(status);

		ni_note("%s: link change confirmation in reply with status %s", dev->ifname,
				message ? message : ni_dhcp6_status_name(status->code));
		return NI_DHCP6_STATUS_NOTONLINK;
	}

	if (ni_fsm_confirm_process_find_ia_status(lease->dhcp6.ia_list, NI_DHCP6_STATUS_FAILURE, &iaddr)) {
		status = iaddr ? &iaddr->status : &ia->status;
		message = ni_dhcp6_status_message(status);

		ni_string_printf(hint, "link confirmation failure from server with status %s",
				message ? message : ni_dhcp6_status_name(status->code));
		return NI_DHCP6_STATUS_FAILURE;
	} else if (ni_dhcp6_status_code(lease->dhcp6.status) == NI_DHCP6_STATUS_FAILURE) {
		status = lease->dhcp6.status;
		message = ni_dhcp6_status_message(status);

		ni_string_printf(hint, "link confirmation failure from server with status %s",
				message ? message : ni_dhcp6_status_name(status->code));
		return NI_DHCP6_STATUS_FAILURE;
	}

	if (ni_fsm_confirm_process_find_ia_status(lease->dhcp6.ia_list, NI_DHCP6_STATUS_SUCCESS, &iaddr)) {
		status = iaddr ? &iaddr->status : &ia->status;
		message = ni_dhcp6_status_message(status);

		ni_note("%s: link confirmation in reply with status %s", dev->ifname,
				message ? message : ni_dhcp6_status_name(status->code));
	} else if (ni_dhcp6_status_code(lease->dhcp6.status) == NI_DHCP6_STATUS_SUCCESS) {
		status = lease->dhcp6.status;
		message = ni_dhcp6_status_message(status);

		ni_note("%s: link confirmation in reply with status %s", dev->ifname,
				message ? message : ni_dhcp6_status_name(status->code));
	} else {
		status = lease->dhcp6.status;
		message = ni_dhcp6_status_message(status);
		if (!message)
			message = ni_dhcp6_status_name(ni_dhcp6_status_code(status));

		ni_note("%s: link confirmation reply without link change indication from server%s%s",
				dev->ifname, message ? " with status " : "", message ? message : "");
	}
	return NI_DHCP6_STATUS_SUCCESS;
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
		 * If the client receives a Reply message with a Status Code containing
		 * UnspecFail, the server is indicating that it was unable to process
		 * the message due to an unspecified failure condition. If the client
		 * retransmits [...] client MUST limit the rate [..] and [..] duration
		 *  [...]
		 * When the client receives a NotOnLink status from the server in
		 * response to a Confirm message, the client performs DHCP server
		 * solicitation, as described in section 17, and client-initiated
		 * configuration as described in section 18. If the client receives
		 * any Reply messages that do not indicate a NotOnLink status, the
		 * client can use the addresses in the IA and ignore any messages
		 * that indicate a NotOnLink status.
		 *  [...]"
		 */
		if (!dev->lease) {
			ni_string_printf(hint, "confirm reply without a lease?!");
			goto cleanup;
		}

		switch (ni_fsm_confirm_process_reply_status(dev, msg->lease, hint)) {
		case NI_DHCP6_STATUS_NOTONLINK:
			/* NotOnLink: confirmation that link changed ==>> re-solicit  */
			ni_dhcp6_fsm_reset(dev);
			ni_dhcp6_device_drop_lease(dev);
			ni_dhcp6_fsm_solicit(dev);
			rv = 0;
			goto cleanup;

		case NI_DHCP6_STATUS_FAILURE:
			/* UnspecFail: rate/duration already limitted, ignore & go on */
			goto cleanup;

		case NI_DHCP6_STATUS_SUCCESS:
			/* Success: explicit confirmation that link did not changed   */
		default:
			/* Any another failures do not signal link change (NotOnLink) */
			ni_dhcp6_fsm_reset(dev);
			ni_address_list_destroy(&dev->lease->addrs);
			if (ni_dhcp6_ia_copy_to_lease_addrs(dev, dev->lease)) {
				ni_dhcp6_fsm_commit_lease(dev, dev->lease);
			} else {
				/* expired in the meantime */
				ni_dhcp6_fsm_solicit(dev);
			}
			rv = 0;
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
		/* reset weight for offers without any lease addrs */
		count = ni_address_list_count(lease->addrs);
		if (!count) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"Lease without any address");
			weight = 0;
		}
		weight += count;

		if(__fsm_select_best_offer(dev, msg->lease, weight)) {
			ni_dhcp6_device_set_best_offer(dev, msg->lease, weight);
			msg->lease = NULL;
		} else if (!dev->best_offer.lease) {
			ni_string_printf(hint, "unacceptable rapid-commmit offer with weight %d",
						weight);
			goto cleanup;
		}

		/* the weight has maximum value, just accept this lease */
		if (dev->best_offer.weight > 255) {
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
	ni_dhcp6_ia_addr_t *iadr, *next;
	ni_dhcp6_ia_t *ia;
	ni_sockaddr_t ip;
	int resolicit = 0;
	int rv = 1;

	switch (msg->type) {
	case NI_DHCP6_REPLY:
		if (__fsm_parse_client_options(dev, msg, opts) < 0)
			return -1;

		if (!dev->lease) {
			ni_string_printf(hint, "decline reply without a lease");
			goto cleanup;
		}

		for (ia = msg->lease->dhcp6.ia_list; ia; ia = ia->next) {
			for (iadr = ia->addrs; iadr; iadr = iadr->next) {

				ni_sockaddr_set_ipv6(&ip, iadr->addr, 0);
				ni_debug_dhcp("%s: %s id %u address %s decline status: %s - %s",
						dev->ifname, ni_dhcp6_option_name(ia->type),
						ia->iaid, ni_sockaddr_print(&ip),
						ni_dhcp6_status_name(iadr->status.code),
						ni_dhcp6_status_message(&iadr->status));
			}
			if (!ia->addrs && (ia->status.message || ia->status.code)) {
				ni_debug_dhcp("%s: %s id %u decline status: %s - %s",
						dev->ifname, ni_dhcp6_option_name(ia->type),
						ia->iaid,
						ni_dhcp6_status_name(ia->status.code),
						ni_dhcp6_status_message(&ia->status));
			}
		}
		if (msg->lease->dhcp6.status) {
			ni_debug_dhcp("%s: decline reply status: %s - %s", dev->ifname,
					ni_dhcp6_status_name(msg->lease->dhcp6.status->code),
					ni_dhcp6_status_message(msg->lease->dhcp6.status));
		}

		/*
		 * https://tools.ietf.org/html/rfc7550#section-4.4.5
		 * (https://tools.ietf.org/html/rfc3315#section-18.1.8)
		 * "[...]
		 * When the client receives a valid Reply message in response to a
		 * Decline message, the client considers the Decline event completed,
		 * regardless of the Status Code option(s) returned by the server.
		 * [...]"
		 *
		 * https://tools.ietf.org/html/rfc7550#section-4.6
		 * "[...]
		 * The client SHOULD retain the non-conflicting bindings. The client SHOULD
		 * treat the failure to acquire a binding as a result of the conflict, to be
		 * equivalent to not having received the binding, insofar as it behaves when
		 * sending Renew and Rebind messages.
		 * [...]"
		 */
		for (ia = dev->lease->dhcp6.ia_list; ia; ia = ia->next) {
			if (!ni_dhcp6_ia_type_na(ia) && !ni_dhcp6_ia_type_ta(ia))
				continue;

			if (!ia->addrs)
				continue;	/* already empty before */

			for (iadr = ia->addrs; iadr; iadr = next) {
				next = iadr->next;

				if (iadr->flags & NI_DHCP6_IA_ADDR_DECLINE) {
					ni_sockaddr_set_ipv6(&ip, iadr->addr, 0);
					ni_debug_dhcp("%s: deleting declined %s id %u address %s",
							dev->ifname, ni_dhcp6_option_name(ia->type),
							ia->iaid, ni_sockaddr_print(&ip));

					ni_dhcp6_ia_addr_list_delete(&ia->addrs, iadr);
				}
			}
			if (!ia->addrs) {
				resolicit++;	/* retry to get new one */
				ni_debug_dhcp("%s: retrigger solicit due to empty %s id %u",
					dev->ifname, ni_dhcp6_option_name(ia->type), ia->iaid);
			}
		}

		ni_addrconf_lease_file_write(dev->ifname, dev->lease);
		ni_dhcp6_fsm_reset(dev);
		if (resolicit) {
			ni_dhcp6_fsm_solicit(dev);
		} else {
			ni_dhcp6_fsm_bound(dev);
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
	int weight = 0;
	int pref = 0;
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

		/* check if the config provides/overrides the preference */
		if (!ni_dhcp6_config_server_preference(	&msg->lease->dhcp6.server_addr,
							&msg->lease->dhcp6.server_id,
							&pref)) {
			pref = msg->lease->dhcp6.server_pref;
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: dhcp6 server preference %u",
					dev->ifname, msg->lease->dhcp6.server_pref);
		} else {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: dhcp6 server preference %u overriden by config to %d",
					dev->ifname, msg->lease->dhcp6.server_pref, pref);
		}
		if (pref < 0) {
			ni_string_printf(hint, "blacklisted server");
			goto cleanup;
		}

		if (ni_address_list_count(msg->lease->addrs) > 0) {
			ni_string_printf(hint, "info reply containing addresses?");
			goto cleanup;
		}
		if (msg->lease->resolver && msg->lease->resolver->dns_servers.count) {
			weight += !!msg->lease->resolver->dns_servers.count;
			weight += !!msg->lease->resolver->dns_search.count;
		} else {
			ni_debug_dhcp("%s: lease offer without resolver settings", dev->ifname);
			weight = 0;
		}

		if(__fsm_select_best_offer(dev, msg->lease, pref, weight)) {
			ni_dhcp6_device_set_best_offer(dev, msg->lease, pref, weight);
			msg->lease = NULL;
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
					"%s: recorded info offer with pref %d and weight %d",
					dev->ifname, dev->best_offer.pref, dev->best_offer.weight);
		} else if (!dev->best_offer.lease) {
			ni_string_printf(hint, "%s: unacceptable info offer with pref %d and weight %d",
						dev->ifname, pref, weight);
			goto cleanup;
		}

		if (dev->best_offer.lease) {
			/* if the weight has maximum value, just accept this offer */
			if (dev->best_offer.pref > 254) {
				ni_dhcp6_fsm_timer_cancel(dev);
				rv = ni_dhcp6_fsm_accept_offer(dev);
			} else {
				ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_DHCP,
						"%s: waiting for better offers than pred %d and weight %d",
						dev->ifname, dev->best_offer.pref, dev->best_offer.weight);
			}
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
__fsm_parse_client_options(ni_dhcp6_device_t *dev, struct ni_dhcp6_message *msg, ni_buffer_t *opts)
{
	ni_addrconf_lease_t *lease = NULL;

	lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
	lease->state = NI_ADDRCONF_STATE_GRANTED;
	lease->type = NI_ADDRCONF_DHCP;
	ni_timer_get_time(&lease->acquired);
	lease->fqdn.enabled = NI_TRISTATE_DEFAULT;
	lease->fqdn.qualify = dev->config->fqdn.qualify;

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
	static unsigned int err_xid = 0;
	static unsigned int err_cnt = 0;
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
		if (err_xid != msg_xid) {
			err_xid = msg_xid;
			err_cnt = 0;
		} else {
			err_cnt++;
		}

		if ((err_cnt % 5) == 0) {
			ni_note("%s: ignoring %s message xid 0x%06x"
					" in state %s from %s%s%s",
				dev->ifname, ni_dhcp6_message_name(msg_type),
				msg_xid, ni_dhcp6_fsm_state_name(state),
				ni_dhcp6_address_print(sender),
				(hint ? ": " : ""), (hint ? hint : ""));
		} else {
			ni_debug_dhcp("%s: ignoring %s message xid 0x%06x"
					" in state %s from %s%s%s",
				dev->ifname, ni_dhcp6_message_name(msg_type),
				msg_xid, ni_dhcp6_fsm_state_name(state),
				ni_dhcp6_address_print(sender),
				(hint ? ": " : ""), (hint ? hint : ""));
		}
	}
	ni_string_free(&hint);

	if (msg.lease != NULL && msg.lease != dev->lease)
		ni_addrconf_lease_free(msg.lease);

	return rv;
}

static unsigned int
ni_dhcp6_remaining_time(struct timeval *start, unsigned int timeout)
{
	struct timeval now;
	struct timeval dif;

	ni_timer_get_time(&now);
	timersub(&now, start, &dif);
	return timeout > dif.tv_sec ? timeout - dif.tv_sec : 0;
}

static int
ni_dhcp6_fsm_solicit(ni_dhcp6_device_t *dev)
{
	ni_addrconf_lease_t *lease = NULL;
	unsigned int deadline = 0;
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
	if (dev->retrans.count == 0) {
		ni_info("%s: Initiating DHCPv6 Server Solicitation",
			dev->ifname);

		if ((lease = dev->lease) == NULL) {
			lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);
			/* TODO: add addrs from interface as hint */
		}
		lease->uuid = dev->config->uuid;
		lease->fqdn.enabled = NI_TRISTATE_DEFAULT;
		lease->fqdn.qualify = dev->config->fqdn.qualify;

		dev->dhcp6.xid = 0;
		ni_dhcp6_device_drop_best_offer(dev);
		if (ni_dhcp6_init_message(dev, NI_DHCP6_SOLICIT, lease) != 0)
			goto cleanup;

		if (dev->config->start_delay) {
			dev->retrans.delay = dev->config->start_delay * 1000;
		}

		if (dev->config->defer_timeout) {
			deadline = ni_dhcp6_remaining_time(&dev->start_time,
					dev->config->defer_timeout);
			dev->fsm.fail_on_timeout = 0;
		}
		if (!deadline && dev->config->acquire_timeout) {
			deadline = ni_dhcp6_remaining_time(&dev->start_time,
					dev->config->acquire_timeout);
			dev->fsm.fail_on_timeout = 1;
		}
		if (deadline) {
			dev->retrans.duration = deadline * 1000;
		}

		dev->fsm.state = NI_DHCP6_STATE_SELECTING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		if (dev->best_offer.lease && dev->best_offer.weight > 0) {
			/*
			 * Initial retransmission timeout is over,
			 * we can process the collected offers now.
			 */
			if ((rv = ni_dhcp6_fsm_accept_offer(dev)) == 0)
				goto cleanup;
		}

		ni_debug_dhcp("%s: Retransmitting DHCPv6 Server Solicitation",
				dev->ifname);

		if ((lease = dev->lease) == NULL) {
			lease = ni_addrconf_lease_new(NI_ADDRCONF_DHCP, AF_INET6);

			/* TODO: add addrs from interface as hint */
		}
		lease->uuid = dev->config->uuid;
		lease->fqdn.enabled = NI_TRISTATE_DEFAULT;
		lease->fqdn.qualify = dev->config->fqdn.qualify;

		if (ni_dhcp6_build_message(dev, NI_DHCP6_SOLICIT, &dev->message, lease) != 0)
			goto cleanup;

		rv = ni_dhcp6_device_transmit(dev);
	}

cleanup:
	if (lease && lease != dev->lease) {
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
		ni_info("%s: Requesting DHCPv6 lease with timeout %d sec",
			dev->ifname, dev->config->acquire_timeout);

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

		rv = ni_dhcp6_device_transmit_init(dev);
	} else
	if (dev->best_offer.lease && dev->best_offer.weight > 0) {
		rv = ni_dhcp6_fsm_accept_offer(dev);
	} else {
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

		ni_info("%s: Initiating renewal of DHCPv6 lease, duration %u sec until %s",
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

		ni_info("%s: Initiating rebind of DHCPv6 lease, duration %u sec until %s",
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

static ni_bool_t
ni_dhcp6_fsm_decline_info(const ni_dhcp6_device_t *dev, const ni_dhcp6_ia_t *ia_list,
				const char *info, const char *warn)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	const ni_dhcp6_ia_addr_t *iadr;
	const ni_dhcp6_ia_t *ia;
	ni_sockaddr_t ip;

	ip.ss_family = AF_UNSPEC;
	for (ia = ia_list; ia; ia = ia->next) {
		if (ia->type != NI_DHCP6_OPTION_IA_NA &&
		    ia->type != NI_DHCP6_OPTION_IA_TA)
			continue;

		for (iadr = ia->addrs; iadr; iadr = iadr->next) {
			if (!(iadr->flags & NI_DHCP6_IA_ADDR_DECLINE))
				continue;

			if (ip.ss_family == AF_UNSPEC && info)
				ni_info("%s: %s", dev->ifname, info);

			ni_sockaddr_set_ipv6(&ip, iadr->addr, 0);
			if (info) {
				ni_stringbuf_puts(&buf, ni_sockaddr_print(&ip));
				ni_stringbuf_puts(&buf, " valid-lft ");
				ni_lifetime_print_valid(&buf, iadr->valid_lft);
				ni_stringbuf_puts(&buf, " preferred-lft ");
				ni_lifetime_print_preferred(&buf, iadr->preferred_lft);
				ni_info("%s:    %s %s", dev->ifname,
						ni_dhcp6_option_name(ia->type), buf.string);
				ni_stringbuf_destroy(&buf);
			}
		}
	}

	if (ip.ss_family == AF_UNSPEC && warn)
		ni_warn("%s: %s", dev->ifname, warn);

	return ip.ss_family != AF_UNSPEC;
}

static int
ni_dhcp6_fsm_decline(ni_dhcp6_device_t *dev)
{
	int rv = -1;

	if (!dev->lease)
		return -1;


	if (dev->retrans.count == 0) {

		if (!ni_dhcp6_fsm_decline_info(dev, dev->lease->dhcp6.ia_list,
				"Initiating DHCPv6 lease addresses decline",
				"No DHCPv6 lease address marked to decline"))
			return -1;

		dev->dhcp6.xid = 0;
		if (ni_dhcp6_init_message(dev, NI_DHCP6_DECLINE, dev->lease) != 0)
			return -1;

		dev->fsm.state = NI_DHCP6_STATE_DECLINING;
		rv = ni_dhcp6_device_transmit_init(dev);
	} else {
		if (!ni_dhcp6_fsm_decline_info(dev, dev->lease->dhcp6.ia_list,
				"Retransmitting DHCPv6 lease addresses decline",
				"No DHCPv6 lease address marked to decline"))
			return -1;

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
		if (nretries < (unsigned int)dev->retrans.params.nretries)
			dev->retrans.params.nretries = nretries;
		rv = ni_dhcp6_device_transmit_init(dev);
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
	unsigned int nretries;

	/* When all IA's are expired, just commit a release */
	if (ni_dhcp6_lease_with_active_address(dev->lease)) {
		if (dev->config && dev->config->release_lease) {
			nretries = ni_dhcp6_config_release_nretries(dev->ifname);
			if (__ni_dhcp6_fsm_release(dev, nretries) == 0)
				return 1;
		}
	}

	if (dev->lease)
		ni_dhcp6_send_event(NI_DHCP6_EVENT_RELEASED, dev, dev->lease);
	return 0;
}

static int
ni_dhcp6_fsm_accept_offer(ni_dhcp6_device_t *dev)
{
	ni_addrconf_lease_t *offer;
	ni_sockaddr_t server_addr;
	int rv;

	if (!(offer = dev->best_offer.lease))
		return -1;

	ni_sockaddr_set_ipv6(&server_addr, offer->dhcp6.server_addr, 0);

	ni_info("%s: Accepting best DHCPv6 %slease offer with weight %d from server %s",
		dev->ifname, offer->dhcp6.rapid_commit ? "rapid-commit " : "",
		dev->best_offer.weight, ni_sockaddr_print(&server_addr));

	ni_dhcp6_device_retransmit_disarm(dev);
	if (dev->config->dry_run == NI_DHCP6_RUN_OFFER) {
		/* Send offer as event to the caller */
		ni_dhcp6_send_event(NI_DHCP6_EVENT_ACQUIRED, dev, offer);

		/* When it is a rapid-commit lease, release */
		if (dev->config->mode != NI_DHCP6_MODE_INFO &&
		    offer->dhcp6.rapid_commit) {
			/* reset best offer, apply and release */
			dev->best_offer.lease = NULL;
			dev->best_offer.weight = -1;
			ni_dhcp6_device_set_lease(dev, offer);

			if ((rv = __ni_dhcp6_fsm_release(dev, 1)) != -1)
				return rv;
		}

		ni_dhcp6_device_drop_best_offer(dev);
		ni_dhcp6_device_drop_lease(dev);
		ni_dhcp6_device_stop(dev);
		return 0;
	} else {
		/* When it is a rapid-commit lease, commit */
		if (dev->config->mode == NI_DHCP6_MODE_INFO ||
		    offer->dhcp6.rapid_commit) {
			/* reset best offer, commit as lease */
			dev->best_offer.lease = NULL;
			dev->best_offer.weight = -1;

			return ni_dhcp6_fsm_commit_lease(dev, offer);
		}
		/* Otherwise request the best lease offer */
		return ni_dhcp6_fsm_request_lease(dev, dev->best_offer.lease);
	}
}

static int
ni_dhcp6_fsm_commit_lease(ni_dhcp6_device_t *dev, ni_addrconf_lease_t *lease)
{
	ni_string_array_t *iaddrs = NULL;
	ni_var_array_t p_lft = NI_VAR_ARRAY_INIT; /* ia_addr preferred_lft */
	ni_var_array_t v_lft = NI_VAR_ARRAY_INIT; /* ia_addr valid_lft */
	unsigned int i;

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

		iaddrs = ni_dhcp6_get_ia_addrs(dev->lease->dhcp6.ia_list, &p_lft, &v_lft);

		if (iaddrs && iaddrs->count) {
			ni_note("%s: Committed DHCPv6 lease with addresses:", dev->ifname);
			for (i = 0; i < iaddrs->count; ++i) {
				uint32_t pref_lft;
				uint32_t valid_lft;
				ni_var_array_get_uint(&p_lft, iaddrs->data[i], &pref_lft);
				ni_var_array_get_uint(&v_lft, iaddrs->data[i], &valid_lft);
				ni_note("    %s, pref-lft %u, valid-lft %u",
					iaddrs->data[i], pref_lft, valid_lft);
			}
			ni_var_array_destroy(&p_lft);
			ni_var_array_destroy(&v_lft);
			ni_string_array_destroy(iaddrs);
		} else {
			ni_note("%s: Committed DHCPv6 lease", dev->ifname);
		}

		if (dev->config->dry_run != NI_DHCP6_RUN_OFFER) {
			ni_addrconf_lease_file_write(dev->ifname, lease);
		}

		ni_dhcp6_send_event(NI_DHCP6_EVENT_ACQUIRED, dev, lease);
		if (dev->config->dry_run != NI_DHCP6_RUN_NORMAL) {
			ni_dhcp6_device_drop_lease(dev);
			ni_dhcp6_device_stop(dev);
		} else if (dev->config->mode == NI_DHCP6_MODE_INFO) {
			dev->fsm.state = NI_DHCP6_STATE_BOUND;
			ni_dhcp6_fsm_bound(dev);
		} else {
			dev->fsm.state = NI_DHCP6_STATE_VALIDATING;
			ni_dhcp6_fsm_set_timeout_msec(dev, NI_DHCP6_WAIT_IAADDR_READY);
		}

	} else {
		if ((lease = dev->lease) != NULL) {
			ni_note("%s: Dropped DHCPv6 lease with UUID %s",
				dev->ifname, ni_uuid_print(&lease->uuid));
			lease->state = NI_ADDRCONF_STATE_RELEASED;

			ni_dhcp6_send_event(NI_DHCP6_EVENT_RELEASED, dev, lease);

			if (!dev->config || dev->config->dry_run != NI_DHCP6_RUN_OFFER) {
				ni_addrconf_lease_file_remove(dev->ifname,
						lease->type, lease->family);
			}

			ni_dhcp6_device_drop_lease(dev);
			ni_dhcp6_device_stop(dev);
		}

		ni_dhcp6_fsm_restart(dev);
	}
	return 0;
}

static int
ni_dhcp6_fsm_bound_info(ni_dhcp6_device_t *dev)
{
	ni_uint_range_t range;
	unsigned int refresh;
	struct timeval now;

	dev->fsm.state = NI_DHCP6_STATE_BOUND;

	refresh = ni_dhcp6_config_info_refresh_time(dev->ifname, &range);
	if (dev->lease->dhcp6.info_refresh) {
		if (ni_uint_in_range(&range, dev->lease->dhcp6.info_refresh))
			refresh = dev->lease->dhcp6.info_refresh;
		else if (dev->lease->dhcp6.info_refresh < range.min)
			refresh = range.min;
		else if (dev->lease->dhcp6.info_refresh > range.max)
			refresh = range.max;
	}

	ni_timer_get_time(&now);
	refresh = ni_lifetime_left(refresh, &dev->lease->acquired, &now);

	switch (refresh) {
	case NI_LIFETIME_INFINITE:
		/* don't refresh */
		break;

	case NI_LIFETIME_EXPIRED:
		return ni_dhcp6_fsm_request_info(dev);

	default:
		ni_dhcp6_fsm_set_timeout_msec(dev, (unsigned long)refresh * 1000);
		break;
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

	if (dev->config->mode == NI_DHCP6_MODE_INFO)
		return ni_dhcp6_fsm_bound_info(dev);

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
	unsigned int count;
	unsigned int rt;
	struct timeval now;
	ni_dhcp6_ia_t *ia;

	count = 0;
	ni_timer_get_time(&now);
	for (ia = dev->lease->dhcp6.ia_list; ia; ia = ia->next) {
		rt = get_ia_time(ia);

		if (timercmp(&now, &ia->acquired, >)) {
			struct timeval dif;

			timersub(&now, &ia->acquired, &dif);
			if (dif.tv_sec + 1 >= rt) {
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
	struct timeval now;
	ni_dhcp6_ia_t *ia = NULL;
	unsigned int lt;

	ia = __ni_dhcp6_fsm_find_lowest_ia(dev->lease->dhcp6.ia_list,
						get_ia_time, &lt);
	if (!ia)
		return 0;

	/* Infinite lease time .. should we ever refresh it? */
	if (lt ==  NI_DHCP6_INFINITE_LIFETIME)
		return lt;

	if (lt > 0) {
		ni_timer_get_time(&now);

		if (timercmp(&now, &ia->acquired, >)) {
			struct timeval dif;

			timersub(&now, &ia->acquired, &dif);
			if (lt > dif.tv_sec)
				lt -= dif.tv_sec;
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
	struct timeval now;
	ni_dhcp6_ia_t *ia = NULL;
	unsigned int lt;

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
		ni_timer_get_time(&now);

		if (timercmp(&now, &ia->acquired, >)) {
			struct timeval dif;

			timersub(&now, &ia->acquired, &dif);
			if (lt > dif.tv_sec)
				lt -= dif.tv_sec;
		}
	}
	return lt;
}


/*
 * interface address event handlers
 */
static void
ni_dhcp6_fsm_ia_addr_update(ni_netdev_t *ifp, ni_dhcp6_device_t *dev, const ni_address_t *addr)
{
	ni_address_t *ap;
	ni_dhcp6_ia_t *ia;
	ni_dhcp6_ia_addr_t *iadr;
	unsigned int tentative = 0;
	unsigned int duplicate = 0;

	for (ap = ifp->addrs; ap; ap = ap->next) {
		if (ap->family != AF_INET6 || ap->local_addr.ss_family != AF_INET6)
			continue;

		for (ia = dev->lease->dhcp6.ia_list; ia; ia = ia->next) {
			if (ia->type != NI_DHCP6_OPTION_IA_NA &&
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
ni_dhcp6_fsm_ia_addr_delete(ni_netdev_t *ifp, ni_dhcp6_device_t *dev, const ni_address_t *addr)
{
	ni_dhcp6_ia_t *ia;
	ni_dhcp6_ia_addr_t *iadr;
	unsigned int duplicate = 0;

	if (!addr || addr->family != AF_INET6)
		return;

	for (ia = dev->lease->dhcp6.ia_list; ia; ia = ia->next) {
		if (ia->type != NI_DHCP6_OPTION_IA_NA &&
		    ia->type != NI_DHCP6_OPTION_IA_TA)
			continue;

		for (iadr = ia->addrs; iadr; iadr = iadr->next) {
			if (!IN6_ARE_ADDR_EQUAL(&iadr->addr, &addr->local_addr.six.sin6_addr))
				continue;

			if (ni_address_is_tentative(addr)) {
				duplicate++;

				iadr->flags |= NI_DHCP6_IA_ADDR_DECLINE;
				ni_debug_dhcp("%s: duplicate address %s deleted, marked for decline",
						dev->ifname, ni_sockaddr_print(&addr->local_addr));
			}
		}
	}

	if (duplicate)
		ni_dhcp6_fsm_decline(dev);
}

static void
ni_dhcp6_fsm_address_update(ni_dhcp6_device_t *dev, ni_netdev_t *ifp, const ni_address_t *addr)
{
	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_INIT:
		if (dev->config) {
			ni_dhcp6_device_start(dev);
		}
	break;

	case NI_DHCP6_STATE_VALIDATING:
		if (dev->lease) {
			ni_dhcp6_fsm_ia_addr_update(ifp, dev, addr);
		}
	break;

	default:
	break;
	}
}

static void
ni_dhcp6_fsm_address_delete(ni_dhcp6_device_t *dev, ni_netdev_t *ifp, const ni_address_t *addr)
{
	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_VALIDATING:
		if (dev->lease) {
			ni_dhcp6_fsm_ia_addr_delete(ifp, dev, addr);
		}
	break;

	default:
	break;
	}
}

void
ni_dhcp6_fsm_address_event(ni_dhcp6_device_t *dev, ni_netdev_t *ifp, ni_event_t event, const ni_address_t *addr)
{
	ni_server_trace_interface_addr_events(ifp, event, addr);
	switch (event) {
	case NI_EVENT_ADDRESS_UPDATE:
		ni_dhcp6_fsm_address_update(dev, ifp, addr);
	break;

	case NI_EVENT_ADDRESS_DELETE:
		ni_dhcp6_fsm_address_delete(dev, ifp, addr);
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
