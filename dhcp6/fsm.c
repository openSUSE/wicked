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
#include "dhcp6/fsm.h"


/*
 * Global fsm handler
 */
static ni_dhcp6_event_handler_t *ni_dhcp6_fsm_event_handler;

static void			ni_dhcp6_fsm_timeout(ni_dhcp6_device_t *);
static void             	__ni_dhcp6_fsm_timeout(void *, const ni_timer_t *);


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

	if(dev->retrans.delay) {
		dev->retrans.delay = 0;

		ni_dhcp6_device_retransmit_arm(dev);
		ni_dhcp6_device_transmit(dev);

		ni_trace("transmitted, retrans deadline: %ld.%ld",
			dev->retrans.deadline.tv_sec, dev->retrans.deadline.tv_usec);
	}

	switch (dev->fsm.state) {
	case NI_DHCP6_STATE_SELECTING:

		break;

	default:
		break;
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

int
ni_dhcp6_fsm_process_client_packet(ni_dhcp6_device_t *dev, ni_buffer_t *msgbuf, const struct in6_addr *sender)
{
	ni_addrconf_lease_t * lease = NULL;
	int msg_type;

	msg_type = ni_dhcp6_client_parse_response(dev, msgbuf, sender, &lease);
	if (msg_type < 0) {
		ni_error("unable to parse DHCP response");
		return -1;
	}

        ni_debug_dhcp("%s: received %s message in state %s",
                        dev->ifname, ni_dhcp6_message_name(msg_type),
                        ni_dhcp6_fsm_state_name(dev->fsm.state));

        /*
         * We've received a valid response; if something goes wrong now
         * it's nothing that could be fixed by retransmitting the message.
         */
        if (dev->fsm.timer)
        	ni_timer_cancel(dev->fsm.timer);
        ni_dhcp6_device_retransmit_disarm(dev);

        /* here we are .......... */

	/* if (dev->lease != lease) { */
        if (lease) {
		ni_dhcp6_ia_list_destroy(&lease->dhcp6.ia_na);
		ni_dhcp6_ia_list_destroy(&lease->dhcp6.ia_ta);
		ni_dhcp6_ia_list_destroy(&lease->dhcp6.ia_pd);
		ni_addrconf_lease_free(lease);
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

void
ni_dhcp6_send_event(enum ni_dhcp6_event ev, ni_dhcp6_device_t *dev, ni_addrconf_lease_t *lease)
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
