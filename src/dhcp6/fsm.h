/*
 *	DHCP6 supplicant - finite client state machine
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
#ifndef   __WICKED_DHCP6_FSM_H__
#define   __WICKED_DHCP6_FSM_H__


/*
 * -- fsm states
 */
enum {
	NI_DHCP6_STATE_INIT,
	NI_DHCP6_STATE_SELECTING,
	NI_DHCP6_STATE_CONFIRMING,
	NI_DHCP6_STATE_REQUESTING,
	NI_DHCP6_STATE_VALIDATING,
	NI_DHCP6_STATE_BOUND,
	NI_DHCP6_STATE_RENEWING,
	NI_DHCP6_STATE_REBINDING,
	NI_DHCP6_STATE_RELEASING,
	NI_DHCP6_STATE_DECLINING,
	NI_DHCP6_STATE_REQUESTING_INFO,
	__NI_DHCP6_STATE_MAX,
};


/*
 * -- fsm functions used in device.c and protocol.c
 */
const char *			ni_dhcp6_fsm_state_name(int state);

extern int			ni_dhcp6_fsm_process_client_message(ni_dhcp6_device_t *,
						unsigned int, unsigned int, ni_buffer_t *,
						const struct in6_addr *);

extern void			ni_dhcp6_fsm_set_timeout_msec(ni_dhcp6_device_t *, unsigned long);

extern int			ni_dhcp6_fsm_start(ni_dhcp6_device_t *dev);
extern void			ni_dhcp6_fsm_reset(ni_dhcp6_device_t *dev);
extern int			ni_dhcp6_fsm_release(ni_dhcp6_device_t *dev);

extern int			ni_dhcp6_fsm_retransmit(ni_dhcp6_device_t *dev);

extern void			ni_dhcp6_fsm_address_event(ni_dhcp6_device_t *, ni_netdev_t *,
								ni_event_t, const ni_address_t *);
extern void			ni_dhcp6_send_event(enum ni_dhcp6_event, const ni_dhcp6_device_t *, ni_addrconf_lease_t *);


#endif /* __WICKED_DHCP6_FSM_H__ */
