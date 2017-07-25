/*
 *	DHCP6 supplicant
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
#ifndef __WICKED_DHCP6_DEVICE_H__
#define __WICKED_DHCP6_DEVICE_H__

/* device functions used in fsm.c and protocol.c */
extern int		ni_dhcp6_device_transmit_init(ni_dhcp6_device_t *);
extern int		ni_dhcp6_device_transmit_start(ni_dhcp6_device_t *);
extern int		ni_dhcp6_device_transmit(ni_dhcp6_device_t *);

extern int		ni_dhcp6_device_retransmit(ni_dhcp6_device_t *);
extern void		ni_dhcp6_device_retransmit_disarm(ni_dhcp6_device_t *);

extern ni_bool_t	ni_dhcp6_device_is_ready(const ni_dhcp6_device_t *, const ni_netdev_t *);
extern void		ni_dhcp6_device_update_mode(ni_dhcp6_device_t *, const ni_netdev_t *);
extern const ni_ipv6_ra_info_t  *ni_dhcp6_device_ra_info(const ni_dhcp6_device_t *, const ni_netdev_t *);
extern const ni_ipv6_ra_pinfo_t *ni_dhcp6_device_ra_pinfo(const ni_dhcp6_device_t *, const ni_netdev_t *);
extern int		ni_dhcp6_device_start(ni_dhcp6_device_t *);
extern int		ni_dhcp6_device_restart(ni_dhcp6_device_t *);
extern void		ni_dhcp6_device_stop(ni_dhcp6_device_t *);

extern void		ni_dhcp6_device_set_lease(ni_dhcp6_device_t *,  ni_addrconf_lease_t *);
extern void		ni_dhcp6_device_drop_lease(ni_dhcp6_device_t *);
extern void		ni_dhcp6_device_set_best_offer(ni_dhcp6_device_t *, ni_addrconf_lease_t *, int);
extern void		ni_dhcp6_device_drop_best_offer(ni_dhcp6_device_t *);

extern unsigned int	ni_dhcp6_device_uptime(const ni_dhcp6_device_t *, unsigned int);
extern ni_bool_t	ni_dhcp6_device_iaid(const ni_dhcp6_device_t *, unsigned int *);

/* config access [/etc/wicked/config.xml, node /config/addrconf/dhcp6] */
extern int		ni_dhcp6_config_user_class(ni_string_array_t *);
extern int		ni_dhcp6_config_vendor_class(unsigned int *, ni_string_array_t *);
extern int		ni_dhcp6_config_vendor_opts(unsigned int *, ni_var_array_t *);
extern int		ni_dhcp6_config_ignore_server(struct in6_addr);
extern ni_bool_t	ni_dhcp6_config_have_server_preference(void);
extern ni_bool_t	ni_dhcp6_config_server_preference(const struct in6_addr *, const ni_opaque_t *, int *);
extern unsigned int	ni_dhcp6_config_max_lease_time(void);

#endif /* __WICKED_DHCP6_DEVICE_H__ */
