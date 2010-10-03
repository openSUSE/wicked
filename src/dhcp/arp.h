/*
 * Interface for sending ARP queries
 *
 * Copyright (C) 2010, Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_DHCP_ARP_H__
#define __WICKED_DHCP_ARP_H__

#include <wicked/netinfo.h>


#define NI_DHCP_ARP_TIMEOUT	200	/* msec */

extern int		ni_arp_socket_open(ni_dhcp_device_t *);
extern int		ni_arp_send_request(ni_dhcp_device_t *, struct in_addr,
				const ni_hwaddr_t *, struct in_addr);
extern int		ni_arp_parse_reply(ni_dhcp_device_t *, ni_buffer_t *,
				struct in_addr *, ni_hwaddr_t *);

#endif /* __WICKED_DHCP_ARP_H__ */
