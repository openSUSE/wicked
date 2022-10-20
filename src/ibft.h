/*
 *	Routines for iBFT (iSCSI Boot Firmware Table) NIC
 *
 *	Copyright (C) 2010-2022 SUSE LLC
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski
 *
 */
#ifndef WICKED_IBFT_H
#define WICKED_IBFT_H

typedef struct ni_ibft_nic {
	unsigned int	users;		/* refcount */

	char *		node;		/* ethernet0, ... */

	char *		ifname;		/* physical interface name */
	unsigned int	ifindex;	/* physical interface index */

	char *		devpath;	/* sysfs path to physical device */
	unsigned int	index;
	unsigned int	flags;
	unsigned int	origin;
	unsigned int 	vlan;

	ni_hwaddr_t	hwaddr;
	ni_sockaddr_t	ipaddr;
	unsigned int	prefix_len;
	ni_sockaddr_t	dhcp;
	ni_sockaddr_t	gateway;
	ni_sockaddr_t	primary_dns;
	ni_sockaddr_t	secondary_dns;
	char *		hostname;
} ni_ibft_nic_t;


#define NI_IBFT_NIC_ARRAY_INIT		{ .count = 0, .data = NULL }

typedef struct ni_ibft_nic_array {
	unsigned int	count;
	ni_ibft_nic_t **data;		/* array of refcount pointers! */
} ni_ibft_nic_array_t;


extern ni_ibft_nic_t *	ni_ibft_nic_new(void);
extern ni_ibft_nic_t *	ni_ibft_nic_ref (ni_ibft_nic_t *nic);
extern void		ni_ibft_nic_free(ni_ibft_nic_t *nic);

extern void		ni_ibft_nic_array_init(ni_ibft_nic_array_t *nics);
extern void		ni_ibft_nic_array_destroy(ni_ibft_nic_array_t *nics);
extern void		ni_ibft_nic_array_append(ni_ibft_nic_array_t *nics,
							ni_ibft_nic_t *nic);

extern int		ni_sysfs_ibft_scan_nics(ni_ibft_nic_array_t *nics,
						const char *root);

#endif /* WICKED_IBFT_H */
