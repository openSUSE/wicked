/*
 * Routines for iBFT (iSCSI Boot Firmware Table) NIC
 *
 * Copyright (C) 2011-2012 Marius Tomaschewski <mt@suse.com>
 */
#ifndef __NETINFO_IBFT_H__
#define __NETINFO_IBFT_H__

struct ni_ibft_nic {
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
};

struct ni_ibft_nic_array {
	unsigned int	count;
	ni_ibft_nic_t **data;		/* array of refcount pointers! */
};

#define NI_IBFT_NIC_ARRAY_INIT		{ 0, NULL }

ni_ibft_nic_t *		ni_ibft_nic_new(void);
ni_ibft_nic_t *		ni_ibft_nic_ref (ni_ibft_nic_t *nic);
void			ni_ibft_nic_free(ni_ibft_nic_t *nic);

void			ni_ibft_nic_array_init(ni_ibft_nic_array_t *nics);
void			ni_ibft_nic_array_destroy(ni_ibft_nic_array_t *nics);
void			ni_ibft_nic_array_append(ni_ibft_nic_array_t *nics, ni_ibft_nic_t *nic);

#endif /* __NETINFO_IBFT_H__ */
