/*
 * ethernet definitions for netinfo
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_ETHERNET_H__
#define __WICKED_ETHERNET_H__

#include <wicked/types.h>

typedef enum {
	NI_ETHERNET_PORT_DEFAULT = 0,
	NI_ETHERNET_PORT_TP,
	NI_ETHERNET_PORT_AUI,
	NI_ETHERNET_PORT_BNC,
	NI_ETHERNET_PORT_MII,
	NI_ETHERNET_PORT_FIBRE,
} ni_ether_port_t;

typedef enum {
	NI_ETHERNET_DUPLEX_DEFAULT = 0,
	NI_ETHERNET_DUPLEX_HALF,
	NI_ETHERNET_DUPLEX_FULL,
	NI_ETHERNET_DUPLEX_NONE,	/* autoneg not complete */
} ni_ether_duplex_t;

typedef enum {
	NI_ETHERNET_SETTING_DEFAULT = 0,
	NI_ETHERNET_SETTING_ENABLE,
	NI_ETHERNET_SETTING_DISABLE,
} ni_ether_tristate_t;

struct ni_ethernet {
	ni_hwaddr_t		permanent_address;
	unsigned int		link_speed;
	ni_ether_port_t		port_type;
	ni_ether_duplex_t	duplex;
	ni_ether_tristate_t	autoneg_enable;

	struct {
		ni_ether_tristate_t	rx_csum;
		ni_ether_tristate_t	tx_csum;
		ni_ether_tristate_t	scatter_gather;
		ni_ether_tristate_t	tso;
		ni_ether_tristate_t	ufo;
		ni_ether_tristate_t	gso;
		ni_ether_tristate_t	gro;
		ni_ether_tristate_t	lro;
	} offload;

	unsigned int		identify_time;
};

extern ni_ethernet_t *	ni_ethernet_alloc(void);
extern void		ni_ethernet_free(ni_ethernet_t *);

extern ni_ether_port_t	ni_ethernet_name_to_port_type(const char *);
extern const char *	ni_ethernet_port_type_to_name(ni_ether_port_t);

#endif /* __WICKED_ETHERNET_H__ */
