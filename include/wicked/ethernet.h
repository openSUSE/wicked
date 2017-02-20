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
	NI_ETHERNET_PORT_DA,
	NI_ETHERNET_PORT_NONE,
	NI_ETHERNET_PORT_OTHER,
} ni_ether_port_t;

typedef enum {
	NI_ETHERNET_DUPLEX_DEFAULT = 0,
	NI_ETHERNET_DUPLEX_HALF,
	NI_ETHERNET_DUPLEX_FULL,
	NI_ETHERNET_DUPLEX_NONE,	/* autoneg not complete */
} ni_ether_duplex_t;

typedef enum {
	NI_ETHERNET_WOL_PHY		= 0,	/* p, phy	*/
	NI_ETHERNET_WOL_UCAST		= 1,	/* u, unicast	*/
	NI_ETHERNET_WOL_MCAST		= 2,	/* m, multicast	*/
	NI_ETHERNET_WOL_BCAST		= 3,	/* b, broadcast	*/
	NI_ETHERNET_WOL_ARP		= 4,	/* a, arp	*/
	NI_ETHERNET_WOL_MAGIC		= 5,	/* g, magic	*/
	NI_ETHERNET_WOL_SECUREON	= 6,	/* s, secure-on	*/

	__NI_ETHERNET_WOL_DISABLE	= 0,	/* d: disable	*/
	__NI_ETHERNET_WOL_DEFAULT	= -1U,	/* unset	*/
} ni_ether_wol_flags_t;

typedef struct ni_ethernet_wol {
	ni_ether_wol_flags_t	support;
	ni_ether_wol_flags_t	options;
	ni_hwaddr_t		sopass;
} ni_ethernet_wol_t;

typedef struct ni_ethtool_offload {
	ni_tristate_t	rx_csum;
	ni_tristate_t	tx_csum;
	ni_tristate_t	scatter_gather;
	ni_tristate_t	tso;
	ni_tristate_t	ufo;
	ni_tristate_t	gso;
	ni_tristate_t	gro;
	ni_tristate_t	lro;
} ni_ethtool_offload_t;

#define NI_ETHTOOL_EEE_DEFAULT		-1U

typedef struct ni_ethtool_eee {
	ni_tristate_t	supported;

	struct {
		ni_tristate_t	enabled;
		ni_tristate_t	active;
	} status;
	struct {
		unsigned int	supported;
		unsigned int	advertised;
		unsigned int	lp_advertised;
	} speed;
	struct {
		ni_tristate_t	enabled;
		unsigned int	timer;
	} tx_lpi;
} ni_ethtool_eee_t;

#define NI_ETHTOOL_RING_DEFAULT		-1U

typedef struct ni_ethtool_ring {
	ni_tristate_t	supported;
	unsigned int	tx;
	unsigned int	rx;
	unsigned int	rx_jumbo;
	unsigned int	rx_mini;
} ni_ethtool_ring_t;

#define NI_ETHTOOL_COALESCE_DEFAULT		-1U

typedef struct ni_ethtool_coalesce {
	ni_tristate_t	supported;

	ni_tristate_t   adaptive_tx;
	ni_tristate_t   adaptive_rx;

	unsigned int	pkt_rate_low;
	unsigned int	pkt_rate_high;

	unsigned int	sample_interval;
	unsigned int	stats_block_usecs;

	unsigned int	rx_usecs;
	unsigned int	rx_usecs_irq;
	unsigned int	rx_usecs_low;
	unsigned int	rx_usecs_high;

	unsigned int	rx_frames;
	unsigned int	rx_frames_irq;
	unsigned int	rx_frames_low;
	unsigned int	rx_frames_high;

	unsigned int	tx_usecs;
	unsigned int	tx_usecs_irq;
	unsigned int	tx_usecs_low;
	unsigned int	tx_usecs_high;

	unsigned int	tx_frames;
	unsigned int	tx_frames_irq;
	unsigned int	tx_frames_low;
	unsigned int	tx_frames_high;
} ni_ethtool_coalesce_t;

struct ni_ethernet {
	ni_hwaddr_t		permanent_address;
	unsigned int		link_speed;
	ni_ether_port_t		port_type;
	ni_ether_duplex_t	duplex;
	ni_tristate_t		autoneg_enable;

	ni_ethernet_wol_t	wol;
	ni_ethtool_offload_t	offload;
	ni_ethtool_eee_t	eee;
	ni_ethtool_ring_t       ring;
	ni_ethtool_coalesce_t   coalesce;

	unsigned int		identify_time;
};

extern ni_ethernet_t *	ni_ethernet_new(void);
extern void		ni_ethernet_free(ni_ethernet_t *);

extern ni_ether_port_t	ni_ethernet_name_to_port_type(const char *);
extern const char *	ni_ethernet_port_type_to_name(ni_ether_port_t);
extern const char *	ni_ethernet_wol_options_format(ni_stringbuf_t *,
							unsigned int,
							const char *);

#endif /* __WICKED_ETHERNET_H__ */
