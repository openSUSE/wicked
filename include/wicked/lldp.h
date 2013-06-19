/*
 * LLDP agent support (transmit-only) for wicked
 *
 * Copyright (C) 2013 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_LLDP_H__
#define __WICKED_LLDP_H__

#include <wicked/types.h>
#include <wicked/constants.h>
#include <wicked/address.h>
#include <wicked/dcb.h>

/* Chassis ID subtype */
typedef enum ni_lldp_chassis_id_type {
	NI_LLDP_CHASSIS_ID_INVALID		= 0,
	NI_LLDP_CHASSIS_ID_CHASSIS_COMPONENT	= 1,
	NI_LLDP_CHASSIS_ID_INTERFACE_ALIAS	= 2,
	NI_LLDP_CHASSIS_ID_PORT_COMPONENT	= 3,
	NI_LLDP_CHASSIS_ID_MAC_ADDRESS		= 4,
	NI_LLDP_CHASSIS_ID_NETWORK_ADDRESS	= 5,
	NI_LLDP_CHASSIS_ID_INTERFACE_NAME	= 6,
	NI_LLDP_CHASSIS_ID_LOCALLY_ASSIGNED	= 7,
} ni_lldp_chassis_id_type_t;

/* Port ID subtype */
typedef enum ni_lldp_port_id_type {
	NI_LLDP_PORT_ID_INVALID			= 0,
	NI_LLDP_PORT_ID_INTERFACE_ALIAS		= 1,
	NI_LLDP_PORT_ID_PORT_COMPONENT		= 2,
	NI_LLDP_PORT_ID_MAC_ADDRESS		= 3,
	NI_LLDP_PORT_ID_NETWORK_ADDRESS		= 4,
	NI_LLDP_PORT_ID_INTERFACE_NAME		= 5,
	NI_LLDP_PORT_ID_AGENT_CIRCUIT_ID	= 6,
	NI_LLDP_PORT_ID_LOCALLY_ASSIGNED	= 7,
} ni_lldp_port_id_type_t;

typedef struct ni_lldp_ieee_802_1 ni_lldp_ieee_802_1_t;

struct ni_lldp {
	ni_lldp_destination_t			destination;

	struct {
		ni_lldp_chassis_id_type_t	type;
		char *				string_value;
		ni_hwaddr_t			mac_addr_value;
		ni_sockaddr_t			net_addr_value;
	} chassis_id;

	struct {
		ni_lldp_port_id_type_t		type;
		char *				string_value;
		ni_hwaddr_t			mac_addr_value;
		ni_sockaddr_t			net_addr_value;
	} port_id;

	char *					port_description;

	struct {
		char *				name;
		char *				description;
		unsigned int			capabilities;
	} system;

	uint32_t				ttl;

	ni_lldp_ieee_802_1_t *			ieee_802_1;

	/* 802.1 Qaz fields. Only used in the rx code; the
	 * tx code builds the PDU from the data found in
	 * the ni_dcbx_state attached to the agent.
	 */
	ni_dcb_attributes_t *			dcb_attributes;
};

/*
 * IEEE 802.1 OUI TLV
 */
struct ni_lldp_ieee_802_1 {
	uint16_t				pvid;		/* port VLAN ID */
	uint16_t				ppvid;		/* port and protocol VLAN ID, default 0 */
	unsigned char				ppvlan_flags;	/* port and protocol VLAN flags */

	char *					vlan_name;	/* VLAN name */
	uint16_t				mgmt_vid;	/* Management VID */

	/* Not supported right now:
	 *  - protocol identity
	 *  - VID usage
	 *  - link aggregation
	 */
};

extern ni_lldp_t *	ni_lldp_new(void);
extern void		ni_lldp_free(ni_lldp_t *);
extern int		ni_system_lldp_up(ni_netdev_t *, const ni_lldp_t *);
extern int		ni_system_lldp_down(ni_netdev_t *);

extern const char *	ni_lldp_destination_type_to_name(ni_lldp_destination_t);
extern const char *	ni_lldp_system_capability_type_to_name(ni_lldp_destination_t);

#endif /* __WICKED_LLDP_H__ */
