/*
 * Type declarations for netinfo.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */
#ifndef __WICKED_TYPES_H__
#define __WICKED_TYPES_H__

#include <wicked/constants.h>
#include <stdint.h>

typedef struct ni_handle	ni_handle_t;		/* nuke */
typedef struct ni_syntax	ni_syntax_t;		/* make private */
typedef struct ni_interface	ni_interface_t;		/* rename to ni_netif_t? */
typedef struct ni_vlan		ni_vlan_t;
typedef struct ni_bridge	ni_bridge_t;
typedef struct ni_bridge_port	ni_bridge_port_t;
typedef struct ni_bonding	ni_bonding_t;
typedef struct ni_wireless	ni_wireless_t;
typedef struct ni_wireless_scan	ni_wireless_scan_t;
typedef struct ni_ethernet	ni_ethernet_t;
typedef struct ni_addrconf	ni_addrconf_t;
typedef struct ni_nis_info	ni_nis_info_t;
typedef struct ni_resolver_info	ni_resolver_info_t;
typedef struct ni_addrconf_request ni_addrconf_request_t;
typedef struct ni_addrconf_lease  ni_addrconf_lease_t;
typedef struct ni_interface_request ni_interface_request_t;

typedef struct ni_socket	ni_socket_t;
typedef struct ni_buffer	ni_buffer_t;
typedef struct ni_extension	ni_extension_t;
typedef struct ni_script_action	ni_script_action_t;

/*
 * These are used by the XML and XPATH code.
 */
typedef struct xpath_format xpath_format_t;
typedef struct xpath_enode xpath_enode_t;
typedef struct xml_document xml_document_t;
typedef struct xml_node xml_node_t;

typedef struct xpath_format_array {
	unsigned int		count;
	xpath_format_t **	data;
} xpath_format_array_t;

/*
 * This is the all-encompassing thingy that holds a
 * complete network config state
 */
typedef struct ni_netconfig	ni_netconfig_t;
struct ni_netconfig {
	ni_interface_t *	interfaces;
	struct ni_route *	routes;		/* should kill this */
	unsigned int		seqno;		/* should kill this */
};

/*
 * Policies
 */
typedef struct ni_policy	ni_policy_t;
struct ni_policy {
	ni_policy_t *		next;
	ni_event_t		event;
	ni_interface_t *	interface;
};

typedef struct ni_policy_info {
	ni_policy_t *		event_policies;
} ni_policy_info_t;

typedef union ni_uuid {
	unsigned char		octets[16];
	uint32_t		words[4];
} ni_uuid_t;

/*
 * Link layer address
 */
#define NI_MAXHWADDRLEN		64
typedef struct ni_hwaddr {
	unsigned short		type;
	unsigned short		len;
	unsigned char		data[NI_MAXHWADDRLEN];
} ni_hwaddr_t;

#endif /* __WICKED_TYPES_H__ */
