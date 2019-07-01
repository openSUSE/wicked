/*
 * Type declarations for netinfo.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifndef __WICKED_TYPES_H__
#define __WICKED_TYPES_H__

#include <wicked/constants.h>
#include <sys/types.h>
#include <stdint.h>

typedef unsigned char		ni_bool_t;
#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif

typedef enum {
	NI_TRISTATE_DEFAULT	= -1,
	NI_TRISTATE_DISABLE	= 0,
	NI_TRISTATE_ENABLE	= 1
} ni_tristate_t;

typedef union ni_sockaddr	ni_sockaddr_t;
typedef struct ni_netconfig	ni_netconfig_t;
typedef struct ni_netdev	ni_netdev_t;
typedef struct ni_route		ni_route_t;
typedef struct ni_route_table	ni_route_table_t;
typedef struct ni_rule		ni_rule_t;
typedef struct ni_rule_array	ni_rule_array_t;
typedef struct ni_vlan		ni_vlan_t;
typedef struct ni_vxlan		ni_vxlan_t;
typedef struct ni_macvlan	ni_macvlan_t;
typedef struct ni_bridge	ni_bridge_t;
typedef struct ni_bridge_port	ni_bridge_port_t;
typedef struct ni_ovs_bridge	ni_ovs_bridge_t;
typedef struct ni_ovs_bridge_port_config ni_ovs_bridge_port_config_t;
typedef struct ni_bonding	ni_bonding_t;
typedef struct ni_bonding_slave_info	ni_bonding_slave_info_t;
typedef struct ni_team		ni_team_t;
typedef struct ni_team_port_config ni_team_port_config_t;
typedef struct ni_wireless	ni_wireless_t;
typedef struct ni_wireless_scan	ni_wireless_scan_t;
typedef struct ni_ethtool	ni_ethtool_t;
typedef struct ni_ethernet	ni_ethernet_t;
typedef struct ni_infiniband	ni_infiniband_t;
typedef struct ni_openvpn	ni_openvpn_t;
typedef struct ni_tuntap	ni_tuntap_t;
typedef struct ni_tunnel	ni_tunnel_t;
typedef struct ni_sit		ni_sit_t;
typedef struct ni_ipip		ni_ipip_t;
typedef struct ni_gre		ni_gre_t;
typedef struct ni_ppp		ni_ppp_t;
typedef struct ni_dcb		ni_dcb_t;
typedef struct ni_lldp		ni_lldp_t;
typedef struct ni_nis_info	ni_nis_info_t;
typedef struct ni_resolver_info	ni_resolver_info_t;
typedef struct ni_addrconf_lease  ni_addrconf_lease_t;
typedef struct ni_auto4_request	ni_auto4_request_t;
typedef struct ni_netdev_req	ni_netdev_req_t;
typedef struct ni_ipv4_devinfo	ni_ipv4_devinfo_t;
typedef struct ni_ipv4_devconf	ni_ipv4_devconf_t;
typedef struct ni_ipv6_devinfo	ni_ipv6_devinfo_t;
typedef struct ni_ipv6_devconf	ni_ipv6_devconf_t;
typedef struct ni_auto6		ni_auto6_t;
typedef struct ni_event_filter	ni_event_filter_t;
typedef struct ni_modem		ni_modem_t;
typedef struct ni_pci_dev	ni_pci_dev_t;

typedef struct ni_netdev_ref {
	unsigned int		index;	/* by ifindex */
	char *			name;	/* by ifname  */
} ni_netdev_ref_t;

typedef struct ni_dbus_server	ni_dbus_server_t;
typedef struct ni_dbus_client	ni_dbus_client_t;

typedef struct ni_socket	ni_socket_t;
typedef struct ni_socket_array	ni_socket_array_t;
typedef struct ni_buffer	ni_buffer_t;
typedef struct ni_extension	ni_extension_t;
typedef struct ni_script_action	ni_script_action_t;

typedef struct ni_shellcmd	ni_shellcmd_t;
typedef struct ni_process	ni_process_t;

/*
 * These are used by the XML and XPATH code.
 */
typedef struct xpath_format		xpath_format_t;
typedef struct xpath_enode		xpath_enode_t;
typedef struct xml_document		xml_document_t;
typedef struct xml_document_array	xml_document_array_t;
typedef struct xml_node			xml_node_t;
typedef struct xml_location		xml_location_t;

typedef struct ni_xs_type		ni_xs_type_t;
typedef struct ni_xs_scope		ni_xs_scope_t;
typedef struct ni_xs_method		ni_xs_method_t;
typedef struct ni_xs_service		ni_xs_service_t;

typedef struct xpath_format_array {
	unsigned int		count;
	xpath_format_t **	data;
} xpath_format_array_t;

typedef union ni_uuid {
	unsigned char		octets[16];
	uint16_t		shorts[8];
	uint32_t		words[4];
} ni_uuid_t;
#define NI_UUID_INIT		{ .words = { 0, 0, 0, 0 } }

/*
 * Link layer address
 */
#define NI_MAXHWADDRLEN		64
typedef struct ni_hwaddr {
	unsigned short		type;
	unsigned short		len;
	unsigned char		data[NI_MAXHWADDRLEN];
} ni_hwaddr_t;

/*
 * Range of unsigned values
 */
typedef struct ni_uint_range {
	unsigned int		min, max;
} ni_uint_range_t;

static inline void
ni_uint_range_update_min(ni_uint_range_t *r, unsigned int min)
{
	if (min > r->min)
		r->min = min;
}

static inline void
ni_uint_range_update_max(ni_uint_range_t *r, unsigned int max)
{
	if (max < r->max)
		r->max = max;
}

/*
 * Range of signed values
 */
typedef struct ni_int_range {
	int			min, max;
} ni_int_range_t;

/*
 * Prototypes for ipv6 devinfo RA details
 */
typedef struct ni_ipv6_ra_info	ni_ipv6_ra_info_t;
typedef struct ni_ipv6_ra_pinfo	ni_ipv6_ra_pinfo_t;

/*
 * Custom dhcp option declaration
 */
typedef struct ni_dhcp_option_decl ni_dhcp_option_decl_t;

#endif /* __WICKED_TYPES_H__ */
