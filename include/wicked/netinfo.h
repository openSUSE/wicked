/*
 * Global header file for netinfo library
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_NETINFO_H__
#define __WICKED_NETINFO_H__

#include <sys/socket.h>
#include <stdio.h>

#include <wicked/types.h>
#include <wicked/constants.h>
#include <wicked/util.h>
#include <wicked/address.h>

#include "client/client_state.h"

typedef struct ni_link_stats	ni_link_stats_t;

typedef struct ni_slaveinfo	ni_slaveinfo_t;
struct ni_slaveinfo {
	ni_iftype_t		type;
	char *			kind;

	union {
	    ni_bonding_slave_info_t *	bond;
	};
};

typedef struct ni_linkinfo ni_linkinfo_t;
struct ni_linkinfo {
	ni_iftype_t		type;
	unsigned int		ifindex;
	unsigned int		ifflags;
	ni_hwaddr_t		hwaddr;
	ni_hwaddr_t		hwpeer; /* alias hwbrd */
	char *			alias;

	unsigned int		mtu;
	unsigned int		metric;
	unsigned int		txqlen;
	ni_netdev_ref_t		lowerdev;
	ni_netdev_ref_t		masterdev;
	ni_slaveinfo_t		slave;
	unsigned int		oper_state;
	char *			qdisc;
	char *			kind;

	unsigned int		saved_mtu;

	ni_link_stats_t *	stats;
};

struct ni_netdev {
	ni_netdev_t *		next;
	unsigned int		seq;
	unsigned int		modified : 1,
				deleted : 1,
				created : 1;

	char *			name;
	ni_linkinfo_t		link;

	ni_client_state_t *	client_state;

	unsigned int		users;

	ni_address_t *		addrs;
	ni_route_table_t *	routes;

	/* Network layer */
	ni_ipv4_devinfo_t *	ipv4;
	ni_ipv6_devinfo_t *	ipv6;
	ni_auto6_t *		auto6;

	/* Assigned leases */
	ni_addrconf_lease_t *	leases;

	/* link layer info specific to different device types. */
	ni_team_t *		team;
	ni_bonding_t *		bonding;
	ni_bridge_t *		bridge;
	ni_ovs_bridge_t *	ovsbr;
	ni_ethernet_t *		ethernet;
	ni_infiniband_t *	infiniband;
	ni_vlan_t *		vlan;
	ni_vxlan_t *		vxlan;
	ni_macvlan_t *		macvlan;
	ni_wireless_t *		wireless;
	ni_openvpn_t *		openvpn;
	ni_tuntap_t *		tuntap;
	ni_sit_t *		sit;
	ni_ipip_t *		ipip;
	ni_gre_t *		gre;
	ni_ppp_t *		ppp;
	ni_lldp_t *		lldp;
	ni_dcb_t *		dcb;

	ni_pci_dev_t *		pci_dev;
	ni_ethtool_t *		ethtool;

	ni_event_filter_t *	event_filter;
};

typedef struct ni_netdev_port_req	ni_netdev_port_req_t;
struct ni_netdev_req {
	unsigned int		ifflags;

	unsigned int		mtu;
	unsigned int		metric;
	unsigned int		txqlen;

	char *			alias;

	ni_netdev_ref_t		master;
	ni_netdev_port_req_t *	port;
};

extern ni_bool_t	ni_set_global_config_path(const char *);
extern const char *	ni_get_global_config_path(void);
extern const char *	ni_get_global_config_dir(void);

extern int		ni_init(const char *appname);

/*
 * Extended config file handling for applications that need
 * additional config options
 */
typedef ni_bool_t	ni_init_appdata_callback_t(void *, const xml_node_t *);
extern int		ni_init_ex(const char *appname, ni_init_appdata_callback_t *, void *);

extern int		ni_server_background(const char *, ni_daemon_close_t);
extern int		ni_server_listen_interface_events(void (*handler)(ni_netdev_t *, ni_event_t));
extern int		ni_server_enable_interface_addr_events(void (*handler)(ni_netdev_t *, ni_event_t, const ni_address_t *));
extern int		ni_server_enable_interface_prefix_events(void (*handler)(ni_netdev_t *, ni_event_t, const ni_ipv6_ra_pinfo_t *));
extern int		ni_server_enable_interface_nduseropt_events(void (*handler)(ni_netdev_t *, ni_event_t));
extern int		ni_server_enable_route_events(void (*handler)(ni_netconfig_t *, ni_event_t, const ni_route_t *));
extern int		ni_server_enable_rule_events(void (*handler)(ni_netconfig_t *, ni_event_t, const ni_rule_t *));
extern int		ni_server_enable_interface_uevents(void);
extern void		ni_server_disable_interface_uevents(void);
extern void		ni_server_trace_interface_addr_events(ni_netdev_t *, ni_event_t, const ni_address_t *);
extern void		ni_server_trace_interface_prefix_events(ni_netdev_t *, ni_event_t, const ni_ipv6_ra_pinfo_t *);
extern void		ni_server_trace_interface_nduseropt_events(ni_netdev_t *, ni_event_t);
extern void		ni_server_trace_route_events(ni_netconfig_t *, ni_event_t, const ni_route_t *);
extern void		ni_server_trace_rule_events(ni_netconfig_t *, ni_event_t, const ni_rule_t *);
extern void		ni_server_deactivate_interface_events(void);
extern void		ni_server_deactivate_interface_uevents(void);
extern ni_bool_t	ni_server_disabled_uevents(void);
extern ni_bool_t	ni_server_listens_uevents(void);
extern void		ni_server_listen_other_events(void (*handler)(ni_event_t));
extern ni_dbus_server_t *ni_server_listen_dbus(const char *bus_name);
extern ni_xs_scope_t *	ni_server_dbus_xml_schema(void);
extern const char *	ni_config_piddir(void);
extern const char *	ni_config_statedir(void);
extern const char *	ni_config_storedir(void);
extern const char *	ni_config_backupdir(void);
extern const char *	ni_extension_statedir(const char *);

extern ni_dbus_client_t *ni_create_dbus_client(const char *bus_name);

extern ni_netconfig_t * ni_netconfig_new(void);
extern void		ni_netconfig_free(ni_netconfig_t *);
extern void		ni_netconfig_init(ni_netconfig_t *);
extern void		ni_netconfig_destroy(ni_netconfig_t *);
extern ni_netdev_t *	ni_netconfig_devlist(ni_netconfig_t *nic);
extern xml_document_t *	ni_netconfig_firmware_discovery(const char *, const char *);

extern ni_modem_t *	ni_netconfig_modem_list(ni_netconfig_t *);

extern ni_netconfig_t *	ni_global_state_handle(int);


extern ni_netdev_t *	ni_netdev_by_name(ni_netconfig_t *nic, const char *name);
extern ni_netdev_t *	ni_netdev_by_index(ni_netconfig_t *nic, unsigned int index);
extern ni_netdev_t *	ni_netdev_by_hwaddr(ni_netconfig_t *nic, const ni_hwaddr_t *lla);
extern ni_netdev_t *	ni_netdev_by_vlan_name_and_tag(ni_netconfig_t *nc,
				const char *physdev, uint16_t tag);
extern unsigned int	ni_netdev_name_to_index(const char *);
extern const char *	ni_netdev_make_name(ni_netconfig_t *, const char *, unsigned int);

extern ni_netdev_t *	ni_netdev_new(const char *name, unsigned int ifindex);
extern ni_netdev_t *	ni_netdev_get(ni_netdev_t *ifp);
extern unsigned int	ni_netdev_put(ni_netdev_t *ifp);
extern int		ni_netdev_update(ni_netdev_t *ifp);
extern int		ni_netdev_guess_type(ni_netdev_t *ifp);

extern int		ni_netdev_set_lease(ni_netdev_t *, ni_addrconf_lease_t *);
extern int		ni_netdev_unset_lease(ni_netdev_t *, unsigned int af, ni_addrconf_mode_t type);
ni_addrconf_lease_t *	ni_netdev_get_lease(ni_netdev_t *, unsigned int, ni_addrconf_mode_t);
ni_addrconf_lease_t *	ni_netdev_get_lease_by_uuid(ni_netdev_t *, const ni_uuid_t *);
ni_addrconf_lease_t *	ni_netdev_get_lease_by_owner(ni_netdev_t *, const char *);

extern ni_address_t *	ni_netdev_get_addresses(ni_netdev_t *, unsigned int af);
extern ni_ethtool_t *	ni_netdev_get_ethtool(ni_netdev_t *);
extern ni_ethernet_t *	ni_netdev_get_ethernet(ni_netdev_t *);
extern ni_infiniband_t *ni_netdev_get_infiniband(ni_netdev_t *);
extern ni_bonding_t *	ni_netdev_get_bonding(ni_netdev_t *);
extern ni_team_t *	ni_netdev_get_team(ni_netdev_t *);
extern ni_vlan_t *	ni_netdev_get_vlan(ni_netdev_t *);
extern ni_vxlan_t *	ni_netdev_get_vxlan(ni_netdev_t *);
extern ni_macvlan_t *	ni_netdev_get_macvlan(ni_netdev_t *);
extern ni_bridge_t *	ni_netdev_get_bridge(ni_netdev_t *);
extern ni_ovs_bridge_t *ni_netdev_get_ovs_bridge(ni_netdev_t *);
extern ni_wireless_t *	ni_netdev_get_wireless(ni_netdev_t *);
extern ni_openvpn_t *	ni_netdev_get_openvpn(ni_netdev_t *);
extern ni_tuntap_t *	ni_netdev_get_tuntap(ni_netdev_t *);
extern ni_sit_t *	ni_netdev_get_sit(ni_netdev_t *);
extern ni_ipip_t *	ni_netdev_get_ipip(ni_netdev_t *);
extern ni_gre_t *	ni_netdev_get_gre(ni_netdev_t *);
extern ni_ppp_t *	ni_netdev_get_ppp(ni_netdev_t *);
extern ni_lldp_t *	ni_netdev_get_lldp(ni_netdev_t *);
extern ni_auto6_t *	ni_netdev_get_auto6(ni_netdev_t *);
extern void		ni_netdev_set_bonding(ni_netdev_t *, ni_bonding_t *);
extern void		ni_netdev_set_team(ni_netdev_t *, ni_team_t *);
extern void		ni_netdev_set_vlan(ni_netdev_t *, ni_vlan_t *);
extern void		ni_netdev_set_vxlan(ni_netdev_t *, ni_vxlan_t *);
extern void		ni_netdev_set_macvlan(ni_netdev_t *, ni_macvlan_t *);
extern void		ni_netdev_set_bridge(ni_netdev_t *, ni_bridge_t *);
extern void		ni_netdev_set_ovs_bridge(ni_netdev_t *, ni_ovs_bridge_t *);
extern void		ni_netdev_set_ethtool(ni_netdev_t *, ni_ethtool_t *);
extern void		ni_netdev_set_ethernet(ni_netdev_t *, ni_ethernet_t *);
extern void		ni_netdev_set_infiniband(ni_netdev_t *, ni_infiniband_t *);
extern void		ni_netdev_set_link_stats(ni_netdev_t *, ni_link_stats_t *);
extern void		ni_netdev_set_wireless(ni_netdev_t *, ni_wireless_t *);
extern void		ni_netdev_set_openvpn(ni_netdev_t *, ni_openvpn_t *);
extern void		ni_netdev_set_tuntap(ni_netdev_t *, ni_tuntap_t *);
extern void		ni_netdev_set_sit(ni_netdev_t *, ni_sit_t *);
extern void		ni_netdev_set_ipip(ni_netdev_t *, ni_ipip_t *);
extern void		ni_netdev_set_gre(ni_netdev_t *, ni_gre_t *);
extern void		ni_netdev_set_ppp(ni_netdev_t *, ni_ppp_t *);
extern void		ni_netdev_set_dcb(ni_netdev_t *, ni_dcb_t *);
extern void		ni_netdev_set_lldp(ni_netdev_t *, ni_lldp_t *);
extern void		ni_netdev_set_auto6(ni_netdev_t *, ni_auto6_t *);
extern void		ni_netdev_set_pci(ni_netdev_t *, ni_pci_dev_t *);
extern void		ni_netdev_set_client_state(ni_netdev_t *, ni_client_state_t *);
extern ni_client_state_t *	ni_netdev_get_client_state(ni_netdev_t *);
extern ni_bool_t	ni_netdev_load_client_state(ni_netdev_t *);
extern void		ni_netdev_discover_client_state(ni_netdev_t *);
extern ni_bool_t	ni_netdev_supports_arp(ni_netdev_t *);

extern void             ni_netdev_clear_addresses(ni_netdev_t *);
extern void             ni_netdev_clear_routes(ni_netdev_t *);
extern void		ni_netdev_clear_event_filters(ni_netdev_t *);
extern void		ni_netdev_slaveinfo_destroy(ni_slaveinfo_t *);

extern const ni_uuid_t *ni_netdev_add_event_filter(ni_netdev_t *, unsigned int mask);
extern const ni_uuid_t *ni_netdev_get_event_uuid(ni_netdev_t *, ni_event_t);

extern ni_bool_t	ni_netdev_ref_init(ni_netdev_ref_t *, const char *, unsigned int);
extern ni_bool_t	ni_netdev_ref_set(ni_netdev_ref_t *, const char *, unsigned int);
extern ni_bool_t	ni_netdev_ref_set_ifname(ni_netdev_ref_t *, const char *);
extern ni_bool_t	ni_netdev_ref_set_ifindex(ni_netdev_ref_t *, unsigned int);
extern ni_netdev_t *	ni_netdev_ref_resolve(const ni_netdev_ref_t *, ni_netconfig_t *);
extern ni_netdev_t *	ni_netdev_ref_bind_ifindex(ni_netdev_ref_t *, ni_netconfig_t *);
extern ni_netdev_t *	ni_netdev_ref_bind_ifname (ni_netdev_ref_t *, ni_netconfig_t *);
extern void		ni_netdev_ref_destroy(ni_netdev_ref_t *);

extern ni_netdev_req_t *ni_netdev_req_new(void);
extern void		ni_netdev_req_free(ni_netdev_req_t *req);

extern void		ni_link_address_init(ni_hwaddr_t *);
extern int		ni_link_address_format(const ni_hwaddr_t *ss,
				char *abuf, size_t buflen);
extern const char *	ni_link_address_print(const ni_hwaddr_t *ss);
extern int		ni_link_address_parse(ni_hwaddr_t *, unsigned short, const char *);
extern ni_bool_t	ni_link_address_equal(const ni_hwaddr_t *, const ni_hwaddr_t *);
extern unsigned int	ni_link_address_length(unsigned short);
extern int		ni_link_address_get_broadcast(unsigned short, ni_hwaddr_t *);
extern int		ni_link_address_set(ni_hwaddr_t *, unsigned short arp_type, const void *data, size_t len);
extern ni_bool_t	ni_link_address_is_broadcast(const ni_hwaddr_t *);
extern ni_bool_t	ni_link_address_is_invalid(const ni_hwaddr_t *);

extern int		ni_linktype_name_to_type(const char *);
extern const char *	ni_linktype_type_to_name(unsigned int);
extern const char *	ni_linkflags_bit_to_name(unsigned int);
extern const char *	ni_linkflags_format(ni_stringbuf_t *, unsigned int, const char *);
extern int		ni_addrfamily_name_to_type(const char *);
extern const char *	ni_addrfamily_type_to_name(unsigned int);
extern int		ni_arphrd_name_to_type(const char *);
extern const char *	ni_arphrd_type_to_name(unsigned int);
extern ni_event_t	ni_event_name_to_type(const char *);
extern const char *	ni_event_type_to_name(ni_event_t);
extern int		ni_oper_state_name_to_type(const char *);
extern const char *	ni_oper_state_type_to_name(int);

extern const char *	ni_strerror(int errcode);

extern ni_bool_t	ni_netdev_name_is_valid(const char *);
extern ni_bool_t	ni_netdev_alias_label_is_valid(const char *, const char *);

extern ni_bool_t	ni_netdev_device_is_ready(ni_netdev_t *);
extern ni_bool_t	ni_netdev_device_always_ready(ni_netdev_t *);
extern ni_bool_t	ni_netdev_link_always_ready(ni_linkinfo_t *);

extern ni_tristate_t	ni_netdev_guess_link_required(const ni_netdev_t *);

static inline int
ni_netdev_device_is_up(const ni_netdev_t *ifp)
{
	return ifp ? ifp->link.ifflags & NI_IFF_DEVICE_UP : 0;
}

static inline int
ni_netdev_link_is_up(const ni_netdev_t *ifp)
{
	return ifp ? ifp->link.ifflags & NI_IFF_LINK_UP : 0;
}

static inline int
ni_netdev_network_is_up(const ni_netdev_t *ifp)
{
	return ifp ? ifp->link.ifflags & NI_IFF_NETWORK_UP : 0;
}

#endif /* __WICKED_NETINFO_H__ */
