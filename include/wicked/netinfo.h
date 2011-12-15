/*
 * Global header file for netinfo library
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_NETINFO_H__
#define __WICKED_NETINFO_H__

#include <sys/socket.h>
#include <stdio.h>
#include <net/if.h>
#include <netinet/in.h>

#include <wicked/types.h>
#include <wicked/constants.h>
#include <wicked/util.h>
#include <wicked/dbus.h>

#define NI_MAXADDRLEN		16

typedef union ni_sockaddr {
	sa_family_t		ss_family;
	struct sockaddr_storage	ss;
	struct sockaddr_in	sin;
	struct sockaddr_in6	six;
} ni_sockaddr_t;

typedef struct ni_address {
	struct ni_address *	next;

	ni_addrconf_mode_t	config_method;		/* usually static, but can be dhcp or autoip */
	unsigned int		seq;
	unsigned int		family;
	unsigned int		flags;
	int			scope;
	unsigned int		prefixlen;
	ni_sockaddr_t		local_addr;
	ni_sockaddr_t		peer_addr;
	ni_sockaddr_t		anycast_addr;
	ni_sockaddr_t		bcast_addr;
	char			label[IFNAMSIZ];
	time_t			expires;		/* when address expires (ipv6) */
} ni_address_t;

typedef struct ni_route_nexthop {
	struct ni_route_nexthop *next;
	ni_sockaddr_t		gateway;
	char *                  device;
	unsigned int		weight;
	unsigned int		flags;
} ni_route_nexthop_t;

typedef struct ni_route {
	struct ni_route *	next;

	ni_addrconf_mode_t	config_method;		/* usually static, but can be dhcp or autoip */
	unsigned int		seq;
	unsigned int		family;
	unsigned int		prefixlen;
	ni_sockaddr_t		destination;
	ni_route_nexthop_t	nh;

	unsigned int		mtu;
	unsigned int		tos;
	unsigned int		priority;
	time_t			expires;		/* when route expires (ipv6) */
} ni_route_t;

typedef struct ni_link_stats {
	unsigned long		rx_packets;		/* total packets received	*/
	unsigned long		tx_packets;		/* total packets transmitted	*/
	unsigned long		rx_bytes;		/* total bytes received 	*/
	unsigned long		tx_bytes;		/* total bytes transmitted	*/
	unsigned long		rx_errors;		/* bad packets received		*/
	unsigned long		tx_errors;		/* packet transmit problems	*/
	unsigned long		rx_dropped;		/* no space in linux buffers	*/
	unsigned long		tx_dropped;		/* no space available in linux	*/
	unsigned long		multicast;		/* multicast packets received	*/
	unsigned long		collisions;

	/* detailed rx_errors: */
	unsigned long		rx_length_errors;
	unsigned long		rx_over_errors;		/* receiver ring buff overflow	*/
	unsigned long		rx_crc_errors;		/* recved pkt with crc error	*/
	unsigned long		rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long		rx_fifo_errors;		/* recv'r fifo overrun		*/
	unsigned long		rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	unsigned long		tx_aborted_errors;
	unsigned long		tx_carrier_errors;
	unsigned long		tx_fifo_errors;
	unsigned long		tx_heartbeat_errors;
	unsigned long		tx_window_errors;
	
	/* for cslip etc */
	unsigned long		rx_compressed;
	unsigned long		tx_compressed;
} ni_link_stats_t;

enum {
	NI_AF_MASK_IPV4		= 0x0001,
	NI_AF_MASK_IPV6		= 0x0002,
};

typedef struct ni_afinfo {
	int			family;
	int			enabled;
	int			forwarding;

	unsigned int		addrconf;	/* bitmask of enabled addrconf modes */

	ni_addrconf_lease_t *	lease[__NI_ADDRCONF_MAX];
	ni_addrconf_request_t *	request[__NI_ADDRCONF_MAX];
} ni_afinfo_t;

typedef struct ni_ifaction {
	ni_evaction_t		action;
	unsigned int		wait;
	unsigned int		mandatory : 1,
				only_if_link : 1;
} ni_ifaction_t;

/*
 * Note: do not change order - NI_IFACTION_* constants need to match order
 * of ifaction members in ni_ifbehavior
 */
enum {
	NI_IFACTION_BOOT,
	NI_IFACTION_SHUTDOWN,
	NI_IFACTION_LINK_UP,
	NI_IFACTION_LINK_DOWN,
	NI_IFACTION_MANUAL_UP,
	NI_IFACTION_MANUAL_DOWN,

	__NI_IFACTION_MAX
};

typedef struct ni_ifbehavior {
	ni_ifaction_t		ifaction[__NI_IFACTION_MAX];
} ni_ifbehavior_t;

typedef struct ni_linkinfo ni_linkinfo_t;
struct ni_linkinfo {
	ni_iftype_t		type;
	unsigned int		ifindex;
	unsigned int		ifflags;
	unsigned int		arp_type;
	ni_hwaddr_t		hwaddr;

	unsigned int		mtu;
	unsigned int		metric;
	unsigned int		txqlen;
	unsigned int		master;		/* ifindex */
	char *			qdisc;
	char *			kind;

	ni_vlan_t *		vlan;

	ni_link_stats_t *	stats;
};

struct ni_interface {
	ni_interface_t *	next;
	unsigned int		seq;
	unsigned int		modified : 1,
				deleted : 1;

	char *			name;
	ni_linkinfo_t		link;

	ni_uuid_t		uuid;

	unsigned int		users;

	unsigned int		up_requesters;

	ni_address_t *		addrs;
	ni_route_t *		routes;

	/* Network layer */
	ni_afinfo_t		ipv4;
	ni_afinfo_t		ipv6;

	/* link layer info specific to different device types. */
	ni_interface_t *	parent;
	ni_bonding_t *		bonding;
	ni_bridge_t *		bridge;
	ni_ethernet_t *		ethernet;
	ni_wireless_t *		wireless;
	ni_wireless_scan_t *	wireless_scan;

	/* Configuration data */
	ni_ifbehavior_t		startmode;
};

struct ni_interface_request {
	unsigned int		ifflags;

	unsigned int		mtu;
	unsigned int		metric;
	unsigned int		txqlen;

	/* Network layer */
	ni_afinfo_t *		ipv4;
	ni_afinfo_t *		ipv6;
};

typedef struct ni_interface_array {
	unsigned int		count;
	ni_interface_t **	data;
} ni_interface_array_t;
#define NI_INTERFACE_ARRAY_INIT	{ .count = 0, .data = NULL }

struct ni_vlan {
	char *			physdev_name;
	unsigned int		physdev_index;	/* when parsing system state, this is the
						 * ifindex of the master */
	uint16_t		tag;
	ni_interface_t *	interface_dev;
};

#define CONFIG_WICKED_STATEDIR	"/var/run/wicked"

extern void		ni_set_global_config_path(const char *);
extern int		ni_init(void);

extern int		ni_policy_update(ni_netconfig_t *, const ni_policy_t *);
extern ni_policy_t *	ni_policy_match_event(const ni_netconfig_t *, ni_event_t, const ni_interface_t *);

extern void		ni_policy_info_append(ni_policy_info_t *, ni_policy_t *);
extern void		ni_policy_info_destroy(ni_policy_info_t *);
extern ni_policy_t *	ni_policy_new(ni_event_t);
extern void		ni_policy_free(ni_policy_t *);

extern ni_socket_t *	ni_server_listen(void);
extern ni_socket_t *	ni_server_connect(void);
extern int		ni_server_background(void);
extern int		ni_server_listen_events(void (*handler)(ni_netconfig_t *, ni_interface_t *, ni_event_t));
extern ni_dbus_server_t *ni_server_listen_dbus(const char *);
extern ni_syntax_t *	ni_default_xml_syntax(void);

extern int		ni_enable_debug(const char *);
extern void		ni_debug_help(FILE *);
extern const char * 	ni_debug_facility_to_name(unsigned int);
extern int		ni_debug_name_to_facility(const char *, unsigned int *);
extern const char *	ni_debug_facility_to_description(int);

extern void		ni_log_destination_syslog(const char *program);

extern void		ni_netconfig_init(ni_netconfig_t *);
extern void		ni_netconfig_destroy(ni_netconfig_t *);

extern ni_netconfig_t *	ni_global_state_handle(int);

/* Error reporting */
extern void		ni_bad_reference(const ni_interface_t *, const char *);

extern ni_syntax_t *	ni_syntax_new(const char *schema, const char *pathname);
extern void		ni_syntax_free(ni_syntax_t *);

extern ni_syntax_t *	ni_netconfig_default_syntax(const char *root_dir);

extern ni_interface_t *	ni_interfaces(ni_netconfig_t *nic);

extern ni_interface_t *	ni_interface_by_name(ni_netconfig_t *nic, const char *name);
extern ni_interface_t *	ni_interface_by_index(ni_netconfig_t *nic, unsigned int index);
extern ni_interface_t *	ni_interface_by_hwaddr(ni_netconfig_t *nic, const ni_hwaddr_t *lla);
extern ni_interface_t *	ni_interface_by_vlan_tag(ni_netconfig_t *nc, uint16_t tag);

/* Replace this */
extern ni_interface_t *	nc_interface_by_name(ni_netconfig_t *nic, const char *name);

extern ni_interface_t *	ni_interface_new(ni_netconfig_t *, const char *name, unsigned int ifindex);
extern ni_interface_t *	ni_interface_clone(const ni_interface_t *);
extern ni_interface_t *	ni_interface_get(ni_interface_t *ifp);
extern int		ni_interface_put(ni_interface_t *ifp);
extern int		ni_interface_update(ni_interface_t *ifp);
extern int		ni_interface_guess_type(ni_interface_t *ifp);
extern int		ni_interface_up(ni_netconfig_t *, ni_interface_t *, const ni_interface_request_t *);
extern int		ni_interface_down(ni_netconfig_t *, ni_interface_t *);
extern int		ni_interface_configure(ni_netconfig_t *, const ni_interface_t *);
extern int		ni_interface_configure2(ni_netconfig_t *, ni_interface_t *, const ni_interface_t *);
extern int		ni_interface_set_lease(ni_interface_t *, ni_addrconf_lease_t *);
extern int		ni_interface_stats_refresh(ni_netconfig_t *, ni_interface_t *);
extern int		ni_interface_request_scan(ni_netconfig_t *, ni_interface_t *);
extern int		ni_interface_get_scan_results(ni_netconfig_t *, ni_interface_t *);
extern int		ni_interface_create_vlan(ni_netconfig_t *nc, const char *ifname,
				const ni_vlan_t *cfg_vlan, ni_interface_t **ifpp);
extern int		ni_interface_delete_vlan(ni_interface_t *ifp);
extern int		ni_interface_create_bridge(ni_netconfig_t *nc, const char *ifname,
				const ni_bridge_t *cfg_bridge, ni_interface_t **ifpp);
extern int		ni_interface_add_bridge_port(ni_netconfig_t *nc, ni_interface_t *ifp,
				ni_bridge_port_t *);
extern int		ni_interface_remove_bridge_port(ni_netconfig_t *, ni_interface_t *, int);
extern int		ni_interface_delete_bridge(ni_netconfig_t *nc, ni_interface_t *ifp);
extern int		ni_interface_create_bond(ni_netconfig_t *nc, const char *ifname,
				const ni_bonding_t *cfg_bond, ni_interface_t **ifpp);
extern int		ni_interface_delete_bond(ni_netconfig_t *nc, ni_interface_t *ifp);
extern int		ni_interface_delete(ni_netconfig_t *, const char *);

extern ni_route_t *	ni_interface_add_route(ni_interface_t *,
				unsigned int prefix_len,
				const ni_sockaddr_t *dest,
				const ni_sockaddr_t *gw);

extern ni_address_t *	ni_interface_get_addresses(ni_interface_t *, int af);
extern ni_ethernet_t *	ni_interface_get_ethernet(ni_interface_t *);
extern ni_bonding_t *	ni_interface_get_bonding(ni_interface_t *);
extern ni_vlan_t *	ni_interface_get_vlan(ni_interface_t *);
extern ni_bridge_t *	ni_interface_get_bridge(ni_interface_t *);
extern void		ni_interface_set_bonding(ni_interface_t *, ni_bonding_t *);
extern void		ni_interface_set_vlan(ni_interface_t *, ni_vlan_t *);
extern void		ni_interface_set_bridge(ni_interface_t *, ni_bridge_t *);
extern void		ni_interface_set_ethernet(ni_interface_t *, ni_ethernet_t *);
extern void		ni_interface_set_link_stats(ni_interface_t *, ni_link_stats_t *);
extern void		ni_interface_set_wireless(ni_interface_t *, ni_wireless_t *);
extern void		ni_interface_set_wireless_scan(ni_interface_t *, ni_wireless_scan_t *);

extern void		ni_interface_array_init(ni_interface_array_t *);
extern void		ni_interface_array_append(ni_interface_array_t *, ni_interface_t *);
extern void		ni_interface_array_destroy(ni_interface_array_t *);
extern int		ni_interface_array_index(const ni_interface_array_t *, const ni_interface_t *);

extern void             ni_interface_clear_addresses(ni_interface_t *);
extern void             ni_interface_clear_routes(ni_interface_t *);

extern ni_interface_request_t *ni_interface_request_new(void);
extern void		ni_interface_request_free(ni_interface_request_t *req);

extern ni_address_t *	ni_address_new(ni_interface_t *ifp, int af,
				unsigned int prefix_len,
				const ni_sockaddr_t *local_addr);
extern ni_address_t *	ni_address_clone(const ni_address_t *);
extern void		ni_address_list_append(ni_address_t **, ni_address_t *);
extern void		ni_address_list_destroy(ni_address_t **);
extern void		ni_address_free(ni_address_t *);

extern const char *	ni_address_format(const ni_sockaddr_t *ss, char *abuf, size_t buflen);
extern const char *	ni_address_print(const ni_sockaddr_t *ss);
extern int		ni_address_parse(ni_sockaddr_t *ss, const char *string, int af);
extern unsigned int	ni_address_length(int af);
extern int		ni_address_can_reach(const ni_address_t *laddr, const ni_sockaddr_t *gw);
extern int		ni_address_is_loopback(const ni_address_t *laddr);
extern unsigned int	ni_netmask_bits(const ni_sockaddr_t *mask);
extern int		ni_build_netmask(int, unsigned int, ni_sockaddr_t *);
extern int		ni_address_prefix_match(unsigned int, const ni_sockaddr_t *,
				const ni_sockaddr_t *);
extern int		ni_address_equal(const ni_sockaddr_t *, const ni_sockaddr_t *);
extern int		__ni_address_info(int, unsigned int *, unsigned int *);
extern int		ni_address_probably_dynamic(const ni_address_t *);

extern int		ni_link_address_format(const ni_hwaddr_t *ss,
				char *abuf, size_t buflen);
extern const char *	ni_link_address_print(const ni_hwaddr_t *ss);
extern int		ni_link_address_parse(ni_hwaddr_t *, unsigned int, const char *);
extern int		ni_link_address_equal(const ni_hwaddr_t *, const ni_hwaddr_t *);
extern unsigned int	ni_link_address_length(int);
extern int		ni_link_address_get_broadcast(int, ni_hwaddr_t *);
extern int		ni_link_address_set(ni_hwaddr_t *, int iftype, const void *data, size_t len);

extern ni_route_t *	ni_route_new(ni_netconfig_t *, unsigned int prefix_len,
				const ni_sockaddr_t *dest,
				const ni_sockaddr_t *gw);
extern void		ni_route_list_destroy(ni_route_t **);
extern void		ni_route_free(ni_route_t *);
extern int		ni_route_equal(const ni_route_t *, const ni_route_t *);
extern const char *	ni_route_print(const ni_route_t *);

extern int		ni_vlan_bind_ifindex(ni_vlan_t *, ni_netconfig_t *);
extern void		ni_vlan_free(ni_vlan_t *);
extern ni_vlan_t *	ni_vlan_clone(const ni_vlan_t *);

extern ni_ethernet_t *	ni_ethernet_alloc(void);
extern void		ni_ethernet_free(ni_ethernet_t *);
extern ni_ethernet_t *	ni_ethernet_clone(const ni_ethernet_t *);

extern void		ni_sockaddr_set_ipv4(ni_sockaddr_t *, struct in_addr, uint16_t);
extern void		ni_sockaddr_set_ipv6(ni_sockaddr_t *, struct in6_addr, uint16_t);

extern const char *	ni_print_link_flags(int flags);
extern const char *	ni_print_link_type(int type);
extern const char *	ni_print_integer_nice(unsigned long long, const char *);

extern int		ni_linktype_name_to_type(const char *);
extern const char *	ni_linktype_type_to_name(unsigned int);
extern int		ni_addrconf_name_to_type(const char *);
extern const char *	ni_addrconf_type_to_name(unsigned int);
extern int		ni_addrconf_name_to_state(const char *);
extern const char *	ni_addrconf_state_to_name(unsigned int);
extern int		ni_addrconf_name_to_update_target(const char *);
extern const char *	ni_addrconf_update_target_to_name(unsigned int);
extern int		ni_addrfamily_name_to_type(const char *);
extern const char *	ni_addrfamily_type_to_name(unsigned int);
extern int		ni_arphrd_name_to_type(const char *);
extern const char *	ni_arphrd_type_to_name(unsigned int);
extern unsigned int	ni_arphrd_type_to_iftype(int arp_type);
extern ni_event_t	ni_event_name_to_type(const char *);
extern const char *	ni_event_type_to_name(ni_event_t);
extern int		ni_ifaction_name_to_type(const char *);
extern const char *	ni_ifaction_type_to_name(unsigned int);
extern int		ni_iftype_to_arphrd_type(unsigned int iftype);

extern const char *	ni_strerror(int errcode);


static inline int
ni_interface_device_is_up(const ni_interface_t *ifp)
{
	return ifp->link.ifflags & NI_IFF_DEVICE_UP;
}

static inline void
ni_interface_device_mark_up(ni_interface_t *ifp)
{
	ifp->link.ifflags |= NI_IFF_DEVICE_UP;
}

static inline void
ni_interface_device_mark_down(ni_interface_t *ifp)
{
	ifp->link.ifflags &= ~NI_IFF_DEVICE_UP;
}

static inline int
ni_interface_link_is_up(const ni_interface_t *ifp)
{
	return ifp->link.ifflags & NI_IFF_LINK_UP;
}

static inline void
ni_interface_link_mark_up(ni_interface_t *ifp)
{
	ifp->link.ifflags |= NI_IFF_LINK_UP;
}

static inline void
ni_interface_link_mark_down(ni_interface_t *ifp)
{
	ifp->link.ifflags &= ~NI_IFF_LINK_UP;
}

static inline int
ni_interface_network_is_up(const ni_interface_t *ifp)
{
	return ifp->link.ifflags & NI_IFF_NETWORK_UP;
}

static inline void
ni_interface_network_mark_up(ni_interface_t *ifp)
{
	ifp->link.ifflags |= NI_IFF_NETWORK_UP;
}

static inline void
ni_interface_network_mark_down(ni_interface_t *ifp)
{
	ifp->link.ifflags &= ~NI_IFF_NETWORK_UP;
}

#endif /* __WICKED_NETINFO_H__ */
