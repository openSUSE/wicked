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

#define NI_MAXADDRLEN		16
#define NI_MAXHWADDRLEN		64

typedef struct ni_address {
	struct ni_address *	next;

	ni_addrconf_mode_t	config_method;		/* usually static, but can be dhcp or autoip */
	unsigned int		seq;
	unsigned int		family;
	unsigned int		flags;
	int			scope;
	unsigned int		prefixlen;
	struct sockaddr_storage	local_addr;
	struct sockaddr_storage	peer_addr;
	struct sockaddr_storage	anycast_addr;
	struct sockaddr_storage	bcast_addr;
	char			label[IFNAMSIZ];
	time_t			expires;		/* when address expires (ipv6) */
} ni_address_t;

typedef struct ni_hwaddr {
	unsigned short		type;
	unsigned short		len;
	unsigned char		data[NI_MAXHWADDRLEN];
} ni_hwaddr_t;

typedef struct ni_route_nexthop {
	struct ni_route_nexthop *next;
	struct sockaddr_storage gateway;
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
	struct sockaddr_storage	destination;
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
	unsigned int		mandatory : 1;
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

struct ni_interface {
	ni_interface_t *	next;
	unsigned int		seq;
	unsigned int		modified : 1,
				deleted : 1;

	ni_uuid_t		uuid;

	unsigned int		users;

	char *			name;
	unsigned int		ifindex;
	unsigned int		flags;
	ni_iftype_t		type;

	unsigned int		arp_type;

	ni_hwaddr_t		hwaddr;
	ni_address_t *		addrs;
	ni_route_t *		routes;

	unsigned int		mtu;
	unsigned int		metric;
	unsigned int		txqlen;
	unsigned int		master;		/* ifindex */
	char *			qdisc;
	char *			kind;

	ni_link_stats_t *	link_stats;

	/* Network layer */
	ni_afinfo_t		ipv4;
	ni_afinfo_t		ipv6;
	ni_socket_t *		ipv6ra_listener;

	struct ni_interface *	parent;
	struct ni_bonding *	bonding;
	struct ni_vlan *	vlan;
	struct ni_bridge *	bridge;

	/* Configuration data */
	ni_ifbehavior_t		startmode;
};

typedef struct ni_interface_array {
	unsigned int		count;
	ni_interface_t **	data;
} ni_interface_array_t;

typedef struct ni_vlan {
	char *			interface_name;
	unsigned int		link;		/* when parsing system state, this is the
						 * ifindex of the master */
	uint16_t		tag;
	ni_interface_t *	interface_dev;
} ni_vlan_t;

#define CONFIG_WICKED_STATEDIR	"/var/run/wicked"

extern void		ni_set_global_config_path(const char *);
extern int		ni_init(void);

extern int		ni_policy_file_parse(const char *, ni_policy_info_t *);
extern ni_policy_t *	ni_policy_match_event(ni_policy_info_t *, xml_node_t *);
extern void		ni_policy_info_destroy(ni_policy_info_t *);
extern ni_policy_t *	ni_policy_match_event(ni_policy_info_t *, xml_node_t *);
extern int		ni_policy_apply(const ni_policy_t *, xml_node_t *);

extern ni_socket_t *	ni_server_listen(void);
extern ni_socket_t *	ni_server_connect(void);
extern int		ni_server_background(void);
extern int		ni_server_listen_events(void (*handler)(ni_handle_t *, ni_interface_t *, ni_event_t));
extern ni_syntax_t *	ni_default_xml_syntax(void);
extern ni_policy_info_t *ni_default_policies(void);

extern int		ni_enable_debug(const char *);
extern void		ni_debug_help(FILE *);
extern const char * 	ni_debug_facility_to_name(unsigned int);
extern int		ni_debug_name_to_facility(const char *, unsigned int *);
extern const char *	ni_debug_facility_to_description(int);

extern void		ni_log_destination_syslog(const char *program);

extern ni_handle_t *	ni_global_state_handle(void);
extern ni_handle_t *	ni_state_open(void);
extern ni_handle_t *	ni_netconfig_open(ni_syntax_t *);
extern ni_handle_t *	ni_indirect_open(const char *);
extern void		ni_indirect_set_root(ni_handle_t *, const char *);
extern ni_handle_t *	ni_dummy_open(void);
extern int		ni_refresh(ni_handle_t *);
extern int		ni_interface_refresh_one(ni_handle_t *, const char *);
extern int		ni_create_topology(ni_handle_t *);
extern void		ni_close(ni_handle_t *);

/* Error reporting */
extern void		ni_bad_reference(ni_handle_t *, const ni_interface_t *, const char *);

extern ni_syntax_t *	ni_syntax_new(const char *schema, const char *pathname);
extern void		ni_syntax_free(ni_syntax_t *);
extern int		ni_syntax_get_interfaces(ni_syntax_t *, ni_handle_t *);
extern int		ni_syntax_parse_file(ni_syntax_t *, ni_handle_t *, const char *);
extern int		ni_syntax_parse_data(ni_syntax_t *, ni_handle_t *, const char *);
extern int		ni_syntax_parse_stream(ni_syntax_t *, ni_handle_t *, FILE *);
extern int		ni_syntax_put_interfaces(ni_syntax_t *, ni_handle_t *, FILE *);
extern int		ni_syntax_put_one_interface(ni_syntax_t *, ni_handle_t *, ni_interface_t *, FILE *);
extern xml_node_t *	ni_syntax_xml_from_interface(ni_syntax_t *, ni_handle_t *, ni_interface_t *);
extern ni_interface_t *	ni_syntax_xml_to_interface(ni_syntax_t *, ni_handle_t *, xml_node_t *);
extern xml_document_t *	ni_syntax_xml_from_all(ni_syntax_t *, ni_handle_t *);
extern int		ni_syntax_xml_to_all(ni_syntax_t *, ni_handle_t *, const xml_document_t *);
extern xml_node_t *	ni_syntax_xml_from_lease(ni_syntax_t *, ni_addrconf_lease_t *, xml_node_t *);
extern ni_addrconf_lease_t *ni_syntax_xml_to_lease(ni_syntax_t *, const xml_node_t *);
extern xml_node_t *	ni_syntax_xml_from_addrconf_request(ni_syntax_t *, ni_addrconf_request_t *, xml_node_t *);
extern ni_addrconf_request_t *ni_syntax_xml_to_addrconf_request(ni_syntax_t *, const xml_node_t *, int);
extern xml_node_t *	ni_syntax_xml_from_nis(ni_syntax_t *, const ni_nis_info_t *, xml_node_t *);
extern ni_nis_info_t *	ni_syntax_xml_to_nis(ni_syntax_t *, const xml_node_t *);
extern xml_node_t *	ni_syntax_xml_from_resolver(ni_syntax_t *, const ni_resolver_info_t *, xml_node_t *);
extern ni_resolver_info_t *ni_syntax_xml_to_resolver(ni_syntax_t *, const xml_node_t *);
extern void		ni_syntax_set_root_directory(ni_syntax_t *, const char *);
extern const char *	ni_syntax_base_path(ni_syntax_t *);
extern const char *	ni_syntax_build_path(ni_syntax_t *, const char *, ...);
extern ni_syntax_t *	ni_netconfig_default_syntax(const char *root_dir);

extern ni_interface_t *	ni_interfaces(ni_handle_t *nic);
extern ni_interface_t *	ni_interface_by_name(ni_handle_t *nic, const char *name);
extern ni_interface_t *	ni_interface_by_index(ni_handle_t *nic, unsigned int index);
extern ni_interface_t *	ni_interface_by_hwaddr(ni_handle_t *nic, const ni_hwaddr_t *lla);
extern ni_interface_t *	ni_interface_first(ni_handle_t *nic, ni_interface_t **pos);
extern ni_interface_t *	ni_interface_next(ni_handle_t *nic, ni_interface_t **pos);

extern ni_interface_t *	ni_interface_new(ni_handle_t *,
				const char *name, unsigned int ifindex);
extern ni_interface_t *	ni_interface_clone(const ni_interface_t *);
extern ni_interface_t *	ni_interface_get(ni_interface_t *ifp);
extern int		ni_interface_put(ni_interface_t *ifp);
extern int		ni_interface_update(ni_interface_t *ifp);
extern int		ni_interface_guess_type(ni_interface_t *ifp);
extern int		ni_interface_configure(ni_handle_t *, ni_interface_t *, xml_node_t *);
extern int		ni_interface_update_lease(ni_handle_t *, ni_interface_t *ifp,
				ni_addrconf_lease_t *);
extern int		ni_interface_set_lease(ni_handle_t *, ni_interface_t *, ni_addrconf_lease_t *);
extern int		ni_interface_delete(ni_handle_t *, const char *);

extern ni_route_t *	ni_interface_add_route(ni_handle_t *, ni_interface_t *,
				unsigned int prefix_len,
				const struct sockaddr_storage *dest,
				const struct sockaddr_storage *gw);

extern ni_address_t *	ni_interface_get_addresses(ni_interface_t *, int af);
extern ni_bonding_t *	ni_interface_get_bonding(ni_interface_t *);
extern ni_vlan_t *	ni_interface_get_vlan(ni_interface_t *);
extern ni_bridge_t *	ni_interface_get_bridge(ni_interface_t *);

extern void		ni_interface_array_init(ni_interface_array_t *);
extern void		ni_interface_array_append(ni_interface_array_t *, ni_interface_t *);
extern void		ni_interface_array_destroy(ni_interface_array_t *);
extern int		ni_interface_array_index(const ni_interface_array_t *, const ni_interface_t *);

extern void             ni_interface_clear_addresses(ni_interface_t *);
extern void             ni_interface_clear_routes(ni_interface_t *);

extern ni_address_t *	ni_address_new(ni_interface_t *ifp, int af,
				unsigned int prefix_len,
				const struct sockaddr_storage *local_addr);
extern ni_address_t *	ni_address_clone(const ni_address_t *);
extern void		ni_address_list_append(ni_address_t **, ni_address_t *);
extern void		ni_address_list_destroy(ni_address_t **);
extern void		ni_address_free(ni_address_t *);

extern int		ni_address_format(const struct sockaddr_storage *ss,
				char *abuf, size_t buflen);
extern const char *	ni_address_print(const struct sockaddr_storage *ss);
extern int		ni_address_parse(struct sockaddr_storage *ss, const char *string, int af);
extern unsigned int	ni_address_length(int af);
extern int		ni_address_can_reach(const ni_address_t *laddr, const struct sockaddr_storage *gw);
extern int		ni_address_is_loopback(const ni_address_t *laddr);
extern unsigned int	ni_netmask_bits(const struct sockaddr_storage *mask);
extern int		ni_build_netmask(int, unsigned int, struct sockaddr_storage *);
extern int		ni_address_prefix_match(unsigned int, const struct sockaddr_storage *,
				const struct sockaddr_storage *);
extern int		ni_address_equal(const struct sockaddr_storage *, const struct sockaddr_storage *);
extern int		__ni_address_info(int, unsigned int *, unsigned int *);
extern int		ni_address_probably_dynamic(const ni_address_t *);

extern int		ni_link_address_format(const ni_hwaddr_t *ss,
				char *abuf, size_t buflen);
extern const char *	ni_link_address_print(const ni_hwaddr_t *ss);
extern int		ni_link_address_parse(ni_hwaddr_t *, unsigned int, const char *);
extern int		ni_link_address_equal(const ni_hwaddr_t *, const ni_hwaddr_t *);
extern unsigned int	ni_link_address_length(int);
extern int		ni_link_address_get_broadcast(int, ni_hwaddr_t *);

extern ni_route_t *	ni_route_new(ni_handle_t *, unsigned int prefix_len,
				const struct sockaddr_storage *dest,
				const struct sockaddr_storage *gw);
extern void		ni_route_list_destroy(ni_route_t **);
extern void		ni_route_free(ni_route_t *);
extern int		ni_route_equal(const ni_route_t *, const ni_route_t *);

extern int		ni_vlan_bind(ni_interface_t *, ni_handle_t *);
extern int		ni_vlan_bind_ifindex(ni_vlan_t *, ni_handle_t *);
extern void		ni_vlan_free(ni_vlan_t *);
extern ni_vlan_t *	ni_vlan_clone(const ni_vlan_t *);

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

#endif /* __WICKED_NETINFO_H__ */
