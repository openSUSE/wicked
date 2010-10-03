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
#include <wicked/util.h>

#define NI_MAXADDRLEN		16
#define NI_MAXHWADDRLEN		64

enum {
	NI_ADDRCONF_DHCP,
	NI_ADDRCONF_STATIC,
	NI_ADDRCONF_AUTOCONF,
	NI_ADDRCONF_IBFT,	/* SUSE extension */

	__NI_ADDRCONF_MAX
};

typedef struct ni_handle	ni_handle_t;
typedef struct ni_syntax	ni_syntax_t;
typedef struct ni_interface	ni_interface_t;

typedef struct ni_address {
	struct ni_address *	next;

	unsigned int		config_method;		/* usually static, but can be dhcp or autoip */
	unsigned int		seq;
	unsigned int		family;
	unsigned int		flags;
	unsigned int		scope;
	unsigned int		prefixlen;
	struct sockaddr_storage	local_addr;
	struct sockaddr_storage	peer_addr;
	struct sockaddr_storage	anycast_addr;
	struct sockaddr_storage	bcast_addr;
	char			label[IFNAMSIZ];
} ni_address_t;

typedef struct ni_hwaddr {
	unsigned short	type;
	unsigned short	len;
	unsigned char	data[NI_MAXHWADDRLEN];
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
	unsigned int		seq;
	unsigned int		family;
	unsigned int		prefixlen;
	struct sockaddr_storage	destination;
	ni_route_nexthop_t	nh;

	unsigned int		mtu;
	unsigned int		tos;
	unsigned int		priority;
} ni_route_t;

typedef struct ni_link_stats {
	unsigned long	rx_packets;		/* total packets received	*/
	unsigned long	tx_packets;		/* total packets transmitted	*/
	unsigned long	rx_bytes;		/* total bytes received 	*/
	unsigned long	tx_bytes;		/* total bytes transmitted	*/
	unsigned long	rx_errors;		/* bad packets received		*/
	unsigned long	tx_errors;		/* packet transmit problems	*/
	unsigned long	rx_dropped;		/* no space in linux buffers	*/
	unsigned long	tx_dropped;		/* no space available in linux	*/
	unsigned long	multicast;		/* multicast packets received	*/
	unsigned long	collisions;

	/* detailed rx_errors: */
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;		/* receiver ring buff overflow	*/
	unsigned long	rx_crc_errors;		/* recved pkt with crc error	*/
	unsigned long	rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long	rx_fifo_errors;		/* recv'r fifo overrun		*/
	unsigned long	rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	
	/* for cslip etc */
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
} ni_link_stats_t;

enum {
	NI_IFTYPE_UNKNOWN = 0,
	NI_IFTYPE_LOOPBACK,
	NI_IFTYPE_ETHERNET,
	NI_IFTYPE_BRIDGE,
	NI_IFTYPE_BOND,
	NI_IFTYPE_VLAN,
	NI_IFTYPE_WIRELESS,
	NI_IFTYPE_INFINIBAND,
	NI_IFTYPE_PPP,
	NI_IFTYPE_SLIP,
	NI_IFTYPE_SIT,
	NI_IFTYPE_GRE,
	NI_IFTYPE_ISDN,
	NI_IFTYPE_TUNNEL,	/* ipip tunnel */
	NI_IFTYPE_TUNNEL6,	/* ip6ip6 tunnel */
	NI_IFTYPE_TOKENRING,
	NI_IFTYPE_FIREWIRE,

	NI_IFTYPE_TUN,
	NI_IFTYPE_TAP,
	NI_IFTYPE_DUMMY,
};

/*
 * DHCP configuration info
 */
#define DHCP_TIMEOUT_INFINITE	(~0U)

typedef struct ni_dhclient_info {
	/* Controlling general behavior */
	unsigned int		settle_timeout;

	/* How to manange leases */
	struct {
		unsigned int	timeout;
		int		reuse_unexpired;
		int		release_on_exit;
	} lease;

	/* Options controlling what to put into the lease request */
	struct {
		char *		hostname;
		char *		clientid;
		char *		vendor_class;
		unsigned int	lease_time;
	} request;

	/* Options what to update based on the info received from 
	 * the DHCP server. */
	struct {
		int		hostname;
		int		resolver;
		int		hosts_file;
		int		default_route;
		int		ntp_servers;
		int		nis_servers;
		int		smb_config;
	} update;
} ni_dhclient_info_t;

/*
 * Leases obtained through a dynamic addrconf protocol,
 * such as DHCP, DHCPv6, IPv4LL, or IBFT.
 */
enum {
	NI_ADDRCONF_STATE_NONE,
	NI_ADDRCONF_STATE_REQUESTING,
	NI_ADDRCONF_STATE_GRANTED,
	NI_ADDRCONF_STATE_RELEASING,
	NI_ADDRCONF_STATE_RELEASED,
	NI_ADDRCONF_STATE_FAILED,
};
typedef struct ni_addrconf_state {
	int			type;
	int			family;
	int			state;

	char *			hostname;
	ni_string_array_t	log_servers;
	ni_string_array_t	dns_servers;
	ni_string_array_t	dns_search;
	ni_string_array_t	ntp_servers;
	ni_string_array_t	nis_servers;
	char *			nis_domain;
	ni_string_array_t	netbios_servers;
	char *			netbios_domain;
	ni_string_array_t	slp_servers;
	ni_string_array_t	slp_scopes;
	ni_address_t *		addrs;
	ni_route_t *		routes;
} ni_addrconf_state_t;

enum {
	NI_AF_MASK_IPV4		= 0x0001,
	NI_AF_MASK_IPV6		= 0x0002,
};

typedef struct ni_addrconf {
	int			type;

	/* Supported address families.
	 * Bitwise OR of NI_AF_MASK_* values
	 */
	unsigned int		supported_af;

	void *			private;

	int			(*request)(const struct ni_addrconf *, ni_interface_t *, const xml_node_t *);
	int			(*release)(const struct ni_addrconf *, ni_interface_t *, ni_addrconf_state_t *);
	int			(*test)(const struct ni_addrconf *, const ni_interface_t *, const xml_node_t *);
} ni_addrconf_t;

typedef struct ni_afinfo {
	int			family;
	int			enabled;
	int			forwarding;
	int			config;	/* formerly known as bootproto */

	ni_addrconf_state_t *	lease[__NI_ADDRCONF_MAX];

	/* This is valid if config == NI_ADDRCONF_DHCP */
	ni_dhclient_info_t *	dhcp;
} ni_afinfo_t;

struct ni_interface {
	struct ni_interface *	next;
	unsigned int		seq;
	unsigned int		modified : 1,
				deleted : 1;

	ni_uuid_t		uuid;

	unsigned int		users;

	char *			name;
	unsigned int		ifindex;
	unsigned int		flags;
	unsigned int		type;

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

	struct ni_interface *	parent;
	struct ni_bonding *	bonding;
	struct ni_vlan *	vlan;
	struct ni_bridge *	bridge;

	/* Configuration data */
	unsigned int		startmode;
};

typedef struct ni_interface_array {
	unsigned int		count;
	ni_interface_t **	data;
} ni_interface_array_t;

enum {
	NI_BOND_MONITOR_ARP,
	NI_BOND_MONITOR_MII,
};
enum {
	NI_BOND_MODE_BALANCE_RR = 0,
	NI_BOND_MODE_ACTIVE_BACKUP = 1,
	NI_BOND_MODE_BALANCE_XOR = 2,
	NI_BOND_MODE_BROADCAST = 3,
	NI_BOND_MODE_802_3AD = 4,
	NI_BOND_MODE_BALANCE_TLB = 5,
	NI_BOND_MODE_BALANCE_ALB = 6,
};
enum {
	NI_BOND_VALIDATE_NONE = 0,
	NI_BOND_VALIDATE_ACTIVE = 1,
	NI_BOND_VALIDATE_BACKUP = 2,
	NI_BOND_VALIDATE_ALL = 3,
};
enum {
	NI_BOND_CARRIER_DETECT_IOCTL = 0,
	NI_BOND_CARRIER_DETECT_NETIF = 1,
};
typedef struct ni_bonding {
	/* For now, just the lump of module options.
	   We really need to break these up */
	char *			module_opts;

	unsigned int		mode;

	int			monitoring;
	struct ni_bonding_arpmon {
		unsigned int	interval;	/* ms */
		unsigned int	validate;
		ni_string_array_t targets;
	}			arpmon;
	struct ni_bonding_miimon {
		unsigned int	frequency;
		unsigned int	updelay;
		unsigned int	downdelay;
		unsigned int	carrier_detect;
	}			miimon;
	char *			primary;	/* FIXME: rename to primary_name/primary_dev */
	ni_interface_t *	primary_ptr;
	char *			extra_options;

	ni_string_array_t	slave_names;
	ni_interface_array_t	slave_devs;
} ni_bonding_t;

typedef struct ni_vlan {
	char *			interface_name;
	unsigned int		link;		/* when parsing system state, this is the
						 * ifindex of the master */
	uint16_t		tag;
	ni_interface_t *	interface_dev;
} ni_vlan_t;

typedef struct ni_bridge {
	int			stp_enabled;
	unsigned int		forward_delay;
	struct ni_string_array	port_names;
	ni_interface_array_t	port_devs;
} ni_bridge_t;

enum {
	NI_START_DISABLE,
	NI_START_ONBOOT,
	NI_START_MANUAL,
	NI_START_HOTPLUG,	/* RHEL extension */
	NI_START_IFPLUGD,	/* SUSE extension */
	NI_START_NFSROOT,	/* SUSE extension */
};

/*
 * Events generated by the rtnetlink layer, and translated
 * by us.
 */
typedef enum ni_event {
	NI_EVENT_LINK_CREATE = 0,
	NI_EVENT_LINK_DELETE,
	NI_EVENT_LINK_UP,
	NI_EVENT_LINK_DOWN,
	NI_EVENT_NETWORK_UP,
	NI_EVENT_NETWORK_DOWN,

	__NI_EVENT_MAX
} ni_event_t;

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
extern void		ni_log_destination_syslog(const char *program);

extern ni_handle_t *	ni_state_open(void);
extern ni_handle_t *	ni_netconfig_open(ni_syntax_t *);
extern ni_handle_t *	ni_indirect_open(const char *);
extern void		ni_indirect_set_root(ni_handle_t *, const char *);
extern ni_handle_t *	ni_dummy_open(void);
extern int		ni_refresh(ni_handle_t *);
extern int		ni_create_topology(ni_handle_t *);
extern void		ni_close(ni_handle_t *);

/* Error reporting */
extern void		ni_bad_reference(ni_handle_t *, const ni_interface_t *, const char *);

extern ni_syntax_t *	ni_syntax_new(const char *schema, const char *pathname);
extern void		ni_syntax_free(ni_syntax_t *);
extern int		ni_syntax_parse_all(ni_syntax_t *, ni_handle_t *);
extern int		ni_syntax_parse_file(ni_syntax_t *, ni_handle_t *, const char *);
extern int		ni_syntax_parse_data(ni_syntax_t *, ni_handle_t *, const char *);
extern int		ni_syntax_parse_stream(ni_syntax_t *, ni_handle_t *, FILE *);
extern int		ni_syntax_format_all(ni_syntax_t *, ni_handle_t *, FILE *);
extern int		ni_syntax_format_interface(ni_syntax_t *, ni_handle_t *, ni_interface_t *, FILE *);
extern xml_node_t *	ni_syntax_xml_from_interface(ni_syntax_t *, ni_handle_t *, ni_interface_t *);
extern ni_interface_t *	ni_syntax_xml_to_interface(ni_syntax_t *, ni_handle_t *, xml_node_t *);
extern xml_document_t *	ni_syntax_xml_from_all(ni_syntax_t *, ni_handle_t *);
extern int		ni_syntax_xml_to_all(ni_syntax_t *, ni_handle_t *, const xml_document_t *);
extern xml_node_t *	ni_syntax_xml_from_lease(ni_syntax_t *, ni_addrconf_state_t *, xml_node_t *);
extern ni_addrconf_state_t *ni_syntax_xml_to_lease(ni_syntax_t *, const xml_node_t *);
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
				ni_addrconf_state_t *);
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

extern ni_address_t *	ni_address_new(ni_interface_t *ifp, int af,
				unsigned int prefix_len,
				const struct sockaddr_storage *local_addr);
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
extern int		ni_address_equal(const struct sockaddr_storage *, const struct sockaddr_storage *);
extern int		__ni_address_info(int, unsigned int *, unsigned int *);
extern int		__ni_address_probably_dynamic(const ni_afinfo_t *, const ni_address_t *);

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

extern int		ni_bonding_bind(ni_interface_t *, ni_handle_t *);
extern void		ni_bonding_free(ni_bonding_t *);
extern ni_bonding_t *	ni_bonding_clone(const ni_bonding_t *);
extern void		ni_bonding_add_slave(ni_bonding_t *, const char *);
extern void		ni_bonding_parse_module_options(ni_bonding_t *);
extern void		ni_bonding_build_module_options(ni_bonding_t *);
extern int		ni_bonding_parse_sysfs_attrs(const char *, ni_bonding_t *);
extern int		ni_bonding_write_sysfs_attrs(const char *ifname,
				const ni_bonding_t *cfg_bond,
				const ni_bonding_t *cur_bond,
				int state);

extern int		ni_bridge_bind(ni_interface_t *, ni_handle_t *);
extern void		ni_bridge_free(ni_bridge_t *);
extern ni_bridge_t *	ni_bridge_clone(const ni_bridge_t *);
extern void		ni_bridge_add_port(ni_bridge_t *, const char *);

extern int		ni_vlan_bind(ni_interface_t *, ni_handle_t *);
extern int		ni_vlan_bind_ifindex(ni_vlan_t *, ni_handle_t *);
extern void		ni_vlan_free(ni_vlan_t *);
extern ni_vlan_t *	ni_vlan_clone(const ni_vlan_t *);

extern ni_dhclient_info_t *ni_dhclient_info_new(void);
extern void		ni_dhclient_info_free(ni_dhclient_info_t *);

extern ni_addrconf_state_t *ni_addrconf_state_new(int type, int family);
extern void		ni_addrconf_state_free(ni_addrconf_state_t *);
extern void		ni_addrconf_register(ni_addrconf_t *);
extern ni_addrconf_t *	ni_addrconf_get(int type, int family);
extern int		ni_addrconf_acquire_lease(const ni_addrconf_t *,
				ni_interface_t *, const xml_node_t *);
extern int		ni_addrconf_drop_lease(const ni_addrconf_t *, ni_interface_t *);
extern int		ni_addrconf_check(const ni_addrconf_t *, const ni_interface_t *, const xml_node_t *);
extern const ni_addrconf_t *ni_addrconf_list_first(const void **);
extern const ni_addrconf_t *ni_addrconf_list_next(const void **);

extern const char *	ni_print_link_flags(int flags);
extern const char *	ni_print_link_type(int type);
extern const char *	ni_print_integer_nice(unsigned long long, const char *);

extern int		ni_linktype_name_to_type(const char *);
extern const char *	ni_linktype_type_to_name(unsigned int);
extern int		ni_addrconf_name_to_type(const char *);
extern const char *	ni_addrconf_type_to_name(unsigned int);
extern int		ni_addrconf_name_to_state(const char *);
extern const char *	ni_addrconf_state_to_name(unsigned int);
extern int		ni_addrfamily_name_to_type(const char *);
extern const char *	ni_addrfamily_type_to_name(unsigned int);
extern int		ni_arphrd_name_to_type(const char *);
extern const char *	ni_arphrd_type_to_name(unsigned int);
extern unsigned int	ni_arphrd_type_to_iftype(int arp_type);
extern int		ni_iftype_to_arphrd_type(unsigned int iftype);

#endif /* __WICKED_NETINFO_H__ */
