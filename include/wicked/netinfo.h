/*
 * Global header file for netinfo library
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
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

typedef union ni_sockaddr {
	sa_family_t		ss_family;
	struct sockaddr_storage	ss;
	struct sockaddr_in	sin;
	struct sockaddr_in6	six;
} ni_sockaddr_t;

typedef struct ni_address {
	struct ni_address *	next;

	const ni_addrconf_lease_t *config_lease;	/* configured through lease */

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

typedef struct ni_link_stats	ni_link_stats_t;
typedef struct ni_ethtool_stats	ni_ethtool_stats_t;

enum {
	NI_AF_MASK_IPV4		= 0x0001,
	NI_AF_MASK_IPV6		= 0x0002,
};

typedef struct ni_afinfo {
	int			family;
	unsigned int		enabled;
	unsigned int		forwarding;

	unsigned int		addrconf;	/* bitmask of enabled addrconf modes */
} ni_afinfo_t;
typedef struct ni_afinfo	ni_ipv6_devinfo_t;	/* for now */
typedef struct ni_afinfo	ni_ipv4_devinfo_t;	/* for now */

typedef struct ni_linkinfo ni_linkinfo_t;
struct ni_linkinfo {
	ni_iftype_t		type;
	unsigned int		ifindex;
	unsigned int		ifflags;
	unsigned int		arp_type;
	ni_hwaddr_t		hwaddr;
	char *			alias;

	unsigned int		mtu;
	unsigned int		metric;
	unsigned int		txqlen;
	unsigned int		master;		/* ifindex */
	unsigned int		oper_state;
	char *			qdisc;
	char *			kind;

	ni_vlan_t *		vlan;

	ni_link_stats_t *	stats;
	ni_ethtool_stats_t *	ethtool_stats;

	/* When someone is waiting for the next link change
	 * event, this will be non-NULL */
	ni_uuid_t		event_uuid;
};

struct ni_netdev {
	ni_netdev_t *		next;
	unsigned int		seq;
	unsigned int		modified : 1,
				deleted : 1;

	char *			name;
	ni_linkinfo_t		link;

	char *			client_state;
	ni_uuid_t		uuid;

	unsigned int		users;

	ni_address_t *		addrs;
	ni_route_t *		routes;

	/* Network layer */
	ni_afinfo_t		ipv4;
	ni_afinfo_t		ipv6;

	/* Assigned leases */
	ni_addrconf_lease_t *	leases;

	/* link layer info specific to different device types. */
	ni_netdev_t *		parent;
	ni_bonding_t *		bonding;
	ni_bridge_t *		bridge;
	ni_ethernet_t *		ethernet;
	ni_wireless_t *		wireless;
	ni_openvpn_t *		openvpn;
	ni_ppp_t *		ppp;

	ni_ibft_nic_t *		ibft_nic;
};

struct ni_netdev_req {
	unsigned int		ifflags;

	unsigned int		mtu;
	unsigned int		metric;
	unsigned int		txqlen;

	char *			alias;

	/* Network layer */
	ni_afinfo_t *		ipv4;
	ni_afinfo_t *		ipv6;
};

#define CONFIG_WICKED_STATEDIR	"/var/run/wicked"

extern void		ni_set_global_config_path(const char *);
extern int		ni_init(void);

extern int		ni_server_background(void);
extern int		ni_server_listen_interface_events(void (*handler)(ni_netdev_t *, ni_event_t));
extern void		ni_server_listen_other_events(void (*handler)(ni_event_t));
extern ni_dbus_server_t *ni_server_listen_dbus(const char *bus_name);
extern ni_xs_scope_t *	ni_server_dbus_xml_schema(void);

extern ni_dbus_client_t *ni_create_dbus_client(const char *bus_name);

extern int		ni_enable_debug(const char *);
extern void		ni_debug_help(FILE *);
extern const char * 	ni_debug_facility_to_name(unsigned int);
extern int		ni_debug_name_to_facility(const char *, unsigned int *);
extern const char *	ni_debug_facility_to_description(int);

extern void		ni_log_destination_syslog(const char *program);

extern ni_netconfig_t * ni_netconfig_new(void);
extern void		ni_netconfig_free(ni_netconfig_t *);
extern void		ni_netconfig_init(ni_netconfig_t *);
extern void		ni_netconfig_destroy(ni_netconfig_t *);
extern ni_netdev_t *	ni_netconfig_devlist(ni_netconfig_t *nic);

extern ni_modem_t *	ni_netconfig_modem_list(ni_netconfig_t *);

extern ni_netconfig_t *	ni_global_state_handle(int);


extern ni_netdev_t *	ni_netdev_by_name(ni_netconfig_t *nic, const char *name);
extern ni_netdev_t *	ni_netdev_by_index(ni_netconfig_t *nic, unsigned int index);
extern ni_netdev_t *	ni_netdev_by_hwaddr(ni_netconfig_t *nic, const ni_hwaddr_t *lla);
extern ni_netdev_t *	ni_netdev_by_ibft_nodename(ni_netconfig_t *, const char *);
extern ni_netdev_t *	ni_netdev_by_vlan_name_and_tag(ni_netconfig_t *nc,
				const char *physdev, uint16_t tag);
extern const char *	ni_netdev_make_name(ni_netconfig_t *, const char *);

extern ni_netdev_t *	ni_netdev_new(ni_netconfig_t *, const char *name, unsigned int ifindex);
extern ni_netdev_t *	ni_netdev_get(ni_netdev_t *ifp);
extern int		ni_netdev_put(ni_netdev_t *ifp);
extern int		ni_netdev_update(ni_netdev_t *ifp);
extern int		ni_netdev_guess_type(ni_netdev_t *ifp);

extern int		ni_netdev_set_lease(ni_netdev_t *, ni_addrconf_lease_t *);
extern int		ni_netdev_unset_lease(ni_netdev_t *, int af, ni_addrconf_mode_t type);
ni_addrconf_lease_t *	ni_netdev_get_lease(ni_netdev_t *, int, ni_addrconf_mode_t);
ni_addrconf_lease_t *	ni_netdev_get_lease_by_owner(ni_netdev_t *, const char *);

extern ni_route_t *	ni_netdev_add_route(ni_netdev_t *,
				unsigned int prefix_len,
				const ni_sockaddr_t *dest,
				const ni_sockaddr_t *gw);

extern ni_address_t *	ni_netdev_get_addresses(ni_netdev_t *, int af);
extern ni_ethernet_t *	ni_netdev_get_ethernet(ni_netdev_t *);
extern ni_bonding_t *	ni_netdev_get_bonding(ni_netdev_t *);
extern ni_vlan_t *	ni_netdev_get_vlan(ni_netdev_t *);
extern ni_bridge_t *	ni_netdev_get_bridge(ni_netdev_t *);
extern ni_wireless_t *	ni_netdev_get_wireless(ni_netdev_t *);
extern ni_openvpn_t *	ni_netdev_get_openvpn(ni_netdev_t *);
extern ni_ppp_t *	ni_netdev_get_ppp(ni_netdev_t *);
extern void		ni_netdev_set_bonding(ni_netdev_t *, ni_bonding_t *);
extern void		ni_netdev_set_vlan(ni_netdev_t *, ni_vlan_t *);
extern void		ni_netdev_set_bridge(ni_netdev_t *, ni_bridge_t *);
extern void		ni_netdev_set_ethernet(ni_netdev_t *, ni_ethernet_t *);
extern void		ni_netdev_set_link_stats(ni_netdev_t *, ni_link_stats_t *);
extern void		ni_netdev_set_wireless(ni_netdev_t *, ni_wireless_t *);
extern void		ni_netdev_set_openvpn(ni_netdev_t *, ni_openvpn_t *);
extern void		ni_netdev_set_ppp(ni_netdev_t *, ni_ppp_t *);
extern void		ni_netdev_set_ibft_nic(ni_netdev_t *, ni_ibft_nic_t *);

extern void             ni_netdev_clear_addresses(ni_netdev_t *);
extern void             ni_netdev_clear_routes(ni_netdev_t *);

extern ni_netdev_req_t *ni_netdev_req_new(void);
extern void		ni_netdev_req_free(ni_netdev_req_t *req);

extern ni_address_t *	ni_address_new(ni_netdev_t *ifp, int af,
				unsigned int prefix_len,
				const ni_sockaddr_t *local_addr);
extern void		ni_address_list_append(ni_address_t **, ni_address_t *);
extern void		ni_address_list_destroy(ni_address_t **);
extern void		ni_address_free(ni_address_t *);

extern const char *	ni_address_format(const ni_sockaddr_t *ss, char *abuf, size_t buflen);
extern const char *	ni_address_print(const ni_sockaddr_t *ss);
extern int		ni_address_parse(ni_sockaddr_t *ss, const char *string, int af);
extern unsigned int	ni_address_length(int af);
extern ni_bool_t	ni_address_can_reach(const ni_address_t *laddr, const ni_sockaddr_t *gw);
extern ni_bool_t	ni_address_is_loopback(const ni_address_t *laddr);
extern unsigned int	ni_netmask_bits(const ni_sockaddr_t *mask);
extern int		ni_build_netmask(int, unsigned int, ni_sockaddr_t *);
extern ni_bool_t	ni_address_prefix_match(unsigned int, const ni_sockaddr_t *,
				const ni_sockaddr_t *);
extern ni_bool_t	ni_address_equal(const ni_sockaddr_t *, const ni_sockaddr_t *);
extern ni_bool_t	__ni_address_info(int, unsigned int *, unsigned int *);
extern ni_bool_t	ni_address_probably_dynamic(const ni_address_t *);

extern int		ni_link_address_format(const ni_hwaddr_t *ss,
				char *abuf, size_t buflen);
extern const char *	ni_link_address_print(const ni_hwaddr_t *ss);
extern int		ni_link_address_parse(ni_hwaddr_t *, unsigned int, const char *);
extern ni_bool_t	ni_link_address_equal(const ni_hwaddr_t *, const ni_hwaddr_t *);
extern unsigned int	ni_link_address_length(int);
extern int		ni_link_address_get_broadcast(int, ni_hwaddr_t *);
extern int		ni_link_address_set(ni_hwaddr_t *, int iftype, const void *data, size_t len);

extern ni_route_t *	ni_route_new(ni_netconfig_t *, unsigned int prefix_len,
				const ni_sockaddr_t *dest,
				const ni_sockaddr_t *gw);
extern void		ni_route_list_destroy(ni_route_t **);
extern void		ni_route_free(ni_route_t *);
extern ni_bool_t	ni_route_equal(const ni_route_t *, const ni_route_t *);
extern const char *	ni_route_print(const ni_route_t *);

extern void		ni_sockaddr_set_ipv4(ni_sockaddr_t *, struct in_addr, uint16_t);
extern void		ni_sockaddr_set_ipv6(ni_sockaddr_t *, struct in6_addr, uint16_t);
extern ni_opaque_t *	ni_sockaddr_pack(const ni_sockaddr_t *, ni_opaque_t *);
extern ni_sockaddr_t *	ni_sockaddr_unpack(ni_sockaddr_t *, const ni_opaque_t *);
extern ni_opaque_t *	ni_sockaddr_prefix_pack(const ni_sockaddr_t *, unsigned int, ni_opaque_t *);
extern ni_sockaddr_t *	ni_sockaddr_prefix_unpack(ni_sockaddr_t *, unsigned int *, const ni_opaque_t *);

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
extern int		ni_oper_state_name_to_type(const char *);
extern const char *	ni_oper_state_type_to_name(int);
extern int		ni_iftype_to_arphrd_type(unsigned int iftype);

extern const char *	ni_strerror(int errcode);


static inline int
ni_netdev_device_is_up(const ni_netdev_t *ifp)
{
	return ifp->link.ifflags & NI_IFF_DEVICE_UP;
}

static inline int
ni_netdev_link_is_up(const ni_netdev_t *ifp)
{
	return ifp->link.ifflags & NI_IFF_LINK_UP;
}

static inline int
ni_netdev_network_is_up(const ni_netdev_t *ifp)
{
	return ifp->link.ifflags & NI_IFF_NETWORK_UP;
}

#endif /* __WICKED_NETINFO_H__ */
