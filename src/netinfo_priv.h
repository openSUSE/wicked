/*
 * Private header file for netinfo library.
 * No user serviceable parts inside.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __NETINFO_PRIV_H__
#define __NETINFO_PRIV_H__

#include <stdio.h>

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/team.h>
#include <wicked/ovs.h>

typedef struct ni_capture	ni_capture_t;
typedef struct __ni_netlink	ni_netlink_t;

extern ni_netlink_t *		__ni_global_netlink;
extern int			__ni_global_iocfd;

struct ni_event_filter {
	ni_event_filter_t *	next;

	unsigned int		event_mask;
	ni_uuid_t		uuid;
};

enum {
	/* link details discover filter using external calls */
	NI_NETCONFIG_DISCOVER_LINK_EXTERN = 1U << 0,
};

/*
 * These constants describe why/how the interface has been brought up
 */
extern unsigned int	__ni_global_seqno;

extern ni_netlink_t *	__ni_netlink_open(int);
extern void		__ni_netlink_close(ni_netlink_t *);

extern void		ni_netconfig_device_append(ni_netconfig_t *, ni_netdev_t *);
extern void		ni_netconfig_device_remove(ni_netconfig_t *, ni_netdev_t *);
extern ni_netdev_t **	ni_netconfig_device_list_head(ni_netconfig_t *);
extern void		ni_netconfig_modem_append(ni_netconfig_t *, ni_modem_t *);
extern int		ni_netconfig_route_add(ni_netconfig_t *, ni_route_t *, ni_netdev_t *);
extern int		ni_netconfig_route_del(ni_netconfig_t *, ni_route_t *, ni_netdev_t *);
extern int		ni_netconfig_rule_add(ni_netconfig_t *, ni_rule_t *);
extern int		ni_netconfig_rule_del(ni_netconfig_t *, const ni_rule_t *, ni_rule_t **);
extern ni_rule_t *	ni_netconfig_rule_find(ni_netconfig_t *, const ni_rule_t *);
extern ni_rule_array_t *ni_netconfig_rule_array(ni_netconfig_t *);

extern ni_bool_t	ni_netconfig_set_discover_filter(ni_netconfig_t *, unsigned int);
extern ni_bool_t	ni_netconfig_discover_filtered(ni_netconfig_t *, unsigned int);
extern ni_bool_t	ni_netconfig_set_family_filter(ni_netconfig_t *, unsigned int);
extern unsigned int	ni_netconfig_get_family_filter(ni_netconfig_t *);

extern ni_bool_t	__ni_linkinfo_kind_to_type(const char *, ni_iftype_t *);

extern void		__ni_netdev_list_append(ni_netdev_t **, ni_netdev_t *);
extern void		__ni_netdev_list_destroy(ni_netdev_t **);
extern ni_addrconf_lease_t *__ni_netdev_find_lease(ni_netdev_t *, unsigned int, ni_addrconf_mode_t, int);
extern ni_addrconf_lease_t *__ni_netdev_address_to_lease(ni_netdev_t *, const ni_address_t *, unsigned int);
extern ni_addrconf_lease_t *__ni_netdev_route_to_lease(ni_netdev_t *, const ni_route_t *, unsigned int);
extern void		__ni_netdev_track_ipv6_autoconf(ni_netdev_t *, int);
extern unsigned int	__ni_netdev_translate_ifflags(unsigned int, unsigned int);
extern void		__ni_netdev_process_events(ni_netconfig_t *, ni_netdev_t *, unsigned int);
extern void		__ni_netdev_event(ni_netconfig_t *, ni_netdev_t *, ni_event_t);

extern int		__ni_ipv4_devconf_process_flags(ni_netdev_t *, int32_t *, unsigned int);
extern int		__ni_ipv6_devconf_process_flags(ni_netdev_t *, int32_t *, unsigned int);

extern void		__ni_routes_clear(ni_netconfig_t *);

extern ni_bool_t	__ni_address_list_remove(ni_address_t **, ni_address_t *);

extern int		__ni_system_refresh_all(ni_netconfig_t *nc, ni_netdev_t **del_list);
extern int		__ni_system_refresh_interfaces(ni_netconfig_t *nc);
extern int		__ni_system_refresh_interface(ni_netconfig_t *, ni_netdev_t *);
extern int		__ni_system_refresh_interface_addrs(ni_netconfig_t *, ni_netdev_t *);
extern int		__ni_system_refresh_interface_routes(ni_netconfig_t *, ni_netdev_t *);
extern int		__ni_system_refresh_routes(ni_netconfig_t *);
extern int		__ni_system_refresh_rules(ni_netconfig_t *);
extern int		__ni_device_refresh_link_info(ni_netconfig_t *, ni_linkinfo_t *);
extern int		__ni_device_refresh_ipv6_link_info(ni_netconfig_t *, ni_netdev_t *);
extern int		__ni_system_interface_configure(ni_netconfig_t *, ni_netdev_t *, const ni_netdev_t *);
extern int		__ni_system_interface_delete(ni_netconfig_t *, const char *);
extern int		__ni_system_interface_stats_refresh(ni_netconfig_t *, ni_netdev_t *);
extern int		__ni_system_interface_flush_addrs(ni_netconfig_t *, ni_netdev_t *);
extern int		__ni_system_interface_flush_routes(ni_netconfig_t *, ni_netdev_t *);
extern void		__ni_system_ethernet_refresh(ni_netdev_t *);
extern void		__ni_system_ethernet_update(ni_netdev_t *, ni_ethernet_t *);

/* FIXME: These should go elsewhere, maybe runtime.h */
extern int		__ni_system_interface_update_lease(ni_netdev_t *, ni_addrconf_lease_t **);

/* FIXME: These should go elsewhere, maybe runtime.h */
extern int		__ni_system_hostname_put(const char *);
extern int		__ni_system_hostname_get(char *, size_t);
extern int		__ni_system_nis_domain_put(const char *);
extern int		__ni_system_nis_domain_get(char *, size_t);
extern int		__ni_system_nis_put(const ni_nis_info_t *);
extern ni_nis_info_t *	__ni_system_nis_get(void);
extern int		__ni_system_nis_backup(void);
extern int		__ni_system_nis_restore(void);
extern int		__ni_system_resolver_put(const ni_resolver_info_t *);
extern ni_resolver_info_t *__ni_system_resolver_get(void);
extern int		__ni_system_resolver_backup(void);
extern int		__ni_system_resolver_restore(void);

extern ni_bool_t	__ni_lease_owns_address(const ni_addrconf_lease_t *, const ni_address_t *);
extern ni_route_t *	__ni_lease_owns_route(const ni_addrconf_lease_t *, const ni_route_t *);

extern int		__ni_wireless_link_event(ni_netconfig_t *, ni_netdev_t *, void *, size_t);

static inline ni_bool_t	__ni_addrconf_should_update(unsigned int mask, unsigned int bit)
{
	return !!(mask & (1 << bit));
}

/*
 * Packet capture and raw sockets
 */
#include <wicked/socket.h>

typedef struct ni_capture_devinfo {
	char *			ifname;
	unsigned int		ifindex;
	ni_iftype_t		iftype;
	unsigned int		mtu;
	ni_hwaddr_t		hwaddr;
} ni_capture_devinfo_t;

typedef struct ni_capture_protinfo {
	uint16_t		eth_protocol;
	ni_hwaddr_t		eth_destaddr;

	/* If eth_protocol is ETHERTYPE_IP */
	uint8_t			ip_protocol;

	/* If ip_protocol is IPPROT_UDP or TCP */
	uint16_t		ip_port;
} ni_capture_protinfo_t;

extern int		ni_capture_devinfo_init(ni_capture_devinfo_t *, const char *, const ni_linkinfo_t *);
extern int		ni_capture_devinfo_refresh(ni_capture_devinfo_t *, const char *, const ni_linkinfo_t *);
extern ni_capture_t *	ni_capture_open(const ni_capture_devinfo_t *, const ni_capture_protinfo_t *, void (*)(ni_socket_t *));
extern int		ni_capture_recv(ni_capture_t *, ni_buffer_t *);
extern ssize_t		ni_capture_send(ni_capture_t *, const ni_buffer_t *, const ni_timeout_param_t *);
extern void		ni_capture_disarm_retransmit(ni_capture_t *);
extern void		ni_capture_force_retransmit(ni_capture_t *, unsigned int);
extern void		ni_capture_free(ni_capture_t *);
extern int		ni_capture_desc(const ni_capture_t *);
extern int		ni_capture_build_udp_header(ni_buffer_t *,
					struct in_addr src_addr, uint16_t src_port,
					struct in_addr dst_addr, uint16_t dst_port);
extern void		ni_capture_set_user_data(ni_capture_t *, void *);
extern void *		ni_capture_get_user_data(const ni_capture_t *);
extern int		ni_capture_is_valid(const ni_capture_t *, int protocol);

typedef struct ni_arp_socket ni_arp_socket_t;

typedef struct ni_arp_packet {
	unsigned int		op;
	ni_hwaddr_t		sha;
	struct in_addr		sip;
	ni_hwaddr_t		tha;
	struct in_addr		tip;
} ni_arp_packet_t;

typedef void		ni_arp_callback_t(ni_arp_socket_t *, const ni_arp_packet_t *, void *);

struct ni_arp_socket {
	ni_capture_t *		capture;
	ni_capture_devinfo_t	dev_info;

	ni_arp_callback_t *	callback;
	void *			user_data;
};

extern ni_arp_socket_t *ni_arp_socket_open(const ni_capture_devinfo_t *,
					ni_arp_callback_t *, void *);
extern void		ni_arp_socket_close(ni_arp_socket_t *);
extern int		ni_arp_send_request(ni_arp_socket_t *, struct in_addr, struct in_addr);
extern int		ni_arp_send_reply(ni_arp_socket_t *, struct in_addr,
				const ni_hwaddr_t *, struct in_addr);
extern int		ni_arp_send_grat_reply(ni_arp_socket_t *, struct in_addr);
extern int		ni_arp_send_grat_request(ni_arp_socket_t *, struct in_addr);
extern int		ni_arp_send(ni_arp_socket_t *, const ni_arp_packet_t *);

/* netdev reques port config */
struct ni_netdev_port_req {
	ni_iftype_t				type;
	union {
		ni_team_port_config_t		team;
		ni_ovs_bridge_port_config_t	ovsbr;
	};
};

extern ni_netdev_port_req_t *	ni_netdev_port_req_new(ni_iftype_t);
extern void			ni_netdev_port_req_free(ni_netdev_port_req_t *);

#endif /* __NETINFO_PRIV_H__ */
