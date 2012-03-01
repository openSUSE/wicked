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

typedef struct ni_capture	ni_capture_t;
typedef struct __ni_netlink	ni_netlink_t;

extern ni_netlink_t *		__ni_global_netlink;
extern int			__ni_global_iocfd;

struct ni_handle {
	ni_netconfig_t		netconfig;
};

/*
 * These constants describe why/how the interface has been brought up
 */
extern unsigned int	__ni_global_seqno;

extern ni_netlink_t *	__ni_netlink_open(int);
extern void		__ni_netlink_close(ni_netlink_t *);

extern ni_interface_t *	__ni_interface_new(const char *name, unsigned int index);
extern void		__ni_interface_list_append(ni_interface_t **, ni_interface_t *);
extern void		__ni_interface_list_destroy(ni_interface_t **);
extern void		__ni_interfaces_clear(ni_netconfig_t *);
extern ni_addrconf_lease_t *__ni_interface_find_lease(ni_interface_t *, int, ni_addrconf_mode_t, int);
extern ni_addrconf_lease_t *__ni_interface_address_to_lease(ni_interface_t *, const ni_address_t *);
extern ni_addrconf_lease_t *__ni_interface_route_to_lease(ni_interface_t *, const ni_route_t *);
extern void		__ni_interface_track_ipv6_autoconf(ni_interface_t *, int);
extern ni_route_t *	__ni_interface_add_autoconf_prefix(ni_interface_t *, const ni_sockaddr_t *, unsigned int, unsigned int);
extern unsigned int	__ni_interface_translate_ifflags(unsigned int);
extern void		__ni_interface_event(ni_netconfig_t *, ni_interface_t *, ni_event_t);

#define __ni_interface_address_info(ifp, af) \
	((af) == AF_INET? &((ifp)->ipv4) : \
	 ((af) == AF_INET6? &((ifp)->ipv6) : \
	  NULL))

extern void		__ni_afinfo_init(ni_afinfo_t *, int af);

extern ni_route_t *	__ni_route_new(ni_route_t **, unsigned int prefix_len,
				const ni_sockaddr_t *, const ni_sockaddr_t *);
extern void		__ni_route_list_append(ni_route_t **, ni_route_t *);
extern void		__ni_route_list_destroy(ni_route_t **);
extern void		__ni_routes_clear(ni_netconfig_t *);

extern ni_address_t *	__ni_address_new(ni_address_t **, int, unsigned int,
				const ni_sockaddr_t *);
extern int		__ni_address_list_dedup(ni_address_t **);
extern ni_address_t *	__ni_address_list_find(ni_address_t *, const ni_sockaddr_t *);

extern int		__ni_system_refresh_all(ni_netconfig_t *nc, ni_interface_t **del_list);
extern int		__ni_system_refresh_interfaces(ni_netconfig_t *nc);
extern int		__ni_system_refresh_interface(ni_netconfig_t *, ni_interface_t *);
extern int		__ni_device_refresh_link_info(ni_netconfig_t *, ni_linkinfo_t *);
extern int		__ni_system_interface_configure(ni_netconfig_t *, ni_interface_t *, const ni_interface_t *);
extern int		__ni_system_interface_delete(ni_netconfig_t *, const char *);
extern int		__ni_system_interface_stats_refresh(ni_netconfig_t *, ni_interface_t *);
extern int		__ni_system_ethernet_refresh(ni_interface_t *);
extern int		__ni_system_ethernet_update(ni_interface_t *, const ni_ethernet_t *);
extern int		__ni_rtevent_refresh_all(ni_netconfig_t *, ni_interface_t **del_list);

/* FIXME: These should go elsewhere, maybe runtime.h */
extern int		__ni_system_interface_update_lease(ni_interface_t *, ni_addrconf_lease_t **);

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

extern int		__ni_lease_owns_address(const ni_addrconf_lease_t *, const ni_address_t *);
extern ni_route_t *	__ni_lease_owns_route(const ni_addrconf_lease_t *, const ni_route_t *);

extern ni_vlan_t *	__ni_vlan_new(void);
extern void		__ni_vlan_destroy(ni_vlan_t *);

extern int		__ni_wireless_link_event(ni_netconfig_t *, ni_interface_t *, void *, size_t);

static inline void
__ni_addrconf_set_update(unsigned int *mask, unsigned int bit)
{
	*mask |= (1 << bit);
}

static inline int
__ni_addrconf_should_update(unsigned int mask, unsigned int bit)
{
	return !!(mask & (1 << bit));
}

/*
 * Packet capture and raw sockets
 */
typedef struct ni_timeout_param {
	unsigned int		timeout;
	unsigned int		increment;
	unsigned int		max_jitter;
	unsigned int		max_timeout;
	struct timeval		deadline;
} ni_timeout_param_t;

typedef struct ni_capture_devinfo {
	const char *		ifname;
	int			ifindex;
	int			iftype;
	int			arp_type;
	unsigned		mtu;
	ni_hwaddr_t		hwaddr;
} ni_capture_devinfo_t;

extern int		ni_capture_devinfo_init(ni_capture_devinfo_t *, const char *, const ni_linkinfo_t *);
extern int		ni_capture_devinfo_refresh(ni_capture_devinfo_t *, const ni_linkinfo_t *);
extern ni_capture_t *	ni_capture_open(const ni_capture_devinfo_t *, int, void (*)(ni_socket_t *));
extern int		ni_capture_recv(ni_capture_t *, ni_buffer_t *);
extern ssize_t		ni_capture_broadcast(ni_capture_t *, const ni_buffer_t *, const ni_timeout_param_t *);
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
extern int		ni_arp_send(ni_arp_socket_t *, const ni_arp_packet_t *);

/*
 * Allocation helpers
 */
extern void *		xcalloc(unsigned int, size_t);
extern char *		xstrdup(const char *);


#endif /* __NETINFO_PRIV_H__ */
