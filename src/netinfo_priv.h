/*
 * Private header file for netinfo library.
 * No user serviceable parts inside.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __NETINFO_PRIV_H__
#define __NETINFO_PRIV_H__

#include <stdio.h>

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/logging.h>

#include <netlink/netlink.h>

typedef struct ni_capture	ni_capture_t;

typedef struct __ni_netlink {
	struct nl_handle *	nl_handle;
	struct nl_cache *	nl_cache;
	struct nl_cb *		nl_cb;
	struct genl_family *	nl_family;
} ni_netlink_t;


struct ni_handle {
	ni_interface_t *	iflist;
	ni_route_t *		routes;
	ni_policy_info_t	policy;

	/* For a state handle */
	ni_netlink_t *		netlink;
	int			iocfd;
};

struct ni_ops {
	void			(*close)(ni_handle_t *);
};

/*
 * This encapsulates how we store network configuration.
 * This can be a sysconfig style collection of files (with
 * variant variable naming schemes, etc), or an XML file
 * like the ones used by netcf.
 */
#include <wicked/backend.h>
struct ni_syntax {
	const char *		schema;
	char *			base_path;
	char *			root_dir;
	unsigned char		strict;

	int			(*get_interfaces)(ni_syntax_t *, ni_netconfig_t *);
	int			(*put_interfaces)(ni_syntax_t *, ni_netconfig_t *, FILE *);
	int			(*put_one_interface)(ni_syntax_t *, ni_netconfig_t *, ni_interface_t *, FILE *);

	int			(*get_hostname)(ni_syntax_t *, char *, size_t);
	int			(*put_hostname)(ni_syntax_t *, const char *);
	int			(*get_nis)(ni_syntax_t *, ni_nis_info_t *);
	int			(*put_nis)(ni_syntax_t *, const ni_nis_info_t *);

	xml_node_t *		(*xml_from_interface)(ni_syntax_t *, const ni_interface_t *, xml_node_t *parent);
	ni_interface_t *	(*xml_to_interface)(ni_syntax_t *, ni_netconfig_t *, xml_node_t *);

	xml_node_t *		(*xml_from_interface_stats)(ni_syntax_t *, ni_netconfig_t *, const ni_interface_t *, xml_node_t *);
	int			(*xml_to_interface_stats)(ni_syntax_t *, ni_netconfig_t *, ni_interface_t *, const xml_node_t *);

	xml_node_t *		(*xml_from_policy)(ni_syntax_t *, const ni_policy_t *, xml_node_t *parent);
	ni_policy_t *		(*xml_to_policy)(ni_syntax_t *, xml_node_t *);

	xml_node_t *		(*xml_from_ethernet)(ni_syntax_t *, const ni_ethernet_t *, xml_node_t *parent);
	ni_ethernet_t *		(*xml_to_ethernet)(ni_syntax_t *, const xml_node_t *);

	xml_node_t *		(*xml_from_wireless_scan)(ni_syntax_t *, const ni_wireless_scan_t *, xml_node_t *parent);
	ni_wireless_scan_t *	(*xml_to_wireless_scan)(ni_syntax_t *, const xml_node_t *);

	xml_node_t *		(*xml_from_lease)(ni_syntax_t *, const ni_addrconf_lease_t *, xml_node_t *parent);
	ni_addrconf_lease_t *	(*xml_to_lease)(ni_syntax_t *, const xml_node_t *);
	xml_node_t *		(*xml_from_request)(ni_syntax_t *, const ni_addrconf_request_t *, xml_node_t *parent);
	ni_addrconf_request_t *	(*xml_to_request)(ni_syntax_t *, const xml_node_t *, int);

	xml_node_t *		(*xml_from_nis)(ni_syntax_t *, const ni_nis_info_t *, xml_node_t *parent);
	ni_nis_info_t *		(*xml_to_nis)(ni_syntax_t *, const xml_node_t *);
	xml_node_t *		(*xml_from_resolver)(ni_syntax_t *, const ni_resolver_info_t *, xml_node_t *parent);
	ni_resolver_info_t *	(*xml_to_resolver)(ni_syntax_t *, const xml_node_t *);
};

/*
 * These constants describe why/how the interface has been brought up
 */
typedef enum {
	NI_INTERFACE_ADMIN = 0,
	NI_INTERFACE_WIRELESS_SCAN,
} ni_interface_activity_t;

extern unsigned int	__ni_global_seqno;

extern ni_netlink_t *	__ni_netlink_open(int);
extern void		__ni_netlink_close(ni_netlink_t *);

extern ni_handle_t *	__ni_handle_new(size_t);
extern ni_interface_t *	__ni_interface_new(const char *name, unsigned int index);
extern void		__ni_interface_list_append(ni_interface_t **, ni_interface_t *);
extern void		__ni_interface_list_destroy(ni_interface_t **);
extern void		__ni_interfaces_clear(ni_handle_t *);
extern ni_addrconf_lease_t *__ni_interface_address_to_lease(ni_interface_t *, const ni_address_t *);
extern ni_addrconf_lease_t *__ni_interface_route_to_lease(ni_interface_t *, const ni_route_t *);
extern unsigned int	__ni_interface_translate_ifflags(unsigned int);
extern int		__ni_interface_begin_activity(ni_handle_t *, ni_interface_t *, ni_interface_activity_t);
extern int		__ni_interface_end_activity(ni_handle_t *, ni_interface_t *, ni_interface_activity_t);
extern int		__ni_interface_check_activity(ni_handle_t *, ni_interface_t *, ni_interface_activity_t);

#define __ni_interface_address_info(ifp, af) \
	((af) == AF_INET? &((ifp)->ipv4) : \
	 ((af) == AF_INET6? &((ifp)->ipv6) : \
	  NULL))

extern void		__ni_afinfo_set_addrconf_request(ni_afinfo_t *, unsigned int, ni_addrconf_request_t *);
extern void		__ni_afinfo_set_addrconf_lease(ni_afinfo_t *, unsigned int, ni_addrconf_lease_t *);

extern ni_route_t *	__ni_route_new(ni_route_t **, unsigned int prefix_len,
				const ni_sockaddr_t *, const ni_sockaddr_t *);
extern ni_route_t *	__ni_route_list_clone(const ni_route_t *);
extern void		__ni_route_list_append(ni_route_t **, ni_route_t *);
extern void		__ni_route_list_destroy(ni_route_t **);
extern void		__ni_routes_clear(ni_handle_t *);

extern int		__ni_generic_policy_update(ni_handle_t *, const ni_policy_t *, ni_policy_t **);
extern ni_policy_t *	__ni_policy_clone(const ni_policy_t *);

extern ni_address_t *	__ni_address_new(ni_address_t **, int, unsigned int,
				const ni_sockaddr_t *);
extern int		__ni_address_list_dedup(ni_address_t **);
extern ni_address_t *	__ni_address_list_find(ni_address_t *, const ni_sockaddr_t *);

extern int		__ni_system_refresh_all(ni_handle_t *nih, ni_interface_t **del_list);
extern int		__ni_system_refresh_interfaces(ni_handle_t *nih);
extern int		__ni_system_refresh_interface(ni_handle_t *, ni_interface_t *);
extern int		__ni_device_refresh_link_info(ni_handle_t *, ni_linkinfo_t *);
extern int		__ni_system_interface_configure(ni_handle_t *, ni_interface_t *, const ni_interface_t *);
extern int		__ni_system_interface_delete(ni_handle_t *, const char *);
extern int		__ni_system_interface_stats_refresh(ni_handle_t *, ni_interface_t *);
extern int		__ni_system_ethernet_refresh(ni_handle_t *, ni_interface_t *);
extern int		__ni_rtevent_refresh_all(ni_handle_t *, ni_interface_t **del_list);

/* FIXME: These should go elsewhere, maybe runtime.h */
extern int		__ni_system_interface_update_lease(ni_interface_t *, ni_addrconf_lease_t *);

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

extern int		__ni_syntax_xml_to_all(ni_syntax_t *, ni_netconfig_t *, const xml_node_t *);
extern int		__ni_syntax_xml_to_policy_info(ni_syntax_t *, ni_policy_info_t *,
					const xml_node_t *);
extern xml_node_t *	__ni_syntax_xml_from_policy_info(ni_syntax_t *, const ni_policy_info_t *);

extern ni_syntax_t *	__ni_syntax_sysconfig_suse(const char *pathname);
extern ni_syntax_t *	__ni_syntax_sysconfig_redhat(const char *pathname);
extern ni_syntax_t *	__ni_syntax_netcf(const char *pathname);
extern ni_syntax_t *	__ni_syntax_netcf_strict(const char *pathname);

extern ni_address_t *	__ni_address_list_clone(const ni_address_t *);

extern ni_address_t *	__ni_lease_owns_address(const ni_addrconf_lease_t *, const ni_address_t *);
extern ni_route_t *	__ni_lease_owns_route(const ni_addrconf_lease_t *, const ni_route_t *);

extern ni_vlan_t *	__ni_vlan_new(void);
extern void		__ni_vlan_destroy(ni_vlan_t *);

extern int		__ni_wireless_request_scan(ni_handle_t *, ni_interface_t *);
extern int		__ni_wireless_get_scan_results(ni_handle_t *, ni_interface_t *);
extern int		__ni_wireless_link_event(ni_handle_t *, ni_interface_t *, void *, size_t);

/*
 * Helper function to match interface "behaviors" to names
 */
struct __ni_ifbehavior_map {
	const char *	name;
	ni_ifbehavior_t	behavior;
};
extern const char *	__ni_netinfo_best_behavior(const ni_ifbehavior_t *, const struct __ni_ifbehavior_map *);
extern const ni_ifbehavior_t *__ni_netinfo_get_behavior(const char *, const struct __ni_ifbehavior_map *);

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

/*
 * Retain warn() error() etc as shorthand for now
 */
#define warn(fmt, args...)	ni_warn(fmt, ##args)
#define error(fmt, args...)	ni_error(fmt, ##args)
#define fatal(fmt, args...)	ni_fatal(fmt, ##args)
#define trace(fmt, args...)	ni_trace(fmt, ##args)

#define debug_ifconfig	ni_debug_ifconfig
#define debug_readwrite	ni_debug_readwrite
#define debug_xpath	ni_debug_xpath
#define debug_extension	ni_debug_extension
#define debug_wicked	ni_debug_wicked

#endif /* __NETINFO_PRIV_H__ */
