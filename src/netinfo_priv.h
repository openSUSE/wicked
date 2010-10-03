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

#include "libnetlink.h"

struct ni_handle {
	ni_interface_t *	iflist;
	ni_route_t *		routes;
	unsigned int		seqno;

	struct ni_ops *		op;

	/* For a state handle */
	struct rtnl_handle	rth;
	int			iocfd;
};

struct ni_ops {
	int			(*refresh)(ni_handle_t *);
	int			(*configure_interface)(ni_handle_t *, ni_interface_t *, xml_node_t *);
	int			(*delete_interface)(ni_handle_t *, const char *);
	int			(*update_lease)(ni_handle_t *, ni_interface_t *, ni_addrconf_state_t *);
	int			(*hostname_get)(ni_handle_t *, char *, size_t);
	int			(*hostname_put)(ni_handle_t *, const char *);
	void			(*close)(ni_handle_t *);
};

/*
 * This encapsulates how we store network configuration.
 * This can be a sysconfig style collection of files (with
 * variant variable naming schemes, etc), or an XML file
 * like the ones used by netcf.
 */
struct ni_syntax {
	const char *		schema;
	char *			base_path;
	char *			root_dir;
	unsigned char		strict;

	int			(*parse_all)(ni_syntax_t *, ni_handle_t *);
	int			(*parse_all_from_file)(ni_syntax_t *, ni_handle_t *, const char *);
	int			(*parse_all_from_stream)(ni_syntax_t *, ni_handle_t *, FILE *);
	int			(*format_all)(ni_syntax_t *, ni_handle_t *, FILE *);
	int			(*format_interface)(ni_syntax_t *, ni_handle_t *, ni_interface_t *, FILE *);

	xml_node_t *		(*xml_from_interface)(ni_syntax_t *, ni_handle_t *, const ni_interface_t *,
						xml_node_t *parent);
	ni_interface_t *	(*xml_to_interface)(ni_syntax_t *, ni_handle_t *, xml_node_t *);

	xml_node_t *		(*xml_from_lease)(ni_syntax_t *, const ni_addrconf_state_t *, xml_node_t *parent);
	ni_addrconf_state_t *	(*xml_to_lease)(ni_syntax_t *, const xml_node_t *);
};

extern ni_handle_t *	__ni_handle_new(size_t, struct ni_ops *);
extern ni_interface_t *	__ni_interface_new(const char *name, unsigned int index);
extern void		__ni_interface_list_destroy(ni_interface_t **);
extern void		__ni_interface_clear_routes(ni_interface_t *);
extern void		__ni_interface_clear_addresses(ni_interface_t *);
extern void		__ni_interface_clear_stats(ni_interface_t *);
extern void		__ni_interfaces_clear(ni_handle_t *);
extern ni_addrconf_state_t *__ni_interface_address_to_lease(ni_interface_t *, const ni_address_t *);
extern ni_addrconf_state_t *__ni_interface_route_to_lease(ni_interface_t *, const ni_route_t *);

static inline ni_afinfo_t *
__ni_interface_address_info(ni_interface_t *ifp, int af)
{
	if (af == AF_INET)
		return &ifp->ipv4;
	if (af == AF_INET6)
		return &ifp->ipv6;
	return NULL;
}

extern ni_route_t *	__ni_route_new(ni_route_t **, unsigned int prefix_len,
				const struct sockaddr_storage *,
				const struct sockaddr_storage *);
extern ni_route_t *	__ni_route_list_clone(const ni_route_t *);
extern void		__ni_route_list_destroy(ni_route_t **);
extern void		__ni_routes_clear(ni_handle_t *);

extern ni_address_t *	__ni_address_new(ni_address_t **, int, unsigned int,
				const struct sockaddr_storage *);

extern int		__ni_system_refresh_all(ni_handle_t *);
extern int		__ni_system_refresh_interface(ni_handle_t *, ni_interface_t *);
extern int		__ni_system_interface_configure(ni_handle_t *, ni_interface_t *, xml_node_t *);
extern int		__ni_system_interface_delete(ni_handle_t *, const char *);
extern int		__ni_system_interface_update_lease(ni_handle_t *, ni_interface_t *, ni_addrconf_state_t *);
extern int		__ni_rtevent_refresh_all(ni_handle_t *);

extern int		__ni_syntax_xml_to_all(ni_syntax_t *, ni_handle_t *, const xml_node_t *);
extern ni_syntax_t *	__ni_syntax_sysconfig_suse(const char *pathname);
extern ni_syntax_t *	__ni_syntax_sysconfig_redhat(const char *pathname);
extern ni_syntax_t *	__ni_syntax_netcf(const char *pathname);
extern ni_syntax_t *	__ni_syntax_netcf_strict(const char *pathname);

extern ni_address_t *	__ni_address_list_clone(const ni_address_t *);

extern ni_address_t *	__ni_lease_owns_address(const ni_addrconf_state_t *, const ni_address_t *);
extern ni_route_t *	__ni_lease_owns_route(const ni_addrconf_state_t *, const ni_route_t *);

/*
 * Helper function to do strcmp with NULL pointer check
 */
static inline int
xstreq(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return a == b;
	return strcmp(a, b) == 0;
}

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
