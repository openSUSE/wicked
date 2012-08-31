/*
 * Header file for netinfo library; describe routing information
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_ROUTE_H__
#define __WICKED_ROUTE_H__

#include <sys/socket.h>
#include <stdio.h>
#include <net/if.h>
#include <netinet/in.h>

#include <wicked/types.h>
#include <wicked/constants.h>
#include <wicked/util.h>

typedef struct ni_route_nexthop {
	struct ni_route_nexthop *next;
	ni_sockaddr_t		gateway;
	char *                  device;
	unsigned int		weight;
	unsigned int		flags;
} ni_route_nexthop_t;

struct ni_route {
	struct ni_route *	next;

	const ni_addrconf_lease_t *config_lease;	/* configured through lease */

	unsigned int		seq;
	unsigned int		family;
	unsigned int		prefixlen;
	ni_sockaddr_t		destination;
	ni_route_nexthop_t	nh;

	int			type;			/* RTN_* */
	int			scope;			/* RT_SCOPE_* */
	int			protocol;		/* RTPROT_* */
	int			table;			/* RT_TABLE_* */
	unsigned int		tos;
	unsigned int		metric;

	unsigned int		mtu;
	unsigned int		priority;
	unsigned int		advmss;
	unsigned int		rtt;
	unsigned int		rttvar;
	unsigned int		window;
	unsigned int		cwnd;
	unsigned int		initcwnd;
	unsigned int		ssthresh;
	unsigned int		realms;
	unsigned int		rto_min;
	unsigned int		hoplimit;

	ni_ipv6_cache_info_t	ipv6_cache_info;
};


extern ni_route_t *	ni_route_new(unsigned int prefix_len,
				const ni_sockaddr_t *dest,
				const ni_sockaddr_t *gw,
				ni_route_t **list);
extern ni_route_t *	ni_route_clone(const ni_route_t *);
extern void		ni_route_list_append(ni_route_t **, ni_route_t *);
extern void		ni_route_list_destroy(ni_route_t **);
extern void		ni_route_free(ni_route_t *);
extern ni_bool_t	ni_route_equal(const ni_route_t *, const ni_route_t *);
extern const char *	ni_route_print(const ni_route_t *);

extern int		ni_route_type_name_to_type(const char *);
extern const char *	ni_route_type_type_to_name(unsigned int);
extern int		ni_route_table_name_to_type(const char *);
extern const char *	ni_route_table_type_to_name(unsigned int);
extern int		ni_route_protocol_name_to_type(const char *);
extern const char *	ni_route_protocol_type_to_name(unsigned int);
extern int		ni_route_scope_name_to_type(const char *);
extern const char *	ni_route_scope_type_to_name(unsigned int);

#endif /* __WICKED_ROUTE_H__ */
