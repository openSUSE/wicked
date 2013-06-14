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


#define NI_ROUTE_ARRAY_INIT    { .count = 0, .data = 0 }


typedef struct ni_route_nexthop {
	struct ni_route_nexthop *next;
	ni_sockaddr_t		gateway;
	ni_netdev_ref_t		device;
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
	ni_sockaddr_t		source;
	ni_route_nexthop_t	nh;

	unsigned int		type;			/* RTN_* */
	unsigned int		scope;			/* RT_SCOPE_* */
	unsigned int		protocol;		/* RTPROT_* */
	unsigned int		table;			/* RT_TABLE_* */
	unsigned int		tos;
	unsigned int		priority;

	unsigned int		mtu;
	ni_bool_t		mtu_lock;
	unsigned int		advmss;
	unsigned int		rtt;
	unsigned int		rttvar;
	unsigned int		window;
	unsigned int		cwnd;
	unsigned int		initcwnd;
	unsigned int		initrwnd;
	unsigned int		ssthresh;
	unsigned int		realm;
	unsigned int		rto_min;
	unsigned int		hoplimit;
	unsigned int		reordering;

	ni_ipv6_cache_info_t	ipv6_cache_info;
};

typedef struct ni_route_array  ni_route_array_t;

struct ni_route_array {
	unsigned int		count;
	ni_route_t **		data;
};

struct ni_route_table {
	ni_route_table_t *	next;

	unsigned int		tid;
	unsigned int		count;
	ni_route_t **		routes;
};


extern ni_route_t *		ni_route_new(void);
extern ni_route_t *		ni_route_create(unsigned int prefix_len,
						const ni_sockaddr_t *dest,
						const ni_sockaddr_t *gw,
						ni_route_t **list);
extern ni_route_t *		ni_route_clone(const ni_route_t *);
extern void			ni_route_free(ni_route_t *);
extern ni_bool_t		ni_route_equal(const ni_route_t *, const ni_route_t *);
extern const char *		ni_route_print(ni_stringbuf_t *, const ni_route_t *);

extern int			ni_route_type_name_to_type(const char *);
extern const char *		ni_route_type_type_to_name(unsigned int);
extern int			ni_route_table_name_to_type(const char *);
extern const char *		ni_route_table_type_to_name(unsigned int);
extern int			ni_route_protocol_name_to_type(const char *);
extern const char *		ni_route_protocol_type_to_name(unsigned int);
extern int			ni_route_scope_name_to_type(const char *);
extern const char *		ni_route_scope_type_to_name(unsigned int);

extern void			ni_route_list_append(ni_route_t **, ni_route_t *);
extern void			ni_route_list_destroy(ni_route_t **);


extern ni_route_nexthop_t *	ni_route_nexthop_new(void);
extern void			ni_route_nexthop_copy(ni_route_nexthop_t *, const ni_route_nexthop_t *);
extern void			ni_route_nexthop_free(ni_route_nexthop_t *);
extern void			ni_route_nexthop_destroy(ni_route_nexthop_t *);

extern void			ni_route_nexthop_list_append(ni_route_nexthop_t **, ni_route_nexthop_t*);
extern void			ni_route_nexthop_list_destroy(ni_route_nexthop_t **);


extern ni_route_array_t *	ni_route_array_new(void);
extern void			ni_route_array_free(ni_route_array_t *);
extern void			ni_route_array_init(ni_route_array_t *);
extern void			ni_route_array_destroy(ni_route_array_t *);
extern ni_bool_t		ni_route_array_append(ni_route_array_t *, ni_route_t *);
extern ni_bool_t		ni_route_array_delete(ni_route_array_t *, unsigned int);
extern ni_route_t *		ni_route_array_remove(ni_route_array_t *, unsigned int);
extern ni_route_t *		ni_route_array_get(ni_route_array_t *, unsigned int);


extern ni_route_table_t *	ni_route_table_new(unsigned int);
extern void			ni_route_table_free(ni_route_table_t *);

extern void			ni_route_table_clear(ni_route_table_t *);
extern ni_bool_t		ni_route_table_add_route(ni_route_table_t *, ni_route_t *);
extern ni_bool_t		ni_route_table_del_route(ni_route_table_t *, unsigned int);

extern ni_route_table_t *	ni_route_table_list_get(ni_route_table_t **, unsigned int);
extern ni_route_table_t *	ni_route_table_list_find(ni_route_table_t **, unsigned int);
extern void			ni_route_table_list_destroy(ni_route_table_t **);

#endif /* __WICKED_ROUTE_H__ */
