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


#define NI_ROUTE_ARRAY_INIT	{ .count = 0, .data = NULL }


typedef struct ni_route_nexthop {
	struct ni_route_nexthop *next;
	ni_sockaddr_t		gateway;
	ni_netdev_ref_t		device;
	unsigned int		weight;
	unsigned int		flags;
	unsigned int		realm;
} ni_route_nexthop_t;

struct ni_route {
	unsigned int		users;

	ni_addrconf_mode_t	owner;		/* configured through lease */
	unsigned int		seq;

	unsigned int		family;
	unsigned int		prefixlen;
	ni_sockaddr_t		destination;
/*	ni_sockaddr_t		from_src;	*/	/* RTA_SRC, unsupported */
	ni_sockaddr_t		pref_src;
	unsigned int		priority;
	unsigned int		flags;
	unsigned int		realm;
	unsigned int		mark;
	unsigned int		tos;
	ni_route_nexthop_t	nh;

	unsigned int		table;			/* RT_TABLE_* */
	unsigned int		type;			/* RTN_* */
	unsigned int		scope;			/* RT_SCOPE_* */
	unsigned int		protocol;		/* RTPROT_* */

	unsigned int		lock;
	unsigned int		mtu;
	unsigned int		rtt;
	unsigned int		rttvar;
	unsigned int		window;
	unsigned int		cwnd;
	unsigned int		initcwnd;
	unsigned int		initrwnd;
	unsigned int		ssthresh;
	unsigned int		advmss;
	unsigned int		rto_min;
	unsigned int		hoplimit;
	unsigned int		features;
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
	ni_route_array_t	routes;
};


extern ni_route_t *		ni_route_new(void);
extern ni_route_t *		ni_route_create(unsigned int prefix_len,
						const ni_sockaddr_t *dest,
						const ni_sockaddr_t *gw,
						unsigned int table,
						ni_route_table_t **list);
extern ni_route_t *		ni_route_clone(const ni_route_t *);
extern ni_route_t *		ni_route_ref(ni_route_t *);
extern void			ni_route_free(ni_route_t *);
extern ni_bool_t		ni_route_equal(const ni_route_t *, const ni_route_t *);
extern ni_bool_t		ni_route_equal_gateways(const ni_route_t *, const ni_route_t *);
extern ni_bool_t		ni_route_equal_destination(const ni_route_t *, const ni_route_t *);
extern const char *		ni_route_print(ni_stringbuf_t *, const ni_route_t *);

extern const char *		ni_route_type_type_to_name(unsigned int);
extern const char *		ni_route_table_type_to_name(unsigned int, char **);
extern const char *		ni_route_scope_type_to_name(unsigned int);
extern const char *		ni_route_protocol_type_to_name(unsigned int);
extern const char *		ni_route_flag_bit_to_name(unsigned int);
extern const char *		ni_route_nh_flag_bit_to_name(unsigned int);
extern const char *		ni_route_metrics_lock_bit_to_name(unsigned int);

extern ni_bool_t		ni_route_type_name_to_type(const char *, unsigned int *);
extern ni_bool_t		ni_route_table_name_to_type(const char *, unsigned int *);
extern ni_bool_t		ni_route_scope_name_to_type(const char *, unsigned int *);
extern ni_bool_t		ni_route_protocol_name_to_type(const char *, unsigned int *);
extern ni_bool_t		ni_route_flags_get_names(unsigned int, ni_string_array_t *);
extern ni_bool_t		ni_route_nh_flags_get_names(unsigned int, ni_string_array_t *);
extern ni_bool_t		ni_route_metrics_lock_get_names(unsigned int, ni_string_array_t *);
extern ni_bool_t		ni_route_metrics_lock_set(const char *, unsigned int *);
extern ni_bool_t		ni_route_type_needs_nexthop(unsigned int);
extern ni_bool_t		ni_route_is_valid_type(unsigned int);
extern ni_bool_t		ni_route_is_valid_table(unsigned int);
extern ni_bool_t		ni_route_is_valid_scope(unsigned int);
extern ni_bool_t		ni_route_is_valid_protocol(unsigned int);
extern unsigned int		ni_route_guess_table(ni_route_t *);
extern unsigned int		ni_route_guess_scope(ni_route_t *);

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
extern ni_route_t *		ni_route_array_ref(ni_route_array_t *, unsigned int);
extern ni_route_t *		ni_route_array_find_match(ni_route_array_t *, const ni_route_t *,
				ni_bool_t (*match)(const ni_route_t *, const ni_route_t *));

extern ni_route_table_t *	ni_route_table_new(unsigned int);
extern void			ni_route_table_free(ni_route_table_t *);
extern void			ni_route_table_clear(ni_route_table_t *);

extern ni_bool_t		ni_route_tables_add_route(ni_route_table_t **, ni_route_t *);
extern ni_bool_t		ni_route_tables_add_routes(ni_route_table_t **, ni_route_array_t *);

extern ni_route_t *		ni_route_tables_find_match(ni_route_table_t *, const ni_route_t *,
				ni_bool_t (*match)(const ni_route_t *, const ni_route_t *));

extern ni_route_table_t *	ni_route_tables_find(ni_route_table_t *, unsigned int);
extern ni_route_table_t *	ni_route_tables_get(ni_route_table_t **, unsigned int);
extern void			ni_route_tables_destroy(ni_route_table_t **);

#endif /* __WICKED_ROUTE_H__ */
