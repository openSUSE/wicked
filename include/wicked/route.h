/*
 *	Handling of IP routing information
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2016 SUSE LINUX GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Olaf Kirch <okir@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifndef WICKED_ROUTE_H
#define WICKED_ROUTE_H

#include <sys/socket.h>
#include <stdio.h>
#include <net/if.h>
#include <netinet/in.h>

#include <wicked/types.h>
#include <wicked/constants.h>
#include <wicked/util.h>


#define NI_ROUTE_ARRAY_INIT	{ .count = 0, .data = NULL }
#define NI_RULE_ARRAY_INIT	{ .count = 0, .data = NULL }


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

typedef struct ni_route_array	ni_route_array_t;

struct ni_route_array {
	unsigned int		count;
	ni_route_t **		data;
};

struct ni_route_table {
	ni_route_table_t *	next;

	unsigned int		tid;
	ni_route_array_t	routes;
};

enum {
	/* bit numbers */
	NI_RULE_PERMANENT		= 0U,
	NI_RULE_INVERT,
	NI_RULE_UNRESOLVED,
	NI_RULE_IIF_DETACHED,
	NI_RULE_OIF_DETACHED,
};

enum {
	NI_RULE_ACTION_NONE		= 0U,
	NI_RULE_ACTION_TO_TBL		= 1U,
	NI_RULE_ACTION_GOTO		= 2U,
	NI_RULE_ACTION_NOP		= 3U,
	/* reserved */
	NI_RULE_ACTION_BLACKHOLE	= 6U,
	NI_RULE_ACTION_UNREACHABLE	= 7U,
	NI_RULE_ACTION_PROHIBIT		= 8U,
};

enum {
	/* attr is set flags */
	NI_RULE_SET_PREF		= NI_BIT(0),
};

typedef struct ni_rule_prefix {
	unsigned int		len;
	ni_sockaddr_t		addr;
} ni_rule_prefix_t;

struct ni_rule {
	unsigned int		refcount;

	ni_uuid_t		owner;		/* configured through lease */
	unsigned int		seq;
	unsigned int		set;

	unsigned int		family;
	unsigned int		flags;
	unsigned int		pref;		/* priority alias preference */
	unsigned int		table;
	unsigned int		action;
	unsigned int		target;

	ni_rule_prefix_t	src;
	ni_rule_prefix_t	dst;
	ni_netdev_ref_t		iif;
	ni_netdev_ref_t		oif;

	unsigned int		tos;
	unsigned int		realm;
	unsigned int		fwmark;
	unsigned int		fwmask;
	unsigned int		suppress_prefixlen;
	unsigned int		suppress_ifgroup;
};

typedef struct ni_rule_array  {
	unsigned int		count;
	ni_rule_t **		data;
} ni_rule_array_t;


typedef int			ni_route_cmp_fn(const ni_route_t *, const ni_route_t *);

extern ni_route_t *		ni_route_new(void);
extern ni_route_t *		ni_route_create(unsigned int prefix_len,
						const ni_sockaddr_t *dest,
						const ni_sockaddr_t *gw,
						unsigned int table,
						ni_route_table_t **list);
extern ni_route_t *		ni_route_clone(const ni_route_t *);
extern ni_route_t *		ni_route_ref(ni_route_t *);
extern void			ni_route_free(ni_route_t *);
extern ni_bool_t		ni_route_copy(ni_route_t *, const ni_route_t *);
extern ni_bool_t		ni_route_equal(const ni_route_t *, const ni_route_t *);
extern ni_bool_t		ni_route_equal_ref(const ni_route_t *, const ni_route_t *);
extern ni_bool_t		ni_route_equal_hops(const ni_route_t *, const ni_route_t *);
extern ni_bool_t		ni_route_equal_options(const ni_route_t *, const ni_route_t *);
extern ni_bool_t		ni_route_equal_gateways(const ni_route_t *, const ni_route_t *);
extern ni_bool_t		ni_route_equal_pref_source(const ni_route_t *, const ni_route_t *);
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
extern ni_bool_t		ni_route_is_multipath(const ni_route_t *);
extern ni_bool_t		ni_route_via_gateway(const ni_route_t *);
extern ni_bool_t		ni_route_contains_hop(const ni_route_t *, const ni_route_nexthop_t *);
extern ni_bool_t		ni_route_contains_hops(const ni_route_t *, const ni_route_nexthop_t *);
extern unsigned int		ni_route_guess_table(ni_route_t *);
extern unsigned int		ni_route_guess_scope(ni_route_t *);

extern ni_bool_t		ni_route_update(ni_route_t *, const ni_route_t *);
extern ni_bool_t		ni_route_update_options(ni_route_t *, const ni_route_t *);

extern ni_bool_t		ni_route_replace_hops(ni_route_t *, const ni_route_nexthop_t *);
extern unsigned int		ni_route_expand_hops(ni_route_array_t *, const ni_route_t *);

extern ni_route_t *		ni_route_squash_hops(const ni_route_array_t *, const ni_route_t *);
extern ni_route_t *		ni_route_drop_ifindex_hops(const ni_route_t *, unsigned int);

extern void			ni_route_bind_ifname(ni_route_t *, ni_netconfig_t *, ni_netdev_t *);
extern void			ni_route_bind_ifindex(ni_route_t *, ni_netconfig_t *, ni_netdev_t *, unsigned int);

extern ni_route_nexthop_t *	ni_route_nexthop_new(void);
extern ni_bool_t		ni_route_nexthop_copy(ni_route_nexthop_t *, const ni_route_nexthop_t *);
extern void			ni_route_nexthop_free(ni_route_nexthop_t *);
extern void			ni_route_nexthop_destroy(ni_route_nexthop_t *);
extern ni_bool_t		ni_route_nexthop_empty(const ni_route_nexthop_t *);
extern ni_bool_t		ni_route_nexthop_equal(const ni_route_nexthop_t *,const  ni_route_nexthop_t *);
extern ni_bool_t		ni_route_nexthop_equal_device(const ni_route_nexthop_t *, const  ni_route_nexthop_t *);
extern ni_bool_t		ni_route_nexthop_equal_gateway(const ni_route_nexthop_t *,const  ni_route_nexthop_t *);
extern ni_bool_t		ni_route_nexthop_bound(const ni_route_nexthop_t *);
extern void			ni_route_nexthop_bind_ifname(ni_route_nexthop_t *, ni_netconfig_t *, ni_netdev_t *);
extern void			ni_route_nexthop_bind_ifindex(ni_route_nexthop_t *, ni_netconfig_t *, ni_netdev_t *, unsigned int);

extern void			ni_route_nexthop_list_append(ni_route_nexthop_t **, ni_route_nexthop_t*);
extern void			ni_route_nexthop_list_destroy(ni_route_nexthop_t **);
extern const ni_route_nexthop_t *	ni_route_nexthop_find_by_ifname(const ni_route_nexthop_t *, const char *);
extern const ni_route_nexthop_t *	ni_route_nexthop_find_by_ifindex(const ni_route_nexthop_t *, unsigned int);
extern const ni_route_nexthop_t *	ni_route_nexthop_find_by_device(const ni_route_nexthop_t *, const ni_netdev_ref_t *);
extern const ni_route_nexthop_t *	ni_route_nexthop_find_by_gateway(const ni_route_nexthop_t *, const ni_sockaddr_t *);

extern ni_route_array_t *	ni_route_array_new(void);
extern void			ni_route_array_free(ni_route_array_t *);
extern void			ni_route_array_init(ni_route_array_t *);
extern void			ni_route_array_destroy(ni_route_array_t *);
extern ni_bool_t		ni_route_array_append(ni_route_array_t *, ni_route_t *);
extern ni_bool_t		ni_route_array_delete_ref(ni_route_array_t *, const ni_route_t *);
extern ni_bool_t		ni_route_array_delete(ni_route_array_t *, unsigned int);
extern ni_route_t *		ni_route_array_remove_ref(ni_route_array_t *, const ni_route_t *);
extern ni_route_t *		ni_route_array_remove(ni_route_array_t *, unsigned int);
extern ni_route_t *		ni_route_array_get(ni_route_array_t *, unsigned int);
extern ni_route_t *		ni_route_array_ref(ni_route_array_t *, unsigned int);
extern ni_route_t *		ni_route_array_find_match(ni_route_array_t *, const ni_route_t *,
					ni_bool_t (*match)(const ni_route_t *, const ni_route_t *));
extern unsigned int		ni_route_array_find_matches(ni_route_array_t *, const ni_route_t *,
					ni_bool_t (*match)(const ni_route_t *, const ni_route_t *),
					ni_route_array_t *);
extern void			ni_route_array_qsort(ni_route_array_t *, ni_route_cmp_fn *);
extern void			ni_route_array_sort(ni_route_array_t *);
extern void			ni_route_array_sort_rev(ni_route_array_t *);

extern ni_route_table_t *	ni_route_table_new(unsigned int);
extern void			ni_route_table_free(ni_route_table_t *);
extern void			ni_route_table_clear(ni_route_table_t *);

extern ni_bool_t		ni_route_tables_add_route(ni_route_table_t **, ni_route_t *);
extern ni_bool_t		ni_route_tables_add_routes(ni_route_table_t **, ni_route_array_t *);

extern ni_bool_t		ni_route_tables_del_route(ni_route_table_t *, ni_route_t *);

extern ni_route_t *		ni_route_tables_find_match(ni_route_table_t *, const ni_route_t *,
					ni_bool_t (*match)(const ni_route_t *, const ni_route_t *));
extern unsigned int		ni_route_tables_find_matches(ni_route_table_t *, const ni_route_t *,
					ni_bool_t (*match)(const ni_route_t *, const ni_route_t *),
					ni_route_array_t *);

extern ni_route_table_t *	ni_route_tables_find(ni_route_table_t *, unsigned int);
extern ni_bool_t		ni_route_tables_empty(const ni_route_table_t *);
extern ni_route_table_t *	ni_route_tables_get(ni_route_table_t **, unsigned int);
extern void			ni_route_tables_destroy(ni_route_table_t **);

extern ni_rule_t *		ni_rule_new(void);
extern ni_rule_t *		ni_rule_ref(ni_rule_t *);
extern ni_bool_t		ni_rule_copy(ni_rule_t *, const ni_rule_t *);
extern ni_rule_t *		ni_rule_clone(const ni_rule_t *);
extern void			ni_rule_free(ni_rule_t *);
extern ni_bool_t		ni_rule_equal(const ni_rule_t *, const ni_rule_t *);
extern ni_bool_t		ni_rule_equal_ref(const ni_rule_t *, const ni_rule_t *);
extern ni_bool_t		ni_rule_equal_match(const ni_rule_t *, const ni_rule_t *);
extern ni_bool_t		ni_rule_equal_action(const ni_rule_t *, const ni_rule_t *);
extern const char *		ni_rule_print(ni_stringbuf_t *, const ni_rule_t *);
extern const char *		ni_rule_action_type_to_name(unsigned int);
extern ni_bool_t		ni_rule_action_name_to_type(const char *, unsigned int *);

extern ni_rule_array_t *	ni_rule_array_new(void);
extern void			ni_rule_array_free(ni_rule_array_t *);
extern void			ni_rule_array_init(ni_rule_array_t *);
extern void			ni_rule_array_destroy(ni_rule_array_t *);
extern unsigned int		ni_rule_array_index(const ni_rule_array_t *, const ni_rule_t *);
extern ni_bool_t		ni_rule_array_append(ni_rule_array_t *, ni_rule_t *);
extern ni_bool_t		ni_rule_array_insert(ni_rule_array_t *, unsigned int, ni_rule_t *);
extern ni_bool_t		ni_rule_array_delete(ni_rule_array_t *, unsigned int);
extern ni_rule_t *		ni_rule_array_remove(ni_rule_array_t *, unsigned int);
extern ni_rule_t *		ni_rule_array_get(ni_rule_array_t *, unsigned int);
extern ni_rule_t *		ni_rule_array_find_match(const ni_rule_array_t *, const ni_rule_t *,
					ni_bool_t (*match)(const ni_rule_t *, const ni_rule_t *));
extern unsigned int		ni_rule_array_find_matches(const ni_rule_array_t *, const ni_rule_t *,
					ni_bool_t (*match)(const ni_rule_t *, const ni_rule_t *),
					ni_rule_array_t *);

#endif /* WICKED_ROUTE_H */
