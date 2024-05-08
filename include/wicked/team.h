/*
 *	Team network interface support
 *
 *	Copyright (C) 2015-2023 SUSE LLC
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
 *      along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef NI_WICKED_TEAM_H
#define NI_WICKED_TEAM_H

#include <wicked/array.h>

/*
 * runner
 */
typedef enum {
	NI_TEAM_RUNNER_ROUND_ROBIN = 0,
	NI_TEAM_RUNNER_ACTIVE_BACKUP,
	NI_TEAM_RUNNER_LOAD_BALANCE,
	NI_TEAM_RUNNER_BROADCAST,
	NI_TEAM_RUNNER_RANDOM,
	NI_TEAM_RUNNER_LACP,
} ni_team_runner_type_t;

/*
 * tx hash and balancer
 */
typedef enum {
	NI_TEAM_TX_HASH_NONE = 0,
	NI_TEAM_TX_HASH_ETH,
	NI_TEAM_TX_HASH_VLAN,
	NI_TEAM_TX_HASH_IPV4,
	NI_TEAM_TX_HASH_IPV6,
	NI_TEAM_TX_HASH_IP,
	NI_TEAM_TX_HASH_L3,
	NI_TEAM_TX_HASH_TCP,
	NI_TEAM_TX_HASH_UDP,
	NI_TEAM_TX_HASH_SCTP,
	NI_TEAM_TX_HASH_L4,
} ni_team_tx_hash_bit_t;

typedef enum {
	NI_TEAM_TX_BALANCER_BASIC = 0,
} ni_team_tx_balancer_type_t;

typedef struct ni_team_tx_balancer {
	ni_team_tx_balancer_type_t		type;
	/* currently, there is a basic only */
	unsigned int				interval;
} ni_team_tx_balancer_t;

/*
 * lacp runner
 */
typedef enum {
	NI_TEAM_LACP_SELECT_POLICY_PRIO = 0,
	NI_TEAM_LACP_SELECT_POLICY_PRIO_STABLE,
	NI_TEAM_LACP_SELECT_POLICY_BANDWIDTH,
	NI_TEAM_LACP_SELECT_POLICY_COUNT,
	NI_TEAM_LACP_SELECT_POLICY_PORT_CONFIG,
} ni_team_lacp_select_policy_t;

typedef struct ni_team_lacp {
	ni_bool_t				active;
	unsigned int				sys_prio;
	ni_bool_t				fast_rate;
	unsigned int				min_ports;
	ni_team_lacp_select_policy_t		select_policy;
	ni_team_tx_hash_bit_t			tx_hash; /* bitmap */
	ni_team_tx_balancer_t			tx_balancer;
} ni_team_lacp_t;

typedef struct ni_team_runner_lacp {
	ni_team_lacp_t				config;
} ni_team_runner_lacp_t;

/*
 * lb runner
 */
typedef struct ni_team_load_balance {
	ni_team_tx_hash_bit_t			tx_hash; /* bitmap */
	ni_team_tx_balancer_t			tx_balancer;
} ni_team_load_balance_t;

typedef struct ni_team_runner_load_balance {
	ni_team_load_balance_t			config;
} ni_team_runner_load_balance_t;

/*
 * ab runner
 */
typedef enum {
	NI_TEAM_AB_HWADDR_POLICY_SAME_ALL = 0,
	NI_TEAM_AB_HWADDR_POLICY_BY_ACTIVE,
	NI_TEAM_AB_HWADDR_POLICY_ONLY_ACTIVE,
} ni_team_ab_hwaddr_policy_t;

typedef struct ni_team_active_backup {
	ni_team_ab_hwaddr_policy_t		hwaddr_policy;
} ni_team_active_backup_t;

typedef struct ni_team_runner_active_backup {
	ni_team_active_backup_t			config;
} ni_team_runner_active_backup_t;

/*
 * runner type union
 */
typedef struct ni_team_runner {
	ni_team_runner_type_t			type;

	union {
		ni_team_runner_active_backup_t	ab;
		ni_team_runner_load_balance_t	lb;
		ni_team_runner_lacp_t		lacp;
	};
} ni_team_runner_t;

/*
 * link watch type
 */
typedef enum {
	NI_TEAM_LINK_WATCH_ETHTOOL = 0,
	NI_TEAM_LINK_WATCH_ARP_PING,
	NI_TEAM_LINK_WATCH_NSNA_PING,
	NI_TEAM_LINK_WATCH_TIPC,
} ni_team_link_watch_type_t;

/*
 * link watch type structs
 */
typedef struct ni_team_link_watch_arp {
	char *					source_host;
	char *					target_host;

	unsigned int				interval;
	unsigned int				init_wait;
	ni_bool_t				validate_active;
	ni_bool_t				validate_inactive;
	ni_bool_t				send_always;
	unsigned int				missed_max;
	uint16_t				vlanid;
} ni_team_link_watch_arp_t;

typedef struct ni_team_link_watch_tipc {
	char *					bearer;
} ni_team_link_watch_tipc_t;

typedef struct ni_team_link_watch_nsna {
	char *					target_host;

	unsigned int				interval;
	unsigned int				init_wait;
	unsigned int				missed_max;
} ni_team_link_watch_nsna_t;

typedef struct ni_team_link_watch_ethtool {
	unsigned int				delay_up;
	unsigned int				delay_down;
} ni_team_link_watch_ethtool_t;

/*
 * link watch type union
 */
typedef struct ni_team_link_watch {
	ni_team_link_watch_type_t		type;

	union {
		ni_team_link_watch_arp_t	arp;
		ni_team_link_watch_tipc_t	tipc;
		ni_team_link_watch_nsna_t	nsna;
		ni_team_link_watch_ethtool_t	ethtool; /* default */
	};
} ni_team_link_watch_t;

ni_declare_ptr_array_type(ni_team_link_watch);

/*
 * team port config
 */
typedef struct ni_team_port_active_backup {
	unsigned int				prio;
	ni_bool_t				sticky;
} ni_team_port_active_backup_t;

typedef struct ni_team_port_lacp {
	unsigned int				prio;
	unsigned int				key;
} ni_team_port_lacp_t;

/*
 * team port (link-request) configuration
 */
struct ni_team_port_config {
	unsigned int				queue_id;

	ni_team_port_active_backup_t		ab;
	ni_team_port_lacp_t			lacp;
};

/*
 * team port interface info properties
 */
typedef struct ni_team_port_runner_lacp_info	ni_team_port_runner_lacp_info_t;
typedef struct ni_team_port_runner_info		ni_team_port_runner_info_t;
typedef struct ni_team_port_link_watches_info	ni_team_port_link_watches_info_t;

struct ni_team_port_runner_lacp_info {
	struct {
		unsigned int			id;
	} aggregator;
	ni_bool_t				selected;
	char *					state;
};
struct ni_team_port_runner_info {
	ni_team_runner_type_t			type;
	union {
		ni_team_port_runner_lacp_info_t	lacp;
	};
};
struct ni_team_port_link_watches_info {
	ni_bool_t				up;
};

struct ni_team_port_info {
	ni_team_port_runner_info_t		runner;
	ni_team_port_link_watches_info_t	watches;
};

/*
 * team interface
 */
typedef enum {
	NI_TEAM_LINK_WATCH_POLICY_ANY = 0U,
	NI_TEAM_LINK_WATCH_POLICY_ALL = 1,
} ni_team_link_watch_policy_t;

typedef struct ni_team_notify_peers {
	unsigned int				count;
	unsigned int				interval;
} ni_team_notify_peers_t;

typedef struct ni_team_mcast_rejoin {
	unsigned int				count;
	unsigned int				interval;
} ni_team_mcast_rejoin_t;

struct ni_team {
	unsigned int				debug_level;
	ni_team_notify_peers_t			notify_peers;
	ni_team_mcast_rejoin_t			mcast_rejoin;
	ni_team_runner_t			runner;
	ni_team_link_watch_policy_t		link_watch_policy;
	ni_team_link_watch_array_t		link_watch;
};

extern ni_team_t *				ni_team_new();
extern void					ni_team_free(ni_team_t *);

extern void					ni_team_runner_init(ni_team_runner_t *, ni_team_runner_type_t);
extern void					ni_team_runner_destroy(ni_team_runner_t *);

extern const char *				ni_team_runner_type_to_name(ni_team_runner_type_t);
extern ni_bool_t				ni_team_runner_name_to_type(const char *, ni_team_runner_type_t *);

extern const char *				ni_team_tx_hash_bit_to_name(ni_team_tx_hash_bit_t);
extern ni_bool_t				ni_team_tx_hash_name_to_bit(const char *, ni_team_tx_hash_bit_t *);
extern unsigned int				ni_team_tx_hash_get_bit_names(ni_team_tx_hash_bit_t,
								ni_string_array_t *);
extern const char *				ni_team_tx_balancer_type_to_name(ni_team_tx_balancer_type_t);
extern ni_bool_t				ni_team_tx_balancer_name_to_type(const char *,
								ni_team_tx_balancer_type_t *);

extern const char *				ni_team_lacp_select_policy_type_to_name(ni_team_lacp_select_policy_t);
extern ni_bool_t				ni_team_lacp_select_policy_name_to_type(const char *,
								ni_team_lacp_select_policy_t *);

extern const char *				ni_team_ab_hwaddr_policy_type_to_name(ni_team_ab_hwaddr_policy_t);
extern ni_bool_t				ni_team_ab_hwaddr_policy_name_to_type(const char *,
								ni_team_ab_hwaddr_policy_t *);

extern const char *				ni_team_link_watch_type_to_name(ni_team_link_watch_type_t);
extern ni_bool_t				ni_team_link_watch_name_to_type(const char *,
								ni_team_link_watch_type_t *);

extern const char *				ni_team_link_watch_policy_type_to_name(ni_team_link_watch_policy_t);
extern ni_bool_t				ni_team_link_watch_policy_name_to_type(const char *,
								ni_team_link_watch_policy_t *);

extern ni_team_link_watch_t *			ni_team_link_watch_new(ni_team_link_watch_type_t);
extern void					ni_team_link_watch_free(ni_team_link_watch_t *);
extern						ni_declare_ptr_array_append(ni_team_link_watch);
extern						ni_declare_ptr_array_delete_at(ni_team_link_watch);

extern ni_team_port_config_t *			ni_team_port_config_new(void);
extern ni_bool_t				ni_team_port_config_init(ni_team_port_config_t *);
extern void					ni_team_port_config_destroy(ni_team_port_config_t *);
extern void					ni_team_port_config_free(ni_team_port_config_t *);

extern ni_team_port_info_t *			ni_team_port_info_new(void);
extern void					ni_team_port_info_free(ni_team_port_info_t *);

#endif /* NI_WICKED_TEAM_H */
