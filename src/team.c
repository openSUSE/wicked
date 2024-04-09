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
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <wicked/util.h>
#include <wicked/netinfo.h>
#include <wicked/team.h>
#include "util_priv.h"
#include "array_priv.h"

#define NI_TEAM_LINK_WATCH_ARRAY_CHUNK		4

/*
 * Map teamd mode names to constants
 */
static const ni_intmap_t	ni_team_runner_names[] = {
	{ "roundrobin",		NI_TEAM_RUNNER_ROUND_ROBIN	},
	{ "activebackup",	NI_TEAM_RUNNER_ACTIVE_BACKUP	},
	{ "loadbalance",	NI_TEAM_RUNNER_LOAD_BALANCE	},
	{ "broadcast",		NI_TEAM_RUNNER_BROADCAST	},
	{ "random",		NI_TEAM_RUNNER_RANDOM		},
	{ "lacp",		NI_TEAM_RUNNER_LACP		},

	{ NULL,			-1U				}
};

const char *
ni_team_runner_type_to_name(ni_team_runner_type_t type)
{
	return ni_format_uint_mapped(type, ni_team_runner_names);
}

ni_bool_t
ni_team_runner_name_to_type(const char *name, ni_team_runner_type_t *type)
{
	unsigned int _type;

	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, ni_team_runner_names, &_type) != 0)
		return FALSE;

	*type = _type;
	return TRUE;
}

/*
 * Map teamd tx_hash flag bits to names
 */
static const ni_intmap_t	ni_team_tx_hash_bit_names[] = {
	{ "eth",		NI_TEAM_TX_HASH_ETH		},
	{ "vlan",		NI_TEAM_TX_HASH_VLAN		},
	{ "ipv4",		NI_TEAM_TX_HASH_IPV4		},
	{ "ipv6",		NI_TEAM_TX_HASH_IPV6		},
	{ "ip",			NI_TEAM_TX_HASH_IP		},
	{ "l3",			NI_TEAM_TX_HASH_L3		},
	{ "tcp",		NI_TEAM_TX_HASH_TCP		},
	{ "udp",		NI_TEAM_TX_HASH_UDP		},
	{ "sctp",		NI_TEAM_TX_HASH_SCTP		},
	{ "l4",			NI_TEAM_TX_HASH_L4		},

	{ NULL,			NI_TEAM_TX_HASH_NONE		}
};

const char *
ni_team_tx_hash_bit_to_name(ni_team_tx_hash_bit_t bit)
{
	return ni_format_uint_mapped(bit, ni_team_tx_hash_bit_names);
}

ni_bool_t
ni_team_tx_hash_name_to_bit(const char *name, ni_team_tx_hash_bit_t *bit)
{
	unsigned int _bit;

	if (!name || !bit)
		return FALSE;

	if (ni_parse_uint_mapped(name, ni_team_tx_hash_bit_names, &_bit) != 0)
		return FALSE;

	*bit = _bit;
	return TRUE;
}

unsigned int
ni_team_tx_hash_get_bit_names(ni_team_tx_hash_bit_t mask, ni_string_array_t *names)
{
	const ni_intmap_t *map;
	unsigned int n = 0;

	for (map = ni_team_tx_hash_bit_names; map->name; ++map) {
		if (mask & (1 << map->value)) {
			ni_string_array_append(names, map->name);
			n++;
		}
	}
	return n;
}

/*
 * Map teamd tx_balancer names to constants
 */
static const ni_intmap_t	ni_team_tx_balancer_names[] = {
	{ "basic",		NI_TEAM_TX_BALANCER_BASIC	},

	{ NULL,			-1U				}
};

const char *
ni_team_tx_balancer_type_to_name(ni_team_tx_balancer_type_t type)
{
	return ni_format_uint_mapped(type, ni_team_tx_balancer_names);
}

ni_bool_t
ni_team_tx_balancer_name_to_type(const char *name, ni_team_tx_balancer_type_t *type)
{
	unsigned int _type;

	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, ni_team_tx_balancer_names, &_type) != 0)
		return FALSE;

	*type = _type;
	return TRUE;
}

/*
 * Map teamd lacp select policy names to constants
 */
static const ni_intmap_t	ni_team_lacp_select_policies[] = {
	{ "lacp_prio",		NI_TEAM_LACP_SELECT_POLICY_PRIO		},
	{ "lacp_prio_stable",	NI_TEAM_LACP_SELECT_POLICY_PRIO_STABLE	},
	{ "bandwidth",		NI_TEAM_LACP_SELECT_POLICY_BANDWIDTH	},
	{ "count",		NI_TEAM_LACP_SELECT_POLICY_COUNT	},
	{ "port_options",	NI_TEAM_LACP_SELECT_POLICY_PORT_CONFIG	},

	{ NULL,			-1U					}
};

const char *
ni_team_lacp_select_policy_type_to_name(ni_team_lacp_select_policy_t policy)
{
	return ni_format_uint_mapped(policy, ni_team_lacp_select_policies);
}

ni_bool_t
ni_team_lacp_select_policy_name_to_type(const char *name, ni_team_lacp_select_policy_t *type)
{
	unsigned int _type;

	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, ni_team_lacp_select_policies, &_type) != 0)
		return FALSE;

	*type = _type;
	return TRUE;
}

/*
 * Map teamd activebackup hwaddr_policy names to constants
 */
static const ni_intmap_t	ni_team_ab_hwaddr_policies[] = {
	{ "same_all",		NI_TEAM_AB_HWADDR_POLICY_SAME_ALL	},
	{ "by_active",		NI_TEAM_AB_HWADDR_POLICY_BY_ACTIVE	},
	{ "only_active",	NI_TEAM_AB_HWADDR_POLICY_ONLY_ACTIVE	},

	{ NULL,			-1U					}
};

const char *
ni_team_ab_hwaddr_policy_type_to_name(ni_team_ab_hwaddr_policy_t policy)
{
	return ni_format_uint_mapped(policy, ni_team_ab_hwaddr_policies);
}

ni_bool_t
ni_team_ab_hwaddr_policy_name_to_type(const char *name, ni_team_ab_hwaddr_policy_t *type)
{
	unsigned int _type;

	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, ni_team_ab_hwaddr_policies, &_type) != 0)
		return FALSE;

	*type = _type;
	return TRUE;
}

void
ni_team_runner_init(ni_team_runner_t *runner, ni_team_runner_type_t type)
{
	memset(runner, 0, sizeof(*runner));
	runner->type = type;

	/* apply non-zero type depending defaults here */
	switch (runner->type) {
	case NI_TEAM_RUNNER_ROUND_ROBIN:
	case NI_TEAM_RUNNER_ACTIVE_BACKUP:
	case NI_TEAM_RUNNER_LOAD_BALANCE:
	case NI_TEAM_RUNNER_BROADCAST:
	case NI_TEAM_RUNNER_RANDOM:
	case NI_TEAM_RUNNER_LACP:
	default:
		break;
	}
}

void
ni_team_runner_destroy(ni_team_runner_t *runner)
{
}

/*
 * Map teamd link watch names to constants
 */
static const ni_intmap_t	ni_team_link_watch_names[] = {
	{ "ethtool",		NI_TEAM_LINK_WATCH_ETHTOOL	},
	{ "arp_ping",		NI_TEAM_LINK_WATCH_ARP_PING	},
	{ "nsna_ping",		NI_TEAM_LINK_WATCH_NSNA_PING	},
	{ "tipc",		NI_TEAM_LINK_WATCH_TIPC		},

	{ NULL,			-1U				}
};

const char *
ni_team_link_watch_type_to_name(ni_team_link_watch_type_t type)
{
	return ni_format_uint_mapped(type, ni_team_link_watch_names);
}

ni_bool_t
ni_team_link_watch_name_to_type(const char *name, ni_team_link_watch_type_t *type)
{
	unsigned int _type;

	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, ni_team_link_watch_names, &_type) != 0)
		return FALSE;

	*type = _type;
	return TRUE;
}

void
ni_team_link_watch_init(ni_team_link_watch_t *lw)
{
	if (lw) switch (lw->type) {
	case NI_TEAM_LINK_WATCH_ETHTOOL:
		break;
	case NI_TEAM_LINK_WATCH_ARP_PING:
		lw->arp.vlanid = UINT16_MAX;
		break;
	case NI_TEAM_LINK_WATCH_NSNA_PING:
		break;
	case NI_TEAM_LINK_WATCH_TIPC:
		break;
	default:
		return;
	}
}

/*
 * team master link watch
 */
ni_team_link_watch_t *
ni_team_link_watch_new(ni_team_link_watch_type_t type)
{
	ni_team_link_watch_t *lw;

	lw = xcalloc(1, sizeof(*lw));
	lw->type = type;

	ni_team_link_watch_init(lw);
	return lw;
}

void
ni_team_link_watch_free(ni_team_link_watch_t *lw)
{
	if (lw) switch (lw->type) {
	case NI_TEAM_LINK_WATCH_ETHTOOL:
		break;
	case NI_TEAM_LINK_WATCH_ARP_PING:
		ni_string_free(&lw->arp.source_host);
		ni_string_free(&lw->arp.target_host);
		break;
	case NI_TEAM_LINK_WATCH_NSNA_PING:
		ni_string_free(&lw->nsna.target_host);
		break;
	case NI_TEAM_LINK_WATCH_TIPC:
		ni_string_free(&lw->tipc.bearer);
		break;
	default:
		return;
	}
	free(lw);
}

/*
 * Map teamd link watch policy to constants
 */
static const ni_intmap_t	ni_team_link_watch_policy[] = {
	{ "any",		NI_TEAM_LINK_WATCH_POLICY_ANY		},
	{ "all",		NI_TEAM_LINK_WATCH_POLICY_ALL		},

	{ NULL,			-1U					}
};

const char *
ni_team_link_watch_policy_type_to_name(ni_team_link_watch_policy_t type)
{
	return ni_format_uint_mapped(type, ni_team_link_watch_policy);
}

ni_bool_t
ni_team_link_watch_policy_name_to_type(const char *name, ni_team_link_watch_policy_t *type)
{
	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, ni_team_link_watch_policy, type) != 0)
		return FALSE;

	return TRUE;
}

static ni_define_ptr_array_init(ni_team_link_watch);
static ni_define_ptr_array_destroy(ni_team_link_watch);
static ni_define_ptr_array_realloc(ni_team_link_watch, NI_TEAM_LINK_WATCH_ARRAY_CHUNK);
extern ni_define_ptr_array_append(ni_team_link_watch);
extern ni_define_ptr_array_delete_at(ni_team_link_watch);

/*
 * team interface
 */
static void
ni_team_init(ni_team_t *team)
{
	team->notify_peers.count = -1U;
	team->notify_peers.interval = -1U;
	team->mcast_rejoin.count = -1U;
	team->mcast_rejoin.interval = -1U;
}

ni_team_t *
ni_team_new(void)
{
	ni_team_t *team;

	team = xcalloc(1, sizeof(*team));
	ni_team_init(team);

	return team;
}

void
ni_team_free(ni_team_t *team)
{
	if (team) {
		ni_team_runner_destroy(&team->runner);
		ni_team_link_watch_array_destroy(&team->link_watch);
		free(team);
	}
}

/*
 * team port link-request configuration
 */
ni_bool_t
ni_team_port_config_init(ni_team_port_config_t *conf)
{
	if (conf) {
		memset(conf, 0, sizeof(*conf));
		conf->queue_id = -1U;
		return TRUE;
	}
	return FALSE;
}

void
ni_team_port_config_destroy(ni_team_port_config_t *conf)
{
	ni_team_port_config_init(conf);
}

ni_team_port_config_t *
ni_team_port_config_new(void)
{
	ni_team_port_config_t *conf;

	conf = malloc(sizeof(*conf));
	if (ni_team_port_config_init(conf))
		return conf;

	free(conf);
	return NULL;
}

void
ni_team_port_config_free(ni_team_port_config_t *conf)
{
	ni_team_port_config_destroy(conf);
	free(conf);
}

/*
 * team port interface info properties
 */
static ni_bool_t
ni_team_port_info_init(ni_team_port_info_t *info)
{
	if (info) {
		memset(info, 0, sizeof(*info));
		/* apply "not set" defaults */
		info->runner.type = -1U;
		return TRUE;
	}
	return FALSE;
}

ni_team_port_info_t *
ni_team_port_info_new(void)
{
	ni_team_port_info_t *info;

	info = malloc(sizeof(*info));
	if (ni_team_port_info_init(info))
		return info;

	free(info);
	return NULL;
}

static inline void
ni_team_port_runner_lacp_info_free(ni_team_port_runner_lacp_info_t *lacp)
{
	ni_string_free(&lacp->state);
}

static inline void
ni_team_port_runner_info_free(ni_team_port_runner_info_t *runner)
{
	switch (runner->type) {
	case NI_TEAM_RUNNER_LACP:
		ni_team_port_runner_lacp_info_free(&runner->lacp);
		break;
	default:
		break;
	}
}

void
ni_team_port_info_free(ni_team_port_info_t *info)
{
	if (info) {
		ni_team_port_runner_info_free(&info->runner);
		free(info);
	}
}
