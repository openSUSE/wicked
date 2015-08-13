/*
 *	Team device support
 *
 *	Copyright (C) 2015 SUSE Linux GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <wicked/util.h>
#include <wicked/team.h>
#include "util_priv.h"

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
ni_team_lacp_select_policy_to_name(ni_team_lacp_select_policy_t policy)
{
	return ni_format_uint_mapped(policy, ni_team_lacp_select_policies);
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
ni_team_ab_hwaddr_policy_to_name(ni_team_ab_hwaddr_policy_t policy)
{
	return ni_format_uint_mapped(policy, ni_team_ab_hwaddr_policies);
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

ni_team_link_watch_t *
ni_team_link_watch_new(ni_team_link_watch_type_t type)
{
	ni_team_link_watch_t *lw;

	lw = xcalloc(1, sizeof(*lw));
	lw->type = type;

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

static inline void
ni_team_link_watch_array_init(ni_team_link_watch_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_team_link_watch_array_destroy(ni_team_link_watch_array_t *array)
{
	while (array->count > 0)
		ni_team_link_watch_free(array->data[--array->count]);
	free(array->data);
	ni_team_link_watch_array_init(array);
}

static void
__ni_team_link_watch_array_realloc(ni_team_link_watch_array_t *array, unsigned int newsize)
{
	ni_team_link_watch_t **newdata;
	unsigned int i;

	newsize = (newsize + NI_TEAM_LINK_WATCH_ARRAY_CHUNK);
	newdata = xrealloc(array->data, newsize * sizeof(ni_team_link_watch_t));
	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		array->data[i] = NULL;
}

ni_bool_t
ni_team_link_watch_array_append(ni_team_link_watch_array_t *array, ni_team_link_watch_t *lw)
{
	if (array && lw) {
		if ((array->count % NI_TEAM_LINK_WATCH_ARRAY_CHUNK) == 0)
			__ni_team_link_watch_array_realloc(array, array->count);

		array->data[array->count++] = lw;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_team_link_watch_array_delete_at(ni_team_link_watch_array_t *array, unsigned int pos)
{
	if (!array || pos >= array->count)
		return FALSE;

	ni_team_link_watch_free(array->data[pos]);
	array->count--;
	if (pos < array->count) {
		memmove(&array->data[pos], &array->data[pos + 1],
			(array->count - pos) * sizeof(ni_team_link_watch_t *));
	}
	array->data[array->count] = NULL;
	return TRUE;
}

ni_team_t *
ni_team_new(void)
{
	ni_team_t *team;

	team = xcalloc(1, sizeof(*team));
	return team;
}

void
ni_team_free(ni_team_t *team)
{
	if (team) {
		ni_team_link_watch_array_destroy(&team->link_watch);
		free(team);
	}
}

