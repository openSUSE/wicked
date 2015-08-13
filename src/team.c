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

