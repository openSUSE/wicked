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


/*
 * Map teamd mode names to constants
 */
static const ni_intmap_t	ni_team_mode_names[] = {
	{ "roundrobin",		NI_TEAM_MODE_ROUND_ROBIN	},
	{ "activebackup",	NI_TEAM_MODE_ACTIVE_BACKUP	},
	{ "loadbalance",	NI_TEAM_MODE_LOAD_BALANCE	},
	{ "broadcast",		NI_TEAM_MODE_BROADCAST		},
	{ "random",		NI_TEAM_MODE_RANDOM		},
	{ "lacp",		NI_TEAM_MODE_LACP		},

	{ NULL,			-1U				}
};

const char *
ni_team_mode_type_to_name(ni_team_mode_t type)
{
	return ni_format_uint_mapped(type, ni_team_mode_names);
}

ni_bool_t
ni_team_mode_name_to_type(const char *name, ni_team_mode_t *type)
{
	unsigned int _type;

	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, ni_team_mode_names, &_type) != 0)
		return FALSE;

	*type = _type;
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
		free(team);
	}
}

