/*
 *	Routines for handling macvlan device settings
 *
 *	Copyright (C) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/util.h>
#include <wicked/macvlan.h>
#include "util_priv.h"


static const ni_intmap_t	__map_macvlan_mode[] = {
	{ "private",		NI_MACVLAN_MODE_PRIVATE	},
	{ "vepa",		NI_MACVLAN_MODE_VEPA	},
	{ "pass-through",	NI_MACVLAN_MODE_PASSTHRU},
	{ "passthru",		NI_MACVLAN_MODE_PASSTHRU},
	{ "bridge",		NI_MACVLAN_MODE_BRIDGE	},
	{ "source", 		NI_MACVLAN_MODE_SOURCE	},

	{ NULL,			0			}
};

static const ni_intmap_t	__map_macvlan_flags[] = {
	{ "nopromisc",		NI_MACVLAN_FLAG_NOPROMISC},

	{ NULL,			0			}
};

ni_macvlan_t *
ni_macvlan_new(void)
{
	ni_macvlan_t *macvlan;

	macvlan = xcalloc(1, sizeof(*macvlan));
	return macvlan;
}

void
ni_macvlan_free(ni_macvlan_t *macvlan)
{
	if (macvlan) {
		free(macvlan);
	}
}

const char *
ni_macvlan_validate(const ni_macvlan_t *macvlan)
{
	if (!macvlan)
		return "Uninitialized macvlan configuration";

	switch (macvlan->mode) {
	default:
		return "Invalid/unsupported macvlan mode";
	case NI_MACVLAN_MODE_PRIVATE:
	case NI_MACVLAN_MODE_VEPA:
	case NI_MACVLAN_MODE_PASSTHRU:
	case NI_MACVLAN_MODE_BRIDGE:
	case NI_MACVLAN_MODE_SOURCE:
	case 0:
		break;
	}

	if (macvlan->flags && (macvlan->flags & ~NI_MACVLAN_FLAG_NOPROMISC))
		return "Invalid/unsupported macvlan flags";

	return NULL;
}

const char *
ni_macvlan_mode_to_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, __map_macvlan_mode);
}

ni_bool_t
ni_macvlan_name_to_mode(const char *name, unsigned int *flag)
{
	return ni_parse_uint_mapped(name, __map_macvlan_mode, flag) == 0;
}

const char *
ni_macvlan_flag_to_name(unsigned int flag)
{
	return ni_format_uint_mapped(flag, __map_macvlan_flags);
}

ni_bool_t
ni_macvlan_name_to_flag(const char *name, unsigned int *flag)
{
	return ni_parse_uint_mapped(name, __map_macvlan_flags, flag) == 0;
}

const char *
ni_macvlan_flag_bit_name(unsigned int bit)
{
	return bit < 32 ? ni_macvlan_flag_to_name(1 << bit) : NULL;
}

ni_bool_t
ni_macvlan_flags_to_names(unsigned int flags, ni_string_array_t *names)
{
	const ni_intmap_t *map;

	if (!names)
		return FALSE;

	ni_string_array_destroy(names);
	for (map = __map_macvlan_flags; map->name; ++map) {
		if (flags & map->value)
			ni_string_array_append(names, map->name);
	}
	return TRUE;
}

