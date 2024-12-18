/*
 *	Copyright (C) 2024 SUSE LLC
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
 *		Clemens Famulla-Conrad
 */
#include "wicked/util.h"
#include <stdlib.h>
#include <wicked/types.h>
#include <wicked/ipvlan.h>

static const ni_intmap_t	ni_ipvlan_mode_map[] = {
	{ "l2",  NI_IPVLAN_MODE_L2 },
	{ "l3",  NI_IPVLAN_MODE_L3 },
	{ "l3s", NI_IPVLAN_MODE_L3S},
	{ .name = NULL }
};

static const ni_intmap_t	ni_ipvlan_flag_bits[] = {
	{ "private",	NI_IPVLAN_F_PRIVATE },
	{ "vepa",	NI_IPVLAN_F_VEPA    },
	{ .name = NULL}
};


ni_ipvlan_t *
ni_ipvlan_new(void)
{
	ni_ipvlan_t *ipvlan;

	if (!(ipvlan = calloc(1, sizeof(ni_ipvlan_t))))
		return NULL;

	ipvlan->mode = NI_IPVLAN_MODE_L3;

	return ipvlan;
}

void
ni_ipvlan_free(ni_ipvlan_t *ipvlan)
{
	if (ipvlan)
		free(ipvlan);
}

const ni_intmap_t*
ni_ipvlan_flags_bitmap()
{
	return ni_ipvlan_flag_bits;
}

const char *
ni_ipvlan_mode_to_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, ni_ipvlan_mode_map);
}

ni_bool_t
ni_ipvlan_name_to_mode(const char *name, unsigned int *result)
{
	return ni_parse_uint_mapped(name, ni_ipvlan_mode_map, result) == 0;
}

ni_bool_t
ni_ipvlan_parse_flags(const char *flags, unsigned int *result)
{
	if (!flags || !result)
		return FALSE;

	*result = 0;

	if (ni_string_eq_nocase(flags, "bridge"))
		return TRUE;

	if (ni_parse_bitmap_string(result, ni_ipvlan_flags_bitmap(), flags, NULL, NULL) == 0)
		return TRUE;

	return FALSE;
}

const char*
ni_ipvlan_format_flags(unsigned int flags, ni_stringbuf_t *result)
{
	return ni_format_bitmap_string(result, ni_ipvlan_flags_bitmap(), flags, NULL, NULL);
}

ni_bool_t
ni_ipvlan_valid_flags(unsigned int flags)
{
	switch (flags) {
	case 0:				/* default is 0, which mean bridge */
	case NI_BIT(NI_IPVLAN_F_VEPA):
	case NI_BIT(NI_IPVLAN_F_PRIVATE):
		return TRUE;
	break;
	default:
		return FALSE;
	}
}

const char *
ni_ipvlan_validate(const ni_ipvlan_t *ipvlan)
{
	static const char *err_nocfg = "Uninitialized configuration";
	static const char *err_mode = "Invalid mode";
	static const char *err_flags = "Invalid flags";

	if (!ipvlan)
		return err_nocfg;

	switch (ipvlan->mode) {
	case NI_IPVLAN_MODE_L2:
	case NI_IPVLAN_MODE_L3:
	case NI_IPVLAN_MODE_L3S:
		/* valid */
	break;
	default:
		return err_mode;
	}

	if (!ni_ipvlan_valid_flags(ipvlan->flags))
		return err_flags;

	return NULL;
}
