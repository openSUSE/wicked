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
#ifndef NI_WICKED_IPVLAN_H
#define NI_WICKED_IPVLAN_H

#include <wicked/types.h>
#include <wicked/util.h>

enum {
	NI_IPVLAN_MODE_L2	= 0,
	NI_IPVLAN_MODE_L3	= 1,
	NI_IPVLAN_MODE_L3S	= 2
};

enum {
	NI_IPVLAN_F_PRIVATE	= 0,
	NI_IPVLAN_F_VEPA	= 1,
};

struct ni_ipvlan {
	uint16_t	mode;
	uint16_t	flags;
};

ni_ipvlan_t *	        ni_ipvlan_new(void);
void		        ni_ipvlan_free(ni_ipvlan_t *);

const ni_intmap_t *     ni_ipvlan_flags_bitmap(void);

const char *	        ni_ipvlan_mode_to_name(unsigned int);
ni_bool_t	        ni_ipvlan_name_to_mode(const char *, unsigned int *);
const char*	        ni_ipvlan_format_flags(unsigned int, ni_stringbuf_t *);
ni_bool_t	        ni_ipvlan_parse_flags(const char *, unsigned int *);
const char *	        ni_ipvlan_validate(const ni_ipvlan_t *);
ni_bool_t		ni_ipvlan_valid_flags(unsigned int);

#endif /* NI_WICKED_IPVLAN_H */
