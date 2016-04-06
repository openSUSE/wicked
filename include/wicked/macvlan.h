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
#ifndef   __WICKED_MACVLAN_H__
#define   __WICKED_MACVLAN_H__

#include <wicked/types.h>

enum {
	NI_MACVLAN_MODE_PRIVATE		= 1,
	NI_MACVLAN_MODE_VEPA		= 2,
	NI_MACVLAN_MODE_BRIDGE		= 4,
	NI_MACVLAN_MODE_PASSTHRU	= 8,
	NI_MACVLAN_MODE_SOURCE		= 16,
};

enum {
	NI_MACVLAN_FLAG_NOPROMISC	= 1,
};

struct ni_macvlan {
	unsigned int		mode;
	uint16_t		flags;
};

extern ni_macvlan_t *	ni_macvlan_new(void);
extern void		ni_macvlan_free(ni_macvlan_t *);

extern const char *	ni_macvlan_validate(const ni_macvlan_t *);

extern const char *	ni_macvlan_mode_to_name(unsigned int);
extern ni_bool_t	ni_macvlan_name_to_mode(const char *, unsigned int *);

extern const char *	ni_macvlan_flag_to_name(unsigned int);
extern ni_bool_t	ni_macvlan_name_to_flag(const char *, unsigned int *);
extern const char *	ni_macvlan_flag_bit_name(unsigned int);
extern ni_bool_t	ni_macvlan_flags_to_names(unsigned int, ni_string_array_t *);

#endif /* __WICKED_MACVLAN_H__ */
