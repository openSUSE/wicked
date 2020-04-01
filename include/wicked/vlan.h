/*
 *	vlan definitions for netinfo
 *
 *	Copyright (C) 2009-2013 SÜSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Olaf Kirch <okir@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifndef __WICKED_VLAN_H__
#define __WICKED_VLAN_H__

#include <wicked/types.h>

enum {
	NI_VLAN_PROTOCOL_8021Q	= 0,
	NI_VLAN_PROTOCOL_8021AD	= 1,
};

struct ni_vlan {
	uint16_t		protocol;
	uint16_t		tag;
};

extern ni_vlan_t *	ni_vlan_new(void);
extern void		ni_vlan_free(ni_vlan_t *);

extern const char *	ni_vlan_validate(const ni_vlan_t *);

extern const char *	ni_vlan_protocol_to_name(unsigned int);
extern ni_bool_t	ni_vlan_name_to_protocol(const char *, unsigned int *);

#endif /* __WICKED_VLAN_H__ */
