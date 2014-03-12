/*
 *	Routines for handling tun device settings
 *
 *	Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *
 */

#ifndef   __WICKED_TUN_H__
#define   __WICKED_TUN_H__

#include <wicked/types.h>

struct ni_tun {
	ni_bool_t	persistent; /* Always TRUE */
	uid_t		owner;
	gid_t		group;
};

extern ni_tun_t *	ni_tun_new(void);
extern void		ni_tun_free(ni_tun_t *);
extern const char *	ni_tun_validate(const ni_tun_t *);

extern int		ni_tun_parse_sysfs_attrs(const char *, ni_tun_t *);
#endif /* __WICKED_MACVLAN_H__ */
