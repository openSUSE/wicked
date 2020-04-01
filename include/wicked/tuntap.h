/*
 *	Routines for handling tun/tap device settings
 *
 *	Copyright (C) 2014 SÜSE LINUX Products GmbH, Nuernberg, Germany.
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

#ifndef   __WICKED_TUNTAP_H__
#define   __WICKED_TUNTAP_H__

#include <wicked/types.h>

struct ni_tuntap {
	uid_t		owner;
	gid_t		group;
};

extern ni_tuntap_t *	ni_tuntap_new(void);
extern void		ni_tuntap_free(ni_tuntap_t *);
extern const char *	ni_tuntap_validate(const ni_tuntap_t *);

extern int		ni_tuntap_parse_sysfs_attrs(const char *, ni_tuntap_t *);

#endif /* __WICKED_TUNTAP_H__ */
