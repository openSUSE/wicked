/*
 *	Lease information.
 *
 *	Copyright (C) 2013 SÜSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Karol Mroz <kmroz@suse.com>
 */

#ifndef __WICKED_LEASEINFO_H__
#define __WICKED_LEASEINFO_H__

#include <stdio.h>
#include <wicked/types.h>

extern char *	ni_leaseinfo_path(const char *, const ni_addrconf_mode_t,
				const unsigned int);
extern void	ni_leaseinfo_remove(const char *, const ni_addrconf_mode_t,
				const unsigned int);
extern void	ni_leaseinfo_dump(FILE *, const ni_addrconf_lease_t *,
				const char *, const char *);

#endif /* __WICKED_LEASEINFO_H__ */
