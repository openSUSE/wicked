/*
 *	wicked client ifup action and utilities
 *
 *	Copyright (C) 2010-2014 SÜSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
 */
#ifndef   __WICKED_CLIENT_IFUP_H__
#define   __WICKED_CLIENT_IFUP_H__

extern unsigned int ni_wait_for_interfaces;

extern int		ni_do_ifup(int argc, char **argv);
extern ni_bool_t	ni_ifup_hire_nanny(ni_ifworker_array_t *, ni_bool_t);

#endif /* __WICKED_CLIENT_IFUP_H__ */
