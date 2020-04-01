/*
 *	wicked udev utilities
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
 * 	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *
 */
#ifndef WICKED_UDEV_UTILS_H
#define WICKED_UDEV_UTILS_H

extern int			ni_udevadm_info(ni_var_array_t **, const char *, const char *);

extern ni_bool_t		ni_udev_is_active(void);
extern ni_bool_t		ni_udev_net_subsystem_available(void);
extern ni_bool_t		ni_udev_netdev_is_ready(ni_netdev_t *);

#endif /* WICKED_UDEV_UTILS_H */
