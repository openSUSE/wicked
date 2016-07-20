/*
 *	DBus API for wicked dhcp6 supplicant
 *
 *	Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012 Marius Tomaschewski <mt@suse.de>
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
 */
#ifndef __WICKED_DHCP6_DBUS_API_H__
#define __WICKED_DHCP6_DBUS_API_H__

#include <wicked/dbus.h>
#include "dhcp6/dhcp6.h"

extern void				ni_objectmodel_dhcp6_init(void);
extern ni_dbus_object_t *		ni_objectmodel_register_dhcp6_device(ni_dbus_server_t *, ni_dhcp6_device_t *);

#endif /* __WICKED_DHCP6_DBUS_API_H__ */
