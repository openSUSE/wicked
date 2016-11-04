/*
 *	wicked addrconf utilities for dhcp4 specific lease
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Karol Mroz <kmroz@suse.com>
 *		Marius Tomaschewski <mt@suse.de>
 *
 */
#ifndef   __WICKED_DHCP4_LEASE_H__
#define   __WICKED_DHCP4_LEASE_H__

int
ni_dhcp4_lease_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);

int
ni_dhcp4_lease_data_to_xml(const ni_addrconf_lease_t *, xml_node_t *, const char *);


int
ni_dhcp4_lease_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);

int
ni_dhcp4_lease_data_from_xml(ni_addrconf_lease_t *, const xml_node_t *, const char *);

#endif /* __WICKED_DHCP4_LEASE_H__ */
