/*
 *	wicked dhcp6 in test (request offer) mode
 *
 *	Copyright (C) 2013-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
#ifndef   __WICKED_DHCP6_TESTER_H__
#define   __WICKED_DHCP6_TESTER_H__

extern int		dhcp6_tester_run(const char *ifname, const char *request,
						unsigned int timeout);

#endif /* __WICKED_DHCP6_TESTER_H__ */
