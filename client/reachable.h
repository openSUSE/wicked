/*
 *	wicked fsm check for reachability of a given host
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
 */
#ifndef   __WICKED_CLIENT_REACHABLE_H__
#define   __WICKED_CLIENT_REACHABLE_H__

extern ni_fsm_require_t *	ni_ifworker_reachability_check_new(xml_node_t *);

#endif /* __WICKED_CLIENT_REACHABLE_H__ */
