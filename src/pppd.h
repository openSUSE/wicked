/*
 *	Interfacing with pppd daemon
 *
 *	Copyright (C) 2016 SUSE Linux GmbH, Nuernberg, Germany.
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
 */
#ifndef NI_PPPD_CLIENT_H
#define NI_PPPD_CLIENT_H

#include <wicked/types.h>
#include <wicked/ppp.h>

extern int				ni_pppd_config_file_remove(const char *);
extern int				ni_pppd_discover(ni_netdev_t *, ni_netconfig_t *);

extern int				ni_pppd_service_start(const ni_netdev_t *);
extern int				ni_pppd_service_stop (const char *);

#endif /* NI_PPPD_CLIENT_H */
