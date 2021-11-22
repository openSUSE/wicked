/*
 *	Network socket related functionality for wicked.
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2021 SUSE LLC
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Olaf Kirch
 *		Marius Tomaschewski
 */

#ifndef WICKED_SOCKET_H
#define WICKED_SOCKET_H

#include <wicked/types.h>

extern ni_socket_t *	ni_socket_hold(ni_socket_t *);
extern void		ni_socket_release(ni_socket_t *);
extern ni_socket_t *	ni_socket_wrap(int fd, int sotype);
extern ni_bool_t	ni_socket_activate(ni_socket_t *);
extern ni_bool_t	ni_socket_deactivate(ni_socket_t *);
extern void		ni_socket_deactivate_all(void);
extern int		ni_socket_wait(long timeout);

extern void		ni_socket_close(ni_socket_t *);

#endif /* WICKED_SOCKET_H */
