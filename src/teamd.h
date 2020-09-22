/*
 *	Interfacing with teamd through dbus interface
 *
 *	Copyright (C) 2015 SUSE Linux GmbH, Nuernberg, Germany.
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
#ifndef NI_TEAMD_CLIENT_H
#define NI_TEAMD_CLIENT_H

#include <wicked/types.h>
#include <wicked/team.h>

typedef struct ni_teamd_client		ni_teamd_client_t;

ni_teamd_client_t *			ni_teamd_client_open(const char*);
void					ni_teamd_client_free(ni_teamd_client_t *);

extern int				ni_teamd_ctl_config_dump(ni_teamd_client_t *, ni_bool_t, char **);
extern int				ni_teamd_ctl_state_dump(ni_teamd_client_t *, char **);
extern int				ni_teamd_ctl_state_get_item(ni_teamd_client_t *, const char *, char **);
extern int				ni_teamd_ctl_state_set_item(ni_teamd_client_t *, const char *,
											 const char *);
extern int				ni_teamd_ctl_port_add(ni_teamd_client_t *, const char *);
extern int				ni_teamd_ctl_port_remove(ni_teamd_client_t *, const char *);
extern int				ni_teamd_ctl_port_config_update(ni_teamd_client_t *, const char *, const char *);

extern int				ni_teamd_port_enslave(const ni_netdev_t *, const ni_netdev_t *, const ni_team_port_config_t *);
extern int				ni_teamd_port_unenslave(const ni_netdev_t *, const ni_netdev_t *);

extern int				ni_teamd_discover(ni_netdev_t *);

extern int				ni_teamd_service_start(const ni_netdev_t *);
extern int				ni_teamd_service_stop (const char *);

extern ni_bool_t			ni_teamd_enabled(const char *);

#endif /* NI_TEAMD_CLIENT_H */
