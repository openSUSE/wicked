/*
 *	Address configuration aka lease for wicked
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2022 SUSE LLC
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
#ifndef WICKED_ADDRCONF_H
#define WICKED_ADDRCONF_H

#include <wicked/types.h>
#include <wicked/time.h>


typedef struct ni_addrconf_action	ni_addrconf_action_t;
typedef int				ni_addrconf_action_exec_t(ni_netdev_t *, ni_addrconf_lease_t *);
typedef void				ni_addrconf_action_free_t(ni_addrconf_action_t *);

typedef void				ni_addrconf_updater_cleanup_t(void *);

struct ni_addrconf_action {
	ni_addrconf_action_t *		next;

	const char *			info;
	ni_addrconf_action_exec_t *	exec;
	ni_addrconf_action_free_t *	free;
};

struct ni_addrconf_updater {
	ni_addrconf_action_t *		action;
	struct timeval			astart;		/* action  */

	ni_netdev_ref_t			device;
	ni_event_t			event;

	const ni_timer_t *		timer;
	ni_int_range_t			jitter;
	ni_timeout_t			timeout;
	struct timeval			started;	/* updater */
	unsigned int			deadline;

	ni_addrconf_updater_cleanup_t *	cleanup;	/* state   */
	void *				user_data;
};

extern ni_addrconf_updater_t *	ni_addrconf_updater_new_applying(ni_addrconf_lease_t *, const ni_netdev_t *, ni_event_t);
extern ni_addrconf_updater_t *	ni_addrconf_updater_new_removing(ni_addrconf_lease_t *, const ni_netdev_t *, ni_event_t);
extern ni_bool_t		ni_addrconf_updater_background(ni_addrconf_updater_t *, unsigned int);
extern int			ni_addrconf_updater_execute(ni_netdev_t *, ni_addrconf_lease_t *);
extern void			ni_addrconf_updater_set_data(ni_addrconf_updater_t *, void *, ni_addrconf_updater_cleanup_t *);
extern void *			ni_addrconf_updater_get_data(ni_addrconf_updater_t *, ni_addrconf_updater_cleanup_t *);
extern void			ni_addrconf_updater_free(ni_addrconf_updater_t **);

extern int			ni_addrconf_action_mtu_apply(ni_netdev_t *, ni_addrconf_lease_t *);
extern int			ni_addrconf_action_addrs_apply(ni_netdev_t *, ni_addrconf_lease_t *);
extern int			ni_addrconf_action_addrs_verify(ni_netdev_t *, ni_addrconf_lease_t *);
extern int			ni_addrconf_action_routes_apply(ni_netdev_t *, ni_addrconf_lease_t *);
extern int			ni_addrconf_action_system_update(ni_netdev_t *, ni_addrconf_lease_t *);
extern int			ni_addrconf_action_verify_apply(ni_netdev_t *, ni_addrconf_lease_t *);
extern int			ni_addrconf_action_write_lease(ni_netdev_t *, ni_addrconf_lease_t *);

extern int			ni_addrconf_action_addrs_remove(ni_netdev_t *, ni_addrconf_lease_t *);
extern int			ni_addrconf_action_routes_remove(ni_netdev_t *, ni_addrconf_lease_t *);
extern int			ni_addrconf_action_mtu_restore(ni_netdev_t *, ni_addrconf_lease_t *);
extern int			ni_addrconf_action_remove_lease(ni_netdev_t *, ni_addrconf_lease_t *);

extern ni_addrconf_action_t *	ni_addrconf_action_new(const char *, ni_addrconf_action_exec_t *);
extern void			ni_addrconf_action_free(ni_addrconf_action_t *);

extern ni_addrconf_action_t *	ni_addrconf_action_list_find_exec(ni_addrconf_action_t *, ni_addrconf_action_exec_t *);
extern ni_bool_t		ni_addrconf_action_list_insert(ni_addrconf_action_t **, ni_addrconf_action_t *);
extern ni_bool_t		ni_addrconf_action_list_append(ni_addrconf_action_t **, ni_addrconf_action_t *);
extern void			ni_addrconf_action_list_destroy(ni_addrconf_action_t **);

#endif /* WICKED_ADDRCONF_H */
