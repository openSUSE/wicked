/*
 *	wicked uevent event listener
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
#ifndef WICKED_UEVENT_H
#define WICKED_UEVENT_H

#include <wicked/util.h>

typedef struct ni_uevent_monitor	ni_uevent_monitor_t;
typedef void				ni_uevent_callback_t(const ni_var_array_t *, void *);

extern void				ni_uevent_trace_callback(const ni_var_array_t *, void *);


ni_uevent_monitor_t *			ni_uevent_monitor_new(unsigned int,
							ni_uevent_callback_t *, void *);

extern int				ni_uevent_monitor_enable(ni_uevent_monitor_t *);
extern int				ni_uevent_monitor_filter_apply(ni_uevent_monitor_t *);
extern void				ni_uevent_monitor_free(ni_uevent_monitor_t *);


#endif /* WICKED_UEVENT_H */
