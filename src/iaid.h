/*
 *	DHCP Identity Association Identifier (IAID) utilities
 *
 *	Copyright (C) 2016 SÜSE LINUX GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 *		Nirmoy Das <ndas@suse.de>
 */
#ifndef   WICKED_IAID_H
#define   WICKED_IAID_H

#include <wicked/types.h>
#include <wicked/util.h>

typedef struct ni_iaid_map	ni_iaid_map_t;

extern ni_bool_t		ni_iaid_create(unsigned int *iaid, const ni_netdev_t *dev, const ni_iaid_map_t *map);

extern ni_bool_t		ni_iaid_acquire(unsigned int *iaid, const ni_netdev_t *dev, unsigned int requested);

extern ni_iaid_map_t *		ni_iaid_map_load(const char *filename);
extern ni_bool_t		ni_iaid_map_save(ni_iaid_map_t *);
extern void			ni_iaid_map_free(ni_iaid_map_t *);
extern ni_bool_t		ni_iaid_map_to_vars(const ni_iaid_map_t *map, ni_var_array_t *vars);
extern ni_bool_t		ni_iaid_map_get_iaid(const ni_iaid_map_t *map, const char *name, unsigned int *iaid);
extern ni_bool_t		ni_iaid_map_get_name(const ni_iaid_map_t *map, unsigned int iaid, const char **name);
extern ni_bool_t		ni_iaid_map_set(ni_iaid_map_t *map, const char *name, unsigned int iaid);
extern ni_bool_t		ni_iaid_map_del_name(ni_iaid_map_t *map, const char *name);
extern ni_bool_t		ni_iaid_map_del_iaid(ni_iaid_map_t *map, unsigned int iaid);

#endif /* WICKED_IAID_H */
