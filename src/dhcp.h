/*
 *	Common DHCP related utilities
 *
 *	Copyright (C) 2016 Marius Tomaschewski <mt@suse.de>
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
 */
#ifndef   WICKED_DHCP_H
#define   WICKED_DHCP_H

#include <wicked/addrconf.h>


/*
 * Generic DHCP option structure
 */
struct ni_dhcp_option {
	ni_dhcp_option_t *              next;

	unsigned int			code;
	unsigned int			len;
	unsigned char *			data;
};

extern ni_dhcp_option_t *	ni_dhcp_option_new(unsigned int, unsigned int, unsigned char *);
extern ni_bool_t		ni_dhcp_option_append(ni_dhcp_option_t *, unsigned int, unsigned char *);
extern void			ni_dhcp_option_free(ni_dhcp_option_t *);

extern void			ni_dhcp_option_list_destroy(ni_dhcp_option_t **);
extern ni_bool_t		ni_dhcp_option_list_append(ni_dhcp_option_t **, ni_dhcp_option_t *);
extern ni_dhcp_option_t *	ni_dhcp_option_list_find(ni_dhcp_option_t *, unsigned int);
extern ni_dhcp_option_t *	ni_dhcp_option_list_pull(ni_dhcp_option_t **);

#endif /* WICKED_DHCP_H */
