/*
 *	DHCP6 option utilities used in addrconf / lease and supplicant
 *
 *	Copyright (C) 2010-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifndef   __WICKED_DHCP6_OPTIONS_H__
#define   __WICKED_DHCP6_OPTIONS_H__

#include <wicked/types.h>
#include <wicked/address.h>


typedef struct ni_dhcp6_status	ni_dhcp6_status_t;
typedef struct ni_dhcp6_ia_addr	ni_dhcp6_ia_addr_t;
typedef struct ni_dhcp6_ia	ni_dhcp6_ia_t;


struct ni_dhcp6_status {
	uint16_t		code;
	char *			message;
};

struct ni_dhcp6_ia_addr {
	ni_dhcp6_ia_addr_t *	next;
	unsigned int		flags;

	struct in6_addr		addr;
	uint8_t			plen;
	uint32_t		preferred_lft;
	uint32_t		valid_lft;
	ni_dhcp6_status_t	status;
};

struct ni_dhcp6_ia {
	ni_dhcp6_ia_t *		next;
	unsigned int		flags;

	uint16_t		type;
	uint32_t		iaid;
	uint32_t		time_acquired;
	uint32_t		renewal_time;
	uint32_t		rebind_time;
	ni_dhcp6_ia_addr_t *	addrs;
	ni_dhcp6_status_t	status;
};


extern ni_dhcp6_status_t *	ni_dhcp6_status_new(void);
extern void			ni_dhcp6_status_clear(ni_dhcp6_status_t *);
extern void			ni_dhcp6_status_destroy(ni_dhcp6_status_t **);


extern ni_dhcp6_ia_addr_t *	ni_dhcp6_ia_addr_new(const struct in6_addr,
							unsigned int);
extern void			ni_dhcp6_ia_addr_destory(ni_dhcp6_ia_addr_t *);

extern void			ni_dhcp6_ia_addr_list_append(ni_dhcp6_ia_addr_t **,
								ni_dhcp6_ia_addr_t *);
extern void			ni_dhcp6_ia_addr_list_destroy(ni_dhcp6_ia_addr_t **);


extern ni_dhcp6_ia_t *		ni_dhcp6_ia_new(unsigned int, unsigned int);
extern void			ni_dhcp6_ia_destroy(ni_dhcp6_ia_t *);

extern void			ni_dhcp6_ia_list_destroy(ni_dhcp6_ia_t **);
extern void			ni_dhcp6_ia_list_append(ni_dhcp6_ia_t **,
							ni_dhcp6_ia_t *);

#endif /* __WICKED_DHCP6_OPTIONS_H__ */
