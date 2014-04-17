/*
 *	Routines for handling tunneling (sit, ipip, gre) device settings
 *
 *	Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Karol Mroz <kmroz@suse.com>
 */

#ifndef   __WICKED_TUNNELING_H__
#define   __WICKED_TUNNELING_H__

#include <wicked/types.h>

enum {
	NI_TUNNELING_LOCAL = 0,
	NI_TUNNELING_REMOTE,
	NI_TUNNELING_TTL,
	NI_TUNNELING_TOS,
	NI_TUNNELING_PMTUDISC,

	__NI_TUNNELING_MAX,
};

/* Generic tunnel struct.
 * ttl, tos and pmtudisc are u8 from netlink, but stored as u16 and boolean
 * for better dbus output formatting.
 */
struct ni_tunnel {
	uint16_t	ttl;
	uint16_t	tos;
	ni_bool_t	pmtudisc;
};


struct ni_sit {
	unsigned int ifla_map[__NI_TUNNELING_MAX];
	ni_tunnel_t tunnel;
};

/* ttl, tos and pmtudisc are u8 from netlink, but stored as u16 and boolean
 * for better dbus output formatting.
 */
struct ni_ipip {
	unsigned int ifla_map[__NI_TUNNELING_MAX];
	ni_tunnel_t tunnel;
};

/* ttl, tos and pmtudisc are u8 from netlink, but stored as u16 and boolean
 * for better dbus output formatting.
 */
struct ni_gre {
	unsigned int ifla_map[__NI_TUNNELING_MAX];
	ni_tunnel_t tunnel;
};

extern ni_sit_t *	ni_sit_new(void);
extern void		ni_sit_free(ni_sit_t *);
extern const char *	ni_sit_validate(const ni_sit_t *);

extern ni_ipip_t *	ni_ipip_new(void);
extern void		ni_ipip_free(ni_ipip_t *);
extern const char *	ni_ipip_validate(const ni_ipip_t *);

extern ni_gre_t *	ni_gre_new(void);
extern void		ni_gre_free(ni_gre_t *);
extern const char *	ni_gre_validate(const ni_gre_t *);

#endif /* __WICKED_TUNNELING_H__ */
