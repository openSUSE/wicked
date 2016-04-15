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

/* Generic tunnel struct.
 * ttl, tos and pmtudisc are u8 from netlink, but stored as u16 and boolean
 * for better dbus output formatting.
 */
struct ni_tunnel {
	uint16_t	ttl;
	uint16_t	tos;
	ni_bool_t	pmtudisc;
	uint16_t	iflags;
};


struct ni_sit {
	ni_tunnel_t tunnel;
	ni_bool_t isatap;
};

/* ttl, tos and pmtudisc are u8 from netlink, but stored as u16 and boolean
 * for better dbus output formatting.
 */
struct ni_ipip {
	ni_tunnel_t tunnel;
};

enum {
	/* bit number flags */
	NI_GRE_FLAG_IKEY,
	NI_GRE_FLAG_OKEY,
	NI_GRE_FLAG_ISEQ,
	NI_GRE_FLAG_OSEQ,
	NI_GRE_FLAG_ICSUM,
	NI_GRE_FLAG_OCSUM,
};

enum {
	NI_GRE_ENCAP_TYPE_NONE,
	NI_GRE_ENCAP_TYPE_FOU,
	NI_GRE_ENCAP_TYPE_GUE,
};

enum {
	/* bit number flags */
	NI_GRE_ENCAP_FLAG_CSUM,
	NI_GRE_ENCAP_FLAG_CSUM6,
	NI_GRE_ENCAP_FLAG_REMCSUM,
};

/* ttl, tos and pmtudisc are u8 from netlink, but stored as u16 and boolean
 * for better dbus output formatting.
 */
struct ni_gre {
	ni_tunnel_t	tunnel;
	uint16_t	flags;
	struct in_addr	ikey;
	struct in_addr	okey;
	struct {
		uint16_t	type;
		uint16_t	flags;
		uint16_t	sport;
		uint16_t	dport;
	} encap;
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

extern const char *	ni_gre_flag_bit_to_name(unsigned int);
extern ni_bool_t	ni_gre_flag_name_to_bit(const char *, unsigned int *);

extern const char *	ni_gre_encap_type_to_name(unsigned int);
extern ni_bool_t	ni_gre_encap_name_to_type(const char *, unsigned int *);

extern const char *	ni_gre_encap_flag_bit_to_name(unsigned int);
extern ni_bool_t	ni_gre_encap_flag_name_to_bit(const char *, unsigned int *);

#endif /* __WICKED_TUNNELING_H__ */
