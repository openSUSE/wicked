/*
 *	DHCP Unique Identifier (DUID)
 *
 *	Copyright (C) 2012 Marius Tomaschewski <mt@suse.de>
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
 */
#ifndef __WICKED_DUID_H__
#define __WICKED_DUID_H__

#include <wicked/types.h>
#include <wicked/util.h>


/*
 * DUID can be not more than 128 octets long,
 *      not including the type code.
 *
 * http://tools.ietf.org/html/rfc3315#section-9.1
 * http://tools.ietf.org/html/rfc4361
 */
#define NI_DUID_TYPE_LEN	sizeof(uint16_t)
#define NI_DUID_DATA_LEN	128
#define	NI_DUID_MAX_SIZE	(NI_DUID_TYPE_LEN + NI_DUID_DATA_LEN)

/*
 * DUID (LLT type 1) generation time is in seconds since
 * midnight (UTC), January 1, 2000, modulo 2^32. This is
 * the offset in seconds since POSIX.1 time() 1970 epoch:
 *
 * http://tools.ietf.org/html/rfc3315#section-9.2
 */
#define NI_DUID_TIME_EPOCH	946684800

/*
 * Known DUID types
 *
 * http://tools.ietf.org/html/rfc3315#section-9.1
 * http://tools.ietf.org/html/rfc6355#section-6
 */
#define NI_DUID_TYPE_LLT	1
#define NI_DUID_TYPE_EN		2
#define NI_DUID_TYPE_LL		3
#define NI_DUID_TYPE_UUID	4

/*
 * We use gcc compiler specific attributes for
 * these direct access structs to duid members.
 */
#define NI_PACKED __attribute__((__packed__))

/*
 * DUID type 1, Link-layer address plus time
 *
 * http://tools.ietf.org/html/rfc3315#section-9.2
 */
typedef struct ni_duid_llt {
	uint16_t		type;		/* type 1                     */
	uint16_t		hwtype;         /* link layer address type    */
	uint32_t		v6time;		/* second since 2001 % 2^32   */
	unsigned char		hwaddr[];	/* link layer address         */
} NI_PACKED ni_duid_llt_t;

/*
 * DUID type 2, Vendor-assigned unique ID based on Enterprise Number
 *
 * http://tools.ietf.org/html/rfc3315#section-9.3
 * https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
 */
typedef struct ni_duid_en {
	uint16_t		type;		/* type 2                     */
	uint32_t		enterprise;	/* assigned enterprise-number */
	unsigned char		identifier[];	/* machine unique identifier  */
} NI_PACKED ni_duid_en_t;

/*
 * DUID type 3, Link-layer address
 *
 * http://tools.ietf.org/html/rfc3315#section-9.4
 */
typedef struct ni_duid_ll {
	uint16_t		type;		/* type 3                     */
	uint16_t		hwtype;		/* RFC 826 hardware type code */
	unsigned char		hwaddr[];	/* link layer address         */
} NI_PACKED ni_duid_ll_t;

/*
 * DUID type 4, UUID-Based DHCPv6 Unique Identifier
 *
 * http://tools.ietf.org/html/rfc6355
 * http://tools.ietf.org/html/rfc4122
 */
typedef struct ni_duid_uuid {
	uint16_t		type;		/* type 4                     */
	ni_uuid_t		uuid;		/* RFC4122 UUID as bytes      */
} NI_PACKED ni_duid_uuid_t;

#undef NI_PACKED


extern const ni_intmap_t *	ni_duid_type_map(void);
extern const char *		ni_duid_type_to_name(unsigned int type);
extern ni_bool_t		ni_duid_type_by_name(const char *name, unsigned int *type);

extern ni_bool_t		ni_duid_init_llt(ni_opaque_t *duid, unsigned short arp_type, const void *hwaddr, size_t len);
extern ni_bool_t		ni_duid_init_ll (ni_opaque_t *duid, unsigned short arp_type, const void *hwaddr, size_t len);
extern ni_bool_t		ni_duid_init_en (ni_opaque_t *duid, unsigned int enumber, const void *identifier, size_t len);
extern ni_bool_t		ni_duid_init_uuid(ni_opaque_t *duid, const ni_uuid_t *uuid);

extern ni_bool_t		ni_duid_copy (ni_opaque_t * duid, const ni_opaque_t *src);
extern void			ni_duid_clear(ni_opaque_t * duid);

extern ni_bool_t		ni_duid_parse_hex(ni_opaque_t *duid, const char *hex);
extern const char *		ni_duid_format_hex(char **hex, const ni_opaque_t *duid);

static inline const char *	ni_duid_print_hex(const ni_opaque_t *duid)
{
	return ni_print_hex(duid->data, duid->len);
}

extern int			ni_duid_load(ni_opaque_t *, const char *, const char *);
extern int			ni_duid_save(const ni_opaque_t *, const char *, const char *);

#endif /* __WICKED_DUID_H__ */
