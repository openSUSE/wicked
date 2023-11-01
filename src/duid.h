/*
 *	DHCP Unique Identifier (DUID)
 *
 *	DHCP Unique Identifier (DUID) utilities
 *
 *	Copyright (C) 2012-2017 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *      Authors:
 *              Marius Tomaschewski <mt@suse.de>
 *              Nirmoy Das <ndas@suse.de>
 */
#ifndef WICKED_DUID_H
#define WICKED_DUID_H

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
#define NI_DUID_TYPE_ANY	0		/* unset, not a defined type  */
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
	uint32_t		v6time;		/* second since 2000 % 2^32   */
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

typedef struct ni_duid_map	ni_duid_map_t;


extern const ni_intmap_t *	ni_duid_type_map(void);
extern const char *		ni_duid_type_to_name(unsigned int type);
extern ni_bool_t		ni_duid_type_by_name(const char *name, unsigned int *type);

extern const ni_intmap_t *	ni_duid_hwtype_map(void);
extern const char *		ni_duid_hwtype_to_name(unsigned int hwtype);
extern ni_bool_t		ni_duid_hwtype_by_name(const char *name, unsigned int *hwtype);

extern ni_bool_t		ni_duid_init_llt(ni_opaque_t *duid, unsigned short hwtype, const void *hwaddr, size_t len);
extern ni_bool_t		ni_duid_init_ll (ni_opaque_t *duid, unsigned short hwtype, const void *hwaddr, size_t len);
extern ni_bool_t		ni_duid_init_en (ni_opaque_t *duid, unsigned int enumber, const void *identifier, size_t len);
extern ni_bool_t		ni_duid_init_uuid(ni_opaque_t *duid, const ni_uuid_t *uuid);

extern ni_bool_t		ni_duid_copy (ni_opaque_t * duid, const ni_opaque_t *src);
extern void			ni_duid_clear(ni_opaque_t * duid);

extern ni_bool_t		ni_duid_parse_hex(ni_opaque_t *duid, const char *hex);
extern const char *		ni_duid_format_hex(char **hex, const ni_opaque_t *duid);

static inline const char *	ni_duid_print_hex(const ni_opaque_t *duid)
{
	return duid ? ni_print_hex(duid->data, duid->len) : NULL;
}

extern ni_bool_t		ni_duid_create_en (ni_opaque_t *duid, const char *enumber, const char *identifier);
extern ni_bool_t		ni_duid_create_ll (ni_opaque_t *duid, const char *hwtype, const char *hwaddr);
extern ni_bool_t		ni_duid_create_llt(ni_opaque_t *duid, const char *hwtype, const char *hwaddr);
extern ni_bool_t		ni_duid_create_uuid_string(ni_opaque_t *duid, const char *string);
extern ni_bool_t		ni_duid_create_uuid_machine_id(ni_opaque_t *duid, const char *filename);
extern ni_bool_t		ni_duid_create_uuid_dmi_product_id(ni_opaque_t *duid, const char *filename);
extern ni_bool_t		ni_duid_create_from_device(ni_opaque_t *duid, uint16_t type, const ni_netdev_t *dev);
extern ni_bool_t		ni_duid_create_pref_device(ni_opaque_t *duid, uint16_t type, ni_netconfig_t *nc, const ni_netdev_t *preferred);
extern ni_bool_t		ni_duid_create(ni_opaque_t *duid, uint16_t type, ni_netconfig_t *nc, const ni_netdev_t *preferred);

extern ni_bool_t		ni_duid_acquire(ni_opaque_t *duid, const ni_netdev_t *dev, ni_netconfig_t *nc, const char *requested);

extern ni_duid_map_t *		ni_duid_map_load(const char *filename);
extern ni_bool_t		ni_duid_map_save(ni_duid_map_t *map);
extern void			ni_duid_map_free(ni_duid_map_t *map);

extern ni_bool_t		ni_duid_map_get_duid(ni_duid_map_t *map, const char *name, const char **hex, ni_opaque_t *raw);
extern ni_bool_t		ni_duid_map_get_name(ni_duid_map_t *map, const char *duid, const char **name);
extern ni_bool_t		ni_duid_map_set(ni_duid_map_t *map, const char *name, const char *duid);
extern ni_bool_t		ni_duid_map_del(ni_duid_map_t *map, const char *name);
extern ni_bool_t		ni_duid_map_to_vars(ni_duid_map_t *map, ni_var_array_t *vars);

#endif /* WICKED_DUID_H */
