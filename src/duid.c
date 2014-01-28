/*
 *	DHCP Unique Identifier (DUID) utilities
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <wicked/logging.h>

#include "duid.h"
#include "util_priv.h"


/*
 * compiler (gcc) specific ...
 */
#define PACKED __attribute__((__packed__))

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
} ni_duid_llt_t;

/*
 * DUID type 2, Vendor-assigned unique ID based on Enterprise Number
 *
 * http://tools.ietf.org/html/rfc3315#section-9.3
 */
typedef struct ni_duid_en {
	uint16_t		type;		/* type 2                     */
	uint32_t		enterprise;	/* vendor enterprise-number   */
	char			identifier[];	/* vendor unique identifier   */
} ni_duid_en_t;

/*
 * DUID type 3, Link-layer address
 *
 * http://tools.ietf.org/html/rfc3315#section-9.4
 */
typedef struct ni_duid_ll {
	uint16_t		type;		/* type 3                     */
	uint16_t		hwtype;		/* RFC 826 hardware type code */
	unsigned char		hwaddr[];	/* link layer address         */
} ni_duid_ll_t;

/*
 * DUID type 4, UUID-Based DHCPv6 Unique Identifier
 *
 * http://tools.ietf.org/html/rfc6355
 * http://tools.ietf.org/html/rfc4122
 */
typedef struct ni_duid_uuid {
	uint16_t		type;		/* type 4                     */
	ni_uuid_t		uuid;		/* RFC4122 UUID as bytes      */
} ni_duid_uuid_t;

/*
 * DUID typed data
 */
typedef union ni_duid_data {
	ni_duid_uuid_t		uuid;
	ni_duid_llt_t		llt;
	ni_duid_ll_t		ll;
	ni_duid_en_t		en;
} PACKED ni_duid_data_t;


ni_bool_t
ni_duid_init_llt(ni_opaque_t *duid, unsigned short arp_type, const void *hwaddr, size_t len)
{
	ni_duid_data_t *data;
	time_t		now;
	uint64_t	u64;

	memset(duid, 0, sizeof(*duid));
	if (!len)
		return FALSE;

	if (time(&now) == (time_t)-1)
		return FALSE;

	if ((sizeof(ni_duid_llt_t) + len) > sizeof(duid->data))
		len = sizeof(duid->data) - sizeof(ni_duid_llt_t);

	duid->len = sizeof(ni_duid_llt_t) + len;

	u64 = (uint64_t)(now - NI_DUID_TIME_EPOCH);
	data = (ni_duid_data_t *)&duid->data;
	data->llt.type = htons((uint16_t)NI_DUID_TYPE_LLT);
	data->llt.hwtype = htons(arp_type);
	data->llt.v6time = htonl((uint32_t)(u64 & 0xffffffff));
	memcpy(data->llt.hwaddr, hwaddr, len);
	return TRUE;
}

ni_bool_t
ni_duid_init_ll (ni_opaque_t *duid, unsigned short hwtype, const void *hwaddr, size_t len)
{
	ni_duid_data_t *data;

	memset(duid, 0, sizeof(*duid));
	if (!len)
		return FALSE;

	if ((sizeof(ni_duid_ll_t) + len) > sizeof(duid->data))
		len = sizeof(duid->data) - sizeof(ni_duid_ll_t);

	duid->len = sizeof(ni_duid_ll_t) + len;

	data = (ni_duid_data_t *)&duid->data;
	data->ll.type = htons((uint16_t)NI_DUID_TYPE_LL);
	data->ll.hwtype = htons(hwtype);
	memcpy(data->ll.hwaddr, hwaddr, len);
	return TRUE;
}

ni_bool_t
ni_duid_init_en (ni_opaque_t *duid, unsigned int enumber, const void *identifier, size_t len)
{
	ni_duid_data_t *data;

	memset(duid, 0, sizeof(*duid));
	if (!len || !enumber)
		return FALSE;

	if ((sizeof(ni_duid_en_t) + len) > sizeof(duid->data))
		len = sizeof(duid->data) - sizeof(ni_duid_en_t);

	duid->len = sizeof(ni_duid_en_t) + len;

	data = (ni_duid_data_t *)&duid->data;
	data->en.type = htons((uint16_t)NI_DUID_TYPE_EN);
	data->en.enterprise = htonl(enumber);
	memcpy(data->en.identifier, identifier, len);
	return TRUE;
}

ni_bool_t
ni_duid_init_uuid(ni_opaque_t *duid, const ni_uuid_t *uuid)
{
	ni_duid_data_t *data;

	memset(duid, 0, sizeof(*duid));
	if (ni_uuid_is_null(uuid))
		return FALSE;

	duid->len = sizeof(ni_duid_uuid_t);

	data = (ni_duid_data_t *)&duid->data;
	data->uuid.type = htons((uint16_t)NI_DUID_TYPE_UUID);
	memcpy(&data->uuid.uuid, uuid, sizeof(data->uuid.uuid));
	return TRUE;
}

void
ni_duid_clear(ni_opaque_t *duid)
{
	memset(duid, 0, sizeof(*duid));
}

ni_bool_t
ni_duid_parse_hex(ni_opaque_t *duid, const char *hex)
{
	int len;

	len = ni_parse_hex(hex, duid->data, sizeof(duid->data));
	if (len < 0 || (size_t)len <= sizeof(ni_duid_ll_t))
		return FALSE;

	return (duid->len = len) > 0;
}

const char *
ni_duid_format_hex(char **hex, const ni_opaque_t *duid)
{
	ni_string_free(hex);

	if (duid->len > 0) {
		size_t len = duid->len * 3 + 1;
		*hex = xcalloc(1, len);
		ni_format_hex(duid->data, duid->len, *hex, len);
	}
	return *hex;
}
