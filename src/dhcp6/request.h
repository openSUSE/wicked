/*
 *	DHCP6 request properties
 *
 *	Copyright (C) 2019 SÜSE Software Solutions Germany GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifndef   WICKED_DHCP6_REQUEST_H
#define   WICKED_DHCP6_REQUEST_H

#include <wicked/types.h>

/*
 * -- prefix request
 *
 * RFC7550 describes handling of multiple IAs (NA + PD)
 * in a single session using one server (Section 4).
 * RFC8415 (Section 12.2) updates the original DHCPv6
 * RFC3315 and considers also multiple per-device IA-PDs
 * and collecting IA-NA/IA-PDs from multiple servers.
 *
 * Currently, we support getting one prefix for subnets
 * on other devices; requesting multiple (per-device)
 * prefixes maybe added later when we find an RFC8415
 * DHCPv6 server implementation.
 * Unlike IA structure, we use device name references
 * which are resolved into IAID from our IAID database.
 */
struct ni_dhcp6_prefix_req {
	ni_dhcp6_prefix_req_t *		next;

	ni_dhcp6_ia_addr_t *		hints;
#if 0
	ni_netdev_ref_t			device; /* iaid from db */
#endif
};

extern ni_dhcp6_prefix_req_t *		ni_dhcp6_prefix_req_new(void);
extern void				ni_dhcp6_prefix_req_free(ni_dhcp6_prefix_req_t *);

extern ni_bool_t			ni_dhcp6_prefix_req_list_append(ni_dhcp6_prefix_req_t **,
									ni_dhcp6_prefix_req_t *);
extern void				ni_dhcp6_prefix_req_list_destroy(ni_dhcp6_prefix_req_t **);

#endif /* WICKED_DHCP6_REQUEST_H */
