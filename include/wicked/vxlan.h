/*
 *	vxlan definitions
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
#ifndef WICKED_VXLAN_H
#define WICKED_VXLAN_H

#include <wicked/types.h>
#include <wicked/address.h>

struct ni_vxlan {
	uint32_t		id;
	ni_sockaddr_t		local_ip;
	ni_sockaddr_t		remote_ip;
	struct {
		uint16_t	low;
		uint16_t	high;
	}			src_port;
	uint16_t		dst_port;
	uint16_t		ttl;
	uint16_t		tos;
	uint32_t		ageing;
	uint32_t		maxaddr;
	ni_bool_t		learning;
	ni_bool_t		proxy;
	ni_bool_t		rsc;
	ni_bool_t		l2miss;
	ni_bool_t		l3miss;
	ni_bool_t		udp_csum;
	ni_bool_t		udp6_zero_csum_rx;
	ni_bool_t		udp6_zero_csum_tx;
	ni_bool_t		rem_csum_rx;
	ni_bool_t		rem_csum_tx;
	ni_bool_t		rem_csum_partial;
	ni_bool_t		collect_metadata;
	ni_bool_t		gbp;
	ni_bool_t		gpe;
};

extern ni_vxlan_t *	ni_vxlan_new(void);
extern void		ni_vxlan_free(ni_vxlan_t *);
extern const char *	ni_vxlan_validate(const ni_vxlan_t *, const ni_netdev_ref_t *);

#endif /* WICKED_VXLAN_H */
