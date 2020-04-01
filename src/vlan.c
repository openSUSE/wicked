/*
 *	Routines for handling VLAN devices.
 *
 *	Copyright (C) 2009-2013 SÜSE LINUX Products GmbH, Nuernberg, Germany.
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <wicked/vlan.h>
#include <wicked/netinfo.h>
#include "util_priv.h"

#ifdef HAVE_LINUX_VLAN_H
#include <linux/if_vlan.h>
#endif

#ifndef VLAN_VID_MASK
#define	VLAN_VID_MASK	0x0fff
#endif

/*
 * Map of vlan protocol to names
 */
static const ni_intmap_t	__map_vlan_protocol[] = {
	{ "ieee802-1Q",		NI_VLAN_PROTOCOL_8021Q	},
	{ "ieee802-1ad",	NI_VLAN_PROTOCOL_8021AD	},

	{ NULL,			0			}
};


/*
 * Create a new VLAN device
 */
ni_vlan_t *
ni_vlan_new(void)
{
	ni_vlan_t *vlan;

	vlan = xcalloc(1, sizeof(ni_vlan_t));
	return vlan;
}

void
ni_vlan_free(ni_vlan_t *vlan)
{
	free(vlan);
}

const char *
ni_vlan_validate(const ni_vlan_t *vlan)
{
	if (!vlan)
		return "Invalid/empty vlan configuration";

	switch (vlan->protocol) {
	case NI_VLAN_PROTOCOL_8021Q:
	case NI_VLAN_PROTOCOL_8021AD:
		/* 0 .. 4094, 0 disables VLAN filter */
		if (vlan->tag >= VLAN_VID_MASK)
			return "vlan tag not in range 1..4094";
	break;

	default:
		return "Invalid vlan protocol";
	}
	return NULL;
}

const char *
ni_vlan_protocol_to_name(unsigned int protocol)
{
	return ni_format_uint_mapped(protocol, __map_vlan_protocol);
}

ni_bool_t
ni_vlan_name_to_protocol(const char *name, unsigned int *protocol)
{
	return ni_parse_uint_mapped(name, __map_vlan_protocol, protocol) == 0;
}

