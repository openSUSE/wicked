/*
 *	VXLAN interface routines.
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <wicked/vxlan.h>
#include "util_priv.h"

/*
 * Create a new VXLAN device
 */
ni_vxlan_t *
ni_vxlan_new(void)
{
	ni_vxlan_t *vxlan;

	vxlan = xcalloc(1, sizeof(ni_vxlan_t));
	if (vxlan) {
		vxlan->learning = TRUE;
		vxlan->rem_csum_partial = TRUE;
	}
	return vxlan;
}

void
ni_vxlan_free(ni_vxlan_t *vxlan)
{
	free(vxlan);
}

const char *
ni_vxlan_validate(const ni_vxlan_t *vxlan, const ni_netdev_ref_t *link)
{
	if (!vxlan)
		return "Invalid/empty vxlan configuration";

	if (vxlan->id >= 0xffffff)
		return "vxlan id not in range 0..16777215";

	if (vxlan->src_port.high < vxlan->src_port.low)
		return "vxlan src-port high is lower than src-port low";

	if (vxlan->tos > 0xff)
		return "invalid tos";

	if (vxlan->ttl > 0xff)
		return "invalid ttl";

	if (vxlan->collect_metadata && vxlan->id)
		return "vxlan id and metadata are both specified";

	if (link && ni_sockaddr_is_multicast(&vxlan->remote_ip) && ni_string_empty(link->name))
		return "multicast vxlan requires a link device";

	return NULL;
}

