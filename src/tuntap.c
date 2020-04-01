/*
 *	Routines for handling tun/tap device settings
 *
 *	Copyright (C) 2014 SÜSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <limits.h>

#include <wicked/netinfo.h>
#include <wicked/tuntap.h>

#include "netinfo_priv.h"
#include "util_priv.h"
#include "sysfs.h"
#include "modprobe.h"


/*
 * Initialize defaults
 */
static inline void
__ni_tuntap_init(ni_tuntap_t *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
}

/*
 * Create a tun/tap config
 */
ni_tuntap_t *
ni_tuntap_new(void)
{
	ni_tuntap_t *cfg;

	cfg = xcalloc(1, sizeof(ni_tuntap_t));
	__ni_tuntap_init(cfg);

	return cfg;
}

/*
 * Free tun/tap configuration
 */
void
ni_tuntap_free(ni_tuntap_t *cfg)
{
	free(cfg);
}

/*
 * Check whether the given tun/tap settings are valid
 */
const char *
ni_tuntap_validate(const ni_tuntap_t *cfg)
{
	if (cfg == NULL)
		return "uninitialized tun/tap options";

	if (cfg->owner == -1U)
		return "Invalid/unset tun owner UID";

	if (cfg->group == -1U)
		return "Invalid tun group GID";

	return NULL;
}

/*
 * Load tun configuration from sysfs
 */
int
ni_tuntap_parse_sysfs_attrs(const char *ifname, ni_tuntap_t *cfg)
{
	static const struct {
		const char *name;
		ni_bool_t   nofail;	/* don't fail, may be missed */
	} attrs[] = {
		{ "owner",	FALSE },
		{ "group",	FALSE },
		{ NULL,		FALSE },
	};

	__ni_tuntap_init(cfg);

	if (ni_sysfs_netif_get_uint(ifname, attrs[0].name, &cfg->owner) < 0) {
		if (!attrs[0].nofail)
			return -1;
	}

	if (ni_sysfs_netif_get_uint(ifname, attrs[1].name, &cfg->group) < 0) {
		if (!attrs[1].nofail)
			return -1;
	}

	return 0;
}
