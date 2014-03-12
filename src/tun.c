/*
 *	DBus encapsulation for tun/tap interfaces
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
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <limits.h>

#include <wicked/netinfo.h>
#include <wicked/tun.h>

#include "netinfo_priv.h"
#include "util_priv.h"
#include "sysfs.h"
#include "modprobe.h"


/*
 * Initialize defaults
 */
static inline void
__ni_tun_init(ni_tun_t *tun)
{
	memset(tun, 0, sizeof(*tun));
	tun->persistent = TRUE;
}

/*
 * Create a tun config
 */
ni_tun_t *
ni_tun_new(void)
{
	ni_tun_t *tun;

	tun = xcalloc(1, sizeof(ni_tun_t));
	__ni_tun_init(tun);

	return tun;
}

/*
 * Free tun configuration
 */
void
ni_tun_free(ni_tun_t *tun)
{
	free(tun);
}

/*
 * Check whether the given tun settings are valid
 */
const char *
ni_tun_validate(const ni_tun_t *tun)
{
	if (tun == NULL)
		return "uninitialized tun options";

	if (FALSE == tun->persistent)
		return "Invalid/unsupported tun persistent setting (FALSE)";

	if (tun->owner == -1u)
		return "Invalid/unset tun owner UID";

	if (tun->group == -1u)
		return "Invalid tun group GID";

	return NULL;
}

static inline gid_t
__ni_tun_normalize_group(gid_t group)
{
	return group == -1u ? 0 : group;
}

/*
 * Load tun configuration from sysfs
 */
int
ni_tun_parse_sysfs_attrs(const char *ifname, ni_tun_t *tun)
{
	static const struct {
		const char *name;
		ni_bool_t   nofail;	/* don't fail, may be missed */
	} attrs[] = {
		{ "owner",		FALSE },
		{ "group",	FALSE },
		{ NULL,			FALSE },
	};
	const char *err = NULL;

	__ni_tun_init(tun);

	if (ni_sysfs_netif_get_uint(ifname, attrs[0].name, &tun->owner) < 0) {
		if (!attrs[0].nofail)
			return -1;
	}

	if (ni_sysfs_netif_get_uint(ifname, attrs[1].name, &tun->group) < 0) {
		if (!attrs[1].nofail)
			return -1;
	}

	/* When group is unset (-1), should be normalized to GID=0 */
	tun->group = __ni_tun_normalize_group(tun->group);

	if ((err = ni_tun_validate(tun))) {
		ni_error("%s: %s", ifname, err);
		return -1;
	}

	return 0;
}
