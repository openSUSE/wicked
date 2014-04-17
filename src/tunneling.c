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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <linux/if_tunnel.h>

#include <wicked/netinfo.h>
#include <wicked/util.h>
#include <wicked/tunneling.h>
#include <wicked/logging.h>

#include "util_priv.h"

static ni_bool_t	__ni_tunnel_map_ifla_constants(unsigned int *, unsigned int);

static ni_bool_t
__ni_tunnel_map_ifla_constants(unsigned int *ifla_map, unsigned int type)
{
	if (!ifla_map)
		return FALSE;

	switch (type) {
	case NI_IFTYPE_SIT:
	case NI_IFTYPE_IPIP:
		ifla_map[NI_TUNNELING_LOCAL] = IFLA_IPTUN_LOCAL;
		ifla_map[NI_TUNNELING_REMOTE] = IFLA_IPTUN_REMOTE;
		ifla_map[NI_TUNNELING_TTL] = IFLA_IPTUN_TTL;
		ifla_map[NI_TUNNELING_TOS] = IFLA_IPTUN_TOS;
		ifla_map[NI_TUNNELING_PMTUDISC] = IFLA_IPTUN_PMTUDISC;
		break;

	case NI_IFTYPE_GRE:
		ifla_map[NI_TUNNELING_LOCAL] = IFLA_GRE_LOCAL;
		ifla_map[NI_TUNNELING_REMOTE] = IFLA_GRE_REMOTE;
		ifla_map[NI_TUNNELING_TTL] = IFLA_GRE_TTL;
		ifla_map[NI_TUNNELING_TOS] = IFLA_GRE_TOS;
		ifla_map[NI_TUNNELING_PMTUDISC] = IFLA_GRE_PMTUDISC;
		break;

	default:
		ni_error("Unable to map constants. Unsupported tunnel type.");
		return FALSE;
	}

	return TRUE;
}

ni_sit_t *
ni_sit_new(void)
{
	ni_sit_t *sit;

	sit = xcalloc(1, sizeof(*sit));
	if (!__ni_tunnel_map_ifla_constants(sit->ifla_map, NI_IFTYPE_SIT))
		ni_sit_free(sit);

	return sit;
}

void
ni_sit_free(ni_sit_t *sit)
{
	if (sit)
		free(sit);

	sit = NULL;
}

const char *
ni_sit_validate(const ni_sit_t *sit)
{
	if (!sit)
		return "Unintialized sit configuration";

	return NULL;
}

ni_ipip_t *
ni_ipip_new(void)
{
	ni_ipip_t *ipip;

	ipip = xcalloc(1, sizeof(*ipip));
	if (!__ni_tunnel_map_ifla_constants(ipip->ifla_map, NI_IFTYPE_IPIP))
		ni_ipip_free(ipip);

	return ipip;
}

void
ni_ipip_free(ni_ipip_t *ipip)
{
	if (ipip)
		free(ipip);

	ipip = NULL;
}

const char *
ni_ipip_validate(const ni_ipip_t *ipip)
{
	if (!ipip)
		return "Unintialized ipip configuration";

	return NULL;
}

ni_gre_t *
ni_gre_new(void)
{
	ni_gre_t *gre;

	gre = xcalloc(1, sizeof(*gre));
	if (!__ni_tunnel_map_ifla_constants(gre->ifla_map, NI_IFTYPE_GRE))
		ni_gre_free(gre);

	return gre;
}

void
ni_gre_free(ni_gre_t *gre)
{
	if (gre)
		free(gre);

	gre = NULL;
}

const char *
ni_gre_validate(const ni_gre_t *gre)
{
	if (!gre)
		return "Unintialized gre configuration";

	return NULL;
}
