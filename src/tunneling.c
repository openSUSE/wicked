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

#include <wicked/netinfo.h>
#include <wicked/util.h>
#include <wicked/tunneling.h>
#include "util_priv.h"

ni_sit_t *
ni_sit_new(void)
{
	ni_sit_t *sit;

	sit = xcalloc(1, sizeof(*sit));
	return sit;
}

void
ni_sit_free(ni_sit_t *sit)
{
	if (sit)
		free(sit);
}

const char *
ni_sit_validate(const ni_sit_t *sit)
{
	if (!sit)
		return "Unintialized sit configuration";

	return NULL;
}

ni_tunnel_t *
ni_tunnel_new(void)
{
	ni_tunnel_t *tunnel;

	tunnel = xcalloc(1, sizeof(*tunnel));
	return tunnel;
}

void
ni_tunnel_free(ni_tunnel_t *tunnel)
{
	if (tunnel)
		free(tunnel);
}

const char *
ni_tunnel_validate(const ni_tunnel_t *tunnel)
{
	if (!tunnel)
		return "Unintialized tunnel configuration";

	return NULL;
}

ni_gre_t *
ni_gre_new(void)
{
	ni_gre_t *gre;

	gre = xcalloc(1, sizeof(*gre));
	return gre;
}

void
ni_gre_free(ni_gre_t *gre)
{
	if (gre)
		free(gre);
}

const char *
ni_gre_validate(const ni_gre_t *gre)
{
	if (!gre)
		return "Unintialized gre configuration";

	return NULL;
}
