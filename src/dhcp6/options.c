/*
 *	DHCP6 option utilities used in addrconf / lease and supplicant
 *
 *	Copyright (C) 2010-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <wicked/util.h>
#include "dhcp6/options.h"
#include "util_priv.h"

/*
 * status
 */
ni_dhcp6_status_t *
ni_dhcp6_status_new(void)
{
	return xcalloc(1, sizeof(ni_dhcp6_status_t));
}

void
ni_dhcp6_status_clear(ni_dhcp6_status_t *status)
{
	status->code = 0;
	ni_string_free(&status->message);
}

void
ni_dhcp6_status_destroy(ni_dhcp6_status_t **status)
{
	if (status && *status) {
		ni_dhcp6_status_clear(*status);
		free(*status);
		*status = NULL;
	}
}


/*
 * ia address
 */
ni_dhcp6_ia_addr_t *
ni_dhcp6_ia_addr_new(const struct in6_addr addr, unsigned int plen)
{
	ni_dhcp6_ia_addr_t *iadr;

	iadr = xcalloc(1, sizeof(*iadr));
	iadr->addr = addr;
	iadr->plen = plen;
	return iadr;
}

void
ni_dhcp6_ia_addr_destory(ni_dhcp6_ia_addr_t *iadr)
{
	ni_dhcp6_status_clear(&iadr->status);
	free(iadr);
}


/*
 * ia address list
 */
void
ni_dhcp6_ia_addr_list_append(ni_dhcp6_ia_addr_t **list, ni_dhcp6_ia_addr_t *iadr)
{
	while (*list)
		list = &(*list)->next;
	*list = iadr;
}

void
ni_dhcp6_ia_addr_list_destroy(ni_dhcp6_ia_addr_t **list)
{
	ni_dhcp6_ia_addr_t *iadr;
	while ((iadr = *list) != NULL) {
		*list = iadr->next;
		ni_dhcp6_ia_addr_destory(iadr);
	}
}


/*
 * ia
 */
ni_dhcp6_ia_t *
ni_dhcp6_ia_new(unsigned int type, unsigned int iaid)
{
	ni_dhcp6_ia_t *ia;

	ia = xcalloc(1, sizeof(*ia));
	ia->type = type;
	ia->iaid = iaid;
	return ia;
}

void
ni_dhcp6_ia_destroy(ni_dhcp6_ia_t *ia)
{
	ni_dhcp6_status_clear(&ia->status);
	ni_dhcp6_ia_addr_list_destroy(&ia->addrs);
	free(ia);
}


/*
 * ia list
 */
void
ni_dhcp6_ia_list_destroy(ni_dhcp6_ia_t **list)
{
	ni_dhcp6_ia_t *ia;
	while ((ia = *list) != NULL) {
		*list = ia->next;
		ni_dhcp6_ia_destroy(ia);
	}
}

void
ni_dhcp6_ia_list_append(ni_dhcp6_ia_t **list, ni_dhcp6_ia_t *ia)
{
	while (*list)
		list = &(*list)->next;
	*list = ia;
}

