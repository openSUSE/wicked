/*
 *	Routines for iBFT (iSCSI Boot Firmware Table) NIC
 *
 *	Copyright (C) 2010-2022 SUSE LLC
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
 *		Marius Tomaschewski
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/logging.h>

#include "ibft.h"
#include "util_priv.h"

/* ibft nic array chunk size */
#define NI_IBFT_NIC_ARRAY_CHUNK		2

ni_ibft_nic_t *
ni_ibft_nic_new()
{
	ni_ibft_nic_t *nic;

	nic = xcalloc(1, sizeof(*nic));
	ni_assert(nic);

	nic->users = 1;
	return nic;
}

ni_ibft_nic_t *
ni_ibft_nic_ref(ni_ibft_nic_t *nic)
{
	ni_assert(nic && nic->users);
	nic->users++;
	return nic;
}

void
ni_ibft_nic_free(ni_ibft_nic_t *nic)
{
	if (nic) {
		ni_assert(nic->users);
		nic->users--;
		if(nic->users == 0) {
			ni_string_free(&nic->node);
			ni_string_free(&nic->ifname);
			ni_string_free(&nic->devpath);
			ni_string_free(&nic->hostname);
			free(nic);
		}
	}
}

void
ni_ibft_nic_array_init(ni_ibft_nic_array_t *nics)
{
	memset(nics, 0, sizeof(*nics));
}

void
ni_ibft_nic_array_destroy(ni_ibft_nic_array_t *nics)
{
	if (nics) {
		while(nics->count--) {
			ni_ibft_nic_free(nics->data[nics->count]);
			nics->data[nics->count] = NULL;
		}
		free(nics->data);
		memset(nics, 0, sizeof(*nics));
	}
}

static void
__ni_ibft_nic_array_realloc(ni_ibft_nic_array_t *nics, unsigned int newsize)
{
	ni_ibft_nic_t **newdata;
	unsigned int   i;

	newsize = (newsize + NI_IBFT_NIC_ARRAY_CHUNK);
	newdata = realloc(nics->data, newsize * sizeof(ni_ibft_nic_t *));
	ni_assert(newdata != NULL);

	nics->data = newdata;
	for(i = nics->count; i < newsize; ++i) {
		nics->data[i] = NULL;
	}
}

void
ni_ibft_nic_array_append(ni_ibft_nic_array_t *nics, ni_ibft_nic_t *nic)
{
	if (nics && nic) {
		if((nics->count % NI_IBFT_NIC_ARRAY_CHUNK) == 0)
			__ni_ibft_nic_array_realloc(nics, nics->count);

		nics->data[nics->count++] = ni_ibft_nic_ref(nic);
	}
}
