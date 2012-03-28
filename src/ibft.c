/*
 * Routines for iBFT (iSCSI Boot Firmware Table) NIC
 *
 * Copyright (C) 2011-2012 Marius Tomaschewski <mt@suse.com>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/ibft.h>
#include <wicked/logging.h>
#include <stdlib.h>

#define NI_IBFT_NIC_ARRAY_CHUNK		2

ni_ibft_nic_t *
ni_ibft_nic_new()
{
	ni_ibft_nic_t *nic;

	nic = calloc(1, sizeof(*nic));
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
	ni_assert(nic && nic->users);
	nic->users--;
	if(nic->users == 0) {
		ni_string_free(&nic->node);
		ni_string_free(&nic->ifname);
		ni_string_free(&nic->devpath);
		ni_string_free(&nic->hostname);
		free(nic);
	}
}

/* ------------------------------------------------------------------------- */

void
ni_ibft_nic_array_init(ni_ibft_nic_array_t *nics)
{
	memset(nics, 0, sizeof(*nics));
}

void
ni_ibft_nic_array_destroy(ni_ibft_nic_array_t *nics)
{
	while(nics->count--) {
		ni_ibft_nic_free(nics->data[nics->count]);
		nics->data[nics->count] = NULL;
	}
	free(nics->data);
	memset(nics, 0, sizeof(*nics));
}

static void
__ni_ibft_nic_array_realloc(ni_ibft_nic_array_t *nics, unsigned int newsize)
{
	ni_ibft_nic_t **newdata;
	unsigned int   i;

	newsize = (newsize + NI_IBFT_NIC_ARRAY_CHUNK) + 1; /* + 1 for NULL */
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
	ni_assert(nics != NULL);
	ni_assert(nic != NULL);

	if((nics->count % NI_IBFT_NIC_ARRAY_CHUNK) == 0)
		__ni_ibft_nic_array_realloc(nics, nics->count);

	nics->data[nics->count++] = ni_ibft_nic_ref(nic);
}
