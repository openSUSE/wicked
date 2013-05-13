/*
 * infiniband handling
 *
 * Copyright (C) 2013 Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <wicked/infiniband.h>
#include <wicked/netinfo.h>
#include <wicked/util.h>
#include "util_priv.h"

/*
 * Maps for ipoib connection mode and user-multicast option values
 */
static const ni_intmap_t	__map_ipoib_mode[] = {
	{ "datagram",		NI_INFINIBAND_MODE_DATAGRAM	},
	{ "connected",		NI_INFINIBAND_MODE_CONNECTED	},
	{ NULL,			~0				},
};
static const ni_intmap_t	__map_ipoib_umcast[] = {
	{ "disallowed",		NI_INFINIBAND_UMCAST_DISALLOWED	},
	{ "allowed",		NI_INFINIBAND_UMCAST_ALLOWED	},
	{ NULL,			~0				},
};

ni_infiniband_t *
ni_infiniband_new(void)
{
	ni_infiniband_t *ib;

	ib = xcalloc(1, sizeof(*ib));
	/* Apply "not set" defaults */
	ib->pkey = 0xffff;
	ib->mode = -1;
	ib->umcast = -1;
	return ib;
}

void
ni_infiniband_free(ni_infiniband_t *ib)
{
	if (ib) {
		ni_netdev_ref_destroy(&ib->parent);
		free(ib);
	}
}

const char *
ni_infiniband_get_mode_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, __map_ipoib_mode);
}

int
ni_infiniband_get_mode_flag(const char *mode)
{
	unsigned int flag = ~0;

	if (ni_parse_uint_mapped(mode, __map_ipoib_mode, &flag) < 0)
		return -1;
	return flag;
}

const char *
ni_infiniband_get_umcast_name(unsigned int umcast)
{
	return ni_format_uint_mapped(umcast, __map_ipoib_umcast);
}

int
ni_infiniband_get_umcast_flag(const char *umcast)
{
	unsigned int flag = ~0;

	if (ni_parse_uint_mapped(umcast, __map_ipoib_umcast, &flag) < 0)
		return -1;
	return flag;
}

