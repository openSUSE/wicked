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
	ib->pkey = NI_INFINIBAND_DEFAULT_PKEY;
	ib->mode = NI_INFINIBAND_VALUE_NOT_SET;
	ib->umcast = NI_INFINIBAND_VALUE_NOT_SET;
	return ib;
}

void
ni_infiniband_free(ni_infiniband_t *ib)
{
	if (ib) {
		free(ib);
	}
}

const char *
ni_infiniband_get_mode_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, __map_ipoib_mode);
}

ni_bool_t
ni_infiniband_get_mode_flag(const char *mode, unsigned int *fp)
{
	unsigned int flag = NI_INFINIBAND_VALUE_NOT_SET;

	if (!mode || !fp)
		return FALSE;
	if (ni_parse_uint_mapped(mode, __map_ipoib_mode, &flag) < 0)
		return FALSE;
	*fp = flag;
	return TRUE;
}

const char *
ni_infiniband_get_umcast_name(unsigned int umcast)
{
	return ni_format_uint_mapped(umcast, __map_ipoib_umcast);
}

ni_bool_t
ni_infiniband_get_umcast_flag(const char *umcast, unsigned int *fp)
{
	unsigned int flag = NI_INFINIBAND_VALUE_NOT_SET;

	if (!umcast || !fp)
		return FALSE;
	if (ni_parse_uint_maybe_mapped(umcast, __map_ipoib_umcast, &flag, 10) != 0)
		return FALSE;
	*fp = flag;
	return TRUE;
}

const char *
ni_infiniband_validate(ni_iftype_t iftype, const ni_infiniband_t *ib,
					const ni_netdev_ref_t *lowerdev)
{

	switch (iftype) {
	default:
		return "Not a valid infiniband interface type";

	case NI_IFTYPE_INFINIBAND:
		if (!ib)
			return "Invalid/empty infiniband configuration";

		if (ib->pkey != NI_INFINIBAND_DEFAULT_PKEY)
			return "Infiniband partition key supported for child interfaces only";
		if (lowerdev && !ni_string_empty(lowerdev->name))
			return "Infiniband parent supported for child interfaces only";
		break;

	case NI_IFTYPE_INFINIBAND_CHILD:
		if (!ib)
			return "Invalid/empty infiniband child configuration";

		if (!lowerdev || ni_string_empty(lowerdev->name))
			return "Infiniband parent device name required for child interfaces";

		/*
		 * we currently use sysfs, that always ORs with 0x8000,
		 * new rtnetlink code does not seem to constrain it and
		 * the children inherit parent key as default (0xffff)
		 * so we may remove this when switching to rtnetlink.
		 */
		if (ib->pkey < 0x8000 || ib->pkey == NI_INFINIBAND_DEFAULT_PKEY)
			return "Infiniband partition key not in supported range (0x8000..0xffff)";
		break;
	}

	if (ib->mode != NI_INFINIBAND_VALUE_NOT_SET &&
			ni_infiniband_get_mode_name(ib->mode) == NULL)
		return "Invalid/unsupported infiniband connection-mode";
	if (ib->umcast != NI_INFINIBAND_VALUE_NOT_SET &&
			ni_infiniband_get_umcast_name(ib->umcast) == NULL)
		return "Invalid/unsupported infiniband user-multicast policy";

	return NULL;
}

