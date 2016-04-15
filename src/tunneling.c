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

static const ni_intmap_t	ni_gre_flag_bit_names[] = {
	/* ikey + okey are intentionally unnamed */
	{ "iseq",		NI_GRE_FLAG_ISEQ		},
	{ "oseq",		NI_GRE_FLAG_OSEQ		},
	{ "icsum",		NI_GRE_FLAG_ICSUM		},
	{ "ocsum",		NI_GRE_FLAG_OCSUM		},
	{ NULL,			0				},
};

const char *
ni_gre_flag_bit_to_name(unsigned int bit)
{
	return ni_format_uint_mapped(bit, ni_gre_flag_bit_names);
}

ni_bool_t
ni_gre_flag_name_to_bit(const char *name, unsigned int *bit)
{
	 return ni_parse_uint_mapped(name, ni_gre_flag_bit_names, bit) == 0;
}

static const ni_intmap_t	ni_gre_encap_type_names[] = {
	{ "fou",		NI_GRE_ENCAP_TYPE_FOU		},
	{ "gue",		NI_GRE_ENCAP_TYPE_GUE		},
	{ NULL,			NI_GRE_ENCAP_TYPE_NONE		},
};

const char *
ni_gre_encap_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_gre_encap_type_names);
}

ni_bool_t
ni_gre_encap_name_to_type(const char *name, unsigned int *type)
{
	 return ni_parse_uint_mapped(name, ni_gre_encap_type_names, type) == 0;
}

static const ni_intmap_t	ni_gre_encap_flag_bit_names[] = {
	{ "csum",		NI_GRE_ENCAP_FLAG_CSUM		},
	{ "csum6",		NI_GRE_ENCAP_FLAG_CSUM6		},
	{ "remcsum",		NI_GRE_ENCAP_FLAG_REMCSUM	},
	{ NULL,			0				},
};

const char *
ni_gre_encap_flag_bit_to_name(unsigned int bit)
{
	return ni_format_uint_mapped(bit, ni_gre_encap_flag_bit_names);
}

ni_bool_t
ni_gre_encap_flag_name_to_bit(const char *name, unsigned int *bit)
{
	return ni_parse_uint_mapped(name, ni_gre_encap_flag_bit_names, bit) == 0;
}

