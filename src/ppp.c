/*
 *	PPP device support
 *
 *	Copyright (C) 2016 SUSE Linux GmbH, Nuernberg, Germany.
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
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <sys/mman.h>

#include <wicked/util.h>
#include <wicked/ppp.h>
#include "util_priv.h"

/*
 * Map ppp mode names to constants
 */
static const ni_intmap_t	ni_ppp_mode_names[] = {
	{ "pppoe",		NI_PPP_MODE_PPPOE	},
	{ "pppoatm",		NI_PPP_MODE_PPPOATM	},
	{ "pptp",		NI_PPP_MODE_PPTP	},
	{ "isdn",		NI_PPP_MODE_ISDN	},
	{ "serial",		NI_PPP_MODE_SERIAL	},

	{ NULL,			-1U			}
};

const char *
ni_ppp_mode_type_to_name(ni_ppp_mode_type_t type)
{
	return ni_format_uint_mapped(type, ni_ppp_mode_names);
}

ni_bool_t
ni_ppp_mode_name_to_type(const char *name, ni_ppp_mode_type_t *type)
{
	unsigned int _type;

	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, ni_ppp_mode_names, &_type) != 0)
		return FALSE;

	*type = _type;
	return TRUE;
}

/*
 * ppp config
 */
void
ni_ppp_config_init(ni_ppp_config_t *conf)
{
	if (conf) {
		memset(conf, 0, sizeof(*conf));

		conf->idle    = -1U;
		conf->maxfail = -1U;
		conf->holdoff = -1U;

		conf->dns.usepeerdns = TRUE;

		conf->ipv4.ipcp.accept_local = TRUE;
		conf->ipv4.ipcp.accept_remote = TRUE;

		conf->ipv6.enabled = TRUE;
		conf->ipv6.ipcp.accept_local = TRUE;
	}
}

static ni_bool_t
ni_ppp_config_copy(ni_ppp_config_t *dst, const ni_ppp_config_t *src)
{
	if (!src || !dst)
		return FALSE;

	dst->demand		= src->demand;
	dst->persist		= src->persist;
	dst->idle		= src->idle;
	dst->maxfail		= src->maxfail;
	dst->holdoff		= src->holdoff;

	dst->multilink		= src->multilink;
	ni_string_dup(&dst->endpoint, src->endpoint);

	ni_string_dup(&dst->auth.hostname, src->auth.hostname);
	ni_string_dup(&dst->auth.username, src->auth.username);
	ni_string_dup(&dst->auth.password, src->auth.password);

	dst->dns		= src->dns;

	dst->ipv4		= src->ipv4;
	dst->ipv6		= src->ipv6;

	return TRUE;
}

static void
ni_ppp_config_destroy(ni_ppp_config_t *conf)
{
	if (conf) {
		ni_string_free(&conf->endpoint);

		ni_string_free(&conf->auth.hostname);
		ni_string_free(&conf->auth.username);
		ni_string_free(&conf->auth.password);

		memset(conf, 0, sizeof(*conf));
	}
}

/*
 * ppp device
 */
ni_ppp_t *
ni_ppp_new(void)
{
	ni_ppp_t *ppp;

	ppp = xcalloc(1, sizeof(*ppp));
	if (ppp) {
		ni_ppp_config_init(&ppp->config);
	}
	return ppp;
}

static void
ni_ppp_mode_destroy(ni_ppp_mode_t *mode)
{
	if (!mode)
		return;

	switch (mode->type) {
	case NI_PPP_MODE_PPPOE:
		ni_netdev_ref_destroy(&mode->pppoe.device);
		break;
	default:
		break;
	}
	memset(mode, 0, sizeof(*mode));
}

void
ni_ppp_mode_init(ni_ppp_mode_t *mode, ni_ppp_mode_type_t type)
{
	memset(mode, 0, sizeof(*mode));
	mode->type = type;
}


static inline void
ni_ppp_mode_copy(ni_ppp_mode_t *new_mode, ni_ppp_mode_t *old_mode)
{
	ni_ppp_mode_pppoe_t *new_pppoe;
	ni_ppp_mode_pppoe_t *old_pppoe;
	ni_netdev_ref_t *old_device;

	if (!new_mode || !old_mode)
		return;

	ni_ppp_mode_init(new_mode, old_mode->type);
	switch (old_mode->type) {
	case NI_PPP_MODE_PPPOE:
		new_pppoe = &new_mode->pppoe;
		old_pppoe = &old_mode->pppoe;
		old_device = &old_pppoe->device;
		ni_netdev_ref_init(&new_pppoe->device, old_device->name, old_device->index);
		break;
	default:
		break;
	}
}

ni_ppp_t *
ni_ppp_clone(ni_ppp_t *old_ppp)
{
	ni_ppp_t *new_ppp;

	if (!old_ppp)
		return NULL;

	new_ppp = ni_ppp_new();
	ni_ppp_mode_copy(&new_ppp->mode, &old_ppp->mode);
	ni_ppp_config_copy(&new_ppp->config, &old_ppp->config);
	return new_ppp;
}

static void
ni_ppp_destroy(ni_ppp_t *ppp)
{
	if (ppp) {
		ni_ppp_mode_destroy(&ppp->mode);
		ni_ppp_config_destroy(&ppp->config);
	}
}

void
ni_ppp_free(ni_ppp_t *ppp)
{
	ni_ppp_destroy(ppp);
	free(ppp);
}
