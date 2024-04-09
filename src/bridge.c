/*
 *	bridge interface handling
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2023 SUSE LLC
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
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/bridge.h>
#include <wicked/xml.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "limits.h"

#include <linux/if_bridge.h>


static ni_bool_t
ni_bridge_port_config_init(ni_bridge_port_config_t *conf)
{
	if (conf) {
		/* apply "not set" defaults */
		conf->priority = NI_BRIDGE_VALUE_NOT_SET;
		conf->path_cost = NI_BRIDGE_VALUE_NOT_SET;
		return TRUE;
	}
	return FALSE;
}

ni_bridge_port_config_t *
ni_bridge_port_config_new(void)
{
	ni_bridge_port_config_t *conf;

	conf = malloc(sizeof(*conf));
	if (ni_bridge_port_config_init(conf))
		return conf;

	free(conf);
	return NULL;
}

void
ni_bridge_port_config_free(ni_bridge_port_config_t *conf)
{
	ni_bridge_port_config_init(conf);
	free(conf);
}

static ni_bool_t
ni_bridge_port_info_init(ni_bridge_port_info_t *info)
{
	if (info) {
		memset(info, 0, sizeof(*info));
		/* apply "not set" defaults */
		info->priority = NI_BRIDGE_VALUE_NOT_SET;
		info->path_cost = NI_BRIDGE_VALUE_NOT_SET;
		return TRUE;
	}
	return FALSE;
}

ni_bridge_port_info_t *
ni_bridge_port_info_new(void)
{
	ni_bridge_port_info_t *info;

	info = malloc(sizeof(*info));
	if (ni_bridge_port_info_init(info))
		return info;

	free(info);
	return NULL;
}

void
ni_bridge_port_info_free(ni_bridge_port_info_t *info)
{
	if (info) {
		ni_string_free(&info->designated_root);
		ni_string_free(&info->designated_bridge);
		ni_bridge_port_info_init(info);
		free(info);
	}
}

/*
 * Bridge constructor and new operator
 */
static void
__ni_bridge_init(ni_bridge_t *bridge)
{
	/* apply "not set" defaults */
	bridge->stp = FALSE;
	bridge->forward_delay = NI_BRIDGE_VALUE_NOT_SET;
	bridge->ageing_time = NI_BRIDGE_VALUE_NOT_SET;
	bridge->hello_time = NI_BRIDGE_VALUE_NOT_SET;
	bridge->max_age = NI_BRIDGE_VALUE_NOT_SET;
	bridge->priority = NI_BRIDGE_VALUE_NOT_SET;
}

ni_bridge_t *
ni_bridge_new(void)
{
	ni_bridge_t *bridge;

	bridge = xcalloc(1, sizeof(*bridge));
	__ni_bridge_init(bridge);
	return bridge;
}

/*
 * Bridge destructor and delete operator
 */
static void
__ni_bridge_destroy(ni_bridge_t *bridge)
{
	ni_bridge_status_destroy(&bridge->status);
}

void
ni_bridge_free(ni_bridge_t *bridge)
{
	__ni_bridge_destroy(bridge);
	free(bridge);
}

void
ni_bridge_status_destroy(ni_bridge_status_t *bs)
{
	ni_string_free(&bs->root_id);
	ni_string_free(&bs->bridge_id);
	ni_string_free(&bs->group_addr);
	memset(bs, 0, sizeof(*bs));
}

/*
 * From IEEE 802.1D-1998, 8.10.2 (STP):
 * 				Recommended	Fixed value	Range
 * 	Bridge Hello Time:	 2.0		--		1.0 - 10.0
 * 	Bridge Max Age:		20.0		--		6.0 - 40.0
 * 	Bridge Forward Delay:	15.0		--		4.0 - 30.0
 * 	Hold Time:		--		1.0		--
 *
 * 	Bridge Priority:	32 768		0 - 65535
 * 	Port Priority:		128		0 - 255

 * 	Port Path Cost is 16bit, depends on link speed, range: 1-65535
 *
 * From IEEE 802.1D-2004, 17.14 (RSTP):
 * 				Recommended	Permitted	Compatibility
 * 	Migrate Time:		 3.0		--		--
 * 	Bridge Hello Time:	 2.0		--		1.0 -  2.0
 * 	Bridge Max Age:		20.0		6.0 - 40.0	6.0 - 40.0
 * 	Bridge Forward Delay:	15.0		4.0 - 30.0	4.0 - 30.0
 * 	Transmit Hold Count:	 6		1   - 10	1   - 10
 *
 * 				Recommended	Range
 * 	Bridge Priority:	32 768		0 - 61440 in steps of 4096
 * 	Port Priority:		128		0 - 240   in steps of 16
 *
 * 	Port Path Cost is 32bit, range: 1-200 000 000
 *
 * Linux kernel 3.7.10 bridge v2.3:
 * 				Default		Permitted:
 * 	Bridge Hello Time:	  2 HZ		1 - 10 HZ
 * 	Bridge Forward Delay:	 15 HZ		2 - 30 HZ
 * 	Bridge Max Age:		 20 HZ		6 - 60 HZ
 *
 *	Port Count:		-		1024
 * 	Port Priority:		128		0 - 63
 * 	Port Path Cost is 16bit, range: 1-65535
 *
 * The following are the "hard-coded" limits we use:
 */
#define NI_BRIDGE_PRIORITY_MIN		0
#define NI_BRIDGE_PRIORITY_MAX		USHRT_MAX

#define NI_BRIDGE_AGEING_TIME_MIN	0
#define NI_BRIDGE_AGEING_TIME_MAX	UINT_MAX/100

#define NI_BRIDGE_FORWARD_DELAY_MIN	2
#define NI_BRIDGE_FORWARD_DELAY_MAX	30
#define NI_BRIDGE_FORWARD_DELAY_DEFAULT	15

#define NI_BRIDGE_HELLO_TIME_MIN	1
#define NI_BRIDGE_HELLO_TIME_MAX	10
#define NI_BRIDGE_HELLO_TIME_DEFAULT	2

#define NI_BRIDGE_MAX_AGE_MIN		6
#define NI_BRIDGE_MAX_AGE_MAX		60
#define NI_BRIDGE_MAX_AGE_DEFAULT	20

#define NI_BRIDGE_PORT_PRIORITY_MIN	0
#define NI_BRIDGE_PORT_PRIORITY_MAX	63	/* kernel */

#define NI_BRIDGE_PORT_PATH_COST_MIN	1
#define NI_BRIDGE_PORT_PATH_COST_MAX	USHRT_MAX

#define NI_BRIDGE_PORT_MAX_COUNT	1024

const char *
ni_bridge_port_priority_validate(unsigned int priority)
{
	if (priority != NI_BRIDGE_VALUE_NOT_SET &&
	    priority > NI_BRIDGE_PORT_PRIORITY_MAX)
		return "bridge port priority is out of supported range (0-63)";

	return NULL;
}

const char *
ni_bridge_port_path_cost_validate(unsigned int path_cost)
{
	if (path_cost != NI_BRIDGE_VALUE_NOT_SET &&
	    (path_cost < NI_BRIDGE_PORT_PATH_COST_MIN ||
	     path_cost > NI_BRIDGE_PORT_PATH_COST_MAX))
		return "bridge port path-cost is out of supported range (0-65535)";

	return NULL;
}

const char *
ni_bridge_validate(const ni_bridge_t *bridge)
{
	if (!bridge)
		return "uninitialized bridge configuration";

	if (bridge->priority != NI_BRIDGE_VALUE_NOT_SET &&
	    bridge->priority > NI_BRIDGE_PRIORITY_MAX)
		return "bridge priority is out of 0-65535 range";

	if (bridge->ageing_time != NI_BRIDGE_VALUE_NOT_SET &&
	   (bridge->ageing_time < NI_BRIDGE_AGEING_TIME_MIN ||
	    bridge->ageing_time > NI_BRIDGE_AGEING_TIME_MAX))
		return "bridge ageing-time is out of supported range (0-UINT_MAX)";

	if (bridge->stp) {
		if (bridge->forward_delay != NI_BRIDGE_VALUE_NOT_SET &&
		   (bridge->forward_delay < NI_BRIDGE_FORWARD_DELAY_MIN ||
		    bridge->forward_delay > NI_BRIDGE_FORWARD_DELAY_MAX))
			return "bridge forward-delay is out of supported range (2.0-30.0)";

		if (bridge->hello_time != NI_BRIDGE_VALUE_NOT_SET &&
		   (bridge->hello_time < NI_BRIDGE_HELLO_TIME_MIN ||
		    bridge->hello_time > NI_BRIDGE_HELLO_TIME_MAX))
			return "bridge hello-time is out of supported range (0.0-10.0)";

		if (bridge->max_age != NI_BRIDGE_VALUE_NOT_SET &&
		   (bridge->max_age < NI_BRIDGE_MAX_AGE_MIN ||
		    bridge->max_age > NI_BRIDGE_MAX_AGE_MAX))
			return "bridge max-age is out of supported range (0.0-60.0)";
	} else {
		if (bridge->forward_delay != NI_BRIDGE_VALUE_NOT_SET &&
		   (bridge->forward_delay < 0 ||
		    bridge->forward_delay > NI_BRIDGE_FORWARD_DELAY_MAX))
			return "bridge forward-delay is out of supported range (0.0-30.0)";

		if (bridge->hello_time != NI_BRIDGE_VALUE_NOT_SET &&
		   (bridge->hello_time < 0 ||
		    bridge->hello_time > NI_BRIDGE_HELLO_TIME_MAX))
			return "bridge hello-time is out of supported range (0.0-10.0)";

		if (bridge->max_age != NI_BRIDGE_VALUE_NOT_SET &&
		   (bridge->max_age < 0 ||
		    bridge->max_age > NI_BRIDGE_MAX_AGE_MAX))
			return "bridge max-age is out of supported range (0.0-60.0)";
	}

	return NULL;
}

static unsigned int
ni_bridge_waittime(const ni_bridge_t *bridge)
{
	double forward_delay = 0;
	double max_age = 0;

	if (bridge && bridge->stp) {
		if (bridge->forward_delay != NI_BRIDGE_VALUE_NOT_SET)
			forward_delay = bridge->forward_delay;
		else
			forward_delay = NI_BRIDGE_FORWARD_DELAY_DEFAULT;
		if (bridge->max_age != NI_BRIDGE_VALUE_NOT_SET)
			max_age = bridge->max_age;
		else
			max_age = NI_BRIDGE_MAX_AGE_DEFAULT;
	}
	return (unsigned int)(max_age + (forward_delay * 2.0));
}

unsigned int
ni_bridge_waittime_from_xml(const xml_node_t *brnode)
{
	unsigned int waittime = 0;
	ni_bridge_t bridge;
	xml_node_t *child;

	if (xml_node_is_empty(brnode))
		return waittime;

	__ni_bridge_init(&bridge);
	for (child = brnode->children; child; child = child->next) {
		if (ni_string_eq(child->name, "stp")) {
			if (ni_parse_boolean(child->cdata, &bridge.stp))
				continue;
		} else
		if (ni_string_eq(child->name, "forward-delay")) {
			if (ni_parse_double(child->cdata, &bridge.forward_delay))
				continue;

			if (bridge.forward_delay > NI_BRIDGE_FORWARD_DELAY_MAX)
				bridge.forward_delay = NI_BRIDGE_FORWARD_DELAY_MAX;
			else
			if (bridge.forward_delay < NI_BRIDGE_FORWARD_DELAY_MIN)
				bridge.forward_delay = NI_BRIDGE_FORWARD_DELAY_MIN;
		} else
		if (ni_string_eq(child->name, "max-age")) {
			if (ni_parse_double(child->cdata, &bridge.max_age))
				continue;

			if (bridge.max_age > NI_BRIDGE_MAX_AGE_MAX)
				bridge.max_age = NI_BRIDGE_MAX_AGE_MAX;
			else
			if (bridge.max_age < NI_BRIDGE_MAX_AGE_MIN)
				bridge.max_age = NI_BRIDGE_MAX_AGE_MIN;
		}
	}

	waittime = ni_bridge_waittime(&bridge);
	return waittime;
}

static const ni_intmap_t	ni_bridge_port_state_map[] = {
	/*
	 * just use BR_STATE constants from linux/if_bridge.h;
	 * br_port_state_names from linux/net/bridge/br_stp.c.
	 */
	{ "disabled",		BR_STATE_DISABLED		},
	{ "listening",		BR_STATE_LISTENING		},
	{ "learning",		BR_STATE_LEARNING		},
	{ "forwarding",		BR_STATE_FORWARDING		},
	{ "blocking",		BR_STATE_BLOCKING		},

	{ NULL,			-1U				}
};

const char *
ni_bridge_port_state_name(unsigned int state)
{
	return ni_format_uint_mapped(state, ni_bridge_port_state_map);
}
