/*
 * Handing bridge interfaces.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
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


#define NI_BRIDGE_PORT_ARRAY_CHUNK	16

static void			ni_bridge_port_array_init(ni_bridge_port_array_t *);
static void			ni_bridge_port_array_destroy(ni_bridge_port_array_t *);
static void			__ni_bridge_port_array_realloc(ni_bridge_port_array_t *,
					unsigned int);
static int			__ni_bridge_port_array_append(ni_bridge_port_array_t *,
					ni_bridge_port_t *);


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

void
ni_bridge_port_info_destroy(ni_bridge_port_info_t *info)
{
	if (info) {
		ni_string_free(&info->designated_root);
		ni_string_free(&info->designated_bridge);
		ni_bridge_port_info_init(info);
	}
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
	ni_bridge_port_info_destroy(info);
	free(info);
}

ni_bridge_port_t *
ni_bridge_port_new(ni_bridge_t *bridge, const char *ifname, unsigned int ifindex)
{
	ni_bridge_port_t *port;

	port = xcalloc(1, sizeof(ni_bridge_port_t));
	ni_string_dup(&port->ifname, ifname);
	port->ifindex = ifindex;
	/* apply "not set" defaults */
	port->priority = NI_BRIDGE_VALUE_NOT_SET;
	port->path_cost = NI_BRIDGE_VALUE_NOT_SET;

	if (bridge)
		__ni_bridge_port_array_append(&bridge->ports, port);
	return port;
}

ni_bridge_port_t *
ni_bridge_port_clone(const ni_bridge_port_t *src)
{
	ni_bridge_port_t *dst;

	if (src) {
		dst = ni_bridge_port_new(NULL, src->ifname, src->ifindex);
		dst->priority = src->priority;
		dst->path_cost = src->path_cost;
		return dst;
	}
	return NULL;
}

void
ni_bridge_port_free(ni_bridge_port_t *port)
{
	ni_string_free(&port->ifname);
	ni_bridge_port_info_destroy(&port->info);
	free(port);
}

static void
ni_bridge_port_array_init(ni_bridge_port_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

static void
ni_bridge_port_array_destroy(ni_bridge_port_array_t *array)
{
	while (array->count > 0)
		ni_bridge_port_free(array->data[--array->count]);
	free(array->data);
	ni_bridge_port_array_init(array);
}

static void
__ni_bridge_port_array_realloc(ni_bridge_port_array_t *array, unsigned int newsize)
{
	ni_bridge_port_t **newdata;
	unsigned int i;

	newsize = (newsize + NI_BRIDGE_PORT_ARRAY_CHUNK);
	newdata = xrealloc(array->data, newsize * sizeof(ni_bridge_port_t));
	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		array->data[i] = NULL;
}

static int
__ni_bridge_port_array_append(ni_bridge_port_array_t *array, ni_bridge_port_t *port)
{
	if ((array->count % NI_BRIDGE_PORT_ARRAY_CHUNK) == 0)
		__ni_bridge_port_array_realloc(array, array->count);

	array->data[array->count++] = port;
	return 0;
}

static int
ni_bridge_port_array_remove_index(ni_bridge_port_array_t *array, unsigned int pos)
{
	unsigned int i;

	if (pos >= array->count)
		return -1;

	ni_bridge_port_free(array->data[pos]);
	/* make it less cumbersome... */
	array->data[pos] = NULL;
	for (i = pos + 1; i < array->count; ++i) {
		array->data[i - 1] = array->data[i];
		array->data[i] = NULL;
	}
	array->count--;
	return 0;
}

/*
 * Locate a port given its name or index
 */
ni_bridge_port_t *
ni_bridge_port_by_index(const ni_bridge_t *bridge, unsigned int ifindex)
{
	ni_bridge_port_t **pp, *port;
	unsigned int i;

	for (i = 0, pp = bridge->ports.data; i < bridge->ports.count; ++i) {
		port = *pp++;
		if (port->ifindex == ifindex)
			return port;
	}
	return NULL;
}

ni_bridge_port_t *
ni_bridge_port_by_name(const ni_bridge_t *bridge, const char *ifname)
{
	ni_bridge_port_t **pp, *port;
	unsigned int i;

	if (ifname == NULL)
		return NULL;

	for (i = 0, pp = bridge->ports.data; i < bridge->ports.count; ++i) {
		port = *pp++;
		if (ni_string_eq(port->ifname, ifname))
			return port;
	}
	return NULL;
}

/*
 * Add a port to the bridge configuration
 * Note, in case of success, the bridge will have taken ownership of the port object.
 */
int
ni_bridge_add_port(ni_bridge_t *bridge, ni_bridge_port_t *port)
{
	if (!port)
		return -1;

	if (port->ifindex && ni_bridge_port_by_index(bridge, port->ifindex))
		return -1;
	if (port->ifname && ni_bridge_port_by_name(bridge, port->ifname))
		return -1;

	__ni_bridge_port_array_append(&bridge->ports, port);
	return 0;
}


int
ni_bridge_del_port(ni_bridge_t *bridge, unsigned int pos)
{
	return ni_bridge_port_array_remove_index(&bridge->ports, pos);
}

int
ni_bridge_del_port_ifname(ni_bridge_t *bridge, const char *ifname)
{
	ni_bridge_port_t **pp, *port;
	unsigned int i;

	for (i = 0, pp = bridge->ports.data; i < bridge->ports.count; ++i) {
		port = *pp++;
		if (ni_string_eq(port->ifname, ifname)) {
			ni_bridge_port_array_remove_index(&bridge->ports, i);
			return 0;
		}
	}
	return -1;
}

int
ni_bridge_del_port_ifindex(ni_bridge_t *bridge, unsigned int ifindex)
{
	ni_bridge_port_t **pp, *port;
	unsigned int i;

	for (i = 0, pp = bridge->ports.data; i < bridge->ports.count; ++i) {
		port = *pp++;
		if (port->ifindex == ifindex) {
			ni_bridge_port_array_remove_index(&bridge->ports, i);
			return 0;
		}
	}
	return -1;
}

void
ni_bridge_get_port_names(const ni_bridge_t *bridge, ni_string_array_t *names)
{
	unsigned int i;

	if (!bridge || !names)
		return;
	for (i = 0; i < bridge->ports.count; ++i) {
		ni_bridge_port_t *port = bridge->ports.data[i];
		if (port && port->ifname && *port->ifname)
			ni_string_array_append(names, port->ifname);
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
	ni_bridge_port_array_destroy(&bridge->ports);
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

void
ni_bridge_ports_destroy(ni_bridge_t *bridge)
{
	ni_bridge_port_array_destroy(&bridge->ports);
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
ni_bridge_port_validate(const ni_bridge_port_t *port)
{
	if (!port || !port->ifname)
		return "uninitialized port configuration";

	if (port->priority != NI_BRIDGE_VALUE_NOT_SET &&
	    port->priority > NI_BRIDGE_PORT_PRIORITY_MAX)
		return "bridge port priority is out of supported range (0-63)";

	if (port->path_cost != NI_BRIDGE_VALUE_NOT_SET &&
	   (port->path_cost < NI_BRIDGE_PORT_PATH_COST_MIN ||
	    port->path_cost > NI_BRIDGE_PORT_PATH_COST_MAX))
		return "bridge port priority is out of supported range (0-65535)";

	return NULL;
}

const char *
ni_bridge_validate(const ni_bridge_t *bridge)
{
	unsigned int i;

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

	if (bridge->ports.count > NI_BRIDGE_PORT_MAX_COUNT)
		return "bridge port count is higher than supported (0-1024)";

	for (i = 0; i < bridge->ports.count; ++i) {
		const char *err = ni_bridge_port_validate(bridge->ports.data[i]);
		if (err != NULL)
			return err;
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
