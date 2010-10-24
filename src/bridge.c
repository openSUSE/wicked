/*
 * Handing bridge interfaces.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include "netinfo_priv.h"

#define NI_BRIDGE_VALUE_NOT_SET		~0U
#define NI_BRIDGE_PORT_ARRAY_CHUNK	16

static int			__ni_bridge_str_to_uint(const char *, unsigned int *);
static int			__ni_bridge_uint_to_str(unsigned int, char **);
static int			__ni_bridge_str_to_time(const char *, unsigned long *);
static int			__ni_bridge_time_to_str(unsigned long, char **);

static ni_bridge_port_t *	__ni_bridge_port_create(const char *);
static ni_bridge_port_t *	__ni_bridge_port_clone(const ni_bridge_port_t *);
static void			__ni_bridge_port_destroy(ni_bridge_port_t *);

static void			ni_bridge_port_array_init(ni_bridge_port_array_t *);
static int			ni_bridge_port_array_copy(ni_bridge_port_array_t *,
					const ni_bridge_port_array_t *);
static void			ni_bridge_port_array_destroy(ni_bridge_port_array_t *);
static void			__ni_bridge_port_array_realloc(ni_bridge_port_array_t *,
					unsigned int);
static int			__ni_bridge_port_array_append(ni_bridge_port_array_t *,
					ni_bridge_port_t *);



/*
 * Bridge option value conversion utilities
 * Returns -1 on error, 0 if the value is not set, and 1 otherwise.
 */
static int
__ni_bridge_str_to_uint(const char *str, unsigned int *val)
{
	if (!str || !*str) {
		*val = NI_BRIDGE_VALUE_NOT_SET;
		return 0;
	} else {
		char *end = NULL;
		unsigned int i = strtoul(str, &end, 0);

		if (*end == '\0') {
			*val = i;
			return 1;
		}
	}
	return -1;
}

static int
__ni_bridge_uint_to_str(unsigned int val, char **str)
{
	if (val == NI_BRIDGE_VALUE_NOT_SET) {
		ni_string_free(str);
		return 0;
	} else {
		char   buf[32];

		snprintf(buf, sizeof(buf), "%u", val);
		ni_string_dup(str, buf);
		return *str ? 1 : -1;
	}
}

static int
__ni_bridge_str_to_time(const char *str, unsigned long *val)
{
	if (!str || !*str) {
		*val = NI_BRIDGE_VALUE_NOT_SET;
		return 0;
	} else {
		char *end = NULL;
		double d = strtod(str, &end);

		if (*end == '\0') {
			*val = (unsigned long)(d * 100);
			return 1;
		}
	}
	return -1;
}

static int
__ni_bridge_time_to_str(unsigned long val, char **str)
{
	if (val == NI_BRIDGE_VALUE_NOT_SET) {
		ni_string_free(str);
		return 0;
	} else {
		char   buf[32];
		double d = (double)val;

		snprintf(buf, sizeof(buf), "%.2lf", (d / 100));
		ni_string_dup(str, buf);
		return *str ? 1 : -1;
	}
}

static ni_bridge_port_t *
__ni_bridge_port_create(const char *name)
{
	ni_bridge_port_t *newport;

	newport = calloc(1, sizeof(ni_bridge_port_t));
	if (!newport)
		ni_fatal("%s: out of memory", __FUNCTION__);

	ni_string_dup(&newport->name, name);
	newport->config.priority = NI_BRIDGE_VALUE_NOT_SET;
	newport->config.path_cost = NI_BRIDGE_VALUE_NOT_SET;
	return newport;
}

static ni_bridge_port_t *
__ni_bridge_port_clone(const ni_bridge_port_t *port)
{
	ni_bridge_port_t *newport;

	newport = __ni_bridge_port_create(port->name);
	memcpy(&newport->config, &port->config, sizeof(newport->config));
	return newport;
}

static void
__ni_bridge_port_destroy(ni_bridge_port_t *port)
{
	if (port->name)
		free(port->name);
	if (port->device)
		ni_interface_put(port->device);
	if (port->status)
		ni_bridge_port_status_free(port->status);
	free(port);
}

static void
ni_bridge_port_array_init(ni_bridge_port_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

static int
ni_bridge_port_array_copy(ni_bridge_port_array_t *dst, const ni_bridge_port_array_t *src)
{
	unsigned int i;
	ni_bridge_port_array_destroy(dst);
	for (i = 0; i < src->count; ++i) {
		if (__ni_bridge_port_array_append(dst,
			__ni_bridge_port_clone(src->data[i])) < 0)
			return -1;
	}
	return 0;
}

static void
ni_bridge_port_array_destroy(ni_bridge_port_array_t *array)
{
	while (array->count > 0)
		__ni_bridge_port_destroy(array->data[--array->count]);
	free(array->data);
	ni_bridge_port_array_init(array);
}

static void
__ni_bridge_port_array_realloc(ni_bridge_port_array_t *array, unsigned int newsize)
{
	ni_bridge_port_t **newdata;
	unsigned int i;

	newsize = (newsize + NI_BRIDGE_PORT_ARRAY_CHUNK);
	newdata = realloc(array->data, newsize * sizeof(ni_bridge_port_t));
	if (!newdata)
		ni_fatal("%s: out of memory", __FUNCTION__);

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
__ni_bridge_port_array_index(ni_bridge_port_array_t *array, const char *port)
{
	unsigned int i;
	for (i = 0; i < array->count; ++i) {
		if (!strcmp(port, array->data[i]->name))
			return i;
	}
	return -1;
}

static int
ni_bridge_port_array_remove_index(ni_bridge_port_array_t *array, unsigned int pos)
{
	unsigned int i;

	if (pos >= array->count)
		return -1;

	__ni_bridge_port_destroy(array->data[pos]);
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
 * Add a port to the bridge configuration
 */
int
ni_bridge_add_port(ni_bridge_t *bridge, const char *ifname)
{
	if (!ifname || !*ifname)
		return -1;

	if (__ni_bridge_port_array_index(&bridge->ports, ifname) < 0) {
		return __ni_bridge_port_array_append(&bridge->ports,
			__ni_bridge_port_create(ifname));
	}
	return -1;
}

int
ni_bridge_del_port(ni_bridge_t *bridge, const char *ifname)
{
	unsigned int i;
	for (i = 0; i < bridge->ports.count; ++i) {
		if (!strcmp(bridge->ports.data[i]->name, ifname)) {
			ni_bridge_port_array_remove_index(&bridge->ports, i);
			return 0;
		}
	}
	return -1;
}

void
ni_bridge_get_port_names(const ni_bridge_t *bridge, ni_string_array_t *ports)
{
	unsigned int i;

	for (i = 0; i < bridge->ports.count; ++i)
		ni_string_array_append(ports, bridge->ports.data[i]->name);
}

/*
 * Get bridge options
 */
int
ni_bridge_get_stp(ni_bridge_t *bridge, char **value)
{
	if (bridge->config.stp_enabled == NI_BRIDGE_NO_STP)
		ni_string_dup(value, "off");
	else
		ni_string_dup(value, "on");
	return *value ? 1 : 0;
}

int
ni_bridge_get_forward_delay(ni_bridge_t *bridge, char **value)
{
	return __ni_bridge_time_to_str(bridge->config.forward_delay, value);
}

int
ni_bridge_get_ageing_time(ni_bridge_t *bridge, char **value)
{
	return __ni_bridge_time_to_str(bridge->config.ageing_time, value);
}

int
ni_bridge_get_hello_time(ni_bridge_t *bridge, char **value)
{
	return __ni_bridge_time_to_str(bridge->config.hello_time, value);
}

int
ni_bridge_get_max_age(ni_bridge_t *bridge, char **value)
{
	return __ni_bridge_time_to_str(bridge->config.max_age, value);
}

int
ni_bridge_get_priority(ni_bridge_t *bridge, char **value)
{
	return __ni_bridge_uint_to_str(bridge->config.priority, value);
}

int
ni_bridge_get(ni_bridge_t *bridge, unsigned int opt, char **value)
{
	switch (opt) {
	case NI_BRIDGE_STP_ENABLED:
		return ni_bridge_get_stp(bridge, value);
	case NI_BRIDGE_FORWARD_DELAY:
		return ni_bridge_get_forward_delay(bridge, value);
	case NI_BRIDGE_AGEING_TIME:
		return ni_bridge_get_ageing_time(bridge, value);
	case NI_BRIDGE_HELLO_TIME:
		return ni_bridge_get_hello_time(bridge, value);
	case NI_BRIDGE_MAX_AGE:
		return ni_bridge_get_max_age(bridge, value);
	case NI_BRIDGE_PRIORITY:
		return ni_bridge_get_priority(bridge, value);
	}
	return -1;
}

/*
 * Set bridge options
 */
int
ni_bridge_set_stp(ni_bridge_t *bridge, const char *value)
{
	/* brctl accepts "on" / "off" as well as "yes" / "no"
	 * note: it is a bool {0,!0} while write, just sysfs
	 * shows details {0=off,1=stp,2=rstp} in stp_state.
	 */
	if (!value || !*value) {
		bridge->config.stp_enabled = NI_BRIDGE_NO_STP;
		return 0;
	} else
	if (!strcmp(value, "off") || !strcmp(value, "no")) {
		bridge->config.stp_enabled = NI_BRIDGE_NO_STP;
		return 0;
	} else
	if (!strcmp(value, "on") || !strcmp(value, "yes")) {
		bridge->config.stp_enabled = NI_BRIDGE_STP;
		return 0;
	}
	return -1;
}

int
ni_bridge_set_forward_delay(ni_bridge_t *bridge, const char *value)
{
	return __ni_bridge_str_to_time(value, &bridge->config.forward_delay);
}

int
ni_bridge_set_ageing_time(ni_bridge_t *bridge, const char *value)
{
	return __ni_bridge_str_to_time(value, &bridge->config.ageing_time);
}

int
ni_bridge_set_hello_time(ni_bridge_t *bridge, const char *value)
{
	return __ni_bridge_str_to_time(value, &bridge->config.hello_time);
}

int
ni_bridge_set_max_age(ni_bridge_t *bridge, const char *value)
{
	return __ni_bridge_str_to_time(value, &bridge->config.max_age);
}

int
ni_bridge_set_priority(ni_bridge_t *bridge, const char *value)
{
	return __ni_bridge_str_to_uint(value, &bridge->config.priority);
}

int
ni_bridge_set(ni_bridge_t *bridge, unsigned int opt, const char *value)
{
	switch (opt) {
	case NI_BRIDGE_STP_ENABLED:
		return ni_bridge_set_stp(bridge, value);
	case NI_BRIDGE_FORWARD_DELAY:
		return ni_bridge_set_forward_delay(bridge, value);
	case NI_BRIDGE_AGEING_TIME:
		return ni_bridge_set_ageing_time(bridge, value);
	case NI_BRIDGE_HELLO_TIME:
		return ni_bridge_set_hello_time(bridge, value);
	case NI_BRIDGE_MAX_AGE:
		return ni_bridge_set_max_age(bridge, value);
	case NI_BRIDGE_PRIORITY:
		return ni_bridge_set_priority(bridge, value);
	}
	return -1;
}

/*
 * Get bridge port options
 */
int
ni_bridge_port_get_priority(ni_bridge_t *bridge, const char *port, char **value)
{
	int i = __ni_bridge_port_array_index(&bridge->ports, port);
	if (i < 0)
		return -1;
	return __ni_bridge_uint_to_str(bridge->ports.data[i]->config.priority, value);
}

int
ni_bridge_port_get_path_cost(ni_bridge_t *bridge, const char *port, char **value)
{
	int i = __ni_bridge_port_array_index(&bridge->ports, port);
	if (i < 0)
		return -1;
	return __ni_bridge_uint_to_str(bridge->ports.data[i]->config.path_cost, value);
}

int
ni_bridge_port_get(ni_bridge_t *bridge, const char *port, unsigned int opt, char **value)
{
	switch (opt) {
	case NI_BRIDGE_PORT_PRIORITY:
		return ni_bridge_port_get_priority(bridge, port, value);
	case NI_BRIDGE_PORT_PATH_COST:
		return ni_bridge_port_get_path_cost(bridge, port, value);
	}
	return -1;
}

/*
 * Set bridge port options
 */
int
ni_bridge_port_set_priority(ni_bridge_t *bridge, const char *port, const char *value)
{
	int i = __ni_bridge_port_array_index(&bridge->ports, port);
	if (i < 0)
		return -1;
	return __ni_bridge_str_to_uint(value, &bridge->ports.data[i]->config.priority);
}

int
ni_bridge_port_set_path_cost(ni_bridge_t *bridge, const char *port, const char *value)
{
	int i = __ni_bridge_port_array_index(&bridge->ports, port);
	if (i < 0)
		return -1;
	return __ni_bridge_str_to_uint(value, &bridge->ports.data[i]->config.path_cost);
}

int
ni_bridge_port_set(ni_bridge_t *bridge, const char *port, unsigned int opt, const char *value)
{
	switch (opt) {
	case NI_BRIDGE_PORT_PRIORITY:
		return ni_bridge_port_set_priority(bridge, port, value);
	case NI_BRIDGE_PORT_PATH_COST:
		return ni_bridge_port_set_path_cost(bridge, port, value);
	}
	return -1;
}

/*
 * Binding callback for the bridge config.
 * This looks up interface config for all ports, and binds it
 */
int
ni_bridge_bind(ni_interface_t *parent, ni_handle_t *nih)
{
	ni_bridge_t *bridge = parent->bridge;
	unsigned int i = 0;

	for (i = 0; i < bridge->ports.count; ++i) {
		ni_bridge_port_t *port = bridge->ports.data[i];
		const char *ifname = port->name;
		ni_interface_t *slave;

		if (port->device) {
			ni_interface_put(port->device);
			port->device = NULL;
		}

		slave = ni_interface_by_name(nih, ifname);
		if (slave == NULL) {
			ni_bad_reference(nih, parent, ifname);
			return -1;
		}

		port->device = ni_interface_get(slave);
		slave->parent = parent;
	}
	return 0;
}

/*
 * Create a copy of a bridge's configuration
 */
ni_bridge_t *
ni_bridge_clone(const ni_bridge_t *src)
{
	ni_bridge_t *dst;

	dst = calloc(1, sizeof(ni_bridge_t));
	if (!dst)
		return NULL;

	memcpy(&dst->config, &src->config, sizeof(dst->config));
	if (ni_bridge_port_array_copy(&dst->ports, &src->ports) < 0)
		goto failed;

	return dst;

failed:
	error("Error clonding bridge configuration");
	ni_bridge_free(dst);
	return NULL;
}

void
ni_bridge_init(ni_bridge_t *bridge)
{
	ni_bridge_port_array_destroy(&bridge->ports);

	if (bridge->status)
		ni_bridge_status_free(bridge->status);

	memset(bridge, 0, sizeof(*bridge));

	/* apply "not set" defaults */
	bridge->config.forward_delay = NI_BRIDGE_VALUE_NOT_SET;
	bridge->config.ageing_time = NI_BRIDGE_VALUE_NOT_SET;
	bridge->config.hello_time = NI_BRIDGE_VALUE_NOT_SET;
	bridge->config.max_age = NI_BRIDGE_VALUE_NOT_SET;
	bridge->config.priority = NI_BRIDGE_VALUE_NOT_SET;
}

void
ni_bridge_status_free(ni_bridge_status_t *bs)
{
	if (bs->root_id)
		free(bs->root_id);
	if (bs->bridge_id)
		free(bs->bridge_id);
	if (bs->group_addr);
		free(bs->group_addr);
	free(bs);
}

void
ni_bridge_port_status_free(ni_bridge_port_status_t *ps)
{
	if (ps->designated_root)
		free(ps->designated_root);
	if (ps->designated_bridge)
		free(ps->designated_bridge);
	free(ps);
}

/*
 * Free bridge information
 */
void
ni_bridge_free(ni_bridge_t *bridge)
{
	ni_bridge_init(bridge);
	free(bridge);
}
