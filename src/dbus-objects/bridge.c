/*
 * DBus encapsulation for bridge interfaces.
 *
 * Note, most of this is now handled via extension scripts. We only do properties
 * here, for the sake of speed.
 *
 * Copyright (C) 2011, 2012 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/bridge.h>
#include <wicked/system.h>
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static dbus_bool_t	__wicked_dbus_bridge_port_to_dict(const ni_bridge_port_t *port,
				ni_dbus_variant_t *dict,
				const ni_dbus_object_t *object,
				int config_only);
static dbus_bool_t	__wicked_dbus_bridge_port_from_dict(ni_bridge_port_t *port,
				const ni_dbus_variant_t *dict,
				DBusError *error,
				int config_only);

/*
 * Helper function to obtain bridge config from dbus object
 */
static ni_bridge_t *
__wicked_dbus_bridge_handle(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	ni_bridge_t *bridge;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return NULL;

	if (!(bridge = ni_interface_get_bridge(ifp))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting bridge handle for interface");
		return NULL;
	}
	return bridge;
}

void *
ni_objectmodel_get_bridge(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	ni_bridge_t *br;

	if (!(br = ni_interface_get_bridge(ifp))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting bridge handle for interface");
		return NULL;
	}
	return br;
}

static dbus_bool_t
__wicked_dbus_bridge_parse_stp(const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				const char *value)
{
	if (!value)
		return FALSE;
	if (!strcmp(value, "yes") || !strcmp(value, "on"))
		return ni_dbus_variant_set_int(result, 1);
	if (!strcmp(value, "no") || !strcmp(value, "off"))
		return ni_dbus_variant_set_int(result, 0);
	return ni_dbus_variant_parse(result, value, property->signature);
}

/*
 * Property ports
 */
static dbus_bool_t
__wicked_dbus_bridge_get_ports(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	ni_bridge_t *bridge;
	unsigned int i;

	if (!(bridge = __wicked_dbus_bridge_handle(object, error)))
		return FALSE;

	ni_dbus_dict_array_init(result);
	for (i = 0; i < bridge->ports.count; ++i) {
		const ni_bridge_port_t *port = bridge->ports.data[i];
		ni_dbus_variant_t *dict;

		/* Append a new element to the array */
		if (!(dict = ni_dbus_dict_array_add(result)))
			return FALSE;
		ni_dbus_variant_init_dict(dict);

		if (!__wicked_dbus_bridge_port_to_dict(port, dict, object, 0))
			return FALSE;
	}
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_bridge_set_ports(ni_dbus_object_t *object, const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument, DBusError *error)
{
	ni_dbus_variant_t *port_dict;
	ni_bridge_t *bridge;
	unsigned int i;

	if (!(bridge = __wicked_dbus_bridge_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict_array(argument))
		return FALSE;

	port_dict = argument->variant_array_value;
	for (i = 0; i < argument->array.len; ++i, ++port_dict) {
		ni_bridge_port_t *port;

		port = calloc(1, sizeof(*port));
		if (!__wicked_dbus_bridge_port_from_dict(port, port_dict, error, TRUE)) {
			ni_bridge_port_free(port);
			return FALSE;
		}

		ni_bridge_add_port(bridge, port);
		ni_bridge_port_free(port);
	}

	return TRUE;
}

/*
 * Helper functions to represent ports as a dbus dict
 */
static dbus_bool_t
__wicked_dbus_bridge_port_to_dict(const ni_bridge_port_t *port, ni_dbus_variant_t *dict,
				const ni_dbus_object_t *object,
				int config_only)
{
	if (port->name)
		ni_dbus_dict_add_string(dict, "device", port->name);
	ni_dbus_dict_add_uint32(dict, "priority", port->priority);
	ni_dbus_dict_add_uint32(dict, "path-cost", port->path_cost);

	if (config_only)
		return TRUE;

	ni_dbus_dict_add_uint32(dict, "state", port->status.state);
	ni_dbus_dict_add_uint32(dict, "port-id", port->status.port_id);
	ni_dbus_dict_add_uint32(dict, "port-no", port->status.port_no);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_bridge_port_from_dict(ni_bridge_port_t *port, const ni_dbus_variant_t *dict,
				DBusError *error,
				int config_only)
{
	const char *string;
	uint32_t value;

	if (dict->array.len == 0)
		return TRUE;
	if (ni_dbus_dict_get_string(dict, "device", &string))
		ni_string_dup(&port->name, string);
	if (ni_dbus_dict_get_uint32(dict, "priority", &value))
		port->priority = value;
	if (ni_dbus_dict_get_uint32(dict, "path-cost", &value))
		port->path_cost = value;

	if (ni_dbus_dict_get_uint32(dict, "state", &value))
		port->status.state = value;
	if (ni_dbus_dict_get_uint32(dict, "port-id", &value))
		port->status.port_id = value;
	if (ni_dbus_dict_get_uint32(dict, "port-no", &value))
		port->status.port_no = value;

	return TRUE;
}

/*
 * Dummy properties for bridge port.
 * This is needed for encoding bridge port properties in addPort calls
 */
#define WICKED_BRIDGE_PORT_PROPERTY(type, __name) \
	NI_DBUS_DUMMY_PROPERTY(type, __name)

const ni_dbus_property_t	ni_objectmodel_bridge_port_property_table[] = {
	WICKED_BRIDGE_PORT_PROPERTY(UINT32, priority),
	WICKED_BRIDGE_PORT_PROPERTY(UINT32, path_cost),

	{ NULL }
};

#define BRIDGE_INT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT_PROPERTY(bridge, dbus_name, member_name, rw)
#define BRIDGE_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(bridge, dbus_name, member_name, rw)
#define WICKED_BRIDGE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_bridge, rw)

const ni_dbus_property_t	ni_objectmodel_bridge_property_table[] = {
	BRIDGE_UINT_PROPERTY(priority, priority, RO),
	/* This one needs a special parse function: */
	__NI_DBUS_GENERIC_PROPERTY(bridge, DBUS_TYPE_UINT32_AS_STRING, stp, uint, stp, RO,
			.parse = __wicked_dbus_bridge_parse_stp),
	BRIDGE_UINT_PROPERTY(forward-delay, forward_delay, RO),
	BRIDGE_UINT_PROPERTY(aging-time, ageing_time, RO),
	BRIDGE_UINT_PROPERTY(hello-time, hello_time, RO),
	BRIDGE_UINT_PROPERTY(max-age, max_age, RO),

	/* ports is an array of dicts */
	WICKED_BRIDGE_PROPERTY_SIGNATURE(DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE,
			ports, RO),

	{ NULL }
};
