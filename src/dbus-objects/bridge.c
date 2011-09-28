/*
 * DBus encapsulation for bridge interfaces
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
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
#include "model.h"

#define TRACE_ENTERN(fmt, args...) \
				ni_debug_dbus("%s(" fmt ")", __FUNCTION__, ##args)

static dbus_bool_t	__wicked_dbus_bridge_port_to_dict(const ni_bridge_port_t *port,
				ni_dbus_variant_t *dict,
				const ni_dbus_object_t *object,
				int config_only);

#define NULL_bridge		((ni_bridge_t *) 0)

/*
 * Create a new Bridge interface
 */
ni_dbus_object_t *
ni_objectmodel_new_bridge(ni_dbus_server_t *server, const ni_dbus_object_t *config)
{
	ni_interface_t *cfg_ifp = ni_dbus_object_get_handle(config);
	ni_interface_t *new_ifp;
	const ni_bridge_t *bridge = ni_interface_get_bridge(cfg_ifp);
	ni_handle_t *nih = ni_global_state_handle();

	cfg_ifp->type = NI_IFTYPE_BRIDGE;
	if (cfg_ifp->name == NULL) {
		static char namebuf[64];
		unsigned int num;

		for (num = 0; num < 65536; ++num) {
			snprintf(namebuf, sizeof(namebuf), "br%u", num);
			if (!ni_interface_by_name(nih, namebuf)) {
				ni_string_dup(&cfg_ifp->name, namebuf);
				break;
			}
		}

		if (cfg_ifp->name == NULL) {
			/* FIXME: report error */
			return NULL;
		}
	}

#if 1
	(void) bridge;
	(void) new_ifp;
	ni_error("%s: not yet supported", __func__);
	return NULL;
#else
	if (ni_interface_create_bridge(nih, cfg_ifp->name, bridge, &new_ifp) < 0) {
		/* FIXME: report error */
		return NULL;
	}

	if (new_ifp->type != NI_IFTYPE_BRIDGE) {
		/* FIXME: report error */
		return NULL;
	}

	return ni_objectmodel_register_interface(server, new_ifp);
#endif
}

/*
 * BRIDGE.delete method
 */
static dbus_bool_t
__ni_dbus_bridge_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_handle_t *nih = ni_global_state_handle();
	ni_interface_t *ifp = object->handle;

	TRACE_ENTERN("ifp=%s", ifp->name);
	if (nih /* ni_interface_delete_bridge(nih, ifp) < 0 */) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting bridge interface", ifp->name);
		return FALSE;
	}

	/* FIXME: destroy the object */
	ni_dbus_object_free(object);

	return TRUE;
}


/*
 * Helper function to obtain bridge config from dbus object
 */
static ni_bridge_t *
__wicked_dbus_bridge_handle(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	return ni_interface_get_bridge(ifp);
}

/*
 * Property priority
 */
static dbus_bool_t
__wicked_dbus_bridge_get_priority(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_uint(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->priority, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_priority(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->priority, argument);
}

/*
 * Property stp
 */
static dbus_bool_t
__wicked_dbus_bridge_get_stp(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_uint(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->stp, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_stp(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->stp, argument);
}

/*
 * Property forward_delay
 */
static dbus_bool_t
__wicked_dbus_bridge_get_forward_delay(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->forward_delay, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_forward_delay(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->forward_delay, argument);
}

/*
 * Property aging_time
 */
static dbus_bool_t
__wicked_dbus_bridge_get_aging_time(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->ageing_time, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_aging_time(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->ageing_time, argument);
}

/*
 * Property hello_time
 */
static dbus_bool_t
__wicked_dbus_bridge_get_hello_time(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->hello_time, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_hello_time(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->hello_time, argument);
}

/*
 * Property max_age
 */
static dbus_bool_t
__wicked_dbus_bridge_get_max_age(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->max_age, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_max_age(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->max_age, argument);
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
	/* TBD */
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
	/* FIXME: we should look up the slave device here and
	 * return its object path */
	ni_dbus_dict_add_string(dict, "name", port->name);
	ni_dbus_dict_add_uint32(dict, "priority", port->priority);
	ni_dbus_dict_add_uint32(dict, "path_cost", port->path_cost);

	if (config_only)
		return TRUE;

	ni_dbus_dict_add_uint32(dict, "state", port->status.state);
	ni_dbus_dict_add_uint32(dict, "port_id", port->status.port_id);
	ni_dbus_dict_add_uint32(dict, "port_no", port->status.port_no);
	return TRUE;
}

#define WICKED_BRIDGE_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, 0, __wicked_dbus_bridge, rw)
#define WICKED_BRIDGE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, 0, __wicked_dbus_bridge, rw)

static ni_dbus_property_t	wicked_dbus_bridge_properties[] = {
	WICKED_BRIDGE_PROPERTY(UINT32, priority, RO),
	WICKED_BRIDGE_PROPERTY(INT32, stp, RO),
	WICKED_BRIDGE_PROPERTY(UINT32, forward_delay, RO),
	WICKED_BRIDGE_PROPERTY(UINT32, aging_time, RO),
	WICKED_BRIDGE_PROPERTY(UINT32, hello_time, RO),
	WICKED_BRIDGE_PROPERTY(UINT32, max_age, RO),

	/* ports is an array of dicts */
	WICKED_BRIDGE_PROPERTY_SIGNATURE(
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
			ports, RO),


	/* The following are really just status used for reporting */
	{ NULL }
};


static ni_dbus_method_t		wicked_dbus_bridge_methods[] = {
	{ "delete",		"",		__ni_dbus_bridge_delete },
#if 0
	{ "addPort",		"sa{sv}",	__ni_dbus_bridge_add_port },
	{ "removePort",		"sa{sv}",	__ni_dbus_bridge_remove_port },
#endif
	{ NULL }
};

ni_dbus_service_t	wicked_dbus_bridge_service = {
	.name = WICKED_DBUS_INTERFACE ".Bridge",
	.methods = wicked_dbus_bridge_methods,
	.properties = wicked_dbus_bridge_properties,
};
