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
			&NULL_bridge->config.priority, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_priority(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_uint(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.priority, argument);
}

/*
 * Property stp
 */
static dbus_bool_t
__wicked_dbus_bridge_get_stp(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_int(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.stp_enabled, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_stp(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_int(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.stp_enabled, argument);
}

/*
 * Property forward_delay
 */
static dbus_bool_t
__wicked_dbus_bridge_get_forward_delay(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.forward_delay, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_forward_delay(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.forward_delay, argument);
}

/*
 * Property aging_time
 */
static dbus_bool_t
__wicked_dbus_bridge_get_aging_time(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.ageing_time, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_aging_time(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.ageing_time, argument);
}

/*
 * Property hello_time
 */
static dbus_bool_t
__wicked_dbus_bridge_get_hello_time(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.hello_time, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_hello_time(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.hello_time, argument);
}

/*
 * Property max_age
 */
static dbus_bool_t
__wicked_dbus_bridge_get_max_age(const ni_dbus_object_t *object, const ni_dbus_property_t *property,
				ni_dbus_variant_t *result, DBusError *error)
{
	return __ni_objectmodel_get_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.max_age, result);
}

static dbus_bool_t
__wicked_dbus_bridge_set_max_age(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	return __ni_objectmodel_set_property_ulong(__wicked_dbus_bridge_handle(object, error),
			&NULL_bridge->config.max_age, argument);
}

#if 0
/*
 * Get/set underlying interface
 */
static dbus_bool_t
__wicked_dbus_bridge_get_interface_name(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bridge_t *bridge;

	if (!(bridge = __wicked_dbus_bridge_handle(object, error)))
		return FALSE;

	ni_dbus_variant_set_string(result, bridge->interface_name);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_bridge_set_interface_name(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bridge_t *bridge;
	const char *interface_name;

	if (!(bridge = __wicked_dbus_bridge_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_string(result, &interface_name))
		return FALSE;
	ni_string_dup(&bridge->interface_name, interface_name);
	return TRUE;
}
#endif

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

	/* The following are really just status used for reporting */
	{ NULL }
};


static ni_dbus_method_t		wicked_dbus_bridge_methods[] = {
	{ "delete",		"",		__ni_dbus_bridge_delete },
	{ NULL }
};

ni_dbus_service_t	wicked_dbus_bridge_service = {
	.name = WICKED_DBUS_INTERFACE ".Bridge",
	.methods = wicked_dbus_bridge_methods,
	.properties = wicked_dbus_bridge_properties,
};


