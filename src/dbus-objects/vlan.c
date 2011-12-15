/*
 * DBus encapsulation for VLAN interfaces
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
#include "model.h"
#include "debug.h"


/*
 * Create a new VLAN interface
 */
ni_dbus_object_t *
ni_objectmodel_new_vlan(ni_dbus_server_t *server, const ni_dbus_object_t *config, DBusError *error)
{
	ni_interface_t *cfg_ifp = ni_dbus_object_get_handle(config);
	ni_interface_t *new_ifp;
	const ni_vlan_t *vlan = cfg_ifp->link.vlan;
	ni_netconfig_t *nc = ni_global_state_handle(0);
	int rv;

	if (!vlan
	 || !vlan->tag
	 || !vlan->physdev_name) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Incomplete arguments (need VLAN tag and interface name)");
		return NULL;
	}

	cfg_ifp->link.type = NI_IFTYPE_VLAN;
	if (cfg_ifp->name == NULL) {
		static char namebuf[64];
		unsigned int num;

		for (num = 0; num < 65536; ++num) {
			snprintf(namebuf, sizeof(namebuf), "vlan%u", num);
			if (!ni_interface_by_name(nc, namebuf)) {
				ni_string_dup(&cfg_ifp->name, namebuf);
				break;
			}
		}

		if (cfg_ifp->name == NULL) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Unable to create vlan - too many interfaces");
			return NULL;
		}
	}

	if ((rv = ni_system_vlan_create(nc, cfg_ifp->name, vlan, &new_ifp)) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create VLAN interface: %s",
				ni_strerror(rv));
		return NULL;
	}

	if (new_ifp->link.type != NI_IFTYPE_VLAN) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create VLAN interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		return NULL;
	}

	return ni_objectmodel_register_interface(server, new_ifp);
}

/*
 * VLAN.delete method
 */
static dbus_bool_t
__ni_dbus_vlan_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_interface_t *ifp = object->handle;

	NI_TRACE_ENTER_ARGS("ifp=%s", ifp->name);
	if (ni_system_vlan_delete(ifp) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting VLAN interface", ifp->name);
		return FALSE;
	}

	/* FIXME: destroy the object */
	ni_dbus_object_free(object);

	return TRUE;
}


/*
 * Helper function to obtain VLAN config from dbus object
 */
static ni_vlan_t *
__wicked_dbus_vlan_handle(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	return ni_interface_get_vlan(ifp);
}

/*
 * Get/set VLAN tag
 */
static dbus_bool_t
__wicked_dbus_vlan_get_tag(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_vlan_t *vlan;

	if (!(vlan = __wicked_dbus_vlan_handle(object, error)))
		return FALSE;

	ni_dbus_variant_set_uint16(result, vlan->tag);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_vlan_set_tag(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_vlan_t *vlan;
	uint16_t value;

	if (!(vlan = __wicked_dbus_vlan_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_uint16(result, &value)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"tag property must be of type uint16");
		return FALSE;
	}
	if (value == 0) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"tag property must not be 0");
		return FALSE;
	}
	vlan->tag = value;
	return TRUE;
}

/*
 * Get/set underlying interface
 */
static dbus_bool_t
__wicked_dbus_vlan_get_interface_name(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_vlan_t *vlan;

	if (!(vlan = __wicked_dbus_vlan_handle(object, error)))
		return FALSE;

	ni_dbus_variant_set_string(result, vlan->physdev_name);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_vlan_set_interface_name(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_vlan_t *vlan;
	const char *physdev_name;

	if (!(vlan = __wicked_dbus_vlan_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_string(result, &physdev_name))
		return FALSE;
	ni_string_dup(&vlan->physdev_name, physdev_name);
	return TRUE;
}

#define WICKED_VLAN_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, 0, __wicked_dbus_vlan, rw)
#define WICKED_VLAN_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, 0, __wicked_dbus_vlan, rw)

static ni_dbus_property_t	wicked_dbus_vlan_properties[] = {
	WICKED_VLAN_PROPERTY(STRING, interface_name, RO),
	WICKED_VLAN_PROPERTY(UINT16, tag, RO),
	{ NULL }
};


static ni_dbus_method_t		wicked_dbus_vlan_methods[] = {
	{ "delete",		"",		__ni_dbus_vlan_delete },
	{ NULL }
};

ni_dbus_service_t	wicked_dbus_vlan_service = {
	.name = WICKED_DBUS_VLAN_INTERFACE,
	.methods = wicked_dbus_vlan_methods,
	.properties = wicked_dbus_vlan_properties,
};

