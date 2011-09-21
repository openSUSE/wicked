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

static ni_dbus_service_t	wicked_dbus_vlan_interface;

void
ni_objectmodel_register_vlan_interface(ni_dbus_object_t *object)
{
	ni_dbus_object_register_service(object, &wicked_dbus_vlan_interface);
}

static ni_vlan_t *
__wicked_dbus_vlan_handle(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	ni_vlan_t *vlan;

	if (!(vlan = ifp->vlan)) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Interface %s has no vlan property",
				ifp->name);
		return NULL;
	}
	return vlan;
}

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

	if (!ni_dbus_variant_get_uint16(result, &value))
		return FALSE;
	if (value == 0)
		return FALSE;
	vlan->tag = value;
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_vlan_get_interface_name(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_vlan_t *vlan;

	if (!(vlan = __wicked_dbus_vlan_handle(object, error)))
		return FALSE;

	ni_dbus_variant_set_string(result, vlan->interface_name);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_vlan_set_interface_name(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_vlan_t *vlan;
	const char *interface_name;

	if (!(vlan = __wicked_dbus_vlan_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_string(result, &interface_name))
		return FALSE;
	ni_string_dup(&vlan->interface_name, interface_name);
	return TRUE;
}

#define WICKED_VLAN_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, offsetof(ni_vlan_t, __name), __wicked_dbus_vlan, rw)
#define WICKED_VLAN_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, offsetof(ni_vlan_t, __name), __wicked_dbus_ethernet, rw)

static ni_dbus_property_t	wicked_dbus_vlan_properties[] = {
	WICKED_VLAN_PROPERTY(UINT32, interface_name, RO),
	WICKED_VLAN_PROPERTY(UINT32, tag, RO),
	{ NULL }
};


static ni_dbus_method_t		wicked_dbus_vlan_methods[] = {
	{ NULL }
};

static ni_dbus_service_t	wicked_dbus_vlan_interface = {
	.object_interface = WICKED_DBUS_INTERFACE ".VLAN",
	.methods = wicked_dbus_vlan_methods,
	.properties = wicked_dbus_vlan_properties,
};

