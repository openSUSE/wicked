/*
 * DBus encapsulation for VLAN interfaces
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/vlan.h>
#include "model.h"

/*
 * Helper function to obtain VLAN config from dbus object
 */
static void *
ni_objectmodel_get_vlan(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp;

	if (!(ifp = ni_objectmodel_unwrap_interface(object))) {
		ni_error("trying to access %s properties for incompatible object (class %s)",
				WICKED_DBUS_VLAN_INTERFACE, object->class->name);
		return NULL;
	}

	return ni_interface_get_vlan(ifp);
}

#define VLAN_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(vlan, dbus_type, type, rw)
#define VLAN_UINT_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(vlan, dbus_type, type, rw)
#define VLAN_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(vlan, dbus_type, type, rw)

const ni_dbus_property_t	ni_objectmodel_vlan_property_table[] = {
	VLAN_STRING_PROPERTY(slave-name, physdev_name, RO),
	VLAN_UINT16_PROPERTY(tag, tag, RO),
	{ NULL }
};
