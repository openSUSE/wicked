/*
 * This is a hack we need to use when building the library as a static library.
 * It makes sure that all interface implementations get linked in, so that they
 * can be referenced via <builtin> bindings in the config file.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#include <wicked/objectmodel.h>

extern const ni_dbus_property_t		ni_objectmodel_vlan_property_table[];

const ni_dbus_property_t *		__force_linkage[] = {
	ni_objectmodel_vlan_property_table,
};

void
__ni_objectmodel_force_linkage()
{
}
