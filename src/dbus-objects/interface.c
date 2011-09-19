/*
 * dbus encapsulation for network interfaces
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

static ni_dbus_method_t		wicked_dbus_interface_methods[];
static ni_dbus_property_t	wicked_dbus_interface_properties[];

void
ni_objectmodel_register_interface(ni_dbus_server_t *server, ni_interface_t *ifp)
{
	ni_dbus_object_t *object;
	char object_path[256];

	snprintf(object_path, sizeof(object_path), "Interface/%s", ifp->name);
	object = ni_dbus_server_register_object(server, object_path, ifp);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interface %s", ifp->name);

	ni_dbus_object_register_service(object, WICKED_DBUS_INTERFACE ".Interface",
			wicked_dbus_interface_methods,
			wicked_dbus_interface_properties);

	switch (ifp->type) {
	case NI_IFTYPE_ETHERNET:
		ni_objectmodel_register_interface_ethernet(server, ifp);
		break;

	default: ;
	}
}


static ni_dbus_method_t		wicked_dbus_interface_methods[] = {
	{ NULL }
};

static dbus_bool_t
__wicked_dbus_interface_get_type(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_uint32(result, ifp->type);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_get_status(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_uint32(result, ifp->ifflags);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_get_mtu(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_uint32(result, ifp->mtu);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_get_hwaddr(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_byte_array(result, ifp->hwaddr.len, ifp->hwaddr.data);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_interface_get_addresses(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);
	const ni_address_t *addr;

	ni_dbus_variant_set_string_array(result, 0, NULL);
	for (addr = ifp->addrs; addr; addr = addr->next) {
		const char *string = ni_address_print(&addr->local_addr);

		ni_dbus_variant_append_string_array(result, string);
	}

	return TRUE;
}

#define WICKED_INTERFACE_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __wicked_dbus_interface, rw)
#define WICKED_INTERFACE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_interface, rw)

static ni_dbus_property_t	wicked_dbus_interface_properties[] = {
	WICKED_INTERFACE_PROPERTY(UINT32, status, RO),
	WICKED_INTERFACE_PROPERTY(UINT32, type, RO),
	WICKED_INTERFACE_PROPERTY(UINT32, mtu, RO),
	WICKED_INTERFACE_PROPERTY_SIGNATURE(
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			hwaddr, RO),

	/* addresses is an array of dicts */
	WICKED_INTERFACE_PROPERTY_SIGNATURE(
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
			addresses, RO),
	{ NULL }
};

