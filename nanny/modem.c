/*
 * This daemon manages modems in response to modem-manager
 * events.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/objectmodel.h>
#include <wicked/modem.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/fsm.h>
#include <wicked/client.h>
#include "nanny.h"

#ifdef MODEM
void
ni_objectmodel_managed_modem_init(ni_dbus_server_t *server)
{
	ni_dbus_object_t *root_object;

	ni_objectmodel_register_class(&ni_objectmodel_managed_modem_class);
	ni_objectmodel_register_service(&ni_objectmodel_managed_modem_service);

	root_object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_create(root_object, "Modem", NULL, NULL);
}
#endif

/*
 * Create a dbus object representing the managed modem
 */
ni_dbus_object_t *
ni_objectmodel_register_managed_modem(ni_dbus_server_t *server, ni_managed_device_t *mdev)
{
	ni_modem_t *modem;
	char relative_path[128];
	ni_dbus_object_t *object;
	ni_ifworker_t *w;

	if (!(w = ni_managed_device_get_worker(mdev)))
		return NULL;

	modem = ni_ifworker_get_modem(w);
	snprintf(relative_path, sizeof(relative_path), "Modem/%s", modem->device);
	object = ni_dbus_server_register_object(server, relative_path, &ni_objectmodel_managed_modem_class, mdev);

	if (object)
		ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}

/*
 * Extract managed_modem handle from dbus object
 */
static ni_managed_device_t *
ni_objectmodel_managed_modem_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_managed_device_t *mdev = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_managed_modem_class))
		return mdev;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a managed network interface)",
			object->path, object->class->name);
	return NULL;
}

/*
 * ctor/dtor for the managed-modem class
 */
static void
ni_managed_modem_initialize(ni_dbus_object_t *object)
{
	ni_assert(object->handle == NULL);
}

static void
ni_managed_modem_destroy(ni_dbus_object_t *object)
{
	ni_managed_device_t *mdev;

	if (!(mdev = ni_objectmodel_managed_modem_unwrap(object, NULL)))
		return;

	ni_managed_device_free(mdev);
}

ni_dbus_class_t			ni_objectmodel_managed_modem_class = {
	.name		= NI_OBJECTMODEL_MANAGED_MODEM_CLASS,
	.initialize	= ni_managed_modem_initialize,
	.destroy	= ni_managed_modem_destroy,
};

static ni_dbus_method_t		ni_objectmodel_managed_modem_methods[] = {
	{ NULL }
};

/*
 * Handle object properties
 */
static void *
ni_objectmodel_get_managed_device(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_managed_modem_unwrap(object, error);
}

#define MANAGED_MODEM_UINT_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(managed_device, dbus_name, name, rw)
#define MANAGED_MODEM_BOOL_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(managed_device, dbus_name, name, rw)

static ni_dbus_property_t	ni_objectmodel_managed_modem_properties[] = {
	MANAGED_MODEM_BOOL_PROPERTY(allowed, allowed, RW),
	MANAGED_MODEM_BOOL_PROPERTY(monitor, monitor, RW),
	MANAGED_MODEM_UINT_PROPERTY(state, state, RO),
	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_managed_modem_service = {
	.name		= NI_OBJECTMODEL_MANAGED_MODEM_INTERFACE,
	.compatible	= &ni_objectmodel_managed_modem_class,
	.methods	= ni_objectmodel_managed_modem_methods,
	.properties	= ni_objectmodel_managed_modem_properties,
};

