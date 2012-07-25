/*
 * This daemon manages interfaces in response to link up/down
 * events, WLAN network reachability, etc.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
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
#include <wicked/fsm.h>
#include "manager.h"


void
ni_objectmodel_managed_netif_init(ni_dbus_server_t *server)
{
	ni_dbus_object_t *root_object;

	ni_objectmodel_register_class(&managed_netdev_class);
	ni_objectmodel_register_service(&managed_netdev_service);

	root_object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_create(root_object, "Interface", NULL, NULL);
}

/*
 * managed_netdev objects
 */
ni_managed_netdev_t *
ni_managed_netdev_new(ni_netdev_t *dev)
{
	ni_managed_netdev_t *mdev;

	mdev = calloc(1, sizeof(*mdev));
	mdev->dev = ni_netdev_get(dev);

	switch (dev->link.type) {
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_WIRELESS:
		mdev->user_controlled = TRUE;
		break;

	default: ;
	}

	return mdev;
}

void
ni_managed_netdev_free(ni_managed_netdev_t *mdev)
{
	if (mdev->dev != NULL) {
		ni_netdev_put(mdev->dev);
		mdev->dev = NULL;
	}

	free(mdev);
}

/*
 * Create a dbus object representing the managed netdev
 */
ni_dbus_object_t *
ni_objectmodel_register_managed_netdev(ni_dbus_server_t *server, ni_managed_netdev_t *mdev)
{
	char relative_path[128];
	ni_dbus_object_t *object;

	snprintf(relative_path, sizeof(relative_path), "Interface/%u", mdev->dev->link.ifindex);
	object = ni_dbus_server_register_object(server, relative_path, &managed_netdev_class, mdev);

	ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}

/*
 * Extract managed_netdev handle from dbus object
 */
static ni_managed_netdev_t *
ni_objectmodel_managed_netdev_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_managed_netdev_t *mdev = object->handle;

	if (ni_dbus_object_isa(object, &managed_netdev_class))
		return mdev;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a managed network interface)",
			object->path, object->class->name);
	return NULL;
}

/*
 * ctor/dtor for the managed-netif class
 */
static void
ni_managed_netdev_initialize(ni_dbus_object_t *object)
{
	ni_assert(object->handle == NULL);
}

static void
ni_managed_netdev_destroy(ni_dbus_object_t *object)
{
	ni_managed_netdev_t *mdev;

	if (!(mdev = ni_objectmodel_managed_netdev_unwrap(object, NULL)))
		return;

	ni_managed_netdev_free(mdev);
}

ni_dbus_class_t			managed_netdev_class = {
	.name		= "managed-netif",
	.initialize	= ni_managed_netdev_initialize,
	.destroy	= ni_managed_netdev_destroy,
};

/*
 * Handle object properties
 */
static void *
ni_objectmodel_get_managed_netdev(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_managed_netdev_unwrap(object, error);
}

#define MANAGED_NETIF_BOOL_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(managed_netdev, dbus_name, name, rw)

static ni_dbus_property_t	managed_netdev_properties[] = {
	MANAGED_NETIF_BOOL_PROPERTY(user-controlled, user_controlled, RW),
	{ NULL }
};

ni_dbus_service_t		managed_netdev_service = {
	.name		= NI_OBJECTMODEL_MANAGED_NETIF_INTERFACE,
	.compatible	= &managed_netdev_class,
	.properties	= managed_netdev_properties,
};
