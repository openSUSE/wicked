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
#include <wicked/dbus-errors.h>
#include <wicked/fsm.h>
#include <wicked/client.h>
#include "manager.h"


void
ni_objectmodel_managed_netif_init(ni_dbus_server_t *server)
{
	ni_dbus_object_t *root_object;

	ni_objectmodel_register_class(&ni_objectmodel_managed_netdev_class);
	ni_objectmodel_register_service(&ni_objectmodel_managed_netdev_service);

	root_object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_create(root_object, "Interface", NULL, NULL);
}

/*
 * Enable a netdev for monitoring
 */
ni_bool_t
ni_managed_netdev_enable(ni_managed_device_t *mdev)
{
	ni_ifworker_t *w = mdev->worker;

	if (mdev->rfkill_blocked) {
		ni_debug_nanny("%s: radio disabled, will enable scanning later", w->name);
		mdev->user_controlled = TRUE;
		return TRUE;
	}

	switch (w->device->link.type) {
	case NI_IFTYPE_WIRELESS:
	case NI_IFTYPE_ETHERNET:
		/* bring it to state "UP" so that we can monitor for link status */
		if (ni_call_link_monitor(w->object) < 0) {
			ni_error("Failed to enable monitoring on %s", w->name);
			return FALSE;
		}
		break;

	default:
		return FALSE;
	}

	ni_manager_schedule_recheck(mdev->manager, mdev->worker);
	mdev->user_controlled = TRUE;
	return TRUE;
}

/*
 * Stop monitoring interface
 */
ni_bool_t
ni_managed_netdev_disable(ni_managed_device_t *mdev)
{
	if (mdev->user_controlled)
		ni_manager_schedule_down(mdev->manager, mdev->worker);
	mdev->user_controlled = FALSE;
	return TRUE;
}

/*
 * Create a dbus object representing the managed netdev
 */
ni_dbus_object_t *
ni_objectmodel_register_managed_netdev(ni_dbus_server_t *server, ni_managed_device_t *mdev)
{
	ni_netdev_t *dev = ni_ifworker_get_netdev(mdev->worker);
	char relative_path[128];
	ni_dbus_object_t *object;

	snprintf(relative_path, sizeof(relative_path), "Interface/%u", dev->link.ifindex);
	object = ni_dbus_server_register_object(server, relative_path, &ni_objectmodel_managed_netdev_class, mdev);

	if (object)
		ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}

/*
 * Extract managed_netdev handle from dbus object
 */
static ni_managed_device_t *
ni_objectmodel_managed_netdev_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_managed_device_t *mdev = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_managed_netdev_class))
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
	ni_managed_device_t *mdev;

	if (!(mdev = ni_objectmodel_managed_netdev_unwrap(object, NULL)))
		return;

	ni_managed_device_free(mdev);
}

ni_dbus_class_t			ni_objectmodel_managed_netdev_class = {
	.name		= "managed-netif",
	.initialize	= ni_managed_netdev_initialize,
	.destroy	= ni_managed_netdev_destroy,
};

/*
 * ManagedInterface.enable
 */
static dbus_bool_t
ni_objectmodel_managed_netdev_enable(ni_dbus_object_t *object, const ni_dbus_method_t *method,
					unsigned int argc, const ni_dbus_variant_t *argv,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_managed_device_t *mdev;

	if ((mdev = ni_objectmodel_managed_netdev_unwrap(object, error)) == NULL)
		return FALSE;

	if (argc != 0)
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	if (!ni_managed_netdev_enable(mdev)) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to enable device");
		return FALSE;
	}

	return TRUE;
}

/*
 * ManagedInterface.disable
 */
static dbus_bool_t
ni_objectmodel_managed_netdev_disable(ni_dbus_object_t *object, const ni_dbus_method_t *method,
					unsigned int argc, const ni_dbus_variant_t *argv,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_managed_device_t *mdev;

	if ((mdev = ni_objectmodel_managed_netdev_unwrap(object, error)) == NULL)
		return FALSE;

	if (argc != 0)
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	if (!ni_managed_netdev_disable(mdev)) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to disable device");
		return FALSE;
	}

	return TRUE;
}

static ni_dbus_method_t		ni_objectmodel_managed_netdev_methods[] = {
	{ "enable",		"",		ni_objectmodel_managed_netdev_enable	},
	{ "disable",		"",		ni_objectmodel_managed_netdev_disable	},
	{ NULL }
};

/*
 * Handle object properties
 */
static void *
ni_objectmodel_get_managed_device(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_managed_netdev_unwrap(object, error);
}

#define MANAGED_NETIF_BOOL_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(managed_device, dbus_name, name, rw)

static ni_dbus_property_t	ni_objectmodel_managed_netdev_properties[] = {
	MANAGED_NETIF_BOOL_PROPERTY(user-controlled, user_controlled, RW),
	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_managed_netdev_service = {
	.name		= NI_OBJECTMODEL_MANAGED_NETIF_INTERFACE,
	.compatible	= &ni_objectmodel_managed_netdev_class,
	.methods	= ni_objectmodel_managed_netdev_methods,
	.properties	= ni_objectmodel_managed_netdev_properties,
};
