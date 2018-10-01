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
#include "nanny.h"


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
	ni_nanny_t *mgr = mdev->nanny;
	ni_ifworker_t *w;

	if (!(w = ni_managed_device_get_worker(mdev)))
		return FALSE;

	if (mdev->rfkill_blocked) {
		ni_debug_nanny("%s: radio disabled, will enable scanning later",
			w->name);
		mdev->monitor = TRUE;
		return TRUE;
	}

	if (ni_netdev_device_is_ready(w->device))
		ni_nanny_schedule_recheck(&mgr->recheck, w);
	ni_nanny_unschedule(&mgr->down, w);
	ni_ifworker_rearm(w);

	mdev->monitor = TRUE;

	return TRUE;
}

/*
 * Stop monitoring interface
 */
ni_bool_t
ni_managed_netdev_disable(ni_managed_device_t *mdev)
{
	ni_nanny_t *mgr = mdev->nanny;
	ni_ifworker_t *w;

	if (!(w = ni_managed_device_get_worker(mdev)))
		return FALSE;

	ni_nanny_schedule_recheck(&mgr->down, w);
	ni_nanny_unschedule(&mgr->recheck, w);
	ni_ifworker_rearm(w);

	mdev->monitor = FALSE;
	return TRUE;
}

/*
 * Create a dbus object representing the managed netdev
 */
ni_dbus_object_t *
ni_objectmodel_register_managed_netdev(ni_dbus_server_t *server, ni_managed_device_t *mdev)
{
	ni_netdev_t *dev;
	char relative_path[128];
	ni_dbus_object_t *object;
	ni_ifworker_t *w;

	if (!(w = ni_managed_device_get_worker(mdev)))
		return NULL;

	if (!(dev = ni_ifworker_get_netdev(w)))
		return NULL;

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
					unsigned int argc, const ni_dbus_variant_t *argv, uid_t caller_uid,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_managed_device_t *mdev;

	if ((mdev = ni_objectmodel_managed_netdev_unwrap(object, error)) == NULL)
		return FALSE;

	/* root user should always be allowed to enable a device */
	if (caller_uid != 0 && !mdev->allowed) {
		dbus_set_error(error, DBUS_ERROR_ACCESS_DENIED,
				"you are not permitted to enable this device");
		return FALSE;
	}

	if (argc != 0)
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	/* When calling enable on a failed device, implicitly clear the error state */
	if (mdev->state == NI_MANAGED_STATE_FAILED)
		mdev->state = NI_MANAGED_STATE_LIMBO;

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
					unsigned int argc, const ni_dbus_variant_t *argv, uid_t caller_uid,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_managed_device_t *mdev;

	if ((mdev = ni_objectmodel_managed_netdev_unwrap(object, error)) == NULL)
		return FALSE;

	/* root user should always be allowed to disable a device */
	if (caller_uid != 0 && !mdev->allowed) {
		dbus_set_error(error, DBUS_ERROR_ACCESS_DENIED,
				"you are not permitted to disable this device");
		return FALSE;
	}

	if (argc != 0)
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	if (!ni_managed_netdev_disable(mdev)) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to disable device");
		return FALSE;
	}

	return TRUE;
}

static ni_dbus_method_t		ni_objectmodel_managed_netdev_methods[] = {
	{ "enable",		"",		.handler_ex = ni_objectmodel_managed_netdev_enable	},
	{ "disable",		"",		.handler_ex = ni_objectmodel_managed_netdev_disable	},
	{ NULL }
};

/*
 * Handle object properties
 */
static void *
ni_objectmodel_get_managed_device(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_managed_netdev_unwrap(object, error);
}

#define MANAGED_NETIF_UINT_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(managed_device, dbus_name, name, rw)
#define MANAGED_NETIF_BOOL_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(managed_device, dbus_name, name, rw)

static ni_dbus_property_t	ni_objectmodel_managed_netdev_properties[] = {
	MANAGED_NETIF_BOOL_PROPERTY(allowed, allowed, RW),
	MANAGED_NETIF_BOOL_PROPERTY(monitor, monitor, RW),
	MANAGED_NETIF_UINT_PROPERTY(state, state, RO),
	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_managed_netdev_service = {
	.name		= NI_OBJECTMODEL_MANAGED_NETIF_INTERFACE,
	.compatible	= &ni_objectmodel_managed_netdev_class,
	.methods	= ni_objectmodel_managed_netdev_methods,
	.properties	= ni_objectmodel_managed_netdev_properties,
};
