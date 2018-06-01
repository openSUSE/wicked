/*
 * DBus API for wicked autoip4 supplicant
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 *
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
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/objectmodel.h>
#include "autoip.h"
#include "util_priv.h"

static void			__ni_objectmodel_autoip4_device_release(ni_dbus_object_t *);

static const ni_dbus_service_t	ni_objectmodel_autoip4_service;
static ni_dbus_class_t		ni_objectmodel_autoip4_device_class = {
	.name		= "autoip4-device",
	.destroy	= __ni_objectmodel_autoip4_device_release,
	.superclass	= &ni_objectmodel_addrconf_device_class,
};

/*
 * Register services and classes for dhcp4 supplicant service
 */
void
ni_objectmodel_autoip4_init(void)
{
	if (ni_objectmodel_init(NULL) == NULL)
		ni_fatal("Cannot initialize objectmodel, giving up.");
	ni_objectmodel_register_class(&ni_objectmodel_autoip4_device_class);
	ni_objectmodel_register_service(&ni_objectmodel_autoip4_service);
}


/*
 * Build a dbus-object encapsulating a network device.
 * If @server is non-NULL, register the object with a canonical object path
 */
static ni_dbus_object_t *
__ni_objectmodel_build_autoip4_device_object(ni_dbus_server_t *server, ni_autoip_device_t *dev)
{
	ni_dbus_object_t *object;
	char object_path[256];

	if (dev->link.ifindex <= 0) {
		ni_error("%s: autoip4 device %s has bad ifindex %d", __func__, dev->ifname, dev->link.ifindex);
		return NULL;
	}

	if (server != NULL) {
		snprintf(object_path, sizeof(object_path), "Interface/%d", dev->link.ifindex);
		object = ni_dbus_server_register_object(server, object_path,
						&ni_objectmodel_autoip4_device_class,
						ni_autoip_device_get(dev));
	} else {
		object = ni_dbus_object_new(&ni_objectmodel_autoip4_device_class, NULL,
						ni_autoip_device_get(dev));
	}

	if (object == NULL)
		ni_fatal("Unable to create dbus object for autoip4 device %s", dev->ifname);

	ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}


/*
 * Register a network interface with our dbus server,
 * and add the appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_register_autoip4_device(ni_dbus_server_t *server, ni_autoip_device_t *dev)
{
	return __ni_objectmodel_build_autoip4_device_object(server, dev);
}

/*
 * Extract the autoip_device handle from a dbus object
 */
static ni_autoip_device_t *
ni_objectmodel_unwrap_autoip4_device(const ni_dbus_object_t *object, DBusError *error)
{
	if (!object) {
		if (error) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Cannot unwrap autoip4 device from a NULL dbus object");
		}
		return NULL;
	}
	if (!ni_dbus_object_isa(object, &ni_objectmodel_autoip4_device_class)) {
		if (error)  {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"method not compatible with object %s of class %s (not autoip4 device)",
					object->path, object->class->name);
		}
		return NULL;
	}
	return object->handle;
}

/*
 * Destroy a dbus object wrapping an autoip device.
 */
static void
__ni_objectmodel_autoip4_device_release(ni_dbus_object_t *object)
{
	ni_autoip_device_t *dev = ni_objectmodel_unwrap_autoip4_device(object, NULL);

	object->handle = NULL;
	if (dev)
		ni_autoip_device_put(dev);
}

/*
 * Interface.acquire(dict options)
 * Acquire a lease for the given interface.
 *
 * Server side method implementation
 */
static dbus_bool_t
ni_objectmodel_autoip4_acquire_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_auto4_request_t req;
	ni_autoip_device_t *dev;
	dbus_bool_t ret = FALSE;
	ni_uuid_t req_uuid = NI_UUID_INIT;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_autoip4_device(object, error)))
		return FALSE;

	ni_debug_dbus("%s(dev=%s, argc=%u)", __func__, dev->ifname, argc);

	if (argc == 2) {
		/*
		 * Extract the request uuid and pass that along to acquire.
		 */
		if (!ni_dbus_variant_get_uuid(&argv[0], &req_uuid)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s: unable to extract acquire request uuid argument",
					method->name);
			goto failed;
		}
		argc--;
		argv++;
	}

	if (argc != 1) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: unable to extract arguments", method->name);
		 goto failed;
	}

	ni_auto4_request_init(&req, TRUE);
	if (!ni_objectmodel_set_auto4_request_dict(&req, &argv[0], error)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: unable to extract request from argument",
				method->name);
		goto failed;
	}
	req.uuid = req_uuid;

	if ((rv = ni_autoip_acquire(dev, &req)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot configure interface %s: %s", dev->ifname,
				ni_strerror(rv));
		goto failed;
	}

	/* We've now initiated the IPv4ll exchange. It will complete
	 * asynchronously, and when done, we will emit a signal that
	 * notifies the sender of its results. */

	ret = TRUE;

failed:
	return ret;
}

/*
 * Interface.drop(void)
 * Drop a IPv4ll lease
 */
static dbus_bool_t
ni_objectmodel_autoip4_drop_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_autoip_device_t *dev;
	dbus_bool_t ret = FALSE;
	ni_uuid_t req_uuid = NI_UUID_INIT;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_autoip4_device(object, error)))
		return FALSE;

	ni_debug_dbus("%s(dev=%s, argc=%u)", __func__, dev->ifname, argc);

	if (argc == 1) {
		/*
		 * Extract the lease uuid and pass that along to ni_autoip_release.
		 */
		if (!ni_dbus_variant_get_uuid(&argv[0], &req_uuid)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s: unable to extract drop request uuid argument",
					method->name);
			goto failed;
		}
	}

	if ((rv = ni_autoip_release(dev, &req_uuid)) < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"Unable to drop auto4 lease for interface %s: %s",
				dev->ifname, ni_strerror(rv));
		goto failed;
	}

	ret = TRUE;

failed:
	return ret;
}

/*
 * Request class and properties
 */
static ni_dbus_method_t		ni_objectmodel_autoip4_methods[] = {
	{ "acquire",		"aya{sv}",	.handler = ni_objectmodel_autoip4_acquire_svc },
	{ "drop",		"ay",		.handler = ni_objectmodel_autoip4_drop_svc },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_autoip4_signals[] = {
	{ .name = NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL },
	{ .name = NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL },
	{ .name = NI_OBJECTMODEL_LEASE_LOST_SIGNAL     },
	{ NULL }
};

/*
 * Device property access functions -- just showing
 * the device name and currently assigned request.
 */
static void *
ni_objectmodel_get_autoip_device(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_autoip4_device(object, error);
}

static dbus_bool_t
ni_objectmodel_autoip_device_get_request(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_autoip_device_t *dev;

	if (!(dev = ni_objectmodel_unwrap_autoip4_device(object, error)))
		return FALSE;

	if (!dev->request.enabled)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	return ni_objectmodel_get_auto4_request_dict(&dev->request, result, error);
}

static dbus_bool_t
ni_objectmodel_autoip_device_set_request(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_autoip_device_t *dev;

	if (!(dev = ni_objectmodel_unwrap_autoip4_device(object, error)))
		return FALSE;

	return ni_objectmodel_set_auto4_request_dict(&dev->request, argument, error);
}

static ni_dbus_property_t	ni_objectmodel_autoip4_properties[] = {
	NI_DBUS_GENERIC_STRING_PROPERTY(autoip_device, name, ifname, RO),
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, request, request,
				ni_objectmodel_autoip_device, RO),
	{ NULL }
};

static const ni_dbus_service_t	ni_objectmodel_autoip4_service = {
	.name		= NI_OBJECTMODEL_AUTO4_INTERFACE,
	.compatible	= &ni_objectmodel_autoip4_device_class,
	.methods	= ni_objectmodel_autoip4_methods,
	.signals	= ni_objectmodel_autoip4_signals,
	.properties	= ni_objectmodel_autoip4_properties,
};
