/*
 * DBus API for wicked autoip4 supplicant
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 *
 * Much of this code is in dbus-objects/autoip4.c for now.
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
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "dbus-objects/model.h"
#include "debug.h"
#include "autoip.h"


extern const ni_dbus_service_t	wicked_dbus_addrconf_request_service; /* XXX */
static const ni_dbus_service_t	wicked_dbus_autoip4_service;
static ni_dbus_class_t		ni_objectmodel_autoip4dev_class = {
	"autoip4-device",
};

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
						&ni_objectmodel_autoip4dev_class,
						ni_autoip_device_get(dev));
	} else {
		object = ni_dbus_object_new(&ni_objectmodel_autoip4dev_class, NULL,
						ni_autoip_device_get(dev));
	}

	if (object == NULL)
		ni_fatal("Unable to create dbus object for autoip4 device %s", dev->ifname);

	ni_dbus_object_register_service(object, &wicked_dbus_autoip4_service);
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
ni_objectmodel_unwrap_autoip4_device(const ni_dbus_object_t *object)
{
	ni_autoip_device_t *dev = object->handle;

	return object->class == &ni_objectmodel_autoip4dev_class? dev : NULL;
}

/*
 * Interface.acquire(dict options)
 * Acquire a lease for the given interface.
 *
 * Server side method implementation
 */
static dbus_bool_t
__wicked_dbus_autoip4_acquire_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_autoip_device_t *dev = ni_objectmodel_unwrap_autoip4_device(object);
	dbus_bool_t ret = FALSE;
	int rv;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->ifname);

	/* Ignore all arguments for now */
	if ((rv = ni_autoip_acquire(dev)) < 0) {
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
__wicked_dbus_autoip4_drop_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_autoip_device_t *dev = ni_objectmodel_unwrap_autoip4_device(object);
	dbus_bool_t ret = FALSE;
	ni_uuid_t uuid;
	int rv;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->ifname);

	memset(&uuid, 0, sizeof(uuid));
	if (argc == 1) {
		/* Extract the lease uuid and pass that along to ni_autoip_release.
		 * This makes sure we don't cancel the wrong lease.
		 */
		unsigned int len;

		if (!ni_dbus_variant_get_byte_array_minmax(&argv[0], uuid.octets, &len, 16, 16)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "bad uuid argument");
			goto failed;
		}
	}

	if ((rv = ni_autoip_release(dev, &uuid)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to drop IPv4ll lease for interface %s: %s", dev->ifname,
				ni_strerror(rv));
		goto failed;
	}

	ret = TRUE;

failed:
	return ret;
}

static ni_dbus_method_t		wicked_dbus_autoip4_methods[] = {
	{ "acquire",		"a{sv}",		__wicked_dbus_autoip4_acquire_svc },
	{ "drop",		"ay",			__wicked_dbus_autoip4_drop_svc },
	{ NULL }
};

static ni_dbus_method_t		wicked_dbus_autoip4_signals[] = {
	{ NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL },
	{ NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL },
	{ NI_OBJECTMODEL_LEASE_LOST_SIGNAL },
	{ NULL }
};

/*
 * Property name
 */
static dbus_bool_t
__wicked_dbus_autoip4_get_name(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_autoip_device_t *dev = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_string(result, dev->ifname);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_autoip4_set_name(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_autoip_device_t *dev = ni_dbus_object_get_handle(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;
	ni_string_dup(&dev->ifname, value);
	return TRUE;
}

#define WICKED_INTERFACE_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __wicked_dbus_autoip4, rw)
#define WICKED_INTERFACE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_autoip4, rw)

static ni_dbus_property_t	wicked_dbus_autoip4_properties[] = {
	WICKED_INTERFACE_PROPERTY(STRING, name, RO),

	{ NULL }
};

static const ni_dbus_service_t	wicked_dbus_autoip4_service = {
	.name		= NI_OBJECTMODEL_AUTO4_INTERFACE,
	.compatible	= &ni_objectmodel_autoip4dev_class,
	.methods	= wicked_dbus_autoip4_methods,
	.signals	= wicked_dbus_autoip4_signals,
	.properties	= wicked_dbus_autoip4_properties,
};
