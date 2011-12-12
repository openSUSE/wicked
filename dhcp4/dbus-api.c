/*
 * DBus API for wicked dhcp4 supplicant
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 *
 * Much of this code is in dbus-objects/dhcp4.c for now.
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
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "dbus-objects/model.h"
#include "debug.h"
#include "dhcp.h"

static ni_dbus_object_functions_t wicked_dbus_dhcp4_functions;

extern const ni_dbus_service_t	wicked_dbus_addrconf_request_service; /* XXX */
static const ni_dbus_service_t	wicked_dbus_dhcp4_service;

/*
 * Build a dbus-object encapsulating a network device.
 * If @server is non-NULL, register the object with a canonical object path
 */
static ni_dbus_object_t *
__ni_objectmodel_build_dhcp4_device_object(ni_dbus_server_t *server, ni_dhcp_device_t *dev)
{
	ni_dbus_object_t *object;
	char object_path[256];

	if (dev->link.ifindex <= 0) {
		ni_error("%s: dhcp4 device %s has bad ifindex %d", __func__, dev->ifname, dev->link.ifindex);
		return NULL;
	}

	if (server != NULL) {
		snprintf(object_path, sizeof(object_path), "Interface/%d", dev->link.ifindex);
		object = ni_dbus_server_register_object(server, object_path,
						&wicked_dbus_dhcp4_functions,
						ni_dhcp_device_get(dev));
	} else {
		object = ni_dbus_object_new(NULL,
						&wicked_dbus_dhcp4_functions,
						ni_dhcp_device_get(dev));
	}

	if (object == NULL)
		ni_fatal("Unable to create dbus object for dhcp4 device %s", dev->ifname);

	ni_dbus_object_register_service(object, &wicked_dbus_dhcp4_service);
	return object;
}


/*
 * Register a network interface with our dbus server,
 * and add the appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_register_dhcp4_device(ni_dbus_server_t *server, ni_dhcp_device_t *dev)
{
	return __ni_objectmodel_build_dhcp4_device_object(server, dev);
}

static ni_dbus_object_functions_t wicked_dbus_dhcp4_functions = {
	.destroy		= NULL,
};

/*
 * Interface.acquire(dict options)
 * Acquire a lease for the given interface.
 *
 * Server side method implementation
 */
static dbus_bool_t
__wicked_dbus_dhcp4_acquire_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dhcp_device_t *dev = object->handle;
	ni_dbus_object_t *cfg_object;
	ni_addrconf_request_t *req;
	dbus_bool_t ret = FALSE;
	int rv;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->ifname);

	/* Build a dummy object for the address configuration request */
	req = ni_addrconf_request_new(NI_ADDRCONF_DHCP, AF_INET);
	cfg_object = ni_dbus_object_new(NULL, NULL, req);

	/* Extract configuration from dict */
	if (argc == 0) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "Missing arguments in %s", __func__);
		goto failed;
	}
	if (!__wicked_dbus_set_addrconf_request(req, &argv[0], error)) {
		/* dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "Cannot extract addrconf request from property dict"); */
		goto failed;
	}

	if ((rv = ni_dhcp_acquire(dev, req)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot configure interface %s: %s", dev->ifname,
				ni_strerror(rv));
		goto failed;
	}

	/* We've now initiated the DHCP exchange. It will complete
	 * asynchronously, and when done, we will emit a signal that
	 * notifies the sender of its results. */

	ret = TRUE;

failed:
	ni_addrconf_request_free(req);
	if (cfg_object)
		ni_dbus_object_free(cfg_object);
	return ret;
}

/*
 * Interface.drop(void)
 * Drop a DHCP lease
 */
static dbus_bool_t
__wicked_dbus_dhcp4_drop_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dhcp_device_t *dev = object->handle;
	dbus_bool_t ret = FALSE;
	int rv;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->ifname);
	if (argc == 1) {
		/* FIXME: Extract the lease uuid and pass that along to
		 * ni_dhcp_release. This makes sure we don't cancel the wrong
		 * lease.
		 */
	}

	if ((rv = ni_dhcp_release(dev, NULL)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to drop DHCP lease for interface %s: %s", dev->ifname,
				ni_strerror(rv));
		goto failed;
	}

	ret = TRUE;

failed:
	return ret;
}

static ni_dbus_method_t		wicked_dbus_dhcp4_methods[] = {
	{ "acquire",		"a{sv}",		__wicked_dbus_dhcp4_acquire_svc },
	{ "drop",		"",			__wicked_dbus_dhcp4_drop_svc },
	{ NULL }
};


/*
 * Property name
 */
static dbus_bool_t
__wicked_dbus_dhcp4_get_name(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_dhcp_device_t *dev = ni_dbus_object_get_handle(object);

	ni_dbus_variant_set_string(result, dev->ifname);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_dhcp4_set_name(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_dhcp_device_t *dev = ni_dbus_object_get_handle(object);
	const char *value;

	if (!ni_dbus_variant_get_string(argument, &value))
		return FALSE;
	ni_string_dup(&dev->ifname, value);
	return TRUE;
}

#define WICKED_INTERFACE_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, 0,__wicked_dbus_dhcp4, rw)
#define WICKED_INTERFACE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, 0, __wicked_dbus_dhcp4, rw)

static ni_dbus_property_t	wicked_dbus_dhcp4_properties[] = {
	WICKED_INTERFACE_PROPERTY(STRING, name, RO),

	{ NULL }
};

static const ni_dbus_service_t	wicked_dbus_dhcp4_service = {
	.name = WICKED_DBUS_DHCP4_INTERFACE,
	.methods = wicked_dbus_dhcp4_methods,
	.properties = wicked_dbus_dhcp4_properties,
};
