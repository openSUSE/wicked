/*
 * DBus API for wicked dhcp4 supplicant
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
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
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/dbus.h>
#include <wicked/dbus-errors.h>
#include "dbus-objects/model.h"
#include "debug.h"
#include "dhcp.h"

static ni_dhcp4_request_t *	ni_objectmodel_dhcp4_request_from_dict(const ni_dbus_variant_t *);
static ni_dhcp4_request_t *	ni_dhcp4_request_new(void);
static void			ni_dhcp4_request_free(ni_dhcp4_request_t *);
static void			__ni_objectmodel_dhcp_device_release(ni_dbus_object_t *);

static ni_dbus_class_t		ni_objectmodel_dhcp4dev_class = {
	.name		= "dhcp4-device",
	.destroy	= __ni_objectmodel_dhcp_device_release,
};

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
						&ni_objectmodel_dhcp4dev_class,
						ni_dhcp_device_get(dev));
	} else {
		object = ni_dbus_object_new(&ni_objectmodel_dhcp4dev_class, NULL,
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

/*
 * Extract the dhcp4_device handle from a dbus object
 */
static ni_dhcp_device_t *
ni_objectmodel_unwrap_dhcp4_device(const ni_dbus_object_t *object)
{
	ni_dhcp_device_t *dev = object->handle;

	return object->class == &ni_objectmodel_dhcp4dev_class? dev : NULL;
}

/*
 * Destroy a dbus object wrapping a dhcp_device.
 */
void
__ni_objectmodel_dhcp_device_release(ni_dbus_object_t *object)
{
	ni_dhcp_device_t *dev = ni_objectmodel_unwrap_dhcp4_device(object);

	ni_assert(dev != NULL);
	ni_dhcp_device_put(dev);
	object->handle = NULL;
}

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
	ni_dhcp_device_t *dev = ni_objectmodel_unwrap_dhcp4_device(object);
	ni_uuid_t req_uuid = NI_UUID_INIT;
	ni_dhcp4_request_t *req = NULL;
	dbus_bool_t ret = FALSE;
	int rv;

	if ((dev = ni_objectmodel_unwrap_dhcp4_device(object)) == NULL) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"method %s called on incompatible object (class %s)",
				method->name, object->class->name);
		goto failed;
	}

	if (argc == 2) {
		unsigned int dummy;

		if (!ni_dbus_variant_get_byte_array_minmax(&argv[0], req_uuid.octets, &dummy, 16, 16)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s: unable to extract uuid from argument",
					method->name);
		}
		argc--;
		argv++;
	}

	if (argc != 1) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"method %s called with %d arguments (expected 1)",
				argc);
		goto failed;
	}

	NI_TRACE_ENTER_ARGS("dev=%s", dev->ifname);

	/* Extract configuration from dict */
	if (!(req = ni_objectmodel_dhcp4_request_from_dict(&argv[0]))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: unable to extract request from argument",
				method->name);
		goto failed;
	}
	req->uuid = req_uuid;

	if ((rv = ni_dhcp_acquire(dev, req)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"cannot configure interface %s: %s", dev->ifname,
				ni_strerror(rv));
		goto failed;
	}

	/* We've now initiated the DHCP exchange. It will complete
	 * asynchronously, and when done, we will emit a signal that
	 * notifies the sender of its results. */

	ret = TRUE;

failed:
	if (req)
		ni_dhcp4_request_free(req);
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
	ni_dhcp_device_t *dev = ni_objectmodel_unwrap_dhcp4_device(object);
	dbus_bool_t ret = FALSE;
	ni_uuid_t uuid;
	int rv;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->ifname);

	memset(&uuid, 0, sizeof(uuid));
	if (argc == 1) {
		/* Extract the lease uuid and pass that along to ni_dhcp_release.
		 * This makes sure we don't cancel the wrong lease.
		 */
		unsigned int len;

		if (!ni_dbus_variant_get_byte_array_minmax(&argv[0], uuid.octets, &len, 16, 16)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "bad uuid argument");
			goto failed;
		}
	}

	if ((rv = ni_dhcp_release(dev, &uuid)) < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"Unable to drop DHCP lease for interface %s", dev->ifname);
		goto failed;
	}

	ret = TRUE;

failed:
	return ret;
}

static ni_dbus_method_t		wicked_dbus_dhcp4_methods[] = {
	{ "acquire",		"aya{sv}",		__wicked_dbus_dhcp4_acquire_svc },
	{ "drop",		"ay",			__wicked_dbus_dhcp4_drop_svc },
	{ NULL }
};

/*
 * This is a helper function extracts a ni_dhcp4_request_t from a dbus dict
 */
ni_dhcp4_request_t *
ni_objectmodel_dhcp4_request_from_dict(const ni_dbus_variant_t *dict)
{
	ni_dhcp4_request_t *req;
	const ni_dbus_variant_t *child;
	const char *string_value;
	unsigned int dummy;
	uint32_t value32;

	if (!ni_dbus_variant_is_dict(dict))
		return NULL;

	req = ni_dhcp4_request_new();
	if (ni_dbus_dict_get_uint32(dict, "settle-timeout", &value32))
		req->settle_timeout = value32;
	if (ni_dbus_dict_get_uint32(dict, "acquire-timeout", &value32))
		req->acquire_timeout = value32;

	if ((child = ni_dbus_dict_get(dict, "uuid")) != NULL
	 && !ni_dbus_variant_get_byte_array_minmax(child, req->uuid.octets, &dummy, 16, 16))
		goto failed;

	if (ni_dbus_dict_get_string(dict, "hostname", &string_value))
		ni_string_dup(&req->hostname, string_value);
	if (ni_dbus_dict_get_string(dict, "clientid", &string_value))
		ni_string_dup(&req->clientid, string_value);
	if (ni_dbus_dict_get_string(dict, "vendor-class", &string_value))
		ni_string_dup(&req->vendor_class, string_value);
	if (ni_dbus_dict_get_uint32(dict, "lease-time", &value32))
		req->lease_time = value32;

	if (ni_dbus_dict_get_uint32(dict, "update", &value32))
		req->update = value32;

	return req;

failed:
	ni_dhcp4_request_free(req);
	return NULL;
}

ni_dhcp4_request_t *
ni_dhcp4_request_new(void)
{
	ni_dhcp4_request_t *req;

	req = calloc(1, sizeof(*req));

	/* By default, we try to obtain all sorts of config from the server */
	req->update = ~0;

	return req;
}

void
ni_dhcp4_request_free(ni_dhcp4_request_t *req)
{
	ni_string_free(&req->hostname);
	ni_string_free(&req->clientid);
	ni_string_free(&req->vendor_class);
	free(req);
}

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
	NI_DBUS_PROPERTY(type, __name, __wicked_dbus_dhcp4, rw)
#define WICKED_INTERFACE_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_dhcp4, rw)

static ni_dbus_property_t	wicked_dbus_dhcp4_properties[] = {
	WICKED_INTERFACE_PROPERTY(STRING, name, RO),

	{ NULL }
};

static const ni_dbus_service_t	wicked_dbus_dhcp4_service = {
	.name		= NI_OBJECTMODEL_DHCP4_INTERFACE,
	.compatible	= &ni_objectmodel_dhcp4dev_class,
	.methods	= wicked_dbus_dhcp4_methods,
	.properties	= wicked_dbus_dhcp4_properties,
};
