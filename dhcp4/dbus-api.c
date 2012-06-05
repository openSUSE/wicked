/*
 * DBus API for wicked dhcp4 supplicant
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 *
 * Much of this code is in dbus-objects/dhcp4.c for now.
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
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/objectmodel.h>
#include "dhcp.h"

static ni_dhcp4_request_t *	ni_objectmodel_dhcp4_request_from_dict(const ni_dbus_variant_t *);
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
ni_objectmodel_unwrap_dhcp4_device(const ni_dbus_object_t *object, DBusError *error)
{
	ni_dhcp_device_t *dev = ni_dbus_object_get_handle(object);

	if (ni_dbus_object_isa(object, &ni_objectmodel_dhcp4dev_class))
		return dev;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a dhcp4 device)",
			object->path, object->class->name);

	return NULL;
}

/*
 * Destroy a dbus object wrapping a dhcp_device.
 */
void
__ni_objectmodel_dhcp_device_release(ni_dbus_object_t *object)
{
	ni_dhcp_device_t *dev = ni_objectmodel_unwrap_dhcp4_device(object, NULL);

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
	ni_dhcp_device_t *dev;
	ni_uuid_t req_uuid = NI_UUID_INIT;
	ni_dhcp4_request_t *req = NULL;
	dbus_bool_t ret = FALSE;
	int rv;

	if ((dev = ni_objectmodel_unwrap_dhcp4_device(object, error)) == NULL)
		goto failed;

	if (argc == 2) {
		if (!ni_dbus_variant_get_uuid(&argv[0], &req_uuid)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s: unable to extract uuid from argument",
					method->name);
			goto failed;
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

	ni_debug_dhcp("%s(dev=%s)", __func__, dev->ifname);

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

	ni_dhcp_device_set_request(dev, req);
	return TRUE;

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
	ni_dhcp_device_t *dev;
	dbus_bool_t ret = FALSE;
	ni_uuid_t uuid;
	int rv;

	if ((dev = ni_objectmodel_unwrap_dhcp4_device(object, error)) == NULL)
		goto failed;

	ni_debug_dhcp("%s(dev=%s)", __func__, dev->ifname);

	memset(&uuid, 0, sizeof(uuid));
	if (argc == 1) {
		/* Extract the lease uuid and pass that along to ni_dhcp_release.
		 * This makes sure we don't cancel the wrong lease.
		 */
		if (!ni_dbus_variant_get_uuid(&argv[0], &uuid)) {
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

static ni_dbus_method_t		wicked_dbus_dhcp4_signals[] = {
	{ NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL },
	{ NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL },
	{ NI_OBJECTMODEL_LEASE_LOST_SIGNAL },
	{ NULL }
};

/*
 * Create or delete a dhcp4 request object
 */
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
 * Properties associated with a DHCP4 request
 */
static ni_dbus_class_t		ni_objectmodel_dhcp4req_class = {
	.name		= "dhcp4-request",
};

#define DHCP4REQ_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(dhcp4_request, dbus_name, member_name, rw)
#define DHCP4REQ_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(dhcp4_request, dbus_name, member_name, rw)
#define DHCP4REQ_UUID_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UUID_PROPERTY(dhcp4_request, dbus_name, member_name, rw)
#define DHCP4REQ_BOOL_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(dhcp4_request, dbus_name, member_name, rw)
#define DHCP4REQ_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __dhcp4_request, rw)

static ni_dhcp4_request_t *
__ni_objectmodel_get_dhcp4_request(const ni_dbus_object_t *object, DBusError *error)
{
	ni_dhcp4_request_t *req = ni_dbus_object_get_handle(object);

	if (ni_dbus_object_isa(object, &ni_objectmodel_dhcp4req_class))
		return req;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a dhcp4 request)",
			object->path, object->class->name);

	return NULL;
}

static void *
ni_objectmodel_get_dhcp4_request(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_get_dhcp4_request(object, error);
}

static ni_dbus_property_t	dhcp4_request_properties[] = {
	DHCP4REQ_BOOL_PROPERTY(enabled, enabled, RO),
	DHCP4REQ_UUID_PROPERTY(uuid, uuid, RO),
	DHCP4REQ_UINT_PROPERTY(settle-timeout, settle_timeout, RO),
	DHCP4REQ_UINT_PROPERTY(acquire-timeout, acquire_timeout, RO),
	DHCP4REQ_STRING_PROPERTY(hostname, hostname, RO),
	DHCP4REQ_STRING_PROPERTY(client-id, clientid, RO),
	DHCP4REQ_STRING_PROPERTY(vendor-class, vendor_class, RO),
	DHCP4REQ_UINT_PROPERTY(update, update, RO),
	{ NULL },
};

static ni_dbus_service_t	ni_objectmodel_dhcp4req_service = {
	.name		= NI_OBJECTMODEL_DHCP4_INTERFACE ".Request",
	.compatible	= &ni_objectmodel_dhcp4req_class,
	.properties	= dhcp4_request_properties,
};

/*
 * Create a dummy DBus object encapsulating a dhcp4 request
 */
static ni_dbus_object_t *
__dhcp4_request_dummy_object(ni_dhcp4_request_t *req)
{
	static ni_dbus_object_t dummy;

	memset(&dummy, 0, sizeof(dummy));
	dummy.handle = req;
	dummy.class = &ni_objectmodel_dhcp4req_class;
	return &dummy;
}

/*
 * This is a helper function extracts a ni_dhcp4_request_t from a dbus dict
 */
ni_dhcp4_request_t *
ni_objectmodel_dhcp4_request_from_dict(const ni_dbus_variant_t *dict)
{
	ni_dhcp4_request_t *req;
	ni_dbus_object_t *dummy;

	req = ni_dhcp4_request_new();

	dummy = __dhcp4_request_dummy_object(req);
	if (!ni_dbus_object_set_properties_from_dict(dummy, &ni_objectmodel_dhcp4req_service, dict, NULL)) {
		ni_dhcp4_request_free(req);
		return NULL;
	}

	return req;
}

/*
 * Property name
 */
static void *
ni_objectmodel_get_dhcp_device(const ni_dbus_object_t *object, DBusError *error)
{
	ni_dhcp_device_t *dev;

	dev = ni_objectmodel_unwrap_dhcp4_device(object, error);
	return dev;
}

/*
 * Property config
 */
static dbus_bool_t
__wicked_dbus_dhcp4_get_request(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_dbus_object_t *dummy;
	ni_dhcp_device_t *dev;
	
	if (!(dev = ni_objectmodel_unwrap_dhcp4_device(object, error)))
		return FALSE;

	if (dev->request == NULL)
		return ni_dbus_error_property_not_present(error, object->path, property->name);
	dummy = __dhcp4_request_dummy_object(dev->request);

	ni_dbus_variant_init_dict(result);
	return ni_dbus_object_get_properties_as_dict(dummy, &ni_objectmodel_dhcp4req_service, result, error);
}

static dbus_bool_t
__wicked_dbus_dhcp4_set_request(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_dbus_object_t *dummy;
	ni_dhcp_device_t *dev;

	if (!(dev = ni_objectmodel_unwrap_dhcp4_device(object, error)))
		return FALSE;

	if (dev->request == NULL)
		dev->request = ni_dhcp4_request_new();
	dummy = __dhcp4_request_dummy_object(dev->request);

	return ni_dbus_object_set_properties_from_dict(dummy, &ni_objectmodel_dhcp4req_service, argument, error);
}


#define DHCP4DEV_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __wicked_dbus_dhcp4, rw)
#define DHCP4DEV_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(dhcp_device, dbus_name, member_name, rw)
#define DHCP4DEV_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_dhcp4, rw)

static ni_dbus_property_t	wicked_dbus_dhcp4_properties[] = {
	DHCP4DEV_STRING_PROPERTY(name, ifname, RO),

	DHCP4DEV_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, request, RO),

	{ NULL }
};

static const ni_dbus_service_t	wicked_dbus_dhcp4_service = {
	.name		= NI_OBJECTMODEL_DHCP4_INTERFACE,
	.compatible	= &ni_objectmodel_dhcp4dev_class,
	.methods	= wicked_dbus_dhcp4_methods,
	.signals	= wicked_dbus_dhcp4_signals,
	.properties	= wicked_dbus_dhcp4_properties,
};
