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
#include "appconfig.h"
#include "dhcp4/dhcp4.h"
#include "dhcp.h"

static ni_dhcp4_request_t *	ni_objectmodel_dhcp4_request_from_dict(const ni_dbus_variant_t *);
static void			__ni_objectmodel_dhcp4_device_release(ni_dbus_object_t *);

static ni_dbus_class_t		ni_objectmodel_dhcp4dev_class = {
	.name		= "dhcp4-device",
	.destroy	= __ni_objectmodel_dhcp4_device_release,
	.superclass	= &ni_objectmodel_addrconf_device_class,
};

static const ni_dbus_service_t	ni_objectmodel_dhcp4_service;

/*
 * Register services and classes for dhcp4 supplicant service
 */
void
ni_objectmodel_dhcp4_init(void)
{
	if (ni_objectmodel_init(NULL) == NULL)
		ni_fatal("Cannot initialize objectmodel, giving up.");
	ni_objectmodel_register_class(&ni_objectmodel_dhcp4dev_class);
	ni_objectmodel_register_service(&ni_objectmodel_dhcp4_service);
}

/*
 * Build a dbus-object encapsulating a network device.
 * If @server is non-NULL, register the object with a canonical object path
 */
static ni_dbus_object_t *
__ni_objectmodel_build_dhcp4_device_object(ni_dbus_server_t *server, ni_dhcp4_device_t *dev)
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
						ni_dhcp4_device_get(dev));
	} else {
		object = ni_dbus_object_new(&ni_objectmodel_dhcp4dev_class, NULL,
						ni_dhcp4_device_get(dev));
	}

	if (object == NULL)
		ni_fatal("Unable to create dbus object for dhcp4 device %s", dev->ifname);

	ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}


/*
 * Register a network interface with our dbus server,
 * and add the appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_register_dhcp4_device(ni_dbus_server_t *server, ni_dhcp4_device_t *dev)
{
	return __ni_objectmodel_build_dhcp4_device_object(server, dev);
}

/*
 * Extract the dhcp4_device handle from a dbus object
 */
static ni_dhcp4_device_t *
ni_objectmodel_unwrap_dhcp4_device(const ni_dbus_object_t *object, DBusError *error)
{
	ni_dhcp4_device_t *dev = ni_dbus_object_get_handle(object);

	if (ni_dbus_object_isa(object, &ni_objectmodel_dhcp4dev_class))
		return dev;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a dhcp4 device)",
			object->path, object->class->name);

	return NULL;
}

/*
 * Destroy a dbus object wrapping a dhcp4_device.
 */
void
__ni_objectmodel_dhcp4_device_release(ni_dbus_object_t *object)
{
	ni_dhcp4_device_t *dev = ni_objectmodel_unwrap_dhcp4_device(object, NULL);

	ni_assert(dev != NULL);
	ni_dhcp4_device_put(dev);
	object->handle = NULL;
}

/*
 * Interface.acquire(dict options)
 * Acquire a lease for the given interface.
 *
 * Server side method implementation
 */
static dbus_bool_t
__ni_objectmodel_dhcp4_acquire_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dhcp4_device_t *dev;
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
				method->name, argc);
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

	if ((rv = ni_dhcp4_acquire(dev, req)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"cannot configure interface %s: %s", dev->ifname,
				ni_strerror(rv));
		goto failed;
	}

	/* We've now initiated the DHCP4 exchange. It will complete
	 * asynchronously, and when done, we will emit a signal that
	 * notifies the sender of its results. */

	ni_dhcp4_device_set_request(dev, req);
	return TRUE;

failed:
	if (req)
		ni_dhcp4_request_free(req);
	return ret;
}

/*
 * Interface.drop(void)
 * Drop a DHCP4 lease
 */
static dbus_bool_t
__ni_objectmodel_dhcp4_drop_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dhcp4_device_t *dev;
	dbus_bool_t ret = FALSE;
	ni_uuid_t uuid;
	int rv;

	if ((dev = ni_objectmodel_unwrap_dhcp4_device(object, error)) == NULL)
		goto failed;

	ni_debug_dhcp("%s(dev=%s)", __func__, dev->ifname);

	memset(&uuid, 0, sizeof(uuid));
	if (argc == 1) {
		/* Extract the lease uuid and pass that along to ni_dhcp4_release.
		 * This makes sure we don't cancel the wrong lease.
		 */
		if (!ni_dbus_variant_get_uuid(&argv[0], &uuid)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "bad uuid argument");
			goto failed;
		}
	}

	if ((rv = ni_dhcp4_release(dev, &uuid)) < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"Unable to drop DHCP4 lease for interface %s", dev->ifname);
		goto failed;
	}

	ret = TRUE;

failed:
	return ret;
}

static ni_dbus_method_t		ni_objectmodel_dhcp4_methods[] = {
	{ "acquire",		"aya{sv}",	.handler = __ni_objectmodel_dhcp4_acquire_svc },
	{ "drop",		"ay",		.handler = __ni_objectmodel_dhcp4_drop_svc },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_dhcp4_signals[] = {
	{ .name = NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL },
	{ .name = NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL },
	{ .name = NI_OBJECTMODEL_LEASE_LOST_SIGNAL },
	{ NULL }
};

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
#define DHCP4REQ_STRING_ARRAY_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(dhcp4_request, dbus_name, member_name, rw)
#define DHCP4REQ_DICT_PROPERTY(member, fstem, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, member, fstem, \
				ni_objectmodel_dhcp4_request, rw)

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
ni_objectmodel_get_dhcp4_request(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_get_dhcp4_request(object, error);
}

static dbus_bool_t
ni_objectmodel_dhcp4_request_set_user_class(ni_dbus_object_t *object,
			const ni_dbus_property_t *property,
			const ni_dbus_variant_t *argument,
			DBusError *error)
{
	ni_dhcp4_request_t *req = NULL;
	ni_dhcp4_user_class_t *uc = NULL;
	ni_dbus_variant_t *var = NULL;
	uint32_t format;
	size_t total_len = 0;
	size_t len;

	if (!(req = __ni_objectmodel_get_dhcp4_request(object, error)))
		return FALSE;

	uc = &req->user_class;

	if (!ni_dbus_dict_get_uint32(argument, "format", &format))
		return FALSE;

	if (format != NI_DHCP4_USER_CLASS_RFC3004 && format != NI_DHCP4_USER_CLASS_STRING) {
		ni_warn("Invalid user class format (%u) obtained", format);
		return FALSE;
	}
	uc->format = format;

	while ((var = ni_dbus_dict_get_next(argument, "identifier", var))) {
		if (!(len = ni_string_len(var->string_value))) {
			ni_warn("Empty user class identifier found");
			return FALSE;
		}

		if (format == NI_DHCP4_USER_CLASS_STRING && uc->class_id.count)
			break; /* only one user class identifier for this format type */

		if (!ni_dhcp_check_user_class_id(var->string_value, len)) {
			ni_warn("Suspect user class id string: '%s' obtained. Skipping.",
				ni_print_suspect(var->string_value, len));
			return FALSE;
		}

		if(uc->format == NI_DHCP4_USER_CLASS_RFC3004)
			total_len += len + 1;
		else
			total_len += len;

		if (len >= 255 || total_len >= 255) {
			ni_warn("User class data exceeds maximum allowed length.");
			ni_string_array_destroy(&uc->class_id);
			return FALSE;
		}

		ni_string_array_append(&uc->class_id, var->string_value);
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_dhcp4_request_get_user_class(const ni_dbus_object_t *object,
			const ni_dbus_property_t *property,
			ni_dbus_variant_t *result,
			DBusError *error)
{
	ni_dhcp4_request_t *req = NULL;
	ni_dhcp4_user_class_t *uc = NULL;
	unsigned int i;
	size_t len;

	if (!(req = __ni_objectmodel_get_dhcp4_request(object, error)))
		return FALSE;

	uc = &req->user_class;

	if (uc->format != NI_DHCP4_USER_CLASS_RFC3004 && uc->format != NI_DHCP4_USER_CLASS_STRING) {
		ni_warn("Invalid user class format (%u) found", uc->format);
		return FALSE;
	}

	if (!uc->class_id.count)
		return FALSE;

	ni_dbus_dict_add_uint32(result, "format", uc->format);

	for (i = 0; i < uc->class_id.count; ++i) {
		len = ni_string_empty(uc->class_id.data[i]);
		if (!ni_check_domain_name(uc->class_id.data[i], len, 0))
			ni_warn("Suspect user class id string: '%s' found. Skipping.",
				ni_print_suspect(uc->class_id.data[i], len));
		else
			ni_dbus_dict_add_string(result, "identifier", uc->class_id.data[i]);
		if (uc->format == NI_DHCP4_USER_CLASS_STRING)
			break; /* a single string */
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_dhcp4_request_get_fqdn(const ni_dbus_object_t *object,
			const ni_dbus_property_t *property,
			ni_dbus_variant_t *result,
			DBusError *error)
{
	const ni_dhcp4_request_t *req = NULL;

	if (!(req = __ni_objectmodel_get_dhcp4_request(object, error)))
		return FALSE;

	if (req->fqdn.enabled != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "enabled", req->fqdn.enabled);

	if (req->fqdn.enabled != NI_TRISTATE_DISABLE) {
		ni_dbus_dict_add_int32(result, "update", req->fqdn.update);
		ni_dbus_dict_add_bool (result, "encode", req->fqdn.encode);
		ni_dbus_dict_add_bool (result, "qualify", req->fqdn.qualify);
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_dhcp4_request_set_fqdn(ni_dbus_object_t *object,
			const ni_dbus_property_t *property,
			const ni_dbus_variant_t *argument,
			DBusError *error)
{
	ni_dhcp4_request_t *req = NULL;
	dbus_bool_t bval;
	int32_t update;

	if (!(req = __ni_objectmodel_get_dhcp4_request(object, error)))
		return FALSE;

	if (!ni_dbus_dict_get_int32(argument, "enabled", &req->fqdn.enabled))
		req->fqdn.enabled = NI_TRISTATE_DEFAULT;

	if (req->fqdn.enabled != NI_TRISTATE_DISABLE) {
		if (!ni_dbus_dict_get_int32(argument, "update", &update))
			req->fqdn.update = NI_DHCP_FQDN_UPDATE_BOTH;
		else
			switch (update) {
			case NI_DHCP_FQDN_UPDATE_BOTH:
			case NI_DHCP_FQDN_UPDATE_NONE:
			case NI_DHCP_FQDN_UPDATE_PTR:
				req->fqdn.update = update;
				break;
			default:
				return FALSE;
			}

		if (!ni_dbus_dict_get_bool(argument, "encoded", &bval))
			req->fqdn.encode = TRUE;
		else
			req->fqdn.encode = bval;

		if (!ni_dbus_dict_get_bool(argument, "qualify", &bval))
			req->fqdn.qualify = TRUE;
		else
			req->fqdn.qualify = bval;
	}
	return TRUE;
}

static ni_dbus_property_t	dhcp4_request_properties[] = {
	DHCP4REQ_BOOL_PROPERTY(enabled, enabled, RO),
	DHCP4REQ_UUID_PROPERTY(uuid, uuid, RO),
	DHCP4REQ_UINT_PROPERTY(flags, flags, RO),
	DHCP4REQ_STRING_PROPERTY(client-id, clientid, RO),
	DHCP4REQ_STRING_PROPERTY(vendor-class, vendor_class, RO),
	DHCP4REQ_DICT_PROPERTY(user-class, user_class, RO),
	DHCP4REQ_UINT_PROPERTY(start-delay, start_delay, RO),
	DHCP4REQ_UINT_PROPERTY(defer-timeout, defer_timeout, RO),
	DHCP4REQ_UINT_PROPERTY(acquire-timeout, acquire_timeout, RO),
	DHCP4REQ_UINT_PROPERTY(lease-time, lease_time, RO),
	DHCP4REQ_BOOL_PROPERTY(recover-lease, recover_lease, RO),
	DHCP4REQ_BOOL_PROPERTY(release-lease, release_lease, RO),
	DHCP4REQ_UINT_PROPERTY(update, update, RO),
	DHCP4REQ_STRING_PROPERTY(hostname, hostname, RO),
	DHCP4REQ_DICT_PROPERTY(fqdn, fqdn, RO),
	DHCP4REQ_UINT_PROPERTY(route-priority, route_priority, RO),

	DHCP4REQ_STRING_ARRAY_PROPERTY(request-options, request_options, RO),

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
ni_objectmodel_get_dhcp4_device(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_dhcp4_device_t *dev;

	dev = ni_objectmodel_unwrap_dhcp4_device(object, error);
	return dev;
}

/*
 * Property config
 */
static dbus_bool_t
__ni_objectmodel_dhcp4_get_request(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_dbus_object_t *dummy;
	ni_dhcp4_device_t *dev;
	
	if (!(dev = ni_objectmodel_unwrap_dhcp4_device(object, error)))
		return FALSE;

	if (dev->request == NULL)
		return ni_dbus_error_property_not_present(error, object->path, property->name);
	dummy = __dhcp4_request_dummy_object(dev->request);

	ni_dbus_variant_init_dict(result);
	return ni_dbus_object_get_properties_as_dict(dummy, &ni_objectmodel_dhcp4req_service, result, error);
}

static dbus_bool_t
__ni_objectmodel_dhcp4_set_request(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_dbus_object_t *dummy;
	ni_dhcp4_device_t *dev;

	if (!(dev = ni_objectmodel_unwrap_dhcp4_device(object, error)))
		return FALSE;

	if (dev->request == NULL)
		dev->request = ni_dhcp4_request_new();
	dummy = __dhcp4_request_dummy_object(dev->request);

	return ni_dbus_object_set_properties_from_dict(dummy, &ni_objectmodel_dhcp4req_service, argument, error);
}


#define DHCP4DEV_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __ni_objectmodel_dhcp4, rw)
#define DHCP4DEV_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(dhcp4_device, dbus_name, member_name, rw)
#define DHCP4DEV_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __ni_objectmodel_dhcp4, rw)

static ni_dbus_property_t	ni_objectmodel_dhcp4_properties[] = {
	DHCP4DEV_STRING_PROPERTY(name, ifname, RO),

	DHCP4DEV_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, request, RO),

	{ NULL }
};

static const ni_dbus_service_t	ni_objectmodel_dhcp4_service = {
	.name		= NI_OBJECTMODEL_DHCP4_INTERFACE,
	.compatible	= &ni_objectmodel_dhcp4dev_class,
	.methods	= ni_objectmodel_dhcp4_methods,
	.signals	= ni_objectmodel_dhcp4_signals,
	.properties	= ni_objectmodel_dhcp4_properties,
};
