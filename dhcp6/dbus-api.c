/*
 *	DBus API for wicked dhcp6 supplicant
 *
 *	Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012 Marius Tomaschewski <mt@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 */
/*
 * Much of this code is in src/dbus-objects/... for now.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include "dhcp6/dbus-api.h"
#include "appconfig.h"
#include "util_priv.h"

static ni_dhcp6_request_t *	ni_objectmodel_dhcp6_request_from_dict(const ni_dbus_variant_t *);

static void			__ni_objectmodel_dhcp6_device_release(ni_dbus_object_t *);

static ni_dbus_class_t		ni_objectmodel_dhcp6_device_class = {
	.name		= "dhcp6-device",
	.destroy	= __ni_objectmodel_dhcp6_device_release,
	.superclass	= &ni_objectmodel_addrconf_device_class,
};

static const ni_dbus_service_t	ni_objectmodel_dhcp6_service;

/*
 * Register services and classes for dhcp6 supplicant service
 */
void
ni_objectmodel_dhcp6_init(void)
{
	if (ni_objectmodel_init(NULL) == NULL)
		ni_fatal("Cannot initialize objectmodel, giving up.");
	ni_objectmodel_register_class(&ni_objectmodel_dhcp6_device_class);
	ni_objectmodel_register_service(&ni_objectmodel_dhcp6_service);
}

/*
 * Build a dbus-object encapsulating a network device.
 * If @server is non-NULL, register the object with a canonical object path
 */
static ni_dbus_object_t *
__ni_objectmodel_dhcp6_device_build_object(ni_dbus_server_t *server, ni_dhcp6_device_t *dev)
{
	ni_dbus_object_t *object;
	char object_path[256];

	if (dev->link.ifindex <= 0) {
		ni_error("%s: dhcp6 device has invalid interface index %u",
			dev->ifname, dev->link.ifindex);
		return NULL;
	}

	if (server != NULL) {
		snprintf(object_path, sizeof(object_path), "Interface/%d", dev->link.ifindex);

		object = ni_dbus_server_register_object(server, object_path,
						&ni_objectmodel_dhcp6_device_class,
						ni_dhcp6_device_get(dev));
	} else {
		object = ni_dbus_object_new(&ni_objectmodel_dhcp6_device_class, NULL,
						ni_dhcp6_device_get(dev));
	}

	if (object == NULL)
		ni_fatal("%s: Unable to create dbus object for dhcp6 device",
			dev->ifname);

	ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}

/*
 * Register a network interface with our dbus server,
 * and add the appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_register_dhcp6_device(ni_dbus_server_t *server, ni_dhcp6_device_t *dev)
{
	return __ni_objectmodel_dhcp6_device_build_object(server, dev);
}

/*
 * Extract the dhcp6_device handle from a dbus object
 */
static ni_dhcp6_device_t *
ni_objectmodel_dhcp6_device_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_dhcp6_device_t *dev = ni_dbus_object_get_handle(object);

	if (ni_dbus_object_isa(object, &ni_objectmodel_dhcp6_device_class))
		return dev;

	if (error) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a dhcp6 device)",
			object->path, object->class->name);
	}
	return NULL;
}

/*
 * Destroy a dbus object wrapping a dhcp_device.
 */

void
__ni_objectmodel_dhcp6_device_release(ni_dbus_object_t *object)
{
	ni_dhcp6_device_t *dev = ni_objectmodel_dhcp6_device_unwrap(object, NULL);

	ni_assert(dev != NULL);
	ni_dhcp6_device_put(dev);
	object->handle = NULL;
}

/*
 * Interface.acquire(dict options)
 * Acquire a lease for the given interface.
 *
 * Server side method implementation
 */
static dbus_bool_t
ni_objectmodel_dhcp6_acquire_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dhcp6_device_t *dev;
	ni_uuid_t req_uuid = NI_UUID_INIT;
	ni_dhcp6_request_t *req = NULL;
	char *errdetail = NULL;
	int rv;

	if ((dev = ni_objectmodel_dhcp6_device_unwrap(object, error)) == NULL)
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
	if (!(req = ni_objectmodel_dhcp6_request_from_dict(&argv[0]))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s: unable to extract request from argument",
				method->name);
		goto failed;
	}
	req->uuid = req_uuid;

	if ((rv = ni_dhcp6_acquire(dev, req, &errdetail)) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"%s: DHCPv6 acquire request %s failed: %s%s[%s]",
				dev->ifname, ni_uuid_print(&req->uuid),
				(errdetail ? errdetail : ""),
				(errdetail ? " " : ""),
				ni_strerror(rv));
		ni_string_free(&errdetail);
		goto failed;
	}

	/*
	 * We've now initiated the DHCPv6 exchange.
	 * It will complete asynchronously, and when done, it will
	 * emit a signal, that notifies the sender of its results.
	 *
	 * Remember request for restart and return success.
	 */
	ni_dhcp6_device_set_request(dev, req);
	return TRUE;

failed:
	if (req)
		ni_dhcp6_request_free(req);
	return FALSE;
}

/*
 * Interface.drop(void)
 * Drop a DHCP lease
 */
static dbus_bool_t
ni_objectmodel_dhcp6_drop_svc(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dhcp6_device_t *dev;
	dbus_bool_t ret = FALSE;
	ni_uuid_t uuid;
	int rv;

	if ((dev = ni_objectmodel_dhcp6_device_unwrap(object, error)) == NULL)
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

	if ((rv = ni_dhcp6_release(dev, &uuid)) < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"%s: Unable to drop DHCPv6 lease with UUID %s",
				dev->ifname, ni_uuid_print(&uuid));
		goto failed;
	}

	ret = TRUE;

failed:
	return ret;
}

static ni_dbus_method_t		ni_objectmodel_dhcp6_methods[] = {
	{ "acquire",		"aya{sv}",	.handler = ni_objectmodel_dhcp6_acquire_svc },
	{ "drop",		"ay",		.handler = ni_objectmodel_dhcp6_drop_svc },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_dhcp6_signals[] = {
	{ .name = NI_OBJECTMODEL_LEASE_ACQUIRED_SIGNAL },
	{ .name = NI_OBJECTMODEL_LEASE_RELEASED_SIGNAL },
	{ .name = NI_OBJECTMODEL_LEASE_LOST_SIGNAL },
	{ NULL }
};


/*
 * Properties associated with a DHCP6 request
 */
static ni_dbus_class_t		ni_objectmodel_dhcp6_request_class = {
	.name		= "dhcp6-request",
};

#define DHCP6REQ_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(dhcp6_request, dbus_name, member_name, rw)
#define DHCP6REQ_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(dhcp6_request, dbus_name, member_name, rw)
#define DHCP6REQ_UUID_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UUID_PROPERTY(dhcp6_request, dbus_name, member_name, rw)
#define DHCP6REQ_BOOL_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(dhcp6_request, dbus_name, member_name, rw)
#define DHCP6REQ_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __dhcp6_request, rw)
#define DHCP6REQ_STRING_ARRAY_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(dhcp6_request, dbus_name, member_name, rw)
#define DHCP6REQ_DICT_PROPERTY(member, fstem, rw) \
	___NI_DBUS_PROPERTY(NI_DBUS_DICT_SIGNATURE, member, fstem, \
				ni_objectmodel_dhcp6_request, rw)

static ni_dhcp6_request_t *
__ni_objectmodel_get_dhcp6_request(const ni_dbus_object_t *object, DBusError *error)
{
	ni_dhcp6_request_t *req = ni_dbus_object_get_handle(object);

	if (ni_dbus_object_isa(object, &ni_objectmodel_dhcp6_request_class))
		return req;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a dhcp6 request)",
			object->path, object->class->name);

	return NULL;
}

static void *
ni_objectmodel_get_dhcp6_request(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_get_dhcp6_request(object, error);
}

static dbus_bool_t
ni_objectmodel_dhcp6_request_get_fqdn(const ni_dbus_object_t *object,
			const ni_dbus_property_t *property,
			ni_dbus_variant_t *result,
			DBusError *error)
{
	const ni_dhcp6_request_t *req = NULL;

	if (!(req = __ni_objectmodel_get_dhcp6_request(object, error)))
		return FALSE;

	if (req->fqdn.enabled != NI_TRISTATE_DEFAULT)
		ni_dbus_dict_add_int32(result, "enabled", req->fqdn.enabled);

	if (req->fqdn.enabled != NI_TRISTATE_DISABLE) {
		ni_dbus_dict_add_int32(result, "update",  req->fqdn.update);
		ni_dbus_dict_add_bool (result, "qualify", req->fqdn.qualify);
	}

	return TRUE;
}

static dbus_bool_t
ni_objectmodel_dhcp6_request_set_fqdn(ni_dbus_object_t *object,
			const ni_dbus_property_t *property,
			const ni_dbus_variant_t *argument,
			DBusError *error)
{
	ni_dhcp6_request_t *req = NULL;
	dbus_bool_t bval;
	int32_t update;

	if (!(req = __ni_objectmodel_get_dhcp6_request(object, error)))
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

		if (!ni_dbus_dict_get_bool(argument, "qualify", &bval))
			req->fqdn.qualify = TRUE;
		else
			req->fqdn.qualify = bval;
	}
	return TRUE;
}

static ni_dbus_property_t	dhcp6_request_properties[] = {
	DHCP6REQ_BOOL_PROPERTY(enabled, enabled, RO),
	DHCP6REQ_UUID_PROPERTY(uuid, uuid, RO),
	DHCP6REQ_UINT_PROPERTY(flags, flags, RO),
	DHCP6REQ_UINT_PROPERTY(mode, mode, RO),
	DHCP6REQ_BOOL_PROPERTY(rapid-commit, rapid_commit, RO),
	DHCP6REQ_UINT_PROPERTY(address-length, address_len, RO),
	DHCP6REQ_STRING_PROPERTY(client-id, clientid, RO),
	//DHCP6REQ_STRING_PROPERTY(vendor-class, vendor_class, RO),
	DHCP6REQ_UINT_PROPERTY(start-delay, start_delay, RO),
	DHCP6REQ_UINT_PROPERTY(defer-timeout, defer_timeout, RO),
	DHCP6REQ_UINT_PROPERTY(acquire-timeout, acquire_timeout, RO),
	DHCP6REQ_UINT_PROPERTY(lease-time, lease_time, RO),
	DHCP6REQ_BOOL_PROPERTY(recover-lease, recover_lease, RO),
	DHCP6REQ_BOOL_PROPERTY(release-lease, release_lease, RO),
	DHCP6REQ_UINT_PROPERTY(update, update, RO),
	DHCP6REQ_STRING_PROPERTY(hostname, hostname, RO),
	DHCP6REQ_DICT_PROPERTY(fqdn, fqdn, RO),
	DHCP6REQ_STRING_ARRAY_PROPERTY(request-options, request_options, RO),
	{ NULL },
};

static ni_dbus_service_t	ni_objectmodel_dhcp6_request_service = {
	.name		= NI_OBJECTMODEL_DHCP6_INTERFACE ".Request",
	.compatible	= &ni_objectmodel_dhcp6_request_class,
	.properties	= dhcp6_request_properties,
};

/*
 * Create a dummy DBus object encapsulating a dhcp6 request
 */
static ni_dbus_object_t *
__dhcp6_request_dummy_object(ni_dhcp6_request_t *req)
{
	static ni_dbus_object_t dummy;

	memset(&dummy, 0, sizeof(dummy));
	dummy.handle = req;
	dummy.class = &ni_objectmodel_dhcp6_request_class;
	return &dummy;
}

/*
 * This is a helper function extracts a ni_dhcp6_request_t from a dbus dict
 */
ni_dhcp6_request_t *
ni_objectmodel_dhcp6_request_from_dict(const ni_dbus_variant_t *dict)
{
	ni_dhcp6_request_t *req;
	ni_dbus_object_t *dummy;

	req = ni_dhcp6_request_new();

	dummy = __dhcp6_request_dummy_object(req);
	if (!ni_dbus_object_set_properties_from_dict(dummy, &ni_objectmodel_dhcp6_request_service, dict, NULL)) {
		ni_dhcp6_request_free(req);
		return NULL;
	}

	return req;
}

/*
 * Property name
 */
static void *
ni_objectmodel_get_dhcp6_device(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_dhcp6_device_t *dev;

	dev = ni_objectmodel_dhcp6_device_unwrap(object, error);
	return dev;
}

/*
 * Property config
 */
static dbus_bool_t
__ni_objectmodel_dhcp6_get_request(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_dbus_object_t *dummy;
	ni_dhcp6_device_t *dev;
	
	if (!(dev = ni_objectmodel_dhcp6_device_unwrap(object, error)))
		return FALSE;

	if (dev->request == NULL)
		return ni_dbus_error_property_not_present(error, object->path, property->name);
	dummy = __dhcp6_request_dummy_object(dev->request);

	ni_dbus_variant_init_dict(result);
	return ni_dbus_object_get_properties_as_dict(dummy, &ni_objectmodel_dhcp6_request_service, result, error);
}

static dbus_bool_t
__ni_objectmodel_dhcp6_set_request(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_dbus_object_t *dummy;
	ni_dhcp6_device_t *dev;

	if (!(dev = ni_objectmodel_dhcp6_device_unwrap(object, error)))
		return FALSE;

	if (dev->request == NULL)
		dev->request = ni_dhcp6_request_new();
	dummy = __dhcp6_request_dummy_object(dev->request);

	return ni_dbus_object_set_properties_from_dict(dummy, &ni_objectmodel_dhcp6_request_service, argument, error);
}


#define DHCP6DEV_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __ni_objectmodel_dhcp6, rw)

#define DHCP6DEV_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(dhcp6_device, dbus_name, member_name, rw)

#define DHCP6DEV_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __ni_objectmodel_dhcp6, rw)

static ni_dbus_property_t	ni_objectmodel_dhcp6_properties[] = {
	DHCP6DEV_STRING_PROPERTY(name, ifname, RO),
	DHCP6DEV_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, request, RO),

	{ NULL }
};

static const ni_dbus_service_t	ni_objectmodel_dhcp6_service = {
	.name		= NI_OBJECTMODEL_DHCP6_INTERFACE,
	.compatible	= &ni_objectmodel_dhcp6_device_class,
	.methods	= ni_objectmodel_dhcp6_methods,
	.signals	= ni_objectmodel_dhcp6_signals,
	.properties	= ni_objectmodel_dhcp6_properties,
};
