/*
 * Simple DBus client functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <dbus/dbus.h>
#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wicked/util.h>
#include <wicked/logging.h>
#include "socket_priv.h"
#include "dbus-common.h"
#include "dbus-client.h"
#include "dbus-dict.h"
#include "dbus-object.h"
#include "debug.h"

struct ni_dbus_client {
	ni_dbus_connection_t *	connection;
	char *			bus_name;
	unsigned int		call_timeout;
	const ni_intmap_t *	error_map;
};

struct ni_dbus_client_object {
	ni_dbus_client_t *	client;
	char *			default_interface;
};


static dbus_bool_t	__ni_dbus_object_get_managed_object_interfaces(ni_dbus_object_t *, DBusMessageIter *);
static dbus_bool_t	__ni_dbus_object_get_managed_object_properties(ni_dbus_object_t *proxy,
					const ni_dbus_service_t *service,
					DBusMessageIter *iter);

/*
 * Constructor for DBus client handle
 */
ni_dbus_client_t *
ni_dbus_client_open(const char *bus_name)
{
	ni_dbus_connection_t *busconn;
	ni_dbus_client_t *dbc;

	ni_debug_dbus("%s(%s)", __FUNCTION__, bus_name);
	busconn = ni_dbus_connection_open(NULL);
	if (busconn == NULL)
		return NULL;

	dbc = calloc(1, sizeof(*dbc));
	ni_string_dup(&dbc->bus_name, bus_name);
	dbc->connection = busconn;
	dbc->call_timeout = 10000;
	return dbc;
}

/*
 * Destructor for DBus client handle
 */
void
ni_dbus_client_free(ni_dbus_client_t *dbc)
{
	NI_TRACE_ENTER();

	ni_dbus_connection_free(dbc->connection);
	dbc->connection = NULL;
	free(dbc);
}

/*
 * Constructor/Destructor for client-side objects
 */
void
__ni_dbus_client_object_init(ni_dbus_object_t *object, ni_dbus_client_t *client, const char *interface)
{
	ni_dbus_client_object_t *cob;

	cob = calloc(1, sizeof(*cob));
	cob->client = client;
	ni_string_dup(&cob->default_interface, interface);
	object->client_object = cob;
}

void
__ni_dbus_client_object_inherit(ni_dbus_object_t *child, const ni_dbus_object_t *parent)
{
	ni_dbus_client_object_t *cob;

	if ((cob = parent->client_object) != NULL)
		__ni_dbus_client_object_init(child, cob->client, cob->default_interface);
}

void
__ni_dbus_client_object_destroy(ni_dbus_object_t *object)
{
	ni_dbus_client_object_t *cob;

	if ((cob = object->client_object) != NULL) {
		ni_string_free(&cob->default_interface);
		cob->client = NULL;
	}
}

const ni_intmap_t *
__ni_dbus_client_object_get_error_map(const ni_dbus_object_t *object)
{
	ni_dbus_client_object_t *cob;

	if ((cob = object->client_object) != NULL && cob->client)
		return cob->client->error_map;
	return NULL;
}

ni_dbus_object_t *
ni_dbus_client_object_new(ni_dbus_client_t *client, const ni_dbus_class_t *class,
		const char *path, const char *interface, void *local_data)
{
	ni_dbus_object_t *object;

	object = ni_dbus_object_new(class, path, local_data);
	if (object)
		__ni_dbus_client_object_init(object, client, interface);
	return object;
}

/*
 * Accessor functions for client-side objects
 */
ni_dbus_client_t *
ni_dbus_object_get_client(const ni_dbus_object_t *object)
{
	ni_dbus_client_object_t *cob = object->client_object;

	return cob? cob->client : NULL;
}

void
ni_dbus_object_set_default_interface(ni_dbus_object_t *object, const char *interface_name)
{
	ni_dbus_client_object_t *cob = object->client_object;

	if (cob)
		ni_string_dup(&cob->default_interface, interface_name);
}

const char *
ni_dbus_object_get_default_interface(const ni_dbus_object_t *object)
{
	ni_dbus_client_object_t *cob = object->client_object;

	return cob? cob->default_interface : NULL;
}

/*
 * DBus knows two types of errors - general protocol level errors,
 * and application specific codes. We help translate the latter by
 * allowing the caller to set an error map.
 */
extern void
ni_dbus_client_set_error_map(ni_dbus_client_t *dbc, const ni_intmap_t *error_map)
{
	dbc->error_map = error_map;
}

int
ni_dbus_client_translate_error(ni_dbus_client_t *dbc, const DBusError *err)
{
	return ni_dbus_translate_error(err, dbc->error_map);
}

/*
 * Set the timeout, specifying how long we wait for the dbus response before
 * timing out
 */
void
ni_dbus_client_set_call_timeout(ni_dbus_client_t *dbc, unsigned int msec)
{
	dbc->call_timeout = msec;
}

/*
 * Place a synchronous call
 */
ni_dbus_message_t *
ni_dbus_client_call(ni_dbus_client_t *client, ni_dbus_message_t *call, DBusError *error)
{
	return ni_dbus_connection_call(client->connection, call, client->call_timeout, error);
}

/*
 * Signal handling
 */
void
ni_dbus_client_add_signal_handler(ni_dbus_client_t *client,
					const char *sender,
					const char *object_path,
					const char *object_interface,
					ni_dbus_signal_handler_t *callback,
					void *user_data)
{
	ni_dbus_add_signal_handler(client->connection,
					sender, object_path, object_interface,
					callback, user_data);
}

/*
 * Proxy objects, and calling through proxies
 */
ni_dbus_message_t *
ni_dbus_object_call_new(const ni_dbus_object_t *dbo, const char *method, ...)
{
	ni_dbus_message_t *msg;
	va_list ap;

	va_start(ap, method);
	msg = ni_dbus_object_call_new_va(dbo, method, &ap);
	va_end(ap);

	return msg;
}

static int
ni_dbus_message_serialize_va(DBusMessage *msg, va_list ap)
{
	int type;

	if ((type = va_arg(ap, int)) != 0
	 && !dbus_message_append_args_valist(msg, type, ap))
		return -EINVAL;
	return 0;
}

ni_dbus_message_t *
ni_dbus_object_call_new_va(const ni_dbus_object_t *dbo, const char *method, va_list *app)
{
	ni_dbus_client_t *client = ni_dbus_object_get_client(dbo);
	const char *interface_name;
	ni_dbus_message_t *msg;

	if (!client)
		return NULL;

	if (!(interface_name = ni_dbus_object_get_default_interface(dbo))) {
		ni_error("ni_dbus_object_call_new: no default interface for object %s", dbo->path);
		return NULL;
	}

	ni_debug_dbus("%s(obj=%s, intf=%s, method=%s)", __FUNCTION__, dbo->path, interface_name, method);
	msg = dbus_message_new_method_call(client->bus_name, dbo->path, interface_name, method);

	/* Serialize arguments */
	if (msg && app) {
		if (ni_dbus_message_serialize_va(msg, *app) < 0) {
			ni_error("ni_dbus_object_call_new: failed to serialize args");
			dbus_message_unref(msg);
			return NULL;
		}
	}
	return msg;
}

int
ni_dbus_object_call_simple(const ni_dbus_object_t *proxy,
				const char *interface_name, const char *method,
				int arg_type, void *arg_ptr,
				int res_type, void *res_ptr)
{
	ni_dbus_client_t *client = ni_dbus_object_get_client(proxy);
	ni_dbus_message_t *msg = NULL, *reply = NULL;
	DBusError error;
	int rv = 0;

	ni_debug_dbus("%s(method=%s, arg=%c/%p, res=%c/%p)", __FUNCTION__, method,
			arg_type, arg_ptr, res_type, res_ptr);
	dbus_error_init(&error);

	if (!client)
		return -EIO;

	if (!interface_name)
		interface_name = ni_dbus_object_get_default_interface(proxy);
	if (interface_name == NULL) {
		ni_error("ni_dbus_object_call_new: no default interface for object %s", proxy->path);
		return -EIO;
	}

	msg = dbus_message_new_method_call(client->bus_name, proxy->path, interface_name, method);
	if (msg == NULL) {
		ni_error("%s: unable to build %s() message", __FUNCTION__, method);
		return -EIO;
	}

	if (arg_type && !dbus_message_append_args(msg, arg_type, arg_ptr, 0)) {
		ni_error("%s: unable to serialize %s(%c, %p) arguments",
				__FUNCTION__, method, arg_type, arg_ptr);
		rv = -EINVAL;
		goto out;
	}

	if ((reply = ni_dbus_client_call(client, msg, &error)) == NULL) {
		rv = -EIO;
		goto out;
	}

	if (res_type && !dbus_message_get_args(reply, &error, res_type, res_ptr, 0)) {
		ni_error("%s: unable to deserialize %s() response", __FUNCTION__, method);
		rv = -ni_dbus_client_translate_error(client, &error);
		goto out;
	}
	if (res_type == DBUS_TYPE_STRING
	 || res_type == DBUS_TYPE_OBJECT_PATH) {
		char **res_string = (char **) res_ptr;

		if (*res_string)
			*res_string = xstrdup(*res_string);
	}

out:
	if (msg)
		dbus_message_unref(msg);
	if (reply)
		dbus_message_unref(reply);
	dbus_error_free(&error);
	return rv;
}

dbus_bool_t
ni_dbus_object_call_variant(const ni_dbus_object_t *proxy,
					const char *interface_name, const char *method,
					unsigned int nargs, const ni_dbus_variant_t *args,
					unsigned int maxres, ni_dbus_variant_t *res,
					DBusError *error)
{
	ni_dbus_message_t *call = NULL, *reply = NULL;
	ni_dbus_client_t *client;
	dbus_bool_t rv = FALSE;
	int nres;

	if (!interface_name)
		interface_name = ni_dbus_object_get_default_interface(proxy);

	if (!proxy || !(client = ni_dbus_object_get_client(proxy)) || !interface_name) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: bad proxy object", __FUNCTION__);
		return FALSE;
	}

	NI_TRACE_ENTER_ARGS("%s, if=%s, method=%s", proxy->path, interface_name, method);
	call = dbus_message_new_method_call(client->bus_name, proxy->path, interface_name, method);
	if (call == NULL) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "%s: unable to build %s() message", __FUNCTION__, method);
		goto out;
	}

	if (nargs && !ni_dbus_message_serialize_variants(call, nargs, args, error))
		goto out;

	if ((reply = ni_dbus_client_call(client, call, error)) == NULL)
		goto out;

	nres = ni_dbus_message_get_args_variants(reply, res, maxres);
	if (nres < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "%s: unable to parse %s() response", __func__, method);
		goto out;
	}

	/* FIXME: should we return nres? */

	rv = TRUE;

out:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	return rv;
}

/*
 * Asynchronous dbus calls
 */
int
ni_dbus_object_call_async(ni_dbus_object_t *proxy,
			ni_dbus_async_callback_t *callback, const char *method, ...)
{
	ni_dbus_client_t *client = ni_dbus_object_get_client(proxy);
	ni_dbus_message_t *call = NULL;
	va_list ap;
	int rv = 0;

	ni_debug_dbus("%s(method=%s)", __FUNCTION__, method);
	va_start(ap, method);
	call = ni_dbus_object_call_new_va(proxy, method, &ap);
	va_end(ap);

	if (call == NULL) {
		ni_error("%s: unable to build %s message", __FUNCTION__, method);
		rv = -EINVAL;
	} else {
		rv = ni_dbus_connection_call_async(client->connection,
			call, client->call_timeout,
			callback, proxy);
		dbus_message_unref(call);
	}

	return rv;
}

/*
 * Use ObjectManager.GetManagedObjects to retrieve (part of)
 * the server's object hierarchy
 */
dbus_bool_t
ni_dbus_object_get_managed_objects(ni_dbus_object_t *proxy, DBusError *error)
{
	ni_dbus_client_t *client;
	ni_dbus_object_t *objmgr;
	ni_dbus_message_t *call = NULL, *reply = NULL;
	DBusMessageIter iter, iter_dict;
	dbus_bool_t rv = FALSE;

	if (!(client = ni_dbus_object_get_client(proxy))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "%s: not a client object", __FUNCTION__);
		return FALSE;
	}

	objmgr = ni_dbus_client_object_new(client, &ni_dbus_anonymous_class, proxy->path,
			NI_DBUS_INTERFACE ".ObjectManager",
			NULL);

	call = ni_dbus_object_call_new(objmgr, "GetManagedObjects", 0);
	if ((reply = ni_dbus_client_call(client, call, error)) == NULL)
		goto out;

	dbus_message_iter_init(reply, &iter);
	if (!ni_dbus_dict_open_read(&iter, &iter_dict))
		goto bad_reply;
	while (dbus_message_iter_get_arg_type(&iter_dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter iter_dict_entry;
		ni_dbus_object_t *descendant;
		const char *object_path;
		unsigned int len;

		dbus_message_iter_recurse(&iter_dict, &iter_dict_entry);
		dbus_message_iter_next(&iter_dict);

		if (dbus_message_iter_get_arg_type(&iter_dict_entry) != DBUS_TYPE_STRING)
			goto bad_reply;
		dbus_message_iter_get_basic(&iter_dict_entry, &object_path);

		if (!dbus_message_iter_next(&iter_dict_entry))
			goto bad_reply;

		ni_debug_dbus("remote object %s", object_path);

		len = strlen(proxy->path);
		if (strncmp(object_path, proxy->path, len)
		 || (object_path[len] && object_path[len] != '/')) {
			ni_debug_dbus("ignoring remote object %s (not a descendant of %s)",
					object_path, proxy->path);
			continue;
		}
		if (object_path[len])
			descendant = ni_dbus_object_create(proxy, object_path + len + 1, NULL, NULL);
		else
			descendant = proxy;

		if (!__ni_dbus_object_get_managed_object_interfaces(descendant, &iter_dict_entry))
			goto bad_reply;
	}

	rv = TRUE;

out:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	ni_dbus_object_free(objmgr);
	return rv;

bad_reply:
	dbus_set_error(error, DBUS_ERROR_FAILED, "%s: failed to parse reply", __FUNCTION__);
	goto out;
}

static dbus_bool_t
__ni_dbus_object_get_managed_object_interfaces(ni_dbus_object_t *proxy, DBusMessageIter *iter)
{
	DBusMessageIter iter_variant, iter_dict;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_VARIANT)
		return FALSE;
	dbus_message_iter_recurse(iter, &iter_variant);

	if (!ni_dbus_dict_open_read(&iter_variant, &iter_dict))
		return FALSE;

	while (dbus_message_iter_get_arg_type(&iter_dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter iter_dict_entry;
		const char *interface_name;
		const ni_dbus_service_t *service;

		dbus_message_iter_recurse(&iter_dict, &iter_dict_entry);
		dbus_message_iter_next(&iter_dict);

		if (dbus_message_iter_get_arg_type(&iter_dict_entry) != DBUS_TYPE_STRING)
			return FALSE;
		dbus_message_iter_get_basic(&iter_dict_entry, &interface_name);

		if (!dbus_message_iter_next(&iter_dict_entry))
			return FALSE;

		/* Handle built-in interfaces like org.freedesktop.DBus.ObjectManager */
		service = ni_dbus_get_standard_service(interface_name);
		if (service == NULL)
			service = ni_objectmodel_service_by_name(interface_name);
		if (service == NULL) {
			ni_debug_dbus("%s: dbus service %s not known", proxy->path, interface_name);
			continue;
		}

		/* We may need to frob the object class here. When we receive a vlan interface,
		 * the default object class would be netif. However, we would also find properties
		 * for the VLAN interface, which specifies a class of "netif-vlan". We need to
		 * the class in this case. */
		if (service->compatible && !ni_dbus_object_isa(proxy, service->compatible)) {
			const ni_dbus_class_t *check;

			for (check = service->compatible; check; check = check->superclass) {
				if (proxy->class == check)
					break;
			}
			if (check == NULL) {
				ni_error("GetManagedObjects(%s): ignoring interface %s (class %s) "
						"which is not compatible with object class %s",
						proxy->path, service->name, service->compatible->name,
						proxy->class->name);
				continue;
			}
			proxy->class = service->compatible;
			ni_debug_dbus("%s: specializing object as a %s", proxy->path, proxy->class->name);
		}

		ni_dbus_object_register_service(proxy, service);

		/* The value of this dict entry is the property dict */
		if (!__ni_dbus_object_get_managed_object_properties(proxy, service, &iter_dict_entry))
			return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
__ni_dbus_object_get_managed_object_properties(ni_dbus_object_t *proxy,
				const ni_dbus_service_t *service,
				DBusMessageIter *iter)
{
	DBusMessageIter iter_variant, iter_dict;
	DBusError error = DBUS_ERROR_INIT;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_VARIANT)
		return FALSE;
	dbus_message_iter_recurse(iter, &iter_variant);

	if (!ni_dbus_dict_open_read(&iter_variant, &iter_dict))
		return FALSE;

	while (dbus_message_iter_get_arg_type(&iter_dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter iter_dict_entry;
		ni_dbus_variant_t value = NI_DBUS_VARIANT_INIT;
		const char *property_name;
		const ni_dbus_property_t *property;

		dbus_message_iter_recurse(&iter_dict, &iter_dict_entry);
		dbus_message_iter_next(&iter_dict);

		if (dbus_message_iter_get_arg_type(&iter_dict_entry) != DBUS_TYPE_STRING)
			return FALSE;
		dbus_message_iter_get_basic(&iter_dict_entry, &property_name);

		if (!dbus_message_iter_next(&iter_dict_entry))
			return FALSE;

		if (!ni_dbus_message_iter_get_variant(&iter_dict_entry, &value)) {
			ni_debug_dbus("Couldn't deserialize property %s.%s",
					service->name, property_name);
			continue;
		}

		/* now set the object property */
		if (!(property = ni_dbus_service_get_property(service, property_name))) {
			ni_debug_dbus("Ignoring unknown %s property %s=%s",
					service->name,
					property_name, ni_dbus_variant_sprint(&value));
			continue;
		}

		if (!property->set) {
			ni_debug_dbus("Ignoring read-only property %s=%s",
					property_name, ni_dbus_variant_sprint(&value));
			continue;
		}

		if (!property->set(proxy, property, &value, &error)) {
			ni_debug_dbus("Error setting property %s=%s (%s: %s)",
					property_name, ni_dbus_variant_sprint(&value),
					error.name, error.message);
			continue;
		}

		ni_debug_dbus("Setting property %s=%s", property_name, ni_dbus_variant_sprint(&value));
		ni_dbus_variant_destroy(&value);
	}

	dbus_error_free(&error);
	return TRUE;
}

dbus_bool_t
ni_dbus_object_refresh_children(ni_dbus_object_t *proxy)
{
	DBusError error = DBUS_ERROR_INIT;
	dbus_bool_t rv;

	rv = ni_dbus_object_get_managed_objects(proxy, &error);
	dbus_error_free(&error);
	return rv;
}

