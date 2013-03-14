/*
 * Simple DBus client functions
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "socket_priv.h"
#include "dbus-common.h"
#include "dbus-connection.h"
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
static dbus_bool_t	__ni_dbus_object_refresh_properties(ni_dbus_object_t *proxy,
					const ni_dbus_service_t *service,
					DBusMessageIter *iter);
static void		__ni_dbus_object_mark_stale(ni_dbus_object_t *);
static void		__ni_dbus_object_purge_stale(ni_dbus_object_t *);
static const char *	__ni_dbus_print_argument(char, const void *);

/*
 * Constructor for DBus client handle
 */
ni_dbus_client_t *
ni_dbus_client_open(const char *bus_type, const char *bus_name)
{
	ni_dbus_connection_t *busconn;
	ni_dbus_client_t *dbc;

	NI_TRACE_ENTER_ARGS("bus_type=%s, bus_name=%s", bus_type, bus_name);
	busconn = ni_dbus_connection_open(bus_type, NULL);
	if (busconn == NULL)
		return NULL;

	dbc = xcalloc(1, sizeof(*dbc));
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
	ni_string_free(&dbc->bus_name);
	free(dbc);
}

/*
 * Constructor/Destructor for client-side objects
 */
void
__ni_dbus_client_object_init(ni_dbus_object_t *object, ni_dbus_client_t *client, const char *interface)
{
	ni_dbus_client_object_t *cob;

	cob = xcalloc(1, sizeof(*cob));
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
		return -NI_ERROR_INVALID_ARGS;
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

#if 0
	ni_debug_dbus("%s(obj=%s, intf=%s, method=%s)", __FUNCTION__, dbo->path, interface_name, method);
#endif
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

	dbus_error_init(&error);

	if (!client)
		return -NI_ERROR_INVALID_ARGS;

	if (!interface_name)
		interface_name = ni_dbus_object_get_default_interface(proxy);
	if (interface_name == NULL) {
		ni_error("ni_dbus_object_call_new: no default interface for object %s", proxy->path);
		return -NI_ERROR_INVALID_ARGS;
	}

	msg = dbus_message_new_method_call(client->bus_name, proxy->path, interface_name, method);
	if (msg == NULL) {
		ni_error("%s: unable to build %s() message", __FUNCTION__, method);
		return -NI_ERROR_DBUS_CALL_FAILED;
	}

	if (arg_type && !dbus_message_append_args(msg, arg_type, arg_ptr, 0)) {
		ni_error("%s: unable to serialize %s(%c, %p) arguments",
				__FUNCTION__, method, arg_type, arg_ptr);
		rv = -NI_ERROR_INVALID_ARGS;
		goto out;
	}

	if ((reply = ni_dbus_client_call(client, msg, &error)) == NULL) {
		rv = -NI_ERROR_DBUS_CALL_FAILED;
		if (dbus_error_is_set(&error))
			rv = ni_dbus_client_translate_error(client, &error);
		goto out;
	}

	if (res_type && !dbus_message_get_args(reply, &error, res_type, res_ptr, 0)) {
		ni_error("%s: unable to deserialize %s() response", __FUNCTION__, method);
		rv = ni_dbus_client_translate_error(client, &error);
		goto out;
	}
	if (res_type == DBUS_TYPE_STRING
	 || res_type == DBUS_TYPE_OBJECT_PATH) {
		char **res_string = (char **) res_ptr;

		if (*res_string)
			*res_string = xstrdup(*res_string);
	}

	ni_debug_dbus("%s: %s.%s(%s) = %s", __func__, proxy->path, method,
			__ni_dbus_print_argument(arg_type, arg_ptr),
			__ni_dbus_print_argument(res_type, res_ptr));

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

	if (!interface_name) {
		const ni_dbus_service_t **pos, *service, *best = NULL;

		pos = proxy->interfaces;
		while (pos && (service = *pos++) != NULL) {
			if (ni_dbus_service_get_method(service, method) == NULL)
				continue;

			if (best == NULL) {
				best = service;
			} else
			if (best->compatible && service->compatible) {
				if (ni_dbus_class_is_subclass(best->compatible, service->compatible)) {
					/* best is more specific than service */
				} else
				if (ni_dbus_class_is_subclass(service->compatible, best->compatible)) {
					/* service is more specific than best */
					best = service;
				} else {
					dbus_set_error(error, DBUS_ERROR_UNKNOWN_METHOD,
							"%s: several dbus interfaces provide method %s",
							proxy->path, method);
					return FALSE;
				}
			}
		}

		if (best != NULL)
			interface_name = best->name;
	}

	if (interface_name == NULL)
		interface_name = ni_dbus_object_get_default_interface(proxy);

	if (interface_name == NULL) {
		dbus_set_error(error, DBUS_ERROR_UNKNOWN_METHOD,
				"%s: no registered dbus interface provides method %s",
				proxy->path, method);
		return FALSE;
	}

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

	ni_debug_dbus("%s(%s, %s)", __FUNCTION__, method, proxy->path);
	va_start(ap, method);
	call = ni_dbus_object_call_new_va(proxy, method, &ap);
	va_end(ap);

	if (call == NULL) {
		ni_error("%s: unable to build %s message", __FUNCTION__, method);
		rv = -NI_ERROR_INVALID_ARGS;
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
ni_dbus_object_get_managed_objects(ni_dbus_object_t *proxy, DBusError *error, ni_bool_t purge)
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

	if (purge)
		__ni_dbus_object_mark_stale(proxy);

	objmgr = ni_dbus_client_object_new(client, &ni_dbus_anonymous_class, proxy->path,
			NI_DBUS_INTERFACE ".ObjectManager",
			NULL);

	call = ni_dbus_object_call_new(objmgr, "GetManagedObjects", 0);
	if ((reply = ni_dbus_client_call(client, call, error)) == NULL)
		goto out;

	dbus_message_iter_init(reply, &iter);
	if (!ni_dbus_message_open_dict_read(&iter, &iter_dict))
		goto bad_reply;
	while (dbus_message_iter_get_arg_type(&iter_dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter iter_dict_entry;
		ni_dbus_object_t *descendant;
		const char *object_path;

		dbus_message_iter_recurse(&iter_dict, &iter_dict_entry);
		dbus_message_iter_next(&iter_dict);

		if (dbus_message_iter_get_arg_type(&iter_dict_entry) != DBUS_TYPE_STRING)
			goto bad_reply;
		dbus_message_iter_get_basic(&iter_dict_entry, &object_path);

		if (!dbus_message_iter_next(&iter_dict_entry))
			goto bad_reply;

		descendant = ni_dbus_object_create(proxy, object_path, NULL, NULL);

		/* On the client side, we may have to assign classes to newly created
		 * proxy objects on the fly.
		 * We do this in two pieces. When we instantiate an object as a child of a
		 * list object (such as Wicked/Interfaces), we automatically assign the
		 * default list item class to the new child.
		 * In a second step, we check if the new child has an initialize member
		 * function, and if it has, we use that to create a local netdev object
		 * and assign that to the proxy object.
		 */
		if (descendant->class == &ni_dbus_anonymous_class && descendant->parent) {
			ni_dbus_object_t *parent = descendant->parent;

			if (parent->class)
				descendant->class = parent->class->list.item_class;
		}
		if (descendant->class && descendant->handle == NULL && descendant->class->initialize)
			descendant->class->initialize(descendant);

		if (!__ni_dbus_object_get_managed_object_interfaces(descendant, &iter_dict_entry))
			goto bad_reply;

		descendant->stale = FALSE;
	}

	if (purge)
		__ni_dbus_object_purge_stale(proxy);

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

	if (!ni_dbus_message_open_dict_read(&iter_variant, &iter_dict))
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
		 * specialize the class in this case. */
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
	DBusMessageIter iter_variant;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_VARIANT)
		return FALSE;
	dbus_message_iter_recurse(iter, &iter_variant);

	return __ni_dbus_object_refresh_properties(proxy, service, &iter_variant);
}

static dbus_bool_t
__ni_dbus_object_refresh_properties(ni_dbus_object_t *proxy, const ni_dbus_service_t *service, DBusMessageIter *iter)
{
	DBusMessageIter iter_dict;
	DBusError error = DBUS_ERROR_INIT;

	if (!ni_dbus_message_open_dict_read(iter, &iter_dict))
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
			ni_debug_dbus("couldn't deserialize property %s.%s",
					service->name, property_name);
			continue;
		}

		/* now set the object property */
		if (!(property = ni_dbus_service_get_property(service, property_name))) {
			ni_debug_dbus("ignoring unknown %s property %s=%s",
					service->name,
					property_name, ni_dbus_variant_sprint(&value));
			continue;
		}

		if (!property->set) {
			ni_debug_dbus("ignoring read-only property %s=%s",
					property_name, ni_dbus_variant_sprint(&value));
			continue;
		}

		if (!property->set(proxy, property, &value, &error)) {
			ni_debug_dbus("error setting property %s=%s (%s: %s)",
					property_name, ni_dbus_variant_sprint(&value),
					error.name, error.message);
			dbus_error_free(&error);
			continue;
		}

#if 0
		ni_debug_dbus("Setting property %s=%s", property_name, ni_dbus_variant_sprint(&value));
#endif
		ni_dbus_variant_destroy(&value);
	}

	dbus_error_free(&error);
	return TRUE;
}

/*
 * Handle purging of stale objects
 */
void
__ni_dbus_object_mark_stale(ni_dbus_object_t *proxy)
{
	ni_dbus_object_t *child;

	for (child = proxy->children; child; child = child->next) {
		child->stale = TRUE;
		if (child->children)
			__ni_dbus_object_mark_stale(child);
	}
}

void
__ni_dbus_object_purge_stale(ni_dbus_object_t *proxy)
{
	ni_dbus_object_t *child, *next;

	for (child = proxy->children; child; child = next) {
		next = child->next;

		if (child->stale) {
			ni_debug_dbus("purging stale object %s", child->path);
			ni_dbus_object_free(child);
		} else if (child->children) {
			__ni_dbus_object_purge_stale(child);
		}
	}
}

dbus_bool_t
ni_dbus_object_refresh_children(ni_dbus_object_t *proxy)
{
	DBusError error = DBUS_ERROR_INIT;
	dbus_bool_t rv;

	rv = ni_dbus_object_get_managed_objects(proxy, &error, TRUE);
	if (!rv)
		ni_dbus_print_error(&error, "%s.getManagedObjects failed", proxy->path);
	dbus_error_free(&error);
	return rv;
}

/*
 * Use Properties.GetAll to refresh the properties of an object
 */
dbus_bool_t
ni_dbus_object_refresh_properties(ni_dbus_object_t *proxy, const ni_dbus_service_t *service, DBusError *error)
{
	ni_dbus_client_t *client;
	ni_dbus_object_t *objmgr;
	ni_dbus_message_t *call = NULL, *reply = NULL;
	DBusMessageIter iter;
	dbus_bool_t rv = FALSE;

	if (!(client = ni_dbus_object_get_client(proxy))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "%s: not a client object", __func__);
		return FALSE;
	}

	objmgr = ni_dbus_client_object_new(client, &ni_dbus_anonymous_class, proxy->path,
			NI_DBUS_INTERFACE ".Properties",
			NULL);

	call = ni_dbus_object_call_new(objmgr, "GetAll", 0);
	ni_dbus_message_append_string(call, service->name);
	if ((reply = ni_dbus_client_call(client, call, error)) == NULL)
		goto out;

	dbus_message_iter_init(reply, &iter);
	rv = __ni_dbus_object_refresh_properties(proxy, service, &iter);
	if (!rv)
		dbus_set_error(error, DBUS_ERROR_FAILED, "%s: failed to parse reply", __func__);

out:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	ni_dbus_object_free(objmgr);
	return rv;
}

/*
 * Use Properties.Set to update one properties of an object
 */
dbus_bool_t
ni_dbus_object_send_property(ni_dbus_object_t *proxy,
				const char *service_name,
				const char *property_name,
				const ni_dbus_variant_t *value,
				DBusError *error)
{
	DBusError local_error = DBUS_ERROR_INIT;
	ni_dbus_variant_t argv[3];
	dbus_bool_t rv = FALSE;

	memset(argv, 0, sizeof(argv));
	ni_dbus_variant_set_string(&argv[0], service_name);
	ni_dbus_variant_set_string(&argv[1], property_name);
	argv[2] = *value;

	if (!error)
		error = &local_error;

	rv = ni_dbus_object_call_variant(proxy, NI_DBUS_INTERFACE ".Properties", "Set", 3, argv, 0, NULL, error);

	if (!rv && error == &local_error)
		ni_dbus_print_error(&local_error, "failed to set property %s.%s=\"%s\"",
				service_name, property_name,
				ni_dbus_variant_sprint(value));

	ni_dbus_variant_destroy(&argv[0]);
	ni_dbus_variant_destroy(&argv[1]);

	return rv;
}

dbus_bool_t
ni_dbus_object_send_property_string(ni_dbus_object_t *proxy,
				const char *service_name,
				const char *property_name,
				const char *value,
				DBusError *error)
{
	ni_dbus_variant_t var = NI_DBUS_VARIANT_INIT;
	dbus_bool_t rv;

	ni_dbus_variant_set_string(&var, value);
	rv = ni_dbus_object_send_property(proxy, service_name, property_name, &var, error);
	ni_dbus_variant_destroy(&var);
	return rv;
}

/*
 * Helper function for debug purposes
 */
static const char *
__ni_dbus_print_argument(char type, const void *ptr)
{
	static char buffer[2][128];
	static int idx = 0;
	char *bp;

	bp = buffer[idx];
	idx = 1 - idx;

	switch (type) {
	case DBUS_TYPE_INVALID:
		return "<none>";

	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		return ptr? *(const char **) ptr : "<null>";

	case DBUS_TYPE_INT32:
		snprintf(bp, 128, "int32:%d", *(const int32_t *) ptr);
		return bp;

	case DBUS_TYPE_UINT32:
		snprintf(bp, 128, "uint32:%u", *(const uint32_t *) ptr);
		return bp;

	case DBUS_TYPE_BOOLEAN:
		return (*(const dbus_bool_t *) ptr)? "true" : "false";
	}

	snprintf(bp, 128, "%c/%p", type, ptr);
	return bp;
}
