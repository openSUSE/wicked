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

#define TRACE_ENTER()		ni_debug_dbus("%s()", __FUNCTION__)
#define TP()			ni_debug_dbus("TP - %s:%u", __FUNCTION__, __LINE__)

struct ni_dbus_client {
	ni_dbus_connection_t *	connection;
	char *			bus_name;
	unsigned int		call_timeout;
	const ni_intmap_t *	error_map;
};

static dbus_bool_t	__ni_dbus_proxy_get_managed_object_interfaces(ni_dbus_proxy_t *, DBusMessageIter *);
static dbus_bool_t	__ni_dbus_proxy_get_managed_object_properties(ni_dbus_proxy_t *proxy,
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
	dbc->call_timeout = 1000;
	return dbc;
}

/*
 * Destructor for DBus client handle
 */
void
ni_dbus_client_free(ni_dbus_client_t *dbc)
{
	TRACE_ENTER();

	ni_dbus_connection_free(dbc->connection);
	dbc->connection = NULL;
	free(dbc);
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
ni_dbus_proxy_call_new(const ni_dbus_proxy_t *dbo, const char *method, ...)
{
	ni_dbus_message_t *msg;
	va_list ap;

	va_start(ap, method);
	msg = ni_dbus_proxy_call_new_va(dbo, method, &ap);
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
ni_dbus_proxy_call_new_va(const ni_dbus_proxy_t *dbo, const char *method, va_list *app)
{
	ni_dbus_message_t *msg;

	ni_debug_dbus("%s(obj=%s, intf=%s, method=%s)", __FUNCTION__, dbo->path, dbo->interface, method);
	msg = dbus_message_new_method_call(dbo->client->bus_name, dbo->path, dbo->interface, method);

	/* Serialize arguments */
	if (msg && app) {
		if (ni_dbus_message_serialize_va(msg, *app) < 0) {
			ni_error("ni_dbus_proxy_call_new: failed to serialize args");
			dbus_message_unref(msg);
			return NULL;
		}
	}
	return msg;
}

int
ni_dbus_proxy_call_simple(const ni_dbus_proxy_t *proxy, const char *method,
				int arg_type, void *arg_ptr,
				int res_type, void *res_ptr)
{
	ni_dbus_message_t *msg = NULL, *reply = NULL;
	DBusError error;
	int rv = 0;

	ni_debug_dbus("%s(method=%s, arg=%c/%p, res=%c/%p)", __FUNCTION__, method,
			arg_type, arg_ptr, res_type, res_ptr);
	dbus_error_init(&error);

	msg = dbus_message_new_method_call(proxy->client->bus_name, proxy->path, proxy->interface, method);
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

	if ((reply = ni_dbus_client_call(proxy->client, msg, &error)) == NULL) {
		rv = -EIO;
		goto out;
	}

	if (res_type && !dbus_message_get_args(reply, &error, res_type, res_ptr, 0)) {
		ni_error("%s: unable to deserialize %s() response", __FUNCTION__, method);
		rv = -ni_dbus_client_translate_error(proxy->client, &error);
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
dbus_message_serialize_variants(ni_dbus_message_t *msg,
			unsigned int nargs, const ni_dbus_variant_t *argv,
			DBusError *error)
{
	DBusMessageIter iter;
	unsigned int i;

	dbus_message_iter_init_append(msg, &iter);
	for (i = 0; i < nargs; ++i) {
		ni_debug_dbus("  [%u]: type=%s, value=\"%s\"", i,
				ni_dbus_variant_signature(&argv[i]),
				ni_dbus_variant_sprint(&argv[i]));
		if (!ni_dbus_message_iter_append_value(&iter, &argv[i], NULL)) {
			dbus_set_error(error,
					DBUS_ERROR_FAILED,
					"Error marshalling message arguments");
			return FALSE;
		}
	}
	return TRUE;
}

dbus_bool_t
ni_dbus_proxy_call_variant(const ni_dbus_proxy_t *proxy, const char *method,
					unsigned int nargs, const ni_dbus_variant_t *args,
					unsigned int maxres, const ni_dbus_variant_t *res,
					DBusError *error)
{
	ni_dbus_message_t *call = NULL, *reply = NULL;
	ni_dbus_client_t *client;
	dbus_bool_t rv = FALSE;

	if (!proxy || !(client = proxy->client)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: bad proxy object", __FUNCTION__);
		return FALSE;
	}

	call = dbus_message_new_method_call(client->bus_name, proxy->path, proxy->interface, method);
	if (call == NULL) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "%s: unable to build %s() message", __FUNCTION__, method);
		goto out;
	}

	if (nargs && !dbus_message_serialize_variants(call, nargs, args, error))
		goto out;

	if ((reply = ni_dbus_client_call(proxy->client, call, error)) == NULL)
		goto out;

#if 0
	if (res_type && !dbus_message_get_args(reply, &error, res_type, res_ptr, 0)) {
		ni_error("%s: unable to deserialize %s() response", __FUNCTION__, method);
		rv = -ni_dbus_client_translate_error(proxy->client, &error);
		goto out;
	}
	if (res_type == DBUS_TYPE_STRING
	 || res_type == DBUS_TYPE_OBJECT_PATH) {
		char **res_string = (char **) res_ptr;

		if (*res_string)
			*res_string = xstrdup(*res_string);
	}
#endif
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
ni_dbus_proxy_call_async(ni_dbus_proxy_t *proxy,
			ni_dbus_async_callback_t *callback, const char *method, ...)
{
	ni_dbus_client_t *client = proxy->client;
	ni_dbus_message_t *call = NULL;
	va_list ap;
	int rv = 0;

	ni_debug_dbus("%s(method=%s)", __FUNCTION__, method);
	va_start(ap, method);
	call = ni_dbus_proxy_call_new_va(proxy, method, &ap);
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

ni_dbus_proxy_t *
ni_dbus_proxy_new(ni_dbus_client_t *client, const char *path, const char *interface,
		const ni_dbus_proxy_functions_t *functions, void *local_data)
{
	ni_dbus_proxy_t *dbo;

	dbo = calloc(1, sizeof(*dbo));
	dbo->client = client;
	dbo->local_data = local_data;
	dbo->functions = functions;
	ni_string_dup(&dbo->path, path);
	ni_string_dup(&dbo->interface, interface);
	return dbo;
}

ni_dbus_proxy_t *
ni_dbus_proxy_new_child(ni_dbus_proxy_t *parent, const char *name, const char *interface,
		const ni_dbus_proxy_functions_t *functions, void *local_data)
{
	ni_dbus_proxy_t *dbo;
	unsigned int plen;

	dbo = calloc(1, sizeof(*dbo));
	dbo->client = parent->client;
	dbo->local_data = local_data;
	dbo->functions = functions;
	ni_string_dup(&dbo->interface, interface);

	plen = strlen(parent->path) + strlen(name) + 2;
	dbo->path = malloc(plen);
	snprintf(dbo->path, plen, "%s/%s", parent->path, name);

	return dbo;
}

/*
 * proxy object lookup functions
 */
ni_dbus_proxy_t *
ni_dbus_proxy_lookup(ni_dbus_proxy_t *proxy, const char *path)
{
	char *path_copy, *pos;

	if (!path)
		return proxy;

	path_copy = xstrdup(path);
	for (pos = path_copy; pos; ) {
		ni_dbus_proxy_t *child;
		char *sp;

		if ((sp = strchr(pos, '/')) != NULL)
			*sp = '\0';

		for (child = proxy->children; child; child = child->next) {
			if (!strcmp(child->path, path_copy))
				break;
		}
		if (child == NULL) {
			if (!proxy->functions || !proxy->functions->create_child)
				return NULL;
			child = proxy->functions->create_child(proxy, pos);
		}
		proxy = child;

		if (sp) {
			*sp++ = '/';
			while (*sp == '/')
				++sp;
		}
		pos = sp;
	}

	free(path_copy);
	return proxy;
}

void
ni_dbus_proxy_free(ni_dbus_proxy_t *dbo)
{
	ni_dbus_proxy_t *child;

	ni_string_free(&dbo->path);
	ni_string_free(&dbo->interface);
	/* Free list of interfaces */

	/* Free list of children */
	while ((child = dbo->children) != NULL) {
		dbo->children = child->next;
		ni_dbus_proxy_free(child);
	}
	free(dbo);
}

/*
 * Use ObjectManager.GetManagedObjects to retrieve (part of)
 * the server's object hierarchy
 */
dbus_bool_t
ni_dbus_proxy_get_managed_objects(ni_dbus_proxy_t *proxy, DBusError *error)
{
	ni_dbus_proxy_t *objmgr;
	ni_dbus_message_t *call = NULL, *reply = NULL;
	DBusMessageIter iter, iter_dict;
	dbus_bool_t rv = FALSE;

	ni_debug_dbus("proxy functions = %p, create_child=%p", 
		proxy->functions,
		proxy->functions? proxy->functions->create_child : 0);

	objmgr = ni_dbus_proxy_new(proxy->client,
			proxy->path,
			NI_DBUS_INTERFACE ".ObjectManager",
			NULL, NULL);

	call = ni_dbus_proxy_call_new(objmgr, "GetManagedObjects", 0);
	if ((reply = ni_dbus_client_call(proxy->client, call, error)) == NULL)
		goto out;

	dbus_message_iter_init(reply, &iter);
	if (!ni_dbus_dict_open_read(&iter, &iter_dict))
		goto bad_reply;
	while (dbus_message_iter_get_arg_type(&iter_dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter iter_dict_entry;
		ni_dbus_proxy_t *descendant;
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
			descendant = ni_dbus_proxy_lookup(proxy, object_path + len + 1);
		else
			descendant = proxy;

		if (!__ni_dbus_proxy_get_managed_object_interfaces(descendant, &iter_dict_entry))
			goto bad_reply;
	}

	rv = TRUE;

out:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	ni_dbus_proxy_free(objmgr);
	return rv;

bad_reply:
	dbus_set_error(error, DBUS_ERROR_FAILED, "%s: failed to parse reply", __FUNCTION__);
	goto out;
}

static dbus_bool_t
__ni_dbus_proxy_get_managed_object_interfaces(ni_dbus_proxy_t *proxy, DBusMessageIter *iter)
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

		ni_debug_dbus("object interface %s", interface_name);
		service = ni_objectmodel_service_by_name(interface_name);
		if (!service)
			continue;

		/* The value of this dict entry is the property dict */
		if (!__ni_dbus_proxy_get_managed_object_properties(proxy, service, &iter_dict_entry))
			return FALSE;
	}

	return TRUE;
}

static dbus_bool_t
__ni_dbus_proxy_get_managed_object_properties(ni_dbus_proxy_t *proxy,
				const ni_dbus_service_t *service,
				DBusMessageIter *iter)
{
	DBusMessageIter iter_variant, iter_dict;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_VARIANT)
		return FALSE;
	dbus_message_iter_recurse(iter, &iter_variant);

	if (!ni_dbus_dict_open_read(&iter_variant, &iter_dict))
		return FALSE;

	while (dbus_message_iter_get_arg_type(&iter_dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter iter_dict_entry;
		ni_dbus_variant_t value = NI_DBUS_VARIANT_INIT;
		const char *property_name;

		dbus_message_iter_recurse(&iter_dict, &iter_dict_entry);
		dbus_message_iter_next(&iter_dict);

		if (dbus_message_iter_get_arg_type(&iter_dict_entry) != DBUS_TYPE_STRING)
			return FALSE;
		dbus_message_iter_get_basic(&iter_dict_entry, &property_name);

		if (!dbus_message_iter_next(&iter_dict_entry))
			return FALSE;

		if (!ni_dbus_message_iter_get_variant(&iter_dict_entry, &value))
			continue;
		ni_debug_dbus("property %s=%s", property_name, ni_dbus_variant_sprint(&value));

		/* FIXME now set the object property */
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_proxy_refresh_children(ni_dbus_proxy_t *proxy)
{
	DBusError error = DBUS_ERROR_INIT;
	dbus_bool_t rv;

	rv = ni_dbus_proxy_get_managed_objects(proxy, &error);
	dbus_error_free(&error);
	return rv;
}

