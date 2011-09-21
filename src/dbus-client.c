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
	unsigned int		call_timeout;
	const ni_intmap_t *	error_map;
};

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
int
ni_dbus_client_call(ni_dbus_client_t *client, ni_dbus_message_t *call, ni_dbus_message_t **reply_p)
{
	return ni_dbus_connection_call(client->connection, call, reply_p, client->call_timeout, client->error_map);
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
	msg = dbus_message_new_method_call(dbo->bus_name, dbo->path, dbo->interface, method);

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
	int rv;

	ni_debug_dbus("%s(method=%s, arg=%c/%p, res=%c/%p)", __FUNCTION__, method,
			arg_type, arg_ptr, res_type, res_ptr);
	dbus_error_init(&error);

	msg = dbus_message_new_method_call(proxy->bus_name, proxy->path, proxy->interface, method);
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

	if ((rv = ni_dbus_client_call(proxy->client, msg, &reply)) < 0)
		goto out;

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

	call = dbus_message_new_method_call(proxy->bus_name, proxy->path, proxy->interface, method);
	if (call == NULL) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "%s: unable to build %s() message", __FUNCTION__, method);
		goto out;
	}

	if (nargs && !dbus_message_serialize_variants(call, nargs, args, error))
		goto out;

	if ((rv = ni_dbus_client_call(proxy->client, call, &reply)) < 0)
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
ni_dbus_proxy_new(ni_dbus_client_t *client, const char *bus_name, const char *path, const char *interface, void *local_data)
{
	ni_dbus_proxy_t *dbo;

	dbo = calloc(1, sizeof(*dbo));
	dbo->client = client;
	dbo->local_data = local_data;
	ni_string_dup(&dbo->bus_name, bus_name);
	ni_string_dup(&dbo->path, path);
	ni_string_dup(&dbo->interface, interface);
	return dbo;
}

ni_dbus_proxy_t *
ni_dbus_proxy_new_child(ni_dbus_proxy_t *parent, const char *name, const char *interface, void *local_data)
{
	ni_dbus_proxy_t *dbo;
	unsigned int plen;

	dbo = calloc(1, sizeof(*dbo));
	dbo->client = parent->client;
	dbo->local_data = local_data;
	ni_string_dup(&dbo->bus_name, parent->bus_name);
	ni_string_dup(&dbo->interface, interface);

	plen = strlen(parent->path) + strlen(name) + 2;
	dbo->path = malloc(plen);
	snprintf(dbo->path, plen, "%s/%s", parent->path, name);

	return dbo;
}

void
ni_dbus_proxy_free(ni_dbus_proxy_t *dbo)
{
	ni_string_free(&dbo->bus_name);
	ni_string_free(&dbo->path);
	ni_string_free(&dbo->interface);
	free(dbo);
}
