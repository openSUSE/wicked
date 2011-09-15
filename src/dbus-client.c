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
	void *			user_data;
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
	busconn = ni_dbus_connection_open();
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

/*
 * Deserialize response
 *
 * We need this wrapper function because dbus_message_get_args_valist
 * does not copy any strings, but returns char pointers that point at
 * the message body. Which is bad if you want to access these strings
 * after you've freed the message.
 */
int
ni_dbus_message_get_args(ni_dbus_message_t *reply, ...)
{
	DBusError error;
	va_list ap;
	int rv = 0, type;

	TRACE_ENTER();
	dbus_error_init(&error);
	va_start(ap, reply);

	type = va_arg(ap, int);
	if (type
	 && !dbus_message_get_args_valist(reply, &error, type, ap)) {
		ni_error("%s: unable to retrieve reply data", __FUNCTION__);
		rv = -EINVAL;
		goto done;
	}

	while (type) {
		char **data = va_arg(ap, char **);

		switch (type) {
		case DBUS_TYPE_STRING:
		case DBUS_TYPE_OBJECT_PATH:
			if (data && *data)
				*data = xstrdup(*data);
			break;
		}

		type = va_arg(ap, int);
	}

done:
	va_end(ap);
	return rv;
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

extern int
ni_dbus_client_call(ni_dbus_client_t *client, ni_dbus_message_t *call, ni_dbus_message_t **reply_p)
{
	return ni_dbus_connection_call(client->connection, call, reply_p, client->call_timeout, client->error_map);
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

void
ni_dbus_proxy_free(ni_dbus_proxy_t *dbo)
{
	ni_string_free(&dbo->bus_name);
	ni_string_free(&dbo->path);
	ni_string_free(&dbo->interface);
	free(dbo);
}

/*
 * Helper function for processing a DBusDict
 */
static inline const struct ni_dbus_dict_entry_handler *
__ni_dbus_get_property_handler(const struct ni_dbus_dict_entry_handler *handlers, const char *name)
{
	const struct ni_dbus_dict_entry_handler *h;

	for (h = handlers; h->type; ++h) {
		if (!strcmp(h->name, name))
			return h;
	}
	return NULL;
}

int
ni_dbus_process_properties(DBusMessageIter *iter, const struct ni_dbus_dict_entry_handler *handlers, void *user_object)
{
	struct ni_dbus_dict_entry entry;
	int rv = 0;

	TRACE_ENTER();
	while (ni_dbus_dict_get_entry(iter, &entry)) {
		const struct ni_dbus_dict_entry_handler *h;

#if 0
		if (entry.type == DBUS_TYPE_ARRAY) {
			ni_debug_dbus("++%s -- array of type %c", entry.key, entry.array_type);
		} else {
			ni_debug_dbus("++%s -- type %c", entry.key, entry.type);
		}
#endif

		if (!(h = __ni_dbus_get_property_handler(handlers, entry.key))) {
			ni_debug_dbus("%s: ignore unknown dict element \"%s\"", __FUNCTION__, entry.key);
			continue;
		}

		if (h->type != entry.type
		 || (h->type == DBUS_TYPE_ARRAY && h->array_type != entry.array_type)) {
			ni_error("%s: unexpected type for dict element \"%s\"", __FUNCTION__, entry.key);
			rv = -EINVAL;
			break;
		}

		if (h->type == DBUS_TYPE_ARRAY && h->array_len_max != 0
		 && (entry.array_len < h->array_len_min || h->array_len_max < entry.array_len)) {
			ni_error("%s: unexpected array length %u for dict element \"%s\"",
					__FUNCTION__, (int) entry.array_len, entry.key);
			rv = -EINVAL;
			break;
		}

		if (h->set)
			h->set(&entry, user_object);
	}

	return rv;
}
