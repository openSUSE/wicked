/*
 * Simple DBus connection wrappers
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
#include "dbus-connection.h"
#include "dbus-dict.h"

#define TRACE_ENTER()		ni_debug_dbus("%s()", __FUNCTION__)
#define TRACE_ENTERN(fmt, args...) \
				ni_debug_dbus("%s(" fmt ")", __FUNCTION__, ##args)
#define TP()			ni_debug_dbus("TP - %s:%u", __FUNCTION__, __LINE__)


typedef struct ni_dbus_pending ni_dbus_pending_t;
struct ni_dbus_pending {
	ni_dbus_pending_t *	next;

	DBusPendingCall *	call;
	ni_dbus_async_callback_t *callback;
	ni_dbus_proxy_t *	proxy;
};

typedef struct ni_dbus_sigaction ni_dbus_sigaction_t;
struct ni_dbus_sigaction {
	ni_dbus_sigaction_t *	next;
	char *			sender;
	char *			object_path;
	char *			object_interface;
	ni_dbus_signal_handler_t *signal_handler;
	void *			user_data;
};

struct ni_dbus_connection {
	DBusConnection *	conn;
	ni_dbus_pending_t *	pending;
	ni_dbus_sigaction_t *	sighandlers;
};

typedef struct ni_dbus_watch_data ni_dbus_watch_data_t;
struct ni_dbus_watch_data {
	ni_dbus_watch_data_t *	next;
	DBusConnection *	conn;
	DBusWatch *		watch;
	ni_socket_t *		socket;
};
static ni_dbus_watch_data_t *	ni_dbus_watches;

static void			__ni_dbus_sigaction_free(ni_dbus_sigaction_t *);
static void			__ni_dbus_pending_free(ni_dbus_pending_t *);
static void			__ni_dbus_notify_async(DBusPendingCall *, void *);
static dbus_bool_t		__ni_dbus_add_watch(DBusWatch *, void *);
static void			__ni_dbus_remove_watch(DBusWatch *, void *);
static DBusHandlerResult	__ni_dbus_signal_filter(DBusConnection *, DBusMessage *, void *);

static int			ni_dbus_use_socket_mainloop = 1;

/*
 * Constructor for DBus connection handle
 */
ni_dbus_connection_t *
ni_dbus_connection_open(const char *bus_name)
{
	ni_dbus_connection_t *connection;
	DBusError error;

	TRACE_ENTERN("%s", bus_name?: "");

	dbus_error_init(&error);

	connection = calloc(1, sizeof(*connection));
	if (bus_name == NULL) {
		connection->conn = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
		if (dbus_error_is_set(&error)) {
			ni_error("Cannot get dbus system bus handle (%s)",
					error.message);
			goto failed;
		}
		if (connection->conn == NULL)
			goto failed_unexpectedly;
	} else {
		int rv;

		connection->conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
		if (dbus_error_is_set(&error)) {
			ni_error("Cannot get dbus system bus handle (%s)",
					error.message);
			goto failed;
		}
		if (connection->conn == NULL)
			goto failed_unexpectedly;

		rv = dbus_bus_request_name(connection->conn, bus_name,
				DBUS_NAME_FLAG_REPLACE_EXISTING,
				&error);
		if (dbus_error_is_set(&error)) {
			ni_error("Failed to register dbus bus name \"%s\" (%s)",
					bus_name, error.message);
			goto failed;
		}
		if (rv != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
			goto failed_unexpectedly;
		ni_debug_dbus("Successfully acquired bus name \"%s\"", bus_name);
	}

	dbus_connection_add_filter(connection->conn, __ni_dbus_signal_filter, connection, NULL);
	if (ni_dbus_use_socket_mainloop) {
		dbus_connection_set_watch_functions(connection->conn,
				__ni_dbus_add_watch,
				__ni_dbus_remove_watch,
				NULL,			/* toggle_function */
				connection->conn,	/* data */
				NULL);			/* free_data_function */
	}

	return connection;

failed_unexpectedly:
	ni_error("%s: unexpected error", __FUNCTION__);

failed:
	ni_dbus_connection_free(connection);
	dbus_error_free(&error);
	return NULL;
}

/*
 * Destructor for DBus connection handle
 */
void
ni_dbus_connection_free(ni_dbus_connection_t *dbc)
{
	ni_dbus_pending_t *pd;
	ni_dbus_sigaction_t *sig;

	TRACE_ENTER();

	while ((pd = dbc->pending) != NULL) {
		dbc->pending = pd->next;
		dbus_pending_call_cancel(pd->call);
		__ni_dbus_pending_free(pd);
	}

	while ((sig = dbc->sighandlers) != NULL) {
		dbc->sighandlers = sig->next;
		__ni_dbus_sigaction_free(sig);
	}

	if (dbc->conn) {
		dbus_connection_close(dbc->conn);
		dbus_connection_unref(dbc->conn);
		dbc->conn = NULL;
	}

	free(dbc);
}

/*
 * Handle pending (async) calls
 */
static void
ni_dbus_connection_add_pending(ni_dbus_connection_t *connection,
			DBusPendingCall *call,
			ni_dbus_async_callback_t *callback,
			ni_dbus_proxy_t *proxy)
{
	ni_dbus_pending_t *pd;

	pd = calloc(1, sizeof(*pd));
	pd->proxy = proxy;
	pd->call = call;
	pd->callback = callback;

	pd->next = connection->pending;
	connection->pending = pd;
}

static void
__ni_dbus_pending_free(ni_dbus_pending_t *pd)
{
	dbus_pending_call_unref(pd->call);
	free(pd);
}

static int
__ni_dbus_process_pending(ni_dbus_connection_t *dbc, DBusPendingCall *call)
{
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	ni_dbus_pending_t *pd, **pos;
	int rv = 0;

	for (pos = &dbc->pending; (pd = *pos) != NULL; pos = &pd->next) {
		if (pd->call == call) {
			*pos = pd->next;
			pd->callback(pd->proxy, msg);
			__ni_dbus_pending_free(pd);
			rv = 1;
			break;
		}
	}

	dbus_message_unref(msg);
	return rv;
}

/*
 * Do a synchronous call across a connection
 */
int
ni_dbus_connection_call(ni_dbus_connection_t *connection,
		ni_dbus_message_t *call, ni_dbus_message_t **reply_p,
		unsigned int call_timeout, const ni_intmap_t *error_map)
{
	DBusPendingCall *pending;
	DBusMessage *reply;
	int rv;

	TRACE_ENTER();
	if (!dbus_connection_send_with_reply(connection->conn, call, &pending, call_timeout)) {
		ni_error("dbus_connection_send_with_reply: %m");
		return -EIO;
	}

	dbus_pending_call_block(pending);

	reply = dbus_pending_call_steal_reply(pending);

	if (call == NULL) {
		ni_error("dbus: no reply");
		return -EIO;
	}

	{
		DBusError error = DBUS_ERROR_INIT;

		switch (dbus_message_get_type(reply)) {
		case DBUS_MESSAGE_TYPE_METHOD_CALL:
			ni_warn("dbus reply = %p, type = methodCall", reply);
			goto eio;

		case DBUS_MESSAGE_TYPE_METHOD_RETURN:
			ni_debug_dbus("dbus reply = %p, type = methodReturn", reply);
			break;

		case DBUS_MESSAGE_TYPE_ERROR:
			dbus_set_error_from_message(&error, reply);
			ni_debug_dbus("dbus error reply = %s (%s)", error.name, error.message);
			rv = -ni_dbus_translate_error(&error, error_map);
			dbus_error_free(&error);
			goto failed;

		case DBUS_MESSAGE_TYPE_SIGNAL:
			ni_warn("dbus reply = %p, type = signal", reply);
			goto eio;
		}
	}

	*reply_p = reply;
	return 0;

eio:	rv = -EIO;
failed:	if (reply)
		dbus_message_unref(reply);
	ni_debug_dbus("%s returns %d", __FUNCTION__, rv);
	return rv;
}

/*
 * Do an asynchronous call across a DBus connection
 */
int
ni_dbus_connection_call_async(ni_dbus_connection_t *connection,
			ni_dbus_message_t *call, unsigned int timeout,
			ni_dbus_async_callback_t *callback, ni_dbus_proxy_t *proxy)
{
	DBusPendingCall *pending;

	if (!dbus_connection_send_with_reply(connection->conn, call, &pending, timeout)) {
		ni_error("dbus_connection_send_with_reply: %m");
		return -EIO;
	}

	ni_dbus_connection_add_pending(connection, pending, callback, proxy);
	dbus_pending_call_set_notify(pending, __ni_dbus_notify_async, connection, NULL);

	return 0;
}

static void
__ni_dbus_notify_async(DBusPendingCall *pending, void *call_data)
{
	ni_dbus_connection_t *conn = call_data;

	__ni_dbus_process_pending(conn, pending);
}

/*
 * Send a message out
 */
int
ni_dbus_connection_send_message(ni_dbus_connection_t *connection, ni_dbus_message_t *msg)
{
	if (!dbus_connection_send(connection->conn, msg, NULL))
		return -ENOMEM;
	return 0;
}

/*
 * Mainloop for watching a single connection.
 * Kill this.
 */
void
ni_dbus_mainloop(ni_dbus_connection_t *connection)
{
	TRACE_ENTER();
	while (dbus_connection_dispatch(connection->conn) == DBUS_DISPATCH_DATA_REMAINS)
		;
	while (ni_socket_wait(1000) >= 0) {
#if 0
		while (dbus_connection_dispatch(connection->conn) == DBUS_DISPATCH_DATA_REMAINS)
			;
#endif
	}
}

/*
 * Signal handling
 */
static ni_dbus_sigaction_t *
__ni_sigaction_new(const char *object_interface,
				ni_dbus_signal_handler_t *callback,
				void *user_data)
{
	ni_dbus_sigaction_t *s;

	s = calloc(1, sizeof(*s));
	ni_string_dup(&s->object_interface, object_interface);
	s->signal_handler = callback;
	s->user_data = user_data;

	return s;
}

static void
__ni_dbus_sigaction_free(ni_dbus_sigaction_t *s)
{
	ni_string_free(&s->object_interface);
	free(s);
}

void
ni_dbus_add_signal_handler(ni_dbus_connection_t *connection,
					const char *sender,
					const char *object_path,
					const char *object_interface,
					ni_dbus_signal_handler_t *callback,
					void *user_data)
{
	DBusMessage *call = NULL, *reply = NULL;
	ni_dbus_sigaction_t *sigact;
	char specbuf[1024], *arg;
	int rv;

	if (sender && object_path && object_interface) {
		snprintf(specbuf, sizeof(specbuf), "type='signal',sender='%s',path='%s',interface='%s'",
			sender, object_path, object_interface);
	} else if (sender && object_interface) {
		snprintf(specbuf, sizeof(specbuf), "type='signal',sender='%s',interface='%s'",
			sender, object_interface);
	} else {
		snprintf(specbuf, sizeof(specbuf), "type='signal',interface='%s'",
			object_interface);
	}
	arg = specbuf;

	call = dbus_message_new_method_call(NI_DBUS_BUS_NAME,
			NI_DBUS_OBJECT_PATH, NI_DBUS_INTERFACE, "AddMatch");
	if (!dbus_message_append_args(call, DBUS_TYPE_STRING, &arg, 0))
		goto failed;

	if ((rv = ni_dbus_connection_call(connection, call, &reply, 1000, NULL)) < 0)
		goto out;

	sigact = __ni_sigaction_new(object_interface, callback, user_data);
	sigact->next = connection->sighandlers;
	connection->sighandlers = sigact;

out:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	return;

failed:
	ni_error("Failed to add signal handler");
	goto out;
}

static DBusHandlerResult
__ni_dbus_signal_filter(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	ni_dbus_connection_t *connection = user_data;
	ni_dbus_sigaction_t *sigact;
	const char *interface;
	int handled = 0;

	if (connection->conn != conn)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	interface = dbus_message_get_interface(msg);
	for (sigact = connection->sighandlers; sigact; sigact = sigact->next) {
		if (!strcmp(sigact->object_interface, interface)) {
			sigact->signal_handler(connection, msg, sigact->user_data);
			handled++;
		}
	}

	if (handled)
		return DBUS_HANDLER_RESULT_HANDLED;
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/*
 * Handle server-side objects and dispatch incoming call
 */
void
ni_dbus_connection_register_object(ni_dbus_connection_t *connection, ni_dbus_object_t *object)
{
	dbus_connection_register_object_path(connection->conn,
			ni_dbus_object_get_path(object),
			ni_dbus_object_get_vtable(object),
			object);
}

void
ni_dbus_connection_unregister_object(ni_dbus_connection_t *connection, ni_dbus_object_t *object)
{
	const char *path = ni_dbus_object_get_path(object);

	if (!path)
		return;
	dbus_connection_unregister_object_path(connection->conn, path);
}

/*
 * Handle watching a connection
 */
static inline void
__ni_dbus_watch_handle(const char *func, ni_socket_t *sock, int flags)
{
	ni_dbus_watch_data_t *wd = sock->user_data;

	if (wd == NULL) {
		ni_warn("%s: dead socket", func);
	} else {
		ni_debug_dbus("%s(fd=%d)", func, dbus_watch_get_socket(wd->watch));
		dbus_watch_handle(wd->watch, flags);

		if (flags & (DBUS_WATCH_READABLE | DBUS_WATCH_WRITABLE)) {
			DBusConnection *conn = wd->conn;

			while (dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS)
				;
		}
		sock->poll_flags = 0;
		if (dbus_watch_get_enabled(wd->watch)) {
			flags = dbus_watch_get_flags(wd->watch);
			if (flags & DBUS_WATCH_READABLE)
				sock->poll_flags |= POLLIN;
			if (flags & DBUS_WATCH_WRITABLE)
				sock->poll_flags |= POLLOUT;
		}
	}
}

static void
__ni_dbus_watch_recv(ni_socket_t *sock)
{
	__ni_dbus_watch_handle(__FUNCTION__, sock, DBUS_WATCH_READABLE);
}

static void
__ni_dbus_watch_send(ni_socket_t *sock)
{
	__ni_dbus_watch_handle(__FUNCTION__, sock, DBUS_WATCH_WRITABLE);
}

static void
__ni_dbus_watch_error(ni_socket_t *sock)
{
	__ni_dbus_watch_handle(__FUNCTION__, sock, DBUS_WATCH_ERROR);
}

static void
__ni_dbus_watch_hangup(ni_socket_t *sock)
{
	__ni_dbus_watch_handle(__FUNCTION__, sock, DBUS_WATCH_HANGUP);
}

static void
__ni_dbus_watch_close(ni_socket_t *sock)
{
	ni_dbus_watch_data_t *wd = sock->user_data;

	TRACE_ENTER();
	if (wd != NULL) {
		/* Note, we're not explicitly closing the socket.
		 * We may want to shut down the connection owning
		 * us, however. */
		sock->user_data = NULL;
		wd->socket = NULL;
	}
}


dbus_bool_t
__ni_dbus_add_watch(DBusWatch *watch, void *data)
{
	DBusConnection *conn = data;
	ni_dbus_watch_data_t *wd;
	ni_socket_t *sock;

	ni_debug_dbus("%s(%p, conn=%p)", __FUNCTION__, watch, conn);

	if (!(wd = calloc(1, sizeof(*wd))))
		return 0;
	wd->conn = conn;
	wd->watch = watch;
	wd->next = ni_dbus_watches;
	ni_dbus_watches = wd;

	sock = ni_socket_wrap(dbus_watch_get_socket(watch), -1);
	sock->close = __ni_dbus_watch_close;
	sock->receive = __ni_dbus_watch_recv;
	sock->transmit = __ni_dbus_watch_send;
	sock->handle_error = __ni_dbus_watch_error;
	sock->handle_hangup = __ni_dbus_watch_hangup;
	sock->user_data = wd;
	wd->socket = sock;

	ni_socket_activate(sock);

	return 1;
}

void
__ni_dbus_remove_watch(DBusWatch *watch, void *dummy)
{
	ni_dbus_watch_data_t *wd, **pos;

	ni_debug_dbus("%s(%p)", __FUNCTION__, watch);
	for (pos = &ni_dbus_watches; (wd = *pos) != NULL; pos = &wd->next) {
		if (wd->watch == watch) {
			*pos = wd->next;
			if (wd->socket)
				ni_socket_close(wd->socket);
			free(wd);
			return;
		}
	}

	ni_warn("%s(%p): watch not found", __FUNCTION__, watch);
}

