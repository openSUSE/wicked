/*
 * Simple DBus connection wrappers
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
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
#include "process.h"
#include "debug.h"

#undef DEBUG_WATCH_VERBOSE

typedef struct ni_dbus_async_client_call ni_dbus_async_client_call_t;
struct ni_dbus_async_client_call {
	ni_dbus_async_client_call_t *next;

	DBusPendingCall *	call;
	ni_dbus_async_callback_t *callback;
	ni_dbus_object_t *	proxy;
};

typedef struct ni_dbus_async_server_call ni_dbus_async_server_call_t;
struct ni_dbus_async_server_call {
	ni_dbus_async_server_call_t *next;

	const ni_dbus_method_t *method;
	DBusMessage *		call_message;
	ni_process_t *		sub_process;
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
	ni_dbus_async_client_call_t *async_client_calls;
	ni_dbus_async_server_call_t *async_server_calls;
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
static void			__ni_dbus_async_server_call_free(ni_dbus_async_server_call_t *);
static void			__ni_dbus_async_client_call_free(ni_dbus_async_client_call_t *);
static void			__ni_dbus_notify_async(DBusPendingCall *, void *);
static dbus_bool_t		__ni_dbus_add_watch(DBusWatch *, void *);
static void			__ni_dbus_remove_watch(DBusWatch *, void *);
static DBusHandlerResult	__ni_dbus_signal_filter(DBusConnection *, DBusMessage *, void *);

static int			ni_dbus_use_socket_mainloop = 1;

/*
 * Constructor for DBus connection handle
 */
ni_dbus_connection_t *
ni_dbus_connection_open(const char *bus_type_string, const char *bus_name)
{
	ni_dbus_connection_t *connection;
	DBusError error;
	DBusBusType bus_type;

	NI_TRACE_ENTER_ARGS("bus=%s, name=%s", bus_type_string?: "system", bus_name?: "");

	dbus_error_init(&error);

	bus_type = DBUS_BUS_SYSTEM;
	if (bus_type_string) {
		if (!strcmp(bus_type_string, "system"))
			bus_type = DBUS_BUS_SYSTEM;
		else
		if (!strcmp(bus_type_string, "session"))
			bus_type = DBUS_BUS_SESSION;
		else {
			ni_error("%s: unknown bus type \"%s\"", __func__, bus_type_string);
			return NULL;
		}
	}

	connection = calloc(1, sizeof(*connection));
	if (bus_name == NULL) {
		connection->conn = dbus_bus_get_private(bus_type, &error);
		if (dbus_error_is_set(&error)) {
			ni_error("Cannot get dbus %s bus handle (%s)",
					bus_type == DBUS_BUS_SYSTEM? "system" : "session",
					error.message);
			goto failed;
		}
		if (connection->conn == NULL)
			goto failed_unexpectedly;
	} else {
		int rv;

		connection->conn = dbus_bus_get(bus_type, &error);
		if (dbus_error_is_set(&error)) {
			ni_error("Cannot get dbus %s bus handle (%s)",
					bus_type == DBUS_BUS_SYSTEM? "system" : "session",
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
		if (rv != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
			ni_error("%s: failed to acquire dbus name %s (rv=%d) - service already running?", __func__, bus_name, rv);
			goto failed;
		}
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
	ni_dbus_sigaction_t *sig;

	NI_TRACE_ENTER();

	while (dbc->async_client_calls) {
		ni_dbus_async_client_call_t *async = dbc->async_client_calls;

		dbc->async_client_calls = async->next;
		dbus_pending_call_cancel(async->call);
		__ni_dbus_async_client_call_free(async);
	}

	while (dbc->async_server_calls) {
		ni_dbus_async_server_call_t *async = dbc->async_server_calls;

		dbc->async_server_calls = async->next;
		__ni_dbus_async_server_call_free(async);
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
			ni_dbus_object_t *proxy)
{
	ni_dbus_async_client_call_t *async;

	async = calloc(1, sizeof(*async));
	async->proxy = proxy;
	async->call = call;
	async->callback = callback;

	async->next = connection->async_client_calls;
	connection->async_client_calls = async;
}

static void
__ni_dbus_async_client_call_free(ni_dbus_async_client_call_t *async)
{
	dbus_pending_call_unref(async->call);
	free(async);
}

static int
__ni_dbus_process_pending(ni_dbus_connection_t *dbc, DBusPendingCall *call)
{
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	ni_dbus_async_client_call_t *async, **pos;
	int rv = 0;

	for (pos = &dbc->async_client_calls; (async = *pos) != NULL; pos = &async->next) {
		if (async->call == call) {
			*pos = async->next;
			async->callback(async->proxy, msg);
			__ni_dbus_async_client_call_free(async);
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
ni_dbus_message_t *
ni_dbus_connection_call(ni_dbus_connection_t *connection,
		ni_dbus_message_t *call, unsigned int call_timeout, DBusError *error)
{
	DBusPendingCall *pending;
	DBusMessage *reply = NULL;
	int msgtype;

	if (!dbus_connection_send_with_reply(connection->conn, call, &pending, call_timeout)) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"unable to send DBus message (errno=%d)", errno);
		return NULL;
	}

	dbus_pending_call_block(pending);

	/* This makes sure that any signals we received while waiting for the reply
	 * do get dispatchd. */
	while (dbus_connection_dispatch(connection->conn) == DBUS_DISPATCH_DATA_REMAINS)
		;

	reply = dbus_pending_call_steal_reply(pending);

	if (call == NULL) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "dbus: no reply");
		return NULL;
	}

	msgtype = dbus_message_get_type(reply);
	if (msgtype == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
		/* All is well */
		return reply;
	}

	if (msgtype == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_set_error_from_message(error, reply);
		ni_debug_dbus("dbus error reply = %s (%s)", error->name, error->message);
	} else {
		dbus_set_error(error, DBUS_ERROR_FAILED, "dbus: unexpected message type in reply");
	}


	if (reply)
		dbus_message_unref(reply);
	return NULL;
}

/*
 * Do an asynchronous call across a DBus connection
 */
int
ni_dbus_connection_call_async(ni_dbus_connection_t *connection,
			ni_dbus_message_t *call, unsigned int timeout,
			ni_dbus_async_callback_t *callback, ni_dbus_object_t *proxy)
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
 * Send an error reply
 */
void
ni_dbus_connection_send_error(ni_dbus_connection_t *connection, ni_dbus_message_t *call, DBusError *error)
{
	ni_dbus_message_t *reply;

	if (!dbus_error_is_set(error))
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unexpected error in method call");
	reply = dbus_message_new_error(call, error->name, error->message);

	if (ni_dbus_connection_send_message(connection, reply) < 0)
		ni_error("unable to send reply (out of memory)");

	dbus_message_unref(reply);
}

/*
 * Mainloop for watching a single connection.
 * Kill this.
 */
void
ni_dbus_mainloop(ni_dbus_connection_t *connection)
{
	NI_TRACE_ENTER();
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
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_sigaction_t *sigact;
	char specbuf[1024], *arg;

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

	if ((reply = ni_dbus_connection_call(connection, call, 5000, &error)) == NULL)
		goto out;

	sigact = __ni_sigaction_new(object_interface, callback, user_data);
	sigact->next = connection->sighandlers;
	connection->sighandlers = sigact;

out:
	if (call)
		dbus_message_unref(call);
	if (reply)
		dbus_message_unref(reply);
	dbus_error_free(&error);
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

	if (path) {
		ni_debug_dbus("dbus_connection_unregister_object_path(%s)", path);
		dbus_connection_unregister_object_path(connection->conn, path);
	}
}

/*
 * Server side: process calls asynchronously
 */
void
__ni_dbus_async_server_call_callback(ni_process_t *proc)
{
	ni_dbus_connection_t *conn = proc->user_data;
	ni_dbus_async_server_call_t **pos, *async;

	for (pos = &conn->async_server_calls; (async = *pos) != NULL; pos = &async->next) {
		if (async->sub_process == proc) {
			*pos = async->next;
			break;
		}
	}
	if (async == NULL) {
		ni_error("%s: unknown subprocess exited", __func__);
		return;
	}

	async->sub_process = NULL;

	/* Should build response and send it out now */
	async->method->async_completion(conn, async->method, async->call_message, proc);

	__ni_dbus_async_server_call_free(async);
}

static ni_dbus_async_server_call_t *
__ni_dbus_async_server_call_new(ni_dbus_connection_t *conn,
					const ni_dbus_method_t *method,
					DBusMessage *call_message)
{
	ni_dbus_async_server_call_t *async;

	async = xcalloc(1, sizeof(*async));
	async->method = method;
	async->call_message = dbus_message_ref(call_message);

	async->next = conn->async_server_calls;
	conn->async_server_calls = async;

	return async;
}

void
__ni_dbus_async_server_call_free(ni_dbus_async_server_call_t *async)
{
	if (async->call_message)
		dbus_message_unref(async->call_message);
	if (async->sub_process) {
		ni_process_t *proc = async->sub_process;

		async->sub_process = NULL;

		/* kill subprocess and free associated struct */
		ni_process_free(proc);
	}
	free(async);
}

int
ni_dbus_async_server_call_run_command(ni_dbus_connection_t *conn,
					ni_dbus_object_t *object,
					const ni_dbus_method_t *method,
					DBusMessage *call_message,
					ni_process_t *process)
{
	ni_dbus_async_server_call_t *async;
	int rv;

	if ((rv = ni_process_run(process)) < 0) {
		const char *path = ni_dbus_object_get_path(object);

		ni_debug_dbus("%s: unable to run command \"%s\"", path, process->process->command);
		return rv;
	}

	async = __ni_dbus_async_server_call_new(conn, method, call_message);
	async->sub_process = process;
	process->notify_callback = __ni_dbus_async_server_call_callback;
	process->user_data = conn;

	return 0;
}

/*
 * Handle watching a connection
 */
static inline const char *
__ni_dbus_watch_flags(int flags)
{
	switch (flags) {
	case DBUS_WATCH_READABLE:
		return "read";

	case DBUS_WATCH_WRITABLE:
		return "write";

	case DBUS_WATCH_READABLE|DBUS_WATCH_WRITABLE:
		return "readwrite";

	case DBUS_WATCH_ERROR:
		return "error";

	case DBUS_WATCH_HANGUP:
		return "hangup";
	}

	return "???";
}

static inline void
__ni_dbus_watch_handle(const char *func, ni_socket_t *sock, int flags)
{
	ni_dbus_watch_data_t *wd;
	int found = 0, poll_flags = 0;

	/* All of this is somewhat more complicated than it may need to be.
	 * For some odd reason, libdbus insists on maintaining two watches
	 * per connection, so that for every socket state change, we need to
	 * loop over all watches.
	 */
	for (wd = ni_dbus_watches; wd; wd = wd->next) {
		int new_watch_flags;
#ifdef DEBUG_WATCH_VERBOSE
		int old_watch_flags;
#endif

		if (wd->socket != sock)
			continue;
		found++;

#ifdef DEBUG_WATCH_VERBOSE
		ni_debug_dbus("%s(watch=%p, fd=%d, flags=%s)",
				func, wd->watch, dbus_watch_get_socket(wd->watch),
				__ni_dbus_watch_flags(flags));

		old_watch_flags = dbus_watch_get_flags(wd->watch);
#endif
		dbus_watch_handle(wd->watch, flags);

		if (flags & (DBUS_WATCH_READABLE | DBUS_WATCH_WRITABLE)) {
			DBusConnection *conn = wd->conn;

			while (dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS)
				;
		}

		new_watch_flags = dbus_watch_get_flags(wd->watch);
		if (dbus_watch_get_enabled(wd->watch)) {
			if (new_watch_flags & DBUS_WATCH_READABLE)
				poll_flags |= POLLIN;
			if (new_watch_flags & DBUS_WATCH_WRITABLE)
				poll_flags |= POLLOUT;
		}

#ifdef DEBUG_WATCH_VERBOSE
		if (old_watch_flags != new_watch_flags) {
			ni_debug_dbus("%s: changing watch flags %s to %s",
					__func__,
					__ni_dbus_watch_flags(old_watch_flags),
					__ni_dbus_watch_flags(new_watch_flags));
		}
#endif
	}

	sock->poll_flags = poll_flags;
	if (!found)
		ni_warn("%s: dead socket", func);
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
	ni_dbus_watch_data_t *wd;

	NI_TRACE_ENTER();
	for (wd = ni_dbus_watches; wd; wd = wd->next) {
		if (wd->socket == sock) {
			/* Note, we're not explicitly closing the socket.
			 * We may want to shut down the connection owning
			 * us, however. */
			wd->socket = NULL;
		}
	}
}


dbus_bool_t
__ni_dbus_add_watch(DBusWatch *watch, void *data)
{
	DBusConnection *conn = data;
	ni_dbus_watch_data_t *wd;
	ni_socket_t *sock = NULL;

	for (wd = ni_dbus_watches; wd; wd = wd->next) {
		if (wd->conn == conn) {
			sock = wd->socket;
			break;
		}
	}

	ni_debug_dbus("%s(%p, conn=%p, fd=%d, reuse sock=%p)",
			__FUNCTION__, watch, conn, dbus_watch_get_socket(watch), sock);

	if (!(wd = calloc(1, sizeof(*wd))))
		return 0;
	wd->conn = conn;
	wd->watch = watch;
	wd->next = ni_dbus_watches;
	ni_dbus_watches = wd;

	if (sock == NULL) {
		sock = ni_socket_wrap(dbus_watch_get_socket(watch), -1);
		sock->close = __ni_dbus_watch_close;
		sock->receive = __ni_dbus_watch_recv;
		sock->transmit = __ni_dbus_watch_send;
		sock->handle_error = __ni_dbus_watch_error;
		sock->handle_hangup = __ni_dbus_watch_hangup;
		ni_socket_activate(sock);
	} else {
		ni_socket_hold(sock);
	}

	wd->socket = sock;

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

