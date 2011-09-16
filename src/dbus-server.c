/*
 * Simple DBus server functions
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
#include "dbus-server.h"
#include "dbus-dict.h"

#define TRACE_ENTER()		ni_debug_dbus("%s()", __FUNCTION__)
#define TP()			ni_debug_dbus("TP - %s:%u", __FUNCTION__, __LINE__)


struct ni_dbus_object {
	ni_dbus_object_t *	next;
	ni_dbus_server_t *	server;			/* back pointer at server */
	char *			object_name;		/* relative path */
	char *			object_path;		/* absolute path */
	void *			object_handle;		/* local object */
	ni_dbus_service_t *	interfaces;
	ni_dbus_object_t *	children;
};

struct ni_dbus_service {
	ni_dbus_service_t *	next;
	char *			object_interface;
	ni_dbus_service_handler_t *handler;
};

struct ni_dbus_server {
	ni_dbus_connection_t *	connection;
	ni_dbus_object_t *	root_object;
};

static char *			__ni_dbus_server_root_path(const char *);
static void			__ni_dbus_object_free(ni_dbus_object_t *);
static void			__ni_dbus_service_free(ni_dbus_service_t *);

/*
 * Constructor for DBus server handle
 */
ni_dbus_server_t *
ni_dbus_server_open(const char *bus_name, void *root_object_handle)
{
	ni_dbus_server_t *server;

	ni_debug_dbus("%s(%s)", __FUNCTION__, bus_name);

	server = calloc(1, sizeof(*server));
	server->connection = ni_dbus_connection_open(bus_name);
	if (server->connection == NULL) {
		ni_dbus_server_free(server);
		return NULL;

	}

	/* Translate bus name foo.bar.baz into object path /foo/bar/baz */
	server->root_object = calloc(1, sizeof(ni_dbus_object_t));
	server->root_object->server = server;
	server->root_object->object_path = __ni_dbus_server_root_path(bus_name);
	server->root_object->object_handle = root_object_handle;

	return server;
}

/*
 * Destructor for DBus server handle
 */
void
ni_dbus_server_free(ni_dbus_server_t *server)
{
	TRACE_ENTER();

	if (server->root_object)
		__ni_dbus_object_free(server->root_object);

	ni_dbus_connection_free(server->connection);
	server->connection = NULL;

	free(server);
}

/*
 * Retrieve the server's root object
 */
ni_dbus_object_t *
ni_dbus_server_get_root_object(const ni_dbus_server_t *server)
{
	return server->root_object;
}

/*
 * Look up an object by its relative name
 */
static ni_dbus_object_t *
__ni_dbus_server_get_object(ni_dbus_object_t *parent, const char *name, int create)
{
	ni_dbus_object_t **pos, *object;

	if (*name == '\0') {
		return parent;
	}

	pos = &parent->children;
	while ((object = *pos) != NULL) {
		if (!strcmp(object->object_name, name))
			return object;
		pos = &object->next;
	}

	if (create) {
		unsigned int len;

		object = calloc(1, sizeof(*object));
		ni_string_dup(&object->object_name, name);
		len = strlen(parent->object_path) + strlen(name) + 2;
		object->object_path = malloc(len);
		snprintf(object->object_path, len, "%s/%s", parent->object_path, name);

		*pos = object;
	}
	return object;
}

static ni_dbus_object_t *
__ni_dbus_server_find_object(ni_dbus_server_t *server, const char *path, int create)
{
	char *path_copy = NULL, *name;
	ni_dbus_object_t *found;

	if (path == NULL)
		return server->root_object;

	ni_string_dup(&path_copy, path);

	found = server->root_object;
	for (name = strtok(path_copy, "/"); name && found; name = strtok(NULL, "/"))
		found = __ni_dbus_server_get_object(found, name, create);

	ni_string_free(&path_copy);
	return found;
}

/*
 * Register an object
 */
ni_dbus_object_t *
ni_dbus_server_register_object(ni_dbus_server_t *server, const char *object_path, void *object_handle)
{
	ni_dbus_object_t *object;

	object = __ni_dbus_server_find_object(server, object_path, 1);
	if (object == NULL) {
		ni_error("%s: could not create object \"%s\"", __FUNCTION__, object_path);
		return NULL;
	}
	if (object->object_handle == NULL) {
		object->object_handle = object_handle;
	} else 
	if (object->object_handle != object_handle) {
		ni_error("%s: cannot re-register object \"%s\"", __FUNCTION__, object_path);
		return NULL;
	}

	return object;
}

/*
 * Register an object interface
 */
ni_dbus_service_t *
ni_dbus_object_get_service(ni_dbus_object_t *object, const char *interface)
{
	ni_dbus_service_t *svc;

	for (svc = object->interfaces; svc; svc = svc->next) {
		if (!strcasecmp(svc->object_interface, interface))
			return svc;
	}

	return NULL;
}

/*
 * Register a service for the given object.
 * Note, we cannot register fallback services yet.
 */
ni_dbus_service_t *
ni_dbus_object_register_service(ni_dbus_object_t *object, const char *interface, ni_dbus_service_handler_t *handler)
{
	ni_dbus_service_t *svc;

	svc = ni_dbus_object_get_service(object, interface);
	if (svc == NULL) {
		svc = calloc(1, sizeof(*svc));
		ni_string_dup(&svc->object_interface, interface);
		svc->handler = handler;

		if (object->interfaces == NULL)
			ni_dbus_connection_register_object(object->server->connection, object);

		svc->next = object->interfaces;
		object->interfaces = svc;
	}

	return svc;
}

/*
 * Support the built-in ObjectManager interface
 */
static int	__ni_dbus_object_manager_handler(void *object_handle, const char *method,
				ni_dbus_message_t *call, ni_dbus_message_t *reply,
				DBusError *error);

ni_dbus_service_t *
ni_dbus_object_register_object_manager(ni_dbus_object_t *object)
{
	ni_dbus_service_t *service;

	service = ni_dbus_object_register_service(object, NI_DBUS_INTERFACE ".ObjectManager",
					__ni_dbus_object_manager_handler);

	return service;
}

static int
__ni_dbus_object_manager_handler(void *object, const char *method,
		ni_dbus_message_t *call, ni_dbus_message_t *reply,
		DBusError *error)
{
	return 0;
}

/*
 * Object callbacks from dbus dispatcher
 */
static void
__ni_dbus_object_unregister(DBusConnection *conn, void *user_data)
{
	ni_dbus_object_t *object = user_data;

	ni_warn("%s(path=%s) called\n", __FUNCTION__, object->object_path);
}

static DBusHandlerResult
__ni_dbus_object_message(DBusConnection *conn, DBusMessage *call, void *user_data)
{
	const char *interface = dbus_message_get_interface(call);
	const char *method = dbus_message_get_member(call);
	ni_dbus_object_t *object = user_data;
	DBusMessage *reply;
	DBusError error;
	ni_dbus_service_t *svc;
	int rv;

	/* FIXME: check for type CALL */

	ni_debug_dbus("%s(path=%s, interface=%s, method=%s) called\n", __FUNCTION__, object->object_path, interface, method);
	svc = ni_dbus_object_get_service(object, interface);
	if (svc == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_error_init(&error);
	reply = dbus_message_new_method_return(call);
	rv = svc->handler(object->object_handle, method, call, reply, &error);
	if (rv < 0) {
		dbus_message_unref(reply);
		reply = dbus_message_new_error(call, error.name, error.message);
	}

	/* send reply */
	if (ni_dbus_connection_send_message(object->server->connection, reply) < 0)
		ni_error("unable to send reply (out of memory)");

	dbus_error_free(&error);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

/*
 * Helper functions
 */
const char *
ni_dbus_object_get_path(const ni_dbus_object_t *object)
{
	return object->object_path;
}

const DBusObjectPathVTable *
ni_dbus_object_get_vtable(const ni_dbus_object_t *dummy)
{
	static DBusObjectPathVTable vtable = {
		.unregister_function = __ni_dbus_object_unregister,
		.message_function = __ni_dbus_object_message,
	};

	return &vtable;
}

/*
 * Unregister all dbus objects for a given C object
 */
void
__ni_dbus_server_unregister_object(ni_dbus_object_t *parent, void *object_handle)
{
	ni_dbus_object_t **pos, *object;

	for (pos = &parent->children; (object = *pos) != NULL; ) {
		if (object->object_handle != object_handle) {
			__ni_dbus_server_unregister_object(object, object_handle);
			pos = &object->next;
		} else {
			*pos = object->next;
			__ni_dbus_object_free(object);
		}
	}
}

void
ni_dbus_server_unregister_object(ni_dbus_server_t *server, void *object_handle)
{
	__ni_dbus_server_unregister_object(server->root_object, object_handle);
}

static void
__ni_dbus_object_free(ni_dbus_object_t *object)
{
	ni_dbus_service_t *svc;
	ni_dbus_object_t *child;

	ni_dbus_connection_unregister_object(object->server->connection, object);

	ni_string_free(&object->object_name);
	ni_string_free(&object->object_path);
	while ((svc = object->interfaces) != NULL) {
		object->interfaces = svc->next;
		__ni_dbus_service_free(svc);
	}
	while ((child = object->children) != NULL) {
		object->children = child->next;
		__ni_dbus_object_free(child);
	}
	free(object);
}

static void
__ni_dbus_service_free(ni_dbus_service_t *svc)
{
	ni_string_free(&svc->object_interface);
	free(svc);
}


/*
 * Translate bus name foo.bar.baz into object path /foo/bar/baz
 */
static char *
__ni_dbus_server_root_path(const char *bus_name)
{
	char *root_path;
	unsigned int i, len;

	len = strlen(bus_name) + 2;
	root_path = malloc(len);
	root_path[0] = '/';

	for (i = 1; *bus_name != '\0'; ) {
		if (*bus_name == '.') {
			root_path[i++] = '/';
			while (*bus_name++ == '.')
				;
		} else {
			root_path[i] = *bus_name++;
		}
	}
	root_path[i] = '\0';
	ni_assert(i < len);

	return root_path;
}

