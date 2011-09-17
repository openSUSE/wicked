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
#define TRACE_ENTERN(fmt, args...) \
				ni_debug_dbus("%s(" fmt ")", __FUNCTION__, ##args)
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

	const ni_dbus_property_t *properties;
};

struct ni_dbus_server {
	ni_dbus_connection_t *	connection;
	ni_dbus_object_t *	root_object;
};

static ni_dbus_service_t *	ni_dbus_object_register_object_manager(ni_dbus_object_t *);
static ni_dbus_service_t *	ni_dbus_object_register_property_interface(ni_dbus_object_t *object);
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

	ni_dbus_object_register_object_manager(server->root_object);

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
		char *child_path;

		len = strlen(parent->object_path) + strlen(name) + 2;
		child_path = malloc(len);
		snprintf(child_path, len, "%s/%s", parent->object_path, name);

		object = calloc(1, sizeof(*object));
		ni_string_dup(&object->object_name, name);
		object->object_path = child_path;
		object->server = parent->server;

		ni_debug_dbus("created %s as child of %s",
			object->object_path,
			parent->object_path);

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

	TRACE_ENTERN("path=%s, handle=%p", object_path, object_handle);

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
ni_dbus_object_register_service(ni_dbus_object_t *object, const char *interface,
				ni_dbus_service_handler_t *handler,
				const ni_dbus_property_t *properties)
{
	ni_dbus_service_t *svc;

	TRACE_ENTERN("path=%s, interface=%s", object->object_path, interface);

	svc = ni_dbus_object_get_service(object, interface);
	if (svc == NULL) {
		svc = calloc(1, sizeof(*svc));
		ni_string_dup(&svc->object_interface, interface);
		svc->handler = handler;

		if (object->interfaces == NULL) {
			ni_dbus_connection_register_object(object->server->connection, object);

			/* FIXME: register ObjectManager interface */
		}

		svc->next = object->interfaces;
		object->interfaces = svc;
	}

	if (svc->properties == NULL) {
		svc->properties = properties;
		if (svc->properties)
			ni_dbus_object_register_property_interface(object);
	} else if (svc->properties != properties) {
		ni_warn("Cannot override properties for object %s (interface %s)",
				object->object_path, interface);
	}

	return svc;
}

/*
 * Find the named property
 */
const ni_dbus_property_t *
ni_dbus_service_get_property(ni_dbus_service_t *service, const char *name)
{
	const ni_dbus_property_t *property;

	if (service->properties == NULL)
		return NULL;
	for (property = service->properties; property->name; ++property) {
		if (!strcmp(property->name, name))
			return property;
	}
	return NULL;
}

/*
 * Support the built-in ObjectManager interface
 */
static int	__ni_dbus_object_manager_handler(ni_dbus_object_t *object, const char *method,
				ni_dbus_message_t *call, ni_dbus_message_t *reply,
				DBusError *error);
static int	__ni_dbus_object_properties_handler(ni_dbus_object_t *object, const char *method,
				ni_dbus_message_t *call, ni_dbus_message_t *reply,
				DBusError *error);
static int	__ni_dbus_object_manager_enumerate_object(ni_dbus_object_t *, DBusMessageIter *);
static int	__ni_dbus_object_manager_enumerate_interface(ni_dbus_object_t *, ni_dbus_service_t *, DBusMessageIter *);

ni_dbus_service_t *
ni_dbus_object_register_object_manager(ni_dbus_object_t *object)
{
	ni_dbus_service_t *service;

	service = ni_dbus_object_register_service(object, NI_DBUS_INTERFACE ".ObjectManager",
					__ni_dbus_object_manager_handler,
					NULL);

	return service;
}

ni_dbus_service_t *
ni_dbus_object_register_property_interface(ni_dbus_object_t *object)
{
	ni_dbus_service_t *service;

	service = ni_dbus_object_register_service(object, NI_DBUS_INTERFACE ".Properties",
					__ni_dbus_object_properties_handler,
					NULL);

	return service;
}

static int
__ni_dbus_object_manager_handler(ni_dbus_object_t *object, const char *method,
		ni_dbus_message_t *call, ni_dbus_message_t *reply,
		DBusError *error)
{
	DBusMessageIter iter, dict_iter;

	TRACE_ENTERN("path=%s, method=%s", object->object_path, method);
	if (!strcmp(method, "GetManagedObjects")) {
		int rv = 0;

		dbus_message_iter_init_append(reply, &iter);
		if (!ni_dbus_dict_open_write(&iter, &dict_iter))
			rv = -1;
		if (!__ni_dbus_object_manager_enumerate_object(object, &dict_iter))
			rv = -1;
		ni_dbus_dict_close_write(&iter, &dict_iter);
		return rv;
	}

	dbus_set_error_const(error,
			"org.freedesktop.DBus.Error.UnknownMethod",
			"Method does not exist");
	return -1;
}

static int
__ni_dbus_object_properties_handler(ni_dbus_object_t *object, const char *method,
		ni_dbus_message_t *call, ni_dbus_message_t *reply,
		DBusError *error)
{
	DBusMessageIter iter, args_iter, dict_iter;
	const ni_dbus_property_t *property;
	ni_dbus_service_t *service;
	const char *interface_name, *property_name;
	int type;

	TRACE_ENTERN("path=%s, method=%s", object->object_path, method);
	if (strcmp(method, "Get") && strcmp(method, "Set") && strcmp(method, "GetAll")) {
		dbus_set_error_const(error,
				"org.freedesktop.DBus.Error.UnknownMethod",
				"Method does not exist");
		return -1;
	}

	dbus_message_iter_init(call, &args_iter);
	type = dbus_message_iter_get_arg_type(&args_iter);
	if (type != DBUS_TYPE_STRING)
		goto failed;
	dbus_message_iter_get_basic(&args_iter, &interface_name);
	if (interface_name == NULL || interface_name[0] == '\0') {
		service = NULL;
	} else {
		service = ni_dbus_object_get_service(object, interface_name);
		if (service == NULL) {
			dbus_set_error(error, DBUS_ERROR_SERVICE_UNKNOWN, "interface not known");
			return -1;
		}
	}

	if (!strcmp(method, "GetAll")) {
		int rv = 0;

		dbus_message_iter_init_append(reply, &iter);
		if (!ni_dbus_dict_open_write(&iter, &dict_iter))
			rv = -1;
		if (service != NULL) {
			if (!__ni_dbus_object_manager_enumerate_interface(object, service, &dict_iter))
				rv = -1;
		} else {
			for (service = object->interfaces; service; service = service->next) {
				if (!__ni_dbus_object_manager_enumerate_interface(object, service, &dict_iter))
					rv = -1;
			}
		}
		ni_dbus_dict_close_write(&iter, &dict_iter);
		return rv;
	}

	if (!dbus_message_iter_next(&args_iter)) {
		ni_debug_dbus("Missing property name in %s call to object %s interface %s",
				method, object->object_path, service->object_interface);
		goto failed;
	}

	type = dbus_message_iter_get_arg_type(&args_iter);
	if (type != DBUS_TYPE_STRING)
		goto failed;
	dbus_message_iter_get_basic(&args_iter, &property_name);
	if (service != NULL) {
		property = ni_dbus_service_get_property(service, property_name);
	} else {
		property = NULL;
		for (service = object->interfaces; service; service = service->next) {
			property = ni_dbus_service_get_property(service, property_name);
			if (property)
				break;
		}
	}
	if (property == NULL) {
		ni_debug_dbus("Unknown property \"%s\" on object %s interface %s",
				property_name, object->object_path, service->object_interface);
		goto failed;
	}

	dbus_message_iter_init_append(reply, &iter);
	if (!strcmp(method, "Get")) {
		ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;

		if (property->get == NULL)
			goto failed;
		if (!property->get(object, property, &result, error))
			return -1;

		/* Add variant to reply */
		if (!ni_dbus_message_iter_append_variant(&iter, &result))
			goto failed;

		ni_dbus_variant_destroy(&result);
	} else
	if (!strcmp(method, "Set")) {
		ni_dbus_variant_t value = NI_DBUS_VARIANT_INIT;

		if (!dbus_message_iter_next(&args_iter)) {
			ni_debug_dbus("Missing value in %s call to object %s interface %s",
					method, object->object_path, service->object_interface);
			goto failed;
		}

		/* get variant from message */
		if (!ni_dbus_message_iter_get_variant(&args_iter, &value))
			goto failed;

		ni_debug_dbus("Set %s %s=%s", object->object_path, property->name, ni_dbus_variant_sprint(&value));

		if (property->set == NULL)
			goto failed;

		/* FIXME: Verify variant against property's signature */

		if (!property->set(object, property, &value, error))
			return -1;
		ni_dbus_variant_destroy(&value);
	}

	return 0;

failed:
	/* the Properties interface should really define some errors... */
	dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting/setting property");
	return -1;
}

static int
__ni_dbus_object_manager_enumerate_interface(ni_dbus_object_t *object, ni_dbus_service_t *service, DBusMessageIter *dict_iter)
{
	DBusMessageIter entry_iter, val_iter, prop_iter;
	const ni_dbus_property_t *property;
	int rv = TRUE;

	TRACE_ENTERN("object=%s, interface=%s", object->object_path, service->object_interface);
	if (!ni_dbus_dict_begin_string_dict(dict_iter, service->object_interface,
					&entry_iter, &val_iter, &prop_iter))
		return FALSE;

	/* Loop over properties and add them here */
	if (service->properties) {
		for (property = service->properties; property->name; ++property) {
			ni_dbus_variant_t value = NI_DBUS_VARIANT_INIT;
			DBusError error = DBUS_ERROR_INIT;

			if (property->get == NULL)
				continue;
			if (property->get(object, property, &value, &error))
				ni_dbus_dict_append_variant(&prop_iter, property->name, &value);
			ni_dbus_variant_destroy(&value);
			dbus_error_free(&error);
		}
	}

	ni_dbus_dict_end_string_dict(dict_iter, &entry_iter, &val_iter, &prop_iter);
	return rv;
}

int
__ni_dbus_object_manager_enumerate_object(ni_dbus_object_t *object, DBusMessageIter *dict_iter)
{
	DBusMessageIter entry_iter, val_iter, interface_iter;
	ni_dbus_object_t *child;
	int rv = TRUE;

	if (object->interfaces) {
		ni_dbus_service_t *svc;

		if (!ni_dbus_dict_begin_string_dict(dict_iter, object->object_path,
						&entry_iter, &val_iter, &interface_iter))
			return FALSE;

		for (svc = object->interfaces; svc && rv; svc = svc->next)
			rv = __ni_dbus_object_manager_enumerate_interface(object, svc, &interface_iter);

		ni_dbus_dict_end_string_dict(dict_iter, &entry_iter, &val_iter, &interface_iter);
	}

	for (child = object->children; child && rv; child = child->next)
		rv = __ni_dbus_object_manager_enumerate_object(child, dict_iter);

	return rv;
}

/*
 * Object callbacks from dbus dispatcher
 */
static void
__ni_dbus_object_unregister(DBusConnection *conn, void *user_data)
{
	ni_dbus_object_t *object = user_data;

	ni_warn("%s(path=%s) called", __FUNCTION__, object->object_path);
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

	ni_debug_dbus("%s(path=%s, interface=%s, method=%s) called", __FUNCTION__, object->object_path, interface, method);
	svc = ni_dbus_object_get_service(object, interface);
	if (svc == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_error_init(&error);
	reply = dbus_message_new_method_return(call);
	rv = svc->handler(object, method, call, reply, &error);
	if (rv < 0) {
		dbus_message_unref(reply);
		if (error.name == NULL)
			dbus_set_error(&error, DBUS_ERROR_FAILED, "Unexpected error in method call");
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

void *
ni_dbus_object_get_handle(const ni_dbus_object_t *object)
{
	return object->object_handle;
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
			while (*bus_name == '.')
				++bus_name;
		} else {
			root_path[i++] = *bus_name++;
		}
	}
	root_path[i] = '\0';
	ni_assert(i < len);

	return root_path;
}

