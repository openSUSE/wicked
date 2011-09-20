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
	const ni_dbus_service_t **interfaces;
	ni_dbus_object_t *	children;
	const ni_dbus_object_functions_t *functions;
};

struct ni_dbus_server {
	ni_dbus_connection_t *	connection;
	ni_dbus_object_t *	root_object;
};

static dbus_bool_t		ni_dbus_object_register_object_manager(ni_dbus_object_t *);
static dbus_bool_t		ni_dbus_object_register_property_interface(ni_dbus_object_t *object);
static char *			__ni_dbus_server_root_path(const char *);
static char *			__ni_dbus_server_child_path(const ni_dbus_object_t *, const char *);
static ni_dbus_object_t *	__ni_dbus_object_new(ni_dbus_server_t *, char *);
static void			__ni_dbus_object_free(ni_dbus_object_t *);

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
	server->root_object = __ni_dbus_object_new(server, __ni_dbus_server_root_path(bus_name));
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
 * Create a new dbus object
 */
static ni_dbus_object_t *
__ni_dbus_object_new(ni_dbus_server_t *server, char *path)
{
	ni_dbus_object_t *object;

	object = calloc(1, sizeof(*object));
	object->object_path = path;
	object->server = server;

	ni_dbus_object_register_object_manager(object);
	return object;
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
		object = __ni_dbus_object_new(parent->server, 
					__ni_dbus_server_child_path(parent, name));
		ni_string_dup(&object->object_name, name);

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
ni_dbus_server_register_object(ni_dbus_server_t *server, const char *object_path,
				const ni_dbus_object_functions_t *functions,
				void *object_handle)
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

	if (object->functions == NULL) {
		object->functions = functions;
	} else 
	if (object->functions != functions) {
		ni_error("%s: cannot re-register object \"%s\"", __FUNCTION__, object_path);
		return NULL;
	}

	return object;
}

/*
 * Register an object interface
 */
const ni_dbus_service_t *
ni_dbus_object_get_service(ni_dbus_object_t *object, const char *interface)
{
	const ni_dbus_service_t *svc;
	unsigned int i;

	if (object->interfaces == NULL)
		return NULL;

	for (i = 0; (svc = object->interfaces[i]) != NULL; ++i) {
		if (!strcasecmp(svc->object_interface, interface))
			return svc;
	}

	return NULL;
}

/*
 * Register a service for the given object.
 * Note, we cannot register fallback services yet.
 */
dbus_bool_t
ni_dbus_object_register_service(ni_dbus_object_t *object, const ni_dbus_service_t *svc)
{
	unsigned int count;

	TRACE_ENTERN("path=%s, interface=%s", object->object_path, svc->object_interface);

	count = 0;
	if (object->interfaces != NULL) {
		while (object->interfaces[count] != NULL) {
			if (object->interfaces[count] == svc)
				return TRUE;
			++count;
		}
	}

	if (object->interfaces == NULL) {
		ni_dbus_connection_register_object(object->server->connection, object);

		/* FIXME: register ObjectManager interface */
	}

	object->interfaces = realloc(object->interfaces, (count + 2) * sizeof(svc));
	object->interfaces[count++] = svc;
	object->interfaces[count] = NULL;

	if (svc->properties)
		ni_dbus_object_register_property_interface(object);
	return TRUE;
}

/*
 * Find the named property
 */
const ni_dbus_property_t *
ni_dbus_service_get_property(const ni_dbus_service_t *service, const char *name)
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
 * Find the named method
 */
const ni_dbus_method_t *
ni_dbus_service_get_method(const ni_dbus_service_t *service, const char *name)
{
	const ni_dbus_method_t *method;

	if (service->methods == NULL)
		return NULL;
	for (method = service->methods; method->name; ++method) {
		if (!strcmp(method->name, name))
			return method;
	}
	return NULL;
}

/*
 * Support the built-in ObjectManager interface
 */
static const ni_dbus_service_t __ni_dbus_object_manager_interface;
static const ni_dbus_service_t __ni_dbus_object_properties_interface;
static dbus_bool_t	__ni_dbus_object_manager_enumerate_object(ni_dbus_object_t *, DBusMessageIter *);
static dbus_bool_t	__ni_dbus_object_manager_enumerate_interface(ni_dbus_object_t *,
				const ni_dbus_service_t *,
				DBusMessageIter *);

dbus_bool_t
ni_dbus_object_register_object_manager(ni_dbus_object_t *object)
{
	return ni_dbus_object_register_service(object,
					&__ni_dbus_object_manager_interface);
}

dbus_bool_t
ni_dbus_object_register_property_interface(ni_dbus_object_t *object)
{
	return ni_dbus_object_register_service(object, &__ni_dbus_object_properties_interface);
}

static dbus_bool_t
__ni_dbus_object_manager_get_managed_objects(ni_dbus_object_t *object,
		const ni_dbus_method_t *method,
		unsigned int argc, const ni_dbus_variant_t *argv,
		ni_dbus_message_t *reply,
		DBusError *error)
{
	DBusMessageIter iter, dict_iter;
	int rv = TRUE;

	TRACE_ENTERN("path=%s, method=%s", object->object_path, method->name);

	dbus_message_iter_init_append(reply, &iter);
	rv = ni_dbus_dict_open_write(&iter, &dict_iter);
	if (rv)
		rv = __ni_dbus_object_manager_enumerate_object(object, &dict_iter);
	ni_dbus_dict_close_write(&iter, &dict_iter);
	return rv;
}

static ni_dbus_method_t	__ni_dbus_object_manager_methods[] = {
	{ "GetManagedObjects",		NULL,		__ni_dbus_object_manager_get_managed_objects },
	{ NULL }
};

static const ni_dbus_service_t __ni_dbus_object_manager_interface = {
	.object_interface = NI_DBUS_INTERFACE ".ObjectManager",
	.methods = __ni_dbus_object_manager_methods,
};

/*
 * Helper function for Properties.* methods
 */
static dbus_bool_t
__ni_dbus_object_properties_arg_interface(ni_dbus_object_t *object, const ni_dbus_method_t *method,
				const char *interface_name, DBusError *error,
				const ni_dbus_service_t **service_p)
{
	const ni_dbus_service_t *service;

	if (interface_name == NULL || interface_name[0] == '\0') {
		*service_p = NULL;
		return TRUE;
	}

	service = ni_dbus_object_get_service(object, interface_name);
	if (service == NULL) {
		dbus_set_error(error, DBUS_ERROR_SERVICE_UNKNOWN,
				"%s: Properties.%s() failed: interface %s not known",
				object->object_path, method->name,
				interface_name);
		return FALSE;
	}

	*service_p = service;
	return TRUE;
}

static dbus_bool_t
__ni_dbus_object_properties_arg_property(ni_dbus_object_t *object, const ni_dbus_method_t *method,
				const char *property_name, DBusError *error,
				const ni_dbus_service_t **service_p, const ni_dbus_property_t **property_p)
{
	const ni_dbus_service_t *service = *service_p;
	const ni_dbus_property_t *property = NULL;

	if (property_name == NULL || property_name[0] == '\0')
		return FALSE;

	if (service != NULL) {
		property = ni_dbus_service_get_property(service, property_name);
	} else {
		unsigned int i;

		for (i = 0; (service = object->interfaces[i]) != NULL; ++i) {
			property = ni_dbus_service_get_property(service, property_name);
			if (property)
				break;
		}
	}

	if (property == NULL) {
		dbus_set_error(error, DBUS_ERROR_UNKNOWN_METHOD,
				"Unknown property \"%s\" on object %s interface %s",
				property_name, object->object_path,
				service? service->object_interface : "*");
		return FALSE;
	}
	*property_p = property;
	return TRUE;
}

/*
 * This method implements Properties.GetAll
 */
static dbus_bool_t
__ni_dbus_object_properties_getall(ni_dbus_object_t *object, const ni_dbus_method_t *method,
		unsigned int argc, const ni_dbus_variant_t *argv,
		ni_dbus_message_t *reply, DBusError *error)
{
	DBusMessageIter iter, dict_iter;
	const ni_dbus_service_t *service;
	int rv = TRUE;

	if (!__ni_dbus_object_properties_arg_interface(object, method,
				argv[0].string_value, error, &service))
		return FALSE;

	dbus_message_iter_init_append(reply, &iter);
	if (!ni_dbus_dict_open_write(&iter, &dict_iter))
		rv = FALSE;
	if (service != NULL) {
		if (!__ni_dbus_object_manager_enumerate_interface(object, service, &dict_iter))
			rv = FALSE;
	} else {
		unsigned int i;

		for (i = 0; (service = object->interfaces[i]) != NULL; ++i) {
			if (!__ni_dbus_object_manager_enumerate_interface(object, service, &dict_iter))
				rv = FALSE;
		}
	}
	ni_dbus_dict_close_write(&iter, &dict_iter);
	return rv;
}

static dbus_bool_t
__ni_dbus_object_properties_get(ni_dbus_object_t *object, const ni_dbus_method_t *method,
		unsigned int argc, const ni_dbus_variant_t *argv,
		ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	const ni_dbus_property_t *property;
	const ni_dbus_service_t *service;
	DBusMessageIter iter;

	if (!__ni_dbus_object_properties_arg_interface(object, method,
				argv[0].string_value, error, &service))
		return FALSE;

	if (!__ni_dbus_object_properties_arg_property(object, method,
				argv[1].string_value, error,
				&service, &property))
		return FALSE;

	dbus_message_iter_init_append(reply, &iter);

	if (property->get == NULL)
		goto failed;
	if (!property->get(object, property, &result, error))
		return FALSE;

	/* Add variant to reply */
	if (!ni_dbus_message_iter_append_variant(&iter, &result))
		goto failed;

	ni_dbus_variant_destroy(&result);

	return TRUE;

failed:
	/* the Properties interface should really define some errors... */
	dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting/setting property");
	return FALSE;
}

static dbus_bool_t
__ni_dbus_object_properties_set(ni_dbus_object_t *object, const ni_dbus_method_t *method,
		unsigned int argc, const ni_dbus_variant_t *argv,
		ni_dbus_message_t *reply, DBusError *error)
{
	const ni_dbus_property_t *property;
	const ni_dbus_service_t *service;

	if (!__ni_dbus_object_properties_arg_interface(object, method,
				argv[0].string_value, error, &service))
		return FALSE;

	if (!__ni_dbus_object_properties_arg_property(object, method,
				argv[1].string_value, error,
				&service, &property))
		return FALSE;

	ni_debug_dbus("Set %s %s=%s", object->object_path, property->name,
			ni_dbus_variant_sprint(&argv[2]));

	if (property->set == NULL) {
		dbus_set_error(error,
				DBUS_ERROR_UNKNOWN_METHOD,	/* no error msgs defined */
				"%s: unable to set read-only property %s.%s",
				object->object_path, service->object_interface,
				property->name);
		return FALSE;
	}

	/* FIXME: Verify variant against property's signature */

	if (!property->set(object, property, &argv[2], error))
		return FALSE;

	return TRUE;
}

static ni_dbus_method_t	__ni_dbus_object_properties_methods[] = {
	{ "GetAll",		"s",		__ni_dbus_object_properties_getall },
	{ "Get",		"ss",		__ni_dbus_object_properties_get },
	{ "Set",		"ssv",		__ni_dbus_object_properties_set },
	{ NULL }
};

static const ni_dbus_service_t __ni_dbus_object_properties_interface = {
	.object_interface = NI_DBUS_INTERFACE ".Properties",
	.methods = __ni_dbus_object_properties_methods,
};

static dbus_bool_t
__ni_dbus_object_manager_enumerate_interface(ni_dbus_object_t *object,
		const ni_dbus_service_t *service, DBusMessageIter *dict_iter)
{
	const ni_dbus_property_t *property;
	int rv = TRUE;

	TRACE_ENTERN("object=%s, interface=%s", object->object_path, service->object_interface);

	/* Loop over properties and add them here */
	if (service->properties) {
		for (property = service->properties; property->name; ++property) {
			ni_dbus_variant_t value = NI_DBUS_VARIANT_INIT;
			DBusError error = DBUS_ERROR_INIT;

			if (property->get == NULL)
				continue;
			if (!property->get(object, property, &value, &error)) {
				ni_debug_dbus("%s: unable to get property %s.%s",
						object->object_path,
						service->object_interface,
						property->name);
			} else if (!ni_dbus_dict_append_variant(dict_iter, property->name, &value)) {
				ni_debug_dbus("%s: unable to encode property %s.%s",
						object->object_path,
						service->object_interface,
						property->name);
				rv = FALSE;
			}
			ni_dbus_variant_destroy(&value);
			dbus_error_free(&error);
		}
	}

	return rv;
}

dbus_bool_t
__ni_dbus_object_manager_enumerate_object(ni_dbus_object_t *object, DBusMessageIter *dict_iter)
{
	DBusMessageIter entry_iter, val_iter, interface_iter;
	ni_dbus_object_t *child;
	int rv = TRUE;

	if (object->interfaces) {
		const ni_dbus_service_t *svc;
		unsigned int i;

		if (!ni_dbus_dict_begin_string_dict(dict_iter, object->object_path,
						&entry_iter, &val_iter, &interface_iter))
			return FALSE;

		for (i = 0; rv && (svc = object->interfaces[i]) != NULL; ++i) {
			DBusMessageIter entry_iter, val_iter, prop_iter;

			if (!ni_dbus_dict_begin_string_dict(&interface_iter, svc->object_interface,
							&entry_iter, &val_iter, &prop_iter))
				return FALSE;

			rv = __ni_dbus_object_manager_enumerate_interface(object, svc, &prop_iter);
			ni_dbus_dict_end_string_dict(&interface_iter, &entry_iter, &val_iter, &prop_iter);
		}

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
	const char *method_name = dbus_message_get_member(call);
	ni_dbus_object_t *object = user_data;
	const ni_dbus_method_t *method;
	DBusError error = DBUS_ERROR_INIT;
	DBusMessage *reply = NULL;
	const ni_dbus_service_t *svc;
	dbus_bool_t rv = FALSE;

	/* FIXME: check for type CALL */

	ni_debug_dbus("%s(path=%s, interface=%s, method=%s) called", __FUNCTION__, object->object_path, interface, method_name);
	svc = ni_dbus_object_get_service(object, interface);
	if (svc == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	method = ni_dbus_service_get_method(svc, method_name);
	if (method == NULL) {
		dbus_set_error(&error,
				DBUS_ERROR_UNKNOWN_METHOD,
				"Unknown method in call to object %s, %s.%s",
				object->object_path,
				svc->object_interface,
				method_name);
	} else {
		ni_dbus_variant_t argv[16];
		int argc = 0;

		memset(argv, 0, sizeof(argv));
		if (method->call_signature) {
			const char *signature = dbus_message_get_signature(call);

			if (!signature || strcmp(signature, method->call_signature)) {
				/* Call signature mismatch */
				dbus_set_error(&error,
						DBUS_ERROR_INVALID_SIGNATURE,
						"Bad call signature in call to object %s, %s.%s",
						object->object_path,
						svc->object_interface,
						method_name);
				goto error_reply;
			}
			argc = ni_dbus_message_get_args_variants(call, argv, 16);
			if (argc < 0) {
				dbus_set_error(&error,
						DBUS_ERROR_INVALID_ARGS,
						"Bad arguments in call to object %s, %s.%s",
						object->object_path,
						svc->object_interface,
						method_name);
				goto error_reply;
			}
		}

		/* If the object has a refresh function, call it now */
		if (object->functions && object->functions->refresh
		 && !object->functions->refresh(object)) {
			dbus_set_error(&error,
					DBUS_ERROR_FAILED,
					"Failed to refresh object %s",
					object->object_path);
			rv = FALSE;
		} else {
			/* Allocate a reply message */
			reply = dbus_message_new_method_return(call);

			/* Now do the call. */
			rv = method->handler(object, method, argc, argv, reply, &error);
		}

		while (argc--)
			ni_dbus_variant_destroy(&argv[argc]);
	}

	if (!rv) {
error_reply:
		if (reply)
			dbus_message_unref(reply);
		if (!dbus_error_is_set(&error))
			dbus_set_error(&error, DBUS_ERROR_FAILED, "Unexpected error in method call");
		reply = dbus_message_new_error(call, error.name, error.message);
	}

	/* send reply */
	if (ni_dbus_connection_send_message(object->server->connection, reply) < 0)
		ni_error("unable to send reply (out of memory)");

	dbus_error_free(&error);
	if (reply)
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
	ni_dbus_object_t *child;

	ni_dbus_connection_unregister_object(object->server->connection, object);

	ni_string_free(&object->object_name);
	ni_string_free(&object->object_path);
	while ((child = object->children) != NULL) {
		object->children = child->next;
		__ni_dbus_object_free(child);
	}
	free(object->interfaces);
	free(object);
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

static char *
__ni_dbus_server_child_path(const ni_dbus_object_t *parent, const char *name)
{
	unsigned int len;
	char *child_path;

	len = strlen(parent->object_path) + strlen(name) + 2;
	child_path = malloc(len);
	snprintf(child_path, len, "%s/%s", parent->object_path, name);

	return child_path;
}
