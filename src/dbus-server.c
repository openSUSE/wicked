/*
 * Simple DBus server functions
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include "dbus-server.h"
#include "dbus-object.h"
#include "dbus-dict.h"
#include "debug.h"
#include "util_priv.h"


struct ni_dbus_server_object {
	ni_dbus_server_t *	server;			/* back pointer at server */
};

static const ni_dbus_class_t	dbus_root_object_class = {
	.name = "<root>",
};

struct ni_dbus_server {
	ni_dbus_connection_t *	connection;
	ni_dbus_object_t *	root_object;
};

static dbus_bool_t		ni_dbus_object_register_object_manager(ni_dbus_object_t *);
static dbus_bool_t		ni_dbus_object_register_introspectable_interface(ni_dbus_object_t *);
static const char *		__ni_dbus_server_root_path(const char *);
static void			__ni_dbus_server_object_init(ni_dbus_object_t *object, ni_dbus_server_t *server);

/*
 * Constructor for DBus server handle
 */
ni_dbus_server_t *
ni_dbus_server_open(const char *bus_type, const char *bus_name, void *root_object_handle)
{
	ni_dbus_server_t *server;
	ni_dbus_object_t *root;

	ni_debug_dbus("%s(%s)", __FUNCTION__, bus_name);

	server = xcalloc(1, sizeof(*server));
	server->connection = ni_dbus_connection_open(bus_type, bus_name);
	if (server->connection == NULL) {
		ni_dbus_server_free(server);
		return NULL;

	}

	/* Translate bus name foo.bar.baz into object path /foo/bar/baz */
	root = ni_dbus_object_new(&dbus_root_object_class, __ni_dbus_server_root_path(bus_name), root_object_handle);
	__ni_dbus_server_object_init(root, server);
	__ni_dbus_object_insert(&server->root_object, root);

	return server;
}

/*
 * Destructor for DBus server handle
 */
void
ni_dbus_server_free(ni_dbus_server_t *server)
{
	NI_TRACE_ENTER();

	if (server->root_object)
		__ni_dbus_object_free(server->root_object);
	server->root_object = NULL;

	if (server->connection)
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
 * Turn a dbus object into a server side object
 */
static void
__ni_dbus_server_object_init(ni_dbus_object_t *object, ni_dbus_server_t *server)
{
	if (server) {
		if (object->server_object) {
			if (object->server_object->server != server)
				ni_fatal("%s: server object already set", __FUNCTION__);
			return;
		}

		object->server_object = calloc(1, sizeof(ni_dbus_server_object_t));
		object->server_object->server = server;

		if (object->path) {
			ni_dbus_connection_register_object(server->connection, object);
			ni_dbus_object_register_object_manager(object);
			ni_dbus_object_register_introspectable_interface(object);
		}
	}
}

/*
 * Send a signal
 */
dbus_bool_t
ni_dbus_server_send_signal(ni_dbus_server_t *server, ni_dbus_object_t *object,
				const char *interface, const char *signal_name,
				unsigned int nargs, const ni_dbus_variant_t *args)
{
	const ni_dbus_service_t *svc = NULL;
	const ni_dbus_method_t *method;
	DBusError error = DBUS_ERROR_INIT;
	DBusMessage *msg = NULL;
	dbus_bool_t rv = FALSE;

	if (interface) {
		if (!(svc = ni_dbus_object_get_service(object, interface)))
			ni_warn("%s: unknown interface %s", __func__, interface);
	} else {
		svc = ni_dbus_object_get_service_for_signal(object, signal_name);
		if (svc == NULL) {
			ni_error("%s: cannot determine interface name for signal %s",
					__func__, signal_name);
			return FALSE;
		}
		interface = svc->name;
	}

	if (svc && !(method = ni_dbus_service_get_signal(svc, signal_name)))
		ni_warn("%s: unknown signal %s", __func__, signal_name);

	msg = dbus_message_new_signal(object->path, interface, signal_name);
	if (msg == NULL) {
		ni_error("%s: unable to build %s() signal message", __func__, signal_name);
		return FALSE;
	}

	if (nargs && !ni_dbus_message_serialize_variants(msg, nargs, args, &error))
		goto out;

	if (ni_dbus_connection_send_message(server->connection, msg) < 0)
		goto out;

	rv = TRUE;

out:
	if (msg)
		dbus_message_unref(msg);

	return rv;
}

/*
 * When creating an object as a child of a server side object, inherit
 * its server handle.
 */
void
__ni_dbus_server_object_inherit(ni_dbus_object_t *child, const ni_dbus_object_t *parent)
{
	if (parent->server_object)
		__ni_dbus_server_object_init(child, parent->server_object->server);
}

/*
 * When deleting an object, destroy its server handle.
 */
void
__ni_dbus_server_object_destroy(ni_dbus_object_t *object)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(object);

	if (server && object->path)
		ni_dbus_connection_unregister_object(server->connection, object);

	if (object->server_object) {
		free(object->server_object);
		object->server_object = NULL;
	}
}

/*
 * Register an object
 */
ni_dbus_object_t *
ni_dbus_server_register_object(ni_dbus_server_t *server, const char *object_path,
				const ni_dbus_class_t *object_class,
				void *object_handle)
{
	ni_dbus_object_t *object;

	NI_TRACE_ENTER_ARGS("path=%s, handle=%p", object_path, object_handle);
	object = ni_dbus_object_create(server->root_object, object_path, object_class, object_handle);

	return object;
}

/*
 * Support the built-in ObjectManager interface
 */
static const ni_dbus_service_t __ni_dbus_object_manager_interface;
static const ni_dbus_service_t __ni_dbus_object_properties_interface;
static const ni_dbus_service_t __ni_dbus_object_introspectable_interface;
static dbus_bool_t		__ni_dbus_object_manager_enumerate_object(ni_dbus_object_t *,
					ni_dbus_variant_t *dict, DBusError *);

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

dbus_bool_t
ni_dbus_object_register_introspectable_interface(ni_dbus_object_t *object)
{
	return ni_dbus_object_register_service(object, &__ni_dbus_object_introspectable_interface);
}

const ni_dbus_service_t *
ni_dbus_get_standard_service(const char *name)
{
	const ni_dbus_service_t *services[] = {
		&__ni_dbus_object_manager_interface,
		&__ni_dbus_object_properties_interface,
		&__ni_dbus_object_introspectable_interface,

		NULL
	};
	const ni_dbus_service_t *service, **pos;

	for (pos = services; (service = *pos) != NULL; ++pos) {
		if (!strcmp(service->name, name))
			return service;
	}
	return NULL;
}

static dbus_bool_t
__ni_dbus_object_manager_get_managed_objects(ni_dbus_object_t *object,
		const ni_dbus_method_t *method,
		unsigned int argc, const ni_dbus_variant_t *argv,
		ni_dbus_message_t *reply,
		DBusError *error)
{
	ni_dbus_variant_t obj_dict = NI_DBUS_VARIANT_INIT;
	int rv = TRUE;

	NI_TRACE_ENTER_ARGS("path=%s, method=%s", object->path, method->name);

	ni_dbus_variant_init_dict(&obj_dict);
	rv = __ni_dbus_object_manager_enumerate_object(object, &obj_dict, error);
	if (rv)
		rv = ni_dbus_message_serialize_variants(reply, 1, &obj_dict, error);
	ni_dbus_variant_destroy(&obj_dict);

	return rv;
}

static ni_dbus_method_t	__ni_dbus_object_manager_methods[] = {
	{ "GetManagedObjects",	NULL,	.handler = __ni_dbus_object_manager_get_managed_objects },
	{ NULL }
};

static const ni_dbus_service_t __ni_dbus_object_manager_interface = {
	.name = NI_DBUS_INTERFACE ".ObjectManager",
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
				object->path, method->name,
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
				property_name, object->path,
				service? service->name : "*");
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
	const ni_dbus_service_t *service;
	ni_dbus_variant_t dict = NI_DBUS_VARIANT_INIT;
	int rv = TRUE;

	if (!__ni_dbus_object_properties_arg_interface(object, method,
				argv[0].string_value, error, &service))
		return FALSE;

	ni_dbus_variant_init_dict(&dict);
	if (service != NULL) {
		rv = ni_dbus_object_get_properties_as_dict(object, service, &dict, error);
	} else {
		unsigned int i;

		for (i = 0; rv && (service = object->interfaces[i]) != NULL; ++i)
			rv = ni_dbus_object_get_properties_as_dict(object, service, &dict, error);
	}

	if (rv)
		rv = ni_dbus_message_serialize_variants(reply, 1, &dict, error);

	ni_dbus_variant_destroy(&dict);
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

	if (property->get == NULL)
		goto failed;
	if (property->signature) {
		/* Initialize the variant to the specified type. This allows
		 * the property handler to use generic variant_set_int functions
		 * and the like, without having to know exactly which type
		 * is being used. */
		if (!ni_dbus_variant_init_signature(&result, property->signature))
			goto failed;
	}
	if (!property->get(object, property, &result, error))
		return FALSE;

	/* Add variant to reply */
	dbus_message_iter_init_append(reply, &iter);
	if (!ni_dbus_message_iter_append_variant(&iter, &result))
		goto failed;

	ni_dbus_variant_destroy(&result);
	return TRUE;

failed:
	/* the Properties interface should really define some errors... */
	dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting/setting property");
	ni_dbus_variant_destroy(&result);
	return FALSE;
}

static dbus_bool_t
__ni_dbus_object_properties_set(ni_dbus_object_t *object, const ni_dbus_method_t *method,
		unsigned int argc, const ni_dbus_variant_t *argv,
		ni_dbus_message_t *reply, DBusError *error)
{
	const ni_dbus_property_t *property;
	const ni_dbus_service_t *service;
	dbus_bool_t rv;

	if (!__ni_dbus_object_properties_arg_interface(object, method,
				argv[0].string_value, error, &service))
		return FALSE;

	if (!__ni_dbus_object_properties_arg_property(object, method,
				argv[1].string_value, error,
				&service, &property))
		return FALSE;

	ni_debug_dbus("Set %s %s=%s", object->path, property->name,
			ni_dbus_variant_sprint(&argv[2]));

	if (property->update == NULL) {
		dbus_set_error(error,
				DBUS_ERROR_UNKNOWN_METHOD,	/* no error msgs defined */
				"%s: unable to set read-only property %s.%s",
				object->path, service->name,
				property->name);
		return FALSE;
	}

	/* FIXME: Verify variant against property's signature */

	rv = property->update(object, property, &argv[2], error);
	return rv;
}

static ni_dbus_method_t	__ni_dbus_object_properties_methods[] = {
	{ "GetAll",		"s",		.handler = __ni_dbus_object_properties_getall },
	{ "Get",		"ss",		.handler = __ni_dbus_object_properties_get },
	{ "Set",		"ssv",		.handler = __ni_dbus_object_properties_set },
	{ NULL }
};

static const ni_dbus_service_t __ni_dbus_object_properties_interface = {
	.name = NI_DBUS_INTERFACE ".Properties",
	.methods = __ni_dbus_object_properties_methods,
};

static dbus_bool_t
__ni_dbus_object_introspectable_introspect(ni_dbus_object_t *object, const ni_dbus_method_t *method,
		unsigned int argc, const ni_dbus_variant_t *argv,
		ni_dbus_message_t *reply, DBusError *error)
{
	char *data;

	if (!(data = ni_dbus_object_introspect(object))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Failed to introspect object %s", object->path);
		return FALSE;
	}

	ni_dbus_message_append_string(reply, data);
	free(data);
	return TRUE;
}

static ni_dbus_method_t	__ni_dbus_object_introspectable_methods[] = {
	{ "Introspect",		"",		.handler = __ni_dbus_object_introspectable_introspect },
	{ NULL }
};

static const ni_dbus_service_t __ni_dbus_object_introspectable_interface = {
	.name = NI_DBUS_INTERFACE ".Introspectable",
	.methods = __ni_dbus_object_introspectable_methods,
};

dbus_bool_t
__ni_dbus_object_manager_enumerate_object(ni_dbus_object_t *object, ni_dbus_variant_t *obj_dict, DBusError *error)
{
	ni_dbus_object_t *child;
	int rv = TRUE;

	if (object->interfaces) {
		ni_dbus_variant_t *ifdict = ni_dbus_dict_add(obj_dict, object->path);
		const ni_dbus_service_t *service;
		unsigned int i;

		ni_dbus_variant_init_dict(ifdict);
		for (i = 0; rv && (service = object->interfaces[i]) != NULL; ++i) {
			ni_dbus_variant_t *propdict = ni_dbus_dict_add(ifdict, service->name);

			ni_dbus_variant_init_dict(propdict);
			rv = ni_dbus_object_get_properties_as_dict(object, service, propdict, error);
		}
	}

	for (child = object->children; child && rv; child = child->next) {
		/* If the object has a refresh function, call it now.
		 * Note that the server method call handling code will
		 * already have refreshed the top-level object, so we will
		 * only refresh the children here.
		 */
		if (child->class && child->class->refresh
		 && !child->class->refresh(object)) {
			rv = FALSE;
			continue;
		}

		rv = __ni_dbus_object_manager_enumerate_object(child, obj_dict, error);
	}

	return rv;
}

/*
 * Object callbacks from dbus dispatcher
 */
static void
__ni_dbus_object_unregister(DBusConnection *conn, void *user_data)
{
	ni_dbus_object_t *object = user_data;

	NI_TRACE_ENTER_ARGS("path=%s, handle=%p", object->path, object->handle);
	if (object->handle) {
		const ni_dbus_class_t *class;

		for (class = object->class; class; class = class->superclass) {
			if (class->destroy) {
				class->destroy(object);
				break;
			}
		}
		object->handle = NULL;
	}
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
	ni_dbus_server_t *server;
	dbus_bool_t rv = FALSE;

	/* Clean out deceased objects */
	ni_dbus_objects_garbage_collect();

	if (dbus_message_get_type(call) != DBUS_MESSAGE_TYPE_METHOD_CALL
	 || interface == NULL
	 || method_name == NULL) {
		ni_error("%s: internal error, bad message", __func__);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	ni_debug_dbus("%s(path=%s, interface=%s, method=%s) called", __FUNCTION__, object->path, interface, method_name);
	svc = ni_dbus_object_get_service(object, interface);
	if (svc == NULL) {
		ni_debug_dbus("Unsupported service %s on object %s", interface, object->path);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	server = ni_dbus_object_get_server(object);

	method = ni_dbus_service_get_method(svc, method_name);
	if (method == NULL
	 || (!method->handler && !method->handler_ex && !method->async_handler)) {
		dbus_set_error(&error,
				DBUS_ERROR_UNKNOWN_METHOD,
				"Unknown method in call to object %s, %s.%s",
				object->path,
				svc->name,
				method_name);
	} else {
		ni_dbus_variant_t argv[16];
		uid_t caller_uid = -1;
		int argc = 0;

		memset(argv, 0, sizeof(argv));
		if (method->call_signature) {
			const char *signature = dbus_message_get_signature(call);

			if (!signature || strcmp(signature, method->call_signature)) {
				/* Call signature mismatch */
				ni_debug_dbus("Mismatched call signature; expect=%s; got=%s",
						method->call_signature, signature);
				dbus_set_error(&error,
						DBUS_ERROR_INVALID_SIGNATURE,
						"Bad call signature in call to object %s, %s.%s",
						object->path,
						svc->name,
						method_name);
				goto error_reply;
			}
		}

		/* If the object has a refresh function, call it now */
		if (object->class && object->class->refresh
		 && !object->class->refresh(object)) {
			dbus_set_error(&error,
					DBUS_ERROR_FAILED,
					"Failed to refresh object %s",
					object->path);
			goto error_reply;
		}

		if (method->handler_ex) {
			int err;

			err = ni_dbus_object_get_caller_uid(object, call, &caller_uid);
			if (err < 0) {
				ni_dbus_set_error_from_code(&error, err, "unable to get caller's uid");
				goto error_reply;
			}
		}

		if (method->handler || method->handler_ex) {
			/* Deserialize dbus message */
			argc = ni_dbus_message_get_args_variants(call, argv, 16);
			if (argc < 0) {
				dbus_set_error(&error,
						DBUS_ERROR_INVALID_ARGS,
						"Bad arguments in call to object %s, %s.%s",
						object->path,
						svc->name,
						method_name);
				goto error_reply;
			}

			/* Allocate a reply message */
			reply = dbus_message_new_method_return(call);

			/* Now do the call. */
			if (method->handler_ex) {
				rv = method->handler_ex(object, method, argc, argv, caller_uid, reply, &error);
			} else {
				rv = method->handler(object, method, argc, argv, reply, &error);
			}

			/* Beware, object may be gone after this! */
			object = NULL;

			while (argc--)
				ni_dbus_variant_destroy(&argv[argc]);
		} else
		if (method->async_handler) {
			rv = method->async_handler(server->connection, object, method, call);
		} else {
			dbus_set_error(&error, DBUS_ERROR_FAILED, "No server side handler for method");
			rv = FALSE;
		}
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
	if (reply && ni_dbus_connection_send_message(server->connection, reply) < 0)
		ni_error("unable to send reply (out of memory)");

	dbus_error_free(&error);
	if (reply)
		dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;


}

/*
 * Helper functions
 */
ni_dbus_server_t *
ni_dbus_object_get_server(const ni_dbus_object_t *object)
{
	ni_dbus_server_object_t *sob = object->server_object;

	return sob? sob->server : NULL;
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

int
ni_dbus_object_get_caller_uid(const ni_dbus_object_t *object, ni_dbus_message_t *call, uid_t *uidp)
{
	ni_dbus_server_t *server;

	if ((server = ni_dbus_object_get_server(object)) == NULL)
		return -NI_ERROR_INVALID_ARGS;

	return ni_dbus_connection_get_caller_uid(server->connection, dbus_message_get_sender(call), uidp);
}

/*
 * Find an object given its internal handle
 */
ni_dbus_object_t *
ni_dbus_server_find_object_by_handle(ni_dbus_server_t *server, const void *object_handle)
{
	return ni_dbus_object_find_descendant_by_handle(server->root_object, object_handle);
}

/*
 * Unregister all dbus objects for a given C object
 */
dbus_bool_t
__ni_dbus_server_unregister_object(ni_dbus_object_t *parent, void *object_handle)
{
	ni_dbus_object_t **pos, *object;
	dbus_bool_t rv = FALSE;

	for (pos = &parent->children; (object = *pos) != NULL; ) {
		if (object->handle != object_handle) {
			if (__ni_dbus_server_unregister_object(object, object_handle))
				rv = TRUE;
			pos = &object->next;
		} else {
			__ni_dbus_server_object_destroy(object);
			ni_dbus_object_free(object);
			rv = TRUE;
		}
	}
	return rv;
}

dbus_bool_t
ni_dbus_server_unregister_object(ni_dbus_server_t *server, void *object_handle)
{
	return __ni_dbus_server_unregister_object(server->root_object, object_handle);
}

/*
 * Translate bus name foo.bar.baz into object path /foo/bar/baz
 */
static const char *
__ni_dbus_server_root_path(const char *bus_name)
{
	static char root_path[256];
	unsigned int i, len;

	len = strlen(bus_name) + 2;
	if (len >= sizeof(root_path))
		ni_fatal("%s: bus name too long (%s)", __FUNCTION__, bus_name);

	root_path[0] = '/';
	for (i = 1; *bus_name != '\0'; ) {
		char cc = *bus_name++;

		if (cc == '.')
			cc = '/';
		root_path[i++] = cc;
	}
	root_path[i] = '\0';
	ni_assert(i < len);

	return root_path;
}
