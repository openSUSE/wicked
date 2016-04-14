/*
 * DBus generic interfaces for wicked
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/xml.h>
#include <wicked/dbus-errors.h>
#include "util_priv.h"
#include "dbus-common.h"
#include "xml-schema.h"
#include "model.h"
#include "appconfig.h"
#include "debug.h"
#include "dbus-connection.h"
#include "process.h"

extern ni_dbus_object_t *	ni_objectmodel_new_interface(ni_dbus_server_t *server,
					const ni_dbus_service_t *service,
					const ni_dbus_variant_t *dict, DBusError *error);

#define NI_DBUS_SERVICES_MAX	128
typedef struct ni_dbus_service_array {
	unsigned int		count;
	const ni_dbus_service_t *services[NI_DBUS_SERVICES_MAX];
} ni_dbus_service_array_t;

#define NI_DBUS_CLASSES_MAX	1024
typedef struct ni_dbus_class_array {
	unsigned int		count;
	const ni_dbus_class_t *	class[NI_DBUS_CLASSES_MAX];
} ni_dbus_class_array_t;

static ni_dbus_class_array_t	ni_objectmodel_class_registry;
static ni_dbus_service_array_t	ni_objectmodel_service_registry;

static ni_dbus_service_t	ni_objectmodel_netif_root_interface;

ni_dbus_server_t *		__ni_objectmodel_server;
ni_xs_scope_t *			__ni_objectmodel_schema;

/*
 * Create the dbus service
 */
ni_dbus_server_t *
ni_objectmodel_create_service(void)
{
	ni_dbus_server_t *server;

	server = ni_server_listen_dbus(NI_OBJECTMODEL_DBUS_BUS_NAME);
	if (server == NULL)
		ni_fatal("unable to initialize dbus service");

	__ni_objectmodel_server = server;
	return server;
}

/*
 * Initialize the objectmodel.
 * If server is non-NULL, we perform some server-side initialization,
 * such as creating the object hierarchy.
 */
ni_xs_scope_t *
ni_objectmodel_init(ni_dbus_server_t *server)
{
	if (__ni_objectmodel_schema == NULL) {
		__ni_objectmodel_schema = ni_server_dbus_xml_schema();
		if (__ni_objectmodel_schema == NULL)
			ni_fatal("Giving up.");

		/* Register all built-in classes and services */
		ni_objectmodel_register_all();

		/* Register/amend all services defined in the schema */
		ni_dbus_xml_register_services(__ni_objectmodel_schema);

		/* If we're the server, create the initial objects of the
		 * server-side object hierarchy.
		 * Also, register any netif naming services specified in
		 * the config file.
		 */
		if (server) {
			ni_objectmodel_create_initial_objects(server);

			ni_objectmodel_register_ns_dynamic();
		}

		/* Bind all extensions */
		ni_objectmodel_bind_extensions();
	}

	return __ni_objectmodel_schema;
}

void
ni_objectmodel_register_all(void)
{
	/* register all netif classes and service */
	ni_objectmodel_register_netif_classes();
	ni_objectmodel_register_netif_services();
#ifdef MODEM
	ni_objectmodel_register_modem_classes();
	ni_objectmodel_register_modem_services();
#endif
	ni_objectmodel_register_addrconf_classes();
}

/*
 * Create the initial object hierarchy
 */
dbus_bool_t
ni_objectmodel_create_initial_objects(ni_dbus_server_t *server)
{
	ni_dbus_object_t *object;

	/* Register root interface with the root of the object hierarchy */
	object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_register_service(object, &ni_objectmodel_netif_root_interface);

	ni_objectmodel_create_netif_list(server);
#ifdef MODEM
	ni_objectmodel_create_modem_list(server);
#endif
	return TRUE;
}

dbus_bool_t
ni_objectmodel_bind_compatible_interfaces(ni_dbus_object_t *object)
{
	unsigned int i;

	if (object->class == NULL) {
		ni_error("%s: object \"%s\" without class", __func__, object->path);
		return FALSE;
	}

	NI_TRACE_ENTER_ARGS("object=%s, class=%s", object->path, object->class->name);
	for (i = 0; i < ni_objectmodel_service_registry.count; ++i) {
		const ni_dbus_service_t *service = ni_objectmodel_service_registry.services[i];

		/* If the service is compatible with the object's dbus class,
		 * or any of its superclasses, register this interface to this
		 * object */
		if (ni_dbus_object_isa(object, service->compatible))
			ni_dbus_object_register_service(object, service);
	}

	return TRUE;
}

unsigned int
ni_objectmodel_compatible_services_for_class(const ni_dbus_class_t *query_class,
		const ni_dbus_service_t **list, unsigned int max)
{
	unsigned int i, count;

	for (i = count = 0; i < ni_objectmodel_service_registry.count; ++i) {
		const ni_dbus_service_t *service = ni_objectmodel_service_registry.services[i];
		const ni_dbus_class_t *class;

		/* If the service is compatible with the object's dbus class,
		 * or any of its superclasses, register this interface to this
		 * object */
		for (class = query_class; class; class = class->superclass) {
			if (service->compatible == class) {
				if (count < max)
					list[count++] = service;
				break;
			}
		}
	}

	return count;
}

/*
 * objectmodel service registry
 */
void
ni_objectmodel_register_service(const ni_dbus_service_t *service)
{
	unsigned int index = ni_objectmodel_service_registry.count;

	ni_assert(index < NI_DBUS_SERVICES_MAX);

	ni_objectmodel_service_registry.services[index++] = service;
	ni_objectmodel_service_registry.count = index;
}

const ni_dbus_service_t *
ni_objectmodel_service_by_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < ni_objectmodel_service_registry.count; ++i) {
		const ni_dbus_service_t *service = ni_objectmodel_service_registry.services[i];

		if (!strcmp(service->name, name))
			return service;
	}

	return NULL;
}

const ni_dbus_service_t *
ni_objectmodel_service_by_class(const ni_dbus_class_t *class)
{
	unsigned int i;

	for (i = 0; i < ni_objectmodel_service_registry.count; ++i) {
		const ni_dbus_service_t *service = ni_objectmodel_service_registry.services[i];

		if (service->compatible == class)
			return service;
	}

	return NULL;
}

const ni_dbus_service_t *
ni_objectmodel_service_by_tag(const char *tag)
{
	unsigned int i;

	for (i = 0; i < ni_objectmodel_service_registry.count; ++i) {
		const ni_dbus_service_t *service = ni_objectmodel_service_registry.services[i];
		const ni_xs_service_t *xs_service;

		if ((xs_service = service->schema) != NULL
		 && ni_string_eq(xs_service->name, tag))
			return service;
	}

	return NULL;
}

const ni_dbus_service_t *
ni_objectmodel_factory_service(const ni_dbus_service_t *service)
{
	const ni_xs_service_t *xs_service;
	const char *factory_name = NULL;
	char namebuf[256];

	/* See if the schema specifies a factory service explicitly */
	if ((xs_service = service->schema) != NULL) {
		const ni_var_t *attr;

		attr = ni_var_array_get(&xs_service->attributes, "factory");
		if (attr)
			factory_name = attr->value;
	}
	
	/* If not, the default is to append ".Factory" to the service name */
	if (factory_name == NULL) {
		snprintf(namebuf, sizeof(namebuf), "%s.Factory", service->name);
		factory_name = namebuf;
	}

	return ni_objectmodel_service_by_name(factory_name);
}

const ni_dbus_service_t *
ni_objectmodel_auth_service(const ni_dbus_service_t *service)
{
	const ni_xs_service_t *xs_service;
	const char *auth_name = NULL;
	char namebuf[256];

	/* See if the schema specifies a auth service explicitly */
	if ((xs_service = service->schema) != NULL) {
		const ni_var_t *attr;

		attr = ni_var_array_get(&xs_service->attributes, "auth");
		if (attr)
			auth_name = attr->value;
	}
	
	/* If not, the default is to append ".Auth" to the service name */
	if (auth_name == NULL) {
		snprintf(namebuf, sizeof(namebuf), "%s.Auth", service->name);
		auth_name = namebuf;
	}

	return ni_objectmodel_service_by_name(auth_name);
}

/*
 * objectmodel service registry
 * This is mostly needed for doing proper type checking when binding
 * extensions
 */
void
ni_objectmodel_register_class(const ni_dbus_class_t *class)
{
	unsigned int index = ni_objectmodel_class_registry.count;

	ni_assert(class->name);
	ni_assert(index < NI_DBUS_CLASSES_MAX);

	ni_objectmodel_class_registry.class[index++] = class;
	ni_objectmodel_class_registry.count = index;
}

const ni_dbus_class_t *
ni_objectmodel_get_class(const char *name)
{
	unsigned int i;

	for (i = 0; i < ni_objectmodel_class_registry.count; ++i) {
		const ni_dbus_class_t *class = ni_objectmodel_class_registry.class[i];

		if (!strcmp(class->name, name))
			return class;
	}
	return NULL;
}

ni_dbus_class_t *
ni_objectmodel_class_new(const char *classname, const ni_dbus_class_t *base_class)
{
	ni_dbus_class_t *new_class;

	/* Create the new class */
	new_class = xcalloc(1, sizeof(*new_class));
	ni_string_dup(&new_class->name, classname);
	new_class->superclass = base_class;

	/* inherit all methods from netif */
	new_class->list = base_class->list;
	new_class->destroy = base_class->destroy;
	new_class->refresh = base_class->refresh;

	return new_class;
}

/*
 * Do an object lookup using the full path
 */
ni_dbus_object_t *
ni_objectmodel_object_by_path(const char *path)
{
	ni_dbus_object_t *root;

	if (!__ni_objectmodel_server || !path)
		return NULL;

	root = ni_dbus_server_get_root_object(__ni_objectmodel_server);
	if (path[0] == '/' && !(path = ni_dbus_object_get_relative_path(root, path)))
		return NULL;

	return ni_dbus_object_lookup(root, path);
}

/*
 * Send out an event (not associated with a network device or other object)
 */
dbus_bool_t
ni_objectmodel_other_event(ni_dbus_server_t *server, ni_event_t event, const ni_uuid_t *uuid)
{
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	const char *signal_name = NULL;
	unsigned int argc = 0;

	if (!(signal_name = ni_objectmodel_event_to_signal(event)))
		return FALSE;

	if (!server && !(server = __ni_objectmodel_server)) {
		ni_error("%s: help! No dbus server handle! Cannot send signal.", __func__);
		return FALSE;
	}

	if (uuid) {
		ni_dbus_variant_set_uuid(&arg, uuid);
		argc++;
	}

	ni_debug_dbus("sending event \"%s\"", signal_name);
	ni_dbus_server_send_signal(server,
				ni_dbus_server_get_root_object(server),
				ni_objectmodel_netif_root_interface.name,
				signal_name, argc, &arg);

	ni_dbus_variant_destroy(&arg);
	return TRUE;
}

/*
 * The interface for the dbus root node. Nothing much for now.
 */
static ni_dbus_method_t		ni_objectmodel_netif_root_signals[] = {
	{ "resolverUpdated",	"",		NULL },
	{ "hostnameUpdated",	"",		NULL },
	{ "genericUpdated",	"",		NULL },

	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_netif_root_interface = {
	.name		= NI_OBJECTMODEL_INTERFACE,
	.signals	= ni_objectmodel_netif_root_signals,
};

/*
 * Expand the environment of an extension
 * This should probably go with the objectmodel code.
 */
static int
ni_objectmodel_expand_environment(const ni_dbus_object_t *object, const ni_var_array_t *env, ni_process_t *process)
{
	const ni_var_t *var;
	unsigned int i;

	for (i = 0, var = env->data; i < env->count; ++i, ++var) {
		ni_dbus_variant_t variant = NI_DBUS_VARIANT_INIT;
		const char *value = var->value;

		if (!strcmp(value, "$object-path")) {
			value = object->path;
		} else if (!strncmp(value, "$property:", 10)) {
			if (ni_dbus_object_get_property(object, value + 10, NULL, &variant)) {
				value = ni_dbus_variant_sprint(&variant);
			}
		} else if (value[0] == '$') {
			ni_error("%s: unable to expand environment variable %s=\"%s\"",
					object->path, var->name, var->value);
			return -1;
		}

		ni_debug_dbus("%s: expanded %s=%s -> \"%s\"", object->path, var->name, var->value, value);
		ni_process_setenv(process, var->name, value);

		ni_dbus_variant_destroy(&variant);
	}

	return 0;
}

/*
 * Write dbus message to a temporary file
 */
static char *
__ni_objectmodel_write_message(ni_dbus_message_t *msg, const ni_dbus_method_t *method, ni_tempstate_t *temp_state)
{
	ni_dbus_variant_t argv[16];
	char *tempname = NULL;
	xml_node_t *xmlnode;
	int argc = 0;
	FILE *fp;

	/* Deserialize dbus message */
	memset(argv, 0, sizeof(argv));
	argc = ni_dbus_message_get_args_variants(msg, argv, 16);
	if (argc < 0)
		return NULL;

	xmlnode = ni_dbus_xml_deserialize_arguments(method, argc, argv, NULL, temp_state);

	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);

	if (xmlnode == NULL) {
		ni_error("%s: unable to build XML from arguments", method->name);
		return NULL;
	}

	if ((fp = ni_mkstemp(&tempname)) == NULL) {
		ni_error("%s: unable to create tempfile for script arguments", __func__);
	} else {
		/* Add file to tempstate; it will be deleted when we destroy the process handle */
		ni_tempstate_add_file(temp_state, tempname);
		if (xml_node_print(xmlnode, fp) < 0) {
			ni_error("%s: unable to store message arguments in file", method->name);
			ni_string_free(&tempname); /* tempname is NULL after this */
		}

		fclose(fp);
	}

	xml_node_free(xmlnode);
	return tempname;
}

static char *
__ni_objectmodel_empty_tempfile(ni_tempstate_t *temp_state)
{
	char *tempname = NULL;
	FILE *fp;

	if ((fp = ni_mkstemp(&tempname)) == NULL) {
		ni_error("%s: unable to create tempfile for script arguments", __func__);
		return NULL;
	}

	fclose(fp);

	/* Add file to tempstate; it will be deleted when we destroy the process handle */
	ni_tempstate_add_file(temp_state, tempname);
	return tempname;
}

dbus_bool_t
ni_objectmodel_extension_call(ni_dbus_connection_t *connection,
				ni_dbus_object_t *object, const ni_dbus_method_t *method,
				ni_dbus_message_t *call)
{
	DBusError error = DBUS_ERROR_INIT;
	const char *interface = dbus_message_get_interface(call);
	ni_tempstate_t *temp_state = NULL;
	ni_extension_t *extension;
	ni_shellcmd_t *command;
	ni_process_t *process;
	char *tempname = NULL;

	NI_TRACE_ENTER_ARGS("object=%s, interface=%s, method=%s", object->path, interface, method->name);

	extension = ni_config_find_extension(ni_global.config, interface);
	if (extension == NULL) {
		dbus_set_error(&error, DBUS_ERROR_SERVICE_UNKNOWN, "%s: no/unknown interface %s",
				__func__, interface);
		ni_dbus_connection_send_error(connection, call, &error);
		return FALSE;
	}

	if ((command = ni_extension_script_find(extension, method->name)) == NULL) {
		dbus_set_error(&error, DBUS_ERROR_FAILED, "%s: no/unknown extension method %s",
				__func__, method->name);
		ni_dbus_connection_send_error(connection, call, &error);
		return FALSE;
	}

	ni_debug_extension("preparing to run extension script \"%s\"", command->command);

	/* Create an instance of this command */
	process = ni_process_new(command);

	ni_objectmodel_expand_environment(object, &extension->environment, process);
	temp_state = ni_process_tempstate(process);

	/* Build the argument blob and store it in a file */
	tempname = __ni_objectmodel_write_message(call, method, temp_state);
	if (tempname != NULL) {
		ni_process_setenv(process, "WICKED_ARGFILE", tempname);
		ni_string_free(&tempname);
	} else {
		dbus_set_error(&error, DBUS_ERROR_INVALID_ARGS,
				"Bad arguments in call to object %s, %s.%s",
				object->path, interface, method->name);
		goto send_error;
	}

	/* Create empty reply for script return data */
	tempname = __ni_objectmodel_empty_tempfile(temp_state);
	if (tempname != NULL) {
		ni_process_setenv(process, "WICKED_RETFILE", tempname);
		ni_string_free(&tempname);
	} else {
		goto general_failure;
	}

	/* Run the process */
	if (ni_dbus_async_server_call_run_command(connection, object, method, call, process) < 0) {
		ni_error("%s: error executing method %s", __func__, method->name);
		dbus_set_error(&error, DBUS_ERROR_FAILED, "%s: error executing method %s",
				__func__, method->name);
		ni_dbus_connection_send_error(connection, call, &error);
		ni_process_free(process);
		return FALSE;
	}

	return TRUE;

general_failure:
	dbus_set_error(&error, DBUS_ERROR_FAILED, "%s - general failure when executing method",
			method->name);

send_error:
	ni_dbus_connection_send_error(connection, call, &error);

	if (process)
		ni_process_free(process);

	return FALSE;
}

static dbus_bool_t
ni_objectmodel_extension_completion(ni_dbus_connection_t *connection, const ni_dbus_method_t *method,
				ni_dbus_message_t *call, const ni_process_t *process)
{
	const char *interface_name = dbus_message_get_interface(call);
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_message_t *reply;
	const char *filename;
	xml_document_t *doc = NULL;

	if ((filename = ni_process_getenv(process, "WICKED_RETFILE")) != NULL) {
		if (!(doc = xml_document_read(filename)))
			ni_error("%s.%s: failed to parse return data",
					interface_name, method->name);
	}

	if (ni_process_exit_status_okay(process)) {
		ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
		xml_node_t *retnode = NULL;
		int nres;

		/* if the method returns anything, read it from the response file
		 * and encode it. */
		if (doc == NULL
		 || (retnode = xml_node_get_child(xml_document_root(doc), "return")) == NULL) {
			nres = 0;
		} else if ((nres = ni_dbus_serialize_return(method, &result, retnode)) < 0) {
			dbus_set_error(&error, NI_DBUS_ERROR_CANNOT_MARSHAL,
					"%s.%s: unable to serialize returned data",
					interface_name, method->name);
			ni_dbus_variant_destroy(&result);
			goto send_error;
		}

		/* Build the response message */
		reply = dbus_message_new_method_return(call);
		if (!ni_dbus_message_serialize_variants(reply, nres, &result, &error)) {
			ni_dbus_variant_destroy(&result);
			dbus_message_unref(reply);
			goto send_error;
		}
		ni_dbus_variant_destroy(&result);
	} else {
		xml_node_t *errnode = NULL;

		if (doc != NULL)
			errnode = xml_node_get_child(xml_document_root(doc), "error");

		if (errnode)
			ni_dbus_serialize_error(&error, errnode);
		else
			dbus_set_error(&error, DBUS_ERROR_FAILED, "dbus extension script returns error");

send_error:
		reply = dbus_message_new_error(call, error.name, error.message);
	}

	if (ni_dbus_connection_send_message(connection, reply) < 0)
		ni_error("unable to send reply (out of memory)");

	dbus_message_unref(reply);
	return TRUE;
}

/*
 * Bind extension scripts to the interface functions they are specified for.
 */
int
ni_objectmodel_bind_extensions(void)
{
	unsigned int i;

	NI_TRACE_ENTER();
	for (i = 0; i < ni_objectmodel_service_registry.count; ++i) {
		const ni_dbus_service_t *service = ni_objectmodel_service_registry.services[i];
		const ni_dbus_method_t *method;
		ni_extension_t *extension;
		const ni_c_binding_t *binding;

		extension = ni_config_find_extension(ni_global.config, service->name);
		if (extension == NULL)
			continue;

		for (method = service->methods; method && method->name != NULL; ++method) {
			ni_dbus_method_t *mod_method = (ni_dbus_method_t *) method;

			if (method->handler != NULL)
				continue;
			if (ni_extension_script_find(extension, method->name) != NULL) {
				ni_debug_dbus("binding method %s.%s to external command",
						service->name, method->name);
				mod_method->async_handler = ni_objectmodel_extension_call;
				mod_method->async_completion = ni_objectmodel_extension_completion;
			} else
			if ((binding = ni_extension_find_c_binding(extension, method->name)) != NULL) {
				void *addr;

				if ((addr = ni_c_binding_get_address(binding)) == NULL) {
					ni_error("cannot bind method %s.%s - invalid C binding",
							service->name, method->name);
					continue;
				}

				ni_debug_dbus("binding method %s.%s to builtin %s",
						service->name, method->name, binding->symbol);
				mod_method->handler = addr;
			}
		}

		/* Bind the properties table if we have one */
		if ((binding = ni_extension_find_c_binding(extension, "__properties")) != NULL) {
			ni_dbus_service_t *mod_service = ((ni_dbus_service_t *) service);
			void *addr;

			if ((addr = ni_c_binding_get_address(binding)) == NULL) {
				ni_error("cannot bind %s properties - invalid C binding",
						service->name);
			} else {
				mod_service->properties = addr;
			}
		}

	}

	return 0;
}

static dbus_bool_t
set_bind_netdev_ref_index_error(const char *ifname, const char *hint,
				ni_netdev_ref_t *device, DBusError *error,
				const char *reason)
{
	if (!error)
		return FALSE;
	dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
			"%s%sUnable to bind %s%sdevice %s%sindex: %s",
			ifname ? ifname : "", ifname ? ":" : "",
			hint ? hint : "", hint ? " " : "",
			device && device->name ? ni_print_suspect(device->name, 15) : "",
			device && device->name ? " " : "", reason);
	return FALSE;
}

dbus_bool_t
ni_objectmodel_bind_netdev_ref_index(const char *ifname, const char *hint,
				ni_netdev_ref_t *device, ni_netconfig_t *nc,
				DBusError *error)
{
	if (!ifname || !device || ni_string_empty(device->name))
		return set_bind_netdev_ref_index_error(ifname, hint, device,
				error, "incomplete arguments");

	if (ni_string_eq(ifname, device->name))
		return set_bind_netdev_ref_index_error(ifname, hint, device,
				error, "invalid self-reference");

	if (!ni_netdev_name_is_valid(device->name))
		return set_bind_netdev_ref_index_error(ifname, hint, device,
				error, "suspect device name");

	if (!ni_netdev_ref_bind_ifindex(device, nc))
		return set_bind_netdev_ref_index_error(ifname, hint, device,
				error, "device does not exist");

	return TRUE;
}

