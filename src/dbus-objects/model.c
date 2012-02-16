/*
 * DBus generic interfaces for wicked
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

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
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "model.h"
#include "config.h"
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

static const ni_dbus_class_t	ni_objectmodel_netif_list_class;
static ni_dbus_service_t	ni_objectmodel_netif_list_service;
static ni_dbus_service_t	ni_objectmodel_netif_root_interface;

ni_dbus_server_t *		__ni_objectmodel_server;

/*
 * Create the dbus service
 */
ni_dbus_server_t *
ni_objectmodel_create_service(void)
{
	ni_dbus_server_t *server;

	server = ni_server_listen_dbus(WICKED_DBUS_BUS_NAME);
	if (server == NULL)
		ni_fatal("unable to initialize dbus service");

	/* Initialize our addrconf clients */
	ni_objectmodel_dhcp4_init(server);
	ni_objectmodel_autoip_init(server);

	__ni_objectmodel_server = server;
	return server;
}

void
ni_objectmodel_register_all(void)
{
	/* register the netif-list class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(&ni_objectmodel_netif_list_class);

	/* register all netif classes and service */
	ni_objectmodel_register_netif_classes();

	ni_objectmodel_register_service(&ni_objectmodel_netif_list_service);
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

	/* Register com.suse.Wicked.Interface, which is the list of all interfaces */
	object = ni_dbus_server_register_object(server, "Interface",
					&ni_objectmodel_netif_list_class,
					NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for interfaces");

	ni_objectmodel_bind_compatible_interfaces(object);
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
		const ni_dbus_class_t *class;

		/* If the service is compatible with the object's dbus class,
		 * or any of its superclasses, register this interface to this
		 * object */
		for (class = object->class; class; class = class->superclass) {
			if (service->compatible == class) {
				ni_dbus_object_register_service(object, service);
				break;
			}
		}
	}

	return TRUE;
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

/*
 * netif list class
 */

/*
 * The init_child method is needed by the client side when GetManagedObjects
 * returns an interface we haven't heard of before.
 * FIXME: We should really clean this up and use this callback exclusively from
 * GetManagedObjects, to avoid any bad side effects.
 */
static dbus_bool_t
ni_objectmodel_netif_list_init_child(ni_dbus_object_t *object)
{
	static const ni_dbus_class_t *netif_class = NULL;
	ni_interface_t *ifp;

	/* Ugly - should move netif_list stuff to interface.c */
	if (netif_class == NULL) {
		const ni_dbus_service_t *netif_service;

		netif_service = ni_objectmodel_service_by_name(WICKED_DBUS_NETIF_INTERFACE);
		ni_assert(netif_service);

		netif_class = netif_service->compatible;
	}

	ifp = ni_interface_new(NULL, NULL, 0);
	object->class = netif_class;
	object->handle = ifp;

	return TRUE;
}

static const ni_dbus_class_t	ni_objectmodel_netif_list_class = {
	.name		= NI_OBJECTMODEL_NETIF_LIST_CLASS,
	.init_child	= ni_objectmodel_netif_list_init_child,
};


static ni_dbus_service_t	ni_objectmodel_netif_list_service = {
	.name		= WICKED_DBUS_NETIFLIST_INTERFACE,
	.compatible	= &ni_objectmodel_netif_list_class,
//	.methods	= wicked_dbus_netif_methods,
//	.properties	= wicked_dbus_netif_properties,
};

/*
 * The interface for the dbus root node. Nothing much for now.
 */
static ni_dbus_service_t	ni_objectmodel_netif_root_interface = {
	.name		= WICKED_DBUS_INTERFACE,
};

/*
 * Expand the environment of an extension
 * This should probably go with the objectmodel code.
 */
static int
ni_objectmodel_expand_environment(const ni_dbus_object_t *object, const ni_var_array_t *env, ni_process_instance_t *process)
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
		ni_process_instance_setenv(process, var->name, value);

		ni_dbus_variant_destroy(&variant);
	}

	return 0;
}

/*
 * Write dbus message to a temporary file
 */
static char *
__ni_objectmodel_write_message(ni_dbus_message_t *msg, const ni_dbus_method_t *method)
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

	xmlnode = ni_dbus_xml_deserialize_arguments(method, argc, argv, NULL);

	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);

	if (xmlnode == NULL) {
		ni_error("%s: unable to build XML from arguments", method->name);
		return NULL;
	}

	if ((fp = ni_mkstemp(&tempname)) == NULL) {
		ni_error("%s: unable to create tempfile for script arguments", __func__);
	} else {
		if (xml_node_print(xmlnode, fp) < 0) {
			ni_error("%s: unable to store message arguments in file", method->name);
			unlink(tempname);
			ni_string_free(&tempname);
			/* tempname is NULL after this */
		}

		fclose(fp);
	}

	xml_node_free(xmlnode);
	return tempname;
}

static char *
__ni_objectmodel_empty_tempfile(void)
{
	char *tempname = NULL;
	FILE *fp;

	if ((fp = ni_mkstemp(&tempname)) == NULL) {
		ni_error("%s: unable to create tempfile for script arguments", __func__);
		return NULL;
	}

	fclose(fp);
	return tempname;
}

dbus_bool_t
ni_objectmodel_extension_call(ni_dbus_connection_t *connection,
				ni_dbus_object_t *object, const ni_dbus_method_t *method,
				ni_dbus_message_t *call)
{
	DBusError error = DBUS_ERROR_INIT;
	const char *interface = dbus_message_get_interface(call);
	ni_extension_t *extension;
	ni_process_t *command;
	ni_process_instance_t *process;
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
	process = ni_process_instance_new(command);

	ni_objectmodel_expand_environment(object, &extension->environment, process);

	/* Build the argument blob and store it in a file */
	tempname = __ni_objectmodel_write_message(call, method);
	if (tempname != NULL) {
		ni_process_instance_setenv(process, "WICKED_ARGFILE", tempname);
		ni_string_free(&tempname);
	} else {
		dbus_set_error(&error, DBUS_ERROR_INVALID_ARGS,
				"Bad arguments in call to object %s, %s.%s",
				object->path, interface, method->name);
		goto send_error;
	}

	/* Create empty reply for script return data */
	tempname = __ni_objectmodel_empty_tempfile();
	if (tempname != NULL) {
		ni_process_instance_setenv(process, "WICKED_RETFILE", tempname);
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
		ni_process_instance_free(process);
		return FALSE;
	}

	return TRUE;

general_failure:
	dbus_set_error(&error, DBUS_ERROR_FAILED, "%s - general failure when executing method",
			method->name);

send_error:
	ni_dbus_connection_send_error(connection, call, &error);

	if (process)
		ni_process_instance_free(process);

	if (tempname) {
		unlink(tempname);
		free(tempname);
	}
	return FALSE;
}

static dbus_bool_t
ni_objectmodel_extension_completion(ni_dbus_connection_t *connection, const ni_dbus_method_t *method,
				ni_dbus_message_t *call, const ni_process_instance_t *process)
{
	ni_dbus_message_t *reply;
	const char *filename;

	if (ni_process_exit_status_okay(process)) {
		reply = dbus_message_new_method_return(call);
		/* FIXME: if the method returns anything, we need to read it
		 * from the response file */
	} else {
		reply = dbus_message_new_error(call, DBUS_ERROR_FAILED,
				"dbus extension script returns error");
	}

	if (ni_dbus_connection_send_message(connection, reply) < 0)
		ni_error("unable to send reply (out of memory)");

	dbus_message_unref(reply);

	if ((filename = ni_process_instance_getenv(process, "WICKED_ARGFILE")) != NULL) {
		ni_debug_dbus("cleaning up tempfile %s", filename);
		unlink(filename);
	}
	if ((filename = ni_process_instance_getenv(process, "WICKED_RETFILE")) != NULL) {
		ni_debug_dbus("cleaning up tempfile %s", filename);
		unlink(filename);
	}
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

		extension = ni_config_find_extension(ni_global.config, service->name);
		if (extension == NULL)
			continue;

		for (method = service->methods; method->name != NULL; ++method) {
			if (method->handler != NULL)
				continue;
			if (ni_extension_script_find(extension, method->name) != NULL) {
				ni_dbus_method_t *mod_method = (ni_dbus_method_t *) method;

				ni_debug_dbus("registering extension hook for method %s.%s",
						service->name, method->name);
				mod_method->async_handler = ni_objectmodel_extension_call;
				mod_method->async_completion = ni_objectmodel_extension_completion;
			}
		}
	}

	return 0;
}

