/*
 * No REST for the wicked!
 *
 * Client-side functions for calling the wicked server.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/xml.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>

#include "client/wicked-client.h"

/*
 * Error context - this is an opaque type.
 */
struct ni_call_error_context {
	ni_call_error_handler_t *handler;
	xml_node_t *		config;
	xml_node_t *		__allocated;
};
#define NI_CALL_ERROR_CONTEXT_INIT(func, node) \
		{ .handler = func, .config = node, .__allocated = NULL }

static void	ni_call_error_context_destroy(ni_call_error_context_t *);

/*
 * Create the client and return the handle of the root object
 */
ni_dbus_object_t *
ni_call_create_client(void)
{
	static ni_dbus_object_t *root_object = NULL;

	if (root_object == NULL) {
		ni_dbus_client_t *client;

		ni_objectmodel_init(NULL);

		/* Use ni_objectmodel_create_client() */
		client = ni_create_dbus_client(WICKED_DBUS_BUS_NAME);
		if (!client)
			ni_fatal("Unable to connect to wicked dbus service");

		root_object = ni_dbus_client_object_new(client,
					&ni_dbus_anonymous_class,
					WICKED_DBUS_OBJECT_PATH,
					WICKED_DBUS_INTERFACE,
					NULL);
	}

	return root_object;
}

/*
 * Get the dbus interface for a given link layer type
 */
const ni_dbus_service_t *
ni_call_link_layer_service(const char *link_type)
{
	ni_iftype_t iftype;
	const char *classname;
	const ni_dbus_class_t *class;
	const ni_dbus_service_t *service;

	iftype = ni_linktype_name_to_type(link_type);
	if ((classname = ni_objectmodel_link_classname(iftype)) == NULL
	 || !(class = ni_objectmodel_get_class(classname))) {
		ni_error("no dbus class for link layer \"%s\"", link_type);
		return NULL;
	}

	/* See if there's a service for this link layer class. Note that
	 * ni_objectmodel_service_by_class may return a service for a
	 * base class (such as for netif), which we're not interested in.
	 */
	if (!(service = ni_objectmodel_service_by_class(class))) {
		ni_debug_dbus("no dbus service for link layer \"%s\"", link_type);
		return NULL;
	}

	return service;
}

/*
 * Get the factory interface for a given link layer type
 */
const ni_dbus_service_t *
ni_call_link_layer_factory_service(const char *link_type)
{
	char namebuf[256];
	const ni_dbus_service_t *service;

	if (!(service = ni_call_link_layer_service(link_type)))
		return NULL;

	snprintf(namebuf, sizeof(namebuf), "%s.Factory", service->name);
	if (!(service = ni_objectmodel_service_by_name(namebuf))) {
		ni_debug_dbus("no dbus factory service for link layer \"%s\"", link_type);
		return NULL;
	}

	if (!ni_dbus_service_get_method(service, "newLink")) {
		ni_debug_dbus("dbus factory service for link layer \"%s\" has no newLink method", link_type);
		return NULL;
	}

	return service;
}

/*
 * Get the authentication service for a given link layer type
 */
const ni_dbus_service_t *
ni_call_link_layer_auth_service(const char *link_type)
{
	char namebuf[256];
	const ni_dbus_service_t *service;

	if (!(service = ni_call_link_layer_service(link_type)))
		return NULL;

	snprintf(namebuf, sizeof(namebuf), "%s.Auth", service->name);
	if (!(service = ni_objectmodel_service_by_name(namebuf))) {
		ni_debug_dbus("no dbus auth service for link layer \"%s\"", link_type);
		return NULL;
	}

	if (!ni_dbus_service_get_method(service, "login")) {
		ni_debug_dbus("dbus auth service for link layer \"%s\" has no login method", link_type);
		return NULL;
	}

	return service;
}

/*
 * Create a virtual network interface
 */
static char *
ni_call_link_new(const ni_dbus_service_t *service, ni_dbus_variant_t call_argv[2])
{
	ni_dbus_variant_t call_resp[1];
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_object_t *object = NULL;
	char *result = NULL;

	memset(call_resp, 0, sizeof(call_resp));
	if (!(object = wicked_get_interface_object(service->name))) {
		ni_error("unable to create proxy object for %s", service->name);
		goto failed;
	}

	if (!ni_dbus_object_call_variant(object, service->name, "newLink",
				2, call_argv,
				1, call_resp,
				&error)) {
		ni_error("Server refused to create interface. Server responds:");
		ni_error_extra("%s: %s", error.name, error.message);
	} else {
		const char *response;

		/* extract device object path from reply */
		if (!ni_dbus_variant_get_string(&call_resp[0], &response)) {
			ni_error("%s: newLink call succeeded but didn't return interface name",
					service->name);
		} else {
			ni_string_dup(&result, response);
		}
	}

failed:
	ni_dbus_variant_destroy(&call_resp[0]);
	dbus_error_free(&error);
	return result;
}

char *
ni_call_link_new_argv(const ni_dbus_service_t *service, int argc, char **argv)
{
	ni_dbus_variant_t call_argv[2], *dict;
	char *result = NULL;
	int i, j;

	memset(call_argv, 0, sizeof(call_argv));

	/* The first argument of the newLink() call is the requested interface
	 * name. If there's a name="..." argument on the command line, use that
	 * (and remove it from the list of arguments) */
	ni_dbus_variant_set_string(&call_argv[0], "");
	for (i = j = 0; i < argc; ++i) {
		char *arg = argv[i];

		if (!strncmp(arg, "name=", 5)) {
			ni_dbus_variant_set_string(&call_argv[0], arg + 5);
			--argc;
		} else {
			argv[j++] = arg;
		}
	}

	/* NOTE: This doesn't work right now */
	dict = &call_argv[1];
	ni_dbus_variant_init_dict(dict);
	if (!ni_call_properties_from_argv(service, dict, argc, argv)) {
		ni_error("Error parsing properties");
		goto failed;
	}

	result = ni_call_link_new(service, call_argv);

failed:
	ni_dbus_variant_destroy(&call_argv[0]);
	ni_dbus_variant_destroy(&call_argv[1]);
	return result;
}

char *
ni_call_link_new_xml(const ni_dbus_service_t *service,
				const char *ifname, xml_node_t *linkdef)
{
	ni_dbus_variant_t call_argv[2];
	const ni_dbus_method_t *method;
	char *result = NULL;

	memset(call_argv, 0, sizeof(call_argv));

	/* The first argument of the newLink() call is the requested interface
	 * name. If there's a name="..." argument on the command line, use that
	 * (and remove it from the list of arguments) */
	ni_dbus_variant_set_string(&call_argv[0], "");
	if (ifname)
		ni_dbus_variant_set_string(&call_argv[0], ifname);

	method = ni_dbus_service_get_method(service, "newLink");
	ni_assert(method);

	ni_assert(method->user_data);

	if (ni_dbus_xml_serialize_arg(method, 1, &call_argv[1], linkdef)) {
		result = ni_call_link_new(service, call_argv);
	} else {
		ni_error("%s.%s: error serializing arguments",
				service->name, method->name);
	}

	ni_dbus_variant_destroy(&call_argv[0]);
	ni_dbus_variant_destroy(&call_argv[1]);
	return result;
}

/*
 * Bring the link of an interface up
 */
static int
ni_call_link_method_common(ni_dbus_object_t *object,
				const ni_dbus_service_t *service, const ni_dbus_method_t *method,
				unsigned int argc, ni_dbus_variant_t *argv,
				ni_objectmodel_callback_info_t **callback_list,
				ni_call_error_context_t *error_ctx)
{
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	int rv = 0;

	if (!ni_dbus_object_call_variant(object, service->name, method->name,
				argc, argv,
				1, &result,
				&error)) {

		if (error_ctx) {
			rv = error_ctx->handler(error_ctx, &error);
			if (rv > 0) {
				ni_warn("Whaaah. Error context handler returns positive code. "
					"Assuming programmer mistake");
				rv = -rv;
			}
		} else {
			ni_error("%s.%s() failed. Server responds:", service->name, method->name);
			ni_error_extra("%s: %s", error.name, error.message);
			rv = ni_dbus_get_error(&error, NULL);
		}
	} else {
		*callback_list = ni_objectmodel_callback_info_from_dict(&result);
		rv = 0;
	}

	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return rv;
}

static dbus_bool_t
ni_call_link_method_xml(ni_dbus_object_t *object, const char *method_name, xml_node_t *config,
			ni_objectmodel_callback_info_t **callback_list,
			ni_call_error_context_t *error_context)
{
	ni_dbus_variant_t argv[1];
	const ni_dbus_service_t *service;
	const ni_dbus_method_t *method;
	int rv, argc;

	if (!(service = ni_dbus_object_get_service_for_method(object, method_name))) {
		ni_error("%s: no registered dbus service for method %s()",
				object->path, method_name);
		return FALSE;
	}
	method = ni_dbus_service_get_method(service, method_name);
	ni_assert(method);

retry_operation:
	memset(argv, 0, sizeof(argv));
	argc = 0;

	/* Query the xml schema whether the call expects an argument or not.
	 * All calls that end up here always take at most one argument, which
	 * would be a dict built from the xml node passed in by the caller. */
	if (ni_dbus_xml_method_num_args(method)) {
		ni_dbus_variant_t *dict = &argv[argc++];

		ni_dbus_variant_init_dict(dict);
		if (config && !ni_dbus_xml_serialize_arg(method, 0, dict, config)) {
			ni_error("%s.%s: error serializing argument", service->name, method->name);
			rv = -NI_ERROR_CANNOT_MARSHAL;
			goto out;
		}
	}

	rv = ni_call_link_method_common(object, service, method, argc, argv, callback_list, error_context);

out:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);

	/* On the first time around, we may have run into a problem and tried to fix
	 * it up in the error handler. For instance, a wireless passphrase or a
	 * UMTS PIN might have missed, and we prompted the user for it.
	 * In this case, the error handler will retur RETRY_OPERATION.
	 */
	if (rv == -NI_ERROR_RETRY_OPERATION && error_context != NULL && error_context->config) {
		config = error_context->config;
		error_context = NULL;
		goto retry_operation;
	}

	return rv >= 0;
}

dbus_bool_t
ni_call_firewall_up_xml(ni_dbus_object_t *object, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "firewallUp", config, callback_list, NULL);
}

dbus_bool_t
ni_call_firewall_down_xml(ni_dbus_object_t *object, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "firewallDown", NULL, callback_list, NULL);
}

dbus_bool_t
ni_call_link_up_xml(ni_dbus_object_t *object, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "linkUp", config, callback_list, NULL);
}

dbus_bool_t
ni_call_link_login_xml(ni_dbus_object_t *object, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list,
				ni_call_error_handler_t *error_handler)
{
	ni_call_error_context_t error_context = NI_CALL_ERROR_CONTEXT_INIT(error_handler, config);
	dbus_bool_t success;

	success = ni_call_link_method_xml(object, "login", config, callback_list, &error_context);
	ni_call_error_context_destroy(&error_context);
	return success;
}

dbus_bool_t
ni_call_link_logout(ni_dbus_object_t *object, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "logout", config, callback_list, NULL);
}

dbus_bool_t
ni_call_link_change_xml(ni_dbus_object_t *object, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list,
				ni_call_error_handler_t *error_handler)
{
	ni_call_error_context_t error_context = NI_CALL_ERROR_CONTEXT_INIT(error_handler, config);
	dbus_bool_t success;

	success = ni_call_link_method_xml(object, "linkChange", config, callback_list, &error_context);
	ni_call_error_context_destroy(&error_context);
	return success;
}

dbus_bool_t
ni_call_link_down(ni_dbus_object_t *object, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "linkDown", NULL, callback_list, NULL);
}

dbus_bool_t
ni_call_device_delete(ni_dbus_object_t *object, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "deleteLink", NULL, callback_list, NULL);
}

/*
 * Helper functions for dealing with error contexts.
 */
xml_node_t *
ni_call_error_context_get_node(ni_call_error_context_t *error_context, const char *path)
{
	xml_node_t *node, *child;
	char *s, *copy;

	/* If we weren't given a config node, allocate one on the fly */
	if ((node = error_context->config) == NULL) {
		node = xml_node_new(NULL, NULL);
		error_context->config = node;
		error_context->__allocated = node;
	}

	copy = strdup(path);
	for (s = strtok(copy, "."); s; s = strtok(NULL, ".")) {
		if (!(child = xml_node_get_child(node, s)))
			child = xml_node_new(s, node);
		node = child;
	}

	free(copy);
	return node;
}

void
ni_call_error_context_destroy(ni_call_error_context_t *error_context)
{
	if (error_context->__allocated)
		xml_node_free(error_context->__allocated);
	error_context->__allocated = NULL;
}

/*
 * Configure address configuration on a link
 */
dbus_bool_t
ni_call_request_lease(ni_dbus_object_t *object, const ni_dbus_service_t *service, ni_dbus_variant_t *arg,
				ni_objectmodel_callback_info_t **callback_list)
{
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	dbus_bool_t rv = FALSE;

	if (!ni_dbus_object_call_variant(object, service->name, "requestLease",
				1, arg,
				1, &result,
				&error)) {
		ni_error("server refused to configure addresses. Server responds:");
		ni_error_extra("%s: %s", error.name, error.message);
	} else {
		*callback_list = ni_objectmodel_callback_info_from_dict(&result);
		rv = TRUE;
	}

	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return rv;
}

dbus_bool_t
ni_call_request_lease_xml(ni_dbus_object_t *object, const ni_dbus_service_t *service, xml_node_t *config,
				ni_objectmodel_callback_info_t **callback_list)
{
	ni_dbus_variant_t argument = NI_DBUS_VARIANT_INIT;
	const ni_dbus_method_t *method;
	dbus_bool_t rv = FALSE;

	method = ni_dbus_service_get_method(service, "requestLease");
	ni_assert(method);

	ni_dbus_variant_init_dict(&argument);
	if (config && !ni_dbus_xml_serialize_arg(method, 0, &argument, config)) {
		ni_error("%s.%s: error serializing argument", service->name, method->name);
		goto out;
	}

	rv = ni_call_request_lease(object, service, &argument, callback_list);

out:
	ni_dbus_variant_destroy(&argument);
	return rv;
}

/*
 * Request that a given lease will be dropped.
 */
dbus_bool_t
ni_call_drop_lease(ni_dbus_object_t *object, const ni_dbus_service_t *service,
				ni_objectmodel_callback_info_t **callback_list)
{
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	dbus_bool_t rv = FALSE;

	if (!ni_dbus_object_call_variant(object, service->name, "dropLease",
				0, NULL,
				1, &result,
				&error)) {
		ni_error("server refused to drop lease. Server responds:");
		ni_error_extra("%s: %s", error.name, error.message);
	} else {
		*callback_list = ni_objectmodel_callback_info_from_dict(&result);
		rv = TRUE;
	}

	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return rv;
}

/*
 * Populate a property dict with parameters
 */
dbus_bool_t
ni_call_properties_from_argv(const ni_dbus_service_t *interface, ni_dbus_variant_t *dict, int argc, char **argv)
{
	int i;

	ni_dbus_variant_init_dict(dict);
	for (i = 0; i < argc; ++i) {
		const ni_dbus_property_t *property;
		ni_dbus_variant_t *var, *var_dict;
		char *property_name = argv[i];
		char *value;

		if ((value = strchr(property_name, '=')) == NULL) {
			ni_error("Cannot parse property \"%s\"", property_name);
			return FALSE;
		}
		*value++ = '\0';

		/* Using lookup_property will also resolve hierarchical names, such
		 * as foo.bar.baz (which is property baz within a dict named bar,
		 * which is part of dict foo). */
		if (!(property = ni_dbus_service_create_property(interface, property_name, dict, &var_dict))) {
			ni_error("Unsupported property \"%s\"", property_name);
			return FALSE;
		}

		var = ni_dbus_dict_add(var_dict, property->name);
		if (!ni_dbus_variant_init_signature(var, property->signature)) {
			ni_error("Unable to parse property %s=%s (bad type signature)",
					property_name, value);
			return FALSE;
		}

		if (property->parse) {
			if (!property->parse(property, var, value)) {
				ni_error("Unable to parse property %s=%s", property_name, value);
				return FALSE;
			}
		} else {
			/* FIXME: variant_parse should unquote string if needed */
			if (!ni_dbus_variant_parse(var, value, property->signature)) {
				ni_error("Unable to parse property %s=%s", property_name, value);
				return FALSE;
			}
		}
	}

	return TRUE;
}

