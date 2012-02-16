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

#include "client/wicked-client.h"


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
 * Note, this must use the same class naming convention
 * as in ni_objectmodel_link_classname()
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
 * Get the dbus interface for a given link layer type
 * Note, this must use the same class naming convention
 * as in __ni_objectmodel_link_classname()
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
static dbus_bool_t
ni_call_link_change_common(ni_dbus_object_t *object,
				const ni_dbus_service_t *service, const ni_dbus_method_t *method,
				unsigned int argc, ni_dbus_variant_t *argv,
				ni_objectmodel_callback_info_t **callback_list)
{
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	dbus_bool_t rv = FALSE;

	if (!ni_dbus_object_call_variant(object, service->name, method->name,
				argc, argv,
				1, &result,
				&error)) {
		ni_error("Server refused to create interface. Server responds:");
		ni_error_extra("%s: %s", error.name, error.message);
	} else {
		*callback_list = ni_objectmodel_callback_info_from_dict(&result);
		rv = TRUE;
	}

	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return rv;
}

static dbus_bool_t
ni_call_link_method_xml(ni_dbus_object_t *object, const char *method_name, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list)
{
	ni_dbus_variant_t argv[1];
	const ni_dbus_service_t *service;
	const ni_dbus_method_t *method;
	dbus_bool_t rv = FALSE;
	int argc = 0;

	if (!(service = ni_dbus_object_get_service_for_method(object, method_name)))
		return FALSE;
	method = ni_dbus_service_get_method(service, method_name);
	ni_assert(method);

	memset(argv, 0, sizeof(argv));
	if (!strcmp(method_name, "linkUp") || !strcmp(method_name, "linkChange")) {
		ni_dbus_variant_t *dict = &argv[argc++];

		ni_dbus_variant_init_dict(dict);
		if (config && !ni_dbus_xml_serialize_arg(method, 0, dict, config)) {
			ni_error("%s.%s: error serializing argument", service->name, method->name);
			goto out;
		}
	}

	rv = ni_call_link_change_common(object, service, method, argc, argv, callback_list);

out:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
	return rv;
}

dbus_bool_t
ni_call_link_up_xml(ni_dbus_object_t *object, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "linkUp", config, callback_list);
}

dbus_bool_t
ni_call_link_change_xml(ni_dbus_object_t *object, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "linkChange", config, callback_list);
}

dbus_bool_t
ni_call_link_down(ni_dbus_object_t *object, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "linkDown", NULL, callback_list);
}

dbus_bool_t
ni_call_device_delete(ni_dbus_object_t *object, ni_objectmodel_callback_info_t **callback_list)
{
	return ni_call_link_method_xml(object, "deleteLink", NULL, callback_list);
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

