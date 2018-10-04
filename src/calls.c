/*
 * No REST for the wicked!
 *
 * Client-side functions for calling the wicked server.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/xml.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>

#include "client/wicked-client.h"

/*
 * Error context - this is an opaque type.
 */
struct ni_call_error_context {
	ni_call_error_handler_t *handler;
	xml_node_t *		config;
	xml_node_t *		__allocated;

#define MAX_TRACKED_ERRORS	6
	struct ni_call_error_counter {
		unsigned int	count;
		char *		error_name;
		char *		error_message;
	} tracked[MAX_TRACKED_ERRORS];
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
		client = ni_create_dbus_client(NI_OBJECTMODEL_DBUS_BUS_NAME);
		if (!client)
			ni_fatal("Unable to connect to wicked dbus service");

		root_object = ni_dbus_client_object_new(client,
					&ni_dbus_anonymous_class,
					NI_OBJECTMODEL_OBJECT_PATH,
					NI_OBJECTMODEL_INTERFACE,
					NULL);
	}

	return root_object;
}

/*
 * Obtain an object handle, generic version
 */
static ni_dbus_object_t *
__ni_call_get_proxy_object(const ni_dbus_service_t *service, const char *relative_path)
{
	ni_dbus_object_t *root_object, *child;

	if (!(root_object = ni_call_create_client()))
		return NULL;

	child = ni_dbus_object_create(root_object, relative_path, service->compatible, NULL);
	ni_dbus_object_set_default_interface(child, service->name);

	return child;
}

/*
 * Obtain a service handle for Wicked.InterfacaList
 */
static const ni_dbus_service_t *
ni_call_get_netif_list_service(void)
{
	static const ni_dbus_service_t *list_service = NULL;

	if (list_service)
	       return list_service;

	list_service = ni_objectmodel_service_by_name(NI_OBJECTMODEL_NETIFLIST_INTERFACE);
	return list_service;
}

/*
 * Obtain an object handle for Wicked.InterfaceList
 */
ni_dbus_object_t *
ni_call_get_netif_list_object(void)
{
	static ni_dbus_object_t *list_object = NULL;
	const ni_dbus_service_t *list_service;

	if (list_object)
		return list_object;

	if (!(list_service = ni_call_get_netif_list_service()))
		return NULL;

	if ((list_object = __ni_call_get_proxy_object(list_service, "Interface")))
		ni_dbus_object_set_default_interface(list_object, list_service->name);

	return list_object;
}

/*
 * Obtain an object handle for Wicked.Modem
 */
ni_dbus_object_t *
ni_call_get_modem_list_object(void)
{
	static const ni_dbus_service_t *modem_list_service;
	ni_dbus_object_t *list_object;

	if (modem_list_service == NULL) {
		modem_list_service = ni_objectmodel_service_by_name(NI_OBJECTMODEL_MODEM_LIST_INTERFACE);
		ni_assert(modem_list_service);
	}

	list_object = __ni_call_get_proxy_object(modem_list_service, "Modem");
	return list_object;
}

/*
 * Identify an interface by name
 */
char *
ni_call_device_by_name(ni_dbus_object_t *list_object, const char *name)
{
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_variant_t arg = NI_DBUS_VARIANT_INIT;
	ni_dbus_variant_t res = NI_DBUS_VARIANT_INIT;
	char *result = NULL;

	ni_dbus_variant_set_string(&arg, name);
	if (ni_dbus_object_call_variant(list_object, NULL, "deviceByName", 1, &arg, 1, &res, &error)) {
		const char *value;

		if (ni_dbus_variant_get_string(&res, &value))
			result = strdup(value);
	} else {
		ni_dbus_print_error(&error, "%s.deviceByName(%s): failed",
				list_object->path, name);
		dbus_error_free(&error);
	}

	ni_dbus_variant_destroy(&arg);
	ni_dbus_variant_destroy(&res);
	return result;
}

/*
 * This works a lot like the serialization code in xml-dbus, except we're not defining a
 * schema for this.
 * Used by the device identification code below.
 */
static void
__ni_call_build_dict(ni_dbus_variant_t *var, const xml_node_t *query)
{
	if (query->cdata) {
		ni_dbus_variant_set_string(var, query->cdata);
	} else if (query->children) {
		const xml_node_t *attr;

		ni_dbus_variant_init_dict(var);
		for (attr = query->children; attr; attr = attr->next)
			__ni_call_build_dict(ni_dbus_dict_add(var, attr->name), attr);
	} else {
		ni_warn("ni_call_identify_device: empty query attribute %s (%s)",
				query->name, xml_node_location(query));
	}
}

/*
 * Identify device.
 * Device identification information usually looks like this:
 *  <device namespace="ethernet">
 *   <permanent-address>01:02:03:04:05:06</permanent-address>
 *  </device>
 * The name of the node is of the form naming-service:attribute.
 *
 * However, identification information may also be more complex. Consider
 * a system that identifies network interfaces by chassis/card/port:
 *
 *  <device namespace="funky-device">
 *    <chassis>1</chassis>
 *    <card>7</card>
 *    <port>0</port>
 *  </device>
 *
 * This approach can also be used to make all the udev renaming obsolete that
 * is done on system z, or with biosdevname.
 */
static char *
__ni_call_identify_device(ni_dbus_object_t *list_object, const char *namespace, const xml_node_t *query)
{
	ni_dbus_variant_t argv[2];
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	char *object_path = NULL;

	if (list_object == NULL) {
		ni_error("no proxy object for device list");
		return NULL;
	}

	memset(argv, 0, sizeof(argv));
	ni_dbus_variant_set_string(&argv[0], namespace);
	__ni_call_build_dict(&argv[1], query);

	if (ni_dbus_object_call_variant(list_object, NULL, "identifyDevice",
						2, argv, 1, &result, &error)) {
		const char *response;

		/* extract device object path from reply */
		if (!ni_dbus_variant_get_string(&result, &response)) {
			ni_error("identifyDevice(%s): succeeded but didn't return interface name", query->name);
		} else {
			ni_string_dup(&object_path, response);
		}
	}

	ni_dbus_variant_destroy(&argv[0]);
	ni_dbus_variant_destroy(&argv[1]);
	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return object_path;
}

char *
ni_call_identify_device(const char *namespace, const xml_node_t *query)
{
	return __ni_call_identify_device(ni_call_get_netif_list_object(), namespace, query);
}

char *
ni_call_identify_modem(const char *namespace, const xml_node_t *query)
{
	return __ni_call_identify_device(ni_call_get_modem_list_object(), namespace, query);
}

/*
 * Create a virtual network interface
 */
static char *
ni_call_device_new(const ni_dbus_service_t *service, ni_dbus_variant_t call_argv[2])
{
	ni_dbus_variant_t call_resp[1];
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_object_t *object = NULL;
	char *result = NULL;

	memset(call_resp, 0, sizeof(call_resp));
	if (!(object = ni_call_get_netif_list_object())) {
		ni_error("unable to create proxy object for %s", service->name);
		goto failed;
	}

	if (!ni_dbus_object_call_variant(object, service->name, "newDevice",
				2, call_argv,
				1, call_resp,
				&error)) {
		ni_dbus_print_error(&error, "server refused to create interface");
	} else {
		const char *response;

		/* extract device object path from reply */
		if (!ni_dbus_variant_get_string(&call_resp[0], &response)) {
			ni_error("%s: newDevice call succeeded but didn't return interface name",
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
ni_call_device_new_xml(const ni_dbus_service_t *service,
				const char *ifname, xml_node_t *linkdef)
{
	ni_dbus_variant_t call_argv[2];
	const ni_dbus_method_t *method;
	char *result = NULL;

	memset(call_argv, 0, sizeof(call_argv));

	/* The first argument of the newDevice() call is the requested interface
	 * name. If there's a name="..." argument on the command line, use that
	 * (and remove it from the list of arguments) */
	ni_dbus_variant_set_string(&call_argv[0], "");
	if (ifname)
		ni_dbus_variant_set_string(&call_argv[0], ifname);

	method = ni_dbus_service_get_method(service, "newDevice");
	ni_assert(method);

	if (ni_dbus_xml_serialize_arg(method, 1, &call_argv[1], linkdef)) {
		result = ni_call_device_new(service, call_argv);
	} else {
		ni_error("%s.%s: error serializing arguments",
				service->name, method->name);
	}

	ni_dbus_variant_destroy(&call_argv[0]);
	ni_dbus_variant_destroy(&call_argv[1]);
	return result;
}

/*
 * Place a generic call to a device. This call will optionally return a
 * callback list.
 */
static int
ni_call_device_method_common(ni_dbus_object_t *object,
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
			ni_dbus_print_error(&error, "%s.%s() failed", service->name, method->name);
			rv = ni_dbus_get_error(&error, NULL);
		}
	} else {
		if (callback_list)
			*callback_list = ni_objectmodel_callback_info_from_dict(&result);
		rv = 0;
	}

	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return rv;
}

int
ni_call_common_xml(ni_dbus_object_t *object, const ni_dbus_service_t *service, const ni_dbus_method_t *method,
			xml_node_t *config, ni_objectmodel_callback_info_t **callback_list,
			ni_call_error_handler_t *error_handler)
{
	ni_call_error_context_t error_context = NI_CALL_ERROR_CONTEXT_INIT(error_handler, config);
	ni_dbus_variant_t argv[1];
	int rv, argc;

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

	rv = ni_call_device_method_common(object, service, method, argc, argv, callback_list, &error_context);

out:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);

	/* On the first time around, we may have run into a problem and tried to fix
	 * it up in the error handler. For instance, a wireless passphrase or a
	 * UMTS PIN might have missed, and we prompted the user for it.
	 * In this case, the error handler will retur RETRY_OPERATION.
	 *
	 * Note, the error context handler should limit the number of retries by
	 * using ni_call_error_context_get_retries().
	 */
	if (rv == -NI_ERROR_RETRY_OPERATION && error_context.config) {
		config = error_context.config;
		goto retry_operation;
	}

	ni_call_error_context_destroy(&error_context);
	return rv;
}

static int
ni_get_device_method(ni_dbus_object_t *object, const char *method_name, const ni_dbus_service_t **service_ret, const ni_dbus_method_t **method_ret)
{
	if (!(*service_ret = ni_dbus_object_get_service_for_method(object, method_name))) {
		ni_error("%s: no registered dbus service for method %s()",
				object->path, method_name);
		return -NI_ERROR_METHOD_NOT_SUPPORTED;
	}
	*method_ret = ni_dbus_service_get_method(*service_ret, method_name);
	ni_assert(*method_ret);
	return 0;
}

static int
ni_call_device_method_xml(ni_dbus_object_t *object, const char *method_name, xml_node_t *config,
			ni_objectmodel_callback_info_t **callback_list)
{
	const ni_dbus_service_t *service;
	const ni_dbus_method_t *method;
	int rv;

	if ((rv = ni_get_device_method(object, method_name, &service, &method)) < 0)
		return rv;

	return ni_call_common_xml(object, service, method, config, callback_list, NULL);
}

int
ni_call_set_client_state_control(ni_dbus_object_t *object, const ni_client_state_control_t *ctrl)
{
	const ni_dbus_service_t *service;
	const ni_dbus_method_t *method;
	ni_dbus_variant_t dict;
	int rv;

	if ((rv = ni_get_device_method(object, "setClientControl", &service, &method)) < 0)
		return rv;

	memset(&dict, 0, sizeof(dict));
	ni_dbus_variant_init_dict(&dict);
	if (!ni_objectmodel_netif_client_state_control_to_dict(ctrl, &dict))
		return -1;

	rv = ni_call_device_method_common(object, service, method, 1, &dict, NULL, NULL);

	ni_dbus_variant_destroy(&dict);
	return rv;
}

int
ni_call_set_client_state_config(ni_dbus_object_t *object, const ni_client_state_config_t *conf)
{
	const ni_dbus_service_t *service;
	const ni_dbus_method_t *method;
	ni_dbus_variant_t dict;
	int rv;

	if ((rv = ni_get_device_method(object, "setClientConfig", &service, &method)) < 0)
		return rv;

	memset(&dict, 0, sizeof(dict));
	ni_dbus_variant_init_dict(&dict);
	if (!ni_objectmodel_netif_client_state_config_to_dict(conf, &dict))
		return -1;

	rv = ni_call_device_method_common(object, service, method, 1, &dict, NULL, NULL);

	ni_dbus_variant_destroy(&dict);
	return rv;
}

int
ni_call_set_client_state_scripts(ni_dbus_object_t *object, const ni_client_state_scripts_t *scripts)
{
	ni_dbus_xml_validate_context_t ctx;
	const ni_dbus_service_t *service;
	const ni_dbus_method_t *method;
	ni_dbus_variant_t argv[1];
	xml_node_t *node;
	int rv, argc;

	if ((rv = ni_get_device_method(object, "setClientScripts", &service, &method)) < 0)
		return rv;

	node = scripts->node;
	memset(&ctx, 0, sizeof(ctx));
	if (node && !ni_dbus_xml_validate_argument(method, 0, node, &ctx)) {
		ni_error("%s.%s: error validating argument", service->name, method->name);
		return -NI_ERROR_DOCUMENT_ERROR;
	}

	argc = 0;
	memset(argv, 0, sizeof(argv));
	if (ni_dbus_xml_method_num_args(method)) {
		ni_dbus_variant_t *dict = &argv[argc++];

		ni_dbus_variant_init_dict(dict);
		if (node && !ni_dbus_xml_serialize_arg(method, 0, dict, node)) {
			ni_error("%s.%s: error serializing argument", service->name, method->name);
			rv = -NI_ERROR_CANNOT_MARSHAL;
			goto out;
		}
	}

	rv = ni_call_device_method_common(object, service, method, argc, argv, NULL, NULL);
out:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
	return rv;
}

/*
 * Call setMonitor(bool) on a device
 */
int
ni_call_link_monitor(ni_dbus_object_t *object)
{
	const ni_dbus_service_t *service;
	const ni_dbus_method_t *method;
	int rv;

	if ((rv = ni_get_device_method(object, "linkMonitor", &service, &method)) < 0)
		return rv;

	return ni_call_device_method_common(object, service, method, 0, NULL, NULL, NULL);
}

/*
 * Clear the event filters of a device
 */
int
ni_call_clear_event_filters(ni_dbus_object_t *object)
{
	const ni_dbus_service_t *service;
	const ni_dbus_method_t *method;
	int rv;

	if ((rv = ni_get_device_method(object, "clearEventFilters", &service, &method)) < 0)
		return rv;

	return ni_call_device_method_common(object, service, method, 0, NULL, NULL, NULL);
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
	struct ni_call_error_counter *ctr;
	unsigned int i;

	for (i = 0, ctr = error_context->tracked; i < MAX_TRACKED_ERRORS; ++i, ++ctr) {
		ni_string_free(&ctr->error_name);
		ni_string_free(&ctr->error_message);
	}

	if (error_context->__allocated)
		xml_node_free(error_context->__allocated);
	error_context->__allocated = NULL;
}

/*
 * Count the number of times the server returns the same error code.
 * This is used by the auth info code when retrieving missing user names,
 * passwords or key phrases from the user. It'd be clumsy to limit the overall
 * number of AuthInfoMissing errors we tolerate; instead, we want to limit
 * how often we retry an operation because a specific piece of auth information
 * was missing.
 *
 * This function returns -1 if we encountered more than MAX_TRACKED_ERRORS distinct
 * errors. Otherwise, it returns how often we've seen this specific error.
 */
int
ni_call_error_context_get_retries(ni_call_error_context_t *error_context, const DBusError *error)
{
	struct ni_call_error_counter *ctr;
	unsigned int i;

	for (i = 0, ctr = error_context->tracked; i < MAX_TRACKED_ERRORS; ++i, ++ctr) {
		if (ctr->error_name == NULL) {
			ni_string_dup(&ctr->error_name, error->name);
			ni_string_dup(&ctr->error_message, error->message);
		} else
		if (!ni_string_eq(ctr->error_name, error->name)
		 || !ni_string_eq(ctr->error_message, error->message))
			continue;
		
		ctr->count++;
		return ctr->count;
	}

	return -1;
}

int
ni_call_install_lease_xml(ni_dbus_object_t *object, xml_node_t *node)
{
	ni_debug_objectmodel("%s(%s)", __func__, object->path);
	return ni_call_device_method_xml(object, "installLease", node, NULL);
}
