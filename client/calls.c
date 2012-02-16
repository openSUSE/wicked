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
 * Bring the link of an interface up
 */
static dbus_bool_t
wicked_link_change_common(ni_dbus_object_t *object,
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

dbus_bool_t
wicked_link_change_xml(ni_dbus_object_t *object, const char *method_name, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list)
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
	if (!strcmp(method_name, "linkUp")) {
		ni_dbus_variant_t *dict = &argv[argc++];

		ni_dbus_variant_init_dict(dict);
		if (config && !ni_dbus_xml_serialize_arg(method, 0, dict, config)) {
			ni_error("%s.%s: error serializing argument", service->name, method->name);
			goto out;
		}
	}

	rv = wicked_link_change_common(object, service, method, argc, argv, callback_list);

out:
	while (argc--)
		ni_dbus_variant_destroy(&argv[argc]);
	return rv;
}

dbus_bool_t
ni_call_link_up_xml(ni_dbus_object_t *object, xml_node_t *config, ni_objectmodel_callback_info_t **callback_list)
{
	return wicked_link_change_xml(object, "linkUp", config, callback_list);
}

dbus_bool_t
ni_call_link_down(ni_dbus_object_t *object, ni_objectmodel_callback_info_t **callback_list)
{
	return wicked_link_change_xml(object, "linkDown", NULL, callback_list);
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

