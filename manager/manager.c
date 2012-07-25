/*
 * This daemon manages interface policies.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
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
#include <limits.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/socket.h>
#include <wicked/objectmodel.h>
#include <wicked/modem.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/fsm.h>
#include "manager.h"



void
ni_objectmodel_manager_init(ni_dbus_server_t *server, ni_fsm_t *fsm)
{
	ni_dbus_object_t *root_object;

	ni_objectmodel_managed_policy_init(server);
	ni_objectmodel_managed_netif_init(server);

	ni_objectmodel_register_service(&ni_objectmodel_manager_service);

	root_object = ni_dbus_server_get_root_object(server);
	root_object->handle = fsm;
	root_object->class = &ni_objectmodel_manager_class;
	ni_objectmodel_bind_compatible_interfaces(root_object);
}

/*
 * Extract fsm handle from dbus object
 */
static ni_fsm_t *
ni_objectmodel_manager_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_fsm_t *fsm = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_manager_class))
		return fsm;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s",
			object->path, object->class->name);
	return NULL;
}

/*
 * Manager.createPolicy()
 */
static dbus_bool_t
ni_objectmodel_manager_create_policy(ni_dbus_object_t *object, const ni_dbus_method_t *method,
					unsigned int argc, const ni_dbus_variant_t *argv,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_object_t *policy_object;
	ni_fsm_t *fsm;
	ni_fsm_policy_t *policy;
	//xml_document_t *doc;
	const char *name;

	if ((fsm = ni_objectmodel_manager_unwrap(object, error)) == NULL)
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_get_string(&argv[0], &name))
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

#ifdef notyet
	if (!ni_policy_name_valid(name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Bad policy name \"%s\" in call to %s.%s",
				name, ni_dbus_object_get_path(object), method->name);
		return FALSE;
	}
#endif

	if (ni_fsm_policy_by_name(fsm, name) == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Policy \"%s\" already exists in call to %s.%s",
				name, ni_dbus_object_get_path(object), method->name);
		return FALSE;
	}

	policy = ni_fsm_policy_new(fsm, name, NULL);

	policy_object = ni_objectmodel_register_managed_policy(ni_dbus_object_get_server(object),
					ni_managed_policy_new(policy, NULL));

	ni_dbus_message_append_string(reply, ni_dbus_object_get_path(policy_object));
	return TRUE;
}

static ni_dbus_method_t		ni_objectmodel_manager_methods[] = {
	{ "createPolicy",	"s",		ni_objectmodel_manager_create_policy	},
	{ NULL }
};

ni_dbus_class_t			ni_objectmodel_manager_class = {
	.name		= "manager",
};

ni_dbus_service_t		ni_objectmodel_manager_service = {
	.name		= NI_OBJECTMODEL_MANAGER_INTERFACE,
	.compatible	= &ni_objectmodel_manager_class,
	.methods	= ni_objectmodel_manager_methods
};
