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
ni_objectmodel_manager_init(ni_manager_t *mgr)
{
	ni_dbus_object_t *root_object;

	ni_objectmodel_managed_policy_init(mgr->server);
	ni_objectmodel_managed_netif_init(mgr->server);

	ni_objectmodel_register_service(&ni_objectmodel_manager_service);

	root_object = ni_dbus_server_get_root_object(mgr->server);
	root_object->handle = mgr;
	root_object->class = &ni_objectmodel_manager_class;
	ni_objectmodel_bind_compatible_interfaces(root_object);

	{
		unsigned int i;

		ni_trace("%s supports:", ni_dbus_object_get_path(root_object));
		for (i = 0; root_object->interfaces[i]; ++i) {
			const ni_dbus_service_t *service = root_object->interfaces[i];

			ni_trace("  %s", service->name);
		}
		ni_trace("(%u interfaces)", i);
	}
}

/*
 * Extract fsm handle from dbus object
 */
static ni_manager_t *
ni_objectmodel_manager_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_manager_t *mgr = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_manager_class))
		return mgr;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s",
			object->path, object->class->name);
	return NULL;
}

/*
 * Manager.getDevice(devname)
 */
static dbus_bool_t
ni_objectmodel_manager_get_device(ni_dbus_object_t *object, const ni_dbus_method_t *method,
					unsigned int argc, const ni_dbus_variant_t *argv,
					ni_dbus_message_t *reply, DBusError *error)
{
	ni_manager_t *mgr;
	const char *ifname;
	ni_ifworker_t *w;
	ni_managed_netdev_t *mdev = NULL;

	if ((mgr = ni_objectmodel_manager_unwrap(object, error)) == NULL)
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_get_string(&argv[0], &ifname))
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	/* XXX: scalability. Use ni_call_identify_device() */
	ni_fsm_refresh_state(mgr->fsm);
	w = ni_fsm_ifworker_by_name(mgr->fsm, NI_IFWORKER_TYPE_NETDEV, ifname);

	if (w)
		mdev = ni_manager_get_netdev(mgr, w->device);

	if (mdev == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_DEVICE_NOT_KNOWN, "No such device: %s", ifname);
		return FALSE;
	} else {
		char object_path[128];

		snprintf(object_path, sizeof(object_path),
				NI_OBJECTMODEL_MANAGED_NETIF_LIST_PATH "/%u",
				mdev->dev->link.ifindex);

		ni_dbus_message_append_object_path(reply, object_path);
	}
	return TRUE;
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
	ni_manager_t *mgr;
	ni_fsm_policy_t *policy;
	const char *name;
	char namebuf[64];

	if ((mgr = ni_objectmodel_manager_unwrap(object, error)) == NULL)
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_get_string(&argv[0], &name))
		return ni_dbus_error_invalid_args(error, ni_dbus_object_get_path(object), method->name);

	if (*name == '\0') {
		static unsigned int counter = 0;

		do {
			snprintf(namebuf, sizeof(namebuf), "policy%u", counter++);
		} while (ni_fsm_policy_by_name(mgr->fsm, namebuf) == NULL);
		name = namebuf;
	}

#ifdef notyet
	if (!ni_policy_name_valid(name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"Bad policy name \"%s\" in call to %s.%s",
				name, ni_dbus_object_get_path(object), method->name);
		return FALSE;
	}
#endif

	if (ni_fsm_policy_by_name(mgr->fsm, name) != NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_POLICY_EXISTS,
				"Policy \"%s\" already exists in call to %s.%s",
				name, ni_dbus_object_get_path(object), method->name);
		return FALSE;
	}

	policy = ni_fsm_policy_new(mgr->fsm, name, NULL);

	policy_object = ni_objectmodel_register_managed_policy(ni_dbus_object_get_server(object),
					ni_managed_policy_new(mgr, policy, NULL));

	ni_dbus_message_append_object_path(reply, ni_dbus_object_get_path(policy_object));
	return TRUE;
}

static ni_dbus_method_t		ni_objectmodel_manager_methods[] = {
	{ "createPolicy",	"s",		ni_objectmodel_manager_create_policy	},
	{ "getDevice",		"s",		ni_objectmodel_manager_get_device	},
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
