/*
 * This daemon manages modems in response to modem-manager
 * events.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
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
#include <wicked/client.h>
#include "manager.h"


void
ni_objectmodel_managed_modem_init(ni_dbus_server_t *server)
{
	ni_dbus_object_t *root_object;

	ni_objectmodel_register_class(&ni_objectmodel_managed_modem_class);
	ni_objectmodel_register_service(&ni_objectmodel_managed_modem_service);

	root_object = ni_dbus_server_get_root_object(server);
	ni_dbus_object_create(root_object, "Modem", NULL, NULL);
}

/*
 * managed_modem objects
 */
ni_managed_modem_t *
ni_managed_modem_new(ni_manager_t *mgr, ni_ifworker_t *w)
{
	ni_managed_modem_t *mdev;

	if (w->modem == NULL)
		ni_warn("%s(%s): device not bound", __func__, w->name);

	mdev = calloc(1, sizeof(*mdev));
	mdev->manager = mgr;
	mdev->worker = ni_ifworker_get(w);
	mdev->dev = ni_modem_hold(w->modem);

	/* FIXME: for now, we allow users to control all modems */
	mdev->user_controlled = TRUE;

	mdev->next = mgr->modem_list;
	mgr->modem_list = mdev;

	return mdev;
}

void
ni_managed_modem_free(ni_managed_modem_t *mdev)
{
	if (mdev->dev != NULL) {
		ni_modem_release(mdev->dev);
		mdev->dev = NULL;
	}

	free(mdev);
}

void
ni_managed_modem_apply_policy(ni_managed_modem_t *mdev, ni_managed_policy_t *mpolicy, ni_fsm_t *fsm)
{
	const char *device_name = mdev->worker->name;
	const ni_fsm_policy_t *policy = mpolicy->fsm_policy;
	xml_node_t *config;

	/* If the device is up and running, do not reconfigure unless the policy
	 * has really changed */
	if (ni_ifworker_is_running(mdev->worker)) {
		if (mdev->selected_policy == mpolicy && mdev->selected_policy_seq == mpolicy->seqno) {
			ni_trace("%s: keep using policy %s", device_name, ni_fsm_policy_name(policy));
			return;
		}
	}

	ni_trace("%s: using policy %s", device_name, ni_fsm_policy_name(policy));
	config = xml_node_new("modem", NULL);
	xml_node_new_element("name", config, device_name);

	config = ni_fsm_policy_transform_document(config, &policy, 1);
	if (config == NULL) {
		ni_error("%s: error when applying policy to interface document", device_name);
		return;
	}

	ni_trace("%s: using device config", device_name);
	xml_node_print(config, NULL);
	if (mdev->selected_config)
		xml_node_free(mdev->selected_config);
	mdev->selected_config = config;
	mdev->selected_policy = mpolicy;
	mdev->selected_policy_seq = mpolicy->seqno;
	mdev->timeout = fsm->worker_timeout;

	/* Now do the fandango */
	ni_managed_modem_up(mdev, NI_FSM_STATE_DEVICE_UP);
}

/*
 * Bring up the device
 */
void
ni_managed_modem_up(ni_managed_modem_t *mdev, unsigned int target_state)
{
	ni_ifworker_t *w = mdev->worker;
	char security_id[256];

	ni_ifworker_reset(w);

	snprintf(security_id, sizeof(security_id), "modem:%s", w->modem->identify.equipment);
	ni_string_dup(&w->security_id, security_id);

	ni_ifworker_set_config(w, mdev->selected_config, "manager");
	w->target_range.min = target_state;
	w->target_range.max = __NI_FSM_STATE_MAX;
	ni_ifworker_start(mdev->manager->fsm, w, mdev->timeout);
}

/*
 * Create a dbus object representing the managed modem
 */
ni_dbus_object_t *
ni_objectmodel_register_managed_modem(ni_dbus_server_t *server, ni_managed_modem_t *mdev)
{
	char relative_path[128];
	ni_dbus_object_t *object;

	snprintf(relative_path, sizeof(relative_path), "Modem/%s", mdev->dev->device);
	object = ni_dbus_server_register_object(server, relative_path, &ni_objectmodel_managed_modem_class, mdev);

	ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}

/*
 * Extract managed_modem handle from dbus object
 */
static ni_managed_modem_t *
ni_objectmodel_managed_modem_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_managed_modem_t *mdev = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_managed_modem_class))
		return mdev;

	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a managed network interface)",
			object->path, object->class->name);
	return NULL;
}

/*
 * ctor/dtor for the managed-modem class
 */
static void
ni_managed_modem_initialize(ni_dbus_object_t *object)
{
	ni_assert(object->handle == NULL);
}

static void
ni_managed_modem_destroy(ni_dbus_object_t *object)
{
	ni_managed_modem_t *mdev;

	if (!(mdev = ni_objectmodel_managed_modem_unwrap(object, NULL)))
		return;

	ni_managed_modem_free(mdev);
}

ni_dbus_class_t			ni_objectmodel_managed_modem_class = {
	.name		= "managed-modem",
	.initialize	= ni_managed_modem_initialize,
	.destroy	= ni_managed_modem_destroy,
};

static ni_dbus_method_t		ni_objectmodel_managed_modem_methods[] = {
	{ NULL }
};

/*
 * Handle object properties
 */
static void *
ni_objectmodel_get_managed_modem(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_managed_modem_unwrap(object, error);
}

#define MANAGED_MODEM_BOOL_PROPERTY(dbus_name, name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(managed_modem, dbus_name, name, rw)

static ni_dbus_property_t	ni_objectmodel_managed_modem_properties[] = {
	MANAGED_MODEM_BOOL_PROPERTY(user-controlled, user_controlled, RW),
	{ NULL }
};

ni_dbus_service_t		ni_objectmodel_managed_modem_service = {
	.name		= NI_OBJECTMODEL_MANAGED_MODEM_INTERFACE,
	.compatible	= &ni_objectmodel_managed_modem_class,
	.methods	= ni_objectmodel_managed_modem_methods,
	.properties	= ni_objectmodel_managed_modem_properties,
};

