/*
 * DBus encapsulation for modems
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/dbus-errors.h>
#include <wicked/system.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "modem-manager.h"
#include "model.h"
#include "debug.h"

extern ni_modem_t *	ni_objectmodel_modem_unwrap(const ni_dbus_object_t *, DBusError *);
extern dbus_bool_t	ni_objectmodel_modem_list_refresh(ni_dbus_object_t *);
static void		ni_objectmodel_modem_initialize(ni_dbus_object_t *object);
static void		ni_objectmodel_modem_destroy(ni_dbus_object_t *object);
static const char *	ni_objectmodel_modem_path(const ni_modem_t *);

static ni_dbus_class_t		ni_objectmodel_modem_class = {
	.name		= NI_OBJECTMODEL_MODEM_CLASS,
	.initialize	= ni_objectmodel_modem_initialize,
	.destroy	= ni_objectmodel_modem_destroy,
};

static ni_dbus_class_t		ni_objectmodel_modem_proxy_class = {
	.name		= NI_OBJECTMODEL_MODEM_PROXY_CLASS,
	.initialize	= ni_objectmodel_modem_initialize,
	.destroy	= ni_objectmodel_modem_destroy,
};

static const ni_dbus_class_t	ni_objectmodel_modem_list_class = {
	.name		= NI_OBJECTMODEL_MODEM_LIST_CLASS,
	.list = {
		.item_class = &ni_objectmodel_modem_proxy_class,
	},
};

static ni_dbus_service_t	ni_objectmodel_modem_list_service;
static ni_dbus_service_t	ni_objectmodel_modem_service;

/*
 * For all link layer types, create a dbus object class named "modem-$linktype".
 * This allows to define extensions and interface for specific link layers.
 */
void
ni_objectmodel_register_modem_classes(void)
{
	static ni_bool_t initialized;
	unsigned int modem_type;

	if (initialized)
		return;
	initialized = TRUE;

	ni_trace("%s()", __func__);

	/* register the modem-list class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(&ni_objectmodel_modem_list_class);

	/* register the modem class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(&ni_objectmodel_modem_class);

	/* register the modem interface */
	ni_objectmodel_register_service(&ni_objectmodel_modem_service);

	for (modem_type = 0; modem_type < __MM_MODEM_TYPE_MAX; ++modem_type) {
		ni_dbus_class_t *class;
		const char *classname;
		char proxyname[64];

		if (!(classname = ni_objectmodel_modem_get_classname(modem_type)))
			continue;

		/* Create and register the new modem class */
		class = ni_objectmodel_class_new(classname, &ni_objectmodel_modem_class);
		ni_objectmodel_register_class(class);

		snprintf(proxyname, sizeof(proxyname), "%s-proxy", classname);
		class = ni_objectmodel_class_new(proxyname, &ni_objectmodel_modem_proxy_class);
		ni_objectmodel_register_class(class);
	}

	ni_objectmodel_register_service(&ni_objectmodel_modem_list_service);
}

/*
 * modem list class
 */
void
ni_objectmodel_create_modem_list(ni_dbus_server_t *server)
{
	ni_dbus_object_t *object;

	/* Register com.suse.Wicked.Modem, which is the list of all modems */
	object = ni_dbus_server_register_object(server, "Modem",
					&ni_objectmodel_modem_list_class,
					NULL);
	if (object == NULL)
		ni_fatal("Unable to create dbus object for modem list");

	ni_objectmodel_bind_compatible_interfaces(object);
}

/*
 * Constructor function for a modem object - this creates a dummy modem
 * object which we need to store the retrieved properties
 * Used on the client side in GetManagedObjects.
 */
static void
ni_objectmodel_modem_initialize(ni_dbus_object_t *object)
{
	ni_assert(object->handle == NULL);
	object->handle = ni_modem_new();
}

/*
 * Destructor function for a modem object.
 * This function is used both for ModemManager client objects
 * referencing a modem, as well as Wicked server side objects
 * presenting a modem to wicked clients.
 */
static void
ni_objectmodel_modem_destroy(ni_dbus_object_t *object)
{
	ni_modem_t *modem;

	if ((modem = ni_objectmodel_modem_unwrap(object, NULL)) != NULL) {
		object->handle = NULL;
		ni_modem_release(modem);
	}
}

/*
 * Build a dbus-object encapsulating a modem
 * If @server is non-NULL, register the object with a canonical object path
 */
static ni_dbus_object_t *
__ni_objectmodel_build_modem_object(ni_dbus_server_t *server, ni_modem_t *modem)
{
	const ni_dbus_class_t *class = NULL;
	ni_dbus_object_t *object;

	class = ni_objectmodel_modem_get_proxy_class(modem->type);
	if (class == NULL)
		class = &ni_objectmodel_modem_class;

	if (server != NULL) {
		object = ni_dbus_server_register_object(server,
						ni_objectmodel_modem_path(modem),
						class, ni_modem_hold(modem));
	} else {
		object = ni_dbus_object_new(class, NULL, ni_modem_hold(modem));
	}

	if (object == NULL)
		ni_fatal("Unable to create proxy object for modem %s", modem->real_path);

	ni_objectmodel_bind_compatible_interfaces(object);
	return object;
}


/*
 * Register a modem with our dbus server, and add the appropriate dbus services
 */
ni_dbus_object_t *
ni_objectmodel_register_modem(ni_dbus_server_t *server, ni_modem_t *modem)
{
	return __ni_objectmodel_build_modem_object(server, modem);
}

/*
 * Unregister a modem from our dbus server.
 */
dbus_bool_t
ni_objectmodel_unregister_modem(ni_dbus_server_t *server, ni_modem_t *modem)
{
	if (ni_dbus_server_unregister_object(server, modem)) {
		ni_debug_dbus("unregistered modem %s", modem->real_path);
		return 1;
	}

	return 0;
}

/*
 * Return the canonical object path for an interface object
 */
const char *
ni_objectmodel_modem_path(const ni_modem_t *modem)
{
	static char object_path[256];
	char *sp;

	ni_assert(modem->real_path != NULL);
	if ((sp = strrchr(modem->real_path, '/')) == NULL)
		return NULL;

	snprintf(object_path, sizeof(object_path), "Modem%s", sp);
	return object_path;
}

const char *
ni_objectmodel_modem_full_path(const ni_modem_t *modem)
{
	static char object_path[256];

	snprintf(object_path, sizeof(object_path), NI_OBJECTMODEL_OBJECT_PATH "/%s", ni_objectmodel_modem_path(modem));
	return object_path;
}

/*
 * Given a DBus object, make sure it represents a modem, and obtain the
 * modem object
 */
ni_modem_t *
ni_objectmodel_modem_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_modem_t *modem = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_modem_class))
		return modem;
	if (ni_dbus_object_isa(object, &ni_objectmodel_modem_proxy_class))
		return modem;
	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a modem device)",
			object->path, object->class->name);
	return NULL;
}


/*
 * The ModemList service
 */
static dbus_bool_t
ni_objectmodel_modem_list_identify_device(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	const ni_dbus_variant_t *dict, *var;
	const char *name;
	char *copy, *naming_service, *attribute;
	ni_dbus_object_t *found;

	ni_assert(argc == 1);
	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);
	dict = &argv[0];

	if ((var = ni_dbus_dict_get_entry(dict, 0, &name)) == NULL)
		goto invalid_args;

	ni_debug_dbus("%s(name=%s)", __func__, name);
	copy = naming_service = strdup(name);
	if ((attribute = strchr(copy, ':')) != NULL)
		*attribute++ = '\0';

	found = ni_objectmodel_resolve_name(object, naming_service, attribute, var);
	free(copy);

	if (found == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_INTERFACE_NOT_KNOWN,
				"unable to identify interface via %s", name);
		return FALSE;
	}

	if (ni_objectmodel_modem_unwrap(found, NULL) == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_INTERFACE_NOT_KNOWN,
				"failed to identify interface via %s - naming service returned "
				"a %s object", name, found->class->name);
		return FALSE;
	}

	ni_dbus_message_append_string(reply, found->path);
	return TRUE;

invalid_args:
	return ni_dbus_error_invalid_args(error, object->path, method->name);
}

static ni_dbus_method_t		ni_objectmodel_modem_list_methods[] = {
	{ "identifyDevice",	"a{sv}",	ni_objectmodel_modem_list_identify_device },
	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_modem_list_service = {
	.name		= NI_OBJECTMODEL_MODEM_LIST_INTERFACE,
	.compatible	= &ni_objectmodel_modem_list_class,
	.methods	= ni_objectmodel_modem_list_methods,
};

/*
 * The modem proxy service. This is little more than a registry of
 * modem devices, re-exporting the ModemManager devices below
 * /com/suse/Wicked/Modem. The reason we introduce this indirection
 * is that we want to bring the modem link up and down using the same
 * verbs (methods) as for network devices.
 *
 * The properties exported by the modem proxy objects are
 *  -	realpath: the dbus path name used by ModemManager
 *  -	identification information
 *
 * The methods supported by these modem proxies are
 *  -	changeDevice():
 *	Provide the device PIN (if needed)
 *  -	linkUp():
 *	Bring up the modem link (by dialing, or by connecting
 *	via GPRS/UMTS/whatnot).
 *  -	linkDown():
 *	Hang up
 *
 * This allows a wicked client to treat modems just the same way
 * as other subordinate devices that need to be brought up.
 */
static void *
ni_objectmodel_get_modem(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_modem_unwrap(object, error);
}

#define MODEM_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(modem, dbus_name, member_name, rw)
#define MODEM_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(modem, dbus_name, member_name, rw)

static ni_dbus_property_t	ni_objectmodel_modem_properties[] = {
	MODEM_STRING_PROPERTY(real-path, real_path, RO),

	{ NULL }
};
static ni_dbus_service_t	ni_objectmodel_modem_service = {
	.name		= NI_OBJECTMODEL_MODEM_INTERFACE,
	.properties	= ni_objectmodel_modem_properties,
	.compatible	= &ni_objectmodel_modem_proxy_class,
};
