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
#include <wicked/dbus-service.h>
#include <wicked/system.h>
#include "netinfo_priv.h"
#include "dbus-common.h"
#include "modem-manager.h"
#include "model.h"
#include "debug.h"

extern dbus_bool_t	ni_objectmodel_modem_list_refresh(ni_dbus_object_t *);
static void		ni_objectmodel_modem_initialize(ni_dbus_object_t *object);
static void		ni_objectmodel_modem_destroy(ni_dbus_object_t *object);
static const char *	ni_objectmodel_modem_path(const ni_modem_t *);
static ni_modem_t *	__ni_objectmodel_get_modem_arg(const ni_dbus_variant_t *dict, ni_dbus_object_t **ret_object);

static ni_dbus_class_t		ni_objectmodel_mm_modem_class = {
	.name		= NI_OBJECTMODEL_MM_MODEM_CLASS,
	.initialize	= ni_objectmodel_modem_initialize,
	.destroy	= ni_objectmodel_modem_destroy,
};

static ni_dbus_class_t		ni_objectmodel_modem_class = {
	.name		= NI_OBJECTMODEL_MODEM_CLASS,
	.initialize	= ni_objectmodel_modem_initialize,
	.destroy	= ni_objectmodel_modem_destroy,
};

static const ni_dbus_class_t	ni_objectmodel_modem_list_class = {
	.name		= NI_OBJECTMODEL_MODEM_LIST_CLASS,
	.list = {
		.item_class = &ni_objectmodel_modem_class,
	},
};

static ni_dbus_service_t	ni_objectmodel_modem_list_service;
static ni_dbus_service_t	ni_objectmodel_modem_service;

/*
 * Shortcut to return the (cached) registered modem base-class or NULL
 */
const ni_dbus_class_t *
ni_objectmodel_get_modem_class(void)
{
	static const ni_dbus_class_t *class = NULL;

	return class ?: (class = ni_objectmodel_get_class(NI_OBJECTMODEL_MODEM_CLASS));
}

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

	/* register the modem-list class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(&ni_objectmodel_modem_list_class);

	/* register the modem class (to allow extensions to attach to it) */
	ni_objectmodel_register_class(&ni_objectmodel_mm_modem_class);
	ni_objectmodel_register_class(&ni_objectmodel_modem_class);

	for (modem_type = 0; modem_type < __MM_MODEM_TYPE_MAX; ++modem_type) {
		ni_dbus_class_t *class;
		const char *classname;

		/* Create and register the modem-manager client class for this modem type */
		if ((classname = ni_objectmodel_mm_modem_get_classname(modem_type)) != NULL) {
			class = ni_objectmodel_class_new(classname, &ni_objectmodel_mm_modem_class);
			ni_objectmodel_register_class(class);
		}

		/* Create and register the wicked server class for this modem type */
		if ((classname = ni_objectmodel_modem_get_classname(modem_type)) != NULL) {
			class = ni_objectmodel_class_new(classname, &ni_objectmodel_modem_class);
			ni_objectmodel_register_class(class);
		}
	}
}

const char *
ni_objectmodel_modem_get_classname(ni_modem_type_t type)
{
	switch (type) {
	case MM_MODEM_TYPE_GSM:
		return NI_OBJECTMODEL_MODEM_GSM_CLASS;

	case MM_MODEM_TYPE_CDMA:
		return NI_OBJECTMODEL_MODEM_CDMA_CLASS;

	default: ;
	}

	return NULL;
}

const ni_dbus_class_t *
ni_objectmodel_modem_get_class(ni_modem_type_t type)
{
	const char *classname;

	if ((classname = ni_objectmodel_modem_get_classname(type)) == NULL)
		return NULL;
	return ni_objectmodel_get_class(classname);
}

void
ni_objectmodel_register_modem_services(void)
{
	ni_objectmodel_register_service(&ni_objectmodel_modem_service);
	ni_objectmodel_register_service(&ni_objectmodel_modem_list_service);
}

/*
 * modem list class
 */
void
ni_objectmodel_create_modem_list(ni_dbus_server_t *server)
{
	ni_dbus_object_t *object;

	/* Register the list of all modems */
	object = ni_dbus_server_register_object(server,
					NI_OBJECTMODEL_MODEM_LIST_PATH,
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

	if ((modem = ni_objectmodel_unwrap_modem(object, NULL)) != NULL) {
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

	class = ni_objectmodel_modem_get_class(modem->type);
	if (class == NULL)
		class = &ni_objectmodel_mm_modem_class;

	if (server != NULL) {
		object = ni_dbus_server_register_object(server,
						ni_objectmodel_modem_path(modem),
						class, ni_modem_hold(modem));
	} else {
		object = ni_dbus_object_new(class, NULL, ni_modem_hold(modem));
	}

	if (object == NULL) {
		ni_error("Unable to create proxy object for modem %s (%s)",
				modem->device, modem->real_path);
		return NULL;
	}

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
		return TRUE;
	}

	return FALSE;
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
ni_objectmodel_unwrap_modem(const ni_dbus_object_t *object, DBusError *error)
{
	ni_modem_t *modem;

	if (!object) {
		if (error)
			dbus_set_error(error, DBUS_ERROR_FAILED,
				"Cannot unwrap modem from a NULL dbus object");
		return NULL;
	}

	modem = object->handle;
	if (ni_dbus_object_isa(object, &ni_objectmodel_mm_modem_class))
		return modem;
	if (ni_dbus_object_isa(object, &ni_objectmodel_modem_class))
		return modem;
	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a modem device)",
			object->path, object->class->name);
	return NULL;
}

/*
 * Given a modem device, look up the server object encapsulating it
 */
ni_dbus_object_t *
ni_objectmodel_get_modem_object(ni_dbus_server_t *server, const ni_modem_t *modem)
{
	ni_dbus_object_t *object;

	if (!modem)
		return NULL;

	object = ni_dbus_server_find_object_by_handle(server, modem);
	if (object == NULL)
		return NULL;

	if (!ni_dbus_object_isa(object, &ni_objectmodel_modem_class)) {
		ni_error("%s: modem is encapsulated by a %s class object", __func__, object->class->name);
		return NULL;
	}

	return object;
}

/*
 * The ModemList service
 */
static dbus_bool_t
ni_objectmodel_modem_list_identify_device(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	const char *namespace;
	ni_dbus_object_t *found;

	if (argc != 2
	 || !ni_dbus_variant_get_string(&argv[0], &namespace)
	 || (!ni_dbus_variant_is_dict(&argv[1]) && argv[1].type != DBUS_TYPE_STRING))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	found = ni_objectmodel_resolve_name(object, namespace, &argv[1]);
	if (found == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_DEVICE_NOT_KNOWN,
				"unable to identify interface via %s", namespace);
		return FALSE;
	}

	if (ni_objectmodel_unwrap_modem(found, NULL) == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_DEVICE_NOT_KNOWN,
				"failed to identify interface via %s - naming service returned "
				"a %s object", namespace, found->class->name);
		return FALSE;
	}

	ni_dbus_message_append_string(reply, found->path);
	return TRUE;
}

static ni_dbus_method_t		ni_objectmodel_modem_list_methods[] = {
	{ "identifyDevice",	"a{sv}",	.handler = ni_objectmodel_modem_list_identify_device },
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
 * /org/opensuse/Network/Modem. The reason we introduce this indirection
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

/*
 * Modem.changeDevice(dict options)
 */
static dbus_bool_t
ni_objectmodel_modem_change_device(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_object_t *config_object = NULL;
	ni_modem_t *modem, *config;
	dbus_bool_t ret = FALSE;
	int rv;

	if (!(modem = ni_objectmodel_unwrap_modem(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("modem=%s", modem->device);

	/* Create an interface_request object and extract configuration from dict */
	if (!(config = __ni_objectmodel_get_modem_arg(&argv[0], &config_object)))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	/* Update the modem's pin cache */
	while (config->unlock.auth) {
		ni_modem_pin_t *pin = config->unlock.auth;

		config->unlock.auth = pin->next;
		pin->next = NULL;

		ni_modem_add_pin(modem, pin);
	}

	/* See if we have the PIN required to unlock this modem */
	if (!ni_string_empty(modem->unlock.required)) {
		ni_modem_pin_t *pin;

		if ((pin = ni_modem_get_pin(modem, modem->unlock.required)) == NULL) {
			dbus_set_error(error, NI_DBUS_ERROR_AUTH_INFO_MISSING,
					"%s|PASSWORD|%s",
					modem->unlock.required,
					"unidentified-modem");
			goto failed;
		}

#if 0
		if ((rv = ni_modem_manager_unlock(modem, pin)) < 0) {
			ni_dbus_set_error_from_code(error, rv, "failed to unlock device");
			goto failed;
		}
#endif
	}

	if (!modem->enabled) {
		if ((rv = ni_modem_manager_enable(modem)) < 0) {
			ni_dbus_set_error_from_code(error, rv, "failed to enable device");
			goto failed;
		}
	}

#if 0
	if (modem->state >= MM_MODEM_STATE_REGISTERED) {
		ret = TRUE;
	} else {
		/* Link is not associated yet. Tell the caller to wait for an event. */
		if (ni_uuid_is_null(&modem->event_uuid))
			ni_uuid_generate(&modem->event_uuid);
		ret =  __ni_objectmodel_return_callback_info(reply, NI_EVENT_LINK_ASSOCIATED,
				&modem->event_uuid, error);
	}
#else
	ret = TRUE;
#endif

failed:
	ni_dbus_object_free(config_object);
	return ret;
}

/*
 * Modem.connect(dict options)
 */
static dbus_bool_t
ni_objectmodel_modem_connect(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_object_t *config_object = NULL;
	ni_modem_t *modem, *config;
	dbus_bool_t ret = FALSE;
	int rv;

	if (!(modem = ni_objectmodel_unwrap_modem(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("modem=%s", modem->device);

	/* Create an interface_request object and extract configuration from dict */
	if (!(config = __ni_objectmodel_get_modem_arg(&argv[0], &config_object)))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	(void) ni_modem_manager_disconnect(modem);

	if ((rv = ni_modem_manager_connect(modem, config)) < 0) {
		ni_dbus_set_error_from_code(error, rv, "failed to connect");
		goto failed;
	}

	ret = TRUE;

#if 0
	if (!ni_modem_is_connected(modem)) {
		/* Link is not up yet. Tell the caller to wait for an event. */
		if (ni_uuid_is_null(&modem->event_uuid))
			ni_uuid_generate(&modem->event_uuid);
		ret = __ni_objectmodel_return_callback_info(reply, NI_EVENT_LINK_UP, &modem->event_uuid, error);
	}
#else
	if (modem->state >= MM_MODEM_STATE_REGISTERED) {
		ret = TRUE;
	} else {
		/* Link is not associated yet. Tell the caller to wait for an event. */
		if (ni_uuid_is_null(&modem->event_uuid))
			ni_uuid_generate(&modem->event_uuid);
		ret =  __ni_objectmodel_return_callback_info(reply, NI_EVENT_LINK_UP,
				&modem->event_uuid, NULL, error);
	}
#endif

failed:
	ni_dbus_object_free(config_object);
	return ret;
}

static dbus_bool_t
ni_objectmodel_modem_disconnect(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_modem_t *modem;
	int rv;

	if (!(modem = ni_objectmodel_unwrap_modem(object, error)))
		return FALSE;

	if ((rv = ni_modem_manager_disconnect(modem)) < 0) {
		ni_dbus_set_error_from_code(error, rv, "failed to disconnect modem");
		return FALSE;
	}

	return TRUE;
}

/*
 * Helper function: extract modem config from dict argument
 */
static ni_modem_t *
__ni_objectmodel_get_modem_arg(const ni_dbus_variant_t *dict, ni_dbus_object_t **ret_object)
{
	ni_dbus_object_t *config_object;

	config_object = ni_dbus_object_new(&ni_objectmodel_mm_modem_class, NULL, NULL);
	config_object->class->initialize(config_object);

	if (!ni_dbus_object_set_properties_from_dict(config_object, &ni_objectmodel_modem_service, dict, NULL)) {
		ni_dbus_object_free(config_object);
		return NULL;
	}

	*ret_object = config_object;
	return ni_objectmodel_unwrap_modem(config_object, NULL);
}

/*
 * Modem.setClientState()
 *
 * This is used by clients to record a uuid identifying the configuration used, and
 * a "state" string that helps them track where they are.
 */
static dbus_bool_t
ni_objectmodel_modem_set_client_state(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_modem_t *dev;
	ni_client_state_t *cs;

	if (!(dev = ni_objectmodel_unwrap_modem(object, error)))
		return FALSE;

	if (argc != 1 || !ni_dbus_variant_is_dict(&argv[0]))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	cs = ni_modem_get_client_state(dev);
	if (!ni_objectmodel_netif_client_state_from_dict(cs, &argv[0])) {
		ni_modem_set_client_state(dev, NULL);
		return ni_dbus_error_invalid_args(error, object->path, method->name);
	}

	return TRUE;
}

/*
 * Broadcast a modem event
 */
dbus_bool_t
ni_objectmodel_send_modem_event(ni_dbus_server_t *server, ni_dbus_object_t *object,
			ni_event_t ifevent, const ni_uuid_t *uuid)
{
	if (ifevent >= __NI_EVENT_MAX)
		return FALSE;

	if (!server && !(server = __ni_objectmodel_server)) {
		ni_error("%s: help! No dbus server handle! Cannot send signal.", __func__);
		return FALSE;
	}

	return __ni_objectmodel_device_event(server, object, NI_OBJECTMODEL_MODEM_INTERFACE, ifevent, uuid);
}

/*
 * Properties of a modem object, as seen by a wicked client
 */
static void *
ni_objectmodel_get_modem(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_modem(object, error);
}

static dbus_bool_t
__ni_objectmodel_modem_get_auth(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_modem_t *modem;
	ni_modem_pin_t *pin;

	if (!(modem = ni_objectmodel_unwrap_modem(object, error)))
		return FALSE;

	if (modem->unlock.auth == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_PROPERTY_NOT_PRESENT, "property %s not present", property->name);
		return FALSE;
	}

	for (pin = modem->unlock.auth; pin; pin = pin->next) {
		ni_dbus_variant_t *dict;

		dict = ni_dbus_dict_array_add(result);
		if (pin->kind)
			ni_dbus_dict_add_string(dict, "kind", pin->kind);
		if (pin->value)
			ni_dbus_dict_add_string(dict, "value", pin->value);
		ni_dbus_dict_add_uint32(dict, "cache-lifetime", pin->cache_lifetime);
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_modem_set_auth(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_modem_t *modem;
	unsigned int i;

	if (!(modem = ni_objectmodel_unwrap_modem(object, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict_array(argument)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s: argument type mismatch", __func__);
		return FALSE;
	}

	for (i = 0; i < argument->array.len; ++i) {
		ni_dbus_variant_t *dict = &argument->variant_array_value[i];
		const char *kind = NULL, *value = NULL;
		ni_modem_pin_t *pin;

		ni_dbus_dict_get_string(dict, "kind", &kind);
		ni_dbus_dict_get_string(dict, "value", &value);
		pin = ni_modem_pin_new(kind, value);

		ni_modem_add_pin(modem, pin);
	}
	return TRUE;
}


static dbus_bool_t
__ni_objectmodel_modem_get_identify(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_modem_t *modem;

	if (!(modem = ni_objectmodel_unwrap_modem(object, error)))
		return FALSE;

	ni_dbus_variant_init_dict(result);
	if (modem->identify.manufacturer)
		ni_dbus_dict_add_string(result, "manufacturer", modem->identify.manufacturer);
	if (modem->identify.model)
		ni_dbus_dict_add_string(result, "model", modem->identify.model);
	if (modem->identify.version)
		ni_dbus_dict_add_string(result, "version", modem->identify.version);
	if (modem->identify.equipment)
		ni_dbus_dict_add_string(result, "equipment-id", modem->identify.equipment);

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_modem_set_identify(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_modem_t *modem;
	const char *value;

	if (!(modem = ni_objectmodel_unwrap_modem(object, error)))
		return FALSE;

	if (ni_dbus_dict_get_string(argument, "manufacturer", &value))
		ni_string_dup(&modem->identify.manufacturer, value);
	if (ni_dbus_dict_get_string(argument, "model", &value))
		ni_string_dup(&modem->identify.model, value);
	if (ni_dbus_dict_get_string(argument, "version", &value))
		ni_string_dup(&modem->identify.version, value);
	if (ni_dbus_dict_get_string(argument, "equipment-id", &value))
		ni_string_dup(&modem->identify.equipment, value);

	return TRUE;
}


#define MODEM_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(modem, dbus_name, member_name, rw)
#define MODEM_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(modem, dbus_name, member_name, rw)
#define MODEM_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __ni_objectmodel_modem, rw)

static ni_dbus_property_t	ni_objectmodel_modem_properties[] = {
	MODEM_STRING_PROPERTY(device, device, RO),
	MODEM_STRING_PROPERTY(real-path, real_path, RO),
	MODEM_STRING_PROPERTY(unlock-required, unlock.required, RO),

	MODEM_PROPERTY_SIGNATURE(NI_DBUS_DICT_ARRAY_SIGNATURE, auth, RO),
	MODEM_PROPERTY_SIGNATURE(NI_DBUS_DICT_ARRAY_SIGNATURE, identify, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_modem_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_modem_change_device },
	{ "linkUp",		"a{sv}",	.handler = ni_objectmodel_modem_connect },
	{ "linkDown",		"",		.handler = ni_objectmodel_modem_disconnect },
	{ "setClientState",	"a{sv}",	.handler = ni_objectmodel_modem_set_client_state },
	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_modem_service = {
	.name		= NI_OBJECTMODEL_MODEM_INTERFACE,
	.properties	= ni_objectmodel_modem_properties,
	.methods	= ni_objectmodel_modem_methods,
	.compatible	= &ni_objectmodel_modem_class,
};
