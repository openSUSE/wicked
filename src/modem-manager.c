/*
 * Interfacing with ModemManager through its dbus interface
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <wicked/util.h>
#include <wicked/dbus.h>
#include <wicked/dbus-errors.h>
#include <netinfo_priv.h>
#include <errno.h>
#include <ctype.h>

#include "dbus-dict.h"
#include "dbus-common.h"
#include "dbus-objects/model.h"
#include "modem-manager.h"

#define NI_MM_SIGNAL_DEVICE_ADDED "DeviceAdded"
#define NI_MM_SIGNAL_DEVICE_REMOVED "DeviceRemoved"

#define NI_MM_BUS_NAME		"org.freedesktop.ModemManager"
#define NI_MM_OBJECT_PATH	"/org/freedesktop/ModemManager"
#define NI_MM_INTERFACE		"org.freedesktop.ModemManager"
#define NI_MM_DEV_PATH_PFX	"/org/freedesktop/ModemManager/Modems/"
#define NI_MM_MODEM_IF		"org.freedesktop.ModemManager.Modem"
#define NI_MM_GSM_CARD_IF	"org.freedesktop.ModemManager.Modem.Gsm.Card"
#define NI_MM_GSM_NETWORK_IF	"org.freedesktop.ModemManager.Modem.Gsm.Network"

typedef struct ni_modem_manager_client ni_modem_manager_client_t;
struct ni_modem_manager_client {
	ni_dbus_client_t *	dbus;

	ni_dbus_object_t *	proxy;
};

typedef enum ni_modem_type {
	MM_MODEM_TYPE_UNKNOWN = 0,
	MM_MODEM_TYPE_GSM = 1,
	MM_MODEM_TYPE_CDMA = 2,
} ni_modem_type_t;

typedef enum ni_modem_ipmethod {
	MM_MODEM_IP_METHOD_PPP = 0,
	MM_MODEM_IP_METHOD_STATIC = 1,
	MM_MODEM_IP_METHOD_DHCP = 2,
} ni_modem_ipmethod_t;

struct ni_modem {
	char *			device;
	char *			master_device;
	char *			driver;
	ni_modem_type_t		type;
	ni_modem_ipmethod_t	ip_config_method;
	dbus_bool_t		enabled;

	struct {
		char *		device;
		char *		equipment;
	} identify;

	struct {
		char *		required;
		uint32_t	retries;
	} unlock;

	struct {
		char *		imei;
		uint32_t	supported_bands;
		uint32_t	supported_modes;
	} gsm;
};

static void			ni_objectmodel_modem_destroy(ni_dbus_object_t *);
static ni_modem_t *		ni_objectmodel_modem_unwrap(const ni_dbus_object_t *, DBusError *);
static void			ni_modem_manager_add_modem(ni_modem_manager_client_t *modem_manager, const char *object_path);
static void			ni_modem_manager_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);

static ni_dbus_class_t		ni_objectmodel_modem_manager_class = {
	"modem-manager"
};
static ni_dbus_class_t		ni_objectmodel_modem_class = {
	.name		= "modem",
	.destroy	= ni_objectmodel_modem_destroy,
};
static ni_dbus_class_t		ni_objectmodel_gsm_modem_class = {
	.name		= "gsm-modem",
	.superclass	= &ni_objectmodel_modem_class,
};
static ni_dbus_service_t	ni_objectmodel_modem_service;
static ni_dbus_service_t	ni_objectmodel_gsm_modem_service;

static ni_modem_manager_client_t *ni_modem_manager_client;

static ni_intmap_t	__ni_modem_manager_error_names[] = {
	{ "org.freedesktop.ModemManager.Modem.SerialSendfailed",	NI_ERROR_PERMISSION_DENIED },

	{ NULL }
};


ni_modem_manager_client_t *
ni_modem_manager_client_open(void)
{
	ni_dbus_client_t *dbc;
	ni_modem_manager_client_t *modem_manager;

	dbc = ni_dbus_client_open("system", NI_MM_BUS_NAME);
	if (!dbc)
		return NULL;

	ni_dbus_client_set_error_map(dbc, __ni_modem_manager_error_names);

	modem_manager = xcalloc(1, sizeof(*modem_manager));
	modem_manager->proxy = ni_dbus_client_object_new(dbc,
						&ni_objectmodel_modem_manager_class,
						NI_MM_OBJECT_PATH, NI_MM_INTERFACE,
						modem_manager);
	modem_manager->dbus = dbc;

	ni_dbus_client_add_signal_handler(dbc,
				NI_MM_BUS_NAME,		/* sender */
				NULL,			/* object path */
				NI_MM_INTERFACE,	/* object interface */
				ni_modem_manager_signal,
				modem_manager);

	return modem_manager;
}

void
ni_modem_manager_client_free(ni_modem_manager_client_t *modem_manager)
{
	if (modem_manager->dbus) {
		ni_dbus_client_free(modem_manager->dbus);
		modem_manager->dbus = NULL;
	}

	if (modem_manager->proxy) {
		ni_dbus_object_free(modem_manager->proxy);
		modem_manager->proxy = NULL;
	}

	free(modem_manager);
}

ni_bool_t
ni_modem_manager_enumerate(ni_modem_manager_client_t *modem_manager)
{
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_variant_t resp = NI_DBUS_VARIANT_INIT;
	unsigned int i;
	dbus_bool_t rv;

	rv = ni_dbus_object_call_variant(modem_manager->proxy,
					NI_MM_INTERFACE, "EnumerateDevices",
					0, NULL, 1, &resp, &error);
	if (!rv) {
		ni_dbus_print_error(&error, "unable to enumerate modem devices");
		dbus_error_free(&error);
		return FALSE;
	}

	if (!ni_dbus_variant_is_array_of(&resp, DBUS_TYPE_OBJECT_PATH_AS_STRING)) {
		ni_error("%s: unexpected return value - expected array of object paths, got %s",
				__func__, ni_dbus_variant_signature(&resp));
		rv = FALSE;
		goto done;
	}

	for (i = 0; i < resp.array.len; ++i) {
		const char *object_path = resp.string_array_value[i];

		ni_modem_manager_add_modem(modem_manager, object_path);
	}

done:
	ni_dbus_variant_destroy(&resp);
	return rv;
}

ni_bool_t
ni_modem_manager_init(void)
{
	if (!ni_modem_manager_client) {
		ni_modem_manager_client_t *client;

		client = ni_modem_manager_client_open();
		if (!client)
			return FALSE;

		ni_objectmodel_register_service(&ni_objectmodel_modem_service);
		ni_objectmodel_register_service(&ni_objectmodel_gsm_modem_service);

		if (!ni_modem_manager_enumerate(client)) {
			ni_modem_manager_client_free(client);
			return FALSE;
		}

		ni_modem_manager_client = client;
	}

	return TRUE;
}

static void
ni_modem_manager_add_modem(ni_modem_manager_client_t *modem_manager, const char *object_path)
{
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_object_t *modem_object;
	ni_modem_t *modem;

	ni_debug_dbus("%s(%s)", __func__, object_path);

	modem = ni_modem_new();

	modem_object = ni_dbus_client_object_new(modem_manager->dbus,
				&ni_objectmodel_modem_class,
				object_path,
				NI_MM_MODEM_IF,
				modem);

	if (!ni_dbus_object_refresh_properties(modem_object, &ni_objectmodel_modem_service, &error)) {
		ni_dbus_print_error(&error, "cannot update properties of %s", object_path);
		dbus_error_free(&error);
		return;
	}

	ni_debug_dbus("%s: dev=%s master=%s type=%u", object_path, modem->device, modem->master_device, modem->type);

	switch (modem->type) {
	case MM_MODEM_TYPE_GSM:
		modem_object->class = &ni_objectmodel_gsm_modem_class;
		ni_objectmodel_bind_compatible_interfaces(modem_object);
		break;

	default: ;
	}
}

/*
 * Constructor/destructor for modem objects
 */
ni_modem_t *
ni_modem_new(void)
{
	return xcalloc(1, sizeof(ni_modem_t));
}

void
ni_modem_free(ni_modem_t *modem)
{
	ni_string_free(&modem->device);
	ni_string_free(&modem->master_device);
	ni_string_free(&modem->driver);
	ni_string_free(&modem->unlock.required);
	ni_string_free(&modem->identify.device);
	ni_string_free(&modem->identify.equipment);
	ni_string_free(&modem->gsm.imei);
	free(modem);
}

static void
ni_objectmodel_modem_destroy(ni_dbus_object_t *object)
{
	ni_modem_t *modem;

	if ((modem = ni_objectmodel_modem_unwrap(object, NULL)) != NULL) {
		object->handle = NULL;
		ni_modem_free(modem);
	}
}

static ni_modem_t *
ni_objectmodel_modem_unwrap(const ni_dbus_object_t *object, DBusError *error)
{
	ni_modem_t *modem = object->handle;

	if (ni_dbus_object_isa(object, &ni_objectmodel_modem_class))
		return modem;
	if (error)
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"method not compatible with object %s of class %s (not a modem device)",
			object->path, object->class->name);
	return NULL;
}

/*
 * Properties for org.freedesktop.ModemManager.Modem
 */
static void *
ni_objectmodel_get_modem(const ni_dbus_object_t *object, DBusError *error)
{
	return ni_objectmodel_modem_unwrap(object, error);
}

#define MODEM_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(modem, dbus_type, type, rw)
#define MODEM_UINT_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(modem, dbus_type, type, rw)
#define MODEM_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(modem, dbus_type, type, rw)
#define MODEM_BOOL_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(modem, dbus_type, type, rw)

const ni_dbus_property_t        ni_objectmodel_modem_property_table[] = {
	MODEM_STRING_PROPERTY(Device, device, RO),
	MODEM_STRING_PROPERTY(MasterDevice, master_device, RO),
	MODEM_STRING_PROPERTY(Driver, driver, RO),
	MODEM_STRING_PROPERTY(UnlockRequired, unlock.required, RO),
	MODEM_UINT_PROPERTY(UnlockRetries, unlock.retries, RO),
	MODEM_STRING_PROPERTY(DeviceIdentifier, identify.device, RO),
	MODEM_STRING_PROPERTY(EquipmentIdentifier, identify.equipment, RO),
	MODEM_BOOL_PROPERTY(Enabled, enabled, RO),
	MODEM_UINT_PROPERTY(Type, type, RO),
	MODEM_UINT_PROPERTY(IpMethod, ip_config_method, RO),
	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_modem_service = {
	.name		= NI_MM_MODEM_IF,
	.compatible	= &ni_objectmodel_modem_class,
	.properties	= ni_objectmodel_modem_property_table,
};

const ni_dbus_property_t        ni_objectmodel_gsm_modem_property_table[] = {
	MODEM_UINT_PROPERTY(SupportedBands, gsm.supported_bands, RO),
	MODEM_UINT_PROPERTY(SupportedModes, gsm.supported_modes, RO),
	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_gsm_modem_service = {
	.name		= NI_MM_GSM_CARD_IF,
	.compatible	= &ni_objectmodel_gsm_modem_class,
	.properties	= ni_objectmodel_gsm_modem_property_table,
};

ni_dbus_client_t *
ni_modem_manager_client_dbus(ni_modem_manager_client_t *modem_manager)
{
	return modem_manager->dbus;
}

static void
ni_modem_manager_signal(ni_dbus_connection_t *conn, ni_dbus_message_t *msg, void *user_data)
{
	ni_modem_manager_client_t *modem_manager = user_data;
	const char *member = dbus_message_get_member(msg);

	ni_debug_dbus("%s: %s", __func__, member);
	if (!strcmp(member, NI_MM_SIGNAL_DEVICE_ADDED)) {
		/* TBD */
	} else
	if (!strcmp(member, NI_MM_SIGNAL_DEVICE_REMOVED)) {
		/* TBD */
	} else {
		ni_debug_wireless("%s signal received (not handled)", member);
	}
	(void) modem_manager;
}
