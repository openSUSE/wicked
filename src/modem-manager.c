/*
 * Interfacing with ModemManager through its dbus interface
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include "netinfo_priv.h"
#include "util_priv.h"

#include "dbus-dict.h"
#include "dbus-common.h"
#include "dbus-objects/model.h"
#include "modem-manager.h"

#define NI_MM_SIGNAL_DEVICE_ADDED	"DeviceAdded"
#define NI_MM_SIGNAL_DEVICE_REMOVED	"DeviceRemoved"
#define NI_MM_SIGNAL_STATE_CHANGED	"StateChanged"
#define NI_MM_SIGNAL_SIGNAL_QUALITY	"SignalQuality"
#define NI_MM_SIGNAL_REGISTRATION_INFO	"RegistrationInfo"
#define NI_MM_SIGNAL_NETWORK_MODE	"NetworkMode"

#define NI_MM_BUS_NAME		"org.freedesktop.ModemManager"
#define NI_MM_OBJECT_PATH	"/org/freedesktop/ModemManager"
#define NI_MM_INTERFACE		"org.freedesktop.ModemManager"
#define NI_MM_DEV_PATH_PFX	"/org/freedesktop/ModemManager/Modems/"
#define NI_MM_MODEM_IF		"org.freedesktop.ModemManager.Modem"
#define NI_MM_GSM_CARD_IF	"org.freedesktop.ModemManager.Modem.Gsm.Card"
#define NI_MM_GSM_NETWORK_IF	"org.freedesktop.ModemManager.Modem.Gsm.Network"
#define NI_MM_MODEM_SIMPLE_IF	"org.freedesktop.ModemManager.Modem.Simple"
#define NI_MM_MODEM_GSM_IF	"org.freedesktop.ModemManager.Modem.Gsm"

typedef struct ni_modem_manager_client ni_modem_manager_client_t;
struct ni_modem_manager_client {
	ni_dbus_client_t *	dbus;

	ni_dbus_object_t *	proxy;
};

static void			ni_modem_manager_add_modem(ni_modem_manager_client_t *modem_manager, const char *object_path);
static void			ni_modem_manager_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);
static void			ni_modem_unlink(ni_modem_t *);

static ni_dbus_class_t		ni_objectmodel_modem_manager_class = {
	.name		= "modem-manager"
};
static const ni_dbus_class_t *	ni_objectmodel_mm_modem_class_ptr;
static ni_dbus_service_t	ni_objectmodel_mm_modem_service;
static ni_dbus_service_t	ni_objectmodel_mm_gsm_modem_service;

static ni_modem_manager_client_t *ni_modem_manager_client;
static ni_modem_manager_event_handler_fn_t *ni_modem_manager_event_handler;

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

	ni_dbus_client_add_signal_handler(dbc,
				NI_MM_BUS_NAME,		/* sender */
				NULL,			/* object path */
				NI_MM_GSM_NETWORK_IF,	/* object interface */
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
ni_modem_manager_init(ni_modem_manager_event_handler_fn_t *event_handler)
{
	if (!ni_modem_manager_client) {
		ni_modem_manager_client_t *client;

		client = ni_modem_manager_client_open();
		if (!client)
			return FALSE;

		ni_objectmodel_register_modem_classes();
		ni_objectmodel_register_modem_services();

		ni_objectmodel_mm_modem_class_ptr = ni_objectmodel_get_class(NI_OBJECTMODEL_MM_MODEM_CLASS);

		ni_objectmodel_mm_modem_service.compatible = ni_objectmodel_mm_modem_class_ptr;
		ni_objectmodel_mm_gsm_modem_service.compatible = ni_objectmodel_mm_modem_get_class(MM_MODEM_TYPE_GSM);

		if (!ni_modem_manager_enumerate(client)) {
			ni_modem_manager_client_free(client);
			return FALSE;
		}

		ni_modem_manager_client = client;
	}

	ni_modem_manager_event_handler = event_handler;

	return TRUE;
}

/*
 * Given a modem object, look up the corresponding ModemManager object
 */
static ni_dbus_object_t *
__ni_modem_manager_object(const ni_modem_t *modem)
{
	if (ni_modem_manager_client == NULL)
		return NULL;

	return ni_dbus_object_find_descendant_by_handle(ni_modem_manager_client->proxy, modem);
}

/*
 * Get modem information - manufacturer, model, version
 */
int
ni_modem_manager_get_info(ni_modem_t *modem, ni_dbus_object_t *modem_object)
{
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	int rv = 0;

	if (!ni_dbus_object_call_variant(modem_object,
				NI_MM_MODEM_IF, "GetInfo",
				0, NULL, 1, &result, &error)) {
		rv = ni_dbus_get_error(&error, NULL);
	} else {
		const char *string;

		if (ni_dbus_struct_get_string(&result, 0, &string))
			ni_string_dup(&modem->identify.manufacturer, string);
		if (ni_dbus_struct_get_string(&result, 1, &string))
			ni_string_dup(&modem->identify.model, string);
		if (ni_dbus_struct_get_string(&result, 2, &string))
			ni_string_dup(&modem->identify.version, string);
	}

	ni_dbus_variant_destroy(&result);
	return rv;
}

/*
 * Unlock the modem
 */
int
ni_modem_manager_unlock(ni_modem_t *modem, const ni_modem_pin_t *pin)
{
	ni_dbus_object_t *modem_object;
	int rv = 0;

	if ((modem_object = __ni_modem_manager_object(modem)) == NULL)
		return -NI_ERROR_DEVICE_NOT_KNOWN;

	if (modem->type == MM_MODEM_TYPE_GSM) {
		rv = ni_dbus_object_call_simple(modem_object, NI_MM_GSM_CARD_IF,
				"SendPin",
				DBUS_TYPE_STRING, (void *) &pin->value,
				0, NULL);
	} else {
		ni_error("%s: not supported for this type of modem", __func__);
		return -NI_ERROR_DEVICE_NOT_COMPATIBLE;
	}

	return rv;
}

int
ni_modem_manager_enable(ni_modem_t *modem)
{
	ni_dbus_object_t *modem_object;
	int rv = 0;

	if ((modem_object = __ni_modem_manager_object(modem)) == NULL)
		return -NI_ERROR_DEVICE_NOT_KNOWN;

	if (modem->type == MM_MODEM_TYPE_GSM) {
#if 0
		dbus_bool_t enable = TRUE;

		rv = ni_dbus_object_call_simple(modem_object, NI_MM_MODEM_IF,
				"Enable",
				DBUS_TYPE_BOOLEAN, &enable,
				0, NULL);

		if (rv < 0)
			return rv;
#endif

		rv = ni_dbus_object_send_property_string(modem_object,
				NI_MM_MODEM_IF,
				"InitCommandOptional",
				"AT^U2DIAG=256", NULL);

		/* FIXME: refresh object properties, and call Gsm.Card.GetStatus
		 * to obtain the provider info */
		modem->enabled = TRUE;
	}

	return rv;
}

/*
 * Connect
 */
int
ni_modem_manager_connect(ni_modem_t *modem, const ni_modem_t *config)
{
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_variant_t dict = NI_DBUS_VARIANT_INIT;
	ni_dbus_object_t *modem_object;
	ni_modem_pin_t *pin = NULL;

	if ((modem_object = __ni_modem_manager_object(modem)) == NULL)
		return -NI_ERROR_DEVICE_NOT_KNOWN;

	if (!ni_string_empty(modem->unlock.required)) {
		if ((pin = ni_modem_get_pin(modem, modem->unlock.required)) == NULL)
			return -NI_ERROR_AUTH_INFO_MISSING;
	}

	ni_dbus_variant_init_dict(&dict);
	ni_dbus_dict_add_string(&dict, "number", "*99#");
	if (pin)
		ni_dbus_dict_add_string(&dict, "pin", pin->value);

	/* Other items to handle here:
	 * network_id - numeric ID of provider to select
	 * apn - APN id
	 * home_only - roaming not allowed
	 */

	/* FIXME: this call blocks until it managed to connect.
	 * Turn this into an async call and assign an adequate timeout.
	 */
	if (!ni_dbus_object_call_variant(modem_object,
				NI_MM_MODEM_SIMPLE_IF, "Connect",
				1, &dict, 0, NULL, &error)) {
		ni_dbus_variant_destroy(&dict);
		return ni_dbus_get_error(&error, NULL);
	}

	ni_dbus_variant_destroy(&dict);
	return 0;
}

int
ni_modem_manager_disconnect(ni_modem_t *modem)
{
	return -1;
}

/*
 * Support classes for objectmodel
 */
const char *
ni_objectmodel_mm_modem_get_classname(ni_modem_type_t type)
{
	switch (type) {
	case MM_MODEM_TYPE_GSM:
		return NI_OBJECTMODEL_MM_MODEM_GSM_CLASS;

	case MM_MODEM_TYPE_CDMA:
		return NI_OBJECTMODEL_MM_MODEM_CDMA_CLASS;

	default: ;
	}

	return NULL;
}

const ni_dbus_class_t *
ni_objectmodel_mm_modem_get_class(ni_modem_type_t type)
{
	const char *classname;

	if ((classname = ni_objectmodel_mm_modem_get_classname(type)) == NULL)
		return NULL;
	return ni_objectmodel_get_class(classname);
}

static void
ni_modem_manager_add_modem(ni_modem_manager_client_t *modem_manager, const char *object_path)
{
	DBusError error = DBUS_ERROR_INIT;
	ni_dbus_object_t *modem_object;
	const ni_dbus_class_t *class;
	ni_modem_t *modem;

	ni_debug_dbus("%s(%s)", __func__, object_path);

	modem = ni_modem_new();
	ni_string_dup(&modem->real_path, object_path);

	/* Create the DBus client object for this modem. */
	modem_object = ni_dbus_object_create(modem_manager->proxy, object_path, ni_objectmodel_mm_modem_class_ptr, modem);
	if (modem_object == NULL) {
		ni_modem_release(modem);
		return;
	}
	ni_dbus_object_set_default_interface(modem_object, NI_MM_MODEM_IF);

	/* Use Properties.GetAll() to refresh the properties of this modem */
	if (!ni_dbus_object_refresh_properties(modem_object, &ni_objectmodel_mm_modem_service, &error)) {
		ni_dbus_print_error(&error, "cannot update properties of %s", object_path);
		dbus_error_free(&error);
		return;
	}

	if (ni_modem_manager_get_info(modem, modem_object) < 0)
		ni_error("Cannot obtain model info for modem (%s)", object_path);

	/* Override the dbus class of this object */
	if ((class = ni_objectmodel_mm_modem_get_class(modem->type)) != NULL)
		modem_object->class = class;

	ni_debug_dbus("%s: dev=%s master=%s type=%u equipment-id=%s",
			object_path, modem->device, modem->master_device, modem->type,
			modem->identify.equipment);
	ni_objectmodel_bind_compatible_interfaces(modem_object);

	{
		ni_netconfig_t *nc = ni_global_state_handle(0);

		ni_netconfig_modem_append(nc, modem);
	}

	if (ni_modem_manager_event_handler) {
		ni_modem_manager_event_handler(modem, NI_EVENT_DEVICE_CREATE);
		/* TODO: we don't wait for udev here, code disabled anyway */
		ni_modem_manager_event_handler(modem, NI_EVENT_DEVICE_READY);
	}
}

static void
ni_modem_manager_remove_modem(ni_modem_manager_client_t *modem_manager, const char *object_path)
{
	ni_dbus_object_t *modem_object;
	ni_modem_t *modem;

	ni_debug_dbus("%s(%s)", __func__, object_path);

	modem_object = ni_dbus_object_lookup(modem_manager->proxy, object_path);
	if (modem_object == NULL) {
		ni_warn("%s: spurious remove event, cannot find object \"%s\"", __func__, object_path);
		return;
	}

	if ((modem = ni_objectmodel_unwrap_modem(modem_object, NULL)) != NULL) {
		if (ni_modem_manager_event_handler)
			ni_modem_manager_event_handler(modem, NI_EVENT_DEVICE_DELETE);
		ni_modem_unlink(modem);
	}

	ni_dbus_object_free(modem_object);
}

static ni_modem_t *
ni_modem_manager_get_modem(ni_modem_manager_client_t *modem_manager, const char *object_path)
{
	ni_dbus_object_t *modem_object;

	if (!(modem_object = ni_dbus_object_lookup(modem_manager->proxy, object_path))) {
		ni_error("%s: cannot handle event for modem object \"%s\", bad path", __func__, object_path);
		return NULL;
	}

	return ni_objectmodel_unwrap_modem(modem_object, NULL);
}

/*
 * Constructor/destructor for modem objects
 */
ni_modem_t *
ni_modem_new(void)
{
	ni_modem_t *modem;

	modem = xcalloc(1, sizeof(ni_modem_t));
	modem->refcount = 1;
	modem->use_lock_file = TRUE;
	return modem;
}

void
ni_modem_free(ni_modem_t *modem)
{
	ni_assert(modem->refcount == 0);
	ni_string_free(&modem->device);
	ni_string_free(&modem->master_device);
	ni_string_free(&modem->driver);
	ni_string_free(&modem->unlock.required);
	ni_string_free(&modem->identify.manufacturer);
	ni_string_free(&modem->identify.model);
	ni_string_free(&modem->identify.version);
	ni_string_free(&modem->identify.device);
	ni_string_free(&modem->identify.equipment);
	ni_string_free(&modem->gsm.imei);
	ni_string_free(&modem->gsm.operator_code);
	ni_string_free(&modem->gsm.operator_name);
	ni_string_free(&modem->pots.number);
	ni_modem_unlink(modem);

	if (modem->unlock.auth) {
		ni_modem_pin_t *pin;

		while ((pin = modem->unlock.auth) != NULL) {
			modem->unlock.auth = pin->next;
			ni_modem_pin_free(pin);
		}
	}

	ni_modem_set_client_state(modem, NULL);
	free(modem);
}

ni_modem_t *
ni_modem_hold(ni_modem_t *modem)
{
	ni_assert(modem->refcount);
	modem->refcount++;
	return modem;
}

void
ni_modem_release(ni_modem_t *modem)
{
	ni_assert(modem->refcount != 0);
	if (--(modem->refcount) == 0)
		ni_modem_free(modem);
}

void
ni_modem_set_client_state(ni_modem_t *modem, ni_client_state_t *client_state)
{
	if (modem->client_state == client_state)
		return;
	if (modem->client_state)
		ni_client_state_free(modem->client_state);

	modem->client_state = client_state;
}

ni_client_state_t *
ni_modem_get_client_state(ni_modem_t *dev)
{
	if (!dev)
		return NULL;

	if (!dev->client_state)
		dev->client_state = ni_client_state_new();

	return dev->client_state;
}

/*
 * Remove the modem from the linked list attached to ni_netconfig_t
 */
void
ni_modem_unlink(ni_modem_t *modem)
{
	ni_modem_t **prev = modem->list.prev;
	ni_modem_t *next = modem->list.next;

	if (prev)
		*prev = next;
	if (next)
		next->list.prev = prev;

	modem->list.prev = NULL;
	modem->list.next = NULL;
}

/*
 * Handle modem auth information
 */
ni_modem_pin_t *
ni_modem_pin_new(const char *kind, const char *value)
{
	ni_modem_pin_t *pin;

	pin = xcalloc(1, sizeof(*pin));
	ni_string_dup(&pin->kind, kind);
	ni_string_dup(&pin->value, value);

	return pin;
}

void
ni_modem_pin_free(ni_modem_pin_t *pin)
{
	ni_string_free(&pin->kind);
	ni_string_free(&pin->value);
	free(pin);
}

void
ni_modem_add_pin(ni_modem_t *modem, ni_modem_pin_t *pin)
{
	ni_modem_pin_t **pos, *rover;

	pos = &modem->unlock.auth;
	while ((rover = *pos) != NULL) {
		if (ni_string_eq(rover->kind, pin->kind)) {
			*pos = rover->next;
			ni_modem_pin_free(rover);
		} else {
			pos = &rover->next;
		}
	}

	*pos = pin;
}

ni_modem_pin_t *
ni_modem_get_pin(ni_modem_t *modem, const char *tag)
{
	ni_modem_pin_t *pin;

	for (pin = modem->unlock.auth; pin; pin = pin->next) {
		if (ni_string_eq(pin->kind, tag))
			return pin;
	}

	return NULL;
}

/*
 * Properties for org.freedesktop.ModemManager.Modem
 */
static void *
ni_objectmodel_get_modem(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_modem(object, error);
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
	MODEM_UINT_PROPERTY(State, state, RO),
	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_mm_modem_service = {
	.name		= NI_MM_MODEM_IF,
	.compatible	= NULL,		/* will be filled in later */
	.properties	= ni_objectmodel_modem_property_table,
};

const ni_dbus_property_t        ni_objectmodel_gsm_modem_property_table[] = {
#ifdef broken
	/* Current ModemManager versions don't report anything useful here */
	MODEM_UINT_PROPERTY(SupportedBands, gsm.supported_bands, RO),
	MODEM_UINT_PROPERTY(SupportedModes, gsm.supported_modes, RO),
#endif
	{ NULL }
};

static ni_dbus_service_t	ni_objectmodel_mm_gsm_modem_service = {
	.name		= NI_MM_GSM_CARD_IF,
	.compatible	= NULL,		/* will be filled in later */
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
	DBusMessageIter iter;
	DBusError error = DBUS_ERROR_INIT;

	ni_debug_dbus("%s: %s", __func__, member);
	dbus_message_iter_init(msg, &iter);
	if (!strcmp(member, NI_MM_SIGNAL_DEVICE_ADDED)) {
		const char *object_path;

		/* FIXME: use ni_dbus_message_get_args */
		if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_OBJECT_PATH
		 || dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&iter, &object_path);
			ni_modem_manager_add_modem(modem_manager, object_path);
		} else {
			ni_error("%s: unexpected argument type 0x%x",
					member, dbus_message_iter_get_arg_type(&iter));
		}
	} else
	if (!strcmp(member, NI_MM_SIGNAL_DEVICE_REMOVED)) {
		const char *object_path;

		/* FIXME: use ni_dbus_message_get_args */
		if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_OBJECT_PATH
		 || dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&iter, &object_path);
			ni_modem_manager_remove_modem(modem_manager, object_path);
		} else {
			ni_error("%s: unexpected argument type 0x%x",
					member, dbus_message_iter_get_arg_type(&iter));
		}
	} else
	if (!strcmp(member, NI_MM_SIGNAL_SIGNAL_QUALITY)) {
		const char *object_path = dbus_message_get_path(msg);
		ni_modem_t *modem;
		uint32_t quality;

		if ((modem = ni_modem_manager_get_modem(modem_manager, object_path)) == NULL) {
			ni_error("%s: cannot handle event %s for modem object \"%s\", bad path",
					__func__, member, object_path);
			return;
		}

		/* FIXME: use ni_dbus_message_get_args */
		if (!dbus_message_get_args(msg, &error, DBUS_TYPE_UINT32, &quality, DBUS_TYPE_INVALID))
			goto bad_vibes;

		ni_debug_modem("%s: quality changed %u -> %u", object_path,
				modem->gsm.signal_quality, quality);
		modem->gsm.signal_quality = quality;
	} else
	if (!strcmp(member, NI_MM_SIGNAL_REGISTRATION_INFO)) {
		const char *object_path = dbus_message_get_path(msg);
		ni_modem_t *modem;

		if ((modem = ni_modem_manager_get_modem(modem_manager, object_path)) == NULL) {
			ni_error("%s: cannot handle event %s for modem object \"%s\", bad path",
					__func__, member, object_path);
			return;
		} else {
			const char *oper_code = NULL, *oper_name = NULL;
			uint32_t status = MM_MODEM_GSM_NETWORK_REG_STATUS_IDLE;

			if (!dbus_message_get_args(msg, &error,
						DBUS_TYPE_UINT32, &status,
						DBUS_TYPE_STRING, &oper_code,
						DBUS_TYPE_STRING, &oper_name,
						DBUS_TYPE_INVALID, NULL))
				goto bad_vibes;

			ni_debug_modem("%s: reg info changed: status=%u, operator=%s (%s)",
				object_path, status, oper_code, oper_name);

			modem->gsm.reg_status = status;
			ni_string_dup(&modem->gsm.operator_code, oper_code);
			ni_string_dup(&modem->gsm.operator_name, oper_name);
		}
	} else
	if (!strcmp(member, NI_MM_SIGNAL_STATE_CHANGED)) {
		const char *object_path = dbus_message_get_path(msg);
		ni_modem_t *modem;

		if ((modem = ni_modem_manager_get_modem(modem_manager, object_path)) == NULL) {
			ni_error("%s: cannot handle event %s for modem object \"%s\", bad path",
					__func__, member, object_path);
			return;
		} else {
			uint32_t old_state, new_state, reason;

			if (!dbus_message_get_args(msg, &error,
						DBUS_TYPE_UINT32, &old_state,
						DBUS_TYPE_UINT32, &new_state,
						DBUS_TYPE_UINT32, &reason,
						DBUS_TYPE_INVALID, NULL))
				goto bad_vibes;

			ni_debug_modem("%s: state changed: %u -> %u", object_path, old_state, new_state);

			if (ni_modem_manager_event_handler) {
				if (modem->state < MM_MODEM_STATE_REGISTERED && new_state >= MM_MODEM_STATE_REGISTERED)
					ni_modem_manager_event_handler(modem, NI_EVENT_LINK_ASSOCIATED);
				else
				if (modem->state >= MM_MODEM_STATE_REGISTERED && new_state < MM_MODEM_STATE_REGISTERED)
					ni_modem_manager_event_handler(modem, NI_EVENT_LINK_ASSOCIATION_LOST);
				memset(&modem->event_uuid, 0, sizeof(modem->event_uuid));
			}

			modem->state = new_state;
		}
	} else
	if (!strcmp(member, NI_MM_SIGNAL_NETWORK_MODE)) {
		const char *object_path = dbus_message_get_path(msg);
		ni_modem_t *modem;

		if ((modem = ni_modem_manager_get_modem(modem_manager, object_path)) == NULL) {
			ni_error("%s: cannot handle event %s for modem object \"%s\", bad path",
					__func__, member, object_path);
			return;
		} else {
			uint32_t mode;

			if (!dbus_message_get_args(msg, &error,
						DBUS_TYPE_UINT32, &mode,
						DBUS_TYPE_INVALID, NULL))
				goto bad_vibes;

			ni_debug_modem("%s: network mode changed: %u", object_path, mode);
		}
	} else {
		ni_debug_objectmodel("%s signal received (not handled)", member);
	}

out:
	dbus_error_free(&error);
	return;

bad_vibes:
	ni_error("unable to process signal \"%s\" from object \"%s\"",
			member, dbus_message_get_path(msg));
	goto out;
}
