/*
 * DBus encapsulation for ppp interfaces
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/ppp.h>
#include <wicked/modem.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"
#include "util_priv.h"
#include "dbus-common.h"


#define NI_OBJECTMODEL_PPP_FACTORY_INTERFACE		NI_OBJECTMODEL_PPP_INTERFACE ".Factory"
#define NI_OBJECTMODEL_PPPOE_FACTORY_INTERFACE		NI_OBJECTMODEL_PPPOE_INTERFACE ".Factory"

typedef ni_netdev_t *	(*__get_device_arg_fn_t)(const ni_dbus_variant_t *, DBusError *);
static ni_netdev_t *	__ni_objectmodel_ppp_newlink(ni_netdev_t *, const char *, DBusError *);

/*
 * Create a new PPP interface
 * We're given two arguments, the interface name and the <ppp> configuration data.
 * However, we ignore all the config data at this point and just create the
 * device. The configuration data is consumed by a subsequent call to changeDevice
 * (where we build a config file from it).
 */
dbus_bool_t
ni_objectmodel_ppp_newlink(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error,
			__get_device_arg_fn_t get_device_arg_fn)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	const char *ifname = NULL;
	ni_netdev_t *dev, *dev_cfg;

	NI_TRACE_ENTER();

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);
	if (!(dev_cfg = get_device_arg_fn(&argv[1], error)))
		return FALSE;

	dev = __ni_objectmodel_ppp_newlink(dev_cfg, ifname, error);
	ni_netdev_put(dev_cfg);

	if (dev == NULL)
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_ppp_newlink(ni_netdev_t *cfg, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_dev = NULL;
	int rv;

	ni_debug_dbus("PPP.newDevice(name=%s)", ifname);

	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "ppp"))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create ppp - too many interfaces");
		return NULL;
	}

	if ((rv = ni_system_ppp_create(nc, ifname, cfg->ppp, &new_dev)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS
		 && (ifname != NULL && strcmp(ifname, new_dev->name))) {
			ni_dbus_set_error_from_code(error, rv,
					"unable to create PPP interface %s",
					ifname);
			return NULL;
		}
		ni_debug_dbus("PPP interface exists (and name matches)");
	}

	if (new_dev->link.type != NI_IFTYPE_PPP) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create PPP interface: new interface is of type %s",
				ni_linktype_type_to_name(new_dev->link.type));
		/* FIXME: delete device? */
		return NULL;
	}

	if (ni_ppp_write_config(new_dev->ppp) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create PPP interface: failed to write coniguration files");
		/* FIXME: delete device */
		return NULL;
	}

	return new_dev;
}

/*
 * Delete a PPP interface
 */
dbus_bool_t
ni_objectmodel_ppp_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;
	int rv;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if ((rv = ni_system_ppp_delete(dev)) < 0) {
		ni_dbus_set_error_from_code(error, rv,
				"Unable to delete PPP interface %s: %s",
				dev->name, ni_strerror(rv));
		return FALSE;
	}

	ni_client_state_drop(dev->name);
	ni_dbus_object_free(object);
	return TRUE;
}


/*
 * Support for PPP over serial
 */
static inline ni_netdev_t *
__ni_objectmodel_ppp_device_arg(const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_netdev_t *ppp_dev;
	const char *device_path;
	ni_dbus_object_t *device_object;
	ni_ppp_t *ppp;
	ni_modem_t *modem;

	if (!(ppp_dev = ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_PPP, &ni_objectmodel_ppp_service))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "Error unwrapping PPP device configuration");
		return NULL;
	}

	ppp = ni_netdev_get_ppp(ppp_dev);
	if (!ni_ppp_check_config(ppp) || !(device_path = ppp->config->device.object_path)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "No or incomplete PPP device configuration");
		return NULL;
	}

	device_object = ni_objectmodel_object_by_path(device_path);
	if (device_object == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"PPP device configuration references unknown object path \"%s\"", device_path);
		return NULL;
	}

	modem = ni_objectmodel_unwrap_modem(device_object, error);
	if (modem == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"PPP device configuration references incompatible object (expected a modem)");
		return NULL;
	}
	ppp->config->device.modem = ni_modem_hold(modem);
	ni_string_dup(&ppp->config->device.name, modem->device);

	return ppp_dev;
}

dbus_bool_t
ni_objectmodel_ppp_serial_newlink(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_ppp_newlink(factory_object, method, argc, argv, reply, error,
					__ni_objectmodel_ppp_device_arg);
}

/*
 * Support for PPP over Ethernet
 */
static inline ni_netdev_t *
__ni_objectmodel_pppoe_device_arg(const ni_dbus_variant_t *dict, DBusError *error)
{
	ni_netdev_t *ppp_dev, *eth_dev;
	const char *device_path;
	ni_dbus_object_t *device_object;
	ni_ppp_t *ppp;

	if (!(ppp_dev = ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_PPP, &ni_objectmodel_ppp_service))) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "Error unwrapping PPP device configuration");
		return NULL;
	}

	ppp = ni_netdev_get_ppp(ppp_dev);
	if (!ppp || !ppp->config || !(device_path = ppp->config->device.object_path)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "No or incomplete PPP device configuration");
		return NULL;
	}

	device_object = ni_objectmodel_object_by_path(device_path);
	if (device_object == NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"PPP device configuration references unknown object path \"%s\"", device_path);
		return NULL;
	}

	eth_dev = ni_objectmodel_unwrap_netif(device_object, error);
	if (eth_dev == NULL || !eth_dev->ethernet) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"PPP device configuration references incompatible object (expected an ethernet device)");
		return NULL;
	}
	ppp->config->device.ethernet = ni_netdev_get(eth_dev);
	ni_string_dup(&ppp->config->device.name, eth_dev->name);

	return ppp_dev;
}

dbus_bool_t
ni_objectmodel_pppoe_newlink(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	return ni_objectmodel_ppp_newlink(factory_object, method, argc, argv, reply, error,
					__ni_objectmodel_pppoe_device_arg);
}

/*
 * PPP device properties
 */
static ni_ppp_config_t *
__ni_objectmodel_ppp_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_ppp_t *ppp;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access) {
		if (!dev->ppp)
			return NULL;
		return dev->ppp->config;
	}

	ppp = ni_netdev_get_ppp(dev);
	if (!ppp->config)
		ppp->config = ni_ppp_config_new();
	return ppp->config;
}

#if 0
static ni_ppp_config_t *
__ni_objectmodel_ppp_write_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_ppp_handle(object, TRUE, error);
}

static ni_ppp_config_t *
__ni_objectmodel_ppp_read_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_ppp_handle(object, FALSE, error);
}
#endif

static void *
ni_objectmodel_get_ppp_config(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_ppp_handle(object, write_access, error);
}

static void *
ni_objectmodel_get_ppp_authconfig(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_ppp_config_t *ppp_config;

	if (!(ppp_config = __ni_objectmodel_ppp_handle(object, write_access, error)))
		return NULL;

	if (!ppp_config->auth && write_access)
		ppp_config->auth = ni_ppp_authconfig_new();
	return ppp_config->auth;
}

#define PPPCFG_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(ppp_config, dbus_type, type, rw)
#define PPPCFG_UINT_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(ppp_config, dbus_type, type, rw)
#define PPPCFG_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __ni_objectmodel_ppp_config, rw)
#define PPPAUTH_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(ppp_authconfig, dbus_type, type, rw)

/*
 * Authentication properties are wrapped into a separate <auth> element
 */
const ni_dbus_property_t	ni_objectmodel_ppp_auth_property_table[] = {
	PPPAUTH_STRING_PROPERTY(user, username, RO),
	PPPAUTH_STRING_PROPERTY(password, password, RO),
	PPPAUTH_STRING_PROPERTY(hostname, hostname, RO),

	{ NULL }
};

const ni_dbus_property_t	ni_objectmodel_ppp_property_table[] = {
	PPPCFG_STRING_PROPERTY(device, device.object_path, RO),
	PPPCFG_STRING_PROPERTY(number, number, RO),
	PPPCFG_UINT_PROPERTY(mru, mru, RO),
	PPPCFG_UINT_PROPERTY(idle-timeout, idle_timeout, RO),

	NI_DBUS_GENERIC_DICT_PROPERTY(auth, ni_objectmodel_ppp_auth_property_table, RO),

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ppp_methods[] = {
	{ "deleteDevice",	"",			ni_objectmodel_ppp_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ppp_factory_methods[] = {
	{ "newDevice",		"sa{sv}",		ni_objectmodel_ppp_serial_newlink },

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_pppoe_factory_methods[] = {
	{ "newDevice",		"sa{sv}",		ni_objectmodel_pppoe_newlink },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_ppp_factory_service = {
	.name		= NI_OBJECTMODEL_PPP_FACTORY_INTERFACE,
	.methods	= ni_objectmodel_ppp_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_pppoe_factory_service = {
	.name		= NI_OBJECTMODEL_PPPOE_FACTORY_INTERFACE,
	.methods	= ni_objectmodel_pppoe_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_ppp_service = {
	.name		= NI_OBJECTMODEL_PPP_INTERFACE,
	.methods	= ni_objectmodel_ppp_methods,
	.properties	= ni_objectmodel_ppp_property_table,
};


