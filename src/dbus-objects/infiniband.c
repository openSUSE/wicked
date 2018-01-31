/*
 * DBus encapsulation for Infiniband interfaces
 *
 * Copyright (C) 2013 Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/infiniband.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "model.h"
#include "debug.h"


/*
 * Return an interface handle containing all ib-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_ibparent_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_INFINIBAND,
						&ni_objectmodel_ibparent_service);
}
static inline ni_netdev_t *
__ni_objectmodel_ibchild_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_INFINIBAND_CHILD,
						&ni_objectmodel_ibchild_service);
}

/*
 * InfinibandChild.Factory.newDevice:
 * Create a new infiniband child interface
 */
static ni_netdev_t *
__ni_objectmodel_ib_newchild(ni_netdev_t *cfg, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev = NULL;
	const ni_infiniband_t *ib;
	const char *err;
	int rv;

	ib = ni_netdev_get_infiniband(cfg);
	if ((err = ni_infiniband_validate(NI_IFTYPE_INFINIBAND_CHILD,
					ib, &cfg->link.lowerdev)) != NULL) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS, "%s", err);
		return NULL;
	}

	if (ni_string_empty(ifname)) {
		if (ni_string_empty(cfg->name) &&
		    !ni_string_printf(&cfg->name, "%s.%04x",
					cfg->link.lowerdev.name, ib->pkey)) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create infiniband child: "
				"name argument missed, failed to construct");
			return NULL;
		}
		ifname = NULL;
	} else if (!ni_string_eq(cfg->name, ifname)) {
		ni_string_dup(&cfg->name, ifname);
	}

	if (ni_string_eq(cfg->name, cfg->link.lowerdev.name)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
			"Cannot to create infiniband child: "
			"child name %s equal with parent device name",
			cfg->name);
		return NULL;
	}

	if ((rv = ni_system_infiniband_child_create(nc, cfg, &dev)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || !dev
		|| (ifname && dev && !ni_string_eq(ifname, dev->name))) {
			dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create infiniband child interface: %s",
				ni_strerror(rv));
			return NULL;
		}
	}

	if (dev && dev->link.type != NI_IFTYPE_INFINIBAND_CHILD) {
		dbus_set_error(error,
			DBUS_ERROR_FAILED,
			"Unable to create infiniband child interface %s: it exists with type %s",
			cfg->name, ni_linktype_type_to_name(dev->link.type));
		return NULL;
        }

	return dev;
}

static dbus_bool_t
ni_objectmodel_ib_newchild(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
				unsigned int argc, const ni_dbus_variant_t *argv,
				ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *cfg, *dev;
	const char *ifname = NULL;

	NI_TRACE_ENTER();

	if (argc != 2 || !ni_dbus_variant_get_string(&argv[0], &ifname) || !ifname ||
	    !(cfg = __ni_objectmodel_ibchild_device_arg(&argv[1]))) {
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);
	}

	if (!(dev = __ni_objectmodel_ib_newchild(cfg, ifname, error))) {
		ni_netdev_put(cfg);
		return FALSE;
	}
	ni_netdev_put(cfg);

	return ni_objectmodel_netif_factory_result(server, reply, dev, NULL, error);
}


/*
 * InfinibandChild.delete method
 */
static dbus_bool_t
ni_objectmodel_ib_delete(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *ifp;

	if (!(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("ifp=%s", ifp->name);
	if (ni_system_infiniband_child_delete(ifp) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Unable to delete infiniband child interface", ifp->name);
		return FALSE;
	}

	ni_client_state_drop(ifp->link.ifindex);
	return TRUE;
}

/*
 * Infiniband(Child).changeDevice method
 */
static dbus_bool_t
ni_objectmodel_ib_setup(ni_dbus_object_t *object, const ni_dbus_method_t *method,
				unsigned int argc, const ni_dbus_variant_t *argv,
				ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *ifp, *cfg;
	dbus_bool_t rv = FALSE;

	/* we've already checked that argv matches our signature */
	if (argc != 1 || !(ifp = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	if (ifp->link.type == NI_IFTYPE_INFINIBAND) {
		cfg = __ni_objectmodel_ibparent_device_arg(&argv[0]);
	} else
	if (ifp->link.type == NI_IFTYPE_INFINIBAND_CHILD) {
		cfg = __ni_objectmodel_ibchild_device_arg(&argv[0]);
	} else {
		cfg = NULL;
	}
	if (!cfg) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	/* when <infiniband/> node is empty (defaults only), skip setup */
	if (cfg->infiniband) {
		const char *err;

		if ((err = ni_infiniband_validate(ifp->link.type, cfg->infiniband,
							&cfg->link.lowerdev))) {
			dbus_set_error(error, DBUS_ERROR_FAILED, "%s", err);
			goto out;
		}

		if (ni_system_infiniband_setup(nc, ifp, cfg) < 0) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"failed to configure infiniband device %s",
					ifp->name);
			goto out;
		}
	}

	rv = TRUE;
out:
	if (cfg)
		ni_netdev_put(cfg);
	return rv;
}

/*
 * Helper function to obtain bridge config from dbus object
 */
static void *
ni_objectmodel_get_netdev(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return ni_objectmodel_unwrap_netif(object, error);
}

static ni_infiniband_t *
__ni_objectmodel_infiniband_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_infiniband_t *ib;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->infiniband;

	if (!(ib = ni_netdev_get_infiniband(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Error getting infiniband handle for interface");
		return NULL;
	}

	return ib;
}

static dbus_bool_t
ni_objectmodel_infiniband_get_multicast(const ni_dbus_object_t *object,
					const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	ni_infiniband_t *ib;

	if (!(ib = __ni_objectmodel_infiniband_handle(object, FALSE, error)))
		return FALSE;

	ni_dbus_variant_set_uint32(result, ib->umcast);
	return TRUE;
}


static dbus_bool_t
ni_objectmodel_infiniband_get_mode(	const ni_dbus_object_t *object,
					const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	ni_infiniband_t *ib;

	if (!(ib = __ni_objectmodel_infiniband_handle(object, FALSE, error)))
		return FALSE;

	ni_dbus_variant_set_uint32(result, ib->mode);
	return TRUE;
}


static dbus_bool_t
ni_objectmodel_infiniband_get_pkey(	const ni_dbus_object_t *object,
					const ni_dbus_property_t *property,
					ni_dbus_variant_t *result, DBusError *error)
{
	ni_infiniband_t *ib;

	if (!(ib = __ni_objectmodel_infiniband_handle(object, FALSE, error)))
		return FALSE;

	ni_dbus_variant_set_uint16(result, ib->pkey);
	return TRUE;
}

static dbus_bool_t
ni_objectmodel_infiniband_set_multicast(ni_dbus_object_t *object,
					const ni_dbus_property_t *property,
					const ni_dbus_variant_t *result, DBusError *error)
{
	ni_infiniband_t *ib;

	if (!(ib = __ni_objectmodel_infiniband_handle(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint32(result, &ib->umcast);
}

static dbus_bool_t
ni_objectmodel_infiniband_set_mode(	ni_dbus_object_t *object,
					const ni_dbus_property_t *property,
					const ni_dbus_variant_t *result, DBusError *error)
{
	ni_infiniband_t *ib;

	if (!(ib = __ni_objectmodel_infiniband_handle(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint32(result, &ib->mode);
}

static dbus_bool_t
ni_objectmodel_infiniband_set_pkey(	ni_dbus_object_t *object,
					const ni_dbus_property_t *property,
					const ni_dbus_variant_t *result, DBusError *error)
{
	ni_infiniband_t *ib;

	if (!(ib = __ni_objectmodel_infiniband_handle(object, TRUE, error)))
		return FALSE;

	return ni_dbus_variant_get_uint16(result, &ib->pkey);
}


#define IB_PROPERTY_SIGNATURE(signature, dbus_name, rw) \
		__NI_DBUS_PROPERTY(signature, dbus_name, ni_objectmodel_infiniband, rw)
#define IB_UINT32_PROPERTY(dbus_name, rw) \
		IB_PROPERTY_SIGNATURE(DBUS_TYPE_UINT32_AS_STRING, dbus_name, rw)
#define IB_UINT16_PROPERTY(dbus_name, rw) \
		IB_PROPERTY_SIGNATURE(DBUS_TYPE_UINT16_AS_STRING, dbus_name, rw)

const ni_dbus_property_t	ni_objectmodel_ibparent_property_table[] = {
	IB_UINT32_PROPERTY(mode,	RO),
	IB_UINT32_PROPERTY(multicast,	RO),
	IB_UINT16_PROPERTY(pkey,        RO),	/* read-only */

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ibparent_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_ib_setup },

	{ NULL }
};

const ni_dbus_property_t	ni_objectmodel_ibchild_property_table[] = {
	NI_DBUS_GENERIC_STRING_PROPERTY(netdev, device, link.lowerdev.name, RO),
	IB_UINT32_PROPERTY(mode,	RO),
	IB_UINT32_PROPERTY(multicast,	RO),
	IB_UINT16_PROPERTY(pkey,        RO),	/* read-write */

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ibchild_methods[] = {
	{ "changeDevice",	"a{sv}",	.handler = ni_objectmodel_ib_setup  },
	{ "deleteDevice",	"",		.handler = ni_objectmodel_ib_delete },

	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ibchild_factory_methods[] = {
	{ "newDevice",		"sa{sv}",	.handler = ni_objectmodel_ib_newchild},
	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_ibparent_service = {
	.name		= NI_OBJECTMODEL_INFINIBAND_INTERFACE,
	.methods	= ni_objectmodel_ibparent_methods,
	.properties	= ni_objectmodel_ibparent_property_table,
};

ni_dbus_service_t	ni_objectmodel_ibchild_factory_service = {
	.name		= NI_OBJECTMODEL_INFINIBAND_INTERFACE "Child.Factory",
	.methods	= ni_objectmodel_ibchild_factory_methods,
};

ni_dbus_service_t	ni_objectmodel_ibchild_service = {
	.name		= NI_OBJECTMODEL_INFINIBAND_INTERFACE "Child",
	.methods	= ni_objectmodel_ibchild_methods,
	.properties	= ni_objectmodel_ibchild_property_table,
};

