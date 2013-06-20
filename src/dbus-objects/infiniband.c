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
__ni_objectmodel_ib_newchild(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_ifp = NULL;
	const ni_infiniband_t *ib;
	const char *err;
	int rv;

	if (!ifname) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
			"Unable to create infiniband child interface - name argument missed");
		goto out;
	} else if (!ni_string_eq(cfg_ifp->name, ifname)) {
		ni_string_dup(&cfg_ifp->name, ifname);
	}

	ib = ni_netdev_get_infiniband(cfg_ifp);
	if ((err = ni_infiniband_validate(NI_IFTYPE_INFINIBAND_CHILD, ib)) != NULL) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "%s", err);
		goto out;
	}

	if ((rv = ni_system_infiniband_child_create(nc, cfg_ifp->name, ib, &new_ifp)) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create infiniband child interface: %s",
				ni_strerror(rv));
		goto out;
	}

	if (new_ifp->link.type != NI_IFTYPE_INFINIBAND_CHILD) {
		dbus_set_error(error,
			DBUS_ERROR_FAILED,
			"Unable to create infiniband child interface: it exists with type %s",
			ni_linktype_type_to_name(new_ifp->link.type));
                ni_netdev_put(new_ifp);
                new_ifp = NULL;
        }

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return new_ifp;
}

static dbus_bool_t
ni_objectmodel_ib_newchild(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
				unsigned int argc, const ni_dbus_variant_t *argv,
				ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *ifp;
	const char *ifname = NULL;

	NI_TRACE_ENTER();

	if (argc != 2 || !ni_dbus_variant_get_string(&argv[0], &ifname) || !ifname ||
	    !(ifp = __ni_objectmodel_ibchild_device_arg(&argv[1]))) {
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);
	}

	if (!(ifp = __ni_objectmodel_ib_newchild(ifp, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, ifp, NULL, error);
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

	ni_dbus_object_free(object);
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

		if ((err = ni_infiniband_validate(ifp->link.type, cfg->infiniband))) {
			dbus_set_error(error, DBUS_ERROR_FAILED, "%s", err);
			goto out;
		}

		if (ni_system_infiniband_setup(nc, ifp, cfg->infiniband) < 0) {
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
void *
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

void *
ni_objectmodel_get_infiniband(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_infiniband_handle(object, write_access, error);
}

#define IB_STRING_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(infiniband, dbus_type, type, rw)
#define IB_UINT_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(infiniband, dbus_type, type, rw)
#define IB_UINT32_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT32_PROPERTY(infiniband, dbus_type, type, rw)
#define IB_UINT16_PROPERTY(dbus_type, type, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(infiniband, dbus_type, type, rw)

const ni_dbus_property_t	ni_objectmodel_ibparent_property_table[] = {
	IB_UINT32_PROPERTY(mode,	mode,	RO),
	IB_UINT32_PROPERTY(multicast,	umcast,	RO),
	IB_UINT16_PROPERTY(pkey,        pkey,	RO),	/* read-only */
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ibparent_methods[] = {
	{ "changeDevice",	"a{sv}",		ni_objectmodel_ib_setup },
	{ NULL }
};

const ni_dbus_property_t	ni_objectmodel_ibchild_property_table[] = {
	IB_UINT32_PROPERTY(mode,	mode,	RO),
	IB_UINT32_PROPERTY(multicast,	umcast,	RO),
	IB_UINT16_PROPERTY(pkey,        pkey,	RO),	/* read-write */
	IB_STRING_PROPERTY(parent,      parent.name, RO),
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ibchild_methods[] = {
	{ "changeDevice",	"a{sv}",		ni_objectmodel_ib_setup  },
	{ "deleteDevice",	"",			ni_objectmodel_ib_delete },
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_ibchild_factory_methods[] = {
	{ "newDevice",		"sa{sv}",		ni_objectmodel_ib_newchild},
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

