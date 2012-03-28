/*
 * DBus encapsulation for bonding interfaces
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
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
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/bonding.h>
#include <wicked/dbus-errors.h>
#include "dbus-common.h"
#include "model.h"
#include "debug.h"

static ni_netdev_t *	__ni_objectmodel_bond_device_arg(const ni_dbus_variant_t *);
static ni_netdev_t *	__ni_objectmodel_bond_newlink(ni_netdev_t *, const char *, DBusError *);

/*
 * Return an interface handle containing all bridge-specific information provided
 * by the dict argument
 */
static inline ni_netdev_t *
__ni_objectmodel_bond_device_arg(const ni_dbus_variant_t *dict)
{
	return ni_objectmodel_get_netif_argument(dict, NI_IFTYPE_BOND, &ni_objectmodel_bond_service);
}

/*
 * Create a new bonding interface
 */
static dbus_bool_t
ni_objectmodel_new_bond(ni_dbus_object_t *factory_object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_dbus_server_t *server = ni_dbus_object_get_server(factory_object);
	ni_netdev_t *ifp;
	const char *ifname = NULL;

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(ifp = __ni_objectmodel_bond_device_arg(&argv[1])))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);

	if (!(ifp = __ni_objectmodel_bond_newlink(ifp, ifname, error)))
		return FALSE;

	return ni_objectmodel_device_factory_result(server, reply, ifp, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_bond_newlink(ni_netdev_t *cfg_ifp, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *new_ifp = NULL;
	const ni_bonding_t *bond;
	int rv;

	bond = ni_netdev_get_bonding(cfg_ifp);

	if (ifname == NULL && !(ifname = ni_netdev_make_name(nc, "bond"))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Unable to create bonding interface - too many interfaces");
		goto out;
	}
	ni_string_dup(&cfg_ifp->name, ifname);

	if ((rv = ni_system_bond_create(nc, cfg_ifp->name, bond, &new_ifp)) < 0) {
		if (rv != -NI_ERROR_INTERFACE_EXISTS
		 && (ifname != NULL && strcmp(ifname, new_ifp->name))) {
			dbus_set_error(error,
					DBUS_ERROR_FAILED,
					"Unable to create bonding interface: %s",
					ni_strerror(rv));
			goto out;
		}
		ni_debug_dbus("Bonding interface exists (and name matches)");
	}

	if (new_ifp->link.type != NI_IFTYPE_BOND) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create bonding interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		ni_netdev_put(new_ifp);
		new_ifp = NULL;
	}

out:
	if (cfg_ifp)
		ni_netdev_put(cfg_ifp);
	return new_ifp;
}

/*
 * Bonding.changeDevice method
 */
static dbus_bool_t
ni_objectmodel_bond_setup(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *ifp, *cfg;
	dbus_bool_t rv = FALSE;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	if (!(cfg = __ni_objectmodel_bond_device_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (ni_system_bond_setup(nc, ifp, cfg->bonding) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "failed to set up bonding device");
		goto out;
	}

	rv = TRUE;

out:
	if (cfg)
		ni_netdev_put(cfg);
	return rv;
}

/*
 * Bonding.delete method
 */
static dbus_bool_t
__ni_objectmodel_delete_bond(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *ifp;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("ifp=%s", ifp->name);
	if (ni_system_bond_delete(nc, ifp) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting bonding interface", ifp->name);
		return FALSE;
	}

	ni_dbus_object_free(object);
	return TRUE;
}


/*
 * Helper function to obtain bonding config from dbus object
 */
static ni_bonding_t *
__ni_objectmodel_get_bonding(const ni_dbus_object_t *object, DBusError *error)
{
	ni_netdev_t *ifp;
	ni_bonding_t *bond;

	if (!(ifp = ni_objectmodel_unwrap_interface(object, error)))
		return NULL;

	if (!(bond = ni_netdev_get_bonding(ifp))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting bonding handle for interface");
		return NULL;
	}
	return bond;
}

static void *
ni_objectmodel_get_bonding(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_get_bonding(object, error);
}

/*
 * Get/set MII monitoring info
 */
static dbus_bool_t
__ni_objectmodel_bonding_get_miimon(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;

	if (!(bond = __ni_objectmodel_get_bonding(object, error)))
		return FALSE;

	if (bond->monitoring != NI_BOND_MONITOR_MII)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	ni_dbus_dict_add_uint32(result, "frequency", bond->miimon.frequency);
	ni_dbus_dict_add_uint32(result, "updelay", bond->miimon.updelay);
	ni_dbus_dict_add_uint32(result, "downdelay", bond->miimon.downdelay);
	ni_dbus_dict_add_uint32(result, "carrier-detect", bond->miimon.carrier_detect);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_bonding_set_miimon(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;

	if (!(bond = __ni_objectmodel_get_bonding(object, error)))
		return FALSE;

	bond->monitoring = NI_BOND_MONITOR_MII;

	ni_dbus_dict_get_uint32(result, "frequency", &bond->miimon.frequency);
	ni_dbus_dict_get_uint32(result, "updelay", &bond->miimon.updelay);
	ni_dbus_dict_get_uint32(result, "downdelay", &bond->miimon.downdelay);
	ni_dbus_dict_get_uint32(result, "carrier-detect", &bond->miimon.carrier_detect);
	return TRUE;
}

/*
 * Get/set ARP monitoring info
 */
static dbus_bool_t
__ni_objectmodel_bonding_get_arpmon(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;
	ni_dbus_variant_t *var;

	if (!(bond = __ni_objectmodel_get_bonding(object, error)))
		return FALSE;

	if (bond->monitoring != NI_BOND_MONITOR_ARP)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	ni_dbus_dict_add_uint32(result, "interval", bond->arpmon.interval);
	ni_dbus_dict_add_uint32(result, "validate", bond->arpmon.validate);
	var = ni_dbus_dict_add(result, "targets");
	ni_dbus_variant_set_string_array(var,
			(const char **) bond->arpmon.targets.data,
			bond->arpmon.targets.count);
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_bonding_set_arpmon(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;
	ni_dbus_variant_t *var;

	if (!(bond = __ni_objectmodel_get_bonding(object, error)))
		return FALSE;

	bond->monitoring = NI_BOND_MONITOR_ARP;
	ni_dbus_dict_get_uint32(result, "interval", &bond->arpmon.interval);
	ni_dbus_dict_get_uint32(result, "validate", &bond->arpmon.validate);
	if ((var = ni_dbus_dict_get(result, "targets")) != NULL) {
		unsigned int i;

		if (!ni_dbus_variant_is_string_array(var)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s property - expected string array for attribute targets",
				object->path, property->name);
			return FALSE;
		}

		for (i = 0; i < var->array.len; ++i) {
			const char *s = var->string_array_value[i];

			ni_string_array_append(&bond->arpmon.targets, s);
		}
	}

	return TRUE;
}

/*
 * Get/set the list of slaves
 */
static dbus_bool_t
__ni_objectmodel_bonding_get_slaves(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;
	unsigned int i;

	if (!(bond = __ni_objectmodel_get_bonding(object, error)))
		return FALSE;

	ni_dbus_dict_array_init(result);
	for (i = 0; i < bond->slave_names.count; ++i) {
		const char *slave_name = bond->slave_names.data[i];
		ni_dbus_variant_t *slave;

		slave = ni_dbus_dict_array_add(result);

		ni_dbus_dict_add_string(slave, "device", slave_name);
		if (bond->primary && ni_string_eq(bond->primary, slave_name))
			ni_dbus_dict_add_bool(slave, "primary", TRUE);
	}

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_bonding_set_slaves(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;
	ni_dbus_variant_t *var;
	unsigned int i;

	if (!(bond = __ni_objectmodel_get_bonding(object, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict_array(result)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s property - expected dict array",
				object->path, property->name);
		return FALSE;
	}

	ni_string_free(&bond->primary);
	for (i = 0, var = result->variant_array_value; i < result->array.len; ++i, ++var) {
		dbus_bool_t is_primary = FALSE;
		const char *slave_name;

		if (!ni_dbus_dict_get_string(var, "device", &slave_name)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s.%s property - missing device attribute",
					object->path, property->name);
			return FALSE;
		}
		ni_string_array_append(&bond->slave_names, slave_name);

		if (ni_dbus_dict_get_bool(var, "primary", &is_primary) && is_primary) {
			if (bond->primary) {
				dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s.%s property - duplicate primary device",
					object->path, property->name);
				return FALSE;
			}
			ni_string_dup(&bond->primary, slave_name);
		}
	}
	return TRUE;
}

#define BONDING_INT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT_PROPERTY(bonding, dbus_name, member_name, rw)
#define BONDING_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(bonding, dbus_name, member_name, rw)
#define BONDING_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(bonding, dbus_name, member_name, rw)
#define BONDING_STRING_ARRAY_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(bonding, dbus_name, member_name, rw)

static ni_dbus_property_t	ni_objectmodel_bond_properties[] = {
	BONDING_UINT_PROPERTY(mode, mode, RO),
	BONDING_STRING_PROPERTY(primary, primary, RO),
	BONDING_UINT_PROPERTY(xmit-hash-policy, xmit_hash_policy, RO),

	__NI_DBUS_PROPERTY(
			DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE,
			slaves, __ni_objectmodel_bonding, RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			miimon, __ni_objectmodel_bonding, RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			arpmon, __ni_objectmodel_bonding, RO),

	{ NULL }
};


static ni_dbus_method_t		ni_objectmodel_bond_methods[] = {
	{ "changeDevice",	"",				ni_objectmodel_bond_setup },
	{ "deleteDevice",	"",				__ni_objectmodel_delete_bond },
#if 0
	{ "addSlave",		DBUS_TYPE_OJECT_AS_STRING,	__ni_objectmodel_bond_add_slave },
	{ "removeSlave",	DBUS_TYPE_OJECT_AS_STRING,	__ni_objectmodel_bond_remove_slave },
#endif
	{ NULL }
};

static ni_dbus_method_t		ni_objectmodel_bond_factory_methods[] = {
	{ "newDevice",		"sa{sv}",			ni_objectmodel_new_bond },

	{ NULL }
};

ni_dbus_service_t	ni_objectmodel_bond_service = {
	.name		= NI_OBJECTMODEL_BONDING_INTERFACE,
	.methods	= ni_objectmodel_bond_methods,
	.properties	= ni_objectmodel_bond_properties,
};

ni_dbus_service_t	ni_objectmodel_bond_factory_service = {
	.name		= NI_OBJECTMODEL_BONDING_INTERFACE ".Factory",
	.methods	= ni_objectmodel_bond_factory_methods,
};
