/*
 * DBus encapsulation for bonding interfaces
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

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
#include "dbus-common.h"
#include "model.h"
#include "debug.h"


/*
 * Create a new bonding interface
 */
ni_dbus_object_t *
ni_objectmodel_new_bond(ni_dbus_server_t *server, const ni_dbus_object_t *config, DBusError *error)
{
	ni_interface_t *cfg_ifp = ni_dbus_object_get_handle(config);
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_interface_t *new_ifp;
	const ni_bonding_t *bond;
	int rv;

	bond = ni_interface_get_bonding(cfg_ifp);

	cfg_ifp->link.type = NI_IFTYPE_BOND;
	if (cfg_ifp->name == NULL) {
		static char namebuf[64];
		unsigned int num;

		for (num = 0; num < 65536; ++num) {
			snprintf(namebuf, sizeof(namebuf), "bond%u", num);
			if (!ni_interface_by_name(nc, namebuf)) {
				ni_string_dup(&cfg_ifp->name, namebuf);
				break;
			}
		}

		if (cfg_ifp->name == NULL) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
					"Unable to create bonding interface - too many interfaces");
			return NULL;
		}
	}

	if ((rv = ni_system_bond_create(nc, cfg_ifp->name, bond, &new_ifp)) < 0) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create bonding interface: %s",
				ni_strerror(rv));
		return NULL;
	}

	if (new_ifp->link.type != NI_IFTYPE_BOND) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create bonding interface: new interface is of type %s",
				ni_linktype_type_to_name(new_ifp->link.type));
		return NULL;
	}

	return ni_objectmodel_register_interface(server, new_ifp);
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
	ni_interface_t *ifp = object->handle;

	NI_TRACE_ENTER_ARGS("ifp=%s", ifp->name);
	if (ni_system_bond_delete(nc, ifp) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting bonding interface", ifp->name);
		return FALSE;
	}

	/* FIXME: destroy the object */
	ni_dbus_object_free(object);

	return TRUE;
}


/*
 * Helper function to obtain bonding config from dbus object
 */
static ni_bonding_t *
__wicked_dbus_bond_handle(const ni_dbus_object_t *object, DBusError *error)
{
	ni_interface_t *ifp = ni_dbus_object_get_handle(object);

	return ni_interface_get_bonding(ifp);
}

/*
 * Get/set bonding mode
 */
static dbus_bool_t
__wicked_dbus_bond_get_mode(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;

	if (!(bond = __wicked_dbus_bond_handle(object, error)))
		return FALSE;

	ni_dbus_variant_set_uint32(result, bond->mode);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_bond_set_mode(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;
	unsigned int value;

	if (!(bond = __wicked_dbus_bond_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_uint(result, &value))
		return FALSE;
	bond->mode = value;
	return TRUE;
}

/*
 * Get/set monitoring mode
 */
static dbus_bool_t
__wicked_dbus_bond_get_monitor(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_dbus_variant_t *var;
	ni_bonding_t *bond;

	if (!(bond = __wicked_dbus_bond_handle(object, error)))
		return FALSE;

	ni_dbus_variant_init_dict(result);
	ni_dbus_dict_add_uint32(result, "mode", bond->monitoring);
	switch (bond->monitoring) {
	case NI_BOND_MONITOR_ARP:
		ni_dbus_dict_add_uint32(result, "arp-interval", bond->arpmon.interval);
		ni_dbus_dict_add_uint32(result, "arp-validate", bond->arpmon.validate);
		var = ni_dbus_dict_add(result, "arp-targets");
		ni_dbus_variant_set_string_array(var,
				(const char **) bond->arpmon.targets.data,
				bond->arpmon.targets.count);
		break;

	case NI_BOND_MONITOR_MII:
		ni_dbus_dict_add_uint32(result, "mii-frequency", bond->miimon.frequency);
		ni_dbus_dict_add_uint32(result, "mii-updelay", bond->miimon.updelay);
		ni_dbus_dict_add_uint32(result, "mii-downdelay", bond->miimon.downdelay);
		ni_dbus_dict_add_uint32(result, "mii-carrier-detect", bond->miimon.carrier_detect);
		break;
	}
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_bond_set_monitor(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;
	unsigned int value;

	if (!(bond = __wicked_dbus_bond_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_uint(result, &value))
		return FALSE;
	bond->monitoring = value;
	return TRUE;
}

#if 0
/*
 * Get/set underlying interface
 */
static dbus_bool_t
__wicked_dbus_bond_get_interface_name(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;

	if (!(bond = __wicked_dbus_bond_handle(object, error)))
		return FALSE;

	ni_dbus_variant_set_string(result, bond->physdev_name);
	return TRUE;
}

static dbus_bool_t
__wicked_dbus_bond_set_interface_name(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_bonding_t *bond;
	const char *physdev_name;

	if (!(bond = __wicked_dbus_bond_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_get_string(result, &physdev_name))
		return FALSE;
	ni_string_dup(&bond->physdev_name, physdev_name);
	return TRUE;
}
#endif

#define WICKED_BONDING_PROPERTY(type, __name, rw) \
	NI_DBUS_PROPERTY(type, __name, __wicked_dbus_bond, rw)
#define WICKED_BONDING_PROPERTY_SIGNATURE(signature, __name, rw) \
	__NI_DBUS_PROPERTY(signature, __name, __wicked_dbus_bond, rw)

static ni_dbus_property_t	wicked_dbus_bond_properties[] = {
	WICKED_BONDING_PROPERTY(UINT16, mode, RO),
	WICKED_BONDING_PROPERTY_SIGNATURE(NI_DBUS_DICT_SIGNATURE, monitor, RO),
	{ NULL }
};


static ni_dbus_method_t		wicked_dbus_bond_methods[] = {
	{ "delete",		"",		__ni_objectmodel_delete_bond },
	{ NULL }
};

ni_dbus_service_t	wicked_dbus_bond_service = {
	.name = WICKED_DBUS_BONDING_INTERFACE,
	.methods = wicked_dbus_bond_methods,
	.properties = wicked_dbus_bond_properties,
};

