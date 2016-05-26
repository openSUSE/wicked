/*
 * DBus encapsulation for bonding interfaces
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/system.h>
#include <wicked/bonding.h>
#include <wicked/address.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "dbus-common.h"
#include "model.h"
#include "debug.h"
#include "misc.h"

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
	ni_netdev_t *cfg;
	const char *ifname = NULL;

	ni_assert(argc == 2);
	if (!ni_dbus_variant_get_string(&argv[0], &ifname)
	 || !(cfg = __ni_objectmodel_bond_device_arg(&argv[1])))
		return ni_dbus_error_invalid_args(error, factory_object->path, method->name);

	if (!(cfg = __ni_objectmodel_bond_newlink(cfg, ifname, error)))
		return FALSE;

	return ni_objectmodel_netif_factory_result(server, reply, cfg, NULL, error);
}

static ni_netdev_t *
__ni_objectmodel_bond_newlink(ni_netdev_t *cfg, const char *ifname, DBusError *error)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_netdev_t *dev = NULL;
	int rv;

#if 0
	ni_netdev_get_bonding(cfg);
#endif

	if (ni_string_empty(ifname) && !(ifname = ni_netdev_make_name(nc, "bond", 0))) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create bonding interface - too many interfaces");
		goto out;
	}
	if (!ni_netdev_name_is_valid(ifname)) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create bonding interface - invalid interface name '%s'",
				ni_print_suspect(ifname, ni_string_len(ifname)));
		goto out;
	}
	ni_string_dup(&cfg->name, ifname);

	if (cfg->link.hwaddr.len) {
		/* the config address is opaque/void without a type set */
		if (cfg->link.hwaddr.len == ni_link_address_length(ARPHRD_ETHER)) {
			cfg->link.hwaddr.type = ARPHRD_ETHER;
			if (ni_link_address_is_invalid(&cfg->link.hwaddr)) {
				ni_warn("%s: cannot set invalid ethernet hardware address, ignoring '%s'",
						ifname, ni_link_address_print(&cfg->link.hwaddr));
				ni_link_address_init(&cfg->link.hwaddr);
			}
		} else
		if (cfg->link.hwaddr.len == ni_link_address_length(ARPHRD_INFINIBAND)) {
			ni_warn("%s: cannot set infiniband bonding hardware address, ignoring '%s'",
					ifname, ni_link_address_print(&cfg->link.hwaddr));
			ni_link_address_init(&cfg->link.hwaddr);
		} else {
			ni_warn("%s: cannot set unknown type hardware address, ignoring '%s'",
					ifname, ni_link_address_print(&cfg->link.hwaddr));
			ni_link_address_init(&cfg->link.hwaddr);
		}
	}

	if ((rv = ni_system_bond_create(nc, cfg, &dev)) < 0) {
		if (rv != -NI_ERROR_DEVICE_EXISTS || dev == NULL
		|| (ifname && dev && !ni_string_eq(ifname, dev->name))) {
			dbus_set_error(error, DBUS_ERROR_FAILED,
				"Unable to create bonding interface '%s'", ifname);
			dev = NULL;
			goto out;
		}
		ni_debug_dbus("Bonding interface exists (and name matches)");
	}

	if (dev->link.type != NI_IFTYPE_BOND) {
		dbus_set_error(error,
				DBUS_ERROR_FAILED,
				"Unable to create bonding interface: new interface is of type %s",
				ni_linktype_type_to_name(dev->link.type));
		dev = NULL;
	}

out:
	if (cfg)
		ni_netdev_put(cfg);
	return dev;
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
	ni_netdev_t *dev, *cfg;
	dbus_bool_t rv = FALSE;

	/* we've already checked that argv matches our signature */
	ni_assert(argc == 1);

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return ni_dbus_error_invalid_args(error, object->path, method->name);

	if (!(cfg = __ni_objectmodel_bond_device_arg(&argv[0]))) {
		ni_dbus_error_invalid_args(error, object->path, method->name);
		goto out;
	}

	if (cfg->link.hwaddr.len) {
		/* the config address is opaque/void without a type set */
		if (cfg->link.hwaddr.len == ni_link_address_length(ARPHRD_ETHER)) {
			cfg->link.hwaddr.type = ARPHRD_ETHER;
			if (ni_link_address_is_invalid(&cfg->link.hwaddr)) {
				ni_warn("%s: cannot set invalid ethernet hardware address, ignoring '%s'",
						dev->name, ni_link_address_print(&cfg->link.hwaddr));
				ni_link_address_init(&cfg->link.hwaddr);
			} else
			if (dev && cfg->link.hwaddr.type != dev->link.hwaddr.type) {
				ni_warn("%s: cannot set ethernet hardware address%s, ignoring '%s'",
						dev->name, dev->link.hwaddr.type == ARPHRD_INFINIBAND ?
						" on infiniband bonding" : "",
						ni_link_address_print(&cfg->link.hwaddr));
				ni_link_address_init(&cfg->link.hwaddr);
			} else
			if (ni_system_hwaddr_change(nc, dev, &cfg->link.hwaddr) < 0) {
				ni_error("%s: failed to set ethernet hardware address to '%s",
						dev->name, ni_link_address_print(&cfg->link.hwaddr));
				/* clear it, otherwise setup (link change) could fail too */
				ni_link_address_init(&cfg->link.hwaddr);
			}
		} else
		if (cfg->link.hwaddr.len == ni_link_address_length(ARPHRD_INFINIBAND)) {
			ni_warn("%s: cannot set infiniband bonding hardware address, ignoring '%s'",
					dev->name, ni_link_address_print(&cfg->link.hwaddr));
			ni_link_address_init(&cfg->link.hwaddr);
		} else {
			ni_warn("%s: cannot set unknown type hardware address, ignoring '%s'",
					dev->name, ni_link_address_print(&cfg->link.hwaddr));
			ni_link_address_init(&cfg->link.hwaddr);
		}
	}

	if (ni_system_bond_setup(nc, dev, cfg) < 0) {
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
 * Bonding.shutdown method
 */
static dbus_bool_t
__ni_objectmodel_shutdown_bond(ni_dbus_object_t *object, const ni_dbus_method_t *method,
			unsigned int argc, const ni_dbus_variant_t *argv,
			ni_dbus_message_t *reply, DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_bond_shutdown(dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error shutting bonding interface down", dev->name);
		return FALSE;
	}

	return TRUE;
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
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;

	NI_TRACE_ENTER_ARGS("dev=%s", dev->name);
	if (ni_system_bond_delete(nc, dev) < 0) {
		dbus_set_error(error, DBUS_ERROR_FAILED,
				"Error deleting bonding interface", dev->name);
		return FALSE;
	}

	ni_client_state_drop(dev->link.ifindex);
	return TRUE;
}


/*
 * Helper function to obtain bonding config from dbus object
 */
static ni_bonding_t *
__ni_objectmodel_bonding_handle(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	ni_netdev_t *dev;
	ni_bonding_t *bond;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return NULL;

	if (!write_access)
		return dev->bonding;

	if (!(bond = ni_netdev_get_bonding(dev))) {
		dbus_set_error(error, DBUS_ERROR_FAILED, "Error getting bonding handle for interface");
		return NULL;
	}
	return bond;
}

static ni_bonding_t *
__ni_objectmodel_bonding_write_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_bonding_handle(object, TRUE, error);
}

static const ni_bonding_t *
__ni_objectmodel_bonding_read_handle(const ni_dbus_object_t *object, DBusError *error)
{
	return __ni_objectmodel_bonding_handle(object, FALSE, error);
}

static void *
ni_objectmodel_get_bonding(const ni_dbus_object_t *object, ni_bool_t write_access, DBusError *error)
{
	return __ni_objectmodel_bonding_handle(object, write_access, error);
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
	const ni_bonding_t *bond;

	if (!(bond = __ni_objectmodel_bonding_read_handle(object, error)))
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

	if (!(bond = __ni_objectmodel_bonding_write_handle(object, error)))
		return FALSE;

	bond->monitoring |= NI_BOND_MONITOR_MII;

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
	const ni_bonding_t *bond;
	ni_dbus_variant_t *var;

	if (!(bond = __ni_objectmodel_bonding_read_handle(object, error)))
		return FALSE;

	if (bond->monitoring != NI_BOND_MONITOR_ARP)
		return ni_dbus_error_property_not_present(error, object->path, property->name);

	ni_dbus_dict_add_uint32(result, "interval", bond->arpmon.interval);
	ni_dbus_dict_add_uint32(result, "validate", bond->arpmon.validate);
	ni_dbus_dict_add_uint32(result, "validate-targets", bond->arpmon.validate_targets);
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

	if (!(bond = __ni_objectmodel_bonding_write_handle(object, error)))
		return FALSE;

	bond->monitoring |= NI_BOND_MONITOR_ARP;

	ni_dbus_dict_get_uint32(result, "interval", &bond->arpmon.interval);
	ni_dbus_dict_get_uint32(result, "validate", &bond->arpmon.validate);
	ni_dbus_dict_get_uint32(result, "validate-targets", &bond->arpmon.validate_targets);
	if ((var = ni_dbus_dict_get(result, "targets")) != NULL) {
		ni_bool_t valid = TRUE;
		unsigned int i;

		if (!ni_dbus_variant_is_string_array(var)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s property - expected string array for attribute targets",
				object->path, property->name);
			return FALSE;
		}

		for (i = 0; i < var->array.len; ++i) {
			const char *s = var->string_array_value[i];

			if (!ni_bonding_is_valid_arp_ip_target(s)) {
				valid = FALSE;
				break;
			}
			ni_string_array_append(&bond->arpmon.targets, s);
		}

		if (!valid) {
			ni_string_array_destroy(&bond->arpmon.targets);
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s property - invalid arp ip target adddress",
				object->path, property->name);
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * Helper for bond slave info
 */
static dbus_bool_t
__ni_objectmodel_bonding_slave_info_to_dict(const ni_bonding_slave_t *slave, ni_dbus_variant_t *dict, DBusError *error)
{
	if (!slave || !slave->info || !dict)
		return FALSE;

	if (slave->info->state != -1U)
		ni_dbus_dict_add_uint32(dict, "state", slave->info->state);

	if (slave->info->mii_status != -1U)
		ni_dbus_dict_add_uint32(dict, "mii-status", slave->info->mii_status);

	if (slave->info->perm_hwaddr.type == ARPHRD_ETHER && slave->info->perm_hwaddr.len)
		__ni_objectmodel_dict_add_hwaddr(dict, "perm-hwaddr", &slave->info->perm_hwaddr);

	if (slave->info->link_failure_count)
		ni_dbus_dict_add_uint32(dict, "link-failures", slave->info->link_failure_count);

	if (slave->info->queue_id != -1U)
		ni_dbus_dict_add_uint16(dict, "queue-id", slave->info->queue_id);

	if (slave->info->ad_aggregator_id != -1U)
		ni_dbus_dict_add_uint16(dict, "ad-aggregator-id", slave->info->ad_aggregator_id);

	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_bonding_slave_info_from_dict(ni_bonding_slave_t *slave, const ni_dbus_variant_t *dict, DBusError *error)
{
	uint32_t u32;
	uint16_t u16;

	if (!slave || !dict)
		return FALSE;

	if (dict->array.len == 0)
		return TRUE;

	if (slave->info)
		ni_bonding_slave_info_reset(slave->info);
	else if (!(slave->info = ni_bonding_slave_info_new()))
		return FALSE;

	if (ni_dbus_dict_get_uint32(dict, "state", &u32))
		slave->info->state = u32;

	if (ni_dbus_dict_get_uint32(dict, "mii-status", &u32))
		slave->info->mii_status = u32;

	if (__ni_objectmodel_dict_get_hwaddr(dict, "perm-hwaddr", &slave->info->perm_hwaddr)) {
		if (slave->info->perm_hwaddr.len == ni_link_address_length(ARPHRD_ETHER))
			slave->info->perm_hwaddr.type = ARPHRD_ETHER;
	}

	if (ni_dbus_dict_get_uint32(dict, "link-failures", &u32))
		slave->info->link_failure_count = u32;

	if (ni_dbus_dict_get_uint16(dict, "queue-id", &u16))
		slave->info->queue_id = u16;

	if (ni_dbus_dict_get_uint16(dict, "ad-aggregator-id", &u16))
		slave->info->ad_aggregator_id = u16;

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
	const ni_bonding_t *bond;
	unsigned int i;

	if (!(bond = __ni_objectmodel_bonding_read_handle(object, error)))
		return FALSE;

	ni_dbus_dict_array_init(result);
	for (i = 0; i < bond->slaves.count; ++i) {
		const ni_bonding_slave_t *slave = bond->slaves.data[i];
		const char *slave_name;
		ni_dbus_variant_t *dict;

		/* should not happen, but better safe than sorry */
		if (!slave || ni_string_empty(slave->device.name))
			continue;

		slave_name = slave->device.name;
		dict = ni_dbus_dict_array_add(result);

		ni_dbus_dict_add_string(dict, "device", slave_name);
		if (bond->primary_slave.name && ni_string_eq(bond->primary_slave.name, slave_name))
			ni_dbus_dict_add_bool(dict, "primary", TRUE);
		if (bond->active_slave.name && ni_string_eq(bond->active_slave.name, slave_name))
			ni_dbus_dict_add_bool(dict, "active", TRUE);

		__ni_objectmodel_bonding_slave_info_to_dict(slave, dict, error);
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

	if (!(bond = __ni_objectmodel_bonding_write_handle(object, error)))
		return FALSE;

	if (!ni_dbus_variant_is_dict_array(result)) {
		dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s property - expected dict array",
				object->path, property->name);
		return FALSE;
	}

	ni_netdev_ref_destroy(&bond->primary_slave);
	ni_netdev_ref_destroy(&bond->active_slave);
	ni_bonding_slave_array_destroy(&bond->slaves);
	for (i = 0, var = result->variant_array_value; i < result->array.len; ++i, ++var) {
		dbus_bool_t is_primary = FALSE;
		dbus_bool_t is_active = FALSE;
		ni_bonding_slave_t *slave;
		const char *slave_name;

		if (!ni_dbus_dict_get_string(var, "device", &slave_name) ||
				ni_string_empty(slave_name)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s.%s property - missing device attribute",
					object->path, property->name);
			return FALSE;
		}
		if (ni_bonding_has_slave(bond, slave_name)) {
			dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
				"%s.%s property - duplicate slave device %s",
				object->path, property->name, slave_name);
			return FALSE;
		}

		if (ni_dbus_dict_get_bool(var, "primary", &is_primary) && is_primary) {
			if (bond->primary_slave.name) {
				dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s.%s property - duplicate primary device",
					object->path, property->name);
				return FALSE;
			}
			ni_string_dup(&bond->primary_slave.name, slave_name);
		}
		if (ni_dbus_dict_get_bool(var, "active", &is_active) && is_active) {
			if (bond->active_slave.name) {
				dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
					"%s.%s property - duplicate active device",
					object->path, property->name);
				return FALSE;
			}
			ni_string_dup(&bond->active_slave.name, slave_name);
		}

		slave = ni_bonding_add_slave(bond, slave_name);
		if (slave)
			__ni_objectmodel_bonding_slave_info_from_dict(slave, var, error);
	}
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_bonding_get_ad_actor_system(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	const ni_bonding_t *bond;

	if (!(bond = __ni_objectmodel_bonding_read_handle(object, error)))
		return FALSE;
	return __ni_objectmodel_get_hwaddr(result, &bond->ad_actor_system);
}

static dbus_bool_t
__ni_objectmodel_bonding_set_ad_actor_system(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_bonding_t *bond;

	if (!(bond = __ni_objectmodel_bonding_write_handle(object, error)))
		return FALSE;

	ni_link_address_init(&bond->ad_actor_system);
	if (__ni_objectmodel_set_hwaddr(argument, &bond->ad_actor_system)) {
		if (bond->ad_actor_system.len == ni_link_address_length(ARPHRD_ETHER))
			bond->ad_actor_system.type = ARPHRD_ETHER;
		return TRUE;
	}
	return TRUE;
}

static dbus_bool_t
__ni_objectmodel_bonding_get_address(const ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				ni_dbus_variant_t *result,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_get_hwaddr(result, &dev->link.hwaddr);
}

static dbus_bool_t
__ni_objectmodel_bonding_set_address(ni_dbus_object_t *object,
				const ni_dbus_property_t *property,
				const ni_dbus_variant_t *argument,
				DBusError *error)
{
	ni_netdev_t *dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, error)))
		return FALSE;
	return __ni_objectmodel_set_hwaddr(argument, &dev->link.hwaddr);
}

#define BONDING_INT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_INT_PROPERTY(bonding, dbus_name, member_name, rw)
#define BONDING_STRING_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_PROPERTY(bonding, dbus_name, member_name, rw)
#define BONDING_UINT_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT_PROPERTY(bonding, dbus_name, member_name, rw)
#define BONDING_UINT16_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_UINT16_PROPERTY(bonding, dbus_name, member_name, rw)
#define BONDING_BOOL_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_BOOL_PROPERTY(bonding, dbus_name, member_name, rw)
#define BONDING_STRING_ARRAY_PROPERTY(dbus_name, member_name, rw) \
	NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(bonding, dbus_name, member_name, rw)

static ni_dbus_property_t	ni_objectmodel_bond_properties[] = {
	BONDING_UINT_PROPERTY(mode, mode, RO),
	BONDING_UINT_PROPERTY(xmit-hash-policy, xmit_hash_policy, RO),
	BONDING_UINT_PROPERTY(lacp-rate, lacp_rate, RO),
	BONDING_UINT_PROPERTY(ad-select, ad_select, RO),
	BONDING_UINT16_PROPERTY(ad-user-port-key, ad_user_port_key, RO),
	BONDING_UINT16_PROPERTY(ad-actor-sys-prio, ad_actor_sys_prio, RO),
	___NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			ad-actor-system, ad_actor_system, __ni_objectmodel_bonding, RO),
	BONDING_UINT_PROPERTY(min-links, min_links, RO),
	BONDING_UINT_PROPERTY(resend-igmp, resend_igmp, RO),
	BONDING_UINT_PROPERTY(num-grat-arp, num_grat_arp, RO),
	BONDING_UINT_PROPERTY(num-unsol-na, num_unsol_na, RO),
	BONDING_UINT_PROPERTY(fail-over-mac, fail_over_mac, RO),
	BONDING_UINT_PROPERTY(primary-reselect, primary_reselect, RO),
	BONDING_BOOL_PROPERTY(all-slaves-active, all_slaves_active, RO),
	BONDING_UINT_PROPERTY(packets-per-slave, packets_per_slave, RO),
	BONDING_BOOL_PROPERTY(tlb-dynamic-lb, tlb_dynamic_lb, RO),
	BONDING_UINT_PROPERTY(lp-interval, lp_interval, RO),

	__NI_DBUS_PROPERTY(
			DBUS_TYPE_ARRAY_AS_STRING NI_DBUS_DICT_SIGNATURE,
			slaves, __ni_objectmodel_bonding, RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			miimon, __ni_objectmodel_bonding, RO),
	__NI_DBUS_PROPERTY(
			NI_DBUS_DICT_SIGNATURE,
			arpmon, __ni_objectmodel_bonding, RO),

	__NI_DBUS_PROPERTY(DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING,
			address, __ni_objectmodel_bonding, RO),

	{ NULL }
};


static ni_dbus_method_t		ni_objectmodel_bond_methods[] = {
	{ "changeDevice",	"a{sv}",			ni_objectmodel_bond_setup },
	{ "shutdownDevice",	"",				__ni_objectmodel_shutdown_bond },
	{ "deleteDevice",	"",				__ni_objectmodel_delete_bond },
#if 0
	{ "addSlave",		DBUS_TYPE_OJECT_AS_STRING,	__ni_objectmodel_bond_add_slave },
	{ "removeSlave",	DBUS_TYPE_OJECT_AS_STRING,	__ni_objectmodel_bond_remove_slave },
	{ "setActive",		DBUS_TYPE_OJECT_AS_STRING,	__ni_objectmodel_bond_add_active },
	{ "setPrimary",		DBUS_TYPE_OJECT_AS_STRING,	__ni_objectmodel_bond_set_primary },
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
