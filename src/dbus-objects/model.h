
#ifndef __WICKED_OBJECTMODEL_P_H__
#define __WICKED_OBJECTMODEL_P_H__

#include <wicked/objectmodel.h>

#define __pointer(base, offset_ptr) \
	((typeof(offset_ptr)) (((caddr_t) base) + (unsigned long) offset_ptr))

static inline dbus_bool_t
__ni_objectmodel_set_property_int(void *handle, int *member_offset, const ni_dbus_variant_t *result)
{
	if (handle == NULL)
		return FALSE;

	return ni_dbus_variant_get_int(result, __pointer(handle, member_offset));
}

static inline dbus_bool_t
__ni_objectmodel_set_property_uint(void *handle, unsigned int *member_offset, const ni_dbus_variant_t *result)
{
	if (handle == NULL)
		return FALSE;

	return ni_dbus_variant_get_uint(result, __pointer(handle, member_offset));
}

static inline dbus_bool_t
__ni_objectmodel_set_property_long(void *handle, long *member_offset, const ni_dbus_variant_t *result)
{
	if (handle == NULL)
		return FALSE;

	return ni_dbus_variant_get_long(result, __pointer(handle, member_offset));
}

static inline dbus_bool_t
__ni_objectmodel_set_property_ulong(void *handle, unsigned long *member_offset, const ni_dbus_variant_t *result)
{
	if (handle == NULL)
		return FALSE;

	return ni_dbus_variant_get_ulong(result, __pointer(handle, member_offset));
}

static inline dbus_bool_t
__ni_objectmodel_get_property_int(const void *handle, int *member_offset, ni_dbus_variant_t *result)
{
	if (handle == NULL)
		return FALSE;

	return ni_dbus_variant_set_int(result, *__pointer(handle, member_offset));
}

static inline dbus_bool_t
__ni_objectmodel_get_property_uint(const void *handle, unsigned int *member_offset, ni_dbus_variant_t *result)
{
	if (handle == NULL)
		return FALSE;

	return ni_dbus_variant_set_uint(result, *__pointer(handle, member_offset));
}

static inline dbus_bool_t
__ni_objectmodel_get_property_long(const void *handle, long *member_offset, ni_dbus_variant_t *result)
{
	if (handle == NULL)
		return FALSE;

	return ni_dbus_variant_set_long(result, *__pointer(handle, member_offset));
}

static inline dbus_bool_t
__ni_objectmodel_get_property_ulong(const void *handle, unsigned long *member_offset, ni_dbus_variant_t *result)
{
	if (handle == NULL)
		return FALSE;

	return ni_dbus_variant_set_ulong(result, *__pointer(handle, member_offset));
}


extern ni_dbus_server_t *	__ni_objectmodel_server;
extern ni_xs_scope_t *		__ni_objectmodel_schema;
extern ni_dbus_service_t	ni_objectmodel_ipv4_service;
extern ni_dbus_service_t	ni_objectmodel_ipv6_service;
extern ni_dbus_service_t	ni_objectmodel_ethernet_service;
extern ni_dbus_service_t	ni_objectmodel_bridge_service;
extern ni_dbus_service_t	ni_objectmodel_bridge_factory_service;
extern ni_dbus_service_t	ni_objectmodel_ovs_bridge_service;
extern ni_dbus_service_t	ni_objectmodel_ovs_bridge_factory_service;
extern ni_dbus_service_t	ni_objectmodel_bond_service;
extern ni_dbus_service_t	ni_objectmodel_bond_factory_service;
extern ni_dbus_service_t	ni_objectmodel_team_service;
extern ni_dbus_service_t	ni_objectmodel_team_factory_service;
extern ni_dbus_service_t	ni_objectmodel_vlan_service;
extern ni_dbus_service_t	ni_objectmodel_vlan_factory_service;
extern ni_dbus_service_t	ni_objectmodel_macvlan_service;
extern ni_dbus_service_t	ni_objectmodel_macvlan_factory_service;
extern ni_dbus_service_t	ni_objectmodel_macvtap_service;
extern ni_dbus_service_t	ni_objectmodel_macvtap_factory_service;
extern ni_dbus_service_t	ni_objectmodel_dummy_service;
extern ni_dbus_service_t	ni_objectmodel_dummy_factory_service;
extern ni_dbus_service_t	ni_objectmodel_tun_service;
extern ni_dbus_service_t	ni_objectmodel_tun_factory_service;
extern ni_dbus_service_t	ni_objectmodel_tap_service;
extern ni_dbus_service_t	ni_objectmodel_tap_factory_service;
extern ni_dbus_service_t	ni_objectmodel_sit_service;
extern ni_dbus_service_t	ni_objectmodel_sit_factory_service;
extern ni_dbus_service_t	ni_objectmodel_ipip_service;
extern ni_dbus_service_t	ni_objectmodel_ipip_factory_service;
extern ni_dbus_service_t	ni_objectmodel_gre_service;
extern ni_dbus_service_t	ni_objectmodel_gre_factory_service;
extern ni_dbus_service_t	ni_objectmodel_ppp_service;
extern ni_dbus_service_t	ni_objectmodel_ppp_factory_service;
extern ni_dbus_service_t	ni_objectmodel_ibparent_service;
extern ni_dbus_service_t	ni_objectmodel_ibchild_service;
extern ni_dbus_service_t	ni_objectmodel_ibchild_factory_service;
extern ni_dbus_service_t	ni_objectmodel_lldp_service;

extern ni_netdev_t *		ni_objectmodel_get_netif_argument(const ni_dbus_variant_t *, ni_iftype_t,
						const ni_dbus_service_t *);
extern dbus_bool_t		ni_objectmodel_netif_factory_result(ni_dbus_server_t *, ni_dbus_message_t *,
						ni_netdev_t *, const ni_dbus_class_t *,
						DBusError *);
extern const char *		ni_objectmodel_netif_path(const ni_netdev_t *);
extern const char *		ni_objectmodel_netif_full_path(const ni_netdev_t *);
extern const char *		ni_objectmodel_interface_full_path(const ni_netdev_t *);

extern dbus_bool_t		__ni_objectmodel_set_hwaddr(const ni_dbus_variant_t *, ni_hwaddr_t *);
extern dbus_bool_t		__ni_objectmodel_get_hwaddr(ni_dbus_variant_t *, const ni_hwaddr_t *);

extern dbus_bool_t		__ni_objectmodel_get_address_list(ni_address_t *list,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_address_list(ni_address_t **list,
						const ni_dbus_variant_t *argument,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_get_route_list(ni_route_table_t *list,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_route_list(ni_route_table_t **list,
						const ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_get_addrconf_lease(const ni_addrconf_lease_t *lease,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_addrconf_lease(ni_addrconf_lease_t *lease,
						const ni_dbus_variant_t *result,
						DBusError *error);

extern void			ni_objectmodel_create_netif_list(ni_dbus_server_t *);
extern void			ni_objectmodel_create_modem_list(ni_dbus_server_t *);

extern ni_dbus_object_t *	ni_objectmodel_resolve_name(ni_dbus_object_t *parent, const char *namespace,
					const ni_dbus_variant_t *var);

extern void			ni_objectmodel_addrconf_signal_handler(ni_dbus_connection_t *,
						ni_dbus_message_t *, void *);
extern dbus_bool_t		__ni_objectmodel_device_event(ni_dbus_server_t *server, ni_dbus_object_t *object,
						const char *interface, ni_event_t event, const ni_uuid_t *uuid);
extern dbus_bool_t		__ni_objectmodel_return_callback_info(ni_dbus_message_t *, ni_event_t,
						const ni_uuid_t *, const ni_objectmodel_callback_data_t *,
						DBusError *);

extern dbus_bool_t		__ni_objectmodel_get_address_dict(ni_address_t *list, ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_address_dict(ni_address_t **list, const ni_dbus_variant_t *dict,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_get_route_dict(ni_route_table_t *list,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_route_dict(ni_route_table_t **list,
						const ni_dbus_variant_t *dict,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_get_rule_dict(ni_rule_array_t *rules, unsigned int family,
						ni_dbus_variant_t *result, DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_rule_dict(ni_rule_array_t **rules, unsigned int family,
						const ni_dbus_variant_t *dict, DBusError *error);
extern dbus_bool_t		__ni_objectmodel_get_domain_string(const ni_dbus_variant_t *,
						const char *, const char **);
extern dbus_bool_t		__ni_objectmodel_set_resolver_dict(ni_resolver_info_t **,
						const ni_dbus_variant_t *, DBusError *);

extern dbus_bool_t		__ni_objectmodel_get_team_port_config(const ni_team_port_config_t *,
						ni_dbus_variant_t *, DBusError *);
extern dbus_bool_t		__ni_objectmodel_set_team_port_config(ni_team_port_config_t *,
						const ni_dbus_variant_t *, DBusError *);

extern dbus_bool_t		__ni_objectmodel_get_ovs_bridge_port_config(const ni_ovs_bridge_port_config_t *,
						ni_dbus_variant_t *, DBusError *);
extern dbus_bool_t		__ni_objectmodel_set_ovs_bridge_port_config(ni_ovs_bridge_port_config_t *,
						const ni_dbus_variant_t *, DBusError *);

extern dbus_bool_t		ni_objectmodel_bind_netdev_ref_index(const char *, const char *,
						ni_netdev_ref_t *, ni_netconfig_t *, DBusError *);

#endif /* __WICKED_OBJECTMODEL_P_H__ */
