
#ifndef __WICKED_OBJECTMODEL_P_H__
#define __WICKED_OBJECTMODEL_P_H__

#include <wicked/objectmodel.h>

#define __NI_DBUS_PROPERTY_RO(fstem, __name) \
	__NI_DBUS_PROPERTY_GET_FN(fstem, __name), \
	__NI_DBUS_PROPERTY_SET_FN(fstem, __name)
#define __NI_DBUS_PROPERTY_ROP(fstem, __name) \
	__NI_DBUS_PROPERTY_RO(fstem, __name), \
	__NI_DBUS_PROPERTY_PARSE_FN(fstem, __name)
#define __NI_DBUS_PROPERTY_RW(fstem, __name) \
	__NI_DBUS_PROPERTY_RO(fstem, __name), \
	__NI_DBUS_PROPERTY_UPDATE_FN(fstem, __name)
#define __NI_DBUS_PROPERTY_RWP(fstem, __name) \
	__NI_DBUS_PROPERTY_RW(fstem, __name), \
	__NI_DBUS_PROPERTY_PARSE_FN(fstem, __name), \
	__NI_DBUS_PROPERTY_UPDATE_FN(fstem, __name)

#define __NI_DBUS_PROPERTY_GET_FN(fstem, __name) \
	.get = fstem ## _get_ ## __name
#define __NI_DBUS_PROPERTY_SET_FN(fstem, __name) \
	.set = fstem ## _set_ ## __name
#define __NI_DBUS_PROPERTY_UPDATE_FN(fstem, __name) \
	.update = fstem ## _update_ ## __name
#define __NI_DBUS_PROPERTY_PARSE_FN(fstem, __name) \
	.parse = fstem ## _parse_ ## __name

#define __NI_DBUS_DUMMY_PROPERTY(__signature, __name) { \
	.name = #__name, \
	.signature = __signature, \
}
#define NI_DBUS_DUMMY_PROPERTY(type, __name) \
	__NI_DBUS_DUMMY_PROPERTY(DBUS_TYPE_##type##_AS_STRING, __name)
#define __NI_DBUS_PROPERTY(__signature, __name, fstem, rw) \
	___NI_DBUS_PROPERTY(__signature, __name, __name, fstem, rw)
#define ___NI_DBUS_PROPERTY(__signature, __dbus_name, __member_name, fstem, rw) { \
	.name = #__dbus_name, \
	.signature = __signature, \
	__NI_DBUS_PROPERTY_##rw(fstem, __member_name), \
}
#define NI_DBUS_PROPERTY(type, __name, fstem, rw) \
	__NI_DBUS_PROPERTY(DBUS_TYPE_##type##_AS_STRING, __name, fstem, rw)

#define __NI_DBUS_GENERIC_PROPERTY(struct_name, dbus_sig, dbus_name, member_type, member_name, rw, args...) { \
	.name = #dbus_name, \
	.signature = dbus_sig, \
	__NI_DBUS_PROPERTY_##rw##P(ni_dbus_generic_property, member_type), \
	.generic = { \
		.get_handle = ni_objectmodel_get_##struct_name, \
		.u = { .member_type##_offset = &((ni_##struct_name##_t *) 0)->member_name }, \
	} \
	, ##args \
}
#define __NI_DBUS_GENERIC_DICT_PROPERTY(dbus_name, child_properties, rw) { \
	.name = #dbus_name, \
	.signature = NI_DBUS_DICT_SIGNATURE, \
	.generic = { \
		.u = { .dict_children = child_properties }, \
	} \
}
#define NI_DBUS_GENERIC_INT_PROPERTY(struct_name, dbus_name, member_name, rw) \
	__NI_DBUS_GENERIC_PROPERTY(struct_name, DBUS_TYPE_INT32_AS_STRING, dbus_name, int, member_name, rw)
#define NI_DBUS_GENERIC_UINT_PROPERTY(struct_name, dbus_name, member_name, rw) \
	__NI_DBUS_GENERIC_PROPERTY(struct_name, DBUS_TYPE_UINT32_AS_STRING, dbus_name, uint, member_name, rw)
#define NI_DBUS_GENERIC_UINT16_PROPERTY(struct_name, dbus_name, member_name, rw) \
	__NI_DBUS_GENERIC_PROPERTY(struct_name, DBUS_TYPE_UINT16_AS_STRING, dbus_name, uint16, member_name, rw)
#define NI_DBUS_GENERIC_STRING_PROPERTY(struct_name, dbus_name, member_name, rw) \
	__NI_DBUS_GENERIC_PROPERTY(struct_name, DBUS_TYPE_STRING_AS_STRING, dbus_name, string, member_name, rw)
#define NI_DBUS_GENERIC_STRING_ARRAY_PROPERTY(struct_name, dbus_name, member_name, rw) \
	__NI_DBUS_GENERIC_PROPERTY(struct_name, \
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, \
			dbus_name, string_array, member_name, rw)
#define NI_DBUS_GENERIC_DICT_PROPERTY(dbus_name, child_properties, rw) \
	__NI_DBUS_GENERIC_DICT_PROPERTY(dbus_name, child_properties, rw)


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
extern ni_dbus_service_t	ni_objectmodel_ethernet_service;
extern ni_dbus_service_t	ni_objectmodel_bridge_service;
extern ni_dbus_service_t	ni_objectmodel_bridge_factory_service;
extern ni_dbus_service_t	ni_objectmodel_bond_service;
extern ni_dbus_service_t	ni_objectmodel_bond_factory_service;
extern ni_dbus_service_t	ni_objectmodel_vlan_service;
extern ni_dbus_service_t	ni_objectmodel_vlan_factory_service;
extern ni_dbus_service_t	ni_objectmodel_tun_service;
extern ni_dbus_service_t	ni_objectmodel_tun_factory_service;
extern ni_dbus_service_t	ni_objectmodel_openvpn_service;
extern ni_dbus_service_t	ni_objectmodel_openvpn_factory_service;

extern ni_netdev_t *		ni_objectmodel_get_netif_argument(const ni_dbus_variant_t *, ni_iftype_t,
						const ni_dbus_service_t *);
extern dbus_bool_t		ni_objectmodel_device_factory_result(ni_dbus_server_t *, ni_dbus_message_t *,
						ni_netdev_t *, const ni_dbus_class_t *,
						DBusError *);
extern const char *		ni_objectmodel_interface_path(const ni_netdev_t *);
extern const char *		ni_objectmodel_interface_full_path(const ni_netdev_t *);

extern dbus_bool_t		__ni_objectmodel_get_address_list(ni_address_t *list,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_address_list(ni_address_t **list,
						const ni_dbus_variant_t *argument,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_get_route_list(ni_route_t *list,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_route_list(ni_route_t **list,
						const ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_get_addrconf_lease(const ni_addrconf_lease_t *lease,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_addrconf_lease(ni_addrconf_lease_t *lease,
						const ni_dbus_variant_t *result,
						DBusError *error);

extern void			ni_objectmodel_register_service(ni_dbus_service_t *);
extern void			ni_objectmodel_register_netif_classes(void);
extern void			ni_objectmodel_create_netif_list(ni_dbus_server_t *);
extern dbus_bool_t		ni_objectmodel_bind_compatible_interfaces(ni_dbus_object_t *);

extern void			ni_objectmodel_addrconf_signal_handler(ni_dbus_connection_t *,
						ni_dbus_message_t *, void *);
extern dbus_bool_t		__ni_objectmodel_interface_event(ni_dbus_server_t *server, ni_dbus_object_t *object,
						ni_event_t event, const ni_uuid_t *uuid);
extern const char *		__ni_objectmodel_event_to_signal(ni_event_t);
extern dbus_bool_t		__ni_objectmodel_return_callback_info(ni_dbus_message_t *, ni_event_t, const ni_uuid_t *,
						DBusError *);

extern dbus_bool_t		__ni_objectmodel_get_address_dict(ni_address_t *list, ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_address_dict(ni_address_t **list, const ni_dbus_variant_t *dict,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_get_route_dict(ni_route_t *list,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__ni_objectmodel_set_route_dict(ni_route_t **list,
						const ni_dbus_variant_t *dict,
						DBusError *error);

#endif /* __WICKED_OBJECTMODEL_P_H__ */
