#ifndef __WICKED_OBJECTMODEL_H__
#define __WICKED_OBJECTMODEL_H__

#include <wicked/dbus.h>

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
#define __NI_DBUS_PROPERTY(__signature, __name, fstem, rw) { \
	.name = #__name, \
	.signature = __signature, \
	__NI_DBUS_PROPERTY_##rw(fstem, __name), \
}
#define NI_DBUS_PROPERTY(type, __name, fstem, rw) \
	__NI_DBUS_PROPERTY(DBUS_TYPE_##type##_AS_STRING, __name, fstem, rw)

#define __NI_DBUS_GENERIC_PROPERTY(struct_name, dbus_sig, dbus_name, member_type, member_name, rw) { \
	.name = #dbus_name, \
	.signature = dbus_sig, \
	__NI_DBUS_PROPERTY_##rw##P(ni_dbus_generic_property, member_type), \
	.generic = { \
		.get_handle = ni_objectmodel_get_##struct_name, \
		.u = { .member_type##_offset = &((ni_##struct_name##_t *) 0)->member_name }, \
	} \
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


extern ni_dbus_service_t	wicked_dbus_ethernet_service;
extern ni_dbus_service_t	wicked_dbus_vlan_service;
extern ni_dbus_service_t	wicked_dbus_bridge_service;
extern ni_dbus_service_t	wicked_dbus_bond_service;
extern ni_dbus_service_t	wicked_dbus_bridge_port_dummy_service;
extern ni_dbus_service_t	wicked_dbus_bond_port_dummy_service;

extern ni_dbus_object_t *	ni_objectmodel_new_vlan(ni_dbus_server_t *server,
					const ni_dbus_object_t *config,
					DBusError *error);
extern ni_dbus_object_t *	ni_objectmodel_new_bridge(ni_dbus_server_t *server,
					const ni_dbus_object_t *config,
					DBusError *error);
extern ni_dbus_object_t *	ni_objectmodel_new_bond(ni_dbus_server_t *server,
					const ni_dbus_object_t *config,
					DBusError *error);
extern ni_dbus_object_t *	ni_objectmodel_new_ppp(ni_dbus_server_t *server,
					const ni_dbus_object_t *config,
					DBusError *error);

extern dbus_bool_t		__wicked_dbus_get_address_list(ni_address_t *list,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__wicked_dbus_set_address_list(ni_address_t **list,
						const ni_dbus_variant_t *argument,
						DBusError *error);
extern dbus_bool_t		__wicked_dbus_get_route_list(ni_route_t *list,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__wicked_dbus_set_route_list(ni_route_t **list,
						const ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__wicked_dbus_get_addrconf_request(const ni_addrconf_request_t *req,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__wicked_dbus_set_addrconf_request(ni_addrconf_request_t *req,
						const ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__wicked_dbus_get_addrconf_lease(const ni_addrconf_lease_t *lease,
						ni_dbus_variant_t *result,
						DBusError *error);
extern dbus_bool_t		__wicked_dbus_set_addrconf_lease(ni_addrconf_lease_t *lease,
						const ni_dbus_variant_t *result,
						DBusError *error);

extern void			ni_objectmodel_dhcp4_init(ni_dbus_server_t *);
extern void			ni_objectmodel_autoip_init(ni_dbus_server_t *);
extern int			ni_objectmodel_addrconf_acquire(ni_dbus_object_t *,
						const ni_addrconf_request_t *);
extern int			ni_objectmodel_addrconf_release(ni_dbus_object_t *,
						const ni_addrconf_lease_t *);
extern void			ni_objectmodel_addrconf_signal_handler(ni_dbus_connection_t *,
						ni_dbus_message_t *, void *);

#endif /* __WICKED_OBJECTMODEL_H__ */
