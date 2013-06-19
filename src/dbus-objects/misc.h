
#ifndef __WICKED_DBUS_OBJECTS_MISC_H__
#define __WICKED_DBUS_OBJECTS_MISC_H__

extern dbus_bool_t	__ni_objectmodel_get_opaque(const ni_dbus_variant_t *, ni_opaque_t *);
extern dbus_bool_t	__ni_objectmodel_set_sockaddr(ni_dbus_variant_t *, const ni_sockaddr_t *);
extern dbus_bool_t	__ni_objectmodel_set_sockaddr_prefix(ni_dbus_variant_t *var, const ni_sockaddr_t *sockaddr, unsigned int prefix_len);
extern dbus_bool_t	__ni_objectmodel_get_sockaddr(const ni_dbus_variant_t *var, ni_sockaddr_t *sockaddr);
extern dbus_bool_t	__ni_objectmodel_get_sockaddr_prefix(const ni_dbus_variant_t *var, ni_sockaddr_t *sockaddr, unsigned int *prefixlen);
extern dbus_bool_t	__ni_objectmodel_dict_add_sockaddr(ni_dbus_variant_t *dict, const char *name, const ni_sockaddr_t *sockaddr);
extern dbus_bool_t	__ni_objectmodel_dict_add_sockaddr_prefix(ni_dbus_variant_t *dict, const char *name, const ni_sockaddr_t *sockaddr, unsigned int prefix_len);
extern dbus_bool_t	__ni_objectmodel_dict_get_sockaddr(const ni_dbus_variant_t *dict, const char *name, ni_sockaddr_t *sockaddr);
extern dbus_bool_t	__ni_objectmodel_dict_get_sockaddr_prefix(const ni_dbus_variant_t *dict, const char *name, ni_sockaddr_t *sockaddr, unsigned int *prefixlen);
extern dbus_bool_t	__ni_objectmodel_set_hwaddr(const ni_dbus_variant_t *argument, ni_hwaddr_t *hwaddr);
extern dbus_bool_t	__ni_objectmodel_get_hwaddr(ni_dbus_variant_t *result, const ni_hwaddr_t *hwaddr);

#endif /* __WICKED_DBUS_OBJECTS_MISC_H__ */
