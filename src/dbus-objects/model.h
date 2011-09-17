#ifndef __WICKED_OBJECTMODEL_H__
#define __WICKED_OBJECTMODEL_H__

#define NI_DBUS_PROPERTY_METHODS_RO(fstem, __name) \
	.get = fstem ## _get_ ## __name, .set = NULL
#define NI_DBUS_PROPERTY_METHODS_RW(fstem, __name) \
	.get = fstem ## _get_ ## __name, .set = fstem ## _set_ ## __name
#define __NI_DBUS_PROPERTY(__signature, __name, fstem, rw) \
{ .name = #__name, .id = 0, .signature = __signature, NI_DBUS_PROPERTY_METHODS_##rw(fstem, __name) }
#define NI_DBUS_PROPERTY(type, __name, fstem, rw) \
	__NI_DBUS_PROPERTY(DBUS_TYPE_##type##_AS_STRING, __name, fstem, rw)

#endif /* __WICKED_OBJECTMODEL_H__ */
