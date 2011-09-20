#ifndef __WICKED_OBJECTMODEL_H__
#define __WICKED_OBJECTMODEL_H__

#define __NI_DBUS_PROPERTY_RO	1
#define __NI_DBUS_PROPERTY_RW	0

#define __NI_DBUS_PROPERTY(__signature, __name, fstem, rw) { \
	.name = #__name, \
	.id = 0, \
	.signature = __signature, \
	.readonly = __NI_DBUS_PROPERTY_##rw, \
	.get = fstem ## _get_ ## __name, \
	.set = fstem ## _set_ ## __name \
}
#define NI_DBUS_PROPERTY(type, __name, fstem, rw) \
	__NI_DBUS_PROPERTY(DBUS_TYPE_##type##_AS_STRING, __name, fstem, rw)

#endif /* __WICKED_OBJECTMODEL_H__ */
