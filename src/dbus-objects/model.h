#ifndef __WICKED_OBJECTMODEL_H__
#define __WICKED_OBJECTMODEL_H__

#define __NI_DBUS_PROPERTY_RO(fstem, __name)	NULL
#define __NI_DBUS_PROPERTY_RW(fstem, __name)	fstem ## _update_ ## __name

#define __NI_DBUS_PROPERTY(__signature, __name, __id, fstem, rw) { \
	.name = #__name, \
	.id = __id, \
	.signature = __signature, \
	.get = fstem ## _get_ ## __name, \
	.set = fstem ## _set_ ## __name, \
	.update = __NI_DBUS_PROPERTY_##rw(fstem, __name), \
}
#define NI_DBUS_PROPERTY(type, __name, __id, fstem, rw) \
	__NI_DBUS_PROPERTY(DBUS_TYPE_##type##_AS_STRING, __name, __id, fstem, rw)

#endif /* __WICKED_OBJECTMODEL_H__ */
