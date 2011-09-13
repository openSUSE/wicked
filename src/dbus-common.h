
#define NI_DBUS_BUS_NAME	"org.freedesktop.DBus"
#define NI_DBUS_OBJECT_PATH	"/org/freedesktop/DBus"
#define NI_DBUS_INTERFACE	"org.freedesktop.DBus"

extern int ni_dbus_translate_error(const DBusError *, const ni_intmap_t *);
