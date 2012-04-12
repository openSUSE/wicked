
#ifndef __WICKED_MODEM_MANAGER_H__
#define __WICKED_MODEM_MANAGER_H__

#include <wicked/modem.h>

extern const char *		ni_objectmodel_modem_get_classname(ni_modem_type_t);
extern const ni_dbus_class_t *	ni_objectmodel_modem_get_class(ni_modem_type_t);

extern const char *		ni_objectmodel_modem_get_proxy_classname(ni_modem_type_t);
extern const ni_dbus_class_t *	ni_objectmodel_modem_get_proxy_class(ni_modem_type_t);

#endif /* __WICKED_MODEM_MANAGER_H__ */

