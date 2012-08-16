
#ifndef __WICKED_MODEM_MANAGER_H__
#define __WICKED_MODEM_MANAGER_H__

#include <wicked/modem.h>

extern const char *		ni_objectmodel_mm_modem_get_classname(ni_modem_type_t);
extern const ni_dbus_class_t *	ni_objectmodel_mm_modem_get_class(ni_modem_type_t);

extern const char *		ni_objectmodel_modem_get_proxy_classname(ni_modem_type_t);
extern const ni_dbus_class_t *	ni_objectmodel_modem_get_proxy_class(ni_modem_type_t);

extern ni_modem_pin_t *		ni_modem_pin_new(const char *kind, const char *value);
extern void			ni_modem_pin_free(ni_modem_pin_t *);
extern void			ni_modem_add_pin(ni_modem_t *, ni_modem_pin_t *);
extern ni_modem_pin_t *		ni_modem_get_pin(ni_modem_t *, const char *);

#endif /* __WICKED_MODEM_MANAGER_H__ */

