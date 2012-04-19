

#ifndef __SERVER_SERVER_H__
#define __SERVER_SERVER_H__

extern ni_bool_t	wicked_save_state(ni_xs_scope_t *, ni_dbus_server_t *, const char *);
extern ni_bool_t	wicked_recover_state(ni_xs_scope_t *, ni_dbus_server_t *, const char *);

#endif /* __SERVER_SERVER_H__ */
