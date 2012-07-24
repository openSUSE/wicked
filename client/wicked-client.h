/*
 * No REST for the wicked!
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef WICKED_CLIENT_H
#define WICKED_CLIENT_H

extern const char *		program_name;
extern int			opt_global_dryrun;
extern char *			opt_global_rootdir;
extern int			opt_global_progressmeter;

extern int			do_ifup(int argc, char **argv);
extern int			do_ifdown(int argc, char **argv);

typedef struct ni_client	ni_client_t;

typedef struct ni_call_error_context ni_call_error_context_t;
typedef int			ni_call_error_handler_t(ni_call_error_context_t *, const DBusError *);

extern xml_node_t *		ni_call_error_context_get_node(ni_call_error_context_t *, const char *);
extern int			ni_call_error_context_get_retries(ni_call_error_context_t *, const DBusError *);

extern ni_dbus_object_t *	ni_call_get_netif_list_object(void);
extern ni_dbus_object_t *	ni_call_get_modem_list_object(void);

extern ni_dbus_object_t *	ni_call_create_client(void);
extern char *			ni_call_identify_device(const xml_node_t *query);
extern char *			ni_call_identify_modem(const xml_node_t *query);
extern char *			ni_call_device_new_xml(const ni_dbus_service_t *, const char *, xml_node_t *);
extern int			ni_call_common_xml(ni_dbus_object_t *,
					const ni_dbus_service_t *, const ni_dbus_method_t *,
					xml_node_t *, ni_objectmodel_callback_info_t **,
					ni_call_error_handler_t *error_func);
extern int			ni_call_set_client_info(ni_dbus_object_t *, const ni_netdev_clientinfo_t *);

extern int			ni_call_install_lease_xml(ni_dbus_object_t *, xml_node_t *);

/* We may want to move this into the library. */
extern int			ni_resolve_hostname_timed(const char *, int, ni_sockaddr_t *, unsigned int);
extern int			ni_host_is_reachable(const char *, const ni_sockaddr_t *);

#endif /* WICKED_CLIENT_H */
