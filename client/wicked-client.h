/*
 * No REST for the wicked!
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef WICKED_CLIENT_H
#define WICKED_CLIENT_H

#include <wicked/client.h>
#include <wicked/fsm.h>
#include <wicked/objectmodel.h>
#include <wicked/fsm.h>

extern int			opt_global_dryrun;
extern char *			opt_global_rootdir;
extern ni_bool_t		opt_systemd;

extern int			do_ifup(int argc, char **argv);
extern int			do_ifdown(int argc, char **argv);

/* We may want to move this into the library. */
extern int			ni_resolve_hostname_timed(const char *, int, ni_sockaddr_t *, unsigned int);
extern int			ni_host_is_reachable(const char *, const ni_sockaddr_t *);

typedef struct ni_compat_netdev {
	ni_netdev_t *		dev;
	const ni_ifworker_control_t *control;

	struct {
		ni_hwaddr_t	hwaddr;
	} identify;

	struct {
		ni_bool_t	enabled;
		ni_bool_t	required;

		char *		hostname;
		char *		client_id;
		char *		vendor_class;
		unsigned int	acquire_timeout;
		unsigned int	lease_time;

		unsigned int	update;
	} dhcp4;
	struct {
		ni_bool_t	enabled;
		ni_bool_t	required;

		unsigned int	mode;
		ni_bool_t	rapid_commit;

		char *		hostname;
		char *		client_id;

		unsigned int	update;
	} dhcp6;
} ni_compat_netdev_t;

typedef struct ni_compat_netdev_array {
	unsigned int		count;
	ni_compat_netdev_t **	data;
} ni_compat_netdev_array_t;

typedef struct ni_compat_ifconfig {
	ni_compat_netdev_array_t netdev_array;
} ni_compat_ifconfig_t;

extern ni_compat_netdev_t *	ni_compat_netdev_new(const char *);
extern void			ni_compat_netdev_free(ni_compat_netdev_t *);
extern void			ni_compat_netdev_array_append(ni_compat_netdev_array_t *, ni_compat_netdev_t *);
extern void			ni_compat_netdev_array_destroy(ni_compat_netdev_array_t *);
extern ni_compat_netdev_t *	ni_compat_netdev_by_name(ni_compat_netdev_array_t *, const char *);
extern ni_compat_netdev_t *	ni_compat_netdev_by_hwaddr(ni_compat_netdev_array_t *, const ni_hwaddr_t *);
extern void			ni_compat_netdev_client_info_set(ni_netdev_t *, const char *);

extern unsigned int		ni_compat_generate_interfaces(xml_document_array_t *, ni_compat_ifconfig_t *, ni_bool_t);

extern ni_bool_t		ni_ifconfig_read(xml_document_array_t *, const char *, const char *, ni_bool_t);

extern ni_bool_t		__ni_suse_get_interfaces(const char *, const char *, ni_compat_netdev_array_t *);
extern ni_bool_t		__ni_redhat_get_interfaces(const char *, const char *, ni_compat_netdev_array_t *);

extern const ni_string_array_t *ni_config_sources(const char *);

extern ni_device_clientinfo_t *	ni_ifconfig_generate_client_info(const char *, const char *, const char *);
extern ni_device_clientinfo_t *	ni_ifconfig_get_client_info(xml_document_t *);
extern void			ni_ifconfig_add_client_info(xml_document_t *, ni_device_clientinfo_t *,     char *);
extern void			ni_ifconfig_del_client_info(xml_document_t *, const char *);

#endif /* WICKED_CLIENT_H */
