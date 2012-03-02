/*
 * Handle global configuration for netinfo
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */


#ifndef __NI_NETINFO_CONFIG_H__
#define __NI_NETINFO_CONFIG_H__

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/logging.h>

#define NI_DEFAULT_CONFIG_PATH	"/etc/wicked/config.xml"

struct ni_script_action {
	ni_script_action_t *	next;
	char *			name;
	ni_shellcmd_t *		process;
};

typedef struct ni_c_binding ni_c_binding_t;
struct ni_c_binding {
	ni_c_binding_t *	next;
	char *			name;
	char *			library;
	char *			symbol;
};

struct ni_extension {
	ni_extension_t *	next;

	/* Name of the extension; could be "dhcp4" or "ibft". */
	char *			name;

	/* Supported dbus interface */
	char *			interface;

	/* Shell commands */
	ni_script_action_t *	actions;

	/* C bindings */
	ni_c_binding_t *	c_bindings;

	/* Environment variables.
	 * The values are of the form
	 *   $object-path
	 *   $property:property-name
	 */
	ni_var_array_t		environment;
};

typedef struct ni_config_fslocation {
	char *			path;
	unsigned int		mode;
} ni_config_fslocation_t;

#define NI_DHCP_SERVER_PREFERENCES_MAX	16
typedef struct ni_server_preference {
	ni_sockaddr_t		address;
	int			weight;
} ni_server_preference_t;

typedef struct ni_config {
	/* Mostly using enabled, forwarding from these: */
	ni_afinfo_t		ipv4;
	ni_afinfo_t		ipv6;

	ni_config_fslocation_t	pidfile;
	unsigned int		recv_max;

	struct {
	    unsigned int	default_allow_update;

	    struct ni_config_dhcp {
	        unsigned int	allow_update;
		char *		vendor_class;
		unsigned int	lease_time;
		ni_string_array_t ignore_servers;

		unsigned int	num_preferred_servers;
		ni_server_preference_t preferred_server[NI_DHCP_SERVER_PREFERENCES_MAX];
	    } dhcp;

	    struct ni_config_autoip {
	        unsigned int	allow_update;
	    } autoip;

	    struct ni_config_ibft {
	        unsigned int	allow_update;
	    } ibft;
	} addrconf;

	char *			dbus_xml_schema_file;
	ni_extension_t *	extensions;
	ni_extension_t *	ns_extensions;

	char *			dbus_name;
	char *			dbus_type;
} ni_config_t;

extern ni_config_t *	ni_config_new();
extern ni_config_t *	ni_config_parse(const char *);
extern ni_extension_t *	ni_config_find_extension(ni_config_t *, const char *);
extern unsigned int	ni_config_addrconf_update_mask(ni_config_t *, ni_addrconf_mode_t); /* KILL */

extern ni_extension_t *	ni_extension_list_find(ni_extension_t *, const char *);
extern void		ni_extension_list_destroy(ni_extension_t **);
extern ni_extension_t *	ni_extension_new(ni_extension_t **, const char *);
extern void		ni_extension_free(ni_extension_t *);

extern void		ni_c_binding_free(ni_c_binding_t *);
extern void *		ni_c_binding_get_address(const ni_c_binding_t *);

extern ni_shellcmd_t *	ni_extension_script_new(ni_extension_t *, const char *name, const char *command);
extern ni_shellcmd_t *	ni_extension_script_find(ni_extension_t *, const char *);
extern const ni_c_binding_t *ni_extension_find_c_binding(const ni_extension_t *, const char *name);

typedef struct ni_global {
	int			initialized;
	char *			config_path;
	ni_config_t *		config;

	void			(*interface_event)(ni_netconfig_t *, ni_netdev_t *, ni_event_t);
} ni_global_t;

extern ni_global_t	ni_global;

static inline void
__ni_assert_initialized(void)
{
	if (!ni_global.initialized)
		ni_fatal("Library not initialized, please call ni_init() first");
}

#endif /* __NI_NETINFO_CONFIG_H__ */
