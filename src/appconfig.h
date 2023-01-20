/*
 * Handle global application config file
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */


#ifndef __NI_NETINFO_APPCONFIG_H__
#define __NI_NETINFO_APPCONFIG_H__

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/logging.h>

struct ni_script_action {
	ni_script_action_t *	next;
	char *			name;
	ni_shellcmd_t *		process;
	ni_bool_t		enabled;
};

typedef struct ni_c_binding ni_c_binding_t;
struct ni_c_binding {
	ni_c_binding_t *	next;
	char *			name;
	char *			library;
	char *			symbol;
	ni_bool_t		enabled;
};

typedef struct ni_config_fslocation {
	char *			path;
	unsigned int		mode;
} ni_config_fslocation_t;

struct ni_extension {
	ni_extension_t *	next;

	/* Name of the extension */
	char *			name;

	/* Supported dbus interface */
	char *			interface;

	/* Format type used by system-updater */
	char *			format;

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

	ni_config_fslocation_t	statedir;
};

#define NI_DHCP_SERVER_PREFERENCES_MAX	16
typedef struct ni_server_preference {
	ni_opaque_t		serverid;
	ni_sockaddr_t		address;
	int			weight;
} ni_server_preference_t;

typedef struct ni_config_rtnl_event {
	/*
	 * rtnetlink event related tunables
	 */
	unsigned int	recv_buff_length;
	unsigned int	mesg_buff_length;
} ni_config_rtnl_event_t;

typedef enum {
	NI_CONFIG_BONDING_CTL_NETLINK = 0,
	NI_CONFIG_BONDING_CTL_SYSFS,
} ni_config_bonding_ctl_t;

typedef struct ni_config_bonding {
	ni_config_bonding_ctl_t	ctl;
} ni_config_bonding_t;

typedef enum {
	NI_CONFIG_TEAMD_CTL_DETECT_ONCE = 0,
	NI_CONFIG_TEAMD_CTL_DETECT,
	NI_CONFIG_TEAMD_CTL_DBUS,
	NI_CONFIG_TEAMD_CTL_UNIX,
} ni_config_teamd_ctl_t;

typedef struct ni_config_teamd {
	ni_bool_t		enabled;
	ni_config_teamd_ctl_t	ctl;
} ni_config_teamd_t;

typedef enum {
	NI_CONFIG_DHCP4_ROUTES_CSR,
	NI_CONFIG_DHCP4_ROUTES_MSCSR,
	NI_CONFIG_DHCP4_ROUTES_CLASS,
} ni_config_dhcp4_routes_t;

typedef enum {
	NI_CONFIG_DHCP4_CID_TYPE_AUTO = 0U,
	NI_CONFIG_DHCP4_CID_TYPE_HWADDR,
	NI_CONFIG_DHCP4_CID_TYPE_DHCPv6,
	NI_CONFIG_DHCP4_CID_TYPE_DISABLE,
} ni_config_dhcp4_cid_type_t;

typedef struct ni_config_dhcp4 {
	struct ni_config_dhcp4 *next;
	char *			device;

	unsigned int		create_cid;

	unsigned int		allow_update;
	unsigned int		routes_opts;
	char *			vendor_class;
	unsigned int		lease_time;
	ni_string_array_t	ignore_servers;

	unsigned int		num_preferred_servers;
	ni_server_preference_t	preferred_server[NI_DHCP_SERVER_PREFERENCES_MAX];

	ni_dhcp_option_decl_t *	custom_options;
} ni_config_dhcp4_t;

typedef struct ni_config_dhcp6 {
	struct ni_config_dhcp6 *next;
	char *			device;

	char *			default_duid;
	unsigned int		create_duid;
	ni_bool_t		device_duid;

	unsigned int		allow_update;
	unsigned int		lease_time;
	unsigned int		release_nretries;
	struct {
		unsigned int	time;
		ni_uint_range_t range;
	}			info_refresh;

	ni_string_array_t 	user_class_data;
	unsigned int		vendor_class_en;
	ni_string_array_t	vendor_class_data;
	unsigned int		vendor_opts_en;
	ni_var_array_t		vendor_opts_data;

	ni_string_array_t	ignore_servers;
	unsigned int		num_preferred_servers;
	ni_server_preference_t	preferred_server[NI_DHCP_SERVER_PREFERENCES_MAX];

	ni_dhcp_option_decl_t *	custom_options;
} ni_config_dhcp6_t;

typedef struct ni_config_auto4 {
	unsigned int	allow_update;
} ni_config_auto4_t;

typedef struct ni_config_auto6 {
	unsigned int	allow_update;
} ni_config_auto6_t;

typedef struct ni_config {
	ni_config_fslocation_t	piddir;
	ni_config_fslocation_t	storedir;
	ni_config_fslocation_t	statedir;
	ni_config_fslocation_t	backupdir;

	struct {
	    unsigned int	default_allow_update;

	    ni_config_dhcp4_t	dhcp4;
	    ni_config_dhcp6_t	dhcp6;

	    ni_config_auto4_t	auto4;
	    ni_config_auto6_t	auto6;

	} addrconf;

	char *			dbus_xml_schema_file;
	ni_extension_t *	dbus_extensions;
	ni_extension_t *	ns_extensions;
	ni_extension_t *	fw_extensions;
	ni_extension_t *	updater_extensions;

	struct {
	    ni_string_array_t	ifconfig;
	} sources;

	char *			dbus_name;
	char *			dbus_type;

	ni_config_rtnl_event_t	rtnl_event;

	ni_config_bonding_t	bonding;
	ni_config_teamd_t	teamd;
} ni_config_t;

extern ni_config_t *		ni_config_new();
extern void			ni_config_free(ni_config_t *);
extern ni_config_t *		ni_config_parse(const char *, ni_init_appdata_callback_t *, void *);
extern ni_extension_t *		ni_config_find_extension(ni_config_t *, const char *);
extern ni_extension_t *		ni_config_find_system_updater(ni_config_t *, const char *);
extern unsigned int		ni_config_addrconf_update_mask(ni_addrconf_mode_t, unsigned int);
extern unsigned int		ni_config_addrconf_update(const char *, ni_addrconf_mode_t, unsigned int);

extern const ni_config_dhcp4_t *ni_config_dhcp4_find_device(const char *);
extern const char *		ni_config_dhcp4_cid_type_format(ni_config_dhcp4_cid_type_t);
extern ni_bool_t		ni_config_dhcp4_cid_type_parse(ni_config_dhcp4_cid_type_t *, const char *);
extern const ni_config_dhcp6_t *ni_config_dhcp6_find_device(const char *);

extern ni_config_bonding_ctl_t	ni_config_bonding_ctl(void);

extern ni_bool_t		ni_config_teamd_enable(ni_config_teamd_ctl_t);
extern ni_bool_t		ni_config_teamd_disable(void);
extern ni_bool_t		ni_config_teamd_enabled(void);
extern ni_config_teamd_ctl_t	ni_config_teamd_ctl(void);
extern const char *		ni_config_teamd_ctl_type_to_name(ni_config_teamd_ctl_t);

extern void			ni_config_fslocation_init(ni_config_fslocation_t *, const char *, unsigned int);
extern void			ni_config_fslocation_destroy(ni_config_fslocation_t *);

typedef struct ni_global {
	int			initialized;
	char *			config_path;
	char *			config_dir;
	ni_config_t *		config;

	ni_netconfig_t *	state;
	void			(*interface_event)(ni_netdev_t *, ni_event_t);
	void			(*interface_addr_event)(ni_netdev_t *, ni_event_t, const ni_address_t *);
	void			(*interface_prefix_event)(ni_netdev_t *, ni_event_t, const ni_ipv6_ra_pinfo_t *);
	void			(*interface_nduseropt_event)(ni_netdev_t *, ni_event_t);
	void			(*route_event)(ni_netconfig_t *, ni_event_t, const ni_route_t *);
	void			(*rule_event)(ni_netconfig_t *, ni_event_t, const ni_rule_t *);
	void			(*other_event)(ni_event_t);
} ni_global_t;

extern ni_global_t	ni_global;

#endif /* __NI_NETINFO_APPCONFIG_H__ */
