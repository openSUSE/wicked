/*
 * Handle global configuration for netinfo
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */


#ifndef __NI_NETINFO_CONFIG_H__
#define __NI_NETINFO_CONFIG_H__

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/logging.h>

#define NI_DEFAULT_CONFIG_PATH	"/etc/wicked/config.xml"

struct ni_script_action {
	struct ni_script_action *next;
	char *			name;
	xpath_format_t *	command;
};

struct ni_extension {
	struct ni_extension *	next;

	/* Name of the extension; could be "dhcp4" or "ibft". */
	char *			name;

	/* type: what this helper supports.
	 *	For instance, for addrconf helpers this would
	 *	be "dhcp", "ibft", etc.
	 */
	int			type;

	/* Supported address families.
	 * Bitwise OR of NI_AF_MASK_* values
	 */
	unsigned int		supported_af;

	/* PID file.
	 * For facilities like dhcp client daemons, the name of
	 * the PID file allows us to detect whether there's a DHCP
	 * client running on this interface.
	 */
	xpath_format_t *	pid_file_path;

	/* Shell commands */
	ni_script_action_t *	actions;

	/* Environment variables */
	xpath_format_array_t	environment;
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
	ni_config_fslocation_t	socket;
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

	ni_extension_t *	api_extensions;
	ni_extension_t *	linktype_extensions;
	ni_extension_t *	addrconf_extensions;

	char *			default_syntax;
	char *			default_syntax_path;
} ni_config_t;

extern ni_config_t *	ni_config_new();
extern ni_config_t *	ni_config_parse(const char *);
extern ni_extension_t *	ni_config_find_linktype_extension(ni_config_t *, int);
extern ni_extension_t *	ni_config_find_addrconf_extension(ni_config_t *, int, int);
extern ni_extension_t *	ni_config_find_file_extension(ni_config_t *, const char *);
extern unsigned int	ni_config_addrconf_update_mask(ni_config_t *, ni_addrconf_mode_t);

extern ni_extension_t *	ni_extension_list_find(ni_extension_t *, int type, int af);
extern ni_extension_t *	ni_extension_by_name(ni_extension_t *, const char *);
extern void		ni_extension_list_destroy(ni_extension_t **);
extern ni_extension_t *	ni_extension_new(ni_extension_t **, const char *, unsigned int);
extern int		ni_extension_active(const ni_extension_t *, const char *, xml_node_t *);
extern int		ni_extension_start(const ni_extension_t *, const char *, xml_node_t *);
extern int		ni_extension_stop(const ni_extension_t *, const char *, xml_node_t *);
extern int		ni_extension_run(const ni_extension_t *, ni_script_action_t *);
extern void		ni_extension_free(ni_extension_t *);

extern ni_script_action_t *ni_script_action_new(const char *name, ni_script_action_t **list);
extern void		ni_script_action_free(ni_script_action_t *);
extern ni_script_action_t *ni_script_action_find(ni_script_action_t *, const char *);

typedef struct ni_global {
	int			initialized;
	char *			config_path;
	ni_config_t *		config;
	ni_syntax_t *		default_syntax;
	ni_syntax_t *		xml_syntax;

	ni_policy_info_t	policies;

	void			(*interface_event)(ni_handle_t *, ni_interface_t *, ni_event_t);
} ni_global_t;

extern ni_global_t	ni_global;

static inline void
__ni_assert_initialized(void)
{
	if (!ni_global.initialized)
		ni_fatal("Library not initialized, please call ni_init() first");
}

#endif /* __NI_NETINFO_CONFIG_H__ */
