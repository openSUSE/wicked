/*
 * Handle global configuration for netinfo
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */


#ifndef __NI_NETINFO_CONFIG_H__
#define __NI_NETINFO_CONFIG_H__

#include "types.h"
#include "netinfo.h"
#include "logging.h"

#define NI_DEFAULT_CONFIG_PATH	"/etc/wicked/config.xml"
#define NI_DEFAULT_POLICY_PATH	"/etc/wicked/policy.xml"

enum {
	NI_AF_MASK_IPV4		= 0x0001,
	NI_AF_MASK_IPV6		= 0x0002,
};

typedef struct ni_extension {
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

	/* Shell command to start the service */
	xpath_format_t *	start_command;

	/* Shell command to stop the service */
	xpath_format_t *	stop_command;

	/* Environment variables */
	xpath_format_array_t	environment;
} ni_extension_t;

typedef struct ni_config_fslocation {
	char *			path;
	unsigned int		mode;
} ni_config_fslocation_t;

typedef struct ni_config {
	/* Mostly using enabled, forwarding from these: */
	ni_afinfo_t		ipv4;
	ni_afinfo_t		ipv6;

	ni_config_fslocation_t	pidfile;
	ni_config_fslocation_t	socket;

	ni_extension_t *	linktype_extensions;
	ni_extension_t *	addrconf_extensions;

	ni_config_fslocation_t	policy;
} ni_config_t;

extern ni_config_t *	ni_config_new();
extern ni_config_t *	ni_config_parse(const char *);
extern ni_extension_t *	ni_config_find_linktype_extension(ni_config_t *, int);
extern ni_extension_t *	ni_config_find_addrconf_extension(ni_config_t *, int, int);

extern ni_extension_t *	ni_extension_list_find(ni_extension_t *, int type, int af);
extern void		ni_extension_list_destroy(ni_extension_t **);
extern ni_extension_t *	ni_extension_new(ni_extension_t **, const char *, unsigned int);
extern int		ni_extension_active(const ni_extension_t *, const char *, xml_node_t *);
extern int		ni_extension_start(const ni_extension_t *, const char *, xml_node_t *);
extern int		ni_extension_stop(const ni_extension_t *, const char *, xml_node_t *);
extern void		ni_extension_free(ni_extension_t *);


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
