/*
 * IPv6 device settings
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef NI_WICKED_IPv6_H
#define NI_WICKED_IPv6_H

#include <wicked/types.h>

typedef struct ni_ipv6_ra_rdnss	ni_ipv6_ra_rdnss_t;
typedef struct ni_ipv6_ra_dnssl	ni_ipv6_ra_dnssl_t;

enum {
	NI_IPV6_PRIVACY_DEFAULT		= -1,
	NI_IPV6_PRIVACY_DISABLED	=  0,
	NI_IPV6_PRIVACY_PREFER_PUBLIC	=  1,
	NI_IPV6_PRIVACY_PREFER_TEMPORARY=  2,
};

enum {
	NI_IPV6_ACCEPT_RA_DEFAULT	= -1,
	NI_IPV6_ACCEPT_RA_DISABLED	=  0,
	NI_IPV6_ACCEPT_RA_HOST		=  1,
	NI_IPV6_ACCEPT_RA_ROUTER	=  2,
};

enum {
	NI_IPV6_ACCEPT_DAD_DEFAULT	= -1,
	NI_IPV6_ACCEPT_DAD_DISABLED	=  0,
	NI_IPV6_ACCEPT_DAD_FAIL_ADDRESS	=  1,
	NI_IPV6_ACCEPT_DAD_FAIL_PROTOCOL=  2,
};

enum {
	NI_IPV6_ADDR_GEN_MODE_DEFAULT	= -1,
	NI_IPV6_ADDR_GEN_MODE_EUI64	=  0,
	NI_IPV6_ADDR_GEN_MODE_NONE,
	NI_IPV6_ADDR_GEN_MODE_STABLE_PRIVACY,
	NI_IPV6_ADDR_GEN_MODE_RANDOM,
};

enum {
	NI_IPV6_READY			= 0U,
	NI_IPV6_RS_SENT			= 1,
	NI_IPV6_RA_RCVD			= 2,
};

struct ni_ipv6_devconf {
	ni_tristate_t		enabled;
	ni_tristate_t		forwarding;
	ni_tristate_t		accept_redirects;
	int			accept_ra;
	int			accept_dad;

	int			addr_gen_mode;
	struct in6_addr		stable_secret;

	ni_tristate_t		autoconf;
	int			privacy; /* -1 for lo & p-t-p otherwise 0, 1, >1 */
};

struct ni_ipv6_ra_pinfo {
	ni_ipv6_ra_pinfo_t *	next;

	ni_sockaddr_t		prefix;
	unsigned int		length;

	ni_bool_t		on_link;
	ni_bool_t		autoconf;

	struct timeval		acquired;
	unsigned int		valid_lft;
	unsigned int		preferred_lft;
};

struct ni_ipv6_ra_rdnss {
	ni_ipv6_ra_rdnss_t *	next;

	ni_sockaddr_t		server;

	struct timeval		acquired;
	unsigned int		lifetime;
};

struct ni_ipv6_ra_dnssl {
	ni_ipv6_ra_dnssl_t *	next;

	char *			domain;

	struct timeval		acquired;
	unsigned int		lifetime;
};

struct ni_ipv6_ra_info {
	ni_bool_t		managed_addr;	/* address config available via DHCPv6  */
	ni_bool_t		other_config;	/* non-address config only via DHCPv6   */

	ni_ipv6_ra_pinfo_t *	pinfo;
	ni_ipv6_ra_rdnss_t *	rdnss;
	ni_ipv6_ra_dnssl_t *	dnssl;
};

struct ni_ipv6_devinfo {
	unsigned int		flags;

	ni_ipv6_devconf_t	conf;
	ni_ipv6_ra_info_t	radv;
};

extern ni_bool_t		ni_ipv6_supported(void);
extern ni_ipv6_devinfo_t *	ni_netdev_get_ipv6(ni_netdev_t *);
extern void			ni_netdev_set_ipv6(ni_netdev_t *, ni_ipv6_devconf_t *);
extern ni_bool_t		ni_netdev_ipv6_is_ready(const ni_netdev_t *);
extern ni_bool_t		ni_netdev_ipv6_ra_received(const ni_netdev_t *);
extern ni_bool_t		ni_netdev_ipv6_ra_requested(const ni_netdev_t *);

extern ni_ipv6_devinfo_t *	ni_ipv6_devinfo_new(void);
extern void			ni_ipv6_devinfo_free(ni_ipv6_devinfo_t *);
extern ni_bool_t		ni_ipv6_devinfo_is_ready(const ni_ipv6_devinfo_t *);
extern ni_bool_t		ni_ipv6_devinfo_ra_received(const ni_ipv6_devinfo_t *);
extern ni_bool_t		ni_ipv6_devinfo_ra_requested(const ni_ipv6_devinfo_t *);

extern int			ni_system_ipv6_devinfo_get(ni_netdev_t *, ni_ipv6_devinfo_t *);
extern int			ni_system_ipv6_devinfo_set(ni_netdev_t *, const ni_ipv6_devconf_t *);

extern const char *		ni_ipv6_devconf_privacy_to_name(int privacy);
extern const char *		ni_ipv6_devconf_accept_ra_to_name(int accept_ra);
extern const char *		ni_ipv6_devconf_accept_dad_to_name(int accept_dad);
extern const char *		ni_ipv6_devconf_addr_gen_mode_to_name(int addr_gen_mode);

#endif /* NI_WICKED_IPv6_H */
