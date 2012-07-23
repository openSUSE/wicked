/*
 * Address configuration modes for netinfo
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_ADDRCONF_H__
#define __WICKED_ADDRCONF_H__

#include <wicked/types.h>
#include <wicked/constants.h>

/*
 * DHCP configuration info
 */
enum {
	NI_ADDRCONF_UPDATE_DEFAULT_ROUTE,
	NI_ADDRCONF_UPDATE_HOSTNAME,
	NI_ADDRCONF_UPDATE_HOSTSFILE,
	NI_ADDRCONF_UPDATE_SYSLOG,
	NI_ADDRCONF_UPDATE_RESOLVER,
	NI_ADDRCONF_UPDATE_NIS,
	NI_ADDRCONF_UPDATE_NTP,
	NI_ADDRCONF_UPDATE_NETBIOS,
	NI_ADDRCONF_UPDATE_SLP,

	__NI_ADDRCONF_UPDATE_MAX,
};


/*
 * Leases obtained through a dynamic addrconf protocol,
 * such as DHCP, DHCPv6, IPv4LL, or IBFT.
 */
enum {
	NI_ADDRCONF_STATE_NONE,
	NI_ADDRCONF_STATE_REQUESTING,
	NI_ADDRCONF_STATE_GRANTED,
	NI_ADDRCONF_STATE_RELEASING,
	NI_ADDRCONF_STATE_RELEASED,
	NI_ADDRCONF_STATE_FAILED,

	__NI_ADDRCONF_STATE_MAX
};

struct ni_dhcp6_status;
struct ni_dhcp6_ia;

struct ni_addrconf_lease {
	ni_addrconf_lease_t *	next;

	unsigned int		seqno;		/* globally unique sequence # */
	ni_addrconf_mode_t	type;
	int			family;
	char *			owner;

	ni_uuid_t		uuid;
	int			state;

	unsigned int		time_acquired;

	unsigned int		update;

	char *			hostname;
	ni_address_t *		addrs;
	ni_route_t *		routes;

	/* Services discovered through the DHCP and similar */
	ni_nis_info_t *		nis;
	ni_resolver_info_t *	resolver;

	ni_string_array_t	log_servers;
	ni_string_array_t	ntp_servers;
	ni_string_array_t	netbios_name_servers;
	ni_string_array_t	netbios_dd_servers;
	char *			netbios_domain;
	char *			netbios_scope;
	ni_string_array_t	slp_servers;
	ni_string_array_t	slp_scopes;
	ni_string_array_t	sip_servers;
	ni_string_array_t	lpr_servers;

	/* Information specific to some addrconf protocol */
	union {
	    struct ni_addrconf_lease_dhcp {
		struct in_addr		serveraddress;
		char			servername[64];
		char			client_id[64];

		struct in_addr		address;
		struct in_addr		netmask;
		struct in_addr		broadcast;
		uint16_t		mtu;

		uint32_t		lease_time;
		uint32_t		renewal_time;
		uint32_t		rebind_time;

		char *			message;
		char *			rootpath;
	    } dhcp;
	    struct ni_addrconf_lease_dhcp6 {
		ni_opaque_t		client_id;
		ni_opaque_t		server_id;
		uint8_t			server_pref;
		struct in6_addr		server_addr;
		ni_bool_t		rapid_commit;
		struct ni_dhcp6_status *status;
		struct ni_dhcp6_ia *	ia_na;
		struct ni_dhcp6_ia *	ia_ta;
		struct ni_dhcp6_ia *	ia_pd;
	    } dhcp6;
	};
};

enum ni_lease_event {
	NI_EVENT_LEASE_ACQUIRED,
	NI_EVENT_LEASE_RELEASED,
	NI_EVENT_LEASE_LOST
};

extern ni_addrconf_lease_t *ni_addrconf_lease_new(int type, int family);
extern void		ni_addrconf_lease_destroy(ni_addrconf_lease_t *);
extern void		ni_addrconf_lease_free(ni_addrconf_lease_t *);
extern void		ni_addrconf_lease_list_destroy(ni_addrconf_lease_t **list);

static inline int
ni_addrconf_lease_is_valid(const ni_addrconf_lease_t *lease)
{
	return lease && lease->state == NI_ADDRCONF_STATE_GRANTED;
}

extern int		ni_addrconf_lease_file_write(const char *, ni_addrconf_lease_t *);
extern ni_addrconf_lease_t *ni_addrconf_lease_file_read(const char *, int, int);
extern void		ni_addrconf_lease_file_remove(const char *, int, int);

extern int		ni_system_update_from_lease(const ni_addrconf_lease_t *);

#endif /* __WICKED_ADDRCONF_H__ */
