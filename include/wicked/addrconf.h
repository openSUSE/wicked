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
 * Lease update flags
 */
enum {
	NI_ADDRCONF_UPDATE_DEFAULT_ROUTE,
	NI_ADDRCONF_UPDATE_HOSTNAME,
	NI_ADDRCONF_UPDATE_DNS,
	NI_ADDRCONF_UPDATE_NIS,
	NI_ADDRCONF_UPDATE_NTP,
	NI_ADDRCONF_UPDATE_SMB,
	NI_ADDRCONF_UPDATE_NDS,
	NI_ADDRCONF_UPDATE_SLP,
	NI_ADDRCONF_UPDATE_LOG,
	__NI_ADDRCONF_UPDATE_NONE = 0,
};

/*
 * Lease updater types
 */
enum {
	NI_ADDRCONF_UPDATER_GENERIC,
	NI_ADDRCONF_UPDATER_HOSTNAME,
	NI_ADDRCONF_UPDATER_RESOLVER,
	__NI_ADDRCONF_UPDATER_MAX
};

/*
 * Lease updater format, leaseinfo only for now
 */
enum {
	NI_ADDRCONF_UPDATER_FORMAT_NONE,
	NI_ADDRCONF_UPDATER_FORMAT_INFO,
};

/*
 * Leases obtained through a dynamic addrconf protocol,
 * such as DHCPv4, DHCPv6, IPv4LL, or IBFT.
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


/*
 * DHCP6 run/configuration mode
 */
typedef enum ni_dhcp6_mode {
	NI_DHCP6_MODE_AUTO,		/* Follow router advertisement hint  */
	NI_DHCP6_MODE_INFO,		/* Request configuration info only   */
	NI_DHCP6_MODE_MANAGED		/* Request address and configuration */
} ni_dhcp6_mode_t;


struct ni_dhcp6_status;
struct ni_dhcp6_ia;

struct ni_addrconf_lease {
	ni_addrconf_lease_t *	next;

	unsigned int		seqno;		/* globally unique sequence # */
	ni_addrconf_mode_t	type;
	unsigned int		family;
	char *			owner;

	ni_uuid_t		uuid;
	int			state;

	unsigned int		time_acquired;

	unsigned int		update;

	char *			hostname;
	ni_address_t *		addrs;
	ni_route_table_t *	routes;

	/* Services discovered through the DHCP and similar */
	ni_nis_info_t *		nis;
	ni_resolver_info_t *	resolver;

	ni_string_array_t	ntp_servers;
	ni_string_array_t	nds_servers;
	ni_string_array_t	nds_context;
	char *			nds_tree;
	ni_string_array_t	netbios_name_servers;
	ni_string_array_t	netbios_dd_servers;
	char *			netbios_scope;
	unsigned int 		netbios_type;
	ni_string_array_t	slp_servers;
	ni_string_array_t	slp_scopes;
	ni_string_array_t	sip_servers;
	ni_string_array_t	lpr_servers;
	ni_string_array_t	log_servers;
	char *			posix_tz_string;
	char *			posix_tz_dbname;

	/* Information specific to some addrconf protocol */
	union {
	    struct ni_addrconf_lease_dhcp4 {
		ni_opaque_t		client_id;
		struct in_addr		server_id;
		struct in_addr		relay_addr;

		struct in_addr		address;
		struct in_addr		netmask;
		struct in_addr		broadcast;
		uint16_t		mtu;

		uint32_t		lease_time;
		uint32_t		renewal_time;
		uint32_t		rebind_time;

		struct in_addr		boot_saddr;
		char *			boot_sname;
		char *			boot_file;
		char *			root_path;
		char *			message;
	    } dhcp4;
	    struct ni_addrconf_lease_dhcp6 {
		ni_opaque_t		client_id;
		ni_opaque_t		server_id;
		uint8_t			server_pref;
		struct in6_addr		server_addr;
		ni_bool_t		rapid_commit;
		struct ni_dhcp6_status *status;
		struct ni_dhcp6_ia *	ia_list;
		char *			boot_url;
		ni_string_array_t	boot_params;
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

extern int		ni_addrconf_lease_to_xml(const ni_addrconf_lease_t *, xml_node_t **);
extern int		ni_addrconf_lease_from_xml(ni_addrconf_lease_t **, const xml_node_t *);

extern int		ni_system_update_from_lease(const ni_addrconf_lease_t *, const unsigned int, const char *);

extern const char *	ni_addrconf_update_flag_to_name(unsigned int);
extern ni_bool_t	ni_addrconf_update_name_to_flag(const char *, unsigned int *);
extern void		ni_addrconf_update_set(unsigned int *, unsigned int, ni_bool_t);

extern const char *	ni_netbios_node_type_to_name(unsigned int);
extern ni_bool_t	ni_netbios_node_type_to_code(const char *, unsigned int *);

#endif /* __WICKED_ADDRCONF_H__ */
