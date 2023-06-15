/*
 *	Address configuration for wicked
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2022 SUSE LLC
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Olaf Kirch
 *		Marius Tomaschewski
 */

#ifndef NI_WICKED_ADDRCONF_H
#define NI_WICKED_ADDRCONF_H

#include <wicked/types.h>
#include <wicked/refcount.h>
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
	NI_ADDRCONF_UPDATE_MTU,
	NI_ADDRCONF_UPDATE_SIP,
	NI_ADDRCONF_UPDATE_LPR,
	NI_ADDRCONF_UPDATE_TZ,
	NI_ADDRCONF_UPDATE_BOOT,
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
	NI_ADDRCONF_STATE_APPLYING,
	NI_ADDRCONF_STATE_GRANTED,
	NI_ADDRCONF_STATE_RELEASING,
	NI_ADDRCONF_STATE_RELEASED,
	NI_ADDRCONF_STATE_FAILED,

	__NI_ADDRCONF_STATE_MAX
};

/*
 * Lease handling flag bits
 */
enum {
	NI_ADDRCONF_FLAGS_GROUP,	/* lease type group acting as one    */
	NI_ADDRCONF_FLAGS_PRIMARY,	/* primary lease triggering fallback */
	NI_ADDRCONF_FLAGS_FALLBACK,	/* fallback of a primary lease       */
	NI_ADDRCONF_FLAGS_OPTIONAL,	/* optional lease allowed to fail    */
};

/*
 * DHCP FQDN option update
 */
typedef enum {
	NI_DHCP_FQDN_UPDATE_BOTH,	/* server updates A/AAAA and PTR RR  */
	NI_DHCP_FQDN_UPDATE_NONE,	/* server does not update DNS        */
	NI_DHCP_FQDN_UPDATE_PTR,	/* server updates PTR RR only        */
} ni_dhcp_fqdn_update_t;

typedef struct ni_dhcp_fqdn {
	ni_tristate_t		enabled;
	ni_dhcp_fqdn_update_t	update;
	ni_bool_t		encode;	/* DHCP6 ignored, DHCP4: default true,
					   false for deprecated ascii format */
	ni_bool_t		qualify;/* qualify subdomains, default: true */
} ni_dhcp_fqdn_t;

/*
 * DHCP6 run/configuration mode
 */
typedef enum ni_dhcp6_mode {
	NI_DHCP6_MODE_AUTO,		/* Follow router advertisement hint  */
	NI_DHCP6_MODE_INFO,		/* Request configuration info only   */
	NI_DHCP6_MODE_MANAGED,		/* Request address and configuration */
	NI_DHCP6_MODE_PREFIX		/* Request delegation prefix (+info) */
} ni_dhcp6_mode_t;

/*
 * DHCPv4 user class structure
 */
typedef enum {
	NI_DHCP4_USER_CLASS_RFC3004 = 0U,
	NI_DHCP4_USER_CLASS_STRING,
} ni_dhcp4_user_class_format_t;

typedef struct ni_dhcp4_user_class {
	ni_dhcp4_user_class_format_t    format;
	ni_string_array_t               class_id;
} ni_dhcp4_user_class_t;

typedef struct ni_dhcp_option		ni_dhcp_option_t;

typedef struct ni_addrconf_updater	ni_addrconf_updater_t;

struct ni_addrconf_lease {
	ni_refcount_t		refcount;
	ni_addrconf_lease_t *	next;

	ni_addrconf_updater_t *	updater;	/* update actions	*/
	ni_addrconf_lease_t *	old;		/* replaced old lease	*/

	unsigned int		seqno;		/* globally unique sequence # */
	ni_addrconf_mode_t	type;
	unsigned int		family;
	unsigned int		flags;
	char *			owner;

	ni_uuid_t		uuid;
	int			state;
	struct timeval		acquired;

	unsigned int		update;

	ni_dhcp_fqdn_t		fqdn;
	char *			hostname;
	ni_address_t *		addrs;
	ni_route_table_t *	routes;
	ni_rule_array_t	*	rules;

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
		char *			sender_hwa;

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

		ni_dhcp_option_t *	options;
	    } dhcp4;
	    struct ni_addrconf_lease_dhcp6 {
		ni_opaque_t		client_id;
		ni_opaque_t		server_id;
		uint8_t			server_pref;
		struct in6_addr		server_addr;
		ni_bool_t		rapid_commit;
		uint32_t		info_refresh;
		ni_dhcp6_status_t *	status;
		ni_dhcp6_ia_t *		ia_list;
		char *			boot_url;
		ni_string_array_t	boot_params;

		ni_dhcp_option_t *	options;
	    } dhcp6;
	};
};

enum ni_lease_event {
	NI_EVENT_LEASE_ACQUIRED,
	NI_EVENT_LEASE_RELEASED,
	NI_EVENT_LEASE_DEFERRED,
	NI_EVENT_LEASE_LOST
};

extern				ni_declare_refcounted_new(ni_addrconf_lease,
							int type, int family);
extern				ni_declare_refcounted_ref(ni_addrconf_lease);
extern				ni_declare_refcounted_free(ni_addrconf_lease);
extern				ni_declare_refcounted_hold(ni_addrconf_lease);
extern				ni_declare_refcounted_drop(ni_addrconf_lease);
extern				ni_declare_refcounted_move(ni_addrconf_lease);

extern ni_addrconf_lease_t *	ni_addrconf_lease_clone(const ni_addrconf_lease_t *);
extern void			ni_addrconf_lease_destroy(ni_addrconf_lease_t *);
extern void			ni_addrconf_lease_list_destroy(ni_addrconf_lease_t **);

static inline int		ni_addrconf_lease_is_valid(const ni_addrconf_lease_t *lease)
{
	return lease && lease->state == NI_ADDRCONF_STATE_GRANTED;
}

extern int			ni_addrconf_lease_file_write(const char *, ni_addrconf_lease_t *);
extern ni_addrconf_lease_t *	ni_addrconf_lease_file_read(const char *, int, int);
extern ni_bool_t		ni_addrconf_lease_file_exists(const char *, int, int);
extern void			ni_addrconf_lease_file_remove(const char *, int, int);

extern int			ni_addrconf_lease_to_xml(const ni_addrconf_lease_t *, xml_node_t **, const char *);
extern int			ni_addrconf_lease_from_xml(ni_addrconf_lease_t **, const xml_node_t *, const char *);

extern int			ni_addrconf_name_to_type(const char *);
extern const char *		ni_addrconf_type_to_name(unsigned int);

extern int			ni_addrconf_name_to_state(const char *);
extern const char *		ni_addrconf_state_to_name(unsigned int);

extern const char *		ni_addrconf_flag_bit_to_name(unsigned int);
extern ni_bool_t		ni_addrconf_name_to_flag_bit(const char *, unsigned int *);
extern void			ni_addrconf_flag_bit_set(unsigned int *, unsigned int, ni_bool_t);
extern ni_bool_t		ni_addrconf_flag_bit_is_set(unsigned int, unsigned int);
extern const char *		ni_addrconf_flags_format(ni_stringbuf_t *, unsigned int, const char *);

extern const char *		ni_addrconf_update_flag_to_name(unsigned int);
extern ni_bool_t		ni_addrconf_update_name_to_flag(const char *, unsigned int *);
extern void			ni_addrconf_update_set(unsigned int *, unsigned int, ni_bool_t);
extern ni_bool_t		ni_addrconf_update_flags_parse_names(unsigned int *, const ni_string_array_t *);
extern ni_bool_t		ni_addrconf_update_flags_parse(unsigned int *, const char *, const char *);
extern const char *		ni_addrconf_update_flags_format(ni_stringbuf_t *, unsigned int, const char *);

extern const char *		ni_dhcp4_user_class_format_type_to_name(unsigned int);
extern int			ni_dhcp4_user_class_format_name_to_type(const char *, unsigned int *);

extern void			ni_dhcp_fqdn_init(ni_dhcp_fqdn_t *);
extern const char *		ni_dhcp_fqdn_update_mode_to_name(unsigned int);
extern ni_bool_t		ni_dhcp_fqdn_update_name_to_mode(const char *, unsigned int *);

extern const char *		ni_netbios_node_type_to_name(unsigned int);
extern ni_bool_t		ni_netbios_node_type_to_code(const char *, unsigned int *);

extern unsigned int		ni_addrconf_lease_get_priority(const ni_addrconf_lease_t *);
extern unsigned int		ni_addrconf_lease_addrs_set_tentative(ni_addrconf_lease_t *, ni_bool_t);

struct ni_auto4_request {
	ni_bool_t	enabled;
	unsigned int	flags;
	ni_uuid_t	uuid;
};

extern ni_auto4_request_t *	ni_auto4_request_new(void);
extern ni_bool_t		ni_auto4_request_copy(ni_auto4_request_t *, const ni_auto4_request_t *);
extern void			ni_auto4_request_init(ni_auto4_request_t *, ni_bool_t);
extern void			ni_auto4_request_destroy(ni_auto4_request_t *);
extern void			ni_auto4_request_free(ni_auto4_request_t *);

extern const ni_intmap_t *	ni_dhcp6_mode_map(void);
extern const char *		ni_dhcp6_mode_flag_to_name(ni_dhcp6_mode_t);
extern ni_bool_t		ni_dhcp6_mode_name_to_flag(const char *, ni_dhcp6_mode_t *);
extern unsigned int		ni_dhcp6_mode_adjust(unsigned int);
extern ni_bool_t		ni_dhcp6_mode_parse(unsigned int *, const char *);
extern const char *		ni_dhcp6_mode_format(ni_stringbuf_t *, unsigned int, const char *);

#endif /* NI_WICKED_ADDRCONF_H */
