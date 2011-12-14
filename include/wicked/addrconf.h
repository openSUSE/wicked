/*
 * Address configuration modes for netinfo
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_ADDRCONF_H__
#define __WICKED_ADDRCONF_H__

#include <wicked/types.h>
#include <wicked/constants.h>

struct ni_addrconf {
	ni_addrconf_mode_t	type;

	/* Supported address families.
	 * Bitwise OR of NI_AF_MASK_* values
	 */
	unsigned int		supported_af;

	void *			private;

	int			(*request)(const ni_addrconf_t *, ni_interface_t *);
	int			(*release)(const ni_addrconf_t *, ni_interface_t *, ni_addrconf_lease_t *);
	int			(*test)(const ni_addrconf_t *, const ni_interface_t *, const xml_node_t *);
	void			(*interface_event)(const ni_addrconf_t *, ni_interface_t *, ni_event_t);
	int			(*is_valid)(const ni_addrconf_t *, const ni_addrconf_lease_t *);

	/* Convert protocol specific lease information */
	int			(*xml_to_request)(const ni_addrconf_t *, ni_addrconf_request_t *, const xml_node_t *);
	int			(*xml_from_request)(const ni_addrconf_t *, const ni_addrconf_request_t *, xml_node_t *);
	int			(*xml_to_lease)(const ni_addrconf_t *, ni_addrconf_lease_t *, const xml_node_t *);
	int			(*xml_from_lease)(const ni_addrconf_t *, const ni_addrconf_lease_t *, xml_node_t *);
};

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


struct ni_addrconf_request {
	ni_addrconf_mode_t	type;		/* addrconf type */
	unsigned int		family;		/* address family */
	ni_uuid_t		uuid;

	/* Controlling general behavior */
	int			reuse_unexpired;
	unsigned int		settle_timeout;	/* wait that long before starting DHCP */
	unsigned int		acquire_timeout;/* acquiry of the lease times out after this */

	/* Options controlling what to put into the lease request */
	struct {
		ni_address_t *	addrs;
		ni_route_t *	routes;
	} statik;
	struct {
		char *		hostname;
		char *		clientid;
		char *		vendor_class;
		unsigned int	lease_time;
	} dhcp;

	/* Options what to update based on the info received from 
	 * the DHCP server. */
	unsigned int		update;
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
};

struct ni_addrconf_lease {
	ni_addrconf_mode_t	type;
	int			family;
	ni_uuid_t		uuid;
	int			state;

	unsigned int		time_acquired;

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
	};
};

enum ni_lease_event {
	NI_EVENT_LEASE_ACQUIRED,
	NI_EVENT_LEASE_RELEASED,
	NI_EVENT_LEASE_LOST
};

#define NI_ADDRCONF_MASK(mode)		(1 << (mode))
#define NI_ADDRCONF_TEST(mask, mode)	!!((mask) & NI_ADDRCONF_MASK(mode))

static inline void
ni_afinfo_addrconf_enable(struct ni_afinfo *afi, ni_addrconf_mode_t mode)
{
	afi->addrconf |= NI_ADDRCONF_MASK(mode);
}

static inline void
ni_afinfo_addrconf_disable(struct ni_afinfo *afi, ni_addrconf_mode_t mode)
{
	afi->addrconf &= ~NI_ADDRCONF_MASK(mode);
}

static inline int
ni_afinfo_addrconf_test(const struct ni_afinfo *afi, ni_addrconf_mode_t mode)
{
	return !!(afi->addrconf & NI_ADDRCONF_MASK(mode));
}

static inline void
ni_addrconf_set_update(ni_addrconf_request_t *req, unsigned int target)
{
	req->update |= (1 << target);
}

static inline int
ni_addrconf_should_update(const ni_addrconf_request_t *req, unsigned int target)
{
	return req->update & (1 << target);
}

static inline void
__ni_addrconf_set_update(unsigned int *mask_p, unsigned int target)
{
	*mask_p |= (1 << target);
}

static inline void
__ni_addrconf_clear_update(unsigned int *mask_p, unsigned int target)
{
	*mask_p &= ~(1 << target);
}

static inline int
__ni_addrconf_should_update(unsigned int mask, unsigned int target)
{
	return mask & (1 << target);
}

extern ni_afinfo_t *	ni_afinfo_new(int family);
extern void		ni_afinfo_free(ni_afinfo_t *);

extern ni_addrconf_request_t *ni_addrconf_request_new(unsigned int mode, unsigned int af);
extern ni_addrconf_request_t *ni_addrconf_request_clone(const ni_addrconf_request_t *);
extern void		ni_addrconf_request_free(ni_addrconf_request_t *);
extern int		ni_addrconf_request_equal(const ni_addrconf_request_t *, const ni_addrconf_request_t *);

extern ni_addrconf_lease_t *ni_addrconf_lease_new(int type, int family);
extern void		ni_addrconf_lease_destroy(ni_addrconf_lease_t *);
extern void		ni_addrconf_lease_free(ni_addrconf_lease_t *);
extern void		ni_addrconf_register(ni_addrconf_t *);
extern ni_addrconf_t *	ni_addrconf_get(int type, int family);
extern int		ni_addrconf_acquire_lease(const ni_addrconf_t *, ni_interface_t *);
extern int		ni_addrconf_drop_lease(const ni_addrconf_t *, ni_interface_t *);
extern int		ni_addrconf_lease_is_valid(const ni_addrconf_lease_t *);
extern int		ni_addrconf_check(const ni_addrconf_t *, const ni_interface_t *, const xml_node_t *);
extern const ni_addrconf_t *ni_addrconf_list_first(unsigned int *);
extern const ni_addrconf_t *ni_addrconf_list_next(unsigned int *);
extern int		ni_addrconf_lease_file_write(const char *, ni_addrconf_lease_t *);
extern ni_addrconf_lease_t *ni_addrconf_lease_file_read(const char *, int, int);
extern void		ni_addrconf_lease_file_remove(const char *, int, int);
extern int		ni_addrconf_request_file_write(const char *, ni_addrconf_request_t *);
extern ni_addrconf_request_t *ni_addrconf_request_file_read(const char *, int, int);
extern void		ni_addrconf_request_file_remove(const char *, int, int);

extern unsigned int	ni_system_update_capabilities(void);
extern int		ni_system_update_from_lease(ni_handle_t *, ni_interface_t *, const ni_addrconf_lease_t *);

#endif /* __WICKED_ADDRCONF_H__ */
