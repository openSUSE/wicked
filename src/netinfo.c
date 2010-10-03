/*
 * Routines for detecting and monitoring network interfaces.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 *
 * TODO
 *  -	Check that the module options specified for the bonding
 *	module do not conflict between interfaces
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include "netinfo_priv.h"
#include "config.h"

static void	__ni_interface_clear_vlan(ni_interface_t *);
static void	__ni_interface_clear_bonding(ni_interface_t *);
static void	__ni_interface_clear_bridge(ni_interface_t *);

/*
 * Global data for netinfo library
 */
ni_global_t	ni_global;

/*
 * Global initialization of application
 */
int
ni_init()
{
	int explicit_config = 1;
	ni_config_t *conf;

	if (ni_global.initialized) {
		error("ni_init called twice");
		return -1;
	}

	if (ni_global.config_path == NULL) {
		ni_string_dup(&ni_global.config_path, NI_DEFAULT_CONFIG_PATH);
		explicit_config = 0;
	}

	if (ni_file_exists(ni_global.config_path)) {
		ni_global.config = ni_config_parse(ni_global.config_path);
		if (!ni_global.config) {
			error("Unable to parse netinfo configuration file");
			return -1;
		}
	} else {
		if (explicit_config) {
			error("Configuration file %s does not exist",
					ni_global.config_path);
			return -1;
		}
		/* Create empty default configuration */
		ni_global.config = ni_config_new();
	}

	conf = ni_global.config;
	if (conf->policy.path
	 && ni_policy_file_parse(conf->policy.path, &ni_global.policies) < 0) {
		ni_error("error parsing policy file %s", conf->policy.path);
		return -1;
	}

	if (!ni_global.default_syntax)
		ni_global.default_syntax = ni_syntax_new("netcf", NULL);
	ni_global.xml_syntax = ni_syntax_new("netcf", NULL);

	ni_global.initialized = 1;
	return 0;
}

ni_syntax_t *
ni_default_xml_syntax(void)
{
	__ni_assert_initialized();
	return ni_global.xml_syntax;
}

ni_policy_info_t *
ni_default_policies(void)
{
	__ni_assert_initialized();
	return &ni_global.policies;
}

void
ni_set_global_config_path(const char *pathname)
{
	ni_string_dup(&ni_global.config_path, pathname);
}

/*
 * Utility functions for starting/stopping the wicked daemon,
 * and for connecting to it
 */
int
ni_server_background(void)
{
	ni_config_fslocation_t *fsloc = &ni_global.config->pidfile;

	return ni_daemonize(fsloc->path, fsloc->mode);
}

int
ni_server_listen(void)
{
	ni_config_fslocation_t *fsloc = &ni_global.config->socket;
	int sockfd;

	__ni_assert_initialized();
	if (fsloc->path == NULL) {
		error("no socket path set for server socket");
		return -1;
	}

	sockfd = ni_local_socket_listen(fsloc->path, fsloc->mode);
	return sockfd;
}

int
ni_server_connect(void)
{
	__ni_assert_initialized();
	return ni_local_socket_connect(ni_global.config->socket.path);
}

void
ni_server_set_event_handler(void (*ifevent_handler)(ni_handle_t *, ni_interface_t *, ni_event_t))
{
	ni_global.interface_event = ifevent_handler;
}

ni_handle_t *
__ni_handle_new(size_t size, struct ni_ops *ops)
{
	ni_handle_t *nih;

	__ni_assert_initialized();

	if (size < sizeof(*nih))
		ni_fatal("__ni_handle_new: requested size less than size of ni_handle!");

	nih = calloc(1, size);
	if (!nih) {
		ni_error("__ni_handle_new: %m");
		return NULL;
	}

	nih->op = ops;
	nih->rth.fd = -1;
	nih->iocfd = -1;

	return nih;
}

int
ni_refresh(ni_handle_t *nih)
{
	__ni_assert_initialized();
	return nih->op->refresh(nih);
}

void
ni_close(ni_handle_t *nih)
{
	if (nih->op->close)
		nih->op->close(nih);

	ni_route_list_destroy(&nih->routes);
	__ni_interfaces_clear(nih);

	nih->op = NULL;
	free(nih);
}

/*
 * Dummy ni_handle - this can be used to convert XML to an
 * interface description, which is then manipulated further.
 */
static struct ni_ops ni_dummy_ops = {
	/* No operations defined */
};

ni_handle_t *
ni_dummy_open(void)
{
	return __ni_handle_new(sizeof(ni_handle_t), &ni_dummy_ops);
}


/*
 * Map interface link layer types to strings and vice versa
 */
static ni_intmap_t __linktype_names[] = {
	{ "unknown",		NI_IFTYPE_UNKNOWN },
	{ "loopback",		NI_IFTYPE_LOOPBACK },
	{ "ethernet",		NI_IFTYPE_ETHERNET },
	{ "bridge",		NI_IFTYPE_BRIDGE },
	{ "bond",		NI_IFTYPE_BOND },
	{ "vlan",		NI_IFTYPE_VLAN },
	{ "wireless",		NI_IFTYPE_WIRELESS },
	{ "infiniband",		NI_IFTYPE_INFINIBAND },
	{ "ppp",		NI_IFTYPE_PPP },
	{ "slip",		NI_IFTYPE_SLIP },
	{ "sit",		NI_IFTYPE_SIT },
	{ "gre",		NI_IFTYPE_GRE },
	{ "isdn",		NI_IFTYPE_ISDN },
	{ "tunnel",		NI_IFTYPE_TUNNEL },
	{ "tunnel6",		NI_IFTYPE_TUNNEL6 },
	{ "virtual-tunnel",	NI_IFTYPE_TUN },
	{ "virtual-tap",	NI_IFTYPE_TAP },
	{ "dummy",		NI_IFTYPE_DUMMY },

	{ NULL }
};

int
ni_linktype_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __linktype_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_linktype_type_to_name(unsigned int type)
{
	return ni_format_int_mapped(type, __linktype_names);
}

/*
 * Map addrconf name to type constant and vice versa
 */
static ni_intmap_t __addrconf_names[] = {
	{ "dhcp",	NI_ADDRCONF_DHCP	},
	{ "ibft",	NI_ADDRCONF_IBFT	},

	{ NULL }
};

int
ni_addrconf_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __addrconf_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_addrconf_type_to_name(unsigned int type)
{
	return ni_format_int_mapped(type, __addrconf_names);
}

/*
 * Map address family names to type constants and vice versa
 */
static ni_intmap_t __addrfamily_names[] = {
	{ "ipv4",	AF_INET		},
	{ "ipv6",	AF_INET6	},

	{ NULL }
};

int
ni_addrfamily_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __addrfamily_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_addrfamily_type_to_name(unsigned int type)
{
	return ni_format_int_mapped(type, __addrfamily_names);
}

/*
 * Map ARPHRD_* constants to string
 */
#define __ARPMAP(token, name) { #name, ARPHRD_##token }

static ni_intmap_t __arphrd_names[] = {
 __ARPMAP(NETROM,		netrom),
 __ARPMAP(ETHER,		ether),
 __ARPMAP(EETHER,		eether),
 __ARPMAP(AX25,			ax25),
 __ARPMAP(PRONET,		pronet),
 __ARPMAP(CHAOS,		chaos),
 __ARPMAP(IEEE802,		ieee802),
 __ARPMAP(ARCNET,		arcnet),
 __ARPMAP(APPLETLK,		appletlk),
 __ARPMAP(DLCI,			dlci),
 __ARPMAP(ATM,			atm),
 __ARPMAP(METRICOM,		metricom),
 __ARPMAP(IEEE1394,		ieee1394),
 __ARPMAP(EUI64,		eui64),
 __ARPMAP(INFINIBAND,		infiniband),
 __ARPMAP(SLIP,			slip),
 __ARPMAP(CSLIP,		cslip),
 __ARPMAP(SLIP6,		slip6),
 __ARPMAP(CSLIP6,		cslip6),
 __ARPMAP(RSRVD,		rsrvd),
 __ARPMAP(ADAPT,		adapt),
 __ARPMAP(ROSE,			rose),
 __ARPMAP(X25,			x25),
 __ARPMAP(HWX25,		hwx25),
 __ARPMAP(PPP,			ppp),
 __ARPMAP(HDLC,			hdlc),
 __ARPMAP(LAPB,			lapb),
 __ARPMAP(DDCMP,		ddcmp),
 __ARPMAP(RAWHDLC,		rawhdlc),
 __ARPMAP(TUNNEL,		tunnel),
 __ARPMAP(TUNNEL6,		tunnel6),
 __ARPMAP(FRAD,			frad),
 __ARPMAP(SKIP,			skip),
 __ARPMAP(LOOPBACK,		loopback),
 __ARPMAP(LOCALTLK,		localtlk),
 __ARPMAP(FDDI,			fddi),
 __ARPMAP(BIF,			bif),
 __ARPMAP(SIT,			sit),
 __ARPMAP(IPDDP,		ipddp),
 __ARPMAP(IPGRE,		ipgre),
 __ARPMAP(PIMREG,		pimreg),
 __ARPMAP(HIPPI,		hippi),
 __ARPMAP(ASH,			ash),
 __ARPMAP(ECONET,		econet),
 __ARPMAP(IRDA,			irda),
 __ARPMAP(FCPP,			fcpp),
 __ARPMAP(FCAL,			fcal),
 __ARPMAP(FCPL,			fcpl),
 __ARPMAP(FCFABRIC,		fcfabric),
 __ARPMAP(IEEE802_TR,		IEEE802_tr),
 __ARPMAP(IEEE80211,		ieee80211),
 __ARPMAP(IEEE80211_PRISM,	IEEE80211_prism),
 __ARPMAP(IEEE80211_RADIOTAP,	IEEE80211_radiotap),
 __ARPMAP(VOID,			void),
 __ARPMAP(NONE,			none),
 /* 65534 tun */

 { 0 }
};

int
ni_arphrd_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __arphrd_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_arphrd_type_to_name(unsigned int type)
{
	return ni_format_int_mapped(type, __arphrd_names);
}

/*
 * Map netinfo interface types to ARPHRD_ and vice versa
 */
static struct __ni_arptype_iftype_map {
	int		type;
	unsigned int	arp_type;
} __ni_arptype_iftype_map[] = {
      {	NI_IFTYPE_LOOPBACK,	ARPHRD_LOOPBACK	},
      {	NI_IFTYPE_ETHERNET,	ARPHRD_ETHER	},
      {	NI_IFTYPE_BRIDGE,	ARPHRD_ETHER	},
      {	NI_IFTYPE_BOND,		ARPHRD_ETHER	},
      {	NI_IFTYPE_VLAN,		ARPHRD_ETHER	},
      {	NI_IFTYPE_WIRELESS,	ARPHRD_ETHER	},
      {	NI_IFTYPE_INFINIBAND,	ARPHRD_INFINIBAND },
      {	NI_IFTYPE_PPP,		ARPHRD_PPP	},
      {	NI_IFTYPE_SLIP,		ARPHRD_SLIP	},
      {	NI_IFTYPE_SLIP,		ARPHRD_CSLIP	},
      {	NI_IFTYPE_SIT,		ARPHRD_SIT	},
      {	NI_IFTYPE_GRE,		ARPHRD_IPGRE	},
      {	NI_IFTYPE_ISDN,		ARPHRD_NONE	},
      {	NI_IFTYPE_TUNNEL,	ARPHRD_TUNNEL	},
      {	NI_IFTYPE_TUNNEL6,	ARPHRD_TUNNEL6	},
      {	NI_IFTYPE_TUN,		ARPHRD_ETHER	},
      {	NI_IFTYPE_TAP,		ARPHRD_ETHER	},
      {	NI_IFTYPE_DUMMY,	ARPHRD_LOOPBACK	},

      {	NI_IFTYPE_UNKNOWN, ARPHRD_NONE }
};

unsigned int
ni_arphrd_type_to_iftype(int arp_type)
{
	struct __ni_arptype_iftype_map *map;

	for (map = __ni_arptype_iftype_map; map->arp_type != ARPHRD_NONE; ++map)
		if (map->arp_type == arp_type)
			break;
	return map->type;
}

int
ni_iftype_to_arphrd_type(unsigned int iftype)
{
	struct __ni_arptype_iftype_map *map;

	for (map = __ni_arptype_iftype_map; map->arp_type != ARPHRD_NONE; ++map)
		if (map->type == iftype)
			break;
	return map->arp_type;
}

/*
 * Configure an interface.
 */
int
ni_interface_configure(ni_handle_t *nih, ni_interface_t *cfg, xml_node_t *cfg_xml)
{
	if (nih->op->configure_interface == NULL) {
		error("cannot configure interface; not supported by this handle");
		return -1;
	}

	return nih->op->configure_interface(nih, cfg, cfg_xml);
}

/*
 * We received an updated lease from an addrconf agent-.
 */
int
ni_interface_update_lease(ni_handle_t *nih, ni_interface_t *ifp,
				ni_addrconf_state_t *lease)
{
	ni_addrconf_state_t **p;
	ni_afinfo_t *afi;

	switch (lease->family) {
	case AF_INET:
		afi = &ifp->ipv4;
		break;

	case AF_INET6:
		afi = &ifp->ipv6;
		break;

	default:
		ni_error("unknown address family %d in lease update", lease->family);
		return -1;
	}

	switch (lease->type) {
	case NI_ADDRCONF_DHCP:
		p = &afi->dhcp_lease;
		break;

	default:
		ni_error("unknown addrconf type %d in lease type", lease->type);
		return -1;
	}

	if (*p)
		ni_addrconf_state_free(*p);
	*p = lease;

	return 0;
}

/*
 * Delete an interface, by removing its configuration file, or
 * by destroying the kernel network interface (only possible for
 * virtual interfaces like bridges, bonds or VLANs
 */
int
ni_interface_delete(ni_handle_t *nih, const char *ifname)
{
	if (nih->op->delete_interface == NULL) {
		error("cannot delete interface; not supported by this handle");
		return -1;
	}

	return nih->op->delete_interface(nih, ifname);
}

/*
 * Create the interface topology.
 * For bonds, bridges and VLANs, this looks up the interfaces
 * referred to by the parent interface, and sets the child's
 * parent pointer; and adds the child to the parent's interface
 * pointer list.
 */
int
ni_create_topology(ni_handle_t *nih)
{
	ni_interface_t *ifp;

	for (ifp = nih->iflist; ifp; ifp = ifp->next)
		ifp->parent = NULL;

	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		if (ifp->bridge && ni_bridge_bind(ifp, nih) < 0)
			return -1;
		if (ifp->bonding && ni_bonding_bind(ifp, nih) < 0)
			return -1;
		if (ifp->vlan && ni_vlan_bind(ifp, nih) < 0)
			return -1;
	}

	return 0;
}

/*
 * Error handling.
 * This needs to be expanded so that we save the error information
 * somewhere inside the ni_handle_t, so that the caller
 * can extract that error info.
 */
void
ni_bad_reference(ni_handle_t *nih, const ni_interface_t *referrer, const char *ifname)
{
	error("Error: %s references unknown interface %s",
		referrer->name, ifname);
}

/*
 * Constructor for network interface.
 * Takes interface name and ifindex.
 */
ni_interface_t *
__ni_interface_new(const char *name, unsigned int index)
{
	ni_interface_t *ifp;

	ifp = calloc(1, sizeof(*ifp) * 2);
	if (!ifp)
		return NULL;

	ifp->users = 1;
	ifp->startmode = NI_START_ONBOOT;
	ifp->type = NI_IFTYPE_UNKNOWN;
	ifp->arp_type = ARPHRD_NONE;
	ifp->hwaddr.type = ARPHRD_NONE;
	ifp->ifindex = index;
	ifp->name = strdup(name);
	if (!ifp->name) {
		free(ifp);
		return NULL;
	}

	/* Initialize address family specific info */
	ifp->ipv4.family = AF_INET;
	ifp->ipv4.config = NI_ADDRCONF_DHCP;
	ifp->ipv4.enabled = 1;
	ifp->ipv6.family = AF_INET6;
	ifp->ipv6.config = NI_ADDRCONF_AUTOCONF;
	ifp->ipv6.enabled = 1;

	return ifp;
}

ni_interface_t *
ni_interface_new(ni_handle_t *nih, const char *name, unsigned int index)
{
	ni_interface_t *ifp, **pos;

	for (pos = &nih->iflist; (ifp = *pos) != NULL; pos = &ifp->next)
		;

	ifp = __ni_interface_new(name, index);
	if (ifp)
		*pos = ifp;
	
	return ifp;
}

ni_interface_t *
ni_interface_clone(const ni_interface_t *ofp)
{
	ni_interface_t *ifp;

	ifp = __ni_interface_new(ofp->name, ofp->ifindex);
	if (!ifp)
		goto failed;

#define C(member)	ifp->member = ofp->member
#define D(member, clone_fn)	\
		do { \
			if (ofp->member) { \
				ifp->member = clone_fn(ofp->member); \
				if (!ifp->member) \
					goto failed; \
			} \
		} while (0)
	C(flags);
	C(type);
	C(arp_type);
	C(hwaddr);
	/* FIXME: clone routes, addrs */
	C(mtu);
	C(metric);
	C(txqlen);
	C(master);
	D(qdisc, strdup);
	D(kind, strdup);
	C(ipv4);
	C(ipv6);
	D(addrs, __ni_address_list_clone);
	D(routes, __ni_route_list_clone);
	D(bonding, ni_bonding_clone);
	D(vlan, ni_vlan_clone);
	D(bridge, ni_bridge_clone);
	C(startmode);
#undef C
#undef D

	return ifp;

failed:
	error("Failed to clone interface data for interface %s", ofp->name);
	if (ifp)
		ni_interface_put(ifp);
	return NULL;
}

/*
 * Look up address information for given address family.
 */
ni_address_t *
ni_interface_get_addresses(ni_interface_t *ifp, int af)
{
	ni_address_t *ap, **tail;

	for (tail = &ifp->addrs; (ap = *tail) != NULL; tail = &ap->next) {
		if (ap->family == af)
			return ap;
	}

	ap = calloc(1, sizeof(*ap));
	ap->family = af;

	*tail = ap;
	return ap;
}

ni_route_t *
ni_interface_add_route(ni_handle_t *nih, ni_interface_t *ifp,
				unsigned int prefix_len,
				const struct sockaddr_storage *dest,
				const struct sockaddr_storage *gw)
{
	return __ni_route_new(&ifp->routes, prefix_len, dest, gw);
}

/*
 * Destructor function (and assorted helpers)
 */
void
__ni_interface_clear_addresses(ni_interface_t *ifp)
{
	ni_address_list_destroy(&ifp->addrs);
}

void
__ni_interface_clear_routes(ni_interface_t *ifp)
{
	ni_route_list_destroy(&ifp->routes);
}

void
__ni_interface_clear_stats(ni_interface_t *ifp)
{
	if (ifp->link_stats)
		free(ifp->link_stats);
	ifp->link_stats = NULL;
}

static void
ni_interface_free(ni_interface_t *ifp)
{
	free(ifp->name);
	free(ifp->qdisc);

	/* Clear out addresses, stats */
	__ni_interface_clear_addresses(ifp);
	__ni_interface_clear_routes(ifp);
	__ni_interface_clear_stats(ifp);
	__ni_interface_clear_bonding(ifp);
	__ni_interface_clear_bridge(ifp);
	__ni_interface_clear_vlan(ifp);

	if (ifp->ipv4.dhcp)
		ni_dhclient_info_free(ifp->ipv4.dhcp);
	if (ifp->ipv4.dhcp_lease)
		ni_addrconf_state_free(ifp->ipv4.dhcp_lease);
	if (ifp->ipv6.dhcp)
		ni_dhclient_info_free(ifp->ipv6.dhcp);
	if (ifp->ipv6.dhcp_lease)
		ni_addrconf_state_free(ifp->ipv6.dhcp_lease);

	free(ifp);
}

/*
 * Guess the interface type based on its name and characteristics
 */
static ni_intmap_t __ifname_types[] = {
	{ "ib",		NI_IFTYPE_INFINIBAND	},
	{ "ip6tunl",	NI_IFTYPE_TUNNEL6	},
	{ "ipip",	NI_IFTYPE_TUNNEL	},
	{ "sit",	NI_IFTYPE_SIT		},
	{ "tun",	NI_IFTYPE_TUN		},

	{ NULL }
};
int
ni_interface_guess_type(ni_interface_t *ifp)
{
	if (ifp->type != NI_IFTYPE_UNKNOWN)
		return ifp->type;

	ifp->type = NI_IFTYPE_ETHERNET;
	if (!strcmp(ifp->name, "lo")) {
		ifp->type = NI_IFTYPE_LOOPBACK;
	} else {
		ni_intmap_t *map;

		for (map = __ifname_types; map->name; ++map) {
			unsigned int len = strlen(map->name);

			if (!strncmp(ifp->name, map->name, len)
			 && isdigit(ifp->name[len])) {
				ifp->type = map->value;
				break;
			}
		}
	}

	return ifp->type;
}

/*
 * Reference counting of interface objects
 */
ni_interface_t *
ni_interface_get(ni_interface_t *ifp)
{
	if (!ifp->users)
		return NULL;
	ifp->users++;
	return ifp;
}

int
ni_interface_put(ni_interface_t *ifp)
{
	if (!ifp->users) {
		error("ni_interface_put: bad mojo");
		return 0;
	}
	ifp->users--;
	if (ifp->users == 0) {
		ni_interface_free(ifp);
		return 0;
	}
	return ifp->users;
}

void
ni_interface_array_init(ni_interface_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_interface_array_append(ni_interface_array_t *array, ni_interface_t *ifp)
{
	if ((array->count & 15) == 0) {
		array->data = realloc(array->data, (array->count + 16) * sizeof(ni_interface_t *));
		assert(array->data);
	}
	array->data[array->count++] = ifp;
}

void
ni_interface_array_destroy(ni_interface_array_t *array)
{
	free(array->data);
	memset(array, 0, sizeof(*array));
}

void
__ni_interfaces_clear(ni_handle_t *nih)
{
	ni_interface_t *ifp;

	while ((ifp = nih->iflist) != NULL) {
		nih->iflist = ifp->next;
		ni_interface_put(ifp);
	}
}

/*
 * Get the list of all discovered interfaces, given a
 * netinfo handle.
 */
ni_interface_t *
ni_interfaces(ni_handle_t *nih)
{
	return nih->iflist;
}

/*
 * Find interface by name
 */
ni_interface_t *
ni_interface_by_name(ni_handle_t *nih, const char *name)
{
	ni_interface_t *ifp;

	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		if (!strcmp(ifp->name, name))
			return ifp;
	}

	return NULL;
}

/*
 * Find interface by its ifindex
 */
ni_interface_t *
ni_interface_by_index(ni_handle_t *nih, unsigned int ifindex)
{
	ni_interface_t *ifp;

	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		if (ifp->ifindex == ifindex)
			return ifp;
	}

	return NULL;
}

/*
 * Find interface by its LL address
 */
ni_interface_t *
ni_interface_by_hwaddr(ni_handle_t *nih, const ni_hwaddr_t *lla)
{
	ni_interface_t *ifp;

	if (!lla || !lla->len)
		return NULL;

	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		if (ni_link_address_equal(&ifp->hwaddr, lla))
			return ifp;
	}

	return NULL;
}

/*
 * Helper functions to iterate over all interfaces
 */
ni_interface_t *
ni_interface_first(ni_handle_t *nih, ni_interface_t **pos)
{
	ni_interface_t *ifp = nih->iflist;

	*pos = ifp? ifp->next : NULL;
	return ifp;
}

ni_interface_t *
ni_interface_next(ni_handle_t *nih, ni_interface_t **pos)
{
	ni_interface_t *ifp = *pos;

	*pos = ifp? ifp->next : NULL;
	return ifp;
}

/*
 * Get the interface's VLAN information
 */
ni_vlan_t *
ni_interface_get_vlan(ni_interface_t *ifp)
{
	if (!ifp->vlan)
		ifp->vlan = calloc(1, sizeof(ni_vlan_t));
	return ifp->vlan;
}

void
__ni_interface_clear_vlan(ni_interface_t *ifp)
{
	if (ifp->vlan) {
		ni_vlan_free(ifp->vlan);
		ifp->vlan = NULL;
	}
}

/*
 * Get the interface's bridge information
 */
ni_bridge_t *
ni_interface_get_bridge(ni_interface_t *ifp)
{
	if (!ifp->bridge)
		ifp->bridge = calloc(1, sizeof(ni_bridge_t));
	return ifp->bridge;
}

void
__ni_interface_clear_bridge(ni_interface_t *ifp)
{
	if (ifp->bridge) {
		ni_bridge_free(ifp->bridge);
		ifp->bridge = NULL;
	}
}

/*
 * Get the interface's bonding information
 */
ni_bonding_t *
ni_interface_get_bonding(ni_interface_t *ifp)
{
	if (!ifp->bonding)
		ifp->bonding = calloc(1, sizeof(ni_bonding_t));
	return ifp->bonding;
}

void
__ni_interface_clear_bonding(ni_interface_t *ifp)
{
	if (ifp->bonding) {
		ni_bonding_free(ifp->bonding);
		ifp->bonding = NULL;
	}
}


/*
 * dhcp client info
 */
ni_dhclient_info_t *
ni_dhclient_info_new(void)
{
	ni_dhclient_info_t *dhcp;

	dhcp = calloc(1, sizeof(*dhcp));

	/* Set defaults */
	dhcp->lease.timeout = -1;

	return dhcp;
}

void
ni_dhclient_info_free(ni_dhclient_info_t *dhcp)
{
	ni_string_free(&dhcp->request.hostname);
	ni_string_free(&dhcp->request.clientid);
	ni_string_free(&dhcp->request.vendor_class);
	free(dhcp);
}

/*
 * Address configuration state (aka leases)
 */
ni_addrconf_state_t *
ni_addrconf_state_new(int type, int family)
{
	ni_addrconf_state_t *lease;

	lease = calloc(1, sizeof(*lease));
	lease->type = type;
	lease->family = family;
	return lease;
}

void
ni_addrconf_state_free(ni_addrconf_state_t *lease)
{
	ni_string_free(&lease->hostname);
	ni_string_free(&lease->nis_domain);
	ni_string_free(&lease->netbios_domain);
	ni_string_array_destroy(&lease->log_servers);
	ni_string_array_destroy(&lease->dns_servers);
	ni_string_array_destroy(&lease->dns_search);
	ni_string_array_destroy(&lease->nis_servers);
	ni_string_array_destroy(&lease->ntp_servers);
	ni_string_array_destroy(&lease->netbios_servers);
	ni_string_array_destroy(&lease->slp_servers);
	ni_string_array_destroy(&lease->slp_scopes);
	ni_address_list_destroy(&lease->addrs);
	ni_route_list_destroy(&lease->routes);
}
