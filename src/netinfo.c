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
#include <signal.h>
#include <time.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/ethernet.h>
#include <wicked/wireless.h>
#include <wicked/socket.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include "netinfo_priv.h"
#include "dbus-server.h"
#include "config.h"

#define DEFAULT_ADDRCONF_IPV4 (\
			NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC) |\
			NI_ADDRCONF_MASK(NI_ADDRCONF_DHCP))
#define DEFAULT_ADDRCONF_IPV6 (\
			NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC) |\
			NI_ADDRCONF_MASK(NI_ADDRCONF_AUTOCONF))

static void		__ni_afinfo_destroy(ni_afinfo_t *);

/*
 * Global data for netinfo library
 */
ni_global_t	ni_global;
unsigned int	__ni_global_seqno;

/*
 * Global initialization of application
 */
int
ni_init()
{
	int explicit_config = 1;

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

	if (!ni_global.default_syntax)
		ni_global.default_syntax = ni_syntax_new("netcf", NULL);
	ni_global.xml_syntax = ni_syntax_new("netcf", NULL);

	/* Our socket code relies on us ignoring this */
	signal(SIGPIPE, SIG_IGN);

	ni_global.initialized = 1;
	return 0;
}

ni_syntax_t *
ni_default_xml_syntax(void)
{
	__ni_assert_initialized();
	return ni_global.xml_syntax;
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

ni_socket_t *
ni_server_listen(void)
{
	ni_config_fslocation_t *fsloc = &ni_global.config->socket;

	__ni_assert_initialized();
	if (fsloc->path == NULL) {
		error("no socket path set for server socket");
		return NULL;
	}

	return ni_local_socket_listen(fsloc->path, fsloc->mode);
}

ni_dbus_server_t *
ni_server_listen_dbus(const char *dbus_name)
{
	__ni_assert_initialized();
	if (dbus_name == NULL)
		dbus_name = ni_global.config->dbus_name;
	if (dbus_name == NULL) {
		ni_error("%s: no bus name specified", __FUNCTION__);
		return NULL;
	}

	return ni_dbus_server_open(dbus_name, NULL);
}

ni_socket_t *
ni_server_connect(void)
{
	__ni_assert_initialized();
	return ni_local_socket_connect(ni_global.config->socket.path);
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
	nih->iocfd = -1;

	return nih;
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
	{ "static",	NI_ADDRCONF_STATIC	},
	{ "auto",	NI_ADDRCONF_AUTOCONF	},
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
 * Map addrconf states to strings and vice versa
 */
static ni_intmap_t __addrconf_states[] = {
	{ "none",		NI_ADDRCONF_STATE_NONE },
	{ "requesting",		NI_ADDRCONF_STATE_REQUESTING },
	{ "granted",		NI_ADDRCONF_STATE_GRANTED },
	{ "releasing",		NI_ADDRCONF_STATE_RELEASING },
	{ "released",		NI_ADDRCONF_STATE_RELEASED },
	{ "failed",		NI_ADDRCONF_STATE_FAILED },

	{ NULL }
};

int
ni_addrconf_name_to_state(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __addrconf_states, &value) < 0)
		return -1;
	return value;
}

const char *
ni_addrconf_state_to_name(unsigned int type)
{
	return ni_format_int_mapped(type, __addrconf_states);
}

/*
 * Map addrconf update values to strings and vice versa
 */
static ni_intmap_t __addrconf_updates[] = {
	{ "default-route",	NI_ADDRCONF_UPDATE_DEFAULT_ROUTE },
	{ "hostname",		NI_ADDRCONF_UPDATE_HOSTNAME },
	{ "hosts-file",		NI_ADDRCONF_UPDATE_HOSTSFILE },
	{ "syslog",		NI_ADDRCONF_UPDATE_SYSLOG },
	{ "resolver",		NI_ADDRCONF_UPDATE_RESOLVER },
	{ "nis",		NI_ADDRCONF_UPDATE_NIS },
	{ "ntp",		NI_ADDRCONF_UPDATE_NTP },
	{ "smb",		NI_ADDRCONF_UPDATE_NETBIOS },
	{ "slp",		NI_ADDRCONF_UPDATE_SLP },

	{ NULL }
};

int
ni_addrconf_name_to_update_target(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __addrconf_updates, &value) < 0)
		return -1;
	return value;
}

const char *
ni_addrconf_update_target_to_name(unsigned int type)
{
	return ni_format_int_mapped(type, __addrconf_updates);
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
 * Map event names to type constants and vice versa
 */
static ni_intmap_t __event_names[] = {
	{ "link-create",	NI_EVENT_LINK_CREATE },
	{ "link-delete",	NI_EVENT_LINK_DELETE },
	{ "link-up",		NI_EVENT_LINK_UP },
	{ "link-down",		NI_EVENT_LINK_DOWN },
	{ "network-up",		NI_EVENT_NETWORK_UP },
	{ "network-down",	NI_EVENT_NETWORK_DOWN },

	{ NULL }
};

ni_event_t
ni_event_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __event_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_event_type_to_name(ni_event_t type)
{
	return ni_format_int_mapped(type, __event_names);
}

static ni_intmap_t __ifaction_names[] = {
	{ "boot",		NI_IFACTION_BOOT },
	{ "shutdown",		NI_IFACTION_SHUTDOWN },
	{ "manual-up",		NI_IFACTION_MANUAL_UP },
	{ "manual-down",	NI_IFACTION_MANUAL_DOWN },
	{ "link-up",		NI_IFACTION_LINK_UP },
	{ "link-down",		NI_IFACTION_LINK_DOWN },

	{ NULL }
};

int
ni_ifaction_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __ifaction_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_ifaction_type_to_name(unsigned int type)
{
	return ni_format_int_mapped(type, __ifaction_names);
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
 * We received an updated lease from an addrconf agent.
 */
int
ni_interface_set_lease(ni_interface_t *ifp, ni_addrconf_lease_t *lease)
{
	ni_afinfo_t *afi;

	afi = __ni_interface_address_info(ifp, lease->family);
	if (afi == NULL) {
		ni_error("unknown address family %d in lease update", lease->family);
		return -1;
	}

	if (lease->type >= __NI_ADDRCONF_MAX) {
		ni_error("unknown addrconf type %d in lease type", lease->type);
		return -1;
	}

	if (afi->lease[lease->type] != NULL)
		ni_addrconf_lease_free(afi->lease[lease->type]);
	if (lease->state == NI_ADDRCONF_STATE_GRANTED) {
		ni_afinfo_addrconf_enable(afi, lease->type);
		afi->lease[lease->type] = lease;
	} else {
		ni_afinfo_addrconf_disable(afi, lease->type);
		afi->lease[lease->type] = NULL;
	}

	return 0;
}

/*
 * Given an address, look up the lease owning it
 */
ni_addrconf_lease_t *
__ni_interface_address_to_lease(ni_interface_t *ifp, const ni_address_t *ap)
{
	ni_afinfo_t *afi = __ni_interface_address_info(ifp, ap->family);
	unsigned int type;

	if (!afi)
		return NULL;

	for (type = 0; type < __NI_ADDRCONF_MAX; ++type) {
		ni_addrconf_lease_t *lease;

		if ((lease = afi->lease[type])
		 && __ni_lease_owns_address(lease, ap))
			return lease;
	}

	return NULL;
}

ni_address_t *
__ni_lease_owns_address(const ni_addrconf_lease_t *lease, const ni_address_t *ap)
{
	time_t now = time(NULL);
	ni_address_t *own;

	if (!lease)
		return 0;
	for (own = lease->addrs; own; own = own->next) {
		if (own->prefixlen != ap->prefixlen)
			continue;
		if (own->expires && own->expires <= now)
			continue;

		/* Note: for IPv6 autoconf, we will usually have recorded the
		 * address prefix only; the address that will eventually be picked
		 * by the autoconf logic will be different */
		if (lease->family == AF_INET6 && lease->type == NI_ADDRCONF_AUTOCONF) {
			if (!ni_address_prefix_match(ap->prefixlen, &own->local_addr, &ap->local_addr))
				continue;
		} else {
			if (ni_address_equal(&own->local_addr, &ap->local_addr))
				continue;
		}

		if (ni_address_equal(&own->peer_addr, &ap->peer_addr)
		 && ni_address_equal(&own->anycast_addr, &ap->anycast_addr))
			return own;
	}
	return NULL;
}

/*
 * Given a route, look up the lease owning it
 */
ni_addrconf_lease_t *
__ni_interface_route_to_lease(ni_interface_t *ifp, const ni_route_t *rp)
{
	ni_afinfo_t *afi;
	ni_address_t *ap;
	unsigned int type;

	if (!ifp || !rp)
		return NULL;

	afi = __ni_interface_address_info(ifp, rp->family);
	if (!afi)
		return NULL;

	for (type = 0; type < __NI_ADDRCONF_MAX; ++type) {
		ni_addrconf_lease_t *lease;

		if ((lease = afi->lease[type]) == NULL)
			continue;

		/* First, check if this is an interface route */
		for (ap = lease->addrs; ap; ap = ap->next) {
			if (rp->prefixlen == ap->prefixlen
			 && ni_address_prefix_match(ap->prefixlen, &rp->destination, &ap->local_addr))
				return lease;
		}

		if (__ni_lease_owns_route(lease, rp))
			return lease;
	}

	return NULL;
}

ni_route_t *
__ni_lease_owns_route(const ni_addrconf_lease_t *lease, const ni_route_t *rp)
{
	ni_route_t *own;

	if (!lease)
		return 0;

	for (own = lease->routes; own; own = own->next) {
		if (ni_route_equal(own, rp))
			return own;
	}
	return NULL;
}

/*
 * Error handling.
 * This is crap, kill it.
 */
void
ni_bad_reference(const ni_interface_t *referrer, const char *ifname)
{
	ni_error("%s references unknown interface %s", referrer->name, ifname);
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
	ifp->startmode.ifaction[NI_IFACTION_BOOT].action = NI_INTERFACE_START;
	ifp->startmode.ifaction[NI_IFACTION_BOOT].mandatory = 1;
	ifp->startmode.ifaction[NI_IFACTION_BOOT].wait = 30;
	ifp->startmode.ifaction[NI_IFACTION_SHUTDOWN].action = NI_INTERFACE_STOP;
	ifp->startmode.ifaction[NI_IFACTION_MANUAL_UP].action = NI_INTERFACE_START;
	ifp->startmode.ifaction[NI_IFACTION_MANUAL_UP].mandatory = 1;
	ifp->startmode.ifaction[NI_IFACTION_MANUAL_UP].wait = 30;
	ifp->startmode.ifaction[NI_IFACTION_MANUAL_DOWN].action = NI_INTERFACE_STOP;
	ifp->link.type = NI_IFTYPE_UNKNOWN;
	ifp->link.arp_type = ARPHRD_NONE;
	ifp->link.hwaddr.type = ARPHRD_NONE;
	ifp->link.ifindex = index;

	if (name)
		ifp->name = xstrdup(name);

	/* Initialize address family specific info */
	ifp->ipv4.family = AF_INET;
	ifp->ipv4.addrconf = DEFAULT_ADDRCONF_IPV4;
	ifp->ipv4.enabled = 1;
	ifp->ipv6.family = AF_INET6;
	ifp->ipv6.addrconf = DEFAULT_ADDRCONF_IPV6;
	ifp->ipv6.enabled = 1;

	return ifp;
}

void
__ni_interface_list_destroy(ni_interface_t **list)
{
	ni_interface_t *ifp;

	while ((ifp = *list) != NULL) {
		*list = ifp->next;
		ni_interface_put(ifp);
	}
}


void
__ni_interface_list_append(ni_interface_t **list, ni_interface_t *new_ifp)
{
	ni_interface_t *ifp;

	while ((ifp = *list) != NULL)
		list = &ifp->next;

	new_ifp->next = NULL;
	*list = new_ifp;
}

ni_interface_t *
ni_interface_new(ni_handle_t *nih, const char *name, unsigned int index)
{
	ni_interface_t *ifp;

	ifp = __ni_interface_new(name, index);
	if (nih && ifp)
		__ni_interface_list_append(&nih->iflist, ifp);
	
	return ifp;
}

ni_interface_t *
nc_interface_new(ni_netconfig_t *nc, const char *name, unsigned int index)
{
	ni_interface_t *ifp;

	ifp = __ni_interface_new(name, index);
	if (ifp)
		__ni_interface_list_append(&nc->interfaces, ifp);
	
	return ifp;
}

ni_interface_t *
ni_interface_clone(const ni_interface_t *ofp)
{
	ni_interface_t *ifp;

	ifp = __ni_interface_new(ofp->name, ofp->link.ifindex);
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
	C(link.ifflags);
	C(link.type);
	C(link.arp_type);
	C(link.hwaddr);
	/* FIXME: clone routes, addrs */
	C(link.mtu);
	C(link.metric);
	C(link.txqlen);
	C(link.master);
	D(link.qdisc, xstrdup);
	D(link.kind, xstrdup);
	D(link.vlan, ni_vlan_clone);
	C(ipv4.enabled);
	C(ipv4.forwarding);
	C(ipv4.addrconf);
	C(ipv6.enabled);
	C(ipv6.forwarding);
	C(ipv6.addrconf);
	D(addrs, __ni_address_list_clone);
	D(routes, __ni_route_list_clone);
	D(bonding, ni_bonding_clone);
	D(bridge, ni_bridge_clone);
	D(ethernet, ni_ethernet_clone);
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
ni_interface_add_route(ni_interface_t *ifp,
				unsigned int prefix_len,
				const ni_sockaddr_t *dest,
				const ni_sockaddr_t *gw)
{
	return __ni_route_new(&ifp->routes, prefix_len, dest, gw);
}

/*
 * Destructor function (and assorted helpers)
 */
void
ni_interface_clear_addresses(ni_interface_t *ifp)
{
	ni_address_list_destroy(&ifp->addrs);
}

void
ni_interface_clear_routes(ni_interface_t *ifp)
{
	ni_route_list_destroy(&ifp->routes);
}

void
__ni_afinfo_set_addrconf_request(ni_afinfo_t *afi, unsigned int mode, ni_addrconf_request_t *req)
{
	if (mode >= __NI_ADDRCONF_MAX) {
		ni_error("%s: bad addrconf mode %u", __FUNCTION__, mode);
		return;
	}
	if (afi->request[mode])
		ni_addrconf_request_free(afi->request[mode]);
	afi->request[mode] = req;
}

void
__ni_afinfo_set_addrconf_lease(ni_afinfo_t *afi, unsigned int mode, ni_addrconf_lease_t *lease)
{
	ni_assert(lease->type == mode);
	if (mode >= __NI_ADDRCONF_MAX) {
		ni_error("%s: bad addrconf mode %u", __FUNCTION__, mode);
		return;
	}
	if (afi->lease[mode])
		ni_addrconf_lease_free(afi->lease[mode]);
	if (lease->state == NI_ADDRCONF_STATE_GRANTED) {
		afi->lease[mode] = lease;
	} else {
		afi->lease[mode] = NULL;
	}
}

static void
ni_interface_free(ni_interface_t *ifp)
{
	ni_string_free(&ifp->name);
	ni_string_free(&ifp->link.qdisc);
	ni_string_free(&ifp->link.kind);

	/* Clear out addresses, stats */
	ni_interface_clear_addresses(ifp);
	ni_interface_clear_routes(ifp);
	ni_interface_set_link_stats(ifp, NULL);
	ni_interface_set_ethernet(ifp, NULL);
	ni_interface_set_bonding(ifp, NULL);
	ni_interface_set_bridge(ifp, NULL);
	ni_interface_set_vlan(ifp, NULL);
	ni_interface_set_wireless(ifp, NULL);
	ni_interface_set_wireless_scan(ifp, NULL);

	__ni_afinfo_destroy(&ifp->ipv4);
	__ni_afinfo_destroy(&ifp->ipv6);

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
	if (ifp->link.type != NI_IFTYPE_UNKNOWN)
		return ifp->link.type;

	if (ifp->name == NULL)
		return ifp->link.type;

	ifp->link.type = NI_IFTYPE_ETHERNET;
	if (!strcmp(ifp->name, "lo")) {
		ifp->link.type = NI_IFTYPE_LOOPBACK;
	} else {
		ni_intmap_t *map;

		for (map = __ifname_types; map->name; ++map) {
			unsigned int len = strlen(map->name);

			if (!strncmp(ifp->name, map->name, len)
			 && isdigit(ifp->name[len])) {
				ifp->link.type = map->value;
				break;
			}
		}
	}

	return ifp->link.type;
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

int
ni_interface_array_index(const ni_interface_array_t *array, const ni_interface_t *ifp)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		if (array->data[i] == ifp)
			return i;
	}
	return -1;
}

void
ni_interface_array_destroy(ni_interface_array_t *array)
{
	free(array->data);
	memset(array, 0, sizeof(*array));
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
		if (ifp->name && !strcmp(ifp->name, name))
			return ifp;
	}

	return NULL;
}

ni_interface_t *
nc_interface_by_name(ni_netconfig_t *nc, const char *name)
{
	ni_interface_t *ifp;

	for (ifp = nc->interfaces; ifp; ifp = ifp->next) {
		if (ifp->name && !strcmp(ifp->name, name))
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
		if (ifp->link.ifindex == ifindex)
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
		if (ni_link_address_equal(&ifp->link.hwaddr, lla))
			return ifp;
	}

	return NULL;
}

/*
 * Find VLAN interface by its tag
 */
ni_interface_t *
ni_interface_by_vlan_tag(ni_handle_t *nih, uint16_t tag)
{
	ni_interface_t *ifp;

	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		if (ifp->link.type == NI_IFTYPE_VLAN
		 && ifp->link.vlan
		 && ifp->link.vlan->tag == tag)
			return ifp;
	}

	return NULL;
}

/*
 * Get the interface's VLAN information
 */
ni_vlan_t *
ni_interface_get_vlan(ni_interface_t *ifp)
{
	if (!ifp->link.vlan)
		ifp->link.vlan = __ni_vlan_new();
	return ifp->link.vlan;
}

void
ni_interface_set_vlan(ni_interface_t *ifp, ni_vlan_t *vlan)
{
	if (ifp->link.vlan)
		ni_vlan_free(ifp->link.vlan);
	ifp->link.vlan = vlan;
}

/*
 * Get the interface's bridge information
 */
ni_bridge_t *
ni_interface_get_bridge(ni_interface_t *ifp)
{
	if (!ifp->bridge)
		ifp->bridge = ni_bridge_new();
	return ifp->bridge;
}

void
ni_interface_set_bridge(ni_interface_t *ifp, ni_bridge_t *bridge)
{
	if (ifp->bridge)
		ni_bridge_free(ifp->bridge);
	ifp->bridge = bridge;
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
ni_interface_set_bonding(ni_interface_t *ifp, ni_bonding_t *bonding)
{
	if (ifp->bonding)
		ni_bonding_free(ifp->bonding);
	ifp->bonding = bonding;
}

/*
 * Get the interface's ethernet information
 */
ni_ethernet_t *
ni_interface_get_ethernet(ni_interface_t *ifp)
{
	if (!ifp->ethernet)
		ifp->ethernet = calloc(1, sizeof(ni_ethernet_t));
	return ifp->ethernet;
}

void
ni_interface_set_ethernet(ni_interface_t *ifp, ni_ethernet_t *ethernet)
{
	if (ifp->ethernet)
		ni_ethernet_free(ifp->ethernet);
	ifp->ethernet = ethernet;
}

/*
 * Set the interface's wireless info
 */
void
ni_interface_set_wireless(ni_interface_t *ifp, ni_wireless_t *wireless)
{
	if (ifp->wireless)
		ni_wireless_free(ifp->wireless);
	ifp->wireless = wireless;
}

void
ni_interface_set_wireless_scan(ni_interface_t *ifp, ni_wireless_scan_t *scan)
{
	if (ifp->wireless_scan)
		ni_wireless_scan_free(ifp->wireless_scan);
	ifp->wireless_scan = scan;
}

/*
 * Set the interface's link stats
 */
void
ni_interface_set_link_stats(ni_interface_t *ifp, ni_link_stats_t *stats)
{
	if (ifp->link.stats)
		free(ifp->link.stats);
	ifp->link.stats = stats;
}

/*
 * Handle interface_request objects
 */
ni_interface_request_t *
ni_interface_request_new(void)
{
	ni_interface_request_t *req;

	req = xcalloc(1, sizeof(*req));
	return req;
}

void
ni_interface_request_free(ni_interface_request_t *req)
{
	if (req->ipv4)
		ni_afinfo_free(req->ipv4);
	if (req->ipv6)
		ni_afinfo_free(req->ipv6);
	free(req);
}

/*
ni_interface_request_
ni_interface_request_
ni_interface_request_
ni_interface_request_
ni_interface_request_
ni_interface_request_
ni_interface_request_
ni_interface_request_
   */

/*
 * Address configuration info
 */
ni_afinfo_t *
ni_afinfo_new(int family)
{
	ni_afinfo_t *afi = xcalloc(1, sizeof(*afi));

	afi->family = family;
	if (family == AF_INET)
		afi->addrconf = DEFAULT_ADDRCONF_IPV4;
	else if (family == AF_INET6)
		afi->addrconf = DEFAULT_ADDRCONF_IPV6;
	afi->enabled = 1;
	return afi;
}

static void
__ni_afinfo_destroy(ni_afinfo_t *afi)
{
	unsigned int i;

	for (i = 0; i < __NI_ADDRCONF_MAX; ++i) {
		if (afi->request[i]) {
			ni_addrconf_request_free(afi->request[i]);
			afi->request[i] = NULL;
		}
		if (afi->lease[i]) {
			ni_addrconf_lease_free(afi->lease[i]);
			afi->lease[i] = NULL;
		}
	}
}

void
ni_afinfo_free(ni_afinfo_t *afi)
{
	__ni_afinfo_destroy(afi);
	free(afi);
}

/*
 * addrconf requests
 */
ni_addrconf_request_t *
ni_addrconf_request_new(unsigned int type, unsigned int af)
{
	ni_addrconf_request_t *dhcp;

	dhcp = xcalloc(1, sizeof(*dhcp));

	dhcp->type = type;
	dhcp->family = af;
	dhcp->acquire_timeout = 0;	/* means infinite */
	dhcp->reuse_unexpired = 1;
	dhcp->update = ~0;

	return dhcp;
}

ni_addrconf_request_t *
ni_addrconf_request_clone(const ni_addrconf_request_t *src)
{
	ni_addrconf_request_t *dst;

	if (src == NULL)
		return NULL;

	dst = ni_addrconf_request_new(src->type, src->family);
	dst->reuse_unexpired = src->reuse_unexpired;
	dst->settle_timeout = src->settle_timeout;
	dst->acquire_timeout = src->acquire_timeout;
	ni_string_dup(&dst->dhcp.hostname, src->dhcp.hostname);
	ni_string_dup(&dst->dhcp.clientid, src->dhcp.clientid);
	ni_string_dup(&dst->dhcp.vendor_class, src->dhcp.vendor_class);
	dst->dhcp.lease_time = src->dhcp.lease_time;
	dst->update = src->update;

	return dst;
}

void
ni_addrconf_request_free(ni_addrconf_request_t *req)
{
	ni_string_free(&req->dhcp.hostname);
	ni_string_free(&req->dhcp.clientid);
	ni_string_free(&req->dhcp.vendor_class);

	ni_address_list_destroy(&req->statik.addrs);
	ni_route_list_destroy(&req->statik.routes);
	free(req);
}

int
ni_addrconf_request_equal(const ni_addrconf_request_t *req1, const ni_addrconf_request_t *req2)
{
	if (req1->type != req2->type
	 || req1->family != req2->family
	 || req1->update != req2->update)
		return 0;

	if (req1->type == NI_ADDRCONF_DHCP && req1->family == AF_INET) {
		if (ni_string_eq(req1->dhcp.hostname, req2->dhcp.hostname)
		 || ni_string_eq(req1->dhcp.clientid, req2->dhcp.clientid)
		 || ni_string_eq(req1->dhcp.vendor_class, req2->dhcp.vendor_class)
		 || req1->dhcp.lease_time != req2->dhcp.lease_time)
			return 0;
	}

	return 1;
}

/*
 * Address configuration state (aka leases)
 */
ni_addrconf_lease_t *
ni_addrconf_lease_new(int type, int family)
{
	ni_addrconf_lease_t *lease;

	lease = calloc(1, sizeof(*lease));
	lease->type = type;
	lease->family = family;
	return lease;
}

void
ni_addrconf_lease_free(ni_addrconf_lease_t *lease)
{
	ni_addrconf_lease_destroy(lease);
	free(lease);
}

void
ni_addrconf_lease_destroy(ni_addrconf_lease_t *lease)
{
	ni_string_free(&lease->hostname);
	ni_string_free(&lease->netbios_domain);
	ni_string_free(&lease->netbios_scope);
	ni_string_array_destroy(&lease->log_servers);
	ni_string_array_destroy(&lease->ntp_servers);
	ni_string_array_destroy(&lease->netbios_name_servers);
	ni_string_array_destroy(&lease->netbios_dd_servers);
	ni_string_array_destroy(&lease->slp_servers);
	ni_string_array_destroy(&lease->slp_scopes);
	ni_address_list_destroy(&lease->addrs);
	ni_route_list_destroy(&lease->routes);

	if (lease->nis) {
		ni_nis_info_free(lease->nis);
		lease->nis = NULL;
	}
	if (lease->resolver) {
		ni_resolver_info_free(lease->resolver);
		lease->resolver = NULL;
	}

	switch (lease->type) {
	case NI_ADDRCONF_DHCP:
		ni_string_free(&lease->dhcp.message);
		ni_string_free(&lease->dhcp.rootpath);
		break;

	default: ;
	}
}

/*
 * Helper functions for backends like RedHat's or SUSE.
 * This is used to make interface behavior to STARTMODE and vice versa.
 */
const ni_ifbehavior_t *
__ni_netinfo_get_behavior(const char *name, const struct __ni_ifbehavior_map *map)
{
	for (; map->name; ++map) {
		if (!strcmp(map->name, name))
			return &map->behavior;
	}
	return NULL;
}

static unsigned int
__ni_behavior_to_mask(const ni_ifbehavior_t *beh)
{
	unsigned int mask = 0;

#define INSPECT(what) { \
	mask <<= 2; \
	switch (beh->ifaction[NI_IFACTION_##what].action) { \
	case NI_INTERFACE_START: \
		mask |= 1; break; \
	case NI_INTERFACE_STOP: \
		mask |= 2; break; \
	default: ; \
	} \
}
	INSPECT(MANUAL_UP);
	INSPECT(MANUAL_DOWN);
	INSPECT(BOOT);
	INSPECT(SHUTDOWN);
	INSPECT(LINK_UP);
	INSPECT(LINK_DOWN);
#undef INSPECT

	return mask;
}

/*
 * Out of a set of predefined interface behaviors, try to find the one that matches
 * best.
 * In the approach implemented here, we compare the action configured as response to specific
 * events. In order of decreasing precedence, we check:
 *	manual, boot, shutdown, link_up, link_down
 */
const char *
__ni_netinfo_best_behavior(const ni_ifbehavior_t *beh, const struct __ni_ifbehavior_map *map)
{
	unsigned int beh_mask = __ni_behavior_to_mask(beh);
	const char *best_match = NULL;
	unsigned int best_mask = 0;

	for (; map->name; ++map) {
		unsigned int this_mask = __ni_behavior_to_mask(&map->behavior) & beh_mask;

		if (this_mask > best_mask) {
			best_match = map->name;
			best_mask = this_mask;
		}
	}

	return best_match;
}
