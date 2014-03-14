/*
 * Routines for mapping constants to names and vice versa
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/lldp.h>
#include "kernel.h"

/*
 * Map interface link layer types to strings and vice versa
 */
static const ni_intmap_t	__linktype_names[] = {
	{ "unknown",		NI_IFTYPE_UNKNOWN },
	{ "loopback",		NI_IFTYPE_LOOPBACK },
	{ "ethernet",		NI_IFTYPE_ETHERNET },
	{ "bridge",		NI_IFTYPE_BRIDGE },
	{ "bond",		NI_IFTYPE_BOND },
	{ "vlan",		NI_IFTYPE_VLAN },
	{ "macvlan",		NI_IFTYPE_MACVLAN },
	{ "wireless",		NI_IFTYPE_WIRELESS },
	{ "infiniband",		NI_IFTYPE_INFINIBAND },
	{ "infiniband-child",	NI_IFTYPE_INFINIBAND_CHILD },
	{ "ppp",		NI_IFTYPE_PPP },
	{ "slip",		NI_IFTYPE_SLIP },
	{ "sit",		NI_IFTYPE_SIT },
	{ "gre",		NI_IFTYPE_GRE },
	{ "isdn",		NI_IFTYPE_ISDN },
	{ "tunnel",		NI_IFTYPE_TUNNEL },
	{ "tunnel6",		NI_IFTYPE_TUNNEL6 },
	{ "tun",		NI_IFTYPE_TUN },
	{ "tap",		NI_IFTYPE_TAP },
	{ "dummy",		NI_IFTYPE_DUMMY },
	{ "ctcm",		NI_IFTYPE_CTCM },
	{ "iucv",		NI_IFTYPE_IUCV },

	{ NULL }
};

int
ni_linktype_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __linktype_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_linktype_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __linktype_names);
}

/*
 * Map addrconf name to type constant and vice versa
 */
static const ni_intmap_t	__addrconf_names[] = {
	{ "dhcp",		NI_ADDRCONF_DHCP	},
	{ "static",		NI_ADDRCONF_STATIC	},
	{ "auto",		NI_ADDRCONF_AUTOCONF	},
	{ "intrinsic",		NI_ADDRCONF_INTRINSIC	},

	{ NULL }
};

int
ni_addrconf_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __addrconf_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_addrconf_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __addrconf_names);
}

/*
 * Map addrconf states to strings and vice versa
 */
static const ni_intmap_t	__addrconf_states[] = {
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

	if (ni_parse_uint_mapped(name, __addrconf_states, &value) < 0)
		return -1;
	return value;
}

const char *
ni_addrconf_state_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __addrconf_states);
}

/*
 * Map addrconf update values to strings and vice versa
 */
static const ni_intmap_t	__addrconf_update_flags[] = {
	{ "default-route",	NI_ADDRCONF_UPDATE_DEFAULT_ROUTE },
	{ "hostname",		NI_ADDRCONF_UPDATE_HOSTNAME      },
	{ "dns",		NI_ADDRCONF_UPDATE_DNS           },
	{ "nis",		NI_ADDRCONF_UPDATE_NIS           },
	{ "ntp",		NI_ADDRCONF_UPDATE_NTP           },
	{ "smb",		NI_ADDRCONF_UPDATE_SMB           },
	{ "nds",		NI_ADDRCONF_UPDATE_NDS           },
	{ "slp",		NI_ADDRCONF_UPDATE_SLP           },
	{ "log",		NI_ADDRCONF_UPDATE_LOG           },

	{ NULL }
};

const char *
ni_addrconf_update_flag_to_name(unsigned int flag)
{
	return ni_format_uint_mapped(flag, __addrconf_update_flags);
}

ni_bool_t
ni_addrconf_update_name_to_flag(const char *name, unsigned int *flag)
{
	unsigned int value;

	if (!flag || ni_parse_uint_maybe_mapped(name,
				__addrconf_update_flags, &value, 0) < 0)
		return FALSE;
	*flag = value;
	return TRUE;
}

void
ni_addrconf_update_set(unsigned int *mask, unsigned int flag, ni_bool_t enable)
{
	if (mask) {
		if (enable)
			*mask |= (1 << flag);
		else
			*mask &= ~(1 << flag);
	}
}

/*
 * Map address family names to type constants and vice versa
 */
static const ni_intmap_t __addrfamily_names[] = {
	{ "ipv4",	AF_INET		},
	{ "ipv6",	AF_INET6	},

	{ NULL }
};

int
ni_addrfamily_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __addrfamily_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_addrfamily_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __addrfamily_names);
}

/*
 * Map DHCP6 configuration modes
 */
static const ni_intmap_t	__dhcp6_modes[] = {
	{ "auto",		NI_DHCP6_MODE_AUTO	},
	{ "info",		NI_DHCP6_MODE_INFO	},
	{ "managed",		NI_DHCP6_MODE_MANAGED	},

	{ NULL,			NI_DHCP6_MODE_AUTO	}
};

const char *
ni_dhcp6_mode_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __dhcp6_modes);
}

int
ni_dhcp6_mode_name_to_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, __dhcp6_modes, type);
}

/*
 * Map ARPHRD_* constants to string
 */
#define __ARPMAP(token, name) { #name, ARPHRD_##token }

#ifndef	ARPHRD_CAN
#define	ARPHRD_CAN		280
#endif
#ifndef	ARPHRD_PHONET
#define	ARPHRD_PHONET		820
#endif
#ifndef	ARPHRD_PHONET_PIPE
#define	ARPHRD_PHONET_PIPE	821
#endif
#ifndef	ARPHRD_CAIF
#define	ARPHRD_CAIF		822
#endif
#ifndef	ARPHRD_IP6GRE
#define	ARPHRD_IP6GRE		823
#endif
#ifndef	ARPHRD_NETLINK
#define	ARPHRD_NETLINK		824
#endif

static const ni_intmap_t	__arphrd_names[] = {
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
 __ARPMAP(CAN,			can),
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
 __ARPMAP(LOCALTLK,		localtalk),
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
 __ARPMAP(IEEE802_TR,		ieee802-tr),
 __ARPMAP(IEEE80211,		ieee80211),
 __ARPMAP(IEEE80211_PRISM,	ieee80211-prism),
 __ARPMAP(IEEE80211_RADIOTAP,	ieee80211-radiotap),
 __ARPMAP(IEEE802154,		ieee802154),
 __ARPMAP(IEEE802154_PHY,	ieee802154-monitor),
 __ARPMAP(PHONET,		phonet),
 __ARPMAP(PHONET_PIPE,		phonet-pipe),
 __ARPMAP(CAIF,			caif),
 __ARPMAP(IP6GRE,		ip6gre),
 __ARPMAP(NETLINK,		netlink),
 __ARPMAP(NONE,			none),
 __ARPMAP(VOID,			void),

 { 0 }
};

int
ni_arphrd_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __arphrd_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_arphrd_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __arphrd_names);
}

/*
 * Map event names to type constants and vice versa
 */
static const ni_intmap_t		__event_names[] = {
	{ "device-create",		NI_EVENT_DEVICE_CREATE },
	{ "device-delete",		NI_EVENT_DEVICE_DELETE },
	{ "device-up",			NI_EVENT_DEVICE_UP },
	{ "device-down",		NI_EVENT_DEVICE_DOWN },
	{ "link-associated",		NI_EVENT_LINK_ASSOCIATED },
	{ "link-association-lost",	NI_EVENT_LINK_ASSOCIATION_LOST },
	{ "link-scan-updated",		NI_EVENT_LINK_SCAN_UPDATED },
	{ "link-up",			NI_EVENT_LINK_UP },
	{ "link-down",			NI_EVENT_LINK_DOWN },
	{ "network-up",			NI_EVENT_NETWORK_UP },
	{ "network-down",		NI_EVENT_NETWORK_DOWN },
	{ "address-acquired",		NI_EVENT_ADDRESS_ACQUIRED },
	{ "address-released",		NI_EVENT_ADDRESS_RELEASED },
	{ "address-lost",		NI_EVENT_ADDRESS_LOST },
	{ "address-updated",		NI_EVENT_ADDRESS_UPDATE },
	{ "address-deleted",		NI_EVENT_ADDRESS_DELETE },
	{ "prefix-updated",		NI_EVENT_PREFIX_UPDATE },
	{ "prefix-deleted",		NI_EVENT_PREFIX_DELETE },
	{ "rdnss-updated",		NI_EVENT_RDNSS_UPDATE },
	{ "resolver-updated",		NI_EVENT_RESOLVER_UPDATED },
	{ "hostname-updated",		NI_EVENT_HOSTNAME_UPDATED },
	{ "generic-updated",		NI_EVENT_GENERIC_UPDATED },

	{ NULL }
};

ni_event_t
ni_event_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __event_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_event_type_to_name(ni_event_t type)
{
	return ni_format_uint_mapped(type, __event_names);
}

/*
 * Names for the kernel's oper_state values
 */
static const ni_intmap_t	__ni_operstate_names[] = {
	{ "unknown",		IF_OPER_UNKNOWN		},
	{ "not-present",	IF_OPER_NOTPRESENT	},
	{ "down",		IF_OPER_DOWN		},
	{ "lower-layer-down",	IF_OPER_LOWERLAYERDOWN	},
	{ "testing",		IF_OPER_TESTING		},
	{ "dormant",		IF_OPER_DORMANT		},
	{ "up",			IF_OPER_UP		},

	{ NULL }
};

int
ni_oper_state_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __ni_operstate_names, &value) < 0)
		return -1;
	return value;
}

const char *
ni_oper_state_type_to_name(int type)
{
	return ni_format_uint_mapped(type, __ni_operstate_names);
}


/*
 * Names for LLDP destinations
 */
static const ni_intmap_t		__ni_lldp_type_names[] = {
	{ "nearest-bridge",		NI_LLDP_DEST_NEAREST_BRIDGE	},
	{ "nearest-non-tmpr-bridge",	NI_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE	},
	{ "nearest-customer-bridge",	NI_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE	},

	{ NULL }
};

int
ni_lldp_destination_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_maybe_mapped(name, __ni_lldp_type_names, &value, 10) < 0)
		return -1;
	return value;
}

const char *
ni_lldp_destination_type_to_name(ni_lldp_destination_t type)
{
	return ni_format_uint_maybe_mapped(type, __ni_lldp_type_names);
}

/*
 * Names for LLDP System capabilities
 */
static const ni_intmap_t		__ni_lldp_systemcap_names[] = {
	{ "nearest-bridge",		NI_LLDP_DEST_NEAREST_BRIDGE	},
	{ "nearest-non-tmpr-bridge",	NI_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE	},
	{ "nearest-customer-bridge",	NI_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE	},
	{ "other",			NI_LLDP_SYSCAP_OTHER },
	{ "repeater",			NI_LLDP_SYSCAP_REPEATER },
	{ "bridge",			NI_LLDP_SYSCAP_MAC_BRIDGE },
	{ "wlan-ap",			NI_LLDP_SYSCAP_WLAN_AP },
	{ "router",			NI_LLDP_SYSCAP_ROUTER },
	{ "telephone",			NI_LLDP_SYSCAP_TELEPHONE },
	{ "docsis-cable-device",	NI_LLDP_SYSCAP_DOCSIS_CABLE_DEV },
	{ "station-only",		NI_LLDP_SYSCAP_STATION_ONLY },
	{ "vlan-bridge-c-vlan",		NI_LLDP_SYSCAP_VLAN_BRIDGE_C_VLAN },
	{ "vlan-bridge-s-vlan",		NI_LLDP_SYSCAP_VLAN_BRIDGE_S_VLAN },
	{ "two-port-repeater",		NI_LLDP_SYSCAP_TPMR },

	{ NULL }
};

int
ni_lldp_system_capability_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_maybe_mapped(name, __ni_lldp_systemcap_names, &value, 10) < 0)
		return -1;
	return value;
}

const char *
ni_lldp_system_capability_type_to_name(unsigned int type)
{
	return ni_format_uint_maybe_mapped(type, __ni_lldp_systemcap_names);
}

static const ni_intmap_t	__ni_netbios_node_types[] = {
	{ "B-node",		0x1 },
	{ "P-node",		0x2 },
	{ "M-node",		0x4 },
	{ "H-node",		0x8 },
	{ NULL,			0x0 }
};

const char *
ni_netbios_node_type_to_name(unsigned int code)
{
	return ni_format_uint_mapped(code, __ni_netbios_node_types);
}

ni_bool_t
ni_netbios_node_type_to_code(const char *name, unsigned int *value)
{
	unsigned int val;

	/* allow parsing as number, ... but verify it's a valid type */
	if (!value || ni_parse_uint_maybe_mapped(name,
				__ni_netbios_node_types, &val, 0) != 0)
		return FALSE;
	*value = val;
	return TRUE;
}
