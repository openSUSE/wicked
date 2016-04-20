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
 * Tristate is basically a bool + "unset, use defaults"
 */
static const ni_intmap_t	__tristate_names[] = {
	{ "true",		NI_TRISTATE_ENABLE	},
	{ "enable",		NI_TRISTATE_ENABLE	},
	{ "enabled",		NI_TRISTATE_ENABLE	},
	{ "false",		NI_TRISTATE_DISABLE	},
	{ "disable",		NI_TRISTATE_DISABLE	},
	{ "disabled",		NI_TRISTATE_DISABLE	},
	{ "default",		NI_TRISTATE_DEFAULT	},
	{ NULL,			NI_TRISTATE_DEFAULT	},
};

const char *
ni_tristate_to_name(ni_tristate_t tristate)
{
	return ni_format_uint_mapped(tristate, __tristate_names);
}

ni_bool_t
ni_tristate_by_name(const char *name, ni_tristate_t *tristate)
{
	unsigned int t;

	if (!tristate || ni_parse_uint_mapped(name, __tristate_names, &t) < 0)
		return FALSE;

	*tristate = (int)t;
	return TRUE;
}


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
	{ "macvtap",		NI_IFTYPE_MACVTAP },
	{ "wireless",		NI_IFTYPE_WIRELESS },
	{ "infiniband",		NI_IFTYPE_INFINIBAND },
	{ "infiniband-child",	NI_IFTYPE_INFINIBAND_CHILD },
	{ "ppp",		NI_IFTYPE_PPP },
	{ "slip",		NI_IFTYPE_SLIP },
	{ "sit",		NI_IFTYPE_SIT },
	{ "gre",		NI_IFTYPE_GRE },
	{ "isdn",		NI_IFTYPE_ISDN },
	{ "ipip",		NI_IFTYPE_IPIP },
	{ "tunnel6",		NI_IFTYPE_TUNNEL6 },
	{ "tun",		NI_IFTYPE_TUN },
	{ "tap",		NI_IFTYPE_TAP },
	{ "dummy",		NI_IFTYPE_DUMMY },
	{ "ctcm",		NI_IFTYPE_CTCM },
	{ "iucv",		NI_IFTYPE_IUCV },
	{ "team",		NI_IFTYPE_TEAM },
	{ "ovs-system",		NI_IFTYPE_OVS_SYSTEM },
	{ "ovs-bridge",		NI_IFTYPE_OVS_BRIDGE },

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
 * Map kernel kind to type
 *
 * Note: this is an initial, incomplete, one-direction match!
 */
static const ni_intmap_t	__linkinfo_kind_names[] = {
	{ "bridge",		NI_IFTYPE_BRIDGE },
	{ "bond",		NI_IFTYPE_BOND },
	{ "team",		NI_IFTYPE_TEAM },
	{ "vlan",		NI_IFTYPE_VLAN },
	{ "macvlan",		NI_IFTYPE_MACVLAN },
	{ "macvtap",		NI_IFTYPE_MACVTAP },
	{ "tun",		NI_IFTYPE_TUN },
	{ "dummy",		NI_IFTYPE_DUMMY },
	{ "sit",		NI_IFTYPE_SIT },
	{ "ipip",		NI_IFTYPE_IPIP },
	{ "gre",		NI_IFTYPE_GRE },

	{ NULL }
};

ni_bool_t
__ni_linkinfo_kind_to_type(const char *name, ni_iftype_t *iftype)
{
	unsigned int value;

	if (!iftype || ni_parse_uint_mapped(name, __linkinfo_kind_names, &value) < 0)
		return FALSE;
	*iftype = value;
	return TRUE;
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
	{ "applying",		NI_ADDRCONF_STATE_APPLYING },
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
 * Map addrconf flag bits to strings and vice versa
 */
static const ni_intmap_t	__addrconf_flag_bits[] = {
	{ "group",		NI_ADDRCONF_FLAGS_GROUP		},
	{ "primary",		NI_ADDRCONF_FLAGS_PRIMARY	},
	{ "fallback",		NI_ADDRCONF_FLAGS_FALLBACK	},
	{ "optional",		NI_ADDRCONF_FLAGS_OPTIONAL	},
	{ NULL,			-1U				},
};

const char *
ni_addrconf_flag_bit_to_name(unsigned int flag)
{
	return ni_format_uint_mapped(flag, __addrconf_flag_bits);
}

ni_bool_t
ni_addrconf_name_to_flag_bit(const char *name, unsigned int *flag)
{
	unsigned int value;

	if (!flag || ni_parse_uint_maybe_mapped(name,
				__addrconf_flag_bits, &value, 0) < 0)
		return FALSE;
	*flag = value;
	return TRUE;
}

void
ni_addrconf_flag_bit_set(unsigned int *mask, unsigned int flag, ni_bool_t enable)
{
	if (mask) {
		if (enable)
			*mask |=  (1U << flag);
		else
			*mask &= ~(1U << flag);
	}
}

ni_bool_t
ni_addrconf_flag_bit_is_set(unsigned int flags, unsigned int flag)
{
	return flags & (1 << flag);
}

const char *
ni_addrconf_flags_format(ni_stringbuf_t *buf, unsigned int flags, const char *sep)
{
	return ni_format_bitmap(buf, __addrconf_flag_bits, flags, sep);
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
	{ "mtu",		NI_ADDRCONF_UPDATE_MTU           },

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

const char *
ni_addrconf_update_flags_format(ni_stringbuf_t *buf, unsigned int flags, const char *sep)
{
	return ni_format_bitmap(buf, __addrconf_update_flags, flags, sep);
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

/* Map DHCP4 user-class formats */
static const ni_intmap_t	__dhcp4_user_class_formats[] = {
	{ "rfc3004",		NI_DHCP4_USER_CLASS_RFC3004	},
	{ "string",		NI_DHCP4_USER_CLASS_STRING	},

	{ NULL,			-1U				}
};

const char *
ni_dhcp4_user_class_format_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __dhcp4_user_class_formats);
}

int
ni_dhcp4_user_class_format_name_to_type(const char *name, unsigned int *type)
{
	return ni_parse_uint_mapped(name, __dhcp4_user_class_formats, type);
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
	{ "device-change",		NI_EVENT_DEVICE_CHANGE },
	{ "device-ready",		NI_EVENT_DEVICE_READY },
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
	{ "address-deferred",		NI_EVENT_ADDRESS_DEFERRED },
	{ "address-lost",		NI_EVENT_ADDRESS_LOST },
	{ "address-updated",		NI_EVENT_ADDRESS_UPDATE },
	{ "address-deleted",		NI_EVENT_ADDRESS_DELETE },
	{ "prefix-updated",		NI_EVENT_PREFIX_UPDATE },
	{ "prefix-deleted",		NI_EVENT_PREFIX_DELETE },
	{ "route-updated",		NI_EVENT_ROUTE_UPDATE },
	{ "route-deleted",		NI_EVENT_ROUTE_DELETE },
	{ "rule-updated",		NI_EVENT_RULE_UPDATE },
	{ "rule-deleted",		NI_EVENT_RULE_DELETE },
	{ "rdnss-updated",		NI_EVENT_RDNSS_UPDATE },
	{ "dnssl-updated",		NI_EVENT_DNSSL_UPDATE },
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
 * Names for wicked link ifflags
 */
static const ni_intmap_t	__ni_linkifflag_names[] = {
	{ "device-up",		NI_IFF_DEVICE_UP	},
	{ "link-up",		NI_IFF_LINK_UP		},
	{ "powersave",		NI_IFF_POWERSAVE	},
	{ "network-up",		NI_IFF_NETWORK_UP	},
	{ "point-to-point",	NI_IFF_POINT_TO_POINT	},
	{ "arp",		NI_IFF_ARP_ENABLED	},
	{ "broadcast",		NI_IFF_BROADCAST_ENABLED},
	{ "multicast",		NI_IFF_MULTICAST_ENABLED},
	{ "ready",		NI_IFF_DEVICE_READY	},
	{ NULL,			0			},
};

const char *
ni_linkflags_bit_to_name(unsigned int bit)
{
	if (bit >= 32)
		return NULL;
	return ni_format_uint_mapped(1 << bit, __ni_linkifflag_names);
}

const char *
ni_linkflags_format(ni_stringbuf_t *buf, unsigned int flags, const char *sep)
{
	const ni_intmap_t *map = __ni_linkifflag_names;
	unsigned int i;

	if (!buf)
		return NULL;
	if (ni_string_empty(sep))
		sep = "|";

	for (i = 0; map->name; ++map) {
		if (flags & map->value) {
			if (i++)
				ni_stringbuf_puts(buf, sep);
			ni_stringbuf_puts(buf, map->name);
		}
	}
	return buf->string;
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
