/*
 * Process a template and insert constants
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <mcheck.h>
#include <stdlib.h>
#include <ctype.h>
#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wireless.h>
#include <wicked/bonding.h>
#include <wicked/route.h>
#include <wicked/infiniband.h>
#include <wicked/lldp.h>

static ni_intmap_t *	build_ifflag_bits_map(void);
static ni_intmap_t *	buildmap(const char *(*)(unsigned), unsigned int);
static void		generate(char *, const char *, const ni_intmap_t *);


#define _(x)	{ #x, x }
static ni_intmap_t	iftype_map[] = {
	_(NI_IFTYPE_UNKNOWN),
	_(NI_IFTYPE_LOOPBACK),
	_(NI_IFTYPE_ETHERNET),
	_(NI_IFTYPE_BRIDGE),
	_(NI_IFTYPE_BOND),
	_(NI_IFTYPE_VLAN),
	_(NI_IFTYPE_WIRELESS),
	_(NI_IFTYPE_INFINIBAND),
	_(NI_IFTYPE_PPP),
	_(NI_IFTYPE_SLIP),
	_(NI_IFTYPE_SIT),
	_(NI_IFTYPE_GRE),
	_(NI_IFTYPE_ISDN),
	_(NI_IFTYPE_TUNNEL),
	_(NI_IFTYPE_TUNNEL6),
	_(NI_IFTYPE_TOKENRING),
	_(NI_IFTYPE_FIREWIRE),
	_(NI_IFTYPE_TUN),
	_(NI_IFTYPE_TAP),
	_(NI_IFTYPE_DUMMY),

	{ NULL }
};
static ni_intmap_t	arphrd_map[] = {
	_(ARPHRD_NONE),
	_(ARPHRD_LOOPBACK),
	_(ARPHRD_ETHER),
	_(ARPHRD_INFINIBAND),
	_(ARPHRD_PPP),
	_(ARPHRD_SLIP),
	_(ARPHRD_SIT),
	_(ARPHRD_IPGRE),
	_(ARPHRD_TUNNEL),
	_(ARPHRD_TUNNEL6),

	{ NULL }
};

struct generic_map {
	const char *		prefix;
	unsigned int		prefix_len;
	const char *		(*mapfunc)(unsigned int);
	unsigned int		max_value;
};

#define MAP(name, func) \
	{ #name, sizeof(#name) - 1, func, 128 }
#define MAPN(name, func, max) \
	{ #name, sizeof(#name) - 1, func, max }
static struct generic_map	generic_maps[] = {
	MAPN(IFTYPENAME, ni_linktype_type_to_name, __NI_IFTYPE_MAX),
	MAPN(ADDRCONF_MODE, ni_addrconf_type_to_name, __NI_ADDRCONF_MAX),
	MAPN(ADDRCONF_STATE, ni_addrconf_state_to_name, __NI_ADDRCONF_STATE_MAX),
	MAP(WIRELESS_MODE, ni_wireless_mode_to_name),
	MAP(WIRELESS_SECURITY, ni_wireless_security_to_name),
	MAP(WIRELESS_AUTH, ni_wireless_auth_mode_to_name),
	MAP(WIRELESS_CIPHER, ni_wireless_cipher_to_name),
	MAP(WIRELESS_KEY_MGMT, ni_wireless_key_management_to_name),
	MAP(WIRELESS_EAP_METHOD, ni_wireless_eap_method_to_name),
	MAP(BONDING_MODE, ni_bonding_mode_type_to_name),
	MAP(BONDING_ARP_VALIDATE, ni_bonding_arp_validate_type_to_name),
	MAP(BONDING_MII_CARRIER_DETECT, ni_bonding_mii_carrier_detect_name),
	MAP(BONDING_XMIT_HASH, ni_bonding_xmit_hash_policy_to_name),
	MAP(BONDING_LACP_RATE, ni_bonding_lacp_rate_name),
	MAP(BONDING_AD_SELECT, ni_bonding_ad_select_name),
	MAP(BONDING_FAIL_OVER_MAC, ni_bonding_fail_over_mac_name),
	MAP(BONDING_PRIMARY_RESELECT, ni_bonding_primary_reselect_name),
	MAP(ROUTE_TYPE, ni_route_type_type_to_name),
	MAP(ROUTE_PROTOCOL, ni_route_protocol_type_to_name),
	MAPN(ROUTE_SCOPE, ni_route_scope_type_to_name, 256),
	MAPN(ROUTE_TABLE, ni_route_table_type_to_name, 256),
	MAP(ROUTE_FLAG, ni_route_flag_bit_to_name),
	MAP(ROUTE_NH_FLAG, ni_route_nh_flag_bit_to_name),
	MAP(ROUTE_METRICS_LOCK, ni_route_metrics_lock_bit_to_name),
	MAP(INFINIBAND_MODE, ni_infiniband_get_mode_name),
	MAP(INFINIBAND_UMCAST, ni_infiniband_get_umcast_name),
	MAP(LLDP_DESTINATION, ni_lldp_destination_type_to_name),
	MAP(LLDP_SYSTEM_CAPABILITY, ni_lldp_system_capability_type_to_name),

	{ NULL }
};

int
main(int argc, char **argv)
{
	unsigned int line = 0;
	char buffer[512];

	while (fgets(buffer, sizeof(buffer), stdin) != NULL) {
		char *atat;

		++line;
		if ((atat = strstr(buffer, "@@")) == NULL) {
			fputs(buffer, stdout);
			continue;
		}

		if (!strncmp(atat + 2, "IFTYPE_", 7)) {
			generate(buffer, "IFTYPE", iftype_map);
		} else
		if (!strncmp(atat + 2, "ARPHRD_", 7)) {
			generate(buffer, "ARPHRD", arphrd_map);
		} else
		if (!strncmp(atat + 2, "IFFLAG_", 7)) {
			generate(buffer, "IFFLAG", build_ifflag_bits_map());
		} else {
			struct generic_map *map;
			int indent;

			for (map = generic_maps; map->prefix; ++map) {
				if (!strncmp(atat + 2, map->prefix, map->prefix_len)
				 && atat[2 + map->prefix_len] == '_') {
					generate(buffer, map->prefix,
							buildmap(map->mapfunc, map->max_value));
					goto found;
				}
			}

			indent = atat - buffer;

			ni_error("line %u: unsupported constant class\n", line);
			fputs(buffer, stderr);
			fprintf(stderr, "%*.*s^--- here\n", indent, indent, "");
			ni_fatal("Giving up.");
		}
found: ;
	}

	return 0;
}

/*
 * The NI_IFF_* values are bitmask values; but in order to
 * define the corresponding type in the xml schema, we need the
 * shift values
 */
static ni_intmap_t *
build_ifflag_bits_map(void)
{
	static ni_intmap_t mask_map[] = {
	{ "device-up",		NI_IFF_DEVICE_UP		},
	{ "link-up",		NI_IFF_LINK_UP			},
	{ "powersave",		NI_IFF_POWERSAVE		},
	{ "network-up",		NI_IFF_NETWORK_UP		},
	{ "point-to-point",	NI_IFF_POINT_TO_POINT		},
	{ "arp",		NI_IFF_ARP_ENABLED		},
	{ "broadcast",		NI_IFF_BROADCAST_ENABLED	},
	{ "multicast",		NI_IFF_MULTICAST_ENABLED	},

	{ NULL }
	};
	static ni_intmap_t bits_map[33];
	unsigned int i, j = 0;

	for (i = 0; i < 32; ++i) {
		const char *name;

		name = ni_format_uint_mapped(1 << i, mask_map);
		if (name) {
			bits_map[j].name = name;
			bits_map[j].value = i;
			++j;
		}
	}

	return bits_map;
}

static ni_intmap_t *
buildmap(const char *(*type2name)(unsigned int), unsigned int max)
{
	static ni_intmap_t *map = 0;
	unsigned int iftype;
	const char *name;
	unsigned int k;

	if (map) {
		free(map);
		map = NULL;
	}
	if (max == 0)
		return NULL;

	map = calloc(max + 1, sizeof(map[0]));
	for (iftype = k = 0; iftype < max; ++iftype) {
		if ((name = type2name(iftype)) != NULL && !isdigit(name[0])) {
			map[k].name = name;
			map[k].value = iftype;
			++k;
		}
	}

	return map;
}

static void
generate(char *linebuf, const char *key, const ni_intmap_t *map)
{
	enum { NONE = 0, NAME, VALUE };
	struct segment {
		char *		string;
		int		select;
	} segment[42];
	unsigned int nseg = 0;
	char *s;

	memset(segment, 0, sizeof(segment));
	while ((s = strstr(linebuf, "@@")) != NULL) {
		char *end;

		if (s != linebuf)
			segment[nseg++].string = linebuf;

		s[0] = '\0';
		s += 2;

		if ((end = strstr(s, "@@")) == NULL)
			ni_fatal("Missing @@ terminator");
		end[0] = '\0';
		end += 2;

		if (strncmp(s, key, strlen(key)))
			ni_fatal("unexpected key @@%s@@ - expected @@%s_*@@", s, key);

		s += strlen(key);
		if (!strncmp(s, "_NAME", 5)) {
			segment[nseg++].select = NAME;
		} else
		if (!strncmp(s, "_VALUE", 6)) {
			segment[nseg++].select = VALUE;
		} else {
			ni_fatal("Unknown selector %s%s", key, s);
		}

		linebuf = end;
	}
	if (linebuf && *linebuf)
		segment[nseg++].string = linebuf;

	for (; map->name; ++map) {
		unsigned int i;

		for (i = 0; i < nseg; ++i) {
			if (segment[i].string)
				fputs(segment[i].string, stdout);
			else switch (segment[i].select) {
			case NAME:
				printf("%s", map->name);
				break;
			case VALUE:
				printf("%u", map->value);
				break;
			}
		}
	}
}
