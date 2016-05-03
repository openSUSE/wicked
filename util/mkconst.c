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
#include <wicked/team.h>
#include <wicked/route.h>
#include <wicked/infiniband.h>
#include <wicked/tunneling.h>
#include <wicked/macvlan.h>
#include <wicked/vlan.h>
#include <wicked/lldp.h>

extern const char *	ni_ifworker_state_name(unsigned int);

static ni_intmap_t *	buildmap(const char *(*)(unsigned), unsigned int);
static void		generate(char *, const char *, const ni_intmap_t *);


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
	MAPN(IFTYPE, ni_linktype_type_to_name, __NI_IFTYPE_MAX),
	MAP(IFFLAGS, ni_linkflags_bit_to_name),
	MAPN(ARPHRD, ni_arphrd_type_to_name, ARPHRD_VOID),
	MAPN(ADDRESS_FAMILY, ni_addrfamily_type_to_name, AF_MAX),
	MAPN(ADDRCONF_MODE, ni_addrconf_type_to_name, __NI_ADDRCONF_MAX),
	MAPN(ADDRCONF_STATE, ni_addrconf_state_to_name, __NI_ADDRCONF_STATE_MAX),
	MAP(ADDRCONF_FLAG_BIT, ni_addrconf_flag_bit_to_name),
	MAP(ADDRCONF_UPDATE_FLAG, ni_addrconf_update_flag_to_name),
	MAP(DHCP6_MODE, ni_dhcp6_mode_type_to_name),
	MAP(WIRELESS_MODE, ni_wireless_mode_to_name),
	MAP(WIRELESS_SECURITY, ni_wireless_security_to_name),
	MAP(WIRELESS_AUTH, ni_wireless_auth_mode_to_name),
	MAP(WIRELESS_AUTH_ALGO, ni_wireless_auth_algo_to_name),
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
	MAP(BONDING_SLAVE_STATE, ni_bonding_slave_state_name),
	MAP(BONDING_SLAVE_MII_STATUS, ni_bonding_slave_mii_status_name),
	MAP(ROUTE_TYPE, ni_route_type_type_to_name),
	MAP(ROUTE_PROTOCOL, ni_route_protocol_type_to_name),
	MAPN(ROUTE_SCOPE, ni_route_scope_type_to_name, 256),
	MAP(ROUTE_FLAG, ni_route_flag_bit_to_name),
	MAP(ROUTE_NH_FLAG, ni_route_nh_flag_bit_to_name),
	MAP(ROUTE_METRICS_LOCK, ni_route_metrics_lock_bit_to_name),
	MAP(RULE_ACTION_TYPE, ni_rule_action_type_to_name),
	MAP(INFINIBAND_MODE, ni_infiniband_get_mode_name),
	MAP(INFINIBAND_UMCAST, ni_infiniband_get_umcast_name),
	MAP(VLAN_PROTOCOL, ni_vlan_protocol_to_name),
	MAP(LLDP_DESTINATION, ni_lldp_destination_type_to_name),
	MAP(LLDP_SYSTEM_CAPABILITY, ni_lldp_system_capability_type_to_name),
	MAP(MACVLAN_MODE, ni_macvlan_mode_to_name),
	MAP(MACVLAN_FLAG, ni_macvlan_flag_bit_name),
	MAP(TEAM_TX_HASH_BIT, ni_team_tx_hash_bit_to_name),
	MAP(TEAM_TX_BALANCER, ni_team_tx_balancer_type_to_name),
	MAP(TEAM_AB_HWADDR_POLICY, ni_team_ab_hwaddr_policy_type_to_name),
	MAP(TEAM_LACP_SELECT_POLICY, ni_team_lacp_select_policy_type_to_name),
	MAP(GRE_FLAG_BIT, ni_gre_flag_bit_to_name),
	MAP(GRE_ENCAP_TYPE, ni_gre_encap_type_to_name),
	MAP(GRE_ENCAP_FLAG_BIT, ni_gre_encap_flag_bit_to_name),

	{ NULL }
};

int
main(int argc, char **argv)
{
	unsigned int line = 0;
	char buffer[512];

	while (fgets(buffer, sizeof(buffer), stdin) != NULL) {
		struct generic_map *map;
		int indent;
		char *atat;

		++line;
		if ((atat = strstr(buffer, "@@")) == NULL) {
			fputs(buffer, stdout);
			continue;
		}

		for (map = generic_maps; map->prefix; ++map) {
			if (!strncmp(atat + 2, map->prefix, map->prefix_len)
			 && !strncmp(atat + 2 + map->prefix_len, "_NAME@@", 7)) {
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
found: ;
	}

	return 0;
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
