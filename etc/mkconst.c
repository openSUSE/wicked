/*
 * Process a template and insert constants
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <mcheck.h>
#include <stdlib.h>
#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/logging.h>
#include <wicked/wireless.h>

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
		} else
		if (!strncmp(atat + 2, "IFTYPENAME_", 11)) {
			generate(buffer, "IFTYPENAME",
					buildmap(ni_linktype_type_to_name, __NI_IFTYPE_MAX));
		} else
		if (!strncmp(atat + 2, "ADDRCONFNAME_", 13)) {
			generate(buffer, "ADDRCONFNAME",
					buildmap(ni_addrconf_state_to_name, __NI_ADDRCONF_STATE_MAX));
		} else
		if (!strncmp(atat + 2, "ADDRCONFSTATE_", 14)) {
			generate(buffer, "ADDRCONFSTATE",
					buildmap(ni_addrconf_state_to_name, __NI_ADDRCONF_STATE_MAX));
		} else
		if (!strncmp(atat + 2, "WIRELESSMODE_", 13)) {
			generate(buffer, "WIRELESSMODE",
					buildmap(ni_wireless_mode_to_name, 128));
		} else
		if (!strncmp(atat + 2, "WIRELESS_SECURITY_", 18)) {
			generate(buffer, "WIRELESS_SECURITY",
					buildmap(ni_wireless_security_to_name, 128));
		} else
		if (!strncmp(atat + 2, "WIRELESS_AUTH_", 14)) {
			generate(buffer, "WIRELESS_AUTH",
					buildmap(ni_wireless_auth_mode_to_name, 128));
		} else {
			int indent = atat - buffer;

			ni_error("line %u: unsupported constant class\n", line);
			fputs(buffer, stderr);
			fprintf(stderr, "%*.*s^--- here\n", indent, indent, "");
			ni_fatal("Giving up.");
		}
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

		name = ni_format_int_mapped(1 << i, mask_map);
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
		if ((name = type2name(iftype)) != NULL) {
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
