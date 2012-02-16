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
#include <wicked/logging.h>

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
