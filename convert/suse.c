/*
 * Translation between internal representation and SUSE ifcfg files
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/vlan.h>
#include "backend-priv.h"
#include "netinfo_priv.h"
#include "sysconfig.h"


#define _PATH_NETCONFIG_DIR		"/etc/sysconfig/network"

static int		__ni_suse_read_routes(ni_route_t **, const char *);
static ni_interface_t *	__ni_suse_read_interface(ni_netconfig_t *, const char *, const char *);
static int		__ni_suse_sysconfig2ifconfig(ni_interface_t *, ni_sysconfig_t *);
static int		__ni_suse_startmode_set(ni_ifbehavior_t *, const char *);
static int		__ni_suse_bootproto_set(ni_interface_t *, char *);

static void		__process_indexed_variables(ni_interface_t *, ni_sysconfig_t *,
				const char *,
				void (*)(ni_interface_t *, ni_sysconfig_t *, const char *));
static void		try_add_address(ni_interface_t *, ni_sysconfig_t *, const char *);
static void		try_bonding(ni_interface_t *, ni_sysconfig_t *);
static void		try_bridge(ni_interface_t *ifp, ni_sysconfig_t *);
static void		try_wireless(ni_interface_t *ifp, ni_sysconfig_t *);
static void		try_vlan(ni_interface_t *ifp, ni_sysconfig_t *);

/*
 * Refresh network configuration by reading all ifcfg files.
 */
int
ni_sysconfig_read_suse(ni_netconfig_t *nc, const char *root_dir)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	char pathbuf[PATH_MAX], *base_dir;
	int i;

	base_dir = _PATH_NETCONFIG_DIR;
	if (root_dir) {
		snprintf(pathbuf, sizeof(pathbuf), "%s%s", root_dir, base_dir);
		base_dir = pathbuf;
	}
	if (!ni_sysconfig_scandir(base_dir, "ifcfg-*", &files)) {
		ni_error("No ifcfg files found");
		return -1;
	}

	for (i = 0; i < files.count; ++i) {
		const char *filename = files.data[i];
		const char *ifname = filename + 6;
		ni_interface_t *ifp;

		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", base_dir, filename);
		ifp = __ni_suse_read_interface(nc, pathbuf, filename + 6);
		if (ifp == NULL)
			goto failed;

		snprintf(pathbuf, sizeof(pathbuf), "%s/ifroute-%s", base_dir, ifname);
		if (__ni_suse_read_routes(&ifp->routes, pathbuf) < 0)
			goto failed;
	}
	snprintf(pathbuf, sizeof(pathbuf), "%s/routes", base_dir);
	if (__ni_suse_read_routes(&nc->routes, pathbuf) < 0)
		goto failed;

	ni_string_array_destroy(&files);
	return 0;

failed:
	ni_string_array_destroy(&files);
	return -1;
}

/*
 * Read the routing information from sysconfig/network/routes.
 */
static int
__ni_suse_read_routes(ni_route_t **route_list, const char *filename)
{
	char buffer[512];
	FILE *fp;

	if ((fp = fopen(filename, "r")) == NULL) {
		if (errno == ENOENT)
			return 0;
		ni_error("unable to open %s: %m", filename);
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char *dest, *gw, *mask = NULL, *ifname = NULL, *type = NULL;
		ni_sockaddr_t dest_addr, gw_addr, mask_addr;
		unsigned int prefixlen = 255;
		ni_route_t *rp;

		buffer[strcspn(buffer, "#\r\n")] = '\0';
		
		if (!(dest = strtok(buffer, " \t")))
			continue;

		gw = strtok(NULL, " \t");
		if (gw)
			mask = strtok(NULL, " \t");
		if (mask)
			ifname = strtok(NULL, " \t");
		if (ifname)
			type = strtok(NULL, " \t");

		if (gw == NULL || !strcmp(gw, "-")) {
			/* This is a local interface route.
			 * Some SLES versions have an ifcfg-route with
			 * "127/8" in it. */
			memset(&gw_addr, 0, sizeof(gw_addr));
		} else
		if (ni_address_parse(&gw_addr, gw, AF_UNSPEC) < 0) {
			ni_error("%s: cannot parse gw addr \"%s\"",
					filename, gw);
			goto error;
		}

		if (!strcmp(dest, "default")) {
			memset(&dest_addr, 0, sizeof(dest_addr));
			dest_addr.ss_family = gw_addr.ss_family;
			prefixlen = 0;
		} else {
			char *sp;

			if ((sp = strchr(dest, '/')) != NULL) {
				*sp++ = '\0';
				prefixlen = strtoul(sp, NULL, 10);
			}
			if (ni_address_parse(&dest_addr, dest, AF_UNSPEC) < 0) {
				ni_error("%s: cannot parse dest addr \"%s\"",
						filename, dest);
				goto error;
			}
			if (prefixlen == 255) {
				if (!mask || !strcmp(mask, "-")) {
					/* No prefix and no mask given - assume the destination
					   is a single address. Use the full address length
					   as prefix. */
					prefixlen = ni_address_length(dest_addr.ss_family) * 8;
				} else {
					/* We have a mask. Try to parse it and count the bits. */
					if (ni_address_parse(&mask_addr, mask, AF_UNSPEC) < 0) {
						ni_error("%s: cannot parse mask addr \"%s\"",
								filename, mask);
						goto error;
					}
					prefixlen = ni_netmask_bits(&mask_addr);
				}
			}
		}

		rp = __ni_route_new(route_list, prefixlen, &dest_addr, &gw_addr);
		if (rp == NULL) {
			ni_error("Unable to add route %s %s %s", dest, gw, mask?: "-");
			goto error;
		}

		if (ifname && strcmp(ifname, "-"))
			ni_string_dup(&rp->nh.device, ifname);
	}

	fclose(fp);
	return 0;

error:
	fclose(fp);
	return -1;
}

/*
 * Read the configuration of a single interface from a sysconfig file
 */
static ni_interface_t *
__ni_suse_read_interface(ni_netconfig_t *nc, const char *filename, const char *ifname)
{
	ni_interface_t *ifp;
	ni_sysconfig_t *sc;

	sc = ni_sysconfig_read(filename);
	if (!sc) {
		ni_error("unable to read %s", filename);
		goto error;
	}

	ifp = __ni_interface_new(ifname, 0);
	if (!ifp) {
		ni_error("Failed to alloc interface %s", ifname);
		goto error;
	}
	__ni_interface_list_append(&nc->interfaces, ifp);

	if (__ni_suse_sysconfig2ifconfig(ifp, sc) < 0)
		goto error;

	/* We rely on the kernel to set up the ::1 device (if ipv6 is enabled) */
	if (ifp->link.type == NI_IFTYPE_LOOPBACK) {
		ni_sockaddr_t local_addr;

		ni_address_parse(&local_addr, "127.0.0.1", AF_INET);
		if (__ni_address_list_find(ifp->addrs, &local_addr) == NULL) {
			ni_debug_readwrite("%s: adding 127.0.0.1/8 to config", ifp->name);
			ni_address_new(ifp, local_addr.ss_family, 8, &local_addr);
		}
		ni_afinfo_addrconf_enable(&ifp->ipv4, NI_ADDRCONF_STATIC);

		ni_address_parse(&local_addr, "::1", AF_INET6);
		if (__ni_address_list_find(ifp->addrs, &local_addr) == NULL) {
			ni_debug_readwrite("%s: adding ::1/128 to config", ifp->name);
			ni_address_new(ifp, local_addr.ss_family, 128, &local_addr);
		}
		ni_afinfo_addrconf_enable(&ifp->ipv6, NI_ADDRCONF_STATIC);
	}

	if (ifp->link.type == NI_IFTYPE_LOOPBACK)
		ni_afinfo_addrconf_disable(&ifp->ipv6, NI_ADDRCONF_AUTOCONF);

	ni_sysconfig_destroy(sc);
	return ifp;

error:
	if (sc)
		ni_sysconfig_destroy(sc);
	return NULL;
}

static int
__ni_suse_sysconfig2ifconfig(ni_interface_t *ifp, ni_sysconfig_t *sc)
{
	char *value = NULL, *hwaddr = NULL;

	if (ni_sysconfig_get_string(sc, "STARTMODE", &value) >= 0)
		__ni_suse_startmode_set(&ifp->startmode, value);
	if (ni_sysconfig_get_string(sc, "BOOTPROTO", &value) >= 0)
		__ni_suse_bootproto_set(ifp, value);
	ni_string_free(&value);

	if (ni_sysconfig_get_string(sc, "LLADDR", &hwaddr) >= 0 && hwaddr) {
		if (ni_link_address_parse(&ifp->link.hwaddr, NI_IFTYPE_ETHERNET, hwaddr) < 0)
			return -1;
		ni_string_free(&hwaddr);
	}

	if (ni_sysconfig_get_integer(sc, "MTU", &ifp->link.mtu) < 0)
		return -1;

	__process_indexed_variables(ifp, sc, "IPADDR", try_add_address);
	try_bonding(ifp, sc);
	try_bridge(ifp, sc);
	try_vlan(ifp, sc);
	try_wireless(ifp, sc);

	/* Guess the interface type */
	ni_interface_guess_type(ifp);

	/* FIXME: What to do with these:
		NAME
		ETHTOOL_OPTIONS
		USERCONTROL
	 */

	return 0;
}

/*
 * Given a basename like "IPADDR", try to find all variables with this
 * prefix (eg "IPADDR", "IPADDR_0", "IPADDR_1", ...) and invoke the provided function
 * for each. Note, this passes the variable suffix ("", "_0", "_1") rather than
 * the full variable name into the called function.
 */
static void
__process_indexed_variables(ni_interface_t *ifp, ni_sysconfig_t *sc,
				const char *basename,
				void (*func)(ni_interface_t *, ni_sysconfig_t *, const char *))
{
	ni_string_array_t names = NI_STRING_ARRAY_INIT;
	unsigned int i, pfxlen;

	if (!ni_sysconfig_find_matching(sc, basename, &names))
		return;

	pfxlen = strlen(basename);
	for (i = 0; i < names.count; ++i)
		func(ifp, sc, names.data[i] + pfxlen);
	ni_string_array_destroy(&names);
}

/*
 * Given a base name and a suffix (eg "IPADDR" and "_1"), build a variable name
 * and look it up.
 */
static ni_var_t *
__find_indexed_variable(ni_sysconfig_t *sc, const char *basename, const char *suffix)
{
	ni_var_t *res;
	char namebuf[64];

	snprintf(namebuf, sizeof(namebuf), "%s%s", basename, suffix);
	res = ni_sysconfig_get(sc, namebuf);
	if (res && (res->value == NULL || res->value[0] == '\0'))
		res = NULL;
	return res;
}

/*
 * Given a suffix like "" or "_1", try to get the IP address and prefix length.
 * If successful, create a new ni_address, attach it to the interface object
 * and return it. 
 */
static ni_address_t *
__get_ipaddr(ni_interface_t *ifp, ni_sysconfig_t *sc, const char *suffix)
{
	ni_var_t *var;
	char *address_string;
	ni_sockaddr_t addr;
	unsigned int prefix_len = 32;
	char *sp;

	var = __find_indexed_variable(sc, "IPADDR", suffix);
	if (!var)
		return NULL;

	address_string = xstrdup(var->value);
	if ((sp = strchr(address_string, '/')) != NULL) {
		*sp++ = '\0';
		prefix_len = strtoul(sp, NULL, 0);
	} else {
		ni_sockaddr_t netmask;

		/* Try PREFIXLEN variable */
		var = __find_indexed_variable(sc, "PREFIXLEN", suffix);
		if (var && var->value) {
			prefix_len = strtoul(var->value, NULL, 0);
		} else
		if ((var = __find_indexed_variable(sc, "NETMASK", suffix)) != NULL
		 && ni_address_parse(&netmask, var->value, AF_UNSPEC) >= 0) {
			prefix_len = ni_netmask_bits(&netmask);
		}
	}

	if (ni_address_parse(&addr, address_string, AF_UNSPEC) < 0) {
		ni_error("Unable to parse %s=\"%s\"", var->name, address_string);
		free(address_string);
		return NULL;
	}
	free(address_string);

	return ni_address_new(ifp, addr.ss_family, prefix_len, &addr);
}

/*
 * Given a suffix like "" or "_1", try to get the IP address and related information.
 * This will evaluate
 *   IPADDR_x
 *   PREFIXLEN_x if needed
 *   BROADCAST_x
 *   REMOTE_IPADDR_x
 */
static void
try_add_address(ni_interface_t *ifp, ni_sysconfig_t *sc, const char *suffix)
{
	ni_var_t *var;
	ni_address_t *ap;

	if (!(ap = __get_ipaddr(ifp, sc, suffix)))
		return;

	if (ap->family == AF_INET) {
		var = __find_indexed_variable(sc, "BROADCAST", suffix);
		if (var)
			ni_address_parse(&ap->bcast_addr, var->value, AF_UNSPEC);
	}

	var = __find_indexed_variable(sc, "REMOTE_IPADDR", suffix);
	if (var)
		ni_address_parse(&ap->peer_addr, var->value, AF_UNSPEC);
}

/*
 * Handle bonding.
 * Bonding interfaces have variables BONDIG_SLAVE_0, BONDIG_SLAVE_1, ... that
 * describe the slave devices.
 *
 * Global bonding configuration is contained in BONDING_MODULE_OPTS
 */
static void
try_add_bonding_slave(ni_interface_t *ifp, ni_sysconfig_t *sc, const char *suffix)
{
	ni_var_t *var;
	ni_bonding_t *bonding;

	var = __find_indexed_variable(sc, "BONDING_SLAVE", suffix);
	if (!var || !var->value)
		return;

	bonding = ni_interface_get_bonding(ifp);
	ni_bonding_add_slave(bonding, var->value);
}

static void
try_bonding(ni_interface_t *ifp, ni_sysconfig_t *sc)
{
	__process_indexed_variables(ifp, sc, "BONDING_SLAVE", try_add_bonding_slave);

	if (ifp->bonding) {
		ifp->link.type = NI_IFTYPE_BOND;
		ni_sysconfig_get_string(sc, "BONDING_MODULE_OPTS", &ifp->bonding->module_opts);
		ni_bonding_parse_module_options(ifp->bonding);
	}
}

/*
 * Bridge devices are recognized by BRIDGE=yes
 */
static void
try_bridge(ni_interface_t *ifp, ni_sysconfig_t *sc)
{
	ni_bridge_t *bridge;
	char *value = NULL, *token;
	int enabled;
	ni_var_t *var;

	if (ni_sysconfig_get_boolean(sc, "BRIDGE", &enabled) < 0 || !enabled)
		return;

	/* Create the interface's bridge data */
	bridge = ni_interface_get_bridge(ifp);
	ifp->link.type = NI_IFTYPE_BRIDGE;

	if ((var = ni_sysconfig_get(sc, "BRIDGE_STP")) != NULL)
		ni_bridge_set_stp(bridge, var->value);
	if ((var = ni_sysconfig_get(sc, "BRIDGE_FORWARDDELAY")) != NULL)
		ni_bridge_set_forward_delay(bridge, var->value);
	if ((var = ni_sysconfig_get(sc, "BRIDGE_AGEINGTIME")) != NULL)
		ni_bridge_set_ageing_time(bridge, var->value);
	if( (var = ni_sysconfig_get(sc, "BRIDGE_HELLOTIME")) != NULL)
		ni_bridge_set_hello_time(bridge, var->value);
	if( (var = ni_sysconfig_get(sc, "BRIDGE_MAXAGE")) != NULL)
		ni_bridge_set_max_age(bridge, var->value);
	if( (var = ni_sysconfig_get(sc, "BRIDGE_PRIORITY")) != NULL)
		ni_bridge_set_priority(bridge, var->value);

	if (ni_sysconfig_get_string(sc, "BRIDGE_PORTS", &value) >= 0) {
		for (token = strtok(value, " \t"); token; token = strtok(NULL, " \t"))
			ni_bridge_add_port_name(bridge, token);
		ni_string_free(&value);
	}

	if (ni_sysconfig_get_string(sc, "BRIDGE_PORTPRIORITIES", &value) >= 0) {
		unsigned int i = 0;
		for (token = strtok(value, " \t"); token; token = strtok(NULL, " \t"), ++i) {
			if (i >= bridge->ports.count)
				break;
			const char *port = bridge->ports.data[i]->name;
			if( ni_bridge_port_set_priority(bridge, port, token) < 0)
				break;
		}
		ni_string_free(&value);
	}
	if (ni_sysconfig_get_string(sc, "BRIDGE_PATHCOSTS", &value) >= 0) {
		unsigned int i = 0;
		for (token = strtok(value, " \t"); token; token = strtok(NULL, " \t"), ++i) {
			if (i >= bridge->ports.count)
				break;
			const char *port = bridge->ports.data[i]->name;
			if( ni_bridge_port_set_path_cost(bridge, port, token) < 0)
				break;
		}
		ni_string_free(&value);
	}
}

/*
 * Wireless interfaces are recognized by WIRELESS=yes
 */
static void
try_wireless(ni_interface_t *ifp, ni_sysconfig_t *sc)
{
	/* TBD */
}

/*
 * VLAN interfaces are recognized by their name (vlan<N>)
 */
static void
try_vlan(ni_interface_t *ifp, ni_sysconfig_t *sc)
{
	ni_vlan_t *vlan;

	/* SLES and openSUSE currently use the vlan<TAG> naming
	 * convention for VLAN interfaces. */
	if (strncmp(ifp->name, "vlan", 4))
		return;

	ifp->link.type = NI_IFTYPE_VLAN;

	vlan = ni_interface_get_vlan(ifp);
	vlan->tag = strtoul(ifp->name + 4, NULL, 0);
	ni_sysconfig_get_string(sc, "ETHERDEVICE", &vlan->physdev_name);
}

/*
 * Mapping STARTMODE values to behaviors and vice versa
 */
#define __DO_START_WAIT(mand, link, timeo) \
					{ .action = NI_INTERFACE_START, .mandatory = mand, .only_if_link = link, .wait = timeo }
#define __DO_START_NOWAIT		{ .action = NI_INTERFACE_START }
#define __DO_STOP_NOWAIT		{ .action = NI_INTERFACE_STOP }
#define __DO_IGNORE			{ .action = NI_INTERFACE_IGNORE }
static struct __ni_ifbehavior_map __ni_suse_startmodes[] = {
	{
		"manual",
		.behavior.ifaction = {
			[NI_IFACTION_MANUAL_UP]	= __DO_START_WAIT(1, 0, 30),
			[NI_IFACTION_MANUAL_DOWN]= __DO_STOP_NOWAIT,
			[NI_IFACTION_BOOT]	= __DO_IGNORE,
			[NI_IFACTION_SHUTDOWN]	= __DO_IGNORE,
			[NI_IFACTION_LINK_UP]	= __DO_IGNORE,
			[NI_IFACTION_LINK_DOWN]	= __DO_IGNORE,
		}
	},
	{
		"auto",
		.behavior.ifaction = {
			[NI_IFACTION_MANUAL_UP]	= __DO_START_WAIT(1, 0, 30),
			[NI_IFACTION_MANUAL_DOWN]= __DO_STOP_NOWAIT,
			[NI_IFACTION_BOOT]	= __DO_START_WAIT(1, 1, 30),
			[NI_IFACTION_SHUTDOWN]	= __DO_STOP_NOWAIT,
			[NI_IFACTION_LINK_UP]	= __DO_START_NOWAIT,
			[NI_IFACTION_LINK_DOWN]	= __DO_STOP_NOWAIT,
		}
	},
	{
		"hotplug",	/* exactly like onboot, except we don't fail during network boot */
		.behavior.ifaction = {
			[NI_IFACTION_MANUAL_UP]	= __DO_START_WAIT(1, 0, 30),
			[NI_IFACTION_MANUAL_DOWN]= __DO_STOP_NOWAIT,
			[NI_IFACTION_BOOT]	= __DO_START_WAIT(0, 1, 30),
			[NI_IFACTION_SHUTDOWN]	= __DO_STOP_NOWAIT,
			[NI_IFACTION_LINK_UP]	= __DO_START_NOWAIT,
			[NI_IFACTION_LINK_DOWN]	= __DO_STOP_NOWAIT,
		}
	},
	{
		"ifplugd",
		.behavior.ifaction = {
			[NI_IFACTION_MANUAL_UP]	= __DO_START_WAIT(1, 0, 30),
			[NI_IFACTION_MANUAL_DOWN]= __DO_STOP_NOWAIT,
			[NI_IFACTION_BOOT]	= __DO_IGNORE,
			[NI_IFACTION_SHUTDOWN]	= __DO_STOP_NOWAIT,
			[NI_IFACTION_LINK_UP]	= __DO_START_NOWAIT,
			[NI_IFACTION_LINK_DOWN]	= __DO_STOP_NOWAIT,
		},
	},
	{
		"nfsroot",
		.behavior.ifaction = {
			[NI_IFACTION_MANUAL_UP]	= __DO_START_WAIT(1, 0, 30),
			[NI_IFACTION_MANUAL_DOWN]= __DO_STOP_NOWAIT,
			[NI_IFACTION_BOOT]	= __DO_START_WAIT(1, 0, ~0U),
			[NI_IFACTION_SHUTDOWN]	= __DO_IGNORE,
			[NI_IFACTION_LINK_UP]	= __DO_START_NOWAIT,
			[NI_IFACTION_LINK_DOWN]	= __DO_STOP_NOWAIT,
		}
	},
	{
		"off",
		.behavior.ifaction = {
			[NI_IFACTION_MANUAL_UP]	= __DO_IGNORE,
			[NI_IFACTION_MANUAL_DOWN]= __DO_STOP_NOWAIT,
			[NI_IFACTION_BOOT]	= __DO_IGNORE,
			[NI_IFACTION_SHUTDOWN]	= __DO_IGNORE,
			[NI_IFACTION_LINK_UP]	= __DO_IGNORE,
			[NI_IFACTION_LINK_DOWN]	= __DO_IGNORE,
		}
	},

	{ NULL }
};

static int
__ni_suse_startmode_set(ni_ifbehavior_t *beh, const char *name)
{
	const ni_ifbehavior_t *match = NULL;

	if (name) {
		if (!strcmp(name, "on")
		 || !strcmp(name, "boot")
		 || !strcmp(name, "onboot"))
			name = "auto";

		match = __ni_netinfo_get_behavior(name, __ni_suse_startmodes);
	}

	if (match)
		*beh = *match;
	else
		*beh = __ni_suse_startmodes[0].behavior;
	return 0;
}

/*
 * Handle BOOTPROTO settings.
 */
struct __ni_suse_bootproto {
	const char *		name;
	unsigned int		ipv4_mask;
	unsigned int		ipv6_mask;
};

#define _(x)		NI_ADDRCONF_MASK(x)
#define AUTO6		NI_ADDRCONF_MASK(NI_ADDRCONF_AUTOCONF)
static struct __ni_suse_bootproto __ni_suse_bootprotos[] = {
	{ "static",	_(NI_ADDRCONF_STATIC),		_(NI_ADDRCONF_STATIC) | AUTO6 },
	{ "static4",	_(NI_ADDRCONF_STATIC),		0 },
	{ "static6",	0,				_(NI_ADDRCONF_STATIC) },

	{ "dhcp",	_(NI_ADDRCONF_DHCP),		AUTO6 },
	{ "dhcp4",	_(NI_ADDRCONF_DHCP),		0 },
	{ "dhcp6",	0,				_(NI_ADDRCONF_DHCP) | AUTO6 },

	{ "ibft",	_(NI_ADDRCONF_IBFT),		_(NI_ADDRCONF_IBFT) | AUTO6 },
	{ "ibft4",	_(NI_ADDRCONF_IBFT),		0 },
	{ "ibft6",	0,				_(NI_ADDRCONF_IBFT) | AUTO6 },

	{ "autoip",	_(NI_ADDRCONF_AUTOCONF),	AUTO6 },
	{ "auto4",	_(NI_ADDRCONF_AUTOCONF),	0 },
	{ "auto6",	0,				AUTO6 },

	{ NULL }
};
#undef _

static int
__ni_suse_bootproto_set(ni_interface_t *ifp, char *value)
{
	char *s;

	if (value == NULL) {
		ifp->ipv4.addrconf = NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC);
		ifp->ipv6.addrconf = NI_ADDRCONF_MASK(NI_ADDRCONF_STATIC) | NI_ADDRCONF_MASK(NI_ADDRCONF_AUTOCONF);
		return 0;
	}

	ifp->ipv4.addrconf = 0;
	ifp->ipv6.addrconf = 0;
	for (s = strtok(value, "+"); s; s = strtok(NULL, "+")) {
		if (!strcmp(s, "none")) {
			ifp->ipv4.addrconf = 0;
			ifp->ipv6.addrconf = 0;
		} else {
			struct __ni_suse_bootproto *bp;

			for (bp = __ni_suse_bootprotos; bp->name; ++bp) {
				if (!strcmp(bp->name, s)) {
					ifp->ipv4.addrconf |= bp->ipv4_mask;
					ifp->ipv6.addrconf |= bp->ipv6_mask;
					goto found;
				}
			}

			ni_warn("%s: unhandled BOOTPROTO \"%s\"", ifp->name, s);

found: ;
		}
	}

	return 0;
}
