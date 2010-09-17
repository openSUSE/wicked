/*
 * Translation between internal representation and SUSE ifcfg files
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <net/if_arp.h>
#include "netinfo_priv.h"
#include "sysconfig.h"


#define _PATH_NETCONFIG_DIR		"/etc/sysconfig/network"

static int		__ni_suse_parse_all(ni_syntax_t *, ni_handle_t *);
static int		__ni_suse_format_all(ni_syntax_t *, ni_handle_t *, FILE *);
static int		__ni_suse_read_routes(ni_route_t **, const char *);
static ni_dhclient_info_t *__ni_suse_read_dhcp(ni_handle_t *);
static ni_interface_t *	__ni_suse_read_interface(ni_handle_t *, const char *, const char *);
static int		__ni_suse_sysconfig2ifconfig(ni_interface_t *, ni_sysconfig_t *);
static int		__ni_suse_sysconfig2dhcp(ni_dhclient_info_t *, ni_sysconfig_t *);
static int		__ni_suse_ifconfig2sysconfig(ni_interface_t *, ni_sysconfig_t *);
static const char *	__ni_suse_startmode(int);
static const char *	__ni_suse_bootproto(int);

static void		__process_indexed_variables(ni_interface_t *, ni_sysconfig_t *,
				const char *,
				void (*)(ni_interface_t *, ni_sysconfig_t *, const char *));
static void		try_add_address(ni_interface_t *, ni_sysconfig_t *, const char *);
static void		try_bonding(ni_interface_t *, ni_sysconfig_t *);
static void		try_bridge(ni_interface_t *ifp, ni_sysconfig_t *);
static void		try_wireless(ni_interface_t *ifp, ni_sysconfig_t *);
static void		try_vlan(ni_interface_t *ifp, ni_sysconfig_t *);

static const char *	__ni_ifcfg_vars_preserve[] = {
	"NAME",
	"ETHTOOL_OPTIONS",
	"USERCONTROL",
	"FIREWALL",

	NULL,
};

/*
 * Create a syntax object for SUSE style ifcfg files
 * For now, we support only reading.
 */
ni_syntax_t *
__ni_syntax_sysconfig_suse(const char *pathname)
{
	ni_syntax_t *syntax;

	if (!pathname)
		pathname = _PATH_NETCONFIG_DIR;
	syntax = calloc(1, sizeof(ni_syntax_t));

	syntax->schema = "suse";
	syntax->base_path = strdup(pathname);
	syntax->parse_all = __ni_suse_parse_all;
	syntax->format_all = __ni_suse_format_all;

	return syntax;
}

/*
 * Refresh network configuration by reading all ifcfg files.
 */
static int
__ni_suse_parse_all(ni_syntax_t *syntax, ni_handle_t *nih)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	const char *base_dir;
	char pathbuf[PATH_MAX];
	int i;

	/* Wipe out all interface information */
	__ni_interfaces_clear(nih);

	base_dir = ni_syntax_base_path(syntax);
	if (!ni_sysconfig_scandir(base_dir, "ifcfg-", &files)) {
		error("No ifcfg files found");
		return -1;
	}

	for (i = 0; i < files.count; ++i) {
		const char *filename = files.data[i];
		const char *ifname = filename + 6;
		ni_interface_t *ifp;

		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", base_dir, filename);
		ifp = __ni_suse_read_interface(nih, pathbuf, filename + 6);
		if (ifp == NULL)
			goto failed;

		snprintf(pathbuf, sizeof(pathbuf), "%s/ifroute-%s", base_dir, ifname);
		if (__ni_suse_read_routes(&ifp->routes, pathbuf) < 0)
			goto failed;
	}
	snprintf(pathbuf, sizeof(pathbuf), "%s/routes", base_dir);
	if (__ni_suse_read_routes(&nih->routes, pathbuf) < 0)
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
		error("Unable to open %s: %m", filename);
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char *dest, *gw, *mask = NULL, *ifname = NULL, *type = NULL;
		struct sockaddr_storage dest_addr, gw_addr, mask_addr;
		unsigned int prefixlen = 255;

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
			error("%s: cannot parse gw addr \"%s\"",
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
				error("%s: cannot parse dest addr \"%s\"",
						filename, dest);
				goto error;
			}
			if (prefixlen == 255) {
				if (!mask || !strcmp(mask, "-")) {
					/* No prefix and no mask given - assume the destination
					   is a single address. Use the full address length
					   as prefix. */
					prefixlen = ni_address_length(dest_addr.ss_family);
				} else {
					/* We have a mask. Try to parse it and count the bits. */
					if (ni_address_parse(&mask_addr, mask, AF_UNSPEC) < 0) {
						error("%s: cannot parse mask addr \"%s\"",
								filename, mask);
						goto error;
					}
					prefixlen = ni_netmask_bits(&mask_addr);
				}
			}
		}

		if (!__ni_route_new(route_list, prefixlen, &dest_addr, &gw_addr)) {
			error("Unable to add route %s %s %s", dest, gw, mask?: "-");
			goto error;
		}
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
__ni_suse_read_interface(ni_handle_t *nih, const char *filename, const char *ifname)
{
	ni_interface_t *ifp;
	ni_sysconfig_t *sc;

	sc = ni_sysconfig_read(filename);
	if (!sc) {
		error("Error parsing %s", filename);
		goto error;
	}

	ifp = ni_interface_new(nih, ifname, 0);
	if (!ifp) {
		error("Failed to alloc interface %s", ifname);
		goto error;
	}

	if (__ni_suse_sysconfig2ifconfig(ifp, sc) < 0)
		goto error;

	if (ifp->ipv4.config == NI_ADDRCONF_DHCP) {
		/* Read default DHCP config */
		if (!(ifp->ipv4.dhcp = __ni_suse_read_dhcp(nih)))
			goto error;

		/* Now check whether the ifcfg file overwrites any of these */
		if (__ni_suse_sysconfig2dhcp(ifp->ipv4.dhcp, sc) < 0)
			goto error;
	}

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

	if (ni_sysconfig_get_string(sc, "STARTMODE", &value) >= 0) {
		/* The following are equivalent */
		if (!value)
			ifp->startmode = NI_START_MANUAL;
		else if (!strcmp(value, "auto")
		 || !strcmp(value, "on")
		 || !strcmp(value, "boot")
		 || !strcmp(value, "onboot")
		 || !strcmp(value, "hotplug"))
			ifp->startmode = NI_START_ONBOOT;
		else if (!strcmp(value, "off"))
			ifp->startmode = NI_START_DISABLE;
		else
			ifp->startmode = NI_START_MANUAL;
	}
	if (ni_sysconfig_get_string(sc, "BOOTPROTO", &value) >= 0) {
		if (!value) {
			ifp->ipv4.config = ifp->ipv6.config = NI_ADDRCONF_STATIC;
		} else {
			char *s;

			for (s = strtok(value, "+"); s; s = strtok(NULL, "+")) {
				if (!strcmp(s, "dhcp")) {
					ifp->ipv4.config = NI_ADDRCONF_DHCP;
					ifp->ipv6.config = NI_ADDRCONF_DHCP;
				} else if (!strcmp(s, "static")) {
					ifp->ipv4.config = NI_ADDRCONF_STATIC;
					ifp->ipv6.config = NI_ADDRCONF_STATIC;
				} else if (!strcmp(s, "dhcp4"))
					ifp->ipv4.config = NI_ADDRCONF_DHCP;
				else if (!strcmp(s, "dhcp6"))
					ifp->ipv6.config = NI_ADDRCONF_DHCP;
				else if (!strcmp(s, "ibft")) {
					ifp->ipv4.config = NI_ADDRCONF_IBFT;
					ifp->ipv6.config = NI_ADDRCONF_IBFT;
				}
				else
					warn("%s: unhandled BOOTPROTO \"%s\"",
							sc->pathname, s);
			}
		}
	}
	ni_string_free(&value);

	if (ni_sysconfig_get_string(sc, "LLADDR", &hwaddr) >= 0 && hwaddr) {
		if (ni_link_address_parse(&ifp->hwaddr, NI_IFTYPE_ETHERNET, hwaddr) < 0)
			return -1;
		ni_string_free(&hwaddr);
	}

	if (ni_sysconfig_get_integer(sc, "MTU", &ifp->mtu) < 0)
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
	struct sockaddr_storage addr;
	unsigned int prefix_len = 32;
	char *sp;

	var = __find_indexed_variable(sc, "IPADDR", suffix);
	if (!var)
		return NULL;

	address_string = strdup(var->value);
	if ((sp = strchr(address_string, '/')) != NULL) {
		*sp++ = '\0';
		prefix_len = strtoul(sp, NULL, 0);
	} else {
		struct sockaddr_storage netmask;

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
		error("Unable to parse %s=\"%s\"", var->name, address_string);
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
		ifp->type = NI_IFTYPE_BOND;
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
	char *ports = NULL, *port;
	int enabled;

	if (ni_sysconfig_get_boolean(sc, "BRIDGE", &enabled) < 0 || !enabled)
		return;

	/* Create the interface's bridge data */
	bridge = ni_interface_get_bridge(ifp);
	ifp->type = NI_IFTYPE_BRIDGE;

	(void) ni_sysconfig_get_integer(sc, "BRIDGE_FORWARDDELAY", &bridge->forward_delay);
	(void) ni_sysconfig_get_boolean(sc, "BRIDGE_STP", &bridge->stp_enabled);

	if (ni_sysconfig_get_string(sc, "BRIDGE_PORTS", &ports) >= 0) {
		for (port = strtok(ports, " \t"); port; port = strtok(NULL, " \t"))
			ni_bridge_add_port(bridge, port);
		ni_string_free(&ports);
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

	ifp->type = NI_IFTYPE_VLAN;

	vlan = ni_interface_get_vlan(ifp);
	vlan->tag = strtoul(ifp->name + 4, NULL, 0);
	ni_sysconfig_get_string(sc, "ETHERDEVICE", &vlan->interface_name);
}

/*
 * Read the global DHCP configuration
 */
static ni_dhclient_info_t *
__ni_suse_read_dhcp(ni_handle_t *nih)
{
	ni_dhclient_info_t *dhcp = ni_dhclient_info_new();
	ni_sysconfig_t *sc;

	sc = ni_sysconfig_read("/etc/sysconfig/network/dhcp");
	if (!sc) {
		ni_error("Error parsing /etc/sysconfig/network/dhcp");
		goto error;
	}

	if (__ni_suse_sysconfig2dhcp(dhcp, sc) < 0)
		goto error;

	ni_sysconfig_destroy(sc);
	return dhcp;

error:
	if (sc)
		ni_sysconfig_destroy(sc);
	if (dhcp)
		ni_dhclient_info_free(dhcp);
	return NULL;
}

static int
__ni_suse_sysconfig2dhcp(ni_dhclient_info_t *dhcp, ni_sysconfig_t *sc)
{
	ni_sysconfig_get_string_optional(sc, "DHCLIENT_HOSTNAME_OPTION", &dhcp->request.hostname);

	/* Convert to lower-case (AUTO -> auto) */
	if (dhcp->request.hostname != NULL) {
		char *s = dhcp->request.hostname;

		for (; *s; ++s)
			*s = tolower(*s);
	}

	ni_sysconfig_get_integer_optional(sc, "DHCLIENT_WAIT_AT_BOOT", &dhcp->lease.timeout);
	ni_sysconfig_get_boolean_optional(sc, "DHCLIENT_RELEASE_BEFORE_QUIT", &dhcp->lease.release_on_exit);
	ni_sysconfig_get_boolean_optional(sc, "DHCLIENT_USE_LAST_LEASE", &dhcp->lease.reuse_unexpired);

	ni_sysconfig_get_string_optional(sc, "DHCLIENT_CLIENT_ID", &dhcp->request.clientid);
	ni_sysconfig_get_string_optional(sc, "DHCLIENT_VENDOR_CLASS_ID", &dhcp->request.vendor_class);
	ni_sysconfig_get_integer_optional(sc, "DHCLIENT_LEASE_TIME", &dhcp->request.lease_time);

	ni_sysconfig_get_boolean_optional(sc, "WRITE_HOSTNAME_TO_HOSTS", &dhcp->update.hosts_file);

	ni_sysconfig_get_boolean_optional(sc, "DHCLIENT_MODIFY_SMB_CONF", &dhcp->update.smb_config);
	ni_sysconfig_get_boolean_optional(sc, "DHCLIENT_SET_HOSTNAME", &dhcp->update.hostname);
	ni_sysconfig_get_boolean_optional(sc, "DHCLIENT_SET_DEFAULT_ROUTE", &dhcp->update.default_route);

	return 0;
}

/*
 * Produce sysconfig files
 */
int
__ni_suse_format_all(ni_syntax_t *syntax, ni_handle_t *nih, FILE *outfile)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	const char *base_dir;
	char pathbuf[PATH_MAX];
	unsigned int i;
	ni_interface_t *ifp;

	nih->seqno++;

	base_dir = ni_syntax_base_path(syntax);
	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		ni_sysconfig_t *sc;

		snprintf(pathbuf, sizeof(pathbuf), "%s/ifcfg-%s", base_dir, ifp->name);
		if (!ni_file_exists(pathbuf)) {
			sc = ni_sysconfig_new(pathbuf);
		} else {
			sc = ni_sysconfig_read_matching(pathbuf, __ni_ifcfg_vars_preserve);
			if (!sc)
				return -1;
		}

		if (__ni_suse_ifconfig2sysconfig(ifp, sc) < 0) {
			ni_sysconfig_destroy(sc);
			return -1;
		}

		if (ni_sysconfig_overwrite(sc) < 0) {
			ni_sysconfig_destroy(sc);
			return -1;
		}
		ni_sysconfig_destroy(sc);

		/* FIXME: rewrite the ifroutes file if there is one.
		 * When we write out the route, update its seqno.
		 */

	}

	/* FIXME: write out the routes file. Ignore all routes that
	 * were written to an ifroutes file above.
	 */
#if 0
	snprintf(pathbuf, sizeof(pathbuf), "%s/routes", base_dir);
	if (__ni_suse_write_routes(&nih->routes, pathbuf) < 0)
		return -1;
#else
	trace("should really rewrite %s here\n", pathbuf);
#endif

	(void) ni_sysconfig_scandir(base_dir, "ifcfg-", &files);
	for (i = 0; i < files.count; ++i) {
		const char *filename = files.data[i];
		const char *ifname = filename + 6;

		if (ni_interface_by_name(nih, ifname) == NULL) {
			/* This interface went away */
			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", base_dir, filename);
			trace("should really unlink(%s) here\n", pathbuf);
		}
	}
	ni_string_array_destroy(&files);

	return 0;
}

static int
__ni_suse_ifconfig2sysconfig(ni_interface_t *ifp, ni_sysconfig_t *sc)
{
	unsigned int aindex;
	ni_address_t *ap;

	ni_sysconfig_set(sc, "STARTMODE", __ni_suse_startmode(ifp->startmode));
	ni_sysconfig_set(sc, "BOOTPROTO", __ni_suse_bootproto(ifp->startmode));

	if (!ifp->hwaddr.type != NI_IFTYPE_UNKNOWN)
		ni_sysconfig_set(sc, "LLADDR", ni_link_address_print(&ifp->hwaddr));

	/* Only do this if the MTU value differs from the device default? */
	if (ifp->mtu)
		ni_sysconfig_set_integer(sc, "MTU", ifp->mtu);

	for (ap = ifp->addrs, aindex = 0; ap; ap = ap->next, aindex++) {
		char addrbuf[256], varname[64];
		char suffix[16] = { '\0' };

		if (aindex)
			snprintf(suffix, sizeof(suffix), "_%u", aindex);

		snprintf(varname, sizeof(varname), "IPADDR%s", suffix);
		snprintf(addrbuf, sizeof(addrbuf), "%s/%u",
			ni_address_print(&ap->local_addr), ap->prefixlen);
		ni_sysconfig_set(sc, varname, addrbuf);

		if (ap->bcast_addr.ss_family != AF_UNSPEC) {
			snprintf(varname, sizeof(varname), "BROADCAST%s", suffix);
			ni_sysconfig_set(sc, varname,
					ni_address_print(&ap->bcast_addr));
		}

		if (ap->peer_addr.ss_family != AF_UNSPEC) {
			snprintf(varname, sizeof(varname), "REMOTE_IPADDR%s", suffix);
			ni_sysconfig_set(sc, varname,
					ni_address_print(&ap->peer_addr));
		}
	}

#if 0
	if (ifp->bonding && __ni_suse_bonding2sysconfig(ifp, sc))
		return -1;

	if (ifp->bridge && __ni_suse_bridge2sysconfig(ifp, sc))
		return -1;

	if (ifp->vlan && __ni_suse_vlan2sysconfig(ifp, sc))
		return -1;

	if (ifp->wireless && __ni_suse_wireless2sysconfig(ifp, sc))
		return -1;
#endif

	return 0;
}

static const char *
__ni_suse_startmode(int mode)
{
	switch (mode) {
	case NI_START_MANUAL:
	default:
		return "manual";
	case NI_START_ONBOOT:
		return "auto";
	case NI_START_DISABLE:
		return "off";
	}
}

static const char *
__ni_suse_bootproto(int proto)
{
	switch (proto) {
	default:
	case NI_ADDRCONF_STATIC:
		return "static";
	case NI_ADDRCONF_DHCP:
		return "dhcp";
	}
}
