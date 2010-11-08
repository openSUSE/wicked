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
#include <unistd.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include "netinfo_priv.h"
#include "sysconfig.h"


#define _PATH_NETCONFIG_DIR		"/etc/sysconfig/network"

static int		__ni_suse_get_interfaces(ni_syntax_t *, ni_handle_t *);
static int		__ni_suse_put_interfaces(ni_syntax_t *, ni_handle_t *, FILE *);
static int		__ni_suse_read_routes(ni_route_t **, const char *);
static ni_addrconf_request_t *__ni_suse_read_dhcp(ni_handle_t *);
static ni_interface_t *	__ni_suse_read_interface(ni_handle_t *, const char *, const char *);
static int		__ni_suse_sysconfig2ifconfig(ni_interface_t *, ni_sysconfig_t *);
static int		__ni_suse_sysconfig2dhcp(ni_addrconf_request_t *, ni_sysconfig_t *);
static int		__ni_suse_ifconfig2sysconfig(ni_interface_t *, ni_sysconfig_t *);
static int		__ni_suse_dhcp2sysconfig(const ni_addrconf_request_t *, const ni_addrconf_request_t *,
				ni_sysconfig_t *);
static int		__ni_suse_bridge2sysconfig(const ni_interface_t *, ni_sysconfig_t *);
static int		__ni_suse_bonding2sysconfig(const ni_interface_t *, ni_sysconfig_t *);
static const char *	__ni_suse_startmode_get(const ni_ifbehavior_t *);
static int		__ni_suse_startmode_set(ni_ifbehavior_t *, const char *);
static const char *	__ni_suse_bootproto_get(const ni_interface_t *);
static int		__ni_suse_bootproto_set(ni_interface_t *, char *);

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
	"BROADCAST",
	"MTU",
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
	syntax->get_interfaces = __ni_suse_get_interfaces;
	syntax->put_interfaces = __ni_suse_put_interfaces;

	return syntax;
}

/*
 * Refresh network configuration by reading all ifcfg files.
 */
static int
__ni_suse_get_interfaces(ni_syntax_t *syntax, ni_handle_t *nih)
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
					prefixlen = ni_address_length(dest_addr.ss_family) * 8;
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

	if (ni_afinfo_addrconf_test(&ifp->ipv4, NI_ADDRCONF_DHCP)) {
		/* Read default DHCP config */
		if (!(ifp->ipv4.request[NI_ADDRCONF_DHCP] = __ni_suse_read_dhcp(nih)))
			goto error;

		/* Now check whether the ifcfg file overwrites any of these */
		if (__ni_suse_sysconfig2dhcp(ifp->ipv4.request[NI_ADDRCONF_DHCP], sc) < 0)
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

	if (ni_sysconfig_get_string(sc, "STARTMODE", &value) >= 0)
		__ni_suse_startmode_set(&ifp->startmode, value);
	if (ni_sysconfig_get_string(sc, "BOOTPROTO", &value) >= 0)
		__ni_suse_bootproto_set(ifp, value);
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
 * Build an indexed variable name
 */
static const char *
__build_indexed_name(const char *stem, int index)
{
	static char namebuf[64];

	if (index < 0)
		return stem;

	snprintf(namebuf, sizeof(namebuf), "%s_%u", stem, index);
	return namebuf;
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

static int
__ni_suse_bonding2sysconfig(const ni_interface_t *ifp, ni_sysconfig_t *sc)
{
	ni_bonding_t *bonding = ifp->bonding;
	unsigned int i;

	for (i = 0; i < bonding->slave_names.count; ++i) {
		ni_sysconfig_set(sc, __build_indexed_name("BONDING_SLAVE", i),
				bonding->slave_names.data[i]);
	}

	ni_bonding_build_module_options(bonding);
	ni_sysconfig_set(sc, "BONDING_MODULE_OPTS", ifp->bonding->module_opts);

	return 0;
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
	ifp->type = NI_IFTYPE_BRIDGE;

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
			ni_bridge_add_port(bridge, token);
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

static int
__ni_suse_bridge2sysconfig(const ni_interface_t *ifp, ni_sysconfig_t *sc)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_bridge_t *bridge = ifp->bridge;
	unsigned int i;
	char *value = NULL;

	ni_sysconfig_set_boolean(sc, "BRIDGE", 1);
	if (ni_bridge_get_stp(bridge, &value) >= 0) {
		ni_sysconfig_set(sc, "BRIDGE_STP", value);
		ni_string_free(&value);
	}
	if (ni_bridge_get_forward_delay(bridge, &value) >= 0) {
		ni_sysconfig_set(sc, "BRIDGE_FORWARDDELAY", value);
		ni_string_free(&value);
	}
	if (ni_bridge_get_ageing_time(bridge, &value) >= 0) {
		ni_sysconfig_set(sc, "BRIDGE_AGEINGTIME", value);
		ni_string_free(&value);
	}
	if (ni_bridge_get_hello_time(bridge, &value) >= 0) {
		ni_sysconfig_set(sc, "BRIDGE_HELLOTIME", value);
		ni_string_free(&value);
	}
	if (ni_bridge_get_priority(bridge, &value) >= 0) {
		ni_sysconfig_set(sc, "BRIDGE_PRIORITY", value);
		ni_string_free(&value);
	}
	if (ni_bridge_get_max_age(bridge, &value) >= 0) {
		ni_sysconfig_set(sc, "BRIDGE_MAXAGE", value);
		ni_string_free(&value);
	}

	for (i = 0; i < bridge->ports.count; ++i) {
		const char *port = bridge->ports.data[i]->name;
		if (i)
			ni_stringbuf_putc(&buf, ' ');
		ni_stringbuf_puts(&buf, port);
	}
	ni_sysconfig_set(sc, "BRIDGE_PORTS", buf.string);
	ni_stringbuf_clear(&buf);

	for (i = 0; i < bridge->ports.count; ++i) {
		const char *port = bridge->ports.data[i]->name;
		if (ni_bridge_port_get_priority(bridge, port, &value) <= 0)
			break;
		if (i)
			ni_stringbuf_putc(&buf, ' ');
		ni_stringbuf_puts(&buf, value);
		ni_string_free(&value);
	}
	ni_sysconfig_set(sc, "BRIDGE_PORTPRIORITIES", buf.string);
	ni_stringbuf_clear(&buf);

	for (i = 0; i < bridge->ports.count; ++i) {
		const char *port = bridge->ports.data[i]->name;
		if (ni_bridge_port_get_path_cost(bridge, port, &value) <= 0)
			break;
		if (i)
			ni_stringbuf_putc(&buf, ' ');
		ni_stringbuf_puts(&buf, value);
		ni_string_free(&value);
	}
	ni_sysconfig_set(sc, "BRIDGE_PATHCOSTS", buf.string);
	ni_stringbuf_destroy(&buf);

	return 0;
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
static ni_addrconf_request_t *
__ni_suse_read_dhcp(ni_handle_t *nih)
{
	ni_addrconf_request_t *dhcp = ni_addrconf_request_new(NI_ADDRCONF_DHCP, -1);
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
		ni_addrconf_request_free(dhcp);
	return NULL;
}

static int
__ni_suse_sysconfig2dhcp(ni_addrconf_request_t *dhcp, ni_sysconfig_t *sc)
{
	ni_sysconfig_get_string_optional(sc, "DHCLIENT_HOSTNAME_OPTION", &dhcp->dhcp.hostname);

	/* Convert to lower-case (AUTO -> auto) */
	if (dhcp->dhcp.hostname != NULL) {
		char *s = dhcp->dhcp.hostname;

		for (; *s; ++s)
			*s = tolower(*s);
	}

	ni_sysconfig_get_integer_optional(sc, "DHCLIENT_WAIT_AT_BOOT", &dhcp->acquire_timeout);
	ni_sysconfig_get_boolean_optional(sc, "DHCLIENT_USE_LAST_LEASE", &dhcp->reuse_unexpired);

	ni_sysconfig_get_string_optional(sc, "DHCLIENT_CLIENT_ID", &dhcp->dhcp.clientid);
	ni_sysconfig_get_string_optional(sc, "DHCLIENT_VENDOR_CLASS_ID", &dhcp->dhcp.vendor_class);
	ni_sysconfig_get_integer_optional(sc, "DHCLIENT_LEASE_TIME", &dhcp->dhcp.lease_time);

	if (ni_sysconfig_test_boolean(sc, "WRITE_HOSTNAME_TO_HOSTS"))
		ni_addrconf_set_update(dhcp, NI_ADDRCONF_UPDATE_HOSTSFILE);
	if (ni_sysconfig_test_boolean(sc, "DHCLIENT_MODIFY_SMB_CONF"))
		ni_addrconf_set_update(dhcp, NI_ADDRCONF_UPDATE_NETBIOS);
	if (ni_sysconfig_test_boolean(sc, "DHCLIENT_SET_HOSTNAME"))
		ni_addrconf_set_update(dhcp, NI_ADDRCONF_UPDATE_HOSTNAME);
	if (ni_sysconfig_test_boolean(sc, "DHCLIENT_SET_DEFAULT_ROUTE"))
		ni_addrconf_set_update(dhcp, NI_ADDRCONF_UPDATE_DEFAULT_ROUTE);

	return 0;
}

int
__ni_suse_dhcp2sysconfig(const ni_addrconf_request_t *ifdhcp, const ni_addrconf_request_t *sysdhcp,
				ni_sysconfig_t *sc)
{
	if (ifdhcp->acquire_timeout != sysdhcp->acquire_timeout)
		ni_sysconfig_set_integer(sc, "DHCLIENT_WAIT_AT_BOOT", ifdhcp->acquire_timeout);
	if (ifdhcp->reuse_unexpired != sysdhcp->reuse_unexpired)
		ni_sysconfig_set_boolean(sc, "DHCLIENT_USE_LAST_LEASE", ifdhcp->reuse_unexpired);

	if (!xstreq(ifdhcp->dhcp.hostname, sysdhcp->dhcp.hostname))
		ni_sysconfig_set(sc, "DHCLIENT_HOSTNAME_OPTION", ifdhcp->dhcp.hostname);
	if (!xstreq(ifdhcp->dhcp.clientid, sysdhcp->dhcp.clientid))
		ni_sysconfig_set(sc, "DHCLIENT_CLIENT_ID", ifdhcp->dhcp.clientid);
	if (!xstreq(ifdhcp->dhcp.vendor_class, sysdhcp->dhcp.vendor_class))
		ni_sysconfig_set(sc, "DHCLIENT_VENDOR_CLASS_ID", ifdhcp->dhcp.vendor_class);
	if (ifdhcp->dhcp.lease_time != sysdhcp->dhcp.lease_time)
		ni_sysconfig_set_integer(sc, "DHCLIENT_LEASE_TIME", ifdhcp->dhcp.lease_time);

	ni_sysconfig_set_boolean(sc, "WRITE_HOSTNAME_TO_HOSTS",
			ni_addrconf_should_update(ifdhcp, NI_ADDRCONF_UPDATE_HOSTSFILE));
	ni_sysconfig_set_boolean(sc, "DHCLIENT_MODIFY_SMB_CONF",
			ni_addrconf_should_update(ifdhcp, NI_ADDRCONF_UPDATE_NETBIOS));
	ni_sysconfig_set_boolean(sc, "DHCLIENT_SET_HOSTNAME",
			ni_addrconf_should_update(ifdhcp, NI_ADDRCONF_UPDATE_HOSTNAME));
	ni_sysconfig_set_boolean(sc, "DHCLIENT_SET_DEFAULT_ROUTE",
			ni_addrconf_should_update(ifdhcp, NI_ADDRCONF_UPDATE_DEFAULT_ROUTE));
	ni_sysconfig_set_boolean(sc, "DHCLIENT_MODIFY_NIS_CONF",
			ni_addrconf_should_update(ifdhcp, NI_ADDRCONF_UPDATE_NIS));


	return 0;
}

/*
 * Produce sysconfig files
 */
int
__ni_suse_put_interfaces(ni_syntax_t *syntax, ni_handle_t *nih, FILE *outfile)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	ni_addrconf_request_t *dhcp = NULL;
	const char *base_dir;
	char pathbuf[PATH_MAX];
	unsigned int i;
	ni_interface_t *ifp;

	nih->seqno++;

	base_dir = ni_syntax_base_path(syntax);
	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		ni_sysconfig_t *sc;

		snprintf(pathbuf, sizeof(pathbuf), "%s/ifcfg-%s", base_dir, ifp->name);
		if (ifp->deleted) {
			ni_debug_readwrite("removing %s", pathbuf);
			if (unlink(pathbuf) < 0)
				ni_error("unable to remove %s: %m", pathbuf);
			continue;
		}

		if (!ifp->modified)
			continue;

		if (!ni_file_exists(pathbuf)) {
			sc = ni_sysconfig_new(pathbuf);
		} else {
			sc = ni_sysconfig_read_matching(pathbuf, __ni_ifcfg_vars_preserve);
			if (!sc)
				return -1;
		}

		if (__ni_suse_ifconfig2sysconfig(ifp, sc) < 0) {
			ni_sysconfig_destroy(sc);
			goto error;
		}

		/* Write out DHCP parameters. It would be really cool to know
		 * whether the client asked to use all system config options
		 * as-is, or whether he wanted some of them changed specifically
		 * for this interface.
		 * The best we can do for now is look for where we differ from the
		 * system defaults.
		 */
		if (ni_afinfo_addrconf_test(&ifp->ipv4, NI_ADDRCONF_DHCP)) {
			if (!dhcp)
				dhcp = __ni_suse_read_dhcp(nih);
			if (__ni_suse_dhcp2sysconfig(ifp->ipv4.request[NI_ADDRCONF_DHCP], dhcp, sc) < 0) {
				ni_sysconfig_destroy(sc);
				goto error;
			}
		}

		if (ni_debug & NI_TRACE_READWRITE) {
			const ni_var_t *var = sc->vars.data;
			unsigned int i;

			ni_trace("Rewriting %s:", sc->pathname);
			for (i = 0; i < sc->vars.count; ++i, ++var)
				ni_trace("  %s=%s", var->name, var->value);
		}

		ni_debug_readwrite("rewriting %s", pathbuf);
		if (ni_sysconfig_rewrite(sc) < 0) {
			ni_sysconfig_destroy(sc);
			goto error;
		}
		ni_sysconfig_destroy(sc);

		/* FIXME: rewrite the ifroutes file if there is one.
		 * When we write out the route, update its seqno.
		 */

	}

	/* FIXME: write out the routes file. Ignore all routes that
	 * were written to an ifroutes file above.
	 */
	snprintf(pathbuf, sizeof(pathbuf), "%s/routes", base_dir);
#if 0
	if (__ni_suse_write_routes(&nih->routes, pathbuf) < 0)
		return -1;
#else
	trace("should really rewrite %s here", pathbuf);
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

	if (dhcp)
		ni_addrconf_request_free(dhcp);
	return 0;

error:
	if (dhcp)
		ni_addrconf_request_free(dhcp);
	return -1;
}

static int
__ni_suse_ifconfig2sysconfig(ni_interface_t *ifp, ni_sysconfig_t *sc)
{
	unsigned int aindex;
	ni_address_t *ap;

	ni_sysconfig_set(sc, "STARTMODE", __ni_suse_startmode_get(&ifp->startmode));
	ni_sysconfig_set(sc, "BOOTPROTO", __ni_suse_bootproto_get(ifp));

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

		snprintf(varname, sizeof(varname), "BROADCAST%s", suffix);
		if (ap->bcast_addr.ss_family != AF_UNSPEC) {
			ni_sysconfig_set(sc, varname,
					ni_address_print(&ap->bcast_addr));
		} else {
			ni_sysconfig_set(sc, varname, NULL);
		}

		snprintf(varname, sizeof(varname), "NETWORK%s", suffix);
		/* FIXME: should print network prefix */

		snprintf(varname, sizeof(varname), "REMOTE_IPADDR%s", suffix);
		if (ap->peer_addr.ss_family != AF_UNSPEC) {
			ni_sysconfig_set(sc, varname,
					ni_address_print(&ap->peer_addr));
		} else {
			ni_sysconfig_set(sc, varname, NULL);
		}
	}

	if (ifp->bonding && __ni_suse_bonding2sysconfig(ifp, sc))
		return -1;

	if (ifp->bridge && __ni_suse_bridge2sysconfig(ifp, sc))
		return -1;

#if 0
	if (ifp->vlan && __ni_suse_vlan2sysconfig(ifp, sc))
		return -1;

	if (ifp->wireless && __ni_suse_wireless2sysconfig(ifp, sc))
		return -1;
#endif

	return 0;
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

static const char *
__ni_suse_startmode_get(const ni_ifbehavior_t *beh)
{
	return __ni_netinfo_best_behavior(beh, __ni_suse_startmodes);
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

/* Test whether all bits in @mustbeset are also present in @value */
#define mask_at_least(value, mustbeset)	(((mustbeset) & ~(value)) == 0)

static const char *
__ni_suse_bootproto_get(const ni_interface_t *ifp)
{
	static char protobuf[256];
	unsigned int aconf4, missing4;
	unsigned int aconf6, missing6;
	struct __ni_suse_bootproto *bp;

	aconf4 = missing4 = ifp->ipv4.addrconf;
	aconf6 = missing6 = ifp->ipv6.addrconf;

	if (aconf4 == 0 && aconf6 == 0)
		return "none";

	protobuf[0] = '\0';
	for (bp = __ni_suse_bootprotos; bp->name; ++bp) {
		/* Skip this entry if it doesn't cover any new bits */
		if (!(bp->ipv4_mask & missing4) && !(bp->ipv6_mask & missing6))
			continue;

		if (mask_at_least(aconf4, bp->ipv4_mask)
		 && mask_at_least(aconf6, bp->ipv6_mask)) {
			missing4 &= ~bp->ipv4_mask;
			missing6 &= ~bp->ipv6_mask;

			if (protobuf[0])
				strcat(protobuf, "+");
			strcat(protobuf, bp->name);

			/* Are we done yet? */
			if (missing4 == 0 && missing6 == 0)
				break;
		}
	}

	if (missing4 || missing6)
		ni_warn("%s: unable to represent addrconf modes", ifp->name);

	return protobuf;
}

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
