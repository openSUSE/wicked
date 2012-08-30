/*
 * Compat functions for SUSE ifcfg style files
 * This support is not complete yet.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#include <limits.h>
#include <errno.h>

#include <wicked/address.h>
#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/sysconfig.h>
#include <wicked/netinfo.h>
#include <wicked/route.h>
#include <wicked/xml.h>

#include <wicked/objectmodel.h>
#include <wicked/dbus.h>
#include "wicked-client.h"

static ni_bool_t	__ni_suse_read_interface(xml_document_t *, const char *, const char *);
static ni_bool_t	__ni_suse_read_globals(const char *path);
static ni_bool_t	__ni_suse_sysconfig2xml(ni_sysconfig_t *, xml_node_t *, const char *);
static ni_bool_t	__process_indexed_variables(const ni_sysconfig_t *, xml_node_t *, const char *, void (*)(const ni_sysconfig_t *, xml_node_t *, const char *));
static ni_var_t *	__find_indexed_variable(const ni_sysconfig_t *, const char *, const char *);
static ni_route_t *	__ni_suse_read_routes(const char *);

/* Helper functions */
static xml_node_t *	xml_node_create(xml_node_t *, const char *);
static void		xml_node_dict_set(xml_node_t *, const char *, const char *);

static ni_sysconfig_t *	__ni_suse_dhcp_defaults;
static ni_route_t *	__ni_suse_global_routes = NULL;

ni_bool_t
__ni_suse_get_interfaces(const char *path, xml_document_t *doc)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	ni_bool_t success = FALSE;
	int i;

	if (path == NULL)
		path = "/etc/sysconfig/network";

	if (ni_isdir(path)) {
		if (!__ni_suse_read_globals(path))
			goto done;

		if (!ni_scandir(path, "ifcfg-*", &files)) {
			ni_error("No ifcfg files found");
			goto done;
		}

		for (i = 0; i < files.count; ++i) {
			const char *filename = files.data[i];
			const char *ifname = filename + 6;
			char pathbuf[PATH_MAX];

			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, filename);
			if (!__ni_suse_read_interface(doc, pathbuf, ifname))
				goto done;
		}
	} else {
		char *basedir;

		ni_string_dup(&basedir, ni_dirname(path));
		if (!__ni_suse_read_globals(path)) {
			ni_string_free(&basedir);
			goto done;
		}
		ni_string_free(&basedir);

		if (!__ni_suse_read_interface(doc, path, NULL))
			goto done;
	}

	success = TRUE;

done:
	ni_route_list_destroy(&__ni_suse_global_routes);
	if (__ni_suse_dhcp_defaults)
		ni_sysconfig_destroy(__ni_suse_dhcp_defaults);

	ni_string_array_destroy(&files);
	return success;
}

/*
 * Read global ifconfig files like ifcfg-routes and dhcp
 */
ni_bool_t
__ni_suse_read_globals(const char *path)
{
	char pathbuf[PATH_MAX];

	if (path == NULL) {
		ni_error("%s: path is NULL", __func__);
		return FALSE;
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/dhcp", path);
	if (ni_file_exists(pathbuf)) {
		__ni_suse_dhcp_defaults = ni_sysconfig_read(pathbuf);
		if (__ni_suse_dhcp_defaults == NULL) {
			ni_error("unable to parse %s", pathbuf);
			return FALSE;
		}
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/routes", path);
	if (ni_file_exists(pathbuf)) {
		if ((__ni_suse_global_routes = __ni_suse_read_routes(pathbuf)) == NULL)
			return FALSE;
	}

	return TRUE;
}

/*
 * Read the routing information from sysconfig/network/routes.
 */
ni_route_t *
__ni_suse_read_routes(const char *filename)
{
	ni_route_t *route_list = NULL;
	char buffer[512];
	FILE *fp;

	if ((fp = fopen(filename, "r")) == NULL) {
		ni_error("unable to open %s: %m", filename);
		return NULL;
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

		rp = ni_route_new(prefixlen, &dest_addr, &gw_addr, &route_list);
		if (rp == NULL) {
			ni_error("Unable to add route %s %s %s", dest, gw, mask?: "-");
			goto error;
		}

		if (ifname && strcmp(ifname, "-"))
			ni_string_dup(&rp->nh.device, ifname);
	}

	fclose(fp);
	return route_list;

error:
	ni_route_list_destroy(&route_list);
	fclose(fp);
	return NULL;
}

/*
 * Read the configuration of a single interface from a sysconfig file
 */
static ni_bool_t
__ni_suse_read_interface(xml_document_t *doc, const char *filename, const char *ifname)
{
	xml_node_t *ifnode;
	ni_sysconfig_t *sc;

	if (!(sc = ni_sysconfig_read(filename))) {
		ni_error("unable to parse %s", filename);
		goto error;
	}

	if (ifname == NULL) {
		const char *basename = ni_basename(filename);

		if (!strncmp(basename, "ifcfg-", 6))
			ifname = basename + 6;
	}
	if (ifname == NULL) {
		ni_error("%s: cannot determine interface name", filename);
		return FALSE;
	}

	ifnode = xml_node_new("interface", doc->root);
	xml_node_new_element("name", ifnode, ifname);

	if (__ni_suse_sysconfig2xml(sc, ifnode, ifname) < 0)
		goto error;

#if 0
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
#endif

	ni_sysconfig_destroy(sc);
	return TRUE;

error:
	if (sc)
		ni_sysconfig_destroy(sc);
	return FALSE;
}

/*
 * Helper function - should go to util.c
 */
const char *
ni_sprint_uint(unsigned int value)
{
	static char buffer[64];

	snprintf(buffer, sizeof(buffer), "%u", value);
	return buffer;
}

/*
 * Translate the SUSE startmodes to <control> element
 */
static xml_node_t *
__ni_suse_startmode2xml(const char *mode, xml_node_t *ifnode)
{
	static struct __ni_control_params {
		const char *		name;
		const char *		control_mode;
		const char *		boot_stage;

		ni_bool_t		mandatory;
		ni_bool_t		link_required;
		unsigned int		timeout;
	} __ni_suse_control_params[] = {
		{ "manual",	NULL,		NULL,		TRUE,	FALSE,	30	},
		{ "auto",	"auto",		NULL,		TRUE,	TRUE,	30	},
		{ "hotplug",	NULL,		NULL,		FALSE,	TRUE,	30	},
		{ "ifplugd",	"ignore",	NULL,		FALSE,	FALSE,	30	},
		{ "nfsroot",	"boot",		"localfs",	TRUE,	TRUE,	~0	},
		{ "off",	"off",		NULL,		FALSE,	FALSE,	0	},
		{ NULL }
	};
	struct __ni_control_params *p, *params = NULL;
	xml_node_t *control, *link;

	if (ni_string_eq(mode, "on")
	 || ni_string_eq(mode, "boot")
	 || ni_string_eq(mode, "onboot"))
		mode = "auto";

	for (p = __ni_suse_control_params; p->name; ++p) {
		if (ni_string_eq(p->name, mode)) {
			params = p;
			break;
		}
	}

	if (!params)
		params = &__ni_suse_control_params[0];

	control = xml_node_create(ifnode, "control");
	if (params->control_mode)
		xml_node_new_element("mode", control, params->control_mode);
	if (params->boot_stage)
		xml_node_new_element("boot-stage", control, params->boot_stage);

	link = xml_node_create(control, "link-detection");
	if (params->timeout == ~0)
		xml_node_new_element("timeout", link, "infinite");
	else if (params->timeout) {
		xml_node_new_element("timeout", link, ni_sprint_uint(params->timeout));
	}
	if (params->link_required)
		(void) xml_node_new("link-required", link);

	return control;
}

/*
 * Handle Ethernet devices
 */
static ni_bool_t
try_ethernet(const ni_sysconfig_t *sc, xml_node_t *ifnode, const char *ifname)
{
	const char *value;
	xml_node_t *child;

	if (strncmp(ifname, "eth", 3))
		return FALSE;

	child = xml_node_new("ethernet", ifnode);

	if ((value = ni_sysconfig_get_value(sc, "LLADDR")) != NULL) {
		ni_hwaddr_t link_addr;

		if (ni_link_address_parse(&link_addr, NI_IFTYPE_ETHERNET, value) >= 0) {
			xml_node_new_element("address", child, value);
		} else {
			ni_warn("cannot parse LLADDR=%s", value);
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "ETHTOOL_OPTIONS")) != NULL) {
		/* ETHTOOL_OPTIONS comes in two flavors
		 *   - starting with a dash: this is "-$option ifname $stuff"
		 *   - otherwise: this is a paramater to be passed to "-s ifname"
		 */
		/* TBD - parse and translate to xml */
	}

	return TRUE;
}

/*
 * Handle bonding devices
 *
 * Bonding interfaces have variables BONDIG_SLAVE_0, BONDIG_SLAVE_1, ... that
 * describe the slave devices.
 *
 * Global bonding configuration is contained in BONDING_MODULE_OPTS
 */
static void
try_add_bonding_slave(const ni_sysconfig_t *sc, xml_node_t *ifnode, const char *suffix)
{
	xml_node_t *bond, *slave;
	ni_var_t *var;

	var = __find_indexed_variable(sc, "BONDING_SLAVE", suffix);
	if (!var || !var->value)
		return;

	bond = xml_node_create(ifnode, "bond");

	slave = xml_node_new("slave", bond);
	xml_node_new_element("device", slave, var->value);

	/* May add <primary>true</primary> if the slave is the primary slave */
}

static ni_bool_t
try_bonding(ni_sysconfig_t *sc, xml_node_t *ifnode, const char *ifname)
{
	const char *module_opts;

	if (!__process_indexed_variables(sc, ifnode, "BONDING_SLAVE", try_add_bonding_slave))
		return FALSE;

	if ((module_opts = ni_sysconfig_get_value(sc, "BONDING_MODULE_OPTS")) != NULL) {
		// ni_bonding_parse_module_options(module_opts);
	}

	return TRUE;
}

/*
 * Bridge devices are recognized by BRIDGE=yes
 */
static ni_bool_t
try_bridge(const ni_sysconfig_t *sc, xml_node_t *ifnode, const char *ifname)
{
	xml_node_t *bridge;
	ni_bool_t enabled;
	ni_var_t *var;

	if (ni_sysconfig_get_boolean(sc, "BRIDGE", &enabled) || !enabled)
		return FALSE;

	bridge = xml_node_create(ifnode, "brigde");
	if ((var = ni_sysconfig_get(sc, "BRIDGE_STP")) != NULL)
		xml_node_new_element("stp", bridge, var->value);
	if ((var = ni_sysconfig_get(sc, "BRIDGE_FORWARDDELAY")) != NULL)
		xml_node_new_element("forward-delay", bridge, var->value);
	if ((var = ni_sysconfig_get(sc, "BRIDGE_AGEINGTIME")) != NULL)
		xml_node_new_element("aging-time", bridge, var->value);
	if( (var = ni_sysconfig_get(sc, "BRIDGE_HELLOTIME")) != NULL)
		xml_node_new_element("hello-time", bridge, var->value);
	if( (var = ni_sysconfig_get(sc, "BRIDGE_MAXAGE")) != NULL)
		xml_node_new_element("max-age", bridge, var->value);
	if( (var = ni_sysconfig_get(sc, "BRIDGE_PRIORITY")) != NULL)
		xml_node_new_element("priority", bridge, var->value);

	if ((var = ni_sysconfig_get(sc, "BRIDGE_PORTS")) != NULL) {
		char *port_pos = NULL, *cost_pos = NULL, *prio_pos = NULL;
		char *port, *cost = NULL, *prio = NULL;
		char *ports, *pathcosts = NULL, *portprios = NULL;

		ports = strdup(var->value);

		if ((var = ni_sysconfig_get(sc, "BRIDGE_PORTPRIORITIES")) != NULL)
			portprios = strdup(var->value);
		if ((var = ni_sysconfig_get(sc, "BRIDGE_PATHCOSTS")) != NULL)
			pathcosts = strdup(var->value);

		port = strtok_r(ports, " \t", &port_pos);
		prio = strtok_r(portprios, " \t", &prio_pos);
		cost = strtok_r(pathcosts, " \t", &cost_pos);

		while (port != NULL) {
			xml_node_t *portnode = xml_node_new("port", bridge);

			xml_node_new_element("device", portnode, port);
			if (prio)
				xml_node_new_element("priority", portnode, prio);
			if (cost)
				xml_node_new_element("path-cost", portnode, cost);

			port = strtok_r(NULL, " \t", &port_pos);
			prio = strtok_r(NULL, " \t", &prio_pos);
			cost = strtok_r(NULL, " \t", &cost_pos);
		}
		ni_string_free(&ports);
		ni_string_free(&portprios);
		ni_string_free(&pathcosts);
	}

	return TRUE;
}


/*
 * VLAN interfaces are recognized by their name (vlan<N>)
 */
static ni_bool_t
try_vlan(const ni_sysconfig_t *sc, xml_node_t *ifnode, const char *ifname)
{
	xml_node_t *vlan;
	const char *etherdev = NULL;

	/* SLES and openSUSE currently use the vlan<TAG> naming
	 * convention for VLAN interfaces. */
	if (strncmp(ifname, "vlan", 4))
		return FALSE;

	if ((etherdev = ni_sysconfig_get_value(sc, "ETHERDEVICE")) != NULL) {
		ni_warn("%s: missing ETHERDEVICE", ifname);
		return FALSE;
	}

	vlan = xml_node_create(ifnode, "vlan");
	xml_node_new_element("device", vlan, etherdev);
	xml_node_new_element("tag", vlan, ifname + 4);
	return TRUE;
}

/*
 * Handle Wireless devices
 * Not yet implemented
 */
static ni_bool_t
try_wireless(const ni_sysconfig_t *sc, xml_node_t *ifnode, const char *ifname)
{
	if (ni_sysconfig_get(sc, "WIRELESS_ESSID") == NULL)
		return FALSE;

	ni_warn("%s: conversion of wireless interfaces not yet supported", ifname);
	return FALSE;
}

/*
 * Static addrconf:
 *
 * Given a suffix like "" or "_1", try to get the IP address and related information.
 * This will evaluate
 *   IPADDR_x
 *   PREFIXLEN_x if needed
 *   BROADCAST_x
 *   REMOTE_IPADDR_x
 */
static ni_bool_t
__get_ipaddr(const ni_sysconfig_t *sc, const char *suffix, ni_address_t **list)
{
	ni_var_t *var;
	ni_sockaddr_t local_addr;
	unsigned int prefixlen;
	ni_address_t *ap;

	var = __find_indexed_variable(sc, "IPADDR", suffix);
	if (!var || !var->value || !var->value[0])
		return TRUE;

	if (!ni_sockaddr_prefix_parse(var->value, &local_addr, &prefixlen)) {
cannot_parse:
		ni_error("Unable to parse %s=\"%s\"", var->name, var->value);
		return FALSE;
	}

	/* If the address wasn't in addr/prefix format, go look elsewhere */
	if (prefixlen == ~0U) {
		ni_sockaddr_t netmask;

		/* Try PREFIXLEN variable */
		var = __find_indexed_variable(sc, "PREFIXLEN", suffix);
		if (var && var->value) {
			prefixlen = strtoul(var->value, NULL, 0);
		} else
		if (local_addr.ss_family == AF_INET
		 && (var = __find_indexed_variable(sc, "NETMASK", suffix)) != NULL
		 && ni_address_parse(&netmask, var->value, AF_INET) >= 0) {
			prefixlen = ni_netmask_bits(&netmask);
		} else {
			unsigned int dummy, len;

			if (!__ni_address_info(local_addr.ss_family, &dummy, &len))
				goto cannot_parse;
			prefixlen = len * 8;
		}
	}

	ap = ni_address_new(local_addr.ss_family, prefixlen, &local_addr, list);
	if (ap->family == AF_INET) {
		var = __find_indexed_variable(sc, "BROADCAST", suffix);
		if (var) {
			ni_address_parse(&ap->bcast_addr, var->value, AF_INET);
			if (ap->bcast_addr.ss_family != ap->family) {
				ni_error("%s: ignoring BROADCAST%s=%s (wrong address family)",
						sc->pathname, suffix, var->value);
				ap->bcast_addr.ss_family = AF_UNSPEC;
			}
		} else {
			/* Clear the default, it's useless */
			memset(&ap->bcast_addr, 0, sizeof(ap->bcast_addr));
		}
	}

	var = __find_indexed_variable(sc, "REMOTE_IPADDR", suffix);
	if (var) {
		ni_address_parse(&ap->peer_addr, var->value, AF_UNSPEC);
		if (ap->peer_addr.ss_family != ap->family) {
			ni_error("%s: ignoring REMOTE_IPADDR%s=%s (wrong address family)",
					sc->pathname, suffix, var->value);
			ap->peer_addr.ss_family = AF_UNSPEC;
		}
	}

	return TRUE;
}


static xml_node_t *
__ni_suse_convert_addrs(xml_node_t *ifnode, ni_address_t *addr_list, int af)
{
	ni_address_t *ap;
	const char *afname;
	xml_node_t *aconf = NULL;

	afname = ni_addrfamily_type_to_name(af);
	if (!afname) {
		ni_error("%s: unknown address family %u", __func__, af);
		return NULL;
	}

	for (ap = addr_list; ap; ap = ap->next) {
		xml_node_t *anode;

		if (ap->family != af)
			continue;

		if (aconf == NULL) {
			char buffer[64];

			snprintf(buffer, sizeof(buffer), "%s:static", afname);
			aconf = xml_node_create(ifnode, buffer);
		}

		anode = xml_node_new("address", aconf);
		xml_node_new_element("local", anode, ni_sockaddr_prefix_print(&ap->local_addr, ap->prefixlen));

		if (ap->peer_addr.ss_family != AF_UNSPEC)
			xml_node_new_element("peer", anode, ni_address_print(&ap->peer_addr));
		if (ap->bcast_addr.ss_family != AF_UNSPEC)
			xml_node_new_element("broadcast", anode, ni_address_print(&ap->bcast_addr));
	}

	return aconf;
}

void
__ni_suse_convert_route(xml_node_t *aconf, const ni_route_t *rp)
{
	xml_node_t *rnode;
	const ni_route_nexthop_t *nh;

	rnode = xml_node_new("route", aconf);
	if (rp->destination.ss_family != AF_UNSPEC && rp->prefixlen != 0) {
		xml_node_new_element("destination", rnode,
				ni_sockaddr_prefix_print(&rp->destination, rp->prefixlen));
	}

	for (nh = &rp->nh; nh; nh = nh->next) {
		xml_node_t *nhnode;

		nhnode = xml_node_new("nexthop", rnode);
		if (nh->gateway.ss_family != AF_UNSPEC)
			xml_node_new_element("gateway", nhnode,
				ni_address_print(&nh->gateway));
	}
}

/*
 * Process static addrconf
 */
static ni_bool_t
__ni_suse_addrconf_static(const ni_sysconfig_t *sc, xml_node_t *ifnode, const char *ifname)
{
	ni_address_t *device_addrs = NULL;
	ni_route_t *device_routes = NULL;
	const char *routespath;
	xml_node_t *aconf;

	/* Loop over all IPADDR* variables and get the addresses */
	{
		ni_string_array_t names = NI_STRING_ARRAY_INIT;
		unsigned int i;

		if (!ni_sysconfig_find_matching(sc, "IPADDR", &names))
			return FALSE;

		for (i = 0; i < names.count; ++i) {
			if (!__get_ipaddr(sc, names.data[i] + 6, &device_addrs))
				return FALSE;
		}
		ni_string_array_destroy(&names);
	}

	/* Hack up the loopback interface */
	if (!strcmp(ifname, "lo")) {
		ni_sockaddr_t local_addr;

		ni_address_parse(&local_addr, "127.0.0.1", AF_INET);
		if (ni_address_list_find(device_addrs, &local_addr) == NULL)
			ni_address_new(AF_INET, 8, &local_addr, &device_addrs);

		ni_address_parse(&local_addr, "::1", AF_INET6);
		if (ni_address_list_find(device_addrs, &local_addr) == NULL)
			ni_address_new(AF_INET6, 128, &local_addr, &device_addrs);
	}

	routespath = ni_sibling_path_printf(sc->pathname, "ifroute-%s", ifname);
	if (routespath && ni_file_exists(routespath)) {
		ni_route_t *device_routes;

		device_routes = __ni_suse_read_routes(routespath);
		if (device_routes == NULL)
			ni_warn("unable to parse %s", routespath);
	}

	ni_address_list_dedup(&device_addrs);

	if ((aconf = __ni_suse_convert_addrs(ifnode, device_addrs, AF_INET)) != NULL) {
		ni_route_t *rp;

		for (rp = __ni_suse_global_routes; rp; rp = rp->next) {
			ni_address_t *ap;

			if (rp->family != AF_INET)
				continue;
			if (rp->nh.device && !ni_string_eq(rp->nh.device, ifname))
				continue;
			for (ap = device_addrs; ap; ap = ap->next) {
				if (rp->nh.gateway.ss_family == AF_INET
				 && ni_address_can_reach(ap, &rp->nh.gateway)) {
					__ni_suse_convert_route(aconf, rp);
					break;
				}
			}
		}

		for (rp = device_routes; rp; rp = rp->next) {
			if (rp->family == AF_INET)
				__ni_suse_convert_route(aconf, rp);
		}
	}

	if ((aconf = __ni_suse_convert_addrs(ifnode, device_addrs, AF_INET6)) != NULL) {
		ni_route_t *rp;

		for (rp = __ni_suse_global_routes; rp; rp = rp->next) {
			if (rp->family != AF_INET6)
				continue;
			if (rp->nh.device && !ni_string_eq(rp->nh.device, ifname))
				continue;

			__ni_suse_convert_route(aconf, rp);
		}

		for (rp = device_routes; rp; rp = rp->next) {
			if (rp->family == AF_INET6)
				__ni_suse_convert_route(aconf, rp);
		}
	}

	ni_route_list_destroy(&device_routes);
	return TRUE;
}

/*
 * Process DHCPv4 addrconf
 */
static ni_bool_t
__ni_suse_addrconf_dhcp_options(const ni_sysconfig_t *sc, xml_node_t *dhcp)
{
	const ni_var_t *var;

	if ((var = ni_sysconfig_get(sc, "DHCLIENT_HOSTNAME_OPTION")) != NULL
	 && var->value && strcasecmp(var->value, "auto"))
		xml_node_dict_set(dhcp, "hostname", var->value);

	if ((var = ni_sysconfig_get(sc, "DHCLIENT_WAIT_AT_BOOT")) != NULL)
		xml_node_dict_set(dhcp, "acquire-timeout", var->value);

	if ((var = ni_sysconfig_get(sc, "DHCLIENT_CLIENT_ID")) != NULL)
		xml_node_dict_set(dhcp, "client-id", var->value);
	if ((var = ni_sysconfig_get(sc, "DHCLIENT_VENDOR_CLASS_ID")) != NULL)
		xml_node_dict_set(dhcp, "vendor-class", var->value);
	if ((var = ni_sysconfig_get(sc, "DHCLIENT_LEASE_TIME")) != NULL)
		xml_node_dict_set(dhcp, "lease-time", var->value);

	/* Ignored for now:
	   DHCLIENT_USE_LAST_LEASE
	   WRITE_HOSTNAME_TO_HOSTS
	   DHCLIENT_MODIFY_SMB_CONF
	   DHCLIENT_SET_HOSTNAME
	   DHCLIENT_SET_DEFAULT_ROUTE
	 */

	return TRUE;
}

static ni_bool_t
__ni_suse_addrconf_dhcp4(const ni_sysconfig_t *sc, xml_node_t *ifnode, const char *ifname)
{
	xml_node_t *aconf;

	aconf = xml_node_new("ipv4:dhcp", ifnode);
	xml_node_new_element("enabled", aconf, "true");

	if (__ni_suse_dhcp_defaults)
		__ni_suse_addrconf_dhcp_options(__ni_suse_dhcp_defaults, aconf);

	/* overwrite DHCP defaults with parameters from this ifcfg file */
	__ni_suse_addrconf_dhcp_options(sc, aconf);

	return TRUE;
}

/*
 * Convert an ifcfg file to XML
 */
ni_bool_t
__ni_suse_sysconfig2xml(ni_sysconfig_t *sc, xml_node_t *ifnode, const char *ifname)
{
	const char *value = NULL;
	unsigned int mtu = 0;
	xml_node_t *child;

	if (ni_sysconfig_get_string(sc, "STARTMODE", &value))
		__ni_suse_startmode2xml(value, ifnode);
	else
		__ni_suse_startmode2xml(value, NULL);

	child = xml_node_new("link", ifnode);
	if (ni_sysconfig_get_integer(sc, "MTU", &mtu) && mtu) {
		xml_node_new_element("mtu", child, ni_sprint_uint(mtu));

		/* Other values? */
	}

	if (!try_ethernet(sc, ifnode, ifname)
	 && !try_bonding(sc, ifnode, ifname)
	 && !try_bridge(sc, ifnode, ifname)
	 && !try_vlan(sc, ifnode, ifname)
	 && !try_wireless(sc, ifnode, ifname)
	 )
		;

	if ((value = ni_sysconfig_get_value(sc, "BOOTPROTO")) == NULL) {
		if (ni_string_eq(ifname, "lo"))
			value = "static";
		else
			value = "dhcp";
	}

	if (ni_string_eq(value, "static"))
		__ni_suse_addrconf_static(sc, ifnode, ifname);
	else if (ni_string_eq(value, "dhcp"))
		__ni_suse_addrconf_dhcp4(sc, ifnode, ifname);

	/* FIXME: What to do with these:
		NAME
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
static ni_bool_t
__process_indexed_variables(const ni_sysconfig_t *sc, xml_node_t *node,
				const char *basename,
				void (*func)(const ni_sysconfig_t *, xml_node_t *, const char *))
{
	ni_string_array_t names = NI_STRING_ARRAY_INIT;
	unsigned int i, pfxlen;

	if (!ni_sysconfig_find_matching(sc, basename, &names))
		return FALSE;

	pfxlen = strlen(basename);
	for (i = 0; i < names.count; ++i)
		func(sc, node, names.data[i] + pfxlen);
	ni_string_array_destroy(&names);
	return TRUE;
}

/*
 * Given a base name and a suffix (eg "IPADDR" and "_1"), build a variable name
 * and look it up.
 */
static ni_var_t *
__find_indexed_variable(const ni_sysconfig_t *sc, const char *basename, const char *suffix)
{
	ni_var_t *res;
	char namebuf[64];

	snprintf(namebuf, sizeof(namebuf), "%s%s", basename, suffix);
	res = ni_sysconfig_get(sc, namebuf);
	if (res && (res->value == NULL || res->value[0] == '\0'))
		res = NULL;
	return res;
}

static xml_node_t *
xml_node_create(xml_node_t *parent, const char *name)
{
	xml_node_t *child;

	if ((child = xml_node_get_child(parent, name)) == NULL)
		child = xml_node_new(name, parent);
	return child;
}

static void
xml_node_dict_set(xml_node_t *parent, const char *name, const char *value)
{
	xml_node_t *child;

	if (!value || !*value)
		return;

	child = xml_node_create(parent, name);
	xml_node_set_cdata(child, value);
}
