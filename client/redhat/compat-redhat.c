/*
 *	Translation between internal representation and RedHat ifcfg files
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/route.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/vlan.h>
#include <wicked/logging.h>
#include <wicked/sysconfig.h>

#include "client/wicked-client.h"


#define _PATH_NETCONFIG_DIR		"/etc/sysconfig/network-scripts"

static ni_compat_netdev_t *__ni_redhat_read_interface(const char *, const char *, ni_compat_netdev_array_t *);
static ni_bool_t	__ni_redhat_define_interface(ni_sysconfig_t *, ni_compat_netdev_t *, ni_compat_netdev_array_t *);
static ni_compat_netdev_t *__ni_redhat_define_alias(ni_sysconfig_t *, const char *, ni_compat_netdev_array_t *);

/*
 * Refresh network configuration by reading all ifcfg files.
 */
static ni_bool_t
__ni_redhat_get_interfaces(const char *root, const char *path, ni_compat_ifconfig_t *config)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	ni_bool_t success = FALSE;
	char pathbuf[PATH_MAX];
	char *pathname = NULL;
	const char *_path = _PATH_NETCONFIG_DIR;

	if (!ni_string_empty(path))
		_path = path;

	if (!root)
		root = "";

	if (ni_string_empty(root))
		snprintf(pathbuf, sizeof(pathbuf), "%s", _path);
	else
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", root, _path);

	if (!ni_realpath(pathbuf, &pathname)) {
		if (!ni_string_empty(path)) {
			ni_error("Configuration directory '%s' does not exist", path);
			goto done;
		}
	} else
	if (ni_isdir(pathname)) {
		unsigned int i;

		if (!ni_sysconfig_scandir(pathname, "ifcfg-*", &files)) {
			ni_error("No ifcfg files found in %s", pathname);
			success = TRUE;
			goto done;
		}

		for (i = 0; i < files.count; ++i) {
			const char *filename = files.data[i];
			const char *ifname = filename + sizeof("ifcfg-")-1;
			ni_compat_netdev_t *compat;

			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", pathname, filename);
			if (!(compat = __ni_redhat_read_interface(pathbuf, ifname, &config->netdevs)))
				goto done;

			ni_compat_netdev_set_origin(compat, config->schema, pathbuf);
		}
	} else {
		ni_error("Cannot use '%s' to read redhat ifcfg files -- not a directory",
			pathname);
		goto done;
	}


	success = TRUE;
done:
	ni_string_free(&pathname);
	ni_string_array_destroy(&files);
	return success;
}

ni_bool_t
__ni_redhat_get_ifconfig(const char *root, const char *path, ni_compat_ifconfig_t *result)
{
	/* get global control things here */
	return __ni_redhat_get_interfaces(root, path, result);
}


/*
 * Read the configuration of a single interface from a sysconfig file
 */
static ni_compat_netdev_t *
__ni_redhat_read_interface(const char *filename, const char *ifname, ni_compat_netdev_array_t *known_devices)
{
	ni_compat_netdev_t *compat = NULL;
	const char *value;
	ni_sysconfig_t *sc;

	if (!(sc = ni_sysconfig_read(filename))) {
		ni_error("unable to parse %s", filename);
		goto error;
	}

	/* RH expects the DEVICE=... to take precedence over whatever is
	 * specified in the filename */
	ifname = ni_sysconfig_get_value(sc, "DEVICE");

	/* HWADDR is used to identify the interface by its MAC address. */
	if ((value = ni_sysconfig_get_value(sc, "HWADDR")) != NULL) {
		ni_hwaddr_t hwaddr;

		if (ni_link_address_parse(&hwaddr, ARPHRD_ETHER, value) < 0) {
			ni_warn("%s: cannot parse HWADDR=%s", sc->pathname, value);
			return NULL;
		}

		compat = ni_compat_netdev_by_hwaddr(known_devices, &hwaddr);
		if (compat == NULL) {
			compat = ni_compat_netdev_new(ifname);
			compat->identify.hwaddr = hwaddr;
			ni_compat_netdev_array_append(known_devices, compat);
		} else if (ifname) {
			ni_warn("%s: file specifies DEVICE and HWADDR", sc->pathname);
		}
	}

	/* Bonding slaves may create their master interface
	 * on the fly, so we cannot create the netdev directly here,
	 * but have to consult the list of devices we've learned so far.
	 */
	if (compat == NULL && ifname)
		compat = ni_compat_netdev_by_name(known_devices, ifname);

	if (compat == NULL && ifname) {
		/* Handle eth0:0 alias devices */
		if (strchr(ifname, ':') != NULL) {
			compat = __ni_redhat_define_alias(sc, ifname, known_devices);
			goto done;
		}

		if ((compat = ni_compat_netdev_new(ifname)) == NULL) {
			ni_error("Failed to alloc interface %s", ifname);
			goto error;
		}
		ni_compat_netdev_array_append(known_devices, compat);
	}

	if (compat == NULL) {
		ni_error("%s: no DEVICE and no HWADDR specified", filename);
		goto error;
	}

	if (compat->identify.hwaddr.len && compat->dev->name) {
		ni_warn("%s: device naming conflict - have both name and Ethernet MAC",
				compat->dev->name);
	}

	if (__ni_redhat_define_interface(sc, compat, known_devices) == FALSE)
		goto error;

done:
	ni_sysconfig_destroy(sc);
	return compat;

error:
	if (sc)
		ni_sysconfig_destroy(sc);
	return NULL;
}

/*
 * Translate the RedHat startmodes to <control> element
 */
static ni_ifworker_control_t *
__ni_redhat_startmode(const char *mode)
{
	static const struct __ni_control_params {
		const char *		name;
		ni_ifworker_control_t	control;
	} __ni_redhat_control_params[] = {
		{ "manual",	{ "manual",	NULL,	FALSE, FALSE, TRUE, 0, 0 } },
		{ "onboot",	{ "auto",	NULL,	FALSE, FALSE, TRUE, 0, 0 } },
		{ NULL }
	};
	const struct __ni_control_params *p;

	for (p = __ni_redhat_control_params; p->name; ++p) {
		if (ni_string_eq(p->name, mode))
			return ni_ifworker_control_clone(&p->control);
	}

	return ni_ifworker_control_clone(&__ni_redhat_control_params[0].control);
}

/*
 * Handle Ethernet devices
 */
static ni_bool_t
try_ethernet(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_ethernet_t *eth;
	const char *value;

	if (strncmp(dev->name, "eth", 3))
		return FALSE;

	dev->link.type = NI_IFTYPE_ETHERNET;
	eth = ni_netdev_get_ethernet(dev);

	if ((value = ni_sysconfig_get_value(sc, "ETHTOOL_OPTS")) != NULL) {
		/* TBD - parse and translate to xml */
		(void) eth;
	}

	return TRUE;
}

/*
 * Bridge devices are recognized by TYPE=Bridge
 */
static ni_bool_t
try_bridge(ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_bridge_t *bridge;
	const char *value;

	/* RedHat has TYPE=Bridge for bridge devices */
	if ((value = ni_sysconfig_get_value(sc, "TYPE")) == NULL || strcasecmp(value, "bridge"))
		return FALSE;

	dev->link.type = NI_IFTYPE_BRIDGE;

	/* Create the interface's bridge data */
	bridge = ni_netdev_get_bridge(dev);
	if ((value = ni_sysconfig_get_value(sc, "STP")) != NULL)
		bridge->stp = strtoul(value, NULL, 0);
	if ((value = ni_sysconfig_get_value(sc, "DELAY")) != NULL)
		bridge->forward_delay = strtoul(value, NULL, 0);

	return TRUE;
}

/*
 * Recognize bridge port. This works a lot like bonding, ie we create
 * the bridge device if it doesn't exist, but do not set its type.
 */
static ni_bool_t
try_bridge_port(ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_compat_netdev_array_t *known_devices)
{
	ni_netdev_t *dev = compat->dev;
	ni_compat_netdev_t *master;
	ni_bridge_t *bridge;
	const char *bridge_name;

	if (!(bridge_name = ni_sysconfig_get_value(sc, "BRIDGE")))
		return FALSE;

	master = ni_compat_netdev_by_name(known_devices, bridge_name);
	if (master == NULL)
		master = ni_compat_netdev_new(bridge_name);
	if (master->dev->link.type == NI_IFTYPE_UNKNOWN) {
		master->dev->link.type = NI_IFTYPE_BRIDGE;
	} else if (master->dev->link.type != NI_IFTYPE_BRIDGE) {
		ni_error("%s: specifies BRIDGE=%s which is not a bonding device",
				dev->name, bridge_name);
		return FALSE;
	}

	bridge = ni_netdev_get_bridge(master->dev);
	ni_bridge_port_new(bridge, dev->name, 0);

	return TRUE;
}

/*
 * See if the device is a bonding slave.
 */
static ni_bool_t
try_bonding_slave(ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_compat_netdev_array_t *known_devices)
{
	ni_netdev_t *dev = compat->dev;
	ni_compat_netdev_t *master;
	ni_bool_t is_slave = 0;
	ni_bonding_t *bonding;
	const char *master_name;

	if (!ni_sysconfig_get_boolean(sc, "SLAVE", &is_slave) || !is_slave)
		return FALSE;

	if (!(master_name = ni_sysconfig_get_value(sc, "MASTER"))) {
		ni_error("%s: slave interface with no MASTER", dev->name);
		return FALSE;
	}

	master = ni_compat_netdev_by_name(known_devices, master_name);
	if (master == NULL) {
		master = ni_compat_netdev_new(master_name);
		master->dev->link.type = NI_IFTYPE_BOND;
	} else if (master->dev->link.type != NI_IFTYPE_BOND) {
		ni_error("%s: specifies MASTER=%s which is not a bonding device", dev->name, master_name);
		return FALSE;
	}

	bonding = ni_netdev_get_bonding(master->dev);
	if (ni_bonding_has_slave(bonding, dev->name))
		return TRUE;
	return ni_bonding_add_slave(bonding, dev->name) != NULL;
}


/*
 * Handle bonding.
 *
 * On Redhat, the master/slave relationship is defined in separate sysconfig files.
 * The slaves have SLAVE=yes MASTER=bondX, whereas the master has just BONDING_OPTS
 */
static ni_bool_t
try_bonding_master(ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_bonding_t *bonding;
	const char *value;

	if (strncmp(dev->name, "bond", 4))
		return FALSE;

	dev->link.type = NI_IFTYPE_BOND;

	bonding = ni_netdev_get_bonding(dev);

	if ((value = ni_sysconfig_get_value(sc, "BONDING_OPTS")) != NULL) {
		/* Parse bonding module options */
		(void) bonding;
	}

	return TRUE;
}

/*
 * Wireless interfaces are recognized by WIRELESS=yes
 */
static ni_bool_t
try_wireless(ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	/* TBD */
	return FALSE;
}

/*
 * VLAN interfaces are recognized by their name (ethM.N)
 */
static ni_bool_t
try_vlan(ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	unsigned int eth_num, vlan_tag;
	ni_vlan_t *vlan;
	ni_bool_t is_vlan = 0;

	if (!ni_sysconfig_get_boolean(sc, "VLAN", &is_vlan) || !is_vlan)
		return FALSE;

	if (sscanf(dev->name, "eth%u.%u", &eth_num, &vlan_tag) != 2) {
		ni_error("%s: not a valid VLAN name", dev->name);
		return FALSE;
	}

	dev->link.type = NI_IFTYPE_VLAN;

	vlan = ni_netdev_get_vlan(dev);
	vlan->tag = vlan_tag;

	if(!ni_string_printf(&dev->link.lowerdev.name, "eth%u", eth_num)) {
		ni_error("%s: unable to allocate VLAN base interface name",
			dev->name);
		free(vlan);
		return FALSE;
	}
	return TRUE;
}

/*
 * Given a suffix like "" or "_1", try to get the IP address and prefix length.
 * If successful, create a new ni_address, attach it to the interface object
 * and return it. 
 */
static ni_bool_t
__ni_redhat_addrconf_static(ni_sysconfig_t *sc, ni_compat_netdev_t *compat, const char *label)
{
	ni_netdev_t *dev = compat->dev;
	ni_sockaddr_t address, netmask;
	unsigned int prefix_len;
	const char *value;
	ni_address_t *ap;

	if ((value = ni_sysconfig_get_value(sc, "IPADDR")) == NULL
	 || ni_sockaddr_parse(&address, value, AF_INET) < 0)
		return FALSE;

	/* Not clear what an empty NETMASK means on RH. Probably default
	 * to IP address class... */
	prefix_len = 24;

	if ((value = ni_sysconfig_get_value(sc, "NETMASK")) != NULL) {
		if (ni_sockaddr_parse(&netmask, value, AF_INET) < 0)
			return FALSE;
		prefix_len = ni_sockaddr_netmask_bits(&netmask);
	}

	if (!(ap = ni_address_new(address.ss_family, prefix_len, &address, &dev->addrs)))
		return FALSE;

	if (label)
		ni_string_dup(&ap->label, label);

	if ((value = ni_sysconfig_get_value(sc, "BROADCAST")) != NULL) {
		if (ni_sockaddr_parse(&ap->bcast_addr, value, AF_INET) < 0)
			return FALSE;
	}

	if ((value = ni_sysconfig_get_value(sc, "GATEWAY")) != NULL) {
		ni_sockaddr_t gateway;

		if (ni_sockaddr_parse(&gateway, value, AF_INET) < 0)
			return FALSE;
		if (ni_route_create(0, NULL, &gateway, 0, &dev->routes) == NULL)
			return FALSE;
	}

	return TRUE;
}

/*
 * DHCP address config
 */
static ni_bool_t
__ni_redhat_addrconf_dhcp(ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	const char *value;

	compat->dhcp4.enabled = TRUE;
	if ((value = ni_sysconfig_get_value(sc, "DHCP_HOSTNAME")) != NULL)
		ni_string_dup(&compat->dhcp4.hostname, value);

	ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_DEFAULT_ROUTE,
				ni_sysconfig_test_boolean(sc, "DEFROUTE"));
	ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_DNS,
				ni_sysconfig_test_boolean(sc, "PEERDNS"));
#if 0
	ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_ROUTES,
			ni_sysconfig_test_boolean(sc, "PEERROUTES"));
#endif

	ni_addrconf_flag_bit_set(&compat->dhcp4.flags, NI_ADDRCONF_FLAGS_OPTIONAL,
			!ni_sysconfig_test_boolean(sc, "IPV4_FAILURE_FATAL"));

	if (ni_sysconfig_test_boolean(sc, "IPV6INIT")) {
#if 0
		if ((value = ni_sysconfig_get_value(sc, "IPV6_AUTOCONF")) != NULL)
			/* TBD */;
#endif

		compat->dhcp6.enabled = TRUE;
		ni_addrconf_update_set(&compat->dhcp6.update, NI_ADDRCONF_UPDATE_DEFAULT_ROUTE,
				ni_sysconfig_test_boolean(sc, "IPV6_DEFROUTE"));
		ni_addrconf_update_set(&compat->dhcp6.update, NI_ADDRCONF_UPDATE_DNS,
				ni_sysconfig_test_boolean(sc, "IPV6_PEERDNS"));
#if 0
		ni_addrconf_update_set(&compat->dhcp6.update, NI_ADDRCONF_UPDATE_ROUTES,
			ni_sysconfig_test_boolean(sc, "IPV6_PEERROUTES"));
#endif

		ni_addrconf_flag_bit_set(&compat->dhcp6.flags, NI_ADDRCONF_FLAGS_OPTIONAL,
				!ni_sysconfig_test_boolean(sc, "IPV6_FAILURE_FATAL"));
	}

	return TRUE;
}

static ni_bool_t
__ni_redhat_define_interface(ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_compat_netdev_array_t *known_devices)
{
	ni_netdev_t *dev = compat->dev;
	const char *value;
	ni_bool_t onboot = 0;

	if (!ni_sysconfig_get_boolean(sc, "ONBOOT", &onboot))
		return FALSE;

	if (onboot)
		compat->control = __ni_redhat_startmode("onboot");
	else
		compat->control = __ni_redhat_startmode("manual");

	ni_sysconfig_get_integer(sc, "MTU", &dev->link.mtu);

	/* HWADDR is used to identify the interface by its MAC address.
	 * MACADDR is used to reconfigure the device's MAC address at runtime
	 */
	if ((value = ni_sysconfig_get_value(sc, "HWADDR")) != NULL
	 && ni_link_address_parse(&compat->identify.hwaddr, ARPHRD_ETHER, value) < 0) {
		ni_warn("cannot parse HWADDR=%s", value);
	}

	if ((value = ni_sysconfig_get_value(sc, "MACADDR")) != NULL
	 && ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, value) < 0) {
		ni_warn("cannot parse MACADDR=%s", value);
	}

	if (dev->link.type == NI_IFTYPE_UNKNOWN
	 && !try_ethernet(sc, compat)
	 && !try_bonding_master(sc, compat)
	 && !try_bridge(sc, compat)
	 && !try_vlan(sc, compat)
	 && !try_wireless(sc, compat)
	 )
		ni_netdev_guess_type(dev);

	try_bonding_slave(sc, compat, known_devices);
	try_bridge_port(sc, compat, known_devices);

	if ((value = ni_sysconfig_get_value(sc, "BOOTPROTO")) != NULL) {
		if (ni_string_eq(value, "dhcp"))
			__ni_redhat_addrconf_dhcp(sc, compat);
		else
			__ni_redhat_addrconf_static(sc, compat, NULL);
	}

	/* FIXME: What to do with these:
		USERCONTROL
	 */

	return TRUE;
}

static ni_compat_netdev_t *
__ni_redhat_define_alias(ni_sysconfig_t *sc, const char *label, ni_compat_netdev_array_t *known_devices)
{
	ni_compat_netdev_t *compat;
	char *ifname, *s;
	const char *value;

	ifname = strdup(label);
	if ((s = strchr(ifname, ':')) == NULL) {
		ni_error("%s: invalid alias \"%s\"", __func__, label);
		return NULL;
	}
	*s++ = '\0';

	compat = ni_compat_netdev_by_name(known_devices, ifname);
	if (compat == NULL) {
		compat = ni_compat_netdev_new(ifname);
		ni_compat_netdev_array_append(known_devices, compat);
	}

	if ((value = ni_sysconfig_get_value(sc, "BOOTPROTO")) != NULL) {
		if (ni_string_eq(value, "dhcp"))
			__ni_redhat_addrconf_dhcp(sc, compat);
		else
			__ni_redhat_addrconf_static(sc, compat, label);
	}

	free(ifname);
	return compat;
}
