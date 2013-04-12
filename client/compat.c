/*
 * Compat functions for parsing traditional config file formats
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#include <wicked/logging.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus.h>
#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/route.h>
#include <wicked/ethernet.h>
#include <wicked/bonding.h>
#include <wicked/bridge.h>
#include <wicked/vlan.h>
#include <wicked/fsm.h>
#include <wicked/xml.h>
#include "wicked-client.h"

/* Helper functions */
static const char *	ni_sprint_uint(unsigned int value);
static const char *	ni_sprint_timeout(unsigned int timeout);
static xml_node_t *	xml_node_create(xml_node_t *, const char *);
static void		xml_node_dict_set(xml_node_t *, const char *, const char *);

ni_bool_t
__ni_compat_get_interfaces(const char *format, const char *path, xml_document_t *doc)
{
	ni_compat_netdev_array_t array = { 0, NULL };
	ni_bool_t rv;

	if (format == NULL) {
		/* Guess what system we're on */
		if (ni_file_exists("/etc/SuSE-release"))
			format = "suse";
		else
		if (ni_file_exists("/etc/redhat-release"))
			format = "redhat";
		else
			ni_fatal("Cannot determine what file format to read");
	}

	/* TBD: add support for more formats */
	if (ni_string_eq(format, "suse"))
		rv = __ni_suse_get_interfaces(path, &array);
	else
	if (ni_string_eq(format, "redhat"))
		rv = __ni_redhat_get_interfaces(path, &array);
	else
		ni_fatal("Unsupported configuration file format %s", format);

	if (rv) {
		unsigned int i;

		for (i = 0; i < array.count; ++i) {
			ni_compat_netdev_t *compat = array.data[i];

			ni_compat_generate_interface(compat, doc);
		}
	}

	ni_compat_netdev_array_destroy(&array);
	return rv;
}

/*
 * Array handling functions
 */
void
ni_compat_netdev_array_append(ni_compat_netdev_array_t *array, ni_compat_netdev_t *compat)
{
	array->data = realloc(array->data, (array->count + 1) * sizeof(array->data[0]));
	array->data[array->count++] = compat;
}

void
ni_compat_netdev_array_destroy(ni_compat_netdev_array_t *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i) {
		ni_compat_netdev_t *compat = array->data[i];

		ni_compat_netdev_free(compat);
	}
	free(array->data);
	memset(array, 0, sizeof(*array));
}

ni_compat_netdev_t *
ni_compat_netdev_by_name(ni_compat_netdev_array_t *array, const char *name)
{
	unsigned int i;

	if (array == NULL || name == NULL)
		return NULL;
	for (i = 0; i < array->count; ++i) {
		ni_compat_netdev_t *compat = array->data[i];

		if (ni_string_eq(name, compat->dev->name))
			return compat;
	}
	return NULL;
}

ni_compat_netdev_t *
ni_compat_netdev_by_hwaddr(ni_compat_netdev_array_t *array, const ni_hwaddr_t *hwaddr)
{
	unsigned int i;

	if (array == NULL || hwaddr == NULL || hwaddr->type == 0)
		return NULL;
	for (i = 0; i < array->count; ++i) {
		ni_compat_netdev_t *compat = array->data[i];

		if (ni_link_address_equal(hwaddr, &compat->identify.hwaddr))
			return compat;
	}
	return NULL;
}

void
ni_compat_netdev_free(ni_compat_netdev_t *compat)
{
	ni_netdev_put(compat->dev);

	/* FIXME: clean up the rest */

	free(compat);
}

/*
 * Functions for generating XML
 */
static ni_bool_t
__ni_compat_generate_ethernet(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	const ni_netdev_t *dev = compat->dev;
	xml_node_t *child;

	child = xml_node_new("ethernet", ifnode);
	if (dev->link.hwaddr.len)
		xml_node_new_element("address", child, ni_link_address_print(&dev->link.hwaddr));

	/* generate offload and other information */

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_bonding(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	ni_bonding_t *bond;
	xml_node_t *child, *slaves, *slave;
	unsigned int i;
	int verbose = 0; /* do not supress defaults */

	bond = ni_netdev_get_bonding(compat->dev);
	child = xml_node_create(ifnode, "bond");

	xml_node_new_element("mode", child,
			ni_bonding_mode_type_to_name(bond->mode));

	if (bond->monitoring == NI_BOND_MONITOR_ARP) {
		xml_node_t *arpmon;
		xml_node_t *targets;

		arpmon = xml_node_create(child, "arpmon");
		xml_node_new_element("interval", arpmon,
				ni_sprint_uint(bond->arpmon.interval));
		xml_node_new_element("validate", arpmon,
				ni_bonding_arp_validate_type_to_name(bond->arpmon.validate));

		targets = xml_node_create(arpmon, "targets");
		for (i = 0; i < bond->arpmon.targets.count; ++i) {
			xml_node_new_element("ipv4-address", targets,
					bond->arpmon.targets.data[i]);
		}
	} else
	if (bond->monitoring == NI_BOND_MONITOR_MII) {
		xml_node_t *miimon;

		miimon = xml_node_create(child, "miimon");
		xml_node_new_element("frequency", miimon,
			ni_sprint_uint(bond->miimon.frequency));
		if (verbose || bond->miimon.updelay) {
			xml_node_new_element("updelay", miimon,
				ni_sprint_uint(bond->miimon.updelay));
		}
		if (verbose || bond->miimon.downdelay) {
			xml_node_new_element("downdelay", miimon,
				ni_sprint_uint(bond->miimon.downdelay));
		}
		xml_node_new_element("carrier", miimon,
			ni_bonding_mii_carrier_detect_name(bond->miimon.carrier_detect));
	}

	slaves = xml_node_create(child, "slaves");
	for (i = 0; i < bond->slave_names.count; ++i) {
		const char *slave_name = bond->slave_names.data[i];

		slave = xml_node_new("slave", slaves);
		xml_node_new_element("device", slave, slave_name);

		switch (bond->mode) {
		case NI_BOND_MODE_ACTIVE_BACKUP:
		case NI_BOND_MODE_BALANCE_TLB:
		case NI_BOND_MODE_BALANCE_ALB:
			if (ni_string_eq(bond->primary_slave, slave_name)) {
				xml_node_new_element("primary", slave, "true");
			}
			if (ni_string_eq(bond->active_slave, slave_name)) {
				xml_node_new_element("active", slave, "true");
			}
		default:
			break;
		}
	}

	switch (bond->mode) {
	case NI_BOND_MODE_802_3AD:
	case NI_BOND_MODE_BALANCE_XOR:
		if (verbose || bond->xmit_hash_policy) {
			xml_node_new_element("xmit-hash-policy", child,
				ni_bonding_xmit_hash_policy_to_name(bond->xmit_hash_policy));
		}
	default:
		break;
	}

	if (bond->mode == NI_BOND_MODE_802_3AD) {
		if (verbose || bond->lacp_rate) {
			xml_node_new_element("lacp-rate", child,
				ni_bonding_lacp_rate_name(bond->lacp_rate));
		}
		if (verbose || bond->ad_select) {
			xml_node_new_element("ad-select", child,
				ni_bonding_ad_select_name(bond->ad_select));
		}
		if (verbose || bond->min_links > 0) {
			xml_node_new_element("min-links", child,
					ni_sprint_uint(bond->min_links));
		}
	}

	if (bond->mode == NI_BOND_MODE_ACTIVE_BACKUP) {
		if (verbose || bond->primary_reselect) {
			xml_node_new_element("primary-reselect", child,
				ni_bonding_primary_reselect_name(bond->primary_reselect));
		}
		if (verbose || bond->fail_over_mac) {
			xml_node_new_element("fail-over-mac", child,
				ni_bonding_fail_over_mac_name(bond->fail_over_mac));
		}
		if (verbose || bond->num_grat_arp != 1) {
			xml_node_new_element("num-grat-arp", child,
				ni_sprint_uint(bond->num_grat_arp));
		}
		if (verbose || bond->num_unsol_na != 1) {
			xml_node_new_element("num-unsol-na", child,
				ni_sprint_uint(bond->num_unsol_na));
		}
	}

	switch (bond->mode) {
	case NI_BOND_MODE_ACTIVE_BACKUP:
	case NI_BOND_MODE_BALANCE_RR:
	case NI_BOND_MODE_BALANCE_TLB:
	case NI_BOND_MODE_BALANCE_ALB:
		if (verbose || bond->resend_igmp != 1) {
			xml_node_new_element("resend-igmp", child,
				ni_sprint_uint(bond->resend_igmp));
		}
	default:
		break;
	}

	if (verbose || bond->all_slaves_active) {
		xml_node_new_element("all-slaves-active", child,
			(bond->all_slaves_active ? "true" : "false"));
	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_bridge(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	ni_bridge_t *bridge;
	xml_node_t *child;
	unsigned int i;

	bridge = ni_netdev_get_bridge(compat->dev);

	child = xml_node_create(ifnode, "brigde");

	switch (bridge->stp) {
	case 0:
		xml_node_new_element("stp", child, "off");
		break;
	case 1:
		xml_node_new_element("stp", child, "on");
		break;
	default:
		xml_node_new_element("stp", child, ni_sprint_uint(bridge->stp));
		break;
	}

	if (bridge->forward_delay != NI_BRIDGE_VALUE_NOT_SET)
		xml_node_new_element("forward-delay", child, ni_sprint_uint(bridge->forward_delay));
	if (bridge->ageing_time != NI_BRIDGE_VALUE_NOT_SET)
		xml_node_new_element("aging-time", child, ni_sprint_uint(bridge->ageing_time));
	if (bridge->hello_time != NI_BRIDGE_VALUE_NOT_SET)
		xml_node_new_element("hello-time", child, ni_sprint_uint(bridge->hello_time));
	if (bridge->max_age != NI_BRIDGE_VALUE_NOT_SET)
		xml_node_new_element("max-age", child, ni_sprint_uint(bridge->max_age));
	if (bridge->priority != NI_BRIDGE_VALUE_NOT_SET)
		xml_node_new_element("priority", child, ni_sprint_uint(bridge->priority));

	for (i = 0; i < bridge->ports.count; ++i) {
		const ni_bridge_port_t *port = bridge->ports.data[i];
		xml_node_t *portnode = xml_node_new("port", child);

		xml_node_new_element("device", portnode, port->ifname);
		if (port->priority != NI_BRIDGE_VALUE_NOT_SET)
			xml_node_new_element("priority", portnode, ni_sprint_uint(port->priority));
		if (port->path_cost != NI_BRIDGE_VALUE_NOT_SET)
			xml_node_new_element("path-cost", portnode, ni_sprint_uint(port->path_cost));
	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_vlan(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	ni_vlan_t *vlan;
	xml_node_t *child;

	vlan = ni_netdev_get_vlan(compat->dev);

	child = xml_node_create(ifnode, "vlan");

	xml_node_new_element("device", child, vlan->physdev_name);
	xml_node_new_element("tag", child, ni_sprint_uint(vlan->tag));
	return TRUE;
}

static ni_bool_t
__ni_compat_generate_wireless(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	ni_wireless_t *wireless;
	xml_node_t *child;

	wireless = ni_netdev_get_wireless(compat->dev);

	child = xml_node_create(ifnode, "wireless");

	/* TBD */
	(void) child;
	(void) wireless;
	return TRUE;
}

void
__ni_compat_generate_static_route(xml_node_t *aconf, const ni_route_t *rp)
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

		if (nh->gateway.ss_family != AF_UNSPEC) {
			nhnode = xml_node_new("nexthop", rnode);
			xml_node_new_element("gateway", nhnode,
				ni_sockaddr_print(&nh->gateway));
		}
	}
}

static xml_node_t *
__ni_compat_generate_static_address_list(xml_node_t *ifnode, ni_address_t *addr_list, int af)
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
			xml_node_new_element("peer", anode, ni_sockaddr_print(&ap->peer_addr));
		if (ap->bcast_addr.ss_family != AF_UNSPEC)
			xml_node_new_element("broadcast", anode, ni_sockaddr_print(&ap->bcast_addr));
		if (ap->label)
			xml_node_new_element("label", anode, ap->label);
	}

	return aconf;
}

xml_node_t *
__ni_compat_generate_static_addrconf(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	const ni_netdev_t *dev = compat->dev;
	xml_node_t *aconf;

	if ((aconf = __ni_compat_generate_static_address_list(ifnode, dev->addrs, AF_INET)) != NULL) {
		const ni_route_t *rp;

		for (rp = dev->routes; rp; rp = rp->next) {
			if (rp->family == AF_INET)
				__ni_compat_generate_static_route(aconf, rp);
		}
	}

	if ((aconf = __ni_compat_generate_static_address_list(ifnode, dev->addrs, AF_INET6)) != NULL) {
		const ni_route_t *rp;

		for (rp = dev->routes; rp; rp = rp->next) {
			if (rp->family == AF_INET6)
				__ni_compat_generate_static_route(aconf, rp);
		}
	}

	return aconf;
}

static xml_node_t *
__ni_compat_generate_dynamic_addrconf(xml_node_t *ifnode, const char *name, ni_bool_t required, unsigned int update)
{
	xml_node_t *aconf;

	aconf = xml_node_new(name, ifnode);
	xml_node_new_element("enabled", aconf, "true");

	if (!required)
		xml_node_new_element("optional", aconf, "true");

	if (update) {
		xml_node_t *child = xml_node_new("update", aconf);
		unsigned int i;

		for (i = 0; update != 0; ++i, update >>= 1) {
			if (update & 1) {
				const char *key = ni_addrconf_update_target_to_name(i);

				if (key)
					xml_node_new(key, child);
			}
		}
	}

	return aconf;
}

static xml_node_t *
__ni_compat_generate_dhcp4_addrconf(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *dhcp;

	if (!compat->dhcp4.enabled)
		return NULL;

	dhcp = __ni_compat_generate_dynamic_addrconf(ifnode, "ipv4:dhcp", compat->dhcp4.required, compat->dhcp4.update);

	if (compat->dhcp4.hostname)
		xml_node_dict_set(dhcp, "hostname", compat->dhcp4.hostname);

	if (compat->dhcp4.acquire_timeout)
		xml_node_dict_set(dhcp, "acquire-timeout",
				ni_sprint_timeout(compat->dhcp4.acquire_timeout));
	if (compat->dhcp4.lease_time)
		xml_node_dict_set(dhcp, "lease-time",
				ni_sprint_timeout(compat->dhcp4.lease_time));

	if (compat->dhcp4.client_id)
		xml_node_dict_set(dhcp, "client-id", compat->dhcp4.client_id);
	if (compat->dhcp4.vendor_class)
		xml_node_dict_set(dhcp, "vendor-class", compat->dhcp4.vendor_class);

	/* Ignored for now:
	   DHCLIENT_USE_LAST_LEASE
	   WRITE_HOSTNAME_TO_HOSTS
	   DHCLIENT_MODIFY_SMB_CONF
	   DHCLIENT_SET_HOSTNAME
	   DHCLIENT_SET_DEFAULT_ROUTE
	 */

	return dhcp;
}

static xml_node_t *
__ni_compat_generate_dhcp6_addrconf(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *dhcp;

	if (!compat->dhcp4.enabled)
		return NULL;

	dhcp = __ni_compat_generate_dynamic_addrconf(ifnode, "ipv6:dhcp", compat->dhcp6.required, compat->dhcp6.update);
	return dhcp;
}


ni_bool_t
__ni_compat_generate_interface(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	const ni_netdev_t *dev = compat->dev;
	xml_node_t *linknode;

	if (compat->control) {
		const ni_ifworker_control_t *control = compat->control;
		xml_node_t *child, *linkdet;

		child = xml_node_create(ifnode, "control");
		if (control->mode)
			xml_node_new_element("mode", child, control->mode);
		if (control->boot_stage)
			xml_node_new_element("boot-stage", child, control->boot_stage);

		if (control->link_timeout || control->link_required) {
			linkdet = xml_node_create(child, "link-detection");
			if (control->link_timeout)
				xml_node_new_element("timeout", linkdet,
						ni_sprint_timeout(control->link_timeout));
			if (control->link_required)
				(void) xml_node_new("require-link", linkdet);
		}
	}

	switch (dev->link.type) {
	case NI_IFTYPE_ETHERNET:
		__ni_compat_generate_ethernet(ifnode, compat);
		break;

	case NI_IFTYPE_BOND:
		__ni_compat_generate_bonding(ifnode, compat);
		break;

	case NI_IFTYPE_BRIDGE:
		__ni_compat_generate_bridge(ifnode, compat);
		break;

	case NI_IFTYPE_VLAN:
		__ni_compat_generate_vlan(ifnode, compat);
		break;

	case NI_IFTYPE_WIRELESS:
		__ni_compat_generate_wireless(ifnode, compat);
		break;

	default: ;
	}

	linknode = xml_node_new("link", ifnode);
	if (dev->link.mtu)
		xml_node_new_element("mtu", linknode, ni_sprint_uint(dev->link.mtu));

	__ni_compat_generate_static_addrconf(ifnode, compat);

	__ni_compat_generate_dhcp4_addrconf(ifnode, compat);
	__ni_compat_generate_dhcp6_addrconf(ifnode, compat);

	return TRUE;
}

xml_node_t *
ni_compat_generate_interface(const ni_compat_netdev_t *compat, xml_document_t *doc)
{
	xml_node_t *ifnode, *namenode;

	ifnode = xml_node_new("interface", doc->root);

	namenode = xml_node_new("name", ifnode);
	if (compat->identify.hwaddr.type == NI_IFTYPE_ETHERNET) {
		xml_node_add_attr(namenode, "namespace", "ethernet");
		xml_node_new_element("permanent-address", namenode,
				ni_link_address_print(&compat->identify.hwaddr));
	} else {
		xml_node_set_cdata(namenode, compat->dev->name);
	}

	__ni_compat_generate_interface(ifnode, compat);
	return ifnode;
}

/*
 * XML helper functions
 */
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

static const char *
ni_sprint_timeout(unsigned int timeout)
{
	if (timeout == NI_IFWORKER_INFINITE_TIMEOUT)
		return "infinite";
	return ni_sprint_uint(timeout);
}

