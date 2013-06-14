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
#include <wicked/infiniband.h>
#include <wicked/bonding.h>
#include <wicked/bridge.h>
#include <wicked/vlan.h>
#include <wicked/fsm.h>
#include <wicked/xml.h>
#include "wicked-client.h"
#include <netlink/netlink.h>


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
__ni_compat_generate_infiniband(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	ni_infiniband_t *ib = ni_netdev_get_infiniband(compat->dev);
	xml_node_t *child;
	const char *value;
	char *pkey = NULL;

	switch (compat->dev->link.type) {
	case NI_IFTYPE_INFINIBAND:
		value = "infiniband";
		break;
	case NI_IFTYPE_INFINIBAND_CHILD:
		value = "infiniband-child";
		break;
	default:
		return FALSE;
	}
	if (!(child = xml_node_new(value, ifnode)))
		return FALSE;

	if ((value = ni_infiniband_get_mode_name(ib->mode)))
		xml_node_new_element("mode", child, value);

	if ((value = ni_infiniband_get_umcast_name(ib->umcast)))
		xml_node_new_element("multicast", child, value);

	if (ib->parent.name) {
		if (!ni_string_printf(&pkey, "0x%04x", ib->pkey))
			return FALSE;

		xml_node_new_element("parent", child, ib->parent.name);
		xml_node_new_element("pkey",   child, pkey);
		ni_string_free(&pkey);
	}

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
	xml_node_t *ports;
	unsigned int i;
	char *tmp = NULL;

	bridge = ni_netdev_get_bridge(compat->dev);

	child = xml_node_create(ifnode, "bridge");

	xml_node_new_element("stp", child, bridge->stp ? "true" : "false");
	if (bridge->priority != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_string_printf(&tmp, "%u", bridge->priority)) {
		xml_node_new_element("priority", child, tmp);
		ni_string_free(&tmp);
	}

	if (bridge->forward_delay != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_string_printf(&tmp, "%.2f", bridge->forward_delay)) {
		xml_node_new_element("forward-delay", child, tmp);
		ni_string_free(&tmp);
	}
	if (bridge->ageing_time != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_string_printf(&tmp, "%.2f", bridge->ageing_time)) {
		xml_node_new_element("aging-time", child, tmp);
		ni_string_free(&tmp);
	}
	if (bridge->hello_time != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_string_printf(&tmp, "%.2f", bridge->hello_time)) {
		xml_node_new_element("hello-time", child, tmp);
		ni_string_free(&tmp);
	}
	if (bridge->max_age != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_string_printf(&tmp, "%.2f", bridge->max_age)) {
		xml_node_new_element("max-age", child, tmp);
		ni_string_free(&tmp);
	}

	ports = xml_node_new("ports", child);
	for (i = 0; i < bridge->ports.count; ++i) {
		const ni_bridge_port_t *port = bridge->ports.data[i];
		xml_node_t *portnode = xml_node_new("port", ports);

		xml_node_new_element("device", portnode, port->ifname);
		if (port->priority != NI_BRIDGE_VALUE_NOT_SET &&
		    ni_string_printf(&tmp, "%u", port->priority)) {
			xml_node_new_element("priority", portnode, tmp);
			ni_string_free(&tmp);
		}
		if (port->path_cost != NI_BRIDGE_VALUE_NOT_SET &&
		    ni_string_printf(&tmp, "%u", port->path_cost)) {
			xml_node_new_element("path-cost", portnode, tmp);
			ni_string_free(&tmp);
		}
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

	xml_node_new_element("device", child, vlan->parent.name);
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

static void
__ni_compat_generate_static_route_hops(xml_node_t *rnode, const ni_route_nexthop_t *hops,
					const char *ifname)
{
	const ni_route_nexthop_t *nh;

	for (nh = hops; nh; nh = nh->next) {
		xml_node_t *nhnode;

		if (nh->gateway.ss_family == AF_UNSPEC && !nh->device.name)
			continue;

		nhnode = xml_node_new("nexthop", rnode);
		if (nh->gateway.ss_family != AF_UNSPEC) {
			xml_node_new_element("gateway", nhnode,
				ni_sockaddr_print(&nh->gateway));
		}
		if (nh->device.name && !ni_string_eq(ifname, nh->device.name)) {
			xml_node_new_element("device", nhnode, nh->device.name);
		} else if (ifname) {
			xml_node_new_element("device", nhnode, ifname);
		}
		if (!hops->next)
			continue;

		if (nh->weight > 0) {
			xml_node_new_element("weight", nhnode,
					ni_sprint_uint(nh->weight));
		}
		if (nh->realm > 0) {
			/* Hmm.. */
			xml_node_new_element("realm", nhnode,
					ni_sprint_uint(nh->realm));
		}
		if (nh->flags > 0) {
			ni_string_array_t names = NI_STRING_ARRAY_INIT;
			xml_node_t *fnode = NULL;
			unsigned int i;

			ni_route_nh_flags_get_names(nh->flags, &names);
			for (i = 0; i < names.count; ++i) {
				if (fnode == NULL)
					fnode = xml_node_new("flags", nhnode);
				xml_node_new(names.data[i], fnode);
			}
		}
	}
}

void
__ni_compat_generate_static_route_metrics(xml_node_t *mnode, const ni_route_t *rp)
{
	ni_string_array_t names = NI_STRING_ARRAY_INIT;
	xml_node_t *lnode = NULL;
	unsigned int i;

	ni_route_metrics_lock_get_names(rp->lock, &names);
	for (i = 0; i < names.count; ++i) {
		if (lnode == NULL)
			lnode = xml_node_new("lock", mnode);
		xml_node_new(names.data[i], lnode);
	}
	if (rp->mtu > 0) {
		xml_node_new_element("mtu", mnode, ni_sprint_uint(rp->mtu));
	}
	if (rp->window > 0) {
		xml_node_new_element("window", mnode, ni_sprint_uint(rp->window));
	}
	if (rp->rtt > 0) {
		xml_node_new_element("rtt", mnode, ni_sprint_uint(rp->rtt));
	}
	if (rp->rttvar > 0) {
		xml_node_new_element("rttvar", mnode, ni_sprint_uint(rp->rttvar));
	}
	if (rp->ssthresh > 0) {
		xml_node_new_element("ssthresh", mnode, ni_sprint_uint(rp->ssthresh));
	}
	if (rp->cwnd > 0) {
		xml_node_new_element("cwnd", mnode, ni_sprint_uint(rp->cwnd));
	}
	if (rp->advmss > 0) {
		xml_node_new_element("advmss", mnode, ni_sprint_uint(rp->advmss));
	}
	if (rp->reordering > 0) {
		xml_node_new_element("reordering", mnode, ni_sprint_uint(rp->reordering));
	}
	if (rp->hoplimit > 0) {
		xml_node_new_element("hoplimit", mnode, ni_sprint_uint(rp->hoplimit));
	}
	if (rp->initcwnd > 0) {
		xml_node_new_element("initcwnd", mnode, ni_sprint_uint(rp->initcwnd));
	}
	if (rp->features > 0) {
		xml_node_new_element("features", mnode, ni_sprint_uint(rp->features));
	}
	if (rp->rto_min > 0) {
		xml_node_new_element("rto-min", mnode, ni_sprint_uint(rp->rto_min));
	}
	if (rp->initrwnd > 0) {
		xml_node_new_element("initrwnd", mnode, ni_sprint_uint(rp->initrwnd));
	}
}

void
__ni_compat_generate_static_route(xml_node_t *aconf, const ni_route_t *rp, const char *ifname)
{
	xml_node_t *rnode, *mnode, *knode;
	char *tmp = NULL;
	const char *ptr;

	rnode = xml_node_new("route", aconf);

	if (rp->destination.ss_family != AF_UNSPEC && rp->prefixlen != 0) {
		xml_node_new_element("destination", rnode,
			ni_sockaddr_prefix_print(&rp->destination, rp->prefixlen));
	}

	__ni_compat_generate_static_route_hops(rnode, &rp->nh, ifname);

	knode = NULL;
	if (rp->table != RT_TABLE_UNSPEC && rp->table != RT_TABLE_MAIN) {
		if (!(ptr = ni_route_table_type_to_name(rp->table)))
			ptr = ni_sprint_uint(rp->table);
		if (knode == NULL)
			knode = xml_node_new("kern", rnode);
		xml_node_new_element("table", knode, ptr);
	}
	if (rp->type != RTN_UNSPEC && rp->type != RTN_UNICAST) {
		if (!(ptr = ni_route_type_type_to_name(rp->type)))
			ptr = ni_sprint_uint(rp->type);
		if (knode == NULL)
			knode = xml_node_new("kern", rnode);
		xml_node_new_element("type", knode, ptr);
	}
	if (rp->scope != RT_SCOPE_UNIVERSE) {
		if (!(ptr = ni_route_scope_type_to_name(rp->scope)))
			ptr = ni_sprint_uint(rp->scope);
		if (knode == NULL)
			knode = xml_node_new("kern", rnode);
		xml_node_new_element("scope", knode, ptr);
	}
	if (rp->protocol != RTPROT_UNSPEC && rp->protocol != RTPROT_BOOT) {
		if (!(ptr = ni_route_protocol_type_to_name(rp->protocol)))
			ptr = ni_sprint_uint(rp->protocol);
		if (knode == NULL)
			knode = xml_node_new("kern", rnode);
		xml_node_new_element("protocol", knode, ptr);
	}

	if (rp->priority > 0) {
		xml_node_new_element("priority", rnode, ni_sprint_uint(rp->priority));
	}
	if (ni_sockaddr_is_specified(&rp->pref_src)) {
		xml_node_new_element("source", rnode, ni_sockaddr_print(&rp->pref_src));
	}
	if (rp->realm > 0) {
		/* Hmm */
		xml_node_new_element("realm", rnode, ni_sprint_uint(rp->realm));
	}
	if (rp->mark > 0 && ni_string_printf(&tmp, "0x%02x", rp->mark)) {
		xml_node_new_element("mark", rnode, tmp);
		ni_string_free(&tmp);
	}
	if (rp->flags > 0) {
		ni_string_array_t names = NI_STRING_ARRAY_INIT;
		xml_node_t *fnode = NULL;
		unsigned int i;

		ni_route_flags_get_names(rp->flags, &names);
		for (i = 0; i < names.count; ++i) {
			if (fnode == NULL)
				fnode = xml_node_new("flags", rnode);
			xml_node_new(names.data[i], fnode);
		}
	}
	if (rp->tos > 0 && ni_string_printf(&tmp, "0x%02x", rp->tos)) {
		xml_node_new_element("tos", rnode, tmp);
		ni_string_free(&tmp);
	}

	mnode = xml_node_new("metrics", NULL);
	__ni_compat_generate_static_route_metrics(mnode, rp);
	if (mnode->children || mnode->attrs.count || mnode->cdata)
		xml_node_add_child(rnode, mnode);
	else
		xml_node_free(mnode);
}

static xml_node_t *
__ni_compat_generate_static_address_list(xml_node_t *ifnode, ni_address_t *addr_list, unsigned int af)
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
	const ni_route_table_t *tab;
	const ni_route_t *rp;
	unsigned int i;
	xml_node_t *aconf;

	if ((aconf = __ni_compat_generate_static_address_list(ifnode, dev->addrs, AF_INET)) != NULL) {
		for (tab = dev->routes; tab; tab = tab->next) {
			for (i = 0; i < tab->routes.count; ++i) {
				rp = tab->routes.data[i];

				if( !rp || rp->family != AF_INET)
					continue;

				__ni_compat_generate_static_route(aconf, rp, dev->name);
			}
		}
	}

	if ((aconf = __ni_compat_generate_static_address_list(ifnode, dev->addrs, AF_INET6)) != NULL) {
		for (tab = dev->routes; tab; tab = tab->next) {
			for (i = 0; i < tab->routes.count; ++i) {
				rp = tab->routes.data[i];

				if( !rp || rp->family != AF_INET)
					continue;

				__ni_compat_generate_static_route(aconf, rp, dev->name);
			}
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

	case NI_IFTYPE_INFINIBAND:
	case NI_IFTYPE_INFINIBAND_CHILD:
		__ni_compat_generate_infiniband(ifnode, compat);
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

