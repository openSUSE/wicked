/*
 *	Compat functions for parsing traditional config file formats
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
 *		Marius Tomaschewski <mt@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 */
#include <net/if_arp.h>
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
#include <wicked/macvlan.h>
#include <wicked/tuntap.h>
#include <wicked/tunneling.h>
#include <wicked/wireless.h>
#include <wicked/fsm.h>
#include <wicked/xml.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/util.h>
#include "wicked-client.h"
#include <netlink/netlink.h>
#include <sys/param.h>

#include "client/client_state.h"
#include "appconfig.h"
#include "util_priv.h"

/*
 * Compat ifconfig handling functions
 */
void
ni_compat_ifconfig_init(ni_compat_ifconfig_t *conf)
{
	memset(conf, 0, sizeof(*conf));
}

void
ni_compat_ifconfig_destroy(ni_compat_ifconfig_t *conf)
{
	if (conf) {
		ni_compat_netdev_array_destroy(&conf->netdevs);
	}
}

/*
 * Compat netdev handling functions
 */
void
ni_compat_netdev_array_init(ni_compat_netdev_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_compat_netdev_array_append(ni_compat_netdev_array_t *array, ni_compat_netdev_t *compat)
{
	ni_assert(array && compat);
	array->data = xrealloc(array->data, (array->count + 1) * sizeof(array->data[0]));
	array->data[array->count++] = compat;
}

void
ni_compat_netdev_array_destroy(ni_compat_netdev_array_t *array)
{
	unsigned int i;

	ni_assert(array);
	for (i = 0; i < array->count; ++i) {
		ni_compat_netdev_t *compat = array->data[i];

		ni_compat_netdev_free(compat);
	}
	free(array->data);
	memset(array, 0, sizeof(*array));
}

/*
 * Compat netdev functions
 */
ni_compat_netdev_t *
ni_compat_netdev_new(const char *ifname)
{
	ni_compat_netdev_t *compat;

	compat = xcalloc(1, sizeof(*compat));
	compat->dev = ni_netdev_new(ifname, 0);

	/* Apply defaults */
	compat->dhcp4.update = ni_config_addrconf_update_mask(NI_ADDRCONF_DHCP, AF_INET);
	compat->dhcp4.recover_lease = TRUE;
	compat->dhcp4.release_lease = FALSE;
	compat->dhcp4.user_class.format = -1U;

	compat->dhcp6.update = ni_config_addrconf_update_mask(NI_ADDRCONF_DHCP, AF_INET6);
	compat->dhcp6.mode = NI_DHCP6_MODE_AUTO;
	compat->dhcp6.rapid_commit = TRUE;
	compat->dhcp6.recover_lease = TRUE;
	compat->dhcp6.release_lease = FALSE;

	return compat;
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

	if (array == NULL || hwaddr == NULL || hwaddr->len == 0)
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
	if (compat) {
		if (compat->dev)
			ni_netdev_put(compat->dev);
		ni_ifworker_control_free(compat->control);

		ni_string_free(&compat->dhcp4.hostname);
		ni_string_free(&compat->dhcp4.client_id);
		ni_string_free(&compat->dhcp4.vendor_class);
		ni_string_array_destroy(&compat->dhcp4.user_class.class_id);

		ni_string_free(&compat->dhcp6.hostname);
		ni_string_free(&compat->dhcp6.client_id);

		free(compat);
	}
}

void
ni_compat_netdev_client_state_set(ni_netdev_t *dev, const char *filename)
{
	ni_client_state_t *cs;

	if (!dev)
		return;

	cs = ni_netdev_get_client_state(dev);
	ni_ifconfig_metadata_generate(&cs->config, "compat", filename);
}

/*
 * Functions for generating XML
 */
static void
__ni_compat_optional_tristate(const char *name, xml_node_t *node, ni_tristate_t flag)
{
	if (ni_tristate_is_set(flag)) {
		xml_node_new_element(name, node, ni_tristate_to_name(flag));
	}
}

static void
__ni_compat_generate_eth_offload_node(xml_node_t *parent, const ni_ethtool_offload_t *offload)
{
	xml_node_t *node;

	if (!parent || !offload)
		return;

	/* generate offload and other information */
	node = xml_node_new("offload", NULL);

	__ni_compat_optional_tristate("rx-csum", node, offload->rx_csum);
	__ni_compat_optional_tristate("tx-csum", node, offload->tx_csum);
	__ni_compat_optional_tristate("scatter-gather", node, offload->scatter_gather);
	__ni_compat_optional_tristate("tso", node, offload->tso);
	__ni_compat_optional_tristate("ufo", node, offload->ufo);
	__ni_compat_optional_tristate("gso", node, offload->gso);
	__ni_compat_optional_tristate("gro", node, offload->gro);
	__ni_compat_optional_tristate("lro", node, offload->lro);

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);

}

static void
__ni_compat_generate_eth_node(xml_node_t *child, const ni_ethernet_t *eth)
{
	const char *ptr;

	/* generate common <ethernet> node settings */
	if (eth->link_speed) {
		xml_node_new_element_uint("link-speed", child, eth->link_speed);
	}
	if (eth->port_type != NI_ETHERNET_PORT_DEFAULT &&
	    (ptr = ni_ethernet_port_type_to_name(eth->port_type))) {
		xml_node_new_element("port-type", child, ptr);
	}
	if (eth->duplex == NI_ETHERNET_DUPLEX_HALF) {
		xml_node_new_element("duplex", child, "half");
	} else
	if (eth->duplex == NI_ETHERNET_DUPLEX_FULL) {
		xml_node_new_element("duplex", child, "full");
	}
	__ni_compat_optional_tristate("autoneg-enable", child, eth->autoneg_enable);

	if (eth->wol.options != __NI_ETHERNET_WOL_DEFAULT) {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
		xml_node_t *wol = xml_node_new("wake-on-lan", NULL);

		ni_ethernet_wol_options_format(&buf, eth->wol.options, "|");
		xml_node_new_element("options", wol, buf.string);
		ni_stringbuf_destroy(&buf);

		if (eth->wol.options & (1<<NI_ETHERNET_WOL_SECUREON)
				&& eth->wol.sopass.len) {
			xml_node_new_element("sopass", wol,
					ni_link_address_print(&eth->wol.sopass));
		}

		if (wol->children)
			xml_node_add_child(child, wol);
		else
			xml_node_free(wol);
	}

	__ni_compat_generate_eth_offload_node(child, &eth->offload);
}

static ni_bool_t
__ni_compat_generate_ethernet(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	const ni_netdev_t *dev = compat->dev;
	xml_node_t *child;

	child = xml_node_new("ethernet", ifnode);
	if (dev->link.hwaddr.len) {
		xml_node_new_element("address", child,
			ni_link_address_print(&dev->link.hwaddr));
	}

	if (dev->ethernet) {
		__ni_compat_generate_eth_node(child, dev->ethernet);
	}
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
		value = "infiniband:child";
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

	if (compat->dev->link.lowerdev.name) {
		if (!ni_string_printf(&pkey, "0x%04x", ib->pkey))
			return FALSE;

		xml_node_new_element("device", child, compat->dev->link.lowerdev.name);
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
		if (bond->arpmon.validate != NI_BOND_ARP_VALIDATE_NONE) {
			xml_node_new_element("validate-targets", arpmon,
				ni_bonding_arp_validate_targets_to_name(bond->arpmon.validate_targets));
		}
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
		break;
	case NI_BOND_MODE_BALANCE_RR:
		if (verbose || bond->packets_per_slave != 1) {
			xml_node_new_element("packets-per-slave", child,
					ni_sprint_uint(bond->packets_per_slave));
		}
		break;
	case NI_BOND_MODE_BALANCE_TLB:
		if (verbose || !bond->tlb_dynamic_lb) {
			xml_node_new_element("tlb-dynamic-lb", child,
					(bond->tlb_dynamic_lb ? "true" : "false"));
		}
		break;
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
	case NI_BOND_MODE_BALANCE_TLB:
	case NI_BOND_MODE_BALANCE_ALB:
		if (verbose || bond->lp_interval != 1) {
			xml_node_new_element("lp-interval", child,
				ni_sprint_uint(bond->lp_interval));
		}
		break;
	default:
		break;
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

	xml_node_new_element("device", child, compat->dev->link.lowerdev.name);
	if (compat->dev->link.hwaddr.len) {
		xml_node_new_element("address", child,
			ni_link_address_print(&compat->dev->link.hwaddr));
	}
	xml_node_new_element("protocol", child, ni_vlan_protocol_to_name(vlan->protocol));
	xml_node_new_element("tag", child, ni_sprint_uint(vlan->tag));
	return TRUE;
}

static ni_bool_t
__ni_compat_generate_macvlan(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	ni_macvlan_t *macvlan;
	xml_node_t *child;

	macvlan = ni_netdev_get_macvlan(compat->dev);

	/* Will create either <macvlan> or <macvtap> node. */
	child = xml_node_create(ifnode,
				ni_linktype_type_to_name(compat->dev->link.type));

	xml_node_new_element("device", child, compat->dev->link.lowerdev.name);
	if (compat->dev->link.hwaddr.len) {
		xml_node_new_element("address", child,
				ni_link_address_print(&compat->dev->link.hwaddr));
	}
	xml_node_new_element("mode", child, ni_macvlan_mode_to_name(macvlan->mode));
	if (macvlan->flags) {
		ni_string_array_t names = NI_STRING_ARRAY_INIT;
		xml_node_t *flags = NULL;
		unsigned int i;

		ni_macvlan_flags_to_names(macvlan->flags, &names);
		for (i = 0; i < names.count; ++i) {
			if (flags == NULL)
				flags = xml_node_new("flags", child);
			xml_node_new(names.data[i], flags);
		}
		ni_string_array_destroy(&names);
	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_dummy(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *child = NULL;

	child = xml_node_create(ifnode, "dummy");

	if (compat->dev->link.hwaddr.len)
		xml_node_new_element("address", child,
				ni_link_address_print(&compat->dev->link.hwaddr));

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_wireless(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	ni_wireless_t *wlan;
	ni_wireless_network_t *net;
	xml_node_t *wireless, *network, *wep, *wpa_psk, *wpa_eap;
	ni_wireless_blob_t *cert;
	char *tmp = NULL;
	const char *value;
	int i, count, key_i;

	wlan = ni_netdev_get_wireless(compat->dev);

	if (!(wireless = xml_node_create(ifnode, "wireless"))) {
		return FALSE;
	}

	if (ni_string_len(wlan->conf.country) == 2) {
		xml_node_new_element("country", wireless, wlan->conf.country);
	}

	if (wlan->conf.ap_scan <= NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH &&
		ni_string_printf(&tmp, "%u", wlan->conf.ap_scan)) {
		xml_node_new_element("ap-scan", wireless, tmp);
		ni_string_free(&tmp);
	}

	if (!ni_string_empty(wlan->conf.driver))
		xml_node_new_element("wpa-driver", wireless, wlan->conf.driver);

	count = wlan->conf.networks.count;

	for (i = 0; i < count; i++) {
		net = wlan->conf.networks.data[i];
		if (!(network = xml_node_new("network", wireless)))
			return FALSE;

		if (net->essid.len > 0) {
			ni_string_set(&tmp, (const char *) net->essid.data, net->essid.len);
			xml_node_new_element("essid", network, tmp);
			ni_string_free(&tmp);
		}

		xml_node_new_element("scan-ssid", network, net->scan_ssid?"true":"false");

		if (net->priority > 0 &&
			ni_string_printf(&tmp, "%u", net->priority)) {
			xml_node_new_element("priority", network, tmp);
			ni_string_free(&tmp);
		}

		if ((value = ni_wireless_mode_to_name(net->mode))) {
			xml_node_new_element("mode", network, value);
		}

		if (net->access_point.len > 0) {
			xml_node_new_element("access-point", network,
				ni_link_address_print(&net->access_point));
		}

		if (net->channel > 0 &&
			ni_string_printf(&tmp, "%u", net->channel)) {
			xml_node_new_element("channel", network, tmp);
			ni_string_free(&tmp);
		}

		if (net->fragment_size > 0 &&
			ni_string_printf(&tmp, "%u", net->fragment_size)) {
			xml_node_new_element("fragment-size", network, tmp);
			ni_string_free(&tmp);
		}

		if ((value = ni_wireless_key_management_to_name(net->keymgmt_proto))) {
			xml_node_new_element("key-management", network, value);
		}

		switch (net->keymgmt_proto) {
		case NI_WIRELESS_KEY_MGMT_NONE:
			if (!(wep = xml_node_new("wep", network))) {
				return FALSE;
			}

			if ((value = ni_wireless_auth_algo_to_name(net->auth_algo))) {
				xml_node_new_element("auth-algo", wep, value);
			}

			if (net->default_key < NI_WIRELESS_WEP_KEY_COUNT &&
				ni_string_printf(&tmp, "%u", net->default_key)) {
				xml_node_new_element("default-key", wep, tmp);
				ni_string_free(&tmp);
			}

			for (key_i = 0; key_i < NI_WIRELESS_WEP_KEY_COUNT; key_i++) {
				if (!ni_string_empty(net->wep_keys[key_i])) {
					/* To be secured */
					xml_node_new_element("key", wep, net->wep_keys[key_i]);
				}
			}

			break;
		case NI_WIRELESS_KEY_MGMT_PSK:
			if (!(wpa_psk = xml_node_new("wpa-psk", network))) {
				return FALSE;
			}

			if (!ni_string_empty(net->wpa_psk.passphrase)) {
				/* To be secured */
				xml_node_new_element("passphrase", wpa_psk,
					net->wpa_psk.passphrase);
			}

			if ((value = ni_wireless_auth_mode_to_name(net->auth_proto))) {
				xml_node_new_element("auth-proto", wpa_psk, value);
			}

			if ((value = ni_wireless_cipher_to_name(net->pairwise_cipher))) {
				xml_node_new_element("pairwise-cipher", wpa_psk, value);
			}

			if ((value = ni_wireless_cipher_to_name(net->group_cipher))) {
				xml_node_new_element("group-cipher", wpa_psk, value);
			}

			break;

		case NI_WIRELESS_KEY_MGMT_EAP:
			if (!(wpa_eap = xml_node_new("wpa-eap", network))) {
				return FALSE;
			}

			if ((value = ni_wireless_eap_method_to_name(net->wpa_eap.method))) {
				xml_node_new_element("method", wpa_eap, value);
			}

			if ((value = ni_wireless_auth_mode_to_name(net->auth_proto))) {
				xml_node_new_element("auth-proto", wpa_eap, value);
			}

			if ((value = ni_wireless_cipher_to_name(net->pairwise_cipher))) {
				xml_node_new_element("pairwise-cipher", wpa_eap, value);
			}

			if ((value = ni_wireless_cipher_to_name(net->group_cipher))) {
				xml_node_new_element("group-cipher", wpa_eap, value);
			}

			if (!ni_string_empty(net->wpa_eap.identity)) {
				xml_node_new_element("identity", wpa_eap, net->wpa_eap.identity);
			}

			xml_node_t *phase1 = xml_node_new("phase1", wpa_eap);

			if (ni_string_printf(&tmp, "%u", net->wpa_eap.phase1.peapver)) {
				xml_node_new_element("peap-version", phase1, tmp);
				ni_string_free(&tmp);
			}

			xml_node_t *phase2 = xml_node_new("phase2", wpa_eap);

			if ((value = ni_wireless_eap_method_to_name(net->wpa_eap.phase2.method))) {
				xml_node_new_element("method", phase2, value);
			}

			if (!ni_string_empty(net->wpa_eap.phase2.password)) {
				/* To be secured */
				xml_node_new_element("password", phase2,
						net->wpa_eap.phase2.password);
			}

			if (!ni_string_empty(net->wpa_eap.anonid)) {
				xml_node_new_element("anonid", wpa_eap, net->wpa_eap.anonid);
			}

			xml_node_t *tls = xml_node_new("tls", wpa_eap);

			if ((cert = net->wpa_eap.tls.ca_cert)) {
				if (!ni_string_empty(cert->name)) {
					xml_node_new_element("ca-cert", tls, cert->name);
					/* FIXME/ADDME file data and size exporting */
				}
			}

			if ((cert = net->wpa_eap.tls.client_cert)) {
				if (!ni_string_empty(cert->name)) {
					xml_node_new_element("client-cert", tls, cert->name);
					/* FIXME/ADDME file data and size exporting */
				}
			}

			if ((cert = net->wpa_eap.tls.client_key)) {
				if (!ni_string_empty(cert->name)) {
					xml_node_new_element("client-key", tls, cert->name);
					/* FIXME/ADDME file data and size exporting */
				}
			}

			if (!ni_string_empty(net->wpa_eap.tls.client_key_passwd)) {
				xml_node_new_element("client-key-passwd", tls,
						net->wpa_eap.tls.client_key_passwd);
				/* FIXME/ADDME file data and size exporting */
			}

			break;

		default:
			return FALSE;
			break;
		}
	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_tuntap(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *child = NULL;
	ni_tuntap_t *tuntap;

	if (!(tuntap = ni_netdev_get_tuntap(compat->dev)))
		return FALSE;

	if (compat->dev->link.type == NI_IFTYPE_TUN) {
		child = xml_node_create(ifnode, "tun");
	} else
	if (compat->dev->link.type == NI_IFTYPE_TAP) {
		child = xml_node_create(ifnode, "tap");

		if (child && compat->dev->link.hwaddr.len) {
			xml_node_new_element("address", child,
				ni_link_address_print(&compat->dev->link.hwaddr));
		}
	}

	if (!child)
		return FALSE;

	if (tuntap->owner != -1U)
		xml_node_new_element_uint("owner", child, tuntap->owner);
	if (tuntap->group != -1U)
		xml_node_new_element_uint("group", child, tuntap->group);

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_generic_tunnel(xml_node_t *ifnode, ni_linkinfo_t *link,
				ni_tunnel_t *tunnel)
{
	if (!ifnode)
		return FALSE;

	xml_node_new_element("local-address", ifnode,
			ni_link_address_print(&link->hwaddr));
	xml_node_new_element("remote-address", ifnode,
			ni_link_address_print(&link->hwpeer));

	xml_node_new_element("ttl", ifnode,
			ni_sprint_uint((unsigned int)tunnel->ttl));
	xml_node_new_element("tos", ifnode,
			ni_sprint_uint((unsigned int)tunnel->tos));
	xml_node_new_element("pmtudisc", ifnode,
			ni_format_boolean(tunnel->pmtudisc));

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_ipip(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *child = NULL;
	ni_ipip_t *ipip = NULL;
	ni_netdev_t *dev = compat->dev;
	ni_bool_t rv;

	if (!(ipip = ni_netdev_get_ipip(dev)))
		return FALSE;

	child = xml_node_create(ifnode, "ipip");

	rv = __ni_compat_generate_generic_tunnel(child, &dev->link,
						&ipip->tunnel);

	return rv;
}

static ni_bool_t
__ni_compat_generate_gre(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *child = NULL;
	ni_gre_t *gre = NULL;
	ni_netdev_t *dev = compat->dev;
	ni_bool_t rv;

	if (!(gre = ni_netdev_get_gre(dev)))
		return FALSE;

	child = xml_node_create(ifnode, "gre");

	rv = __ni_compat_generate_generic_tunnel(child, &dev->link,
						&gre->tunnel);

	return rv;
}

static ni_bool_t
__ni_compat_generate_sit(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *child = NULL;
	ni_sit_t *sit = NULL;
	ni_netdev_t *dev = compat->dev;
	ni_bool_t rv;

	if (!(sit = ni_netdev_get_sit(dev)))
		return FALSE;

	child = xml_node_create(ifnode, "sit");

	rv = __ni_compat_generate_generic_tunnel(child, &dev->link,
						&sit->tunnel);

	xml_node_new_element("isatap", child,
			ni_format_boolean(sit->isatap));

	return rv;
}

static void
__ni_compat_generate_static_route_hops(xml_node_t *rnode, const ni_route_nexthop_t *hops,
					const char *ifname)
{
	const ni_route_nexthop_t *nh;

	for (nh = hops; nh; nh = nh->next) {
		xml_node_t *nhnode;

		if (!ni_sockaddr_is_specified(&nh->gateway) && !nh->device.name)
			continue;

		nhnode = xml_node_new("nexthop", NULL);
		if (ni_sockaddr_is_specified(&nh->gateway)) {
			xml_node_new_element("gateway", nhnode,
				ni_sockaddr_print(&nh->gateway));
		}
		if (nh->device.name && !ni_string_eq(ifname, nh->device.name)) {
			xml_node_new_element("device", nhnode, nh->device.name);
		} else
		if (ifname && hops->next && nh->gateway.ss_family == AF_UNSPEC) {
			xml_node_new_element("device", nhnode, ifname);
		}

		if (nhnode->children)
			xml_node_add_child(rnode, nhnode);
		else
			xml_node_free(nhnode);

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
			ni_string_array_destroy(&names);
		}
	}
}

static void
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
	ni_string_array_destroy(&names);

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

static void
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
		char *table_ptr = NULL;
		if (!(ptr = ni_route_table_type_to_name(rp->table, &table_ptr))) {
			/* Should not happen. */
			ni_error("failed to obtain name of routing table %u", rp->table);
		}
		if (knode == NULL)
			knode = xml_node_new("kern", rnode);
		xml_node_new_element("table", knode, ptr);
		ni_string_free(&table_ptr);
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
		ni_string_array_destroy(&names);
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

static void
__ni_compat_generate_static_route_list(xml_node_t *afnode, ni_route_table_t *routes, const char *ifname, unsigned int af)
{
	const ni_route_table_t *tab;
	const ni_route_t *rp;
	unsigned int i;

	for (tab = routes; tab; tab = tab->next) {
		for (i = 0; i < tab->routes.count; ++i) {
			rp = tab->routes.data[i];

			if( !rp || rp->family != af)
				continue;

			__ni_compat_generate_static_route(afnode, rp, ifname);
		}
	}
}

static void
__ni_compat_generate_static_address_list(xml_node_t *afnode, ni_address_t *addr_list, unsigned int af)
{
	ni_address_t *ap;
	xml_node_t *anode;

	for (ap = addr_list; ap; ap = ap->next) {
		if (ap->family != af)
			continue;

		anode = xml_node_new("address", afnode);
		xml_node_new_element("local", anode, ni_sockaddr_prefix_print(&ap->local_addr, ap->prefixlen));

		if (ap->peer_addr.ss_family != AF_UNSPEC)
			xml_node_new_element("peer", anode, ni_sockaddr_print(&ap->peer_addr));
		if (ap->bcast_addr.ss_family != AF_UNSPEC)
			xml_node_new_element("broadcast", anode, ni_sockaddr_print(&ap->bcast_addr));
		if (af == AF_INET && ap->label)
			xml_node_new_element("label", anode, ap->label);
	}
}

xml_node_t *
__ni_compat_generate_static_addrconf(xml_node_t *ifnode, const ni_compat_netdev_t *compat,
		unsigned int af)
{
	const ni_netdev_t *dev = compat->dev;
	const char *afname;
	xml_node_t *afnode;

	afname = ni_addrfamily_type_to_name(af);
	if (afname) {
		char buffer[64];

		snprintf(buffer, sizeof(buffer), "%s:static", afname);
		afnode = xml_node_new(buffer, NULL);
	} else {
		ni_error("%s: unknown address family %u", __func__, af);
		return NULL;
	}

	__ni_compat_generate_static_address_list(afnode, dev->addrs, af);
	__ni_compat_generate_static_route_list(afnode, dev->routes, dev->name, af);

	if (afnode->children) {
		xml_node_add_child(ifnode, afnode);
	} else {
		xml_node_free(afnode);
		afnode = NULL;
	}
	return afnode;
}

static xml_node_t *
__ni_compat_generate_dynamic_addrconf(xml_node_t *ifnode, const char *name, unsigned int flags, unsigned int update)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	xml_node_t *aconf;

	aconf = xml_node_new(name, ifnode);
	xml_node_new_element("enabled", aconf, "true");

	if (flags && !ni_string_empty(ni_addrconf_flags_format(&buf, flags, ",")))
		xml_node_new_element("flags", aconf, buf.string);
	ni_stringbuf_destroy(&buf);

	if (update && !ni_string_empty(ni_addrconf_update_flags_format(&buf, update, ",")))
		xml_node_new_element("update", aconf, buf.string);
	ni_stringbuf_destroy(&buf);

	return aconf;
}

/*
 * Generate XML for user-class data. We want to support both rfc3004 and non-standardized
 * string case and allow for specification of formatting.
 */
static void
__ni_compat_generate_dhcp4_user_class(xml_node_t *ifnode, const ni_dhcp4_user_class_t *user_class)
{
	xml_node_t *user_class_node;
	const char *ptr;
	unsigned int i;

	if ((ptr = ni_dhcp4_user_class_format_type_to_name(user_class->format))) {
		user_class_node = xml_node_new("user-class", ifnode);
		xml_node_dict_set(user_class_node, "format", ptr);
		for (i = 0; i < user_class->class_id.count; ++i) {
			xml_node_new_element("identifier", user_class_node, user_class->class_id.data[i]);
			if (user_class->format ==  NI_DHCP4_USER_CLASS_STRING)
				break;
		}
	}
}


static xml_node_t *
__ni_compat_generate_dhcp4_addrconf(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *dhcp;

	if (!compat->dhcp4.enabled)
		return NULL;

	dhcp = __ni_compat_generate_dynamic_addrconf(ifnode, "ipv4:dhcp",
			compat->dhcp4.flags, compat->dhcp4.update);

	if (compat->dhcp4.hostname)
		xml_node_dict_set(dhcp, "hostname", compat->dhcp4.hostname);

	if (compat->dhcp4.route_priority)
		xml_node_dict_set(dhcp, "route-priority",
				ni_sprint_uint(compat->dhcp4.route_priority));


	if (compat->dhcp4.start_delay)
		xml_node_dict_set(dhcp, "start-delay",
				ni_sprint_timeout(compat->dhcp4.start_delay));

	if (compat->dhcp4.defer_timeout)
		xml_node_dict_set(dhcp, "defer-timeout",
				ni_sprint_timeout(compat->dhcp4.defer_timeout));

	if (compat->dhcp4.acquire_timeout)
		xml_node_dict_set(dhcp, "acquire-timeout",
				ni_sprint_timeout(compat->dhcp4.acquire_timeout));

	if (compat->dhcp4.lease_time)
		xml_node_dict_set(dhcp, "lease-time",
				ni_sprint_timeout(compat->dhcp4.lease_time));

	xml_node_dict_set(dhcp, "recover-lease",
				ni_format_boolean(compat->dhcp4.recover_lease));
	xml_node_dict_set(dhcp, "release-lease",
				ni_format_boolean(compat->dhcp4.release_lease));

	if (compat->dhcp4.client_id)
		xml_node_dict_set(dhcp, "client-id", compat->dhcp4.client_id);
	if (compat->dhcp4.vendor_class)
		xml_node_dict_set(dhcp, "vendor-class", compat->dhcp4.vendor_class);

	if (compat->dhcp4.user_class.class_id.count) {
		__ni_compat_generate_dhcp4_user_class(dhcp, &compat->dhcp4.user_class);
	}

	return dhcp;
}

static xml_node_t *
__ni_compat_generate_dhcp6_addrconf(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *dhcp;
	const char *ptr;

	if (!compat->dhcp6.enabled)
		return NULL;

	dhcp = __ni_compat_generate_dynamic_addrconf(ifnode, "ipv6:dhcp",
			compat->dhcp6.flags, compat->dhcp6.update);

	if ((ptr = ni_dhcp6_mode_type_to_name(compat->dhcp6.mode)) != NULL)
		xml_node_dict_set(dhcp, "mode", ptr);

	xml_node_dict_set(dhcp, "rapid-commit",
			ni_format_boolean(compat->dhcp6.rapid_commit));


	if (compat->dhcp6.hostname)
		xml_node_dict_set(dhcp, "hostname", compat->dhcp6.hostname);


	if (compat->dhcp6.start_delay)
		xml_node_dict_set(dhcp, "start-delay",
				ni_sprint_timeout(compat->dhcp6.start_delay));

	if (compat->dhcp6.defer_timeout)
		xml_node_dict_set(dhcp, "defer-timeout",
				ni_sprint_timeout(compat->dhcp6.defer_timeout));

	if (compat->dhcp6.acquire_timeout)
		xml_node_dict_set(dhcp, "acquire-timeout",
				ni_sprint_timeout(compat->dhcp6.acquire_timeout));

	if (compat->dhcp6.lease_time)
		xml_node_dict_set(dhcp, "lease-time",
				ni_sprint_timeout(compat->dhcp6.lease_time));

	xml_node_dict_set(dhcp, "recover-lease",
				ni_format_boolean(compat->dhcp6.recover_lease));
	xml_node_dict_set(dhcp, "release-lease",
				ni_format_boolean(compat->dhcp6.release_lease));


	if (compat->dhcp6.client_id)
		xml_node_dict_set(dhcp, "client-id", compat->dhcp6.client_id);
#if 0
	if (compat->dhcp6.vendor_class)
		xml_node_dict_set(dhcp, "vendor-class", compat->dhcp6.vendor_class);
#endif
	return dhcp;
}

static ni_bool_t
__ni_compat_generate_ipv4_devconf(xml_node_t *ifnode, const ni_ipv4_devinfo_t *ipv4, ni_iftype_t iftype)
{
	xml_node_t *node;

	if (!ipv4)
		return FALSE;

	node = xml_node_new("ipv4", NULL);
	__ni_compat_optional_tristate("enabled", node, ipv4->conf.enabled);
	if (ni_tristate_is_disabled(ipv4->conf.enabled)) {
		xml_node_add_child(ifnode, node);
		return TRUE;
	}

	__ni_compat_optional_tristate("forwarding", node, ipv4->conf.forwarding);
	switch (iftype) {
	case NI_IFTYPE_ETHERNET:
	case NI_IFTYPE_WIRELESS:
	case NI_IFTYPE_BRIDGE:
	case NI_IFTYPE_BOND:
	case NI_IFTYPE_VLAN:
	case NI_IFTYPE_MACVLAN:
	case NI_IFTYPE_MACVTAP:
	case NI_IFTYPE_INFINIBAND:
	case NI_IFTYPE_INFINIBAND_CHILD:
	case NI_IFTYPE_TOKENRING:
	case NI_IFTYPE_FIREWIRE:
	case NI_IFTYPE_UNKNOWN:
		__ni_compat_optional_tristate("arp-verify", node, ipv4->conf.arp_verify);
		__ni_compat_optional_tristate("arp-notify", node, ipv4->conf.arp_notify);
	default:
		break;
	}

	if (node->children) {
		xml_node_add_child(ifnode, node);
		return TRUE;
	} else {
		xml_node_free(node);
		return FALSE;
	}
}

static ni_bool_t
__ni_compat_generate_ipv6_devconf(xml_node_t *ifnode, const ni_ipv6_devinfo_t *ipv6)
{
	xml_node_t *node;

	if (!ipv6)
		return TRUE;

	node = xml_node_new("ipv6", NULL);

	__ni_compat_optional_tristate("enabled", node, ipv6->conf.enabled);
	if (ni_tristate_is_disabled(ipv6->conf.enabled)) {
		xml_node_add_child(ifnode, node);
		return TRUE;
	}

	__ni_compat_optional_tristate("forwarding", node, ipv6->conf.forwarding);
	__ni_compat_optional_tristate("autoconf", node, ipv6->conf.autoconf);
	if (ipv6->conf.privacy > NI_IPV6_PRIVACY_DEFAULT) {
		xml_node_new_element("privacy", node,
			ni_ipv6_devconf_privacy_to_name(ipv6->conf.privacy));
	}
	if (ipv6->conf.accept_ra > NI_IPV6_ACCEPT_RA_DEFAULT) {
		xml_node_new_element("accept-ra", node,
				ni_ipv6_devconf_accept_ra_to_name(ipv6->conf.accept_ra));
	}
	if (ipv6->conf.accept_dad > NI_IPV6_ACCEPT_DAD_DEFAULT) {
		xml_node_new_element("accept-dad", node,
				ni_ipv6_devconf_accept_dad_to_name(ipv6->conf.accept_dad));
	}
	__ni_compat_optional_tristate("accept-redirects", node,
						ipv6->conf.accept_redirects);

	if (node->children) {
		xml_node_add_child(ifnode, node);
		return TRUE;
	} else {
		xml_node_free(node);
		return FALSE;
	}
}

static ni_bool_t
__ni_compat_generate_ifcfg(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	xml_node_t *linknode;

	if (compat->control) {
		const ni_ifworker_control_t *control = compat->control;
		xml_node_t *child, *linkdet;

		child = xml_node_create(ifnode, "control");
		if (control->mode)
			xml_node_new_element("mode", child, control->mode);
		if (control->boot_stage)
			xml_node_new_element("boot-stage", child, control->boot_stage);

		if (control->persistent) {
			xml_node_new_element(NI_CLIENT_STATE_XML_PERSISTENT_NODE, child,
				ni_format_boolean(control->persistent));
		}
		if (control->usercontrol) {
			xml_node_new_element(NI_CLIENT_STATE_XML_USERCONTROL_NODE, child,
				ni_format_boolean(control->usercontrol));
		}

		if (control->link_timeout || control->link_priority || control->link_required) {
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

	case NI_IFTYPE_MACVLAN:
	case NI_IFTYPE_MACVTAP:
		__ni_compat_generate_macvlan(ifnode, compat);
		break;

	case NI_IFTYPE_DUMMY:
		__ni_compat_generate_dummy(ifnode, compat);
		break;

	case NI_IFTYPE_WIRELESS:
		__ni_compat_generate_wireless(ifnode, compat);
		break;

	case NI_IFTYPE_TUN:
	case NI_IFTYPE_TAP:
		__ni_compat_generate_tuntap(ifnode, compat);
		break;

	case NI_IFTYPE_IPIP:
		__ni_compat_generate_ipip(ifnode, compat);
		break;

	case NI_IFTYPE_GRE:
		__ni_compat_generate_gre(ifnode, compat);
		break;

	case NI_IFTYPE_SIT:
		__ni_compat_generate_sit(ifnode, compat);
		break;

	default: ;
	}

	linknode = xml_node_new("link", ifnode);
	if (dev->link.mtu)
		xml_node_new_element("mtu", linknode, ni_sprint_uint(dev->link.mtu));

	__ni_compat_generate_ipv4_devconf(ifnode, dev->ipv4, dev->link.type);
	if (dev->ipv4 && !ni_tristate_is_disabled(dev->ipv4->conf.enabled)) {
		__ni_compat_generate_static_addrconf(ifnode, compat, AF_INET);
		__ni_compat_generate_dhcp4_addrconf(ifnode, compat);
	}

	__ni_compat_generate_ipv6_devconf(ifnode, dev->ipv6);
	if (dev->ipv6 && !ni_tristate_is_disabled(dev->ipv6->conf.enabled)) {
		__ni_compat_generate_static_addrconf(ifnode, compat, AF_INET6);
		__ni_compat_generate_dhcp6_addrconf(ifnode, compat);
	}

	return TRUE;
}

static xml_node_t *
ni_compat_generate_ifcfg(const ni_compat_netdev_t *compat, xml_document_t *doc)
{
	xml_node_t *ifnode, *namenode;

	ifnode = xml_node_new("interface", doc->root);

	namenode = xml_node_new("name", ifnode);
	if (compat->identify.hwaddr.len &&
	    compat->identify.hwaddr.type == ARPHRD_ETHER) {
		xml_node_add_attr(namenode, "namespace", "ethernet");
		xml_node_new_element("permanent-address", namenode,
				ni_link_address_print(&compat->identify.hwaddr));
	} else {
		xml_node_set_cdata(namenode, compat->dev->name);
	}

	__ni_compat_generate_ifcfg(ifnode, compat);
	return ifnode;
}

unsigned int
ni_compat_generate_interfaces(xml_document_array_t *array, ni_compat_ifconfig_t *ifcfg, ni_bool_t check_prio, ni_bool_t raw)
{
	xml_document_t *config_doc;
	unsigned int i;

	if (!ifcfg)
		return 0;

	for (i = 0; i < ifcfg->netdevs.count; ++i) {
		ni_compat_netdev_t *compat = ifcfg->netdevs.data[i];
		ni_client_state_t *cs = ni_netdev_get_client_state(compat->dev);
		ni_client_state_config_t *conf = &cs->config;

		config_doc = xml_document_new();
		ni_compat_generate_ifcfg(compat, config_doc);

		if (conf) {
			xml_node_t *root = xml_document_root(config_doc);

			if (!ni_string_empty(conf->origin)) {
				xml_location_set(root, xml_location_create(conf->origin, 0));
				ni_debug_ifconfig("%s: location: %s, line: %u", __func__,
						xml_node_get_location_filename(root),
						xml_node_get_location_line(root));
			}

			if (!raw)
				ni_ifconfig_metadata_add_to_node(root, conf);
		}

		if (ni_ifconfig_validate_adding_doc(config_doc, check_prio))
			xml_document_array_append(array, config_doc);
		else
			xml_document_free(config_doc);
	}

	return i;
}
