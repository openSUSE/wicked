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
 *		Nirmoy Das <ndas@suse.de>
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
#include <wicked/ppp.h>
#include <wicked/team.h>
#include <wicked/ovs.h>
#include <wicked/bridge.h>
#include <wicked/vlan.h>
#include <wicked/vxlan.h>
#include <wicked/macvlan.h>
#include <wicked/tuntap.h>
#include <wicked/tunneling.h>
#include <wicked/wireless.h>
#include <wicked/fsm.h>
#include <wicked/xml.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/util.h>
#include <wicked/ethtool.h>
#include "wicked-client.h"
#include <netlink/netlink.h>
#include <sys/param.h>
#include <arpa/inet.h>

#include "client/client_state.h"
#include "appconfig.h"
#include "util_priv.h"

static ni_bool_t ni_compat_generate_ethtool_link_advertise(xml_node_t *, const ni_bitfield_t *);
/*
 * Compat ifconfig handling functions
 */
void
ni_compat_ifconfig_init(ni_compat_ifconfig_t *conf, const char *schema)
{
	memset(conf, 0, sizeof(*conf));
	ni_string_dup(&conf->schema, schema);
}

void
ni_compat_ifconfig_destroy(ni_compat_ifconfig_t *conf)
{
	if (conf) {
		ni_string_free(&conf->schema);
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
	compat->dhcp4.update = ni_config_addrconf_update(ifname, NI_ADDRCONF_DHCP, AF_INET);
	compat->dhcp4.recover_lease = TRUE;
	compat->dhcp4.release_lease = FALSE;
	compat->dhcp4.broadcast = NI_TRISTATE_DEFAULT;
	compat->dhcp4.user_class.format = -1U;
	ni_dhcp_fqdn_init(&compat->dhcp4.fqdn);

	compat->dhcp6.update = ni_config_addrconf_update(ifname, NI_ADDRCONF_DHCP, AF_INET6);
	compat->dhcp6.mode = NI_DHCP6_MODE_AUTO;
	compat->dhcp6.rapid_commit = TRUE;
	compat->dhcp6.recover_lease = TRUE;
	compat->dhcp6.release_lease = FALSE;
	ni_dhcp_fqdn_init(&compat->dhcp6.fqdn);

	compat->auto6.update = ni_config_addrconf_update(ifname, NI_ADDRCONF_AUTOCONF, AF_INET6);

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
		ni_var_array_destroy(&compat->scripts);
		ni_string_free(&compat->firewall.zone);

		ni_rule_array_destroy(&compat->rules);

		ni_string_free(&compat->dhcp4.hostname);
		ni_string_free(&compat->dhcp4.client_id);
		ni_string_free(&compat->dhcp4.vendor_class);
		ni_string_array_destroy(&compat->dhcp4.user_class.class_id);
		ni_string_array_destroy(&compat->dhcp4.request_options);

		ni_string_free(&compat->dhcp6.hostname);
		ni_string_free(&compat->dhcp6.client_id);
		ni_string_array_destroy(&compat->dhcp6.request_options);

		free(compat);
	}
}

void
ni_compat_netdev_set_origin(ni_compat_netdev_t *compat, const char *schema, const char *path)
{
	ni_client_state_t *cs;

	if (!compat || !compat->dev || ni_string_empty(schema) || ni_string_empty(path))
		return;

	if (!(cs = ni_netdev_get_client_state(compat->dev)))
		return;

	ni_client_state_config_reset(&cs->config);
	ni_ifconfig_format_origin(&cs->config.origin, schema, path);
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

/* generate coalesce configuration */
static void
ni_compat_generate_ethtool_coalesce(xml_node_t *parent, const ni_ethtool_coalesce_t *coalesce)
{
	xml_node_t *node;

	if (!parent || !coalesce)
		return;

	node = xml_node_new("coalesce", NULL);

	if (coalesce->adaptive_rx != NI_TRISTATE_DEFAULT)
		xml_node_new_element("adaptive-rx", node, ni_format_boolean(coalesce->adaptive_rx));

	if (coalesce->adaptive_tx != NI_TRISTATE_DEFAULT)
		xml_node_new_element("adaptive-tx", node, ni_format_boolean(coalesce->adaptive_tx));

	if (coalesce->rx_usecs != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-usecs", node, coalesce->rx_usecs);
	}
	if (coalesce->rx_frames != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-frames", node, coalesce->rx_frames);
	}
	if (coalesce->rx_usecs_irq != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-usecs-irq", node, coalesce->rx_usecs_irq);
	}
	if (coalesce->rx_frames_irq != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-frames-irq", node, coalesce->rx_frames_irq);
	}
	if (coalesce->tx_usecs != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("tx-usecs", node, coalesce->tx_usecs);
	}
	if (coalesce->tx_frames != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("tx-frames", node, coalesce->tx_frames);
	}
	if (coalesce->tx_usecs_irq != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("tx-usecs-irq", node, coalesce->tx_usecs_irq);
	}
	if (coalesce->tx_frames_irq != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("tx-frames-irq", node, coalesce->tx_frames_irq);
	}
	if (coalesce->stats_block_usecs != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("stats-block-usecs", node, coalesce->stats_block_usecs);
	}
	if (coalesce->pkt_rate_low != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("pkt-rate-low", node, coalesce->pkt_rate_low);
	}
	if (coalesce->rx_usecs_low != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-usecs-low", node, coalesce->rx_usecs_low);
	}
	if (coalesce->rx_frames_low != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-frames-low", node, coalesce->rx_frames_low);
	}
	if (coalesce->tx_usecs_low != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("tx-usecs-low", node, coalesce->tx_usecs_low);
	}
	if (coalesce->tx_frames_low != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("tx-frames-low", node, coalesce->tx_frames_low);
	}
	if (coalesce->pkt_rate_high != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("pkt-rate-high", node, coalesce->pkt_rate_high);
	}
	if (coalesce->rx_usecs_high != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-usecs-high", node, coalesce->rx_usecs_high);
	}
	if (coalesce->rx_frames_high != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-frames-high", node, coalesce->rx_frames_high);
	}
	if (coalesce->tx_usecs_high != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("tx-usecs-high", node, coalesce->tx_usecs_high);
	}
	if (coalesce->tx_frames_high != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("tx-frames-high", node, coalesce->tx_frames_high);
	}
	if (coalesce->sample_interval != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("sample-interval", node, coalesce->sample_interval);
	}

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);

}

/* generate eee configuration */
static void
ni_compat_generate_ethtool_eee(xml_node_t *parent, const ni_ethtool_eee_t *eee)
{
	xml_node_t *node;

	if (!parent || !eee)
		return;

	node = xml_node_new("eee", NULL);
	if (eee->status.enabled != NI_TRISTATE_DEFAULT)
		xml_node_new_element("enabled", node, ni_format_boolean(eee->status.enabled));

	ni_compat_generate_ethtool_link_advertise(node, &eee->speed.advertising);

	if (eee->tx_lpi.enabled != NI_TRISTATE_DEFAULT)
		xml_node_new_element("tx-lpi", node, ni_format_boolean(eee->tx_lpi.enabled));
	if (eee->tx_lpi.timer != NI_ETHTOOL_EEE_DEFAULT)
		xml_node_new_element_uint("tx-timer", node, eee->tx_lpi.timer);

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);
}

/* generate channels information */
static void
ni_compat_generate_ethtool_channels(xml_node_t *parent, const ni_ethtool_channels_t *channels)
{
	xml_node_t *node;

	if (!parent || !channels)
		return;

	node = xml_node_new("channels", NULL);
	if (channels->tx != NI_ETHTOOL_CHANNELS_DEFAULT) {
		xml_node_new_element_uint("tx", node, channels->tx);
	}
	if (channels->rx != NI_ETHTOOL_CHANNELS_DEFAULT) {
		xml_node_new_element_uint("rx", node, channels->rx);
	}
	if (channels->other != NI_ETHTOOL_CHANNELS_DEFAULT) {
		xml_node_new_element_uint("other", node, channels->other);
	}
	if (channels->combined != NI_ETHTOOL_CHANNELS_DEFAULT) {
		xml_node_new_element_uint("combined", node, channels->combined);
	}

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);

}
/* generate ring information */
static void
ni_compat_generate_ethtool_ring(xml_node_t *parent, const ni_ethtool_ring_t *ring)
{
	xml_node_t *node;

	if (!parent || !ring)
		return;

	node = xml_node_new("ring", NULL);
	if (ring->tx != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("tx", node, ring->tx);
	}
	if (ring->rx != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx", node, ring->rx);
	}
	if (ring->rx_jumbo != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-jumbo", node, ring->rx_jumbo);
	}
	if (ring->rx_mini != NI_ETHTOOL_RING_DEFAULT) {
		xml_node_new_element_uint("rx-mini", node, ring->rx_mini);
	}

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);

}

/* generate pause information */
static void
ni_compat_generate_ethtool_pause(xml_node_t *parent, const ni_ethtool_pause_t *pause)
{
	xml_node_t *node;

	if (!parent || !pause)
		return;

	node = xml_node_new("pause", NULL);
	if (pause->tx != NI_TRISTATE_DEFAULT) {
		xml_node_new_element("tx", node, ni_format_boolean(pause->tx));
	}
	if (pause->rx != NI_TRISTATE_DEFAULT) {
		xml_node_new_element("rx", node, ni_format_boolean(pause->rx));
	}
	if (pause->autoneg != NI_TRISTATE_DEFAULT) {
		xml_node_new_element("autoneg", node, ni_format_boolean(pause->autoneg));
	}

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);

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
	xml_node_t *child, *snodes, *snode;
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
		xml_node_new_element("carrier-detect", miimon,
			ni_bonding_mii_carrier_detect_name(bond->miimon.carrier_detect));
	}

	snodes = xml_node_create(child, "slaves");
	for (i = 0; i < bond->slaves.count; ++i) {
		ni_bonding_slave_t *slave = bond->slaves.data[i];

		if (!slave || ni_string_empty(slave->device.name))
			continue;

		snode = xml_node_new("slave", snodes);
		xml_node_new_element("device", snode, slave->device.name);

		switch (bond->mode) {
		case NI_BOND_MODE_ACTIVE_BACKUP:
		case NI_BOND_MODE_BALANCE_TLB:
		case NI_BOND_MODE_BALANCE_ALB:
			if (ni_string_eq(bond->primary_slave.name, slave->device.name)) {
				xml_node_new_element("primary", snode, "true");
			}
			if (ni_string_eq(bond->active_slave.name, slave->device.name)) {
				xml_node_new_element("active", snode, "true");
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
		if (verbose || bond->ad_user_port_key) {
			xml_node_new_element("ad-user-port-key", child,
				ni_sprint_uint(bond->ad_user_port_key));
		}
		if (verbose || bond->ad_actor_sys_prio != 65535) {
			xml_node_new_element("ad-actor-sys-prio", child,
				ni_sprint_uint(bond->ad_actor_sys_prio));
		}
		if (bond->ad_actor_system.len) {
			xml_node_new_element("ad-actor-system", child,
				ni_link_address_print(&bond->ad_actor_system));
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

	if (compat->dev->link.hwaddr.len) {
		xml_node_new_element("address", child,
			ni_link_address_print(&compat->dev->link.hwaddr));
	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_team_runner(xml_node_t *tnode, const ni_team_runner_t *runner)
{
	xml_node_t *rnode;
	const char *name;

	if (!tnode || !runner)
		return FALSE;

	if (!(name = ni_team_runner_type_to_name(runner->type)))
		return FALSE;

	rnode = xml_node_new("runner", tnode);
	xml_node_add_attr(rnode, "name", name);

	switch (runner->type) {
	case NI_TEAM_RUNNER_ACTIVE_BACKUP: {
		const ni_team_runner_active_backup_t *ab = &runner->ab;

		if (ab->config.hwaddr_policy) {
			if ((name = ni_team_ab_hwaddr_policy_type_to_name(ab->config.hwaddr_policy)))
				xml_node_new_element("hwaddr_policy", rnode, name);
		}
	}
	break;

	case NI_TEAM_RUNNER_LOAD_BALANCE: {
		const ni_team_runner_load_balance_t *lb = &runner->lb;
		ni_string_array_t flags = NI_STRING_ARRAY_INIT;
		xml_node_t *tx_balancer;
		char *tx_hash = NULL;
		const char *name;

		ni_team_tx_hash_get_bit_names(lb->config.tx_hash, &flags);
		ni_string_join(&tx_hash, &flags, ",");
		if (!ni_string_empty(tx_hash))
			xml_node_new_element("tx_hash", rnode, tx_hash);
		ni_string_array_destroy(&flags);

		if (lb->config.tx_balancer.type || lb->config.tx_balancer.interval) {
			tx_balancer = xml_node_new("tx_balancer", rnode);
			if ((name = ni_team_tx_balancer_type_to_name(lb->config.tx_balancer.type)))
				xml_node_new_element("name", tx_balancer, name);
			xml_node_new_element("balancing_interval", tx_balancer,
						ni_sprint_uint(lb->config.tx_balancer.interval));
		}
	}
	break;

	case NI_TEAM_RUNNER_ROUND_ROBIN:
	break;

	case NI_TEAM_RUNNER_BROADCAST:
	break;

	case NI_TEAM_RUNNER_RANDOM:
	break;

	case NI_TEAM_RUNNER_LACP: {
		const ni_team_runner_lacp_t *lacp = &runner->lacp;
		ni_string_array_t flags = NI_STRING_ARRAY_INIT;
		xml_node_t *tx_balancer;
		char *tx_hash = NULL;
		const char *name;

		xml_node_new_element("active", rnode, ni_format_boolean(lacp->config.active));
		xml_node_new_element("fast_rate", rnode, ni_format_boolean(lacp->config.fast_rate));
		xml_node_new_element("sys_prio", rnode, ni_sprint_uint(lacp->config.sys_prio));
		xml_node_new_element("min_ports", rnode, ni_sprint_uint(lacp->config.min_ports));
		xml_node_new_element("select_policy", rnode,
				ni_team_lacp_select_policy_type_to_name(lacp->config.select_policy));

		ni_team_tx_hash_get_bit_names(lacp->config.tx_hash, &flags);
		ni_string_join(&tx_hash, &flags, ",");
		if (!ni_string_empty(tx_hash))
			xml_node_new_element("tx_hash", rnode, tx_hash);
		ni_string_array_destroy(&flags);

		if (lacp->config.tx_balancer.type || lacp->config.tx_balancer.interval) {
			tx_balancer = xml_node_new("tx_balancer", rnode);
			if ((name = ni_team_tx_balancer_type_to_name(lacp->config.tx_balancer.type)))
				xml_node_new_element("name", tx_balancer, name);
			xml_node_new_element("balancing_interval", tx_balancer,
						ni_sprint_uint(lacp->config.tx_balancer.interval));
		}
	}
	break;

	default:
		return FALSE;
	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_team_link_watch(xml_node_t *tnode, const ni_team_link_watch_array_t *array)
{
	xml_node_t *link_watch;
	unsigned int i;

	if (!array || !tnode)
		return FALSE;

	if (!array->count)
		return TRUE;

	link_watch = xml_node_new("link_watch", tnode);
	for (i = 0; i < array->count; ++i) {
		ni_team_link_watch_t *lw = array->data[i];
		xml_node_t *watch;
		const char *name;

		if (!(name = ni_team_link_watch_type_to_name(lw->type)))
			return FALSE;

		watch = xml_node_new("watch", link_watch);
		xml_node_add_attr(watch, "name", name);

		switch(lw->type) {
		case NI_TEAM_LINK_WATCH_ETHTOOL: {
			ni_team_link_watch_ethtool_t *ethtool = &lw->ethtool;

			xml_node_new_element("delay_up", watch, ni_sprint_uint(ethtool->delay_up));
			xml_node_new_element("delay_down", watch, ni_sprint_uint(ethtool->delay_down));
		}
		break;

		case NI_TEAM_LINK_WATCH_ARP_PING: {
			const ni_team_link_watch_arp_t *arp = &lw->arp;

			if (!ni_string_empty(arp->source_host))
				xml_node_new_element("source_host", watch, arp->source_host);

			if (!ni_string_empty(arp->target_host))
				xml_node_new_element("target_host", watch, arp->target_host);

			xml_node_new_element("interval", watch, ni_sprint_uint(arp->interval));
			xml_node_new_element("init_wait", watch, ni_sprint_uint(arp->init_wait));

			xml_node_new_element("validate_active", watch, ni_format_boolean(arp->validate_active));
			xml_node_new_element("validate_inactive", watch, ni_format_boolean(arp->validate_inactive));
			xml_node_new_element("send_always", watch, ni_format_boolean(arp->send_always));

			xml_node_new_element("missed_max", watch, ni_sprint_uint(arp->missed_max));
		}
		break;

		case NI_TEAM_LINK_WATCH_NSNA_PING: {
			const ni_team_link_watch_nsna_t *nsna = &lw->nsna;

			if (!ni_string_empty(nsna->target_host))
				xml_node_new_element("target_host", watch, nsna->target_host);

			xml_node_new_element("interval", watch, ni_sprint_uint(nsna->interval));
			xml_node_new_element("init_wait", watch, ni_sprint_uint(nsna->init_wait));
			xml_node_new_element("missed_max", watch, ni_sprint_uint(nsna->missed_max));
		}
		break;

		case NI_TEAM_LINK_WATCH_TIPC: {
			const ni_team_link_watch_tipc_t *tipc = &lw->tipc;

			if (!ni_string_empty(tipc->bearer))
				xml_node_new_element("bearer", watch, tipc->bearer);
		}
		break;

		default:
			return FALSE;
		}
	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_team_ports(xml_node_t *tnode, const ni_team_port_array_t *array)
{
	xml_node_t *ports;
	unsigned int i;

	if (!array || !tnode)
		return FALSE;

	if (!array->count)
		return TRUE;

	ports = xml_node_new("ports", tnode);
	for (i = 0; i < array->count; i++) {
		ni_team_port_t *p = array->data[i];
		xml_node_t *port;

		if (ni_string_empty(p->device.name))
			continue;

		port = xml_node_new("port", ports);
		xml_node_new_element("device", port, p->device.name);

		if (p->config.queue_id != -1U)
			xml_node_new_element("queue_id", port, ni_sprint_uint(p->config.queue_id));

		if (p->config.ab.prio)
			xml_node_new_element("prio", port, ni_sprint_uint(p->config.ab.prio));
		if (p->config.ab.sticky)
			xml_node_new_element("sticky", port, ni_format_boolean(p->config.ab.sticky));

		if (p->config.lacp.prio)
			xml_node_new_element("lacp_prio", port, ni_sprint_uint(p->config.lacp.prio));
		if (p->config.lacp.key)
			xml_node_new_element("lacp_key", port, ni_sprint_uint(p->config.lacp.key));

	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_team(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	const ni_team_t *team;
	xml_node_t *tnode;

	team = ni_netdev_get_team(compat->dev);
	tnode = xml_node_create(ifnode, "team");

	if (compat->dev->link.hwaddr.len) {
		xml_node_new_element("address", tnode,
			ni_link_address_print(&compat->dev->link.hwaddr));
	}

	if (!__ni_compat_generate_team_runner(tnode, &team->runner))
		return FALSE;

	if (!__ni_compat_generate_team_link_watch(tnode, &team->link_watch))
		return FALSE;

	if (!__ni_compat_generate_team_ports(tnode, &team->ports))
		return FALSE;

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_ppp_mode(xml_node_t *tnode, const ni_ppp_mode_t *mode)
{
	xml_node_t *rnode;
	const char *name;

	if (!tnode || !mode)
		return FALSE;

	if (!(name = ni_ppp_mode_type_to_name(mode->type)))
		return FALSE;

	rnode = xml_node_new("mode", tnode);
	xml_node_add_attr(rnode, "name", name);

	switch (mode->type) {
	case NI_PPP_MODE_PPPOE: {
		const ni_ppp_mode_pppoe_t *pppoe = &mode->pppoe;

		if (!ni_string_empty(pppoe->device.name))
			xml_node_new_element("device", rnode, pppoe->device.name);
	}
	break;

	default:
		return FALSE;
	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_ppp(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	const ni_ppp_t *ppp;
	const ni_ppp_config_t *conf;
	xml_node_t *pnode, *node;

	ppp = ni_netdev_get_ppp(compat->dev);
	pnode = xml_node_create(ifnode, "ppp");

	if (!__ni_compat_generate_ppp_mode(pnode, &ppp->mode))
		return FALSE;

	conf = &ppp->config;
	if (conf->debug)
		xml_node_new_element("debug", pnode, ni_format_boolean(conf->debug));
	xml_node_new_element("demand", pnode, ni_format_boolean(conf->demand));
	xml_node_new_element("persist", pnode, ni_format_boolean(conf->persist));
	if (conf->idle != -1U)
		xml_node_new_element("idle", pnode, ni_sprint_uint(conf->idle));
	if (conf->maxfail != -1U)
		xml_node_new_element("maxfail", pnode, ni_sprint_uint(conf->maxfail));
	if (conf->holdoff != -1U)
		xml_node_new_element("holdoff", pnode, ni_sprint_uint(conf->holdoff));

	xml_node_new_element("multilink", pnode, ni_format_boolean(conf->multilink));
	if (!ni_string_empty(conf->endpoint))
		xml_node_new_element("endpoint", pnode, conf->endpoint);

	if ((node = xml_node_new("auth", NULL))) {
		if (!ni_string_empty(conf->auth.username))
			xml_node_new_element("username", node, conf->auth.username);
		if (!ni_string_empty(conf->auth.password))
			xml_node_new_element("password", node, conf->auth.password);

		if (node->children)
			xml_node_add_child(pnode, node);
		else
			xml_node_free(node);
	}

	xml_node_new_element("defaultroute", pnode, ni_format_boolean(conf->defaultroute));

	if ((node = xml_node_create(pnode, "dns"))) {
		xml_node_new_element("usepeerdns", node, ni_format_boolean(conf->dns.usepeerdns));

		if (ni_sockaddr_is_specified(&conf->dns.dns1))
			xml_node_new_element("dns1", node,
					ni_sockaddr_print(&conf->dns.dns1));
		if (ni_sockaddr_is_specified(&conf->dns.dns2))
			xml_node_new_element("dns2", node,
					ni_sockaddr_print(&conf->dns.dns2));
	}

	if ((node = xml_node_new("ipv4", NULL))) {
		xml_node_t *ipcp;

		if (ni_sockaddr_is_specified(&conf->ipv4.local_ip))
			xml_node_new_element("local-ip", node,
					ni_sockaddr_print(&conf->ipv4.local_ip));
		if (ni_sockaddr_is_specified(&conf->ipv4.remote_ip))
			xml_node_new_element("remote-ip", node,
					ni_sockaddr_print(&conf->ipv4.remote_ip));

		if ((ipcp = xml_node_new("ipcp", NULL))) {
			xml_node_new_element("accept-local", ipcp,
					ni_format_boolean(conf->ipv4.ipcp.accept_local));
			xml_node_new_element("accept-remote", ipcp,
					ni_format_boolean(conf->ipv4.ipcp.accept_remote));

			if (ipcp->children)
				xml_node_add_child(node, ipcp);
			else
				xml_node_free(ipcp);
		}
		if (node->children)
			xml_node_add_child(pnode, node);
		else
			xml_node_free(node);
	}

	if ((node = xml_node_new("ipv6", NULL))) {
		xml_node_t *ipcp;

		xml_node_new_element("enabled", node, ni_format_boolean(conf->ipv6.enabled));
		if (conf->ipv6.enabled) {
			if (ni_sockaddr_is_specified(&conf->ipv6.local_ip))
				xml_node_new_element("local-ip", node,
						ni_sockaddr_print(&conf->ipv6.local_ip));
			if (ni_sockaddr_is_specified(&conf->ipv6.remote_ip))
				xml_node_new_element("remote-ip", node,
						ni_sockaddr_print(&conf->ipv6.remote_ip));

			if ((ipcp = xml_node_new("ipcp", NULL))) {
				xml_node_new_element("accept-local", ipcp,
						ni_format_boolean(conf->ipv6.ipcp.accept_local));
				if (ipcp->children)
					xml_node_add_child(node, ipcp);
				else
					xml_node_free(ipcp);
			}
		}
		if (node->children)
			xml_node_add_child(pnode, node);
		else
			xml_node_free(node);
	}

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_ovs_bridge_ports(xml_node_t *bnode, const ni_ovs_bridge_port_array_t *array)
{
	xml_node_t *ports;
	unsigned int i;

	if (!array || !bnode)
		return FALSE;

	if (!array->count)
		return TRUE;

	ports = xml_node_new("ports", bnode);
	for (i = 0; i < array->count; i++) {
		ni_ovs_bridge_port_t *p = array->data[i];
		xml_node_t *port;

		if (ni_string_empty(p->device.name))
			continue;

		port = xml_node_new("port", ports);
		xml_node_new_element("device", port, p->device.name);
	}
	return TRUE;
}

static ni_bool_t
__ni_compat_generate_ovs_bridge(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	const ni_ovs_bridge_t *ovsbr;
	xml_node_t *bnode;

	ovsbr = ni_netdev_get_ovs_bridge(compat->dev);
	bnode = xml_node_create(ifnode, "ovs-bridge");

	if (ovsbr->config.vlan.parent.name) {
		xml_node_t *vnode = xml_node_new("vlan", bnode);
		xml_node_new_element("parent", vnode, ovsbr->config.vlan.parent.name);
		xml_node_new_element_uint("tag", vnode, ovsbr->config.vlan.tag);
	} /* else? */
	if (!__ni_compat_generate_ovs_bridge_ports(bnode, &ovsbr->ports))
		return FALSE;

	return TRUE;
}

static ni_bool_t
__ni_compat_generate_bridge(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	const ni_netdev_t *dev = compat->dev;
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

	if (dev->link.hwaddr.len) {
		xml_node_new_element("address", child,
			ni_link_address_print(&dev->link.hwaddr));
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
__ni_compat_generate_vxlan(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	ni_vxlan_t *vxlan;
	xml_node_t *child;

	if (!(vxlan = ni_netdev_get_vxlan(compat->dev)))
		return FALSE;
	if (!(child = xml_node_create(ifnode, "vxlan")))
		return FALSE;

	/* netdev properties/relations */
	if (compat->dev->link.hwaddr.len)
		xml_node_new_element("address", child,
				ni_link_address_print(&compat->dev->link.hwaddr));
	if (!ni_string_empty(compat->dev->link.lowerdev.name))
		xml_node_new_element("device", child, compat->dev->link.lowerdev.name);

	/* vxlan specific properties */
	xml_node_new_element_uint("id", child, vxlan->id);

	if (ni_sockaddr_is_specified(&vxlan->local_ip))
		xml_node_new_element("local-ip", child, ni_sockaddr_print(&vxlan->local_ip));
	if (ni_sockaddr_is_specified(&vxlan->remote_ip))
		xml_node_new_element("remote-ip", child, ni_sockaddr_print(&vxlan->remote_ip));

	if (vxlan->src_port.low || vxlan->src_port.high) {
		xml_node_t *sport;
		if ((sport = xml_node_create(child, "src-port"))) {
			xml_node_new_element_uint("low",  sport, vxlan->src_port.low);
			xml_node_new_element_uint("high", sport, vxlan->src_port.high);
		}
	}
	if (vxlan->dst_port)
		xml_node_new_element_uint("dst-port", child, vxlan->dst_port);

	if (vxlan->ttl)
		xml_node_new_element_uint("ttl", child, vxlan->ttl);
	if (vxlan->tos)
		xml_node_new_element_uint("tos", child, vxlan->tos);

	if (vxlan->ageing)
		xml_node_new_element_uint("ageing", child, vxlan->ageing);
	if (vxlan->maxaddr)
		xml_node_new_element_uint("max-address", child, vxlan->maxaddr);

	if (!vxlan->learning)
		xml_node_new_element("learning", child, ni_format_boolean(vxlan->learning));
	if (vxlan->proxy)
		xml_node_new_element("proxy", child, ni_format_boolean(vxlan->proxy));
	if (vxlan->rsc)
		xml_node_new_element("rsc", child, ni_format_boolean(vxlan->rsc));
	if (vxlan->l2miss)
		xml_node_new_element("l2miss", child, ni_format_boolean(vxlan->l2miss));
	if (vxlan->l3miss)
		xml_node_new_element("l3miss", child, ni_format_boolean(vxlan->l3miss));

	if (vxlan->udp_csum)
		xml_node_new_element("udp-csum", child, ni_format_boolean(vxlan->udp_csum));
	if (vxlan->udp6_zero_csum_rx)
		xml_node_new_element("udp6-zero-csum-rx", child, ni_format_boolean(vxlan->udp6_zero_csum_rx));
	if (vxlan->udp6_zero_csum_tx)
		xml_node_new_element("udp6-zero-csum-tx", child, ni_format_boolean(vxlan->udp6_zero_csum_tx));

	if (vxlan->rem_csum_rx)
		xml_node_new_element("rem-csum-rx", child, ni_format_boolean(vxlan->rem_csum_rx));
	if (vxlan->rem_csum_tx)
		xml_node_new_element("rem-csum-tx", child, ni_format_boolean(vxlan->rem_csum_tx));
	if (!vxlan->rem_csum_partial)
		xml_node_new_element("rem-csum-partial", child, ni_format_boolean(vxlan->rem_csum_partial));

	if (vxlan->collect_metadata)
		xml_node_new_element("collect-metadata", child, ni_format_boolean(vxlan->collect_metadata));
	if (vxlan->gbp)
		xml_node_new_element("gpb", child, ni_format_boolean(vxlan->gbp));
	if (vxlan->gpe)
		xml_node_new_element("gpe", child, ni_format_boolean(vxlan->gpe));
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
			xml_node_new_element("essid", network, ni_wireless_print_ssid(&net->essid));
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

			if (NI_WIRELESS_EAP_PEAP == net->wpa_eap.method ||
			    NI_WIRELESS_EAP_NONE == net->wpa_eap.method) {
				if (net->wpa_eap.phase1.peapver != -1U) {
					ni_string_printf(&tmp, "%u", net->wpa_eap.phase1.peapver);
					xml_node_new_element("peap-version", phase1, tmp);
					ni_string_free(&tmp);
				}

				xml_node_new_element("peap-label", phase1,
					ni_format_boolean(net->wpa_eap.phase1.peaplabel));
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

	if (!ni_string_empty(link->lowerdev.name))
		xml_node_new_element("device", ifnode, link->lowerdev.name);

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
	ni_string_array_t flags = NI_STRING_ARRAY_INIT;
	ni_netdev_t *dev = compat->dev;
	xml_node_t *child, *encap;
	ni_gre_t *gre;
	ni_bool_t rv;
	char *str = NULL;

	if (!(gre = ni_netdev_get_gre(dev)))
		return FALSE;

	child = xml_node_create(ifnode, "gre");

	rv = __ni_compat_generate_generic_tunnel(child, &dev->link,
						&gre->tunnel);
	if (!rv)
		return rv;

	if (gre->flags & NI_BIT(NI_GRE_FLAG_ISEQ))
		ni_string_array_append(&flags, ni_gre_flag_bit_to_name(NI_GRE_FLAG_ISEQ));
	if (gre->flags & NI_BIT(NI_GRE_FLAG_ICSUM))
		ni_string_array_append(&flags, ni_gre_flag_bit_to_name(NI_GRE_FLAG_ICSUM));
	if (gre->flags & NI_BIT(NI_GRE_FLAG_OSEQ))
		ni_string_array_append(&flags, ni_gre_flag_bit_to_name(NI_GRE_FLAG_OSEQ));
	if (gre->flags & NI_BIT(NI_GRE_FLAG_OCSUM))
		ni_string_array_append(&flags, ni_gre_flag_bit_to_name(NI_GRE_FLAG_OCSUM));

	if (!ni_string_empty(ni_string_join(&str, &flags, ", ")))
		xml_node_new_element("flags", child, str);
	ni_string_array_destroy(&flags);
	ni_string_free(&str);

	if (gre->flags & NI_BIT(NI_GRE_FLAG_IKEY))
		xml_node_new_element("ikey", child, inet_ntoa(gre->ikey));
	if (gre->flags & NI_BIT(NI_GRE_FLAG_OKEY))
		xml_node_new_element("okey", child, inet_ntoa(gre->okey));

	if (gre->encap.type == NI_GRE_ENCAP_TYPE_NONE)
		return rv;

	if (!(encap = xml_node_create(child, "encap")))
		return FALSE;

	xml_node_new_element("type", encap, ni_gre_encap_type_to_name(gre->encap.type));
	if (gre->encap.flags & NI_BIT(NI_GRE_ENCAP_FLAG_CSUM))
		ni_string_array_append(&flags, ni_gre_encap_flag_bit_to_name(NI_GRE_ENCAP_FLAG_CSUM));
	if (gre->encap.flags & NI_BIT(NI_GRE_ENCAP_FLAG_CSUM6))
		ni_string_array_append(&flags, ni_gre_encap_flag_bit_to_name(NI_GRE_ENCAP_FLAG_CSUM6));
	if (gre->encap.flags & NI_BIT(NI_GRE_ENCAP_FLAG_REMCSUM))
		ni_string_array_append(&flags, ni_gre_encap_flag_bit_to_name(NI_GRE_ENCAP_FLAG_REMCSUM));

	if (!ni_string_empty(ni_string_join(&str, &flags, ", ")))
		xml_node_new_element("flags", encap, str);
	ni_string_array_destroy(&flags);
	ni_string_free(&str);

	if (gre->encap.sport)
		xml_node_new_element_uint("sport", encap, gre->encap.sport);
	if (gre->encap.dport)
		xml_node_new_element_uint("dport", encap, gre->encap.dport);

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
		xml_node_new_element("pref-source", rnode, ni_sockaddr_print(&rp->pref_src));
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
__ni_compat_generate_static_rule_match(xml_node_t *rnode, const ni_rule_t *rule, const char *ifname)
{
	xml_node_t *node;

	node = xml_node_new("match", NULL);

	if (rule->set & NI_RULE_SET_PREF)
		xml_node_new_element_uint("priority", node, rule->pref);

	if (rule->flags & NI_BIT(NI_RULE_INVERT))
		xml_node_new_element("invert", node, "true");

	if (!ni_sockaddr_is_unspecified(&rule->src.addr))
		xml_node_new_element("from", node,
			ni_sockaddr_prefix_print(&rule->src.addr, rule->src.len));

	if (!ni_sockaddr_is_unspecified(&rule->dst.addr))
		xml_node_new_element("to", node,
			ni_sockaddr_prefix_print(&rule->dst.addr, rule->dst.len));

	if (!ni_string_empty(rule->iif.name))
		xml_node_new_element("iif", node, rule->iif.name);

	if (!ni_string_empty(rule->oif.name))
		xml_node_new_element("oif", node, rule->oif.name);

	if (rule->fwmark)
		xml_node_new_element_uint("fwmark", node, rule->fwmark);

	if (rule->fwmask && rule->fwmask != -1U)
		xml_node_new_element_uint("fwmask", node, rule->fwmask);

	if (rule->tos)
		xml_node_new_element_uint("tos", node, rule->tos);

	if (node->children || node->attrs.count || node->cdata)
		xml_node_add_child(rnode, node);
	else
		xml_node_free(node);
}

static void
__ni_compat_generate_static_rule_action(xml_node_t *rnode, const ni_rule_t *rule, const char *ifname)
{
	xml_node_t *node;
	char *tmp = NULL;

	node = xml_node_new("action", NULL);

	xml_node_new_element("type", node, ni_rule_action_type_to_name(rule->action));

	if (rule->table != RT_TABLE_UNSPEC && rule->table != RT_TABLE_MAIN) {
		if (ni_route_table_type_to_name(rule->table, &tmp))
			xml_node_new_element("table", node, tmp);
		ni_string_free(&tmp);
	}

	if (rule->target)
		xml_node_new_element_uint("target", node, rule->target);
	if (rule->realm)
		xml_node_new_element_uint("realm", node, rule->realm);

	if (node->children || node->attrs.count || node->cdata)
		xml_node_add_child(rnode, node);
	else
		xml_node_free(node);
}

static void
__ni_compat_generate_static_rule_suppress(xml_node_t *rnode, const ni_rule_t *rule, const char *ifname)
{
	xml_node_t *node;

	node = xml_node_new("suppress", NULL);

	if (rule->suppress_prefixlen != -1U)
		xml_node_new_element_uint("prefix-length", node, rule->suppress_prefixlen);

	if (rule->suppress_ifgroup != -1U)
		xml_node_new_element_uint("if-group", node, rule->suppress_ifgroup);

	if (node->children || node->attrs.count || node->cdata)
		xml_node_add_child(rnode, node);
	else
		xml_node_free(node);
}

static void
__ni_compat_generate_static_rule(xml_node_t *aconf, const ni_rule_t *r, const char *ifname)
{
	xml_node_t *rnode;

	if (!aconf || !r || !r->family || !r->action)
		return;

	if (!(rnode = xml_node_new("rule", aconf)))
		return;

	__ni_compat_generate_static_rule_match(rnode, r, ifname);
	__ni_compat_generate_static_rule_action(rnode, r, ifname);
	__ni_compat_generate_static_rule_suppress(rnode, r, ifname);
}

static void
__ni_compat_generate_static_rule_list(xml_node_t *afnode, const ni_rule_array_t *rules, const char *ifname, unsigned int af)
{
	const ni_rule_t *r;
	unsigned int i;

	if (!afnode || !rules || !af)
		return;

	for (i = 0; i < rules->count; ++i) {
		r = rules->data[i];
		if (!r || r->family != af)
			continue;
		__ni_compat_generate_static_rule(afnode, r, ifname);
	}
}

static void
__ni_compat_generate_static_address_list(xml_node_t *afnode, ni_address_t *addr_list, unsigned int af)
{
	ni_address_t *ap;
	xml_node_t *anode;
	const char *ptr;

	for (ap = addr_list; ap; ap = ap->next) {
		if (ap->family != af)
			continue;

		anode = xml_node_new("address", afnode);
		xml_node_new_element("local", anode, ni_sockaddr_prefix_print(&ap->local_addr, ap->prefixlen));

		if (ap->peer_addr.ss_family == af)
			xml_node_new_element("peer", anode, ni_sockaddr_print(&ap->peer_addr));
		if (ap->bcast_addr.ss_family == af && af == AF_INET)
			xml_node_new_element("broadcast", anode, ni_sockaddr_print(&ap->bcast_addr));
		if (af == AF_INET && ap->label)
			xml_node_new_element("label", anode, ap->label);

		if (ap->scope >= 0 && (ptr = ni_route_scope_type_to_name(ap->scope)))
			xml_node_new_element("scope", anode, ptr);

		if (ap->flags)
			xml_node_new_element_uint("flags", anode, ap->flags);

		/* We are applying static address, but at least valid_lft = infinite,
		 * preferred_lft = 0 is a valid case to apply deprecated addresses...
		 */
		if (ap->cache_info.preferred_lft != NI_LIFETIME_INFINITE) {
			xml_node_t *cache_info = xml_node_new("cache-info", anode);
			if (cache_info) {
				xml_node_new_element_uint("valid-lifetime", cache_info,
							ap->cache_info.valid_lft);
				xml_node_new_element_uint("preferred-lifetime", cache_info,
							ap->cache_info.preferred_lft);
			}
		}
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
	__ni_compat_generate_static_rule_list(afnode, &compat->rules, dev->name, af);

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

static xml_node_t *
__ni_compat_generate_dhcp_fqdn(xml_node_t *dhcp, const ni_dhcp_fqdn_t *fqdn, unsigned int family, ni_bool_t update)
{
	ni_dhcp_fqdn_t dflt;
	xml_node_t *node;

	node = xml_node_new("fqdn", NULL);

	ni_dhcp_fqdn_init(&dflt);
	if (fqdn->enabled != dflt.enabled)
		xml_node_new_element("enabled", node, ni_format_boolean(fqdn->enabled));

	if (fqdn->enabled != NI_TRISTATE_DISABLE) {
		if (fqdn->qualify != dflt.qualify)
			xml_node_new_element("qualify", node, ni_format_boolean(FALSE));

		if (update && fqdn->update != dflt.update)
			xml_node_new_element("update", node, ni_dhcp_fqdn_update_mode_to_name(fqdn->update));

		if (family == AF_INET && fqdn->encode != dflt.encode)
			xml_node_new_element("encode", node, ni_format_boolean(FALSE));
	}

	if (node->children) {
		xml_node_add_child(dhcp, node);
	} else {
		xml_node_free(node);
	}
	return node;
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

	__ni_compat_generate_dhcp_fqdn(dhcp, &compat->dhcp4.fqdn, AF_INET,
						!!compat->dhcp4.hostname);

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

	if (compat->dhcp4.broadcast != NI_TRISTATE_DEFAULT)
		xml_node_dict_set(dhcp, "broadcast",
				ni_format_boolean(compat->dhcp4.broadcast));

	if (compat->dhcp4.client_id)
		xml_node_dict_set(dhcp, "client-id", compat->dhcp4.client_id);
	if (compat->dhcp4.vendor_class)
		xml_node_dict_set(dhcp, "vendor-class", compat->dhcp4.vendor_class);

	if (compat->dhcp4.user_class.class_id.count) {
		__ni_compat_generate_dhcp4_user_class(dhcp, &compat->dhcp4.user_class);
	}

	if (compat->dhcp4.request_options.count) {
		xml_node_t *req;
		unsigned int i;

		req = xml_node_new("request-options", NULL);
		for (i = 0; req && i < compat->dhcp4.request_options.count; ++i) {
			const char *opt = compat->dhcp4.request_options.data[i];
			xml_node_new_element("option", req, opt);
		}
		if (req->children) {
			xml_node_add_child(dhcp, req);
		} else {
			xml_node_free(req);
		}
	}

	return dhcp;
}

static xml_node_t *
__ni_compat_generate_auto4_addrconf(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	if (!compat->auto4.enabled)
		return NULL;

	return __ni_compat_generate_dynamic_addrconf(ifnode, "ipv4:auto",
			compat->auto4.flags, 0);
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

	if (compat->dhcp6.address_len) {
		xml_node_dict_set(dhcp, "address-length",
				ni_sprint_uint(compat->dhcp6.address_len));
	}

	xml_node_dict_set(dhcp, "rapid-commit",
			ni_format_boolean(compat->dhcp6.rapid_commit));

	if (compat->dhcp6.hostname)
		xml_node_dict_set(dhcp, "hostname", compat->dhcp6.hostname);

	__ni_compat_generate_dhcp_fqdn(dhcp, &compat->dhcp6.fqdn, AF_INET6,
					!!compat->dhcp6.hostname);

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

	if (compat->dhcp6.request_options.count) {
		xml_node_t *req;
		unsigned int i;

		req = xml_node_new("request-options", NULL);
		for (i = 0; req && i < compat->dhcp6.request_options.count; ++i) {
			const char *opt = compat->dhcp6.request_options.data[i];
			xml_node_new_element("option", req, opt);
		}
		if (req->children) {
			xml_node_add_child(dhcp, req);
		} else {
			xml_node_free(req);
		}
	}

	return dhcp;
}

static xml_node_t *
__ni_compat_generate_auto6_addrconf(xml_node_t *ifnode, const ni_compat_netdev_t *compat)
{
	xml_node_t *aconf;

	if (!compat->auto6.enabled)
		return NULL;

	aconf = __ni_compat_generate_dynamic_addrconf(ifnode, "ipv6:auto", 0, compat->auto6.update);

	if (aconf && compat->auto6.defer_timeout != -1U) {
		xml_node_dict_set(aconf, "defer-timeout",
				ni_sprint_timeout(compat->auto6.defer_timeout));
	}

	return aconf;
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
	case NI_IFTYPE_VXLAN:
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
ni_compat_generate_ethtool_link_advertise(xml_node_t *parent, const ni_bitfield_t *bitfield)
{
	ni_bitfield_t unknown = NI_BITFIELD_INIT;
	unsigned int bit, bits;
	xml_node_t *node;
	const char *name;
	char *hex = NULL;

	if (!parent || !ni_bitfield_isset(bitfield))
		return FALSE;

	if (!(node = xml_node_new("advertise", NULL)))
		return FALSE;

	bits = ni_bitfield_bits(bitfield);
	for (bit = 0; bit < bits; ++bit) {
		if (!ni_bitfield_testbit(bitfield, bit))
			continue;

		if ((name = ni_ethtool_link_adv_name(bit)))
			xml_node_new_element("mode", node, name);
		else
			ni_bitfield_setbit(&unknown, bit);
	}

	if (ni_bitfield_isset(&unknown)) {
		ni_bitfield_format(&unknown, &hex, FALSE);
		xml_node_new_element("mode", node, hex);
		ni_string_free(&hex);
	}
	ni_bitfield_destroy(&unknown);

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);
	return TRUE;
}

static void
ni_compat_generate_ethtool_link(xml_node_t *parent, const ni_ethtool_link_settings_t *link)
{
	xml_node_t *node;
	const char *ptr;

	if (!parent || !link || !(node = xml_node_new("link-settings", NULL)))
		return;

	__ni_compat_optional_tristate("autoneg", node, link->autoneg);

	if (link->speed != NI_ETHTOOL_SPEED_UNKNOWN)
		xml_node_new_element_uint("speed", node, link->speed);

	if (link->port != NI_ETHTOOL_PORT_DEFAULT &&
	    (ptr = ni_ethtool_link_port_name(link->port))) {
		xml_node_new_element("port", node, ptr);
	}

	if (link->duplex !=  NI_ETHTOOL_DUPLEX_UNKNOWN &&
	    (ptr = ni_ethtool_link_duplex_name(link->duplex))) {
		xml_node_new_element("duplex", node, ptr);
	}

	if (link->tp_mdix != NI_ETHTOOL_MDI_INVALID)
		xml_node_new_element_uint("mdix", node, link->tp_mdix);
	if (link->phy_address != NI_ETHTOOL_PHYAD_UNKNOWN)
		xml_node_new_element_uint("phy-address", node, link->phy_address);
	if (link->transceiver != NI_ETHTOOL_XCVR_UNKNOWN)
		xml_node_new_element_uint("transceiver", node, link->transceiver);

	ni_compat_generate_ethtool_link_advertise(node, &link->advertising);

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);
	return;
}

static void
ni_compat_generate_ethtool_priv(xml_node_t *parent, const ni_ethtool_priv_flags_t *priv)
{
	xml_node_t *node;
	int i;
	int priv_count;

	if (!parent || !priv || !(node = xml_node_new("private-flags", NULL)))
		return;

	priv_count = priv->names.count;
	for (i = 0; i < priv_count; ++i) {
		const char *name = priv->names.data[i];
		if (ni_string_empty(name))
			continue;
		xml_node_t *flag = xml_node_new("flag", node);
		xml_node_new_element("name", flag, name);
		xml_node_new_element("enabled", flag, ni_format_boolean(priv->bitmap & NI_BIT(i)));
	}

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);
	return;
}

static void
ni_compat_generate_ethtool_wol(xml_node_t *parent, const ni_ethtool_wake_on_lan_t *wol)
{
	xml_node_t *node;
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

	if (!parent || !wol || !(node = xml_node_new("wake-on-lan", NULL)))
		return;

	ni_ethtool_wol_flags_format(&buf, wol->options, ", ");
	xml_node_new_element("options", node, buf.string);

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);

	ni_stringbuf_destroy(&buf);
	return;

}

static void
ni_compat_generate_ethtool_features(xml_node_t *parent, const ni_ethtool_features_t *features)
{
	xml_node_t *node;
	const ni_ethtool_feature_t *feature;
	int i;
	int count;

	if (!parent || !features || !(node = xml_node_new("features", NULL)))
		return;

	count = features->count;
	for (i = 0; i < count; ++i) {
		const char *ptr;

		if (!(feature = features->data[i]))
			continue;

		ptr = ni_format_boolean(feature->value & NI_ETHTOOL_FEATURE_ON);
		xml_node_t *feature_node = xml_node_new("feature", node);
		xml_node_new_element("name", feature_node, feature->map.name);
		xml_node_new_element("enabled", feature_node, ptr);
	}

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);

	return;
}

static void
ni_compat_generate_ethtool(xml_node_t *parent, const ni_compat_netdev_t *compat)
{
	const ni_ethtool_t *ethtool;
	xml_node_t *node;

	if (!compat || !compat->dev || !(ethtool = compat->dev->ethtool))
		return;

	if (!(node = xml_node_new("ethtool", NULL)))
		return;

	ni_compat_generate_ethtool_link(node, ethtool->link_settings);
	ni_compat_generate_ethtool_priv(node, ethtool->priv_flags);
	ni_compat_generate_ethtool_wol(node, ethtool->wake_on_lan);
	ni_compat_generate_ethtool_features(node, ethtool->features);

	ni_compat_generate_ethtool_eee(node, ethtool->eee);
	ni_compat_generate_ethtool_channels(node, ethtool->channels);
	ni_compat_generate_ethtool_ring(node, ethtool->ring);
	ni_compat_generate_ethtool_coalesce(node, ethtool->coalesce);
	ni_compat_generate_ethtool_pause(node, ethtool->pause);

	if (node->children)
		xml_node_add_child(parent, node);
	else
		xml_node_free(node);
	return;
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

		if (control->link_timeout || control->link_priority || ni_tristate_is_set(control->link_required)) {
			linkdet = xml_node_create(child, "link-detection");
			if (linkdet) {
				if (ni_tristate_is_set(control->link_required)) {
					xml_node_new_element("require-link", linkdet,
						ni_format_boolean(ni_tristate_is_enabled(control->link_required)));
				}
				if (control->link_timeout) {
					xml_node_new_element("timeout", linkdet,
						ni_sprint_timeout(control->link_timeout));
				}
			}
		}
	}
	if (compat->scripts.count) {
		const ni_var_t *var;
		xml_node_t *snode;
		unsigned int i, j;

		snode = xml_node_create(ifnode, "scripts");
		for (i = 0, var = compat->scripts.data; i < compat->scripts.count; ++i, ++var) {
			ni_string_array_t scripts = NI_STRING_ARRAY_INIT;
			xml_node_t *tnode;

			if (ni_string_empty(var->value) || ni_string_empty(var->name))
				continue;

			if (ni_string_split(&scripts, var->value, " ", 0)) {
				tnode = xml_node_create(snode, var->name);
				for (j = 0; j < scripts.count; ++j) {
					const char *script = scripts.data[j];
					xml_node_new_element("script", tnode, script);
				}
			}
			ni_string_array_destroy(&scripts);
		}
	}
	if (compat->firewall.enabled) {
		xml_node_t *fw;

		if ((fw = xml_node_create(ifnode, "firewall"))) {
			if (!ni_string_empty(compat->firewall.zone))
				xml_node_new_element("zone", fw, compat->firewall.zone);
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

	case NI_IFTYPE_PPP:
		__ni_compat_generate_ppp(ifnode, compat);
		break;

	case NI_IFTYPE_TEAM:
		__ni_compat_generate_team(ifnode, compat);
		break;

	case NI_IFTYPE_OVS_BRIDGE:
		__ni_compat_generate_ovs_bridge(ifnode, compat);
		break;

	case NI_IFTYPE_BRIDGE:
		__ni_compat_generate_bridge(ifnode, compat);
		break;

	case NI_IFTYPE_VLAN:
		__ni_compat_generate_vlan(ifnode, compat);
		break;

	case NI_IFTYPE_VXLAN:
		__ni_compat_generate_vxlan(ifnode, compat);
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
	if (dev->link.masterdev.name) {
		xml_node_t *port;

		xml_node_new_element("master", linknode, dev->link.masterdev.name);
		if (compat->link_port.ovsbr.bridge.name) {
			port = xml_node_new("port", linknode);
			xml_node_add_attr(port, "type", ni_linktype_type_to_name(NI_IFTYPE_OVS_BRIDGE));
			xml_node_new_element("bridge", port, compat->link_port.ovsbr.bridge.name);
		}
	}
	if (dev->link.mtu)
		xml_node_new_element("mtu", linknode, ni_sprint_uint(dev->link.mtu));

	__ni_compat_generate_ipv4_devconf(ifnode, dev->ipv4, dev->link.type);
	if (dev->ipv4 && !ni_tristate_is_disabled(dev->ipv4->conf.enabled)) {
		__ni_compat_generate_dhcp4_addrconf(ifnode, compat);
		__ni_compat_generate_auto4_addrconf(ifnode, compat);
		__ni_compat_generate_static_addrconf(ifnode, compat, AF_INET);
	}

	__ni_compat_generate_ipv6_devconf(ifnode, dev->ipv6);
	if (dev->ipv6 && !ni_tristate_is_disabled(dev->ipv6->conf.enabled)) {
		__ni_compat_generate_dhcp6_addrconf(ifnode, compat);
		__ni_compat_generate_auto6_addrconf(ifnode, compat);
		__ni_compat_generate_static_addrconf(ifnode, compat, AF_INET6);
	}

	if (dev->ethtool)
		ni_compat_generate_ethtool(ifnode, compat);

	return TRUE;
}

static xml_node_t *
ni_compat_generate_ifcfg(const ni_compat_netdev_t *compat, xml_document_t *doc)
{
	xml_node_t *ifnode, *namenode;

	ifnode = xml_node_new("interface", xml_document_root(doc));

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
	xml_node_t *root;
	unsigned int i;

	if (!ifcfg)
		return 0;

	for (i = 0; i < ifcfg->netdevs.count; ++i) {
		ni_compat_netdev_t *compat = ifcfg->netdevs.data[i];
		ni_client_state_t *cs = ni_netdev_get_client_state(compat->dev);
		ni_client_state_config_t *conf = &cs->config;

		config_doc = xml_document_new();
		root = xml_document_root(config_doc);

		if (ni_string_empty(conf->origin))
			ni_string_dup(&conf->origin, ifcfg->schema);

		ni_compat_generate_ifcfg(compat, config_doc);
		if (!raw)
			ni_ifconfig_metadata_add_to_node(root, conf);

		xml_node_location_relocate(root, conf->origin);

		if (ni_ifconfig_validate_adding_doc(config_doc, check_prio)) {
			ni_debug_ifconfig("%s: %s", __func__, xml_node_location(root));
			xml_document_array_append(array, config_doc);
		} else {
			xml_document_free(config_doc);
		}
	}

	return i;
}
