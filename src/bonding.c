/*
 * Routines for handling bonding devices
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <limits.h>

#include <wicked/netinfo.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "sysfs.h"
#include "modprobe.h"

/*
 * Slave array (re)allocation chunk
 */
#define NI_BONDING_SLAVE_ARRAY_CHUNK		4


/*
 * Kernel module and default parameter.
 *
 * The max_bonds=0 parameter is used by default to avoid automatic
 * "bond0" interface creation at load time. We may need another one.
 */
#ifndef BONDING_MODULE_NAME
#define BONDING_MODULE_NAME "bonding"
#endif
#ifndef BONDING_MODULE_OPTS
#define BONDING_MODULE_OPTS "max_bonds=0"
#endif


/*
 * Maps of kernel/sysctl named bonding option settings
 */
static const ni_intmap_t	__map_kern_mode[] = {
	{ "balance-rr",		NI_BOND_MODE_BALANCE_RR    },
	{ "active-backup",	NI_BOND_MODE_ACTIVE_BACKUP },
	{ "balance-xor",	NI_BOND_MODE_BALANCE_XOR   },
	{ "broadcast",		NI_BOND_MODE_BROADCAST     },
	{ "802.3ad",		NI_BOND_MODE_802_3AD       },
	{ "balance-tlb",	NI_BOND_MODE_BALANCE_TLB   },
	{ "balance-alb",	NI_BOND_MODE_BALANCE_ALB   },
	{ NULL }
};
static const ni_intmap_t	__map_kern_arp_validate[] = {
	{ "none",		NI_BOND_ARP_VALIDATE_NONE   },
	{ "active",		NI_BOND_ARP_VALIDATE_ACTIVE },
	{ "backup",		NI_BOND_ARP_VALIDATE_BACKUP },
	{ "all",		NI_BOND_ARP_VALIDATE_ALL    },
	{ "filter",		NI_BOND_ARP_VALIDATE_FILTER        },
	{ "filter_active",	NI_BOND_ARP_VALIDATE_FILTER_ACTIVE },
	{ "filter_backup",	NI_BOND_ARP_VALIDATE_FILTER_BACKUP },
	{ NULL }
};
static const ni_intmap_t	__map_kern_arp_all_targets[] = {
	{ "any",		NI_BOND_ARP_VALIDATE_TARGETS_ANY },
	{ "all",		NI_BOND_ARP_VALIDATE_TARGETS_ALL },
	{ NULL }
};
static const ni_intmap_t	__map_kern_xmit_hash_policy[] = {
	{ "layer2",		NI_BOND_XMIT_HASH_LAYER2   },
	{ "layer2+3",		NI_BOND_XMIT_HASH_LAYER2_3 },
	{ "layer3+4",		NI_BOND_XMIT_HASH_LAYER3_4 },
	{ "encap2+3",		NI_BOND_XMIT_HASH_ENCAP2_3 },
	{ "encap3+4",		NI_BOND_XMIT_HASH_ENCAP3_4 },
	{ NULL }
};
static const ni_intmap_t	__map_kern_lacp_rate[] = {
	{ "slow",		NI_BOND_LACP_RATE_SLOW },
	{ "fast",		NI_BOND_LACP_RATE_FAST },
	{ NULL }
};
static const ni_intmap_t	__map_kern_ad_select[] = {
	{ "stable",		NI_BOND_AD_SELECT_STABLE    },
	{ "bandwidth",		NI_BOND_AD_SELECT_BANDWIDTH },
	{ "count",		NI_BOND_AD_SELECT_COUNT     },
	{ NULL }
};
static const ni_intmap_t	__map_kern_fail_over_mac[] = {
	{ "none",		NI_BOND_FAIL_OVER_MAC_NONE   },
	{ "active",		NI_BOND_FAIL_OVER_MAC_ACTIVE },
	{ "follow",		NI_BOND_FAIL_OVER_MAC_FOLLOW },
	{ NULL }
};
static const ni_intmap_t	__map_kern_primary_reselect[] = {
	{ "always",		NI_BOND_PRIMARY_RESELECT_ALWAYS  },
	{ "better",		NI_BOND_PRIMARY_RESELECT_BETTER  },
	{ "failure",		NI_BOND_PRIMARY_RESELECT_FAILURE },
	{ NULL }
};

/*
 * For now, the enum names in the xml schema use almost the same mode names as
 * the kernel. 802.3ad being the notable exception, as starts with a digit,
 * which is illegal in xml element names.
 */
static const ni_intmap_t	__map_user_mode[] = {
	{ "balance-rr",		NI_BOND_MODE_BALANCE_RR    },
	{ "active-backup",	NI_BOND_MODE_ACTIVE_BACKUP },
	{ "balance-xor",	NI_BOND_MODE_BALANCE_XOR   },
	{ "broadcast",		NI_BOND_MODE_BROADCAST     },
	{ "ieee802-3ad",	NI_BOND_MODE_802_3AD       },
	{ "balance-tlb",	NI_BOND_MODE_BALANCE_TLB   },
	{ "balance-alb",	NI_BOND_MODE_BALANCE_ALB   },
	{ NULL }
};
/*
 * The kernel's xmit hash policies contain a + character.
 */
static const ni_intmap_t	__map_user_xmit_hash_policy[] = {
	{ "layer2",		NI_BOND_XMIT_HASH_LAYER2   },
	{ "layer23",		NI_BOND_XMIT_HASH_LAYER2_3 },
	{ "layer34",		NI_BOND_XMIT_HASH_LAYER3_4 },
	{ "encap23",		NI_BOND_XMIT_HASH_ENCAP2_3 },
	{ "encap34",		NI_BOND_XMIT_HASH_ENCAP3_4 },
	{ NULL }
};
/*
 * This setting is used in the schema; the kernel wants use_carrier=0/1.
 */
static const ni_intmap_t	__map_user_carrier_detect[] = {
	{ "ioctl",		NI_BOND_MII_CARRIER_DETECT_IOCTL },
	{ "netif",		NI_BOND_MII_CARRIER_DETECT_NETIF },
	{ NULL }
};

/*
 * Bonding slave state and mii_status maps
 */
static const ni_intmap_t	ni_bonding_slave_state_map[] = {
	{ "active",		NI_BOND_SLAVE_STATE_ACTIVE	},
	{ "backup",		NI_BOND_SLAVE_STATE_BACKUP	},

	{ NULL,			-1U				}
};
static const ni_intmap_t	ni_bonding_slave_mii_status_map[] = {
	{ "up",			NI_BOND_SLAVE_LINK_UP		},
	{ "fail",		NI_BOND_SLAVE_LINK_FAIL		},
	{ "down",		NI_BOND_SLAVE_LINK_DOWN		},
	{ "back",		NI_BOND_SLAVE_LINK_BACK		},

	{ NULL,			-1U				}
};

/*
 * Load bonding module with specified arguments.
 *
 * Default is max_bonds=1 that automatically creates a bond0
 * interface. We use max_bonds=0 option as default to avoid
 * an automatic bond0 interface creation. They're requested
 * explicitly by the factory, which may need another name.
 */
int
ni_bonding_load(const char *options)
{
	if (options == NULL)
		options = BONDING_MODULE_OPTS;

	return ni_modprobe(BONDING_MODULE_NAME, options);
}

/*
 * Initialize defaults
 */
static inline void
__ni_bonding_init(ni_bonding_t *bonding)
{
	/* Apply non-zero kernel defaults */
	bonding->miimon.carrier_detect = NI_BOND_MII_CARRIER_DETECT_NETIF;
	bonding->num_grat_arp = 1;
	bonding->num_unsol_na = 1;
	bonding->resend_igmp = 1;
	bonding->packets_per_slave = 1;
	bonding->tlb_dynamic_lb = TRUE;
	bonding->lp_interval = 1;
	bonding->ad_actor_sys_prio = 65535;
	ni_link_address_init(&bonding->ad_actor_system);
}

/*
 * Reinitialize the bonding configuration
 */
static inline void
__ni_bonding_clear(ni_bonding_t *bonding)
{
	ni_netdev_ref_destroy(&bonding->primary_slave);
	ni_netdev_ref_destroy(&bonding->active_slave);
	ni_bonding_slave_array_destroy(&bonding->slaves);
	ni_string_array_destroy(&bonding->arpmon.targets);
	memset(bonding, 0, sizeof(*bonding));

	__ni_bonding_init(bonding);
}

/*
 * Create a bonding config
 */
ni_bonding_t *
ni_bonding_new(void)
{
	ni_bonding_t *bonding;

	bonding = xcalloc(1, sizeof(ni_bonding_t));
	__ni_bonding_init(bonding);

	return bonding;
}

ni_bonding_t *
ni_bonding_clone(const ni_bonding_t *orig)
{
	ni_bonding_t *bond;
	unsigned int i;

	if (!orig || !(bond = ni_bonding_new()))
		return NULL;

#define C(x)	bond->x = orig->x
	C(mode);
	C(monitoring);

	C(arpmon.interval);
	C(arpmon.validate);
	C(arpmon.validate_targets);
	ni_string_array_copy(&bond->arpmon.targets, &orig->arpmon.targets);

	C(miimon.frequency);
	C(miimon.updelay);
	C(miimon.downdelay);
	C(miimon.carrier_detect);

	C(xmit_hash_policy);
	C(lacp_rate);
	C(ad_select);
	C(min_links);
	C(resend_igmp);
	C(num_grat_arp);
	C(num_unsol_na);
	C(fail_over_mac);
	C(primary_reselect);
	C(all_slaves_active);
	C(packets_per_slave);
	C(tlb_dynamic_lb);
	C(lp_interval);

	C(ad_user_port_key);
	C(ad_actor_sys_prio);
	memcpy(&bond->ad_actor_system, &orig->ad_actor_system,
			sizeof(bond->ad_actor_system));
	C(ad_info.aggregator_id);
	C(ad_info.ports);
	C(ad_info.actor_key);
	C(ad_info.partner_key);
	memcpy(&bond->ad_info.partner_mac, &orig->ad_info.partner_mac,
			sizeof(bond->ad_info.partner_mac));

	ni_netdev_ref_set(&bond->primary_slave, orig->primary_slave.name,
						orig->primary_slave.index);
	ni_netdev_ref_set(&bond->active_slave,  orig->active_slave.name,
						orig->active_slave.index);

	for (i = 0; i < orig->slaves.count; ++i) {
		const ni_bonding_slave_t *o = orig->slaves.data[i];
		ni_bonding_slave_t *s = ni_bonding_slave_new();
		ni_netdev_ref_set(&s->device, o->device.name, o->device.index);
		s->info = ni_bonding_slave_info_ref(o->info);
		ni_bonding_slave_array_append(&bond->slaves, s);
	}
#undef C

	return bond;
}

/*
 * Free bonding configuration
 */
void
ni_bonding_free(ni_bonding_t *bonding)
{
	__ni_bonding_clear(bonding);
	free(bonding);
}

/*
 * Check whether the given bonding settings are valid
 */
const char *
ni_bonding_validate(const ni_bonding_t *bonding)
{
	unsigned int i;

	if (bonding == NULL)
		return "uninitialized bonding options";

	switch (bonding->mode) {
	case NI_BOND_MODE_BALANCE_RR:
	case NI_BOND_MODE_ACTIVE_BACKUP:
	case NI_BOND_MODE_BALANCE_XOR:
	case NI_BOND_MODE_BROADCAST:
	case NI_BOND_MODE_802_3AD:
	case NI_BOND_MODE_BALANCE_TLB:
	case NI_BOND_MODE_BALANCE_ALB:
		break;

	default:
		return "unsupported bonding mode";
	}

	/*
	 * Bonding without monitoring is nonsense/unsupported:
	 *
	 * "[...] It is critical that either the miimon or arp_interval and
	 *  arp_ip_target parameters be specified, otherwise serious network
	 *  degradation will occur during link failures. [...]"
	 *
	 * While miimon can be used in any mode, arpmon is not usable in
	 * balance-tlb/-alb and arp-validate limited to active-bacup only.
	 */
	switch (bonding->monitoring) {
	case NI_BOND_MONITOR_ARP:
		if (bonding->miimon.frequency > 0)
			return "invalid arp and mii monitoring option mix";

		switch(bonding->mode) {
		case NI_BOND_MODE_802_3AD:
		case NI_BOND_MODE_BALANCE_TLB:
		case NI_BOND_MODE_BALANCE_ALB:
			return "invalid arp monitoring in balance-tlb/-alb or 802.3ad mode";
		default:
			break;
		}

		if (bonding->arpmon.interval == 0 ||
		    bonding->arpmon.interval > INT_MAX)
			return "invalid arp monitoring interval";

		switch (bonding->arpmon.validate) {
		case NI_BOND_ARP_VALIDATE_NONE:
			break;
		case NI_BOND_ARP_VALIDATE_ACTIVE:
		case NI_BOND_ARP_VALIDATE_BACKUP:
		case NI_BOND_ARP_VALIDATE_ALL:
		case NI_BOND_ARP_VALIDATE_FILTER:
		case NI_BOND_ARP_VALIDATE_FILTER_ACTIVE:
		case NI_BOND_ARP_VALIDATE_FILTER_BACKUP:
			if (bonding->mode == NI_BOND_MODE_ACTIVE_BACKUP)
				break;
			return "arp validate is valid in active-backup mode only";
		default:
			return "invalid arp validate setting";
		}

		if (bonding->arpmon.targets.count == 0)
			return "no targets for arp monitoring";

		for (i = 0; i < bonding->arpmon.targets.count; ++i) {
			const char *target = bonding->arpmon.targets.data[i];
			if (!ni_bonding_is_valid_arp_ip_target(target))
				return "invalid arp ip target address";
		}
		break;

	case NI_BOND_MONITOR_MII:
		if (bonding->arpmon.interval > 0 ||
		    bonding->arpmon.targets.count > 0)
			return "invalid mii and arp monitoring option mix";

		if (bonding->miimon.frequency == 0)
			return "invalid mii monitoring frequency";

		/*
		 * Both should be a multiple of frequency and are rounded down
		 * with a warning from the kernel driver. That is, when they're
		 * smaller than miimon, they're rounded down to 0 / disabled.
		 */
		if (bonding->miimon.updelay > 0 &&
				(bonding->miimon.updelay < bonding->miimon.frequency))
			return "miimon updelay is smaller than frequency";
		if (bonding->miimon.downdelay > 0 &&
				(bonding->miimon.downdelay < bonding->miimon.frequency))
			return "miimon downdelay is smaller than frequency";

		switch (bonding->miimon.carrier_detect) {
		case NI_BOND_MII_CARRIER_DETECT_IOCTL:
		case NI_BOND_MII_CARRIER_DETECT_NETIF:
			break;
		default:
			return "invalid miimon carrier detect setting";
		}
		break;

	case NI_BOND_MONITOR_MII|NI_BOND_MONITOR_ARP:
		return "unsupported mii / arp monintoring mix";

	default:
		return "unsupported, insufficient monitoring settings";
	}

	switch(bonding->mode) {
	case NI_BOND_MODE_BALANCE_XOR:
	case NI_BOND_MODE_802_3AD:
		switch (bonding->xmit_hash_policy) {
		case NI_BOND_XMIT_HASH_LAYER2:
		case NI_BOND_XMIT_HASH_LAYER2_3:
		case NI_BOND_XMIT_HASH_LAYER3_4:
		case NI_BOND_XMIT_HASH_ENCAP2_3:
		case NI_BOND_XMIT_HASH_ENCAP3_4:
			break;
		default:
			return "unsupported xmit hash policy";
		}
		break;
	default:
		if (bonding->xmit_hash_policy != NI_BOND_XMIT_HASH_LAYER2)
			return "invalid xmit hash policy and mode combination";
	}

	if (bonding->mode == NI_BOND_MODE_802_3AD) {
		switch (bonding->lacp_rate) {
		case NI_BOND_LACP_RATE_SLOW:
		case NI_BOND_LACP_RATE_FAST:
			break;
		default:
			return "unsupported ieee802-3ad lacp-rate setting";
		}

		switch (bonding->ad_select) {
		case NI_BOND_AD_SELECT_STABLE:
		case NI_BOND_AD_SELECT_BANDWIDTH:
		case NI_BOND_AD_SELECT_COUNT:
			break;
		default:
			return "unsupported ieee802-3ad ad-select setting";
		}

		if (bonding->min_links > INT_MAX)
			return "ieee802-3ad min-links option not in range 0-INT_MAX";

		if (bonding->ad_user_port_key > 1023)
			return "ieee802-3ad user port key is not in range 0-1023";
		if (bonding->ad_actor_sys_prio < 1)
			return "ieee802-3ad actor system prio is not in range 1-65535";
		if (bonding->ad_actor_system.len &&
		    bonding->ad_actor_system.type != ARPHRD_ETHER &&
		    ni_link_address_is_invalid(&bonding->ad_actor_system))
			return "ieee802-3ad actor system is not a valid ethernet address";

	} else {
		if (bonding->lacp_rate != NI_BOND_LACP_RATE_SLOW)
			return "lacp rate only valid in ieee802-3ad mode";
		if (bonding->ad_select != NI_BOND_AD_SELECT_STABLE)
			return "ad-select only valid in ieee802-3ad mode";
		if (bonding->min_links > 0)
			return "min-links option valid only in ieee802-3ad mode";
	}

	switch (bonding->mode) {
	case NI_BOND_MODE_ACTIVE_BACKUP:
	case NI_BOND_MODE_BALANCE_RR:
	case NI_BOND_MODE_BALANCE_TLB:
	case NI_BOND_MODE_BALANCE_ALB:
		if (bonding->resend_igmp > 255)
			return "resend IGMP count not in range 0-255";
		break;
	default:
		if (bonding->resend_igmp > 1)
			return "resend IGMP count is not valid in this mode";
		break;
	}

	if (bonding->mode == NI_BOND_MODE_ACTIVE_BACKUP) {
		switch (bonding->fail_over_mac) {
		case NI_BOND_FAIL_OVER_MAC_NONE:
		case NI_BOND_FAIL_OVER_MAC_ACTIVE:
		case NI_BOND_FAIL_OVER_MAC_FOLLOW:
			break;
		default:
			return "unsupported fail-over-mac setting";
		}
		if (bonding->num_grat_arp > 255)
			return "gratuitous ARP count not in range 0-255";

		if (bonding->num_unsol_na > 255)
			return "unsolicited IPv6-NA count not in range 0-255";
	} else {
		if (bonding->fail_over_mac != NI_BOND_FAIL_OVER_MAC_NONE)
			return "fail-over-mac only valid in active-backup mode";
		if (bonding->num_grat_arp > 1)
			return "gratuitous ARP count valid in active-backup only ";
		if (bonding->num_unsol_na > 1)
			return "unsolicited IPv6-NA count valid in active-backup only";
	}

	switch (bonding->mode) {
	case NI_BOND_MODE_ACTIVE_BACKUP:
	case NI_BOND_MODE_BALANCE_TLB:
	case NI_BOND_MODE_BALANCE_ALB:
		switch (bonding->primary_reselect) {
		case NI_BOND_PRIMARY_RESELECT_ALWAYS:
		case NI_BOND_PRIMARY_RESELECT_BETTER:
		case NI_BOND_PRIMARY_RESELECT_FAILURE:
			break;
		default:
			return "unsupported primary reselect setting";
		}
		break;
	default:
		if (bonding->primary_reselect != NI_BOND_PRIMARY_RESELECT_ALWAYS)
			return "primary reselect is not supported in current bonding mode";
		if (bonding->primary_slave.name != NULL)
			return "primary slave is not supported in current bonding mode";
		if (bonding->active_slave.name != NULL)
			return "active slave is not supported in current bonding mode";
		break;
	}

	if (bonding->all_slaves_active > 1)
		return "invalid all slaves active flag";

	if (bonding->mode == NI_BOND_MODE_BALANCE_RR) {
		if (bonding->packets_per_slave > USHRT_MAX)
			return "packets per slave not in range 0..65535";
	} else {
		if (bonding->packets_per_slave != 1)
			return "packets per slave is valid in balance-rr mode only";
	}

	switch (bonding->mode) {
	case NI_BOND_MODE_BALANCE_TLB:
	case NI_BOND_MODE_BALANCE_ALB:
		if (!bonding->lp_interval || bonding->lp_interval > INT_MAX)
			return "lp interval not in range 1 - 0x7fffffff";
		break;
	default:
		break;
	}

	if (bonding->mode != NI_BOND_MODE_BALANCE_TLB) {
		if (!bonding->tlb_dynamic_lb)
			return "tlb dynamic lb 0 is valid in balance-tlb mode only";
	}

	return NULL;
}

ni_bool_t
ni_bonding_is_valid_arp_ip_target(const char *target)
{
	struct in_addr addr;

	if (!target || inet_pton(AF_INET, target, &addr) != 1)
		return FALSE;

	if (addr.s_addr == INADDR_ANY || addr.s_addr == INADDR_NONE)
		return FALSE;

#if 0	/* senseless, but the kernel does not check it either */
	if ((addr.s_addr >> 24) == IN_LOOPBACKNET)
		return FALSE;
#endif
	return TRUE;
}

/*
 * Copy the slave names into the name array
 */
void
ni_bonding_get_slave_names(const ni_bonding_t *bonding, ni_string_array_t *array)
{
	unsigned int i;

	if (!bonding || !array)
		return;

	ni_string_array_destroy(array);
	for (i = 0; i < bonding->slaves.count; ++i) {
		ni_bonding_slave_t *slave = bonding->slaves.data[i];

		if (!slave || ni_string_empty(slave->device.name))
			continue;

		ni_string_array_append(array, slave->device.name);
	}
}

/*
 * Report if the bond contains a slave device
 */
ni_bool_t
ni_bonding_has_slave(ni_bonding_t *bonding, const char *ifname)
{
	if (!bonding || ni_string_empty(ifname))
		return FALSE;

	return ni_bonding_slave_array_index_by_ifname(&bonding->slaves, ifname) != -1U;
}

/*
 * Add a slave device to the bond
 */
ni_bonding_slave_t *
ni_bonding_add_slave(ni_bonding_t *bonding, const char *ifname)
{
	ni_bonding_slave_t *slave;

	if (!bonding || ni_string_empty(ifname))
		return NULL;

	if ((slave = ni_bonding_slave_new())) {

		ni_netdev_ref_set_ifname(&slave->device, ifname);
		if (ni_bonding_slave_array_append(&bonding->slaves, slave))
			return slave;

		ni_bonding_slave_free(slave);
	}
	return NULL;
}

ni_bonding_slave_t *
ni_bonding_bind_slave(ni_bonding_t *bonding, const ni_netdev_ref_t *ref, const char *ifname)
{
	ni_bonding_slave_t *slave;

	if (!bonding || !ref || !ref->index || ni_string_empty(ref->name)) {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_EVENTS,
				"%s: bind of bonding slave %s[%u] skipped -- invalid args",
				ifname, ref ? ref->name : NULL, ref ? ref->index : 0);
		return NULL;
	}

	slave = ni_bonding_slave_array_get_by_ifindex(&bonding->slaves, ref->index);
	if (slave) {
		if (ni_string_eq(slave->device.name, ref->name)) {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
					"%s: bonding slave %s[%u] is up to date",
					ifname, slave->device.name, slave->device.index);
		} else {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
					"%s: rebind of bonding slave %s[%u] ifname to %s",
					ifname, slave->device.name, slave->device.index, ref->name);

			ni_netdev_ref_set_ifname(&slave->device, ref->name);
		}
		return slave;
	}

	slave = ni_bonding_slave_new();
	if (slave) {
		ni_netdev_ref_set(&slave->device, ref->name, ref->index);
		if (ni_bonding_slave_array_append(&bonding->slaves, slave)) {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
					"%s: bound new bonding slave %s[%u]",
					ifname, slave->device.name, slave->device.index);
			return slave;
		}

		ni_bonding_slave_free(slave);
	}

	ni_error("%s: unable to bind new slave %s[%u]", ifname, ref->name, ref->index);
	return NULL;
}

ni_bool_t
ni_bonding_unbind_slave(ni_bonding_t *bonding, const ni_netdev_ref_t *ref, const char *ifname)
{
	const ni_bonding_slave_t *slave;
	unsigned int pos;

	if (!bonding || !ref || !ref->index) {
		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_EVENTS,
				"%s: unbind of bonding slave %s[%u] skipped -- invalid args",
				ifname, ref ? ref->name : NULL, ref ? ref->index : 0);
		return FALSE;
	}

	pos = ni_bonding_slave_array_index_by_ifindex(&bonding->slaves, ref->index);
	if (pos != -1U) {
		slave = ni_bonding_slave_array_get(&bonding->slaves, pos);

		if (slave)
			ref = &slave->device;

		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
				"%s: unbind of bonding slave %s[%u] by ifindex",
				ifname, ref->name, ref->index);

		return ni_bonding_slave_array_delete(&bonding->slaves, pos);
	}

	ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_EVENTS,
			"%s: unbind of bonding slave %s[%u] skipped -- slave not found",
			ifname, ref->name, ref->index);
	return FALSE;
}

/*
 * Set the bonding mode, using the strings supported by the
 * module options
 */
static int
__ni_bonding_set_module_option_mode(ni_bonding_t *bonding, char *value)
{
	int rv;

	/* When we parse /sys/net/class/<ifname>/bonding/mode, we end up
	 * with "balance-rr 0" or similar; strip off the int value */
	value[strcspn(value, " \t\n")] = '\0';
	rv = ni_parse_uint_mapped(value, __map_kern_mode, &bonding->mode);
	if (rv < 0)
		ni_error("bonding: kernel reports unknown mode \"%s\"", value);
	return rv;
}

static int
__ni_bonding_get_module_option_mode(const ni_bonding_t *bonding, char *buffer, size_t bufsize)
{
	const char *name;

	name = ni_format_uint_mapped(bonding->mode, __map_kern_mode);
	if (name == NULL) {
		ni_error("bonding: unsupported bonding mode %u", bonding->mode);
		return -1;
	}
	strncpy(buffer, name, bufsize - 1);
	buffer[bufsize - 1] = '\0';
	return 0;
}

const char *
ni_bonding_mode_type_to_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, __map_user_mode);
}

int
ni_bonding_mode_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_maybe_mapped(name, __map_user_mode, &value, 10) != 0)
		return -1;
	return value;
}

/*
 * Set the validation mode of ARP probes.
 */
static int
__ni_bonding_set_module_option_arp_validate(ni_bonding_t *bonding, char *value)
{
	int rv;

	/* When we parse /sys/net/class/<ifname>/bonding/arp_validate, we end up
	 * with "none 0" or similar; strip off the int value */
	value[strcspn(value, " \t\n")] = '\0';
	rv = ni_parse_uint_mapped(value, __map_kern_arp_validate,
					&bonding->arpmon.validate);
	if (rv < 0)
		ni_error("bonding: kernel reports unknown arp_validate mode \"%s\"", value);
	return rv;
}

static int
__ni_bonding_get_module_option_arp_validate(const ni_bonding_t *bonding, char *buffer, size_t bufsize)
{
	const char *name;

	name = ni_format_uint_mapped(bonding->arpmon.validate,
				__map_kern_arp_validate);
	if (name == NULL) {
		ni_error("bonding: unsupported arp_validate mode %u", bonding->arpmon.validate);
		return -1;
	}
	strncpy(buffer, name, bufsize - 1);
	return 0;
}

const char *
ni_bonding_arp_validate_type_to_name(unsigned int value)
{
	return ni_format_uint_mapped(value, __map_kern_arp_validate);
}

int
ni_bonding_arp_validate_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __map_kern_arp_validate, &value) < 0)
		return -1;
	return value;
}

const char *
ni_bonding_mii_carrier_detect_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __map_user_carrier_detect);
}

int
ni_bonding_mii_carrier_detect_type(const char *name)
{
	unsigned int type;

	if (ni_parse_uint_mapped(name, __map_user_carrier_detect, &type) < 0)
		return -1;
	return type;
}

/*
 * Set the xmit hash policy
 */
static int
__ni_bonding_set_module_option_xmit_hash_policy(ni_bonding_t *bonding, char *value)
{
	int rv;

	value[strcspn(value, " \t\n")] = '\0';
	rv = ni_parse_uint_mapped(value, __map_kern_xmit_hash_policy,
					&bonding->xmit_hash_policy);
	if (rv < 0)
		ni_error("bonding: kernel reports unknown xmit_hash_policy mode \"%s\"", value);
	return rv;
}

int
__ni_bonding_get_module_option_xmit_hash_policy(const ni_bonding_t *bonding, char *buffer, size_t bufsize)
{
	const char *name;

	name = ni_format_uint_mapped(bonding->xmit_hash_policy,
				__map_kern_xmit_hash_policy);
	if (name == NULL) {
		ni_error("bonding: unsupported xmit_hash_policy %u", bonding->xmit_hash_policy);
		return -1;
	}
	strncpy(buffer, name, bufsize - 1);
	return 0;
}

/*
 * For now, the enum names in the xml schema use the same xmit hash policy names as
 * the kernel.
 */
const char *
ni_bonding_xmit_hash_policy_to_name(unsigned int value)
{
	return ni_format_uint_mapped(value, __map_user_xmit_hash_policy);
}

int
ni_bonding_xmit_hash_policy_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_mapped(name, __map_user_xmit_hash_policy, &value) < 0)
		return -1;
	return value;
}

const char *
ni_bonding_lacp_rate_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, __map_kern_lacp_rate);
}

int
ni_bonding_lacp_rate_mode(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_maybe_mapped(name, __map_kern_lacp_rate, &value, 10) < 0)
		return -1;
	return value;
}

const char *
ni_bonding_ad_select_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, __map_kern_ad_select);
}

int
ni_bonding_ad_select_mode(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_maybe_mapped(name, __map_kern_ad_select, &value, 10) < 0)
		return -1;
	return value;
}

const char *
ni_bonding_primary_reselect_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, __map_kern_primary_reselect);
}

int
ni_bonding_primary_reselect_mode(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_maybe_mapped(name, __map_kern_primary_reselect, &value, 10) < 0)
		return -1;
	return value;
}

const char *
ni_bonding_fail_over_mac_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, __map_kern_fail_over_mac);
}

int
ni_bonding_fail_over_mac_mode(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_maybe_mapped(name, __map_kern_fail_over_mac, &value, 10) < 0)
		return -1;
	return value;
}

const char *
ni_bonding_arp_validate_targets_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, __map_kern_arp_all_targets);
}

int
ni_bonding_arp_validate_targets_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_uint_maybe_mapped(name, __map_kern_arp_all_targets, &value, 10) < 0)
		return -1;
	return value;
}

const char *
ni_bonding_slave_state_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, ni_bonding_slave_state_map);
}

const char *
ni_bonding_slave_mii_status_name(unsigned int mode)
{
	return ni_format_uint_mapped(mode, ni_bonding_slave_mii_status_map);
}

/*
 * Set one bonding module option/attribute
 */
static int
ni_bonding_parse_sysfs_attribute(ni_bonding_t *bonding, const char *attr, char *value)
{
	if (!strcmp(attr, "mode")) {
		if (__ni_bonding_set_module_option_mode(bonding, value) < 0)
			return -1;
	} else if (!strcmp(attr, "fail_over_mac")) {
		value[strcspn(value, " \t\n")] = '\0';
		if (ni_parse_uint_mapped(value, __map_kern_fail_over_mac,
					&bonding->fail_over_mac) < 0)
			return -1;
	} else if (!strcmp(attr, "primary_reselect")) {
		value[strcspn(value, " \t\n")] = '\0';
		if (ni_parse_uint_mapped(value, __map_kern_primary_reselect,
					&bonding->primary_reselect) < 0)
			return -1;
	} else if (!strcmp(attr, "xmit_hash_policy")) {
		if (__ni_bonding_set_module_option_xmit_hash_policy(bonding, value) < 0)
			return -1;
	} else if (!strcmp(attr, "lacp_rate")) {
		value[strcspn(value, " \t\n")] = '\0';
		if (ni_parse_uint_mapped(value, __map_kern_lacp_rate,
					&bonding->lacp_rate) < 0)
			return -1;
	} else if (!strcmp(attr, "ad_select")) {
		value[strcspn(value, " \t\n")] = '\0';
		if (ni_parse_uint_mapped(value, __map_kern_ad_select,
					&bonding->ad_select) < 0)
			return -1;
	} else if (!strcmp(attr, "min_links")) {
		if (ni_parse_uint(value, &bonding->min_links, 10) < 0)
			return -1;
	} else if (!strcmp(attr, "num_grat_arp")) {
		if (ni_parse_uint(value, &bonding->num_grat_arp, 10) < 0)
			return -1;
	} else if (!strcmp(attr, "num_unsol_na")) {
		if (ni_parse_uint(value, &bonding->num_unsol_na, 10) < 0)
			return -1;
	} else if (!strcmp(attr, "resend_igmp")) {
		if (ni_parse_uint(value, &bonding->resend_igmp, 10) < 0)
			return -1;
	} else if (!strcmp(attr, "all_slaves_active")) {
		unsigned int tmp;
		if (ni_parse_uint(value, &tmp, 10) < 0)
			return -1;
		bonding->all_slaves_active = tmp;
	} else if (!strcmp(attr, "miimon")) {
		if (ni_parse_uint(value, &bonding->miimon.frequency, 10) < 0)
			return -1;
		if (bonding->miimon.frequency > 0)
			bonding->monitoring = NI_BOND_MONITOR_MII;
	} else if (!strcmp(attr, "updelay")) {
		if (ni_parse_uint(value, &bonding->miimon.updelay, 10) < 0)
			return -1;
	} else if (!strcmp(attr, "downdelay")) {
		if (ni_parse_uint(value, &bonding->miimon.downdelay, 10) < 0)
			return -1;
	} else if (!strcmp(attr, "use_carrier")) {
		if (ni_parse_uint(value, &bonding->miimon.carrier_detect, 10) < 0)
			return -1;
	} else if (!strcmp(attr, "arp_validate")) {
		if (__ni_bonding_set_module_option_arp_validate(bonding, value) < 0)
			return -1;
	} else if (!strcmp(attr, "arp_interval")) {
		if (ni_parse_uint(value, &bonding->arpmon.interval, 10) < 0)
			return -1;
		if (bonding->arpmon.interval > 0)
			bonding->monitoring = NI_BOND_MONITOR_ARP;
	} else if (!strcmp(attr, "arp_ip_target")) {
		char *s, *p = NULL;
		for (s = strtok_r(value, " \t\n", &p); s; s = strtok_r(NULL, " \t\n", &p)) {
			if (ni_bonding_is_valid_arp_ip_target(s))
				ni_string_array_append(&bonding->arpmon.targets, s);
		}
	} else if (!strcmp(attr, "arp_all_targets")) {
		value[strcspn(value, " \t\n")] = '\0';
		if (ni_parse_uint_mapped(value, __map_kern_arp_all_targets,
					&bonding->arpmon.validate_targets) < 0)
			return -1;
	} else if (!strcmp(attr, "primary")) {
		ni_string_dup(&bonding->primary_slave.name, value);
	} else if (!strcmp(attr, "active_slave")) {
		ni_string_dup(&bonding->active_slave.name, value);
	} else if (!strcmp(attr, "packets_per_slave")) {
		if (ni_parse_uint(value, &bonding->packets_per_slave, 10) < 0)
			return -1;
	} else if (!strcmp(attr, "tlb_dynamic_lb")) {
		unsigned int tmp;
		if (ni_parse_uint(value, &tmp, 10) < 0)
			return -1;
		bonding->tlb_dynamic_lb = !!tmp;
	} else if (!strcmp(attr, "lp_interval")) {
		if (ni_parse_uint(value, &bonding->lp_interval, 10) < 0)
			return -1;
	} else {
		return -2;
	}

	return 0;
}

/*
 * Get one bonding module option/attribute
 */
static int
ni_bonding_format_sysfs_attribute(const ni_bonding_t *bonding, const char *attr, char *buffer, size_t bufsize)
{
	const char *ptr;

	memset(buffer, 0, bufsize);
	if (!strcmp(attr, "mode")) {
		return __ni_bonding_get_module_option_mode(bonding, buffer, bufsize);
	} else if (!strcmp(attr, "fail_over_mac")) {
		if ((ptr = ni_bonding_fail_over_mac_name(bonding->fail_over_mac)) == NULL)
			return -1;
		snprintf(buffer, bufsize, "%s", ptr);
	} else if (!strcmp(attr, "primary_reselect")) {
		if ((ptr = ni_bonding_primary_reselect_name(bonding->primary_reselect)) == NULL)
			return -1;
		snprintf(buffer, bufsize, "%s", ptr);
	} else if (!strcmp(attr, "xmit_hash_policy")) {
		return __ni_bonding_get_module_option_xmit_hash_policy(bonding, buffer, bufsize);
	} else if (!strcmp(attr, "lacp_rate")) {
		if ((ptr = ni_bonding_lacp_rate_name(bonding->lacp_rate)) == NULL)
			return -1;
		snprintf(buffer, bufsize, "%s", ptr);
	} else if (!strcmp(attr, "ad_select")) {
		if ((ptr = ni_bonding_ad_select_name(bonding->ad_select)) == NULL)
			return -1;
		snprintf(buffer, bufsize, "%s", ptr);
	} else if (!strcmp(attr, "min_links")) {
		snprintf(buffer, bufsize, "%u", bonding->min_links);
	} else if (!strcmp(attr, "num_grat_arp")) {
		snprintf(buffer, bufsize, "%u", bonding->num_grat_arp);
	} else if (!strcmp(attr, "num_unsol_na")) {
		snprintf(buffer, bufsize, "%u", bonding->num_unsol_na);
	} else if (!strcmp(attr, "resend_igmp")) {
		snprintf(buffer, bufsize, "%u", bonding->resend_igmp);
	} else if (!strcmp(attr, "all_slaves_active")) {
		snprintf(buffer, bufsize, "%u", bonding->all_slaves_active);
	} else if (!strcmp(attr, "miimon")) {
		unsigned int freq = 0;
		if (bonding->monitoring == NI_BOND_MONITOR_MII)
			freq = bonding->miimon.frequency;
		snprintf(buffer, bufsize, "%u", freq);
	} else if (!strcmp(attr, "updelay")) {
		if (bonding->monitoring != NI_BOND_MONITOR_MII)
			return 0;
		snprintf(buffer, bufsize, "%u", bonding->miimon.updelay);
	} else if (!strcmp(attr, "downdelay")) {
		if (bonding->monitoring != NI_BOND_MONITOR_MII)
			return 0;
		snprintf(buffer, bufsize, "%u", bonding->miimon.downdelay);
	} else if (!strcmp(attr, "use_carrier")) {
		if (bonding->monitoring != NI_BOND_MONITOR_MII)
			return 0;
		snprintf(buffer, bufsize, "%u", bonding->miimon.carrier_detect);
	} else if (!strcmp(attr, "arp_validate")) {
		if (bonding->monitoring != NI_BOND_MONITOR_ARP)
			return 0;
		return __ni_bonding_get_module_option_arp_validate(bonding, buffer, bufsize);
	} else if (!strcmp(attr, "arp_interval")) {
		if (bonding->monitoring != NI_BOND_MONITOR_ARP)
			return 0;
		snprintf(buffer, bufsize, "%u", bonding->arpmon.interval);
	} else if (!strcmp(attr, "arp_all_targets")) {
		if (bonding->monitoring != NI_BOND_MONITOR_ARP ||
		    bonding->arpmon.validate == NI_BOND_ARP_VALIDATE_NONE)
			return 0;
		if (!(ptr = ni_bonding_arp_validate_targets_to_name(bonding->arpmon.validate_targets)))
			return -1;
		snprintf(buffer, bufsize, "%s", ptr);
	} else if (!strcmp(attr, "active_slave")) {
		if (!bonding->active_slave.name)
			return 0;
		snprintf(buffer, bufsize, "%s", bonding->active_slave.name);
	} else if (!strcmp(attr, "primary")) {
		if (!bonding->primary_slave.name)
			return 0;
		snprintf(buffer, bufsize, "%s", bonding->primary_slave.name);
	} else if (!strcmp(attr, "packets_per_slave")) {
		snprintf(buffer, bufsize, "%u", bonding->packets_per_slave);
	} else if (!strcmp(attr, "tlb_dynamic_lb")) {
		snprintf(buffer, bufsize, "%u", bonding->tlb_dynamic_lb ? 1 : 0);
	} else if (!strcmp(attr, "lp_interval")) {
		snprintf(buffer, bufsize, "%u", bonding->lp_interval);
	} else {
		return -1;
	}

	return 0;
}

/*
 * Load bonding configuration from sysfs
 */
int
ni_bonding_parse_sysfs_attrs(const char *ifname, ni_bonding_t *bonding)
{
	static const struct {
		const char *name;
		ni_bool_t   nofail;	/* don't fail, may be missed */
	} attrs[] = {
		{ "mode",		FALSE },
		{ "fail_over_mac",	FALSE },
		{ "primary_reselect",	FALSE },
		{ "xmit_hash_policy",	FALSE },
		{ "lacp_rate",		FALSE },
		{ "ad_select",		FALSE },
		{ "min_links",		TRUE  },
		{ "num_grat_arp",	FALSE },
		{ "num_unsol_na",	FALSE },
		{ "resend_igmp",	FALSE },
		{ "all_slaves_active",	FALSE },
		{ "active_slave",	FALSE },
		{ "primary",		FALSE },
		{ "miimon",		FALSE },
		{ "updelay",		FALSE },
		{ "downdelay",		FALSE },
		{ "use_carrier",	FALSE },
		{ "arp_validate",	FALSE },
		{ "arp_interval",	FALSE },
		{ "arp_all_targets",	TRUE  },
		{ "packets_per_slave",	TRUE  },
		{ "tlb_dynamic_lb",	TRUE  },
		{ "lp_interval",	TRUE  },
		{ NULL,			FALSE },
	};
	ni_string_array_t slave_names = NI_STRING_ARRAY_INIT;
	char *attrval = NULL;
	unsigned int i;

	__ni_bonding_clear(bonding);
	ni_sysfs_bonding_get_slaves(ifname, &slave_names);
	for (i = 0; i < slave_names.count; ++i)
		ni_bonding_add_slave(bonding, slave_names.data[i]);
	ni_string_array_destroy(&slave_names);

	for (i = 0; attrs[i].name; ++i) {
		const char *attrname = attrs[i].name;
		int rv;

		if (ni_sysfs_bonding_get_attr(ifname, attrname, &attrval) < 0) {
			if (attrs[i].nofail)
				continue;

			ni_error("%s: cannot get bonding attribute %s", ifname, attrname);
			goto failed;
		}

		if (attrval == NULL)
			continue;

		rv = ni_bonding_parse_sysfs_attribute(bonding, attrname, attrval);
		if (rv == -2) {
			ni_error("ignoring unknown bonding module option %s=%s", attrname, attrval);
		} else if (rv < 0) {
			ni_error("unable to parse bonding module option %s=%s", attrname, attrval);
			goto failed;
		}
	}

	ni_sysfs_bonding_get_arp_targets(ifname, &bonding->arpmon.targets);

	ni_string_free(&attrval);
	return 0;

failed:
	ni_string_free(&attrval);
	return -1;
}

/*
 * Write one sysfs attribute
 */
static int
ni_bonding_write_one_sysfs_attr(const char *ifname, const ni_bonding_t *bonding,
			const ni_bonding_t *current, const char *attrname)
{
	char current_value[128], config_value[128];

	if (ni_bonding_format_sysfs_attribute(current, attrname, current_value, sizeof(current_value)) < 0
	 || ni_bonding_format_sysfs_attribute(bonding, attrname, config_value, sizeof(config_value)) < 0) {
		ni_error("%s: cannot represent attribute %s", ifname, attrname);
		return -1;
	}

#if 0
	ni_debug_ifconfig("%s: checking  attr %s: cur=%s cfg=%s", ifname, attrname,
				current_value, config_value);
#endif

	if (config_value[0] == '\0') {
		ni_debug_ifconfig("%s: ignoring  attr: %s", ifname, attrname);
		return 0;
	}

	if (!strcmp(current_value, config_value)) {
		ni_debug_ifconfig("%s: unchanged attr: %s", ifname, attrname);
		return 0;
	}

	ni_debug_ifconfig("%s: setting   attr: %s=%s", ifname, attrname, config_value);
	if (ni_sysfs_bonding_set_attr(ifname, attrname, config_value) < 0) {
		ni_error("%s: cannot set bonding attribute %s=%s", ifname, attrname, config_value);
		return -1;
	}

	return 0;
}

/*
 * Write bonding configuration to sysfs.
 * This happens in two stages, prior to enslaving interfaces and after,
 * as well as in dependency of the bonding up/down state and slave count.
 */
int
ni_bonding_write_sysfs_attrs(const char *ifname, const ni_bonding_t *bonding, ni_bonding_t *current, ni_bool_t is_up, ni_bool_t has_slaves)
{
	/*
	 * option		up/down	slaves		modes
	 * -------------------------------------------------------------
	 * mode:		down	!slaves
	 * fail_over_mac:		!slaves		AB
	 * xmit_hash_policy:	down			3AD, XOR
	 * lacp_rate:		down			3AD
	 * ad_select:		down			3AD
	 * min_links:		(down)			3AD
	 * num_grat_arp:				AB
	 * num_unsol_na:				AB
	 * resend_igmp:					AB, TLB, ALB, RR
	 * all_slaves_active:
	 * primary_reselect:				AB, TLB, ALB
	 * primary:					AB, TLB, ALB
	 * active_slave:	up	slaves		AB, TLB, ALB
	 * arp_interval:				!TLB, !ALB, !3AD
	 *   arp_ip_target:				!TLB, !ALB, !3AD
	 *   arp_validate:				BAK
	 * miimon:
	 *   updelay:
	 *   downdelay:
	 *   use_carrier:
	 */
	struct attr_matrix {
		const char *	name;
		int		bstate;		/* 1: bond down, 2: bond up      */
		int		slaves;		/* 1: no slaves, 2: wants slaves */
		ni_bool_t	islist;	/* 1: list value (arp_ip_target) */
		ni_bool_t		nofail;	/* 1: do not fail on set error   */
	};
	const struct attr_matrix attr_matrix[] = {
		{ "mode",		1,	1,	FALSE,	FALSE },
		{ "fail_over_mac",	0,	1,	FALSE,	FALSE },
		{ "primary_reselect",	0,	0,	FALSE,	FALSE },
		{ "xmit_hash_policy",	1,	0,	FALSE,	FALSE },
		{ "lacp_rate",		1,	0,	FALSE,	FALSE },
		{ "ad_select",		1,	0,	FALSE,	FALSE },
		{ "min_links",		1,	0,	FALSE,	TRUE  },
		{ "num_grat_arp",	0,	0,	FALSE,	FALSE },
		{ "num_unsol_na",	0,	0,	FALSE,	FALSE },
		{ "resend_igmp",	0,	0,	FALSE,	FALSE },
		{ "all_slaves_active",	0,	0,	FALSE,	FALSE },
		{ "active_slave",	2,	2,	FALSE,	FALSE },
		{ "primary",		0,	0,	FALSE,	FALSE },
		{ "miimon",		0,	0,	FALSE,	FALSE },
		{ "updelay",		0,	0,	FALSE,	FALSE },
		{ "downdelay",		0,	0,	FALSE,	FALSE },
		{ "use_carrier",	0,	0,	FALSE,	FALSE },
		{ "arp_ip_target",	0,	0,	TRUE,	FALSE },
		{ "arp_interval",	0,	0,	FALSE,	FALSE },
		{ "arp_validate",	0,	0,	FALSE,	FALSE },
		{ "arp_all_targets",	0,	0,	FALSE,	FALSE },
		{ "packets_per_slave",	0,	0,	FALSE,	FALSE },
		{ "tlb_dynamic_lb",	1,	1,	FALSE,	FALSE },
		{ "lp_interval",	0,	0,	FALSE,	FALSE },
		{ NULL,			0,	0,	FALSE,	FALSE },
	};
	const struct attr_matrix *attrs;
	unsigned int i;
	char *attrval = NULL;

	attrs = attr_matrix;
	for (i = 0; attrs[i].name; ++i) {
		if (attrs[i].bstate == 1 && is_up)
			continue;
		if (attrs[i].bstate == 2 && !is_up)
			continue;
		if (attrs[i].slaves == 1 && has_slaves)
			continue;
		if (attrs[i].slaves == 2 && !has_slaves)
			continue;

		if (attrs[i].islist) {
			if (ni_sysfs_bonding_set_list_attr(ifname, attrs[i].name,
						&bonding->arpmon.targets) < 0 &&
					!attrs[i].nofail)
				return -1;
		} else {
			if (ni_bonding_write_one_sysfs_attr(ifname, bonding,
						current, attrs[i].name) < 0 &&
					!attrs[i].nofail)
				return -1;
		}

		if (!ni_sysfs_bonding_get_attr(ifname, attrs[i].name, &attrval) && attrval)
			ni_bonding_parse_sysfs_attribute(current, attrs[i].name, attrval);
		ni_string_free(&attrval);
	}

	return 0;
}

/*
 * Set specified bonding setting value for a given kernel option name.
 *
 * The setting values are verified, but without dependency checks;
 * see also ni_bonding_validate.
 */
ni_bool_t
ni_bonding_set_option(ni_bonding_t *bond, const char *option, const char *value)
{
	unsigned int tmp;

	if (!bond || !option || !value || !*value)
		return FALSE;

	if (strcmp(option, "mode") == 0) {
		if (ni_parse_uint_maybe_mapped(value,
				__map_kern_mode, &tmp, 10) != 0)
			return FALSE;

		bond->mode = tmp;
		return TRUE;
	} else

	if (strcmp(option, "fail_over_mac") == 0) {
		if (ni_parse_uint_maybe_mapped(value,
				__map_kern_fail_over_mac, &tmp, 10) != 0)
			return FALSE;

		bond->fail_over_mac = tmp;
		return TRUE;
	} else

	if (strcmp(option, "primary_reselect") == 0) {
		if (ni_parse_uint_maybe_mapped(value,
				__map_kern_primary_reselect, &tmp, 10) != 0)
			return FALSE;

		bond->primary_reselect = tmp;
		return TRUE;
	} else

	if (strcmp(option, "xmit_hash_policy") == 0) {
		if (ni_parse_uint_maybe_mapped(value,
				__map_kern_xmit_hash_policy, &tmp, 10) != 0)
			return FALSE;

		bond->xmit_hash_policy = tmp;
		return TRUE;
	} else

	if (strcmp(option, "lacp_rate") == 0) {
		if (ni_parse_uint_maybe_mapped(value,
				__map_kern_lacp_rate, &tmp, 10) != 0)
			return FALSE;

		bond->lacp_rate = tmp;
		return TRUE;
	} else

	if (strcmp(option, "ad_select") == 0) {
		if (ni_parse_uint_maybe_mapped(value,
				__map_kern_ad_select, &tmp, 10) != 0)
			return FALSE;

		bond->ad_select = tmp;
		return TRUE;
	} else

	if (strcmp(option, "ad_user_port_key") == 0) {
		if (ni_parse_uint(value, &tmp, 0) < 0 || tmp > 1023)
			return FALSE;
		bond->ad_user_port_key = tmp;
		return TRUE;
	} else

	if (strcmp(option, "ad_actor_sys_prio") == 0) {
		if (ni_parse_uint(value, &tmp, 0) < 0 || tmp < 1 || tmp > 65535)
			return FALSE;
		bond->ad_actor_sys_prio = tmp;
		return TRUE;
	} else

	if (strcmp(option, "ad_actor_system") == 0) {
		if (ni_link_address_parse(&bond->ad_actor_system, ARPHRD_ETHER, value) < 0 ||
		    ni_link_address_is_invalid(&bond->ad_actor_system)) {
			ni_link_address_init(&bond->ad_actor_system);
			return FALSE;
		}
		return TRUE;
	} else

	if (strcmp(option, "min_links") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0)
			return FALSE;

		bond->min_links = tmp;
		return TRUE;
	} else

	if (strcmp(option, "num_grat_arp") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > 255)
			return FALSE;

		bond->num_grat_arp = tmp;
		return TRUE;
	} else

	if (strcmp(option, "num_unsol_na") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > 255)
			return FALSE;

		bond->num_unsol_na = tmp;
		return TRUE;
	} else

	if (strcmp(option, "resend_igmp") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > 255)
			return FALSE;

		bond->resend_igmp = tmp;
		return TRUE;
	} else

	if (strcmp(option, "all_slaves_active") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > 1)
			return FALSE;

		bond->all_slaves_active = tmp;
		return TRUE;
	} else

	if (strcmp(option, "miimon") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > INT_MAX)
			return FALSE;

		bond->miimon.frequency = tmp;
		bond->monitoring |= NI_BOND_MONITOR_MII;
		return TRUE;
	} else

	if (strcmp(option, "updelay") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > INT_MAX)
			return FALSE;

		bond->miimon.updelay = tmp;
		return TRUE;
	} else

	if (strcmp(option, "downdelay") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > INT_MAX)
			return FALSE;

		bond->miimon.downdelay = tmp;
		return TRUE;
	} else

	if (strcmp(option, "use_carrier") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0)
			return FALSE;

		if (tmp > NI_BOND_MII_CARRIER_DETECT_NETIF)
			return FALSE;

		bond->miimon.carrier_detect = tmp;
		return TRUE;
	} else

	if (strcmp(option, "arp_interval") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > INT_MAX)
			return FALSE;

		bond->arpmon.interval = tmp;
		bond->monitoring |= NI_BOND_MONITOR_ARP;
		return TRUE;
	} else

	if (strcmp(option, "arp_ip_target") == 0) {
		unsigned int i;

		ni_string_array_destroy(&bond->arpmon.targets);
		if (ni_string_split(&bond->arpmon.targets, value, ",", 16) == 0)
			return FALSE;

		for (i = 0; i < bond->arpmon.targets.count; ++i) {
			const char *target = bond->arpmon.targets.data[i];

			if (ni_bonding_is_valid_arp_ip_target(target))
				continue;

			ni_string_array_destroy(&bond->arpmon.targets);
			return FALSE;
		}
		return TRUE;
	} else

	if (strcmp(option, "arp_validate") == 0) {
		if (ni_parse_uint_maybe_mapped(value,
				__map_kern_arp_validate, &tmp, 10) != 0)
			return FALSE;

		bond->arpmon.validate = tmp;
		return TRUE;
	} else

	if (strcmp(option, "arp_all_targets") == 0) {
		if (ni_parse_uint_maybe_mapped(value,
				__map_kern_arp_all_targets, &tmp, 10) != 0)
			return FALSE;

		bond->arpmon.validate_targets = tmp;
		return TRUE;
	} else

	if (strcmp(option, "primary") == 0) {
		ni_string_dup(&bond->primary_slave.name, value);
		return TRUE;
	} else

	if (strcmp(option, "active_slave") == 0) {
		ni_string_dup(&bond->active_slave.name, value);
		return TRUE;
	} else

	if (strcmp(option, "packets_per_slave") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > 65535)
			return FALSE;

		bond->packets_per_slave = tmp;
		return TRUE;
	} else

	if (strcmp(option, "tlb_dynamic_lb") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > INT_MAX)
			return FALSE;

		bond->tlb_dynamic_lb = tmp ? TRUE : FALSE;
		return TRUE;
	} else

	if (strcmp(option, "lp_interval") == 0) {
		if (ni_parse_uint(value, &tmp, 10) < 0 || tmp > INT_MAX)
			return FALSE;

		bond->lp_interval = tmp;
		return TRUE;
	}

	return FALSE;
}

void
ni_bonding_slave_info_reset(ni_bonding_slave_info_t *info)
{
	info->state = -1U;
	info->mii_status = -1U;
	info->queue_id = -1U;
	info->ad_aggregator_id = -1U;
	ni_link_address_init(&info->perm_hwaddr);
}

ni_bonding_slave_info_t *
ni_bonding_slave_info_new(void)
{
	ni_bonding_slave_info_t *info;

	info = xcalloc(1, sizeof(*info));
	info->refcount = 1;
	ni_bonding_slave_info_reset(info);
	return info;
}

ni_bonding_slave_info_t *
ni_bonding_slave_info_ref(ni_bonding_slave_info_t *info)
{
	if (info) {
		ni_assert(info->refcount);
		info->refcount++;
	}
	return info;
}

void
ni_bonding_slave_info_free(ni_bonding_slave_info_t *info)
{
	if (info) {
		ni_assert(info->refcount);
		info->refcount--;

		if (info->refcount == 0)
			free(info);
	}
}

ni_bonding_slave_t *
ni_bonding_slave_new(void)
{
	ni_bonding_slave_t *slave;

	slave = xcalloc(1, sizeof(*slave));
	return slave;
}

void
ni_bonding_slave_free(ni_bonding_slave_t *slave)
{
	if (slave) {
		ni_netdev_ref_destroy(&slave->device);
		ni_bonding_slave_info_free(slave->info);
		free(slave);
	}
}

ni_bonding_slave_info_t *
ni_bonding_slave_get_info(ni_bonding_slave_t *slave)
{
	if (slave) {
		if (!slave->info)
			slave->info = ni_bonding_slave_info_new();
		return slave->info;
	}
	return NULL;
}

void
ni_bonding_slave_set_info(ni_bonding_slave_t *slave, ni_bonding_slave_info_t *info)
{
	if (slave) {
		ni_bonding_slave_info_t *temp;

		temp = ni_bonding_slave_info_ref(info);
		ni_bonding_slave_info_free(slave->info);
		slave->info = temp;
	}
}

static inline void
ni_bonding_slave_array_init(ni_bonding_slave_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

static void
ni_bonding_slave_array_realloc(ni_bonding_slave_array_t *array, unsigned int newsize)
{
	ni_bonding_slave_t **newdata;
	unsigned int i;

	newsize += NI_BONDING_SLAVE_ARRAY_CHUNK;
	newdata = xrealloc(array->data, newsize * sizeof(ni_bonding_slave_t *));
	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		array->data[i] = NULL;
}

ni_bool_t
ni_bonding_slave_array_append(ni_bonding_slave_array_t *array, ni_bonding_slave_t *slave)
{
	if (!array || !slave)
		return FALSE;

	if ((array->count % NI_BONDING_SLAVE_ARRAY_CHUNK) == 0)
		ni_bonding_slave_array_realloc(array, array->count);

	array->data[array->count++] = slave;
	return TRUE;
}

ni_bonding_slave_t *
ni_bonding_slave_array_remove(ni_bonding_slave_array_t *array, unsigned int index)
{
	ni_bonding_slave_t *slave;

	if (!array || index >= array->count)
		return NULL;

	slave = array->data[index];
	array->count--;
	if (index < array->count) {
		memmove(&array->data[index], &array->data[index + 1],
			(array->count - index) * sizeof(slave));
	}
	array->data[array->count] = NULL;
	return slave;
}

ni_bool_t
ni_bonding_slave_array_delete(ni_bonding_slave_array_t *array, unsigned int index)
{
	ni_bonding_slave_t *slave;

	if (!(slave = ni_bonding_slave_array_remove(array, index)))
		return FALSE;

	ni_bonding_slave_free(slave);
	return TRUE;
}

void
ni_bonding_slave_array_destroy(ni_bonding_slave_array_t *array)
{
	if (array) {
		while (array->count > 0)
			ni_bonding_slave_free(array->data[--array->count]);
		free(array->data);

		ni_bonding_slave_array_init(array);
	}
}

unsigned int
ni_bonding_slave_array_index_by_ifname(ni_bonding_slave_array_t *array, const char *ifname)
{
	unsigned int i;

	if (!array || !ifname)
		return -1U;

	for (i = 0; i < array->count; ++i) {
		ni_bonding_slave_t *slave = array->data[i];

		if (slave && ni_string_eq(ifname, slave->device.name))
			return i;
	}
	return -1U;
}

unsigned int
ni_bonding_slave_array_index_by_ifindex(ni_bonding_slave_array_t *array, unsigned int ifindex)
{
	unsigned int i;

	if (!array || !ifindex)
		return -1U;

	for (i = 0; i < array->count; ++i) {
		ni_bonding_slave_t *slave = array->data[i];

		if (slave && ifindex == slave->device.index)
			return i;
	}
	return -1U;
}

ni_bonding_slave_t *
ni_bonding_slave_array_get(ni_bonding_slave_array_t *array, unsigned int index)
{
	if (!array || index >= array->count)
		return NULL;

	return array->data[index];
}

ni_bonding_slave_t *
ni_bonding_slave_array_get_by_ifname(ni_bonding_slave_array_t *array, const char *ifname)
{
	unsigned int index = ni_bonding_slave_array_index_by_ifname(array, ifname);

	return ni_bonding_slave_array_get(array, index);
}

ni_bonding_slave_t *
ni_bonding_slave_array_get_by_ifindex(ni_bonding_slave_array_t *array, unsigned int ifindex)
{
	unsigned int index = ni_bonding_slave_array_index_by_ifindex(array, ifindex);

	return ni_bonding_slave_array_get(array, index);
}

