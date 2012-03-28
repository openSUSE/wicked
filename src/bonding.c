/*
 * Routines for handling bonding devices
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#include <wicked/netinfo.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include "netinfo_priv.h"
#include "sysfs.h"

/*
 * Create a bonding config
 */
ni_bonding_t *
ni_bonding_new(void)
{
	ni_bonding_t *bonding;

	bonding = calloc(1, sizeof(ni_bonding_t));
	bonding->mode = NI_BOND_MODE_BALANCE_RR;
	bonding->monitoring = NI_BOND_MONITOR_ARP;
	bonding->arpmon.interval = 2000;
	bonding->arpmon.validate = NI_BOND_VALIDATE_ACTIVE;
	bonding->xmit_hash_policy = NI_BOND_XMIT_HASH_LAYER2;

	return bonding;
}

/*
 * Add a slave device to the bond
 */
void
ni_bonding_add_slave(ni_bonding_t *bonding, const char *ifname)
{
	ni_string_array_append(&bonding->slave_names, ifname);
}

/*
 * Reinitialize the bonding configuration
 *
 * - The default bonding mode is balance-rr
 * - The default monitoring mode is ARP (unless miimon=... is set)
 */
static void
ni_bonding_clear(ni_bonding_t *bonding)
{
	bonding->mode = NI_BOND_MODE_BALANCE_RR;
	bonding->monitoring = NI_BOND_MONITOR_ARP;

	ni_string_free(&bonding->primary);

	ni_string_array_destroy(&bonding->slave_names);
	ni_string_array_destroy(&bonding->arpmon.targets);
}

/*
 * Check whether the given bonding settings are valid
 */
const char *
ni_bonding_validate(const ni_bonding_t *bonding)
{
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

	switch (bonding->monitoring) {
	case NI_BOND_MONITOR_ARP:
		if (bonding->arpmon.interval == 0)
			return "invalid arpmon interval";

		switch (bonding->arpmon.validate) {
		case NI_BOND_VALIDATE_NONE:
		case NI_BOND_VALIDATE_ACTIVE:
		case NI_BOND_VALIDATE_BACKUP:
		case NI_BOND_VALIDATE_ALL:
			break;

		default:
			return "invalid arpmon validate setting";
		}

		if (bonding->arpmon.targets.count == 0)
			return "no targets for arp monitoring";
		break;

	case NI_BOND_MONITOR_MII:
		/* FIXME: validate frequency, updelay, downdelay */
		switch (bonding->miimon.carrier_detect) {
		case NI_BOND_CARRIER_DETECT_IOCTL:
		case NI_BOND_CARRIER_DETECT_NETIF:
			break;

		default:
			return "invalid miimon carrier detect setting";

		}
		break;

	default:
		return "unsupported monitoring mode";
	}

	return NULL;
}

/*
 * Free bonding configuration
 */
void
ni_bonding_free(ni_bonding_t *bonding)
{
	ni_bonding_clear(bonding);
	free(bonding);
}

/*
 * Set the bonding mode, using the strings supported by the
 * module options
 */
static ni_intmap_t	__kernel_bonding_mode_names[] = {
	{ "balance-rr",		NI_BOND_MODE_BALANCE_RR },
	{ "active-backup",	NI_BOND_MODE_ACTIVE_BACKUP },
	{ "balance-xor",	NI_BOND_MODE_BALANCE_XOR },
	{ "broadcast",		NI_BOND_MODE_BROADCAST },
	{ "802.3ad",		NI_BOND_MODE_802_3AD },
	{ "balance-tlb",	NI_BOND_MODE_BALANCE_TLB },
	{ "balance-alb",	NI_BOND_MODE_BALANCE_ALB },
	{ NULL }
};

int
__ni_bonding_set_module_option_mode(ni_bonding_t *bonding, char *value)
{
	int rv;

	/* When we parse /sys/net/class/<ifname>/bonding/mode, we end up
	 * with "balance-rr 0" or similar; strip off the int value */
	value[strcspn(value, " \t\n")] = '\0';
	rv = ni_parse_int_mapped(value, __kernel_bonding_mode_names, &bonding->mode);
	if (rv < 0)
		ni_error("bonding: kernel reports unknown arp_validate mode \"%s\"", value);
	return rv;
}

int
__ni_bonding_get_module_option_mode(const ni_bonding_t *bonding, char *buffer, size_t bufsize)
{
	const char *name;

	name = ni_format_int_mapped(bonding->mode, __kernel_bonding_mode_names);
	if (name == NULL) {
		ni_error("bonding: unsupported bonding mode %u", bonding->mode);
		return -1;
	}
	strncpy(buffer, name, bufsize - 1);
	return 0;
}

/*
 * For now, the enum names in the xml schema use almost the same mode names as
 * the kernel. 802.3ad being the notable exception, as starts with a digit, which
 * is illegal in xml element names.
 */
static ni_intmap_t	__user_bonding_mode_names[] = {
	{ "balance-rr",		NI_BOND_MODE_BALANCE_RR },
	{ "active-backup",	NI_BOND_MODE_ACTIVE_BACKUP },
	{ "balance-xor",	NI_BOND_MODE_BALANCE_XOR },
	{ "broadcast",		NI_BOND_MODE_BROADCAST },
	{ "ieee802-3ad",	NI_BOND_MODE_802_3AD },
	{ "balance-tlb",	NI_BOND_MODE_BALANCE_TLB },
	{ "balance-alb",	NI_BOND_MODE_BALANCE_ALB },
	{ NULL }
};

const char *
ni_bonding_mode_type_to_name(unsigned int mode)
{
	return ni_format_int_mapped(mode, __user_bonding_mode_names);
}

int
ni_bonding_mode_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __user_bonding_mode_names, &value) < 0)
		return -1;
	return value;
}

/*
 * Set the validation mode of ARP probes.
 */
static ni_intmap_t	__arp_validate[] = {
	{ "none",		NI_BOND_VALIDATE_NONE },
	{ "active",		NI_BOND_VALIDATE_ACTIVE },
	{ "backup",		NI_BOND_VALIDATE_BACKUP },
	{ "all",		NI_BOND_VALIDATE_ALL },
	{ NULL }
};

int
__ni_bonding_set_module_option_arp_validate(ni_bonding_t *bonding, char *value)
{
	int rv;

	/* When we parse /sys/net/class/<ifname>/bonding/arp_validate, we end up
	 * with "none 0" or similar; strip off the int value */
	value[strcspn(value, " \t\n")] = '\0';
	rv = ni_parse_int_mapped(value, __arp_validate, &bonding->arpmon.validate);
	if (rv < 0)
		ni_error("bonding: kernel reports unknown arp_validate mode \"%s\"", value);
	return rv;
}

int
__ni_bonding_get_module_option_arp_validate(const ni_bonding_t *bonding, char *buffer, size_t bufsize)
{
	const char *name;

	name = ni_format_int_mapped(bonding->arpmon.validate, __arp_validate);
	if (name == NULL) {
		ni_error("bonding: unsupported arp_validate mode %u", bonding->arpmon.validate);
		return -1;
	}
	strncpy(buffer, name, bufsize - 1);
	return 0;
}

/*
 * For now, the enum names in the xml schema use the same arp-valiate names as
 * the kernel.
 */
const char *
ni_bonding_validate_type_to_name(unsigned int value)
{
	return ni_format_int_mapped(value, __arp_validate);
}

int
ni_bonding_validate_name_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __arp_validate, &value) < 0)
		return -1;
	return value;
}

/*
 * Set the xmit hash policy
 */
static ni_intmap_t	__kernel_xmit_hash_policies[] = {
	{ "layer2",		NI_BOND_XMIT_HASH_LAYER2 },
	{ "layer2+3",		NI_BOND_XMIT_HASH_LAYER2_3 },
	{ "layer3+4",		NI_BOND_XMIT_HASH_LAYER3_4 },
	{ NULL }
};

static ni_intmap_t	__user_xmit_hash_policies[] = {
	{ "layer2",		NI_BOND_XMIT_HASH_LAYER2 },
	{ "layer23",		NI_BOND_XMIT_HASH_LAYER2_3 },
	{ "layer34",		NI_BOND_XMIT_HASH_LAYER3_4 },
	{ NULL }
};

int
__ni_bonding_set_module_option_xmit_hash_policy(ni_bonding_t *bonding, char *value)
{
	int rv;

	value[strcspn(value, " \t\n")] = '\0';
	rv = ni_parse_int_mapped(value, __kernel_xmit_hash_policies, &bonding->xmit_hash_policy);
	if (rv < 0)
		ni_error("bonding: kernel reports unknown xmit_hash_policy mode \"%s\"", value);
	return rv;
}

int
__ni_bonding_get_module_option_xmit_hash_policy(const ni_bonding_t *bonding, char *buffer, size_t bufsize)
{
	const char *name;

	name = ni_format_int_mapped(bonding->xmit_hash_policy, __kernel_xmit_hash_policies);
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
	return ni_format_int_mapped(value, __user_xmit_hash_policies);
}

int
ni_bonding_xmit_hash_policy_to_type(const char *name)
{
	unsigned int value;

	if (ni_parse_int_mapped(name, __user_xmit_hash_policies, &value) < 0)
		return -1;
	return value;
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
	} else if (!strcmp(attr, "miimon")) {
		if (ni_parse_int(value, &bonding->miimon.frequency) < 0)
			return -1;
		if (bonding->miimon.frequency != 0)
			bonding->monitoring = NI_BOND_MONITOR_MII;
		else
			bonding->monitoring = NI_BOND_MONITOR_ARP;
	} else if (!strcmp(attr, "updelay")) {
		if (ni_parse_int(value, &bonding->miimon.updelay) < 0)
			return -1;
	} else if (!strcmp(attr, "downdelay")) {
		if (ni_parse_int(value, &bonding->miimon.downdelay) < 0)
			return -1;
	} else if (!strcmp(attr, "use_carrier")) {
		if (ni_parse_int(value, &bonding->miimon.carrier_detect) < 0)
			return -1;
	} else if (!strcmp(attr, "arp_validate")) {
		if (__ni_bonding_set_module_option_arp_validate(bonding, value) < 0)
			return -1;
	} else if (!strcmp(attr, "arp_interval")) {
		if (ni_parse_int(value, &bonding->arpmon.interval) < 0)
			return -1;
	} else if (!strcmp(attr, "arp_ip_target")) {
		char *s, *saveptr = NULL;

		for (s = strtok_r(value, ",", &saveptr); s; s = strtok_r(NULL, ",", &saveptr)) {
			struct in_addr dummy;

			if (inet_aton(value, &dummy) == 0)
				return -1;
			ni_string_array_append(&bonding->arpmon.targets, s);
		}
	} else if (!strcmp(attr, "primary")) {
		ni_string_dup(&bonding->primary, value);
	} else if (!strcmp(attr, "xmit_hash_policy")) {
		if (__ni_bonding_set_module_option_xmit_hash_policy(bonding, value) < 0)
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
	memset(buffer, 0, bufsize);
	if (!strcmp(attr, "mode")) {
		return __ni_bonding_get_module_option_mode(bonding, buffer, bufsize);
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
	} else if (!strcmp(attr, "primary")) {
		if (!bonding->primary)
			return 0;
		strncpy(buffer, bonding->primary, bufsize - 1);
	} else if (!strcmp(attr, "xmit_hash_policy")) {
		return __ni_bonding_get_module_option_xmit_hash_policy(bonding, buffer, bufsize);
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
	const char *attrs[] = {
		"mode",
		"miimon",
		"xmit_hash_policy",
		"arp_validate",
		"arp_interval",
		"updelay",
		"downdelay",
		"use_carrier",
		"primary",
		NULL,
	};
	char *attrval = NULL;
	unsigned int i;

	ni_bonding_clear(bonding);
	ni_sysfs_bonding_get_slaves(ifname, &bonding->slave_names);

	for (i = 0; attrs[i]; ++i) {
		const char *attrname = attrs[i];
		int rv;

		if (ni_sysfs_bonding_get_attr(ifname, attrname, &attrval) < 0) {
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

	if (config_value[0] == '\0') {
		ni_debug_ifconfig("%s: attr %s ignored", ifname, attrname);
		return 0;
	}

	if (!strcmp(current_value, config_value)) {
		ni_debug_ifconfig("%s: attr %s unchanged", ifname, attrname);
		return 0;
	}

	/* FIXME: for stage 0 attributes, we should verify that the device is down.
	 * For stage 1 attributes, we should verify that it is up */

	ni_debug_ifconfig("%s: setting attr %s=%s", ifname, attrname, config_value);
	if (ni_sysfs_bonding_set_attr(ifname, attrname, config_value) < 0) {
		ni_error("%s: cannot set bonding attribute %s=%s", ifname, attrname, config_value);
		return -1;
	}

	return 0;
}

/*
 * Write bonding configuration to sysfs.
 * This happens in two stages; the first stage happens prior to enslaving interfaces,
 * the other happens afterwards.
 */
int
ni_bonding_write_sysfs_attrs(const char *ifname, const ni_bonding_t *bonding, const ni_bonding_t *current, int stage)
{
	const char *stage0_attrs[] = {
		"mode",
		"miimon",
		"xmit_hash_policy",

		/* ignored for ARP monitoring: */
		"updelay",
		"downdelay",
		"use_carrier",

		/* ignored for MII monitoring: */
		"arp_interval",
		"arp_validate",
		NULL,
	};
	const char *stage1_attrs[] = {
		"primary",
		NULL,
	};
	const char **attrs;
	unsigned int i;


	attrs = (stage == 0)? stage0_attrs : stage1_attrs;
	for (i = 0; attrs[i]; ++i) {
		if (ni_bonding_write_one_sysfs_attr(ifname, bonding, current, attrs[i]) < 0)
			return -1;
	}

	/* arp_ip_target is special, since it's a list of addrs */
	if (stage == 0 && bonding->monitoring == NI_BOND_MONITOR_ARP
	 && ni_sysfs_bonding_set_list_attr(ifname, "arp_ip_target", &bonding->arpmon.targets) < 0)
		return -1;

	return 0;
}
