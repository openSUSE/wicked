/*
 * Bonding support for netinfo
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_BONDING_H__
#define __WICKED_BONDING_H__

enum {
	NI_BOND_MONITOR_MII = 1,
	NI_BOND_MONITOR_ARP = 2,
};

enum {
	NI_BOND_MODE_BALANCE_RR = 0,
	NI_BOND_MODE_ACTIVE_BACKUP = 1,
	NI_BOND_MODE_BALANCE_XOR = 2,
	NI_BOND_MODE_BROADCAST = 3,
	NI_BOND_MODE_802_3AD = 4,
	NI_BOND_MODE_BALANCE_TLB = 5,
	NI_BOND_MODE_BALANCE_ALB = 6,
};
enum {
	NI_BOND_VALIDATE_NONE = 0,
	NI_BOND_VALIDATE_ACTIVE = 1,
	NI_BOND_VALIDATE_BACKUP = 2,
	NI_BOND_VALIDATE_ALL = 3,
};
enum {
	NI_BOND_CARRIER_DETECT_IOCTL = 0,
	NI_BOND_CARRIER_DETECT_NETIF = 1,
};
enum {
	NI_BOND_XMIT_HASH_LAYER2 = 0,
	NI_BOND_XMIT_HASH_LAYER2_3 = 1,
	NI_BOND_XMIT_HASH_LAYER3_4 = 2,
};
enum {
	NI_BOND_LACP_RATE_SLOW = 0,
	NI_BOND_LACP_RATE_FAST = 1,
};
enum {
	NI_BOND_AD_SELECT_STABLE = 0,
	NI_BOND_AD_SELECT_BANDWIDTH = 1,
	NI_BOND_AD_SELECT_COUNT = 2,
};
enum {
	NI_BOND_FAIL_OVER_MAC_NONE = 0,
	NI_BOND_FAIL_OVER_MAC_ACTIVE = 1,
	NI_BOND_FAIL_OVER_MAC_FOLLOW = 2,
};
enum {
	NI_BOND_PRIMARY_RESELECT_ALWAYS = 0,
	NI_BOND_PRIMARY_RESELECT_BETTER = 1,
	NI_BOND_PRIMARY_RESELECT_FAILURE = 2,
};

struct ni_bonding {
	unsigned int		mode;

	int			monitoring;
	struct ni_bonding_arpmon {
		unsigned int	interval;	/* ms */
		unsigned int	validate;
		ni_string_array_t targets;
	}			arpmon;
	struct ni_bonding_miimon {
		unsigned int	frequency;
		unsigned int	updelay;
		unsigned int	downdelay;
		unsigned int	carrier_detect;
	}			miimon;

	unsigned int		xmit_hash_policy;
	unsigned int		lacp_rate;
	unsigned int		ad_select;
	unsigned int		min_links;
	unsigned int		all_slaves_active;
	unsigned int		primary_reselect;
	unsigned int		fail_over_mac;
	unsigned int		num_grat_arp;
	unsigned int		num_unsol_na;
	unsigned int		resend_igmp;

	char *			primary;
	char *			requested_primary;

	ni_string_array_t	slave_names;
};

extern int		ni_bonding_load(const char *options);

extern ni_bonding_t *	ni_bonding_new(void);
extern void		ni_bonding_free(ni_bonding_t *);

extern ni_bool_t	ni_bonding_add_slave(ni_bonding_t *, const char *);
extern ni_bool_t	ni_bonding_set_option(ni_bonding_t *, const char *, const char *);

extern int		ni_bonding_parse_sysfs_attrs(const char *, ni_bonding_t *);
extern int		ni_bonding_write_sysfs_attrs(const char *ifname,
						const ni_bonding_t *cfg_bond,
						const ni_bonding_t *cur_bond,
						int state);

extern const char *	ni_bonding_validate(const ni_bonding_t *bonding);

extern const char *	ni_bonding_mode_type_to_name(unsigned int);
extern int		ni_bonding_mode_name_to_type(const char *);

extern const char *	ni_bonding_validate_type_to_name(unsigned int);
extern int		ni_bonding_validate_name_to_type(const char *);

extern const char *	ni_bonding_xmit_hash_policy_to_name(unsigned int);
extern int		ni_bonding_xmit_hash_name_to_policy(const char *);

extern const char *	ni_bonding_lacp_rate_name(unsigned int);
extern int		ni_bonding_lacp_rate_mode(const char *);

extern const char *	ni_bonding_ad_select_name(unsigned int);
extern int		ni_bonding_ad_select_mode(const char *);

extern const char *	ni_bonding_primary_reselect_name(unsigned int);
extern int		ni_bonding_primary_reselect_mode(const char *);

extern const char *	ni_bonding_fail_over_mac_name(unsigned int);
extern int		ni_bonding_fail_over_mac_mode(const char *);

extern const char *	ni_bonding_carrier_detect_name(unsigned int);
extern int		ni_bonding_carrier_detect_type(const char *);


#endif /* __WICKED_BONDING_H__ */
