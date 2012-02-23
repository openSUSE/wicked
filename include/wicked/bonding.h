/*
 * Bonding support for netinfo
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_BONDING_H__
#define __WICKED_BONDING_H__

enum {
	NI_BOND_MONITOR_ARP,
	NI_BOND_MONITOR_MII,
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

struct ni_bonding {
	/* This is where we store the module options taken from
	 * the sysconfig files. Most distros don't bother with breaking
	 * these up into lots of little pieces; they just use one
	 * string.
	 * So we store the string, then analyze it.
	 */
	char *			module_opts;

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
	char *			primary;	/* FIXME: rename to primary_name/primary_dev */
	ni_interface_t *	primary_ptr;
	char *			extra_options;

	ni_string_array_t	slave_names;
	ni_interface_array_t	slave_devs;
};

extern ni_bonding_t *	ni_bonding_new(void);
extern void		ni_bonding_free(ni_bonding_t *);
extern void		ni_bonding_add_slave(ni_bonding_t *, const char *);
extern void		ni_bonding_parse_module_options(ni_bonding_t *);
extern void		ni_bonding_build_module_options(ni_bonding_t *);
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


#endif /* __WICKED_BONDING_H__ */
