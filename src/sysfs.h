/*
 * Routines for loading and storing sysconfig files
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __NETINFO_SYSFS_H__
#define __NETINFO_SYSFS_H__

extern int	ni_sysfs_netif_get_int(const char *, const char *, int *);
extern int	ni_sysfs_bonding_available(void);
extern int	ni_sysfs_bonding_get_masters(ni_string_array_t *list);
extern int	ni_sysfs_bonding_is_master(const char *);
extern int	ni_sysfs_bonding_add_master(const char *);
extern int	ni_sysfs_bonding_delete_master(const char *);
extern int	ni_sysfs_bonding_get_slaves(const char *, ni_string_array_t *);
extern int	ni_sysfs_bonding_add_slave(const char *, const char *);
extern int	ni_sysfs_bonding_delete_slave(const char *, const char *);
extern int	ni_sysfs_bonding_get_slaves(const char *, ni_string_array_t *);
extern int	ni_sysfs_bonding_get_attr(const char *, const char *, char **);
extern int	ni_sysfs_bonding_set_attr(const char *, const char *, const char *);
extern int	ni_sysfs_bonding_get_arp_targets(const char *, ni_string_array_t *);
extern int	ni_sysfs_bonding_add_arp_target(const char *, const char *);
extern int	ni_sysfs_bonding_delete_arp_target(const char *, const char *);
extern int	ni_sysfs_bonding_set_list_attr(const char *, const char *, const ni_string_array_t *);

#endif /* __NETINFO_SYSFS_H__ */
