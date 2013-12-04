/*
 * System functions (configure interfaces and such)
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_SYSTEM_H__
#define __WICKED_SYSTEM_H__

#include <wicked/types.h>

extern int		ni_system_interface_link_change(ni_netdev_t *, const ni_netdev_req_t *);
extern int		ni_system_interface_link_monitor(ni_netdev_t *);

/*
 * Most of this stuff will go as we move things into extension scripts:
 */
extern int		ni_system_interface_stats_refresh(ni_netconfig_t *, ni_netdev_t *);
extern int		ni_system_ipv4_setup(ni_netconfig_t *, ni_netdev_t *, const ni_ipv4_devconf_t *);
extern int		ni_system_ipv6_setup(ni_netconfig_t *, ni_netdev_t *, const ni_ipv6_devconf_t *);
extern int		ni_system_ethernet_setup(ni_netconfig_t *, ni_netdev_t *,
				const ni_ethernet_t *);
extern int		ni_system_infiniband_setup(ni_netconfig_t *, ni_netdev_t *,
				const ni_infiniband_t *);
extern int		ni_system_infiniband_child_create(ni_netconfig_t *, const char *,
				const ni_infiniband_t *, ni_netdev_t **);
extern int		ni_system_infiniband_child_delete(ni_netdev_t *);
extern int		ni_system_vlan_create(ni_netconfig_t *,
				const ni_netdev_t *, ni_netdev_t **);
extern int		ni_system_vlan_delete(ni_netdev_t *);
extern int		ni_system_macvlan_create(ni_netconfig_t *, const char *,
				const ni_macvlan_t *, ni_netdev_t **);
extern int		ni_system_macvlan_delete(ni_netdev_t *);
extern int		ni_system_bridge_create(ni_netconfig_t *, const char *,
				const ni_bridge_t *, ni_netdev_t **);
extern int		ni_system_bridge_setup(ni_netconfig_t *, ni_netdev_t *,
				const ni_bridge_t *);
extern int		ni_system_bridge_add_port(ni_netconfig_t *, ni_netdev_t *,
				ni_bridge_port_t *);
extern int		ni_system_bridge_remove_port(ni_netdev_t *, unsigned int);
extern int		ni_system_bridge_shutdown(ni_netdev_t *);
extern int		ni_system_bridge_delete(ni_netconfig_t *, ni_netdev_t *);
extern int		ni_system_bond_create(ni_netconfig_t *nc, const char *,
				const ni_bonding_t *, ni_netdev_t **);
extern int		ni_system_bond_setup(ni_netconfig_t *nc, ni_netdev_t *,
				const ni_bonding_t *);
extern int		ni_system_bond_delete(ni_netconfig_t *nc, ni_netdev_t *);
extern int		ni_system_bond_shutdown(ni_netdev_t *);
extern int		ni_system_tun_create(ni_netconfig_t *, const char *,
				ni_netdev_t **);
extern int		ni_system_tun_delete(ni_netdev_t *);
extern int		ni_system_ppp_create(ni_netconfig_t *, const char *,
				ni_ppp_t *, ni_netdev_t **);
extern int		ni_system_ppp_delete(ni_netdev_t *);

#endif /* __WICKED_SYSTEM_H__ */

