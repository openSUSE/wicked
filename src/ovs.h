/*
 *	OVS (bridge) device ctl operations
 *
 *	Copyright (C) 2015-2023 SUSE LLC
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef NI_WICKED_OVS_CTL_H
#define NI_WICKED_OVS_CTL_H

#include <wicked/types.h>
#include <wicked/ovs.h>

extern int	ni_ovs_vsctl_bridge_add(const ni_netdev_t *, ni_bool_t);
extern int	ni_ovs_vsctl_bridge_del(const char *);
extern int	ni_ovs_vsctl_bridge_exists(const char *);
extern int	ni_ovs_vsctl_bridge_to_vlan(const char *, uint16_t *);
extern int	ni_ovs_vsctl_bridge_to_parent(const char *, char **);
extern int	ni_ovs_vsctl_bridge_ports(const char *, ni_netdev_ref_array_t *);

extern int	ni_ovs_vsctl_bridge_port_add(const char *, const char *,
				const ni_ovs_bridge_port_config_t *, ni_bool_t);
extern int	ni_ovs_vsctl_bridge_port_del(const char *, const char *);
extern int	ni_ovs_vsctl_bridge_port_to_bridge(const char *, char **);

extern int	ni_ovs_bridge_discover(ni_netdev_t *, ni_netconfig_t *);
extern int	ni_ovs_port_info_discover(ni_netdev_port_info_t *,
				const char *, ni_netconfig_t *);

#endif /* NI_WICKED_OVS_CTL_H */
