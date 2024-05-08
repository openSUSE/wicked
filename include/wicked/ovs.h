/*
 *	OVS (bridge) device support
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
#ifndef NI_WICKED_OVS_H
#define NI_WICKED_OVS_H

#include <wicked/array.h>

typedef struct ni_ovs_bridge_config	ni_ovs_bridge_config_t;
typedef struct ni_ovs_bridge_port	ni_ovs_bridge_port_t;

/*
 * ovs bridge port config
 */
struct ni_ovs_bridge_port_config {
	ni_var_array_t			args; /* currently unused   */
};

/*
 * OVS Bridge port interface info properties
 */
struct ni_ovs_bridge_port_info {
	ni_netdev_ref_t			bridge; /* wickedd internal */
};

/*
 * ovs bridge config
 */
struct ni_ovs_bridge_config {
	struct {
		ni_netdev_ref_t		parent;
		uint16_t		tag;
	} vlan;
};

/*
 * ovs bridge
 */
struct ni_ovs_bridge {
	ni_ovs_bridge_config_t		config;
};


extern ni_ovs_bridge_t *		ni_ovs_bridge_new(void);
extern void				ni_ovs_bridge_free(ni_ovs_bridge_t *);
extern void				ni_ovs_bridge_config_init(ni_ovs_bridge_config_t *);
extern void				ni_ovs_bridge_config_destroy(ni_ovs_bridge_config_t *);

extern ni_ovs_bridge_port_config_t *	ni_ovs_bridge_port_config_new(void);
extern ni_bool_t			ni_ovs_bridge_port_config_init(ni_ovs_bridge_port_config_t *);
extern void				ni_ovs_bridge_port_config_destroy(ni_ovs_bridge_port_config_t *);
extern void				ni_ovs_bridge_port_config_free(ni_ovs_bridge_port_config_t *);

extern ni_ovs_bridge_port_info_t *	ni_ovs_bridge_port_info_new(void);
extern void				ni_ovs_bridge_port_info_free(ni_ovs_bridge_port_info_t *);

#endif /* NI_WICKED_OVS_H */
