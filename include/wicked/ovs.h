/*
 *	OVS (bridge) device support
 *
 *	Copyright (C) 2015 SUSE Linux GmbH, Nuernberg, Germany.
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
 *		Marius Tomaschewski <mt@suse.de>
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
	ni_netdev_ref_t			bridge;
};

/*
 * OVS Bridge port interface info properties
 */
struct ni_ovs_bridge_port_info {
	ni_netdev_ref_t			bridge;
};

/*
 * ovs bridge port
 */
struct ni_ovs_bridge_port {
	ni_netdev_ref_t			device;
};

ni_declare_ptr_array_type(ni_ovs_bridge_port);


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
	ni_ovs_bridge_port_array_t	ports;
};


extern ni_ovs_bridge_t *	ni_ovs_bridge_new(void);
extern void			ni_ovs_bridge_free(ni_ovs_bridge_t *);
extern void			ni_ovs_bridge_config_init(ni_ovs_bridge_config_t *);
extern void			ni_ovs_bridge_config_destroy(ni_ovs_bridge_config_t *);

extern ni_ovs_bridge_port_t *	ni_ovs_bridge_port_new(void);
extern void			ni_ovs_bridge_port_free(ni_ovs_bridge_port_t *);

extern				ni_declare_ptr_array_init(ni_ovs_bridge_port);
extern				ni_declare_ptr_array_destroy(ni_ovs_bridge_port);
extern				ni_declare_ptr_array_append(ni_ovs_bridge_port);
extern				ni_declare_ptr_array_delete_at(ni_ovs_bridge_port);
extern ni_ovs_bridge_port_t *	ni_ovs_bridge_port_array_add_new(ni_ovs_bridge_port_array_t *, const char *);
extern ni_ovs_bridge_port_t *	ni_ovs_bridge_port_array_find_by_name(ni_ovs_bridge_port_array_t *, const char *);

extern void			ni_ovs_bridge_port_config_init(ni_ovs_bridge_port_config_t *);
extern void			ni_ovs_bridge_port_config_destroy(ni_ovs_bridge_port_config_t *);

extern ni_ovs_bridge_port_info_t *	ni_ovs_bridge_port_info_new(void);
extern void				ni_ovs_bridge_port_info_free(ni_ovs_bridge_port_info_t *);

#endif /* NI_WICKED_OVS_H */
