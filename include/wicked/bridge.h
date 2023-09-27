/*
 *	bridge definitions for netinfo
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2012-2023 SUSE LLC
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
#ifndef NI_WICKED_BRIDGE_H
#define NI_WICKED_BRIDGE_H


#define NI_BRIDGE_VALUE_NOT_SET			-1U

/*
 * Bridge port (link-request) configuration
 */
struct ni_bridge_port_config {
	unsigned int		priority;
	unsigned int		path_cost;
};

/*
 * Bridge port interface info properties
 */
struct ni_bridge_port_info {
	unsigned int		state;
	unsigned int		port_id;
	unsigned int		port_no;

	unsigned int		priority;
	unsigned int		path_cost;

	char *			designated_root;
	char *			designated_bridge;

	unsigned int		designated_cost;
	unsigned int		designated_port;

	unsigned int		change_ack;
	unsigned int		hairpin_mode;
	unsigned int		config_pending;

	unsigned long		hold_timer;
	unsigned long		message_age_timer;
	unsigned long		forward_delay_timer;
};

typedef enum ni_bridge_stp {
	NI_BRIDGE_NO_STP = 0,			/* no spanning tree    */
	NI_BRIDGE_KERN_STP,			/* STP in the kernel   */
	NI_BRIDGE_USER_STP,			/* (R)STP in userspace */
} ni_bridge_stp_t;

typedef struct ni_bridge_status {
	unsigned int		stp_state;
	char *			root_id;
	char *			bridge_id;
	char *			group_addr;

	unsigned int		root_port;
	unsigned int		root_path_cost;
	unsigned int		topology_change;
	unsigned int		topology_change_detected;

	unsigned long		gc_timer;
	unsigned long		tcn_timer;
	unsigned long		hello_timer;
	unsigned long		topology_change_timer;
} ni_bridge_status_t;

struct ni_bridge {
	ni_bool_t		stp;
	unsigned int		priority;
	double			forward_delay;
	double			ageing_time;
	double			hello_time;
	double			max_age;

	ni_bridge_status_t	status;
};

extern ni_bridge_t *			ni_bridge_new(void);
extern void				ni_bridge_free(ni_bridge_t *);
extern void				ni_bridge_status_destroy(ni_bridge_status_t *);

extern unsigned int			ni_bridge_waittime_from_xml(const xml_node_t *brnode);

extern const char *			ni_bridge_port_priority_validate(unsigned int);
extern const char *			ni_bridge_port_path_cost_validate(unsigned int);
extern const char *			ni_bridge_validate(const ni_bridge_t *);

extern ni_bridge_port_config_t *	ni_bridge_port_config_new(void);
extern void				ni_bridge_port_config_free(ni_bridge_port_config_t *);

extern ni_bridge_port_info_t *		ni_bridge_port_info_new(void);
extern void				ni_bridge_port_info_free(ni_bridge_port_info_t *);

extern const char *			ni_bridge_port_state_name(unsigned int);

#endif /* NI_WICKED_BRIDGE_H */
