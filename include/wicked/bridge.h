/*
 * bridge definitions for netinfo
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_BRIDGE_H__
#define __WICKED_BRIDGE_H__

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

struct ni_bridge_port {
	char *			ifname;
	unsigned int		ifindex;

	unsigned int		priority;
	unsigned int		path_cost;
};

typedef struct ni_bridge_port_array {
	unsigned int		count;
	ni_bridge_port_t **	data;
} ni_bridge_port_array_t;

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
	ni_bridge_port_array_t	ports;
};

extern ni_bridge_t *	ni_bridge_new(void);
extern void		ni_bridge_free(ni_bridge_t *);
extern void		ni_bridge_ports_destroy(ni_bridge_t *);
extern void		ni_bridge_status_destroy(ni_bridge_status_t *);
extern int		ni_bridge_add_port(ni_bridge_t *, ni_bridge_port_t *);
extern int		ni_bridge_del_port(ni_bridge_t *, unsigned int);
extern int		ni_bridge_del_port_ifname(ni_bridge_t *, const char *);
extern int		ni_bridge_del_port_ifindex(ni_bridge_t *, unsigned int);
extern void		ni_bridge_get_port_names(const ni_bridge_t *, ni_string_array_t *);

extern ni_bridge_port_t *ni_bridge_port_new(ni_bridge_t *br, const char *ifname, unsigned int ifindex);
extern ni_bridge_port_t *ni_bridge_port_by_index(const ni_bridge_t *br, unsigned int ifindex);
extern ni_bridge_port_t *ni_bridge_port_by_name(const ni_bridge_t *br, const char *ifname);
extern ni_bridge_port_t *ni_bridge_port_clone(const ni_bridge_port_t *port);
extern void		ni_bridge_port_free(ni_bridge_port_t *port);

extern const char *			ni_bridge_port_priority_validate(unsigned int);
extern const char *			ni_bridge_port_path_cost_validate(unsigned int);
extern const char *			ni_bridge_port_validate(const ni_bridge_port_t *);
extern const char *			ni_bridge_validate(const ni_bridge_t *);

extern unsigned int			ni_bridge_waittime_from_xml(const xml_node_t *brnode);

extern ni_bridge_port_config_t *	ni_bridge_port_config_new(void);
extern void				ni_bridge_port_config_free(ni_bridge_port_config_t *);

extern ni_bridge_port_info_t *		ni_bridge_port_info_new(void);
extern void				ni_bridge_port_info_free(ni_bridge_port_info_t *);

extern const char *			ni_bridge_port_state_name(unsigned int);

#endif /* __WICKED_BRIDGE_H__ */
