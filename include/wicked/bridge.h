/*
 * bridge definitions for netinfo
 *
 * Copyright (C) 2009-2011 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_BRIDGE_H__
#define __WICKED_BRIDGE_H__

typedef enum ni_bridge_stp {
	NI_BRIDGE_NO_STP = 0,			/* no spanning tree */
	NI_BRIDGE_STP,				/* old STP in kernel */
	NI_BRIDGE_RSTP,				/* new RSTP in userspace */
} ni_bridge_stp_t;

typedef struct ni_bridge_port_status {
	unsigned int		priority;
	unsigned int		path_cost;

	int			state;
	unsigned int		port_id;
	unsigned int		port_no;

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
} ni_bridge_port_status_t;

struct ni_bridge_port {
	char *			ifname;
	unsigned int		ifindex;

	unsigned int		priority;
	unsigned int		path_cost;

	ni_bridge_port_status_t	status;
};

typedef struct ni_bridge_port_array {
	unsigned int		count;
	ni_bridge_port_t **	data;
} ni_bridge_port_array_t;

typedef struct ni_bridge_status {
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
	unsigned int		priority;
	ni_bridge_stp_t		stp;

	/* The following should probably be changed to type double */
	unsigned int		forward_delay;	/* time in 1/100 sec */
	unsigned int		ageing_time;	/* time in 1/100 sec */
	unsigned int		hello_time;	/* time in 1/100 sec */
	unsigned int		max_age;	/* time in 1/100 sec */

	ni_bridge_status_t	status;
	ni_bridge_port_array_t	ports;
};

extern ni_bridge_t *	ni_bridge_new(void);
extern void		ni_bridge_free(ni_bridge_t *);
extern void		ni_bridge_ports_destroy(ni_bridge_t *);
extern void		ni_bridge_status_destroy(ni_bridge_status_t *);
extern void		ni_bridge_port_status_destroy(ni_bridge_port_status_t *);
extern int		ni_bridge_add_port(ni_bridge_t *, const ni_bridge_port_t *);
extern int		ni_bridge_del_port(ni_bridge_t *, unsigned int ifindex);
extern int		ni_bridge_del_port_ifindex(ni_bridge_t *, int);
extern void		ni_bridge_get_port_names(const ni_bridge_t *, ni_string_array_t *);

extern ni_bridge_port_t *ni_bridge_port_new(ni_bridge_t *br, const char *ifname, unsigned int ifindex);
extern ni_bridge_port_t *ni_bridge_port_by_index(const ni_bridge_t *br, unsigned int ifindex);
extern ni_bridge_port_t *ni_bridge_port_by_name(const ni_bridge_t *br, const char *ifname);
extern void		ni_bridge_port_free(ni_bridge_port_t *port);

#endif /* __WICKED_BRIDGE_H__ */
