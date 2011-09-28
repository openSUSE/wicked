/*
 * bridge definitions for netinfo
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_BRIDGE_H__
#define __WICKED_BRIDGE_H__

enum {
	NI_BRIDGE_NO_STP = 0,			/* no spanning tree */
	NI_BRIDGE_STP,				/* old STP in kernel */
	NI_BRIDGE_RSTP,				/* new RSTP in userspace */
};

enum {
	NI_BRIDGE_STP_ENABLED	= 1,		/* bridge config options */
	NI_BRIDGE_FORWARD_DELAY	= 2,
	NI_BRIDGE_AGEING_TIME	= 3,
	NI_BRIDGE_HELLO_TIME	= 4,
	NI_BRIDGE_MAX_AGE	= 5,
	NI_BRIDGE_PRIORITY	= 6,
	NI_BRIDGE_PORT_PRIORITY	= 7,		/* bridge port config options */
	NI_BRIDGE_PORT_PATH_COST= 8,
};

typedef struct ni_bridge_port_config {
	unsigned int		priority;
	unsigned int		path_cost;
} ni_bridge_port_config_t;

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

typedef struct ni_bridge_port {
	char *			name;
	ni_interface_t *	device;
	ni_bridge_port_config_t config;
	ni_bridge_port_status_t	*status;
} ni_bridge_port_t;

typedef struct ni_bridge_port_array {
	unsigned int		count;
	ni_bridge_port_t **	data;
} ni_bridge_port_array_t;

typedef struct ni_bridge_config {
	unsigned int		priority;
	int			stp_enabled;

	/* The following should probably be changed to type double */
	unsigned long		forward_delay;	/* time in 1/100 sec */
	unsigned long		ageing_time;	/* time in 1/100 sec */
	unsigned long		hello_time;	/* time in 1/100 sec */
	unsigned long		max_age;	/* time in 1/100 sec */
} ni_bridge_config_t;

typedef struct ni_bridge_status {
	/* Not sure why this is duplicated from bridge_config. Marius? */
#if 1
	unsigned int		priority;
	unsigned long		forward_delay;
	unsigned long		ageing_time;
	unsigned long		hello_time;
	unsigned long		max_age;
#endif
	int			stp_state;

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
	ni_bridge_config_t	config;
	ni_bridge_status_t *	status;
	ni_bridge_port_array_t	ports;
};

extern int		ni_bridge_bind(ni_interface_t *, ni_handle_t *);
extern ni_bridge_t *	ni_bridge_new(void);
extern void		ni_bridge_free(ni_bridge_t *);
extern void		ni_bridge_status_free(ni_bridge_status_t *);
extern void		ni_bridge_port_status_free(ni_bridge_port_status_t *);
extern ni_bridge_t *	ni_bridge_clone(const ni_bridge_t *);
extern int		ni_bridge_add_port(ni_bridge_t *, const char *);
extern int		ni_bridge_del_port(ni_bridge_t *, const char *);
extern void		ni_bridge_get_port_names(const ni_bridge_t *, ni_string_array_t *);
extern int		ni_bridge_get(ni_bridge_t *, unsigned int, char **);
extern int		ni_bridge_get_stp(ni_bridge_t *, char **);
extern int		ni_bridge_get_forward_delay(ni_bridge_t *, char **);
extern int		ni_bridge_get_ageing_time(ni_bridge_t *, char **);
extern int		ni_bridge_get_hello_time(ni_bridge_t *, char **);
extern int		ni_bridge_get_max_age(ni_bridge_t *, char **);
extern int		ni_bridge_get_priority(ni_bridge_t *, char **);
extern int		ni_bridge_set_stp(ni_bridge_t *, const char *);
extern int		ni_bridge_set_forward_delay(ni_bridge_t *, const char *);
extern int		ni_bridge_set_ageing_time(ni_bridge_t *, const char *);
extern int		ni_bridge_set_hello_time(ni_bridge_t *, const char *);
extern int		ni_bridge_set_max_age(ni_bridge_t *, const char *);
extern int		ni_bridge_set_priority(ni_bridge_t *, const char *);
extern int		ni_bridge_port_get(ni_bridge_t *, const char *, unsigned int, char **);
extern int		ni_bridge_port_get_priority(ni_bridge_t *,const char *, char **);
extern int		ni_bridge_port_get_path_cost(ni_bridge_t *,const char *, char **);
extern int		ni_bridge_port_set_priority(ni_bridge_t *,const char *, const char *);
extern int		ni_bridge_port_set_path_cost(ni_bridge_t *,const char *, const char *);

#endif /* __WICKED_BRIDGE_H__ */
