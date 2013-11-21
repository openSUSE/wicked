/*
 * Routines for runtime-persistent interface fsm ifup state used
 * while ifdown to stop managed interfaces.
 *
 * Copyright (C) 2011 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Authors: Marius Tomaschewski <mt@suse.de>
 *
 */
#ifndef __WICKED_IFSTATE_H__
#define __WICKED_IFSTATE_H__

#define NI_IFSTATE_XML_STATE_NODE	"ifstate"
#define NI_IFSTATE_XML_PERSISTENT_NODE	"persistent"
#define NI_IFSTATE_XML_INIT_STATE_NODE	"init-state"
#define NI_IFSTATE_XML_INIT_TIME_NODE	"init-time"
#define NI_IFSTATE_XML_LAST_TIME_NODE	"last-time"

typedef struct ni_ifstate {
	ni_bool_t	persistent;	/* allowing/disallowing ifdown flag */
	unsigned int	init_state;	/* state while initial ifup */
	struct timeval	init_time;	/* time of initial ifup     */
	struct timeval	last_time;	/* time of last ifup/reload */
} ni_ifstate_t;

extern ni_ifstate_t *	ni_ifstate_new(unsigned int);
extern void		ni_ifstate_free(ni_ifstate_t *);

extern ni_bool_t		ni_ifstate_set_state(ni_ifstate_t *, unsigned int);
extern inline ni_bool_t	ni_ifstate_is_valid(const ni_ifstate_t *);
extern inline const char *	ni_ifstate_print(ni_ifstate_t *, char **);
extern const char *		ni_ifstate_print_timeval(const struct timeval *, char **);
extern ni_bool_t		ni_ifstate_parse_timeval(const char *, struct timeval *);
extern ni_bool_t		ni_ifstate_print_xml(const ni_ifstate_t *, xml_node_t *);
extern ni_bool_t		ni_ifstate_parse_xml(const xml_node_t *, ni_ifstate_t *);
extern ni_bool_t		ni_ifstate_load(ni_ifstate_t *, const char *);
extern ni_bool_t		ni_ifstate_save(const ni_ifstate_t *, const char *);
extern ni_bool_t		ni_ifstate_move(const char *, const char *);
extern ni_bool_t		ni_ifstate_drop(const char *);

#endif
