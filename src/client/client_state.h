/*
 * Routines for runtime-persistent interface fsm ifup state used
 * while ifdown to stop managed interfaces.
 *
 * Copyright (C) 2011 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Authors: Marius Tomaschewski <mt@suse.de>
 *          Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
 */
#ifndef __WICKED_CLIENT_STATE_H__
#define __WICKED_CLIENT_STATE_H__

#define NI_CLIENT_STATE_XML_STATE_NODE	"client-state"
#define NI_CLIENT_STATE_XML_PERSISTENT_NODE	"persistent"
#define NI_CLIENT_STATE_XML_INIT_STATE_NODE	"init-state"
#define NI_CLIENT_STATE_XML_INIT_TIME_NODE	"init-time"
#define NI_CLIENT_STATE_XML_LAST_TIME_NODE	"last-time"

typedef struct ni_client_state {
	ni_bool_t	persistent;	/* allowing/disallowing ifdown flag */
	unsigned int	init_state;	/* state while initial ifup */
	struct timeval	init_time;	/* time of initial ifup     */
	struct timeval	last_time;	/* time of last ifup/reload */
} ni_client_state_t;

extern ni_client_state_t *	ni_client_state_new(unsigned int);
extern void		ni_client_state_init(ni_client_state_t *);
extern ni_client_state_t *	ni_client_state_clone(ni_client_state_t *);
extern void		ni_client_state_free(ni_client_state_t *);

extern ni_bool_t	ni_client_state_set_state(ni_client_state_t *, unsigned int);
extern ni_bool_t	ni_client_state_is_valid_state(unsigned int);
extern const char *	ni_client_state_print(ni_client_state_t *, char **);
extern ni_bool_t	ni_client_state_parse_timeval(const char *, struct timeval *);
extern ni_bool_t	ni_client_state_print_xml(const ni_client_state_t *, xml_node_t *);
extern ni_bool_t	ni_client_state_parse_xml(const xml_node_t *, ni_client_state_t *);
extern ni_bool_t	ni_client_state_load(ni_client_state_t *, unsigned int);
extern ni_bool_t	ni_client_state_save(const ni_client_state_t *, unsigned int);
extern ni_bool_t	ni_client_state_move(unsigned int, unsigned int);
extern ni_bool_t	ni_client_state_drop(unsigned int);

/*
 * Static inline functions
 */
static inline ni_bool_t
ni_client_state_is_valid_time(const struct timeval *tv)
{
	if (tv->tv_sec < 0 || tv->tv_usec < 0)
		return FALSE;
	return (tv->tv_sec || tv->tv_usec);
}

static inline ni_bool_t
ni_client_state_is_valid(const ni_client_state_t *client_state)
{
	return client_state &&
		   ni_client_state_is_valid_state(client_state->init_state) &&
		   ni_client_state_is_valid_time(&client_state->init_time) &&
		   ni_client_state_is_valid_time(&client_state->last_time);
}

static inline const char *
ni_client_state_print_timeval(const struct timeval *tv, char **str)
{
	return ni_string_printf(str, "%lu.%02lu",
			(unsigned long)tv->tv_sec,
			(unsigned long)tv->tv_usec);
}

#endif
