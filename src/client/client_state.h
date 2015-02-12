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
#include <unistd.h>
#include <wicked/logging.h>

#define NI_CLIENT_STATE_XML_NODE		"client-state"

#define NI_CLIENT_STATE_XML_CONTROL_NODE	"control"
#define NI_CLIENT_STATE_XML_PERSISTENT_NODE	"persistent"
#define NI_CLIENT_STATE_XML_USERCONTROL_NODE	"usercontrol"
#define NI_CLIENT_STATE_XML_REQUIRE_LINK_NODE	"require-link"

#define NI_CLIENT_STATE_XML_CONFIG_NODE		"config"
#define NI_CLIENT_STATE_XML_CONFIG_UUID_NODE	"uuid"
#define NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE	"origin"
#define NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE	"owner-uid"

typedef struct ni_client_state_control {
	ni_bool_t	persistent;	/* allowing/disallowing ifdown flag */
	ni_bool_t	usercontrol;	/* allowing/disallowing user to change the config */
	ni_tristate_t	require_link;	/* require link-up or ignore link detection results
					   and consider an administrative UP as sufficient? */
} ni_client_state_control_t;

typedef struct ni_client_state_config {
	ni_uuid_t	uuid;		/* Configuration UUID marker of the interface */
	char *		origin;		/* Source of the configuration of the interface */
	uid_t		owner;		/* User's UID who has initiated the given configuration */
} ni_client_state_config_t;
#define NI_CLIENT_STATE_CONFIG_INIT { .uuid = NI_UUID_INIT, .origin = NULL, .owner = -1U }

typedef struct ni_client_state {
	ni_client_state_control_t	control;
	ni_client_state_config_t	config;
} ni_client_state_t;

extern ni_client_state_t *	ni_client_state_new(unsigned int);
extern ni_client_state_t *	ni_client_state_clone(ni_client_state_t *);
extern void		ni_client_state_init(ni_client_state_t *);
extern void		ni_client_state_reset(ni_client_state_t *);
extern void		ni_client_state_free(ni_client_state_t *);
extern void		ni_client_state_config_init(ni_client_state_config_t *);
extern void		ni_client_state_config_reset(ni_client_state_config_t *);
extern void		ni_client_state_config_copy(ni_client_state_config_t *,
						const ni_client_state_config_t *);
extern void		ni_client_state_control_init(ni_client_state_control_t *);
extern void		ni_client_state_control_reset(ni_client_state_control_t *);
extern void		ni_client_state_control_copy(ni_client_state_control_t *,
						const ni_client_state_control_t *);
extern ni_bool_t	ni_client_state_control_is_valid(const ni_client_state_control_t *);
extern ni_bool_t	ni_client_state_config_is_valid(const ni_client_state_config_t *);
extern ni_bool_t	ni_client_state_is_valid(const ni_client_state_t *);

extern ni_bool_t	ni_client_state_parse_timeval(const char *, struct timeval *);
extern ni_bool_t	ni_client_state_config_print_xml(const ni_client_state_config_t *, xml_node_t *);
extern ni_bool_t	ni_client_state_print_xml(const ni_client_state_t *, xml_node_t *);
extern ni_bool_t	ni_client_state_config_parse_xml(const xml_node_t *, ni_client_state_config_t *);
extern ni_bool_t	ni_client_state_parse_xml(const xml_node_t *, ni_client_state_t *);
extern ni_bool_t	ni_client_state_load(ni_client_state_t *, unsigned int);
extern ni_bool_t	ni_client_state_save(const ni_client_state_t *, unsigned int);
extern ni_bool_t	ni_client_state_move(unsigned int, unsigned int);
extern ni_bool_t	ni_client_state_drop(unsigned int);
extern ni_bool_t	ni_client_state_set_persistent(xml_node_t *);

extern void		ni_client_state_control_debug(const char *, const ni_client_state_control_t *, const char *);
extern void		ni_client_state_config_debug(const char *, const ni_client_state_config_t *, const char *);
extern void		ni_client_state_debug(const char *, const ni_client_state_t *, const char *);

/*
 * Static inline functions
 */
static inline const char *
ni_client_state_print_timeval(const struct timeval *tv, char **str)
{
	return ni_string_printf(str, "%lu.%02lu",
			(unsigned long)tv->tv_sec,
			(unsigned long)tv->tv_usec);
}

#endif
