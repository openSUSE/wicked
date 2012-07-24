/*
 * Wicked policy handling
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __CLIENT_POLICY_H__
#define __CLIENT_POLICY_H__

#include <wicked/xml.h>
#include <wicked/dbus.h>

typedef struct ni_ifcondition ni_ifcondition_t;
typedef struct ni_fsm_policy_action ni_fsm_policy_action_t;

struct ni_fsm_policy {
	ni_fsm_policy_t *	next;
	char *			name;
	xml_node_t *		node;
	unsigned int		weight;

	ni_ifcondition_t *	match;
	ni_fsm_policy_action_t *actions;
};

#endif /* __CLIENT_POLICY_H__ */
