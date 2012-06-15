/*
 * Wicked policy handling
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __CLIENT_POLICY_H__
#define __CLIENT_POLICY_H__

#include <wicked/xml.h>
#include <wicked/dbus.h>

typedef struct ni_ifpolicy ni_ifpolicy_t;
typedef struct ni_ifcondition ni_ifcondition_t;
typedef struct ni_ifpolicy_action ni_ifpolicy_action_t;

struct ni_ifpolicy {
	ni_ifpolicy_t *		next;
	char *			name;
	xml_node_t *		node;
	unsigned int		weight;

	ni_ifcondition_t *	match;
	ni_ifpolicy_action_t *	actions;
};


extern void		ni_ifpolicy_install(ni_ifpolicy_t *policy);
extern ni_ifpolicy_t *	ni_ifpolicy_new(const char *, xml_node_t *);

extern ni_ifpolicy_t *	ni_ifpolicy_by_name(const char *);
extern unsigned int	ni_ifpolicy_get_applicable_policies(ni_ifworker_t *, const ni_ifpolicy_t **, unsigned int);
extern xml_node_t *	ni_ifpolicy_transform_document(xml_node_t *, const ni_ifpolicy_t * const *, unsigned int);

#endif /* __CLIENT_POLICY_H__ */
