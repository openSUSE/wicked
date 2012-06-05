/*
 * Wicked policy handling
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __CLIENT_POLICY_H__
#define __CLIENT_POLICY_H__

#include <wicked/xml.h>
#include <wicked/dbus.h>

typedef enum {
	NI_IFPOLICY_TYPE_MERGE,
	NI_IFPOLICY_TYPE_CREATE,
} ni_ifpolicy_type_t;

typedef struct ni_ifpolicy ni_ifpolicy_t;
typedef struct ni_ifcondition ni_ifcondition_t;

struct ni_ifpolicy {
	ni_ifpolicy_t *		next;
	char *			name;
	xml_node_t *		node;
	unsigned int		weight;

	ni_ifcondition_t *	match;
	struct {
		ni_ifpolicy_type_t	type;
		xml_node_t *		data;
	} action;
};


extern void		ni_ifpolicy_install(ni_ifpolicy_t *policy);
extern ni_ifpolicy_t *	ni_ifpolicy_new(const char *, xml_node_t *);

extern ni_ifpolicy_t *	ni_ifpolicy_by_name(const char *);
extern int		ni_ifpolicy_rebind_action(ni_ifworker_t *, struct ni_netif_action_binding *);

#endif /* __CLIENT_POLICY_H__ */
