/*
 * Wicked policy handling.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/modem.h>
#include <wicked/wireless.h>
#include <wicked/fsm.h>
#include <limits.h>

#include "client/ifxml.h"
#include "util_priv.h"
#include "refcount_priv.h"
#include "array_priv.h"

#define NI_FSM_POLICY_ARRAY_CHUNK	2

/*
 * The <match> expression
 */
typedef struct ni_ifcondition	ni_ifcondition_t;
typedef ni_bool_t	ni_ifcondition_check_fn_t(const ni_ifcondition_t *, const ni_fsm_t *, ni_ifworker_t *);
typedef void		ni_ifcondition_free_fn_t(ni_ifcondition_t *);

struct ni_ifcondition {
	ni_ifcondition_check_fn_t *	check;
	ni_ifcondition_free_fn_t *	free;

	union {
		struct {
			ni_ifworker_type_t	type;
			ni_ifcondition_t *	ref;
		};
		struct {
			ni_ifcondition_t *left;
			ni_ifcondition_t *right;
		} terms;
		const ni_dbus_class_t *	class;
		char *			string;
		unsigned int		uint;
	} args;
};

/*
 * A template operates on one or more devices, aggregating
 * them or building a virtual device on top of them.
 */
typedef struct ni_fsm_template_input	ni_fsm_template_input_t;
struct ni_fsm_template_input {
	ni_fsm_template_input_t *	next;

	char *				id;

	ni_bool_t			shared;
	ni_ifcondition_t *		match;

	ni_ifworker_t *			device;
};

/*
 * Actions associated with the policy - <merge>, <create> etc.
 */
typedef enum {
	NI_FSM_POLICY_ACTION_MERGE,
	NI_FSM_POLICY_ACTION_REPLACE,
	NI_FSM_POLICY_ACTION_CREATE,
} ni_fsm_policy_action_type_t;

typedef struct ni_fsm_policy_action ni_fsm_policy_action_t;
struct ni_fsm_policy_action {
	ni_fsm_policy_action_t *	next;
	ni_fsm_policy_action_type_t	type;
	xml_node_t *			data;

	/* An xml policy may specify the node it
	 * applies to by a path, which is a bit like a very
	 * simple xpath, like /foo/bar/baz.
	 */
	char *				xpath;
	ni_bool_t			final;

	/* Templates can create one or more devices */
	struct {
		const ni_dbus_class_t *	class;
		unsigned int		serial;
		ni_bool_t		instantiate_multi;
		ni_fsm_template_input_t *inputs;
	} create;
};

/*
 * Opaque policy object
 */
typedef enum {
	NI_FSM_POLICY_TYPE_CONFIG,
	NI_FSM_POLICY_TYPE_TEMPLATE,
} ni_fsm_policy_type_t;

struct ni_fsm_policy {
	ni_refcount_t			refcount;

	ni_fsm_policy_t **		pprev;
	ni_fsm_policy_t *		next;

	unsigned int			seq;

	ni_fsm_policy_type_t		type;
	char *				name;
	xml_node_t *			node;
	ni_uuid_t			uuid;
	uid_t				owner;
	unsigned int			weight;

	struct {
		ni_ifworker_type_t	type;
		const ni_dbus_class_t *	class;
	} config;

	ni_ifcondition_t *		match;

	ni_fsm_policy_action_t *	create_action;
	ni_fsm_policy_action_t *	actions;
};


static ni_ifcondition_t *	ni_fsm_policy_conditions_from_xml(xml_node_t *);
static ni_bool_t		ni_ifcondition_check(const ni_ifcondition_t *, const ni_fsm_t *, ni_ifworker_t *);
static ni_ifcondition_t *	ni_ifcondition_from_xml(xml_node_t *);
static void			ni_ifcondition_free(ni_ifcondition_t *);
static ni_fsm_policy_action_t *	ni_fsm_policy_action_new(ni_fsm_policy_action_type_t, xml_node_t *, ni_fsm_policy_t *);
static void			ni_fsm_policy_action_free(ni_fsm_policy_action_t *);
static xml_node_t *		ni_fsm_policy_action_xml_merge(const ni_fsm_policy_action_t *, xml_node_t *);
static xml_node_t *		ni_fsm_policy_action_xml_replace(const ni_fsm_policy_action_t *, xml_node_t *);
static xml_node_t *		ni_fsm_template_build_document(ni_fsm_policy_t *policy, ni_fsm_policy_action_t *action);
static ni_bool_t		ni_fsm_template_bind_devices(ni_fsm_policy_t *, ni_fsm_policy_action_t *, xml_node_t *);
static ni_fsm_template_input_t *ni_fsm_template_input_new(const char *id, ni_fsm_template_input_t ***tailp);
static void			ni_fsm_template_input_free(ni_fsm_template_input_t *);

/*
 * fsm policy list primitives
 */
static inline void
ni_fsm_policy_list_insert(ni_fsm_policy_t **list, ni_fsm_policy_t *policy)
{
	policy->pprev = list;
	policy->next = *list;
	if (policy->next)
		policy->next->pprev = &policy->next;
	*list = policy;
}

static inline void
ni_fsm_policy_list_unlink(ni_fsm_policy_t *policy)
{
	ni_fsm_policy_t **pprev, *next;

	pprev = policy->pprev;
	next = policy->next;
	if (pprev)
		*pprev = next;
	if (next)
		next->pprev = pprev;
	policy->pprev = NULL;
	policy->next = NULL;
}


/*
 * Destructor for policy objects
 */
static void
ni_fsm_policy_reset(ni_fsm_policy_t *policy)
{
	if (policy->match) {
		ni_ifcondition_free(policy->match);
		policy->match = NULL;
	}
	while (policy->actions) {
		ni_fsm_policy_action_t *a = policy->actions;

		policy->actions = a->next;
		ni_fsm_policy_action_free(a);
	}
	if (policy->create_action) {
		ni_fsm_policy_action_free(policy->create_action);
		policy->create_action = NULL;
	}
}

static void
ni_fsm_policy_destroy(ni_fsm_policy_t *policy)
{
	ni_fsm_policy_list_unlink(policy);
	ni_fsm_policy_reset(policy);
	ni_string_free(&policy->name);
	xml_node_free(policy->node);
	memset(policy, 0, sizeof(*policy));
}

/*
 * Constructor for policy objects
 */
static ni_bool_t
ni_fsm_policy_type_from_xml(ni_fsm_policy_t *policy, xml_node_t *node)
{
	if (ni_string_eq(node->name, NI_NANNY_IFPOLICY)) {
		policy->type = NI_FSM_POLICY_TYPE_CONFIG;
		return TRUE;
	}
#ifdef NI_ENABLE_NANNY_TEMPLATE
	if (ni_string_eq(node->name, NI_NANNY_IFTEMPLATE)) {
		policy->type = NI_FSM_POLICY_TYPE_TEMPLATE;
		return TRUE;
	}
#endif
	ni_error("%s: invalid policy, node must be either <%s> or <%s>",
			xml_node_location(node),
			NI_NANNY_IFPOLICY, NI_NANNY_IFTEMPLATE);
	return FALSE;
}

static ni_bool_t
ni_fsm_policy_name_from_xml(ni_fsm_policy_t *policy, xml_node_t *node)
{
	const char *name = ni_ifpolicy_get_name(node);

	if (!ni_ifpolicy_name_is_valid(name)) {
		ni_error("%s: invalid %s name \"%s\"",
				xml_node_location(node), node->name,
				ni_print_suspect(name, ni_string_len(name)));
		return FALSE;
	}

	return ni_string_dup(&policy->name, name);
}

static ni_bool_t
ni_fsm_policy_class_from_xml(ni_fsm_policy_t *policy, xml_node_t *node)
{
	/*
	 * Without a worker, we cannot match if the policy is applicable
	 * as the match expression matches properties of the worker and/or
	 * the netif device/modem inside the worker.
	 *
	 * We need to know the worker type a policy configures to create
	 * a worker from the policy config for (virtual) interfaces that
	 * do not exist yet (in the kernel/wickedd).
	 *
	 * The content of the policy <merge/> and/or <replace/> nodes is
	 * transformed into the effective (wickedd) config and we need
	 * to know if to use an <interface/> or <modem/> node for it.
	 *
	 * Once the worker exist, we can bind factory to create the
	 * virtual interface or wait until it the expected interface
	 * (or modem) has been detected, match it and start the setup.
	 */
	const ni_dbus_class_t *class;
	const char *name;

	name = ni_ifpolicy_get_class(node);
#ifndef MODEM
	if (ni_string_empty(name)) {
		name = NI_OBJECTMODEL_NETIF_CLASS;
		ni_debug_xml("%s: policy without class declaration,"
				" assuming class=\"%s\"",
				xml_node_location(node), name);
	}
#endif

	class = ni_objectmodel_get_netif_class();
	if (class && ni_string_eq(name, class->name)) {
		policy->config.type = NI_IFWORKER_TYPE_NETDEV;
		policy->config.class = class;
		return TRUE;
	}

#ifdef MODEM
	class = ni_objectmodel_get_modem_class();
	if (class && ni_string_eq(name, class->name)) {
		policy->config.type = NI_IFWORKER_TYPE_MODEM;
		policy->config.class = class;
		return TRUE;
	}
#endif

	ni_error("%s: policy class=\"%s\" is unknown/not supported",
			xml_node_location(node), name);
	return FALSE;
}

static ni_bool_t
ni_fsm_policy_owner_from_xml(ni_fsm_policy_t *policy, xml_node_t *node)
{
	const char *attr;

	if ((attr = ni_ifpolicy_get_owner(node))) {
		if (ni_parse_uint(attr, &policy->owner, 10) < 0) {
			ni_error("%s: cannot parse %s=\"%s\" attribute",
					xml_node_location(node),
					NI_NANNY_IFPOLICY_OWNER, attr);
			return FALSE;
		}
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_policy_weight_from_xml(ni_fsm_policy_t *policy, xml_node_t *node)
{
	const char *attr;

	if ((attr = ni_ifpolicy_get_weight(node))) {
		if (ni_parse_uint(attr, &policy->weight, 10) < 0) {
			ni_error("%s: cannot parse %s=\"%s\" attribute",
					xml_node_location(node),
					NI_NANNY_IFPOLICY_WEIGHT, attr);
			return FALSE;
		}
	}
	return TRUE;
}

static ni_bool_t
ni_fsm_policy_uuid_from_xml(ni_fsm_policy_t *policy, xml_node_t *node)
{
	ni_uuid_t uuid = NI_UUID_INIT;
	const char *old, *new;

	if (!ni_ifconfig_generate_uuid(node, &policy->uuid) ||
	    !(new = ni_uuid_print(&policy->uuid))) {
		ni_warn("%s: unable to generate a policy checksum %s",
				xml_node_location(node),
				NI_NANNY_IFPOLICY_UUID);

		ni_uuid_init(&policy->uuid);
		return FALSE;
	}

	old = ni_ifpolicy_get_uuid(node);
	if (ni_uuid_parse(&uuid, old) < 0 || ni_uuid_is_null(&uuid)) {
		/* missed or not parsable checksum uuid   */
		ni_warn("%s: adjusting invalid policy checksum %s=\"%s\" to \"%s\"",
				xml_node_location(node),
				NI_NANNY_IFPOLICY_UUID, old, new);

		return ni_ifpolicy_set_uuid(node, &policy->uuid);
	}

	if (!ni_uuid_equal(&policy->uuid, &uuid)) {
		/* can happen if policy has been migrated */
		ni_info("%s: adjusting incorrect policy checksum %s=\"%s\" to \"%s\"",
				xml_node_location(node),
				NI_NANNY_IFPOLICY_UUID, old, new);

		return ni_ifpolicy_set_uuid(node, &policy->uuid);
	}

	return TRUE;
}

static ni_bool_t
ni_fsm_policy_from_xml(ni_fsm_policy_t *policy, xml_node_t *node)
{
	static unsigned int policy_seq = 1;
	xml_node_t *item;

	if (!policy || !node)
		return FALSE;

	if (!ni_fsm_policy_type_from_xml(policy, node))
		return FALSE;

	if (!ni_fsm_policy_name_from_xml(policy, node))
		return FALSE;

	if (!ni_fsm_policy_class_from_xml(policy, node))
		return FALSE;

	if (!ni_fsm_policy_owner_from_xml(policy, node))
		return FALSE;

	if (!ni_fsm_policy_weight_from_xml(policy, node))
		return FALSE;

	if (!ni_fsm_policy_uuid_from_xml(policy, node))
		return FALSE;

	for (item = node->children; item; item = item->next) {
		ni_fsm_policy_action_t *action = NULL;

		if (ni_string_eq(item->name, NI_NANNY_IFPOLICY_MATCH)) {
			if (policy->type == NI_FSM_POLICY_TYPE_TEMPLATE) {
				ni_error("%s: <%s> elements not permitted in %s",
						xml_node_location(item),
						item->name, node->name);
				return FALSE;
			}

			if (policy->match) {
				ni_error("%s: %s specifies multiple <%s> elements",
						xml_node_location(item),
						node->name, item->name);
				return FALSE;
			}

			if (!(policy->match = ni_fsm_policy_conditions_from_xml(item))) {
				ni_error("%s: trouble parsing <%s> conditions in %s",
						xml_node_location(item),
						item->name, node->name);
				return FALSE;
			}
			continue;
		} else
		if (ni_string_eq(item->name, NI_NANNY_IFPOLICY_MERGE)) {
			action = ni_fsm_policy_action_new(NI_FSM_POLICY_ACTION_MERGE, item, policy);
		} else
		if (ni_string_eq(item->name, NI_NANNY_IFPOLICY_REPLACE)) {
			action = ni_fsm_policy_action_new(NI_FSM_POLICY_ACTION_REPLACE, item, policy);
		} else
		if (ni_string_eq(item->name, NI_NANNY_IFPOLICY_CREATE)) {
			if (policy->type != NI_FSM_POLICY_TYPE_TEMPLATE) {
				ni_error("%s: <%s> elements not permitted in %s",
						xml_node_location(item),
						item->name, node->name);
				return FALSE;
			}

			if (policy->create_action) {
				ni_error("%s: %s specifies more than one <%s> action",
						xml_node_location(item),
						node->name, item->name);
				return FALSE;
			}

			policy->create_action = ni_fsm_policy_action_new(NI_FSM_POLICY_ACTION_CREATE, item, NULL);
		} else {
			ni_error("%s: unknown <%s> element in %s",
					xml_node_location(item),
					item->name, node->name);
			return FALSE;
		}

		if (!action && !policy->create_action) {
			ni_error("%s: unable to parse <%s> action in %s",
					xml_node_location(item),
					item->name, node->name);
			return FALSE;
		}
	}

	/* if we have a config policy, make sure it provides a <match> expression */
	if (policy->type == NI_FSM_POLICY_TYPE_CONFIG && !policy->match) {
		ni_error("%s: %s does not specify any <%s> expression",
				xml_node_location(node), node->name,
				NI_NANNY_IFPOLICY_MATCH);
		return FALSE;
	}

	/* if we have a template, make sure it has exactly one <create> element */
	if (policy->type == NI_FSM_POLICY_TYPE_TEMPLATE && !policy->create_action) {
		ni_error("%s: %s does not specify a <%s> action",
				xml_node_location(node), node->name,
				NI_NANNY_IFPOLICY_CREATE);
		return FALSE;
	}

	/*
	 * Both policy types provide <merge>|<replace> action(s) constructing
	 * the effective configuration and is useless without any action.
	 */
	if (!policy->actions) {
		ni_error("%s: %s does not specify any <%s> or <%s> action",
			xml_node_location(node), node->name,
			NI_NANNY_IFPOLICY_MERGE, NI_NANNY_IFPOLICY_REPLACE);
		return FALSE;
	}

	xml_node_free(policy->node);
	policy->node = xml_node_ref(node);
	policy->seq = policy_seq++;
	return TRUE;
}

static ni_bool_t
ni_fsm_policy_init(ni_fsm_policy_t *policy, xml_node_t *node)
{
	if (!policy || !node || !node->children)
		return FALSE;

	memset(policy, 0, sizeof(*policy));

	policy->owner = -1U;
	if (!ni_fsm_policy_from_xml(policy, node)) {
		ni_fsm_policy_destroy(policy);
		return FALSE;
	}

	return TRUE;
}

static ni_define_refcounted_new(ni_fsm_policy, xml_node_t *);
extern ni_define_refcounted_ref(ni_fsm_policy);
extern ni_define_refcounted_free(ni_fsm_policy);
extern ni_define_refcounted_hold(ni_fsm_policy);
extern ni_define_refcounted_drop(ni_fsm_policy);
extern ni_define_refcounted_move(ni_fsm_policy);

ni_fsm_policy_t *
ni_fsm_create_policy(ni_fsm_t *fsm, xml_node_t *node)
{
	ni_fsm_policy_t *policy;

	if (!fsm || !(policy = ni_fsm_policy_new(node)))
		return NULL;

	ni_fsm_policy_list_insert(&fsm->policies, policy);
	return policy;
}

ni_fsm_policy_t *
ni_fsm_replace_policy(ni_fsm_policy_t *policy, xml_node_t *node)
{
	ni_fsm_policy_t *update;

	if (!policy || !policy->pprev)
		return NULL;

	if (!(update = ni_fsm_policy_new(node)))
		return NULL;

	if (!ni_string_eq(policy->name, update->name)) {
		ni_error("Cannot replace policy '%s' with policy '%s'",
				policy->name, update->name);
		ni_fsm_policy_free(update);
		return NULL;
	}

	ni_fsm_policy_list_insert(&policy->next, update);
	ni_fsm_policy_list_unlink(policy);
	ni_fsm_policy_free(policy);
	return update;
}

ni_bool_t
ni_fsm_delete_policy(ni_fsm_t *fsm, ni_fsm_policy_t *policy)
{
	ni_fsm_policy_t *cur;

	if (!fsm || !policy)
		return FALSE;

	for (cur = fsm->policies; cur; cur = cur->next) {
		if (cur == policy) {
			/*
			 * force remove if in fsm list,
			 * even it is not the last ref.
			 */
			ni_fsm_policy_list_unlink(cur);
			ni_fsm_policy_free(cur);
			return TRUE;
		}
	}

	return FALSE;
}

ni_bool_t
ni_fsm_policies_changed_since(const ni_fsm_t *fsm, unsigned int *tstamp)
{
	ni_fsm_policy_t *policy;
	ni_bool_t rv = FALSE;

	for (policy = fsm->policies; policy; policy = policy->next) {
		if (policy->seq > *tstamp) {
			*tstamp = policy->seq;
			rv = TRUE;
		}
	}
	return rv;
}

ni_fsm_policy_t *
ni_fsm_get_policy_by_ref(const ni_fsm_t *fsm, const ni_fsm_policy_t *ref)
{
	ni_fsm_policy_t *policy;

	if (!fsm || !ref)
		return NULL;

	for (policy = fsm->policies; policy; policy = policy->next) {
		if (policy == ref)
			return policy;
	}
	return NULL;
}

ni_fsm_policy_t *
ni_fsm_get_policy_by_name(const ni_fsm_t *fsm, const char *name)
{
	ni_fsm_policy_t *policy;

	if (!fsm || ni_string_empty(name))
		return NULL;

	for (policy = fsm->policies; policy; policy = policy->next) {
		if (ni_string_eq(policy->name, name))
			return policy;
	}
	return NULL;
}

/*
 * Get the policy's name (if set)
 */
const char *
ni_fsm_policy_name(const ni_fsm_policy_t *policy)
{
	return policy ? policy->name : NULL;
}

/*
 * Get the policy xml node
 */
const xml_node_t *
ni_fsm_policy_node(const ni_fsm_policy_t *policy)
{
	return policy ? policy->node : NULL;
}

/*
 * Get the policy's location (if set)
 */
const xml_location_t *
ni_fsm_policy_location(const ni_fsm_policy_t *policy)
{
	if (!policy || !policy->node)
		return NULL;

	return policy->node->location;
}

/*
 *  Get the policy uuid calculated in policy from xml
 */
const ni_uuid_t *
ni_fsm_policy_uuid(const ni_fsm_policy_t *policy)
{
	return policy ? &policy->uuid : NULL;
}

/*
 * Get the policy owner uid parsed in policy from xml
 */
uid_t
ni_fsm_policy_owner(const ni_fsm_policy_t *policy)
{
	return policy ? policy->owner : -1U;
}

/*
 * Retrieve policy origin directly from node
 */
const char *
ni_fsm_policy_origin(const ni_fsm_policy_t *policy)
{
	const char *origin;

	if (!policy || !policy->node)
		return NULL;

	origin = ni_ifpolicy_get_origin(policy->node);
	return ni_string_empty(origin) ? "nanny" : origin;
}

/*
 * Get the policy weight parsed in policy from xml
 */
unsigned int
ni_fsm_policy_weight(const ni_fsm_policy_t *policy)
{
	return policy ? policy->weight : -1U;
}

ni_ifworker_type_t
ni_fsm_policy_config_type(const ni_fsm_policy_t *policy)
{
	return policy ? policy->config.type : NI_IFWORKER_TYPE_NONE;
}

const ni_dbus_class_t *
ni_fsm_policy_config_class(const ni_fsm_policy_t *policy)
{
	return policy ? policy->config.class : NULL;
}

/*
 * Check whether policy applies to this ifworker
 */
static ni_bool_t
ni_fsm_policy_applicable(const ni_fsm_t *fsm, ni_fsm_policy_t *policy, ni_ifworker_t *w)
{
	xml_node_t *node;
	char *pname;

	if (!policy || !w)
		return FALSE;

	/* 1st match check -ifworker to policy name comparison */
	pname = ni_ifpolicy_name_from_ifname(w->name);
	if (!ni_string_eq(policy->name, pname)) {
		ni_string_free(&pname);
		return FALSE;
	}
	ni_string_free(&pname);

	/* 2nd match check - ifworker  to config name comparison */
	if (!xml_node_is_empty(w->config.node) &&
	    (node = xml_node_get_child(w->config.node, "name"))) {
		const char *namespace = xml_node_get_attr(node, "namespace");
		if (!namespace && !ni_string_eq(node->cdata, w->name)) {
			ni_error("%s: config name does not match policy name",
					policy->name);
			return FALSE;
		}
	}

	/* 3rd match check - physical worker must be ready  */
	if (ni_ifworker_is_device_created(w)) {
		if (!ni_netdev_device_is_ready(w->device))
			return FALSE;
	}
	else if (!ni_ifworker_is_factory_device(w))
		return FALSE;

	/* 4th match check - <match> condition must be fulfilled */
	if (!ni_ifcondition_check(policy->match, fsm, w)) {
		ni_debug_nanny("%s: policy <match> condition is not met for worker %s",
			policy->name, w->name);
		return FALSE;
	}

	ni_debug_nanny("%s: found applicable policy: %s", w->name, policy->name);
	return TRUE;
}

/*
 * Compare two applicable policies to sort them by owner and weight.
 * The sort order of equal policies is undefined, so when the owner
 * and weight are equal, compare policy name to keep it predictable.
 *
 * Returns < 0 if a's weight is smaller than that of b, etc.
 */
static int
ni_fsm_policy_compare_applicable(const ni_fsm_policy_t *a, const ni_fsm_policy_t *b)
{
#define num_cmp(a, b)	(a < b ? -1 : a > b ? 1 : 0)
	int ret;

	if (!a || !b || a == b)
		return num_cmp(a, b);

	if ((ret = num_cmp(a->owner, b->owner)))
		return ret;

	if ((ret = num_cmp(a->weight, b->weight)))
		return ret;

	return ni_string_cmp(a->name, b->name);
#undef	num_cmp
}

/*
 * Obtain the list of applicable policies
 */
unsigned int
ni_fsm_get_applicable_policies(const ni_fsm_t *fsm, ni_ifworker_t *w,
			ni_fsm_policy_array_t *result, unsigned int max)
{
	ni_fsm_policy_t *policy;
	unsigned int count;

	if (!fsm || !w || !result || !max) {
		ni_error("unable to get applicable policy: invalid arguments");
		return 0;
	}

	count = result->count;
	for (policy = fsm->policies; policy; policy = policy->next) {
		if (result->count >= max)
			break;

		if (policy->type == NI_FSM_POLICY_TYPE_CONFIG) {

			if (policy->config.type != w->type)
				continue;

			if (ni_fsm_policy_applicable(fsm, policy, w))
				ni_fsm_policy_array_append_ref(result, policy);
		}
	}

	if (result->count > 1)
		ni_fsm_policy_array_qsort(result, ni_fsm_policy_compare_applicable);

	return result->count - count;
}

ni_bool_t
ni_fsm_exists_applicable_policy(const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_fsm_policy_t *policy;

	if (!fsm || !w)
		return FALSE;

	for (policy = fsm->policies; policy; policy = policy->next) {
		if (policy->type == NI_FSM_POLICY_TYPE_CONFIG) {

			if (policy->config.type != w->type)
				continue;

			if (ni_fsm_policy_applicable(fsm, policy, w))
				return TRUE;
		}
	}

	return FALSE;
}

/*
 * Transform an interface or modem XML document according to a list of policies.
 * Usually, you would obtain that list via ni_fsm_policy_get_applicable_policies
 * above.
 *
 * The way this works is
 *   a) dbus methods expect their input from the XML interface definition,
 *	explicitly specifying that it takes its input from element <foo>
 *
 *   b) the document may or may not contain a <foo> element, but one or
 *	more policies may.
 *
 *   c)	Policies may specify <merge> actions, which means we merge the
 *	<foo> element from the policy with the <foo> element from the
 *	interface definition. Such a policy might look like this:
 *
 *	<policy>
 *	  ... conditions ...
 *	  <merge>
 *	    <foo> <bar/> <baz/> </foo>
 *	  </merge>
 *	</policy>
 *
 *	Note, in the above example we replace the entire <foo> element
 *	of the original document with the <foo> element specified
 *	in the action.
 *
 *	Alternatively, if you want to overwrite specific children of
 *	the <foo> node only, you could specify an alternative merge
 *	action:
 *
 *	  <merge path="/foo">
 *	    <bar/> <baz/>
 *	  </merge>
 *
 *	This would create the foo node (if it does not exist), and
 *	add elements <bar> and <baz> to it. If the document contains
 *	a <foo> node already, the merge rule will only replace <bar>
 *	and <baz>, but leave all other children of <foo> unchanged.
 *
 *   d) Policies may also specify <replace> actions, which work
 *	pretty similar to <merge> except that they replace all children
 *	with what is specified in the action.
 *
 *   e)	Policies are applied in order of increasing weight, ie any
 *	policy with a greater "weight" attribute potentially overwrites
 *	changes made by a policy with lower weight.
 */
ni_bool_t
ni_fsm_transform_policies_to_config(xml_node_t *config, ni_fsm_policy_t * const *policies, unsigned int count)
{
	ni_bool_t applied = FALSE;
	unsigned int i;

	if (!config || !policies || !count)
		return applied;

	/*
	 * Apply policies in order of increasing weight,
	 * see e) in the transform description above.
	 */
	for (i = 0; !config->final && i < count; ++i) {
		const ni_fsm_policy_t *policy = policies[i];
		ni_fsm_policy_action_t *action;

		if (!policy)
			continue;

		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_WICKED_XML,
				"transforming policy '%s' into config",
				policy->name);

		for (action = policy->actions; action; action = action->next) {
			switch (action->type) {
			case NI_FSM_POLICY_ACTION_MERGE:
				if (ni_fsm_policy_action_xml_merge(action, config)) {
					applied = TRUE;
					ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_WICKED_XML,
							"policy '%s' merge action applied",
							policy->name);
				} else {
					ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_WICKED_XML,
							"policy '%s' merge action failed",
							policy->name);
				}
				break;

			case NI_FSM_POLICY_ACTION_REPLACE:
				if (ni_fsm_policy_action_xml_replace(action, config)) {
					applied = TRUE;
					ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_WICKED_XML,
							"policy '%s' replace action applied",
							policy->name);
				} else {
					ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_WICKED_XML,
							"policy '%s' replace action failed",
							policy->name);
				}
				break;

			default:
				continue;
			}

			if (config->final || !(action->next || i + 1 < count)) {
				ni_debug_config_xml(config, NI_LOG_DEBUG3,
						"resulting config (final):");
				break;
			}

			ni_debug_config_xml(config, NI_LOG_DEBUG3,
					"resulting config (transient):");
		}
	}

	return applied;
}

/*
 * Policy actions
 */
ni_fsm_policy_action_t *
ni_fsm_policy_action_new(ni_fsm_policy_action_type_t type, xml_node_t *node, ni_fsm_policy_t *policy)
{
	ni_fsm_policy_action_t **list = NULL;
	ni_fsm_policy_action_t *action;
	const char *attr;

	if (policy) {
		for (list = &policy->actions; (action = *list) != NULL; list = &action->next)
			;
	}

	action = xcalloc(1, sizeof(*action));
	action->type = type;
	action->data = node;

	if (list)
		*list = action;

	if (type == NI_FSM_POLICY_ACTION_MERGE || type == NI_FSM_POLICY_ACTION_REPLACE) {
		if ((attr = xml_node_get_attr(node, "path")) != NULL)
			ni_string_dup(&action->xpath, attr);
		if ((attr = xml_node_get_attr(node, "final")) != NULL) {
			if (!strcasecmp(attr, "true") || !strcmp(attr, "1"))
				action->final = TRUE;
		}
	} else if (type == NI_FSM_POLICY_ACTION_CREATE) {
		ni_fsm_template_input_t **input_tail;
		xml_node_t *child;

		if ((attr = xml_node_get_attr(node, "class")) == NULL) {
			ni_error("%s: <%s> element lacks class attribute", xml_node_location(node), node->name);
			return NULL;
		}
		action->create.class = ni_objectmodel_get_class(attr);
		if (action->create.class == NULL) {
			ni_error("%s: <%s> specifies unknown class \"%s\"", xml_node_location(node), node->name, attr);
			return NULL;
		}

		action->create.instantiate_multi = FALSE;
		if ((attr = xml_node_get_attr(node, "instantiate")) != NULL) {
			if (ni_string_eq(attr, "multi"))
				action->create.instantiate_multi = TRUE;
			else if (!ni_string_eq(attr, "once")) {
				ni_error("%s: <%s> specifies bad instantiate=\"%s\" attribute",
						xml_node_location(node), node->name, attr);
				return NULL;
			}
		}

		input_tail = &action->create.inputs;
		for (child = node->children; child; child = child->next) {
			if (ni_string_eq(child->name, "input-device")) {
				ni_fsm_template_input_t *input;
				xml_node_t *matchnode;

				if (!(attr = xml_node_get_attr(child, "id"))) {
					ni_error("%s: <%s> element lacks id attribute", xml_node_location(child), child->name);
					return NULL;
				}

				/* FIXME: check for duplicate IDs */

				input = ni_fsm_template_input_new(attr, &input_tail);

				if ((attr = xml_node_get_attr(child, "shared")) != NULL) {
					if (!strcasecmp(attr, "true") || !strcmp(attr, "1"))
						input->shared = TRUE;
				}

				if (!(matchnode = xml_node_get_child(child, "match"))) {
					ni_error("%s: <%s> element lacks <match> child", xml_node_location(child), child->name);
					return NULL;
				}
				if (!(input->match = ni_fsm_policy_conditions_from_xml(matchnode))) {
					ni_error("%s: trouble parsing policy conditions", xml_node_location(matchnode));
					return NULL;
				}
			} else {
				ni_error("%s: unexpected element <%s>", xml_node_location(child), child->name);
				return NULL;
			}
		}
	}

	return action;
}

void
ni_fsm_policy_action_free(ni_fsm_policy_action_t *action)
{
	if (action->xpath)
		ni_string_free(&action->xpath);

	if (action->type == NI_FSM_POLICY_ACTION_CREATE) {
		ni_fsm_template_input_t *input;

		while ((input = action->create.inputs) != NULL) {
			action->create.inputs = input->next;
			ni_fsm_template_input_free(input);
		}
	}
	free(action);
}

ni_fsm_template_input_t *
ni_fsm_template_input_new(const char *id, ni_fsm_template_input_t ***tailp)
{
	ni_fsm_template_input_t **tail;
	ni_fsm_template_input_t *result;

	result = xcalloc(1, sizeof(*result));
	ni_string_dup(&result->id, id);

	if (tailp && (tail = *tailp)) {
		*tail = result;
		*tailp = &result->next;
	}

	return result;
}

void
ni_fsm_template_input_free(ni_fsm_template_input_t *input)
{
	ni_string_free(&input->id);
	if (input->match) {
		ni_ifcondition_free(input->match);
		input->match = NULL;
	}
	free(input);
}

/*
 * Look up XML elements based on the fake xpath.
 * If the named child does not exist, we create a new child of this name.
 * If the named child exists but is marked as "final", we refuse to change it
 * any further.
 */
static void
ni_fsm_policy_action_xml_lookup_next(xml_node_t *node, const char *name, xml_node_array_t *res)
{
	xml_node_t *child;
	unsigned int found = 0;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, name)) {
			if (!child->final)
				xml_node_array_append_ref(res, child);
			found++;
		}
	}

	if (!found) {
		child = xml_node_new(name, NULL);
		if (xml_node_array_append_ref(res, child))
			xml_node_add_child(node, child);
		else
			xml_node_free(child);
	}
}

static xml_node_array_t *
ni_fsm_policy_action_xml_lookup(xml_node_t *node, const char *path)
{
	xml_node_array_t *cur;
	char *copy, *name;

	if (node->final) {
		ni_error("%s: called with XML element that's marked final", __func__);
		return NULL;
	}

	if (!(cur = xml_node_array_new()))
		return NULL;

	if (!xml_node_array_append_ref(cur, node)) {
		xml_node_array_free(cur);
		return NULL;
	}

	copy = strdup(path);
	for (name = strtok(copy, "/"); name && cur->count; name = strtok(NULL, "/")) {
		xml_node_array_t *next;
		unsigned int i;

		if (!(next = xml_node_array_new())) {
			xml_node_array_free(cur);
			free(copy);
			return NULL;
		}

		for (i = 0; i < cur->count; ++i) {
			xml_node_t *np = cur->data[i];

			ni_fsm_policy_action_xml_lookup_next(np, name, next);
		}

		xml_node_array_free(cur);
		cur = next;
	}

	free(copy);
	return cur;
}

/*
 * ifpolicy merge action
 *   <merge path="/foo">
 *    <bar/> <baz/>
 *   </merge>
 * This will look up the <foo> element inside the given document, and merge
 * <bar> and <baz> into it, without replacing existing <bar> and <baz> elements.
 *
 * If the path attribute is not given, this transformation applies to the
 * top-level xml node (which is usually an <interface> or <modem> element).
 */
xml_node_t *
ni_fsm_policy_action_xml_merge(const ni_fsm_policy_action_t *action, xml_node_t *node)
{
	xml_node_array_t *nodes;
	unsigned int i;

	if (node->final)
		return node;

	if (action->xpath == NULL) {
		xml_node_merge(node, action->data);
		node->final = action->final;
		return node;
	}

	nodes = ni_fsm_policy_action_xml_lookup(node, action->xpath);
	if (nodes == NULL)
		return NULL;

	for (i = 0; i < nodes->count; ++i) {
		xml_node_t *np = nodes->data[i];

		xml_node_merge(np, action->data);
		np->final = action->final;
	}

	xml_node_array_free(nodes);
	return node;
}

/*
 * See d) in the transform description.
 *
 * The policy replace action:
 *   <replace path="/foo">
 *    <bar/> <baz/>
 *   </replace>
 * will look up the <foo> element inside the given document, remove all of its
 * children and replace them with <bar> and <baz>.
 *
 * If the path attribute is not given, this transformation replaces the children
 * in the top-level xml node (which is usually an <interface> or <modem> config),
 * except when a child to replace is marked final.
 */
static inline ni_bool_t
ni_fsm_policy_action_xml_replace_children(xml_node_t *node, xml_node_t *from)
{
	xml_node_t *nchild, *next;
	xml_node_t *fchild;

	if (!node || !from)
		return FALSE;

	for (nchild = node->children; nchild; nchild = next) {
		next = nchild->next;

		if (nchild->final)
			continue;

		xml_node_delete_child_node(node, nchild);
	}

	for (fchild = from->children; fchild; fchild = fchild->next) {
		if (xml_node_get_child(node, fchild->name))
			continue;

		xml_node_clone(fchild, node);
	}

	return TRUE;
}

xml_node_t *
ni_fsm_policy_action_xml_replace(const ni_fsm_policy_action_t *action, xml_node_t *node)
{
	xml_node_array_t *nodes;
	unsigned int i;

	if (node->final)
		return node;

	if (action->xpath == NULL) {
		if (ni_fsm_policy_action_xml_replace_children(node, action->data))
			node->final = action->final;

		return node;
	}

	nodes = ni_fsm_policy_action_xml_lookup(node, action->xpath);
	if (nodes == NULL)
		return NULL;

	for (i = 0; i < nodes->count; ++i) {
		xml_node_t *np = nodes->data[i];

		if (ni_fsm_policy_action_xml_replace_children(np, action->data))
			np->final = action->final;
	}

	xml_node_array_free(nodes);
	return node;
}

/*
 * Template handling
 */
ni_bool_t
ni_fsm_policy_is_template(const ni_fsm_policy_t *policy)
{
	return policy->type == NI_FSM_POLICY_TYPE_TEMPLATE;
}

ni_bool_t
ni_fsm_template_multi_instance(const ni_fsm_policy_t *policy)
{
	return policy->create_action && policy->create_action->create.instantiate_multi;
}

xml_node_t *
ni_fsm_template_instantiate(const ni_fsm_t *fsm, ni_fsm_policy_t *policy, const ni_ifworker_array_t *devices)
{
	ni_fsm_template_input_t *input;
	ni_fsm_policy_action_t *action;
	unsigned int i, num_needed;
	xml_node_t *config;

	if (policy->type != NI_FSM_POLICY_TYPE_TEMPLATE
	 || (action = policy->create_action) == NULL)
		return NULL;

	num_needed = 0;
	for (input = action->create.inputs; input; input = input->next) {
		input->device = NULL;
		num_needed++;
	}

	for (i = 0; i < devices->count && num_needed; ++i) {
		ni_ifworker_t *w = devices->data[i];
		unsigned int nshared = 0;

		for (input = action->create.inputs; input; input = input->next) {
			if (input->device != NULL)
				continue;

			if (!ni_ifcondition_check(input->match, fsm, w))
				continue;

			if (input->shared) {
				input->device = w;
				num_needed--;
				nshared++;
			} else if (nshared == 0) {
				input->device = w;
				num_needed--;
				break;
			}
		}
	}

	if (num_needed)
		return NULL;

	config = ni_fsm_template_build_document(policy, action);
	if (config == NULL)
		return NULL;

	if (!ni_fsm_template_bind_devices(policy, action, config)) {
		xml_node_free(config);
		return NULL;
	}

	return config;
}

xml_node_t *
ni_fsm_template_build_document(ni_fsm_policy_t *policy, ni_fsm_policy_action_t *action)
{
	xml_node_t *config;

	if (ni_dbus_class_is_subclass(action->create.class, &ni_objectmodel_netif_class)) {
		config = xml_node_new("interface", NULL);
	} else {
		ni_error("%s: class %s not supported", __func__, action->create.class->name);
		return NULL;
	}

	xml_node_add_attr(config, "class", action->create.class->name);

	if (action->create.instantiate_multi) {
		char new_name[128];

		snprintf(new_name, sizeof(new_name), "%s%u", policy->name, action->create.serial++);
		xml_node_new_element("name", config, new_name);
	} else {
		xml_node_new_element("name", config, policy->name);
	}

	/* Now transform the document */
	for (action = policy->actions; action; action = action->next) {
		switch (action->type) {
		case NI_FSM_POLICY_ACTION_MERGE:
			config = ni_fsm_policy_action_xml_merge(action, config);
			break;

		case NI_FSM_POLICY_ACTION_REPLACE:
			config = ni_fsm_policy_action_xml_replace(action, config);
			break;

		default:
			continue;
		}

		if (config == NULL) {
			ni_error("%s: failed to build document", policy->name);
			return NULL;
		}
	}

	return config;
}

ni_bool_t
ni_fsm_template_bind_devices(ni_fsm_policy_t *policy, ni_fsm_policy_action_t *action, xml_node_t *node)
{
	xml_node_t *child;

again:
	for (child = node->children; child; child = child->next) {
		ni_fsm_template_input_t *input;
		const char *id;

		if (!ni_string_eq(child->name, "template:use"))
			continue;

		if (!(id = xml_node_get_attr(child, "id"))) {
			ni_error("%s: <%s> element lacking id attribute",
					xml_node_location(child), child->name);
			return FALSE;
		}

		for (input = action->create.inputs; input; input = input->next) {
			if (ni_string_eq(input->id, id))
				break;
		}

		if (input == NULL) {
			ni_error("%s: <%s> element specifies unknown id=\"%s\"",
					xml_node_location(child), child->name,
					id);
			return FALSE;
		}

		xml_node_new_element("path", node, input->device->object_path);
		xml_node_delete_child_node(node, child);
		goto again;
	}

	return TRUE;
}

/*
 * Policy matching functions
 */
static ni_ifcondition_t *
ni_ifcondition_new(ni_ifcondition_check_fn_t *check_fn)
{
	ni_ifcondition_t *cond;

	cond = xcalloc(1, sizeof(*cond));
	cond->check = check_fn;

	return cond;
}

static void
ni_ifcondition_free_args_string(ni_ifcondition_t *cond)
{
	ni_string_free(&cond->args.string);
}
static void
ni_ifcondition_free_args_reference(ni_ifcondition_t *cond)
{
	ni_ifcondition_free(cond->args.ref);
}

static ni_ifcondition_t *
ni_ifcondition_new_cdata(ni_ifcondition_check_fn_t *check_fn, const xml_node_t *node)
{
	ni_ifcondition_t *cond;

	if (node->cdata == NULL) {
		ni_error("%s: empty policy condition", xml_node_location(node));
		return NULL;
	}

	cond = ni_ifcondition_new(check_fn);
	cond->free = ni_ifcondition_free_args_string;
	ni_string_dup(&cond->args.string, node->cdata);
	return cond;
}

static ni_ifcondition_t *
ni_ifcondition_new_uint(ni_ifcondition_check_fn_t *check_fn, unsigned int value)
{
	ni_ifcondition_t *cond;

	cond = ni_ifcondition_new(check_fn);
	cond->args.uint = value;
	return cond;
}

static void
ni_ifcondition_free_args_terms(ni_ifcondition_t *cond)
{
	ni_ifcondition_free(cond->args.terms.left);
	ni_ifcondition_free(cond->args.terms.right);
}

static ni_ifcondition_t *
ni_ifcondition_new_terms(ni_ifcondition_check_fn_t *check_fn,
			ni_ifcondition_t *left,
			ni_ifcondition_t *right)
{
	ni_ifcondition_t *cond;

	cond = ni_ifcondition_new(check_fn);
	cond->free = ni_ifcondition_free_args_terms;
	cond->args.terms.left = left;
	cond->args.terms.right = right;
	return cond;
}

static void
ni_ifcondition_free(ni_ifcondition_t *cond)
{
	if (cond && cond->free)
		cond->free(cond);
	free(cond);
}

static ni_bool_t
ni_ifcondition_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_assert(cond->check);

	return cond->check(cond, fsm, w);
}


static ni_ifcondition_t *
ni_ifcondition_term2(xml_node_t *node, ni_ifcondition_check_fn_t *check_fn)
{
	ni_ifcondition_t *result = NULL;
	xml_node_t *child;

	if (node->children == NULL) {
		ni_error("%s: empty <%s> condition", xml_node_location(node), node->name);
		return NULL;
	}

	for (child = node->children; child; child = child->next) {
		ni_ifcondition_t *cond;

		if (!(cond = ni_ifcondition_from_xml(child))) {
			if (result)
				ni_ifcondition_free(result);
			return NULL;
		}

		if (result == NULL) {
			result = cond;
		} else {
			result = ni_ifcondition_new_terms(check_fn, result, cond);
		}
	}

	return result;
}

/*
 * <and>
 *  <term1>
 *  <term2>
 *  ..
 * </and>
 */
static ni_bool_t
ni_fsm_policy_match_and_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_bool_t rv;

	rv = ni_ifcondition_check(cond->args.terms.left, fsm, w)
	    && ni_ifcondition_check(cond->args.terms.right, fsm, w);

	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
		ni_trace("%s: %s condition is %s",
			w->name, __func__, ni_format_boolean(rv));
	}
	return rv;

}

static ni_bool_t
ni_fsm_policy_match_and_children_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	unsigned int i;
	ni_bool_t rv = FALSE;

	for (i = 0; i < fsm->workers.count; i++) {
		ni_ifworker_t *child = fsm->workers.data[i];

		if (w->lowerdev != child && child->masterdev != w)
			continue;

		if (ni_ifworker_is_device_created(child)) {
			if (!ni_netdev_device_is_ready(child->device))
				continue;
		}
		else if (!ni_ifworker_is_factory_device(child))
			continue;

		rv = ni_ifcondition_check(cond->args.terms.left, fsm, child);
		if (rv)
			break;
	}

	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
		ni_trace("%s: %s condition is %s",
			w->name, __func__, ni_format_boolean(rv));
	}
	return rv;
}

static ni_ifcondition_t *
ni_ifcondition_and_terms(ni_ifcondition_t *left, ni_ifcondition_t *right)
{
	return ni_ifcondition_new_terms(ni_fsm_policy_match_and_check, left, right);
}

static ni_ifcondition_t *
ni_ifcondition_and(xml_node_t *node)
{
	return ni_ifcondition_term2(node, ni_fsm_policy_match_and_check);
}

static ni_ifcondition_t *
ni_ifcondition_and_child(xml_node_t *node)
{
	ni_ifcondition_t *and;

	if (node->children == NULL) {
		ni_error("%s: <%s> condition must not be empty",
				xml_node_location(node), node->name);
		return NULL;
	}

	if (!(and = ni_ifcondition_and(node)))
		return NULL;

	return ni_ifcondition_new_terms(ni_fsm_policy_match_and_children_check, and, NULL);
}

/*
 * <or>
 *  <term1>
 *  <term2>
 *  ..
 * </or>
 */
static ni_bool_t
ni_fsm_policy_match_or_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_bool_t rv;

	rv = ni_ifcondition_check(cond->args.terms.left, fsm, w)
	    || ni_ifcondition_check(cond->args.terms.right, fsm, w);

	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
		ni_trace("%s: %s condition is %s",
			w->name, __func__, ni_format_boolean(rv));
	}
	return rv;
}

static ni_ifcondition_t *
ni_ifcondition_or(xml_node_t *node)
{
	return ni_ifcondition_term2(node, ni_fsm_policy_match_or_check);
}

/*
 * <not>
 *  <term>
 * </not>
 */
static ni_bool_t
ni_fsm_policy_match_not_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	return !ni_ifcondition_check(cond->args.terms.left, fsm, w);
}

static ni_ifcondition_t *
ni_ifcondition_not(xml_node_t *node)
{
	ni_ifcondition_t *child;

	if (node->children == NULL || node->children->next != NULL) {
		ni_error("%s: <%s> condition needs exactly one child term",
				xml_node_location(node), node->name);
		return NULL;
	}

	if (!(child = ni_ifcondition_from_xml(node->children)))
		return NULL;

	return ni_ifcondition_new_terms(ni_fsm_policy_match_not_check, child, NULL);
}

/*
 * <type>interface</type>
 * <type>modem</type>
 */
static ni_bool_t
ni_fsm_policy_match_type_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	return cond->args.type == w->type;
}

static ni_ifcondition_t *
ni_ifcondition_type(xml_node_t *node)
{
	ni_ifcondition_t *result;
	ni_ifworker_type_t type;

	type = ni_ifworker_type_from_string(node->cdata);
	if (type == NI_IFWORKER_TYPE_NONE) {
		ni_error("%s: unknown device type \"%s\"",
				xml_node_location(node), node->cdata);
		return NULL;
	}
	result = ni_ifcondition_new(ni_fsm_policy_match_type_check);
	result->args.type = type;
	return result;
}

/*
 * <class>...</class>
 * <link-type>...</link-type>
 */
static ni_bool_t
ni_fsm_policy_match_class_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_bool_t rv;

	rv = w->object &&
		ni_dbus_class_is_subclass(cond->args.class, w->object->class);

	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
		ni_trace("%s: %s condition is %s",
			w->name, __func__, ni_format_boolean(rv));
	}
	return rv;
}

static ni_bool_t
ni_fsm_policy_match_linktype_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_bool_t rv;
	ni_iftype_t iftype = (ni_iftype_t) cond->args.uint;

	rv = (iftype == w->iftype);

	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
		ni_trace("%s: %s condition is %s",
			w->name, __func__, ni_format_boolean(rv));
	}
	return rv;
}

static ni_ifcondition_t *
ni_fsm_policy_match_class_new(xml_node_t *node, const char *classname)
{
	const ni_dbus_class_t *class;
	ni_ifcondition_t *result;

	if ((class = ni_objectmodel_get_class(classname)) == NULL) {
		ni_error("%s: unknown object class \"%s\" in <%s> condition",
				xml_node_location(node), classname, node->name);
		return NULL;
	}

	result = ni_ifcondition_new(ni_fsm_policy_match_class_check);
	result->args.class = class;

	return result;
}

static ni_ifcondition_t *
ni_fsm_policy_match_linktype_new(xml_node_t *node, ni_iftype_t iftype)
{
	ni_ifcondition_t *result;

	result = ni_ifcondition_new(ni_fsm_policy_match_linktype_check);
	result->args.uint = iftype;

	return result;
}

static ni_ifcondition_t *
ni_ifcondition_class(xml_node_t *node)
{
	return ni_fsm_policy_match_class_new(node, node->cdata);
}

static ni_ifcondition_t *
ni_ifcondition_linktype(xml_node_t *node)
{
	ni_iftype_t iftype;

	iftype = ni_linktype_name_to_type(node->cdata);
	if (iftype >= __NI_IFTYPE_MAX) {
		ni_error("%s: unknown link type \"%s\"", xml_node_location(node), node->cdata);
		return NULL;
	}

	return ni_fsm_policy_match_linktype_new(node, iftype);
}

/*
 * <sharable>...</sharable>
 */
static ni_bool_t
ni_fsm_policy_match_sharable_check(const ni_ifcondition_t *cond,
		const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	if (ni_string_eq(cond->args.string, "shared"))
		return w->masterdev == NULL;

	if (ni_string_eq(cond->args.string, "exclusive")) {
		ni_ifworker_t *linked;
		unsigned int i;

		if (w->masterdev)
			return FALSE;

		for (i = 0; i < fsm->workers.count; ++i) {
			linked = fsm->workers.data[i];

			if (linked->lowerdev == w)
				return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

static ni_ifcondition_t *
ni_ifcondition_sharable(xml_node_t *node)
{
	if (!ni_string_eq(node->cdata, "shared")
	 && !ni_string_eq(node->cdata, "exclusive")) {
		ni_error("bad <%s> condition: must be either shared or exclusive (found \"%s\")",
				node->name, node->cdata);
		return NULL;
	}
	return ni_ifcondition_new_cdata(ni_fsm_policy_match_sharable_check, node);
}

/*
 * <device>...</device>
 * <device:name>...</device:name>
 * <device:alias>...</device:alias>
 * <device:ifindex>...</device:ifindex>
 */
static ni_bool_t
ni_fsm_policy_match_device_name_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_bool_t rv;

	rv = ni_ifworker_match_netdev_name(w, cond->args.string);

	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
		ni_trace("%s: %s condition is %s",
			w->name, __func__, ni_format_boolean(rv));
	}
	return rv;
}
static ni_bool_t
ni_fsm_policy_match_device_alias_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	return ni_ifworker_match_netdev_alias(w, cond->args.string);
}
static ni_bool_t
ni_fsm_policy_match_device_ifindex_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	unsigned int ifindex;

	if (ni_parse_uint(cond->args.string, &ifindex, 10) < 0 || !ifindex)
		return FALSE;
	return ni_ifworker_match_netdev_ifindex(w, ifindex);
}

static ni_ifcondition_t *
ni_ifcondition_device_element(xml_node_t *node, const char *name)
{
	if (ni_string_eq(name, "name")) {
		return ni_ifcondition_new_cdata(ni_fsm_policy_match_device_name_check, node);
	}
	if (ni_string_eq(name, "alias")) {
		return ni_ifcondition_new_cdata(ni_fsm_policy_match_device_alias_check, node);
	}
	if (ni_string_eq(name, "ifindex")) {
		return ni_ifcondition_new_cdata(ni_fsm_policy_match_device_ifindex_check, node);
	}
	ni_error("%s: unknown device condition <%s>", xml_node_location(node), name);
	return NULL;
}

static ni_ifcondition_t *
ni_ifcondition_device(xml_node_t *node)
{
	ni_ifcondition_t *result = NULL;

	if (!node->children && node->cdata)
		return ni_ifcondition_new_cdata(ni_fsm_policy_match_device_name_check, node);

	for (node = node->children; node; node = node->next) {
		ni_ifcondition_t *cond;

		cond = ni_ifcondition_device_element(node, node->name);
		if (cond == NULL) {
			if (result)
				ni_ifcondition_free(result);
			return NULL;
		}

		if (result == NULL)
			result = cond;
		else
			result = ni_ifcondition_and_terms(result, cond);
	}

	return result;
}

/*
 * <control-mode>xyz</control-mode>
 * Compare xyz to the contents of <control><mode> ...</mode></control>
 */
static ni_bool_t
ni_fsm_policy_match_control_mode_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	return ni_string_eq(w->control.mode, cond->args.string);
}

static ni_ifcondition_t *
ni_ifcondition_control_mode(xml_node_t *node)
{
	return ni_ifcondition_new_cdata(ni_fsm_policy_match_control_mode_check, node);
}

/*
 * <boot-stage>xyz</boot-stage>
 * Compare xyz to the contents of <control><boot-stage> ...</boot-stage></control>
 */
static ni_bool_t
ni_fsm_policy_match_boot_stage_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	return ni_string_eq(w->control.boot_stage, cond->args.string);
}

static ni_ifcondition_t *
ni_ifcondition_boot_stage(xml_node_t *node)
{
	return ni_ifcondition_new_cdata(ni_fsm_policy_match_boot_stage_check, node);
}

/*
 * <minimum-device-state>link-up</minimum-device-state>
 */
static ni_bool_t
ni_fsm_policy_min_device_state_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
#if 0
	ni_trace("%s: state is %u, need %u", w->name, w->fsm.state, cond->args.uint);
#endif
	return w->fsm.state >= cond->args.uint;
}

static ni_ifcondition_t *
ni_ifcondition_min_device_state(xml_node_t *node)
{
	ni_fsm_state_t state;

	if (!ni_ifworker_state_from_name(node->cdata, &state)) {
		ni_error("%s: invalid device state \"%s\"", xml_node_location(node), node->cdata);
		return NULL;
	}
	return ni_ifcondition_new_uint(ni_fsm_policy_min_device_state_check, state);
}

/*
 * <modem>...</modem>
 * <modem:foobar>...</modem:foobar>
 */
static ni_bool_t
ni_fsm_policy_match_modem_equipment_id_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_modem_t *modem;

	if (!(modem = ni_ifworker_get_modem(w)))
		return FALSE;
	return ni_string_eq(modem->identify.equipment, cond->args.string);
}

static ni_bool_t
ni_fsm_policy_match_modem_manufacturer_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_modem_t *modem;

	if (!(modem = ni_ifworker_get_modem(w)))
		return FALSE;
	return ni_string_eq(modem->identify.manufacturer, cond->args.string);
}

static ni_bool_t
ni_fsm_policy_match_modem_model_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_modem_t *modem;

	if (!(modem = ni_ifworker_get_modem(w)))
		return FALSE;
	return ni_string_eq(modem->identify.model, cond->args.string);
}

static ni_ifcondition_t *
ni_ifcondition_modem_element(xml_node_t *node, const char *name)
{
	if (ni_string_eq(name, "equipment-id"))
		return ni_ifcondition_new_cdata(ni_fsm_policy_match_modem_equipment_id_check, node);
	if (ni_string_eq(name, "manufacturer"))
		return ni_ifcondition_new_cdata(ni_fsm_policy_match_modem_manufacturer_check, node);
	if (ni_string_eq(name, "model"))
		return ni_ifcondition_new_cdata(ni_fsm_policy_match_modem_model_check, node);

	ni_error("%s: unknown modem condition <%s>", xml_node_location(node), name);
	return NULL;
}

static ni_ifcondition_t *
ni_ifcondition_modem(xml_node_t *node)
{
	ni_ifcondition_t *result = NULL;

	for (node = node->children; node; node = node->next) {
		ni_ifcondition_t *cond;

		cond = ni_ifcondition_modem_element(node, node->name);
		if (cond == NULL) {
			if (result)
				ni_ifcondition_free(result);
			return NULL;
		}

		if (result == NULL)
			result = cond;
		else
			result = ni_ifcondition_and_terms(result, cond);
	}

	return result;
}

static ni_bool_t
ni_fsm_policy_match_reference(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	unsigned int i;

	if (cond && cond->args.ref && fsm) {
		for (i = 0; i < fsm->workers.count; ++i) {
			w = fsm->workers.data[i];
			if (!w || w->type !=  cond->args.type)
				continue;

			if (ni_ifcondition_check(cond->args.ref, fsm, w))
				return TRUE;
		}
	}
	return FALSE;
}

static ni_ifcondition_t *
ni_ifcondition_new_reference(ni_ifcondition_t *ref, ni_ifworker_type_t type)
{
	ni_ifcondition_t *cond;

	if (ref) {
		cond = ni_ifcondition_new(ni_fsm_policy_match_reference);
		cond->free = ni_ifcondition_free_args_reference;
		cond->args.ref = ref;
		cond->args.type = type;
		return cond;
	}
	return NULL;
}

static inline ni_bool_t
ni_ifcondition_reference_bind_type(ni_ifworker_type_t *bound, ni_ifworker_type_t type)
{
	if (*bound == NI_IFWORKER_TYPE_NONE) {
		*bound = type;
		return TRUE;
	} else {
		return *bound == type;
	}
}

static ni_ifcondition_t *
ni_ifcondition_reference_type_element(ni_ifworker_type_t *type, xml_node_t *node, const char *name)
{
	if (ni_string_eq(name, "device")) {
		if (ni_ifcondition_reference_bind_type(type, NI_IFWORKER_TYPE_NETDEV))
			return ni_ifcondition_device(node);

		ni_error("%s: invalid <%s> reference element type mix", name, xml_node_location(node));
		return NULL;
	}
	if (ni_string_eq(name, "modem")) {
		if (ni_ifcondition_reference_bind_type(type, NI_IFWORKER_TYPE_MODEM))
			return ni_ifcondition_modem(node);

		ni_error("%s: invalid <%s> reference element type mix", name, xml_node_location(node));
		return NULL;
	}

	ni_error("%s: unknown reference condition <%s>", xml_node_location(node), name);
	return NULL;
}

/*
 * <reference:device>...</reference:device>
 * <reference:modem>...</reference:modem>
 *
 * Match a single property element of a referenced worker.
 */
static ni_ifcondition_t *
ni_ifcondition_reference_element(xml_node_t *node, const char *name)
{
	ni_ifworker_type_t type = NI_IFWORKER_TYPE_NONE;
	ni_ifcondition_t *cond;

	cond = ni_ifcondition_reference_type_element(&type, node, name);
	return ni_ifcondition_new_reference(cond, type);
}

/*
 * <reference>...and device property match...</reference>
 * <reference>...and modem property match...</reference>
 *
 * Each worker has a type (modem or device) and a reference is bond to
 * the type of the 1st worker matching it's properties using an and term.
 */
static ni_ifcondition_t *
ni_ifcondition_reference(xml_node_t *node)
{
	ni_ifcondition_t *result = NULL;
	ni_ifworker_type_t type = NI_IFWORKER_TYPE_NONE;

	for (node = node->children; node; node = node->next) {
		ni_ifcondition_t *cond;

		cond = ni_ifcondition_reference_type_element(&type, node, node->name);
		if (cond == NULL) {
			if (result)
				ni_ifcondition_free(result);
			return NULL;
		}

		if (result == NULL)
			result = cond;
		else
			result = ni_ifcondition_and_terms(result, cond);
	}

	return ni_ifcondition_new_reference(result, type);
}

/*
 * <wireless>...</wireless>
 * <wireless:foobar>...</wireless:foobar>
 */
static ni_bool_t
ni_fsm_policy_match_wireless_essid_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	ni_netdev_t *dev;
	ni_wireless_t *wireless;
	ni_wireless_ssid_t ssid;
	ni_wireless_bss_t *bss;
	ni_stringbuf_t sbuf = NI_STRINGBUF_INIT_DYNAMIC;

	if (!(dev = ni_ifworker_get_netdev(w)) || !(wireless = dev->wireless))
		return FALSE;

	if (!(bss = wireless->scan.bsss))
		return FALSE;

	if (!ni_wireless_ssid_parse(&ssid, cond->args.string))
		return FALSE;


	for (; bss; bss = bss->next) {
		if (!ni_wireless_ssid_eq(&ssid, &bss->ssid))
			continue;

		if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_IFCONFIG)) {
			ni_trace("%s - ssid `%s` MATCH - bssid:%s age:%u signal:%hd",
					__func__, ni_wireless_ssid_print(&ssid, &sbuf),
					ni_link_address_print(&bss->bssid),
					bss->age, bss->signal );
			ni_stringbuf_destroy(&sbuf);
		}
		return TRUE;
	}

	return FALSE;
}

static ni_ifcondition_t *
ni_ifcondition_wireless_element(xml_node_t *node, const char *name)
{
	if (ni_string_eq(name, "essid")) {
		ni_wireless_ssid_t essid;

		if (!ni_wireless_ssid_parse(&essid, node->cdata)) {
			ni_error("%s: cannot parse essid \"%s\"",
					xml_node_location(node), node->cdata);
			return NULL;
		}

		return ni_ifcondition_new_cdata(ni_fsm_policy_match_wireless_essid_check, node);
	}

	ni_error("%s: unknown wireless condition <%s>", xml_node_location(node), name);
	return NULL;
}

static ni_ifcondition_t *
ni_ifcondition_wireless(xml_node_t *node)
{
	ni_ifcondition_t *result = NULL;

	for (node = node->children; node; node = node->next) {
		ni_ifcondition_t *cond;

		cond = ni_ifcondition_wireless_element(node, node->name);
		if (cond == NULL) {
			if (result)
				ni_ifcondition_free(result);
			return NULL;
		}

		if (result == NULL)
			result = cond;
		else
			result = ni_ifcondition_and_terms(result, cond);
	}

	return result;
}

/*
 * <any>...</any>
 */
static ni_bool_t
ni_fsm_policy_match_any_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	return TRUE;
}

static ni_ifcondition_t *
ni_ifcondition_any(xml_node_t *node)
{
	return ni_ifcondition_new(ni_fsm_policy_match_any_check);
}

/*
 * <none>...</none>
 */
static ni_bool_t
ni_fsm_policy_match_none_check(const ni_ifcondition_t *cond, const ni_fsm_t *fsm, ni_ifworker_t *w)
{
	return FALSE;
}

static ni_ifcondition_t *
ni_ifcondition_none(xml_node_t *node)
{
	return ni_ifcondition_new(ni_fsm_policy_match_none_check);
}

/*
 * condition constructors
 */
ni_ifcondition_t *
ni_ifcondition_from_xml(xml_node_t *node)
{
	if (!strcmp(node->name, "and"))
		return ni_ifcondition_and(node);
	if (!strcmp(node->name, "or"))
		return ni_ifcondition_or(node);
	if (!strcmp(node->name, "not"))
		return ni_ifcondition_not(node);

	if (!strcmp(node->name, "any"))
		return ni_ifcondition_any(node);
	if (!strcmp(node->name, "none"))
		return ni_ifcondition_none(node);
	if (!strcmp(node->name, "type"))
		return ni_ifcondition_type(node);
	if (!strcmp(node->name, "class"))
		return ni_ifcondition_class(node);
	if (!strcmp(node->name, "sharable"))
		return ni_ifcondition_sharable(node);
	if (!strcmp(node->name, "link-type"))
		return ni_ifcondition_linktype(node);
	if (!strcmp(node->name, "control-mode"))
		return ni_ifcondition_control_mode(node);
	if (!strcmp(node->name, "boot-stage"))
		return ni_ifcondition_boot_stage(node);
	if (!strcmp(node->name, "minimum-device-state"))
		return ni_ifcondition_min_device_state(node);
	if (!strcmp(node->name, "device"))
		return ni_ifcondition_device(node);
	if (!strncmp(node->name, "device:", sizeof("device:")-1))
		return ni_ifcondition_device_element(node, node->name + sizeof("device:")-1);
	if (!strcmp(node->name, "reference"))
		return ni_ifcondition_reference(node);
	if (!strncmp(node->name, "reference:", sizeof("reference:")-1))
		return ni_ifcondition_reference_element(node, node->name + sizeof("reference:")-1);
	if (!strcmp(node->name, "child"))
		return ni_ifcondition_and_child(node);
	if (!strcmp(node->name, "modem"))
		return ni_ifcondition_modem(node);
	if (!strncmp(node->name, "modem:", sizeof("modem:")-1))
		return ni_ifcondition_modem_element(node, node->name + sizeof("modem:")-1);
	if (!strcmp(node->name, "wireless"))
		return ni_ifcondition_wireless(node);
	if (!strncmp(node->name, "wireless:", sizeof("wireless:")-1))
		return ni_ifcondition_wireless_element(node, node->name + sizeof("wireless:")-1);

	ni_error("%s: unsupported policy conditional <%s>", xml_node_location(node), node->name);
	return NULL;
}

/*
 * When the policy's <match> element contains several children, this
 * is treated as an <and> statement
 */
ni_ifcondition_t *
ni_fsm_policy_conditions_from_xml(xml_node_t *node)
{
	return ni_ifcondition_and(node);
}

extern ni_define_ptr_array_init(ni_fsm_policy);
extern ni_define_ptr_array_destroy(ni_fsm_policy);
static ni_define_ptr_array_realloc(ni_fsm_policy, NI_FSM_POLICY_ARRAY_CHUNK);
extern ni_define_ptr_array_append_ref(ni_fsm_policy);
extern ni_define_ptr_array_insert_ref(ni_fsm_policy);
extern ni_define_ptr_array_remove_at(ni_fsm_policy);
extern ni_define_ptr_array_delete_at(ni_fsm_policy);
extern ni_define_ptr_array_at(ni_fsm_policy);
extern ni_define_ptr_array_index(ni_fsm_policy);
static ni_define_ptr_array_qsort_cmp_fn(ni_fsm_policy);
extern ni_define_ptr_array_qsort(ni_fsm_policy);

