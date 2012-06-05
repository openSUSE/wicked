/*
 * Wicked policy handling.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>

#include "fsm.h"
#include "policy.h"

/*
 * The <match> expression
 */
typedef ni_bool_t	ni_ifcondition_check_fn_t(const ni_ifcondition_t *, ni_ifworker_t *);

struct ni_ifcondition {
	ni_ifcondition_check_fn_t *check;

	union {
		ni_ifworker_type_t	type;
		struct {
			xml_node_t *	node;
			ni_dbus_object_t *object;
		} device;
		struct {
			ni_ifcondition_t *left;
			ni_ifcondition_t *right;
		} terms;
		const ni_dbus_class_t *	class;
	} args;
};

static ni_ifcondition_t *	ni_ifpolicy_conditions_from_xml(xml_node_t *);
static ni_bool_t		ni_ifcondition_check(const ni_ifcondition_t *, ni_ifworker_t *);
static ni_ifcondition_t *	ni_ifcondition_from_xml(xml_node_t *);
static void			ni_ifcondition_free(ni_ifcondition_t *);

static ni_ifpolicy_t *		ni_ifpolicies;

static void
ni_ifpolicy_free(ni_ifpolicy_t *policy)
{
	ni_string_free(&policy->name);
	if (policy->match) {
		ni_ifcondition_free(policy->match);
		policy->match = NULL;
	}

	free(policy);
}

static void
__ni_ifpolicy_set_action(ni_ifpolicy_t *policy, ni_ifpolicy_type_t type, xml_node_t *node)
{
	policy->action.type = type;
	policy->action.data = node;
}

static ni_bool_t
__ni_ifpolicy_from_xml(ni_ifpolicy_t *policy, xml_node_t *node)
{
	xml_node_t *item;
	const char *attr;

	policy->node = node;

	if ((attr = xml_node_get_attr(node, "weight")) != NULL) {
		if (ni_parse_int(attr, &policy->weight) < 0) {
			ni_error("%s: cannot parse weight=\"%s\" attribute",
						xml_node_location(node), attr);
			return FALSE;
		}
	}

	for (item = node->children; item; item = item->next) {
		if (ni_string_eq(item->name, "match")) {
			if (policy->match) {
				ni_error("%s: policy specifies multiple <match> elements", xml_node_location(item));
				return FALSE;
			}

			if (!(policy->match = ni_ifpolicy_conditions_from_xml(item))) {
				ni_error("%s: trouble parsing policy conditions", xml_node_location(item));
				return FALSE;
			}
		} else
		if (ni_string_eq(item->name, "merge")) {
			__ni_ifpolicy_set_action(policy, NI_IFPOLICY_TYPE_MERGE, item);
		} else
		if (ni_string_eq(item->name, "create")) {
			__ni_ifpolicy_set_action(policy, NI_IFPOLICY_TYPE_CREATE, item);
		} else {
			ni_error("%s: unknown <%s> element in policy",
					xml_node_location(item), item->name);
			return FALSE;
		}
	}

	return TRUE;
}

ni_ifpolicy_t *
ni_ifpolicy_new(const char *name, xml_node_t *node)
{
	ni_ifpolicy_t *policy;
	
	policy = calloc(1, sizeof(*policy));
	ni_string_dup(&policy->name, name);

	policy->match = NULL;
	policy->action.type = -1;

	if (!__ni_ifpolicy_from_xml(policy, node)) {
		ni_ifpolicy_free(policy);
		return NULL;
	}

	return policy;
}

void
ni_ifpolicy_install(ni_ifpolicy_t *policy)
{
	ni_ifpolicy_t *pos, **tail;

	for (tail = &ni_ifpolicies; (pos = *tail) != NULL; tail = &pos->next)
		;
	*tail = policy;
}

ni_ifpolicy_t *
ni_ifpolicy_by_name(const char *name)
{
	ni_ifpolicy_t *policy;

	for (policy = ni_ifpolicies; policy; policy = policy->next) {
		if (policy->name && ni_string_eq(policy->name, name))
			return policy;
	}

	return NULL;
}

static ni_bool_t
ni_ifpolicy_applicable(ni_ifpolicy_t *policy, ni_ifworker_t *w)
{
	return policy->match && ni_ifcondition_check(policy->match, w);
}

int
ni_ifpolicy_rebind_action(ni_ifworker_t *w, struct ni_netif_action_binding *bind)
{
	ni_ifpolicy_t *policy, *best = NULL;
	int rv = 0;

	if (!w->use_default_policies)
		return FALSE;

	/* FIXME: first loop over explicitly specified policies; if we
	 * find a policy there, record its weight */

	for (policy = ni_ifpolicies; policy; policy = policy->next) {
		if (policy->action.type == NI_IFPOLICY_TYPE_MERGE && ni_ifpolicy_applicable(policy, w)) {
			if (best == NULL || best->weight < policy->weight) {
				/* See if this merge policy specifies input for this method */
				xml_node_t *config = NULL;

				rv = ni_dbus_xml_map_method_argument(bind->method, 0, policy->action.data, &config, NULL);
				if (rv < 0)
					return rv;
				if (config) {
					bind->config = config;
					bind->skip_call = FALSE;
					best = policy;
				}
			}
		}
	}

	return rv;
}

/*
 * Policy matching functions
 */
static ni_ifcondition_t *
ni_ifcondition_new(ni_ifcondition_check_fn_t *check_fn)
{
	ni_ifcondition_t *cond;

	cond = calloc(1, sizeof(*cond));
	cond->check = check_fn;

	return cond;
}

static void
ni_ifcondition_free(ni_ifcondition_t *cond)
{
	free(cond);

	/* XXX: delete subordinate terms */
}

static ni_bool_t
ni_ifcondition_check(const ni_ifcondition_t *cond, ni_ifworker_t *w)
{
	ni_assert(cond->check);

	return cond->check(cond, w);
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
		ni_ifcondition_t *policy, *new;

		if (!(policy = ni_ifcondition_from_xml(child))) {
			if (result)
				ni_ifcondition_free(result);
			return NULL;
		}

		if (result == NULL) {
			result = policy;
		} else {
			new = ni_ifcondition_new(check_fn);
			new->args.terms.left = result;
			new->args.terms.right = policy;
			result = new;
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
__ni_ifpolicy_match_and_check(const ni_ifcondition_t *cond, ni_ifworker_t *w)
{
	return ni_ifcondition_check(cond->args.terms.left, w)
	    && ni_ifcondition_check(cond->args.terms.right, w);
}

static ni_ifcondition_t *
ni_ifcondition_and(xml_node_t *node)
{
	return ni_ifcondition_term2(node, __ni_ifpolicy_match_and_check);
}

/*
 * <or>
 *  <term1>
 *  <term2>
 *  ..
 * </or>
 */
static ni_bool_t
__ni_ifpolicy_match_or_check(const ni_ifcondition_t *cond, ni_ifworker_t *w)
{
	return ni_ifcondition_check(cond->args.terms.left, w)
	    || ni_ifcondition_check(cond->args.terms.right, w);
}

static ni_ifcondition_t *
ni_ifcondition_or(xml_node_t *node)
{
	return ni_ifcondition_term2(node, __ni_ifpolicy_match_or_check);
}

/*
 * <not>
 *  <term>
 * </not>
 */
static ni_bool_t
__ni_ifpolicy_match_not_check(const ni_ifcondition_t *cond, ni_ifworker_t *w)
{
	return !ni_ifcondition_check(cond->args.terms.left, w);
}

static ni_ifcondition_t *
ni_ifcondition_not(xml_node_t *node)
{
	ni_ifcondition_t *result = NULL;
	ni_ifcondition_t *child;

	if (node->children == NULL || node->children->next != NULL) {
		ni_error("%s: <%s> condition needs exactly one child term",
				xml_node_location(node), node->name);
		return NULL;
	}

	if (!(child = ni_ifcondition_from_xml(node->children)))
		return NULL;

	result = ni_ifcondition_new(__ni_ifpolicy_match_not_check);
	result->args.terms.left = child;

	return result;
}

/*
 * <type>interface</type>
 * <type>modem</type>
 */
static ni_bool_t
__ni_ifpolicy_match_type_check(const ni_ifcondition_t *cond, ni_ifworker_t *w)
{
	return cond->args.type == w->type;
}

static ni_ifcondition_t *
ni_ifcondition_type(xml_node_t *node)
{
	ni_ifcondition_t *result;
	ni_ifworker_type_t type;

	if ((type = ni_ifworker_type_from_string(node->cdata)) < 0) {
		ni_error("%s: unknown device type \"%s\"",
				xml_node_location(node), node->cdata);
		return NULL;
	}
	result = ni_ifcondition_new(__ni_ifpolicy_match_type_check);
	result->args.type = type;
	return result;
}

/*
 * <class>...</class>
 * <link-type>...</link-type>
 */
static ni_bool_t
__ni_ifpolicy_match_class_check(const ni_ifcondition_t *cond, ni_ifworker_t *w)
{
	return w->object && ni_dbus_object_isa(w->object, cond->args.class);
}

static ni_ifcondition_t *
__ni_ifpolicy_match_class_new(xml_node_t *node, const char *classname)
{
	const ni_dbus_class_t *class;
	ni_ifcondition_t *result;

	if ((class = ni_objectmodel_get_class(classname)) == NULL) {
		ni_error("%s: unknown object class \"%s\" in <%s> condition",
				xml_node_location(node), classname, node->name);
		return NULL;
	}

	result = ni_ifcondition_new(__ni_ifpolicy_match_class_check);
	result->args.class = class;

	return result;
}

static ni_ifcondition_t *
ni_ifcondition_class(xml_node_t *node)
{
	return __ni_ifpolicy_match_class_new(node, node->cdata);
}

static ni_ifcondition_t *
ni_ifcondition_linktype(xml_node_t *node)
{
	char namebuf[128];

	if (ni_linktype_name_to_type(node->cdata) < 0) {
		ni_error("%s: unknown link type \"%s\"", xml_node_location(node), node->cdata);
		return NULL;
	}
	snprintf(namebuf, sizeof(namebuf), "netif-%s", node->cdata);
	return __ni_ifpolicy_match_class_new(node, namebuf);
}

/*
 * <device>...</device>
 */
static ni_bool_t
__ni_ifpolicy_match_device_check(const ni_ifcondition_t *cond, ni_ifworker_t *w)
{
	ni_warn("<device> condition not implemented yet");
	return FALSE;
}

static ni_ifcondition_t *
ni_ifcondition_device(xml_node_t *node)
{
	ni_ifcondition_t *result;

	result = ni_ifcondition_new(__ni_ifpolicy_match_device_check);
	result->args.device.node = node;
	return result;
}

/*
 * <any>...</any>
 */
static ni_bool_t
__ni_ifpolicy_match_any_check(const ni_ifcondition_t *cond, ni_ifworker_t *w)
{
	return TRUE;
}

static ni_ifcondition_t *
ni_ifcondition_any(xml_node_t *node)
{
	return ni_ifcondition_new(__ni_ifpolicy_match_any_check);
}

/*
 * <none>...</none>
 */
static ni_bool_t
__ni_ifpolicy_match_none_check(const ni_ifcondition_t *cond, ni_ifworker_t *w)
{
	return TRUE;
}

static ni_ifcondition_t *
ni_ifcondition_none(xml_node_t *node)
{
	return ni_ifcondition_new(__ni_ifpolicy_match_none_check);
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
	if (!strcmp(node->name, "device"))
		return ni_ifcondition_device(node);
	if (!strcmp(node->name, "class"))
		return ni_ifcondition_class(node);
	if (!strcmp(node->name, "link-type"))
		return ni_ifcondition_linktype(node);

	ni_error("%s: unsupported policy conditional <%s>", xml_node_location(node), node->name);
	return NULL;
}

/*
 * When the policy's <match> element contains several children, this
 * is treated as an <and> statement
 */
ni_ifcondition_t *
ni_ifpolicy_conditions_from_xml(xml_node_t *node)
{
	return ni_ifcondition_and(node);
}
