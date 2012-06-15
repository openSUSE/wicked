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

/*
 * Actions associated with the policy - <merge>, <create> etc.
 */
typedef enum {
	NI_IFPOLICY_TYPE_MERGE,
	NI_IFPOLICY_TYPE_REPLACE,
	NI_IFPOLICY_TYPE_CREATE,
} ni_ifpolicy_action_type_t;

struct ni_ifpolicy_action {
	ni_ifpolicy_action_t *		next;
	ni_ifpolicy_action_type_t	type;
	xml_node_t *			data;

	/* An xml policy may specify the node it
	 * applies to by a path, which is a bit like a very
	 * simple xpath, like /foo/bar/baz.
	 */
	char *				xpath;
	ni_bool_t			final;
};

static void			ni_ifpolicy_free(ni_ifpolicy_t *);
static ni_ifcondition_t *	ni_ifpolicy_conditions_from_xml(xml_node_t *);
static ni_bool_t		ni_ifcondition_check(const ni_ifcondition_t *, ni_ifworker_t *);
static ni_ifcondition_t *	ni_ifcondition_from_xml(xml_node_t *);
static void			ni_ifcondition_free(ni_ifcondition_t *);
static ni_ifpolicy_action_t *	ni_ifpolicy_action_new(ni_ifpolicy_action_type_t, xml_node_t *, ni_ifpolicy_t *);
static void			ni_ifpolicy_action_free(ni_ifpolicy_action_t *);
static xml_node_t *		ni_ifpolicy_action_xml_merge(const ni_ifpolicy_action_t *, xml_node_t *);
static xml_node_t *		ni_ifpolicy_action_xml_replace(const ni_ifpolicy_action_t *, xml_node_t *);

static ni_ifpolicy_t *		ni_ifpolicies;

/*
 * Destructor for policy objects
 */
static void
ni_ifpolicy_free(ni_ifpolicy_t *policy)
{
	ni_string_free(&policy->name);
	if (policy->match) {
		ni_ifcondition_free(policy->match);
		policy->match = NULL;
	}
	while (policy->actions) {
		ni_ifpolicy_action_t *a = policy->actions;

		policy->actions = a->next;
		ni_ifpolicy_action_free(a);
	}

	free(policy);
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
		ni_ifpolicy_action_t *action = NULL;

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
			action = ni_ifpolicy_action_new(NI_IFPOLICY_TYPE_MERGE, item, policy);
		} else
		if (ni_string_eq(item->name, "replace")) {
			action = ni_ifpolicy_action_new(NI_IFPOLICY_TYPE_REPLACE, item, policy);
		} else
		if (ni_string_eq(item->name, "create")) {
			action = ni_ifpolicy_action_new(NI_IFPOLICY_TYPE_CREATE, item, policy);
		} else {
			ni_error("%s: unknown <%s> element in policy",
					xml_node_location(item), item->name);
			return FALSE;
		}

		if (action == NULL) {
			ni_error("%s: unable to process <%s> action",
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

/*
 * Compare the weight of two policies.
 * Returns < 0 if a's weight is smaller than that of b, etc.
 */
static int
__ni_ifpolicy_compare(const void *a, const void *b)
{
	const ni_ifpolicy_t *pa = a;
	const ni_ifpolicy_t *pb = b;

	return ((int) pa->weight) - ((int) pb->weight);
}

/*
 * Obtain the list of applicable policies
 */
unsigned int
ni_ifpolicy_get_applicable_policies(ni_ifworker_t *w, const ni_ifpolicy_t **result, unsigned int max)
{
	unsigned int count = 0;
	ni_ifpolicy_t *policy;

	if (!w->use_default_policies)
		return 0;

	for (policy = ni_ifpolicies; policy; policy = policy->next) {
		if (ni_ifpolicy_applicable(policy, w)) {
			if (count < max)
				result[count++] = policy;
		}
	}

	qsort(result, count, sizeof(result[0]), __ni_ifpolicy_compare);
	return count;
}

/*
 * Transform an interface or modem XML document according to a list of policies.
 * Usually, you would obtain that list via ni_ifpolicy_get_applicable_policies
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
xml_node_t *
ni_ifpolicy_transform_document(xml_node_t *node, const ni_ifpolicy_t * const *policies, unsigned int count)
{
	unsigned int i = 0;

	/* Apply policies in order of decreasing weight */
	for (i = count; i--; ) {
		const ni_ifpolicy_t *policy = policies[i];
		ni_ifpolicy_action_t *action;

		for (action = policy->actions; action; action = action->next) {
			switch (action->type) {
			case NI_IFPOLICY_TYPE_MERGE:
				node = ni_ifpolicy_action_xml_merge(action, node);
				break;

			case NI_IFPOLICY_TYPE_REPLACE:
				node = ni_ifpolicy_action_xml_replace(action, node);
				break;

			default:
				continue;
			}
		}
	}

	return node;
}

/*
 * Policy actions
 */
ni_ifpolicy_action_t *
ni_ifpolicy_action_new(ni_ifpolicy_action_type_t type, xml_node_t *node, ni_ifpolicy_t *policy)
{
	ni_ifpolicy_action_t **list = NULL;
	ni_ifpolicy_action_t *action;
	const char *attr;

	if (policy) {
		for (list = &policy->actions; (action = *list) != NULL; list = &action->next)
			;
	}

	action = calloc(1, sizeof(*action));
	action->type = type;
	action->data = node;
	
	switch (type) {
	case NI_IFPOLICY_TYPE_MERGE:
	case NI_IFPOLICY_TYPE_REPLACE:
		if ((attr = xml_node_get_attr(node, "path")) != NULL)
			ni_string_dup(&action->xpath, attr);
		if ((attr = xml_node_get_attr(node, "final")) != NULL) {
			if (!strcasecmp(attr, "true") || !strcmp(attr, "1"))
				action->final = TRUE;
		}
		break;

	default: ;
	}

	if (list)
		*list = action;
	return action;
}

void
ni_ifpolicy_action_free(ni_ifpolicy_action_t *action)
{
	if (action->xpath)
		ni_string_free(&action->xpath);
	free(action);
}

/*
 * Look up XML elements based on the fake xpath.
 * If the named child does not exist, we create a new child of this name.
 * If the named child exists but is marked as "final", we refuse to change it
 * any further.
 */
static void
__ni_ifpolicy_action_xml_lookup(xml_node_t *node, const char *name, xml_node_array_t *res)
{
	xml_node_t *child;
	unsigned int found = 0;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, name)) {
			if (!child->final)
				xml_node_array_append(res, child);
			found++;
		}
	}

	if (!found)
		xml_node_array_append(res, xml_node_new(name, node));
}

static xml_node_array_t *
ni_ifpolicy_action_xml_lookup(xml_node_t *node, const char *path)
{
	xml_node_array_t *cur;
	char *copy, *name;

	if (node->final) {
		ni_error("%s: called with XML element that's marked final", __func__);
		return NULL;
	}

	cur = xml_node_array_new();
	xml_node_array_append(cur, node);

	copy = strdup(path);
	for (name = strtok(copy, "/"); name && cur->count; name = strtok(NULL, "/")) {
		xml_node_array_t *next;
		unsigned int i;

		next = xml_node_array_new();
		for (i = 0; i < cur->count; ++i) {
			xml_node_t *np = cur->data[i];

			__ni_ifpolicy_action_xml_lookup(np, name, next);
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
ni_ifpolicy_action_xml_merge(const ni_ifpolicy_action_t *action, xml_node_t *node)
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

	nodes = ni_ifpolicy_action_xml_lookup(node, action->xpath);
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
 * ifpolicy replace action
 *   <replace path="/foo">
 *    <bar/> <baz/>
 *   </replace>
 * This will look up the <foo> element inside the given document, remove all of
 * its children and replace them with <bar> and <baz>.
 *
 * If the path attribute is not given, this transformation replaces the
 * top-level xml node (which is usually an <interface> or <modem> element).
 */
xml_node_t *
ni_ifpolicy_action_xml_replace(const ni_ifpolicy_action_t *action, xml_node_t *node)
{
	xml_node_array_t *nodes;
	unsigned int i;

	if (node->final)
		return node;

	if (action->xpath == NULL) {
		xml_node_free(node);
		return xml_node_clone_ref(action->data);
	}

	nodes = ni_ifpolicy_action_xml_lookup(node, action->xpath);
	if (nodes == NULL)
		return NULL;

	for (i = 0; i < nodes->count; ++i) {
		xml_node_t *np = nodes->data[i];
		xml_node_t *child;

		/* Remove all children of the node we found. */
		while ((child = np->children) != NULL)
			xml_node_delete_child_node(np, child);

		/* Add all children of the <replace> action to it. */
		for (child = action->data->children; child; child = child->next)
			xml_node_clone(child, np);

		np->final = action->final;
	}

	xml_node_array_free(nodes);
	return node;
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
	return FALSE;
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
