/*
 * Policy objects for wickedd
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 *
 * A policy basically consists of three aspects:
 *
 *  - a type (eg "event")
 *  - a match clause
 *  - a transformation clause
 *
 * For now, the only type defined is the "event" type;
 * policies of this type will apply to link change events.
 * Usually, they can be used to automatically apply
 * a configuration to an interface as it comes up.
 *
 * The following (rather simple) example will automatically
 * bring up the ethernet device with the specified MAC address
 * whenever 
 *
 * <policy type="event">
 *  <match>
 *   <event type="link-up">
 *    <interface type="ethernet">
 *     <mac address="00:11:22:33:44:55"/>
 *    </interface>
 *   </event>
 *  </match>
 *
 *  <transformation action="put">
 *   <interface>
 *    <status network="up"/>
 *    <protocol family="ipv4">
 *     <dhcp/>
 *    </protocol>
 *   </interface>
 *  </transformation>
 * </policy>
 *
 * Matching works by making sure all elements specified
 * in the match clause exist in the event object and the
 * interface object it contains, and that they have matching
 * attributes.
 *
 * Transformations are calls to the REST API. The <interface>
 * clause specifies changes to the interface - for now, the
 * transformation logic will pretty simple-mindedly replace
 * any child elements of <interface> with the elements given
 * in the transformation clause.
 *
 * The path of the REST call is (implicitly) /system/interface/<ifname>.
 *
 * In a later version, we can make this arbitrarily complex if
 * needed. Feel free to implement an XSLT processor :-)
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <unistd.h>

#include <wicked/xml.h>
#include "netinfo_priv.h"
#include "config.h"

static ni_policy_t *	ni_policy_match(ni_policy_t *, xml_node_t *);

/*
 * Parse the global XML policy file
 */
int
ni_policy_file_parse(const char *filename, ni_policy_info_t *info)
{
	ni_policy_t *policy;
	xml_document_t *doc;
	xml_node_t *pnode;

	ni_policy_info_destroy(info);

	if (!ni_file_exists(filename))
		return 0;

	doc = xml_document_read(filename);
	if (!doc) {
		ni_error("unable to parse policy file %s", filename);
		return -1;
	}

	info->document = doc;
	for (pnode = xml_document_root(doc)->children; pnode; pnode = pnode->next) {
		xml_node_t *match, *xfrm;
		const char *type, *xfrm_action;
		ni_policy_t **list, *tail;

		if (strcmp(pnode->name, "policy")) {
			ni_warn("%s: ignoring unexpected element <%s>", filename, pnode->name);
			continue;
		}

		if (!(type = xml_node_get_attr(pnode, "type"))
		 || !(match = xml_node_get_child(pnode, "match"))
		 || !(xfrm = xml_node_get_child(pnode, "transformation"))
		 || !(xfrm_action = xml_node_get_attr(xfrm, "action"))) {
			ni_error("%s: incomplete policy definition", filename);
			return -1;
		}

		if (!strcmp(type, "event")) {
			list = &info->event_policies;
		} else {
			ni_error("%s: unknown policy type \"%s\"", filename, type);
			return -1;
		}

		policy = calloc(1, sizeof(*policy));
		policy->match = match->children;
		policy->transform = xfrm;
		policy->action = xfrm_action;

		while ((tail = *list) != NULL)
			list = &tail->next;

		*list = policy;
	}

	return 0;
}

/*
 * Find a policy object for a given input (event)
 */
ni_policy_t *
ni_policy_match_event(ni_policy_info_t *info, xml_node_t *event)
{
	return ni_policy_match(info->event_policies, event);
}

/*
 * Matching policies is mostly a recursive XML comparison exercise
 */
static int
__xml_element_match(const xml_node_t *match, const xml_node_t *input)
{
	for (; match; match = match->next) {
		const xml_node_t *found = NULL;

		found = xml_node_get_child_with_attrs(input, match->name, &match->attrs);
		if (!found)
			return 0;

		/* Now make sure that all descendant elements match */
		if (match->children && !__xml_element_match(match->children, found))
			return 0;
	}

	return 1;
}

ni_policy_t *
ni_policy_match(ni_policy_t *list, xml_node_t *event)
{
	ni_policy_t *policy;

	for (policy = list; policy; policy = policy->next) {
		const xml_node_t *match = policy->match;

		if (strcmp(event->name, match->name)
		 || !xml_node_match_attrs(event, &match->attrs))
			continue;

		if (__xml_element_match(match->children, event))
			return policy;
	}

	return NULL;
}

/*
 * Apply a policy transformation to an interface
 */
int
ni_policy_apply(const ni_policy_t *policy, xml_node_t *transformee)
{
	xml_node_t *changes, *replace;

	changes = xml_node_get_child(policy->transform, transformee->name);
	if (!changes) {
		ni_error("policy does not contain a <%s> transform", transformee->name);
		return -1;
	}

	for (replace = changes->children; replace; replace = replace->next) {
		xml_node_t *match;

		/* delete the child node we're about to replace */
		match = xml_node_get_child_with_attrs(transformee, replace->name, &replace->attrs);
		if (match)
			xml_node_delete_child_node(transformee, match);

		/* Create a clone of this node and its descendants */
		xml_node_clone(replace, transformee);
	}
	return 0;
}

/*
 * Destructor function
 */
static void
__ni_policy_list_destroy(ni_policy_t **list)
{
	ni_policy_t *pos;

	while ((pos = *list) != NULL) {
		list = &pos->next;
		free(pos);
	}
}

void
ni_policy_info_destroy(ni_policy_info_t *info)
{
	if (info->document) {
		xml_document_free(info->document);
		info->document = NULL;
	}
	__ni_policy_list_destroy(&info->event_policies);
}
