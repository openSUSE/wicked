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


static int		ni_policy_match_interface(const ni_policy_t *, const ni_interface_t *);

/*
 * Constructor/destructor
 */
ni_policy_t *
ni_policy_new(ni_event_t event)
{
	ni_policy_t *policy;

	policy = calloc(1, sizeof(*policy));
	policy->event = event;

	return policy;
}

ni_policy_t *
__ni_policy_clone(const ni_policy_t *src)
{
	ni_policy_t *policy;

	policy = ni_policy_new(src->event);
	if (src->interface)
		policy->interface = ni_interface_get(src->interface);
	return policy;
}

void
ni_policy_free(ni_policy_t *policy)
{
	if (policy->interface)
		ni_interface_put(policy->interface);
	free(policy);
}

/*
 * Add or update a policy
 */
int
__ni_generic_policy_update(ni_handle_t *nih, const ni_policy_t *new_policy)
{
	ni_policy_info_t *info = &nih->policy;
	ni_policy_t *policy, **pos;

	if (new_policy->interface == NULL) {
		ni_error("%s: interface is NULL", __FUNCTION__);
		return -1;
	}

	for (pos = &info->event_policies; (policy = *pos) != NULL; pos = &policy->next) {
		if (policy->event != new_policy->event)
			continue;

		if (ni_policy_match_interface(policy, new_policy->interface) >= 0
		 && ni_policy_match_interface(new_policy, policy->interface) >= 0) {
			ni_interface_put(policy->interface);
			policy->interface = ni_interface_get(new_policy->interface);
			return 0;
		}
	}

	policy = __ni_policy_clone(new_policy);
	policy->next = *pos;
	*pos = policy;
	return 0;
}

int
ni_policy_update(ni_handle_t *nih, const ni_policy_t *new_policy)
{
	if (nih->op->policy_update)
		return nih->op->policy_update(nih, new_policy);
	return __ni_generic_policy_update(nih, new_policy);
}

/*
 * Find a policy object for a given input (event)
 */
ni_policy_t *
ni_policy_match_event(const ni_handle_t *nih, ni_event_t event, const ni_interface_t *dev)
{
	const ni_policy_info_t *info = &nih->policy;
	ni_policy_t *policy, *best = NULL;
	int best_weight = -1;
	int ifaction;

	if (info == NULL)
		return NULL;

	switch (event) {
	case NI_EVENT_LINK_UP:
		ifaction = NI_IFACTION_LINK_UP;
	default:
		return NULL;
	}

	for (policy = info->event_policies; policy; policy = policy->next) {
		ni_interface_t *cfg = policy->interface;
		int weight;

		if (cfg->startmode.ifaction[ifaction].action == NI_INTERFACE_IGNORE)
			continue;

		weight = ni_policy_match_interface(policy, dev);
		if (weight <= best_weight)
			continue;

		best = policy;
		best_weight = weight;
	}

	return best;
}
static int
ni_policy_match_interface(const ni_policy_t *policy, const ni_interface_t *dev)
{
	const ni_interface_t *cfg = policy->interface;
	unsigned int weight = 0;

	/* We do the same matching as __ni_interface_for_config here.
	 * We should unify these. */
	if (cfg->type != dev->type)
		return -1;

	if (cfg->hwaddr.len) {
		if (!ni_link_address_equal(&dev->hwaddr, &cfg->hwaddr))
			return -1;
		weight |= 2;
	}
	if (cfg->name) {
		if (strcmp(cfg->name, dev->name))
			return -1;
		weight |= 1;
	}

	return weight;
}

/*
 * Destructor function
 */
static void
__ni_policy_list_destroy(ni_policy_t **list)
{
	ni_policy_t *pos, *next;

	for (pos = *list; pos != NULL; pos = next) {
		next = pos->next;
		ni_policy_free(pos);
	}
	*list = NULL;
}

void
ni_policy_info_append(ni_policy_info_t *info, ni_policy_t *policy)
{
	ni_policy_t **pos, *tail;

	pos = &info->event_policies;
	while ((tail = *pos) != NULL)
		pos = &tail->next;
	*pos = policy;
}

void
ni_policy_info_destroy(ni_policy_info_t *info)
{
	__ni_policy_list_destroy(&info->event_policies);
}
