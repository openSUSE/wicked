/*
 *	wicked client related policy functions
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
 */

#include <unistd.h>
#include <sys/types.h>

#include <wicked/fsm.h>
#include <wicked/netinfo.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/logging.h>
#include <wicked/xml.h>

#include "client/ifconfig.h"

static xml_node_t *
__ni_policy_add_to_match(xml_node_t *policy, const char *name, const char *value)
{
	if (policy && !ni_string_empty(name)) {
		xml_node_t *match = xml_node_get_child(policy, NI_NANNY_IFPOLICY_MATCH);

		if (match)
			return xml_node_new_element(name, match, value);
	}

	return NULL;
}

ni_bool_t
ni_ifpolicy_match_add_min_state(xml_node_t *policy, ni_fsm_state_t state)
{
	if (ni_ifworker_is_valid_state(state)) {
		const char *sname = ni_ifworker_state_name(state);

		if (__ni_policy_add_to_match(policy,
		    NI_NANNY_IFPOLICY_MATCH_MIN_STATE, sname)) {
			return TRUE;
		}
	}

	return FALSE;
}

ni_bool_t
ni_ifpolicy_match_add_link_type(xml_node_t *policy, unsigned int type)
{
	const char *linktype;

	linktype = ni_linktype_type_to_name(type);
	if (__ni_policy_add_to_match(policy,
	    NI_NANNY_IFPOLICY_MATCH_LINK_TYPE, linktype)) {
		return TRUE;
	}

	return FALSE;
}

/*
 * Generate a <match> node for ifpolicy
 */
static xml_node_t *
ni_ifpolicy_generate_match(const xml_node_t *ifname)
{
	xml_node_t *mnode;
	const char *namespace;
	char *device_str = NULL;

	if (!ifname)
		return NULL;

	/* Resolve namespace */
	namespace = xml_node_get_attr(ifname, "namespace");
	ni_string_printf(&device_str, "%s%s%s", NI_NANNY_IFPOLICY_MATCH_DEV,
		ni_string_empty(namespace) ? "" : ":",
		ni_string_empty(namespace) ? "" : namespace);

	if (!(mnode = xml_node_new(NI_NANNY_IFPOLICY_MATCH, NULL)) ||
	    !xml_node_new_element(device_str, mnode, ifname->cdata)) {
		return NULL;
	}

	ni_string_free(&device_str);
	return mnode;
}


/*
 * Convert ifconfig to ifpolicy format
 */
xml_node_t *
ni_convert_cfg_into_policy_node(xml_node_t *ifcfg, const char *origin)
{
	xml_node_t *ifpolicy, *match, *ifname;
	ni_uuid_t uuid;

	if (!(ifname = xml_node_get_child(ifcfg, NI_CLIENT_IFCONFIG_MATCH_NAME)))
		return NULL;

	if (!(match = ni_ifpolicy_generate_match(ifname)))
		return NULL;

	ifpolicy = xml_node_new(NI_NANNY_IFPOLICY, NULL);
	xml_node_add_child(ifpolicy, match);

	xml_node_add_attr(ifpolicy, NI_NANNY_IFPOLICY_NAME, ifname->cdata);

	xml_node_add_attr(ifpolicy, NI_NANNY_IFPOLICY_ORIGIN, origin);
	ni_uuid_generate(&uuid);
	xml_node_add_attr(ifpolicy, NI_NANNY_IFPOLICY_UUID, ni_uuid_print(&uuid));

	ni_string_dup(&ifcfg->name, NI_NANNY_IFPOLICY_MERGE);
	xml_node_reparent(ifpolicy, ifcfg);

	return ifpolicy;
}

xml_document_t *
ni_convert_cfg_into_policy_doc(xml_document_t *ifconfig)
{
	xml_node_t *root, *ifnode;
	const char *origin;

	if (xml_document_is_empty(ifconfig))
		return NULL;

	root = xml_document_root(ifconfig);
	origin = xml_node_get_location_filename(root);

	for (ifnode = root->children; ifnode; ifnode = ifnode->next) {
		if (ni_ifpolicy_is_valid(ifnode)) {
			const char *name = xml_node_get_attr(ifnode, NI_NANNY_IFPOLICY_NAME);
			ni_debug_ifconfig("Ignoring already existing %s named %s from %s",
				NI_NANNY_IFPOLICY, name, origin);
			continue;
		}
		else if (ni_ifconfig_is_policy(ifnode)) {
			ni_debug_ifconfig("Ignoring already existing, noname %s from %s",
				NI_NANNY_IFPOLICY, origin);
			continue;
		}

		if (!ni_ifconfig_is_config(ifnode)) {
			ni_error("Invalid object found in file %s: neither an %s nor %s",
				origin, NI_CLIENT_IFCONFIG, NI_NANNY_IFPOLICY);
			return NULL;
		}

		xml_node_add_child(root,
			ni_convert_cfg_into_policy_node(ifnode, origin));
	}

	return ifconfig;
}
