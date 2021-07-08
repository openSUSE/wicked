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
#include <ctype.h>

#include <wicked/fsm.h>
#include <wicked/netinfo.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/logging.h>
#include <wicked/xml.h>

#include "client/ifconfig.h"

/*
 * Given the configuration for a device, generate a UUID that uniquely
 * identifies this configuration. We want to use this later to check
 * whether the configuration changed.
 *
 * We do this by hashing the XML configuration using a reasonably
 * collision free SHA hash algorithm, and storing that in a UUIDv5.
 */
ni_bool_t
ni_ifconfig_generate_uuid(const xml_node_t *config, ni_uuid_t *uuid)
{
	/* UUIDv5 of https://github.com/openSUSE/wicked in the URL
	 * namespace as our private namespace for the config UUIDs:
	 *      c89756cc-b7fb-569b-b7f0-49a400fa41fe
	 */
	static const ni_uuid_t ns = {
		.octets = {
			0xc8, 0x97, 0x56, 0xcc, 0xb7, 0xfb, 0x56, 0x9b,
			0xb7, 0xf0, 0x49, 0xa4, 0x00, 0xfa, 0x41, 0xfe
		}
	};
	memset(uuid, 0, sizeof(*uuid));

	/* Generate a version 5 (SHA1) UUID, of the node _content_ */
	return xml_node_content_uuid(config, 5, &ns, uuid) == 0;
}

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

char *
ni_ifpolicy_name_from_ifname(const char *ifname)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	size_t len, i;

	/*
	 * The policy name is used in dbus path which allows to
	 * use only "[A-Z][a-z][0-9]_" elements separated by "/".
	 *
	 * Just use some simple encoding for valid netdev name
	 * characters and return new policy name or NULL.
	 */
	len = ni_string_len(ifname);
	for (i = 0; i < len; ++i) {
		if (i == 0) {
			ni_stringbuf_puts(&buf, "policy__");
		}
		if (isalnum((unsigned char)ifname[i])) {
			ni_stringbuf_putc(&buf, ifname[i]);
			continue;
		}
		switch (ifname[i]) {
			case '_':
				ni_stringbuf_putc(&buf, '_');
				ni_stringbuf_putc(&buf, '_');
				break;
			case '.':
				ni_stringbuf_putc(&buf, '_');
				ni_stringbuf_putc(&buf, 'd');
				break;
			case '-':
				ni_stringbuf_putc(&buf, '_');
				ni_stringbuf_putc(&buf, 'm');
				break;
			default:
				ni_stringbuf_destroy(&buf);
				return NULL;
		}
	}
	return buf.string;
}

ni_bool_t
ni_ifpolicy_name_is_valid(const char *name)
{
	size_t i, len;

	if (!(len = ni_string_len(name)))
		return FALSE;

	for (i = 0; i < len; ++i) {
		if(isalnum((unsigned char)name[i]) ||
				name[i] == '_')
			continue;
		return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_ifpolicy_get_owner_uid(const xml_node_t *node, uid_t *uid)
{
	const char *owner;

	if (!(owner = ni_ifpolicy_get_owner(node)))
		return FALSE;

	if (ni_parse_uint(owner, uid, 10))
		return FALSE;

	return TRUE;
}

ni_bool_t
ni_ifpolicy_set_owner_uid(xml_node_t *node, uid_t uid)
{
	if (!node)
		return FALSE;

	while (xml_node_del_attr(node, NI_NANNY_IFPOLICY_OWNER))
		;

	xml_node_add_attr_uint(node, NI_NANNY_IFPOLICY_OWNER, uid);
	return TRUE;
}

ni_bool_t
ni_ifpolicy_set_owner(xml_node_t *node, const char *owner)
{
	uid_t uid = -1U;

	if (!node || ni_parse_uint(owner, &uid, 10))
		return FALSE;

	return ni_ifpolicy_set_owner_uid(node, uid);
}

ni_bool_t
ni_ifpolicy_set_uuid(xml_node_t *node, const ni_uuid_t *uuid)
{
	const char *ptr;

	if (!node)
		return FALSE;

	while (xml_node_del_attr(node, NI_NANNY_IFPOLICY_UUID))
		;

	ptr = ni_uuid_print(uuid);
	if (!ni_string_empty(ptr))
		xml_node_add_attr(node, NI_NANNY_IFPOLICY_UUID, ptr);
	return TRUE;
}

/*
 * Generate a <match> node for ifpolicy
 */
xml_node_t *
ni_ifpolicy_generate_match(const ni_string_array_t *ifnames, const char *cond)
{
	xml_node_t *mnode = NULL;
	xml_node_t *cnode = NULL;

	if (!(mnode = xml_node_new(NI_NANNY_IFPOLICY_MATCH, NULL)))
		return NULL;

	/* Always true condition */
	if (!ifnames || 0 == ifnames->count) {
		if (!xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_ALWAYS_TRUE, mnode, NULL))
			goto error;
	}
	else {
		unsigned int i;

		if (ni_string_empty(cond))
			cond = NI_NANNY_IFPOLICY_MATCH_COND_OR;

		if (!(cnode = xml_node_new(cond, mnode)))
			goto error;

		for (i = 0; i < ifnames->count; i++) {
			 const char *ifname = ifnames->data[i];

			if (!xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_DEV, cnode, ifname))
				goto error;
		}
	}

	return mnode;

error:
	xml_node_free(mnode);
	xml_node_free(cnode);
	return NULL;
}


/*
 * Convert ifconfig to ifpolicy format
 */
xml_node_t *
ni_convert_cfg_into_policy_node(const xml_node_t *ifcfg, xml_node_t *match, const char *name, const char *origin)
{
	xml_node_t *ifpolicy;
	ni_uuid_t uuid;
	xml_node_t *node;

	if (!ifcfg || !match || ni_string_empty(name) || ni_string_empty(origin))
		return NULL;

	ifpolicy = xml_node_new(NI_NANNY_IFPOLICY, NULL);
	xml_node_reparent(ifpolicy, xml_node_clone_ref(match));

	xml_node_add_attr(ifpolicy, NI_NANNY_IFPOLICY_NAME, name);

	xml_node_add_attr(ifpolicy, NI_NANNY_IFPOLICY_ORIGIN, origin);
	ni_uuid_generate(&uuid);
	xml_node_add_attr(ifpolicy, NI_NANNY_IFPOLICY_UUID, ni_uuid_print(&uuid));

	/* clone <interface> into policy and rename to <merge> */
	node = xml_node_clone(ifcfg, ifpolicy);
	ni_string_dup(&node->name, NI_NANNY_IFPOLICY_MERGE);

	return ifpolicy;
}

xml_document_t *
ni_convert_cfg_into_policy_doc(xml_document_t *ifconfig)
{
	xml_node_t *root, *ifnode, *ifname, *match;
	const char *origin;

	if (xml_document_is_empty(ifconfig))
		return NULL;

	root = xml_document_root(ifconfig);
	origin = xml_node_location_filename(root);

	for (ifnode = root->children; ifnode; ifnode = ifnode->next) {
		if (ni_ifpolicy_is_valid(ifnode)) {
			const char *name = ni_ifpolicy_get_name(ifnode);
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

		ifname = xml_node_get_child(ifnode, NI_CLIENT_IFCONFIG_MATCH_NAME);
		if (!ifname || ni_string_empty(ifname->cdata))
			return NULL;

		if (!(match = ni_ifpolicy_generate_match(NULL, NULL)))
			return NULL;

		xml_node_add_child(root,
			ni_convert_cfg_into_policy_node(ifnode, match, ifname->cdata, origin));
	}

	return ifconfig;
}

static ni_bool_t
ni_ifconfig_migrate_ethtool_link_settings_add(xml_node_t *ethtool, const char *name, const char *value)
{
	xml_node_t *link;

	if ((link = xml_node_get_child(ethtool, "link-settings")))
		return xml_node_new_element(name, link, value) != NULL;
	else
	if ((link = xml_node_new("link-settings", ethtool)))
		return xml_node_new_element(name, link, value) != NULL;

	return FALSE;
}

static ni_bool_t
ni_ifconfig_migrate_ethtool_eee(xml_node_t *ethtool, const xml_node_t *orig)
{
	const xml_node_t *entry;
	xml_node_t *eee, *adv;

	if (!(eee = xml_node_new("eee", NULL)))
		return FALSE;

	for (entry = orig->children; entry; entry = entry->next) {
		if (ni_string_eq(entry->name, "advertise")) {
			if ((adv = xml_node_new(entry->name, eee)))
				xml_node_new_element("mode", adv, entry->cdata);
		} else {
			xml_node_new_element(entry->name, eee, entry->cdata);
		}
	}
	if (eee->children)
		xml_node_add_child(ethtool, eee);
	else
		xml_node_free(eee);
	return TRUE;
}

static ni_bool_t
ni_ifconfig_migrate_ethtool_features(xml_node_t *ethtool, const xml_node_t *offloads)
{
	xml_node_t *features, *feature;
	const xml_node_t *offload;
	ni_bool_t enabled;

	if (!(features = xml_node_new("features", NULL)))
		return FALSE;

	for (offload = offloads->children; offload; offload = offload->next) {
		/* it's a tristate, but we omit the non-boolean values */
		if (ni_parse_boolean(offload->cdata, &enabled))
			continue;

		if ((feature = xml_node_new("feature", features))) {
			xml_node_new_element("name", feature, offload->name);
			xml_node_new_element("enabled", feature, ni_format_boolean(enabled));
		}
	}
	if (features->children)
		xml_node_add_child(ethtool, features);
	else
		xml_node_free(features);
	return TRUE;
}

static ni_bool_t
ni_ifconfig_migrate_ethtool(xml_node_t *ethernet, xml_node_t *ethtool)
{
	ni_bool_t modified = FALSE;
	xml_node_t *orig;

	if ((orig = xml_node_get_child(ethernet, "autoneg-enable"))) {
		ni_ifconfig_migrate_ethtool_link_settings_add(ethtool, "autoneg", orig->cdata);
		xml_node_delete_child_node(ethernet, orig);
		modified = TRUE;
	}
	if ((orig = xml_node_get_child(ethernet, "link-speed"))) {
		ni_ifconfig_migrate_ethtool_link_settings_add(ethtool, "speed", orig->cdata);
		xml_node_delete_child_node(ethernet, orig);
		modified = TRUE;
	}
	if ((orig = xml_node_get_child(ethernet, "port-type"))) {
		ni_ifconfig_migrate_ethtool_link_settings_add(ethtool, "port", orig->cdata);
		xml_node_delete_child_node(ethernet, orig);
		modified = TRUE;
	}
	if ((orig = xml_node_get_child(ethernet, "duplex"))) {
		ni_ifconfig_migrate_ethtool_link_settings_add(ethtool, "duplex", orig->cdata);
		xml_node_delete_child_node(ethernet, orig);
		modified = TRUE;
	}
	if ((orig = xml_node_get_child(ethernet, "wake-on-lan"))) {
		xml_node_reparent(ethtool, orig);
		modified = TRUE;
	}
	if ((orig = xml_node_get_child(ethernet, "eee"))) {
		ni_ifconfig_migrate_ethtool_eee(ethtool, orig);
		xml_node_delete_child_node(ethernet, orig);
		modified = TRUE;
	}
	if ((orig = xml_node_get_child(ethernet, "ring"))) {
		xml_node_reparent(ethtool, orig);
		modified = TRUE;
	}
	if ((orig = xml_node_get_child(ethernet, "offload"))) {
		ni_ifconfig_migrate_ethtool_features(ethtool, orig);
		xml_node_delete_child_node(ethernet, orig);
		modified = TRUE;
	}
	if ((orig = xml_node_get_child(ethernet, "channels"))) {
		xml_node_reparent(ethtool, orig);
		modified = TRUE;
	}
	if ((orig = xml_node_get_child(ethernet, "coalesce"))) {
		xml_node_reparent(ethtool, orig);
		modified = TRUE;
	}
	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_config_node(xml_node_t *config)
{
	ni_bool_t modified = FALSE;
	xml_node_t *old, *new;

	if ((old = xml_node_get_child(config, "ethernet"))) {
		if ((new = xml_node_new("ethtool", NULL))) {
			modified = ni_ifconfig_migrate_ethtool(old, new);
			if (!xml_node_get_child(config, "ethtool") && new->children)
				xml_node_add_child(config, new);
			else
				xml_node_free(new);
		}
		/* keep the (maybe empty) ethernet node,
		 * because it is an iftype giving one */
	}
	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_node(xml_node_t *node, ni_bool_t *modified)
{
	if (!modified || xml_node_is_empty(node))
		return FALSE;

	if (ni_ifconfig_is_config(node)) {
		/* ifconfig with the effective config data */
		if (ni_ifconfig_migrate_config_node(node))
			*modified = TRUE;
		return TRUE;
	} else
	if (ni_ifconfig_is_policy(node)) {
		xml_node_t *action = NULL;

		/* policy action contains the config data  */
		if ((action = xml_node_get_child(node, NI_NANNY_IFPOLICY_MERGE))) {
			if (ni_ifconfig_migrate_config_node(action))
				*modified = TRUE;
			return TRUE;
		}
		if ((action = xml_node_get_child(node, NI_NANNY_IFPOLICY_CREATE))) {
			if (ni_ifconfig_migrate_config_node(action))
				*modified = TRUE;
			return TRUE;
		}
		if ((action = xml_node_get_child(node, NI_NANNY_IFPOLICY_REPLACE))) {
			if (ni_ifconfig_migrate_config_node(action))
				*modified = TRUE;
			return TRUE;
		}
	}
	/* not a ifconfig or ifpolicy node */
	return FALSE;
}

ni_bool_t
ni_ifconfig_migrate(xml_node_t *node)
{
	ni_bool_t modified = FALSE;
	xml_node_t *child;

	if (!node)
		return FALSE;

	/* node itself is a config or policy node  */
	if (ni_ifconfig_migrate_node(node, &modified))
		return modified;

	/* node is a document root with children   */
	for (child = node->children; child; child = child->next)
		ni_ifconfig_migrate_node(child, &modified);

	return modified;
}
