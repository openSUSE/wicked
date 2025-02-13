/*
 *	wicked xml interface config and policy utilities
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *	Copyright (C) 2014-2025 SUSE LLC
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
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

#include "client/ifxml.h"

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

	return xml_node_add_attr_uint(node, NI_NANNY_IFPOLICY_OWNER, uid);
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

	ptr = ni_uuid_print(uuid);
	if (!node || ni_string_empty(ptr))
		return FALSE;

	while (xml_node_del_attr(node, NI_NANNY_IFPOLICY_UUID))
		;

	return xml_node_add_attr(node, NI_NANNY_IFPOLICY_UUID, ptr);
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

	if (xml_node_is_empty(ifcfg) || xml_node_is_empty(match) ||
		ni_string_empty(name) || ni_string_empty(origin))
		return NULL;

	ifpolicy = xml_node_new(NI_NANNY_IFPOLICY, NULL);

	/* add match node as counted reference to the policy */
	xml_node_reparent(ifpolicy, xml_node_ref(match));

	/* clone <interface> into policy and rename to <merge>
	 * TODO: ahm... add action parameter to this function.
	 */
	node = xml_node_clone(ifcfg, ifpolicy);
	ni_string_dup(&node->name, NI_NANNY_IFPOLICY_MERGE);

	/* apply name and origin to the policy node itself … */
	ni_var_array_destroy(&ifpolicy->attrs);
	xml_node_add_attr(ifpolicy, NI_NANNY_IFPOLICY_NAME, name);
	xml_node_add_attr(ifpolicy, NI_NANNY_IFPOLICY_ORIGIN, origin);

	/* … and remove origin, uuid, ... from policy action */
	ni_var_array_destroy(&node->attrs);

	/* calculate an UUIDv5 (sha1 checksum) of the policy content */
	ni_ifconfig_generate_uuid(ifpolicy, &uuid);
	ni_ifpolicy_set_uuid(ifpolicy, &uuid);

	return ifpolicy;
}

xml_document_t *
ni_convert_cfg_into_policy_doc(xml_document_t *doc)
{
	xml_node_t *root, *match, *policy;
	const char *origin;
	const char *ifname;
	char *name = NULL;

	if (!(root = xml_document_root(doc)))
		return NULL;

	if (ni_string_empty(root->name) || !root->children)
		return NULL;

	origin = ni_ifconfig_get_origin(root);
	if (ni_string_empty(origin))
		return NULL;

	if (ni_ifpolicy_is_valid(root)) {
		const char *name = ni_ifpolicy_get_name(root);

		ni_debug_ifconfig("Ignoring already existing %s named %s from %s",
				NI_NANNY_IFPOLICY, name, origin);
		return doc;
	}
	if (ni_ifxml_is_policy(root)) {
		ni_debug_ifconfig("Ignoring already existing, noname %s from %s",
				NI_NANNY_IFPOLICY, origin);
		return doc;
	}

	if (!ni_ifxml_is_config(root)) {
		ni_error("Unknown document node '%s' found in file %s: neither an %s nor %s",
				root->name, origin, NI_CLIENT_IFCONFIG, NI_NANNY_IFPOLICY);
		return NULL;
	}

	ifname = xml_node_get_child_cdata(root, NI_CLIENT_IFCONFIG_MATCH_NAME);
	if (ni_string_empty(ifname))
		return NULL;

	if (!(match = xml_node_new(NI_NANNY_IFPOLICY_MATCH, NULL)))
		return NULL;

	if (!xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_DEV, match, ifname)) {
		xml_node_free(match);
		return NULL;
	}

	name = ni_ifpolicy_name_from_ifname(ifname);
	policy = ni_convert_cfg_into_policy_node(root, match, name, origin);
	ni_string_free(&name);
	if (policy) {
		xml_node_location_relocate(policy, origin);
		xml_document_set_root(doc, policy);
		xml_node_free(match);
		return doc;
	}
	xml_node_free(match);
	return NULL;
}

/*
 * ifxml utilities
 */
ni_bool_t
ni_ifxml_is_config(const xml_node_t *node)
{
	return node && node->children && ni_string_eq(node->name, NI_CLIENT_IFCONFIG);
}

ni_bool_t
ni_ifxml_is_policy(const xml_node_t *node)
{
	if (node && node->children) {
		if (ni_string_eq(node->name, NI_NANNY_IFPOLICY))
			return TRUE;
#ifdef NI_ENABLE_NANNY_TEMPLATE
		if (ni_string_eq(node->name, NI_NANNY_IFTEMPLATE))
			return TRUE;
#endif
	}
	return FALSE;
}

/*
 * ifxml migration utilities
 */
ni_bool_t
ni_ifxml_node_is_migrated(const xml_node_t *node)
{
	ni_bool_t migrated = FALSE;
	const char *value;

	while (node && node->parent && !ni_string_empty(node->parent->name))
		node = node->parent;

	value = xml_node_get_attr(node, "migrated");
	if (ni_parse_boolean(value, &migrated) != 0)
		return FALSE;

	return migrated;
}

ni_bool_t
ni_ifxml_node_set_migrated(xml_node_t *node, ni_bool_t migrated)
{
	const char *value;

	while (node && node->parent && !ni_string_empty(node->parent->name))
		node = node->parent;

	xml_node_del_attr(node, "migrated");
	if (!migrated)
		return TRUE;

	value = ni_format_boolean(TRUE);
	return xml_node_add_attr(node, "migrated", value);
}

static const char *
ni_ifconfig_control_get_mode(xml_node_t *config)
{
	xml_node_t *ctrl;

	if (!(ctrl = xml_node_create(config, NI_CLIENT_IFCONFIG_CONTROL)))
		return NULL;

	return xml_node_get_child_cdata(ctrl, NI_CLIENT_IFCONFIG_MODE);
}

static ni_bool_t
ni_ifconfig_control_set_mode(xml_node_t *config, const char *mode)
{
	xml_node_t *ctrl, *node;

	if (!(ctrl = xml_node_create(config, NI_CLIENT_IFCONFIG_CONTROL)))
		return FALSE;

	if (!(node = xml_node_create(ctrl, NI_CLIENT_IFCONFIG_MODE)))
		return FALSE;

	return xml_node_set_cdata(node, mode);
}

static const char *
ni_ifconfig_link_get_master(xml_node_t *config, const xml_node_t **node)
{
	xml_node_t *link, *master;

	if (!(link = xml_node_get_child(config, NI_CLIENT_IFCONFIG_LINK)))
		return NULL;

	if (!(master = xml_node_get_child(link, NI_CLIENT_IFCONFIG_MASTER)))
		return NULL;

	if (ni_string_empty(master->cdata))
		return NULL;

	if (node)
		*node = master;
	return master->cdata;
}

static ni_bool_t
ni_ifconfig_link_set_master(xml_node_t *config, const char *master)
{
	xml_node_t *link, *node;

	if (!(link = xml_node_create(config, NI_CLIENT_IFCONFIG_LINK)))
		return FALSE;

	if (!(node = xml_node_create(link, NI_CLIENT_IFCONFIG_MASTER)))
		return FALSE;

	return xml_node_set_cdata(node, master);
}

static const char *
ni_ifconfig_link_get_port_config(xml_node_t *config, const xml_node_t **node)
{
	xml_node_t *link, *pconf;
	const char *ptype;

	if (!(link = xml_node_get_child(config, NI_CLIENT_IFCONFIG_LINK)))
		return NULL;

	if (!(pconf = xml_node_get_child(link, NI_CLIENT_IFCONFIG_LINK_PORT)))
		return NULL;

	ptype = xml_node_get_attr(pconf, NI_CLIENT_IFCONFIG_PORT_TYPE);
	if (ni_string_empty(ptype))
		return NULL;	/* invalid union node without a type */

	if (node)
		*node = pconf;
	return ptype;
}

static ni_bool_t
ni_ifconfig_link_set_port_config(xml_node_t *config, xml_node_t *pconf)
{
	xml_node_t *link, *oconf;

	if (!pconf || !(link = xml_node_create(config, NI_CLIENT_IFCONFIG_LINK)))
		return FALSE;

	if ((oconf = xml_node_get_child(link, NI_CLIENT_IFCONFIG_LINK_PORT))) {
		xml_node_detach(oconf);
		xml_node_free(oconf);
	}

	xml_node_reparent(link, pconf);
	return TRUE;
}

static xml_node_t *
ni_ifconfig_create_port_config_node(const char *ptype)
{
	xml_node_t *pconf;

	if (!(pconf = xml_node_new(NI_CLIENT_IFCONFIG_LINK_PORT, NULL)))
		return NULL;

	if (xml_node_add_attr(pconf, NI_CLIENT_IFCONFIG_PORT_TYPE, ptype))
		return pconf;

	xml_node_free(pconf);
	return NULL;
}

static xml_node_t *
ni_ifconfig_create(const char *ifname, const char *origin, const char *owner)
{
	xml_node_t *config;

	if (ni_string_empty(ifname))
		return NULL;

	if (!(config = xml_node_new(NI_CLIENT_IFCONFIG, NULL)))
		return NULL;

	if (origin && !xml_node_add_attr(config, NI_CLIENT_IFCONFIG_ORIGIN, origin))
		goto failure;

	if (owner && !xml_node_add_attr(config, NI_CLIENT_IFCONFIG_OWNER, owner))
		goto failure;

	if (!xml_node_new_element(NI_CLIENT_IFCONFIG_MATCH_NAME, config, ifname))
		goto failure;

	return config;

failure:
	xml_node_free(config);
	return NULL;
}

static xml_node_t *
ni_ifconfig_get_name(xml_node_t *config)
{
	return xml_node_get_child(config, NI_CLIENT_IFCONFIG_MATCH_NAME);
}

static const char *
ni_ifconfig_get_ifname(xml_node_t *config)
{
	xml_node_t *name;

	if (!(name = ni_ifconfig_get_name(config)))
		return NULL;

	if (xml_node_get_attr(name, "namespace"))
		return NULL;

	return name->cdata;
}

static const char *
ni_ifconfig_get_ifindex(xml_node_t *config)
{
	xml_node_t *name;
	const char *ns;

	if (!(name = ni_ifconfig_get_name(config)))
		return NULL;

	ns = xml_node_get_attr(name, "namespace");
	if (!ni_string_eq("ifindex", ns))
		return NULL;

	return name->cdata;
}

static xml_node_t *
ni_ifpolicy_create(const char *ifname, const char *origin, const char *owner,
		xml_node_t **config)
{
	xml_node_t *policy, *match, *action;
	char *name = NULL;

	if (ni_string_empty(ifname) || (config && *config))
		return NULL;

	if (!(policy = xml_node_new(NI_NANNY_IFPOLICY, NULL)))
		return NULL;

	if (!(name = ni_ifpolicy_name_from_ifname(ifname)))
		goto failure;

	if (!xml_node_add_attr(policy, NI_NANNY_IFPOLICY_NAME, name))
		goto failure;

	ni_string_free(&name);

	if (origin && !xml_node_add_attr(policy, NI_NANNY_IFPOLICY_ORIGIN, origin))
		goto failure;

	if (owner && !xml_node_add_attr(policy, NI_NANNY_IFPOLICY_OWNER, owner))
		goto failure;

	if (!(match = xml_node_new(NI_NANNY_IFPOLICY_MATCH, policy)))
		goto failure;

	if (!xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_DEV, match, ifname))
		goto failure;

	if (!(action = xml_node_new(NI_NANNY_IFPOLICY_MERGE, policy)))
		goto failure;

	if (!xml_node_new_element(NI_CLIENT_IFCONFIG_MATCH_NAME, action, ifname))
		goto failure;

	/* action contains the actual config */
	if (config)
		*config = action;

	return policy;

failure:
	ni_string_free(&name);
	xml_node_detach(policy);
	xml_node_free(policy);
	return NULL;
}

static xml_node_t *
ni_ifxml_get_ifconfig_node(xml_document_t *doc)
{
	xml_node_t *root, *node;

	if (!(root = xml_document_root(doc)))
		return NULL;

	if (ni_ifxml_is_config(root))
		return root;

	if (ni_ifxml_is_policy(root)) {
		if ((node = xml_node_get_child(root, NI_NANNY_IFPOLICY_MERGE)))
			return node;
		if ((node = xml_node_get_child(root, NI_NANNY_IFPOLICY_REPLACE)))
			return node;
		if ((node = xml_node_get_child(root, NI_NANNY_IFPOLICY_CREATE)))
			return node;
	}

	return NULL;
}

static xml_node_t *
ni_ifxml_find_config_by_ifname(xml_document_array_t *docs, const char *ifname)
{
	xml_document_t *doc;
	xml_node_t *config;
	const char *name;
	unsigned int i;

	for (i = 0; i < docs->count; ++i) {
		doc = docs->data[i];
		if (!(config = ni_ifxml_get_ifconfig_node(doc)))
			continue;

		if (!(name = ni_ifconfig_get_ifname(config)))
			continue;

		if (ni_string_eq(ifname, name))
			return config;
	}
	return NULL;
}

static xml_node_t *
ni_ifxml_find_config_by_ifindex(xml_document_array_t *docs, const char *ifindex)
{
	xml_document_t *doc;
	xml_node_t *config;
	const char *index;
	unsigned int i;

	for (i = 0; i < docs->count; ++i) {
		doc = docs->data[i];
		if (!(config = ni_ifxml_get_ifconfig_node(doc)))
			continue;

		if (!(index = ni_ifconfig_get_ifindex(config)))
			continue;

		if (ni_string_eq(ifindex, index))
			return config;
	}
	return NULL;
}

static const char *
ni_ifxml_find_ifname_by_ifindex(xml_document_array_t *docs, const char *ifindex)
{
	xml_node_t *config;
	xml_node_t *policy;
	xml_node_t *match;
	xml_node_t *device;

	/*
	 * The original (ibft,nbft firmware) vlan ifconfig referred to
	 * lower (ethernet) via ifindex. The conversion to policy added
	 * an odd child reference match to the lower .. by ifname.
	 *
	 * The resulting policy is using device match by name and action
	 * config with ifindex in it's name we also found as reference
	 * in an another policy... lookup by ifindex and return ifname
	 * from match.
	 */
	if (!(config = ni_ifxml_find_config_by_ifindex(docs, ifindex)))
		return NULL;

	if (!(policy = ni_ifxml_is_config(config) ? NULL : config->parent))
		return NULL;

	if (!(match = xml_node_get_child(policy, NI_NANNY_IFPOLICY_MATCH)))
		return NULL;

	if (!(device = xml_node_get_child(match, NI_NANNY_IFPOLICY_MATCH_DEV)))
		return NULL;

	return device->cdata;
}

static const char *
ni_ifxml_resolve_ifname_node(xml_document_array_t *docs, xml_node_t *device,
		const char **ifindex)
{
	const char *attr;

	if (!docs || !device)
		return NULL;

	if (!(attr = xml_node_get_attr(device, "namespace")))
		return device->cdata;

	if (ni_string_eq(attr, "ifindex")) {
		if (ifindex)
			*ifindex = device->cdata;
		return ni_ifxml_find_ifname_by_ifindex(docs, device->cdata);
	}

	return NULL;
}

static ni_bool_t
ni_ifpolicy_match_remove_child_ref(xml_node_t *policy, const char *name)
{
	xml_node_t *match, *or, *child, *next, *device;
	ni_bool_t modified = FALSE;
	const char *ns;

	/*
	 * A bond,team,[ovs-]bridge were referencing their ports via:
	 * <or>
	 *   <child><device>${portname}</device></or>
	 *   […]
	 * </or>
	 * We remove the obsolete reference to the port inclusive of
	 * the <or> and <child> nodes once they're empty.
	 */
	if (!ni_ifxml_is_policy(policy) || ni_string_empty(name))
		return modified;

	if (!(match = xml_node_get_child(policy, NI_NANNY_IFPOLICY_MATCH)))
		return modified;

	if (!(or = xml_node_get_child(match, NI_NANNY_IFPOLICY_MATCH_COND_OR)))
		return modified;

	for (child = or->children; child; child = next) {
		next = or->next;

		if (!(device = xml_node_get_child(child, NI_NANNY_IFPOLICY_MATCH_DEV)))
			continue;

		ns = xml_node_get_attr(device, "namespace");
		if (!ni_string_empty(ns))
			continue;

		if (!ni_string_eq(device->cdata, name))
			continue;

		if (xml_node_delete_child_node(child, device))
			modified = TRUE;

		if (xml_node_is_empty(child) && xml_node_delete_child_node(or, child))
			modified = TRUE;

		break; /* We don't expect to find it again */
	}
	if (xml_node_is_empty(or) && xml_node_delete_child_node(match, or))
		modified = TRUE;

	return modified;
}

static ni_bool_t
ni_ifpolicy_add_match_device_ref(xml_node_t *policy, const char *device)
{
	ni_bool_t modified = FALSE;
	xml_node_t *match, *ref, *dev;

	if (!ni_ifxml_is_policy(policy) || ni_string_empty(device))
		return modified;

	if (!(match = xml_node_create(policy, NI_NANNY_IFPOLICY_MATCH)))
		return modified;

	ref = NULL;
	while ((ref = xml_node_get_next_child(match, NI_NANNY_IFPOLICY_MATCH_REF, ref))) {
		if (!(dev = xml_node_get_child(ref, NI_NANNY_IFPOLICY_MATCH_DEV)))
			continue;

		if (!ni_string_empty(xml_node_get_attr(dev, "namespace")))
			continue;

		if (!ni_string_eq(dev->cdata, device))
			continue;

		return FALSE;
	}

	if (!(ref = xml_node_new(NI_NANNY_IFPOLICY_MATCH_REF, NULL)))
		return FALSE;

	if (!(dev = xml_node_new_element(NI_NANNY_IFPOLICY_MATCH_DEV, ref, device))) {
		xml_node_free(ref);
		return FALSE;
	}

	xml_node_add_child(match, ref);
	return TRUE;
}


/*
 * ifxml node migration functions
 */
static ni_bool_t
ni_ifconfig_migrate_ethtool_link_settings_add(xml_node_t *ethtool, const char *name, const char *value)
{
	xml_node_t *link;

	if ((link = xml_node_get_child(ethtool, "link-settings")))
		return xml_node_new_element(name, link, value) != NULL;

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
ni_ifconfig_migrate_ethernet_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *ethernet)
{
	ni_bool_t modified = FALSE;
	xml_node_t *ethtool;

	/* Do we need to cleanup old "ethernet" even the config
	 * already contains "ethtool" node? IMO not needed... */
	if (xml_node_get_child(config, "ethtool"))
		return modified;

	if (!(ethtool = xml_node_new("ethtool", NULL)))
		return modified;

	modified = ni_ifconfig_migrate_ethtool(ethernet, ethtool);
	if (ethtool->children)
		xml_node_add_child(config, ethtool);
	else
		xml_node_free(ethtool);

	/* keep the (maybe empty) ethernet node,
	 * because it is an iftype giving one */
	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_wireless_network(xml_node_t *network)
{
	/* migrate content inside the network dict if needed */
	return FALSE;
}

static ni_bool_t
ni_ifconfig_migrate_wireless_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *wireless)
{
	ni_bool_t modified = FALSE;
	xml_node_t *networks;
	xml_node_t *network;

	if (xml_node_get_child(wireless, "networks"))
		return modified;

	if (!(networks = xml_node_new("networks", wireless)))
		return modified;

	while ((network = xml_node_get_child(wireless, "network"))) {
		xml_node_reparent(networks, network);
		ni_ifconfig_migrate_wireless_network(network);
		modified = TRUE;
	}
	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_link_ovsbr_port(xml_node_t *link, xml_node_t *port)
{
	xml_node_t *bnode;
	xml_node_t *mnode;
	const char *mtype;

	/*
	 * Rewrite link node containing port with type=ovs-bridge from:
	 *   <link>
	 *     <master>ovs-system</master>
	 *     <port type="ovs-bridge">
	 *       <bridge>ovsbrX</bridge>
	 *     </port>
	 *   </link>
	 * into resolved link node with ovs-bridge in master reference:
	 *   <link>
	 *     <master>ovsbrX</master>
	 *     <port type="ovs-bridge"/>
	 *   </link>
	 * by moving the bridge name from port into master node cdata.
	 */
	bnode = xml_node_get_child(port, NI_CLIENT_IFCONFIG_BRIDGE);
	if (!bnode || ni_string_empty(bnode->cdata))
		return FALSE;

	if ((mnode = xml_node_get_child(link, NI_CLIENT_IFCONFIG_MASTER))) {
		mtype = ni_linktype_type_to_name(NI_IFTYPE_OVS_SYSTEM);

		/* if master is empty, ovs-system or same bridge */
		if (!ni_string_empty(mnode->cdata) &&
		    !ni_string_eq(mnode->cdata, mtype) &&
		    !ni_string_eq(mnode->cdata, bnode->cdata))
			return FALSE;

	} else if (!(mnode = xml_node_new(NI_CLIENT_IFCONFIG_MASTER, link)))
		return FALSE;

	xml_node_set_cdata(mnode, bnode->cdata);
	/* we've set the bridge in master and can remove the
	 * obsolete bridge node from bridge-port config now. */
	xml_node_detach(bnode);
	xml_node_free(bnode);

	/* mark the port migrated, may be triggered by master */
	ni_ifxml_node_set_migrated(link, TRUE);
	return TRUE;
}

static ni_bool_t
ni_ifconfig_migrate_link_port(xml_node_t *link)
{
	xml_node_t *port;
	const char *type;

	if (!(port = xml_node_get_child(link, NI_CLIENT_IFCONFIG_LINK_PORT)))
		return FALSE;

	type = xml_node_get_attr(port, NI_CLIENT_IFCONFIG_PORT_TYPE);
	switch ((ni_iftype_t)ni_linktype_name_to_type(type)) {
	case NI_IFTYPE_OVS_BRIDGE:
		return ni_ifconfig_migrate_link_ovsbr_port(link, port);
	default:
		return FALSE;
	}
}

static ni_bool_t
ni_ifconfig_migrate_link_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	ni_bool_t modified = FALSE;
	xml_node_t *policy;
	const char *master;

	if (ni_ifconfig_migrate_link_port(migrate))
		modified = TRUE;

	policy = ni_ifxml_is_config(config) ? NULL : config->parent;
	if (!policy || !(master = xml_node_get_child_cdata(migrate, "master")))
		return modified;

	if (ni_ifpolicy_match_remove_child_ref(policy, master))
		modified = TRUE;

	if (ni_ifpolicy_add_match_device_ref(policy, master))
		modified = TRUE;

	return modified;
}

static int
ni_ifconfig_migrate_port_master(xml_node_t *migrate,
		const char *port, const char *ptype,
		const char *master)
{
	const xml_node_t *node = NULL;
	const char *current;

	if (!(current = ni_ifconfig_link_get_master(migrate, &node))) {
		if (!ni_ifconfig_link_set_master(migrate, master)) {
			ni_error("%s: failed to add %s port '%s' to '%s'",
					xml_node_location(migrate), ptype,
					port, master);
			return -1;
		}
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_READWRITE,
				"%s: added %s port '%s' to '%s'",
				xml_node_location(migrate), ptype,
				port, master);
		return 0;
	}

	if (!ni_string_eq(current, master)) {
		ni_error("%s: cannot add %s port '%s' to '%s', already in '%s'",
			xml_node_location(node), ptype, port, master, current);
		return -1;
	}
	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_READWRITE,
			"%s: %s port '%s' is already set to '%s'",
			xml_node_location(node), ptype, port, current);
	return 1;
}

static ni_bool_t
ni_ifconfig_migrate_l2_port_ipv4(xml_node_t *migrate)
{
	xml_node_t *ip, *en;

	if (!(ip = xml_node_create(migrate, NI_CLIENT_IFCONFIG_IPV4)))
		return FALSE;

	if (!(en = xml_node_create(ip, NI_CLIENT_IFCONFIG_IP_ENABLED)))
		return FALSE;

	if (ni_string_eq(en->cdata, "false"))
		return FALSE; /* nothing to migrate */

	return xml_node_set_cdata(en, "false");
}

static ni_bool_t
ni_ifconfig_migrate_l2_port_ipv6(xml_node_t *migrate, ni_bool_t l2v6)
{
	ni_bool_t modified = FALSE;
	xml_node_t *ip, *en, *ra;

	if (!(ip = xml_node_create(migrate, NI_CLIENT_IFCONFIG_IPV6)))
		return FALSE;

	if (!(en = xml_node_create(ip, NI_CLIENT_IFCONFIG_IP_ENABLED)))
		return FALSE;

	if (l2v6) {
		if (!(ra = xml_node_create(ip, "accept-ra")))
			return FALSE;

		if (!ni_string_eq(ra->cdata, "disable")) {
			if (xml_node_set_cdata(ra, "disable"))
				modified = TRUE;
		}
	}
	if (!ni_string_eq(en->cdata, ni_format_boolean(l2v6))) {
		if (xml_node_set_cdata(en, ni_format_boolean(l2v6)))
			modified = TRUE;
	}
	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_bond_port(xml_node_t *migrate,
		const char *bond, const char *port,
		ni_iftype_t type, const xml_node_t *data,
		ni_bool_t l2v6)
{
	const char *ptype = ni_linktype_type_to_name(type);
	const xml_node_t *oconf = NULL;
	const char *otype = NULL;
	xml_node_t *nconf;
	int ret;

	if ((ret = ni_ifconfig_migrate_port_master(migrate, port, ptype, bond)) < 0)
		return FALSE;

	if ((otype = ni_ifconfig_link_get_port_config(migrate, &oconf))) {
		if (ni_string_eq(otype, ptype))
			return ret == 0; /* no bond config to _migrate_ */

		ni_warn("%s: removing mismatching %s port config from %s port '%s'",
				xml_node_location(oconf), otype, ptype, port);
	}
	if ((nconf = ni_ifconfig_create_port_config_node(ptype))) {
		/*
		 * no port specific properties to migrate
		 * from bonding:slave array, queue-id is new
		 */
		(void)data;

		if (!ni_ifconfig_link_set_port_config(migrate, nconf))
			xml_node_free(nconf);
		else
			ret = 0;
	}

	if (ni_ifconfig_migrate_l2_port_ipv4(migrate))
		ret = 0;

	if (ni_ifconfig_migrate_l2_port_ipv6(migrate, l2v6))
		ret = 0;

	return ret == 0;
}

static ni_bool_t
ni_ifconfig_migrate_team_port(xml_node_t *migrate,
		const char *team, const char *port,
		ni_iftype_t type, const xml_node_t *data,
		ni_bool_t l2v6)
{
	const char *ptype = ni_linktype_type_to_name(type);
	const xml_node_t *oconf = NULL;
	const char *otype = NULL;
	xml_node_t *nconf;
	int ret;

	if ((ret = ni_ifconfig_migrate_port_master(migrate, port, ptype, team)) < 0)
		return FALSE;

	if ((otype = ni_ifconfig_link_get_port_config(migrate, &oconf))) {
		if (ni_string_eq(otype, ptype))
			return ret == 0; /* no port config to _migrate_ */

		ni_warn("%s: removing mismatching %s port config from %s port '%s'",
				xml_node_location(oconf), otype, ptype, port);
	}
	if ((nconf = ni_ifconfig_create_port_config_node(ptype))) {
		xml_node_t *node;

		if ((node = xml_node_get_child(data, "queue_id")))
			xml_node_reparent(nconf, node);
		if ((node = xml_node_get_child(data, "prio")))
			xml_node_reparent(nconf, node);
		if ((node = xml_node_get_child(data, "sticky")))
			xml_node_reparent(nconf, node);
		if ((node = xml_node_get_child(data, "lacp_key")))
			xml_node_reparent(nconf, node);
		if ((node = xml_node_get_child(data, "lacp_prio")))
			xml_node_reparent(nconf, node);

		if (!ni_ifconfig_link_set_port_config(migrate, nconf))
			xml_node_free(nconf);
		else
			ret = 0;
	}

	if (ni_ifconfig_migrate_l2_port_ipv4(migrate))
		ret = 0;

	if (ni_ifconfig_migrate_l2_port_ipv6(migrate, l2v6))
		ret = 0;

	return ret == 0;
}

static ni_bool_t
ni_ifconfig_migrate_bridge_port(xml_node_t *migrate,
		const char *bridge, const char *port,
		ni_iftype_t type, const xml_node_t *data,
		ni_bool_t l2v6)
{
	const char *ptype = ni_linktype_type_to_name(type);
	const xml_node_t *oconf = NULL;
	const char *otype = NULL;
	xml_node_t *nconf;
	int ret;

	if ((ret = ni_ifconfig_migrate_port_master(migrate, port, ptype, bridge)) < 0)
		return FALSE;

	if ((otype = ni_ifconfig_link_get_port_config(migrate, &oconf))) {
		if (ni_string_eq(otype, ptype))
			return ret == 0; /* no port config to _migrate_ */

		ni_warn("%s: removing mismatching %s port config from %s port '%s'",
				xml_node_location(oconf), otype, ptype, port);
	}
	if ((nconf = ni_ifconfig_create_port_config_node(ptype))) {
		xml_node_t *node;

		if ((node = xml_node_get_child(data, "priority")))
			xml_node_reparent(nconf, node);
		if ((node = xml_node_get_child(data, "path-cost")))
			xml_node_reparent(nconf, node);

		if (!ni_ifconfig_link_set_port_config(migrate, nconf))
			xml_node_free(nconf);
		else
			ret = 0;
	}

	if (ni_ifconfig_migrate_l2_port_ipv4(migrate))
		ret = 0;

	if (ni_ifconfig_migrate_l2_port_ipv6(migrate, l2v6))
		ret = 0;

	return ret == 0;
}

static ni_bool_t
ni_ifconfig_migrate_ovsbr_port(xml_node_t *migrate,
		const char *ovsbr, const char *port,
		ni_iftype_t type, const xml_node_t *data,
		ni_bool_t l2v6)
{
	const char *ptype = ni_linktype_type_to_name(type);
	const xml_node_t *oconf = NULL;
	const char *otype = NULL;
	xml_node_t *nconf, *link;
	int ret = 1;

	/*
	 * Hmm... just migrate the port's <link/> node as such -- for ovs,
	 * we replace the ovs-system master with bridge from port config.
	 */
	link = xml_node_get_child(migrate, NI_CLIENT_IFCONFIG_LINK);
	if (ni_ifconfig_migrate_link_port(link))
		ret = 0;

	/*
	 * Now, we set the current ovsbr as master of the port and check
	 * for conflict .. same as with any other (bond,team,...) master.
	 */
	if ((ret = ni_ifconfig_migrate_port_master(migrate, port, ptype, ovsbr)) < 0)
		return FALSE;

	if ((otype = ni_ifconfig_link_get_port_config(migrate, &oconf))) {
		if (ni_string_eq(otype, ptype))
			return ret == 0;

		ni_warn("%s: removing mismatching %s port config from %s port '%s'",
				xml_node_location(oconf), otype, ptype, port);
	}
	if ((nconf = ni_ifconfig_create_port_config_node(ptype))) {
		/*
		 * no port specific properties to migrate
		 * from (old) ovs-bridge:port-device node
		 */
		(void)data;

		/*
		 * The ovs-bridge:port-config was always
		 * in the port node of the port interface
		 * and referring to the ovs bridge.
		 */
		if (!ni_ifconfig_link_set_port_config(migrate, nconf))
			xml_node_free(nconf);
		else
			ret = 0;
	}

	if (ni_ifconfig_migrate_l2_port_ipv4(migrate))
		ret = 0;

	if (ni_ifconfig_migrate_l2_port_ipv6(migrate, l2v6))
		ret = 0;

	return ret == 0;
}

static ni_bool_t
ni_ifconfig_migrate_l2_port(xml_node_t *migrate,
		const char *master, const char *port,
		ni_iftype_t type, const xml_node_t *data,
		ni_bool_t l2v6)
{
	ni_bool_t modified;

	switch (type) {
	case NI_IFTYPE_BOND:
		modified = ni_ifconfig_migrate_bond_port(migrate,
				master, port, type, data, l2v6);
		break;
	case NI_IFTYPE_TEAM:
		modified = ni_ifconfig_migrate_team_port(migrate,
				master, port, type, data, l2v6);
		break;
	case NI_IFTYPE_BRIDGE:
		modified = ni_ifconfig_migrate_bridge_port(migrate,
				master, port, type, data, l2v6);
		break;
	case NI_IFTYPE_OVS_BRIDGE:
		modified = ni_ifconfig_migrate_ovsbr_port(migrate,
				master, port, type, data, l2v6);
		break;
	default:
		modified = FALSE;
		break;
	}
	if (modified)
		ni_ifxml_node_set_migrated(migrate, TRUE);
	return modified;
}

static ni_bool_t
ni_ifconfig_create_l2_port(xml_document_array_t *docs,
		const char *master, const char *port,
		ni_iftype_t type, const xml_node_t *data,
		const char *origin, const char *owner,
		ni_bool_t l2v6)
{
	xml_document_t *doc;
	xml_node_t *config;

	if (!(config = ni_ifconfig_create(port, origin, owner)))
		goto failure;

	if (!ni_ifconfig_control_set_mode(config, "hotplug"))
		goto failure;

	if (!ni_ifconfig_migrate_l2_port(config, master, port, type, data, l2v6))
		goto failure;

	if (!ni_ifxml_node_set_migrated(config, TRUE))
		goto failure;

	if (!(doc = xml_document_create(NULL, config)))
		goto failure;

	config = NULL;

	if (!xml_document_array_append(docs, doc)) {
		xml_document_free(doc);
		goto failure;
	}

	ni_warn("generated missing config for port '%s' referenced by %s '%s' (%s)",
			port, ni_linktype_type_to_name(type), master,
			xml_node_location(data));
	return TRUE;

failure:
	ni_error("failed to generate missing config for port '%s' referenced by %s '%s' (%s)",
			port, ni_linktype_type_to_name(type), master, xml_node_location(data));
	xml_node_free(config);
	return FALSE;
}

static ni_bool_t
ni_ifpolicy_create_l2_port(xml_document_array_t *docs,
		const char *master, const char *port,
		ni_iftype_t type, const xml_node_t *data,
		const char *origin, const char *owner,
		ni_bool_t l2v6)
{
	xml_node_t *policy = NULL;
	xml_node_t *config = NULL;
	xml_document_t *doc;

	if (!(policy = ni_ifpolicy_create(port, origin, owner, &config)))
		goto failure;

	if (!ni_ifpolicy_add_match_device_ref(policy, master))
		goto failure;

	if (!ni_ifconfig_control_set_mode(config, "hotplug"))
		goto failure;

	if (!ni_ifconfig_migrate_l2_port(config, master, port, type, data, l2v6))
		goto failure;

	if (!ni_ifxml_node_set_migrated(policy, TRUE))
		goto failure;

	if (!(doc = xml_document_create(NULL, policy)))
		goto failure;

	policy = NULL;

	if (!xml_document_array_append(docs, doc)) {
		xml_document_free(doc);
		goto failure;
	}

	ni_warn("generated missing policy for port '%s' referenced by %s '%s' (%s)",
			port, ni_linktype_type_to_name(type), master,
			xml_node_location(data));
	return TRUE;

failure:
	ni_error("failed to generate missing policy for port '%s' referenced by %s '%s' (%s)",
			port, ni_linktype_type_to_name(type), master, xml_node_location(data));
	xml_node_free(policy);
	return FALSE;
}

static ni_bool_t
ni_ifxml_migrate_l2_port(xml_document_array_t *docs,
		const char *master, const char *port,
		ni_iftype_t type, const xml_node_t *data,
		const char *origin, const char *owner,
		ni_bool_t l2v6, ni_bool_t policy)
{
	ni_bool_t modified = FALSE;
	xml_node_t *config;

	if ((config = ni_ifxml_find_config_by_ifname(docs, port))) {
		if (ni_ifconfig_migrate_l2_port(config, master, port, type, data, l2v6))
			modified = TRUE;
		if (ni_ifpolicy_add_match_device_ref(config->parent, master))
			modified = TRUE;
	} else if (policy) {
		if (ni_ifpolicy_create_l2_port(docs, master, port, type, data, origin, owner, l2v6))
			modified = TRUE;
	} else {
		if (ni_ifconfig_create_l2_port(docs, master, port, type, data, origin, owner, l2v6))
			modified = TRUE;
	}

	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_bond_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	ni_bool_t   modified = FALSE;
	xml_node_t *ports, *port;
	xml_node_t *policy;
	xml_node_t *device;
	const char *primary = NULL;
	const char *origin;
	const char *owner;
	const char *bond;

	if (!(ports = xml_node_get_child(migrate, "slaves")))
		return modified;

	if (!(bond = ni_ifconfig_get_ifname(config)))
		return modified;

	policy = ni_ifxml_is_config(config) ? NULL : config->parent;
	origin = ni_ifpolicy_get_origin(policy ?: config);
	owner = ni_ifpolicy_get_owner(policy ?: config);

	for (port = ports->children; port; port = port->next) {
		if (!ni_string_eq("slave", port->name))
			continue;

		if (!(device = xml_node_get_child(port, "device")))
			continue;

		if (xml_node_get_attr(device, "namespace") ||
		    ni_string_empty(device->cdata))
			continue;

		if (!primary) {
			ni_bool_t enabled;
			const char *ptr;

			ptr = xml_node_get_child_cdata(port, "primary");
			if (ni_parse_boolean(ptr, &enabled) == 0 && enabled)
				primary = device->cdata;
		}

		if (ni_ifxml_migrate_l2_port(docs,
				bond, device->cdata,
				NI_IFTYPE_BOND, NULL,
				origin, owner, FALSE, !!policy))
			modified = TRUE;

		if (ni_ifpolicy_match_remove_child_ref(policy, device->cdata))
			modified = TRUE;
	}

	if (primary && !xml_node_get_child_cdata(migrate, "primary")) {
		if (xml_node_new_element("primary", migrate, primary))
			modified = TRUE;
	}

	if (ports && xml_node_delete_child_node(migrate, ports))
		modified = TRUE;

	return modified;
}

static ni_bool_t
ni_ifconfig_team_l2v6(const xml_node_t *team)
{
	const xml_node_t *link_watch, *watch;

	if (!team || !(link_watch = xml_node_get_child(team, "link_watch")))
		return FALSE;

	for (watch = link_watch->children; watch; watch = watch->next) {
		if (xml_node_get_attr(watch, "nsna_ping"))
			return TRUE;
	}

	return FALSE;
}

static ni_bool_t
ni_ifconfig_migrate_team_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	ni_bool_t   modified = FALSE;
	xml_node_t *ports, *port;
	xml_node_t *policy;
	xml_node_t *device;
	const char *origin;
	const char *owner;
	const char *team;
	ni_bool_t   l2v6;

	if (!(ports = xml_node_get_child(migrate, "ports")))
		return modified;

	if (!(team = ni_ifconfig_get_ifname(config)))
		return modified;

	policy = ni_ifxml_is_config(config) ? NULL : config->parent;
	origin = ni_ifpolicy_get_origin(policy ?: config);
	owner = ni_ifpolicy_get_owner(policy ?: config);

	l2v6 = ni_ifconfig_team_l2v6(migrate);
	for (port = ports->children; port; port = port->next) {
		if (!ni_string_eq("port", port->name))
			continue;

		if (!(device = xml_node_get_child(port, "device")))
			continue;

		if (xml_node_get_attr(device, "namespace") ||
		    ni_string_empty(device->cdata))
			continue;

		if (ni_ifxml_migrate_l2_port(docs,
				team, device->cdata,
				NI_IFTYPE_TEAM, port,
				origin, owner, l2v6, !!policy))
			modified = TRUE;

		if (ni_ifpolicy_match_remove_child_ref(policy, device->cdata))
			modified = TRUE;
	}

	if (ports && xml_node_delete_child_node(migrate, ports))
		modified = TRUE;

	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_bridge_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	ni_bool_t   modified = FALSE;
	xml_node_t *ports, *port;
	xml_node_t *policy;
	xml_node_t *device;
	const char *origin;
	const char *owner;
	const char *bridge;

	if (!(ports = xml_node_get_child(migrate, "ports")))
		return modified;

	if (!(bridge = ni_ifconfig_get_ifname(config)))
		return modified;

	policy = ni_ifxml_is_config(config) ? NULL : config->parent;
	origin = ni_ifpolicy_get_origin(policy ?: config);
	owner = ni_ifpolicy_get_owner(policy ?: config);

	for (port = ports->children; port; port = port->next) {
		if (!ni_string_eq("port", port->name))
			continue;

		if (!(device = xml_node_get_child(port, "device")))
			continue;

		if (xml_node_get_attr(device, "namespace") ||
		    ni_string_empty(device->cdata))
			continue;

		if (ni_ifxml_migrate_l2_port(docs,
				bridge, device->cdata,
				NI_IFTYPE_BRIDGE, port,
				origin, owner, FALSE, !!policy))
			modified = TRUE;

		if (ni_ifpolicy_match_remove_child_ref(policy, device->cdata))
			modified = TRUE;
	}

	if (ports && xml_node_delete_child_node(migrate, ports))
		modified = TRUE;

	return modified;
}

static ni_bool_t
ni_ifpolicy_migrate_ovsbr_vlan(xml_node_t *policy, xml_node_t *migrate)
{
	ni_bool_t   modified = FALSE;
	xml_node_t *vlan, *parent;

	if (!(vlan = xml_node_get_child(migrate, "vlan")))
		return modified;

	if (!(parent = xml_node_get_child(vlan, "parent")))
		return modified;

	if (xml_node_get_attr(parent, "namespace"))
		return modified;

	if (ni_ifpolicy_match_remove_child_ref(policy, parent->cdata))
		modified = TRUE;

	if (ni_ifpolicy_add_match_device_ref(policy, parent->cdata))
		modified = TRUE;

	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_ovsbr_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	ni_bool_t   modified = FALSE;
	xml_node_t *ports, *port;
	xml_node_t *policy;
	xml_node_t *device;
	const char *origin;
	const char *owner;
	const char *ovsbr;

	policy = ni_ifxml_is_config(config) ? NULL : config->parent;
	origin = ni_ifpolicy_get_origin(policy ?: config);
	owner = ni_ifpolicy_get_owner(policy ?: config);

	if (ni_ifpolicy_migrate_ovsbr_vlan(policy, migrate))
		modified = TRUE;

	if (!(ports = xml_node_get_child(migrate, "ports")))
		return modified;

	if (!(ovsbr = ni_ifconfig_get_ifname(config)))
		return modified;

	for (port = ports->children; port; port = port->next) {
		if (!ni_string_eq("port", port->name))
			continue;

		if (!(device = xml_node_get_child(port, "device")))
			continue;

		if (xml_node_get_attr(device, "namespace") ||
		    ni_string_empty(device->cdata))
			continue;

		if (ni_ifxml_migrate_l2_port(docs,
				ovsbr, device->cdata,
				NI_IFTYPE_OVS_BRIDGE, port,
				origin, owner, FALSE, !!policy))
			modified = TRUE;

		if (ni_ifpolicy_match_remove_child_ref(policy, device->cdata))
			modified = TRUE;
	}

	if (ports && xml_node_delete_child_node(migrate, ports))
		modified = TRUE;

	return modified;
}

static ni_bool_t
ni_ifxml_add_missing_lower(xml_document_array_t *docs,
		const xml_node_t *from, const char *iftype,
		const char *lower, const char *upper,
		const char *startmode, const char *origin,
		const char *owner, ni_bool_t policy)
{
	xml_document_t *doc = NULL;
	xml_node_t *config = NULL;

	if (!lower || !upper)
		return FALSE;

	if ((config = ni_ifxml_find_config_by_ifname(docs, lower)))
		return FALSE;

	if (policy) {
		xml_node_t *root;

		if (!(root = ni_ifpolicy_create(lower, origin, owner, &config)))
			goto failure;

		if (!config || !(doc = xml_document_create(NULL, root))) {
			xml_node_free(root);
			goto failure;
		}
	} else {
		if (!(config = ni_ifconfig_create(lower, origin, owner)))
			goto failure;

		if (!(doc = xml_document_create(NULL, config))) {
			xml_node_free(config);
			goto failure;
		}
	}

	if (!ni_ifxml_node_set_migrated(doc->root, TRUE))
		goto failure;

	if (!ni_ifconfig_control_set_mode(config, startmode ?: "hotplug"))
		goto failure;

	if (!xml_document_array_append(docs, doc))
		goto failure;

	ni_warn("generated missing %s for '%s' referenced by %s '%s' (%s)",
			policy ? "policy" : "config", lower, iftype, upper,
			xml_node_location(from));
	return TRUE;

failure:
	xml_document_free(doc);
	ni_error("failed to generate missing %s for '%s' referenced by %s in '%s' (%s)",
			policy ? "policy" : "config", lower, iftype, upper,
			xml_node_location(from));

	return FALSE;
}

static ni_bool_t
ni_ifxml_migrate_lower_device(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate,
		const char *ifnode, const char *iftype)
{
	ni_bool_t modified = FALSE;
	xml_node_t *policy;
	xml_node_t *device;
	const char *ifname;
	const char *origin;
	const char *lower;
	const char *index;
	const char *owner;
	const char *mode;

	device = xml_node_get_child(migrate, ifnode);
	index = NULL;
	if (!(lower = ni_ifxml_resolve_ifname_node(docs, device, &index)))
		return modified;

	policy = ni_ifxml_is_config(config) ? NULL : config->parent;
	if (ni_ifpolicy_match_remove_child_ref(policy, lower))
		modified = TRUE;

	if (ni_ifpolicy_add_match_device_ref(policy, lower))
		modified = TRUE;

	/*
	 * When ni_ifxml_resolve_ifname_node provides an index,
	 * there already is a lower config (using lower index),
	 * thus do not try to create one (using lower ifname).
	 */
	if (index)
		return modified;

	/*
	 * Creating missing lower link config/policy does not
	 * modify and set migrated mark on this config/policy,
	 * but creates a missing config for the lower (which
	 * is marked migrated itself).
	 */
	ifname = ni_ifconfig_get_ifname(config);
	origin = ni_ifconfig_get_origin(policy ?: config);
	owner  = ni_ifpolicy_get_owner(policy ?: config);
	mode   = ni_ifconfig_control_get_mode(config);

	ni_ifxml_add_missing_lower(docs, migrate, iftype, lower,
			ifname, mode, origin, owner, !!policy);

	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_ibchild_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_macvlan_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_macvtap_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_ipvlan_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_ipvtap_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_vxlan_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_vlan_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_ipip_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_sit_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_gre_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_tun_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_tap_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	return ni_ifxml_migrate_lower_device(docs, config, migrate, "device", migrate->name);
}

static ni_bool_t
ni_ifconfig_migrate_ppp_node(xml_document_array_t *docs,
		xml_node_t *config, xml_node_t *migrate)
{
	ni_bool_t   modified = FALSE;
	xml_node_t *mode;
	const char *name;

	mode = xml_node_get_child(migrate, "mode");
	name = xml_node_get_attr(mode, "name");
	if (ni_string_eq(name, "pppoe")) {
		if (ni_ifxml_migrate_lower_device(docs, config, mode, "device", name))
			modified = TRUE;
	}

	return modified;
}

static ni_bool_t
ni_ifconfig_migrate_node(xml_document_array_t *docs,
		ni_bool_t (*func)(xml_document_array_t *,
				xml_node_t *, xml_node_t *),
		const char *name, xml_node_t *config)
{
	xml_node_t *node;

	if (!(node = xml_node_get_child(config, name)))
		return FALSE;

	if (!func(docs, config, node))
		return FALSE;

	ni_ifxml_node_set_migrated(config, TRUE);
	return TRUE;
}

static ni_bool_t
ni_ifpolicy_migrate_node(xml_document_array_t *docs,
		ni_bool_t (*func)(xml_document_array_t *,
				xml_node_t *, xml_node_t *),
		const char *name, xml_node_t *policy)
{
	ni_bool_t modified = FALSE;
	xml_node_t *config = NULL;

	/* policy action contains the effective ifconfig data */
	if ((config = xml_node_get_child(policy, NI_NANNY_IFPOLICY_MERGE))) {
		if (ni_ifconfig_migrate_node(docs, func, name, config))
			modified = TRUE;
	}
	if ((config = xml_node_get_child(policy, NI_NANNY_IFPOLICY_REPLACE))) {
		if (ni_ifconfig_migrate_node(docs, func, name, config))
			modified = TRUE;
	}
	if ((config = xml_node_get_child(policy, NI_NANNY_IFPOLICY_CREATE))) {
		if (ni_ifconfig_migrate_node(docs, func, name, config))
			modified = TRUE;
	}

	return modified;
}

static ni_bool_t
ni_ifxml_migrate_ifconfig_node(xml_document_array_t *docs, const char *name,
	ni_bool_t (*func)(xml_document_array_t *, xml_node_t *, xml_node_t *))
{
	ni_bool_t modified = FALSE;
	xml_document_t *doc;
	xml_node_t *root;
	unsigned int i;

	for (i = 0; i < docs->count; ++i) {
		doc = docs->data[i];
		root = xml_document_root(doc);

		if (ni_ifxml_is_config(root)) {
			if (ni_ifconfig_migrate_node(docs, func, name, root))
				modified = TRUE;
			continue;
		}

		if (ni_ifxml_is_policy(root)) {
			if (ni_ifpolicy_migrate_node(docs, func, name, root))
				modified = TRUE;
			continue;
		}
	}

	return modified;
}

static ni_bool_t
ni_ifxml_migrate_nodes(xml_document_array_t *docs)
{
	struct migrate_node {
		const char *name;
		ni_bool_t (*func)(xml_document_array_t *, xml_node_t *, xml_node_t *);
	} *migrate, map[] = {
		{ "ethernet",		ni_ifconfig_migrate_ethernet_node	},
		{ "wireless",		ni_ifconfig_migrate_wireless_node	},
		{ "link",		ni_ifconfig_migrate_link_node		},
		{ "bond",		ni_ifconfig_migrate_bond_node		},
		{ "team",		ni_ifconfig_migrate_team_node		},
		{ "bridge",		ni_ifconfig_migrate_bridge_node		},
		{ "ovs-bridge",		ni_ifconfig_migrate_ovsbr_node		},
		{ "infiniband-child",	ni_ifconfig_migrate_ibchild_node	},
		{ "macvlan",		ni_ifconfig_migrate_macvlan_node	},
		{ "macvtap",		ni_ifconfig_migrate_macvtap_node	},
		{ "ipvlan",		ni_ifconfig_migrate_ipvlan_node		},
		{ "ipvtap",		ni_ifconfig_migrate_ipvtap_node		},
		{ "vxlan",		ni_ifconfig_migrate_vxlan_node		},
		{ "vlan",		ni_ifconfig_migrate_vlan_node		},
		{ "ipip",		ni_ifconfig_migrate_ipip_node		},
		{ "sit",		ni_ifconfig_migrate_sit_node		},
		{ "gre",		ni_ifconfig_migrate_gre_node		},
		{ "tun",		ni_ifconfig_migrate_tun_node		},
		{ "tap",		ni_ifconfig_migrate_tap_node		},
		{ "ppp",		ni_ifconfig_migrate_ppp_node		},

		{ NULL }
	};
	ni_bool_t modified = FALSE;

	for (migrate = map; migrate->name && migrate->func; ++migrate) {
		if (ni_ifxml_migrate_ifconfig_node(docs,
				migrate->name, migrate->func))
			modified = TRUE;
	}

	return modified;
}

ni_bool_t
ni_ifxml_migrate_docs(xml_document_array_t *docs)
{
	ni_bool_t modified = FALSE;
	xml_document_t *doc;
	xml_node_t *root;
	ni_uuid_t uuid;
	unsigned int i;

	modified = ni_ifxml_migrate_nodes(docs);
	for (i = 0; i < docs->count; ++i) {
		doc = docs->data[i];
		root = xml_document_root(doc);

		if (!ni_ifxml_node_is_migrated(root))
			continue;

		/* calculate and update checksum uuid */
		ni_ifconfig_generate_uuid(root, &uuid);
		ni_ifpolicy_set_uuid(root, &uuid);
	}

	return modified;
}
