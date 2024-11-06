/*
 *	wicked client configuration reading.
 *	Currently supported are following configuration schemes:
 *		wicked:
 *		compat:
 *		firmware:
 *		dracut:
 *	along their associated sub-types.
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
 *		Olaf Kirch <okir@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/netinfo.h>

#include "appconfig.h"
#include "wicked-client.h"
#include "client/ifconfig.h"
#include "client/read-config.h"
#include "dracut/dracut.h"
#include "firmware.h"

#if defined(COMPAT_AUTO) || defined(COMPAT_SUSE)
extern ni_bool_t	__ni_suse_get_ifconfig(const char *, const char *,
						ni_compat_ifconfig_t *);
#endif
#if defined(COMPAT_AUTO) || defined(COMPAT_REDHAT)
extern ni_bool_t	__ni_redhat_get_ifconfig(const char *, const char *,
						ni_compat_ifconfig_t *);
#endif

static ni_bool_t	ni_ifconfig_read_wicked(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_ifconfig_kind_t,
						ni_bool_t,
						ni_bool_t);
static ni_bool_t	ni_ifconfig_read_wicked_xml(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_ifconfig_kind_t,
						ni_bool_t,
						ni_bool_t);
static ni_bool_t	ni_ifconfig_read_compat(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_ifconfig_kind_t,
						ni_bool_t,
						ni_bool_t);
#if defined(COMPAT_AUTO) || defined(COMPAT_SUSE)
static ni_bool_t	ni_ifconfig_read_compat_suse(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_ifconfig_kind_t,
						ni_bool_t,
						ni_bool_t);
#endif
#if defined(COMPAT_AUTO) || defined(COMPAT_REDHAT)
static ni_bool_t	ni_ifconfig_read_compat_redhat(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_ifconfig_kind_t,
						ni_bool_t,
						ni_bool_t);
#endif
static ni_bool_t	ni_ifconfig_read_firmware(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_ifconfig_kind_t,
						ni_bool_t,
						ni_bool_t);

const ni_ifconfig_type_t *
ni_ifconfig_find_map(const ni_ifconfig_type_t *map, const char *name, size_t len)
{
	const ni_ifconfig_type_t *pos = map;

	if (pos) {
		while (pos->name) {
			if (name && strlen(pos->name) == len &&
			    strncasecmp(pos->name, name, len) == 0)
				break;
			++pos;
		}
	}
	return pos;
}

const ni_ifconfig_type_t *
ni_ifconfig_find_type(const ni_ifconfig_type_t *map, const char *root,
			const char *path, const char *name, size_t len)
{
	const ni_ifconfig_type_t *ret;

	ret = ni_ifconfig_find_map(map, name, len);

	if (!name && ret && ret->ops.guess) {
		ret = ret->ops.guess(map, root, path);
	}
	return ret;
}

ni_bool_t
ni_ifconfig_read_subtype(xml_document_array_t *array, const ni_ifconfig_type_t *type,
			const char *root, const char *path, ni_ifconfig_kind_t kind,
			ni_bool_t prio, ni_bool_t raw, const char *supertype)
{
	const ni_ifconfig_type_t *map;
	const char *sub_path = path;
	const char *sub_name = NULL;
	char *sub_type = NULL;
	ni_bool_t ret = FALSE;
	size_t len;

	if (!array || !type)
		return ret;

	len = strcspn(path, ":");
	if (path[len] == ':') {
		sub_name = len ? path : NULL;
		sub_path = path + len + 1;
	}

	map = ni_ifconfig_find_type(type, root, path, sub_name, len);
	if (map && map->name && map->ops.read) {
		ni_string_printf(&sub_type, "%s:%s", supertype, map->name);
		ret = map->ops.read(array, sub_type, root, sub_path, kind, prio, raw);
		ni_string_free(&sub_type);
	} else {
		ni_error("Unsupported ifconfig type %s:%.*s", supertype, (int)len, sub_name);
	}
	return ret;
}

const ni_ifconfig_type_t *
ni_ifconfig_guess_compat_type(const ni_ifconfig_type_t *map,
				const char *root, const char *path)
{
	(void)path;

#ifdef COMPAT_SUSE
	return ni_ifconfig_find_map(map, "suse", sizeof("suse")-1);
#endif
#ifdef COMPAT_REDHAT
	return ni_ifconfig_find_map(map, "redhat", sizeof("redhat")-1);
#endif
#ifdef COMPAT_AUTO
	if (ni_file_exists_fmt("%s%s", (root ? root : ""), "/etc/SuSE-release") ||
	    ni_file_exists_fmt("%s%s", (root ? root : ""), "/etc/SUSE-brand"))
		return ni_ifconfig_find_map(map, "suse", sizeof("suse")-1);

	if (ni_file_exists_fmt("%s%s", (root ? root : ""), "/etc/redhat-release"))
		return ni_ifconfig_find_map(map, "redhat", sizeof("redhat")-1);
#endif

	return NULL;
}

static inline ni_ifconfig_kind_t
ni_ifconfig_kind_guess(ni_ifconfig_kind_t kind)
{
	switch (kind) {
	case NI_IFCONFIG_KIND_POLICY:
	case NI_IFCONFIG_KIND_CONFIG:
		return kind;

	case NI_IFCONFIG_KIND_DEFAULT:
	default:
		return NI_IFCONFIG_KIND_POLICY;
	}
}

static const ni_intmap_t	ni_ifconfig_kind_map[] = {
	{ "policy",		NI_IFCONFIG_KIND_POLICY		},
	{ "config",		NI_IFCONFIG_KIND_CONFIG		},
	{ NULL,			NI_IFCONFIG_KIND_DEFAULT	}
};

const char *
ni_ifconfig_kind_to_name(ni_ifconfig_kind_t kind)
{
	return ni_format_uint_mapped(kind, ni_ifconfig_kind_map);
}

ni_bool_t
ni_ifconfig_kind_by_name(const char *name, ni_ifconfig_kind_t *kind)
{
	unsigned int type;

	if (!kind || ni_parse_uint_mapped(name, ni_ifconfig_kind_map, &type) < 0)
		return FALSE;

	*kind = type;
	return TRUE;
}

const ni_ifconfig_type_t *
ni_ifconfig_guess_wicked_type(const ni_ifconfig_type_t *map,
			const char *root, const char *path)
{
	return ni_ifconfig_find_map(map, "xml", sizeof("xml")-1);
}

const ni_ifconfig_type_t *
ni_ifconfig_guess_type(const ni_ifconfig_type_t *map,
			const char *root, const char *path)
{
	return ni_ifconfig_find_map(map, "wicked", sizeof("wicked")-1);
}

static const ni_ifconfig_type_t		ni_ifconfig_types_wicked[] = {
	{ "xml",	{ .read = ni_ifconfig_read_wicked_xml	} },
	{ NULL,		{ .guess= ni_ifconfig_guess_wicked_type	} },
};

static const ni_ifconfig_type_t		ni_ifconfig_types_compat[] = {
#if defined(COMPAT_AUTO) || defined(COMPAT_SUSE)
	{ "suse",	{ .read = ni_ifconfig_read_compat_suse	} },
#endif
#if defined(COMPAT_AUTO) || defined(COMPAT_REDHAT)
	{ "redhat",	{ .read = ni_ifconfig_read_compat_redhat} },
#endif
	{ NULL,		{ .guess= ni_ifconfig_guess_compat_type } },
};

static const ni_ifconfig_type_t		ni_ifconfig_types[] = {
	{ "wicked",	{ .read = ni_ifconfig_read_wicked	} },
	{ "compat",	{ .read = ni_ifconfig_read_compat	} },
	{ "firmware",	{ .read = ni_ifconfig_read_firmware	} },
	{ "dracut",	{ .read = ni_ifconfig_read_dracut	} },
	{ NULL,		{ .guess= ni_ifconfig_guess_type	} },
};

ni_bool_t
ni_ifconfig_load(ni_fsm_t *fsm, const char *root, ni_string_array_t *sources, ni_bool_t check_prio)
{
	xml_document_array_t docs = XML_DOCUMENT_ARRAY_INIT;
	ni_ifconfig_kind_t kind = NI_IFCONFIG_KIND_CONFIG; /* load into fsm */
	unsigned int i;

	for (i = 0; i < sources->count; ++i) {
		const char *source = sources->data[i];

		if (ni_ifconfig_read(&docs, root, source, kind, check_prio, FALSE))
			continue;

		xml_document_array_destroy(&docs);
		return FALSE;
	}

	if (ni_ifxml_migrate_docs(&docs))
		ni_debug_readwrite("Migrated configuration to current schema");

	for (i = 0; i < docs.count; i++) {
		xml_node_t *root;
		const char *origin;

		root = xml_document_root(docs.data[i]);
		origin = ni_ifconfig_get_origin(root);
		/* We do not fail when unable to generate ifworker */
		ni_fsm_workers_from_xml(fsm, root, origin);
	}

	xml_document_array_destroy(&docs);
	return TRUE;
}

ni_bool_t
ni_ifconfig_read(xml_document_array_t *array, const char *root, const char *path, ni_ifconfig_kind_t kind, ni_bool_t check_prio, ni_bool_t raw)
{
	const ni_ifconfig_type_t *map;
	const char *_path = path;
	const char *_name = NULL;
	size_t len;

	len = strcspn(path, ":");
	if (path[len] == ':') {
		_name = len ? path : NULL;
		_path = path + len + 1;
	}

	map = ni_ifconfig_find_type(ni_ifconfig_types, root, path, _name, len);
	if (map && map->name && map->ops.read) {
		return map->ops.read(array, map->name, root, _path, kind, check_prio, raw);
	}

	ni_error("Unsupported ifconfig type %.*s", (int)len, path);
	return FALSE;
}

static ni_config_origin_prio_t
ni_ifconfig_origin_get_prio(const char *origin)
{
	ni_config_origin_prio_t prio;

	if (ni_string_empty(origin))
		return NI_CONFIG_ORIGIN_PRIO_UNKNOWN;

	if (ni_string_startswith(origin, "firmware:"))
		prio = NI_CONFIG_ORIGIN_PRIO_FIRMWARE;
	else if (ni_string_startswith(origin, "compat:"))
		prio = NI_CONFIG_ORIGIN_PRIO_COMPAT;
	else if (ni_string_startswith(origin, "wicked:"))
		prio = NI_CONFIG_ORIGIN_PRIO_WICKED;
	else
		prio = NI_CONFIG_ORIGIN_PRIO_UNKNOWN; /* Currently wicked */

	return prio;
}

/*
 * Parse name node and its namespace from xml config.
 *
 * Return true when interface name is available/can be resolved.
 */
static ni_bool_t
ni_ifconfig_read_get_ifname(xml_node_t *ifnode, char **ifname)
{
	xml_node_t *nnode = NULL;
	const char *namespace;

	if (!ifnode || !ifname)
		return FALSE;

	/* Check for   <name> node */
	nnode = xml_node_get_child(ifnode, "name");
	if (!nnode || ni_string_empty(nnode->cdata)) {
		ni_error("cannot get interface name - "
			"config has no valid <name> node");
		return FALSE;
	}

	/* Resolve a namespace if specified */
	namespace = xml_node_get_attr(nnode, "namespace");
	if (ni_string_empty(namespace)) {
		if (!ni_netdev_name_is_valid(nnode->cdata)) {
			ni_error("invalid interface name node data: '%s'",
					nnode->cdata);
			return FALSE;
		}
		if (!ni_string_dup(ifname, nnode->cdata)) {
			ni_error("unable to allocate interface name: %m");
			return FALSE;
		}
	}
	else if (ni_string_eq(namespace, "ifindex")) {
		unsigned int value;

		if (ni_parse_uint(nnode->cdata, &value, 10) < 0) {
			ni_error("unable to parse ifindex value"
				" specified via <name namespace=\"ifindex\">");
			return FALSE;
		}
		if (!ni_netdev_index_to_name(ifname, value)) {
			ni_error("unable to obtain interface name"
				" using ifindex value %u", value);
			return FALSE;
		}
	}
	else {
		/* TODO: Implement other namespaces */;
		ni_error("unable to resolve interface name from namespace '%s'",
			namespace);
		return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_ifconfig_validate_adding_doc(xml_document_t *config_doc, ni_bool_t check_prio)
{
	static ni_var_array_t validated_cfgs; /* Array of already processed configs */
	ni_config_origin_prio_t src_prio, dst_prio;
	xml_node_t *src_root, *src_child;
	char *ifname = NULL;

	if (!config_doc)
		return FALSE;

	if (!check_prio)
		return TRUE;

	src_root = xml_document_root(config_doc);
	src_prio = ni_ifconfig_origin_get_prio(xml_node_location_filename(src_root));

	if (ni_string_empty(src_root->name))
		src_child = src_root->children;
	else
		src_child = src_root;
	for ( ; src_child; src_child = src_child->next) {
		int rv;

		if (ni_ifconfig_is_policy(src_child)) {
			ni_debug_ifconfig("ignoring validation on policy nodes");
			continue;
		}

		if (!ni_ifconfig_read_get_ifname(src_child, &ifname))
			goto cleanup;

		rv = ni_var_array_get_uint(&validated_cfgs, ifname, &dst_prio);
		if (rv < 0)
			goto cleanup;

		if (rv && dst_prio < src_prio) {
			ni_warn("Ignoring %s config %s because of higher prio config",
				ifname, xml_node_location_filename(src_root));
			goto cleanup;
		}

		ni_var_array_set_uint(&validated_cfgs, ifname, src_prio);
	}

	ni_string_free(&ifname);
	return TRUE;
cleanup:
	ni_string_free(&ifname);
	return FALSE;
}

/*
 * Read ifconfig
 */
static ni_bool_t
ni_ifconfig_read_wicked_xml_file(xml_document_array_t *docs,
			const char *type, const char *root, const char *pathname,
			ni_ifconfig_kind_t kind, ni_bool_t check_prio, ni_bool_t raw)
{
	ni_client_state_config_t conf = NI_CLIENT_STATE_CONFIG_INIT;
	char pathbuf[PATH_MAX] = {'\0'};
	xml_document_t *config_doc;
	xml_node_t *rnode, *cnode, *next;

	if (!ni_string_empty(root)) {
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", root, pathname);
		pathname = pathbuf;
	}

	if (!(config_doc = xml_document_read(pathname))) {
		ni_error("unable to load interface definition from %s", pathname);
		return FALSE;
	}

	/* Modify shared location in the document to use origin */
	rnode = xml_document_root(config_doc);
	ni_ifconfig_format_origin(&conf.origin, type, pathname);
	xml_node_location_modify(rnode, conf.origin);

	/* Move each (interface/policy/template) child node into
	 * a separate document, adjust it's location and add them
	 * to the result array.
	 */
	for (cnode = rnode->children; cnode; cnode = next) {
		xml_document_t *doc;
		xml_node_t *node;

		next = cnode->next;
		doc = xml_document_new();
		node = xml_document_root(doc);

		xml_node_location_set(node, xml_location_clone(cnode->location));
		xml_node_reparent(node, cnode);

		ni_ifconfig_metadata_clear(node);
		if (!raw)
			ni_ifconfig_metadata_add_to_node(node, &conf);

		if (ni_ifconfig_validate_adding_doc(doc, check_prio)) {
			ni_debug_ifconfig("%s: %s", __func__, xml_node_location(node));

			if (xml_document_expand(docs, doc))
				continue;
		}
		xml_document_free(doc);
	}

	ni_client_state_config_reset(&conf);
	xml_document_free(config_doc);

	return TRUE;
}

static ni_bool_t
ni_ifconfig_read_wicked_xml_dir(xml_document_array_t *docs,
			const char *type, const char *root, const char *pathname,
			ni_ifconfig_kind_t kind, ni_bool_t check_prio, ni_bool_t raw)
{
	char pathbuf[PATH_MAX] = {'\0'};
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	unsigned int i;
	ni_bool_t empty = TRUE;

	ni_assert(docs);

	if (!ni_string_empty(root)) {
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", root, pathname);
		pathname = pathbuf;
	}

	if (ni_scandir(pathname, "*.xml", &files) != 0) {
		for (i = 0; i < files.count; ++i) {
			/* Ignore wrong xml config files - warning only */
			if (ni_ifconfig_read_wicked_xml_file(docs, type,
						pathname, files.data[i],
						kind, check_prio, raw))
				empty = FALSE;
		}
	}

	if (empty)
		ni_debug_ifconfig("No valid configuration files found at %s", pathname);

	ni_string_array_destroy(&files);
	return TRUE;
}

ni_bool_t
ni_ifconfig_read_wicked_xml(xml_document_array_t *array,
			const char *type, const char *root, const char *path,
			ni_ifconfig_kind_t kind, ni_bool_t check_prio, ni_bool_t raw)
{
	char *ifconfig_dir = NULL;
	char pathbuf[PATH_MAX];
	ni_bool_t rv = FALSE;

	if (ni_string_empty(path)) {
		ni_string_printf(&ifconfig_dir, "%s/%s", ni_get_global_config_dir(), "ifconfig");
		path = ifconfig_dir;
		rv = TRUE; /* do not fail if default path does not exist */
	}

	if (ni_string_empty(root)) {
		snprintf(pathbuf, sizeof(pathbuf), "%s", path);
	} else {
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", root, path);
	}

	/* At the moment only XML is supported */
	if (ni_isreg(pathbuf))
		rv = ni_ifconfig_read_wicked_xml_file(array, type, root, path, kind, check_prio, raw);
	else if (ni_isdir(pathbuf))
		rv = ni_ifconfig_read_wicked_xml_dir(array, type, root, path, kind, check_prio, raw);

	ni_string_free(&ifconfig_dir);
	return rv;
}

ni_bool_t
ni_ifconfig_read_wicked(xml_document_array_t *array,
			const char *type, const char *root, const char *path,
			ni_ifconfig_kind_t kind, ni_bool_t prio, ni_bool_t raw)
{
	return ni_ifconfig_read_subtype(array, ni_ifconfig_types_wicked, root, path, kind, prio, raw, type);
}

/*
 * Read old-style ifcfg file(s)
 */
#if defined(COMPAT_AUTO) || defined(COMPAT_SUSE)
ni_bool_t
ni_ifconfig_read_compat_suse(xml_document_array_t *array,
			const char *type, const char *root, const char *path,
			ni_ifconfig_kind_t kind, ni_bool_t check_prio, ni_bool_t raw)
{
	ni_compat_ifconfig_t conf;
	ni_bool_t rv;

	ni_compat_ifconfig_init(&conf, type);

	/* TODO: apply timeout */
	if ((rv = __ni_suse_get_ifconfig(root, path, &conf))) {
#if 0
		/* TODO:
		 * we currently convert config to policy later
		 */
		kind = ni_ifconfig_kind_guess(kind);
#endif
		if (kind == NI_IFCONFIG_KIND_POLICY)
			ni_compat_generate_policies(array, &conf, check_prio, raw);
		else
			ni_compat_generate_interfaces(array, &conf, check_prio, raw);
	}
	ni_compat_ifconfig_destroy(&conf);
	return rv;
}
#endif

#if defined(COMPAT_AUTO) || defined(COMPAT_REDHAT)
ni_bool_t
ni_ifconfig_read_compat_redhat(xml_document_array_t *array,
			const char *type, const char *root, const char *path,
			ni_ifconfig_kind_t kind, ni_bool_t check_prio, ni_bool_t raw)
{
	ni_compat_ifconfig_t conf;
	ni_bool_t rv;

	ni_compat_ifconfig_init(&conf, type);
	if ((rv = __ni_redhat_get_ifconfig(root, path, &conf))) {
#if 0
		/* TODO:
		 * we currently convert config to policy later
		 */
		kind = ni_ifconfig_kind_guess(kind);
#endif
		if (kind == NI_IFCONFIG_KIND_POLICY)
			ni_compat_generate_policies(array, &conf, check_prio, raw);
		else
			ni_compat_generate_interfaces(array, &conf, check_prio, raw);
	}

	ni_compat_ifconfig_destroy(&conf);
	return rv;
}
#endif

ni_bool_t
ni_ifconfig_read_compat(xml_document_array_t *array,
			const char *type, const char *root, const char *path,
			ni_ifconfig_kind_t kind, ni_bool_t check_prio, ni_bool_t raw)
{
	return ni_ifconfig_read_subtype(array, ni_ifconfig_types_compat, root, path, kind, check_prio, raw, type);
}

ni_bool_t
ni_ifconfig_read_firmware(xml_document_array_t *array,
			const char *type, const char *root, const char *path,
			ni_ifconfig_kind_t kind, ni_bool_t check_prio, ni_bool_t raw)
{
	ni_client_state_config_t conf = NI_CLIENT_STATE_CONFIG_INIT;
	xml_document_array_t docs = XML_DOCUMENT_ARRAY_INIT;
	xml_node_t *rnode, *cnode, *next;
	unsigned int i;

	if (!ni_netif_firmware_discover_ifconfig(&docs, type, root, path)) {
		ni_error("unable to get firmware interface definitions from %s:%s",
				type, path);
		return FALSE;
	}

	/*
	 * Firmware is expected to provide a more exact origin
	 * than we can set here, just read it from the nodes.
	 */
	for (i = 0; i < docs.count; ++i) {
		xml_document_t *doc = docs.data[i];

		if (xml_document_is_empty(doc))
			continue;

		rnode = xml_document_root(doc);
		for (cnode = rnode->children; cnode; cnode = next) {
			xml_document_t *config;
			xml_node_t *node;

			next = cnode->next;
			if (!(config = xml_document_new()))
				continue;
			node = xml_document_root(config);

			if (!ni_ifconfig_metadata_get_from_node(&conf, rnode))
				ni_ifconfig_format_origin(&conf.origin, type, path);

			xml_node_reparent(node, cnode);
			xml_node_location_relocate(node, conf.origin);

			ni_ifconfig_metadata_clear(node);
			if (!raw)
				ni_ifconfig_metadata_add_to_node(node, &conf);

			if (ni_ifconfig_validate_adding_doc(config, check_prio)) {
				ni_debug_ifconfig("%s: %s", __func__, xml_node_location(node));
				if (xml_document_expand(array, config))
					continue;
			}
			xml_document_free(config);
		}
	}

	ni_client_state_config_reset(&conf);
	xml_document_array_destroy(&docs);

	return TRUE;
}

const char *
ni_ifconfig_format_origin(char **origin, const char *schema, const char *path)
{
	ni_string_printf(origin, "%s%s%s", (schema ? schema : ""),
			(schema ? ":" : ""), (path ? path : ""));

	if (ni_string_empty(*origin))
		ni_string_free(origin);

	return *origin;
}

void
ni_ifconfig_metadata_add_to_node(xml_node_t *root, ni_client_state_config_t *conf)
{
	xml_node_t *ifnode = NULL;

	if (!root || !root->children || !conf || ni_string_empty(conf->origin))
		return;

	if (ni_string_empty(root->name))
		ifnode = root->children;
	else
		ifnode = root;
	for ( ; ifnode; ifnode = ifnode->next) {
		xml_node_add_attr(ifnode,
				NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE,
					conf->origin);

		if (!ni_uuid_is_null(&conf->uuid)) {
			xml_node_add_attr(ifnode,
				NI_CLIENT_STATE_XML_CONFIG_UUID_NODE,
					ni_uuid_print(&conf->uuid));
		}
		if (conf->owner != -1U) {
			xml_node_add_attr_uint(ifnode,
				NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE,
					conf->owner);
		}
	}
}

ni_bool_t
ni_ifconfig_metadata_get_from_node(ni_client_state_config_t *conf, xml_node_t *root)
{
	xml_node_t *ifnode = NULL;

	if (!root || !root->children || !conf)
		return FALSE;

	ni_client_state_config_reset(conf);
	if (ni_string_empty(root->name))
		ifnode = root->children;
	else
		ifnode = root;
	for ( ; ifnode; ifnode = ifnode->next) {
		/* only first   node with proper meta data attributes is processed */
		const char *origin;
		const char *str;
		ni_uuid_t uuid;

		origin = xml_node_get_attr(ifnode, NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE);
		if (ni_string_empty(origin))
			continue;

		str = xml_node_get_attr(ifnode, NI_CLIENT_STATE_XML_CONFIG_UUID_NODE);
		if (str) {
			if (ni_uuid_parse(&uuid, str) < 0)
				continue;
			conf->uuid = uuid;
		}
		ni_string_dup(&conf->origin, origin);
		return TRUE;
	}

	return FALSE;
}

void
ni_ifconfig_metadata_clear(xml_node_t *root)
{
	xml_node_t *ifnode = NULL;

	if (!root || !root->children)
		return;

	if (ni_string_empty(root->name))
		ifnode = root->children;
	else
		ifnode = root;
	for ( ; ifnode; ifnode = ifnode->next) {
		xml_node_del_attr(ifnode, NI_CLIENT_STATE_XML_CONFIG_ORIGIN_NODE);
		xml_node_del_attr(ifnode, NI_CLIENT_STATE_XML_CONFIG_UUID_NODE);
		xml_node_del_attr(ifnode, NI_CLIENT_STATE_XML_CONFIG_OWNER_NODE);
	}
}
