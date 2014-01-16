/*
 *	wicked client configuration reading.
 *	Currently supported are following configuration schemes:
 *		wicked:
 *		compat:
 *		firmware:
 *	along their assosciated sub-types.
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
#include "wicked-client.h"

typedef struct ni_ifconfig_type	ni_ifconfig_type_t;
struct ni_ifconfig_type {
	const char *			name;
	struct {
		ni_bool_t		(*read)(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_bool_t);
	    const ni_ifconfig_type_t *	(*guess)(const ni_ifconfig_type_t *,
						const char *root,
						const char *path);
	} ops;
};

static ni_bool_t	ni_ifconfig_read_wicked(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_bool_t);
static ni_bool_t	ni_ifconfig_read_wicked_xml(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_bool_t);
static ni_bool_t	ni_ifconfig_read_compat(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_bool_t);
static ni_bool_t	ni_ifconfig_read_compat_suse(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_bool_t);
static ni_bool_t	ni_ifconfig_read_compat_redhat(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_bool_t);
static ni_bool_t	ni_ifconfig_read_firmware(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_bool_t);

static const ni_ifconfig_type_t *
__ni_ifconfig_find_map(const ni_ifconfig_type_t *map, const char *name, size_t len)
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

static const ni_ifconfig_type_t *
ni_ifconfig_find_type(const ni_ifconfig_type_t *map, const char *root,
			const char *path, const char *name, size_t len)
{
	const ni_ifconfig_type_t *ret;

	ret = __ni_ifconfig_find_map(map, name, len);

	if (!name && ret && ret->ops.guess) {
		ret = ret->ops.guess(map, root, path);
	}
	return ret;
}

const ni_ifconfig_type_t *
ni_ifconfig_guess_compat_type(const ni_ifconfig_type_t *map,
				const char *root, const char *path)
{
	(void)path;

	if (ni_file_exists_fmt("%s%s", (root ? root : ""), "/etc/SuSE-release"))
		return __ni_ifconfig_find_map(map, "suse", sizeof("suse")-1);

	if (ni_file_exists_fmt("%s%s", (root ? root : ""), "/etc/redhat-release"))
		return __ni_ifconfig_find_map(map, "redhat", sizeof("redhat")-1);

	return NULL;
}

const ni_ifconfig_type_t *
ni_ifconfig_guess_wicked_type(const ni_ifconfig_type_t *map,
			const char *root, const char *path)
{
	return __ni_ifconfig_find_map(map, "xml", sizeof("xml")-1);
}

const ni_ifconfig_type_t *
ni_ifconfig_guess_type(const ni_ifconfig_type_t *map,
			const char *root, const char *path)
{
	return __ni_ifconfig_find_map(map, "wicked", sizeof("wicked")-1);
}

static const ni_ifconfig_type_t	__ni_ifconfig_types_wicked[] = {
	{ "xml",	{ .read = ni_ifconfig_read_wicked_xml	} },
	{ NULL,		{ .guess= ni_ifconfig_guess_wicked_type	} },
};

static const ni_ifconfig_type_t	__ni_ifconfig_types_compat[] = {
	{ "suse",	{ .read = ni_ifconfig_read_compat_suse	} },
	{ "redhat",	{ .read = ni_ifconfig_read_compat_redhat} },
	{ NULL,		{ .guess= ni_ifconfig_guess_compat_type } },
};

static const ni_ifconfig_type_t	__ni_ifconfig_types[] = {
	{ "wicked",	{ .read = ni_ifconfig_read_wicked	} },
	{ "compat",	{ .read = ni_ifconfig_read_compat	} },
	{ "firmware",	{ .read = ni_ifconfig_read_firmware	} },
	{ NULL,		{ .guess= ni_ifconfig_guess_type	} },
};

ni_bool_t
ni_ifconfig_load(ni_fsm_t *fsm, const char *root, const char *location, ni_bool_t force)
{
	xml_document_array_t docs = XML_DOCUMENT_ARRAY_INIT;
	unsigned int i;

	if (!ni_ifconfig_read(&docs, root, location, FALSE))
		return FALSE;

	for (i = 0; i < docs.count; i++) {
		/* TODO: review ni_fsm_workers_from_xml return codes */
		ni_fsm_workers_from_xml(fsm, docs.data[i], force);
	}

	/* Do not destroy xml documents as referenced by the fsm workers */
	free(docs.data);

	return TRUE;
}

ni_bool_t
ni_ifconfig_read(xml_document_array_t *array, const char *root, const char *path, ni_bool_t raw)
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

	map = ni_ifconfig_find_type(__ni_ifconfig_types, root, path, _name, len);
	if (map && map->name && map->ops.read) {
		return map->ops.read(array, map->name, root, _path, raw);
	}

	ni_error("Unsupported ifconfig type %.*s", (int)len, path);
	return FALSE;
}

/*
 * Read ifconfig file
 */
static ni_bool_t
__ni_ifconfig_xml_read_file(xml_document_array_t *docs, const char *root, const char *pathname, ni_bool_t raw)
{
	xml_document_t *config_doc;
	char pathbuf[PATH_MAX] = {'\0'};

	if (root) {
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", root, pathname);
		pathname = pathbuf;
	}

	if (!(config_doc = xml_document_read(pathname))) {
		ni_error("unable to load interface definition from %s", pathname);
		return FALSE;
	}

	if (!raw) {
		ni_ifconfig_add_client_info(config_doc,
			ni_ifconfig_generate_client_info("wicked", pathname, NULL), NULL);
	}

	xml_document_array_append(docs, config_doc);
	return TRUE;
}

static ni_bool_t
__ni_ifconfig_xml_read_dir(xml_document_array_t *docs, const char *root, const char *pathname, ni_bool_t raw)
{
	char pathbuf[PATH_MAX] = {'\0'};
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	unsigned int i;
	ni_bool_t empty = TRUE;

	ni_assert(docs);

	if (root) {
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", root, pathname);
		pathname = pathbuf;
	}

	if (ni_scandir(pathname, "*.xml", &files) != 0) {
		for (i = 0; i < files.count; ++i) {
			/* Ignore wrong xml config files - warning only */
			if (__ni_ifconfig_xml_read_file(docs, pathname, files.data[i], raw))
				empty = FALSE;
		}
	}

	if (empty)
		ni_info("No valid configuration files found at %s", pathname);

	ni_string_array_destroy(&files);
	return TRUE;
}

ni_bool_t
ni_ifconfig_read_wicked_xml(xml_document_array_t *array, const char *type,
			const char *root, const char *path, ni_bool_t raw)
{
	char *ifconfig_dir = NULL;
	ni_bool_t rv = FALSE;

	if (ni_string_empty(path)) {
		ni_string_printf(&ifconfig_dir, "%s/%s", ni_get_global_config_dir(),
				"ifconfig");
		path = ifconfig_dir;
	}

	/* At the moment only XML is supported */
	if (ni_isreg(path))
		rv = __ni_ifconfig_xml_read_file(array, root, path, raw);
	else if (ni_isdir(path))
		rv = __ni_ifconfig_xml_read_dir(array, root, path, raw);

	ni_string_free(&ifconfig_dir);
	return rv;
}

ni_bool_t
ni_ifconfig_read_wicked(xml_document_array_t *array, const char *type,
			const char *root, const char *path, ni_bool_t raw)
{
	const ni_ifconfig_type_t *map;
	const char *_path = path;
	const char *_name = NULL;
	char *_type = NULL;
	size_t len;

	len = strcspn(path, ":");
	if (path[len] == ':') {
		_name = len ? path : NULL;
		_path = path + len + 1;
	}

	map = ni_ifconfig_find_type(__ni_ifconfig_types_wicked, root, path, _name, len);
	if (map && map->name && map->ops.read) {
		ni_string_printf(&_type, "%s:%s", type, map->name);
		if (map->ops.read(array, _type, root, _path, raw)) {
			ni_string_free(&_type);
			return TRUE;
		}
		ni_string_free(&_type);
	}
	else {
		ni_error("Unsupported ifconfig type %s:%.*s", type, (int)len, _name);
	}

	return FALSE;
}

/*
 * Read old-style ifcfg file(s)
 */
ni_bool_t
ni_ifconfig_read_compat_suse(xml_document_array_t *array, const char *type,
			const char *root, const char *path, ni_bool_t raw)
{
	ni_compat_ifconfig_t ifcfg = { {0, NULL} };
	ni_bool_t rv;

	if ((rv = __ni_suse_get_interfaces(root, path, &ifcfg.netdev_array))) {
		ni_compat_generate_interfaces(array, &ifcfg, raw);
	}

	ni_compat_netdev_array_destroy(&ifcfg.netdev_array);
	return rv;
}

ni_bool_t
ni_ifconfig_read_compat_redhat(xml_document_array_t *array, const char *type,
			const char *root, const char *path, ni_bool_t raw)
{
	ni_compat_ifconfig_t ifcfg = { {0, NULL} };
	ni_bool_t rv;

	if ((rv = __ni_redhat_get_interfaces(root, path, &ifcfg.netdev_array))) {
		ni_compat_generate_interfaces(array, &ifcfg, raw);
	}

	ni_compat_netdev_array_destroy(&ifcfg.netdev_array);
	return rv;
}

ni_bool_t
ni_ifconfig_read_compat(xml_document_array_t *array, const char *type,
			const char *root, const char *path, ni_bool_t raw)
{
	const ni_ifconfig_type_t *map;
	const char *_path = path;
	const char *_name = NULL;
	char *_type = NULL;
	size_t len;

	len = strcspn(path, ":");
	if (path[len] == ':') {
		_name = len ? path : NULL;
		_path = path + len + 1;
	}

	map = ni_ifconfig_find_type(__ni_ifconfig_types_compat, root, path, _name, len);
	if (map && map->name && map->ops.read) {
		ni_string_printf(&_type, "%s:%s", type, map->name);
		if (map->ops.read(array, _type, root, _path, raw)) {
			ni_string_free(&_type);
			return TRUE;
		}
		ni_string_free(&_type);
	}
	else {
		ni_error("Unsupported ifconfig type %s:%.*s", type, (int)len, _name);
	}

	return FALSE;
}

ni_bool_t
ni_ifconfig_read_firmware(xml_document_array_t *array, const char *type,
			const char *root, const char *path, ni_bool_t raw)
{
	xml_document_t *config_doc;
	ni_device_clientinfo_t *client_info;

	config_doc = ni_netconfig_firmware_discovery(root, path);

	if (!config_doc) {
		ni_error("unable to get firmware interface definitions from %s:%s",
			type, path);
		return FALSE;
	}

	client_info = ni_ifconfig_get_client_info(config_doc);
	if (!client_info) {
		client_info = ni_ifconfig_generate_client_info("firmware", path, NULL);
		if (!raw)
			ni_ifconfig_add_client_info(config_doc, client_info, NULL);
	}

	/* Add location */
	if (!ni_string_empty(client_info->config_origin)) {
		xml_location_set(config_doc->root,
			xml_location_create(client_info->config_origin, 0));
		ni_debug_ifconfig("%s: location: %s, line: %u", __func__,
				xml_node_get_location_filename(config_doc->root),
				xml_node_get_location_line(config_doc->root));
	}

	ni_device_clientinfo_free(client_info);
	xml_document_array_append(array, config_doc);
	return TRUE;
}

ni_device_clientinfo_t *
ni_ifconfig_generate_client_info(const char *schema, const char *filename, const char *state)
{
	ni_device_clientinfo_t *client_info;
	char *origin = NULL;

	ni_string_printf(&origin, "%s%s%s",
			(schema ? schema : ""),
			(schema ? ":" : ""),
			(filename ? filename : ""));

	client_info = ni_device_clientinfo_new();
	if (!ni_string_empty(state))
		ni_string_dup(&client_info->state, state);
	if (!ni_string_empty(origin))
		ni_string_dup(&client_info->config_origin, origin);
	if (ni_file_exists(filename))
		ni_uuid_for_file(&client_info->config_uuid, filename);
	else
		ni_uuid_generate(&client_info->config_uuid);

	ni_string_free(&origin);
	return client_info;
}

ni_device_clientinfo_t *
ni_ifconfig_get_client_info(xml_document_t *doc)
{
	ni_device_clientinfo_t *client_info = NULL;
	xml_node_t *cinode = NULL;
	const char *val;

	if (!doc || !xml_document_root(doc))
		return NULL;

	/* FIXME: Currently returns either the first occurence or NULL */
	cinode = xml_node_get_next_child(doc->root, "interface", cinode);

	if (cinode) {
		client_info = ni_device_clientinfo_new();
		if ((val = xml_node_get_attr(cinode, "state")))
			ni_string_dup(&client_info->state, val);
		if ((val = xml_node_get_attr(cinode, "config-origin")))
			ni_string_dup(&client_info->config_origin, val);
		if ((val = xml_node_get_attr(cinode, "config-uuid")))
			ni_uuid_parse(&client_info->config_uuid, val);
	}

	return client_info;
}

void
ni_ifconfig_add_client_info(xml_document_t *doc, ni_device_clientinfo_t *client_info, char *to_node)
{
	xml_node_t *root, *cinode, *ifnode = NULL;

	if (!doc || !(root = xml_document_root(doc)) || !client_info)
		return;

	if (!to_node) {
		if (root->children)
			to_node = root->children->name;
		else
			return;
	}

	while ((ifnode = xml_node_get_next_child(root, to_node, ifnode))) {
		cinode = xml_node_new("client-info", NULL);
		xml_node_replace_child(ifnode, cinode);

		if (!ni_string_empty(client_info->state))
			xml_node_new_element("state", cinode, client_info->state);
		if (!ni_string_empty(client_info->config_origin)) {
			xml_node_new_element("config-origin", cinode,
				client_info->config_origin);
		}
		if (!ni_uuid_is_null(&client_info->config_uuid)) {
			xml_node_new_element("config-uuid", cinode,
				ni_uuid_print(&client_info->config_uuid));
		}
	}
}

void
ni_ifconfig_del_client_info(xml_document_t *doc, const char *from_node)
{
	xml_node_t *root, *ifnode = NULL;

	if (!doc || !(root = xml_document_root(doc)))
		return;

	if (!from_node) {
		if (root->children)
			from_node = root->children->name;
		else
			return;
	}

	while ((ifnode = xml_node_get_next_child(root, from_node, ifnode)))
		xml_node_delete_child(ifnode, "client-info");
}
