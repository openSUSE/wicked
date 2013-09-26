/*
 * Functionality for reading configuration files accessed by client program.
 * Currently supported configuration types are:
 * 	wicked:
 * 	compat:
 * 	firmware:
 * with their assosciated sub-types.
 *
 * Copyright (C) 2010-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 * Authors:
 * 	Olaf Kirch <okir@suse.de>
 * 	Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 * 	Marius Tomaschewski <mt@suse.de>
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
						const char *);
	    const ni_ifconfig_type_t *	(*guess)(const ni_ifconfig_type_t *,
						const char *root,
						const char *path);
	} ops;
};

static ni_bool_t	ni_ifconfig_read_wicked(xml_document_array_t *,
						const char *,
						const char *,
						const char *);
static ni_bool_t	ni_ifconfig_read_wicked_xml(xml_document_array_t *,
						const char *,
						const char *,
						const char *);
static ni_bool_t	ni_ifconfig_read_compat(xml_document_array_t *,
						const char *,
						const char *,
						const char *);
static ni_bool_t	ni_ifconfig_read_compat_suse(xml_document_array_t *,
						const char *,
						const char *,
						const char *);
static ni_bool_t	ni_ifconfig_read_compat_redhat(xml_document_array_t *,
						const char *,
						const char *,
						const char *);
static ni_bool_t	ni_ifconfig_read_firmware(xml_document_array_t *,
						const char *,
						const char *,
						const char *);

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
ni_ifconfig_read(xml_document_array_t *array, const char *root, const char *path)
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
		return map->ops.read(array, map->name, root, _path);
	}

	ni_error("Unsupported ifconfig type %.*s", (int)len, path);
	return FALSE;
}

/*
 * Read ifconfig file
 */
static ni_bool_t
__ni_ifconfig_xml_read_file(xml_document_array_t *docs, const char *root, const char *pathname)
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

	xml_document_array_append(docs, config_doc);
	return TRUE;
}

static ni_bool_t
__ni_ifconfig_xml_read_dir(xml_document_array_t *docs, const char *root, const char *pathname)
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
			if (__ni_ifconfig_xml_read_file(docs, pathname, files.data[i]))
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
			const char *root, const char *path)
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
		rv = __ni_ifconfig_xml_read_file(array, root, path);
	else if (ni_isdir(path))
		rv = __ni_ifconfig_xml_read_dir(array, root, path);

	ni_string_free(&ifconfig_dir);
	return rv;
}

ni_bool_t
ni_ifconfig_read_wicked(xml_document_array_t *array, const char *type,
			const char *root, const char *path)
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
		if (map->ops.read(array, _type, root, _path)) {
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
			const char *root, const char *path)
{
	ni_compat_ifconfig_t ifcfg = { {0, NULL} };
	ni_bool_t rv;

	if ((rv = __ni_suse_get_interfaces(root, path, &ifcfg.netdev_array))) {
		ni_compat_generate_interfaces(array, &ifcfg);
	}

	ni_compat_netdev_array_destroy(&ifcfg.netdev_array);
	return rv;
}

ni_bool_t
ni_ifconfig_read_compat_redhat(xml_document_array_t *array, const char *type,
			const char *root, const char *path)
{
	ni_compat_ifconfig_t ifcfg = { {0, NULL} };
	ni_bool_t rv;

	if ((rv = __ni_redhat_get_interfaces(root, path, &ifcfg.netdev_array))) {
		ni_compat_generate_interfaces(array, &ifcfg);
	}

	ni_compat_netdev_array_destroy(&ifcfg.netdev_array);
	return rv;
}

ni_bool_t
ni_ifconfig_read_compat(xml_document_array_t *array, const char *type,
			const char *root, const char *path)
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
		if (map->ops.read(array, _type, root, _path)) {
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
			const char *root, const char *path)
{
	xml_document_t *config_doc;

	config_doc = ni_netconfig_firmware_discovery(root, path);

	if (!config_doc) {
		ni_error("unable to get firmware interface definitions from %s:%s",
			type, path);
		return FALSE;
	}

	xml_document_array_append(array, config_doc);
	return TRUE;
}
