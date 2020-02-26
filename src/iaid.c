/*
 *	DHCP Identity Association Identifier (IAID) utilities
 *
 *	Copyright (C) 2016 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *		Nirmoy Das <ndas@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if_arp.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/util.h>
#include <wicked/xml.h>

#include "iaid.h"
#include "buffer.h"


#define NI_CONFIG_DEFAULT_IAID_NODE	"iaid"
#define NI_CONFIG_DEFAULT_IAID_DEVICE	"device"
#define NI_CONFIG_DEFAULT_IAID_FILE	"iaid.xml"

struct ni_iaid_map {
	xml_document_t *	doc;

	int			fd;
	char *			file;
	struct flock		flock;
};

static ni_iaid_map_t *
ni_iaid_map_new(void)
{
	ni_iaid_map_t *map;

	map = calloc(1, sizeof(*map));
	if (map) {
		map->fd = -1;
		map->flock.l_type = F_UNLCK;
	}
	return map;
}

static	ni_bool_t
ni_iaid_map_lock(ni_iaid_map_t *map)
{
	if (!map || map->fd < 0)
		return FALSE;

	memset(&map->flock, 0, sizeof(map->flock));
	map->flock.l_type   = F_WRLCK;
	map->flock.l_whence = SEEK_SET;

	if (fcntl(map->fd,  F_SETLKW, &map->flock) < 0) {
		map->flock.l_type = F_UNLCK;
		return FALSE;
	}
	return TRUE;
}

static	ni_bool_t
ni_iaid_map_unlock(ni_iaid_map_t *map)
{
	if (!map || map->fd < 0)
		return FALSE;

	if (map->flock.l_type == F_UNLCK)
		return TRUE;

	memset(&map->flock, 0, sizeof(map->flock));
	map->flock.l_type   = F_UNLCK;
	map->flock.l_whence = SEEK_SET;

	if (fcntl(map->fd,  F_SETLKW, &map->flock) < 0)
		return FALSE;
	return TRUE;
}

void
ni_iaid_map_free(ni_iaid_map_t *map)
{
	if (map) {
		if (map->fd >= 0) {
			ni_iaid_map_unlock(map);
			close(map->fd);
			map->fd = -1;
		}
		xml_document_free(map->doc);
		ni_string_free(&map->file);
		free(map);
	}
}

static ni_bool_t
ni_iaid_map_open(ni_iaid_map_t *map)
{
	int flags = O_CLOEXEC | O_NOCTTY | O_RDWR | O_CREAT;
	int mode = S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;

	if (!map || map->fd >= 0 || ni_string_empty(map->file))
		return FALSE;

	map->fd = open(map->file, flags, mode);
	if (map->fd < 0)
		return FALSE;
	return TRUE;
}

static ni_bool_t
ni_iaid_map_set_default_file(char **filename)
{
	return ni_string_printf(filename, "%s/%s",
			ni_config_storedir(),
			NI_CONFIG_DEFAULT_IAID_FILE) != NULL;
}

static ni_bool_t
ni_iaid_map_set_fallback_file(char **filename)
{
	return ni_string_printf(filename, "%s/%s",
			ni_config_statedir(),
			NI_CONFIG_DEFAULT_IAID_FILE) != NULL;
}

ni_iaid_map_t *
ni_iaid_map_load(const char *filename)
{
	ni_iaid_map_t *map;
	const char *type;
	ni_buffer_t buff;
	struct stat stb;
	ssize_t len;

	if (!(map = ni_iaid_map_new())) {
		ni_error("unable to allocate memory for iaid map: %m");
		return NULL;
	}

	if (filename) {
		type = "given";
		if (!ni_string_dup(&map->file, filename)) {
			ni_error("unable to copy %s iaid map file name (%s): %m", type, filename);
			goto failure;
		}

		if (!ni_iaid_map_open(map)) {
			ni_error("unable to open %s iaid map file name (%s): %m", type, map->file);
			goto failure;
		}
	} else {
		type = "default";
		if (!ni_iaid_map_set_default_file(&map->file)) {
			ni_error("unable to construct %s iaid map file name: %m", type);
			goto failure;
		}

		if (!ni_iaid_map_open(map)) {
			ni_debug_readwrite("unable to open %s iaid map file name (%s): %m", type, map->file);

			type = "fallback";
			if (!ni_iaid_map_set_fallback_file(&map->file)) {
				ni_error("unable to construct %s iaid map file name: %m", type);
				goto failure;
			}
			
			if (!ni_iaid_map_open(map)) {
				ni_error("unable to open iaid map file name (%s): %m", map->file);
				goto failure;
			}
		}
	}

	if (!ni_iaid_map_lock(map)) {
		ni_error("unable to lock %s iaid map file name (%s): %m", type, map->file);
		goto failure;
	}

	if (fstat(map->fd, &stb) < 0)
		stb.st_size = BUFSIZ;

	ni_buffer_init_dynamic(&buff, stb.st_size + 1);
	do {
		if (!ni_buffer_tailroom(&buff))
			ni_buffer_ensure_tailroom(&buff, BUFSIZ);

		do {
			 len = read(map->fd, ni_buffer_tail(&buff), ni_buffer_tailroom(&buff));
			 if (len > 0)
				 ni_buffer_push_tail(&buff, len);
		} while (len < 0 && errno == EINTR);
	} while (len > 0);

	if (len < 0) {
		ni_error("unable to read %s iaid map file name (%s): %m", type, map->file);
	} else {
		map->doc = xml_document_from_buffer(&buff, map->file);
		ni_buffer_destroy(&buff);
		if (!map->doc) {
			map->doc = xml_document_new();
			ni_warn("unable to parse %s iaid map file name (%s): %m", type, map->file);
		}
		return map;
	}

failure:
	ni_iaid_map_free(map);
	return NULL;
}

ni_bool_t
ni_iaid_map_save(ni_iaid_map_t *map)
{
	char *data = NULL;
	size_t off, len;
	ssize_t ret;

	if (!map || map->fd < 0)
		return FALSE;

	if (lseek(map->fd, 0, SEEK_SET) < 0)
		 return FALSE;

	if (ftruncate(map->fd, 0) < 0)
		return FALSE;

	if (map->doc && map->doc->root)
		data = xml_node_sprint(map->doc->root);

	len = ni_string_len(data);
	off = 0;
	ret = 0;
	while (len > off) {
		ret = write(map->fd, data + off, len - off);
		if (ret < 0 && errno != EINTR)
			break;
		else
		if (ret > 0)
			off += ret;
	}
	free(data);

	return ret < 0 ? FALSE : TRUE;
}

static xml_node_t *
ni_iaid_map_root_node(const ni_iaid_map_t *map)
{
	if (!map || !map->doc)
		return NULL;
	return xml_document_root(map->doc);
}

static xml_node_t *
ni_iaid_map_next_node(const xml_node_t *root, const xml_node_t *last)
{
	return xml_node_get_next_child(root, NI_CONFIG_DEFAULT_IAID_NODE, last);
}

static ni_bool_t
ni_iaid_map_node_to_name(const xml_node_t *node, const char **name)
{
	if (!node || !name)
		return FALSE;

	*name = xml_node_get_attr(node, NI_CONFIG_DEFAULT_IAID_DEVICE);
	return !ni_string_empty(*name);
}

static ni_bool_t
ni_iaid_map_node_to_iaid(const xml_node_t *node, unsigned int *iaid)
{
	if (!node || !iaid)
		return FALSE;

	return ni_parse_uint(node->cdata, iaid, 0) == 0;
}

ni_bool_t
ni_iaid_map_to_vars(const ni_iaid_map_t *map, ni_var_array_t *vars)
{
	xml_node_t *root, *node = NULL;
	const char *name;

	if (!vars)
		return FALSE;

	if (!(root = ni_iaid_map_root_node(map)))
		return FALSE;

	ni_var_array_destroy(vars);
	while ((node = ni_iaid_map_next_node(root, node))) {
		if (ni_string_empty(node->cdata))
			continue;

		name = xml_node_get_attr(node, NI_CONFIG_DEFAULT_IAID_DEVICE);
		if (ni_string_empty(name))
			continue;

		ni_var_array_set(vars, name, node->cdata);
	}
	return TRUE;
}

ni_bool_t
ni_iaid_map_get_iaid(const ni_iaid_map_t *map, const char *name, unsigned int *iaid)
{
	xml_node_t *root, *node = NULL;
	const char *attr;

	if (!iaid || ni_string_empty(name))
		return FALSE;

	if (!(root = ni_iaid_map_root_node(map)))
		return FALSE;

	while ((node = ni_iaid_map_next_node(root, node))) {
		attr = xml_node_get_attr(node, NI_CONFIG_DEFAULT_IAID_DEVICE);
		if (!ni_string_eq(name, attr))
			continue;

		return ni_iaid_map_node_to_iaid(node, iaid);
	}
	return FALSE;
}

ni_bool_t
ni_iaid_map_get_name(const ni_iaid_map_t *map, unsigned int iaid, const char **name)
{
	xml_node_t *root, *node = NULL;
	unsigned int curr;

	if (!name)
		return FALSE;

	if (!(root = ni_iaid_map_root_node(map)))
		return FALSE;

	while ((node = ni_iaid_map_next_node(root, node))) {
		if (!ni_iaid_map_node_to_iaid(node, &curr) || iaid != curr)
			continue;

		return ni_iaid_map_node_to_name(node, name);
	}
	return FALSE;
}

ni_bool_t
ni_iaid_map_set(ni_iaid_map_t *map, const char *name, unsigned int iaid)
{
	xml_node_t *root, *node = NULL;
	const char *attr;

	if (!(root = ni_iaid_map_root_node(map)) || ni_string_empty(name))
		return FALSE;

	while ((node = ni_iaid_map_next_node(root, node))) {
		attr = xml_node_get_attr(node, NI_CONFIG_DEFAULT_IAID_DEVICE);
		if (!ni_string_eq(name, attr))
			continue;

		xml_node_set_uint(node, iaid);
		return TRUE;
	}

	if ((node = xml_node_new(NI_CONFIG_DEFAULT_IAID_NODE, root))) {
		xml_node_add_attr(node, NI_CONFIG_DEFAULT_IAID_DEVICE, name);
		xml_node_set_uint(node, iaid);
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_iaid_map_del_name(ni_iaid_map_t *map, const char *name)
{
	xml_node_t *root, *node = NULL;
	const char *attr;

	if (ni_string_empty(name))
		return FALSE;

	if (!(root = ni_iaid_map_root_node(map)))
		return FALSE;

	while ((node = ni_iaid_map_next_node(root, node))) {
		attr = xml_node_get_attr(node, NI_CONFIG_DEFAULT_IAID_DEVICE);
		if (!ni_string_eq(name, attr))
			continue;

		xml_node_detach(node);
		xml_node_free(node);
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_iaid_map_del_iaid(ni_iaid_map_t *map, unsigned int iaid)
{
	xml_node_t *root, *node = NULL;
	unsigned int curr;

	if (!(root = ni_iaid_map_root_node(map)))
		return FALSE;

	while ((node = ni_iaid_map_next_node(root, node))) {
		if (!ni_iaid_map_node_to_iaid(node, &curr) || iaid != curr)
			continue;

		xml_node_detach(node);
		xml_node_free(node);
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_iaid_create_hwaddr(unsigned int *iaid, const ni_hwaddr_t *hwa)
{
	size_t off;

	if (!iaid || !hwa)
		return FALSE;

	if (hwa->len < sizeof(*iaid))
		return FALSE;

	if (ni_link_address_is_invalid(hwa))
		return FALSE;

	off = hwa->len - sizeof(*iaid);
	memcpy(iaid, hwa->data + off, sizeof(uint32_t));
	*iaid = ntohl(*iaid);
	return TRUE;
}

ni_bool_t
ni_iaid_create(unsigned int *iaid, const ni_netdev_t *dev, const ni_iaid_map_t *map)
{
	unsigned int i;

	if (!iaid || !dev)
		return FALSE;

	if (ni_iaid_create_hwaddr(iaid, &dev->link.hwaddr))
		return TRUE;

	if (map) {
		for (i = 1; i < -1U; ++i) {
			const char *name = NULL;

			if (ni_iaid_map_get_name(map, i, &name))
				continue;

			*iaid = i;
			return TRUE;
		}
	}
	return FALSE;
}

ni_bool_t
ni_iaid_acquire(unsigned int *iaid, const ni_netdev_t *dev, unsigned int requested)
{
	ni_iaid_map_t * map = NULL;

	if (!iaid || !dev)
		return FALSE;

	if (!(map = ni_iaid_map_load(NULL)))
		goto failure;

	if (ni_iaid_map_get_iaid(map, dev->name, iaid))
		goto cleanup;

	if (!requested && !ni_iaid_create(&requested, dev, map))
		goto failure;

	*iaid = requested;

	if (!ni_iaid_map_set(map, dev->name, requested))
		goto failure;

	if (!ni_iaid_map_save(map))
		goto failure;

cleanup:
	ni_iaid_map_free(map);
	return TRUE;

failure:
	*iaid = 0;
	ni_iaid_map_free(map);
	return FALSE;
}

