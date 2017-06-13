/*
 *	DHCP Unique Identifier (DUID) utilities
 *
 *	Copyright (C) 2012 Marius Tomaschewski <mt@suse.de>
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
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/util.h>
#include <wicked/xml.h>

#include "duid.h"
#include "util_priv.h"

#ifndef NI_MACHINE_ID_UUID_FILE
#define NI_MACHINE_ID_UUID_FILE		"/etc/machine-id"
#endif
#ifndef NI_DMI_PRODUCT_UUID_FILE
#define NI_DMI_PRODUCT_UUID_FILE	"/sys/devices/virtual/dmi/id/product_uuid";
#endif

#define CONFIG_DEFAULT_DUID_NODE	"duid"
#define CONFIG_DEFAULT_DUID_FILE	"duid.xml"


/*
 * compiler (gcc) specific ...
 */
#define NI_PACKED __attribute__((__packed__))

/*
 * DUID typed packed data union
 */
typedef union ni_duid_data {
	ni_duid_uuid_t		uuid;
	ni_duid_llt_t		llt;
	ni_duid_ll_t		ll;
	ni_duid_en_t		en;
} NI_PACKED ni_duid_data_t;

#undef NI_PACKED


/*
 * Well-known DUID type name map
 */
static const ni_intmap_t	ni_duid_type_names[] = {
	{ "en",			NI_DUID_TYPE_EN		},
	{ "ll",			NI_DUID_TYPE_LL		},
	{ "llt",		NI_DUID_TYPE_LLT	},
	{ "uuid",		NI_DUID_TYPE_UUID	},

	{ NULL,			0			}
};

/*
 * Note: only types we support duid ll[t] creation + aliases.
 *
 * The complete arp-type mapping is in src/names.c and available
 * via the ni_arphrd_type_to_name() and related functions.
 */
static const ni_intmap_t	ni_duid_hwtype_names[] = {
	{ "ethernet",		ARPHRD_ETHER		},
	{ "ether",		ARPHRD_ETHER		},
	{ "infiniband",		ARPHRD_INFINIBAND	},
	{ "ipoib",		ARPHRD_INFINIBAND	},

	{ NULL,			ARPHRD_VOID		}
};


const ni_intmap_t *
ni_duid_type_map(void)
{
	return ni_duid_type_names;
}

const char *
ni_duid_type_to_name(unsigned int type)
{
	return ni_format_uint_mapped(type, ni_duid_type_names);
}

ni_bool_t
ni_duid_type_by_name(const char *name, unsigned int *type)
{
	if (!type || ni_parse_uint_mapped(name, ni_duid_type_names, type) < 0)
		return FALSE;
	return TRUE;
}

const ni_intmap_t *
ni_duid_hwtype_map(void)
{
	return ni_duid_hwtype_names;
}

const char *
ni_duid_hwtype_to_name(unsigned int hwtype)
{
	return ni_format_uint_mapped(hwtype, ni_duid_hwtype_names);
}

ni_bool_t
ni_duid_hwtype_by_name(const char *name, unsigned int *hwtype)
{
	if (!hwtype || ni_parse_uint_maybe_mapped(name, ni_duid_hwtype_names, hwtype, 0) < 0)
		return FALSE;
	return TRUE;
}

ni_bool_t
ni_duid_init_llt(ni_opaque_t *duid, unsigned short hwtype, const void *hwaddr, size_t len)
{
	ni_duid_data_t *data;
	time_t		now;
	uint64_t	u64;

	memset(duid, 0, sizeof(*duid));
	if (!len)
		return FALSE;

	if (time(&now) == (time_t)-1)
		return FALSE;

	if ((sizeof(ni_duid_llt_t) + len) > sizeof(duid->data))
		len = sizeof(duid->data) - sizeof(ni_duid_llt_t);

	duid->len = sizeof(ni_duid_llt_t) + len;

	u64 = (uint64_t)(now - NI_DUID_TIME_EPOCH);
	data = (ni_duid_data_t *)&duid->data;
	data->llt.type = htons((uint16_t)NI_DUID_TYPE_LLT);
	data->llt.hwtype = htons(hwtype);
	data->llt.v6time = htonl((uint32_t)(u64 & 0xffffffff));
	memcpy(data->llt.hwaddr, hwaddr, len);
	return TRUE;
}

ni_bool_t
ni_duid_init_ll (ni_opaque_t *duid, unsigned short hwtype, const void *hwaddr, size_t len)
{
	ni_duid_data_t *data;

	memset(duid, 0, sizeof(*duid));
	if (!len)
		return FALSE;

	if ((sizeof(ni_duid_ll_t) + len) > sizeof(duid->data))
		len = sizeof(duid->data) - sizeof(ni_duid_ll_t);

	duid->len = sizeof(ni_duid_ll_t) + len;

	data = (ni_duid_data_t *)&duid->data;
	data->ll.type = htons((uint16_t)NI_DUID_TYPE_LL);
	data->ll.hwtype = htons(hwtype);
	memcpy(data->ll.hwaddr, hwaddr, len);
	return TRUE;
}

ni_bool_t
ni_duid_init_en (ni_opaque_t *duid, unsigned int enumber, const void *identifier, size_t len)
{
	ni_duid_data_t *data;

	memset(duid, 0, sizeof(*duid));
	if (!len || !enumber)
		return FALSE;

	if ((sizeof(ni_duid_en_t) + len) > sizeof(duid->data))
		len = sizeof(duid->data) - sizeof(ni_duid_en_t);

	duid->len = sizeof(ni_duid_en_t) + len;

	data = (ni_duid_data_t *)&duid->data;
	data->en.type = htons((uint16_t)NI_DUID_TYPE_EN);
	data->en.enterprise = htonl(enumber);
	memcpy(data->en.identifier, identifier, len);
	return TRUE;
}

ni_bool_t
ni_duid_init_uuid(ni_opaque_t *duid, const ni_uuid_t *uuid)
{
	ni_duid_data_t *data;

	memset(duid, 0, sizeof(*duid));
	if (ni_uuid_is_null(uuid))
		return FALSE;

	duid->len = sizeof(ni_duid_uuid_t);

	data = (ni_duid_data_t *)&duid->data;
	data->uuid.type = htons((uint16_t)NI_DUID_TYPE_UUID);
	memcpy(&data->uuid.uuid, uuid, sizeof(data->uuid.uuid));
	return TRUE;
}

ni_bool_t
ni_duid_copy(ni_opaque_t *duid, const ni_opaque_t *src)
{
	if (!duid || !src)
		return FALSE;

	ni_duid_clear(duid);
	if (src->len)
		ni_opaque_set(duid, src->data, src->len);
	return TRUE;
}

void
ni_duid_clear(ni_opaque_t *duid)
{
	memset(duid, 0, sizeof(*duid));
}

ni_bool_t
ni_duid_parse_hex(ni_opaque_t *duid, const char *hex)
{
	int len;

	len = ni_parse_hex(hex, duid->data, sizeof(duid->data));
	if (len < 0 || (size_t)len <= sizeof(ni_duid_ll_t))
		return FALSE;

	return (duid->len = len) > 0;
}

const char *
ni_duid_format_hex(char **hex, const ni_opaque_t *duid)
{
	ni_string_free(hex);

	if (duid->len > 0) {
		size_t len = duid->len * 3 + 1;
		*hex = xcalloc(1, len);
		ni_format_hex(duid->data, duid->len, *hex, len);
	}
	return *hex;
}

int
ni_duid_load(ni_opaque_t *duid, const char *filename, const char *name)
{
	char path[PATH_MAX];
	xml_node_t *xml = NULL;
	xml_node_t *node;
	FILE *fp;
	int rv;

	if (ni_string_empty(name))
		name = CONFIG_DEFAULT_DUID_NODE;

	if (!filename) {
		/* On root-fs, state dir used as fallback */
		snprintf(path, sizeof(path), "%s/%s",
				ni_config_statedir(),
				CONFIG_DEFAULT_DUID_FILE);
		filename = path;

		/* Then the proper, reboot persistent dir */
		if ((fp = fopen(filename, "re")) == NULL) {
			snprintf(path, sizeof(path), "%s/%s",
					ni_config_storedir(),
					CONFIG_DEFAULT_DUID_FILE);
			filename = path;

			fp = fopen(filename, "re");
		}
	} else {
		fp = fopen(filename, "re");
	}

	if (fp == NULL) {
		if (errno != ENOENT)
			ni_error("unable to open %s for reading: %m", filename);
		return -1;
	}
	xml = xml_node_scan(fp, NULL);
	fclose(fp);

	if (xml == NULL) {
		ni_error("%s: unable to parse xml file", filename);
		return -1;
	}

	if (xml->name == NULL)
		node = xml->children;
	else
		node = xml;

	if (!node || !ni_string_eq(node->name, name)) {
		ni_error("%s: does not contain %s", filename, name);
		xml_node_free(xml);
		return -1;
	}

	rv = 0;
	if (!node->cdata || !ni_duid_parse_hex(duid, node->cdata)) {
		ni_error("%s: unable to parse %s file", filename, name);
		rv = -1;
	}

	xml_node_free(xml);
	return rv;
}

static int
__ni_duid_save_node(xml_node_t *node, const char *filename)
{
	char tempname[PATH_MAX] = {'\0'};
	FILE *fp = NULL;
	int rv = -1;
	int fd;

	if (!node || !node->name || !filename)
		return rv;

	snprintf(tempname, sizeof(tempname), "%s.XXXXXX", filename);
	if ((fd = mkstemp(tempname)) < 0) {
		if (errno == EROFS)
			return 1;

		ni_error("%s: unable create temporary file for writing: %m", filename);
		goto failed;
	}

	if ((fp = fdopen(fd, "we")) == NULL) {
		ni_error("%s: unable to open file for writing: %m", filename);
		goto failed;
	}

	if (xml_node_print(node, fp) < 0) {
		ni_error("%s: unable to write %s representation",
				filename, node->name);
		goto failed;
	}

	if ((rv = rename(tempname, filename)) != 0) {
		ni_error("%s: unable to rename temporary file '%s': %m",
				filename, tempname);
		goto failed;
	}

failed:
	if (fp != NULL)
		fclose(fp);
	else if (fd >= 0)
		close(fd);
	if (tempname[0])
		unlink(tempname);
	return rv;
}

int
ni_duid_save(const ni_opaque_t *duid, const char *filename, const char *name)
{
	char path[PATH_MAX] = {'\0'};
	xml_node_t *node;
	int rv = -1;

	if (!duid || !duid->len) {
		ni_error("BUG: Refusing to save empty duid");
		return -1;
	}

	if (ni_string_empty(name))
		name = CONFIG_DEFAULT_DUID_NODE;

	if ((node = xml_node_new(name, NULL)) == NULL) {
		ni_error("Unable to create %s xml node: %m", name);
		return -1;
	}
	ni_duid_format_hex(&node->cdata, duid);

	if (!filename) {
		snprintf(path, sizeof(path), "%s/%s",
				ni_config_storedir(),
				CONFIG_DEFAULT_DUID_FILE);
		filename = path;
	}

	/* Try reboot persistent store dir */
	rv = __ni_duid_save_node(node, filename);
	if (filename == path) {
		if (rv == 0) {
			snprintf(path, sizeof(path), "%s/%s",
					ni_config_statedir(),
					CONFIG_DEFAULT_DUID_FILE);

			/* Fallback in state dir is obsolete */
			unlink(path);
		} else
		if (rv > 0) {
			snprintf(path, sizeof(path), "%s/%s",
					ni_config_statedir(),
					CONFIG_DEFAULT_DUID_FILE);

			/* Then try state dir as fallback */
			rv = __ni_duid_save_node(node, path);
		}
	}

	xml_node_free(node);
	return rv > 0 ? -1 : rv;
}

static ni_bool_t
ni_duid_create_parse_hwaddr(ni_hwaddr_t *hwa, unsigned short hwtype, const char *hwaddr)
{
	if (!hwa || !ni_link_address_length(hwtype) || ni_string_empty(hwaddr))
		return FALSE;

	if (ni_link_address_parse(hwa, hwtype, hwaddr) != 0)
		return FALSE;

	return !ni_link_address_is_invalid(hwa); /* all zero and brd */
}

ni_bool_t
ni_duid_create_ll(ni_opaque_t *duid, const char *hwtype, const char *hwaddr)
{
	unsigned int type;
	ni_hwaddr_t hwa;

	if (!duid || !ni_duid_hwtype_by_name(hwtype, &type))
		return FALSE;

	if (!ni_duid_create_parse_hwaddr(&hwa, type, hwaddr))
		return FALSE;

	return ni_duid_init_ll(duid, hwa.type, hwa.data, hwa.len);
}

ni_bool_t
ni_duid_create_llt(ni_opaque_t *duid, const char *hwtype, const char *hwaddr)
{
	unsigned int type;
	ni_hwaddr_t hwa;

	if (!duid || !ni_duid_hwtype_by_name(hwtype, &type))
		return FALSE;

	if (!ni_duid_create_parse_hwaddr(&hwa, type, hwaddr))
		return FALSE;

	return ni_duid_init_llt(duid, hwa.type, hwa.data, hwa.len);
}

ni_bool_t
ni_duid_create_en(ni_opaque_t *duid, const char *enumber, const char *identifier)
{
	ni_opaque_t id;
	unsigned int nr;

	if (!duid || ni_string_empty(identifier))
		return FALSE;

	if (ni_parse_uint(enumber, &nr, 0) < 0 || !nr)
		return FALSE;

	id.len = ni_parse_hex_data(identifier, id.data, sizeof(duid->data), ":");
	if ((ssize_t)id.len <= 0 || id.len > NI_DUID_DATA_LEN - sizeof(uint32_t))
		return FALSE;

	return ni_duid_init_en(duid, nr, id.data, id.len);
}

ni_bool_t
ni_duid_create_uuid_string(ni_opaque_t *duid, const char *string)
{
	ni_uuid_t uuid;

	if (!duid || ni_uuid_parse(&uuid, string) < 0)
		return FALSE;

	return ni_duid_init_uuid(duid, &uuid);
}

ni_bool_t
ni_duid_create_uuid_machine_id(ni_opaque_t *duid, const char *filename)
{
	char line[64] = {'\0'};
	ni_uuid_t uuid;
	ssize_t len;
	FILE *file;

	if (ni_string_empty(filename))
		filename = NI_MACHINE_ID_UUID_FILE;

	if (!duid || !(file = fopen(filename, "re")))
		return FALSE;

	if (fgets(line, sizeof(line)-1, file)) {
		line[strcspn(line, " \t\n")] = '\0';
		fclose(file);
	} else {
		fclose(file);
		return FALSE;
	}

	len = ni_parse_hex_data(line, uuid.octets, sizeof(uuid.octets), "");
	if (len != sizeof(uuid.octets))
		return FALSE;

	return ni_duid_init_uuid(duid, &uuid);
}

ni_bool_t
ni_duid_create_uuid_dmi_product_id(ni_opaque_t *duid, const char *filename)
{
	char line[64] = {'\0'};
	ni_uuid_t uuid;
	FILE *file;

	if (ni_string_empty(filename))
		filename = NI_DMI_PRODUCT_UUID_FILE;

	if (!duid || !(file = fopen(filename, "re")))
		return FALSE;

	if (fgets(line, sizeof(line)-1, file)) {
		line[strcspn(line, " \t\n")] = '\0';
		fclose(file);
	} else {
		fclose(file);
		return FALSE;
	}

	if (ni_uuid_parse(&uuid, line) < 0)
		return FALSE;

	return ni_duid_init_uuid(duid, &uuid);
}

static ni_bool_t
ni_duid_create_from_device_ll(ni_opaque_t *duid, const ni_netdev_t *dev)
{
	if (!duid || !dev || !dev->link.hwaddr.len)
		return FALSE;

	return ni_duid_init_ll(duid, dev->link.hwaddr.type, dev->link.hwaddr.data, dev->link.hwaddr.len);
}

static ni_bool_t
ni_duid_create_from_device_llt(ni_opaque_t *duid, const ni_netdev_t *dev)
{
	if (!duid || !dev || !dev->link.hwaddr.len)
		return FALSE;

	return ni_duid_init_llt(duid, dev->link.hwaddr.type, dev->link.hwaddr.data, dev->link.hwaddr.len);
}

ni_bool_t
ni_duid_create_from_device(ni_opaque_t *duid, uint16_t type, const ni_netdev_t *dev)
{
	switch (type) {
	case NI_DUID_TYPE_LL:
		return ni_duid_create_from_device_ll(duid, dev);
	case NI_DUID_TYPE_LLT:
		return ni_duid_create_from_device_llt(duid, dev);
	default:
		return FALSE;
	}
}

ni_bool_t
ni_duid_create_pref_device(ni_opaque_t *duid, uint16_t type, ni_netconfig_t *nc, const ni_netdev_t *preferred)
{
	const ni_netdev_t *dev;

	if (!duid || (!nc && !(nc = ni_global_state_handle(0))))
		return FALSE;

	if (preferred && ni_duid_create_from_device(duid, type, preferred))
		return TRUE;

	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next) {
		switch (dev->link.hwaddr.type) {
		case ARPHRD_ETHER:
		case ARPHRD_IEEE802:
		case ARPHRD_INFINIBAND:
			if (ni_duid_create_from_device(duid, type, dev))
				return TRUE;
		default:
			break;
		}
	}
	return FALSE;
}

ni_bool_t
ni_duid_create(ni_opaque_t *duid, uint16_t type, ni_netconfig_t *nc, const ni_netdev_t *preferred)
{
	ni_uuid_t uuid;

	if (!duid)
		return FALSE;

	switch (type) {
	case NI_DUID_TYPE_LL:
	case NI_DUID_TYPE_LLT:
		if (ni_duid_create_pref_device(duid, type, nc, preferred))
			return TRUE;
		break;

	case NI_DUID_TYPE_UUID:
		if (ni_duid_create_uuid_machine_id(duid, NULL))
			return TRUE;
		if (ni_duid_create_uuid_dmi_product_id(duid, NULL))
			return TRUE;
		break;

	case NI_DUID_TYPE_ANY:
		if (ni_duid_create_pref_device(duid, NI_DUID_TYPE_LLT, nc, preferred))
			return TRUE;

		if (ni_duid_create_uuid_machine_id(duid, NULL))
			return TRUE;
		if (ni_duid_create_uuid_dmi_product_id(duid, NULL))
			return TRUE;

		/* Better using a random uuid than nothing?? */
		ni_uuid_generate(&uuid);
		if (ni_duid_init_uuid(duid, &uuid)) {
			ni_warn("Cannot create stable DUID, fallback to use a random UUID!");
			return TRUE;
		}

	default:
		break;
	}
	return FALSE;
}

