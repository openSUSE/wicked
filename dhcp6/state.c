/*
 *	DHCP6 supplicant -- state files
 *
 *	Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/util.h>
#include <wicked/xml.h>

#include "dhcp6/duid.h"

#define CONFIG_DHCP6_DUID_NODE		"default-duid"
#define CONFIG_DHCP6_DUID_FILE		CONFIG_WICKED_STATEDIR "/dhcp6-duid.xml"
#define CONFIG_DHCP6_STATE_FILE		CONFIG_WICKED_STATEDIR "/dhcp6-state.xml"

/*
 * Use some locking here...
 */
int
ni_dhcp6_load_duid(ni_opaque_t *duid, const char *filename)
{
	const char *name = CONFIG_DHCP6_DUID_NODE;
	xml_node_t *xml = NULL;
	xml_node_t *node;
	FILE *fp;
	int rv;

	if (!filename)
		filename = CONFIG_DHCP6_DUID_FILE;
	else
		name = "duid";

	if ((fp = fopen(filename, "r")) == NULL) {
		if (errno != ENOENT)
			ni_error("unable to open %s for reading: %m", filename);
		return -1;
	}
	xml = xml_node_scan(fp);
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
		ni_error("%s: unable to parse %s xml file", filename, name);
		rv = -1;
	}

	xml_node_free(xml);
	return rv;
}

int
ni_dhcp6_save_duid(const ni_opaque_t *duid, const char *filename)
{
	const char *name = CONFIG_DHCP6_DUID_NODE;
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_opaque_t temp = NI_OPAQUE_INIT;
	xml_node_t *node;
	FILE *fp;
	int rv = -1;

	if (!duid || !duid->len) {
		ni_error("BUG: Refusing to save empty duid");
		return -1;
	}

	if (!filename)
		filename = CONFIG_DHCP6_DUID_FILE;
	else
		name = "duid";

	if(ni_dhcp6_load_duid(&temp, filename) == 0)
		return 1;

	ni_stringbuf_grow(&buf, duid->len * 3);
	ni_format_hex(duid->data, duid->len, buf.string, buf.size);

	if ((node = xml_node_new(name, NULL)) == NULL) {
		ni_stringbuf_destroy(&buf);
		ni_error("Unable to create %s xml node: %m", name);
		return -1;
	}

	node->cdata = buf.string;

	if ((fp = fopen(filename, "w")) == NULL) {
		ni_error("%s: unable to open file for writing: %m", filename);
	}
	else
	if ((rv = xml_node_print(node, fp)) < 0) {
		ni_error("%s: unable to write %s xml representation",
				filename, name);
	}

	xml_node_free(node);
	fclose(fp);

	if(rv < 0)
		unlink(filename);
	return rv;
}
