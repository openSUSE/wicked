/*
 *	wicked client configuration reading in dracut.
 *
 *	Copyright (C) 2019 SÜSE Software Solutions Germany GmbH, Nuernberg, Germany.
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
 *		Rubén Torrero Marijnissen <rtorreromarijnissen@suse.com>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <wicked/types.h>
#include <wicked/util.h>

#include "client/read-config.h"
#include "client/dracut/dracut.h"
#include "client/dracut/cmdline.h"

static const ni_ifconfig_type_t *
ni_ifconfig_guess_dracut_type(const ni_ifconfig_type_t *map, const char *root, const char *path)
{
	return ni_ifconfig_find_map(map, "cmdline", sizeof("cmdline")-1);
}

static const ni_ifconfig_type_t		ni_ifconfig_types_dracut[] = {
	{ "cmdline",	{ .read = ni_ifconfig_read_dracut_cmdline } },
	{ NULL,		{ .guess = ni_ifconfig_guess_dracut_type  } },
};

ni_bool_t
ni_ifconfig_read_dracut(xml_document_array_t *array,
			const char *type, const char *root, const char *path,
			ni_ifconfig_kind_t kind, ni_bool_t prio, ni_bool_t raw)
{
	return ni_ifconfig_read_subtype(array, ni_ifconfig_types_dracut,
					root, path, kind, prio, raw, type);
}
