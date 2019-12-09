/*
 *	wicked client configuration reading in dracut.
 *
 *	Copyright (C) 2019 SUSE Software Solutions Germany GmbH, Nuernberg, Germany.
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
#ifndef WICKED_CLIENT_DRACUT_H
#define WICKED_CLIENT_DRACUT_H

#include <wicked/types.h>

extern ni_bool_t			ni_ifconfig_read_dracut(xml_document_array_t *,
						const char *, const char *, const char *,
						ni_ifconfig_kind_t, ni_bool_t, ni_bool_t);

#endif /* WICKED_CLIENT_DRACUT_H */
