/*
 * WPA Supplicant / dbus-based control interface
 * Copyright (c) 2006, Dan Williams <dcbw@redhat.com> and Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef DBUS_DICT_HELPERS_H
#define DBUS_DICT_HELPERS_H

/*
 * Reading a dict from a DBusMessage
 */

extern dbus_bool_t	ni_dbus_message_open_dict_read(DBusMessageIter *iter,
				    DBusMessageIter *iter_dict);
extern dbus_bool_t	ni_dbus_message_get_next_dict_entry(DBusMessageIter *iter_dict,
				    ni_dbus_dict_entry_t *entry);
extern void		ni_dbus_dict_entry_clear(ni_dbus_dict_entry_t *);

#endif  /* DBUS_DICT_HELPERS_H */
