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
 * Adding a dict to a DBusMessage
 */

dbus_bool_t ni_dbus_dict_open_write(DBusMessageIter *iter,
				     DBusMessageIter *iter_dict);

dbus_bool_t ni_dbus_dict_close_write(DBusMessageIter *iter,
				      DBusMessageIter *iter_dict);

dbus_bool_t ni_dbus_dict_append_variant(DBusMessageIter *iter_dict,
				      const char *key, const ni_dbus_variant_t *);

/* Convenience function to add a whole string list */
dbus_bool_t ni_dbus_dict_append_string_array(DBusMessageIter *iter_dict,
					      const char *key,
					      const char **items,
					      const dbus_uint32_t num_items);

dbus_bool_t ni_dbus_dict_begin_string_dict(DBusMessageIter *iter_parent_dict,
					     const char *key,
					     DBusMessageIter *iter_parent_entry,
					     DBusMessageIter *iter_parent_val,
					     DBusMessageIter *iter_child_dict);

dbus_bool_t ni_dbus_dict_end_string_dict(DBusMessageIter *iter_parent_dict,
					   DBusMessageIter *iter_parent_entry,
					   DBusMessageIter *iter_parent_val,
					   DBusMessageIter *iter_child_dict);

/*
 * Reading a dict from a DBusMessage
 */

extern dbus_bool_t	ni_dbus_dict_open_read(DBusMessageIter *iter,
				    DBusMessageIter *iter_dict);
extern dbus_bool_t	ni_dbus_dict_get_entry(DBusMessageIter *iter_dict,
				    ni_dbus_dict_entry_t *entry);
extern void		ni_dbus_dict_entry_clear(ni_dbus_dict_entry_t *);

#endif  /* DBUS_DICT_HELPERS_H */
