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

dbus_bool_t ni_dbus_dict_append_string(DBusMessageIter *iter_dict,
					const char *key, const char *value);

dbus_bool_t ni_dbus_dict_append_byte(DBusMessageIter *iter_dict,
				      const char *key, const char value);

dbus_bool_t ni_dbus_dict_append_bool(DBusMessageIter *iter_dict,
				      const char *key,
				      const dbus_bool_t value);

dbus_bool_t ni_dbus_dict_append_int16(DBusMessageIter *iter_dict,
				       const char *key,
				       const dbus_int16_t value);

dbus_bool_t ni_dbus_dict_append_uint16(DBusMessageIter *iter_dict,
					const char *key,
					const dbus_uint16_t value);

dbus_bool_t ni_dbus_dict_append_int32(DBusMessageIter *iter_dict,
				       const char *key,
				       const dbus_int32_t value);

dbus_bool_t ni_dbus_dict_append_uint32(DBusMessageIter *iter_dict,
					const char *key,
					const dbus_uint32_t value);

dbus_bool_t ni_dbus_dict_append_int64(DBusMessageIter *iter_dict,
				       const char *key,
				       const dbus_int64_t value);

dbus_bool_t ni_dbus_dict_append_uint64(DBusMessageIter *iter_dict,
					const char *key,
					const dbus_uint64_t value);

dbus_bool_t ni_dbus_dict_append_double(DBusMessageIter *iter_dict,
					const char *key,
					const double value);

dbus_bool_t ni_dbus_dict_append_object_path(DBusMessageIter *iter_dict,
					     const char *key,
					     const char *value);

dbus_bool_t ni_dbus_dict_append_variant(DBusMessageIter *iter_dict,
				      const char *key, const ni_dbus_variant_t *);

dbus_bool_t ni_dbus_dict_append_byte_array(DBusMessageIter *iter_dict,
					    const char *key,
					    const char *value,
					    const dbus_uint32_t value_len);

/* Manual construction and addition of string array elements */
dbus_bool_t ni_dbus_dict_begin_string_array(DBusMessageIter *iter_dict,
                                             const char *key,
                                             DBusMessageIter *iter_dict_entry,
                                             DBusMessageIter *iter_dict_val,
                                             DBusMessageIter *iter_array);

dbus_bool_t ni_dbus_dict_string_array_add_element(DBusMessageIter *iter_array,
                                             const char *elem);

dbus_bool_t ni_dbus_dict_end_string_array(DBusMessageIter *iter_dict,
                                           DBusMessageIter *iter_dict_entry,
                                           DBusMessageIter *iter_dict_val,
                                           DBusMessageIter *iter_array);

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

struct ni_dbus_dict_entry {
	/* key of the dict entry */
	const char *		key;

	/* datum associated with key */
	ni_dbus_variant_t	datum;
};

extern dbus_bool_t	ni_dbus_dict_open_read(DBusMessageIter *iter,
				    DBusMessageIter *iter_dict);
extern dbus_bool_t	ni_dbus_dict_get_entry(DBusMessageIter *iter_dict,
				    struct ni_dbus_dict_entry *entry);
extern dbus_bool_t	ni_dbus_dict_has_dict_entry(DBusMessageIter *iter_dict);
extern void		ni_dbus_dict_entry_clear(ni_dbus_dict_entry_t *);

#endif  /* DBUS_DICT_HELPERS_H */
