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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>

#include "netinfo_priv.h"
#include "dbus-common.h"
#include "dbus-dict.h"

/**
 * Start reading from a dbus dict.
 *
 * @param iter A valid DBusMessageIter pointing to the start of the dict
 * @param iter_dict (out) A DBusMessageIter to be passed to
 *    ni_dbus_dict_read_next_entry()
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
ni_dbus_message_open_dict_read(DBusMessageIter *iter, DBusMessageIter *iter_dict)
{
	if (!iter || !iter_dict)
		return FALSE;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY ||
	    dbus_message_iter_get_element_type(iter) != DBUS_TYPE_DICT_ENTRY)
		return FALSE;

	dbus_message_iter_recurse(iter, iter_dict);
	return TRUE;
}


/**
 * Read the current key/value entry from the dict.  Entries are dynamically
 * allocated when needed and must be freed after use with the
 * ni_dbus_dict_entry_clear() function.
 *
 * The returned entry object will be filled with the type and value of the next
 * entry in the dict, or the type will be DBUS_TYPE_INVALID if an error
 * occurred.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_message_open_dict_read()
 * @param entry A valid dict entry object into which the dict key and value
 *    will be placed
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
ni_dbus_message_get_next_dict_entry(DBusMessageIter *iter_dict, struct ni_dbus_dict_entry *entry)
{
	DBusMessageIter iter_dict_entry;
	const char *key;

	if (!iter_dict || !entry)
		goto error;

	if (dbus_message_iter_get_arg_type(iter_dict) != DBUS_TYPE_DICT_ENTRY)
		goto error;

	dbus_message_iter_recurse(iter_dict, &iter_dict_entry);

	if (dbus_message_iter_get_arg_type(&iter_dict_entry) != DBUS_TYPE_STRING)
		goto error;
	dbus_message_iter_get_basic(&iter_dict_entry, &key);
	entry->key = key;

	if (!dbus_message_iter_next(&iter_dict_entry))
		goto error;

	if (!ni_dbus_message_iter_get_variant(&iter_dict_entry, &entry->datum))
		goto error;

	dbus_message_iter_next(iter_dict);
	return TRUE;

error:
	if (entry)
		ni_dbus_dict_entry_clear(entry);

	return FALSE;
}


/**
 * Free any memory used by the entry object.
 *
 * @param entry The entry object
 */
void ni_dbus_dict_entry_clear(struct ni_dbus_dict_entry *entry)
{
	if (!entry)
		return;
	ni_dbus_variant_destroy(&entry->datum);
	memset(entry, 0, sizeof(*entry));
}
