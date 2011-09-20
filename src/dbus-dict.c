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

#include <wicked/util.h>
#include <dbus/dbus.h>

#include "netinfo_priv.h"
#include "dbus-common.h"
#include "dbus-dict.h"


/**
 * Start a dict in a dbus message.  Should be paired with a call to
 * ni_dbus_dict_close_write().
 *
 * @param iter A valid dbus message iterator
 * @param iter_dict (out) A dict iterator to pass to further dict functions
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_open_write(DBusMessageIter *iter,
				     DBusMessageIter *iter_dict)
{
	dbus_bool_t result;

	if (!iter || !iter_dict)
		return FALSE;

	result = dbus_message_iter_open_container(
		iter,
		DBUS_TYPE_ARRAY,
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		DBUS_TYPE_STRING_AS_STRING
		DBUS_TYPE_VARIANT_AS_STRING
		DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
		iter_dict);
	return result;
}


/**
 * End a dict element in a dbus message.  Should be paired with
 * a call to ni_dbus_dict_open_write().
 *
 * @param iter valid dbus message iterator, same as passed to
 *    ni_dbus_dict_open_write()
 * @param iter_dict a dbus dict iterator returned from
 *    ni_dbus_dict_open_write()
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_close_write(DBusMessageIter *iter,
				      DBusMessageIter *iter_dict)
{
	if (!iter || !iter_dict)
		return FALSE;

	return dbus_message_iter_close_container(iter, iter_dict);
}


static dbus_bool_t __ni_dbus_add_dict_entry_start(
	DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry,
	const char *key)
{
	if (!key)
		return FALSE;

	if (!dbus_message_iter_open_container(iter_dict,
					      DBUS_TYPE_DICT_ENTRY, NULL,
					      iter_dict_entry))
		return FALSE;

	if (!dbus_message_iter_append_basic(iter_dict_entry, DBUS_TYPE_STRING,
					    &key))
		return FALSE;

	return TRUE;
}


static dbus_bool_t __ni_dbus_add_dict_entry_end(
	DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry,
	DBusMessageIter *iter_dict_val)
{
	if (!dbus_message_iter_close_container(iter_dict_entry, iter_dict_val))
		return FALSE;
	if (!dbus_message_iter_close_container(iter_dict, iter_dict_entry))
		return FALSE;

	return TRUE;
}


static dbus_bool_t __ni_dbus_add_dict_entry_basic(DBusMessageIter *iter_dict,
						  const char *key,
						  const int value_type,
						  const void *value)
{
	DBusMessageIter iter_dict_entry, iter_dict_val;
	const char *type_as_string = NULL;

	type_as_string = ni_dbus_type_as_string(value_type);
	if (!type_as_string)
		return FALSE;

	if (!__ni_dbus_add_dict_entry_start(iter_dict, &iter_dict_entry, key))
		return FALSE;

	if (!dbus_message_iter_open_container(&iter_dict_entry,
					      DBUS_TYPE_VARIANT,
					      type_as_string, &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_append_basic(&iter_dict_val, value_type, value))
		return FALSE;

	if (!__ni_dbus_add_dict_entry_end(iter_dict, &iter_dict_entry,
					  &iter_dict_val))
		return FALSE;

	return TRUE;
}

static dbus_bool_t __ni_dbus_add_dict_entry_byte_array(
	DBusMessageIter *iter_dict, const char *key,
	const char *value, const dbus_uint32_t value_len)
{
	DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
	dbus_uint32_t i;

	if (!__ni_dbus_add_dict_entry_start(iter_dict, &iter_dict_entry, key))
		return FALSE;

	if (!dbus_message_iter_open_container(&iter_dict_entry,
					      DBUS_TYPE_VARIANT,
					      DBUS_TYPE_ARRAY_AS_STRING
					      DBUS_TYPE_BYTE_AS_STRING,
					      &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container(&iter_dict_val, DBUS_TYPE_ARRAY,
					      DBUS_TYPE_BYTE_AS_STRING,
					      &iter_array))
		return FALSE;

	for (i = 0; i < value_len; i++) {
		if (!dbus_message_iter_append_basic(&iter_array,
						    DBUS_TYPE_BYTE,
						    &(value[i])))
			return FALSE;
	}

	if (!dbus_message_iter_close_container(&iter_dict_val, &iter_array))
		return FALSE;

	if (!__ni_dbus_add_dict_entry_end(iter_dict, &iter_dict_entry,
					  &iter_dict_val))
		return FALSE;

	return TRUE;
}

dbus_bool_t
ni_dbus_dict_append_variant(DBusMessageIter *iter_dict,
				      const char *key, const ni_dbus_variant_t *variant)
{
	DBusMessageIter iter_dict_entry;
	const char *type_as_string = NULL;
	dbus_bool_t rv;

	type_as_string = ni_dbus_variant_signature(variant);
	if (!type_as_string)
		return FALSE;

	if (!__ni_dbus_add_dict_entry_start(iter_dict, &iter_dict_entry, key))
		return FALSE;

	rv = ni_dbus_message_iter_append_variant(&iter_dict_entry, variant);
	if (!dbus_message_iter_close_container(iter_dict, &iter_dict_entry))
		rv = FALSE;

	return rv;
}

/**
 * Add a string entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The string value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
ni_dbus_dict_append_string(DBusMessageIter *iter_dict,
					const char *key, const char *value)
{
	if (!key || !value)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_STRING,
					      &value);
}


/**
 * Add a byte entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The byte value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_byte(DBusMessageIter *iter_dict,
				      const char *key, const char value)
{
	if (!key)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_BYTE,
					      &value);
}


/**
 * Add a boolean entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The boolean value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_bool(DBusMessageIter *iter_dict,
				      const char *key, const dbus_bool_t value)
{
	if (!key)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key,
					      DBUS_TYPE_BOOLEAN, &value);
}


/**
 * Add a 16-bit signed integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The 16-bit signed integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_int16(DBusMessageIter *iter_dict,
				       const char *key,
				       const dbus_int16_t value)
{
	if (!key)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_INT16,
					      &value);
}


/**
 * Add a 16-bit unsigned integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The 16-bit unsigned integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_uint16(DBusMessageIter *iter_dict,
					const char *key,
					const dbus_uint16_t value)
{
	if (!key)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_UINT16,
					      &value);
}


/**
 * Add a 32-bit signed integer to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The 32-bit signed integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_int32(DBusMessageIter *iter_dict,
				       const char *key,
				       const dbus_int32_t value)
{
	if (!key)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_INT32,
					      &value);
}


/**
 * Add a 32-bit unsigned integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The 32-bit unsigned integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_uint32(DBusMessageIter *iter_dict,
					const char *key,
					const dbus_uint32_t value)
{
	if (!key)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_UINT32,
					      &value);
}


/**
 * Add a 64-bit integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The 64-bit integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_int64(DBusMessageIter *iter_dict,
				       const char *key,
				       const dbus_int64_t value)
{
	if (!key)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_INT64,
					      &value);
}


/**
 * Add a 64-bit unsigned integer entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The 64-bit unsigned integer value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_uint64(DBusMessageIter *iter_dict,
					const char *key,
					const dbus_uint64_t value)
{
	if (!key)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_UINT64,
					      &value);
}


/**
 * Add a double-precision floating point entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The double-precision floating point value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_double(DBusMessageIter *iter_dict,
					const char * key,
					const double value)
{
	if (!key)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_DOUBLE,
					      &value);
}


/**
 * Add a DBus object path entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The DBus object path value
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_object_path(DBusMessageIter *iter_dict,
					     const char *key,
					     const char *value)
{
	if (!key || !value)
		return FALSE;
	return __ni_dbus_add_dict_entry_basic(iter_dict, key,
					      DBUS_TYPE_OBJECT_PATH, &value);
}


/**
 * Add a byte array entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param value The byte array
 * @param value_len The length of the byte array, in bytes
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_byte_array(DBusMessageIter *iter_dict,
					    const char *key,
					    const char *value,
					    const dbus_uint32_t value_len)
{
	if (!key)
		return FALSE;
	if (!value && (value_len != 0))
		return FALSE;
	return __ni_dbus_add_dict_entry_byte_array(iter_dict, key, value,
						   value_len);
}


/**
 * Begin a string array entry in the dict
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *                  ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param iter_dict_entry A private DBusMessageIter provided by the caller to
 *                        be passed to ni_dbus_dict_end_string_array()
 * @param iter_dict_val A private DBusMessageIter provided by the caller to
 *                      be passed to ni_dbus_dict_end_string_array()
 * @param iter_array On return, the DBusMessageIter to be passed to
 *                   ni_dbus_dict_string_array_add_element()
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_begin_string_array(DBusMessageIter *iter_dict,
					     const char *key,
					     DBusMessageIter *iter_dict_entry,
					     DBusMessageIter *iter_dict_val,
					     DBusMessageIter *iter_array)
{
	if (!iter_dict || !iter_dict_entry || !iter_dict_val || !iter_array)
		return FALSE;

	if (!__ni_dbus_add_dict_entry_start(iter_dict, iter_dict_entry, key))
		return FALSE;

	if (!dbus_message_iter_open_container(iter_dict_entry,
					      DBUS_TYPE_VARIANT,
					      DBUS_TYPE_ARRAY_AS_STRING
					      DBUS_TYPE_STRING_AS_STRING,
					      iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container(iter_dict_val, DBUS_TYPE_ARRAY,
					      DBUS_TYPE_BYTE_AS_STRING,
					      iter_array))
		return FALSE;

	return TRUE;
}


/**
 * Add a single string element to a string array dict entry
 *
 * @param iter_array A valid DBusMessageIter returned from
 *                   ni_dbus_dict_begin_string_array()'s
 *                   iter_array parameter
 * @param elem The string element to be added to the dict entry's string array
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_string_array_add_element(DBusMessageIter *iter_array,
						   const char *elem)
{
	if (!iter_array || !elem)
		return FALSE;

	return dbus_message_iter_append_basic(iter_array, DBUS_TYPE_STRING,
					      &elem);
}


/**
 * End a string array dict entry
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *                  ni_dbus_dict_open_write()
 * @param iter_dict_entry A private DBusMessageIter returned from
 *                        ni_dbus_dict_end_string_array()
 * @param iter_dict_val A private DBusMessageIter returned from
 *                      ni_dbus_dict_end_string_array()
 * @param iter_array A DBusMessageIter returned from
 *                   ni_dbus_dict_end_string_array()
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_end_string_array(DBusMessageIter *iter_dict,
					   DBusMessageIter *iter_dict_entry,
					   DBusMessageIter *iter_dict_val,
					   DBusMessageIter *iter_array)
{
	if (!iter_dict || !iter_dict_entry || !iter_dict_val || !iter_array)
		return FALSE;

	if (!dbus_message_iter_close_container(iter_dict_val, iter_array))
		return FALSE;

	if (!__ni_dbus_add_dict_entry_end(iter_dict, iter_dict_entry,
					  iter_dict_val))
		return FALSE;

	return TRUE;
}


/**
 * Convenience function to add an entire string array to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *                  ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param items The array of strings
 * @param num_items The number of strings in the array
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_append_string_array(DBusMessageIter *iter_dict,
					      const char *key,
					      const char **items,
					      const dbus_uint32_t num_items)
{
	DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
	dbus_uint32_t i;

	if (!key)
		return FALSE;
	if (!items && (num_items != 0))
		return FALSE;

	if (!ni_dbus_dict_begin_string_array(iter_dict, key,
					      &iter_dict_entry, &iter_dict_val,
					      &iter_array))
		return FALSE;

	for (i = 0; i < num_items; i++) {
		if (!ni_dbus_dict_string_array_add_element(&iter_array,
							    items[i]))
			return FALSE;
	}

	if (!ni_dbus_dict_end_string_array(iter_dict, &iter_dict_entry,
					    &iter_dict_val, &iter_array))
		return FALSE;

	return TRUE;
}


/**
 * Begin a string dict entry in the dict
 *
 * @param iter_parent_dict A valid DBusMessageIter returned from
 *                  ni_dbus_dict_open_write()
 * @param key The key of the dict item
 * @param iter_parent_entry A private DBusMessageIter provided by the caller to
 *                        be passed to ni_dbus_dict_end_string_dict()
 * @param iter_parent_val A private DBusMessageIter provided by the caller to
 *                      be passed to ni_dbus_dict_end_string_dict()
 * @param iter_child_dict On return, the DBusMessageIter to be passed to
 *                   ni_dbus_dict_string_dict_add_element()
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_begin_string_dict(DBusMessageIter *iter_parent_dict,
					     const char *key,
					     DBusMessageIter *iter_parent_entry,
					     DBusMessageIter *iter_parent_val,
					     DBusMessageIter *iter_child_dict)
{
	if (!iter_parent_dict || !iter_parent_entry || !iter_parent_val || !iter_child_dict)
		return FALSE;

	if (!__ni_dbus_add_dict_entry_start(iter_parent_dict, iter_parent_entry, key))
		return FALSE;

#if 0
	ni_debug_dbus("dbus_message_iter_open_container(%d, %s)",
					      DBUS_TYPE_VARIANT,
					      DBUS_TYPE_ARRAY_AS_STRING
					      DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					      DBUS_TYPE_STRING_AS_STRING
					      DBUS_TYPE_VARIANT_AS_STRING
					      DBUS_DICT_ENTRY_END_CHAR_AS_STRING);
#endif

	if (!dbus_message_iter_open_container(iter_parent_entry,
					      DBUS_TYPE_VARIANT,
					      DBUS_TYPE_ARRAY_AS_STRING
					      DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					      DBUS_TYPE_STRING_AS_STRING
					      DBUS_TYPE_VARIANT_AS_STRING
					      DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					      iter_parent_val))
		return FALSE;

	if (!ni_dbus_dict_open_write(iter_parent_val, iter_child_dict))
		return FALSE;

	return TRUE;
}


/**
 * End a string dict dict entry
 *
 * @param iter_parent_dict A valid DBusMessageIter returned from
 *                  ni_dbus_dict_open_write()
 * @param iter_parent_entry A private DBusMessageIter returned from
 *                        ni_dbus_dict_end_string_dict()
 * @param iter_parent_val A private DBusMessageIter returned from
 *                      ni_dbus_dict_end_string_dict()
 * @param iter_child_dict A DBusMessageIter returned from
 *                   ni_dbus_dict_end_string_dict()
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_end_string_dict(DBusMessageIter *iter_parent_dict,
					   DBusMessageIter *iter_parent_entry,
					   DBusMessageIter *iter_parent_val,
					   DBusMessageIter *iter_child_dict)
{
	if (!iter_parent_dict || !iter_parent_entry || !iter_parent_val || !iter_child_dict)
		return FALSE;

	if (!dbus_message_iter_close_container(iter_parent_val, iter_child_dict))
		return FALSE;

	if (!__ni_dbus_add_dict_entry_end(iter_parent_dict, iter_parent_entry,
					  iter_parent_val))
		return FALSE;

	return TRUE;
}

/*****************************************************/
/* Stuff for reading dicts                           */
/*****************************************************/

/**
 * Start reading from a dbus dict.
 *
 * @param iter A valid DBusMessageIter pointing to the start of the dict
 * @param iter_dict (out) A DBusMessageIter to be passed to
 *    ni_dbus_dict_read_next_entry()
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t ni_dbus_dict_open_read(DBusMessageIter *iter,
				    DBusMessageIter *iter_dict)
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
 *    ni_dbus_dict_open_read()
 * @param entry A valid dict entry object into which the dict key and value
 *    will be placed
 * @return TRUE on success, FALSE on failure
 *
 */
dbus_bool_t
ni_dbus_dict_get_entry(DBusMessageIter *iter_dict, struct ni_dbus_dict_entry *entry)
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
 * Return whether or not there are additional dictionary entries.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    ni_dbus_dict_open_read()
 * @return TRUE if more dict entries exists, FALSE if no more dict entries
 * exist
 */
dbus_bool_t ni_dbus_dict_has_dict_entry(DBusMessageIter *iter_dict)
{
	if (!iter_dict) {
		perror("ni_dbus_dict_has_dict_entry[dbus]: out of memory");
		return FALSE;
	}
	return dbus_message_iter_get_arg_type(iter_dict) ==
		DBUS_TYPE_DICT_ENTRY;
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
