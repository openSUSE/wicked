/*
 * Convenience functions for marshalling dbus messages
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <wicked/util.h>
#include <wicked/dbus.h>

#include "netinfo_priv.h"
#include "dbus-common.h"


dbus_bool_t
ni_dbus_message_iter_append_byte_array(DBusMessageIter *iter,
				const unsigned char *value, unsigned int len)
{
	DBusMessageIter iter_array;
	unsigned int i;

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					      DBUS_TYPE_BYTE_AS_STRING,
					      &iter_array))
		return FALSE;

	for (i = 0; i < len; i++) {
		if (!dbus_message_iter_append_basic(&iter_array,
						    DBUS_TYPE_BYTE,
						    &(value[i])))
			return FALSE;
	}

	if (!dbus_message_iter_close_container(iter, &iter_array))
		return FALSE;

	return TRUE;
}

dbus_bool_t
ni_dbus_message_iter_append_string_array(DBusMessageIter *iter,
				char **string_array, unsigned int len)
{
	DBusMessageIter iter_array;
	unsigned int i;

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					      DBUS_TYPE_STRING_AS_STRING,
					      &iter_array))
		return FALSE;

	for (i = 0; i < len; i++) {
		if (!dbus_message_iter_append_basic(&iter_array,
						    DBUS_TYPE_STRING,
						    &string_array[i]))
			return FALSE;
	}

	if (!dbus_message_iter_close_container(iter, &iter_array))
		return FALSE;

	return TRUE;
}

dbus_bool_t
ni_dbus_message_iter_append_dict_entry(DBusMessageIter *iter,
				const ni_dbus_dict_entry_t *entry)
{
	DBusMessageIter iter_dict_entry;

	if (!dbus_message_iter_open_container(iter,
					      DBUS_TYPE_DICT_ENTRY, NULL,
					      &iter_dict_entry))
		return FALSE;

	if (!dbus_message_iter_append_basic(&iter_dict_entry, DBUS_TYPE_STRING,
					    &entry->key))
		return FALSE;

	if (!ni_dbus_message_iter_append_variant(&iter_dict_entry, &entry->datum))
		return FALSE;

	if (!dbus_message_iter_close_container(iter, &iter_dict_entry))
		return FALSE;

	return TRUE;
}

dbus_bool_t
ni_dbus_message_iter_append_dict(DBusMessageIter *iter,
				const ni_dbus_dict_entry_t *dict_array, unsigned int len)
{
	DBusMessageIter iter_array;
	unsigned int i;

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					      DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					      DBUS_TYPE_STRING_AS_STRING
					      DBUS_TYPE_VARIANT_AS_STRING
					      DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					      &iter_array))
		return FALSE;

	for (i = 0; i < len; i++) {
		if (!ni_dbus_message_iter_append_dict_entry(&iter_array,
							&dict_array[i]))
			return FALSE;
	}

	if (!dbus_message_iter_close_container(iter, &iter_array))
		return FALSE;

	return TRUE;
}

dbus_bool_t
ni_dbus_message_iter_append_variant(DBusMessageIter *iter, const ni_dbus_variant_t *variant)
{
	const char *type_as_string = NULL;
	const void *value;
	DBusMessageIter iter_val;
	dbus_bool_t rv = FALSE;

	type_as_string = ni_dbus_variant_signature(variant);
	if (!type_as_string)
		return FALSE;

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, type_as_string, &iter_val))
		return FALSE;

	value = ni_dbus_variant_datum_const_ptr(variant);
	if (value != NULL) {
		rv = dbus_message_iter_append_basic(&iter_val, variant->type, value);
	} else
	if (variant->type == DBUS_TYPE_ARRAY) {
		switch (variant->array.element_type) {
		case DBUS_TYPE_BYTE:
			rv = ni_dbus_message_iter_append_byte_array(&iter_val,
					variant->byte_array_value, variant->array.len);
			break;

		case DBUS_TYPE_STRING:
			rv = ni_dbus_message_iter_append_string_array(&iter_val,
					variant->string_array_value, variant->array.len);
			break;

		case DBUS_TYPE_DICT_ENTRY:
			rv = ni_dbus_message_iter_append_dict(&iter_val,
					variant->dict_array_value, variant->array.len);
			break;

		default:
			ni_warn("%s: variant type %s not supported", __FUNCTION__, type_as_string);
		}
	} else {
		ni_warn("%s: variant type %s not supported", __FUNCTION__, type_as_string);
	}

	if (rv)
		rv = dbus_message_iter_close_container(iter, &iter_val);

	return rv;
}

dbus_bool_t
ni_dbus_message_iter_get_byte_array(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	ni_dbus_variant_set_byte_array(variant, 0, NULL);

	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_BYTE) {
		unsigned char byte;

		dbus_message_iter_get_basic(iter, &byte);
		ni_dbus_variant_append_byte_array(variant, byte);
		dbus_message_iter_next(iter);
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_message_iter_get_string_array(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	ni_dbus_variant_set_string_array(variant, 0, NULL);
	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRING) {
		const char *value;

		dbus_message_iter_get_basic(iter, &value);
		ni_dbus_variant_append_string_array(variant, value);
		dbus_message_iter_next(iter);
	}

	return TRUE;
}


static dbus_bool_t
ni_dbus_message_iter_get_array(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	int array_type = dbus_message_iter_get_element_type(iter);
	dbus_bool_t success = FALSE;
	DBusMessageIter iter_array;

	if (!variant)
		return FALSE;

	dbus_message_iter_recurse(iter, &iter_array);

	switch (array_type) {
	case DBUS_TYPE_BYTE:
		success = ni_dbus_message_iter_get_byte_array(&iter_array, variant);
		break;
	case DBUS_TYPE_STRING:
		success = ni_dbus_message_iter_get_string_array(&iter_array, variant);
		break;
	default:
		break;
	}

	return success;
}


dbus_bool_t
ni_dbus_message_iter_get_variant_data(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	void *value;

	ni_dbus_variant_destroy(variant);
	variant->type = dbus_message_iter_get_arg_type(iter);

	value = ni_dbus_variant_datum_ptr(variant);
	if (value != NULL) {
		/* Basic types */
		dbus_message_iter_get_basic(iter, value);

		if (variant->type == DBUS_TYPE_STRING
		 || variant->type == DBUS_TYPE_OBJECT_PATH)
			variant->string_value = xstrdup(variant->string_value);
	} else if (variant->type == DBUS_TYPE_ARRAY) {
		if (!ni_dbus_message_iter_get_array(iter, variant))
			return FALSE;
	} else {
		/* FIXME: need to handle other types here */
		return FALSE;
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_message_iter_get_variant(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	DBusMessageIter iter_val;
	int type;

	ni_dbus_variant_destroy(variant);

	type = dbus_message_iter_get_arg_type(iter);
	if (type != DBUS_TYPE_VARIANT)
		return FALSE;

	dbus_message_iter_recurse(iter, &iter_val);
	return ni_dbus_message_iter_get_variant_data(&iter_val, variant);
}


