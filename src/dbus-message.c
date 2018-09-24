/*
 * Convenience functions for marshalling dbus messages
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include <wicked/dbus.h>
#include <wicked/logging.h>

#include "util_priv.h"
#include "dbus-common.h"
#include "dbus-dict.h"
#include "debug.h"

static dbus_bool_t	ni_dbus_message_iter_get_array(DBusMessageIter *, ni_dbus_variant_t *);

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

static dbus_bool_t
__ni_dbus_message_iter_append_string_array(DBusMessageIter *iter, const char *element_signature,
				char **string_array, unsigned int len)
{
	unsigned char element_type = element_signature[0];
	DBusMessageIter iter_array;
	unsigned int i;

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, element_signature, &iter_array))
		return FALSE;

	for (i = 0; i < len; i++) {
		if (!dbus_message_iter_append_basic(&iter_array, element_type, &string_array[i]))
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
	return __ni_dbus_message_iter_append_string_array(iter, DBUS_TYPE_STRING_AS_STRING, string_array, len);
}

dbus_bool_t
ni_dbus_message_iter_append_object_path_array(DBusMessageIter *iter,
				char **string_array, unsigned int len)
{
	return __ni_dbus_message_iter_append_string_array(iter, DBUS_TYPE_OBJECT_PATH_AS_STRING, string_array, len);
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
	{
		const ni_dbus_variant_t *v = &entry->datum;
		ni_error("failed to append variant, type=%s/%c, value=\"%s\"",
					ni_dbus_variant_signature(v), v->type,
					ni_dbus_variant_sprint(v));
		return FALSE;
	}

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
ni_dbus_message_iter_append_struct(DBusMessageIter *iter, const ni_dbus_variant_t *variant_array, unsigned int len)
{
	DBusMessageIter iter_array;
	unsigned int i;
	dbus_bool_t rv = TRUE;

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT,
					      NULL,
					      &iter_array))
		return FALSE;

	for (i = 0; rv && i < len; i++) {
		rv = ni_dbus_message_iter_append_value(&iter_array,
						    &variant_array[i], NULL);
	}

	if (!dbus_message_iter_close_container(iter, &iter_array))
		rv = FALSE;

	return rv;
}

dbus_bool_t
ni_dbus_message_iter_append_variant_array(DBusMessageIter *iter,
				const ni_dbus_variant_t *variant_array, unsigned int len)
{
	DBusMessageIter iter_array;
	unsigned int i;
	dbus_bool_t rv = TRUE;

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					      DBUS_TYPE_VARIANT_AS_STRING,
					      &iter_array))
		return FALSE;

	for (i = 0; rv && i < len; i++) {
		rv = ni_dbus_message_iter_append_variant(&iter_array,
						    &variant_array[i]);
	}

	if (!dbus_message_iter_close_container(iter, &iter_array))
		rv = FALSE;

	return rv;
}

dbus_bool_t
ni_dbus_message_iter_append_some_array(DBusMessageIter *iter,
				const char *element_signature,
				const ni_dbus_variant_t *values,
				unsigned int len)
{
	DBusMessageIter iter_array;
	unsigned int i;
	dbus_bool_t rv = TRUE;

	if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					      element_signature,
					      &iter_array))
		return FALSE;

	for (i = 0; rv && i < len; i++) {
		rv = ni_dbus_message_iter_append_value(&iter_array,
						    &values[i],
						    element_signature);
	}

	if (!dbus_message_iter_close_container(iter, &iter_array))
		rv = FALSE;

	return rv;
}

dbus_bool_t
ni_dbus_message_iter_append_value(DBusMessageIter *iter, const ni_dbus_variant_t *variant, const char *signature)
{
	const void *value;
	DBusMessageIter *iter_val, _iter_val;
	dbus_bool_t rv = FALSE;

	iter_val = iter;
	if (signature == NULL) {
		if (!(signature = ni_dbus_variant_signature(variant)))
			return FALSE;
	} else
	if (signature[0] == DBUS_TYPE_VARIANT) {
		if (!(signature = ni_dbus_variant_signature(variant)))
			return FALSE;

		if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, signature, &_iter_val))
			return FALSE;
		iter_val = &_iter_val;
	}

	value = ni_dbus_variant_datum_const_ptr(variant);
	if (value != NULL) {
		const char *empty = "";

		if (!strcmp(signature, DBUS_TYPE_STRING_AS_STRING) && !*(const char **) value)
			value = &empty;
		rv = dbus_message_iter_append_basic(iter_val, variant->type, value);
	} else
	if (variant->type == DBUS_TYPE_ARRAY) {
		switch (variant->array.element_type) {
		case DBUS_TYPE_BYTE:
			rv = ni_dbus_message_iter_append_byte_array(iter_val,
					variant->byte_array_value, variant->array.len);
			break;

		case DBUS_TYPE_STRING:
			rv = ni_dbus_message_iter_append_string_array(iter_val,
					variant->string_array_value, variant->array.len);
			break;

		case DBUS_TYPE_OBJECT_PATH:
			rv = ni_dbus_message_iter_append_object_path_array(iter_val,
					variant->string_array_value, variant->array.len);
			break;

		case DBUS_TYPE_VARIANT:
			rv = ni_dbus_message_iter_append_variant_array(iter_val,
					variant->variant_array_value, variant->array.len);
			break;

		case DBUS_TYPE_DICT_ENTRY:
			rv = ni_dbus_message_iter_append_dict(iter_val,
					variant->dict_array_value, variant->array.len);
			break;

		case DBUS_TYPE_INVALID:
			rv = ni_dbus_message_iter_append_some_array(iter_val,
					variant->array.element_signature,
					variant->variant_array_value,
					variant->array.len);
			break;

		default:
			ni_warn("%s: variant type %s not supported", __FUNCTION__, signature);
		}
	} else
	if (variant->type == DBUS_TYPE_STRUCT) {
		rv = ni_dbus_message_iter_append_struct(iter_val, variant->struct_value, variant->array.len);
	} else {
		ni_warn("%s: variant type %s not supported", __FUNCTION__, signature);
	}

	if (iter_val != iter && !dbus_message_iter_close_container(iter, iter_val))
		rv = FALSE;

	return rv;
}

dbus_bool_t
ni_dbus_message_iter_append_variant(DBusMessageIter *iter, const ni_dbus_variant_t *variant)
{
	return ni_dbus_message_iter_append_value(iter, variant, DBUS_TYPE_VARIANT_AS_STRING);
}

dbus_bool_t
ni_dbus_message_iter_get_byte_array(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	ni_dbus_variant_init_byte_array(variant);

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
	ni_dbus_variant_init_string_array(variant);
	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRING) {
		const char *value;

		dbus_message_iter_get_basic(iter, &value);
		ni_dbus_variant_append_string_array(variant, value);
		dbus_message_iter_next(iter);
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_message_iter_get_object_path_array(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	ni_dbus_variant_init_object_path_array(variant);
	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_OBJECT_PATH) {
		const char *value;

		dbus_message_iter_get_basic(iter, &value);
		ni_dbus_variant_append_object_path_array(variant, value);
		dbus_message_iter_next(iter);
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_message_iter_get_array_array(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	dbus_bool_t rv = TRUE;
	char *signature;

	if (!(signature = dbus_message_iter_get_signature(iter)))
		return FALSE;

	ni_dbus_array_array_init(variant, signature);
	ni_string_free(&signature);

	while (rv && dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_ARRAY) {
		ni_dbus_variant_t *elem;

		elem = ni_dbus_array_array_add(variant);
		rv = ni_dbus_message_iter_get_array(iter, elem);
		dbus_message_iter_next(iter);
	}

	return rv;
}

dbus_bool_t
ni_dbus_message_iter_get_dict(DBusMessageIter *iter, ni_dbus_variant_t *result)
{
	DBusMessageIter iter_dict;

	ni_dbus_variant_init_dict(result);

	if (!ni_dbus_message_open_dict_read(iter, &iter_dict))
		return FALSE;

	while (1) {
		ni_dbus_dict_entry_t entry;
		ni_dbus_variant_t *ev;

		memset(&entry, 0, sizeof(entry));
		if (!ni_dbus_message_get_next_dict_entry(&iter_dict, &entry))
			break;

		ev = ni_dbus_dict_add(result, entry.key);
		*ev = entry.datum;
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_message_iter_get_variant_array(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	dbus_bool_t rv = TRUE;

	ni_dbus_variant_init_variant_array(variant);
	while (rv && dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_VARIANT) {
		ni_dbus_variant_t *elem;

		elem = ni_dbus_variant_append_variant_element(variant);
		rv = ni_dbus_message_iter_get_variant(iter, elem);
		dbus_message_iter_next(iter);
	}

	return rv;
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
	case DBUS_TYPE_OBJECT_PATH:
		success = ni_dbus_message_iter_get_object_path_array(&iter_array, variant);
		break;
	case DBUS_TYPE_DICT_ENTRY:
		success = ni_dbus_message_iter_get_dict(iter, variant);
		break;
	case DBUS_TYPE_ARRAY:
		success = ni_dbus_message_iter_get_array_array(&iter_array, variant);
		break;
	case DBUS_TYPE_VARIANT:
		success = ni_dbus_message_iter_get_variant_array(&iter_array, variant);
		break;
	default:
		ni_debug_dbus("%s: cannot decode array of type %c", __FUNCTION__, array_type);
		break;
	}

	return success;
}

static dbus_bool_t
ni_dbus_message_iter_get_struct(DBusMessageIter *iter, ni_dbus_variant_t *variant)
{
	DBusMessageIter iter_struct;
	int type;

	if (!variant)
		return FALSE;

	dbus_message_iter_recurse(iter, &iter_struct);

	while ((type = dbus_message_iter_get_arg_type(&iter_struct)) != 0) {
		ni_dbus_variant_t *member;

		member = ni_dbus_struct_add(variant);
		if (!member)
			return FALSE;

		if (!ni_dbus_message_iter_get_variant_data(&iter_struct, member))
			return FALSE;
		dbus_message_iter_next(&iter_struct);
	}

	return TRUE;
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
	} else if (variant->type == DBUS_TYPE_STRUCT) {
		if (!ni_dbus_message_iter_get_struct(iter, variant))
			return FALSE;
	} else {
		/* FIXME: need to handle other types here */
		ni_debug_dbus("%s: cannot handle message with %c data", __func__, variant->type);
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

/*
 * Append one or more variants to a dbus message
 */
dbus_bool_t
ni_dbus_message_serialize_variants(ni_dbus_message_t *msg,
			unsigned int nargs, const ni_dbus_variant_t *argv,
			DBusError *error)
{
	DBusMessageIter iter;
	unsigned int i;

	dbus_message_iter_init_append(msg, &iter);
	for (i = 0; i < nargs; ++i) {
#if 0
		ni_debug_dbus("  [%u]: type=%s, value=\"%s\"", i,
				ni_dbus_variant_signature(&argv[i]),
				ni_dbus_variant_sprint(&argv[i]));
#endif
		if (!ni_dbus_message_iter_append_value(&iter, &argv[i], NULL)) {
			ni_error("error marshalling message, type=%s, value=\"%s\"",
					ni_dbus_variant_signature(&argv[i]),
					ni_dbus_variant_sprint(&argv[i]));
			dbus_set_error(error,
					DBUS_ERROR_FAILED,
					"Error marshalling message arguments");
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * Helper functions
 */
dbus_bool_t
ni_dbus_message_append_byte(ni_dbus_message_t *msg, unsigned char value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_BYTE, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_uint16(ni_dbus_message_t *msg, uint16_t value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_UINT16, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_uint32(ni_dbus_message_t *msg, uint32_t value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_UINT32, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_uint64(ni_dbus_message_t *msg, uint64_t value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_UINT64, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_int16(ni_dbus_message_t *msg, int16_t value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_INT16, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_int32(ni_dbus_message_t *msg, int32_t value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_INT32, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_int64(ni_dbus_message_t *msg, int64_t value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_INT64, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_string(ni_dbus_message_t *msg, const char * value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_STRING, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_object_path(ni_dbus_message_t *msg, const char * value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_double(ni_dbus_message_t *msg, double value)
{
	return dbus_message_append_args(msg, DBUS_TYPE_DOUBLE, &value, 0);
}

dbus_bool_t
ni_dbus_message_append_uuid(ni_dbus_message_t *msg, const ni_uuid_t *uuid)
{
	DBusMessageIter iter;

	dbus_message_iter_init_append(msg, &iter);
	return ni_dbus_message_iter_append_byte_array(&iter, uuid->octets, sizeof(uuid->octets));
}
