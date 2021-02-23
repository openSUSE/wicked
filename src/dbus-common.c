/*
 * Common DBus functions
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/dbus-errors.h>
#include "socket_priv.h"
#include "dbus-common.h"
#include "dbus-dict.h"
#include "debug.h"

int
ni_dbus_translate_error(const DBusError *err, const ni_intmap_t *error_map)
{
	unsigned int errcode;

	ni_debug_dbus("%s(%s, msg=%s)", __func__, err->name, err->message);
	/* allow parsing as number, ... but verify it's a valid error name */
	if (ni_parse_uint_maybe_mapped(err->name, error_map, &errcode, 10) == 0)
		return -errcode;

	return ni_dbus_get_error(err, NULL);
}

/*
 * Deserialize message
 *
 * We need this wrapper function because dbus_message_get_args_valist
 * does not copy any strings, but returns char pointers that point at
 * the message body. Which is bad if you want to access these strings
 * after you've freed the message.
 */
int
ni_dbus_message_get_args(ni_dbus_message_t *msg, ...)
{
	DBusError error;
	va_list ap;
	int rv = 0, type;

	dbus_error_init(&error);
	va_start(ap, msg);

	type = va_arg(ap, int);
	if (type
	 && !dbus_message_get_args_valist(msg, &error, type, ap)) {
		ni_error("%s: unable to retrieve msg data", __FUNCTION__);
		rv = -NI_ERROR_INVALID_ARGS;
		goto done;
	}

	/* Reset va_list */
	va_end(ap);
	va_start(ap, msg);

	while (TRUE) {
		char **data;

		type = va_arg(ap, int);
		switch (type) {
		case DBUS_TYPE_INVALID:
			goto done;

		case DBUS_TYPE_STRING:
		case DBUS_TYPE_OBJECT_PATH:
			data = va_arg(ap, char **);
			if (data && *data)
				*data = xstrdup(*data);
			break;

		default:
			(void) va_arg(ap, void *);
			break;
		}
	}

done:
	va_end(ap);
	return rv;
}

/*
 * Deserialize message and store data in an array of variant objects
 */
int
ni_dbus_message_get_args_variants(ni_dbus_message_t *msg, ni_dbus_variant_t *argv, unsigned int max_args)
{
	DBusMessageIter iter;
	unsigned int argc = 0;

	dbus_message_iter_init(msg, &iter);
	for (argc = 0; argc < max_args; ++argc) {
		DBusMessageIter *iter_p = &iter, iter_val;

		if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_INVALID)
			break;

		/* As a matter of convenience to the coder,
		 * automatically drill into arguments that are wrapped in a variant */
		if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_VARIANT) {
			dbus_message_iter_recurse(&iter, &iter_val);
			iter_p = &iter_val;
		}

		if (!ni_dbus_message_iter_get_variant_data(iter_p, &argv[argc])) {
			do {
				ni_dbus_variant_destroy(&argv[argc]);
			} while (argc--);
			return -1;
		}

		/* We keep a reference to the dbus message in this variant variable,
		 * because the caller may decide to free the message (eg in
		 * ni_dbus_object_call_variant()). However, some strings we use point
		 * directly into the message; such as the dict keys.
		 */
		argv[argc].__message = dbus_message_ref(msg);
		dbus_message_iter_next(&iter);
	}

	return argc;
}

/*
 * Test for array-ness
 */
static inline dbus_bool_t
__ni_dbus_is_array(const ni_dbus_variant_t *var, const char *element_signature)
{
	if (var->type != DBUS_TYPE_ARRAY)
		return FALSE;
	if (var->array.element_type != DBUS_TYPE_INVALID)
		return element_signature[0] == var->array.element_type
		    && element_signature[1] == '\0';
	if (var->array.element_signature != NULL)
		return !strcmp(var->array.element_signature, element_signature);
	return FALSE;
}

dbus_bool_t
ni_dbus_variant_is_array_of(const ni_dbus_variant_t *var, const char *signature)
{
	return __ni_dbus_is_array(var, signature);
}

dbus_bool_t
ni_dbus_variant_is_dict(const ni_dbus_variant_t *var)
{
	return __ni_dbus_is_array(var, DBUS_TYPE_DICT_ENTRY_AS_STRING);
}

dbus_bool_t
ni_dbus_variant_is_dict_array(const ni_dbus_variant_t *var)
{
	return __ni_dbus_is_array(var, NI_DBUS_DICT_SIGNATURE);
}

dbus_bool_t
ni_dbus_variant_is_string_array(const ni_dbus_variant_t *var)
{
	return __ni_dbus_is_array(var, DBUS_TYPE_STRING_AS_STRING);
}

dbus_bool_t
ni_dbus_variant_is_object_path_array(const ni_dbus_variant_t *var)
{
	return __ni_dbus_is_array(var, DBUS_TYPE_OBJECT_PATH_AS_STRING);
}

/*
 * Get/set functions for variant values
 */
static inline void
__ni_dbus_variant_change_type(ni_dbus_variant_t *var, int new_type)
{
	if (var->type == new_type)
		return;
	if (var->type != DBUS_TYPE_INVALID) {
		if (var->type == DBUS_TYPE_STRING
		 || var->type == DBUS_TYPE_OBJECT_PATH
		 || var->type == DBUS_TYPE_ARRAY
		 || var->type == DBUS_TYPE_STRUCT
		 || var->type == DBUS_TYPE_VARIANT)
			ni_dbus_variant_destroy(var);
	}
	var->type = new_type;
}

static inline void
__ni_dbus_init_array(ni_dbus_variant_t *var, int element_type)
{
	var->type = DBUS_TYPE_ARRAY;
	var->array.element_type = element_type;
}

static inline void
__ni_dbus_init_array_signature(ni_dbus_variant_t *var, const char *element_sig)
{
	int element_type;

	var->type = DBUS_TYPE_ARRAY;

	element_type = element_sig[0];
	if (element_sig[1] == DBUS_TYPE_INVALID && ni_dbus_type_as_string(element_type)) {
		/* It's an array of basic types */
		var->array.element_type = element_type;
	} else {
		ni_string_dup(&var->array.element_signature, element_sig);
	}
}

/*
 * Initialize a variant using the specified type signature
 */
dbus_bool_t
ni_dbus_variant_init_signature(ni_dbus_variant_t *var, const char *sig)
{
	const char *sig_orig = sig;
	int type;

	ni_dbus_variant_destroy(var);

	/* Check if it's a basic type */
	type = *sig++;

	if (type == DBUS_TYPE_INVALID)
		goto sick_nature;

	if (*sig == DBUS_TYPE_INVALID && ni_dbus_type_as_string(type)) {
		var->type = type;
		return TRUE;
	}

	if (type == DBUS_TYPE_ARRAY) {
		if (*sig == DBUS_TYPE_INVALID)
			goto sick_nature;
		if (!strcmp(sig, DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				 DBUS_TYPE_STRING_AS_STRING
				 DBUS_TYPE_VARIANT_AS_STRING
				 DBUS_DICT_ENTRY_END_CHAR_AS_STRING))
			__ni_dbus_init_array(var, DBUS_TYPE_DICT_ENTRY);
		else
			__ni_dbus_init_array_signature(var, sig);
		return TRUE;
	}

sick_nature:
	ni_debug_dbus("%s: cannot parse signature %s", __func__, sig_orig);
	return FALSE;
}

void
ni_dbus_variant_set_string(ni_dbus_variant_t *var, const char *value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_STRING);
	ni_string_dup(&var->string_value, value);
}

void
ni_dbus_variant_set_object_path(ni_dbus_variant_t *var, const char *value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_OBJECT_PATH);
	ni_string_dup(&var->string_value, value);
}

void
ni_dbus_variant_set_bool(ni_dbus_variant_t *var, dbus_bool_t value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_BOOLEAN);
	var->bool_value = value;
}

void
ni_dbus_variant_set_byte(ni_dbus_variant_t *var, unsigned char value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_BYTE);
	var->byte_value = value;
}

void
ni_dbus_variant_set_uint16(ni_dbus_variant_t *var, uint16_t value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_UINT16);
	var->uint16_value = value;
}

void
ni_dbus_variant_set_int16(ni_dbus_variant_t *var, int16_t value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_INT16);
	var->int16_value = value;
}

void
ni_dbus_variant_set_uint32(ni_dbus_variant_t *var, uint32_t value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_UINT32);
	var->uint32_value = value;
}

void
ni_dbus_variant_set_int32(ni_dbus_variant_t *var, int32_t value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_INT32);
	var->int32_value = value;
}

void
ni_dbus_variant_set_uint64(ni_dbus_variant_t *var, uint64_t value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_UINT64);
	var->uint64_value = value;
}

void
ni_dbus_variant_set_int64(ni_dbus_variant_t *var, int64_t value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_INT64);
	var->int64_value = value;
}

void
ni_dbus_variant_set_double(ni_dbus_variant_t *var, double value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_DOUBLE);
	var->double_value = value;
}

/*
 * Get simple types from a variant
 */
dbus_bool_t
ni_dbus_variant_get_string(const ni_dbus_variant_t *var, const char **ret)
{
	if (var->type != DBUS_TYPE_STRING)
		return FALSE;
	*ret = var->string_value;
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_object_path(const ni_dbus_variant_t *var, const char **ret)
{
	if (var->type != DBUS_TYPE_OBJECT_PATH)
		return FALSE;
	*ret = var->string_value;
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_bool(const ni_dbus_variant_t *var, dbus_bool_t *ret)
{
	if (var->type != DBUS_TYPE_BOOLEAN)
		return FALSE;
	*ret = var->bool_value;
	return TRUE;
}


dbus_bool_t
ni_dbus_variant_get_byte(const ni_dbus_variant_t *var, unsigned char *ret)
{
	if (var->type != DBUS_TYPE_BYTE)
		return FALSE;
	*ret = var->byte_value;
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_uint16(const ni_dbus_variant_t *var, uint16_t *ret)
{
	if (var->type != DBUS_TYPE_UINT16)
		return FALSE;
	*ret = var->uint16_value;
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_int16(const ni_dbus_variant_t *var, int16_t *ret)
{
	if (var->type != DBUS_TYPE_INT16)
		return FALSE;
	*ret = var->int16_value;
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_uint32(const ni_dbus_variant_t *var, uint32_t *ret)
{
	if (var->type != DBUS_TYPE_UINT32)
		return FALSE;
	*ret = var->uint32_value;
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_int32(const ni_dbus_variant_t *var, int32_t *ret)
{
	if (var->type != DBUS_TYPE_INT32)
		return FALSE;
	*ret = var->int32_value;
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_uint64(const ni_dbus_variant_t *var, uint64_t *ret)
{
	if (var->type != DBUS_TYPE_UINT64)
		return FALSE;
	*ret = var->uint64_value;
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_int64(const ni_dbus_variant_t *var, int64_t *ret)
{
	if (var->type != DBUS_TYPE_INT64)
		return FALSE;
	*ret = var->int64_value;
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_double(const ni_dbus_variant_t *var, double *ret)
{
	if (var->type != DBUS_TYPE_DOUBLE)
		return FALSE;
	*ret = var->double_value;
	return TRUE;
}

/*
 * The following functions "cast" the value of a variant integer to a
 * C type, and vice versa.
 */
#define CAST_SWITCH(var, ret) \
	switch (var->type) { \
	case DBUS_TYPE_BOOLEAN: \
		*ret = var->bool_value; break; \
	case DBUS_TYPE_BYTE: \
		*ret = var->byte_value; break; \
	case DBUS_TYPE_INT16: \
		*ret = var->int16_value; break; \
	case DBUS_TYPE_UINT16: \
		*ret = var->uint16_value; break; \
	case DBUS_TYPE_INT32: \
		*ret = var->int32_value; break; \
	case DBUS_TYPE_UINT32: \
		*ret = var->uint32_value; break; \
	case DBUS_TYPE_INT64: \
		*ret = var->int64_value; break; \
	case DBUS_TYPE_UINT64: \
		*ret = var->uint64_value; break; \
	case DBUS_TYPE_DOUBLE: \
		*ret = var->double_value; break; \
	default: \
		return FALSE; \
	}

dbus_bool_t
ni_dbus_variant_get_int(const ni_dbus_variant_t *var, int *ret)
{
	CAST_SWITCH(var, ret);
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_uint(const ni_dbus_variant_t *var, unsigned int *ret)
{
	CAST_SWITCH(var, ret);
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_long(const ni_dbus_variant_t *var, long *ret)
{
	CAST_SWITCH(var, ret);
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_get_ulong(const ni_dbus_variant_t *var, unsigned long *ret)
{
	CAST_SWITCH(var, ret);
	return TRUE;
}

#undef CAST_SWITCH

#define CAST_SWITCH(var, value) \
	switch (var->type) { \
	case DBUS_TYPE_BOOLEAN: \
		var->bool_value = value; break; \
	case DBUS_TYPE_BYTE: \
		var->byte_value = value; break; \
	case DBUS_TYPE_INT16: \
		var->int16_value = value; break; \
	case DBUS_TYPE_UINT16: \
		var->uint16_value = value; break; \
	case DBUS_TYPE_INT32: \
		var->int32_value = value; break; \
	case DBUS_TYPE_UINT32: \
		var->uint32_value = value; break; \
	case DBUS_TYPE_INT64: \
		var->int64_value = value; break; \
	case DBUS_TYPE_UINT64: \
		var->uint64_value = value; break; \
	case DBUS_TYPE_DOUBLE: \
		var->double_value = value; break; \
	default: \
		return FALSE; \
	}

dbus_bool_t
ni_dbus_variant_assign_bool(ni_dbus_variant_t *var, dbus_bool_t value)
{
	CAST_SWITCH(var, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_set_int(ni_dbus_variant_t *var, int value)
{
	CAST_SWITCH(var, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_set_uint(ni_dbus_variant_t *var, unsigned int value)
{
	CAST_SWITCH(var, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_set_long(ni_dbus_variant_t *var, long value)
{
	CAST_SWITCH(var, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_set_ulong(ni_dbus_variant_t *var, unsigned long value)
{
	CAST_SWITCH(var, value);
	return TRUE;
}

#undef CAST_SWITCH

/*
 * Extract a byte array from a variant.
 */
dbus_bool_t
ni_dbus_variant_get_byte_array_minmax(const ni_dbus_variant_t *var,
					unsigned char *array, unsigned int *len,
					unsigned int minlen, unsigned int maxlen)
{
	if (!__ni_dbus_is_array(var, DBUS_TYPE_BYTE_AS_STRING))
		return FALSE;
	if (var->array.len < minlen || maxlen < var->array.len)
		return FALSE;
	*len = var->array.len;
	memcpy(array, var->byte_array_value, *len);
	return TRUE;
}

dbus_bool_t
ni_dbus_variant_is_byte_array(const ni_dbus_variant_t *var)
{
	return __ni_dbus_is_array(var, DBUS_TYPE_BYTE_AS_STRING);
}

/*
 * Helper function for handling arrays
 */
#define NI_DBUS_ARRAY_CHUNK		32
#define NI_DBUS_ARRAY_ALLOCATION(len)	(((len) + NI_DBUS_ARRAY_CHUNK - 1) & ~(NI_DBUS_ARRAY_CHUNK - 1))
static inline void
__ni_dbus_array_grow(ni_dbus_variant_t *var, size_t element_size, unsigned int grow_by)
{
	unsigned int max = NI_DBUS_ARRAY_ALLOCATION(var->array.len);
	unsigned int len = var->array.len;

	if (len + grow_by >= max) {
		void *new_data;

		max = NI_DBUS_ARRAY_ALLOCATION(len + grow_by);
		new_data = xcalloc(max, element_size);
		if (new_data == NULL)
			ni_fatal("%s: out of memory try to grow array to %u elements",
					__FUNCTION__, len + grow_by);

		memcpy(new_data, var->byte_array_value, len * element_size);
		free(var->byte_array_value);
		var->byte_array_value = new_data;
	}
}

void
ni_dbus_variant_init_byte_array(ni_dbus_variant_t *var)
{
	ni_dbus_variant_destroy(var);
	__ni_dbus_init_array(var, DBUS_TYPE_BYTE);
}

void
ni_dbus_variant_set_byte_array(ni_dbus_variant_t *var,
				const unsigned char *data, unsigned int len)
{
	ni_dbus_variant_destroy(var);
	__ni_dbus_init_array(var, DBUS_TYPE_BYTE);

	__ni_dbus_array_grow(var, sizeof(unsigned char), len);
	if (len) {
		memcpy(var->byte_array_value, data, len);
		var->array.len = len;
	}
}

dbus_bool_t
ni_dbus_variant_append_byte_array(ni_dbus_variant_t *var, unsigned char byte)
{
	if (!__ni_dbus_is_array(var, DBUS_TYPE_BYTE_AS_STRING))
		return FALSE;

	__ni_dbus_array_grow(var, sizeof(unsigned char), 1);
	var->byte_array_value[var->array.len++] = byte;
	return TRUE;
}

/*
 * A UUID is encoded as a fixed length array of bytes
 */
void
ni_dbus_variant_set_uuid(ni_dbus_variant_t *var, const ni_uuid_t *uuid)
{
	ni_dbus_variant_set_byte_array(var, uuid->octets, sizeof(uuid->octets));
}

dbus_bool_t
ni_dbus_variant_get_uuid(const ni_dbus_variant_t *var, ni_uuid_t *uuid)
{
	unsigned int len;

	return ni_dbus_variant_get_byte_array_minmax(var, uuid->octets, &len,
					sizeof(uuid->octets),
					sizeof(uuid->octets));
}

void
ni_dbus_variant_init_string_array(ni_dbus_variant_t *var)
{
	ni_dbus_variant_destroy(var);
	__ni_dbus_init_array(var, DBUS_TYPE_STRING);
}

void
ni_dbus_variant_set_string_array(ni_dbus_variant_t *var,
				const char **data, unsigned int len)
{
	ni_dbus_variant_destroy(var);
	__ni_dbus_init_array(var, DBUS_TYPE_STRING);

	__ni_dbus_array_grow(var, sizeof(char *), len);
	if (len) {
		unsigned int i;

		for (i = 0; i < len; ++i)
			var->string_array_value[i] = xstrdup(data[i]?: "");
		var->array.len = len;
	}
}

dbus_bool_t
ni_dbus_variant_append_string_array(ni_dbus_variant_t *var, const char *string)
{
	unsigned int len = var->array.len;

	if (!__ni_dbus_is_array(var, DBUS_TYPE_STRING_AS_STRING))
		return FALSE;

	__ni_dbus_array_grow(var, sizeof(char *), 1);
	var->string_array_value[len] = xstrdup(string?: "");
	var->array.len++;

	return TRUE;
}

void
ni_dbus_variant_init_object_path_array(ni_dbus_variant_t *var)
{
	ni_dbus_variant_destroy(var);
	__ni_dbus_init_array(var, DBUS_TYPE_OBJECT_PATH);
}

dbus_bool_t
ni_dbus_variant_append_object_path_array(ni_dbus_variant_t *var, const char *string)
{
	unsigned int len = var->array.len;

	if (!__ni_dbus_is_array(var, DBUS_TYPE_OBJECT_PATH_AS_STRING))
		return FALSE;

	__ni_dbus_array_grow(var, sizeof(char *), 1);
	var->string_array_value[len] = xstrdup(string?: "");
	var->array.len++;

	return TRUE;
}

void
ni_dbus_variant_init_variant_array(ni_dbus_variant_t *var)
{
	ni_dbus_variant_destroy(var);
	__ni_dbus_init_array(var, DBUS_TYPE_VARIANT);
}

ni_dbus_variant_t *
ni_dbus_variant_append_variant_element(ni_dbus_variant_t *var)
{
	ni_dbus_variant_t *dst;

	if (!__ni_dbus_is_array(var, DBUS_TYPE_VARIANT_AS_STRING))
		return NULL;

	__ni_dbus_array_grow(var, sizeof(ni_dbus_variant_t), 1);
	dst = &var->variant_array_value[var->array.len++];

	return dst;
}

void
ni_dbus_variant_copy(ni_dbus_variant_t *dst, const ni_dbus_variant_t *src)
{
	ni_dbus_variant_destroy(dst);
	ni_fatal("%s: not implemented", __FUNCTION__);
}

void
ni_dbus_variant_destroy(ni_dbus_variant_t *var)
{
	if (var->__magic != 0 && var->__magic != NI_DBUS_VARIANT_MAGIC) {
		ni_fatal("%s: variant with bad magic cookie 0x%x",
				__func__, var->__magic);
	}

	if (var->type == DBUS_TYPE_STRING
	 || var->type == DBUS_TYPE_OBJECT_PATH)
		ni_string_free(&var->string_value);
	else if (var->type == DBUS_TYPE_VARIANT) {
		if (var->variant_value) {
			ni_dbus_variant_destroy(var->variant_value);
			free(var->variant_value);
		}
	}
	else if (var->type == DBUS_TYPE_ARRAY) {
		unsigned int i;

		switch (var->array.element_type) {
		case DBUS_TYPE_BYTE:
			free(var->byte_array_value);
			break;
		case DBUS_TYPE_STRING:
		case DBUS_TYPE_OBJECT_PATH:
			for (i = 0; i < var->array.len; ++i)
				free(var->string_array_value[i]);
			free(var->string_array_value);
			break;
		case DBUS_TYPE_DICT_ENTRY:
			for (i = 0; i < var->array.len; ++i)
				ni_dbus_variant_destroy(&var->dict_array_value[i].datum);
			free(var->dict_array_value);
			break;
		case DBUS_TYPE_INVALID:
			if (var->array.element_signature == NULL)
				break;
			// fallthrough
		case DBUS_TYPE_VARIANT:
			for (i = 0; i < var->array.len; ++i)
				ni_dbus_variant_destroy(&var->variant_array_value[i]);
			free(var->variant_array_value);
			break;
		case DBUS_TYPE_STRUCT:
			for (i = 0; i < var->array.len; ++i)
				ni_dbus_variant_destroy(&var->struct_value[i]);
			free(var->struct_value);
			break;
		default:
			ni_warn("Don't know how to destroy this type of array");
			break;
		}
		ni_string_free(&var->array.element_signature);
	}

	if (var->__message)
		dbus_message_unref(var->__message);

	memset(var, 0, sizeof(*var));
	var->type = DBUS_TYPE_INVALID;
	var->__magic = NI_DBUS_VARIANT_MAGIC;
}

const char *
ni_dbus_variant_print(ni_stringbuf_t *sb, const ni_dbus_variant_t *var)
{
	switch (var->type) {
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		ni_stringbuf_printf(sb, "%s", var->string_value);
		break;

	case DBUS_TYPE_BYTE:
		ni_stringbuf_printf(sb, "0x%02x", var->byte_value);
		break;

	case DBUS_TYPE_BOOLEAN:
		ni_stringbuf_printf(sb, "%s", var->bool_value? "true" : "false");
		break;

	case DBUS_TYPE_INT16:
		ni_stringbuf_printf(sb, "%d", var->int16_value);
		break;

	case DBUS_TYPE_UINT16:
		ni_stringbuf_printf(sb, "%u", var->uint16_value);
		break;

	case DBUS_TYPE_INT32:
		ni_stringbuf_printf(sb, "%d", var->int32_value);
		break;

	case DBUS_TYPE_UINT32:
		ni_stringbuf_printf(sb, "%u", var->uint32_value);
		break;

	case DBUS_TYPE_INT64:
		ni_stringbuf_printf(sb, "%lld", (long long) var->int64_value);
		break;

	case DBUS_TYPE_UINT64:
		ni_stringbuf_printf(sb, "%llu", (unsigned long long) var->uint64_value);
		break;

	case DBUS_TYPE_DOUBLE:
		ni_stringbuf_printf(sb, "%f", var->double_value);
		break;

	case DBUS_TYPE_VARIANT:
		ni_stringbuf_printf(sb, "v{");
		if (var->variant_value)
			ni_dbus_variant_print(sb, var->variant_value);
		else
			ni_stringbuf_printf(sb, "<NULL>");
		ni_stringbuf_printf(sb, "}");
		break;

	case DBUS_TYPE_STRUCT:
		ni_stringbuf_printf(sb, "<struct>");
		break;

	case DBUS_TYPE_ARRAY:
		ni_stringbuf_printf(sb, "<array>");
		break;

	default:
		ni_stringbuf_printf(sb, "<unknown type (%d)>", var->type);
	}
	return sb->string;
}

const char *
ni_dbus_variant_sprint(const ni_dbus_variant_t *var)
{
	static char buffer[256];
	ni_stringbuf_t sbuf = NI_STRINGBUF_INIT_BUFFER(buffer);

	ni_stringbuf_truncate(&sbuf, 0);
	return ni_dbus_variant_print(&sbuf, var);
}

dbus_bool_t
ni_dbus_variant_parse(ni_dbus_variant_t *var,
					const char *string_value, const char *signature)
{
	if (signature[0] && !signature[1]) {
		char *ep = NULL;

		__ni_dbus_variant_change_type(var, signature[0]);
		switch (signature[0]) {
		case DBUS_TYPE_STRING:
		case DBUS_TYPE_OBJECT_PATH:
			ni_dbus_variant_set_string(var, string_value);
			break;

		case DBUS_TYPE_BYTE:
			var->byte_value = strtoul(string_value, &ep, 0);
			break;

		case DBUS_TYPE_BOOLEAN:
			if (!strcmp(string_value, "true"))
				var->bool_value = 1;
			else if (!strcmp(string_value, "false"))
				var->bool_value = 0;
			else
				var->bool_value = strtoul(string_value, &ep, 0);
			break;

		case DBUS_TYPE_INT16:
			var->int16_value = strtol(string_value, &ep, 0);
			break;

		case DBUS_TYPE_UINT16:
			var->uint16_value = strtoul(string_value, &ep, 0);
			break;

		case DBUS_TYPE_INT32:
			var->int32_value = strtol(string_value, &ep, 0);
			break;

		case DBUS_TYPE_UINT32:
			var->uint32_value = strtoul(string_value, &ep, 0);
			break;

		case DBUS_TYPE_INT64:
			var->int64_value = strtoll(string_value, &ep, 0);
			break;

		case DBUS_TYPE_UINT64:
			var->uint64_value = strtoull(string_value, &ep, 0);
			break;

		case DBUS_TYPE_DOUBLE:
			var->double_value = strtod(string_value, &ep);
			break;

		default:
			return FALSE;
		}

		if (ep && *ep)
			return FALSE;

		return TRUE;
	}

	if (signature[0] == 'a') {
		/* TBD: Array types */
	}

	return FALSE;
}

/*
 * Append any type of data to an array of scalars.
 */
static inline size_t
ni_dbus_type_size(unsigned int dbus_type)
{
	static size_t	type_size[256] = {
	[DBUS_TYPE_STRING]	= sizeof(char *),
	[DBUS_TYPE_OBJECT_PATH]	= sizeof(char *),
	[DBUS_TYPE_BYTE]	= sizeof(unsigned char),
	[DBUS_TYPE_BOOLEAN]	= sizeof(unsigned char),
	[DBUS_TYPE_INT16]	= sizeof(int16_t),
	[DBUS_TYPE_UINT16]	= sizeof(int16_t),
	[DBUS_TYPE_INT32]	= sizeof(int32_t),
	[DBUS_TYPE_UINT32]	= sizeof(int32_t),
	[DBUS_TYPE_INT64]	= sizeof(int64_t),
	[DBUS_TYPE_UINT64]	= sizeof(int64_t),
	[DBUS_TYPE_DOUBLE]	= sizeof(double),
	};

	if (dbus_type >= 256)
		return 0;
	return type_size[dbus_type];
}

dbus_bool_t
ni_dbus_variant_array_parse_and_append_string(ni_dbus_variant_t *var, const char *string_value)
{
	unsigned int scalar_type;
	unsigned int element_size;
	unsigned int index;
	char *ep = NULL;

	if (var->type != DBUS_TYPE_ARRAY)
		return FALSE;
	if (var->array.element_type == 0)
		return FALSE;
	scalar_type = var->array.element_type;

	element_size = ni_dbus_type_size(scalar_type);
	if (!element_size)
		return FALSE;

	__ni_dbus_array_grow(var, element_size, 1);
	index = var->array.len;

	switch (scalar_type) {
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		ni_string_dup(&var->string_array_value[index], string_value);
		break;

	case DBUS_TYPE_BYTE:
		var->byte_array_value[index] = strtoul(string_value, &ep, 0);
		break;

#ifdef notyet
	case DBUS_TYPE_BOOLEAN:
		if (!strcmp(string_value, "true"))
			var->bool_array_value[index] = 1;
		else if (!strcmp(string_value, "false"))
			var->bool_array_value[index] = 1;
		else
			var->bool_array_value[index] = strtoul(string_value, &ep, 0);
		break;

	case DBUS_TYPE_INT16:
		var->int16_array_value[index] = strtol(string_value, &ep, 0);
		break;

	case DBUS_TYPE_UINT16:
		var->uint16_array_value[index] = strtoul(string_value, &ep, 0);
		break;

	case DBUS_TYPE_INT32:
		var->int32_array_value[index] = strtol(string_value, &ep, 0);
		break;

	case DBUS_TYPE_UINT32:
		var->uint32_array_value[index] = strtoul(string_value, &ep, 0);
		break;

	case DBUS_TYPE_INT64:
		var->int64_array_value[index] = strtoll(string_value, &ep, 0);
		break;

	case DBUS_TYPE_UINT64:
		var->uint64_array_value[index] = strtoull(string_value, &ep, 0);
		break;

	case DBUS_TYPE_DOUBLE:
		var->double_array_value[index] = strtod(string_value, &ep);
		break;
#endif

	default:
		return FALSE;
	}

	if (ep && *ep)
		return FALSE;

	var->array.len++;
	return TRUE;
}

const char *
ni_dbus_variant_array_print_element(const ni_dbus_variant_t *var, unsigned int index)
{
	unsigned int scalar_type;
	static char buffer[32];

	if (var->type != DBUS_TYPE_ARRAY)
		return FALSE;
	if (var->array.element_type == 0)
		return FALSE;
	scalar_type = var->array.element_type;

	if (index >= var->array.len)
		return FALSE;

	switch (scalar_type) {
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		return var->string_array_value[index];

	case DBUS_TYPE_BYTE:
		snprintf(buffer, sizeof(buffer), "0x%02x", var->byte_array_value[index]);
		break;

#ifdef notyet
	case DBUS_TYPE_BOOLEAN:
		return var->bool_array_value[index]? "true" : "false";

	case DBUS_TYPE_INT16:
		snprintf(buffer, sizeof(buffer), "%d", var->int16_array_value[index]);
		break;

	case DBUS_TYPE_UINT16:
		snprintf(buffer, sizeof(buffer), "%u", var->uint16_array_value[index]);
		break;

	case DBUS_TYPE_INT32:
		snprintf(buffer, sizeof(buffer), "%d", var->int32_array_value[index]);
		break;

	case DBUS_TYPE_UINT32:
		snprintf(buffer, sizeof(buffer), "%u", var->uint32_array_value[index]);
		break;

	case DBUS_TYPE_INT64:
		snprintf(buffer, sizeof(buffer), "%lld", (long long) var->int64_array_value[index]);
		break;

	case DBUS_TYPE_UINT64:
		snprintf(buffer, sizeof(buffer), "%llu", (long long) var->uint64_array_value[index]);
		break;

	case DBUS_TYPE_DOUBLE:
		snprintf(buffer, sizeof(buffer), "%f", var->double_array_value[index]);
		break;
#endif

	default:
		return FALSE;
	}

	return buffer;
}

const char *
ni_dbus_variant_signature(const ni_dbus_variant_t *var)
{
	const char *sig;

	sig = ni_dbus_type_as_string(var->type);
	if (sig)
		return sig;

	switch (var->type) {
	case DBUS_TYPE_ARRAY:
		if (var->array.element_signature) {
			static char buffer[16];

			snprintf(buffer, sizeof(buffer), "%s%s",
					DBUS_TYPE_ARRAY_AS_STRING,
					var->array.element_signature);
			return buffer;
		}
		switch (var->array.element_type) {
		case DBUS_TYPE_BYTE:
			return DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING;
		case DBUS_TYPE_STRING:
			return DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING;
		case DBUS_TYPE_VARIANT:
			return DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_VARIANT_AS_STRING;
		case DBUS_TYPE_DICT_ENTRY:
			return DBUS_TYPE_ARRAY_AS_STRING
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING
				;
		}
		break;

	case DBUS_TYPE_STRUCT:
		{
			static char *saved_sig = NULL;
			ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
			unsigned int i;

			ni_stringbuf_putc(&buf, DBUS_STRUCT_BEGIN_CHAR);
			for (i = 0; i < var->array.len; ++i) {
				ni_dbus_variant_t *member = &var->struct_value[i];
				const char *msig;

				if ((msig = ni_dbus_variant_signature(member)) == NULL) {
					ni_stringbuf_destroy(&buf);
					return NULL;
				}
				ni_stringbuf_puts(&buf, msig);
			}
			ni_stringbuf_putc(&buf, DBUS_STRUCT_END_CHAR);
			ni_string_dup(&saved_sig, buf.string);
			ni_stringbuf_destroy(&buf);
			return saved_sig;
		}
	}

	return NULL;
}

/*
 * Dict handling
 */
void
ni_dbus_variant_init_dict(ni_dbus_variant_t *var)
{
	ni_dbus_variant_destroy(var);
	__ni_dbus_init_array(var, DBUS_TYPE_DICT_ENTRY);
}

dbus_bool_t
ni_dbus_dict_is_empty(const ni_dbus_variant_t *var)
{
	if (!ni_dbus_variant_is_dict(var))
		return FALSE;
	return var->array.len == 0;
}

ni_dbus_variant_t *
ni_dbus_dict_add(ni_dbus_variant_t *dict, const char *key)
{
	ni_dbus_dict_entry_t *dst;

	if (dict->type != DBUS_TYPE_ARRAY
	 || dict->array.element_type != DBUS_TYPE_DICT_ENTRY)
		return NULL;

	__ni_dbus_array_grow(dict, sizeof(ni_dbus_dict_entry_t), 1);
	dst = &dict->dict_array_value[dict->array.len++];
	dst->key = key;

	return &dst->datum;
}

dbus_bool_t
ni_dbus_dict_add_entry(ni_dbus_variant_t *dict, const ni_dbus_dict_entry_t *entry)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, entry->key)))
		return FALSE;
	ni_dbus_variant_copy(dst, &entry->datum);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_string(ni_dbus_variant_t *dict, const char *key, const char *value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_string(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_object_path(ni_dbus_variant_t *dict, const char *key, const char *value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_object_path(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_bool(ni_dbus_variant_t *dict, const char *key, dbus_bool_t value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_bool(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_uint16(ni_dbus_variant_t *dict, const char *key, uint16_t value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_uint16(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_int16(ni_dbus_variant_t *dict, const char *key, int16_t value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_int16(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_uint32(ni_dbus_variant_t *dict, const char *key, uint32_t value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_uint32(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_int32(ni_dbus_variant_t *dict, const char *key, int32_t value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_int32(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_uint64(ni_dbus_variant_t *dict, const char *key, uint64_t value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_uint64(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_int64(ni_dbus_variant_t *dict, const char *key, int64_t value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_int64(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_double(ni_dbus_variant_t *dict, const char *key, double value)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_double(dst, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_uuid(ni_dbus_variant_t *dict, const char *key, const ni_uuid_t *uuid)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_uuid(dst, uuid);
	return TRUE;
}

dbus_bool_t
ni_dbus_dict_add_byte_array(ni_dbus_variant_t *dict, const char *key,
			const unsigned char *byte_array, unsigned int len)
{
	ni_dbus_variant_t *dst;

	if (!(dst = ni_dbus_dict_add(dict, key)))
		return FALSE;
	ni_dbus_variant_set_byte_array(dst, byte_array, len);
	return TRUE;
}

ni_dbus_variant_t *
ni_dbus_dict_get(const ni_dbus_variant_t *dict, const char *key)
{
	ni_dbus_dict_entry_t *entry;
	unsigned int i;

	if (!ni_dbus_variant_is_dict(dict))
		return NULL;

	for (i = 0; i < dict->array.len; ++i) {
		entry = &dict->dict_array_value[i];
		if (entry->key && !strcmp(entry->key, key))
			return &entry->datum;
	}

	return NULL;
}

ni_dbus_variant_t *
ni_dbus_dict_get_entry(const ni_dbus_variant_t *dict, unsigned int index, const char **key)
{
	ni_dbus_dict_entry_t *entry;

	if (!ni_dbus_variant_is_dict(dict))
		return NULL;

	if (index >= dict->array.len)
		return NULL;

	entry = &dict->dict_array_value[index];
	if (key)
		*key = entry->key;
	return &entry->datum;
}

ni_dbus_variant_t *
ni_dbus_dict_get_next(const ni_dbus_variant_t *dict, const char *key, const ni_dbus_variant_t *previous)
{
	ni_dbus_dict_entry_t *entry;
	unsigned int pos = 0;

	if (!ni_dbus_variant_is_dict(dict))
		return FALSE;

	if (previous != NULL) {
		dbus_bool_t found = FALSE;

		while (pos < dict->array.len) {
			entry = &dict->dict_array_value[pos++];

			if (previous == &entry->datum) {
				found = TRUE;
				break;
			}
		}
		if (!found) {
			ni_warn("%s(%s): caller passed in bad previous pointer", __func__, key);
			return NULL;
		}
	}

	while (pos < dict->array.len) {
		entry = &dict->dict_array_value[pos++];
		if (key == NULL || ni_string_eq(entry->key, key))
			return &entry->datum;
	}

	return NULL;
}

dbus_bool_t
ni_dbus_dict_get_bool(const ni_dbus_variant_t *dict, const char *key, dbus_bool_t *value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_bool(var, value);
}

dbus_bool_t
ni_dbus_dict_get_int16(const ni_dbus_variant_t *dict, const char *key, int16_t *value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_int16(var, value);
}

dbus_bool_t
ni_dbus_dict_get_uint16(const ni_dbus_variant_t *dict, const char *key, uint16_t *value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_uint16(var, value);
}

dbus_bool_t
ni_dbus_dict_get_int32(const ni_dbus_variant_t *dict, const char *key, int32_t *value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_int32(var, value);
}

dbus_bool_t
ni_dbus_dict_get_uint32(const ni_dbus_variant_t *dict, const char *key, uint32_t *value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_uint32(var, value);
}

dbus_bool_t
ni_dbus_dict_get_int64(const ni_dbus_variant_t *dict, const char *key, int64_t *value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_int64(var, value);
}

dbus_bool_t
ni_dbus_dict_get_uint64(const ni_dbus_variant_t *dict, const char *key, uint64_t *value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_uint64(var, value);
}

dbus_bool_t
ni_dbus_dict_get_string(const ni_dbus_variant_t *dict, const char *key, const char **value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_string(var, value);
}

dbus_bool_t
ni_dbus_dict_get_object_path(const ni_dbus_variant_t *dict, const char *key, const char **value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_object_path(var, value);
}

dbus_bool_t
ni_dbus_dict_get_double(const ni_dbus_variant_t *dict, const char *key, double *value)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_double(var, value);
}

dbus_bool_t
ni_dbus_dict_get_uuid(const ni_dbus_variant_t *dict, const char *key, ni_uuid_t *uuid)
{
	const ni_dbus_variant_t *var;

	if (!(var = ni_dbus_dict_get(dict, key)))
		return FALSE;
	return ni_dbus_variant_get_uuid(var, uuid);
}

dbus_bool_t
ni_dbus_dict_delete_entry(ni_dbus_variant_t *dict, const char *key)
{
	ni_dbus_dict_entry_t *entry;
	unsigned int i;

	if (dict->type != DBUS_TYPE_ARRAY
	 || dict->array.element_type != DBUS_TYPE_DICT_ENTRY)
		return FALSE;

	entry = &dict->dict_array_value[0];
	for (i = 0; i < dict->array.len; ++i, ++entry) {
		if (entry->key && !strcmp(entry->key, key)) {
			ni_dbus_variant_destroy(&entry->datum);
			dict->array.len--;

			/* Shift down all entries */
			memmove(entry, entry + 1, (dict->array.len - i) * sizeof(*entry));
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Array of dicts
 */
void
ni_dbus_dict_array_init(ni_dbus_variant_t *var)
{
	ni_dbus_variant_destroy(var);
	var->type = DBUS_TYPE_ARRAY;
	ni_string_dup(&var->array.element_signature, NI_DBUS_DICT_SIGNATURE);
}

ni_dbus_variant_t *
ni_dbus_dict_array_add(ni_dbus_variant_t *var)
{
	ni_dbus_variant_t *dst;

	if (!__ni_dbus_is_array(var, NI_DBUS_DICT_SIGNATURE))
		return NULL;

	__ni_dbus_array_grow(var, sizeof(ni_dbus_variant_t), 1);
	dst = &var->variant_array_value[var->array.len++];

	ni_dbus_variant_init_dict(dst);
	return dst;
}

/*
 * DBus struct type
 */
void
ni_dbus_variant_init_struct(ni_dbus_variant_t *var)
{
	ni_dbus_variant_destroy(var);
	var->type = DBUS_TYPE_STRUCT;
	var->array.len = 0;
}

dbus_bool_t
ni_dbus_variant_is_struct(const ni_dbus_variant_t *var)
{
	return var->type == DBUS_TYPE_STRUCT;
}

ni_dbus_variant_t *
ni_dbus_struct_add(ni_dbus_variant_t *var)
{
	ni_dbus_variant_t *dst;

	if (var->type != DBUS_TYPE_STRUCT)
		return NULL;

	__ni_dbus_array_grow(var, sizeof(ni_dbus_variant_t), 1);
	dst = &var->struct_value[var->array.len++];

	return dst;
}

ni_bool_t
ni_dbus_struct_add_string(ni_dbus_variant_t *var, const char *string_value)
{
	ni_dbus_variant_t *member;

	if (!(member = ni_dbus_struct_add(var)))
		return FALSE;

	ni_dbus_variant_set_string(member, string_value);
	return TRUE;
}

ni_dbus_variant_t *
ni_dbus_struct_get(const ni_dbus_variant_t *var, unsigned int index)
{
	if (var->type != DBUS_TYPE_STRUCT || index >= var->array.len)
		return NULL;

	return &var->struct_value[index];
}

dbus_bool_t
ni_dbus_struct_get_string(const ni_dbus_variant_t *var, unsigned int index, const char **result)
{
	ni_dbus_variant_t *member;

	if (!(member = ni_dbus_struct_get(var, index)))
		return FALSE;
	return ni_dbus_variant_get_string(member, result);
}

/*
 * Array of arrays
 */
void
ni_dbus_array_array_init(ni_dbus_variant_t *var, const char *elem_signature)
{
	ni_dbus_variant_destroy(var);
	var->type = DBUS_TYPE_ARRAY;
	ni_string_dup(&var->array.element_signature, elem_signature);
}

ni_dbus_variant_t *
ni_dbus_array_array_add(ni_dbus_variant_t *var)
{
	ni_dbus_variant_t *dst;

	if (var->type != DBUS_TYPE_ARRAY
	 || var->array.element_type != DBUS_TYPE_INVALID
	 || var->array.element_signature == NULL
	 || var->array.element_signature[0] != DBUS_TYPE_ARRAY)
		return NULL;

	__ni_dbus_array_grow(var, sizeof(ni_dbus_variant_t), 1);
	dst = &var->variant_array_value[var->array.len++];

	return dst;
}

/*
 * DBus Variant 'v' container
 */
ni_dbus_variant_t *
ni_dbus_variant_init_variant(ni_dbus_variant_t *var)
{
	ni_dbus_variant_destroy(var);
	var->type = DBUS_TYPE_VARIANT;
	var->variant_value = calloc(1, sizeof(ni_dbus_variant_t));
	if (var->variant_value)
		ni_dbus_variant_destroy(var->variant_value);
	return var->variant_value;
}

dbus_bool_t
ni_dbus_variant_is_variant(const ni_dbus_variant_t *var)
{
	return var->type == DBUS_TYPE_VARIANT;
}

dbus_bool_t
ni_dbus_variant_get_variant(const ni_dbus_variant_t *var, const ni_dbus_variant_t **ret)
{
	if (!ni_dbus_variant_is_variant(var))
		return FALSE;
	*ret = var->variant_value;
	return TRUE;
}

/*
 * Translate basic dbus types to signature strings
 */
static const char * __ni_dbus_basic_type_as_string[256] = {
[DBUS_TYPE_BYTE]	= DBUS_TYPE_BYTE_AS_STRING,
[DBUS_TYPE_BOOLEAN]	= DBUS_TYPE_BOOLEAN_AS_STRING,
[DBUS_TYPE_INT16]	= DBUS_TYPE_INT16_AS_STRING,
[DBUS_TYPE_UINT16]	= DBUS_TYPE_UINT16_AS_STRING,
[DBUS_TYPE_INT32]	= DBUS_TYPE_INT32_AS_STRING,
[DBUS_TYPE_UINT32]	= DBUS_TYPE_UINT32_AS_STRING,
[DBUS_TYPE_INT64]	= DBUS_TYPE_INT64_AS_STRING,
[DBUS_TYPE_UINT64]	= DBUS_TYPE_UINT64_AS_STRING,
[DBUS_TYPE_DOUBLE]	= DBUS_TYPE_DOUBLE_AS_STRING,
[DBUS_TYPE_STRING]	= DBUS_TYPE_STRING_AS_STRING,
[DBUS_TYPE_OBJECT_PATH]	= DBUS_TYPE_OBJECT_PATH_AS_STRING,
[DBUS_TYPE_VARIANT]	= DBUS_TYPE_VARIANT_AS_STRING,
};

const char *
ni_dbus_type_as_string(int type)
{
	if (type < 0 || type >= 256)
		return NULL;
	return __ni_dbus_basic_type_as_string[(unsigned int) type];
}

/*
 * Offsets of all elements in the variant struct
 */
unsigned int
__ni_dbus_variant_offsets[256] = {
[DBUS_TYPE_BYTE]		= offsetof(ni_dbus_variant_t, byte_value),
[DBUS_TYPE_BOOLEAN]		= offsetof(ni_dbus_variant_t, bool_value),
[DBUS_TYPE_STRING]		= offsetof(ni_dbus_variant_t, string_value),
[DBUS_TYPE_OBJECT_PATH]		= offsetof(ni_dbus_variant_t, string_value),
[DBUS_TYPE_INT16]		= offsetof(ni_dbus_variant_t, int16_value),
[DBUS_TYPE_UINT16]		= offsetof(ni_dbus_variant_t, uint16_value),
[DBUS_TYPE_INT32]		= offsetof(ni_dbus_variant_t, int32_value),
[DBUS_TYPE_UINT32]		= offsetof(ni_dbus_variant_t, uint32_value),
[DBUS_TYPE_INT64]		= offsetof(ni_dbus_variant_t, int64_value),
[DBUS_TYPE_UINT64]		= offsetof(ni_dbus_variant_t, uint64_value),
[DBUS_TYPE_DOUBLE]		= offsetof(ni_dbus_variant_t, double_value),
};
