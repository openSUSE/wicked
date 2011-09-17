/*
 * Common DBus functions
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <dbus/dbus.h>
#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wicked/util.h>
#include <wicked/logging.h>
#include "socket_priv.h"
#include "dbus-common.h"
#include "dbus-dict.h"

#define TRACE_ENTER()		ni_debug_dbus("%s()", __FUNCTION__)
#define TP()			ni_debug_dbus("TP - %s:%u", __FUNCTION__, __LINE__)

static ni_intmap_t      __ni_dbus_error_map[] = {
	{ "org.freedesktop.DBus.Error.AccessDenied",	EACCES },
	{ "org.freedesktop.DBus.Error.InvalidArgs",	EINVAL },
	{ "org.freedesktop.DBus.Error.UnknownMethod",	EOPNOTSUPP },

	{ NULL }
};


int
ni_dbus_translate_error(const DBusError *err, const ni_intmap_t *error_map)
{
	unsigned int errcode;

	ni_debug_dbus("%s(%s, msg=%s)", __FUNCTION__, err->name, err->message);

	if (error_map && ni_parse_int_mapped(err->name, error_map, &errcode) >= 0)
		return errcode;

	if (ni_parse_int_mapped(err->name, __ni_dbus_error_map, &errcode) >= 0)
		return errcode;

	ni_warn("Cannot translate DBus error <%s>", err->name);
	return EIO;
}

/*
 * Deserialize response
 *
 * We need this wrapper function because dbus_message_get_args_valist
 * does not copy any strings, but returns char pointers that point at
 * the message body. Which is bad if you want to access these strings
 * after you've freed the message.
 */
int
ni_dbus_message_get_args(ni_dbus_message_t *reply, ...)
{
	DBusError error;
	va_list ap;
	int rv = 0, type;

	TRACE_ENTER();
	dbus_error_init(&error);
	va_start(ap, reply);

	type = va_arg(ap, int);
	if (type
	 && !dbus_message_get_args_valist(reply, &error, type, ap)) {
		ni_error("%s: unable to retrieve reply data", __FUNCTION__);
		rv = -EINVAL;
		goto done;
	}

	while (type) {
		char **data = va_arg(ap, char **);

		switch (type) {
		case DBUS_TYPE_STRING:
		case DBUS_TYPE_OBJECT_PATH:
			if (data && *data)
				*data = xstrdup(*data);
			break;
		}

		type = va_arg(ap, int);
	}

done:
	va_end(ap);
	return rv;
}

/*
 * Helper function for processing a DBusDict
 */
static inline const struct ni_dbus_dict_entry_handler *
__ni_dbus_get_property_handler(const struct ni_dbus_dict_entry_handler *handlers, const char *name)
{
	const struct ni_dbus_dict_entry_handler *h;

	for (h = handlers; h->type; ++h) {
		if (!strcmp(h->name, name))
			return h;
	}
	return NULL;
}

int
ni_dbus_process_properties(DBusMessageIter *iter, const struct ni_dbus_dict_entry_handler *handlers, void *user_object)
{
	struct ni_dbus_dict_entry entry;
	int rv = 0;

	TRACE_ENTER();
	while (ni_dbus_dict_get_entry(iter, &entry)) {
		const struct ni_dbus_dict_entry_handler *h;

#if 0
		if (entry.type == DBUS_TYPE_ARRAY) {
			ni_debug_dbus("++%s -- array of type %c", entry.key, entry.array_type);
		} else {
			ni_debug_dbus("++%s -- type %c", entry.key, entry.type);
		}
#endif

		if (!(h = __ni_dbus_get_property_handler(handlers, entry.key))) {
			ni_debug_dbus("%s: ignore unknown dict element \"%s\"", __FUNCTION__, entry.key);
			continue;
		}

		if (h->type != entry.type
		 || (h->type == DBUS_TYPE_ARRAY && h->array_type != entry.array_type)) {
			ni_error("%s: unexpected type for dict element \"%s\"", __FUNCTION__, entry.key);
			rv = -EINVAL;
			break;
		}

		if (h->type == DBUS_TYPE_ARRAY && h->array_len_max != 0
		 && (entry.array_len < h->array_len_min || h->array_len_max < entry.array_len)) {
			ni_error("%s: unexpected array length %u for dict element \"%s\"",
					__FUNCTION__, (int) entry.array_len, entry.key);
			rv = -EINVAL;
			break;
		}

		if (h->set)
			h->set(&entry, user_object);
	}

	return rv;
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
		 || var->type == DBUS_TYPE_ARRAY)
			ni_dbus_variant_destroy(var);
	}
	var->type = new_type;
}

void
ni_dbus_variant_set_string(ni_dbus_variant_t *var, const char *value)
{
	__ni_dbus_variant_change_type(var, DBUS_TYPE_BOOLEAN);
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
ni_dbus_variant_destroy(ni_dbus_variant_t *var)
{
	if (var->type == DBUS_TYPE_STRING)
		ni_string_free(&var->string_value);
	memset(var, 0, sizeof(*var));
	var->type = DBUS_TYPE_INVALID;
}

/*
 * Offsets of all elements in the variant struct
 */
unsigned int
__ni_dbus_variant_offsets[256] = {
[DBUS_TYPE_BYTE]		= offsetof(ni_dbus_variant_t, byte_value),
[DBUS_TYPE_BOOLEAN]		= offsetof(ni_dbus_variant_t, bool_value),
[DBUS_TYPE_STRING]		= offsetof(ni_dbus_variant_t, string_value),
[DBUS_TYPE_INT16]		= offsetof(ni_dbus_variant_t, int16_value),
[DBUS_TYPE_UINT16]		= offsetof(ni_dbus_variant_t, uint16_value),
[DBUS_TYPE_INT32]		= offsetof(ni_dbus_variant_t, int32_value),
[DBUS_TYPE_UINT32]		= offsetof(ni_dbus_variant_t, uint32_value),
[DBUS_TYPE_INT64]		= offsetof(ni_dbus_variant_t, int64_value),
[DBUS_TYPE_UINT64]		= offsetof(ni_dbus_variant_t, uint64_value),
};
