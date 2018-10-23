/*
 *	An elementary JSON implementation
 *
 *	Copyright (C) 2015 SUSE Linux GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#if 0
#include <iconv.h>
#endif
#include <inttypes.h>
#include <wicked/logging.h>

#include "json.h"
#include "buffer.h"
#include "util_priv.h"

/*
 * object and array prealloc chunk sizes
 */
#define	NI_JSON_OBJECT_CHUNK	4
#define NI_JSON_ARRAY_CHUNK	4


/*
 * structured types
 */
struct ni_json {
	unsigned int	refcount;
	ni_json_type_t	type;

	union {
	    ni_bool_t		bool_value;
	    int64_t		int64_value;
	    double		double_value;
	    char *		string_value;
	    ni_json_object_t *	object_value;
	    ni_json_array_t *	array_value;
	};
};

struct ni_json_pair {
	unsigned int		refcount;

	char *			name;
	ni_json_t *		value;
};

struct ni_json_object {
	unsigned int		count;
	ni_json_pair_t **	data;
};

struct ni_json_array {
	unsigned int		count;
	ni_json_t **		data;
};

ni_json_type_t
ni_json_type(const ni_json_t *json)
{
	return json ? json->type : NI_JSON_TYPE_NONE;
}

const char *
ni_json_type_name(ni_json_type_t type)
{
	static const ni_intmap_t	type_names[] = {
		{ "null",	NI_JSON_TYPE_NULL	},
		{ "bool",	NI_JSON_TYPE_BOOL	},
		{ "int64",	NI_JSON_TYPE_INT64	},
		{ "double",	NI_JSON_TYPE_DOUBLE	},
		{ "string",	NI_JSON_TYPE_STRING	},
		{ "object",	NI_JSON_TYPE_OBJECT	},
		{ "array",	NI_JSON_TYPE_ARRAY	},
		{ NULL,		NI_JSON_TYPE_NONE	}
	};
	return ni_format_uint_mapped(type, type_names);
}

/*
 * json variant value access
 */
static inline ni_bool_t *
ni_json_to_bool(ni_json_t *json)
{
	return ni_json_is_bool(json) ? &json->bool_value : NULL;
}

static inline int64_t *
ni_json_to_int64(ni_json_t *json)
{
	return ni_json_is_int64(json) ? &json->int64_value : NULL;
}

static inline double *
ni_json_to_double(ni_json_t *json)
{
	return ni_json_is_double(json) ? &json->double_value : NULL;
}

static inline char **
ni_json_to_string(ni_json_t *json)
{
	return ni_json_is_string(json) ? &json->string_value : NULL;
}

static inline ni_json_object_t *
ni_json_to_object(ni_json_t *json)
{
	return ni_json_is_object(json) ? json->object_value : NULL;
}

static inline ni_json_array_t *
ni_json_to_array(ni_json_t *json)
{
	return ni_json_is_array(json) ? json->array_value : NULL;
}

/*
 * json scalar value access
 */
ni_bool_t
ni_json_bool_get(ni_json_t *json, ni_bool_t *ret)
{
	ni_bool_t *val;

	if (ret && (val = ni_json_to_bool(json))) {
		*ret = *val;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_json_int64_get(ni_json_t *json, int64_t *ret)
{
	int64_t *val;

	if (ret && (val = ni_json_to_int64(json))) {
		*ret = *val;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_json_double_get(ni_json_t *json, double *ret)
{
	double *val;

	if (ret && (val = ni_json_to_double(json))) {
		*ret = *val;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_json_string_get(ni_json_t *json, char **ret)
{
	char **val;

	if (ret && (val = ni_json_to_string(json))) {
		ni_string_dup(ret, *val);
		return TRUE;
	}
	return FALSE;
}

/*
 * json object name:value pair
 */
ni_json_pair_t *
ni_json_pair_new(const char *name, ni_json_t *value)
{
	ni_json_pair_t *pair;

	if (name && value) {
		pair = xcalloc(1, sizeof(*pair));
		pair->refcount = 1;
		pair->name = xstrdup(name);
		pair->value = value;
		return pair;
	}
	return NULL;
}

ni_json_pair_t *
ni_json_pair_ref(ni_json_pair_t *pair)
{
	if (pair) {
		ni_assert(pair->refcount);
		pair->refcount++;
	}
	return pair;
}

void
ni_json_pair_free(ni_json_pair_t *pair)
{
	if (!pair)
		return;

	ni_assert(pair->refcount);
	pair->refcount--;
	if (pair->refcount != 0)
		return;

	ni_json_free(pair->value);
	free(pair->name);
	free(pair);
}

const char *
ni_json_pair_get_name(ni_json_pair_t *pair)
{
	return pair ? pair->name : NULL;
}

ni_json_t *
ni_json_pair_get_value(ni_json_pair_t *pair)
{
	return pair ? pair->value : NULL;
}

ni_json_t *
ni_json_pair_ref_value(ni_json_pair_t *pair)
{
	return ni_json_ref(ni_json_pair_get_value(pair));
}

ni_bool_t
ni_json_pair_set_value(ni_json_pair_t *pair, ni_json_t *value)
{
	if (value) {
		ni_json_free(pair->value);
		pair->value = value;
		return TRUE;
	}
	return FALSE;
}


/*
 * json object
 */
static inline ni_json_object_t *
ni_json_object_new(void)
{
	return xcalloc(1, sizeof(ni_json_object_t));
}

static void
ni_json_object_free(ni_json_object_t *njo)
{
	while (njo->count) {
		njo->count--;
		ni_json_pair_free(njo->data[njo->count]);
		njo->data[njo->count] = NULL;
	}
	free(njo->data);
	njo->data = NULL;
	free(njo);
}

ni_json_pair_t *
ni_json_object_get_pair(ni_json_t *json, const char *name)
{
	ni_json_object_t *njo;
	unsigned int i;

	if (!(njo = ni_json_to_object(json)))
		return NULL;

	for (i = 0; i < njo->count; ++i) {
		ni_json_pair_t *pair = njo->data[i];

		if (ni_string_eq(pair->name, name))
			return pair;
	}
	return NULL;
}

ni_json_pair_t *
ni_json_object_get_pair_at(ni_json_t *json, unsigned int pos)
{
	ni_json_object_t *njo;

	if (!(njo = ni_json_to_object(json)) || pos >= njo->count)
		return NULL;

	return njo->data[pos];
}

ni_json_pair_t *
ni_json_object_ref_pair_at(ni_json_t *json, unsigned int pos)
{
	return ni_json_pair_ref(ni_json_object_get_pair_at(json, pos));
}

ni_json_pair_t *
ni_json_object_ref_pair(ni_json_t *json, const char *name)
{
	return ni_json_pair_ref(ni_json_object_get_pair(json, name));
}

ni_json_t *
ni_json_object_get_value(ni_json_t *json, const char *name)
{
	ni_json_pair_t *pair = ni_json_object_get_pair(json, name);
	return pair ? pair->value : NULL;
}

ni_json_t *
ni_json_object_ref_value(ni_json_t *json, const char *name)
{
	return ni_json_ref(ni_json_object_get_value(json, name));
}

static void
ni_json_object_realloc(ni_json_object_t *njo, unsigned int size)
{
	ni_json_pair_t **data;
	unsigned int i;

	size = (size + NI_JSON_OBJECT_CHUNK);
	data = xrealloc(njo->data, size * sizeof(ni_json_pair_t *));
	njo->data = data;

	for (i = njo->count; i < size; ++i)
		njo->data[i] = NULL;
}

static ni_bool_t
ni_json_object_append(ni_json_t *json, const char *name, ni_json_t *value)
{
	ni_json_object_t *njo;
	ni_json_pair_t *pair;

	if (!(njo = ni_json_to_object(json)))
		return FALSE;

	if (!(pair = ni_json_pair_new(name, value)))
		return FALSE;

	if ((njo->count % NI_JSON_OBJECT_CHUNK) == 0)
		ni_json_object_realloc(njo, njo->count);

	njo->data[njo->count++] = pair;
	return TRUE;
}

static ni_json_t *
ni_json_object_clone(const ni_json_object_t *njo)
{
	ni_json_t *json;
	unsigned int i;

	json = ni_json_new_object();
	for(i = 0; i < njo->count; ++i) {
		ni_json_pair_t *pair = njo->data[i];
		ni_json_t *value = ni_json_clone(pair->value);
		if (!ni_json_object_append(json, pair->name, value)) {
			ni_json_free(value);
			ni_json_free(json);
			return NULL;
		}
	}
	return json;
}

ni_bool_t
ni_json_object_set(ni_json_t *json, const char *name, ni_json_t *value)
{
	ni_json_pair_t *pair;

	if (!json || !name || !value)
		return FALSE;

	if ((pair = ni_json_object_get_pair(json, name))) {
		return ni_json_pair_set_value(pair, value);
	} else {
		return ni_json_object_append(json, name, value);
	}
	return FALSE;
}

ni_json_t *
ni_json_object_remove_at(ni_json_t *json, unsigned int pos)
{
	ni_json_object_t *njo;
	ni_json_t *ret;

	if (!(njo = ni_json_to_object(json)) || pos >= njo->count)
		return NULL;

	ret = ni_json_ref(njo->data[pos]->value);
	ni_json_pair_free(njo->data[pos]);
	njo->count--;

	if (pos < njo->count) {
		memmove(&njo->data[pos], &njo->data[pos + 1],
			(njo->count - pos) * sizeof(ni_json_pair_t *));
	}
	njo->data[njo->count] = NULL;

	return ret;
}

ni_bool_t
ni_json_object_delete_at(ni_json_t *json, unsigned int pos)
{
	ni_json_t *ref = ni_json_object_remove_at(json, pos);
	ni_json_free(ref);
	return ref != NULL;
}

ni_json_t *
ni_json_object_remove(ni_json_t *json, const char *name)
{
	ni_json_object_t *njo;
	unsigned int i;

	if (!(njo = ni_json_to_object(json)))
		return NULL;

	for (i = 0; i < njo->count; ++i) {
		ni_json_pair_t *pair = njo->data[i];

		if (ni_string_eq(pair->name, name))
			return ni_json_object_remove_at(json, i);
	}
	return NULL;
}

ni_bool_t
ni_json_object_delete(ni_json_t *json, const char *name)
{
	ni_json_t *ref = ni_json_object_remove(json, name);
	ni_json_free(ref);
	return ref != NULL;
}

unsigned int
ni_json_object_entries(ni_json_t *json)
{
	ni_json_object_t *njo;

	if ((njo = ni_json_to_object(json)))
		return njo->count;
	return 0;
}

/*
 * json array
 */
static inline ni_json_array_t *
ni_json_array_new(void)
{
	return xcalloc(1, sizeof(ni_json_array_t));
}

static void
ni_json_array_free(ni_json_array_t *nja)
{
	while (nja->count) {
		nja->count--;
		ni_json_free(nja->data[nja->count]);
		nja->data[nja->count] = NULL;
	}
	free(nja->data);
	nja->data = NULL;
	free(nja);
}

ni_json_t *
ni_json_array_get(ni_json_t *json, unsigned int pos)
{
	ni_json_array_t *nja;

	if (!(nja = ni_json_to_array(json)) || pos >= nja->count)
		return NULL;
	return nja->data[pos];
}

ni_json_t *
ni_json_array_ref(ni_json_t *json, unsigned int pos)
{
	return ni_json_ref(ni_json_array_get(json, pos));
}

static void
ni_json_array_realloc(ni_json_array_t *nja, unsigned int size)
{
	ni_json_t **data;
	unsigned int i;

	size = (size + NI_JSON_ARRAY_CHUNK);
	data = xrealloc(nja->data, size * sizeof(ni_json_t *));
	nja->data = data;

	for (i = nja->count; i < size; ++i)
		nja->data[i] = NULL;
}

ni_bool_t
ni_json_array_append(ni_json_t *json, ni_json_t *value)
{
	ni_json_array_t *nja;

	if (!value || !(nja = ni_json_to_array(json)))
		return FALSE;

	if ((nja->count % NI_JSON_ARRAY_CHUNK) == 0)
		ni_json_array_realloc(nja, nja->count);

	nja->data[nja->count++] = value;
	return TRUE;
}

ni_bool_t
ni_json_array_insert(ni_json_t *json, unsigned int pos, ni_json_t *value)
{
	ni_json_array_t *nja;

	if (!value || !(nja = ni_json_to_array(json)))
		return FALSE;

	if ((nja->count % NI_JSON_ARRAY_CHUNK) == 0)
		ni_json_array_realloc(nja, nja->count);

	if (pos >= nja->count) {
		nja->data[nja->count++] = value;
	} else {
		memmove(&nja->data[pos + 1], &nja->data[pos],
			(nja->count - pos) * sizeof(ni_json_t *));
		nja->data[pos] = value;
		nja->count++;
	}
	return TRUE;
}

ni_bool_t
ni_json_array_set(ni_json_t *json, unsigned int pos, ni_json_t *value)
{
	ni_json_array_t *nja;

	if (!value || !(nja = ni_json_to_array(json)) || pos >= nja->count)
		return FALSE;

	ni_json_free(nja->data[pos]);
	nja->data[pos] = value;
	return TRUE;
}

static ni_json_t *
ni_json_array_clone(const ni_json_array_t *src)
{
	ni_json_t *json;
	unsigned int i;

	json = ni_json_new_array();
	for (i = 0; i < src->count; ++i) {
		ni_json_t *value = ni_json_clone(src->data[i]);
		if (!ni_json_array_append(json, value)) {
			ni_json_free(value);
			ni_json_free(json);
			return NULL;
		}
	}
	return json;
}

ni_json_t *
ni_json_array_remove_at(ni_json_t *json, unsigned int pos)
{
	ni_json_array_t *nja;
	ni_json_t *ret;

	if (!(nja = ni_json_to_array(json)) || pos >= nja->count)
		return NULL;

	ret = nja->data[pos];
	nja->count--;
	if (pos < nja->count) {
		memmove(&nja->data[pos], &nja->data[pos + 1],
			(nja->count - pos) * sizeof(ni_json_t *));
	}
	nja->data[pos] = NULL;
	return ret;
}

ni_bool_t
ni_json_array_delete_at(ni_json_t *json, unsigned int pos)
{
	ni_json_t *ref = ni_json_array_remove_at(json, pos);
	ni_json_free(ref);
	return ref != NULL;
}

unsigned int
ni_json_array_entries(ni_json_t *json)
{
	ni_json_array_t *nja;

	if ((nja = ni_json_to_array(json)))
		return nja->count;
	return 0;
}

/*
 * json constructors, destructor, clone and reference
 */
static ni_json_t *
ni_json_new(ni_json_type_t type)
{
	ni_json_t *json;

	json = xcalloc(1, sizeof(*json));
	json->type = type;
	json->refcount = 1;
	return json;
}

ni_json_t *
ni_json_new_null(void)
{
	static ni_json_t _null = {
		.type = NI_JSON_TYPE_NULL,
		.object_value = NULL,
		.refcount = -1U,
	};
	return &_null;
}

ni_json_t *
ni_json_new_bool(ni_bool_t value)
{
	ni_json_t *json;

	json = ni_json_new(NI_JSON_TYPE_BOOL);
	json->bool_value = !!value;
	return json;
}

ni_json_t *
ni_json_new_int64(int64_t value)
{
	ni_json_t *json;

	json = ni_json_new(NI_JSON_TYPE_INT64);
	json->int64_value = value;
	return json;
}

ni_json_t *
ni_json_new_double(double value)
{
	ni_json_t *json;

	json = ni_json_new(NI_JSON_TYPE_DOUBLE);
	json->double_value = value;
	return json;
}

ni_json_t *
ni_json_new_string(const char *value)
{
	ni_json_t *json;

	json = ni_json_new(NI_JSON_TYPE_STRING);
	ni_string_dup(&json->string_value, value);
	return json;
}

ni_json_t *
ni_json_new_object(void)
{
	ni_json_t *json;

	json = ni_json_new(NI_JSON_TYPE_OBJECT);
	json->object_value = ni_json_object_new();
	return json;
}

ni_json_t *
ni_json_new_array(void)
{
	ni_json_t *json;

	json = ni_json_new(NI_JSON_TYPE_ARRAY);
	json->array_value = ni_json_array_new();
	return json;
}

ni_json_t *
ni_json_new_number(const char *string)
{
	if (ni_string_contains(string, ".")) {
		double value = 0.0;

		if (ni_parse_double(string, &value) < 0)
			return NULL;

		return ni_json_new_double(value);
	} else {
		int64_t value = 0;

		if (ni_parse_int64(string, &value, 10) < 0)
			return NULL;

		return ni_json_new_int64(value);
	}
}

ni_json_t *
ni_json_new_literal(const char *string)
{
	if (ni_string_eq("null", string))
		return ni_json_new_null();

	if (ni_string_eq("true", string))
		return ni_json_new_bool(TRUE);

	if (ni_string_eq("false", string))
		return ni_json_new_bool(FALSE);

	return NULL;
}

ni_json_t *
ni_json_clone(const ni_json_t *src)
{
	switch (ni_json_type(src)) {
	case NI_JSON_TYPE_NULL:
		return ni_json_new_null();

	case NI_JSON_TYPE_BOOL:
		return ni_json_new_bool(src->bool_value);

	case NI_JSON_TYPE_INT64:
		return ni_json_new_int64(src->int64_value);

	case NI_JSON_TYPE_DOUBLE:
		return ni_json_new_double(src->double_value);

	case NI_JSON_TYPE_STRING:
		return ni_json_new_string(src->string_value);

	case NI_JSON_TYPE_OBJECT:
		return ni_json_object_clone(src->object_value);

	case NI_JSON_TYPE_ARRAY:
		return ni_json_array_clone(src->array_value);

	default:
		return NULL;
	}
}

ni_json_t *
ni_json_ref(ni_json_t *json)
{
	if (json && json->refcount != -1U) {
		ni_assert(json->refcount);
		json->refcount++;
	}
	return json;
}

void
ni_json_free(ni_json_t *json)
{
	if (!json || json->refcount == -1U)
		return;

	ni_assert(json->refcount && json->type);
	json->refcount--;
	if (json->refcount != 0)
		return;

	switch (json->type) {
	case NI_JSON_TYPE_BOOL:
	case NI_JSON_TYPE_INT64:
	case NI_JSON_TYPE_DOUBLE:
		json->type = NI_JSON_TYPE_NONE;
		free(json);
		break;

	case NI_JSON_TYPE_STRING:
		ni_string_free(&json->string_value);
		json->type = NI_JSON_TYPE_NONE;
		free(json);
		break;

	case NI_JSON_TYPE_OBJECT:
		ni_json_object_free(json->object_value);
		json->type = NI_JSON_TYPE_NONE;
		free(json);
		break;

	case NI_JSON_TYPE_ARRAY:
		ni_json_array_free(json->array_value);
		json->type = NI_JSON_TYPE_NONE;
		free(json);
		break;

	default:
		ni_assert(json->type >  NI_JSON_TYPE_NULL &&
			  json->type <= NI_JSON_TYPE_ARRAY);
		break;
	}
}

/*
 * format into stringbuf
 */
static inline const char *
ni_json_string_escape_map(unsigned char uc, const ni_json_format_options_t *options)
{
	switch (uc) {
		case '\b':	return "\\b";
		case '\f':	return "\\f";
		case '\n':	return "\\n";
		case '\r':	return "\\r";
		case '\t':	return "\\t";
		case '\\':	return "\\\\";
		case '"':	return "\\\"";
		case '/':	if (options->flags & NI_JSON_ESCAPE_SLASH)
					return "\\/";
				return NULL;
		default:	return NULL;
	}
}

static void
ni_json_string_escape(ni_stringbuf_t *buf, const char *str,
			const ni_json_format_options_t *options)
{
	static const char *hex = "0123456789abcdefABCDEF";
	size_t len = ni_string_len(str);
	size_t pos = 0, off = 0;
	unsigned char uc;
	const char *es;

	while (len--) {
		uc = str[pos];
		es = ni_json_string_escape_map(uc, options);
		if (es) {
			if (pos - off > 0)
				ni_stringbuf_put(buf, str + off, pos - off);
			ni_stringbuf_puts(buf, es);
			off = ++pos;
		} else
		if (uc < ' ') {
			if (pos - off > 0)
				ni_stringbuf_put(buf, str + off, pos - off);
			ni_stringbuf_printf(buf, "\\u00%c%c", hex[uc >> 4], hex[uc & 0x0f]);
			off = ++pos;
		} else {
			pos++;
		}
	}
	if (pos - off > 0)
		ni_stringbuf_put(buf, str + off, pos - off);
}

static void
ni_json_string_format(ni_stringbuf_t *buf, const char *value,
			const ni_json_format_options_t *options)
{
	ni_stringbuf_putc(buf, '\"');
	ni_json_string_escape(buf, value, options);
	ni_stringbuf_putc(buf, '\"');
}

static void
ni_json_array_format(ni_stringbuf_t *buf, const ni_json_array_t *nja,
			const ni_json_format_options_t *options)
{
	unsigned int i;

	if (!nja || !nja->count) {
		ni_stringbuf_puts(buf, "[]");
		return;
	}

	ni_stringbuf_puts(buf, "[ ");
	for (i = 0; i < nja->count; ++i) {
		if (i)
			ni_stringbuf_puts(buf, ", ");
		ni_json_format_string(buf, nja->data[i], options);
	}
	ni_stringbuf_puts(buf, " ]");
}

static void
ni_json_pair_format(ni_stringbuf_t *buf, const ni_json_pair_t *pair,
			const ni_json_format_options_t *options)
{
	ni_stringbuf_putc(buf, '\"');
	ni_json_string_escape(buf, pair->name, options);
	ni_stringbuf_puts(buf, "\": ");
	ni_json_format_string(buf, pair->value, options);
}

static void
ni_json_object_format(ni_stringbuf_t *buf, const ni_json_object_t *njo,
			const ni_json_format_options_t *options)
{
	unsigned int i;

	if (!njo || !njo->count) {
		ni_stringbuf_puts(buf, "{}");
		return;
	}

	ni_stringbuf_puts(buf, "{ ");
	for (i = 0; i < njo->count; ++i) {
		if (i)
			ni_stringbuf_puts(buf, ", ");
		ni_json_pair_format(buf, njo->data[i], options);
	}
	ni_stringbuf_puts(buf, " }");
}

const char *
ni_json_format_string(ni_stringbuf_t *buf, const ni_json_t *json,
			const ni_json_format_options_t *options)
{
	static const ni_json_format_options_t defaults = {
		.flags = 0,
	};

	if (!json || !buf)
		return NULL;

	if (!options)
		options = &defaults;

	switch (json->type) {
	case NI_JSON_TYPE_NULL:
		ni_stringbuf_puts(buf, "null");
		break;

	case NI_JSON_TYPE_BOOL:
		ni_stringbuf_puts(buf, json->bool_value ? "true" : "false");
		break;

	case NI_JSON_TYPE_INT64:
		ni_stringbuf_printf(buf, "%"PRId64, json->int64_value);
		break;

	case NI_JSON_TYPE_DOUBLE:
		ni_stringbuf_printf(buf, "%.*g", 2, json->double_value);
		break;

	case NI_JSON_TYPE_STRING:
		ni_json_string_format(buf, json->string_value, options);
		break;

	case NI_JSON_TYPE_ARRAY:
		ni_json_array_format(buf, json->array_value, options);
		break;

	case NI_JSON_TYPE_OBJECT:
		ni_json_object_format(buf, json->object_value, options);
		break;

	default:
		return NULL;
	}

	return buf->string;
}

/*
 * parsing from string
 */
typedef enum {
	None = 0,
	Literal,
	Number,
	String,
	Colon,
	Comma,
	ArrayBegin,
	ArrayEnd,
	ObjectBegin,
	ObjectEnd,
	EndOfFile,
} ni_json_token_type_t;

typedef enum {
	Initial = 0,
	InArray,
	InObject,
	InPair,
	Stop,
	Error
} ni_json_state_t;

typedef struct ni_json_reader_stack	ni_json_reader_stack_t;
typedef struct ni_json_reader		ni_json_reader_t;

struct ni_json_reader_stack {
	ni_json_reader_stack_t *	parent;
	ni_json_state_t			state;
	char *				name;
	ni_json_t *			value;
};

struct ni_json_reader {
	ni_buffer_t *			inbuf;
#if 0
	iconv_t				iconv;
#endif
	ni_bool_t			quiet;
	ni_string_array_t		error;
	ni_json_reader_stack_t *	stack;
};

static ni_json_reader_stack_t *
ni_json_reader_stack_new(ni_json_reader_t *jr, ni_json_state_t state)
{
	ni_json_reader_stack_t *stack;

	stack = xcalloc(1, sizeof(*stack));
	stack->state = state;
	stack->parent = jr->stack;
	jr->stack = stack;
	return stack;
}

static ni_json_reader_stack_t *
ni_json_reader_stack_pop(ni_json_reader_t *jr)
{
	ni_json_reader_stack_t *stack;

	if ((stack = jr->stack)) {
		jr->stack = stack->parent;
		stack->parent = NULL;
		ni_string_free(&stack->name);
		ni_json_free(stack->value);
	}
	return jr->stack;
}

static ni_bool_t
ni_json_reader_init_buffer(ni_json_reader_t *jr, ni_buffer_t *buf)
{
	jr->inbuf = buf;
#if 0
	jr->iconv = (iconv_t)-1;
#endif
	jr->stack = NULL;
	jr->quiet = FALSE;
	ni_string_array_init(&jr->error);
	return buf != NULL;
}

#if 0
static ni_bool_t
ni_json_reader_open_iconv(ni_json_reader_t *jr)
{
	if (jr->iconv == (iconv_t)-1)
		jr->iconv = iconv_open("UTF-8", "UTF-16BE");
	return	jr->iconv != (iconv_t)-1;
}
#endif

static ni_bool_t
ni_json_reader_destroy(ni_json_reader_t *jr)
{
	ni_string_array_destroy(&jr->error);
	while (ni_json_reader_stack_pop(jr))
		;
	jr->inbuf = NULL;
#if 0
	if (jr->iconv)
		iconv_close(jr->iconv);
	jr->iconv = (iconv_t)-1;
#endif
	return TRUE;
}

static inline ni_json_state_t
ni_json_reader_get_state(ni_json_reader_t *jr)
{
	return jr->stack->state;
}

static inline void
ni_json_reader_set_state(ni_json_reader_t *jr, ni_json_state_t state)
{
	jr->stack->state = state;
}

static inline ni_bool_t
ni_json_reader_set_error(ni_json_reader_t *jr, const char *fmt, ...)
{
	if (!ni_string_empty(fmt)) {
		char *err = NULL;
		va_list ap;
		int ret;

		va_start(ap, fmt);
		ret = vasprintf(&err, fmt, ap);
		va_end(ap);
		if (ret > 0 && !ni_string_empty(err)) {
			if (!jr->quiet)
				ni_error("json reader: %s", err);
			ni_string_array_append(&jr->error, err);
		}
		free(err);
	}
	ni_json_reader_set_state(jr, Error);
	return FALSE;
}

static inline const char *
ni_json_reader_get_pair_name(ni_json_reader_t *jr)
{
	return jr->stack->name;
}

static inline void
ni_json_reader_set_pair_name(ni_json_reader_t *jr, const char *name)
{
	ni_string_dup(&jr->stack->name, name);
}

static inline ni_json_t *
ni_json_reader_get_current(ni_json_reader_t *jr)
{
	return jr->stack->value;
}

static inline void
ni_json_reader_set_current(ni_json_reader_t *jr, ni_json_t *value)
{
	jr->stack->value = value;
}

static inline ni_json_t *
ni_json_reader_get_parent(ni_json_reader_t *jr)
{
	return jr->stack->parent ? jr->stack->parent->value : NULL;
}

static void
ni_json_reader_skip_spaces(ni_json_reader_t *jr)
{
	int cc;

	while ((cc = ni_buffer_getc(jr->inbuf)) != EOF) {
		if (!isspace(cc)) {
			ni_buffer_ungetc(jr->inbuf, cc);
			break;
		}
	}
}

static void
ni_json_reader_get_literal(ni_json_reader_t *jr, ni_stringbuf_t *res)
{
	int cc;

	while ((cc = ni_buffer_getc(jr->inbuf)) != EOF) {
		if (!isalpha(cc)) {
			ni_buffer_ungetc(jr->inbuf, cc);
			break;
		}
		ni_stringbuf_putc(res, cc);
	}
}

static void
ni_json_reader_get_number(ni_json_reader_t *jr, ni_stringbuf_t *res)
{
	int cc;

	while ((cc = ni_buffer_getc(jr->inbuf)) != EOF) {
		switch (cc) {
		case '+': case '-':
		case 'e': case 'E':
		case '.':
			ni_stringbuf_putc(res, cc);
			break;
		default:
			if (isdigit(cc)) {
				ni_stringbuf_putc(res, cc);
				break;
			}
			ni_buffer_ungetc(jr->inbuf, cc);
			return;
		}
	}
}

static ni_bool_t
ni_json_reader_get_eunicode(ni_json_reader_t *jr, ni_stringbuf_t *res)
{
	char hbuf[5], sbuf[2] /*, obuf[8], *sptr, *optr */;
	/* size_t slen, olen, n; */
	unsigned int octet;
	char *end = NULL;

	if (ni_buffer_count(jr->inbuf) < 4)
		return FALSE;

	/*
	 * TODO: We decode mandatory control chars only...
	 * Also.. do we need to handle multiple sequences:
	 * "\uD834\uDD1E", a G clef character (U+1D11E)??
	 */
	memset(hbuf, 0, sizeof(hbuf));
	if (ni_buffer_get(jr->inbuf, &hbuf[0], 2) < 0)
		return FALSE;

	octet = strtoul(&hbuf[0], &end, 16);
	if (octet > 255 || *end != '\0')
		return FALSE;
	sbuf[0] = octet & 0xff;

	if (ni_buffer_get(jr->inbuf, &hbuf[2], 2) < 0)
		return FALSE;
	octet = strtoul(&hbuf[2], &end, 16);
        if (octet > 255 || *end != '\0')
		return FALSE;
	sbuf[1] = octet & 0xff;

	if (sbuf[0] != 0)
		return FALSE;
	if (sbuf[1] != 0)
		ni_stringbuf_putc(res, sbuf[1]);
#if 0
	sptr = sbuf;
	slen = sizeof(sbuf);
	while (slen > 0) {
		optr = obuf;
		olen = sizeof(obuf);

		n = iconv(jr->iconv, &sptr, &slen, &optr, &olen);
		if (n == (size_t)-1)
			return FALSE;

		ni_stringbuf_put(res, obuf, n);
	}
#endif
	return TRUE;
}

static inline const char *
ni_json_string_unescape_map(unsigned char ec)
{
	switch (ec) {
		case '/':	return "/";
		case '\\':	return "\\";
		case '"':	return "\"";
		case 'b':	return "\b";
		case 'f':	return "\f";
		case 'n':	return "\n";
		case 'r':	return "\r";
		case 't':	return "\t";
		default:	return NULL;
	}
}

static ni_bool_t
ni_json_reader_get_qstring(ni_json_reader_t *jr, ni_stringbuf_t *res)
{
	ni_bool_t escaped = FALSE;
	const char *us;
	int cc;

	while ((cc = ni_buffer_getc(jr->inbuf)) != EOF) {
		if (escaped) {
			if (cc == 'u') {
#if 0
				if (!ni_json_reader_open_iconv(jr))
					return FALSE;	/* decoder failed */
#endif
				if (!ni_json_reader_get_eunicode(jr, res))
					return FALSE;	/* decoding error */
			} else {
				if (!(us = ni_json_string_unescape_map(cc)))
					return FALSE;	/* unknown escape */

				ni_stringbuf_puts(res, us);
			}
			escaped = FALSE;
		} else {
			switch (cc) {
			case '"':
				return TRUE; /* OK, end of quoted string */
			case '\\':
				escaped = TRUE;
				break;
			default:
				ni_stringbuf_putc(res, cc);
				break;
			}
		}
	}
	return FALSE; /* unterminated quoted string */
}

static ni_json_token_type_t
ni_json_get_token(ni_json_reader_t *jr, ni_stringbuf_t *res)
{
	int cc;

	if ((cc = ni_buffer_getc(jr->inbuf)) == EOF)
		return EndOfFile;

	switch (cc) {
	case '[':
		return ArrayBegin;
	case ']':
		return ArrayEnd;
	case '{':
		return ObjectBegin;
	case '}':
		return ObjectEnd;
	case ',':
		return Comma;
	case ':':
		return Colon;
	case '"':
		if (!ni_json_reader_get_qstring(jr, res)) {
			ni_json_reader_set_error(jr, "failed to extract string");
			return None;
		}
		return String;
	case 'n':
	case 't':
	case 'f':
		ni_stringbuf_putc(res, cc);
		ni_json_reader_get_literal(jr, res);
		return Literal;

	default:
		if (isdigit(cc) || cc == '-') {
			ni_stringbuf_putc(res, cc);
			ni_json_reader_get_number(jr, res);
			return Number;
		}
		return None;
	}
}

static void
ni_json_reader_process_array_beg(ni_json_reader_t *jr)
{
	if (ni_json_reader_get_current(jr)) {
		ni_json_reader_set_error(jr, "unexpected array begin");
	} else {
		ni_json_reader_set_current(jr, ni_json_new_array());
		if (!ni_json_reader_stack_new(jr, InArray))
			ni_json_reader_set_state(jr, Error);
	}
}

static void
ni_json_reader_process_array_add(ni_json_reader_t *jr)
{
	ni_json_t *parent = ni_json_reader_get_parent(jr);
	ni_json_t *value = ni_json_reader_get_current(jr);

	ni_json_reader_set_current(jr, NULL);
	if (!value)
		ni_json_reader_set_error(jr, "unexpected array element separator");
	else
	if (!ni_json_array_append(parent, value)) {
		ni_json_free(value);
		ni_json_reader_set_error(jr, "unable to add value to array");
	}
}

static void
ni_json_reader_process_array_end(ni_json_reader_t *jr)
{
	ni_json_t *parent = ni_json_reader_get_parent(jr);
	ni_json_t *value = ni_json_reader_get_current(jr);

	ni_json_reader_set_current(jr, NULL);
	if (!ni_json_reader_stack_pop(jr)) {
		ni_json_free(value);
		ni_json_reader_set_state(jr, Error);
	} else
	if (value && !ni_json_array_append(parent, value)) {
		ni_json_free(value);
		ni_json_reader_set_state(jr, Error);
	}

}

static void
ni_json_reader_process_object_beg(ni_json_reader_t *jr)
{
	if (ni_json_reader_get_current(jr)) {
		ni_json_reader_set_error(jr, "unexpected array begin");
	} else {
		ni_json_reader_set_current(jr, ni_json_new_object());
		if (!ni_json_reader_stack_new(jr, InObject))
			ni_json_reader_set_state(jr, Error);
	}
}

static void
ni_json_reader_process_object_add(ni_json_reader_t *jr)
{
	ni_json_t *parent = ni_json_reader_get_parent(jr);
	ni_json_t *value = ni_json_reader_get_current(jr);
	const char *name = ni_json_reader_get_pair_name(jr);

	if (!name)
		ni_json_reader_set_error(jr, "object pair without name");
	else
	if (!value)
		ni_json_reader_set_error(jr, "object pair without value");
	else
	if (!ni_json_object_set(parent, name, value)) {
		ni_json_free(value);
		ni_json_reader_set_error(jr, "unable to add member to object");
	}
	ni_json_reader_set_pair_name(jr, NULL);
	ni_json_reader_set_current(jr, NULL);
	ni_json_reader_set_state(jr, InObject);
}

static void
ni_json_reader_process_object_end(ni_json_reader_t *jr)
{
	ni_json_t *parent = ni_json_reader_get_parent(jr);
	ni_json_t *value = ni_json_reader_get_current(jr);
	const char *name = ni_json_reader_get_pair_name(jr);

	if (name && !value)
		ni_json_reader_set_error(jr, "unexpected object end");
	else
	if (name && value && !ni_json_object_set(parent, name, value)) {
		ni_json_free(value);
		ni_json_reader_set_error(jr, "unable to add member to object");
	}
	ni_json_reader_set_pair_name(jr, NULL);
	ni_json_reader_set_current(jr, NULL);
	ni_json_reader_set_state(jr, InObject);
	ni_json_reader_stack_pop(jr);
}

static void
ni_json_reader_process_literal_value(ni_json_reader_t *jr, const char *string)
{
	ni_json_t *value;

	if ((value = ni_json_new_literal(string)))
		ni_json_reader_set_current(jr, value);
	else
		ni_json_reader_set_error(jr, "invalid literal '%s'", string);
}

static void
ni_json_reader_process_number_value(ni_json_reader_t *jr, const char *string)
{
	ni_json_t *value;

	if ((value = ni_json_new_number(string)))
		ni_json_reader_set_current(jr, value);
	else
		ni_json_reader_set_error(jr, "invalid number '%s'", string);
}

static void
ni_json_reader_process_string_value(ni_json_reader_t *jr, const char *string)
{
	ni_json_t *value;

	if ((value = ni_json_new_string(string)))
		ni_json_reader_set_current(jr, value);
	else
		ni_json_reader_set_error(jr, "invalid string '%s'", string);
}

static void
ni_json_reader_parse_array(ni_json_reader_t *jr)
{
	ni_stringbuf_t tokenValue = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_token_type_t token;

	ni_json_reader_skip_spaces(jr);
	token = ni_json_get_token(jr, &tokenValue);

	switch (token) {
	case ArrayBegin:
		/* [ [...] ] or [ foo, bar, [...] ] */
		ni_json_reader_process_array_beg(jr);
		break;

	case Comma:
		ni_json_reader_process_array_add(jr);
		break;

	case ArrayEnd:
		/* be picky on unhandled case: [ foo, ] ?? */
		ni_json_reader_process_array_end(jr);
		break;

	case ObjectBegin:
		/* [ {...} ] or [ foo, bar, {...} ] */
		ni_json_reader_process_object_beg(jr);
		break;

	case Literal:
		if (ni_json_reader_get_current(jr))
			ni_json_reader_set_error(jr, "missed array element separator");
		else
			ni_json_reader_process_literal_value(jr, tokenValue.string);
		break;

	case Number:
		if (ni_json_reader_get_current(jr))
			ni_json_reader_set_error(jr, "missed array element separator");
		else
			ni_json_reader_process_number_value(jr, tokenValue.string);
		break;

	case String:
		if (ni_json_reader_get_current(jr))
			ni_json_reader_set_error(jr, "missed array element separator");
		else
			ni_json_reader_process_string_value(jr, tokenValue.string);
		break;

	case EndOfFile:
		ni_json_reader_set_error(jr, "unexpected end of file");
		break;

	default:
		ni_json_reader_set_error(jr, "unexpected array token");
		break;
	}
	ni_stringbuf_clear(&tokenValue);
}

static void
ni_json_reader_parse_object(ni_json_reader_t *jr)
{
	ni_stringbuf_t tokenValue = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_token_type_t token;
	ni_json_t *value;
	const char *name;

	ni_json_reader_skip_spaces(jr);
	token = ni_json_get_token(jr, &tokenValue);

	switch (token) {
	case ObjectEnd:
		ni_json_reader_process_object_end(jr);
		break;

	case String:
		/* { "name" : ... }, we seem to have a name or string value */
		if ((name = ni_json_reader_get_pair_name(jr)))
			ni_json_reader_set_error(jr, "unexpected object pair name");
		else
		if ((value = ni_json_reader_get_current(jr)))
			ni_json_reader_set_error(jr, "unexpected object pair value");
		else
			ni_json_reader_set_pair_name(jr, tokenValue.string);
		break;

	case Colon:
		if (!(name = ni_json_reader_get_pair_name(jr)))
			ni_json_reader_set_error(jr, "unexpected colon without object pair name");
		else
			ni_json_reader_set_state(jr, InPair);
		break;

	case EndOfFile:
		ni_json_reader_set_error(jr, "unexpected end of file");
		break;

	default:
		ni_json_reader_set_error(jr, "unexpected object token");
		break;
	}
	ni_stringbuf_clear(&tokenValue);
}

static void
ni_json_reader_parse_pair(ni_json_reader_t *jr)
{
	ni_stringbuf_t tokenValue = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_token_type_t token;

	ni_json_reader_skip_spaces(jr);
	token = ni_json_get_token(jr, &tokenValue);

	switch (token) {
	case ArrayBegin:
		ni_json_reader_process_array_beg(jr);
		break;

	case ObjectBegin:
		ni_json_reader_process_object_beg(jr);
		break;

	case Comma:
		ni_json_reader_process_object_add(jr);
		break;

	case ObjectEnd:
		ni_json_reader_process_object_end(jr);
		break;

	case Literal:
		if (ni_json_reader_get_current(jr))
			ni_json_reader_set_error(jr, "missed object member separator or end");
		else
			ni_json_reader_process_literal_value(jr, tokenValue.string);
		break;

	case Number:
		if (ni_json_reader_get_current(jr))
			ni_json_reader_set_error(jr, "missed object member separator or end");
		else
			ni_json_reader_process_number_value(jr, tokenValue.string);
		break;

	case String:
		if (ni_json_reader_get_current(jr))
			ni_json_reader_set_error(jr, "missed object memmer separator or end");
		else
			ni_json_reader_process_string_value(jr, tokenValue.string);
		break;

	case EndOfFile:
		ni_json_reader_set_error(jr, "unexpected end of file");
		break;

	default:
		ni_json_reader_set_error(jr, "unexpected object pair token");
		break;
	}
}

static void
ni_json_reader_parse_initial(ni_json_reader_t *jr)
{
	ni_stringbuf_t tokenValue = NI_STRINGBUF_INIT_DYNAMIC;
	ni_json_token_type_t token;

	ni_json_reader_skip_spaces(jr);
	token = ni_json_get_token(jr, &tokenValue);

	switch (token) {
	case ArrayBegin:
		ni_json_reader_process_array_beg(jr);
		break;

	case ObjectBegin:
		ni_json_reader_process_object_beg(jr);
		break;

	case Literal:
		if (ni_json_reader_get_current(jr))
			ni_json_reader_set_error(jr, "unexpected literal in scalar context");
		else
			ni_json_reader_process_literal_value(jr, tokenValue.string);
		break;

	case Number:
		if (ni_json_reader_get_current(jr))
			ni_json_reader_set_error(jr, "unexpected number in scalar context");
		else
			ni_json_reader_process_number_value(jr, tokenValue.string);
		break;

	case String:
		if (ni_json_reader_get_current(jr))
			ni_json_reader_set_error(jr, "unexpected string in scalar context");
		else
			ni_json_reader_process_string_value(jr, tokenValue.string);
		break;

	case EndOfFile:
		ni_json_reader_set_state(jr, Stop);
		break;

	default:
		ni_json_reader_set_error(jr, "unexpected token");
		break;
	}
}

static ni_json_t *
ni_json_reader_parse(ni_json_reader_t *jr)
{
	if (!jr || !ni_json_reader_stack_new(jr, Initial))
		return NULL;

	while (jr->stack) {
		switch (ni_json_reader_get_state(jr)) {
		default:
			ni_json_reader_set_error(jr, "Unexpected state in json reader");
			return NULL;
		case Error:
			/* error already printed unless quiet */
			return NULL;

		case Initial:
			ni_json_reader_parse_initial(jr);
			break;

		case InArray:
			ni_json_reader_parse_array(jr);
			break;

		case InObject:
			ni_json_reader_parse_object(jr);
			break;

		case InPair:
			ni_json_reader_parse_pair(jr);
			break;

		case Stop:
			return jr->stack ? ni_json_ref(jr->stack->value) : NULL;
		}
	}
	return NULL;
}

ni_json_t *
ni_json_parse_buffer(ni_buffer_t *buf)
{
	ni_json_reader_t reader;
	ni_json_t *json;

	if (!ni_json_reader_init_buffer(&reader, buf))
		return NULL;

	json = ni_json_reader_parse(&reader);
	if (!ni_json_reader_destroy(&reader)) {
		ni_json_free(json);
		return NULL;
	}
	return json;
}

ni_json_t *
ni_json_parse_string(const char *str)
{
	ni_buffer_t buf;

	if (ni_string_empty(str))
		return NULL;

	ni_buffer_init_reader(&buf, (char *)str, ni_string_len(str));
	return ni_json_parse_buffer(&buf);
}

