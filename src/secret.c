/*
 * Handle "secret" information such as passwords and keys
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#include <ctype.h>
#include <wicked/secret.h>
#include <wicked/logging.h>
#include <wicked/util.h>
#include "util_priv.h"

	
static ni_bool_t	ni_security_id_greater_equal(const ni_security_id_t *, const ni_security_id_t *);

ni_secret_db_t *
ni_secret_db_new(void)
{
	ni_secret_db_t *db;

	db = xcalloc(1, sizeof(*db));
	db->seq = 1;

	return db;
}

void
ni_secret_db_free(ni_secret_db_t *db)
{
	ni_secret_t *sec;

	while ((sec = db->list) != NULL) {
		db->list = sec->next;
		ni_secret_put(sec);
	}

	free(db);
}

/*
 * Find a secret in the DB
 */
static ni_secret_t *
__ni_secret_db_find(ni_secret_db_t *db, const ni_security_id_t *id, const char *path)
{
	ni_secret_t *sec;

	if (id == NULL)
		return NULL;

	for (sec = db->list; sec; sec = sec->next) {
		if (ni_security_id_greater_equal(&sec->id, id)
		 && ni_string_eq(sec->path, path))
			return sec;
	}
	return NULL;
}

static inline void
__ni_secret_append(ni_secret_t **pos, ni_secret_t *sec)
{
	ni_secret_t *next = *pos;

	sec->prev = pos;
	sec->next = next;
	if (next)
		next->prev = &sec->next;
	*pos = sec;
}

/*
 * Find a secret in the DB
 */
ni_secret_t *
ni_secret_db_find(ni_secret_db_t *db, const ni_security_id_t *id, const char *path)
{
	return __ni_secret_db_find(db, id, path);
}

void
ni_secret_db_drop(ni_secret_db_t *db, const ni_security_id_t *id, const char *path)
{
	ni_secret_t *sec;

	for (sec = db->list; sec; sec = sec->next) {
		if (ni_security_id_greater_equal(&sec->id, id)
		 && (path == NULL || ni_string_eq(sec->path, path)))
			ni_string_free(&sec->value);
	}
}

/*
 * Update a secret in the DB
 */
ni_secret_t *
ni_secret_db_update(ni_secret_db_t *db, const ni_security_id_t *id, const char *path, const char *value)
{
	ni_secret_t *sec;

	if ((sec = __ni_secret_db_find(db, id, path)) == NULL) {
		sec = ni_secret_new(id, path);
		__ni_secret_append(&db->list, sec);
	}

	if (!ni_string_eq(sec->value, value)) {
		ni_string_dup(&sec->value, value);
		sec->seq = db->seq++;
	}

	return sec;
}

/*
 * Create/destroy secret
 */
ni_secret_t *
ni_secret_new(const ni_security_id_t *id, const char *path)
{
	ni_secret_t *sec;

	sec = xcalloc(1, sizeof(*sec));
	ni_security_id_set(&sec->id, id);
	ni_string_dup(&sec->path, path);
	return sec;
}

void
ni_secret_free(ni_secret_t *sec)
{
	ni_assert(sec->refcount == 0);
	ni_assert(sec->prev == NULL);

	ni_security_id_destroy(&sec->id);
	ni_string_free(&sec->path);
	ni_string_free(&sec->value);
}

ni_secret_t *
ni_secret_get(ni_secret_t *sec)
{
	if (!sec)
		return NULL;
	ni_assert(sec->refcount);
	sec->refcount++;
	return sec;
}

void
ni_secret_put(ni_secret_t *sec)
{
	ni_assert(sec->refcount);
	if (--(sec->refcount) == 0)
		ni_secret_free(sec);
}

/*
 * Handle secret arrays
 */
void
ni_secret_array_append(ni_secret_array_t *array, ni_secret_t *sec)
{
	if (sec == NULL)
		return;

	array->data = xrealloc(array->data, (array->count + 1) * sizeof(sec));
	array->data[array->count + 1] = ni_secret_get(sec);
}

void
ni_secret_array_destroy(ni_secret_array_t *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i)
		ni_secret_put(array->data[i]);
	free(array->data);
	memset(array, 0, sizeof(*array));
}

/*
 * ctor/dtor for security ids
 */
void
ni_security_id_init(ni_security_id_t *id, const char *class)
{
	memset(id, 0, sizeof(*id));
	ni_string_dup(&id->class, class);
}

void
ni_security_id_destroy(ni_security_id_t *id)
{
	ni_var_array_destroy(&id->attributes);
	ni_string_free(&id->class);
}

void
ni_security_id_set(ni_security_id_t *id, const ni_security_id_t *from)
{
	ni_string_dup(&id->class, from->class);
	ni_security_id_set_attrs(id, &from->attributes);
}

void
ni_security_id_set_attr(ni_security_id_t *id, const char *name, const char *value)
{
	ni_var_array_set(&id->attributes, name, value);
}

void
ni_security_id_set_attrs(ni_security_id_t *id, const ni_var_array_t *attrs)
{
	unsigned int i;

	ni_var_array_destroy(&id->attributes);
	for (i = 0; i < attrs->count; ++i) {
		ni_var_t *var = &attrs->data[i];

		ni_var_array_set(&id->attributes, var->name, var->value);
	}
}

/*
 * Match two security IDs
 * Note that this is not symmetric!
 */
ni_bool_t
ni_security_id_greater_equal(const ni_security_id_t *id, const ni_security_id_t *match)
{
	unsigned int i;

	if (match == NULL)
		return TRUE;
	if (id == NULL)
		return FALSE;

	/* The id's class must match */
	if (!ni_string_eq(id->class, match->class))
		return FALSE;

	/* Every attribute in @match must be present in @id */
	for (i = 0; i < match->attributes.count; ++i) {
		const ni_var_t *mvar = &match->attributes.data[i];
		ni_var_t *var;

		if (!(var = ni_var_array_get(&id->attributes, mvar->name)))
			return FALSE;
		if (!ni_string_eq(mvar->value, var->value))
			return FALSE;
	}

	return TRUE;
}

ni_bool_t
ni_security_id_equal(const ni_security_id_t *a, const ni_security_id_t *b)
{
	return ni_security_id_greater_equal(a, b) && ni_security_id_greater_equal(b, a);
}

ni_bool_t
ni_security_id_valid(const ni_security_id_t *id)
{
	return id->class != NULL;
}

const char *
ni_security_id_print(const ni_security_id_t *id)
{
	static ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int i;

	ni_stringbuf_destroy(&buf);
	buf.autoreset = FALSE;

	ni_stringbuf_printf(&buf, "%s:", id->class);
	for (i = 0; i < id->attributes.count; ++i) {
		ni_var_t *var = &id->attributes.data[i];
		char *quoted;

		if (var->value == NULL)
			continue;

		quoted = ni_quote(var->value, ", \t");
		if (i)
			ni_stringbuf_putc(&buf, ',');
		ni_stringbuf_printf(&buf, "%s=%s", var->name, quoted);
		free(quoted);
	}

	return buf.string;
}

static const char *
get_identifier(const char **stringp, char *buffer, size_t size)
{
	const char *string = *stringp;
	unsigned int n = 0;
	char cc;

	if (!isalpha(string[n++]))
		return NULL;

	while ((cc = string[n]) != '\0') {
		if (!isalnum(cc) && (cc != '-' && cc != '_'))
			break;
		++n;
	}

	if (n >= size)
		return NULL;

	strncpy(buffer, string, n);
	buffer[n] = '\0';
	*stringp = string + n;

	return buffer;
}

ni_bool_t
ni_security_id_parse(ni_security_id_t *id, const char *string)
{
	const char *orig_string = string;
	char namebuf[64];
	const char *name;

	if (!(name = get_identifier(&string, namebuf, sizeof(namebuf))))
		goto failed;
	if (*string++ != ':')
		goto failed;
	ni_string_dup(&id->class, name);

	while (*string) {
		char *value;

		if (!(name = get_identifier(&string, namebuf, sizeof(namebuf))))
			goto failed;
		if (*string++ != '=')
			goto failed;

		if (!(value = ni_unquote(&string, ",")))
			goto failed;

		ni_security_id_set_attr(id, name, value);
		free(value);
	}

	return TRUE;

failed:
	ni_error("unable to parse security id");
	ni_error("  %s", orig_string);
	ni_error("  %.*s^--- failed here", (int)(string - orig_string), "");
	return FALSE;
}

