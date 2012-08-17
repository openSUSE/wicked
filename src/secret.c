/*
 * Handle "secret" information such as passwords and keys
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */


#include <wicked/secret.h>
#include <wicked/logging.h>
#include <wicked/util.h>
#include "util_priv.h"

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
__ni_secret_db_find(ni_secret_db_t *db, const char *id, const char *path)
{
	ni_secret_t *sec;

	for (sec = db->list; sec; sec = sec->next) {
		if (ni_string_eq(sec->id, id) && ni_string_eq(sec->path, path))
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
ni_secret_db_find(ni_secret_db_t *db, const char *id, const char *path)
{
	return __ni_secret_db_find(db, id, path);
}

void
ni_secret_db_drop(ni_secret_db_t *db, const char *id, const char *path)
{
	ni_secret_t *sec;

	for (sec = db->list; sec; sec = sec->next) {
		if ((id == NULL || ni_string_eq(sec->id, id))
		 && (path == NULL || ni_string_eq(sec->path, path)))
			ni_string_free(&sec->value);
	}
}

/*
 * Update a secret in the DB
 */
ni_secret_t *
ni_secret_db_update(ni_secret_db_t *db, const char *id, const char *path, const char *value)
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
ni_secret_new(const char *id, const char *path)
{
	ni_secret_t *sec;

	sec = xcalloc(1, sizeof(*sec));
	ni_string_dup(&sec->id, id);
	ni_string_dup(&sec->path, path);
	return sec;
}

void
ni_secret_free(ni_secret_t *sec)
{
	ni_assert(sec->refcount == 0);
	ni_assert(sec->prev == NULL);

	ni_string_free(&sec->id);
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
