/*
 * Handle "secret" information such as passwords and keys
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_SECRET_H__
#define __WICKED_SECRET_H__

#include <wicked/types.h>
#include <wicked/util.h>

typedef struct ni_security_id {
	char *			class;
	ni_var_array_t		attributes;
} ni_security_id_t;

#define NI_SECURITY_ID_INIT	{ .class = 0, .attributes = { .count = 0 } }

typedef struct ni_secret	ni_secret_t;

struct ni_secret {
	ni_secret_t **		prev;
	ni_secret_t *		next;

	unsigned int		refcount;
	unsigned int		seq;		/* sequence no of last update */

	ni_security_id_t	id;
	char *			path;
	char *			value;
	unsigned int		cache_lifetime;
};

typedef struct ni_secret_array {
	unsigned int		count;
	ni_secret_t **		data;
} ni_secret_array_t;

typedef struct ni_secret_db {
	unsigned int		seq;

	ni_secret_t *		list;
} ni_secret_db_t;

extern ni_secret_db_t *	ni_secret_db_new(void);
extern void		ni_secret_db_free(ni_secret_db_t *);
extern ni_secret_t *	ni_secret_db_update(ni_secret_db_t *,
					const ni_security_id_t *id, const char *path,
					const char *value);
extern ni_secret_t *	ni_secret_db_find(ni_secret_db_t *, const ni_security_id_t *id, const char *path);
extern void		ni_secret_db_drop(ni_secret_db_t *, const ni_security_id_t *id, const char *path);

extern ni_secret_t *	ni_secret_new(const ni_security_id_t *id, const char *path);
extern void		ni_secret_free(ni_secret_t *);
extern ni_secret_t *	ni_secret_get(ni_secret_t *);
extern void		ni_secret_put(ni_secret_t *);

extern void		ni_secret_array_append(ni_secret_array_t *, ni_secret_t *);
extern void		ni_secret_array_destroy(ni_secret_array_t *);

extern void		ni_security_id_init(ni_security_id_t *id, const char *class);
extern void		ni_security_id_set(ni_security_id_t *, const ni_security_id_t *);
extern void		ni_security_id_destroy(ni_security_id_t *id);
extern void		ni_security_id_set_attr(ni_security_id_t *id, const char *name, const char *value);
extern void		ni_security_id_set_attrs(ni_security_id_t *id, const ni_var_array_t *attrs);
extern ni_bool_t	ni_security_id_valid(const ni_security_id_t *);
extern ni_bool_t	ni_security_id_equal(const ni_security_id_t *, const ni_security_id_t *);
extern const char *	ni_security_id_print(const ni_security_id_t *);
extern ni_bool_t	ni_security_id_parse(ni_security_id_t *, const char *);

#endif /* __WICKED_SECRET_H__ */


