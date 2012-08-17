/*
 * Handle "secret" information such as passwords and keys
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_SECRET_H__
#define __WICKED_SECRET_H__

#include <wicked/types.h>

typedef struct ni_secret	ni_secret_t;

struct ni_secret {
	ni_secret_t **		prev;
	ni_secret_t *		next;

	unsigned int		refcount;
	unsigned int		seq;		/* sequence no of last update */

	char *			id;		/* eg modem:<imei> or wireless:<essid> */
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
					const char *id, const char *path,
					const char *value);
extern ni_secret_t *	ni_secret_db_find(ni_secret_db_t *, const char *id, const char *path);
extern void		ni_secret_db_drop(ni_secret_db_t *, const char *id, const char *path);

extern ni_secret_t *	ni_secret_new(const char *id, const char *path);
extern void		ni_secret_free(ni_secret_t *);
extern ni_secret_t *	ni_secret_get(ni_secret_t *);
extern void		ni_secret_put(ni_secret_t *);

extern void		ni_secret_array_append(ni_secret_array_t *, ni_secret_t *);
extern void		ni_secret_array_destroy(ni_secret_array_t *);

#endif /* __WICKED_SECRET_H__ */


