/*
 * Routines for loading and storing sysconfig files
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_SYSCONFIG_H__
#define __WICKED_SYSCONFIG_H__

#include <wicked/util.h>

typedef struct ni_sysconfig	ni_sysconfig_t;
struct ni_sysconfig {
	char *		pathname;
	ni_var_array_t	vars;
};

extern int		ni_sysconfig_scandir(const char *, const char *,
				struct ni_string_array *nsa);
extern ni_sysconfig_t *	ni_sysconfig_new(const char *pathname);
extern void		ni_sysconfig_destroy(ni_sysconfig_t *);
extern ni_sysconfig_t *	ni_sysconfig_read(const char *);
extern ni_sysconfig_t *	ni_sysconfig_read_matching(const char *filename, const char **varnames);
extern int		ni_sysconfig_overwrite(ni_sysconfig_t *);
extern int		ni_sysconfig_rewrite(ni_sysconfig_t *);

extern int		ni_sysconfig_set(ni_sysconfig_t *, const char *name, const char *variable);
extern int		ni_sysconfig_set_integer(ni_sysconfig_t *, const char *name, unsigned int);
extern int		ni_sysconfig_set_boolean(ni_sysconfig_t *, const char *name, int);

extern ni_var_t *	ni_sysconfig_get(const ni_sysconfig_t *, const char *name);
extern int		ni_sysconfig_get_string(const ni_sysconfig_t *, const char *, char **);
extern int		ni_sysconfig_get_integer(const ni_sysconfig_t *, const char *, unsigned int *);
extern int		ni_sysconfig_get_boolean(const ni_sysconfig_t *, const char *, int *);
extern int		ni_sysconfig_get_string_optional(const ni_sysconfig_t *, const char *, char **);
extern int		ni_sysconfig_get_integer_optional(const ni_sysconfig_t *, const char *, unsigned int *);
extern int		ni_sysconfig_get_boolean_optional(const ni_sysconfig_t *, const char *, int *);
extern int		ni_sysconfig_test_boolean(const ni_sysconfig_t *, const char *);

extern int		ni_sysconfig_find_matching(ni_sysconfig_t *, const char *,
				struct ni_string_array *);


#endif /* __WICKED_SYSCONFIG_H__ */
