/*
 * Helper functions
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_UTIL_H__
#define __WICKED_UTIL_H__

#include <sys/types.h>
#include <wicked/types.h>

typedef struct ni_string_array {
	unsigned int	count;
	char **		data;
} ni_string_array_t;

#define NI_STRING_ARRAY_INIT { .count = 0, .data = 0 }

typedef struct ni_intmap {
	const char *	name;
	unsigned int	value;
} ni_intmap_t;

typedef struct ni_variable	ni_var_t;
struct ni_variable {
	char *		name;
	char *		value;
};

typedef struct ni_var_array ni_var_array_t;
struct ni_var_array {
	unsigned int	count;
	ni_var_t *	data;
};

typedef struct ni_stringbuf {
	size_t			len;
	char *			string;
	int			dynamic;
} ni_stringbuf_t;

#define NI_STRINGBUF_INIT_BUFFER(buf)	{ sizeof(buf), buf, 0 }
#define NI_STRINGBUF_INIT_DYNAMIC	{ 0, NULL, 1 }

extern void		ni_string_free(char **);
extern void		ni_string_dup(char **, const char *);

extern void		ni_string_array_init(ni_string_array_t *);
extern int		ni_string_array_copy(ni_string_array_t *dst, const ni_string_array_t *src);
extern void		ni_string_array_destroy(ni_string_array_t *);
extern int		ni_string_array_append(ni_string_array_t *, const char *);
extern void		ni_string_array_comm(const ni_string_array_t *a, const ni_string_array_t *b,
				ni_string_array_t *uniq_a,
				ni_string_array_t *uniq_b,
				ni_string_array_t *common);
extern int		ni_string_array_is_uniq(const ni_string_array_t *);

extern void		ni_var_array_init(ni_var_array_t *);
extern void		ni_var_array_destroy(ni_var_array_t *);
extern ni_var_t *	ni_var_array_get(const ni_var_array_t *, const char *name);
extern int		ni_var_array_set(ni_var_array_t *, const char *name, const char *value);

extern int		ni_var_array_get_string(ni_var_array_t *, const char *, char **);
extern int		ni_var_array_get_integer(ni_var_array_t *, const char *, unsigned int *);
extern int		ni_var_array_get_boolean(ni_var_array_t *, const char *, int *);
extern int		ni_var_array_set_integer(ni_var_array_t *, const char *name, unsigned int);
extern int		ni_var_array_set_boolean(ni_var_array_t *, const char *name, int);

extern void		ni_stringbuf_set(ni_stringbuf_t *, const char *);
extern void		ni_stringbuf_init(ni_stringbuf_t *);
extern void		ni_stringbuf_puts(ni_stringbuf_t *, const char *);
extern void		ni_stringbuf_putc(ni_stringbuf_t *, char);
extern void		ni_stringbuf_printf(ni_stringbuf_t *, const char *, ...);
extern void		ni_stringbuf_move(ni_stringbuf_t *dest, ni_stringbuf_t *src);
extern void		ni_stringbuf_clear(ni_stringbuf_t *);
extern void		ni_stringbuf_destroy(ni_stringbuf_t *);
extern void		ni_stringbuf_trim_empty_lines(ni_stringbuf_t *);
extern int		ni_stringbuf_empty(const ni_stringbuf_t *);

extern int		ni_file_exists(const char *);
extern int		ni_scandir(const char *, const char *, ni_string_array_t *);
extern int		ni_daemonize(const char *, unsigned int);
extern pid_t		ni_pidfile_check(const char *);
extern int		ni_pidfile_write(const char *, unsigned int, pid_t);

extern FILE *		ni_mkstemp(void);
extern int		ni_copy_file(FILE *, FILE *);

extern int		ni_parse_int_mapped(const char *, const struct ni_intmap *, unsigned int *);
extern int		ni_parse_int(const char *, unsigned int *);
extern const char *	ni_format_int_mapped(unsigned int, const ni_intmap_t *);

extern int		ni_local_socket_listen(const char *, unsigned int);
extern int		ni_local_socket_connect(const char *);
extern int		ni_local_socket_accept(int, uid_t *, gid_t *);

extern const char *	ni_uuid_print(const ni_uuid_t *);
extern int		ni_uuid_parse(ni_uuid_t *, const char *);
extern int		ni_uuid_is_null(const ni_uuid_t *);

#endif /* __WICKED_UTIL_H__ */

