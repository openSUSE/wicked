/*
 * Helper functions
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_UTIL_H__
#define __WICKED_UTIL_H__

#include <sys/types.h>
#include <wicked/types.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

typedef struct ni_string_array {
	unsigned int	count;
	char **		data;
} ni_string_array_t;

#define NI_STRING_ARRAY_INIT	{ .count = 0, .data = NULL }

typedef struct ni_intmap {
	const char *	name;
	unsigned int	value;
} ni_intmap_t;

typedef struct ni_uint_arrray {
	unsigned int	count;
	unsigned int *	data;
} ni_uint_array_t;

#define NI_UINT_ARRAY_INIT	{ .count = 0, .data = NULL }

typedef struct ni_variable	ni_var_t;
struct ni_variable {
	char *		name;
	char *		value;
};

typedef struct ni_var_array ni_var_array_t;
struct ni_var_array {
	ni_var_array_t *next;
	unsigned int	count;
	ni_var_t *	data;
};

#define NI_VAR_ARRAY_INIT	{ .count = 0, .data = NULL }

typedef struct ni_stringbuf {
	size_t			size;
	size_t			len;
	char *			string;
	ni_bool_t		dynamic;
} ni_stringbuf_t;

#define NI_STRINGBUF_INIT_BUFFER(buf)	{ .size = sizeof(buf), .len = 0, .string = buf, .dynamic = 0 }
#define NI_STRINGBUF_INIT_DYNAMIC	{ .size = 0, .len = 0, .string = NULL, .dynamic = 1 }

typedef struct ni_opaque {
	unsigned char	data[130];
	size_t		len;
} ni_opaque_t;

#define NI_OPAQUE_INIT	{ .len = 0 }

#define NI_BIT(nr)	(1U << (nr))

typedef struct ni_bitfield {
	unsigned int	size;
	uint32_t *	field;
	uint32_t	__local_field[4];
} ni_bitfield_t;

#define NI_BITFIELD_INIT { 0, NULL }

typedef enum ni_daemon_close {
	NI_DAEMON_CLOSE_NONE	= 0,
	NI_DAEMON_CLOSE_IN	= 1,
	NI_DAEMON_CLOSE_OUT	= 2,
	NI_DAEMON_CLOSE_ERR	= 4,
	NI_DAEMON_CLOSE_STD	= NI_DAEMON_CLOSE_IN|NI_DAEMON_CLOSE_OUT|NI_DAEMON_CLOSE_ERR,
	NI_DAEMON_CLOSE_ALL	= -1U,
} ni_daemon_close_t;

extern void		ni_bitfield_init(ni_bitfield_t *);
extern void		ni_bitfield_destroy(ni_bitfield_t *);
extern void		ni_bitfield_setbit(ni_bitfield_t *, unsigned int);
extern void		ni_bitfield_clearbit(ni_bitfield_t *, unsigned int);
extern int		ni_bitfield_testbit(const ni_bitfield_t *, unsigned int);

extern void		ni_string_free(char **);
extern void		ni_string_clear(char **);
extern void		ni_string_dup(char **, const char *);
extern void		ni_string_set(char **, const char *, unsigned int len);
extern const char *	ni_string_printf(char **, const char *, ...);

extern void		ni_string_array_init(ni_string_array_t *);
extern int		ni_string_array_copy(ni_string_array_t *dst, const ni_string_array_t *src);
extern void		ni_string_array_move(ni_string_array_t *dst, ni_string_array_t *src);
extern void		ni_string_array_destroy(ni_string_array_t *);
extern int		ni_string_array_append(ni_string_array_t *, const char *);
extern int		ni_string_array_insert(ni_string_array_t *, unsigned int, const char *);
extern int		ni_string_array_set(ni_string_array_t *, unsigned int, const char *);
extern int		ni_string_array_get(ni_string_array_t *, unsigned int, char **);
extern const char *	ni_string_array_at(ni_string_array_t *, unsigned int);
extern int		ni_string_array_index(const ni_string_array_t *, const char *);
extern int		ni_string_array_remove_index(ni_string_array_t *, unsigned int);
extern int		ni_string_array_remove_match(ni_string_array_t *, const char *, unsigned int);
extern void		ni_string_array_comm(const ni_string_array_t *a, const ni_string_array_t *b,
				ni_string_array_t *uniq_a,
				ni_string_array_t *uniq_b,
				ni_string_array_t *common);
extern int		ni_string_array_is_uniq(const ni_string_array_t *);
extern ni_bool_t	ni_string_array_eq(const ni_string_array_t *, const ni_string_array_t *);
extern int		ni_string_array_cmp(const ni_string_array_t *, const ni_string_array_t *);

extern void		ni_uint_array_init(ni_uint_array_t *);
extern void		ni_uint_array_destroy(ni_uint_array_t *);
extern ni_bool_t	ni_uint_array_append(ni_uint_array_t *, unsigned int);
extern ni_bool_t	ni_uint_array_contains(ni_uint_array_t *, unsigned int);

extern ni_var_array_t *	ni_var_array_new(void);
extern void		ni_var_array_free(ni_var_array_t *);
extern void		ni_var_array_init(ni_var_array_t *);
extern ni_bool_t	ni_var_array_remove_at(ni_var_array_t *, unsigned int);
extern ni_bool_t	ni_var_array_remove(ni_var_array_t *, const char *);
extern void		ni_var_array_destroy(ni_var_array_t *);
extern void		ni_var_array_copy(ni_var_array_t *, const ni_var_array_t *);
extern void		ni_var_array_move(ni_var_array_t *, ni_var_array_t *);
extern ni_var_t *	ni_var_array_get(const ni_var_array_t *, const char *name);
extern void		ni_var_array_set(ni_var_array_t *, const char *name, const char *value);

extern int		ni_var_array_get_string(ni_var_array_t *, const char *, char **);
extern int		ni_var_array_get_uint(ni_var_array_t *, const char *, unsigned int *);
extern int		ni_var_array_get_long(ni_var_array_t *, const char *, unsigned long *);
extern int		ni_var_array_get_double(ni_var_array_t *, const char *, double *);
extern int		ni_var_array_get_boolean(ni_var_array_t *, const char *, ni_bool_t *);
extern void		ni_var_array_set_uint(ni_var_array_t *, const char *name, unsigned int);
extern void		ni_var_array_set_long(ni_var_array_t *, const char *name, unsigned long);
extern void		ni_var_array_set_double(ni_var_array_t *, const char *name, double);
extern void		ni_var_array_set_boolean(ni_var_array_t *, const char *name, int);

extern void		ni_var_array_list_append(ni_var_array_t **, ni_var_array_t *);
extern void		ni_var_array_list_destroy(ni_var_array_t **);

extern void		ni_stringbuf_set(ni_stringbuf_t *, const char *);
extern void		ni_stringbuf_init(ni_stringbuf_t *);
extern void		ni_stringbuf_grow(ni_stringbuf_t *, size_t);
extern void		ni_stringbuf_put(ni_stringbuf_t *, const char *, size_t);
extern void		ni_stringbuf_puts(ni_stringbuf_t *, const char *);
extern void		ni_stringbuf_putc(ni_stringbuf_t *, int);
extern int		ni_stringbuf_printf(ni_stringbuf_t *, const char *, ...);
extern int		ni_stringbuf_vprintf(ni_stringbuf_t *, const char *, va_list);
extern void		ni_stringbuf_move(ni_stringbuf_t *dest, ni_stringbuf_t *src);
extern void		ni_stringbuf_clear(ni_stringbuf_t *);
extern void		ni_stringbuf_destroy(ni_stringbuf_t *);
extern void		ni_stringbuf_truncate(ni_stringbuf_t *, size_t);
extern void		ni_stringbuf_trim_head(ni_stringbuf_t *, const char *);
extern void		ni_stringbuf_trim_tail(ni_stringbuf_t *, const char *);
extern void		ni_stringbuf_trim_empty_lines(ni_stringbuf_t *);
extern ni_bool_t	ni_stringbuf_empty(const ni_stringbuf_t *);

extern ni_bool_t	ni_file_exists(const char *);
extern ni_bool_t	ni_file_executable(const char *);
extern ni_bool_t	ni_isdir(const char *);
extern ni_bool_t	ni_isreg(const char *);
extern ni_bool_t	ni_fs_is_read_only(const char *);
extern ni_bool_t	ni_file_exists_fmt(const char*, ...);
extern const char *	ni_find_executable(const char **);
extern const char *	ni_basename(const char *path);
extern const char *	ni_dirname(const char *path);
extern const char *	ni_realpath(const char *path, char **resolved);
extern const char *	ni_sibling_path(const char *path, const char *file);
extern const char *	ni_sibling_path_printf(const char *path, const char *fmt, ...);
extern int		ni_scandir(const char *, const char *, ni_string_array_t *);
extern int		ni_daemonize(const char *, unsigned int, ni_daemon_close_t);
extern pid_t		ni_pidfile_check(const char *);
extern int		ni_pidfile_write(const char *, unsigned int, pid_t);

extern FILE *		ni_mkstemp(char **namep);
extern int		ni_copy_file(FILE *, FILE *);
extern int		ni_backup_file_to(const char *, const char *);
extern int		ni_restore_file_from(const char *, const char *);
extern FILE *		ni_file_open(const char *, const char *, unsigned int);
extern void *		ni_file_read(FILE *, size_t *, size_t);
extern int		ni_file_write(FILE *, const void *, size_t);
extern ni_bool_t	ni_file_remove_recursively(const char *path);
extern int		ni_mkdir_maybe(const char *pathname, unsigned int mode);

extern int		ni_parse_int(const char *, int *, int);
extern int		ni_parse_uint(const char *, unsigned int *, int);
extern int		ni_parse_int64(const char *, int64_t *, int);
extern int		ni_parse_uint64(const char *, uint64_t *, int);
extern int		ni_parse_long(const char *, long *, int);
extern int		ni_parse_ulong(const char *, unsigned long *, int);
extern int		ni_parse_llong(const char *, long long *, int);
extern int		ni_parse_ullong(const char *, unsigned long long *, int);
extern int		ni_parse_double(const char *, double *);
extern int		ni_parse_hex(const char *, unsigned char *, unsigned int);
extern int		ni_parse_boolean(const char *, ni_bool_t *);

extern int		ni_parse_uint_mapped(const char *, const struct ni_intmap *, unsigned int *);
extern int		ni_parse_uint_maybe_mapped(const char *, const struct ni_intmap *, unsigned int *, int);

extern const char *	ni_format_uint_mapped(unsigned int, const ni_intmap_t *);
extern const char *	ni_format_uint_maybe_mapped(unsigned int, const ni_intmap_t *);
extern const char *	ni_format_hex(const unsigned char *data, unsigned int data_len,
				char *namebuf, size_t name_max);
extern const char *	ni_print_hex(const unsigned char *data, unsigned int data_len);

extern size_t		ni_format_hex_data(const unsigned char *data, size_t data_len,
						char *name_buf, size_t name_max,
						const char *sep, ni_bool_t upper);
extern ssize_t		ni_parse_hex_data(const char *string, unsigned char *data,
						size_t data_size, const char *sep);
extern const char *	ni_format_bitmap(ni_stringbuf_t *, const ni_intmap_t *, unsigned int, const char *);
extern ni_bool_t	ni_intmap_file_get_name(const char *, unsigned int *, char **);
extern ni_bool_t	ni_intmap_file_get_value(const char *, unsigned int *, char **);

extern const char *	ni_uuid_print(const ni_uuid_t *);
extern int		ni_uuid_parse(ni_uuid_t *, const char *);
extern int		ni_uuid_is_null(const ni_uuid_t *);
extern int		ni_uuid_equal(const ni_uuid_t *, const ni_uuid_t *);
extern ni_uuid_t *	ni_uuid_generate(ni_uuid_t *);
extern int		ni_uuid_for_file(ni_uuid_t *, const char *);
extern int		ni_uuid_set_version(ni_uuid_t *, unsigned int);

extern char *		ni_quote(const char *string, const char *sepa);
extern char *		ni_unquote(const char **stringp, const char *sepa);

extern void		ni_srandom(void);

extern ni_bool_t	ni_try_mlock(const void *, size_t);

/* Use this in mainloop-like functions to check at defined execution points
 * whether we were signaled in the meantime.
 */
extern ni_bool_t	ni_caught_terminal_signal(void);

static inline void
ni_opaque_set(ni_opaque_t *obj, const void *data, size_t len)
{
	if (len > sizeof(obj->data))
		len = sizeof(obj->data);
	memcpy(obj->data, data, len);
	obj->len = len;
}

static inline ni_bool_t
ni_opaque_eq(const ni_opaque_t *a, const ni_opaque_t *b)
{
	return a->len == b->len && !memcmp(a->data, b->data, a->len);
}

extern ni_opaque_t *	ni_opaque_new(const void *data, size_t len);
extern void		ni_opaque_free(ni_opaque_t *);

/*
 * Helper function to do strcmp with NULL pointer check
 */
static inline ni_bool_t
ni_string_eq(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return a == b;
	return strcmp(a, b) == 0;
}

static inline ni_bool_t
ni_string_eq_nocase(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return a == b;
	return strcasecmp(a, b) == 0;
}

static inline int
ni_string_cmp(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return a > b ? 1 : -1;
	else
		return strcmp(a, b);
}

static inline int
ni_string_cmp_nocase(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return a > b ? 1 : -1;
	else
		return strcasecmp(a, b);
}


static inline ni_bool_t
ni_string_contains(const char *haystack, const char *needle)
{
	if (haystack == NULL || needle == NULL)
		return haystack == needle;
	return strstr(haystack, needle) != NULL;
}

static inline ni_bool_t
ni_string_startswith(const char *string, const char *with)
{
	if (string == NULL || with == NULL)
		return string == with;
	return !strncmp(string, with, strlen(with));
}

static inline ni_bool_t
ni_string_empty(const char *s)
{
	return s == NULL || *s == '\0';
}
static inline size_t
ni_string_len(const char *s)
{
	return s ? strlen(s) : 0;
}

/*
 * Parse and format inline functions
 */
static inline const char *
ni_format_boolean(ni_bool_t data)
{
	return (data ? "true" : "false");
}

/*
 * type-safe min/max macros
 */
#define min_t(type, a, b) ({ \
				type __res = a, __b = b; \
				if (__res > __b) \
					__res = __b; \
				__res; \
			  })
#define max_t(type, a, b) ({ \
				type __res = a, __b = b; \
				if (__res < __b) \
					__res = __b; \
				__res; \
			  })

/*
 * Tristate (bool + "unset/default") translation
 */
extern const char *	ni_tristate_to_name(ni_tristate_t tristate);
extern ni_bool_t	ni_tristate_by_name(const char *name, ni_tristate_t *tristate);
static inline ni_bool_t	ni_tristate_is_enabled(ni_tristate_t tristate)
{
	return tristate == NI_TRISTATE_ENABLE;
}
static inline ni_bool_t	ni_tristate_is_disabled(ni_tristate_t tristate)
{
	return tristate == NI_TRISTATE_DISABLE;
}
static inline ni_bool_t	ni_tristate_is_set(ni_tristate_t tristate)
{
	return tristate != NI_TRISTATE_DEFAULT;
}
static inline void	ni_tristate_set(ni_tristate_t *tristate, int value)
{
	*tristate = value ? NI_TRISTATE_ENABLE : NI_TRISTATE_DISABLE;
}

/*
 * Further string related utililies
 */
extern const char *	ni_string_strip_prefix(const char *string, const char *prefix);
extern char *		ni_string_strip_suffix(char *string, const char *suffix);
extern const char *	ni_string_join(char **str, const ni_string_array_t *nsa, const char *sep);
extern unsigned int	ni_string_split(ni_string_array_t *nsa, const char *str, const char *sep, unsigned int);
extern ni_bool_t	ni_string_ishex(const char *);
extern int		ni_string_remove_char(char *, int);

extern char *		ni_sprint_hex(const unsigned char *, size_t);
extern const char *	ni_sprint_uint(unsigned int);
extern const char *	ni_sprint_timeout(unsigned int);

/*
 * When we allocate temporary resources (such as tempfiles)
 * we can track them as a whole, and clean them up as a whole.
 */
typedef struct ni_tempstate ni_tempstate_t;
extern ni_tempstate_t *	ni_tempstate_new(const char *);
extern void		ni_tempstate_finish(ni_tempstate_t *);
extern void		ni_tempstate_add_file(ni_tempstate_t *, const char *filename);
extern int		ni_tempstate_mkdir(ni_tempstate_t *);
extern char *		ni_tempstate_mkfile(ni_tempstate_t *, const char *);

/*
 * Functions for hashing
 */
typedef struct ni_hashctx ni_hashctx_t;

typedef enum {
	NI_HASHCTX_MD5	= 1,
	NI_HASHCTX_SHA1	= 2,
} ni_hashctx_algo_t;

extern ni_hashctx_t *	ni_hashctx_new(ni_hashctx_algo_t algo);
extern void		ni_hashctx_free(ni_hashctx_t *);
extern void		ni_hashctx_begin(ni_hashctx_t *);
extern void		ni_hashctx_finish(ni_hashctx_t *);
extern unsigned int	ni_hashctx_get_digest_length(ni_hashctx_t *);
extern int		ni_hashctx_get_digest(ni_hashctx_t *, void *, size_t);
extern void		ni_hashctx_put(ni_hashctx_t *, const void *, size_t);
extern void		ni_hashctx_puts(ni_hashctx_t *, const char *);


/*
 * Sanity check functions
 */
extern ni_bool_t	ni_check_domain_name(const char *, size_t, int);
extern ni_bool_t	ni_check_pathname(const char *, size_t);
extern ni_bool_t	ni_check_printable(const char *, size_t);
extern const char *	ni_print_suspect(const char *, size_t);

#endif /* __WICKED_UTIL_H__ */

