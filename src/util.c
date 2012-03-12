/*
 * Helper functions
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */

#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#include <wicked/util.h>
#include <wicked/logging.h>
#include "util_priv.h"

#define NI_STRINGARRAY_CHUNK	16
#define NC_STRINGBUF_CHUNK	64


static int		__ni_pidfile_write(const char *, unsigned int, pid_t, int);
static const char *	__ni_build_backup_path(const char *, const char *);

void
ni_string_array_init(ni_string_array_t *nsa)
{
	memset(nsa, 0, sizeof(*nsa));
}

int
ni_string_array_copy(ni_string_array_t *dst, const ni_string_array_t *src)
{
	unsigned int i;

	ni_string_array_destroy(dst);
	for (i = 0; i < src->count; ++i) {
		if (ni_string_array_append(dst, src->data[i]) < 0)
			return -1;
	}
	return 0;
}

void
ni_string_array_move(ni_string_array_t *dst, ni_string_array_t *src)
{
	ni_string_array_destroy(dst);
	*dst = *src;
	memset(src, 0, sizeof(*src));
}

void
ni_string_array_destroy(ni_string_array_t *nsa)
{
	while (nsa->count--)
		free(nsa->data[nsa->count]);
	free(nsa->data);
	memset(nsa, 0, sizeof(*nsa));
}

static void
__ni_string_array_realloc(ni_string_array_t *nsa, unsigned int newsize)
{
	char **newdata;
	unsigned int i;

	newsize = (newsize + NI_STRINGARRAY_CHUNK) + 1;
	newdata = realloc(nsa->data, newsize * sizeof(char *));
	if (!newdata)
		ni_fatal("%s: out of memory", __FUNCTION__);

	nsa->data = newdata;
	for (i = nsa->count; i < newsize; ++i)
		nsa->data[i] = NULL;
}

static int
__ni_string_array_append(ni_string_array_t *nsa, char *str)
{
	if ((nsa->count % NI_STRINGARRAY_CHUNK) == 0)
		__ni_string_array_realloc(nsa, nsa->count);

	nsa->data[nsa->count++] = str;
	return 0;
}

static int
__ni_string_array_insert(ni_string_array_t *nsa, unsigned int pos, char *str)
{
	if ((nsa->count % NI_STRINGARRAY_CHUNK) == 0)
		__ni_string_array_realloc(nsa, nsa->count);

	if (pos >= nsa->count) {
		nsa->data[nsa->count++] = str;
	} else {
		memmove(&nsa->data[pos + 1], &nsa->data[pos], (nsa->count - pos) * sizeof(char *));
		nsa->data[pos] = str;
		nsa->count++;
	}
	return 0;
}

int
ni_string_array_set(ni_string_array_t *nsa, unsigned int pos, const char *str)
{
	if (pos >= nsa->count)
		return -1;

	ni_string_dup(&nsa->data[pos], str);

	return nsa->data[pos] ? 0 : -1;
}

int
ni_string_array_get(ni_string_array_t *nsa, unsigned int pos, char **str)
{
	if (pos >= nsa->count)
		return -1;

	ni_string_dup(str, nsa->data[pos]);

	return *str ? 0 : -1;
}

int
ni_string_array_append(ni_string_array_t *nsa, const char *str)
{
	char *newstr;

	/* Note, this allows a NULL string pointer to be inserted into the array. */
	newstr = xstrdup(str);
	if (__ni_string_array_append(nsa, newstr) < 0) {
		free(newstr);
		return -1;
	}

	return 0;
}

int
ni_string_array_insert(ni_string_array_t *nsa, unsigned int pos, const char *str)
{
	char *newstr;

	newstr = strdup(str);
	if (!newstr)
		return -1;

	if (__ni_string_array_insert(nsa, pos, newstr) < 0) {
		free(newstr);
		return -1;
	}

	return 0;
}

int
ni_string_array_index(const ni_string_array_t *nsa, const char *str)
{
	unsigned int i;

	for (i = 0; i < nsa->count; ++i) {
		if (!strcmp(nsa->data[i], str))
			return i;
	}
	return -1;
}

/*
 * Remove string at index @pos
 */
int
ni_string_array_remove_index(ni_string_array_t *nsa, unsigned int pos)
{
	if (pos >= nsa->count)
		return -1;

	free(nsa->data[pos]);

	/* Note: this also copies the NULL pointer following the last element */
	memmove(&nsa->data[pos], &nsa->data[pos + 1], (nsa->count - pos) * sizeof(char *));
	nsa->count--;

	/* Don't bother with shrinking the array. It's not worth the trouble */
	return 0;
}

/*
 * Remove up to @maxkill occurrences of string @str from the array.
 */
int
ni_string_array_remove_match(ni_string_array_t *nsa, const char *str, unsigned int maxkill)
{
	unsigned int i, j, killed = 0;

	if (!maxkill)
		maxkill = nsa->count;
	for (i = j = 0; i < nsa->count; ++i) {
		if (killed < maxkill && !strcmp(nsa->data[i], str)) {
			free(nsa->data[i]);
			killed++;
		} else {
			nsa->data[j++] = nsa->data[i];
		}
	}

	/* assert(j + killed == nsa->count); */
	memset(&nsa->data[j], 0, killed * sizeof(char *));
	nsa->count = j;

	/* Don't bother with shrinking the array. It's not worth the trouble */
	return killed;
}

/*
 * Compare string arrays, much the same way comm(1) works
 * We ignore order of the input arrays, but expect values to be
 * unique.
 *
 * Mode of operations: first duplicate string arrays.
 * Then sort array A into common or uniq_a - we can do this by simply
 * moving the string pointer, no need to further clone it.
 * When we find a common string, we also clear out the corresponding
 * value in B.
 * As a last step, we know that any strings left in the copy of array B
 * must be unique to B.
 */
void
ni_string_array_comm(const ni_string_array_t *a, const ni_string_array_t *b,
				ni_string_array_t *uniq_a,
				ni_string_array_t *uniq_b,
				ni_string_array_t *common)
{
	ni_string_array_t copy_a, copy_b;
	unsigned int i, j;

	ni_string_array_init(&copy_a);
	ni_string_array_copy(&copy_a, a);
	ni_string_array_init(&copy_b);
	ni_string_array_copy(&copy_b, b);

	for (i = 0; i < copy_a.count; ++i) {
		char *val_a = copy_a.data[i];

		for (j = 0; j < copy_b.count && val_a; ++j) {
			char *val_b = copy_b.data[j];

			if (val_b && !strcmp(val_a, val_b)) {
				__ni_string_array_append(common, val_a);
				ni_string_free(&copy_b.data[j]);
				val_a = NULL;
			}
		}

		if (val_a)
			__ni_string_array_append(uniq_a, val_a);
		copy_a.data[i] = NULL;
	}

	for (j = 0; j < copy_b.count; ++j) {
		char *val_b = copy_b.data[j];

		if (val_b)
			__ni_string_array_append(uniq_b, val_b);
		copy_b.data[j] = NULL;
	}

	ni_string_array_destroy(&copy_a);
	ni_string_array_destroy(&copy_b);
}

/*
 * Check that all strings in a string array are unique
 * Returns bool.
 */
int
ni_string_array_is_uniq(const ni_string_array_t *nsa)
{
	unsigned int i, j;

	for (i = 0; i < nsa->count; ++i) {
		char *val_a = nsa->data[i];

		for (j = i + 1; j < nsa->count && val_a; ++j) {
			char *val_b = nsa->data[i];

			if (!strcmp(val_a, val_b))
				return 0;
		}
	}
	return 1;
}

/*
 * Array of variables
 */
void
ni_var_array_init(ni_var_array_t *nva)
{
	memset(nva, 0, sizeof(*nva));
}

void
ni_var_array_destroy(ni_var_array_t *nva)
{
	unsigned int i;

	for (i = 0; i < nva->count; ++i) {
		free(nva->data[i].name);
		free(nva->data[i].value);
	}
	free(nva->data);
	memset(nva, 0, sizeof(*nva));
}

ni_var_t *
ni_var_array_get(const ni_var_array_t *nva, const char *name)
{
	unsigned int i;
	ni_var_t *var;

	for (i = 0, var = nva->data; i < nva->count; ++i, ++var) {
		if (!strcmp(var->name, name))
			return var;
	}
	return NULL;
}

int
ni_var_array_set(ni_var_array_t *nva, const char *name, const char *value)
{
	ni_var_t *var;

	if ((var = ni_var_array_get(nva, name)) == NULL) {
		if ((nva->count & 15) == 0) {
			nva->data = realloc(nva->data, (nva->count + 16) * sizeof(ni_var_t));
			if (!nva->data)
				return -1;
		}

		var = &nva->data[nva->count++];
		var->name = xstrdup(name);
		var->value = NULL;
	}

	ni_string_dup(&var->value, value);
	return 0;
}

int
ni_var_array_get_string(ni_var_array_t *nva, const char *name, char **p)
{
	ni_var_t *var;

	if (*p) {
		free(*p);
		*p = NULL;
	}

	if ((var = ni_var_array_get(nva, name)) != NULL)
		*p = xstrdup(var->value);
	return 0;
}

int
ni_var_array_get_integer(ni_var_array_t *nva, const char *name, unsigned int *p)
{
	ni_var_t *var;

	*p = 0;
	if ((var = ni_var_array_get(nva, name)) != NULL)
		*p = strtoul(var->value, NULL, 0);
	return 0;
}

int
ni_var_array_get_boolean(ni_var_array_t *nva, const char *name, int *p)
{
	ni_var_t *var;

	*p = 0;
	if ((var = ni_var_array_get(nva, name)) != NULL) {
		if (!strcasecmp(var->value, "on")
		 || !strcasecmp(var->value, "true")
		 || !strcasecmp(var->value, "yes"))
			*p = 1;
	}
	return 0;
}

int
ni_var_array_set_integer(ni_var_array_t *nva, const char *name, unsigned int value)
{
	char buffer[32];

	snprintf(buffer, sizeof(buffer), "%u", value);
	return ni_var_array_set(nva, name, buffer);
}

int
ni_var_array_set_long(ni_var_array_t *nva, const char *name, unsigned long value)
{
	char buffer[32];

	snprintf(buffer, sizeof(buffer), "%lu", value);
	return ni_var_array_set(nva, name, buffer);
}

int
ni_var_array_set_double(ni_var_array_t *nva, const char *name, double value)
{
	char buffer[32];

	snprintf(buffer, sizeof(buffer), "%g", value);
	return ni_var_array_set(nva, name, buffer);
}

int
ni_var_array_set_boolean(ni_var_array_t *nva, const char *name, int value)
{
	return ni_var_array_set(nva, name, value? "yes" : "no");
}


/*
 * Bitfield functions
 */
void
ni_bitfield_init(ni_bitfield_t *bf)
{
	memset(bf, 0, sizeof(*bf));
}

void
ni_bitfield_destroy(ni_bitfield_t *bf)
{
	if (bf->field && bf->field != bf->__local_field)
		free(bf->field);
	memset(bf, 0, sizeof(*bf));
}

static inline void
__ni_bitfield_grow(ni_bitfield_t *bf, unsigned int nbits)
{
	unsigned int nwords = (nbits + 31) / 32;

	if (nwords >= bf->size) {
		const unsigned int local_words = sizeof(bf->__local_field);

		if (nwords <= local_words) {
			memset(bf->__local_field, 0, local_words);
			bf->field = bf->__local_field;
			bf->size = local_words;
		} else {
			uint32_t *new_field;

			new_field = xcalloc(nwords, sizeof(uint32_t));
			if (bf->size)
				memcpy(new_field, bf->field, bf->size);
			if (bf->field && bf->field != bf->__local_field)
				free(bf->field);
			bf->field = new_field;
			bf->size = nwords;
		}
	}
}

void
ni_bitfield_setbit(ni_bitfield_t *bf, unsigned int bit)
{
	__ni_bitfield_grow(bf, bit);
	bf->field[bit / 32] = (1 << (bit % 32));
}

void
ni_bitfield_clearbit(ni_bitfield_t *bf, unsigned int bit)
{
	__ni_bitfield_grow(bf, bit);
	bf->field[bit / 32] &= ~(1 << (bit % 32));
}

int
ni_bitfield_testbit(const ni_bitfield_t *bf, unsigned int bit)
{
	if (bit / 32 >= bf->size)
		return 0;
	return !!(bf->field[bit / 32] & (1 << (bit % 32)));
}

/*
 * Scan directory and return all file names matching the given prefix.
 */
int
ni_scandir(const char *dirname, const char *pattern, ni_string_array_t *res)
{
	struct dirent *dp;
	char *copy = NULL;
	const char *match_prefix = NULL;
	const char *match_suffix = NULL;
	unsigned int pfxlen, sfxlen;
	unsigned int rv = 0;
	DIR *dir;

	dir = opendir(dirname);
	if (dir == NULL) {
		perror(dirname);
		return 0;
	}

	if (pattern) {
		char *s;

		copy = xstrdup(pattern);
		if ((s = strchr(copy, '*')) == NULL) {
			ni_error("%s: bad pattern \"%s\"", __func__, pattern);
			goto out;
		}
		if (s != copy)
			match_prefix = copy;
		*s++ = '\0';
		if (*s != '\0')
			match_suffix = s;
	}

	pfxlen = match_prefix? strlen(match_prefix) : 0;
	sfxlen = match_suffix? strlen(match_suffix) : 0;
	while ((dp = readdir(dir)) != NULL) {
		const char *name = dp->d_name;

		if (name[0] == '.')
			continue;
		if (pfxlen && strncmp(name, match_prefix, pfxlen))
			continue;
		if (sfxlen != 0) {
			unsigned int namelen = strlen(name);

			if (namelen < pfxlen + sfxlen)
				continue;
			if (strcmp(name + namelen - sfxlen, match_suffix))
				continue;
		}
		ni_string_array_append(res, name);
	}
	rv = res->count;

out:
	closedir(dir);
	free(copy);
	return rv;
}

/*
 * Recursive removal of files/directories
 */
ni_bool_t
ni_file_remove_recursively(const char *path)
{
	struct dirent *dp;
	ni_bool_t rv = TRUE;
	DIR *dir;

	dir = opendir(path);
	if (dir == NULL) {
		if (errno != ENOTDIR) {
			ni_error("unable to open %s: %m", path);
			return FALSE;
		}

		if (unlink(path) < 0) {
			ni_error("unable to remove %s: %m", path);
			return FALSE;
		}
		return TRUE;
	}

	while ((dp = readdir(dir)) != NULL && rv) {
		const char *name = dp->d_name;
		char pathbuf[PATH_MAX];

		if (name[0] == '.')
			continue;

		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, name);
		if (unlink(pathbuf) >= 0)
			continue;

		rv = ni_file_remove_recursively(pathbuf);
	}

	closedir(dir);
	return rv;
}

/*
 * Check if the given file exists
 */
extern int
ni_file_exists(const char *filename)
{
	return access(filename, F_OK) == 0; /* bool */
}

void
ni_string_free(char **pp)
{
	if (pp && *pp) {
		free(*pp);
		*pp = NULL;
	}
}

void
ni_string_dup(char **pp, const char *value)
{
	if (*pp)
		free(*pp);
	*pp = value? xstrdup(value) : NULL;
}

void
ni_string_set(char **pp, const char *value, unsigned int len)
{
	if (*pp) {
		free(*pp);
		*pp = NULL;
	}

	if (len) {
		*pp = malloc(len + 1);
		memcpy(*pp, value, len);
		(*pp)[len] = '\0';
	}
}

const char *
ni_string_strip_prefix(const char *prefix, const char *string)
{
	unsigned int len;

	if (!prefix || !string)
		return string;

	len = strlen(prefix);
	if (!strncmp(string, prefix, len))
		return string + len;
	return NULL;
}

char *
ni_string_strip_suffix(char *string, const char *suffix)
{
	unsigned int len, slen;

	if (!string || !suffix)
		return string;
	len = strlen(string);
	slen = strlen(suffix);
	if (slen < len && !strcmp(string + len - slen, suffix))
		string[len - slen] = '\0';
	return string;
}

int
ni_parse_int(const char *input, unsigned int *result)
{
	char *end;

	if (!input)
		return -1;
	*result = strtoul(input, (char **) &end, 0);
	if (*end == '\0')
		return 0;

	return -1;
}

int
ni_parse_int_mapped(const char *input, const ni_intmap_t *map, unsigned int *result)
{
	char *end;

	if (!input)
		return -1;
	if (isdigit(input[0])) {
		*result = strtoul(input, (char **) &end, 0);
		if (*end == '\0')
			return 0;
	}

	if (!map)
		return -1;
	for (; map->name; ++map) {
		if (!strcasecmp(map->name, input)) {
			*result = map->value;
			return 0;
		}
	}

	return -1;
}

const char *
ni_format_int_mapped(unsigned int value, const ni_intmap_t *map)
{
	for (; map->name; ++map) {
		if (map->value == value)
			return map->name;
	}

	return NULL;
}

const char *
ni_format_int_maybe_mapped(unsigned int value, const ni_intmap_t *map)
{
	static char buffer[20];
	const char *name;

	if (!(name = ni_format_int_mapped(value, map))) {
		snprintf(buffer, sizeof(buffer), "%u", value);
		name = buffer;
	}
	return name;
}

int
ni_parse_double(const char *input, double *result)
{
	char *end;

	if (!input)
		return -1;
	*result = strtod(input, (char **) &end);
	if (*end == '\0')
		return 0;

	return -1;
}

/*
 * Format and parse hex data as aa:bb:cc:... striung
 */
const char *
ni_format_hex(const unsigned char *data, unsigned int datalen, char *namebuf, size_t namelen)
{
	unsigned int i, j;

	for (i = j = 0; i < datalen; ++i) {
		if (j + 4 >= namelen)
			break;
		if (i)
			namebuf[j++] = ':';
		snprintf(namebuf + j, namelen - j, "%02x", data[i]);
		j += 2;
	}
	return namebuf;
}

const char *
ni_print_hex(const unsigned char *data, unsigned int datalen)
{
	static char addrbuf[256];

	return ni_format_hex(data, datalen, addrbuf, sizeof(addrbuf));
}

int
ni_parse_hex(const char *string, unsigned char *data, unsigned int datasize)
{
	unsigned int len = 0;

	while (1) {
		unsigned int octet;

		octet = strtoul(string, (char **) &string, 16);
		if (octet > 255)
			return -1;

		data[len++] = octet;
		if (*string == '\0')
			break;
		if (*string++ != ':')
			return -1;
		if (len >= datasize)
			return -1;
	}

	return len;
}

/*
 * stringbuf functions
 */
void
ni_stringbuf_init(ni_stringbuf_t *sb)
{
	memset(sb, 0, sizeof(*sb));
	sb->dynamic = 1;
}

void
ni_stringbuf_clear(ni_stringbuf_t *sb)
{
	if (sb->dynamic)
		free(sb->string);
	sb->string = NULL;
	sb->len = 0;
}

void
ni_stringbuf_destroy(ni_stringbuf_t *sb)
{
	ni_stringbuf_clear(sb);
}

ni_bool_t
ni_stringbuf_empty(const ni_stringbuf_t *sb)
{
	return sb->len == 0; /* bool */
}

inline static size_t
__ni_stringbuf_size(ni_stringbuf_t *sb, size_t len)
{
	return ((sb->len + len + (NC_STRINGBUF_CHUNK - 1)) & ~(NC_STRINGBUF_CHUNK - 1));
}

static void
__ni_stringbuf_realloc(ni_stringbuf_t *sb, size_t len)
{
	size_t size;
	char * data;

	size = __ni_stringbuf_size(sb, 0);
	if (sb->len + len + 1 > size) {
		ni_assert(sb->dynamic);

		size = __ni_stringbuf_size(sb, len + 1);
		data = realloc(sb->string, size);
		ni_assert(data != NULL);

		sb->string = data;
		memset(sb->string + sb->len, 0, size - sb->len);
	}
}

void
ni_stringbuf_grow(ni_stringbuf_t *sb, size_t len)
{
	__ni_stringbuf_realloc(sb, len);
}

static void
__ni_stringbuf_put(ni_stringbuf_t *sb, const char *ptr, size_t len)
{
	__ni_stringbuf_realloc(sb, len);

	memcpy(sb->string + sb->len, ptr, len);
	sb->string[sb->len + len] = '\0';
	sb->len += len;
}

void
ni_stringbuf_putc(ni_stringbuf_t *sb, char cc)
{
	__ni_stringbuf_put(sb, &cc, 1);
}

void
ni_stringbuf_puts(ni_stringbuf_t *sb, const char *s)
{
	if (s)
		__ni_stringbuf_put(sb, s, strlen(s));
}

int
ni_stringbuf_printf(ni_stringbuf_t *sb, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = ni_stringbuf_vprintf(sb, fmt, ap);
	va_end(ap);

	return ret;
}

int
ni_stringbuf_vprintf(ni_stringbuf_t *sb, const char *fmt, va_list ap)
{
	va_list cp;
	size_t size = (NC_STRINGBUF_CHUNK * 4) - 1;
	int n;

	sb->len = 0;
	ni_stringbuf_grow(sb, size++);
	while(1) {
		va_copy(cp, ap);
		n = vsnprintf(sb->string, size, fmt, cp);
		va_end(cp);

		if(n > -1 && (size_t)n < size) {
			sb->len = n;
			break;
		}
		if (n > -1)
			size = n;
		else
			size *= 2;

		ni_stringbuf_grow(sb, size++);
	}
	return sb->len;
}

void
ni_stringbuf_move(ni_stringbuf_t *dest, ni_stringbuf_t *src)
{
	assert(dest->dynamic == src->dynamic);
	ni_stringbuf_clear(dest);
	*dest = *src;

	src->string = NULL;
	src->len = 0;
}

void
ni_stringbuf_trim_empty_lines(ni_stringbuf_t *sb)
{
	char *str = sb->string;
	int n, trim;

	/* trim tail */
	for (trim = n = sb->len; n; --n) {
		char cc = str[n-1];

		if (cc == '\r' || cc == '\n')
			trim = n;
		else if (cc != ' ' && cc != '\t')
			break;
	}
	sb->string[trim] = '\0';
	sb->len = trim;

	/* trim head */
	for (trim = n = 0; n < sb->len; ) {
		char cc = str[n++];

		if (cc == '\r' || cc == '\n')
			trim = n;
		else if (cc != ' ' && cc != '\t')
			break;
	}
	if (trim) {
		sb->len -= trim;
		memmove(sb->string, sb->string + trim, sb->len + 1);
	}
}

/*
 * background the current process
 */
int
ni_daemonize(const char *pidfile, unsigned int permissions)
{
	pid_t pid;

	if (pidfile) {
		/* check if service is already running */

		pid = ni_pidfile_check(pidfile);
		if (pid < 0)
			return -1;

		if (pid > 0) {
			ni_error("cannot create pidfile %s: service already running", pidfile);
			return -1;
		}

		if (ni_file_exists(pidfile)) {
			if (unlink(pidfile) < 0) {
				ni_error("cannot remove stale pidfile %s: %m", pidfile);
				return -1;
			}
			ni_warn("removing stale pidfile %s", pidfile);
		}
	}

	if (pidfile && ni_pidfile_write(pidfile, permissions, getpid()) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		ni_error("unable to fork: %m");
		return -1;
	}

	/* parent process */
	if (pid != 0) {
		if (pidfile)
			__ni_pidfile_write(pidfile, permissions, pid, 0);
		exit(0);
	}

	/* chdir to root and close fds */
	if (daemon(0, 0) < 0)
		ni_fatal("unable to background process! daemon() failed: %m");

	return 0;
}

/*
 * pidfile management functions
 */
static int
__ni_pidfile_write(const char *pidfile, unsigned int permissions, pid_t pid, int oflags)
{
	char buffer[64];
	int fd, len, r;

	if ((fd = open(pidfile, O_WRONLY|oflags, permissions)) < 0) {
		ni_error("unable to open pidfile %s for writing: %m", pidfile);
		return -1;
	}

	snprintf(buffer, sizeof(buffer), "%u", (unsigned int) pid);
	len = strlen(buffer);

	if ((r = write(fd, buffer, len)) < 0) {
		ni_error("error writing to pidfile %s: %m", pidfile);
failed:
		unlink(pidfile);
		close(fd);
		return -1;
	}

	if (r < len) {
		ni_error("error writing to pidfile %s: short write", pidfile);
		goto failed;
	}

	close(fd);
	return 0;
}

int
ni_pidfile_write(const char *pidfile, unsigned int permissions, pid_t pid)
{
	return __ni_pidfile_write(pidfile, permissions, pid, O_CREAT|O_EXCL);
}

/*
 * Check for presence of pidfile
 *  0:	no or stale pidfile
 *  >0:	pid of active process
 *  <0:	error occured
 */
pid_t
ni_pidfile_check(const char *pidfile)
{
	char buffer[128];
	FILE *fp;
	pid_t pid = 0;

	if (!ni_file_exists(pidfile))
		return 0;

	if (!(fp = fopen(pidfile, "r"))) {
		/* pidfile exists but we can't read it. bad. */
		ni_error("cannot open pidfile %s for reading: %m", pidfile);
		return -1;
	}

	if (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char *s;

		pid = strtoul(buffer, &s, 0);
		if (*s && !isspace(*s)) {
			ni_error("cannot parse pidfile %s", pidfile);
			pid = -1;
		}
	}

	fclose(fp);

	/* See if process is still around */
	if (pid > 0 && kill(pid, 0) < 0) {
		/* Stale pid file, process no longer running */
		if (errno == ESRCH)
			return 0;
		ni_error("unexpected error when checking pidfile %s: kill returns: %m",
				pidfile);
		return -1;
	}

	return pid;
}

/*
 * Create a temporary file
 */
FILE *
ni_mkstemp(char **namep)
{
	char namebuf[PATH_MAX];
	char *tmpdir;
	int fd;

	if (namep == NULL)
		return tmpfile();

	if ((tmpdir = getenv("TMPDIR")) == NULL)
		tmpdir = "/tmp";

	snprintf(namebuf, sizeof(namebuf), "%s/wicked.XXXXXX", tmpdir);
	if ((fd = mkstemp(namebuf)) < 0) {
		ni_error("unable to create unique tempfile in %s", tmpdir);
		return NULL;
	}

	ni_string_dup(namep, namebuf);
	return fdopen(fd, "w");
}

/*
 * Copy contents of file <src> to file <dst>
 */
int
ni_copy_file(FILE *src, FILE *dst)
{
	char buffer[1024];
	int got;

	while ((got = fread(buffer, 1, sizeof(buffer), src)) > 0) {
		int pos, written;

		for (pos = 0; pos < got; pos += written) {
			written = fwrite(buffer + pos, 1, got - pos, dst);
			if (written < 0) {
				ni_error("ni_copy_file failed to write: %m");
				return -1;
			}
		}
	}

	if (got < 0) {
		ni_error("ni_copy_file failed to read: %m");
		return -1;
	}

	return 0;
}

int
ni_copy_file_path(const char *srcpath, const char *dstpath)
{
	FILE *srcfp = NULL, *dstfp = NULL;
	int rv = -1;

	if ((srcfp = fopen(srcpath, "r")) == NULL) {
		ni_error("cannot copy \"%s\": %m", srcpath);
		goto out;
	}
	if ((dstfp = fopen(dstpath, "w")) == NULL) {
		ni_error("cannot copy \"%s\" to \"%s\": %m", srcpath, dstpath);
		goto out;
	}
	rv = ni_copy_file(srcfp, dstfp);

out:
	if (dstfp)
		fclose(dstfp);
	if (srcfp)
		fclose(srcfp);
	return rv;
}

/*
 * Write data to a file
 */
int
ni_file_write(FILE *fp, const void *data, size_t len)
{
	size_t written;

	written = fwrite(data, 1, len, fp);
	if (written < len) {
		ni_error("%s: %m", __func__);
		return -1;
	}
	return written;
}

void *
ni_file_read(FILE *fp, unsigned int *lenp)
{
	struct stat stb;
	unsigned char *buffer;
	unsigned int count, done, size;

	if (fstat(fileno(fp), &stb) < 0)
		return NULL;
	size = stb.st_size;

	buffer = malloc(size);
	if (buffer == NULL)
		return NULL;

	for (done = 0; done < size; done += count) {
		count = fread(buffer + done, 1, size - done, fp);
		if (count == 0) {
			ni_error("%s: short read from file", __func__);
			free(buffer);
			return NULL;
		}
	}

	*lenp = done;
	return buffer;
}

/*
 * Copy file for backup
 */
int
ni_backup_file_to(const char *srcpath, const char *backupdir)
{
	const char *dstpath;

	if (!(dstpath = __ni_build_backup_path(srcpath, backupdir)))
		return -1;
	if (access(backupdir, F_OK) < 0 && errno == ENOENT)
		mkdir(backupdir, 0700);
	if (access(dstpath, F_OK) == 0) {
		ni_debug_readwrite("%s(%s, %s): backup copy already exists",
				__FUNCTION__, srcpath, backupdir);
		return 0;
	}
	ni_debug_readwrite("%s(%s, %s)", __FUNCTION__, srcpath, backupdir);
	return ni_copy_file_path(srcpath, dstpath);
}

/*
 * Restore file from backup
 */
int
ni_restore_file_from(const char *dstpath, const char *backupdir)
{
	const char *srcpath;

	if (!(srcpath = __ni_build_backup_path(dstpath, backupdir)))
		return -1;
	if (access(srcpath, R_OK) < 0) {
		if (errno == ENOENT) {
			ni_debug_readwrite("%s(%s, %s): no backup copy to restore",
				__FUNCTION__, dstpath, backupdir);
			return 0;
		}
		ni_error("cannot restore %s from %s: %m", dstpath, srcpath);
		return -1;
	}

	ni_debug_readwrite("%s(%s, %s)", __FUNCTION__, dstpath, backupdir);
	if (ni_copy_file_path(srcpath, dstpath) < 0)
		return -1;

	unlink(srcpath);
	return 0;
}

const char *
__ni_build_backup_path(const char *syspath, const char *backupdir)
{
	static char backupfile[PATH_MAX];
	const char *basename;

	if (syspath[0] != '/') {
		ni_error("cannot backup files by relative path \"%s\"", syspath);
		return NULL;
	}

	basename = strrchr(syspath, '/') + 1;
	if (basename[0] == '\0') {
		ni_error("cannot backup file: filename \"%s\" ends with slash", syspath);
		return NULL;
	}

	snprintf(backupfile, sizeof(backupfile), "%s/%s", backupdir, basename);
	return backupfile;
}

/*
 * Return the basename of a file path
 */
const char *
ni_basename(const char *path)
{
	const char *sp;

	if ((sp = strrchr(path, '/')) == NULL)
		return path;
	return sp + 1;
}

/*
 * Utility functions for handling uuids
 */
const char *
ni_uuid_print(const ni_uuid_t *uuid)
{
	static char buffer[64];
	const unsigned char *p;

	if (!uuid)
		return NULL;
	if (ni_uuid_is_null(uuid))
		return "";

	p = uuid->octets;
	snprintf(buffer, sizeof(buffer),
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		"%02x%02x%02x%02x%02x%02x",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
		p[10], p[11], p[12], p[13], p[14], p[15]);
	return buffer;
}

int
ni_uuid_parse(ni_uuid_t *uuid, const char *string)
{
	unsigned int nibbles = 0;
	uint32_t word = 0;

	if (string == NULL)
		return -1;
	if (*string == 0) {
		memset(uuid, 0, sizeof(uuid));
		return 0;
	}

	while (*string) {
		char cc = tolower(*string++);

		if (nibbles == 32)
			return -1;

		if (isdigit(cc)) {
			word = (word << 4) | (cc - '0');
		} else if ('a' <= cc && cc <= 'f') {
			word = (word << 4) | (cc - 'a' + 10);
		} else {
			return -1;
		}
		++nibbles;

		if (nibbles == 8) {
			uuid->words[nibbles / 8] = word;
			if (*string == '-' || *string == ':')
				++string;
		}
	}

	if (nibbles < 32)
		return -1;
	return 0;
}

int
ni_uuid_is_null(const ni_uuid_t *uuid)
{
	return uuid->words[0] == 0 && uuid->words[1] == 0 && uuid->words[2] == 0 && uuid->words[3] == 0;
}

int
ni_uuid_equal(const ni_uuid_t *uuid1, const ni_uuid_t *uuid2)
{
	return !memcmp(uuid1, uuid2, sizeof(uuid1));
}

/*
 * Generate a uuid.
 * Not elaborate, but good enough for our purposes.
 */
ni_uuid_t *
ni_uuid_generate(ni_uuid_t *uuid)
{
	static ni_uuid_t req_uuid;

	if (ni_uuid_is_null(&req_uuid)) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		req_uuid.words[0] = tv.tv_sec;
		req_uuid.words[1] = tv.tv_usec;
		req_uuid.words[2] = getpid();
	}

	req_uuid.words[3]++;
	*uuid = req_uuid;

	return uuid;
}

/*
 * Seed the RNG from /dev/urandom
 */
void
ni_srandom(void)
{
	uint32_t seed = 0;
	int fd;

	if ((fd = open("/dev/urandom", O_RDONLY)) >= 0) {
		if (read(fd, &seed, 4) < 4)
			seed = 0;
		close(fd);
	} else {
		ni_warn("unable to open /dev/random: %m");
	}

	if (seed == 0) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		seed = tv.tv_usec ^ tv.tv_usec / 1024;
		seed = seed ^ tv.tv_sec;
		seed = seed ^ getpid();
	}

	srandom(seed);
}

/*
 * Alloc helpers with NULLL check
 */
void *
xcalloc(unsigned int count, size_t size)
{
	void *p = calloc(count, size);

	if (p == NULL)
		ni_fatal("allocation failed calloc(%u, %lu): %m", count, (unsigned long) size);
	return p;
}

char *
xstrdup(const char *string)
{
	char *p;

	if (string == NULL)
		return NULL;
	p = strdup(string);
	if (p == NULL)
		ni_fatal("allocation failed strdup(%s): %m", string);
	return p;
}

ni_opaque_t *
ni_opaque_new(const void *data, size_t len)
{
	ni_opaque_t *opaq;

	if (len > sizeof(opaq->data)) {
		ni_error("%s: data too large for buffer (len=%lu)",
				__FUNCTION__, (long) len);
		return NULL;
	}

	opaq = xcalloc(1, sizeof(*opaq));
	memcpy(opaq->data, data, len);
	opaq->len = len;

	return opaq;
}

void
ni_opaque_free(ni_opaque_t *opaq)
{
	free(opaq);
}

/*
 * Track temporary resources and clean them up when done
 */
struct ni_tempstate {
	ni_string_array_t	files;
};

ni_tempstate_t *
ni_tempstate_new()
{
	ni_tempstate_t *ts;

	ts = calloc(1, sizeof(*ts));
	return ts;
}

void
ni_tempstate_finish(ni_tempstate_t *ts)
{
	unsigned int i;

	for (i = 0; i < ts->files.count; ++i) {
		const char *filename = ts->files.data[i];

		if (unlink(filename) < 0)
			ni_warn("failed to remove %s: %m", filename);
	}

	ni_string_array_destroy(&ts->files);
	free(ts);
}

void
ni_tempstate_add_file(ni_tempstate_t *ts, const char *filename)
{
	ni_string_array_append(&ts->files, filename);
}
