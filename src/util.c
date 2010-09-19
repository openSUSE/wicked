/*
 * Helper functions
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

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

static int	__ni_pidfile_write(const char *, unsigned int, pid_t, int);

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
		if (!ni_string_array_append(dst, src->data[i]))
			return 0;
	}
	return 1;
}

void
ni_string_array_destroy(ni_string_array_t *nsa)
{
	while (nsa->count--)
		free(nsa->data[nsa->count]);
	free(nsa->data);
	memset(nsa, 0, sizeof(*nsa));
}

static int
__ni_string_array_append(ni_string_array_t *nsa, char *str)
{
	if ((nsa->count & 15) == 0) {
		char **newdata;

		newdata = realloc(nsa->data, (nsa->count + 17) * sizeof(char *));
		if (!newdata)
			return 0;
		nsa->data = newdata;
	}

	nsa->data[nsa->count++] = str;
	return 1;
}

int
ni_string_array_append(ni_string_array_t *nsa, const char *str)
{
	char *newstr;

	newstr = strdup(str);
	if (!newstr)
		return 0;

	if (!__ni_string_array_append(nsa, newstr)) {
		free(newstr);
		return 0;
	}

	return 1;
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
		var->name = strdup(name);
		var->value = NULL;
	}

	if (var->value)
		free(var->value);
	var->value = value? strdup(value) : NULL;
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
		*p = strdup(var->value);
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
ni_var_array_set_boolean(ni_var_array_t *nva, const char *name, int value)
{
	return ni_var_array_set(nva, name, value? "yes" : "no");
}


/*
 * Scan directory and return all file names matching the given prefix.
 */
int
ni_scandir(const char *dirname, const char *match_prefix, ni_string_array_t *res)
{
	struct dirent *dp;
	unsigned int pfxlen;
	DIR *dir;

	ni_debug_readwrite("ni_scandir(%s, %s)", dirname, match_prefix);
	dir = opendir(dirname);
	if (dir == NULL) {
		perror(dirname);
		return 0;
	}

	pfxlen = match_prefix? strlen(match_prefix) : 0;
	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;
		if (!pfxlen || !strncmp(dp->d_name, match_prefix, pfxlen))
			ni_string_array_append(res, dp->d_name);
	}
	closedir(dir);

	return res->count;
}

/*
 * Check if the given file exists
 */
extern int
ni_file_exists(const char *filename)
{
	return access(filename, F_OK) == 0;
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
	*pp = value? strdup(value) : NULL;
}

int
ni_parse_int(const char *input, unsigned int *result)
{
	char *end;

	*result = strtoul(input, (char **) &end, 0);
	if (*end == '\0')
		return 0;

	return -1;
}

int
ni_parse_int_mapped(const char *input, const ni_intmap_t *map, unsigned int *result)
{
	char *end;

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

/*
 * strinbuf functions
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

int
ni_stringbuf_empty(const ni_stringbuf_t *sb)
{
	return sb->len == 0;
}

static void
__ni_stringbuf_put(ni_stringbuf_t *sb, const char *ptr, size_t len)
{
	size_t size;

	size = (sb->len + 63) & ~63;
	if (sb->len + len + 1 > size) {
		size = (sb->len + len + 1 + 63) & ~63;
		sb->string = realloc(sb->string, size);
	}
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

void
ni_stringbuf_printf(ni_stringbuf_t *sb, const char *fmt, ...)
{
	char temp[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(temp, sizeof(temp), fmt, ap);
	va_end(ap);

	ni_stringbuf_puts(sb, temp);
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
ni_mkstemp(void)
{
	return tmpfile();
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

