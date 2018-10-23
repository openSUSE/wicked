/*
 *	wicked client utilities to parse sysctl/ifsysctl files.
 *
 *	Copyright (C) 2011-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *
 */
#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

#include <wicked/logging.h>
#include "ifsysctl.h"

static char *
__ni_string_strip_spaces(char *string)
{
	char *end;

	if (ni_string_empty(string))
		return string;

	/* strip trailing spaces */
	end = string + strlen(string);
	while (end-- > string) {
		if (!isspace((unsigned char)*end))
			break;
		*end = '\0';
	}

	/* strip leading spaces */
	while (isspace((unsigned char)*string))
		string++;

	return string;
}

void
__ni_sysctl_rewrite_to_slash(char *ptr)
{
	char *p, sep = 0;

	if(!ptr)
		return;

	for (p=ptr; *p; p++) {
		switch (*p) {
		case '/':
			switch (sep) {
			case 0:
				sep = '/';
				break;
			case '/':
				break;
			default:
				*p = '.';
				break;
			}
			break;
		case '.':
			switch (sep) {
			case 0:
				sep = '.';
				*p = '/';
				break;
			case '.':
				*p = '/';
				break;
			default:
				break;
			}
		default:
			break;
		}
	}
}

void
__ni_sysctl_rewrite_to_dot(char *ptr)
{
	char *p, sep = 0;

	if(!ptr)
		return;

	for (p=ptr; *p; p++) {
		switch (*p) {
		case '/':
			switch (sep) {
			case 0:
				sep = '/';
				*p = '.';
				break;
			case '/':
				*p = '.';
				break;
			default:
				break;
			}
			break;
		case '.':
			switch (sep) {
			case 0:
				sep = '.';
				break;
			case '.':
				break;
			default:
				*p = '/';
				break;
			}
		default:
			break;
		}
	}
}

ni_bool_t
__ni_sysctl_file_load(ni_var_array_t *vars, const char *filename,
		 void (*process)(ni_var_array_t *, const char *, const char *))
{
	char buffer[PATH_MAX + 1] = {'\0'};
	char *key, *val;
	FILE *fp;

	fp = fopen(filename, "re");
	if(fp == NULL) {
		if (errno != ENOENT) {
			ni_error("Unable to open %s: %m", filename);
		}
		return FALSE;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		key = __ni_string_strip_spaces(buffer);
		if (*key == '\0' || *key == ';' || *key == '#')
			continue;

		if ((val = strchr(key, '=')) == NULL)
			continue;
		*val++ = '\0';

		key = __ni_string_strip_spaces(key);
		val = __ni_string_strip_spaces(val);

		if(*key && *val) {
			__ni_sysctl_rewrite_to_dot(key);
			process(vars, key, val);
		}
	}

	fclose(fp);
	return TRUE;
}

ni_var_t *
ni_ifsysctl_vars_get(const ni_var_array_t *vars, const char *keyfmt, ...)
{
	ni_var_t *var;
	char *key = NULL;
	va_list ap;
	int ret;

	if(!vars || !keyfmt)
		return NULL;

	va_start(ap, keyfmt);
	ret = vasprintf(&key, keyfmt, ap);
	va_end(ap);
	if (ret < 0)
		return NULL;

	__ni_sysctl_rewrite_to_dot(key);
	var = ni_var_array_get(vars, key);
	ni_string_free(&key);
	return var;
}

ni_bool_t
ni_ifsysctl_vars_set(ni_var_array_t *vars, const char *value, const char *keyfmt, ...)
{
	char *key = NULL;
	va_list ap;
	int ret;

	if(!vars || !keyfmt || !value)
		return FALSE;

	va_start(ap, keyfmt);
	ret = vasprintf(&key, keyfmt, ap);
	va_end(ap);
	if (ret < 0)
		return FALSE;

	__ni_sysctl_rewrite_to_dot(key);
	ni_var_array_set(vars, key, value);
	ni_string_free(&key);
	return TRUE;
}

void
__ni_ifsysctl_vars_map(ni_var_array_t *vars, const char *key, const char *val)
{
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
	const char *ptr;

	/* Normalize the net.ipv4.ip_forward alias */
	if (!strcmp(key, "net.ipv4.ip_forward"))
		key = "net.ipv4.conf.all.forwarding";

	/*
	 * Filter out net.ipv4.conf.* and net.ipv6.conf.* only.
	 */
	if (strncmp(key, "net.ipv4.conf.", sizeof("net.ipv4.conf.")-1)
	&&  strncmp(key, "net.ipv6.conf.", sizeof("net.ipv6.conf.")-1))
		return;

	/*
	 * Resolve $INTERFACE and $SYSCTL_IF wildcard crap
	 */
	if ((ptr = strstr(key, "$INTERFACE"))) {
		ni_stringbuf_puts(&buf, key);
		ni_stringbuf_truncate(&buf, ptr - key);
		ni_stringbuf_puts(&buf, "default");
		ptr += sizeof("$INTERFACE")-1;
		ni_stringbuf_puts(&buf, ptr);
		key = buf.string;
	} else
	if ((ptr = strstr(key, "$SYSCTL_IF"))) {
		ni_stringbuf_puts(&buf, key);
		ni_stringbuf_truncate(&buf, ptr - key);
		ni_stringbuf_puts(&buf, "default");
		ptr += sizeof("$SYSCTL_IF")-1;
		ni_stringbuf_puts(&buf, ptr);
		key = buf.string;
	}

	/*
	 * And finally add it to the array
	 */
	ni_var_array_set(vars, key, val);
	ni_stringbuf_destroy(&buf);
}

ni_bool_t
ni_ifsysctl_file_load(ni_var_array_t *vars, const char *filename)
{
	if (!vars || ni_string_empty(filename))
		return FALSE;

	ni_debug_readwrite("Reading sysctl file '%s'", filename);
	return __ni_sysctl_file_load(vars, filename, __ni_ifsysctl_vars_map);
}
