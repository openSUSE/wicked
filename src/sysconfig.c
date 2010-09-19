/*
 * Routines for loading and storing sysconfig files
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <ctype.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include "sysconfig.h"

static int	unquote(char *);
static char *	quote(char *);

int
ni_sysconfig_scandir(const char *dirname, const char *match_prefix, ni_string_array_t *res)
{
	return ni_scandir(dirname, match_prefix, res);
}

ni_sysconfig_t *
ni_sysconfig_new(const char *pathname)
{
	ni_sysconfig_t *sc;

	sc = calloc(1, sizeof(ni_sysconfig_t));
	sc->pathname = pathname? strdup(pathname) : NULL;

	return sc;
}

void
ni_sysconfig_destroy(ni_sysconfig_t *sc)
{
	ni_var_array_destroy(&sc->vars);
	ni_string_free(&sc->pathname);
	free(sc);
}

ni_sysconfig_t *
__ni_sysconfig_read(const char *filename, const char **varnames)
{
	ni_sysconfig_t *sc;
	char linebuf[512];
	FILE *fp;

	ni_debug_readwrite("ni_sysconfig_read(%s)", filename);
	if (!(fp = fopen(filename, "r"))) {
		perror(filename);
		return NULL;
	}

	sc = ni_sysconfig_new(filename);
	while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
		char *name, *value;
		char *sp = linebuf;

		while (isspace(*sp))
			++sp;
		if (*sp == '#')
			continue;

		/* Silently ignore fishy strings which do not seem to be
		   variables . */
		if (!isalpha(*sp))
			continue;
		name = sp;

		while (isalnum(*sp) || *sp == '_')
			++sp;
		if (*sp != '=')
			continue;
		*sp++ = '\0';

		/* If we were given a list of variable names to match
		 * against, ignore all variables not in this list. */
		if (varnames) {
			const char **vp = varnames, *match;

			while ((match = *vp++) != NULL) {
				if (!strcmp(match, name))
					break;
			}
			if (!match)
				continue;
		}

		value = sp;
		if (!unquote(value))
			continue;

		if (ni_sysconfig_set(sc, name, value) < 0)
			goto error;
	}

	fclose(fp);
	return sc;

error:
	ni_sysconfig_destroy(sc);
	fclose(fp);
	return NULL;
}

/*
 * Read all variables from the specified sysconfig file
 */
ni_sysconfig_t *
ni_sysconfig_read(const char *filename)
{
	return __ni_sysconfig_read(filename, NULL);
}

/*
 * Read all variables from the specified sysconfig file listed in @varnames
 */
ni_sysconfig_t *
ni_sysconfig_read_matching(const char *filename, const char **varnames)
{
	return __ni_sysconfig_read(filename, varnames);
}

/*
 * Write out sysconfig variables, just clobbering everything that is there.
 */
int
ni_sysconfig_overwrite(ni_sysconfig_t *sc)
{
	FILE *fp;
	unsigned int i;

	fp = fopen(sc->pathname, "w");
	if (fp == NULL) {
		ni_error("Unable to open %s for writing: %m", sc->pathname);
		return -1;
	}

	for (i = 0; i < sc->vars.count; ++i) {
		ni_var_t *var = &sc->vars.data[i];

		if (var->value == NULL) {
			fprintf(fp, "%s=''\n", var->name);
		} else {
			char *quoted = quote(var->value);

			fprintf(fp, "%s='%s'\n", var->name, quoted);
			if (quoted != var->value)
				free(quoted);
		}
	}

	fclose(fp);
	return 0;
}

static int
unquote(char *string)
{
	char *src, *dst, cc;

	src = dst = string;
	while ((cc = *src++) != '\0') {
		if (isspace(cc))
			break;
		if (*string == '"') {
			while ((cc = *src++) != '"') {
				if (cc == '\\') {
					cc = *src++;
					if (cc == '\0')
						return 0;
				}
				*dst++ = cc;
			}
		} else if (*string == '\'') {
			while ((cc = *src++) != '\'')
				*dst++ = cc;
			string = dst;
		} else {
			*dst++ = cc;
		}
	}
	*dst = '\0';
	return 1;
}

char *
quote(char *string)
{
	char *quoted, *s;

	if (strchr(string, '\'') == NULL)
		return string;

	/* For now, just remove ticks. We don't want them */
	quoted = strdup(string);
	while ((s = strchr(quoted, '\'')) != NULL)
		*s = ' ';
	return quoted;
}

int
ni_sysconfig_set(ni_sysconfig_t *sc, const char *name, const char *value)
{
	return ni_var_array_set(&sc->vars, name, value);
}

int
ni_sysconfig_set_integer(ni_sysconfig_t *sc, const char *name, unsigned int value)
{
	char buffer[32];

	snprintf(buffer, sizeof(buffer), "%u", value);
	return ni_sysconfig_set(sc, name, buffer);
}

ni_var_t *
ni_sysconfig_get(const ni_sysconfig_t *sc, const char *name)
{
	return ni_var_array_get(&sc->vars, name);
}

int
ni_sysconfig_find_matching(ni_sysconfig_t *sc, const char *prefix,
		ni_string_array_t *res)
{
	unsigned int i, pfxlen;
	ni_var_t *var;

	pfxlen = strlen(prefix);
	for (i = 0, var = sc->vars.data; i < sc->vars.count; ++i, ++var) {
		const char *value = var->value;

		if (value && *value && !strncmp(var->name, prefix, pfxlen))
			ni_string_array_append(res, var->name);
	}
	return res->count;
}

int
ni_sysconfig_get_string(const ni_sysconfig_t *sc, const char *name, char **p)
{
	ni_var_t *var;

	ni_string_free(p);
	if ((var = ni_sysconfig_get(sc, name)) != NULL)
		ni_string_dup(p, var->value);
	return 0;
}

int
ni_sysconfig_get_integer(const ni_sysconfig_t *sc, const char *name, unsigned int *p)
{
	ni_var_t *var;

	*p = 0;
	if ((var = ni_sysconfig_get(sc, name)) != NULL)
		*p = strtoul(var->value, NULL, 0);
	return 0;
}

int
ni_sysconfig_get_boolean(const ni_sysconfig_t *sc, const char *name, int *p)
{
	ni_var_t *var;

	*p = 0;
	if ((var = ni_sysconfig_get(sc, name)) != NULL) {
		if (!strcasecmp(var->value, "on")
		 || !strcasecmp(var->value, "true")
		 || !strcasecmp(var->value, "yes"))
			*p = 1;
	}
	return 0;
}

int
ni_sysconfig_get_string_optional(const ni_sysconfig_t *sc, const char *name, char **p)
{
	ni_var_t *var;

	if ((var = ni_sysconfig_get(sc, name)) != NULL && var->value && var->value[0])
		ni_string_dup(p, var->value);
	return 0;
}

int
ni_sysconfig_get_integer_optional(const ni_sysconfig_t *sc, const char *name, unsigned int *p)
{
	ni_var_t *var;

	if ((var = ni_sysconfig_get(sc, name)) != NULL && var->value && var->value[0])
		*p = strtoul(var->value, NULL, 0);
	return 0;
}

int
ni_sysconfig_get_boolean_optional(const ni_sysconfig_t *sc, const char *name, int *p)
{
	ni_var_t *var;

	if ((var = ni_sysconfig_get(sc, name)) != NULL && var->value && var->value[0]) {
		if (!strcasecmp(var->value, "on")
		 || !strcasecmp(var->value, "true")
		 || !strcasecmp(var->value, "yes"))
			*p = 1;
		else
			*p = 0;
	}
	return 0;
}
