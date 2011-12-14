/*
 * Routines for loading and storing all network configuration
 * from system config files.
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include "netinfo_priv.h"
#include "sysconfig.h"
#include "config.h"

#define _PATH_HOSTNAME	"/etc/HOSTNAME"

static void		__ni_netonfig_close(ni_handle_t *nih);

static struct ni_ops ni_netconfig_ops = {
	.close			= __ni_netonfig_close,
};

typedef struct ni_nchandle {
	ni_handle_t		base;

	ni_syntax_t *		syntax;
} ni_nchandle_t;

static inline ni_nchandle_t *
__to_netconfig(const ni_handle_t *nih)
{
	assert(nih->op == &ni_netconfig_ops);
	return (ni_nchandle_t *) nih;
}

ni_handle_t *
ni_netconfig_open(ni_syntax_t *syntax)
{
	ni_nchandle_t *nih;

	if (!syntax) {
		ni_error("ni_netconfig_open: syntax is NULL");
		return NULL;
	}

	nih = (ni_nchandle_t *) __ni_handle_new(sizeof(*nih), &ni_netconfig_ops);
	if (nih)
		nih->syntax = syntax;

	return &nih->base;
}

static inline ni_syntax_t *
__ni_netconfig_syntax(const ni_handle_t *nih)
{
	ni_nchandle_t *nit = __to_netconfig(nih);
	return nit->syntax;
}

const char *
ni_netconfig_default_schema(const char *root_dir)
{
	struct __schemamap {
		char *path, *schema;
	};
	static struct __schemamap schemamap[] = {
		{ "/etc/SuSE-release", "suse" },
		{ "/etc/redhat-release", "redhat" },
		{ NULL }
	};
	struct __schemamap *map;

	for (map = schemamap; map->path; ++map) {
		char fullpath[PATH_MAX];

		if (root_dir) {
			snprintf(fullpath, sizeof(fullpath), "%s%s", root_dir, map->path);
			if (ni_file_exists(fullpath))
				return map->schema;
		} else {
			if (ni_file_exists(map->path))
				return map->schema;
		}
	}
	return NULL;
}

ni_syntax_t *
ni_netconfig_default_syntax(const char *root_dir)
{
	const char *schema, *base_path = NULL;
	ni_syntax_t *syntax;

	schema = ni_global.config->default_syntax;
	if (schema) {
		base_path = ni_global.config->default_syntax_path;
	} else {
		/* No syntax defined in configuration file. Try to find out
		 * which distro we're on. */
		schema = ni_netconfig_default_schema(root_dir);
	}

	syntax = ni_syntax_new(schema, base_path);
	if (root_dir)
		ni_syntax_set_root_directory(syntax, root_dir);
	return syntax;
}

static void
__ni_netonfig_close(ni_handle_t *nih)
{
	ni_nchandle_t *nit = __to_netconfig(nih);

	if (nit->syntax)
		ni_syntax_free(nit->syntax);
}
