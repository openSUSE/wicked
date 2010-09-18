/*
 * Routines for loading and storing all network configuration
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

static const char *	ni_netconfig_default_schema(const char *);
static int		__ni_config_refresh(ni_handle_t *nih);
static void		__ni_config_close(ni_handle_t *nih);

static struct ni_ops ni_config_ops = {
	.refresh	= __ni_config_refresh,
	.close		= __ni_config_close,
};

ni_handle_t *
ni_netconfig_open(ni_syntax_t *syntax)
{
	ni_handle_t *nih;

	if (!syntax) {
		syntax = ni_netconfig_default_syntax(NULL);
		if (!syntax)
			return NULL;
	}

	nih = __ni_handle_new(&ni_config_ops);
	if (nih)
		nih->default_syntax = syntax;

	return nih;
}

ni_syntax_t *
ni_netconfig_default_syntax(const char *root_dir)
{
	ni_syntax_t *syntax;
	const char *schema;

	schema = ni_global.config->default_syntax;
	if (schema) {
		//base_path = ni_global.config->default_syntax_path;
	} else {
		/* No syntax defined in configuration file. Try to find out
		 * which distro we're on. */
		schema = ni_netconfig_default_schema(root_dir);
	}

	syntax = ni_syntax_new(schema, NULL);
	if (root_dir)
		ni_syntax_set_root_directory(syntax, root_dir);
	return syntax;
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

static void
__ni_config_close(ni_handle_t *nih)
{
	if (nih->default_syntax)
		ni_syntax_free(nih->default_syntax);
}

static int
__ni_config_refresh(ni_handle_t *nih)
{
	if (nih->default_syntax == NULL) {
		error("__ni_config_refresh: no syntax object associated");
		return -1;
	}
	return ni_syntax_parse_all(nih->default_syntax, nih);
}
