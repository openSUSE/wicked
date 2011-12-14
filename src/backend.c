#include <stdlib.h>
#include <dirent.h>
#include <wicked/backend.h>
#include "backend-priv.h"
#include "config.h"

#define _PATH_HOSTNAME	"/etc/HOSTNAME"

extern ni_syntax_t *	ni_backend_default_syntax(const char *);
extern const char *	ni_backend_default_schema(const char *);

/*
 * Create a new backend handle
 */
ni_backend_t *
ni_backend_new(const char *schema, const char *pathname)
{
	ni_syntax_t *syntax = NULL;
	ni_backend_t *be;

	if (schema == NULL) {
		syntax = ni_backend_default_syntax(pathname);
	} else {
		syntax = ni_syntax_new(schema, pathname);
	}

	if (syntax == NULL) {
		ni_error("unable to create syntax object for schema %s",
				schema? schema : "default");
		return NULL;
	}

	be = calloc(1, sizeof(*be));
	be->syntax = syntax;

	return be;
}

/*
 * Free a configuration backend
 */
void
ni_backend_free(ni_backend_t *be)
{
	if (be->syntax)
		ni_syntax_free(be->syntax);
	be->syntax = NULL;

	free(be);
}

/*
 * Determine which syntax to use when opening a backend
 */
ni_syntax_t *
ni_backend_default_syntax(const char *root_dir)
{
	const char *schema, *base_path = NULL;
	ni_syntax_t *syntax;

	schema = ni_global.config->default_syntax;
	if (schema) {
		base_path = ni_global.config->default_syntax_path;
	} else {
		/* No syntax defined in configuration file. Try to find out
		 * which distro we're on. */
		schema = ni_backend_default_schema(root_dir);
	}

	syntax = ni_syntax_new(schema, base_path);
	if (root_dir)
		ni_syntax_set_root_directory(syntax, root_dir);
	return syntax;
}

const char *
ni_backend_default_schema(const char *root_dir)
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


/*
 * Build path relative to root directory, if one is given. Otherwise,
 * just return pathname as-is.
 */
static const char *
__ni_backend_build_path(ni_backend_t *be, const char *path)
{
	return ni_syntax_build_path(be->syntax, "%s", path);
}

/*
 * Get the netconfig struct associated with this backend
 */
ni_netconfig_t *
ni_backend_get_netconfig(ni_backend_t *be)
{
	return &be->nc;
}

/*
 * Reload interface information
 */
int
ni_backend_interfaces_reload(ni_backend_t *be)
{
	if (be->syntax == NULL) {
		ni_error("netonfig: cannot refresh, no syntax associated");
		return -1;
	}
	return ni_syntax_get_interfaces(be->syntax, &be->nc);
}

/*
 * Read/write /etc/HOSTNAME
 * We should allow runtime configuration to change the location of the
 * file, and to specify an "updater" script that can be called to rewrite
 * other depedencies (eg if we have a special entry in the hosts file,
 * or httpd.conf, or whatever)
 */
const char *
ni_backend_hostname_get(ni_backend_t *be, char *buffer, size_t size)
{
	ni_syntax_t *syntax = be->syntax;
	int rv = 0;

	if (syntax->get_hostname) {
		rv = syntax->get_hostname(syntax, buffer, size);
		if (rv < 0) {
			ni_error("Cannot read hostname: %s", ni_strerror(rv));
			return NULL;
		}
	} else {
		const char *path;
		FILE *fp;

		path = __ni_backend_build_path(be, _PATH_HOSTNAME);
		if ((fp = fopen(path, "r")) == NULL) {
			ni_error("cannot open %s: %m", path);
			return NULL;
		}

		if (fgets(buffer, size, fp) == NULL) {
			fclose(fp);
			return NULL;
		}
		/* strip off trailing newline */
		buffer[strcspn(buffer, "\r\n")] = '\0';
		fclose(fp);
	}

	return buffer;
}

int
ni_backend_hostname_put(ni_backend_t *be, const char *hostname)
{
	ni_syntax_t *syntax = be->syntax;

	if (syntax->put_hostname) {
		if (syntax->put_hostname(syntax, hostname) < 0)
			return -1;
	} else {
		const char *path;
		FILE *fp;

		path = __ni_backend_build_path(be, _PATH_HOSTNAME);
		if ((fp = fopen(path, "w")) == NULL) {
			ni_error("cannot open %s: %m", path);
			return -1;
		}
		fprintf(fp, "%s\n", hostname);
		fclose(fp);
	}

	return 0;
}
