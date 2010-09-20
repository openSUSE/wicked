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

static const char *	ni_netconfig_default_schema(const char *);
static int		__ni_netonfig_refresh(ni_handle_t *nih);
static int		__ni_netconfig_interface_configure(ni_handle_t *, ni_interface_t *, xml_node_t *);
static int		__ni_netconfig_interface_delete(ni_handle_t *, const char *);
static void		__ni_netonfig_close(ni_handle_t *nih);

static struct ni_ops ni_netconfig_ops = {
	.refresh	= __ni_netonfig_refresh,
	.configure_interface = __ni_netconfig_interface_configure,
	.delete_interface = __ni_netconfig_interface_delete,
	.close		= __ni_netonfig_close,
};

ni_handle_t *
ni_netconfig_open(ni_syntax_t *syntax)
{
	ni_handle_t *nih;

	if (!syntax) {
		ni_error("ni_netconfig_open: syntax is NULL");
		return NULL;
	}

	nih = __ni_handle_new(&ni_netconfig_ops);
	if (nih)
		nih->default_syntax = syntax;

	return nih;
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
__ni_netonfig_close(ni_handle_t *nih)
{
	if (nih->default_syntax)
		ni_syntax_free(nih->default_syntax);
}

static int
__ni_netonfig_refresh(ni_handle_t *nih)
{
	if (nih->default_syntax == NULL) {
		ni_error("netonfig: cannot refresh, no syntax associated");
		return -1;
	}
	return ni_syntax_parse_all(nih->default_syntax, nih);
}

/*
 * Configure an interface.
 * @nih is the netconfig handle representing our local configuration files.
 * @cfg is the interface data to be added/replaced.
 * @cfg_xml is the original XML blob passed in by the caller, if any. Since we
 *	do no process information beyond what's in a ni_interface, we ignore
 *	this argument here.
 */
static int
__ni_netconfig_interface_configure(ni_handle_t *nih, ni_interface_t *cfg, xml_node_t *cfg_xml)
{
	ni_interface_t *nfp, *ifp, **pos;

	if (!cfg->name) {
		ni_error("netconfig: cannot configure unnamed interfaces");
		return -1;
	}

	nfp = ni_interface_clone(cfg);
	if (!nfp) {
		ni_error("netconfig: unable to clone interface %s", cfg->name);
		return -1;
	}
	nfp->modified = 1;

	for (pos = &nih->iflist; (ifp = *pos) != NULL; pos = &ifp->next) {
		if (!strcmp(ifp->name, cfg->name)) {
			nfp->next = ifp->next;
			ni_interface_put(ifp);
			break;
		}
	}

	/* Insert new interface */
	*pos = nfp;

	/* write back changes */
	return ni_syntax_format_all(nih->default_syntax, nih, NULL);
}

/*
 * Delete an interface.
 */
static int
__ni_netconfig_interface_delete(ni_handle_t *nih, const char *ifname)
{
	ni_interface_t *ifp;

	ifp = ni_interface_by_name(nih, ifname);
	if (!ifp) {
		ni_error("netconfig: cannot delete interface %s - not found", ifname);
		return -1;
	}
	ifp->deleted = 1;

	/* write back changes */
	return ni_syntax_format_all(nih->default_syntax, nih, NULL);
}
