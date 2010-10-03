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

static const char *	ni_netconfig_default_schema(const char *);
static int		__ni_netonfig_refresh(ni_handle_t *nih);
static int		__ni_netconfig_interface_configure(ni_handle_t *, ni_interface_t *, xml_node_t *);
static int		__ni_netconfig_interface_delete(ni_handle_t *, const char *);
static int		__ni_netconfig_hostname_put(ni_handle_t *, const char *);
static int		__ni_netconfig_hostname_get(ni_handle_t *, char *, size_t);
static void		__ni_netonfig_close(ni_handle_t *nih);

static struct ni_ops ni_netconfig_ops = {
	.refresh		= __ni_netonfig_refresh,
	.configure_interface	= __ni_netconfig_interface_configure,
	.delete_interface	= __ni_netconfig_interface_delete,
	.hostname_get		= __ni_netconfig_hostname_get,
	.hostname_put		= __ni_netconfig_hostname_put,
	.close			= __ni_netonfig_close,
};

typedef struct ni_netconfig {
	ni_handle_t		base;

	ni_syntax_t *		syntax;
} ni_netconfig_t;

static inline ni_netconfig_t *
__to_netconfig(ni_handle_t *nih)
{
	assert(nih->op == &ni_netconfig_ops);
	return (ni_netconfig_t *) nih;
}

ni_handle_t *
ni_netconfig_open(ni_syntax_t *syntax)
{
	ni_netconfig_t *nih;

	if (!syntax) {
		ni_error("ni_netconfig_open: syntax is NULL");
		return NULL;
	}

	nih = (ni_netconfig_t *) __ni_handle_new(sizeof(*nih), &ni_netconfig_ops);
	if (nih)
		nih->syntax = syntax;

	return &nih->base;
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
	ni_netconfig_t *nit = __to_netconfig(nih);

	if (nit->syntax)
		ni_syntax_free(nit->syntax);
}

static int
__ni_netonfig_refresh(ni_handle_t *nih)
{
	ni_netconfig_t *nit = __to_netconfig(nih);

	if (nit->syntax == NULL) {
		ni_error("netonfig: cannot refresh, no syntax associated");
		return -1;
	}
	return ni_syntax_get_interfaces(nit->syntax, nih);
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
	ni_netconfig_t *nit = __to_netconfig(nih);
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
	return ni_syntax_put_interfaces(nit->syntax, nih, NULL);
}

/*
 * Delete an interface.
 */
static int
__ni_netconfig_interface_delete(ni_handle_t *nih, const char *ifname)
{
	ni_netconfig_t *nit = __to_netconfig(nih);
	ni_interface_t *ifp;

	ifp = ni_interface_by_name(nih, ifname);
	if (!ifp) {
		ni_error("netconfig: cannot delete interface %s - not found", ifname);
		return -1;
	}
	ifp->deleted = 1;

	/* write back changes */
	return ni_syntax_put_interfaces(nit->syntax, nih, NULL);
}

/*
 * Read/write /etc/HOSTNAME
 * We should allow runtime configuration to change the location of the
 * file, and to specify an "updater" script that can be called to rewrite
 * other depedencies (eg if we have a special entry in the hosts file,
 * or httpd.conf, or whatever)
 */
static int
__ni_netconfig_hostname_put(ni_handle_t *nih, const char *hostname)
{
	FILE *fp;

	if ((fp = fopen(_PATH_HOSTNAME, "w")) == NULL) {
		ni_error("cannot open %s: %m", _PATH_HOSTNAME);
		return -1;
	}
	fprintf(fp, "%s\n", hostname);
	fclose(fp);
	return 0;
}

static int
__ni_netconfig_hostname_get(ni_handle_t *nih, char *buffer, size_t size)
{
	FILE *fp;
	int rv = 0;

	if ((fp = fopen(_PATH_HOSTNAME, "r")) == NULL) {
		ni_error("cannot open %s: %m", _PATH_HOSTNAME);
		return -1;
	}

	if (fgets(buffer, size, fp) == NULL) {
		rv = -1;
	} else {
		/* strip off trailing newline */
		buffer[strcspn(buffer, "\r\n")] = '\0';
	}
	fclose(fp);
	return rv;
}
