/*
 * Routines for accessing interface state through the wicked server
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>

#include <wicked/xml.h>
#include <wicked/wicked.h>
#include "netinfo_priv.h"
#include "config.h"

static int	__ni_indirect_refresh_all(ni_handle_t *);
static int	__ni_indirect_interface_refresh_one(ni_handle_t *, const char *);
static int	__ni_indirect_interface_configure(ni_handle_t *,
				ni_interface_t *, xml_node_t *);
static int	__ni_indirect_interface_delete(ni_handle_t *, const char *);
static void	__ni_indirect_close(ni_handle_t *nih);

static struct ni_ops ni_indirect_ops = {
	.refresh		= __ni_indirect_refresh_all,
	.interface_refresh_one	= __ni_indirect_interface_refresh_one,
	.configure_interface	= __ni_indirect_interface_configure,
	.delete_interface	= __ni_indirect_interface_delete,
	.close			= __ni_indirect_close,
};

typedef struct ni_indirect {
	ni_handle_t		base;
	char *			namespace;
	char *			root_dir;
} ni_indirect_t;

static inline ni_indirect_t *
__to_indirect(ni_handle_t *nih)
{
	assert(nih->op == &ni_indirect_ops);
	return (ni_indirect_t *) nih;
}

ni_handle_t *
ni_indirect_open(const char *basepath)
{
	ni_indirect_t *nih;

	if (!basepath)
		return NULL;

	nih = (ni_indirect_t *) __ni_handle_new(sizeof(*nih), &ni_indirect_ops);
	ni_string_dup(&nih->namespace, basepath);

	return &nih->base;
}

void
ni_indirect_set_root(ni_handle_t *nih, const char *root_dir)
{
	ni_indirect_t *nid = __to_indirect(nih);

	ni_string_dup(&nid->root_dir, root_dir);
}

static void
__ni_indirect_close(ni_handle_t *nih)
{
	ni_indirect_t *nid = __to_indirect(nih);

	ni_string_free(&nid->namespace);
	ni_string_free(&nid->root_dir);
}

/*
 * Construct a wicked request.
 */
static void
__ni_indirect_build_request(ni_indirect_t *nid, ni_wicked_request_t *req,
			int rest_op, const char *path)
{
	ni_wicked_request_init(req);

	req->cmd = rest_op;
	if (nid->root_dir)
		ni_wicked_request_add_option(req, "root", nid->root_dir);
	ni_string_dup(&req->path, path);
}

/*
 * Execute a GET call
 */
static xml_node_t *
__ni_indirect_get(ni_handle_t *nih, const char *fmt, ...)
{
	xml_node_t *result = NULL;
	ni_indirect_t *nid = __to_indirect(nih);
	ni_wicked_request_t req;
	char pathbuf[256];
	va_list ap;

	{
		unsigned int len;

		snprintf(pathbuf, sizeof(pathbuf), "%s/", nid->namespace);
		len = strlen(pathbuf);

		va_start(ap, fmt);
		vsnprintf(pathbuf + len, sizeof(pathbuf) - len, fmt, ap);
		va_end(ap);
	}

	__ni_indirect_build_request(nid, &req, NI_REST_OP_GET, pathbuf);

	if (ni_wicked_call_indirect(&req) < 0) {
		ni_error("wicked server returned error: %s", req.error_msg);
		goto out;
	}
	if ((result = req.xml_out) == NULL) {
		ni_error("wicked server returned no information");
		goto out;
	}
	req.xml_out = NULL;

out:
	ni_wicked_request_destroy(&req);
	return result;
}

/*
 * Refresh all interfaces
 */
int
__ni_indirect_refresh_all(ni_handle_t *nih)
{
	ni_syntax_t *syntax = NULL;
	xml_node_t *result;
	int rv = -1;

	__ni_interfaces_clear(nih);

	result = __ni_indirect_get(nih, "interface");
	if (result == NULL)
		goto out;

	syntax = ni_default_xml_syntax();
	if (!syntax)
		goto out;

	rv = __ni_syntax_xml_to_all(syntax, nih, result);

out:
	if (result)
		xml_node_free(result);
	return rv;
}

/*
 * Refresh one interface
 */
int
__ni_indirect_interface_refresh_one(ni_handle_t *nih, const char *ifname)
{
	ni_syntax_t *syntax = NULL;
	ni_interface_t *ifp, **pos;
	xml_node_t *result;
	int rv = -1;

	for (pos = &nih->iflist; (ifp = *pos) != NULL; pos = &ifp->next) {
		if (!strcmp(ifp->name, ifname)) {
			*pos = ifp->next;
			ni_interface_put(ifp);
			break;
		}
	}

	result = __ni_indirect_get(nih, "interface/%s", ifname);
	if (result == NULL)
		goto out;

	syntax = ni_default_xml_syntax();
	if (!syntax)
		goto out;

	ifp = ni_syntax_xml_to_interface(syntax, nih, result);
	if (ifp == NULL) {
		ni_error("failed to parse interface xml");
		goto out;
	}

	ifp->next = *pos;
	*pos = ifp;

out:
	if (result)
		xml_node_free(result);
	return rv;
}

int
__ni_indirect_interface_configure(ni_handle_t *nih,
				ni_interface_t *ifp, xml_node_t *xml)
{
	ni_indirect_t *nid = __to_indirect(nih);
	ni_wicked_request_t req;
	char pathbuf[64];
	ni_syntax_t *syntax = NULL;
	int xml_is_temp = 0;
	int rv;

	syntax = ni_default_xml_syntax();
	if (!syntax)
		goto failed;

	if (xml == NULL) {
		xml = ni_syntax_xml_from_interface(syntax, nih, ifp);
		if (!xml)
			goto failed;

		xml_is_temp = 1;
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/interface/%s", nid->namespace, ifp->name);
	__ni_indirect_build_request(nid, &req, NI_REST_OP_PUT, pathbuf);
	req.xml_in = xml;

	rv = ni_wicked_call_indirect(&req);
	if (rv < 0) {
		ni_error("unable to configure %s, server responds: %s", ifp->name, req.error_msg);
		goto out;
	}

	/* If we received XML data from server, update cached interface desc */
	if (req.xml_out != NULL) {
		ni_interface_t **pos;

		for (pos = &nih->iflist; *pos; pos = &(*pos)->next) {
			if (*pos == ifp) {
				*pos = ifp->next;
				ni_interface_put(ifp);
				break;
			}
		}

		ifp = ni_syntax_xml_to_interface(syntax, nih, req.xml_out);
		if (ifp < 0) {
			ni_error("failed to parse server xml");
			rv = -1;
		}
	}

out:
	if (xml_is_temp)
		xml_node_free(xml);
	ni_wicked_request_destroy(&req);
	return rv;

failed:
	rv = -1;
	goto out;
}

int
__ni_indirect_interface_delete(ni_handle_t *nih, const char *name)
{
	ni_indirect_t *nid = __to_indirect(nih);
	ni_wicked_request_t req;
	char pathbuf[64];
	int rv;

	snprintf(pathbuf, sizeof(pathbuf), "%s/interface/%s", nid->namespace, name);
	__ni_indirect_build_request(nid, &req, NI_REST_OP_DELETE, pathbuf);

	rv = ni_wicked_call_indirect(&req);
	ni_wicked_request_destroy(&req);
	return rv;
}
