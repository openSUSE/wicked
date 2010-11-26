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

#define XML_ERR_PTR	((xml_node_t *) -1)
#define XML_IS_ERR(p)	((p) == XML_ERR_PTR)

static int	__ni_indirect_refresh_all(ni_handle_t *);
static int	__ni_indirect_interface_refresh_one(ni_handle_t *, const char *);
static int	__ni_indirect_interface_configure(ni_handle_t *, ni_interface_t *, const ni_interface_t *);
static int	__ni_indirect_interface_delete(ni_handle_t *, const char *);
static int	__ni_indirect_policy_update(ni_handle_t *, const ni_policy_t *);
static void	__ni_indirect_close(ni_handle_t *nih);

static struct ni_ops ni_indirect_ops = {
	.refresh		= __ni_indirect_refresh_all,
	.interface_refresh_one	= __ni_indirect_interface_refresh_one,
	.configure_interface	= __ni_indirect_interface_configure,
	.delete_interface	= __ni_indirect_interface_delete,
	.policy_update		= __ni_indirect_policy_update,
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
 * Execute a remote call
 */
static xml_node_t *
__ni_indirect_vcall(ni_handle_t *nih, ni_rest_op_t rop, const xml_node_t *args, const char *fmt, ...)
{
	xml_node_t *result = XML_ERR_PTR;
	ni_indirect_t *nid = __to_indirect(nih);
	ni_wicked_request_t req;
	char pathbuf[256];
	unsigned int len;
	va_list ap;

	snprintf(pathbuf, sizeof(pathbuf), "%s/", nid->namespace);
	len = strlen(pathbuf);

	va_start(ap, fmt);
	vsnprintf(pathbuf + len, sizeof(pathbuf) - len, fmt, ap);
	va_end(ap);

	__ni_indirect_build_request(nid, &req, rop, pathbuf);
	req.xml_in = args;

	if (ni_wicked_call_indirect(&req) < 0) {
		ni_error("wicked server returned error: %s", req.error_msg);
	} else {
		result = req.xml_out;
		req.xml_out = NULL;
	}

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

	result = __ni_indirect_vcall(nih, NI_REST_OP_GET, NULL, "interface");
	if (XML_IS_ERR(result))
		goto out;
	if (result == NULL) {
		ni_error("wicked server returned no information");
		goto out;
	}

	syntax = ni_default_xml_syntax();
	if (!syntax)
		goto out;

	rv = __ni_syntax_xml_to_all(syntax, nih, result);

out:
	if (result && !XML_IS_ERR(result))
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

	result = __ni_indirect_vcall(nih, NI_REST_OP_GET, NULL, "interface/%s", ifname);
	if (XML_IS_ERR(result))
		goto out;
	if (result == NULL) {
		ni_error("wicked server returned no information");
		goto out;
	}

	if (result->name == NULL && result->children)
		result = result->children;

	syntax = ni_default_xml_syntax();
	if (!syntax)
		goto out;

	ifp = ni_syntax_xml_to_interface(syntax, nih, result);
	if (ifp == NULL) {
		ni_error("failed to parse interface xml");
		goto out;
	}

	rv = 0;

out:
	if (result && !XML_IS_ERR(result))
		xml_node_free(result);
	return rv;
}

int
__ni_indirect_interface_configure(ni_handle_t *nih,
				ni_interface_t *change_if,
				const ni_interface_t *ifp)
{
	ni_syntax_t *syntax = NULL;
	xml_node_t *xml = NULL, *result = NULL;
	int rv = -1;

	syntax = ni_default_xml_syntax();
	if (!syntax)
		goto failed;

	xml = ni_syntax_xml_from_interface(syntax, nih, ifp);
	if (!xml)
		goto failed;

	result = __ni_indirect_vcall(nih, NI_REST_OP_PUT, xml, "interface/%s", ifp->name);
	if (XML_IS_ERR(result)) {
		ni_error("unable to configure %s", ifp->name);
		goto failed;
	}

	/* If we received XML data from server, update cached interface desc */
	if (result != NULL) {
		xml_node_t *response = result;
		ni_interface_t **pos, *rover;

		if (response->name == NULL && response->children)
			response = response->children;

		for (pos = &nih->iflist; (rover = *pos) != NULL; pos = &rover->next) {
			if (change_if && change_if != rover)
				continue;
			if (ni_string_eq(ifp->name, rover->name)) {
				*pos = rover->next;
				ni_interface_put(rover);
				break;
			}
		}

		ifp = ni_syntax_xml_to_interface(syntax, nih, response);
		if (ifp < 0) {
			ni_error("failed to parse server xml");
			rv = -1;
		}
	}
	rv = 0;

out:
	if (xml)
		xml_node_free(xml);
	if (result && !XML_IS_ERR(result))
		xml_node_free(result);
	return rv;

failed:
	rv = -1;
	goto out;
}

int
__ni_indirect_interface_delete(ni_handle_t *nih, const char *name)
{
	xml_node_t *result;

	result = __ni_indirect_vcall(nih, NI_REST_OP_DELETE, NULL, "interface/%s", name);
	if (XML_IS_ERR(result)) {
		ni_error("unable to delete %s", name);
		return -1;
	}

	if (result)
		xml_node_free(result);
	return 0;
}

static int
__ni_indirect_policy_update(ni_handle_t *nih, const ni_policy_t *new_policy)
{
	ni_policy_info_t policy_info = { NULL };
	xml_node_t *args, *result;
	int rv = -1;

	ni_policy_info_append(&policy_info, __ni_policy_clone(new_policy));
	args = __ni_syntax_xml_from_policy_info(ni_default_xml_syntax(), &policy_info);
	ni_policy_info_destroy(&policy_info);

	if (!args)
		return -1;

	result = __ni_indirect_vcall(nih, NI_REST_OP_POST, args, "policy");
	if (XML_IS_ERR(result)) {
		ni_error("unable to post policy");
		goto out;
	}

	if (result)
		xml_node_free(result);
	rv = 0;

out:
	if (args)
		xml_node_free(args);
	return rv;
}
