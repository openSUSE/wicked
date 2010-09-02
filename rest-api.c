/*
 * No REST for the wicked!
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <sys/poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include "netinfo.h"
#include "logging.h"
#include "wicked.h"
#include "xml.h"
#include "xpath.h"

int
ni_rest_request_process(ni_wicked_request_t *req, const char *cmd, const char *path)
{
	ni_rest_node_t *node;
	int fn;

	ni_debug_wicked("Processing REST request %s \"%s\"", cmd, path);
	if (!strcasecmp(cmd, "get")) {
		fn = NI_REST_OP_GET;
	} else
	if (!strcasecmp(cmd, "put")) {
		fn = NI_REST_OP_PUT;
	} else
	if (!strcasecmp(cmd, "post")) {
		fn = NI_REST_OP_POST;
	} else
	if (!strcasecmp(cmd, "delete")) {
		fn = NI_REST_OP_DELETE;
	} else {
		werror(req, "unknown command \"%s\"", cmd);
		return -1;
	}

	node = ni_rest_node_lookup(path, (const char **) &path);
	if (!node) {
		werror(req, "unknown path \"%s\"", path);
		return -1;
	}

	if (node->ops.fn[fn] == NULL) {
		werror(req, "%s command not supported for this path", cmd);
		return -1;
	}

	return node->ops.fn[fn](path, req);
}

static ni_handle_t *
system_handle(ni_wicked_request_t *req)
{
	ni_handle_t *nih;

	nih = ni_state_open();
	if (nih == NULL) {
		werror(req, "unable to obtain netinfo handle");
		return NULL;
	}
	if (ni_refresh(nih) < 0) {
		werror(req, "cannot refresh interface list!");
		ni_close(nih);
		return NULL;
	}

	return nih;
}

static ni_handle_t *
config_handle(ni_wicked_request_t *req)
{
	ni_handle_t *nih;

	nih = ni_netconfig_open(ni_syntax_new(NULL, NULL));
	if (nih == NULL) {
		werror(req, "unable to obtain netinfo handle");
		return NULL;
	}
	if (ni_refresh(nih) < 0) {
		werror(req, "cannot refresh interface list!");
		ni_close(nih);
		return NULL;
	}

	return nih;
}

static int
generic_interface_response(ni_handle_t *nih, ni_interface_t *ifp, ni_wicked_request_t *req)
{
	ni_syntax_t *xmlsyntax = ni_default_xml_syntax();

	if (ifp == NULL) {
		req->xml_out = ni_syntax_xml_from_all(xmlsyntax, nih);
	} else {
		xml_node_t *result;

		result = ni_syntax_xml_from_interface(xmlsyntax, nih, ifp);
		if (result) {
			req->xml_out = xml_document_new();
			xml_document_set_root(req->xml_out, result);
		}
	}

	if (req->xml_out == NULL) {
		werror(req, "cannot render interface information");
		return -1;
	}

	return 0;
}

static int
generic_interface_get(ni_handle_t *nih, const char *path, ni_wicked_request_t *req)
{
	ni_interface_t *ifp = NULL;

	if (nih == NULL)
		return -1;

	if (path != NULL) {
		/* select interface and display only that */
		if (!(ifp = ni_interface_by_name(nih, path))) {
			werror(req, "interface %s not known", path);
			return -1;
		}
	}

	return generic_interface_response(nih, ifp, req);
}

static int
system_interface_get(const char *path, ni_wicked_request_t *req)
{
	return generic_interface_get(system_handle(req), path, req);
}

static int
config_interface_get(const char *path, ni_wicked_request_t *req)
{
	return generic_interface_get(config_handle(req), path, req);
}

static int
generic_interface_put(ni_handle_t *nih, const char *ifname, ni_wicked_request_t *req)
{
	ni_interface_t *ifp = NULL;
	ni_handle_t *cnih = NULL;
	xml_node_t *cfg_xml;
	int rv = -1;

	if (nih == NULL)
		return -1;

	if (ifname == NULL) {
		werror(req, "no interface name given");
		return -1;
	}

	cnih = ni_netconfig_open(NULL);
	if (cnih == NULL) {
		werror(req, "unable to create config handle");
		goto failed;
	}

	if (ni_syntax_xml_to_all(ni_default_xml_syntax(), cnih, req->xml_in) < 0) {
		werror(req, "unable to parse interface configuration");
		goto failed;
	}

	if (!(ifp = ni_interface_by_name(cnih, ifname))) {
		werror(req, "cannot find configuration for interface %s", ifname);
		goto failed;
	}

	/* Find the XML intrface element - we want to pass it to the configure
	 * routine. This helps us write flexible extensions */
	for (cfg_xml = req->xml_in->root->children; cfg_xml; cfg_xml = cfg_xml->next) {
		const char *name;

		if (strcmp(cfg_xml->name, "interface"))
			continue;
		if ((name = xml_node_get_attr(cfg_xml, "name")) && !strcmp(name, ifname))
			break;
	}
	if (cfg_xml == NULL) {
		werror(req, "surprising, found interface %s but no xml?!", ifname);
		goto failed;
	}

	if (ni_interface_configure(nih, ifp, cfg_xml) < 0) {
		werror(req, "error configuring interface %s", ifname);
		goto failed;
	}

	if (!(ifp = ni_interface_by_name(nih, ifname))) {
		werror(req, "cannot find current status for interface %s", ifname);
		goto failed;
	}

	rv = generic_interface_response(nih, ifp, req);

failed:
	if (cnih)
		ni_close(cnih);
	return rv;
}

static int
system_interface_put(const char *path, ni_wicked_request_t *req)
{
	return generic_interface_put(system_handle(req), path, req);
}

static int
config_interface_put(const char *path, ni_wicked_request_t *req)
{
	return generic_interface_put(config_handle(req), path, req);
}

static int
generic_interface_delete(ni_handle_t *nih, const char *ifname, ni_wicked_request_t *req)
{
	if (nih == NULL)
		return -1;

	if (ifname == NULL) {
		werror(req, "DELETE: no interface name given");
		return -1;
	}

	if (ni_interface_delete(nih, ifname) < 0) {
		werror(req, "unable to delete %s", ifname);
		return -1;
	}

	return 0;
}

static int
system_interface_delete(const char *path, ni_wicked_request_t *req)
{
	return generic_interface_delete(system_handle(req), path, req);
}

static int
config_interface_delete(const char *path, ni_wicked_request_t *req)
{
	return generic_interface_delete(config_handle(req), path, req);
}

static ni_rest_node_t	ni_rest_system_interface_node = {
	.name		= "interface",
	.ops = {
	    .byname = {
		.get	= system_interface_get,
		.put	= system_interface_put,
		.delete	= system_interface_delete,
	    },
	},
};

static ni_rest_node_t	ni_rest_config_interface_node = {
	.name		= "interface",
	.ops = {
	    .byname = {
		.get	= config_interface_get,
		.put	= config_interface_put,
		.delete	= config_interface_delete,
	    },
	},
};

static int
system_hostname_get(const char *path, ni_wicked_request_t *req)
{
	char hostname[256];
	xml_node_t *hnode;

	if (path && *path) {
		werror(req, "excess elements in path");
		return 0;
	}

	if (gethostname(hostname, sizeof(hostname)) < 0) {
		werror(req, "error getting hostname");
		return 0;
	}

	req->xml_out = xml_document_new();
	hnode = xml_node_new("hostname", xml_document_root(req->xml_out));
	xml_node_set_cdata(hnode, hostname);

	return 0;
}


static ni_rest_node_t	ni_rest_system_hostname_node = {
	.name		= "hostname",
	.ops = {
	    .byname = {
		.get	= system_hostname_get,
		//.put	= system_hostname_put,
	    },
	},
};

static ni_rest_node_t	ni_rest_system_node = {
	.name		= "system",
	.children = {
		&ni_rest_system_interface_node,
		&ni_rest_system_hostname_node,
	},
};

static ni_rest_node_t	ni_rest_config_node = {
	.name		= "config",
	.children = {
		&ni_rest_config_interface_node,
	},
};

static ni_rest_node_t	ni_rest_root_node = {
	.name		= "/",
	.children = {
		&ni_rest_config_node,
		&ni_rest_system_node,
	},
};

static ni_rest_node_t *
ni_rest_node_find_child(ni_rest_node_t *node, const char *name)
{
	unsigned int i;

	for (i = 0; i < __NI_REST_CHILD_MAX; ++i) {
		ni_rest_node_t *child = node->children[i];

		if (child == NULL)
			break;
		if (!strcmp(child->name, name))
			return child;
	}
	return NULL;
}

ni_rest_node_t *
ni_rest_node_lookup(const char *path, const char **remainder)
{
	ni_rest_node_t *node = &ni_rest_root_node;
	char *copy, *pos;

	copy = pos = strdup(path);
	while (*pos) {
		char *comp;

		while (*pos == '/')
			++pos;
		comp = pos;

		/* No more children; remainder of path is interpreted by node */
		if (node->children[0] == NULL)
			break;

		/* Find end of component, and NUL terminate it */
		pos += strcspn(pos, "/");
		if (*pos)
			*pos++ = '\0';

		node = ni_rest_node_find_child(node, comp);
		if (!node)
			return NULL;
	}

	if (*pos == '\0')
		*remainder = NULL;
	else
		*remainder = path + (pos - copy);
	free(copy);
	return node;
}

void
werror(ni_wicked_request_t *req, const char *fmt, ...)
{
	char buffer[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	ni_string_dup(&req->error_msg, buffer);
	va_end(ap);
}
