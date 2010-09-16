/*
 * Routines for accessing interface state through the wicked server
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wicked/xml.h>
#include <wicked/wicked.h>
#include "netinfo_priv.h"
#include "config.h"

static int	__ni_indirect_refresh_all(ni_handle_t *);
static int	__ni_indirect_interface_configure(ni_handle_t *,
				ni_interface_t *, xml_node_t *);
static int	__ni_indirect_interface_delete(ni_handle_t *, const char *);
static void	__ni_indirect_close(ni_handle_t *nih);

static struct ni_ops ni_indirect_ops = {
	.refresh		= __ni_indirect_refresh_all,
	.configure_interface	= __ni_indirect_interface_configure,
	.delete_interface	= __ni_indirect_interface_delete,
	.close			= __ni_indirect_close,
};

ni_handle_t *
ni_indirect_open(const char *basepath)
{
	ni_handle_t *nih;

	if (!basepath)
		return NULL;

	nih = __ni_handle_new(&ni_indirect_ops);
	ni_string_dup(&nih->indirect_path, basepath);

	return nih;
}

static void
__ni_indirect_close(ni_handle_t *nih)
{
	ni_string_free(&nih->indirect_path);
}

int
__ni_indirect_refresh_all(ni_handle_t *nih)
{
	ni_wicked_request_t req;
	char pathbuf[64];
	ni_syntax_t *syntax = NULL;
	int rv;

	__ni_interfaces_clear(nih);

	ni_wicked_request_init(&req);
	snprintf(pathbuf, sizeof(pathbuf), "%s/interface", nih->indirect_path);
	rv = ni_wicked_call_indirect(&req, "GET", pathbuf);
	if (rv < 0)
		goto out;
	if (req.xml_out == NULL) {
		ni_error("wicked server returned no information");
		goto failed;
	}

	syntax = ni_default_xml_syntax();
	if (!syntax)
		goto failed;

	rv = __ni_syntax_xml_to_all(syntax, nih, req.xml_out);
	if (rv < 0)
		goto failed;

out:
	ni_wicked_request_destroy(&req);
	return rv;

failed:
	rv = -1;
	goto out;
}

int
__ni_indirect_interface_configure(ni_handle_t *nih,
				ni_interface_t *ifp, xml_node_t *xml)
{
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

	ni_wicked_request_init(&req);
	req.xml_in = xml;

	snprintf(pathbuf, sizeof(pathbuf), "%s/interface/%s", nih->indirect_path, ifp->name);
	rv = ni_wicked_call_indirect(&req, "PUT", pathbuf);
	if (rv < 0)
		goto out;

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
	ni_wicked_request_t req;
	char pathbuf[64];
	int rv;

	ni_wicked_request_init(&req);

	snprintf(pathbuf, sizeof(pathbuf), "%s/interface/%s", nih->indirect_path, name);
	rv = ni_wicked_call_indirect(&req, "DELETE", pathbuf);
	ni_wicked_request_destroy(&req);
	return rv;
}
