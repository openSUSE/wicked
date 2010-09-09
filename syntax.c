/*
 * Handle abstract syntax objects.
 * Should possibly move to netinfo.c
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "netinfo_priv.h"
#include "xml.h"

ni_syntax_t *
ni_syntax_new(const char *schema, const char *base_path)
{
	/* Make this a compile time option */
	if (!schema) {
		if (ni_file_exists("/etc/SuSE-release"))
			schema = "suse";
		else if (ni_file_exists("/etc/redhat-release"))
			schema = "redhat";
		else {
			ni_error("Unable to determine default schema");
			return NULL;
		}
	}

	if (!strcasecmp(schema, "suse"))
		return __ni_syntax_sysconfig_suse(base_path);
	if (!strcasecmp(schema, "redhat"))
		return __ni_syntax_sysconfig_redhat(base_path);
	if (!strcasecmp(schema, "netcf"))
		return __ni_syntax_netcf(base_path);
	if (!strcasecmp(schema, "netcf-strict"))
		return __ni_syntax_netcf_strict(base_path);

	ni_error("schema \"%s\" not supported", schema);
	return NULL;
}

void
ni_syntax_free(ni_syntax_t *syntax)
{
	free(syntax->base_path);
	free(syntax);
}

int
ni_syntax_parse_all(ni_syntax_t *syntax, ni_handle_t *nih)
{
	if (syntax->parse_all)
		return syntax->parse_all(syntax, nih);

	return ni_syntax_parse_file(syntax, nih, syntax->base_path);

	error("%s: syntax not capable of writing a single interface", __FUNCTION__);
	return -1;
}

int
ni_syntax_parse_data(ni_syntax_t *syntax, ni_handle_t *nih, const char *data)
{
	FILE *memstream;
	int rv = -1;

	memstream = fmemopen((void *) data, strlen(data), "r");
	if (memstream == NULL) {
		error("Unable to open memstream for data: %m");
	} else {
		rv = ni_syntax_parse_stream(syntax, nih, memstream);
		fclose(memstream);
	}

	return rv;
}

int
ni_syntax_parse_file(ni_syntax_t *syntax, ni_handle_t *nih, const char *filename)
{
	if (syntax->parse_all_from_file)
		return syntax->parse_all_from_file(syntax, nih, filename);

	if (syntax->xml_to_interface) {
		xml_document_t *doc;
		int rv;

		if (!(doc = xml_document_read(filename))) {
			error("%s: unable to parse XML document %s", __FUNCTION__, filename);
			return -1;
		}

		rv = ni_syntax_xml_to_all(syntax, nih, doc);

		xml_document_free(doc);
		return rv;
	}

	error("%s: syntax not capable of parsing config data", __FUNCTION__);
	return -1;
}

int
ni_syntax_parse_stream(ni_syntax_t *syntax, ni_handle_t *nih, FILE *input)
{
	if (syntax->parse_all_from_stream)
		return syntax->parse_all_from_stream(syntax, nih, input);

	if (syntax->xml_to_interface) {
		xml_document_t *doc;
		int rv;

		if (!(doc = xml_document_scan(input))) {
			error("%s: unable to parse XML document", __FUNCTION__);
			return -1;
		}

		rv = ni_syntax_xml_to_all(syntax, nih, doc);

		xml_document_free(doc);
		return rv;
	}

	error("%s: syntax not capable of parsing config data", __FUNCTION__);
	return -1;
}


int
ni_syntax_format_all(ni_syntax_t *syntax, ni_handle_t *nih, FILE *outfile)
{
	if (syntax->format_all)
		return syntax->format_all(syntax, nih, outfile);

	if (syntax->xml_from_interface) {
		xml_document_t *doc;
		int rv = -1;

		doc = ni_syntax_xml_from_all(syntax, nih);
		if (!doc) {
			error("%s: problem building XML from ni_handle", syntax->schema);
			return -1;
		}

		if (outfile) {
			rv = xml_document_print(doc, outfile);
		} else
		if (!syntax->base_path || !strcmp(syntax->base_path, "-")) {
			rv = xml_document_print(doc, stdout);
		} else {
			char filename[PATH_MAX];

			/* FIXME: create temp file, and use separate commit at
			 * a later point to rename it to final destination.
			 * This allows atomic updates and rollback */
			snprintf(filename, sizeof(filename), "%s/all.xml",
					syntax->base_path);

			rv = xml_document_write(doc, filename);
		}

		xml_document_free(doc);
		return rv;
	}

	error("%s: syntax not capable of writing global config", __FUNCTION__);
	return -1;
}

int
ni_syntax_format_interface(ni_syntax_t *syntax, ni_handle_t *nih, ni_interface_t *ifp, FILE *outfile)
{
	if (syntax->format_interface)
		return syntax->format_interface(syntax, nih, ifp, outfile);

	if (syntax->xml_from_interface) {
		xml_document_t *doc;
		int rv = -1;

		doc = xml_document_new();

		if (!syntax->xml_from_interface(syntax, nih, ifp, doc->root))
			goto error;

		if (outfile) {
			rv = xml_document_print(doc, outfile);
		} else
		if (!syntax->base_path || !strcmp(syntax->base_path, "-")) {
			rv = xml_document_print(doc, stdout);
		} else {
			char filename[PATH_MAX];

			/* FIXME: create temp file, and use separate commit at
			 * a later point to rename it to final destination.
			 * This allows atomic updates and rollback */
			snprintf(filename, sizeof(filename), "%s/%s.xml",
					syntax->base_path,
					ifp->name);

			rv = xml_document_write(doc, filename);
		}

error:
		xml_document_free(doc);
		return rv;
	}

	error("%s: syntax not capable of writing a single interface", __FUNCTION__);
	return -1;
}

/*
 * Produce XML for a single interface and vice versa
 */
xml_node_t *
ni_syntax_xml_from_interface(ni_syntax_t *syntax, ni_handle_t *nih, ni_interface_t *ifp)
{
	if (!syntax->xml_from_interface) {
		error("%s: syntax not capable of creating xml for interface", __FUNCTION__);
		return NULL;
	}
	return syntax->xml_from_interface(syntax, nih, ifp, NULL);
}

ni_interface_t *
ni_syntax_xml_to_interface(ni_syntax_t *syntax, ni_handle_t *nih, xml_node_t *xmlnode)
{
	if (!syntax->xml_to_interface) {
		error("%s: syntax not capable of creating interface from xml", __FUNCTION__);
		return NULL;
	}
	return syntax->xml_to_interface(syntax, nih, xmlnode);
}

/*
 * Produce XML for all interfaces
 */
xml_document_t *
ni_syntax_xml_from_all(ni_syntax_t *syntax, ni_handle_t *nih)
{
	xml_document_t *doc = NULL;
	xml_node_t *root;
	ni_interface_t *ifp;

	if (!syntax->xml_from_interface) {
		error("%s: syntax not capable of creating xml for interface", __FUNCTION__);
		return NULL;
	}

	doc = xml_document_new();
	root = xml_document_root(doc);

	/* Produce all interfaces */
	for (ifp = nih->iflist; ifp; ifp = ifp->next) {
		if (syntax->xml_from_interface(syntax, nih, ifp, root) == NULL)
			goto error;
	}

	return doc;

error:
	if (doc)
		xml_document_free(doc);
	return NULL;
}

/*
 * Produce interfaces from XML
 */
int
ni_syntax_xml_to_all(ni_syntax_t *syntax, ni_handle_t *nih, xml_document_t *doc)
{
	xml_node_t *root, *child;

	if (!syntax->xml_to_interface) {
		error("%s: syntax not capable of creating interface from xml", __FUNCTION__);
		return -1;
	}

	if (!doc)
		return -1;

	root = xml_document_root(doc);
	for (child = root->children; child; child = child->next) {
		if (strcmp(child->name, "interface"))
			continue;

		if (syntax->xml_to_interface(syntax, nih, child) < 0) {
			error("%s: failed to parse configuration data", __FUNCTION__);
			return -1;
		}
	}

	return 0;
}
