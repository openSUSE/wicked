/*
 *	VERY limited XML read/write implementation
 *	This basically parses tags, attributes and CDATA, and that's
 *	just about it.
 *
 *	Copyright (C) 2009, 2010  Olaf Kirch <okir@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include <wicked/xml.h>
#include <wicked/logging.h>
#include "netinfo_priv.h"

typedef struct xml_writer {
	FILE *		file;
	unsigned int	noclose : 1;
	ni_stringbuf_t	buffer;
} xml_writer_t;

static int		xml_writer_open(xml_writer_t *, const char *);
static int		xml_writer_init_file(xml_writer_t *, FILE *);
static int		xml_writer_close(xml_writer_t *);
static int		xml_writer_destroy(xml_writer_t *);
static void		xml_writer_printf(xml_writer_t *, const char *, ...);

static void		xml_document_output(const xml_document_t *, xml_writer_t *);
static void		xml_node_output(const xml_node_t *node, xml_writer_t *, unsigned int indent);
static const char *	xml_escape_quote(const char *);
static const char *	xml_escape_entities(const char *);

int
xml_document_write(const xml_document_t *doc, const char *filename)
{
	xml_writer_t writer;

	if (xml_writer_open(&writer, filename) < 0)
		return -1;

	xml_document_output(doc, &writer);
	return xml_writer_destroy(&writer);
}

int
xml_document_print(const xml_document_t *doc, FILE *fp)
{
	xml_writer_t writer;

	if (xml_writer_init_file(&writer, fp) < 0)
		return -1;

	xml_document_output(doc, &writer);
	return xml_writer_destroy(&writer);
}

void
xml_document_output(const xml_document_t *doc, xml_writer_t *writer)
{
	xml_writer_printf(writer, "<?xml version=\"1.0\" encoding=\"utf8\"?>\n");
	xml_node_output(doc->root, writer, 0);
}

int
xml_node_print(const xml_node_t *node, FILE *fp)
{
	xml_writer_t writer;
	int rv = 0;

	if (xml_writer_init_file(&writer, fp? fp : stdout) >= 0) {
		xml_node_output(node, &writer, 0);
		rv = xml_writer_destroy(&writer);
	}

	return 0;
}

int
xml_node_print_fn(const xml_node_t *node, void (*writefn)(const char *, void *), void *user_data)
{
	char *membuf = NULL;
	size_t memsz = 0;
	FILE *memf;
	int rv;

	memf = open_memstream(&membuf, &memsz);
	rv = xml_node_print(node, memf);
	fclose(memf);

	if (rv >= 0) {
		char *s, *t;

		for (s = membuf; s; s = t) {
			if ((t = strchr(s, '\n')) != NULL)
				*t++ = '\0';
			writefn(s, user_data);
		}
	}

	free(membuf);
	return rv;
}

void
xml_node_output(const xml_node_t *node, xml_writer_t *writer, unsigned int indent)
{
	unsigned int child_indent = indent;
	int newline = 0;

	if (node->name != NULL) {
		ni_var_t *attr;
		unsigned int i;

		xml_writer_printf(writer, "%*.*s<%s", indent, indent, "", node->name);
		for (i = 0, attr = node->attrs.data; i < node->attrs.count; ++i, ++attr) {
			if (attr->value)
				xml_writer_printf(writer, " %s=\"%s\"",
						attr->name, xml_escape_quote(attr->value));
			else
				xml_writer_printf(writer, " %s", attr->name);
		}

		if (node->cdata == NULL && node->children == NULL) {
			xml_writer_printf(writer, "/>\n");
			return;
		}
		xml_writer_printf(writer, ">");
		child_indent += 2;
	} else {
		newline = 1;
	}

	if (node->cdata) {
		unsigned int len;

		if (strchr(node->cdata, '\n')) {
			xml_writer_printf(writer, "\n");
			newline = 1;
		}
		xml_writer_printf(writer, "%s", xml_escape_entities(node->cdata));

		if (newline) {
			len = strlen(node->cdata);
			if (len && node->cdata[len-1] != '\n')
				xml_writer_printf(writer, "\n");
		}
	}
	if (node->children) {
		xml_node_t *child;

		if (!newline)
			xml_writer_printf(writer, "\n");
		for (child = node->children; child; child = child->next)
			xml_node_output(child, writer, child_indent);
		newline = 1;
	}

	if (node->name != NULL) {
		if (newline)
			xml_writer_printf(writer, "%*.*s", indent, indent, "");
		xml_writer_printf(writer, "</%s>\n", node->name);
	}
}

const char *
xml_escape_entities(const char *cdata)
{
	return cdata;
}

const char *
xml_escape_quote(const char *string)
{
	return string;
}

/*
 * xml_writer object
 */
int
xml_writer_open(xml_writer_t *writer, const char *filename)
{
	memset(writer, 0, sizeof(*writer));
	writer->file = fopen(filename, "w");
	if (!writer->file) {
		ni_error("xml_writer: cannot open %s for writing: %m", filename);
		return -1;
	}

	return 0;
}

int
xml_writer_init_file(xml_writer_t *writer, FILE *file)
{
	memset(writer, 0, sizeof(*writer));
	writer->file = file;
	writer->noclose = 1;
	return 0;
}

int
xml_writer_close(xml_writer_t *writer)
{
	int rv = 0;

	if (writer->file && ferror(writer->file))
		rv = -1;
	if (writer->file && !writer->noclose) {
		fclose(writer->file);
		writer->file = NULL;
	}
	return rv;
}

int
xml_writer_destroy(xml_writer_t *writer)
{
	ni_stringbuf_destroy(&writer->buffer);
	return xml_writer_close(writer);
}

void
xml_writer_printf(xml_writer_t *writer, const char *fmt, ...)
{
	char temp[256];
	va_list ap;

	va_start(ap, fmt);
	if (writer->file) {
		vfprintf(writer->file, fmt, ap);
	} else {
		vsnprintf(temp, sizeof(temp), fmt, ap);
		ni_stringbuf_puts(&writer->buffer, temp);
	}
	va_end(ap);
}
