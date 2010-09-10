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

#ifndef __WICKED_XML_H__
#define __WICKED_XML_H__

#include <stdio.h>
#include <wicked/util.h>
#include <wicked/types.h>

struct xml_document {
	char *			dtd;
	struct xml_node *	root;
};

struct xml_node {
	struct xml_node *	next;

	char *			name;
	struct xml_node *	parent;

	/* For now, we assume just a single blob of cdata */
	char *			cdata;

	ni_var_array_t		attrs;
	struct xml_node *	children;
};

extern xml_document_t *	xml_document_read(const char *);
extern xml_document_t *	xml_document_scan(FILE *);
extern int		xml_document_write(xml_document_t *, const char *);
extern int		xml_document_print(xml_document_t *, FILE *fp);
extern const char *	xml_document_dtd(const xml_document_t *);

extern xml_document_t *	xml_document_new();
extern xml_node_t *	xml_document_root(xml_document_t *);
extern void		xml_document_set_root(xml_document_t *, xml_node_t *);
extern void		xml_document_free(xml_document_t *);

extern xml_node_t *	xml_node_new(const char *ident, xml_node_t *);
extern xml_node_t *	xml_node_clone(const xml_node_t *src, xml_node_t *parent);
extern void		xml_node_free(xml_node_t *);
extern int		xml_node_print(xml_node_t *, FILE *fp);
extern xml_node_t *	xml_node_scan(FILE *fp);
extern void		xml_node_set_cdata(xml_node_t *, const char *);
extern void		xml_node_add_attr(xml_node_t *, const char *, const char *);
extern void		xml_node_add_attr_uint(xml_node_t *, const char *, unsigned int);

extern int		xml_node_has_attr(const xml_node_t *, const char *);
extern const char *	xml_node_get_attr(const xml_node_t *, const char *);
extern int		xml_node_get_attr_uint(const xml_node_t *, const char *, unsigned int *);
extern xml_node_t *	xml_node_get_child(const xml_node_t *, const char *);
extern xml_node_t *	xml_node_get_child_with_attrs(const xml_node_t *, const char *,
					const ni_var_array_t *);
extern int		xml_node_replace_child(xml_node_t *, xml_node_t *);
extern int		xml_node_delete_child(xml_node_t *, const char *);
extern int		xml_node_delete_child_node(xml_node_t *, xml_node_t *);

extern int		xml_node_match_attrs(const xml_node_t *, const ni_var_array_t *);

#endif /* __WICKED_XML_H__ */
