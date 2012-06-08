/*
 *	VERY limited XML read/write implementation
 *	This basically parses tags, attributes and CDATA, and that's
 *	just about it.
 *
 *	Copyright (C) 2009-2012  Olaf Kirch <okir@suse.de>
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
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write 
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, 
 *	Boston, MA 02110-1301 USA.
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

struct xml_location_shared {
	unsigned int		refcount;
	char *			filename;
};

struct xml_location {
	struct xml_location_shared *shared;
	unsigned int		line;
};

struct xml_node {
	struct xml_node *	next;
	unsigned int		refcount;

	char *			name;
	struct xml_node *	parent;

	/* For now, we assume just a single blob of cdata */
	char *			cdata;

	ni_var_array_t		attrs;
	struct xml_node *	children;

	struct xml_location *	location;
};

extern xml_document_t *	xml_document_read(const char *);
extern xml_document_t *	xml_document_scan(FILE *);
extern int		xml_document_write(const xml_document_t *, const char *);
extern int		xml_document_print(const xml_document_t *, FILE *fp);
extern const char *	xml_document_dtd(const xml_document_t *);

extern xml_document_t *	xml_document_new();
extern xml_node_t *	xml_document_root(xml_document_t *);
extern void		xml_document_set_root(xml_document_t *, xml_node_t *);
extern xml_node_t *	xml_document_take_root(xml_document_t *);
extern void		xml_document_free(xml_document_t *);

extern xml_node_t *	xml_node_new(const char *ident, xml_node_t *);
extern xml_node_t *	xml_node_new_element(const char *ident, xml_node_t *, const char *cdata);
extern xml_node_t *	xml_node_clone(const xml_node_t *src, xml_node_t *parent);
extern void		xml_node_free(xml_node_t *);
extern int		xml_node_print(const xml_node_t *, FILE *fp);
extern int		xml_node_print_fn(const xml_node_t *, void (*)(const char *, void *), void *);
extern xml_node_t *	xml_node_scan(FILE *fp);
extern void		xml_node_set_cdata(xml_node_t *, const char *);
extern void		xml_node_add_attr(xml_node_t *, const char *, const char *);
extern void		xml_node_add_attr_uint(xml_node_t *, const char *, unsigned int);
extern void		xml_node_add_attr_ulong(xml_node_t *, const char *, unsigned long);
extern void		xml_node_add_attr_double(xml_node_t *, const char *, double);

extern int		xml_node_has_attr(const xml_node_t *, const char *);
extern const char *	xml_node_get_attr(const xml_node_t *, const char *);
extern int		xml_node_get_attr_uint(const xml_node_t *, const char *, unsigned int *);
extern int		xml_node_get_attr_ulong(const xml_node_t *, const char *, unsigned long *);
extern int		xml_node_get_attr_double(const xml_node_t *, const char *, double *);
extern xml_node_t *	xml_node_get_child(const xml_node_t *, const char *);
extern xml_node_t *	xml_node_get_child_with_attrs(const xml_node_t *, const char *,
					const ni_var_array_t *);
extern int		xml_node_replace_child(xml_node_t *, xml_node_t *);
extern int		xml_node_delete_child(xml_node_t *, const char *);
extern int		xml_node_delete_child_node(xml_node_t *, xml_node_t *);
extern void		xml_node_detach(xml_node_t *);
extern void		xml_node_reparent(xml_node_t *parent, xml_node_t *child);
extern void		xml_node_add_child(xml_node_t *, xml_node_t *);
extern xml_node_t *	xml_node_get_next_named(xml_node_t *, const char *, xml_node_t *);

extern int		xml_node_match_attrs(const xml_node_t *, const ni_var_array_t *);

extern const char *	xml_node_location(const xml_node_t *);
extern void		xml_location_free(struct xml_location *);


#endif /* __WICKED_XML_H__ */
