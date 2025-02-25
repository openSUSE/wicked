/*
 *	VERY limited XML read/write implementation
 *	This basically parses tags, attributes and CDATA, and that's
 *	just about it.
 *
 *	Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 *	Copyright (C) 2009-2024 SUSE LLC
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
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef NI_WICKED_XML_H
#define NI_WICKED_XML_H

#include <stdio.h>
#include <wicked/util.h>
#include <wicked/types.h>
#include <wicked/array.h>
#include <wicked/refcount.h>

struct xml_document {
	char *			dtd;
	struct xml_node *	root;
};

ni_declare_ptr_array_struct(xml_document);

#define XML_DOCUMENT_ARRAY_INIT	NI_ARRAY_INIT

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
	ni_refcount_t		refcount;
	uint16_t		final : 1;

	char *			name;
	struct xml_node *	parent;

	/* For now, we assume just a single blob of cdata */
	char *			cdata;

	ni_var_array_t		attrs;
	struct xml_node *	children;

	xml_location_t *	location;
};

ni_declare_ptr_array_type(xml_node);

#define XML_NODE_ARRAY_INIT	NI_ARRAY_INIT

extern xml_document_t *	xml_document_read(const char *);
extern xml_document_t *	xml_document_scan(FILE *, const char *location);
extern xml_document_t *	xml_document_from_buffer(ni_buffer_t *, const char *location);
extern xml_document_t *	xml_document_from_string(const char *, const char *location);
extern int		xml_document_write(const xml_document_t *, const char *);
extern int		xml_document_print(const xml_document_t *, FILE *fp);
extern char *		xml_document_sprint(const xml_document_t *);
extern int		xml_document_hash(const xml_document_t *, ni_hashctx_algo_t, void *, size_t);
extern int		xml_document_uuid(const xml_document_t *, unsigned int, const ni_uuid_t *, ni_uuid_t *);
extern const char *	xml_document_dtd(const xml_document_t *);

extern xml_document_t *	xml_document_new();
extern xml_node_t *	xml_document_root(xml_document_t *);
extern void		xml_document_set_root(xml_document_t *, xml_node_t *);
extern xml_node_t *	xml_document_take_root(xml_document_t *);
extern void		xml_document_free(xml_document_t *);
extern xml_document_t *	xml_document_create(const char *, xml_node_t *);
extern ni_bool_t	xml_document_expand(xml_document_array_t *, xml_document_t *);

extern xml_node_t *	xml_node_new(const char *, xml_node_t *);
extern			ni_declare_refcounted_ref(xml_node);
extern			ni_declare_refcounted_free(xml_node);
extern			ni_declare_refcounted_hold(xml_node);
extern			ni_declare_refcounted_drop(xml_node);
extern			ni_declare_refcounted_move(xml_node);

extern xml_node_t *	xml_node_new_element(const char *ident, xml_node_t *, const char *cdata);
extern xml_node_t *	xml_node_new_element_int(const char *ident, xml_node_t *, int);
extern xml_node_t *	xml_node_new_element_int64(const char *ident, xml_node_t *, int64_t);
extern xml_node_t *	xml_node_new_element_uint(const char *ident, xml_node_t *, unsigned int);
extern xml_node_t *	xml_node_new_element_uint64(const char *ident, xml_node_t *, uint64_t);
extern xml_node_t *	xml_node_new_element_unique(const char *ident, xml_node_t *, const char *cdata);
extern xml_node_t *	xml_node_clone(const xml_node_t *src, xml_node_t *parent);
extern void		xml_node_merge(xml_node_t *, const xml_node_t *);
extern int		xml_node_print(const xml_node_t *, FILE *fp);
extern char *		xml_node_sprint(const xml_node_t *);
extern int		xml_node_hash(const xml_node_t *, ni_hashctx_algo_t, void *md_buffer, size_t md_bufsz);
extern int		xml_node_uuid(const xml_node_t *, unsigned int, const ni_uuid_t *, ni_uuid_t *);
extern int		xml_node_content_uuid(const xml_node_t *, unsigned int, const ni_uuid_t *, ni_uuid_t *);
extern int		xml_node_print_fn(const xml_node_t *, void (*)(const char *, void *), void *);
extern int		xml_node_print_debug(const xml_node_t *, unsigned int facility);
extern void		xml_node_hide_cdata(xml_node_t *, const char * const [], const char *);
extern xml_node_t *	xml_node_scan(FILE *fp, const char *location);
extern ni_bool_t	xml_node_set_cdata(xml_node_t *, const char *);
extern ni_bool_t	xml_node_set_int(xml_node_t *, int);
extern ni_bool_t	xml_node_set_int64(xml_node_t *, int64_t);
extern ni_bool_t	xml_node_set_uint(xml_node_t *, unsigned int);
extern ni_bool_t	xml_node_set_uint64(xml_node_t *, uint64_t);
extern ni_bool_t	xml_node_set_uint_hex(xml_node_t *, unsigned int);
extern ni_bool_t	xml_node_add_attr(xml_node_t *, const char *, const char *);
extern ni_bool_t	xml_node_add_attr_uint(xml_node_t *, const char *, unsigned int);
extern ni_bool_t	xml_node_add_attr_ulong(xml_node_t *, const char *, unsigned long);
extern ni_bool_t	xml_node_add_attr_double(xml_node_t *, const char *, double);

extern ni_bool_t	xml_node_has_attr(const xml_node_t *, const char *);
extern ni_bool_t	xml_node_del_attr(xml_node_t *, const char *);
extern const char *	xml_node_get_attr(const xml_node_t *, const char *);
extern const ni_var_t *	xml_node_get_attr_var(const xml_node_t *, const char *);
extern ni_bool_t	xml_node_get_attr_uint(const xml_node_t *, const char *, unsigned int *);
extern ni_bool_t	xml_node_get_attr_ulong(const xml_node_t *, const char *, unsigned long *);
extern ni_bool_t	xml_node_get_attr_double(const xml_node_t *, const char *, double *);
extern xml_node_t *	xml_node_get_child(const xml_node_t *, const char *);
extern xml_node_t *	xml_node_get_next_child(const xml_node_t *, const char *, const xml_node_t *);
extern const char *	xml_node_get_child_cdata(const xml_node_t *, const char *);
extern xml_node_t *	xml_node_get_child_with_attrs(const xml_node_t *, const char *,
					const ni_var_array_t *);
extern ni_bool_t	xml_node_replace_child(xml_node_t *, xml_node_t *);
extern ni_bool_t	xml_node_delete_child(xml_node_t *, const char *);
extern ni_bool_t	xml_node_delete_child_node(xml_node_t *, xml_node_t *);
extern void		xml_node_detach(xml_node_t *);
extern xml_node_t *	xml_node_find_parent(const xml_node_t *, const char *);
extern void		xml_node_reparent(xml_node_t *parent, xml_node_t *child);
extern void		xml_node_add_child(xml_node_t *, xml_node_t *);
extern xml_node_t *	xml_node_get_next_named(xml_node_t *, const char *, xml_node_t *);

extern ni_bool_t	xml_node_match_attrs(const xml_node_t *, const ni_var_array_t *);

extern const char *	xml_node_get_path(ni_stringbuf_t *, const xml_node_t *, const xml_node_t *);

extern void		xml_location_free(xml_location_t *);
extern xml_location_t *	xml_location_clone(const xml_location_t *);
extern xml_location_t *	xml_location_create(const char *, unsigned int);
extern const char *	xml_node_location_filename(const xml_node_t *);
extern unsigned int	xml_node_location_line(const xml_node_t *);
extern const char *	xml_node_location(const xml_node_t *);
extern void		xml_node_location_set(xml_node_t *, xml_location_t *);
extern void		xml_node_location_modify(xml_node_t *, const char *);
extern void		xml_node_location_relocate(xml_node_t *, const char *);

extern xml_node_t*	xml_node_create(xml_node_t *, const char *);
extern void		xml_node_dict_set(xml_node_t *, const char *, const char *);

/*
 * Static inline functions
 */
static inline ni_bool_t
xml_node_is_empty(const xml_node_t *node)
{
	return (!node || (ni_string_empty(node->cdata) && !node->children));
}

static inline ni_bool_t
xml_document_is_empty(const xml_document_t *doc)
{
	return (!doc || xml_node_is_empty(doc->root));
}

extern				ni_declare_ptr_array_init(xml_document);
extern				ni_declare_ptr_array_destroy(xml_document);
extern				ni_declare_ptr_array_append(xml_document);
extern				ni_declare_ptr_array_insert(xml_document);
extern				ni_declare_ptr_array_index(xml_document);

extern				ni_declare_ptr_array_init(xml_node);
extern				ni_declare_ptr_array_destroy(xml_node);
extern				ni_declare_ptr_array_append_ref(xml_node);

extern xml_node_array_t *	xml_node_array_new(void);
extern void			xml_node_array_free(xml_node_array_t *);

#endif /* NI_WICKED_XML_H */
