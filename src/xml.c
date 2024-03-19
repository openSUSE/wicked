/*
 *	XML objects - document and node
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/xml.h>
#include <wicked/logging.h>
#include "util_priv.h"
#include "slist_priv.h"
#include <inttypes.h>

#define XML_DOCUMENTARRAY_CHUNK		1
#define XML_NODEARRAY_CHUNK		8

xml_document_t *
xml_document_new()
{
	xml_document_t *doc;

	doc = xcalloc(1, sizeof(*doc));
	doc->root = xml_node_new(NULL, NULL);
	return doc;
}

xml_node_t *
xml_document_root(xml_document_t *doc)
{
	return doc ? doc->root : NULL;
}

const char *
xml_document_type(const xml_document_t *doc)
{
	return doc ? doc->dtd : NULL;
}

void
xml_document_set_root(xml_document_t *doc, xml_node_t *root)
{
	if (doc && doc->root != root) {
		xml_node_free(doc->root);
		doc->root = root;
	}
}

xml_node_t *
xml_document_take_root(xml_document_t *doc)
{
	xml_node_t *root = NULL;

	if (doc) {
		root = doc->root;
		doc->root = NULL;
	}
	return root;
}

void
xml_document_free(xml_document_t *doc)
{
	if (doc) {
		xml_node_free(doc->root);
		ni_string_free(&doc->dtd);
		free(doc);
	}
}

/*
 * Helper functions for xml node list management
 */
static inline void
__xml_node_list_insert(xml_node_t **pos, xml_node_t *node, xml_node_t *parent)
{
	node->parent = parent;
	node->next = *pos;
	*pos = node;
}

static inline xml_node_t *
__xml_node_list_remove(xml_node_t **pos)
{
	xml_node_t *np = *pos;

	if (np) {
		np->parent = NULL;
		*pos = np->next;
		np->next = NULL;
	}

	return np;
}

static inline void
__xml_node_list_drop(xml_node_t **pos)
{
	xml_node_t *np;

	if ((np = __xml_node_list_remove(pos)) != NULL)
		xml_node_free(np);
}

static inline xml_node_t **
__xml_node_list_tail(xml_node_t **pos)
{
	xml_node_t *np;

	while ((np = *pos) != NULL)
		pos = &np->next;
	return pos;
}

void
xml_node_add_child(xml_node_t *parent, xml_node_t *child)
{
	xml_node_t **tail;

	ni_assert(child->parent == NULL);

	tail = __xml_node_list_tail(&parent->children);
	__xml_node_list_insert(tail, child, parent);
}

xml_node_t *
xml_node_new(const char *ident, xml_node_t *parent)
{
	xml_node_t *node;

	node = xcalloc(1, sizeof(xml_node_t));
	if (ident)
		node->name = xstrdup(ident);

	if (parent)
		xml_node_add_child(parent, node);
	node->refcount = 1;

	return node;
}

xml_node_t *
xml_node_new_element(const char *ident, xml_node_t *parent, const char *cdata)
{
	xml_node_t *node = xml_node_new(ident, parent);

	if (cdata)
		xml_node_set_cdata(node, cdata);
	return node;
}

xml_node_t *
xml_node_new_element_unique(const char *ident, xml_node_t *parent, const char *cdata)
{
	xml_node_t *node;

	if (parent == NULL || (node = xml_node_get_child(parent, ident)) == NULL)
		node = xml_node_new(ident, parent);

	xml_node_set_cdata(node, cdata);
	return node;
}

xml_node_t *
xml_node_new_element_int(const char *ident, xml_node_t *parent, int value)
{
	xml_node_t *node = xml_node_new(ident, parent);

	xml_node_set_int(node, value);
	return node;
}

xml_node_t *
xml_node_new_element_int64(const char *ident, xml_node_t *parent, int64_t value)
{
	xml_node_t *node = xml_node_new(ident, parent);

	xml_node_set_int64(node, value);
	return node;
}

xml_node_t *
xml_node_new_element_uint(const char *ident, xml_node_t *parent, unsigned int value)
{
	xml_node_t *node = xml_node_new(ident, parent);

	xml_node_set_uint(node, value);
	return node;
}

xml_node_t *
xml_node_new_element_uint64(const char *ident, xml_node_t *parent, uint64_t value)
{
	xml_node_t *node = xml_node_new(ident, parent);

	xml_node_set_uint64(node, value);
	return node;
}

/*
 * Clone an XML node and all its descendants
 */
xml_node_t *
xml_node_clone(const xml_node_t *src, xml_node_t *parent)
{
	xml_node_t *dst, *child;
	const ni_var_t *attr;
	unsigned int i;

	if (!src)
		return NULL;

	dst = xml_node_new(src->name, parent);
	ni_string_dup(&dst->cdata, src->cdata);

	for (i = 0, attr = src->attrs.data; i < src->attrs.count; ++i, ++attr)
		xml_node_add_attr(dst, attr->name, attr->value);

	for (child = src->children; child; child = child->next)
		xml_node_clone(child, dst);

	dst->location = xml_location_clone(src->location);
	return dst;
}

/*
 * "Clone" an XML node by incrementing its refcount
 */
xml_node_t *
xml_node_clone_ref(xml_node_t *src)
{
	if (!src)
		return NULL;

	ni_assert(src->refcount);
	src->refcount++;
	return src;
}

/*
 * Merge node @merge into node @base.
 */
void
xml_node_merge(xml_node_t *base, const xml_node_t *merge)
{
	const xml_node_t *mchild;

	for (mchild = merge->children; mchild; mchild = mchild->next) {
		xml_node_t **pos, *np, *clone;

		for (pos = &base->children; (np = *pos) != NULL; pos = &np->next) {
			if (ni_string_eq(mchild->name, np->name))
				goto dont_merge;
		}

		clone = xml_node_clone(mchild, NULL);
		__xml_node_list_insert(pos, clone, base);

dont_merge: ;
	}
}



/*
 * Free an XML node
 */
void
xml_node_free(xml_node_t *node)
{
	xml_node_t *child;

	if (!node)
		return;

	ni_assert(node->refcount);
	if (--(node->refcount) != 0)
		return;

	while ((child = node->children) != NULL) {
		node->children = child->next;
		child->parent = NULL;
		xml_node_free(child);
	}

	if (node->location)
		xml_location_free(node->location);

	ni_var_array_destroy(&node->attrs);
	free(node->cdata);
	free(node->name);
	free(node);
}

void
xml_node_set_cdata(xml_node_t *node, const char *cdata)
{
	ni_string_dup(&node->cdata, cdata);
}

void
xml_node_set_int(xml_node_t *node, int value)
{
	char buffer[32];

	snprintf(buffer, sizeof(buffer), "%d", value);
	ni_string_dup(&node->cdata, buffer);
}

void
xml_node_set_int64(xml_node_t *node, int64_t value)
{
	char buffer[32];

	snprintf(buffer, sizeof(buffer), "%"PRId64, value);
	ni_string_dup(&node->cdata, buffer);
}

void
xml_node_set_uint(xml_node_t *node, unsigned int value)
{
	char buffer[32];

	snprintf(buffer, sizeof(buffer), "%u", value);
	ni_string_dup(&node->cdata, buffer);
}

void
xml_node_set_uint64(xml_node_t *node, uint64_t value)
{
	char buffer[32];

	snprintf(buffer, sizeof(buffer), "%"PRIu64, value);
	ni_string_dup(&node->cdata, buffer);
}

void
xml_node_set_uint_hex(xml_node_t *node, unsigned int value)
{
	char buffer[32];

	snprintf(buffer, sizeof(buffer), "0x%x", value);
	ni_string_dup(&node->cdata, buffer);
}

void
xml_node_add_attr(xml_node_t *node, const char *name, const char *value)
{
	ni_var_array_set(&node->attrs, name, value);
}

void
xml_node_add_attr_uint(xml_node_t *node, const char *name, unsigned int value)
{
	ni_var_array_set_uint(&node->attrs, name, value);
}

void
xml_node_add_attr_ulong(xml_node_t *node, const char *name, unsigned long value)
{
	ni_var_array_set_ulong(&node->attrs, name, value);
}

void
xml_node_add_attr_double(xml_node_t *node, const char *name, double value)
{
	ni_var_array_set_double(&node->attrs, name, value);
}

const ni_var_t *
xml_node_get_attr_var(const xml_node_t *node, const char *name)
{
	return node ? ni_var_array_get(&node->attrs, name) : NULL;
}

ni_bool_t
xml_node_has_attr(const xml_node_t *node, const char *name)
{
	return xml_node_get_attr_var(node, name) != NULL;
}

const char *
xml_node_get_attr(const xml_node_t *node, const char *name)
{
	const ni_var_t *attr;

	if (!(attr = xml_node_get_attr_var(node, name)))
		return NULL;
	return attr->value;
}

ni_bool_t
xml_node_del_attr(xml_node_t *node, const char *name)
{
	return node ? ni_var_array_remove(&node->attrs, name) : FALSE;
}

ni_bool_t
xml_node_get_attr_uint(const xml_node_t *node, const char *name, unsigned int *valp)
{
	const char *value;

	if (!valp || !(value = xml_node_get_attr(node, name)))
		return FALSE;

	if (ni_parse_uint(value, valp, 10) < 0)
		return FALSE;

	return TRUE;
}

ni_bool_t
xml_node_get_attr_ulong(const xml_node_t *node, const char *name, unsigned long *valp)
{
	const char *value;

	if (!valp || !(value = xml_node_get_attr(node, name)))
		return FALSE;

	if (ni_parse_ulong(value, valp, 10) < 0)
		return FALSE;

	return TRUE;
}

ni_bool_t
xml_node_get_attr_double(const xml_node_t *node, const char *name, double *valp)
{
	const char *value;

	if (!valp || !(value = xml_node_get_attr(node, name)))
		return FALSE;

	if (ni_parse_double(value, valp) < 0)
		return FALSE;

	return TRUE;
}

/*
 * Find a child element given its name
 */
xml_node_t *
xml_node_get_next_child(const xml_node_t *top, const char *name, const xml_node_t *cur)
{
	xml_node_t *child;

	if (top == NULL)
		return NULL;
	for (child = cur ? cur->next : top->children; child; child = child->next) {
		if (!strcmp(child->name, name))
			return child;
	}

	return NULL;
}

inline xml_node_t *
xml_node_get_child(const xml_node_t *node, const char *name)
{
	return xml_node_get_next_child(node, name, NULL);
}

/*
 * Find a child element given its name and a list of attributes
 */
xml_node_t *
xml_node_get_child_with_attrs(const xml_node_t *node, const char *name,
		const ni_var_array_t *attrs)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (!strcmp(child->name, name)
		 && xml_node_match_attrs(child, attrs))
			return child;
	}
	return NULL;
}

ni_bool_t
xml_node_replace_child(xml_node_t *node, xml_node_t *newchild)
{
	xml_node_t **pos, *child;
	ni_bool_t found = FALSE;

	pos = &node->children;
	while ((child = *pos) != NULL) {
		if (!strcmp(child->name, newchild->name)) {
			__xml_node_list_drop(pos);
			found = TRUE;
		} else {
			pos = &child->next;
		}
	}

	__xml_node_list_insert(pos, newchild, node);
	return found;
}

ni_bool_t
xml_node_delete_child(xml_node_t *node, const char *name)
{
	xml_node_t **pos, *child;
	ni_bool_t found = FALSE;

	pos = &node->children;
	while ((child = *pos) != NULL) {
		if (!strcmp(child->name, name)) {
			__xml_node_list_drop(pos);
			found = TRUE;
		} else {
			pos = &child->next;
		}
	}

	return found;
}

ni_bool_t
xml_node_delete_child_node(xml_node_t *node, xml_node_t *destroy)
{
	xml_node_t **pos, *child;

	ni_assert(destroy->parent == node);

	pos = &node->children;
	while ((child = *pos) != NULL) {
		if (child == destroy) {
			__xml_node_list_drop(pos);
			return TRUE;
		}
		pos = &child->next;
	}

	return FALSE;
}

void
xml_node_detach(xml_node_t *node)
{
	xml_node_t *parent, **pos, *sibling;

	if ((parent = node->parent) == NULL)
		return;

	pos = &parent->children;
	while ((sibling = *pos) != NULL) {
		if (sibling == node) {
			__xml_node_list_remove(pos);
			break;
		}
		pos = &sibling->next;
	}
}

void
xml_node_reparent(xml_node_t *parent, xml_node_t *child)
{
	if (child->parent)
		xml_node_detach(child);
	xml_node_add_child(parent, child);
}

xml_node_t *
xml_node_find_parent(const xml_node_t *node, const char *parent)
{
	xml_node_t *p;

	for (p = node ? node->parent : NULL; p; p = p->parent) {
		if (ni_string_eq(p->name, parent))
			return p;
	}
	return NULL;
}

/*
 * Get xml node path relative to some top node
 */
static const char *
__xml_node_path(const xml_node_t *node, const xml_node_t *top, char *buf, size_t size)
{
	unsigned int offset = 0;

	if (node->parent && node->parent != top) {
		__xml_node_path(node->parent, top, buf, size);
		offset = strlen(buf);
		if ((offset == 0 || buf[offset-1] != '/') && offset < size)
			buf[offset++] = '/';
	}

	if (node->name == NULL && node->parent == NULL) {
		/* this is the root node */
		strcpy(buf, "/");
	} else {
		snprintf(buf + offset, size - offset, "%s", node->name);
	}
	return buf;
}

const char *
xml_node_path(const xml_node_t *node, const xml_node_t *top)
{
	static char pathbuf[1024];

	return __xml_node_path(node, top, pathbuf, sizeof(pathbuf));
}

static const char *
__xml_node_get_path(ni_stringbuf_t *path, const xml_node_t *node, const xml_node_t *top)
{
	if (node->parent && node->name && node->parent != top) {
		__xml_node_get_path(path, node->parent, top);

		if (path->len && path->string[path->len - 1] != '/')
			ni_stringbuf_putc(path, '/');
	}

	if (node->name) {
		ni_stringbuf_puts(path, node->name);
	} else if (!node->parent) {
		/* this is the root node */
		ni_stringbuf_putc(path, '/');
	}
	return path->string;
}

const char *
xml_node_get_path(ni_stringbuf_t *path, const xml_node_t *node, const xml_node_t *top)
{
	if (!path || !node)
		return NULL;
	return __xml_node_get_path(path, node, top);
}

/*
 * Traverse an xml tree, depth first.
 */
xml_node_t *
xml_node_get_next(xml_node_t *top, xml_node_t *cur)
{
	if (cur == NULL) {
		/* Start at the top node and descend */
		cur = top;
	} else {
		/* We've already visited this node. Get the
		 * next one.
		 * By default, move right, then down. If there's
		 * no right sibling, move up and repeat.
		 */

		/* No next sibling: move up, then right */
		if (cur->next == NULL) {
			if (cur == top || cur->parent == top)
				return NULL;
			cur = cur->parent;
			ni_assert(cur);
			return cur;
		}
		cur = cur->next;
	}

	/* depth first */
	while (cur->children)
		cur = cur->children;

	return cur;
}

xml_node_t *
xml_node_get_next_named(xml_node_t *top, const char *name, xml_node_t *cur)
{
	while ((cur = xml_node_get_next(top, cur)) != NULL) {
		if (!strcmp(cur->name, name))
			return cur;
	}

	return NULL;
}

/*
 * XML node matching functions
 */
ni_bool_t
xml_node_match_attrs(const xml_node_t *node, const ni_var_array_t *attrlist)
{
	unsigned int i;
	ni_var_t *attr;

	for (i = 0, attr = attrlist->data; i < attrlist->count; ++i, ++attr) {
		const char *value;

		value = xml_node_get_attr(node, attr->name);
		if (attr->value == NULL || value == NULL) {
			if (attr->value != value)
				return FALSE;
		} else if (strcmp(attr->value, value)) {
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * XML document arrays
 */
void
xml_document_array_init(xml_document_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
xml_document_array_destroy(xml_document_array_t *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i)
		xml_document_free(array->data[i]);

	if (array->data)
		free(array->data);
	memset(array, 0, sizeof(*array));
}

xml_document_array_t *
xml_document_array_new(void)
{
	xml_document_array_t *array;

	array = xcalloc(1, sizeof(*array));
	return array;
}

void
xml_document_array_free(xml_document_array_t *array)
{
	xml_document_array_destroy(array);
	free(array);
}

static void
__xml_document_array_realloc(xml_document_array_t *array, unsigned int newsize)
{
	xml_document_t **newdata;
	unsigned int i;

	newsize = (newsize + XML_DOCUMENTARRAY_CHUNK) + 1;
	newdata = xrealloc(array->data, newsize * sizeof(xml_document_t *));

	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		array->data[i] = NULL;
}

void
xml_document_array_append(xml_document_array_t *array, xml_document_t *doc)
{
	if ((array->count % XML_DOCUMENTARRAY_CHUNK) == 0)
		__xml_document_array_realloc(array, array->count);

	array->data[array->count++] = doc;
}

/*
 * XML node arrays
 */
void
xml_node_array_init(xml_node_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
xml_node_array_destroy(xml_node_array_t *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i)
		xml_node_free(array->data[i]);

	if (array->data)
		free(array->data);
	memset(array, 0, sizeof(*array));
}

xml_node_array_t *
xml_node_array_new(void)
{
	xml_node_array_t *array;

	array = xcalloc(1, sizeof(*array));
	return array;
}

void
xml_node_array_free(xml_node_array_t *array)
{
	xml_node_array_destroy(array);
	free(array);
}

static void
__xml_node_array_realloc(xml_node_array_t *array, unsigned int newsize)
{
	xml_node_t **newdata;
	unsigned int i;

	newsize = (newsize + XML_NODEARRAY_CHUNK) + 1;
	newdata = xrealloc(array->data, newsize * sizeof(array->data[0]));

	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		array->data[i] = NULL;
}

void
xml_node_array_append(xml_node_array_t *array, xml_node_t *node)
{
	if (!array || !node)
		return;

	if ((array->count % XML_NODEARRAY_CHUNK) == 0)
		__xml_node_array_realloc(array, array->count);

	array->data[array->count++] = xml_node_clone_ref(node);
}

xml_node_t *
xml_node_create(xml_node_t *parent, const char *name)
{
	xml_node_t *child;

	if ((child = xml_node_get_child(parent, name)) == NULL)
		child = xml_node_new(name, parent);
	return child;
}

void
xml_node_dict_set(xml_node_t *parent, const char *name, const char *value)
{
	xml_node_t *child;

	if (!value || !*value)
		return;

	child = xml_node_create(parent, name);
	xml_node_set_cdata(child, value);
}

typedef struct xml_node_name_path	xml_node_name_path_t;

struct xml_node_name_path {
	xml_node_name_path_t *	next;
	ni_string_array_t	path;
};

static xml_node_name_path_t *
xml_node_name_path_new(void)
{
	return calloc(1, sizeof(xml_node_name_path_t));
}

static void
xml_node_name_path_free(xml_node_name_path_t *item)
{
	if (item) {
		ni_string_array_destroy(&item->path);
		free(item);
	}
}

static inline ni_bool_t
xml_node_name_path_match(xml_node_t *node, const ni_string_array_t *path)
{
	ni_bool_t ret = FALSE;
	const char *name;
	unsigned int i;

	if (!node || !path)
		return FALSE;

	for (i = 0; i < path->count; ++i) {
		name = path->data[i];

		if (!node || !ni_string_eq(node->name, name))
			return FALSE;

		node = node->parent;
		ret = TRUE;
	}
	return ret;
}

static ni_define_slist_destroy(xml_node_name_path);
static ni_define_slist_append(xml_node_name_path);

static ni_bool_t
xml_node_name_path_list_create(xml_node_name_path_t **list, const char * const npaths[])
{
	xml_node_name_path_t *item;
	const char * const *nptr;

	if (!list || !npaths)
		return FALSE;

	for (nptr = npaths; *nptr; ++nptr) {
		if (!(item = xml_node_name_path_new())) {
			xml_node_name_path_list_destroy(list);
			return FALSE;
		}
		if (!ni_string_split(&item->path, *nptr, "/", 0))
			xml_node_name_path_free(item);
		else
			xml_node_name_path_list_append(list, item);
	}
	return TRUE;
}

static void
xml_node_name_path_list_hide_cdata(xml_node_t *node,
		const xml_node_name_path_t *list, const char *hidden)
{
	const xml_node_name_path_t *item;
	xml_node_t *child;

	ni_slist_foreach(list, item) {
		if (!xml_node_name_path_match(node, &item->path))
			continue;

		xml_node_set_cdata(node, hidden);
	}

	for (child = node->children; child; child = child->next)
		xml_node_name_path_list_hide_cdata(child, list, hidden);
}

extern void
xml_node_hide_cdata(xml_node_t *node, const char * const npaths[], const char *hidden)
{
	xml_node_name_path_t *list = NULL;

	if (!node || !npaths)
		return;

	if (!xml_node_name_path_list_create(&list, npaths) || !list)
		return;

	xml_node_name_path_list_hide_cdata(node, list, hidden);
	xml_node_name_path_list_destroy(&list);
}
