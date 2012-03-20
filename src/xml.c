/*
 *	XML objects - document and node
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <wicked/xml.h>
#include <wicked/logging.h>
#include "util_priv.h"

xml_document_t *
xml_document_new()
{
	xml_document_t *doc;

	doc = calloc(1, sizeof(*doc));
	doc->root = calloc(1, sizeof(xml_node_t));
	return doc;
}

xml_node_t *
xml_document_root(xml_document_t *doc)
{
	return doc->root;
}

const char *
xml_document_type(const xml_document_t *doc)
{
	return doc->dtd;
}

void
xml_document_set_root(xml_document_t *doc, xml_node_t *root)
{
	if (doc->root != root) {
		xml_node_free(doc->root);
		doc->root = root;
	}
}

xml_node_t *
xml_document_take_root(xml_document_t *doc)
{
	xml_node_t *root = doc->root;

	doc->root = NULL;
	return root;
}

void
xml_document_free(xml_document_t *doc)
{
	xml_node_free(doc->root);
	ni_string_free(&doc->dtd);
	free(doc);
}

void
xml_node_add_child(xml_node_t *parent, xml_node_t *child)
{
	xml_node_t **tail, *np;

	ni_assert(child->parent == NULL);

	tail = &parent->children;
	while ((np = *tail) != NULL)
		tail = &np->next;

	child->parent = parent;
	*tail = child;
}

xml_node_t *
xml_node_new(const char *ident, xml_node_t *parent)
{
	xml_node_t *node;

	node = calloc(1, sizeof(xml_node_t));
	if (ident)
		node->name = xstrdup(ident);

	if (parent)
		xml_node_add_child(parent, node);

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

/*
 * Clone an XML node and all its descendants
 */
xml_node_t *
xml_node_clone(const xml_node_t *src, xml_node_t *parent)
{
	xml_node_t *dst, *child;
	const ni_var_t *attr;
	unsigned int i;

	dst = xml_node_new(src->name, parent);
	ni_string_dup(&dst->cdata, src->cdata);

	for (i = 0, attr = src->attrs.data; i < src->attrs.count; ++i, ++attr)
		xml_node_add_attr(dst, attr->name, attr->value);

	for (child = src->children; child; child = child->next)
		xml_node_clone(child, dst);

	return dst;
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
	while ((child = node->children) != NULL) {
		node->children = child->next;
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
xml_node_add_attr(xml_node_t *node, const char *name, const char *value)
{
	ni_var_array_set(&node->attrs, name, value);
}

void
xml_node_add_attr_uint(xml_node_t *node, const char *name, unsigned int value)
{
	ni_var_array_set_integer(&node->attrs, name, value);
}

void
xml_node_add_attr_ulong(xml_node_t *node, const char *name, unsigned long value)
{
	ni_var_array_set_long(&node->attrs, name, value);
}

void
xml_node_add_attr_double(xml_node_t *node, const char *name, double value)
{
	ni_var_array_set_double(&node->attrs, name, value);
}

static const ni_var_t *
__xml_node_get_attr(const xml_node_t *node, const char *name)
{
	unsigned int i;

	for (i = 0; i < node->attrs.count; ++i) {
		if (!strcmp(node->attrs.data[i].name, name))
			return &node->attrs.data[i];
	}
	return NULL;
}

int
xml_node_has_attr(const xml_node_t *node, const char *name)
{
	return __xml_node_get_attr(node, name) != NULL;
}

const char *
xml_node_get_attr(const xml_node_t *node, const char *name)
{
	const ni_var_t *attr;

	if (!(attr = __xml_node_get_attr(node, name)))
		return NULL;
	return attr->value;
}

int
xml_node_get_attr_uint(const xml_node_t *node, const char *name, unsigned int *valp)
{
	const ni_var_t *attr;
	char *pos;

	if (!(attr = __xml_node_get_attr(node, name)) || !attr->value)
		return 0;

	*valp = strtoul(attr->value, &pos, 0);
	if (*pos)
		return -1;
	return 0;
}

int
xml_node_get_attr_ulong(const xml_node_t *node, const char *name, unsigned long *valp)
{
	const ni_var_t *attr;
	char *pos;

	if (!(attr = __xml_node_get_attr(node, name)) || !attr->value)
		return 0;

	*valp = strtoul(attr->value, &pos, 0);
	if (*pos)
		return -1;
	return 0;
}

int
xml_node_get_attr_double(const xml_node_t *node, const char *name, double *valp)
{
	const ni_var_t *attr;
	char *pos;

	if (!(attr = __xml_node_get_attr(node, name)) || !attr->value)
		return 0;

	*valp = strtod(attr->value, &pos);
	if (*pos)
		return -1;
	return 0;
}

/*
 * Find a child element given its name
 */
xml_node_t *
xml_node_get_child(const xml_node_t *node, const char *name)
{
	xml_node_t *child;

	if (node == NULL)
		return NULL;
	for (child = node->children; child; child = child->next) {
		if (!strcmp(child->name, name))
			return child;
	}
	return NULL;
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

int
xml_node_replace_child(xml_node_t *node, xml_node_t *newchild)
{
	xml_node_t **pos, *child;
	int found = 0;

	pos = &node->children;
	while ((child = *pos) != NULL) {
		if (!strcmp(child->name, newchild->name)) {
			*pos = child->next;
			child->parent = NULL;
			xml_node_free(child);
		} else {
			pos = &child->next;
		}
	}

	newchild->parent = node;
	*pos = newchild;
	return found;
}

int
xml_node_delete_child(xml_node_t *node, const char *name)
{
	xml_node_t **pos, *child;
	int found = 0;

	pos = &node->children;
	while ((child = *pos) != NULL) {
		if (!strcmp(child->name, name)) {
			*pos = child->next;
			child->parent = NULL;
			xml_node_free(child);
			found++;
		} else {
			pos = &child->next;
		}
	}

	return found;
}

int
xml_node_delete_child_node(xml_node_t *node, xml_node_t *destroy)
{
	xml_node_t **pos, *child;

	assert(destroy->parent == node);

	pos = &node->children;
	while ((child = *pos) != NULL) {
		if (child == destroy) {
			*pos = child->next;
			child->parent = NULL;
			xml_node_free(child);
			return 1;
		}
		pos = &child->next;
	}

	return 0;
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
			*pos = node->next;
			node->parent = NULL;
			node->next = NULL;
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
int
xml_node_match_attrs(const xml_node_t *node, const ni_var_array_t *attrlist)
{
	unsigned int i;
	ni_var_t *attr;

	for (i = 0, attr = attrlist->data; i < attrlist->count; ++i, ++attr) {
		const char *value;

		value = xml_node_get_attr(node, attr->name);
		if (attr->value == NULL || value == NULL) {
			if (attr->value != value)
				return 0;
		} else if (strcmp(attr->value, value)) {
			return 0;
		}
	}
	return 1;
}
