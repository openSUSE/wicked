/*
 * Simple XML schema, in no way intended to be conforming to any standard.
 *
 * Copyright (C) 2012, Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>

#include <wicked/logging.h>
#include <wicked/xml.h>
#include <wicked/logging.h>
#include "xml-schema.h"
#include "util_priv.h"

static int		ni_xs_process_include(xml_node_t *, ni_xs_scope_t *);
static int		ni_xs_process_class(xml_node_t *, ni_xs_scope_t *);
static int		ni_xs_process_define(xml_node_t *, ni_xs_scope_t *);
static int		ni_xs_process_service(xml_node_t *, ni_xs_scope_t *);
static int		ni_xs_process_method(xml_node_t *, ni_xs_service_t *, ni_xs_scope_t *);
static int		ni_xs_process_signal(xml_node_t *, ni_xs_service_t *, ni_xs_scope_t *);
static int		ni_xs_build_typelist(xml_node_t *, ni_xs_name_type_array_t *, ni_xs_scope_t *,
				ni_bool_t, ni_xs_group_array_t *);
static ni_xs_type_t *	ni_xs_build_simple_type(xml_node_t *, const char *, ni_xs_scope_t *, ni_xs_group_array_t *);
static ni_xs_type_t *	ni_xs_build_complex_type(xml_node_t *, const char *, ni_xs_scope_t *);
static void		ni_xs_name_type_array_copy(ni_xs_name_type_array_t *, const ni_xs_name_type_array_t *);
static void		ni_xs_name_type_array_destroy(ni_xs_name_type_array_t *);
static ni_xs_type_t *	ni_xs_build_one_type(xml_node_t *, ni_xs_scope_t *);
static void		ni_xs_service_free(ni_xs_service_t *);
static ni_bool_t	ni_xs_type_build_constraints(ni_xs_type_t **, const xml_node_t *, ni_xs_group_array_t *);
static const char *	ni_xs_get_description(const xml_node_t *);
static ni_xs_type_t *	ni_xs_type_set_description(ni_xs_type_t *, const xml_node_t *);
static ni_xs_intmap_t *	ni_xs_build_bitmask_constraint(const xml_node_t *);
static ni_xs_intmap_t *	ni_xs_build_bitmap_constraint(const xml_node_t *);
static ni_xs_intmap_t *	ni_xs_build_enum_constraint(const xml_node_t *);
static ni_xs_range_t *	ni_xs_build_range_constraint(const xml_node_t *);
static void		ni_xs_intmap_free(ni_xs_intmap_t *);
static void		ni_xs_range_free(ni_xs_range_t *);
static void		__ni_xs_intmap_free(ni_intmap_t *);
static ni_xs_group_t *	ni_xs_group_clone(ni_xs_group_t *group);
static void		ni_xs_group_free(ni_xs_group_t *group);
static void		ni_xs_group_array_append(ni_xs_group_array_t *, ni_xs_group_t *);
static void		ni_xs_group_array_copy(ni_xs_group_array_t *, const ni_xs_group_array_t *);
static void		ni_xs_group_array_destroy(ni_xs_group_array_t *);
static ni_xs_group_t *	ni_xs_group_get(ni_xs_group_array_t *, unsigned int, const char *);
static void		ni_xs_scalar_set_bitmask(ni_xs_type_t *, ni_xs_intmap_t *);
static void		ni_xs_scalar_set_bitmap(ni_xs_type_t *, ni_xs_intmap_t *);
static void		ni_xs_scalar_set_enum(ni_xs_type_t *, ni_xs_intmap_t *);
static void		ni_xs_scalar_set_range(ni_xs_type_t *, ni_xs_range_t *);

/*
 * Constructor functions for basic and complex types
 */
static ni_xs_type_t *
ni_xs_type_new(unsigned int class)
{
	ni_xs_type_t *type = xcalloc(1, sizeof(*type));

	type->refcount = 1;
	type->class = class;
	return type;
}

ni_xs_type_t *
ni_xs_scalar_new(const char *basic_name, unsigned int scalar_type)
{
	ni_xs_type_t *type = ni_xs_type_new(NI_XS_TYPE_SCALAR);

	type->u.scalar_info = xcalloc(1, sizeof(ni_xs_scalar_info_t));
	type->u.scalar_info->basic_name = basic_name;
	type->u.scalar_info->type = scalar_type;
	return type;
}

ni_xs_type_t *
ni_xs_struct_new(ni_xs_name_type_array_t *children)
{
	ni_xs_type_t *type = ni_xs_type_new(NI_XS_TYPE_STRUCT);

	type->u.struct_info = xcalloc(1, sizeof(ni_xs_struct_info_t));
	if (children)
		ni_xs_name_type_array_copy(&type->u.struct_info->children, children);
	return type;
}

ni_xs_type_t *
ni_xs_union_new(ni_xs_name_type_array_t *children, const char *discriminant)
{
	ni_xs_type_t *type = ni_xs_type_new(NI_XS_TYPE_UNION);

	type->u.union_info = xcalloc(1, sizeof(ni_xs_union_info_t));
	if (children)
		ni_xs_name_type_array_copy(&type->u.union_info->children, children);
	ni_string_dup(&type->u.union_info->discriminant, discriminant);
	return type;
}

ni_xs_type_t *
ni_xs_dict_new(ni_xs_name_type_array_t *children)
{
	ni_xs_type_t *type = ni_xs_type_new(NI_XS_TYPE_DICT);

	type->u.dict_info = xcalloc(1, sizeof(ni_xs_dict_info_t));
	if (children)
		ni_xs_name_type_array_copy(&type->u.dict_info->children, children);
	return type;
}

ni_xs_type_t *
ni_xs_array_new(ni_xs_type_t *elementType, const char *elementName, unsigned long minlen, unsigned long maxlen)
{
	ni_xs_type_t *type = ni_xs_type_new(NI_XS_TYPE_ARRAY);

	type->u.array_info = xcalloc(1, sizeof(struct ni_xs_array_info));
	type->u.array_info->element_type = ni_xs_type_hold(elementType);
	type->u.array_info->element_name = xstrdup(elementName);
	type->u.array_info->minlen = minlen;
	type->u.array_info->maxlen = maxlen;
	return type;
}

/*
 * Clone a type. This is needed when we define or extend a type
 */
ni_xs_type_t *
ni_xs_type_clone(const ni_xs_type_t *src)
{
	ni_xs_type_t *dst = NULL;

	switch (src->class) {
	case NI_XS_TYPE_VOID:
		break;

	case NI_XS_TYPE_SCALAR:
		{
			ni_xs_scalar_info_t *scalar_info = src->u.scalar_info;

			dst = ni_xs_scalar_new(scalar_info->basic_name, scalar_info->type);

			/* we clone the constraints as well */
			ni_xs_scalar_set_bitmask(dst, scalar_info->constraint.bitmask);
			ni_xs_scalar_set_bitmap(dst, scalar_info->constraint.bitmap);
			ni_xs_scalar_set_enum(dst, scalar_info->constraint.enums);
			ni_xs_scalar_set_range(dst, scalar_info->constraint.range);
			break;
		}

	case NI_XS_TYPE_DICT:
		{
			ni_xs_dict_info_t *dict_info = src->u.dict_info;

			dst = ni_xs_dict_new(&dict_info->children);
			ni_xs_group_array_copy(&dst->u.dict_info->groups, &dict_info->groups);
			break;
		}

	case NI_XS_TYPE_STRUCT:
		{
			ni_xs_struct_info_t *struct_info = src->u.struct_info;

			dst = ni_xs_struct_new(&struct_info->children);
			break;
		}

	case NI_XS_TYPE_UNION:
		{
			ni_xs_union_info_t *union_info = src->u.union_info;

			dst = ni_xs_union_new(&union_info->children, union_info->discriminant);
			break;
		}

	case NI_XS_TYPE_ARRAY:
		{
			ni_xs_array_info_t *src_array_info = src->u.array_info;

			dst = ni_xs_array_new(src_array_info->element_type,
					src_array_info->element_name,
					src_array_info->minlen,
					src_array_info->maxlen);
			dst->u.array_info->notation = src_array_info->notation;
			break;
		}

	}

	dst->constraint.mandatory = src->constraint.mandatory;
	dst->constraint.group = ni_xs_group_clone(src->constraint.group);

	return dst;
}

/*
 * Clone and release a type
 */
static inline ni_xs_type_t *
ni_xs_type_clone_and_release(ni_xs_type_t *type)
{
	ni_xs_type_t *clone;

	if (type->refcount == 1)
		return type;
	clone = ni_xs_type_clone(type);
	ni_xs_type_release(type);
	return clone;
}

void
ni_xs_type_free(ni_xs_type_t *type)
{
	switch (type->class) {
	case NI_XS_TYPE_DICT:
		{
			ni_xs_dict_info_t *dict_info = type->u.dict_info;

			ni_xs_name_type_array_destroy(&dict_info->children);
			ni_xs_group_array_destroy(&dict_info->groups);
			free(dict_info);
			type->u.dict_info = NULL;
			break;
		}

	case NI_XS_TYPE_STRUCT:
		{
			ni_xs_struct_info_t *struct_info = type->u.struct_info;

			ni_xs_name_type_array_destroy(&struct_info->children);
			free(struct_info);
			type->u.struct_info = NULL;
			break;
		}

	case NI_XS_TYPE_UNION:
		{
			ni_xs_union_info_t *union_info = type->u.union_info;

			ni_xs_name_type_array_destroy(&union_info->children);
			ni_string_free(&union_info->discriminant);
			free(union_info);
			type->u.union_info = NULL;
			break;
		}

	case NI_XS_TYPE_ARRAY:
		{
			ni_xs_array_info_t *array_info = type->u.array_info;

			ni_xs_type_release(array_info->element_type);
			ni_string_free(&array_info->element_name);
			free(array_info);
			type->u.array_info = NULL;
			break;
		}

	case NI_XS_TYPE_SCALAR:
		{
			ni_xs_scalar_info_t *scalar_info = type->u.scalar_info;

			ni_xs_scalar_set_enum(type, NULL);
			ni_xs_scalar_set_bitmask(type, NULL);
			ni_xs_scalar_set_bitmap(type, NULL);
			ni_xs_scalar_set_range(type, NULL);

			free(scalar_info);
			type->u.scalar_info = NULL;
			break;
		}
	}

	if (type->constraint.group) {
		ni_xs_group_free(type->constraint.group);
		type->constraint.group = NULL;
	}

	if (type->meta)
		xml_node_free(type->meta);
	type->meta = NULL;

	ni_string_free(&type->description);
	ni_string_free(&type->name);
	free(type);
}

void
ni_xs_type_array_destroy(ni_xs_type_array_t *ap)
{
	unsigned int i;

	for (i = 0; i < ap->count; ++i)
		ni_xs_type_release(ap->data[i]);
	free(ap->data);
	memset(ap, 0, sizeof(*ap));
}

void
ni_xs_type_array_append(ni_xs_type_array_t *array, ni_xs_type_t *type)
{
	if ((array->count % 32) == 0)
		array->data = xrealloc(array->data, (array->count + 32) * sizeof(array->data[0]));
	array->data[array->count++] = ni_xs_type_hold(type);
}

/*
 * Array of name/type pairs. These are used in structs, dict and type dicts.
 */
ni_xs_name_type_array_t *
ni_xs_name_type_array_new(void)
{
	ni_xs_name_type_array_t *array = xcalloc(1, sizeof(*array));
	return array;
}

void
ni_xs_name_type_array_destroy(ni_xs_name_type_array_t *array)
{
	ni_xs_name_type_t *def;
	unsigned int i;

	for (i = 0, def = array->data; i < array->count; ++i, ++def) {
		ni_string_free(&def->name);
		ni_xs_type_release(def->type);
	}
	free(array->data);
	memset(array, 0, sizeof(*array));
}

void
ni_xs_name_type_array_free(ni_xs_name_type_array_t *array)
{
	ni_xs_name_type_array_destroy(array);
	free(array);
}

void
ni_xs_name_type_array_append(ni_xs_name_type_array_t *array, const char *name, ni_xs_type_t *type, const char *description)
{
	ni_xs_name_type_t *def;

	if ((array->count % 32) == 0) {
		array->data = xrealloc(array->data, (array->count + 32) * sizeof(array->data[0]));
	}
	def = &array->data[array->count++];
	def->name = xstrdup(name);
	def->type = ni_xs_type_hold(type);
	def->description = xstrdup(description);
}

void
ni_xs_name_type_array_copy(ni_xs_name_type_array_t *dst, const ni_xs_name_type_array_t *src)
{
	ni_xs_name_type_t *def;
	unsigned int i;

	if (dst->count)
		ni_xs_name_type_array_destroy(dst);
	for (i = 0, def = src->data; i < src->count; ++i, ++def)
		ni_xs_name_type_array_append(dst, def->name, def->type, def->description);
}

static ni_xs_type_t *
ni_xs_name_type_array_find_local(const ni_xs_name_type_array_t *array, const char *name)
{
	ni_xs_name_type_t *def;
	unsigned int i;

	for (i = 0, def = array->data; i < array->count; ++i, ++def) {
		if (!strcmp(def->name, name))
			return def->type;
	}
	return NULL;
}

const ni_xs_type_t *
ni_xs_name_type_array_find(const ni_xs_name_type_array_t *array, const char *name)
{
	return ni_xs_name_type_array_find_local(array, name);
}

/*
 * Scopes in the schema hierarchy
 */
ni_xs_scope_t *
ni_xs_scope_new(ni_xs_scope_t *parent, const char *name)
{
	ni_xs_scope_t *scope = xcalloc(1, sizeof(ni_xs_scope_t));

	scope->parent = parent;
	ni_string_dup(&scope->name, name);
	if (parent && name) {
		ni_xs_scope_t **tail;

		for (tail = &parent->children; *tail; tail = &(*tail)->next)
			;
		*tail = scope;
	}
	ni_var_array_init(&scope->constants);
	return scope;
}

void
ni_xs_scope_free(ni_xs_scope_t *scope)
{
	/* Debug code: make sure we're no longer on the parent's list of children */
	if (scope->parent) {
		ni_xs_scope_t *child;

		for (child = scope->parent->children; child; child = child->next)
			ni_assert(child != scope);
	}

	ni_string_free(&scope->name);
	ni_xs_name_type_array_destroy(&scope->types);
	if (scope->children) {
		ni_xs_scope_t *child;

		while ((child = scope->children) != NULL) {
			scope->children = child->next;
			child->parent = NULL; /* Skip the debug step when freeing the child scope */
			child->next = NULL;
			ni_xs_scope_free(child);
		}
	}

	if (scope->services) {
		ni_xs_service_t *service;

		while ((service = scope->services) != NULL) {
			scope->services = service->next;
			ni_xs_service_free(service);
		}
	}

	ni_var_array_destroy(&scope->constants);
	free(scope);
}

const ni_xs_scope_t *
ni_xs_scope_lookup_scope(const ni_xs_scope_t *scope, const char *name)
{
	for (scope = scope->children; scope; scope = scope->next) {
		if (!strcmp(scope->name, name))
			return scope;
	}
	return NULL;
}

ni_xs_type_t *
ni_xs_scope_lookup_local(const ni_xs_scope_t *dict, const char *name)
{
	return ni_xs_name_type_array_find_local(&dict->types, name);
}

ni_xs_type_t *
ni_xs_scope_lookup(const ni_xs_scope_t *dict, const char *name)
{
	ni_xs_type_t *result = NULL;

	if (strchr(name, ':') != NULL) {
		char *copy, *cur_name, *rest;

		while (dict->parent)
			dict = dict->parent;

		copy = strdup(name);
		cur_name = strtok(copy, ":");
		while ((rest = strtok(NULL, ":")) != NULL) {
			dict = ni_xs_scope_lookup_scope(dict, cur_name);
			if (dict == NULL)
				break;
			cur_name = rest;
		}

		if (dict)
			result = ni_xs_scope_lookup_local(dict, cur_name);
		free(copy);
		return result;
	}

	while (result == NULL && dict != NULL) {
		result = ni_xs_scope_lookup_local(dict, name);
		dict = dict->parent;
	}
	return result;
}

int
ni_xs_scope_typedef(ni_xs_scope_t *dict, const char *name, ni_xs_type_t *type, const char *description)
{
	if (ni_xs_scope_lookup_local(dict, name) != NULL)
		return -1;

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_XML,
		"define type %s in scope %s", name, dict->name?: "<anon>");

	ni_xs_name_type_array_append(&dict->types, name, type, description);

	if (type->origdef.scope == NULL) {
		type->origdef.scope = dict;
		type->origdef.name = dict->types.data[dict->types.count-1].name;
	}
	return 0;
}

/*
 * Service definitions
 */
static ni_xs_method_t *
ni_xs_method_new(ni_xs_method_t **list, const char *name)
{
	ni_xs_method_t *method;

	method = xcalloc(1, sizeof(*method));
	ni_string_dup(&method->name, name);

	while (*list)
		list = &(*list)->next;
	*list = method;

	return method;
}

static void
ni_xs_method_free(ni_xs_method_t *method)
{
	ni_string_free(&method->name);
	ni_string_free(&method->description);
	ni_xs_name_type_array_destroy(&method->arguments);

	if (method->retval)
		ni_xs_type_release(method->retval);
	method->retval = NULL;

	free(method);
}

static ni_xs_service_t *
ni_xs_service_new(const char *name, const char *interface, ni_xs_scope_t *scope)
{
	ni_xs_service_t *service, **tail;

	service = xcalloc(1, sizeof(*service));
	ni_string_dup(&service->name, name);
	ni_string_dup(&service->interface, interface);

	for (tail = &scope->services; *tail; tail = &(*tail)->next)
		;
	*tail = service;

	return service;
}

static void
ni_xs_service_free(ni_xs_service_t *service)
{
	ni_xs_method_t *method;

	while ((method = service->methods) != NULL) {
		service->methods = method->next;
		ni_xs_method_free(method);
	}
	while ((method = service->signals) != NULL) {
		service->signals = method->next;
		ni_xs_method_free(method);
	}
	ni_string_free(&service->name);
	ni_string_free(&service->interface);
	ni_string_free(&service->description);

	free(service);
}

/*
 * Check for various sorts of reserved keywords
 */
static inline int
__string_is_in_list(const char *name, const char **list)
{
	while (*list) {
		if (!strcmp(*list++, name))
			return 1;
	}
	return 0;
}

static int
ni_xs_is_class_name(const char *name)
{
	static const char *class_names[] = {
		"scalar", "dict", "struct", "union", "array",
		NULL
	};

	return __string_is_in_list(name, class_names);
}

static int
ni_xs_is_reserved_name(const char *name)
{
	static const char *reserved[] = {
		"dict", "struct", "union", "array", "define", "object-class",
		NULL
	};

	return __string_is_in_list(name, reserved);
}

/*
 * Parse an XML schema file and process it
 */
int
ni_xs_process_schema_file(const char *filename, ni_xs_scope_t *scope)
{
	xml_document_t *doc = NULL;

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_XML,
		"ni_xs_process_schema_file(filename=%s)", filename);

	if (filename == NULL) {
		ni_error("%s: NULL filename", __func__);
		return -1;
	}

	doc = xml_document_read(filename);
	if (doc == NULL) {
		ni_error("cannot parse schema file \"%s\"", filename);
		return -1;
	}

	if (ni_xs_process_schema(doc->root, scope) < 0) {
		ni_error("invalid schema xml for schema file \"%s\"", filename);
		xml_document_free(doc);
		return -1;
	}

	xml_document_free(doc);
	return 0;
}

/*
 * Process a schema.
 * For now, this is nothing but a sequence of <define> elements
 */
int
ni_xs_process_schema(xml_node_t *node, ni_xs_scope_t *scope)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		int rv;

		if (!strcmp(child->name, "include")) {
			if ((rv = ni_xs_process_include(child, scope)) < 0)
				return rv;
		} else
		if (!strcmp(child->name, "object-class")) {
			if ((rv = ni_xs_process_class(child, scope)) < 0)
				return rv;
		} else
		if (!strcmp(child->name, "define")) {
			if ((rv = ni_xs_process_define(child, scope)) < 0)
				return rv;
		} else
		if (!strcmp(child->name, "service")) {
			if ((rv = ni_xs_process_service(child, scope)) < 0)
				return rv;
		} else {
			ni_error("%s: unsupported schema element <%s>", xml_node_location(node), child->name);
			return -1;
		}
	}

	return 0;
}

/*
 * Process a <service> element.
 */
int
ni_xs_process_service(xml_node_t *node, ni_xs_scope_t *scope)
{
	const char *nameAttr, *intfAttr;
	ni_xs_service_t *service;
	ni_xs_scope_t *sub_scope;
	xml_node_t *child;

	if (!(nameAttr = xml_node_get_attr(node, "name"))) {
		ni_error("%s: <service> element lacks name attribute", xml_node_location(node));
		return -1;
	}
	if (!(intfAttr = xml_node_get_attr(node, "interface"))) {
		ni_error("%s: <service> element lacks interface attribute", xml_node_location(node));
		return -1;
	}
	if (ni_xs_is_reserved_name(nameAttr)) {
		ni_error("%s: trying to <define> reserved name \"%s\"", xml_node_location(node), nameAttr);
		return -1;
	}

	sub_scope = ni_xs_scope_new(scope, nameAttr);

#ifdef DEBUG_VERBOSE
	ni_debug_dbus("define schema for service %s (interface=%s) in scope %s", nameAttr, intfAttr, scope->name);
#endif
	service = ni_xs_service_new(nameAttr, intfAttr, scope);
	sub_scope->defined_by.service = service;

	/* Copy all service attributes we don't deal with here */
	{
		unsigned int i;
		ni_var_t *var;

		var = node->attrs.data;
		for (i = 0; i < node->attrs.count; ++i, ++var) {
			if (strcmp(var->name, "name")
			 && strcmp(var->name, "interface"))
				ni_var_array_set(&service->attributes, var->name, var->value);
		}
	}

	for (child = node->children; child; child = child->next) {
		int rv;

		/* We do not allow nested definitions of service or object-class */
		if (!strcmp(child->name, "define")) {
			if ((rv = ni_xs_process_define(child, sub_scope)) < 0)
				return rv;
		} else
		if (!strcmp(child->name, "method")) {
			if ((rv = ni_xs_process_method(child, service, sub_scope)) < 0)
				return rv;
		} else
		if (!strcmp(child->name, "signal")) {
			if ((rv = ni_xs_process_signal(child, service, sub_scope)) < 0)
				return rv;
		} else
		if (!strcmp(child->name, "description")) {
			ni_string_dup(&service->description, child->cdata);
		} else {
			ni_warn("%s: ignoring unknown element <%s>", xml_node_location(child), child->name);
		}
	}

	return 0;
}

/*
 * Process a <method> declaration inside a service definition
 */
int
ni_xs_process_method(xml_node_t *node, ni_xs_service_t *service, ni_xs_scope_t *scope)
{
	const char *nameAttr;
	ni_xs_method_t *method;
	xml_node_t *child, *next;

	if (!(nameAttr = xml_node_get_attr(node, "name"))) {
		ni_error("%s: <method> element lacks name attribute", xml_node_location(node));
		return -1;
	}

	method = ni_xs_method_new(&service->methods, nameAttr);
	for (child = node->children; child; child = next) {
		ni_xs_scope_t *temp_scope;

		next = child->next;

		if (ni_string_eq(child->name, "arguments")) {
			temp_scope = ni_xs_scope_new(scope, NULL);
			if (ni_xs_build_typelist(child, &method->arguments, temp_scope, TRUE, NULL) < 0) {
				ni_xs_scope_free(temp_scope);
				return -1;
			}

			ni_xs_scope_free(temp_scope);
		} else
		if (ni_string_eq(child->name, "return")) {
			ni_xs_type_t *type;

			temp_scope = ni_xs_scope_new(scope, NULL);
			type = ni_xs_build_one_type(child, temp_scope);
			ni_xs_scope_free(temp_scope);

			if (type == NULL) {
				ni_error("%s: cannot parse <return> element", xml_node_location(node));
				return -1;
			}
			method->retval = type;
		} else
		if (ni_string_eq(child->name, "description")) {
			ni_string_dup(&method->description, child->cdata);
		} else
		if (ni_string_eq(child->name, "meta")) {
			xml_node_detach(child);
			method->meta = child;
		} else
		if (!strncmp(child->name, "meta:", 5)) {
			if (method->meta == NULL)
				method->meta = xml_node_new("meta", NULL);
			xml_node_reparent(method->meta, child);
			ni_string_dup(&child->name, child->name + 5);
		}
	}

	return 0;
}

/*
 * Process a <signal> declaration inside a service definition
 */
int
ni_xs_process_signal(xml_node_t *node, ni_xs_service_t *service, ni_xs_scope_t *scope)
{
	const char *nameAttr;
	ni_xs_method_t *signal;
	xml_node_t *child, *next;

	if (!(nameAttr = xml_node_get_attr(node, "name"))) {
		ni_error("%s: <%s> element lacks name attribute", xml_node_location(node), node->name);
		return -1;
	}

	signal = ni_xs_method_new(&service->signals, nameAttr);
	for (child = node->children; child; child = next) {
		ni_xs_scope_t *temp_scope;

		next = child->next;

		if (ni_string_eq(child->name, "arguments")) {
			temp_scope = ni_xs_scope_new(scope, NULL);
			if (ni_xs_build_typelist(child, &signal->arguments, temp_scope, TRUE, NULL) < 0) {
				ni_xs_scope_free(temp_scope);
				return -1;
			}

			ni_xs_scope_free(temp_scope);
		} else
		if (ni_string_eq(child->name, "description")) {
			ni_string_dup(&signal->description, child->cdata);
		}
	}

	return 0;
}

/*
 * Process a <include> element.
 */
int
ni_xs_process_include(xml_node_t *node, ni_xs_scope_t *scope)
{
	char pathbuf[PATH_MAX];
	const char *nameAttr;

	if (!(nameAttr = xml_node_get_attr(node, "name"))) {
		ni_error("%s: <include> element lacks name attribute", xml_node_location(node));
		return -1;
	}

	if (nameAttr[0] != '/') {
		xml_location_t *loc = node->location;

		if (loc && loc->shared) {
			char *copy = xstrdup(loc->shared->filename), *s;

			if ((s = strrchr(copy, '/')) != NULL)
				*s = '\0';
			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", copy, nameAttr);
			nameAttr = pathbuf;
			free(copy);
		}
	}

	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_XML, "trying to include %s", nameAttr);
	return ni_xs_process_schema_file(nameAttr, scope);
}

/*
 * Process an <object-class> element.
 */
int
ni_xs_process_class(xml_node_t *node, ni_xs_scope_t *scope)
{
	const char *nameAttr, *baseClassAttr;
	ni_xs_class_t *class, **tail;

	if (node->name == NULL || strcmp(node->name, "object-class")) {
		ni_error("%s: bad node name", xml_node_location(node));
		return -1;
	}

	if (!(nameAttr = xml_node_get_attr(node, "name"))) {
		ni_error("%s: <class> element lacks name attribute", xml_node_location(node));
		return -1;
	}
	if (!(baseClassAttr = xml_node_get_attr(node, "base-class"))) {
		ni_error("%s: <class> element lacks base-class attribute", xml_node_location(node));
		return -1;
	}

	for (tail = &scope->classes; (class = *tail) != NULL; tail = &class->next)
		;

	class = xcalloc(1, sizeof(*class));
	ni_string_dup(&class->name, nameAttr);
	ni_string_dup(&class->base_name, baseClassAttr);
	*tail = class;

	return 0;
}

/*
 * Process a <define> element.
 * This can define a type or a constant.
 */
int
ni_xs_process_define(xml_node_t *node, ni_xs_scope_t *scope)
{
	const char *nameAttr, *typeAttr;
	ni_xs_type_t *refType = NULL;

	if (node->name == NULL || strcmp(node->name, "define")) {
		ni_error("%s: bad node name", xml_node_location(node));
		return -1;
	}

	if (!(nameAttr = xml_node_get_attr(node, "name"))) {
		ni_error("%s: <define> element lacks name attribute", xml_node_location(node));
		return -1;
	}
	if (ni_xs_is_reserved_name(nameAttr)) {
		ni_error("%s: trying to <define> reserved name \"%s\"", xml_node_location(node), nameAttr);
		return -1;
	}

	if ((typeAttr = xml_node_get_attr(node, "class")) != NULL) {
		/* check for
		 *   <define name="..." class="(dict|array|struct|union)">...</define>
		 */
		ni_xs_type_t *newType;
		ni_xs_scope_t *context;

		/* create (permanent) named scope as context */
		context = ni_xs_scope_new(scope, nameAttr);

		newType = ni_xs_build_complex_type(node, typeAttr, context);
		if (newType == NULL) {
			ni_error("%s: cannot build schema for node <%s> (class \"%s\") in %s",
					xml_node_location(node), nameAttr, typeAttr, __func__);
			return -1;
		}

		refType = newType;
	} else
	if ((typeAttr = xml_node_get_attr(node, "type")) != NULL) {
		/* check for type aliasing - take one type, and define it by another name.
		 *  <define name="..." type="..."/>
		 */
		ni_xs_scope_t *context;

		/* create (permanent) named scope as context */
		context = ni_xs_scope_new(scope, nameAttr);

		refType = ni_xs_build_simple_type(node, typeAttr, context, NULL);
		if (refType == NULL) {
			ni_error("%s: definition of type <%s> references unknown base type <%s>",
					xml_node_location(node), nameAttr, typeAttr);
			return -1;
		}
	} else if (node->children != NULL) {
		/*
		 * <define> <type/> </define>
		 */
		refType = ni_xs_build_one_type(node, scope);
		if (refType == NULL)
			return -1;

		/* FIXME: build constraints if there are any */
	} else {
		const char *value;

		if ((value = node->cdata) == NULL)
			value = "";

		ni_var_array_set(&scope->constants, nameAttr, value);
		return 0;
	}

	refType = ni_xs_type_set_description(refType, node);

	if (ni_xs_scope_typedef(scope, nameAttr, refType, NULL) < 0) {
		ni_error("%s: attempt to redefine type <%s>", xml_node_location(node), nameAttr);
		ni_xs_type_release(refType);
		return -1;
	}

	ni_xs_type_release(refType);
	return 0;
}

int
ni_xs_build_typelist(xml_node_t *node, ni_xs_name_type_array_t *result, ni_xs_scope_t *scope,
			ni_bool_t allow_anon, ni_xs_group_array_t *group_array)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		const char *memberName = NULL;
		ni_xs_type_t *memberType;

		if (child->name == NULL) {
			ni_error("%s: NULL node name?!", xml_node_location(node));
			continue;
		}

		if (!strcmp(child->name, "define")) {
			if (ni_xs_process_define(child, scope) < 0)
				return -1;
			continue;
		}

		if (!strcmp(child->name, "description"))
			continue;

		if (ni_xs_is_class_name(child->name)) {
			/* <struct ...> <union ...> <dict ...> or <array ...> */
			ni_xs_scope_t *localdict;

			/* Create an anonymous scope and destroy it afterwards */
			localdict = ni_xs_scope_new(scope, NULL);

			memberType = ni_xs_build_complex_type(child, child->name, localdict);

			ni_xs_scope_free(localdict);
			if (memberType == NULL)
				return -1;
		} else {
			/* This can be either
			 *   <u32/> (or any other scalar type)
			 * or
			 *   <somename class="(dict|struct|union|array)">
			 * or
			 *   <somename type="othertype"/>
			 */
			memberType = ni_xs_scope_lookup(scope, child->name);
			if (memberType != NULL) {
				if (xml_node_get_attr(child, "class")
				 || xml_node_get_attr(child, "type")) {
					ni_error("%s: ambiguous type: node <%s> is a type, but has a type or class attribute",
							xml_node_location(child), child->name);
					return -1;
				}
				if (!allow_anon) {
					ni_error("%s: anonymous child elements not allowed in this context",
							xml_node_location(child));
					return -1;
				}
				ni_xs_type_hold(memberType);
			} else {
				ni_xs_scope_t *context;
				const char *typeAttr;

				memberName = child->name;

				if (ni_xs_is_reserved_name(memberName)) {
					ni_error("%s: named type node uses reserved name", xml_node_location(child));
					return -1;
				}

				if (ni_xs_scope_lookup(scope, memberName)) {
					ni_error("%s: ambiguous type for node <%s>", xml_node_location(child), memberName);
					return -1;
				}

				/* create (permanent) named scope as context */
				context = ni_xs_scope_new(scope, memberName);

				if ((typeAttr = xml_node_get_attr(child, "class")) != NULL) {
					memberType = ni_xs_build_complex_type(child, typeAttr, context);
					if (memberType == NULL) {
						ni_error("%s: unknown class \"%s\" in <%s>", xml_node_location(child), typeAttr, child->name);
						return -1;
					}
				} else
				if ((typeAttr = xml_node_get_attr(child, "type")) != NULL) {
					memberType = ni_xs_build_simple_type(child, typeAttr, context, group_array);
					if (memberType == NULL) {
						ni_error("%s: unknown type \"%s\" in <%s>", xml_node_location(child), typeAttr, child->name);
						return -1;
					}
				}
			}
		}

		ni_xs_name_type_array_append(result, memberName, memberType, ni_xs_get_description(child));
		ni_xs_type_release(memberType);
	}

	return result->count;
}

ni_xs_type_t *
ni_xs_build_complex_type(xml_node_t *node, const char *className, ni_xs_scope_t *scope)
{
	const char *typeAttr;
	ni_xs_type_t *type = NULL;

	if (className == NULL) {
		ni_error("%s: NULL class name?!", xml_node_location(node));
		return NULL;
	}

	if (!strcmp(className, "struct")) {
		const char *base_name;

		if ((base_name = xml_node_get_attr(node, "extends")) != NULL) {
			ni_xs_type_t *base_type;
			ni_xs_struct_info_t *struct_info;

			base_type = ni_xs_scope_lookup(scope, base_name);
			if (base_type == NULL) {
				ni_error("%s: base type \"%s\" not known in this scope",
						xml_node_location(node), base_name);
				return NULL;
			}
			if (base_type->class != NI_XS_TYPE_STRUCT) {
				ni_error("%s: base type \"%s\" not compatible",
						xml_node_location(node), base_name);
				return NULL;
			}

			struct_info = ni_xs_struct_info(base_type);
			type = ni_xs_struct_new(&struct_info->children);
		} else {
			type = ni_xs_struct_new(NULL);
		}

		if (ni_xs_build_typelist(node, &type->u.struct_info->children, scope, TRUE, NULL) < 0) {
			ni_xs_type_free(type);
			return NULL;
		}
	} else
	if (!strcmp(className, "union")) {
		const char *disc_name;

		if ((disc_name = xml_node_get_attr(node, "switch")) == NULL) {
			ni_error("%s: discriminated union lacking switch attribute",
					xml_node_location(node));
			return NULL;
		}
		type = ni_xs_union_new(NULL, disc_name);
		if (ni_xs_build_typelist(node, &type->u.union_info->children, scope, TRUE, NULL) < 0) {
			ni_xs_type_free(type);
			return NULL;
		}
	} else
	if (!strcmp(className, "array")) {
		ni_xs_type_t *elementType = NULL;
		unsigned long minlen = 0, maxlen = ULONG_MAX;
		const ni_xs_notation_t *notation = NULL;
		const char *attrValue;
		const char *elementName = NULL;

		if ((typeAttr = xml_node_get_attr(node, "element-type")) != NULL) {
			elementType = ni_xs_scope_lookup(scope, typeAttr);
			if (elementType == NULL) {
				ni_error("%s: array definition references unknown element type <%s>", __func__, typeAttr);
				return NULL;
			}
		} else {
			elementType = ni_xs_build_one_type(node, scope);
			if (elementType == NULL)
				return NULL;
		}

		if ((attrValue = xml_node_get_attr(node, "element-name")) != NULL && *attrValue)
			elementName = attrValue;
		if ((attrValue = xml_node_get_attr(node, "minlen")) != NULL)
			minlen = strtoul(attrValue, NULL, 0);
		if ((attrValue = xml_node_get_attr(node, "maxlen")) != NULL)
			maxlen = strtoul(attrValue, NULL, 0);

		if (elementType->class == NI_XS_TYPE_SCALAR
		 && (attrValue = xml_node_get_attr(node, "notation")) != NULL) {
			notation = ni_xs_get_array_notation(attrValue);
			if (notation == NULL) {
				ni_error("%s: array definition references unknown notation \"%s\"", __func__, attrValue);
				ni_xs_type_release(elementType);
				return NULL;
			}
			if (notation->array_element_type != elementType->u.scalar_info->type) {
				ni_error("%s: array definition references incompatible notation \"%s\"", __func__, attrValue);
				ni_xs_type_release(elementType);
				return NULL;
			}
		}

		type = ni_xs_array_new(elementType, elementName, minlen, maxlen);
		type->u.array_info->notation = notation;
		ni_xs_type_release(elementType);
	} else
	if (!strcmp(className, "dict")) {
		ni_xs_dict_info_t *dict_info;
		const char *base_name;
		unsigned int i;

		if ((base_name = xml_node_get_attr(node, "extends")) != NULL) {
			ni_xs_type_t *base_type;

			base_type = ni_xs_scope_lookup(scope, base_name);
			if (base_type == NULL) {
				ni_error("%s: base type \"%s\" not known in this scope",
						xml_node_location(node), base_name);
				return NULL;
			}
			if (base_type->class != NI_XS_TYPE_DICT) {
				ni_error("%s: base type \"%s\" not compatible",
						xml_node_location(node), base_name);
				return NULL;
			}

			dict_info = ni_xs_dict_info(base_type);
			type = ni_xs_dict_new(&dict_info->children);
		} else {
			type = ni_xs_dict_new(NULL);
		}

		if (ni_xs_build_typelist(node, &type->u.dict_info->children, scope, FALSE, &type->u.dict_info->groups) < 0) {
			ni_xs_type_free(type);
			return NULL;
		}

		/* ensure that all child types are named */
		dict_info = type->u.dict_info;
		for (i = 0; i < dict_info->children.count; ++i) {
			if (dict_info->children.data[i].name == NULL) {
				ni_error("%s: dict definition has child element without name", xml_node_location(node));
				return NULL;
			}
		}
	} else
	if (!strcmp(className, "void")) {
		type = ni_xs_type_new(NI_XS_TYPE_VOID);
	} else {
		ni_error("%s: unknown class=\"%s\"", xml_node_location(node), className);
		return NULL;
	}

	if (type)
		type = ni_xs_type_set_description(type, node);

	return type;
}

/*
 * Build a simple type (by referencing another type).
 */
ni_xs_type_t *
ni_xs_build_simple_type(xml_node_t *node, const char *typeName, ni_xs_scope_t *scope, ni_xs_group_array_t *group_array)
{
	ni_xs_type_t *result;
	xml_node_t *child, *next, *meta;

	if (typeName == NULL) {
		ni_error("%s: NULL type name?!", xml_node_location(node));
		return NULL;
	}

	result = ni_xs_scope_lookup(scope, typeName);
	if (result == NULL)
		return NULL;

	ni_xs_type_hold(result);
	if (!ni_xs_type_build_constraints(&result, node, group_array)) {
		ni_xs_type_release(result);
		return NULL;
	}

	/* If we find any <meta> type inside a scalar type definition,
	 * detach it from the schema xml tree and store it in the scalar
	 * type node for later use.
	 * <meta:foobar> is a shorthand for <foobar> nested inside <meta>.
	 */
	meta = NULL;
	for (child = node->children; child; child = next) {
		next = child->next;
		if (ni_string_eq(child->name, "meta")) {
			if (meta) {
				ni_error("%s: duplicate <meta> elements", xml_node_location(node));
			} else {
				xml_node_detach(child);
				meta = child;
			}
		} else
		if (!strncasecmp(child->name, "meta:", 5)) {
			if (meta == NULL)
				meta = xml_node_new("meta", NULL);
			xml_node_reparent(meta, child);
			ni_string_dup(&child->name, child->name + 5);
		}
	}
	if (meta) {
		result = ni_xs_type_clone_and_release(result);
		if (result->meta)
			ni_error("%s: overwriting <meta> info of node", xml_node_location(node));
		else
			result->meta = meta;
	}

	return result;
}

/*
 * Evaluate constraints associated with a type
 */
ni_bool_t
ni_xs_type_build_constraints(ni_xs_type_t **type_p, const xml_node_t *node, ni_xs_group_array_t *group_array)
{
	ni_xs_type_t *type = *type_p;
	const ni_var_t *attr;
	unsigned int i;

	for (i = 0, attr = node->attrs.data; i < node->attrs.count; ++i, ++attr) {
		const char *attrValue;

		if (!ni_string_eq(attr->name, "constraint"))
			continue;

		*type_p = type = ni_xs_type_clone_and_release(type);

		attrValue = attr->value;

		if (!strcmp(attrValue, "required")) {
			type->constraint.mandatory = TRUE;
			continue;
		}
		if (!strncmp(attrValue, "required:", 9)) {
			if (type->constraint.group) {
				ni_error("%s: conflicting group constraints",
						xml_node_location(node));
				return FALSE;
			}
			type->constraint.group = ni_xs_group_get(group_array, NI_XS_GROUP_CONSTRAINT_REQUIRE, attrValue + 9);
			continue;
		}
		if (!strncmp(attrValue, "exclusive:", 10)) {
			if (type->constraint.group) {
				ni_error("%s: conflicting group constraints",
						xml_node_location(node));
				return FALSE;
			}
			type->constraint.group = ni_xs_group_get(group_array, NI_XS_GROUP_CONSTRAINT_CONFLICT, attrValue + 10);
			continue;
		}

		if (type->class == NI_XS_TYPE_SCALAR) {
#if 0
			ni_xs_scalar_info_t *scalar_info;

			scalar_info = ni_xs_scalar_info(type);
			if(scalar_info) /* FIXME: unused */
				;
#endif
			if (!strcmp(attrValue, "bitmask")) {
				ni_xs_intmap_t *map;

				if (!(map = ni_xs_build_bitmask_constraint(node)))
					return FALSE;
				ni_xs_scalar_set_bitmask(type, map);
				ni_xs_intmap_free(map);
				continue;
			} else
			if (!strcmp(attrValue, "bitmap")) {
				ni_xs_intmap_t *map;

				if (!(map = ni_xs_build_bitmap_constraint(node)))
					return FALSE;
				ni_xs_scalar_set_bitmap(type, map);
				ni_xs_intmap_free(map);
				continue;
			} else
			if (!strcmp(attrValue, "enum")) {
				ni_xs_intmap_t *map;

				if (!(map = ni_xs_build_enum_constraint(node)))
					return FALSE;
				ni_xs_scalar_set_enum(type, map);
				ni_xs_intmap_free(map);
				continue;
			} else
			if (!strcmp(attrValue, "range")) {
				ni_xs_range_t *range;

				if (!(range = ni_xs_build_range_constraint(node)))
					return FALSE;

				ni_xs_scalar_set_range(type, range);
				ni_xs_range_free(range);
				continue;
			}
		}

		ni_warn("%s: unknown constraint=\"%s\"", xml_node_location(node), attrValue);
	}

	return TRUE;
}

/*
 * Build an intmap from a list of xml nodes. The mapping from name to value is
 *  <name attr="..."/>
 * where name specifies the name of the value. The attribute can be either
 * "bit" or "value".
 * An optional name attribte permits to specify the map name and permits to use
 * e.g. names starting with a number:
 *  <map name="64bit" attr="1"/>
 *
 */
static ni_intmap_t *
__ni_xs_intmap_build(const xml_node_t *node, const char *attr_name)
{
	ni_intmap_t *result = NULL;
	unsigned int i, count;
	xml_node_t *child;

	/* Count the defined bits */
	for (child = node->children, count = 0; child; child = child->next, ++count)
		;

	result = xcalloc(count + 1, sizeof(ni_intmap_t));
	for (child = node->children, i = 0; child; child = child->next) {
		const char *attr_value;
		const char *name_value;
		unsigned int value;
		char *ep = NULL;

		if (!(name_value = xml_node_get_attr(child, "name")))
			name_value = child->name;

		attr_value = xml_node_get_attr(child, attr_name);
		if (attr_value == NULL) {
			if (ni_string_eq(name_value, "description"))
				continue;

			ni_debug_wicked_xml(child, NI_LOG_DEBUG3,
				"ignoring %s enum/bitmap element without %s attribute",
				node->name, attr_name);
			continue;
		}

		value = strtoul(attr_value, &ep, 0);
		if (*ep != '\0') {
			ni_error("%s: bad enum/bitmap element <%s %s=\"%s\"> in constraints",
					xml_node_location(child), name_value,
					attr_name, attr_value);
			goto failed;
		}

		result[i].name = xstrdup(name_value);
		result[i].value = value;
		i++;
	}

	return result;

failed:
	__ni_xs_intmap_free(result);
	return NULL;
}

static void
__ni_xs_intmap_free(ni_intmap_t *map)
{
	ni_intmap_t *p;

	if (map != NULL) {
		for (p = map; p->name; ++p)
			free((char *) p->name);
		free(map);
	}
}

static ni_xs_intmap_t *
ni_xs_intmap_build(const xml_node_t *node, const char *attr_name)
{
	ni_xs_intmap_t *result;
	ni_intmap_t *bitmap;

	if (!(bitmap = __ni_xs_intmap_build(node, attr_name)))
		return NULL;

	result = xcalloc(1, sizeof(*result));
	result->refcount = 1;
	result->bits = bitmap;
	return result;
}

ni_xs_intmap_t *
ni_xs_build_bitmap_constraint(const xml_node_t *node)
{
	return ni_xs_intmap_build(node, "bit");
}

ni_xs_intmap_t *
ni_xs_build_bitmask_constraint(const xml_node_t *node)
{
	return ni_xs_intmap_build(node, "value");
}

void
ni_xs_intmap_free(ni_xs_intmap_t *constraint)
{
	ni_assert(constraint->refcount);
	if (--(constraint->refcount) == 0) {
		__ni_xs_intmap_free(constraint->bits);
		free(constraint);
	}
}

ni_xs_intmap_t *
ni_xs_build_enum_constraint(const xml_node_t *node)
{
	return ni_xs_intmap_build(node, "value");
}

ni_xs_range_t *
ni_xs_range_new(unsigned long min, unsigned long max)
{
	ni_xs_range_t *range;

	range = xcalloc(1, sizeof(*range));
	range->refcount = 1;
	range->min = min;
	range->max = max;
	return range;
}

void
ni_xs_range_free(ni_xs_range_t *constraint)
{
	ni_assert(constraint->refcount);
	if (--(constraint->refcount) == 0)
		free(constraint);
}

ni_xs_range_t *
ni_xs_build_range_constraint(const xml_node_t *node)
{
	unsigned long min = 0, max = ~0UL;
	const char *attr;

	if ((attr = xml_node_get_attr(node, "min")) != NULL) {
		if (ni_parse_ulong(attr, &min, 0)) {
			ni_error("%s: invalid min value for range constraint",
					xml_node_location(node));
			return NULL;
		}
	}
	if ((attr = xml_node_get_attr(node, "max")) != NULL) {
		if (ni_parse_ulong(attr, &max, 0)) {
			ni_error("%s: invalid max value for range constraint",
					xml_node_location(node));
			return NULL;
		}
	}

	if (min > max) {
		ni_error("%s: invalid range constraint", xml_node_location(node));
		return NULL;
	}

	return ni_xs_range_new(min, max);
}

void
ni_xs_scalar_set_bitmask(ni_xs_type_t *type, ni_xs_intmap_t *map)
{
	ni_xs_scalar_info_t *scalar_info;

	if (map) {
		ni_assert(map->refcount);
		map->refcount++;

		/* FIXME: warn if there's a conflicting scalar constraint */
	}

	scalar_info = ni_xs_scalar_info(type);
	ni_assert(scalar_info);

	if (scalar_info->constraint.bitmask)
		ni_xs_intmap_free(scalar_info->constraint.bitmask);
	scalar_info->constraint.bitmask = map;
}

void
ni_xs_scalar_set_bitmap(ni_xs_type_t *type, ni_xs_intmap_t *map)
{
	ni_xs_scalar_info_t *scalar_info;

	if (map) {
		ni_assert(map->refcount);
		map->refcount++;

		/* FIXME: warn if there's a conflicting scalar constraint */
	}

	scalar_info = ni_xs_scalar_info(type);
	ni_assert(scalar_info);

	if (scalar_info->constraint.bitmap)
		ni_xs_intmap_free(scalar_info->constraint.bitmap);
	scalar_info->constraint.bitmap = map;
}

void
ni_xs_scalar_set_enum(ni_xs_type_t *type, ni_xs_intmap_t *map)
{
	ni_xs_scalar_info_t *scalar_info;

	if (map) {
		ni_assert(map->refcount);
		map->refcount++;

		/* FIXME: warn if there's a conflicting scalar constraint */
	}

	scalar_info = ni_xs_scalar_info(type);
	ni_assert(scalar_info);

	if (scalar_info->constraint.enums)
		ni_xs_intmap_free(scalar_info->constraint.enums);
	scalar_info->constraint.enums = map;
}

void
ni_xs_scalar_set_range(ni_xs_type_t *type, ni_xs_range_t *range)
{
	ni_xs_scalar_info_t *scalar_info;

	if (range) {
		ni_assert(range->refcount);
		range->refcount++;

		/* FIXME: warn if there's a conflicting scalar constraint */
	}

	scalar_info = ni_xs_scalar_info(type);
	ni_assert(scalar_info);

	if (scalar_info->constraint.range)
		ni_xs_range_free(scalar_info->constraint.range);
	scalar_info->constraint.range = range;
}

const char *
ni_xs_get_description(const xml_node_t *node)
{
	const char *description;
	xml_node_t *dnode;

	if ((description = xml_node_get_attr(node, "description")) != NULL)
		return description;

	if ((dnode = xml_node_get_child(node, "description")) != NULL)
		return dnode->cdata;

	return NULL;
}

ni_xs_type_t *
ni_xs_type_set_description(ni_xs_type_t *type, const xml_node_t *node)
{
	const char *description;

	if ((description = ni_xs_get_description(node)) != NULL) {
		type = ni_xs_type_clone_and_release(type);
		ni_string_dup(&type->description, description);
	}

	return type;
}

/*
 * Handling of group constraints
 */
ni_xs_group_t *
ni_xs_group_new(int kind, const char *name)
{
	ni_xs_group_t *group;

	group = xcalloc(1, sizeof(*group));
	ni_string_dup(&group->name, name);
	group->relation = kind;
	group->refcount = 1;

	return group;
}

ni_xs_group_t *
ni_xs_group_clone(ni_xs_group_t *group)
{
	if (group == NULL)
		return NULL;

	ni_assert(group->refcount);
	group->refcount++;
	return group;
}

void
ni_xs_group_array_append(ni_xs_group_array_t *group_array, ni_xs_group_t *group)
{
	group_array->data = xrealloc(group_array->data, (group_array->count + 1) * sizeof(group));
	group_array->data[group_array->count++] = ni_xs_group_clone(group);
}

void
ni_xs_group_array_copy(ni_xs_group_array_t *dst, const ni_xs_group_array_t *src)
{
	unsigned int i;

	for (i = 0; i < src->count; ++i)
		ni_xs_group_array_append(dst, src->data[i]);
}

ni_xs_group_t *
ni_xs_group_get(ni_xs_group_array_t *group_array, unsigned int kind, const char *name)
{
	ni_xs_group_t *group;
	unsigned int i;

	for (i = 0; i < group_array->count; ++i) {
		group = group_array->data[i];
		if (group->relation == kind && ni_string_eq(group->name, name))
			return ni_xs_group_clone(group);
	}

	group = ni_xs_group_new(kind, name);
	ni_xs_group_array_append(group_array, group);
	return group;
}

void
ni_xs_group_free(ni_xs_group_t *group)
{
	if (group == NULL)
		return;

	ni_assert(group->refcount);
	if (--(group->refcount) == 0) {
		ni_string_free(&group->name);
		free(group);
	}
}

void
ni_xs_group_array_destroy(ni_xs_group_array_t *group_array)
{
	unsigned int i;

	for (i = 0; i < group_array->count; ++i)
		ni_xs_group_free(group_array->data[i]);

	free(group_array->data);
	group_array->data = NULL;
}

/*
 * Process a list of XML child elements, which consists of zero or more
 * <define> elements, and exactly one type element, which is either a
 * scalar type (like <uint32>), or a complex type (like <dict>).
 *
 * Note that <foobar type="uint32"> forms are not allowed here.
 */
ni_xs_type_t *
ni_xs_build_one_type(xml_node_t *node, ni_xs_scope_t *scope)
{
	ni_xs_type_t *result = NULL;
	xml_node_t *child;

	if (node->children == NULL) {
		ni_error("%s: cannot build type, empty context", xml_node_location(node));
		return NULL;
	}

	for (child = node->children; child != NULL; child = child->next) {
		if (!strcmp(child->name, "define")) {
			if (ni_xs_process_define(child, scope) < 0)
				goto error;
			continue;
		}
		if (!strcmp(child->name, "description"))
			continue;
		if (result != NULL) {
			ni_error("%s: definition of type is ambiguous", xml_node_location(node));
			goto error;
		}

		if (ni_xs_is_class_name(child->name)) {
			ni_xs_scope_t *localdict;

			/* Create an anonymous scope */
			localdict = ni_xs_scope_new(scope, NULL);
			result = ni_xs_build_complex_type(child, child->name, localdict);
			ni_xs_scope_free(localdict);
		} else {
			result = ni_xs_scope_lookup(scope, child->name);
			ni_xs_type_hold(result);
		}
		if (result == NULL) {
			ni_error("%s: unknown type or class <%s>", xml_node_location(child), child->name);
			goto error;
		}
	}

	if (result == NULL) {
		ni_error("%s: cannot build type, no type element in this context", xml_node_location(node));
		goto error;
	}

	return result;

error:
	ni_xs_type_release(result);
	return NULL;
}

/*
 * Handle different array notations
 */
#define NI_XS_NOTATIONS_MAX	64
static const ni_xs_notation_t *	array_notations[NI_XS_NOTATIONS_MAX];
static unsigned int		num_array_notations;

void
ni_xs_register_array_notation(const ni_xs_notation_t *notation)
{
	ni_assert(num_array_notations < NI_XS_NOTATIONS_MAX);
	ni_assert(notation->name != NULL);
	array_notations[num_array_notations++] = notation;
}


const ni_xs_notation_t *
ni_xs_get_array_notation(const char *name)
{
	unsigned int i;

	for (i = 0; i < num_array_notations; ++i) {
		const ni_xs_notation_t *notation = array_notations[i];

		if (!strcmp(notation->name, name))
			return notation;
	}
	return NULL;
}
