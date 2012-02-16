/*
 * Simple XML schema, in no way intended to be conforming to any standard.
 *
 * Copyright (C) 2012, Olaf Kirch <okir@suse.de>
 */

#include <limits.h>
#include <stdlib.h>
#include <wicked/logging.h>
#include <wicked/xml.h>
#include <wicked/logging.h>
#include "xml-schema.h"
#include "util_priv.h"

static int		ni_xs_process_include(xml_node_t *, ni_xs_scope_t *);
static int		ni_xs_process_define(xml_node_t *, ni_xs_scope_t *);
static int		ni_xs_process_service(xml_node_t *, ni_xs_scope_t *);
static int		ni_xs_process_method(xml_node_t *, ni_xs_service_t *, ni_xs_scope_t *);
static int		ni_xs_build_typelist(xml_node_t *, ni_xs_name_type_array_t *, ni_xs_scope_t *);
static ni_xs_type_t *	ni_xs_build_simple_type(xml_node_t *, const char *, ni_xs_scope_t *);
static ni_xs_type_t *	ni_xs_build_complex_type(xml_node_t *, const char *, ni_xs_scope_t *);
static void		ni_xs_name_type_array_copy(ni_xs_name_type_array_t *, const ni_xs_name_type_array_t *);
static void		ni_xs_name_type_array_destroy(ni_xs_name_type_array_t *);
static ni_xs_type_t *	ni_xs_build_one_type(xml_node_t *, ni_xs_scope_t *);
static ni_xs_type_t *	ni_xs_scope_lookup(const ni_xs_scope_t *, const char *);
static ni_xs_type_t *	ni_xs_scope_lookup_local(const ni_xs_scope_t *, const char *);
static void		ni_xs_service_free(ni_xs_service_t *);
static struct ni_xs_type_constraint_bitmap *ni_xs_build_bitmap_constraint(const xml_node_t *);

/*
 * Constructor functions for basic and complex types
 */
static ni_xs_type_t *
__ni_xs_type_new(unsigned int class)
{
	ni_xs_type_t *type = calloc(1, sizeof(*type));

	type->refcount = 1;
	type->class = class;
	return type;
}

ni_xs_type_t *
ni_xs_scalar_new(unsigned int scalar_type)
{
	ni_xs_type_t *type = __ni_xs_type_new(NI_XS_TYPE_SCALAR);

	type->u.scalar_info = xcalloc(1, sizeof(ni_xs_scalar_info_t));
	type->u.scalar_info->type = scalar_type;
	return type;
}

ni_xs_type_t *
ni_xs_struct_new(ni_xs_name_type_array_t *children)
{
	ni_xs_type_t *type = __ni_xs_type_new(NI_XS_TYPE_STRUCT);

	type->u.struct_info = xcalloc(1, sizeof(ni_xs_struct_info_t));
	if (children)
		ni_xs_name_type_array_copy(&type->u.struct_info->children, children);
	return type;
}

ni_xs_type_t *
ni_xs_dict_new(ni_xs_name_type_array_t *children)
{
	ni_xs_type_t *type = __ni_xs_type_new(NI_XS_TYPE_DICT);

	type->u.dict_info = xcalloc(1, sizeof(ni_xs_dict_info_t));
	if (children)
		ni_xs_name_type_array_copy(&type->u.dict_info->children, children);
	return type;
}

ni_xs_type_t *
ni_xs_array_new(ni_xs_type_t *elementType, unsigned long minlen, unsigned long maxlen)
{
	ni_xs_type_t *type = __ni_xs_type_new(NI_XS_TYPE_ARRAY);

	type->u.array_info = calloc(1, sizeof(struct ni_xs_array_info));
	type->u.array_info->element_type = ni_xs_type_hold(elementType);
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
	case NI_XS_TYPE_SCALAR:
		{
			ni_xs_scalar_info_t *scalar_info = src->u.scalar_info;

			dst = ni_xs_scalar_new(scalar_info->type);

			/* FIXME: should we clone the constraints as well? */
			break;
		}

	case NI_XS_TYPE_DICT:
		{
			ni_xs_dict_info_t *dict_info = src->u.dict_info;

			dst = ni_xs_dict_new(&dict_info->children);
			break;
		}

	case NI_XS_TYPE_STRUCT:
		{
			ni_xs_struct_info_t *struct_info = src->u.struct_info;

			dst = ni_xs_struct_new(&struct_info->children);
			break;
		}

	case NI_XS_TYPE_ARRAY:
		{
			ni_xs_array_info_t *src_array_info = src->u.array_info;

			dst = ni_xs_array_new(src_array_info->element_type,
					src_array_info->minlen,
					src_array_info->maxlen);
			dst->u.array_info->notation = src_array_info->notation;
			break;
		}

	}

	return dst;
}

void
ni_xs_type_free(ni_xs_type_t *type)
{
	switch (type->class) {
	case NI_XS_TYPE_DICT:
		{
			ni_xs_dict_info_t *dict_info = type->u.dict_info;

			ni_xs_name_type_array_destroy(&dict_info->children);
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

	case NI_XS_TYPE_ARRAY:
		{
			ni_xs_array_info_t *array_info = type->u.array_info;

			ni_xs_type_release(array_info->element_type);
			free(array_info);
			type->u.array_info = NULL;
			break;
		}

	case NI_XS_TYPE_SCALAR:
		{
			ni_xs_scalar_info_t *scalar_info = type->u.scalar_info;

			free(scalar_info);
			type->u.scalar_info = NULL;

			/* FIXME: free constraint data */
			break;
		}
	}

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
		array->data = realloc(array->data, (array->count + 32) * sizeof(array->data[0]));
	array->data[array->count++] = ni_xs_type_hold(type);
}

/*
 * Array of name/type pairs. These are used in structs, dict and type dicts.
 */
ni_xs_name_type_array_t *
ni_xs_name_type_array_new(void)
{
	ni_xs_name_type_array_t *array = calloc(1, sizeof(*array));
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
ni_xs_name_type_array_append(ni_xs_name_type_array_t *array, const char *name, ni_xs_type_t *type)
{
	ni_xs_name_type_t *def;

	if ((array->count % 32) == 0) {
		array->data = realloc(array->data, (array->count + 32) * sizeof(array->data[0]));
	}
	def = &array->data[array->count++];
	def->name = xstrdup(name);
	def->type = ni_xs_type_hold(type);
}

void
ni_xs_name_type_array_copy(ni_xs_name_type_array_t *dst, const ni_xs_name_type_array_t *src)
{
	ni_xs_name_type_t *def;
	unsigned int i;

	if (dst->count)
		ni_xs_name_type_array_destroy(dst);
	for (i = 0, def = src->data; i < src->count; ++i, ++def)
		ni_xs_name_type_array_append(dst, def->name, def->type);
}

static ni_xs_type_t *
__ni_xs_name_type_array_find(const ni_xs_name_type_array_t *array, const char *name)
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
	return __ni_xs_name_type_array_find(array, name);
}

/*
 * Scopes in the schema hierarchy
 */
ni_xs_scope_t *
ni_xs_scope_new(ni_xs_scope_t *parent, const char *name)
{
	ni_xs_scope_t *scope = calloc(1, sizeof(ni_xs_scope_t));

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

		for (child = scope->children; child; child = child->next) {
			scope->children = child->next;
			child->parent = NULL; /* Skip the debug step when freeing the child scope */
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

static const ni_xs_scope_t *
ni_xs_scope_lookup_scope(const ni_xs_scope_t *scope, const char *name)
{
	for (scope = scope->children; scope; scope = scope->next) {
		if (!strcmp(scope->name, name))
			return scope;
	}
	return NULL;
}

static ni_xs_type_t *
ni_xs_scope_lookup_local(const ni_xs_scope_t *dict, const char *name)
{
	return __ni_xs_name_type_array_find(&dict->types, name);
}

static ni_xs_type_t *
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
ni_xs_scope_typedef(ni_xs_scope_t *dict, const char *name, ni_xs_type_t *type)
{
	if (ni_xs_scope_lookup_local(dict, name) != NULL)
		return -1;
	ni_debug_xml("define type %s in scope %s", name, dict->name?: "<anon>");
	ni_xs_name_type_array_append(&dict->types, name, type);
	return 0;
}

/*
 * Service definitions
 */
static ni_xs_method_t *
ni_xs_method_new(const char *name, ni_xs_service_t *service)
{
	ni_xs_method_t *method, **tail;

	method = xcalloc(1, sizeof(*method));
	ni_string_dup(&method->name, name);

	for (tail = &service->methods; *tail; tail = &(*tail)->next)
		;
	*tail = method;

	return method;
}

static void
ni_xs_method_free(ni_xs_method_t *method)
{
	ni_string_free(&method->name);
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
	ni_string_free(&service->name);
	ni_string_free(&service->interface);

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
		"scalar", "dict", "struct", "array",
		NULL
	};

	return __string_is_in_list(name, class_names);
}

static int
ni_xs_is_reserved_name(const char *name)
{
	static const char *reserved[] = {
		"dict", "struct", "array", "define", "choice",
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

	ni_debug_xml("ni_xs_process_schema_file(filename=%s)", filename);
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

	ni_debug_dbus("define schema for service %s (interface=%s) in scope %s", nameAttr, intfAttr, scope->name);
	service = ni_xs_service_new(nameAttr, intfAttr, scope);

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

		if (!strcmp(child->name, "define")) {
			if ((rv = ni_xs_process_define(child, sub_scope)) < 0)
				return rv;
		} else
		if (!strcmp(child->name, "method")) {
			if ((rv = ni_xs_process_method(child, service, sub_scope)) < 0)
				return rv;
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
	xml_node_t *child;

	if (!(nameAttr = xml_node_get_attr(node, "name"))) {
		ni_error("%s: <method> element lacks name attribute", xml_node_location(node));
		return -1;
	}

	method = ni_xs_method_new(nameAttr, service);
	if ((child = xml_node_get_child(node, "arguments")) != NULL) {
		ni_xs_scope_t *temp_scope;

		temp_scope = ni_xs_scope_new(scope, NULL);
		if (ni_xs_build_typelist(child, &method->arguments, temp_scope) < 0) {
			ni_xs_scope_free(temp_scope);
			return -1;
		}

		ni_xs_scope_free(temp_scope);
	}

	if ((child = xml_node_get_child(node, "return")) != NULL) {
		ni_xs_scope_t *temp_scope = ni_xs_scope_new(scope, NULL);
		ni_xs_type_t *type;

		type = ni_xs_build_one_type(child, temp_scope);
		ni_xs_scope_free(temp_scope);

		if (type == NULL) {
			ni_error("%s: cannot parse <return> element", xml_node_location(node));
			return -1;
		}
		method->retval = ni_xs_type_hold(type);
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
		struct xml_location *loc = node->location;

		if (loc && loc->shared) {
			char *copy = strdup(loc->shared->filename), *s;

			if ((s = strrchr(copy, '/')) != NULL)
				*s = '\0';
			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", copy, nameAttr);
			nameAttr = pathbuf;
			free(copy);
		}
	}

	ni_debug_xml("trying to include %s", nameAttr);
	return ni_xs_process_schema_file(nameAttr, scope);
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
		 *   <define name="..." class="(dict|array|struct)">...</define>
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

		if (ni_xs_scope_typedef(scope, nameAttr, newType) < 0) {
			ni_error("%s: attempt to redefine type <%s>", xml_node_location(node), nameAttr);
			ni_xs_type_release(newType);
			return -1;
		}
		ni_xs_type_release(newType);
	} else
	if ((typeAttr = xml_node_get_attr(node, "type")) != NULL) {
		/* check for type aliasing - take one type, and define it by another name.
		 *  <define name="..." type="..."/>
		 */
		ni_xs_scope_t *context;

		/* create (permanent) named scope as context */
		context = ni_xs_scope_new(scope, nameAttr);

		refType = ni_xs_build_simple_type(node, typeAttr, context);
		if (refType == NULL) {
			ni_error("%s: definition of type <%s> references unknown base type <%s>",
					xml_node_location(node), nameAttr, typeAttr);
			return -1;
		}

		if (ni_xs_scope_typedef(scope, nameAttr, refType) < 0) {
			ni_error("%s: attempt to redefine type <%s>", xml_node_location(node), nameAttr);
			return -1;
		}
		ni_xs_type_release(refType);
	} else if (node->children != NULL) {
		/*
		 * <define> <type/> </define>
		 */
		refType = ni_xs_build_one_type(node, scope);
		if (refType == NULL)
			return -1;

		/* FIXME: build constraints if there are any */

		if (ni_xs_scope_typedef(scope, nameAttr, refType) < 0) {
			ni_error("%s: attempt to redefine type <%s>", xml_node_location(node), nameAttr);
			ni_xs_type_release(refType);
			return -1;
		}
		ni_xs_type_release(refType);
	} else {
		const char *value;

		if ((value = node->cdata) == NULL)
			value = "";

		ni_var_array_set(&scope->constants, nameAttr, value);
	}

	return 0;
}

int
ni_xs_build_typelist(xml_node_t *node, ni_xs_name_type_array_t *result, ni_xs_scope_t *scope)
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

		if (ni_xs_is_class_name(child->name)) {
			/* <struct ...> <dict ...> or <array ...> */
			ni_xs_scope_t *localdict;

			/* Create an anonymous scope and destroy it afterwards */
			localdict = ni_xs_scope_new(scope, NULL);

			memberType = ni_xs_build_complex_type(child, child->name, localdict);

			ni_xs_scope_free(localdict);
			if (memberType == NULL)
				return -1;
		} else {
			/* This can be either
			 *   <u32/>
			 * or
			 *   <somename class="(dict|struct|array)">
			 * or
			 *   <somename type="othertype"/>
			 */
			memberType = ni_xs_scope_lookup(scope, child->name);
			if (memberType != NULL) {
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
				} else
				if ((typeAttr = xml_node_get_attr(child, "type")) != NULL) {
					memberType = ni_xs_build_simple_type(child, typeAttr, context);
				}

				if (memberType == NULL) {
					ni_error("%s: unknown type <%s>", xml_node_location(child), child->name);
					return -1;
				}
			}
		}

		ni_xs_name_type_array_append(result, memberName, memberType);
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

		if (ni_xs_build_typelist(node, &type->u.struct_info->children, scope) < 0) {
			ni_xs_type_free(type);
			return NULL;
		}
	} else
	if (!strcmp(className, "array")) {
		ni_xs_type_t *elementType = NULL;
		unsigned long minlen = 0, maxlen = ULONG_MAX;
		const ni_xs_notation_t *notation = NULL;
		const char *attrValue;

		if ((typeAttr = xml_node_get_attr(node, "element-type")) != NULL) {
			elementType = ni_xs_scope_lookup(scope, typeAttr);
			if (elementType == NULL) {
				ni_error("%s: array definition references unknown element type <%s>", __func__, typeAttr);
				return NULL;
			}
			ni_xs_type_hold(elementType);
		} else {
			elementType = ni_xs_build_one_type(node, scope);
			if (elementType == NULL)
				return NULL;
		}

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

		type = ni_xs_array_new(elementType, minlen, maxlen);
		type->u.array_info->notation = notation;
		ni_xs_type_release(elementType);
	} else
	if (!strcmp(className, "dict")) {
		const char *base_name;

		if ((base_name = xml_node_get_attr(node, "extends")) != NULL) {
			ni_xs_type_t *base_type;
			ni_xs_dict_info_t *dict_info;

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

		if (ni_xs_build_typelist(node, &type->u.dict_info->children, scope) < 0) {
			ni_xs_type_free(type);
			return NULL;
		}

		/* FIXME: ensure that all child types are named */
	} else {
		ni_error("%s: unknown class=\"%s\"", xml_node_location(node), className);
		return NULL;
	}

	return type;
}

/*
 * Build a simple type (by referencing another type).
 */
ni_xs_type_t *
ni_xs_build_simple_type(xml_node_t *node, const char *typeName, ni_xs_scope_t *scope)
{
	const char *attrValue;
	ni_xs_type_t *result;

	if (typeName == NULL) {
		ni_error("%s: NULL type name?!", xml_node_location(node));
		return NULL;
	}

	result = ni_xs_scope_lookup(scope, typeName);
	if (result == NULL)
		return NULL;

	ni_xs_type_hold(result);
	if (result->class == NI_XS_TYPE_SCALAR) {
		if ((attrValue = xml_node_get_attr(node, "constraint")) != NULL) {
			ni_xs_scalar_info_t *scalar_info;
			ni_xs_type_t *clone;

			clone = ni_xs_type_clone(result);
			ni_xs_type_release(result);
			result = clone;

			scalar_info = ni_xs_scalar_info(result);
			if (!strcmp(attrValue, "bitmap")) {
				scalar_info->constraint.bitmap = ni_xs_build_bitmap_constraint(node);
				if (scalar_info->constraint.bitmap == NULL) {
					ni_xs_type_release(result);
					return NULL;
				}
			}
		}
	}

	return result;
}

struct ni_xs_type_constraint_bitmap *
ni_xs_build_bitmap_constraint(const xml_node_t *node)
{
	struct ni_xs_type_constraint_bitmap *result;
	unsigned int i, count;
	xml_node_t *child;

	/* Count the defined bits */
	for (child = node->children, count = 0; child; child = child->next, ++count)
		;

	result = xcalloc(1, sizeof(*result) + (count + 1) * sizeof(ni_intmap_t));
	result->bits = (ni_intmap_t *) (result + 1);

	for (child = node->children, i = 0; child; child = child->next, ++i) {
		const char *bitnum;
		unsigned int value;
		char *ep = NULL;

		bitnum = xml_node_get_attr(child, "bit");
		if (bitnum != NULL) {
			value = strtoul(bitnum, &ep, 0);
			if (*ep == '\0') {
				result->bits[i].name = strdup(child->name);
				result->bits[i].value = value;
				continue;
			}
		}

		ni_error("%s: bad bit value for <%s> in bitmap constraints",
				xml_node_location(child), child->name);
		goto failed;
	}
	return result;

failed:
	// ni_xs_type_constraint_bitmap_free(result);
	return NULL;
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

	ni_xs_type_hold(result);
	return result;

error:
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
