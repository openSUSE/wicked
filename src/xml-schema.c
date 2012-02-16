/*
 * Simple XML schema, in no way intended to be conforming to any standard.
 *
 * Copyright (C) 2012, Olaf Kirch <okir@suse.de>
 */

#include <limits.h>
#include <stdlib.h>
#include <wicked/logging.h>
#include <wicked/xml.h>
#include "xml-schema.h"
#include "util_priv.h"

static int		ni_xs_process_define(xml_node_t *, ni_xs_type_dict_t *);
static ni_xs_type_t *	ni_xs_build_complex_type(xml_node_t *, const char *, ni_xs_type_dict_t *);
static void		ni_xs_name_type_array_destroy(ni_xs_name_type_array_t *);
static ni_xs_type_t *	ni_xs_build_one_type(xml_node_t *, ni_xs_type_dict_t *);
static ni_xs_type_t *	ni_xs_typedict_lookup(ni_xs_type_dict_t *, const char *);
static ni_xs_type_t *	ni_xs_typedict_lookup_local(const ni_xs_type_dict_t *, const char *);

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
ni_xs_struct_new(void)
{
	ni_xs_type_t *type = __ni_xs_type_new(NI_XS_TYPE_STRUCT);

	type->u.struct_info = xcalloc(1, sizeof(ni_xs_struct_info_t));
	return type;
}

ni_xs_type_t *
ni_xs_dict_new(void)
{
	ni_xs_type_t *type = __ni_xs_type_new(NI_XS_TYPE_DICT);

	type->u.dict_info = xcalloc(1, sizeof(ni_xs_dict_info_t));
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
 * Typedicts represent a type contexts in the schema hierarchy.
 */
ni_xs_type_dict_t *
ni_xs_typedict_new(ni_xs_type_dict_t *parent)
{
	ni_xs_type_dict_t *newdict = calloc(1, sizeof(ni_xs_type_dict_t));

	newdict->parent = parent;
	return newdict;
}

void
ni_xs_typedict_free(ni_xs_type_dict_t *dict)
{
	ni_xs_name_type_array_destroy(&dict->types);
	free(dict);
}

static ni_xs_type_t *
ni_xs_typedict_lookup_local(const ni_xs_type_dict_t *dict, const char *name)
{
	return __ni_xs_name_type_array_find(&dict->types, name);
}

static ni_xs_type_t *
ni_xs_typedict_lookup(ni_xs_type_dict_t *dict, const char *name)
{
	ni_xs_type_t *result = NULL;

	while (result == NULL && dict != NULL) {
		result = ni_xs_typedict_lookup_local(dict, name);
		dict = dict->parent;
	}
	return result;
}

int
ni_xs_typedict_typedef(ni_xs_type_dict_t *dict, const char *name, ni_xs_type_t *type)
{
	if (ni_xs_typedict_lookup_local(dict, name) != NULL)
		return -1;
	ni_xs_name_type_array_append(&dict->types, name, type);
	return 0;
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
 * Process a schema.
 * For now, this is nothing but a sequence of <define> elements
 */
int
ni_xs_process_schema(xml_node_t *node, ni_xs_type_dict_t *typedict)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		int rv;

		if (!strcmp(child->name, "define")) {
			if ((rv = ni_xs_process_define(child, typedict)) < 0)
				return rv;
		} else {
			ni_error("%s: unsupported schema element <%s>", xml_node_location(node), child->name);
			return -1;
		}
	}

	return 0;
}

/*
 * Process a <define> element.
 * This can define a type or a constant.
 */
int
ni_xs_process_define(xml_node_t *node, ni_xs_type_dict_t *typedict)
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

		newType = ni_xs_build_complex_type(node, typeAttr, typedict);
		if (newType == NULL) {
			ni_error("%s: cannot build schema for node <%s> (class \"%s\") in %s",
					xml_node_location(node), nameAttr, typeAttr, __func__);
			return -1;
		}

		if (ni_xs_typedict_typedef(typedict, nameAttr, newType) < 0) {
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
		refType = ni_xs_typedict_lookup(typedict, typeAttr);
		if (refType == NULL) {
			ni_error("%s: definition of type <%s> references unknown base type <%s>",
					xml_node_location(node), nameAttr, typeAttr);
			return -1;
		}

		if (ni_xs_typedict_typedef(typedict, nameAttr, refType) < 0) {
			ni_error("%s: attempt to redefine type <%s>", xml_node_location(node), nameAttr);
			return -1;
		}
	} else if (node->children != NULL) {
		/*
		 * <define> <type/> </define>
		 */
		refType = ni_xs_build_one_type(node, typedict);
		if (refType == NULL)
			return -1;

		/* FIXME: build constraints if there are any */

		if (ni_xs_typedict_typedef(typedict, nameAttr, refType) < 0) {
			ni_error("%s: attempt to redefine type <%s>", xml_node_location(node), nameAttr);
			ni_xs_type_release(refType);
			return -1;
		}
		ni_xs_type_release(refType);
	} else {
		/* Definition of a constant */
		ni_fatal("define const not implemented yet");
	}

	return 0;
}

int
ni_xs_build_typelist(xml_node_t *node, ni_xs_name_type_array_t *result, ni_xs_type_dict_t *typedict)
{
	ni_xs_type_dict_t *localdict = ni_xs_typedict_new(typedict);
	xml_node_t *child;
	int rv = -1;

	for (child = node->children; child; child = child->next) {
		const char *memberName = NULL;
		ni_xs_type_t *memberType;

		if (child->name == NULL) {
			ni_error("%s: NULL node name?!", xml_node_location(node));
			continue;
		}

		if (!strcmp(child->name, "define")) {
			if (ni_xs_process_define(child, localdict) < 0)
				goto out;
			continue;
		}

		if (ni_xs_is_class_name(child->name)) {
			/* <struct ...> <dict ...> or <array ...> */
			memberType = ni_xs_build_complex_type(child, child->name, localdict);
			if (memberType == NULL)
				goto out;
		} else {
			/* This can be either
			 *   <u32/>
			 * or
			 *   <somename class="(dict|struct|array)">
			 * or
			 *   <somename type="othertype"/>
			 */
			memberType = ni_xs_typedict_lookup(localdict, child->name);
			if (memberType == NULL) {
				const char *typeAttr;

				memberName = child->name;

				if (ni_xs_is_reserved_name(memberName)) {
					ni_error("%s: named type node uses reserved name", xml_node_location(child));
					goto out;
				}

				if (ni_xs_typedict_lookup(typedict, memberName)) {
					ni_error("%s: ambiguous type for node <%s>", xml_node_location(child), memberName);
					goto out;
				}

				if ((typeAttr = xml_node_get_attr(child, "class")) != NULL) {
					memberType = ni_xs_build_complex_type(child, typeAttr, localdict);
				} else
				if ((typeAttr = xml_node_get_attr(child, "type")) != NULL) {
					memberType = ni_xs_typedict_lookup(localdict, typeAttr);
					ni_xs_type_hold(memberType);
				}

				if (memberType == NULL) {
					ni_error("%s: unknown type <%s>", xml_node_location(child), child->name);
					goto out;
				}
			}
		}

		ni_xs_name_type_array_append(result, memberName, memberType);
		ni_xs_type_release(memberType);
	}

	rv = result->count;

out:
	ni_xs_typedict_free(localdict);
	return rv;
}

ni_xs_type_t *
ni_xs_build_complex_type(xml_node_t *node, const char *className, ni_xs_type_dict_t *typedict)
{
	const char *typeAttr;
	ni_xs_type_t *type = NULL;

	if (className == NULL) {
		ni_error("%s: NULL class name?!", __func__);
		return NULL;
	}

	if (!strcmp(className, "struct")) {
		type = ni_xs_struct_new();
		if (ni_xs_build_typelist(node, &type->u.struct_info->children, typedict) < 0) {
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
			elementType = ni_xs_typedict_lookup(typedict, typeAttr);
			if (elementType == NULL) {
				ni_error("%s: array definition references unknown element type <%s>", __func__, typeAttr);
				return NULL;
			}
			ni_xs_type_hold(elementType);
		} else {
			elementType = ni_xs_build_one_type(node, typedict);
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
		type = ni_xs_dict_new();
		if (ni_xs_build_typelist(node, &type->u.dict_info->children, typedict) < 0) {
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
 * Process a list of XML child elements, which consists of zero or more
 * <define> elements, and exactly one type element, which is either a
 * scalar type (like <uint32>), or a complex type (like <dict>).
 *
 * Note that <foobar type="uint32"> forms are not allowed here.
 */
ni_xs_type_t *
ni_xs_build_one_type(xml_node_t *node, ni_xs_type_dict_t *typedict)
{
	ni_xs_type_dict_t *localdict = ni_xs_typedict_new(typedict);
	ni_xs_type_t *result = NULL;
	xml_node_t *child;

	if (node->children == NULL) {
		ni_error("%s: cannot build type, empty context", xml_node_location(node));
		return NULL;
	}

	for (child = node->children; child != NULL; child = child->next) {
		if (!strcmp(child->name, "define")) {
			if (ni_xs_process_define(child, localdict) < 0)
				goto error;
			continue;
		}
		if (result != NULL) {
			ni_error("%s: definition of type is ambiguous", xml_node_location(node));
			goto error;
		}

		if (ni_xs_is_class_name(child->name)) {
			result = ni_xs_build_complex_type(child, child->name, localdict);
		} else {
			result = ni_xs_typedict_lookup(localdict, child->name);
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

	ni_xs_typedict_free(localdict);
	ni_xs_type_hold(result);
	return result;

error:
	ni_xs_typedict_free(localdict);
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
