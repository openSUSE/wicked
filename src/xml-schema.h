/*
 * Simple XML schema, in no way intended to be conforming to any standard.
 *
 * Copyright (C) 2012, Olaf Kirch <okir@suse.de>
 *
 *
 * Type definitions look like this:
 *   <define name="..." type="..."/>    <!-- for scalars -->
 *   <define name="..." class="..."/>   <!-- for complex types -->
 *
 * Alternative notations are
 *   <define name="...">
 *    ...
 *   </define>
 * where the <define> element can contain any number of nested defines,
 * and *exactly* one anonymous type. This anonymous type can be written
 * like one of the following:
 *
 *   <footype/>                <!-- where footype was defined previously -->
 *   <array ... />
 *   <struct> ... </struct>    <!-- child elements define struct members -->
 *   <dict> ... </dict>        <!-- child elements define dict members -->
 *
 *
 * Constant definitions look like this:
 *   <define name="...">#cdata</define>
 * Note, constant definitions must not contain xml elements, in order to
 * distinguish them from type definitions.
 *
 * Scalar type names use the common dbus type names, such as uint32, string, etc.
 *
 * Types can be used anonymously, or in a context where the value has a "name".
 * The contexts a value/type can appear in, are these:
 *
 *  -	all by themselves, e.g. as a positional argument of a dbus call.
 *	It should have a name in this case, however.
 *  -	as a member of a struct; it may be anonymous, but doesn't have to be.
 *  -	as the element type of an array. This use case is always anonymous.
 *  -	as a member of a dict; in this case, the member must be named.
 *
 * In a named context, types can be represented in two ways:
 * 	<name>
 *       <type/>
 * 	</name>
 * This allows for even the most complex type definitions to be used, such as
 * an array or dicts, for instance.
 * As an abbreviation, where possible, you can also use
 *      <name type="type"/>
 * In this case, the named type must be either a scalar type, or a type previously
 * defined via a <define> element.
 *
 * Atomic types can be constrained in a number of ways, expressed by adding
 * a constraint="..." attribute to the type element.
 *
 * oneof
 *	If an atom can take on value from a limited number of choices only,
 *	specify it using constraint="oneof". The type element is then expected
 *	to have one or more child elements specifying the permitted values:
 *		<choice value="..."/>
 *
 * range
 *	If a numeric type can take on values from a limited range of numbers only,
 *	specify it using constrain="range". The type element is then expected
 *	to have additional min="..." and max="..." attributes.
 *
 * bitmap
 *	If a numeric type is a bitmap, the individual bits can be named. In this
 *	case, the XML representation will be an element containing child elements
 *	using the given flag names, where a child is present iff the corresponding
 *	bit in the bitmap is set.
 *	So, for instance, if a bitmap's three low-order bits are named secret,
 *	urgent, and archive, you may define it like this:
 *	 <define name="document-disposition" type="uint32" contstraint="bitmap">
 *	  <secret bit="0" />
 *	  <urgent bit="1" />
 *	  <archive bit="2" />
 *	 </define>
 *	 <disposition type="document-disposition" />
 *
 *	If the variable disposition takes on the value 5, it would be represented
 *	as
 *	  <disposition> <archive/> <secret/> </disposition>
 *
 *
 * Arrays are represented like this:
 *   <array element-type="..." minlen="..." maxlen="..."/>
 * or
 *   <array minlen="..." maxlen="...">
 *    <type...>
 *   </array>
 * The latter form can be used for arrays of complex types, such as a dict,
 * without having to define a named type for the array element type.
 *
 * Note that the minlen/maxlen attributes are optional.
 *
 * Structs can be represented either as
 *   <struct>
 *    <nameA type="typeA"/>
 *    <nameB type="typeB"/>
 *    ...
 *   </struct>
 * or using anonymous members
 *   <struct>
 *    <typeA/>
 *    <typeB/>
 *    ...
 *   </struct>
 *
 * structs support some limited notion of "inheritance" via the "extends"
 * attribute. This lets the schema writer create a struct type that extends
 * (or inherits from) an existing struct:
 *
 *   <define name="base-struct" class="struct">
 *     <foo type="string" />
 *   </define>
 *   <define name="derived-struct" class="struct" extends="base-struct">
 *     <bar type="uint32" />
 *   </define>
 *
 * String-keyed dicts are represented as
 *   <dict>
 *    <nameA type="typeA"/>
 *    <nameB type="typeB"/>
 *    ...
 *   </dict>
 * where each of the @typeX* elements must have an additional name="..." attribute.
 *
 * Discriminated unions are not yet defined.
 *
 */

#ifndef __WICKED_XML_SCHEMA_H__
#define __WICKED_XML_SCHEMA_H__

#include <wicked/xml.h>

typedef struct ni_xs_type_array {
	unsigned int		count;
	ni_xs_type_t **		data;
} ni_xs_type_array_t;

typedef struct ni_xs_name_type	ni_xs_name_type_t;
struct ni_xs_name_type {
	char *			name;
	ni_xs_type_t *		type;
};

typedef struct ni_xs_name_type_array {
	unsigned int		count;
	ni_xs_name_type_t *	data;
} ni_xs_name_type_array_t;

struct ni_xs_type_constraint_oneof {
	ni_string_array_t	values;
};

struct ni_xs_type_constraint_bitmap {
	ni_intmap_t *		bits;
};

enum {
	NI_XS_TYPE_SCALAR,
	NI_XS_TYPE_STRUCT,
	NI_XS_TYPE_ARRAY,
	NI_XS_TYPE_DICT,
};

typedef struct ni_xs_notation	ni_xs_notation_t;
struct ni_xs_notation {
	const char *		name;
	unsigned int		array_element_type;
	ni_opaque_t *		(*parse)(const char *, ni_opaque_t *);
	const char *		(*print)(const ni_opaque_t *, char *, size_t);
};

typedef struct ni_xs_array_info ni_xs_array_info_t;
struct ni_xs_array_info {
	ni_xs_type_t *		element_type;
	unsigned long		minlen;
	unsigned long		maxlen;
	const ni_xs_notation_t *notation;
};

typedef struct ni_xs_dict_info	ni_xs_dict_info_t;
struct ni_xs_dict_info {
	ni_xs_name_type_array_t children;
};

typedef struct ni_xs_struct_info ni_xs_struct_info_t;
struct ni_xs_struct_info {
	ni_xs_name_type_array_t children;
};

typedef struct ni_xs_scalar_info ni_xs_scalar_info_t;
struct ni_xs_scalar_info {
	unsigned int		type;

	struct {
		struct ni_xs_type_constraint_oneof *oneof;
		struct ni_xs_type_constraint_range *range;
		struct ni_xs_type_constraint_bitmap *bitmap;
	} constraint;
};

struct ni_xs_type {
	unsigned int		refcount;
	unsigned int		class;
	char *			name;

	union {
		ni_xs_scalar_info_t *	scalar_info;
		ni_xs_dict_info_t *	dict_info;
		ni_xs_struct_info_t *	struct_info;
		ni_xs_array_info_t *	array_info;
	} u;
};

typedef struct ni_xs_method	ni_xs_method_t;
struct ni_xs_method {
	ni_xs_method_t *	next;
	char *			name;
	ni_xs_name_type_array_t	arguments;
	ni_xs_type_t *		retval;
};

typedef struct ni_xs_service	ni_xs_service_t;
struct ni_xs_service {
	ni_xs_service_t *	next;
	char *			name;
	char *			interface;

	ni_layer_t		layer;
	union {
		ni_iftype_t	iftype;
	} provides;
	ni_xs_method_t *	methods;
};

struct ni_xs_scope {
	ni_xs_scope_t *		parent;
	ni_xs_scope_t *		next;

	char *			name;
	ni_xs_name_type_array_t	types;
	ni_xs_service_t *	services;
	ni_var_array_t		constants;

	ni_xs_scope_t *		children;
};

extern ni_xs_scope_t *	ni_xs_scope_new(ni_xs_scope_t *, const char *);
extern void		ni_xs_scope_free(ni_xs_scope_t *);

extern int		ni_xs_process_schema_file(const char *, ni_xs_scope_t *);
extern int		ni_xs_process_schema(xml_node_t *, ni_xs_scope_t *);

extern ni_xs_type_t *	ni_xs_scalar_new(unsigned int);
extern int		ni_xs_scope_typedef(ni_xs_scope_t *, const char *, ni_xs_type_t *);
extern void		ni_xs_type_free(ni_xs_type_t *type);

const ni_xs_type_t *	ni_xs_name_type_array_find(const ni_xs_name_type_array_t *, const char *);

extern void		ni_xs_register_array_notation(const ni_xs_notation_t *);
const ni_xs_notation_t *ni_xs_get_array_notation(const char *);

static inline ni_xs_type_t *
ni_xs_type_hold(ni_xs_type_t *type)
{
	if (type)
		type->refcount++;
	return type;
}

static inline void
ni_xs_type_release(ni_xs_type_t *type)
{
	ni_assert(type->refcount);
	if (--(type->refcount) == 0)
		ni_xs_type_free(type);
}

static inline ni_xs_scalar_info_t *
ni_xs_scalar_info(const ni_xs_type_t *type)
{
	ni_assert(type->class == NI_XS_TYPE_SCALAR);
	ni_assert(type->u.scalar_info);
	return type->u.scalar_info;
}

static inline ni_xs_struct_info_t *
ni_xs_struct_info(const ni_xs_type_t *type)
{
	ni_assert(type->class == NI_XS_TYPE_STRUCT);
	ni_assert(type->u.struct_info);
	return type->u.struct_info;
}

static inline ni_xs_dict_info_t *
ni_xs_dict_info(const ni_xs_type_t *type)
{
	ni_assert(type->class == NI_XS_TYPE_DICT);
	ni_assert(type->u.dict_info);
	return type->u.dict_info;
}

static inline ni_xs_array_info_t *
ni_xs_array_info(const ni_xs_type_t *type)
{
	ni_assert(type->class == NI_XS_TYPE_ARRAY);
	ni_assert(type->u.array_info);
	return type->u.array_info;
}

static inline const ni_xs_type_t *
ni_xs_dict_info_find(const ni_xs_dict_info_t *dict_info, const char *name)
{
	return ni_xs_name_type_array_find(&dict_info->children, name);
}

static inline const ni_xs_type_t *
ni_xs_struct_info_find(const ni_xs_struct_info_t *struct_info, const char *name)
{
	return ni_xs_name_type_array_find(&struct_info->children, name);
}

#endif /* __WICKED_XML_SCHEMA_H__ */
