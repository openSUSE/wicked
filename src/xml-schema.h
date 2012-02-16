/*
 * Simple XML schema, in no way intended to be conforming to any standard.
 *
 * Copyright (C) 2012, Olaf Kirch <okir@suse.de>
 *
 *
 * Type definitions look like this:
 *   <define name="..." type="..."/>
 * or
 *   <define name="...">
 *    <type...>
 *   </define>
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
 * Arrays are represented like this:
 *   <array type="..." minlen="..." maxlen="..."/>
 * or
 *   <array minlen="..." maxlen="...">
 *    <type...>
 *   </array>
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
   <define name="bond" class="dict">
     <mode type="string"/>

     <arpmon class="dict">
       <define name="arp-validate-type">
        <string value="none" value="active" value="backup" value="all"/>
       </define>
       <interval type="uint32"/>
       <validate type="arp-validate-type"/>
       <target>
        <array element="ipv4-address" minlen="1"/>
       </target>
     </arpmon>

     <miimon = class="dict">
       <frequency uint32/>
       <validate uint32/>
       <updelay uint32/>
       <downdelay uint32/>
       <carrier>
        <uint32 constraint="oneof">
         <choice value="ioctl"/>
         <choice value="netif"/>
        </uint32>
       </carrier>
     </miimon>
   </define>
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

struct ni_xs_type {
	unsigned int		refcount;
	unsigned int		class;

	unsigned int		scalar_type;
	ni_xs_name_type_array_t *children;		/* dict or struct */
	ni_xs_array_info_t *	array_info;

	struct {
		struct ni_xs_type_constraint_oneof *oneof;
		struct ni_xs_type_constraint_range *range;
	} constraint;
};

struct ni_xs_type_dict {
	ni_xs_type_dict_t *	parent;
	ni_xs_name_type_array_t	types;
};

extern ni_xs_type_dict_t *ni_xs_typedict_new(ni_xs_type_dict_t *);
extern void		ni_xs_typedict_free(ni_xs_type_dict_t *);

extern int		ni_xs_process_schema(xml_node_t *, ni_xs_type_dict_t *);

extern ni_xs_type_t *	ni_xs_scalar_new(void);
extern int		ni_xs_typedict_typedef(ni_xs_type_dict_t *, const char *, ni_xs_type_t *);
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

#endif /* __WICKED_XML_SCHEMA_H__ */
