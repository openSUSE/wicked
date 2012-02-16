/*
 * Serialize and deserialize XML definitions, according to a given schema.
 *
 * Copyright (C) 2012, Olaf Kirch <okir@suse.de>
 */

#include <limits.h>
#include <stdlib.h>
#include <wicked/logging.h>
#include <wicked/xml.h>
#include "dbus-common.h"
#include "xml-schema.h"

static void		ni_dbus_define_scalar_types(ni_xs_type_dict_t *);
static void		ni_dbus_define_xml_notations(void);
static dbus_bool_t	ni_dbus_serialize_xml_scalar(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_struct(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_array(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_dict(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);

ni_xs_type_dict_t *
ni_dbus_xml_init(void)
{
	ni_xs_type_dict_t *schema_dict;

	schema_dict = ni_xs_typedict_new(NULL);
	ni_dbus_define_scalar_types(schema_dict);
	ni_dbus_define_xml_notations();

	return schema_dict;
}

dbus_bool_t
ni_dbus_serialize_xml(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	switch (type->class) {
		case NI_XS_TYPE_SCALAR:
			return ni_dbus_serialize_xml_scalar(node, type, var);

		case NI_XS_TYPE_STRUCT:
			return ni_dbus_serialize_xml_struct(node, type, var);

		case NI_XS_TYPE_ARRAY:
			return ni_dbus_serialize_xml_array(node, type, var);

		case NI_XS_TYPE_DICT:
			return ni_dbus_serialize_xml_dict(node, type, var);

		default:
			ni_error("unsupported xml type class %u", type->class);
			return FALSE;
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_serialize_xml_scalar(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	char signature[2];

	if (node->cdata == NULL) {
		ni_error("unable to serialize node %s - no data", node->name);
		return FALSE;
	}

	/* TBD: handle constants defined in the schema? */

	signature[0] = type->scalar_type;
	signature[1] = '\0';
	if (!ni_dbus_variant_parse(var, node->cdata, signature)) {
		ni_error("unable to serialize node %s - cannot parse value", node->name);
		return FALSE;
	}

	return TRUE;
}

static char *
__ni_xs_type_to_dbus_signature(const ni_xs_type_t *type, char *sigbuf, size_t buflen)
{
	unsigned int i = 0;

	ni_assert(buflen >= 2);
	switch (type->class) {
	case NI_XS_TYPE_SCALAR:
		sigbuf[i++] = type->scalar_type;
		sigbuf[i++] = '\0';
		break;

	case NI_XS_TYPE_ARRAY:
		sigbuf[i++] = DBUS_TYPE_ARRAY;

		/* Arrays of non-scalar types always wrap each element into a VARIANT */
		if (type->array_info->element_type->class != NI_XS_TYPE_SCALAR)
			sigbuf[i++] = DBUS_TYPE_VARIANT;

		if (!__ni_xs_type_to_dbus_signature(type->array_info->element_type, sigbuf + i, buflen - i))
			return NULL;
		break;

	case NI_XS_TYPE_DICT:
		ni_assert(buflen >= sizeof(NI_DBUS_DICT_SIGNATURE));
		strcpy(sigbuf, NI_DBUS_DICT_SIGNATURE);
		break;

	default:
		return NULL;

	}
	return sigbuf;
}

static char *
ni_xs_type_to_dbus_signature(const ni_xs_type_t *type)
{
	static char sigbuf[32];

	return __ni_xs_type_to_dbus_signature(type, sigbuf, sizeof(sigbuf));
}

/*
 * Serialize an array
 */
dbus_bool_t
ni_dbus_serialize_xml_array(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	ni_xs_array_info_t *array_info = type->array_info;
	ni_xs_type_t *element_type = array_info->element_type;
	xml_node_t *child;

	if (array_info->notation) {
		const ni_xs_notation_t *notation = array_info->notation;
		ni_opaque_t data = NI_OPAQUE_INIT;

		/* For now, we handle only byte arrays */
		if (notation->array_element_type != DBUS_TYPE_BYTE) {
			ni_error("%s: cannot handle array notation \"%s\"", __func__, notation->name);
			return FALSE;
		}
		if (node->cdata == NULL) {
			ni_error("%s: array not compatible with notation \"%s\"", __func__, notation->name);
			return FALSE;
		}
		if (!notation->parse(node->cdata, &data)) {
			ni_error("%s: cannot parse array with notation \"%s\"", __func__, notation->name);
			return FALSE;
		}
		ni_dbus_variant_set_byte_array(var, data.data, data.len);
		return TRUE;
	}

	if (!ni_dbus_variant_init_signature(var, ni_xs_type_to_dbus_signature(type)))
		return FALSE;

	for (child = node->children; child; child = child->next) {
		if (element_type->class == NI_XS_TYPE_SCALAR) {
			if (child->cdata == NULL) {
				ni_error("%s: NULL array element",__func__);
				return FALSE;
			}

			/* TBD: handle constants defined in the schema? */
			if (!ni_dbus_variant_array_parse_and_append_string(var, child->cdata)) {
				ni_error("%s: syntax error in array element",__func__);
				return FALSE;
			}
		} else {
			ni_error("%s: arrays of type %s not implemented yet", __func__, ni_xs_type_to_dbus_signature(element_type));
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * Serialize a dict
 */
dbus_bool_t
ni_dbus_serialize_xml_dict(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *dict)
{
	xml_node_t *child;

	ni_assert(type->children);
	for (child = node->children; child; child = child->next) {
		const ni_xs_type_t *child_type = ni_xs_name_type_array_find(type->children, child->name);
		ni_dbus_variant_t *child_var;

		if (child_type == NULL) {
			ni_warn("%s: ignoring unknown dict element \"%s\"", __func__, child->name);
			continue;
		}
		child_var = ni_dbus_dict_add(dict, child->name);
		if (!ni_dbus_serialize_xml(child, child_type, child_var))
			return FALSE;
	}
	return TRUE;
}

/*
 * Serialize a struct
 */
dbus_bool_t
ni_dbus_serialize_xml_struct(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	ni_error("%s: not implemented yet", __func__);
	return FALSE;
}

/*
 * Scalar types for dbus xml
 */
static void
ni_dbus_define_scalar_types(ni_xs_type_dict_t *typedict)
{
	static struct dbus_xml_type {
		const char *	name;
		unsigned int	dbus_type;
	} dbus_xml_types[] = {
		{ "boolean",	DBUS_TYPE_BOOLEAN },
		{ "byte",	DBUS_TYPE_BYTE },
		{ "string",	DBUS_TYPE_STRING },
		{ "double",	DBUS_TYPE_DOUBLE },
		{ "uint16",	DBUS_TYPE_UINT16 },
		{ "uint32",	DBUS_TYPE_UINT32 },
		{ "uint64",	DBUS_TYPE_UINT64 },
		{ "int16",	DBUS_TYPE_INT16 },
		{ "int32",	DBUS_TYPE_INT32 },
		{ "int64",	DBUS_TYPE_INT64 },

		{ NULL }
	}, *tp;

	for (tp = dbus_xml_types; tp->name; ++tp) {
		ni_xs_type_t *xtype = ni_xs_scalar_new();

		xtype->scalar_type = tp->dbus_type;
		ni_xs_typedict_typedef(typedict, tp->name, xtype);
	}
}

/*
 * Array notations
 */
#include <netinet/in.h>
#include <arpa/inet.h>

static ni_opaque_t *
ni_parse_ipv4_opaque(const char *string_value, ni_opaque_t *data)
{
	struct in_addr addr;

	if (inet_pton(AF_INET, string_value, &addr) != 1)
		return NULL;
	memcpy(data->data, &addr, sizeof(addr));
	data->len = sizeof(addr);
	return data;
}

static ni_opaque_t *
ni_parse_ipv6_opaque(const char *string_value, ni_opaque_t *data)
{
	struct in6_addr addr;

	if (inet_pton(AF_INET6, string_value, &addr) != 1)
		return NULL;
	memcpy(data->data, &addr, sizeof(addr));
	data->len = sizeof(addr);
	return data;
}

static ni_opaque_t *
ni_parse_hwaddr_opaque(const char *string_value, ni_opaque_t *data)
{
	int len;

	len = ni_parse_hex(string_value, data->data, sizeof(data->data));
	if (len < 0)
		return NULL;
	data->len = len;
	return data;
}

static ni_xs_notation_t	__ni_dbus_notations[] = {
	{
		.name = "ipv4addr",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = ni_parse_ipv4_opaque
	}, {
		.name = "ipv6addr",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = ni_parse_ipv6_opaque
	}, {
		.name = "hwaddr",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = ni_parse_hwaddr_opaque
	},

	{ NULL }
};

void
ni_dbus_define_xml_notations(void)
{
	ni_xs_notation_t *na;

	for (na = __ni_dbus_notations; na->name; ++na)
		ni_xs_register_array_notation(na);
}
