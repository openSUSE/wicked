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
#include "util_priv.h"
#include "debug.h"

#include <wicked/netinfo.h>
#include "dbus-objects/model.h"

static void		ni_dbus_define_scalar_types(ni_xs_scope_t *);
static void		ni_dbus_define_xml_notations(void);
static ni_dbus_method_t *ni_dbus_xml_register_methods(ni_xs_service_t *, ni_xs_method_t *, const ni_dbus_method_t *);

static dbus_bool_t	ni_dbus_serialize_xml(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_scalar(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_struct(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_array(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_dict(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_deserialize_xml(ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static dbus_bool_t	ni_dbus_deserialize_xml_scalar(ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static dbus_bool_t	ni_dbus_deserialize_xml_struct(ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static dbus_bool_t	ni_dbus_deserialize_xml_array(ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static dbus_bool_t	ni_dbus_deserialize_xml_dict(ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static char *		__ni_xs_type_to_dbus_signature(const ni_xs_type_t *, char *, size_t);
static char *		ni_xs_type_to_dbus_signature(const ni_xs_type_t *);
static ni_xs_service_t *ni_dbus_xml_get_service_schema(const ni_xs_scope_t *, const char *);
static ni_xs_type_t *	ni_dbus_xml_get_properties_schema(const ni_xs_scope_t *, const ni_xs_service_t *);

ni_xs_scope_t *
ni_dbus_xml_init(void)
{
	ni_xs_scope_t *schema;

	schema = ni_xs_scope_new(NULL, "dbus");
	ni_dbus_define_scalar_types(schema);
	ni_dbus_define_xml_notations();

	return schema;
}

/*
 * Register all services defined by the schema
 */
int
ni_dbus_xml_register_services(ni_xs_scope_t *scope)
{
	ni_xs_service_t *xs_service;

	NI_TRACE_ENTER_ARGS("scope=%s", scope->name);
	for (xs_service = scope->services; xs_service; xs_service = xs_service->next) {
		ni_dbus_service_t *service;
		const ni_dbus_class_t *class = NULL;
		const ni_var_t *attr;

		/* An interface needs to be attached to an object. The object-class
		 * attribute specifies which object class this can attach to. */
		if ((attr = ni_var_array_get(&xs_service->attributes, "object-class")) != NULL) {
			const char *class_name = attr->value;

			if ((class = ni_objectmodel_get_class(class_name)) == NULL) {
				ni_error("xml service definition for %s: unknown object-class \"%s\"",
						xs_service->interface, class_name);
			}
		}

		service = (ni_dbus_service_t *) ni_objectmodel_service_by_name(xs_service->interface);
		if (service != NULL) {
			if (service->compatible == NULL) {
				service->compatible = class;
			} else if (class && service->compatible != class) {
				ni_error("schema definition of interface %s changes class from %s to %s",
						xs_service->interface,
						service->compatible->name,
						class->name);
			}
		} else {
			service = xcalloc(1, sizeof(*service));
			ni_string_dup(&service->name, xs_service->interface);
			service->compatible = class;

			ni_debug_dbus("register dbus service description %s", service->name);
			ni_objectmodel_register_service(service);
		}

		service->user_data = xs_service;

		if (xs_service->methods)
			service->methods = ni_dbus_xml_register_methods(xs_service, xs_service->methods, service->methods);
		if (xs_service->signals)
			service->signals = ni_dbus_xml_register_methods(xs_service, xs_service->signals, service->signals);
	}

	return 0;
}

ni_dbus_method_t *
ni_dbus_xml_register_methods(ni_xs_service_t *xs_service, ni_xs_method_t *xs_method_list, const ni_dbus_method_t *old_array)
{
	ni_dbus_method_t *method_array, *method;
	unsigned int num_new_methods = 0, num_old_methods = 0, num_methods = 0;
	ni_xs_method_t *xs_method;

	if (xs_method_list == NULL)
		return NULL;

	if (old_array) {
		for (num_old_methods = 0; old_array[num_old_methods].name; ++num_old_methods)
			;
	}
	for (xs_method = xs_method_list; xs_method; xs_method = xs_method->next)
		num_new_methods++;
	method_array = xcalloc(num_old_methods + num_new_methods + 1, sizeof(ni_dbus_method_t));

	if (old_array) {
		memcpy(method_array, old_array, num_old_methods * sizeof(ni_dbus_method_t));
		num_methods = num_old_methods;
	}

	for (xs_method = xs_method_list; xs_method; xs_method = xs_method->next) {
		char sigbuf[64];
		unsigned int i;

		/* Skip private methods */
		if (xs_method->name == 0 || xs_method->name[0] == '_')
			continue;

		for (i = 0, method = NULL; i < num_methods; ++i) {
			if (!strcmp(method_array[i].name, xs_method->name)) {
				method = &method_array[i];
				break;
			}
		}
		if (method != NULL) {
			ni_debug_dbus("%s method %s is built-in, do not redefine",
					xs_service->interface, xs_method->name);
			method->user_data = xs_method;
			continue;
		}

		/* First, build the method signature */
		sigbuf[0] = '\0';
		for (i = 0; i < xs_method->arguments.count; ++i) {
			ni_xs_type_t *type = xs_method->arguments.data[i].type;
			unsigned int k = strlen(sigbuf);

			if (!__ni_xs_type_to_dbus_signature(type, sigbuf + k, sizeof(sigbuf) - k)) {
				ni_error("bad definition of service %s method %s: "
					 "cannot build dbus signature of argument[%u] (%s)",
					 xs_service->interface, xs_method->name, i,
					 xs_method->arguments.data[i].name);
				goto next_method;
			}
		}

		method = &method_array[num_methods++];
		ni_string_dup((char **) &method->name, xs_method->name);
		ni_string_dup((char **) &method->call_signature, sigbuf);
		method->handler = NULL; /* will be bound later in ni_objectmodel_bind_extensions() */
		method->user_data = xs_method;

next_method: ;
	}

	return method_array;
}

/*
 * Serialize XML rep of an argument to a dbus call
 */
dbus_bool_t
ni_dbus_xml_serialize_arg(const ni_dbus_method_t *method, unsigned int narg,
					ni_dbus_variant_t *var, xml_node_t *node)
{
	ni_xs_method_t *xs_method = method->user_data;
	ni_xs_type_t *xs_type;

	ni_assert(xs_method);
	if (narg >= xs_method->arguments.count)
		return FALSE;

	ni_debug_dbus("%s: serializing argument %u (%s)",
			method->name, narg, xs_method->arguments.data[narg].name);
	xs_type = xs_method->arguments.data[narg].type;

	return ni_dbus_serialize_xml(node, xs_type, var);
}

xml_node_t *
ni_dbus_xml_deserialize_arguments(const ni_dbus_method_t *method,
				unsigned int num_vars, ni_dbus_variant_t *vars,
				xml_node_t *parent)
{
	xml_node_t *node = xml_node_new("arguments", parent);
	ni_xs_method_t *xs_method = method->user_data;
	unsigned int i;

	for (i = 0; i < num_vars; ++i) {
		xml_node_t *arg = xml_node_new(xs_method->arguments.data[i].name, node);

		if (!ni_dbus_deserialize_xml(&vars[i], xs_method->arguments.data[i].type, arg)) {
			xml_node_free(node);
			return NULL;
		}
	}

	return node;
}

xml_node_t *
ni_dbus_xml_deserialize_properties(ni_xs_scope_t *schema, const char *interface_name, ni_dbus_variant_t *var, xml_node_t *parent)
{
	ni_xs_service_t *service;
	xml_node_t *node;
	ni_xs_type_t *type;

	if (!(service = ni_dbus_xml_get_service_schema(schema, interface_name))) {
		ni_error("cannot represent %s properties - no schema definition", interface_name);
		return NULL;
	}

	if (!(type = ni_dbus_xml_get_properties_schema(schema, service))) {
		ni_error("no type named <properties> for interface %s", interface_name);
		return NULL;
	}

	node = xml_node_new(service->name, parent);
	if (!ni_dbus_deserialize_xml(var, type, node)) {
		ni_error("failed to build xml for %s properties", interface_name);
		return NULL;
	}

	return node;
}

/*
 * Given an XML tree representing the data returned by an extension script,
 * build the dbus response from it
 */
dbus_bool_t
ni_dbus_serialize_return(const ni_dbus_method_t *method, ni_dbus_variant_t *result, xml_node_t *node)
{
	ni_xs_method_t *xs_method = method->user_data;
	ni_xs_type_t *xs_type;

	ni_assert(xs_method);
	if ((xs_type = xs_method->retval) == NULL)
		return TRUE;

	ni_debug_dbus("%s: serializing response (%s)", method->name, xs_type->name);
	return ni_dbus_serialize_xml(node, xs_type, result);
}

/*
 * Extract a dbus error from an XML node
 */
void
ni_dbus_serialize_error(DBusError *error, xml_node_t *node)
{
	const char *error_name;

	if ((error_name = xml_node_get_attr(node, "name")) == NULL)
		error_name = DBUS_ERROR_FAILED;

	dbus_set_error(error, error_name,
			node->cdata? node->cdata : "extension call failed (no error message returned by script)");
}

/*
 * Convert an XML tree to a dbus data object for serialization
 */
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

/*
 * Create XML from a dbus data object
 */
dbus_bool_t
ni_dbus_deserialize_xml(ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
	switch (type->class) {
	case NI_XS_TYPE_SCALAR:
		return ni_dbus_deserialize_xml_scalar(var, type, node);

	case NI_XS_TYPE_STRUCT:
		return ni_dbus_deserialize_xml_struct(var, type, node);

	case NI_XS_TYPE_ARRAY:
		return ni_dbus_deserialize_xml_array(var, type, node);

	case NI_XS_TYPE_DICT:
		return ni_dbus_deserialize_xml_dict(var, type, node);

	default:
		ni_error("unsupported xml type class %u", type->class);
		return FALSE;
	}

	return TRUE;
}

/*
 * XML -> dbus_variant conversion for scalars
 */
dbus_bool_t
ni_dbus_serialize_xml_scalar(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	ni_xs_scalar_info_t *scalar_info = ni_xs_scalar_info(type);

	if (scalar_info->constraint.bitmap) {
		const ni_intmap_t *bits = scalar_info->constraint.bitmap->bits;
		unsigned long value = 0;
		xml_node_t *child;

		for (child = node->children; child; child = child->next) {
			unsigned int bb;

			if (ni_parse_int_mapped(child->name, bits, &bb) < 0 || bb >= 32) {
				ni_warn("%s: ignoring unknown or bad bit value <%s>",
						xml_node_location(node), child->name);
				continue;
			}

			value |= 1 << bb;
		}

		if (!ni_dbus_variant_init_signature(var, ni_xs_type_to_dbus_signature(type)))
			return FALSE;
		return ni_dbus_variant_set_ulong(var, value);
	}

	if (node->cdata == NULL) {
		ni_error("unable to serialize node %s - no data", node->name);
		return FALSE;
	}

	if (scalar_info->constraint.enums) {
		const ni_intmap_t *names = scalar_info->constraint.enums;
		unsigned int value;

		if (ni_parse_int_mapped(node->cdata, names, &value) < 0) {
			ni_error("%s: unknown enum value %s", xml_node_location(node), node->cdata);
			return FALSE;
		}

		if (!ni_dbus_variant_init_signature(var, ni_xs_type_to_dbus_signature(type)))
			return FALSE;
		return ni_dbus_variant_set_uint(var, value);
	}

	/* TBD: handle constants defined in the schema? */
	if (!ni_dbus_variant_parse(var, node->cdata, ni_xs_type_to_dbus_signature(type))) {
		ni_error("unable to serialize node %s - cannot parse value", node->name);
		return FALSE;
	}

	return TRUE;
}

/*
 * XML from dbus variant for scalars
 */
dbus_bool_t
ni_dbus_deserialize_xml_scalar(ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
	ni_xs_scalar_info_t *scalar_info = ni_xs_scalar_info(type);
	const char *value;

	if (var->type == DBUS_TYPE_ARRAY) {
		ni_error("%s: expected a scalar, but got an array or dict", __func__);
		return FALSE;
	}

	if (scalar_info->constraint.bitmap) {
		const ni_intmap_t *bits = scalar_info->constraint.bitmap->bits;
		unsigned long value = 0;
		unsigned int bb;

		if (!ni_dbus_variant_get_ulong(var, &value))
			return FALSE;

		for (bb = 0; bb < 32; ++bb) {
			const char *bitname;

			if ((value & (1 << bb)) == 0)
				continue;

			if ((bitname = ni_format_int_mapped(bb, bits)) != NULL) {
				xml_node_new(bitname, node);
			} else {
				ni_warn("unable to represent bit%u in <%s>", bb, node->name);
			}
		}

		return TRUE;
	}

	if (scalar_info->constraint.enums) {
		const char *enum_name;
		unsigned int value;

		if (!ni_dbus_variant_get_uint(var, &value)) {
			ni_error("%s: cannot get value for <%s>", __func__, node->name);
			return FALSE;
		}

		enum_name = ni_format_int_mapped(value, scalar_info->constraint.enums);
		if (enum_name != NULL) {
			xml_node_set_cdata(node, enum_name);
		} else {
			char buffer[32];

			snprintf(buffer, sizeof(buffer), "%u", value);
			xml_node_set_cdata(node, buffer);
		}
		return TRUE;
	}

	if (!(value = ni_dbus_variant_sprint(var))) {
		ni_error("%s: unable to represent variable value as string", __func__);
		return FALSE;
	}

	/* FIXME: make sure we properly quote any xml meta characters */
	xml_node_set_cdata(node, value);
	return TRUE;
}

/*
 * Serialize an array
 */
dbus_bool_t
ni_dbus_serialize_xml_array(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	ni_xs_array_info_t *array_info = ni_xs_array_info(type);
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
			ni_error("%s: cannot parse array with notation \"%s\", value=\"%s\"", __func__, notation->name, node->cdata);
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
		} else if (element_type->class == NI_XS_TYPE_DICT) {
			ni_dbus_variant_t *element;

			ni_debug_dbus("var signature is %s", ni_dbus_variant_signature(var));
			element = ni_dbus_variant_append_variant_element(var);
			if (!element) {
				/* should not happen */
				ni_error("%s: could not append element to array", __func__);
				return FALSE;
			}

			if (!ni_dbus_serialize_xml(child, element_type, element)) {
				ni_error("%s: failed to serialize array element", xml_node_location(child));
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
 * XML from dbus variant for arrays
 */
dbus_bool_t
ni_dbus_deserialize_xml_array(ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
	ni_xs_array_info_t *array_info = ni_xs_array_info(type);
	ni_xs_type_t *element_type = array_info->element_type;
	unsigned int i, array_len;

	array_len = var->array.len;
	if (array_info->notation) {
		const ni_xs_notation_t *notation = array_info->notation;
		ni_opaque_t data = NI_OPAQUE_INIT;
		char buffer[256];

		/* For now, we handle only byte arrays */
		if (notation->array_element_type != DBUS_TYPE_BYTE) {
			ni_error("%s: cannot handle array notation \"%s\"", __func__, notation->name);
			return FALSE;
		}

		if (!ni_dbus_variant_is_byte_array(var)) {
			ni_error("%s: expected byte array, but got something else", __func__);
			return FALSE;
		}
		if (array_len > sizeof(data.data)) {
			ni_error("%s: cannot extract data from byte array - too long (len=%u)", __func__, var->array.len);
			return FALSE;
		}

		ni_opaque_set(&data, var->byte_array_value, array_len);
		if (!notation->print(&data, buffer, sizeof(buffer))) {
			ni_error("%s: cannot represent array with notation \"%s\"", __func__, notation->name);
			return FALSE;
		}
		xml_node_set_cdata(node, buffer);
		return TRUE;
	}

	if (element_type->class == NI_XS_TYPE_SCALAR) {
		/* An array of non-scalars always wraps each element in a variant */
		if (var->array.element_type == DBUS_TYPE_VARIANT) {
			ni_error("%s: expected an array of scalars, but got an array of variants",
					__func__);
			return FALSE;
		}

		for (i = 0; i < array_len; ++i) {
			const char *string;
			xml_node_t *child;

			if (!(string = ni_dbus_variant_array_print_element(var, i))) {
				ni_error("%s: cannot represent array element", __func__);
				return FALSE;
			}
			child = xml_node_new("e", node);
			xml_node_set_cdata(child, string);
		}
	} else if (element_type->class == NI_XS_TYPE_DICT) {
		/* An array of non-scalars always wraps each element in a variant */
		if (var->array.element_type != DBUS_TYPE_VARIANT
		 && !ni_dbus_variant_is_dict_array(var)) {
			ni_error("%s: expected an array of variants (got %s)", __func__, ni_dbus_variant_signature(var));
			return FALSE;
		}

		for (i = 0; i < array_len; ++i) {
			ni_dbus_variant_t *element = &var->variant_array_value[i];
			xml_node_t *child;

			child = xml_node_new("e", node);
			if (!ni_dbus_deserialize_xml(element, element_type, child))
				return FALSE;
		}
	} else {
		ni_error("%s: arrays of type %s not implemented yet", __func__, ni_xs_type_to_dbus_signature(element_type));
		return FALSE;
	}

	return TRUE;
}

/*
 * Serialize a dict
 */
dbus_bool_t
ni_dbus_serialize_xml_dict(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *dict)
{
	ni_xs_dict_info_t *dict_info = ni_xs_dict_info(type);
	xml_node_t *child;

	ni_assert(dict_info);

	ni_dbus_variant_init_dict(dict);
	for (child = node->children; child; child = child->next) {
		const ni_xs_type_t *child_type = ni_xs_dict_info_find(dict_info, child->name);
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
 * Deserialize a dict
 */
dbus_bool_t
ni_dbus_deserialize_xml_dict(ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
	ni_xs_dict_info_t *dict_info = ni_xs_dict_info(type);
	ni_dbus_dict_entry_t *entry;
	unsigned int i;

	if (!ni_dbus_variant_is_dict(var)) {
		ni_error("unable to deserialize %s: expected a dict", node->name);
		return FALSE;
	}

	entry = var->dict_array_value;
	for (i = 0; i < var->array.len; ++i, ++entry) {
		const ni_xs_type_t *child_type;
		xml_node_t *child;

		/* Silently ignore dict entries we have no schema information for */
		if (!(child_type = ni_xs_dict_info_find(dict_info, entry->key))) {
			ni_debug_dbus("%s: ignoring unknown dict entry %s in node <%s>",
					__func__, entry->key, node->name);
			continue;
		}

		child = xml_node_new(entry->key, node);
		if (!ni_dbus_deserialize_xml(&entry->datum, child_type, child))
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

static dbus_bool_t
ni_dbus_deserialize_xml_struct(ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
	ni_error("%s: not implemented yet", __func__);
	return FALSE;
}

/*
 * Get the dbus signature of a dbus-xml type
 */
static char *
__ni_xs_type_to_dbus_signature(const ni_xs_type_t *type, char *sigbuf, size_t buflen)
{
	ni_xs_scalar_info_t *scalar_info;
	ni_xs_array_info_t *array_info;
	unsigned int i = 0;

	ni_assert(buflen >= 2);
	switch (type->class) {
	case NI_XS_TYPE_SCALAR:
		scalar_info = ni_xs_scalar_info(type);
		sigbuf[i++] = scalar_info->type;
		sigbuf[i++] = '\0';
		break;

	case NI_XS_TYPE_ARRAY:
		array_info = ni_xs_array_info(type);
		sigbuf[i++] = DBUS_TYPE_ARRAY;

		/* Arrays of non-scalar types always wrap each element into a VARIANT */
		if (array_info->element_type->class != NI_XS_TYPE_SCALAR)
			sigbuf[i++] = DBUS_TYPE_VARIANT;
		else if (!__ni_xs_type_to_dbus_signature(array_info->element_type, sigbuf + i, buflen - i))
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
 * Scalar types for dbus xml
 */
static void
ni_dbus_define_scalar_types(ni_xs_scope_t *typedict)
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
		{ "object-path",DBUS_TYPE_OBJECT_PATH },

		{ NULL }
	}, *tp;

	for (tp = dbus_xml_types; tp->name; ++tp)
		ni_xs_scope_typedef(typedict, tp->name, ni_xs_scalar_new(tp->dbus_type));
}

/*
 * Array notations
 */
#include <netinet/in.h>
#include <arpa/inet.h>

static ni_opaque_t *
__ni_notation_ipv4addr_parse(const char *string_value, ni_opaque_t *data)
{
	struct in_addr addr;

	if (inet_pton(AF_INET, string_value, &addr) != 1)
		return NULL;
	memcpy(data->data, &addr, sizeof(addr));
	data->len = sizeof(addr);
	return data;
}

static const char *
__ni_notation_ipv4addr_print(const ni_opaque_t *data, char *buffer, size_t size)
{
	if (data->len != sizeof(struct in_addr))
		return NULL;
	return inet_ntop(AF_INET, data->data, buffer, size);
}

static ni_opaque_t *
__ni_notation_ipv6addr_address_parse(const char *string_value, ni_opaque_t *data)
{
	struct in6_addr addr;

	if (inet_pton(AF_INET6, string_value, &addr) != 1)
		return NULL;
	memcpy(data->data, &addr, sizeof(addr));
	data->len = sizeof(addr);
	return data;
}

static const char *
__ni_notation_ipv6addr_address_print(const ni_opaque_t *data, char *buffer, size_t size)
{
	if (data->len != sizeof(struct in6_addr))
		return NULL;
	return inet_ntop(AF_INET6, data->data, buffer, size);
}

static ni_opaque_t *
__ni_notation_hwaddr_parse(const char *string_value, ni_opaque_t *data)
{
	int len;

	len = ni_parse_hex(string_value, data->data, sizeof(data->data));
	if (len < 0)
		return NULL;
	data->len = len;
	return data;
}

static const char *
__ni_notation_hwaddr_print(const ni_opaque_t *data, char *buffer, size_t size)
{
	/* We need to check whether the resulting string would fit, as
	 * ni_format_hex will happily truncate the output string if it
	 * does not fit. */
	if (3 * data->len + 1 > size)
		return NULL;

	return ni_format_hex(data->data, data->len, buffer, size);
}

/*
 * Parse and print functions for sockaddrs and prefixed sockaddrs
 */
static ni_opaque_t *
__ni_notation_netaddr_parse(const char *string_value, ni_opaque_t *pack)
{
	ni_sockaddr_t sockaddr;

	if (ni_address_parse(&sockaddr, string_value, AF_UNSPEC) < 0)
		return NULL;
	return ni_sockaddr_pack(&sockaddr, pack);
}

static const char *
__ni_notation_netaddr_print(const ni_opaque_t *pack, char *buffer, size_t size)
{
	ni_sockaddr_t sockaddr;

	if (!ni_sockaddr_unpack(&sockaddr, pack))
		return NULL;
	return ni_address_format(&sockaddr, buffer, size);
}

static ni_opaque_t *
__ni_notation_netaddr_prefix_parse(const char *string_value, ni_opaque_t *pack)
{
	char *copy = xstrdup(string_value), *s;
	unsigned int prefix = 0xFFFF;
	ni_sockaddr_t sockaddr;
	ni_opaque_t *result = NULL;

	if ((s = strchr(copy, '/')) != NULL) {
		unsigned long value;

		*s++ = '\0';

		value = strtoul(s, &s, 0);
		if (*s != '\0' || value >= 0xFFFF)
			goto failed;

		prefix = value;
	}

	if (ni_address_parse(&sockaddr, copy, AF_UNSPEC) >= 0)
		result = ni_sockaddr_prefix_pack(&sockaddr, prefix, pack);

failed:
	free(copy);
	return result;
}

static const char *
__ni_notation_netaddr_prefix_print(const ni_opaque_t *pack, char *buffer, size_t size)
{
	ni_sockaddr_t sockaddr;
	unsigned int prefix;

	if (!ni_sockaddr_prefix_unpack(&sockaddr, &prefix, pack))
		return NULL;

	snprintf(buffer, size, "%s/%u", ni_address_print(&sockaddr), prefix);
	return buffer;
}

static ni_xs_notation_t	__ni_dbus_notations[] = {
	{
		.name = "ipv4addr",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = __ni_notation_ipv4addr_parse,
		.print = __ni_notation_ipv4addr_print,
	}, {
		.name = "ipv6addr",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = __ni_notation_ipv6addr_address_parse,
		.print = __ni_notation_ipv6addr_address_print,
	}, {
		.name = "hwaddr",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = __ni_notation_hwaddr_parse,
		.print = __ni_notation_hwaddr_print,
	}, {
		.name = "net-address",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = __ni_notation_netaddr_parse,
		.print = __ni_notation_netaddr_print,
	}, {
		.name = "net-address-prefix",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = __ni_notation_netaddr_prefix_parse,
		.print = __ni_notation_netaddr_prefix_print,
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

/*
 * Helper functions
 */
static ni_xs_service_t *
ni_dbus_xml_get_service_schema(const ni_xs_scope_t *scope, const char *interface_name)
{
	ni_xs_service_t *service;

	for (service = scope->services; service; service = service->next) {
		if (!strcmp(service->interface, interface_name))
			return service;
	}

	return NULL;
}

static ni_xs_type_t *
ni_dbus_xml_get_properties_schema(const ni_xs_scope_t *scope, const ni_xs_service_t *service)
{
	scope = ni_xs_scope_lookup_scope(scope, service->name);
	if (scope == NULL) {
		ni_error("weird - no xml scope \"%s\" for interface %s", service->name, service->interface);
		return NULL;
	}

	return ni_xs_scope_lookup_local(scope, "properties");
}

