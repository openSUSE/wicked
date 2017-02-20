/*
 * Serialize and deserialize XML definitions, according to a given schema.
 *
 * Copyright (C) 2012, Olaf Kirch <okir@suse.de>
 *
 * FIXME: we ought to validate the schema, to make sure people don't do stupid things
 * like attaching bitmap constraints to a string type etc.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/logging.h>
#include <wicked/xml.h>
#include "dbus-common.h"
#include "xml-schema.h"
#include "util_priv.h"
#include "limits.h"
#include "debug.h"

#include <wicked/netinfo.h>
#include <wicked/xpath.h>
#include "dbus-objects/model.h"

static void		ni_dbus_define_scalar_types(ni_xs_scope_t *);
static void		ni_dbus_define_xml_notations(void);
static int		ni_dbus_xml_register_classes(ni_xs_scope_t *);
static ni_dbus_method_t *ni_dbus_xml_register_methods(ni_xs_service_t *, ni_xs_method_t *, const ni_dbus_method_t *);

static dbus_bool_t	ni_dbus_validate_xml(xml_node_t *, const ni_xs_type_t *, const ni_dbus_xml_validate_context_t *);
static dbus_bool_t	ni_dbus_validate_xml_void(xml_node_t *, const ni_xs_type_t *, const ni_dbus_xml_validate_context_t *);
static dbus_bool_t	ni_dbus_validate_xml_scalar(xml_node_t *, const ni_xs_type_t *, const ni_dbus_xml_validate_context_t *);
static dbus_bool_t	ni_dbus_validate_xml_struct(xml_node_t *, const ni_xs_type_t *, const ni_dbus_xml_validate_context_t *);
static dbus_bool_t	ni_dbus_validate_xml_union(xml_node_t *, const ni_xs_type_t *, const ni_dbus_xml_validate_context_t *);
static dbus_bool_t	ni_dbus_validate_xml_array(xml_node_t *, const ni_xs_type_t *, const ni_dbus_xml_validate_context_t *);
static dbus_bool_t	ni_dbus_validate_xml_dict(xml_node_t *, const ni_xs_type_t *, const ni_dbus_xml_validate_context_t *);
static dbus_bool_t	ni_dbus_serialize_xml(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_scalar(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_struct(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_union(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_array(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_dict(xml_node_t *, const ni_xs_type_t *, ni_dbus_variant_t *);
static dbus_bool_t	ni_dbus_serialize_xml_bitmask(const xml_node_t *, const ni_xs_scalar_info_t *, unsigned long *);
static dbus_bool_t	ni_dbus_serialize_xml_bitmap(const xml_node_t *, const ni_xs_scalar_info_t *, unsigned long *);
static dbus_bool_t	ni_dbus_deserialize_xml(const ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static dbus_bool_t	ni_dbus_deserialize_xml_scalar(const ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static dbus_bool_t	ni_dbus_deserialize_xml_struct(const ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static dbus_bool_t	ni_dbus_deserialize_xml_union(const ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static dbus_bool_t	ni_dbus_deserialize_xml_array(const ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static dbus_bool_t	ni_dbus_deserialize_xml_dict(const ni_dbus_variant_t *, const ni_xs_type_t *, xml_node_t *);
static char *		__ni_xs_type_to_dbus_signature(const ni_xs_type_t *, char *, size_t);
static char *		ni_xs_type_to_dbus_signature(const ni_xs_type_t *);
static ni_xs_service_t *ni_dbus_xml_get_service_schema(const ni_xs_scope_t *, const char *);
static ni_xs_type_t *	ni_dbus_xml_get_properties_schema(const ni_xs_scope_t *, const ni_xs_service_t *);

static ni_tempstate_t *	__ni_dbus_xml_global_temp_state;

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
	int rv;

	NI_TRACE_ENTER_ARGS("scope=%s", scope->name);

	/* First, register any classes defined by the schema */
	if ((rv = ni_dbus_xml_register_classes(scope)) < 0)
		return rv;

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

		service->schema = xs_service;

		if (xs_service->methods)
			service->methods = ni_dbus_xml_register_methods(xs_service, xs_service->methods, service->methods);
		if (xs_service->signals)
			service->signals = ni_dbus_xml_register_methods(xs_service, xs_service->signals, service->signals);
	}

	return 0;
}

/*
 * Register all classes defined by a schema
 */
int
ni_dbus_xml_register_classes(ni_xs_scope_t *scope)
{
	ni_xs_class_t *xs_class;

	for (xs_class = scope->classes; xs_class; xs_class = xs_class->next) {
		const ni_dbus_class_t *base_class;
		ni_dbus_class_t *new_class;

		base_class = ni_objectmodel_get_class(xs_class->base_name);
		if (base_class == NULL) {
			ni_error("unknown object base class \"%s\" referenced by schema", xs_class->base_name);
			return -1;
		}

		new_class = ni_objectmodel_class_new(xs_class->name, base_class);
		ni_objectmodel_register_class(new_class);
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

		if (method != NULL) {
			if (method->call_signature && !ni_string_eq(method->call_signature, sigbuf)) {
				ni_warn("%s method %s signature mismatch. Built-in \"%s\" vs schema \"%s\"",
					xs_service->interface, xs_method->name,
					method->call_signature, sigbuf);
			}
			method->schema = xs_method;
			continue;
		}

		method = &method_array[num_methods++];
		ni_string_dup((char **) &method->name, xs_method->name);
		ni_string_dup((char **) &method->call_signature, sigbuf);
		method->handler = NULL; /* will be bound later in ni_objectmodel_bind_extensions() */
		method->schema = xs_method;

next_method: ;
	}

	return method_array;
}

/*
 * Check whether a given method takes any arguments/returns anything
 */
unsigned int
ni_dbus_xml_method_num_args(const ni_dbus_method_t *method)
{
	const ni_xs_method_t *xs_method = method->schema;

	if (xs_method == NULL)
		return 0;
	return xs_method->arguments.count;
}

dbus_bool_t
ni_dbus_xml_method_has_return(const ni_dbus_method_t *method)
{
	const ni_xs_method_t *xs_method = method->schema;

	if (xs_method == NULL)
		return FALSE;
	return xs_method->retval != NULL;
}

/*
 * Serialize XML rep of an argument to a dbus call
 */
dbus_bool_t
ni_dbus_xml_validate_argument(const ni_dbus_method_t *method, unsigned int narg,
					xml_node_t *node, const ni_dbus_xml_validate_context_t *ctx)
{
	const ni_xs_method_t *xs_method = method->schema;

	if (!xs_method || narg >= xs_method->arguments.count)
		return FALSE;

	return ni_dbus_validate_xml(node, xs_method->arguments.data[narg].type, ctx);
}

ni_xs_type_t *
ni_dbus_xml_get_argument_type(const ni_dbus_method_t *method, unsigned int narg)
{
	const ni_xs_method_t *xs_method = method->schema;

	if (!xs_method || narg >= xs_method->arguments.count)
		return NULL;

	return xs_method->arguments.data[narg].type;
}

const xml_node_t *
ni_dbus_xml_get_argument_metadata(const ni_dbus_method_t *method, unsigned int narg)
{
	ni_xs_type_t *xs_type;

	if (!(xs_type = ni_dbus_xml_get_argument_type(method, narg)))
		return NULL;

	return xs_type->meta;
}

dbus_bool_t
ni_dbus_xml_serialize_arg(const ni_dbus_method_t *method, unsigned int narg,
					ni_dbus_variant_t *var, xml_node_t *node)
{
	ni_xs_type_t *xs_type;

	if (!(xs_type = ni_dbus_xml_get_argument_type(method, narg)))
		return FALSE;

	return ni_dbus_serialize_xml(node, xs_type, var);
}

xml_node_t *
ni_dbus_xml_deserialize_arguments(const ni_dbus_method_t *method,
				unsigned int num_vars, const ni_dbus_variant_t *vars,
				xml_node_t *parent, ni_tempstate_t *temp_state)
{
	xml_node_t *node = xml_node_new("arguments", parent);
	const ni_xs_method_t *xs_method = method->schema;
	unsigned int i;

	/* This is a lousy hack, but it sure beats passing down the temp_state to
	 * all functions. */
	__ni_dbus_xml_global_temp_state = temp_state;

	for (i = 0; i < num_vars; ++i) {
		xml_node_t *arg = xml_node_new(xs_method->arguments.data[i].name, node);

		if (!ni_dbus_deserialize_xml(&vars[i], xs_method->arguments.data[i].type, arg)) {
			xml_node_free(node);
			node = NULL;
			break;
		}
	}

	__ni_dbus_xml_global_temp_state = NULL;
	return node;
}

xml_node_t *
ni_dbus_xml_deserialize_properties(ni_xs_scope_t *schema, const char *interface_name, ni_dbus_variant_t *var, xml_node_t *parent)
{
	ni_xs_service_t *service;
	xml_node_t *node;
	ni_xs_type_t *type;

	if (ni_dbus_variant_is_dict(var) && var->array.len == 0)
		return NULL;

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

int
ni_dbus_xml_serialize_properties(ni_xs_scope_t *schema, ni_dbus_variant_t *result, xml_node_t *node)
{
	const char *interface_name = node->name;
	ni_xs_service_t *service;
	ni_xs_type_t *type;

	ni_dbus_variant_init_dict(result);
	if (!(service = ni_dbus_xml_get_service_schema(schema, interface_name))) {
		ni_error("cannot represent %s properties - no schema definition", interface_name);
		return -NI_ERROR_CANNOT_MARSHAL;
	}

	if (!(type = ni_dbus_xml_get_properties_schema(schema, service))) {
		ni_error("no type named <properties> for interface %s", interface_name);
		return -NI_ERROR_CANNOT_MARSHAL;
	}

	if (!ni_dbus_serialize_xml(node, type, result)) {
		ni_error("failed to parse xml for %s properties", interface_name);
		return -NI_ERROR_CANNOT_MARSHAL;
	}

	return 0;
}

/*
 * Given an XML tree representing the data returned by an extension script,
 * build the dbus response from it
 */
int
ni_dbus_serialize_return(const ni_dbus_method_t *method, ni_dbus_variant_t *result, xml_node_t *node)
{
	const ni_xs_method_t *xs_method = method->schema;
	ni_xs_type_t *xs_type;

	ni_assert(xs_method);
	if ((xs_type = xs_method->retval) == NULL)
		return 0;

	ni_debug_dbus("%s: serializing response (%s)", method->name, xs_type->name);
	if (!ni_dbus_serialize_xml(node, xs_type, result))
		return -NI_ERROR_CANNOT_MARSHAL;

	return 1;
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
 * Validate an XML tree
 */
dbus_bool_t
ni_dbus_validate_xml(xml_node_t *node, const ni_xs_type_t *type, const ni_dbus_xml_validate_context_t *ctx)
{
	if (ctx && ctx->metadata_callback && type->meta) {
		if (!ctx->metadata_callback(node, type, type->meta, ctx->user_data))
			return FALSE;
	}

	switch (type->class) {
	case NI_XS_TYPE_VOID:
		return ni_dbus_validate_xml_void(node, type, ctx);

	case NI_XS_TYPE_SCALAR:
		return ni_dbus_validate_xml_scalar(node, type, ctx);

	case NI_XS_TYPE_STRUCT:
		return ni_dbus_validate_xml_struct(node, type, ctx);

	case NI_XS_TYPE_UNION:
		return ni_dbus_validate_xml_union(node, type, ctx);

	case NI_XS_TYPE_ARRAY:
		return ni_dbus_validate_xml_array(node, type, ctx);

	case NI_XS_TYPE_DICT:
		return ni_dbus_validate_xml_dict(node, type, ctx);

	default:
		ni_error("unsupported xml type class %u", type->class);
		return FALSE;
	}

	return TRUE;
}

/*
 * Convert an XML tree to a dbus data object for serialization
 */
static dbus_bool_t
ni_dbus_serialize_xml(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	switch (type->class) {
		case NI_XS_TYPE_VOID:
			return TRUE;

		case NI_XS_TYPE_SCALAR:
			return ni_dbus_serialize_xml_scalar(node, type, var);

		case NI_XS_TYPE_STRUCT:
			return ni_dbus_serialize_xml_struct(node, type, var);

		case NI_XS_TYPE_UNION:
			return ni_dbus_serialize_xml_union(node, type, var);

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
ni_dbus_deserialize_xml(const ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
#if 0
	int depth = 0;

	{
		xml_node_t *p;
		for (p = node->parent; p; p = p->parent)
			depth++;
	}

	ni_trace("%*.*sdeserialize <%s>", depth, depth, "", node->name);
#endif

	switch (type->class) {
	case NI_XS_TYPE_VOID:
		return TRUE;

	case NI_XS_TYPE_SCALAR:
		return ni_dbus_deserialize_xml_scalar(var, type, node);

	case NI_XS_TYPE_STRUCT:
		return ni_dbus_deserialize_xml_struct(var, type, node);

	case NI_XS_TYPE_UNION:
		return ni_dbus_deserialize_xml_union(var, type, node);

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
static dbus_bool_t
ni_dbus_serialize_xml_bitmask(const xml_node_t *node, const ni_xs_scalar_info_t *scalar_info, unsigned long *result)
{
	ni_string_array_t bit_name_arr = NI_STRING_ARRAY_INIT;
	const ni_intmap_t *bits;
	unsigned long value = 0, v;
	unsigned int i, bv;

	if (!node || !result || !scalar_info || !scalar_info->constraint.bitmask->bits)
		return FALSE;

	bits = scalar_info->constraint.bitmask->bits;
	ni_string_split(&bit_name_arr, node->cdata, " ,|\t\n", 0);
	for (i = 0; i < bit_name_arr.count; ++i) {
		if (ni_parse_ulong(bit_name_arr.data[i], &v, 16) == 0) {
			value |= v;
		} else
		if (ni_parse_uint_mapped(bit_name_arr.data[i], bits, &bv) == 0) {
			value |= bv;
		} else {
			ni_error("%s: unknown bitmask value name <%s>",
				xml_node_location(node),
				bit_name_arr.data[i]);
			return FALSE;
		}
	}

	*result = value;
	return TRUE;
}

static dbus_bool_t
ni_dbus_serialize_xml_bitmap(const xml_node_t *node, const ni_xs_scalar_info_t *scalar_info, unsigned long *result)
{
	const ni_intmap_t *bits = scalar_info->constraint.bitmap->bits;
	ni_string_array_t bit_name_arr = NI_STRING_ARRAY_INIT;
	unsigned long value = 0;
	unsigned int i;
	unsigned int bb;
	xml_node_t *child;
	dbus_bool_t ret = TRUE;

	if (!node)
		return FALSE;

	if (!node->children) {
		/* Data is of the form:
		 *   <node>flag1,...,flagN</node>
		 */
		ni_string_split(&bit_name_arr, node->cdata, " ,|\t\n", 0);
	} else {
		/* Data is of the form:
		 *   <node>
		 *     <flag1/>
		 *     ...
		 *     <flagN/>
		 *   </node>
		 */
		for (child = node->children; child; child = child->next)
			ni_string_array_append(&bit_name_arr, child->name);
	}

	for (i = 0; i < bit_name_arr.count && ret; ++i) {
		if (ni_parse_uint_mapped(bit_name_arr.data[i], bits, &bb) < 0 ||
			bb >= 32) {
			ni_error("%s: unknown or bad bit value <%s>",
				xml_node_location(node),
				bit_name_arr.data[i]);
			ret = FALSE;
		}

		/* May left shift past width of value if bb >= 32, but as ret
		 * will be FALSE assignment to result will not happen. */
		value |= 1 << bb;
	}

	ni_string_array_destroy(&bit_name_arr);
	*result = ret ? value : *result;

	return ret;
}

static dbus_bool_t
ni_dbus_serialize_xml_enum(const xml_node_t *node, const ni_xs_scalar_info_t *scalar_info, unsigned long *result)
{
	const ni_intmap_t *names = scalar_info->constraint.enums->bits;
	unsigned int value;

	if (ni_parse_uint_maybe_mapped(node->cdata, names, &value, 0) < 0) {
		ni_error("%s: unknown enum value \"%s\"", xml_node_location(node), node->cdata);
		return FALSE;
	}

	*result = value;
	return TRUE;
}

/*
 * Validate a void node.
 */
dbus_bool_t
ni_dbus_validate_xml_void(xml_node_t *node, const ni_xs_type_t *type, const ni_dbus_xml_validate_context_t *ctx)
{
	if (node->cdata) {
		ni_error("%s: invalid void element <%s>: element has data", xml_node_location(node), node->name);
		return FALSE;
	}
	if (node->children) {
		ni_error("%s: invalid void element <%s>: element has children", xml_node_location(node), node->name);
		return FALSE;
	}
	return TRUE;
}

/*
 * Validate a scalar node.
 * This is where we use the validation callback for
 *  - resolving references to e.g. device names
 *  - prompting the user for authentication data too valuable to store in a file
 *  - recording dependency information.
 * and some more.
 */
dbus_bool_t
ni_dbus_validate_xml_scalar(xml_node_t *node, const ni_xs_type_t *type, const ni_dbus_xml_validate_context_t *ctx)
{
	ni_xs_scalar_info_t *scalar_info = ni_xs_scalar_info(type);
	unsigned long value;

	if (scalar_info->constraint.bitmap)
		return ni_dbus_serialize_xml_bitmap(node, scalar_info, &value);

	if (scalar_info->constraint.bitmask)
		return ni_dbus_serialize_xml_bitmask(node, scalar_info, &value);

	/* This signals a "flag" type element, ie we simply test for its presence or
	 * absence. */
	if (scalar_info->type == DBUS_TYPE_INVALID) {
		if (node->cdata != NULL) {
			ni_error("%s: invalid flag scalar <%s> - should be empty", xml_node_location(node), node->name);
			return FALSE;
		}
		return TRUE;
	}

	if (node->cdata == NULL) {
		ni_error("%s: unable to serialize scalar <%s> - no data", xml_node_location(node), node->name);
		return FALSE;
	}

	if (scalar_info->constraint.enums)
		return ni_dbus_serialize_xml_enum(node, scalar_info, &value);

	/* FIXME: validate whether scalar value can be parsed! */
	return TRUE;
}

dbus_bool_t
ni_dbus_serialize_xml_scalar(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	ni_xs_scalar_info_t *scalar_info = ni_xs_scalar_info(type);

	/* This signals a "flag" type element, ie we simply test for its presence or
	 * absence. We encode it as a BYTE value. */
	if (scalar_info->type == DBUS_TYPE_INVALID) {
		ni_dbus_variant_set_byte(var, 0);
		return TRUE;
	}

	if (scalar_info->constraint.bitmap) {
		unsigned long value;

		if (!ni_dbus_serialize_xml_bitmap(node, scalar_info, &value)
		 || !ni_dbus_variant_init_signature(var, ni_xs_type_to_dbus_signature(type)))
			return FALSE;
		return ni_dbus_variant_set_ulong(var, value);
	}

	if (scalar_info->constraint.bitmask) {
		unsigned long value;

		if (!ni_dbus_serialize_xml_bitmask(node, scalar_info, &value)
		 || !ni_dbus_variant_init_signature(var, ni_xs_type_to_dbus_signature(type)))
			return FALSE;
		return ni_dbus_variant_set_ulong(var, value);
	}

	if (node->cdata == NULL) {
		ni_error("unable to serialize node %s - no data", node->name);
		return FALSE;
	}

	if (scalar_info->constraint.enums) {
		unsigned long value;

		if (!ni_dbus_serialize_xml_enum(node, scalar_info, &value)
		 || !ni_dbus_variant_init_signature(var, ni_xs_type_to_dbus_signature(type)))
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
ni_dbus_deserialize_xml_scalar(const ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
	ni_xs_scalar_info_t *scalar_info = ni_xs_scalar_info(type);
	const char *value;

	if (var->type == DBUS_TYPE_ARRAY) {
		ni_error("%s: expected a scalar, but got an array or dict", __func__);
		return FALSE;
	}

	/* This signals a "flag" type element, ie we simply test for its presence or
	 * absence. We encode it as a BYTE value. */
	if (scalar_info->type == DBUS_TYPE_INVALID) {
		if (var->type != DBUS_TYPE_BYTE) {
			ni_error("%s: <%s> flag element encoded incorrectly",
					__func__, node->name);
			return FALSE;
		}
		return TRUE;
	}

	if (scalar_info->constraint.bitmask) {
		const ni_intmap_t *bits = scalar_info->constraint.bitmask->bits;
		ni_string_array_t bit_name_arr = NI_STRING_ARRAY_INIT;
		unsigned long value = 0;

		if (!ni_dbus_variant_get_ulong(var, &value))
			return FALSE;

		for (; bits->name; ++bits) {
			if ((value & bits->value) != bits->value)
				continue;

			ni_string_array_append(&bit_name_arr, bits->name);
			value &= ~(bits->value);
		}
		if (value) {
			char num[64] = { '\0' };
			snprintf(num, sizeof(num), "0x%lx", value);
			ni_string_array_append(&bit_name_arr, num);
		}

		ni_string_join(&node->cdata, &bit_name_arr, " | ");
		ni_string_array_destroy(&bit_name_arr);
		return TRUE;
	}

	if (scalar_info->constraint.bitmap) {
		const ni_intmap_t *bits = scalar_info->constraint.bitmap->bits;
		ni_string_array_t bit_name_arr = NI_STRING_ARRAY_INIT;
		unsigned long value = 0;
		unsigned int bb;

		if (!ni_dbus_variant_get_ulong(var, &value))
			return FALSE;

		for (bb = 0; bb < 32; ++bb) {
			const char *bit_name;

			if ((value & (1 << bb)) == 0)
				continue;

			if ((bit_name = ni_format_uint_mapped(bb, bits)) != NULL)
				ni_string_array_append(&bit_name_arr, bit_name);
			else
				ni_warn("unable to represent bit%u in <%s>", bb, node->name);
		}

		if (!ni_string_join(&node->cdata, &bit_name_arr, ", "))
			ni_debug_dbus("Empty bit names string obtained.");

		ni_string_array_destroy(&bit_name_arr);

		return TRUE;
	}

	if (scalar_info->constraint.enums) {
		const char *enum_name;
		unsigned int value;

		if (!ni_dbus_variant_get_uint(var, &value)) {
			ni_error("%s: cannot get value for <%s>", __func__, node->name);
			return FALSE;
		}

		enum_name = ni_format_uint_mapped(value, scalar_info->constraint.enums->bits);
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
 * Serialize arrays with special notation
 */
static dbus_bool_t
ni_dbus_serialize_byte_array_notation(xml_node_t *node, const ni_xs_array_info_t *array_info,
				unsigned char **data_ptr, unsigned int *data_len)
{
	const ni_xs_notation_t *notation = array_info->notation;

	/* For now, we handle only byte arrays */
	if (notation->array_element_type != DBUS_TYPE_BYTE) {
		ni_error("%s: cannot handle array notation \"%s\"", xml_node_location(node), notation->name);
		return FALSE;
	}
	if (node->cdata == NULL) {
		ni_error("%s: array not compatible with notation \"%s\"", xml_node_location(node), notation->name);
		return FALSE;
	}

	if (!notation->parse(node->cdata, data_ptr, data_len)) {
		ni_error("%s: cannot parse array with notation \"%s\", value=\"%s\"",
				xml_node_location(node), notation->name, node->cdata);
		return FALSE;
	}
	return TRUE;
}

/*
 * Validate an array
 */
dbus_bool_t
ni_dbus_validate_xml_array(xml_node_t *node, const ni_xs_type_t *type, const ni_dbus_xml_validate_context_t *ctx)
{
	ni_xs_array_info_t *array_info = ni_xs_array_info(type);
	ni_xs_type_t *element_type = array_info->element_type;
	xml_node_t *child;

	if (array_info->notation) {
		unsigned char *data = NULL;
		unsigned int len = 0;

		if (!ni_dbus_serialize_byte_array_notation(node, array_info, &data, &len))
			return FALSE;
		free(data);
		return TRUE;
	}

	for (child = node->children; child; child = child->next) {
		if (!ni_dbus_validate_xml(child, element_type, ctx))
			return FALSE;
	}

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
		ni_dbus_variant_init_byte_array(var);
		return ni_dbus_serialize_byte_array_notation(node, array_info, &var->byte_array_value, &var->array.len);
	}

	if (!ni_dbus_variant_init_signature(var, ni_xs_type_to_dbus_signature(type)))
		return FALSE;

	for (child = node->children; child; child = child->next) {
		if (element_type->class == NI_XS_TYPE_SCALAR) {
			if (child->cdata == NULL) {
				ni_error("%s: NULL array element",
						xml_node_location(child));
				return FALSE;
			}

			/* TBD: handle constants defined in the schema? */
			if (!ni_dbus_variant_array_parse_and_append_string(var, child->cdata)) {
				ni_error("%s: syntax error in array element",__func__);
				return FALSE;
			}
		} else if (element_type->class == NI_XS_TYPE_DICT) {
			ni_dbus_variant_t *element;

			element = ni_dbus_dict_array_add(var);
			if (!element) {
				/* should not happen */
				ni_error("%s: could not append element to array",
						xml_node_location(child));
				return FALSE;
			}

			if (!ni_dbus_serialize_xml(child, element_type, element)) {
				ni_error("%s: failed to serialize array element", xml_node_location(child));
				return FALSE;
			}
		} else {
			ni_error("%s: arrays of type %s not implemented yet",
					xml_node_location(child), ni_xs_type_to_dbus_signature(element_type));
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * XML from dbus variant for arrays
 */
dbus_bool_t
ni_dbus_deserialize_xml_array(const ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
	ni_xs_array_info_t *array_info = ni_xs_array_info(type);
	ni_xs_type_t *element_type = array_info->element_type;
	unsigned int i, array_len;

	array_len = var->array.len;
	if (array_info->notation) {
		const ni_xs_notation_t *notation = array_info->notation;
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

		if (!notation->print(var->byte_array_value, array_len, buffer, sizeof(buffer))) {
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
			const char *string, *name = "e";
			xml_node_t *child;

			if (!(string = ni_dbus_variant_array_print_element(var, i))) {
				ni_error("%s: cannot represent array element", __func__);
				return FALSE;
			}

			if (array_info->element_name != NULL)
				name = array_info->element_name;
			else if (element_type->origdef.name != NULL)
				name = element_type->origdef.name;

			child = xml_node_new(name, node);
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
			const char *name = "e";

			if (array_info->element_name != NULL)
				name = array_info->element_name;
			else if (element_type->origdef.name != NULL)
				name = element_type->origdef.name;

			child = xml_node_new(name, node);
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

dbus_bool_t
ni_dbus_validate_xml_dict(xml_node_t *node, const ni_xs_type_t *type, const ni_dbus_xml_validate_context_t *ctx)
{
	ni_xs_dict_info_t *dict_info = ni_xs_dict_info(type);
	xml_node_t *child;
	unsigned int i;

	ni_assert(dict_info);

	/* First, validate all child nodes. This gives us an opportunity to fix up things
	 * inside the callback */
	for (child = node->children; child; child = child->next) {
		const ni_xs_type_t *child_type = ni_xs_dict_info_find(dict_info, child->name);

		if (child_type == NULL)
			continue;
		if (!ni_dbus_validate_xml(child, child_type, ctx))
			return FALSE;
	}

	for (i = 0; i < dict_info->children.count; ++i) {
		const ni_xs_name_type_t *name_type = &dict_info->children.data[i];
		const ni_xs_type_t *child_type = name_type->type;

		if (child_type->constraint.mandatory
		 && !xml_node_get_child(node, name_type->name)) {
			xml_node_t *meta;

			if (ctx->prompt_callback != NULL
			 && child_type->meta != NULL
			 && (meta = xml_node_get_child(child_type->meta, "user-input")) != NULL) {
				xml_node_t *child = xml_node_new(name_type->name, node);
				int rv;

				rv = ctx->prompt_callback(child, child_type, meta, ctx->user_data);
				if (rv == 0)
					continue;

				xml_node_delete_child_node(node, child);

				/* When the prompt function returns RETRY_OPERATION, it
				 * asks us to ignore the issue for now and come back later. */
				if (rv == -NI_ERROR_RETRY_OPERATION)
					continue;
			}

			ni_error("%s: <%s> lacks mandatory <%s> child element",
					xml_node_location(node),
					node->name, name_type->name);
			return FALSE;
		}
	}

	if (dict_info->groups.count) {
		unsigned int i;

		for (i = 0; i < dict_info->groups.count; ++i)
			dict_info->groups.data[i]->count = 0;

		for (child = node->children; child; child = child->next) {
			const ni_xs_type_t *child_type = ni_xs_dict_info_find(dict_info, child->name);

			if (child_type == NULL) {
				ni_warn("%s: ignoring unknown dict element \"%s\"", __func__, child->name);
				continue;
			}
			if (child_type->constraint.group)
				child_type->constraint.group->count++;
		}

		for (i = 0; i < dict_info->groups.count; ++i) {
			ni_xs_group_t *group = dict_info->groups.data[i];

			switch (group->relation) {
			case NI_XS_GROUP_CONSTRAINT_REQUIRE:
				if (group->count == 0) {
					ni_error("%s: <%s> lacks child element of group required:%s",
							xml_node_location(node), node->name,
							group->name);
					return FALSE;
				}
				break;

			case NI_XS_GROUP_CONSTRAINT_CONFLICT:
				if (group->count > 1) {
					ni_error("%s: <%s> has more than one child element of group exclusive:%s",
							xml_node_location(node), node->name,
							group->name);
					return FALSE;
				}
				break;
			}
		}
	}

	return TRUE;
}

/*
 * Deserialize a dict
 */
dbus_bool_t
ni_dbus_deserialize_xml_dict(const ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
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
ni_dbus_validate_xml_struct(xml_node_t *node, const ni_xs_type_t *type, const ni_dbus_xml_validate_context_t *ctx)
{
	ni_error("%s: not implemented yet", __func__);
	return FALSE;
}

dbus_bool_t
ni_dbus_serialize_xml_struct(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	ni_error("%s: not implemented yet", __func__);
	return FALSE;
}

static dbus_bool_t
ni_dbus_deserialize_xml_struct(const ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
	ni_error("%s: not implemented yet", __func__);
	return FALSE;
}

/*
 * Serialize a discriminated union
 */
static inline const ni_xs_type_t *
__ni_dbus_xml_union_type(xml_node_t *node, const ni_xs_type_t *type, const char **kind_p)
{
	ni_xs_union_info_t *union_info = ni_xs_union_info(type);
	const ni_xs_type_t *child_type;
	const char *kind;

	ni_assert(union_info);

	kind = xml_node_get_attr(node, union_info->discriminant);
	if (kind == NULL) {
		ni_error("%s: <%s> lacks %s attribute",
				xml_node_location(node),
				node->name, union_info->discriminant);
		return NULL;
	}
	if (kind_p)
		*kind_p = kind;

	child_type = ni_xs_union_info_find(union_info, kind);
	if (child_type == NULL) {
		ni_error("%s: <%s> invalid attribute %s=\"%s\": discriminant type not known",
				xml_node_location(node),
				node->name, union_info->discriminant, kind);
		return NULL;
	}
	return child_type;
}

dbus_bool_t
ni_dbus_validate_xml_union(xml_node_t *node, const ni_xs_type_t *type, const ni_dbus_xml_validate_context_t *ctx)
{
	const ni_xs_type_t *child_type;

	child_type = __ni_dbus_xml_union_type(node, type, NULL);
	if (child_type == NULL)
		return FALSE;

	return ni_dbus_validate_xml(node, child_type, ctx);
}

dbus_bool_t
ni_dbus_serialize_xml_union(xml_node_t *node, const ni_xs_type_t *type, ni_dbus_variant_t *var)
{
	const ni_xs_type_t *child_type;
	ni_dbus_variant_t *child;
	const char *kind;

	child_type = __ni_dbus_xml_union_type(node, type, &kind);
	if (child_type == NULL)
		return FALSE;

	ni_dbus_variant_init_struct(var);

	if (!(child = ni_dbus_struct_add(var)))
		return FALSE;
	ni_dbus_variant_set_string(child, kind);

	if (child_type->class == NI_XS_TYPE_VOID)
		return TRUE;

	if (!(child = ni_dbus_struct_add(var)))
		return FALSE;

	return ni_dbus_serialize_xml(node, child_type, child);
}

static dbus_bool_t
ni_dbus_deserialize_xml_union(const ni_dbus_variant_t *var, const ni_xs_type_t *type, xml_node_t *node)
{
	ni_xs_union_info_t *union_info = ni_xs_union_info(type);
	const ni_xs_type_t *child_type;
	ni_dbus_variant_t *child;
	const char *kind;

	/* Set the discriminant="kind" attribute first */
	if (!ni_dbus_struct_get_string(var, 0, &kind))
		return FALSE;
	xml_node_add_attr(node, union_info->discriminant, kind);

	/* Now we can look up the child type based on the discriminant */
	child_type = __ni_dbus_xml_union_type(node, type, NULL);
	if (child_type == NULL)
		return FALSE;

	if (child_type->class == NI_XS_TYPE_VOID)
		return TRUE;

	if (!(child = ni_dbus_struct_get(var, 1)))
		return FALSE;
	return ni_dbus_deserialize_xml(child, child_type, node);
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

#if 1
		if (!__ni_xs_type_to_dbus_signature(array_info->element_type, sigbuf + i, buflen - i))
			return NULL;
#else
		/* Arrays of non-scalar types always wrap each element into a VARIANT */
		if (array_info->element_type->class != NI_XS_TYPE_SCALAR)
			sigbuf[i++] = DBUS_TYPE_VARIANT;
		else if (!__ni_xs_type_to_dbus_signature(array_info->element_type, sigbuf + i, buflen - i))
			return NULL;
#endif
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
		{ "flag",	DBUS_TYPE_INVALID },

		{ NULL }
	}, *tp;

	for (tp = dbus_xml_types; tp->name; ++tp)
		ni_xs_scope_typedef(typedict, tp->name, ni_xs_scalar_new(tp->name, tp->dbus_type), NULL);
}

/*
 * Array notations
 */
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * We need to allocate the byte array as a multiple of 32, see __ni_dbus_array_grow
 */
static inline void *
__ni_notation_alloc(size_t size)
{
	void *p = malloc((size + 31) & ~31);
	ni_assert(p);
	return p;
}

static inline ni_bool_t
__ni_notation_return(const void *data, unsigned int size, unsigned char **retbuf, unsigned int *retlen)
{
	void *p;

	*retlen = size;
	*retbuf = p = __ni_notation_alloc(size);
	memcpy(p, data, size);

	return TRUE;
}

static ni_bool_t
__ni_notation_ipv4addr_parse(const char *string_value, unsigned char **retbuf, unsigned int *retlen)
{
	struct in_addr addr;

	if (inet_pton(AF_INET, string_value, &addr) != 1)
		return FALSE;

	return __ni_notation_return(&addr, sizeof(addr), retbuf, retlen);
}

static const char *
__ni_notation_ipv4addr_print(const unsigned char *data_ptr, unsigned int data_len, char *buffer, size_t size)
{
	if (data_len != sizeof(struct in_addr))
		return NULL;
	return inet_ntop(AF_INET, data_ptr, buffer, size);
}

static ni_bool_t
__ni_notation_ipv6addr_address_parse(const char *string_value, unsigned char **retbuf, unsigned int *retlen)
{
	struct in6_addr addr;

	if (inet_pton(AF_INET6, string_value, &addr) != 1)
		return FALSE;

	return __ni_notation_return(&addr, sizeof(addr), retbuf, retlen);
}

static const char *
__ni_notation_ipv6addr_address_print(const unsigned char *data_ptr, unsigned int data_len, char *buffer, size_t size)
{
	if (data_len != sizeof(struct in6_addr))
		return NULL;
	return inet_ntop(AF_INET6, data_ptr, buffer, size);
}

static ni_bool_t
__ni_notation_hwaddr_parse(const char *string_value, unsigned char **retbuf, unsigned int *retlen)
{
	unsigned int size;
	int len;
	void *p;

	size = strlen(string_value);

	p = __ni_notation_alloc(size);
	len = ni_parse_hex(string_value, p, size);
	if (len < 0) {
		free(p);
		return FALSE;
	}

	*retbuf = p;
	*retlen = len;
	return TRUE;
}

static const char *
__ni_notation_hwaddr_print(const unsigned char *data_ptr, unsigned int data_len, char *buffer, size_t size)
{
	/* We need to check whether the resulting string would fit, as
	 * ni_format_hex will happily truncate the output string if it
	 * does not fit. */
	if (3 * data_len + 1 > size)
		return NULL;

	return ni_format_hex(data_ptr, data_len, buffer, size);
}

static ni_bool_t
__ni_notation_uuid_parse(const char *string_value, unsigned char **retbuf, unsigned int *retlen)
{
	ni_uuid_t uuid;
	void *p;

	if (ni_uuid_parse(&uuid, string_value) < 0)
		return FALSE;

	p = __ni_notation_alloc(16);
	memcpy(p, uuid.octets, 16);

	*retbuf = p;
	*retlen = 16;
	return TRUE;
}

static const char *
__ni_notation_uuid_print(const unsigned char *data_ptr, unsigned int data_len, char *buffer, size_t size)
{
	ni_uuid_t uuid;
	const char *formatted;

	if (data_len != 16)
		return NULL;
	memcpy(uuid.octets, data_ptr, 16);

	formatted = ni_uuid_print(&uuid);
	if (strlen(formatted) >= size)
		return NULL;

	strcpy(buffer, formatted);
	return buffer;
}

/*
 * Parse and print functions for sockaddrs and prefixed sockaddrs
 */
static ni_bool_t
__ni_notation_netaddr_parse(const char *string_value, unsigned char **retbuf, unsigned int *retlen)
{
	ni_sockaddr_t sockaddr;
	ni_opaque_t pack;

	if (ni_sockaddr_parse(&sockaddr, string_value, AF_UNSPEC) < 0)
		return FALSE;
	if (!ni_sockaddr_pack(&sockaddr, &pack))
		return FALSE;

	return __ni_notation_return(pack.data, pack.len, retbuf, retlen);
}

static const char *
__ni_notation_netaddr_print(const unsigned char *data_ptr, unsigned int data_len, char *buffer, size_t size)
{
	ni_opaque_t pack;
	ni_sockaddr_t sockaddr;

	ni_opaque_set(&pack, data_ptr, data_len);
	if (!ni_sockaddr_unpack(&sockaddr, &pack))
		return NULL;
	return ni_sockaddr_format(&sockaddr, buffer, size);
}

static ni_bool_t
__ni_notation_netaddr_prefix_parse(const char *string_value, unsigned char **retbuf, unsigned int *retlen)
{
	char *copy = xstrdup(string_value), *s;
	unsigned int prefix = 0xFFFF;
	ni_sockaddr_t sockaddr;
	ni_bool_t result = FALSE;

	if ((s = strchr(copy, '/')) != NULL) {
		unsigned long value;

		*s++ = '\0';

		value = strtoul(s, &s, 0);
		if (*s != '\0' || value >= 0xFFFF)
			goto failed;

		prefix = value;
	}

	if (ni_sockaddr_parse(&sockaddr, copy, AF_UNSPEC) >= 0) {
		ni_opaque_t pack;

		if (!ni_sockaddr_prefix_pack(&sockaddr, prefix, &pack))
			goto failed;
		result = __ni_notation_return(pack.data, pack.len, retbuf, retlen);
	}

failed:
	free(copy);
	return result;
}

static const char *
__ni_notation_netaddr_prefix_print(const unsigned char *data_ptr, unsigned int data_len, char *buffer, size_t size)
{
	ni_opaque_t pack;
	ni_sockaddr_t sockaddr;
	unsigned int prefix;

	ni_opaque_set(&pack, data_ptr, data_len);
	if (!ni_sockaddr_prefix_unpack(&sockaddr, &prefix, &pack))
		return NULL;

	snprintf(buffer, size, "%s/%u", ni_sockaddr_print(&sockaddr), prefix);
	return buffer;
}

static ni_bool_t
__ni_notation_external_file_parse(const char *string_value, unsigned char **retbuf, unsigned int *retlen)
{
	const char *filename = string_value;
	size_t len;
	FILE *fp;

	if (!(fp = fopen(filename, "r"))) {
		ni_error("%s: %m", filename);
		return FALSE;
	}

	*retbuf = ni_file_read(fp, &len, INT_MAX);
	fclose(fp);

	if (*retbuf == NULL) {
		*retlen = 0;
		ni_error("unable to read %s: %m", filename);
	} else {
		*retlen = len;
	}

	return *retbuf != NULL;
}

static const char *
__ni_notation_external_file_print(const unsigned char *data_ptr, unsigned int data_len, char *buffer, size_t size)
{
	char *tempname = NULL;
	FILE *fp;

	if (__ni_dbus_xml_global_temp_state == NULL) {
		snprintf(buffer, size, "[[file data]]");
		return buffer;
	}

	/* If we have a global tempstate, we can store the data in a temporary file
	 * and track it for later deletion. */
	if ((fp = ni_mkstemp(&tempname)) == NULL)
		return NULL;

	ni_tempstate_add_file(__ni_dbus_xml_global_temp_state, tempname);
	ni_file_write(fp, data_ptr, data_len);
	fclose(fp);

	snprintf(buffer, size, "%s", tempname);
	ni_string_free(&tempname);

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
		.name = "uuid",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = __ni_notation_uuid_parse,
		.print = __ni_notation_uuid_print,
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
	}, {
		.name = "external-file",
		.array_element_type = DBUS_TYPE_BYTE,
		.parse = __ni_notation_external_file_parse,
		.print = __ni_notation_external_file_print,
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

/*
 * Given an xml node and an xpath expression, get list of nodes referenced by this
 */
int
ni_dbus_xml_expand_element_reference(xml_node_t *doc_node, const char *expr_string,
			xml_node_t **ret_nodes, unsigned int max_nodes)
{
	xpath_enode_t *expression;
	xpath_result_t *result;
	unsigned int i, nret;

	if (xml_node_is_empty(doc_node))
		return 0;

	expression = xpath_expression_parse(expr_string);
	if (expression == NULL)
		return -NI_ERROR_DOCUMENT_ERROR;

	result = xpath_expression_eval(expression, doc_node);
	xpath_expression_free(expression);

	if (result == NULL)
		return -NI_ERROR_DOCUMENT_ERROR;

	for (i = nret = 0; i < result->count; ++i) {
		if (result->node[i].type != XPATH_ELEMENT) {
			ni_error("%s: non-element result of xpath expression \"%s\"",
					xml_node_location(doc_node), expr_string);
			xpath_result_free(result);
			return -NI_ERROR_DOCUMENT_ERROR;
		}
		if (nret < max_nodes)
			ret_nodes[nret++] = result->node[i].value.node;
	}

	xpath_result_free(result);
	return nret;
}

/*
 * Process per-argument metadata for dbus methods
 *
 * Consult the method's metadata information to see how to
 * locate the configuration node. Any argument to a method may have
 * a <mapping> metadata element:
 *
 * <method ...>
 *   <arguments>
 *     <config type="...">
 *       <meta>
 *	   <mapping
 *	   	document-node="/some/xpath/expression" 
 *		skip-unless-present="true"
 *		/>
 *       </meta>
 *     </config>
 *   </arguments>
 * </method>
 *
 * The document node is an xpath relative to the enclosing
 * <interface> element. If the document does not contain the
 * referenced node, and skip-unless-present is true, then we
 * do not perform this call.
 */
int
ni_dbus_xml_map_method_argument(const ni_dbus_method_t *method, unsigned int index,
				xml_node_t *doc_node,
				xml_node_t **ret_node,
				ni_bool_t *ret_skip_call)
{
	ni_bool_t skip_call = FALSE; /* The default is to not skip the call. */
	const xml_node_t *meta, *mapping;

	*ret_node = NULL;

	meta = ni_dbus_xml_get_argument_metadata(method, index);
	if (meta && (mapping = xml_node_get_child(meta, "mapping")) != NULL) {
		const char *attr;

		attr = xml_node_get_attr(mapping, "skip-unless-present");
		if (attr && !strcasecmp(attr, "true"))
			skip_call = TRUE;

		attr = xml_node_get_attr(mapping, "document-node");
		if (attr != NULL && !xml_node_is_empty(doc_node)) {
			xml_node_t *expanded[2];
			int rv;

			rv = ni_dbus_xml_expand_element_reference(doc_node, attr, expanded, 2);
			if (rv < 0) {
				ni_error("%s: invalid mapping expression \"%s\"",
						xml_node_location(mapping), attr);
				return rv;
			}

#if 0
			ni_trace("applying xpath %s to node <%s> @%s - rv=%d", attr,
					doc_node->name, xml_node_location(doc_node), rv);
#endif

			if (rv == 0) {
				/* Fine, the element referenced by the xpath is not present. */
			} else
			if (rv == 1) {
				*ret_node = expanded[0];
				skip_call = FALSE;
			} else {
				ni_error("%s: ambiguous result of xpath expression \"%s\"",
						xml_node_location(mapping), attr);
				return -NI_ERROR_DOCUMENT_ERROR;
			}
		}
	}

	if (ret_skip_call)
		*ret_skip_call = skip_call;

	return 0;
}

int
ni_dbus_xml_get_method_metadata(const ni_dbus_method_t *method, const char *name,
				xml_node_t **list, unsigned int max_nodes)
{
	const ni_xs_method_t *xs_method;
	xml_node_t *meta, *child;
	unsigned int count = 0;

	if (!(xs_method = method->schema))
		return 0;
	if ((meta = xs_method->meta) == NULL)
		return 0;

	for (child = meta->children; child; child = child->next) {
		if (ni_string_eq(child->name, name) && count < max_nodes)
			list[count++] = child;
	}

	return count;
}

/*
 * A different entry point for ni_xs_type_to_dbus_signature
 */
const char *
ni_dbus_xml_type_signature(const ni_xs_type_t *type)
{
	return ni_xs_type_to_dbus_signature(type);
}
