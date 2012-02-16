/*
 * DBus generic objects (server and client side)
 *
 * Copyright (C) 2011 Olaf Kirch <okir@suse.de>
 */

#include <dbus/dbus.h>
#include <stdlib.h>
#include <wicked/util.h>
#include <wicked/logging.h>
#include "dbus-server.h"
#include "dbus-object.h"
#include "dbus-dict.h"
#include "util_priv.h"
#include "debug.h"

static ni_dbus_object_t *	__ni_dbus_objects_trashcan;

static const char *		__ni_dbus_object_child_path(const ni_dbus_object_t *, const char *);

/*
 * Create a new dbus object
 */
ni_dbus_object_t *
__ni_dbus_object_new(const char *path)
{
	ni_dbus_object_t *object;

	object = calloc(1, sizeof(*object));
	ni_string_dup(&object->path, path);
	return object;
}

ni_dbus_object_t *
ni_dbus_object_new(const char *path, const ni_dbus_object_functions_t *functions, void *handle)
{
	ni_dbus_object_t *object;

	object = __ni_dbus_object_new(path? xstrdup(path) : NULL);
	object->functions = functions;
	object->handle = handle;
	return object;
}

static ni_dbus_object_t *
__ni_dbus_object_new_child(ni_dbus_object_t *parent, const char *name,
				const ni_dbus_object_functions_t *functions,
				void *object_handle)
{
	ni_dbus_object_t **pos, *child;

	/* Find the tail of the children list */
	for (pos = &parent->children; (child = *pos) != NULL; pos = &child->next)
		;

	child = __ni_dbus_object_new(__ni_dbus_object_child_path(parent, name));
	if (!child)
		return NULL;

	child->parent = parent;
	__ni_dbus_object_insert(pos, child);
	ni_string_dup(&child->name, name);
	if (parent->server_object)
		__ni_dbus_server_object_inherit(child, parent);
	if (parent->client_object)
		__ni_dbus_client_object_inherit(child, parent);

	if (parent->functions && parent->functions->init_child) {
		if (functions || object_handle) {
			ni_fatal("error when creating dbus object %s: "
				"handle/functions arguments conflict with parent object's init_child method",
				child->path);
		}
		parent->functions->init_child(child);
	} else {
		child->handle = object_handle;
		child->functions = functions;
	}

	ni_debug_dbus("created %s as child of %s", child->path, parent->path);

	return child;
}

/*
 * Free a dbus object
 */
void
__ni_dbus_object_free(ni_dbus_object_t *object)
{
	ni_dbus_object_t *child;

	__ni_dbus_object_unlink(object);
	object->parent = NULL;

	if (object->server_object)
		__ni_dbus_server_object_destroy(object);
	if (object->client_object)
		__ni_dbus_client_object_destroy(object);

	ni_string_free(&object->name);
	ni_string_free(&object->path);

	while ((child = object->children) != NULL)
		__ni_dbus_object_free(child);

	free(object->interfaces);
	free(object);
}

/*
 * User-visible function: delete an object previously created through
 * ni_dbus_server_create_anonymous_object.
 */
void
ni_dbus_object_free(ni_dbus_object_t *object)
{
	if (object->pprev) {
		ni_debug_dbus("%s: deferring deletion of active object %s",
				__FUNCTION__, object->path);
		__ni_dbus_object_unlink(object);
		object->parent = NULL;
		__ni_dbus_object_insert(&__ni_dbus_objects_trashcan, object);
	} else {
		__ni_dbus_object_free(object);
	}
}

void
__ni_dbus_objects_garbage_collect(void)
{
	ni_dbus_object_t *object;

	while ((object = __ni_dbus_objects_trashcan) != NULL)
		__ni_dbus_object_free(object);
}

/*
 * Translate a DBus error, optionally using the error map provided by
 * the client handle (if this is a client side object)
 */
int
ni_dbus_object_translate_error(ni_dbus_object_t *obj, const DBusError *error)
{
	const ni_intmap_t *error_map = NULL;

	error_map = __ni_dbus_client_object_get_error_map(obj);
#if 0
	if (error_map == NULL)
		error_map = __ni_dbus_server_object_get_error_map(obj);
#endif
	return ni_dbus_translate_error(error, error_map);
}

/*
 * Look up an object by its relative name
 */
static ni_dbus_object_t *
__ni_dbus_object_get_child(ni_dbus_object_t *parent, const char *name)
{
	ni_dbus_object_t *child;

	if (*name == '\0')
		return parent;

	for (child = parent->children; child; child = child->next) {
		if (!strcmp(child->name, name))
			return child;
	}

	return NULL;
}

static ni_dbus_object_t *
__ni_dbus_object_lookup(ni_dbus_object_t *root_object, const char *path, int create,
				const ni_dbus_object_functions_t *functions,
				void *object_handle)
{
	char *path_copy = NULL, *name, *next_name;
	ni_dbus_object_t *found;

	if (path == NULL)
		return root_object;

	ni_string_dup(&path_copy, path);

	found = root_object;
	for (name = strtok(path_copy, "/"); name && found; name = next_name) {
		ni_dbus_object_t *child;

		next_name = strtok(NULL, "/");
		child = __ni_dbus_object_get_child(found, name);
		if (child == NULL && create) {
			if (next_name != NULL) {
				/* Intermediate path component */
				child = __ni_dbus_object_new_child(found, name, NULL, NULL);
			} else {
				/* Final path component consumes object handle and functions */
				child = __ni_dbus_object_new_child(found, name, functions, object_handle);
			}
		}
		found = child;
	}

	ni_string_free(&path_copy);
	return found;
}

ni_dbus_object_t *
ni_dbus_object_create(ni_dbus_object_t *root_object, const char *object_path,
				const ni_dbus_object_functions_t *functions,
				void *object_handle)
{
	ni_dbus_object_t *object;

	object = __ni_dbus_object_lookup(root_object, object_path, 0, NULL, NULL);
	if (object != NULL) {
		/* Object already exists. Check for idempotent registration */
		if (object->handle != object_handle) {
			ni_error("%s: cannot re-register object \"%s\"", __FUNCTION__, object_path);
			return NULL;
		}
		if (object->functions != functions) {
			ni_error("%s: cannot re-register object \"%s\"", __FUNCTION__, object_path);
			return NULL;
		}
		return object;
	}

	object = __ni_dbus_object_lookup(root_object, object_path, 1, functions, object_handle);
	if (object == NULL) {
		ni_error("%s: could not create object \"%s\"", __FUNCTION__, object_path);
		return NULL;
	}

	return object;
}

ni_dbus_object_t *
ni_dbus_object_lookup(ni_dbus_object_t *root_object, const char *path)
{
	return __ni_dbus_object_lookup(root_object, path, 0, NULL, NULL);
}

/*
 * Look up an object interface by name
 */
const ni_dbus_service_t *
ni_dbus_object_get_service(const ni_dbus_object_t *object, const char *interface)
{
	const ni_dbus_service_t *svc;
	unsigned int i;

	if (object->interfaces == NULL)
		return NULL;

	for (i = 0; (svc = object->interfaces[i]) != NULL; ++i) {
		if (!strcasecmp(svc->name, interface))
			return svc;
	}

	return NULL;
}

const ni_dbus_service_t *
ni_dbus_object_get_service_for_method(const ni_dbus_object_t *object, const char *method)
{
	const ni_dbus_service_t *svc;
	unsigned int i;

	if (object->interfaces == NULL || method == NULL)
		return NULL;

	for (i = 0; (svc = object->interfaces[i]) != NULL; ++i) {
		if (ni_dbus_service_get_method(svc, method))
			return svc;
	}

	return NULL;
}

const ni_dbus_service_t *
ni_dbus_object_get_service_for_signal(const ni_dbus_object_t *object, const char *signal_name)
{
	const ni_dbus_service_t *svc;
	unsigned int i;

	if (object->interfaces == NULL)
		return NULL;

	for (i = 0; (svc = object->interfaces[i]) != NULL; ++i) {
		if (ni_dbus_service_get_signal(svc, signal_name))
			return svc;
	}

	return NULL;
}

/*
 * Helper functions
 */
const char *
ni_dbus_object_get_path(const ni_dbus_object_t *object)
{
	return object->path;
}

void *
ni_dbus_object_get_handle(const ni_dbus_object_t *object)
{
	return object->handle;
}

/*
 * Register an interface for the given object.
 * Note, we cannot register fallback services yet.
 */
dbus_bool_t
ni_dbus_object_register_service(ni_dbus_object_t *object, const ni_dbus_service_t *svc)
{
	unsigned int count;

	NI_TRACE_ENTER_ARGS("path=%s, interface=%s", object->path, svc->name);

	count = 0;
	if (object->interfaces != NULL) {
		while (object->interfaces[count] != NULL) {
			if (object->interfaces[count] == svc)
				return TRUE;
			++count;
		}
	}

	object->interfaces = realloc(object->interfaces, (count + 2) * sizeof(svc));
	object->interfaces[count++] = svc;
	object->interfaces[count] = NULL;

	if (svc->properties)
		ni_dbus_object_register_property_interface(object);
	return TRUE;
}

/*
 * Find the named method
 */
const ni_dbus_method_t *
ni_dbus_service_get_method(const ni_dbus_service_t *service, const char *name)
{
	const ni_dbus_method_t *method;

	if (service->methods == NULL)
		return NULL;
	for (method = service->methods; method->name; ++method) {
		if (!strcmp(method->name, name))
			return method;
	}
	return NULL;
}

/*
 * Find the named signal
 */
const ni_dbus_method_t *
ni_dbus_service_get_signal(const ni_dbus_service_t *service, const char *name)
{
	const ni_dbus_method_t *method;

	if (service->signals == NULL)
		return NULL;
	for (method = service->signals; method->name; ++method) {
		if (!strcmp(method->name, name))
			return method;
	}
	return NULL;
}


/*
 * Find the named property
 */
const ni_dbus_property_t *
__ni_dbus_service_get_property(const ni_dbus_property_t *property_list, const char *name)
{
	const ni_dbus_property_t *property;

	if (property_list == NULL)
		return NULL;
	for (property = property_list; property->name; ++property) {
		if (!strcmp(property->name, name))
			return property;
	}
	return NULL;
}

const ni_dbus_property_t *
ni_dbus_service_get_property(const ni_dbus_service_t *service, const char *name)
{
	return __ni_dbus_service_get_property(service->properties, name);
}

const ni_dbus_property_t *
ni_dbus_service_lookup_property(const ni_dbus_service_t *service, const char *name)
{
	return ni_dbus_service_create_property(service, name, NULL, NULL);
}

const ni_dbus_property_t *
ni_dbus_service_create_property(const ni_dbus_service_t *service, const char *name,
				ni_dbus_variant_t *dict, ni_dbus_variant_t **outdict)
{
	const ni_dbus_property_t *property_list, *property = NULL;
	char *dot, *s, *copy;

	/* Fast path - handle properties without . in the name */
	if (strchr(name, '.') == NULL) {
		property = __ni_dbus_service_get_property(service->properties, name);
		goto done;
	}

	copy = xstrdup(name);
	property_list = service->properties;
	for (s = copy; s; s = dot) {
		if ((dot = strchr(s, '.')) != NULL)
			*dot++ = '\0';
		property = __ni_dbus_service_get_property(property_list, s);
		if (property == NULL)
			break;

		property_list = NULL;
		if (property->signature && !strcmp(property->signature, NI_DBUS_DICT_SIGNATURE)) {
			property_list = property->generic.u.dict_children;
			if (dict) {
				ni_dbus_variant_t *child;

				child = ni_dbus_dict_get(dict, property->name);
				if (child == NULL) {
					child = ni_dbus_dict_add(dict, property->name);
					ni_dbus_variant_init_dict(child);
				} else if (!ni_dbus_variant_is_dict(child)) {
					ni_error("Error adding property %s to dict - exists but is not a dict",
							property->name);
					return NULL;
				}
				dict = child;
			}
		}
	}
	free(copy);

done:
	if (outdict)
		*outdict = dict;
	return property;
}

/*
 * Get all properties of an object, for a given dbus interface
 */
dbus_bool_t
__ni_dbus_object_get_properties_as_dict(const ni_dbus_object_t *object,
					const char *context,
					const ni_dbus_property_t *properties,
					ni_dbus_variant_t *dict,
					DBusError *error)
{
	const ni_dbus_property_t *property;

	/* Loop over properties and add them here */
	for (property = properties; property->name; ++property) {
		ni_dbus_variant_t *var;

		if (property->signature == NULL)
			continue;

		/* We could just have a .get function for dicts that does what
		 * the following if() statement does, except we'd lose the context
		 * of the surrounding interface/property names in error messages.
		 * Maybe not such a great loss, though...
		 */
		if (!strcmp(property->signature, NI_DBUS_DICT_SIGNATURE)
		 && property->generic.u.dict_children != NULL) {
			const ni_dbus_property_t *child_properties = property->generic.u.dict_children;
			ni_dbus_variant_t *child;
			char subcontext[512];

			child = ni_dbus_dict_add(dict, property->name);
			ni_dbus_variant_init_dict(child);

			snprintf(subcontext, sizeof(subcontext), "%s.%s", context, property->name);
			if (!__ni_dbus_object_get_properties_as_dict(object, subcontext, child_properties, child, error))
				return FALSE;
			continue;
		}

		if (property->get == NULL)
			continue;

		var = ni_dbus_dict_add(dict, property->name);
		if (property->signature) {
			/* Initialize the variant to the specified type. This allows
			 * the property handler to use generic variant_set_int functions
			 * and the like, without having to know exactly which type
			 * is being used. */
			if (!ni_dbus_variant_init_signature(var, property->signature)) {
				ni_debug_dbus("%s: unable to initialize property %s.%s of type %s",
					object->path,
					context,
					property->name,
					property->signature);
				return FALSE;
			}
		}

		if (!property->get(object, property, var, error)) {
			ni_debug_dbus("%s: unable to get property %s.%s",
					object->path,
					context,
					property->name);
			ni_dbus_variant_destroy(var);
		}
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_object_get_properties_as_dict(const ni_dbus_object_t *object,
					const ni_dbus_service_t *interface,
					ni_dbus_variant_t *dict)
{
	int rv = TRUE;

	NI_TRACE_ENTER_ARGS("object=%s, interface=%s", object->path, interface->name);

	/* Loop over properties and add them here */
	if (interface->properties) {
		DBusError error = DBUS_ERROR_INIT;

		rv = __ni_dbus_object_get_properties_as_dict(object,
						interface->name,
						interface->properties,
						dict, &error);
		dbus_error_free(&error);
	}

	return rv;
}

/*
 * Generic property handlers
 */
#define __property_offset(prop, type)		prop->generic.u.type##_offset
#define __property_data(prop, handle, type) \
	(typeof(__property_offset(prop, type))) (handle + (unsigned long) __property_offset(prop, type))

dbus_bool_t
ni_dbus_generic_property_get_uint(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const unsigned int *vptr;
	const void *handle;

	if (!(handle = prop->generic.get_handle(obj, error)))
		return FALSE;

	vptr = __property_data(prop, handle, uint);
	return ni_dbus_variant_set_uint(var, *vptr);
}

dbus_bool_t
ni_dbus_generic_property_set_uint(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	unsigned int *vptr;
	void *handle;

	if (!(handle = prop->generic.get_handle(obj, error)))
		return FALSE;

	vptr = __property_data(prop, handle, uint);
	return ni_dbus_variant_get_uint(var, vptr);
}

dbus_bool_t
ni_dbus_generic_property_parse_uint(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	return ni_dbus_variant_parse(var, string, prop->signature);
}

dbus_bool_t
ni_dbus_generic_property_get_uint16(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const uint16_t *vptr;
	const void *handle;

	if (!(handle = prop->generic.get_handle(obj, error)))
		return FALSE;

	vptr = __property_data(prop, handle, uint16);
	ni_dbus_variant_set_uint16(var, *vptr);
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_set_uint16(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	uint16_t *vptr;
	void *handle;

	if (!(handle = prop->generic.get_handle(obj, error)))
		return FALSE;

	vptr = __property_data(prop, handle, uint16);
	return ni_dbus_variant_get_uint16(var, vptr);
}

dbus_bool_t
ni_dbus_generic_property_parse_uint16(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	return ni_dbus_variant_parse(var, string, prop->signature);
}

dbus_bool_t
ni_dbus_generic_property_get_string(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	char **vptr;
	const void *handle;

	if (!(handle = prop->generic.get_handle(obj, error)))
		return FALSE;

	vptr = __property_data(prop, handle, string);
	ni_dbus_variant_set_string(var, *vptr);
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_set_string(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	const char *value;
	char **vptr;
	void *handle;

	if (!(handle = prop->generic.get_handle(obj, error)))
		return FALSE;

	if (!ni_dbus_variant_get_string(var, &value))
		return FALSE;

	vptr = __property_data(prop, handle, string);
	ni_string_dup(vptr, value);
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_parse_string(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	return ni_dbus_variant_parse(var, string, prop->signature);
}

dbus_bool_t
ni_dbus_generic_property_get_string_array(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const ni_string_array_t *vptr;
	const void *handle;
	unsigned int i;

	if (!(handle = prop->generic.get_handle(obj, error)))
		return FALSE;

	vptr = __property_data(prop, handle, string_array);

	ni_dbus_variant_init_string_array(var);
	for (i = 0; i < vptr->count; ++i) {
		ni_dbus_variant_append_string_array(var, vptr->data[i]);
	}
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_set_string_array(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	ni_string_array_t *vptr;
	unsigned int i;
	void *handle;

	if (!(handle = prop->generic.get_handle(obj, error)))
		return FALSE;

	vptr = __property_data(prop, handle, string_array);
	for (i = 0; i < var->array.len; ++i)
		ni_string_array_append(vptr, var->string_array_value[i]);
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_parse_string_array(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	char *s, *copy;

	copy = strdup(string);
	ni_dbus_variant_init_string_array(var);

	/* Should take quoting into account */
	for (s = strtok(copy, ","); s; s = strtok(NULL, ","))
		ni_dbus_variant_append_string_array(var, s);
	return TRUE;
}

/*
 * Build an object path from parent path + name
 */
static const char *
__ni_dbus_object_child_path(const ni_dbus_object_t *parent, const char *name)
{
	static char child_path[256];
	unsigned int len;

	len = strlen(parent->path) + strlen(name) + 2;
	if (len >= sizeof(child_path))
		ni_fatal("%s: child path too long (%s.%s)", __FUNCTION__,
				parent->path, name);

	snprintf(child_path, sizeof(child_path), "%s/%s", parent->path, name);
	return child_path;
}
