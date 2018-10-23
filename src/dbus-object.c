/*
 * DBus generic objects (server and client side)
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/dbus-errors.h>
#include <wicked/dbus-service.h>
#include "dbus-server.h"
#include "dbus-object.h"
#include "dbus-dict.h"
#include "util_priv.h"
#include "debug.h"

static ni_dbus_object_t *	__ni_dbus_objects_trashcan;

static dbus_bool_t		__ni_dbus_object_get_one_property(const ni_dbus_object_t *object,
					const char *context,
					const ni_dbus_property_t *property,
					ni_dbus_variant_t *var,
					DBusError *error);
static const char *		__ni_dbus_object_child_path(const ni_dbus_object_t *, const char *);

const ni_dbus_class_t		ni_dbus_anonymous_class = {
	.name = "<anonymous>"
};

/*
 * Create a new dbus object
 */
ni_dbus_object_t *
__ni_dbus_object_new(const ni_dbus_class_t *class, const char *path)
{
	ni_dbus_object_t *object;

	object = xcalloc(1, sizeof(*object));
	ni_string_dup(&object->path, path);
	object->class = class;
	return object;
}

ni_dbus_object_t *
ni_dbus_object_new(const ni_dbus_class_t *class, const char *path, void *handle)
{
	ni_dbus_object_t *object;

	object = __ni_dbus_object_new(class, path);
	object->handle = handle;
	return object;
}

static ni_dbus_object_t *
__ni_dbus_object_new_child(ni_dbus_object_t *parent, const ni_dbus_class_t *object_class, const char *name,
				void *object_handle)
{
	ni_dbus_object_t **pos, *child;

	/* Find the tail of the children list */
	for (pos = &parent->children; (child = *pos) != NULL; pos = &child->next)
		;

	child = __ni_dbus_object_new(object_class, __ni_dbus_object_child_path(parent, name));
	if (!child)
		return NULL;

	child->parent = parent;
	__ni_dbus_object_insert(pos, child);
	ni_string_dup(&child->name, name);
	if (parent->server_object)
		__ni_dbus_server_object_inherit(child, parent);
	if (parent->client_object)
		__ni_dbus_client_object_inherit(child, parent);

	if (object_class == NULL && object_handle == NULL) {
#if 0
		/* We get here when called from the client side's get_managed_object code,
		 * where we do not know which objects we may be receiving from the server,
		 * but we have to create a local proxy object with a C backing object for it. */
		if (parent->class && parent->class->init_child)
			parent->class->init_child(child);
#endif
	} else {
		child->class = object_class;
		child->handle = object_handle;
	}

	if (child->class == NULL)
		child->class = &ni_dbus_anonymous_class;

	ni_debug_dbus("created %s as child of %s, class %s", child->path, parent->path, child->class->name);

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

	while ((child = object->children) != NULL)
		__ni_dbus_object_free(child);

	if (object->handle && object->class && object->class->destroy)
		object->class->destroy(object);

	ni_string_free(&object->name);
	ni_string_free(&object->path);

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

ni_bool_t
ni_dbus_objects_garbage_collect(void)
{
	ni_dbus_object_t *object;

	if (!__ni_dbus_objects_trashcan)
		return FALSE;

	ni_debug_dbus("%s()", __func__);
	while ((object = __ni_dbus_objects_trashcan) != NULL)
		__ni_dbus_object_free(object);
	return TRUE;
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
				const ni_dbus_class_t *object_class,
				void *object_handle)
{
	char *path_copy = NULL, *name, *next_name;
	ni_dbus_object_t *found;

	if (path == NULL)
		return root_object;

	/* If the path starts with a /, it's an absolute path.
	 * Strip off the root node's path. */
	if (*path == '/') {
		const char *relative_path;

		relative_path = ni_dbus_object_get_relative_path(root_object, path);
		if (relative_path == NULL) {
			ni_warn("cannot look up object %s (not a descendant of %s)",
					path, root_object->path);
			return NULL;
		}

		path = relative_path;
	}

	ni_string_dup(&path_copy, path);

	found = root_object;
	for (name = strtok(path_copy, "/"); name && found; name = next_name) {
		ni_dbus_object_t *child;

		next_name = strtok(NULL, "/");
		child = __ni_dbus_object_get_child(found, name);
		if (child == NULL && create) {
			if (next_name != NULL) {
				/* Intermediate path component */
				child = __ni_dbus_object_new_child(found, NULL, name, NULL);
			} else {
				/* Final path component consumes object handle and functions */
				child = __ni_dbus_object_new_child(found, object_class, name, object_handle);
			}
		}
		found = child;
	}

	ni_string_free(&path_copy);
	return found;
}

ni_dbus_object_t *
ni_dbus_object_create(ni_dbus_object_t *root_object, const char *object_path,
				const ni_dbus_class_t *object_class,
				void *object_handle)
{
	ni_dbus_object_t *object;

	object = __ni_dbus_object_lookup(root_object, object_path, 0, NULL, NULL);
	if (object != NULL) {
		/* Object already exists. Check for idempotent registration */
		if (object_handle && object->handle != object_handle) {
			ni_error("%s: cannot re-register object \"%s\"", __FUNCTION__, object_path);
			return NULL;
		}
		if (object_class && object->class != object_class) {
			ni_error("%s: cannot re-register object \"%s\" (changing class from %s to %s)",
					__FUNCTION__, object_path, object->class->name, object_class->name);
			return NULL;
		}
		return object;
	}

	object = __ni_dbus_object_lookup(root_object, object_path, 1, object_class, object_handle);
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
 * Find an object given its internal handle
 */
ni_dbus_object_t *
ni_dbus_object_find_descendant_by_handle(const ni_dbus_object_t *parent, const void *object_handle)
{
	ni_dbus_object_t *object, *found = NULL;

	for (object = parent->children; object && !found; object = object->next) {
		if (object->handle == object_handle)
			found = object;
		else
			found = ni_dbus_object_find_descendant_by_handle(object, object_handle);
	}

	return found;
}

/*
 * Look up an object interface by name
 */
const ni_dbus_service_t *
ni_dbus_object_get_service(const ni_dbus_object_t *object, const char *interface)
{
	const ni_dbus_service_t *svc;
	unsigned int i;

	if (object == NULL || object->interfaces == NULL)
		return NULL;

	for (i = 0; (svc = object->interfaces[i]) != NULL; ++i) {
		if (!strcasecmp(svc->name, interface))
			return svc;
	}

	return NULL;
}

/*
 * Helper function for ni_dbus_object_get_{service,signal}_for_method.
 * When searching an object's method tables, a specific method may be offered
 * by more than one service. This may be a bug, but it may also be intended,
 * for instance a subclass of netif may provide an overloaded "linkUp" method.
 * When we encounter this, we want to more specific dbus interface to "win".
 */
static inline const ni_dbus_service_t *
__ni_dbus_object_pick_more_specific(const ni_dbus_service_t *best, const ni_dbus_service_t *cur)
{
	if (best == NULL)
		return cur;

	/* Current service is more specific than the one found previously */
	if (best->compatible == NULL || ni_dbus_class_is_subclass(cur->compatible, best->compatible))
		return cur;

	/* Current service is less specific than the one found previously */
	if (cur->compatible == NULL || ni_dbus_class_is_subclass(cur->compatible, best->compatible))
		return best;

	return NULL;
}

const ni_dbus_service_t *
ni_dbus_object_get_service_for_method(const ni_dbus_object_t *object, const char *method)
{
	const ni_dbus_service_t *svc, *best = NULL;
	unsigned int i;

	if (object == NULL || object->interfaces == NULL || method == NULL)
		return NULL;

	for (i = 0; (svc = object->interfaces[i]) != NULL; ++i) {
		if (ni_dbus_service_get_method(svc, method)) {
			if (!(best = __ni_dbus_object_pick_more_specific(best, svc))) {
				ni_error("%s: ambiguous overloaded method \"%s\"", object->path, method);
				return NULL;
			}
		}
	}

	return best;
}

unsigned int
ni_dbus_object_get_all_services_for_method(const ni_dbus_object_t *object, const char *method,
					const ni_dbus_service_t **list, unsigned int list_size)
{
	const ni_dbus_service_t *svc;
	unsigned int i, found = 0;

	if (object == NULL || object->interfaces == NULL || method == NULL)
		return 0;

	for (i = 0; (svc = object->interfaces[i]) != NULL; ++i) {
		if (ni_dbus_service_get_method(svc, method)) {
			if (found < list_size)
				list[found++] = svc;
		}
	}

	return found;
}

const ni_dbus_service_t *
ni_dbus_object_get_service_for_signal(const ni_dbus_object_t *object, const char *signal_name)
{
	const ni_dbus_service_t *svc, *best = NULL;
	unsigned int i;

	if (object == NULL || object->interfaces == NULL)
		return NULL;

	for (i = 0; (svc = object->interfaces[i]) != NULL; ++i) {
		if (ni_dbus_service_get_signal(svc, signal_name)) {
			if (!(best = __ni_dbus_object_pick_more_specific(best, svc))) {
				ni_error("%s: ambiguous overloaded method \"%s\"", object->path, signal_name);
				return NULL;
			}
		}
	}

	return best;
}

const ni_dbus_service_t *
ni_dbus_object_get_service_for_property(const ni_dbus_object_t *object, const char *property_name)
{
	const ni_dbus_service_t *svc;
	unsigned int i;

	if (object == NULL || object->interfaces == NULL)
		return NULL;

	for (i = 0; (svc = object->interfaces[i]) != NULL; ++i) {
		if (ni_dbus_service_get_property(svc, property_name))
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

const char *
ni_dbus_object_get_relative_path(const ni_dbus_object_t *ancestor, const char *descendant_path)
{
	unsigned int len;

	len = strlen(ancestor->path);
	if (strncmp(descendant_path, ancestor->path, len)
	 || (descendant_path[len] && descendant_path[len] != '/'))
		return NULL;

	while (descendant_path[len] == '/')
		++len;

	return descendant_path + len;
}

/*
 * Check if a given object's is of a (subclass of a) given type
 */
dbus_bool_t
ni_dbus_object_isa(const ni_dbus_object_t *object, const ni_dbus_class_t *class)
{
	return ni_dbus_class_is_subclass(object->class, class);
}

dbus_bool_t
ni_dbus_class_is_subclass(const ni_dbus_class_t *subclass, const ni_dbus_class_t *superclass)
{
	while (subclass) {
		if (subclass == superclass)
			return TRUE;
		subclass = subclass->superclass;
	}
	return FALSE;
}

/*
 * Register an interface for the given object.
 * Note, we cannot register fallback services yet.
 */
dbus_bool_t
ni_dbus_object_register_service(ni_dbus_object_t *object, const ni_dbus_service_t *svc)
{
	unsigned int count;

#if 0
	NI_TRACE_ENTER_ARGS("path=%s, interface=%s", object->path, svc->name);
#endif

	if (svc->compatible && !ni_dbus_object_isa(object, svc->compatible)) {
		ni_error("cannot register dbus interface %s (class %s) with object %s: "
			 "not compatible with object class %s",
			 svc->name, svc->compatible->name,
			 object->path, object->class? object->class->name : "<no class>");
		return FALSE;
	}

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
 * Given an object and a property name, get its value
 */
dbus_bool_t
ni_dbus_object_get_property(const ni_dbus_object_t *object, const char *property_path, const ni_dbus_service_t *service, ni_dbus_variant_t *var)
{
	const ni_dbus_property_t *property = NULL;
	DBusError error = DBUS_ERROR_INIT;

	if (service == NULL) {
		char *copy, *s;

		/* Truncate the property path at the first dot, and look up the
		 * dbus interface that provides this property. */
		copy = xstrdup(property_path);
		if ((s = strchr(copy, '.')) != NULL)
			*s = '\0';

		service = ni_dbus_object_get_service_for_property(object, copy);
		free(copy);

		if (service == NULL) {
			ni_error("object %s has no property named \"%s\"", object->path, property_path);
			return FALSE;
		}
	}

	if (!(property = ni_dbus_service_lookup_property(service, property_path))) {
		ni_error("object %s has no property named \"%s\"", object->path, property_path);
		return FALSE;
	}

	if (!__ni_dbus_object_get_one_property(object, property_path, property, var, &error)) {
		ni_error("%s: unable to get property named \"%s\"", object->path, property_path);
		dbus_error_free(&error);
		return FALSE;
	}

	dbus_error_free(&error);
	return TRUE;
}

/*
 * Get one property of an object
 */
dbus_bool_t
__ni_dbus_object_get_one_property(const ni_dbus_object_t *object,
					const char *context,
					const ni_dbus_property_t *property,
					ni_dbus_variant_t *var,
					DBusError *error)
{
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
		ni_dbus_variant_destroy(var);

		/* If get() fails without setting the error, this means the property is not present. */
		if (!dbus_error_is_set(error))
			ni_dbus_error_property_not_present(error, object->path, property->name);
		return FALSE;
	}

	return TRUE;
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
	ni_dbus_property_get_handle_fn_t *get_handle_failed = NULL;
	const ni_dbus_property_t *property;

	/* Loop over properties and add them here */
	for (property = properties; property->name; ++property) {
		ni_dbus_variant_t value = NI_DBUS_VARIANT_INIT, *var;

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
			ni_dbus_variant_t *child, temp = NI_DBUS_VARIANT_INIT;
			char subcontext[512];

			ni_dbus_variant_init_dict(&temp);

			snprintf(subcontext, sizeof(subcontext), "%s.%s", context, property->name);
			if (!__ni_dbus_object_get_properties_as_dict(object, subcontext, child_properties, &temp, error)) {
				ni_dbus_variant_destroy(&temp);
				return FALSE;
			}

			if (ni_dbus_dict_is_empty(&temp)) {
				/* If the child dict is empty, do not encode it at all */
				ni_dbus_variant_destroy(&temp);
			} else {
				child = ni_dbus_dict_add(dict, property->name);
				ni_assert(child);
				*child = temp;
			}
			continue;
		}

		if (property->get == NULL)
			continue;

		/* Quite often, we have a set of values attached to a netdev object
		 * that is accessed through a pointer (dev->foobar).
		 *
		 * Generic properties use the get_handle function to retrieve that
		 * pointer, and the operate on a variable at a specific offset.
		 *
		 * Now, if the device's pointer is not set, we could call each
		 * property's get() function in turn, setting up a variant variable,
		 * only to find that the get_handle() function returns NULL.
		 *
		 * We try to optimize this case slightly by checking this here, and
		 * recording this failure.
		 */
		if (property->generic.get_handle
		 && property->generic.get_handle == get_handle_failed)
			continue;

		get_handle_failed = NULL;
		if (__ni_dbus_object_get_one_property(object, context, property, &value, error)) {
			var = ni_dbus_dict_add(dict, property->name);
			*var = value;
		} else {
			ni_dbus_variant_destroy(&value);
			if (error->name && !strcmp(error->name, NI_DBUS_ERROR_PROPERTY_NOT_PRESENT)) {
				/* just ignore this error */
				dbus_error_free(error);

				/* Remember the get_handle function if there is one */
				get_handle_failed = property->generic.get_handle;
				if (get_handle_failed) {
					/* The get() call may have failed for some other reason.
					 * Verify that the get_handle() call really returned NULL. */
					if (get_handle_failed(object, FALSE, error) != NULL)
						get_handle_failed = NULL;
					dbus_error_free(error);
				}
			} else {
				ni_debug_dbus("%s: unable to get property %s.%s (error %s: %s)",
						object->path,
						context,
						property->name,
						error->name, error->message);
				return FALSE;
			}
		}
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_object_get_properties_as_dict(const ni_dbus_object_t *object,
					const ni_dbus_service_t *interface,
					ni_dbus_variant_t *dict,
					DBusError *error)
{
	int rv = TRUE;

#if 0
	NI_TRACE_ENTER_ARGS("object=%s, interface=%s", object->path, interface->name);
#endif

	/* Loop over properties and add them here */
	if (interface->properties) {
		DBusError local_error = DBUS_ERROR_INIT;

		if (error == NULL)
			error = &local_error;

		rv = __ni_dbus_object_get_properties_as_dict(object,
						interface->name,
						interface->properties,
						dict, error);
		dbus_error_free(&local_error);
	}

	return rv;
}

/*
 * Helper function for setting all properties from a dict
 */
static dbus_bool_t
__ni_dbus_object_set_properties_from_dict(ni_dbus_object_t *object,
				const char *context,
				const ni_dbus_property_t *properties,
				const ni_dbus_variant_t *dict,
				DBusError *error)
{
	unsigned int i;

	for (i = 0; i < dict->array.len; ++i) {
		ni_dbus_dict_entry_t *entry = &dict->dict_array_value[i];
		const ni_dbus_property_t *property;

		/* now set the object property */
		if (!(property = __ni_dbus_service_get_property(properties, entry->key))) {
			ni_debug_dbus("%s: ignoring unknown property %s.%s=%s",
					object->path, context, entry->key,
					ni_dbus_variant_sprint(&entry->datum));
			continue;
		}

		/* We could just have a .set function for dicts that does what
		 * the following if() statement does, except we'd lose the context
		 * of the surrounding interface/property names in error messages.
		 * Maybe not such a great loss, though...
		 */
		if (property->signature && !strcmp(property->signature, NI_DBUS_DICT_SIGNATURE)
		 && property->generic.u.dict_children != NULL) {
			const ni_dbus_property_t *child_properties = property->generic.u.dict_children;
			char subcontext[512];

			snprintf(subcontext, sizeof(subcontext), "%s.%s", context, property->name);
			if (!__ni_dbus_object_set_properties_from_dict(object, subcontext, child_properties, &entry->datum, error))
				return FALSE;
			continue;
		}

		if (!property->set) {
			ni_debug_dbus("%s: ignoring read-only property %s.%s=%s",
					object->path, context, entry->key,
					ni_dbus_variant_sprint(&entry->datum));
			continue;
		}

		if (!property->set(object, property, &entry->datum, error)) {
			ni_debug_dbus("%s: error setting property %s.%s=%s (%s: %s)",
					object->path, context, entry->key,
					ni_dbus_variant_sprint(&entry->datum),
					error->name, error->message);
			dbus_error_free(error);
			continue;
		}

#if 0
		ni_debug_dbus("Setting property %s=%s", entry->key, ni_dbus_variant_sprint(&entry->datum));
#endif
	}

	return TRUE;
}

dbus_bool_t
ni_dbus_object_set_properties_from_dict(ni_dbus_object_t *object,
				const ni_dbus_service_t *interface,
				const ni_dbus_variant_t *dict, DBusError *error)
{
	DBusError local_error = DBUS_ERROR_INIT;
	dbus_bool_t rv;

	if (!error)
		error = &local_error;
	rv = __ni_dbus_object_set_properties_from_dict(object,
				interface->name,
				interface->properties,
				dict,
				error);
	dbus_error_free(&local_error);
	return rv;
}

/*
 * Generic property handlers
 */
#define __property_offset(prop, type)		prop->generic.u.type##_offset
#define __property_data(prop, handle, type) \
	(typeof(__property_offset(prop, type))) (handle + (unsigned long) __property_offset(prop, type))

void *
ni_dbus_generic_property_write_handle(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop, DBusError *error)
{
	return prop->generic.get_handle(obj, TRUE, error);
}

const void *
ni_dbus_generic_property_read_handle(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop, DBusError *error)
{
	void *handle;

	dbus_error_free(error);
	handle = prop->generic.get_handle(obj, FALSE, error);

	/* If the get_handle function returns NULL without setting the error,
	 * this means the property is not present. */
	if (handle == NULL && !dbus_error_is_set(error))
		ni_dbus_error_property_not_present(error, obj->path, prop->name);
	return handle;
}

dbus_bool_t
ni_dbus_generic_property_get_bool(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const ni_bool_t *vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, bool);

	/* More recent dbus libraries get fuzzy with what they accept in
	 * a boolean.
	 * However, some variables we use (such as ipv6/use_tempaddr) may
	 * have a value of -1 or 0xFF to signal "not possible".
	 * For now, work around this issue by using this hack. */
	if (*vptr != FALSE && *vptr != TRUE)
		return ni_dbus_error_property_not_present(error, obj->path, prop->name);
	return ni_dbus_variant_assign_bool(var, *vptr);
}

dbus_bool_t
ni_dbus_generic_property_set_bool(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	dbus_bool_t dbool;
	ni_bool_t *vptr;
	void *handle;

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, bool);
	if (!ni_dbus_variant_get_bool(var, &dbool))
		return FALSE;
	*vptr = dbool;
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_parse_bool(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	return ni_dbus_variant_parse(var, string, prop->signature);
}

dbus_bool_t
ni_dbus_generic_property_update_bool(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	if (!ni_dbus_generic_property_set_bool(obj, prop, var, error))
		return FALSE;

#if 0
	/* call object's "property_updated" callback */
#endif
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_get_int(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const int *vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, int);
	return ni_dbus_variant_set_int(var, *vptr);
}

dbus_bool_t
ni_dbus_generic_property_set_int(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	int *vptr;
	void *handle;

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, int);
	return ni_dbus_variant_get_int(var, vptr);
}

dbus_bool_t
ni_dbus_generic_property_parse_int(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	return ni_dbus_variant_parse(var, string, prop->signature);
}

dbus_bool_t
ni_dbus_generic_property_get_uint(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const unsigned int *vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
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

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
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
ni_dbus_generic_property_get_int16(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const int16_t *vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, int16);
	ni_dbus_variant_set_int16(var, *vptr);
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_set_int16(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	int16_t *vptr;
	void *handle;

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, int16);
	return ni_dbus_variant_get_int16(var, vptr);
}

dbus_bool_t
ni_dbus_generic_property_parse_int16(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	return ni_dbus_variant_parse(var, string, prop->signature);
}

dbus_bool_t
ni_dbus_generic_property_get_uint16(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const uint16_t *vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
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

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
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
ni_dbus_generic_property_get_int64(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const int64_t *vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, int64);
	ni_dbus_variant_set_int64(var, *vptr);
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_set_int64(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	int64_t *vptr;
	void *handle;

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, int64);
	return ni_dbus_variant_get_int64(var, vptr);
}

dbus_bool_t
ni_dbus_generic_property_parse_int64(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	return ni_dbus_variant_parse(var, string, prop->signature);
}

dbus_bool_t
ni_dbus_generic_property_get_uint64(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const uint64_t *vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, uint64);
	ni_dbus_variant_set_uint64(var, *vptr);
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_set_uint64(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	uint64_t *vptr;
	void *handle;

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, uint64);
	return ni_dbus_variant_get_uint64(var, vptr);
}

dbus_bool_t
ni_dbus_generic_property_parse_uint64(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	return ni_dbus_variant_parse(var, string, prop->signature);
}

dbus_bool_t
ni_dbus_generic_property_get_double(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const double *vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, double);
	ni_dbus_variant_set_double(var, *vptr);
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_set_double(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	double *vptr;
	void *handle;

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, double);
	return ni_dbus_variant_get_double(var, vptr);
}

dbus_bool_t
ni_dbus_generic_property_parse_double(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
{
	return ni_dbus_variant_parse(var, string, prop->signature);
}

dbus_bool_t
ni_dbus_generic_property_get_string(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	char **vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, string);
	if (*vptr == NULL) {
		dbus_set_error(error, NI_DBUS_ERROR_PROPERTY_NOT_PRESENT, "property %s not present", prop->name);
		return FALSE;
	}
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

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
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
ni_dbus_generic_property_get_uuid(const ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					ni_dbus_variant_t *var, DBusError *error)
{
	const ni_uuid_t *vptr;
	const void *handle;

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, uuid);
	ni_dbus_variant_set_uuid(var, vptr);
	return TRUE;
}

dbus_bool_t
ni_dbus_generic_property_set_uuid(ni_dbus_object_t *obj, const ni_dbus_property_t *prop,
					const ni_dbus_variant_t *var, DBusError *error)
{
	ni_uuid_t *vptr;
	void *handle;

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
		return FALSE;

	vptr = __property_data(prop, handle, uuid);
	return ni_dbus_variant_get_uuid(var, vptr);
}

dbus_bool_t
ni_dbus_generic_property_parse_uuid(const ni_dbus_property_t *prop, ni_dbus_variant_t *var, const char *string)
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

	if (!(handle = ni_dbus_generic_property_read_handle(obj, prop, error)))
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

	if (!(handle = ni_dbus_generic_property_write_handle(obj, prop, error)))
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
