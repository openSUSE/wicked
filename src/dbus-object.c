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

#define TRACE_ENTER()		ni_debug_dbus("%s()", __FUNCTION__)
#define TRACE_ENTERN(fmt, args...) \
				ni_debug_dbus("%s(" fmt ")", __FUNCTION__, ##args)
#define TP()			ni_debug_dbus("TP - %s:%u", __FUNCTION__, __LINE__)


static char *			__ni_dbus_object_child_path(const ni_dbus_object_t *, const char *);

/*
 * Create a new dbus object
 */
ni_dbus_object_t *
__ni_dbus_object_new(char *path)
{
	ni_dbus_object_t *object;

	object = calloc(1, sizeof(*object));
	object->path = path;
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
__ni_dbus_object_new_child(const ni_dbus_object_t *parent, const char *name)
{
	ni_dbus_object_t *child;

	child = __ni_dbus_object_new(__ni_dbus_object_child_path(parent, name));
	if (!child)
		return NULL;

	ni_string_dup(&child->name, name);
	if (parent->server_object)
		__ni_dbus_server_object_inherit(child, parent);

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

	if (object->pprev) {
		*(object->pprev) = object->next;
		object->pprev = NULL;
	}

	if (object->server_object)
		__ni_dbus_server_object_destroy(object);

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
	if (object->path) {
		ni_error("%s: refusing to delete server object %s",
				__FUNCTION__, object->path);
	} else {
		__ni_dbus_object_free(object);
	}
}

/*
 * Look up an object by its relative name
 */
static ni_dbus_object_t *
__ni_dbus_object_get_child(ni_dbus_object_t *parent, const char *name, int create)
{
	ni_dbus_object_t **pos, *object;

	if (*name == '\0') {
		return parent;
	}

	pos = &parent->children;
	while ((object = *pos) != NULL) {
		if (!strcmp(object->name, name))
			return object;
		pos = &object->next;
	}

	if (create) {
		object = __ni_dbus_object_new_child(parent, name);
		__ni_dbus_object_insert(pos, object);
	}
	return object;
}

static ni_dbus_object_t *
__ni_dbus_object_lookup(ni_dbus_object_t *root_object, const char *path, int create)
{
	char *path_copy = NULL, *name;
	ni_dbus_object_t *found;

	if (path == NULL)
		return root_object;

	ni_string_dup(&path_copy, path);

	found = root_object;
	for (name = strtok(path_copy, "/"); name && found; name = strtok(NULL, "/"))
		found = __ni_dbus_object_get_child(found, name, create);

	ni_string_free(&path_copy);
	return found;
}

ni_dbus_object_t *
__ni_dbus_object_create(ni_dbus_object_t *root_object, const char *object_path,
				const ni_dbus_object_functions_t *functions,
				void *object_handle)
{
	ni_dbus_object_t *object;

	object = __ni_dbus_object_lookup(root_object, object_path, 0);
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

	object = __ni_dbus_object_lookup(root_object, object_path, 1);
	if (object == NULL) {
		ni_error("%s: could not create object \"%s\"", __FUNCTION__, object_path);
		return NULL;
	}
	object->handle = object_handle;
	object->functions = functions;

	return object;
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
		if (!strcasecmp(svc->object_interface, interface))
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

	TRACE_ENTERN("path=%s, interface=%s", object->path, svc->object_interface);

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
 * Find the named property
 */
const ni_dbus_property_t *
ni_dbus_service_get_property(const ni_dbus_service_t *service, const char *name)
{
	const ni_dbus_property_t *property;

	if (service->properties == NULL)
		return NULL;
	for (property = service->properties; property->name; ++property) {
		if (!strcmp(property->name, name))
			return property;
	}
	return NULL;
}

/*
 * Build an object path from parent path + name
 */
static char *
__ni_dbus_object_child_path(const ni_dbus_object_t *parent, const char *name)
{
	unsigned int len;
	char *child_path;

	len = strlen(parent->path) + strlen(name) + 2;
	child_path = malloc(len);
	snprintf(child_path, len, "%s/%s", parent->path, name);

	return child_path;
}
