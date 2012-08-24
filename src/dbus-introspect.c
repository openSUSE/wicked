/*
 * org.freedesktop.DBus.Introspectable
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/dbus-service.h>
#include <wicked/xml.h>
#include "dbus-server.h"
#include "dbus-object.h"
#include "dbus-dict.h"
#include "xml-schema.h"

static ni_bool_t	__ni_dbus_introspect_object(ni_dbus_object_t *, xml_node_t *);
static ni_bool_t	__ni_dbus_introspect_service(const ni_dbus_service_t *, xml_node_t *);
static ni_bool_t	__ni_dbus_introspect_method(const ni_dbus_method_t *, xml_node_t *);
static ni_bool_t	__ni_dbus_introspect_property(const ni_dbus_property_t *, xml_node_t *);
static void		__ni_dbus_introspect_annotate(xml_node_t *, const char *, const char *);

char *
ni_dbus_object_introspect(ni_dbus_object_t *object)
{
	xml_node_t *node;
	char *result = NULL;

	ni_debug_dbus("%s(%s)", __func__, object->path);

	/* FIXME: we should really create an xml_document_t here, so that we
	 * generate a proper DOCTYPE element.
	 * <!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
	 *     "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
	 */
	node = xml_node_new("node", NULL);
	if (!__ni_dbus_introspect_object(object, node))
		goto out;

	if (object->children) {
		/* We do not do a full introspection of children, but only show their presence. */
		ni_dbus_object_t *child;

		for (child = object->children; child; child = child->next) {
			xml_node_t *cnode = xml_node_new("node", node);

			xml_node_add_attr(cnode, "name", child->name);
		}
	}

	result = xml_node_sprint(node);

out:
	xml_node_free(node);
	return result;
}

ni_bool_t
__ni_dbus_introspect_object(ni_dbus_object_t *object, xml_node_t *node)
{
	unsigned int i;

	xml_node_add_attr(node, "name", object->path);
	for (i = 0; object->interfaces[i]; ++i) {
		if (!__ni_dbus_introspect_service(object->interfaces[i], xml_node_new("interface", node)))
			return FALSE;
	}

	if (object->class && object->class != &ni_dbus_anonymous_class)
		__ni_dbus_introspect_annotate(node, "org.opensuse.DBus.Class", object->class->name);
	return TRUE;
}

ni_bool_t
__ni_dbus_introspect_service(const ni_dbus_service_t *service, xml_node_t *node)
{
	unsigned int i;

	xml_node_add_attr(node, "name", service->name);
	if (service->methods) {
		for (i = 0; service->methods[i].name; ++i) {
			if (!__ni_dbus_introspect_method(&service->methods[i], xml_node_new("method", node)))
				return FALSE;
		}
	}

	if (service->signals) {
		for (i = 0; service->signals[i].name; ++i) {
			if (!__ni_dbus_introspect_method(&service->signals[i], xml_node_new("signal", node)))
				return FALSE;
		}
	}

	if (service->properties) {
		for (i = 0; service->properties[i].name; ++i) {
			if (!__ni_dbus_introspect_property(&service->properties[i], xml_node_new("property", node)))
				return FALSE;
		}
	}

	if (service->compatible)
		__ni_dbus_introspect_annotate(node, "org.opensuse.DBus.Class", service->compatible->name);

	return TRUE;
}

ni_bool_t
__ni_dbus_introspect_method(const ni_dbus_method_t *method, xml_node_t *node)
{
	const ni_xs_method_t *xs_method;
	xml_node_add_attr(node, "name", method->name);

	/* If we have the schema definition, call out the arguments here */
	if ((xs_method = method->schema) != NULL) {
		xml_node_t *arg;
		unsigned int i;

		for (i = 0; i < xs_method->arguments.count; ++i) {
			const ni_xs_name_type_t *nametype = &xs_method->arguments.data[i];
			const char *signature;

			arg = xml_node_new("arg", node);
			xml_node_add_attr(arg, "direction", "in");
			xml_node_add_attr(arg, "name", nametype->name);
			if ((signature = ni_dbus_xml_type_signature(nametype->type)) != NULL)
				xml_node_add_attr(arg, "type", signature);
		}
		if (xs_method->retval) {
			const char *signature;

			arg = xml_node_new("arg", node);
			xml_node_add_attr(arg, "direction", "out");
			xml_node_add_attr(arg, "name", "return-value");

			if ((signature = ni_dbus_xml_type_signature(xs_method->retval)) != NULL)
				xml_node_add_attr(arg, "type", signature);
		}

	}
	return TRUE;
}

ni_bool_t
__ni_dbus_introspect_property(const ni_dbus_property_t *property, xml_node_t *node)
{
	xml_node_add_attr(node, "name", property->name);
	if (property->signature)
		xml_node_add_attr(node, "type", property->signature);

	if (property->update && property->get)
		xml_node_add_attr(node, "access", "readwrite");
	else if (property->get)
		xml_node_add_attr(node, "access", "read");
	else if (property->update)
		xml_node_add_attr(node, "access", "write");
	return TRUE;
}

void
__ni_dbus_introspect_annotate(xml_node_t *node, const char *name, const char *value)
{
	xml_node_t *anode = xml_node_new("annotation", node);

	xml_node_add_attr(anode, "name", name);
	xml_node_add_attr(anode, "value", value);
}
