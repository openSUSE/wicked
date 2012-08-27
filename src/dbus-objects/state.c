/*
 * Save state of netif objects to an XML file and restore from it.
 * This can be used to retain things like addrconf state across daemon
 * restarts.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/dbus.h>
#include <wicked/objectmodel.h>
#include <wicked/xml.h>
#include "model.h"

/*
 * Get the state of a dbus object as XML.
 * We do this by going via the dbus representation, which is a bit of a waste of
 * time but at least that saves me from writing lots of code, and it makes sure
 * that we have one canonical mapping.
 * In fact, this is a lot like doing a Properties.GetAll call...
 */
static ni_bool_t
ni_objectmodel_save_object_state_xml(const ni_dbus_object_t *object, xml_node_t *parent)
{
	const ni_dbus_service_t *service;
	xml_node_t *object_node;
	unsigned int i;
	int rv = TRUE;

	object_node = xml_node_new("object", parent);
	xml_node_add_attr(object_node, "path", object->path);

	for (i = 0; rv && (service = object->interfaces[i]) != NULL; ++i) {
		ni_dbus_variant_t dict;
		xml_node_t *prop_node;

		ni_dbus_variant_init_dict(&dict);
		rv = ni_dbus_object_get_properties_as_dict(object, service, &dict, NULL);
		if (rv && dict.array.len != 0) {
			/* serialize as XML */
			prop_node = ni_dbus_xml_deserialize_properties(__ni_objectmodel_schema, service->name, &dict, object_node);
			if (!prop_node)
				rv = FALSE;
		}
		ni_dbus_variant_destroy(&dict);
	}

	return rv;
}

static ni_bool_t
ni_objectmodel_save_state_xml(xml_node_t *list, ni_dbus_server_t *server)
{
	ni_dbus_object_t *object, *netif_object;
	ni_bool_t rv = TRUE;

	object = ni_objectmodel_object_by_path(NI_OBJECTMODEL_NETIF_LIST_PATH);
	if (object == NULL) {
		ni_error("Cannot save state: no object list at %s", NI_OBJECTMODEL_NETIF_LIST_PATH);
		return FALSE;
	}

	for (netif_object = object->children; rv && netif_object; netif_object = netif_object->next) {
		rv = ni_objectmodel_save_object_state_xml(netif_object, list);
	}

	return rv;
}

ni_bool_t
ni_objectmodel_save_state(const char *filename)
{
	xml_document_t *doc;
	ni_bool_t rv = FALSE;
	FILE *fp = NULL;

	ni_debug_objectmodel("saving server state to %s", filename);

	doc = xml_document_new();
	if (!ni_objectmodel_save_state_xml(doc->root, __ni_objectmodel_server))
		goto done;

	fp = ni_file_open(filename, "w", 0600);
	if (xml_document_print(doc, fp) < 0) {
		ni_error("%s: unable to write server state to %s", __func__, filename);
		goto done;
	}

	rv = TRUE;

done:
	if (fp)
		fclose(fp);
	xml_document_free(doc);
	return rv;
}

/*
 * Recover object state from an XML file
 */
static ni_bool_t
ni_objectmodel_recover_object_state_xml(xml_node_t *object_node, ni_dbus_object_t *object, const char **prefix_list)
{
	xml_node_t *prop_node;

	/* Now process all the different properties */
	for (prop_node = object_node->children; prop_node; prop_node = prop_node->next) {
		ni_dbus_variant_t dict = NI_DBUS_VARIANT_INIT;
		const char *interface_name;
		const ni_dbus_service_t *service;
		dbus_bool_t rv;

		interface_name = prop_node->name;

		if (prefix_list) {
			ni_bool_t match = FALSE;
			unsigned int i;

			for (i = 0; prefix_list[i] && !match; ++i) {
				const char *pfx = prefix_list[i];
				unsigned int len;

				len = strlen(pfx);
				match = !strncmp(pfx, interface_name, len)
					&& (interface_name[len] == '.' || interface_name[len] == '\0');
			}
			if (!match)
				continue;
		}

		/* Parse the XML properties and store in a dbus dict. */
		if (ni_dbus_xml_serialize_properties(__ni_objectmodel_schema, &dict, prop_node) < 0) {
			ni_error("%s: unable to parse xml properties", xml_node_location(prop_node));
			ni_dbus_variant_destroy(&dict);
			return FALSE;
		}

		/* If ni_dbus_xml_serialize_properties succeeded, the following call cannot fail. */
		service = ni_objectmodel_service_by_name(interface_name);

		/* Now set the object properties from the dbus dict */
		rv = ni_dbus_object_set_properties_from_dict(object, service, &dict, NULL);
		ni_dbus_variant_destroy(&dict);

		if (!rv) {
			ni_error("%s: unable to assign properties", xml_node_location(prop_node));
			return FALSE;
		}
	}

	return TRUE;
}

static ni_bool_t
ni_objectmodel_recover_state_xml(xml_node_t *list, const char **prefix_list)
{
	ni_dbus_object_t *root_object;
	xml_node_t *object_node;

	root_object = ni_dbus_server_get_root_object(__ni_objectmodel_server);
	for (object_node = list->children; object_node; object_node = object_node->next) {
		ni_dbus_object_t *object;
		const char *name;

		if (!ni_string_eq(object_node->name, "object")) {
			ni_error("%s: not an <object> element", xml_node_location(object_node));
			return FALSE;
		}

		if (!(name = xml_node_get_attr(object_node, "path"))) {
			ni_error("%s: <object> lacks path attribute", xml_node_location(object_node));
			return FALSE;
		}
		if (!(name = ni_dbus_object_get_relative_path(root_object, name))) {
			ni_error("%s: <object> has invalid path attribute", xml_node_location(object_node));
			return FALSE;
		}

		if (!(object = ni_dbus_object_lookup(root_object, name)))
			continue;

		if (!ni_objectmodel_recover_object_state_xml(object_node, object, prefix_list))
			return FALSE;

	}

	return TRUE;
}

ni_bool_t
ni_objectmodel_recover_state(const char *filename, const char **prefix_list)
{
	xml_document_t *doc;
	ni_bool_t rv;

	if (!(doc = xml_document_read(filename))) {
		ni_error("unable to read server state from %s", filename);
		return FALSE;
	}

	rv = ni_objectmodel_recover_state_xml(doc->root, prefix_list);
	xml_document_free(doc);
	return rv;
}


