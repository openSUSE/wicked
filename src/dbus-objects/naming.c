/*
 * DBus encapsulation for network interfaces
 *
 * Copyright (C) 2011-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/dbus-errors.h>
#include <wicked/ethernet.h>
#include <wicked/modem.h>
#include <wicked/pci.h>
#include <wicked/xml.h>
#include "dbus-common.h"
#include "model.h"
#include "appconfig.h"
#include "extension.h"
#include "debug.h"

static unsigned int		ni_objectmodel_ns_count;
static ni_objectmodel_ns_t **	ni_objectmodel_ns_list;

void
ni_objectmodel_register_ns(ni_objectmodel_ns_t *ns)
{
	if ((ni_objectmodel_ns_count % 8) == 0)
		ni_objectmodel_ns_list = realloc(ni_objectmodel_ns_list,
				(ni_objectmodel_ns_count + 8) * sizeof(ni_objectmodel_ns_list[0]));
	ni_objectmodel_ns_list[ni_objectmodel_ns_count++] = ns;
}

ni_objectmodel_ns_t *
ni_objectmodel_get_ns(const char *name)
{
	unsigned int i;

	for (i = 0; i < ni_objectmodel_ns_count; ++i) {
		ni_objectmodel_ns_t *ns;

		ns = ni_objectmodel_ns_list[i];
		if (ni_string_eq(ns->name, name))
			return ns;
	}
	return NULL;
}

/*
 * Register all naming services specified in the config file.
 * These naming services are supposed to be provided by shared libraries.
 * The symbol specified by the C binding element must refer to a
 * ni_objectmodel_ns struct.
 */
void
ni_objectmodel_register_ns_dynamic(void)
{
	ni_config_t *config = ni_global.config;
	ni_extension_t *ex;

	ni_assert(config);
	for (ex = config->ns_extensions; ex; ex = ex->next) {
		ni_c_binding_t *binding;
		void *addr;

		for (binding = ex->c_bindings; binding; binding = binding->next) {
			if ((addr = ni_c_binding_get_address(binding)) == NULL) {
				ni_error("cannot bind %s name service - invalid C binding",
						binding->name);
				continue;
			}

			ni_debug_objectmodel("trying to bind netif naming service \"%s\"", binding->name);
			ni_objectmodel_register_ns((ni_objectmodel_ns_t *) addr);
		}
	}
}

ni_dbus_object_t *
ni_objectmodel_lookup_by_attrs(ni_dbus_object_t *list_object, ni_objectmodel_ns_t *ns, const ni_var_array_t *attrs)
{
	ni_dbus_object_t *obj;

	if (ns->lookup_by_attrs)
		return ns->lookup_by_attrs(ns, attrs);

	if (ns->match_attr == NULL)
		return NULL;

	for (obj = list_object->children; obj; obj = obj->next) {
		ni_bool_t match = TRUE;
		ni_var_t *ap;
		unsigned int i;

		for (i = 0, ap = attrs->data; match && i < attrs->count; ++i, ++ap)
			match = ns->match_attr(obj, ap->name, ap->value);
		if (match) {
			ni_debug_dbus("%s: found %s", __func__, obj->path);
			return obj;
		}
	}
	return NULL;
}

/*
 * Provide all possible descriptions of a device.
 */
xml_node_t *
ni_objectmodel_get_names(const ni_dbus_object_t *object)
{
	xml_node_t *result;
	unsigned int i;
	ni_bool_t ok = FALSE;

	result = xml_node_new(NULL, NULL);
	for (i = 0; i < ni_objectmodel_ns_count; ++i) {
		ni_objectmodel_ns_t *ns;

		ns = ni_objectmodel_ns_list[i];
		if (ns->describe && ns->describe(ns, object, result))
			ok = TRUE;
	}

	if (!ok) {
		xml_node_free(result);
		result = NULL;
	}

	return result;
}

/*
 * Helper functions for matching naming attributes
 */
static ni_bool_t
__match_hwaddr(const ni_hwaddr_t *hwaddr, const char *string)
{
	ni_hwaddr_t match;

	if (!string)
		return FALSE;

	if (ni_link_address_parse(&match, hwaddr->type, string) < 0)
		return FALSE;

	return ni_link_address_equal(hwaddr, &match);
}

static ni_bool_t
__match_uint(unsigned int device_value, const char *query_string)
{
	unsigned int query_value;

	if (ni_parse_uint(query_string, &query_value, 0) < 0)
		return FALSE;
	return device_value == query_value;
}

/*
 * Helper function for creating <name> elements for ns->describe()
 */
static xml_node_t *
__describe(const ni_objectmodel_ns_t *ns, xml_node_t *parent)
{
	xml_node_t *node = xml_node_new("name", parent);

	xml_node_add_attr(node, "namespace", ns->name);
	return node;
}

/*
 * Identify device by ethernet attributes
 */
static ni_bool_t
ni_objectmodel_ether_match_attr(const ni_dbus_object_t *object, const char *name, const char *value)
{
	ni_netdev_t *dev;
	ni_ethernet_t *eth;

	if (!(dev = ni_objectmodel_unwrap_netif(object, NULL)))
		return FALSE;

	if (!(eth = dev->ethernet))
		return FALSE;

	if (!strcmp(name, "address"))
		return __match_hwaddr(&dev->link.hwaddr, value);

	if (!strcmp(name, "permanent-address"))
		return __match_hwaddr(&eth->permanent_address, value);

	ni_warn("%s: unsupported query attribute %s", __func__, name);
	return FALSE;
}

static ni_bool_t
ni_objectmodel_ether_describe(const ni_objectmodel_ns_t *ns, const ni_dbus_object_t *object, xml_node_t *parent)
{
	ni_netdev_t *dev;
	ni_ethernet_t *eth;
	xml_node_t *node;

	if (!(dev = ni_objectmodel_unwrap_netif(object, NULL)))
		return FALSE;

	if (!(eth = dev->ethernet))
		return FALSE;

	if (eth->permanent_address.len) {
		node = __describe(ns, parent);
		xml_node_new_element("permanent-address", node,
				ni_link_address_print(&eth->permanent_address));
	}

	return TRUE;
}

static ni_objectmodel_ns_t ni_objectmodel_ether_ns = {
	.name		= "ethernet",
	.match_attr	= ni_objectmodel_ether_match_attr,
	.describe	= ni_objectmodel_ether_describe,
};

/*
 * Identify a device by PCI attributes
 */
static ni_bool_t
ni_objectmodel_pci_match_attr(const ni_dbus_object_t *object, const char *name, const char *value)
{
	ni_netdev_t *dev;
	ni_pci_dev_t *pci_dev;

	if (!(dev = ni_objectmodel_unwrap_netif(object, NULL)))
		return FALSE;

	if (!(pci_dev = dev->pci_dev))
		return FALSE;

	if (ni_string_eq(name, "path"))
		return ni_string_eq(pci_dev->path, value);

	/* Bridge means, we match if the query string is a prefix of the device's path */
	if (ni_string_eq(name, "bridge")) {
		unsigned int len;

		if (!value)
			return FALSE;
		len = strlen(value);
		return strncmp(pci_dev->path, value, len) == 0 && pci_dev->path[len] == '/';
	}

	if (ni_string_eq(name, "vendor"))
		return __match_uint(pci_dev->vendor, value);

	if (ni_string_eq(name, "device"))
		return __match_uint(pci_dev->device, value);

	ni_warn("%s: unsupported query attribute %s", __func__, name);
	return FALSE;
}

static ni_bool_t
ni_objectmodel_pci_describe(const ni_objectmodel_ns_t *ns, const ni_dbus_object_t *object, xml_node_t *parent)
{
	ni_netdev_t *dev;
	ni_pci_dev_t *pci_dev;
	xml_node_t *node;
	char *copy, *s;

	if (!(dev = ni_objectmodel_unwrap_netif(object, NULL)))
		return FALSE;

	if (!(pci_dev = dev->pci_dev))
		return FALSE;

	/* Describe by path */
	node = __describe(ns, parent);
	xml_node_new_element("path", node, pci_dev->path);

	/* Describe by vendor/device */
	node = __describe(ns, parent);
	xml_node_set_uint_hex(xml_node_new("vendor", node), pci_dev->vendor);
	xml_node_set_uint_hex(xml_node_new("device", node), pci_dev->device);

	/* Describe by bridge */
	copy = strdup(pci_dev->path);
	if ((s = strrchr(copy, '/')) != NULL) {
		*s = '\0';
		node = __describe(ns, parent);
		xml_node_new_element("bridge", node, copy);
	}
	free(copy);

	return TRUE;
}

static ni_objectmodel_ns_t ni_objectmodel_pci_ns = {
	.name		= "pci",
	.match_attr	= ni_objectmodel_pci_match_attr,
	.describe	= ni_objectmodel_pci_describe,
};

/*
 * Match modem devices
 */
static ni_bool_t
ni_objectmodel_modem_match_attr(const ni_dbus_object_t *object, const char *name, const char *match)
{
	ni_modem_t *modem;
	const char *value = NULL;

	if (!(modem = ni_objectmodel_unwrap_modem(object, NULL)))
		return FALSE;

	if (!strcmp(name, "equipment-id"))
		value = modem->identify.equipment;
	else if (!strcmp(name, "device"))
		value = modem->identify.device;
	else if (!strcmp(name, "manufacturer"))
		value = modem->identify.manufacturer;
	else if (!strcmp(name, "model"))
		value = modem->identify.model;
	else if (!strcmp(name, "version"))
		value = modem->identify.version;
	else {
		ni_warn("%s: unsupported query attribute %s", __func__, name);
		return FALSE;
	}

	ni_trace("%s(%s): match=\"%s\", value=\"%s\"", __func__, name, match, value);
	return ni_string_eq_nocase(match, value);
}

static ni_objectmodel_ns_t ni_objectmodel_modem_ns = {
	.name		= "modem",
	.match_attr	= ni_objectmodel_modem_match_attr,
};

void
ni_objectmodel_register_ns_builtin(void)
{
	ni_objectmodel_register_ns(&ni_objectmodel_ether_ns);
	ni_objectmodel_register_ns(&ni_objectmodel_pci_ns);
	ni_objectmodel_register_ns(&ni_objectmodel_modem_ns);
}
