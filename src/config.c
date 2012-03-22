/*
 * Handle global configuration for netinfo
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>

#include <wicked/util.h>
#include <wicked/wicked.h>
#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/xpath.h>
#include <wicked/dbus.h>
#include "netinfo_priv.h"
#include "appconfig.h"
#include "xml-schema.h"

static int		ni_config_parse_addrconf_dhcp(struct ni_config_dhcp *, xml_node_t *);
static int		ni_config_parse_afinfo(ni_afinfo_t *, const char *, xml_node_t *);
static int		ni_config_parse_update_targets(unsigned int *, const xml_node_t *);
static int		ni_config_parse_fslocation(ni_config_fslocation_t *, const char *, xml_node_t *);
static int		ni_config_parse_objectmodel_extension(ni_extension_t **, xml_node_t *);
static int		ni_config_parse_objectmodel_netif_ns(ni_extension_t **, xml_node_t *);
static ni_c_binding_t *	ni_c_binding_new(ni_c_binding_t **, const char *name, const char *lib, const char *symbol);

/*
 * Create an empty config object
 */
ni_config_t *
ni_config_new()
{
	ni_config_t *conf;

	conf = calloc(1, sizeof(*conf));
	conf->ipv4.family = AF_INET;
	conf->ipv4.enabled = 1;
	conf->ipv6.family = AF_INET6;
	conf->ipv6.enabled = 1;

	conf->addrconf.default_allow_update = ~0;
	conf->addrconf.dhcp.allow_update = ~0;
	conf->addrconf.ibft.allow_update = ~0;
	conf->addrconf.autoip.allow_update = ~0;

	conf->recv_max = 64 * 1024;

	return conf;
}

void
ni_config_free(ni_config_t *conf)
{
	ni_extension_list_destroy(&conf->extensions);
	ni_extension_list_destroy(&conf->ns_extensions);
	ni_string_free(&conf->dbus_name);
	ni_string_free(&conf->dbus_type);
	ni_string_free(&conf->dbus_xml_schema_file);
	free(conf);
}

ni_config_t *
ni_config_parse(const char *filename)
{
	xml_document_t *doc;
	xml_node_t *node, *child;
	ni_config_t *conf = NULL;

	ni_debug_wicked("Reading config file %s", filename);
	doc = xml_document_read(filename);
	if (!doc) {
		ni_error("%s: error parsing configuration file", filename);
		goto failed;
	}

	node = xml_node_get_child(doc->root, "config");
	if (!node) {
		ni_error("%s: no <config> element", filename);
		goto failed;
	}

	conf = ni_config_new();

	conf->pidfile.mode = 0644;

	if (ni_config_parse_afinfo(&conf->ipv4, "ipv4", node) < 0
	 || ni_config_parse_afinfo(&conf->ipv6, "ipv6", node) < 0
	 || ni_config_parse_fslocation(&conf->pidfile, "pidfile", node) < 0)
		goto failed;

	child = xml_node_get_child(node, "dbus");
	if (child) {
		const char *attrval;

		if ((attrval = xml_node_get_attr(child, "name")) != NULL)
			ni_string_dup(&conf->dbus_name, attrval);
		if ((attrval = xml_node_get_attr(child, "type")) != NULL)
			ni_string_dup(&conf->dbus_type, attrval);
	}

	child = xml_node_get_child(node, "schema");
	if (child) {
		const char *attrval;

		if ((attrval = xml_node_get_attr(child, "name")) != NULL)
			ni_string_dup(&conf->dbus_xml_schema_file, attrval);
	}

	child = xml_node_get_child(node, "addrconf");
	if (child) {
		for (child = child->children; child; child = child->next) {
			if (!strcmp(child->name, "default-allow-update")
			 && ni_config_parse_update_targets(&conf->addrconf.default_allow_update, child) < 0)
				goto failed;

			if (!strcmp(child->name, "dhcp")
			 && ni_config_parse_addrconf_dhcp(&conf->addrconf.dhcp, child) < 0)
				goto failed;
		}
	}

	/* Parse extensions */
	for (child = node->children; child; child = child->next) {
		if (strcmp(child->name, "extension") == 0) {
			if (ni_config_parse_objectmodel_extension(&conf->extensions, child) < 0)
				goto failed;
		} else
		if (strcmp(child->name, "netif-naming-services") == 0) {
			if (ni_config_parse_objectmodel_netif_ns(&conf->ns_extensions, child) < 0)
				goto failed;
		}
	}


	xml_document_free(doc);
	return conf;

failed:
	if (conf)
		ni_config_free(conf);
	if (doc)
		xml_document_free(doc);
	return NULL;
}

int
ni_config_parse_addrconf_dhcp(struct ni_config_dhcp *dhcp, xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		const char *attrval;

		if (!strcmp(child->name, "vendor-class"))
			ni_string_dup(&dhcp->vendor_class, child->cdata);
		if (!strcmp(child->name, "lease-time") && child->cdata)
			dhcp->lease_time = strtoul(child->cdata, NULL, 0);
		if (!strcmp(child->name, "ignore-server")
		 && (attrval = xml_node_get_attr(child, "ip")) != NULL)
			ni_string_array_append(&dhcp->ignore_servers, attrval);
		if (!strcmp(child->name, "prefer-server")
		 && (attrval = xml_node_get_attr(child, "ip")) != NULL) {
			ni_server_preference_t *pref;

			if (dhcp->num_preferred_servers >= NI_DHCP_SERVER_PREFERENCES_MAX) {
				ni_warn("config: too many <prefer-server> elements");
				continue;
			}

			pref = &dhcp->preferred_server[dhcp->num_preferred_servers++];
			if (ni_address_parse(&pref->address, attrval, AF_UNSPEC) < 0) {
				ni_error("config: unable to parse <prefer-server ip=\"%s\"",
						attrval);
				return -1;
			}

			pref->weight = 100;
			if ((attrval = xml_node_get_attr(child, "weight")) != NULL) {
				if (!strcmp(attrval, "always")) {
					pref->weight = 100;
				} else if (!strcmp(attrval, "never")) {
					pref->weight = -1;
				} else {
					pref->weight = strtol(attrval, NULL, 0);
					if (pref->weight > 100) {
						pref->weight = 100;
						ni_warn("preferred dhcp server weight exceeds max, "
							"clamping to %d",
							pref->weight);
					}
				}
			}
		}
		if (!strcmp(child->name, "allow-update"))
			ni_config_parse_update_targets(&dhcp->allow_update, child);
	}
	return 0;
}

int
ni_config_parse_update_targets(unsigned int *update_mask, const xml_node_t *node)
{
	const xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		int target;

		if (!strcmp(child->name, "all")) {
			*update_mask = ~0;
		} else
		if (!strcmp(child->name, "none")) {
			*update_mask = 0;
		} else
		if ((target = ni_addrconf_name_to_update_target(child->name)) >= 0) {
			*update_mask |= (1 << target);
		} else {
			ni_warn("ignoring unknown addrconf update target \"%s\"", child->name);
		}
	}
	return 0;
}

int
ni_config_parse_afinfo(ni_afinfo_t *afi, const char *afname, xml_node_t *node)
{
	/* No config data for this address family? use defaults. */
	if (!(node = xml_node_get_child(node, afname)))
		return 0;

	if (xml_node_get_child(node, "enabled"))
		afi->enabled = 1;
	else if (xml_node_get_child(node, "disabled"))
		afi->enabled = 0;

	if (xml_node_get_child(node, "forwarding"))
		afi->forwarding = 1;

	return 0;
}

int
ni_config_parse_fslocation(ni_config_fslocation_t *fsloc, const char *name, xml_node_t *node)
{
	const char *attrval;

	if (!(node = xml_node_get_child(node, name)))
		return 0;

	if ((attrval = xml_node_get_attr(node, "path")) != NULL)
		ni_string_dup(&fsloc->path, attrval);
	if ((attrval = xml_node_get_attr(node, "mode")) != NULL)
		ni_parse_int(attrval, &fsloc->mode);
	return 0;
}

/*
 * Object model extensions let you implement parts of a dbus interface separately
 * from the main wicked body of code; either through a shared library or an
 * external command/shell script
 *
 * <extension interface="com.suse.Wicked.foobar">
 *  <action name="dbusMethodName" command="/some/shell/scripts some-args"/>
 *  <builtin name="dbusOtherMethodName" library="/usr/lib/libfoo.so" symbol="c_method_impl_name"/>
 *
 *  <putenv name="WICKED_OBJECT_PATH" value="$object-path"/>
 *  <putenv name="WICKED_INTERFACE_NAME" value="$property:name"/>
 *  <putenv name="WICKED_INTERFACE_INDEX" value="$property:index"/>
 * </extension>
 */
int
ni_config_parse_objectmodel_extension(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex;
	xml_node_t *child;
	const char *name;

	if (!(name = xml_node_get_attr(node, "interface"))) {
		ni_error("%s: <extension> element lacks interface attribute",
				xml_node_location(node));
		return -1;
	}

	ex = ni_extension_new(list, name);
	for (child = node->children; child; child = child->next) {
		if (!strcmp(child->name, "action")) {
			const char *name, *command;

			if (!(name = xml_node_get_attr(child, "name"))) {
				ni_error("action element without name attribute");
				return -1;
			}
			if (!(command = xml_node_get_attr(child, "command"))) {
				ni_error("action element without command attribute");
				return -1;
			}

			if (!ni_extension_script_new(ex, name, command))
				return -1;
		} else
		if (!strcmp(child->name, "builtin")) {
			const char *name, *library, *symbol;

			if (!(name = xml_node_get_attr(child, "name"))) {
				ni_error("builtin element without name attribute");
				return -1;
			}
			if (!(symbol = xml_node_get_attr(child, "symbol"))) {
				ni_error("action element without command attribute");
				return -1;
			}
			library = xml_node_get_attr(child, "library");

			ni_c_binding_new(&ex->c_bindings, name, library, symbol);
		} else
		if (!strcmp(child->name, "putenv")) {
			const char *name, *value;

			if (!(name = xml_node_get_attr(child, "name"))) {
				ni_error("%s: <putenv> element without name attribute",
						xml_node_location(child));
				return -1;
			}
			value = xml_node_get_attr(child, "value");
			ni_var_array_set(&ex->environment, name, value);
		}
	}

	return 0;
}

/*
 * Object model naming extensions let you implement alternative ways of specifying
 * a network interface. This should help avoid all the messy udev tricks with renaming
 * interfaces to obtain "persistent" device names.
 *
 * <netif-naming-services>
 *  <builtin name="naming-service1" library="/usr/lib/libfoo.so" symbol="ns1_struct_name"/>
 *  <builtin name="naming-service2" library="/usr/lib/libfoo.so" symbol="ns2_struct_name"/>
 *  ...
 * </netif-naming-services>
 */
int
ni_config_parse_objectmodel_netif_ns(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex;
	xml_node_t *child;

	ex = ni_extension_new(list, NULL);
	for (child = node->children; child; child = child->next) {
		if (!strcmp(child->name, "builtin")) {
			const char *name, *library, *symbol;

			if (!(name = xml_node_get_attr(child, "name"))) {
				ni_error("builtin element without name attribute");
				return -1;
			}
			if (!(symbol = xml_node_get_attr(child, "symbol"))) {
				ni_error("action element without command attribute");
				return -1;
			}
			library = xml_node_get_attr(child, "library");

			ni_c_binding_new(&ex->c_bindings, name, library, symbol);
		}
	}

	return 0;
}

/*
 * Extension handling
 */
ni_extension_t *
ni_config_find_extension(ni_config_t *conf, const char *interface)
{
	return ni_extension_list_find(conf->extensions, interface);
}

/*
 * Handle methods implemented via C bindings
 */
static ni_c_binding_t *
ni_c_binding_new(ni_c_binding_t **list, const char *name, const char *library, const char *symbol)
{
	ni_c_binding_t *binding, **pos;

	for (pos = list; (binding = *pos) != NULL; pos = &binding->next)
		;

	binding = xcalloc(1, sizeof(*binding));
	ni_string_dup(&binding->name, name);
	ni_string_dup(&binding->library, library);
	ni_string_dup(&binding->symbol, symbol);

	*pos = binding;
	return binding;
}

void
ni_c_binding_free(ni_c_binding_t *binding)
{
	ni_string_free(&binding->name);
	ni_string_free(&binding->library);
	ni_string_free(&binding->symbol);
	free(binding);
}

void *
ni_c_binding_get_address(const ni_c_binding_t *binding)
{
	void *handle;
	void *addr;

	handle = dlopen(binding->library, RTLD_LAZY);
	if (handle == NULL) {
		ni_error("invalid binding for %s - cannot dlopen(%s): %s",
				binding->name, binding->library?: "<main>", dlerror());
		return NULL;
	}

	addr = dlsym(handle, binding->symbol);
	dlclose(handle);

	if (addr == NULL) {
		ni_error("invalid binding for %s - no such symbol in %s: %s",
				binding->name, binding->library?: "<main>", binding->symbol);
		return NULL;
	}

	return addr;
}

/*
 * Query the default update mask
 */
unsigned int
ni_config_addrconf_update_mask(ni_config_t *conf, ni_addrconf_mode_t type)
{
	unsigned int update_mask = conf->addrconf.default_allow_update;

	switch (type) {
	case NI_ADDRCONF_DHCP:
		update_mask &= conf->addrconf.dhcp.allow_update;
		break;

	default: ;
	}
	return update_mask;
}
