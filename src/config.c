/*
 * Handle global configuration for netinfo
 *
 * Copyright (C) 2010-2011 Olaf Kirch <okir@suse.de>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <wicked/util.h>
#include <wicked/wicked.h>
#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/xpath.h>
#include <wicked/dbus.h>
#include "netinfo_priv.h"
#include "config.h"
#include "xml-schema.h"

static int		ni_config_parse_addrconf_dhcp(struct ni_config_dhcp *, xml_node_t *);
static int		ni_config_parse_afinfo(ni_afinfo_t *, const char *, xml_node_t *);
static int		ni_config_parse_update_targets(unsigned int *, const xml_node_t *);
static int		ni_config_parse_fslocation(ni_config_fslocation_t *, const char *, xml_node_t *);
static int		ni_config_parse_extensions(ni_extension_t **, xml_node_t *);
static int		ni_config_parse_xpath(xpath_format_t **, const char *);


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
	ni_string_free(&conf->dbus_name);
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
	conf->socket.mode = 0600;

	if (ni_config_parse_afinfo(&conf->ipv4, "ipv4", node) < 0
	 || ni_config_parse_afinfo(&conf->ipv6, "ipv6", node) < 0
	 || ni_config_parse_fslocation(&conf->pidfile, "pidfile", node) < 0
	 || ni_config_parse_fslocation(&conf->socket, "socket", node) < 0)
		goto failed;

	child = xml_node_get_child(node, "dbus");
	if (child) {
		const char *attrval;

		if ((attrval = xml_node_get_attr(child, "name")) != NULL)
			ni_string_dup(&conf->dbus_name, attrval);
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

	/* Intersect addrconf update capabilities with what the system supports. */
	conf->addrconf.default_allow_update &= ni_system_update_capabilities();

	/* Parse extensions */
	if (ni_config_parse_extensions(&conf->extensions, node) < 0)
		goto failed;

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

int
ni_config_parse_extensions(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex;
	const char *attrval;
	xml_node_t *child;

	for (node = node->children; node; node = node->next) {
		const char *name;

		/*
		 * <extension interface="com.suse.Wicked.foobar">
		 *  <pidfile path="/var/run/dhcpcd-%{@name}.pid"/>
		 *  <start command="bla bla..."/>
		 *  <stop command="bla bla..."/>
		 *  ...
		 * </extension>
		 */
		if (strcmp(node->name, "extension") != 0)
			continue;

		if (!(name = xml_node_get_attr(node, "interface"))) {
			ni_error("%s: <extension> element lacks interface attribute",
					xml_node_location(node));
			return -1;
		}

		ex = ni_extension_new(list, name);
		for (child = node->children; child; child = child->next) {
			xpath_format_t *fmt = NULL;

			if (!strcmp(child->name, "action")) {
				const char *name, *command;
				ni_process_t *process;

				if (!(name = xml_node_get_attr(child, "name"))) {
					ni_error("action element without name attribute");
					return -1;
				}
				if (!(command = xml_node_get_attr(child, "command"))) {
					ni_error("action element without command attribute");
					return -1;
				}

				process = ni_extension_script_new(ex, name, command);
			} else
			if (!strcmp(child->name, "environment")) {
				if (!(attrval = xml_node_get_attr(child, "putenv"))) {
					ni_error("environment element without putenv attribute");
					return -1;
				}
				if (ni_config_parse_xpath(&fmt, attrval) < 0)
					return -1;
				xpath_format_array_append(&ex->environment, fmt);
			}
		}
	}

	return 0;
}

int
ni_config_parse_xpath(xpath_format_t **varp, const char *expr)
{
	if (*varp)
		xpath_format_free(*varp);
	*varp = xpath_format_parse(expr);
	if (*varp == NULL) {
		ni_error("cannot parse configuration: bad xpath expression \"%s\"", expr);
		return -1;
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
