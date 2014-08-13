/*
 * Handle global configuration for netinfo
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <dlfcn.h>

#include <wicked/util.h>
#include <wicked/wicked.h>
#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/xpath.h>
#include <wicked/dbus.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "appconfig.h"
#include "xml-schema.h"

static const char *__ni_ifconfig_source_types[] = {
	"firmware:",
	"compat:",
	"wicked:",
	NULL
};

static ni_bool_t	ni_config_parse_addrconf_dhcp4(struct ni_config_dhcp4 *, xml_node_t *);
static ni_bool_t	ni_config_parse_addrconf_dhcp6(struct ni_config_dhcp6 *, xml_node_t *);
static void		ni_config_parse_update_targets(unsigned int *, const xml_node_t *);
static void		ni_config_parse_fslocation(ni_config_fslocation_t *, xml_node_t *);
static ni_bool_t	ni_config_parse_objectmodel_extension(ni_extension_t **, xml_node_t *);
static ni_bool_t	ni_config_parse_objectmodel_netif_ns(ni_extension_t **, xml_node_t *);
static ni_bool_t	ni_config_parse_objectmodel_firmware_discovery(ni_extension_t **, xml_node_t *);
static ni_bool_t	ni_config_parse_system_updater(ni_extension_t **, xml_node_t *);
static ni_bool_t	ni_config_parse_extension(ni_extension_t *, xml_node_t *);
static ni_bool_t	ni_config_parse_sources(ni_config_t *, xml_node_t *);
static ni_c_binding_t *	ni_c_binding_new(ni_c_binding_t **, const char *name, const char *lib, const char *symbol);
static const char *	ni_config_build_include(const char *, const char *);
static unsigned int	ni_config_addrconf_update_mask_all(void);

/*
 * Create an empty config object
 */
ni_config_t *
ni_config_new()
{
	ni_config_t *conf;

	conf = xcalloc(1, sizeof(*conf));

	conf->addrconf.default_allow_update = ni_config_addrconf_update_mask_all();
	conf->addrconf.dhcp4.allow_update   = conf->addrconf.default_allow_update;
	conf->addrconf.dhcp6.allow_update   = conf->addrconf.default_allow_update;
	conf->addrconf.autoip.allow_update  = conf->addrconf.default_allow_update;

	conf->recv_max = 64 * 1024;

	ni_config_fslocation_init(&conf->piddir,   WICKED_PIDDIR,   0755);
	ni_config_fslocation_init(&conf->statedir, WICKED_STATEDIR, 0755);
	ni_config_fslocation_init(&conf->storedir, WICKED_STOREDIR, 0755);

	conf->use_nanny = FALSE;

	return conf;
}

void
ni_config_free(ni_config_t *conf)
{
	ni_string_array_destroy(&conf->sources.ifconfig);
	ni_extension_list_destroy(&conf->dbus_extensions);
	ni_extension_list_destroy(&conf->ns_extensions);
	ni_extension_list_destroy(&conf->fw_extensions);
	ni_extension_list_destroy(&conf->updater_extensions);
	ni_string_free(&conf->dbus_name);
	ni_string_free(&conf->dbus_type);
	ni_string_free(&conf->dbus_xml_schema_file);
	ni_config_fslocation_destroy(&conf->piddir);
	ni_config_fslocation_destroy(&conf->storedir);
	ni_config_fslocation_destroy(&conf->statedir);
	ni_config_fslocation_destroy(&conf->backupdir);
	free(conf);
}

ni_bool_t
__ni_config_parse(ni_config_t *conf, const char *filename, ni_init_appdata_callback_t *cb, void *appdata)
{
	xml_document_t *doc;
	xml_node_t *node, *child;

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

	/* Loop over all elements in the config file */
	for (child = node->children; child; child = child->next) {
		if (strcmp(child->name, "include") == 0) {
			const char *attrval, *path;

			if ((attrval = xml_node_get_attr(child, "name")) == NULL) {
				ni_error("%s: <include> element lacks filename", xml_node_location(child));
				goto failed;
			}
			if (!(path = ni_config_build_include(filename, attrval)))
				goto failed;
			if (!__ni_config_parse(conf, path, cb, appdata))
				goto failed;
		} else
		if (strcmp(child->name, "use-nanny") == 0) {
			if (ni_parse_boolean(child->cdata, &conf->use_nanny)) {
				ni_error("%s: invalid <%s>%s</%s> element value",
					filename, child->name, child->name, child->cdata);
				goto failed;
			}
		} else
		if (strcmp(child->name, "piddir") == 0) {
			ni_config_parse_fslocation(&conf->piddir, child);
		} else
		if (strcmp(child->name, "statedir") == 0) {
			ni_config_parse_fslocation(&conf->statedir, child);
		} else
		if (strcmp(child->name, "storedir") == 0) {
			ni_config_parse_fslocation(&conf->storedir, child);
		} else
		if (strcmp(child->name, "dbus") == 0) {
			const char *attrval;

			if ((attrval = xml_node_get_attr(child, "name")) != NULL)
				ni_string_dup(&conf->dbus_name, attrval);
			if ((attrval = xml_node_get_attr(child, "type")) != NULL)
				ni_string_dup(&conf->dbus_type, attrval);
		} else 
		if (strcmp(child->name, "schema") == 0) {
			const char *attrval;

			if ((attrval = xml_node_get_attr(child, "name")) != NULL)
				ni_string_dup(&conf->dbus_xml_schema_file, attrval);
		} else
		if (strcmp(child->name, "addrconf") == 0) {
			xml_node_t *gchild;

			for (gchild = child->children; gchild; gchild = gchild->next) {
				if (!strcmp(gchild->name, "default-allow-update"))
					ni_config_parse_update_targets(&conf->addrconf.default_allow_update, gchild);

				if (!strcmp(gchild->name, "dhcp4")
				 && !ni_config_parse_addrconf_dhcp4(&conf->addrconf.dhcp4, gchild))
					goto failed;

				if (!strcmp(gchild->name, "dhcp6")
				 && !ni_config_parse_addrconf_dhcp6(&conf->addrconf.dhcp6, gchild))
					goto failed;
			}
		} else
		if (strcmp(child->name, "sources") == 0) {
			if (!ni_config_parse_sources(conf, child))
				goto failed;
		} else
		if (strcmp(child->name, "extension") == 0
		 || strcmp(child->name, "dbus-service") == 0) {
			if (!ni_config_parse_objectmodel_extension(&conf->dbus_extensions, child))
				goto failed;
		} else
		if (strcmp(child->name, "netif-naming-services") == 0) {
			if (!ni_config_parse_objectmodel_netif_ns(&conf->ns_extensions, child))
				goto failed;
		} else
		if (strcmp(child->name, "netif-firmware-discovery") == 0) {
			if (!ni_config_parse_objectmodel_firmware_discovery(&conf->fw_extensions, child))
				goto failed;
		} else
		if (strcmp(child->name, "system-updater") == 0) {
			if (!ni_config_parse_system_updater(&conf->updater_extensions, child))
				goto failed;
		} else
		if (strcmp(child->name, "debug")) {
			ni_debug_set_default(child->cdata);
		} else
		if (cb != NULL) {
			if (!cb(appdata, child))
				goto failed;
		}
	}

	if (conf->backupdir.path == NULL) {
		char pathname[PATH_MAX];

		snprintf(pathname, sizeof(pathname), "%s/backup", conf->statedir.path);
		ni_config_fslocation_init(&conf->backupdir, pathname, 0700);
	}

	xml_document_free(doc);
	return TRUE;

failed:
	if (doc)
		xml_document_free(doc);
	return FALSE;
}

ni_config_t *
ni_config_parse(const char *filename, ni_init_appdata_callback_t *cb, void *appdata)
{
	ni_config_t *conf;

	conf = ni_config_new();
	if (!__ni_config_parse(conf, filename, cb, appdata)) {
		ni_config_free(conf);
		return NULL;
	}

	return conf;
}

const char *
ni_config_build_include(const char *parent_filename, const char *incl_filename)
{
	char fullname[PATH_MAX + 1];

	if (incl_filename[0] != '/') {
		unsigned int i;

		i = strlen(parent_filename);
		if (i >= PATH_MAX)
			goto too_long;
		strcpy(fullname, parent_filename);

		while (i && fullname[i-1] != '/')
			--i;
		fullname[i] = '\0';

		if (i + strlen(incl_filename) >= PATH_MAX)
			goto too_long;
		strcpy(&fullname[i], incl_filename);
		incl_filename = fullname;
	}
	return incl_filename;

too_long:
	ni_error("unable to include \"%s\" - path too long", incl_filename);
	return NULL;
}

ni_bool_t
ni_config_parse_addrconf_dhcp4(struct ni_config_dhcp4 *dhcp4, xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		const char *attrval;

		if (!strcmp(child->name, "vendor-class"))
			ni_string_dup(&dhcp4->vendor_class, child->cdata);
		if (!strcmp(child->name, "lease-time") && child->cdata)
			dhcp4->lease_time = strtoul(child->cdata, NULL, 0);
		if (!strcmp(child->name, "ignore-server")
		 && (attrval = xml_node_get_attr(child, "ip")) != NULL)
			ni_string_array_append(&dhcp4->ignore_servers, attrval);
		if (!strcmp(child->name, "prefer-server")
		 && (attrval = xml_node_get_attr(child, "ip")) != NULL) {
			ni_server_preference_t *pref;

			if (dhcp4->num_preferred_servers >= NI_DHCP_SERVER_PREFERENCES_MAX) {
				ni_warn("config: too many <prefer-server> elements");
				continue;
			}

			pref = &dhcp4->preferred_server[dhcp4->num_preferred_servers++];
			if (ni_sockaddr_parse(&pref->address, attrval, AF_INET) < 0) {
				ni_error("config: unable to parse <prefer-server ip=\"%s\"",
						attrval);
				return FALSE;
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
			ni_config_parse_update_targets(&dhcp4->allow_update, child);
	}
	return TRUE;
}

static int
__ni_config_parse_dhcp6_class_data(xml_node_t *node, ni_string_array_t *data, const char *parent)
{
	const char *attrval;
	enum {
		FORMAT_STR,	/* normal string */
		FORMAT_HEX,	/* XX:XX format  */
	};
	int format = FORMAT_STR;
	size_t len;

	if (strcmp(node->name, "class-data")) {
		ni_error("config: <%s> is not a valid <%s> class-data node",
			node->name, parent);
		return -1;
	}

	len = ni_string_len(node->cdata);
	if (len == 0) {
		ni_warn("config: empty %s <class-data> node",
			parent);
		return 0;
	}

	if ((attrval = xml_node_get_attr(node, "format")) != NULL) {
		if (!strcmp(attrval, "hex") || !strcmp(attrval, "mac")) {
			format = FORMAT_HEX;
		} else
		if (!strcmp(attrval, "str") || !strcmp(attrval, "string")) {
			format = FORMAT_STR;
		} else {
			ni_error("config: unknown %s <class-data format=\"%s\"",
				parent, attrval);
			return -1;
		}
	}

	if(format == FORMAT_HEX) {
		unsigned char *buf;

		/* verify the format early ... */
		len = (len / 3) + 1;
		buf = xcalloc(1, len);
		if (ni_parse_hex(node->cdata, buf, len) <= 0) {
			ni_error("config: unable to parse %s hex class-data",
				parent);
			free(buf);
			return -1;
		}
		free(buf);

		ni_string_array_append(data, node->cdata);
	} else {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

		/* convert to hex-string format */
		ni_stringbuf_grow(&buf, (len * 3));
		ni_format_hex((unsigned char *)node->cdata, len, buf.string, buf.size);

		ni_string_array_append(data, buf.string);
		ni_stringbuf_destroy(&buf);
	}

	return 0;
}

static int
__ni_config_parse_dhcp6_class_data_nodes(xml_node_t *node, ni_string_array_t *data)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (__ni_config_parse_dhcp6_class_data(child, data, node->name) < 0)
			return -1;
	}
	return 0;
}

static int
__ni_config_parse_dhcp6_vendor_opt_node(xml_node_t *node, ni_var_array_t *opts, const char *parent)
{
	const char *attrval;
	const char *code = NULL;
	enum {
		FORMAT_STR,	/* normal string */
		FORMAT_HEX,	/* XX:XX format  */
	};
	int format = FORMAT_STR;
	size_t len;

	if (strcmp(node->name, "option")) {
		ni_error("config: <%s> is not a valid <%s> option node",
			node->name, parent);
		return -1;
	}

	if ((attrval = xml_node_get_attr(node, "code")) != NULL) {
		char *      err;
		long        num;

		num = strtol(attrval, &err, 0);
		if (*err != '\0' || num < 0 || num > 0xffff) {
			ni_error("config: unable to parse %s <option code=\"%s\"",
				parent, attrval);
			return -1;
		}
		code = attrval;
	} else {
		ni_error("config: missed %s <option> without code attribute",
			parent);
		return -1;
	}

	if ((attrval = xml_node_get_attr(node, "format")) != NULL) {
		if (!strcmp(attrval, "hex") || !strcmp(attrval, "mac")) {
			format = FORMAT_HEX;
		} else
		if (!strcmp(attrval, "str") || !strcmp(attrval, "string")) {
			format = FORMAT_STR;
		} else {
			ni_error("config: unknown %s <option format=\"%s\"",
				parent, attrval);
			return -1;
		}
	}

	len = ni_string_len(node->cdata);
	if(format == FORMAT_HEX) {
		unsigned char *buf;

		/* verify the format early ... */
		if (len > 0) {
			len = (len / 3) + 1;
			buf = xcalloc(1, len);
			if (ni_parse_hex(node->cdata, buf, len) <= 0) {
				ni_error("config: unable to parse %s hex option data",
					parent);
				free(buf);
				return -1;
			}
			free(buf);
		}

		ni_var_array_set(opts, code, node->cdata);
	} else {
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

		/* convert to hex-string format */
		if (len > 0) {
			ni_stringbuf_grow(&buf, (len * 3));
			ni_format_hex((unsigned char *)node->cdata, len, buf.string, buf.size);
		}

		ni_var_array_set(opts, code, buf.string);
		ni_stringbuf_destroy(&buf);
	}

	return 0;
}

static int
__ni_config_parse_dhcp6_vendor_opts_nodes(xml_node_t *node, ni_var_array_t *opts)
{
	xml_node_t *child;
	for (child = node->children; child; child = child->next) {
		if (__ni_config_parse_dhcp6_vendor_opt_node(child, opts, node->name) < 0)
			return -1;
	}
	return 0;
}

ni_bool_t
ni_config_parse_addrconf_dhcp6(struct ni_config_dhcp6 *dhcp6, xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		const char *attrval;

		if (!strcmp(child->name, "default-duid") && !ni_string_empty(child->cdata)) {
			ni_string_dup(&dhcp6->default_duid, child->cdata);
		} else
		if (!strcmp(child->name, "user-class")) {
			ni_string_array_destroy(&dhcp6->user_class_data);

			if (__ni_config_parse_dhcp6_class_data_nodes(child, &dhcp6->user_class_data) < 0) {
				ni_string_array_destroy(&dhcp6->user_class_data);
				return FALSE;
			}

			if (dhcp6->user_class_data.count == 0) {
				ni_warn("config: discarding <user-class> without any <class-data>");
			}
		} else
		if (!strcmp(child->name, "vendor-class") &&
		    (attrval = xml_node_get_attr(child, "enterprise-number")) != NULL) {
			char *      err;
			long        num;
			
			num = strtol(attrval, &err, 0);
			if (*err != '\0' || num < 0 || num >= 0xffffffff) {
				ni_error("config: unable to parse <vendor-class enterprise-number=\"%s\"",
						attrval);
				return FALSE;
			}

			ni_string_array_destroy(&dhcp6->vendor_class_data);
			if (__ni_config_parse_dhcp6_class_data_nodes(child, &dhcp6->vendor_class_data) < 0) {
				ni_string_array_destroy(&dhcp6->vendor_class_data);
				return FALSE;
			}

			if (dhcp6->vendor_class_data.count == 0) {
				ni_warn("config: discarding <vendor-class> without any <class-data>");
			} else {
				dhcp6->vendor_class_en = num;
			}
		} else
		if (!strcmp(child->name, "vendor-opts") &&
		    (attrval = xml_node_get_attr(child, "enterprise-number")) != NULL) {
			char *      err;
			long        num;
			
			num = strtol(attrval, &err, 0);
			if (*err != '\0' || num < 0 || num >= 0xffffffff) {
				ni_error("config: unable to parse <vendor-class enterprise-number=\"%s\"",
						attrval);
				return FALSE;
			}

			ni_var_array_destroy(&dhcp6->vendor_opts_data);
			if (__ni_config_parse_dhcp6_vendor_opts_nodes(child, &dhcp6->vendor_opts_data) < 0) {
				ni_var_array_destroy(&dhcp6->vendor_opts_data);
			}

			if (dhcp6->vendor_opts_data.count == 0) {
				ni_warn("config: discarding <vendor-opts> without any <option>");
			} else {
				dhcp6->vendor_opts_en = num;
			}
		} else
		if (!strcmp(child->name, "lease-time") && child->cdata) {
			dhcp6->lease_time = strtoul(child->cdata, NULL, 0);
		} else
		if (!strcmp(child->name, "ignore-server")
		 && (attrval = xml_node_get_attr(child, "ip")) != NULL) {
			ni_string_array_append(&dhcp6->ignore_servers, attrval);
		} else
		if (!strcmp(child->name, "prefer-server")) {
			ni_server_preference_t *pref;
			const char *id, *ip;

			ip = xml_node_get_attr(child, "ip"); 
			id = xml_node_get_attr(child, "id");

			if (ip == NULL && id == NULL)
				continue;

			if (dhcp6->num_preferred_servers >= NI_DHCP_SERVER_PREFERENCES_MAX) {
				ni_warn("config: too many <prefer-server> elements");
				continue;
			}

			pref = &dhcp6->preferred_server[dhcp6->num_preferred_servers++];

			if (ip && ni_sockaddr_parse(&pref->address, ip, AF_INET6) < 0) {
				ni_error("config: unable to parse <prefer-server ip=\"%s\"",
						ip);
				return FALSE;
			}

			if (id) {
				int len;

				/* DUID is "opaque", but has 2 bytes type + up to 128 bytes */
				if ((len = sizeof(pref->serverid.data)) > 130)
					len = 130;

				 /* DUID-LL has 2+2 fixed bytes + variable length hwaddress
				  * and seems to be the shortest one I'm aware of ...       */
				if ((len = ni_parse_hex(id, pref->serverid.data, len)) <= 4) {
					ni_error("config: unable to parse <prefer-server id=\"%s\"",
							id);
					return FALSE;
				}
				pref->serverid.len = (size_t)len;
			}

			pref->weight = 255;
			if ((attrval = xml_node_get_attr(child, "weight")) != NULL) {
				if (!strcmp(attrval, "always")) {
					pref->weight = 255;
				} else if (!strcmp(attrval, "never")) {
					pref->weight =  -1;
				} else {
					pref->weight = strtol(attrval, NULL, 0);
					if (pref->weight > 255) {
						pref->weight = 255;
						ni_warn("preferred dhcp server weight exceeds max, "
							"clamping to %d",
							pref->weight);
					}
				}
			}
		} else
		if (!strcmp(child->name, "allow-update")) {
			ni_config_parse_update_targets(&dhcp6->allow_update, child);
		}
	}
	return TRUE;
}

void
ni_config_parse_update_targets(unsigned int *update_mask, const xml_node_t *node)
{
	const xml_node_t *child;

	*update_mask = __NI_ADDRCONF_UPDATE_NONE;
	for (child = node->children; child; child = child->next) {
		unsigned int target;

		if (!strcmp(child->name, "all")) {
			*update_mask = ni_config_addrconf_update_mask_all();
		} else
		if (!strcmp(child->name, "none")) {
			*update_mask = __NI_ADDRCONF_UPDATE_NONE;
		} else
		if (ni_addrconf_update_name_to_flag(child->name, &target)) {
			ni_addrconf_update_set(update_mask, target, TRUE);
		} else {
			ni_info("ignoring unknown addrconf update target \"%s\"",
					child->name);
		}
	}
}

void
ni_config_parse_fslocation(ni_config_fslocation_t *fsloc, xml_node_t *node)
{
	const char *attrval;

	if ((attrval = xml_node_get_attr(node, "path")) != NULL)
		ni_string_dup(&fsloc->path, attrval);
	if ((attrval = xml_node_get_attr(node, "mode")) != NULL)
		ni_parse_uint(attrval, &fsloc->mode, 8);
}

/*
 * Object model extensions let you implement parts of a dbus interface separately
 * from the main wicked body of code; either through a shared library or an
 * external command/shell script
 *
 * <extension interface="org.opensuse.Network.foobar">
 *  <action name="dbusMethodName" command="/some/shell/scripts some-args"/>
 *  <builtin name="dbusOtherMethodName" library="/usr/lib/libfoo.so" symbol="c_method_impl_name"/>
 *
 *  <putenv name="WICKED_OBJECT_PATH" value="$object-path"/>
 *  <putenv name="WICKED_INTERFACE_NAME" value="$property:name"/>
 *  <putenv name="WICKED_INTERFACE_INDEX" value="$property:index"/>
 * </extension>
 */
ni_bool_t
ni_config_parse_objectmodel_extension(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex;
	const char *name;

	if (!(name = xml_node_get_attr(node, "interface"))) {
		ni_error("%s: <%s> element lacks interface attribute",
				node->name, xml_node_location(node));
		return FALSE;
	}

	ex = ni_extension_new(list, name);

	return ni_config_parse_extension(ex, node);
}

static ni_bool_t
ni_config_parse_extension(ni_extension_t *ex, xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (!strcmp(child->name, "action") || !strcmp(child->name, "script")) {
			const char *name, *command;

			if (!(name = xml_node_get_attr(child, "name"))) {
				ni_error("action element without name attribute");
				return FALSE;
			}
			if (!(command = xml_node_get_attr(child, "command"))) {
				ni_error("action element without command attribute");
				return FALSE;
			}

			if (!ni_extension_script_new(ex, name, command))
				return FALSE;
		} else
		if (!strcmp(child->name, "builtin")) {
			const char *name, *library, *symbol;

			if (!(name = xml_node_get_attr(child, "name"))) {
				ni_error("builtin element without name attribute");
				return FALSE;
			}
			if (!(symbol = xml_node_get_attr(child, "symbol"))) {
				ni_error("action element without command attribute");
				return FALSE;
			}
			library = xml_node_get_attr(child, "library");

			ni_c_binding_new(&ex->c_bindings, name, library, symbol);
		} else
		if (!strcmp(child->name, "putenv")) {
			const char *name, *value;

			if (!(name = xml_node_get_attr(child, "name"))) {
				ni_error("%s: <putenv> element without name attribute",
						xml_node_location(child));
				return FALSE;
			}
			value = xml_node_get_attr(child, "value");
			ni_var_array_set(&ex->environment, name, value);
		}
	}

	return TRUE;
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
ni_bool_t
ni_config_parse_objectmodel_netif_ns(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex;

	ex = ni_extension_new(list, NULL);
	return ni_config_parse_extension(ex, node);
}

/*
 * Another class of extensions helps with discovery of interface configuration through
 * firmware, such as iBFT. You can use this to specify one or more shell commands
 * that generate a list of <interface> elemens as output.
 *
 * <netif-firmware-discovery>
 *  <script name="ibft" command="/some/crazy/path/to/script" />
 *  ...
 * </netif-firmware-discovery>
 */
ni_bool_t
ni_config_parse_objectmodel_firmware_discovery(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex;

	ex = ni_extension_new(list, NULL);
	return ni_config_parse_extension(ex, node);
}

/*
 * Another class of extensions helps with updating system files such as resolv.conf
 * This expects scripts for install, backup and restore (named accordingly).
 *
 * <system-updater name="resolver">
 *  <script name="install" command="/some/crazy/path/to/script install" />
 *  <script name="backup" command="/some/crazy/path/to/script backup" />
 *  <script name="restore" command="/some/crazy/path/to/script restore" />
 *  ...
 * </system-updater>
 */
ni_bool_t
ni_config_parse_system_updater(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex;
	const char *name;

	if (!(name = xml_node_get_attr(node, "name"))) {
		ni_error("%s: <%s> element lacks name attribute",
				node->name, xml_node_location(node));
		return FALSE;
	}

	ex = ni_extension_new(list, name);

	/* If the updater has a format type, extract. */
	ni_string_dup(&ex->format, xml_node_get_attr(node, "format"));

	return ni_config_parse_extension(ex, node);
}

/*
 * This specifies sources of client configuration.
 *
 * The ifconfig source specifies the type, location and the
 * priority / load order of the interface configurations.
 *
 * <sources>
 *   <ifconfig location="firmware:" />
 *   <ifconfig location="compat:" />
 *   <ifconfig location="wicked:/etc/wicked/ifconfig" />
 * </sources>
 *
 */
static ni_bool_t
__ni_config_parse_ifconfig_source(ni_string_array_t *sources, xml_node_t *node)
{
	const char *attrval = NULL;
	unsigned int i;

	if ((attrval = xml_node_get_attr(node, "location")) != NULL && *attrval) {
		const char **p = __ni_ifconfig_source_types;
		for (i = 0; p[i]; i++) {
			if (!strncasecmp(attrval, p[i], ni_string_len(p[i]))) {
				ni_debug_readwrite("%s: Adding ifconfig %s", __func__, attrval);
				ni_string_array_append(sources, attrval);
				return TRUE;
			}
		}
	}

	ni_error("Unknown ifconfig location: %s", attrval);
	return FALSE;
}
ni_bool_t
ni_config_parse_sources(ni_config_t *conf, xml_node_t *sources)
{
	xml_node_t *child;

	for (child = sources->children; child && child->name; child = child->next) {
		if (!strcmp(child->name, "ifconfig")) {
			 if (!__ni_config_parse_ifconfig_source(&conf->sources.ifconfig, child))
				return FALSE;
		}
	}

	return TRUE;
}

const ni_string_array_t *
ni_config_sources(const char *type)
{
	ni_string_array_t *retval = NULL;
	unsigned int i;

	if (ni_string_eq(type, "ifconfig")) {
		retval = &ni_global.config->sources.ifconfig;
		if (retval->count == 0) {
			for (i = 0; __ni_ifconfig_source_types[i]; i++)
				ni_string_array_append(retval, __ni_ifconfig_source_types[i]);
		}
	}
	return retval;
}

/*
 * Extension handling
 */
ni_extension_t *
ni_config_find_extension(ni_config_t *conf, const char *interface)
{
	return ni_extension_list_find(conf->dbus_extensions, interface);
}

ni_extension_t *
ni_config_find_system_updater(ni_config_t *conf, const char *name)
{
	return ni_extension_list_find(conf->updater_extensions, name);
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
static unsigned int
ni_config_addrconf_update_mask_all(void)
{
	static unsigned mask = __NI_ADDRCONF_UPDATE_NONE;
	if (!mask) {
		unsigned int i;
		mask = ~mask;
		for (i = 0; i < 32; ++i) {
			if (!ni_addrconf_update_flag_to_name(i))
				mask &= ~(1 << i);
		}
	}
	return mask;
}

unsigned int
ni_config_addrconf_update_mask(ni_addrconf_mode_t type, unsigned int family)
{
	unsigned int mask = __NI_ADDRCONF_UPDATE_NONE;
	ni_config_t *conf = ni_global.config;

	switch (type) {
	case NI_ADDRCONF_STATIC:
		mask = conf ? conf->addrconf.default_allow_update :
			ni_config_addrconf_update_mask_all();
		break;

	case NI_ADDRCONF_AUTOCONF:
		mask = conf ? conf->addrconf.autoip.allow_update :
			ni_config_addrconf_update_mask_all();
		break;

	case NI_ADDRCONF_DHCP:
		switch (family) {
		case AF_INET:
			mask = conf ? conf->addrconf.dhcp4.allow_update :
				ni_config_addrconf_update_mask_all();
			break;
		case AF_INET6:
			mask = conf ? conf->addrconf.dhcp6.allow_update :
				ni_config_addrconf_update_mask_all();
			break;
		default: ;
		}
		break;
	default: ;
	}
	return mask;
}

ni_bool_t
ni_config_use_nanny(void)
{
	return ni_global.config ? ni_global.config->use_nanny : FALSE;
}

void
ni_config_fslocation_init(ni_config_fslocation_t *loc, const char *path, unsigned int mode)
{
	memset(loc, 0, sizeof(*loc));
	ni_string_dup(&loc->path, path);
	loc->mode = mode;
}

void
ni_config_fslocation_destroy(ni_config_fslocation_t *loc)
{
	ni_string_free(&loc->path);
	memset(loc, 0, sizeof(*loc));
}
