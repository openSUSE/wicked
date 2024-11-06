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
#include <netinet/if_ether.h>

#include <wicked/util.h>
#include <wicked/wicked.h>
#include <wicked/netinfo.h>
#include <wicked/addrconf.h>
#include <wicked/address.h>
#include <wicked/xpath.h>
#include <wicked/dbus.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "appconfig.h"
#include "extension.h"
#include "xml-schema.h"
#include "process.h"
#include "dhcp.h"
#include "duid.h"

static const char *__ni_ifconfig_source_types[] = {
	"firmware:",
	"compat:",
	"wicked:",
	NULL
};

static ni_bool_t	ni_config_parse_addrconf_dhcp4(ni_config_t *, xml_node_t *);
static ni_bool_t	ni_config_parse_addrconf_dhcp6(ni_config_t *, xml_node_t *);
static ni_bool_t	ni_config_parse_addrconf_auto4(ni_config_auto4_t *, xml_node_t *);
static ni_bool_t	ni_config_parse_addrconf_auto6(ni_config_auto6_t *, xml_node_t *);
static ni_bool_t	ni_config_parse_addrconf_arp(ni_config_arp_t *, const xml_node_t *);
static void		ni_config_parse_update_targets(unsigned int *, const xml_node_t *);
static void		ni_config_parse_update_dhcp4_routes(unsigned int *, const xml_node_t *);
static void		ni_config_parse_fslocation(ni_config_fslocation_t *, xml_node_t *);
static ni_bool_t	ni_config_parse_objectmodel_extension(ni_extension_t **, xml_node_t *);
static ni_bool_t	ni_config_parse_objectmodel_netif_ns(ni_extension_t **, xml_node_t *);
static ni_bool_t	ni_config_parse_objectmodel_firmware_discovery(ni_extension_t **, xml_node_t *);
static ni_bool_t	ni_config_parse_system_updater(ni_extension_t **, xml_node_t *);
static ni_bool_t	ni_config_parse_sources(ni_config_t *, xml_node_t *);
static ni_bool_t	ni_config_parse_rtnl_event(ni_config_rtnl_event_t *, xml_node_t *);
static ni_bool_t	ni_config_parse_bonding(ni_config_bonding_t *, const xml_node_t *);
static ni_bool_t	ni_config_parse_teamd(ni_config_teamd_t *, const xml_node_t *);
static const char *	ni_config_build_include(char *, size_t, const char *, const char *);
static unsigned int	ni_config_addrconf_update_mask_all(void);
static unsigned int	ni_config_addrconf_update_mask_dhcp4(void);
static unsigned int	ni_config_addrconf_update_mask_dhcp6(void);
static unsigned int	ni_config_addrconf_update_mask_auto4(void);
static unsigned int	ni_config_addrconf_update_mask_auto6(void);
static unsigned int	ni_config_addrconf_update_default(void);
static unsigned int	ni_config_addrconf_update_dhcp4(void);
static unsigned int	ni_config_addrconf_update_dhcp6(void);
static unsigned int	ni_config_addrconf_update_auto4(void);
static unsigned int	ni_config_addrconf_update_auto6(void);
static void		ni_config_addrconf_arp_default(ni_config_arp_t *);

#define NI_ADDRCONF_ARP_VERIFY_COUNT		3					/* PROBE_NUM */
#define NI_ADDRCONF_ARP_VERIFY_RETRIES		16
#define NI_ADDRCONF_ARP_VERIFY_MIN		(2000 / NI_ADDRCONF_ARP_VERIFY_COUNT)	/* PROBE_MIN */
#define NI_ADDRCONF_ARP_VERIFY_MAX		(3000 / NI_ADDRCONF_ARP_VERIFY_COUNT)	/* PROBE_MAX */
#define NI_ADDRCONF_ARP_NOTIFY_COUNT		1					/* ANNOUNCE_NUM */
#define NI_ADDRCONF_ARP_NOTIFY_RETRIES		16
#define NI_ADDRCONF_ARP_NOTIFY_INTERVAL		300					/* ANNOUNCE_INTERVAL */
#define NI_ADDRCONF_ARP_INTERVAL_MIN		100
#define NI_ADDRCONF_ARP_MAX_DURATION		15000
#define NI_ADDRCONF_ARP_COUNT_MIN		1

/*
 * Create an empty config object
 */
ni_config_t *
ni_config_new()
{
	ni_config_t *conf;

	conf = xcalloc(1, sizeof(*conf));

	conf->addrconf.default_allow_update = ni_config_addrconf_update_default();
	ni_config_addrconf_arp_default(&conf->addrconf.arp);
	ni_config_addrconf_arp_default(&conf->addrconf.dhcp4.arp);
	ni_config_addrconf_arp_default(&conf->addrconf.auto4.arp);
	conf->addrconf.dhcp4.allow_update   = ni_config_addrconf_update_dhcp4();
	conf->addrconf.dhcp6.allow_update   = ni_config_addrconf_update_dhcp6();
	conf->addrconf.auto4.allow_update   = ni_config_addrconf_update_auto4();
	conf->addrconf.auto6.allow_update   = ni_config_addrconf_update_auto6();
	conf->addrconf.dhcp4.routes_opts = -1U;
	conf->addrconf.dhcp6.release_nretries = -1U;
	conf->addrconf.dhcp6.info_refresh.range.max = NI_LIFETIME_INFINITE;

	ni_config_fslocation_init(&conf->piddir,   WICKED_PIDDIR,   0755);
	ni_config_fslocation_init(&conf->statedir, WICKED_STATEDIR, 0755);
	ni_config_fslocation_init(&conf->storedir, WICKED_STOREDIR, 0755);

	conf->rtnl_event.recv_buff_length = 1024 * 1024;
	conf->rtnl_event.mesg_buff_length = 0;

	/* we enable it explicitly in wickedd only */
	conf->teamd.enabled = FALSE;

	return conf;
}

static ni_config_dhcp4_t *
ni_config_dhcp4_new(void)
{
	return calloc(1, sizeof(ni_config_dhcp4_t));
}
static ni_config_dhcp4_t *
ni_config_dhcp4_clone(const ni_config_dhcp4_t *src, const char *device)
{
	ni_config_dhcp4_t *dst;

	if (!src || !(dst = ni_config_dhcp4_new()))
		return NULL;

	ni_string_dup(&dst->device, device);

	dst->create_cid = src->create_cid;
	dst->allow_update = src->allow_update;
	dst->routes_opts = src->routes_opts;
	dst->arp = src->arp;
	ni_string_dup(&dst->vendor_class, src->vendor_class);
	dst->lease_time = src->lease_time;
	ni_string_array_copy(&dst->ignore_servers, &src->ignore_servers);
	memcpy(&dst->preferred_server, &src->preferred_server, sizeof(dst->preferred_server));
	ni_dhcp_option_decl_list_copy(&dst->custom_options, src->custom_options);
	return dst;
}
static void
ni_config_dhcp4_destroy(ni_config_dhcp4_t *dhcp4)
{
	ni_string_free(&dhcp4->vendor_class);
	ni_string_array_destroy(&dhcp4->ignore_servers);
	ni_dhcp_option_decl_list_destroy(&dhcp4->custom_options);

	ni_string_free(&dhcp4->device);
	if (dhcp4->next) {
		ni_config_dhcp4_destroy(dhcp4->next);
		free(dhcp4->next);
	}
}
static ni_config_dhcp4_t *
ni_config_dhcp4_list_find(ni_config_dhcp4_t *list, const char *device)
{
	ni_config_dhcp4_t *dhcp;

	/* search at device specific list->next */
	for (dhcp = list ? list->next : NULL; dhcp; dhcp = dhcp->next) {
		if (ni_string_eq(dhcp->device, device))
			return dhcp;
	}
	return NULL;
}
const ni_config_dhcp4_t *
ni_config_dhcp4_find_device(const char *device)
{
	ni_config_dhcp4_t *dhcp;
	ni_config_t *conf;

	if (!(conf = ni_global.config))
		return NULL;

	if ((dhcp = ni_config_dhcp4_list_find(&conf->addrconf.dhcp4, device)))
		return dhcp;

	return &conf->addrconf.dhcp4;
}

static ni_config_dhcp6_t *
ni_config_dhcp6_new(void)
{
	return calloc(1, sizeof(ni_config_dhcp6_t));
}
static ni_config_dhcp6_t *
ni_config_dhcp6_clone(const ni_config_dhcp6_t *src, const char *device)
{
	ni_config_dhcp6_t *dst;

	if (!src || !(dst = ni_config_dhcp6_new()))
		return NULL;

	ni_string_dup(&dst->device, device);

	dst->lease_time = src->lease_time;
	dst->allow_update = src->allow_update;
	ni_string_dup(&dst->default_duid, src->default_duid);
	dst->create_duid = src->create_duid;
	dst->device_duid = src->device_duid;

	ni_string_array_copy(&dst->user_class_data, &src->user_class_data);
	dst->vendor_class_en = src->vendor_class_en;
	ni_string_array_copy(&dst->vendor_class_data, &src->vendor_class_data);
	dst->vendor_opts_en = src->vendor_opts_en;
	ni_var_array_copy(&dst->vendor_opts_data, &src->vendor_opts_data);
	ni_string_array_copy(&dst->ignore_servers, &src->ignore_servers);
	memcpy(&dst->preferred_server, &src->preferred_server, sizeof(dst->preferred_server));
	ni_dhcp_option_decl_list_copy(&dst->custom_options, src->custom_options);
	return dst;
}
static void
ni_config_dhcp6_destroy(ni_config_dhcp6_t *dhcp6)
{
	ni_string_free(&dhcp6->default_duid);
	ni_string_array_destroy(&dhcp6->user_class_data);
	ni_string_array_destroy(&dhcp6->vendor_class_data);
	ni_var_array_destroy(&dhcp6->vendor_opts_data);
	ni_string_array_destroy(&dhcp6->ignore_servers);
	ni_dhcp_option_decl_list_destroy(&dhcp6->custom_options);

	ni_string_free(&dhcp6->device);
	if (dhcp6->next) {
		ni_config_dhcp6_destroy(dhcp6->next);
		free(dhcp6->next);
	}
}
static ni_config_dhcp6_t *
ni_config_dhcp6_list_find(ni_config_dhcp6_t *list, const char *device)
{
	ni_config_dhcp6_t *dhcp;

	/* search at device specific list->next */
	for (dhcp = list ? list->next : NULL; dhcp; dhcp = dhcp->next) {
		if (ni_string_eq(dhcp->device, device))
			return dhcp;
	}
	return NULL;
}

const ni_config_dhcp6_t *
ni_config_dhcp6_find_device(const char *device)
{
	const ni_config_dhcp6_t *dhcp;
	ni_config_t *conf;

	if (!(conf = ni_global.config))
		return NULL;

	if ((dhcp = ni_config_dhcp6_list_find(&conf->addrconf.dhcp6, device)))
		return dhcp;

	return &conf->addrconf.dhcp6;
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

	ni_config_dhcp4_destroy(&conf->addrconf.dhcp4);
	ni_config_dhcp6_destroy(&conf->addrconf.dhcp6);

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
			char fullname[PATH_MAX + 1] = {'\0'};
			const char *attrval, *path;
			ni_bool_t optional = FALSE;

			if ((attrval = xml_node_get_attr(child, "optional")) != NULL) {
				if (ni_parse_boolean(attrval, &optional)) {
					ni_error("%s: invalid <%s optional='%s>...</%s> element value",
						filename, child->name, attrval, child->name);
					goto failed;
				}
			}
			if ((attrval = xml_node_get_attr(child, "name")) == NULL) {
				ni_error("%s: <include> element lacks filename", xml_node_location(child));
				goto failed;
			}
			if (!(path = ni_config_build_include(fullname, sizeof(fullname), filename, attrval)))
				goto failed;
			/* If the file is marked as optional, but does not exist, silently
			 * skip it */
			if (optional && !ni_file_exists(path))
				continue;
			if (!__ni_config_parse(conf, path, cb, appdata))
				goto failed;
		} else
		if (strcmp(child->name, "use-nanny") == 0) {
			ni_bool_t use_nanny = TRUE;

			if (ni_parse_boolean(child->cdata, &use_nanny)) {
				ni_error("%s: invalid <%s>%s</%s> option value",
					filename, child->name, child->cdata, child->name);
				goto failed;
			} else if (!use_nanny) {
				ni_warn("%s: ignoring obsolete <%s>%s</%s> option, please remove",
					filename, child->name, child->cdata, child->name);
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
			xml_node_t *gchild;

			/* Old-school
			 * <dbus name="org.opensuse.Network" />
			 * <schema name="/some/path/wicked.xml" />
			 */
			if ((attrval = xml_node_get_attr(child, "name")) != NULL)
				ni_string_dup(&conf->dbus_name, attrval);
			if ((attrval = xml_node_get_attr(child, "type")) != NULL)
				ni_string_dup(&conf->dbus_type, attrval);

			/* New school:
			 *  <dbus>
			 *    <service name="org.opensuse.Network" />
			 *    <schema name="/some/path/wicked.xml" />
			 *  </dbus>
			 */
			for (gchild = child->children; gchild; gchild = gchild->next) {
				if (!strcmp(gchild->name, "service")) {
					if ((attrval = xml_node_get_attr(gchild, "name")) != NULL)
						ni_string_dup(&conf->dbus_name, attrval);
					if ((attrval = xml_node_get_attr(gchild, "type")) != NULL)
						ni_string_dup(&conf->dbus_type, attrval);
				} else
				if (!strcmp(gchild->name, "schema")) {
					if ((attrval = xml_node_get_attr(gchild, "name")) != NULL)
						ni_string_dup(&conf->dbus_xml_schema_file, attrval);
				}
			}
		} else
		if (strcmp(child->name, "schema") == 0) {
			const char *attrval;

			/* old school */
			if ((attrval = xml_node_get_attr(child, "name")) != NULL)
				ni_string_dup(&conf->dbus_xml_schema_file, attrval);
		} else
		if (strcmp(child->name, "addrconf") == 0) {
			xml_node_t *gchild;

			for (gchild = child->children; gchild; gchild = gchild->next) {
				if (!strcmp(gchild->name, "default-allow-update"))
					ni_config_parse_update_targets(&conf->addrconf.default_allow_update, gchild);

				if (!strcmp(gchild->name, "dhcp4")
				 && !ni_config_parse_addrconf_dhcp4(conf, gchild))
					goto failed;

				if (!strcmp(gchild->name, "dhcp6")
				 && !ni_config_parse_addrconf_dhcp6(conf, gchild))
					goto failed;

				if (!strcmp(gchild->name, "auto4")
				 && !ni_config_parse_addrconf_auto4(&conf->addrconf.auto4, gchild))
					goto failed;

				if (!strcmp(gchild->name, "auto6")
				 && !ni_config_parse_addrconf_auto6(&conf->addrconf.auto6, gchild))
					goto failed;

				if (ni_string_eq(gchild->name, "arp")
				 && !ni_config_parse_addrconf_arp(&conf->addrconf.arp, gchild))
					goto failed;
			}
		} else
		if (strcmp(child->name, "sources") == 0) {
			if (!ni_config_parse_sources(conf, child))
				goto failed;
		} else
		if (strcmp(child->name, "dbus-service") == 0) {
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
		if (strcmp(child->name, "debug") == 0) {
			ni_debug_set_default(child->cdata);
		} else
		if (strcmp(child->name, "netlink-events") == 0) {
			if (!ni_config_parse_rtnl_event(&conf->rtnl_event, child))
				goto failed;
		} else
		if (strcmp(child->name, "bonding") == 0) {
			if (!ni_config_parse_bonding(&conf->bonding, child))
				goto failed;
		} else
		if (strcmp(child->name, "teamd") == 0) {
			if (!ni_config_parse_teamd(&conf->teamd, child))
				goto failed;
		}
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
ni_config_build_include(char *fullname, size_t size,
		const char *parent_filename, const char *incl_filename)
{
	if (parent_filename && incl_filename && incl_filename[0] != '/') {
		size_t i;

		i = strlen(parent_filename);
		if (i >= size)
			goto too_long;

		strncpy(fullname, parent_filename, size - 1);
		fullname[size - 1] = '\0';

		while (i && fullname[i - 1] != '/')
			--i;
		fullname[i] = '\0';

		if (i + strlen(incl_filename) >= size)
			goto too_long;

		strncat(fullname, incl_filename, size - i - 1);
		incl_filename = fullname;
	}
	return incl_filename;

too_long:
	ni_error("unable to include \"%s\" - path too long", incl_filename);
	return NULL;
}

static ni_bool_t
ni_config_parse_dhcp4_definitions(struct ni_config_dhcp4 *dhcp4, xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "option")) {
			ni_dhcp_option_decl_parse_xml(&dhcp4->custom_options, child,
							1, 254, "dhcp4", 5);
		}
	}
	return TRUE;
}

static const ni_intmap_t	config_dhcp6_cid_type_names[] = {
	{ "rfc2132",		NI_CONFIG_DHCP4_CID_TYPE_HWADDR	},
	{ "hwaddr",		NI_CONFIG_DHCP4_CID_TYPE_HWADDR	},

	{ "rfc4361",		NI_CONFIG_DHCP4_CID_TYPE_DHCPv6 },
	{ "dhcpv6",		NI_CONFIG_DHCP4_CID_TYPE_DHCPv6 },
	{ "dhcp6",		NI_CONFIG_DHCP4_CID_TYPE_DHCPv6 },

	{ "disable",		NI_CONFIG_DHCP4_CID_TYPE_DISABLE},
	{ "none",		NI_CONFIG_DHCP4_CID_TYPE_DISABLE},

	{ NULL,			NI_CONFIG_DHCP4_CID_TYPE_AUTO	}
};

const char *
ni_config_dhcp4_cid_type_format(ni_config_dhcp4_cid_type_t type)
{
	return ni_format_uint_mapped(type, config_dhcp6_cid_type_names);
}
ni_bool_t
ni_config_dhcp4_cid_type_parse(ni_config_dhcp4_cid_type_t *type, const char *name)
{
	return ni_parse_uint_mapped(name, config_dhcp6_cid_type_names, type) == 0;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp4_nodes(ni_config_dhcp4_t *dhcp4, xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		const char *attrval;

		if (ni_string_eq(child->name, "create-cid"))
			ni_config_dhcp4_cid_type_parse(&dhcp4->create_cid, child->cdata);
		else
		if (!strcmp(child->name, "vendor-class"))
			ni_string_dup(&dhcp4->vendor_class, child->cdata);
		else
		if (!strcmp(child->name, "lease-time") && child->cdata)
			ni_parse_uint(child->cdata, &dhcp4->lease_time, 0);
		else
		if (!strcmp(child->name, "ignore-server")) {
			if ((attrval = xml_node_get_attr(child, "ip")) != NULL)
				ni_string_array_append(&dhcp4->ignore_servers, attrval);
			else
			if ((attrval = xml_node_get_attr(child, "mac")) != NULL)
				ni_string_array_append(&dhcp4->ignore_servers, attrval);
		} else
		if (!strcmp(child->name, "prefer-server")) {
			ni_server_preference_t *pref;

			if (dhcp4->num_preferred_servers >= NI_DHCP_SERVER_PREFERENCES_MAX) {
				ni_warn("config: too many <prefer-server> elements");
				continue;
			}
			pref = &dhcp4->preferred_server[dhcp4->num_preferred_servers];
			memset(pref, 0, sizeof(*pref));

			if ((attrval = xml_node_get_attr(child, "ip")) != NULL) {
				if (ni_sockaddr_parse(&pref->address, attrval, AF_INET) < 0) {
					ni_warn("config: unable to parse <prefer-server ip=\"%s\">",
							attrval);
					continue;
				}
			} else
			if ((attrval = xml_node_get_attr(child, "mac")) != NULL) {
				ni_hwaddr_t hwaddr;

				if (ni_link_address_parse(&hwaddr, ARPHRD_ETHER, attrval) < 0) {
					ni_warn("config: unable to parse <prefer-server mac=\"%s\">",
							attrval);
					continue;
				} else
				if (sizeof(pref->serverid.data) < (size_t)hwaddr.len + 1) {
					ni_warn("config: <prefer-server mac=\"%s\"> is too long",
							attrval);
					continue;
				} else {
					pref->serverid.len = hwaddr.len + 1;
					pref->serverid.data[0] = hwaddr.type;
					memcpy(&pref->serverid.data[1], hwaddr.data, hwaddr.len);
				}
			} else {
				ni_warn("config: missing prefer-server ip=... or mac=...");
				continue;
			}

			dhcp4->num_preferred_servers++;
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
		} else
		if (!strcmp(child->name, "allow-update")) {
			ni_config_parse_update_targets(&dhcp4->allow_update, child);
			dhcp4->allow_update &= ni_config_addrconf_update_mask_dhcp4();
		} else
		if (!strcmp(child->name, "route-options")) {
			ni_config_parse_update_dhcp4_routes(&dhcp4->routes_opts, child);
		} else
		if (ni_string_eq(child->name, "define")) {
			ni_config_parse_dhcp4_definitions(dhcp4, child);
		} else
		if (ni_string_eq(child->name, "arp")) {
			ni_config_parse_addrconf_arp(&dhcp4->arp, child);
		}
	}
	return TRUE;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp4(ni_config_t *conf, xml_node_t *node)
{
	ni_config_dhcp4_t *dhcp4 = &conf->addrconf.dhcp4;
	ni_config_dhcp4_t **tail;
	xml_node_t *child;
	const char *name;

	if (!ni_config_parse_addrconf_dhcp4_nodes(dhcp4, node))
		return FALSE;

	for (child = node->children; child; child = child->next) {
		if (!ni_string_eq(child->name, "device") || !child->children)
			continue;

		name = xml_node_get_attr(child, "name");
		if (ni_string_empty(name)) {
			ni_warn("%s: <%s> element lacks name attribute",
				xml_node_location(child), child->name);
			continue;
		}

		if (!(dhcp4 = ni_config_dhcp4_list_find(&conf->addrconf.dhcp4, name))) {
			tail = &conf->addrconf.dhcp4.next;
			while ((dhcp4 = *tail))
				tail = &dhcp4->next;

			dhcp4 = ni_config_dhcp4_clone(&conf->addrconf.dhcp4, name);
			*tail = dhcp4;
		}
		ni_config_parse_addrconf_dhcp4_nodes(dhcp4, child);
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
			ni_error("config: unknown %s <class-data format=\"%s\">",
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
			ni_error("config: unable to parse %s <option code=\"%s\">",
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
			ni_error("config: unknown %s <option format=\"%s\">",
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

static ni_bool_t
ni_config_parse_dhcp6_definitions(struct ni_config_dhcp6 *dhcp6, xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "option")) {
			ni_dhcp_option_decl_parse_xml(&dhcp6->custom_options, child,
							1, 65534, "dhcp6", 5);
		}
	}
	return TRUE;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp6_duid_en(ni_config_dhcp6_t *dhcp6, xml_node_t *node)
{
	ni_opaque_t duid;
	xml_node_t *en;
	xml_node_t *id;

	if (!(en = xml_node_get_child(node, "enterprise-number")))
		return FALSE;

	if (!(id = xml_node_get_child(node, "identifier")))
		return FALSE;

	if (!ni_duid_create_en(&duid, en->cdata, id->cdata))
		return FALSE;

	return ni_duid_format_hex(&dhcp6->default_duid, &duid) != NULL;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp6_device_duid(ni_config_dhcp6_t *dhcp6, xml_node_t *node)
{
	/* DUID is an ID of a host. An interface address assotiation (IA)
	 * contains an (unique per IA type) IAID referring to the interface.
	 * As a workaround for corner cases, e.g. where the dhcp-server is
	 * not considering the IAIDs and is searching for a MAC in the duid,
	 * we permit to use/maintain a non-std per-device duid in global
	 * scope:
	 *     <default-duid per-device="true"/>
	 * or
	 *     <default-duid per-device="true"><ll/></default-duid>
	 * or
	 *     <default-duid per-device="true"><llt/></default-duid>
	 * When <default-duid> is specified in device scope, that is as:
	 *     <device name="eth0"><default-duid.../></device>
	 * it is always maintained (stored in the map) per-device.
	 */
	const char *attr;

	if (!dhcp6 || !node)
		return FALSE;

	if (!ni_string_empty(dhcp6->device))
		return FALSE;

	attr = xml_node_get_attr(node, "per-device");
	return attr && ni_parse_boolean(attr, &dhcp6->device_duid) == 0;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp6_duid_ll(ni_config_dhcp6_t *dhcp6, xml_node_t *node)
{
	ni_opaque_t duid;
	xml_node_t *type;
	xml_node_t *addr;

	if (!node->children) {
		dhcp6->create_duid = NI_DUID_TYPE_LL;
		return TRUE;
	}

	if (!(type = xml_node_get_child(node, "hardware")))
		return FALSE;
	if (!(addr = xml_node_get_child(node, "address")))
		return FALSE;

	if (!ni_duid_create_ll(&duid, type->cdata, addr->cdata))
		return FALSE;

	return ni_duid_format_hex(&dhcp6->default_duid, &duid) != NULL;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp6_duid_llt(ni_config_dhcp6_t *dhcp6, xml_node_t *node)
{
	ni_opaque_t duid;
	xml_node_t *type;
	xml_node_t *addr;

	if (!node->children) {
		dhcp6->create_duid = NI_DUID_TYPE_LLT;
		return TRUE;
	}

	if (!(type = xml_node_get_child(node, "hardware")))
		return FALSE;
	if (!(addr = xml_node_get_child(node, "address")))
		return FALSE;

	if (!ni_duid_create_llt(&duid, type->cdata, addr->cdata))
		return FALSE;

	return ni_duid_format_hex(&dhcp6->default_duid, &duid) != NULL;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp6_duid_uuid(ni_config_dhcp6_t *dhcp6, xml_node_t *node)
{
	ni_opaque_t duid;
	xml_node_t *child;

	if (!ni_string_empty(node->cdata)) {
		if (!ni_duid_create_uuid_string(&duid, node->cdata))
			return FALSE;
	} else
	if ((child = xml_node_get_child(node, "machine-id"))) {
		if (!ni_duid_create_uuid_machine_id(&duid, child->cdata))
			return FALSE;
	} else
	if ((child = xml_node_get_child(node, "dmi-product-id"))) {
		if (!ni_duid_create_uuid_dmi_product_id(&duid, child->cdata))
			return FALSE;
	} else
	if (!node->children) {
		dhcp6->create_duid = NI_DUID_TYPE_UUID;
		return TRUE;
	} else
		return FALSE;

	return ni_duid_format_hex(&dhcp6->default_duid, &duid) != NULL;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp6_duid(ni_config_dhcp6_t *dhcp6, xml_node_t *node)
{
	xml_node_t *child;

	dhcp6->device_duid = !ni_string_empty(dhcp6->device);
	/* apply <default-duid per-device="true"/> in global scope */
	ni_config_parse_addrconf_dhcp6_device_duid(dhcp6, node);

	if (!ni_string_empty(node->cdata)) {
		ni_opaque_t duid;

		/* parse + format to discard crap and "normalize" string */
		if (!ni_duid_parse_hex(&duid, node->cdata))
			return FALSE;
		if (!ni_duid_format_hex(&dhcp6->default_duid, &duid))
			return FALSE;
		return TRUE;
	}

	for (child = node->children; child; child = child->next) {
		/* return on 1st success */
		if (ni_string_eq(child->name, "en")) {
			if (ni_config_parse_addrconf_dhcp6_duid_en(dhcp6, child))
				return TRUE;
		} else
		if (ni_string_eq(child->name, "ll")) {
			if (ni_config_parse_addrconf_dhcp6_duid_ll(dhcp6, child))
				return TRUE;
		} else
		if (ni_string_eq(child->name, "llt")) {
			if (ni_config_parse_addrconf_dhcp6_duid_llt(dhcp6, child))
				return TRUE;
		} else
		if (ni_string_eq(child->name, "uuid")) {
			if (ni_config_parse_addrconf_dhcp6_duid_uuid(dhcp6, child))
				return TRUE;
		}
	}

	return !node->children;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp6_nodes(ni_config_dhcp6_t *dhcp6, xml_node_t *node)
{
	xml_node_t *child;

	if (!dhcp6 || !node)
		return FALSE;

	for (child = node->children; child; child = child->next) {
		const char *attrval;

		if (!strcmp(child->name, "default-duid")) {
			if (!ni_config_parse_addrconf_dhcp6_duid(dhcp6, child))
				ni_warn("config: unable to parse <default-duid> (%s)",
					xml_node_location(child));
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
			unsigned int num;

			if (ni_parse_uint(attrval, &num, 0)) {
				ni_error("config: unable to parse <vendor-class enterprise-number=\"%s\">",
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
			unsigned int num;

			if (ni_parse_uint(attrval, &num, 0)) {
				ni_error("config: unable to parse <vendor-class enterprise-number=\"%s\">",
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
			ni_parse_uint(child->cdata, &dhcp6->lease_time, 0);
		} else
		if (!strcmp(child->name, "release-retransmits") && child->cdata) {
			ni_parse_uint(child->cdata, &dhcp6->release_nretries, 0);
		} else
		if (!strcmp(child->name, "info-refresh-time")) {
			const char *attrval;
			unsigned int value;

			dhcp6->info_refresh.time = 0; /* 0 for rfc defaults */
			dhcp6->info_refresh.range.min = 0;
			dhcp6->info_refresh.range.max = NI_LIFETIME_INFINITE;

			if ((attrval = xml_node_get_attr(child, "min"))) {
				if (ni_parse_uint(attrval, &value, 10) == 0 &&
				    ni_uint_in_range(&dhcp6->info_refresh.range, value))
					ni_uint_range_update_min(&dhcp6->info_refresh.range, value);
				else
					ni_warn("config: discarding invalid info-refresh-time min attribute");
			}

			if ((attrval = xml_node_get_attr(child, "max"))) {
				if (ni_parse_uint(attrval, &value, 10) == 0 &&
				    ni_uint_in_range(&dhcp6->info_refresh.range, value))
					ni_uint_range_update_max(&dhcp6->info_refresh.range, value);
				else
					ni_warn("config: discarding invalid info-refresh-time max attribute");
			}

			if (!ni_string_empty(child->cdata)) {
				if (ni_string_eq(child->cdata, "infinite")) {
					value = NI_LIFETIME_INFINITE;
				} else
				if (ni_parse_uint(child->cdata, &value, 10)) {
					ni_warn("config: discarding invalid info-refresh-time value");
					value = 0;
				}
				if (value && !ni_uint_in_range(&dhcp6->info_refresh.range, value))
					ni_warn("config: discarding invalid info-refresh-time value");
				else
					dhcp6->info_refresh.time = value;
			}
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
				ni_error("config: unable to parse <prefer-server ip=\"%s\">",
						ip);
				return FALSE;
			}

			if (id) {
				int len;

				/* DUID is "opaque", but has 2 bytes type + up to 128 bytes */
				if ((len = pref->serverid.len) > 130)
					len = 130;

				 /* DUID-LL has 2+2 fixed bytes + variable length hwaddress
				  * and seems to be the shortest one I'm aware of ...       */
				if ((len = ni_parse_hex(id, pref->serverid.data, len)) <= 4) {
					ni_error("config: unable to parse <prefer-server id=\"%s\">",
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
			dhcp6->allow_update &= ni_config_addrconf_update_mask_dhcp6();
		} else
		if (ni_string_eq(child->name, "define")) {
			ni_config_parse_dhcp6_definitions(dhcp6, child);
		}
	}
	return TRUE;
}

static ni_bool_t
ni_config_parse_addrconf_dhcp6(ni_config_t *conf, xml_node_t *node)
{
	ni_config_dhcp6_t *dhcp6 = &conf->addrconf.dhcp6;
	ni_config_dhcp6_t **tail;
	xml_node_t *child;
	const char *name;

	if (!ni_config_parse_addrconf_dhcp6_nodes(dhcp6, node))
		return FALSE;

	for (child = node->children; child; child = child->next) {
		if (!ni_string_eq(child->name, "device") || !child->children)
			continue;

		name = xml_node_get_attr(child, "name");
		if (ni_string_empty(name)) {
			ni_warn("%s: <%s> element lacks name attribute",
				xml_node_location(child), child->name);
			continue;
		}

		if (!(dhcp6 = ni_config_dhcp6_list_find(&conf->addrconf.dhcp6, name))) {
			tail = &conf->addrconf.dhcp6.next;
			while ((dhcp6 = *tail))
				tail = &dhcp6->next;

			dhcp6 = ni_config_dhcp6_clone(&conf->addrconf.dhcp6, name);
			*tail = dhcp6;
		}
		ni_config_parse_addrconf_dhcp6_nodes(dhcp6, child);
	}

	return TRUE;
}

ni_bool_t
ni_config_parse_addrconf_auto4(ni_config_auto4_t *auto4, xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "arp")) {
			if (!ni_config_parse_addrconf_arp(&auto4->arp, child))
				return FALSE;
		}
	}
	return TRUE;
}

ni_bool_t
ni_config_parse_addrconf_auto6(ni_config_auto6_t *auto6, xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "allow-update")) {
			ni_config_parse_update_targets(&auto6->allow_update, child);
			auto6->allow_update &= ni_config_addrconf_update_mask_auto6();
		}
	}
	return TRUE;
}

static ni_bool_t
ni_config_parse_uint_range(ni_uint_range_t *range, const xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "min")) {
			if (ni_parse_uint(child->cdata, &range->min, 0) < 0) {
				ni_warn("[%s] unable to parse <min>%s</min>",
					xml_node_location(child), child->cdata);
				return FALSE;
			}
		} else if (ni_string_eq(child->name, "max")) {
			if (ni_parse_uint(child->cdata, &range->max, 0) < 0) {
				ni_warn("[%s] unable to parse <max>%s</max>",
					xml_node_location(child), child->cdata);
				return FALSE;
			}
		} else {
			ni_warn("[%s] ignore invalid range node <%s>",
					xml_node_location(child), child->name);
		}
	}

	return TRUE;
}

static ni_bool_t
ni_config_parse_addrconf_arp_verify(ni_config_arp_verify_t *verify, const xml_node_t *node)
{
	xml_node_t *child;
	unsigned int tmp;
	ni_config_arp_verify_t vfy_tmp = *verify;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "count")) {
			if (ni_parse_uint(child->cdata, &tmp, 0) < 0) {
				ni_warn("[%s] unable to parse <count>%s</count>",
						xml_node_location(child), child->cdata);
				continue;
			}
			if (tmp < NI_ADDRCONF_ARP_COUNT_MIN) {
				ni_warn("[%s] ignore invalid count value %u, min: %d",
						xml_node_location(child), tmp,
						NI_ADDRCONF_ARP_COUNT_MIN);
				continue;
			}
			vfy_tmp.count = tmp;
		}

		if (ni_string_eq(child->name, "interval")) {
			ni_uint_range_t range = vfy_tmp.interval;

			if (child->children) {
				if (!ni_config_parse_uint_range(&range, child)) {
					ni_warn("[%s] ignore invalid arp-verify <interval>",
							xml_node_location(child));
					continue;
				}
			} else {
				if (ni_parse_uint(child->cdata, &range.max, 0) < 0) {
					ni_warn("[%s] ignore invalid arp-verify <interval>%s</interval>",
						xml_node_location(child), child->cdata);
					continue;
				}
				range.min = range.max;
			}

			if (range.min < NI_ADDRCONF_ARP_INTERVAL_MIN) {
				ni_warn("[%s]: ignore invalid arp-verify <interval> - min is %u",
						xml_node_location(child), NI_ADDRCONF_ARP_INTERVAL_MIN);
				continue;
			}

			if (range.max < range.min) {
				ni_warn("[%s] ignore invalid arp-verify <interval> - max:%u < min:%u",
						xml_node_location(child), range.max, range.min);
				continue;
			}

			vfy_tmp.interval = range;
		}
		if (ni_string_eq(child->name, "retries")) {
			if (ni_parse_uint(child->cdata, &vfy_tmp.retries, 0) < 0) {
				ni_warn("[%s] unable to parse arp-verify <retries>%s</retries>",
						xml_node_location(child), child->cdata);
				continue;
			}
		}
	}

	if (vfy_tmp.interval.max * vfy_tmp.count > NI_ADDRCONF_ARP_MAX_DURATION) {
		ni_warn("[%s] arp verify duration out of range: %u * %u > %u",
				xml_node_location(node),
				vfy_tmp.interval.max, vfy_tmp.count, NI_ADDRCONF_ARP_MAX_DURATION);
	} else {
		*verify = vfy_tmp;
	}

	return TRUE;
}

static ni_bool_t
ni_config_parse_addrconf_arp_notify(ni_config_arp_notify_t *notify, const xml_node_t *node)
{
	xml_node_t *child;
	unsigned int tmp;
	ni_config_arp_notify_t nfy_tmp = *notify;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "count")) {
			if (ni_parse_uint(child->cdata, &tmp, 0) < 0) {
				ni_warn("[%s] ignore invalid arp-notify <count>%s</count>",
						xml_node_location(child), child->cdata);
				continue;
			}
			if (tmp < NI_ADDRCONF_ARP_COUNT_MIN) {
				ni_warn("[%s] ignore invalid count value %u, min: %d",
						xml_node_location(child), tmp,
						NI_ADDRCONF_ARP_COUNT_MIN);
				continue;
			}
			nfy_tmp.count = tmp;
		}

		if (ni_string_eq(child->name, "interval")) {
			if (ni_parse_uint(child->cdata, &tmp, 0) < 0) {
				ni_warn("[%s] ignore invalid arp-notify <interval>%s</interval>",
						xml_node_location(child), child->cdata);
				continue;
			}

			if  (tmp < NI_ADDRCONF_ARP_INTERVAL_MIN)
				ni_warn("[%s] ignore invalid arp-notify <interval>%u</interval> - "
						"min value %u", xml_node_location(child),
						tmp, NI_ADDRCONF_ARP_INTERVAL_MIN);
			else
				nfy_tmp.interval = tmp;
		}
		if (ni_string_eq(child->name, "retries")) {
			if (ni_parse_uint(child->cdata, &tmp, 0) < 0) {
				ni_warn("[%s] ignore invalid arp-notify <retries>%s</retries>",
						xml_node_location(child), child->cdata);
				continue;
			}

			nfy_tmp.retries = tmp;
		}
	}

	if (nfy_tmp.interval * nfy_tmp.count > NI_ADDRCONF_ARP_MAX_DURATION) {
		ni_warn("[%s] arp notify duration out of range: %u * %u > %u",
				xml_node_location(node),
				nfy_tmp.interval, nfy_tmp.count, NI_ADDRCONF_ARP_MAX_DURATION);
	} else {
		*notify = nfy_tmp;
	}

	return TRUE;
}

static ni_bool_t
ni_config_parse_addrconf_arp(ni_config_arp_t *arpcfg, const xml_node_t *node)
{
	xml_node_t *child;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "verify")) {
			if (!ni_config_parse_addrconf_arp_verify(&arpcfg->verify, child))
				return FALSE;
		}

		if (ni_string_eq(child->name, "notify")) {
			if (!ni_config_parse_addrconf_arp_notify(&arpcfg->notify, child))
				return FALSE;
		}
	}

	return TRUE;
}

void
ni_config_parse_update_targets(unsigned int *update_mask, const xml_node_t *node)
{
	ni_string_array_t targets = NI_STRING_ARRAY_INIT;
	const xml_node_t *child;
	unsigned int mask;

	if (!update_mask || !node)
		return;

	if (node->children) {
		for (child = node->children; child; child = child->next)
			ni_string_array_append(&targets, child->name);
	} else {
		ni_string_split(&targets, node->cdata, " \t,|", 0);
	}

	mask = *update_mask;
	if (ni_addrconf_update_flags_parse_names(&mask, &targets))
		*update_mask = mask;
	ni_string_array_destroy(&targets);
}

void
ni_config_parse_update_dhcp4_routes(unsigned int *routes_opts, const xml_node_t *node)
{
	ni_string_array_t tags = NI_STRING_ARRAY_INIT;
	const xml_node_t *child;
	const char *tag;
	unsigned int i;

	if (!routes_opts || !node)
		return;

	if (node->children) {
		for (child = node->children; child; child = child->next)
			ni_string_array_append(&tags, child->name);
	} else {
		ni_string_split(&tags, node->cdata, " \t,|", 0);
	}

	*routes_opts = 0;
	for (i = 0; i < tags.count; ++i) {
		tag = tags.data[i];

		if (ni_string_eq(tag, "classless") || ni_string_eq(tag, "csr"))
			*routes_opts |= NI_BIT(NI_CONFIG_DHCP4_ROUTES_CSR);
		else
		if (ni_string_eq(tag, "ms-classless") || ni_string_eq(tag, "mscsr"))
			*routes_opts |= NI_BIT(NI_CONFIG_DHCP4_ROUTES_MSCSR);
		else
		if (ni_string_eq(tag, "static-routes") || ni_string_eq(tag, "class"))
			*routes_opts |= NI_BIT(NI_CONFIG_DHCP4_ROUTES_CLASS);
	}
	ni_string_array_destroy(&tags);
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

static ni_bool_t
ni_config_parse_extension_script_env(ni_script_action_t *script, xml_node_t *node,
		const ni_script_action_t *old)
{
	xml_node_t *child;

	if (!node || !script || !script->process)
		return FALSE;

	/* inherit previous environment variables  */
	if (old && old->process && old->process->environ.count) {
		ni_string_array_copy(&script->process->environ,
					&old->process->environ);
	}

	/* add+override with new script environment */
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "putenv")) {
			const char *name, *value;

			if (!(name = xml_node_get_attr(child, "name"))) {
				ni_error("[%s] putenv element without name attribute",
						xml_node_location(child));
				return FALSE;
			}
			value = xml_node_get_attr(child, "value");
			ni_shellcmd_setenv(script->process, name, value);
		}
	}
	return TRUE;
}

static ni_bool_t
ni_config_parse_extension(ni_extension_t *ex, xml_node_t *node)
{
	ni_script_action_t *script;
	ni_c_binding_t *binding;
	xml_node_t *child;

	/*
	 * Each extension has a list of builtin bindings and/or
	 * script actions "indexed" by unique name, that is:
	 *   <script  name="foo" ... />
	 *   <builtin name="foo" ... />
	 * implement two variants of the same action and thus
	 * the 2nd config definition overrides the 1st one.
	 * Further, the optional enabled="false" attribute
	 * permits to enable/disable an action script/builtin
	 * (e.g. users client-local.xml overrides client.xml).
	 */
	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "action") ||
		    ni_string_eq(child->name, "script")) {
			const char *name, *command, *attr;
			ni_bool_t enabled = TRUE;
			ni_script_action_t *old;

			name = xml_node_get_attr(child, "name");
			if (!ni_check_domain_name(name, ni_string_len(name), -1)) {
				ni_error("[%s] script action without valid name attribute",
						xml_node_location(child));
				return FALSE;
			}
			command = xml_node_get_attr(child, "command");
			if (ni_string_empty(command)) {
				ni_error("[%s] script action without valid command attribute",
						xml_node_location(child));
				return FALSE;
			}
			attr = xml_node_get_attr(child, "enabled");
			if (attr && ni_parse_boolean(attr, &enabled)) {
				ni_error("[%s] script action with invalid enabled attribute",
						xml_node_location(child));
			}

			old = ni_script_action_list_find(ex->actions, name);
			if ((script = ni_script_action_new(name, command))) {
				script->enabled = enabled;
				ni_config_parse_extension_script_env(script, child, old);
			}

			if (ni_script_action_list_replace(&ex->actions, old, script)) {
				ni_script_action_free(old);
			} else
			if (!ni_script_action_list_append(&ex->actions, script)) {
				ni_script_action_free(script);
				return FALSE;
			}

			/* override: remove previous binding with same name if any */
			if ((binding = ni_c_binding_list_find(ex->c_bindings, name))) {
				ni_c_binding_list_remove(&ex->c_bindings, binding);
				ni_c_binding_free(binding);
			}
		} else
		if (ni_string_eq(child->name, "builtin")) {
			const char *name, *library, *symbol, *attr;
			ni_bool_t enabled = TRUE;
			ni_c_binding_t *old;

			name = xml_node_get_attr(child, "name");
			if (!ni_check_domain_name(name, ni_string_len(name), -1)) {
				ni_error("[%s] builtin action without valid name attribute",
						xml_node_location(child));
				return FALSE;
			}
			symbol = xml_node_get_attr(child, "symbol");
			if (!ni_check_domain_name(symbol, ni_string_len(symbol), -1)) {
				ni_error("[%s] builtin action without valid symbol attribute",
						xml_node_location(child));
				return FALSE;
			}
			library = xml_node_get_attr(child, "library");
			/* NULL (missing attr) causes to use a symbol in the main program */
			if (library && !ni_check_pathname(library, ni_string_len(library))) {
				ni_error("[%s] builtin action with invalid library attribute",
						xml_node_location(child));
				return FALSE;
			}

			attr = xml_node_get_attr(child, "enabled");
			if (attr && ni_parse_boolean(attr, &enabled)) {
				ni_error("[%s] builtin action with invalid enabled attribute",
						xml_node_location(child));
			}

			if ((binding = ni_c_binding_new(name, library, symbol)))
				binding->enabled = enabled;

			old = ni_c_binding_list_find(ex->c_bindings, name);
			if (ni_c_binding_list_replace(&ex->c_bindings, old, binding)) {
				ni_c_binding_free(old);
			} else
			if (!ni_c_binding_list_append(&ex->c_bindings, binding)) {
				ni_c_binding_free(binding);
				return FALSE;
			}

			/* override: remove previous script with same name if any */
			if ((script = ni_script_action_list_find(ex->actions, name))) {
				ni_script_action_list_remove(&ex->actions, script);
				ni_script_action_free(script);
			}
		} else
		if (ni_string_eq(child->name, "putenv")) {
			const char *name, *value;

			if (!(name = xml_node_get_attr(child, "name"))) {
				ni_error("[%s] putenv element without name attribute",
						xml_node_location(child));
				return FALSE;
			}
			value = xml_node_get_attr(child, "value");
			ni_var_array_set(&ex->environment, name, value);
		}
	}

	return TRUE;
}

static ni_bool_t
ni_config_extension_merge_actions(ni_script_action_t **nactions, ni_script_action_t **oactions)
{
	ni_var_array_t vars = NI_VAR_ARRAY_INIT;
	ni_script_action_t *oscript;
	ni_script_action_t *nscript;
	ni_script_action_t *next;

	if (!nactions || !oactions)
		return FALSE;

	for (oscript = *oactions; oscript; oscript = next) {
		next = oscript->next;

		if (!oscript->name || !oscript->process)
			continue;

		if ((nscript = ni_script_action_list_find(*nactions, oscript->name))) {
			if (ni_environ_getenv_vars(&oscript->process->environ, &vars))
				ni_environ_setenv_vars(&nscript->process->environ,
						&vars, FALSE);
			ni_var_array_destroy(&vars);
		} else {
			if (ni_script_action_list_remove(oactions, oscript))
				ni_script_action_list_append(nactions, oscript);
		}
	}
	return TRUE;
}

static ni_bool_t
ni_config_extension_list_add(ni_extension_t **list, ni_extension_t *oex, ni_extension_t *nex)
{

	if (!list || !nex)
		return FALSE;

	if (oex) {
		ni_config_extension_merge_actions(&nex->actions, &oex->actions);
		ni_var_array_set_vars(&nex->environment, &oex->environment, FALSE);
	}

	if (ni_extension_list_replace(list, oex, nex)) {
		ni_extension_free(oex);
		return TRUE;
	}
	if (!ni_extension_list_append(list, nex)) {
		ni_extension_free(nex);
		return FALSE;
	}
	return TRUE;
}

/*
 * Object model extensions let you implement parts of a dbus interface separately
 * from the main wicked body of code; either through a shared library or an
 * external command/shell script
 *
 * <dbus-service interface="org.opensuse.Network.foobar">
 *  <action name="dbusMethodName" command="/some/shell/scripts some-args"/>
 *  <builtin name="dbusOtherMethodName" library="/usr/lib/libfoo.so" symbol="c_method_impl_name"/>
 *
 *  <putenv name="WICKED_OBJECT_PATH" value="$object-path"/>
 *  <putenv name="WICKED_INTERFACE_NAME" value="$property:name"/>
 *  <putenv name="WICKED_INTERFACE_INDEX" value="$property:index"/>
 * </dbus-service>
 */
static ni_bool_t
ni_config_parse_objectmodel_extension(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex, *old;
	const char *interface;

	ni_assert(list && node);

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
			"parsing %s extension config node", node->name);
	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_APPLICATION)) {
		xml_node_print_debug(node, NI_TRACE_APPLICATION);
	}

	interface = xml_node_get_attr(node, "interface");
	if (!ni_check_domain_name(interface, ni_string_len(interface), 0)) {
		ni_error("[%s] %s element with invalid interface attribute",
				xml_node_location(node), node->name);
		return FALSE;
	}

	ex = ni_extension_new(interface);
	if (!ex || !ni_config_parse_extension(ex, node)) {
		ni_extension_free(ex);
		return FALSE;
	}

	if (!ex->actions && !ex->c_bindings) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
				"[%s] disarding %s '%s' extension without actions",
				xml_node_location(node), node->name, interface);
		ni_extension_free(ex);
		return TRUE;
	}

	old = ni_extension_list_find(*list, interface);
	if (!ni_config_extension_list_add(list, old, ex)) {
		ni_warn("[%s] unable to add %s extension to list",
				xml_node_location(node), node->name);
		ni_extension_free(ex);
		return FALSE;
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
static ni_bool_t
ni_config_parse_objectmodel_netif_ns(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex;

	ni_assert(list && node);

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
			"parsing %s extension config node", node->name);
	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_APPLICATION)) {
		xml_node_print_debug(node, NI_TRACE_APPLICATION);
	}

	/*
	 * we need only 1 netif-naming-services extension
	 * with multiple unique builtin / script actions.
	 */
	if (!(ex = *list))
		ex = ni_extension_new(NULL);

	if (!ex || !ni_config_parse_extension(ex, node)) {
		if (ex != *list)
			ni_extension_free(ex);
		return FALSE;
	}

	if (ex->actions) {
		ni_warn("[%s] script actions not supported in %s extensions",
				xml_node_location(node), node->name);
		ni_script_action_list_destroy(&ex->actions);
	}
	if (!ex->c_bindings) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
				"[%s] disarding %s extension without builtin actions",
				xml_node_location(node), node->name);
		if (ex != *list)
			ni_extension_free(ex);
		return TRUE;
	}

	if (ex != *list && !ni_extension_list_append(list, ex)) {
		ni_warn("[%s] unable to add %s extension to list",
				xml_node_location(node), node->name);
		ni_extension_free(ex);
		return FALSE;
	}
	return TRUE;
}

/*
 * Another class of extensions helps with discovery of interface configuration through
 * firmware, such as iBFT. You can use this to specify one or more shell commands
 * that generate a list of <interface> elements as output.
 *
 * The current netif-firmware-discovery extension definition is:
 *   <netif-firmware-discovery name="ibft">
 *     <script name="show-config"  command="/some/crazy/path/to/script" />
 *     <script name="list-ifnames" command="/some/crazy/path/to/script -l" />
 *     ...
 *   </netif-firmware-discovery>
 *
 * The legacy extension definition is automatically migrated and were:
 *   <netif-firmware-discovery>
 *     <script name="ibft" command="/some/crazy/path/to/script" />
 *     ...
 *   </netif-firmware-discovery>
 * The `-l` command parameter were passed to implement `list-ifnames` action.
 */
static ni_bool_t
ni_config_objectmodel_firmware_discovery_migrate(ni_extension_t **list, ni_extension_t *lex)
{
	ni_script_action_t *nscript, *lscript;
	ni_extension_t *nex;

	if (!list || !lex)
		return FALSE;

	for (lscript = lex->actions; lscript; lscript = lscript->next) {
		if (ni_string_empty(lscript->name) || !lscript->process ||
			ni_string_empty(lscript->process->command))
			continue;

		if (!(nex = ni_extension_new(lscript->name)))
			return FALSE;

		nex->enabled = lscript->enabled;
		ni_var_array_copy(&nex->environment, &lex->environment);

		nscript = ni_script_action_new("show-config", lscript->process->command);
		if (!ni_script_action_list_append(&nex->actions, nscript)) {
			ni_script_action_free(nscript);
			ni_extension_free(nex);
			return FALSE;
		}
		ni_string_array_copy(&nscript->process->environ,
				&lscript->process->environ);

		nscript = ni_script_action_new("list-ifnames", lscript->process->command);
		if (!nscript || !ni_shellcmd_add_arg(nscript->process, "-l") ||
		    !ni_script_action_list_append(&nex->actions, nscript)) {
			ni_script_action_free(nscript);
			ni_extension_free(nex);
			return FALSE;
		}
		ni_string_array_copy(&nscript->process->environ,
				&lscript->process->environ);

		if (!ni_extension_list_append(list, nex)) {
			ni_extension_free(nex);
			return FALSE;
		}
	}
	return TRUE;
}

static ni_bool_t
ni_config_parse_objectmodel_firmware_discovery(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex, *old, *next, *migrated = NULL;
	const char *name, *attr;

	ni_assert(list && node);

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
			"parsing %s extension config node", node->name);
	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_APPLICATION)) {
		xml_node_print_debug(node, NI_TRACE_APPLICATION);
	}

	name = xml_node_get_attr(node, "name");
	if (name && !ni_check_domain_name(name, ni_string_len(name), -1)) {
		ni_error("[%s] <%s> element contains invalid name attribute",
				xml_node_location(node), node->name);
		return FALSE;
	}

	ex = ni_extension_new(name);
	if (!ex || !ni_config_parse_extension(ex, node)) {
		ni_extension_free(ex);
		return FALSE;
	}

	if (name) {
		attr = xml_node_get_attr(node, "enabled");

		if (attr && ni_parse_boolean(attr, &ex->enabled)) {
			ni_error("[%s] disarding %s extension with invalid enabled attribute",
					xml_node_location(node), node->name);
			ni_extension_free(ex);
			return FALSE;
		}

		/*
		 * The client-firmware.xml does not contain any actions default:
		 *   <netif-firmware-discovery name="ibft" enabled=... />
		 * supposed to override the enabled flag only.
		 * We simply change the enable flag in the old extension and
		 * when it defines some env vars, we override then too:
		 */
		if (!ex->actions && (old = ni_extension_list_find(*list, name))) {
			old->enabled = ex->enabled;
			ni_var_array_set_vars(&old->environment, &ex->environment, TRUE);

			ni_extension_free(ex);
			return TRUE;
		}
		migrated = ex;
	} else {
		if (!ni_config_objectmodel_firmware_discovery_migrate(&migrated, ex)) {
			ni_error("[%s] failed to migrate legacy %s extension",
					xml_node_location(node), node->name);
			ni_extension_free(ex);
			return FALSE;
		}
		ni_extension_free(ex);
	}

	for (ex = migrated; ex; ex = next) {
		next = ex->next;
		ex->next = NULL;

		name = ex->name;
		if (ex->c_bindings) {
			ni_warn("[%s] builtin actions not supported in %s extensions",
					xml_node_location(node), node->name);
			ni_c_binding_list_destroy(&ex->c_bindings);
		}
		if (!ex->actions) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
					"[%s] disarding %s extension without script actions",
					xml_node_location(node), node->name);
			ni_extension_free(ex);
			return TRUE;
		}

		old = ni_extension_list_find(*list, name);
		if (!ni_config_extension_list_add(list, old, ex)) {
			ni_warn("[%s] unable to add %s extension to list",
					xml_node_location(node), node->name);
			ni_extension_free(ex);
			return FALSE;
		}
	}
	return TRUE;
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
static ni_bool_t
ni_config_parse_system_updater(ni_extension_t **list, xml_node_t *node)
{
	ni_extension_t *ex, *old;
	const char *name;
	const char *format;

	ni_assert(list && node);

	ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_APPLICATION,
			"parsing %s extension config node", node->name);
	if (ni_debug_guard(NI_LOG_DEBUG2, NI_TRACE_APPLICATION)) {
		xml_node_print_debug(node, NI_TRACE_APPLICATION);
	}

	name = xml_node_get_attr(node, "name");
	if (!ni_check_domain_name(name, ni_string_len(name), -1)) {
		ni_error("[%s] <%s> element lacks name attribute",
				xml_node_location(node), node->name);
		return FALSE;
	}

	ex = ni_extension_new(name);
	if (!ex || !ni_config_parse_extension(ex, node)) {
		ni_extension_free(ex);
		return FALSE;
	}

	format = xml_node_get_attr(node, "format");
	if (format) {
		ex->format = strdup(format);

		if (!ex->format) {
			ni_warn("[%s] failed to allocate memory for format-string", node->name);
			ni_extension_free(ex);
			return FALSE;
		}
	}

	if (ex->c_bindings) {
		ni_warn("[%s] builtin actions not supported in %s extensions",
				xml_node_location(node), node->name);
		ni_c_binding_list_destroy(&ex->c_bindings);
	}
	if (!ex->actions) {
		ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_APPLICATION,
				"[%s] disarding %s extension without script actions",
				xml_node_location(node), node->name);
		ni_extension_free(ex);
		return TRUE;
	}

	old = ni_extension_list_find(*list, name);
	if (!ni_config_extension_list_add(list, old, ex)) {
		ni_warn("[%s] unable to add %s extension to list",
				xml_node_location(node), node->name);
		ni_extension_free(ex);
		return FALSE;
	}
	return TRUE;
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
 *   <ifconfig location="wicked:" />
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

ni_bool_t
ni_config_parse_rtnl_event(ni_config_rtnl_event_t *conf, xml_node_t *node)
{
	xml_node_t *child;

	if (!conf || !node)
		return FALSE;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "receive-buffer-length")) {
			if (ni_parse_uint(child->cdata, &conf->recv_buff_length, 0))
				return FALSE;
		} else
		if (ni_string_eq(child->name, "message-buffer-length")) {
			if (ni_parse_uint(child->cdata, &conf->mesg_buff_length, 0))
				return FALSE;
		}
	}
	return TRUE;
}

/*
 * bonding support config options
 */
static const ni_intmap_t	config_bonding_ctl_names[] = {
	{ "netlink",		NI_CONFIG_BONDING_CTL_NETLINK	},
	{ "sysfs",		NI_CONFIG_BONDING_CTL_SYSFS	},
	{ NULL,			-1U				}
};

const char *
ni_config_bonding_ctl_type_to_name(ni_config_bonding_ctl_t type)
{
	return ni_format_uint_mapped(type, config_bonding_ctl_names);
}

static ni_bool_t
ni_config_bonding_ctl_name_to_type(const char *name, ni_config_bonding_ctl_t *type)
{
	unsigned int _type;

	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, config_bonding_ctl_names, &_type) != 0)
		return FALSE;

	*type = _type;
	return TRUE;
}

ni_config_bonding_ctl_t
ni_config_bonding_ctl(void)
{
	return ni_global.config ? ni_global.config->bonding.ctl : NI_CONFIG_BONDING_CTL_NETLINK;
}

static ni_bool_t
ni_config_parse_bonding(ni_config_bonding_t *conf, const xml_node_t *node)
{
	const xml_node_t *child;

	if (!conf || !node)
		return FALSE;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "ctl")) {
			if (!ni_config_bonding_ctl_name_to_type(child->cdata, &conf->ctl)) {
				ni_error("%s: invalid <bonding><ctl>%s</ctl></bonding> option",
						xml_node_location(child), child->cdata);
				return FALSE;
			}
		}
	}
	return TRUE;
}


/*
 * teamd support config options
 */
static const ni_intmap_t	config_teamd_ctl_names[] = {
	{ "detect-once",	NI_CONFIG_TEAMD_CTL_DETECT_ONCE	},
	{ "detect",		NI_CONFIG_TEAMD_CTL_DETECT	},
	{ "dbus",		NI_CONFIG_TEAMD_CTL_DBUS	},
	{ "unix",		NI_CONFIG_TEAMD_CTL_UNIX	},
	{ NULL,			-1U				}
};

const char *
ni_config_teamd_ctl_type_to_name(ni_config_teamd_ctl_t type)
{
	return ni_format_uint_mapped(type, config_teamd_ctl_names);
}

static ni_bool_t
ni_config_teamd_ctl_name_to_type(const char *name, ni_config_teamd_ctl_t *type)
{
	unsigned int _type;

	if (!name || !type)
		return FALSE;

	if (ni_parse_uint_mapped(name, config_teamd_ctl_names, &_type) != 0)
		return FALSE;

	*type = _type;
	return TRUE;
}

ni_bool_t
ni_config_teamd_enabled(void)
{
	return ni_global.config ? ni_global.config->teamd.enabled : FALSE;
}

ni_config_teamd_ctl_t
ni_config_teamd_ctl(void)
{
	return ni_global.config ? ni_global.config->teamd.ctl : NI_CONFIG_TEAMD_CTL_DETECT_ONCE;
}

ni_bool_t
ni_config_teamd_enable(ni_config_teamd_ctl_t type)
{
	if (ni_global.config && ni_config_teamd_ctl_type_to_name(type)) {
		ni_global.config->teamd.enabled = TRUE;
		ni_global.config->teamd.ctl = type;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_config_teamd_disable(void)
{
	if (ni_global.config) {
		ni_global.config->teamd.enabled = FALSE;
		ni_global.config->teamd.ctl = NI_CONFIG_TEAMD_CTL_DETECT_ONCE;
		return TRUE;
	}
	return FALSE;
}

static ni_bool_t
ni_config_parse_teamd(ni_config_teamd_t *conf, const xml_node_t *node)
{
	const xml_node_t *child;

	if (!conf || !node)
		return FALSE;

	for (child = node->children; child; child = child->next) {
		if (ni_string_eq(child->name, "enabled")) {
			if (ni_parse_boolean(child->cdata, &conf->enabled)) {
				ni_error("%s: invalid <teamd><enable>%s</enable></teamd> option",
						xml_node_location(child), child->cdata);
				return FALSE;
			}
		}
		if (ni_string_eq(child->name, "ctl")) {
			if (!ni_config_teamd_ctl_name_to_type(child->cdata, &conf->ctl)) {
				ni_error("%s: invalid <teamd><ctl>%s</ctl></teamd> option",
						xml_node_location(child), child->cdata);
				return FALSE;
			}
		}
	}
	return TRUE;
}

/*
 * Extension handling
 */
ni_extension_t *
ni_config_find_extension(ni_config_t *conf, const char *interface)
{
	ni_extension_t *ex;

	ex = ni_extension_list_find(conf->dbus_extensions, interface);
	return ex && ex->enabled ? ex : NULL;
}

ni_extension_t *
ni_config_find_system_updater(ni_config_t *conf, const char *name)
{
	ni_extension_t *ex;

	ex = ni_extension_list_find(conf->updater_extensions, name);
	return ex && ex->enabled ? ex : NULL;
}

/*
 * Query the default update mask
 */
static unsigned int
ni_config_addrconf_update_mask_all(void)
{
	/*
	 * Mask of all supported update flags
	 */
	static unsigned mask = __NI_ADDRCONF_UPDATE_NONE;
	if (!mask) {
		unsigned int i;
		mask = ~mask;
		for (i = 0; i < 32; ++i) {
			if (!ni_addrconf_update_flag_to_name(i))
				mask &= ~NI_BIT(i);
		}
	}
	return mask;
}

static unsigned int
ni_config_addrconf_update_default(void)
{
	/*
	 * Update flags enabled for static/intrinsic leases by default
	 */
	return ni_config_addrconf_update_mask_all();
}

static unsigned int
ni_config_addrconf_update_mask_dhcp4(void)
{
	/*
	 * All supported update flags for dhcp4 leases
	 */
	return ni_config_addrconf_update_mask_all();
}

static unsigned int
ni_config_addrconf_update_dhcp4(void)
{
	/*
	 * Update flags enabled for dhcp4 leases by default
	 */
	return	NI_BIT(NI_ADDRCONF_UPDATE_DEFAULT_ROUTE)|
		NI_BIT(NI_ADDRCONF_UPDATE_DNS)		|
		NI_BIT(NI_ADDRCONF_UPDATE_NTP)		|
		NI_BIT(NI_ADDRCONF_UPDATE_NIS)		|
		NI_BIT(NI_ADDRCONF_UPDATE_NDS)		|
		NI_BIT(NI_ADDRCONF_UPDATE_MTU)		|
		NI_BIT(NI_ADDRCONF_UPDATE_TZ)		|
		NI_BIT(NI_ADDRCONF_UPDATE_BOOT);
}

static unsigned int
ni_config_addrconf_update_mask_dhcp6(void)
{
	/*
	 * All supported update flags for dhcp6 leases
	 *
	 * Note:
	 * - DHCPv6 does not handle routes --> IPv6 RA's job
	 */
	return	NI_BIT(NI_ADDRCONF_UPDATE_HOSTNAME)	|
		NI_BIT(NI_ADDRCONF_UPDATE_DNS)		|
		NI_BIT(NI_ADDRCONF_UPDATE_NTP)		|
		NI_BIT(NI_ADDRCONF_UPDATE_NIS)		|
		NI_BIT(NI_ADDRCONF_UPDATE_SIP)		|
		NI_BIT(NI_ADDRCONF_UPDATE_TZ)		|
		NI_BIT(NI_ADDRCONF_UPDATE_BOOT);
}

static unsigned int
ni_config_addrconf_update_dhcp6(void)
{
	/*
	 * Update flags enabled for dhcp6 leases by default
	 */
	return	NI_BIT(NI_ADDRCONF_UPDATE_DNS)		|
		NI_BIT(NI_ADDRCONF_UPDATE_NTP)		|
#ifdef NI_DHCP6_NIS
		NI_BIT(NI_ADDRCONF_UPDATE_NIS)		|
#endif
		NI_BIT(NI_ADDRCONF_UPDATE_TZ)		|
		NI_BIT(NI_ADDRCONF_UPDATE_BOOT);
}

static unsigned int
ni_config_addrconf_update_mask_auto4(void)
{
	/*
	 * All supported update flags for auto4 leases
	 *
	 * Note: empty mask, supports IP address only
	 */
	return __NI_ADDRCONF_UPDATE_NONE;
}

static unsigned int
ni_config_addrconf_update_auto4(void)
{
	/*
	 * Update flags enabled for auto4 leases by default
	 */
	return ni_config_addrconf_update_mask_auto4();
}

static unsigned int
ni_config_addrconf_update_mask_auto6(void)
{
	/*
	 * All supported update flags for auto6 leases
	 */
	return NI_BIT(NI_ADDRCONF_UPDATE_DNS);
}

static unsigned int
ni_config_addrconf_update_auto6(void)
{
	/*
	 * Update flags enabled for auto6 leases by default
	 */
	return ni_config_addrconf_update_mask_auto6();
}

unsigned int
ni_config_addrconf_update_mask(ni_addrconf_mode_t type, unsigned int family)
{
	unsigned int mask = __NI_ADDRCONF_UPDATE_NONE;

	switch (type) {
	case NI_ADDRCONF_STATIC:
	case NI_ADDRCONF_INTRINSIC:
		/* for now we treat intrinsic just like static. We may want to differentiate
		 * a bit better in the future. Let's see if anyone needs it. */
		mask = ni_config_addrconf_update_mask_all();
		break;

	case NI_ADDRCONF_AUTOCONF:
		switch (family) {
		case AF_INET:
			mask = ni_config_addrconf_update_mask_auto4();
			break;
		case AF_INET6:
			mask = ni_config_addrconf_update_mask_auto6();
			break;
		default: ;
		}
		break;

	case NI_ADDRCONF_DHCP:
		switch (family) {
		case AF_INET:
			mask = ni_config_addrconf_update_mask_dhcp4();
			break;
		case AF_INET6:
			mask = ni_config_addrconf_update_mask_dhcp6();
			break;
		default: ;
		}
		break;
	default: ;
	}
	return mask;
}

unsigned int
ni_config_addrconf_update(const char *ifname, ni_addrconf_mode_t type, unsigned int family)
{
	unsigned int mask = __NI_ADDRCONF_UPDATE_NONE;
	const ni_config_t *conf = ni_global.config;
	const ni_config_dhcp4_t *dhcp4;
	const ni_config_dhcp6_t *dhcp6;

	switch (type) {
	case NI_ADDRCONF_STATIC:
	case NI_ADDRCONF_INTRINSIC:
		/* for now we treat intrinsic just like static. We may want to differentiate
		 * a bit better in the future. Let's see if anyone needs it. */
		mask = conf ? conf->addrconf.default_allow_update :
			ni_config_addrconf_update_default();
		break;

	case NI_ADDRCONF_AUTOCONF:
		switch (family) {
		case AF_INET:
			mask = conf ? conf->addrconf.auto4.allow_update :
				ni_config_addrconf_update_auto4();
			break;
		case AF_INET6:
			mask = conf ? conf->addrconf.auto6.allow_update :
				ni_config_addrconf_update_auto6();
			break;
		default: ;
		}
		break;

	case NI_ADDRCONF_DHCP:
		switch (family) {
		case AF_INET:
			dhcp4 = ni_config_dhcp4_find_device(ifname);
			mask = dhcp4 ? dhcp4->allow_update :
				ni_config_addrconf_update_dhcp4();
			break;
		case AF_INET6:
			dhcp6 = ni_config_dhcp6_find_device(ifname);
			mask = dhcp6 ? dhcp6->allow_update :
				ni_config_addrconf_update_dhcp6();
			break;
		default: ;
		}
		break;
	default: ;
	}
	return mask;
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

static void
ni_config_addrconf_arp_default(ni_config_arp_t *cfg)
{
	cfg->verify.count = NI_ADDRCONF_ARP_VERIFY_COUNT;
	cfg->verify.retries = NI_ADDRCONF_ARP_VERIFY_RETRIES;
	cfg->verify.interval.min = NI_ADDRCONF_ARP_VERIFY_MIN;
	cfg->verify.interval.max = NI_ADDRCONF_ARP_VERIFY_MAX;

	cfg->notify.count = NI_ADDRCONF_ARP_NOTIFY_COUNT;
	cfg->notify.interval = NI_ADDRCONF_ARP_NOTIFY_INTERVAL;
	cfg->notify.retries = NI_ADDRCONF_ARP_NOTIFY_RETRIES;
}

extern const ni_config_arp_t *
ni_config_addrconf_arp(ni_addrconf_mode_t owner, const char *ifname)
{
	static ni_config_arp_t default_arp_cfg;
	static ni_bool_t default_is_set = FALSE;
	const ni_config_dhcp4_t *dhcp4;
	ni_config_t *conf;

	if (!default_is_set) {
		default_is_set = TRUE;
		ni_config_addrconf_arp_default(&default_arp_cfg);
	}

	if (!(conf = ni_global.config))
		return &default_arp_cfg;

	switch (owner) {
	case NI_ADDRCONF_DHCP:
		if (!(dhcp4 = ni_config_dhcp4_find_device(ifname)))
			return &default_arp_cfg;
		return &dhcp4->arp;
	case NI_ADDRCONF_AUTOCONF:
		return &conf->addrconf.auto4.arp;
	default:
		return &conf->addrconf.arp;
	}
}
