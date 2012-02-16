/*
 * No REST for the wicked!
 *
 * This command line utility provides an interface to the network
 * configuration/information facilities.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <mcheck.h>
#include <stdlib.h>
#include <getopt.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/addrconf.h>
#include <wicked/bonding.h>
#include <wicked/bridge.h>
#include <wicked/backend.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>
#include <wicked/objectmodel.h>

#include "client/wicked-client.h"

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_DRYRUN,
	OPT_ROOTDIR,
	OPT_LINK_TIMEOUT,
	OPT_NOPROGMETER,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "dryrun",		no_argument,		NULL,	OPT_DRYRUN },
	{ "dry-run",		no_argument,		NULL,	OPT_DRYRUN },
	{ "link-timeout",	required_argument,	NULL,	OPT_LINK_TIMEOUT },
	{ "no-progress-meter",	no_argument,		NULL,	OPT_NOPROGMETER },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "root-directory",	required_argument,	NULL,	OPT_ROOTDIR },

	{ NULL }
};

static int		opt_dryrun = 0;
static char *		opt_rootdir = NULL;
static unsigned int	opt_link_timeout = 10;
static int		opt_progressmeter = 1;
static int		opt_shutdown_parents = 1;

static int		do_create(int, char **);
static int		do_delete(int, char **);
static int		do_show(int, char **);
static int		do_show_xml(int, char **);
static int		do_addport(int, char **);
static int		do_delport(int, char **);
extern int		do_ifup(int, char **);
extern int		do_ifdown(int, char **);
static int		do_xpath(int, char **);

int
main(int argc, char **argv)
{
	char *cmd;
	int c;

	mtrace();
	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"./wicked [options] cmd path\n"
				"This command understands the following options\n"
				"  --config filename\n"
				"        Use alternative configuration file.\n"
				"  --dry-run\n"
				"        Do not change the system in any way.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
				"\n"
				"Supported commands:\n"
				"  create <iftype> [<property>=<value> <property>=<value> ...]\n"
				"  ifup [--boot] [--file xmlspec] ifname\n"
				"  ifdown [--delete] ifname\n"
				"  get /config/interface\n"
				"  get /config/interface/ifname\n"
				"  put /config/interface/ifname < cfg.xml\n"
				"  get /system/interface\n"
				"  get /system/interface/ifname\n"
				"  put /system/interface/ifname < cfg.xml\n"
				"  delete /config/interface/ifname\n"
				"  delete /system/interface/ifname\n"
				"  xpath [options] expr ...\n"
			       );
			return 1;

		case OPT_CONFIGFILE:
			ni_set_global_config_path(optarg);
			break;

		case OPT_DRYRUN:
			opt_dryrun = 1;
			break;

		case OPT_ROOTDIR:
			opt_rootdir = optarg;
			break;

		case OPT_LINK_TIMEOUT:
			if (ni_parse_int(optarg, &opt_link_timeout) < 0)
				ni_fatal("unable to parse link timeout value");
			break;

		case OPT_NOPROGMETER:
			opt_progressmeter = 0;
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help(stdout);
				return 0;
			}
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				return 1;
			}
			break;

		}
	}

	opt_shutdown_parents = 1; /* kill this */

	if (!isatty(1))
		opt_progressmeter = 0;

	if (ni_init() < 0)
		return 1;

	if (optind >= argc) {
		fprintf(stderr, "Missing command\n");
		goto usage;
	}

	cmd = argv[optind++];

	if (!strcmp(cmd, "create"))
		return do_create(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "show"))
		return do_show(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "show-xml"))
		return do_show_xml(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "delete"))
		return do_delete(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "addport"))
		return do_addport(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "delport"))
		return do_delport(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "ifup"))
		return do_ifup(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "ifdown"))
		return do_ifdown(argc - optind + 1, argv + optind - 1);

	/* Old wicked style functions follow */
	if (!strcmp(cmd, "xpath"))
		return do_xpath(argc - optind + 1, argv + optind - 1);

	fprintf(stderr, "Unsupported command %s\n", cmd);
	goto usage;
}

/*
 * Populate a property dict with parameters
 */
dbus_bool_t
ni_call_properties_from_argv(const ni_dbus_service_t *interface, ni_dbus_variant_t *dict, int argc, char **argv)
{
	int i;

	ni_dbus_variant_init_dict(dict);
	for (i = 0; i < argc; ++i) {
		const ni_dbus_property_t *property;
		ni_dbus_variant_t *var, *var_dict;
		char *property_name = argv[i];
		char *value;

		if ((value = strchr(property_name, '=')) == NULL) {
			ni_error("Cannot parse property \"%s\"", property_name);
			return FALSE;
		}
		*value++ = '\0';

		/* Using lookup_property will also resolve hierarchical names, such
		 * as foo.bar.baz (which is property baz within a dict named bar,
		 * which is part of dict foo). */
		if (!(property = ni_dbus_service_create_property(interface, property_name, dict, &var_dict))) {
			ni_error("Unsupported property \"%s\"", property_name);
			return FALSE;
		}

		var = ni_dbus_dict_add(var_dict, property->name);
		if (!ni_dbus_variant_init_signature(var, property->signature)) {
			ni_error("Unable to parse property %s=%s (bad type signature)",
					property_name, value);
			return FALSE;
		}

		if (property->parse) {
			if (!property->parse(property, var, value)) {
				ni_error("Unable to parse property %s=%s", property_name, value);
				return FALSE;
			}
		} else {
			/* FIXME: variant_parse should unquote string if needed */
			if (!ni_dbus_variant_parse(var, value, property->signature)) {
				ni_error("Unable to parse property %s=%s", property_name, value);
				return FALSE;
			}
		}
	}

	return TRUE;
}

/*
 * Obtain an object handle for Wicked.Interface
 */
ni_dbus_object_t *
wicked_get_interface_object(const char *default_interface)
{
	static const ni_dbus_class_t *netif_list_class = NULL;
	ni_dbus_object_t *root_object, *child;

	if (!(root_object = ni_call_create_client()))
		return NULL;

	if (netif_list_class == NULL) {
		const ni_dbus_service_t *netif_list_service;

		netif_list_service = ni_objectmodel_service_by_name(WICKED_DBUS_NETIFLIST_INTERFACE);
		ni_assert(netif_list_service);

		netif_list_class = netif_list_service->compatible;
	}

	child = ni_dbus_object_create(root_object, "Interface",
			netif_list_class,
			NULL);

	if (!default_interface)
		default_interface = WICKED_DBUS_INTERFACE ".Interface";
	ni_dbus_object_set_default_interface(child, default_interface);

	return child;
}

/*
 * Given an XML interface description, find the link layer information.
 * By convention, the link layer information must be an XML element with
 * the name of the link layer, such as <ethernet>, <vlan> or <bond>.
 */
xml_node_t *
wicked_find_link_properties(const xml_node_t *ifnode)
{
	xml_node_t *child, *found = NULL;

	for (child = ifnode->children; child; child = child->next) {
		if (ni_linktype_name_to_type(child->name) >= 0) {
			if (found != NULL) {
				ni_error("%s: ambiguous link layer, found both <%s> and <%s> element",
						xml_node_location(ifnode),
						found->name, child->name);
				return NULL;
			}
			found = child;
		}
	}

	if (found == NULL)
		ni_error("%s: no link layer information found", xml_node_location(ifnode));
	return found;
}

/*
 * Get the dbus interface for a given link layer type
 * Note, this must use the same class naming convention
 * as in __ni_objectmodel_link_classname()
 */
const ni_dbus_service_t *
wicked_link_layer_factory_service(const char *link_type)
{
	char namebuf[256];
	const ni_dbus_class_t *class;
	const ni_dbus_service_t *service;

	snprintf(namebuf, sizeof(namebuf), "netif-%s", link_type);
	if (!(class = ni_objectmodel_get_class(namebuf))) {
		ni_error("no dbus class for link layer \"%s\"", link_type);
		return NULL;
	}

	/* See if there's a service for this link layer class. Note that
	 * ni_objectmodel_service_by_class may return a service for a
	 * base class (such as for netif), which we're not interested in.
	 */
	if (!(service = ni_objectmodel_service_by_class(class))) {
		ni_error("no dbus service for link layer \"%s\"", link_type);
		return NULL;
	}

	snprintf(namebuf, sizeof(namebuf), "%s.Factory", service->name);
	if (!(service = ni_objectmodel_service_by_name(namebuf))) {
		ni_error("no dbus factory service for link layer \"%s\"", link_type);
		return NULL;
	}

	if (!ni_dbus_service_get_method(service, "newLink")) {
		ni_error("no dbus factory service for link layer \"%s\" has no newLink method", link_type);
		return NULL;
	}

	return service;
}

/*
 * Handle "create" command
 */
int
do_create(int argc, char **argv)
{
	enum  { OPT_FILE, };
	static struct option ifup_options[] = {
		{ "file", required_argument, NULL, OPT_FILE },
		{ NULL }
	};
	const char *link_type = NULL;
	const ni_dbus_service_t *service;
	const char *opt_file = NULL;
	char *ifname;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case OPT_FILE:
			opt_file = optarg;
			break;

		default:
			fprintf(stderr,
				"wicked [options] create [create-options] link-type [name=ifname]\n"
				"\nSupported create-options:\n"
				"  --file <filename>\n"
				"      Read interface configuration(s) from file\n"
				);
			return 1;
		}
	}

	if (optind < argc) {
		link_type = argv[optind++];
		if (ni_linktype_name_to_type(link_type) < 0) {
			ni_error("invalid link type \"%s\"", link_type);
			return 1;
		}
	}

	argv += optind;
	argc -= optind;

	ni_objectmodel_init(NULL);

	if (opt_file) {
		xml_document_t *doc;
		xml_node_t *ifnode, *namenode, *linknode;
		const char *requested_name = NULL;

		if (!(doc = xml_document_read(opt_file))) {
			ni_error("unable to parse XML document %s", opt_file);
			return 1;
		}

		if (!(ifnode = xml_node_get_child(doc->root, "interface"))) {
			ni_error("missing <interface> element in file %s", opt_file);
			goto xml_done;
		}

		if (!(linknode = wicked_find_link_properties(ifnode))) {
			ni_error("cannot determine link type of interface");
			goto xml_done;
		}
		link_type = linknode->name;

		if (!(service = wicked_link_layer_factory_service(link_type))) {
			ni_error("wicked create: unknown/unsupported link type %s", link_type);
			return 1;
		}

		if ((namenode = xml_node_get_child(ifnode, "name")) != NULL)
			requested_name = namenode->cdata;

		ifname = ni_call_link_new_xml(service, requested_name, linknode);

xml_done:
		xml_document_free(doc);
	} else {
		if (!(service = wicked_link_layer_factory_service(link_type))) {
			ni_error("wicked create: unknown/unsupported link type %s", link_type);
			return 1;
		}

		ifname = ni_call_link_new_argv(service, argc, argv);
	}

	if (!ifname)
		return 1;

	printf("%s\n", ifname);
	return 0;
}

static ni_dbus_object_t *
wicked_get_interface(ni_dbus_object_t *root_object, const char *ifname)
{
	static ni_dbus_object_t *interfaces = NULL;
	ni_dbus_object_t *object;

	if (interfaces == NULL) {
		if (!(interfaces = wicked_get_interface_object(NULL)))
			return NULL;

		/* Call ObjectManager.GetManagedObjects to get list of objects and their properties */
		if (!ni_dbus_object_refresh_children(interfaces)) {
			ni_error("Couldn't get list of active network interfaces");
			return NULL;
		}
	}

	if (ifname == NULL)
		return interfaces;

	/* Loop over all interfaces and find the one with matching name */
	for (object = interfaces->children; object; object = object->next) {
		ni_interface_t *ifp = ni_objectmodel_unwrap_interface(object, NULL);

		if (ifp && ifp->name && !strcmp(ifp->name, ifname))
			return object;
	}

	ni_error("%s: unknown network interface", ifname);
	return NULL;
}

/* Hack */
struct ni_dbus_dict_entry {
	/* key of the dict entry */
	const char *            key;

	/* datum associated with key */
	ni_dbus_variant_t       datum;
};

static void
__dump_fake_xml(const ni_dbus_variant_t *variant, unsigned int indent, const char **dict_elements)
{
	ni_dbus_dict_entry_t *entry;
	unsigned int index;

	if (ni_dbus_variant_is_dict(variant)) {
		const char *dict_element_tag = NULL;

		if (dict_elements && dict_elements[0])
			dict_element_tag = *dict_elements++;
		for (entry = variant->dict_array_value, index = 0; index < variant->array.len; ++index, ++entry) {
			const ni_dbus_variant_t *child = &entry->datum;
			const char *open_tag, *close_tag;
			char namebuf[256];

			if (dict_element_tag) {
				snprintf(namebuf, sizeof(namebuf), "%s name=\"%s\"", dict_element_tag, entry->key);
				open_tag = namebuf;
				close_tag = dict_element_tag;
			} else {
				open_tag = close_tag = entry->key;
			}

			if (child->type != DBUS_TYPE_ARRAY) {
				/* Must be some type of scalar */
				printf("%*.*s<%s>%s</%s>\n",
						indent, indent, "",
						open_tag,
						ni_dbus_variant_sprint(child),
						close_tag);
			} else if(child->array.len == 0) {
				printf("%*.*s<%s />\n", indent, indent, "", open_tag);
			} else if (ni_dbus_variant_is_byte_array(child)) {
				unsigned char value[64];
				unsigned int num_bytes;
				char display_buffer[128];
				const char *display;

				if (!ni_dbus_variant_get_byte_array_minmax(child, value, &num_bytes, 0, sizeof(value))) {
					display = "<INVALID />";
				} else {
					display = ni_format_hex(value, num_bytes, display_buffer, sizeof(display_buffer));
				}
				printf("%*.*s<%s>%s</%s>\n",
						indent, indent, "",
						open_tag,
						display,
						close_tag);
			} else {
				printf("%*.*s<%s>\n", indent, indent, "", open_tag);
				__dump_fake_xml(child, indent + 2, dict_elements);
				printf("%*.*s</%s>\n", indent, indent, "", close_tag);
			}
		}
	} else if (ni_dbus_variant_is_dict_array(variant)) {
		const ni_dbus_variant_t *child;

		for (child = variant->variant_array_value, index = 0; index < variant->array.len; ++index, ++child) {
			printf("%*.*s<e>\n", indent, indent, "");
			__dump_fake_xml(child, indent + 2, NULL);
			printf("%*.*s</e>\n", indent, indent, "");
		}
	} else {
		ni_trace("%s: %s", __func__, ni_dbus_variant_signature(variant));
	}
}

static xml_node_t *
__dump_object_xml(const char *object_path, const ni_dbus_variant_t *variant, ni_xs_scope_t *schema, xml_node_t *parent)
{
	xml_node_t *object_node;
	ni_dbus_dict_entry_t *entry;
	unsigned int index;

	if (!ni_dbus_variant_is_dict(variant)) {
		ni_error("%s: dbus data is not a dict", __func__);
		return NULL;
	}

	object_node = xml_node_new("object", parent);
	xml_node_add_attr(object_node, "path", object_path);

	for (entry = variant->dict_array_value, index = 0; index < variant->array.len; ++index, ++entry) {
		const char *interface_name = entry->key;

		/* Ignore well-known interfaces that never have properties */
		if (!strcmp(interface_name, "org.freedesktop.DBus.ObjectManager")
		 || !strcmp(interface_name, "org.freedesktop.DBus.Properties"))
			continue;

		ni_dbus_xml_deserialize_properties(schema, interface_name, &entry->datum, object_node);
	}

	return object_node;
}

static xml_node_t *
__dump_schema_xml(const ni_dbus_variant_t *variant, ni_xs_scope_t *schema)
{
	xml_node_t *root = xml_node_new(NULL, NULL);
	ni_dbus_dict_entry_t *entry;
	unsigned int index;

	if (!ni_dbus_variant_is_dict(variant)) {
		ni_error("%s: dbus data is not a dict", __func__);
		return NULL;
	}

	for (entry = variant->dict_array_value, index = 0; index < variant->array.len; ++index, ++entry) {
		if (!__dump_object_xml(entry->key, &entry->datum, schema, root))
			return NULL;
	}

	return root;
}


int
do_show_xml(int argc, char **argv)
{
	enum  { OPT_RAW, };
	static struct option local_options[] = {
		{ "raw", no_argument, NULL, OPT_RAW },
		{ NULL }
	};
	ni_dbus_object_t *iflist, *object;
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	const char *ifname = NULL;
	int opt_raw = 0;
	int c, rv = 1;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", local_options, NULL)) != EOF) {
		switch (c) {
		case OPT_RAW:
			opt_raw = 1;
			break;

		default:
		usage:
			fprintf(stderr,
				"wicked [options] show-xml [ifname]\n"
				"\nSupported options:\n"
				"  --raw\n"
				"      Show raw dbus reply in pseudo-xml, rather than using the schema\n"
				);
			return 1;
		}
	}

	if (optind < argc)
		ifname = argv[optind++];

	if (optind != argc)
		goto usage;

	if (!(object = ni_call_create_client()))
		return 1;

	if (!(iflist = wicked_get_interface_object(NULL)))
		goto out;

	if (!ni_dbus_object_call_variant(iflist,
			"org.freedesktop.DBus.ObjectManager", "GetManagedObjects",
			0, NULL,
			1, &result, &error)) {
		ni_error("GetManagedObject call failed");
		goto out;
	}

	if (opt_raw) {
		static const char *dict_element_tags[] = {
			"object", "interface", NULL
		};

		__dump_fake_xml(&result, 0, dict_element_tags);
	} else {
		ni_xs_scope_t *schema = ni_objectmodel_init(NULL);
		xml_node_t *tree;

		tree = __dump_schema_xml(&result, schema);
		if (tree == NULL) {
			ni_error("unable to represent properties as xml");
			goto out;
		}

		xml_node_print(tree, NULL);
		xml_node_free(tree);
	}

	rv = 0;

out:
	ni_dbus_variant_destroy(&result);
	return rv;
}

int
do_show(int argc, char **argv)
{
	ni_dbus_object_t *object;

	if (argc != 1 && argc != 2) {
		ni_error("wicked show: missing interface name");
		return 1;
	}

	if (!(object = ni_call_create_client()))
		return 1;

	if (argc == 1) {
		object = wicked_get_interface(object, NULL);
		if (!object)
			return 1;

		for (object = object->children; object; object = object->next) {
			ni_interface_t *ifp = object->handle;
			ni_address_t *ap;
			ni_route_t *rp;

			printf("%-12s %-10s %-10s",
					ifp->name,
					(ifp->link.ifflags & NI_IFF_NETWORK_UP)? "up" :
					 (ifp->link.ifflags & NI_IFF_LINK_UP)? "link-up" :
					  (ifp->link.ifflags & NI_IFF_DEVICE_UP)? "device-up" : "down",
					ni_linktype_type_to_name(ifp->link.type));
			printf("\n");

			for (ap = ifp->addrs; ap; ap = ap->next)
				printf("  addr:   %s/%u\n", ni_address_print(&ap->local_addr), ap->prefixlen);

			for (rp = ifp->routes; rp; rp = rp->next) {
				const ni_route_nexthop_t *nh;

				printf("  route: ");

				if (rp->prefixlen)
					printf(" %s/%u", ni_address_print(&rp->destination), rp->prefixlen);
				else
					printf(" default");

				if (rp->nh.gateway.ss_family != AF_UNSPEC) {
					for (nh = &rp->nh; nh; nh = nh->next)
						printf("; via %s", ni_address_print(&nh->gateway));
				}

				printf("\n");
			}
		}
	} else {
		const char *ifname = argv[1];

		object = wicked_get_interface(object, ifname);
		if (!object)
			return 1;
	}

	return 0;
}

int
do_delete(int argc, char **argv)
{
	const ni_dbus_service_t *interface;
	ni_dbus_object_t *object;
	const char *ifname;

	if (argc != 2) {
		ni_error("wicked delete: missing interface name");
		return 1;
	}
	ifname = argv[1];

	if (!(object = ni_call_create_client()))
		return 1;

	object = wicked_get_interface(object, ifname);
	if (!object)
		return 1;

	if (!(interface = ni_dbus_object_get_service_for_method(object, "deleteLink"))) {
		ni_error("%s: interface does not support deletion", ifname);
		return 1;
	}

	if (ni_dbus_object_call_simple(object,
				interface->name, "deleteLink",
				DBUS_TYPE_INVALID, NULL, DBUS_TYPE_INVALID, NULL) < 0) {
		ni_error("DBus delete call failed");
		return 1;
	}

	ni_debug_dbus("successfully deleted %s", ifname);
	return 0;
}

/*
 * Add a port to a bridge or bond
 * FIXME: currently broken
 */
int
do_addport(int argc, char **argv)
{
	const ni_dbus_service_t *interface;
	ni_dbus_variant_t argument[2], result;
	ni_dbus_object_t *root_object, *bridge, *port;
	const char *bridge_name, *port_name;
	DBusError error = DBUS_ERROR_INIT;
	int rv = 1;

	memset(argument, 0, sizeof(argument));
	memset(&result, 0, sizeof(result));

	if (argc < 3) {
		ni_error("wicked addport: usage: bridge-if port-if [options]");
		return 1;
	}

	bridge_name = argv[1];
	port_name = argv[2];

	if (!(root_object = ni_call_create_client()))
		return 1;

	if (!(bridge = wicked_get_interface(root_object, bridge_name))
	 || !(port = wicked_get_interface(root_object, port_name)))
		return 1;

	if (!(interface = ni_dbus_object_get_service_for_method(bridge, "addPort"))) {
		ni_error("%s: interface does not support adding ports", bridge_name);
		return 1;
	}
 
	ni_dbus_variant_set_string(&argument[0], port->path);

	ni_dbus_variant_init_dict(&argument[1]);
	if (argc == 3) {
		/* No properties, nothing to be done */
	} else {
		ni_interface_t *bridge_if = bridge->handle;
		const ni_dbus_service_t *port_interface;

		/* The "interface" for the ports is usually just a dummy type of
		 * interface; needed only to get the dbus types of all properties
		 */
		//port_interface = ni_objectmodel_interface_port_service(bridge_if->link.type);
		(void) bridge_if;
		port_interface = NULL;
		if (port_interface == NULL) {
			ni_error("%s: no port properties for this interface type", bridge_name);
			goto out;
		}

		if (!ni_call_properties_from_argv(port_interface, &argument[1], argc - 3, argv + 3)) {
			ni_error("Error parsing properties");
			goto out;
		}
	}

	if (!ni_dbus_object_call_variant(bridge, interface->name, "addPort",
				2, argument, 1, &result, &error)) {
		ni_error("Server refused to add port. Server responds:");
		ni_error_extra("%s: %s", error.name, error.message);
		goto out;
	}

	ni_debug_wicked("successfully added port %s to %s", port_name, bridge_name);
	rv = 0;

out:
	ni_dbus_variant_destroy(&argument[0]);
	ni_dbus_variant_destroy(&argument[1]);
	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return rv;
}

/*
 * Remove a port from a bridge or bond
 */
int
do_delport(int argc, char **argv)
{
	const ni_dbus_service_t *interface;
	ni_dbus_variant_t argument, result;
	ni_dbus_object_t *root_object, *bridge, *port;
	const char *bridge_name, *port_name;
	DBusError error = DBUS_ERROR_INIT;
	int rv = 1;

	memset(&argument, 0, sizeof(argument));
	memset(&result, 0, sizeof(result));

	if (argc != 3) {
		ni_error("wicked delport: usage: bridge-if port-if");
		return 1;
	}

	bridge_name = argv[1];
	port_name = argv[2];

	if (!(root_object = ni_call_create_client()))
		return 1;

	if (!(bridge = wicked_get_interface(root_object, bridge_name))
	 || !(port = wicked_get_interface(root_object, port_name)))
		return 1;

	if (!(interface = ni_dbus_object_get_service_for_method(bridge, "removePort"))) {
		ni_error("%s: interface does not support removing ports", bridge_name);
		return 1;
	}
 
	ni_dbus_variant_set_string(&argument, port->path);
	if (!ni_dbus_object_call_variant(bridge, interface->name, "removePort",
				1, &argument, 1, &result, &error)) {
		ni_error("Server refused to add port. Server responds:");
		ni_error_extra("%s: %s", error.name, error.message);
		goto out;
	}

	ni_debug_wicked("successfully removed port %s to %s", port_name, bridge_name);
	rv = 0;

out:
	ni_dbus_variant_destroy(&argument);
	ni_dbus_variant_destroy(&result);
	dbus_error_free(&error);
	return rv;
}

/*
 * xpath
 * This is a utility that can be used by network scripts to extracts bits and
 * pieces of information from an XML file.
 * This is still a bit inconvenient, especially if you need to extract more than
 * one of two elements, since we have to parse and reparse the XML file every
 * time you invoke this program.
 * On the other hand, there's a few rather nifty things you can do. For instance,
 * the following will extract addres/prefixlen pairs for every IPv4 address
 * listed in an XML network config:
 *
 * wicked xpath \
 *	--reference "interface/protocol[@family = 'ipv4']/ip" \
 *	--file vlan.xml \
 *	'%{@address}/%{@prefix}'
 *
 * The "reference" argument tells wicked to look up the <protocol>
 * element with a "family" attribute of "ipv4", and within that,
 * any <ip> elements. For each of these, it obtains the address
 * and prefix attribute, and prints it separated by a slash.
 */
int
do_xpath(int argc, char **argv)
{
	static struct option xpath_options[] = {
		{ "reference", required_argument, NULL, 'r' },
		{ "file", required_argument, NULL, 'f' },
		{ NULL }
	};
	const char *opt_reference = NULL, *opt_file = "-";
	xpath_result_t *input;
	xml_document_t *doc;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", xpath_options, NULL)) != EOF) {
		switch (c) {
		case 'r':
			opt_reference = optarg;
			break;

		case 'f':
			opt_file = optarg;
			break;

		default:
			fprintf(stderr,
				"wicked [options] xpath [--reference <expr>] [--file <path>] expr ...\n");
			return 1;
		}
	}

	doc = xml_document_read(opt_file);
	if (!doc) {
		fprintf(stderr, "Error parsing XML document %s\n", opt_file);
		return 1;
	}

	if (opt_reference) {
		xpath_enode_t *enode;

		enode = xpath_expression_parse(opt_reference);
		if (!enode) {
			fprintf(stderr, "Error parsing XPATH expression %s\n", opt_reference);
			return 1;
		}

		input = xpath_expression_eval(enode, doc->root);
		if (!input) {
			fprintf(stderr, "Error evaluating XPATH expression\n");
			return 1;
		}

		if (input->type != XPATH_ELEMENT) {
			fprintf(stderr, "Failed to look up reference node - returned non-element result\n");
			return 1;
		}
		if (input->count == 0) {
			fprintf(stderr, "Failed to look up reference node - returned empty list\n");
			return 1;
		}
		xpath_expression_free(enode);
	} else {
		input = xpath_result_new(XPATH_ELEMENT);
		xpath_result_append_element(input, doc->root);
	}

	while (optind < argc) {
		const char *expression = argv[optind++];
		ni_string_array_t result;
		xpath_format_t *format;
		unsigned int n;

		format = xpath_format_parse(expression);
		if (!format) {
			fprintf(stderr, "Error parsing XPATH format string %s\n", expression);
			return 1;
		}

		ni_string_array_init(&result);
		for (n = 0; n < input->count; ++n) {
			xml_node_t *refnode = input->node[n].value.node;

			if (!xpath_format_eval(format, refnode, &result)) {
				fprintf(stderr, "Error evaluating XPATH expression\n");
				ni_string_array_destroy(&result);
				return 1;
			}
		}

		for (n = 0; n < result.count; ++n)
			printf("%s\n", result.data[n]);

		ni_string_array_destroy(&result);
		xpath_format_free(format);
	}

	return 0;
}
