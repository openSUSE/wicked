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

static int		do_show(int, char **);
static int		do_show_xml(int, char **);
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

	if (!strcmp(cmd, "show"))
		return do_show(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "show-xml"))
		return do_show_xml(argc - optind + 1, argv + optind - 1);

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

		netif_list_service = ni_objectmodel_service_by_name(NI_OBJECTMODEL_NETIFLIST_INTERFACE);
		ni_assert(netif_list_service);

		netif_list_class = netif_list_service->compatible;
	}

	child = ni_dbus_object_create(root_object, "Interface",
			netif_list_class,
			NULL);

	if (!default_interface)
		default_interface = NI_OBJECTMODEL_INTERFACE ".Interface";
	ni_dbus_object_set_default_interface(child, default_interface);

	return child;
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
	(void)ifname; /* FIXME; not used yet */

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
