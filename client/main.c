/*
 *	This command line utility provides an interface to the network
 *	configuration/information facilities.
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Olaf Kirch <okir@suse.de>
 *		Karol Mroz <kmroz@suse.com>
 *		Olaf Hering <ohering@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <mcheck.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/route.h>
#include <wicked/resolver.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus-errors.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>

#include "client/wicked-client.h"
#include "ifup.h"
#include "ifdown.h"
#include "ifcheck.h"
#include "ifreload.h"
#include "ifstatus.h"
#include "main.h"

enum {
	OPT_HELP,
	OPT_VERSION,
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_LOG_LEVEL,
	OPT_LOG_TARGET,
	OPT_SYSTEMD,

	OPT_DRYRUN,
	OPT_ROOTDIR,
	OPT_LINK_TIMEOUT,
};

static struct option	options[] = {
	/* common */
	{ "help",		no_argument,		NULL,	OPT_HELP },
	{ "version",		no_argument,		NULL,	OPT_VERSION },
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "log-level",		required_argument,	NULL,	OPT_LOG_LEVEL },
	{ "log-target",		required_argument,	NULL,	OPT_LOG_TARGET },
	{ "systemd", 		no_argument,		NULL,	OPT_SYSTEMD },

	/* specific */
	{ "dryrun",		no_argument,		NULL,	OPT_DRYRUN },
	{ "dry-run",		no_argument,		NULL,	OPT_DRYRUN },
	{ "root-directory",	required_argument,	NULL,	OPT_ROOTDIR },

	{ NULL }
};

static const char *	opt_log_target;
int			opt_global_dryrun;
char *			opt_global_rootdir;
ni_bool_t		opt_systemd;

unsigned int ni_wait_for_interfaces;

static int		do_show_xml(int, char **);
static int		do_show_config(int, char **, const char *);
extern int		do_nanny(int, char **);
extern int		do_lease(int, char **);
extern int		do_check(int, char **);
static int		do_xpath(int, char **);
static int		do_get_names(int, char **);
static int		do_convert(int, char **);

static void
show_exec_info(int argc, char **argv)
{
	ni_stringbuf_t args = NI_STRINGBUF_INIT_DYNAMIC;
	int i;

	for (i = 0; i < argc && argv[i]; ++i) {
		if (i != 0)
			ni_stringbuf_putc(&args, ' ');
		ni_stringbuf_puts(&args, argv[i]);
	}

	ni_debug_application("Executing: %s", args.string);
	ni_stringbuf_destroy(&args);
}

int
main(int argc, char **argv)
{
	int c, status = NI_WICKED_RC_USAGE;
	const char *program;
	const char *cmd;

	mtrace();

	ni_log_init();
	program = ni_basename(argv[0]);

	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		case OPT_HELP:
			status = NI_WICKED_ST_OK;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"%s [options] <command> ...\n"
				"\n"
				"Options:\n"
				"  --help\n"
				"  --version\n"
				"  --config filename\n"
				"        Use alternative configuration file.\n"
				"  --log-target target\n"
				"        Set log destination to <stderr|syslog>.\n"
				"  --log-level level\n"
				"        Set log level to <error|warning|notice|info|debug>.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
				"        Use '--debug help' for a list of facilities.\n"
				"  --dry-run\n"
				"        Do not change the system in any way.\n"
				"  --root-directory\n"
				"        Search all config files below this directory.\n"
				"  --systemd\n"
				"        Enables behavior required by systemd service\n"
				"\n"
				"Commands:\n"
				"  ifup        [options] <ifname ...>|all\n"
				"  ifdown      [options] <ifname ...>|all\n"
				"  ifcheck     [options] <ifname ...>|all\n"
				"  ifreload    [options] <ifname ...>|all\n"
				"  ifstatus    [options] <ifname ...>|all\n"
				"  show        [options] <ifname ...>|all\n"
				"  show-xml    [options]\n"
				"  show-config [options]\n"
				"  convert     [options]\n"
				"  getnames    [options]\n"
				"  xpath       [options] expr ...\n"
				"  ethtool     [options] <ifname> <...>\n"
				"  nanny       <action> ...\n"
				"  lease       <action> ...\n"
				"  check       <action> ...\n"
				"  test        <action> ...\n"
				"  iaid        <action> ...\n"
				"  duid        <action> ...\n"
				"  arp         <action> ...\n"
				"\n"
				, program);
			goto done;

		case OPT_VERSION:
			printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
			status  = NI_WICKED_RC_SUCCESS;
			goto done;

		case OPT_CONFIGFILE:
			if (!ni_set_global_config_path(optarg)) {
				fprintf(stderr, "Unable to set config file '%s': %m\n", optarg);
				status = NI_WICKED_RC_ERROR;
				goto done;
			}
			break;

		case OPT_DEBUG:
			if (!strcmp(optarg, "help")) {
				printf("Supported debug facilities:\n");
				ni_debug_help();
				status = NI_WICKED_RC_SUCCESS;
				goto done;
			}
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				goto usage;
			}
			break;

		case OPT_LOG_TARGET:
			opt_log_target = optarg;
			break;

		case OPT_LOG_LEVEL:
			if (!ni_log_level_set(optarg)) {
				fprintf(stderr, "Bad log level \%s\"\n", optarg);
				goto usage;
			}
			break;

		case OPT_DRYRUN:
			opt_global_dryrun = 1;
			break;

		case OPT_ROOTDIR:
			if (!ni_realpath(optarg, &opt_global_rootdir)) {
				fprintf(stderr, "Invalid root-directory path '%s': %m\n", optarg);
				status = NI_WICKED_RC_ERROR;
				goto done;
			}
			if (ni_string_eq(opt_global_rootdir, "/"))
				ni_string_free(&opt_global_rootdir);
			break;

		case OPT_SYSTEMD:
			opt_systemd = TRUE;
			break;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing command\n");
		goto usage;
	}

	if (opt_log_target) {
		if (!ni_log_destination(program, opt_log_target)) {
			fprintf(stderr, "Bad log destination \%s\"\n",
				opt_log_target);
			goto usage;
		}
	}
	else if (opt_systemd || getppid() == 1) { /* syslog only */
		ni_log_destination(program, "syslog:user");
	}
	else { /* syslog + stderr */
		ni_log_destination(program, "syslog:user:perror");
	}

	if (ni_init("client") < 0) {
		status = NI_WICKED_RC_ERROR;
		goto done;
	}

	cmd = argv[optind];
	if (!strcmp(cmd, "help")) {
		goto usage;
	}

	show_exec_info(argc, argv);

	if (!strcmp(cmd, "ifup")) {
		status = ni_do_ifup(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "ifdown")) {
		status = ni_do_ifdown(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "ifcheck")) {
		status = ni_do_ifcheck(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "ifreload")) {
		status = ni_do_ifreload(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "ifstatus")) {
		status = ni_do_ifstatus(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "show")) {
		status = ni_do_ifstatus(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "show-xml")) {
		status = do_show_xml(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "show-config")) {
		status = do_show_config(argc - optind, argv + optind, NULL);
	} else
	if (!strcmp(cmd, "nanny")) {
		status = do_nanny(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "xpath")) {
		status = do_xpath(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "lease")) {
		status = do_lease(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "check")) {
		status = do_check(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "getnames")) {
		status = do_get_names(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "convert")) {
		status = do_convert(argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "duid")) {
		status = ni_do_duid(program, argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "iaid")) {
		status = ni_do_iaid(program, argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "test")) {
		status = ni_do_test(program, argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "arp")) {
		status = ni_do_arp(program, argc - optind, argv + optind);
	} else
	if (!strcmp(cmd, "ethtool")) {
		status = ni_do_ethtool(program, argc - optind, argv + optind);
	} else {
		fprintf(stderr, "Unsupported command %s\n", cmd);
		goto usage;
	}

done:
	ni_debug_application("Exit with status: %d", status);
	ni_string_free(&opt_global_rootdir);
	return status;
}

/*
 * Get the dbus object for a list of interfaces.
 */
static ni_dbus_object_t *
get_netif_list_object(void)
{
	static ni_dbus_object_t *interfaces = NULL;

	if (interfaces == NULL) {
		if (!(interfaces = ni_call_get_netif_list_object()))
			return NULL;

		/* Call ObjectManager.GetManagedObjects to get list of objects and their properties */
		if (!ni_dbus_object_refresh_children(interfaces)) {
			ni_error("Couldn't get list of active network interfaces");
			return NULL;
		}
	}

	return interfaces;
}

/*
 * Look up the dbus object for an interface by name.
 * The name can be either a kernel interface device name such as eth0,
 * or a dbus object path such as /org/opensuse/Network/Interfaces/5
 */
static ni_dbus_object_t *
get_netif_object(const char *ifname)
{
	ni_dbus_object_t *list_object, *object;

	if (!(list_object = get_netif_list_object()))
		return NULL;

	/* Loop over all interfaces and find the one with matching name */
	for (object = list_object->children; object; object = object->next) {
		if (ifname[0] == '/') {
			if (ni_string_eq(object->path, ifname))
				return object;
		} else {
			ni_netdev_t *dev = ni_objectmodel_unwrap_netif(object, NULL);

			if (dev && dev->name && !strcmp(dev->name, ifname))
				return object;
		}
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

static void	__dump_fake_xml(const ni_dbus_variant_t *, unsigned int, const char **);

static const char *
__fake_dbus_scalar_type(unsigned int type)
{
	static ni_intmap_t	__fake_dbus_types[] = {
		{ "byte",		DBUS_TYPE_BYTE		},
		{ "boolean",		DBUS_TYPE_BOOLEAN	},
		{ "int16",		DBUS_TYPE_INT16		},
		{ "uint16",		DBUS_TYPE_UINT16	},
		{ "int32",		DBUS_TYPE_INT32		},
		{ "uint32",		DBUS_TYPE_UINT32	},
		{ "int64",		DBUS_TYPE_INT64		},
		{ "uint64",		DBUS_TYPE_UINT64	},
		{ "double",		DBUS_TYPE_DOUBLE	},
		{ "string",		DBUS_TYPE_STRING	},
		{ "object-path",	DBUS_TYPE_OBJECT_PATH	},
		{ NULL },
	};

	return ni_format_uint_mapped(type, __fake_dbus_types);
}

static void
__dump_fake_xml_element(const ni_dbus_variant_t *var, unsigned int indent,
				const char *open_tag, const char *close_tag,
				const char **dict_elements)
{
	if (var->type == DBUS_TYPE_STRUCT) {
		unsigned int i;

		/* Must be a struct or union */
		printf("%*.*s<%s>\n", indent, indent, "", open_tag);
		for (i = 0; i < var->array.len; ++i) {
			ni_dbus_variant_t *member = &var->struct_value[i];
			char open_tag_buf[128], *member_open_tag;
			const char *basic_type;

			basic_type = __fake_dbus_scalar_type(member->type);
			if (basic_type == NULL) {
				member_open_tag = "member";
			} else {
				snprintf(open_tag_buf, sizeof(open_tag_buf), "member type=\"%s\"", basic_type);
				member_open_tag = open_tag_buf;
			}

			__dump_fake_xml_element(member, indent + 2, member_open_tag, "member", NULL);
		}
		printf("%*.*s</%s>\n", indent, indent, "", close_tag);
	} else
	if (var->type != DBUS_TYPE_ARRAY) {
		/* Must be some type of scalar */
		printf("%*.*s<%s>%s</%s>\n",
				indent, indent, "",
				open_tag,
				ni_dbus_variant_sprint(var),
				close_tag);
	} else if(var->array.len == 0) {
		printf("%*.*s<%s />\n", indent, indent, "", open_tag);
	} else if (ni_dbus_variant_is_byte_array(var)) {
		unsigned char value[64];
		unsigned int num_bytes;
		char display_buffer[128];
		const char *display;

		if (!ni_dbus_variant_get_byte_array_minmax(var, value, &num_bytes, 0, sizeof(value))) {
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
		__dump_fake_xml(var, indent + 2, dict_elements);
		printf("%*.*s</%s>\n", indent, indent, "", close_tag);
	}
}

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

			__dump_fake_xml_element(child, indent, open_tag, close_tag, dict_elements);
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

static ni_bool_t
__dump_object_xml(const char *object_path, const ni_dbus_variant_t *variant,
	ni_xs_scope_t *schema, xml_node_t *parent, const ni_string_array_t *filter)
{
	xml_node_t *object_node;
	ni_dbus_dict_entry_t *entry;
	unsigned int index;
	const char *ifname, *interface_name;

	if (!ni_dbus_variant_is_dict(variant)) {
		ni_error("%s: dbus data is not a dict", __func__);
		return FALSE;
	}

	object_node = xml_node_new("object", NULL);
	xml_node_add_attr(object_node, "path", object_path);

	if (filter && !filter->count)
		filter = NULL;

	for (entry = variant->dict_array_value, index = 0; index < variant->array.len; ++index, ++entry) {
		interface_name = entry->key;
		if (filter
		 && ni_string_eq(interface_name, NI_OBJECTMODEL_NETIF_INTERFACE)
		 && ni_dbus_dict_get_string(&entry->datum, "name", &ifname)
		 && ni_string_array_index(filter, ifname) == -1) {
			xml_node_free(object_node);
			return TRUE;
		}

		/* Ignore well-known interfaces that never have properties */
		if (!ni_string_startswith(interface_name, NI_OBJECTMODEL_NAMESPACE))
			continue;

		ni_dbus_xml_deserialize_properties(schema, interface_name, &entry->datum, object_node);
	}

	if (object_node->children)
		xml_node_add_child(parent, object_node);
	else
		xml_node_free(object_node);
	return TRUE;
}

static xml_node_t *
__dump_schema_xml(const ni_dbus_variant_t *variant, ni_xs_scope_t *schema, const ni_string_array_t *filter)
{
	xml_node_t *root = xml_node_new(NULL, NULL);
	ni_dbus_dict_entry_t *entry;
	unsigned int index;

	if (!ni_dbus_variant_is_dict(variant)) {
		ni_error("%s: dbus data is not a dict", __func__);
		xml_node_free(root);
		return NULL;
	}

	for (entry = variant->dict_array_value, index = 0; index < variant->array.len; ++index, ++entry) {
		if (!__dump_object_xml(entry->key, &entry->datum, schema, root, filter)) {
			xml_node_free(root);
			return NULL;
		}
	}

	return root;
}

int
do_show_xml(int argc, char **argv)
{
	enum {
		OPT_HELP,
		OPT_RAW,
#ifdef MODEM
		OPT_MODEMS,
#endif
	};
	static struct option local_options[] = {
		{ "help", no_argument, NULL, OPT_HELP },
		{ "raw", no_argument, NULL, OPT_RAW },
#ifdef MODEM
		{ "modem", no_argument, NULL, OPT_MODEMS },
#endif
		{ NULL }
	};
	ni_dbus_object_t *list_object, *object;
	ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
	DBusError error = DBUS_ERROR_INIT;
	int opt_raw = FALSE;
#ifdef MODEM
	int opt_modems = 0;
#endif
	int c, rv = 1;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", local_options, NULL)) != EOF) {
		switch (c) {
		case OPT_RAW:
			opt_raw = TRUE;
			break;

#ifdef MODEM
		case OPT_MODEMS:
			opt_modems = 1;
			break;
#endif

		default:
		case OPT_HELP:
		usage:
			fprintf(stderr,
				"wicked show-xml [options] [ifname ... |all]\n"
				"\n"
				"Supported options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --raw\n"
				"      Show raw dbus reply in pseudo-xml, rather than using the schema.\n"
				"      This option effectively disables the ifname filter. \n"
#ifdef MODEM
				"  --modem\n"
				"      List Modems\n"
#endif
				);
			return 1;
		}
	}

	if (opt_raw && optind != argc)
		goto usage;

	/* warning: this is a shallow-copy from argv,
	 * use this only with _index() for filtering */
	ifnames.count = argc - optind;
	ifnames.data = argv + optind;
	if (ni_string_array_index(&ifnames, "all") != -1) {
		ifnames.count = 0;
		ifnames.data = NULL;
	}

	if (!(object = ni_call_create_client()))
		return 1;
#ifdef MODEM
	if (!opt_modems) {
#endif
		if (!(list_object = ni_call_get_netif_list_object()))
			goto out;
#ifdef MODEM
	} else {
		if (!(list_object = ni_call_get_modem_list_object()))
			goto out;
	}
#endif

	if (!ni_dbus_object_call_variant(list_object,
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

		tree = __dump_schema_xml(&result, schema, &ifnames);
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
do_show_config(int argc, char **argv, const char *root_schema)
{
	enum { OPT_HELP, OPT_RAW, OPT_OUTPUT };
	static struct option options[] = {
		{ "help",	no_argument, NULL, OPT_HELP },
		{ "raw",	no_argument, NULL, OPT_RAW},
		{ "output",     required_argument, NULL, OPT_OUTPUT },
		{ NULL }
	};

	xml_document_array_t docs = XML_DOCUMENT_ARRAY_INIT;
	ni_bool_t opt_raw = FALSE;
	const char *opt_output = NULL;
	unsigned i;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", options, NULL)) != EOF) {
		switch (c) {
		case OPT_RAW:
			opt_raw = TRUE;
			break;

		case OPT_OUTPUT:
			opt_output = optarg;
			break;

		default:
		case OPT_HELP:
			fprintf(stderr,
				"wicked [options] show-config [options] [SOURCE...]\n"
				"Where SOURCE is one of the following:\n"
				"\t'firmware:'\n"
				"\t'compat:'\n"
				"\t'wicked:[PATH]'\n"
				"\tPATH - to the specific file or dir\n"
				"\n"
				"\nSupported options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --raw\n"
				"      Do not display <client-state> tags\n"
				"  --output <path>\n"
				"      Specify output file\n"
				);
			return 1;
		}
	}

	if (optind == argc) {
		/* Print all */
		const ni_string_array_t *cs_array = ni_config_sources("ifconfig");
		ni_assert(cs_array);

		for (i = 0; i < cs_array->count; i++) {
			if (!root_schema || !strcmp(root_schema, cs_array->data[i])) {
				if (!ni_ifconfig_read(&docs, opt_global_rootdir,
				    cs_array->data[i], FALSE, opt_raw)) {
					ni_error("Unable to read config source %s",
						cs_array->data[i]);
					return 1;
				}
			}
		}
	}
	else {
		while(optind < argc) {
			char *path = NULL;
			if (!root_schema)
				path = argv[optind++];
			else
				ni_string_printf(&path, "%s%s", root_schema, argv[optind++]);

			if (!ni_ifconfig_read(&docs, opt_global_rootdir,
			    path, FALSE, opt_raw)) {
				ni_error("Unable to read config source %s", path);
				return 1;
			}

			if (root_schema)
				ni_string_free(&path);
		}
	}

	if (opt_output == NULL) {
		for (i = 0; i < docs.count; i++)
			xml_node_print(docs.data[i]->root, stdout);
	}
	else if (ni_isdir(opt_output)) {
		for (i = 0; i < docs.count; i++) {
			xml_document_t *result = docs.data[i];
			unsigned int seq = 0;
			xml_node_t *ifnode;

			/* Write resulting XML document as a bunch of files, one per interface */
			for (ifnode = result->root->children; ifnode; ifnode = ifnode->next) {
				char pathbuf[4096];
				xml_node_t *namenode;
				const char *ifname;
				FILE *fp;

				namenode = xml_node_get_child(ifnode, "name");
				if (!namenode) {
					/* FIXME: add config source location */
					ni_error("Config file %s does not contain <name> node", "");
					break;
				}

				if ((ifname = namenode->cdata) != NULL) {
					snprintf(pathbuf, sizeof(pathbuf), "%s/%s.xml", opt_output, ifname);
				} else {
					const char *ns;

					if (!(ns = xml_node_get_attr(namenode, "namespace"))) {
						/* FIXME: add config source location */
						ni_error("Interface node in config file %s has"
							"invalid <name> element", "");
						break;
					}
					snprintf(pathbuf, sizeof(pathbuf), "%s/id-%s-%u.xml",
							opt_output, ns, seq++);
				}

				if ((fp = fopen(pathbuf, "w")) == NULL)
					ni_fatal("unable to open %s for writing: %m", pathbuf);

				xml_node_print(ifnode, fp);
				fclose(fp);
			}
		}
	}
	else {
		FILE *fp;

		if ((fp = fopen(opt_output, "w")) == NULL)
			ni_fatal("unable to open %s for writing: %m", opt_output);

		for (i = 0; i < docs.count; i++)
			xml_node_print(docs.data[i]->root, fp);
		fclose(fp);
	}

	xml_document_array_destroy(&docs);
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
	enum { OPT_HELP, OPT_REFERENCE, OPT_FILE };
	static struct option xpath_options[] = {
		{ "help", no_argument, NULL, OPT_HELP },
		{ "reference", required_argument, NULL, OPT_REFERENCE },
		{ "file", required_argument, NULL, OPT_FILE },
		{ NULL }
	};
	const char *opt_reference = NULL, *opt_file = "-";
	xpath_result_t *input;
	xml_document_t *doc;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", xpath_options, NULL)) != EOF) {
		switch (c) {
		case OPT_REFERENCE:
			opt_reference = optarg;
			break;

		case OPT_FILE:
			opt_file = optarg;
			break;

		case OPT_HELP:
		default:
usage:
			fprintf(stderr,
				"wicked [options] xpath [--reference <expr>] [--file <path>] expr ...\n");
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing expression\n");
		goto usage;
	}

	/* FIXME:
		An invalid expression blocks the command to return in a read()
		call. Need a further check to validate given expression in
		first place and return with an error if garbage is provided.
	*/

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

/*
 * Helper function for do_lease()
 */
static xml_document_t *
__get_lease_document(const char *pathname)
{
	xml_document_t *doc;

	if (!ni_file_exists(pathname)) {
		ni_error("%s: document does not exist, you need to create it with \"lease new\" first", pathname);
		return NULL;
	}

	doc = xml_document_read(pathname);
	if (!doc) {
		ni_error("unable to parse XML document %s", pathname);
		return NULL;
	}

	return doc;
}

static xml_node_t *
__get_lease_xml_root(xml_document_t *doc)
{
	return xml_node_new_element_unique("lease", doc->root, NULL);
}

static xml_node_t *
__get_lease_xml_node_maybe_zap(xml_document_t *doc, const char *name, const char *cmd)
{
	xml_node_t *node;

	/* This function is used to obtain the <addresses> or <routes>
	 * elements of the lease xml.
	 * IFF cmd starts with "set", we clear the list, otherwise we return
	 * what is already there.
	 */
	node = __get_lease_xml_root(doc);
	if (!strncmp(cmd, "set", 3))
		xml_node_delete_child(node, name);

	return xml_node_new_element_unique(name, node, NULL);
}

static xml_node_t *
__get_lease_xml_list_maybe_zap(xml_document_t *doc, const char *name, const char *cmd)
{
	xml_node_t *list;

	list = __get_lease_xml_node_maybe_zap(doc, name, cmd);
	return xml_node_new("e", list);
}

static ni_bool_t
__validate_address(const char *addrstring, int af, const char *subcmd)
{
	ni_sockaddr_t tmp_addr;

	if (ni_sockaddr_parse(&tmp_addr, addrstring, af) < 0) {
		ni_error("cannot parse %s \"%s\"", subcmd, addrstring);
		return FALSE;
	}

	return TRUE;
}

static ni_bool_t
__validate_netmask(const char *addrstring, int af, const char *subcmd, unsigned int *prefixlen_p)
{
	ni_sockaddr_t tmp_addr;

	if (ni_sockaddr_parse(&tmp_addr, addrstring, af) < 0) {
		ni_error("cannot parse %s \"%s\"", subcmd, addrstring);
		return FALSE;
	}

	*prefixlen_p = ni_sockaddr_netmask_bits(&tmp_addr);
	return TRUE;
}


/*
 * Script extensions or external network facilities trying to integrate with wicked
 * may wish to notify wicked about addresses, routes or other settings that they
 * have learned about, and wish to have activated.
 *
 * For instance, this can be used from the PPP ifup/ifdown scripts to
 * inform wicked about a lease that has been granted.
 *
 * Usually, the way you use this goes like this:
 *
 * lf=/var/run/whatever/mylease.xml
 * netif=ppp0
 *
 * wicked lease $lf new family ipv4 state granted hostname my.funky.hostname.org
 * wicked lease $lf add-address 192.168.7.8 netmask 255.255.255.248
 * wicked lease $lf add-route 0/0 gateway 192.168.7.1
 * wicked lease $lf set-resolver default-domain funky.hostname.org server 192.168.1.1 server 192.168.8.1
 * wicked lease $lf install --device $netif
 * rm -f $lf
 *
 * Note, it's up to you whether you actually ask wickedd to take care of the
 * addresses, or whether your external network service does this natively.
 * It's just as easy to just install a lease with eg resolver information.
 *
 * To revoke a lease when the link goes down:
 *
 * lf=/var/run/whatever/mylease.xml
 * netif=ppp0
 *
 * wicked lease $lf new family ipv4 state released
 * wicked lease $lf install --device $netif
 * rm -f $lf
 *
 */
int
do_lease(int argc, char **argv)
{
	const char *opt_file, *opt_cmd, *opt_subcmd;
	xml_document_t *doc;
	xml_node_t *lease_node;
	xml_node_t *type_node = NULL, *fmly_node = NULL;
	int c, ret = 1;

	if (argc <= 2)
		goto usage;
	opt_file = argv[1];
	opt_cmd = argv[2];

	if (!strcmp(opt_cmd, "new")) {
		doc = xml_document_new();

		type_node = xml_node_new("type", doc->root);
		fmly_node = xml_node_new("family", doc->root);

		lease_node = xml_node_new("lease", doc->root);
		/* xml_node_new_element("update", lease_node, "all"); */
	} else {
		if (!(doc = __get_lease_document(opt_file)))
			goto failed;
		lease_node = __get_lease_xml_root(doc);
	}

	optind = 3;
	if (!strcmp(opt_cmd, "new") || !strcmp(opt_cmd, "set")) {
		while (optind < argc) {
			const char *optarg;

			opt_subcmd = argv[optind++];
			if (optind >= argc) {
				ni_error("missing argument to command \"%s %s\"", opt_cmd, opt_subcmd);
				goto failed;
			}
			optarg = argv[optind++];

			if (type_node && !strcmp(opt_subcmd, "type")) {
				if (ni_addrconf_name_to_type(optarg) < 0) {
					ni_error("invalid lease type \"%s\"", optarg);
					goto failed;
				}
				xml_node_set_cdata(type_node, optarg);
			} else
			if (fmly_node && !strcmp(opt_subcmd, "family")) {
				if (ni_addrfamily_name_to_type(optarg) < 0) {
					ni_error("invalid address family \"%s\"", optarg);
					goto failed;
				}
				xml_node_set_cdata(fmly_node, optarg);
			} else
			if (!strcmp(opt_subcmd, "state")) {
				xml_node_new_element_unique("state", lease_node, optarg);
			} else
			if (!strcmp(opt_subcmd, "hostname")) {
				xml_node_new_element_unique("hostname", lease_node, optarg);
			} else
				goto unknown_subcommand;
		}

		if (type_node && type_node->cdata == NULL) {
			/* ni_warn("wicked lease new: no lease type specified, assuming \"intrinsic\""); */
			xml_node_set_cdata(type_node, "intrinsic");
		}
		if (fmly_node && fmly_node->cdata == NULL) {
			ni_warn("wicked lease new: no address family specified, assuming \"ipv4\"");
			xml_node_set_cdata(fmly_node, "ipv4");
		}

		ni_info("Writing lease info to %s", opt_file);
		xml_document_write(doc, opt_file);
	} else
	if (!strcmp(opt_cmd, "add-address")
	 || !strcmp(opt_cmd, "set-address")) {
		xml_node_t *e, *anode;
		char *opt_address;
		ni_sockaddr_t local_addr;
		unsigned int prefixlen;

		if (optind >= argc) {
			ni_error("missing address argument to command \"%s\"", opt_cmd);
			goto failed;
		}
		opt_address = argv[optind++];

		if (!ni_sockaddr_prefix_parse(opt_address, &local_addr, &prefixlen)) {
			ni_error("cannot parse interface address \"%s\"", opt_address);
			goto failed;
		}
		/* FIXME: consistency check - the parsed address should have the same AF as
		 * the lease we're editing. */

		e = __get_lease_xml_list_maybe_zap(doc, "addresses", opt_cmd);
		anode = xml_node_new_element("local", e, NULL);

		while (optind < argc) {
			const char *optarg;

			opt_subcmd = argv[optind++];
			if (optind >= argc) {
				ni_error("missing argument to command \"%s %s\"", opt_cmd, opt_subcmd);
				goto failed;
			}
			optarg = argv[optind++];

			if (!strcmp(opt_subcmd, "peer")) {
				if (!__validate_address(optarg, local_addr.ss_family, opt_subcmd))
					goto failed;
				xml_node_new_element("peer", e, optarg);
			} else
			if (!strcmp(opt_subcmd, "netmask")) {
				if (!__validate_netmask(optarg, local_addr.ss_family, opt_subcmd, &prefixlen))
					goto failed;
			} else
			if (!strcmp(opt_subcmd, "gateway")) {
				ni_warn("ignoring gateway option");
			} else
				goto unknown_subcommand;
		}

		/* Done parsing the command line. Now update the address node itself */
		xml_node_set_cdata(anode, ni_sockaddr_prefix_print(&local_addr, prefixlen));

		ni_info("Writing lease info to %s", opt_file);
		xml_document_write(doc, opt_file);
	} else
	if (!strcmp(opt_cmd, "add-route")
	 || !strcmp(opt_cmd, "set-route")) {
		xml_node_t *e, *rnode;
		char *opt_route;
		ni_sockaddr_t dest_addr;
		unsigned int prefixlen;

		if (optind >= argc) {
			ni_error("missing address argument to command \"%s\"", opt_cmd);
			goto failed;
		}
		opt_route = argv[optind++];

		if (!ni_sockaddr_prefix_parse(opt_route, &dest_addr, &prefixlen)) {
			ni_error("cannot parse route destination \"%s\"", opt_route);
			goto failed;
		}
		/* FIXME: consistency check - the parsed address should have the same AF as
		 * the lease we're editing. */

		e = __get_lease_xml_list_maybe_zap(doc, "routes", opt_cmd);
		rnode = xml_node_new_element("destination", e, NULL);

		while (optind < argc) {
			const char *optarg;

			opt_subcmd = argv[optind++];
			if (optind >= argc) {
				ni_error("missing argument to command \"%s %s\"", opt_cmd, opt_subcmd);
				goto failed;
			}
			optarg = argv[optind++];

			if (!strcmp(opt_subcmd, "netmask")) {
				if (!__validate_netmask(optarg, dest_addr.ss_family, opt_subcmd, &prefixlen))
					goto failed;
			} else
			if (!strcmp(opt_subcmd, "gateway")) {
				xml_node_t *nh = xml_node_new("nexthop", e);

				if (!__validate_address(optarg, dest_addr.ss_family, opt_subcmd))
					goto failed;
				xml_node_new_element("gateway", nh, optarg);
			} else
			if (!strcmp(opt_subcmd, "peer")) {
				ni_warn("ignoring peer option");
			} else
				goto unknown_subcommand;
		}

		/* Done parsing the command line. Now update the address node itself */
		xml_node_set_cdata(rnode, ni_sockaddr_prefix_print(&dest_addr, prefixlen));

		ni_info("Writing lease info to %s", opt_file);
		xml_document_write(doc, opt_file);
	} else
	if (!strcmp(opt_cmd, "add-resolver")
	 || !strcmp(opt_cmd, "set-resolver")) {
		xml_node_t *rnode;

		rnode = __get_lease_xml_node_maybe_zap(doc, "resolver", opt_cmd);

		while (optind < argc) {
			const char *optarg;

			opt_subcmd = argv[optind++];
			if (optind >= argc) {
				ni_error("missing argument to command \"%s %s\"", opt_cmd, opt_subcmd);
				goto failed;
			}
			optarg = argv[optind++];

			if (!strcmp(opt_subcmd, "default-domain")) {
				xml_node_new_element("default-domain", rnode, optarg);
			} else
			if (!strcmp(opt_subcmd, "server")) {
				xml_node_t *list;

				if (!__validate_address(optarg, AF_UNSPEC, opt_subcmd))
					goto failed;
				list = xml_node_new_element_unique("servers", rnode, NULL);
				xml_node_new_element("e", list, optarg);
			} else
			if (!strcmp(opt_subcmd, "search")) {
				xml_node_t *list;

				list = xml_node_new_element_unique("search", rnode, NULL);
				xml_node_new_element("e", list, optarg);
			} else
				goto unknown_subcommand;
		}

		ni_info("Writing lease info to %s", opt_file);
		xml_document_write(doc, opt_file);
	} else if (!strcmp(opt_cmd, "install")) {
		static struct option install_options[] = {
			{ "device", required_argument, NULL, 'd' },
			{ NULL }
		};
		char *opt_device = NULL;
		ni_dbus_object_t *obj;

		while ((c = getopt_long(argc, argv, "", install_options, NULL)) != EOF) {
			switch (c) {
			case 'd':
				opt_device = optarg;
				break;

			default:
				goto usage;
			}
		}

		if (opt_device == NULL) {
			ni_error("missing --device argument");
			goto usage;
		}

		if (doc->root == NULL) {
			ni_error("empty lease file");
			goto failed;
		}

		ni_objectmodel_init(NULL);

		obj = get_netif_object(opt_device);
		if (obj == NULL) {
			ni_error("no such device or object: %s", opt_device);
			goto failed;
		}

		if (ni_call_install_lease_xml(obj, doc->root) < 0) {
			ni_error("unable to install addrconf lease");
			goto failed;
		}
	} else if (!strcmp(opt_cmd, "help")) {
		ret = 0;
		goto usage;
	} else {
		ni_error("unsupported command wicked %s %s", argv[0], opt_cmd);
usage:
		fprintf(stderr,
			"Usage: wicked lease <filename> cmd ...\n"
			"Where cmd is one of the following:\n"
			"  --help\n"
			"  new [type <addrconf-type>] [family <address-family>]\n"
			"  set [hostname <hostname>] [state <addrconf-state>]\n"
			"  {set|add}-address <ipaddr>/prefixlen [netmask <ipmask>] [peer <ipaddr>]\n"
			"  {set|add}-route <ipaddr>/prefixlen [netmask <ipmask>] [gateway <ipaddr>]\n"
			"  {set|add}-resolver [default-domain <domain>] [server <ipaddr> ...] [search <domain> ...]\n"
			"  install --device <object-path>\n"
		       );
		return ret;
	}

	if (doc)
		xml_document_free(doc);
	return 0;

failed:
	if (doc)
		xml_document_free(doc);
	return 1;

unknown_subcommand:
	ni_error("unknown subcommand \"%s\" of command \"%s\"", opt_subcmd, opt_cmd);
	goto failed;
}

/*
 * Get list of <name> elements identifying a device
 */
int
do_get_names(int argc, char **argv)
{
	enum {
		OPT_HELP,
		OPT_XML,
#ifdef MODEM
		OPT_MODEMS,
#endif
	};
	static struct option local_options[] = {
		{ "help", no_argument, NULL, OPT_HELP },
		{ "xml", no_argument, NULL, OPT_XML },
#ifdef MODEM
		{ "modem", no_argument, NULL, OPT_MODEMS },
#endif
		{ NULL }
	};
	ni_dbus_object_t *list_object;
#ifdef MODEM
	int opt_modems = 0;
#endif
	int c, rv = 1;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", local_options, NULL)) != EOF) {
		switch (c) {
#ifdef MODEM
		case OPT_MODEMS:
			opt_modems = 1;
			break;
#endif

		default:
		case OPT_HELP:
		usage:
			fprintf(stderr,
				"wicked [options] getnames ifname ...\n"
				"\nSupported options:\n"
				"  --help\n"
				"      Show this help text.\n"
#ifdef MODEM
				"  --modems\n"
				"      Query for modem device, rather than network device\n"
#endif
				);
			return 1;
		}
	}

	ni_objectmodel_init(NULL);
#ifdef MODEM
	if (!opt_modems) {
#endif
		if (!(list_object = ni_call_get_netif_list_object()))
			goto out;
#ifdef MODEM
	} else {
		if (!(list_object = ni_call_get_modem_list_object()))
			goto out;
	}
#endif

	if (optind < argc) {
		DBusError error = DBUS_ERROR_INIT;

		while (optind < argc) {
			const char *ifname = argv[optind++];
			ni_dbus_variant_t result = NI_DBUS_VARIANT_INIT;
			ni_dbus_object_t *dev_object;
			xml_node_t *names;
			char *object_path;

			object_path = ni_call_device_by_name(list_object, ifname);
			if (object_path == NULL)
				continue;

			ni_trace("%s %s", ifname, object_path);
			dev_object = ni_dbus_object_create(list_object, object_path,
						ni_objectmodel_get_class(NI_OBJECTMODEL_NETIF_CLASS),
						NULL);

			if (!ni_dbus_object_call_variant(dev_object,
					NI_OBJECTMODEL_NETIF_INTERFACE, "getNames",
					0, NULL,
					1, &result, &error)) {
				ni_dbus_print_error(&error, "%s.getNames() failed", object_path);
				dbus_error_free(&error);
				goto out;
			}

			names = xml_node_new("names", NULL);
			xml_node_add_attr(names, "device", ifname);
			if (!ni_objectmodel_set_name_array(names, &result))
				ni_error("%s.getNames(): cannot parse response", object_path);
			else {
				xml_node_print(names, NULL);
			}

			xml_node_free(names);
			ni_dbus_variant_destroy(&result);
			ni_string_free(&object_path);
		}
	} else {
		ni_error("No interface name specified");
		goto usage;
	}

	rv = 0;

out:
	return rv;
}

/*
 * The check for routability is implemented as a simple
 * UDP connect, which should return immediately, since no
 * packets are sent over the wire (except for hostname
 * resolution).
 */
int
ni_host_is_reachable(const char *hostname, const ni_sockaddr_t *addr)
{
	int fd, rv = 1;

	fd = socket(addr->ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		ni_debug_objectmodel("%s: unable to open %s socket", hostname,
				ni_addrfamily_type_to_name(addr->ss_family));
		return -1;
	}

	if (connect(fd, (struct sockaddr *) addr, sizeof(*addr)) < 0) {
		ni_debug_objectmodel("cannot connect to %s: %m", hostname);
		rv = 0;
	}

	close(fd);
	return rv;
}

/*
 * Check for various conditions, such as resolvability and reachability.
 */
static void		write_dbus_error(const char *filename, const char *name, const char *fmt, ...);

int
do_check(int argc, char **argv)
{
	enum { OPT_HELP, OPT_TIMEOUT, OPT_AF, OPT_WRITE_DBUS_ERROR };
	static struct option options[] = {
		{ "help", no_argument, NULL, OPT_HELP },
		{ "timeout", required_argument, NULL, OPT_TIMEOUT },
		{ "af", required_argument, NULL, OPT_AF },
		{ "write-dbus-error", required_argument, NULL, OPT_WRITE_DBUS_ERROR },
		{ NULL }
	};
	const char *opt_cmd;
	const char *opt_dbus_error_file = NULL;
	unsigned int opt_timeout = 2;
	int opt_af = AF_UNSPEC;
	int c;

	if (argc < 2) {
		ni_error("wicked check: missing arguments");
		goto usage;
	}
	opt_cmd = argv[1];

	optind = 2;
	while ((c = getopt_long(argc, argv, "", options, NULL)) != EOF) {
		switch (c) {
		case OPT_TIMEOUT:
			if (ni_parse_uint(optarg, &opt_timeout, 10) < 0)
				ni_fatal("cannot parse timeout value \"%s\"", optarg);
			break;

		case OPT_AF:
			opt_af = ni_addrfamily_name_to_type(optarg);
			if (opt_af < 0)
				ni_fatal("unknown address family \"%s\"", optarg);
			break;

		case OPT_WRITE_DBUS_ERROR:
			opt_dbus_error_file = optarg;
			break;

		default:
		case OPT_HELP:
			goto usage;
		}
	}

	if (ni_string_eq(opt_cmd, "resolve") || ni_string_eq(opt_cmd, "route")) {
		ni_sockaddr_t *address;
		unsigned int i, nreqs;
		int failed = 0;

		nreqs = argc - optind;
		if (nreqs == 0)
			return 0;

		address = calloc(nreqs, sizeof(ni_sockaddr_t));

		if (ni_resolve_hostnames_timed(opt_af, nreqs, (const char **) &argv[optind], address, opt_timeout) < 0) {
			free(address);
			return 1;
		}

		for (i = 0; i < nreqs; ++i) {
			const char *hostname = argv[optind + i];
			ni_sockaddr_t *addr = &address[i];

			if (addr->ss_family == AF_UNSPEC) {
				failed++;
				if (opt_dbus_error_file) {
					write_dbus_error(opt_dbus_error_file,
							NI_DBUS_ERROR_UNRESOLVABLE_HOSTNAME,
							hostname);
					opt_dbus_error_file = NULL;
				}
				continue;
			}

			if (ni_string_eq(opt_cmd, "resolve")) {
				printf("%s %s\n", hostname, ni_sockaddr_print(addr));
				continue;
			}

			if (ni_string_eq(opt_cmd, "route")) {
				switch (ni_host_is_reachable(hostname, addr)) {
				case 1:
					printf("%s %s reachable\n", hostname, ni_sockaddr_print(addr));
					break;

				case 0:
					if (opt_dbus_error_file) {
						write_dbus_error(opt_dbus_error_file,
								NI_DBUS_ERROR_UNREACHABLE_ADDRESS,
								hostname);
						opt_dbus_error_file = NULL;
					}
					/* fallthrough */

				default:
					ni_error("%s %s not reached", hostname, ni_sockaddr_print(addr));
					failed++;
				}

				continue;
			}
		}

		free(address);
	} else {
		ni_error("unsupported command wicked %s %s", argv[0], opt_cmd);
usage:
		fprintf(stderr,
			"Usage: wicked check <cmd> ...\n"
			"Where <cmd> is one of the following:\n"
			"  resolve [options ...] hostname ...\n"
			"  route [options ...] address ...\n"
			"\n"
			"Supported options:\n"
			"  --help\n"
			"      Show this help text.\n"
			"  --timeout n\n"
			"        Fail after n seconds.\n"
			"  --af <address-family>\n"
			"        Specify the address family (ipv4, ipv6, ...) to use when resolving hostnames.\n"
			"  --write-dbus-error <filename>\n"
			"        Write dbus error to <filename>.\n"
		       );
		return 1;
		;
	}

	return 0;
}

/*
 * Write a dbus error message as XML to a file
 */
void
write_dbus_error(const char *filename, const char *name, const char *fmt, ...)
{
	xml_document_t *doc;
	xml_node_t *node;
	char msgbuf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	doc = xml_document_new();
	node = xml_node_new("error", doc->root);
	xml_node_add_attr(node, "name", name);
	xml_node_set_cdata(node, msgbuf);

	if (xml_document_write(doc, filename) < 0)
		ni_fatal("failed to write xml error document");

	xml_document_free(doc);
}

/*
 * Read native sysconfig files and display resulting XML
 */
int
do_convert(int argc, char **argv)
{
	enum { OPT_HELP, OPT_RAW, OPT_OUTPUT };
	static struct option options[] = {
		{ "help",	no_argument, NULL, OPT_HELP },
		{ "raw",	no_argument, NULL, OPT_RAW},
		{ "output",     required_argument, NULL, OPT_OUTPUT },
		{ NULL }
	};

	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", options, NULL)) != EOF) {
		switch (c) {
		case OPT_RAW:
		case OPT_OUTPUT:
			break;
		default:
		case OPT_HELP:
			fprintf(stderr,
				"Usage: wicked convert [options] [path ...]\n"
				"\n"
				"This will parse one or more files/directories in legacy format,\n"
				"and render their content as XML.\n"
				"If no path is given, a format-specific default path is used.\n"
				"\n"
				"Supported options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"  --raw\n"
				"      Do not display <client-state> tags\n"
				"  --output <path>\n"
				"      Specify output file\n"
			       );
			return 0;
		}
	}

	return do_show_config(argc, argv, "compat:");
}
