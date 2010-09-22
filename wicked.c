/*
 * No REST for the wicked!
 *
 * This command line utility provides an interface to the network
 * configuration/information facilities.
 *
 * It uses a RESTful interface (even though it's a command line utility).
 * The idea is to make it easier to extend this to some smallish daemon
 * with a AF_LOCAL socket interface.
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */
#include <stdio.h>
#include <string.h>
#include <mcheck.h>
#include <stdlib.h>
#include <getopt.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/wicked.h>
#include <wicked/xml.h>
#include <wicked/xpath.h>

enum {
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_DRYRUN,
	OPT_ROOTDIR,
};

static struct option	options[] = {
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "dryrun",		no_argument,		NULL,	OPT_DRYRUN },
	{ "dry-run",		no_argument,		NULL,	OPT_DRYRUN },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "root-directory",	required_argument,	NULL,	OPT_ROOTDIR },

	{ NULL }
};

static int	opt_dryrun = 0;
static char *	opt_rootdir = NULL;

static int	do_rest(const char *, int, char **);
static int	do_xpath(int, char **);
static int	do_ifup(int, char **);
static int	do_ifdown(int, char **);

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

	if (ni_init() < 0)
		return 1;

	if (optind >= argc) {
		fprintf(stderr, "Missing command\n");
		goto usage;
	}

	cmd = argv[optind++];

	if (!strcmp(cmd, "xpath"))
		return do_xpath(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "ifup"))
		return do_ifup(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "ifdown"))
		return do_ifdown(argc - optind + 1, argv + optind - 1);

	if (!strcmp(cmd, "get")
	 || !strcmp(cmd, "put")
	 || !strcmp(cmd, "post")
	 || !strcmp(cmd, "delete"))
		return do_rest(cmd, argc - optind + 1, argv + optind - 1);

	fprintf(stderr, "Unsupported command %s\n", cmd);
	goto usage;
}

static int
__wicked_request(int rest_op, const char *path,
		/* const */ xml_node_t *send_xml,
		xml_node_t **recv_xml)
{
	ni_wicked_request_t req;
	int rv;

	if (opt_dryrun && rest_op != NI_REST_OP_GET) {
		printf("Would send request %s %s\n",
				ni_wicked_rest_op_print(rest_op), path);
		if (send_xml)
			xml_node_print(send_xml, stdout);
		return 0;
	}

	ni_wicked_request_init(&req);
	req.cmd = rest_op;
	req.path = strdup(path);
	req.xml_in = send_xml;

	if (opt_rootdir)
		ni_wicked_request_add_option(&req, "Root", opt_rootdir);

	rv = ni_wicked_call_indirect(&req);
	if (rv < 0) {
		ni_error("%s", req.error_msg);
	} else if (recv_xml) {
		*recv_xml = req.xml_out;
		req.xml_out = NULL;
	}

	ni_wicked_request_destroy(&req);
	return rv;
}

xml_node_t *
wicked_get(const char *path)
{
	xml_node_t *out = NULL;

	if (__wicked_request(NI_REST_OP_GET, path, NULL, &out) < 0)
		return NULL;

	return out;
}

xml_node_t *
wicked_get_interface(const char *base_path, const char *ifname)
{
	char pathbuf[256];

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", base_path, ifname);
	return wicked_get(pathbuf);
}

int
wicked_put(const char *path, xml_node_t *in)
{
	return __wicked_request(NI_REST_OP_PUT, path, in, NULL);
}

int
wicked_put_interface(const char *base_path, const char *ifname, xml_node_t *in)
{
	xml_node_t *out = NULL;
	char pathbuf[256];

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", base_path, ifname);
	if (__wicked_request(NI_REST_OP_PUT, pathbuf, in, &out) < 0)
		return -1;

	if (out) {
		xml_node_print(out, stdout);
		xml_node_free(out);
	}

	return 0;
}

int
wicked_delete_interface(const char *base_path, const char *ifname)
{
	char pathbuf[256];

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", base_path, ifname);
	if (__wicked_request(NI_REST_OP_DELETE, pathbuf, NULL, NULL) < 0)
		return -1;

	return 0;
}

/*
 * For an XML interface definition, get the interface name
 */
static const char *
ni_xml_interface_get_name(const xml_node_t *ifnode)
{
	return xml_node_get_attr(ifnode, "name");
}

static const char *
ni_xml_interface_get_type(const xml_node_t *ifnode)
{
	return xml_node_get_attr(ifnode, "type");
}

static const char *
ni_xml_interface_get_startmode(const xml_node_t *ifnode)
{
	xml_node_t *child;

	if (!(child = xml_node_get_child(ifnode, "start")))
		return NULL;
	return xml_node_get_attr(child, "mode");
}

void
ni_xml_interface_change_status(xml_node_t *ifnode,
			const char *link_status,
			const char *network_status)
{
	xml_node_t *child;

	child = xml_node_new("status", NULL);
	(void) xml_node_add_attr(child, "link", link_status);
	(void) xml_node_add_attr(child, "network", network_status);

	xml_node_replace_child(ifnode, child);
}

void
ni_xml_interface_clear_addresses(xml_node_t *ifnode)
{
	xml_node_delete_child(ifnode, "protocol");
}

static xml_node_t *
ni_xml_interface_find(xml_document_t *doc, const char *ifname)
{
	xml_node_t *node;

	for (node = xml_document_root(doc)->children; node; node = node->next) {
		if (!strcmp(node->name, "interface")) {
			const char *other_name;

			if ((other_name = ni_xml_interface_get_name(node)) != NULL
			 && strcmp(other_name, ifname) == 0)
				return node;
		}
	}
	return 0;
}

/*
 * Helper functions to iterate over all interfaces of an XML definition
 */
static xml_node_t *
ni_xml_interface_next(xml_node_t **nextp)
{
	xml_node_t *node = *nextp;

	while (node && strcmp(node->name, "interface"))
		node = node->next;

	if (node)
		*nextp = node->next;
	return node;
}

static xml_node_t *
ni_xml_interface_first(xml_document_t *doc, xml_node_t **nextp)
{
	xml_node_t *root = xml_document_root(doc);

	*nextp = NULL;
	if (!root)
		return NULL;

	*nextp = root->children;
	return ni_xml_interface_next(nextp);
}

/*
 * Sort all interfaces of a list, taking into account master/slave
 * relationships of VLANs, bridges and bonds.
 */
struct ni_interface_dependency {
	const char *		name;
	const char *		type;
	xml_node_t *		xml;
	int			priority;
	unsigned int		link_up : 1,
				network_up : 1;

	struct ni_interface_dependency *parent;
};

static int
__ni_xml_interface_dependeny_cmp(const void *p1, const void *p2)
{
	const struct ni_interface_dependency *d1 = p1;
	const struct ni_interface_dependency *d2 = p2;

	return d1->priority - d2->priority;
}

static int
ni_xml_sort_interfaces(xml_document_t *doc, struct ni_interface_dependency **resultp)
{
	struct ni_interface_dependency *iflist = NULL;
	unsigned int i, j, count;

	/* Do this twice; first iteration: count devices,
	 * second iteration: store them in array. */
	while (1) {
		xml_node_t *ifnode, *pos = NULL;

		count = 0;

		ifnode = ni_xml_interface_first(doc, &pos);
		while (ifnode) {
			if (iflist) {
				const char *ifname, *iftype;

				ifname = ni_xml_interface_get_name(ifnode);
				if (!ifname) {
					ni_error("interface element without name");
					goto failed;
				}

				iftype = ni_xml_interface_get_type(ifnode);
				if (!iftype) {
					ni_error("interface element without type");
					goto failed;
				}

				iflist[count].name = ifname;
				iflist[count].type = iftype;
				iflist[count].xml = ifnode;
				if (!strcmp(ifname, "lo"))
					iflist[count].priority = 0;
				else
					iflist[count].priority = 1;
			}
			ifnode = ni_xml_interface_next(&pos);
			count++;
		}

		if (iflist)
			break;

		iflist = calloc(count, sizeof(iflist[0]));
		if (!iflist)
			return -1;
	}

	/* Resolve master/slave dependencies */
	for (i = 0; i < count; ++i) {
		struct ni_interface_dependency *master = &iflist[i];
		xml_node_t *link_config, *slave_dev, *pos;

		/* bridge, bond, vlan all have a child element
		 * of the same name, with <interface name="...">
		 * elements. */
		link_config = xml_node_get_child(master->xml, master->type);
		if (!link_config)
			continue;

		pos = link_config->children;
		while ((slave_dev = ni_xml_interface_next(&pos)) != NULL) {
			struct ni_interface_dependency *slave;
			const char *slave_name;

			slave_name = ni_xml_interface_get_name(slave_dev);
			if (!slave_name) {
				ni_error("interface %s specifies bad %s child device",
						master->name, master->type);
				goto failed;
			}

			for (j = 0, slave = iflist; j < count; ++j, ++slave) {
				if (strcmp(slave->name, slave_name))
					continue;

				if (slave->parent) {
					ni_error("interface %s used by more than one device",
							slave->name);
					goto failed;
				}

				if (!strcmp(master->type, "vlan")) {
					/* VLANs are special, real device must
					 * be an ether device, and can be referenced
					 * by more than one vlan */
					if (strcmp(slave->type, "ethernet")) {
						ni_error("vlan interface %s references non-ethernet device",
							 master->name);
						goto failed;
					}
					master->priority = 2;

					slave->link_up = 1;
					slave->network_up = 1;
				} else if (!strcmp(master->type, "bridge")) {
					slave->parent = master;

					slave->link_up = 1;
					slave->network_up = 1;
				} else if (!strcmp(master->type, "bond")) {
					slave->parent = master;

					slave->link_up = 1;
					slave->network_up = 0;
				}
				break;
			}
		}
	}

	/* Propagate priorities: master devices get slave->priority + 1 */
	for (i = 0; i < count; ++i) {
		struct ni_interface_dependency *slave = &iflist[i];
		struct ni_interface_dependency *master;
		unsigned int priority;

		priority = slave->priority + 1;
		for (master = slave->parent, j = 0; master; master = master->parent, ++j) {
			if (j > count) {
				ni_error("detected dependency loop in interface definition");
				goto failed;
			}

			if (priority > master->priority)
				master->priority = priority;
			priority = master->priority + 1;
		}

		if (!slave->link_up) {
			slave->link_up = 1;
			slave->network_up = 1;
		}
	}

	qsort(iflist, count, sizeof(iflist[0]), __ni_xml_interface_dependeny_cmp);

	if (ni_debug & NI_TRACE_WICKED) {
		ni_trace("sorted interfaces");
		for (i = 0; i < count; ++i) {
			struct ni_interface_dependency *slave = &iflist[i];

			ni_trace("%s prio=%d link %s network %s",
					slave->name, slave->priority,
					slave->link_up? "up" : "down",
					slave->network_up? "up" : "down");
		}
	}

	*resultp = iflist;
	return count;

failed:
	free(iflist);
	return -1;
}

/*
 * Bring a single interface up
 */
static int
do_ifup_one(xml_node_t *ifnode, int link_up, int network_up, int boot_only)
{
	const char *ifname;
	int rv;

	ifname = ni_xml_interface_get_name(ifnode);

	if (boot_only) {
		const char *start_mode;

		start_mode = ni_xml_interface_get_startmode(ifnode);
		if (!start_mode || strcmp(start_mode, "onboot") != 0)
			return 0;

		/* For DHCP interfaces, we could tell the server here
		 * that it should wait for the interface to come up.
		 * Alternatively, we could keep checking that all interfaces
		 * are up after we're done. */
	}

	ni_xml_interface_change_status(ifnode,
					link_up? "up" : "down",
					network_up? "up" : "down");

	rv = wicked_put_interface("/system/interface", ifname, ifnode);
	if (rv < 0)
		fprintf(stderr, "Unable to bring up interface %s\n", ifname);

	return rv;
}

/*
 * Handle "ifup" command
 */
int
do_ifup(int argc, char **argv)
{
	static struct option ifup_options[] = {
		{ "boot", no_argument, NULL, 'b' },
		{ "file", required_argument, NULL, 'f' },
		{ NULL }
	};
	const char *ifname = NULL;
	const char *opt_file = NULL;
	int opt_boot = 0;
	xml_document_t *doc;
	FILE *ifdesc = NULL;
	int c, rv = -1;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifup_options, NULL)) != EOF) {
		switch (c) {
		case 'b':
			opt_boot = 1;
			break;

		case 'f':
			opt_file = optarg;
			break;

		default:
usage:
			fprintf(stderr,
				"wicked [options] ifup [ifup-options] all\n"
				"wicked [options] ifup [ifup-options] <ifname>\n"
				"\nSupported ifup-options:\n"
				"  --file <filename>\n"
				"      Read interface configuration(s) from file rather than using system config\n"
				"  --boot\n"
				"      Ignore interfaces with startmode != boot\n"
				);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "Bad number of arguments\n");
		goto usage;
	}
	ifname = argv[optind++];

	/* Using --file means, read the interface definition from a local file.
	 * Otherwise, first retrieve /config/interface/<ifname> from the server,
	 * change <status> to up, and send it back.
	 */
	if (opt_file) {
		if ((ifdesc = fopen(opt_file, "r")) == NULL) {
			fprintf(stderr, "Unable to open file %s: %m\n", opt_file);
			return 1;
		}

		doc = xml_document_scan(ifdesc);
		if (!doc) {
			fprintf(stderr, "Cannot parse interface description\n");
			fclose(ifdesc);
			return 1;
		}
		fclose(ifdesc);

		fprintf(stderr, "Read network configuration from %s\n", opt_file);
	} else {
		xml_node_t *response;

		if (!strcmp(ifname, "all")) {
			response = wicked_get("/system/interface");
		} else {
			response = wicked_get_interface("/system/interface", ifname);
		}

		if (!response) {
			fprintf(stderr, "Unable to obtain interface configuration\n");
			return 1;
		}

		doc = xml_document_new();
		xml_document_set_root(doc, response);
	}

	if (!strcmp(ifname, "all")) {
		struct ni_interface_dependency *sorted;
		int i, ifcount;

		ifcount = ni_xml_sort_interfaces(doc, &sorted);
		if (ifcount < 0)
			goto failed;

		for (i = 0; i < ifcount; ++i) {
			rv = do_ifup_one(sorted[i].xml,
						sorted[i].link_up, sorted[i].network_up,
						opt_boot);
			if (rv < 0)
				goto failed;
		}
		free(sorted);
	} else {
		xml_node_t *ifnode;

		if (!(ifnode = ni_xml_interface_find(doc, ifname))) {
			fprintf(stderr,
				"Unable to find interface %s in interface description\n",
				ifname);
			xml_document_free(doc);
			return 1;
		}

		rv = do_ifup_one(ifnode, 1, 1, opt_boot);
	}

failed:
	xml_document_free(doc);
	return (rv == 0);
}

/*
 * Bring a single interface down
 */
static int
do_ifdown_one(xml_node_t *ifnode, int delete)
{
	const char *ifname, *iftype;
	int rv;

	ifname = ni_xml_interface_get_name(ifnode);

	if (delete) {
		iftype = ni_xml_interface_get_type(ifnode);
		if (!iftype)
			return -1;

		if (strcmp(iftype, "vlan")
		 && strcmp(iftype, "bridge")
		 && strcmp(iftype, "bond"))
			delete = 0;
	}

	ni_xml_interface_change_status(ifnode, "down", "down");

	/* Clear IP addressing; this will make sure all addresses are
	 * removed from the interface, and dhcp is shut down etc.
	 */
	ni_xml_interface_clear_addresses(ifnode);

	rv = wicked_put_interface("/system/interface", ifname, ifnode);
	if (rv < 0) {
		ni_error("Unable to shut down interface %s\n", ifname);
		return -1;
	}

	if (delete) {
		rv = wicked_delete_interface("/system/interface", ifname);
		if (rv < 0) {
			ni_error("Unable to delete interface %s\n", ifname);
			return -1;
		}
	}

	return rv;
}

/*
 * Handle "ifdown" command
 */
int
do_ifdown(int argc, char **argv)
{
	static struct option ifdown_options[] = {
		{ "delete", no_argument, NULL, 'd' },
		{ NULL }
	};
	int opt_delete = 0;
	const char *ifname = NULL;
	xml_document_t *doc;
	int c, rv;

	optind = 1;
	while ((c = getopt_long(argc, argv, "", ifdown_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			opt_delete = 1;
			break;

		default:
usage:
			fprintf(stderr,
				"Usage:\n"
				"wicked [options] ifdown [ifdown-options] all\n"
				"wicked [options] ifdown [ifdown-options] <ifname>\n"
				"\nSupported ifdown-options:\n"
				"  --delete\n"
				"      Delete virtual interfaces in addition to shutting them down\n"
				);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "Bad number of arguments\n");
		goto usage;
	}
	ifname = argv[optind++];

	/* Otherwise, first retrieve /config/interface/<ifname> from the server,
	 * change <status> to down, and send it back.
	 */
	{
		xml_node_t *response;

		if (!strcmp(ifname, "all")) {
			response = wicked_get("/system/interface");
		} else {
			response = wicked_get_interface("/system/interface", ifname);
		}

		if (!response) {
			ni_error("unable to obtain interface configuration");
			return 1;
		}

		doc = xml_document_new();
		xml_document_set_root(doc, response);
	}

	if (!strcmp(ifname, "all")) {
		struct ni_interface_dependency *sorted;
		int i, ifcount;

		ifcount = ni_xml_sort_interfaces(doc, &sorted);
		if (ifcount < 0)
			goto failed;

		for (i = ifcount - 1; i >= 0; --i) {
			if ((rv = do_ifdown_one(sorted[i].xml, opt_delete)) < 0)
				goto failed;
		}
		free(sorted);
	} else {
		xml_node_t *ifnode;

		if (!(ifnode = ni_xml_interface_find(doc, ifname))) {
			ni_error("unable to find interface %s in interface description", ifname);
			xml_document_free(doc);
			return 1;
		}

		rv = do_ifdown_one(ifnode, opt_delete);
	}

failed:
	xml_document_free(doc);
	return (rv == 0);
}

/*
 * We also allow the user to send raw REST commands to the server,
 * if s/he so desires
 */
static int
do_rest(const char *cmd, int argc, char **argv)
{
	xml_node_t *send_xml = NULL, *recv_xml = NULL, **recvp = NULL;
	int rest_op;
	char *path;

	if (argc != 2) {
		ni_error("Missing path name\n");
		fprintf(stderr,
			"Usage:\n"
			"wicked [options] get /path\n"
			"wicked [options] put /path\n"
			"wicked [options] post /path\n"
			"wicked [options] delete /path\n"
			"\nput and post commands expect an XML document on standard input\n");
		return 1;
	}

	path = argv[1];

	rest_op = ni_wicked_rest_op_parse(cmd);
	if (rest_op < 0)
		return 1;

	if (rest_op == NI_REST_OP_PUT || rest_op == NI_REST_OP_POST) {
		send_xml = xml_node_scan(stdin);
		if (send_xml == NULL) {
			ni_error("unable to read XML from standard input");
			return 1;
		}
	}
	if (rest_op != NI_REST_OP_DELETE)
		recvp = &recv_xml;
	if (__wicked_request(rest_op, path, send_xml, recvp) < 0)
		return 1;

	if (recv_xml)
		xml_node_print(recv_xml, stdout);

	if (send_xml)
		xml_node_free(send_xml);
	if (recv_xml)
		xml_node_free(recv_xml);

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
