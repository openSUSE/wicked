/*
 * This command line utility converts sysconfig files to standard wicked xml.
 *
 * Copyright (C) 2010-2011 Olaf Kirch <okir@suse.de>
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
#include <wicked/dbus.h>

enum {
	OPT_ALL,
	OPT_CONFIGFILE,
	OPT_DEBUG,
	OPT_DRYRUN,
	OPT_ROOTDIR,
	OPT_SCHEMA,
	OPT_OUTPUT,
};

static struct option	options[] = {
	{ "all",		no_argument,		NULL,	OPT_ALL },
	{ "config",		required_argument,	NULL,	OPT_CONFIGFILE },
	{ "dryrun",		no_argument,		NULL,	OPT_DRYRUN },
	{ "dry-run",		no_argument,		NULL,	OPT_DRYRUN },
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "root-directory",	required_argument,	NULL,	OPT_ROOTDIR },
	{ "schema",		required_argument,	NULL,	OPT_SCHEMA },
	{ "output",		required_argument,	NULL,	OPT_OUTPUT },

	{ NULL }
};

static int		opt_all = 0;
static int		opt_dryrun = 0;
static char *		opt_rootdir = NULL;
static char *		opt_schema = NULL;
static const char *	opt_outfile = NULL;

static FILE *		fopen_or_fail(const char *, const char *);

extern int		ni_sysconfig_read_suse(ni_netconfig_t *, const char *);
extern int		ni_sysconfig_read_redhat(ni_netconfig_t *, const char *root);

int
main(int argc, char **argv)
{
	ni_netconfig_t netconfig;
	int c, rv;

	mtrace();
	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"wicked-convert [options] [interface ...]\n"
				"This command understands the following options\n"
				"  --all\n"
				"        Generate XML files for all interfaces, rather than those specified on the command line\n"
				"  --schema name\n"
				"        Use specified sysconfig schema (currently supported: redhat, suse).\n"
				"  --config filename\n"
				"        Use alternative configuration file.\n"
				"  --dry-run\n"
				"        Do not change the system in any way.\n"
				"  --debug facility\n"
				"        Enable debugging for debug <facility>.\n"
			       );
			return 1;

		case OPT_ALL:
			opt_all = 1;
			break;

		case OPT_CONFIGFILE:
			ni_set_global_config_path(optarg);
			break;

		case OPT_DRYRUN:
			opt_dryrun = 1;
			break;

		case OPT_ROOTDIR:
			opt_rootdir = optarg;
			break;

		case OPT_SCHEMA:
			opt_schema = optarg;
			break;

		case OPT_OUTPUT:
			opt_outfile = optarg;
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

	if (!opt_schema || !strcmp(opt_schema, "sysconfig")) {
		if (ni_file_exists("/etc/SuSE-release")) {
			opt_schema = "suse";
		} else if (ni_file_exists("/etc/redhat-release")) {
			opt_schema = "redhat";
		} else {
			ni_error("Unable to determine default sysconfig schema");
			return 1;
		}
	}

	if (!opt_all && optind >= argc) {
		fprintf(stderr, "You either have to specify --all, or list the interface to be converted\n");
		goto usage;
	}

	ni_netconfig_init(&netconfig);
	if (!strcmp(opt_schema, "suse"))
		rv = ni_sysconfig_read_suse(&netconfig, opt_rootdir);
	else if (!strcmp(opt_schema, "redhat"))
		rv = ni_sysconfig_read_redhat(&netconfig, opt_rootdir);
	else {
		ni_error("Unsupported configuration schema \"%s\"", opt_schema);
		goto usage;
	}

	if (rv < 0) {
		ni_error("failed to load network configuration");
		return 1;
	}

	if (!opt_dryrun) {
		ni_interface_array_t interfaces = NI_INTERFACE_ARRAY_INIT;
		ni_interface_t *ifp;
		FILE *ofp = NULL;
		unsigned int i;

		if (opt_all) {
			for (ifp = netconfig.interfaces; ifp; ifp = ifp->next) {
				ni_interface_array_append(&interfaces, ifp);
			}
		} else {
			while (optind < argc) {
				const char *ifname = argv[optind++];
				ni_interface_t *ifp;

				if (!(ifp = ni_interface_by_name(&netconfig, ifname))) {
					ni_error("no configuration for interface %s - cannot convert", ifname);
					return 1;
				}
				ni_interface_array_append(&interfaces, ifp);
			}
		}

		if (opt_outfile != NULL) {
			ofp = fopen_or_fail(opt_outfile, "w");
			printf("Writing configuration to %s\n",
					strcmp(opt_outfile, "-") == 0? "standard output" : opt_outfile);
		}

		for (i = 0; i < interfaces.count; ++i) {
			ifp = interfaces.data[i];

			if (ofp != NULL) {
				ni_netcf_store_interface(&netconfig, ifp, ofp);
			} else {
				const char *path = ni_netcf_format_path(opt_rootdir, "%s.xml", ifp->name);
				FILE *fp = NULL;

				fp = fopen_or_fail(path, "w");
				printf("Writing configuration to %s\n", path);
				ni_netcf_store_interface(&netconfig, ifp, fp);
				fclose(fp);
			}
		}

		if (ofp)
			fclose(ofp);

		ni_interface_array_destroy(&interfaces);
	}

	ni_netconfig_destroy(&netconfig);
	return 0;
}

FILE *
fopen_or_fail(const char *filename, const char *mode)
{
	FILE *ofp;

	if (!strcmp(filename, "-")) {
		ofp = mode[0] == 'r'? stdin : stdout;
		return fdopen(fileno(ofp), mode);
	}

	if ((ofp = fopen(filename, mode)) == NULL)
		ni_fatal("cannot open %s for %s: %m", filename,
				mode[0] == 'r'? "reading" : "writing");

	return ofp;
}
