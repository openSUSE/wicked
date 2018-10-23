/*
 *      wicked client tester commands
 *
 *      Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License along
 *      with this program; if not, see <http://www.gnu.org/licenses/> or write
 *      to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *      Boston, MA 02110-1301 USA.
 *
 *      Authors:
 *              Marius Tomaschewski <mt@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

#include <wicked/types.h>
#include <wicked/util.h>
#include <wicked/address.h>
#include <wicked/addrconf.h>

#include "dhcp4/tester.h"
#include "dhcp6/tester.h"
#include "netinfo_priv.h"


int
ni_do_test_dhcp4(const char *caller, int argc, char **argv)
{
	enum {
		OPT_HELP 	 = 'h',
		OPT_TEST_TIMEOUT = 't',
		OPT_TEST_REQUEST = 'r',
		OPT_TEST_OUTPUT	 = 'o',
		OPT_TEST_OUTFMT	 = 'F',
		OPT_TEST_BROADCAST = 'b',
	};
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "request",	required_argument,	NULL,	OPT_TEST_REQUEST},
		{ "timeout",	required_argument,	NULL,	OPT_TEST_TIMEOUT},
		{ "output",	required_argument,	NULL,	OPT_TEST_OUTPUT	},
		{ "format",	required_argument,	NULL,	OPT_TEST_OUTFMT	},
		{ "broadcast",	no_argument,		NULL,	OPT_TEST_BROADCAST},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	char *program = NULL;
	ni_dhcp4_tester_t *tester;

	ni_string_printf(&program, "%s %s",	caller  ? caller  : "wicked",
						argv[0] ? argv[0] : "test");
	argv[0] = program;

	tester = ni_dhcp4_tester_init();
	if (tester == NULL) {
		fprintf(stderr, "Error: %s: unable to initialize dhcp4 tester\n", program);
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hr:t:o:F:b", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"  %s [options] <ifname>\n"
				"\n"
				"Options:\n"
				"  --help, -h      show this help text and exit.\n"
				"\n"
				"  --timeout, -t   	<timeout in sec> (default: 20+10)\n"
				"  --request, -r   	<request.xml>\n"
				"  --output, -o    	<output file name>\n"
				"  --format, -F    	<leaseinfo|lease-xml>\n"
				"  --broadcast, -b	request broadcast responses from server\n"
				"\n", program);
			goto cleanup;

		case OPT_TEST_TIMEOUT:
			if (ni_string_empty(optarg))
				goto usage;
			if (ni_parse_uint(optarg, &tester->timeout, 0) < 0) {
				fprintf(stderr, "%s: unable to parse timeout option '%s'\n",
						program, optarg);
				status = NI_WICKED_RC_ERROR;
				goto cleanup;
			}
			break;

		case OPT_TEST_REQUEST:
			if (ni_string_empty(optarg))
				goto usage;
			tester->request = optarg;
			break;

		case OPT_TEST_OUTPUT:
			if (ni_string_empty(optarg))
				goto usage;
			tester->output = optarg;
			break;

		case OPT_TEST_OUTFMT:
			if (ni_string_empty(optarg))
				goto usage;
			if (!ni_dhcp4_tester_set_outfmt(optarg, &tester->outfmt)) {
				fprintf(stderr, "%s: unable to parse output format option '%s'\n",
						program, optarg);
				status = NI_WICKED_RC_ERROR;
				goto cleanup;
			}
			break;

		case OPT_TEST_BROADCAST:
			tester->broadcast = NI_TRISTATE_ENABLE;
			break;
		}
	}

	if (optind >= argc || ni_string_empty(argv[optind])) {
		fprintf(stderr, "Error: %s: missing interface name argument\n", program);
		goto usage;
	} else
	if (optind + 1 != argc) {
		fprintf(stderr, "Error: %s: multiple interface names not supported\n", program);
		goto cleanup;
	}

	ni_netconfig_set_family_filter(ni_global_state_handle(0), AF_INET);
	ni_netconfig_set_discover_filter(ni_global_state_handle(0),
					NI_NETCONFIG_DISCOVER_LINK_EXTERN|
					NI_NETCONFIG_DISCOVER_ROUTE_RULES);

	tester->ifname = argv[optind];
	status = ni_dhcp4_tester_run(tester);

cleanup:
	ni_string_free(&program);
	return status;
}

int
ni_do_test_dhcp6(const char *caller, int argc, char **argv)
{
	enum {
		OPT_HELP 	 = 'h',
		OPT_TEST_TIMEOUT = 't',
		OPT_TEST_REQUEST = 'r',
		OPT_TEST_OUTPUT	 = 'o',
		OPT_TEST_OUTFMT	 = 'F',
		OPT_TEST_MODE	 = 'm',
	};
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "request",	required_argument,	NULL,	OPT_TEST_REQUEST},
		{ "timeout",	required_argument,	NULL,	OPT_TEST_TIMEOUT},
		{ "output",	required_argument,	NULL,	OPT_TEST_OUTPUT	},
		{ "format",	required_argument,	NULL,	OPT_TEST_OUTFMT	},
		{ "mode",	required_argument,	NULL,	OPT_TEST_MODE	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	char *program = NULL;
	ni_dhcp6_tester_t *tester;

	ni_string_printf(&program, "%s %s",	caller  ? caller  : "wicked",
						argv[0] ? argv[0] : "test");
	argv[0] = program;

	tester = ni_dhcp6_tester_init();
	if (tester == NULL) {
		fprintf(stderr, "Error: %s: unable to initialize dhcp6 tester\n", program);
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hr:t:o:F:m:", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"  %s [options] <ifname>\n"
				"\n"
				"Options:\n"
				"  --help, -h      show this help text and exit.\n"
				"\n"
				"  --request, -r   <request.xml>\n"
				"  --timeout, -t   <timeout in sec> (default: 20+10)\n"
				"  --output, -o    <output file name>\n"
				"  --format, -F    <leaseinfo|lease-xml>\n"
				"  --mode, -m      <auto|info|managed>\n"
				"\n", program);
			goto cleanup;

		case OPT_TEST_TIMEOUT:
			if (ni_string_empty(optarg) ||
			    ni_parse_uint(optarg, &tester->timeout, 0) < 0) {
				fprintf(stderr, "%s: unable to parse timeout option '%s'\n",
						program, optarg);
				goto cleanup;
			}
			break;

		case OPT_TEST_REQUEST:
			if (ni_string_empty(optarg))
				goto usage;
			tester->request = optarg;
			break;

		case OPT_TEST_OUTPUT:
			if (ni_string_empty(optarg))
				goto usage;
			tester->output = optarg;
			break;

		case OPT_TEST_OUTFMT:
			if (ni_string_empty(optarg))
				goto usage;
			if (!ni_dhcp4_tester_set_outfmt(optarg, &tester->outfmt)) {
				fprintf(stderr, "%s: unable to parse output format option '%s'\n",
						program, optarg);
				status = NI_WICKED_RC_ERROR;
				goto usage;
			}
			break;

		case OPT_TEST_MODE:
			if (ni_dhcp6_mode_name_to_type(optarg, &tester->mode) < 0) {
				fprintf(stderr, "%s: unable to parse request mode option '%s'\n",
						program, optarg);
				status = NI_WICKED_RC_ERROR;
				goto usage;
			}
			break;
		}
	}

	if (optind >= argc || ni_string_empty(argv[optind])) {
		fprintf(stderr, "Error: %s: missing interface name argument\n", program);
		goto usage;
	} else
	if (optind + 1 != argc) {
		fprintf(stderr, "Error: %s: multiple interface names not supported\n", program);
		goto cleanup;
	}

	ni_netconfig_set_family_filter(ni_global_state_handle(0), AF_INET6);
	ni_netconfig_set_discover_filter(ni_global_state_handle(0),
					NI_NETCONFIG_DISCOVER_LINK_EXTERN|
					NI_NETCONFIG_DISCOVER_ROUTE_RULES);

	tester->ifname = argv[optind];
	status = ni_dhcp6_tester_run(tester);

cleanup:
	ni_string_free(&program);
	return status;
}

int
ni_do_test(const char *caller, int argc, char **argv)
{
	enum { OPT_HELP = 'h' };
	static struct option	options[] = {
		{ "help",	no_argument,	NULL,	'h'	},
		{ NULL,		no_argument,	NULL,	0	}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	char *program = NULL;
	const char *cmd;

	ni_string_printf(&program, "%s %s",	caller  ? caller  : "wicked",
						argv[0] ? argv[0] : "test");
	argv[0] = program;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"  %s <command>\n"
				"\n"
				"Options:\n"
				"  --help, -h      show this help text and exit.\n"
				"\n"
				"Commands:\n"
				"  dhcp4       [options...]\n"
				"  dhcp6       [options...]\n"
				"\n", program);
			goto cleanup;
		}
	}

	if (optind >= argc || ni_string_empty(argv[optind])) {
		fprintf(stderr, "%s: missing command\n", program);
		goto usage;
	}

	cmd = argv[optind];
	if (ni_string_eq(cmd, "help")) {
		status = NI_WICKED_RC_SUCCESS;
		goto usage;
	} else
	if (ni_string_eq(cmd, "dhcp4")) {
		status = ni_do_test_dhcp4(program, argc - optind, argv + optind);
	} else 
	if (ni_string_eq(cmd, "dhcp6")) {
		status = ni_do_test_dhcp6(program, argc - optind, argv + optind);
	} else {
		fprintf(stderr, "%s: unsupported command %s\n", program, cmd);
		goto usage;
	}

cleanup:
	ni_string_free(&program);
	return status;
}

