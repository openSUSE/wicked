/*
 *	wicked client iaid commands
 *
 *	Copyright (C) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *      Authors:
 *              Marius Tomaschewski <mt@suse.de>
 *              Nirmoy Das <ndas@suse.de>
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
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/util.h>
#include <wicked/netinfo.h>
#include "iaid.h"

static int
ni_do_iaid_dump(int argc, char **argv)
{
	enum {	OPT_HELP = 'h' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_var_array_t vars = NI_VAR_ARRAY_INIT;
	ni_iaid_map_t *map = NULL;
	const ni_var_t *var;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
					"Usage: %s [options]\n"
					"\n"
					"Options:\n"
					"  --help, -h           show this help text and exit.\n"
					"\n", argv[0]);
			goto cleanup;
		}
	}
	if (argc - optind)
		goto usage;

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_iaid_map_load(NULL)))
		goto cleanup;

	status = NI_WICKED_RC_SUCCESS;
	if (ni_iaid_map_to_vars(map, &vars)) {
		unsigned int i;

		for (i = 0, var = vars.data; i < vars.count; ++i, ++var) {
			printf("%s\t%s\n", var->name, var->value);
		}
	}
	ni_var_array_destroy(&vars);

cleanup:
	ni_iaid_map_free(map);
	return status;
}

static int
ni_do_iaid_get(int argc, char **argv)
{
	enum {	OPT_HELP = 'h' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_iaid_map_t *map = NULL;
	const char *ifname = NULL;
	unsigned int iaid;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
					"Usage: %s [options] <ifname>\n"
					"\n"
					"Options:\n"
					"  --help, -h           show this help text and exit.\n"
					"\n", argv[0]);
			goto cleanup;
		}
	}
	switch (argc - optind) {
	case 1:
		ifname = argv[optind++];
		break;
	default:
		goto usage;
	}

	if (!ni_netdev_name_is_valid(ifname)) {
		fprintf(stderr, "%s: invalid interface name '%s'\n", argv[0],
				ni_print_suspect(ifname, ni_string_len(ifname)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_iaid_map_load(NULL)))
		goto cleanup;

	status = NI_WICKED_RC_NO_DEVICE;
	if (ni_iaid_map_get_iaid(map, ifname, &iaid)) {
		printf("%s\t%u\n", ifname, iaid);
		status = NI_WICKED_RC_SUCCESS;
	}

cleanup:
	ni_iaid_map_free(map);
	return status;
}

static int
ni_do_iaid_del(int argc, char **argv)
{
	enum {	OPT_HELP = 'h' };
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_iaid_map_t *map = NULL;
	const char *ifname = NULL;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
					"Usage: %s [options] <ifname>\n"
					"\n"
					"Options:\n"
					"  --help, -h           show this help text and exit.\n"
					"\n", argv[0]);
			goto cleanup;
		}
	}
	switch (argc - optind) {
	case 1:
		ifname = argv[optind++];
		break;
	default:
		goto usage;
	}

	if (!ni_netdev_name_is_valid(ifname)) {
		fprintf(stderr, "%s: invalid interface name '%s'\n", argv[0],
				ni_print_suspect(ifname, ni_string_len(ifname)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_iaid_map_load(NULL)))
		goto cleanup;

	status = NI_WICKED_RC_NO_DEVICE;
	if (ni_iaid_map_del_name(map, ifname)) {
		if (ni_iaid_map_save(map))
			status = NI_WICKED_RC_SUCCESS;
	}

cleanup:
	ni_iaid_map_free(map);
	return status;
}

static int
ni_do_iaid_set(int argc, char **argv)
{
	enum {	OPT_HELP = 'h', OPT_UNIQUE = 'U' };
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "unique",	no_argument,		NULL,	OPT_UNIQUE	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_iaid_map_t *map = NULL;
	const char *ifname = NULL;
	const char *ifiaid = NULL;
	ni_bool_t   unique = FALSE;
	const char *conflict;
	unsigned int iaid;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hU", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_UNIQUE:
			unique = TRUE;
			break;

		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
					"Usage: %s [options] <ifname> <iaid>\n"
					"\n"
					"Options:\n"
					"  --help, -h           show this help text and exit.\n"
					"\n", argv[0]);
			goto cleanup;
		}
	}
	switch (argc - optind) {
	case 2:
		ifname = argv[optind++];
		ifiaid = argv[optind++];
		break;
	default:
		goto usage;
	}

	if (!ni_netdev_name_is_valid(ifname)) {
		fprintf(stderr, "%s: invalid interface name '%s'\n", argv[0],
				ni_print_suspect(ifname, ni_string_len(ifname)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	if (ni_parse_uint(ifiaid, &iaid, 0) != 0) {
		fprintf(stderr, "%s: unable to parse iaid argument '%s'\n", argv[0],
				ni_print_suspect(ifiaid, ni_string_len(ifiaid)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_iaid_map_load(NULL)))
		goto cleanup;

	if (unique && ni_iaid_map_get_name(map, iaid, &conflict)) {
		fprintf(stderr, "%s: iaid %u in use by '%s'\n", argv[0], iaid, conflict);
		status = NI_WICKED_RC_NO_DEVICE;
		goto cleanup;
	}

	if (ni_iaid_map_set(map, ifname, iaid)) {
		if (ni_iaid_map_save(map))
			status = NI_WICKED_RC_SUCCESS;
	}

	if (status == NI_WICKED_RC_SUCCESS)
		printf("%s\t%u\n", ifname, iaid);

cleanup:
	ni_iaid_map_free(map);
	return status;
}

static int
ni_do_iaid_create(int argc, char **argv)
{
	enum {	OPT_HELP = 'h', OPT_UPDATE = 'u' };
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "update",	no_argument,		NULL,	OPT_UPDATE	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_iaid_map_t *map = NULL;
	const char *ifname = NULL;
	ni_bool_t   update = FALSE;
	ni_netconfig_t *nc;
	ni_netdev_t *dev;
	unsigned int iaid;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hu", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_UPDATE:
			update = TRUE;
			break;

		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
					"Usage: %s [options] <ifname>\n"
					"\n"
					"Options:\n"
					"  --help, -h           show this help text and exit.\n"
					"  --update, -u         also set in persistent iaid file.\n"
					"\n", argv[0]);
			goto cleanup;
		}
	}
	switch (argc - optind) {
	case 1:
		ifname = argv[optind++];
		break;
	default:
		goto usage;
	}

	if (!ni_netdev_name_is_valid(ifname)) {
		fprintf(stderr, "%s: invalid interface name '%s'\n", argv[0],
				ni_print_suspect(ifname, ni_string_len(ifname)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	if (!(nc = ni_global_state_handle(1))) {
		fprintf(stderr, "%s: cannot retrieve interface properties", argv[0]);
		goto cleanup;
	}

	if (!(dev = ni_netdev_by_name(nc, ifname))) {
		fprintf(stderr, "%s: interface %s does not exists\n", argv[0], ifname);
		goto cleanup;
	}

	if (!(map = ni_iaid_map_load(NULL)))
		goto cleanup;

	if (!ni_iaid_create(&iaid, dev, map)) {
		fprintf(stderr, "%s: cannot create iaid for interface %s\n", argv[0], ifname);
		goto cleanup;
	}

	if (update && (!ni_iaid_map_set(map, ifname, iaid) || !ni_iaid_map_save(map))) {
		fprintf(stderr, "%s: unable to update iaid map file\n", argv[0]);
		goto cleanup;
	}

	printf("%s\t%u\n", ifname, iaid);
	status = NI_WICKED_RC_SUCCESS;

cleanup:
	ni_iaid_map_free(map);
	return status;
}

int
ni_do_iaid(const char *caller, int argc, char **argv)
{
	enum {	OPT_HELP = 'h' };
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	char *program = NULL;
	char *command = NULL;
	const char *cmd;

	ni_string_printf(&program, "%s %s", caller  ? caller  : "wicked",
					    argv[0] ? argv[0] : "iaid");

	optind = 1;
	argv[0] = program;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"  %s [common options] command [...]\n"
				"\n"
				"Common options:\n"
				"  --help, -h           show this help text and exit.\n"
				"\n"
				"Supported Commands:\n"
				"  help                 show this help text and exit.\n"
				"  dump, show           show the iaid map contents\n"
				"  get <ifname>         get current device iaid\n"
				"  del <ifname>         delete current device iaid\n"
				"  set <ifname> <iaid>  set/update the device iaid\n"
				"  create <ifname>      create a new device iaid\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}

	if (optind >= argc || ni_string_empty(argv[optind])) {
		fprintf(stderr, "%s: missing command\n", program);
		goto usage;
	}

	cmd = argv[optind];
	ni_string_printf(&command, "%s %s", program, cmd);
	argv[optind] = command;

	if (ni_string_eq(cmd, "help")) {
		argv[optind] = (char *)cmd;
		status = NI_WICKED_RC_SUCCESS;
		goto usage;
	} else
	if (ni_string_eq(cmd, "dump") || ni_string_eq(cmd, "show")) {
		status = ni_do_iaid_dump(argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "get")) {
		status = ni_do_iaid_get (argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "del")) {
		status = ni_do_iaid_del (argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "set")) {
		status = ni_do_iaid_set (argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "create")) {
		status = ni_do_iaid_create (argc - optind, argv + optind);
	} else {
		argv[optind] = (char *)cmd;
		fprintf(stderr, "%s: unsupported command %s\n", program, cmd);
		goto usage;
	}
	argv[optind] = (char *)cmd;

cleanup:
	argv[0] = NULL;
	ni_string_free(&command);
	ni_string_free(&program);
	return status;
}

