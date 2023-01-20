/*
 *	wicked firmware -- utils to firmware config discovery
 *
 *	Copyright (C) 2023 SUSE LLC
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
 *	Authors:
 *		Marius Tomaschewski
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include <wicked/logging.h>

#include "appconfig.h"
#include "firmware.h"
#include "process.h"
#include "buffer.h"

#include <unistd.h>
#include <getopt.h>

/*
 * wicked --root-directory <path> option argument in main
 */
extern char *		opt_global_rootdir;

static int
ni_wicked_firmware_extensions(const char *caller, int argc, char **argv)
{
	enum {
		OPTION_HELP	= 'h',
	};
	static const struct option	options[] = {
		{ "help",		no_argument,		NULL,	OPTION_HELP	},
		{ NULL }
	};
	int opt, status = NI_WICKED_RC_USAGE;
	char *argv0, *command = NULL;
	const ni_extension_t *ex;

	ni_string_printf(&command, "%s %s", caller, argv[0]);
	argv0 = argv[0];
	argv[0] = command;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL))  != -1) {
		switch (opt) {
		case OPTION_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"%s [options]\n"
				"\n"
				"Options:\n"
				"  --help, -h		show this help text and exit.\n"
				"\n", command);
			goto cleanup;
		}
	}

	if (argc > optind)
		goto usage;

	if (!ni_global.config) {
		fprintf(stderr, "%s: application config is not initialized\n", command);
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_SUCCESS;
	for (ex = ni_global.config->fw_extensions; ex; ex = ex->next) {
		const ni_script_action_t *script;

		/* builtins are not supported in netif-firmware-discovery */

		for (script = ex->actions; script; script = script->next) {
			if (ni_string_empty(script->name) || !script->process)
				continue;

			if (ni_string_empty(script->process->command))
				continue;

			printf("%-15s %s\n", script->name, script->enabled ?
					"enabled" : "disabled");
		}
	}

cleanup:
	argv[0] = argv0;
	ni_string_free(&command);
	return status;
}

static int
ni_wicked_firmware_interfaces(const char *caller, int argc, char **argv)
{
	enum {
		OPTION_HELP	= 'h',
	};
	static const struct option	options[] = {
		{ "help",		no_argument,		NULL,	OPTION_HELP	},
		{ NULL }
	};
	int opt, status = NI_WICKED_RC_USAGE;
	char *argv0, *command = NULL;
	ni_netif_firmware_ifnames_t *list = NULL;
	ni_netif_firmware_ifnames_t *item = NULL;

	ni_string_printf(&command, "%s %s", caller, argv[0]);
	argv0 = argv[0];
	argv[0] = command;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL))  != -1) {
		switch (opt) {
		case OPTION_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"%s [options]\n"
				"\n"
				"Options:\n"
				"  --help, -h		show this help text and exit.\n"
				"\n", command);
			goto cleanup;
		}
	}

	if (argc > optind)
		goto usage;

	if (!ni_netif_firmware_discover_ifnames(&list, NULL, opt_global_rootdir, NULL)) {
		status = NI_WICKED_RC_ERROR;
	} else {
		for (item = list; item; item = item->next) {
			ni_stringbuf_t ifnames = NI_STRINGBUF_INIT_DYNAMIC;

			if (ni_string_empty(item->fwname) || !item->ifnames.count)
				continue;

			ni_stringbuf_join(&ifnames, &item->ifnames, " ");
			if (ifnames.len)
				printf("%-15s %s\n", item->fwname, ifnames.string);
			ni_stringbuf_destroy(&ifnames);
		}
		status = NI_WICKED_RC_SUCCESS;
	}

cleanup:
	argv[0] = argv0;
	ni_string_free(&command);
	ni_netif_firmware_ifnames_list_destroy(&list);
	return status;
}

int
ni_wicked_firmware(const char *caller, int argc, char **argv)
{
	enum {
		OPTION_HELP	= 'h',
	};
	enum {
		ACTION_EXTENSIONS,
		ACTION_INTERFACES,
	};
	static const struct option	options[] = {
		{ "help",		no_argument,		NULL,	OPTION_HELP	},
		{ NULL }
	};
	static const ni_intmap_t	actions[] = {
		{ "extensions",		ACTION_EXTENSIONS	},
		{ "interfaces",		ACTION_INTERFACES	},
		{ NULL,			-1U			}
	};
	int opt, status = NI_WICKED_RC_USAGE;
	char *argv0, *command = NULL;
	unsigned int action = -1U;

	ni_string_printf(&command, "%s %s", caller, argv[0]);
	argv0 = argv[0];
	argv[0] = command;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL))  != -1) {
		switch (opt) {
		case OPTION_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"%s [options] <action>\n"
				"\n"
				"Options:\n"
				"  --help, -h		show this help text and exit.\n"
				"\n"
				"Actions:\n"
				"  extensions		list firmware config extensions and status\n"
				"  interfaces		list firmware and interface names it configures\n"
				"\n", command);
			goto cleanup;
		}
	}

	if (optind >= argc || ni_string_empty(argv[optind]) ||
	    ni_parse_uint_mapped(argv[optind], actions, &action)) {
		fprintf(stderr, "%s: please specify an action\n", command);
		goto usage;
	}

	/* execute actions that do not need decoding */
	switch (action) {
		case ACTION_EXTENSIONS:
			status = ni_wicked_firmware_extensions(command,
					argc - optind, argv + optind);
			goto cleanup;

		case ACTION_INTERFACES:
			status = ni_wicked_firmware_interfaces(command,
					argc - optind, argv + optind);
			goto cleanup;

		default:
			break;
	}

cleanup:
	argv[0] = argv0;
	ni_string_free(&command);
	return status;
}
