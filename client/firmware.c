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
#include <wicked/xml.h>

#include "appconfig.h"
#include "firmware.h"
#include "process.h"
#include "buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>


/*
 * wicked --root-directory <path> option argument in main
 */
extern char *					opt_global_rootdir;

#define NI_NETIF_FIRMWARE_DISCOVERY_NODE	"netif-firmware-discovery"
#define NI_NETIF_FIRMWARE_DISCOVERY_FILE	"client-firmware.xml"


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

static const char *
ni_netif_firmware_discovery_config_file(char **config_file)
{
	const char *config_dir = ni_get_global_config_dir();

	if (ni_string_empty(config_dir) || !config_file)
		return NULL;

	if (!ni_string_printf(config_file, "%s/%s", config_dir,
				NI_NETIF_FIRMWARE_DISCOVERY_FILE))
		return NULL;

	return *config_file;
}

static FILE *
ni_netif_firmware_discovery_config_open(const char *filename, char **tempname)
{
	FILE *fp;
	int fd, err;

	if (!ni_string_printf(tempname, "%s.XXXXXX", filename))
		return NULL;

	if ((fd = mkstemp(*tempname)) < 0) {
		err = errno;
		ni_string_free(tempname);
		errno = err;
		return NULL;
	}

	if (fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) < 0 ||
	    !(fp = fdopen(fd, "we"))) {
		err = errno;
		close(fd);
		unlink(*tempname);
		ni_string_free(tempname);
		errno = err;
		return NULL;
	}
	return fp;
}

static ni_bool_t
ni_netif_firmware_discovery_config_dump(FILE *out, const xml_node_t *config)
{
	if (!out || !config)
		return FALSE;

	if (fputs("<!-- config file generated by "
		  "`wicked firmware <enable|disable> <name>` -->\n", out) <= 0)
		return FALSE;

	return xml_node_print(config, out) == 0;
}

int
ni_netif_firmware_discovery_config_write(xml_node_t *config)
{
	char *config_file = NULL;
	char *config_temp = NULL;
	FILE *temp;
	int err = NI_WICKED_RC_ERROR;

	if (!config)
		return err;

	if (!ni_netif_firmware_discovery_config_file(&config_file)) {
		ni_error("Unable to construct %s '%s' config file name",
				NI_NETIF_FIRMWARE_DISCOVERY_NODE,
				NI_NETIF_FIRMWARE_DISCOVERY_FILE);
		return err;
	}

	temp = ni_netif_firmware_discovery_config_open(config_file, &config_temp);
	if (!temp) {
		if (errno == EACCES || errno == EPERM)
			err = NI_LSB_RC_NOT_ALLOWED;
		ni_error("Unable to create '%s' config temp file: %m", config_file);
		ni_string_free(&config_file);
		return err;
	}

	if (!ni_netif_firmware_discovery_config_dump(temp, config)) {
		ni_error("Unable to write '%s' config temp file: %m", config_file);
		fclose(temp);
		unlink(config_temp);
		ni_string_free(&config_temp);
		ni_string_free(&config_file);
		return err;
	}

	fclose(temp);
	if (rename(config_temp, config_file) < 0) {
		if (errno == EACCES || errno == EPERM)
			err = NI_LSB_RC_NOT_ALLOWED;
		ni_error("Unable to create '%s' config file: %m", config_file);
		unlink(config_temp);
		ni_string_free(&config_temp);
		ni_string_free(&config_file);
		return err;
	} else {
		ni_debug_application("Updated '%s' config file", config_file);
		ni_string_free(&config_temp);
		ni_string_free(&config_file);
		return NI_WICKED_RC_SUCCESS;
	}
}

static int
ni_netif_firmware_discovery_config_modify(xml_node_t *config,
		const ni_string_array_t *names, ni_bool_t enable)
{
	const ni_extension_t *ex;
	xml_node_t *root, *node;
	int modified = 1; /* no */

	if (!config || !names)
		return -1; /* error */

	if (!(root = xml_node_new(NI_NETIF_FIRMWARE_DISCOVERY_NODE, config)))
		return -1; /* error */

	for (ex = ni_global.config->fw_extensions; ex; ex = ex->next) {
		const ni_script_action_t *script;

		/* builtins are not supported in netif-firmware-discovery */

		for (script = ex->actions; script; script = script->next) {
			if (ni_string_empty(script->name))
				continue;
			if (ni_string_empty(script->process->command))
				continue;

			if (!(node = xml_node_new("script", root)))
				return FALSE;

			xml_node_add_attr(node, "name", script->name);
			xml_node_add_attr(node, "command", script->process->command);

			if (names->count &&
			    ni_string_array_index(names, script->name) == -1) {
				if (!script->enabled) {
					xml_node_add_attr(node, "enabled",
						ni_format_boolean(script->enabled));
				}
				continue;
			}

			if (script->enabled != enable)
				modified = 0; /* yes */

			if (!enable) {
				xml_node_add_attr(node, "enabled",
						ni_format_boolean(enable));
			}
		}
	}

	return modified;
}

static int
ni_wicked_firmware_config_modify(const char *caller, int argc, char **argv)
{
	enum {
		OPTION_HELP	= 'h',
		OPTION_STDOUT	= 1000,
	};
	static const struct option	options[] = {
		{ "help",		no_argument,		NULL,	OPTION_HELP	},
		{ "stdout",		no_argument,		NULL,	OPTION_STDOUT	},
		{ NULL }
	};
	int opt, status = NI_WICKED_RC_USAGE;
	char *argv0, *command = NULL;
	ni_string_array_t names = NI_STRING_ARRAY_INIT;
	xml_node_t *config = NULL;
	ni_bool_t dump = FALSE;
	ni_bool_t enable;
	int modified;

	if (ni_string_eq(argv[0], "enable"))
		enable = TRUE;
	else
	if (ni_string_eq(argv[0], "disable"))
		enable = FALSE;
	else {
		/* we don't implement other actions here */
		fprintf(stderr, "%s: unsupported action '%s'\n", caller, argv[0]);
		return NI_WICKED_RC_NOT_IMPLEMENTED;
	}

	ni_string_printf(&command, "%s %s", caller, argv[0]);
	argv0 = argv[0];
	argv[0] = command;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL))  != -1) {
		switch (opt) {
		case OPTION_STDOUT:
			dump = TRUE;
			break;

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
				"  --stdout		dump modified config to stdout only\n"
				"\n", command);
			goto cleanup;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "%s: Missing firmware name argument\n", command);
		goto usage;
	}

	while (optind < argc) {
		const char *name = argv[optind++];

		if (ni_string_eq(name, "all")) {
			ni_string_array_destroy(&names);
			break;
		}

		if (ni_string_array_index(&names, name) < 0)
			ni_string_array_append(&names, name);
	}

	status   = NI_WICKED_RC_SUCCESS;
	config   = xml_node_new("config", NULL);
	modified = ni_netif_firmware_discovery_config_modify(config, &names, enable);
	if (modified < 0) {
		ni_error("Unable to modify %s config", NI_NETIF_FIRMWARE_DISCOVERY_NODE);
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	if (dump) {
		if (!ni_netif_firmware_discovery_config_dump(stdout, config))
			status = NI_WICKED_RC_ERROR;
	} else if (modified > 0) {
		ni_note("No configuration change needed");
	} else {
		status = ni_netif_firmware_discovery_config_write(config);
	}

cleanup:
	argv[0] = argv0;
	ni_string_free(&command);
	ni_string_array_destroy(&names);
	xml_node_free(config);
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
		ACTION_ENABLE,
		ACTION_DISABLE,
	};
	static const struct option	options[] = {
		{ "help",		no_argument,		NULL,	OPTION_HELP	},
		{ NULL }
	};
	static const ni_intmap_t	actions[] = {
		{ "extensions",		ACTION_EXTENSIONS	},
		{ "interfaces",		ACTION_INTERFACES	},
		{ "enable",		ACTION_ENABLE		},
		{ "disable",		ACTION_DISABLE		},
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
				"\n"
				"  enable  <name>	enable specified firmware extension\n"
				"  disable <name>	disable specified firmware extension\n"
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

		case ACTION_ENABLE:
		case ACTION_DISABLE:
			status = ni_wicked_firmware_config_modify(command,
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
