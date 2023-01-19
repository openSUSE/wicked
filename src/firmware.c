/*
 *	Discover network interfaces config provided by firmware (eg iBFT)
 *
 *	Copyright (C) 2012 Olaf Kirch <okir@suse.de>
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
 *		Olaf Kirch
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/*
 * Check if extension script contains name and executable command
 */
ni_bool_t
ni_netif_firmware_extension_script_usable(const ni_script_action_t *script)
{
	if (!script || ni_string_empty(script->name))
		return FALSE;

	if (!script->process || ni_string_empty(script->process->command))
		return FALSE;

	if (!ni_file_executable(script->process->command))
		return FALSE;

	return TRUE;
}

static int
ni_netif_firmware_discovery_script_exec(int argc, char *const argv[], char *const envp[])
{
	if (argc < 1 || !argv)
		return EXIT_FAILURE;

	if (!freopen("/dev/null", "w", stderr))
		{}

	(void)execve(argv[0], argv, envp);

	ni_error("%s: cannot execute %s: %m", __func__, argv[0]);
	exit(EXIT_FAILURE);
}

static int
ni_netif_firmware_discovery_script_call(ni_buffer_t *buf, ni_script_action_t *script,
		const char *type, const char *root, const char *path, ni_bool_t list)
{
	ni_process_t *pi;
	int status;

	ni_assert(buf && script);

	ni_debug_ifconfig("trying to discover %s netif config from extension", type);

	/* Create an instance for this script command process */
	if (!(pi = ni_process_new(script->process))) {
		ni_error("%s discovery process allocation failure: %m", type);
		return NI_PROCESS_FAILURE;
	}

	/* Add root directory argument if given */
	if (!ni_string_empty(root)) {
		ni_string_array_append(&pi->argv, "-r");
		ni_string_array_append(&pi->argv, root);
	}

	/* Add firmware type specific path argument if given */
	if (!ni_string_empty(path)) {
		ni_string_array_append(&pi->argv, "-p");
		ni_string_array_append(&pi->argv, path);
	}

	/* Enable list-interfaces only mode */
	if (list) {
		ni_string_array_append(&pi->argv, "-l");
	}

	pi->exec = ni_netif_firmware_discovery_script_exec;
	status = ni_process_run_and_capture_output(pi, buf);
	ni_process_free(pi);

	if (status > NI_PROCESS_SUCCESS) {
		/* (post-fork) exit codes returned by extension sub-process */
		ni_info("%s discovery script failure: exit status %d", type, status);
		return status;
	}
	if (status < NI_PROCESS_SUCCESS) {
		/* we log / report an error for most of the exec errors ... */
		ni_warn("%s discovery script execution failure: %d", type, status);
		return status;
	}

	ni_debug_extension("%s discovery script output has %zu bytes",
			type, ni_buffer_count(buf));

	return status;
}

static int
ni_netif_firmware_discovery_script_ifconfig(xml_document_t **doc,
		ni_script_action_t *script, const char *type,
		const char *root, const char *path)
{
	char buffer[BUFSIZ];
	ni_buffer_t buf;
	int status;

	ni_assert(doc && !*doc && script);

	/* Use an initial static (8k) buffer, that should be sufficient.
	 * When it gets full, it will be automatically reallocated... */
	memset(buffer, 0, sizeof(buffer));
	ni_buffer_init(&buf, &buffer, sizeof(buffer));

	status = ni_netif_firmware_discovery_script_call(&buf, script,
					type, root, path, FALSE);

	if (status == NI_PROCESS_SUCCESS && ni_buffer_count(&buf)) {

		if (!(*doc = xml_document_from_buffer(&buf, type))) {
			ni_warn("%s discovery script failure: can't parse xml output", type);
			/* hmm... NI_ERROR_DOCUMENT_ERROR? */
			status = NI_WICKED_RC_ERROR;
		} else if (xml_document_is_empty(*doc)) {
			/* bunch of spaces?! */
			ni_debug_ifconfig("%s discovery script xml output: empty", type);
			xml_document_free(*doc);
			*doc = NULL;
		} else if (ni_log_level_at(NI_LOG_DEBUG2)) {
			ni_debug_ifconfig("%s discovery script xml output:", type);
			xml_node_print_debug(xml_document_root(*doc), NI_TRACE_IFCONFIG);
		}
	}
	ni_buffer_destroy(&buf);
	return status;
}

static ni_bool_t
ni_netif_firmware_name_from_path(char **name, const char **path)
{
	if (!name || !path)
		return FALSE;

	/*
	 * get firmware:X specific type name and path:
	 * path: (empty)      => name: NULL, path: (empty)
	 * path: ibft         => name: ibft, path: (empty)
	 * path: ibft:        => name: ibft, path: (empty)
	 * path: ibft:foo-bar => name: ibft, path: foo
	 */
	if (!ni_string_empty(*path)) {
		char *ptr;

		if (!ni_string_dup(name, *path))
			return FALSE;

		if ((ptr = strchr(*name, ':')))
			*ptr++ = '\0';
		*path = ptr;
	}
	if (ni_string_empty(*path))
		*path = NULL;

	return TRUE;
}

/*
 * Run the netif firmware discovery scripts and return their xml output
 * as an XML document array.
 * The optional from parameter allow to specify the firmware extension
 * type (e.g. ibft) and a firmware type specific path (e.g. ethernet0),
 * passed as last argument to the discovery script.
 */
ni_bool_t
ni_netif_firmware_discover_ifconfig(xml_document_array_t *docs,
		const char *type, const char *root, const char *path)
{
	unsigned int success = 0;
	unsigned int failure = 0;
	ni_extension_t *ex;
	char *name = NULL;

	if (!docs || !ni_global.config)
		return FALSE;

	/* sanity adjustments... */
	if (ni_string_empty(root))
		root = NULL;
	if (ni_string_empty(type))
		type = "firmware";

	if (!ni_netif_firmware_name_from_path(&name, &path))
		return FALSE;

	for (ex = ni_global.config->fw_extensions; ex; ex = ex->next) {
		ni_script_action_t *script;

		/* builtins are not supported in netif-firmware-discovery */

		for (script = ex->actions; script; script = script->next) {
			xml_document_t *doc = NULL;
			char *full = NULL;

			/* Check if script is usable/non-empty and executable */
			if (!ni_netif_firmware_extension_script_usable(script))
				continue;

			/* Check if to use specific type/name only (e.g. "ibft") */
			if (name && !ni_string_eq_nocase(name, script->name))
				continue;

			/* Construct full firmware type name, e.g. firmware:ibft */
			if (!ni_string_printf(&full, "%s:%s", type, script->name))
				continue;

			if (ni_netif_firmware_discovery_script_ifconfig(&doc,
						script, full, root, path) == 0) {
				xml_document_array_append(docs, doc);
				success++;
			} else {
				failure++;
			}

			ni_string_free(&full);
		}
	}
	ni_string_free(&name);

	if (failure && !success)
		return FALSE;
	else
		return TRUE;
}
