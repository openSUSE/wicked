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
#include "extension.h"
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
	if (!script || !script->enabled || ni_string_empty(script->name))
		return FALSE;

	if (!script->process || ni_string_empty(script->process->command))
		return FALSE;

	if (!script->process->argv.count || !ni_file_executable(script->process->argv.data[0]))
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
		const ni_var_array_t *vars, const char *type, const char *root,
		const char *path)
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

	/* Apply default extension environment */
	ni_process_setenv_vars(pi, vars, FALSE);

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
		ni_script_action_t *script, const ni_var_array_t *env,
		const char *type, const char *root, const char *path)
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
					env, type, root, path);

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
			ni_debug_verbose_config_xml(xml_document_root(*doc), NI_LOG_DEBUG2,
					NI_TRACE_IFCONFIG, "%s discovery script xml output:", type);
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

		if (ni_string_empty(ex->name) || !ex->enabled)
			continue;

		/* Check if to use specific type/name only (e.g. "ibft") */
		if (name && !ni_string_eq_nocase(name, ex->name))
			continue;

		/* builtins are not supported in netif-firmware-discovery */

		if ((script = ni_script_action_list_find(ex->actions, "show-config"))) {
			xml_document_t *doc = NULL;
			char *full = NULL;

			/* Check if script is usable/non-empty and executable */
			if (!ni_netif_firmware_extension_script_usable(script))
				continue;

			/* Construct full firmware type name, e.g. firmware:ibft */
			if (!ni_string_printf(&full, "%s:%s", type, ex->name))
				continue;

			if (ni_netif_firmware_discovery_script_ifconfig(&doc,
					script, &ex->environment,
					full, root, path) == 0) {
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

/*
 * Run the netif firmware discovery scripts and return interface names
 * the firmware configures.
 */
void
ni_netif_firmware_ifnames_free(ni_netif_firmware_ifnames_t *nfi)
{
	if (nfi) {
		ni_string_free(&nfi->fwname);
		ni_string_array_destroy(&nfi->ifnames);
		free(nfi);
	}
}

ni_netif_firmware_ifnames_t *
ni_netif_firmware_ifnames_new(const char *fwname)
{
	ni_netif_firmware_ifnames_t *nfi;

	if (!(nfi = calloc(1, sizeof(*nfi))))
		return NULL;

	if (ni_string_dup(&nfi->fwname, fwname))
		return nfi;

	ni_netif_firmware_ifnames_free(nfi);
	return NULL;
}

ni_bool_t
ni_netif_firmware_ifnames_list_append(ni_netif_firmware_ifnames_t **list, ni_netif_firmware_ifnames_t *item)
{
	if (list && item) {
		while (*list)
			list = &(*list)->next;
		*list = item;
		return TRUE;
	}
	return FALSE;
}

void
ni_netif_firmware_ifnames_list_destroy(ni_netif_firmware_ifnames_t **list)
{
	ni_netif_firmware_ifnames_t *item;

	if (list) {
		while ((item = *list)) {
			*list = item->next;
			ni_netif_firmware_ifnames_free(item);
		}
	}
}

static ni_bool_t
ni_netif_firmware_ifnames_parse(ni_netif_firmware_ifnames_t **list,
		const char *fwname, ni_buffer_t *buf)
{
	ni_stringbuf_t line = NI_STRINGBUF_INIT_DYNAMIC;
	ni_string_array_t ifnames = NI_STRING_ARRAY_INIT;
	ni_netif_firmware_ifnames_t *item = NULL;
	ni_bool_t ret = TRUE;
	ni_buffer_t rbuf;
	int c;

	if (!list || !buf || !fwname)
		return FALSE;

	if (!ni_buffer_init_reader(&rbuf, ni_buffer_head(buf), ni_buffer_count(buf)))
		return FALSE;

	while (ret && ni_buffer_count(&rbuf)) {
		while ((c = ni_buffer_getc(&rbuf)) != EOF) {
			if (c == '\n')
				break;
			ni_stringbuf_putc(&line, c);
		}

		if (!ni_string_split(&ifnames, line.string, "\t ", 0)) {
			ni_stringbuf_truncate(&line, 0);
			continue;
		}
		ni_stringbuf_truncate(&line, 0);

		if ((item = ni_netif_firmware_ifnames_new(fwname))) {
			ni_string_array_move(&item->ifnames, &ifnames);
			ret = ni_netif_firmware_ifnames_list_append(list, item);
		} else {
			ret = FALSE;
		}
	}

	ni_buffer_destroy(&rbuf);
	ni_stringbuf_destroy(&line);
	ni_string_array_destroy(&ifnames);
	return ret;
}

int
ni_netif_firmware_discover_script_ifnames(ni_netif_firmware_ifnames_t **list,
		ni_script_action_t *script, const ni_var_array_t *env,
		const char *name, const char *type, const char *root, const char *path)
{
	char buffer[BUFSIZ];
	ni_buffer_t buf;
	int status;

	ni_assert(list && script);

	/* Use an initial static (8k) buffer, that should be sufficient.
	 * When it gets full, it will be automatically reallocated... */
	memset(buffer, 0, sizeof(buffer));
	ni_buffer_init(&buf, &buffer, sizeof(buffer));

	status = ni_netif_firmware_discovery_script_call(&buf, script,
					env, type, root, path);

	if (status == NI_PROCESS_SUCCESS && ni_buffer_count(&buf)) {

		if (!ni_netif_firmware_ifnames_parse(list, name, &buf)) {
			ni_debug_ifconfig("%s discovery script failure: invalid list output", type);
			ni_netif_firmware_ifnames_list_destroy(list);
			/* hmm... NI_ERROR_DOCUMENT_ERROR? */
			status = NI_WICKED_RC_ERROR;
		}
	}
	ni_buffer_destroy(&buf);
	return status;
}

ni_bool_t
ni_netif_firmware_discover_ifnames(ni_netif_firmware_ifnames_t **list,
		const char *type, const char *root, const char *path)
{
	unsigned int success = 0;
	unsigned int failure = 0;
	ni_extension_t *ex;
	char *name = NULL;

	if (!list || !ni_global.config)
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

		if (ni_string_empty(ex->name) || !ex->enabled)
			continue;

		/* Check if to use specific type/name only (e.g. "ibft") */
		if (name && !ni_string_eq_nocase(name, ex->name))
			continue;

		/* builtins are not supported in netif-firmware-discovery */

		if ((script = ni_script_action_list_find(ex->actions, "list-ifnames"))) {
			ni_netif_firmware_ifnames_t *curr = NULL;
			char *full = NULL;

			/* Check if script is usable/non-empty and executable */
			if (!ni_netif_firmware_extension_script_usable(script))
				continue;

			/* Construct full firmware type name, e.g. firmware:ibft */
			if (!ni_string_printf(&full, "%s:%s", type, ex->name))
				continue;

			if (ni_netif_firmware_discover_script_ifnames(&curr,
					script, &ex->environment, ex->name,
					full, root, path) == 0) {
				ni_netif_firmware_ifnames_list_append(list, curr);
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
