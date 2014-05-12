/*
 *	wicked udev utilities
 *
 *	Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * 	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <wicked/types.h>
#include <wicked/util.h>
#include "udev-utils.h"
#include "process.h"
#include "buffer.h"


static ni_shellcmd_t *
__ni_udevadm_shellcmd()
{
	const char **p, *paths[] = {
		"/usr/bin/udevadm",
		"/sbin/udevadm",
		NULL
	};
	ni_shellcmd_t *cmd;

	for (p = paths; p && *p; p++) {
		if (!ni_file_executable(*p))
			continue;

		if (!(cmd = ni_shellcmd_new(NULL)))
			return NULL;

		if (ni_shellcmd_add_arg(cmd, *p))
			return cmd;

		ni_shellcmd_release(cmd);
		return NULL;
	}
	return NULL;
}

static ni_var_array_t *
__ni_udevadm_info_parse_output(ni_buffer_t *buff)
{
	ni_stringbuf_t  line = NI_STRINGBUF_INIT_DYNAMIC;
	ni_var_array_t *list = NULL;
	ni_var_array_t *curr = NULL;
	int c;

	while ((c = ni_buffer_getc(buff)) != EOF) {
		if (c != '\n') {
			ni_stringbuf_putc(&line, c);
			continue;
		}
		if (line.string) {
			if (!curr && ni_string_startswith(line.string, "P: ")) {
				/* device start */
				curr = ni_var_array_new();
			} else
			if (curr && ni_string_startswith(line.string, "E: ")) {
				/* device entries */
				char *key = line.string + sizeof("E: ") - 1;
				char *val = strchr(key, '=');
				if (!val)
					continue;
				*val++ = '\0';
				ni_var_array_set(curr, key, val);
			}
			/* network devices aren't using N: L: S: */
		} else if (curr) {
			/* end of device */
			ni_var_array_list_append(&list, curr);
			curr = NULL;
		}
		ni_stringbuf_clear(&line);
	}
	ni_stringbuf_destroy(&line);
	if (curr) {
		/* incomplete device... */
		ni_var_array_free(curr);
	}
	return list;
}

ni_var_array_t *
ni_udevadm_info(const char *query, const char *path)
{
	ni_shellcmd_t  *udevadm;
	ni_process_t   *proc;
	ni_buffer_t    *buff;
	ni_var_array_t *list;
	int ret;

	if (ni_string_empty(query) || ni_string_empty(path))
		return NULL;

	if (!(udevadm = __ni_udevadm_shellcmd()))
		return NULL;

	if (!ni_shellcmd_add_arg(udevadm, "info")) {
		ni_shellcmd_release(udevadm);
		return NULL;
	}
	if (!ni_shellcmd_fmt_arg(udevadm, "--query=%s", query)) {
		ni_shellcmd_release(udevadm);
		return NULL;
	}
	if (!ni_shellcmd_fmt_arg(udevadm, "--path=%s", path)) {
		ni_shellcmd_release(udevadm);
		return NULL;
	}

	proc = ni_process_new(udevadm);
	if (!proc) {
		ni_shellcmd_release(udevadm);
		return NULL;
	}
	ni_shellcmd_release(udevadm);

	buff = ni_buffer_new_dynamic(1024);
	if (!buff) {
		ni_process_free(proc);
		return NULL;
	}

	ret = ni_process_run_and_capture_output(proc, buff);
	ni_process_free(proc);
	if (ret < 0) {
		ni_buffer_free(buff);
		return NULL;
	}

	list = __ni_udevadm_info_parse_output(buff);
	ni_buffer_free(buff);

	return list;
}
