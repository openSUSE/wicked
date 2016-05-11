/*
 *	Interfacing with systemd using systemctl
 *
 *	Copyright (C) 2016 SUSE Linux GmbH, Nuernberg, Germany.
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
 *	with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/util.h>
#include <wicked/logging.h>

#include "buffer.h"
#include "process.h"


static const char *
ni_systemctl_tool_path(void)
{
	static const char *paths[] = {
		"/usr/bin/systemctl",
		"/bin/systemctl",
		NULL
	};

	return ni_find_executable(paths);
}

/*
 * systemd instance service methods
 */
int
ni_systemctl_service_start(const char *service)
{
	const char *systemctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv;

	if (ni_string_empty(service))
		return -1;

	if (!(systemctl = ni_systemctl_tool_path()))
		return -1;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return -1;

	if (!ni_shellcmd_add_arg(cmd, systemctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "start"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, service))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;
	ni_shellcmd_release(cmd);

	rv = ni_process_run_and_wait(pi);
	ni_process_free(pi);

	return rv;

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	return -1;
}

int
ni_systemctl_service_stop(const char *service)
{
	const char *systemctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv;

	if (ni_string_empty(service))
		return -1;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return -1;

	if (!(systemctl = ni_systemctl_tool_path()))
		return -1;

	if (!ni_shellcmd_add_arg(cmd, systemctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "stop"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, service))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;
	ni_shellcmd_release(cmd);

	rv = ni_process_run_and_wait(pi);
	ni_process_free(pi);

	return rv;

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	return -1;
}

const char *
ni_systemctl_service_show_property(const char *service, const char *property, char **result)
{
	const char *systemctl;
	char *complete = NULL;
	char *ptr;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	ni_buffer_t buf;
	int rv;

	if (ni_string_empty(service) || ni_string_empty(property) || !result)
		return NULL;

	if (!ni_string_printf(&complete, "%s=", property))
		return NULL;

	if (!(systemctl = ni_systemctl_tool_path()))
		return NULL;

	ni_buffer_init_dynamic(&buf, 1024);
	if (!(cmd = ni_shellcmd_new(NULL)))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, systemctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "--no-pager"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "-p"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, property))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "show"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, service))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_capture_output(pi, &buf);
	ni_process_free(pi);
	if (rv)
		goto failure;

	ni_buffer_putc(&buf, '\0');
	ptr = (char *)ni_buffer_head(&buf);
	ptr[strcspn(ptr, "\n\r")] = '\0';
	if (!ni_string_startswith(ptr, complete))
		goto failure;

	if (!ni_buffer_pull_head(&buf, ni_string_len(complete)))
		goto failure;

	ptr = (char *)ni_buffer_head(&buf);
	ni_string_set(result, ptr, ni_string_len(ptr));

	ni_buffer_destroy(&buf);
	ni_shellcmd_release(cmd);
	ni_string_free(&complete);
	return *result;

failure:
	if (complete)
		free(complete);
	if (cmd)
		ni_shellcmd_release(cmd);
	ni_buffer_destroy(&buf);
	return NULL;
}
