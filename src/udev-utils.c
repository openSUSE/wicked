/*
 *	wicked udev utilities
 *
 *	Copyright (C) 2014 SÜSE LINUX Products GmbH, Nuernberg, Germany.
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
#include <wicked/netinfo.h>

#include "udev-utils.h"
#include "process.h"
#include "buffer.h"
#include "sysfs.h"


#ifndef _PATH_SYS_CLASS_NET
#define _PATH_SYS_CLASS_NET	"/sys/class/net"
#endif

struct netdev_uinfo {
	unsigned int	ifindex;
	const char *	subsystem;
	const char *	interface;
	const char *	interface_old;
	const char *	tags;
};


static const char *
ni_udevadm_tool_path()
{

	static const char *paths[] = {
		"/usr/bin/udevadm",
		"/sbin/udevadm",
		NULL
	};
	return ni_find_executable(paths);
}

static unsigned int
ni_udevadm_info_parse_output(ni_var_array_t **list, ni_buffer_t *buff)
{
	ni_stringbuf_t  line = NI_STRINGBUF_INIT_DYNAMIC;
	ni_var_array_t *curr = NULL;
	unsigned int count = 0;
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
			ni_var_array_list_append(list, curr);
			curr = NULL;
			count++;
		}
		ni_stringbuf_clear(&line);
	}
	ni_stringbuf_destroy(&line);
	if (curr) {
		/* incomplete device... */
		ni_var_array_free(curr);
	}
	return count;
}

static int
ni_udevadm_info_cmd(ni_shellcmd_t *cmd, const char *query, const char *path)
{
	const char *tool;

	if (!cmd || ni_string_empty(query) || ni_string_empty(path))
		return NI_PROCESS_FAILURE;

	if (!(tool = ni_udevadm_tool_path()))
		return NI_PROCESS_COMMAND;

	if (!ni_shellcmd_add_arg(cmd, tool))
		return NI_PROCESS_FAILURE;

	if (!ni_shellcmd_add_arg(cmd, "info"))
		return NI_PROCESS_FAILURE;

	if (!ni_shellcmd_fmt_arg(cmd, "--query=%s", query))
		return NI_PROCESS_FAILURE;

	if (!ni_shellcmd_fmt_arg(cmd, "--path=%s", path))
		return NI_PROCESS_FAILURE;

	return NI_PROCESS_SUCCESS;
}

int
ni_udevadm_info(ni_var_array_t **list, const char *query, const char *path)
{
	ni_shellcmd_t  *cmd;
	ni_process_t   *proc;
	ni_buffer_t    *buff;
	int ret;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return NI_PROCESS_FAILURE;

	ret = ni_udevadm_info_cmd(cmd, query, path);
	if (ret) {
		ni_shellcmd_release(cmd);
		return ret;
	}

	proc = ni_process_new(cmd);
	ni_shellcmd_release(cmd);
	if (!proc)
		return NI_PROCESS_FAILURE;

	buff = ni_buffer_new_dynamic(1024);
	if (!buff) {
		ni_process_free(proc);
		return NI_PROCESS_FAILURE;
	}

	ret = ni_process_run_and_capture_output(proc, buff);
	ni_process_free(proc);

	if (ret == 0)
		ni_udevadm_info_parse_output(list, buff);

	ni_buffer_free(buff);
	return ret;
}

static ni_bool_t
ni_systemd_udev_is_active(void)
{
	/*
	 * systemd-udevd is a static service and is
	 * always started when /sys fs is writeable.
	 */
	return !ni_sysfs_is_read_only();
}

ni_bool_t
ni_udev_is_active(void)
{
	return ni_systemd_udev_is_active();
}

ni_bool_t
ni_udev_net_subsystem_available(void)
{
	ni_var_array_t *vars = NULL;
	ni_bool_t result = FALSE;
	int ret;

	ret = ni_udevadm_info(&vars, "all", _PATH_SYS_CLASS_NET);
	if (ret == 0 && vars) {
		ni_var_t *devpath = ni_var_array_get(vars, "DEVPATH");
		ni_var_t *subsystem = ni_var_array_get(vars, "SUBSYSTEM");

		if (devpath   && ni_string_eq(devpath->value, "/class/net") &&
		    subsystem && ni_string_eq(subsystem->value, "subsystem"))
			result = TRUE;

		ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_EVENTS,
				"udev: net subsystem %s available",
				result ? "is" : "is not");
	} else if (ret == NI_PROCESS_COMMAND) {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
				"udevadm utility is not available");
	} else {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_EVENTS,
				"udevadm net subsystem query failed: %d", ret);
	}
	ni_var_array_list_destroy(&vars);

	return result;
}

static int
netdev_uinfo_map(struct netdev_uinfo *uinfo, const ni_var_array_t *vars, const char *ifname)
{
	const ni_var_t *var;
	unsigned int i;

	if (!uinfo || !vars)
		return -1;

	memset(uinfo, 0, sizeof(*uinfo));
	for (i = 0; i < vars->count; ++i) {
		var = &vars->data[i];

		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS,
			"udevadm info %s: %s='%s'", ifname, var->name, var->value);

		if (ni_string_eq("SUBSYSTEM", var->name)) {
			uinfo->subsystem = var->value;
		} else
		if (ni_string_eq("IFINDEX", var->name)) {
			if (ni_parse_uint(var->value, &uinfo->ifindex, 10))
				uinfo->ifindex = 0;
		} else
		if (ni_string_eq("INTERFACE_OLD", var->name)) {
			if (!ni_string_empty(var->value))
				uinfo->interface_old = var->value;
		} else
		if (ni_string_eq("INTERFACE", var->name)) {
			if (!ni_string_empty(var->value))
				uinfo->interface = var->value;
		} else
		if (ni_string_eq("TAGS", var->name)) {
			if (!ni_string_empty(var->value))
				uinfo->tags = var->value;
		}
	}
	return 0;
}

static int
netdev_uinfo_ready(const ni_var_array_t *vars, const char *ifname, unsigned int ifindex)
{
	struct netdev_uinfo uinfo;

	if (netdev_uinfo_map(&uinfo, vars, ifname) < 0)
		return -1;

	if (!ni_string_eq(uinfo.subsystem, "net")) {
		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS,
				"%s[%u] udev info: unexpected subsystem %s",
				ifname, ifindex, uinfo.subsystem);
		return -1;	/* huh? not a net subsystem?! */
	}

	if (uinfo.ifindex != ifindex || !ni_string_eq(uinfo.interface, ifname)) {
		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS,
				"%s[%u] udev info: ifname %s or ifindex %u differ",
				ifname, ifindex, uinfo.interface, uinfo.ifindex);
		return 1;	/* repeat, udevadm is using ifname / sysfs  */
	}

	if (uinfo.interface_old) {
		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS,
				"%s[%u] udev info: interface_old still set to %s",
				ifname, ifindex, uinfo.interface_old);
		return -1;	/* not ready, expect rename event to arrive */
	}

	if (uinfo.tags && strstr(uinfo.tags, ":systemd:")) {
		ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS,
				"%s[%u] udev info: systemd tag is set",
				ifname, ifindex);
		return 0;	/* only systemd-udevd sets tags */
	}

	/* TODO: other special cases, e.g. like udev != systemd-udev */
	ni_debug_verbose(NI_LOG_DEBUG3, NI_TRACE_EVENTS,
			"%s[%u] udev info: systemd tag is not set",
			ifname, ifindex);
	return -1;
}

static int
ni_udev_netdev_update_name(ni_netdev_t *dev)
{
	char ifnamebuf[IF_NAMESIZE+1] = {'\0'};
	const char *ifname;

	if (!dev || !dev->link.ifindex)
		return -1;

	ifname = if_indextoname(dev->link.ifindex, ifnamebuf);
	if (ni_string_empty(ifname))
		return -1; /* device seems to be gone */

	if (!ni_string_eq(dev->name, ifname))
		ni_string_dup(&dev->name, ifname);

	return 0;
}

ni_bool_t
ni_udev_netdev_is_ready(ni_netdev_t *dev)
{
	char pathbuf[PATH_MAX] = { '\0' };
	ni_var_array_t *vars = NULL;
	int ret, retry = 2;

	do {
		/*
		 * we're called to bootstrap before events listeners
		 * start to receive, that is the device ifname may
		 * be obsolete in the meantime due to udev renames.
		 */
		if (ni_udev_netdev_update_name(dev) < 0)
			return FALSE;

		snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
				_PATH_SYS_CLASS_NET, dev->name);

		ret = ni_udevadm_info(&vars, "all", pathbuf);
		switch (ret) {
		case 0:
			ret = netdev_uinfo_ready(vars, dev->name, dev->link.ifindex);
			break;
		case 2:	/* syspath not found (by ifname)  */
		case 4: /* another kind of device not found(?) */
			ret = 1;
			break;
		default:
			ret = -1;
		}
		ni_var_array_list_destroy(&vars);

	} while (ret > 0 && retry--);

	return ret == 0;
}

