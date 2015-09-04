/*
 *	OVS (bridge) device support
 *
 *	Copyright (C) 2015 SUSE Linux GmbH, Nuernberg, Germany.
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
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <wicked/util.h>
#include <wicked/netinfo.h>
#include "ovs.h"
#include "buffer.h"
#include "process.h"
#include "util_priv.h"

#define NI_OVS_BRIDGE_PORT_ARRAY_CHUNK		4

ni_ovs_bridge_t *
ni_ovs_bridge_new(void)
{
	ni_ovs_bridge_t *ovsbr;

	ovsbr = xcalloc(1, sizeof(*ovsbr));
	/* ni_ovs_bridge_config_init(&ovsbr->conf); */
	return ovsbr;
}

void
ni_ovs_bridge_free(ni_ovs_bridge_t *ovsbr)
{
	if (ovsbr) {
		ni_ovs_bridge_config_destroy(&ovsbr->config);
		ni_ovs_bridge_port_array_destroy(&ovsbr->ports);
		free(ovsbr);
	}
}

void
ni_ovs_bridge_config_init(ni_ovs_bridge_config_t *conf)
{
	memset(conf, 0, sizeof(*conf));
}

void
ni_ovs_bridge_config_destroy(ni_ovs_bridge_config_t *conf)
{
	ni_netdev_ref_destroy(&conf->vlan.parent);
	ni_ovs_bridge_config_init(conf);
}


ni_ovs_bridge_port_t *
ni_ovs_bridge_port_new(void)
{
	ni_ovs_bridge_port_t *port;

	port = xcalloc(1, sizeof(*port));
	return port;
}

void
ni_ovs_bridge_port_free(ni_ovs_bridge_port_t *port)
{
	if (port) {
		ni_netdev_ref_destroy(&port->device);
		free(port);
	}
}

void
ni_ovs_bridge_port_array_init(ni_ovs_bridge_port_array_t *array)
{
	memset(array, 0, sizeof(*array));
}

void
ni_ovs_bridge_port_array_destroy(ni_ovs_bridge_port_array_t *array)
{
	while (array->count > 0)
		ni_ovs_bridge_port_free(array->data[--array->count]);
	free(array->data);
	ni_ovs_bridge_port_array_init(array);
}

static void
__ni_ovs_bridge_port_array_realloc(ni_ovs_bridge_port_array_t *array, unsigned int newsize)
{
	ni_ovs_bridge_port_t **newdata;
	unsigned int i;

	newsize = (newsize + NI_OVS_BRIDGE_PORT_ARRAY_CHUNK);
	newdata = xrealloc(array->data, newsize * sizeof(ni_ovs_bridge_port_t *));
	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		 array->data[i] = NULL;
}

ni_bool_t
ni_ovs_bridge_port_array_append(ni_ovs_bridge_port_array_t *array, ni_ovs_bridge_port_t *port)
{
	if (array && port) {
		if ((array->count % NI_OVS_BRIDGE_PORT_ARRAY_CHUNK) == 0)
			__ni_ovs_bridge_port_array_realloc(array, array->count);

		array->data[array->count++] = port;
		return TRUE;
	}
	return FALSE;
}

ni_ovs_bridge_port_t *
ni_ovs_bridge_port_array_add_new(ni_ovs_bridge_port_array_t *ports, const char *pname)
{
	ni_ovs_bridge_port_t *port;

	if (!ports || ni_string_empty(pname))
		return NULL;

	if (ni_ovs_bridge_port_array_find_by_name(ports, pname))
		return NULL;

	port = ni_ovs_bridge_port_new();
	ni_netdev_ref_set_ifname(&port->device, pname);

	if (ni_ovs_bridge_port_array_append(ports, port))
		return port;

	ni_ovs_bridge_port_free(port);
	return NULL;
}

ni_bool_t
ni_ovs_bridge_port_array_delete_at(ni_ovs_bridge_port_array_t *array, unsigned int pos)
{
	if (!array || pos >= array->count)
		return FALSE;

	ni_ovs_bridge_port_free(array->data[pos]);
	array->count--;
	if (pos < array->count) {
		memmove(&array->data[pos], &array->data[pos + 1],
			(array->count - pos) * sizeof(ni_ovs_bridge_port_t *));
	}
	array->data[array->count] = NULL;
	return TRUE;
}

ni_ovs_bridge_port_t *
ni_ovs_bridge_port_array_find_by_name(ni_ovs_bridge_port_array_t *array, const char *name)
{
	unsigned int i;

	if (!array || !name)
		return NULL;

	for (i = 0; i < array->count; ++i) {
		ni_ovs_bridge_port_t *port = array->data[i];
		if (ni_string_eq(name, port->device.name))
			return port;
	}
	return NULL;
}

void
ni_ovs_bridge_port_config_init(ni_ovs_bridge_port_config_t *conf)
{
	memset(conf, 0, sizeof(*conf));
}

void
ni_ovs_bridge_port_config_destroy(ni_ovs_bridge_port_config_t *conf)
{
	ni_netdev_ref_destroy(&conf->bridge);
	ni_ovs_bridge_port_config_init(conf);
}


static const char *
ni_ovs_vsctl_tool_path(void)
{
	static const char *paths[] = {
		"/usr/bin/ovs-vsctl",
		NULL
	};
	const char *path = ni_find_executable(paths);

	if (!path)
		ni_warn_once("unable to find ovs-vsctl utility");
	return path;
}

int /* process run codes (for now) */
ni_ovs_vsctl_bridge_exists(const char *brname)
{
	const char *ovs_vsctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv = NI_PROCESS_FAILURE;

	if (ni_string_empty(brname))
		return rv;

	if (!(ovs_vsctl = ni_ovs_vsctl_tool_path()))
		return rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return rv;

	if (!ni_shellcmd_add_arg(cmd, ovs_vsctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "br-exists"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, brname))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_wait(pi);

	ni_process_free(pi);

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	return rv;
}

int /* process run codes (for now) */
ni_ovs_vsctl_bridge_to_vlan(const char *brname, uint16_t *vlan)
{
	const char *ovs_vsctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	ni_buffer_t buf;
	int rv = NI_PROCESS_FAILURE;
	unsigned int value;
	char *ptr;

	if (ni_string_empty(brname) || !vlan)
		return rv;

	if (!(ovs_vsctl = ni_ovs_vsctl_tool_path()))
		return rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return rv;

	ni_buffer_init_dynamic(&buf, 32);

	if (!ni_shellcmd_add_arg(cmd, ovs_vsctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "br-to-vlan"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, brname))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_capture_output(pi, &buf);
	ni_process_free(pi);
	if (rv) {
		ni_error("%s: unable to query bridge vlan", brname);
		goto failure;
	}

	ni_buffer_put(&buf, "\0", 1);
	ptr = (char *)ni_buffer_head(&buf);
	ptr[strcspn(ptr, "\n\r")] = '\0';

	if (ni_parse_uint(ptr, &value, 10) < 0) {
		ni_error("%s: unable to parse bridge vlan id '%s'", brname, ptr);
		rv = NI_PROCESS_FAILURE;
	} else
	if (value >= 0x0fff /* VLAN_VID_MASK */) {
		ni_error("%s: bridge vlan id %u not in range 1..%u", brname, value, 0x0fff);
		rv = NI_PROCESS_FAILURE;
	} else {
		*vlan = value;
	}

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	ni_buffer_destroy(&buf);
	return rv;
}

int /* process run codes (for now) */
ni_ovs_vsctl_bridge_to_parent(const char *brname, char **parent)
{
	const char *ovs_vsctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	ni_buffer_t buf;
	int rv = NI_PROCESS_FAILURE;
	char *ptr;

	if (ni_string_empty(brname) || !parent)
		return rv;

	if (!(ovs_vsctl = ni_ovs_vsctl_tool_path()))
		return rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return rv;

	ni_buffer_init_dynamic(&buf, 32);

	if (!ni_shellcmd_add_arg(cmd, ovs_vsctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "br-to-parent"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, brname))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_capture_output(pi, &buf);
	ni_process_free(pi);
	if (rv) {
		ni_error("%s: unable to query bridge parent", brname);
		goto failure;
	}

	ni_buffer_put(&buf, "\0", 1);
	ptr = (char *)ni_buffer_head(&buf);
	ptr[strcspn(ptr, "\n\r")] = '\0';

	if (!ni_string_eq(brname, ptr))
		ni_string_dup(parent, ptr);

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	ni_buffer_destroy(&buf);
	return rv;
}


int /* process run codes (for now) */
ni_ovs_vsctl_bridge_ports(const char *brname, ni_ovs_bridge_port_array_t *ports)
{
	ni_stringbuf_t pname = NI_STRINGBUF_INIT_DYNAMIC;
	const char *ovs_vsctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	ni_buffer_t buf;
	int rv = NI_PROCESS_FAILURE;
	int cc;

	if (ni_string_empty(brname) || !ports)
		return rv;

	if (!(ovs_vsctl = ni_ovs_vsctl_tool_path()))
		return rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return rv;

	ni_buffer_init_dynamic(&buf, 256);

	if (!ni_shellcmd_add_arg(cmd, ovs_vsctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "list-ports"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, brname))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_capture_output(pi, &buf);
	ni_process_free(pi);
	if (rv) {
		ni_error("%s: unable to query bridge ports", brname);
		goto failure;
	}

	while ((cc = ni_buffer_getc(&buf)) != EOF) {
		if (cc == '\n') {
			if (pname.string)
				pname.string[strcspn(pname.string, "\n\r")] = '\0';
			ni_ovs_bridge_port_array_add_new(ports, pname.string);
			ni_stringbuf_destroy(&pname);
		} else {
			ni_stringbuf_putc(&pname, cc);
		}
	}
	if (pname.string)
		pname.string[strcspn(pname.string, "\n\r")] = '\0';
	ni_ovs_bridge_port_array_add_new(ports, pname.string);
	ni_stringbuf_destroy(&pname);

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	ni_buffer_destroy(&buf);
	return rv;
}

int /* process run codes (for now) */
ni_ovs_vsctl_bridge_add(const ni_netdev_t *cfg, ni_bool_t may_exist)
{
	const char *ovs_vsctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv = NI_PROCESS_FAILURE;

	/* Note: seems, ovs does not check any args and
	 * permits "anything" without to trigger errors.
	 * Add some checks before you call this function.
	 */
	if (!cfg || ni_string_empty(cfg->name) || !cfg->ovsbr)
		return rv;

	if (!(ovs_vsctl = ni_ovs_vsctl_tool_path()))
		return rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return rv;

	if (!ni_shellcmd_add_arg(cmd, ovs_vsctl))
		goto failure;

	if (may_exist && !ni_shellcmd_add_arg(cmd, "--may-exist"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "add-br"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, cfg->name))
		goto failure;

	if (!ni_string_empty(cfg->ovsbr->config.vlan.parent.name) && cfg->ovsbr->config.vlan.tag) {
		if (!ni_shellcmd_add_arg(cmd, cfg->ovsbr->config.vlan.parent.name))
			goto failure;

		if (!ni_shellcmd_add_arg(cmd, ni_sprint_uint(cfg->ovsbr->config.vlan.tag)))
			goto failure;
	} else if (cfg->ovsbr->config.vlan.parent.name || cfg->ovsbr->config.vlan.tag)
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_wait(pi);

	ni_process_free(pi);

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	return rv;
}

int /* process run codes (for now) */
ni_ovs_vsctl_bridge_del(const char *brname)
{
	const char *ovs_vsctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv = NI_PROCESS_FAILURE;

	if (ni_string_empty(brname))
		return rv;

	if (!(ovs_vsctl = ni_ovs_vsctl_tool_path()))
		return rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return rv;

	if (!ni_shellcmd_add_arg(cmd, ovs_vsctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "del-br"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, brname))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_wait(pi);

	ni_process_free(pi);

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	return rv;
}

int /* process run codes (for now) */
ni_ovs_vsctl_bridge_port_add(const char *pname, const ni_ovs_bridge_port_config_t *pconf)
{
	const char *ovs_vsctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv = NI_PROCESS_FAILURE;

	if (ni_string_empty(pname) || !pconf || ni_string_empty(pconf->bridge.name))
		return rv;

	if (!(ovs_vsctl = ni_ovs_vsctl_tool_path()))
		return rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return rv;

	if (!ni_shellcmd_add_arg(cmd, ovs_vsctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "add-port"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, pconf->bridge.name))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, pname))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_wait(pi);

	ni_process_free(pi);

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	return rv;
}


int /* process run codes (for now) */
ni_ovs_vsctl_bridge_port_del(const char *brname, const char *pname)
{
	const char *ovs_vsctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv = NI_PROCESS_FAILURE;

	if (ni_string_empty(brname) || ni_string_empty(pname))
		return rv;

	if (!(ovs_vsctl = ni_ovs_vsctl_tool_path()))
		return rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return rv;

	if (!ni_shellcmd_add_arg(cmd, ovs_vsctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "del-port"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, brname))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, pname))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_wait(pi);

	ni_process_free(pi);

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	return rv;
}

int /* process run codes (for now) */
ni_ovs_vsctl_bridge_port_to_bridge(const char *pname, char **brname)
{
	const char *ovs_vsctl;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	ni_buffer_t buf;
	int rv = NI_PROCESS_FAILURE;
	char *ptr;

	if (ni_string_empty(pname) || !brname)
		return rv;

	if (!(ovs_vsctl = ni_ovs_vsctl_tool_path()))
		return rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return rv;

	ni_buffer_init_dynamic(&buf, 32);

	if (!ni_shellcmd_add_arg(cmd, ovs_vsctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "port-to-br"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, pname))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;

	rv = ni_process_run_and_capture_output(pi, &buf);
	ni_process_free(pi);
	if (rv) {
		ni_error("%s: unable to query port bridge", pname);
		goto failure;
	}

	ni_buffer_put(&buf, "\0", 1);
	ptr = (char *)ni_buffer_head(&buf);
	ptr[strcspn(ptr, "\n\r")] = '\0';
	ni_string_dup(brname, ptr);

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	ni_buffer_destroy(&buf);
	return rv;
}

int
ni_ovs_bridge_discover(ni_netdev_t *dev, ni_netconfig_t *nc)
{
	ni_ovs_bridge_t *ovsbr;
	unsigned int i;

	if (!dev || dev->link.type != NI_IFTYPE_OVS_BRIDGE)
		return -1;

	ovsbr = ni_ovs_bridge_new();
	if (ni_ovs_vsctl_bridge_to_parent(dev->name, &ovsbr->config.vlan.parent.name) ||
	    ni_ovs_vsctl_bridge_to_vlan(dev->name, &ovsbr->config.vlan.tag) ||
	    ni_ovs_vsctl_bridge_ports(dev->name, &ovsbr->ports)) {
		ni_ovs_bridge_free(ovsbr);
		return -1;
	}

	if (nc) {
		if (ovsbr->config.vlan.parent.name)
			ni_netdev_ref_bind_ifindex(&ovsbr->config.vlan.parent, nc);

		for (i = 0; i < ovsbr->ports.count;  ++i) {
			ni_ovs_bridge_port_t *port = ovsbr->ports.data[i];
			if (port->device.name)
				ni_netdev_ref_bind_ifindex(&port->device, nc);
		}
	}
	ni_netdev_set_ovs_bridge(dev, ovsbr);
	return 0;
}

