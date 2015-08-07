/*
 *	Interfacing with teamd through dbus interface
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
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>

#include <wicked/util.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/netinfo.h>
#include <wicked/team.h>

#include "dbus-dict.h"
#include "dbus-common.h"
#include "dbus-objects/model.h"
#include "util_priv.h"
#include "process.h"
#include "teamd.h"


#define NI_TEAMD_CONFIG_DIR			"/run/teamd"
#define NI_TEAMD_CONFIG_FMT			NI_TEAMD_CONFIG_DIR"/%s.conf"

#define NI_TEAMD_BUS_NAME			"org.libteam.teamd"
#define NI_TEAMD_OBJECT_PATH			"/org/libteam/teamd"
#define NI_TEAMD_INTERFACE			"org.libteam.teamd"

#define NI_TEAMD_CALL_CONFIG_DUMP		"ConfigDump"
#define NI_TEAMD_CALL_CONFIG_DUMP_ACTUAL	"ConfigDumpActual"

#define NI_TEAMD_CALL_STATE_DUMP		"StateDump"
#define NI_TEAMD_CALL_STATE_ITEM_GET		"StateItemValueGet"
#define NI_TEAMD_CALL_STATE_ITEM_SET		"StateItemValueSet"


struct ni_teamd_client {
	ni_dbus_client_t *	dbus;

	ni_dbus_object_t *	proxy;
};

static void			ni_teamd_dbus_signal(ni_dbus_connection_t *, ni_dbus_message_t *, void *);

static ni_dbus_class_t		ni_objectmodel_teamd_client_class = {
	"teamd-client"
};
#if 0
static ni_dbus_class_t		ni_objectmodel_teamd_device_class = {
	"teamd-device"
};
#endif

static const ni_intmap_t	ni_teamd_error_names[] = {
	{ NULL,			-1			}
};

ni_teamd_client_t *
ni_teamd_client_open(const char *ifname)
{
	ni_dbus_client_t *dbc;
	ni_teamd_client_t *tdc;
	char *service_name = NULL;

	if (ni_string_empty(ifname))
		return NULL;

	ni_string_printf(&service_name, NI_TEAMD_BUS_NAME".%s", ifname);
	dbc = ni_dbus_client_open("system", service_name);
	ni_string_free(&service_name);
	if (!dbc)
		return NULL;

	ni_dbus_client_set_error_map(dbc, ni_teamd_error_names);

	tdc = xcalloc(1, sizeof(*tdc));
	tdc->proxy = ni_dbus_client_object_new(dbc, &ni_objectmodel_teamd_client_class,
			NI_TEAMD_OBJECT_PATH, NI_TEAMD_INTERFACE, tdc);
	tdc->dbus = dbc;

	ni_dbus_client_add_signal_handler(dbc,
				NI_TEAMD_BUS_NAME,	/* sender */
				NULL,			/* object path */
				NI_TEAMD_INTERFACE,	/* object interface */
				ni_teamd_dbus_signal,
				tdc);
	return tdc;
}

void
ni_teamd_client_free(ni_teamd_client_t *tdc)
{
	if (tdc) {
		if (tdc->dbus) {
			ni_dbus_client_free(tdc->dbus);
			tdc->dbus = NULL;
		}

		/* while (tdc->iflist) */

		if (tdc->proxy) {
			ni_dbus_object_free(tdc->proxy);
			tdc->proxy = NULL;
		}

		free(tdc);
	}
}

#if 0
ni_dbus_client_t *
ni_teamd_client_dbus(ni_teamd_client_t *tdc)
{
	return tdc->dbus;
}
#endif

static void
ni_teamd_dbus_signal(ni_dbus_connection_t *connection, ni_dbus_message_t *msg, void *user_data)
{
	/* ni_teamd_client_t *tdc = user_data; */
	const char *member = dbus_message_get_member(msg);

	ni_debug_dbus("teamd-client: %s signal received (not handled)", member);
}

/*
 * teamd instance dbus access methods
 */
const char *
ni_teamd_ctl_config_dump(ni_teamd_client_t *tdc, ni_bool_t actual)
{
	const char *method;
	char *dump;
	int rv;

	if (!tdc)
		return NULL;

	method =  actual ? NI_TEAMD_CALL_CONFIG_DUMP_ACTUAL :
		NI_TEAMD_CALL_CONFIG_DUMP;
	rv = ni_dbus_object_call_simple(tdc->proxy,
 				NI_TEAMD_INTERFACE, method,
				0, NULL,
				DBUS_TYPE_STRING, &dump);

	if (rv < 0) {
		ni_debug_application("Call to %s.%s() failed: %s",
			ni_dbus_object_get_path(tdc->proxy), method, ni_strerror(rv));
		return NULL;
	}

	return dump;
}

const char *
ni_teamd_ctl_state_dump(ni_teamd_client_t *tdc)
{
	char *dump;
	int rv;

	if (!tdc)
		return NULL;

	rv = ni_dbus_object_call_simple(tdc->proxy,
				NI_TEAMD_INTERFACE, NI_TEAMD_CALL_STATE_DUMP,
				0, NULL,
				DBUS_TYPE_STRING, &dump);

	if (rv < 0) {
		ni_debug_application("Call to %s."NI_TEAMD_CALL_STATE_DUMP"() failed: %s",
			ni_dbus_object_get_path(tdc->proxy), ni_strerror(rv));
		return NULL;
	}

	return dump;
}

const char *
ni_teamd_ctl_state_get_item(ni_teamd_client_t *tdc, const char *item_name)
{
	char *state_item;
	int rv;

	if (!tdc || ni_string_empty(item_name))
		return NULL;

	rv = ni_dbus_object_call_simple(tdc->proxy,
				NI_TEAMD_INTERFACE, NI_TEAMD_CALL_STATE_ITEM_GET,
				DBUS_TYPE_STRING, &item_name,
				DBUS_TYPE_STRING, &state_item);

	if (rv < 0) {
		ni_debug_application("Call to %s."NI_TEAMD_CALL_STATE_ITEM_GET"(%s) failed: %s",
			ni_dbus_object_get_path(tdc->proxy), item_name, ni_strerror(rv));
		return NULL;
	}

	return state_item;
}

int
ni_teamd_ctl_state_set_item(ni_teamd_client_t *tdc, const char *item_name, const char *item_val)
{
	ni_dbus_message_t *call, *reply;
	DBusError error;
	int rv = 0;

	if (!tdc || ni_string_empty(item_name))
		return -NI_ERROR_INVALID_ARGS;

	dbus_error_init(&error);

	call = ni_dbus_object_call_new(tdc->proxy, NI_TEAMD_CALL_STATE_ITEM_SET, 0);
	ni_dbus_message_append_string(call, item_name);
	ni_dbus_message_append_string(call, item_val);
	if ((reply = ni_dbus_client_call(tdc->dbus, call, &error)) == NULL) {
		rv = -NI_ERROR_DBUS_CALL_FAILED;
		if (dbus_error_is_set(&error))
			rv = ni_dbus_client_translate_error(tdc->dbus, &error);
	}

	if (rv < 0) {
		ni_debug_application("Call to %s."NI_TEAMD_CALL_STATE_ITEM_SET"(%s) failed: %s",
			ni_dbus_object_get_path(tdc->proxy), item_name, ni_strerror(rv));
	}

	return rv;
}


/*
 * teamd startup config file
 */
const char *
ni_teamd_config_file_name(char **filename, const char *instance)
{
	return ni_string_printf(filename, NI_TEAMD_CONFIG_FMT, instance);
}

int
ni_teamd_config_file_dump(FILE *fp, const char *instance, const ni_team_t *config)
{
	if (!fp || ni_string_empty(instance) || !config)
		return -1;

	fprintf(fp, "{\n");
	fprintf(fp, "\t\"device\": \"%s\",\n", instance);
	fprintf(fp, "\t\"runner\": {\n");
	fprintf(fp, "\t\t\"name\": \"%s\"\n", ni_team_mode_type_to_name(config->mode));
	fprintf(fp, "\t}\n");
	fprintf(fp, "}\n");

	return 0;
}

int
ni_teamd_config_file_write(const char *instance, const ni_team_t *config)
{
	char *filename = NULL;
	char tempname[PATH_MAX] = {'\0'};
	FILE *fp = NULL;
	int fd;

	if (ni_string_empty(instance) || !config)
		return -1;

	if (!ni_teamd_config_file_name(&filename, instance)) {
		ni_error("%s: cannot create teamd config file name", instance);
		return -1;
	}

	snprintf(tempname, sizeof(tempname), "%s.XXXXXX", filename);
	if ((fd = mkstemp(tempname)) < 0) {
		ni_error("%s: cannot create temporary teamd config '%s': %m", instance, tempname);
		free(filename);
		return -1;
	}

	if ((fp = fdopen(fd, "we")) == NULL) {
		ni_error("%s: cannot reopen temporary teamd config '%s': %m", instance, tempname);
		close(fd);
		unlink(tempname);
		free(filename);
		return -1;
	}

	if (ni_teamd_config_file_dump(fp, instance, config) < 0) {
		ni_error("%s: unable to generate teamd config file for '%s'", instance, filename);
		fclose(fp);
		unlink(tempname);
		free(filename);
		return -1;
	}
	fflush(fp);
	fclose(fp);

	if ((fd = rename(tempname, filename)) != 0) {
		ni_error("%s: unable to commit teamd config file to '%s'", instance, filename);
		unlink(tempname);
		free(filename);
		return -1;
	}

	ni_debug_ifconfig("%s: teamd config file written to '%s'", instance, filename);
        free(filename);
	return 0;
}

int
ni_teamd_config_file_remove(const char *instance)
{
	char *filename = NULL;
	int ret;

	if (!ni_teamd_config_file_name(&filename, instance))
		return -1;

	ret = unlink(filename);
	free(filename);
	return ret;
}

const char *ni_systemctl_tool_path()
{
	static const char *paths[] = {
		"/usr/bin/systemctl",
		"/bin/systemctl",
		NULL
	};
	return ni_find_executable(paths);
}

/*
 * teamd systemd instance service methods
 */
int
ni_teamd_service_start(const char *instance, const ni_team_t *config)
{
	const char *systemctl;
	char *service = NULL;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv;

	if (ni_string_empty(instance) || !config)
		return -1;

	if (!(systemctl = ni_systemctl_tool_path()))
		return -1;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return -1;

	if (!ni_shellcmd_add_arg(cmd, systemctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "start"))
		goto failure;

	ni_string_printf(&service, "teamd@%s.service", instance);
	if (!service || !ni_shellcmd_add_arg(cmd, service))
		goto failure;

	if (ni_teamd_config_file_write(instance, config) < 0)
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;
	ni_shellcmd_release(cmd);

	rv = ni_process_run_and_wait(pi);
	ni_process_free(pi);
	free(service);

	return rv;

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	if (service)
		free(service);
	return -1;
}

int
ni_teamd_service_stop(const char *instance)
{
	const char *systemctl;
	char *service = NULL;
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv;

	if (ni_string_empty(instance))
		return -1;

	if (!(cmd = ni_shellcmd_new(NULL)))
		return -1;

	if (!(systemctl = ni_systemctl_tool_path()))
		return -1;

	if (!ni_shellcmd_add_arg(cmd, systemctl))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "stop"))
		goto failure;

	ni_string_printf(&service, "teamd@%s.service", instance);
	if (!service || !ni_shellcmd_add_arg(cmd, service))
		goto failure;

	if (!(pi = ni_process_new(cmd)))
		goto failure;
	ni_shellcmd_release(cmd);

	rv = ni_process_run_and_wait(pi);
	ni_process_free(pi);

	ni_teamd_config_file_remove(instance);
	free(service);

	return rv;

failure:
	if (cmd)
		ni_shellcmd_release(cmd);
	if (service)
		free(service);
	return -1;
}

