/*
 *	Interfacing with pppd daemon
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>
#include <sys/stat.h>
#include <ctype.h>

#include <wicked/util.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>
#include <wicked/netinfo.h>
#include <wicked/ppp.h>

#include "dbus-dict.h"
#include "dbus-common.h"
#include "dbus-objects/model.h"
#include "util_priv.h"
#include "systemctl.h"
#include "process.h"
#include "pppd.h"

#define NI_PPPD_DAEMON_NAME		"pppd"

#define NI_PPPD_CONFIG_DIR_MODE		0700
#define NI_PPPD_CONFIG_FILE_MODE	0600
#define NI_PPPD_CONFIG_FILE_FMT		"options.%s"

#define NI_PPPD_SERVICE_FMT		"wickedd-pppd@%s.service"

#define NI_PPPD_PLUGIN_PPPOE		"rp-pppoe.so"

#define NI_PPPD_PRE_START		"/etc/ppp/pre-start"
#define NI_PPPD_POST_STOP		"/etc/ppp/post-stop"


/*
 * pppd startup config file
 */
static inline const char *
ni_pppd_config_file_dir(char **path)
{
	if (!path)
		return NULL;

	return ni_string_printf(path, "%s/"NI_PPPD_DAEMON_NAME, ni_config_statedir());
}

static inline const char *
ni_pppd_config_file_name(char **filename, const char *instance)
{
	char *path = NULL;
	const char *ret;

	if (!filename || ni_string_empty(instance))
		return NULL;

	if (!ni_pppd_config_file_dir(&path))
		return NULL;

	ret = ni_string_printf(filename, "%s/"NI_PPPD_CONFIG_FILE_FMT, path, instance);

	ni_string_free(&path);
	return ret;
}

static ni_bool_t
ni_pppd_config_pppoe_dump(ni_stringbuf_t *dump, const ni_ppp_mode_pppoe_t *pppoe)
{
	if (!dump || !pppoe)
		return FALSE;

	/* Append PPPoE plugin directive */
	ni_stringbuf_printf(dump, "plugin %s\n",NI_PPPD_PLUGIN_PPPOE);

	/* Append PPPoE ethernet device */
	if (ni_string_empty(pppoe->device.name)) {
		ni_error("empty PPPoE ethernet device");
		return FALSE;
	}
	ni_stringbuf_printf(dump, "%s\n", pppoe->device.name);

	return TRUE;
}

static ni_bool_t
ni_pppd_config_auth_dump(ni_stringbuf_t *dump, const ni_ppp_auth_config_t *auth)
{
	/* Append PPP hosrname (optional) */
	if (!ni_string_empty(auth->hostname))
		ni_stringbuf_printf(dump, "name \"%s\"\n", auth->hostname);

	/* Append PPP username */
	if (ni_string_empty(auth->username)) {
		ni_error("empty PPP username");
		return FALSE;
	}
	ni_stringbuf_printf(dump, "user \"%s\"\n", auth->username);

	/* Append PPP password */
	if (ni_string_empty(auth->password)) {
		ni_error("empty PPP password");
		return FALSE;
	}
	ni_stringbuf_printf(dump, "password \"%s\"\n", auth->password);

	return TRUE;
}

static ni_bool_t
ni_pppd_config_ipv4_dump(ni_stringbuf_t *dump, const ni_ppp_config_t *config)
{
	char *local_ip = NULL;
	char *remote_ip = NULL;

	if (ni_sockaddr_is_specified(&config->ipv4.local_ip))
		ni_string_dup(&local_ip,  ni_sockaddr_print(&config->ipv4.local_ip));
	if (ni_sockaddr_is_specified(&config->ipv4.remote_ip))
		ni_string_dup(&remote_ip,  ni_sockaddr_print(&config->ipv4.remote_ip));

	if (!ni_string_empty(local_ip) && !ni_string_empty(remote_ip))
		ni_stringbuf_printf(dump, "%s:%s\n", local_ip, remote_ip);
	else if (!ni_string_empty(local_ip))
		ni_stringbuf_printf(dump, "%s:\n", local_ip);
	else if (!ni_string_empty(remote_ip))
		ni_stringbuf_printf(dump, ":%s\n", remote_ip);

	ni_string_free(&local_ip);
	ni_string_free(&remote_ip);

	if (config->ipv4.ipcp.accept_local)
		ni_stringbuf_puts(dump, "ipcp-accept-local\n");
	if (config->ipv4.ipcp.accept_remote)
		ni_stringbuf_puts(dump, "ipcp-accept-remote\n");

	return TRUE;
}

static ni_bool_t
ni_pppd_config_ipv6_dump(ni_stringbuf_t *dump, const ni_ppp_config_t *config)
{
	char *local_ip = NULL;
	char *remote_ip = NULL;

	if (!config->ipv6.enabled) {
		ni_stringbuf_puts(dump, "noipv6");
		return TRUE;
	}

	if (ni_sockaddr_is_specified(&config->ipv6.local_ip))
		ni_string_dup(&local_ip,  ni_sockaddr_print(&config->ipv6.local_ip));
	if (ni_sockaddr_is_specified(&config->ipv6.remote_ip))
		ni_string_dup(&remote_ip,  ni_sockaddr_print(&config->ipv6.remote_ip));

	if (!config->demand)
		ni_stringbuf_puts(dump, "+ipv6\n");

	if (!ni_string_empty(local_ip) && !ni_string_empty(remote_ip)) {
		/* demand requires local + remote id;
		 * otherwise pppd refuses to start */
		if (config->demand)
			ni_stringbuf_puts(dump, "+ipv6\n");
		ni_stringbuf_printf(dump, "ipv6 %s,%s\n", local_ip, remote_ip);
	}
	else if (!ni_string_empty(local_ip))
		ni_stringbuf_printf(dump, "ipv6 %s,\n", local_ip);
	else if (!ni_string_empty(remote_ip))
		ni_stringbuf_printf(dump, "ipv6 ,%s\n", remote_ip);

	ni_string_free(&local_ip);
	ni_string_free(&remote_ip);

	if (config->ipv6.ipcp.accept_local)
		ni_stringbuf_puts(dump, "ipv6cp-accept-local\n");

	return TRUE;
}

static ni_bool_t
ni_pppd_config_dump(ni_stringbuf_t *dump, const ni_ppp_config_t *config)
{
	if (config->debug)
		ni_stringbuf_printf(dump, "debug\n");
	if (config->demand)
		ni_stringbuf_printf(dump, "demand\n");
	if (config->persist)
		ni_stringbuf_printf(dump, "persist\n");
	else
		ni_stringbuf_printf(dump, "nopersist\n");

	if (config->idle != -1U)
		ni_stringbuf_printf(dump, "idle %u\n", config->idle);
	if (config->maxfail != -1U)
		ni_stringbuf_printf(dump, "maxfail %u\n", config->maxfail);
	if (config->holdoff != -1U)
		ni_stringbuf_printf(dump, "holdoff %u\n", config->holdoff);

	if (config->dns.usepeerdns)
		ni_stringbuf_printf(dump, "usepeerdns\n");
#if 0
	if (ni_sockaddr_is_ipv4_specified(&config->dns.dns1))
		ni_stringbuf_printf(dump, "ms-dns", ni_sockaddr_print(&config->dns.dns1));
	if (ni_sockaddr_is_ipv4_specified(&config->dns.dns2))
		ni_stringbuf_printf(dump, "ms-dns", ni_sockaddr_print(&config->dns.dns2));
#endif

	if (config->defaultroute) {
		ni_stringbuf_printf(dump, "defaultroute\n");
		ni_stringbuf_printf(dump, "replacedefaultroute\n");
	}

	if (config->multilink)
		ni_stringbuf_puts(dump, "multilink\n");

	if (!ni_string_empty(config->endpoint))
		ni_stringbuf_printf(dump, "endpoint %s\n", config->endpoint);

	if (!ni_pppd_config_auth_dump(dump, &config->auth))
		return FALSE;

	if (!ni_pppd_config_ipv4_dump(dump, config))
		return FALSE;

	if (!ni_pppd_config_ipv6_dump(dump, config))
		return FALSE;

	return TRUE;
}

static int
ni_pppd_config_file_dump(FILE *fp, const char *instance, const ni_ppp_t *ppp)
{
	ni_stringbuf_t dump = NI_STRINGBUF_INIT_DYNAMIC;
	ni_ppp_mode_type_t type;
	int ret = -1;

	if (!fp || ni_string_empty(instance) || !ppp)
		return ret;

	type = ppp->mode.type;
	switch(type) {
	case NI_PPP_MODE_PPPOE:
		if (!ni_pppd_config_pppoe_dump(&dump, &ppp->mode.pppoe))
			goto done;
		break;
	default:
		ni_error("%s: unsupported ppp mode %s (%d):", instance, ni_ppp_mode_type_to_name(type), type);
		goto done;
	}

	ni_stringbuf_printf(&dump, "linkname %s\n", instance);

	if (!ni_pppd_config_dump(&dump, &ppp->config))
		goto done;

	if (fprintf(fp, "%s", dump.string) < 0)
		goto done;

	ret = 0;
done:
	ni_stringbuf_destroy(&dump);
	return ret;
}

static ni_bool_t
do_pppd_config_file_read_options_plugin(ni_ppp_mode_t *mode, const char *opt)
{
	if (!mode || !opt)
		return FALSE;

	if (ni_string_contains(opt, "pppoe")) {
		ni_ppp_mode_init(mode, NI_PPP_MODE_PPPOE);
		return TRUE;
	} else {
		return FALSE;
	}
}

static int
do_pppd_config_file_read_options_ipv4(ni_ppp_config_t *conf, const char *opt)
{
	ni_string_array_t sa_ip = NI_STRING_ARRAY_INIT;
	int rv = 0; /* Not detected */

	if (!conf || ni_string_empty(opt))
		return -1;

	if (isdigit((unsigned char)opt[0]) && ni_string_contains(opt, ":")) {
		const char *local_ip;
		const char *remote_ip;

		if (ni_string_split(&sa_ip, opt, ":", 2) < 1) {
			/* Just skip in case it's not the local_ip:remote_ip entry */
			goto done;
		}

		local_ip = sa_ip.data[0];
		if (!ni_string_empty(local_ip)) {
			if (ni_sockaddr_parse(&conf->ipv4.local_ip, local_ip, AF_INET) < 0) {
				rv = -1;
				goto done;
			}
		}

		if (sa_ip.count > 1 && !ni_string_empty((remote_ip = sa_ip.data[1]))) {
			if (ni_sockaddr_parse(&conf->ipv4.remote_ip, remote_ip, AF_INET) < 0) {
				rv = -1;
				goto done;
			}
		}

		rv = 1; /* Detected */
	}

done:
	ni_string_array_destroy(&sa_ip);
	return rv;
}

static ni_bool_t
do_pppd_config_file_read_options_ipv6(ni_ppp_config_t *conf, const char *opt)
{
	ni_string_array_t sa_ip = NI_STRING_ARRAY_INIT;
	ni_bool_t rv = FALSE;

	if (!conf || ni_string_empty(opt))
		return rv;

	if (ni_string_contains(opt, ",") && ni_string_split(&sa_ip, opt, ",", 2)) {
		const char *local_ip = sa_ip.data[0];
		const char *remote_ip = NULL;

		if (!ni_string_empty(local_ip)) {
			if (ni_sockaddr_parse(&conf->ipv6.local_ip, local_ip, AF_INET6) < 0)
				goto done;
		}

		if (sa_ip.count > 1 && !ni_string_empty((remote_ip = sa_ip.data[1]))) {
			if (ni_sockaddr_parse(&conf->ipv6.remote_ip, remote_ip, AF_INET6) < 0)
				goto done;
		}

		rv = TRUE;
	}

done:
	ni_string_array_destroy(&sa_ip);
	return rv;
}

static inline ni_bool_t
ni_pppd_config_file_read_line(const char **name, char **value, ni_stringbuf_t *line)
{
	char *ptr;
	size_t len;

	if (!line->len)
		return FALSE;

	ptr = line->string;
	/* strip leading name spaces */
	while (isspace((unsigned char)*ptr))
		++ptr;

	if (*ptr == '#' || ni_string_empty(ptr))
		return FALSE;

	*name = ptr;
	/* terminate end of the name */
	len = strcspn(ptr, " \t");
	ptr = ptr + len;
	*ptr++ = '\0';

	if (ni_string_empty(*name))
		return FALSE;

	/* strip leading value spaces */
	while (isspace((unsigned char)*ptr))
		++ptr;

	/* strip trailing value spaces */
	len = ni_string_len(ptr);
	while (len && isspace((unsigned char)ptr[len - 1]))
		ptr[--len] = '\0';

	if (len)
		*value = ni_unquote((const char **)&ptr, NULL);
	return TRUE;
}

static int
ni_pppd_config_file_read(const char *instance, ni_ppp_t *ppp)
{
	ni_var_array_t opts = NI_VAR_ARRAY_INIT;
	ni_stringbuf_t line = NI_STRINGBUF_INIT_DYNAMIC;
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_ppp_auth_config_t *auth;
	ni_ppp_config_t *conf;
	char buffer[256];
	char *filename = NULL;
	unsigned int pos;
	ni_var_t *var;
	FILE *fp;
	int rv = -1;

	if (!ppp || ni_string_empty(instance))
		return rv;

	if (!ni_pppd_config_file_name(&filename, instance)) {
		ni_error("%s: cannot create pppd config file name", instance);
		goto done;
	}

	if (!(fp = fopen(filename, "r"))) {
		ni_debug_ifconfig("cannot open %s: %m", filename);
		goto done;
	}

	memset(buffer, 0, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		const char *name;
		char *value, *eol;
		size_t len;

		len = strcspn(buffer, "\r\n");
		eol = buffer + len;
		if (*eol == '\0') {
			ni_stringbuf_put(&line, buffer, len);
			continue;
		}
		*eol = '\0';
		ni_stringbuf_put(&line, buffer, len);

		name = NULL;
		value = NULL;
		if (ni_pppd_config_file_read_line(&name, &value, &line)) {
#if 0			/* warning: this could expose secrets in the log */
			ni_debug_verbose(NI_LOG_DEBUG, NI_TRACE_READWRITE,
					"%s: set option: %s=%s", filename,
					name, value);
#endif
			ni_var_array_set(&opts, name, value);
		}
		free(value);
		ni_stringbuf_destroy(&line);
	}
	fclose(fp);

	conf = &ppp->config;
	auth = &conf->auth;
	conf->ipv6.ipcp.accept_local = FALSE;
	conf->ipv4.ipcp.accept_local = FALSE;
	conf->ipv4.ipcp.accept_remote = FALSE;
	for (pos = 0; pos < opts.count; ++pos) {
		var = &opts.data[pos];

		if (ni_string_eq(var->name, "plugin")) {
			if (!do_pppd_config_file_read_options_plugin(&ppp->mode, var->value))
				goto done;
		} else
		if (ni_string_eq(var->name, "name")) {
			if (!ni_string_dup(&auth->hostname, var->value))
				goto done;
		} else
		if (ni_string_eq(var->name, "user")) {
			if (!ni_string_dup(&auth->username, var->value))
				goto done;
		} else
		if (ni_string_eq(var->name, "password")) {
			ni_var_array_remove_at(&opts, pos--);
			/* ignore */
		} else
		if (ni_string_eq(var->name, "usepeerdns")) {
			conf->dns.usepeerdns = TRUE;
		} else
		if (ni_string_eq(var->name, "ms-dns")) {
#if 0
			if (!ni_sockaddr_is_specified(&conf->dns.dns1))
				ni_sockaddr_parse(&conf->dns.dns2, var->value, AF_INET);
			else
			if (!ni_sockaddr_is_specified(&conf->dns.dns2))
				ni_sockaddr_parse(&conf->dns.dns2, var->value, AF_INET);
#endif
		} else
		if (ni_string_eq(var->name, "persist")) {
			conf->persist = TRUE;
		} else
		if (ni_string_eq(var->name, "nopersist")) {
			conf->persist = FALSE;
		} else
		if (ni_string_eq(var->name, "defaultroute") ||
		    ni_string_eq(var->name, "replacedefaultroute")) {
			conf->defaultroute = TRUE;
		} else
		if (ni_string_eq(var->name, "debug")) {
			conf->debug = TRUE;
		} else
		if (ni_string_eq(var->name, "demand")) {
			conf->demand = TRUE;
		} else
		if (ni_string_eq(var->name, "multilink")) {
			conf->multilink = TRUE;
		} else
		if (ni_string_eq(var->name, "endpoint")) {
			if (!ni_string_dup(&conf->endpoint, var->value))
				goto done;
		} else
		if (ni_string_eq(var->name, "idle")) {
			if (ni_parse_uint(var->value, &conf->idle, 10))
				goto done;
		} else
		if (ni_string_eq(var->name, "holdoff")) {
			if (ni_parse_uint(var->value, &conf->holdoff, 10))
				goto done;
		} else
		if (ni_string_eq(var->name, "maxfail")) {
			if (ni_parse_uint(var->value, &conf->maxfail, 10))
				goto done;
		} else
		if (ni_string_eq(var->name, "linkname")) {
			/* Ignored as we have it already in netdev */
		} else
		if (ni_string_eq(var->name, "connect")) {
			/* Ignore */
		} else
		if (ni_string_eq(var->name, "noipv6")) {
			conf->ipv6.enabled = FALSE;
		} else
		if (ni_string_eq(var->name, "+ipv6")) {
			conf->ipv6.enabled = TRUE;
		} else
		if (ni_string_eq(var->name, "ipcp-accept-local")) {
			conf->ipv4.ipcp.accept_local = TRUE;
		} else
		if (ni_string_eq(var->name, "ipcp-accept-remote")) {
			conf->ipv4.ipcp.accept_remote = TRUE;
		} else
		if (ni_string_eq(var->name, "ipv6cp-accept-local")) {
			conf->ipv6.ipcp.accept_local = TRUE;
		} else
		if (ni_string_eq(var->name, "ipv6")) {
			if (!do_pppd_config_file_read_options_ipv6(conf, var->value))
				goto done;
		} else
		if (ni_string_empty(var->value)) {
			ni_netdev_t *dev;

			if (do_pppd_config_file_read_options_ipv4(conf, var->name) < 0)
				goto done;

			if (nc && (dev = ni_netdev_by_name(nc, var->name)))
				ni_netdev_ref_init(&ppp->mode.pppoe.device,
						dev->name, dev->link.ifindex);
		}
	}

	rv = 0;
done:
	if (rv == -1)
		ni_warn("%s: unable to parse options file %s", instance, filename);

	ni_string_free(&filename);
	ni_stringbuf_destroy(&line);
	ni_var_array_destroy(&opts);
	return rv;
}

static int
ni_pppd_config_file_write(const char *instance, const ni_ppp_t *config)
{
	char *dirname = NULL;
	char *filename = NULL;
	char tempname[PATH_MAX] = {'\0'};
	FILE *fp = NULL;
	int fd, ret = -1;

	if (ni_string_empty(instance) || !config)
		return -1;

	if (!ni_pppd_config_file_dir(&dirname))
		return -1;

	if (ni_mkdir_maybe(dirname, NI_PPPD_CONFIG_DIR_MODE) < 0) {
		ni_error("Cannot create pppd run directory \"%s\": %m", dirname);
		goto done;
	}

	if (!ni_pppd_config_file_name(&filename, instance)) {
		ni_error("%s: cannot create pppd config file name", instance);
		goto done;
	}

	snprintf(tempname, sizeof(tempname), "%s.XXXXXX", filename);
	if ((fd = mkstemp(tempname)) < 0) {
		ni_error("%s: cannot create temporary pppd config '%s': %m", instance, tempname);
		goto done;
	}

	if ((fp = fdopen(fd, "we")) == NULL) {
		ni_error("%s: cannot reopen temporary pppd config '%s': %m", instance, tempname);
		close(fd);
		unlink(tempname);
		goto done;
	}

	if (ni_pppd_config_file_dump(fp, instance, config) < 0) {
		ni_error("%s: unable to generate pppd config file for '%s'", instance, filename);
		fclose(fp);
		unlink(tempname);
		goto done;
	}
	fflush(fp);

	if (fchmod(fd, NI_PPPD_CONFIG_FILE_MODE) < 0) {
		ni_error("Unable to change permissions of %s (%m)\n", filename);
		fclose(fp);
		unlink(tempname);
		goto done;
	}
	fclose(fp);

	if (rename(tempname, filename) != 0) {
		ni_error("%s: unable to commit pppd config file to '%s'", instance, filename);
		fclose(fp);
		unlink(tempname);
		goto done;
	}

	ni_debug_ifconfig("%s: pppd config file written to '%s'", instance, filename);
	ret = 0;

done:
	ni_string_free(&filename);
	ni_string_free(&dirname);
	return ret;
}

int
ni_pppd_config_file_remove(const char *instance)
{
	char *filename = NULL;
	int ret;

	if (!ni_pppd_config_file_name(&filename, instance))
		return -1;

	ret = unlink(filename);
	free(filename);
	return ret;
}

/*
 * pppd systemd instance service methods
 */
 static inline const char *
ni_pppd_service_show_property(const char *ifname, const char *property, char **result)
{
	char *service = NULL;
	const char *ret;

	/*
	 * systemctl --no-pager -p ${property} show pppd@${ifname}.service
	 *  -->	${property}=...
	 */
	ni_string_printf(&service, NI_PPPD_SERVICE_FMT, ifname);
	ret = ni_systemctl_service_show_property(service, property, result);

	ni_string_free(&service);
	return ret;
}

static int
ni_pppd_service_running_state(const char *ifname)
{
	char *state = NULL;
	int rv = 0; /* Not running */

	if (!ni_netdev_name_to_index(ifname))
		return rv;

	if (!ni_pppd_service_show_property(ifname, "SubState", &state))
		rv = -1; /* Error */
	else if (ni_string_eq(state, "running"))
		rv = 1; /* Running */

	ni_string_free(&state);
	return rv;
}

int
ni_pppd_discover(ni_netdev_t *dev, ni_netconfig_t *nc)
{
	ni_ppp_t *ppp;

	if (!dev || dev->link.type != NI_IFTYPE_PPP)
		return -1;

	if (!(ppp = ni_ppp_new()))
		goto failure;

	if (ni_string_empty(dev->name))
		goto failure;

	if (ni_pppd_service_running_state(dev->name) <= 0)
		goto failure;

	if (ni_pppd_config_file_read(dev->name, ppp) < 0)
		goto failure;

	ni_netdev_set_ppp(dev, ppp);
	return 0;

failure:
	ni_ppp_free(ppp);
	return -1;
}

static inline int
ni_pppd_call_pre_start(const ni_netdev_t *cfg)
{
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, NI_PPPD_PRE_START))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, cfg->name))
		goto failure;

	ni_shellcmd_setenv(cmd, "IFNAME", cfg->name);
	ni_shellcmd_setenv(cmd, "LINKNAME", cfg->name);

	switch (cfg->ppp->mode.type) {
	case NI_PPP_MODE_PPPOE:
		if (!ni_shellcmd_add_arg(cmd, cfg->ppp->mode.pppoe.device.name))
			goto failure;
		ni_shellcmd_setenv(cmd, "DEVICE", cfg->ppp->mode.pppoe.device.name);
		break;
	default:
		if (!ni_shellcmd_add_arg(cmd, ""))
			goto failure;
		break;
	}

	if (!ni_shellcmd_add_arg(cmd, "0"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "0.0.0.0"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "0.0.0.0"))
		goto failure;

	if (ni_sockaddr_is_specified(&cfg->ppp->config.dns.dns1))
		ni_shellcmd_setenv(cmd, "DNS1", ni_sockaddr_print(&cfg->ppp->config.dns.dns1));
	if (ni_sockaddr_is_specified(&cfg->ppp->config.dns.dns2))
		ni_shellcmd_setenv(cmd, "DNS2", ni_sockaddr_print(&cfg->ppp->config.dns.dns2));

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

static inline int
ni_pppd_call_post_stop(const char *ifname)
{
	ni_shellcmd_t *cmd;
	ni_process_t *pi;
	int rv;

	if (!(cmd = ni_shellcmd_new(NULL)))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, NI_PPPD_POST_STOP))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, ifname))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, ""))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "0"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "0.0.0.0"))
		goto failure;

	if (!ni_shellcmd_add_arg(cmd, "0.0.0.0"))
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
ni_pppd_service_start(const ni_netdev_t *cfg)
{
	char *service = NULL;
	int rv;

	if (!cfg || ni_string_empty(cfg->name) || !cfg->ppp)
		return -1;

	rv = ni_pppd_service_running_state(cfg->name);
	if (rv)
		return rv;

	if (ni_pppd_config_file_write(cfg->name, cfg->ppp) < 0)
		return -1;

	(void)ni_pppd_call_pre_start(cfg);

	ni_string_printf(&service, NI_PPPD_SERVICE_FMT, cfg->name);
	rv = ni_systemctl_service_start(service);
	if (rv < 0) {
		ni_pppd_config_file_remove(cfg->name);
		ni_pppd_call_post_stop(cfg->name);
	}

	ni_string_free(&service);
	return rv;
}

int
ni_pppd_service_stop(const char *ifname)
{
	char *service = NULL;
	int rv;

	ni_string_printf(&service, NI_PPPD_SERVICE_FMT, ifname);
	rv = ni_systemctl_service_stop(service);
	ni_pppd_config_file_remove(ifname);
	ni_pppd_call_post_stop(ifname);

	ni_string_free(&service);
	return rv;
}
