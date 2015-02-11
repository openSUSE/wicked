/*
 *	Translation between internal representation and SUSE ifcfg files
 *
 *	Copyright (C) 2010-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *		Olaf Kirch <okir@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netlink/netlink.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include <wicked/address.h>
#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/sysconfig.h>
#include <wicked/addrconf.h>
#include <wicked/netinfo.h>
#include <wicked/route.h>
#include <wicked/xml.h>
#include <wicked/ethernet.h>
#include <wicked/infiniband.h>
#include <wicked/bonding.h>
#include <wicked/bridge.h>
#include <wicked/vlan.h>
#include <wicked/macvlan.h>
#include <wicked/wireless.h>
#include <wicked/fsm.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/tuntap.h>
#include <wicked/tunneling.h>

#include <wicked/objectmodel.h>
#include <wicked/dbus.h>
#include "appconfig.h"
#include "util_priv.h"
#include "duid.h"
#include "client/suse/ifsysctl.h"
#include "client/wicked-client.h"

typedef ni_bool_t (*try_function_t)(const ni_sysconfig_t *, ni_netdev_t *, const char *);

static ni_compat_netdev_t *	__ni_suse_read_interface(const char *, const char *);
static ni_bool_t		__ni_suse_read_globals(const char *, const char *);
static void			__ni_suse_free_globals(void);
static void			__ni_suse_show_unapplied_routes(void);
static ni_bool_t		__ni_suse_sysconfig_read(ni_sysconfig_t *, ni_compat_netdev_t *);
static int			__process_indexed_variables(const ni_sysconfig_t *, ni_netdev_t *,
							const char *, try_function_t);
static ni_var_t *		__find_indexed_variable(const ni_sysconfig_t *, const char *, const char *);
static ni_bool_t		__ni_suse_read_routes(ni_route_table_t **, const char *, const char *);
static ni_bool_t		__ni_wireless_parse_wep_auth(const ni_sysconfig_t *, ni_wireless_network_t *,
							const char *, const char *, ni_bool_t);
static int			__ni_wireless_parse_auth_proto(const ni_sysconfig_t *, ni_wireless_auth_mode_t *,
							const char *, const char *);
static int			__ni_wireless_parse_cipher(const ni_sysconfig_t *, ni_wireless_cipher_t *,
							const char *, const char *, const char *);
static ni_bool_t		__ni_wireless_parse_psk_auth(const ni_sysconfig_t *, ni_wireless_network_t *,
							const char *, const char *, ni_wireless_ap_scan_mode_t);
static ni_bool_t		__ni_wireless_parse_eap_auth(const ni_sysconfig_t *, ni_wireless_network_t *,
							const char *, const char *, ni_wireless_ap_scan_mode_t);
static ni_bool_t		__ni_suse_parse_dhcp4_user_class(const ni_sysconfig_t *, ni_compat_netdev_t *, const char *);

static char *			__ni_suse_default_hostname;
static ni_sysconfig_t *		__ni_suse_config_defaults;
static ni_sysconfig_t *		__ni_suse_dhcp_defaults;
static ni_route_table_t *	__ni_suse_global_routes;
static ni_var_array_t		__ni_suse_global_ifsysctl;
static ni_bool_t		__ni_ipv6_disbled;

#define __NI_SUSE_SYSCONF_DIR			"/etc"
#define __NI_SUSE_HOSTNAME_FILES		{ __NI_SUSE_SYSCONF_DIR"/hostname", \
						  __NI_SUSE_SYSCONF_DIR"/HOSTNAME", \
						  NULL }
#define __NI_SUSE_SYSCTL_SUFFIX			".conf"
#define __NI_SUSE_SYSCTL_FILE			__NI_SUSE_SYSCONF_DIR"/sysctl.conf"
#define __NI_SUSE_SYSCTL_DIR			__NI_SUSE_SYSCONF_DIR"/sysctl.d"
#define __NI_SUSE_PROC_IPV6_DIR			"/proc/sys/net/ipv6"

#define __NI_SUSE_SYSCONFIG_NETWORK_DIR		__NI_SUSE_SYSCONF_DIR"/sysconfig/network"
#define __NI_SUSE_CONFIG_IFPREFIX		"ifcfg-"
#define __NI_SUSE_CONFIG_GLOBAL			"config"
#define __NI_SUSE_CONFIG_DHCP			"dhcp"
#define __NI_SUSE_ROUTES_IFPREFIX		"ifroute-"
#define __NI_SUSE_ROUTES_GLOBAL			"routes"
#define __NI_SUSE_IFSYSCTL_FILE			"ifsysctl"

#define __NI_VLAN_TAG_MAX			4094
#define __NI_WIRELESS_WPA_PSK_HEX_LEN	64
#define __NI_WIRELESS_WPA_PSK_MIN_LEN	8

static ni_bool_t
__ni_suse_ifcfg_valid_suffix(const char *name, size_t pfxlen)
{
	const char *blacklist[] = {
		"~", ".old", ".bak", ".orig", ".scpmbackup",
		".rpmnew", ".rpmsave", ".rpmorig",
	};
	size_t nlen, slen, i;

	nlen = ni_string_len(name);
	if (nlen <= pfxlen)
		return FALSE;

	for (i = 0; i < sizeof(blacklist)/sizeof(blacklist[0]); ++i) {
		const char *suffix = blacklist[i];

		slen = ni_string_len(suffix);
		if (nlen < slen)
			continue;

		if (ni_string_eq(suffix, name + (nlen - slen)))
			return FALSE;
	}
	return TRUE;
}

static ni_bool_t
__ni_suse_ifcfg_valid_prefix(const char *basename, const char *prefix)
{
	size_t pfxlen;

	if (!basename || !prefix)
		return FALSE;

	pfxlen = strlen(prefix);
	if (strncmp(basename, prefix, pfxlen))
		return FALSE;

	return TRUE;
}

static int
__ni_suse_ifcfg_scan_files(const char *dirname, ni_string_array_t *res)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	const char *pattern = __NI_SUSE_CONFIG_IFPREFIX"*";
	size_t pfxlen = sizeof(__NI_SUSE_CONFIG_IFPREFIX)-1;
	unsigned int i, count = res->count;

	if( !ni_scandir(dirname, pattern, &files))
		return 0;

	for(i = 0; i < files.count; ++i) {
		const char *file = files.data[i];

		if (!__ni_suse_ifcfg_valid_suffix(file, pfxlen)) {
			ni_debug_readwrite("Ignoring blacklisted %sfile: %s",
					__NI_SUSE_CONFIG_IFPREFIX, file);
			continue;
		}

		ni_string_array_append(res, file);
	}
	ni_string_array_destroy(&files);

	return res->count - count;
}

ni_bool_t
__ni_suse_get_ifconfig(const char *root, const char *path, ni_compat_ifconfig_t *result)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	ni_bool_t success = FALSE;
	char *pathname = NULL;
	const char *_path = __NI_SUSE_SYSCONFIG_NETWORK_DIR;
	unsigned int i;

	if (!ni_string_empty(path))
		_path = path;

	if (ni_string_empty(root))
		ni_string_dup(&pathname, _path);
	else
		ni_string_printf(&pathname, "%s%s", root, _path);

	if (ni_isdir(pathname)) {
		if (!__ni_suse_read_globals(root, pathname))
			goto done;

		if (!__ni_suse_ifcfg_scan_files(pathname, &files)) {
			ni_debug_readwrite("No ifcfg files found in %s", pathname);
			success = TRUE;
			goto done;
		}

		for (i = 0; i < files.count; ++i) {
			const char *filename = files.data[i];
			const char *ifname = filename + (sizeof(__NI_SUSE_CONFIG_IFPREFIX)-1);
			char pathbuf[PATH_MAX];
			ni_compat_netdev_t *compat;

			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", pathname, filename);
			if (!(compat = __ni_suse_read_interface(pathbuf, ifname)))
				continue;

			/*
			 * TODO: source should not contain root-dir, ...
			 * Can't change it not without to make the uuid useless.
			 *
			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, filename);
			*/
			ni_compat_netdev_client_state_set(compat->dev, pathbuf);
			ni_compat_netdev_array_append(&result->netdevs, compat);
		}

		if (__ni_suse_config_defaults) {
			extern unsigned int ni_wait_for_interfaces;

			ni_sysconfig_get_integer(__ni_suse_config_defaults,
						"WAIT_FOR_INTERFACES",
						&ni_wait_for_interfaces);
		}
	} else
	if (ni_file_exists(pathname)) {
		ni_error("Cannot use '%s' to read suse ifcfg files -- not a directory",
				pathname);
		goto done;
	} else
	if (!ni_string_empty(path)) {
		ni_error("Configuration directory '%s' does not exist", pathname);
		goto done;
	}

	__ni_suse_show_unapplied_routes();

	success = TRUE;

done:
	ni_string_free(&pathname);
	__ni_suse_free_globals();
	ni_string_array_destroy(&files);
	return success;
}

/*
 * Read HOSTNAME file
 */
static const char *
__ni_suse_read_default_hostname(const char *root, char **hostname)
{
	const char *filenames[] = __NI_SUSE_HOSTNAME_FILES, **name;
	char filename[PATH_MAX];
	char buff[256] = {'\0'};
	FILE *input;

	if (!hostname)
		return NULL;
	ni_string_free(hostname);

	for (name = filenames; name && !ni_string_empty(*name); name++) {
		snprintf(filename, sizeof(filename), "%s%s",
				ni_string_empty(root) ? "" : root, *name);

		if (!ni_isreg(filename))
			continue;

		if (!(input = ni_file_open(filename, "r", 0600)))
			continue;

		if (fgets(buff, sizeof(buff)-1, input)) {
			buff[strcspn(buff, " \t\r\n")] = '\0';

			if (ni_check_domain_name(buff, strlen(buff), 0))
				ni_string_dup(hostname, buff);
		}
		fclose(input);
		break;
	}
	return *hostname;
}

static ni_bool_t
__ni_suse_read_global_ifsysctl(const char *root, const char *path)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	char dirname[PATH_MAX];
	char pathbuf[PATH_MAX];
	const char *name;
	unsigned int i;

	ni_var_array_destroy(&__ni_suse_global_ifsysctl);

	if (ni_string_empty(root))
		root = "";

	/*
	 * canonicalize all files to avoid parsing them multiple
	 * times -- there are symlinks used by default.
	 */
	snprintf(dirname, sizeof(dirname), "%s%s", root, __NI_SUSE_SYSCTL_DIR);
	if (ni_isdir(dirname)) {
		ni_string_array_t names = NI_STRING_ARRAY_INIT;
		if (ni_scandir(dirname, "*"__NI_SUSE_SYSCTL_SUFFIX, &names)) {
			for (i = 0; i < names.count; ++i) {
				snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
						dirname, names.data[i]);
				name = canonicalize_file_name(pathbuf);
				if (name)
					ni_string_array_append(&files, name);
			}
		}
		ni_string_array_destroy(&names);
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s%s", root, __NI_SUSE_SYSCTL_FILE);
	name = canonicalize_file_name(pathbuf);
	if (name && ni_isreg(name)) {
		if (ni_string_array_index(&files, name) == -1)
			ni_string_array_append(&files, name);
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s%s/%s", root, path,
						__NI_SUSE_IFSYSCTL_FILE);
	name = canonicalize_file_name(pathbuf);
	if (name && ni_isreg(name)) {
		if (ni_string_array_index(&files, name) == -1)
			ni_string_array_append(&files, name);
	}

	for (i = 0; i < files.count; ++i) {
		name = files.data[i];
		ni_ifsysctl_file_load(&__ni_suse_global_ifsysctl, name);
	}
	return TRUE;
}


/*
 * Read global ifconfig files like config, dhcp and routes
 */
static ni_bool_t
__ni_suse_read_globals(const char *root, const char *path)
{
	char pathbuf[PATH_MAX];

	if (path == NULL) {
		ni_error("%s: path is NULL", __func__);
		return FALSE;
	}

	__ni_suse_free_globals();

	__ni_suse_read_default_hostname(root, &__ni_suse_default_hostname);

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, __NI_SUSE_CONFIG_GLOBAL);
	if (ni_file_exists(pathbuf)) {
		__ni_suse_config_defaults = ni_sysconfig_read(pathbuf);
		if (__ni_suse_config_defaults == NULL) {
			ni_error("unable to parse %s", pathbuf);
			return FALSE;
		}
	} else {
		ni_warn("unable to find global config '%s': %m", pathbuf);
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, __NI_SUSE_CONFIG_DHCP);
	if (ni_file_exists(pathbuf)) {
		__ni_suse_dhcp_defaults = ni_sysconfig_read(pathbuf);
		if (__ni_suse_dhcp_defaults == NULL) {
			ni_error("unable to parse %s", pathbuf);
			return FALSE;
		}
	} else {
		ni_warn("unable to find global config '%s': %m", pathbuf);
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, __NI_SUSE_ROUTES_GLOBAL);
	if (ni_file_exists(pathbuf)) {
		if (!__ni_suse_read_routes(&__ni_suse_global_routes, pathbuf, NULL))
			return FALSE;
	}

	__ni_suse_read_global_ifsysctl(root, path);

	/* use proc without root-fs */
	if (ni_isdir(__NI_SUSE_PROC_IPV6_DIR))
		__ni_ipv6_disbled = FALSE;
	else
		__ni_ipv6_disbled = TRUE;

	return TRUE;
}

static void
__ni_suse_show_unapplied_routes(void)
{
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;
	ni_route_table_t *tab;
	unsigned int i;

	for (tab = __ni_suse_global_routes; tab; tab = tab->next) {
		for (i = 0; i < tab->routes.count; ++i) {
			ni_route_t *rp = tab->routes.data[i];

			if (!rp || rp->users >= 2)
				continue;

			ni_note("discarding route not matching any interface: %s",
					ni_route_print(&out, rp));
			ni_stringbuf_destroy(&out);
		}
	}
}

static void
__ni_suse_free_globals(void)
{
	ni_string_free(&__ni_suse_default_hostname);

	if (__ni_suse_config_defaults) {
		ni_sysconfig_destroy(__ni_suse_config_defaults);
		__ni_suse_config_defaults = NULL;
	}

	if (__ni_suse_dhcp_defaults) {
		ni_sysconfig_destroy(__ni_suse_dhcp_defaults);
		__ni_suse_dhcp_defaults = NULL;
	}

	ni_route_tables_destroy(&__ni_suse_global_routes);

	ni_var_array_destroy(&__ni_suse_global_ifsysctl);
}

/*
 * Read the routing information from sysconfig/network/routes or ifroutes-<ifname>.
 */
int
__ni_suse_parse_route_hops(ni_route_nexthop_t *nh, ni_string_array_t *opts,
				unsigned int *pos, const char *ifname,
				const char *filename, unsigned int line)
{
	const char *opt, *val;
	unsigned int tmp;

	/*
	 * The routes/ifroute-<nic> multipath syntax is:
	 *
	 * "192.168.0.0/24  -           -   [nic|-]  table 42 \"
	 * "                nexthop via 192.168.1.1 [dev nic] weight 2 \"
	 * "                nexthop via 192.168.1.2 [dev nic] weight 3"
	 */
	while ((opt = ni_string_array_at(opts, (*pos)++))) {
		if (!strcmp(opt, "nexthop")) {
			ni_route_nexthop_t *next = ni_route_nexthop_new();
			if (__ni_suse_parse_route_hops(next, opts, pos, ifname,
							filename, line) < 0) {
				ni_route_nexthop_free(next);
				return -1;
			}
			if (nh->gateway.ss_family == AF_UNSPEC)
				nh->gateway.ss_family = next->gateway.ss_family;

			if (nh->gateway.ss_family != next->gateway.ss_family) {
				ni_route_nexthop_free(next);
				return -1;
			}
			nh->next = next;
			break;
		} else
		if (!strcmp(opt, "via")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (!val || nh->gateway.ss_family != AF_UNSPEC)
				return -1;
			if (ni_sockaddr_parse(&nh->gateway, val, AF_UNSPEC) < 0)
				return -1;
		} else
		if (!strcmp(opt, "dev")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (!val || nh->device.name)
				return -1;
			ni_string_dup(&nh->device.name, val);
		} else
		if (!strcmp(opt, "weight")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (!val || nh->weight)
				return -1;
			if (ni_parse_uint(val, &tmp, 10) < 0 || !tmp)
				return -1;
			nh->weight = tmp;
		} else
		if (!strcmp(opt, "realm")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (!val || nh->realm)
				return -1;
			/* TODO: */
			if (ni_parse_uint(val, &tmp, 10) < 0 || tmp == 0 || tmp > 255)
				return -1;
			nh->realm = tmp;
		} else
#if 0		/* iproute2 does not allow to set them */
		if (!strcmp(opt, "dead")) {
			if (nh->flags & RTNH_F_DEAD)
				return -1;
			nh->flags |= RTNH_F_DEAD;
		} else
		if (!strcmp(opt, "pervasive")) {
			if (nh->flags & RTNH_F_PERVASIVE)
				return -1;
			nh->flags |= RTNH_F_PERVASIVE;
		} else
#endif
		if (!strcmp(opt, "onlink")) {
			if (nh->flags & RTNH_F_ONLINK)
				return -1;
			nh->flags |= RTNH_F_ONLINK;
		} else {
			return -1;
		}
	}

	/* apply default ifname when available */
	if (!nh->device.name && ifname)
		ni_string_dup(&nh->device.name, ifname);

	if (!nh->device.name && nh->gateway.ss_family == AF_UNSPEC)
		return -1;

	return 0;
}

int
__ni_suse_route_parse_opts(ni_route_t *rp, ni_string_array_t *opts,
				unsigned int *pos, const char *ifname,
				const char *filename, unsigned int line)
{
	const char *opt, *val;
	unsigned int tmp;

	while ((opt = ni_string_array_at(opts, (*pos)++))) {
		if (!strcmp(opt, "nexthop")) {
			/* either single or multipath, not both? */
			if (rp->nh.gateway.ss_family != AF_UNSPEC)
				return -1;

			if (__ni_suse_parse_route_hops(&rp->nh, opts, pos,
						ifname, filename, line) < 0)
				return -1;

			if (rp->family == AF_UNSPEC)
				rp->family = rp->nh.gateway.ss_family;

			if (rp->family != rp->nh.gateway.ss_family)
				return -1;
		} else
		if(!strcmp(opt, "via") || !strcmp(opt, "dev")) {
			/* ifname and gw belong into their fields */
			return -1;
		} else

		/* other attrs */
		if (!strcmp(opt, "src")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (!val || rp->pref_src.ss_family != AF_UNSPEC)
				return -1;
			if (ni_sockaddr_parse(&rp->pref_src, val, AF_UNSPEC) < 0)
				return -1;

			if (rp->family == AF_UNSPEC)
				rp->family = rp->pref_src.ss_family;
			if (rp->family != rp->pref_src.ss_family)
				return -1;
		} else
		if (!strcmp(opt, "metric")   ||
		    !strcmp(opt, "priority") ||
		    !strcmp(opt, "preference")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->priority = tmp;
		} else
		if (!strcmp(opt, "realm")) {
			val = ni_string_array_at(opts, (*pos)++);
			/* TODO: */
			if (ni_parse_uint(val, &tmp, 10) < 0 || tmp == 0 || tmp > 255)
				return -1;
			rp->realm = tmp;
		} else
		if (!strcmp(opt, "mark")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->mark = tmp;
		} else
		if (!strcmp(opt, "tos") || !strcmp(opt, "dsfield")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_parse_uint(val, &tmp, 16) < 0 || tmp > 256)
				return -1;
			rp->tos = tmp;
		} else

		/* metrics attr dict */
		if (!strcmp(opt, "mtu")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (!val || ni_parse_uint(val, &tmp, 10) < 0 || tmp > 65536)
				return -1;
			rp->mtu = tmp;
		} else
		if (!strcmp(opt, "window")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->window = tmp;
		} else
		if (!strcmp(opt, "rtt")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->rtt = tmp;
		} else
		if (!strcmp(opt, "rttvar")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->rttvar = tmp;
		} else
		if (!strcmp(opt, "ssthresh")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->ssthresh = tmp;
		} else
		if (!strcmp(opt, "cwnd")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->cwnd = tmp;
		} else
		if (!strcmp(opt, "advmss")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->advmss = tmp;
		} else
		if (!strcmp(opt, "reordering")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->reordering = tmp;
		} else
		if (!strcmp(opt, "hoplimit")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->hoplimit = tmp;
		} else
		if (!strcmp(opt, "initcwnd")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->initcwnd = tmp;
		} else
#if 0		/* iproute2 does not allow to set them */
		if (!strcmp(opt, "features")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->hoplimit = tmp;
		} else
#endif
		if (!strcmp(opt, "rto_min")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->rto_min = tmp;
		} else
		if (!strcmp(opt, "initrwnd")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (ni_string_eq("lock", val)) {
				if (!ni_route_metrics_lock_set(opt, &rp->lock))
					return -1;
				val = ni_string_array_at(opts, (*pos)++);
			}
			if (ni_parse_uint(val, &tmp, 10) < 0)
				return -1;
			rp->initrwnd = tmp;
		} else

		/* kern dict */
		if (!strcmp(opt, "table")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (!val || rp->table != RT_TABLE_UNSPEC)
				return -1;
			if (!ni_route_table_name_to_type(val, &tmp))
				return -1;
			if (tmp == RT_TABLE_UNSPEC || tmp == RT_TABLE_MAX)
				return -1;
			rp->table = tmp;
		} else
		if (!strcmp(opt, "scope")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (!ni_route_scope_name_to_type(val, &tmp))
				return -1;
			if (rp->scope != RT_SCOPE_UNIVERSE)
				return -1;
			rp->scope = tmp;
		} else
		if (!strcmp(opt, "proto") || !strcmp(opt, "protocol")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (!ni_route_protocol_name_to_type(val, &tmp) || tmp > 255)
				return -1;
			if (rp->protocol != RTPROT_UNSPEC)
				return -1;
			rp->protocol = tmp;
		} else
		if (!strcmp(opt, "type")) {
			val = ni_string_array_at(opts, (*pos)++);
			if (!ni_route_type_name_to_type(val, &tmp) || tmp >= __RTN_MAX)
				return -1;
			if (rp->type != RTN_UNSPEC)
				return -1;
			rp->type = tmp;
		} else {
			/* assume it is a route type name without keyword */
			if (!ni_route_type_name_to_type(opt, &tmp) || tmp >= __RTN_MAX)
				return -1;
			if (rp->type != RTN_UNSPEC)
				return -1;
			rp->type = tmp;
		}
	}

	return 0;
}

int
__ni_suse_route_parse(ni_route_table_t **routes, char *buffer, const char *ifname,
			const char *filename, unsigned int line)
{
	char *dest, *gway, *mask = NULL, *name = NULL, *end = NULL;
	unsigned int plen, i = 0;
	ni_string_array_t opts = NI_STRING_ARRAY_INIT;
	ni_route_nexthop_t *nh;
	ni_route_t *rp;

	ni_assert(routes != NULL);

	dest = strtok_r(buffer, " \t", &end);
	if (!dest)
		return 0;	/* empty line */

	gway = strtok_r(NULL, " \t", &end);
	if (gway)
		mask = strtok_r(NULL, " \t", &end);
	if (mask)
		name = strtok_r(NULL, " \t", &end);
	if (name) {
		if (ni_string_eq(name, "-"))
			name = NULL;

		/*
		 * ifname is set while reading per-interface routes;
		 * do not allow another interfaces in the name field.
		 */
		if (ifname && name && !ni_string_eq(ifname, name)) {
			ni_warn("%s[%u]: Ignoring foreign interface name \"%s\"",
				filename, line, name);
			name = NULL;
		}

		if (ifname == NULL)
			ifname = name;

		ni_string_split(&opts, end, " \t", 0);
	}

	/*
	 * Let's allocate a route and fill it directly
	 */
	rp = ni_route_new();

	/*
	 * We need an address either in gateway or in destination
	 * to get the address family.
	 */
	if (!gway || ni_string_eq(gway, "-")) {
		/*
		 * This is either a local interface route, e.g.
		 * ifroute-lo contains just 127/8 in it, or a
		 * multipath route where the hops are in opts.
		 */
		gway = NULL;
	} else
	if (ni_sockaddr_parse(&rp->nh.gateway, gway, AF_UNSPEC) < 0) {
		ni_error("%s[%u]: Cannot parse route gateway address \"%s\"",
			filename, line, gway);
		goto failure;
	}
	if (rp->family == AF_UNSPEC)
		rp->family = rp->nh.gateway.ss_family;

	if (__ni_suse_route_parse_opts(rp, &opts, &i, ifname, filename, line)) {
		ni_error("%s[%u]: Cannot parse route options \"%s\"",
			filename, line, end);
		goto failure;
	}
	ni_string_array_destroy(&opts);

	if (ni_string_eq(dest, "default")) {
		/*
		 * A default route with family from gateway
		 */
		rp->destination.ss_family = rp->family;
		rp->prefixlen = 0;
	} else {
		rp->prefixlen = -1U;

		if ((end = strchr(dest, '/'))) {
			*end++ = '\0';
			if (ni_parse_uint(end, &rp->prefixlen, 10) < 0) {
				ni_error("%s[%u]: Cannot parse route destination length \"%s\"",
					filename, line, end);
				goto failure;
			}
		}
		if (!ni_sockaddr_parse(&rp->destination, dest, AF_UNSPEC) < 0) {
			ni_error("%s[%u]: Cannot parse route destination prefix \"%s\"",
				filename, line, dest);
			goto failure;
		}
		if (rp->family == AF_UNSPEC)
			rp->family = rp->destination.ss_family;
		if (rp->family != rp->destination.ss_family)
			goto failure;

		plen = ni_af_address_length(rp->destination.ss_family) * 8;
		if (end == NULL) {
			/*
			 * Destination without prefix-length, parse mask field.
			 */
			if (!mask || ni_string_eq(mask, "-")) {
				/*
				 * No mask field is provided, assume the destination is
				 * a single IP address -- use the full address length.
				 */
				rp->prefixlen = plen;
			} else
			if (strchr(mask, '.')) {
				ni_sockaddr_t netmask;

				/*
				 * The mask field contains a IPv4 netmask in the standard
				 * dotted-decimal format (we do not parse a IPv6 netmask).
				 */
				if (rp->destination.ss_family != AF_INET ||
				    ni_sockaddr_parse(&netmask, mask, AF_INET) < 0) {
					ni_error("%s[%u]: Cannot parse route netmask \"%s\"",
						filename, line, mask);
					goto failure;
				}
				rp->prefixlen = ni_sockaddr_netmask_bits(&netmask);
			} else
			if (ni_parse_uint(mask, &rp->prefixlen, 10) < 0) {
				/*
				 * The mask field contains a prefix length.
				 */
				ni_error("%s[%u]: Cannot parse route destination length \"%s\"",
					filename, line, mask);
				goto failure;
			}
		}
		if (rp->prefixlen > plen) {
			ni_error("%s[%u]: Cannot parse route destination length \"%s\"",
				filename, line, mask);
			goto failure;
		}
	}

	if (rp->family == AF_UNSPEC) {
		ni_error("%s[%u]: Cannot create route - unable to find out address family",
			filename, line);
		goto failure;
	}

	switch (rp->type) {
	case RTN_UNREACHABLE:
	case RTN_BLACKHOLE:
	case RTN_PROHIBIT:
	case RTN_THROW:
		/* we need the destination only ...    */
		if (rp->nh.device.name && ni_string_eq(rp->nh.device.name, "lo")) {
			ni_warn("%s[%u]: Route type %s aren't bound to specific devices",
				filename, line, ni_route_type_type_to_name(rp->type));
		}
		if (ni_sockaddr_is_specified(&rp->nh.gateway) || rp->nh.next) {
			ni_warn("%s[%u]: Route type %s do not have any gateway",
				filename, line, ni_route_type_type_to_name(rp->type));
		}
		/* Hmm... just assign to loopback (as in kernel) and continue */
		ni_route_nexthop_list_destroy(&rp->nh.next);
		memset(&rp->nh.gateway, 0, sizeof(rp->nh.gateway));
		ni_string_dup(&rp->nh.device.name, "lo");
		break;

	default:
		/* we need either ifname or gateway... */
		for (nh = &rp->nh; nh; nh = nh->next) {
			if (!nh->device.name && ifname) {
				ni_string_dup(&nh->device.name, ifname);
			}
			if (!rp->nh.device.name && rp->nh.gateway.ss_family == AF_UNSPEC) {
				ni_error("%s[%u]: Neither device nor gateway found",
					filename, line);
				goto failure;
			}
		}
		break;
	}

	/* apply defaults when needed */
	if (rp->type == RTN_UNSPEC)
		rp->type = RTN_UNICAST;
	if (rp->table == RT_TABLE_UNSPEC)
		rp->table = RT_TABLE_MAIN;
	if (rp->protocol == RTPROT_UNSPEC)
		rp->protocol = RTPROT_BOOT;

	/*
	 * OK, IMO that's it.
	 */
	{
		ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;
		ni_debug_readwrite("Parsed route: %s", ni_route_print(&buf, rp));
		ni_stringbuf_destroy(&buf);
	}

	/* skip if we have this destination already */
	if (ni_route_tables_find_match(*routes, rp, ni_route_equal_destination)) {
		ni_debug_readwrite("Skipping route -- duplicate destination: %s/%u",
				ni_sockaddr_print(&rp->destination), rp->prefixlen);
		return 1;
	}

	if (ni_route_tables_add_route(routes, rp))
		return 0;

failure:
	ni_string_array_destroy(&opts);
	if (rp) {
		ni_route_free(rp);
	}
	return -1;
}

int
__ni_suse_read_route_line(FILE *fp, ni_stringbuf_t *buff, unsigned int *line)
{
	char temp[512], *ptr, eol;
	size_t len;

	while (fgets(temp, sizeof(temp), fp) != NULL) {
		(*line)++;

		len = strcspn(temp, "\r\n");
		eol = temp[len];
		temp[len] = '\0';

		if ((ptr = strchr(temp, '\\'))) {
			len = ptr - temp;
			*ptr++ = '\0';
			/* continuation only! */
			if (*ptr)
				return -1;
			eol = '\0';
		}
		if (len)
			ni_stringbuf_puts(buff, temp);
		if (eol)
			return 0;
	}

	return 1;
}

ni_bool_t
__ni_suse_read_routes(ni_route_table_t **routes, const char *filename, const char *ifname)
{
	ni_stringbuf_t buff = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int line = 1, lcnt = 0;
	FILE *fp;
	int done;

	if ((fp = fopen(filename, "r")) == NULL) {
		ni_error("unable to open %s: %m", filename);
		return FALSE;
	}

	ni_debug_readwrite("ni_suse_read_routes(%s)", filename);

	ni_stringbuf_grow(&buff, 1023);
	do {
		ni_stringbuf_truncate(&buff, 0);

		line += lcnt;
		lcnt = 0;

		done = __ni_suse_read_route_line(fp, &buff, &lcnt);
		if (done < 0) {
			ni_error("%s[%u]: Cannot parse route line continuation",
				filename, line - 1 + lcnt);
			goto error;
		}

		if (ni_stringbuf_empty(&buff))
			continue;

		/* truncate at first comment char */
		ni_stringbuf_truncate(&buff, strcspn(buff.string, "#"));

		/* skip leading spaces */
		ni_stringbuf_trim_head(&buff, " \t");

		if (!ni_stringbuf_empty(&buff)) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_READWRITE,
					"Parsing route line: %s", buff.string);
			if (__ni_suse_route_parse(routes, buff.string,
						  ifname, filename, line) < 0)
				continue;
		}
	} while (!done);

	ni_stringbuf_destroy(&buff);
	fclose(fp);
	return TRUE;

error:
	ni_stringbuf_destroy(&buff);
	ni_route_tables_destroy(routes);
	fclose(fp);
	return FALSE;
}

/*
 * Read the configuration of a single interface from a sysconfig file
 */
static ni_compat_netdev_t *
__ni_suse_read_interface(const char *filename, const char *ifname)
{
	const char *basename = ni_basename(filename);
	size_t pfxlen = sizeof(__NI_SUSE_CONFIG_IFPREFIX)-1;
	ni_compat_netdev_t *compat = NULL;
	ni_sysconfig_t *sc;

	if (ni_string_len(ifname) == 0) {
		if (!__ni_suse_ifcfg_valid_prefix(basename, __NI_SUSE_CONFIG_IFPREFIX)) {
			ni_error("Rejecting file without '%s' prefix: %s",
				__NI_SUSE_CONFIG_IFPREFIX, filename);
			return NULL;
		}
		if (!__ni_suse_ifcfg_valid_suffix(basename, pfxlen)) {
			ni_error("Rejecting blacklisted %sfile: %s",
				__NI_SUSE_CONFIG_IFPREFIX, filename);
			return NULL;
		}
		ifname = basename + pfxlen;
	}

	if (!ni_netdev_name_is_valid(ifname)) {
		ni_error("Rejecting suspect interface name: %s", ifname);
		return NULL;
	}

	if (!(sc = ni_sysconfig_read(filename)))
		goto error;

	compat = ni_compat_netdev_new(ifname);
	if (!compat || !__ni_suse_sysconfig_read(sc, compat))
		goto error;

	ni_sysconfig_destroy(sc);
	return compat;

error:
	if (sc)
		ni_sysconfig_destroy(sc);
	if (compat)
		ni_compat_netdev_free(compat);
	return NULL;
}

/*
 * Translate the SUSE startmodes to <control> element
 */
static ni_ifworker_control_t *
__ni_suse_startmode(const ni_sysconfig_t *sc)
{
	static const struct __ni_control_params {
		const char *		name;
		ni_ifworker_control_t	control;
	} __ni_suse_control_params[] = {
		/* manual is the default in ifcfg */
		{ "manual",	{ "manual",	NULL,		FALSE,	FALSE,	TRUE,	0, 0 } },

		{ "auto",	{ "boot",	NULL,		FALSE,	FALSE,	TRUE,	0, 0 } },
		{ "boot",	{ "boot",	NULL,		FALSE,	FALSE,	TRUE,	0, 0 } },
		{ "onboot",	{ "boot",	NULL,		FALSE,	FALSE,	TRUE,	0, 0 } },
		{ "on",		{ "boot",	NULL,		FALSE,	FALSE,	TRUE,	0, 0 } },

		{ "nfsroot",	{ "boot",	"localfs",	TRUE,	FALSE,	TRUE,	0, 0 } },

		{ "hotplug",	{ "hotplug",	NULL,		FALSE,	FALSE,	FALSE,	0, 0 } },
		{ "ifplugd",	{ "ifplugd",	NULL,		FALSE,	FALSE,	FALSE,	0, 0 } },

		{ "off",	{ "off",	NULL,		FALSE,	FALSE,	FALSE,	0, 0 } },

		{ NULL }
	};
	const struct __ni_control_params *p, *params = NULL;
	ni_ifworker_control_t *control;
	const char *mode;

	params = &__ni_suse_control_params[0];
	if (sc && (mode = ni_sysconfig_get_value(sc, "STARTMODE"))) {
		for (p = __ni_suse_control_params; p->name; ++p) {
			if (ni_string_eq(p->name, mode)) {
				params = p;
				break;
			}
		}
	}

	if ((control = ni_ifworker_control_clone(&params->control))) {
		if (!control->persistent && !ni_string_eq("off", control->mode)) {
			if (sc && ni_sysconfig_test_boolean(sc, "USERCONTROL"))
				control->usercontrol = TRUE;
		}
		if (ni_string_eq("ifplugd", control->mode)) {
			ni_sysconfig_get_integer(sc, "IFPLUGD_PRIORITY", &control->link_priority);
		}
	}
	return control;
}

/*
 * Try loopback interface
 */
static int
try_loopback(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;

	/* Consider "lo" as a reserved name for loopback. */
	if (strcmp(dev->name, "lo"))
		return 1;

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config is using loopback interface name",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_LOOPBACK;
	return 0;
}

/*
 * Handle infiniband devices
 */
static ni_bool_t
__maybe_infiniband(const char *ifname)
{
	if (ni_string_len(ifname) > 2 &&
	    strncmp(ifname, "ib", 2) == 0 &&
	    isdigit((unsigned char)ifname[2]))
		return TRUE;
	return FALSE;
}

static int
try_infiniband(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	const char *umcast;
	const char *mode;
	const char *pkey;
	const char *err;
	ni_infiniband_t *ib;

	mode   = ni_sysconfig_get_value(sc, "IPOIB_MODE");
	umcast = ni_sysconfig_get_value(sc, "IPOIB_UMCAST");

	if (!mode && !umcast && !__maybe_infiniband(dev->name))
		return 1;

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config is using infiniband interface name",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_INFINIBAND;
	ib = ni_netdev_get_infiniband(dev);

	if ((pkey = strchr(dev->name, '.')) != NULL) {
		dev->link.type = NI_IFTYPE_INFINIBAND_CHILD;
		unsigned long tmp = ~0UL;

		if (ni_parse_ulong(pkey + 1, &tmp, 16) < 0 || tmp > 0xffff) {
			ni_error("ifcfg-%s: Cannot parse infiniband child key number",
				dev->name);
			return -1;
		}

		ib->pkey = tmp;
		ni_string_set(&dev->link.lowerdev.name, dev->name, pkey - dev->name);
	}

	if (mode && !ni_infiniband_get_mode_flag(mode, &ib->mode)) {
		ni_error("ifcfg-%s: Cannot parse infiniband IPOIB_MODE=\"%s\"",
			dev->name, mode);
		return -1;
	}
	if (umcast && !ni_infiniband_get_umcast_flag(umcast, &ib->umcast)) {
		ni_error("ifcfg-%s: Cannot parse infiniband IPOIB_UMCAST=\"%s\"",
			dev->name, umcast);
		return -1;
	}

	if ((err = ni_infiniband_validate(dev->link.type, ib, &dev->link.lowerdev))) {
		ni_error("ifcfg-%s: %s", dev->name, err);
		return -1;
	}

	return 0;
}

/*
 * Handle Ethernet devices
 */
static inline void
ni_parse_ethtool_onoff(const char *input, ni_tristate_t *flag)
{
	if (ni_string_eq(input, "on")) {
		*flag = NI_TRISTATE_ENABLE;
	} else
	if (ni_string_eq(input, "off")) {
		*flag = NI_TRISTATE_DISABLE;
	}
}

static inline ni_bool_t
ni_parse_ethtool_wol_options(const char *input, ni_ethernet_wol_t *wol)
{
	ni_bool_t disabled = FALSE;
	unsigned int options = 0;
	if (!input || !wol)
		return FALSE;

	while(*input) {
		switch (*input) {
		case 'p':
			options |= (1 << NI_ETHERNET_WOL_PHY);
			break;
		case 'u':
			options |= (1 << NI_ETHERNET_WOL_UCAST);
			break;
		case 'm':
			options |= (1 << NI_ETHERNET_WOL_MCAST);
			break;
		case 'b':
			options |= (1 << NI_ETHERNET_WOL_BCAST);
			break;
		case 'a':
			options |= (1 << NI_ETHERNET_WOL_ARP);
			break;
		case 'g':
			options |= (1 << NI_ETHERNET_WOL_MAGIC);
			break;
		case 's':
			options |= (1 << NI_ETHERNET_WOL_SECUREON);
			break;
		case 'd':
			disabled = TRUE;
			break;
		default:
			return FALSE;
		}
		input++;
	}
	if (disabled) {
		wol->options = __NI_ETHERNET_WOL_DISABLE;
	} else
	if (options) {
		wol->options = options;
	}
	return  TRUE;
}

static inline ni_bool_t
ni_parse_ethtool_wol_sopass(const char *input, ni_ethernet_wol_t *wol)
{
	if (!input || !wol)
		return FALSE;

	if (ni_link_address_parse(&wol->sopass, ARPHRD_ETHER, input) < 0)
		return FALSE;

	return TRUE;
}


static void
try_add_ethtool_common(ni_netdev_t *dev, const char *opt, const char *val)
{
	static const ni_intmap_t __ethtool_speed_map[] = {
		{ "10",		10	},
		{ "100",	100	},
		{ "1000",	1000	},
		{ "2500",	2500	},
		{ "10000",	10000	},
		{ NULL,		0	}
	};
	static const ni_intmap_t __ethtool_port_map[] = {
		{ "tp",		NI_ETHERNET_PORT_TP	},
		{ "aui",	NI_ETHERNET_PORT_AUI	},
		{ "bnc",	NI_ETHERNET_PORT_BNC	},
		{ "mii",	NI_ETHERNET_PORT_MII	},
		{ "fibre",	NI_ETHERNET_PORT_FIBRE	},
		{ NULL,		0			},
	};
	ni_ethernet_t *eth = ni_netdev_get_ethernet(dev);
	unsigned int tmp;

	if (ni_string_eq(opt, "speed")) {
		if (ni_parse_uint_mapped(val, __ethtool_speed_map, &tmp) == 0)
			eth->link_speed = tmp;
	} else
	if (ni_string_eq(opt, "port")) {
		if (ni_parse_uint_mapped(val, __ethtool_port_map, &tmp) == 0)
			eth->port_type = tmp;
	} else
	if (ni_string_eq(opt, "duplex")) {
		if (ni_string_eq(val, "half")) {
			eth->duplex = NI_ETHERNET_DUPLEX_HALF;
		} else
		if (ni_string_eq(val, "full")) {
			eth->duplex = NI_ETHERNET_DUPLEX_FULL;
		}
	} else
	if (ni_string_eq(opt, "autoneg")) {
		ni_parse_ethtool_onoff(val, &eth->autoneg_enable);
	}
	else
	if (ni_string_eq(opt, "wol")) {
		ni_parse_ethtool_wol_options(val, &eth->wol);
	}
	else
	if (ni_string_eq(opt, "sopass")) {
		ni_parse_ethtool_wol_sopass(val, &eth->wol);
	}
}

static void
try_add_ethtool_offload(ni_ethtool_offload_t *offload, const char *opt, const char *val)
{
	if (offload) {
		if (ni_string_eq(opt, "rx")) {
			ni_parse_ethtool_onoff(val, &offload->rx_csum);
		} else
		if (ni_string_eq(opt, "tx")) {
			ni_parse_ethtool_onoff(val, &offload->tx_csum);
		} else
		if (ni_string_eq(opt, "sg")) {
			ni_parse_ethtool_onoff(val, &offload->scatter_gather);
		} else
		if (ni_string_eq(opt, "tso")) {
			ni_parse_ethtool_onoff(val, &offload->tso);
		} else
		if (ni_string_eq(opt, "ufo")) {
			ni_parse_ethtool_onoff(val, &offload->ufo);
		} else
		if (ni_string_eq(opt, "gso")) {
			ni_parse_ethtool_onoff(val, &offload->gso);
		} else
		if (ni_string_eq(opt, "gro")) {
			ni_parse_ethtool_onoff(val, &offload->gro);
		} else
		if (ni_string_eq(opt, "lro")) {
			ni_parse_ethtool_onoff(val, &offload->lro);
		}
	}
}

static void
try_add_ethtool_options(ni_netdev_t *dev, const char *type,
			ni_string_array_t *opts, unsigned int start)
{
	unsigned int i;

	if (ni_string_eq(type, "-K") || ni_string_eq(type, "--offload")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_offload(&dev->ethernet->offload, opts->data[i],
						opts->data[i + 1]);
		}
	} else
	if (ni_string_eq(type, "-s") || ni_string_eq(type, "--change")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_common(dev, opts->data[i],
						opts->data[i + 1]);
		}
	}
}

static ni_bool_t
try_add_ethtool_vars(const ni_sysconfig_t *sc, ni_netdev_t *dev, const char *suffix)
{
	ni_string_array_t opts = NI_STRING_ARRAY_INIT;
	const char *type;
	ni_var_t *var;

	var = __find_indexed_variable(sc, "ETHTOOL_OPTIONS", suffix);
	if (!var || ni_string_empty(var->value))
		return TRUE; /* do not abort, just take next suffix */

	dev->link.type = NI_IFTYPE_ETHERNET;
	if (!ni_netdev_get_ethernet(dev))
		return FALSE;

	/*
	 * ETHTOOL_OPTIONS comes in two flavors
	 *   - starting with a dash: this is "-$option ifname $stuff"
	 *   - otherwise: this is a paramater to be passed to "-s ifname"
	 */
	if (ni_string_split(&opts, var->value, " \t", 0) >= 2) {
		type = opts.data[0];
		if (*type == '-') {
			try_add_ethtool_options(dev, type, &opts, 2);
		} else {
			try_add_ethtool_options(dev, "-s", &opts, 0);
		}
	}
	ni_string_array_destroy(&opts);
	return TRUE;
}

static int
try_ethernet(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	const char *lladdr = NULL;

	if (dev->link.type != NI_IFTYPE_UNKNOWN)
		return 1;

	if ((lladdr = ni_sysconfig_get_value(sc, "LLADDR")) != NULL) {
		if (ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, lladdr) < 0) {
			ni_error("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
				dev->name, lladdr);
			return -1;
		}
		dev->link.type = NI_IFTYPE_ETHERNET;
		if (!ni_netdev_get_ethernet(dev))
			return FALSE;
	}

	/* process ETHTOOL_OPTIONS[SUFFIX] array */
	if (__process_indexed_variables(sc, dev, "ETHTOOL_OPTIONS",
					try_add_ethtool_vars) < 0) {
		ni_error("ifcfg-%s: Cannot parse ETHTOOL_OPTIONS variables",
				dev->name);
		return -1;
	}

	return dev->link.type == NI_IFTYPE_ETHERNET ? 0 : 1;
}

/*
 * Handle bonding devices
 *
 * Bonding interfaces have variables BONDIG_SLAVE_0, BONDIG_SLAVE_1, ... that
 * describe the slave devices.
 *
 * Global bonding configuration is contained in BONDING_MODULE_OPTS
 */
static ni_bool_t
try_add_bonding_slave(const ni_sysconfig_t *sc, ni_netdev_t *dev, const char *suffix)
{
	ni_bonding_t *bond;
	ni_var_t *var;

	var = __find_indexed_variable(sc, "BONDING_SLAVE", suffix);
	if (!var || !var->value)
		return FALSE;

	dev->link.type = NI_IFTYPE_BOND;

	if ((bond = ni_netdev_get_bonding(dev)) == NULL)
		return FALSE;

	return ni_bonding_add_slave(bond, var->value);
}

static ni_bool_t
try_set_bonding_options(ni_netdev_t *dev, const char *options)
{
	ni_string_array_t temp;
	ni_bonding_t * bond;
	unsigned int i;
	ni_bool_t ret = TRUE;

	if ((bond = ni_netdev_get_bonding(dev)) == NULL)
		return FALSE;

	ni_string_array_init(&temp);
	ni_string_split(&temp, options, " \t", 0);
	for (i = 0; i < temp.count; ++i) {
		char *key = temp.data[i];
		char *val = strchr(key, '=');

		if (val != NULL)
			*val++ = '\0';

		if (!ni_string_len(key) || !ni_string_len(val)) {
			ni_error("ifcfg-%s: Unable to parse bonding options '%s'",
				dev->name, options);
			ret = FALSE;
			break;
		}
		if (!ni_bonding_set_option(bond, key, val)) {
			ni_error("ifcfg-%s: Unable to parse bonding option: %s=%s",
				dev->name, key, val);
			ret = FALSE;
			break;
		}
	}
	ni_string_array_destroy(&temp);

	return ret;
}

static int
try_bonding(ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	const char *module_opts, *err;
	ni_bool_t enabled;

	if (!ni_sysconfig_get_boolean(sc, "BONDING_MASTER", &enabled) || !enabled)
		return 1;

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains bonding variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_BOND;
	(void)ni_netdev_get_bonding(dev);

	if (__process_indexed_variables(sc, dev, "BONDING_SLAVE",
					try_add_bonding_slave) != 0)
		return -1;

	if ((module_opts = ni_sysconfig_get_value(sc, "BONDING_MODULE_OPTS")) != NULL) {
		if (!try_set_bonding_options(dev, module_opts))
			return -1;
	}

	if ((err = ni_bonding_validate(ni_netdev_get_bonding(dev))) != NULL) {
		ni_error("ifcfg-%s: bonding validation: %s",
			dev->name, err);
		return -1;
	}

	return 0;
}

/*
 * Bridge devices are recognized by BRIDGE=yes
 */
static int
try_bridge(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_bridge_t *bridge;
	ni_bool_t enabled;
	const char *value;

	if (!ni_sysconfig_get_boolean(sc, "BRIDGE", &enabled) || !enabled)
		return 1;

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains bridge variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_BRIDGE;
	bridge = ni_netdev_get_bridge(dev);

	if ((value = ni_sysconfig_get_value(sc, "BRIDGE_STP")) != NULL) {
		if (!strcasecmp(value, "off") || !strcasecmp(value, "no")) {
			bridge->stp = FALSE;
		} else
		if (!strcasecmp(value, "on") || !strcasecmp(value, "yes")) {
			bridge->stp = TRUE;
		} else {
			ni_error("ifcfg-%s: Cannot parse BRIDGE_STP='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "BRIDGE_PRIORITY")) != NULL) {
		if (ni_parse_uint(value, &bridge->priority, 0) < 0) {
			ni_error("ifcfg-%s: Cannot parse BRIDGE_PRIORITY='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "BRIDGE_AGEINGTIME")) != NULL) {
		if (ni_parse_double(value, &bridge->ageing_time) < 0) {
			ni_error("ifcfg-%s: Cannot parse BRIDGE_AGEINGTIME='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "BRIDGE_FORWARDDELAY")) != NULL) {
		if (ni_parse_double(value, &bridge->forward_delay) < 0) {
			ni_error("ifcfg-%s: Cannot parse BRIDGE_FORWARDDELAY='%s'",
				dev->name, value);
			return -1;
		}
	}
	if ((value = ni_sysconfig_get_value(sc, "BRIDGE_HELLOTIME")) != NULL) {
		if (ni_parse_double(value, &bridge->hello_time) < 0) {
			ni_error("ifcfg-%s: Cannot parse BRIDGE_HELLOTIME='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "BRIDGE_MAXAGE")) != NULL) {
		if (ni_parse_double(value, &bridge->max_age) < 0) {
			ni_error("ifcfg-%s: Cannot parse BRIDGE_MAXAGE='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "BRIDGE_PORTS")) != NULL) {
		char *portnames = NULL, *name_pos = NULL, *name = NULL;

		ni_string_dup(&portnames, value);
		for (name = strtok_r(portnames, " \t", &name_pos);
		     name != NULL;
		     name = strtok_r(NULL, " \t", &name_pos)) {

			if (!ni_netdev_name_is_valid(name)) {
				ni_error("ifcfg-%s: BRIDGE_PORTS='%s' "
					 "rejecting suspect port name '%s'",
					 dev->name, value, name);
				free(portnames);
				return -1;
			}

			ni_bridge_port_new(bridge, name, 0);
		}
		ni_string_free(&portnames);
	}

	if ((value = ni_sysconfig_get_value(sc, "BRIDGE_PORTPRIORITIES")) != NULL) {
		char *portprios = NULL, *prio_pos = NULL, *prio = NULL;
		unsigned int tmp, i = 0;

		ni_string_dup(&portprios, value);
		for (prio = strtok_r(portprios, " \t", &prio_pos);
		     prio != NULL && i < bridge->ports.count;
		     prio = strtok_r(NULL, " \t", &prio_pos), ++i) {
			ni_bridge_port_t *port = bridge->ports.data[i];

			if (!strcmp("-", prio))
				continue;

			if (ni_parse_uint(prio, &tmp, 0) < 0) {
				ni_error("ifcfg-%s: BRIDGE_PORTPRIORITIES='%s' "
					 "unable to parse port '%s' priority '%s'",
					 dev->name, value, port->ifname, prio);
				free(portprios);
				return -1;
			}
			port->priority = tmp;
		}
		ni_string_free(&portprios);
	}

	if ((value = ni_sysconfig_get_value(sc, "BRIDGE_PATHCOSTS")) != NULL) {
		char *portcosts = NULL, *cost_pos = NULL, *cost = NULL;
		unsigned int tmp, i = 0;

		ni_string_dup(&portcosts, value);
		for (cost = strtok_r(portcosts, " \t", &cost_pos);
		     cost != NULL && i < bridge->ports.count;
		     cost = strtok_r(NULL, " \t", &cost_pos), ++i) {
			ni_bridge_port_t *port = bridge->ports.data[i++];

			if (!strcmp("-", cost))
				continue;

			if (ni_parse_uint(cost, &tmp, 0) < 0) {
				ni_error("ifcfg-%s: BRIDGE_PATHCOSTS='%s' "
					 "unable to parse port '%s' costs '%s'",
					 dev->name, value, port->ifname, cost);
				free(portcosts);
				return -1;
			}
			port->path_cost = tmp;
		}
		ni_string_free(&portcosts);
	}

	if ((value = ni_bridge_validate(bridge)) != NULL) {
		ni_error("ifcfg-%s: bridge validation: %s", dev->name, value);
		return -1;
	}

	return 0;
}

/*
 * VLAN interfaces are recognized by their name (vlan<N>)
 */
static int
try_vlan(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_vlan_t *vlan;
	const char *etherdev = NULL;
	const char *vlanprot = NULL;
	const char *vlantag = NULL;
	const char *lladdr = NULL;
	unsigned int tag = 0;
	size_t len;

	if ((etherdev = ni_sysconfig_get_value(sc, "ETHERDEVICE")) == NULL)
		return 1;

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains vlan variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_VLAN;
	vlan = ni_netdev_get_vlan(dev);

	if (!strcmp(dev->name, etherdev)) {
		ni_error("ifcfg-%s: ETHERDEVICE=\"%s\" self-reference",
			dev->name, etherdev);
		return -1;
	}

	if ((vlantag = ni_sysconfig_get_value(sc, "VLAN_ID")) != NULL) {
		if (!ni_parse_uint(vlantag, &tag, 10) < 0) {
			ni_error("ifcfg-%s: Cannot parse VLAN_ID=\"%s\"",
				dev->name, vlantag);
			return -1;
		}
	} else {
		if ((vlantag = strrchr(dev->name, '.')) != NULL) {
			/* name.<TAG> */
			++vlantag;
		} else {
			/* name<TAG> */
			len = strlen(dev->name);
			vlantag = &dev->name[len];
			while(len > 0 && isdigit((unsigned char)vlantag[-1]))
				vlantag--;
		}
		if (!ni_parse_uint(vlantag, &tag, 10) < 0) {
			ni_error("ifcfg-%s: Cannot parse vlan-tag from interface name",
				dev->name);
			return -1;
		}
	}
	if (tag > __NI_VLAN_TAG_MAX) {
		ni_error("ifcfg-%s: VLAN tag %u is out of numerical range",
			dev->name, tag);
		return -1;
#if 0
	} else if (tag == 0) {
		ni_warn("%s: VLAN tag 0 disables VLAN filter and is probably not what you want",
			dev->name, tag);
#endif
	}

	if ((vlanprot = ni_sysconfig_get_value(sc, "VLAN_PROTOCOL")) != NULL) {
		unsigned int protocol;
		if (!ni_vlan_name_to_protocol(vlanprot, &protocol)) {
			ni_error("ifcfg-%s: Unsupported VLAN_PROTOCOL=\"%s\"",
				dev->name, vlanprot);
			return -1;
		}
		vlan->protocol = protocol;
	}

	ni_string_dup(&dev->link.lowerdev.name, etherdev);
	vlan->tag = tag;

	if ((lladdr = ni_sysconfig_get_value(sc, "LLADDR")) != NULL) {
		if (ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, lladdr) < 0) {
			ni_error("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
				dev->name, lladdr);
			return -1;
		}
	}

	return 0;
}

/*
 * MACVLAN/MACVTAP is recognized by [MACVLAN|MACVTAP]_DEVICE entry which
 * specifies the lower device to use. The lower device, obviously, has to
 * differ from the macvlan/tap device being created.
 */
static int
try_macvlan(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_macvlan_t *macvlan = NULL;
	const char *macvlan_dev = NULL;
	unsigned int macvlan_iftype = NI_IFTYPE_UNKNOWN;
	const char *macvlan_mode = NULL;
	const char *macvlan_flags = NULL;
	const char *syscfg_dev_key = NULL;
	const char *syscfg_mode_key = NULL;
	const char *syscfg_flags_key = NULL;
	const char *lladdr = NULL;
	const char *err;

	/* Determine if we're a macvlan or a macvtap */
	if ((macvlan_dev = ni_sysconfig_get_value(sc, "MACVLAN_DEVICE")) != NULL) {
		macvlan_iftype = NI_IFTYPE_MACVLAN;
		syscfg_dev_key = "MACVLAN_DEVICE";
		syscfg_mode_key = "MACVLAN_MODE";
		syscfg_flags_key = "MACVLAN_FLAGS";
	} else if ((macvlan_dev = ni_sysconfig_get_value(sc, "MACVTAP_DEVICE")) != NULL) {
		macvlan_iftype = NI_IFTYPE_MACVTAP;
		syscfg_dev_key = "MACVTAP_DEVICE";
		syscfg_mode_key = "MACVTAP_MODE";
		syscfg_flags_key = "MACVTAP_FLAGS";
	} else {
		return 1;
	}

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains macvlan/macvtap variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = macvlan_iftype;

	if (!(macvlan = ni_netdev_get_macvlan(dev))) {
		ni_error("ifcfg-%s: failed to get device specific data. Not a %s device.",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	if (!strcmp(dev->name, macvlan_dev)) {
		ni_error("ifcfg-%s: %s=\"%s\" self-reference",
			dev->name, syscfg_dev_key, macvlan_dev);
		return -1;
	}

	macvlan->mode = NI_MACVLAN_MODE_VEPA;
        if ((macvlan_mode = ni_sysconfig_get_value(sc, syscfg_mode_key)) != NULL) {
                unsigned int mode;
                if (!ni_macvlan_name_to_mode(macvlan_mode, &mode)) {
                        ni_error("ifcfg-%s: Unsupported %s=\"%s\"",
                                dev->name, syscfg_mode_key, macvlan_mode);
                        return -1;
                }
                macvlan->mode = mode;
        }

	macvlan->flags = 0;
	if ((macvlan_flags = ni_sysconfig_get_value(sc, syscfg_flags_key)) != NULL) {
		ni_string_array_t flags = NI_STRING_ARRAY_INIT;
		unsigned int i, flag;

		ni_string_split(&flags, macvlan_flags, " \t", 0);
		for (i = 0; i < flags.count; ++i) {
			if (!ni_macvlan_name_to_flag(flags.data[i], &flag)) {
				ni_error("ifcfg-%s: Unsupported %s=\"%s\"",
					dev->name, syscfg_flags_key, macvlan_flags);
				ni_string_array_destroy(&flags);
				return -1;
			}
			macvlan->flags |= flag;
		}
		ni_string_array_destroy(&flags);
	}

	if ((err = ni_macvlan_validate(macvlan))) {
		ni_error("ifcfg-%s: %s", dev->name, err);
		return -1;
	}
	ni_string_dup(&dev->link.lowerdev.name, macvlan_dev);

	if ((lladdr = ni_sysconfig_get_value(sc, "LLADDR")) != NULL) {
		if (ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, lladdr) < 0) {
			ni_error("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
				dev->name, lladdr);
			return -1;
		}
	}

	return 0;
}

/*
 * A Dummy device is recognized by INTERFACETYPE and/or by the interface name
 * itself.
 */
static int
try_dummy(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	const char *iftype = NULL;
	const char *lladdr = NULL;
	const char *bootproto = NULL;

	iftype = ni_sysconfig_get_value(sc, "INTERFACETYPE");

	if (!ni_string_eq_nocase(iftype, "dummy") &&
		!ni_string_startswith(dev->name, "dummy"))
		return 1; /* This is not a dummy interface*/

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains dummy variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_DUMMY;

	/* We only support "none" and "static". */
	if ((bootproto = ni_sysconfig_get_value(sc, "BOOTPROTO")) != NULL) {
		if (!ni_string_eq_nocase(bootproto, "none") &&
			!ni_string_eq_nocase(bootproto, "static")) {
			ni_error("ifcfg-%s: BOOTPROTO=%s not supported",
				dev->name, bootproto);
			return -1;
		}
	}

	if ((lladdr = ni_sysconfig_get_value(sc, "LLADDR")) != NULL) {
		if (ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, lladdr) < 0) {
			ni_error("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
				dev->name, lladdr);
			return -1;
		}
	}

	return 0;
}

/*
 * Handle Wireless devices
 */
static ni_bool_t
try_add_wireless(const ni_sysconfig_t *sc, ni_netdev_t *dev, const char *suffix)
{
	ni_wireless_network_t *net;
	ni_wireless_t *wlan;
	ni_var_t *var;
	const char *tmp = NULL;
	ni_wireless_ssid_t essid;

	/* Just skip networks with empty ESSID */
	if (!(var = __find_indexed_variable(sc, "WIRELESS_ESSID", suffix))) {
		ni_error("ifcfg-%s: empty WIRELESS_ESSID%s value",
			dev->name, suffix);
		return FALSE;
	}

	switch (dev->link.type) {
	case NI_IFTYPE_UNKNOWN:
		dev->link.type = NI_IFTYPE_WIRELESS;
	case NI_IFTYPE_WIRELESS:
		break;
	default:
		ni_error("ifcfg-%s: %s config contains wireless variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return FALSE;
	}

	if (!(wlan = dev->wireless)) {
		ni_bool_t check_country = FALSE;

		if ((wlan = ni_netdev_get_wireless(dev)) == NULL) {
			ni_error("%s: no wireless info for device", dev->name);
			return FALSE;
		}

		/* Default is ap_scan = 1 */
		if ((tmp = ni_sysconfig_get_value(sc, "WIRELESS_AP_SCANMODE"))) {
			if ((ni_parse_uint(tmp, &wlan->conf.ap_scan, 10) < 0) ||
				(wlan->conf.ap_scan > NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH)) {
				ni_error("ifcfg-%s: wrong WIRELESS_AP_SCANMODE value",
					dev->name);
				goto failure_global;
			}
		}

		/* Default is wpa_drv = "nl80211" */
		if ((tmp = ni_sysconfig_get_value(sc, "WIRELESS_WPA_DRIVER"))) {
			if (!ni_wpa_driver_string_validate(tmp)) {
				ni_error("ifcfg-%s: wrong WIRELESS_WPA_DRIVER value",
					dev->name);
				goto failure_global;
			}
			else if (ni_string_contains(tmp, "80211")) {
				check_country = TRUE;
			}

			ni_string_dup(&wlan->conf.driver, tmp);
		}
		else {
			check_country = TRUE;
		}

		/* Regulatory domain is supported by nl80211 wpa driver */
		if (check_country) {
			if ((tmp = ni_sysconfig_get_value(sc, "WIRELESS_REGULATORY_DOMAIN"))) {
				if ((2 == ni_string_len(tmp)) &&
					(isalpha((unsigned char) tmp[0])) &&
					(isalpha((unsigned char) tmp[1]))) {
						ni_string_dup(&wlan->conf.country, tmp);
				}
				else {
					ni_error("ifcfg-%s: wrong WIRELESS_REGULATORY_DOMAIN value",
						dev->name);
					goto failure_global;
				}
			}
		}
	}

	/* Check whether ESSID already exists */
	if (!ni_wireless_parse_ssid(var->value, &essid)) {
		if ( essid.len > NI_WIRELESS_ESSID_MAX_LEN)
			ni_error("ifcfg-%s: too long WIRELESS_ESSID%s value",
				dev->name, suffix);
		goto failure_global;
	}

	if (ni_wireless_essid_already_exists(wlan, &essid)) {
		ni_error("ifcfg-%s: double configuration of the same ESSID=%s",
			dev->name, var->value);
		goto failure_global;
	}

	/* Allocate and mlock new network object */
	if (!(net = ni_wireless_network_new())) {
		ni_error("ifcfg-%s: unable to create network object", dev->name);
		goto failure_global;
	}

	/* Write down the ESSID */
	memcpy(net->essid.data, essid.data, essid.len);
	net->essid.len = essid.len;

	/* Default is scan_ssid = TRUE */
	if ((var = __find_indexed_variable(sc, "WIRELESS_HIDDEN_SSID", suffix))) {
		if (ni_string_eq_nocase(var->value, "no"))
			net->scan_ssid = FALSE;
		else if (ni_string_eq_nocase(var->value, "yes"))
			net->scan_ssid = TRUE;
		else {
			ni_error("ifcfg-%s: wrong WIRELESS_HIDDEN_SSID%s value",
				dev->name, suffix);
			goto failure;
		}
	}

	/* Default priority is an order of the networks in ifcfg file */
	if (!net->scan_ssid) {
		if ((var = __find_indexed_variable(sc, "WIRELESS_PRIORITY", suffix))) {
			if (ni_parse_uint(var->value, &net->priority, 10) < 0) {
				ni_error("ifcfg-%s: cannot parse WIRELESS_PRIORITY%s value",
					dev->name, suffix);
				goto failure;
			}
			else if (net->priority < 1) {
				ni_error("ifcfg-%s: wrong WIRELESS_PRIORITY%s value",
					dev->name, suffix);
				goto failure;
			}
		}
	}
	else {
		net->priority = wlan->conf.networks.count+1;
	}

	/* Default is mode = NI_WIRELESS_MODE_MANAGED */
	if ((var = __find_indexed_variable(sc, "WIRELESS_MODE", suffix))) {
		if (!ni_wireless_name_to_mode(var->value, &net->mode)) {
			ni_error("ifcfg-%s: wrong WIRELESS_MODE%s value", dev->name, suffix);
			goto failure;
		}
	}

	/* Default is unset */
	if ((var = __find_indexed_variable(sc, "WIRELESS_AP", suffix))) {
		if (ni_string_empty(var->value) || ni_string_eq(var->value, "any")) {
			ni_link_address_init(&net->access_point);
			net->access_point.len = ETH_ALEN;
			net->access_point.type = ARPHRD_ETHER;
		}
		else if (ni_string_eq(var->value, "off")) {
			ni_link_address_get_broadcast(ARPHRD_ETHER, &net->access_point);
		}
		else if (ni_link_address_parse(&net->access_point, ARPHRD_ETHER, var->value)) {
			ni_error("ifcfg-%s: wrong WIRELESS_AP%s value", dev->name, suffix);
			goto failure;
		}
	}

	/* Default is unset */
	if (NI_WIRELESS_MODE_ADHOC == net->mode ||
		NI_WIRELESS_MODE_MASTER == net->mode) {
		if ((var = __find_indexed_variable(sc, "WIRELESS_CHANNEL", suffix))) {
			if (ni_parse_uint(var->value, &net->channel, 10) < 0) {
				ni_error("ifcfg-%s: cannot parse WIRELESS_CHANNEL%s value",
					dev->name, suffix);
				goto failure;
			}
			else if (net->channel < 1) {
				ni_error("ifcfg-%s: wrong WIRELESS_CHANNEL%s value",
					dev->name, suffix);
				goto failure;
			}
		}
	}

	/* Default is unset */
	if ((var = __find_indexed_variable(sc, "WIRELESS_FRAG", suffix))) {
		if (ni_string_eq_nocase(var->value, "auto") ||
			ni_string_eq_nocase(var->value, "fixed") ||
			ni_string_eq_nocase(var->value, "off")) {
			ni_error("ifcfg-%s: not supported WIRELESS_FRAG%s value",
				dev->name, suffix);
			goto failure;
		}
		else if (ni_parse_uint(var->value, &net->fragment_size, 10) < 0) {
			ni_error("ifcfg-%s: cannot parse WIRELESS_FRAG%s value",
				dev->name, suffix);
			goto failure;
		}
		else if (net->fragment_size < 1) {
			ni_error("ifcfg-%s: wrong WIRELESS_FRAG%s value",
				dev->name, suffix);
			goto failure;
		}
	}

	/* Default is unset - open */
	var = __find_indexed_variable(sc, "WIRELESS_AUTH_MODE", suffix);
	if (!var ||
	    ni_string_eq("open", var->value) ||
	    ni_string_eq("no-encryption", var->value)) {
		if (!__ni_wireless_parse_wep_auth(sc, net, suffix, dev->name, FALSE))
			goto failure;
	}
	else if (ni_string_eq("shared", var->value) ||
			 ni_string_eq("sharedkey", var->value)) {
		if (!__ni_wireless_parse_wep_auth(sc, net, suffix, dev->name, TRUE))
			goto failure;
	}
	else if (ni_string_eq_nocase("psk", var->value) ||
			 ni_string_eq_nocase("wpa-psk", var->value)) {
		if (!__ni_wireless_parse_psk_auth(sc, net, suffix, dev->name, wlan->conf.ap_scan))
			goto failure;
	}
	else if (ni_string_eq_nocase("eap", var->value) ||
			 ni_string_eq_nocase("wpa-eap", var->value)) {
		if (!__ni_wireless_parse_eap_auth(sc, net, suffix, dev->name, wlan->conf.ap_scan))
			goto failure;
	}
	else {
		ni_error("ifcfg-%s: wrong WIRELESS_AUTH_MODE%s value",
			dev->name, suffix);
		goto failure;
	}

	ni_wireless_network_array_append(&wlan->conf.networks, net);

	return TRUE;

failure:
	ni_wireless_network_put(net);
failure_global:
	ni_netdev_set_wireless(dev, NULL);
	return FALSE;
}

static ni_bool_t
__ni_wireless_wep_key_len_is_valid(unsigned int len)
{
	switch(len) {
	case NI_WIRELESS_WEP_KEY_LEN_40:
	case NI_WIRELESS_WEP_KEY_LEN_64:
	case NI_WIRELESS_WEP_KEY_LEN_104:
	case NI_WIRELESS_WEP_KEY_LEN_128:
		return TRUE;

	default:
		return FALSE;
	}

	return FALSE;
}

static ni_bool_t
__ni_wireless_wep_key_validate(char *key)
{
	size_t len;

	if (!key)
		return FALSE;

	len = ni_string_len(key);
	if ('s' == key[0] && ':' == key[1]) { /* key ASCII representation */
		/* 5 ASCII chars for 64 bit key ||from 6 to 13 ASCII chars for 128 bit key */
		if ((len-2) < (NI_WIRELESS_WEP_KEY_LEN_40 >> 3) ||
			(len-2) > (NI_WIRELESS_WEP_KEY_LEN_104 >> 3))
			return FALSE;
		else
			return ni_check_printable(key, len);
	}
	else if ('h' == key[0] && ':' == key[1]) { /* passphrase representation to be hashed */
		/* FIXME / ADDME - lwepgen - WEP generation */
		/* key_len aka WIRELESS_KEY_LENGTH matters here */
		return ni_check_printable(key, len);
	}
	else { /* HEX digits with or w/o dashes */
		len -= ni_string_remove_char(key, '-'); /* Remove all dashes */
		if ((NI_WIRELESS_WEP_KEY_LEN_104 >> 2) != len && /* 104/128 key length - 26 HEX digits*/
			(NI_WIRELESS_WEP_KEY_LEN_40 >> 2) != len) /* 40/64 key length - 10 HEX digits */
			return FALSE;
		else
			return ni_string_ishex(key);
	}

	return FALSE;
}

static ni_bool_t
__ni_wireless_wpa_psk_key_validate(const char *key)
{
	size_t len;

	if (!key)
		return FALSE;

	len = ni_string_len(key);

	if (__NI_WIRELESS_WPA_PSK_HEX_LEN == len) {
		return ni_string_ishex(key);
	}
	else if (len >= __NI_WIRELESS_WPA_PSK_MIN_LEN &&
			 len < __NI_WIRELESS_WPA_PSK_HEX_LEN) {
		return ni_check_printable(key, len);
	}
	else
		return FALSE;

	return FALSE;
}

static ni_bool_t
__ni_wireless_parse_wep_auth(const ni_sysconfig_t *sc, ni_wireless_network_t *net, const char *suffix, const char *dev_name, ni_bool_t shared)
{
	ni_var_t *var;
	const char *key_str[NI_WIRELESS_WEP_KEY_COUNT] = {
		"WIRELESS_KEY_0",
		"WIRELESS_KEY_1",
		"WIRELESS_KEY_2",
		"WIRELESS_KEY_3"
	};
	unsigned int key_len;
	int i;

	ni_assert(sc && net && suffix);

	net->keymgmt_proto = NI_WIRELESS_KEY_MGMT_NONE;
	if (shared)
		net->auth_algo = NI_WIRELESS_AUTH_SHARED;
	else
		net->auth_algo = NI_WIRELESS_AUTH_OPEN;

	/* Default key is 0 */
	if ((var = __find_indexed_variable(sc,"WIRELESS_DEFAULT_KEY", suffix))) {
		if(ni_parse_uint(var->value, &net->default_key, 10) < 0 ||
		   net->default_key >= NI_WIRELESS_WEP_KEY_COUNT) {
			ni_error("ifcfg-%s: wrong WIRELESS_DEFAULT_KEY%s value",
				dev_name, suffix);
			goto wep_failure;
		}
	}
	else {
		net->default_key = 0;
	}

	/* Default key length is 104 */
	if ((var = __find_indexed_variable(sc,"WIRELESS_KEY_LENGTH", suffix))) {
		if (ni_parse_uint(var->value, &key_len, 10) < 0 ||
			!__ni_wireless_wep_key_len_is_valid(key_len)) {
			ni_error("ifcfg-%s: wrong WIRELESS_KEY_LENGTH%s value",
				dev_name, suffix);
			goto wep_failure;
		}
	}
	else {
		key_len = NI_WIRELESS_WEP_KEY_LEN_104;
	}

	/* Default wep_key is unset */
	for (i = 0; i < NI_WIRELESS_WEP_KEY_COUNT; i++) {
		ni_assert(!net->wep_keys[i]);

		if ((var = __find_indexed_variable(sc, key_str[i], suffix))) {
			if(!__ni_wireless_wep_key_validate(var->value)) {
				ni_error("ifcfg-%s: wrong WIRELESS_KEY_%d%s format",
					dev_name, i, suffix);
				goto wep_failure;
			}

			ni_string_dup(&net->wep_keys[i], var->value);
		}
	}

	return TRUE;

wep_failure:
	return FALSE;
}

static int
__ni_wireless_parse_auth_proto(const ni_sysconfig_t *sc, ni_wireless_auth_mode_t *auth_proto, const char *suffix, const char *dev_name)
{
	ni_var_t *var;

	ni_assert(sc && auth_proto && suffix);

	if((var = __find_indexed_variable(sc,"WIRELESS_WPA_PROTO", suffix))) {
		if (!ni_wireless_name_to_auth_mode(var->value, auth_proto)) {
			ni_error("ifcfg-%s: wrong WIRELESS_WPA_PROTO%s value",
				dev_name, suffix);
			return -1;
		}

		return 1; /* Present */
	}

	return 0;
}

static int
__ni_wireless_parse_cipher(const ni_sysconfig_t *sc, ni_wireless_cipher_t *cipher, const char *variable, const char *suffix, const char *dev_name)
{
	ni_var_t *var;

	ni_assert(sc && cipher && variable && suffix);

	if((var = __find_indexed_variable(sc,variable, suffix))) {
		if (!ni_wireless_name_to_cipher(var->value, cipher)) {
			ni_error("ifcfg-%s: wrong %s%s value", dev_name, variable, suffix);
			return -1;
		}
		return 1; /* Present */
	}

	return 0;
}

static ni_bool_t
__ni_wireless_parse_psk_auth(const ni_sysconfig_t *sc, ni_wireless_network_t *net, const char *suffix, const char *dev_name, ni_wireless_ap_scan_mode_t ap_scan)
{
	ni_var_t *var;
	const char *pairwise = "WIRELESS_CIPHER_PAIRWISE";
	const char *group = "WIRELESS_CIPHER_GROUP";

	ni_assert(sc && net && suffix);

	net->keymgmt_proto = NI_WIRELESS_KEY_MGMT_PSK;

	if((var = __find_indexed_variable(sc,"WIRELESS_WPA_PSK", suffix))) {
		if (!__ni_wireless_wpa_psk_key_validate(var->value)) {
			ni_error("ifcfg-%s: wrong WIRELESS_WPA_PSK%s value",
				dev_name, suffix);
			goto psk_failure;
		}

		ni_string_dup(&net->wpa_psk.passphrase, var->value);
	}
	else {
		ni_error("ifcfg-%s: no WIRELESS_WPA_PSK%s value specified",
			dev_name, suffix);
		goto psk_failure;
	}

	/* wickedd: Default are both WPA and WPA2 */
	if (__ni_wireless_parse_auth_proto(sc, &net->auth_proto, suffix, dev_name) < 0)
		goto psk_failure;

	/* wickedd: Default are both TKIP and CCMP */
	if (__ni_wireless_parse_cipher(sc, &net->pairwise_cipher, pairwise, suffix, dev_name) < 0)
		goto psk_failure;

	/* wickedd: Default are both TKIP and CCMP */
	if (__ni_wireless_parse_cipher(sc, &net->group_cipher, group, suffix, dev_name) < 0)
		goto psk_failure;

	if (NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH == ap_scan) {
		if (net->auth_proto != NI_WIRELESS_AUTH_WPA2)
			net->auth_proto = NI_WIRELESS_AUTH_WPA1;

		if (net->pairwise_cipher != NI_WIRELESS_CIPHER_CCMP)
			net->pairwise_cipher = NI_WIRELESS_CIPHER_TKIP;

		if (net->group_cipher != NI_WIRELESS_CIPHER_CCMP)
			net->group_cipher = NI_WIRELESS_CIPHER_TKIP;
	}

	return TRUE;

psk_failure:
	return FALSE;
}

static ni_bool_t
__ni_wireless_parse_eap_auth(const ni_sysconfig_t *sc, ni_wireless_network_t *net, const char *suffix, const char *dev_name, ni_wireless_ap_scan_mode_t ap_scan)
{
	ni_var_t *var;
	const char *pairwise = "WIRELESS_CIPHER_PAIRWISE";
	const char *group = "WIRELESS_CIPHER_GROUP";

	ni_assert(sc && net && suffix);

	net->keymgmt_proto = NI_WIRELESS_KEY_MGMT_EAP;

	/*wickedd: Default are TTLS PEAP TLS when not present */
	if ((var = __find_indexed_variable(sc,"WIRELESS_EAP_MODE", suffix))) {
		if (!ni_wireless_name_to_eap_method(var->value, &net->wpa_eap.method)) {
			ni_error("ifcfg-%s: wrong WIRELESS_EAP_MODE%s value",
				dev_name, suffix);
			goto eap_failure;
		}
	}

	/* wickedd: Default are both WPA and WPA2 */
	if (__ni_wireless_parse_auth_proto(sc, &net->auth_proto, suffix, dev_name) < 0)
		goto eap_failure;

	/* wickedd: Default are both TKIP and CCMP */
	if (__ni_wireless_parse_cipher(sc, &net->pairwise_cipher, pairwise, suffix, dev_name) < 0)
		goto eap_failure;

	/* wickedd: Default are both TKIP and CCMP */
	if (__ni_wireless_parse_cipher(sc, &net->group_cipher, group, suffix, dev_name) < 0)
		goto eap_failure;

	if (NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH == ap_scan) {
		if (net->auth_proto != NI_WIRELESS_AUTH_WPA2)
			net->auth_proto = NI_WIRELESS_AUTH_WPA1;

		if (net->pairwise_cipher != NI_WIRELESS_CIPHER_CCMP)
			net->pairwise_cipher = NI_WIRELESS_CIPHER_TKIP;

		if (net->group_cipher != NI_WIRELESS_CIPHER_CCMP)
			net->group_cipher = NI_WIRELESS_CIPHER_TKIP;
	}

	if ((var = __find_indexed_variable(sc,"WIRELESS_WPA_IDENTITY", suffix))) {
		ni_string_dup(&net->wpa_eap.identity, var->value);
	} else {
		ni_error("ifcfg-%s: no WIRELESS_WPA_IDENTITY%s value specified",
			dev_name, suffix);
		goto eap_failure;
	}

	if ((var = __find_indexed_variable(sc,"WIRELESS_WPA_PASSWORD", suffix))) {
		ni_string_dup(&net->wpa_eap.phase2.password, var->value);
	}
	else {
		ni_error("ifcfg-%s: no WIRELESS_WPA_PASSWORD%s value specified",
			dev_name, suffix);
		goto eap_failure;
	}

	/* wickedd: Default is 'anonymous' */
	if ((var = __find_indexed_variable(sc,"WIRELESS_WPA_ANONID", suffix))) {
		ni_string_dup(&net->wpa_eap.anonid, var->value);
	}

	/* FIXME Only path implemented so far */
	if ((var = __find_indexed_variable(sc,"WIRELESS_CA_CERT", suffix))) {
		net->wpa_eap.tls.ca_cert = ni_wireless_blob_new(var->value);
	}

	/* FIXME Only path implemented so far */
	if ((var = __find_indexed_variable(sc,"WIRELESS_CLIENT_CERT", suffix))) {
		net->wpa_eap.tls.client_cert = ni_wireless_blob_new(var->value);
	}

	/* FIXME Only path implemented so far */
	if ((var = __find_indexed_variable(sc,"WIRELESS_CLIENT_KEY", suffix))) {
		net->wpa_eap.tls.client_key = ni_wireless_blob_new(var->value);
	}

	if ((var = __find_indexed_variable(sc,"WIRELESS_CLIENT_KEY_PASSWORD", suffix))) {
		ni_string_dup(&net->wpa_eap.tls.client_key_passwd, var->value);
	}

	/* wickedd: Default is to allow both version 0 and 1 */
	if (NI_WIRELESS_EAP_PEAP == net->wpa_eap.method ||
		NI_WIRELESS_EAP_NONE == net->wpa_eap.method) {
		if ((var = __find_indexed_variable(sc,"WIRELESS_PEAP_VERSION", suffix))) {
			if (ni_parse_uint(var->value, &net->wpa_eap.phase1.peapver, 10) < 0 ||
				net->wpa_eap.phase1.peapver > 1) {
				ni_error("ifcfg-%s: wrong WIRELESS_PEAP_VERSION%s value",
					dev_name, suffix);
				goto eap_failure;
			}
		}
	}

	/*wickedd: Default are TTLS PEAP TLS when not present and WIRELESS_AP_SCANMODE != 2 */
	if ((var = __find_indexed_variable(sc,"WIRELESS_EAP_AUTH", suffix))) {
		if (!ni_wireless_name_to_eap_method(var->value, &net->wpa_eap.phase2.method)) {
			ni_error("ifcfg-%s: wrong WIRELESS_EAP_AUTH%s value",
				dev_name, suffix);
			goto eap_failure;
		}
	}
	else if (NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH == ap_scan) {
		ni_error("ifcfg-%s: WIRELESS_EAP_AUTH%s needed by WIRELESS_AP_SCANMODE=2",
			dev_name, suffix);
		goto eap_failure;
	}

	return TRUE;

eap_failure:
	return FALSE;
}


static int
try_wireless(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	int ret;

	/*
	 * There is a WIRELESS=yes variable, but it is never set by yast2.
	 * We check for non-empty ESSID[_X] vars as they're mandatory for
	 * wpa supplicant wireless network blocks.
	 */
	if (ni_string_eq(ni_sysconfig_get_value(sc, "WIRELESS"), "no"))
		return 1;

	if ((ret = __process_indexed_variables(sc, dev, "WIRELESS_ESSID",
						try_add_wireless)) != 0)
		return ret;

	return 0;
}

/*
 * Handle Tunnel interfaces
 */
static int
__try_tunnel_tuntap(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	const char *value;
	ni_tuntap_t *tuntap;

	if (!(tuntap = ni_netdev_get_tuntap(dev)))
		return -1;

	if (dev->link.type == NI_IFTYPE_TAP
	&&  (value = ni_sysconfig_get_value(sc, "LLADDR"))) {
		if (ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, value) < 0) {
			ni_error("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_SET_OWNER"))) {
		if (ni_parse_uint(value, &tuntap->owner, 10)) {
			struct passwd *pw;

			if (!(pw = getpwnam(value))) {
				ni_error("ifcfg-%s: Cannot parse TUNNEL_SET_OWNER='%s'",
					dev->name, value);
				return -1;
			}
			tuntap->owner = pw->pw_uid;
		}
	}
	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_SET_GROUP"))) {
		if (ni_parse_uint(value, &tuntap->group, 10)) {
			struct group *gr;

			if (!(gr = getgrnam(value))) {
				ni_error("ifcfg-%s: Cannot parse TUNNEL_SET_GROUP='%s'",
					dev->name, value);
				return -1;
			}
			tuntap->group = gr->gr_gid;
		}
	}
	return 0;
}

static int
__try_tunnel_generic(const char *ifname, unsigned short arp_type,
		ni_linkinfo_t *link, ni_tunnel_t *tunnel,
		const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	const char *value = NULL;
	unsigned int ui_value;

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_LOCAL_IPADDR"))) {
		if (ni_link_address_parse(&link->hwaddr, arp_type, value) < 0) {
			ni_error("ifcfg-%s: Cannot parse TUNNEL_LOCAL_IPADDR=\"%s\"",
				ifname, value);
			return -1;
		}
	} else {
		ni_error("ifcfg-%s: TUNNEL_LOCAL_IPADDR needed to configure tunnel interface",
			ifname);
		return -1;
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_REMOTE_IPADDR"))) {
		if (ni_link_address_parse(&link->hwpeer, arp_type, value) < 0) {
			ni_error("ifcfg-%s: Cannot parse TUNNEL_REMOTE_IPADDR=\"%s\"",
				ifname, value);
			return -1;
		}
	} else {
		ni_error("ifcfg-%s: TUNNEL_REMOTE_IPADDR needed to configure tunnel interface",
			ifname);
		return -1;
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_TTL"))) {
		if (ni_parse_uint(value, &ui_value, 10) < 0) {
			ni_error("ifcfg-%s: Cannot parse TUNNEL_TTL=\"%s\"",
				ifname, value);
			return -1;
		}
		tunnel->ttl = (uint16_t)ui_value;
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_TOS"))) {
		if (ni_parse_uint(value, &ui_value, 10) < 0) {
			ni_error("ifcfg-%s: Cannot parse TUNNEL_TOS=\"%s\"",
				ifname, value);
			return -1;
		}
		tunnel->tos = (uint16_t)ui_value;
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_PMTUDISC"))) {
		if (ni_parse_boolean(value, &tunnel->pmtudisc) < 0) {
			ni_error("ifcfg-%s: Cannot parse TUNNEL_PMTUDISC=\"%s\"",
				ifname, value);
			return -1;
		}
	}

	return 0;
}

static int
__try_tunnel_ipip(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_ipip_t *ipip = NULL;
	int rv = 0;

	if (!(ipip = ni_netdev_get_ipip(dev)))
		return -1;

	/* Populate generic tunneling data from config. */
	rv = __try_tunnel_generic(dev->name, ARPHRD_TUNNEL, &dev->link,
				&ipip->tunnel, sc, compat);

	return rv;
}

static int
__try_tunnel_gre(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_gre_t *gre = NULL;
	int rv = 0;

	if (!(gre = ni_netdev_get_gre(dev)))
		return -1;

	/* Populate generic tunneling data from config. */
	rv = __try_tunnel_generic(dev->name, ARPHRD_IPGRE, &dev->link,
				&gre->tunnel, sc, compat);

	return rv;
}

static int
__try_tunnel_sit(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_sit_t *sit = NULL;
	const char *value = NULL;
	int rv = 0;

	if (!(sit = ni_netdev_get_sit(dev)))
		return -1;

	/* Populate generic tunneling data from config. */
	rv = __try_tunnel_generic(dev->name, ARPHRD_SIT, &dev->link,
				&sit->tunnel, sc, compat);

	if ((value = ni_sysconfig_get_value(sc, "SIT_ISATAP"))) {
		if (ni_parse_boolean(value, &sit->isatap) < 0) {
			ni_error("ifcfg-%s: Cannot parse SIT_ISATAP=\"%s\"",
				dev->name, value);
			rv = -1;
		}
	}

	return rv;
}

static int
try_tunnel(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	const char *value;
	static const ni_intmap_t __tunnel_types[] = {
		{ "tun",	NI_IFTYPE_TUN		},
		{ "tap",	NI_IFTYPE_TAP		},
		{ "sit",	NI_IFTYPE_SIT		},
		{ "gre",	NI_IFTYPE_GRE		},
		{ "ipip",	NI_IFTYPE_IPIP		},
		{ "ip6tnl",	NI_IFTYPE_TUNNEL6	},
		{ NULL,		NI_IFTYPE_UNKNOWN	},
	};
	const ni_intmap_t *map;

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL")) == NULL)
		return 1;

	for (map = __tunnel_types; map->name; ++map) {
		if (!strcmp(map->name, value))
			break;
	}
	if (map->name == NULL) {
		ni_error("ifcfg-%s: unsupported tunnel type '%s'",
			dev->name, value);
		return -1;
	}

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains tunnel variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = map->value;
	switch (dev->link.type) {
	case NI_IFTYPE_TUN:
	case NI_IFTYPE_TAP:
		return __try_tunnel_tuntap(sc, compat);

	case NI_IFTYPE_IPIP:
		return __try_tunnel_ipip(sc, compat);

	case NI_IFTYPE_GRE:
		return __try_tunnel_gre(sc, compat);

	case NI_IFTYPE_SIT:
		return __try_tunnel_sit(sc, compat);

	default:
		ni_warn("ifcfg-%s: conversion of %s tunnels not yet supported",
			dev->name, map->name);
		return 0;
	}
}

/*
 * Static addrconf:
 *
 * Given a suffix like "" or "_1", try to get the IP address and related information.
 * This will evaluate
 *   IPADDR_x
 *   PREFIXLEN_x if needed
 *   BROADCAST_x
 *   REMOTE_IPADDR_x
 */
static ni_bool_t
__get_ipaddr(const ni_sysconfig_t *sc, const char *ifname, const char *suffix, ni_address_t **list)
{
	ni_var_t *var;
	ni_sockaddr_t local_addr;
	unsigned int prefixlen = ~0U;
	ni_address_t *ap;

	var = __find_indexed_variable(sc, "IPADDR", suffix);
	if (!var || !var->value || !var->value[0])
		return TRUE;

	if (!ni_sockaddr_prefix_parse(var->value, &local_addr, &prefixlen)) {
		ni_warn("ifcfg-%s: unable to parse %s=\"%s\"",
				ifname, var->name, var->value);
		return FALSE;
	}

	if (!ni_sockaddr_is_specified(&local_addr)) {
		/* usually crap written by yast2 -- bnc#879617 */
		ni_info("ifcfg-%s: ignoring unspecified ip address %s",
				ifname,	ni_sockaddr_print(&local_addr));
		return FALSE;
	}

	/* If the address wasn't in addr/prefix format, go look elsewhere */
	if (!prefixlen || prefixlen > ni_af_address_prefixlen(local_addr.ss_family)) {
		ni_sockaddr_t netmask;

		/* Try PREFIXLEN variable */
		var = __find_indexed_variable(sc, "PREFIXLEN", suffix);
		if (var && var->value) {
			prefixlen = strtoul(var->value, NULL, 0);
		} else
		if (local_addr.ss_family == AF_INET
		 && (var = __find_indexed_variable(sc, "NETMASK", suffix)) != NULL
		 && ni_sockaddr_parse(&netmask, var->value, AF_INET) >= 0) {
			prefixlen = ni_sockaddr_netmask_bits(&netmask);
		}
	}
	/* Uff... assume maximal prefix length of the address family */
	if (!prefixlen || prefixlen > ni_af_address_prefixlen(local_addr.ss_family))
		prefixlen = ni_af_address_prefixlen(local_addr.ss_family);

	ap = ni_address_new(local_addr.ss_family, prefixlen, &local_addr, list);
	if (ap && ap->family == AF_INET) {
		var = __find_indexed_variable(sc, "BROADCAST", suffix);
		if (var) {
			ni_sockaddr_parse(&ap->bcast_addr, var->value, AF_INET);
			if (ap->bcast_addr.ss_family != ap->family) {
				ni_warn("ifcfg-%s: ignoring BROADCAST%s=%s (wrong address family)",
						ifname, suffix, var->value);
				ap->bcast_addr.ss_family = AF_UNSPEC;
			}
		} else {
			/* Clear the default, it's useless */
			memset(&ap->bcast_addr, 0, sizeof(ap->bcast_addr));
		}
	}

	if (prefixlen == ni_af_address_prefixlen(local_addr.ss_family))	{
		var = __find_indexed_variable(sc, "REMOTE_IPADDR", suffix);
		if (var) {
			ni_sockaddr_parse(&ap->peer_addr, var->value, AF_UNSPEC);
			if (ap->peer_addr.ss_family != ap->family) {
				ni_warn("ifcfg-%s: ignoring REMOTE_IPADDR%s=%s (wrong address family)",
						ifname, suffix, var->value);
				ap->peer_addr.ss_family = AF_UNSPEC;
			} else
			if (!ni_sockaddr_is_specified(&ap->peer_addr)) {
				ni_warn("ifcfg-%s: ignoring REMOTE_IPADDR%s=%s (invalid remote address)",
						ifname, suffix, var->value);
				ap->peer_addr.ss_family = AF_UNSPEC;
			}
		}
	}

	if (ap->family == AF_INET) {
		var = __find_indexed_variable(sc, "LABEL", suffix);
		if (var && var->value && !ni_string_eq(ifname, var->value)) {
			if (!ni_netdev_alias_label_is_valid(ifname, var->value)) {
				ni_info("ifcfg-%s: ignoring %s='%s' (incorrect format)",
						ifname, var->name, var->value);
			} else {
				ni_string_dup(&ap->label, var->value);
			}
		}
	}

	return TRUE;
}

/*
 * Process static addrconf
 */
static ni_bool_t
__dev_route_match(ni_route_table_t *routes, unsigned int table,
			const char *device, ni_sockaddr_t *gw)
{
	ni_route_table_t *tab;
	ni_route_nexthop_t *nh;
	ni_route_t *rp;
	unsigned int i;
	ni_bool_t dh;

	if (!(tab =  ni_route_tables_find(routes, table)))
		return FALSE;

	for (i = 0; i < tab->routes.count; ++i) {
		if (!(rp = tab->routes.data[i]))
			continue;

		if (rp->family != gw->ss_family)
			continue;

		if (!ni_sockaddr_is_specified(&rp->destination) ||
		    ni_sockaddr_is_loopback(&rp->destination))
			continue;

		if (!ni_sockaddr_is_specified(&rp->destination))
			continue;

		for (dh = FALSE, nh = &rp->nh; !dh && nh; nh = nh->next) {
			if (!ni_sockaddr_is_unspecified(&nh->gateway))
				continue;
			if (!nh->device.name || ni_string_eq(nh->device.name, device))
				dh = TRUE;
		}

		if (dh && ni_sockaddr_prefix_match(rp->prefixlen, &rp->destination, gw))
			return TRUE;
	}
	return FALSE;
}

static ni_bool_t
__ni_suse_addrconf_static(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_bool_t ipv4_enabled = TRUE;
	ni_bool_t ipv6_enabled = TRUE;
	const char *routespath;
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;

	if (dev->ipv4 && ni_tristate_is_disabled(dev->ipv4->conf.enabled))
		ipv4_enabled = FALSE;
	if (dev->ipv6 && ni_tristate_is_disabled(dev->ipv6->conf.enabled))
		ipv6_enabled = FALSE;

	/* Loop over all IPADDR* variables and get the addresses */
	{
		ni_string_array_t names = NI_STRING_ARRAY_INIT;
		unsigned int i;

		if (ni_sysconfig_find_matching(sc, "IPADDR", &names) > 0) {
			for (i = 0; i < names.count; ++i) {
				(void)__get_ipaddr(sc, dev->name, names.data[i] + 6,
							&dev->addrs);
				/* skip / ignore addrs we aren't able to process */
			}
			ni_string_array_destroy(&names);
		}
	}

	/* Hack up the loopback interface */
	if (dev->link.type == NI_IFTYPE_LOOPBACK) {
		ni_sockaddr_t local_addr;

		if (ipv4_enabled) {
			ni_sockaddr_parse(&local_addr, "127.0.0.1", AF_INET);
			if (ni_address_list_find(dev->addrs, &local_addr) == NULL)
				ni_address_new(AF_INET, 8, &local_addr, &dev->addrs);
		}
		if (ipv6_enabled) {
			ni_sockaddr_parse(&local_addr, "::1", AF_INET6);
			if (ni_address_list_find(dev->addrs, &local_addr) == NULL)
				ni_address_new(AF_INET6, 128, &local_addr, &dev->addrs);
		}
	}

	ni_address_list_dedup(&dev->addrs);

	if (dev->routes != NULL)
		ni_route_tables_destroy(&dev->routes);

	routespath = ni_sibling_path_printf(sc->pathname, "ifroute-%s", dev->name);
	if (routespath && ni_file_exists(routespath)) {
		__ni_suse_read_routes(&dev->routes, routespath, dev->name);
	}

	if (__ni_suse_global_routes) {
		ni_route_table_t *tab;
		unsigned int i;

		for (tab = __ni_suse_global_routes; tab; tab = tab->next) {
			for (i = 0; i < tab->routes.count; ++i) {
				ni_route_t *rp = tab->routes.data[i];
				ni_address_t *ap;
				ni_route_nexthop_t *nh;
				unsigned int matches = 0;

				if (rp->family == AF_INET  && !ipv4_enabled)
					continue;
				if (rp->family == AF_INET6 && !ipv6_enabled)
					continue;

				/* skip if dev->routes contains the destination */
				if (ni_route_tables_find_match(dev->routes, rp,
						ni_route_equal_destination))
					continue;

				for (nh = &rp->nh; nh; nh = nh->next) {
					/* check match by device name */
					if (nh->device.name) {
						if (ni_string_eq(nh->device.name, dev->name))
							matches++;
						continue;
					}

					/* Every interface is in IPv6 link local network,
					 * that is, explicit interface required for them
					 */
					if (ni_sockaddr_is_ipv6_linklocal(&nh->gateway))
						continue;

					/* match gw against already assigned device routes */
					if (__dev_route_match(dev->routes, rp->table,
								dev->name, &nh->gateway)) {
						matches++;
						continue;
					}

					/* match, when gw is on the same network:
					 * e.g. ip from 192.168.1.0/24, gw is 192.168.1.1
					 */
					for (ap = dev->addrs; !matches && ap; ap = ap->next) {
						if (ap->family != nh->gateway.ss_family)
							continue;

						if (ni_address_can_reach(ap, &nh->gateway)) {
							matches++;
						} else
						if (ni_sockaddr_is_specified(&ap->peer_addr) &&
						    ni_sockaddr_equal(&ap->peer_addr, &nh->gateway)) {
							matches++;
						}
					}
				}
				if (matches) {
					for (nh = &rp->nh; nh; nh = nh->next) {
						if (!nh->device.name) {
							ni_string_dup(&nh->device.name, dev->name);
						}
					}

					ni_debug_readwrite("Assigned route to %s: %s",
							dev->name, ni_route_print(&out, rp));
					ni_stringbuf_destroy(&out);

					ni_route_tables_add_route(&dev->routes, ni_route_ref(rp));
				}
			}
		}
	}

	return TRUE;
}

static ni_bool_t
__ni_suse_parse_dhcp4_user_class(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat, const char *prefix)
{
	const char *string;
	size_t length;

	if (compat->dhcp4.user_class.format == NI_DHCP4_USER_CLASS_RFC3004) {
		ni_string_array_t names = NI_STRING_ARRAY_INIT;
		unsigned int i;
		size_t pfxlen;
		size_t total;
		ni_var_t *var;

		if (!ni_sysconfig_find_matching(sc, prefix, &names))
			return FALSE;

		pfxlen = ni_string_len(prefix);
		for (total = 0, i = 0; i < names.count; ++i) {
			const char *suffix = names.data[i] + pfxlen;

			if (!(var = __find_indexed_variable(sc, prefix, suffix)))
				continue;

			if (!(length = ni_string_len(var->value)))
				continue;

			string = var->value;
			total += length + 1;
			if (length >= 255 || total >= 255) {
				ni_warn("%s: %s array%s data is too long",
					ni_basename(sc->pathname), prefix,
					total >= 255 ? "" : " element");
				ni_string_array_destroy(&names);
				ni_string_array_destroy(&compat->dhcp4.user_class.class_id);
				return FALSE;
			} else if (!ni_check_domain_name(string, length, 0)) {
				ni_warn("%s: %s contains suspect class id element: '%s'",
					ni_basename(sc->pathname), prefix,
					ni_print_suspect(string, length));
				ni_string_array_destroy(&names);
				ni_string_array_destroy(&compat->dhcp4.user_class.class_id);
				return FALSE;
			}

			ni_string_array_append(&compat->dhcp4.user_class.class_id, string);
		}
		ni_string_array_destroy(&names);
	} else if ((string = ni_sysconfig_get_value(sc, prefix))) {
		length = ni_string_len(string);

		if (length >= 255) {
			ni_warn("%s: %s string is too long: '%s'",
				ni_basename(sc->pathname), prefix,
				ni_print_suspect(string, length));

			return FALSE;
		} else if (!ni_check_domain_name(string, length, 0)) {
			ni_warn("%s: %s contains suspect class id string: '%s'",
				ni_basename(sc->pathname), prefix,
				ni_print_suspect(string, length));

			return FALSE;
		}

		ni_string_array_append(&compat->dhcp4.user_class.class_id, string);
		compat->dhcp4.user_class.format = NI_DHCP4_USER_CLASS_STRING;
	}
	return TRUE;
}

/*
 * Process DHCPv4 addrconf
 */
static ni_bool_t
__ni_suse_addrconf_dhcp4_options(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	const char *string;
	unsigned int uint;
	ni_bool_t ret = TRUE;

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_HOSTNAME_OPTION")) != NULL) {
		if (!strcasecmp(string, "AUTO")) {
			ni_string_dup(&compat->dhcp4.hostname, __ni_suse_default_hostname);
		} else
		if (ni_check_domain_name(string, ni_string_len(string), 0)) {
			ni_string_dup(&compat->dhcp4.hostname, string);
		} else {
			ni_warn("%s: Cannot parse DHCLIENT_HOSTNAME_OPTION='%s'",
				ni_basename(sc->pathname), string);
			ret = FALSE;
		}
	}

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_CLIENT_ID")) != NULL)
		ni_string_dup(&compat->dhcp4.client_id, string);

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_VENDOR_CLASS_ID")) != NULL)
		ni_string_dup(&compat->dhcp4.vendor_class, string);

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_USER_CLASS_FORMAT")) != NULL)
		ni_dhcp4_user_class_format_name_to_type(string, &compat->dhcp4.user_class.format);
	__ni_suse_parse_dhcp4_user_class(sc, compat, "DHCLIENT_USER_CLASS_ID");


	if (ni_sysconfig_get_integer(sc, "DHCLIENT_SLEEP", &uint))
		compat->dhcp4.start_delay = uint;

	if (ni_sysconfig_get_integer(sc, "DHCLIENT_WAIT_AT_BOOT", &uint))
		compat->dhcp4.defer_timeout = uint;

	if (ni_sysconfig_get_integer(sc, "DHCLIENT_TIMEOUT", &uint))
		compat->dhcp4.acquire_timeout = uint;

	if (ni_sysconfig_get_integer(sc, "DHCLIENT_LEASE_TIME", &uint))
		compat->dhcp4.lease_time = ((int) uint >= 0) ? uint : 0;

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_USE_LAST_LEASE")))
		compat->dhcp4.recover_lease = !ni_string_eq(string, "no");

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_RELEASE_BEFORE_QUIT")))
		compat->dhcp4.release_lease = ni_string_eq(string, "yes");

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_SET_HOSTNAME"))) {
		if (ni_string_eq(string, "yes")) {
			ni_addrconf_update_set(&compat->dhcp4.update,
					NI_ADDRCONF_UPDATE_HOSTNAME, TRUE);
		} else
		if (ni_string_eq(string, "no")) {
			ni_addrconf_update_set(&compat->dhcp4.update,
					NI_ADDRCONF_UPDATE_HOSTNAME, FALSE);
		}
	}
	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_SET_DEFAULT_ROUTE"))) {
		if (ni_string_eq(string, "yes")) {
			ni_addrconf_update_set(&compat->dhcp4.update,
					NI_ADDRCONF_UPDATE_DEFAULT_ROUTE, TRUE);
		} else
		if (ni_string_eq(string, "no")) {
			ni_addrconf_update_set(&compat->dhcp4.update,
					NI_ADDRCONF_UPDATE_DEFAULT_ROUTE, FALSE);
		}
	}
	if (ni_sysconfig_get_integer(sc, "DHCLIENT_ROUTE_PRIORITY", &uint))
		compat->dhcp4.route_priority = uint;

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_MODIFY_SMB_CONF"))) {
		if (ni_string_eq(string, "yes")) {
			ni_addrconf_update_set(&compat->dhcp4.update,
					NI_ADDRCONF_UPDATE_SMB, TRUE);
		} else
		if (ni_string_eq(string, "no")) {
			ni_addrconf_update_set(&compat->dhcp4.update,
					NI_ADDRCONF_UPDATE_SMB, FALSE);
		}
	}

	return ret;
}

/*
 * Process DHCPv6 addrconf
 */
static ni_bool_t
__ni_suse_addrconf_dhcp6_options(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_bool_t ret = TRUE;
	unsigned int uint;
	const char *string;

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_MODE")) != NULL) {
		if (ni_dhcp6_mode_name_to_type(string, &compat->dhcp6.mode) != 0) {
			ni_warn("%s: Cannot parse DHCLIENT6_MODE='%s'",
				ni_basename(sc->pathname), string);
			ret = FALSE;
		}
	}

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_RAPID_COMMIT")) != NULL) {
		if (!strcasecmp(string, "yes")) {
			compat->dhcp6.rapid_commit = TRUE;
		} else
		if (!strcasecmp(string, "no")) {
			compat->dhcp6.rapid_commit = FALSE;
		} else {
			ni_warn("%s: Cannot parse DHCLIENT6_RAPID_COMMIT='%s'",
				ni_basename(sc->pathname), string);
			ret = FALSE;
		}
	}

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_HOSTNAME_OPTION")) != NULL) {
		if (!strcasecmp(string, "AUTO")) {
			ni_string_dup(&compat->dhcp6.hostname, __ni_suse_default_hostname);
		} else if (ni_check_domain_name(string, ni_string_len(string), 0)) {
			ni_string_dup(&compat->dhcp6.hostname, string);
		} else {
			ni_warn("%s: Cannot parse DHCLIENT6_HOSTNAME_OPTION='%s'",
				ni_basename(sc->pathname), string);
			ret = FALSE;
		}
	}

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_CLIENT_ID")) != NULL) {
		ni_opaque_t duid;
		if (ni_duid_parse_hex(&duid, string)) {
			ni_string_dup(&compat->dhcp6.client_id, string);
		} else {
			ni_warn("%s: Cannot parse DHCLIENT6_CLIENT_ID='%s' as DUID",
				ni_basename(sc->pathname), string);
			ret = FALSE;
		}
	}

	if (ni_sysconfig_get_integer(sc, "DHCLIENT6_SLEEP", &uint))
		compat->dhcp6.start_delay = uint;

	if (ni_sysconfig_get_integer(sc, "DHCLIENT6_WAIT_AT_BOOT", &uint))
		compat->dhcp6.defer_timeout = uint;

	if (ni_sysconfig_get_integer(sc, "DHCLIENT6_TIMEOUT", &uint))
		compat->dhcp6.acquire_timeout = uint;

	if (ni_sysconfig_get_integer(sc, "DHCLIENT6_LEASE_TIME", &uint))
		compat->dhcp6.lease_time = ((int) uint >= 0) ? uint : 0;

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_USE_LAST_LEASE")))
		compat->dhcp6.recover_lease = !ni_string_eq(string, "no");

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_RELEASE_BEFORE_QUIT")))
		compat->dhcp6.release_lease = ni_string_eq(string, "yes");

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_SET_HOSTNAME"))) {
		if (ni_string_eq(string, "yes")) {
			ni_addrconf_update_set(&compat->dhcp6.update,
					NI_ADDRCONF_UPDATE_HOSTNAME, TRUE);
		} else
		if (ni_string_eq(string, "no")) {
			ni_addrconf_update_set(&compat->dhcp6.update,
					NI_ADDRCONF_UPDATE_HOSTNAME, FALSE);
		}
	}

	return ret;
}

static ni_bool_t
__ni_suse_addrconf_dhcp4(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_bool_t required)
{
	ni_netdev_t *dev = compat->dev;
	ni_sysconfig_t *merged;

	if (dev && dev->ipv4 && ni_tristate_is_disabled(dev->ipv4->conf.enabled))
		return FALSE;

	if (compat->dhcp4.enabled)
		return TRUE;

	/* apply sysconfig defaults */
	ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_DEFAULT_ROUTE, TRUE);
	ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_HOSTNAME, FALSE);
	ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_MTU, !dev->link.mtu);
	compat->dhcp4.recover_lease = TRUE;
	compat->dhcp4.release_lease = FALSE;

	if ((merged = ni_sysconfig_merge_defaults(sc, __ni_suse_dhcp_defaults))) {
		__ni_suse_addrconf_dhcp4_options(merged, compat);
		ni_sysconfig_destroy(merged);
	}

	compat->dhcp4.enabled = TRUE;
	ni_addrconf_flag_bit_set(&compat->dhcp4.flags, NI_ADDRCONF_FLAGS_GROUP, !required);
	return TRUE;
}

static ni_bool_t
__ni_suse_addrconf_dhcp6(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_bool_t required)
{
	ni_netdev_t *dev = compat->dev;
	ni_sysconfig_t *merged;

	if (dev && dev->ipv6 && ni_tristate_is_disabled(dev->ipv6->conf.enabled))
		return FALSE;

	if (compat->dhcp6.enabled)
		return TRUE;

	/* apply sysconfig defaults */
	ni_addrconf_update_set(&compat->dhcp6.update, NI_ADDRCONF_UPDATE_HOSTNAME, FALSE);
	compat->dhcp6.recover_lease = TRUE;
	compat->dhcp6.release_lease = FALSE;

	if ((merged = ni_sysconfig_merge_defaults(sc, __ni_suse_dhcp_defaults))) {
		__ni_suse_addrconf_dhcp6_options(merged, compat);
		ni_sysconfig_destroy(merged);
	}

	compat->dhcp6.enabled = TRUE;
	ni_addrconf_flag_bit_set(&compat->dhcp6.flags, NI_ADDRCONF_FLAGS_GROUP, !required);
	return TRUE;
}

static ni_bool_t
__ni_suse_addrconf_autoip4(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_bool_t required)
{
	(void)sc;
	(void)compat;
	(void)required;

	/* TODO */
	return TRUE;
}

static ni_bool_t
__ni_suse_bootproto(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_bool_t primary;
	const char *bootproto;
	const char *value;
	char *bp, *s, *p;
	ni_ipv4_devinfo_t *ipv4;
	ni_ipv6_devinfo_t *ipv6;

	if ((bootproto = ni_sysconfig_get_value(sc, "BOOTPROTO")) == NULL)
		bootproto = "static";
	else if (!bootproto[0] || ni_string_eq(dev->name, "lo"))
		bootproto = "static";

	ipv4 = ni_netdev_get_ipv4(dev);
	ipv6 = ni_netdev_get_ipv6(dev);

	/* Hmm... bonding slave -- set ethtool, but no link up */
	if (ni_string_eq_nocase(bootproto, "none")) {
		if (ipv4)
			ni_tristate_set(&ipv4->conf.enabled, FALSE);
		if (ipv6)
			ni_tristate_set(&ipv6->conf.enabled, FALSE);
		return TRUE;
	}

	if (ipv4 && !ni_tristate_is_disabled(ipv4->conf.enabled)) {
		if (__ni_suse_config_defaults) {
			if ((value = ni_sysconfig_get_value(__ni_suse_config_defaults,
						"CHECK_DUPLICATE_IP"))) {
				ni_tristate_set(&ipv4->conf.arp_verify, !ni_string_eq(value, "no"));
			}
			if ((value = ni_sysconfig_get_value(__ni_suse_config_defaults,
						"SEND_GRATUITOUS_ARP"))
					&& !ni_string_eq(value, "auto")) {
				ni_tristate_set(&ipv4->conf.arp_notify, ni_string_eq(value, "yes"));
			}
		}
		if ((value = ni_sysconfig_get_value(sc, "CHECK_DUPLICATE_IP"))) {
			ni_tristate_set(&ipv4->conf.arp_verify, !ni_string_eq(value, "no"));
		}
		if ((value = ni_sysconfig_get_value(sc, "SEND_GRATUITOUS_ARP"))
				&& !ni_string_eq(value, "auto")) {
			ni_tristate_set(&ipv4->conf.arp_notify, ni_string_eq(value, "yes"));
		}
	}

	/* Hmm... ignore this config completely -> ibft firmware */
	if (ni_string_eq_nocase(bootproto, "ibft")) {
		return TRUE;
	}

	if (ni_string_eq_nocase(bootproto, "6to4")) {
		__ni_suse_addrconf_static(sc, compat);
		return TRUE;
	}

	if (ni_string_eq_nocase(bootproto, "static")) {
		__ni_suse_addrconf_static(sc, compat);
		return TRUE;
	}

	/*
	 * We should use a priority here I think, e.g.:
	 *   lower prio for fallbacks (less important),
	 *   same for an OR, priority 0 for optional...
	 */
	bp = p = NULL;
	primary = TRUE;
	ni_string_dup(&bp, bootproto);
	for (s = strtok_r(bp, "+", &p); s; s = strtok_r(NULL, "+", &p)) {
		if(ni_string_eq(s, "dhcp")) {
			/* dhcp4 or dhcp6 -> at least one required */
			__ni_suse_addrconf_dhcp4(sc, compat, FALSE);
			__ni_suse_addrconf_dhcp6(sc, compat, FALSE);
		}
		else if (ni_string_eq(s, "dhcp4")) {
			/* dhcp4 requested -> required             */
			__ni_suse_addrconf_dhcp4(sc, compat, TRUE);
		}
		else if (ni_string_eq(s, "dhcp6")) {
			/* dhcp6 requested -> required             */
			__ni_suse_addrconf_dhcp6(sc, compat, TRUE);
		}
		else if (ni_string_eq(s, "autoip")) {
			/* dhcp6 requested -> required when 1st    */
			__ni_suse_addrconf_autoip4(sc, compat, primary);
		}
		else {
			ni_debug_readwrite("ifcfg-%s: Unknown BOOTPROTO=\"%s\""
					" value \"%s\"", dev->name, bootproto, s);
		}
		primary = FALSE;
	}
	ni_string_free(&bp);

	/* static is always included in the "+" variants */
	__ni_suse_addrconf_static(sc, compat);
	return TRUE;
}

/*
 * Read ifsysctl file
 */
static void
__ifsysctl_get_int(ni_var_array_t *vars, const char *path, const char *ifname,
					const char *attr, int *value, int base)
{
	const char *names[] = { "all", "default", ifname, NULL };
	const char **name;
	ni_var_t *var;

	for (name = names; *name; name++) {
		var = ni_ifsysctl_vars_get(vars, "%s/%s/%s", path, *name, attr);
		if (!var)
			continue;
		if (ni_parse_int(var->value, value, base) < 0) {
			ni_debug_readwrite("Can't parse sysctl '%s'='%s' as integer",
					var->name, var->value);
		} else {
			ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_READWRITE,
				"Parsed sysctl '%s'='%s'", var->name, var->value);
		}
	}
}

static void
__ifsysctl_get_tristate(ni_var_array_t *vars, const char *path, const char *ifname,
			const char *attr, ni_tristate_t *tristate)
{
	int value = NI_TRISTATE_DEFAULT;

	__ifsysctl_get_int(vars, path, ifname, attr, &value, 10);
	if (ni_tristate_is_set(value))
		ni_tristate_set(tristate, value);
}

static ni_bool_t
__ni_suse_read_ifsysctl(ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_var_array_t ifsysctl = NI_VAR_ARRAY_INIT;
	ni_netdev_t *dev = compat->dev;
	char pathbuf[PATH_MAX];
	const char *dirname;
	ni_ipv4_devinfo_t *ipv4;
	ni_ipv6_devinfo_t *ipv6;
	ni_tristate_t disable_ipv6 = NI_TRISTATE_DEFAULT;

	dirname = ni_dirname(sc->pathname);
	if (ni_string_empty(dirname))
		return FALSE;

	ni_var_array_copy(&ifsysctl, &__ni_suse_global_ifsysctl);
	snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s", dirname,
			__NI_SUSE_IFSYSCTL_FILE, dev->name);
	if (ni_isreg(pathbuf)) {
		ni_ifsysctl_file_load(&ifsysctl, pathbuf);
	}

	ipv4 = ni_netdev_get_ipv4(dev);
	ni_tristate_set(&ipv4->conf.enabled, TRUE);
	/* no conf.enable and conf.arp-verify in sysctl */
	__ifsysctl_get_tristate(&ifsysctl, "net/ipv4/conf", dev->name,
				"forwarding", &ipv4->conf.forwarding);
	__ifsysctl_get_tristate(&ifsysctl, "net/ipv4/conf", dev->name,
				"arp-notify", &ipv4->conf.arp_notify);
	__ifsysctl_get_tristate(&ifsysctl, "net/ipv4/conf", dev->name,
				"accept-redirects", &ipv4->conf.accept_redirects);

	ipv6 = ni_netdev_get_ipv6(dev);
	ni_tristate_set(&ipv6->conf.enabled, !__ni_ipv6_disbled);
	if (__ni_ipv6_disbled) {
		ni_var_array_destroy(&ifsysctl);
		return TRUE;
	}
	__ifsysctl_get_tristate(&ifsysctl, "net/ipv6/conf", dev->name,
				"disable_ipv6", &disable_ipv6);
	if (ni_tristate_is_set(disable_ipv6))
		ni_tristate_set(&ipv6->conf.enabled, !disable_ipv6);

	__ifsysctl_get_tristate(&ifsysctl, "net/ipv6/conf", dev->name,
				"forwarding", &ipv6->conf.forwarding);

	__ifsysctl_get_int(&ifsysctl, "net/ipv6/conf", dev->name,
				"accept_ra", &ipv6->conf.accept_ra, 10);
	if (ipv6->conf.accept_ra > NI_IPV6_ACCEPT_RA_ROUTER)
		ipv6->conf.accept_ra = NI_IPV6_ACCEPT_RA_ROUTER;
	else
	if (ipv6->conf.accept_ra < NI_IPV6_ACCEPT_RA_DEFAULT)
		ipv6->conf.accept_ra = NI_IPV6_ACCEPT_RA_DEFAULT;

	__ifsysctl_get_int(&ifsysctl, "net/ipv6/conf", dev->name,
				"accept_dad", &ipv6->conf.accept_dad, 10);
	if (ipv6->conf.accept_dad > NI_IPV6_ACCEPT_DAD_FAIL_PROTOCOL)
		ipv6->conf.accept_dad = NI_IPV6_ACCEPT_DAD_FAIL_PROTOCOL;
	else
	if (ipv6->conf.accept_dad < NI_IPV6_ACCEPT_DAD_DEFAULT)
		ipv6->conf.accept_dad = NI_IPV6_ACCEPT_DAD_DEFAULT;

	__ifsysctl_get_tristate(&ifsysctl, "net/ipv6/conf", dev->name,
				"autoconf", &ipv6->conf.autoconf);

	__ifsysctl_get_int(&ifsysctl, "net/ipv6/conf", dev->name,
				"privacy", &ipv6->conf.privacy, 10);
	if (ipv6->conf.privacy > NI_IPV6_PRIVACY_PREFER_TEMPORARY)
		ipv6->conf.privacy = NI_IPV6_PRIVACY_PREFER_TEMPORARY;
	else if (ipv6->conf.privacy < NI_IPV6_PRIVACY_DEFAULT)
		ipv6->conf.privacy = NI_IPV6_PRIVACY_DISABLED;

	__ifsysctl_get_tristate(&ifsysctl, "net/ipv6/conf", dev->name,
				"accept-redirects", &ipv6->conf.accept_redirects);
	return TRUE;
}

/*
 * Read an ifcfg file
 */
static ni_bool_t
__ni_suse_sysconfig_read(ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;

	compat->control = __ni_suse_startmode(sc);

	ni_sysconfig_get_integer(sc, "MTU", &dev->link.mtu);

	if (try_loopback(sc, compat)   < 0 ||
	    try_bonding(sc, compat)    < 0 ||
	    try_bridge(sc, compat)     < 0 ||
	    try_vlan(sc, compat)       < 0 ||
	    try_macvlan(sc, compat)    < 0 ||
	    try_dummy(sc, compat)      < 0 ||
	    try_tunnel(sc, compat)     < 0 ||
	    try_wireless(sc, compat)   < 0 ||
	    try_infiniband(sc, compat) < 0 ||
	    /* keep ethernet the last one */
	    try_ethernet(sc, compat)   < 0)
		return FALSE;

	__ni_suse_read_ifsysctl(sc, compat);
	__ni_suse_bootproto(sc, compat);
	/* FIXME: What to do with these:
		NAME
	 */

	return TRUE;
}

/*
 * Given a basename like "IPADDR", try to find all variables with this
 * prefix (eg "IPADDR", "IPADDR_0", "IPADDR_1", ...) and invoke the provided function
 * for each. Note, this passes the variable suffix ("", "_0", "_1") rather than
 * the full variable name into the called function.
 */
static int
__process_indexed_variables(const ni_sysconfig_t *sc, ni_netdev_t *dev,
				const char *basename,
				ni_bool_t (*func)(const ni_sysconfig_t *, ni_netdev_t *, const char *))
{
	ni_string_array_t names = NI_STRING_ARRAY_INIT;
	unsigned int i, pfxlen;

	if (!ni_sysconfig_find_matching(sc, basename, &names))
		return 1;

	pfxlen = strlen(basename);
	for (i = 0; i < names.count; ++i) {
		if (!func(sc, dev, names.data[i] + pfxlen)) {
			ni_string_array_destroy(&names);
			return -1;
		}
	}
	ni_string_array_destroy(&names);
	return 0;
}

/*
 * Given a base name and a suffix (eg "IPADDR" and "_1"), build a variable name
 * and look it up.
 */
static ni_var_t *
__find_indexed_variable(const ni_sysconfig_t *sc, const char *basename, const char *suffix)
{
	ni_var_t *res;
	char namebuf[64];

	snprintf(namebuf, sizeof(namebuf), "%s%s", basename, suffix);
	res = ni_sysconfig_get(sc, namebuf);
	if (res && (res->value == NULL || res->value[0] == '\0'))
		res = NULL;
	return res;
}
