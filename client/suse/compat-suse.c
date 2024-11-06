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
 *		Nirmoy Das <ndas@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include <wicked/ppp.h>
#include <wicked/team.h>
#include <wicked/ovs.h>
#include <wicked/bridge.h>
#include <wicked/vlan.h>
#include <wicked/vxlan.h>
#include <wicked/macvlan.h>
#include <wicked/wireless.h>
#include <wicked/fsm.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/tuntap.h>
#include <wicked/tunneling.h>
#include <wicked/ethtool.h>
#include <wicked/objectmodel.h>
#include <wicked/dbus.h>
#include <wicked/array.h>

#include "appconfig.h"
#include "util_priv.h"
#include "array_priv.h"
#include "duid.h"
#include "dhcp.h"
#include "dhcp6/options.h"
#include "dhcp6/request.h"
#include "client/suse/ifsysctl.h"
#include "client/wicked-client.h"

#include <ctype.h>
#include <errno.h>
#include <linux/if_arp.h>
#include <linux/if_addr.h>
#include <netlink/netlink.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <grp.h>


typedef struct ni_suse_ifcfg {
	ni_sysconfig_t *		config;
	ni_compat_netdev_t *		compat;
	ni_bool_t			broken;
	ni_bool_t			l2only;
} ni_suse_ifcfg_t;

#define NI_SUSE_IFCFG_ARRAY_INIT	NI_ARRAY_INIT
#define NI_SUSE_IFCFG_ARRAY_CHUNK	8
ni_declare_ptr_array_type(ni_suse_ifcfg);

static ni_suse_ifcfg_t *		ni_suse_ifcfg_new(void);
static void				ni_suse_ifcfg_free(ni_suse_ifcfg_t *);
static ni_suse_ifcfg_t *		ni_suse_ifcfg_new_missing(ni_suse_ifcfg_t *,
							const char *);
static void				ni_suse_ifcfg_set_hotplug(ni_suse_ifcfg_t *);
static void				ni_suse_ifcfg_set_l2_only(ni_suse_ifcfg_t *, ni_bool_t);
static ni_suse_ifcfg_t *		ni_suse_ifcfg_add_l2_port(ni_suse_ifcfg_array_t *,
							ni_suse_ifcfg_t *, const char *,
							const char *, const char *,
							ni_bool_t);
static ni_suse_ifcfg_t *		ni_suse_ifcfg_add_lower(ni_suse_ifcfg_array_t *,
							ni_suse_ifcfg_t *, const char *,
							const char *);

static ni_suse_ifcfg_t *		ni_suse_ifcfg_find_by_ifname(ni_suse_ifcfg_array_t *,
							const char *);

typedef ni_bool_t (*ifcfg_process_fn_t)(ni_suse_ifcfg_array_t *, ni_suse_ifcfg_t *,
					const char *, const char *, const char *);

static unsigned int			ni_suse_ifcfg_process_indexed(ni_suse_ifcfg_array_t *,
							ni_suse_ifcfg_t *, const char *,
							ifcfg_process_fn_t);

static ni_bool_t			ni_suse_ifcfg_parse(ni_suse_ifcfg_array_t *);

static					ni_declare_ptr_array_init(ni_suse_ifcfg);
static					ni_declare_ptr_array_destroy(ni_suse_ifcfg);
static					ni_declare_ptr_array_append(ni_suse_ifcfg);


typedef ni_bool_t (*try_function_t)(const ni_sysconfig_t *, ni_netdev_t *, const char *);

static ni_bool_t		__ni_suse_read_globals(const char *, const char *, const char *);
static void			__ni_suse_free_globals(void);
static void			__ni_suse_show_unapplied_routes(void);
static int			__process_indexed_variables(const ni_sysconfig_t *, ni_netdev_t *,
							const char *, try_function_t);
static ni_var_t *		__find_indexed_variable(const ni_sysconfig_t *, const char *, const char *);
static ni_bool_t		__ni_suse_read_routes(ni_route_table_t **, const char *, const char *);
static int			ni_wireless_parse_auth_mode(const ni_sysconfig_t *, ni_wireless_network_t *,
							const char *, const char *, ni_wireless_ap_scan_mode_t);
static ni_bool_t		ni_wireless_parse_wep_auth(const ni_sysconfig_t *, ni_wireless_network_t *,
							const char *, const char *);
static int			ni_wireless_parse_auth_proto(const ni_sysconfig_t *, unsigned int *,
							const char *, const char *);
static int			ni_wireless_parse_pairwise_cipher(const ni_sysconfig_t *, unsigned int *,
							const char *, const char *, const char *);
static int			ni_wireless_parse_group_cipher(const ni_sysconfig_t *, unsigned int *,
							const char *, const char *, const char *);
static ni_bool_t		__ni_wireless_parse_psk_auth(const ni_sysconfig_t *, ni_wireless_network_t *,
							const char *, const char *, ni_wireless_ap_scan_mode_t);
static ni_bool_t		__ni_wireless_parse_pmf(const ni_sysconfig_t *, ni_wireless_network_t *,
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

/* compat: no default script scheme as a safeguard (boo#907215, bsc#920070, bsc#919496) */
#define __NI_SUSE_SCRIPT_DEFAULT_SCHEME		NULL
#define __NI_SUSE_SYSCONF_DIR			"/etc"
#define __NI_SUSE_HOSTNAME_FILES		{ __NI_SUSE_SYSCONF_DIR"/hostname", \
						  __NI_SUSE_SYSCONF_DIR"/HOSTNAME", \
						  NULL }
#define __NI_SUSE_SYSCTL_SUFFIX			".conf"
#define __NI_SUSE_SYSCTL_BOOT			"/boot/sysctl.conf-"
#define __NI_SUSE_SYSCTL_DIRS			{ "/etc/sysctl.d",                  \
						  "/run/sysctl.d",                  \
						  "/usr/local/lib/sysctl.d",        \
						  "/usr/lib/sysctl.d",              \
						  "/lib/sysctl.d",                  \
						  NULL }
#define __NI_SUSE_SYSCTL_FILE			"/etc/sysctl.conf"
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
ni_suse_ifcfg_valid_suffix(const char *name, size_t pfxlen)
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
ni_suse_ifcfg_valid_prefix(const char *basename, const char *prefix)
{
	if (!basename || !prefix)
		return FALSE;

	return ni_string_startswith(basename, prefix);
}

/*
 * Read a single ifcfg file and init compat netdev
 */
static ni_suse_ifcfg_t *
ni_suse_ifcfg_read_file(const char *filename)
{
	const char *basename = ni_basename(filename);
	size_t pfxlen = sizeof(__NI_SUSE_CONFIG_IFPREFIX)-1;
	ni_suse_ifcfg_t *ifcfg = NULL;
	const char *ifname;

	/* Check in case ni_suse_ifcfg_read_file is used directly */
	if (!ni_suse_ifcfg_valid_prefix(basename, __NI_SUSE_CONFIG_IFPREFIX)) {
		ni_error("Rejecting file without '%s' prefix: %s",
				__NI_SUSE_CONFIG_IFPREFIX, filename);
		return NULL;
	}
	if (!ni_suse_ifcfg_valid_suffix(basename, pfxlen)) {
		ni_error("Rejecting blacklisted %sfile suffix: %s",
				__NI_SUSE_CONFIG_IFPREFIX, filename);
		return NULL;
	}

	ifname = basename + pfxlen;
	if (!ni_netdev_name_is_valid(ifname)) {
		ni_error("Rejecting suspect interface name: %s", ifname);
		return NULL;
	}

	if (!(ifcfg = ni_suse_ifcfg_new())) {
		ni_error("Unable to allocate ifcfg structure for %sfile: %s",
				__NI_SUSE_CONFIG_IFPREFIX, filename);
		return NULL;
	}

	if (!(ifcfg->compat = ni_compat_netdev_new(ifname))) {
		ni_error("Unable to allocate netdev structure for %sfile: %s",
				__NI_SUSE_CONFIG_IFPREFIX, filename);
		ni_suse_ifcfg_free(ifcfg);
		return NULL;
	}

	if (!(ifcfg->config = ni_sysconfig_read(filename))) {
		/* errors reported */
		ni_suse_ifcfg_free(ifcfg);
		return NULL;
	}

	return ifcfg;
}

/*
 * Read ifcfg files in directory and init compat netdevs
 */
static int
ni_suse_ifcfg_read_files(ni_suse_ifcfg_array_t *ifcfgs, const char *dirname)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	const char *pattern = __NI_SUSE_CONFIG_IFPREFIX"*";
	size_t pfxlen = sizeof(__NI_SUSE_CONFIG_IFPREFIX)-1;
	unsigned int i, count = ifcfgs->count;
	ni_suse_ifcfg_t *ifcfg;
	char *filename = NULL;
	const char *file;

	if (!ni_scandir(dirname, pattern, &files))
		return 0;

	for (i = 0; i < files.count; ++i) {
		if (!(file = files.data[i]))
			continue;

		if (!ni_suse_ifcfg_valid_suffix(file, pfxlen)) {
			/* e.g. .bak suffix created by firewalld */
			ni_debug_readwrite("Ignoring blacklisted %sfile suffix: %s",
					__NI_SUSE_CONFIG_IFPREFIX, file);
			continue;
		}

		if (!ni_string_printf(&filename, "%s/%s", dirname, file)) {
			ni_error("Failed to construct full path for %sfile %s: %m",
					__NI_SUSE_CONFIG_IFPREFIX, file);
			continue;
		}

		if (!(ifcfg = ni_suse_ifcfg_read_file(filename)))
			continue;	/* errors reported */

		if (!ni_suse_ifcfg_array_append(ifcfgs, ifcfg)) {
			ni_error("Failed to add '%s' structure to array: %m", file);
			ni_suse_ifcfg_free(ifcfg);
		}
	}

	ni_string_free(&filename);
	ni_string_array_destroy(&files);

	return ifcfgs->count - count;
}

ni_bool_t
__ni_suse_get_ifconfig(const char *root, const char *path, ni_compat_ifconfig_t *result)
{
	ni_suse_ifcfg_array_t ifcfgs = NI_SUSE_IFCFG_ARRAY_INIT;
	ni_bool_t success = FALSE;
	char pathbuf[PATH_MAX];
	char *pathname = NULL;
	const char *_path = __NI_SUSE_SYSCONFIG_NETWORK_DIR;
	unsigned int i;

	if (!ni_string_empty(path))
		_path = path;

	if (!root)
		root = "";

	if (ni_string_empty(root))
		snprintf(pathbuf, sizeof(pathbuf), "%s", _path);
	else
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", root, _path);

	if (!ni_realpath(pathbuf, &pathname)) {
		if (!ni_string_empty(path)) {
			ni_error("Configuration directory '%s' does not exist", path);
			goto done;
		}
	} else
	if (ni_isdir(pathname)) {

		if (!__ni_suse_read_globals(root, _path, pathname))
			goto done;

		if (!ni_suse_ifcfg_read_files(&ifcfgs, pathname)) {
			ni_debug_readwrite("No ifcfg files found in %s", pathname);
			success = TRUE;
			goto done;
		}

		if (__ni_suse_config_defaults) {
			extern unsigned int ni_wait_for_interfaces;

			ni_sysconfig_get_integer(__ni_suse_config_defaults,
						"WAIT_FOR_INTERFACES",
						&ni_wait_for_interfaces);
		}

		ni_suse_ifcfg_parse(&ifcfgs);
	} else {
		ni_error("Cannot use '%s' to read suse ifcfg files -- not a directory",
				pathname);
		goto done;
	}

	for (i = 0; i < ifcfgs.count; ++i) {
		ni_suse_ifcfg_t *ifcfg = ifcfgs.data[i];

		if (ifcfg->broken)
			continue;

		ni_compat_netdev_set_origin(ifcfg->compat, result->schema,
						ifcfg->config->pathname);
		ni_compat_netdev_array_append(&result->netdevs, ifcfg->compat);
		ifcfg->compat = NULL;
		ni_sysconfig_free(ifcfg->config);
		ifcfg->config = NULL;
	}

	__ni_suse_show_unapplied_routes();

	success = TRUE;

done:
	ni_string_free(&pathname);
	__ni_suse_free_globals();
	ni_suse_ifcfg_array_destroy(&ifcfgs);
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
		snprintf(filename, sizeof(filename), "%s%s", root, *name);

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
	const char *sysctldirs[] = __NI_SUSE_SYSCTL_DIRS, **sysctld;
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	ni_var_array_t sysctl_d_files = NI_VAR_ARRAY_INIT;
	char dirname[PATH_MAX];
	char pathbuf[PATH_MAX];
	const char *name;
	unsigned int i;
	struct utsname u;

	ni_var_array_destroy(&__ni_suse_global_ifsysctl);

	/*
	 * first /boot/sysctl.conf-<kernelversion>
	 */
	memset(&u, 0, sizeof(u));
	if (uname(&u) == 0) {
		snprintf(pathbuf, sizeof(pathbuf), "%s%s%s", root,
				__NI_SUSE_SYSCTL_BOOT, u.release);
		if (ni_file_exists(pathbuf))
			ni_string_array_append(&files, pathbuf);
	}

	/*
	 * then the new sysctl.d directories
	 */
	for (sysctld = sysctldirs; *sysctld; ++sysctld) {
		ni_string_array_t names = NI_STRING_ARRAY_INIT;

		snprintf(dirname, sizeof(dirname), "%s%s", root, *sysctld);
		if (!ni_isdir(dirname))
			continue;

		if (ni_scandir(dirname, "*"__NI_SUSE_SYSCTL_SUFFIX, &names)) {
			for (i = 0; i < names.count; ++i) {
				char *path = NULL;
				if (!ni_string_printf(&path, "%s/%s", dirname, names.data[i]))
					continue;
				if (!ni_var_array_get(&sysctl_d_files, names.data[i]))
					ni_var_array_append(&sysctl_d_files, names.data[i], path);
				ni_string_free(&path);
			}
		}
		ni_string_array_destroy(&names);
	}
	ni_var_array_sort_by_name(&sysctl_d_files);
	for(i = 0; i < sysctl_d_files.count; i++)
		ni_string_array_append(&files, sysctl_d_files.data[i].value);
	ni_var_array_destroy(&sysctl_d_files);

	/*
	 * then the old /etc/sysctl.conf
	 */
	snprintf(pathbuf, sizeof(pathbuf), "%s%s", root, __NI_SUSE_SYSCTL_FILE);
	if (ni_file_exists(pathbuf)) {
		if (ni_string_array_index(&files, pathbuf) == -1)
			ni_string_array_append(&files, pathbuf);
	}

	/*
	 * finally ifsysctl if they exist
	 */
	if (ni_string_empty(root))
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
				path, __NI_SUSE_IFSYSCTL_FILE);
	else
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s/%s",
				root, path, __NI_SUSE_IFSYSCTL_FILE);

	if (ni_file_exists(pathbuf)) {
		if (ni_string_array_index(&files, pathbuf) == -1)
			ni_string_array_append(&files, pathbuf);
	}

	for (i = 0; i < files.count; ++i) {
		name = files.data[i];
		ni_ifsysctl_file_load(&__ni_suse_global_ifsysctl, name);
	}

	ni_string_array_destroy(&files);
	return TRUE;
}


/*
 * Read global ifconfig files like config, dhcp and routes
 */
static ni_bool_t
__ni_suse_read_globals(const char *root, const char *path, const char *real)
{
	char pathbuf[PATH_MAX];

	if (path == NULL || real == NULL) {
		ni_error("%s: path is NULL", __func__);
		return FALSE;
	}

	__ni_suse_free_globals();

	__ni_suse_read_default_hostname(root, &__ni_suse_default_hostname);

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", real, __NI_SUSE_CONFIG_GLOBAL);
	if (ni_file_exists(pathbuf)) {
		__ni_suse_config_defaults = ni_sysconfig_read(pathbuf);
		if (__ni_suse_config_defaults == NULL) {
			ni_error("unable to parse %s", pathbuf);
			return FALSE;
		}
	} else {
		ni_warn("unable to find global config '%s': %m", pathbuf);
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", real, __NI_SUSE_CONFIG_DHCP);
	if (ni_file_exists(pathbuf)) {
		__ni_suse_dhcp_defaults = ni_sysconfig_read(pathbuf);
		if (__ni_suse_dhcp_defaults == NULL) {
			ni_error("unable to parse %s", pathbuf);
			return FALSE;
		}
	} else {
		ni_warn("unable to find global config '%s': %m", pathbuf);
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", real, __NI_SUSE_ROUTES_GLOBAL);
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

			if (!rp || rp->refcount >= 2)
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
		ni_sysconfig_free(__ni_suse_config_defaults);
		__ni_suse_config_defaults = NULL;
	}

	if (__ni_suse_dhcp_defaults) {
		ni_sysconfig_free(__ni_suse_dhcp_defaults);
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
			if (!next)
				return -1;
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
ni_suse_route_parse_time(const char *input, unsigned int *result)
{
        static const ni_intmap_t        time_map[] = {
                { "msecs",              0               },
                { "msec",               0               },
                { "ms",                 0               },
                { "secs",               1000            },
                { "sec",                1000            },
                { "s",                  1000            },
                { NULL,                 0               }
        };
        unsigned int factor = 0;
        unsigned long value;
        char *end = NULL;

        if (!result || !input || !*input || *input == '-') {
                errno = EINVAL;
                return -1;
        }

        errno = 0;
        value = strtoul(input, (char **) &end, 10);
        if (errno)
                return -1;
        if (*end && ni_parse_uint_mapped(end, time_map, &factor) < 0) {
                errno = EINVAL;
                return -1;
        }

        if (factor)
                value *= factor;

        *result = value;
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
			if (ni_suse_route_parse_time(val, &tmp) < 0)
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
			if (ni_suse_route_parse_time(val, &tmp) < 0)
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
			if (ni_suse_route_parse_time(val, &tmp) < 0)
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
	if (!(rp = ni_route_new()))
		goto failure;

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
		if (ni_sockaddr_parse(&rp->destination, dest, AF_UNSPEC) < 0) {
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

static int
parse_rule_prefix(ni_rule_prefix_t *prefix, const char *value, unsigned int family)
{
	unsigned int len;

	if (!prefix || ni_string_empty(value))
		return -1;

	if (ni_string_eq(value, "all")) {
		if (family == AF_INET)
			value = "0.0.0.0/0";
		else
		if (family == AF_INET6)
			value = "::/0";
		else
			return 1;
	}

	if (!ni_sockaddr_prefix_parse(value, &prefix->addr, &prefix->len))
		goto cleanup;

	if (family != AF_UNSPEC && family != prefix->addr.ss_family)
		goto cleanup;

	len = ni_af_address_prefixlen(prefix->addr.ss_family);
	if (prefix->len >= len)
		prefix->len = len;
	else
	if (!prefix->len && !ni_sockaddr_is_unspecified(&prefix->addr))
		prefix->len = len;

	return 0;
cleanup:
	memset(prefix, 0, sizeof(*prefix));
	return -1;
}

static int
ni_suse_parse_rule(ni_rule_t *rule, ni_string_array_t *opts,
		const char *filename, unsigned int line)
{
	const char *opt, *val;
	unsigned int pos = 0;
	unsigned int u32;
	char *tmp = NULL, *ptr;
	int ret;

	while ((opt = ni_string_array_at(opts, pos++))) {
		if (ni_string_eq(opt, "ipv4")) {
			if (rule->family != AF_UNSPEC && rule->family != AF_INET) {
				ni_error("%s[%u]: Cannot set multiple routing rule families",
						filename, line);
				return -1;
			}
			rule->family = AF_INET;
		}
		else
		if (ni_string_eq(opt, "ipv6")) {
			if (rule->family != AF_UNSPEC && rule->family != AF_INET6) {
				ni_error("%s[%u]: Cannot set multiple routing rule families",
						filename, line);
				return -1;
			}
			rule->family = AF_INET6;
		} else
		if (ni_string_eq(opt, "not")) {
			rule->flags |= NI_BIT(NI_RULE_INVERT);
		} else
		if (ni_string_eq(opt, "src") || ni_string_eq(opt, "from")) {
			val = ni_string_array_at(opts, pos++);
			if ((ret = parse_rule_prefix(&rule->src, val, rule->family)) < 0) {
				ni_error("%s[%u]: Cannot parse routing rule %s prefix '%s'",
						filename, line, opt, val);
				return ret;
			}
			if (ret == 0 && rule->family == AF_UNSPEC)
				rule->family = rule->src.addr.ss_family;
		} else
		if (ni_string_eq(opt, "dst") || ni_string_eq(opt, "to")) {
			val = ni_string_array_at(opts, pos++);
			if ((ret = parse_rule_prefix(&rule->dst, val, rule->family)) < 0) {
				ni_error("%s[%u]: Cannot parse routing rule %s prefix '%s'",
						filename, line, opt, val);
				return ret;
			}
			if (ret == 0 && rule->family == AF_UNSPEC)
				rule->family = rule->dst.addr.ss_family;
		} else
		if (ni_string_eq(opt, "preference") || ni_string_eq(opt, "pref") ||
		    ni_string_eq(opt, "priority")   || ni_string_eq(opt, "prio")) {
			val = ni_string_array_at(opts, pos++);
			if (ni_parse_uint(val, &u32, 0) < 0) {
				ni_error("%s[%u]: Cannot parse routing rule preference '%s'",
						filename, line, val);
				return -1;
			}
			rule->pref = u32;
			rule->set |= NI_RULE_SET_PREF;
		} else
		if (ni_string_eq(opt, "tos") || ni_string_eq(opt, "dsfield")) {
			val = ni_string_array_at(opts, pos++);
			if (ni_parse_uint(val, &u32, 16) < 0 || u32 > 255) {
				ni_error("%s[%u]: Cannot parse routing rule tos '%s'",
						filename, line, val);
				return -1;
			}
			rule->tos = u32;
		} else
		if (ni_string_eq(opt, "fwmark")) {
			val = ni_string_array_at(opts, pos++);
			if (!val || !ni_string_dup(&tmp, val)) {
				ni_error("%s[%u]: Cannot parse routing rule fwmark value",
						filename, line);
				ni_string_free(&tmp);
				return -1;
			}
			if ((ptr = strchr(tmp, '/')))
				*ptr++ = '\0';
			if (ni_parse_uint(tmp, &u32, 0) < 0) {
				ni_error("%s[%u]: Cannot parse routing rule fwmark '%s'",
						filename, line, val);
				ni_string_free(&tmp);
				return -1;
			}
			rule->fwmark = u32;
			if (ptr && ni_parse_uint(ptr, &u32, 0) < 0) {
				ni_error("%s[%u]: Cannot parse routing rule fwmark mask '%s'",
						filename, line, ptr);
				ni_string_free(&tmp);
				return -1;
			}
			rule->fwmask = u32;
			ni_string_free(&tmp);
		} else
		if (ni_string_eq(opt, "realm") || ni_string_eq(opt, "realms")) {
			val = ni_string_array_at(opts, pos++);
			if (ni_parse_uint(val, &u32, 0) < 0 || u32 > 255) {
				ni_error("%s[%u]: Cannot parse routing rule realm '%s'",
						filename, line, val);
				return -1;
			}
			rule->realm = u32;
		} else
		if (ni_string_eq(opt, "table") || ni_string_eq(opt, "lookup")) {
			val = ni_string_array_at(opts, pos++);
			if (!val || !ni_route_table_name_to_type(val, &u32)) {
				ni_error("%s[%u]: Cannot parse routing rule table '%s'",
						filename, line, val);
				ni_string_free(&tmp);
				return -1;
			}
			ni_string_free(&tmp);
			if (u32 == RT_TABLE_UNSPEC || u32 == RT_TABLE_MAX) {
				ni_error("%s[%u]: Cannot parse routing rule table '%s'",
						filename, line, val);
				return -1;
			}
			rule->table = u32;
		} else
		if (ni_string_eq(opt, "suppress-prefixlength") ||
		    ni_string_eq(opt, "suppress_prefixlength") ||
		    ni_string_eq(opt, "sup_pl")) {
			val = ni_string_array_at(opts, pos++);
			if (ni_parse_uint(val, &u32, 0) < 0 || u32 > INT_MAX) {
				ni_error("%s[%u]: Cannot parse routing rule prefix length suppressor '%s'",
						filename, line, val);
				return -1;
			}
			rule->suppress_prefixlen = u32;
		} else
		if (ni_string_eq(opt, "suppress-ifgroup") ||
		    ni_string_eq(opt, "suppress_ifgroup") ||
		    ni_string_eq(opt, "sup_group")) {
			val = ni_string_array_at(opts, pos++);
			if (ni_parse_uint(val, &u32, 0) < 0 || u32 > INT_MAX) {
				ni_error("%s[%u]: Cannot parse routing rule ifgroup suppressor '%s'",
						filename, line, val);
				return -1;
			}
			rule->suppress_ifgroup = u32;
		} else
		if (ni_string_eq(opt, "iif") || ni_string_eq(opt, "dev")) {
			val = ni_string_array_at(opts, pos++);
			if (!ni_netdev_name_is_valid(val)) {
				ni_error("%s[%u]: Invalid routing rule input interface '%s'",
						filename, line, val);
				return -1;
			}
			ni_string_dup(&rule->iif.name, val);
		} else
		if (ni_string_eq(opt, "oif")) {
			val = ni_string_array_at(opts, pos++);
			if (!ni_netdev_name_is_valid(val)) {
				ni_error("%s[%u]: Invalid routing rule output interface '%s'",
						filename, line, val);
				return -1;
			}
			ni_string_dup(&rule->oif.name, val);
		} else
		if (ni_string_eq(opt, "nat") || ni_string_eq(opt, "map-to")) {
			ni_error("%s[%u]: NAT routing rules are not supported any more",
					filename, line);
			return -1;
		} else {
			if (ni_string_eq(opt, "type")) {
				opt = ni_string_array_at(opts, pos++);
				if (ni_string_empty(opt)) {
					ni_error("%s[%u]: Missed routing rule action type",
							filename, line);
					return -1;
				}
			}

			if (ni_string_eq(opt, "goto")) {
				val = ni_string_array_at(opts, pos++);
				if (ni_parse_uint(val, &u32, 0) < 0) {
					ni_error("%s[%u]: Cannot parse routing rule goto target '%s'",
						filename, line, val);
					return -1;
				}
				rule->action = NI_RULE_ACTION_GOTO;
				rule->target = u32;
			} else
			if (ni_string_eq(opt, "nop")) {
				rule->action = NI_RULE_ACTION_NOP;
			} else
			if (ni_string_eq(opt, "blackhole")) {
				rule->action = NI_RULE_ACTION_BLACKHOLE;
			} else
			if (ni_string_eq(opt, "unreachable")) {
				rule->action = NI_RULE_ACTION_UNREACHABLE;
			} else
			if (ni_string_eq(opt, "prohibit")) {
				rule->action = NI_RULE_ACTION_PROHIBIT;
			} else {
				ni_error("%s[%u]: Unknown routing rule option '%s",
					filename, line, opt);
				return -1;
			}
		}
	}

	if (rule->family == AF_UNSPEC) {
		ni_error("%s[%u]: Invalid routing rule without family",
				filename, line);
		return -1;
	}

	if (!rule->action)
		rule->action = NI_RULE_ACTION_TO_TBL;
	if (!rule->table)
		rule->table = RT_TABLE_MAIN;

	return 0;
}

static int
ni_suse_parse_rule_line(ni_rule_array_t *rules, char *buffer, const char *ifname,
			const char *filename, unsigned int line)
{
	ni_string_array_t opts = NI_STRING_ARRAY_INIT;
	ni_stringbuf_t out = NI_STRINGBUF_INIT_DYNAMIC;
	ni_rule_t *rule;
	int ret;

	if (!ni_string_split(&opts, buffer, " \t", 0))
		return 1;

	if (!(rule = ni_rule_new())) {
		ni_error("%s[%u]: Unable to allocate routing rule structure",
				filename, line);
		return -1;
	}

	if ((ret = ni_suse_parse_rule(rule, &opts, filename, line))) {
		ni_rule_free(rule);
		return ret;
	}

	ni_debug_readwrite("Parsed routing rule: %s", ni_rule_print(&out, rule));
	ni_stringbuf_destroy(&out);
	return ni_rule_array_append(rules, rule);
}

ni_bool_t
ni_suse_read_rules(ni_rule_array_t *rules, const char *filename, const char *ifname)
{
	ni_stringbuf_t buff = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int line = 1, lcnt = 0;
	FILE *fp;
	int done;

	if ((fp = fopen(filename, "r")) == NULL) {
		ni_error("unable to open %s: %m", filename);
		return FALSE;
	}

	ni_debug_readwrite("ni_suse_read_rules(%s)", filename);

	ni_stringbuf_grow(&buff, 1023);
	do {
		ni_stringbuf_truncate(&buff, 0);

		line += lcnt;
		lcnt = 0;

		done = __ni_suse_read_route_line(fp, &buff, &lcnt);
		if (done < 0) {
			ni_error("%s[%u]: Cannot parse rule line continuation",
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
					"Parsing rule line: %s", buff.string);
			if (ni_suse_parse_rule_line(rules, buff.string,
						  ifname, filename, line) < 0)
				continue;
		}
	} while (!done);

	fclose(fp);
	ni_stringbuf_destroy(&buff);
	return TRUE;

error:
	fclose(fp);
	ni_stringbuf_destroy(&buff);
	ni_rule_array_destroy(rules);
	return FALSE;
}

/*
 * Translate the SUSE startmodes to <control> element
 */
static ni_ifworker_control_t *
ni_suse_ifcfg_parse_startmode(const ni_sysconfig_t *sc)
{
	static const struct ni_suse_control_params {
		const char *		name;
		ni_ifworker_control_t	control;
	} control_params[] = {
		/* manual is the default in ifcfg */
		{ "manual",	{ "manual",	NULL,		FALSE,	FALSE,	NI_TRISTATE_DEFAULT,	0, 0 } },

		{ "auto",	{ "boot",	NULL,		FALSE,	FALSE,	NI_TRISTATE_DEFAULT,	0, 0 } },
		{ "boot",	{ "boot",	NULL,		FALSE,	FALSE,	NI_TRISTATE_DEFAULT,	0, 0 } },
		{ "onboot",	{ "boot",	NULL,		FALSE,	FALSE,	NI_TRISTATE_DEFAULT,	0, 0 } },
		{ "on",		{ "boot",	NULL,		FALSE,	FALSE,	NI_TRISTATE_DEFAULT,	0, 0 } },

		{ "nfsroot",	{ "boot",	"localfs",	TRUE,	FALSE,	NI_TRISTATE_DEFAULT,	0, 0 } },

		{ "hotplug",	{ "hotplug",	NULL,		FALSE,	FALSE,	NI_TRISTATE_DEFAULT,	0, 0 } },
		{ "ifplugd",	{ "ifplugd",	NULL,		FALSE,	FALSE,	NI_TRISTATE_DEFAULT,	0, 0 } },

		{ "off",	{ "off",	NULL,		FALSE,	FALSE,	NI_TRISTATE_DEFAULT,	0, 0 } },

		{ NULL }
	};
	const struct ni_suse_control_params *p, *params = NULL;
	ni_ifworker_control_t *control;
	const char *mode, *value;

	params = &control_params[0];
	if ((mode = ni_sysconfig_get_value(sc, "STARTMODE"))) {
		for (p = control_params; p->name; ++p) {
			if (ni_string_eq(p->name, mode)) {
				params = p;
				break;
			}
		}
		if (!p->name) {
			ni_warn("%s: ifcfg file with invalid STARTMODE='%s', assuming '%s'",
					ni_basename(sc->pathname), mode, params->name);
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

		if (!(value = ni_sysconfig_get_value(sc, "LINK_REQUIRED")) && __ni_suse_config_defaults)
			value = ni_sysconfig_get_value(__ni_suse_config_defaults, "LINK_REQUIRED");
		if (value) {
			/* otherwise assume "auto" */
			if (ni_string_eq(value, "yes"))
				ni_tristate_set(&control->link_required, TRUE);
			else
			if (ni_string_eq(value, "no"))
				ni_tristate_set(&control->link_required, FALSE);
		}

		if ((value = ni_sysconfig_get_value(sc, "LINK_READY_WAIT"))) {
			if (ni_parse_seconds_timeout(value, &control->link_timeout)
			||  control->link_timeout == NI_IFWORKER_INFINITE_SECONDS)
				control->link_timeout = 0; /* ifcfg(5): default is 0 */
		}
	}
	return control;
}

/*
 * Try loopback interface
 */
static int
try_loopback(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	ni_netdev_t *dev = ifcfg->compat->dev;

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
maybe_infiniband(const char *ifname)
{
	char *end = NULL;
	unsigned long tmp = 0;

	if (!ni_string_startswith(ifname, "ib"))
		return FALSE;

	strtoul(ifname + 2, (char**) &end, 10);
	if (end - ifname - 2 == 0)
		return FALSE;

	if (*end == '\0')
		return TRUE;

	if (*end == '.' && ni_parse_ulong(end + 1, &tmp, 16) == 0)
		return TRUE;

	return FALSE;
}

static int
try_infiniband(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_bool_t enabled;
	ni_bool_t ib_ifname = FALSE;
	const char *umcast;
	const char *mode;
	const char *pkey;
	const char *err;
	const char *tmp;
	char *device = NULL;
	ni_infiniband_t *ib;

	mode   = ni_sysconfig_get_value(sc, "IPOIB_MODE");
	umcast = ni_sysconfig_get_value(sc, "IPOIB_UMCAST");

	ib_ifname = maybe_infiniband(dev->name);

	if (!ni_sysconfig_get(sc, "IPOIB")) {
		/* for backward compatibility, UMCAST, MODE or ifname =~ /^ib[0-9]+\.[a-fA-F0-9]+$/
		 * are treated like IPOIB=yes */
		if (!mode && !umcast && !(dev->link.type == NI_IFTYPE_UNKNOWN && ib_ifname))
			return 1;
	} else {
		if (!ni_sysconfig_get_boolean(sc, "IPOIB", &enabled) || !enabled)
			return 1;
	}

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains infiniband variables",
				dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_INFINIBAND;
	ib = ni_netdev_get_infiniband(dev);

	ni_string_dup(&device, ni_sysconfig_get_value(sc, "IPOIB_DEVICE"));
	pkey = ni_sysconfig_get_value(sc, "IPOIB_PKEY");

	if (ib_ifname && (tmp = strchr(dev->name, '.'))) {
		if (!pkey)
			pkey = tmp + 1;
		if (!device)
			ni_string_set(&device, dev->name, tmp - dev->name);
	}

	if (pkey || device) {
		unsigned long tmp = ~0UL;

		if (ni_parse_ulong(pkey, &tmp, 16) < 0 || tmp > 0xffff) {
			ni_error("ifcfg-%s: %s %s partition key (IPOIB_PKEY)", dev->name,
					pkey ? "Cannot parse" : "Missing",
					ni_linktype_type_to_name(NI_IFTYPE_INFINIBAND_CHILD));
			ni_string_free(&device);
			return -1;
		}

		if (!ni_netdev_name_is_valid(device)) {
			ni_error("ifcfg-%s: %s %s parent device name (IPOIB_DEVICE)", dev->name,
					device ? "Invalid" : "Missing",
					ni_linktype_type_to_name(NI_IFTYPE_INFINIBAND_CHILD));
			ni_string_free(&device);
			return -1;
		}

		ib->pkey = tmp;
		dev->link.type = NI_IFTYPE_INFINIBAND_CHILD;

		if (!ni_suse_ifcfg_add_lower(ifcfgs, ifcfg, device, "IPOIB_DEVICE"))
			return -1;

		ni_string_dup(&dev->link.lowerdev.name, device);
	}
	ni_string_free(&device);

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
 * Handle ethtool service config
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


static inline void
ni_parse_ethtool_mdi_onoff(const char *input, uint8_t *val)
{
	if (ni_string_eq(input, "on")) {
		*val = NI_ETHTOOL_MDI_X;
	} else
	if (ni_string_eq(input, "off")) {
		*val = NI_ETHTOOL_MDI;
	} else
	if (ni_string_eq(input, "auto")) {
		*val = NI_ETHTOOL_MDI_AUTO;
	}
}

static inline ni_bool_t
ni_parse_ethtool_wol_options(const char *input, ni_ethtool_wake_on_lan_t *wol)
{
	ni_bool_t disabled = FALSE;
	unsigned int options = 0;
	if (!input || !wol)
		return FALSE;

	while(*input) {
		switch (*input) {
		case 'p':
			options |= NI_BIT(NI_ETHTOOL_WOL_PHY);
			break;
		case 'u':
			options |= NI_BIT(NI_ETHTOOL_WOL_UCAST);
			break;
		case 'm':
			options |= NI_BIT(NI_ETHTOOL_WOL_MCAST);
			break;
		case 'b':
			options |= NI_BIT(NI_ETHTOOL_WOL_BCAST);
			break;
		case 'a':
			options |= NI_BIT(NI_ETHTOOL_WOL_ARP);
			break;
		case 'g':
			options |= NI_BIT(NI_ETHTOOL_WOL_MAGIC);
			break;
		case 's':
			options |= NI_BIT(NI_ETHTOOL_WOL_SECUREON);
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
		wol->options = NI_ETHTOOL_WOL_DISABLE;
	} else
	if (options) {
		wol->options = options;
	}
	return  TRUE;
}

static inline ni_bool_t
ni_parse_ethtool_wol_sopass(const char *input, ni_ethtool_wake_on_lan_t *wol, const char *ifname)
{
	if (!input || !wol)
		return FALSE;


	if (ni_link_address_parse(&wol->sopass, ARPHRD_ETHER, input) < 0) {
		return FALSE;
	}
	if (!(wol->options & NI_BIT(NI_ETHTOOL_WOL_SECUREON))) {
		ni_warn("ifcfg-%s: secureon was disabled , enabling secureon", ifname);
		wol->options |= NI_BIT(NI_ETHTOOL_WOL_SECUREON);
	}

	return TRUE;
}

static void
add_ethtool_advertise(ni_bitfield_t *bitfield, const char *val)
{
	ni_string_array_t modes = NI_STRING_ARRAY_INIT;
	unsigned int bit, i;

	ni_string_split(&modes, val, ",", 0);
	for (i = 0; i < modes.count; i++) {
		const char *name = modes.data[i];

		if (ni_ethtool_link_adv_type(name, &bit))
			ni_bitfield_setbit(bitfield, bit);
		else
			ni_bitfield_parse(bitfield, name, 0);
	}
	ni_string_array_destroy(&modes);
}

static void
try_add_ethtool_common(ni_netdev_t *dev, const char *opt, const char *val)
{
	ni_ethtool_link_settings_t *link = ni_netdev_get_ethtool_link_settings(dev);
	ni_ethtool_wake_on_lan_t   *wol;
	unsigned int tmp;

	if (ni_string_eq(opt, "speed")) {
		if (ni_parse_uint(val, &tmp, 0) == 0 && tmp && tmp <= INT_MAX)
			link->speed = tmp;
	} else
	if (ni_string_eq(opt, "port")) {
		if (ni_ethtool_link_port_type(val, &tmp))
			link->port = tmp;
	} else
	if (ni_string_eq(opt, "duplex")) {
		if (ni_ethtool_link_duplex_type(val, &tmp))
			link->duplex = tmp;
	} else
	if (ni_string_eq(opt, "autoneg")) {
		ni_parse_ethtool_onoff(val, &link->autoneg);
	} else
	if (ni_string_eq(opt, "advertise")) {
		add_ethtool_advertise(&link->advertising, val);
	} else
	if (ni_string_eq(opt, "mdix")) {
		ni_parse_ethtool_mdi_onoff(val, &link->tp_mdix);
	} else
	if (ni_string_eq(opt, "phyad")) {
		if (ni_parse_uint(val, &tmp, 0) == 0)
			link->phy_address = tmp;
	} else
	if (ni_string_eq(opt, "xcvr")) {
		uint32_t xcvr;
		if (ni_ethtool_link_xcvr_type(val, &xcvr) && xcvr <= NI_ETHTOOL_XCVR_UNKNOWN)
			link->transceiver = xcvr;
	} else
	if (ni_string_eq(opt, "wol")) {
		if ((wol = ni_netdev_get_ethtool_wake_on_lan(dev)))
			ni_parse_ethtool_wol_options(val,  wol);
	}
	else
	if (ni_string_eq(opt, "sopass")) {
		if ((wol = ni_netdev_get_ethtool_wake_on_lan(dev)))
			ni_parse_ethtool_wol_sopass(val, wol, dev->name);
	}
}

static void
try_add_ethtool_priv(ni_netdev_t *dev, const char *opt, const char *val)
{
	ni_ethtool_priv_flags_t *priv_flags = ni_netdev_get_ethtool_priv_flags(dev);
	int bit = priv_flags->names.count;
	ni_bool_t enabled;

	ni_string_array_append(&priv_flags->names, opt);
	if (ni_parse_boolean(val, &enabled) == 0 && enabled)
		priv_flags->bitmap |= NI_BIT(bit);
}

static void
try_add_ethtool_features(ni_netdev_t *dev, const char *opt, const char *val)
{
	ni_ethtool_features_t *features = ni_netdev_get_ethtool_features(dev);
	ni_bool_t enabled;


	if (features) {
		ni_parse_boolean(val, &enabled);
		ni_ethtool_features_set(features, opt,
			(enabled ? NI_ETHTOOL_FEATURE_ON : NI_ETHTOOL_FEATURE_OFF));
	}
}

/* get coalesce from ifcfg config */
static void
try_add_ethtool_coalesce(ni_netdev_t *dev, const char *opt, const char *val)
{
	ni_ethtool_coalesce_t *coalesce = ni_netdev_get_ethtool_coalesce(dev);
	ni_bool_t bval;

	if (ni_string_eq(opt, "adaptive-rx")) {
		if (ni_parse_boolean(val, &bval) == 0)
			ni_tristate_set(&coalesce->adaptive_rx, bval);
	} else
	if (ni_string_eq(opt, "adaptive-tx")) {
		if (ni_parse_boolean(val, &bval) == 0)
			ni_tristate_set(&coalesce->adaptive_tx, bval);
	} else
	if (ni_string_eq(opt, "rx-usecs")) {
		ni_parse_uint(val, &coalesce->rx_usecs, 10);
	} else
	if (ni_string_eq(opt, "rx-frames")) {
		ni_parse_uint(val, &coalesce->rx_frames, 10);
	} else
	if (ni_string_eq(opt, "rx-usecs-irq")) {
		ni_parse_uint(val, &coalesce->rx_usecs_irq, 10);
	} else
	if (ni_string_eq(opt, "rx-frames-irq")) {
		ni_parse_uint(val, &coalesce->rx_frames_irq, 10);
	} else
	if (ni_string_eq(opt, "tx-usecs")) {
		ni_parse_uint(val, &coalesce->tx_usecs, 10);
	} else
	if (ni_string_eq(opt, "tx-frames")) {
		ni_parse_uint(val, &coalesce->tx_frames, 10);
	} else
	if (ni_string_eq(opt, "tx-usecs-irq")) {
		ni_parse_uint(val, &coalesce->tx_usecs_irq, 10);
	} else
	if (ni_string_eq(opt, "tx-frames-irq")) {
		ni_parse_uint(val, &coalesce->tx_frames_irq, 10);
	} else
	if (ni_string_eq(opt, "stats-block-usecs")) {
		ni_parse_uint(val, &coalesce->stats_block_usecs, 10);
	} else
	if (ni_string_eq(opt, "pkt-rate-low")) {
		ni_parse_uint(val, &coalesce->pkt_rate_low, 10);
	} else
	if (ni_string_eq(opt, "rx-usecs-low")) {
		ni_parse_uint(val, &coalesce->rx_usecs_low, 10);
	} else
	if (ni_string_eq(opt, "rx-frames-low")) {
		ni_parse_uint(val, &coalesce->rx_frames_low, 10);
	} else
	if (ni_string_eq(opt, "tx-usecs-low")) {
		ni_parse_uint(val, &coalesce->tx_usecs_low, 10);
	} else
	if (ni_string_eq(opt, "tx-frames-low")) {
		ni_parse_uint(val, &coalesce->tx_frames_low, 10);
	} else
	if (ni_string_eq(opt, "pkt-rate-high")) {
		ni_parse_uint(val, &coalesce->pkt_rate_high, 10);
	} else
	if (ni_string_eq(opt, "rx-usecs-high")) {
		ni_parse_uint(val, &coalesce->rx_usecs_high, 10);
	} else
	if (ni_string_eq(opt, "rx-frames-high")) {
		ni_parse_uint(val, &coalesce->rx_frames_high, 10);
	} else
	if (ni_string_eq(opt, "tx-usecs-high")) {
		ni_parse_uint(val, &coalesce->tx_usecs_high, 10);
	} else
	if (ni_string_eq(opt, "tx-frames-high")) {
		ni_parse_uint(val, &coalesce->tx_frames_high, 10);
	} else
	if (ni_string_eq(opt, "sample-interval")) {
		ni_parse_uint(val, &coalesce->sample_interval, 10);
	}
}

/* get eee settings from ifcfg variable */
static void
try_add_ethtool_eee(ni_netdev_t *dev, const char *opt, const char *val)
{
	ni_ethtool_eee_t *eee = ni_netdev_get_ethtool_eee(dev);
	ni_bool_t bval;

	if (!eee)
		return;

	if (ni_string_eq(opt, "eee")) {
		if (ni_parse_boolean(val, &bval) == 0)
			ni_tristate_set(&eee->status.enabled, bval);
	} else
	if (ni_string_eq(opt, "advertise")) {
		add_ethtool_advertise(&eee->speed.advertising, val);
	} else
	if (ni_string_eq(opt, "tx-lpi")) {
		if (ni_parse_boolean(val, &bval) == 0)
			ni_tristate_set(&eee->tx_lpi.enabled, bval);
	} else
	if (ni_string_eq(opt, "tx-timer")) {
		ni_parse_uint(val, &eee->tx_lpi.timer, 10);
	}
}

/* get channels params from wicked config */
static void
try_add_ethtool_channels(ni_netdev_t *dev, const char *opt, const char *val)
{
	ni_ethtool_channels_t *channels = ni_netdev_get_ethtool_channels(dev);

	if (ni_string_eq(opt, "tx")) {
		ni_parse_uint(val, &channels->tx, 10);
	} else
	if (ni_string_eq(opt, "rx")) {
		ni_parse_uint(val, &channels->rx, 10);
	} else
	if (ni_string_eq(opt, "other")) {
		ni_parse_uint(val, &channels->other, 10);
	} else
	if (ni_string_eq(opt, "combined")) {
		ni_parse_uint(val, &channels->combined, 10);
	}
}

/* get ringparams from wicked config */
static void
try_add_ethtool_ring(ni_netdev_t *dev, const char *opt, const char *val)
{
	ni_ethtool_ring_t *ring = ni_netdev_get_ethtool_ring(dev);

	if (ni_string_eq(opt, "tx")) {
		ni_parse_uint(val, &ring->tx, 10);
	} else
	if (ni_string_eq(opt, "rx")) {
		ni_parse_uint(val, &ring->rx, 10);
	} else
	if (ni_string_eq(opt, "rx-jumbo")) {
		ni_parse_uint(val, &ring->rx_jumbo, 10);
	} else
	if (ni_string_eq(opt, "rx-mini")) {
		ni_parse_uint(val, &ring->rx_mini, 10);
	}
}

/* get pause params from wicked config */
static void
try_add_ethtool_pause(ni_netdev_t *dev, const char *opt, const char *val)
{
	ni_ethtool_pause_t *pause = ni_netdev_get_ethtool_pause(dev);
	ni_bool_t bval;

	if (ni_string_eq(opt, "tx")) {
		if (ni_parse_boolean(val, &bval) == 0)
			ni_tristate_set(&pause->tx, bval);
	} else
	if (ni_string_eq(opt, "rx")) {
		if (ni_parse_boolean(val, &bval) == 0)
			ni_tristate_set(&pause->rx, bval);
	} else
	if (ni_string_eq(opt, "autoneg")) {
		if (ni_parse_boolean(val, &bval) == 0)
			ni_tristate_set(&pause->autoneg, bval);
	}
}

static void
try_add_ethtool_options(ni_netdev_t *dev, const char *type,
			ni_string_array_t *opts, unsigned int start)
{
	unsigned int i;

	if (ni_string_eq(type, "-s") || ni_string_eq(type, "--change")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_common(dev, opts->data[i],
						opts->data[i + 1]);
		}
	} else
	if (/* no short option */ ni_string_eq(type, "--set-priv-flags")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_priv(dev, opts->data[i], opts->data[i + 1]);
		}
	} else
	if (ni_string_eq(type, "-K") || ni_string_eq(type, "--offload")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_features(dev, opts->data[i],
						opts->data[i + 1]);
		}
	} else
	if (/* no short eee option */  ni_string_eq(type, "--set-eee")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_eee(dev, opts->data[i],
						opts->data[i + 1]);
		}
	} else
	if (ni_string_eq(type, "-G") || ni_string_eq(type, "--set-ring")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_ring(dev, opts->data[i],
						opts->data[i + 1]);
		}
	} else
	if (ni_string_eq(type, "-C") || ni_string_eq(type, "--coalesce")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_coalesce(dev, opts->data[i],
						opts->data[i + 1]);
		}
	}
	if (ni_string_eq(type, "-L") || ni_string_eq(type, "--set-channels")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_channels(dev, opts->data[i],
						opts->data[i + 1]);
		}
	} else
	if (ni_string_eq(type, "-A") || ni_string_eq(type, "--pause")) {
		for (i = start; (i + 1) < opts->count; i+=2) {
			try_add_ethtool_pause(dev, opts->data[i],
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

	if (!ni_netdev_get_ethtool(dev))
		return FALSE;

	/*
	 * ETHTOOL_OPTIONS comes in two flavors
	 *   - starting with a dash: this is "-$option ifname $stuff"
	 *   - otherwise: this is a parameter to be passed to "-s ifname"
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

static ni_bool_t
ni_suse_ifcfg_parse_ethtool(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_compat_netdev_t *compat = ifcfg->compat;
	ni_netdev_t *dev = compat->dev;

	/* process ETHTOOL_OPTIONS[SUFFIX] array */
	if (__process_indexed_variables(sc, dev, "ETHTOOL_OPTIONS",
					try_add_ethtool_vars) < 0) {
		ni_warn("ifcfg-%s: Cannot parse ETHTOOL_OPTIONS variables",
				dev->name);
	}
	return TRUE;
}

static int
try_ethernet(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
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
try_add_bonding_port(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg,
		const char *port, const char *variable, const char *suffix)
{
	ni_suse_ifcfg_t *pcfg;
	ni_netdev_t *mdev;
	const char *type;

	mdev = ifcfg->compat->dev;
	type = ni_linktype_type_to_name(mdev->link.type);
	if (!(pcfg = ni_suse_ifcfg_add_l2_port(ifcfgs,
			ifcfg, mdev->name, type, port, FALSE))) {
		ni_error("ifcfg-%s: failed to add %s port %s='%s'",
				mdev->name, type, variable, port);
		return FALSE;
	}

	ni_netdev_port_config_destroy(&pcfg->compat->port);
	ni_netdev_port_config_init(&pcfg->compat->port, mdev->link.type);
	/* no bond port specific config variables implemented yet */

	return TRUE;
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
try_bonding(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	const char *module_opts, *err;
	const char *lladdr;
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

	if ((module_opts = ni_sysconfig_get_value(sc, "BONDING_MODULE_OPTS")) != NULL) {
		if (!try_set_bonding_options(dev, module_opts))
			return -1;
	}

	if ((err = ni_bonding_validate(ni_netdev_get_bonding(dev))) != NULL) {
		ni_error("ifcfg-%s: bonding validation: %s",
			dev->name, err);
		return -1;
	}

	if ((lladdr = ni_sysconfig_get_value(sc, "LLADDR")) != NULL) {
		if (ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, lladdr) < 0) {
			ni_link_address_init(&dev->link.hwaddr);
			ni_error("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
				dev->name, lladdr);
			return -1;
		}
	}

	if (!ni_suse_ifcfg_process_indexed(ifcfgs, ifcfg, "BONDING_SLAVE",
			try_add_bonding_port)) {
		ni_error("ifcfg-%s: invalid bonding without BONDING_SLAVEs",
				dev->name);
		return -1;
	}

	return 0;
}

static ni_bool_t
try_add_team_link_watch(const ni_sysconfig_t *sc, ni_netdev_t *dev, const char *suffix)
{
	ni_team_link_watch_t *lw;
	ni_team_t *team;
	ni_var_t *var;
	ni_team_link_watch_type_t type;

	if (!(team = ni_netdev_get_team(dev)))
		return FALSE;

	/* Just skip link_watch with no name */
	if (!(var = __find_indexed_variable(sc, "TEAM_LW_NAME", suffix))) {
		ni_error("ifcfg-%s: empty TEAM_LW_NAME%s value",
			dev->name, suffix);
		return FALSE;
	}

	if (!ni_team_link_watch_name_to_type(var->value, &type)) {
		ni_error("ifcfg-%s: unable to parse TEAM_LW_NAME%s=%s",
			dev->name, suffix, var->value);
		return FALSE;
	}

	lw = ni_team_link_watch_new(type);
	switch(lw->type) {
	case NI_TEAM_LINK_WATCH_ETHTOOL: {
			ni_team_link_watch_ethtool_t *ethtool = &lw->ethtool;

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ETHTOOL_DELAY_UP", suffix))) {
				if (ni_parse_uint(var->value, &ethtool->delay_up, 10) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_ETHTOOL_DELAY_UP%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ETHTOOL_DELAY_DOWN", suffix))) {
				if (ni_parse_uint(var->value, &ethtool->delay_down, 10) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_ETHTOOL_DELAY_DOWN%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}
		}
		break;

	case NI_TEAM_LINK_WATCH_ARP_PING: {
			ni_team_link_watch_arp_t *arp = &lw->arp;

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ARP_PING_SOURCE_HOST", suffix))) {
				ni_string_dup(&arp->source_host, var->value);
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ARP_PING_TARGET_HOST", suffix))) {
				ni_string_dup(&arp->target_host, var->value);
			} else {
				ni_warn("ifcfg-%s: Missed TEAM_LW_ARP_PING_TARGET_HOST%s variable",
					dev->name, suffix);
				goto skipped;
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ARP_PING_INTERVAL", suffix))) {
				if (ni_parse_uint(var->value, &arp->interval, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_ARP_PING_INTERVAL%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ARP_PING_INIT_WAIT", suffix))) {
				if (ni_parse_uint(var->value, &arp->init_wait, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_ARP_PING_INIT_WAIT%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ARP_PING_VALIDATE_ACTIVE", suffix))) {
				if (ni_parse_boolean(var->value, &arp->validate_active)) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_ARP_PING_VALIDATE_ACTIVE%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ARP_PING_VALIDATE_INACTIVE", suffix))) {
				if (ni_parse_boolean(var->value, &arp->validate_inactive)) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_ARP_PING_VALIDATE_INACTIVE%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ARP_PING_SEND_ALWAYS", suffix))) {
				if (ni_parse_boolean(var->value, &arp->send_always)) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_ARP_PING_SEND_ALWAYS%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ARP_PING_MISSED_MAX", suffix))) {
				if (ni_parse_uint(var->value, &arp->missed_max, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_ARP_PING_MISSED_MAX%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_ARP_PING_VLANID", suffix))) {
				uint32_t u32;

				if (ni_parse_uint(var->value, &u32, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_ARP_PING_VLANID%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
				if (u32 > 4096) {
					ni_error("ifcfg-%s: Invalid value in TEAM_LW_ARP_PING_VLANID%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
				arp->vlanid = (uint16_t)u32;
			}
		}
		break;

	case NI_TEAM_LINK_WATCH_NSNA_PING: {
			ni_team_link_watch_nsna_t *nsna = &lw->nsna;

			if ((var = __find_indexed_variable(sc, "TEAM_LW_NSNA_PING_TARGET_HOST", suffix))) {
				ni_string_dup(&nsna->target_host, var->value);
			} else {
				ni_warn("ifcfg-%s: Missed TEAM_LW_NSNA_PING_TARGET_HOST%s variable",
					dev->name, suffix);
				goto skipped;
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_NSNA_PING_INTERVAL", suffix))) {
				if (ni_parse_uint(var->value, &nsna->interval, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_NSNA_PING_INTERVAL%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_NSNA_PING_INIT_WAIT", suffix))) {
				if (ni_parse_uint(var->value, &nsna->init_wait, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_NSNA_PING_INIT_WAIT%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}

			if ((var = __find_indexed_variable(sc, "TEAM_LW_NSNA_PING_MISSED_MAX", suffix))) {
				if (ni_parse_uint(var->value, &nsna->missed_max, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LW_NSNA_PING_MISSED_MAX%s='%s'",
						dev->name, suffix, var->value);
					goto failure;
				}
			}
		}
		break;

	case NI_TEAM_LINK_WATCH_TIPC: {
			ni_team_link_watch_tipc_t *tipc = &lw->tipc;

			if ((var = __find_indexed_variable(sc, "TEAM_LW_TIPC_BEARER", suffix))) {
				ni_string_dup(&tipc->bearer, var->value);
			} else {
				ni_warn("ifcfg-%s: Missed TEAM_LW_TIPC_BEARER%s variable",
					dev->name, suffix);
				goto skipped;
			}
		}
		break;

	default:
		goto failure;
	}

	return ni_team_link_watch_array_append(&team->link_watch, lw);

skipped:
	ni_team_link_watch_free(lw);
	return TRUE;

failure:
	ni_team_link_watch_free(lw);
	return FALSE;
}

static ni_bool_t
try_add_team_port_config(ni_team_port_config_t *pconf, const ni_sysconfig_t *sc,
		const char *suffix, const char *file)
{
	ni_bool_t ret = TRUE;
	ni_var_t *var;

	if ((var = __find_indexed_variable(sc, "TEAM_PORT_QUEUE_ID", suffix))) {
		if (ni_parse_uint(var->value, &pconf->queue_id, 10) < 0) {
			ni_warn("ifcfg-%s: Cannot parse TEAM_PORT_QUEUE_ID%s='%s'",
				file, suffix, var->value);
			ret = FALSE;
		}
	}

	if ((var = __find_indexed_variable(sc, "TEAM_PORT_PRIO", suffix))) {
		if (ni_parse_uint(var->value, &pconf->ab.prio, 10) < 0) {
			ni_warn("ifcfg-%s: Cannot parse TEAM_PORT_PRIO%s='%s'",
				file, suffix, var->value);
			ret = FALSE;
		}
	}

	if ((var = __find_indexed_variable(sc, "TEAM_PORT_STICKY", suffix))) {
		if (ni_parse_boolean(var->value, &pconf->ab.sticky) < 0) {
			ni_warn("ifcfg-%s: Cannot parse TEAM_PORT_STICKY%s='%s'",
				file, suffix, var->value);
			ret = FALSE;
		}
	}

	if ((var = __find_indexed_variable(sc, "TEAM_PORT_LACP_PRIO", suffix))) {
		if (ni_parse_uint(var->value, &pconf->lacp.prio, 10) < 0) {
			ni_warn("ifcfg-%s: Cannot parse TEAM_PORT_LACP_PRIO%s='%s'",
				file, suffix, var->value);
			ret = FALSE;
		}
	}

	if ((var = __find_indexed_variable(sc, "TEAM_PORT_LACP_KEY", suffix))) {
		if (ni_parse_uint(var->value, &pconf->lacp.key, 10) < 0) {
			ni_warn("ifcfg-%s: Cannot parse TEAM_PORT_LACP_KEY%s='%s'",
				file, suffix, var->value);
			ret = FALSE;
		}
	}

	return ret;
}

static ni_bool_t
try_add_team_port(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg,
		const char *port, const char *variable, const char *suffix)
{
	ni_suse_ifcfg_t *pcfg;
	ni_netdev_t *mdev;
	ni_team_t *team;
	ni_bool_t l2v6 = FALSE;
	const char *type;

	mdev = ifcfg->compat->dev;
	if ((team = ni_netdev_get_team(mdev))) {
		ni_team_link_watch_t *lw;
		unsigned int i;

		for (i = 0; i < team->link_watch.count; i++) {
			lw = team->link_watch.data[i];
			if (lw->type == NI_TEAM_LINK_WATCH_NSNA_PING)
				l2v6 = TRUE;
		}
	}
	type = ni_linktype_type_to_name(mdev->link.type);
	if (!(pcfg = ni_suse_ifcfg_add_l2_port(ifcfgs,
			ifcfg, mdev->name, type, port, l2v6))) {
		ni_error("ifcfg-%s: failed to add %s port %s='%s'",
				mdev->name, type, variable, port);
		return FALSE;
	}

	ni_netdev_port_config_destroy(&pcfg->compat->port);
	if (ni_netdev_port_config_init(&pcfg->compat->port, NI_IFTYPE_TEAM)) {
		try_add_team_port_config(pcfg->compat->port.team,
				ifcfg->config, suffix, mdev->name);
	}

	return TRUE;
}

static int
try_team(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	const char *value;
	ni_team_runner_type_t type;
	ni_team_t *team;

	if (!(value = ni_sysconfig_get_value(sc, "TEAM_RUNNER")))
		return 1;

	if (!ni_team_runner_name_to_type(value, &type)) {
		ni_error("ifcfg-%s: unable to parse TEAM_RUNNER=%s", dev->name, value);
		return -1;
	}

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains team variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	/* just drop old if any */
	ni_netdev_set_team(dev, NULL);

	dev->link.type = NI_IFTYPE_TEAM;
	team = ni_netdev_get_team(dev);

	ni_team_runner_init(&team->runner, type);
	switch (team->runner.type) {
	case NI_TEAM_RUNNER_ACTIVE_BACKUP: {
			ni_team_runner_active_backup_t *ab = &team->runner.ab;

			if ((value = ni_sysconfig_get_value(sc, "TEAM_AB_HWADDR_POLICY")) != NULL) {
				if (!ni_team_ab_hwaddr_policy_name_to_type(value, &ab->config.hwaddr_policy)) {
					ni_error("ifcfg-%s: Cannot parse TEAM_AB_HWADDR_POLICY='%s'",
						dev->name, value);
					return -1;
				}
			}
		}
		break;

	case NI_TEAM_RUNNER_LOAD_BALANCE: {
			ni_team_runner_load_balance_t *lb = &team->runner.lb;

			lb->config.tx_hash = NI_TEAM_TX_HASH_NONE;
			if ((value = ni_sysconfig_get_value(sc, "TEAM_LB_TX_HASH")) != NULL) {
				ni_string_array_t flags = NI_STRING_ARRAY_INIT;
				unsigned int i;

				ni_string_split(&flags, value, " \t,", 0);
				for (i = 0; i < flags.count; i++) {
					ni_team_tx_hash_bit_t bit;

					if (!ni_team_tx_hash_name_to_bit(flags.data[i], &bit)) {
						ni_error("ifcfg-%s: Cannot parse TEAM_LB_TX_HASH='%s'",
							dev->name, value);
						return -1;
					}

					lb->config.tx_hash |= (1 << bit);
				}
				ni_string_array_destroy(&flags);
			}

			if ((value = ni_sysconfig_get_value(sc, "TEAM_LB_TX_BALANCER_NAME")) != NULL) {
				if (!ni_team_tx_balancer_name_to_type(value, &lb->config.tx_balancer.type)) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LB_TX_BALANCER_NAME='%s'",
						dev->name, value);
					return -1;
				}
			}

			lb->config.tx_balancer.interval = 50;
			if ((value = ni_sysconfig_get_value(sc, "TEAM_LB_TX_BALANCER_INTERVAL")) != NULL) {
				if (ni_parse_uint(value, &lb->config.tx_balancer.interval, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LB_TX_BALANCER_INTERVAL='%s'",
						dev->name, value);
					return -1;
				}
			}
		}
		break;

	case NI_TEAM_RUNNER_ROUND_ROBIN:
		break;

	case NI_TEAM_RUNNER_BROADCAST:
		break;

	case NI_TEAM_RUNNER_RANDOM:
		break;

	case NI_TEAM_RUNNER_LACP: {
			ni_team_runner_lacp_t *lacp = &team->runner.lacp;

			if ((value = ni_sysconfig_get_value(sc, "TEAM_LACP_ACTIVE")) != NULL) {
				if (ni_parse_boolean(value, &lacp->config.active)) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LACP_ACTIVE='%s'",
						dev->name, value);
					return -1;
				}
			}

			lacp->config.sys_prio = 255;
			if ((value = ni_sysconfig_get_value(sc, "TEAM_LACP_SYS_PRIO")) != NULL) {
				if (ni_parse_uint(value, &lacp->config.sys_prio, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LACP_SYS_PRIO='%s'",
						dev->name, value);
					return -1;
				}
			}

			if ((value = ni_sysconfig_get_value(sc, "TEAM_LACP_FAST_RATE")) != NULL) {
				if (ni_parse_boolean(value, &lacp->config.fast_rate)) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LACP_FAST_RATE='%s'",
						dev->name, value);
					return -1;
				}
			}

			if ((value = ni_sysconfig_get_value(sc, "TEAM_LACP_MIN_PORTS")) != NULL) {
				if (ni_parse_uint(value, &lacp->config.min_ports, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LACP_MIN_PORTS='%s'",
						dev->name, value);
					return -1;
				}
			}

			if ((value = ni_sysconfig_get_value(sc, "TEAM_LACP_SELECT_POLICY")) != NULL) {
				if (!ni_team_lacp_select_policy_name_to_type(value, &lacp->config.select_policy)) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LACP_SELECT_POLICY='%s'",
						dev->name, value);
					return -1;
				}
			}

			lacp->config.tx_hash = NI_TEAM_TX_HASH_NONE;
			if ((value = ni_sysconfig_get_value(sc, "TEAM_LACP_TX_HASH")) != NULL) {
				ni_string_array_t flags = NI_STRING_ARRAY_INIT;
				unsigned int i;

				ni_string_split(&flags, value, " \t,", 0);
				for (i = 0; i < flags.count; i++) {
					ni_team_tx_hash_bit_t bit;

					if (!ni_team_tx_hash_name_to_bit(flags.data[i], &bit)) {
						ni_error("ifcfg-%s: Cannot parse TEAM_LACP_TX_HASH='%s'",
							dev->name, value);
						return -1;
					}

					lacp->config.tx_hash |= (1 << bit);
				}

				ni_string_array_destroy(&flags);
			}

			if ((value = ni_sysconfig_get_value(sc, "TEAM_LACP_TX_BALANCER")) != NULL) {
				if (!ni_team_tx_balancer_name_to_type(value, &lacp->config.tx_balancer.type)) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LACP_TX_BALANCER='%s'",
						dev->name, value);
					return -1;
				}
			}

			lacp->config.tx_balancer.interval = 50;
			if ((value = ni_sysconfig_get_value(sc, "TEAM_LACP_TX_BALANCER_INTERVAL")) != NULL) {
				if (ni_parse_uint(value, &lacp->config.tx_balancer.interval, 0) < 0) {
					ni_error("ifcfg-%s: Cannot parse TEAM_LACP_TX_BALANCER_INTERVAL='%s'",
						dev->name, value);
					return -1;
				}
			}
		}
		break;

	default:
		return -1;
	}

	if ((value = ni_sysconfig_get_value(sc, "LLADDR")) != NULL) {
		if (ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, value) < 0) {
			ni_error("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "TEAM_DEBUG_LEVEL")) != NULL) {
		if (ni_parse_uint(value, &team->debug_level, 0) < 0) {
			ni_error("ifcfg-%s: Cannot parse TEAM_DEBUG_LEVEL='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "TEAM_NOTIFY_PEERS_COUNT")) != NULL) {
		if (ni_parse_uint(value, &team->notify_peers.count, 0) < 0) {
			ni_error("ifcfg-%s: Cannot parse TEAM_NOTIFY_PEERS_COUNT='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "TEAM_NOTIFY_PEERS_INTERVAL")) != NULL) {
		if (ni_parse_uint(value, &team->notify_peers.interval, 0) < 0) {
			ni_error("ifcfg-%s: Cannot parse TEAM_NOTIFY_PEERS_INTERVAL='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "TEAM_MCAST_REJOIN_COUNT")) != NULL) {
		if (ni_parse_uint(value, &team->mcast_rejoin.count, 0) < 0) {
			ni_error("ifcfg-%s: Cannot parse TEAM_MCAST_REJOIN_COUNT='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "TEAM_MCAST_REJOIN_INTERVAL")) != NULL) {
		if (ni_parse_uint(value, &team->mcast_rejoin.interval, 0) < 0) {
			ni_error("ifcfg-%s: Cannot parse TEAM_MCAST_REJOIN_INTERVAL='%s'",
				dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "TEAM_LINK_WATCH_POLICY"))) {
		if (!ni_team_link_watch_policy_name_to_type(value, &team->link_watch_policy)) {
			ni_error("ifcfg-%s: Cannot parse TEAM_LINK_WATCH_POLICY='%s'",
					dev->name, value);
			return -1;
		}
	}

	if (__process_indexed_variables(sc, dev, "TEAM_LW_NAME",
					try_add_team_link_watch) < 0)
		return -1;

#if 0
	if ((err = ni_team_validate(ni_netdev_get_team(dev))) != NULL) {
		ni_error("ifcfg-%s: team validation: %s",
			dev->name, err);
		return -1;
	}
#endif

	if (!ni_suse_ifcfg_process_indexed(ifcfgs, ifcfg, "TEAM_PORT_DEVICE",
			try_add_team_port)) {
		ni_error("ifcfg-%s: invalid bonding without TEAM_PORT_DEVICEs",
				dev->name);
		return -1;
	}

	return 0;
}

static ni_bool_t
try_add_ovs_bridge_port(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg,
		const char *port, const char *variable, const char *suffix)
{
	static const char *ovs_system = NULL;
	ni_suse_ifcfg_t *pcfg;
	ni_netdev_t *bdev;
	const char *type;

	if (!ovs_system)
		ovs_system = ni_linktype_type_to_name(NI_IFTYPE_OVS_SYSTEM);

	bdev = ifcfg->compat->dev;
	if (ni_string_eq(ovs_system, port)) {
		ni_error("ifcfg-%s: reserved ovs datapath in %s='%s'",
				bdev->name, variable, port);
		return FALSE;
	}

	type = ni_linktype_type_to_name(bdev->link.type);
	if (!(pcfg = ni_suse_ifcfg_add_l2_port(ifcfgs,
			ifcfg, bdev->name, type, port, FALSE))) {
		ni_error("ifcfg-%s: failed to add %s port %s='%s'",
				bdev->name, type, variable, port);
		return FALSE;
	}

	ni_netdev_port_config_destroy(&pcfg->compat->port);
	ni_netdev_port_config_init(&pcfg->compat->port, bdev->link.type);
	/* no ovs bridge port specific config variables (any more) */

	return TRUE;
}

static int
try_ovs_bridge(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_ovs_bridge_t *ovsbr;
	ni_bool_t enabled;
	const char *parent;
	const char *vlan;
	unsigned int tag;

	if (!ni_sysconfig_get_boolean(sc, "OVS_BRIDGE", &enabled) || !enabled)
		return 1;

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains ovs bridge variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_OVS_BRIDGE;
	if (!(ovsbr = ni_netdev_get_ovs_bridge(dev))) {
		ni_error("ifcfg-%s: unable to allocate ovs bridge structure",
				dev->name);
		return -1;
	}

	if ((parent = ni_sysconfig_get_value(sc, "OVS_BRIDGE_VLAN_PARENT"))) {
		if (!ni_netdev_name_is_valid(parent)) {
			ni_error("ifcfg-%s: Suspect device in OVS_BRIDGE_VLAN_PARENT='%s'",
					dev->name,
					ni_print_suspect(parent, ni_string_len(parent)));
			return -1;
		}
		if (!ni_suse_ifcfg_find_by_ifname(ifcfgs, parent)) {
			ni_error("ifcfg-%s: Unable to find OVS vlan bridge parent config '%s'",
					dev->name, parent);
			return -1;
		}

		if (!(vlan = ni_sysconfig_get_value(sc, "OVS_BRIDGE_VLAN_TAG"))) {
			ni_error("ifcfg-%s: OVS_BRIDGE_VLAN_TAG=... missed", dev->name);
			return -1;
		}
		if (ni_parse_uint(vlan, &tag, 10) < 0) {
			ni_error("ifcfg-%s: Cannot parse OVS_BRIDGE_VLAN_TAG=\"%s\"",
					dev->name, vlan);
			return -1;
		}
		if (tag > __NI_VLAN_TAG_MAX) {
			ni_error("ifcfg-%s: OVS_BRIDGE_VLAN_TAG='%u' not in range 1..%u",
					dev->name, ovsbr->config.vlan.tag, __NI_VLAN_TAG_MAX);
			return -1;
		}

		ni_netdev_ref_set_ifname(&ovsbr->config.vlan.parent, parent);
		ovsbr->config.vlan.tag = tag;
	}

	ni_suse_ifcfg_process_indexed(ifcfgs, ifcfg, "OVS_BRIDGE_PORT_DEVICE",
			try_add_ovs_bridge_port);

	return 0;
}

static int
try_ovs_system(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	ni_netdev_t *dev = ifcfg->compat->dev;
	static const char *ovs_system = NULL;

	/* Consider ovs-system as a fixed/reserved datapath name for openvswitch */
	if (ovs_system == NULL)
		ovs_system = ni_linktype_type_to_name(NI_IFTYPE_OVS_SYSTEM);

	if (!ni_string_eq(dev->name, ovs_system))
		return 1;

	switch (dev->link.type) {
	case NI_IFTYPE_UNKNOWN:
		dev->link.type = NI_IFTYPE_OVS_SYSTEM;
		/*
		 * This datapath device does not need any setup (not even link up),
		 * but as it is actively used as master device for all ovs ports,
		 * we have to consider it in order to resolve dependencies...
		 */
		ni_suse_ifcfg_set_l2_only(ifcfg, FALSE);
		return 0;
	case NI_IFTYPE_OVS_SYSTEM:
		return 0;
	default:
		ni_error("ifcfg-%s: %s config is using reserved %s device name",
			dev->name, ni_linktype_type_to_name(dev->link.type), ovs_system);
		return -1;
	}
	return 0;
}


/*
 * Bridge devices are recognized by BRIDGE=yes
 */
static ni_bool_t
try_add_bridge_port_config(ni_bridge_port_config_t *pconf, const char *file,
		const char *port, const char *prio, const char *cost)
{
	unsigned int tmp;
	const char *err;

	if (ni_string_empty(prio) || ni_string_eq(prio, "-")) {
		pconf->priority = NI_BRIDGE_VALUE_NOT_SET;
	} else if (ni_parse_uint(prio, &tmp, 0) < 0) {
		ni_warn("ifcfg-%s: unable to parse priority '%s' for port '%s'",
				file, prio, port);
	} else if ((err = ni_bridge_port_priority_validate(tmp))) {
		ni_warn("ifcfg-%s: %s '%s' for port '%s'",
				file, err, prio, port);
	} else {
		pconf->priority = tmp;
	}

	if (ni_string_empty(cost) || ni_string_eq(cost, "-")) {
		pconf->path_cost = NI_BRIDGE_VALUE_NOT_SET;
	} else if (ni_parse_uint(cost, &tmp, 0) < 0) {
		ni_warn("ifcfg-%s: unable to parse path-cost '%s' for port '%s'",
				file, cost, port);
	} else if ((err = ni_bridge_port_path_cost_validate(tmp))) {
		ni_warn("ifcfg-%s: %s '%s' for port '%s'",
				file, err, cost, port);
	} else {
		pconf->path_cost = tmp;
	}

	return TRUE;
}

static ni_bool_t
try_add_bridge_port(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg,
		const char *port, const char *prio, const char *cost)
{
	ni_suse_ifcfg_t *pcfg;
	ni_netdev_t *mdev;
	const char *type;

	mdev = ifcfg->compat->dev;
	type = ni_linktype_type_to_name(mdev->link.type);
	if (!(pcfg = ni_suse_ifcfg_add_l2_port(ifcfgs,
			ifcfg, mdev->name, type, port, FALSE))) {
		ni_error("ifcfg-%s: failed to add %s port %s",
				mdev->name, type, port);
		return FALSE;
	}

	ni_netdev_port_config_destroy(&pcfg->compat->port);
	if (ni_netdev_port_config_init(&pcfg->compat->port, mdev->link.type)) {
		try_add_bridge_port_config(pcfg->compat->port.bridge,
				mdev->name, port, prio, cost);
	}

	return TRUE;
}

static ni_bool_t
try_add_bridge_ports(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	ni_string_array_t ports = NI_STRING_ARRAY_INIT;
	ni_string_array_t prios = NI_STRING_ARRAY_INIT;
	ni_string_array_t costs = NI_STRING_ARRAY_INIT;
	ni_bool_t ret = TRUE;
	unsigned int i;

	ni_string_split(&ports, ni_sysconfig_get_value(ifcfg->config,
				"BRIDGE_PORTS"), " \t", 0);
	ni_string_split(&prios, ni_sysconfig_get_value(ifcfg->config,
				"BRIDGE_PORTPRIORITIES"), " \t", 0);
	ni_string_split(&costs, ni_sysconfig_get_value(ifcfg->config,
				"BRIDGE_PATHCOSTS"), " \t", 0);

	for (i = 0; i < ports.count; ++i) {
		if (!try_add_bridge_port(ifcfgs, ifcfg,
				ni_string_array_at(&ports, i),
				ni_string_array_at(&prios, i),
				ni_string_array_at(&costs, i)))
			ret = FALSE;
	}

	ni_string_array_destroy(&ports);
	ni_string_array_destroy(&prios);
	ni_string_array_destroy(&costs);
	return ret;
}

static int
try_bridge(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
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

	if ((value = ni_bridge_validate(bridge)) != NULL) {
		ni_error("ifcfg-%s: bridge validation: %s", dev->name, value);
		return -1;
	}

	if ((value = ni_sysconfig_get_value(sc, "LLADDR")) != NULL) {
		if (ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, value) < 0) {
			ni_error("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
				dev->name, value);
			return -1;
		}
	}

	try_add_bridge_ports(ifcfgs, ifcfg);

	return 0;
}

/*
 * VLAN interfaces are recognized by their name (vlan<N>)
 */
static int
try_vlan(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_vlan_t *vlan;
	const char *etherdev = NULL;
	const char *vlanprot = NULL;
	const char *vlantag = NULL;
	const char *lladdr = NULL;
	unsigned int tag = 0;
	size_t len;

	etherdev = ni_sysconfig_get_value(sc, "ETHERDEVICE");
	if (ni_string_empty(etherdev))
		return 1;

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains vlan variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_VLAN;
	if (!(vlan = ni_netdev_get_vlan(dev))) {
		ni_error("ifcfg-%s: unable to allocate ethernet vlan structure",
				dev->name);
		return -1;
	}

	if ((vlantag = ni_sysconfig_get_value(sc, "VLAN_ID")) != NULL) {
		if (ni_parse_uint(vlantag, &tag, 10) < 0) {
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
			while(len-- && isdigit((unsigned char)vlantag[-1]))
				vlantag--;
		}
		if (ni_parse_uint(vlantag, &tag, 10) < 0) {
			ni_error("ifcfg-%s: Cannot parse vlan-tag from interface name",
				dev->name);
			return -1;
		}
	}
	if (tag > __NI_VLAN_TAG_MAX) {
		ni_error("ifcfg-%s: VLAN tag %u is out of numerical range 1..%u",
			dev->name, tag, __NI_VLAN_TAG_MAX);
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

	if (!ni_suse_ifcfg_add_lower(ifcfgs, ifcfg, etherdev, "vlan ETHERDEVICE"))
		return -1;

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

static int
try_vxlan(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_vxlan_t *vxlan;
	ni_bool_t enabled;
	unsigned int val;
	const char *str;

	if (!ni_sysconfig_get_boolean(sc, "VXLAN", &enabled) || !enabled)
		return 1;

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains vlan variables",
				dev->name, ni_linktype_type_to_name(dev->link.type));
		return -1;
	}

	dev->link.type = NI_IFTYPE_VXLAN;
	vxlan = ni_netdev_get_vxlan(dev);

	/* netdev properties/relations */
	if ((str = ni_sysconfig_get_value(sc, "LLADDR"))) {
		if (ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, str) < 0) {
			ni_error("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_DEVICE"))) {
		if (!ni_suse_ifcfg_add_lower(ifcfgs, ifcfg, str, "VXLAN_DEVICE"))
			return -1;

		ni_string_dup(&dev->link.lowerdev.name, str);
	}

	/* vxlan specific properties */
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_ID"))) {
		if (ni_parse_uint(str, &vxlan->id, 10) < 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_ID=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_LOCAL_IP"))) {
		if (ni_sockaddr_parse(&vxlan->local_ip, str, AF_UNSPEC) < 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_LOCAL_IP=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_REMOTE_IP"))) {
		if (ni_sockaddr_parse(&vxlan->remote_ip, str, AF_UNSPEC) < 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_REMOTE_IP=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_SRC_PORT_LOW"))) {
		if (ni_parse_uint(str, &val, 10) < 0 || val > 0xffffU) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_SRC_PORT_LOW=\"%s\"",
					dev->name, str);
			return -1;
		}
		vxlan->src_port.low = val;
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_SRC_PORT_HIGH"))) {
		if (ni_parse_uint(str, &val, 10) < 0 || val > 0xffffU) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_SRC_PORT_HIGH=\"%s\"",
					dev->name, str);
			return -1;
		}
		vxlan->src_port.high = val;
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_DST_PORT"))) {
		if (ni_parse_uint(str, &val, 10) < 0 || val > 0xffffU) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_DST_PORT=\"%s\"",
					dev->name, str);
			return -1;
		}
		vxlan->dst_port = val;
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_TTL"))) {
		if (ni_parse_uint(str, &val, 10) < 0 || val > 0xffU) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_TTL=\"%s\"",
					dev->name, str);
			return -1;
		}
		vxlan->ttl = val;
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_TOS"))) {
		if (ni_parse_uint(str, &val, 10) < 0 || val > 0xffU) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_TOS=\"%s\"",
					dev->name, str);
			return -1;
		}
		vxlan->tos = val;
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_AGEING"))) {
		if (ni_parse_uint(str, &vxlan->ageing, 10) < 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_AGEING=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_MAX_ADDRS"))) {
		if (ni_parse_uint(str, &vxlan->maxaddr, 10) < 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_MAX_ADDRS=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_LEARNING"))) {
		if (ni_parse_boolean(str, &vxlan->learning) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_LEARNING=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_PROXY"))) {
		if (ni_parse_boolean(str, &vxlan->proxy) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_PROXY=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_RSC"))) {
		if (ni_parse_boolean(str, &vxlan->rsc) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_RSC=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_L2MISS"))) {
		if (ni_parse_boolean(str, &vxlan->l2miss) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_L2MISS=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_L3MISS"))) {
		if (ni_parse_boolean(str, &vxlan->l3miss) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_L3MISS=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_UDP_CSUM"))) {
		if (ni_parse_boolean(str, &vxlan->udp_csum) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_UDP_CSUM=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_UDP6_ZERO_CSUM_RX"))) {
		if (ni_parse_boolean(str, &vxlan->udp6_zero_csum_rx) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_UDP6_ZERO_CSUM_RX=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_UDP6_ZERO_CSUM_TX"))) {
		if (ni_parse_boolean(str, &vxlan->udp6_zero_csum_tx) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_UDP6_ZERO_CSUM_TX=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_REM_CSUM_RX"))) {
		if (ni_parse_boolean(str, &vxlan->rem_csum_rx) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_REM_CSUM_RX=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_REM_CSUM_TX"))) {
		if (ni_parse_boolean(str, &vxlan->rem_csum_tx) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_REM_CSUM_TX=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_REM_CSUM_PARTIAL"))) {
		if (ni_parse_boolean(str, &vxlan->rem_csum_partial) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_REM_CSUM_PARTIAL=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_COLLECT_METADATA"))) {
		if (ni_parse_boolean(str, &vxlan->collect_metadata) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_COLLECT_METADATA=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_GBP"))) {
		if (ni_parse_boolean(str, &vxlan->gbp) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_GBP=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
#if 0
	if ((str = ni_sysconfig_get_value(sc, "VXLAN_GPE"))) {
		if (ni_parse_boolean(str, &vxlan->gpe) != 0) {
			ni_error("ifcfg-%s: Cannot parse VXLAN_GBP=\"%s\"",
					dev->name, str);
			return -1;
		}
	}
#endif

	if ((str = ni_vxlan_validate(vxlan, &dev->link.lowerdev))) {
		ni_error("ifcfg-%s: %s", dev->name, str);
		return -1;
	}
	return 0;
}

/*
 * MACVLAN/MACVTAP is recognized by [MACVLAN|MACVTAP]_DEVICE entry which
 * specifies the lower device to use. The lower device, obviously, has to
 * differ from the macvlan/tap device being created.
 */
static int
try_macvlan(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
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

	if (!ni_suse_ifcfg_add_lower(ifcfgs, ifcfg, macvlan_dev, syscfg_dev_key))
		return -1;

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


static ni_bool_t
maybe_dummy(const char *ifname)
{
	unsigned long result = 0;

	if (!ni_string_startswith(ifname, "dummy"))
		return FALSE;
	return ni_parse_ulong(ifname + 5, &result, 10) == 0;
}

/*
 * A Dummy device is recognized by INTERFACETYPE and/or by the interface name
 * itself.
 */
static int
try_dummy(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_bool_t enabled;
	const char *iftype = NULL;
	const char *lladdr = NULL;
	const char *bootproto = NULL;

	if (!ni_sysconfig_get(sc, "DUMMY")) {
		/* fallback to deprecated behavior - consider INTERFACETYPE or ifname */
		iftype = ni_sysconfig_get_value(sc, "INTERFACETYPE");
		if (iftype && !ni_string_eq_nocase(iftype, "dummy"))
			return 1;

		if (dev->link.type != NI_IFTYPE_UNKNOWN || (!iftype && !maybe_dummy(dev->name)))
			return 1;
	} else {
		if (!ni_sysconfig_get_boolean(sc, "DUMMY", &enabled) || !enabled)
			return 1;
	}

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

static ni_bool_t
ni_wireless_is_psk_config(const ni_sysconfig_t *sc, ni_wireless_network_t *net,
					const char *suffix)
{
	const ni_var_t *var;
	const char **p, *psk_auth_modes[] = { "psk", "wpa-psk", NULL};

	if ((var = __find_indexed_variable(sc, "WIRELESS_AUTH_MODE", suffix))) {
		for (p = psk_auth_modes; *p; p++) {
			if ( ni_string_eq(var->value, *p))
				return TRUE;
		}
	}

	return !!(net->keymgmt_proto & NI_WIRELESS_KEY_MGMT_DEFAULT_PSK);
}

static ni_bool_t
ni_wireless_is_eap_config(const ni_sysconfig_t *sc, ni_wireless_network_t *net,
					const char *suffix)
{
	const ni_var_t *var;
	const char **p, *psk_auth_modes[] = { "eap", "wpa-eap", NULL};

	if ((var = __find_indexed_variable(sc, "WIRELESS_AUTH_MODE", suffix))) {
		for (p = psk_auth_modes; *p; p++)
			if ( ni_string_eq(var->value, *p))
				return TRUE;
	}

	return !!(net->keymgmt_proto & NI_WIRELESS_KEY_MGMT_DEFAULT_EAP);
}

static int
ni_wireless_parse_auth_mode(const ni_sysconfig_t *sc, ni_wireless_network_t *net,
				const char *suffix, const char *ifname,
				ni_wireless_ap_scan_mode_t ap_scan)
{
	ni_string_array_t invalid = NI_STRING_ARRAY_INIT;
	const ni_var_t *var;
	int err;

	/*
	 * WIRELESS_AUTH_MODE is a combination of the key management protocols
	 * and the allowed authentication algorithms lists.
	 *
	 * While the wpa eap and psk protocols require and open auth_alg, the
	 * deprecated wep security algorithms can be used with the open system
	 * or the (wep only) shared key authentication methods.
	 *
	 * The following maps contain the valid ifcfg settings incl. of the
	 * (sle11) ifup-wireless/yast2 aliases for compatibility.
	 */
	static const ni_intmap_t	auth_algo_map[] = {
		{ "psk",		NI_WIRELESS_AUTH_OPEN		},
		{ "wpa-psk",		NI_WIRELESS_AUTH_OPEN		},
		{ "eap",		NI_WIRELESS_AUTH_OPEN		},
		{ "wpa-eap",		NI_WIRELESS_AUTH_OPEN		},
		{ "open",		NI_WIRELESS_AUTH_OPEN		},
		{ "opensystem",		NI_WIRELESS_AUTH_OPEN		},
		{ "no-encryption",	NI_WIRELESS_AUTH_OPEN		},
		{ "sharedkey",		NI_WIRELESS_AUTH_SHARED		},
		{ "shared",		NI_WIRELESS_AUTH_SHARED		},
		{ "restricted",		NI_WIRELESS_AUTH_SHARED		},

		{ NULL }
	};
	static const ni_intmap_t	keymgmt_map[] = {
		{ "open",		NI_WIRELESS_KEY_MGMT_NONE	},
		{ "opensystem",		NI_WIRELESS_KEY_MGMT_NONE	},
		{ "no-encryption",	NI_WIRELESS_KEY_MGMT_NONE	},
		{ "sharedkey",		NI_WIRELESS_KEY_MGMT_NONE	},
		{ "shared",		NI_WIRELESS_KEY_MGMT_NONE	},
		{ "restricted",		NI_WIRELESS_KEY_MGMT_NONE	},

		{ NULL }
	};

	if (!(var = __find_indexed_variable(sc, "WIRELESS_AUTH_MODE", suffix)))
		return 1;

	err = ni_parse_bitmap_string(&net->auth_algo, auth_algo_map, var->value, NULL, &invalid);
	if (err) {
		char *unknown = NULL;

		ni_string_join(&unknown, &invalid, " ");
		if (net->auth_algo) {
			ni_warn("ifcfg-%s: Invalid options in WIRELESS_AUTH_MODE%s='%s' variable'",
					ifname, suffix, unknown ? unknown : var->value);
			err = 0;
		} else {
			ni_error("ifcfg-%s: No valid options in WIRELESS_AUTH_MODE%s='%s' variable'",
					ifname, suffix, var->value);
			err = -1;
		}
		ni_string_free(&unknown);
		ni_string_array_destroy(&invalid);
		if (err)
			return err;
	}
	ni_string_array_destroy(&invalid);

	/* both maps contain all settings, thus above error handling is enough */
	ni_parse_bitmap_string(&net->keymgmt_proto, keymgmt_map, var->value, NULL, NULL);

	return 0;
}

static ni_bool_t
ni_wireless_parse_key_mgmt(const ni_sysconfig_t *sc, ni_wireless_network_t *net, const char *suffix, const char *dev_name, ni_wireless_ap_scan_mode_t ap_scan)
{
	ni_string_array_t invalid = NI_STRING_ARRAY_INIT;
	ni_var_t *var;
	char *unknown = NULL;
	int err;

	if((var = __find_indexed_variable(sc,"WIRELESS_KEY_MGMT", suffix))) {

		err = ni_parse_bitmap_string(&net->keymgmt_proto,
					ni_wireless_key_management_map(), var->value, NULL, &invalid);
		if (err){
			ni_string_join(&unknown, &invalid, ", ");
			ni_error("ifcfg-%s: Invalid value in WIRELESS_KEY_MGMT%s='%s' variable",
					dev_name, suffix, unknown ? unknown : "");
			ni_string_free(&unknown);
			ni_string_array_destroy(&invalid);
			return FALSE;
		}
		ni_string_array_destroy(&invalid);
	}
	return TRUE;
}

static ni_bool_t
try_add_wireless_net(const ni_sysconfig_t *sc, ni_netdev_t *dev, const char *suffix)
{
	ni_wireless_network_t *net = NULL;
	ni_wireless_t *wlan = ni_netdev_get_wireless(dev);
	ni_var_t *var = NULL;
	ni_wireless_ssid_t essid;

	/* Just skip networks with empty ESSID */
	if (!(var = __find_indexed_variable(sc, "WIRELESS_ESSID", suffix))) {
		ni_error("ifcfg-%s: empty WIRELESS_ESSID%s value",
			dev->name, suffix);
		goto failure;
	}

	/* Check whether ESSID already exists */
	if (!ni_wireless_ssid_parse(&essid, var->value)) {
		ni_error("ifcfg-%s: invalid WIRELESS_ESSID%s value",
				dev->name, suffix);
		goto failure;
	}

	if (ni_wireless_config_has_essid(wlan->conf, &essid)) {
		ni_error("ifcfg-%s: double configuration of the same ESSID=%s",
			dev->name, var->value);
		goto failure;
	}

	/* Allocate and mlock new network object */
	if (!(net = ni_wireless_network_new())) {
		ni_error("ifcfg-%s: unable to create network object", dev->name);
		goto failure;
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

	if (net->mode == NI_WIRELESS_MODE_MANAGED &&
	    (var = __find_indexed_variable(sc, "WIRELESS_FREQUENCY_LIST", suffix))) {

		ni_string_array_t errors = NI_STRING_ARRAY_INIT;
		ni_stringbuf_t tmp = NI_STRINGBUF_INIT_DYNAMIC;

		if (!ni_wireless_frequency_list_parse_string(var->value, &net->frequency_list, &errors)) {
			ni_warn("ifcfg-%s: invalid WIRELESS_FREQUENCY_LIST%s: '%s'",
					dev->name, suffix,
					ni_stringbuf_join(&tmp, &errors, " "));

			ni_string_array_destroy(&errors);
			ni_stringbuf_destroy(&tmp);
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

	if (ni_wireless_parse_auth_mode(sc, net, suffix, dev->name, wlan->conf->ap_scan) < 0)
		goto failure;

	if (!ni_wireless_parse_key_mgmt(sc, net, suffix, dev->name, wlan->conf->ap_scan))
		goto failure;

	if (!__ni_wireless_parse_psk_auth(sc, net, suffix, dev->name, wlan->conf->ap_scan))
		goto failure;

	if (!__ni_wireless_parse_pmf(sc, net, suffix, dev->name, wlan->conf->ap_scan))
		goto failure;

	if (!__ni_wireless_parse_eap_auth(sc, net, suffix, dev->name, wlan->conf->ap_scan))
		goto failure;

	if (net->keymgmt_proto & NI_BIT(NI_WIRELESS_KEY_MGMT_NONE)) {
		if (!ni_wireless_parse_wep_auth(sc, net, suffix, dev->name))
			goto failure;
		else if (!(net->auth_algo & NI_BIT(NI_WIRELESS_AUTH_SHARED)))
			net->auth_algo = NI_BIT(NI_WIRELESS_AUTH_OPEN);
	}

	if (!ni_wireless_network_array_append(&wlan->conf->networks, net))
		goto failure;

	return TRUE;

failure:
	if (net)
		ni_wireless_network_drop(&net);
	return FALSE;
}

/*
 * Handle Wireless devices
 */
static ni_bool_t
try_add_wireless(const ni_sysconfig_t *sc, ni_netdev_t *dev)
{
	ni_wireless_t *wlan;
	const char *tmp = NULL;
	ni_bool_t check_country = FALSE;

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

	if ((wlan = ni_netdev_get_wireless(dev)) == NULL) {
		ni_error("%s: no wireless info for device", dev->name);
		return FALSE;
	}

	if (!wlan->conf && !(wlan->conf = ni_wireless_config_new()))
		return FALSE;

	/* Default is ap_scan = 1 */
	if ((tmp = ni_sysconfig_get_value(sc, "WIRELESS_AP_SCANMODE"))) {
		if ((ni_parse_uint(tmp, &wlan->conf->ap_scan, 10) < 0) ||
			(wlan->conf->ap_scan > NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH)) {
			ni_error("ifcfg-%s: wrong WIRELESS_AP_SCANMODE value",
				dev->name);
			goto failure;
		}
	}

	/* Default is wpa_drv = "nl80211" */
	if ((tmp = ni_sysconfig_get_value(sc, "WIRELESS_WPA_DRIVER"))) {
		if (!ni_wpa_driver_string_validate(tmp)) {
			ni_error("ifcfg-%s: wrong WIRELESS_WPA_DRIVER value",
				dev->name);
			goto failure;
		}
		else if (ni_string_contains(tmp, "80211")) {
			check_country = TRUE;
		}

		ni_string_dup(&wlan->conf->driver, tmp);
	}
	else {
		check_country = TRUE;
	}

	/* Regulatory domain is supported by nl80211 wpa driver */
	if (check_country) {
		if ((tmp = ni_sysconfig_get_value(__ni_suse_config_defaults, "WIRELESS_REGULATORY_DOMAIN"))) {
			if ((2 == ni_string_len(tmp)) &&
				(isalpha((unsigned char) tmp[0])) &&
				(isalpha((unsigned char) tmp[1]))) {
					ni_string_dup(&wlan->conf->country, tmp);
			}
			else {
				ni_error("ifcfg-%s: wrong WIRELESS_REGULATORY_DOMAIN value",
					dev->name);
				goto failure;
			}
		}
	}

	if (__process_indexed_variables(sc, dev, "WIRELESS_ESSID", try_add_wireless_net) >= 0)
		return TRUE;

failure:
	ni_netdev_set_wireless(dev, NULL);
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
ni_wireless_parse_wep_auth(const ni_sysconfig_t *sc, ni_wireless_network_t *net, const char *suffix, const char *dev_name)
{
	ni_var_t *var;
	const char *key_str[NI_WIRELESS_WEP_KEY_COUNT] = {
		"WIRELESS_KEY_0",
		"WIRELESS_KEY_1",
		"WIRELESS_KEY_2",
		"WIRELESS_KEY_3"
	};
	unsigned int keys = 0;
	int i;

	ni_assert(sc && net && suffix);

	if (!(net->keymgmt_proto & NI_BIT(NI_WIRELESS_KEY_MGMT_NONE)))
		return FALSE;

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

	/* Default wep_key is unset */
	for (i = 0; i < NI_WIRELESS_WEP_KEY_COUNT; i++) {
		ni_assert(!net->wep_keys[i]);

		if ((var = __find_indexed_variable(sc, key_str[i], suffix))) {
			if(!ni_wireless_wep_key_parse(NULL, var->value)) {
				ni_error("ifcfg-%s: wrong WIRELESS_KEY_%d%s format",
					dev_name, i, suffix);
				goto wep_failure;
			}
			if (ni_string_dup(&net->wep_keys[i], var->value))
				keys++;
		}
	}

	if (!keys && (net->auth_algo & NI_BIT(NI_WIRELESS_AUTH_SHARED))) {
		ni_error("ifcfg-%s: shared key wep authentication requires a key",
			dev_name);
		goto wep_failure;
	}

	return TRUE;

wep_failure:
	return FALSE;
}

static int
ni_wireless_parse_auth_proto(const ni_sysconfig_t *sc, unsigned int *auth_proto, const char *suffix, const char *dev_name)
{
	ni_var_t *var;

	ni_assert(sc && auth_proto && suffix);

	if((var = __find_indexed_variable(sc,"WIRELESS_WPA_PROTO", suffix))) {
		if (ni_parse_bitmap_string(auth_proto, ni_wireless_auth_proto_map(),
					var->value, " \t", NULL)) {
			ni_error("ifcfg-%s: wrong WIRELESS_WPA_PROTO%s value",
				dev_name, suffix);
			return -1;
		}

		return 1; /* Present */
	}

	return 0;
}

static int
ni_wireless_parse_pairwise_cipher(const ni_sysconfig_t *sc, unsigned int *cipher, const char *variable, const char *suffix, const char *dev_name)
{
	ni_var_t *var;

	ni_assert(sc && cipher && variable && suffix);

	if((var = __find_indexed_variable(sc,variable, suffix))) {
		ni_parse_bitmap_string(cipher, ni_wireless_pairwise_map(), var->value, ",", NULL);
		return 1; /* Present */
	}

	return 0;
}

static int
ni_wireless_parse_group_cipher(const ni_sysconfig_t *sc, unsigned int *cipher, const char *variable, const char *suffix, const char *dev_name)
{
	ni_var_t *var;

	ni_assert(sc && cipher && variable && suffix);

	if((var = __find_indexed_variable(sc,variable, suffix))) {
		ni_parse_bitmap_string(cipher, ni_wireless_group_map(), var->value, ",", NULL);
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

	if((var = __find_indexed_variable(sc,"WIRELESS_WPA_PSK", suffix))) {
		if (!__ni_wireless_wpa_psk_key_validate(var->value)) {
			ni_error("ifcfg-%s: wrong WIRELESS_WPA_PSK%s value",
				dev_name, suffix);
			goto psk_failure;
		}

		ni_string_dup(&net->wpa_psk.passphrase, var->value);
	}
	else {
		if (ni_wireless_is_psk_config(sc, net, suffix)) {
			ni_error("ifcfg-%s: no WIRELESS_WPA_PSK%s value specified",
				dev_name, suffix);
			goto psk_failure;
		} else
			return TRUE;
	}

	/* wickedd: Default are both WPA and WPA2 */
	if (ni_wireless_parse_auth_proto(sc, &net->auth_proto, suffix, dev_name) < 0)
		goto psk_failure;

	/* wickedd: Default are both TKIP and CCMP */
	if (ni_wireless_parse_pairwise_cipher(sc, &net->pairwise_cipher, pairwise, suffix, dev_name) < 0)
		goto psk_failure;

	/* wickedd: Default are both TKIP and CCMP */
	if (ni_wireless_parse_group_cipher(sc, &net->group_cipher, group, suffix, dev_name) < 0)
		goto psk_failure;

	if (NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH == ap_scan) {
		if (!(net->auth_proto & NI_BIT(NI_WIRELESS_AUTH_PROTO_RSN)))
			net->auth_proto = NI_BIT(NI_WIRELESS_AUTH_PROTO_WPA);

		if (!(net->pairwise_cipher & NI_BIT(NI_WIRELESS_CIPHER_CCMP)))
			net->pairwise_cipher = NI_BIT(NI_WIRELESS_CIPHER_TKIP);

		if (!(net->group_cipher & NI_BIT(NI_WIRELESS_CIPHER_CCMP)))
			net->group_cipher = NI_BIT(NI_WIRELESS_CIPHER_TKIP);
	}

	return TRUE;

psk_failure:
	return FALSE;
}

static ni_bool_t
__ni_wireless_parse_pmf(const ni_sysconfig_t *sc, ni_wireless_network_t *net, const char *suffix, const char *dev_name, ni_wireless_ap_scan_mode_t ap_scan)
{
	ni_var_t *var;
	if((var = __find_indexed_variable(sc,"WIRELESS_PMF", suffix))) {
		if (!ni_wireless_name_to_pmf(var->value, &net->pmf)){
			ni_error("ifcfg-%s: invalid WIRELESS_PMF%s value specified",
				dev_name, suffix);
			return FALSE;
		}
	}
	return TRUE;
}

static const char *
__ni_wireless_validate_cert_path(const ni_sysconfig_t *sc, const char *path)
{
	const char *ret = NULL;

	if (!path || !sc)
		return NULL;

	if (path[0] == '/')
		ret = path;
	else
		ret = ni_sibling_path_printf(sc->pathname, path);

	if (!ni_file_exists(ret))
		return NULL;

	return ret;
}

static ni_bool_t
__ni_wireless_parse_eap_auth(const ni_sysconfig_t *sc, ni_wireless_network_t *net, const char *suffix, const char *dev_name, ni_wireless_ap_scan_mode_t ap_scan)
{
	ni_var_t *var;
	const char *pairwise = "WIRELESS_CIPHER_PAIRWISE";
	const char *group = "WIRELESS_CIPHER_GROUP";
	ni_bool_t need_identity = FALSE;
	ni_bool_t need_password = FALSE;
	const char *cert;

	ni_assert(sc && net && suffix);


	/* Default are TTLS PEAP TLS */
	if ((var = __find_indexed_variable(sc,"WIRELESS_EAP_MODE", suffix))) {
		if (!ni_wireless_name_to_eap_method(var->value, &net->wpa_eap.method)) {
			ni_error("ifcfg-%s: wrong WIRELESS_EAP_MODE%s value",
				dev_name, suffix);
			goto eap_failure;
		}
	} else {
		if (ni_wireless_is_eap_config(sc, net, suffix)) {
			ni_error("ifcfg-%s: no WIRELESS_EAP_MODE%s value specified", dev_name, suffix);
			goto eap_failure;
		} else {
			return TRUE;
		}
	}

	if ((var = __find_indexed_variable(sc,"WIRELESS_EAP_AUTH", suffix))) {
		if (net->wpa_eap.method == NI_WIRELESS_EAP_TLS) {
			ni_warn("ifcfg-%s: Ignore WIRELESS_EAP_AUTH%s for eap mode TLS", dev_name, suffix);

		} else if (!ni_wireless_name_to_eap_method(var->value, &net->wpa_eap.phase2.method)) {
			ni_error("ifcfg-%s: wrong WIRELESS_EAP_AUTH%s value",
				dev_name, suffix);
			goto eap_failure;
		}
	}

	/* wickedd: Default are both WPA and WPA2 */
	if (ni_wireless_parse_auth_proto(sc, &net->auth_proto, suffix, dev_name) < 0)
		goto eap_failure;

	/* wickedd: Default are both TKIP and CCMP */
	if (ni_wireless_parse_pairwise_cipher(sc, &net->pairwise_cipher, pairwise, suffix, dev_name) < 0)
		goto eap_failure;

	/* wickedd: Default are both TKIP and CCMP */
	if (ni_wireless_parse_group_cipher(sc, &net->group_cipher, group, suffix, dev_name) < 0)
		goto eap_failure;

	if (NI_WIRELESS_AP_SCAN_SUPPLICANT_EXPLICIT_MATCH == ap_scan) {
		if (!(net->auth_proto & NI_BIT(NI_WIRELESS_AUTH_PROTO_RSN)))
			net->auth_proto = NI_BIT(NI_WIRELESS_AUTH_PROTO_WPA);

		if (!(net->pairwise_cipher & NI_BIT(NI_WIRELESS_CIPHER_CCMP)))
			net->pairwise_cipher = NI_BIT(NI_WIRELESS_CIPHER_TKIP);

		if (!(net->group_cipher & NI_BIT(NI_WIRELESS_CIPHER_CCMP)))
			net->group_cipher = NI_BIT(NI_WIRELESS_CIPHER_TKIP);
	}

	need_identity = net->wpa_eap.method == NI_WIRELESS_EAP_PEAP
			|| net->wpa_eap.method == NI_WIRELESS_EAP_TTLS
			|| net->wpa_eap.method == NI_WIRELESS_EAP_TLS;
	need_password = net->wpa_eap.method == NI_WIRELESS_EAP_PEAP
			|| net->wpa_eap.method == NI_WIRELESS_EAP_TTLS;

	if ((var = __find_indexed_variable(sc,"WIRELESS_WPA_IDENTITY", suffix))) {
		ni_string_dup(&net->wpa_eap.identity, var->value);
	} else if (need_identity) {
		ni_error("ifcfg-%s: no WIRELESS_WPA_IDENTITY%s value specified",
			dev_name, suffix);
		goto eap_failure;
	}

	if ((var = __find_indexed_variable(sc,"WIRELESS_WPA_PASSWORD", suffix))) {
		ni_string_dup(&net->wpa_eap.phase2.password, var->value);
	}
	else if (need_password) {
		ni_error("ifcfg-%s: no WIRELESS_WPA_PASSWORD%s value specified",
			dev_name, suffix);
		goto eap_failure;
	}

	/* wickedd: Default is 'anonymous' */
	if ((var = __find_indexed_variable(sc,"WIRELESS_WPA_ANONID", suffix)))
		ni_string_dup(&net->wpa_eap.anonid, var->value);

	if ((var = __find_indexed_variable(sc,"WIRELESS_CA_CERT", suffix))) {
		if (!(cert = __ni_wireless_validate_cert_path(sc, var->value))) {
			ni_error("ifcfg-%s: WIRELESS_CA_CERT%s file not found.", dev_name, suffix);
			goto eap_failure;
		}
		net->wpa_eap.tls.ca_cert = ni_wireless_blob_new_from_str(cert);
	}

	if ((var = __find_indexed_variable(sc,"WIRELESS_CLIENT_CERT", suffix))) {
		if (!(cert = __ni_wireless_validate_cert_path(sc, var->value))) {
			ni_error("ifcfg-%s: WIRELESS_CLIENT_CERT%s file not found.", dev_name, suffix);
			goto eap_failure;
		}
		net->wpa_eap.tls.client_cert = ni_wireless_blob_new_from_str(cert);
	}

	if ((var = __find_indexed_variable(sc,"WIRELESS_CLIENT_KEY", suffix))) {
		if (!(cert = __ni_wireless_validate_cert_path(sc, var->value))) {
			ni_error("ifcfg-%s: WIRELESS_CLIENT_KEY%s file not found.", dev_name, suffix);
			goto eap_failure;
		}
		net->wpa_eap.tls.client_key = ni_wireless_blob_new_from_str(cert);
	}

	if ((var = __find_indexed_variable(sc,"WIRELESS_CLIENT_KEY_PASSWORD", suffix)))
		ni_string_dup(&net->wpa_eap.tls.client_key_passwd, var->value);

	/* Default are version 0 and 1 */
	net->wpa_eap.phase1.peapver = -1U;
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

		if ((var = __find_indexed_variable(sc,"WIRELESS_PEAP_LABEL", suffix))) {
			if (!ni_parse_boolean(var->value, &net->wpa_eap.phase1.peaplabel)) {
				ni_error("ifcfg-%s: wrong WIRELESS_PEAP_LABEL%s value", dev_name, suffix);
				goto eap_failure;
			}
		}

		if (net->wpa_eap.phase2.method == NI_WIRELESS_EAP_NONE) {
			if (net->wpa_eap.phase1.peapver == 1)
				net->wpa_eap.phase2.method = NI_WIRELESS_EAP_GTC;
			else
				net->wpa_eap.phase2.method = NI_WIRELESS_EAP_MSCHAPV2;

			ni_warn("ifcfg-%s: assuming WIRELESS_EAP_AUTH%s='%s'", dev_name, suffix,
					ni_wireless_eap_method_to_name(net->wpa_eap.phase2.method));
		}
	}

	return TRUE;

eap_failure:
	return FALSE;
}

static int
try_wireless(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_string_array_t vnames = NI_STRING_ARRAY_INIT;
	ni_bool_t enabled = FALSE;
	const char *value;
	int ret = 1;

	/*
	 * Check for WIRELESS, WIRELESS_WPA_DRIVER, WIRELESS_AP_SCANMODE or one
	 * WIRELESS_ESSID to make this a wireless configuration.
	 *
	 * WIRELESS=false avoid parsing of wireless configuration.
	 * An invalid WIRELESS value produce a warning but will be ignored.
	 */

	value = ni_sysconfig_get_value(sc, "WIRELESS");
	if (!ni_string_empty(value)) {
		if (ni_parse_boolean(value, &enabled) != 0)
			ni_warn("ifcfg-%s: invalid WIRELESS='%s' option value", dev->name, value);
		else if (!enabled)
			return ret;
	}

	if (enabled ||
	    ni_sysconfig_get_value(sc, "WIRELESS_AP_SCANMODE") ||
	    ni_sysconfig_get_value(sc, "WIRELESS_WPA_DRIVER")  ||
	    ni_sysconfig_find_matching(sc, "WIRELESS_ESSID", &vnames) > 0 ) {

		if (try_add_wireless(sc, dev))
			ret = 0;
		else
			ret = -1;
	}

	ni_string_array_destroy(&vnames);
	return ret;
}

/*
 * Handle provider files
 */
static ni_sysconfig_t *
__ni_suse_read_provider(const char *sibling, const char *provider)
{
	const char *filename;

	filename = ni_sibling_path_printf(sibling, "providers/%s", provider);
	if (ni_string_empty(filename) || !ni_file_exists(filename))
		return NULL;
	return ni_sysconfig_read(filename);
}

static int
try_pppoe(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg,
		ni_ppp_mode_pppoe_t *pppoe)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	const char *value;

	value = ni_sysconfig_get_value(sc, "DEVICE");
	if (!ni_suse_ifcfg_add_lower(ifcfgs, ifcfg, value, "PPPoE ethernet device"))
		return -1;

	ni_netdev_ref_set_ifname(&pppoe->device, value);
	return 0;
}

/*
 * Handle all sorts of PPP
 */
static int
try_ppp(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_sysconfig_t *psc = NULL;
	const char *value;
	ni_bool_t bval;
	ni_ppp_t *ppp;
	int ret = -1;

	if ((value = ni_sysconfig_get_value(sc, "PPPMODE")) == NULL)
		return 1;

	if (dev->link.type != NI_IFTYPE_UNKNOWN) {
		ni_error("ifcfg-%s: %s config contains ppp variables",
			dev->name, ni_linktype_type_to_name(dev->link.type));
		goto done;
	}

	/* just drop old if any */
	ni_netdev_set_ppp(dev, NULL);

	dev->link.type = NI_IFTYPE_PPP;
	ppp = ni_netdev_get_ppp(dev);

	if (!ni_ppp_mode_name_to_type(value, &ppp->mode.type)) {
		ni_error("ifcfg-%s: unsupported ppp mode '%s'", dev->name, value);
		goto done;
	}

	ni_ppp_mode_init(&ppp->mode, ppp->mode.type);

	if (ni_sysconfig_get_boolean(sc, "PPPDEBUG", &bval))
		ppp->config.debug = bval;

	value = ni_sysconfig_get_value(sc, "PROVIDER");
	if (!ni_string_empty(value)) {
		psc = __ni_suse_read_provider(sc->pathname, value);
		if (!psc) {
			ni_error("ifcfg-%s: unable to read provider file '%s'", dev->name, value);
			goto done;
		}
	}

	if (!psc) {
		ni_error("ifcfg-%s: no valid PROVIDER is specified", dev->name);
		goto done;
	}

	value = ni_sysconfig_get_value(psc, "DEFAULTROUTE");
	if (ni_parse_boolean(value, &ppp->config.defaultroute) < 0)
		ppp->config.defaultroute = TRUE;

	if (ni_sysconfig_get_boolean(psc, "DEMAND", &bval))
		ppp->config.demand = bval;

	value = ni_sysconfig_get_value(psc, "IDLETIME");
	if (!ni_string_empty(value) && ni_parse_uint(value, &ppp->config.idle, 10) < 0) {
		ni_error("ifcfg-%s: unable to parse IDLETIME='%s'", dev->name, value);
		goto done;
	}

	ni_string_dup(&ppp->config.auth.username, ni_sysconfig_get_value(psc, "USERNAME"));
	ni_string_dup(&ppp->config.auth.password, ni_sysconfig_get_value(psc, "PASSWORD"));
	ni_string_dup(&ppp->config.auth.hostname, ni_sysconfig_get_value(psc, "HOSTNAME"));

	value = ni_sysconfig_get_value(psc, "AUTODNS");
	if (ni_parse_boolean(value, &ppp->config.dns.usepeerdns) < 0)
		ppp->config.dns.usepeerdns = TRUE;

	value = ni_sysconfig_get_value(psc, "DNS1");
	if (!ni_string_empty(value)) {
		if (ni_sockaddr_parse(&ppp->config.dns.dns1, value, AF_INET) < 0) {
			ni_error("ifcfg-%s: unable to parse DNS1='%s'", dev->name, value);
			goto done;
		}
	}
	value = ni_sysconfig_get_value(psc, "DNS2");
	if (!ni_string_empty(value)) {
		if (ni_sockaddr_parse(&ppp->config.dns.dns2, value, AF_INET) < 0) {
			ni_error("ifcfg-%s: unable to parse DNS2='%s'", dev->name, value);
			goto done;
		}
	}

	value = ni_sysconfig_get_value(psc, "MODIFYIP");
	if (ni_parse_boolean(value, &bval) == 0) {
		ppp->config.ipv4.ipcp.accept_local = bval;
		ppp->config.ipv4.ipcp.accept_remote = bval;
		ppp->config.ipv6.ipcp.accept_local = bval;
	}
	value = ni_sysconfig_get_value(psc, "MODIFYIP6");
	if (ni_parse_boolean(value, &bval) == 0)
		ppp->config.ipv6.ipcp.accept_local = bval;

	value = ni_sysconfig_get_value(psc, "IPADDR");
	if (!ni_string_empty(value)) {
		if (ni_sockaddr_parse(&ppp->config.ipv4.local_ip, value, AF_INET) < 0) {
			ni_error("ifcfg-%s: unable to parse IPADDR='%s'", dev->name, value);
			goto done;
		}
	}

	value = ni_sysconfig_get_value(psc, "REMOTE_IPADDR");
	if (ni_string_empty(value))
		value = ni_sysconfig_get_value(psc, "PTPADDR");
	if (!ni_string_empty(value)) {
		if (ni_sockaddr_parse(&ppp->config.ipv4.remote_ip, value, AF_INET) < 0) {
			ni_error("ifcfg-%s: unable to parse REMOTE_IPADDR/PTPADDR='%s'", dev->name, value);
			goto done;
		}
	}

	value = ni_sysconfig_get_value(psc, "IPADDR6");
	if (!ni_string_empty(value)) {
		if (ni_sockaddr_parse(&ppp->config.ipv6.local_ip, value, AF_INET6) < 0) {
			ni_error("ifcfg-%s: unable to parse IPADDR6='%s'", dev->name, value);
			goto done;
		}
	}

	value = ni_sysconfig_get_value(psc, "REMOTE_IPADDR6");
	if (ni_string_empty(value))
		value = ni_sysconfig_get_value(psc, "PTPADDR6");
	if (!ni_string_empty(value)) {
		if (ni_sockaddr_parse(&ppp->config.ipv6.remote_ip, value, AF_INET6) < 0) {
			ni_error("ifcfg-%s: unable to parse REMOTE_IPADDR6/PTPADDR6='%s'", dev->name, value);
			goto done;
		}
	}

	if (ni_sysconfig_get_boolean(psc, "MULTILINK", &bval))
		ppp->config.multilink = bval;
	ni_string_dup(&ppp->config.endpoint, ni_sysconfig_get_value(psc, "ENDPOINT"));

	if (ni_sysconfig_get_boolean(psc, "AUTO_RECONNECT", &bval))
		ppp->config.persist = bval;

	value = ni_sysconfig_get_value(psc, "AUTO_RECONNECT_DELAY");
	if (!ni_string_empty(value) && ni_parse_uint(value, &ppp->config.holdoff, 10) < 0) {
		ni_error("ifcfg-%s: unable to parse AUTO_RECONNECT_DELAY='%s'", dev->name, value);
		goto done;
	}

	value = ni_sysconfig_get_value(psc, "MAXFAIL");
	if (!ni_string_empty(value) && ni_parse_uint(value, &ppp->config.maxfail, 10) < 0) {
		ni_error("ifcfg-%s: unable to parse MAXFAIL='%s'", dev->name, value);
		goto done;
	}

	ret = 0;
	switch (ppp->mode.type) {
	case NI_PPP_MODE_PPPOE:
		ret = try_pppoe(ifcfgs, ifcfg, &ppp->mode.pppoe);
		break;
	case NI_PPP_MODE_PPPOATM:
		/* PPPoATM support is not implemented */
		break;
	case NI_PPP_MODE_PPTP:
		/* PPTP support is not implemented */
		break;
	case NI_PPP_MODE_ISDN:
		/* ISDN support is not implemented */
		break;
	case NI_PPP_MODE_SERIAL:
		/* PPP SERIAL support is not implemented */
		break;
	default:
		/* should not happen */
		ret = -1;
		break;
	}

done:
	ni_sysconfig_free(psc);
	return ret;
}

/*
 * Handle Tunnel interfaces
 */
static int
try_tunnel_tuntap(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
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
try_tunnel_generic(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg,
		const char *ifname, unsigned short arp_type,
		ni_linkinfo_t *link, ni_tunnel_t *tunnel)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	const char *value = NULL;
	unsigned int ui_value;

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_DEVICE"))) {
		if (!ni_suse_ifcfg_add_lower(ifcfgs, ifcfg, value, "TUNNEL_DEVICE"))
			return -1;

		ni_string_dup(&link->lowerdev.name, value);
	}

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
try_tunnel_ipip(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_ipip_t *ipip = NULL;
	int rv = 0;

	if (!(ipip = ni_netdev_get_ipip(dev)))
		return -1;

	/* Populate generic tunneling data from config. */
	rv = try_tunnel_generic(ifcfgs, ifcfg, dev->name, ARPHRD_TUNNEL,
				&dev->link, &ipip->tunnel);

	return rv;
}

static int
try_tunnel_gre(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	ni_string_array_t flags = NI_STRING_ARRAY_INIT;
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_gre_t *gre = NULL;
	ni_sockaddr_t addr;
	const char *value;
	unsigned int flag, i;
	int rv = 0;

	if (!(gre = ni_netdev_get_gre(dev)))
		return -1;

	/* Populate generic tunneling data from config. */
	rv = try_tunnel_generic(ifcfgs, ifcfg, dev->name, ARPHRD_IPGRE,
				&dev->link, &gre->tunnel);

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_GRE_FLAGS"))) {
		ni_string_split(&flags, value, " \t", 0);
		for (i = 0; i < flags.count; ++i) {
			if (!ni_gre_flag_name_to_bit(flags.data[i], &flag)) {
				ni_error("ifcfg-%s: Unsupported TUNNEL_GRE_FLAGS=\"%s\"",
						dev->name, flags.data[i]);
				ni_string_array_destroy(&flags);
				return -1;
			}
			gre->flags |= NI_BIT(flag);
		}
		ni_string_array_destroy(&flags);
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_GRE_IKEY"))) {
		if (strchr(value, '.') && ni_sockaddr_parse(&addr, value, AF_INET) == 0) {
			gre->ikey.s_addr = addr.sin.sin_addr.s_addr;
			gre->flags |= NI_BIT(NI_GRE_FLAG_IKEY);
		} else
		if (ni_parse_uint(value, &flag, 10) == 0) {
			gre->ikey.s_addr = htons(flag);
			gre->flags |= NI_BIT(NI_GRE_FLAG_IKEY);
		} else {
			ni_error("ifcfg-%s: Cannot parse TUNNEL_GRE_IKEY=\"%s\"",
					dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_GRE_OKEY"))) {
		if (strchr(value, '.') && ni_sockaddr_parse(&addr, value, AF_INET) == 0) {
			gre->okey.s_addr = addr.sin.sin_addr.s_addr;
			gre->flags |= NI_BIT(NI_GRE_FLAG_OKEY);
		} else
		if (ni_parse_uint(value, &flag, 10) == 0) {
			gre->okey.s_addr = htons(flag);
			gre->flags |= NI_BIT(NI_GRE_FLAG_OKEY);
		} else {
			ni_error("ifcfg-%s: Cannot parse TUNNEL_GRE_OKEY=\"%s\"",
					dev->name, value);
			return -1;
		}
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_GRE_ENCAP_TYPE"))) {
		if (!ni_gre_encap_name_to_type(value, &flag)) {
			ni_error("ifcfg-%s: Unsupported TUNNEL_GRE_ENCAP_TYPE=\"%s\"",
					dev->name, value);
			return -1;
		}
		gre->encap.type = flag;
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_GRE_ENCAP_FLAGS"))) {
		ni_string_split(&flags, value, " \t", 0);
		for (i = 0; i < flags.count; ++i) {
			if (!ni_gre_encap_flag_name_to_bit(flags.data[i], &flag)) {
				ni_error("ifcfg-%s: Unsupported TUNNEL_GRE_ENCAP_FLAGS=\"%s\"",
						dev->name, flags.data[i]);
				ni_string_array_destroy(&flags);
				return -1;
			}
			gre->encap.flags |= NI_BIT(flag);
		}
		ni_string_array_destroy(&flags);
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_GRE_ENCAP_SPORT"))) {
		if (ni_parse_uint(value, &flag, 10) < 0 || flag > USHRT_MAX) {
			ni_error("ifcfg-%s: Cannot parse TUNNEL_GRE_ENCAP_SPORT=\"%s\"",
					dev->name, value);
			return -1;
		}
		gre->encap.sport = flag;
	}

	if ((value = ni_sysconfig_get_value(sc, "TUNNEL_GRE_ENCAP_DPORT"))) {
		if (ni_parse_uint(value, &flag, 10) < 0 || flag > USHRT_MAX) {
			ni_error("ifcfg-%s: Cannot parse TUNNEL_GRE_ENCAP_DPORT=\"%s\"",
					dev->name, value);
			return -1;
		}
		gre->encap.dport = flag;
	}

	return rv;
}

static int
try_tunnel_sit(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_sit_t *sit = NULL;
	const char *value = NULL;
	int rv = 0;

	if (!(sit = ni_netdev_get_sit(dev)))
		return -1;

	/* Populate generic tunneling data from config. */
	rv = try_tunnel_generic(ifcfgs, ifcfg, dev->name, ARPHRD_SIT,
				&dev->link, &sit->tunnel);

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
try_tunnel(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	const char *value;
	static const ni_intmap_t tunnel_types[] = {
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

	for (map = tunnel_types; map->name; ++map) {
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
		return try_tunnel_tuntap(ifcfgs, ifcfg);

	case NI_IFTYPE_IPIP:
		return try_tunnel_ipip(ifcfgs, ifcfg);

	case NI_IFTYPE_GRE:
		return try_tunnel_gre(ifcfgs, ifcfg);

	case NI_IFTYPE_SIT:
		return try_tunnel_sit(ifcfgs, ifcfg);

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
__get_ipaddr_lft(const char *val, unsigned int *lft)
{
	if (ni_string_eq(val, "forever") || ni_string_eq(val, "infinite"))
		*lft = NI_LIFETIME_INFINITE;
	else
	if (!ni_parse_uint(val, lft, 0))
		return FALSE;
	return TRUE;
}

static ni_bool_t
__get_ipaddr_opts(const char *value, ni_address_t *ap)
{
	ni_string_array_t opts = NI_STRING_ARRAY_INIT;
	unsigned int valid_lft = NI_LIFETIME_INFINITE;
	unsigned int preferred_lft = NI_LIFETIME_INFINITE;
	const char *opt, *val;
	unsigned int pos = 0;
	ni_bool_t ret = TRUE;

	/*
	 * All about ipv6 -- anything useful to consider for ipv4?
	 */
	if (ap->family != AF_INET6)
		return TRUE;

	ni_string_split(&opts, value, " \t", 0);

	while ((opt = ni_string_array_at(&opts, pos++))) {
		if (ni_string_eq(opt, "valid_lft")) {
			val = ni_string_array_at(&opts, pos++);
			if (!__get_ipaddr_lft(val, &valid_lft))
				ret = FALSE;
		}
		else
		if (ni_string_eq(opt, "preferred_lft")) {
			val = ni_string_array_at(&opts, pos++);
			if (!__get_ipaddr_lft(val, &preferred_lft))
				ret = FALSE;
		}
		else
		if (ni_string_eq(opt, "nodad"))
			ap->flags |= IFA_F_NODAD;
		else
		if (ni_string_eq(opt, "noprefixroute"))
			ap->flags |= IFA_F_NOPREFIXROUTE;
		else
		if (ni_string_eq(opt, "autojoin"))
			ap->flags |= IFA_F_MCAUTOJOIN;
		else
		if (ni_string_eq(opt, "home") || ni_string_eq(opt, "homeaddress"))
			ap->flags |= IFA_F_HOMEADDRESS;
		else
			ret = FALSE;
	}

	if (preferred_lft > valid_lft)
		preferred_lft = valid_lft;

	if (preferred_lft != NI_LIFETIME_INFINITE) {
		ap->cache_info.valid_lft = valid_lft;
		ap->cache_info.preferred_lft = preferred_lft;
	}

	return ret;
}

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

	ap = ni_address_create(local_addr.ss_family, prefixlen, &local_addr, list);
	if (ap && ap->family == AF_INET) {
		var = __find_indexed_variable(sc, "BROADCAST", suffix);
		if (var && ni_sockaddr_parse(&ap->bcast_addr, var->value, AF_INET) < 0) {
			ni_warn("ifcfg-%s: ignoring BROADCAST%s=%s (unable to parse)",
					ifname, suffix, var->value);
			ap->bcast_addr.ss_family = AF_UNSPEC;
		} else
		if (ni_sockaddr_equal(&ap->bcast_addr, &ap->local_addr)) {
			/* Clear the default, it's useless */
			memset(&ap->bcast_addr, 0, sizeof(ap->bcast_addr));
		}
	}

	if (prefixlen == ni_af_address_prefixlen(local_addr.ss_family))	{
		var = __find_indexed_variable(sc, "REMOTE_IPADDR", suffix);
		if (var) {
			if (ni_sockaddr_parse(&ap->peer_addr, var->value, AF_UNSPEC) < 0) {
				ni_warn("ifcfg-%s: ignoring REMOTE_IPADDR%s=%s (unable to parse)",
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

	var = __find_indexed_variable(sc, "SCOPE", suffix);
	if (var && !ni_string_empty(var->value)) {
		unsigned int scope;
		if (!ni_route_scope_name_to_type(var->value, &scope)) {
			ni_info("ifcfg-%s: ignoring %s='%s' unknown scope",
					ifname, var->name, var->value);
		} else {
			ap->scope = scope;
		}
	}

	var = __find_indexed_variable(sc, "IP_OPTIONS", suffix);
	if (var && !ni_string_empty(var->value)) {
		if (!__get_ipaddr_opts(var->value, ap)) {
			ni_info("ifcfg-%s: %s='%s' contains unsupported options",
					ifname, var->name, var->value);
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
	const char *rulespath;
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
				ni_address_create(AF_INET, 8, &local_addr, &dev->addrs);
		}
		if (ipv6_enabled) {
			ni_sockaddr_parse(&local_addr, "::1", AF_INET6);
			if (ni_address_list_find(dev->addrs, &local_addr) == NULL)
				ni_address_create(AF_INET6, 128, &local_addr, &dev->addrs);
		}
	}

	ni_address_list_dedup(&dev->addrs);

	if (dev->routes != NULL)
		ni_route_tables_destroy(&dev->routes);

	routespath = ni_sibling_path_printf(sc->pathname, "ifroute-%s", dev->name);
	if (routespath && ni_file_exists(routespath)) {
		__ni_suse_read_routes(&dev->routes, routespath, dev->name);
	}

	rulespath = ni_sibling_path_printf(sc->pathname, "ifrule-%s", dev->name);
	if (rulespath && ni_file_exists(rulespath)) {
		ni_suse_read_rules(&compat->rules, rulespath, dev->name);
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
			} else if (!ni_dhcp_check_user_class_id(string, length)) {
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
		} else if (!ni_dhcp_check_user_class_id(string, length)) {
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

static void
__ni_suse_parse_dhcp_req_options(const ni_sysconfig_t *sc, ni_string_array_t *options,
				const char *prefix, const ni_dhcp_option_decl_t *custom,
				unsigned int code_min, unsigned int code_max)
{
	ni_string_array_t vars = NI_STRING_ARRAY_INIT;
	ni_string_array_t opts = NI_STRING_ARRAY_INIT;
	const char *value;
	unsigned int i, j;
	unsigned int code;

	ni_sysconfig_find_matching(sc, prefix, &vars);
	for (i = 0; i < vars.count; ++i) {
		value = ni_sysconfig_get_value(sc, vars.data[i]);
		ni_string_split(&opts, value, " ", 0);
		for (j = 0; j < opts.count; ++j) {
			const ni_dhcp_option_decl_t *decl;
			const char *opt = opts.data[j];

			if ((decl = ni_dhcp_option_decl_list_find_by_name(custom, opt)))
				opt = decl->name;
			else
			if (ni_parse_uint(opt, &code, 10)) {
				ni_warn("%s: Cannot parse %s option code '%s'",
						ni_basename(sc->pathname), vars.data[i],
						opt);
				continue;
			} else
			if (code < code_min || code_max < code) {
				ni_warn("%s: %s option code %u is out of range (%u..%u)",
						ni_basename(sc->pathname), vars.data[i],
						code, code_min, code_max);
				continue;
			} else
			if ((decl = ni_dhcp_option_decl_list_find_by_code(custom, code)))
				opt = decl->name;

			ni_string_array_append(options, opt);
		}
		ni_string_array_destroy(&opts);
	}
	ni_string_array_destroy(&vars);
}

/*
 * Process DHCPv4 addrconf
 */
static ni_bool_t
__ni_suse_addrconf_dhcp4_options(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat,
				const ni_config_dhcp4_t *config)
{
	const char *string;
	unsigned int uint;
	ni_bool_t bvalue;
	ni_bool_t ret = TRUE;

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_BROADCAST")) != NULL) {
		if (ni_parse_boolean(string, &bvalue) == 0) {
			ni_tristate_set(&compat->dhcp4.broadcast, bvalue);
		}
	}

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_UPDATE")) != NULL) {
		uint = compat->dhcp4.update;
		if (ni_addrconf_update_flags_parse(&uint, string, " \t,")) {
			uint &= ni_config_addrconf_update_mask(NI_ADDRCONF_DHCP, AF_INET);
			compat->dhcp4.update = uint;
		} else {
			ni_warn("%s: Unknown flags in DHCLIENT_UPDATE='%s'",
				ni_basename(sc->pathname),
				ni_print_suspect(string, ni_string_len(string)));
		}
	}

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_FQDN_ENABLED")) != NULL) {
		if (ni_parse_boolean(string, &bvalue) == 0)
			ni_tristate_set(&compat->dhcp4.fqdn.enabled, bvalue);
	}
	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_HOSTNAME_OPTION")) != NULL) {
		if (!strcasecmp(string, "FQDN")) {
			ni_string_dup(&compat->dhcp4.hostname, __ni_suse_default_hostname);
		} else
		if (!strcasecmp(string, "AUTO")) {
			ni_string_dup(&compat->dhcp4.hostname, __ni_suse_default_hostname);
			if (compat->dhcp4.fqdn.enabled != NI_TRISTATE_ENABLE) {
				char *ptr;

				/* defaults same to SLES-11: truncate the
				 * hostname to send via hostname option 12 */
				ptr = compat->dhcp4.hostname;
				if (ni_string_len(ptr) && (ptr = strchr(ptr, '.')))
					*ptr = '\0';
			}
		} else
		if (ni_check_domain_name(string, ni_string_len(string), 0)) {
			ni_string_dup(&compat->dhcp4.hostname, string);
		} else {
			ni_warn("%s: Cannot parse DHCLIENT_HOSTNAME_OPTION='%s'",
				ni_basename(sc->pathname),
				ni_print_suspect(string, ni_string_len(string)));
			ret = FALSE;
		}
	}
	if (compat->dhcp4.fqdn.enabled != NI_TRISTATE_DISABLE) {
		if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_FQDN_QUALIFY")) != NULL)
			ni_parse_boolean(string, &compat->dhcp4.fqdn.qualify);
		if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_FQDN_ENCODE")) != NULL)
			ni_parse_boolean(string, &compat->dhcp4.fqdn.encode);
		if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_FQDN_UPDATE")) != NULL)
			ni_dhcp_fqdn_update_name_to_mode(string, &compat->dhcp4.fqdn.update);
		if (ni_string_empty(compat->dhcp4.hostname))
			compat->dhcp4.fqdn.update = NI_DHCP_FQDN_UPDATE_NONE;
	}

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_CLIENT_ID")) != NULL)
		ni_string_dup(&compat->dhcp4.client_id, string);
	else
	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_CREATE_CID")) != NULL) {
		if (!ni_config_dhcp4_cid_type_parse(&compat->dhcp4.create_cid, string))
			ni_warn("%s: Cannot parse DHCLIENT_CREATE_CID='%s' option",
					ni_basename(sc->pathname),
					ni_print_suspect(string, ni_string_len(string)));
	}

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
		compat->dhcp4.lease_time = uint;

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
	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_ROUTE_SET_SRC")))
		ni_parse_boolean(string, &compat->dhcp4.route_set_src);

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

	__ni_suse_parse_dhcp_req_options(sc, &compat->dhcp4.request_options,
					"DHCLIENT_REQUEST_OPTION", config ?
					config->custom_options : NULL, 1, 254);
	return ret;
}

/*
 * Process DHCPv6 addrconf
 */
static ni_bool_t
__ni_suse_addrconf_dhcp6_options(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat,
				const ni_config_dhcp6_t *config)
{
	ni_bool_t ret = TRUE;
	unsigned int uint;
	const char *string;
	ni_bool_t bvalue;

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_UPDATE")) != NULL) {
		uint = compat->dhcp6.update;
		if (ni_addrconf_update_flags_parse(&uint, string, " \t,")) {
			uint &= ni_config_addrconf_update_mask(NI_ADDRCONF_DHCP, AF_INET6);
			compat->dhcp6.update = uint;
		} else {
			ni_warn("%s: Unknown flags in DHCLIENT6_UPDATE='%s'",
				ni_basename(sc->pathname),
				ni_print_suspect(string, ni_string_len(string)));
			ret = FALSE;
		}
	}

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_MODE")) != NULL) {
		if (!ni_dhcp6_mode_parse(&compat->dhcp6.mode, string)) {
			ni_warn("%s: Cannot parse DHCLIENT6_MODE='%s'",
				ni_basename(sc->pathname), string);
			ret = FALSE;
		}
	}

	if (compat->dhcp6.mode & NI_BIT(NI_DHCP6_MODE_PREFIX)) {
		if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_PREFIX_HINT"))) {
			ni_dhcp6_prefix_req_t *pr = NULL;
			ni_dhcp6_ia_addr_t *hint = NULL;
			ni_sockaddr_t addr;
			unsigned int plen;

			if (!ni_sockaddr_prefix_parse(string, &addr, &plen) || !plen ||
			    addr.ss_family != AF_INET6 || plen >= ni_af_address_prefixlen(AF_INET6)) {
				 ni_warn("%s: Invalid prefix hint in DHCLIENT6_PREFIX_HINT='%s'",
						 ni_basename(sc->pathname), string);
				ret = FALSE;
			} else
			if (!(pr = ni_dhcp6_prefix_req_new()) ||
			    !(hint = ni_dhcp6_ia_prefix_new(addr.six.sin6_addr, plen)) ||
			    !ni_dhcp6_ia_addr_list_append(&pr->hints, hint) ||
			    !ni_dhcp6_prefix_req_list_append(&compat->dhcp6.prefix_reqs, pr)) {
				ni_warn("%s: Unable to allocate prefix hint for DHCLIENT6_PREFIX_HINT='%s'",
						ni_basename(sc->pathname), string);
				ret = FALSE;
			}
		}
	}

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_ADDRESS_LENGTH")) != NULL) {
		if (ni_parse_uint(string, &uint, 10) == 0 &&
		    uint <= ni_af_address_prefixlen(AF_INET6)) {
			compat->dhcp6.address_len = uint;
		} else {
			ni_warn("%s: Invalid length in DHCLIENT6_ADDRESS_LENGTH='%s'",
					ni_basename(sc->pathname), string);
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

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_FQDN_ENABLED")) != NULL) {
		if (ni_parse_boolean(string, &bvalue) == 0)
			ni_tristate_set(&compat->dhcp6.fqdn.enabled, bvalue);
	}
	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_HOSTNAME_OPTION")) != NULL) {
		if (!strcasecmp(string, "FQDN")) {
			ni_string_dup(&compat->dhcp6.hostname, __ni_suse_default_hostname);
		} else
		if (!strcasecmp(string, "AUTO")) {
			char *ptr;

			/* defaults same to SLES-11: truncate the name */
			ni_string_dup(&compat->dhcp6.hostname, __ni_suse_default_hostname);
			ptr = compat->dhcp6.hostname;
			if (ni_string_len(ptr) && (ptr = strchr(ptr, '.')))
				*ptr = '\0';
		} else
		if (ni_check_domain_name(string, ni_string_len(string), 0)) {
			ni_string_dup(&compat->dhcp6.hostname, string);
		} else {
			ni_warn("%s: Cannot parse DHCLIENT6_HOSTNAME_OPTION='%s'",
				ni_basename(sc->pathname),
				ni_print_suspect(string, ni_string_len(string)));
			ret = FALSE;
		}
	}
	if (compat->dhcp6.fqdn.enabled != NI_TRISTATE_DISABLE) {
		if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_FQDN_QUALIFY")) != NULL)
			ni_parse_boolean(string, &compat->dhcp6.fqdn.qualify);
		if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_FQDN_UPDATE")) != NULL)
			ni_dhcp_fqdn_update_name_to_mode(string, &compat->dhcp6.fqdn.update);
		if (ni_string_empty(compat->dhcp6.hostname))
			compat->dhcp6.fqdn.update = NI_DHCP_FQDN_UPDATE_NONE;
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
		compat->dhcp6.lease_time = uint;

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_USE_LAST_LEASE")))
		compat->dhcp6.recover_lease = !ni_string_eq(string, "no");

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT6_REFRESH_LEASE")))
		compat->dhcp6.refresh_lease = ni_string_eq(string, "yes");

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

	__ni_suse_parse_dhcp_req_options(sc, &compat->dhcp6.request_options,
					"DHCLIENT6_REQUEST_OPTION", config ?
					config->custom_options : NULL, 1, 65534);

	return ret;
}

static ni_bool_t
__ni_suse_addrconf_dhcp4(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_bool_t required)
{
	const ni_config_dhcp4_t *config = NULL;
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

	config = ni_config_dhcp4_find_device(dev->name);
	if ((merged = ni_sysconfig_merge_defaults(sc, __ni_suse_dhcp_defaults))) {
		__ni_suse_addrconf_dhcp4_options(merged, compat, config);
		ni_sysconfig_free(merged);
	}

	compat->dhcp4.enabled = TRUE;
	ni_addrconf_flag_bit_set(&compat->dhcp4.flags, NI_ADDRCONF_FLAGS_GROUP, !required);
	return TRUE;
}

static ni_bool_t
__ni_suse_addrconf_dhcp6(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_bool_t required)
{
	const ni_config_dhcp6_t *config = NULL;
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

	config = ni_config_dhcp6_find_device(dev->name);
	if ((merged = ni_sysconfig_merge_defaults(sc, __ni_suse_dhcp_defaults))) {
		__ni_suse_addrconf_dhcp6_options(merged, compat, config);
		ni_sysconfig_free(merged);
	}

	compat->dhcp6.enabled = TRUE;
	ni_addrconf_flag_bit_set(&compat->dhcp6.flags, NI_ADDRCONF_FLAGS_GROUP, !required);
	return TRUE;
}

static ni_bool_t
__ni_suse_addrconf_auto4(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_bool_t required)
{
	ni_netdev_t *dev = compat->dev;

	(void)sc; /* no additional config here */

	if (dev && dev->ipv4 && ni_tristate_is_disabled(dev->ipv4->conf.enabled))
		return FALSE;

	if (compat->auto4.enabled)
		return TRUE;

	compat->auto4.enabled = TRUE;
	/* mark auto4 as fallback for dhcp4    */
	ni_addrconf_flag_bit_set(&compat->auto4.flags, NI_ADDRCONF_FLAGS_FALLBACK, !required);
	/* mark dhcp4 as primary triggering it */
	ni_addrconf_flag_bit_set(&compat->dhcp4.flags, NI_ADDRCONF_FLAGS_PRIMARY, !required);
	return TRUE;
}

static ni_bool_t
__ni_suse_addrconf_auto6(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_sysconfig_t *merged;

	if (!dev || !dev->ipv6 || ni_tristate_is_disabled(dev->ipv6->conf.enabled))
		goto ignored;

	switch (dev->link.type) {
	case NI_IFTYPE_LOOPBACK:
	case NI_IFTYPE_DUMMY:
	case NI_IFTYPE_PPP:
	case NI_IFTYPE_TUN:
	case NI_IFTYPE_SIT:
	case NI_IFTYPE_ISDN:
	case NI_IFTYPE_IPIP:
	case NI_IFTYPE_TUNNEL6:
	case NI_IFTYPE_SLIP:
	case NI_IFTYPE_CTCM:
	case NI_IFTYPE_IUCV:
	case NI_IFTYPE_OVS_SYSTEM:
		goto ignored;
	default:
		break;
	}

	if (compat->auto6.enabled)
		return TRUE;

	if (ni_tristate_is_enabled(dev->ipv6->conf.forwarding)) {
		if (dev->ipv6->conf.accept_ra <= NI_IPV6_ACCEPT_RA_HOST)
			goto ignored;
	} else {
		if (dev->ipv6->conf.accept_ra == NI_IPV6_ACCEPT_RA_DISABLED)
			goto ignored;
	}

	compat->auto6.enabled = TRUE;
	compat->auto6.defer_timeout = 0; /* use a built-in timeout by default */
	if ((merged = ni_sysconfig_merge_defaults(sc, __ni_suse_config_defaults))) {
		const char *value;

		ni_sysconfig_get_integer(merged, "AUTO6_WAIT_AT_BOOT",
					&compat->auto6.defer_timeout);

		if ((value = ni_sysconfig_get_value(merged, "AUTO6_UPDATE"))) {
			unsigned int temp = compat->auto6.update;
			if (ni_addrconf_update_flags_parse(&temp, value, " \t,")) {
				temp &= ni_config_addrconf_update_mask(NI_ADDRCONF_AUTOCONF, AF_INET6);
				compat->auto6.update = temp;
			} else {
				ni_warn("ifcfg-%s: unknown flags in AUTO6_UPDATE='%s'",
					dev->name, ni_print_suspect(value, ni_string_len(value)));
			}
		}
		ni_sysconfig_free(merged);
	}
	return TRUE;

ignored:
	ni_warn("ifcfg-%s: BOOTPROTO auto6 not enabled due to (sysctl) constraints", dev->name);
	return FALSE;
}


static ni_bool_t
ni_suse_ifcfg_parse_bootproto(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_compat_netdev_t *compat = ifcfg->compat;
	ni_netdev_t *dev = compat->dev;
	ni_bool_t primary;
	const char *bootproto;
	const char *value;
	char *bp, *s, *p;
	ni_ipv4_devinfo_t *ipv4;
	ni_ipv6_devinfo_t *ipv6;

	/*
	 * The L3 setup & boot protocols are disabled on L2 ports already.
	 */
	if (ifcfg->l2only)
		return TRUE;

	/*
	 * The BOOTPROTO=none disables the L3 (IP) setup & boot protocols.
	 */
	bootproto = ni_sysconfig_get_value(sc, "BOOTPROTO");
	if (ni_string_eq_nocase(bootproto, "none")) {
		ni_suse_ifcfg_set_l2_only(ifcfg, FALSE);
		return TRUE;
	}

	if (ni_string_empty(bootproto) || ni_string_eq(dev->name, "lo")) {
		if (dev->link.type == NI_IFTYPE_PPP)
			bootproto = "ppp";
		else
			bootproto = "static";
	}

	ipv4 = ni_netdev_get_ipv4(dev);
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

	ipv6 = ni_netdev_get_ipv6(dev);
	if (ipv6 && dev->link.type == NI_IFTYPE_PPP && dev->ppp && !ipv6->conf.enabled)
		dev->ppp->config.ipv6.enabled = FALSE;

	if (ni_string_eq_nocase(bootproto, "ppp"))
		return TRUE;

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
		else if (ni_string_eq(s, "auto4") ||
			 ni_string_eq(s, "autoip")) {
			/* dhcp4 requested or required if primary  */
			__ni_suse_addrconf_auto4(sc, compat, primary);
		}
		else if (ni_string_eq(s, "auto6")) {
			__ni_suse_addrconf_auto6(sc, compat);
		}
		else {
			ni_error("ifcfg-%s: Unknown value in BOOTPROTO=\"%s\"",
					dev->name, bootproto);
		}
		primary = FALSE;
	}
	ni_string_free(&bp);

	/* static is always included in the "+" variants */
	__ni_suse_addrconf_static(sc, compat);

	return TRUE;
}

typedef struct ni_ifscript_type ni_ifscript_type_t;
struct ni_ifscript_type {
	const char *	type;
	struct {
		char *	(*qualify)(const char *, const char *, const char *, char **);
	} ops;
};

static char *	ni_ifscript_qualify_wicked     (const char *, const char *, const char *, char **);
static char *	ni_ifscript_qualify_compat     (const char *, const char *, const char *, char **);
static char *	ni_ifscript_qualify_compat_suse(const char *, const char *, const char *, char **);
static char *	ni_ifscript_qualify_systemd    (const char *, const char *, const char *, char **);

static const ni_ifscript_type_t		ni_ifscript_types[] = {
	{ "wicked",	{ .qualify = ni_ifscript_qualify_wicked		} },
	{ "compat",	{ .qualify = ni_ifscript_qualify_compat		} },
	{ "systemd",	{ .qualify = ni_ifscript_qualify_systemd	} },
	{ NULL,		{ .qualify = NULL				} },
};

static const ni_ifscript_type_t		ni_ifscript_types_compat[] = {
	{ "suse",	{ .qualify = ni_ifscript_qualify_compat_suse	} },
	{ NULL,		{ .qualify = NULL				} },
};

static const ni_ifscript_type_t *
ni_ifscript_find_map(const ni_ifscript_type_t *map, const char *type, size_t len)
{
	const ni_ifscript_type_t *pos = map;

	if (pos) {
		while (pos->type) {
			if (type && strlen(pos->type) == len &&
			    strncasecmp(pos->type, type, len) == 0)
				break;
			++pos;
		}
	}
	return pos;
}

static char *
ni_ifscript_qualify_systemd(const char *type, const char *path, const char *hint, char **err)
{
	char *ret = NULL;

	(void)err;
	(void)hint;
	if (strchr(path, ':'))
		return NULL;

	/* any other checks? */
	ni_string_printf(&ret, "%s:%s", type, path);
	return ret;
}

static char *
ni_ifscript_qualify_wicked(const char *type, const char *path, const char *hint, char **err)
{
	char *ret = NULL;

	(void)err;
	(void)hint;
	if (strchr(path, ':'))
		return NULL;

	/* any other checks? */
	ni_string_printf(&ret, "%s:%s", type, path);
	return ret;
}

static char *
ni_ifscript_qualify_compat_suse(const char *type, const char *path, const char *hint, char **err)
{
	char *ret = NULL;

	(void)err;
	(void)hint;
	if (strchr(path, ':'))
		return NULL;

	/* any other checks? */
	ni_string_printf(&ret, "%s:%s", type, path);
	return ret;
}

static char *
ni_ifscript_qualify_compat(const char *type, const char *path, const char *hint, char **err)
{
	const ni_ifscript_type_t *map;
	const char *_path = path;
	const char *_type = NULL;
	size_t len;

	len = strcspn(path, ":");
	if (path[len] == ':') {
		_type = len ? path : NULL;
		_path = path + len + 1;
		hint = NULL;
	} else if (hint) {
		len = strcspn(hint, ":");
		_type = hint;
		if (hint[len] == ':')
			hint += len + 1;
		else
			hint = NULL;
	}

	map = ni_ifscript_find_map(ni_ifscript_types_compat, _type, len);
	if (map && map->type && map->ops.qualify) {
		char *ret, *temp = NULL;

		ni_string_printf(&temp, "%s:%s", type, map->type);
		ret = map->ops.qualify(temp, _path, hint, err);
		ni_string_free(&temp);
		if (ret)
			return ret;

		ni_string_printf(err, "failed to qualify '%s:%s:%s'", type, map->type, _path);
	} else {
		ni_string_printf(err, "unsupported script type '%s:%s'", type, path);
	}
	return NULL;
}

static char *
ni_ifscript_qualify(const char *path, const char *hint, char **err)
{
	const ni_ifscript_type_t *map;
	const char *_path = path;
	const char *_type = NULL;
	size_t len;

	len = strcspn(path, ":");
	if (path[len] == ':') {
		_type = len ? path : NULL;
		_path = path + len + 1;
		hint = NULL;
	} else if (hint) {
		len = strcspn(hint, ":");
		_type = hint;
		if (hint[len] == ':')
			hint += len + 1;
		else
			hint = NULL;
	}

	map = ni_ifscript_find_map(ni_ifscript_types, _type, len);
	if (map && map->type && map->ops.qualify)
		return map->ops.qualify(map->type, _path, hint, err);

	ni_string_printf(err, "%s script type '%.*s:%s'", len ? "unknown" : "missing",
							(int)len, _type, _path);
	return NULL;
}

static void
__ni_suse_qualify_scripts(ni_compat_netdev_t *compat, const char *set, const char *value)
{
	ni_string_array_t scripts = NI_STRING_ARRAY_INIT;
	ni_string_array_t qualified = NI_STRING_ARRAY_INIT;
	char *list = NULL;
	char *err = NULL;
	unsigned int i;

	ni_string_split(&scripts, value, " \t",  0);
	for (i = 0;  i < scripts.count; ++i) {
		char *script = NULL;

		script = ni_ifscript_qualify(scripts.data[i], __NI_SUSE_SCRIPT_DEFAULT_SCHEME, &err);
		if (script) {
			if (ni_string_array_index(&qualified, script) == -1)
				ni_string_array_append(&qualified, script);
			ni_string_free(&script);
		} else if (!ni_string_empty(err)) {
			ni_note("ifcfg-%s: unable to qualify %s script - %s",
				compat->dev->name, set, err);
		} else {
			ni_note("ifcfg-%s: unable to qualify %s script '%s'",
				compat->dev->name, set, scripts.data[i]);
		}
	}
	ni_string_array_destroy(&scripts);
	ni_string_free(&err);

	if (ni_string_join(&list, &qualified, " ")) {
		ni_var_array_set(&compat->scripts, set, list);
		ni_string_free(&list);
	}
	ni_string_array_destroy(&qualified);
}

static ni_bool_t
ni_suse_ifcfg_parse_scripts(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_compat_netdev_t *compat = ifcfg->compat;
	const char *value;

	value = ni_sysconfig_get_value(sc, "PRE_UP_SCRIPT");
	if (!value && __ni_suse_config_defaults)
		value = ni_sysconfig_get_value(__ni_suse_config_defaults, "PRE_UP_SCRIPT");
	__ni_suse_qualify_scripts(compat, "pre-up", value);

	value = ni_sysconfig_get_value(sc, "POST_UP_SCRIPT");
	if (!value && __ni_suse_config_defaults)
		value = ni_sysconfig_get_value(__ni_suse_config_defaults, "POST_UP_SCRIPT");
	__ni_suse_qualify_scripts(compat, "post-up", value);

	value = ni_sysconfig_get_value(sc, "PRE_DOWN_SCRIPT");
	if (!value && __ni_suse_config_defaults)
		value = ni_sysconfig_get_value(__ni_suse_config_defaults, "PRE_DOWN_SCRIPT");
	__ni_suse_qualify_scripts(compat, "pre-down", value);

	value = ni_sysconfig_get_value(sc, "POST_DOWN_SCRIPT");
	if (!value && __ni_suse_config_defaults)
		value = ni_sysconfig_get_value(__ni_suse_config_defaults, "POST_DOWN_SCRIPT");
	__ni_suse_qualify_scripts(compat, "post-down", value);

	return TRUE;
}

static ni_bool_t
ni_suse_ifcfg_parse_firewall(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_compat_netdev_t *compat = ifcfg->compat;
	ni_sysconfig_t *merged;
	const char *value;

	if ((merged = ni_sysconfig_merge_defaults(sc, __ni_suse_config_defaults))) {

		ni_sysconfig_get_boolean(merged, "FIREWALL", &compat->firewall.enabled);
		if (compat->firewall.enabled) {
			value = ni_sysconfig_get_value(sc, "ZONE");
			if (!ni_string_empty(value))
				ni_string_dup(&compat->firewall.zone, value);
		}
		ni_sysconfig_free(merged);
	}
	return TRUE;
}

/*
 * Read ifsysctl file
 */
static const ni_var_t *
__ifsysctl_get_var(ni_var_array_t *vars, const char *path, const char *ifname, const char *attr)
{
	const char *def_names[] = { "all", "default", ifname, NULL };
	const char *lo_names[] = { ifname, NULL };
	const char **names = ni_string_eq(ifname, "lo") ? lo_names : def_names;
	const char **name;
	const ni_var_t *ret = NULL;
	const ni_var_t *var;

	for (name = names; *name; name++) {
		var = ni_ifsysctl_vars_get(vars, "%s/%s/%s", path, *name, attr);
		if (!var || ni_string_empty(var->value))
			continue;
		ret = var;
	}
	return ret;
}

static const char *
__ifsysctl_get_str(ni_var_array_t *vars, const char *path, const char *ifname, const char *attr)
{
	const ni_var_t *var;

	if ((var = __ifsysctl_get_var(vars, path, ifname, attr)))
		return var->value;
	return NULL;
}

static ni_bool_t
__ifsysctl_get_int(ni_var_array_t *vars, const char *path, const char *ifname,
					const char *attr, int *value, int base)
{
	const ni_var_t *var;

	if (!(var = __ifsysctl_get_var(vars, path, ifname, attr)))
		return FALSE;

	if (ni_parse_int(var->value, value, base) < 0) {
		ni_debug_readwrite("Can't parse sysctl '%s'='%s' as integer",
				var->name, var->value);
		return FALSE;
	} else {
		ni_debug_verbose(NI_LOG_DEBUG2, NI_TRACE_READWRITE,
				"Parsed sysctl '%s'='%s'", var->name, var->value);
		return TRUE;
	}
}

static ni_bool_t
__ifsysctl_get_ipv6(ni_var_array_t *vars, const char *path, const char *ifname,
					const char *attr, struct in6_addr *ipv6)
{
	ni_sockaddr_t addr;
	const char *str;

	str = __ifsysctl_get_str(vars, path, ifname, attr);
	if (!str || ni_sockaddr_parse(&addr, str, AF_INET6) < 0)
		return FALSE;

	*ipv6 = addr.six.sin6_addr;
	return TRUE;
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
ni_suse_ifcfg_parse_ifsysctl_ipv4(ni_suse_ifcfg_t *ifcfg, ni_var_array_t *ifsysctl)
{
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_ipv4_devinfo_t *ipv4;

	/*
	 * On L2 ports, we've disabled L3 / IPv4 already.
	 */
	if (ifcfg->l2only)
		return TRUE;

	if (!(ipv4 = ni_netdev_get_ipv4(dev)))
		return FALSE;

	/* Note: no conf.enable and conf.arp-verify in sysctl */

	__ifsysctl_get_tristate(ifsysctl, "net/ipv4/conf", dev->name,
			"forwarding", &ipv4->conf.forwarding);
	__ifsysctl_get_tristate(ifsysctl, "net/ipv4/conf", dev->name,
			"arp_notify", &ipv4->conf.arp_notify);
	__ifsysctl_get_tristate(ifsysctl, "net/ipv4/conf", dev->name,
			"accept_redirects", &ipv4->conf.accept_redirects);

	return TRUE;
}

static ni_bool_t
ni_suse_ifcfg_parse_ifsysctl_ipv6(ni_suse_ifcfg_t *ifcfg, ni_var_array_t *ifsysctl)
{
	ni_tristate_t disable_ipv6 = NI_TRISTATE_DEFAULT;
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_ipv6_devinfo_t *ipv6;

	if (!(ipv6 = ni_netdev_get_ipv6(dev)))
		return FALSE;

	/*
	 * First, get sysctl's affecting also "IPv6 L2" aka
	 * stable secret for the fe80 link-address assignment.
	 */
	__ifsysctl_get_int(ifsysctl, "net/ipv6/conf", dev->name,
			"addr_gen_mode", &ipv6->conf.addr_gen_mode, 10);

	__ifsysctl_get_ipv6(ifsysctl, "net/ipv6/conf", dev->name,
			"stable_secret", &ipv6->conf.stable_secret);

	/*
	 * On L2 ports, we may need the ipv6 link e.g. for nsna
	 * ping monitoring, but already disabled e.g accept_ra
	 * to avoid RA processing affecting the IPv6 L3 autoconf
	 * aka auto6 (SLAAC) & dhcp6 and don't parse static IPs.
	 */
	if (ifcfg->l2only)
		return TRUE;

	/*
	 * When IPv6 is disabled via kernel cmdline, we're done
	 * TODO: it's wrong to mix kernel cmdline overrides into
	 * config parsing and we've to remove this and handle
	 * later at runtime while applying the config.
	 */
	if (__ni_ipv6_disbled) {
		ni_tristate_set(&ipv6->conf.enabled, FALSE);
		return TRUE;
	}

	/*
	 * When IPv6 is disabled via sysctl, we're done
	 */
	__ifsysctl_get_tristate(ifsysctl, "net/ipv6/conf", dev->name,
			"disable_ipv6", &disable_ipv6);
	if (ni_tristate_is_set(disable_ipv6))
		ni_tristate_set(&ipv6->conf.enabled, !disable_ipv6);
	if (ni_tristate_is_disabled(ipv6->conf.enabled))
		return TRUE;

	__ifsysctl_get_tristate(ifsysctl, "net/ipv6/conf", dev->name,
			"forwarding", &ipv6->conf.forwarding);

	__ifsysctl_get_int(ifsysctl, "net/ipv6/conf", dev->name,
			"accept_ra", &ipv6->conf.accept_ra, 10);
	if (ipv6->conf.accept_ra > NI_IPV6_ACCEPT_RA_ROUTER)
		ipv6->conf.accept_ra = NI_IPV6_ACCEPT_RA_ROUTER;
	else
	if (ipv6->conf.accept_ra < NI_IPV6_ACCEPT_RA_DEFAULT)
		ipv6->conf.accept_ra = NI_IPV6_ACCEPT_RA_DEFAULT;

	__ifsysctl_get_int(ifsysctl, "net/ipv6/conf", dev->name,
			"accept_dad", &ipv6->conf.accept_dad, 10);
	if (ipv6->conf.accept_dad > NI_IPV6_ACCEPT_DAD_FAIL_PROTOCOL)
		ipv6->conf.accept_dad = NI_IPV6_ACCEPT_DAD_FAIL_PROTOCOL;
	else
	if (ipv6->conf.accept_dad < NI_IPV6_ACCEPT_DAD_DEFAULT)
		ipv6->conf.accept_dad = NI_IPV6_ACCEPT_DAD_DEFAULT;

	__ifsysctl_get_tristate(ifsysctl, "net/ipv6/conf", dev->name,
				"autoconf", &ipv6->conf.autoconf);

	__ifsysctl_get_int(ifsysctl, "net/ipv6/conf", dev->name,
				"use_tempaddr", &ipv6->conf.privacy, 10);
	if (ipv6->conf.privacy > NI_IPV6_PRIVACY_PREFER_TEMPORARY)
		ipv6->conf.privacy = NI_IPV6_PRIVACY_PREFER_TEMPORARY;
	else if (ipv6->conf.privacy < NI_IPV6_PRIVACY_DEFAULT)
		ipv6->conf.privacy = NI_IPV6_PRIVACY_DISABLED;

	__ifsysctl_get_tristate(ifsysctl, "net/ipv6/conf", dev->name,
			"accept_redirects", &ipv6->conf.accept_redirects);

	return TRUE;
}

static ni_bool_t
ni_suse_ifcfg_parse_ifsysctl(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	ni_var_array_t ifsysctl = NI_VAR_ARRAY_INIT;
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;
	char pathbuf[PATH_MAX];
	const char *dirname;

	dirname = ni_dirname(sc->pathname);
	if (ni_string_empty(dirname))
		return FALSE;

	ni_var_array_copy(&ifsysctl, &__ni_suse_global_ifsysctl);
	snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s", dirname,
			__NI_SUSE_IFSYSCTL_FILE, dev->name);
	if (ni_isreg(pathbuf)) {
		ni_ifsysctl_file_load(&ifsysctl, pathbuf);
	}

	ni_suse_ifcfg_parse_ifsysctl_ipv4(ifcfg, &ifsysctl);
	ni_suse_ifcfg_parse_ifsysctl_ipv6(ifcfg, &ifsysctl);
	ni_var_array_destroy(&ifsysctl);
	return TRUE;
}

static ni_bool_t
ni_suse_ifcfg_parse_linkinfo(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	const ni_sysconfig_t *sc = ifcfg->config;
	ni_netdev_t *dev = ifcfg->compat->dev;

	ni_sysconfig_get_integer(sc, "MTU", &dev->link.mtu);

	return TRUE;
}

static inline ni_bool_t
ni_suse_ifcfg_parse_control(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	if (!(ifcfg->compat->control = ni_suse_ifcfg_parse_startmode(ifcfg->config)))
		return FALSE;

	return TRUE;
}

static inline ni_bool_t
ni_suse_ifcfg_parse_iftypes(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg)
{
	if (try_loopback(ifcfgs, ifcfg)   < 0 ||
	    try_ovs_system(ifcfgs, ifcfg) < 0 ||
	    try_ovs_bridge(ifcfgs, ifcfg) < 0 ||
	    try_bonding(ifcfgs, ifcfg)    < 0 ||
	    try_team(ifcfgs, ifcfg)       < 0 ||
	    try_bridge(ifcfgs, ifcfg)     < 0 ||
	    try_vlan(ifcfgs, ifcfg)       < 0 ||
	    try_vxlan(ifcfgs, ifcfg)      < 0 ||
	    try_macvlan(ifcfgs, ifcfg)    < 0 ||
	    try_tunnel(ifcfgs, ifcfg)     < 0 ||
	    try_ppp(ifcfgs, ifcfg)        < 0 ||
	    try_wireless(ifcfgs, ifcfg)   < 0 ||
	    try_infiniband(ifcfgs, ifcfg) < 0 ||
	    try_dummy(ifcfgs, ifcfg)      < 0 ||
	    /* keep ethernet the last one */
	    try_ethernet(ifcfgs, ifcfg)   < 0)
		return FALSE;

	return TRUE;
}

static ni_bool_t
ni_suse_ifcfg_parse_foreach(ni_suse_ifcfg_array_t *ifcfgs,
		ni_bool_t (*parse)(ni_suse_ifcfg_array_t *, ni_suse_ifcfg_t *))
{
	ni_suse_ifcfg_t *ifcfg;
	unsigned int i;

	if (!ifcfgs || !parse)
		return FALSE;

	for (i = 0; i < ifcfgs->count; ++i) {
		ifcfg = ifcfgs->data[i];
		if (ifcfg->broken)
			continue;

		if (!parse(ifcfgs, ifcfg))
			ifcfg->broken = TRUE;
	}
	return TRUE;
}

static ni_bool_t
ni_suse_ifcfg_parse(ni_suse_ifcfg_array_t *ifcfgs)
{
	if (!ni_suse_ifcfg_parse_foreach(ifcfgs, ni_suse_ifcfg_parse_control)   ||
	    !ni_suse_ifcfg_parse_foreach(ifcfgs, ni_suse_ifcfg_parse_iftypes)   ||
	    !ni_suse_ifcfg_parse_foreach(ifcfgs, ni_suse_ifcfg_parse_linkinfo)  ||
	    !ni_suse_ifcfg_parse_foreach(ifcfgs, ni_suse_ifcfg_parse_ifsysctl)  ||
	    !ni_suse_ifcfg_parse_foreach(ifcfgs, ni_suse_ifcfg_parse_ethtool)	||
	    !ni_suse_ifcfg_parse_foreach(ifcfgs, ni_suse_ifcfg_parse_firewall)  ||
	    !ni_suse_ifcfg_parse_foreach(ifcfgs, ni_suse_ifcfg_parse_scripts)   ||
	    !ni_suse_ifcfg_parse_foreach(ifcfgs, ni_suse_ifcfg_parse_bootproto))
		return FALSE;

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


static ni_suse_ifcfg_t *
ni_suse_ifcfg_new(void)
{
	ni_suse_ifcfg_t *ifcfg;

	ifcfg = calloc(1, sizeof(*ifcfg));
	return ifcfg;
}

static void
ni_suse_ifcfg_free(ni_suse_ifcfg_t *ifcfg)
{
	if (ifcfg) {
		if (ifcfg->config) {
			ni_sysconfig_free(ifcfg->config);
			ifcfg->config = NULL;
		}
		if (ifcfg->compat) {
			ni_compat_netdev_free(ifcfg->compat);
			ifcfg->compat = NULL;
		}
		free(ifcfg);
	}
}

static ni_suse_ifcfg_t *
ni_suse_ifcfg_new_missing(ni_suse_ifcfg_t *from, const char *ifname)
{
	ni_suse_ifcfg_t *ifcfg;

	if (!from || !from->config || !ifname)
		return NULL;

	if (!(ifcfg = ni_suse_ifcfg_new()))
		goto error;

	if (!(ifcfg->config = ni_sysconfig_new(from->config->pathname)))
		goto error;

	if (!(ifcfg->compat = ni_compat_netdev_new(ifname)))
		goto error;

	return ifcfg;

error:
	ni_suse_ifcfg_free(ifcfg);
	return NULL;
}

static void
ni_suse_ifcfg_set_hotplug(ni_suse_ifcfg_t *ifcfg)
{
	static const ni_ifworker_control_t control = {
		"hotplug", NULL, FALSE, FALSE, NI_TRISTATE_DEFAULT, 0, 0
	};

	if (ifcfg->compat->control)
		ni_ifworker_control_free(ifcfg->compat->control);

	/* apply STARTMODE=hotplug (missing Ok) control defaults */
	ifcfg->compat->control = ni_ifworker_control_clone(&control);
}

static void
ni_suse_ifcfg_set_l2_only(ni_suse_ifcfg_t *ifcfg, ni_bool_t l2v6)
{
	ni_ipv4_devinfo_t *ipv4;
	ni_ipv6_devinfo_t *ipv6;

	/* apply BOOTPROTO=none (no L3) defaults in L2 enslave;
	 * link monitoring may need ipv6 (link layer address) */
	if ((ipv4 = ni_netdev_get_ipv4(ifcfg->compat->dev)))
		ni_tristate_set(&ipv4->conf.enabled, FALSE);
	if ((ipv6 = ni_netdev_get_ipv6(ifcfg->compat->dev))) {
		/* ipv6 link only without RA for L3 setup */
		ni_tristate_set(&ipv6->conf.enabled, l2v6);
		ni_tristate_set(&ipv6->conf.accept_ra, 0);
	}
	ifcfg->l2only = TRUE;
}

static ni_bool_t
ni_suse_ifcfg_netdev_set_master(ni_netdev_t *pdev, ni_netdev_t *mdev,
		const char *type, const char *file)
{
	if (ni_string_empty(pdev->link.masterdev.name))
		return ni_netdev_ref_set_ifname(&pdev->link.masterdev, mdev->name);

	if (ni_string_eq(pdev->link.masterdev.name, mdev->name)) {
		ni_warn("ifcfg-%s: ignoring duplicate '%s' %s port '%s'",
				file, mdev->name, type, pdev->name);
		return TRUE;
	}

	/*
	 * The ifcfg device hierarchy _is_ broken.
	 *
	 * As we cannot judge which config is correct and which not,
	 * we keep the already assigned interface intact and let
	 * further layers decide how to handle this condition.
	 */
	ni_error("ifcfg-%s: cannot add %s port '%s' to '%s', already in '%s'",
			file, type, pdev->name, mdev->name,
			pdev->link.masterdev.name);
	return FALSE;
}

static ni_suse_ifcfg_t *
ni_suse_ifcfg_add_l2_port(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *mcfg,
		const char *file, const char *type, const char *port, ni_bool_t l2v6)
{
	ni_suse_ifcfg_t *pcfg;
	ni_netdev_t *mdev;

	mdev = mcfg->compat->dev;
	if (!ni_netdev_name_is_valid(port) || ni_string_eq(mdev->name, port)) {
		ni_error("ifcfg-%s: rejecting invalid '%s' %s port name '%s'",
				mdev->name, file, type, port);
		return NULL;
	}

	if (!(pcfg = ni_suse_ifcfg_find_by_ifname(ifcfgs, port))) {
		pcfg = ni_suse_ifcfg_new_missing(mcfg, port);
		if (!ni_suse_ifcfg_array_append(ifcfgs, pcfg)) {
			ni_suse_ifcfg_free(pcfg);
			ni_error("ifcfg-%s: failed to add %s port '%s' to '%s'",
					file, type, port, mdev->name);
			return NULL;
		}
		ni_suse_ifcfg_set_hotplug(pcfg);
	}
	ni_suse_ifcfg_set_l2_only(pcfg, l2v6);

	if (ni_suse_ifcfg_netdev_set_master(pcfg->compat->dev, mdev, type, file))
		return pcfg;

	pcfg->broken = TRUE;
	return NULL;
}

static ni_suse_ifcfg_t *
ni_suse_ifcfg_add_lower(ni_suse_ifcfg_array_t *ifcfgs, ni_suse_ifcfg_t *ifcfg,
		const char *lower, const char *info)
{
	ni_netdev_t *dev = ifcfg->compat->dev;
	ni_suse_ifcfg_t *cfg;

	if (!ni_netdev_name_is_valid(lower) || ni_string_eq(dev->name, lower)) {
		ni_error("ifcfg-%s: rejecting invalid %s '%s' of '%s'",
				dev->name, info ?: "lower interface",
				lower, dev->name);
		return NULL;
	}

	if (!(cfg = ni_suse_ifcfg_find_by_ifname(ifcfgs, lower))) {
		cfg = ni_suse_ifcfg_new_missing(ifcfg, lower);
		if (!ni_suse_ifcfg_array_append(ifcfgs, cfg)) {
			ni_suse_ifcfg_free(cfg);
			ni_error("ifcfg-%s: failed to add missing %s '%s' for '%s",
					dev->name, info ?: "lower interface",
					lower, dev->name);
			return NULL;
		}
		ni_warn("ifcfg-%s: generated missing %s '%s' config for '%s'",
			dev->name, info ?: "lower interface",
			lower, dev->name);

		/* Inherit from depending somehow? */
		ni_suse_ifcfg_set_hotplug(cfg);
	}
	return cfg;
}

static ni_suse_ifcfg_t *
ni_suse_ifcfg_find_by_ifname(ni_suse_ifcfg_array_t *ifcfgs, const char *ifname)
{
	ni_suse_ifcfg_t *ifcfg;
	ni_netdev_t *dev;
	unsigned int i;

	if (!ifcfgs || !ifname)
		return NULL;

	for (i = 0; i < ifcfgs->count; ++i) {
		ifcfg = ifcfgs->data[i];
		dev = ifcfg->compat->dev;

		if (ni_string_eq(dev->name, ifname))
			return ifcfg;
	}
	return NULL;
}

static unsigned int
ni_suse_ifcfg_process_indexed(ni_suse_ifcfg_array_t *ifcfgs,
		ni_suse_ifcfg_t *ifcfg, const char *prefix,
		ifcfg_process_fn_t process)
{
	const ni_var_t *var;
	unsigned int cnt, i;
	size_t pfxlen;

	if (!ifcfgs || !ifcfg || !ifcfg->config || !process)
		return 0;

	pfxlen = ni_string_len(prefix);
	for (cnt = 0, i = 0; i < ifcfg->config->vars.count; ++i) {
		var = &ifcfg->config->vars.data[i];

		if (!var->value || strncmp(var->name, prefix, pfxlen))
			continue;

		if (process(ifcfgs, ifcfg, var->value, var->name, var->name + pfxlen))
			cnt++;
	}
	return cnt;
}

static ni_define_ptr_array_init(ni_suse_ifcfg);
static ni_define_ptr_array_destroy(ni_suse_ifcfg);
static ni_define_ptr_array_realloc(ni_suse_ifcfg, NI_SUSE_IFCFG_ARRAY_CHUNK);
static ni_define_ptr_array_append(ni_suse_ifcfg);
