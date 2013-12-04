/*
 * Compat functions for SUSE ifcfg style files
 * This support is not complete yet.
 *
 * Copyright (C) 2010-2012 Olaf Kirch <okir@suse.de>
 * Copyright (C) 2013 Marius Tomaschewski <mt@suse.de>
 */

#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netlink/netlink.h>

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
#include <wicked/wireless.h>
#include <wicked/fsm.h>

#include <wicked/objectmodel.h>
#include <wicked/dbus.h>
#include "wicked-client.h"
#include "util_priv.h"

typedef ni_bool_t (*try_function_t)(const ni_sysconfig_t *, ni_netdev_t *, const char *);

static ni_compat_netdev_t *	__ni_suse_read_interface(const char *, const char *);
static ni_bool_t		__ni_suse_read_globals(const char *path);
static void			__ni_suse_free_globals(void);
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

static char *			__ni_suse_default_hostname;
static ni_sysconfig_t *		__ni_suse_config_defaults;
static ni_sysconfig_t *		__ni_suse_dhcp_defaults;
static ni_route_table_t *	__ni_suse_global_routes;


#define __NI_SUSE_SYSCONFIG_NETWORK_DIR		"/etc/sysconfig/network"
#define __NI_SUSE_HOSTNAME_FILE			"/etc/HOSTNAME"
#define __NI_SUSE_CONFIG_IFPREFIX		"ifcfg-"
#define __NI_SUSE_CONFIG_GLOBAL			"config"
#define __NI_SUSE_CONFIG_DHCP			"dhcp"
#define __NI_SUSE_ROUTES_IFPREFIX		"ifroute-"
#define __NI_SUSE_ROUTES_GLOBAL			"routes"

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
__ni_suse_valid_ifname(const char *ifname)
{
	size_t i, len = ni_string_len(ifname);

	if (!len || len >= IFNAMSIZ)
		return FALSE;

	if (!isalnum((unsigned char)ifname[0]))
		return FALSE;

	for(i = 1; i < len; ++i) {
		if(isalnum((unsigned char)ifname[i]) ||
			ifname[i] == '-' ||
			ifname[i] == '_' ||
			ifname[i] == '.')
			continue;
		return FALSE;
	}
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
__ni_suse_get_interfaces(const char *root, const char *path, ni_compat_netdev_array_t *result)
{
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	ni_bool_t success = FALSE;
	char *pathname = NULL;
	unsigned int i;

	if (ni_string_empty(path))
		path = __NI_SUSE_SYSCONFIG_NETWORK_DIR;

	if (ni_string_empty(root))
		ni_string_dup(&pathname, path);
	else
		ni_string_printf(&pathname, "%s%s", root, path);

	if (ni_isdir(pathname)) {
		if (!__ni_suse_read_globals(pathname))
			goto done;

		if (!__ni_suse_ifcfg_scan_files(pathname, &files)) {
			ni_error("No ifcfg files found in %s", pathname);
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
				goto done;

			ni_compat_netdev_client_info_set(compat->dev, pathbuf);
			ni_compat_netdev_array_append(result, compat);
		}
	} else
	if (ni_file_exists(pathname)) {
		ni_compat_netdev_t *compat;

		if (!__ni_suse_read_globals(ni_dirname(pathname)))
			goto done;

		if (!(compat = __ni_suse_read_interface(pathname, NULL)))
			goto done;

		ni_compat_netdev_client_info_set(compat->dev, pathname);
		ni_compat_netdev_array_append(result, compat);
	}
	else
		goto done;

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
__ni_suse_read_default_hostname(char **hostname)
{
	char buff[256];
	FILE *input;

	if (!hostname)
		return NULL;
	ni_string_free(hostname);

	input = ni_file_open(__NI_SUSE_HOSTNAME_FILE, "r", 0600);
	if (!input)
		return NULL;

	if (fgets(buff, sizeof(buff)-1, input)) {
		buff[strcspn(buff, " \t\r\n")] = '\0';

		if (ni_check_domain_name(buff, strlen(buff), 0))
			ni_string_dup(hostname, buff);
	}
	fclose(input);

	return *hostname;
}


/*
 * Read global ifconfig files like config, dhcp and routes
 */
static ni_bool_t
__ni_suse_read_globals(const char *path)
{
	char pathbuf[PATH_MAX];

	if (path == NULL) {
		ni_error("%s: path is NULL", __func__);
		return FALSE;
	}

	__ni_suse_free_globals();

	__ni_suse_read_default_hostname(&__ni_suse_default_hostname);

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, __NI_SUSE_CONFIG_GLOBAL);
	if (ni_file_exists(pathbuf)) {
		__ni_suse_config_defaults = ni_sysconfig_read(pathbuf);
		if (__ni_suse_config_defaults == NULL) {
			ni_error("unable to parse %s", pathbuf);
			return FALSE;
		}
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, __NI_SUSE_CONFIG_DHCP);
	if (ni_file_exists(pathbuf)) {
		__ni_suse_dhcp_defaults = ni_sysconfig_read(pathbuf);
		if (__ni_suse_dhcp_defaults == NULL) {
			ni_error("unable to parse %s", pathbuf);
			return FALSE;
		}
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, __NI_SUSE_ROUTES_GLOBAL);
	if (ni_file_exists(pathbuf)) {
		if (!__ni_suse_read_routes(&__ni_suse_global_routes, pathbuf, NULL))
			return FALSE;
	}

	return TRUE;
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

		if (ifname == NULL)
			ifname = name;

		/*
		 * ifname is set while reading per-interface routes;
		 * do not allow another interfaces in the name field.
		 */
		if (ifname && name && !ni_string_eq(ifname, name)) {
			ni_error("%s[%u]: Invalid (foreign) interface name \"%s\"",
				filename, line, name);
			return -1;
		}

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
		if (rp->nh.gateway.ss_family != AF_UNSPEC ||
		    rp->nh.device.name || rp->nh.next) {
			ni_error("%s[%u]: Route type does not have a device or gateway",
				filename, line);
			goto failure;
		}
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
			ni_debug_readwrite("Parsing route line: %s", buff.string);
			if (__ni_suse_route_parse(routes, buff.string,
						  ifname, filename, line) < 0)
				goto error; /* ? */
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

	if (!__ni_suse_valid_ifname(ifname)) {
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

ni_compat_netdev_t *
ni_compat_netdev_new(const char *ifname)
{
	ni_compat_netdev_t *compat;

	compat = xcalloc(1, sizeof(*compat));
	compat->dev = ni_netdev_new(ifname, 0);

	/* Apply defaults */
	compat->dhcp6.mode = NI_DHCP6_MODE_AUTO;
	compat->dhcp6.rapid_commit = TRUE;

	return compat;
}

/*
 * Translate the SUSE startmodes to <control> element
 */
static const ni_ifworker_control_t *
__ni_suse_startmode(const char *mode)
{
	static const struct __ni_control_params {
		const char *		name;
		ni_ifworker_control_t	control;
	} __ni_suse_control_params[] = {
		/* manual is the default in ifcfg */
		{ "manual",	{ NULL,		NULL,		TRUE,	FALSE,	FALSE,	30	} },

		{ "auto",	{ "boot",	NULL,		FALSE,	TRUE,	FALSE,	30	} },
		{ "boot",	{ "boot",	NULL,		FALSE,	TRUE,	FALSE,	30	} },
		{ "onboot",	{ "boot",	NULL,		FALSE,	TRUE,	FALSE,	30	} },
		{ "on",		{ "boot",	NULL,		FALSE,	TRUE,	FALSE,	30	} },

		{ "hotplug",	{ "boot",	NULL,		FALSE,	FALSE,	FALSE,	30	} },
		{ "ifplugd",	{ "ignore",	NULL,		FALSE,	FALSE,	FALSE,	30	} },

		{ "nfsroot",	{ "boot",	"localfs",	TRUE,	TRUE,	TRUE,	NI_IFWORKER_INFINITE_TIMEOUT	} },
		{ "off",	{ "off",	NULL,		FALSE,	FALSE,	FALSE,	0	} },

		{ NULL }
	};
	const struct __ni_control_params *p, *params = NULL;

	if (mode != NULL) {
		for (p = __ni_suse_control_params; p->name; ++p) {
			if (ni_string_eq(p->name, mode)) {
				params = p;
				break;
			}
		}
	}

	if (!params)
		params = &__ni_suse_control_params[0];

	return &params->control;
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
		ni_string_set(&ib->parent.name, dev->name, pkey - dev->name);
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

	if ((err = ni_infiniband_validate(dev->link.type, ib))) {
		ni_error("ifcfg-%s: %s", dev->name, err);
		return -1;
	}

	return 0;
}

/*
 * Handle Ethernet devices
 */
static int
try_ethernet(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	ni_ethernet_t *eth;
	const char *value;

	/* FIXME: this is an array ETHTOOL_OPTIONS[SUFFIX] */
	if ((value = ni_sysconfig_get_value(sc, "ETHTOOL_OPTIONS")) != NULL) {
		/* ETHTOOL_OPTIONS comes in two flavors
		 *   - starting with a dash: this is "-$option ifname $stuff"
		 *   - otherwise: this is a paramater to be passed to "-s ifname"
		 */
		/* FIXME: parse and translate to xml */
		(void)value;
		(void)dev;
		(void)eth;
	}

	return 1; /* We do not set type to ethernet (yet) */
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

			if (!__ni_suse_valid_ifname(name)) {
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
	const char *vlantag = NULL;
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

	ni_string_dup(&dev->link.lowerdev.name, etherdev);
	vlan->tag = tag;

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

	/* Allocate new network object */
	net = ni_wireless_network_new();

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
		if (ni_parse_hex(var->value, net->access_point.data,
					sizeof(net->access_point.data)) == ETH_ALEN) {
			net->access_point.type = ARPHRD_ETHER;
			net->access_point.len = ETH_ALEN;
		}
		else {
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
try_tunnel(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	const char *value;
	static const ni_intmap_t __tunnel_types[] = {
		{ "tun",	NI_IFTYPE_TUN		},
		{ "tap",	NI_IFTYPE_TAP		},
		{ "sit",	NI_IFTYPE_SIT		},
		{ "gre",	NI_IFTYPE_GRE		},
		{ "ipip",	NI_IFTYPE_TUNNEL	},
		{ "ip6tnl",	NI_IFTYPE_TUNNEL6	},
		{ NULL,		NI_IFTYPE_UNKNOWN	},
	};
	const ni_intmap_t *map;

	/* FIXME: this are just the types... */
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
	ni_warn("ifcfg-%s: conversion of tunnel interfaces not yet supported",
		dev->name);

	return 0;
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
__get_ipaddr(const ni_sysconfig_t *sc, const char *suffix, ni_address_t **list)
{
	ni_var_t *var;
	ni_sockaddr_t local_addr;
	unsigned int prefixlen;
	ni_address_t *ap;

	var = __find_indexed_variable(sc, "IPADDR", suffix);
	if (!var || !var->value || !var->value[0])
		return TRUE;

	if (!ni_sockaddr_prefix_parse(var->value, &local_addr, &prefixlen)) {
cannot_parse:
		ni_error("Unable to parse %s=\"%s\"", var->name, var->value);
		return FALSE;
	}

	/* If the address wasn't in addr/prefix format, go look elsewhere */
	if (prefixlen == ~0U) {
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
		} else {
			unsigned int dummy, len;

			if (!ni_af_sockaddr_info(local_addr.ss_family, &dummy, &len))
				goto cannot_parse;
			prefixlen = len * 8;
		}
	}

	ap = ni_address_new(local_addr.ss_family, prefixlen, &local_addr, list);
	if (ap->family == AF_INET) {
		var = __find_indexed_variable(sc, "BROADCAST", suffix);
		if (var) {
			ni_sockaddr_parse(&ap->bcast_addr, var->value, AF_INET);
			if (ap->bcast_addr.ss_family != ap->family) {
				ni_error("%s: ignoring BROADCAST%s=%s (wrong address family)",
						sc->pathname, suffix, var->value);
				ap->bcast_addr.ss_family = AF_UNSPEC;
			}
		} else {
			/* Clear the default, it's useless */
			memset(&ap->bcast_addr, 0, sizeof(ap->bcast_addr));
		}
	}

	var = __find_indexed_variable(sc, "REMOTE_IPADDR", suffix);
	if (var) {
		ni_sockaddr_parse(&ap->peer_addr, var->value, AF_UNSPEC);
		if (ap->peer_addr.ss_family != ap->family) {
			ni_error("%s: ignoring REMOTE_IPADDR%s=%s (wrong address family)",
					sc->pathname, suffix, var->value);
			ap->peer_addr.ss_family = AF_UNSPEC;
		}
	}

	return TRUE;
}

/*
 * Process static addrconf
 */
static ni_bool_t
__ni_suse_addrconf_static(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	const char *routespath;

	/* Loop over all IPADDR* variables and get the addresses */
	{
		ni_string_array_t names = NI_STRING_ARRAY_INIT;
		unsigned int i;

		if (ni_sysconfig_find_matching(sc, "IPADDR", &names) > 0) {
			for (i = 0; i < names.count; ++i) {
				if (!__get_ipaddr(sc, names.data[i] + 6, &dev->addrs))
					return FALSE;
			}
			ni_string_array_destroy(&names);
		}
	}

	/* Hack up the loopback interface */
	if (!strcmp(dev->name, "lo")) {
		ni_sockaddr_t local_addr;

		ni_sockaddr_parse(&local_addr, "127.0.0.1", AF_INET);
		if (ni_address_list_find(dev->addrs, &local_addr) == NULL)
			ni_address_new(AF_INET, 8, &local_addr, &dev->addrs);

		ni_sockaddr_parse(&local_addr, "::1", AF_INET6);
		if (ni_address_list_find(dev->addrs, &local_addr) == NULL)
			ni_address_new(AF_INET6, 128, &local_addr, &dev->addrs);
	}

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
				ni_bool_t match = FALSE;

				switch (rp->family) {
				case AF_INET:
					/*
					 * FIXME: this is much more complex,
					 *      + move into some functions...
					 */
					for (nh = &rp->nh; nh; nh = nh->next) {
						/* check match by device name */
						if (nh->device.name) {
							if (ni_string_eq(nh->device.name, dev->name)) {
								match = TRUE;
								break;
							}
							continue;
						}

						/* match, when gw is on the same network:
						 * e.g. ip 192.168.1.0/24, gw is 192.168.1.1
						 */
						for (ap = dev->addrs; !match && ap; ap = ap->next) {
							if (ap->family == AF_INET &&
							    ni_address_can_reach(ap, &nh->gateway))
								match = TRUE;
						}

						/* match, when gw is on a previously added dev route
						 * ip 192.168.1.0/24
						 * route1: 192.168.2.0/24 dev $current
						 * route2: 192.168.3.0/24 gw 192.168.2.1
						 */
					}
					if (match) {
						ni_route_tables_add_route(&dev->routes,
								ni_route_clone(rp));
					}
				break;

				case AF_INET6:
					/* For IPv6, we add the route as long as the interface name matches */
					if (!rp->nh.device.name ||
					    !ni_string_eq(rp->nh.device.name, dev->name))
						continue;

					ni_route_tables_add_route(&dev->routes, ni_route_clone(rp));
					break;

				default:
					break;
				}
			}
		}
	}

	ni_address_list_dedup(&dev->addrs);
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
	ni_bool_t ret;

	if ((string = ni_sysconfig_get_value(sc, "DHCLIENT_HOSTNAME_OPTION")) != NULL) {
		if (!strcasecmp(string, "AUTO")) {
			ni_string_dup(&compat->dhcp4.hostname, __ni_suse_default_hostname);
		} else if (ni_check_domain_name(string, ni_string_len(string), 0)) {
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

	if (ni_sysconfig_get_integer(sc, "DHCLIENT_WAIT_AT_BOOT", &uint))
		compat->dhcp4.acquire_timeout = uint? uint : NI_IFWORKER_INFINITE_TIMEOUT;
	if (ni_sysconfig_get_integer(sc, "DHCLIENT_LEASE_TIME", &uint))
		compat->dhcp4.lease_time = ((int) uint >= 0)? uint : NI_IFWORKER_INFINITE_TIMEOUT;

	/* Ignored for now:
	   DHCLIENT_USE_LAST_LEASE
	   WRITE_HOSTNAME_TO_HOSTS
	   DHCLIENT_MODIFY_SMB_CONF
	   DHCLIENT_SET_HOSTNAME
	   DHCLIENT_SET_DEFAULT_ROUTE
	 */

	return ret;
}

/*
 * Process DHCPv6 addrconf
 */
static ni_bool_t
__ni_suse_addrconf_dhcp6_options(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_bool_t ret = TRUE;
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
		int len;
		/* Hmm... consider to move duid.[ch] to src ...
		 * type (2) + hwtype (2) + hwaddr (6) => 10 for duid type 3 (LL)
		 * type (2) + uuid (128)              => 130 for duid type 4 (UUID)
		 */
		len = ni_parse_hex(string, duid.data, sizeof(duid.data));
		if (len >= 10 && len <= 130) {
			ni_string_dup(&compat->dhcp6.client_id, string);
		} else {
			ni_warn("%s: Cannot parse DHCLIENT6_CLIENT_ID='%s' as DUID in hex",
				ni_basename(sc->pathname), string);
			ret = FALSE;
		}
	}

#if 0	/* FIXME: Use defaults for now */

	if (ni_sysconfig_get_integer(sc, "DHCLIENT6_WAIT_AT_BOOT", &uint))
		compat->dhcp4.acquire_timeout = uint? uint : NI_IFWORKER_INFINITE_TIMEOUT;
	if (ni_sysconfig_get_integer(sc, "DHCLIENT6_LEASE_TIME", &uint))
		compat->dhcp4.lease_time = ((int) uint >= 0)? uint : NI_IFWORKER_INFINITE_TIMEOUT;

	/* Ignored for now:
	   DHCLIENT_USE_LAST_LEASE
	   DHCLIENT_MODIFY_SMB_CONF
	   DHCLIENT_SET_HOSTNAME
	   DHCLIENT_SET_DEFAULT_ROUTE
	 */
#endif
	return ret;
}

static ni_bool_t
__ni_suse_addrconf_dhcp4(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_bool_t required)
{
	if (compat->dhcp4.enabled)
		return TRUE;

	if (__ni_suse_dhcp_defaults)
		__ni_suse_addrconf_dhcp4_options(__ni_suse_dhcp_defaults, compat);

	/* overwrite DHCP defaults with parameters from this ifcfg file */
	__ni_suse_addrconf_dhcp4_options(sc, compat);

	compat->dhcp4.enabled = TRUE;
	compat->dhcp4.required = required;
	return TRUE;
}

static ni_bool_t
__ni_suse_addrconf_dhcp6(const ni_sysconfig_t *sc, ni_compat_netdev_t *compat, ni_bool_t required)
{
	if (compat->dhcp6.enabled)
		return TRUE;

	if (__ni_suse_dhcp_defaults)
		__ni_suse_addrconf_dhcp6_options(__ni_suse_dhcp_defaults, compat);

	/* overwrite DHCP defaults with parameters from this ifcfg file */
	__ni_suse_addrconf_dhcp6_options(sc, compat);

	compat->dhcp6.enabled = TRUE;
	compat->dhcp6.required = required;
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
	const char *value;
	char *bp, *s, *p;

	if ((value = ni_sysconfig_get_value(sc, "BOOTPROTO")) == NULL)
		value = "static";
	else if (!value[0] || ni_string_eq(dev->name, "lo"))
		value = "static";

	/* Hmm... bonding slave -- set ethtool, but no link up */
	if (ni_string_eq_nocase(value, "none")) {
		return TRUE;
	}

	/* Hmm... ignore this config completely -> ibft firmware */
	if (ni_string_eq_nocase(value, "ibft")) {
		return TRUE;
	}

	if (ni_string_eq_nocase(value, "6to4")) {
		__ni_suse_addrconf_static(sc, compat);
		return TRUE;
	}

	if (ni_string_eq_nocase(value, "static")) {
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
	ni_string_dup(&bp, value);
	for (s = strtok_r(bp, "+", &p); s; s = strtok_r(NULL, "+", &p)) {
		ni_trace("BOOTPROTO[]=%s", s);
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
					" value \"%s\"", dev->name, value, s);
		}
		primary = FALSE;
	}
	ni_string_free(&bp);

	/* static is always included in the "+" variants */
	__ni_suse_addrconf_static(sc, compat);
	return TRUE;
}

/*
 * Read an ifcfg file
 */
static ni_bool_t
__ni_suse_sysconfig_read(ni_sysconfig_t *sc, ni_compat_netdev_t *compat)
{
	ni_netdev_t *dev = compat->dev;
	const char *value;

	if ((value = ni_sysconfig_get_value(sc, "STARTMODE")) != NULL)
		compat->control = __ni_suse_startmode(value);
	else
		compat->control = __ni_suse_startmode(NULL);

	ni_sysconfig_get_integer(sc, "MTU", &dev->link.mtu);

	if ((value = ni_sysconfig_get_value(sc, "LLADDR")) != NULL
	 && ni_link_address_parse(&dev->link.hwaddr, ARPHRD_ETHER, value) < 0) {
		ni_warn("ifcfg-%s: Cannot parse LLADDR=\"%s\"",
				dev->name, value);
	}


	if (try_loopback(sc, compat)   < 0 ||
	    try_bonding(sc, compat)    < 0 ||
	    try_bridge(sc, compat)     < 0 ||
	    try_vlan(sc, compat)       < 0 ||
	    try_tunnel(sc, compat)     < 0 ||
	    try_wireless(sc, compat)   < 0 ||
	    try_infiniband(sc, compat) < 0 ||
	    try_ethernet(sc, compat)   < 0)
		return FALSE;

	__ni_suse_bootproto(sc, compat);
	/* FIXME: What to do with these:
		NAME
		USERCONTROL
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
