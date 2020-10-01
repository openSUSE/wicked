/*
 * Routines for reading from sysfs files
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <limits.h>
#include <net/if_arp.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/pci.h>
#include "util_priv.h"
#include "sysfs.h"
#include "ibft.h"

#ifndef NI_PATH_SYSFS
#define NI_PATH_SYSFS			"/sys"
#endif

#define _PATH_SYS_CLASS_NET		"/sys/class/net"

/* #include <linux/if_bridge.h> */
#ifndef SYSFS_BRIDGE_ATTR
#define SYSFS_BRIDGE_ATTR		"bridge"
#endif
#ifndef SYSFS_BRIDGE_PORT_SUBDIR
#define SYSFS_BRIDGE_PORT_SUBDIR	"brif"
#endif
#ifndef SYSFS_BRIDGE_PORT_ATTR
#define SYSFS_BRIDGE_PORT_ATTR		"brport"
#endif
#ifndef SYSFS_BRIDGE_PORT_LINK
#define SYSFS_BRIDGE_PORT_LINK		"bridge"
#endif

/* iBFT related constants */
#define NI_SYSFS_FIRMWARE_IBFT_PATH     "/sys/firmware/ibft"
#define NI_SYSFS_IBFT_INI_PREFIX        "initiator"
#define NI_SYSFS_IBFT_NIC_PREFIX        "ethernet"
#define NI_SYSFS_IBFT_TGT_PREFIX        "target"


static const char *	__ni_sysfs_netif_attrpath(const char *ifname, const char *attr);
static const char *	__ni_sysfs_netif_get_attr(const char *ifname, const char *attr);
static int		__ni_sysfs_netif_put_attr(const char *, const char *, const char *);
static int		__ni_sysfs_printf(const char *, const char *, ...);
static int		__ni_sysfs_read_list(const char *, ni_string_array_t *);
static int		__ni_sysfs_read_string(const char *, char **);


/*
 * Functions for reading and writing sysfs attributes
 */
int
ni_sysfs_netif_get_int(const char *ifname, const char *attr_name, int *result)
{
	const char *attr;

	attr = __ni_sysfs_netif_get_attr(ifname, attr_name);
	if (!attr)
		return -1;

	*result = strtol(attr, NULL, 0);
	return 0;
}

int
ni_sysfs_netif_get_long(const char *ifname, const char *attr_name, long *result)
{
	const char *attr;

	attr = __ni_sysfs_netif_get_attr(ifname, attr_name);
	if (!attr)
		return -1;

	*result = strtol(attr, NULL, 0);
	return 0;
}

int
ni_sysfs_netif_get_uint(const char *ifname, const char *attr_name, unsigned int *result)
{
	const char *attr;

	attr = __ni_sysfs_netif_get_attr(ifname, attr_name);
	if (!attr)
		return -1;

	*result = strtoul(attr, NULL, 0);
	return 0;
}

int
ni_sysfs_netif_get_ulong(const char *ifname, const char *attr_name, unsigned long *result)
{
	const char *attr;

	attr = __ni_sysfs_netif_get_attr(ifname, attr_name);
	if (!attr)
		return -1;

	*result = strtoul(attr, NULL, 0);
	return 0;
}

int
ni_sysfs_netif_get_string(const char *ifname, const char *attr_name, char **result)
{
	const char *attr;

	attr = __ni_sysfs_netif_get_attr(ifname, attr_name);
	if (!attr)
		return -1;

	ni_string_dup(result, attr);
	return 0;
}

int
ni_sysfs_netif_put_int(const char *ifname, const char *attr_name, int result)
{
	return ni_sysfs_netif_printf(ifname, attr_name, "%d", result);
}

int
ni_sysfs_netif_put_long(const char *ifname, const char *attr_name, long result)
{
	return ni_sysfs_netif_printf(ifname, attr_name, "%ld", result);
}

int
ni_sysfs_netif_put_uint(const char *ifname, const char *attr_name, unsigned int result)
{
	return ni_sysfs_netif_printf(ifname, attr_name, "%u", result);
}

int
ni_sysfs_netif_put_ulong(const char *ifname, const char *attr_name, unsigned long result)
{
	return ni_sysfs_netif_printf(ifname, attr_name, "%lu", result);
}

int
ni_sysfs_netif_put_string(const char *ifname, const char *attr_name, const char *attr_value)
{
	return __ni_sysfs_netif_put_attr(ifname, attr_name, attr_value);
}

int
ni_sysfs_netif_printf(const char *ifname, const char *attr_name, const char *fmt, ...)
{
	char *attr_value = NULL;
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vasprintf(&attr_value, fmt, ap);
	va_end(ap);

	if (ret < 0)
		return -1;

	ret = __ni_sysfs_netif_put_attr(ifname, attr_name, attr_value);
	free(attr_value);
	return ret;
}

ni_bool_t
ni_sysfs_is_read_only(void)
{
	return ni_fs_is_read_only(NI_PATH_SYSFS);
}

ni_bool_t
ni_sysfs_netif_exists(const char *ifname, const char *attr_name)
{
	return ni_file_exists(__ni_sysfs_netif_attrpath(ifname, attr_name));
}

ni_bool_t
ni_sysfs_netif_readlink(const char *ifname, const char *attr_name, char **link)
{
	char linkbuf[PATH_MAX] = {'\0'};
	const char *path = __ni_sysfs_netif_attrpath(ifname, attr_name);

	if (readlink(path, linkbuf, sizeof(linkbuf)) < 0 || !linkbuf[0])
		return FALSE;

	ni_string_dup(link, linkbuf);
	return TRUE;
}

static const char *
__ni_sysfs_netif_get_attr(const char *ifname, const char *attr_name)
{
	static char buffer[256];
	const char *filename;
	char *result = NULL;
	FILE *fp;

	filename = __ni_sysfs_netif_attrpath(ifname, attr_name);
	if (!(fp = fopen(filename, "r")))
		return NULL;

	if (fgets(buffer, sizeof(buffer), fp) != NULL) {
		buffer[strcspn(buffer, "\n")] = '\0';
		result = buffer;
	}
	fclose(fp);
	return result;
}

static int
__ni_sysfs_netif_put_attr(const char *ifname, const char *attr_name, const char *attr_value)
{
	const char *filename;
	FILE *fp;
	int rv = 0;

	filename = __ni_sysfs_netif_attrpath(ifname, attr_name);
	if (!(fp = fopen(filename, "w"))) {
		ni_error("Unable to set %s attribute %s: %m",
				ifname, attr_name);
		return -1;
	}

	fprintf(fp, "%s\n", attr_value);
	if (fflush(fp) == EOF || ferror(fp)) {
		ni_error("Unable to set %s attribute %s=%s: %s",
				ifname, attr_name, attr_value,
				strerror(ferror(fp)));
		rv = -1;
	}
	fclose(fp);
	return rv;
}

static const char *
__ni_sysfs_netif_attrpath(const char *ifname, const char *attr_name)
{
	static char pathbuf[PATH_MAX];

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s/%s",
			_PATH_SYS_CLASS_NET, ifname, attr_name);
	return pathbuf;
}

/*
 * Bonding support
 */
int
ni_sysfs_bonding_available(void)
{
	return ni_file_exists("/sys/class/net/bonding_masters");
}

int
ni_sysfs_bonding_get_masters(ni_string_array_t *list)
{
	return __ni_sysfs_read_list("/sys/class/net/bonding_masters", list);
}

int
ni_sysfs_bonding_add_master(const char *ifname)
{
	return __ni_sysfs_printf("/sys/class/net/bonding_masters", "+%s\n", ifname);
}

int
ni_sysfs_bonding_is_master(const char *ifname)
{
	return ni_file_exists(__ni_sysfs_netif_attrpath(ifname, "bonding"));
}

int
ni_sysfs_bonding_delete_master(const char *ifname)
{
	return __ni_sysfs_printf("/sys/class/net/bonding_masters", "-%s\n", ifname);
}

int
ni_sysfs_bonding_get_slaves(const char *master, ni_string_array_t *list)
{
	return __ni_sysfs_read_list(__ni_sysfs_netif_attrpath(master, "bonding/slaves"), list);
}

int
ni_sysfs_bonding_add_slave(const char *master, const char *slave)
{
	return __ni_sysfs_printf(__ni_sysfs_netif_attrpath(master, "bonding/slaves"), "+%s", slave);
}

int
ni_sysfs_bonding_delete_slave(const char *master, const char *slave)
{
	return __ni_sysfs_printf(__ni_sysfs_netif_attrpath(master, "bonding/slaves"), "-%s", slave);
}

int
ni_sysfs_bonding_get_arp_targets(const char *master, ni_string_array_t *result)
{
	return __ni_sysfs_read_list(__ni_sysfs_netif_attrpath(master, "bonding/arp_ip_target"), result);
}

int
ni_sysfs_bonding_add_arp_target(const char *master, const char *ipaddress)
{
	return __ni_sysfs_printf(__ni_sysfs_netif_attrpath(master, "bonding/arp_ip_target"), "+%s\n", ipaddress);
}

int
ni_sysfs_bonding_delete_arp_target(const char *master, const char *ipaddress)
{
	return __ni_sysfs_printf(__ni_sysfs_netif_attrpath(master, "bonding/arp_ip_target"), "-%s\n", ipaddress);
}

int
ni_sysfs_bonding_get_attr(const char *ifname, const char *attr_name, char **result)
{
	static char pathbuf[PATH_MAX];

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s/bonding/%s", _PATH_SYS_CLASS_NET, ifname, attr_name);
	return __ni_sysfs_read_string(pathbuf, result);
}

int
ni_sysfs_bonding_set_attr(const char *ifname, const char *attr_name, const char *attr_value)
{
	static char pathbuf[PATH_MAX];

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s/bonding/%s", _PATH_SYS_CLASS_NET, ifname, attr_name);
	return __ni_sysfs_printf(pathbuf, "%s", attr_value);
}

int
ni_sysfs_bonding_set_list_attr(const char *ifname, const char *attr_name, const ni_string_array_t *list)
{
	static char pathbuf[PATH_MAX];
	ni_string_array_t current, delete, add, unchanged;
	unsigned int i;
	int rv = -1;

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s/bonding/%s",
			_PATH_SYS_CLASS_NET, ifname, attr_name);

	ni_string_array_init(&current);
	if (__ni_sysfs_read_list(pathbuf, &current) < 0)
		return -1;

	ni_string_array_init(&delete);
	ni_string_array_init(&add);
	ni_string_array_init(&unchanged);

	ni_string_array_comm(&current, list,
			&delete,	/* unique to 1st array */
			&add,		/* unique to 2nd array */
			&unchanged);	/* common to both */

	if (add.count == 0 && delete.count == 0) {
		ni_debug_ifconfig("%s: attr list %s unchanged",
				ifname, attr_name);
		rv = 0;
		goto done;
	}

	if (ni_log_facility(NI_TRACE_IFCONFIG)) {
		ni_trace("%s: updating attr list %s", ifname, attr_name);
		for (i = 0; i < delete.count; ++i)
			ni_trace("    remove %s", delete.data[i]);
		for (i = 0; i < add.count; ++i)
			ni_trace("    add %s", add.data[i]);
		for (i = 0; i < unchanged.count; ++i)
			ni_trace("    leave %s", unchanged.data[i]);
	}

	for (i = 0; i < add.count; ++i) {
		if (__ni_sysfs_printf(pathbuf, "+%s\n", add.data[i]) < 0) {
			ni_error("%s: could not add %s %s",
					ifname, attr_name,
					add.data[i]);
			goto done;
		}
	}

	for (i = 0; i < delete.count; ++i) {
		if (__ni_sysfs_printf(pathbuf, "-%s\n", delete.data[i]) < 0) {
			ni_error("%s: could not remove %s %s",
					ifname, attr_name,
					delete.data[i]);
			goto done;
		}
	}

	rv = 0;

done:
	ni_string_array_destroy(&unchanged);
	ni_string_array_destroy(&current);
	ni_string_array_destroy(&delete);
	ni_string_array_destroy(&add);
	return rv;
}

/*
 * Bridge support
 * This should really be in bridge.c
 */
void
ni_sysfs_bridge_get_config(const char *ifname, ni_bridge_t *bridge)
{
	unsigned int  ui;
	unsigned long ul;

	if (ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/stp_state", &ui) == 0)
		bridge->stp = ui ? TRUE : FALSE;

	if (ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/priority", &ui) == 0)
		bridge->priority = ui;

	if (ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/forward_delay", &ui) == 0)
		bridge->forward_delay = (double)ui / 100.0;
	if (ni_sysfs_netif_get_ulong(ifname, SYSFS_BRIDGE_ATTR "/ageing_time", &ul) == 0)
		bridge->ageing_time = (double)ui / 100.0;
	if (ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/hello_time", &ui) == 0)
		bridge->hello_time = (double)ui / 100.0;
	if (ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/max_age", &ui) == 0)
		bridge->max_age = (double)ui / 100.0;
}

int
ni_sysfs_bridge_update_config(const char *ifname, const ni_bridge_t *bridge)
{
	int rv = 0;

	if (ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/stp_state", bridge->stp) < 0)
		rv = -1;

	if (bridge->priority != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/priority", bridge->priority) < 0)
		rv = -1;

	if (bridge->forward_delay != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/forward_delay",
				(unsigned int)(bridge->forward_delay * 100.0)) < 0)
		rv = -1;

	if (bridge->ageing_time != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_sysfs_netif_put_ulong(ifname, SYSFS_BRIDGE_ATTR "/ageing_time",
				(unsigned long)(bridge->ageing_time * 100.0)) < 0)
		rv = -1;

	if (bridge->hello_time != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/hello_time",
				(unsigned int)(bridge->hello_time * 100.0)) < 0)
		rv = -1;

	if (bridge->max_age != NI_BRIDGE_VALUE_NOT_SET &&
	    ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/max_age",
				(unsigned int)(bridge->max_age * 100.0)) < 0)
		rv = -1;

	return rv;
}

void
ni_sysfs_bridge_get_status(const char *ifname, ni_bridge_status_t *bs)
{
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/stp_state", &bs->stp_state);
	ni_sysfs_netif_get_string(ifname, SYSFS_BRIDGE_ATTR "/root_id", &bs->root_id);
	ni_sysfs_netif_get_string(ifname, SYSFS_BRIDGE_ATTR "/bridge_id", &bs->bridge_id);
	ni_sysfs_netif_get_string(ifname, SYSFS_BRIDGE_ATTR "/group_addr", &bs->group_addr);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/root_port", &bs->root_port);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/root_path_cost", &bs->root_path_cost);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/topology_change", &bs->topology_change);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/topology_change_detected", &bs->topology_change_detected);
	ni_sysfs_netif_get_ulong(ifname, SYSFS_BRIDGE_ATTR "/gc_timer", &bs->gc_timer);
	ni_sysfs_netif_get_ulong(ifname, SYSFS_BRIDGE_ATTR "/tcn_timer", &bs->tcn_timer);
	ni_sysfs_netif_get_ulong(ifname, SYSFS_BRIDGE_ATTR "/hello_timer", &bs->hello_timer);
	ni_sysfs_netif_get_ulong(ifname, SYSFS_BRIDGE_ATTR "/topology_change_timer", &bs->topology_change_timer);
}

int
ni_sysfs_bridge_get_port_names(const char *ifname, ni_string_array_t *names)
{
	return ni_scandir(__ni_sysfs_netif_attrpath(ifname, SYSFS_BRIDGE_PORT_SUBDIR), NULL, names);
}

void
ni_sysfs_bridge_port_get_config(const char *ifname, ni_bridge_port_t *port)
{
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/priority", &port->priority);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/path_cost", &port->path_cost);
}

int
ni_sysfs_bridge_port_update_config(const char *ifname, const ni_bridge_port_t *port)
{
	int rv = 0;

	if (port->priority != NI_BRIDGE_VALUE_NOT_SET
	 && ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/priority", port->priority) < 0)
		rv = -1;

	if (port->path_cost != NI_BRIDGE_VALUE_NOT_SET
	 && ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/path_cost", port->path_cost) < 0)
		rv = -1;

	return rv;
}

void
ni_sysfs_bridge_port_get_status(const char *ifname, ni_bridge_port_status_t *ps)
{
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/priority", &ps->priority);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/path_cost", &ps->path_cost);

	ni_sysfs_netif_get_int(ifname, SYSFS_BRIDGE_PORT_ATTR "/state", &ps->state);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/port_no", &ps->port_no);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/port_id", &ps->port_no);
	ni_sysfs_netif_get_string(ifname, SYSFS_BRIDGE_PORT_ATTR "/designated_root", &ps->designated_root);
	ni_sysfs_netif_get_string(ifname, SYSFS_BRIDGE_PORT_ATTR "/designated_bridge", &ps->designated_bridge);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/designated_port", &ps->designated_port);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/designated_cost", &ps->designated_cost);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/change_ack", &ps->change_ack);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/hairpin_mode", &ps->hairpin_mode);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_PORT_ATTR "/config_pending", &ps->config_pending);

	ni_sysfs_netif_get_ulong(ifname, SYSFS_BRIDGE_PORT_ATTR "/hold_timer", &ps->hold_timer);
	ni_sysfs_netif_get_ulong(ifname, SYSFS_BRIDGE_PORT_ATTR "/message_age_timer", &ps->message_age_timer);
	ni_sysfs_netif_get_ulong(ifname, SYSFS_BRIDGE_PORT_ATTR "/forward_delay_timer", &ps->forward_delay_timer);
}

/*
 * Get/set IPv4 sysctls
 */
static inline const char *
__ni_sysctl_ipv4_ifconfig_path(const char *ifname, const char *ctl_name)
{
	static char pathname[PATH_MAX];

	if (ctl_name)
		snprintf(pathname, sizeof(pathname), "/proc/sys/net/ipv4/conf/%s/%s", ifname, ctl_name);
	else
		snprintf(pathname, sizeof(pathname), "/proc/sys/net/ipv4/conf/%s", ifname);
	return pathname;
}

int
ni_sysctl_ipv4_ifconfig_is_present(const char *ifname)
{
	const char *pathname = __ni_sysctl_ipv4_ifconfig_path(ifname, NULL);

	return access(pathname, F_OK) == 0;
}

int
ni_sysctl_ipv4_ifconfig_get(const char *ifname, const char *ctl_name, char **result)
{
	const char *pathname = __ni_sysctl_ipv4_ifconfig_path(ifname, ctl_name);

	if (!result || __ni_sysfs_read_string(pathname, result) < 0 || !*result) {
		ni_error("%s: unable to read file: %m", pathname);
		return -1;
	}
	return 0;
}

int
ni_sysctl_ipv4_ifconfig_get_int(const char *ifname, const char *ctl_name, int *value)
{
	char *result = NULL;
	int ret;

	*value = 0;
	if (ni_sysctl_ipv4_ifconfig_get(ifname, ctl_name, &result) < 0)
		return -1;

	ret = ni_parse_int(result, value, 0);
	ni_string_free(&result);
	return ret;
}

int
ni_sysctl_ipv4_ifconfig_get_uint(const char *ifname, const char *ctl_name, unsigned int *value)
{
	char *result = NULL;
	int ret;

	*value = 0;
	if (ni_sysctl_ipv4_ifconfig_get(ifname, ctl_name, &result) < 0)
		return -1;

	ret = ni_parse_uint(result, value, 0);
	ni_string_free(&result);
	return ret;
}

int
ni_sysctl_ipv4_ifconfig_set(const char *ifname, const char *ctl_name, const char *newval)
{
	return __ni_sysfs_printf(__ni_sysctl_ipv4_ifconfig_path(ifname, ctl_name), "%s", newval ? newval : "");
}

int
ni_sysctl_ipv4_ifconfig_set_int(const char *ifname, const char *ctl_name, int newval)
{
	return __ni_sysfs_printf(__ni_sysctl_ipv4_ifconfig_path(ifname, ctl_name), "%d", newval);
}

int
ni_sysctl_ipv4_ifconfig_set_uint(const char *ifname, const char *ctl_name, unsigned int newval)
{
	return __ni_sysfs_printf(__ni_sysctl_ipv4_ifconfig_path(ifname, ctl_name), "%u", newval);
}

/*
 * Get/set IPv6 sysctls
 */
static inline const char *
__ni_sysctl_ipv6_ifconfig_path(const char *ifname, const char *ctl_name)
{
	static char pathname[PATH_MAX];

	if (ctl_name)
		snprintf(pathname, sizeof(pathname), "/proc/sys/net/ipv6/conf/%s/%s", ifname, ctl_name);
	else
		snprintf(pathname, sizeof(pathname), "/proc/sys/net/ipv6/conf/%s", ifname);
	return pathname;
}

int
ni_sysctl_ipv6_ifconfig_is_present(const char *ifname)
{
	const char *pathname = __ni_sysctl_ipv6_ifconfig_path(ifname, NULL);

	return access(pathname, F_OK) == 0;
}

int
ni_sysctl_ipv6_ifconfig_get(const char *ifname, const char *ctl_name, char **result)
{
	const char *pathname = __ni_sysctl_ipv6_ifconfig_path(ifname, ctl_name);

	if (!result || __ni_sysfs_read_string(pathname, result) < 0 || !*result) {
		ni_error("%s: unable to read file: %m", pathname);
		return -1;
	}
	return 0;
}

int
ni_sysctl_ipv6_ifconfig_get_int(const char *ifname, const char *ctl_name, int *value)
{
	char *result = NULL;
	int ret;

	*value = 0;
	if (ni_sysctl_ipv6_ifconfig_get(ifname, ctl_name, &result) < 0)
		return -1;

	ret = ni_parse_int(result, value, 0);
	ni_string_free(&result);
	return ret;
}

int
ni_sysctl_ipv6_ifconfig_get_uint(const char *ifname, const char *ctl_name, unsigned int *value)
{
	char *result = NULL;
	int ret;

	*value = 0;
	if (ni_sysctl_ipv6_ifconfig_get(ifname, ctl_name, &result) < 0)
		return -1;

	ret = ni_parse_uint(result, value, 0);
	ni_string_free(&result);
	return ret;
}

int
ni_sysctl_ipv6_ifconfig_get_ipv6(const char *ifname, const char *ctl_name, struct in6_addr *ipv6)
{
	char *result = NULL;
	ni_sockaddr_t addr;
	int ret;

	*ipv6 = in6addr_any;
	if (ni_sysctl_ipv6_ifconfig_get(ifname, ctl_name, &result) < 0)
		return -1;

	if ((ret = ni_sockaddr_parse(&addr, result, AF_INET6)) == 0)
		*ipv6 = addr.six.sin6_addr;

	ni_string_free(&result);
	return ret;
}

int
ni_sysctl_ipv6_ifconfig_set(const char *ifname, const char *ctl_name, const char *newval)
{
	return __ni_sysfs_printf(__ni_sysctl_ipv6_ifconfig_path(ifname, ctl_name), "%s", newval ? newval : "");
}

int
ni_sysctl_ipv6_ifconfig_set_int(const char *ifname, const char *ctl_name, int newval)
{
	return __ni_sysfs_printf(__ni_sysctl_ipv6_ifconfig_path(ifname, ctl_name), "%d", newval);
}

int
ni_sysctl_ipv6_ifconfig_set_uint(const char *ifname, const char *ctl_name, unsigned int newval)
{
	return __ni_sysfs_printf(__ni_sysctl_ipv6_ifconfig_path(ifname, ctl_name), "%u", newval);
}

int
ni_sysctl_ipv6_ifconfig_set_ipv6(const char *ifname, const char *ctl_name, const struct in6_addr newval)
{
	ni_sockaddr_t addr;
	char abuf[128] = {'\0'};

	ni_sockaddr_set_ipv6(&addr, newval, 0);
	if (!ni_sockaddr_format(&addr, abuf, sizeof(abuf)))
		return -1;

	return ni_sysctl_ipv6_ifconfig_set(ifname, ctl_name, abuf);
}

/*
 * Print a value to a sysfs file
 */
static int
__ni_sysfs_printf(const char *pathname, const char *fmt, ...)
{
	va_list ap;
	FILE *fp;

	if ((fp = fopen(pathname, "w")) == NULL)
		return -1;

	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);

	if (fclose(fp) < 0) {
		ni_error("error writing to %s: %m", pathname);
		return -1;
	}

	return 0;
}

/*
 * Read a list of values from a sysfs file
 */
static int
__ni_sysfs_read_list(const char *pathname, ni_string_array_t *result)
{
	char buffer[256];
	FILE *fp;

	if ((fp = fopen(pathname, "r")) == NULL) {
		ni_error("unable to open %s: %m", pathname);
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char *s;

		for (s = strtok(buffer, " \t\n"); s; s = strtok(NULL, " \t\n"))
			ni_string_array_append(result, s);
	}
	fclose(fp);
	return 0;
}

static int
__ni_sysfs_read_string(const char *pathname, char **result)
{
	char buffer[256];
	FILE *fp;

	if (!(fp = fopen(pathname, "r")))
		return -1;

	ni_string_free(result);

	if (fgets(buffer, sizeof(buffer), fp) != NULL) {
		buffer[strcspn(buffer, "\n")] = '\0';
		ni_string_dup(result, buffer);
	}
	fclose(fp);
	return 0;
}

/*
 * Discover iBFT information stored in sysfs
 */
static const char *
__ni_sysfs_ibft_nic_format_path(const char *base, const char *node,
				const char *attr, char **path)
{
	if (ni_string_empty(base))
		base = NI_SYSFS_FIRMWARE_IBFT_PATH;
	return ni_string_printf(path, "%s/%s/%s", base, node, attr);
}

static int
__ni_sysfs_ibft_nic_get_string(const char *base, const char *node,
				const char *attr, char **value)
{
	char *path = NULL;
	int ret = -1;

	if (__ni_sysfs_ibft_nic_format_path(base, node, attr, &path)) {
		ret = __ni_sysfs_read_string(path, value);
		ni_string_free(&path);
	}
	return ret;
}

static int
__ni_sysfs_ibft_nic_get_devpath(const char *base, const char *node,
				const char *attr, char **value)
{
	char *path = NULL;
	int ret = -1;

	ni_string_free(value);
	if (__ni_sysfs_ibft_nic_format_path(base, node, attr, &path)) {
		ni_realpath(path, value);
		ni_string_free(&path);
		if (*value != NULL)
			ret = 0;
	}
	return ret;
}

static int
__ni_sysfs_ibft_nic_get_uint(const char *base, const char *node,
				const char *attr, unsigned int *value)
{
	char *temp = NULL;
	int ret = -1;

	if (__ni_sysfs_ibft_nic_get_string(base, node, attr, &temp) == 0 && temp) {
		ret = ni_parse_uint(temp, value, 10);
		ni_string_free(&temp);
	}
	return ret;
}

static int
__ni_sysfs_ibft_nic_find_iface(const char *base, const char *devpath,
				char **ifname, unsigned int *ifindex)
{
	ni_string_array_t netlist = NI_STRING_ARRAY_INIT;
	char * netbase = NULL;
	unsigned int i;

	ni_assert(devpath != NULL && ifname != NULL && ifindex != NULL);
	ni_string_free(ifname);
	*ifindex = 0;

	if (!ni_string_printf(&netbase, "%s/net", devpath))
		goto cleanup;

	if (ni_file_exists(netbase)) {
		/* normal reference, e.g. device/net/eth0 */
		if (ni_scandir(netbase, NULL, &netlist) <= 0)
			goto cleanup;
	} else {
		/* virtio reference, e.g. device/virtio0/net/eth0,
		 * because iBFT references PCI IDs without func. */
		ni_string_array_t dirent = NI_STRING_ARRAY_INIT;

		if (ni_scandir(devpath, NULL, &dirent) <= 0)
			goto cleanup;

		for(i = 0; i < dirent.count; ++i) {
			ni_string_printf(&netbase, "%s/%s/net",
					devpath, dirent.data[i]);

			if (ni_file_exists(netbase) &&
			   ni_scandir(netbase, NULL, &netlist) > 0)
				break;

			ni_string_free(&netbase);
		}
		ni_string_array_destroy(&dirent);
	}

	if (netbase && netlist.count > 0) {
		/*
		 * netbase points to device/[subdir/]net/ directory,
		 * netlist contains the interface name entries in it;
		 * verify that the <iface>/ifindex file exists.
		 */
		for(i = 0; i < netlist.count && *ifname == NULL; ++i) {
			char *path = NULL;
			char *temp = NULL;

			ni_string_printf(&path, "%s/%s/ifindex",
					netbase, netlist.data[i]);

			if (__ni_sysfs_read_string(path, &temp) == 0 && temp) {
				if (ni_parse_uint(temp, ifindex, 10) == 0)
					ni_string_dup(ifname, netlist.data[i]);

				ni_string_free(&temp);
			}
			ni_string_free(&path);
		}
	}

cleanup:
	ni_string_array_destroy(&netlist);
	ni_string_free(&netbase);

	return (*ifname != NULL && *ifindex > 0) ? 0 : -1;
}

static ni_ibft_nic_t *
__ni_sysfs_ibft_nic_parse(const char *base, const char *node)
{
	char *temp = NULL;
	ni_ibft_nic_t *nic;

	nic = ni_ibft_nic_new();

	ni_string_dup(&nic->node, node);

	if (__ni_sysfs_ibft_nic_get_devpath(base, node,
				"device", &nic->devpath) != 0)
		goto error;
	if (__ni_sysfs_ibft_nic_find_iface(base, nic->devpath,
				&nic->ifname, &nic->ifindex) != 0)
		goto error;

	if (__ni_sysfs_ibft_nic_get_uint(base, node,
				"index", &nic->index) != 0)
		goto error;
	if (__ni_sysfs_ibft_nic_get_uint(base, node,
				"flags", &nic->flags) != 0)
		goto error;
	if (__ni_sysfs_ibft_nic_get_uint(base, node,
				"origin", &nic->origin) != 0)
		goto error;
	if (__ni_sysfs_ibft_nic_get_uint(base, node,
				"vlan", &nic->vlan) != 0)
		goto error;

	if (__ni_sysfs_ibft_nic_get_string(base, node,
				"mac", &temp) == 0 && temp) {
		if (ni_link_address_parse(&nic->hwaddr,
					ARPHRD_ETHER, temp) != 0)
			goto error;
	}

	if (__ni_sysfs_ibft_nic_get_string(base, node,
				"ip-addr", &temp) == 0 && temp) {
		if (ni_sockaddr_parse(&nic->ipaddr, temp, AF_UNSPEC) != 0)
			goto error;
	}
	if (__ni_sysfs_ibft_nic_get_string(base, node,
				"subnet-mask", &temp) == 0 && temp) {
		/* The ibft module in 3.0.x kernels prints the ibft prefix
		   lenght as ipv4 netmask; I guess nobody ever used IPv6 */
		ni_sockaddr_t mask;
		if (ni_sockaddr_parse(&mask, temp, AF_UNSPEC) != 0)
			goto error;
		nic->prefix_len = ni_sockaddr_netmask_bits(&mask);
	}
	if (__ni_sysfs_ibft_nic_get_string(base, node,
				"dhcp", &temp) == 0 && temp) {
		if (ni_sockaddr_parse(&nic->dhcp, temp, AF_UNSPEC) != 0)
			goto error;
	}
	if (__ni_sysfs_ibft_nic_get_string(base, node,
				"gateway", &temp) == 0 && temp) {
		if (ni_sockaddr_parse(&nic->gateway, temp, AF_UNSPEC) != 0)
			goto error;
	}
	if (__ni_sysfs_ibft_nic_get_string(base, node,
				"primary-dns", &temp) == 0 && temp) {
		if (ni_sockaddr_parse(&nic->primary_dns, temp, AF_UNSPEC) != 0)
			goto error;
	}
	if (__ni_sysfs_ibft_nic_get_string(base, node,
				"secondary-dns", &temp) == 0 && temp) {
		if (ni_sockaddr_parse(&nic->secondary_dns, temp, AF_UNSPEC) != 0)
			goto error;
	}
	__ni_sysfs_ibft_nic_get_string(base, node,
			"hostname", &nic->hostname);

	ni_string_free(&temp);
	return nic;

error:
	ni_string_free(&temp);
	ni_ibft_nic_free(nic);
	return NULL;
}

int
ni_sysfs_ibft_scan_nics(ni_ibft_nic_array_t *nics, const char *root)
{
	ni_string_array_t nodes = NI_STRING_ARRAY_INIT;
	char ibftpath[PATH_MAX] = {'\0'};
	unsigned int i;

	/* iBFT not available (iscsi_ibft module not loaded?) */
	if (!ni_string_empty(root)) {
		snprintf(ibftpath, sizeof(ibftpath), "%s/%s",
				root, NI_SYSFS_FIRMWARE_IBFT_PATH);
	} else {
		snprintf(ibftpath, sizeof(ibftpath), "%s",
				NI_SYSFS_FIRMWARE_IBFT_PATH);
	}

	if (!ni_file_exists(ibftpath))
		return 0;

	if (ni_scandir(ibftpath, NI_SYSFS_IBFT_NIC_PREFIX"*", &nodes) <= 0)
		return 0;

	for(i = 0; i < nodes.count; ++i) {
		ni_ibft_nic_t *nic;

		nic = __ni_sysfs_ibft_nic_parse(ibftpath, nodes.data[i]);

		ni_ibft_nic_array_append(nics, nic);
		ni_ibft_nic_free(nic);
	}
	ni_string_array_destroy(&nodes);

	return nics->count;
}

/*
 * Identify a network PCI device
 */
ni_pci_dev_t *
ni_pci_dev_new(const char *path)
{
	ni_pci_dev_t *pci_dev;

	pci_dev = xcalloc(1, sizeof(*pci_dev));
	ni_string_dup(&pci_dev->path, path);
	return pci_dev;
}

void
ni_pci_dev_free(ni_pci_dev_t *pci_dev)
{
	ni_string_free(&pci_dev->path);
	free(pci_dev);
}

ni_pci_dev_t *
ni_sysfs_netdev_get_pci(const char *ifname)
{
	char pathbuf[PATH_MAX], device_link[PATH_MAX], *pci_path, *s;
	ni_pci_dev_t *pci = NULL;
	const char *attr;

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", _PATH_SYS_CLASS_NET, ifname);
	if (readlink(pathbuf, device_link, sizeof(device_link)) < 0)
		return NULL;

	if (strncmp(device_link, "../../devices/", 14))
		return NULL;
	pci_path = device_link + 14;
	if ((s = strstr(pci_path, "/net/")) == NULL)
		return NULL;
	*s = '\0';
	pci = ni_pci_dev_new(pci_path);

	if ((attr = __ni_sysfs_netif_get_attr(ifname, "device/vendor")) == NULL)
		goto failed;
	pci->vendor = strtoul(attr, NULL, 0);

	if ((attr = __ni_sysfs_netif_get_attr(ifname, "device/device")) == NULL)
		goto failed;
	pci->device = strtoul(attr, NULL, 0);

	return pci;

failed:
	if (pci)
		ni_pci_dev_free(pci);
	return NULL;
}
