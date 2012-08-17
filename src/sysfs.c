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

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include "sysfs.h"

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
static int		__ni_sysfs_netif_printf_attr(const char *, const char *, const char *, ...);
static int		__ni_sysfs_printf(const char *, const char *, ...);
static int		__ni_sysfs_read_list(const char *, ni_string_array_t *);
static int		__ni_sysfs_read_string(const char *, char **);

static int		__ni_sysfs_ibft_nic_format_path(const char *node, const char *attr, ni_stringbuf_t *path);
static int		__ni_sysfs_ibft_nic_get_string(const char *node, const char *attr, char **value);
static int		__ni_sysfs_ibft_nic_get_devpath(const char *node, const char *attr, char **value);
static int		__ni_sysfs_ibft_nic_get_uint(const char *node, const char *attr, unsigned int *value);
static int		__ni_sysfs_ibft_nic_find_iface(const char *devpath, char **ifname, unsigned int *ifindex);
static ni_ibft_nic_t *	__ni_sysfs_ibft_nic_parse(const char *node);


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
	return __ni_sysfs_netif_printf_attr(ifname, attr_name, "%d", result);
}

int
ni_sysfs_netif_put_long(const char *ifname, const char *attr_name, long result)
{
	return __ni_sysfs_netif_printf_attr(ifname, attr_name, "%ld", result);
}

int
ni_sysfs_netif_put_uint(const char *ifname, const char *attr_name, unsigned int result)
{
	return __ni_sysfs_netif_printf_attr(ifname, attr_name, "%u", result);
}

int
ni_sysfs_netif_put_ulong(const char *ifname, const char *attr_name, unsigned long result)
{
	return __ni_sysfs_netif_printf_attr(ifname, attr_name, "%lu", result);
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

static int
__ni_sysfs_netif_printf_attr(const char *ifname, const char *attr_name, const char *fmt, ...)
{
	char attr_value[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(attr_value, sizeof(attr_value), fmt, ap);
	va_end(ap);

	return __ni_sysfs_netif_put_attr(ifname, attr_name, attr_value);
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

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s/bonding/%s", _PATH_SYS_CLASS_NET, ifname, attr_name);

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
		ni_debug_ifconfig("%s: attr list %s unchanged", ifname, attr_name);
		rv = 0;
		goto done;
	}

	if (ni_debug & NI_TRACE_IFCONFIG) {
		ni_trace("%s: updating attr list %s", ifname, attr_name);
		for (i = 0; i < delete.count; ++i)
			ni_trace("    remove %s", delete.data[i]);
		for (i = 0; i < add.count; ++i)
			ni_trace("    add %s", add.data[i]);
		for (i = 0; i < unchanged.count; ++i)
			ni_trace("    leave %s", add.data[i]);
	}

	for (i = 0; i < delete.count; ++i) {
		if (__ni_sysfs_printf(pathbuf, "-%s\n", delete.data[i]) < 0) {
			ni_error("%s: could not remove %s %s",
					ifname, attr_name,
					delete.data[i]);
			goto done;
		}
	}

	for (i = 0; i < add.count; ++i) {
		if (__ni_sysfs_printf(pathbuf, "+%s\n", add.data[i]) < 0) {
			ni_error("%s: could not add %s %s",
					ifname, attr_name,
					add.data[i]);
			goto done;
		}
	}

	rv = 0;

done:
	ni_string_array_init(&current);
	ni_string_array_init(&delete);
	ni_string_array_init(&add);
	ni_string_array_init(&unchanged);
	return rv;
}

/*
 * Bridge support
 * This should really be in bridge.c
 */
void
ni_sysfs_bridge_get_config(const char *ifname, ni_bridge_t *bridge)
{
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/stp_state", &bridge->stp);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/priority", &bridge->priority);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/forward_delay", &bridge->forward_delay);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/ageing_time", &bridge->ageing_time);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/hello_time", &bridge->hello_time);
	ni_sysfs_netif_get_uint(ifname, SYSFS_BRIDGE_ATTR "/max_age", &bridge->max_age);
}

int
ni_sysfs_bridge_update_config(const char *ifname, const ni_bridge_t *bridge)
{
	int rv = 0;

	if (bridge->stp != NI_BRIDGE_VALUE_NOT_SET
	 && ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/stp_state", bridge->stp) < 0)
		rv = -1;
	if (bridge->priority != NI_BRIDGE_VALUE_NOT_SET
	 && ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/priority", bridge->priority) < 0)
		rv = -1;
	if (bridge->forward_delay != NI_BRIDGE_VALUE_NOT_SET
	 && ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/forward_delay", bridge->forward_delay) < 0)
		rv = -1;
	if (bridge->ageing_time != NI_BRIDGE_VALUE_NOT_SET
	 && ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/ageing_time", bridge->ageing_time) < 0)
		rv = -1;
	if (bridge->hello_time != NI_BRIDGE_VALUE_NOT_SET
	 && ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/hello_time", bridge->hello_time) < 0)
		rv = -1;
	if (bridge->max_age != NI_BRIDGE_VALUE_NOT_SET
	 && ni_sysfs_netif_put_uint(ifname, SYSFS_BRIDGE_ATTR "/max_age", bridge->max_age) < 0)
		rv = -1;

	return rv;
}

void
ni_sysfs_bridge_get_status(const char *ifname, ni_bridge_status_t *bs)
{
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
ni_sysctl_ipv4_ifconfig_get_uint(const char *ifname, const char *ctl_name, unsigned int *value)
{
	const char *pathname = __ni_sysctl_ipv4_ifconfig_path(ifname, ctl_name);
	char *result = NULL;

	*value = 0;
	if (__ni_sysfs_read_string(pathname, &result) < 0) {
		ni_error("%s: unable to read file: %m", pathname);
		return -1;
	}
	if (result == NULL) {
		ni_error("%s: empty file", pathname);
		return -1;
	}
	*value = strtoul(result, NULL, 0);
	ni_string_free(&result);
	return 0;
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
ni_sysctl_ipv6_ifconfig_get_uint(const char *ifname, const char *ctl_name, unsigned int *value)
{
	const char *pathname = __ni_sysctl_ipv6_ifconfig_path(ifname, ctl_name);
	char *result = NULL;

	*value = 0;
	if (__ni_sysfs_read_string(pathname, &result) < 0) {
		ni_error("%s: unable to read file: %m", pathname);
		return -1;
	}
	if (result == NULL) {
		ni_error("%s: empty file", pathname);
		return -1;
	}
	*value = strtoul(result, NULL, 0);
	ni_string_free(&result);
	return 0;
}

int
ni_sysctl_ipv6_ifconfig_set_uint(const char *ifname, const char *ctl_name, unsigned int newval)
{
	return __ni_sysfs_printf(__ni_sysctl_ipv6_ifconfig_path(ifname, ctl_name), "%u", newval);
}

/*
 * Print a value to a sysfs file
 */
static int
__ni_sysfs_printf(const char *pathname, const char *fmt, ...)
{
	va_list ap;
	FILE *fp;

	if ((fp = fopen(pathname, "w")) == NULL) {
		ni_error("unable to open %s: %m", pathname);
		return -1;
	}

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
static int
__ni_sysfs_ibft_nic_format_path(const char *node, const char *attr, ni_stringbuf_t *path)
{
	return ni_stringbuf_printf(path, "%s/%s/%s",
	         NI_SYSFS_FIRMWARE_IBFT_PATH, node, attr);
}

static int
__ni_sysfs_ibft_nic_get_string(const char *node, const char *attr, char **value)
{
	ni_stringbuf_t path = NI_STRINGBUF_INIT_DYNAMIC;
	int ret = -1;

	if (__ni_sysfs_ibft_nic_format_path(node, attr, &path) > 0) {
		ret = __ni_sysfs_read_string(path.string, value);
		ni_stringbuf_destroy(&path);
	}
	return ret;
}

static int
__ni_sysfs_ibft_nic_get_devpath(const char *node, const char *attr, char **value)
{
	ni_stringbuf_t path = NI_STRINGBUF_INIT_DYNAMIC;
	int ret = -1;

	ni_string_free(value);
	if (__ni_sysfs_ibft_nic_format_path(node, attr, &path) > 0) {
		ni_string_dup(value, canonicalize_file_name(path.string));
		ni_stringbuf_destroy(&path);
		if (*value != NULL)
			ret = 0;
	}
	return ret;
}

static int
__ni_sysfs_ibft_nic_get_uint(const char *node, const char *attr, unsigned int *value)
{
	char *temp = NULL;
	int ret = -1;

	if (__ni_sysfs_ibft_nic_get_string(node, attr, &temp) == 0 && temp) {
		ret = ni_parse_int(temp, value);
		ni_string_free(&temp);
	}
	return ret;
}

static int
__ni_sysfs_ibft_nic_find_iface(const char *devpath, char **ifname, unsigned int *ifindex)
{
	ni_string_array_t netlist = NI_STRING_ARRAY_INIT;
	ni_stringbuf_t    netbase = NI_STRINGBUF_INIT_DYNAMIC;
	unsigned int i;

	ni_assert(devpath != NULL && ifname != NULL && ifindex != NULL);
	ni_string_free(ifname);
	*ifindex = 0;

	if (ni_stringbuf_printf(&netbase, "%s/net", devpath) <= 0)
		goto cleanup;

	if (ni_file_exists(netbase.string)) {
		/* normal reference, e.g. device/net/eth0 */
		if (ni_scandir(netbase.string, NULL, &netlist) <= 0)
			goto cleanup;
	} else {
		/* virtio reference, e.g. device/virtio0/net/eth0,
		 * because iBFT references PCI IDs without func. */
		ni_string_array_t dirent = NI_STRING_ARRAY_INIT;

		if (ni_scandir(devpath, NULL, &dirent) <= 0)
			goto cleanup;

		for(i = 0; i < dirent.count; ++i) {
			ni_stringbuf_printf(&netbase, "%s/%s/net",
			                    devpath, dirent.data[i]);

			if (ni_file_exists(netbase.string) &&
			   ni_scandir(netbase.string, NULL, &netlist) > 0)
				break;

			ni_stringbuf_destroy(&netbase);
		}
		ni_string_array_destroy(&dirent);
	}

	if (netbase.string && netlist.count > 0) {
		/*
		 * netbase points to device/[subdir/]net/ directory,
		 * netlist contains the interface name entries in it;
		 * verify that the <iface>/ifindex file exists.
		 */
		for(i = 0; i < netlist.count && *ifname == NULL; ++i) {
			ni_stringbuf_t path = NI_STRINGBUF_INIT_DYNAMIC;
			char *temp = NULL;

			ni_stringbuf_printf(&path, "%s/%s/ifindex",
			                    netbase.string, netlist.data[i]);

			if (__ni_sysfs_read_string(path.string, &temp) == 0 && temp) {
				if (ni_parse_int(temp, ifindex) == 0)
					ni_string_dup(ifname, netlist.data[i]);

				ni_string_free(&temp);
			}
			ni_stringbuf_destroy(&path);
		}
	}

cleanup:
	ni_string_array_destroy(&netlist);
	ni_stringbuf_destroy(&netbase);

	return (*ifname != NULL && *ifindex > 0) ? 0 : -1;
}

static ni_ibft_nic_t *
__ni_sysfs_ibft_nic_parse(const char *node)
{
	char *temp = NULL;
	ni_ibft_nic_t *nic;

	nic = ni_ibft_nic_new();

	ni_string_dup(&nic->node, node);

	if (__ni_sysfs_ibft_nic_get_devpath(node, "device", &nic->devpath) != 0)
		goto error;
	if (__ni_sysfs_ibft_nic_find_iface(nic->devpath, &nic->ifname, &nic->ifindex) != 0)
		goto error;

	if (__ni_sysfs_ibft_nic_get_uint(node, "index", &nic->index) != 0)
		goto error;
	if (__ni_sysfs_ibft_nic_get_uint(node, "flags", &nic->flags) != 0)
		goto error;
	if (__ni_sysfs_ibft_nic_get_uint(node, "origin", &nic->origin) != 0)
		goto error;
	if (__ni_sysfs_ibft_nic_get_uint(node, "vlan", &nic->vlan) != 0)
		goto error;

	if (__ni_sysfs_ibft_nic_get_string(node, "mac", &temp) == 0 && temp) {
		if (ni_link_address_parse(&nic->hwaddr, NI_IFTYPE_ETHERNET, temp) != 0)
			goto error;
	}

	if (__ni_sysfs_ibft_nic_get_string(node, "ip-addr", &temp) == 0 && temp) {
		if (ni_address_parse(&nic->ipaddr, temp, AF_UNSPEC) != 0)
			goto error;
	}
	if (__ni_sysfs_ibft_nic_get_string(node, "subnet-mask", &temp) == 0 && temp) {
		/* The ibft module in 3.0.x kernels prints the ibft prefix
		   lenght as ipv4 netmask; I guess nobody ever used IPv6 */
		ni_sockaddr_t mask;
		if (ni_address_parse(&mask, temp, AF_UNSPEC) != 0)
			goto error;
		nic->prefix_len = ni_netmask_bits(&mask);
	}
	if (__ni_sysfs_ibft_nic_get_string(node, "dhcp", &temp) == 0 && temp) {
		if (ni_address_parse(&nic->dhcp, temp, AF_UNSPEC) != 0)
			goto error;
	}
	if (__ni_sysfs_ibft_nic_get_string(node, "gateway", &temp) == 0 && temp) {
		if (ni_address_parse(&nic->gateway, temp, AF_UNSPEC) != 0)
			goto error;
	}
	if (__ni_sysfs_ibft_nic_get_string(node, "primary-dns", &temp) == 0 && temp) {
		if (ni_address_parse(&nic->primary_dns, temp, AF_UNSPEC) != 0)
			goto error;
	}
	if (__ni_sysfs_ibft_nic_get_string(node, "secondary-dns", &temp) == 0 && temp) {
		if (ni_address_parse(&nic->secondary_dns, temp, AF_UNSPEC) != 0)
			goto error;
	}
	__ni_sysfs_ibft_nic_get_string(node, "hostname", &nic->hostname);

	ni_string_free(&temp);
	return nic;

error:
	ni_string_free(&temp);
	ni_ibft_nic_free(nic);
	return NULL;
}

int
ni_sysfs_ibft_scan_nics(ni_ibft_nic_array_t *nics)
{
	ni_string_array_t nodes = NI_STRING_ARRAY_INIT;
	unsigned int i;

	/* iBFT not available (iscsi_ibft module not loaded?) */
	if (!ni_file_exists(NI_SYSFS_FIRMWARE_IBFT_PATH))
		return 0;

	if (ni_scandir(NI_SYSFS_FIRMWARE_IBFT_PATH,
	              NI_SYSFS_IBFT_NIC_PREFIX "*",
	              &nodes) <= 0)
		return 0;

	for(i = 0; i < nodes.count; ++i) {
		ni_ibft_nic_t *nic;

		nic = __ni_sysfs_ibft_nic_parse(nodes.data[i]);

		ni_ibft_nic_array_append(nics, nic);
		ni_ibft_nic_free(nic);
	}
	ni_string_array_destroy(&nodes);

	return nics->count;
}
