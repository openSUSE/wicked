/*
 * Routines for detecting and monitoring network interfaces.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/netinfo.h>
#include <wicked/route.h>
#include <wicked/team.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/ethernet.h>
#include <wicked/wireless.h>
#include <wicked/vlan.h>
#include <wicked/openvpn.h>
#include <wicked/socket.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "dbus-server.h"
#include "appconfig.h"
#include "xml-schema.h"
#include "sysfs.h"
#include "modem-manager.h"

#include <signal.h>
#include <limits.h>
#include <errno.h>

#include <net/if.h>

#include <gcrypt.h>

#define NI_NETDEV_REF_ARRAY_CHUNK	16

typedef struct ni_netconfig_filter {
	unsigned int		family;
	unsigned int		discover;
} ni_netconfig_filter_t;

struct ni_netconfig {
	ni_netconfig_filter_t	filter;

	ni_netdev_t *		interfaces;
	ni_modem_t *		modems;

	struct {
		ni_rule_array_t	rules;
	}			route;

	unsigned char		initialized;
};

/*
 * Global data for netinfo library
 */
ni_global_t	ni_global;
unsigned int	__ni_global_seqno;

/*
 * Global initialization of application
 */
int
ni_init(const char *appname)
{
	return ni_init_ex(appname, NULL, NULL);
}

static int
__ni_init_gcrypt(void)
{
/*
 * gcry_check_version checks for minimum version
 * we want consider sufficient and returns NULL
 * on failures.
 *
 * configure.ac checks and defines the minimum;
 * when our requirements change, adjust there.
 *
 * With NULL, we don't require a minimum version
 * but call the function to initialize libgcrypt
 * and trust the linker and library soname.
 */
#ifndef REQUIRE_LIBGCRYPT
#define REQUIRE_LIBGCRYPT NULL
#endif
	if (!gcry_check_version(REQUIRE_LIBGCRYPT)) {
		ni_error("libgcrypt version mismatch: built %s, required >= %s",
			GCRYPT_VERSION, REQUIRE_LIBGCRYPT);
		return -1;
	}

	if (gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
		return 0;

	gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
		ni_error("Unable to initialize libgcrypt");
		return -1;
	}
	return 0;
}

int
ni_init_ex(const char *appname, ni_init_appdata_callback_t *cb, void *appdata)
{
	int explicit_config = 1;

	if (ni_global.initialized) {
		ni_error("ni_init called twice");
		return -1;
	}

	/* We're using randomized timeouts. Seed the RNG */
	ni_srandom();

	if (__ni_init_gcrypt() < 0)
		return -1;

	if (ni_global.config_path == NULL) {
		if (appname == NULL) {
			/* Backward compatible - for now.
			 * The server will load config.xml
			 */
			appname = "config";
		}

		if (asprintf(&ni_global.config_path, "%s/%s.xml",
					ni_get_global_config_dir(), appname) < 0) {
			ni_global.config_path = NULL;
			return -1;
		}

		/* If the application-specific config file does not exist, fall
		 * back to common.xml */
		if (!ni_file_exists(ni_global.config_path)) {
			ni_string_free(&ni_global.config_path);
			if (asprintf(&ni_global.config_path, "%s/common.xml",
						ni_get_global_config_dir()) < 0) {
				ni_global.config_path = NULL;
				return -1;
			}
		}

		explicit_config = 0;
	}

	if (ni_file_exists(ni_global.config_path)) {
		ni_global.config = ni_config_parse(ni_global.config_path, cb, appdata);
		if (!ni_global.config) {
			ni_error("Unable to parse netinfo configuration file");
			return -1;
		}
	} else {
		if (explicit_config) {
			ni_error("Configuration file %s does not exist",
					ni_global.config_path);
			return -1;
		}
		/* Create empty default configuration */
		ni_global.config = ni_config_new();
	}

	/* Our socket code relies on us ignoring this */
	signal(SIGPIPE, SIG_IGN);

	ni_global.initialized = 1;
	return 0;
}

static inline void
ni_global_assert_initialized(void)
{
	if (!ni_global.initialized)
		ni_fatal("Library not initialized, please call ni_init() first");
}

const char *
ni_get_global_config_dir(void)
{
	if (ni_global.config_dir == NULL)
		return WICKED_CONFIGDIR;
	else
		return ni_global.config_dir;
}

const char *
ni_get_global_config_path(void)
{
	return ni_global.config_path;
}

static ni_bool_t
ni_set_global_config_dir(const char *pathname)
{
	if (pathname == NULL) {
		ni_string_free(&ni_global.config_dir);
		ni_string_free(&ni_global.config_path);
		return TRUE;
	}

	if (ni_isdir(pathname)) {
		char *real = NULL;

		if (*pathname != '/') {
			/* resolve to absolute path */
			if (ni_realpath(pathname, &real) == NULL)
				return FALSE;
			pathname = real;
		}

		if (ni_string_eq(WICKED_CONFIGDIR, pathname))
			pathname = NULL;

		ni_string_dup(&ni_global.config_dir, pathname);
		ni_string_free(&real);

		return TRUE;
	}
	errno = ENOTDIR;
	return FALSE;
}

ni_bool_t
ni_set_global_config_path(const char *pathname)
{
	char *real = NULL;

	if (pathname == NULL) {
		ni_string_free(&ni_global.config_dir);
		ni_string_free(&ni_global.config_path);
		return TRUE;
	}

	if (*pathname != '/') {
		/* resolve to absolute path */
		if (ni_realpath(pathname, &real) == NULL)
			return FALSE;
		pathname = real;
	}

	if (ni_isreg(pathname)) {
		const char *dir;

		if (!(dir = ni_dirname(pathname))) {
			errno = ENAMETOOLONG;
			return FALSE;
		}

		if (!ni_set_global_config_dir(dir))
			return FALSE;

		ni_string_dup(&ni_global.config_path, pathname);
	} else {
		if (!ni_set_global_config_dir(pathname))
			return FALSE;

		ni_string_free(&ni_global.config_path);
	}
	ni_string_free(&real);
	return TRUE;
}

const char *
ni_config_piddir(void)
{
	ni_config_fslocation_t *fsloc = &ni_global.config->piddir;
	static ni_bool_t firsttime = TRUE;

	if (firsttime) {
		if (ni_mkdir_maybe(fsloc->path, fsloc->mode) < 0)
			ni_fatal("Cannot create pid file directory \"%s\": %m", fsloc->path);
		firsttime = FALSE;
	}

	return fsloc->path;
}

const char *
ni_config_storedir(void)
{
	ni_config_fslocation_t *fsloc = &ni_global.config->storedir;
	static ni_bool_t firsttime = TRUE;

	if (firsttime) {
		if (ni_mkdir_maybe(fsloc->path, fsloc->mode) < 0)
			ni_fatal("Cannot create persistent store directory \"%s\": %m", fsloc->path);
		firsttime = FALSE;
	}

	return fsloc->path;
}

const char *
ni_config_statedir(void)
{
	ni_config_fslocation_t *fsloc = &ni_global.config->statedir;
	static ni_bool_t firsttime = TRUE;

	if (firsttime) {
		if (ni_mkdir_maybe(fsloc->path, fsloc->mode) < 0)
			ni_fatal("Cannot create state directory \"%s\": %m", fsloc->path);
		firsttime = FALSE;
	}

	return fsloc->path;
}

const char *
ni_config_backupdir(void)
{
	ni_config_fslocation_t *fsloc = &ni_global.config->backupdir;
	static ni_bool_t firsttime = TRUE;

	if (firsttime) {
		if (ni_mkdir_maybe(fsloc->path, fsloc->mode) < 0)
			ni_fatal("Cannot create backup directory \"%s\": %m", fsloc->path);
		firsttime = FALSE;
	}

	return fsloc->path;
}

static ni_bool_t
ni_config_extension_statedir(const char *extension_dirname, const int mode)
{
	static ni_bool_t res = FALSE;
	char pathname[PATH_MAX];

	if (!res) {
		snprintf(pathname, sizeof(pathname), "%s/%s",
			ni_config_statedir(), extension_dirname);
		if (ni_mkdir_maybe(pathname, mode) < 0) {
			ni_error("Cannot create extension state directory \"%s\": %m", pathname);
			res = FALSE;
		} else {
			res = TRUE;
		}
	}

	return res;
}

const char *
ni_extension_statedir(const char *ex_name)
{
	ni_extension_t *ex = NULL;
	ni_config_fslocation_t *fsloc = NULL;
	const char *extension_dirname = "extension";
	const int mode = 0700;
	char pathname[PATH_MAX];

	if (!(ni_config_extension_statedir(extension_dirname, mode)))
		return NULL;

	if (!(ex = ni_config_find_system_updater(ni_global.config, ex_name)))
		return NULL;

	fsloc = &ex->statedir;

	if (fsloc->path == NULL) {
		snprintf(pathname, sizeof(pathname), "%s/%s/%s",
			ni_config_statedir(), extension_dirname, ex->name);
		if (ni_mkdir_maybe(pathname, mode) < 0) {
			ni_error("Cannot create extension state directory \"%s\": %m", pathname);
		} else {
			ni_config_fslocation_init(fsloc, pathname, mode);
		}
	}

	return fsloc->path;
}

/*
 * Utility functions for starting/stopping the wicked daemon,
 * and for connecting to it
 */
int
ni_server_background(const char *appname, ni_daemon_close_t close_flags)
{
	const char *piddir = ni_config_piddir();
	char pidfilepath[PATH_MAX];

	ni_assert(appname != NULL);
	snprintf(pidfilepath, sizeof(pidfilepath), "%s/%s.pid", piddir, appname);
	return ni_daemonize(pidfilepath, 0644, close_flags);
}

void
ni_server_listen_other_events(void (*event_handler)(ni_event_t))
{
	ni_global.other_event = event_handler;
}

ni_dbus_server_t *
ni_server_listen_dbus(const char *dbus_name)
{
	ni_global_assert_initialized();
	if (dbus_name == NULL)
		dbus_name = ni_global.config->dbus_name;
	if (dbus_name == NULL) {
		ni_error("%s: no bus name specified", __FUNCTION__);
		return NULL;
	}

	return ni_dbus_server_open(ni_global.config->dbus_type, dbus_name, NULL);
}

ni_dbus_client_t *
ni_create_dbus_client(const char *dbus_name)
{
	ni_global_assert_initialized();
	if (dbus_name == NULL)
		dbus_name = ni_global.config->dbus_name;
	if (dbus_name == NULL) {
		ni_error("%s: no bus name specified", __FUNCTION__);
		return NULL;
	}

	return ni_dbus_client_open(ni_global.config->dbus_type, dbus_name);
}

ni_xs_scope_t *
ni_server_dbus_xml_schema(void)
{
	const char *filename = ni_global.config->dbus_xml_schema_file;
	ni_xs_scope_t *scope;

	if (filename == NULL) {
		ni_error("Cannot create dbus xml schema: no schema path configured");
		return NULL;
	}

	scope = ni_dbus_xml_init();
	if (ni_xs_process_schema_file(filename, scope) < 0) {
		ni_error("Cannot create dbus xml schema: error in schema definition");
		ni_xs_scope_free(scope);
		return NULL;
	}

	return scope;
}

/*
 * This is the function used by all wicked code to get the current networking
 * state.
 * If refresh is 0, this will just return the current handle; if it is non-zero,
 * the current state is retrieved.
 */
static inline ni_netconfig_t *
ni_global_state_init(void)
{
	ni_global_assert_initialized();
	if (ni_global.state)
		return ni_global.state;

	if (__ni_global_netlink == NULL) {
		__ni_global_netlink = __ni_netlink_open(0);
		if (__ni_global_netlink == NULL)
			return NULL;
	}

	ni_global.state = ni_netconfig_new();
	return ni_global.state;
}

ni_netconfig_t *
ni_global_state_handle(int refresh)
{
	ni_netconfig_t *nc = ni_global_state_init();

	if (nc && refresh) {
		if (__ni_system_refresh_interfaces(nc) < 0) {
			ni_error("failed to refresh interface list");
			return NULL;
		}

		if (!nc->initialized) {
			ni_openvpn_discover(nc);
			nc->initialized = 1;
		}
	}

	return nc;
}

/*
 * Constructor/destructor for netconfig handles
 */
ni_netconfig_t *
ni_netconfig_new(void)
{
	ni_netconfig_t *nc;

	nc = xcalloc(1, sizeof(*nc));
	return nc;
}

void
ni_netconfig_free(ni_netconfig_t *nc)
{
	ni_netconfig_destroy(nc);
	free(nc);
}

void
ni_netconfig_init(ni_netconfig_t *nc)
{
	memset(nc, 0, sizeof(*nc));
}

void
ni_netconfig_destroy(ni_netconfig_t *nc)
{
	__ni_netdev_list_destroy(&nc->interfaces);
	ni_rule_array_destroy(&nc->route.rules);
	memset(nc, 0, sizeof(*nc));
}

/*
 * apply filter
 */
ni_bool_t
ni_netconfig_set_discover_filter(ni_netconfig_t *nc, unsigned int flag)
{
	if (nc) {
		nc->filter.discover |= flag;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_netconfig_discover_filtered(ni_netconfig_t *nc, unsigned int flag)
{
	return nc && nc->filter.discover & flag;
}

ni_bool_t
ni_netconfig_set_family_filter(ni_netconfig_t *nc, unsigned int family)
{
	if (nc) {
		nc->filter.family = family;
		return TRUE;
	}
	return FALSE;
}

unsigned int
ni_netconfig_get_family_filter(ni_netconfig_t *nc)
{
	return nc ? nc->filter.family : AF_UNSPEC;
}

/*
 * Get the list of all discovered interfaces, given a
 * netinfo handle.
 */
ni_netdev_t *
ni_netconfig_devlist(ni_netconfig_t *nc)
{
	return nc->interfaces;
}

ni_netdev_t **
ni_netconfig_device_list_head(ni_netconfig_t *nc)
{
	return &nc->interfaces;
}

void
ni_netconfig_device_append(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	__ni_netdev_list_append(&nc->interfaces, dev);
}

static inline void
ni_netconfig_device_unbind_ports(ni_netconfig_t *nc, unsigned int master)
{
	ni_netdev_t *dev;

	for (dev = nc->interfaces; dev; dev = dev->next) {
		if (dev->link.masterdev.index == master) {
			ni_netdev_ref_destroy(&dev->link.masterdev);
			ni_netdev_port_info_destroy(&dev->link.port);
		}
	}
}

void
ni_netconfig_device_remove(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	ni_netdev_t **pos, *cur;

	for (pos = &nc->interfaces; (cur = *pos) != NULL; pos = &cur->next) {
		if (cur == dev) {
			*pos = cur->next;
			ni_netconfig_device_unbind_ports(nc, cur->link.ifindex);
			ni_netdev_put(cur);
			return;
		}
	}
}

/*
 * Manage the list of modem devices
 */
ni_modem_t *
ni_netconfig_modem_list(ni_netconfig_t *nc)
{
	return nc->modems;
}

void
ni_netconfig_modem_append(ni_netconfig_t *nc, ni_modem_t *modem)
{
	ni_modem_t **tail;

	ni_assert(!modem->list.prev && !modem->list.next);
	tail = &nc->modems;
	while (*tail)
		tail = &(*tail)->list.next;

	modem->list.prev = tail;
	*tail = modem;
}

/*
 * Manage routing tables
 */
int
ni_netconfig_route_add(ni_netconfig_t *nc, ni_route_t *rp, ni_netdev_t *dev)
{
	ni_stringbuf_t  buf = NI_STRINGBUF_INIT_DYNAMIC;
	ni_uint_array_t idx = NI_UINT_ARRAY_INIT;
	ni_route_nexthop_t *nh;
	int ret = 1;

	/* dev is only a hint */
	if (!nc || !rp)
		return -1;

	for (nh = &rp->nh; ret != -1 && nh; nh = nh->next) {
		if (nh->device.index == 0 ||
		    ni_uint_array_contains(&idx, nh->device.index))
			continue;

		if (!dev || (nh->device.index != dev->link.ifindex)) {
			dev = ni_netdev_by_index(nc, nh->device.index);
		}

		if (!dev) {
			ni_warn("Unable to find route device with index %u: %s",
				nh->device.index, ni_route_print(&buf, rp));
			ni_stringbuf_destroy(&buf);
			ret = -1;
		} else
		if (!ni_route_tables_find_match(dev->routes, rp, ni_route_equal_ref) &&
		    !ni_route_tables_add_route(&dev->routes, rp)) {
			ni_warn("Unable to record route for device %s[%u]: %s",
				dev->name, dev->link.ifindex, ni_route_print(&buf, rp));
			ni_stringbuf_destroy(&buf);
			ret = -1;
		} else
		if (!ni_uint_array_append(&idx, nh->device.index)) {
			ni_warn("Unable to track route device index %u",
				nh->device.index);
			ret = -1;
		} else {
			ni_string_dup(&nh->device.name, dev->name);
			ret = 0;

			if (ni_log_level_at(NI_LOG_DEBUG2)) {
				ni_debug_ifconfig("Route recorded for device %s[%u]: %s [owner %s]",
						dev->name, dev->link.ifindex, ni_route_print(&buf, rp),
						ni_addrconf_type_to_name(rp->owner));
				ni_stringbuf_destroy(&buf);
			}
		}
	}

	if (ret == 1 && ni_log_level_at(NI_LOG_DEBUG1)) {
		ni_debug_ifconfig("Route not recorded for any device: %s [owner %s]",
				ni_route_print(&buf, rp), ni_addrconf_type_to_name(rp->owner));
		ni_stringbuf_destroy(&buf);
	}

	ni_uint_array_destroy(&idx);
	return ret;
}

int
ni_netconfig_route_del(ni_netconfig_t *nc, ni_route_t *rp, ni_netdev_t *dev)
{
	ni_route_nexthop_t *nh;
	int ret = 1;

	/* dev is only a hint */
	if (!nc || !ni_route_ref(rp))
		return -1;

	if (dev && ni_route_tables_del_route(dev->routes, rp))
		ret = 0;

	for (nh = &rp->nh; nh; nh = nh->next) {
		if (!nh->device.index)
			continue;

		if (dev && nh->device.index == dev->link.ifindex)
			continue;

		if (!(dev = ni_netdev_by_index(nc, nh->device.index)))
			continue;

		if (ni_route_tables_del_route(dev->routes, rp))
			ret = 0;
	}

	ni_route_free(rp);
	return ret;
}

ni_rule_array_t *
ni_netconfig_rule_array(ni_netconfig_t *nc)
{
	return nc ? &nc->route.rules : NULL;
}

int
ni_netconfig_rule_add(ni_netconfig_t *nc, ni_rule_t *rule)
{
	unsigned int i, last = 0;
	ni_rule_array_t *rules;
	const ni_rule_t *r;

	if (!(rules = ni_netconfig_rule_array(nc)) || !rule)
		return -1;

	for (i = 0; i < rules->count; ++i) {
		r = rules->data[i];
		if (r->pref > rule->pref)
			break;
		last = i + 1;
	}

	if (!ni_rule_array_insert_ref(rules, last, rule)) {
		ni_error("%s: unable to insert routing policy rule", __func__);
		return -1;
	}

	return 0;
}

int
ni_netconfig_rule_del(ni_netconfig_t *nc, const ni_rule_t *rule, ni_rule_t **pdel)
{
	ni_rule_array_t *rules;
	unsigned int i;
	ni_rule_t *r;

	if (!(rules = ni_netconfig_rule_array(nc)) || !rule)
		return -1;

	for (i = 0; i < rules->count; ++i) {
		r = rules->data[i];
		if (!ni_rule_equal(r, rule))
			continue;

		if (pdel) {
			*pdel = ni_rule_array_remove_at(rules, i);
			if (!*pdel) {
				ni_error("%s: unable to remove policy rule", __func__);
				return -1;
			}
		} else {
			if (!ni_rule_array_delete_at(rules, i)) {
				ni_error("%s: unable to remove policy rule", __func__);
				return -1;
			}
		}

		return 0;
	}
	return 1;
}

ni_rule_t *
ni_netconfig_rule_find(ni_netconfig_t *nc, const ni_rule_t *rule)
{
	ni_rule_array_t *rules;
	unsigned int i;
	ni_rule_t *r;

	if (!(rules = ni_netconfig_rule_array(nc)) || !rule)
		return NULL;

	for (i = 0; i < rules->count; ++i) {
		r = rules->data[i];
		if (ni_rule_equal(r, rule))
			return r;
	}
	return NULL;
}


/*
 * Find interface by name
 */
ni_netdev_t *
ni_netdev_by_name(ni_netconfig_t *nc, const char *name)
{
	ni_netdev_t *dev;

	if (!nc && !(nc = ni_global_state_handle(0)))
		return NULL;

	for (dev = nc->interfaces; dev; dev = dev->next) {
		if (dev->name && ni_string_eq(dev->name, name))
			return dev;
	}

	return NULL;
}

/*
 * Find interface by its ifindex
 */
ni_netdev_t *
ni_netdev_by_index(ni_netconfig_t *nc, unsigned int ifindex)
{
	ni_netdev_t *dev;

	if (!nc && !(nc = ni_global_state_handle(0)))
		return NULL;

	for (dev = nc->interfaces; dev; dev = dev->next) {
		if (dev->link.ifindex == ifindex)
			return dev;
	}

	return NULL;
}

/*
 * Find interface by its LL address
 */
ni_netdev_t *
ni_netdev_by_hwaddr(ni_netconfig_t *nc, const ni_hwaddr_t *lla)
{
	ni_netdev_t *dev;

	if (!lla || !lla->len)
		return NULL;

	if (!nc && !(nc = ni_global_state_handle(0)))
		return NULL;

	for (dev = nc->interfaces; dev; dev = dev->next) {
		if (ni_link_address_equal(&dev->link.hwaddr, lla))
			return dev;
	}

	return NULL;
}

/*
 * Find network interface by iftype
 */
ni_netdev_t *
ni_netdev_by_iftype(ni_netconfig_t *nc, ni_iftype_t iftype)
{
	ni_netdev_t *dev;

	if (!nc && !(nc = ni_global_state_handle(0)))
		return NULL;

	for (dev = nc->interfaces; dev; dev = dev->next) {
		if (dev->link.type == iftype)
			return dev;
	}

	return NULL;
}

/*
 * Find VLAN interface by its tag
 */
ni_netdev_t *
ni_netdev_by_vlan_name_and_tag(ni_netconfig_t *nc, const char *parent_name, uint16_t tag)
{
	ni_netdev_t *dev;

	if (!parent_name || !tag)
		return NULL;

	if (!nc && !(nc = ni_global_state_handle(0)))
		return NULL;

	for (dev = nc->interfaces; dev; dev = dev->next) {
		if (dev->link.type == NI_IFTYPE_VLAN
		 && dev->vlan
		 && dev->vlan->tag == tag
		 && dev->link.lowerdev.name
		 && !strcmp(dev->link.lowerdev.name, parent_name))
			return dev;
	}

	return NULL;
}

unsigned int
ni_netdev_name_to_index(const char *name)
{
	if (ni_string_empty(name))
		return 0;

	return if_nametoindex(name);
}

const char *
ni_netdev_index_to_name(char **ifname, unsigned int ifindex)
{
	char ifnamebuf[IFNAMSIZ] = {'\0'};

	if (!ifname || !ifindex)
		return NULL;

	if (!if_indextoname(ifindex, ifnamebuf))
		return NULL;

	if (!ni_string_dup(ifname, ifnamebuf))
		return NULL;

	return *ifname;
}

/*
 * Create a unique interface name
 */
const char *
ni_netdev_make_name(ni_netconfig_t *nc, const char *stem, unsigned int first)
{
	static char namebuf[IFNAMSIZ];
	unsigned int num;

	for (num = first; num < 65536; ++num) {
		snprintf(namebuf, sizeof(namebuf), "%s%u", stem, num);
		if (!ni_netdev_by_name(nc, namebuf))
			return namebuf;
	}

	return NULL;
}

/*
 * Get port count and optionally an array of port netdev
 * references for the given netdev (index).
 */
static unsigned int
ni_netdev_get_ovsbr_ports_by_index(unsigned int index, ni_netdev_ref_array_t *ports,
		ni_netconfig_t *nc)
{
	unsigned int count = ports ? ports->count : 0;
	ni_ovs_bridge_port_info_t *pinfo;
	ni_netdev_t *dev;

	if (!index || (!nc && !(nc = ni_global_state_handle(0))))
		return count;

	for (dev = nc->interfaces; dev; dev = dev->next) {
		if (dev->link.port.type != NI_IFTYPE_OVS_BRIDGE)
			continue;

		if (!(pinfo = dev->link.port.ovsbr))
			continue;

		if (index != pinfo->bridge.index)
			continue;

		if (ports)
			ni_netdev_ref_array_append(ports, dev->name,
					dev->link.ifindex);
		else
			count++;
	}

	return ports ? ports->count - count : count;
}

static unsigned int
ni_netdev_get_ports_by_index(unsigned int index, ni_netdev_ref_array_t *ports,
		ni_netconfig_t *nc)
{
	unsigned int count = ports ? ports->count : 0;
	ni_netdev_t *dev;

	if (!index || (!nc && !(nc = ni_global_state_handle(0))))
		return count;

	for (dev = nc->interfaces; dev; dev = dev->next) {
		if (dev->link.masterdev.index != index)
			continue;

		if (ports)
			ni_netdev_ref_array_append(ports, dev->name,
					dev->link.ifindex);
		else
			count++;
	}

	return ports ? ports->count - count : count;
}

extern unsigned int
ni_netdev_get_ports(const ni_netdev_t *dev, ni_netdev_ref_array_t *ports,
		ni_netconfig_t *nc)
{
	unsigned int index;

	if (!dev)
		return ports ? ports->count : 0;

	index = dev->link.ifindex;
	if (dev->link.type == NI_IFTYPE_OVS_BRIDGE)
		return ni_netdev_get_ovsbr_ports_by_index(index, ports, nc);
	else
		return ni_netdev_get_ports_by_index(index, ports, nc);
}

/*
 * Resolve port's master reference to netdev
 */
const ni_netdev_ref_t *
ni_netdev_get_master_ref(const ni_netdev_t *dev)
{
	if (!dev)
		return NULL;

	if (dev->link.port.type == NI_IFTYPE_OVS_BRIDGE) {
		ni_ovs_bridge_port_info_t *ovsbr;

		if (!(ovsbr = dev->link.port.ovsbr))
			return NULL;

		return &ovsbr->bridge;
	}

	return &dev->link.masterdev;
}

ni_netdev_t *
ni_netdev_resolve_master(const ni_netdev_t *dev, ni_netconfig_t *nc)
{
	const ni_netdev_ref_t *ref;

	if ((ref = ni_netdev_get_master_ref(dev)))
		return ni_netdev_ref_resolve(ref, nc);

	return NULL;
}

/*
 * netdev reference
 */
ni_bool_t
ni_netdev_ref_init(ni_netdev_ref_t *ref)
{
	if (ref) {
		memset(ref, 0, sizeof(*ref));
		ref->ns_id = NI_NETNSID_DEFAULT;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_netdev_ref_copy(ni_netdev_ref_t *dst, const ni_netdev_ref_t *src)
{
	if (dst && src) {
		ni_netdev_ref_destroy(dst);
		if (ni_string_dup(&dst->name, src->name)) {
			dst->index = src->index;
			dst->ns_id = src->ns_id;
		}
		return TRUE;
	}
	return FALSE;
}


ni_bool_t
ni_netdev_ref_set(ni_netdev_ref_t *ref, const char *ifname, unsigned int ifindex)
{
	if (ref && ni_string_dup(&ref->name, ifname)) {
		ref->index = ifindex;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_netdev_ref_set_ifname(ni_netdev_ref_t *ref, const char *ifname)
{
	return ref && ni_string_dup(&ref->name, ifname);
}

ni_bool_t
ni_netdev_ref_set_ifindex(ni_netdev_ref_t *ref, unsigned int ifindex)
{
	if (ref) {
		ref->index = ifindex;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_netdev_ref_set_netnsid(ni_netdev_ref_t *ref, unsigned int ns_id)
{
	if (ref) {
		ref->ns_id = ns_id;
		return TRUE;
	}
	return FALSE;
}

ni_netdev_t *
ni_netdev_ref_resolve(const ni_netdev_ref_t *ref, ni_netconfig_t *nc)
{
	ni_netdev_t *dev = NULL;

	if (!ref || (!nc && !(nc = ni_global_state_handle(0))))
		return NULL;

	if (ref->ns_id != NI_NETNSID_DEFAULT)
		return NULL;

	if (ref->index && (dev = ni_netdev_by_index(nc, ref->index)))
		return dev;

	if (ref->name && (dev = ni_netdev_by_name(nc, ref->name)))
		return dev;

	return NULL;
}

ni_netdev_t *
ni_netdev_ref_bind_ifname(ni_netdev_ref_t *ref, ni_netconfig_t *nc)
{
	ni_netdev_t *dev;

	if (!ref || (!nc && !(nc = ni_global_state_handle(0))))
		return NULL;

	if (ref->ns_id != NI_NETNSID_DEFAULT)
		return NULL;

	dev = ni_netdev_by_index(nc, ref->index);
	if (dev == NULL)
		return NULL;

	if (!ni_string_eq(ref->name, dev->name))
		ni_string_dup(&ref->name, dev->name);
	return dev;
}

ni_netdev_t *
ni_netdev_ref_bind_ifindex(ni_netdev_ref_t *ref, ni_netconfig_t *nc)
{
	ni_netdev_t *dev;

	if (!ref || (!nc && !(nc = ni_global_state_handle(0))))
		return NULL;

	if (ref->ns_id != NI_NETNSID_DEFAULT)
		return NULL;

	dev = ni_netdev_by_name(nc, ref->name);
	if (dev == NULL)
		return NULL;

	ref->index = dev->link.ifindex;
	return dev;
}

void
ni_netdev_ref_destroy(ni_netdev_ref_t *ref)
{
	if (ref) {
		ref->ns_id = NI_NETNSID_DEFAULT;
		ref->index = 0;
		ni_string_free(&ref->name);
	}
}

ni_bool_t
ni_netdev_ref_array_init(ni_netdev_ref_array_t *array)
{
	if (array) {
		memset(array, 0, sizeof(*array));
		return TRUE;
	}
	return FALSE;
}

const ni_netdev_ref_t *
ni_netdev_ref_array_at(const ni_netdev_ref_array_t *array, unsigned int i)
{
	if (!array || i >= array->count)
		return NULL;
	return &array->data[i];
}

const ni_netdev_ref_t *
ni_netdev_ref_array_find_index(const ni_netdev_ref_array_t *array, unsigned int index)
{
	const ni_netdev_ref_t *ref;
	unsigned int i;

	if (!array)
		return NULL;

	for (i = 0; i < array->count; ++i) {
		ref = &array->data[i];
		if (ref->index == index)
			return ref;
	}
	return NULL;
}

const ni_netdev_ref_t *
ni_netdev_ref_array_find_name(const ni_netdev_ref_array_t *array, const char *name)
{
	const ni_netdev_ref_t *ref;
	unsigned int i;

	if (!array)
		return NULL;

	for (i = 0; i < array->count; ++i) {
		ref = &array->data[i];
		if (ni_string_eq(ref->name, name))
			return ref;
	}
	return NULL;
}

static ni_bool_t
ni_netdev_ref_array_realloc(ni_netdev_ref_array_t *array, unsigned int count)
{
	ni_netdev_ref_t *newdata;
	size_t           newsize;
	unsigned int     i;

	if ((UINT_MAX - array->count) <= count)
		return FALSE;

	newsize = array->count + count;
	if ((SIZE_MAX / sizeof(*newdata)) < newsize)
		return FALSE;

	newdata = realloc(array->data, newsize * sizeof(*newdata));
	if (!newdata)
		return FALSE;

	array->data = newdata;
	for (i = array->count; i < newsize; ++i)
		ni_netdev_ref_init(&array->data[i]);
	return TRUE;
}

const ni_netdev_ref_t *
ni_netdev_ref_array_append(ni_netdev_ref_array_t *array, const char *name, unsigned int index)
{
	ni_netdev_ref_t *item;

	if (!array || ((array->count % NI_NETDEV_REF_ARRAY_CHUNK) == 0 &&
	    !ni_netdev_ref_array_realloc(array, NI_NETDEV_REF_ARRAY_CHUNK)))
		return NULL;

	item = &array->data[array->count++];
	ni_netdev_ref_set(item, name, index);
	return item;
}

void
ni_netdev_ref_array_destroy(ni_netdev_ref_array_t *array)
{
	ni_netdev_ref_t *item;

	if (array) {
		while (array->count) {
			array->count--;
			item = &array->data[array->count];
			ni_netdev_ref_destroy(item);
		}
		free(array->data);
		array->data = NULL;
	}
}

/*
 * Handle netdev request port config
 */
ni_bool_t
ni_netdev_port_config_init(ni_netdev_port_config_t *conf, ni_iftype_t type)
{
	if (conf) {
		memset(conf, 0, sizeof(*conf));

		switch (type) {
		case NI_IFTYPE_BOND:
			if (!(conf->bond = ni_bonding_port_config_new()))
				return FALSE;
			break;

		case NI_IFTYPE_TEAM:
			if (!(conf->team = ni_team_port_config_new()))
				return FALSE;
			break;

		case NI_IFTYPE_BRIDGE:
			if (!(conf->bridge = ni_bridge_port_config_new()))
				return FALSE;
			break;

		case NI_IFTYPE_OVS_BRIDGE:
			if (!(conf->ovsbr = ni_ovs_bridge_port_config_new()))
				return FALSE;
			break;

		default:
			break;
		}
		conf->type = type;

		return TRUE;
	}
	return FALSE;
}
void
ni_netdev_port_config_destroy(ni_netdev_port_config_t *conf)
{
	if (conf) {
		switch (conf->type) {
		case NI_IFTYPE_BOND:
			ni_bonding_port_config_free(conf->bond);
			break;

		case NI_IFTYPE_TEAM:
			ni_team_port_config_free(conf->team);
			break;

		case NI_IFTYPE_BRIDGE:
			ni_bridge_port_config_free(conf->bridge);
			break;

		case NI_IFTYPE_OVS_BRIDGE:
			ni_ovs_bridge_port_config_free(conf->ovsbr);
			break;

		default:
			break;
		}

		memset(conf, 0, sizeof(*conf));
	}
}

/*
 * Handle interface_request objects
 */
ni_netdev_req_t *
ni_netdev_req_new(void)
{
	ni_netdev_req_t *req;

	req = xcalloc(1, sizeof(*req));
	if (req)
		ni_netdev_ref_init(&req->master);
	return req;
}

void
ni_netdev_req_free(ni_netdev_req_t *req)
{
	ni_string_free(&req->alias);
	ni_netdev_ref_destroy(&req->master);
	ni_netdev_port_config_destroy(&req->port);
	free(req);
}

