/*
 * Routines for detecting and monitoring network interfaces.
 *
 * Copyright (C) 2009-2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <signal.h>
#include <limits.h>
#include <errno.h>

#include <wicked/netinfo.h>
#include <wicked/route.h>
#include <wicked/addrconf.h>
#include <wicked/team.h>
#include <wicked/bridge.h>
#include <wicked/bonding.h>
#include <wicked/ethernet.h>
#include <wicked/wireless.h>
#include <wicked/vlan.h>
#include <wicked/openvpn.h>
#include <wicked/socket.h>
#include <wicked/resolver.h>
#include <wicked/nis.h>
#include "netinfo_priv.h"
#include "util_priv.h"
#include "dbus-server.h"
#include "appconfig.h"
#include "xml-schema.h"
#include "sysfs.h"
#include "modem-manager.h"
#include "dhcp6/options.h"
#include <gcrypt.h>

extern void		ni_addrconf_updater_free(ni_addrconf_updater_t **);

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
 * gcry_check_version checks for minmum version
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

void
ni_netconfig_device_remove(ni_netconfig_t *nc, ni_netdev_t *dev)
{
	ni_netdev_t **pos, *cur;

	for (pos = &nc->interfaces; (cur = *pos) != NULL; pos = &cur->next) {
		if (cur == dev) {
			*pos = cur->next;
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
		    !ni_route_tables_add_route(&dev->routes, ni_route_ref(rp))) {
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

	if (!ni_rule_array_insert(rules, last, ni_rule_ref(rule))) {
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
			*pdel = ni_rule_array_remove(rules, i);
			if (!*pdel) {
				ni_error("%s: unable to remove policy rule", __func__);
				return -1;
			}
		} else {
			if (!ni_rule_array_delete(rules, i)) {
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

	for (dev = nc->interfaces; dev; dev = dev->next) {
		if (ni_link_address_equal(&dev->link.hwaddr, lla))
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

/*
 * Create a unique interface name
 */
const char *
ni_netdev_make_name(ni_netconfig_t *nc, const char *stem, unsigned int first)
{
	static char namebuf[64];
	unsigned int num;

	for (num = first; num < 65536; ++num) {
		snprintf(namebuf, sizeof(namebuf), "%s%u", stem, num);
		if (!ni_netdev_by_name(nc, namebuf))
			return namebuf;
	}

	return NULL;
}

/*
 * netdev reference
 */
ni_bool_t
ni_netdev_ref_init(ni_netdev_ref_t *ref, const char *ifname, unsigned int ifindex)
{
	if (ref) {
		memset(ref, 0, sizeof(*ref));
		ni_string_dup(&ref->name, ifname);
		ref->index = ifindex;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_netdev_ref_set(ni_netdev_ref_t *ref, const char *ifname, unsigned int ifindex)
{
	if (ref) {
		ni_string_dup(&ref->name, ifname);
		ref->index = ifindex;
		return TRUE;
	}
	return FALSE;
}

ni_bool_t
ni_netdev_ref_set_ifname(ni_netdev_ref_t *ref, const char *ifname)
{
	if (ref) {
		ni_string_dup(&ref->name, ifname);
		return TRUE;
	}
	return FALSE;
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

ni_netdev_t *
ni_netdev_ref_resolve(ni_netdev_ref_t *ref, ni_netconfig_t *nc)
{
	ni_netdev_t *dev = NULL;

	if (!ref || (!nc && !(nc = ni_global_state_handle(0))))
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
		ref->index = 0;
		ni_string_free(&ref->name);
	}
}

/*
 * Handle netdev request port config
 */
static void
ni_netdev_port_req_init(ni_netdev_port_req_t *port)
{
	switch (port->type) {
        case NI_IFTYPE_TEAM:
		ni_team_port_config_init(&port->team);
		break;

	case NI_IFTYPE_OVS_BRIDGE:
		ni_ovs_bridge_port_config_init(&port->ovsbr);
		break;

	case NI_IFTYPE_BOND:
	case NI_IFTYPE_BRIDGE:
	default:
		break;
	}
}

ni_netdev_port_req_t *
ni_netdev_port_req_new(ni_iftype_t master)
{
	ni_netdev_port_req_t *port;

	switch (master) {
	case NI_IFTYPE_TEAM:
	case NI_IFTYPE_BOND:
	case NI_IFTYPE_BRIDGE:
	case NI_IFTYPE_OVS_BRIDGE:
		port = xcalloc(1, sizeof(*port));
		port->type = master;
		ni_netdev_port_req_init(port);
		return port;
	default:
		return NULL;
	}
}

void
ni_netdev_port_req_free(ni_netdev_port_req_t *port)
{
	if (port) {
		switch (port->type) {
		case NI_IFTYPE_TEAM:
			ni_team_port_config_destroy(&port->team);
			break;

		case NI_IFTYPE_OVS_BRIDGE:
			ni_ovs_bridge_port_config_destroy(&port->ovsbr);
			break;

		case NI_IFTYPE_BOND:
		case NI_IFTYPE_BRIDGE:
		default:
			break;
		}
		free(port);
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
	return req;
}

void
ni_netdev_req_free(ni_netdev_req_t *req)
{
	ni_string_free(&req->alias);
	ni_netdev_ref_destroy(&req->master);
	ni_netdev_port_req_free(req->port);
	free(req);
}

/*
 * Address configuration state (aka leases)
 */
ni_addrconf_lease_t *
ni_addrconf_lease_new(int type, int family)
{
	ni_addrconf_lease_t *lease;

	lease = calloc(1, sizeof(*lease));
	lease->seqno = __ni_global_seqno++;
	lease->type = type;
	lease->family = family;
	ni_config_addrconf_update_mask(lease->type, lease->family);
	return lease;
}

void
ni_addrconf_lease_free(ni_addrconf_lease_t *lease)
{
	ni_addrconf_lease_destroy(lease);
	free(lease);
}

static void
ni_addrconf_lease_dhcp4_destroy(struct ni_addrconf_lease_dhcp4 *dhcp4)
{
	if (dhcp4) {
		ni_string_free(&dhcp4->boot_sname);
		ni_string_free(&dhcp4->boot_file);
		ni_string_free(&dhcp4->root_path);
		ni_string_free(&dhcp4->message);
	}
}

static void
ni_addrconf_lease_dhcp6_destroy(struct ni_addrconf_lease_dhcp6 *dhcp6)
{
	if (dhcp6) {
		ni_dhcp6_status_destroy(&dhcp6->status);
		ni_dhcp6_ia_list_destroy(&dhcp6->ia_list);

		ni_string_free(&dhcp6->boot_url);
		ni_string_array_destroy(&dhcp6->boot_params);
	}
}

void
ni_addrconf_lease_destroy(ni_addrconf_lease_t *lease)
{
	ni_addrconf_updater_free(&lease->updater);
	if (lease->old) {
		ni_addrconf_lease_free(lease->old);
		lease->old = NULL;
	}

	ni_string_free(&lease->owner);
	ni_string_free(&lease->hostname);

	ni_address_list_destroy(&lease->addrs);
	ni_route_tables_destroy(&lease->routes);

	if (lease->rules) {
		ni_rule_array_free(lease->rules);
		lease->rules = NULL;
	}

	if (lease->nis) {
		ni_nis_info_free(lease->nis);
		lease->nis = NULL;
	}
	if (lease->resolver) {
		ni_resolver_info_free(lease->resolver);
		lease->resolver = NULL;
	}

	ni_string_array_destroy(&lease->ntp_servers);
	ni_string_array_destroy(&lease->nds_servers);
	ni_string_array_destroy(&lease->nds_context);
	ni_string_free(&lease->nds_tree);
	ni_string_array_destroy(&lease->netbios_name_servers);
	ni_string_array_destroy(&lease->netbios_dd_servers);
	ni_string_free(&lease->netbios_scope);
	ni_string_array_destroy(&lease->slp_servers);
	ni_string_array_destroy(&lease->slp_scopes);
	ni_string_array_destroy(&lease->sip_servers);
	ni_string_array_destroy(&lease->lpr_servers);
	ni_string_array_destroy(&lease->log_servers);

	ni_string_free(&lease->posix_tz_string);
	ni_string_free(&lease->posix_tz_dbname);

	switch (lease->type) {
	case NI_ADDRCONF_DHCP:

		switch (lease->family) {
		case AF_INET:
			ni_addrconf_lease_dhcp4_destroy(&lease->dhcp4);
			break;

		case AF_INET6:
			ni_addrconf_lease_dhcp6_destroy(&lease->dhcp6);
			break;

		default: ;
		}

		break;

	default: ;
	}
}

void
ni_addrconf_lease_list_destroy(ni_addrconf_lease_t **list)
{
	ni_addrconf_lease_t *lease;

	while ((lease = *list) != NULL) {
		*list = lease->next;
		ni_addrconf_lease_free(lease);
	}
}

unsigned int
ni_addrconf_lease_get_priority(const ni_addrconf_lease_t *lease)
{
	if (!lease)
		return 0;

	switch (lease->type) {
	case NI_ADDRCONF_STATIC:
		return 2;

	case NI_ADDRCONF_DHCP:
	case NI_ADDRCONF_INTRINSIC:
		return 1;

	case NI_ADDRCONF_AUTOCONF:
	default:
		return 0;
	}
}
