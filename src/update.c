/*
 * Update system settings with information received from an addrconf service.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include <wicked/netinfo.h>
#include <wicked/logging.h>
#include <wicked/addrconf.h>
#include <wicked/system.h>
#include <wicked/resolver.h>
#include <wicked/leaseinfo.h>

#include "netinfo_priv.h"
#include "util_priv.h"
#include "process.h"
#include "appconfig.h"
#include "debug.h"

/* secs we try to reverse resolve hostnames */
#ifndef NI_UPDATER_REVERSE_TIMEOUT
#define NI_UPDATER_REVERSE_TIMEOUT	2
#endif
/* how many lease addresses we try out */
#ifndef NI_UPDATER_REVERSE_MAX_CNT
#define NI_UPDATER_REVERSE_MAX_CNT	1
#endif

#define	NI_UPDATER_SOURCE_ARRAY_CHUNK	4
#define	NI_UPDATER_SOURCE_ARRAY_INIT	{ 0, NULL }

typedef struct ni_updater_source	ni_updater_source_t;
struct ni_updater_source {
	unsigned int			users;

	unsigned int			seqno;		/* sequence number of lease */
	ni_netdev_ref_t			d_ref;
	const ni_addrconf_lease_t *	lease;
};

typedef struct ni_updater_source_array	ni_updater_source_array_t;
struct ni_updater_source_array {
	unsigned int			count;
	ni_updater_source_t **		data;
};

typedef struct ni_updater {
	ni_updater_source_array_t	sources;

	unsigned int			kind;
	int				format;
	ni_bool_t			enabled;
	unsigned int			have_backup;

	ni_shellcmd_t *			proc_backup;
	ni_shellcmd_t *			proc_restore;
	ni_shellcmd_t *			proc_install;
	ni_shellcmd_t *			proc_remove;
} ni_updater_t;

static ni_updater_t			updaters[__NI_ADDRCONF_UPDATER_MAX];

static const ni_intmap_t		__ni_updater_format_names[] = {
	{ "info",		NI_ADDRCONF_UPDATER_FORMAT_INFO	},
	{ NULL,			NI_ADDRCONF_UPDATER_FORMAT_NONE }
};

static const ni_intmap_t		__ni_updater_kind_names[] = {
	{ "hostname",		NI_ADDRCONF_UPDATER_HOSTNAME	},
	{ "resolver",		NI_ADDRCONF_UPDATER_RESOLVER	},
	{ "generic",		NI_ADDRCONF_UPDATER_GENERIC	},
	{ NULL,			__NI_ADDRCONF_UPDATER_MAX	}
};

static const char *			ni_updater_name(unsigned int kind);
static unsigned int			ni_updater_format_type(const char * format);
static const char *			ni_updater_format_name(unsigned int format);

static ni_updater_source_t *
ni_updater_source_new(void)
{
	ni_updater_source_t *src;

	src = xcalloc(1, sizeof(*src));
	src->users = 1;
	return src;
}

static ni_updater_source_t *
ni_updater_source_ref(ni_updater_source_t *src)
{
	if (src) {
		ni_assert(src->users);
		src->users++;

		return src;
	}
	return NULL;
}

static void
ni_updater_source_free(ni_updater_source_t *src)
{
	if (src) {
		ni_assert(src->users);
		src->users--;

		if (src->users == 0) {
			src->seqno = 0;
			src->lease = NULL;
			ni_netdev_ref_destroy(&src->d_ref);
			free(src);
		}
	}
}

static inline void
ni_updater_source_array_init(ni_updater_source_array_t *usa)
{
	memset(usa, 0, sizeof(*usa));
}

static void
ni_updater_source_array_destroy(ni_updater_source_array_t *usa)
{
	if (usa) {
		while (usa->count) {
			usa->count--;
			ni_updater_source_free(usa->data[usa->count]);
		}
		ni_updater_source_array_init(usa);
	}
}

static void
__ni_updater_source_array_realloc(ni_updater_source_array_t *usa, unsigned int newsize)
{
	unsigned int i;

	newsize = (newsize + NI_UPDATER_SOURCE_ARRAY_CHUNK);
	usa->data = xrealloc(usa->data, newsize * sizeof(ni_updater_source_t *));

	for (i = usa->count; i < newsize; ++i)
		usa->data[i] = NULL;
}

static ni_bool_t
ni_updater_source_array_append(ni_updater_source_array_t *usa, ni_updater_source_t *src)
{
	if (!usa || !src)
		return FALSE;

	if ((usa-> count % NI_UPDATER_SOURCE_ARRAY_CHUNK) == 0)
		__ni_updater_source_array_realloc(usa, usa->count);

	usa->data[usa->count++] = src;
	return TRUE;
}

static ni_updater_source_t *
ni_updater_source_array_remove(ni_updater_source_array_t *usa, unsigned int index)
{
	ni_updater_source_t *ptr;

	if (!usa || index >= usa->count)
		return NULL;

	ptr = usa->data[index];
	usa->count--;
	if (index < usa->count) {
		memmove(&usa->data[index], &usa->data[index + 1],
			(usa->count - index) * sizeof(ni_updater_source_t *));
	}
	usa->data[usa->count] = NULL;

	/* Don't bother with shrinking the array. It's not worth the trouble */
	return ptr;
}

static ni_bool_t
ni_updater_source_array_delete(ni_updater_source_array_t *usa, unsigned int index)
{
	ni_updater_source_t *ptr;

	if ((ptr = ni_updater_source_array_remove(usa, index))) {
		ni_updater_source_free(ptr);
		return TRUE;
	}
	return FALSE;
}

/*
 * Initialize the system updaters based on the data found in the config
 * file.
 */
void
ni_system_updaters_init(void)
{
	static int initialized = 0;
	unsigned int kind;

	if (initialized)
		return;
	initialized = 1;

	for (kind = 0; kind < __NI_ADDRCONF_UPDATER_MAX; ++kind) {
		ni_updater_t *updater = &updaters[kind];
		const char *name = ni_updater_name(kind);
		ni_extension_t *ex;

		updater->enabled = FALSE;
		updater->kind = kind;
		if (name == NULL)
			continue;

		if (!(ex = ni_config_find_system_updater(ni_global.config, name)))
			continue;

		updater->enabled = TRUE;
		updater->format = ni_updater_format_type(ex->format);
		updater->proc_backup = ni_extension_script_find(ex, "backup");
		updater->proc_restore = ni_extension_script_find(ex, "restore");
		updater->proc_install = ni_extension_script_find(ex, "install");
		updater->proc_remove = ni_extension_script_find(ex, "remove");

		/* Create runtime directories for resolver and hostname extensions. */
		if (!(ni_extension_statedir(name))) {
			updater->enabled = FALSE;
		} else
		if (updater->proc_install == NULL) {
			ni_warn("system-updater %s configured, but no install script defined", name);
			updater->enabled = FALSE;
		} else
		if (updater->proc_remove == NULL) {
			ni_warn("system-updater %s configured, but no remove script defined", name);
			updater->enabled = FALSE;
		}
		if (updater->proc_backup == NULL || updater->proc_restore == NULL) {
			ni_debug_verbose(NI_LOG_DEBUG1, NI_TRACE_IFCONFIG,
				"system-updater %s configured, but no backup/restore script defined", name);
			updater->proc_backup = updater->proc_restore = NULL;
		}
	}
}

/*
 * Get the name of an updater
 */
static const char *
ni_updater_name(unsigned int kind)
{
	return ni_format_uint_mapped(kind, __ni_updater_kind_names);
}

static unsigned int
ni_updater_format_type(const char *format)
{
	unsigned int type;

	if (ni_parse_uint_mapped(format, __ni_updater_format_names, &type))
		return NI_ADDRCONF_UPDATER_FORMAT_NONE;
	return type;
}

static const char *
ni_updater_format_name(unsigned int format)
{
	return ni_format_uint_mapped(format, __ni_updater_format_names);
}

static inline ni_bool_t
can_try_reverse_lookup(const ni_addrconf_lease_t *lease)
{
	/* bnc#861476 workaround */
	if (lease->state != NI_ADDRCONF_STATE_APPLYING &&
	    lease->state != NI_ADDRCONF_STATE_GRANTED)
		return FALSE;

	/* Limit to dhcp leases (for now) */
	if (lease->type != NI_ADDRCONF_DHCP)
		return FALSE;

	return lease->addrs != NULL;
}

static inline ni_bool_t
can_update_type(const ni_addrconf_lease_t *lease, unsigned int kind)
{
	ni_bool_t can = FALSE;

	switch (kind) {
	case NI_ADDRCONF_UPDATER_HOSTNAME:
		if (__ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_HOSTNAME))
			can = lease->hostname ? TRUE : can_try_reverse_lookup(lease);
		break;

	case NI_ADDRCONF_UPDATER_RESOLVER:
		if (__ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_DNS))
			can = lease->resolver ? TRUE : FALSE;
		break;

	case NI_ADDRCONF_UPDATER_GENERIC:
		/* Always attempt generic update. */
		can = TRUE;
		break;

	default:
		break;
	}
	return can;
}

/*
 * Add this lease to the given updater, to record that we can use the
 * information from this lease.
 */
static void
ni_objectmodel_updater_add_source(unsigned int kind, const ni_addrconf_lease_t *lease,
				const unsigned int ifindex, const char *ifname)
{
	ni_updater_source_t *up;

	up = ni_updater_source_new();
	up->seqno = lease->seqno;
	up->lease = lease;
	up->d_ref.index = ifindex;
	ni_string_dup(&(up->d_ref.name), ifname);

	ni_updater_source_array_append(&updaters[kind].sources, up);
}

/*
 * Select the best sources for updating the system settings
 */
static unsigned int
ni_objectmodel_updater_select_sources(ni_updater_t *updater, ni_updater_source_array_t *sources)
{
	ni_updater_source_t *ref;
	unsigned int i, cnt;

	if (!updater || !updater->sources.count || !sources)
		return 0;

	cnt = sources->count;
	for (i = 0; i < updater->sources.count; ++i) {
		ref = ni_updater_source_ref(updater->sources.data[i]);
		ni_updater_source_array_append(sources, ref);
	}
	return sources->count - cnt;
}

/*
 * Run an extension script to update resolver, hostname etc.
 */
static ni_bool_t
ni_system_updater_run(ni_shellcmd_t *shellcmd, ni_string_array_t *args)
{
	ni_process_t *pi;
	int rv;

	pi = ni_process_new(shellcmd);
	if (args) {
		unsigned int i;

		for (i = 0; i < args->count; ++i) {
			const char *arg = args->data[i];

			if (arg == NULL)
				arg = "";
			ni_string_array_append(&pi->argv, arg);
		}
	}

	rv = ni_process_run_and_wait(pi);
	ni_process_free(pi);

	return rv >= 0;
}

/*
 * Back up current configuration
 */
static ni_bool_t
ni_system_updater_backup(ni_updater_t *updater, const char *ifname)
{
	if (updater->have_backup)
		return TRUE;

	if (!updater->proc_backup)
		return TRUE;

	if (!ni_system_updater_run(updater->proc_backup, NULL)) {
		ni_error("failed to back up current %s settings",
				ni_updater_name(updater->kind));
		return FALSE;
	}

	updater->have_backup = 1;
	return TRUE;
}

/*
 * Restore existing configuration
 */
static ni_bool_t
ni_system_updater_restore(ni_updater_t *updater, const char *ifname)
{
	if (!updater->have_backup)
		return TRUE;

	if (!updater->proc_restore)
		return TRUE;

	if (!ni_system_updater_run(updater->proc_restore, NULL)) {
		ni_error("failed to restore current %s settings",
				ni_updater_name(updater->kind));
		return FALSE;
	}

	updater->have_backup = 0;
	return TRUE;
}

/*
 * Install information from a lease, and remember that we did
 */
static ni_bool_t
ni_system_updater_install(ni_updater_t *updater, const ni_addrconf_lease_t *lease, const char *ifname)
{
	ni_string_array_t arguments = NI_STRING_ARRAY_INIT;
	const char *statedir = NULL;
	char *file = NULL;
	ni_bool_t result = FALSE;
	int rv = 0;

	ni_debug_ifconfig("Updating system %s settings from %s/%s lease",
					ni_updater_name(updater->kind),
					ni_addrconf_type_to_name(lease->type),
					ni_addrfamily_type_to_name(lease->family));

	if (!updater->proc_install)
		return TRUE;

	if (!ifname || (!updater->have_backup && !ni_system_updater_backup(updater, ifname)))
		return FALSE;

	ni_string_array_append(&arguments, "-i");
	ni_string_array_append(&arguments, ifname);

	ni_string_array_append(&arguments, "-t");
	ni_string_array_append(&arguments, ni_addrconf_type_to_name(lease->type));

	ni_string_array_append(&arguments, "-f");
	ni_string_array_append(&arguments, ni_addrfamily_type_to_name(lease->family));

	switch (updater->kind) {
	case NI_ADDRCONF_UPDATER_GENERIC:
		switch (updater->format) {
		case NI_ADDRCONF_UPDATER_FORMAT_INFO:
			ni_leaseinfo_dump(NULL, lease, ifname, NULL);
			if (!(file = ni_leaseinfo_path(ifname, lease->type, lease->family))) {
				ni_error("Unable to determine leaseinfo file path.");
				goto done;
			}
			ni_string_array_append(&arguments, file);
			break;

		default:
			ni_error("Unsupported %s updater data format.",
				ni_updater_name(updater->kind));
			goto done;
		}

		ni_string_array_append(&arguments,
				ni_updater_format_name(updater->format));
		break;

	case NI_ADDRCONF_UPDATER_RESOLVER:
		statedir = ni_extension_statedir(ni_updater_name(updater->kind));
		if (!statedir) {
			ni_error("failed to get %s statedir", ni_updater_name(updater->kind));
			goto done;
		}
		ni_string_printf(&file, "%s/resolv.conf.%s.%s.%s",
				statedir, ifname,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
		ni_string_array_append(&arguments, file);

		if ((rv = ni_resolver_write_resolv_conf(file, lease->resolver, NULL)) < 0) {
			ni_error("failed to write resolver info to file: %s",
					ni_strerror(rv));
			goto done;
		}
		break;

	case NI_ADDRCONF_UPDATER_HOSTNAME:
		if (!ni_string_empty(lease->hostname)) {
			ni_string_array_append(&arguments, lease->hostname);
		} else {
			const ni_address_t *ap;
			char *name = NULL;
			unsigned int count;

			/* bnc#861476 workaround */
			if (!can_try_reverse_lookup(lease))
				goto done;

			for (count = 0, ap = lease->addrs; ap; ap = ap->next) {
				if (!ni_sockaddr_is_specified(&ap->local_addr))
					continue;

				if (!ni_resolve_reverse_timed(&ap->local_addr,
						&name, NI_UPDATER_REVERSE_TIMEOUT))
					break;

				ni_info("Unable to resolve %s to hostname",
					ni_sockaddr_print(&ap->local_addr));

				if (++count >= NI_UPDATER_REVERSE_MAX_CNT)
					break;
			}

			if (ni_string_empty(name)) {
				ni_note("Skipping hostname update, none available");
				goto done;
			}
			ni_string_array_append(&arguments, name);
			ni_string_free(&name);
		}
		break;

	default:
		ni_error("cannot install new %s settings - file format not understood",
				ni_updater_name(updater->kind));
		goto done;
	}

	if (!ni_system_updater_run(updater->proc_install, &arguments)) {
		ni_error("failed to install %s settings", ni_updater_name(updater->kind));
		goto done;
	}

	result = TRUE;

	switch (updater->kind) {
	case NI_ADDRCONF_UPDATER_RESOLVER:
		if (ni_global.other_event)
			ni_global.other_event(NI_EVENT_RESOLVER_UPDATED);
		break;

	case NI_ADDRCONF_UPDATER_HOSTNAME:
		if (ni_global.other_event)
			ni_global.other_event(NI_EVENT_HOSTNAME_UPDATED);
		break;

	case NI_ADDRCONF_UPDATER_GENERIC:
		if (ni_global.other_event)
			ni_global.other_event(NI_EVENT_GENERIC_UPDATED);
		break;

	default:
		break;
	}

done:
	if (file)
		free(file);
	ni_string_array_destroy(&arguments);

	return result;
}

/*
 * Remove information from a lease which has been released and already detached
 * from a device.
 */
static ni_bool_t
ni_system_updater_remove(ni_updater_t *updater, const ni_addrconf_lease_t *lease, const char *ifname)
{
	ni_string_array_t arguments = NI_STRING_ARRAY_INIT;
	ni_bool_t result = FALSE;

	ni_debug_ifconfig("Removing system %s settings from %s %s/%s lease",
			ni_updater_name(updater->kind), ifname,
			ni_addrconf_type_to_name(lease->type),
			ni_addrfamily_type_to_name(lease->family));

	if (!updater->proc_remove)
		return TRUE;

	ni_string_array_append(&arguments, "-i");
	ni_string_array_append(&arguments, ifname);

	ni_string_array_append(&arguments, "-t");
	ni_string_array_append(&arguments, ni_addrconf_type_to_name(lease->type));

	ni_string_array_append(&arguments, "-f");
	ni_string_array_append(&arguments, ni_addrfamily_type_to_name(lease->family));

	switch (updater->kind) {
	case NI_ADDRCONF_UPDATER_GENERIC:
		switch (updater->format) {
		case NI_ADDRCONF_UPDATER_FORMAT_INFO:
			ni_leaseinfo_remove(ifname, lease->type, lease->family);
			break;
		default:
			ni_error("Unsupported %s updater data format.",
				ni_updater_name(updater->kind));
			break;
		}
		break;

	case NI_ADDRCONF_UPDATER_RESOLVER:
	case NI_ADDRCONF_UPDATER_HOSTNAME:
		break;

	default:
		ni_error("cannot remove old %s settings - file format not understood",
				ni_updater_name(updater->kind));
		goto done;
	}

	if (!ni_system_updater_run(updater->proc_remove, &arguments)) {
		ni_error("failed to remove %s settings", ni_updater_name(updater->kind));
		goto done;
	}

	result = TRUE;

	switch (updater->kind) {
	case NI_ADDRCONF_UPDATER_RESOLVER:
		if (ni_global.other_event)
			ni_global.other_event(NI_EVENT_RESOLVER_UPDATED);
		break;

	case NI_ADDRCONF_UPDATER_HOSTNAME:
		if (ni_global.other_event)
			ni_global.other_event(NI_EVENT_HOSTNAME_UPDATED);
		break;

	case NI_ADDRCONF_UPDATER_GENERIC:
		if (ni_global.other_event)
			ni_global.other_event(NI_EVENT_GENERIC_UPDATED);
		break;

	default:
		break;
	}

done:
	ni_string_array_destroy(&arguments);
	return result;
}

static ni_bool_t
ni_system_update_remove_matching_leases(ni_updater_t *updater,
					const ni_addrconf_lease_t *lease,
					const unsigned int ifindex,
					const char *ifname)
{
	ni_updater_source_t *src = NULL;
	unsigned int i;

	if (!updater || !lease) {
		ni_error("Unintialized updater sources or lease.");
		return FALSE;
	}

	for (i = 0; i < updater->sources.count; ) {
		src = updater->sources.data[i];

		if (src && src->lease &&
			src->d_ref.index == ifindex &&
			src->lease->type == lease->type &&
			src->lease->family == lease->family) {
			/* Found an existing lease of interest to remove/replace with 'lease.'
			 * If lease is not in granted state (ie. it's a removal request) or if 
			 * the interface name has changed, actually remove the existing src->lease.
			 * Otherwise, it's a simple replacement/overwrite so no need to remove lease
			 * information from the system.
			 */
			if (!ni_string_eq(src->d_ref.name, ifname) ||
			    lease->state != NI_ADDRCONF_STATE_APPLYING) {
				ni_system_updater_remove(updater, src->lease, src->d_ref.name);
			}

			if (ni_updater_source_array_delete(&updater->sources, i))
				continue;
		}
		i++;
	}

	return TRUE;
}

/*
 * A lease has changed, and we are asked to update the system configuration.
 * When we get here, the old lease has already been removed from the interface,
 * and the new one has been added.
 */
int
ni_system_update_from_lease(const ni_addrconf_lease_t *lease, const unsigned int ifindex, const char *ifname)
{
	ni_bool_t res = TRUE;
	int ret;
	unsigned int kind;

	ni_debug_ifconfig("%s()", __func__);
	ni_system_updaters_init();

	for (kind = 0; kind < __NI_ADDRCONF_UPDATER_MAX; ++kind) {
		if (can_update_type(lease, kind)) {
			ni_updater_t *updater = &updaters[kind];
			ni_updater_source_array_t sources = NI_UPDATER_SOURCE_ARRAY_INIT;

			if (!updater->enabled)
				continue;

			switch(lease->state) {
			case NI_ADDRCONF_STATE_APPLYING:
			case NI_ADDRCONF_STATE_GRANTED:
				if(!ni_system_update_remove_matching_leases(updater, lease, ifindex, ifname)) {
					ni_error("Failed to remove any matching leases. Storing new lease anyway.");
					res = FALSE;
				}
				/* Remove matching leases before we install a new lease.
				 * This is important for hostname updates in the case
				 * where the interface name has changed. If we don't process
				 * the resulting remove before we install, we will remove
				 * the newly installed (or already present) hostname file
				 * and thus restore the hostname to /etc/HOSTNAME.
				 */
				if(!ni_system_updater_install(updater, lease, ifname)) {
					res = FALSE;
				}
				ni_objectmodel_updater_add_source(kind, lease, ifindex, ifname);
				break;
			default:
				if(!ni_system_update_remove_matching_leases(updater, lease, ifindex, ifname)) {
					ni_error("Failed to remove any matching leases. Storing new lease anyway.");
					res = FALSE;
				}
				/* If we no longer have any lease data for this resource, restore
				 * the system default.
				 */
				if (!ni_objectmodel_updater_select_sources(updater, &sources)) {
					if (!ni_system_updater_restore(updater, ifname))
						res = FALSE;
				}

				ni_updater_source_array_destroy(&sources);
				break;
			}
		}
	}

	return ret = res ? 0 : -1;
}
