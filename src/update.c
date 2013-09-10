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

#include "netinfo_priv.h"
#include "util_priv.h"
#include "process.h"
#include "appconfig.h"
#include "debug.h"

#define	NI_UPDATER_SOURCE_ARRAY_CHUNK	4
#define	NI_UPDATER_SOURCE_ARRAY_INIT	{ 0, NULL }

typedef struct ni_updater_source	ni_updater_source_t;
struct ni_updater_source {
	unsigned int			users;
	ni_updater_source_t *		next;

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
	ni_updater_source_t *		sources;

	unsigned int			type;
	unsigned int			have_backup;

	ni_bool_t			enabled;
	ni_shellcmd_t *			proc_backup;
	ni_shellcmd_t *			proc_restore;
	ni_shellcmd_t *			proc_install;
	ni_shellcmd_t *			proc_remove;
} ni_updater_t;

static ni_updater_t			updaters[__NI_ADDRCONF_UPDATE_MAX];

static const char *			ni_updater_name(unsigned int);

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

	/* Note: this also copies the NULL pointer following the last element */
	memmove(&usa->data[index], &usa->data[index + 1],
		(usa->count - index) * sizeof(ni_updater_source_t *));
	usa->count--;

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

	for (kind = 0; kind < __NI_ADDRCONF_UPDATE_MAX; ++kind) {
		ni_updater_t *updater = &updaters[kind];
		const char *name = ni_updater_name(kind);
		ni_extension_t *ex;

		updater->type = kind;
		if (name == NULL)
			continue;

		if (!(ex = ni_config_find_system_updater(ni_global.config, name)))
			continue;

		updater->enabled = 1;
		updater->proc_backup = ni_extension_script_find(ex, "backup");
		updater->proc_restore = ni_extension_script_find(ex, "restore");
		updater->proc_install = ni_extension_script_find(ex, "install");
		updater->proc_remove = ni_extension_script_find(ex, "remove");

		if (updater->proc_install == NULL) {
			ni_warn("system-updater %s configured, but no install script defined", name);
			updater->enabled = 0;
		} else
		if (updater->proc_backup == NULL || updater->proc_restore == NULL) {
			ni_warn("system-updater %s configured, but no backup/restore script defined", name);
			updater->proc_backup = updater->proc_restore = NULL;
		} else
		if (updater->proc_remove == NULL) {
			ni_warn("system-updater %s configured, but no remove script defined", name);
			updater->enabled = 0;
		}
	}
}

/*
 * Get the name of an updater
 */
static const char *
ni_updater_name(unsigned int kind)
{
	static ni_intmap_t names[] = {
	{ "hostname",		NI_ADDRCONF_UPDATE_HOSTNAME	},
	{ "resolver",		NI_ADDRCONF_UPDATE_RESOLVER	},

	{ NULL }
	};

	return ni_format_uint_mapped(kind, names);
}

static inline ni_bool_t
can_update_hostname(const ni_addrconf_lease_t *lease)
{
	return __ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_HOSTNAME) && lease->hostname;
}

static inline ni_bool_t
can_update_resolver(const ni_addrconf_lease_t *lease)
{
	return __ni_addrconf_should_update(lease->update, NI_ADDRCONF_UPDATE_RESOLVER) && lease->resolver;
}

static inline ni_bool_t
can_update_type(const ni_addrconf_lease_t *lease, unsigned int kind)
{
	ni_bool_t res = FALSE;

	switch (kind) {
	case NI_ADDRCONF_UPDATE_HOSTNAME:
		res = lease->hostname ? TRUE : FALSE;
		break;

	case NI_ADDRCONF_UPDATE_RESOLVER:
		res = lease->resolver ? TRUE : FALSE;
		break;

	default:
		res = FALSE;
		break;
	}

	return __ni_addrconf_should_update(lease->update, kind) && res;
}

/*
 * Add this lease to the given updater, to record that we can use the
 * information from this lease.
 */
static void
ni_objectmodel_updater_add_source(unsigned int kind, const ni_addrconf_lease_t *lease,
				const unsigned int ifindex, const char *ifname)
{
	ni_updater_source_t **pos, *up;

	for (pos = &updaters[kind].sources; (up = *pos) != NULL; pos = &up->next)
		;

	up = calloc(1, sizeof(*up));
	up->seqno = lease->seqno;
	up->lease = lease;
	up->d_ref.index = ifindex;
	ni_string_dup(&(up->d_ref.name), ifname);

	*pos = up;
}

/*
 * Select the best sources for updating the system settings
 */
static unsigned int
ni_objectmodel_updater_select_sources(ni_updater_t *updater, ni_updater_source_t ***sources)
{
	ni_updater_source_t *src;
	unsigned int num_sources;
	unsigned int i;

	num_sources = 0;
	for (src = updater->sources; src; src = src->next) {
		num_sources += 1;
	}

	*sources = NULL;
	if (!num_sources)
		return 0;

	/* allocate array of pointers and assign only if we have valid sources */
	*sources = xcalloc(num_sources, sizeof(ni_updater_source_t *));

	for (i = 0, src = updater->sources;
	     src && i < num_sources;
	     src = src->next) {
		(*sources)[i++] = src;
	}
	return i;
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
				ni_updater_name(updater->type));
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
				ni_updater_name(updater->type));
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
	char *file = NULL;
	ni_bool_t result = FALSE;
	int rv = 0;

	ni_debug_ifconfig("Updating system %s settings from %s/%s lease",
					ni_updater_name(updater->type),
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

	/* FIXME: build a file containing the new configuration, and run the
	 * indicated script with it */
	switch (updater->type) {
	case NI_ADDRCONF_UPDATE_RESOLVER:
		ni_string_printf(&file, "%s/resolv.conf.%s.%s.%s",
				ni_config_resolverdir(), ifname,
				ni_addrconf_type_to_name(lease->type),
				ni_addrfamily_type_to_name(lease->family));
		ni_string_array_append(&arguments, file);

		if ((rv = ni_resolver_write_resolv_conf(file, lease->resolver, NULL)) < 0) {
			ni_error("failed to write resolver info to file: %s",
					ni_strerror(rv));
			goto done;
		}
		break;

	case NI_ADDRCONF_UPDATE_HOSTNAME:
		if (ni_string_empty(lease->hostname))
			goto done;

		ni_string_array_append(&arguments, lease->hostname);
		break;

	default:
		ni_error("cannot install new %s settings - file format not understood",
				ni_updater_name(updater->type));
		goto done;
	}

	if (!ni_system_updater_run(updater->proc_install, &arguments)) {
		ni_error("failed to install %s settings", ni_updater_name(updater->type));
		goto done;
	}

	result = TRUE;

	switch (updater->type) {
	case NI_ADDRCONF_UPDATE_RESOLVER:
		if (ni_global.other_event)
			ni_global.other_event(NI_EVENT_RESOLVER_UPDATED);
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
			ni_updater_name(updater->type), ifname,
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

	switch (updater->type) {
	case NI_ADDRCONF_UPDATE_RESOLVER:
	case NI_ADDRCONF_UPDATE_HOSTNAME:
		break;

	default:
		ni_error("cannot remove old %s settings - file format not understood",
				ni_updater_name(updater->type));
		goto done;
	}

	if (!ni_system_updater_run(updater->proc_remove, &arguments)) {
		ni_error("failed to remove %s settings", ni_updater_name(updater->type));
		goto done;
	}

	result = TRUE;

	switch (updater->type) {
	case NI_ADDRCONF_UPDATE_RESOLVER:
		if (ni_global.other_event)
			ni_global.other_event(NI_EVENT_RESOLVER_UPDATED);
		break;

	default:
		break;
	}

done:
	ni_string_array_destroy(&arguments);
	return result;
}

#if 0 /* Disable until we need something similar. */
static ni_bool_t
ni_system_update_all(const ni_addrconf_lease_t *lease, const char *ifname)
{
	ni_netconfig_t *nc = ni_global_state_handle(0);
	ni_updater_source_t *up;
	ni_netdev_t *dev;
	unsigned int kind;
	ni_bool_t result = TRUE;

	ni_debug_ifconfig("%s()", __func__);
	ni_system_updaters_init();

	/* if lease is released, remove it first. */
	if (lease && lease->state == NI_ADDRCONF_STATE_RELEASED) {
		if (can_update_hostname(lease)) {
			if (!ni_system_updater_remove(&updaters[NI_ADDRCONF_UPDATE_HOSTNAME], lease, ifname)) {
				result = FALSE;
			}
		}
		if (can_update_resolver(lease)) {
			if (!ni_system_updater_remove(&updaters[NI_ADDRCONF_UPDATE_RESOLVER], lease, ifname)) {
				result = FALSE;
			}
		}
	}

	for (kind = 0; kind < __NI_ADDRCONF_UPDATE_MAX; ++kind) {
		for (up = updaters[kind].sources; up; up = up->next) {
			up->lease = NULL;
		}
	}

	for (dev = ni_netconfig_devlist(nc); dev; dev = dev->next) {
		ni_addrconf_lease_t *lease;

		for (lease = dev->leases; lease; lease = lease->next) {
#if 0
			ni_trace(" %s: %s/%s hostname %s resolver %s",
					dev->name,
					ni_addrconf_type_to_name(lease->type),
					ni_addrfamily_type_to_name(lease->family),
					can_update_hostname(lease)? "YES" : "NO",
					can_update_resolver(lease)? "YES" : "NO");
#endif
			if (can_update_hostname(lease))
				ni_objectmodel_updater_add_source(NI_ADDRCONF_UPDATE_HOSTNAME, lease);
			if (can_update_resolver(lease))
				ni_objectmodel_updater_add_source(NI_ADDRCONF_UPDATE_RESOLVER, lease);
		}
	}

	for (kind = 0; kind < __NI_ADDRCONF_UPDATE_MAX; ++kind) {
		ni_updater_t *updater = &updaters[kind];
		ni_updater_source_t **pos = &updater->sources;
		ni_updater_source_t **sources = NULL;
		ni_updater_source_t *src = NULL;
		unsigned int num_sources, i;

		if (!updater->enabled)
			continue;

		/* Purge all updater sources for which the lease went away. */
		while ((up = *pos)) {
			if (up->lease == NULL) {
				*pos = up->next;
				free(up);
			} else {
				pos = &up->next;
			}
		}

		/* If we no longer have any lease data for this resource, restore
		 * the system default.
		 * If we do have, update the system only if the lease was updated.
		 */
		num_sources = ni_objectmodel_updater_select_sources(updater, &sources);
		/* Only attempt to restore if lease received was a release. */
		if (lease->state == NI_ADDRCONF_STATE_RELEASED && num_sources == 0 &&
			!ni_system_updater_restore(updater, ifname))
			result = FALSE;

		for (i = 0; i < num_sources; i++) {
			src = sources[i];

			if (src->lease && lease && lease->state == NI_ADDRCONF_STATE_GRANTED &&
				src->lease->seqno == lease->seqno) {
				if (!ni_system_updater_install(updater, src->lease, ifname))
					result = FALSE;
			}
		}

		if (sources) {
			for (i = 0; i < num_sources; i++) {
				sources[i] = NULL;
			}
			free(sources);
		}
	}

	return result;
}
#endif

static ni_bool_t
ni_system_update_remove_matching_leases(ni_updater_t *updater,
					const ni_addrconf_lease_t *lease,
					const unsigned int ifindex,
					const char *ifname)
{
	ni_updater_source_t **sources = &updater->sources;
	ni_updater_source_t *src = NULL;

	if (!sources || !lease) {
		ni_error("Unintialized updater sources or lease.");
		return FALSE;
	}

	while ((src = *sources)) {
		if (src->lease && src->d_ref.index == ifindex &&
			src->lease->type == lease->type &&
			src->lease->family == lease->family) {
			/* Found an existing lease of interest to remove/replace with 'lease.'
			 * If lease is not in granted state (ie. it's a removal request) or if 
			 * the interface name has changed, actually remove the existing src->lease.
			 * Otherwise, it's a simple replacement/overwrite so no need to remove lease
			 * information from the system.
			 */
			if (strcmp(src->d_ref.name, ifname) != 0 || lease->state != NI_ADDRCONF_STATE_GRANTED) {
				ni_system_updater_remove(updater, src->lease, src->d_ref.name);
			}

			*sources = src->next;
			ni_netdev_ref_destroy(&src->d_ref);
			free(src);
		} else {
			sources = &src->next;
		}
	}

	return TRUE;
}

static void
ni_system_update_free_selected_sources(ni_updater_source_t **sources, unsigned int num_sources)
{
       unsigned int i;
       if (sources) {
               for (i = 0; i < num_sources; i++) {
                       sources[i] = NULL;
               }
               free(sources);
       }
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
	unsigned int num_sources, kind;

	ni_debug_ifconfig("%s()", __func__);
	ni_system_updaters_init();

	for (kind = 0; kind < __NI_ADDRCONF_UPDATE_MAX; ++kind) {
		if (can_update_type(lease, kind)) {
			ni_updater_t *updater = &updaters[kind];
			ni_updater_source_t **sources = NULL;

			if (!updater->enabled)
				continue;

			switch(lease->state) {
			case NI_ADDRCONF_STATE_GRANTED:
				if(!ni_system_updater_install(updater, lease, ifname)) {
					res = FALSE;
				}
				if(!ni_system_update_remove_matching_leases(updater, lease, ifindex, ifname)) {
					ni_error("Failed to remove any matching leases. Storing new lease anyway.");
					res = FALSE;
				}
				ni_objectmodel_updater_add_source(NI_ADDRCONF_UPDATE_RESOLVER, lease,
								ifindex, ifname);
				break;
			default:
				if(!ni_system_update_remove_matching_leases(updater, lease, ifindex, ifname)) {
					ni_error("Failed to remove any matching leases. Storing new lease anyway.");
					res = FALSE;
				}
				/* If we no longer have any lease data for this resource, restore
				 * the system default.
				 */
				num_sources = ni_objectmodel_updater_select_sources(updater, &sources);
				if (num_sources == 0 && !ni_system_updater_restore(updater, ifname))
					res = FALSE;
				ni_system_update_free_selected_sources(sources, num_sources);
				break;
			}
		}
	}

	return ret = res ? 0 : -1;
}
