/*
 * Handing openvon interfaces.
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>

#include <wicked/netinfo.h>
#include <wicked/openvpn.h>
#include "netinfo_priv.h"


#define __NI_OPENVPN_CONFIG	"config"
#define __NI_OPENVPN_PIDFILE	"pid"

static const char *	ni_openvpn_device_from_config(const char *);
static ni_bool_t	__ni_openvpn_tag_to_index(const char *, unsigned int *);
static const char *	__ni_openvpn_path(const char *tag, const char *file);

ni_openvpn_t *
ni_openvpn_new(const char *tag)
{
	static unsigned int next_index;
	char tagbuf[64];
	ni_openvpn_t *p;

	if (tag != NULL) {
		unsigned int index;

		if (!__ni_openvpn_tag_to_index(tag, &index))
			return NULL;
		if (index >= next_index)
			next_index = index + 1;
	} else {
		snprintf(tagbuf, sizeof(tagbuf), "openvpn%u", next_index++);
		tag = tagbuf;
	}

	p = calloc(1, sizeof(*p));
	ni_string_dup(&p->ident, tag);
	p->temp_state = ni_tempstate_new(tag);

	return p;
}

int
ni_openvpn_mkdir(ni_openvpn_t *vpn)
{
	return ni_tempstate_mkdir(vpn->temp_state);
}

void
ni_openvpn_free(ni_openvpn_t *vpn)
{
	if (vpn->temp_state)
		ni_tempstate_finish(vpn->temp_state);
	vpn->temp_state = NULL;
	ni_string_free(&vpn->ident);
	free(vpn);
}

static ni_bool_t
__ni_openvpn_is_running(const char *tag)
{
	const char *pidfile;
	pid_t pid;

	pidfile = __ni_openvpn_path(tag, __NI_OPENVPN_PIDFILE);
	pid = ni_pidfile_check(pidfile);

	return pid > 0;
}

static void
__ni_openvpn_cleanup(const char *tag)
{
	const char *dirname;

	dirname = __ni_openvpn_path(tag, NULL);
	ni_file_remove_recursively(dirname);
}

/*
 * Check whether a given network device is managed by
 * an openvpn process and return a handle in that case.
 *
 * We do not try to be too clever, but restrict ourselves
 * to those openvpn processes we've started ourselves.
 */
int
ni_openvpn_discover(ni_netconfig_t *nc)
{
	ni_string_array_t subdirs = NI_STRING_ARRAY_INIT;

	if (ni_scandir(ni_config_statedir(), "openvpn*", &subdirs) != 0) {
		unsigned int i;

		for (i = 0; i < subdirs.count; ++i) {
			char *tag = subdirs.data[i];
			const char *pathname;
			const char *devname;
			ni_netdev_t *dev;
			ni_openvpn_t *openvpn;

			if (!__ni_openvpn_is_running(tag)) {
				ni_debug_ifconfig("removing stale openvpn config for %s", tag);
				__ni_openvpn_cleanup(tag);
				continue;
			}

			/* Source the configuration file and try to find the name of
			 * the network interface. */
			pathname = __ni_openvpn_path(tag, __NI_OPENVPN_CONFIG);
			if (!(devname = ni_openvpn_device_from_config(pathname)))
				continue;

			if (!(dev = ni_netdev_by_name(nc, devname)))
				continue;

			if (dev->link.type != NI_IFTYPE_TUN) {
				ni_warn("openvpn tunnel config %s refers to device %s, which is a %s",
						tag, devname,
						ni_linktype_type_to_name(dev->link.type));
				continue;
			}

			ni_debug_ifconfig("discovered tunnel %s (dev %s)", tag, devname);
			openvpn = ni_openvpn_new(tag);

			ni_netdev_set_openvpn(dev, openvpn);
		}
	}

	return 0;
}

static const char *
ni_openvpn_device_from_config(const char *path)
{
	static char device_name[64];
	char buffer[256], *result = NULL;
	FILE *fp;

	if (!(fp = fopen(path, "r"))) {
		ni_warn("cannot open %s: %m", path);
		return NULL;
	}

	memset(device_name, 0, sizeof(device_name));
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char *s, *dev;

		if (!strncmp(buffer, "dev", 3) && isspace(buffer[3])) {
			s = buffer + 3;
			while (isspace(*s))
				++s;
			dev = s;

			while (*s && !isspace(*s))
				++s;
			*s = '\0';

			/* Ignore "generic" names that let the openvpn daemon
			 * pick a random device name. */
			if (!strcmp(dev, "tun") || !strcmp(dev, "tap"))
				break;

			strncpy(device_name, dev, sizeof(device_name) - 1);
			result = device_name;
			break;
		}
	}

	fclose(fp);

	return result;
}

/*
 * Given a tag like "openvpn0", return the path name of the config file, pid file,
 * or of the directory itself.
 */
static const char *
__ni_openvpn_path(const char *tag, const char *filename)
{
	static char pathbuf[PATH_MAX];

	if (filename)
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s/%s", ni_config_statedir(), tag, filename);
	else
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", ni_config_statedir(), tag);
	return pathbuf;
}

/*
 * Given a tag like "openvpn0", extract the index.
 */
static ni_bool_t
__ni_openvpn_tag_to_index(const char *tag, unsigned int *indexp)
{
	char *ep;

	if (strncmp(tag, "openvpn", 7))
		return 0;

	if (!isdigit(tag[7]))
		return 0;

	*indexp = strtoul(tag + 7, &ep, 0);
	if (*ep != '\0')
		return 0;

	return 1;
}
