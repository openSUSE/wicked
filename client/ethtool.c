/*
 *	wicked client ethtool utilities
 *
 *	Copyright (C) 2018 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Marius Tomaschewski <mt@suse.de>
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <net/if.h>

#include <wicked/types.h>
#include <wicked/netinfo.h>
#include <wicked/ethtool.h>
#include <wicked/util.h>

struct ethtool_args {
	int	argc;
	char **	argv;
};

struct ethtool_opt {
	const char *	name;
	int		(*func)(const char *, ni_ethtool_t *, struct ethtool_args *args);
	const char *	usage;
};


static int
get_ethtool_driver_info(const char *ifname, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	const ni_ethtool_driver_info_t *info;
	unsigned int n;

	(void)args;
	if (ni_ethtool_get_driver_info(ifname, ethtool) < 0 || !(info = ethtool->driver_info))
		return -1;

	printf("driver-info:\n");
	if (!ni_string_empty(info->driver))
		printf("\tdriver: %s\n", info->driver);
	if (!ni_string_empty(info->version))
		printf("\tversion: %s\n", info->version);
	if (!ni_string_empty(info->fw_version))
		printf("\tfirmware-version: %s\n", info->fw_version);
	if (!ni_string_empty(info->erom_version))
		printf("\teeprom-version: %s\n", info->erom_version);
	if (!ni_string_empty(info->bus_info))
		printf("\tbus-info: %s\n", info->bus_info);
	for (n = 0; n <= NI_ETHTOOL_DRIVER_SUPP_REGDUMP; ++n) {
		printf("\tsupports-%s: %s\n",
				ni_ethtool_driver_supports_map_bit(n),
				info->supports.bitmap & NI_BIT(n) ? "yes" : "no");
	}

	return 0;
}

static int
get_ethtool_priv_flags(const char *ifname, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	const ni_ethtool_priv_flags_t *pflags;
	const char *name;
	unsigned int n;

	(void)args;
	if (ni_ethtool_get_priv_flags(ifname, ethtool) < 0 || !(pflags = ethtool->priv_flags))
		return -1;

	printf("private-flags:\n");
	for (n = 0; n < pflags->names.count; ++n) {
		name = pflags->names.data[n];
		printf("\t%s: %s\n", name, pflags->bitmap & NI_BIT(n) ? "on" : "off");
	}
	return 0;
}

static int
set_ethtool_priv_flags(const char *ifname, ni_ethtool_t *ethtool, struct ethtool_args *args)
{
	ni_ethtool_priv_flags_t *pflags;
	ni_bool_t enabled;
	char *key, *val;
	int ret = -1, n;

	if (!(pflags = ni_ethtool_priv_flags_new()))
		return ret;

	for (n = 0; n + 1 < args->argc && args->argv[n]; ++n) {
		key = args->argv[n++];
		val = args->argv[n];

		if (ni_parse_boolean(val, &enabled) ||
		    ni_string_array_append(&pflags->names, key))
			goto cleanup;

		if (enabled)
			pflags->bitmap |= NI_BIT(pflags->names.count - 1);
	}

	ret = ni_ethtool_set_priv_flags(ifname, ethtool, pflags);

cleanup:
	ni_ethtool_priv_flags_free(pflags);
	return ret;
}

static const struct ethtool_opt	ethtool_opts[] = {
	/* get */
	{	"--show-driver-info",	.func	= get_ethtool_driver_info	},
	{	"--show-priv-flags",	.func	= get_ethtool_priv_flags	},

	/* set */
	{	"--set-priv-flags",	.func	= set_ethtool_priv_flags,
					.usage	= "<priv-flag on|off> ..."		},

	{	NULL								}
};

void
ethtool_opt_usage(const struct ethtool_opt *opt)
{
	if (opt->usage)
		fprintf(stderr, "  %-20s\t%s\n", opt->name, opt->usage);
	else
		fprintf(stderr, "  %s\n", opt->name);
}

const struct ethtool_opt *
ethtool_opt_find(const struct ethtool_opt *opts, const char *name)
{
	const struct ethtool_opt *opt;

	for (opt = opts; opt && opt->name && opt->func; opt++) {
		if (ni_string_eq(opt->name, name))
			return opt;
	}
	return NULL;
}

static void
ethtool_args_set(struct ethtool_args *args, char **argn, int argc, char *argv[])
{
	args->argv = argv;
	args->argc = 0;
	while (args->argc < argc) {
		if (ni_string_startswith(argv[args->argc], "--"))
			break;
		args->argc++;
	}
	*argn = argv[args->argc];
	argv[args->argc] = NULL;
}

int
ni_do_ethtool(const char *caller, int argc, char **argv)
{
	enum { OPT_HELP };
	static struct option      options[] = {
		{ "help",         no_argument,       NULL, OPT_HELP        },

		{ NULL,           no_argument,       NULL, 0               }
	};
	int c, n, status = NI_WICKED_RC_USAGE;
	const struct ethtool_opt *opt;
	ni_netdev_t *dev = NULL;
	ni_ethtool_t *ethtool;

	optind = 1;
	while ((c = getopt_long(argc, argv, "+", options, NULL)) != EOF) {
		switch (c) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
		default:
		usage:
			fprintf(stderr,
				"wicked %s [global options ...] <ifname> <action option [arguments] > ...\n"
				"\n"
				"Supported global options:\n"
				"  --help\n"
				"      Show this help text.\n"
				"\n"
				"Supported action options:\n"
				, argv[0]
			);
			for (opt = ethtool_opts; opt && opt->name && opt->func; opt++)
				ethtool_opt_usage(opt);
			goto cleanup;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "%s: missing interface argument\n", argv[0]);
		goto usage;
	}
	if (optind + 1 >= argc) {
		fprintf(stderr, "%s: missing action option option\n", argv[0]);
		goto usage;
	}

	status = NI_WICKED_RC_ERROR;
	dev = ni_netdev_new(argv[optind], if_nametoindex(argv[optind]));
	if (!dev || !dev->link.ifindex) {
		fprintf(stderr, "%s: cannot find interface with name '%s'", argv[0], argv[optind]);
		goto cleanup;
	}
	if (!(ethtool = ni_netdev_get_ethtool(dev))) {
		fprintf(stderr, "%s: cannot allocate ethtool parameters for '%s'", argv[0], dev->name);
		goto cleanup;
	}

	status = NI_WICKED_RC_SUCCESS;
	for (n = ++optind; n < argc; ) {
		if ((opt = ethtool_opt_find(ethtool_opts, argv[n]))) {
			struct ethtool_args args;
			char * argn;

			ethtool_args_set(&args, &argn, argc - n - 1, argv + n + 1);
			n += args.argc + 1;
			if (opt->func(dev->name, ethtool, &args) < 0)
				status = NI_WICKED_RC_ERROR;
			argv[n] = argn;
		} else
		if (!ni_string_eq(argv[n], "--")) {
			fprintf(stderr, "%s: unknown action option '%s'\n", argv[0], argv[n]);
			status = NI_WICKED_RC_USAGE;
			goto cleanup;
		} else
			n++;
	}

cleanup:
	if (dev)
		ni_netdev_put(dev);
	return status;
}

