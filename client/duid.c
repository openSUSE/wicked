/*
 *	wicked client main commands
 *
 *	Copyright (C) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *      Authors:
 *              Marius Tomaschewski <mt@suse.de>
 *              Nirmoy Das <ndas@suse.de>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <net/if_arp.h>

#include <wicked/types.h>
#include <wicked/util.h>
#include <wicked/netinfo.h>
#include "duid.h"


static int
ni_do_duid_dump(int argc, char **argv)
{
	enum {	OPT_HELP = 'h' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_var_array_t vars = NI_VAR_ARRAY_INIT;
	ni_duid_map_t *map = NULL;
	ni_var_t *var;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage: %s [options]\n"
				"\n"
				"Options:\n"
				"  --help, -h           show this help text and exit.\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}
	if (argc - optind)
		goto usage;

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	status = NI_WICKED_RC_SUCCESS;
	if (ni_duid_map_to_vars(map, &vars)) {
		unsigned int i;

		for (i = 0, var = vars.data; i < vars.count; ++i, ++var) {
			printf("%s\t%s\n", var->name ? var->name : "default", var->value);
		}
		ni_var_array_destroy(&vars);
	}

cleanup:
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_get(int argc, char **argv)
{
	enum {	OPT_HELP = 'h', OPT_SCOPE = 's' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "scope",	required_argument,	NULL,	OPT_SCOPE	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	const char *scope = NULL;
	const char *duid = NULL;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hs:", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_SCOPE:
			if (optarg && !ni_string_eq(optarg, "default"))
				scope = optarg;
			break;
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage: %s [options]\n"
				"\n"
				"Options:\n"
				"  --help, -h           show this help text and exit.\n"
				"  --scope <ifname>     show device specific duid instead of default\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}
	if (argc - optind)
		goto usage;

	if (scope && !ni_netdev_name_is_valid(scope)) {
		fprintf(stderr, "%s: invalid scope interface name '%s'\n", argv[0],
				ni_print_suspect(scope, ni_string_len(scope)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	status = NI_WICKED_RC_NO_DEVICE;
	if (ni_duid_map_get_duid(map, scope, &duid, NULL)) {
		printf("%s\t%s\n", scope ? scope : "default", duid);
		status = NI_WICKED_RC_SUCCESS;
	} else
	if (scope && ni_duid_map_get_duid(map, NULL, &duid, NULL)) {
		printf("%s\t%s\n", "default", duid);
		status = NI_WICKED_RC_SUCCESS;
	}

cleanup:
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_del(int argc, char **argv)
{
	enum {	OPT_HELP = 'h', OPT_SCOPE = 's' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "scope",	required_argument,	NULL,	OPT_SCOPE	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	const char *scope = NULL;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hs:", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_SCOPE:
			if (optarg && !ni_string_eq(optarg, "default"))
				scope = optarg;
			break;
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage: %s [options]\n"
				"\n"
				"Options:\n"
				"  --help, -h           show this help text and exit.\n"
				"  --scope <ifname>     delete device specific duid instead of default\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}
	if (argc - optind)
		goto usage;

	if (scope && !ni_netdev_name_is_valid(scope)) {
		fprintf(stderr, "%s: invalid scope interface name '%s'\n", argv[0],
				ni_print_suspect(scope, ni_string_len(scope)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	if (ni_duid_map_del(map, scope)) {
		if (ni_duid_map_save(map))
			status = NI_WICKED_RC_SUCCESS;
	}

cleanup:
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_set(int argc, char **argv)
{
	enum { OPT_HELP = 'h', OPT_SCOPE = 's' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "scope",	required_argument,	NULL,	OPT_SCOPE	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	ni_duid_map_t *map = NULL;
	const char *scope = NULL;
	const char *duid = NULL;
	ni_opaque_t raw;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hs:", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_SCOPE:
			if (optarg && !ni_string_eq(optarg, "default"))
				scope = optarg;
			break;
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage: %s [options] <duid>\n"
				"\n"
				"Options:\n"
				"  --help, -h           show this help text and exit.\n"
				"  --scope <ifname>     set device specific duid instead of default\n"
				"\n"
				"Arguments:\n"
				"  duid                 duid string as colon-separated hex bytes\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}
	switch (argc - optind) {
	case 1:
		duid   = argv[optind++];
		break;
	default:
		goto usage;
	}

	if (scope && !ni_netdev_name_is_valid(scope)) {
		fprintf(stderr, "%s: invalid scope interface name '%s'\n", argv[0],
				ni_print_suspect(scope, ni_string_len(scope)));
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}
	if (ni_string_empty(duid) || !ni_duid_parse_hex(&raw, duid)) {
		fprintf(stderr, "%s: unable to parse duid hex string argument\n", argv[0]);
		status = NI_WICKED_RC_ERROR;
		goto cleanup;
	}

	status = NI_WICKED_RC_ERROR;
	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	if (!ni_duid_map_set(map, scope, duid))
		goto cleanup;

	if (!ni_duid_map_save(map))
		goto cleanup;

	status = NI_WICKED_RC_SUCCESS;

cleanup:
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_create_update(const char *scope, const char *duid)
{
	int status = NI_WICKED_RC_ERROR;
	ni_duid_map_t *map = NULL;

	if (!(map = ni_duid_map_load(NULL)))
		goto cleanup;

	if (!ni_duid_map_set(map, scope, duid))
		goto cleanup;

	if (!ni_duid_map_save(map))
		goto cleanup;

	status = NI_WICKED_RC_SUCCESS;

cleanup:
	ni_duid_map_free(map);
	return status;
}

static int
ni_do_duid_create_en(int argc, char **argv)
{
	enum {	OPT_HELP = 'h', OPT_SCOPE = 's', OPT_UPDATE = 'u' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "scope",	required_argument,	NULL,	OPT_SCOPE	},
		{ "update",	no_argument,		NULL,	OPT_UPDATE	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	const char *scope = NULL;
	ni_bool_t update = FALSE;
	const char *en = NULL;
	const char *id = NULL;
	const char *hex = NULL;
	ni_opaque_t raw;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hs:u", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_UPDATE:
			update = TRUE;
			break;
		case OPT_SCOPE:
			if (optarg && !ni_string_eq(optarg, "default"))
				scope = optarg;
			break;
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage: %s [options] <enterprise-number> <machine-identifier>\n"
				"\n"
				"Options:\n"
				"  --help, -h           show this help text and exit.\n"
				"  --scope <ifname>     create device specific duid instead of default\n"
				"  --update             create a duid and update duid map file\n"
				"\n"
				"Arguments:\n"
				"  enterprise-number    IANA assigned 32bit enterprise number\n"
				"  machine-identifier   machine identifier as colon-separated hex bytes\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}
	switch (argc - optind) {
	case 2:
		en = argv[optind++];
		id = argv[optind++];
		break;
	default:
		goto usage;
	}

	status = NI_WICKED_RC_ERROR;
	if (scope && !ni_netdev_name_is_valid(scope)) {
		fprintf(stderr, "%s: invalid scope interface name '%s'\n", argv[0],
				ni_print_suspect(scope, ni_string_len(scope)));
		goto cleanup;
	}

	if (!ni_duid_create_en(&raw, en, id)) {
		fprintf(stderr, "%s: cannot create duid using enterprise-number '%s' and identifier '%s'\n",
				argv[0], en, id);
		goto cleanup;
	}

	hex = raw.len ? ni_duid_print_hex(&raw) : NULL;
	if (ni_string_empty(hex)) {
		fprintf(stderr, "%s: cannot format en duid as a colon-separated hex string\n", argv[0]);
		goto cleanup;
	}

	if (update) {
		status = ni_do_duid_create_update(scope, hex);
		if (status != NI_WICKED_RC_SUCCESS) {
			fprintf(stderr, "%s: cannot update duid map file using the created duid\n", argv[0]);
			goto cleanup;
		}
	}

	printf("%s\t%s\n", scope ? scope : "default", hex);
	status = NI_WICKED_RC_SUCCESS;

cleanup:
	return status;
}

static inline void
ni_do_duid_create_ll_print_hwtypes(FILE *out)
{
	const ni_intmap_t *hwtype = ni_duid_hwtype_map();
	unsigned int alias = -1U;

	fprintf(out, "Supported hardware types are:\n");
	for (; hwtype && hwtype->name; ++hwtype) {
		if (alias == hwtype->value)
			continue;
		alias = hwtype->value;
		fprintf(out, "  %s\n", hwtype->name);
	}
}

static int
ni_do_duid_create_ll_type(uint16_t type, int argc, char **argv)
{
	enum {	OPT_HELP = 'h', OPT_SCOPE = 's', OPT_UPDATE = 'u' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "scope",	required_argument,	NULL,	OPT_SCOPE	},
		{ "update",	no_argument,		NULL,	OPT_UPDATE	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	const char *scope = NULL;
	ni_bool_t update = FALSE;
	const char *ifname = NULL;
	const char *hwtype = NULL;
	const char *hwaddr = NULL;
	const char *hex = NULL;
	ni_opaque_t raw;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hs:u", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_UPDATE:
			update = TRUE;
			break;
		case OPT_SCOPE:
			if (optarg && !ni_string_eq(optarg, "default"))
				scope = optarg;
			break;
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage: %s [options] [ [ifname] | <hwtype> <hwaddr> ]\n"
				"\n"
				"Options:\n"
				"  --help, -h           show this help text and exit.\n"
				"  --scope <ifname>     create device specific duid instead of default\n"
				"  --update             create a duid and update duid map file\n"
				"\n"
				"Arguments:\n"
				"  ifname               get hardware type and address from interface\n"
				"  htwype               hardware type to use in the duid\n"
				"  htaddr               hardware address to use in the duid\n"
				"\n", argv[0]);
			ni_do_duid_create_ll_print_hwtypes(stderr);
			goto cleanup;
		}
	}
	switch (argc - optind) {
	case 2:
		hwtype = argv[optind++];
		hwaddr = argv[optind++];
		break;
	case 1:
		ifname = argv[optind++];
		break;
	case 0:
		break;
	default:
		goto usage;
	}

	status = NI_WICKED_RC_ERROR;
	if (scope && !ni_netdev_name_is_valid(scope)) {
		fprintf(stderr, "%s: invalid scope interface name '%s'\n", argv[0],
				ni_print_suspect(scope, ni_string_len(scope)));
		goto cleanup;
	}

	if (hwtype || hwaddr) {
		switch (type) {
		case NI_DUID_TYPE_LL:
			if (ni_duid_create_ll(&raw, hwtype, hwaddr))
				status = NI_WICKED_RC_SUCCESS;
			break;
		case NI_DUID_TYPE_LLT:
			if (ni_duid_create_llt(&raw, hwtype, hwaddr))
				status = NI_WICKED_RC_SUCCESS;
			break;
		default:
			break;
		}
		if (status != NI_WICKED_RC_SUCCESS) {
			fprintf(stderr, "%s: cannot create duid using hardware type '%s' and address '%s'\n",
				argv[0], hwtype, hwaddr);
			goto cleanup;
		}
	} else {
		ni_netconfig_t *nc = ni_global_state_handle(1);
		ni_netdev_t *dev = NULL;

		if (!nc) {
			fprintf(stderr, "%s: cannot retrieve interface properties", argv[0]);
			goto cleanup;
		}

		if (ifname) {
			dev = ni_netdev_by_name(nc, ifname);
			if (!dev || !ni_duid_create_from_device(&raw, type, dev)) {
				hwtype = dev ? ni_duid_hwtype_to_name(dev->link.hwaddr.type) : "missing";
				fprintf(stderr, "%s: unable to create %s duid using %s device '%s'\n",
					argv[0], ni_duid_type_to_name(type),
					hwtype ? hwtype : "unsupported", ifname);
				goto cleanup;
			}
		} else {
			dev = scope ? ni_netdev_by_name(nc, scope) : NULL;
			if (!ni_duid_create_pref_device(&raw, type, nc, dev)) {
				fprintf(stderr, "%s: unable to create any %s duid (no usable devices)",
					argv[0], ni_duid_type_to_name(type));
				goto cleanup;
			}
		}
	}

	status = NI_WICKED_RC_ERROR;
	hex = raw.len ? ni_duid_print_hex(&raw) : NULL;
	if (ni_string_empty(hex)) {
		fprintf(stderr, "%s: cannot format en duid as a colon-separated hex string\n", argv[0]);
		goto cleanup;
	}

	if (update) {
		status = ni_do_duid_create_update(scope, hex);
		if (status != NI_WICKED_RC_SUCCESS) {
			fprintf(stderr, "%s: cannot update duid map file using the created duid\n", argv[0]);
			goto cleanup;
		}
	}

	printf("%s\t%s\n", scope ? scope : "default", hex);
	status = NI_WICKED_RC_SUCCESS;

cleanup:
	return status;
}

static inline int
ni_do_duid_create_ll(int argc, char **argv)
{
	return ni_do_duid_create_ll_type(NI_DUID_TYPE_LL, argc, argv);
}

static inline int
ni_do_duid_create_llt(int argc, char **argv)
{
	return ni_do_duid_create_ll_type(NI_DUID_TYPE_LLT, argc, argv);
}

static int
ni_do_duid_create_uuid(int argc, char **argv)
{
	enum {	OPT_HELP = 'h', OPT_SCOPE = 's', OPT_UPDATE = 'u',
		OPT_MACHINE_ID = 'm', OPT_PRODUCT_ID = 'p' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ "scope",	required_argument,	NULL,	OPT_SCOPE	},
		{ "update",	no_argument,		NULL,	OPT_UPDATE	},
		{ "machine-id",	optional_argument,	NULL,	OPT_MACHINE_ID	},
		{ "product-id",	optional_argument,	NULL,	OPT_PRODUCT_ID	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	const char *scope = NULL;
	ni_bool_t update = FALSE;
	unsigned int type = 0;
	const char *from = NULL;
	const char *hex = NULL;
	ni_opaque_t raw;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hs:um::p::", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_MACHINE_ID:
			type = OPT_MACHINE_ID;
			from = optarg;
			break;
		case OPT_PRODUCT_ID:
			type = OPT_PRODUCT_ID;
			from = optarg;
			break;
		case OPT_UPDATE:
			update = TRUE;
			break;
		case OPT_SCOPE:
			if (optarg && !ni_string_eq(optarg, "default"))
				scope = optarg;
			break;
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage: %s [options] [uuid]\n"
				"\n"
				"Options:\n"
				"  --help, -h           show this help text and exit.\n"
				"  --scope <ifname>     create device specific duid instead of default\n"
				"  --update             create a duid and update duid map file\n"
				"  --machine-id[=FILE]  import uuid from /etc/machine-id file\n"
				"  --product-id[=FILE]  import uuid from dmi product-id sysfs file\n"
				"\n"
				"Arguments:\n"
				"  uuid                 create duid using specified uuid-string\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}
	switch (type) {
	case OPT_MACHINE_ID:
	case OPT_PRODUCT_ID:
		if ((argc - optind) != 0)
			goto usage;
		break;
	default:
		if ((argc - optind) != 1)
			goto usage;
		from = argv[optind++];
		break;
	}

	status = NI_WICKED_RC_ERROR;
	if (scope && !ni_netdev_name_is_valid(scope)) {
		fprintf(stderr, "%s: invalid scope interface name '%s'\n", argv[0],
				ni_print_suspect(scope, ni_string_len(scope)));
		goto cleanup;
	}

	switch (type) {
	case OPT_MACHINE_ID:
		if (!ni_duid_create_uuid_machine_id(&raw, from)) {
			fprintf(stderr, "%s: cannot create duid by importing uuid from machine-id%s%s",
					argv[0], from ? " file ": "", from ? from : "");
			goto cleanup;
		}
		break;
	case OPT_PRODUCT_ID:
		if (!ni_duid_create_uuid_dmi_product_id(&raw, from)) {
			fprintf(stderr, "%s: cannot create duid by importing uuid from dmi product-id%s%s",
					argv[0], from ? " file ": "", from ? from : "");
			goto cleanup;
		}
		break;
	default:
		if (!ni_duid_create_uuid_string(&raw, from)) {
			fprintf(stderr, "%s: cannot create duid by importing uuid string '%s'",
					argv[0], from);
			goto cleanup;
		}
		break;
	}

	hex = raw.len ? ni_duid_print_hex(&raw) : NULL;
	if (ni_string_empty(hex)) {
		fprintf(stderr, "%s: cannot format en duid as a colon-separated hex string\n", argv[0]);
		goto cleanup;
	}

	if (update) {
		status = ni_do_duid_create_update(scope, hex);
		if (status != NI_WICKED_RC_SUCCESS) {
			fprintf(stderr, "%s: cannot update duid map file using the created duid\n", argv[0]);
			goto cleanup;
		}
	}

	printf("%s\t%s\n", scope ? scope : "default", hex);
	status = NI_WICKED_RC_SUCCESS;

cleanup:
	return status;
}

static int
ni_do_duid_create(int argc, char **argv)
{
	enum {	OPT_HELP = 'h' };
	static struct option    options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	const char *type = NULL;
	char *command = NULL;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"Usage: %s [options] <ll|llt|en|uuid> ...\n"
				"\n"
				"Options:\n"
				"  --help, -h           show this help text and exit.\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}
	if (optind >= argc || ni_string_empty(argv[optind])) {
		fprintf(stderr, "%s: missing duid type argument\n\n", argv[0]);
		goto usage;
	}

	type = argv[optind];
	ni_string_printf(&command, "%s %s", argv[0], type);
	argv[optind] = command;

	if (ni_string_eq(type, "ll")) {
		status = ni_do_duid_create_ll(argc - optind, argv + optind);
	} else
	if (ni_string_eq(type, "llt")) {
		status = ni_do_duid_create_llt(argc - optind, argv + optind);
	} else
	if (ni_string_eq(type, "en")) {
		status = ni_do_duid_create_en(argc - optind, argv + optind);
	} else
	if (ni_string_eq(type, "uuid")) {
		status = ni_do_duid_create_uuid(argc - optind, argv + optind);
	} else {
		argv[optind] = (char *)type;
		fprintf(stderr, "%s: unsupported duid type '%s'\n", argv[0],
				ni_print_suspect(type, ni_string_len(type)));
		goto usage;
	}
	argv[optind] = (char *)type;

cleanup:
	ni_string_free(&command);
	return status;
}

int
ni_do_duid(const char *caller, int argc, char **argv)
{
	enum {	OPT_HELP = 'h' };
	static struct option	options[] = {
		{ "help",	no_argument,		NULL,	OPT_HELP	},
		{ NULL,		no_argument,		NULL,	0		}
	};
	int opt = 0, status = NI_WICKED_RC_USAGE;
	char *program = NULL;
	char *command = NULL;
	const char *cmd;

	ni_string_printf(&program, "%s %s", caller  ? caller  : "wicked",
					    argv[0] ? argv[0] : "duid");

	optind = 1;
	argv[0] = program;
	while ((opt = getopt_long(argc, argv, "+h", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"  %s [common options] <command> [...]\n"
				"\n"
				"Common options:\n"
				"  --help, -h           show this help text and exit.\n"
				"\n"
				"Supported commands:\n"
				"  help                 show this help text and exit.\n"
				"  dump, show		show the duid map contents\n"
				"  get [options]        get current duid\n"
				"  del [options]        delete current duid\n"
				"  set [options] <duid> set/update the duid\n"
				"  create <type> [...]  create a new duid\n"
				"\n", argv[0]);
			goto cleanup;
		}
	}

	if (optind >= argc || ni_string_empty(argv[optind])) {
		fprintf(stderr, "%s: missing command argument\n", argv[0]);
		goto usage;
	}

	cmd = argv[optind];
	ni_string_printf(&command, "%s %s", program, cmd);
	argv[optind] = command;

	if (ni_string_eq(cmd, "help")) {
		argv[optind] = (char *)cmd;
		status = NI_WICKED_RC_SUCCESS;
		goto usage;
	} else
	if (ni_string_eq(cmd, "dump") || ni_string_eq(cmd, "show")) {
		status = ni_do_duid_dump(argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "get")) {
		status = ni_do_duid_get (argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "set")) {
		status = ni_do_duid_set (argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "del")) {
		status = ni_do_duid_del (argc - optind, argv + optind);
	} else
	if (ni_string_eq(cmd, "create")) {
		status = ni_do_duid_create (argc - optind, argv + optind);
	} else {
		argv[optind] = (char *)cmd;
		fprintf(stderr, "%s: unsupported command %s\n", program, (char *)cmd);
		goto usage;
	}
	argv[optind] = (char *)cmd;

cleanup:
	argv[0] = NULL;
	ni_string_free(&command);
	ni_string_free(&program);
	return status;
}

