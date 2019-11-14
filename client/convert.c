/*
 *	wicked convert, show-config
 *
 *	Copyright (C) 2019 SUSE Software Solutions Germany GmbH, Germany.
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
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, see <http://www.gnu.org/licenses/> or write
 *	to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *	Boston, MA 02110-1301 USA.
 *
 *	Authors:
 *		Olaf Kirch
 *		Pawel Wieczorkiewicz
 *      	Marius Tomaschewski
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

#include <wicked/types.h>
#include <wicked/logging.h>
#include <wicked/util.h>
#include <wicked/xml.h>

#include "appconfig.h"
#include "wicked-client.h"
#include "client/ifconfig.h"


static ni_bool_t
ni_wicked_convert_match_config(xml_node_t *node, const char *match)
{
	const char *namespace;
	xml_node_t *child;

	if (!(child = xml_node_get_child(node, "name")))
		return FALSE;

	if ((namespace = xml_node_get_attr(child, "namespace")))
		return FALSE;

	/* match configs by ifname only for now */
	return ni_string_eq(child->cdata, match);
}

static ni_bool_t
ni_wicked_convert_match(xml_node_t *node, ni_string_array_t *filter)
{
	const char *match;
	unsigned int i;

	if (ni_ifconfig_is_config(node)) {
		if (!filter || !filter->count)
			return TRUE;

		for (i = 0; i < filter->count; ++i) {
			match = filter->data[i];
			if (ni_wicked_convert_match_config(node, match))
				return TRUE;
		}
	}

	return FALSE; /* omit any non-ifconfig nodes */
}

static ni_bool_t
ni_wicked_convert_config_filename(char **filename, xml_node_t *node, const char *dirname)
{
	xml_node_t *child;
	const char *ns;

	if (!(child = xml_node_get_child(node, "name")))
		return FALSE;

	if (ni_string_empty(child->cdata))
		return FALSE;

	if (!ni_string_empty(ns = xml_node_get_attr(child, "namespace")))
		return !!ni_string_printf(filename, "%s/id-%s-%s.xml", dirname, ns, child->cdata);
	else
		return !!ni_string_printf(filename, "%s/%s.xml", dirname, child->cdata);
}

static ni_bool_t
ni_wicked_convert_node_filename(char **filename, xml_node_t *node, const char *dirname)
{
	if (ni_ifconfig_is_config(node))
		return ni_wicked_convert_config_filename(filename, node, dirname);
	else
		return FALSE;
}

static ni_bool_t
ni_wicked_convert_dump(xml_document_array_t *docs, ni_string_array_t *filter, FILE *output)
{
	ni_bool_t empty = TRUE;
	unsigned int i;

	for (i = 0; i < docs->count; i++) {
		xml_document_t *doc = docs->data[i];
		xml_node_t *root = xml_document_root(doc);
		xml_node_t *node;

		if (xml_node_is_empty(root))
			continue;

		for (node = root->children; node; node = node->next) {
			if (!ni_wicked_convert_match(node, filter))
				continue;

			xml_node_print(node, output);
			empty = FALSE;
		}
	}

	return !empty;
}

static int
ni_wicked_convert_to_file(xml_document_array_t *docs, ni_string_array_t *filter, const char *filename)
{
	FILE *output;

	if (!(output = fopen(filename, "w"))) {
		ni_error("unable to open '%s' for writing: %m", filename);
		return NI_WICKED_RC_ERROR;
	}

	ni_wicked_convert_dump(docs, filter, output);
	fclose(output);

	return NI_WICKED_RC_SUCCESS;
}

static int
ni_wicked_convert_to_dir(xml_document_array_t *docs, ni_string_array_t *filter, const char *dirname)
{
	char *filename = NULL;
	unsigned int i;
	FILE *output;

	for (i = 0; i < docs->count; i++) {
		xml_document_t *doc = docs->data[i];
		xml_node_t *root = xml_document_root(doc);
		xml_node_t *node;

		if (xml_node_is_empty(root))
			continue;

		for (node = root->children; node; node = node->next) {
			if (!ni_wicked_convert_match(node, filter))
				continue;

			if (!ni_wicked_convert_node_filename(&filename, node, dirname))
				return NI_WICKED_RC_ERROR;

			if (!(output = fopen(filename, "w"))) {
				ni_error("unable to open '%s' for writing: %m", filename);
				ni_string_free(&filename);
				return NI_WICKED_RC_ERROR;
			}
			ni_string_free(&filename);

			xml_node_print(node, output);
			fclose(output);
		}
	}
	return NI_WICKED_RC_SUCCESS;
}

static ni_bool_t
ni_wicked_convert_compat_source(ni_string_array_t *sources, const char *source)
{
	const ni_string_array_t *schemes;
	const char *match = NULL;
	char *path = NULL;
	int ret = -1;

	if (!sources || ni_string_empty(source))
		return FALSE;

	/*
	 * use as-is if it starts with a main source scheme/prefix
	 * (is fully qualified), otherwise prepend "compat:" scheme
	 * so "convert /tmp/mycfg" assumes path to compat ifconfigs
	 * instead of a path to default xml ifconfig scheme.
	 */
	if ((schemes = ni_config_sources("ifconfig"))) {
		unsigned int i;

		for (i = 0; !match && i < schemes->count; ++i) {
			const char *scheme = schemes->data[i];

			if (ni_string_startswith(source, scheme))
				match = scheme;
		}
	}
	if (match) {
		ret = ni_string_array_append(sources, source);
	} else
	if (ni_string_printf(&path, "compat:%s", source)) {
		ret = ni_string_array_append(sources, path);
	}
	ni_string_free(&path);

	return ret == 0;
}

int
ni_wicked_convert(const char *caller, int argc, char **argv)
{
	enum {
		OPT_HELP	= 'h',
		OPT_IFCONFIG	= 'i',
		OPT_OUTPUT	= 'o',
		OPT_RAW		= 'R',
	};
	static struct option options[] = {
		{ "help",	no_argument,		NULL, OPT_HELP		},
		{ "ifconfig",	required_argument,	NULL, OPT_IFCONFIG	},
		{ "output",	required_argument,	NULL, OPT_OUTPUT	},
		{ "raw",	no_argument,		NULL, OPT_RAW		},
		{ NULL }
	};
	xml_document_array_t docs = XML_DOCUMENT_ARRAY_INIT;
	ni_string_array_t sources = NI_STRING_ARRAY_INIT;
	ni_string_array_t filter = NI_STRING_ARRAY_INIT;
	int opt, status = NI_WICKED_RC_USAGE;
	const char *opt_output = NULL;
	ni_bool_t opt_raw = FALSE;
	char *program = NULL;
	enum {
		CONVERT_COMPAT,
		CONVERT_CONFIG,
	} opt_convert = CONVERT_COMPAT;
	unsigned int i;

	if (ni_string_eq(argv[0], "show-config"))
		opt_convert = CONVERT_CONFIG;

	ni_string_printf(&program, "%s %s",	caller  ? caller  : "wicked",
						argv[0] ? argv[0] : "convert");
	argv[0] = program;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hi:o:C:R", options, NULL)) != EOF) {
		switch (opt) {
		case OPT_HELP:
			status = NI_WICKED_RC_SUCCESS;
			/* fall through */
		default:
		usage:
			fprintf(stderr,
				"\nUsage:\n"
				"%s [options] [<ifname ...>|all]\n"
				"\n"
				"Options:\n"
				"  --help, -h		show this help text and exit.\n"
				"\n"
				"  --ifconfig <path>	read config from the specified sources\n"
				"  --output   <path>	write output to specified file or directory\n"
				"  --raw		do not display <client-state> tags\n"
				"\n", program);
			goto cleanup;

		case OPT_IFCONFIG:
			if (ni_string_empty(optarg))
				goto usage;

			if (opt_convert == CONVERT_COMPAT) {
				if (!ni_wicked_convert_compat_source(&sources, optarg)) {
					ni_error("Unable to add compat config source '%s'", optarg);
					status = NI_WICKED_RC_ERROR;
					goto cleanup;
				}
			} else {
				if (ni_string_array_append(&sources, optarg) != 0) {
					ni_error("Unable to add config source '%s'", optarg);
					status = NI_WICKED_RC_ERROR;
					goto cleanup;
				}
			}
			break;

		case OPT_OUTPUT:
			if (!ni_string_empty(optarg))
				opt_output = optarg;
			break;

		case OPT_RAW:
			opt_raw = TRUE;
			break;

		}
	}

	if (!sources.count) {
		/*
		 * compatibility to old "wicked convert [source]"
		 * arguments (instead of [--ifconfig <source>]).
		 */
		while (optind < argc) {
			char *optarg = argv[optind++];

			if (!ni_string_contains(optarg, "=") &&
			    (ni_string_contains(optarg, ":") ||
			     ni_string_contains(optarg, "/"))) {
				/* [scheme:]/foo/bar ifconfig source path */
				if (!ni_wicked_convert_compat_source(&sources, optarg)) {
					ni_error("Unable to add compat config source '%s'", optarg);
					status = NI_WICKED_RC_ERROR;
					goto cleanup;
				}
			} else {
				/* not a source, probably "ifname" filter */
				optind--;
				break;
			}
		}
	}
	if (!sources.count) {
		/* A "wicked convert" converts the "compat:" schemes to xml while
		 * a "wicked show-config" converts all to config
		 */
		if (opt_convert == CONVERT_COMPAT)
			ni_string_array_append(&sources, "compat:");
		else
			ni_string_array_copy(&sources, ni_config_sources("ifconfig"));
	}

	/* ifname filter arguments */
	while (optind < argc) {
		char *optarg = argv[optind++];
		/*
		 * wicked convert [--ifconfig <source>] [<ifname ...>|all]
		 */
		if (ni_string_array_index(&filter, optarg) < 0)
			ni_string_array_append(&filter, optarg);
	}
	/* clear filter when it contains "all" */
	if (ni_string_array_index(&filter, "all") >= 0)
		ni_string_array_destroy(&filter);


	status = NI_WICKED_RC_SUCCESS;
	for (i = 0; i < sources.count; ++i) {
		const char *source = sources.data[i];

		if (!ni_ifconfig_read(&docs, opt_global_rootdir, source, FALSE, opt_raw)) {
			ni_error("Unable to read config source '%s'", source);
			status = NI_WICKED_RC_ERROR;
			goto cleanup;
		}
	}

	if (opt_output == NULL || ni_string_eq(opt_output, "-")) {
		ni_wicked_convert_dump(&docs, &filter, stdout);
	} else
	if (ni_isdir(opt_output)) {
		status = ni_wicked_convert_to_dir(&docs, &filter, opt_output);
	} else {
		status = ni_wicked_convert_to_file(&docs, &filter, opt_output);
	}

cleanup:
	xml_document_array_destroy(&docs);
	ni_string_array_destroy(&filter);
	ni_string_array_destroy(&sources);
	return status;
}

