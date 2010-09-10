/*
 * Small test app for our XPATH routines
 *
 * Copyright (C) 2010 Olaf Kirch <okir@suse.de>
 */

#include <stdlib.h>
#include <getopt.h>
#include <wicked/netinfo.h>
#include <wicked/xpath.h>

enum {
	OPT_DEBUG,
	OPT_REFERENCE,
};

static struct option	options[] = {
	{ "debug",		required_argument,	NULL,	OPT_DEBUG },
	{ "reference",		required_argument,	NULL,	OPT_REFERENCE },

	{ NULL }
};


int
main(int argc, char **argv)
{
	const char *opt_reference = NULL;
	const char *expression = NULL, *filename = "-";
	xml_document_t *doc;
	xml_node_t *refnode;
	xpath_enode_t *enode;
	xpath_result_t *result;
	int c;

	while ((c = getopt_long(argc, argv, "", options, NULL)) != EOF) {
		switch (c) {
		default:
		usage:
			fprintf(stderr,
				"./xpath-test [--reference <expression>] <expression> [filename]\n"
			       );
			return 1;

		case OPT_DEBUG:
			if (ni_enable_debug(optarg) < 0) {
				fprintf(stderr, "Bad debug facility \"%s\"\n", optarg);
				return 1;
			}
			break;

		case OPT_REFERENCE:
			opt_reference = optarg;
			break;

		}
	}

	if (optind >= argc)
		goto usage;
	expression = argv[optind++];

	if (optind < argc)
		filename = argv[optind++];

	if (optind < argc)
		goto usage;

	doc = xml_document_read(filename);
	if (!doc) {
		fprintf(stderr, "Error parsing XML document %s\n", filename);
		return 1;
	}

	refnode = doc->root;
	if (opt_reference) {
		enode = xpath_expression_parse(opt_reference);
		if (!enode) {
			fprintf(stderr, "Error parsing XPATH expression %s\n", opt_reference);
			return 1;
		}

		result = xpath_expression_eval(enode, doc->root);
		if (!result) {
			fprintf(stderr, "Error evaluating XPATH expression\n");
			return 1;
		}

		if (result->type != XPATH_ELEMENT) {
			fprintf(stderr, "Failed to look up reference node - returned non-element result\n");
			return 1;
		}
		if (result->count == 0) {
			fprintf(stderr, "Failed to look up reference node - returned empty list\n");
			return 1;
		}
		refnode = result->node[0].value.node;

		xpath_result_free(result);
		xpath_expression_free(enode);
	}

	enode = xpath_expression_parse(expression);
	if (!enode) {
		fprintf(stderr, "Error parsing XPATH expression %s\n", expression);
		return 1;
	}

	result = xpath_expression_eval(enode, refnode);
	if (!result) {
		fprintf(stderr, "Error evaluating XPATH expression\n");
		return 1;
	}

	xpath_result_print(result, stdout);

	xpath_result_free(result);
	xpath_expression_free(enode);

	return 0;
}

