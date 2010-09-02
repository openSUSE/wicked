/*
 * Small test app for our XML routines
 *
 * Copyright (C) 2009-2010 Olaf Kirch <okir@suse.de>
 */

#include <stdlib.h>
#include "xml.h"

int
main(int argc, char **argv)
{
	const char *filename;
	xml_document_t *doc;

	if (argc != 2) {
		fprintf(stderr, "Usage: xml-test filename\n");
		return 1;
	}
	filename = argv[1];

	doc = xml_document_read(filename);
	if (!doc) {
		fprintf(stderr, "Error parsing %s\n", filename);
		return 1;
	}

	xml_document_print(doc, stdout);
	xml_document_free(doc);
	return 0;
}

